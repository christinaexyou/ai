// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! [`ServiceAccountTokenFilter`] — attaches a Kubernetes pod identity token
//! only to the destination fixed at startup.
//!
//! # Overview
//!
//! Kubernetes puts a short-lived login token in a file inside the pod and
//! replaces that file before the token expires. This filter reads the file
//! when Praxis starts, keeps the token in memory, and watches for a new file.
//! A replacement is picked up without restarting Praxis.
//!
//! `endpoint` is required. Praxis refuses to start if it is left out. The
//! token goes only to the host and port in that address.
//!
//! Put the filter on the outbound chain of the filter that calls `NeMo`. That
//! chain is Praxis's own call to `NeMo`. If the filter is placed on the chain
//! that accepts the client's chat request, it removes the client's login
//! header and never sends the pod token.
//!
//! A port written in the URL is kept. `http` with no port means port 80, and
//! `https` with no port means port 443. A call to any other host or port is
//! sent without the token.
//!
//! # Security
//!
//! - The token is never written to logs, traces, or error messages.
//! - If the file is missing, empty, or too large, the call to `NeMo` is refused with status 503 and is not sent.
//!   Guardrails then fails the check, and the client sees status 500. The chat is not sent on to the model.
//! - The header cannot be one Praxis reserves for itself, and it cannot be a header that controls the connection (for
//!   example `host` or `proxy-authorization`).
//! - In production, use `https://` for both this `endpoint` and the `NeMo` address. The match looks at host and port
//!   only, so an `http://` call to that same host and port still sends the token where anyone on the network can read
//!   it. This filter has no certificate setting. An https call checks the server certificate with the trust store
//!   loaded for the Praxis process.
//!
//! # YAML config
//!
//! ```yaml
//! filter: service_account_token
//! token_file: /var/run/secrets/tokens/nemo/token
//! endpoint: "https://nemo.default.svc:8443/v1/checks" # required; only this host and port receive the token
//! header: Authorization   # optional, defaults to Authorization
//! prefix: "Bearer "       # optional, defaults to "Bearer "
//! ```

use std::{
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    time::Duration,
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::{HeaderName, HeaderValue, header::AUTHORIZATION};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};
use praxis_filter::{
    DeferredCredential, FilterAction, FilterError, HttpFilter, HttpFilterContext, PendingCredentials, Rejection,
    parse_filter_config,
};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::descriptor::RESERVED_HEADER_PREFIXES;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Max length for the token file path.
const MAX_PATH_LEN: usize = 4096;

/// Max length for the header value prefix (e.g. `"Bearer "`).
const MAX_PREFIX_LEN: usize = 64;

/// Max token size accepted from the file.
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Read one byte past the limit so we can detect oversized files without
/// loading them fully into memory.
const MAX_TOKEN_READ_BYTES: u64 = MAX_TOKEN_BYTES as u64 + 1;

/// Default prefix prepended to the token in the header value.
const DEFAULT_PREFIX: &str = "Bearer ";

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the `service_account_token` filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceAccountTokenConfig {
    /// Path to the token file. The file must exist and contain a token when
    /// Praxis starts. Later replacements of the file are picked up on their own.
    token_file: String,

    /// Required address of the service allowed to receive the token. Praxis
    /// refuses to start if `endpoint` is missing. Only the host and port in
    /// this address receive the token. `http` and `https` count as the same
    /// for that match, so use `https://` on the real service address in
    /// production. An `http://` call to the same host and port sends the token
    /// where anyone on the network can read it. This filter has no certificate
    /// setting. An https call checks the server certificate with the trust
    /// store loaded for the Praxis process (`SSL_CERT_FILE`, `SSL_CERT_DIR`,
    /// or the system certificate bundle).
    endpoint: String,

    /// Header that carries the token on the outgoing call. Defaults to
    /// `Authorization`. Cannot be a header Praxis removes before the call
    /// leaves (`x-praxis-*`, `x-mcp-*`, `x-ext-agent-*`, `x-ext-protocol-*`)
    /// or a header that controls the connection (`host`, `content-length`,
    /// `proxy-authorization`, and similar).
    #[serde(default = "default_header")]
    header: String,

    /// Text placed in front of the token. Defaults to `"Bearer "`.
    /// Set this to `""` to send the token by itself.
    #[serde(default = "default_prefix")]
    prefix: String,
}

/// Header used when config omits `header`.
fn default_header() -> String {
    AUTHORIZATION.as_str().to_owned()
}

/// Prefix used when config omits `prefix`.
fn default_prefix() -> String {
    DEFAULT_PREFIX.to_owned()
}

// -----------------------------------------------------------------------------
// Internal types
// -----------------------------------------------------------------------------

/// The token currently held in memory.
///
/// Empty means the last read failed. Calls are refused until a good token
/// is read again.
struct TokenSnapshot {
    /// The header text to send (`"{prefix}{token}"`), or empty if the last
    /// read failed. Wiped from memory when dropped so the token does not linger.
    header_value: Option<Zeroizing<String>>,
}

/// Messages sent to the background watcher thread.
enum WatcherMessage {
    /// A filesystem change was detected.
    Event(notify::Event),
    /// The file watcher reported an error. The saved token is cleared so
    /// later calls are refused until a later read succeeds.
    NotifyError,
    /// Shut down — sent when the filter is dropped.
    Shutdown,
}

/// Keeps the background watcher thread alive for as long as the filter exists.
struct TokenReloadHandle {
    /// Sends the shutdown signal to the watcher thread.
    shutdown: mpsc::Sender<WatcherMessage>,
    /// The watcher thread; joined when this handle is dropped.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for TokenReloadHandle {
    fn drop(&mut self) {
        drop(self.shutdown.send(WatcherMessage::Shutdown));
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
    }
}

// -----------------------------------------------------------------------------
// Filter
// -----------------------------------------------------------------------------

/// Sends the pod's Kubernetes login token only to the address configured at startup.
///
/// `endpoint` is required. Praxis refuses to start if it is left out. The token
/// goes only to the host and port in that address.
///
/// Put this filter on the outbound chain, the chain Praxis uses for its own
/// call to `NeMo`. On the chain that accepts the client's chat request, the
/// filter removes the client's login header and never sends the pod token.
///
/// If the token file is missing, empty, or too large, the call to `NeMo` is
/// refused with status 503 and is not sent. Guardrails then fails the check,
/// and the client sees status 500.
pub struct ServiceAccountTokenFilter {
    /// Header to set on each request.
    header_name: HeaderName,
    /// Exact `host:port` allowed to receive the token, fixed at startup.
    authority: String,
    /// Latest token, updated in the background when the file changes.
    snapshot: Arc<ArcSwap<TokenSnapshot>>,
    /// Keeps the watcher thread alive; dropped after the snapshot.
    _reload_handle: TokenReloadHandle,
}

impl ServiceAccountTokenFilter {
    /// Build from YAML config.
    ///
    /// # Errors
    ///
    /// Returns an error when `endpoint` is missing or is not an `http` or
    /// `https` URL with a host and known port, the token file cannot be
    /// resolved or read, the header or prefix is invalid, or the background
    /// watcher cannot start.
    pub fn from_config(value: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        Ok(Box::new(Self::build(value)?))
    }

    /// Parse config, fix the destination authority, and read the initial token.
    fn build(value: &serde_yaml::Value) -> Result<Self, FilterError> {
        let cfg: ServiceAccountTokenConfig = parse_filter_config("service_account_token", value)?;

        validate_bounded("token_file", &cfg.token_file, MAX_PATH_LEN)?;
        validate_bounded("endpoint", &cfg.endpoint, MAX_PATH_LEN)?;
        let header_name = resolve_header_name(&cfg.header)?;
        validate_prefix(&cfg.prefix)?;
        let authority = praxis_ai_apis::http_credential_authority("service_account_token", &cfg.endpoint)?;

        // Turn a relative path into a full path once. The file watcher reports
        // full paths, so the read, the watch, and the comparison use the same path.
        let token_file = std::path::absolute(&cfg.token_file).map_err(|error| -> FilterError {
            format!("service_account_token: cannot resolve '{}': {error}", cfg.token_file).into()
        })?;

        // Read the token now so a bad config fails at startup.
        let initial_token = read_token(&token_file)?;
        let initial_value = format!("{}{}", cfg.prefix, initial_token.as_str());
        // Check the assembled value is a valid HTTP header value before storing it.
        HeaderValue::from_str(&initial_value).map_err(|e| -> FilterError {
            format!("service_account_token: assembled header value is not valid HTTP: {e}").into()
        })?;

        let snapshot = Arc::new(ArcSwap::from_pointee(TokenSnapshot {
            header_value: Some(Zeroizing::new(initial_value)),
        }));

        let reload_handle = spawn_token_watcher(token_file, cfg.prefix, Arc::clone(&snapshot))?;

        Ok(Self {
            header_name,
            authority,
            snapshot,
            _reload_handle: reload_handle,
        })
    }
}

#[async_trait]
impl HttpFilter for ServiceAccountTokenFilter {
    fn name(&self) -> &'static str {
        "service_account_token"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        // Read the in-memory token. The request path does not touch the file.
        let snapshot = self.snapshot.load_full();
        let Some(assembled) = snapshot.header_value.as_ref() else {
            tracing::debug!("service_account_token: token unavailable; failing closed");
            return Ok(FilterAction::Reject(Rejection::status(503)));
        };

        // Remove any value already on this header. If the call is going somewhere
        // other than the configured address, neither that value nor the pod token is sent.
        ctx.request_headers_to_remove.push(self.header_name.clone());
        let credential = match DeferredCredential::new(&self.authority, self.header_name.clone(), assembled.as_str()) {
            Ok(credential) => credential,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "service_account_token: credential could not be bound to the startup authority; failing closed"
                );
                return Ok(FilterAction::Reject(Rejection::status(503)));
            },
        };
        if let Some(pending) = ctx.extensions.get_mut::<PendingCredentials>() {
            pending.push(credential);
        } else {
            let mut pending = PendingCredentials::new();
            pending.push(credential);
            ctx.extensions.insert(pending);
        }

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Watcher
// -----------------------------------------------------------------------------

/// Re-read the token file and publish a new snapshot, failing closed on any
/// error. The token value is never included in diagnostics — only the file
/// path and the error from the OS or HTTP layer appear in the warning.
fn reload_token(path: &Path, prefix: &str, snapshot: &ArcSwap<TokenSnapshot>) {
    let header_value = match read_token(path) {
        Ok(token) => {
            let assembled = format!("{prefix}{}", token.as_str());
            match HeaderValue::from_str(&assembled) {
                Ok(_) => Some(Zeroizing::new(assembled)),
                Err(error) => {
                    tracing::warn!(
                        path = %path.display(),
                        %error,
                        "service_account_token: assembled header value is not valid HTTP; failing closed"
                    );
                    None
                },
            }
        },
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "service_account_token: token unavailable; failing closed"
            );
            None
        },
    };
    snapshot.store(Arc::new(TokenSnapshot { header_value }));
}

/// Handle one change reported by the file watcher.
///
/// The watcher may report the real path behind a shortcut. A projected
/// service-account token is a shortcut to `..data/token`. Kubernetes rotates
/// the token by replacing `..data` and leaves `token` itself alone, so the
/// change shows up as another file in the same folder. Comparing folders is
/// what notices that replacement.
fn process_watcher_event(event: &notify::Event, path: &Path, prefix: &str, snapshot: &ArcSwap<TokenSnapshot>) {
    if event.need_rescan() || matches!(event.kind, EventKind::Other) {
        reload_token(path, prefix, snapshot);
        return;
    }
    let relevant = matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    );
    if relevant
        && event
            .paths
            .iter()
            .any(|event_path| event_affects_token(event_path, path))
    {
        reload_token(path, prefix, snapshot);
    }
}

/// Whether the changed path is the token file or another file in its folder.
///
/// Folder comparison follows shortcuts, so a macOS path under `/private/var`
/// still matches a configured `/var` path, and a Kubernetes `..data`
/// replacement in that folder is seen.
fn event_affects_token(event_path: &Path, token_path: &Path) -> bool {
    if event_path == token_path {
        return true;
    }
    let (Some(token_dir), Some(event_dir)) = (token_path.parent(), event_path.parent()) else {
        return false;
    };
    if event_dir == token_dir {
        return true;
    }
    let Some(token_real) = token_dir.canonicalize().ok() else {
        return false;
    };
    event_dir
        .canonicalize()
        .is_ok_and(|event_real| event_real == token_real)
}

/// Apply one message from the watcher thread.
///
/// Returns `false` only when the watcher should stop. If the watcher reports
/// an error, the saved token is cleared. Later calls are refused instead of
/// sending a token that may be out of date after the watcher has gone quiet.
fn handle_watcher_message(
    message: WatcherMessage,
    path: &Path,
    prefix: &str,
    snapshot: &ArcSwap<TokenSnapshot>,
) -> bool {
    match message {
        WatcherMessage::Event(event) => {
            process_watcher_event(&event, path, prefix, snapshot);
            true
        },
        WatcherMessage::NotifyError => {
            snapshot.store(Arc::new(TokenSnapshot { header_value: None }));
            true
        },
        WatcherMessage::Shutdown => false,
    }
}

/// Start watching the token file and keep the in-memory snapshot up to date.
///
/// Starts a background thread that:
/// 1. Watches the token file's directory for changes.
/// 2. Re-reads the file immediately to catch any rotation that happened between construction and the watcher becoming
///    active.
/// 3. Signals that startup finished — this function blocks until that point.
/// 4. Reloads the token whenever the file is created, changed, or deleted.
///
/// The thread stops cleanly when the returned [`TokenReloadHandle`] is dropped.
#[expect(
    clippy::too_many_lines,
    reason = "watcher setup and lifecycle are intentionally bounded in one function"
)]
fn spawn_token_watcher(
    path: PathBuf,
    prefix: String,
    snapshot: Arc<ArcSwap<TokenSnapshot>>,
) -> Result<TokenReloadHandle, FilterError> {
    let (ready_tx, ready_rx) = mpsc::channel();
    let (message_tx, message_rx) = mpsc::channel();
    let callback_tx = message_tx.clone();

    let thread = std::thread::Builder::new()
        .name("service-account-token-watcher".to_owned())
        .spawn(move || {
            let mut watcher: RecommendedWatcher = match notify::recommended_watcher(move |event| match event {
                Ok(event) => drop(callback_tx.send(WatcherMessage::Event(event))),
                Err(error) => {
                    tracing::warn!(%error, "service_account_token: watcher error; failing closed");
                    drop(callback_tx.send(WatcherMessage::NotifyError));
                },
            }) {
                Ok(w) => w,
                Err(error) => {
                    drop(ready_tx.send(Err(format!("failed to create token watcher: {error}"))));
                    return;
                },
            };

            let directory = path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
            if let Err(error) = watcher.watch(&directory, RecursiveMode::NonRecursive) {
                drop(ready_tx.send(Err(format!(
                    "failed to watch token directory {}: {error}",
                    directory.display()
                ))));
                return;
            }

            // Start watching before re-reading so we can't miss a rotation that
            // happens between the two. Any filesystem event that fires during
            // the read stays queued and is handled after startup completes.
            match read_token(&path) {
                Ok(token) => {
                    let assembled = format!("{prefix}{}", token.as_str());
                    match HeaderValue::from_str(&assembled) {
                        Ok(_) => {
                            snapshot.store(Arc::new(TokenSnapshot {
                                header_value: Some(Zeroizing::new(assembled)),
                            }));
                        },
                        Err(error) => {
                            drop(ready_tx.send(Err(format!("assembled header value is not valid HTTP: {error}"))));
                            return;
                        },
                    }
                },
                Err(error) => {
                    drop(ready_tx.send(Err(format!("failed authoritative token read: {error}"))));
                    return;
                },
            }
            drop(ready_tx.send(Ok(())));

            while let Ok(message) = message_rx.recv() {
                if !handle_watcher_message(message, &path, &prefix, &snapshot) {
                    break;
                }
            }
        })
        .map_err(|error| format!("service_account_token: failed to spawn watcher: {error}"))?;

    let ready = match ready_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(ready) => ready,
        Err(error) => {
            drop(message_tx.send(WatcherMessage::Shutdown));
            drop(thread.join());
            return Err(format!("service_account_token: watcher did not initialize: {error}").into());
        },
    };
    if let Err(error) = ready {
        drop(message_tx.send(WatcherMessage::Shutdown));
        drop(thread.join());
        return Err(format!("service_account_token: {error}").into());
    }

    Ok(TokenReloadHandle {
        shutdown: message_tx,
        thread: Some(thread),
    })
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Validate the header that receives the token.
///
/// Rejects a header Praxis would remove before the call leaves, because the
/// token would never arrive. Also rejects a header that controls the
/// connection. `proxy-authorization` would hand the token to a proxy in the
/// middle instead of to the real service.
fn resolve_header_name(header: &str) -> Result<HeaderName, FilterError> {
    validate_bounded("header", header, MAX_PATH_LEN)?;
    let name: HeaderName = header.parse().map_err(|error| -> FilterError {
        format!("service_account_token: invalid header '{header}': {error}").into()
    })?;
    if RESERVED_HEADER_PREFIXES
        .iter()
        .any(|prefix| name.as_str().starts_with(prefix))
        || praxis_core::reserved_headers::is_reserved(name.as_str())
    {
        return Err(
            format!("service_account_token: header '{header}' is reserved and is stripped before the callout").into(),
        );
    }
    if name != AUTHORIZATION && praxis_ai_apis::promotion::is_transport_controlled_header_lowercase(name.as_str()) {
        return Err(format!(
            "service_account_token: header '{header}' is transport-controlled and must not receive the service account token"
        )
        .into());
    }
    Ok(name)
}

/// Validate the configured header-value prefix.
fn validate_prefix(prefix: &str) -> Result<(), FilterError> {
    if prefix.len() > MAX_PREFIX_LEN {
        return Err(format!("service_account_token: prefix must be at most {MAX_PREFIX_LEN} bytes").into());
    }
    Ok(())
}

/// Validate a non-empty value against a byte limit.
fn validate_bounded(field: &str, value: &str, maximum: usize) -> Result<(), FilterError> {
    if value.trim().is_empty() || value.len() > maximum {
        return Err(format!("service_account_token: {field} must contain 1-{maximum} bytes").into());
    }
    Ok(())
}

/// Read and validate the complete token file.
///
/// Reads one byte beyond [`MAX_TOKEN_BYTES`] to distinguish an exact-limit
/// file from an oversized one without buffering an unbounded file in full.
/// The token value is never included in the returned error.
fn read_token(path: &Path) -> Result<Zeroizing<String>, FilterError> {
    let file = File::open(path).map_err(|error| -> FilterError {
        format!("service_account_token: cannot read '{}': {error}", path.display()).into()
    })?;
    let mut content = Zeroizing::new(String::new());
    file.take(MAX_TOKEN_READ_BYTES)
        .read_to_string(&mut content)
        .map_err(|error| -> FilterError {
            format!("service_account_token: cannot read '{}': {error}", path.display()).into()
        })?;
    if content.len() > MAX_TOKEN_BYTES {
        return Err(format!("service_account_token: token file exceeds {MAX_TOKEN_BYTES} bytes").into());
    }
    let token = Zeroizing::new(content.trim().to_owned());
    if token.is_empty() {
        return Err(format!("service_account_token: token file '{}' is empty", path.display()).into());
    }
    Ok(token)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;
