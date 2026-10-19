// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use http::Method;

use super::*;

// -------------------------------------------------------------------------
// Config Validation
// -------------------------------------------------------------------------

#[test]
fn missing_file_rejected_at_construction() {
    let err = parse("token_file: /nonexistent/path/to/token")
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("cannot read"), "{err}");
}

#[test]
fn empty_file_rejected_at_construction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, "   \n").unwrap();
    let yaml = format!("token_file: {}", path.display());
    let err = parse(&yaml).err().expect("empty file must be rejected");
    assert!(err.to_string().contains("is empty"), "{err}");
}

#[test]
fn oversized_file_rejected_at_construction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, vec![b't'; MAX_TOKEN_BYTES + 1]).unwrap();
    let yaml = format!("token_file: {}", path.display());
    let err = parse(&yaml).err().expect("oversized file must be rejected");
    assert!(err.to_string().contains("exceeds"), "{err}");
}

#[test]
fn blank_token_file_path_rejected() {
    let err = parse("token_file: ''").err().expect("must fail");
    assert!(err.to_string().contains("token_file"), "{err}");
}

#[test]
fn reserved_prefix_header_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "tok");
    for header in [
        "x-praxis-internal",
        "x-mcp-authorized",
        "x-ext-agent-token",
        "x-ext-protocol-token",
    ] {
        let yaml = format!("token_file: {}\nheader: {header}", path.display());
        let err = parse(&yaml).err().expect("reserved header must be rejected");
        assert!(err.to_string().contains("is reserved"), "{header}: {err}");
    }
}

#[test]
fn transport_controlled_header_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "tok");
    for header in ["host", "content-length", "proxy-authorization"] {
        let yaml = format!("token_file: {}\nheader: {header}", path.display());
        let err = parse(&yaml)
            .err()
            .expect("transport-controlled header must be rejected");
        assert!(err.to_string().contains("transport-controlled"), "{header}: {err}");
    }
}

#[test]
fn oversized_prefix_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "tok");
    let long_prefix = "a".repeat(MAX_PREFIX_LEN + 1);
    let yaml = format!("token_file: {}\nprefix: '{long_prefix}'", path.display());
    let err = parse(&yaml).err().expect("oversized prefix must be rejected");
    assert!(err.to_string().contains("prefix"), "{err}");
}

#[test]
fn valid_minimal_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "tok");
    let yaml = format!("token_file: {}", path.display());
    assert!(parse(&yaml).is_ok(), "valid config must parse");
}

// -------------------------------------------------------------------------
// Request-Time Injection
// -------------------------------------------------------------------------

#[tokio::test]
async fn injects_default_authorization_bearer_header() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "sa-jwt-value");
    let f = parse(&format!("token_file: {}", path.display())).unwrap();
    let req = crate::test_utils::make_request(Method::POST, "/v1/checks");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = f.on_request(&mut ctx).await.unwrap();
    assert!(matches!(action, FilterAction::Continue));
    assert!(
        ctx.request_headers_to_set.is_empty(),
        "the token stays off the in-chain request until the destination matches"
    );
    assert!(ctx.request_headers_to_remove.contains(&AUTHORIZATION));
    let pending = ctx.extensions.get::<PendingCredentials>().expect("credential staged");
    assert!(!pending.is_empty());
}

#[tokio::test]
async fn strips_caller_supplied_authorization_before_setting() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "sa-jwt-value");
    let f = parse(&format!("token_file: {}", path.display())).unwrap();
    let mut req = crate::test_utils::make_request(Method::POST, "/v1/checks");
    req.headers
        .insert(AUTHORIZATION, HeaderValue::from_static("Bearer smuggled"));
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(f.on_request(&mut ctx).await.unwrap());
    assert!(ctx.request_headers_to_remove.contains(&AUTHORIZATION));
    assert!(ctx.request_headers_to_set.is_empty());
    assert!(!ctx.extensions.get::<PendingCredentials>().unwrap().is_empty());
}

#[tokio::test]
async fn custom_header_and_empty_prefix_injects_raw_token() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "raw-token");
    let yaml = format!("token_file: {}\nheader: x-service-token\nprefix: ''", path.display());
    let f = parse(&yaml).unwrap();
    let req = crate::test_utils::make_request(Method::POST, "/v1/checks");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(f.on_request(&mut ctx).await.unwrap());
    assert!(ctx.request_headers_to_set.is_empty());
    assert!(
        ctx.request_headers_to_remove
            .iter()
            .any(|name| name == "x-service-token")
    );
    assert!(!ctx.extensions.get::<PendingCredentials>().unwrap().is_empty());
}

// -------------------------------------------------------------------------
// Rotation / Watcher
// -------------------------------------------------------------------------

#[test]
fn authoritative_startup_reread_replaces_pre_watcher_snapshot() {
    // Pre-populate the snapshot with token-b (simulates the value read at
    // construction), write token-c to the file, then start the watcher.
    // The authoritative re-read inside spawn_token_watcher must publish
    // token-c before returning.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, "token-b\n").unwrap();

    let snapshot = Arc::new(ArcSwap::from_pointee(TokenSnapshot {
        header_value: Some(Zeroizing::new("Bearer token-b".to_owned())),
    }));

    std::fs::write(&path, "token-c\n").unwrap();
    let handle = spawn_token_watcher(path, DEFAULT_PREFIX.to_owned(), Arc::clone(&snapshot)).unwrap();

    assert_eq!(
        snapshot.load().header_value.as_deref().unwrap(),
        "Bearer token-c",
        "authoritative re-read must overwrite the pre-watcher snapshot"
    );
    drop(handle);
}

#[test]
fn watcher_event_matches_canonical_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "token-a");
    let canonical = path.canonicalize().unwrap();
    std::fs::write(&path, "token-b\n").unwrap();

    let snapshot = Arc::new(ArcSwap::from_pointee(TokenSnapshot {
        header_value: Some(Zeroizing::new("Bearer token-a".to_owned())),
    }));
    process_watcher_event(
        &notify::Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(notify::event::DataChange::Content)),
            paths: vec![canonical],
            attrs: notify::event::EventAttributes::new(),
        },
        &path,
        DEFAULT_PREFIX,
        &snapshot,
    );

    assert_eq!(snapshot.load().header_value.as_deref().unwrap(), "Bearer token-b");
}

#[tokio::test]
async fn relative_token_file_observes_rotation_and_delete() {
    let name = format!("sa-token-rel-{}", std::process::id());
    let path = std::env::current_dir().unwrap().join(&name);
    let replacement = path.with_extension("next");
    std::fs::write(&path, "token-a\n").unwrap();
    let _cleanup = RemoveFiles(vec![path.clone(), replacement.clone()]);

    let f = open(&format!("token_file: {name}"));
    assert_eq!(f.snapshot.load().header_value.as_deref().unwrap(), "Bearer token-a");

    std::fs::write(&replacement, "token-b\n").unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    wait_for_snapshot(&f, "relative token path did not observe rotation", |header| {
        header == Some("Bearer token-b")
    })
    .await;

    std::fs::remove_file(&path).unwrap();
    wait_for_snapshot(&f, "relative token path did not observe deletion", |header| {
        header.is_none()
    })
    .await;
}

#[tokio::test]
async fn rotation_is_observed_without_restarting_filter() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "token-a");
    let f = open(&format!("token_file: {}", path.display()));
    assert_eq!(f.snapshot.load().header_value.as_deref().unwrap(), "Bearer token-a");

    // Replacing the token path itself. A projected volume does not do
    // this; see `watcher_detects_data_symlink_swap`.
    let replacement = dir.path().join("token.next");
    std::fs::write(&replacement, "token-b\n").unwrap();
    std::fs::rename(replacement, &path).unwrap();

    wait_for_snapshot(&f, "watcher did not publish the rotated token", |header| {
        header == Some("Bearer token-b")
    })
    .await;

    let req = crate::test_utils::make_request(Method::POST, "/v1/checks");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(f.on_request(&mut ctx).await.unwrap());
    assert!(!ctx.extensions.get::<PendingCredentials>().unwrap().is_empty());
}

/// Kubelet rotates a projected token by swapping the `..data` symlink.
/// The `token` symlink keeps pointing at `..data/token`, so an exact path
/// match never sees the rotation. Same layout as `watcher_detects_symlink_swap`.
#[cfg(unix)]
#[tokio::test]
async fn watcher_detects_data_symlink_swap() {
    let dir = tempfile::tempdir().unwrap();
    let token_path = write_projected_token(dir.path());
    let f = open(&format!("token_file: {}", token_path.display()));
    assert_eq!(f.snapshot.load().header_value.as_deref().unwrap(), "Bearer token-a");

    swap_projected_data(dir.path());
    assert_eq!(
        std::fs::read_link(&token_path).unwrap(),
        Path::new("..data/token"),
        "kubelet leaves the token symlink in place"
    );
    wait_for_snapshot(&f, "watcher did not observe the ..data symlink swap", |header| {
        header == Some("Bearer token-b")
    })
    .await;
}

#[tokio::test]
async fn token_deleted_after_construction_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "token-a");
    let f = parse(&format!("token_file: {}", path.display())).unwrap();
    std::fs::remove_file(&path).unwrap();

    let req = crate::test_utils::make_request(Method::POST, "/v1/checks");
    // Poll until the watcher publishes the fail-closed None snapshot.
    let mut ctx = crate::test_utils::make_filter_context(&req);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            ctx.request_headers_to_set.clear();
            let action = f.on_request(&mut ctx).await.unwrap();
            if matches!(&action, FilterAction::Reject(rejection) if rejection.status == 503) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("watcher did not publish the fail-closed snapshot after file deletion");
    assert!(ctx.request_headers_to_set.is_empty());
}

#[test]
fn watcher_shutdown_wakes_without_receive_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "tok");
    let filter = parse(&format!("token_file: {}", path.display())).unwrap();
    let started = std::time::Instant::now();
    drop(filter);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "watcher teardown should be woken by shutdown, not block until the 5s receive timeout"
    );
}

#[tokio::test]
async fn token_not_in_filter_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "super-secret-sa-token");
    let f = parse(&format!("token_file: {}", path.display())).unwrap();
    let req = crate::test_utils::make_request(Method::POST, "/v1/checks");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    drop(f.on_request(&mut ctx).await.unwrap());
    for value in ctx.filter_metadata.values() {
        assert!(
            !value.contains("super-secret-sa-token"),
            "token must not leak into filter_metadata: {value}"
        );
    }
}

// -------------------------------------------------------------------------
// Security: token not in logs on invalid reload
// -------------------------------------------------------------------------

#[test]
fn invalid_token_replacement_fails_closed_without_token_in_logs() {
    // A rotated token containing a NUL byte is valid UTF-8 but not a
    // valid HTTP header value. reload_token must set the snapshot to None
    // (fail closed) and must NOT include the token value in the warning —
    // only the path and the HTTP error appear (verified by inspection of
    // the tracing::warn! call in reload_token, which logs path and error
    // but not the assembled value).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    // A NUL byte is rejected by HeaderValue::from_str.
    std::fs::write(&path, b"valid-prefix\x00invalid-suffix\n").unwrap();

    let snapshot = Arc::new(ArcSwap::from_pointee(TokenSnapshot {
        header_value: Some(Zeroizing::new("Bearer old-token".to_owned())),
    }));

    reload_token(&path, DEFAULT_PREFIX, &snapshot);

    assert!(
        snapshot.load().header_value.is_none(),
        "snapshot must be None after a reload with an invalid HTTP header value"
    );
}

#[test]
fn watcher_notify_error_clears_token_and_shutdown_preserves_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "old-token");
    let snapshot = Arc::new(ArcSwap::from_pointee(TokenSnapshot {
        header_value: Some(Zeroizing::new("Bearer old-token".to_owned())),
    }));

    assert!(handle_watcher_message(
        WatcherMessage::NotifyError,
        &path,
        DEFAULT_PREFIX,
        &snapshot
    ));
    assert!(
        snapshot.load().header_value.is_none(),
        "a watcher error must clear the token so requests fail closed"
    );

    snapshot.store(Arc::new(TokenSnapshot {
        header_value: Some(Zeroizing::new("Bearer old-token".to_owned())),
    }));
    assert!(!handle_watcher_message(
        WatcherMessage::Shutdown,
        &path,
        DEFAULT_PREFIX,
        &snapshot
    ));
    assert_eq!(snapshot.load().header_value.as_deref().unwrap(), "Bearer old-token");
}

// -------------------------------------------------------------------------
// Test Utilities
// -------------------------------------------------------------------------

#[test]
fn endpoint_authority_fixed_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "tok");
    let https = open(&format!(
        "token_file: {}\nendpoint: https://nemo.example/v1/checks",
        path.display()
    ));
    assert_eq!(https.authority, "nemo.example:443");

    let explicit = open(&format!(
        "token_file: {}\nendpoint: http://127.0.0.1:3001/v1/checks",
        path.display()
    ));
    assert_eq!(explicit.authority, "127.0.0.1:3001");

    let ipv6 = open(&format!(
        "token_file: {}\nendpoint: \"http://[::1]:8443/v1/checks\"",
        path.display()
    ));
    assert_eq!(ipv6.authority, "[::1]:8443");
}

#[test]
fn malformed_endpoint_rejected_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "tok");
    for endpoint in ["not a url", "http://"] {
        let yaml = format!("token_file: {}\nendpoint: '{endpoint}'", path.display());
        let err = from_yaml(&yaml).err().expect("malformed endpoint must be rejected");
        assert!(err.to_string().contains("credential binding"), "{endpoint}: {err}");
    }
}

#[test]
fn non_http_endpoint_rejected_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "tok");
    for endpoint in ["foo://nemo.example/v1", "ftp://nemo.example/v1", "ws://nemo.example/v1"] {
        let yaml = format!("token_file: {}\nendpoint: '{endpoint}'", path.display());
        let err = from_yaml(&yaml).err().expect("non-http endpoint must be rejected");
        assert!(err.to_string().contains("is not http or https"), "{endpoint}: {err}");
    }
}

#[test]
fn missing_endpoint_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "tok");
    let yaml = format!("token_file: {}", path.display());
    let err = from_yaml(&yaml).err().expect("missing endpoint must be rejected");
    assert!(err.to_string().contains("endpoint"), "{err}");
}

/// Deletes the listed paths when dropped, including after a panic.
struct RemoveFiles(Vec<PathBuf>);

impl Drop for RemoveFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            drop(std::fs::remove_file(path));
        }
    }
}

/// Poll until `ready` accepts the published header value, or the snapshot is empty.
async fn wait_for_snapshot(
    filter: &ServiceAccountTokenFilter,
    message: &'static str,
    ready: impl Fn(Option<&str>) -> bool + Send + Sync,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = filter.snapshot.load();
            let header = snapshot.header_value.as_deref().map(String::as_str);
            if ready(header) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect(message);
}

/// `token` -> `..data/token`, with `..data` pointing at `data_v1`.
/// `data_v2` holds the rotated bytes but is not linked yet.
#[cfg(unix)]
fn write_projected_token(dir: &Path) -> PathBuf {
    let data_v1 = dir.join("data_v1");
    let data_v2 = dir.join("data_v2");
    std::fs::create_dir(&data_v1).unwrap();
    std::fs::create_dir(&data_v2).unwrap();
    std::fs::write(data_v1.join("token"), "token-a\n").unwrap();
    std::fs::write(data_v2.join("token"), "token-b\n").unwrap();
    std::os::unix::fs::symlink(&data_v1, dir.join("..data")).unwrap();
    let token_path = dir.join("token");
    std::os::unix::fs::symlink("..data/token", &token_path).unwrap();
    token_path
}

/// `AtomicWriter` swap: point `..data` at `data_v2` without rewriting `token`.
#[cfg(unix)]
fn swap_projected_data(dir: &Path) {
    let tmp_link = dir.join("..data_tmp");
    std::os::unix::fs::symlink(dir.join("data_v2"), &tmp_link).unwrap();
    std::fs::rename(&tmp_link, dir.join("..data")).unwrap();
}

fn write_token(dir: &tempfile::TempDir, token: &str) -> PathBuf {
    let path = dir.path().join("token");
    std::fs::write(&path, format!("{token}\n")).unwrap();
    path
}

fn ensure_endpoint(yaml: &str) -> String {
    if yaml.contains("endpoint:") {
        yaml.to_owned()
    } else {
        format!("{yaml}\nendpoint: http://nemo.example/v1/checks")
    }
}

fn from_yaml(yaml: &str) -> Result<ServiceAccountTokenFilter, FilterError> {
    let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    ServiceAccountTokenFilter::build(&val)
}

fn open(yaml: &str) -> ServiceAccountTokenFilter {
    from_yaml(&ensure_endpoint(yaml)).unwrap()
}

fn parse(yaml: &str) -> Result<Box<dyn HttpFilter>, FilterError> {
    Ok(Box::new(from_yaml(&ensure_endpoint(yaml))?))
}
