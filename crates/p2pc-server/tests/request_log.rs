// SPDX-License-Identifier: AGPL-3.0-only

//! The request log names the matched route template, never the raw URI path (T03 review P3): a path can carry a
//! secret (`/v1/keys/p2pc_sk_…`), and a key ID or job ID is not something to log per request either.
//!
//! This file holds a single test because it installs a process-wide subscriber.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use common::TestApp;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn the_log_names_the_route_template_and_never_the_raw_path() {
    let capture = Capture::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(capture.clone())
        .with_ansi(false)
        .init();

    let app = TestApp::new().await;
    let admin = app.admin.clone();
    // A path that holds a full key, on a matched route (the `{key_id}` parameter) and on an unmatched one.
    let secret_path = app.admin_key.expose();
    let r = app
        .call(Method::DELETE, &format!("/v1/keys/{secret_path}"), Some(&admin), None)
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = app
        .call(Method::GET, &format!("/nowhere/{secret_path}"), Some(&admin), None)
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = app.get("/v1/whoami?x=1", &admin).await;
    assert_eq!(r.status, StatusCode::OK);

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(!logs.contains("p2pc_sk_"), "a path with a key reached the log:\n{logs}");
    assert!(
        !logs.contains("nowhere"),
        "an unmatched raw path reached the log:\n{logs}"
    );
    // The matched routes are named by their template, the unknown one as `<unmatched>`.
    assert!(logs.contains("/v1/keys/{key_id}"), "{logs}");
    assert!(logs.contains("<unmatched>"), "{logs}");
    assert!(logs.contains("/v1/whoami"), "{logs}");
    assert!(!logs.contains("x=1"), "the query string reached the log:\n{logs}");
}
