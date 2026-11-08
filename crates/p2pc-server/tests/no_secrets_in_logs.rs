// SPDX-License-Identifier: AGPL-3.0-only

//! SI-6: an authenticated request, a failed one and a key creation leave no secret in the logs, even at TRACE.
//!
//! This file holds a single test because it installs a process-wide subscriber (the SQLite worker logs from its own
//! thread, so a thread-local subscriber would miss it).

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use common::TestApp;
use p2pc_proto::auth::{ApiKey, Secret};
use serde_json::json;
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
async fn no_secret_reaches_the_logs() {
    let capture = Capture::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .init();

    let app = TestApp::new().await;
    let admin = app.admin.clone();
    let r = app.get("/v1/whoami", &admin).await;
    assert_eq!(r.status, StatusCode::OK);
    let (created, _) = app.create_key(json!({"scopes": ["jobs:read"], "label": "ci"})).await;
    assert_eq!(app.get("/v1/whoami", &created).await.status, StatusCode::OK);
    let wrong = ApiKey::from_parts(app.admin_key.key_id(), Secret::generate()).expose();
    assert_eq!(app.get("/v1/whoami", &wrong).await.status, StatusCode::UNAUTHORIZED);
    let r = app.call(Method::GET, "/v1/keys", Some(&admin), None).await;
    assert_eq!(r.status, StatusCode::OK);

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    // The harness really captured the requests.
    assert!(logs.contains("/v1/whoami"), "{logs}");
    for key in [&admin, &created, &wrong] {
        let secret = &key["p2pc_sk_".len() + 13..];
        assert!(!logs.contains(secret), "secret of {} leaked:\n{logs}", &key[..20]);
    }
    assert!(!logs.to_ascii_lowercase().contains("authorization"), "{logs}");
    assert!(!logs.contains("Bearer"), "{logs}");
}
