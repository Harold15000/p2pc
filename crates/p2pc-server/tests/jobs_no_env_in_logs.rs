// SPDX-License-Identifier: AGPL-3.0-only

//! Hard rule 5 and SI-6: job `env` values (and input file contents) are never logged. Every jobs endpoint is
//! exercised with a secret value in the job, at TRACE, including a rejected job and a database that logs its
//! statements.
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

const ENV_VALUE: &str = "hunter2-ENV-VALUE-0451";
const REJECTED_ENV_VALUE: &str = "rejected-ENV-VALUE-9917\nINJECTED=1";
/// `secret file content` in base64, and the text itself.
const FILE_B64: &str = "c2VjcmV0IGZpbGUgY29udGVudA==";
const FILE_TEXT: &str = "secret file content";

#[tokio::test]
async fn no_env_value_or_file_content_reaches_the_logs() {
    let capture = Capture::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .init();

    let app = TestApp::new().await;
    let admin = app.admin.clone();
    let job = |env_value: &str| {
        json!({
            "image": "python:3.12-slim",
            "command": ["python", "-c", "print(6*7)"],
            "env": {"API_TOKEN": env_value},
            "files": [{"path": "/inputs/secret.txt", "content_b64": FILE_B64}],
            "resources": {"cpu": 1, "memory_mb": 512},
            "idempotency_key": "logs-1",
        })
    };

    // Create, replay, get, list, estimate and cancel the job.
    let r = app
        .call(Method::POST, "/v1/jobs", Some(&admin), Some(job(ENV_VALUE)))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", String::from_utf8_lossy(&r.body));
    let id = r.json()["id"].as_str().unwrap().to_string();
    let r = app
        .call(Method::POST, "/v1/jobs", Some(&admin), Some(job(ENV_VALUE)))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    // The same key with a different env value is a conflict; the answer does not repeat either value.
    let r = app
        .call(
            Method::POST,
            "/v1/jobs",
            Some(&admin),
            Some(job("another-ENV-VALUE-77")),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(!String::from_utf8_lossy(&r.body).contains("ENV-VALUE"));
    assert_eq!(app.get(&format!("/v1/jobs/{id}"), &admin).await.status, StatusCode::OK);
    assert_eq!(app.get("/v1/jobs", &admin).await.status, StatusCode::OK);
    let r = app
        .call(Method::POST, "/v1/estimate", Some(&admin), Some(job(ENV_VALUE)))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = app
        .call(
            Method::POST,
            "/v1/jobs/{id}/cancel".replace("{id}", &id).as_str(),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    // A rejected job (a newline in the value) and a bad body.
    let mut bad = job(REJECTED_ENV_VALUE);
    bad["idempotency_key"] = json!("logs-2");
    let r = app.call(Method::POST, "/v1/jobs", Some(&admin), Some(bad)).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!String::from_utf8_lossy(&r.body).contains("rejected-ENV-VALUE"));
    let mut typo = job(ENV_VALUE);
    typo["memroy_mb"] = json!(1);
    assert_eq!(
        app.call(Method::POST, "/v1/jobs", Some(&admin), Some(typo))
            .await
            .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // A key that fails the re-check, with a job that carries a secret.
    let (key, _) = app
        .create_key(json!({"scopes": ["jobs:write"], "expires_at": "2026-11-05T10:00:01Z"}))
        .await;
    app.clock.advance(time::Duration::seconds(5));
    let r = app
        .call(Method::POST, "/v1/jobs", Some(&key), Some(job(ENV_VALUE)))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    app.flush_audit().await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    // The harness really captured the requests (by route template) and the creation.
    assert!(logs.contains("/v1/jobs/{id}/cancel"), "{logs}");
    assert!(logs.contains("job created"), "{logs}");
    assert!(logs.contains(&id), "the job ID is logged, which is fine: {logs}");
    for secret in [
        ENV_VALUE,
        "ENV-VALUE",
        "rejected-ENV",
        "INJECTED",
        FILE_B64,
        FILE_TEXT,
        "another-ENV",
    ] {
        assert!(!logs.contains(secret), "{secret:?} reached the log:\n{logs}");
    }
}
