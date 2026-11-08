// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! SI-6 for `p2pc mcp`'s logs, in a test binary of its own: `tracing` caches per call site whether anyone listens, so a
//! subscriber installed for one test is only reliable when no other test runs in the same process.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use p2pc_cli::mcp::{McpConfig, McpServer};
use p2pc_client::testing::{MockResponse, MockServer};
use p2pc_client::{Client, RetryPolicy};
use p2pc_proto::api::JobStatus;
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::JobId;
use rmcp::ServiceExt;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn run_args() -> Value {
    json!({"image": "python:3.12-slim", "command": ["python", "-c", "print(6*7)"]})
}

/// With the real filter at its most verbose, a session whose messages hold a fake key (in a malformed request, an
/// unknown tool and a job's env) logs nothing that contains it.
#[tokio::test]
async fn logs_at_the_most_verbose_level_never_hold_request_contents() {
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Captured {
            self.clone()
        }
    }
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(p2pc_cli::mcp::log_filter(Some(
            "trace",
        ))))
        .with_writer(captured.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let fake = "p2pc_sk_abcdefghijkl_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"; // gitleaks:allow
    let job = serde_json::to_value(p2pc_client::testing::fixtures::job(
        JobId::generate(),
        JobStatus::Queued,
        None,
    ))
    .unwrap();
    let rest = MockServer::start(move |req| match req.route().as_str() {
        "POST /v1/jobs" => MockResponse::json(201, &job),
        _ => MockResponse::empty(404),
    });
    let key = ApiKey::generate();
    let results = tempfile::tempdir().unwrap();
    let client = Client::builder(rest.url(), key.clone())
        .retry(RetryPolicy::none())
        .build()
        .unwrap();
    let server = McpServer::new(client, &key, McpConfig::new(results.path().to_path_buf()));
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    let served = tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let (read, mut write) = tokio::io::split(client_io);
    let mut lines = BufReader::new(read).lines();
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}});
    write.write_all(format!("{init}\n").as_bytes()).await.unwrap();
    lines.next_line().await.unwrap();
    let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    write.write_all(format!("{initialized}\n").as_bytes()).await.unwrap();
    // A malformed message, an unknown tool and a job, each holding the fake key.
    write
        .write_all(format!("{{\"jsonrpc\": \"2.0\", \"id\": 2, \"method\": {fake}\n").as_bytes())
        .await
        .unwrap();
    let unknown = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": fake, "arguments": {"x": fake}}});
    write.write_all(format!("{unknown}\n").as_bytes()).await.unwrap();
    let mut run = run_args();
    run["env"] = json!({"TOKEN": fake});
    let call = json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "p2pc_run", "arguments": run}});
    write.write_all(format!("{call}\n").as_bytes()).await.unwrap();
    // Wait for the answer to the last call (id 4).
    loop {
        let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .expect("the server answers");
        if serde_json::from_str::<Value>(&line).is_ok_and(|v| v["id"] == 4) {
            break;
        }
    }
    drop((write, lines));
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("the session ends when the client goes")
        .unwrap();
    let logs = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    assert!(logs.contains("tool call"), "the capture works: {logs}");
    assert!(!logs.contains("FAKEFAKE"), "{logs}");
}
