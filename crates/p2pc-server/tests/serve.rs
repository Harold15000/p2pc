// SPDX-License-Identifier: AGPL-3.0-only

//! `serve` over a real loopback socket: requests work and the server shuts down gracefully.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use p2pc_server::app::AppState;
use p2pc_server::clock::SystemClock;
use p2pc_server::config::Config;
use p2pc_server::store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn http_get(addr: std::net::SocketAddr, path: &str, key: Option<&str>) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let auth = key
        .map(|k| format!("Authorization: Bearer {k}\r\n"))
        .unwrap_or_default();
    let req = format!("GET {path} HTTP/1.1\r\nHost: p2pc.example.invalid\r\n{auth}Connection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

#[tokio::test]
async fn serves_over_loopback_and_shuts_down_gracefully() {
    let tmp = tempfile::tempdir().unwrap();
    let out = p2pc_server::init::init(&tmp.path().join("data"), &SystemClock)
        .await
        .unwrap();
    let config = Config::load(&out.config_path).unwrap();
    let db = store::open(&config.db_path(), store::OpenMode::Existing).await.unwrap();
    let state = AppState::load(db, config, Arc::new(SystemClock)).await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(p2pc_server::serve::serve_on(listener, state, async {
        let _ = stop_rx.await;
    }));

    let health = http_get(addr, "/healthz", None).await;
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(health.ends_with(r#"{"status":"ok"}"#), "{health}");
    let whoami = http_get(addr, "/v1/whoami", Some(&out.admin_key.expose())).await;
    assert!(whoami.starts_with("HTTP/1.1 200"), "{whoami}");
    assert!(whoami.contains(&out.admin_key.key_id().to_string()), "{whoami}");
    // Loopback gets no bypass.
    let anon = http_get(addr, "/v1/whoami", None).await;
    assert!(anon.starts_with("HTTP/1.1 401"), "{anon}");

    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "still listening after shutdown"
    );
}

#[tokio::test]
async fn serve_refuses_a_missing_database() {
    let tmp = tempfile::tempdir().unwrap();
    let err = store::open(&tmp.path().join("p2pc.db"), store::OpenMode::Existing)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("p2pc-server init"), "{err}");
}
