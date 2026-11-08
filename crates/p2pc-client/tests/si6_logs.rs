// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! SI-6 for the client's logs, in a test binary of its own: `tracing` caches per call site whether anyone listens, so a
//! subscriber installed for one test is only reliable when no other test runs in the same process.

use std::sync::Arc;

use p2pc_client::testing::{MockResponse, MockServer, MockTunnelServer, fixtures};
use p2pc_client::tunnel::{Tunnel, TunnelOptions};
use p2pc_client::{Client, RetryPolicy};
use p2pc_proto::api::Scope;
use p2pc_proto::auth::ApiKey;
use p2pc_proto::net::DirectAddresses;

/// Collects everything written by the subscriber.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

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

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// SI-6: with every crate logging at TRACE (reqwest, hyper, iroh, this client), no log line holds the key, over TCP
/// and over the tunnel, for a success and for a refused key.
#[tokio::test]
async fn the_key_never_appears_in_logs_over_either_transport() {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(captured.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let key = ApiKey::generate();
    let who = serde_json::to_value(fixtures::whoami(key.key_id(), vec![Scope::JobsRead])).unwrap();
    let tunnel_server = MockTunnelServer::start(move |_| MockResponse::json(200, &who));
    let tunnel = Tunnel::new(TunnelOptions {
        bind: DirectAddresses::Cidrs(vec!["127.0.0.0/8".parse().unwrap()]),
        server_addrs: tunnel_server.addrs(),
        ..TunnelOptions::new(tunnel_server.address())
    })
    .unwrap();
    let client = Client::builder_tunnel(tunnel.clone(), key.clone())
        .retry(RetryPolicy::none())
        .build()
        .unwrap();
    client.whoami().await.unwrap();
    let tcp_server = MockServer::start(|r| match r.route().as_str() {
        "GET /v1/whoami" => MockResponse::problem(401, "unauthorized", "the key was revoked"),
        _ => MockResponse::empty(404),
    });
    let tcp_client = Client::builder(tcp_server.url(), key.clone())
        .retry(RetryPolicy::none())
        .build()
        .unwrap();
    assert!(tcp_client.whoami().await.is_err());
    tunnel.close().await;

    let logs = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    assert!(!logs.is_empty(), "the capture works");
    let secret = key.expose();
    assert!(!logs.contains(secret.rsplit('_').next().unwrap()), "{logs}");
    // The requests really carried it, so the check above is not vacuous.
    assert!(
        tunnel_server.requests()[0]
            .header("authorization")
            .unwrap()
            .contains(&secret)
    );
    assert!(
        tcp_server.requests()[0]
            .header("authorization")
            .unwrap()
            .contains(&secret)
    );
}
