// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! `relay_tcp`, the splice behind `p2pc proxy`, with short limits: idle, half-close, server close, and an upload that
//! fails while the answer is on its way. The server is a raw iroh endpoint on loopback (relays disabled) that hands
//! each stream to the test, so the test decides exactly what the far end does.

use std::time::Duration;

use iroh::endpoint::{PortmapperConfig, RecvStream, SendStream, presets};
use iroh::{Endpoint, RelayMode, SecretKey};
use p2pc_client::tunnel::{RelayEnd, RelayLimits, Tunnel, TunnelOptions, relay_tcp};
use p2pc_proto::PROTOCOL_ALPN_HTTP;
use p2pc_proto::auth::ServerAddress;
use p2pc_proto::net::DirectAddresses;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// Bound for anything that should happen promptly; only reached when something is broken.
const WAIT: Duration = Duration::from_secs(10);

/// A raw `p2pc/http/1` server: every bidirectional stream goes to the test.
struct RawServer {
    endpoint: Endpoint,
    streams: mpsc::UnboundedReceiver<(SendStream, RecvStream)>,
}

impl RawServer {
    async fn start() -> Self {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .alpns(vec![PROTOCOL_ALPN_HTTP.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .portmapper_config(PortmapperConfig::Disabled)
            .clear_address_lookup()
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let (tx, streams) = mpsc::unbounded_channel();
        let accepting = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accepting.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    while let Ok(pair) = conn.accept_bi().await {
                        let _ = tx.send(pair);
                    }
                });
            }
        });
        Self { endpoint, streams }
    }

    fn tunnel(&self) -> Tunnel {
        Tunnel::new(TunnelOptions {
            bind: DirectAddresses::Cidrs(vec!["127.0.0.0/8".parse().unwrap()]),
            server_addrs: self.endpoint.bound_sockets(),
            ..TunnelOptions::new(ServerAddress::new(self.endpoint.id().to_string(), vec![]))
        })
        .unwrap()
    }

    /// The next stream a client opened (a stream reaches the server with its first bytes).
    async fn next(&mut self) -> (SendStream, RecvStream) {
        tokio::time::timeout(WAIT, self.streams.recv()).await.unwrap().unwrap()
    }
}

/// A local TCP pair: the side the proxy relays, and the side the "application" uses.
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (proxied, _) = listener.accept().await.unwrap();
    (proxied, app)
}

fn limits(idle_ms: u64, after_close_ms: u64) -> RelayLimits {
    RelayLimits {
        idle: Duration::from_millis(idle_ms),
        after_local_close: Duration::from_millis(after_close_ms),
    }
}

async fn read_exact_n(recv: &mut RecvStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(WAIT, recv.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    buf
}

#[tokio::test]
async fn a_silent_connection_ends_after_the_idle_limit_and_the_stream_is_reset() {
    let mut server = RawServer::start().await;
    let tunnel = server.tunnel();
    let (proxied, mut app) = tcp_pair().await;
    let relay = tokio::spawn(relay_tcp(
        tunnel.open_stream().await.unwrap(),
        proxied,
        limits(200, 5_000),
    ));
    app.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
    let (_send, mut recv) = server.next().await;
    assert_eq!(read_exact_n(&mut recv, 16).await, b"GET / HTTP/1.1\r\n");
    // Nobody sends anything more.
    let end = tokio::time::timeout(WAIT, relay).await.unwrap().unwrap();
    assert_eq!(end, RelayEnd::Idle);
    // The server's side sees the stream reset at once, not a clean end it would wait on.
    let rest = tokio::time::timeout(WAIT, recv.read_to_end(1024)).await.unwrap();
    assert!(rest.is_err(), "{rest:?}");
    tunnel.close().await;
}

#[tokio::test]
async fn after_a_half_close_the_answer_still_comes_then_the_relay_ends() {
    let mut server = RawServer::start().await;
    let tunnel = server.tunnel();
    let (proxied, mut app) = tcp_pair().await;
    let relay = tokio::spawn(relay_tcp(
        tunnel.open_stream().await.unwrap(),
        proxied,
        // The window starts at the half-close and the answer must arrive inside it: 2 s leaves a loaded machine room
        // (300 ms did not), and the test still ends well before the 60 s idle limit.
        limits(60_000, 2_000),
    ));
    app.write_all(b"request").await.unwrap();
    app.shutdown().await.unwrap();
    let (mut send, mut recv) = server.next().await;
    assert_eq!(read_exact_n(&mut recv, 7).await, b"request");
    // The answer, after the client's half-close, is delivered.
    send.write_all(b"answer").await.unwrap();
    let mut got = [0u8; 6];
    tokio::time::timeout(WAIT, app.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"answer");
    // Then the far end goes quiet: the relay ends after the short window, well before the idle limit.
    let end = tokio::time::timeout(WAIT, relay).await.unwrap().unwrap();
    assert_eq!(end, RelayEnd::ClientClosed);
    tunnel.close().await;
}

#[tokio::test]
async fn when_the_server_ends_the_stream_the_client_gets_everything_then_eof() {
    let mut server = RawServer::start().await;
    let tunnel = server.tunnel();
    let (proxied, mut app) = tcp_pair().await;
    let relay = tokio::spawn(relay_tcp(
        tunnel.open_stream().await.unwrap(),
        proxied,
        limits(60_000, 60_000),
    ));
    app.write_all(b"request").await.unwrap();
    let (mut send, mut recv) = server.next().await;
    assert_eq!(read_exact_n(&mut recv, 7).await, b"request");
    send.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
        .await
        .unwrap();
    send.finish().unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(WAIT, app.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
    let end = tokio::time::timeout(WAIT, relay).await.unwrap().unwrap();
    assert_eq!(end, RelayEnd::ServerClosed);
    tunnel.close().await;
}

/// T11b1 review: when the server stops reading (its REST side is done) while the client is still uploading, the
/// relay stops uploading but still delivers the answer the server sent.
#[tokio::test]
async fn a_failed_upload_does_not_lose_the_answer() {
    let mut server = RawServer::start().await;
    let tunnel = server.tunnel();
    let (proxied, app) = tcp_pair().await;
    let relay = tokio::spawn(relay_tcp(
        tunnel.open_stream().await.unwrap(),
        proxied,
        limits(60_000, 2_000),
    ));
    let (mut app_read, mut app_write) = app.into_split();
    // The application uploads without end.
    let uploader = tokio::spawn(async move {
        let chunk = vec![b'x'; 16 * 1024];
        while app_write.write_all(&chunk).await.is_ok() {}
    });
    let (mut send, mut recv) = server.next().await;
    let _ = read_exact_n(&mut recv, 1024).await;
    // The server stops reading first, and only then answers and ends its side.
    recv.stop(0u32.into()).unwrap();
    // The answer must arrive *after* the relay's upload has failed on the stop, which the far end cannot observe;
    // this pause only orders the two events (with an answer that arrives first, any relay delivers it).
    tokio::time::sleep(Duration::from_millis(300)).await;
    let answer = b"HTTP/1.1 413 Payload Too Large\r\ncontent-length: 0\r\n\r\n";
    send.write_all(answer).await.unwrap();
    send.finish().unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(WAIT, app_read.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, answer);
    let end = tokio::time::timeout(WAIT, relay).await.unwrap().unwrap();
    assert_eq!(end, RelayEnd::ServerClosed);
    uploader.abort();
    tunnel.close().await;
}
