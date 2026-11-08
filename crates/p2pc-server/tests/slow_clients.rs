// SPDX-License-Identifier: AGPL-3.0-only

//! Spec §10 "Slow clients" (review P2): header, body, whole-request and keep-alive idle limits, and the connection
//! cap, over a real loopback socket. The limits come from `[http]` in the config, set short here so the tests take
//! milliseconds; the defaults are 10 s / 30 s / 30 s / 60 s and 256 connections.
//!
//! These tests observe time-based behaviour, so they wait on the socket with bounded `timeout`s; nothing sleeps to
//! synchronise.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use p2pc_server::app::AppState;
use p2pc_server::clock::SystemClock;
use p2pc_server::config::{Config, HttpConfig};
use p2pc_server::store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

struct Server {
    addr: SocketAddr,
    key: String,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    _tmp: tempfile::TempDir,
}

impl Server {
    async fn start(http: HttpConfig) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let out = p2pc_server::init::init(&tmp.path().join("data"), &SystemClock)
            .await
            .unwrap();
        let mut config = Config::load(&out.config_path).unwrap();
        config.http = http;
        // §10 "Tunnel budget": tunnelled streams stay below the REST cap, which these tests lower to 2.
        config.iroh.tunnel_max_streams = config.iroh.tunnel_max_streams.min(config.http.max_connections - 1);
        assert!(config.problems().is_empty(), "{:?}", config.problems());
        let db = store::open(&config.db_path(), store::OpenMode::Existing).await.unwrap();
        let state = AppState::load(db, config, Arc::new(SystemClock)).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(p2pc_server::serve::serve_on(listener, state, async {
            let _ = stopped.await;
        }));
        Self {
            addr,
            key: out.admin_key.expose(),
            stop: Some(stop),
            task: Some(task),
            _tmp: tmp,
        }
    }

    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.task.take().unwrap().await.unwrap().unwrap();
    }
}

fn limits(header_ms: u64, body_ms: u64, request_ms: u64, idle_ms: u64, max_connections: u32) -> HttpConfig {
    HttpConfig {
        max_connections,
        header_read_timeout_ms: header_ms,
        body_read_timeout_ms: body_ms,
        request_timeout_ms: request_ms,
        keepalive_idle_ms: idle_ms,
    }
}

/// Reads one HTTP/1.1 response (head and `Content-Length` body). `None` if the server closed the connection first.
async fn read_response(s: &mut TcpStream) -> Option<(u16, String)> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    let head = String::from_utf8_lossy(&head).to_string();
    let status = head.get(9..12)?.parse().ok()?;
    let len = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; len];
    s.read_exact(&mut body).await.ok()?;
    Some((status, String::from_utf8_lossy(&body).to_string()))
}

/// Whether the server has closed the connection (EOF or reset) within `within`.
async fn closed_within(s: &mut TcpStream, within: Duration) -> bool {
    let mut buf = [0u8; 256];
    matches!(
        tokio::time::timeout(within, s.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

const HEALTHZ: &[u8] = b"GET /healthz HTTP/1.1\r\nHost: p2pc.example.invalid\r\n\r\n";

#[tokio::test]
async fn a_client_trickling_header_bytes_is_cut_off() {
    let server = Server::start(limits(300, 30_000, 30_000, 60_000, 256)).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(b"GET /healthz HTTP/1.1\r\nHost: p2pc.example.invalid\r\n")
        .await
        .unwrap();
    let start = Instant::now();
    let mut cut = false;
    // One more header line every 50 ms: data keeps arriving, but the head never completes.
    for i in 0..60 {
        if s.write_all(format!("X-Slow-{i}: 1\r\n").as_bytes()).await.is_err()
            || closed_within(&mut s, Duration::from_millis(50)).await
        {
            cut = true;
            break;
        }
    }
    assert!(cut, "still open after {:?}", start.elapsed());
    // Counted from the first byte, not reset by later ones.
    assert!(start.elapsed() < Duration::from_secs(2), "{:?}", start.elapsed());
    server.stop().await;
}

#[tokio::test]
async fn keep_alive_idle_is_longer_than_the_header_limit_and_still_bounded() {
    let server = Server::start(limits(200, 30_000, 30_000, 800, 256)).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(HEALTHZ).await.unwrap();
    assert_eq!(read_response(&mut s).await.unwrap().0, 200);
    // Idle longer than the header limit: the connection must still be usable (a header limit alone would cut it).
    assert!(
        !closed_within(&mut s, Duration::from_millis(400)).await,
        "closed while idle under the idle limit"
    );
    s.write_all(HEALTHZ).await.unwrap();
    assert_eq!(read_response(&mut s).await.unwrap().0, 200);
    // Then idle past the idle limit: closed.
    let start = Instant::now();
    assert!(
        closed_within(&mut s, Duration::from_secs(3)).await,
        "idle connection never closed"
    );
    assert!(
        start.elapsed() >= Duration::from_millis(700),
        "closed too early: {:?}",
        start.elapsed()
    );
    server.stop().await;
}

#[tokio::test]
async fn a_new_connection_that_sends_nothing_is_closed_after_the_header_limit() {
    let server = Server::start(limits(300, 30_000, 30_000, 60_000, 256)).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    assert!(closed_within(&mut s, Duration::from_secs(3)).await);
    server.stop().await;
}

fn stalled_post(key: &str) -> Vec<u8> {
    // Announces 100 bytes and sends 10.
    format!(
        "POST /v1/keys HTTP/1.1\r\nHost: p2pc.example.invalid\r\nAuthorization: Bearer {key}\r\n\
         Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{{\"scopes\":"
    )
    .into_bytes()
}

#[tokio::test]
async fn a_client_stalling_the_body_is_cut_off() {
    let server = Server::start(limits(10_000, 300, 30_000, 60_000, 256)).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(&stalled_post(&server.key)).await.unwrap();
    let start = Instant::now();
    let (status, body) = tokio::time::timeout(Duration::from_secs(3), read_response(&mut s))
        .await
        .expect("no answer to a stalled body")
        .expect("closed without an answer");
    assert_eq!(status, 408, "{body}");
    assert!(body.contains("\"code\":\"request_timeout\""), "{body}");
    assert!(start.elapsed() < Duration::from_secs(2));
    server.stop().await;
}

#[tokio::test]
async fn the_whole_request_limit_applies_even_when_the_body_limit_is_longer() {
    let server = Server::start(limits(10_000, 30_000, 300, 60_000, 256)).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(&stalled_post(&server.key)).await.unwrap();
    let (status, body) = tokio::time::timeout(Duration::from_secs(3), read_response(&mut s))
        .await
        .expect("no answer within the whole-request limit")
        .expect("closed without an answer");
    assert_eq!(status, 408, "{body}");
    assert!(body.contains("\"code\":\"request_timeout\""), "{body}");
    server.stop().await;
}

#[tokio::test]
async fn the_connection_over_the_cap_waits_until_another_closes() {
    let server = Server::start(limits(10_000, 30_000, 30_000, 60_000, 2)).await;
    // Two connections, served and kept alive: they hold both slots.
    let mut first = TcpStream::connect(server.addr).await.unwrap();
    let mut second = TcpStream::connect(server.addr).await.unwrap();
    for s in [&mut first, &mut second] {
        s.write_all(HEALTHZ).await.unwrap();
        assert_eq!(read_response(s).await.unwrap().0, 200);
    }
    // The third connects (the kernel backlog accepts it) but is not served.
    let mut third = TcpStream::connect(server.addr).await.unwrap();
    third.write_all(HEALTHZ).await.unwrap();
    let early = tokio::time::timeout(Duration::from_millis(300), read_response(&mut third)).await;
    assert!(early.is_err(), "served over the cap: {early:?}");
    // One closes: the third is served.
    drop(first);
    let late = tokio::time::timeout(Duration::from_secs(3), read_response(&mut third))
        .await
        .expect("still waiting after a slot was freed");
    assert_eq!(late.unwrap().0, 200);
    drop(second);
    drop(third);
    server.stop().await;
}

#[test]
fn http_limits_default_to_the_spec_and_are_validated() {
    let c = Config::parse("data_dir = \"/srv/p2pc\"\n", std::path::Path::new("server.toml")).unwrap();
    assert_eq!(c.http, limits(10_000, 30_000, 30_000, 60_000, 256));
    let bad = "data_dir = \"/srv/p2pc\"\n[http]\nmax_connections = 0\nheader_read_timeout_ms = 0\n\
               body_read_timeout_ms = 0\nrequest_timeout_ms = 99999999\nkeepalive_idle_ms = 0\n";
    let err = Config::parse(bad, std::path::Path::new("server.toml")).unwrap_err();
    let text = err.to_string();
    for field in [
        "http.max_connections",
        "http.header_read_timeout_ms",
        "http.body_read_timeout_ms",
        "http.request_timeout_ms",
        "http.keepalive_idle_ms",
    ] {
        assert!(text.contains(field), "{field}: {text}");
    }
    assert!(
        Config::parse(
            "data_dir = \"/srv/p2pc\"\n[http]\nidle = 1\n",
            std::path::Path::new("server.toml")
        )
        .is_err()
    );
}
