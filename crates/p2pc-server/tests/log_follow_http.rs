// SPDX-License-Identifier: AGPL-3.0-only

//! The wire contract the log clients rely on (T10d review): over real HTTP/1.1 on a TCP socket, a follow on a quiet job
//! is cut at the idle limit with an **incomplete chunked body** (the connection closes without the terminating `0`
//! chunk), never with a clean end; and a client that reopens from `next_seq = last seq + 1` gets every line exactly
//! once, ending cleanly (the terminating chunk) once the attempt is over. The bytes are read by hand, so the test does
//! not depend on how any particular HTTP client reports a cut body.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::fleet::{Fleet, WAIT};
use p2pc_proto::api::{LogLine, LogStream};
use p2pc_server::gateway::GatewayLimits;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// What one response looked like on the wire.
struct Wire {
    status_line: String,
    chunked: bool,
    /// The decoded body bytes received.
    body: Vec<u8>,
    /// The terminating zero-length chunk (and its trailer end) arrived: the body is complete.
    complete: bool,
}

/// Sends `GET uri` (HTTP/1.1, `Connection: close`) and reads until the server closes the connection.
async fn get(addr: std::net::SocketAddr, key: &str, uri: &str) -> Wire {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET {uri} HTTP/1.1\r\nHost: example.invalid\r\nAuthorization: Bearer {key}\r\nAccept: application/x-ndjson\r\nConnection: close\r\n\r\n"
    );
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(WAIT, tcp.read_to_end(&mut raw))
        .await
        .expect("the server neither finished nor cut the response")
        .ok(); // a reset is also a cut
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("no response head");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status_line = head.lines().next().unwrap().to_string();
    let chunked = head.to_ascii_lowercase().contains("transfer-encoding: chunked");
    let (body, complete) = decode_chunked(&raw[split + 4..]);
    Wire {
        status_line,
        chunked,
        body,
        complete,
    }
}

/// Decodes a chunked body as far as it goes. `complete` only if the zero-length chunk and the final CRLF are there.
fn decode_chunked(mut rest: &[u8]) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    loop {
        let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") else {
            return (body, false);
        };
        let size_text = std::str::from_utf8(&rest[..eol]).unwrap();
        let size = usize::from_str_radix(size_text.split(';').next().unwrap().trim(), 16).expect("a chunk size");
        rest = &rest[eol + 2..];
        if size == 0 {
            // Trailers are empty here: the body is complete when the closing CRLF follows.
            return (body, rest.starts_with(b"\r\n"));
        }
        if rest.len() < size + 2 {
            body.extend_from_slice(&rest[..rest.len().min(size)]);
            return (body, false);
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

fn seqs(body: &[u8]) -> Vec<u64> {
    std::str::from_utf8(body)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<LogLine>(l).unwrap().seq)
        .collect()
}

#[tokio::test]
async fn an_idle_follow_is_cut_with_an_incomplete_chunked_body_and_a_reopen_loses_and_repeats_nothing() {
    let f = Fleet::start_with(|c| c.http.keepalive_idle_ms = 300, GatewayLimits::default()).await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    for seq in 0..5 {
        agent
            .log(lease, epoch, seq, LogStream::Stdout, format!("line {seq}\n").as_bytes())
            .await;
    }
    agent.sync().await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(p2pc_server::serve::serve_on(listener, f.app.state.clone(), async {
        let _ = stopped.await;
    }));
    let key = f.app.admin.to_string();

    // 1. A quiet job: the stored lines arrive, then the idle limit cuts the body. No terminating chunk.
    let first = get(addr, &key, &format!("/v1/jobs/{job}/logs?follow=true")).await;
    assert!(first.status_line.contains("200"), "{}", first.status_line);
    assert!(first.chunked, "a follow is streamed with chunked transfer encoding");
    assert_eq!(seqs(&first.body), vec![0, 1, 2, 3, 4]);
    assert!(
        !first.complete,
        "the idle cut ended the chunked body cleanly: a client would take the log for complete"
    );

    // 2. The job speaks and ends while the client is away; it reopens from next_seq = last seq + 1.
    agent.log(lease, epoch, 5, LogStream::Stdout, b"late").await;
    agent.log(lease, epoch, 6, LogStream::Stderr, b"last").await;
    agent.finished(lease, epoch, 0, vec![]).await;
    let next_seq = seqs(&first.body).last().unwrap() + 1;
    let second = get(
        addr,
        &key,
        &format!("/v1/jobs/{job}/logs?follow=true&since_seq={next_seq}"),
    )
    .await;
    assert!(second.chunked && second.complete, "the attempt is over: a clean end");
    assert_eq!(seqs(&second.body), vec![5, 6]);

    // Together: every line once, in order.
    let mut all = seqs(&first.body);
    all.extend(seqs(&second.body));
    assert_eq!(all, vec![0, 1, 2, 3, 4, 5, 6]);

    // 3. A page (no follow) of a finished job is a complete body too.
    let page = get(addr, &key, &format!("/v1/jobs/{job}/logs")).await;
    assert!(page.complete);
    assert_eq!(seqs(&page.body), vec![0, 1, 2, 3, 4, 5, 6]);

    let _ = stop.send(());
    server.await.unwrap().unwrap();
}
