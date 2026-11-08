// SPDX-License-Identifier: AGPL-3.0-only

//! SI-6 for the node gateway: creating, listing and revoking join tokens, a successful `Join` and a failed one
//! leave no join token or join code in the logs, even at TRACE (iroh's own logs included), nor in `Debug` output.
//!
//! A single test, because it installs a process-wide subscriber.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use common::TestApp;
use iroh::{EndpointAddr, SecretKey};

use p2pc_proto::auth::JoinToken;
use p2pc_proto::protocol::{AgentMsg, MAX_FRAME_LEN, ServerMsg, read_frame, write_frame};
use p2pc_server::gateway::endpoint::bind;
use p2pc_server::gateway::{EndpointOptions, Gateway, GatewayConfig};
use p2pc_server::store::join_tokens;
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

async fn join(addr: &EndpointAddr, token: &JoinToken) -> ServerMsg {
    let ep = bind(SecretKey::generate(), &EndpointOptions::loopback_without_relays())
        .await
        .unwrap();
    let conn = ep.connect(addr.clone(), p2pc_proto::PROTOCOL_ALPN_AGENT).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    write_frame(
        &mut send,
        &AgentMsg::Join {
            token: token.clone(),
            inventory: common::inventory("node-1"),
        },
    )
    .await
    .unwrap();
    let reply = read_frame::<ServerMsg, _>(&mut recv, MAX_FRAME_LEN)
        .await
        .unwrap()
        .unwrap();
    conn.close(0u32.into(), b"");
    ep.close().await;
    reply
}

#[tokio::test]
async fn no_join_token_or_code_reaches_the_logs() {
    let capture = Capture::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .init();

    let app = TestApp::new().await;
    let gw = Gateway::start(
        app.state.clone(),
        GatewayConfig::new(
            EndpointOptions::loopback_without_relays(),
            "127.0.0.1:9".parse().unwrap(),
        ),
    )
    .await
    .unwrap();
    let addr = EndpointAddr::new(gw.endpoint().id()).with_ip_addr(gw.endpoint().bound_sockets()[0]);
    let mut tokens = Vec::new();
    for _ in 0..3 {
        let r = app
            .call(
                Method::POST,
                "/v1/nodes/join-tokens",
                Some(&app.admin),
                Some(json!({"label": "x"})),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED);
        let v = r.json();
        tokens.push((
            JoinToken::decode(v["join_token"].as_str().unwrap()).unwrap(),
            v["id"].as_str().unwrap().to_string(),
        ));
    }
    assert_eq!(
        app.get("/v1/nodes/join-tokens", &app.admin).await.status,
        StatusCode::OK
    );
    let r = app
        .call(
            Method::DELETE,
            &format!("/v1/nodes/join-tokens/{}", tokens[2].1),
            Some(&app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(matches!(join(&addr, &tokens[0].0).await, ServerMsg::Welcome { .. }));
    // A wrong code, and a revoked token.
    let mut wrong = tokens[1].0.clone();
    wrong.code[0] ^= 1;
    for t in [&wrong, &tokens[2].0] {
        assert!(matches!(join(&addr, t).await, ServerMsg::Error { .. }));
    }
    // Debug output of everything that holds a token or its digest.
    let mut conn = app.db.acquire().await.unwrap();
    let row = join_tokens::get(&mut conn, app.account_id, tokens[0].1.parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    drop(conn);
    let debug = format!("{:?} {:?} {:?} {:?}", tokens, row, app.state, wrong);
    gw.shutdown().await;
    app.flush_audit().await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("node enrolled"),
        "the harness captured the gateway's logs"
    );
    assert!(logs.contains("/v1/nodes/join-tokens"), "and the API's");
    let all: Vec<&JoinToken> = tokens.iter().map(|(t, _)| t).chain([&wrong]).collect();
    for token in all {
        let text = token.encode().unwrap();
        let body = &text["p2pc_join_".len()..];
        let code_b32 = data_encoding::BASE32_NOPAD.encode(&token.code).to_ascii_lowercase();
        let code_hex = data_encoding::HEXLOWER.encode(&token.code);
        for (what, needle) in [("token", body), ("code (base32)", &code_b32), ("code (hex)", &code_hex)] {
            assert!(!logs.contains(needle), "{what} leaked into the logs");
            assert!(!debug.contains(needle), "{what} leaked into Debug: {debug}");
        }
    }
    assert!(!logs.contains("p2pc_join_"), "a token prefix in the logs");
}
