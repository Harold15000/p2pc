// SPDX-License-Identifier: AGPL-3.0-only

//! SI-H2-1 (hub side of T2-10): creating a pairing ticket, pairing, a join request's reveal and the minting of its join
//! token leave no pairing ticket or code, no listener nonce before its reveal and no join token in the logs, even at
//! TRACE.
//!
//! This file holds a single test because it installs a process-wide subscriber (the SQLite worker logs from its own
//! thread, so a thread-local subscriber would miss it).

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use common::{DeviceLimits, TestApp, node_key};
use p2pc_proto::api::PHONE_PROFILE;
use p2pc_proto::invite::ListenerNonce;
use p2pc_proto::pair::PairingTicket;
use p2pc_server::clock::Clock;
use p2pc_server::store;
use serde_json::json;
use time::format_description::well_known::Rfc3339;
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
async fn no_ticket_nonce_or_join_token_reaches_the_logs() {
    let capture = Capture::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .init();
    let app = TestApp::with_config(|c| c.devices.web_app_origin = Some("https://app.example.invalid".into())).await;

    // A pairing ticket, then the pairing transaction.
    let r = app
        .call(
            Method::POST,
            "/v1/devices/pairing-tickets",
            Some(&app.admin),
            Some(json!({})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let ticket_text = r.json()["ticket"].as_str().unwrap().to_string();
    let ticket = PairingTicket::decode(&ticket_text).unwrap();
    let mut tx = store::begin_immediate(&app.db).await.unwrap();
    let out = store::devices::pair(
        &mut tx,
        &ticket.code_hash(),
        &app.state.dummy_digest,
        &node_key(),
        None,
        "",
        app.clock.now(),
    )
    .await
    .unwrap();
    assert!(matches!(out, store::devices::PairOutcome::Paired(_)));
    tx.commit().await.unwrap();

    // A join request through to its token.
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let nonce = ListenerNonce::generate();
    let nonce_hex = data_encoding::HEXLOWER.encode(nonce.expose_bytes());
    let body = json!({
        "listener_node_id": node_key(),
        "iroh_node_id": node_key(),
        "invite_expires_at": (app.clock.now() + time::Duration::minutes(10)).format(&Rfc3339).unwrap(),
        "listener_commitment": nonce.commitment().to_string(),
    });
    let r = app
        .device_call(phone, Method::POST, "/v1/nodes/join-requests", Some(body))
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let id = r.json()["id"].as_str().unwrap().to_string();
    // A wrong reveal first: its nonce must not be logged either.
    let wrong = data_encoding::HEXLOWER.encode(ListenerNonce::generate().expose_bytes());
    let other = app
        .device_call(
            phone,
            Method::POST,
            "/v1/nodes/join-requests",
            Some(json!({
                "listener_node_id": node_key(),
                "iroh_node_id": node_key(),
                "invite_expires_at": (app.clock.now() + time::Duration::minutes(10)).format(&Rfc3339).unwrap(),
                "listener_commitment": nonce.commitment().to_string(),
            })),
        )
        .await
        .json();
    let r = app
        .device_call(
            phone,
            Method::POST,
            &format!("/v1/nodes/join-requests/{}/reveal", other["id"].as_str().unwrap()),
            Some(json!({"listener_nonce": wrong})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = app
        .device_call(
            phone,
            Method::POST,
            &format!("/v1/nodes/join-requests/{id}/reveal"),
            Some(json!({"listener_nonce": nonce_hex})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = app
        .call(
            Method::POST,
            &format!("/v1/nodes/join-requests/{id}/approve"),
            Some(&app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = app
        .device_call(
            phone,
            Method::POST,
            &format!("/v1/nodes/join-requests/{id}/token"),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let join_token = r.json()["join_token"].as_str().unwrap().to_string();

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    // The harness really captured the requests.
    assert!(logs.contains("/v1/nodes/join-requests"), "{logs}");
    assert!(logs.contains("pairing ticket created"), "{logs}");
    for (what, secret) in [
        ("pairing ticket", ticket_text.as_str()),
        ("join token", join_token.as_str()),
        ("wrong listener nonce", wrong.as_str()),
    ] {
        assert!(!logs.contains(secret), "{what} leaked:\n{logs}");
    }
    assert!(!logs.contains("p2pc_pair_"), "{logs}");
    assert!(!logs.contains("p2pc_join_"), "{logs}");
}
