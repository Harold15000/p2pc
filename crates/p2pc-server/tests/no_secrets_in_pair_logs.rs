// SPDX-License-Identifier: AGPL-3.0-only

//! Hard rule 5, SI-H2-1 (hub side of T2-11): pairing through the real `p2pc/pair/1` gateway, failed pairings and
//! device requests leave no pairing ticket, no pairing code and no API key in the logs, even at TRACE.
//!
//! This file holds a single test because it installs a process-wide subscriber (the gateway's tasks and the SQLite
//! worker log from their own threads, so a thread-local subscriber would miss them).

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::h2::Hub;
use iroh::SecretKey;
use p2pc_proto::PROTOCOL_ALPN_PAIR;
use p2pc_proto::pair::{PairErrorCode, PairResponse};
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
async fn no_ticket_code_or_key_reaches_the_logs_through_pair_and_device() {
    let capture = Capture::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .init();
    let hub = Hub::start().await;
    let (ticket, v) = hub.ticket(json!({})).await;
    let ticket_text = v["ticket"].as_str().unwrap().to_string();

    // Failed pairings: a ticket the hub never issued, and a frame whose ticket does not decode.
    let forged = hub.forged_ticket();
    let invalid = Some(PairResponse::PairError {
        code: PairErrorCode::InvalidTicket,
    });
    assert_eq!(hub.pair(&SecretKey::generate(), &forged).await, invalid);
    let garbled = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
    let body = format!(
        r#"{{"type":"pair","ticket":"{}x","label":"x","platform":"y"}}"#,
        ticket_text
    );
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body.as_bytes());
    assert_eq!(garbled.pair_raw(&frame).await, invalid);

    // The pairing itself, its idempotent retry, then the device at work.
    let phone = SecretKey::generate();
    for _ in 0..2 {
        assert!(matches!(
            hub.pair(&phone, &ticket).await,
            Some(PairResponse::Paired { .. })
        ));
    }
    let device = hub.device(&phone).await;
    assert_eq!(device.get("/v1/whoami").await.unwrap().status, 200);
    // A device request that wrongly carries an API key is refused; the key is not logged.
    let with_key = format!("Authorization: Bearer {}\r\n", hub.app.admin);
    let r = device.request("GET", "/v1/whoami", &with_key, "").await.unwrap();
    assert_eq!(r.status, 400);
    // A NodeId that is not a device.
    hub.device(&SecretKey::generate()).await.closed_not_paired().await;
    hub.app.flush_audit().await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    // The harness really captured the gateway and the device requests.
    assert!(logs.contains("device paired"), "{logs}");
    assert!(logs.contains("pairing failed"), "{logs}");
    assert!(logs.contains("/v1/whoami"), "{logs}");
    assert!(logs.contains("not_paired"), "{logs}");
    let b32 = |bytes: &[u8]| data_encoding::BASE32_NOPAD.encode(bytes).to_ascii_lowercase();
    for (what, secret) in [
        ("pairing ticket", ticket_text.clone()),
        ("pairing code (base32)", b32(&ticket.code)),
        ("pairing code (hex)", data_encoding::HEXLOWER.encode(&ticket.code)),
        ("forged ticket", forged.encode().unwrap()),
        ("forged code (base32)", b32(&forged.code)),
        ("API key", hub.app.admin.clone()),
    ] {
        assert!(!logs.contains(&secret), "{what} leaked:\n{logs}");
    }
    assert!(!logs.contains("p2pc_pair_"), "{logs}");
    assert!(!logs.contains("p2pc_sk_"), "{logs}");
}
