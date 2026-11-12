// SPDX-License-Identifier: AGPL-3.0-only

//! `p2pc/pair/1` through the real gateway, on loopback with relays disabled (H2 spec §5.2, §5.3, §10.5; SI-H2-11,
//! SI-H2-17).
//!
//! - The ALPN is served only while a pairing ticket is open: otherwise the TLS handshake fails, and a connection that
//!   got in just before the hub stopped accepting it is closed before a frame is read.
//! - One `Pair` per connection, within the deadline, in a frame of at most 4 KiB, under the connection and pending
//!   caps.
//! - The limits never lock the owner out: failures are counted per NodeId and per ticket-hash prefix, the aggregate
//!   cap only limits answers and logging, and a valid ticket that gets a slot pairs whatever the counters say.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration as StdDuration;

use axum::http::{Method, StatusCode};
use common::h2::{Hub, limits};
use iroh::SecretKey;
use p2pc_proto::PROTOCOL_ALPN_PAIR;
use p2pc_proto::api::PHONE_PROFILE;
use p2pc_proto::pair::{PAIR_MAX_FRAME_LEN, PairErrorCode, PairResponse};
use p2pc_proto::protocol::error_code;
use p2pc_server::gateway::GatewayLimits;
use serde_json::json;
use time::Duration;

fn invalid_ticket() -> Option<PairResponse> {
    Some(PairResponse::PairError {
        code: PairErrorCode::InvalidTicket,
    })
}

async fn device_count(hub: &Hub) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM devices")
        .fetch_one(&hub.app.db)
        .await
        .unwrap()
}

async fn audit_count(hub: &Hub, kind: &str) -> usize {
    let audit = hub
        .app
        .get(&format!("/v1/audit?kind={kind}"), &hub.app.admin)
        .await
        .json();
    audit["items"].as_array().unwrap().len()
}

/// H2 §10.5, SI-H2-11: with no ticket open the hub does not accept the ALPN at all, so a `p2pc/pair/1` connection
/// fails at the TLS handshake. It is accepted from the moment a ticket is created until that ticket expires or is
/// revoked; a consumed ticket keeps it open until its expiry, for the idempotent retry of §5.2.
#[tokio::test]
async fn pair_is_served_only_while_a_ticket_is_open() {
    let hub = Hub::start().await;
    let stranger = SecretKey::generate();
    assert!(!hub.gw.refresh_pair_serving().await);
    assert!(
        hub.connect(&stranger, PROTOCOL_ALPN_PAIR).await.is_err(),
        "no ticket was ever created: the handshake must fail"
    );

    // A ticket is created: the ALPN is accepted.
    let (ticket, _) = hub.ticket(json!({"expires_in_s": 60})).await;
    let phone = SecretKey::generate();
    assert!(matches!(
        hub.pair(&phone, &ticket).await,
        Some(PairResponse::Paired { .. })
    ));
    // Consumed, not yet expired: still served, so the phone that lost the answer can retry.
    assert!(hub.gw.refresh_pair_serving().await);
    assert!(matches!(
        hub.pair(&phone, &ticket).await,
        Some(PairResponse::Paired { .. })
    ));

    // At its expiry the ticket is no longer open. A connection that still gets through the handshake (the accepted
    // ALPNs follow at the next sweep) is closed at once, before a frame is read: no answer of any kind.
    hub.app.clock.advance(Duration::seconds(60));
    let late = hub.connect(&stranger, PROTOCOL_ALPN_PAIR).await.unwrap();
    assert_eq!(late.pair(&ticket).await, None);
    late.closed_with_no_detail().await;
    // After the sweep the handshake itself fails again.
    assert!(!hub.gw.refresh_pair_serving().await);
    assert!(hub.connect(&stranger, PROTOCOL_ALPN_PAIR).await.is_err());

    // A revoked ticket is not open either.
    let (_, v) = hub.ticket(json!({})).await;
    assert!(hub.connect(&stranger, PROTOCOL_ALPN_PAIR).await.is_ok());
    let path = format!("/v1/devices/pairing-tickets/{}", v["id"].as_str().unwrap());
    let r = hub.app.call(Method::DELETE, &path, Some(&hub.app.admin), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(!hub.gw.refresh_pair_serving().await);
    assert!(hub.connect(&stranger, PROTOCOL_ALPN_PAIR).await.is_err());
    // The failures above were only handshakes and a connection closed unread: none is a failed pairing.
    assert_eq!(hub.failures_audited("pair").await, 0);
}

/// The gateway's own sweep (each second in production) is what follows the tickets: nothing has to call it.
#[tokio::test]
async fn the_sweep_starts_and_stops_serving_pair() {
    let hub = Hub::start().await;
    let stranger = SecretKey::generate();
    let r = hub
        .app
        .call(
            Method::POST,
            "/v1/devices/pairing-tickets",
            Some(&hub.app.admin),
            Some(json!({"expires_in_s": 30})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert!(hub.connect(&stranger, PROTOCOL_ALPN_PAIR).await.is_err());
    hub.gw.sweep_liveness().await;
    assert!(hub.connect(&stranger, PROTOCOL_ALPN_PAIR).await.is_ok());
    hub.app.clock.advance(Duration::seconds(30));
    hub.gw.sweep_liveness().await;
    assert!(hub.connect(&stranger, PROTOCOL_ALPN_PAIR).await.is_err());
}

/// A network change replaces the endpoint (H1 §10). The new one accepts `p2pc/pair/1` under the same rule: not
/// while no ticket is open, and at once when one is, without waiting for a sweep.
#[tokio::test]
async fn a_rebound_endpoint_serves_pair_only_while_a_ticket_is_open() {
    let hub = Hub::start().await;
    let stranger = SecretKey::generate();
    let loopback = || {
        vec![p2pc_proto::net::SelectedAddr::new(
            p2pc_proto::net::IfAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8),
            "lo",
        )]
    };
    hub.gw.rebind_to(loopback()).await;
    assert!(hub.connect(&stranger, PROTOCOL_ALPN_PAIR).await.is_err());
    // A ticket is open when the network changes: the new endpoint accepts the ALPN from its first connection.
    let (ticket, _) = hub.ticket(json!({"expires_in_s": 60})).await;
    let old = hub.gw.endpoint();
    hub.gw.rebind_to(loopback()).await;
    assert!(old.is_closed());
    assert!(matches!(
        hub.pair(&SecretKey::generate(), &ticket).await,
        Some(PairResponse::Paired { .. })
    ));
    // The ticket expires, then the network changes again before any sweep: the new endpoint does not accept it.
    hub.app.clock.advance(Duration::seconds(60));
    hub.gw.rebind_to(loopback()).await;
    assert!(hub.connect(&stranger, PROTOCOL_ALPN_PAIR).await.is_err());
    // The other ALPNs are served by every endpoint.
    hub.device(&stranger).await.closed_not_paired().await;
}

/// H2 §5.2, §5.3: a valid ticket pairs the connecting NodeId as a device with the ticket's scopes, once; the same
/// NodeId gets the same answer again, any other NodeId `invalid_ticket`, and so does the same NodeId once its device
/// is revoked (SI-H2-2 through the protocol). The paired device then reaches the API on `p2pc/device/1`.
#[tokio::test]
async fn a_valid_ticket_pairs_a_device_once_and_the_retry_is_idempotent() {
    let hub = Hub::start().await;
    let (ticket, _) = hub.ticket(json!({"label": "from the ticket"})).await;
    let phone = SecretKey::generate();
    let peer = hub.connect(&phone, PROTOCOL_ALPN_PAIR).await.unwrap();
    let answer = peer.pair_as(&ticket, "Ada's phone", "iOS Safari").await.unwrap();
    assert_eq!(answer.validate(), Ok(()));
    let PairResponse::Paired {
        device_id,
        hub_name,
        account_id,
        scopes,
        server_version,
        api_version,
    } = answer.clone()
    else {
        panic!("{answer:?}")
    };
    assert_eq!(account_id, hub.app.account_id);
    assert_eq!(
        scopes,
        PHONE_PROFILE.to_vec(),
        "the default scopes are the phone profile"
    );
    assert_eq!(server_version, env!("CARGO_PKG_VERSION"));
    // What `GET /v1/server` says.
    let server = hub.app.get("/v1/server", &hub.app.admin).await.json();
    assert_eq!(u64::from(api_version), server["api_version"].as_u64().unwrap_or(1));
    assert_eq!(api_version, 2, "an H2 hub");
    // A hub nobody named yet has an empty name in `Paired` (`GET /v1/server` leaves it out).
    assert_eq!(hub_name, "");
    // Then the hub closes the connection.
    peer.closed_with_no_detail().await;

    // The device row: the NodeId iroh authenticated, the label and platform of the `Pair`.
    let row: (String, String, String, String) =
        sqlx::query_as("SELECT device_id, iroh_node_id, label, platform FROM devices")
            .fetch_one(&hub.app.db)
            .await
            .unwrap();
    assert_eq!(
        row,
        (
            device_id.clone(),
            phone.public().to_string(),
            "Ada's phone".to_string(),
            "iOS Safari".to_string()
        )
    );
    assert_eq!(audit_count(&hub, "device_paired").await, 1);

    // The retry of the same NodeId: the same answer, and nothing new.
    assert_eq!(hub.pair(&phone, &ticket).await, Some(answer));
    assert_eq!(device_count(&hub).await, 1);
    assert_eq!(audit_count(&hub, "device_paired").await, 1);
    // Any other NodeId: `invalid_ticket`, as for an unknown ticket.
    assert_eq!(hub.pair(&SecretKey::generate(), &ticket).await, invalid_ticket());
    assert_eq!(
        hub.pair(&SecretKey::generate(), &hub.forged_ticket()).await,
        invalid_ticket()
    );
    assert_eq!(device_count(&hub).await, 1);

    // The device works on `p2pc/device/1`.
    let device = hub.device(&phone).await;
    let who = device.get("/v1/whoami").await.unwrap();
    assert_eq!(who.status, 200, "{}", who.head);
    assert_eq!(who.json()["principal"], json!({"kind": "device", "id": device_id}));

    // Revoked: the consumed ticket never revives it.
    let path = format!("/v1/devices/{device_id}");
    let r = hub.app.call(Method::DELETE, &path, Some(&hub.app.admin), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    device.closed_not_paired().await;
    assert_eq!(hub.pair(&phone, &ticket).await, invalid_ticket());
    assert_eq!(device_count(&hub).await, 1);
}

/// H2 §5.3 step 3: `Paired.hub_name` is the name an `admin` gave the hub with `PATCH /v1/server` (§7.3).
#[tokio::test]
async fn paired_carries_the_hub_name() {
    let hub = Hub::start().await;
    let r = hub
        .app
        .call(
            Method::PATCH,
            "/v1/server",
            Some(&hub.app.admin),
            Some(json!({"hub_name": "Home cloud"})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let (ticket, _) = hub.ticket(json!({})).await;
    let answer = hub.pair(&SecretKey::generate(), &ticket).await.unwrap();
    assert_eq!(answer.validate(), Ok(()));
    match answer {
        PairResponse::Paired { hub_name, .. } => assert_eq!(hub_name, "Home cloud"),
        other => panic!("{other:?}"),
    }
}

/// H2 §5.2 "The payload is not authenticated": the hub uses its own row's expiry, whatever the presented ticket says.
#[tokio::test]
async fn a_forged_later_expiry_does_not_revive_an_expired_ticket() {
    let hub = Hub::start().await;
    let (short, _) = hub.ticket(json!({"expires_in_s": 30})).await;
    // Another ticket keeps the ALPN served after the first one expires.
    hub.ticket(json!({"expires_in_s": 600})).await;
    hub.app.clock.advance(Duration::seconds(30));
    let mut forged = short.clone();
    forged.expires_at += Duration::hours(1);
    assert_eq!(hub.pair(&SecretKey::generate(), &forged).await, invalid_ticket());
    assert_eq!(device_count(&hub).await, 0);
}

/// H2 §5.3: one `Pair` per connection, within the deadline, in a frame of at most 4 KiB. A frame that is not a
/// `Pair` the hub can read is answered as a bad ticket or closed; none of it reaches the store.
#[tokio::test]
async fn one_pair_per_connection_within_the_deadline_in_a_frame_of_4_kib() {
    let hub = Hub::start_with(
        |_| {},
        GatewayLimits {
            pair_deadline: StdDuration::from_millis(300),
            ..limits()
        },
    )
    .await;
    let (ticket, _) = hub.ticket(json!({})).await;

    // Nothing sent: closed at the deadline, with no detail.
    let silent = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
    silent.closed_with_no_detail().await;
    // A stream opened and half a frame sent: the same.
    let slow = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
    let (mut send, _recv) = slow.conn.open_bi().await.unwrap();
    send.write_all(&[0, 0]).await.unwrap();
    slow.closed_with_no_detail().await;

    // A frame over 4 KiB is refused on its length prefix: closed, no answer.
    let big = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
    let mut frame = (PAIR_MAX_FRAME_LEN + 1).to_be_bytes().to_vec();
    frame.extend(std::iter::repeat_n(b' ', 64));
    assert_eq!(big.pair_raw(&frame).await, None);
    big.closed_with_no_detail().await;

    // An unknown message type gets `unsupported_message` (H1 §6), then the connection closes.
    let unknown = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
    let body = br#"{"type":"pair_v2","ticket":"x"}"#;
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    match unknown.pair_raw(&frame).await {
        Some(PairResponse::Error { code, .. }) => assert_eq!(code, error_code::UNSUPPORTED_MESSAGE),
        other => panic!("{other:?}"),
    }
    unknown.closed_with_no_detail().await;

    // A `Pair` whose ticket does not decode: the one answer for every bad ticket.
    let garbled = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
    let body = br#"{"type":"pair","ticket":"p2pc_pair_zz","label":"x","platform":"y"}"#; // gitleaks:allow
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    assert_eq!(garbled.pair_raw(&frame).await, invalid_ticket());
    // A `Pair` that breaks the protocol's own limits (a control character in the label): closed, no answer.
    let hostile = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
    assert_eq!(hostile.pair_as(&ticket, "evil\nlabel", "x").await, None);
    hostile.closed_with_no_detail().await;

    // One `Pair` per connection: after its answer the connection is closed, so a second one has nowhere to go.
    let twice = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
    assert_eq!(twice.pair(&hub.forged_ticket()).await, invalid_ticket());
    twice.closed_with_no_detail().await;
    assert_eq!(twice.pair(&ticket).await, None);

    // None of it paired anything, and the valid ticket is still unused.
    assert_eq!(device_count(&hub).await, 0);
    assert!(matches!(
        hub.pair(&SecretKey::generate(), &ticket).await,
        Some(PairResponse::Paired { .. })
    ));
}

/// SI-H2-17: frames of random bytes never take the hub down and never pair; a valid `Pair` still works after them.
#[tokio::test]
async fn hostile_frames_never_pair_and_never_stop_the_hub() {
    let hub = Hub::start_with(
        |_| {},
        GatewayLimits {
            pair_failures_per_node_per_minute: 1000,
            aggregate_failures_per_minute: 1000,
            ..limits()
        },
    )
    .await;
    let (ticket, _) = hub.ticket(json!({})).await;
    let key = SecretKey::generate();
    // A small xorshift generator: the same frames on every run.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..24 {
        let len = (next() % 300) as usize;
        let mut body: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if round % 3 == 0 {
            // Valid JSON of the right shape with hostile values.
            let ticket = format!("p2pc_pair_{}", next()); // gitleaks:allow
            let label = "\u{202e}".repeat((next() % 40) as usize);
            body = serde_json::to_vec(&json!({"type": "pair", "ticket": ticket, "label": label, "platform": next()}))
                .unwrap();
        }
        // An honest length prefix two times out of three, a lying one otherwise.
        let claimed = if round % 3 == 2 {
            next() as u32 % 8192
        } else {
            body.len() as u32
        };
        let mut frame = claimed.to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        let peer = hub.connect(&key, PROTOCOL_ALPN_PAIR).await.unwrap();
        let (mut send, _recv) = peer.conn.open_bi().await.unwrap();
        let _ = send.write_all(&frame).await;
        let _ = send.finish();
        let (code, _) = peer.closed().await;
        assert_eq!(code, common::h2::CLOSE_BY_SERVER, "round {round}");
    }
    assert_eq!(device_count(&hub).await, 0);
    assert!(matches!(
        hub.pair(&SecretKey::generate(), &ticket).await,
        Some(PairResponse::Paired { .. })
    ));
}

/// H2 §5.3: at most `pair_max_connections` connections at once; one beyond the cap is closed with no detail, and a
/// slot that is given back is usable again.
#[tokio::test]
async fn pair_connections_are_capped() {
    let hub = Hub::start_with(
        |_| {},
        GatewayLimits {
            pair_max_connections: 1,
            ..limits()
        },
    )
    .await;
    let (ticket, _) = hub.ticket(json!({})).await;
    // Two connections contend for the only slot. The first sends the start of a frame and then waits; the second
    // sends a whole `Pair`. Whichever handler ran first holds the slot: the other is closed with no detail.
    let waiting = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
    let (mut send, _recv) = waiting.conn.open_bi().await.unwrap();
    send.write_all(&[0]).await.unwrap();
    let second = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
    match second.pair(&hub.forged_ticket()).await {
        Some(answer) => {
            assert_eq!(Some(answer), invalid_ticket());
            waiting.closed_with_no_detail().await;
        }
        None => {
            second.closed_with_no_detail().await;
            assert!(waiting.is_open(), "both were closed");
            waiting.close().await;
        }
    }
    // Whoever held the slot is gone: the valid ticket pairs. The slot is released when the hub's handler ends,
    // which a peer cannot observe, so the `Pair` is retried while it is refused, as a real device does.
    let phone = SecretKey::generate();
    let paired = async {
        loop {
            if let Some(answer) = hub.pair(&phone, &ticket).await {
                return answer;
            }
            tokio::task::yield_now().await;
        }
    };
    let answer = tokio::time::timeout(common::h2::WAIT, paired).await.unwrap();
    assert!(matches!(answer, PairResponse::Paired { .. }), "{answer:?}");
}

/// H2 §5.3: at most `pair_max_pending` `Pair`s are checked at once; one beyond the cap is closed with no detail. The
/// test holds SQLite's write lock, so a `Pair` that got a slot waits inside its transaction (with the slot) until
/// the lock is released; nothing depends on timing.
#[tokio::test]
async fn pending_pairs_are_capped() {
    let hub = Hub::start_with(
        |_| {},
        GatewayLimits {
            pair_max_pending: 1,
            ..limits()
        },
    )
    .await;
    let (ticket, _) = hub.ticket(json!({})).await;
    let lock = p2pc_server::store::begin_immediate(&hub.app.db).await.unwrap();
    let a = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
    let b = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
    let forged = hub.forged_ticket();
    let (pair_a, pair_b) = (a.pair(&ticket), b.pair(&forged));
    tokio::pin!(pair_a, pair_b);
    // Whichever `Pair` reached the cap first is stuck on the lock; the other is refused at once, with no detail.
    let a_was_refused = tokio::select! {
        r = &mut pair_a => { assert_eq!(r, None, "the Pair over the cap gets no answer"); true }
        r = &mut pair_b => { assert_eq!(r, None, "the Pair over the cap gets no answer"); false }
    };
    drop(lock);
    if a_was_refused {
        assert_eq!(pair_b.await, invalid_ticket());
        assert_eq!(device_count(&hub).await, 0);
    } else {
        assert!(matches!(pair_a.await, Some(PairResponse::Paired { .. })));
        assert_eq!(device_count(&hub).await, 1);
    }
}

/// H2 §5.3: failed pairings are counted per NodeId. A NodeId over its limit is refused when it connects, with no
/// detail and without its ticket being looked at (a valid one included: only its own failures count); other NodeIds
/// are not affected, and the next minute starts empty.
#[tokio::test]
async fn failed_pairings_are_limited_per_node_id() {
    let hub = Hub::start_with(
        |_| {},
        GatewayLimits {
            pair_failures_per_node_per_minute: 2,
            ..limits()
        },
    )
    .await;
    let (ticket, _) = hub.ticket(json!({})).await;
    let noisy = SecretKey::generate();
    for _ in 0..2 {
        assert_eq!(hub.pair(&noisy, &hub.forged_ticket()).await, invalid_ticket());
    }
    // Over its limit: closed at connect, even though the ticket it would present is valid.
    let refused = hub.connect(&noisy, PROTOCOL_ALPN_PAIR).await.unwrap();
    refused.closed_with_no_detail().await;
    assert_eq!(refused.pair(&ticket).await, None);
    assert_eq!(device_count(&hub).await, 0);
    // Another NodeId still gets its detailed answer.
    assert_eq!(
        hub.pair(&SecretKey::generate(), &hub.forged_ticket()).await,
        invalid_ticket()
    );
    // The refusal at connect is not a failed pairing: three were.
    assert_eq!(hub.failures_audited("pair").await, 3);
    // The next minute the NodeId starts over, and its valid ticket pairs.
    hub.app.clock.advance(Duration::seconds(60));
    assert!(matches!(
        hub.pair(&noisy, &ticket).await,
        Some(PairResponse::Paired { .. })
    ));
}

/// H2 §5.3: failed pairings are also counted per ticket-hash prefix. Beyond the limit a failing attempt in that
/// prefix is closed with no detail, whatever NodeId it comes from; other prefixes keep their detailed answer, and a
/// **valid** ticket in the limited prefix still pairs.
#[tokio::test]
async fn failed_pairings_are_limited_per_ticket_hash_prefix_and_a_valid_ticket_still_pairs() {
    let hub = Hub::start_with(
        |_| {},
        GatewayLimits {
            pair_failures_per_prefix_per_minute: 2,
            ..limits()
        },
    )
    .await;
    let (ticket, _) = hub.ticket(json!({})).await;
    // Forged tickets whose codes hash into the valid ticket's prefix, each from a fresh NodeId.
    for _ in 0..2 {
        let forged = hub.forged_ticket_in_prefix_of(&ticket);
        assert_eq!(hub.pair(&SecretKey::generate(), &forged).await, invalid_ticket());
    }
    for _ in 0..2 {
        let forged = hub.forged_ticket_in_prefix_of(&ticket);
        let peer = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
        assert_eq!(peer.pair(&forged).await, None, "over the prefix limit: no detail");
        peer.closed_with_no_detail().await;
    }
    // Another prefix is not affected.
    let elsewhere = loop {
        let t = hub.forged_ticket();
        if t.hash_prefix() != ticket.hash_prefix() {
            break t;
        }
    };
    assert_eq!(hub.pair(&SecretKey::generate(), &elsewhere).await, invalid_ticket());
    // Every failure is in the one aggregated audit row, answered or not.
    assert_eq!(hub.failures_audited("pair").await, 5);
    // The valid ticket of the limited prefix pairs.
    assert!(matches!(
        hub.pair(&SecretKey::generate(), &ticket).await,
        Some(PairResponse::Paired { .. })
    ));
}

/// SI-H2-17, H2 §5.3 "aggregate failure cap": with failures spread over fresh NodeIds and prefixes, beyond the cap no
/// failure gets a detailed answer and none is audited one by one (one aggregated row counts them all), while a valid
/// ticket that gets a slot still pairs.
#[tokio::test]
async fn beyond_the_aggregate_cap_failures_get_no_detail_and_a_valid_ticket_still_pairs() {
    let hub = Hub::start_with(
        |_| {},
        GatewayLimits {
            aggregate_failures_per_minute: 3,
            ..limits()
        },
    )
    .await;
    let (ticket, _) = hub.ticket(json!({})).await;
    // Fresh NodeIds and fresh codes (so, with overwhelming probability, fresh prefixes): neither per-key limit trips.
    for _ in 0..3 {
        assert_eq!(
            hub.pair(&SecretKey::generate(), &hub.forged_ticket()).await,
            invalid_ticket()
        );
    }
    for _ in 0..4 {
        let peer = hub.connect(&SecretKey::generate(), PROTOCOL_ALPN_PAIR).await.unwrap();
        assert_eq!(peer.pair(&hub.forged_ticket()).await, None, "beyond the cap: no detail");
        peer.closed_with_no_detail().await;
    }
    assert_eq!(hub.failures_audited("pair").await, 7);
    assert_eq!(audit_count(&hub, "auth_failed").await, 1, "never one row per failure");
    // The cap limits answers and logging, never the lookup.
    let answer = hub.pair(&SecretKey::generate(), &ticket).await;
    assert!(matches!(answer, Some(PairResponse::Paired { .. })), "{answer:?}");
    assert_eq!(audit_count(&hub, "device_paired").await, 1);
    // A success is not a failure.
    assert_eq!(hub.failures_audited("pair").await, 7);
    // The next minute failures are answered again.
    hub.app.clock.advance(Duration::seconds(60));
    assert_eq!(
        hub.pair(&SecretKey::generate(), &hub.forged_ticket()).await,
        invalid_ticket()
    );
}

/// The pair connections are counted apart from the agent ALPN's unknown connections (H2 §5.3 "counted separately").
#[tokio::test]
async fn pair_connections_do_not_take_the_agent_alpns_slots() {
    let hub = Hub::start_with(
        |_| {},
        GatewayLimits {
            max_unknown_connections: 1,
            pair_max_connections: 1,
            ..limits()
        },
    )
    .await;
    let (ticket, _) = hub.ticket(json!({})).await;
    // An unknown NodeId holds the only pre-`Join` slot of `p2pc/agent/1`.
    let agent = hub
        .connect(&SecretKey::generate(), p2pc_proto::PROTOCOL_ALPN_AGENT)
        .await
        .unwrap();
    let (mut send, mut recv) = agent.conn.open_bi().await.unwrap();
    send.write_all(&[0]).await.unwrap();
    // The pairing still gets its own slot.
    assert!(matches!(
        hub.pair(&SecretKey::generate(), &ticket).await,
        Some(PairResponse::Paired { .. })
    ));
    assert!(agent.is_open());
    let _ = recv.stop(0u32.into());
}
