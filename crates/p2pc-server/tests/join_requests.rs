// SPDX-License-Identifier: AGPL-3.0-only

//! Join requests (H2 spec §5.4, §7.3, SI-H2-16, SI-H2-19): input checks, the hub nonce, the reveal against the
//! listener commitment, the approval phrase, the 15-minute rule judged by `created_at` with the expiry sweep stopped,
//! the token bound to the agent NodeId and delivered once to the requesting device only, and the limits.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::{DeviceLimits, T0, TestApp, assert_problem, node_key, not_a_point};
use p2pc_proto::api::{PHONE_PROFILE, Scope};
use p2pc_proto::auth::JoinToken;
use p2pc_proto::ids::DeviceId;
use p2pc_proto::invite::{HubNonce, ListenerNonce, approval_phrase};
use p2pc_server::clock::Clock;
use serde_json::{Value, json};
use time::Duration;
use time::format_description::well_known::Rfc3339;

fn rfc3339(t: time::OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap()
}

/// A join request body as the phone copies it from the QR, with its listener nonce.
fn body(app: &TestApp) -> (Value, ListenerNonce, String) {
    let nonce = ListenerNonce::generate();
    let agent = node_key();
    let v = json!({
        "listener_node_id": node_key(),
        "iroh_node_id": agent,
        "invite_expires_at": rfc3339(app.clock.now() + Duration::minutes(15)),
        "listener_commitment": nonce.commitment().to_string(),
    });
    (v, nonce, agent)
}

fn hex(nonce: &ListenerNonce) -> String {
    data_encoding::HEXLOWER.encode(nonce.expose_bytes())
}

async fn create(app: &TestApp, phone: DeviceId, body: &Value) -> common::Resp {
    app.device_call(phone, Method::POST, "/v1/nodes/join-requests", Some(body.clone()))
        .await
}

async fn open(app: &TestApp, phone: DeviceId) -> (String, ListenerNonce, String, Value) {
    let (b, nonce, agent) = body(app);
    let r = create(app, phone, &b).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let v = r.json();
    (v["id"].as_str().unwrap().to_string(), nonce, agent, v)
}

async fn rows(app: &TestApp) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM join_requests")
        .fetch_one(&app.db)
        .await
        .unwrap()
}

async fn reveal(app: &TestApp, phone: DeviceId, id: &str, nonce: &str) -> common::Resp {
    app.device_call(
        phone,
        Method::POST,
        &format!("/v1/nodes/join-requests/{id}/reveal"),
        Some(json!({"listener_nonce": nonce})),
    )
    .await
}

async fn approve(app: &TestApp, id: &str) -> common::Resp {
    app.call(
        Method::POST,
        &format!("/v1/nodes/join-requests/{id}/approve"),
        Some(&app.admin),
        None,
    )
    .await
}

async fn token(app: &TestApp, phone: DeviceId, id: &str) -> common::Resp {
    app.device_call(
        phone,
        Method::POST,
        &format!("/v1/nodes/join-requests/{id}/token"),
        None,
    )
    .await
}

#[tokio::test]
async fn every_bad_input_is_invalid_join_request_and_creates_nothing() {
    let app = TestApp::new().await;
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let now = app.clock.now();
    let (good, _, _) = body(&app);
    let cases: Vec<(&str, Value)> = vec![
        ("invite_expires_at", json!(rfc3339(now))),
        ("invite_expires_at", json!(rfc3339(now - Duration::seconds(1)))),
        (
            "invite_expires_at",
            json!(rfc3339(now + Duration::seconds(15 * 60 + 120 + 1))),
        ),
        ("listener_node_id", json!(not_a_point())),
        ("iroh_node_id", json!(not_a_point())),
        ("listener_node_id", json!("ab".repeat(31))),
        ("iroh_node_id", json!("ab".repeat(33))),
        ("listener_commitment", json!("ab".repeat(31))),
        ("listener_commitment", json!("AB".repeat(32))),
    ];
    for (field, value) in cases {
        let mut b = good.clone();
        b[field] = value;
        let r = create(&app, phone, &b).await;
        let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "invalid_join_request");
        assert!(!v.to_string().contains("p2pc_"), "{field}: {v}");
    }
    assert_eq!(rows(&app).await, 0);
    // The edge of the window is accepted: now + 15 min + 120 s.
    let mut b = good.clone();
    b["invite_expires_at"] = json!(rfc3339(now + Duration::seconds(15 * 60 + 120)));
    assert_eq!(create(&app, phone, &b).await.status, StatusCode::CREATED);
    // Without `nodes:invite`, nothing.
    let reader = app.add_device(&[Scope::NodesRead], DeviceLimits::default()).await;
    let r = create(&app, reader, &good).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
}

#[tokio::test]
async fn the_full_flow_reveal_approve_and_a_token_bound_to_the_agent() {
    let app = TestApp::new().await;
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let (id, nonce, agent, created) = open(&app, phone).await;
    assert_eq!(created["expires_at"], rfc3339(T0 + Duration::minutes(15)));
    // While `awaiting_reveal`: no phrase, and no approval.
    let r = app
        .device_call(phone, Method::GET, &format!("/v1/nodes/join-requests/{id}"), None)
        .await;
    let v = r.json();
    assert_eq!(v["state"], "awaiting_reveal");
    assert_eq!(v["approval_phrase"], Value::Null);
    assert_problem(&approve(&app, &id).await, StatusCode::CONFLICT, "join_request_closed");
    // The token is for after the approval only.
    assert_problem(
        &token(&app, phone, &id).await,
        StatusCode::CONFLICT,
        "join_request_closed",
    );
    // The reveal that matches makes it `pending`, with the phrase over the hub, the agent and both nonces.
    let r = reveal(&app, phone, &id, &hex(&nonce)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let v = r.json();
    assert_eq!(v["state"], "pending");
    let hub = app.state.server.node_id().to_string().parse().unwrap();
    let hub_nonce: HubNonce = serde_json::from_value(created["hub_nonce"].clone()).unwrap();
    let phrase = approval_phrase(&hub, &agent.parse().unwrap(), &nonce, &hub_nonce).to_string();
    assert_eq!(v["approval_phrase"], phrase);
    // The admin sees the same phrase and the source device.
    let r = app.get("/v1/nodes/join-requests", &app.admin).await;
    let item = &r.json()["items"][0];
    assert_eq!(item["approval_phrase"], phrase);
    assert_eq!(item["requested_by"], json!({"kind": "device", "id": phone.to_string()}));
    // A second reveal is closed.
    assert_problem(
        &reveal(&app, phone, &id, &hex(&nonce)).await,
        StatusCode::CONFLICT,
        "join_request_closed",
    );
    // Only an admin approves.
    let r = app
        .device_call(
            phone,
            Method::POST,
            &format!("/v1/nodes/join-requests/{id}/approve"),
            None,
        )
        .await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    let r = approve(&app, &id).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.json()["state"], "approved");
    // Another device cannot fetch the token.
    let other = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    assert_problem(&token(&app, other, &id).await, StatusCode::NOT_FOUND, "not_found");
    // The requesting device gets it once.
    let r = token(&app, phone, &id).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.headers.get("cache-control").unwrap(), "no-store");
    let v = r.json();
    let join = JoinToken::decode(v["join_token"].as_str().unwrap()).unwrap();
    assert_eq!(v["expires_at"], rfc3339(T0 + Duration::minutes(15)));
    assert_problem(
        &token(&app, phone, &id).await,
        StatusCode::CONFLICT,
        "join_request_closed",
    );
    // Stored only as a hash, bound to the agent, minted by the approver.
    let (digest, bound, by_key, by_device): (String, Option<String>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT code_digest, bound_iroh_node_id, created_by_key_id, created_by_device_id FROM join_tokens",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(digest, join.code_hash().to_stored());
    assert_eq!(bound.as_deref(), Some(agent.as_str()));
    assert_eq!(by_key, Some(app.admin_key.key_id().to_string()));
    assert_eq!(by_device, None);
    let r = app.get(&format!("/v1/nodes/join-requests/{id}"), &app.admin).await;
    assert_eq!(r.json()["state"], "delivered");
    let audit: Vec<String> =
        sqlx::query_scalar("SELECT kind FROM audit_events WHERE kind LIKE 'join_request_%' ORDER BY seq")
            .fetch_all(&app.db)
            .await
            .unwrap();
    assert_eq!(
        audit,
        [
            "join_request_created",
            "join_request_revealed",
            "join_request_approved",
            "join_request_delivered"
        ]
    );
    let details: Vec<String> = sqlx::query_scalar("SELECT detail FROM audit_events")
        .fetch_all(&app.db)
        .await
        .unwrap();
    assert!(
        details.iter().all(|d| !d.contains("p2pc_join_")),
        "SI-H2-1: no token in the audit log"
    );
    // The other device sees nothing of this request.
    let r = app
        .device_call(other, Method::GET, "/v1/nodes/join-requests", None)
        .await;
    assert_eq!(r.json()["items"], json!([]));
    let r = app
        .device_call(other, Method::GET, &format!("/v1/nodes/join-requests/{id}"), None)
        .await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
}

#[tokio::test]
async fn identical_requests_get_different_hub_nonces_and_a_wrong_reveal_rejects_for_good() {
    let app = TestApp::new().await;
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let (b, nonce, _) = body(&app);
    let one = create(&app, phone, &b).await.json();
    let two = create(&app, phone, &b).await.json();
    assert_ne!(one["hub_nonce"], two["hub_nonce"]);
    let id = one["id"].as_str().unwrap();
    // A nonce that does not match the commitment ends the request.
    let wrong = hex(&ListenerNonce::generate());
    assert_problem(
        &reveal(&app, phone, id, &wrong).await,
        StatusCode::CONFLICT,
        "join_request_closed",
    );
    let r = app.get(&format!("/v1/nodes/join-requests/{id}"), &app.admin).await;
    assert_eq!(r.json()["state"], "rejected");
    assert_eq!(r.json()["approval_phrase"], Value::Null);
    // No second try, even with the right nonce.
    assert_problem(
        &reveal(&app, phone, id, &hex(&nonce)).await,
        StatusCode::CONFLICT,
        "join_request_closed",
    );
    assert_problem(&approve(&app, id).await, StatusCode::CONFLICT, "join_request_closed");
    let failed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE kind = 'join_request_reveal_failed'")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(failed, 1);
    // The other request, with the same inputs, still reveals: its phrase differs (another hub nonce).
    let id2 = two["id"].as_str().unwrap();
    let r = reveal(&app, phone, id2, &hex(&nonce)).await;
    assert_eq!(r.status, StatusCode::OK);
    // Bad nonce text is a validation error, not a reveal.
    let r = reveal(&app, phone, id2, "xyz").await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

/// SI-H2-16: approval and token minting of a request created 15 minutes ago are refused, judged by `created_at`,
/// while the expiry sweep has not run (an injected clock, the sweep stopped).
#[tokio::test]
async fn the_15_minute_rule_holds_without_the_expiry_sweep() {
    let app = TestApp::new().await;
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    // A `pending` request.
    let (pending, nonce, _, _) = open(&app, phone).await;
    assert_eq!(reveal(&app, phone, &pending, &hex(&nonce)).await.status, StatusCode::OK);
    // An `approved` request.
    let (approved, nonce, _, _) = open(&app, phone).await;
    assert_eq!(
        reveal(&app, phone, &approved, &hex(&nonce)).await.status,
        StatusCode::OK
    );
    assert_eq!(approve(&app, &approved).await.status, StatusCode::OK);
    app.clock.advance(Duration::minutes(15));
    assert_problem(
        &approve(&app, &pending).await,
        StatusCode::CONFLICT,
        "join_request_closed",
    );
    assert_problem(
        &token(&app, phone, &approved).await,
        StatusCode::CONFLICT,
        "join_request_closed",
    );
    // The stored states are untouched (no sweep ran); the API reports them `expired`.
    let stored: Vec<String> = sqlx::query_scalar("SELECT state FROM join_requests ORDER BY created_at, id")
        .fetch_all(&app.db)
        .await
        .unwrap();
    assert!(stored.contains(&"pending".to_string()) && stored.contains(&"approved".to_string()));
    let r = app.get(&format!("/v1/nodes/join-requests/{pending}"), &app.admin).await;
    assert_eq!(r.json()["state"], "expired");
    // The sweep then writes it down.
    p2pc_server::devices_api::sweep_once(&app.state).await.unwrap();
    let open_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM join_requests WHERE state IN ('pending', 'approved')")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(open_rows, 0);
    // A reveal after 15 minutes is closed too.
    let (late, nonce, _, _) = open(&app, phone).await;
    app.clock.advance(Duration::minutes(15));
    assert_problem(
        &reveal(&app, phone, &late, &hex(&nonce)).await,
        StatusCode::CONFLICT,
        "join_request_closed",
    );
}

#[tokio::test]
async fn a_token_is_refused_when_the_approving_principal_is_no_longer_live() {
    let app = TestApp::new().await;
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let approver = app.add_device(&[Scope::Admin], DeviceLimits::default()).await;
    let (id, nonce, _, _) = open(&app, phone).await;
    assert_eq!(reveal(&app, phone, &id, &hex(&nonce)).await.status, StatusCode::OK);
    let r = app
        .device_call(
            approver,
            Method::POST,
            &format!("/v1/nodes/join-requests/{id}/approve"),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = app
        .call(
            Method::DELETE,
            &format!("/v1/devices/{approver}"),
            Some(&app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_problem(
        &token(&app, phone, &id).await,
        StatusCode::CONFLICT,
        "join_request_closed",
    );
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM join_tokens")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(n, 0, "nothing was minted");
}

#[tokio::test]
async fn requests_can_be_withdrawn_or_rejected_while_open() {
    let app = TestApp::new().await;
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let (id, nonce, _, _) = open(&app, phone).await;
    let path = format!("/v1/nodes/join-requests/{id}");
    // Another device cannot withdraw it.
    let other = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    assert_problem(
        &app.device_call(other, Method::DELETE, &path, None).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    assert_eq!(
        app.device_call(phone, Method::DELETE, &path, None).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.device_call(phone, Method::DELETE, &path, None).await.status,
        StatusCode::NO_CONTENT
    );
    assert_problem(
        &reveal(&app, phone, &id, &hex(&nonce)).await,
        StatusCode::CONFLICT,
        "join_request_closed",
    );
    // An approved request is no longer open for rejection.
    let (id, nonce, _, _) = open(&app, phone).await;
    assert_eq!(reveal(&app, phone, &id, &hex(&nonce)).await.status, StatusCode::OK);
    let path = format!("/v1/nodes/join-requests/{id}");
    assert_eq!(approve(&app, &id).await.status, StatusCode::OK);
    let r = app.call(Method::DELETE, &path, Some(&app.admin), None).await;
    assert_problem(&r, StatusCode::CONFLICT, "join_request_closed");
    let rejected: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE kind = 'join_request_rejected'")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(rejected, 1);
}

/// §5.4 step 3: at most 2 open per device, 6 created per device per hour, 4 open per account (`429`).
#[tokio::test]
async fn the_limits_bound_one_stolen_phone() {
    let app = TestApp::new().await;
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let (a, _, _, _) = open(&app, phone).await;
    let (b, _, _, _) = open(&app, phone).await;
    let (third, _, _) = body(&app);
    assert_problem(
        &create(&app, phone, &third).await,
        StatusCode::TOO_MANY_REQUESTS,
        "too_many_join_requests",
    );
    // Closing them frees the open slots, but not the hourly count.
    for id in [a, b] {
        let path = format!("/v1/nodes/join-requests/{id}");
        assert_eq!(
            app.device_call(phone, Method::DELETE, &path, None).await.status,
            StatusCode::NO_CONTENT
        );
    }
    for _ in 0..4 {
        let (id, _, _, _) = open(&app, phone).await;
        let path = format!("/v1/nodes/join-requests/{id}");
        assert_eq!(
            app.device_call(phone, Method::DELETE, &path, None).await.status,
            StatusCode::NO_CONTENT
        );
    }
    assert_problem(
        &create(&app, phone, &third).await,
        StatusCode::TOO_MANY_REQUESTS,
        "too_many_join_requests",
    );
    // An hour later, it may again.
    app.clock.advance(Duration::hours(1));
    let (fresh, _, _) = body(&app);
    assert_eq!(create(&app, phone, &fresh).await.status, StatusCode::CREATED);
    // The account: 4 open requests in total, whichever devices opened them.
    let mut phones = Vec::new();
    for _ in 0..2 {
        phones.push(app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await);
    }
    let (b1, _, _) = body(&app);
    assert_eq!(create(&app, phones[0], &b1).await.status, StatusCode::CREATED);
    assert_eq!(create(&app, phones[0], &b1).await.status, StatusCode::CREATED);
    assert_eq!(create(&app, phones[1], &b1).await.status, StatusCode::CREATED);
    assert_problem(
        &create(&app, phones[1], &b1).await,
        StatusCode::TOO_MANY_REQUESTS,
        "too_many_join_requests",
    );
}
