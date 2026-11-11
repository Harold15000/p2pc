// SPDX-License-Identifier: AGPL-3.0-only

//! Join tokens of H2 through the **real agent gateway** (`p2pc/agent/1` on loopback, relays disabled), with no change
//! to the gateway itself: the rules live in the store functions a `Join` already calls (H2 spec §5.4, §5.5, SI-H2-16,
//! SI-H2-19).
//!
//! - The token of an approved join request enrolls only the agent NodeId it is bound to: any other NodeId gets H1's
//!   `invalid_token` answer and the token stays unused.
//! - A node is created `approved` only when its token carries an `admin`'s approval; an `admin` device's token
//!   without `pre_approved` gives a `pending_approval` node until an `admin` approves it.
//! - A principal with `nodes:join` and no `admin`, an API key or a developer device, mints a token whose node starts
//!   `pending_approval`: it connects and reports like any node, and gets **no lease** until an `admin` approves it,
//!   and one after (SI-H2-19, end to end).

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::fleet::Fleet;
use common::{DeviceLimits, assert_problem};
use iroh::SecretKey;
use p2pc_proto::api::{DEVELOPER_DEVICE_PROFILE, PHONE_PROFILE, Scope};
use p2pc_proto::auth::JoinToken;
use p2pc_proto::ids::DeviceId;
use p2pc_proto::invite::{ListenerNonce, node_phrase};
use p2pc_proto::protocol::{AgentMsg, ServerMsg};
use p2pc_server::clock::Clock;
use p2pc_server::devices_api::ed25519_node_id;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

/// The NodeId of `key`, as the hub stores it: 64 lowercase hex characters.
fn node_id_of(key: &SecretKey) -> String {
    let id = key.public().to_string();
    assert!(ed25519_node_id(&id).is_some(), "{id}");
    id
}

async fn token_rows(fleet: &Fleet) -> (i64, i64) {
    sqlx::query_as("SELECT COUNT(*), COALESCE(SUM(consumed_at IS NOT NULL), 0) FROM join_tokens")
        .fetch_one(&fleet.app.db)
        .await
        .unwrap()
}

async fn node(fleet: &Fleet, id: p2pc_proto::ids::NodeId) -> Value {
    let r = fleet.app.get(&format!("/v1/nodes/{id}"), &fleet.app.admin).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    r.json()
}

#[tokio::test]
async fn the_token_of_a_join_request_enrolls_only_its_bound_agent() {
    let fleet = Fleet::start().await;
    let app = &fleet.app;
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let agent_key = SecretKey::generate();
    let agent_id = node_id_of(&agent_key);
    // The phone relays the invite, reveals the listener nonce, the hub PC approves, the phone fetches the token.
    let nonce = ListenerNonce::generate();
    let body = json!({
        "listener_node_id": node_id_of(&SecretKey::generate()),
        "iroh_node_id": agent_id,
        "invite_expires_at": (app.clock.now() + time::Duration::minutes(15)).format(&Rfc3339).unwrap(),
        "listener_commitment": nonce.commitment().to_string(),
    });
    let r = app
        .device_call(phone, Method::POST, "/v1/nodes/join-requests", Some(body))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let id = r.json()["id"].as_str().unwrap().to_string();
    let reveal = json!({"listener_nonce": data_encoding::HEXLOWER.encode(nonce.expose_bytes())});
    let r = app
        .device_call(
            phone,
            Method::POST,
            &format!("/v1/nodes/join-requests/{id}/reveal"),
            Some(reveal),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = app
        .call(
            Method::POST,
            &format!("/v1/nodes/join-requests/{id}/approve"),
            Some(&app.admin),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = app
        .device_call(
            phone,
            Method::POST,
            &format!("/v1/nodes/join-requests/{id}/token"),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let token = JoinToken::decode(r.json()["join_token"].as_str().unwrap()).unwrap();

    // A machine with another key that got hold of the token: H1's invalid-token answer, and nothing changed.
    let (_stranger, answer) = fleet.join_as(&SecretKey::generate(), token.clone()).await;
    assert!(
        matches!(&answer, Some(ServerMsg::Error { code, .. }) if code == "invalid_token"),
        "{answer:?}"
    );
    assert_eq!(token_rows(&fleet).await, (1, 0), "the token stays unused");
    let nodes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(nodes, 0);

    // The agent the request named: enrolled, and approved at once (the token carries the admin's approval).
    let (mut agent, answer) = fleet.join_as(&agent_key, token).await;
    assert!(matches!(answer, Some(ServerMsg::Welcome { .. })), "{answer:?}");
    agent.sync().await;
    assert_eq!(token_rows(&fleet).await, (1, 1));
    let v = node(&fleet, agent.node_id.unwrap()).await;
    assert!(v.get("approval").is_none(), "approved is the default, left out: {v}");
    assert_eq!(
        v["enrolled_by"],
        json!({"kind": "key", "id": app.admin_key.key_id().to_string()}),
        "the approving principal minted the token"
    );
    assert_eq!(v["node_phrase"], node_phrase(&agent_id.parse().unwrap()).to_string());
    // And it gets work.
    let (_job, _lease, _epoch) = fleet.running(&mut agent).await;
}

#[tokio::test]
async fn a_node_is_approved_at_enrollment_only_with_an_admins_approval() {
    let fleet = Fleet::start().await;
    let app = &fleet.app;
    let joiner = app.key_with(&[Scope::NodesJoin]).await;
    assert_eq!(token_rows(&fleet).await, (0, 0));

    // The hub PC's own node at first run (§8.2 step 4): the owner device mints a `pre_approved` token of 300 s over
    // its device connection; the node is approved when it enrolls.
    let owner = app.add_device(&[Scope::Admin], DeviceLimits::default()).await;
    let r = app
        .device_call(
            owner,
            Method::POST,
            "/v1/nodes/join-tokens",
            Some(json!({"pre_approved": true, "ttl_s": 300})),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let token = JoinToken::decode(r.json()["join_token"].as_str().unwrap()).unwrap();
    let (mut own, answer) = fleet.join_as(&SecretKey::generate(), token).await;
    assert!(matches!(answer, Some(ServerMsg::Welcome { .. })), "{answer:?}");
    own.sync().await;
    let v = node(&fleet, own.node_id.unwrap()).await;
    assert!(v.get("approval").is_none(), "{v}");
    assert_eq!(v["enrolled_by"], json!({"kind": "device", "id": owner.to_string()}));
    own.conn.close(0u32.into(), b"done");

    // Without `pre_approved`, the same device's token gives a pending node ("Copy invite").
    let r = app
        .device_call(owner, Method::POST, "/v1/nodes/join-tokens", Some(json!({})))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let token = JoinToken::decode(r.json()["join_token"].as_str().unwrap()).unwrap();
    let (mut invited, answer) = fleet.join_as(&SecretKey::generate(), token).await;
    assert!(matches!(answer, Some(ServerMsg::Welcome { .. })), "{answer:?}");
    invited.sync().await;
    let id = invited.node_id.unwrap();
    assert_eq!(node(&fleet, id).await["approval"], "pending_approval");
    // A non-`admin` cannot approve it; an `admin` can.
    let path = format!("/v1/nodes/{id}/approve");
    let r = app.call(Method::POST, &path, Some(&joiner), None).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    let r = app.call(Method::POST, &path, Some(&app.admin), None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert!(node(&fleet, id).await.get("approval").is_none());
}

/// Who mints the token of [`a_pending_node_gets_no_lease_until_an_admin_approves_it`]: a principal with `nodes:join`
/// and no `admin`.
enum Joiner {
    Key(String),
    Device(DeviceId),
}

impl Joiner {
    async fn call(&self, app: &common::TestApp, uri: &str, body: Option<Value>) -> common::Resp {
        match self {
            Joiner::Key(key) => app.call(Method::POST, uri, Some(key), body).await,
            Joiner::Device(device) => app.device_call(*device, Method::POST, uri, body).await,
        }
    }

    fn principal(&self) -> Value {
        match self {
            Joiner::Key(key) => json!({"kind": "key", "id": &key[8..20]}),
            Joiner::Device(device) => json!({"kind": "device", "id": device.to_string()}),
        }
    }
}

/// SI-H2-19, end to end: a node enrolled with a token of a non-`admin` `nodes:join` principal gets no lease until an
/// `admin` approves it, and gets one after the approval. Through the REST API, the real agent gateway and the
/// scheduler as `serve` wires them.
async fn a_pending_node_gets_no_lease_until_an_admin_approves_it(fleet: &Fleet, by: Joiner) {
    let app = &fleet.app;
    let r = by.call(app, "/v1/nodes/join-tokens", Some(json!({}))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let token = JoinToken::decode(r.json()["join_token"].as_str().unwrap()).unwrap();
    // The node enrolls and connects like any node.
    let (mut agent, answer) = fleet.join_as(&SecretKey::generate(), token).await;
    assert!(matches!(answer, Some(ServerMsg::Welcome { .. })), "{answer:?}");
    agent.sync().await;
    let id = agent.node_id.unwrap();
    let v = node(fleet, id).await;
    assert_eq!(
        (v["approval"].as_str(), v["state"].as_str()),
        (Some("pending_approval"), Some("online"))
    );
    assert_eq!(v["enrolled_by"], by.principal());
    // A job is waiting, and the node could run it: pass after pass, across the offer cooldown, nothing is offered.
    let job = fleet
        .submit(json!({"image": "docker.io/library/alpine:3", "command": ["true"],
            "resources": {"cpu": 1, "memory_mb": 256}}))
        .await;
    for _ in 0..3 {
        let report = fleet.scheduler.tick().await;
        assert_eq!((report.errors, report.offered), (0, 0));
        let got = agent.sync().await;
        assert!(got.is_empty(), "a pending node was sent {got:?}");
        app.clock.advance(time::Duration::seconds(61));
    }
    let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM leases")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(leases, 0, "not even an offer");
    let v = app.get(&format!("/v1/jobs/{job}"), &app.admin).await.json();
    assert_eq!(v["status"], "queued");
    assert_eq!(v["reason"], "waiting for approval on the hub PC");
    // The principal that enrolled it cannot approve it (SI-H2-19), and the node still gets nothing.
    let approve = format!("/v1/nodes/{id}/approve");
    let r = by.call(app, &approve, None).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    assert_eq!(fleet.scheduler.tick().await.offered, 0);
    assert!(agent.sync().await.is_empty());
    // An `admin` approves it: the next pass offers the job, and it runs there.
    let r = app.call(Method::POST, &approve, Some(&app.admin), None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let report = fleet.scheduler.tick().await;
    assert_eq!((report.errors, report.offered), (0, 1));
    let (lease_id, epoch) = agent.next_lease().await;
    agent.send(&AgentMsg::LeaseAccepted { lease_id, epoch }).await;
    agent.sync().await;
    let v = app.get(&format!("/v1/jobs/{job}"), &app.admin).await.json();
    assert_eq!((v["status"].as_str(), v["reason"].as_str()), (Some("assigned"), None));
    assert_eq!(v["node_id"], id.to_string());
}

#[tokio::test]
async fn a_node_of_a_nodes_join_api_key_gets_no_lease_until_an_admin_approves_it() {
    let fleet = Fleet::start().await;
    let key = fleet.app.key_with(&[Scope::NodesJoin]).await;
    a_pending_node_gets_no_lease_until_an_admin_approves_it(&fleet, Joiner::Key(key)).await;
}

#[tokio::test]
async fn a_node_of_a_developer_device_gets_no_lease_until_an_admin_approves_it() {
    let fleet = Fleet::start().await;
    let device = fleet
        .app
        .add_device(&DEVELOPER_DEVICE_PROFILE, DeviceLimits::default())
        .await;
    a_pending_node_gets_no_lease_until_an_admin_approves_it(&fleet, Joiner::Device(device)).await;
}
