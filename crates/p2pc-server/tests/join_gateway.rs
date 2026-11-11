// SPDX-License-Identifier: AGPL-3.0-only

//! Join tokens of H2 through the **real agent gateway** (`p2pc/agent/1` on loopback, relays disabled), with no change
//! to the gateway itself: the rules live in the store functions a `Join` already calls (H2 spec §5.4, §5.5, SI-H2-16,
//! SI-H2-19).
//!
//! - The token of an approved join request enrolls only the agent NodeId it is bound to: any other NodeId gets H1's
//!   `invalid_token` answer and the token stays unused.
//! - A node is created `approved` only when its token carries an `admin`'s approval; an `admin` device's token
//!   without `pre_approved` gives a `pending_approval` node until an `admin` approves it.
//! - A `nodes:join` API key with no `admin` cannot mint a join token at all (`403`), until T2-12.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::fleet::Fleet;
use common::{DeviceLimits, assert_problem};
use iroh::SecretKey;
use p2pc_proto::api::{PHONE_PROFILE, Scope};
use p2pc_proto::auth::JoinToken;
use p2pc_proto::invite::{ListenerNonce, node_phrase};
use p2pc_proto::protocol::ServerMsg;
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
    // An API key with `nodes:join` and no `admin` mints nothing: until the scheduler refuses leases to pending nodes
    // (T2-12), a node of such a token would get work without an `admin`'s approval (SI-H2-19).
    let joiner = app.key_with(&[Scope::NodesJoin]).await;
    let r = app
        .call(Method::POST, "/v1/nodes/join-tokens", Some(&joiner), Some(json!({})))
        .await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
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
