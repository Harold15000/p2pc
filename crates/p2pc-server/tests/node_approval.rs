// SPDX-License-Identifier: AGPL-3.0-only

//! Join tokens of H2 and node approval (H2 spec §5.4, §5.5, §7.3, SI-H2-19): who may mint a token and for how long,
//! `pre_approved`, the stored rule that makes a node `approved` or `pending_approval`, tokens bound to an agent
//! NodeId, and `POST /v1/nodes/{id}/approve` with the node phrase.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::{DeviceLimits, T0, TestApp, assert_problem, inventory, node_key};
use p2pc_proto::api::{DEVELOPER_DEVICE_PROFILE, PHONE_PROFILE, Principal, Scope};
use p2pc_proto::auth::JoinToken;
use p2pc_proto::ids::{DeviceId, JoinTokenId, NodeId};
use p2pc_proto::invite::node_phrase;
use p2pc_server::store::{self, join_tokens, nodes};
use serde_json::{Value, json};

/// Who mints a token in these tests.
#[derive(Clone, Copy)]
enum Minter<'a> {
    Key(&'a str),
    Device(DeviceId),
}

async fn mint(app: &TestApp, by: Minter<'_>, body: Value) -> common::Resp {
    match by {
        Minter::Key(k) => {
            app.call(Method::POST, "/v1/nodes/join-tokens", Some(k), Some(body))
                .await
        }
        Minter::Device(d) => {
            app.device_call(d, Method::POST, "/v1/nodes/join-tokens", Some(body))
                .await
        }
    }
}

/// Mints a token and enrolls a node with it through the store, as a `Join` does (`gateway/agent.rs`): insert the
/// node, then consume the token. Returns the node row, or `None` when the consume refused the token.
async fn enroll_with(app: &TestApp, by: Minter<'_>, body: Value, agent: &str) -> Option<nodes::NodeRow> {
    let r = mint(app, by, body).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let token = JoinToken::decode(r.json()["join_token"].as_str().unwrap()).unwrap();
    enroll_token(app, &token, agent).await
}

async fn enroll_token(app: &TestApp, token: &JoinToken, agent: &str) -> Option<nodes::NodeRow> {
    let mut tx = store::begin_immediate(&app.db).await.unwrap();
    let row = join_tokens::find_by_digest(&mut tx, &token.code_hash())
        .await
        .unwrap()
        .unwrap();
    let node = nodes::insert(
        &mut tx,
        &nodes::NewNode {
            id: NodeId::generate(),
            account_id: row.account_id,
            project_id: row.project_id,
            iroh_node_id: agent.to_string(),
            inventory: inventory("box"),
            token_id: row.id,
        },
        T0,
    )
    .await
    .unwrap();
    if !join_tokens::consume(&mut tx, &token.code_hash(), node.id, T0)
        .await
        .unwrap()
    {
        return None;
    }
    tx.commit().await.unwrap();
    Some(node)
}

#[tokio::test]
async fn who_may_mint_a_join_token_and_for_how_long() {
    let app = TestApp::new().await;
    let joiner = app.add_device(&DEVELOPER_DEVICE_PROFILE, DeviceLimits::default()).await;
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let admin_device = app.add_device(&[Scope::Admin], DeviceLimits::default()).await;
    let joiner_key = app.key_with(&[Scope::NodesJoin]).await;
    let reader = app.key_with(&[Scope::NodesRead]).await;
    // Without `nodes:join` (the default phone profile has none, SI-H2-19): nothing, whatever is asked for.
    for by in [Minter::Device(phone), Minter::Key(&reader)] {
        for body in [
            json!({}),
            json!({"ttl_s": 900}),
            json!({"pre_approved": true, "ttl_s": 300}),
        ] {
            let r = mint(&app, by, body).await;
            let v = assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
            assert!(v["detail"].as_str().unwrap().contains("`nodes:join`"), "{v}");
        }
    }
    let minted = async || -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM join_tokens")
            .fetch_one(&app.db)
            .await
            .unwrap()
    };
    assert_eq!(minted().await, 0);
    // `nodes:join` without `admin`, an API key or a device: tokens of at most 900 s and nothing else (SI-H2-18).
    for by in [Minter::Key(&joiner_key), Minter::Device(joiner)] {
        for body in [
            json!({}),
            json!({"ttl_s": 900}),
            json!({"ttl_s": 1, "label": "spare PC"}),
        ] {
            let r = mint(&app, by, body).await;
            assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
            let token = JoinToken::decode(r.json()["join_token"].as_str().unwrap()).unwrap();
            assert!(token.expires_at <= T0 + time::Duration::seconds(900));
        }
        for ttl_s in [901, 86_400] {
            let r = mint(&app, by, json!({"ttl_s": ttl_s})).await;
            assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
        }
        // `pre_approved` carries an `admin`'s approval: only an `admin` sets it.
        for body in [
            json!({"pre_approved": true}),
            json!({"pre_approved": true, "ttl_s": 300}),
        ] {
            let r = mint(&app, by, body).await;
            let v = assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
            assert!(v["detail"].as_str().unwrap().contains("`admin`"), "{v}");
        }
        // It mints; it does not list, revoke or approve.
        let r = match by {
            Minter::Key(k) => app.get("/v1/nodes/join-tokens", k).await,
            Minter::Device(d) => app.device_call(d, Method::GET, "/v1/nodes/join-tokens", None).await,
        };
        assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    }
    assert_eq!(minted().await, 6);
    let pre_approved: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM join_tokens WHERE pre_approved = 1")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(pre_approved, 0);
    // `admin`: H1's 24 h, but at most 900 s with `pre_approved`.
    for by in [Minter::Device(admin_device), Minter::Key(&app.admin)] {
        assert_eq!(
            mint(&app, by, json!({"ttl_s": 86_400})).await.status,
            StatusCode::CREATED
        );
        let r = mint(&app, by, json!({"ttl_s": 901, "pre_approved": true})).await;
        assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
        let r = mint(&app, by, json!({"ttl_s": 900, "pre_approved": true})).await;
        assert_eq!(r.status, StatusCode::CREATED);
    }
    // The listing names each minter; a device's token has no key.
    let r = app.get("/v1/nodes/join-tokens?limit=100", &app.admin).await;
    let items = r.json()["items"].as_array().unwrap().clone();
    let by_device: Vec<&Value> = items.iter().filter(|t| t["created_by"]["kind"] == "device").collect();
    assert!(!by_device.is_empty());
    for t in by_device {
        assert_eq!(t["created_by_key_id"], Value::Null);
    }
    let pre: Vec<&Value> = items.iter().filter(|t| t["pre_approved"] == true).collect();
    assert_eq!(pre.len(), 2);
}

/// Inserts a token row minted by `by` straight into the store, `pre_approved` or not: the stored approval rule covers
/// every combination, including the ones the API refuses to mint.
async fn stored_token(app: &TestApp, by: Principal, pre_approved: bool) -> JoinToken {
    let token = JoinToken::generate(
        app.state.server.node_id().to_string(),
        vec![],
        time::Duration::minutes(15),
        T0,
    )
    .unwrap();
    let mut tx = store::begin_immediate(&app.db).await.unwrap();
    join_tokens::insert(
        &mut tx,
        app.account_id,
        &join_tokens::NewJoinToken {
            id: JoinTokenId::generate(),
            project_id: app.project_id,
            code_digest: token.code_hash(),
            label: None,
            created_by: by,
            bound_iroh_node_id: None,
            pre_approved,
            expires_at: token.expires_at,
        },
        T0,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    token
}

/// The stored rule of §5.5: a node is `approved` iff its token has `pre_approved`, or a bound NodeId, or was minted
/// by an `admin` API key; otherwise `pending_approval`.
#[tokio::test]
async fn a_node_is_approved_only_with_an_admins_approval_on_its_token() {
    let app = TestApp::new().await;
    let joiner = app.add_device(&DEVELOPER_DEVICE_PROFILE, DeviceLimits::default()).await;
    let admin_device = app.add_device(&[Scope::Admin], DeviceLimits::default()).await;
    let joiner_key = app.key_with(&[Scope::NodesJoin]).await;
    // Through the API: the `admin` minters, and the `nodes:join` ones, whose node always waits for approval.
    let cases: [(Minter<'_>, Value, &str); 6] = [
        (Minter::Key(&app.admin), json!({}), "approved"),
        (Minter::Key(&app.admin), json!({"pre_approved": true}), "approved"),
        (Minter::Device(admin_device), json!({}), "pending_approval"),
        (Minter::Device(admin_device), json!({"pre_approved": true}), "approved"),
        (Minter::Key(&joiner_key), json!({}), "pending_approval"),
        (Minter::Device(joiner), json!({}), "pending_approval"),
    ];
    for (i, (by, body, want)) in cases.into_iter().enumerate() {
        let node = enroll_with(&app, by, body, &node_key()).await.unwrap();
        let r = app.get(&format!("/v1/nodes/{}", node.id), &app.admin).await;
        let v = r.json();
        // `approval` is left out when approved (additive, H1 clients see H1 bytes).
        let got = v.get("approval").and_then(Value::as_str).unwrap_or("approved");
        assert_eq!(got, want, "case {i}: {v}");
        let enrolled_by = match by {
            Minter::Device(d) => json!({"kind": "device", "id": d.to_string()}),
            Minter::Key(k) => json!({"kind": "key", "id": &k[8..20]}),
        };
        assert_eq!(v["enrolled_by"], enrolled_by, "case {i}");
    }
    // In the store: a token of a non-`admin` principal, key or device, gives a pending node.
    let joiner_key_id: p2pc_proto::ids::KeyId = joiner_key[8..20].parse().unwrap();
    for by in [Principal::Device(joiner), Principal::Key(joiner_key_id)] {
        let token = stored_token(&app, by, false).await;
        let node = enroll_token(&app, &token, &node_key()).await.unwrap();
        assert_eq!(node.approval, p2pc_proto::api::NodeApproval::PendingApproval, "{by}");
        assert_eq!(node.enrolled_by, Some(by));
    }
    // The audit log names the non-`admin` minters of the tokens above.
    let minters: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT actor_key_id, actor_device_id FROM audit_events WHERE kind = 'join_token_created' ORDER BY seq",
    )
    .fetch_all(&app.db)
    .await
    .unwrap();
    assert!(minters.contains(&(Some(joiner_key_id.to_string()), None)));
    assert!(minters.contains(&(None, Some(joiner.to_string()))));
}

/// §5 "Re-enrolling the same machine": a live node that joins again with a new token records that token's minter as
/// `enrolled_by`, a key or a device, in the same `UPDATE` that records the token.
#[tokio::test]
async fn re_enrolling_records_the_new_tokens_minter() {
    let app = TestApp::new().await;
    let admin_device = app.add_device(&[Scope::Admin], DeviceLimits::default()).await;
    let admin_key = Principal::Key(app.admin_key.key_id());
    let node = enroll_with(&app, Minter::Key(&app.admin), json!({}), &node_key())
        .await
        .unwrap();
    assert_eq!(node.enrolled_by, Some(admin_key));
    for by in [Principal::Device(admin_device), admin_key] {
        let token = stored_token(&app, by, true).await;
        let mut tx = store::begin_immediate(&app.db).await.unwrap();
        let row = join_tokens::find_by_digest(&mut tx, &token.code_hash())
            .await
            .unwrap()
            .unwrap();
        let again = nodes::reenroll(
            &mut tx,
            app.account_id,
            node.id,
            row.project_id,
            &inventory("box"),
            row.id,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            join_tokens::consume(&mut tx, &token.code_hash(), node.id, T0)
                .await
                .unwrap()
        );
        tx.commit().await.unwrap();
        assert_eq!(again.id, node.id, "the same node");
        assert_eq!(again.enrolled_via_token_id, row.id);
        assert_eq!(again.enrolled_by, Some(by), "exactly one principal column is set");
        let r = app.get(&format!("/v1/nodes/{}", node.id), &app.admin).await;
        assert_eq!(r.json()["enrolled_by"], serde_json::to_value(by).unwrap());
    }
}

#[tokio::test]
async fn a_bound_token_enrolls_only_its_agent_node_id_and_stays_unused_otherwise() {
    let app = TestApp::new().await;
    let admin_device = app.add_device(&[Scope::Admin], DeviceLimits::default()).await;
    let agent = node_key();
    let token = JoinToken::generate(
        app.state.server.node_id().to_string(),
        vec![],
        time::Duration::minutes(15),
        T0,
    )
    .unwrap();
    let mut tx = store::begin_immediate(&app.db).await.unwrap();
    join_tokens::insert(
        &mut tx,
        app.account_id,
        &join_tokens::NewJoinToken {
            id: JoinTokenId::generate(),
            project_id: app.project_id,
            code_digest: token.code_hash(),
            label: None,
            // An `admin` device's token without `pre_approved`, which alone would give a pending node: the binding
            // (only join requests approved by an `admin` have one) is what approves it.
            created_by: Principal::Device(admin_device),
            bound_iroh_node_id: Some(agent.clone()),
            pre_approved: false,
            expires_at: token.expires_at,
        },
        T0,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    // Another NodeId: refused, and the token is not consumed.
    assert!(enroll_token(&app, &token, &node_key()).await.is_none());
    let consumed: Option<i64> = sqlx::query_scalar("SELECT consumed_at FROM join_tokens WHERE code_digest = ?")
        .bind(token.code_hash().to_stored())
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(consumed, None);
    // The bound NodeId: enrolled, approved.
    let node = enroll_token(&app, &token, &agent).await.unwrap();
    assert_eq!(node.approval, p2pc_proto::api::NodeApproval::Approved);
}

#[tokio::test]
async fn only_an_admin_approves_a_pending_node_and_approval_is_idempotent() {
    let app = TestApp::new().await;
    let joiner = app.add_device(&DEVELOPER_DEVICE_PROFILE, DeviceLimits::default()).await;
    let admin_device = app.add_device(&[Scope::Admin], DeviceLimits::default()).await;
    let agent = node_key();
    // "Copy invite" without "Pre-approve": an `admin` device's token gives a node that waits for approval.
    let node = enroll_with(&app, Minter::Device(admin_device), json!({}), &agent)
        .await
        .unwrap();
    let path = format!("/v1/nodes/{}/approve", node.id);
    // The node phrase is shown while it waits: 6 words from its NodeId.
    let r = app.get(&format!("/v1/nodes/{}", node.id), &app.admin).await;
    let v = r.json();
    assert_eq!(v["approval"], "pending_approval");
    let phrase = node_phrase(&agent.parse().unwrap()).to_string();
    assert_eq!(v["node_phrase"], phrase);
    assert_eq!(phrase.split(' ').count(), 6);
    // A non-admin principal cannot approve (SI-H2-19).
    let writer = app.key_with(&[Scope::NodesWrite, Scope::NodesRead]).await;
    let r = app.call(Method::POST, &path, Some(&writer), None).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    let r = app.device_call(joiner, Method::POST, &path, None).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    let r = app
        .call(
            Method::POST,
            &format!("/v1/nodes/{}/approve", NodeId::generate()),
            Some(&app.admin),
            None,
        )
        .await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    for _ in 0..2 {
        let r = app.call(Method::POST, &path, Some(&app.admin), None).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        assert!(r.json().get("approval").is_none(), "approved is the default, left out");
    }
    let approvals: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE kind = 'node_approved'")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(approvals, 1, "audited once");
}
