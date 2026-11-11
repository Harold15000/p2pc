// SPDX-License-Identifier: AGPL-3.0-only

//! REST endpoints of T05: `GET /v1/server`, join tokens (§5) and nodes (§7), with the scopes of the §7 table and
//! account filtering (SI-7). The agent protocol itself is in `gateway.rs`.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use common::{T0, TestApp, assert_problem, inventory};
use p2pc_proto::api::Scope;
use p2pc_proto::auth::{JoinToken, ServerAddress};
use p2pc_proto::ids::{AccountId, JoinTokenId, NodeId, ProjectId};
use p2pc_server::app::{AppState, router};
use p2pc_server::clock::Clock;
use p2pc_server::config::Config;
use p2pc_server::store::{self, join_tokens, nodes};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;

async fn create_token(app: &TestApp, body: Value) -> (JoinToken, Value) {
    let r = app
        .call(Method::POST, "/v1/nodes/join-tokens", Some(&app.admin), Some(body))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.headers.get("cache-control").unwrap(), "no-store");
    let v = r.json();
    (JoinToken::decode(v["join_token"].as_str().unwrap()).unwrap(), v)
}

/// Enrolls a node directly through the store (what a `Join` does), for REST tests.
async fn enroll(app: &TestApp, account: AccountId, project: ProjectId, hostname: &str) -> NodeId {
    let mut tx = store::begin_immediate(&app.db).await.unwrap();
    let token_id = JoinTokenId::generate();
    let token = JoinToken::generate("a".repeat(64), vec![], Duration::minutes(15), T0).unwrap();
    // A key of the right account is required by the foreign key; init's admin key belongs to the owner.
    let key_id: String = sqlx::query_scalar("SELECT key_id FROM api_keys WHERE account_id = ? LIMIT 1")
        .bind(account.to_string())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    join_tokens::insert(
        &mut tx,
        account,
        &join_tokens::NewJoinToken {
            id: token_id,
            project_id: project,
            code_digest: token.code_hash(),
            label: None,
            created_by: p2pc_proto::api::Principal::Key(key_id.parse().unwrap()),
            bound_iroh_node_id: None,
            pre_approved: false,
            expires_at: token.expires_at,
        },
        T0,
    )
    .await
    .unwrap();
    let node = nodes::insert(
        &mut tx,
        &nodes::NewNode {
            id: NodeId::generate(),
            account_id: account,
            project_id: project,
            iroh_node_id: data_encoding::HEXLOWER.encode(&rand_bytes()),
            inventory: inventory(hostname),
            token_id,
        },
        T0,
    )
    .await
    .unwrap();
    assert!(
        join_tokens::consume(&mut tx, &token.code_hash(), node.id, T0)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    node.id
}

fn rand_bytes() -> [u8; 32] {
    *iroh::SecretKey::generate().public().as_bytes()
}

#[tokio::test]
async fn get_server_returns_the_node_id_relays_address_and_version() {
    let app = TestApp::new().await;
    let reader = app.key_with(&[Scope::JobsRead]).await;
    let r = app.get("/v1/server", &reader).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let v = r.json();
    let key = p2pc_server::identity::load(&app.data_dir()).unwrap();
    assert_eq!(v["node_id"], key.public().to_string());
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    let address: ServerAddress = v["address"].as_str().unwrap().parse().unwrap();
    assert_eq!(address.server, key.public().to_string());
    let relays: Vec<String> = serde_json::from_value(v["relays"].clone()).unwrap();
    assert_eq!(address.relays.iter().map(|u| u.to_string()).collect::<Vec<_>>(), relays);
    assert!(!relays.is_empty(), "empty iroh.relays means n0's public relays");
    assert_problem(
        &app.call(Method::GET, "/v1/server", None, None).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
}

#[tokio::test]
async fn join_tokens_are_created_once_with_the_server_hints() {
    let app = TestApp::new().await;
    let (token, v) = create_token(&app, json!({"label": "laptop"})).await;
    let id: JoinTokenId = v["id"].as_str().unwrap().parse().unwrap();
    // Default validity: 15 minutes, from the server's clock.
    assert_eq!(token.expires_at, T0 + Duration::minutes(15));
    assert_eq!(v["expires_at"], "2026-11-05T10:15:00Z");
    assert_eq!(token.server, app.state.server.node_id().to_string());
    assert_eq!(token.relays, app.state.server.relays());
    // The row stores the digest of the code, never the code.
    let digest: String = sqlx::query_scalar("SELECT code_digest FROM join_tokens WHERE id = ?")
        .bind(id.to_string())
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(digest, token.code_hash().to_stored());
    // Listing never shows the token or the code.
    let text = v["join_token"].as_str().unwrap();
    let r = app.get("/v1/nodes/join-tokens", &app.admin).await;
    assert_eq!(r.status, StatusCode::OK);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert!(!body.contains(&text["p2pc_join_".len()..]), "{body}");
    assert!(!body.contains("join_token\""), "{body}");
    let item = &r.json()["items"][0];
    assert_eq!(item["id"], id.to_string());
    assert_eq!(item["label"], "laptop");
    assert_eq!(item["created_by_key_id"], app.admin_key.key_id().to_string());
    assert_eq!(item["consumed_at"], Value::Null);
    // Audited without the token.
    let audit = app.get("/v1/audit?kind=join_token_created", &app.admin).await;
    let a = audit.json();
    assert_eq!(a["items"][0]["subject_id"], id.to_string());
    assert!(!String::from_utf8_lossy(&audit.body).contains("p2pc_join_"));
}

#[tokio::test]
async fn join_token_validity_and_labels_are_bounded() {
    let app = TestApp::new().await;
    let (t, _) = create_token(&app, json!({"ttl_s": 86_400})).await;
    assert_eq!(t.expires_at, T0 + Duration::hours(24));
    let (t, _) = create_token(&app, json!({"ttl_s": 1})).await;
    assert_eq!(t.expires_at, T0 + Duration::seconds(1));
    for body in [
        json!({"ttl_s": 0}),
        json!({"ttl_s": 86_401}),
        json!({"label": ""}),
        json!({"label": "x".repeat(257)}),
        json!({"label": "a\nb"}),
    ] {
        let r = app
            .call(
                Method::POST,
                "/v1/nodes/join-tokens",
                Some(&app.admin),
                Some(body.clone()),
            )
            .await;
        assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
    }
    let r = app
        .call(
            Method::POST,
            "/v1/nodes/join-tokens",
            Some(&app.admin),
            Some(json!({"ttl": 5})),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "unknown fields are refused");
}

#[tokio::test]
async fn join_tokens_need_the_admin_scope() {
    let app = TestApp::new().await;
    let key = app
        .key_with(&[Scope::NodesRead, Scope::NodesWrite, Scope::JobsRead, Scope::JobsWrite])
        .await;
    let r = app
        .call(Method::POST, "/v1/nodes/join-tokens", Some(&key), Some(json!({})))
        .await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    assert_problem(
        &app.get("/v1/nodes/join-tokens", &key).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let (_, v) = create_token(&app, json!({})).await;
    let r = app
        .call(
            Method::DELETE,
            &format!("/v1/nodes/join-tokens/{}", v["id"].as_str().unwrap()),
            Some(&key),
            None,
        )
        .await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
}

#[tokio::test]
async fn revoking_a_token_is_idempotent_and_a_consumed_one_is_a_conflict() {
    let app = TestApp::new().await;
    let (_, v) = create_token(&app, json!({})).await;
    let uri = format!("/v1/nodes/join-tokens/{}", v["id"].as_str().unwrap());
    for _ in 0..2 {
        let r = app.call(Method::DELETE, &uri, Some(&app.admin), None).await;
        assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    }
    let list = app.get("/v1/nodes/join-tokens", &app.admin).await.json();
    assert_eq!(list["items"][0]["revoked_at"], "2026-11-05T10:00:00Z");
    let audit = app.get("/v1/audit?kind=join_token_revoked", &app.admin).await.json();
    assert_eq!(audit["items"].as_array().unwrap().len(), 1, "audited once");

    // A consumed token.
    let node = enroll(&app, app.account_id, app.project_id, "box").await;
    let consumed: String = sqlx::query_scalar("SELECT id FROM join_tokens WHERE consumed_by_node_id = ?")
        .bind(node.to_string())
        .fetch_one(&app.db)
        .await
        .unwrap();
    let r = app
        .call(
            Method::DELETE,
            &format!("/v1/nodes/join-tokens/{consumed}"),
            Some(&app.admin),
            None,
        )
        .await;
    assert_problem(&r, StatusCode::CONFLICT, "token_consumed");
    for bad in [
        "jtk_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "nope",
        "node_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ] {
        let r = app
            .call(
                Method::DELETE,
                &format!("/v1/nodes/join-tokens/{bad}"),
                Some(&app.admin),
                None,
            )
            .await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    }
}

#[tokio::test]
async fn join_tokens_list_with_a_cursor() {
    let app = TestApp::new().await;
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(
            create_token(&app, json!({})).await.1["id"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    let p1 = app.get("/v1/nodes/join-tokens?limit=2", &app.admin).await.json();
    let cursor = p1["next_cursor"].as_str().unwrap();
    let p2 = app
        .get(&format!("/v1/nodes/join-tokens?limit=2&cursor={cursor}"), &app.admin)
        .await
        .json();
    let got: Vec<String> = p1["items"]
        .as_array()
        .unwrap()
        .iter()
        .chain(p2["items"].as_array().unwrap())
        .map(|i| i["id"].as_str().unwrap().to_string())
        .collect();
    let mut want = ids.clone();
    want.sort();
    assert_eq!(got, want);
    assert_eq!(p2["next_cursor"], Value::Null);
    let r = app.get("/v1/nodes/join-tokens?cursor=bogus", &app.admin).await;
    assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
}

/// A clock answering a scripted sequence, then repeating the last time (as in `recheck.rs`).
#[derive(Debug)]
struct ScriptedClock(Mutex<VecDeque<OffsetDateTime>>);

impl Clock for ScriptedClock {
    fn now(&self) -> OffsetDateTime {
        let mut q = self.0.lock().unwrap();
        if q.len() > 1 {
            q.pop_front().unwrap()
        } else {
            *q.front().unwrap()
        }
    }
}

/// §5 "Re-checked at the point of use": a key that expires between authentication and the handler gets the plain
/// `401`, and no token is created or revoked.
#[tokio::test]
async fn a_key_that_expires_mid_request_cannot_create_or_revoke_join_tokens() {
    let app = TestApp::new().await;
    let (caller, _) = app
        .create_key(json!({"scopes": ["admin"], "expires_at": "2026-11-05T11:00:00Z"}))
        .await;
    let (_, v) = create_token(&app, json!({})).await;
    let token_id = v["id"].as_str().unwrap().to_string();
    let plain_401 = app.call(Method::GET, "/v1/whoami", None, None).await.body;
    let clock = Arc::new(ScriptedClock(Mutex::new(VecDeque::from([T0]))));
    let config = Config::load(&app.data_dir().join("server.toml")).unwrap();
    let state = AppState::load(app.db.clone(), config, clock.clone()).await.unwrap();
    let router = router(state);
    let late = T0 + Duration::hours(2);
    let send = |method: Method, uri: String, body: Option<Value>| {
        let router = router.clone();
        let caller = caller.clone();
        async move {
            let mut req = axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", format!("Bearer {caller}"));
            let body = match body {
                Some(v) => {
                    req = req.header("content-type", "application/json");
                    axum::body::Body::from(v.to_string())
                }
                None => axum::body::Body::empty(),
            };
            let resp = router.oneshot(req.body(body).unwrap()).await.unwrap();
            let status = resp.status();
            (status, axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap())
        }
    };
    *clock.0.lock().unwrap() = VecDeque::from([T0, late]);
    let (status, body) = send(Method::POST, "/v1/nodes/join-tokens".into(), Some(json!({}))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, plain_401);
    *clock.0.lock().unwrap() = VecDeque::from([T0, late]);
    let (status, body) = send(Method::DELETE, format!("/v1/nodes/join-tokens/{token_id}"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, plain_401);
    // Nothing changed.
    let list = app.get("/v1/nodes/join-tokens", &app.admin).await.json();
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert_eq!(list["items"][0]["revoked_at"], Value::Null);
    // Control: with a steady clock, the same key revokes it.
    *clock.0.lock().unwrap() = VecDeque::from([T0]);
    let (status, _) = send(Method::DELETE, format!("/v1/nodes/join-tokens/{token_id}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn nodes_list_get_drain_resume_and_delete() {
    let app = TestApp::new().await;
    let reader = app.key_with(&[Scope::NodesRead]).await;
    let writer = app.key_with(&[Scope::NodesWrite]).await;
    let a = enroll(&app, app.account_id, app.project_id, "Box.example.invalid").await;
    let b = enroll(&app, app.account_id, app.project_id, "box").await;
    let c = enroll(&app, app.account_id, app.project_id, "BOX").await;

    let list = app.get("/v1/nodes", &reader).await;
    assert_eq!(list.status, StatusCode::OK, "{:?}", list.body);
    let items = list.json()["items"].as_array().unwrap().clone();
    // §5 "Names": sanitized from the hostname, unique per account case-insensitively.
    let names: Vec<&str> = items.iter().map(|n| n["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["box", "box-1", "box-2"]);
    assert_eq!(items[0]["hostname"], "Box.example.invalid");
    assert_eq!(items[0]["state"], "offline");
    assert_eq!(items[0]["draining"], false);
    assert_eq!(items[0]["free"]["cpu"], 6.0);

    let one = app.get(&format!("/v1/nodes/{a}"), &reader).await;
    assert_eq!(one.json()["id"], a.to_string());
    assert_problem(
        &app.get("/v1/nodes/node_01ARZ3NDEKTSV4RRFFQ69G5FAV", &reader).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );

    // Scopes (§7): nodes:read reads, nodes:write drains, resumes and deletes.
    let r = app
        .call(Method::POST, &format!("/v1/nodes/{b}/drain"), Some(&reader), None)
        .await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    assert_problem(&app.get("/v1/nodes", &writer).await, StatusCode::FORBIDDEN, "forbidden");
    let r = app
        .call(Method::POST, &format!("/v1/nodes/{b}/drain"), Some(&writer), None)
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.json()["draining"], true);
    let r = app
        .call(Method::POST, &format!("/v1/nodes/{b}/resume"), Some(&writer), None)
        .await;
    assert_eq!(r.json()["draining"], false);

    let r = app
        .call(Method::DELETE, &format!("/v1/nodes/{c}"), Some(&writer), None)
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = app
        .call(Method::DELETE, &format!("/v1/nodes/{c}"), Some(&writer), None)
        .await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    assert_problem(
        &app.get(&format!("/v1/nodes/{c}"), &reader).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    let audit = app.get("/v1/audit?kind=node_deleted", &app.admin).await.json();
    assert_eq!(audit["items"][0]["subject_id"], c.to_string());
    // A deleted node's name is free again.
    let d = enroll(&app, app.account_id, app.project_id, "box").await;
    let name = app.get(&format!("/v1/nodes/{d}"), &reader).await.json()["name"].clone();
    assert_eq!(name, "box-2");
}

#[tokio::test]
async fn nodes_filter_by_state_and_paginate() {
    let app = TestApp::new().await;
    let mut ids = Vec::new();
    for i in 0..3 {
        ids.push(enroll(&app, app.account_id, app.project_id, &format!("n{i}")).await);
    }
    let mut conn = app.db.acquire().await.unwrap();
    nodes::mark_connected(&mut conn, ids[1], T0).await.unwrap();
    nodes::set_draining(&mut conn, app.account_id, ids[2], true)
        .await
        .unwrap();
    nodes::mark_connected(&mut conn, ids[2], T0).await.unwrap();
    drop(conn);
    let names = |v: Value| -> Vec<String> {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["name"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(
        names(app.get("/v1/nodes?state=online", &app.admin).await.json()),
        ["n1", "n2"]
    );
    assert_eq!(
        names(app.get("/v1/nodes?state=offline", &app.admin).await.json()),
        ["n0"]
    );
    let draining = app.get(&format!("/v1/nodes/{}", ids[2]), &app.admin).await.json();
    assert_eq!(
        (draining["state"].clone(), draining["draining"].clone()),
        (json!("online"), json!(true))
    );
    let r = app.get("/v1/nodes?state=draining", &app.admin).await;
    assert_problem(&r, StatusCode::BAD_REQUEST, "invalid_query");
    let p1 = app.get("/v1/nodes?limit=2", &app.admin).await.json();
    assert_eq!(names(p1.clone()), ["n0", "n1"]);
    let cursor = p1["next_cursor"].as_str().unwrap();
    let p2 = app
        .get(&format!("/v1/nodes?limit=2&cursor={cursor}"), &app.admin)
        .await
        .json();
    assert_eq!(names(p2.clone()), ["n2"]);
    assert_eq!(p2["next_cursor"], Value::Null);
}

/// SI-7: another account's nodes and join tokens are invisible and untouchable.
#[tokio::test]
async fn another_accounts_nodes_and_tokens_are_invisible() {
    let app = TestApp::new().await;
    // A second account with a project and a key, created directly (v0.1 has one owner, but the check must exist).
    let other = AccountId::generate();
    let project = ProjectId::generate();
    sqlx::query("INSERT INTO accounts (account_id, is_owner, created_at) VALUES (?, 0, 0)")
        .bind(other.to_string())
        .execute(&app.db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO projects (project_id, account_id, name, created_at) VALUES (?, ?, 'default', 0)")
        .bind(project.to_string())
        .bind(other.to_string())
        .execute(&app.db)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO api_keys (key_id, account_id, project_id, secret_digest, scopes, created_at) \
         VALUES (?, ?, ?, ?, '[\"admin\"]', 0)",
    )
    .bind(p2pc_proto::ids::KeyId::generate().to_string())
    .bind(other.to_string())
    .bind(project.to_string())
    .bind(p2pc_proto::auth::ApiKey::generate().hash().to_stored())
    .execute(&app.db)
    .await
    .unwrap();
    let theirs = enroll(&app, other, project, "theirs").await;
    let token: String = sqlx::query_scalar("SELECT id FROM join_tokens WHERE account_id = ?")
        .bind(other.to_string())
        .fetch_one(&app.db)
        .await
        .unwrap();
    let mine = enroll(&app, app.account_id, app.project_id, "theirs").await;

    let list = app.get("/v1/nodes", &app.admin).await.json();
    let ids: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [mine.to_string()]);
    // The name is unique per account: the same base in another account does not collide.
    assert_eq!(list["items"][0]["name"], "theirs");
    for (method, uri) in [
        (Method::GET, format!("/v1/nodes/{theirs}")),
        (Method::POST, format!("/v1/nodes/{theirs}/drain")),
        (Method::POST, format!("/v1/nodes/{theirs}/resume")),
        (Method::DELETE, format!("/v1/nodes/{theirs}")),
        (Method::DELETE, format!("/v1/nodes/join-tokens/{token}")),
    ] {
        let r = app.call(method.clone(), &uri, Some(&app.admin), None).await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    }
    let tokens = app.get("/v1/nodes/join-tokens", &app.admin).await.json();
    assert!(
        tokens["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["id"] != token.as_str()),
        "{tokens}"
    );
    // Their node is untouched.
    let mut conn = app.db.acquire().await.unwrap();
    let row = nodes::get(&mut conn, other, theirs).await.unwrap().unwrap();
    assert!(row.deleted_at.is_none() && !row.draining);
}
