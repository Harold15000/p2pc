// SPDX-License-Identifier: AGPL-3.0-only

//! Volumes (H2 spec §6.1, §7.3): the nodes' `VolumeReport`s, `GET /v1/volumes` and
//! `DELETE /v1/volumes/{node_id}/{name}` with its percent-encoded `{name}` segment, including the route test for a
//! `tpl:` name.
//!
//! The server runs as `serve` wires it, with fake agents over loopback iroh connections (relays disabled). Nothing
//! sleeps to synchronise: an agent's `sync` returns once the hub handled what it sent.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use axum::http::{Method, StatusCode};
use common::fleet::{FakeAgent, Fleet, NowForTests};
use common::ports::eventually;
use common::{DeviceLimits, TestApp, assert_problem, second_account};
use p2pc_proto::api::{FileMeta, JobSpec, PHONE_PROFILE, Principal, Scope};
use p2pc_proto::ids::{JobId, LeaseId, NodeId};
use p2pc_proto::protocol::{AgentMsg, ServerMsg, VolumeDelete, VolumeInfo, VolumeReport};
use p2pc_proto::units::Units;
use p2pc_server::clock::Clock;
use p2pc_server::store::{self, jobs};
use serde_json::{Value, json};
use time::Duration;

const CHAT_VOLUME: &str = "tpl:private-chat/models";
/// `tpl:private-chat/models` as one path segment (H2 §7.3).
const CHAT_SEGMENT: &str = "tpl%3Aprivate-chat%2Fmodels";

/// A node whose agent declared `volumes` (and `service_jobs`, so it can be leased a service with a volume).
async fn node(fleet: &Fleet) -> (FakeAgent, NodeId) {
    let agent = fleet.agent().await;
    let agent = fleet.restart_with(agent, &["service_jobs", "volumes"]).await;
    let id = agent.node_id.unwrap();
    (agent, id)
}

fn volume(fleet: &Fleet, name: &str, size_mb: u64, in_use_by: Option<LeaseId>) -> VolumeInfo {
    VolumeInfo {
        name: name.into(),
        size_mb,
        last_used_at: fleet.app.clock.now_for_tests() - Duration::minutes(5),
        in_use_by,
    }
}

/// Sends a `VolumeReport` and returns what the hub sent back before it acknowledged the next heartbeat.
async fn report(agent: &mut FakeAgent, volumes: Vec<VolumeInfo>) -> Vec<ServerMsg> {
    agent.send(&AgentMsg::VolumeReport(VolumeReport { volumes })).await;
    agent.sync().await
}

async fn list(app: &TestApp, key: &str) -> Vec<Value> {
    let r = app.get("/v1/volumes", key).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    r.json()["items"].as_array().unwrap().clone()
}

async fn delete(app: &TestApp, key: &str, node: NodeId, segment: &str) -> common::Resp {
    app.call(
        Method::DELETE,
        &format!("/v1/volumes/{node}/{segment}"),
        Some(key),
        None,
    )
    .await
}

/// The private chat as its launch stores it, with the template's volume.
fn chat_spec() -> Value {
    json!({"kind": "service", "image": "docker.io/library/nginx:1.27", "command": ["nginx"],
        "resources": {"cpu": 1, "memory_mb": 256},
        "service": {"ports": [{"port": 11434, "name": "api"}]},
        "volumes": [{"name": CHAT_VOLUME, "mount": "/volumes/models/blobs", "max_mb": 20480}],
        "template": {"id": "private-chat", "version": 1, "pull": "qwen3:4b-instruct"}})
}

async fn store_job(app: &TestApp, spec: Value) -> JobId {
    let spec: JobSpec = serde_json::from_value(spec).unwrap();
    let mut tx = store::begin_immediate(&app.db).await.unwrap();
    let new = jobs::NewJob {
        job_id: JobId::generate(),
        account_id: app.account_id,
        project_id: app.project_id,
        principal: Principal::Key(app.admin_key.key_id()),
        files_meta: FileMeta::compute_all(&spec).unwrap(),
        spec,
        spec_hash: format!("sha256:{}", "0".repeat(64)),
        units_reserved: Units::ZERO,
    };
    let row = jobs::insert(&mut tx, &new, app.clock.now()).await.unwrap();
    tx.commit().await.unwrap();
    row.job_id
}

/// Stores the chat job and has `agent` accept and start its lease.
async fn running_chat(fleet: &Fleet, agent: &mut FakeAgent) -> (JobId, LeaseId, u64) {
    let job = store_job(&fleet.app, chat_spec()).await;
    assert_eq!(fleet.scheduler.tick().await.errors, 0);
    let (lease_id, epoch) = agent.next_lease().await;
    agent.send(&AgentMsg::LeaseAccepted { lease_id, epoch }).await;
    agent
        .send(&AgentMsg::JobStarted {
            lease_id,
            epoch,
            started_at: fleet.app.clock.now_for_tests(),
        })
        .await;
    agent.sync().await;
    (job, lease_id, epoch)
}

#[tokio::test]
async fn a_nodes_volume_report_is_what_the_listing_shows() {
    let fleet = Fleet::start().await;
    let app = &fleet.app;
    let (mut agent, node_id) = node(&fleet).await;
    assert!(list(app, &app.admin).await.is_empty());

    let (job, lease_id, _) = running_chat(&fleet, &mut agent).await;
    let sent = report(
        &mut agent,
        vec![
            volume(&fleet, CHAT_VOLUME, 2382, Some(lease_id)),
            volume(&fleet, "cache", 7, None),
        ],
    )
    .await;
    assert!(
        sent.is_empty(),
        "a report from an agent that declared `volumes` is not an error: {sent:?}"
    );
    let items = list(app, &app.admin).await;
    // By node, then by name.
    assert_eq!(items.len(), 2, "{items:?}");
    assert_eq!(
        items[0],
        json!({"name": "cache", "node_id": node_id, "size_mb": 7, "max_mb": 0,
            "last_used_at": "2026-11-05T09:55:00Z", "in_use_by": null})
    );
    // `max_mb` is the limit of the job that mounted it there; `in_use_by` the job of the lease that holds it.
    assert_eq!(
        items[1],
        json!({"name": CHAT_VOLUME, "node_id": node_id, "size_mb": 2382, "max_mb": 20480,
            "last_used_at": "2026-11-05T09:55:00Z", "in_use_by": job})
    );

    // A report is the node's whole list: the next one replaces it.
    report(&mut agent, vec![volume(&fleet, CHAT_VOLUME, 2400, None)]).await;
    let items = list(app, &app.admin).await;
    assert_eq!(items.len(), 1);
    assert_eq!(
        (items[0]["size_mb"].as_u64(), &items[0]["in_use_by"]),
        (Some(2400), &Value::Null)
    );

    // `nodes:read` lists (the phone profile has it); a key without it does not; another account sees nothing.
    let phone = app.add_device(&PHONE_PROFILE, DeviceLimits::default()).await;
    let r = app.device_call(phone, Method::GET, "/v1/volumes", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["items"].as_array().unwrap().len(), 1);
    let jobs_only = app.key_with(&[Scope::JobsRead, Scope::JobsWrite]).await;
    assert_problem(
        &app.get("/v1/volumes", &jobs_only).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let (other, _) = second_account(app).await;
    assert!(list(app, &other).await.is_empty());
}

#[tokio::test]
async fn a_report_keeps_only_volume_names_and_only_its_own_leases() {
    let fleet = Fleet::start().await;
    let app = &fleet.app;
    let (mut agent, _) = node(&fleet).await;
    let (mut second, second_id) = node(&fleet).await;
    let (_, lease_id, _) = running_chat(&fleet, &mut agent).await;
    // The second node names things that are not volume names, and a lease that is not its own.
    report(
        &mut second,
        vec![
            volume(&fleet, "../../etc", 1, None),
            volume(&fleet, "Data", 1, None),
            volume(&fleet, "tpl:private-chat", 1, None),
            volume(&fleet, "tpl:Private/models", 1, None),
            volume(&fleet, "/var/lib/p2pc", 1, None),
            volume(&fleet, "models", 64, Some(lease_id)),
            volume(&fleet, "scratch", 1, Some(LeaseId::generate())),
        ],
    )
    .await;
    let items = list(app, &app.admin).await;
    let seen: Vec<(&str, &str, &Value)> = items
        .iter()
        .map(|v| {
            (
                v["node_id"].as_str().unwrap(),
                v["name"].as_str().unwrap(),
                &v["in_use_by"],
            )
        })
        .collect();
    let second_id = second_id.to_string();
    assert_eq!(
        seen,
        [
            (second_id.as_str(), "models", &Value::Null),
            (second_id.as_str(), "scratch", &Value::Null)
        ]
    );
}

#[tokio::test]
async fn an_agent_that_did_not_declare_volumes_is_not_listened_to() {
    let fleet = Fleet::start().await;
    let app = &fleet.app;
    // Joined, and reconnected without the capability.
    let agent = fleet.agent().await;
    let mut agent = fleet.restart_with(agent, &["service_jobs"]).await;
    let sent = report(&mut agent, vec![volume(&fleet, "cache", 1, None)]).await;
    assert!(
        matches!(sent.as_slice(), [ServerMsg::Error { code, .. }] if code == "unsupported_message"),
        "{sent:?}"
    );
    assert!(list(app, &app.admin).await.is_empty());
}

#[tokio::test]
async fn the_listing_is_paginated() {
    let fleet = Fleet::start().await;
    let app = &fleet.app;
    let (mut agent, _) = node(&fleet).await;
    let names = ["a", "b.c", CHAT_VOLUME, "z_9"];
    report(&mut agent, names.iter().map(|n| volume(&fleet, n, 1, None)).collect()).await;
    let mut seen = Vec::new();
    let mut uri = "/v1/volumes?limit=3".to_string();
    loop {
        let r = app.get(&uri, &app.admin).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        let v = r.json();
        for item in v["items"].as_array().unwrap() {
            seen.push(item["name"].as_str().unwrap().to_string());
        }
        match v["next_cursor"].as_str() {
            // A cursor holds a name, so it goes into the query string percent-encoded, as a client sends it.
            Some(c) => {
                let encoded: String = url::form_urlencoded::byte_serialize(c.as_bytes()).collect();
                uri = format!("/v1/volumes?limit=3&cursor={encoded}");
            }
            None => break,
        }
    }
    assert_eq!(seen, names);
    for bad in [
        "/v1/volumes?cursor=nope",
        "/v1/volumes?limit=0",
        "/v1/volumes?limit=101",
    ] {
        let r = app.get(bad, &app.admin).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {:?}", r.body);
    }
}

/// H2 §7.3: the route test for a `tpl:` name. `{name}` is one percent-encoded path segment, decoded once.
#[tokio::test]
async fn deleting_a_tpl_volume_sends_its_decoded_name_to_the_node() {
    let fleet = Fleet::start().await;
    let app = &fleet.app;
    let (mut agent, node_id) = node(&fleet).await;
    report(
        &mut agent,
        vec![
            volume(&fleet, CHAT_VOLUME, 2382, None),
            volume(&fleet, "cache", 7, None),
        ],
    )
    .await;

    let r = delete(app, &app.admin, node_id, CHAT_SEGMENT).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    // The node is told the decoded name, exactly.
    let sent = agent.sync().await;
    assert_eq!(
        sent,
        [ServerMsg::VolumeDelete(VolumeDelete {
            name: CHAT_VOLUME.into()
        })]
    );
    // A plain name needs no encoding.
    let r = delete(app, &app.admin, node_id, "cache").await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    assert_eq!(
        agent.sync().await,
        [ServerMsg::VolumeDelete(VolumeDelete { name: "cache".into() })]
    );
    // The listing follows the node: its fresh report, sent in answer, no longer has them.
    assert_eq!(list(app, &app.admin).await.len(), 2);
    report(&mut agent, vec![]).await;
    assert!(list(app, &app.admin).await.is_empty());
}

#[tokio::test]
async fn a_name_that_is_not_one_decoded_segment_of_a_reported_volume_is_not_found() {
    let fleet = Fleet::start().await;
    let app = &fleet.app;
    let (mut agent, node_id) = node(&fleet).await;
    report(&mut agent, vec![volume(&fleet, CHAT_VOLUME, 2382, None)]).await;
    for segment in [
        // Not encoded: the `/` makes it two segments, which is no route.
        "tpl:private-chat/models",
        // Encoded twice: decoded once, it is not a volume name.
        "tpl%253Aprivate-chat%252Fmodels",
        // Names that are not volume names, however they are encoded.
        "..%2F..%2Fetc",
        "%2E%2E",
        "tpl%3Aprivate-chat%2F..%2Fx",
        "tpl%3Aprivate-chat%2Fmodels%2Fextra",
        "Cache",
        "%00",
        // A volume name the node did not report.
        "cache",
        "tpl%3Atranscribe%2Fmodels",
    ] {
        let r = delete(app, &app.admin, node_id, segment).await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    }
    // A node that is not the caller's, and one that is not a node.
    let (other, _) = second_account(app).await;
    assert_problem(
        &delete(app, &other, node_id, CHAT_SEGMENT).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    assert_problem(
        &delete(app, &app.admin, NodeId::generate(), CHAT_SEGMENT).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    let r = app
        .call(
            Method::DELETE,
            &format!("/v1/volumes/not-a-node/{CHAT_SEGMENT}"),
            Some(&app.admin),
            None,
        )
        .await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    // `admin` only.
    let nodes = app.key_with(&[Scope::NodesRead, Scope::NodesWrite]).await;
    assert_problem(
        &delete(app, &nodes, node_id, CHAT_SEGMENT).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    // Nothing above reached the node.
    assert!(agent.sync().await.is_empty());
    assert_eq!(list(app, &app.admin).await.len(), 1);
}

#[tokio::test]
async fn a_volume_a_job_holds_is_not_deleted() {
    let fleet = Fleet::start().await;
    let app = &fleet.app;
    let (mut agent, node_id) = node(&fleet).await;
    // The node last reported the volume free, and a service that mounts it has started since.
    report(&mut agent, vec![volume(&fleet, CHAT_VOLUME, 2382, None)]).await;
    let (_, lease_id, epoch) = running_chat(&fleet, &mut agent).await;
    let r = delete(app, &app.admin, node_id, CHAT_SEGMENT).await;
    assert_problem(&r, StatusCode::CONFLICT, "volume_in_use");
    // The report says so too.
    report(&mut agent, vec![volume(&fleet, CHAT_VOLUME, 2382, Some(lease_id))]).await;
    let r = delete(app, &app.admin, node_id, CHAT_SEGMENT).await;
    assert_problem(&r, StatusCode::CONFLICT, "volume_in_use");
    assert!(agent.sync().await.is_empty(), "no VolumeDelete for a volume in use");

    // The service ends and the node frees the lease and reports the volume free: now it may go.
    agent.finished(lease_id, epoch, 0, vec![]).await;
    report(&mut agent, vec![volume(&fleet, CHAT_VOLUME, 2382, None)]).await;
    let r = delete(app, &app.admin, node_id, CHAT_SEGMENT).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    assert_eq!(
        agent.sync().await,
        [ServerMsg::VolumeDelete(VolumeDelete {
            name: CHAT_VOLUME.into()
        })]
    );
}

#[tokio::test]
async fn deleting_on_an_offline_node_gets_node_offline_and_is_not_queued() {
    let fleet = Fleet::start().await;
    let app = &fleet.app;
    let (mut agent, node_id) = node(&fleet).await;
    report(&mut agent, vec![volume(&fleet, CHAT_VOLUME, 2382, None)]).await;
    agent.conn.close(0u32.into(), b"bye");
    let hub = app.state.hub.clone();
    eventually("the hub sees the node disconnect", || {
        let hub = hub.clone();
        async move { (!hub.is_connected(node_id)).then_some(()) }
    })
    .await;
    let r = delete(app, &app.admin, node_id, CHAT_SEGMENT).await;
    assert_problem(&r, StatusCode::SERVICE_UNAVAILABLE, "node_offline");
    // The volume is still listed. When the node is back, asking again sends exactly one `VolumeDelete`: the first
    // request left nothing behind.
    assert_eq!(list(app, &app.admin).await.len(), 1);
    let mut agent = fleet.restart_with(agent, &["service_jobs", "volumes"]).await;
    let r = delete(app, &app.admin, node_id, CHAT_SEGMENT).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    assert_eq!(
        agent.sync().await,
        [ServerMsg::VolumeDelete(VolumeDelete {
            name: CHAT_VOLUME.into()
        })]
    );
}
