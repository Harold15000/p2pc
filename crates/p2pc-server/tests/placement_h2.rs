// SPDX-License-Identifier: AGPL-3.0-only

//! Placement and the H2 node state (H2 spec §6.1, §7.2, §8.4, §11.3):
//! - a node whose owner paused it (`Inventory.owner_paused`) is treated as draining: no lease until it is resumed;
//! - a volume that a node reports held (`VolumeReport.in_use_by`) keeps the jobs that use it off that node;
//! - a node whose volume share (`Inventory.volumes_mb`) cannot hold a job's volumes is ineligible, with a `reason`.
//!
//! The server runs as `serve` wires it, with fake agents over loopback iroh connections (relays disabled). Nothing
//! sleeps to synchronise: an agent's `sync` returns once the hub handled what it sent.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::fleet::{FakeAgent, Fleet, NowForTests};
use p2pc_proto::api::Inventory;
use p2pc_proto::ids::LeaseId;
use p2pc_proto::protocol::{AgentMsg, ServerMsg, VolumeInfo, VolumeReport};
use serde_json::{Value, json};

/// A node whose agent declared what a service with a volume needs, with `volumes_mb` of volume share.
async fn volume_node(fleet: &Fleet, volumes_mb: Option<u64>) -> FakeAgent {
    let agent = fleet.agent().await;
    let mut agent = fleet
        .restart_with(agent, &["service_jobs", "volumes", "share_update"])
        .await;
    let mut inv = common::inventory("node");
    inv.volumes_mb = volumes_mb;
    inv.owner_paused = Some(false);
    update(&mut agent, inv).await;
    agent
}

async fn update(agent: &mut FakeAgent, inventory: Inventory) {
    agent.send(&AgentMsg::InventoryUpdate { inventory }).await;
    let other = agent.sync().await;
    assert!(other.is_empty(), "{other:?}");
}

fn service_with_volume(max_mb: u64) -> Value {
    json!({"kind": "service", "image": "docker.io/library/nginx:1.27", "command": ["nginx"],
        "resources": {"cpu": 1, "memory_mb": 256},
        "service": {"ports": [{"port": 8080, "name": "api"}]},
        "volumes": [{"name": "models", "mount": "/volumes/models", "max_mb": max_mb}]})
}

fn batch() -> Value {
    json!({"image": "docker.io/library/alpine:3", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 256}})
}

/// What the hub sent `agent` that is not an answer to a heartbeat: none of it may be a lease.
async fn no_lease(agent: &mut FakeAgent) {
    let sent = agent.sync().await;
    assert!(!sent.iter().any(|m| matches!(m, ServerMsg::Lease { .. })), "{sent:?}");
}

async fn job(fleet: &Fleet, id: &str) -> Value {
    fleet.app.get(&format!("/v1/jobs/{id}"), &fleet.app.admin).await.json()
}

/// Takes the next lease and runs it until it ends by itself, confirmed dead (the node no longer lists it).
async fn run_to_end(fleet: &Fleet, agent: &mut FakeAgent) -> LeaseId {
    let (lease_id, epoch) = agent.next_lease().await;
    agent.send(&AgentMsg::LeaseAccepted { lease_id, epoch }).await;
    agent
        .send(&AgentMsg::JobStarted {
            lease_id,
            epoch,
            started_at: fleet.app.clock.now_for_tests(),
        })
        .await;
    agent.finished(lease_id, epoch, 0, Vec::new()).await;
    lease_id
}

async fn report(fleet: &Fleet, agent: &mut FakeAgent, in_use_by: Option<LeaseId>) {
    let volume = VolumeInfo {
        name: "models".into(),
        size_mb: 100,
        last_used_at: fleet.app.clock.now_for_tests(),
        in_use_by,
    };
    agent
        .send(&AgentMsg::VolumeReport(VolumeReport { volumes: vec![volume] }))
        .await;
    let other = agent.sync().await;
    assert!(other.is_empty(), "{other:?}");
}

/// H2 §6.1, §8.4: while `owner_paused` is true the scheduler treats the node as draining.
#[tokio::test]
async fn a_node_its_owner_paused_gets_no_lease_until_it_is_resumed() {
    let fleet = Fleet::start().await;
    let agent = fleet.agent().await;
    let mut agent = fleet.restart_with(agent, &["share_update"]).await;
    let mut inv = common::inventory("node");
    inv.owner_paused = Some(true);
    update(&mut agent, inv.clone()).await;

    let id = fleet.submit(batch()).await;
    let tick = fleet.scheduler.tick().await;
    assert_eq!((tick.offered, tick.errors), (0, 0));
    no_lease(&mut agent).await;
    assert_eq!(job(&fleet, &id).await["status"], "queued");

    inv.owner_paused = Some(false);
    update(&mut agent, inv).await;
    assert_eq!(fleet.scheduler.tick().await.offered, 1);
    agent.next_lease().await;
}

/// H2 §11.3 "One holder at a time": the scheduler knows holders from `VolumeReport` and does not offer a lease whose
/// volume a node reports held, even by a lease the hub already considers over (the agent keeps the lock until Podman
/// confirms the container gone).
#[tokio::test]
async fn a_volume_reported_held_keeps_its_jobs_off_that_node() {
    let fleet = Fleet::start().await;
    let mut agent = volume_node(&fleet, Some(102_400)).await;
    fleet.submit(service_with_volume(20_480)).await;
    assert_eq!(fleet.scheduler.tick().await.offered, 1);
    let old = run_to_end(&fleet, &mut agent).await;

    // The container of that lease could not be removed: the node still reports the volume held by it.
    report(&fleet, &mut agent, Some(old)).await;
    let id = fleet.submit(service_with_volume(20_480)).await;
    let tick = fleet.scheduler.tick().await;
    assert_eq!((tick.offered, tick.errors), (0, 0));
    no_lease(&mut agent).await;
    // A batch job without volumes still goes there (the node is not blocked, only that volume).
    fleet.submit(batch()).await;
    assert_eq!(fleet.scheduler.tick().await.offered, 1);
    agent.next_lease().await;

    // The lock is released: the next report says so, and the service (the only queued job) is offered.
    report(&fleet, &mut agent, None).await;
    let tick = fleet.scheduler.tick().await;
    assert_eq!((tick.offered, tick.errors), (1, 0));
    agent.next_lease().await;
    assert_eq!(job(&fleet, &id).await["reason"], Value::Null, "it only waited for room");
}

/// H2 §11.3 "Budget": a node whose `volumes_mb` cannot hold a job's volumes even when idle is ineligible, and the job
/// says why; once the owner raises the share, it is placed.
#[tokio::test]
async fn a_volume_share_too_small_for_the_job_makes_the_node_ineligible_with_a_reason() {
    let fleet = Fleet::start().await;
    let mut agent = volume_node(&fleet, Some(10_240)).await;
    let id = fleet.submit(service_with_volume(20_480)).await;
    let tick = fleet.scheduler.tick().await;
    assert_eq!((tick.offered, tick.errors), (0, 0));
    no_lease(&mut agent).await;
    let reason = job(&fleet, &id).await["reason"].as_str().unwrap().to_string();
    assert!(reason.contains("volume"), "{reason}");

    let mut inv = common::inventory("node");
    inv.volumes_mb = Some(20_480);
    inv.owner_paused = Some(false);
    update(&mut agent, inv).await;
    assert_eq!(fleet.scheduler.tick().await.offered, 1);
    agent.next_lease().await;
    assert_eq!(job(&fleet, &id).await["reason"], Value::Null);
}
