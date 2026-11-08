// SPDX-License-Identifier: AGPL-3.0-only

//! §8 "Reservations are held until confirmed", over the real gateway (T06e): a finished lease keeps its node's
//! capacity until the node's `Heartbeat` no longer lists it, and `GET /v1/nodes` says so.

mod common;

use common::fleet::{FakeAgent, Fleet};
use p2pc_proto::ids::NodeId;
use serde_json::{Value, json};

async fn free(fleet: &Fleet, node: NodeId) -> Value {
    fleet
        .app
        .get(&format!("/v1/nodes/{node}"), &fleet.app.admin)
        .await
        .json()["free"]
        .clone()
}

#[tokio::test]
async fn a_finished_leases_capacity_comes_back_with_the_heartbeat_that_drops_it() {
    let fleet = Fleet::start().await;
    let mut agent: FakeAgent = fleet.agent().await;
    let node = agent.node_id.unwrap();
    let idle = free(&fleet, node).await;
    let (job, lease, epoch) = fleet.running(&mut agent).await;
    let busy = free(&fleet, node).await;
    assert_ne!(busy, idle, "the running lease holds capacity");

    // The job ends, but the node is still cleaning up: it lists the lease in its heartbeats.
    agent.finished_held(lease, epoch, 0, vec![]).await;
    agent.heartbeat_listing(&[(lease, epoch)]).await;
    assert_eq!(free(&fleet, node).await, busy, "listed: still held");
    let v = fleet.app.get(&format!("/v1/jobs/{job}"), &fleet.app.admin).await.json();
    assert_eq!(
        v["status"], "succeeded",
        "a finished lease in `running` never revives the job"
    );

    // The cleanup ends: the next heartbeat leaves the lease out and the capacity is free.
    agent.heartbeat_listing(&[]).await;
    assert_eq!(free(&fleet, node).await, idle);

    // And it is offered again at once: a new job goes to the node.
    fleet
        .submit(json!({"image": "docker.io/library/alpine:3", "command": ["true"],
        "resources": {"cpu": 1, "memory_mb": 256}}))
        .await;
    assert_eq!(fleet.scheduler.tick().await.errors, 0);
    let (second, _) = agent.next_lease().await;
    assert_ne!(second, lease);
}

#[tokio::test]
async fn an_older_agent_that_lists_only_running_jobs_frees_the_slot_at_its_next_heartbeat() {
    let fleet = Fleet::start().await;
    let mut agent = fleet.agent().await;
    let node = agent.node_id.unwrap();
    let idle = free(&fleet, node).await;
    let (_, lease, epoch) = fleet.running(&mut agent).await;
    agent.finished_held(lease, epoch, 0, vec![]).await;
    assert_ne!(free(&fleet, node).await, idle, "held until the next heartbeat");
    // `sync` is a heartbeat with an empty `running`, which is what such an agent sends.
    agent.sync().await;
    assert_eq!(free(&fleet, node).await, idle);
}
