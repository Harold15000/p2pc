// SPDX-License-Identifier: AGPL-3.0-only

//! `Leave` (H2 spec §6.1, §8.7): the hub removes the node as `DELETE /v1/nodes/{id}` would, audits `node_left`,
//! closes the connection and answers nothing. Only an agent that declared `leave` is listened to.
//!
//! The server runs as `serve` wires it, with fake agents over loopback iroh connections (relays disabled). Nothing
//! sleeps to synchronise: an agent's `sync` returns once the hub handled what it sent.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::fleet::{FakeAgent, Fleet};
use p2pc_proto::ids::NodeId;
use p2pc_proto::protocol::{AgentMsg, ServerMsg, error_code};
use serde_json::{Value, json};

async fn audit_rows(fleet: &Fleet, kind: &str) -> Vec<(Option<String>, Value)> {
    let rows: Vec<(Option<String>, String)> =
        sqlx::query_as("SELECT subject_id, detail FROM audit_events WHERE kind = ? ORDER BY seq")
            .bind(kind)
            .fetch_all(&fleet.app.db)
            .await
            .unwrap();
    rows.into_iter()
        .map(|(subject, detail)| (subject, serde_json::from_str(&detail).unwrap()))
        .collect()
}

async fn deleted(fleet: &Fleet, node: NodeId) -> bool {
    let at: Option<i64> = sqlx::query_scalar("SELECT deleted_at FROM nodes WHERE id = ?")
        .bind(node.to_string())
        .fetch_one(&fleet.app.db)
        .await
        .unwrap();
    at.is_some()
}

async fn job_status(fleet: &Fleet, job: &str) -> String {
    fleet.app.get(&format!("/v1/jobs/{job}"), &fleet.app.admin).await.json()["status"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A Hello from `agent`'s key on a new connection: what the hub answers first.
async fn hello_again(fleet: &Fleet, agent: FakeAgent) -> Option<ServerMsg> {
    let node_id = agent.node_id;
    let mut again = fleet.reconnect_raw(agent).await;
    again.node_id = node_id;
    again
        .send(&AgentMsg::Hello {
            agent_version: "0.1.0".into(),
            inventory: common::inventory("node"),
            running: Vec::new(),
            features: vec!["leave".into()],
        })
        .await;
    again.recv().await
}

#[tokio::test]
async fn leave_removes_the_node_audits_node_left_and_closes_without_an_answer() {
    let fleet = Fleet::start().await;
    let agent = fleet.agent().await;
    let mut agent = fleet.restart_with(agent, &["leave"]).await;
    let node = agent.node_id.unwrap();
    let (job, _, _) = fleet.running(&mut agent).await;
    assert_eq!(job_status(&fleet, &job).await, "running");

    agent.send(&json!({"type": "leave", "reason": "uninstall"})).await;
    // No answer: the hub closes the connection.
    let answer = agent.recv().await;
    assert!(answer.is_none(), "{answer:?}");

    assert!(deleted(&fleet, node).await, "the node is deleted");
    let left = audit_rows(&fleet, "node_left").await;
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(left[0].0.as_deref(), Some(node.to_string().as_str()));
    assert_eq!(left[0].1["reason"], "uninstall");
    // `node_left`, not `node_deleted`: nobody but the node asked.
    assert!(audit_rows(&fleet, "node_deleted").await.is_empty());
    // As for `DELETE /v1/nodes/{id}`: the node's work goes back to the queue, and the node is no longer listed.
    assert_eq!(job_status(&fleet, &job).await, "queued");
    let nodes = fleet.app.get("/v1/nodes", &fleet.app.admin).await.json();
    assert_eq!(nodes["items"].as_array().unwrap().len(), 0, "{nodes}");
    // Its NodeId is no longer enrolled: the agent that comes back is told `not_enrolled` (and exits 7).
    match hello_again(&fleet, agent).await {
        Some(ServerMsg::Error { code, .. }) => assert_eq!(code, error_code::NOT_ENROLLED),
        other => panic!("expected not_enrolled, got {other:?}"),
    }
}

#[tokio::test]
async fn an_agent_that_did_not_declare_leave_is_not_removed() {
    let fleet = Fleet::start().await;
    let agent = fleet.agent().await;
    let mut agent = fleet.restart_with(agent, &["service_jobs"]).await;
    let node = agent.node_id.unwrap();
    agent.send(&json!({"type": "leave", "reason": "uninstall"})).await;
    let sent = agent.sync().await;
    assert!(
        matches!(sent.as_slice(), [ServerMsg::Error { code, .. }] if code == error_code::UNSUPPORTED_MESSAGE),
        "{sent:?}"
    );
    assert!(!deleted(&fleet, node).await);
    assert!(audit_rows(&fleet, "node_left").await.is_empty());
}
