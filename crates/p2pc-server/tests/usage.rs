// SPDX-License-Identifier: AGPL-3.0-only

//! The scheduler seen from the REST API (T06): `GET /v1/usage` (§7, §11; grouping, range, pagination and SI-7), the
//! daily cap counting reserved **and** used units (§11), the offer-cap reason in `GET /v1/jobs/{id}` and
//! `POST /v1/estimate` (§8), and the nodes' `free` capacity.
//!
//! Jobs are submitted through the API; a [`Scheduler`] over the same database places them, and the test plays the
//! agent through [`Scheduler::on_agent_message`] (the gateway routes there). A recording [`NodeLink`] stands in for
//! the iroh connections.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use common::{T0, TestApp, assert_problem, inventory, second_account};
use p2pc_proto::api::Scope;
use p2pc_proto::auth::JoinToken;
use p2pc_proto::ids::{JobId, JoinTokenId, LeaseId, NodeId};
use p2pc_proto::protocol::{AgentMsg, LeaseRejectReason, Outcome, ServerMsg, Usage};
use p2pc_server::clock::Clock as _;
use p2pc_server::gateway::SendError;
use p2pc_server::scheduler::{DropLogs, Kick, NoOutputs, NodeLink, OFFER_CAP, Scheduler, Timing};
use p2pc_server::store::{self, join_tokens, nodes};
use serde_json::{Value, json};
use time::Duration;
use time::format_description::well_known::Rfc3339;

/// A tick in a test must not have failed any step.
trait Clean {
    fn clean(self) -> Self;
}

impl Clean for p2pc_server::scheduler::TickReport {
    fn clean(self) -> Self {
        assert_eq!(self.errors, 0, "a scheduling step failed: see the log");
        self
    }
}

#[derive(Debug, Default)]
struct Link {
    connected: Mutex<Vec<NodeId>>,
    leases: Mutex<Vec<(NodeId, LeaseId, u64)>>,
}

impl NodeLink for Link {
    fn send(&self, node_id: NodeId, msg: ServerMsg) -> Result<(), SendError> {
        if !self.is_connected(node_id) {
            return Err(SendError::NotConnected);
        }
        if let ServerMsg::Lease { lease_id, epoch, .. } = msg {
            self.leases.lock().unwrap().push((node_id, lease_id, epoch));
        }
        Ok(())
    }
    fn is_connected(&self, node_id: NodeId) -> bool {
        self.connected.lock().unwrap().contains(&node_id)
    }
}

struct World {
    app: TestApp,
    link: Arc<Link>,
    sched: Scheduler,
}

impl World {
    async fn new() -> Self {
        let app = TestApp::new().await;
        let link = Arc::new(Link::default());
        let sched = Scheduler::from_parts(
            app.db.clone(),
            app.clock.clone(),
            Timing::from_config(&app.state.config),
            Kick::default(),
            link.clone(),
            Arc::new(DropLogs),
            Arc::new(NoOutputs),
        );
        Self { app, link, sched }
    }

    /// Enrolls a node of the owner (what a `Join` does), online and connected.
    async fn node(&self, hostname: &str) -> NodeId {
        let app = &self.app;
        let mut tx = store::begin_immediate(&app.db).await.unwrap();
        let token = JoinToken::generate("a".repeat(64), vec![], Duration::minutes(15), T0).unwrap();
        let token_id = JoinTokenId::generate();
        join_tokens::insert(
            &mut tx,
            app.account_id,
            &join_tokens::NewJoinToken {
                id: token_id,
                project_id: app.project_id,
                code_digest: token.code_hash(),
                label: None,
                created_by: p2pc_proto::api::Principal::Key(app.admin_key.key_id()),
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
                account_id: app.account_id,
                project_id: app.project_id,
                iroh_node_id: data_encoding::HEXLOWER.encode(iroh::SecretKey::generate().public().as_bytes()),
                inventory: inventory(hostname),
                token_id,
            },
            T0,
        )
        .await
        .unwrap();
        nodes::mark_connected(&mut tx, node.id, app.clock.now()).await.unwrap();
        tx.commit().await.unwrap();
        self.link.connected.lock().unwrap().push(node.id);
        node.id
    }

    async fn submit(&self, key: &str, body: Value) -> JobId {
        let r = self.app.call(Method::POST, "/v1/jobs", Some(key), Some(body)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        r.json()["id"].as_str().unwrap().parse().unwrap()
    }

    /// Places the job and plays the agent: accept, start, wait `secs`, finish with exit code 0.
    async fn run(&self, job: JobId, secs: i64) -> NodeId {
        self.sched.tick().await.clean();
        let (node, lease_id, epoch) = self.lease_of(job).await;
        self.sched
            .on_agent_message(node, AgentMsg::LeaseAccepted { lease_id, epoch })
            .await
            .unwrap();
        let started_at = self.app.clock.now();
        self.sched
            .on_agent_message(
                node,
                AgentMsg::JobStarted {
                    lease_id,
                    epoch,
                    started_at,
                },
            )
            .await
            .unwrap();
        self.app.clock.advance(Duration::seconds(secs));
        self.sched
            .on_agent_message(
                node,
                AgentMsg::JobFinished {
                    lease_id,
                    epoch,
                    outcome: Outcome::Exited,
                    exit_code: Some(0),
                    error: None,
                    usage: Usage {
                        wall_ms: u64::try_from(secs).unwrap() * 1000,
                        cpu_used_ms: 500,
                        max_rss_mb: 32,
                    },
                    outputs: vec![],
                },
            )
            .await
            .unwrap();
        node
    }

    /// The latest lease offered for `job`.
    async fn lease_of(&self, job: JobId) -> (NodeId, LeaseId, u64) {
        let leases = self.link.leases.lock().unwrap().clone();
        for (node, lease, epoch) in leases.into_iter().rev() {
            let of: String = sqlx::query_scalar("SELECT job_id FROM leases WHERE id = ?")
                .bind(lease.to_string())
                .fetch_one(&self.app.db)
                .await
                .unwrap();
            if of == job.to_string() {
                return (node, lease, epoch);
            }
        }
        panic!("job {job} was never offered");
    }

    async fn usage(&self, key: &str, query: &str) -> Value {
        let r = self.app.get(&format!("/v1/usage{query}"), key).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        r.json()
    }
}

fn job(cpu: f64, timeout_s: u32) -> Value {
    json!({
        "image": "docker.io/library/python:3.12-slim",
        "command": ["python", "-c", "print(6*7)"],
        "resources": {"cpu": cpu, "memory_mb": 512},
        "timeout_s": timeout_s,
    })
}

fn ts(t: time::OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap()
}

#[tokio::test]
async fn usage_is_grouped_by_job_node_and_key_within_the_range() {
    let w = World::new().await;
    let a = w.node("node-a").await;
    let other_key = w.app.key_with(&[Scope::JobsRead, Scope::JobsWrite]).await;
    let j1 = w.submit(&w.app.admin, job(1.0, 3600)).await;
    w.run(j1, 360).await;
    let j2 = w.submit(&other_key, job(2.0, 3600)).await;
    w.run(j2, 180).await;
    // Everything ended today (UTC): the default range.
    let v = w.usage(&w.app.admin, "").await;
    assert_eq!(v["group_by"], "job");
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    // 1 vCPU × 360 s = 100 milli-units; 2 vCPUs × 180 s = 100 milli-units.
    assert_eq!(v["total"]["units"], 200);
    assert_eq!(v["total"]["attempts"], 2);
    assert_eq!(v["total"]["reserved_cpu_ms"], 360_000 + 360_000);
    assert_eq!(v["total"]["used_cpu_ms"], 1000);
    assert_eq!(v["total"]["key"], Value::Null);
    let by_job = |id: JobId| {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["key"] == id.to_string())
            .cloned()
            .unwrap()
    };
    assert_eq!(by_job(j1)["units"], 100);
    assert_eq!(by_job(j2)["reserved_cpu_ms"], 360_000);
    // By node: one node ran both.
    let v = w.usage(&w.app.admin, "?group_by=node").await;
    assert_eq!(
        v["items"],
        json!([{"key": a.to_string(), "attempts": 2, "reserved_cpu_ms": 720_000,
        "reserved_gpu_ms": 0, "used_cpu_ms": 1000, "max_rss_mb": 32, "units": 200,
        "estimated_attempts": 0}])
    );
    // By key: one group per submitting key, ordered by key ID.
    let v = w.usage(&w.app.admin, "?group_by=key").await;
    let keys: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["key"].as_str().unwrap())
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys, sorted);
    // The range is on the end of the attempt, [from, to).
    let end2 = w.app.clock.now();
    let q = format!("?from={}&to={}", ts(end2), ts(end2 + Duration::seconds(1)));
    let v = w.usage(&w.app.admin, &q).await;
    assert_eq!(
        v["items"].as_array().unwrap().len(),
        1,
        "only the attempt that ended at end2"
    );
    let q = format!("?from={}&to={}", ts(T0 - Duration::days(2)), ts(T0 - Duration::days(1)));
    let v = w.usage(&w.app.admin, &q).await;
    assert_eq!(
        (v["items"].as_array().unwrap().len(), &v["total"]["units"]),
        (0, &json!(0))
    );
    // Pagination over the groups.
    let v = w.usage(&w.app.admin, "?limit=1").await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    let cursor = v["next_cursor"].as_str().unwrap().to_string();
    let v2 = w.usage(&w.app.admin, &format!("?limit=1&cursor={cursor}")).await;
    assert_eq!(v2["items"].as_array().unwrap().len(), 1);
    assert_ne!(v["items"][0]["key"], v2["items"][0]["key"]);
    assert_eq!(v2["next_cursor"], Value::Null);
    assert_eq!(v2["total"]["units"], 200, "the total covers every page");
}

#[tokio::test]
async fn usage_of_another_account_is_never_visible() {
    let w = World::new().await;
    w.node("node-a").await;
    let j = w.submit(&w.app.admin, job(1.0, 3600)).await;
    w.run(j, 60).await;
    let (stranger, _) = second_account(&w.app).await;
    for group in ["job", "node", "key"] {
        let v = w.usage(&stranger, &format!("?group_by={group}")).await;
        assert_eq!(v["items"], json!([]), "{group}");
        assert_eq!(v["total"]["attempts"], 0);
    }
    assert_eq!(w.usage(&w.app.admin, "").await["total"]["attempts"], 1);
}

#[tokio::test]
async fn usage_validates_its_query_and_scope() {
    let w = World::new().await;
    let nodes_only = w.app.key_with(&[Scope::NodesRead]).await;
    let r = w.app.get("/v1/usage", &nodes_only).await;
    assert_problem(&r, StatusCode::FORBIDDEN, "forbidden");
    let admin = w.app.admin.clone();
    for (q, field) in [
        ("?from=yesterday", "from"),
        (&format!("?from={}&to={}", ts(T0), ts(T0)) as &str, "from"),
        ("?limit=0", "limit"),
        ("?cursor=nope!", "cursor"),
    ] {
        let r = w.app.get(&format!("/v1/usage{q}"), &admin).await;
        let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
        assert!(v.to_string().contains(field), "{q}: {v}");
    }
    let r = w.app.get("/v1/usage?group_by=project", &admin).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
}

/// §11: the cap counts what finished jobs **used**, not what they reserved; a running job still counts its
/// reservation.
#[tokio::test]
async fn the_daily_cap_counts_used_units_of_finished_jobs() {
    let w = World::new().await;
    w.node("node-a").await;
    let (capped, _) = w
        .app
        .create_key(json!({"scopes": ["jobs:read", "jobs:write"], "daily_unit_cap": 1500}))
        .await;
    // 1 vCPU × 1 h = 1 000 milli-units reserved.
    let first = w.submit(&capped, job(1.0, 3600)).await;
    let r = w
        .app
        .call(Method::POST, "/v1/jobs", Some(&capped), Some(job(1.0, 3600)))
        .await;
    assert_problem(&r, StatusCode::PAYMENT_REQUIRED, "cap_exceeded");
    // It ran 60 s: it used 17 milli-units (1 000 × 60 / 3 600, rounded up).
    w.run(first, 60).await;
    w.submit(&capped, job(1.0, 3600)).await;
    // Now 17 used + 1 000 reserved: another 1 000 does not fit.
    let r = w
        .app
        .call(Method::POST, "/v1/jobs", Some(&capped), Some(job(1.0, 3600)))
        .await;
    assert_problem(&r, StatusCode::PAYMENT_REQUIRED, "cap_exceeded");
}

/// §8 "Offer cap": after 10 refused offers the job stays queued, and both `GET /v1/jobs/{id}` and the estimate of
/// the same request say why.
#[tokio::test]
async fn the_offer_cap_reason_shows_in_the_job_and_the_estimate() {
    let w = World::new().await;
    let node = w.node("node-a").await;
    let mut body = job(1.0, 600);
    body["idempotency_key"] = json!("stuck-job-1");
    let id = w.submit(&w.app.admin, body.clone()).await;
    for _ in 0..OFFER_CAP {
        w.sched.tick().await.clean();
        let (n, lease_id, epoch) = w.lease_of(id).await;
        assert_eq!(n, node);
        w.sched
            .on_agent_message(
                n,
                AgentMsg::LeaseRejected {
                    lease_id,
                    epoch,
                    reason: LeaseRejectReason::UnsupportedSandbox,
                },
            )
            .await
            .unwrap();
        w.app.clock.advance(Duration::seconds(61));
    }
    let want = "no node accepted the job: unsupported_sandbox";
    let v = w.app.get(&format!("/v1/jobs/{id}"), &w.app.admin).await.json();
    assert_eq!(
        (v["status"].as_str(), v["reason"].as_str()),
        (Some("queued"), Some(want))
    );
    let r = w
        .app
        .call(Method::POST, "/v1/estimate", Some(&w.app.admin), Some(body.clone()))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let e = r.json();
    assert_eq!((e["reason"].as_str(), &e["would_queue"]), (Some(want), &json!(true)));
    // Another request (no idempotency key) is estimated on its own, never with that job's reason.
    let r = w
        .app
        .call(Method::POST, "/v1/estimate", Some(&w.app.admin), Some(job(1.0, 600)))
        .await;
    assert_ne!(r.json()["reason"].as_str(), Some(want));
    // The same idempotency key from another key is not this key's job either.
    let other = w.app.key_with(&[Scope::JobsRead]).await;
    let r = w.app.call(Method::POST, "/v1/estimate", Some(&other), Some(body)).await;
    assert_ne!(r.json()["reason"].as_str(), Some(want));
}

/// `GET /v1/nodes` shows what a node offers minus what its leases hold.
#[tokio::test]
async fn node_free_capacity_subtracts_held_reservations() {
    let w = World::new().await;
    let node = w.node("node-a").await;
    let id = w.submit(&w.app.admin, job(2.0, 600)).await;
    w.sched.tick().await.clean();
    let _ = w.lease_of(id).await;
    let v = w.app.get(&format!("/v1/nodes/{node}"), &w.app.admin).await.json();
    // The inventory offers 6 vCPUs and 12 GiB.
    assert_eq!(v["free"], json!({"cpu": 4.0, "memory_mb": 12_288 - 512, "gpu": 0}));
    let list = w.app.get("/v1/nodes", &w.app.admin).await.json();
    assert_eq!(list["items"][0]["free"], v["free"]);
}

/// Review P3 (the ledger gap): an attempt the watchdog ends gets an estimated usage row, and `GET /v1/usage` and the
/// daily cap count the same units for it.
#[tokio::test]
async fn an_attempt_ended_by_the_watchdog_is_estimated_and_the_cap_agrees_with_usage() {
    let w = World::new().await;
    w.node("node-a").await;
    let (capped, _) = w
        .app
        .create_key(json!({"scopes": ["jobs:read", "jobs:write"], "daily_unit_cap": 1500}))
        .await;
    let id = w.submit(&capped, job(1.0, 3600)).await;
    w.sched.tick().await.clean();
    let (node, lease_id, epoch) = w.lease_of(id).await;
    w.sched
        .on_agent_message(node, AgentMsg::LeaseAccepted { lease_id, epoch })
        .await
        .unwrap();
    let started_at = w.app.clock.now();
    w.sched
        .on_agent_message(
            node,
            AgentMsg::JobStarted {
                lease_id,
                epoch,
                started_at,
            },
        )
        .await
        .unwrap();
    // The agent goes silent; the watchdog fires at timeout_s + 60 s.
    w.app.clock.advance(Duration::seconds(3660));
    w.sched.tick().await.clean();
    let v = w.app.get(&format!("/v1/jobs/{id}"), &capped).await.json();
    assert_eq!(v["status"], "timed_out");
    // 1 vCPU × 3 660 s = 1 016.67 milli-units, rounded up.
    let usage = w.usage(&capped, "").await;
    assert_eq!(usage["total"]["units"], 1017);
    assert_eq!(usage["total"]["estimated_attempts"], 1);
    assert_eq!(usage["total"]["used_cpu_ms"], 0, "an estimate measures nothing");
    // The cap counts the same 1 017: another 1 000 does not fit under 1 500, 250 does.
    let r = w
        .app
        .call(Method::POST, "/v1/jobs", Some(&capped), Some(job(1.0, 3600)))
        .await;
    assert_problem(&r, StatusCode::PAYMENT_REQUIRED, "cap_exceeded");
    w.submit(&capped, job(0.25, 3600)).await;
}

// --- `GET /v1/jobs/{id}` attempts (§7, amended 777b461 and 0c79048) ------------------------------------------------

impl World {
    async fn get_job(&self, id: JobId) -> Value {
        let r = self.app.get(&format!("/v1/jobs/{id}"), &self.app.admin).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        r.json()
    }

    async fn agent(&self, node: NodeId, msg: AgentMsg) {
        self.sched.on_agent_message(node, msg).await.unwrap();
    }

    /// Places the job and plays the agent up to `JobStarted`.
    async fn start(&self, job: JobId) -> (NodeId, LeaseId, u64) {
        self.sched.tick().await.clean();
        let (node, lease_id, epoch) = self.lease_of(job).await;
        self.agent(node, AgentMsg::LeaseAccepted { lease_id, epoch }).await;
        let started_at = self.app.clock.now();
        self.agent(
            node,
            AgentMsg::JobStarted {
                lease_id,
                epoch,
                started_at,
            },
        )
        .await;
        (node, lease_id, epoch)
    }

    async fn finish_ok(&self, node: NodeId, lease_id: LeaseId, epoch: u64) {
        self.agent(
            node,
            AgentMsg::JobFinished {
                lease_id,
                epoch,
                outcome: Outcome::Exited,
                exit_code: Some(0),
                error: None,
                usage: Usage {
                    wall_ms: 1000,
                    cpu_used_ms: 10,
                    max_rss_mb: 8,
                },
                outputs: vec![],
            },
        )
        .await;
    }
}

fn at(v: &Value) -> time::OffsetDateTime {
    time::OffsetDateTime::parse(v.as_str().unwrap(), &Rfc3339).unwrap()
}

#[tokio::test]
async fn one_attempt_is_running_then_succeeded() {
    let w = World::new().await;
    let node = w.node("node-a").await;
    let id = w.submit(&w.app.admin, job(1.0, 600)).await;
    assert_eq!(w.get_job(id).await["attempts"], json!([]), "queued: no attempt yet");
    let start = w.app.clock.now();
    let (_, lease_id, epoch) = w.start(id).await;
    let v = w.get_job(id).await;
    assert_eq!(
        v["attempts"],
        json!([{"attempt": 1, "node_id": node.to_string(), "outcome": "running", "reason": null,
            "started_at": v["attempts"][0]["started_at"], "ended_at": null}])
    );
    assert_eq!(at(&v["attempts"][0]["started_at"]), start);
    w.app.clock.advance(Duration::seconds(42));
    w.finish_ok(node, lease_id, epoch).await;
    let a = &w.get_job(id).await["attempts"];
    assert_eq!(a.as_array().unwrap().len(), 1);
    assert_eq!(
        (&a[0]["outcome"], &a[0]["reason"]),
        (&json!("succeeded"), &json!("exited_0"))
    );
    assert_eq!(at(&a[0]["ended_at"]), start + Duration::seconds(42));
}

/// AC-6: attempt 1 is `lost` (with its reason) after node loss, and attempt 2 succeeds on the other node.
#[tokio::test]
async fn a_lost_attempt_and_its_retry_on_another_node() {
    let w = World::new().await;
    w.node("node-a").await;
    w.node("node-b").await;
    let id = w.submit(&w.app.admin, job(1.0, 600)).await;
    let (first, _, _) = w.start(id).await;
    // The node goes silent; the liveness sweep marks it offline after lease_ttl_s.
    let last = w.app.clock.now();
    w.link.connected.lock().unwrap().retain(|n| *n != first);
    let mut c = w.app.db.acquire().await.unwrap();
    nodes::touch_last_seen(&mut c, first, last).await.unwrap();
    nodes::mark_offline(&mut c, first).await.unwrap();
    drop(c);
    w.app.clock.advance(Duration::seconds(60));
    w.sched
        .node_offline(first, p2pc_server::gateway::OfflineReason::Lost)
        .await
        .unwrap();
    let (second, lease_id, epoch) = w.start(id).await;
    assert_ne!(second, first);
    w.finish_ok(second, lease_id, epoch).await;
    let v = w.get_job(id).await;
    assert_eq!(v["status"], "succeeded");
    let a = v["attempts"].as_array().unwrap();
    assert_eq!(a.len(), 2);
    assert_eq!(
        (&a[0]["attempt"], &a[0]["node_id"], &a[0]["outcome"], &a[0]["reason"]),
        (
            &json!(1),
            &json!(first.to_string()),
            &json!("lost"),
            &json!("node_lost")
        )
    );
    assert_eq!(at(&a[0]["ended_at"]), last + Duration::seconds(60));
    assert_eq!(
        (&a[1]["attempt"], &a[1]["node_id"], &a[1]["outcome"]),
        (&json!(2), &json!(second.to_string()), &json!("succeeded"))
    );
}

/// Refused and unanswered offers are not attempts, so they are not listed.
#[tokio::test]
async fn refused_and_unanswered_offers_are_not_attempts() {
    let w = World::new().await;
    w.node("node-a").await;
    let id = w.submit(&w.app.admin, job(1.0, 600)).await;
    w.sched.tick().await.clean();
    let (node, lease_id, epoch) = w.lease_of(id).await;
    w.agent(
        node,
        AgentMsg::LeaseRejected {
            lease_id,
            epoch,
            reason: LeaseRejectReason::InsufficientCapacity,
        },
    )
    .await;
    w.app.clock.advance(Duration::seconds(61));
    // Unanswered for 10 s.
    w.sched.tick().await.clean();
    w.app.clock.advance(Duration::seconds(10));
    w.sched.tick().await.clean();
    assert_eq!(w.get_job(id).await["attempts"], json!([]));
    w.app.clock.advance(Duration::seconds(61));
    let (node, lease_id, epoch) = w.start(id).await;
    assert_eq!(epoch, 3, "two offers took epochs 1 and 2");
    w.finish_ok(node, lease_id, epoch).await;
    let a = &w.get_job(id).await["attempts"];
    assert_eq!(a.as_array().unwrap().len(), 1);
    assert_eq!((&a[0]["attempt"], &a[0]["outcome"]), (&json!(1), &json!("succeeded")));
}

/// SI-7: another account gets 404 for the job, so it never sees its attempts; lists leave the field out.
#[tokio::test]
async fn attempts_are_private_and_absent_from_lists() {
    let w = World::new().await;
    w.node("node-a").await;
    let id = w.submit(&w.app.admin, job(1.0, 600)).await;
    let (node, lease_id, epoch) = w.start(id).await;
    w.finish_ok(node, lease_id, epoch).await;
    let (stranger, _) = second_account(&w.app).await;
    let r = w.app.get(&format!("/v1/jobs/{id}"), &stranger).await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    assert!(!String::from_utf8_lossy(&r.body).contains(&node.to_string()));
    let list = w.app.get("/v1/jobs", &w.app.admin).await.json();
    let item = &list["items"][0];
    assert_eq!(item["id"], id.to_string());
    assert!(item.get("attempts").is_none(), "{item}");
    assert_eq!(w.get_job(id).await["attempts"].as_array().unwrap().len(), 1);
}

/// An accepted attempt whose process has not started yet (an image pull) is `running` with `started_at: null`; if the
/// watchdog then ends it, it is `timed_out`, still with no `started_at`.
#[tokio::test]
async fn an_accepted_attempt_that_never_started() {
    let w = World::new().await;
    w.node("node-a").await;
    let id = w.submit(&w.app.admin, job(1.0, 60)).await;
    w.sched.tick().await.clean();
    let (node, lease_id, epoch) = w.lease_of(id).await;
    w.agent(node, AgentMsg::LeaseAccepted { lease_id, epoch }).await;
    let a = w.get_job(id).await["attempts"][0].clone();
    assert_eq!(
        (&a["outcome"], &a["started_at"], &a["ended_at"]),
        (&json!("running"), &Value::Null, &Value::Null)
    );
    // pull_timeout_s (600) + timeout_s (60) + 60 s after the acceptance.
    w.app.clock.advance(Duration::seconds(720));
    w.sched.tick().await.clean();
    let a = w.get_job(id).await["attempts"][0].clone();
    assert_eq!(
        (&a["outcome"], &a["reason"], &a["started_at"]),
        (&json!("timed_out"), &json!("watchdog"), &Value::Null)
    );
}

/// Review P2: a range at the edge of the calendar never panics. The default other bound (one day away) would leave
/// the representable range: `422` on the field it was derived from, in the spec's error shape.
#[tokio::test]
async fn a_range_at_the_edge_of_the_calendar_is_a_422_not_a_panic() {
    let w = World::new().await;
    let admin = w.app.admin.clone();
    for (query, field) in [
        ("?from=9999-12-31T12:00:00Z", "from"),
        ("?from=9999-12-31T23:59:59Z&group_by=node", "from"),
        ("?to=0000-01-01T00:00:00Z", "to"),
        ("?to=0000-01-01T12:00:00Z&group_by=key", "to"),
    ] {
        let r = w.app.get(&format!("/v1/usage{query}"), &admin).await;
        let v = assert_problem(&r, StatusCode::UNPROCESSABLE_ENTITY, "validation_failed");
        assert_eq!(v["errors"][0]["field"], field, "{query}: {v}");
    }
    // Explicit bounds right at the edges are fine.
    let v = w
        .usage(&admin, "?from=0000-01-01T00:00:00Z&to=9999-12-31T23:59:59Z")
        .await;
    assert_eq!(v["total"]["attempts"], 0);
}
