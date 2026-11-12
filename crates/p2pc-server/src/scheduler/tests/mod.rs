// SPDX-License-Identifier: AGPL-3.0-only

//! Scheduler tests: a real SQLite database, the manual clock and a fake [`NodeLink`] that records what would be sent
//! to each node. Nothing sleeps: time moves only when a test moves the clock, and a pass runs only when a test calls
//! [`Scheduler::tick`].

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod props;

use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex};

use p2pc_proto::api::{JobSpec, JobStatus, OutputFile, Scope};
use p2pc_proto::auth::{ApiKey, Secret, hash_secret};
use p2pc_proto::ids::{AccountId, JobId, JoinTokenId, KeyId, LeaseId, NodeId, ProjectId};
use p2pc_proto::protocol::{AgentMsg, LeaseRejectReason, LogData, Outcome, RunningLease, ServerMsg, Usage};
use p2pc_proto::units::{Units, estimate_units};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

use super::*;
use crate::clock::ManualClock;
use crate::store::jobs::NewJob;
use crate::store::join_tokens::NewJoinToken;
use crate::store::keys::NewKey;
use crate::store::nodes::NewNode;
use crate::store::{OpenMode, accounts, join_tokens, keys, open};

pub(crate) const T0: OffsetDateTime = datetime!(2026-11-05 10:00:00 UTC);
pub(crate) const TTL: Duration = Duration::seconds(60);
pub(crate) const AFFINITY_WAIT: Duration = Duration::seconds(900);

/// Records every message and knows which nodes are connected.
/// A tick in a test must not have failed any step.
pub(crate) trait Clean {
    fn clean(self) -> Self;
}

impl Clean for super::TickReport {
    fn clean(self) -> Self {
        assert_eq!(self.errors, 0, "a scheduling step failed: see the log");
        self
    }
}

#[derive(Debug, Default)]
pub(crate) struct FakeLink {
    connected: Mutex<HashSet<NodeId>>,
    /// Connected nodes whose session queue is full: `send` fails with `SendError::Full`.
    full: Mutex<HashSet<NodeId>>,
    sent: Mutex<Vec<(NodeId, ServerMsg)>>,
}

impl FakeLink {
    pub(crate) fn connect(&self, n: NodeId) {
        self.connected.lock().unwrap().insert(n);
    }
    pub(crate) fn disconnect(&self, n: NodeId) {
        self.connected.lock().unwrap().remove(&n);
    }
    pub(crate) fn set_full(&self, n: NodeId, full: bool) {
        let mut f = self.full.lock().unwrap();
        if full {
            f.insert(n);
        } else {
            f.remove(&n);
        }
    }
    pub(crate) fn take(&self) -> Vec<(NodeId, ServerMsg)> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }
}

impl NodeLink for FakeLink {
    fn send(&self, node_id: NodeId, msg: ServerMsg) -> Result<(), SendError> {
        if !self.is_connected(node_id) {
            return Err(SendError::NotConnected);
        }
        if self.full.lock().unwrap().contains(&node_id) {
            return Err(SendError::Full);
        }
        self.sent.lock().unwrap().push((node_id, msg));
        Ok(())
    }
    fn is_connected(&self, node_id: NodeId) -> bool {
        self.connected.lock().unwrap().contains(&node_id)
    }
}

/// Records the log chunks and the outputs finalised.
#[derive(Debug, Default)]
pub(crate) struct Hooks {
    chunks: Mutex<Vec<(JobId, u32, u64)>>,
    finalized: Mutex<Vec<(JobId, u32, usize)>>,
    note: Mutex<Option<String>>,
}

impl LogSink for Hooks {
    fn on_chunk(&self, job_id: JobId, attempt: u32, chunk: LogChunk) -> BoxFuture<'_, ()> {
        self.chunks.lock().unwrap().push((job_id, attempt, chunk.seq));
        Box::pin(async {})
    }
}

impl OutputsFinalizer for Hooks {
    fn finalize<'a>(&'a self, job_id: JobId, attempt: u32, outputs: &'a [OutputFile]) -> BoxFuture<'a, Option<String>> {
        self.finalized.lock().unwrap().push((job_id, attempt, outputs.len()));
        let note = self.note.lock().unwrap().clone();
        Box::pin(async move { note })
    }
}

pub(crate) struct Fx {
    _dir: tempfile::TempDir,
    pub db: Db,
    pub clock: Arc<ManualClock>,
    pub link: Arc<FakeLink>,
    pub hooks: Arc<Hooks>,
    pub sched: Scheduler,
    pub account: AccountId,
    pub project: ProjectId,
    pub key: KeyId,
    token: JoinTokenId,
}

pub(crate) fn timing() -> Timing {
    Timing {
        lease_ttl: TTL,
        pull_timeout: Duration::seconds(600),
        gpu_hour_units: Units::from_units(10),
        volume_affinity_wait: AFFINITY_WAIT,
    }
}

impl Fx {
    pub(crate) async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = open(&dir.path().join("t.db"), OpenMode::Create).await.unwrap();
        Self::on(dir, db).await
    }

    /// The fixture over `db` (kept in `dir`): an owner, an admin key and a join token.
    pub(crate) async fn on(dir: tempfile::TempDir, db: Db) -> Self {
        let mut conn = db.acquire().await.unwrap();
        let (account, project) = accounts::create_owner(&mut conn, T0).await.unwrap();
        let api_key = ApiKey::generate();
        let new = NewKey {
            key_id: api_key.key_id(),
            project_id: project,
            digest: api_key.hash(),
            scopes: vec![Scope::Admin],
            daily_unit_cap: None,
            allowed_images: None,
            label: None,
            expires_at: None,
        };
        keys::insert(&mut conn, account, &new, T0).await.unwrap();
        let token = JoinTokenId::generate();
        let jt = NewJoinToken {
            id: token,
            project_id: project,
            code_digest: hash_secret(&Secret::generate()),
            label: None,
            created_by: p2pc_proto::api::Principal::Key(api_key.key_id()),
            bound_iroh_node_id: None,
            pre_approved: false,
            expires_at: T0 + Duration::hours(1),
        };
        join_tokens::insert(&mut conn, account, &jt, T0).await.unwrap();
        drop(conn);
        let clock = Arc::new(ManualClock::new(T0));
        let link = Arc::new(FakeLink::default());
        let hooks = Arc::new(Hooks::default());
        let sched = Scheduler::from_parts(
            db.clone(),
            clock.clone(),
            timing(),
            Kick::default(),
            link.clone(),
            hooks.clone(),
            hooks.clone(),
        );
        Self {
            _dir: dir,
            db,
            clock,
            link,
            hooks,
            sched,
            account,
            project,
            key: api_key.key_id(),
            token,
        }
    }

    /// A second scheduler over the same database, link and clock, booted now (a restart, or a concurrent loop).
    pub(crate) fn another_scheduler(&self) -> Scheduler {
        Scheduler::from_parts(
            self.db.clone(),
            self.clock.clone(),
            timing(),
            Kick::default(),
            self.link.clone(),
            self.hooks.clone(),
            self.hooks.clone(),
        )
    }

    pub(crate) fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    pub(crate) fn advance(&self, s: i64) {
        self.clock.advance(Duration::seconds(s));
    }

    /// An online, connected node offering `cpu` vCPUs, `mem` MiB and `gpus` offerable GPUs, and a disk that is never
    /// the limit (10 TiB).
    pub(crate) async fn node(&self, cpu: f64, mem: u64, gpus: u32) -> NodeId {
        self.node_disk(cpu, mem, gpus, Some(10 * 1024 * 1024)).await
    }

    /// Like [`Fx::node`], offering `disk` MiB of disk for job directories (`None`: an agent that does not report it).
    pub(crate) async fn node_disk(&self, cpu: f64, mem: u64, gpus: u32, disk: Option<u64>) -> NodeId {
        let id = NodeId::generate();
        let gpu_list: Vec<serde_json::Value> = (0..gpus)
            .map(|i| {
                serde_json::json!({"uuid": format!("GPU-{id}-{i}"), "index": i, "name": "Example GPU",
                    "driver_version": "1", "vram_mb": 8192})
            })
            .collect();
        let inventory: p2pc_proto::api::Inventory = serde_json::from_value(serde_json::json!({
            "hostname": "node", "platform": "linux", "cpu": {"model": "Example CPU", "cores": 64},
            "memory_mb": 262_144, "os": "Ubuntu 24.04", "arch": "x86_64", "gpus": gpu_list,
            "gpu_status": {"status": "ok"},
            "sandbox": [{"driver": "podman", "class": "container", "runtimes": ["crun"], "ready": true}],
            "offered": {"cpu": cpu, "memory_mb": mem, "gpu": gpus, "disk_mb": disk}, "agent_version": "0.1.0",
        }))
        .unwrap();
        let mut iroh = data_encoding::HEXLOWER.encode(id.to_string().as_bytes());
        iroh.truncate(64);
        while iroh.len() < 64 {
            iroh.push('0');
        }
        let mut conn = self.db.acquire().await.unwrap();
        let new = NewNode {
            id,
            account_id: self.account,
            project_id: self.project,
            iroh_node_id: iroh,
            inventory,
            token_id: self.token,
        };
        nodes::insert(&mut conn, &new, self.now()).await.unwrap();
        nodes::mark_connected(&mut conn, id, self.now()).await.unwrap();
        self.link.connect(id);
        id
    }

    pub(crate) async fn job_with(&self, spec: serde_json::Value) -> JobId {
        let spec: JobSpec = serde_json::from_value(spec).unwrap();
        let mut conn = self.db.acquire().await.unwrap();
        let job = NewJob {
            job_id: JobId::generate(),
            account_id: self.account,
            project_id: self.project,
            principal: p2pc_proto::api::Principal::Key(self.key),
            units_reserved: estimate_units(&spec.resources, spec.timeout_s, Units::from_units(10)),
            files_meta: p2pc_proto::api::FileMeta::compute_all(&spec).unwrap(),
            spec,
            spec_hash: format!("sha256:{}", "0".repeat(64)),
        };
        jobs::insert(&mut conn, &job, self.now()).await.unwrap().job_id
    }

    pub(crate) async fn job(&self, cpu: f64, mem: u64, gpu: u32) -> JobId {
        self.job_with(serde_json::json!({
            "image": "docker.io/library/python:3.12-slim",
            "command": ["true"],
            "env": {"SECRET": "s3cr3t-value"}, // gitleaks:allow (fake test value)
            "resources": {"cpu": cpu, "memory_mb": mem, "gpu": gpu},
            "timeout_s": 100,
        }))
        .await
    }

    /// A job asking for `cpu` vCPUs, 512 MiB and `disk_mb` MiB of disk.
    pub(crate) async fn job_disk(&self, cpu: f64, disk_mb: u64) -> JobId {
        self.job_with(serde_json::json!({
            "image": "docker.io/library/python:3.12-slim",
            "command": ["true"],
            "resources": {"cpu": cpu, "memory_mb": 512, "gpu": 0, "disk_mb": disk_mb},
            "timeout_s": 100,
        }))
        .await
    }

    pub(crate) async fn row(&self, job: JobId) -> JobRow {
        let mut conn = self.db.acquire().await.unwrap();
        jobs::get(&mut conn, self.account, self.project, job)
            .await
            .unwrap()
            .unwrap()
    }

    pub(crate) async fn status(&self, job: JobId) -> JobStatus {
        self.row(job).await.status
    }

    pub(crate) async fn lease(&self, id: LeaseId) -> LeaseRow {
        let mut conn = self.db.acquire().await.unwrap();
        leases::get(&mut conn, id).await.unwrap().unwrap()
    }

    /// The leases sent since the last call: `(node, lease_id, epoch)`, other messages kept in `others`.
    pub(crate) fn sent(&self) -> Sent {
        let mut s = Sent::default();
        for (node, msg) in self.link.take() {
            match msg {
                ServerMsg::Lease { lease_id, epoch, .. } => s.leases.push((node, lease_id, epoch)),
                ServerMsg::Cancel {
                    lease_id,
                    epoch,
                    reason,
                } => s.cancels.push((node, lease_id, epoch, reason)),
                other => s.others.push((node, other)),
            }
        }
        s
    }

    pub(crate) async fn msg(&self, node: NodeId, msg: AgentMsg) {
        self.sched.on_agent_message(node, msg).await.unwrap();
    }

    pub(crate) async fn accept(&self, node: NodeId, lease: LeaseId, epoch: u64) {
        self.msg(node, AgentMsg::LeaseAccepted { lease_id: lease, epoch }).await;
    }

    pub(crate) async fn start(&self, node: NodeId, lease: LeaseId, epoch: u64) {
        let started_at = self.now();
        self.msg(
            node,
            AgentMsg::JobStarted {
                lease_id: lease,
                epoch,
                started_at,
            },
        )
        .await;
    }

    /// `JobFinished` from an agent that frees the lease's resources at once: the report, then the heartbeat that no
    /// longer lists it (§8 "Reservations are held until confirmed"). Tests of the hold use [`Fx::finish_held`].
    pub(crate) async fn finish(&self, node: NodeId, lease: LeaseId, epoch: u64, outcome: Outcome, code: Option<i32>) {
        self.finish_held(node, lease, epoch, outcome, code).await;
        self.heartbeat(node, &[]).await;
    }

    /// Only the `JobFinished`: the node still holds the lease's resources, so the server does too.
    pub(crate) async fn finish_held(
        &self,
        node: NodeId,
        lease: LeaseId,
        epoch: u64,
        outcome: Outcome,
        code: Option<i32>,
    ) {
        self.msg(node, finished(lease, epoch, outcome, code)).await;
    }

    /// A `Heartbeat` of `node` listing `running`.
    pub(crate) async fn heartbeat(&self, node: NodeId, running: &[(LeaseId, u64)]) {
        let running: Vec<RunningLease> = running
            .iter()
            .map(|(lease_id, epoch)| RunningLease::new(*lease_id, *epoch))
            .collect();
        self.sched.on_heartbeat(node, &running).await.unwrap();
    }

    /// The free vCPUs of `node` (`free.cpu` of `GET /v1/nodes`).
    pub(crate) async fn free_cpu(&self, node: NodeId) -> f64 {
        let mut conn = self.db.acquire().await.unwrap();
        let row = nodes::get(&mut conn, self.account, node).await.unwrap().unwrap();
        let mut held = fit::Held::default();
        for r in leases::held_for_account(&mut conn, self.account)
            .await
            .unwrap()
            .get(&node)
            .into_iter()
            .flatten()
        {
            held.add(r);
        }
        fit::free_capacity(&row.inventory, &held).cpu
    }

    /// Places, accepts and starts a job; returns its lease and epoch.
    pub(crate) async fn running(&self, job: JobId) -> (NodeId, LeaseId, u64) {
        self.sched.tick().await.clean();
        self.link.take();
        // The job's offer, whichever pass made it.
        let (id, node, epoch): (String, String, i64) =
            sqlx::query_as("SELECT id, node_id, epoch FROM leases WHERE job_id = ? AND state = 'offered'")
                .bind(job.to_string())
                .fetch_one(&self.db)
                .await
                .expect("the job was offered");
        let (node, lease, epoch): (NodeId, LeaseId, u64) = (
            node.parse().unwrap(),
            id.parse().unwrap(),
            u64::try_from(epoch).unwrap(),
        );
        self.accept(node, lease, epoch).await;
        self.start(node, lease, epoch).await;
        assert_eq!(self.status(job).await, JobStatus::Running);
        (node, lease, epoch)
    }

    /// The gateway's liveness sweep for `node`: it went offline after its last contact `last`.
    pub(crate) async fn node_went_offline(&self, node: NodeId, last: OffsetDateTime) {
        self.link.disconnect(node);
        let mut conn = self.db.acquire().await.unwrap();
        nodes::touch_last_seen(&mut conn, node, last).await.unwrap();
        nodes::mark_offline(&mut conn, node).await.unwrap();
        nodes::open_disconnection(&mut conn, node, last).await.unwrap();
        nodes::resolve_disconnection(&mut conn, node, nodes::DisconnectOutcome::Offline, self.now())
            .await
            .unwrap();
        drop(conn);
        self.sched.node_offline(node, OfflineReason::Lost).await.unwrap();
    }

    /// The node's connection is back with `Hello{running}`, as `agent::session` runs it.
    pub(crate) async fn hello(&self, node: NodeId, running: &[(LeaseId, u64)]) -> Vec<ServerMsg> {
        let mut conn = self.db.acquire().await.unwrap();
        nodes::mark_connected(&mut conn, node, self.now()).await.unwrap();
        drop(conn);
        self.link.connect(node);
        let running: Vec<RunningLease> = running
            .iter()
            .map(|(lease_id, epoch)| RunningLease::new(*lease_id, *epoch))
            .collect();
        let replies = self.sched.reconcile_hello(node, &running).await.unwrap();
        let mut conn = self.db.acquire().await.unwrap();
        nodes::resolve_disconnection(&mut conn, node, nodes::DisconnectOutcome::Recovered, self.now())
            .await
            .unwrap();
        replies
    }

    pub(crate) async fn usage_rows(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM usage_records")
            .fetch_one(&self.db)
            .await
            .unwrap()
    }

    pub(crate) async fn offer_count(&self, job: JobId) -> i64 {
        sqlx::query_scalar("SELECT offer_count FROM jobs WHERE job_id = ?")
            .bind(job.to_string())
            .fetch_one(&self.db)
            .await
            .unwrap()
    }

    pub(crate) async fn jobs_of(&self, leases: &[(NodeId, LeaseId, u64)]) -> Vec<JobId> {
        let mut out = Vec::new();
        for (_, l, _) in leases {
            out.push(self.lease(*l).await.job_id);
        }
        out
    }

    pub(crate) async fn held(&self, node: NodeId) -> usize {
        let mut conn = self.db.acquire().await.unwrap();
        leases::held_on_node(&mut conn, node).await.unwrap().len()
    }
}

#[derive(Debug, Default)]
pub(crate) struct Sent {
    pub leases: Vec<(NodeId, LeaseId, u64)>,
    pub cancels: Vec<(NodeId, LeaseId, u64, String)>,
    pub others: Vec<(NodeId, ServerMsg)>,
}

pub(crate) fn finished(lease: LeaseId, epoch: u64, outcome: Outcome, code: Option<i32>) -> AgentMsg {
    AgentMsg::JobFinished {
        lease_id: lease,
        epoch,
        outcome,
        exit_code: code,
        error: (outcome == Outcome::Error).then(|| "disk_limit".to_string()),
        usage: Usage {
            wall_ms: 1_800_000,
            cpu_used_ms: 1000,
            max_rss_mb: 64,
        },
        outputs: vec![],
    }
}

macro_rules! mt_test {
    ($name:ident, $body:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            $body.await
        }
    };
}

// After `mt_test!`, which it uses.
mod services;

// --- Placement -------------------------------------------------------------------------------------------------

mt_test!(a_queued_job_is_offered_with_its_spec_and_a_fenced_epoch, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    assert_eq!(fx.sched.tick().await.clean().offered, 1);
    let mut msgs = fx.link.take();
    assert_eq!(msgs.len(), 1);
    let (to, msg) = msgs.remove(0);
    assert_eq!(to, node);
    let ServerMsg::Lease {
        lease_id,
        epoch,
        job: lj,
        account_id,
        deadline,
    } = msg
    else {
        panic!("{msg:?}")
    };
    assert_eq!((epoch, account_id), (1, fx.account));
    // The full spec, env value included: only the lease carries it.
    assert_eq!(lj.parse_strict().unwrap().env["SECRET"], "s3cr3t-value");
    // The absolute bound: acceptance, pull, timeout_s and the margin.
    assert_eq!(deadline, T0 + Duration::seconds(10 + 600 + 100 + 60));
    let l = fx.lease(lease_id).await;
    assert_eq!(
        (l.state, l.job_id, l.epoch, l.attempt),
        (LeaseState::Offered, job, 1, 1)
    );
    // An offer is not an assignment: the job stays queued until the agent accepts.
    assert_eq!(fx.status(job).await, JobStatus::Queued);
    // One active lease per job: the next pass offers nothing.
    assert_eq!(fx.sched.tick().await.clean().offered, 0);
});

mt_test!(jobs_are_placed_fifo_and_never_over_commit_a_node, async {
    let fx = Fx::new().await;
    let node = fx.node(2.0, 4096, 0).await;
    let first = fx.job(1.5, 1024, 0).await;
    fx.advance(1);
    let second = fx.job(1.0, 1024, 0).await;
    fx.advance(1);
    let third = fx.job(0.5, 1024, 0).await;
    fx.sched.tick().await.clean();
    let sent = fx.sent();
    let jobs = fx.jobs_of(&sent.leases).await;
    // `first` (1.5) and then `third` (0.5) fill the 2 vCPUs; `second` (1.0) waits, without blocking `third`.
    assert_eq!(jobs, vec![first, third]);
    assert!(sent.leases.iter().all(|(n, _, _)| *n == node));
    assert_eq!(fx.status(second).await, JobStatus::Queued);
});

mt_test!(the_best_fit_node_wins_and_a_gpu_job_gets_a_gpu, async {
    let fx = Fx::new().await;
    let big = fx.node(8.0, 16_384, 0).await;
    let small = fx.node(2.0, 2048, 0).await;
    let gpu = fx.node(8.0, 16_384, 1).await;
    let j = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    assert_eq!(
        fx.sent().leases[0].0,
        small,
        "least capacity left, and no GPU kept busy"
    );
    let g = fx.job(1.0, 1024, 1).await;
    fx.sched.tick().await.clean();
    let sent = fx.sent();
    assert_eq!(sent.leases.len(), 1);
    assert_eq!(sent.leases[0].0, gpu);
    let l = fx.lease(sent.leases[0].1).await;
    assert_eq!(l.reserved.gpu_uuid, Some(format!("GPU-{gpu}-0")));
    let _ = (big, j, g);
});

mt_test!(draining_offline_and_disconnected_nodes_get_no_offer, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let mut conn = fx.db.acquire().await.unwrap();
    nodes::set_draining(&mut conn, fx.account, node, true).await.unwrap();
    drop(conn);
    let job = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    assert!(fx.sent().leases.is_empty(), "draining");
    let mut conn = fx.db.acquire().await.unwrap();
    nodes::set_draining(&mut conn, fx.account, node, false).await.unwrap();
    drop(conn);
    fx.link.disconnect(node);
    fx.sched.tick().await.clean();
    assert!(fx.sent().leases.is_empty(), "not connected");
    fx.link.connect(node);
    fx.sched.tick().await.clean();
    assert_eq!(fx.sent().leases.len(), 1);
    let _ = job;
});

mt_test!(a_running_job_continues_when_its_node_drains, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    let (n, lease, epoch) = fx.running(job).await;
    let mut conn = fx.db.acquire().await.unwrap();
    nodes::set_draining(&mut conn, fx.account, node, true).await.unwrap();
    drop(conn);
    let other = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    assert!(fx.sent().leases.is_empty());
    fx.finish(n, lease, epoch, Outcome::Exited, Some(0)).await;
    assert_eq!(fx.status(job).await, JobStatus::Succeeded);
    assert_eq!(fx.status(other).await, JobStatus::Queued);
});

// --- Two-phase assignment --------------------------------------------------------------------------------------

mt_test!(an_accepted_lease_assigns_the_job_and_opens_an_attempt, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    let (_, lease, epoch) = fx.sent().leases[0];
    fx.advance(9);
    fx.accept(node, lease, epoch).await;
    let row = fx.row(job).await;
    assert_eq!(
        (row.status, row.node_id, row.attempt),
        (JobStatus::Assigned, Some(node), 1)
    );
    assert_eq!(fx.lease(lease).await.state, LeaseState::Accepted);
    // A duplicate acceptance changes nothing and is not fenced.
    fx.accept(node, lease, epoch).await;
    assert!(fx.sent().cancels.is_empty());
    fx.start(node, lease, epoch).await;
    let row = fx.row(job).await;
    assert_eq!(
        (row.status, row.started_at),
        (JobStatus::Running, Some(T0 + Duration::seconds(9)))
    );
    let mut conn = fx.db.acquire().await.unwrap();
    let attempts = leases::attempts(&mut conn, job).await.unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        (attempts[0].attempt, attempts[0].epoch, attempts[0].node_id),
        (1, epoch, node)
    );
    assert_eq!(attempts[0].started_at, Some(T0 + Duration::seconds(9)));
});

mt_test!(a_rejected_offer_is_not_an_attempt_and_cools_the_pair_for_60_s, async {
    let fx = Fx::new().await;
    let a = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    let (_, lease, epoch) = fx.sent().leases[0];
    fx.msg(
        a,
        AgentMsg::LeaseRejected {
            lease_id: lease,
            epoch,
            reason: LeaseRejectReason::InsufficientCapacity,
        },
    )
    .await;
    let row = fx.row(job).await;
    assert_eq!((row.status, row.attempt), (JobStatus::Queued, 1));
    assert_eq!(fx.lease(lease).await.state, LeaseState::Revoked);
    assert_eq!(fx.held(a).await, 0, "a refused offer holds nothing");
    // Same node: not before 60 s.
    fx.advance(59);
    fx.sched.tick().await.clean();
    assert!(fx.sent().leases.is_empty());
    // Another node is fine meanwhile.
    let b = fx.node(4.0, 8192, 0).await;
    fx.sched.tick().await.clean();
    let sent = fx.sent().leases;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, b);
    assert_eq!(sent[0].2, 2, "the epoch moves on with every offer");
    fx.msg(
        b,
        AgentMsg::LeaseRejected {
            lease_id: sent[0].1,
            epoch: 2,
            reason: LeaseRejectReason::Draining,
        },
    )
    .await;
    fx.advance(1);
    fx.sched.tick().await.clean();
    let sent = fx.sent().leases;
    assert_eq!((sent.len(), sent[0].0, sent[0].2), (1, a, 3), "a's cooldown is over");
    let mut conn = fx.db.acquire().await.unwrap();
    assert!(leases::attempts(&mut conn, job).await.unwrap().is_empty());
});

mt_test!(an_offer_not_accepted_within_10_s_is_revoked_and_requeued, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    let (_, lease, epoch) = fx.sent().leases[0];
    fx.advance(9);
    fx.sched.tick().await.clean();
    assert_eq!(fx.lease(lease).await.state, LeaseState::Offered);
    fx.advance(1);
    fx.sched.tick().await.clean();
    let sent = fx.sent();
    assert_eq!(fx.lease(lease).await.state, LeaseState::Revoked);
    assert_eq!(
        sent.cancels,
        vec![(node, lease, epoch, code::ACCEPT_TIMEOUT.to_string())]
    );
    assert_eq!(fx.row(job).await.attempt, 1, "not an attempt");
    // A late acceptance is fenced.
    fx.accept(node, lease, epoch).await;
    assert_eq!(fx.sent().cancels.len(), 1);
    assert_eq!(fx.status(job).await, JobStatus::Queued);
});

mt_test!(
    an_acceptance_after_10_s_counts_as_a_timeout_even_before_the_tick,
    async {
        let fx = Fx::new().await;
        let node = fx.node(4.0, 8192, 0).await;
        let job = fx.job(1.0, 1024, 0).await;
        fx.sched.tick().await.clean();
        let (_, lease, epoch) = fx.sent().leases[0];
        fx.advance(10);
        fx.accept(node, lease, epoch).await;
        assert_eq!(fx.status(job).await, JobStatus::Queued);
        assert_eq!(fx.lease(lease).await.state, LeaseState::Revoked);
        assert_eq!(fx.row(job).await.reason, None, "one failed offer is no cap");
    }
);

// Review P3: the 10 s accept window is 10 s to the millisecond. An offer sent at `x.9` s and accepted 9.9 s later is
// in time (seconds would have truncated the send to `x.0` and timed it out); 10.0 s later is too late.
mt_test!(the_accept_window_is_measured_in_milliseconds, async {
    let fx = Fx::new().await;
    let node = fx.node(8.0, 16_384, 0).await;
    fx.clock.set(T0 + Duration::milliseconds(900));
    let early = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    let (_, lease, epoch) = fx.sent().leases[0];
    fx.clock.advance(Duration::milliseconds(9900));
    fx.accept(node, lease, epoch).await;
    assert_eq!(
        fx.status(early).await,
        JobStatus::Assigned,
        "accepted 9.9 s after the send"
    );
    let late = fx.job(1.0, 1024, 0).await;
    fx.clock.set(T0 + Duration::seconds(30) + Duration::milliseconds(900));
    fx.sched.tick().await.clean();
    let (_, lease, epoch) = fx.sent().leases[0];
    fx.clock.advance(Duration::milliseconds(9999));
    fx.sched.tick().await.clean();
    assert_eq!(
        fx.lease(lease).await.state,
        LeaseState::Offered,
        "9.999 s: still in time"
    );
    fx.clock.advance(Duration::milliseconds(1));
    fx.accept(node, lease, epoch).await;
    assert_eq!(
        fx.status(late).await,
        JobStatus::Queued,
        "10.0 s after the send is too late"
    );
    assert_eq!(fx.lease(lease).await.state, LeaseState::Revoked);
});

mt_test!(after_10_failed_offers_the_job_stays_queued_with_a_reason, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    for i in 1..=OFFER_CAP {
        fx.sched.tick().await.clean();
        let sent = fx.sent().leases;
        assert_eq!(sent.len(), 1, "offer {i}");
        fx.msg(
            node,
            AgentMsg::LeaseRejected {
                lease_id: sent[0].1,
                epoch: sent[0].2,
                reason: LeaseRejectReason::GpuSelectionUnsupported,
            },
        )
        .await;
        fx.advance(61);
    }
    let row = fx.row(job).await;
    assert_eq!(row.status, JobStatus::Queued);
    assert_eq!(fx.offer_count(job).await, i64::from(OFFER_CAP));
    assert_eq!(
        row.reason.as_deref(),
        Some("no node accepted the job: gpu_selection_unsupported")
    );
    assert_eq!(row.to_job().reason, row.reason, "GET /v1/jobs/{{id}} shows it");
    fx.sched.tick().await.clean();
    assert!(fx.sent().leases.is_empty(), "no eleventh offer");
});

// --- Fencing (SI-8) and idempotency -----------------------------------------------------------------------------

mt_test!(
    a_stale_epoch_or_a_foreign_lease_gets_cancel_and_changes_nothing,
    async {
        let fx = Fx::new().await;
        let node = fx.node(4.0, 8192, 0).await;
        let other = fx.node(4.0, 8192, 0).await;
        let job = fx.job(1.0, 1024, 0).await;
        let (n, lease, epoch) = fx.running(job).await;
        // A wrong epoch for this lease.
        fx.finish(n, lease, epoch + 1, Outcome::Exited, Some(0)).await;
        // Another node reporting this node's lease.
        let o = if n == node { other } else { node };
        fx.finish(o, lease, epoch, Outcome::Exited, Some(0)).await;
        // A lease that does not exist.
        let ghost = LeaseId::generate();
        fx.start(n, ghost, 1).await;
        let sent = fx.sent();
        assert_eq!(
            sent.cancels,
            vec![
                (n, lease, epoch + 1, code::STALE_EPOCH.to_string()),
                (o, lease, epoch, code::UNKNOWN_LEASE.to_string()),
                (n, ghost, 1, code::UNKNOWN_LEASE.to_string()),
            ]
        );
        assert_eq!(fx.status(job).await, JobStatus::Running);
        assert_eq!(fx.usage_rows().await, 0);
    }
);

mt_test!(the_old_attempt_cannot_report_after_a_requeue, async {
    let fx = Fx::new().await;
    let a = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    let (n, old, old_epoch) = fx.running(job).await;
    assert_eq!(n, a);
    let last = fx.now();
    fx.advance(60);
    fx.node_went_offline(a, last).await;
    assert_eq!(fx.status(job).await, JobStatus::Queued);
    let b = fx.node(4.0, 8192, 0).await;
    let (n2, _new, new_epoch) = fx.running(job).await;
    assert_eq!(n2, b, "the retry goes to the other node");
    assert!(new_epoch > old_epoch);
    // AC-6: the first node comes back and reports the old attempt: fenced.
    let replies = fx.hello(a, &[(old, old_epoch)]).await;
    assert_eq!(replies, vec![cancel(old, old_epoch, code::STALE_EPOCH)]);
    fx.finish(a, old, old_epoch, Outcome::Exited, Some(0)).await;
    assert_eq!(
        fx.sent().cancels,
        vec![(a, old, old_epoch, code::STALE_EPOCH.to_string())]
    );
    assert_eq!(fx.status(job).await, JobStatus::Running);
    assert_eq!(fx.row(job).await.attempt, 2);
});

mt_test!(duplicate_job_started_and_job_finished_are_harmless, async {
    let fx = Fx::new().await;
    fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    let (n, lease, epoch) = fx.running(job).await;
    let started = fx.row(job).await.started_at;
    fx.advance(5);
    fx.start(n, lease, epoch).await;
    assert_eq!(
        fx.row(job).await.started_at,
        started,
        "a resent JobStarted is deduplicated"
    );
    fx.finish(n, lease, epoch, Outcome::Exited, Some(0)).await;
    fx.finish(n, lease, epoch, Outcome::Exited, Some(3)).await;
    let row = fx.row(job).await;
    assert_eq!((row.status, row.exit_code), (JobStatus::Succeeded, Some(0)));
    assert_eq!(fx.usage_rows().await, 1);
    assert!(fx.sent().cancels.is_empty(), "a second JobFinished is not even fenced");
});

mt_test!(job_finished_maps_every_outcome, async {
    let fx = Fx::new().await;
    fx.node(16.0, 65_536, 0).await;
    for (outcome, code, want, error) in [
        (Outcome::Exited, Some(0), JobStatus::Succeeded, None),
        (Outcome::Exited, Some(2), JobStatus::Failed, None),
        (Outcome::TimedOut, None, JobStatus::TimedOut, None),
        (Outcome::Cancelled, None, JobStatus::Cancelled, None),
        (Outcome::Error, None, JobStatus::Failed, Some("disk_limit")),
    ] {
        let job = fx.job(1.0, 1024, 0).await;
        let (n, lease, epoch) = fx.running(job).await;
        fx.finish(n, lease, epoch, outcome, code).await;
        let row = fx.row(job).await;
        assert_eq!(row.status, want, "{outcome:?} {code:?}");
        assert_eq!((row.exit_code, row.error.as_deref()), (code, error));
        let l = fx.lease(lease).await;
        assert_eq!(l.state, LeaseState::Finished);
        assert!(l.confirmed_dead_at.is_some(), "the reservation is released");
    }
    assert_eq!(fx.usage_rows().await, 5);
});

mt_test!(an_exit_reported_before_job_started_implies_the_start, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    let (_, lease, epoch) = fx.sent().leases[0];
    fx.accept(node, lease, epoch).await;
    fx.finish(node, lease, epoch, Outcome::Exited, Some(0)).await;
    assert_eq!(fx.status(job).await, JobStatus::Succeeded);
    let mut conn = fx.db.acquire().await.unwrap();
    let ev: Vec<JobStatus> = crate::store::job_state::events(&mut conn, fx.account, fx.project, job)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.to)
        .collect();
    assert_eq!(
        ev,
        [
            JobStatus::Queued,
            JobStatus::Assigned,
            JobStatus::Running,
            JobStatus::Succeeded
        ]
    );
});

mt_test!(the_ledger_records_the_reserved_time_and_units, async {
    let fx = Fx::new().await;
    fx.node(4.0, 8192, 1).await;
    let job = fx.job(2.0, 1024, 1).await;
    let (n, lease, epoch) = fx.running(job).await;
    fx.advance(30);
    // 1 800 000 ms reported, capped at timeout_s (100) + 60 s = 160 000 ms.
    fx.finish(n, lease, epoch, Outcome::Exited, Some(0)).await;
    type Row = (i64, i64, i64, i64, i64, i64, i64);
    let r: Row = sqlx::query_as(
        "SELECT attempt, started_at, ended_at, reserved_cpu_ms, reserved_gpu_ms, used_cpu_ms, units FROM usage_records",
    )
    .fetch_one(&fx.db)
    .await
    .unwrap();
    assert_eq!(r.0, 1);
    assert_eq!(
        (r.1, r.2),
        (T0.unix_timestamp(), (T0 + Duration::seconds(30)).unix_timestamp())
    );
    assert_eq!((r.3, r.4, r.5), (320_000, 160_000, 1000));
    // (2 000 milli-vCPU + 10 000 milli-units per GPU-hour) × 160 s / 3600 s, rounded up.
    assert_eq!(r.6, (12_000i64 * 160_000).div_euclid(3_600_000) + 1);
    let appended = sqlx::query("UPDATE usage_records SET units = 0").execute(&fx.db).await;
    assert!(appended.unwrap_err().to_string().contains("append-only"));
});

mt_test!(log_chunks_are_fenced_and_deduplicated, async {
    let fx = Fx::new().await;
    fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    let (n, lease, epoch) = fx.running(job).await;
    let chunk = |seq: u64, epoch: u64| AgentMsg::LogChunk {
        lease_id: lease,
        epoch,
        stream: p2pc_proto::api::LogStream::Stdout,
        seq,
        data_b64: LogData::from("aGk="),
    };
    for seq in [0, 1, 1, 0, 2] {
        fx.msg(n, chunk(seq, epoch)).await;
    }
    fx.msg(n, chunk(3, epoch + 1)).await;
    assert_eq!(
        *fx.hooks.chunks.lock().unwrap(),
        vec![(job, 1, 0), (job, 1, 1), (job, 1, 2)]
    );
    assert_eq!(fx.sent().cancels.len(), 1, "the stale chunk is fenced");
});

mt_test!(
    outputs_are_finalised_before_the_terminal_transition_and_their_note_kept,
    async {
        let fx = Fx::new().await;
        fx.node(4.0, 8192, 0).await;
        let job = fx.job(1.0, 1024, 0).await;
        let (n, lease, epoch) = fx.running(job).await;
        *fx.hooks.note.lock().unwrap() = Some("outputs_incomplete: 1".into());
        fx.finish(n, lease, epoch, Outcome::Error, None).await;
        assert_eq!(*fx.hooks.finalized.lock().unwrap(), vec![(job, 1, 0)]);
        let row = fx.row(job).await;
        assert_eq!(row.error.as_deref(), Some("disk_limit; outputs_incomplete: 1"));
        // A stale JobFinished never reaches the finaliser.
        fx.finish(n, lease, epoch + 1, Outcome::Exited, Some(0)).await;
        assert_eq!(fx.hooks.finalized.lock().unwrap().len(), 1);
    }
);

// --- Reconciliation and liveness --------------------------------------------------------------------------------

mt_test!(hello_keeps_valid_leases_cancels_the_rest_and_loses_the_absent, async {
    let fx = Fx::new().await;
    let node = fx.node(8.0, 16_384, 0).await;
    let kept = fx.job(1.0, 1024, 0).await;
    let gone = fx.job(1.0, 1024, 0).await;
    let (_, l_kept, e_kept) = fx.running(kept).await;
    let (_, l_gone, e_gone) = fx.running(gone).await;
    // The connection drops and comes back at once (well within the TTL).
    fx.link.disconnect(node);
    fx.advance(5);
    let ghost = LeaseId::generate();
    let replies = fx
        .hello(node, &[(l_kept, e_kept), (ghost, 1), (l_kept, e_kept + 7)])
        .await;
    // 1. A valid current lease continues; 2. anything else gets Cancel.
    assert_eq!(
        replies,
        vec![
            cancel(ghost, 1, code::UNKNOWN_LEASE),
            cancel(l_kept, e_kept + 7, code::STALE_EPOCH)
        ]
    );
    assert_eq!(fx.status(kept).await, JobStatus::Running);
    // 3. Held for this node but absent from the Hello: lost at once, requeued with attempt + 1.
    let row = fx.row(gone).await;
    assert_eq!((row.status, row.attempt), (JobStatus::Queued, 2));
    let l = fx.lease(l_gone).await;
    assert_eq!(l.state, LeaseState::Lost);
    assert_eq!(l.confirmed_dead_at, Some(fx.now()));
    let mut conn = fx.db.acquire().await.unwrap();
    let a = leases::attempts(&mut conn, gone).await.unwrap();
    assert_eq!(
        (a[0].outcome.as_deref(), a[0].reason_code.as_deref()),
        (Some("lost"), Some(code::ABSENT_FROM_HELLO))
    );
    let _ = e_gone;
});

mt_test!(no_requeue_before_lease_ttl_s_without_heartbeat, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    let (_, lease, _) = fx.running(job).await;
    let last = fx.now();
    // The connection drops: the node is not connected, but its TTL has not run.
    fx.link.disconnect(node);
    fx.advance(59);
    fx.sched.tick().await.clean();
    fx.sched.node_offline(node, OfflineReason::Lost).await.unwrap();
    assert_eq!(
        fx.status(job).await,
        JobStatus::Running,
        "even a premature hook changes nothing"
    );
    // The DB says offline (the sweep), but the last contact is 59 s old: still nothing.
    let mut conn = fx.db.acquire().await.unwrap();
    nodes::touch_last_seen(&mut conn, node, last).await.unwrap();
    nodes::mark_offline(&mut conn, node).await.unwrap();
    drop(conn);
    fx.sched.tick().await.clean();
    assert_eq!(fx.status(job).await, JobStatus::Running);
    fx.advance(1);
    fx.node_went_offline(node, last).await;
    let row = fx.row(job).await;
    assert_eq!((row.status, row.attempt), (JobStatus::Queued, 2));
    assert_eq!(fx.lease(lease).await.confirmed_dead_at, Some(last + TTL));
    let mut conn = fx.db.acquire().await.unwrap();
    let log = nodes::disconnections(&mut conn, node).await.unwrap();
    assert_eq!(log.last().unwrap().outcome.as_deref(), Some("requeued"));
});

mt_test!(the_tick_backstop_expires_a_silent_node_the_hook_missed, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    fx.running(job).await;
    let last = fx.now();
    fx.link.disconnect(node);
    let mut conn = fx.db.acquire().await.unwrap();
    nodes::touch_last_seen(&mut conn, node, last).await.unwrap();
    nodes::mark_offline(&mut conn, node).await.unwrap();
    drop(conn);
    fx.advance(60);
    fx.sched.tick().await.clean();
    assert_eq!(fx.status(job).await, JobStatus::Queued);
});

mt_test!(a_requeue_gives_the_new_attempt_a_fresh_offer_budget, async {
    let fx = Fx::new().await;
    let a = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    // Three refused offers, then one accepted and running.
    for _ in 0..3 {
        fx.sched.tick().await.clean();
        let (_, lease, epoch) = fx.sent().leases[0];
        fx.msg(
            a,
            AgentMsg::LeaseRejected {
                lease_id: lease,
                epoch,
                reason: LeaseRejectReason::InsufficientCapacity,
            },
        )
        .await;
        fx.advance(61);
    }
    assert_eq!(fx.offer_count(job).await, 3);
    fx.running(job).await;
    let last = fx.now();
    fx.advance(60);
    fx.node_went_offline(a, last).await;
    let row = fx.row(job).await;
    assert_eq!((row.status, row.attempt), (JobStatus::Queued, 2));
    assert_eq!(
        fx.offer_count(job).await,
        0,
        "attempt 2 starts with a fresh offer budget"
    );
});

// Review P3: one bad lease must not stop the tick. A lease whose step fails (here a trigger refuses to update it)
// is logged, counted and skipped; the other leases and the other phases are still served.
mt_test!(a_failing_lease_step_is_skipped_and_the_rest_is_served, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let stuck = fx.job(1.0, 1024, 0).await;
    let fine = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    let sent = fx.sent().leases;
    assert_eq!(sent.len(), 2);
    let mut stuck_lease = None;
    for (_, l, _) in &sent {
        if fx.lease(*l).await.job_id == stuck {
            stuck_lease = Some(*l);
        }
    }
    let stuck_lease = stuck_lease.unwrap();
    for sql in [
        "CREATE TABLE refused (id TEXT NOT NULL)",
        "CREATE TRIGGER refuse_one BEFORE UPDATE ON leases WHEN OLD.id IN (SELECT id FROM refused) \
         BEGIN SELECT RAISE(ABORT, 'refused for the test'); END",
    ] {
        sqlx::query(sql).execute(&fx.db).await.unwrap();
    }
    sqlx::query("INSERT INTO refused (id) VALUES (?)")
        .bind(stuck_lease.to_string())
        .execute(&fx.db)
        .await
        .unwrap();
    // Both offers time out; a third job waits for room.
    let later = fx.job(1.0, 1024, 0).await;
    fx.advance(10);
    let r = fx.sched.tick().await;
    assert_eq!(r.errors, 1, "the refused lease is one failed step");
    assert_eq!(fx.lease(stuck_lease).await.state, LeaseState::Offered);
    let others: Vec<LeaseState> = {
        let mut v = Vec::new();
        for (_, l, _) in &sent {
            if *l != stuck_lease {
                v.push(fx.lease(*l).await.state);
            }
        }
        v
    };
    assert_eq!(others, [LeaseState::Revoked], "the other offer expired");
    // Placement still ran after the failed step.
    let placed = fx.jobs_of(&fx.sent().leases).await;
    assert!(placed.contains(&later), "{placed:?}");
    let _ = (node, fine);
});

// A corrupt lease row is left out of the listings (logged), and its reservation fails closed: its node counts as
// full, while the other nodes keep working.
mt_test!(a_corrupt_lease_row_fails_closed_and_does_not_stop_the_tick, async {
    let fx = Fx::new().await;
    fx.node(4.0, 8192, 0).await;
    fx.node(4.0, 8192, 0).await;
    let broken = fx.job(1.0, 1024, 0).await;
    let (bad_node, bad_lease, bad_epoch) = fx.running(broken).await;
    sqlx::query("UPDATE leases SET reserved = '{}' WHERE id = ?")
        .bind(bad_lease.to_string())
        .execute(&fx.db)
        .await
        .unwrap();
    for _ in 0..3 {
        fx.job(1.0, 1024, 0).await;
    }
    fx.advance(1);
    let r = fx.sched.tick().await;
    assert_eq!(r.errors, 0, "a corrupt row is skipped, not a failed pass");
    let sent = fx.sent().leases;
    assert_eq!(sent.len(), 3, "the healthy node takes the new jobs");
    assert!(
        sent.iter().all(|(n, _, _)| *n != bad_node),
        "the node of the corrupt lease counts as full"
    );
    // A message for the corrupt lease fails on its own; the scheduler goes on.
    assert!(
        fx.sched
            .on_agent_message(bad_node, finished(bad_lease, bad_epoch, Outcome::Exited, Some(0)))
            .await
            .is_err()
    );
    fx.sched.tick().await.clean();
});

// Review P3: a reconciliation that fails on the database cancels nothing (§6 "Server restart": healthy jobs are never
// cancelled for a server-side failure); the gateway closes the session and the agent reconciles again.
mt_test!(a_failed_reconciliation_cancels_nothing, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let kept = fx.job(1.0, 1024, 0).await;
    let gone = fx.job(1.0, 1024, 0).await;
    let (_, l_kept, e_kept) = fx.running(kept).await;
    let (_, l_gone, _) = fx.running(gone).await;
    fx.link.disconnect(node);
    sqlx::query("CREATE TRIGGER refuse_all BEFORE UPDATE ON leases BEGIN SELECT RAISE(ABORT, 'database down'); END")
        .execute(&fx.db)
        .await
        .unwrap();
    // The Hello lists one lease; losing the other needs a write, which fails.
    let running = [RunningLease::new(l_kept, e_kept)];
    let result = LeaseReconciler::reconcile(&fx.sched, node, &running).await;
    assert_eq!(result, Err(ReconcileFailed));
    assert!(fx.link.take().is_empty(), "nothing is sent");
    assert_eq!(fx.status(kept).await, JobStatus::Running);
    assert_eq!(
        fx.status(gone).await,
        JobStatus::Running,
        "nothing was lost either: rolled back"
    );
    sqlx::query("DROP TRIGGER refuse_all").execute(&fx.db).await.unwrap();
    // The agent reconnects: now it reconciles.
    let replies = LeaseReconciler::reconcile(&fx.sched, node, &running).await.unwrap();
    assert!(replies.is_empty(), "{replies:?}");
    assert_eq!(fx.status(kept).await, JobStatus::Running);
    assert_eq!(fx.lease(l_gone).await.state, LeaseState::Lost);
});

// Review P3 (§11, amended 54959f6): every attempt that held a reservation and ended has a ledger row. A lost attempt
// gets the server's estimate: the reservation from its start (or acceptance) to the moment the loss was decided. A job
// requeued twice has three rows, and the daily cap counts all three.
mt_test!(lost_attempts_are_billed_with_an_estimate, async {
    let fx = Fx::new().await;
    let a = fx.node(4.0, 8192, 0).await;
    let job = fx
        .job_with(
            serde_json::json!({"image": "docker.io/library/alpine:3", "command": ["true"],
            "resources": {"cpu": 1, "memory_mb": 256}, "timeout_s": 3600, "retry": {"max_attempts": 3}}),
        )
        .await;
    let spent = |fx: &Fx| {
        let db = fx.db.clone();
        let (account, key, day) = (fx.account, fx.key, crate::units::utc_day(fx.now()));
        async move {
            let mut c = db.acquire().await.unwrap();
            leases::spent(&mut c, account, p2pc_proto::api::Principal::Key(key), day.0)
                .await
                .unwrap()
        }
    };
    // Attempts 1 and 2 are lost: the node goes silent 30 s after the start, the loss is decided 60 s later.
    for attempt in 1..=2 {
        let (node, _, _) = fx.running(job).await;
        assert_eq!(node, a);
        fx.advance(30);
        let last = fx.now();
        fx.advance(60);
        fx.node_went_offline(a, last).await;
        assert_eq!(fx.row(job).await.attempt, attempt + 1);
        // The node comes back for the next attempt.
        fx.hello(a, &[]).await;
    }
    let (_, lease, epoch) = fx.running(job).await;
    type Row = (i64, i64, i64, i64);
    let rows: Vec<Row> =
        sqlx::query_as("SELECT attempt, ended_at - started_at, units, estimated FROM usage_records ORDER BY attempt")
            .fetch_all(&fx.db)
            .await
            .unwrap();
    // 1 vCPU for 90 s: 25 milli-units each.
    assert_eq!(rows, vec![(1, 90, 25, 1), (2, 90, 25, 1)]);
    // While attempt 3 runs: what attempts 1 and 2 cost, plus attempt 3's reservation (1 vCPU × 1 h).
    assert_eq!(spent(&fx).await, 25 + 25 + 1000);
    fx.advance(36);
    fx.finish(a, lease, epoch, Outcome::Exited, Some(0)).await;
    assert_eq!(fx.status(job).await, JobStatus::Succeeded);
    let units: Vec<i64> = sqlx::query_scalar("SELECT units FROM usage_records ORDER BY attempt")
        .fetch_all(&fx.db)
        .await
        .unwrap();
    assert_eq!(units.len(), 3, "three attempts, three rows");
    assert_eq!(
        spent(&fx).await,
        units.iter().sum::<i64>() as u64,
        "the cap counts all three"
    );
});

mt_test!(a_job_with_no_attempt_left_is_lost, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx
        .job_with(
            serde_json::json!({"image": "docker.io/library/alpine:3", "command": ["true"],
            "resources": {"cpu": 1, "memory_mb": 256}, "retry": {"max_attempts": 1}}),
        )
        .await;
    fx.running(job).await;
    let last = fx.now();
    fx.advance(60);
    fx.node_went_offline(node, last).await;
    assert_eq!(fx.status(job).await, JobStatus::Lost);
});

mt_test!(a_lost_attempt_holds_its_reservation_until_confirmed_dead, async {
    let fx = Fx::new().await;
    let node = fx.node(2.0, 4096, 0).await;
    let first = fx.job(2.0, 1024, 0).await;
    let (_, lease, epoch) = fx.running(first).await;
    // Cancel while the node is unreachable: the job is cancelled at once…
    fx.link.disconnect(node);
    let mut conn = fx.db.acquire().await.unwrap();
    assert!(
        jobs::request_cancel(&mut conn, fx.account, fx.project, first, fx.now())
            .await
            .unwrap()
    );
    drop(conn);
    let second = fx.job(2.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    assert_eq!(fx.status(first).await, JobStatus::Cancelled);
    // … but the execution may still run there, so its 2 vCPUs stay held: AC-10, no double booking.
    fx.link.connect(node);
    fx.sched.tick().await.clean();
    assert!(fx.sent().leases.is_empty(), "the capacity is still held");
    assert_eq!(fx.held(node).await, 1);
    // The node comes back still running it: it gets Cancel, and the reservation is still held.
    let replies = fx.hello(node, &[(lease, epoch)]).await;
    assert_eq!(replies, vec![cancel(lease, epoch, code::STALE_EPOCH)]);
    fx.sched.tick().await.clean();
    assert!(fx.sent().leases.is_empty());
    // It reports the end: confirmed dead, released, and the next job is placed.
    fx.finish(node, lease, epoch, Outcome::Cancelled, None).await;
    assert_eq!(
        fx.status(first).await,
        JobStatus::Cancelled,
        "terminal states never change"
    );
    assert_eq!(fx.held(node).await, 0);
    fx.sched.tick().await.clean();
    let sent = fx.sent().leases;
    assert_eq!(sent.len(), 1);
    assert_eq!(fx.jobs_of(&sent).await, vec![second]);
});

mt_test!(a_deleted_nodes_leases_are_lost_at_once_and_it_is_sent_nothing, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let running = fx.job(1.0, 1024, 0).await;
    let (_, lease, _) = fx.running(running).await;
    let offered = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    let offer = fx.sent().leases[0].1;
    let mut conn = fx.db.acquire().await.unwrap();
    nodes::soft_delete(&mut conn, fx.account, node, fx.now()).await.unwrap();
    drop(conn);
    fx.sched.node_offline(node, OfflineReason::Deleted).await.unwrap();
    assert!(fx.link.take().is_empty(), "nothing more goes to a deleted node");
    let row = fx.row(running).await;
    assert_eq!((row.status, row.attempt), (JobStatus::Queued, 2));
    assert_eq!(fx.lease(lease).await.state, LeaseState::Lost);
    assert_eq!(fx.lease(offer).await.state, LeaseState::Revoked);
    assert_eq!(fx.status(offered).await, JobStatus::Queued);
    assert_eq!(
        fx.offer_count(offered).await,
        0,
        "a deletion is not the job's failed offer"
    );
    assert_eq!(fx.held(node).await, 0);
});

mt_test!(a_server_restart_does_not_lose_or_cancel_healthy_leases, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx
        .job_with(
            serde_json::json!({"image": "docker.io/library/alpine:3", "command": ["sleep", "86400"],
            "resources": {"cpu": 1, "memory_mb": 256}, "timeout_s": 86_400}),
        )
        .await;
    let (_, lease, epoch) = fx.running(job).await;
    // The server is down for an hour; the agent keeps running (it reconnects quickly once the server is up).
    fx.link.disconnect(node);
    fx.advance(3600);
    let restarted = fx.another_scheduler();
    // Even if the node row were offline, nothing expires before lease_ttl_s after the boot.
    let mut conn = fx.db.acquire().await.unwrap();
    nodes::mark_offline(&mut conn, node).await.unwrap();
    drop(conn);
    fx.advance(59);
    restarted.tick().await.clean();
    restarted.node_offline(node, OfflineReason::Lost).await.unwrap();
    assert_eq!(fx.status(job).await, JobStatus::Running);
    // The agent reconnects and lists its lease: it continues, nothing is cancelled.
    let mut conn = fx.db.acquire().await.unwrap();
    nodes::mark_connected(&mut conn, node, fx.now()).await.unwrap();
    drop(conn);
    fx.link.connect(node);
    let replies = restarted
        .reconcile_hello(node, &[RunningLease::new(lease, epoch)])
        .await
        .unwrap();
    assert!(replies.is_empty(), "{replies:?}");
    fx.advance(120);
    restarted.tick().await.clean();
    assert_eq!(fx.status(job).await, JobStatus::Running);
    assert!(fx.sent().cancels.is_empty());
});

// --- Cancel and the watchdog -----------------------------------------------------------------------------------

mt_test!(
    cancel_on_a_connected_node_sends_cancel_once_and_waits_for_the_report,
    async {
        let fx = Fx::new().await;
        let node = fx.node(4.0, 8192, 0).await;
        let job = fx.job(1.0, 1024, 0).await;
        let (_, lease, epoch) = fx.running(job).await;
        let mut conn = fx.db.acquire().await.unwrap();
        jobs::request_cancel(&mut conn, fx.account, fx.project, job, fx.now())
            .await
            .unwrap();
        drop(conn);
        fx.sched.tick().await.clean();
        fx.sched.tick().await.clean();
        assert_eq!(fx.sent().cancels, vec![(node, lease, epoch, code::USER.to_string())]);
        assert_eq!(fx.status(job).await, JobStatus::Running);
        fx.finish(node, lease, epoch, Outcome::Cancelled, None).await;
        assert_eq!(fx.status(job).await, JobStatus::Cancelled);
        assert_eq!(fx.held(node).await, 0);
    }
);

// Review P3: a `Cancel` that could not be queued (the session's queue was full) is not lost: it is sent again every
// 5 s while the lease runs and no `JobFinished` came back.
mt_test!(a_cancel_that_could_not_be_queued_is_sent_again, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    let (_, lease, epoch) = fx.running(job).await;
    let mut conn = fx.db.acquire().await.unwrap();
    jobs::request_cancel(&mut conn, fx.account, fx.project, job, fx.now())
        .await
        .unwrap();
    drop(conn);
    let want = vec![(node, lease, epoch, code::USER.to_string())];
    fx.link.set_full(node, true);
    fx.sched.tick().await.clean();
    assert!(fx.sent().cancels.is_empty(), "the queue was full");
    fx.link.set_full(node, false);
    fx.advance(4);
    fx.sched.tick().await.clean();
    assert!(fx.sent().cancels.is_empty(), "not yet: 5 s between attempts");
    fx.advance(1);
    fx.sched.tick().await.clean();
    assert_eq!(fx.sent().cancels, want, "sent again");
    // Delivered, but no JobFinished yet: again after 5 s, not before.
    fx.advance(4);
    fx.sched.tick().await.clean();
    assert!(fx.sent().cancels.is_empty());
    fx.advance(1);
    fx.sched.tick().await.clean();
    assert_eq!(fx.sent().cancels, want);
    // The report ends it: nothing more.
    fx.finish(node, lease, epoch, Outcome::Cancelled, None).await;
    assert_eq!(fx.status(job).await, JobStatus::Cancelled);
    fx.advance(10);
    fx.sched.tick().await.clean();
    assert!(fx.sent().cancels.is_empty());
});

mt_test!(a_job_cancelled_while_its_lease_is_an_offer_revokes_the_offer, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    let (_, lease, epoch) = fx.sent().leases[0];
    let mut conn = fx.db.acquire().await.unwrap();
    let row = fx.row(job).await;
    crate::store::job_state::transition(&mut conn, &row, JobStatus::Cancelled, "cancelled_by_user", fx.now())
        .await
        .unwrap();
    drop(conn);
    fx.sched.tick().await.clean();
    assert_eq!(
        fx.sent().cancels,
        vec![(node, lease, epoch, code::JOB_CANCELLED.to_string())]
    );
    assert_eq!(fx.held(node).await, 0);
    fx.accept(node, lease, epoch).await;
    assert_eq!(fx.status(job).await, JobStatus::Cancelled);
});

// T06 review, carry-over 1: an offer that expires in the tick after its job was cancelled is not a failed offer: the
// terminal job gets no cooldown, no offer count and never the offer cap's reason.
mt_test!(an_offer_expiring_on_a_cancelled_job_leaves_the_job_alone, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    // One failed offer away from the cap.
    sqlx::query("UPDATE jobs SET offer_count = ? WHERE job_id = ?")
        .bind(i64::from(OFFER_CAP - 1))
        .bind(job.to_string())
        .execute(&fx.db)
        .await
        .unwrap();
    fx.sched.tick().await.clean();
    let (_, lease, epoch) = fx.sent().leases[0];
    let mut conn = fx.db.acquire().await.unwrap();
    let row = fx.row(job).await;
    crate::store::job_state::transition(&mut conn, &row, JobStatus::Cancelled, "cancelled_by_user", fx.now())
        .await
        .unwrap();
    drop(conn);
    // The offer's 10 s pass before the next tick: it expires and the cancel is due in the same tick.
    fx.advance(11);
    fx.sched.tick().await.clean();
    let row = fx.row(job).await;
    assert_eq!((row.status, row.reason), (JobStatus::Cancelled, None));
    assert_eq!(fx.offer_count(job).await, i64::from(OFFER_CAP - 1));
    let cooling: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM job_node_cooldowns WHERE job_id = ?")
        .bind(job.to_string())
        .fetch_one(&fx.db)
        .await
        .unwrap();
    assert_eq!(cooling, 0);
    assert_eq!(fx.held(node).await, 0);
    assert_eq!(fx.lease(lease).await.state, LeaseState::Revoked);
    let _ = epoch;
});

// T06 review, carry-over 2: a pending user cancel that is not due again (sent less than 5 s ago) costs no write
// transaction in a tick.
mt_test!(cancels_that_are_not_due_open_no_transaction, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    let (_, lease, epoch) = fx.running(job).await;
    let mut conn = fx.db.acquire().await.unwrap();
    jobs::request_cancel(&mut conn, fx.account, fx.project, job, fx.now())
        .await
        .unwrap();
    drop(conn);
    let r = fx.sched.tick().await.clean();
    assert_eq!(r.cancels_tried, 1);
    assert_eq!(fx.sent().cancels, vec![(node, lease, epoch, code::USER.to_string())]);
    fx.advance(4);
    assert_eq!(
        fx.sched.tick().await.clean().cancels_tried,
        0,
        "not due: no transaction"
    );
    fx.advance(1);
    assert_eq!(fx.sched.tick().await.clean().cancels_tried, 1);
    // An unreachable node is due at once (the job is cancelled now).
    fx.link.disconnect(node);
    assert_eq!(fx.sched.tick().await.clean().cancels_tried, 1);
    assert_eq!(fx.status(job).await, JobStatus::Cancelled);
});

// T06 review, carry-over 3: the `Cancel`s the server sends for executions it ended itself (the watchdog, a cancel on
// an unreachable node) are sent again every 5 s until the node reports, like user cancels: a full session queue
// never loses one for good.
mt_test!(server_side_cancels_are_sent_again_until_the_node_reports, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    let (_, lease, epoch) = fx.running(job).await;
    let want = vec![(node, lease, epoch, code::WATCHDOG.to_string())];
    fx.link.set_full(node, true);
    fx.advance(160);
    fx.sched.tick().await.clean();
    assert_eq!(fx.status(job).await, JobStatus::TimedOut);
    assert!(fx.sent().cancels.is_empty(), "the queue was full");
    fx.link.set_full(node, false);
    fx.advance(4);
    fx.sched.tick().await.clean();
    assert!(fx.sent().cancels.is_empty(), "not yet: 5 s between sends");
    fx.advance(1);
    fx.sched.tick().await.clean();
    assert_eq!(fx.sent().cancels, want);
    fx.advance(5);
    fx.sched.tick().await.clean();
    assert_eq!(fx.sent().cancels, want, "again, until the node reports");
    fx.finish(node, lease, epoch, Outcome::Cancelled, None).await;
    assert_eq!(fx.held(node).await, 0);
    fx.advance(10);
    fx.sched.tick().await.clean();
    assert!(fx.sent().cancels.is_empty());

    // A cancel on an unreachable node: sent once the node is reachable again, until it reports.
    let job = fx.job(1.0, 1024, 0).await;
    let (_, lease, epoch) = fx.running(job).await;
    fx.link.disconnect(node);
    let mut conn = fx.db.acquire().await.unwrap();
    jobs::request_cancel(&mut conn, fx.account, fx.project, job, fx.now())
        .await
        .unwrap();
    drop(conn);
    fx.sched.tick().await.clean();
    assert_eq!(fx.status(job).await, JobStatus::Cancelled);
    fx.link.connect(node);
    fx.advance(5);
    fx.sched.tick().await.clean();
    assert_eq!(
        fx.sent().cancels,
        vec![(node, lease, epoch, code::CANCELLED_UNREACHABLE.to_string())]
    );
});

// T06 review, carry-over 4: a `log_seq` entry re-inserted after its lease ended (the fencing read raced `finish`) does
// not leak: the tick keeps only active leases.
mt_test!(log_seq_keeps_only_active_leases, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    let (_, lease, epoch) = fx.running(job).await;
    let other = fx.job(1.0, 1024, 0).await;
    let (_, live, live_epoch) = fx.running(other).await;
    fx.msg(
        node,
        AgentMsg::LogChunk {
            lease_id: live,
            epoch: live_epoch,
            stream: p2pc_proto::api::LogStream::Stdout,
            seq: 0,
            data_b64: LogData("eA==".into()),
        },
    )
    .await;
    fx.finish(node, lease, epoch, Outcome::Exited, Some(0)).await;
    // The race: a chunk's insert lands after `finish` cleared the entry.
    fx.sched.inner.log_seq.lock().unwrap().insert(lease, 7);
    fx.sched.tick().await.clean();
    let seqs = fx.sched.inner.log_seq.lock().unwrap().clone();
    assert_eq!(seqs.keys().copied().collect::<Vec<_>>(), vec![live]);
});

mt_test!(the_watchdog_times_out_running_and_assigned_jobs, async {
    let fx = Fx::new().await;
    let node = fx.node(8.0, 16_384, 0).await;
    // Running: timeout_s (100) + 60 s after JobStarted.
    let run = fx.job(1.0, 1024, 0).await;
    let (_, lease, epoch) = fx.running(run).await;
    fx.advance(159);
    fx.sched.tick().await.clean();
    assert_eq!(fx.status(run).await, JobStatus::Running);
    fx.advance(1);
    fx.sched.tick().await.clean();
    assert_eq!(fx.status(run).await, JobStatus::TimedOut);
    assert_eq!(
        fx.sent().cancels,
        vec![(node, lease, epoch, code::WATCHDOG.to_string())]
    );
    assert_eq!(fx.held(node).await, 1, "held until the node confirms the end");
    fx.finish(node, lease, epoch, Outcome::Cancelled, None).await;
    assert_eq!(fx.status(run).await, JobStatus::TimedOut);
    assert_eq!(fx.held(node).await, 0);
    // Assigned (a hung pull): pull_timeout_s (600) + timeout_s + 60 s after acceptance.
    let pull = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    let (_, lease, epoch) = fx.sent().leases[0];
    fx.accept(node, lease, epoch).await;
    fx.advance(759);
    fx.sched.tick().await.clean();
    assert_eq!(fx.status(pull).await, JobStatus::Assigned);
    fx.advance(1);
    fx.sched.tick().await.clean();
    assert_eq!(fx.status(pull).await, JobStatus::TimedOut);
    assert_eq!(
        fx.sent().cancels,
        vec![(node, lease, epoch, code::WATCHDOG.to_string())]
    );
});

// Review P3 (the ledger gap): an attempt the server ends itself writes an **estimated** usage row: what it reserved,
// from its start (or acceptance) to the end, with nothing measured. A later `JobFinished` from the node only releases
// the reservation; it never adds a second row.
mt_test!(server_ended_attempts_get_an_estimated_usage_row, async {
    let fx = Fx::new().await;
    let node = fx.node(8.0, 16_384, 0).await;
    // The watchdog, on a running job: 2 vCPUs from JobStarted to the watchdog (timeout 100 s + 60 s).
    let run = fx.job(2.0, 1024, 0).await;
    let (_, lease, epoch) = fx.running(run).await;
    fx.advance(160);
    fx.sched.tick().await.clean();
    assert_eq!(fx.status(run).await, JobStatus::TimedOut);
    type Row = (i64, i64, i64, i64, i64, i64, i64);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT started_at, ended_at, reserved_cpu_ms, used_cpu_ms, max_rss_mb, units, estimated FROM usage_records",
    )
    .fetch_all(&fx.db)
    .await
    .unwrap();
    let start = T0.unix_timestamp();
    assert_eq!(rows, vec![(start, start + 160, 320_000, 0, 0, 89, 1)]);
    // The node reports the end later: released, but no second row.
    fx.finish(node, lease, epoch, Outcome::Cancelled, None).await;
    assert_eq!(fx.usage_rows().await, 1);
    // A cancel on an unreachable node, accepted but never started: from the acceptance to the cancel.
    let job = fx.job(1.0, 1024, 0).await;
    fx.sched.tick().await.clean();
    let (_, lease, epoch) = fx.sent().leases[0];
    fx.accept(node, lease, epoch).await;
    fx.advance(36);
    fx.link.disconnect(node);
    let mut conn = fx.db.acquire().await.unwrap();
    jobs::request_cancel(&mut conn, fx.account, fx.project, job, fx.now())
        .await
        .unwrap();
    drop(conn);
    fx.sched.tick().await.clean();
    assert_eq!(fx.status(job).await, JobStatus::Cancelled);
    let (reserved, units, estimated): (i64, i64, i64) =
        sqlx::query_as("SELECT reserved_cpu_ms, units, estimated FROM usage_records WHERE lease_id = ?")
            .bind(lease.to_string())
            .fetch_one(&fx.db)
            .await
            .unwrap();
    assert_eq!((reserved, units, estimated), (36_000, 10, 1));
    // The cap counts the estimate, not the whole reservation (1 vCPU × 100 s = 28 milli-units).
    let day = crate::units::utc_day(fx.now());
    let mut conn = fx.db.acquire().await.unwrap();
    let spent = leases::spent(&mut conn, fx.account, p2pc_proto::api::Principal::Key(fx.key), day.0)
        .await
        .unwrap();
    assert_eq!(spent, 89 + 10);
});

// Review P3: a (job, node) pair that is cooling down is filtered out in the read-only snapshot, so no placement
// transaction (`BEGIN IMMEDIATE`) is opened for it.
mt_test!(a_cooling_pair_opens_no_placement_transaction, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    let r = fx.sched.tick().await.clean();
    assert_eq!((r.considered, r.placements_tried, r.offered), (1, 1, 1));
    let (_, lease, epoch) = fx.sent().leases[0];
    fx.msg(
        node,
        AgentMsg::LeaseRejected {
            lease_id: lease,
            epoch,
            reason: LeaseRejectReason::InsufficientCapacity,
        },
    )
    .await;
    for _ in 0..3 {
        fx.advance(19);
        let r = fx.sched.tick().await.clean();
        assert_eq!(
            (r.considered, r.placements_tried, r.offered),
            (1, 0, 0),
            "cooling: no transaction"
        );
    }
    fx.advance(3);
    let r = fx.sched.tick().await.clean();
    assert_eq!((r.placements_tried, r.offered), (1, 1), "the cooldown is over");
    let _ = job;
});

// Review P3: a tick looks at most at `MAX_JOBS_PER_TICK` queued jobs, and the next tick resumes after the last one it
// looked at (round-robin), so a long queue never stalls a tick and its tail is still reached.
mt_test!(a_long_queue_is_served_in_rounds_of_256, async {
    let fx = Fx::new().await;
    fx.node(4.0, 8192, 0).await;
    // 299 GPU jobs that no node can run, then one CPU job that fits.
    for _ in 0..(MAX_JOBS_PER_TICK + 43) {
        fx.job(1.0, 512, 1).await;
    }
    fx.advance(1);
    let last = fx.job(1.0, 512, 0).await;
    let r = fx.sched.tick().await.clean();
    assert_eq!((r.considered, r.offered), (MAX_JOBS_PER_TICK, 0), "the first round");
    let r = fx.sched.tick().await.clean();
    assert_eq!(r.considered, MAX_JOBS_PER_TICK, "the rest, then from the start again");
    assert_eq!(r.offered, 1, "the tail was reached");
    assert_eq!(fx.jobs_of(&fx.sent().leases).await, vec![last]);
});

// A queue that fits in one round is always taken from its oldest job: a job that arrives after a tick never jumps
// ahead of older ones (FIFO holds; the resume point is only for queues longer than a round).
mt_test!(a_short_queue_always_starts_from_the_oldest_job, async {
    let fx = Fx::new().await;
    let node = fx.node(1.0, 4096, 0).await;
    let busy = fx.job(1.0, 512, 0).await;
    let (_, lease, epoch) = fx.running(busy).await;
    fx.advance(1);
    let a = fx.job(1.0, 512, 0).await;
    fx.advance(1);
    let b = fx.job(1.0, 512, 0).await;
    let r = fx.sched.tick().await.clean();
    assert_eq!((r.considered, r.offered), (2, 0), "the node is full");
    fx.advance(1);
    let c = fx.job(1.0, 512, 0).await;
    fx.finish(node, lease, epoch, Outcome::Exited, Some(0)).await;
    fx.sched.tick().await.clean();
    assert_eq!(
        fx.jobs_of(&fx.sent().leases).await,
        vec![a],
        "the oldest job, not the newest"
    );
    let _ = (b, c);
});

// --- Concurrency -------------------------------------------------------------------------------------------------

mt_test!(two_schedulers_at_once_never_double_book, async {
    let fx = Fx::new().await;
    let a = fx.node(2.0, 4096, 0).await;
    let b = fx.node(3.0, 4096, 0).await;
    let mut jobs = Vec::new();
    for _ in 0..12 {
        jobs.push(fx.job(1.0, 512, 0).await);
    }
    let other = fx.another_scheduler();
    let (r1, r2) = tokio::join!(fx.sched.tick(), other.tick());
    let offered = r1.clean().offered + r2.clean().offered;
    assert_eq!(offered, 5, "2 + 3 vCPUs of 1-vCPU jobs");
    let sent = fx.sent().leases;
    assert_eq!(sent.len(), 5);
    let per_node = |n: NodeId| sent.iter().filter(|(x, _, _)| *x == n).count();
    assert_eq!((per_node(a), per_node(b)), (2, 3));
    let distinct: BTreeSet<JobId> = fx.jobs_of(&sent).await.into_iter().collect();
    assert_eq!(distinct.len(), 5, "no job got two leases");
});

// --- Estimate and node capacity ----------------------------------------------------------------------------------

mt_test!(the_estimate_counts_matching_and_free_nodes, async {
    let fx = Fx::new().await;
    let a = fx.node(2.0, 4096, 0).await;
    fx.node(1.0, 1024, 0).await;
    let spec: JobSpec = serde_json::from_value(serde_json::json!({"image": "docker.io/library/alpine:3",
        "command": ["true"], "resources": {"cpu": 2, "memory_mb": 2048}}))
    .unwrap();
    let m = fx.sched.match_spec(fx.account, &spec).await.unwrap();
    assert_eq!(
        (m.matching_nodes, m.free_nodes),
        (1, 1),
        "the small node can never run it"
    );
    let job = fx.job(2.0, 1024, 0).await;
    fx.running(job).await;
    let m = fx.sched.match_spec(fx.account, &spec).await.unwrap();
    assert_eq!((m.matching_nodes, m.free_nodes), (1, 0), "busy, but it could");
    let m = fx.sched.match_spec(AccountId::generate(), &spec).await.unwrap();
    assert_eq!(m, NodeMatch::default(), "another account sees none of these nodes");
    let _ = a;
});

// --- Offered disk and the offer cap re-armed when a lease ends (ACC-1 round 2, §8) -------------------------------

/// How many leases of `job` were ever offered.
async fn offers_of(fx: &Fx, job: JobId) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM leases WHERE job_id = ?")
        .bind(job.to_string())
        .fetch_one(&fx.db)
        .await
        .unwrap()
}

mt_test!(
    a_node_whose_free_disk_does_not_fit_is_eligible_again_when_a_lease_ends,
    async {
        let fx = Fx::new().await;
        // 24 vCPUs would take six jobs of 3.75; 40 GiB of disk takes four jobs of 10 GiB.
        let node = fx.node_disk(24.0, 65_536, 0, Some(40_960)).await;
        let mut jobs = Vec::new();
        for _ in 0..5 {
            jobs.push(fx.job_disk(3.75, 10_240).await);
        }
        fx.sched.tick().await.clean();
        let sent = fx.sent().leases;
        assert_eq!(sent.len(), 4, "disk, not CPU, is the limit");
        assert_eq!(
            fx.offer_count(jobs[4]).await,
            0,
            "the fifth was never offered, so never refused"
        );
        assert_eq!(fx.status(jobs[4]).await, JobStatus::Queued);
        // Accepted and started: still held.
        for (n, lease, epoch) in &sent {
            fx.accept(*n, *lease, *epoch).await;
            fx.start(*n, *lease, *epoch).await;
        }
        fx.advance(1);
        fx.sched.tick().await.clean();
        assert!(fx.sent().leases.is_empty(), "no free disk");
        // One lease ends: its disk is free, and the fifth job fits.
        let (n, lease, epoch) = sent[0];
        fx.finish(n, lease, epoch, Outcome::Exited, Some(0)).await;
        fx.sched.tick().await.clean();
        let next = fx.sent().leases;
        assert_eq!(next.len(), 1);
        assert_eq!((next[0].0, fx.lease(next[0].1).await.job_id), (node, jobs[4]));
    }
);

mt_test!(
    a_node_that_does_not_report_disk_is_placed_by_cpu_memory_and_gpu_only,
    async {
        let fx = Fx::new().await;
        fx.node_disk(24.0, 65_536, 0, None).await;
        for _ in 0..6 {
            fx.job_disk(3.75, 10_240).await;
        }
        fx.sched.tick().await.clean();
        assert_eq!(fx.sent().leases.len(), 6, "an older agent: six by CPU");
    }
);

mt_test!(a_lease_reserves_the_disk_of_its_job, async {
    let fx = Fx::new().await;
    let node = fx.node_disk(24.0, 65_536, 0, Some(40_960)).await;
    let job = fx.job_disk(1.0, 10_240).await;
    fx.sched.tick().await.clean();
    let (_, lease, _) = fx.sent().leases[0];
    assert_eq!(fx.lease(lease).await.reserved.disk_mb, 10_240);
    let mut conn = fx.db.acquire().await.unwrap();
    let node_row = nodes::get(&mut conn, fx.account, node).await.unwrap().unwrap();
    let held = leases::held_for_account(&mut conn, fx.account).await.unwrap();
    let mut h = fit::Held::default();
    for r in held.get(&node).into_iter().flatten() {
        h.add(r);
    }
    assert_eq!(fit::free_capacity(&node_row.inventory, &h).disk_mb, Some(30_720));
    let _ = job;
});

/// How long a fake agent takes to clean up after a job: its resources are held that long after `JobFinished`.
const CLEANUP: Duration = Duration::seconds(2);

/// A node's executor, as `p2pc-agent` has it (T06e): it refuses a lease that does not fit its CPU or its disk, and it
/// keeps a finished job's resources through its cleanup, listing the lease in `Heartbeat.running` until they are
/// released, when it heartbeats at once.
struct FakeAgent {
    node: NodeId,
    cpu: f64,
    disk_mb: u64,
    /// `(lease, epoch, cpu, disk_mb)` of the jobs that execute.
    running: Vec<(LeaseId, u64, f64, u64)>,
    /// The same, for the jobs that finished and are being cleaned up, with when their resources are released.
    cleaning: Vec<(LeaseId, u64, f64, u64, OffsetDateTime)>,
}

impl FakeAgent {
    fn new(node: NodeId, cpu: f64, disk_mb: u64) -> Self {
        Self {
            node,
            cpu,
            disk_mb,
            running: Vec::new(),
            cleaning: Vec::new(),
        }
    }

    /// Every lease that holds resources: running or being cleaned up.
    fn holding(&self) -> Vec<(LeaseId, u64)> {
        let running = self.running.iter().map(|r| (r.0, r.1));
        running.chain(self.cleaning.iter().map(|c| (c.0, c.1))).collect()
    }

    /// Answers an offer; returns whether it was refused for capacity.
    async fn offer(&mut self, fx: &Fx, lease: LeaseId, epoch: u64, cpu: f64, disk_mb: u64) -> bool {
        let used_cpu: f64 = self
            .running
            .iter()
            .map(|r| r.2)
            .chain(self.cleaning.iter().map(|c| c.2))
            .sum();
        let used_disk: u64 = self
            .running
            .iter()
            .map(|r| r.3)
            .chain(self.cleaning.iter().map(|c| c.3))
            .sum();
        if used_cpu + cpu > self.cpu + 1e-9 || used_disk + disk_mb > self.disk_mb {
            fx.msg(
                self.node,
                AgentMsg::LeaseRejected {
                    lease_id: lease,
                    epoch,
                    reason: LeaseRejectReason::InsufficientCapacity,
                },
            )
            .await;
            return true;
        }
        fx.accept(self.node, lease, epoch).await;
        fx.start(self.node, lease, epoch).await;
        self.running.push((lease, epoch, cpu, disk_mb));
        false
    }

    /// The oldest job ends: `JobFinished`, then its cleanup, which keeps its resources for [`CLEANUP`]. With
    /// `heartbeat_at_once` the agent also heartbeats right after the report, listing only the jobs that execute: to
    /// the server that is the same as having freed the lease at `JobFinished` (the behaviour before T06e).
    async fn finish_oldest(&mut self, fx: &Fx, heartbeat_at_once: bool) -> bool {
        if self.running.is_empty() {
            return false;
        }
        let (lease, epoch, cpu, disk) = self.running.remove(0);
        fx.finish_held(self.node, lease, epoch, Outcome::Exited, Some(0)).await;
        self.cleaning.push((lease, epoch, cpu, disk, fx.now() + CLEANUP));
        if heartbeat_at_once {
            let running: Vec<_> = self.running.iter().map(|r| (r.0, r.1)).collect();
            fx.heartbeat(self.node, &running).await;
        }
        true
    }

    /// Releases the resources of the cleanups that are over, and heartbeats at once if any was.
    async fn release_due(&mut self, fx: &Fx) {
        let now = fx.now();
        let before = self.cleaning.len();
        self.cleaning.retain(|c| c.4 > now);
        if self.cleaning.len() != before {
            fx.heartbeat(self.node, &self.holding()).await;
        }
    }
}

/// Two nodes with 4 slots each (by CPU and by disk) for the jobs of [`ac10_scene`].
const FOUR_EACH: [(f64, u64, u64); 2] = [(15.0, 65_536, 40_960), (15.0, 65_536, 40_960)];
/// The nodes of ACC-1 round 2: one that takes 6 jobs by CPU but 4 by disk, and a small one.
const BIG_AND_SMALL: [(f64, u64, u64); 2] = [(24.0, 65_536, 40_960), (7.5, 16_384, 20_480)];

/// The AC-10 scene: 100 jobs of 3.75 vCPUs and 10 GiB on `nodes` (`cpu, memory_mb, disk_mb` each), one job ending per
/// node per second and a cleanup of [`CLEANUP`] after each. Returns how many offers the agents refused for capacity,
/// and how many of the 100 jobs succeeded.
async fn ac10_scene(fx: &Fx, nodes: &[(f64, u64, u64)], heartbeat_at_job_finished: bool) -> (u32, usize) {
    let mut agents = Vec::new();
    for &(cpu, memory_mb, disk_mb) in nodes {
        let node = fx.node_disk(cpu, memory_mb, 0, Some(disk_mb)).await;
        agents.push(FakeAgent::new(node, cpu, disk_mb));
    }
    let mut all = Vec::new();
    for _ in 0..100 {
        all.push(fx.job_disk(3.75, 10_240).await);
    }
    let mut refused = 0;
    let mut done = 0;
    for _ in 0..400 {
        fx.sched.tick().await.clean();
        for (n, lease, epoch) in fx.sent().leases {
            let agent = agents.iter_mut().find(|a| a.node == n).unwrap();
            if agent.offer(fx, lease, epoch, 3.75, 10_240).await {
                refused += 1;
            }
        }
        for agent in &mut agents {
            agent.finish_oldest(fx, heartbeat_at_job_finished).await;
        }
        fx.advance(1);
        for agent in &mut agents {
            agent.release_due(fx).await;
        }
        done = 0;
        for j in &all {
            done += usize::from(fx.status(*j).await == JobStatus::Succeeded);
        }
        if done == 100 {
            break;
        }
    }
    (refused, done)
}

// The AC-10 scene (ACC-1 round 3): the agent keeps a finished job's resources through its cleanup, and the server
// holds the reservation until the agent's heartbeat no longer lists the lease. Nobody is refused for capacity, and
// all 100 jobs finish.
mt_test!(
    the_ac10_scene_finishes_100_jobs_without_a_single_capacity_refusal,
    async {
        for nodes in [FOUR_EACH, BIG_AND_SMALL] {
            let fx = Fx::new().await;
            let (refused, done) = ac10_scene(&fx, &nodes, false).await;
            assert_eq!(refused, 0, "no offer was refused for capacity: {nodes:?}");
            assert_eq!(done, 100, "{nodes:?}");
        }
    }
);

// The same scene against the server of before T06e, which freed the reservation at `JobFinished` while the agent still
// held it: the agents refuse offers. This proves the scene measures the race.
mt_test!(
    the_ac10_scene_with_a_server_that_frees_at_job_finished_shows_refusals,
    async {
        let fx = Fx::new().await;
        let (refused, _) = ac10_scene(&fx, &FOUR_EACH, true).await;
        assert!(
            refused > 0,
            "freeing at JobFinished makes the agents refuse for capacity"
        );
    }
);

/// Rejects the lease just offered to `node`, for capacity.
async fn refuse(fx: &Fx, node: NodeId) {
    let sent = fx.sent().leases;
    assert_eq!(sent.len(), 1, "one offer");
    assert_eq!(sent[0].0, node);
    fx.msg(
        node,
        AgentMsg::LeaseRejected {
            lease_id: sent[0].1,
            epoch: sent[0].2,
            reason: LeaseRejectReason::InsufficientCapacity,
        },
    )
    .await;
}

// §8 "Offer cap": a job at the cap gets offers again within the 60 s rule once a lease ends, and its `reason` says
// that the nodes refused it for capacity until then.
mt_test!(a_job_at_the_cap_is_offered_again_after_a_lease_ends, async {
    let fx = Fx::new().await;
    let a = fx.node(4.0, 8192, 0).await;
    let b = fx.node(4.0, 8192, 0).await;
    // `filler` takes all of B; `job` (pinned to A, which refuses everything) reaches the cap.
    let filler = fx
        .job_with(serde_json::json!({
        "image": "docker.io/library/python:3.12-slim", "command": ["true"],
        "resources": {"cpu": 4.0, "memory_mb": 1024, "gpu": 0},
        "placement": {"node_id": b.to_string()}, "timeout_s": 86400}))
        .await;
    let (_, filler_lease, filler_epoch) = fx.running(filler).await;
    let job = fx
        .job_with(serde_json::json!({
        "image": "docker.io/library/python:3.12-slim", "command": ["true"],
        "resources": {"cpu": 1.0, "memory_mb": 512, "gpu": 0}, "timeout_s": 100}))
        .await;
    for i in 1..=OFFER_CAP {
        fx.sched.tick().await.clean();
        refuse(&fx, a).await;
        assert_eq!(fx.offer_count(job).await, i64::from(i));
        fx.advance(61);
    }
    // B has the filler (4 of 4 vCPUs), so the job was offered only to A. At the cap: no more offers.
    let row = fx.row(job).await;
    assert_eq!(
        row.reason.as_deref(),
        Some("no node accepted the job: the nodes refused it for capacity (insufficient_capacity)")
    );
    fx.sched.tick().await.clean();
    assert!(fx.sent().leases.is_empty(), "capped: no eleventh offer");
    // The filler ends. Its capacity is back, the cap is re-armed and the reason gone.
    fx.finish(b, filler_lease, filler_epoch, Outcome::Exited, Some(0)).await;
    assert_eq!(fx.status(filler).await, JobStatus::Succeeded);
    assert_eq!(fx.offer_count(job).await, 0);
    assert_eq!(fx.row(job).await.reason, None);
    fx.sched.tick().await.clean();
    let again = fx.sent().leases;
    assert_eq!(again.len(), 1, "offered again");
    assert_eq!(fx.lease(again[0].1).await.job_id, job);
});

// The re-arm does not touch the 60 s rule of a (job, node) pair: however many leases end, a refusing node is offered
// the job at most once per 60 s.
mt_test!(the_re_arm_cannot_become_an_offer_storm, async {
    let fx = Fx::new().await;
    let a = fx.node(4.0, 8192, 0).await;
    let m = fx.node(4.0, 8192, 0).await;
    let pinned = |node: NodeId, cpu: f64| {
        serde_json::json!({
            "image": "docker.io/library/python:3.12-slim", "command": ["true"],
            "resources": {"cpu": cpu, "memory_mb": 512, "gpu": 0},
            "placement": {"node_id": node.to_string()}, "timeout_s": 100})
    };
    let job = fx.job_with(pinned(a, 1.0)).await;
    let mut offered_at = Vec::new();
    // 300 s, one filler job per second on M (each one a lease that ends, hence a re-arm).
    for _ in 0..300 {
        let filler = fx.job_with(pinned(m, 1.0)).await;
        fx.sched.tick().await.clean();
        for (n, lease, epoch) in fx.sent().leases {
            if n == a {
                assert_eq!(fx.lease(lease).await.job_id, job);
                offered_at.push(fx.now());
                fx.msg(
                    a,
                    AgentMsg::LeaseRejected {
                        lease_id: lease,
                        epoch,
                        reason: LeaseRejectReason::InsufficientCapacity,
                    },
                )
                .await;
            } else {
                fx.accept(n, lease, epoch).await;
                fx.start(n, lease, epoch).await;
                fx.finish(n, lease, epoch, Outcome::Exited, Some(0)).await;
            }
        }
        assert_eq!(fx.status(filler).await, JobStatus::Succeeded);
        fx.advance(1);
    }
    assert!(offered_at.len() >= 2, "it is offered again: {offered_at:?}");
    for w in offered_at.windows(2) {
        assert!(
            w[1] - w[0] >= OFFER_COOLDOWN,
            "offers {} and {} are less than 60 s apart",
            w[0],
            w[1]
        );
    }
    assert_eq!(offers_of(&fx, job).await, i64::try_from(offered_at.len()).unwrap());
    assert!(
        offered_at.len() <= 6,
        "300 s allow at most 5 or 6 offers: {offered_at:?}"
    );
});

// A refused offer is a lease that ends too, but it held nothing: it must not reset the cap, or a job would never
// reach it.
mt_test!(a_refused_offer_does_not_re_arm_the_cap, async {
    let fx = Fx::new().await;
    let a = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    for i in 1..=OFFER_CAP {
        fx.sched.tick().await.clean();
        refuse(&fx, a).await;
        assert_eq!(fx.offer_count(job).await, i64::from(i));
        fx.advance(61);
    }
    assert_eq!(fx.offer_count(job).await, i64::from(OFFER_CAP));
});

// A lease that ends on a draining node frees nothing an offer can use (§8 "an eligible node"): the cap is not
// re-armed. The node's resume does it (`node_changed`).
mt_test!(a_lease_ending_on_a_draining_node_does_not_re_arm_the_cap, async {
    let fx = Fx::new().await;
    let a = fx.node(4.0, 8192, 0).await;
    let job = fx.job(4.0, 1024, 0).await;
    let (n, lease, epoch) = fx.running(job).await;
    assert_eq!(n, a);
    let parked = fx.job(1.0, 1024, 0).await;
    park_at_cap(&fx, parked).await;
    let mut conn = fx.db.acquire().await.unwrap();
    nodes::set_draining(&mut conn, fx.account, a, true).await.unwrap();
    drop(conn);
    fx.finish(a, lease, epoch, Outcome::Exited, Some(0)).await;
    assert_eq!(fx.status(job).await, JobStatus::Succeeded);
    assert_eq!(
        fx.offer_count(parked).await,
        i64::from(OFFER_CAP),
        "a draining node's freed capacity is not offerable: no re-arm"
    );
});

// A lease lost because its node went offline frees nothing offerable either: the node's return re-arms the cap
// (`node_changed`, from the session), so the lost lease does not.
mt_test!(a_lost_lease_on_an_offline_node_does_not_re_arm_the_cap, async {
    let fx = Fx::new().await;
    let a = fx.node(4.0, 8192, 0).await;
    let victim = fx.job(4.0, 1024, 0).await;
    let (n, lease, epoch) = fx.running(victim).await;
    assert_eq!(n, a);
    // A job parked at the cap by hand (an agent that refused it ten times).
    let parked = fx.job(1.0, 1024, 0).await;
    sqlx::query("UPDATE jobs SET offer_count = ?, reason = 'no node accepted the job: x' WHERE job_id = ?")
        .bind(i64::from(OFFER_CAP))
        .bind(parked.to_string())
        .execute(&fx.db)
        .await
        .unwrap();
    // The node goes silent for `lease_ttl_s`: its lease is lost and the job requeued.
    fx.advance(70);
    fx.node_went_offline(a, T0).await;
    assert_eq!(fx.status(victim).await, JobStatus::Queued, "requeued by node loss");
    assert_eq!(
        fx.offer_count(parked).await,
        i64::from(OFFER_CAP),
        "an offline node's lost lease does not re-arm the cap"
    );
    let _ = (lease, epoch);
});

/// Parks `job` at the offer cap by hand (an agent that refused it ten times).
async fn park_at_cap(fx: &Fx, job: JobId) {
    sqlx::query("UPDATE jobs SET offer_count = ?, reason = 'no node accepted the job: x' WHERE job_id = ?")
        .bind(i64::from(OFFER_CAP))
        .bind(job.to_string())
        .execute(&fx.db)
        .await
        .unwrap();
}

// A job the watchdog ends re-arms the cap, and so does the node's later report that the execution is gone.
mt_test!(
    the_watchdog_and_the_confirmation_of_a_dead_execution_re_arm_the_cap,
    async {
        let fx = Fx::new().await;
        fx.node(4.0, 8192, 0).await;
        let victim = fx.job(4.0, 1024, 0).await;
        let (n, lease, epoch) = fx.running(victim).await;
        let parked = fx.job(1.0, 1024, 0).await;
        park_at_cap(&fx, parked).await;
        // `timeout_s` (100) plus the margin (60): the server ends the job; the execution may still run.
        fx.advance(161);
        fx.link.take();
        fx.sched.tick().await.clean();
        assert_eq!(fx.status(victim).await, JobStatus::TimedOut);
        assert!(
            fx.lease(lease).await.holds(),
            "the reservation is held until it is confirmed dead"
        );
        assert_eq!(
            fx.offer_count(parked).await,
            0,
            "a lease the server ended re-arms the cap"
        );
        // Parked again; the node reports the execution is gone: its capacity is back.
        park_at_cap(&fx, parked).await;
        fx.finish(n, lease, epoch, Outcome::Exited, Some(0)).await;
        assert!(!fx.lease(lease).await.holds());
        assert_eq!(
            fx.offer_count(parked).await,
            0,
            "a confirmed-dead execution re-arms the cap"
        );
        assert_eq!(fx.row(parked).await.reason, None);
    }
);

// --- §8 "Reservations are held until confirmed": a finished attempt keeps its reservation (T06e) -----------------------

fn assert_cpu(got: f64, want: f64) {
    assert!((got - want).abs() < 1e-9, "free vCPUs: {got}, want {want}");
}

// The capacity of a finished lease is not free until the node's Heartbeat no longer lists it.
mt_test!(
    a_finished_leases_capacity_is_not_free_until_a_heartbeat_without_it_arrives,
    async {
        let fx = Fx::new().await;
        let node = fx.node(4.0, 8192, 0).await;
        let job = fx.job(4.0, 1024, 0).await;
        let (_, lease, epoch) = fx.running(job).await;
        assert_cpu(fx.free_cpu(node).await, 0.0);
        fx.finish_held(node, lease, epoch, Outcome::Exited, Some(0)).await;
        assert_eq!(fx.status(job).await, JobStatus::Succeeded);
        assert!(fx.lease(lease).await.holds(), "the node has not freed it yet");
        assert_cpu(fx.free_cpu(node).await, 0.0);
        // Nothing is offered to a node that has no room.
        let next = fx.job(1.0, 512, 0).await;
        fx.sched.tick().await.clean();
        assert!(fx.sent().leases.is_empty(), "no offer for a slot the node still holds");
        // A heartbeat that still lists it changes nothing.
        fx.heartbeat(node, &[(lease, epoch)]).await;
        assert_cpu(fx.free_cpu(node).await, 0.0);
        // The first heartbeat without it frees it.
        fx.heartbeat(node, &[]).await;
        assert!(!fx.lease(lease).await.holds());
        assert_cpu(fx.free_cpu(node).await, 4.0);
        fx.sched.tick().await.clean();
        let offered = fx.sent().leases;
        assert_eq!(offered.len(), 1, "the slot is offered again");
        assert_eq!(fx.lease(offered[0].1).await.job_id, next);
    }
);

// The offer cap is re-armed when the node frees the lease, once, and not before.
mt_test!(
    the_offer_cap_is_re_armed_once_when_the_node_frees_a_finished_lease,
    async {
        let fx = Fx::new().await;
        let a = fx.node(4.0, 8192, 0).await;
        let b = fx.node(4.0, 8192, 0).await;
        let filler = fx
            .job_with(serde_json::json!({
        "image": "docker.io/library/python:3.12-slim", "command": ["true"],
        "resources": {"cpu": 4.0, "memory_mb": 1024, "gpu": 0},
        "placement": {"node_id": b.to_string()}, "timeout_s": 86400}))
            .await;
        let (_, filler_lease, filler_epoch) = fx.running(filler).await;
        let job = fx
            .job_with(serde_json::json!({
        "image": "docker.io/library/python:3.12-slim", "command": ["true"],
        "resources": {"cpu": 1.0, "memory_mb": 512, "gpu": 0}, "timeout_s": 100}))
            .await;
        for _ in 1..=OFFER_CAP {
            fx.sched.tick().await.clean();
            refuse(&fx, a).await;
            fx.advance(61);
        }
        assert_eq!(fx.offer_count(job).await, i64::from(OFFER_CAP));
        let reason = fx.row(job).await.reason;
        assert!(reason.is_some(), "held at the offer cap");
        // The filler finishes, but its node still holds the slot: the cap stays.
        fx.finish_held(b, filler_lease, filler_epoch, Outcome::Exited, Some(0))
            .await;
        assert_eq!(fx.status(filler).await, JobStatus::Succeeded);
        assert_eq!(fx.offer_count(job).await, i64::from(OFFER_CAP));
        assert_eq!(fx.row(job).await.reason, reason);
        fx.heartbeat(b, &[(filler_lease, filler_epoch)]).await;
        assert_eq!(
            fx.offer_count(job).await,
            i64::from(OFFER_CAP),
            "still listed: nothing changes"
        );
        // The node frees it: the cap is re-armed and the job is offered again.
        fx.heartbeat(b, &[]).await;
        assert_eq!(fx.offer_count(job).await, 0);
        assert_eq!(fx.row(job).await.reason, None);
        fx.sched.tick().await.clean();
        let again = fx.sent().leases;
        assert_eq!(again.len(), 1, "offered again");
        // Once: the next heartbeat without the lease re-arms nothing.
        fx.msg(
            again[0].0,
            AgentMsg::LeaseRejected {
                lease_id: again[0].1,
                epoch: again[0].2,
                reason: LeaseRejectReason::InsufficientCapacity,
            },
        )
        .await;
        assert_eq!(fx.offer_count(job).await, 1);
        fx.heartbeat(b, &[]).await;
        assert_eq!(
            fx.offer_count(job).await,
            1,
            "the lease was already freed: no second re-arm"
        );
    }
);

// A finished lease that is still listed is normal: nothing changes, nothing is sent to the node.
mt_test!(a_heartbeat_that_still_lists_a_finished_lease_changes_nothing, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(2.0, 1024, 0).await;
    let (_, lease, epoch) = fx.running(job).await;
    fx.finish_held(node, lease, epoch, Outcome::Exited, Some(0)).await;
    fx.sent();
    let (lease_before, row_before) = (fx.lease(lease).await, fx.row(job).await);
    for _ in 0..3 {
        fx.heartbeat(node, &[(lease, epoch)]).await;
    }
    assert_eq!(fx.lease(lease).await, lease_before);
    let row = fx.row(job).await;
    assert_eq!(
        (row.status, row.attempt, row.reason),
        (JobStatus::Succeeded, row_before.attempt, None)
    );
    let sent = fx.sent();
    assert!(
        sent.cancels.is_empty() && sent.others.is_empty(),
        "nothing is told to the node: {sent:?}"
    );
});

// An older agent (no immediate heartbeat; `running` lists only the jobs that execute) frees its slot at its next
// heartbeat after `JobFinished`.
mt_test!(an_old_style_agent_frees_a_finished_lease_at_its_next_heartbeat, async {
    let fx = Fx::new().await;
    let node = fx.node(8.0, 16384, 0).await;
    let first = fx.job(4.0, 1024, 0).await;
    let (_, done_lease, done_epoch) = fx.running(first).await;
    let second = fx.job(4.0, 1024, 0).await;
    let (_, live_lease, live_epoch) = fx.running(second).await;
    fx.finish_held(node, done_lease, done_epoch, Outcome::Exited, Some(0))
        .await;
    assert_cpu(fx.free_cpu(node).await, 0.0);
    // Its next heartbeat lists only the job that still executes.
    fx.heartbeat(node, &[(live_lease, live_epoch)]).await;
    assert!(!fx.lease(done_lease).await.holds());
    assert!(fx.lease(live_lease).await.holds(), "a running lease is untouched");
    assert_eq!(fx.status(second).await, JobStatus::Running);
    assert_cpu(fx.free_cpu(node).await, 4.0);
});

// A heartbeat never frees a lease that is not finished, even when it does not list it: only node loss, `Hello` and
// `lease_ttl_s` end a running lease.
mt_test!(a_heartbeat_without_a_running_lease_does_not_end_it, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(1.0, 1024, 0).await;
    let (_, lease, _) = fx.running(job).await;
    fx.heartbeat(node, &[]).await;
    assert_eq!(fx.status(job).await, JobStatus::Running);
    assert!(fx.lease(lease).await.holds());
});

// A heartbeat of another node never frees this node's lease (the lease is looked up by the heartbeat's node).
mt_test!(a_heartbeat_frees_only_the_leases_of_its_own_node, async {
    let fx = Fx::new().await;
    let a = fx.node(4.0, 8192, 0).await;
    let b = fx.node(4.0, 8192, 0).await;
    let job = fx
        .job_with(serde_json::json!({
        "image": "docker.io/library/python:3.12-slim", "command": ["true"],
        "resources": {"cpu": 1.0, "memory_mb": 512, "gpu": 0},
        "placement": {"node_id": a.to_string()}, "timeout_s": 100}))
        .await;
    let (_, lease, epoch) = fx.running(job).await;
    fx.finish_held(a, lease, epoch, Outcome::Exited, Some(0)).await;
    fx.heartbeat(b, &[]).await;
    assert!(fx.lease(lease).await.holds());
    fx.heartbeat(a, &[]).await;
    assert!(!fx.lease(lease).await.holds());
});

// Node loss: a node that goes silent while it holds a finished lease frees it as the confirmed-dead rules say
// (`lease_ttl_s` of silence), and the job stays succeeded.
mt_test!(a_silent_node_frees_its_finished_leases_after_the_ttl, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(4.0, 1024, 0).await;
    let (_, lease, epoch) = fx.running(job).await;
    fx.finish_held(node, lease, epoch, Outcome::Exited, Some(0)).await;
    let last = fx.now();
    fx.link.disconnect(node);
    fx.advance(59);
    fx.sched.tick().await.clean();
    assert!(fx.lease(lease).await.holds(), "the TTL has not run");
    fx.advance(1);
    fx.node_went_offline(node, last).await;
    let l = fx.lease(lease).await;
    assert!(!l.holds());
    assert_eq!(l.confirmed_dead_at, Some(last + TTL));
    assert_eq!(
        fx.status(job).await,
        JobStatus::Succeeded,
        "a finished job is never requeued"
    );
});

// A reconnect: a `Hello` that does not list a finished lease frees it (the agent restarted, or finished its cleanup);
// one that lists it (the report is not confirmed, or the lease is in cleanup) leaves it held and is told the lease is
// no longer current, which does not change the job.
mt_test!(a_hello_decides_a_finished_lease_by_listing_it, async {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(4.0, 1024, 0).await;
    let (_, lease, epoch) = fx.running(job).await;
    fx.finish_held(node, lease, epoch, Outcome::Exited, Some(0)).await;
    fx.link.disconnect(node);
    let replies = fx.hello(node, &[(lease, epoch)]).await;
    assert!(
        fx.lease(lease).await.holds(),
        "listed: still held until a heartbeat frees it"
    );
    assert_eq!(fx.status(job).await, JobStatus::Succeeded);
    assert!(
        replies
            .iter()
            .all(|m| matches!(m, ServerMsg::Cancel { reason, .. } if reason == "stale_epoch")),
        "{replies:?}"
    );
    fx.link.disconnect(node);
    fx.hello(node, &[]).await;
    assert!(
        !fx.lease(lease).await.holds(),
        "absent from a fresh Hello: confirmed dead"
    );
    assert_eq!(fx.status(job).await, JobStatus::Succeeded);
});

/// Logs of a block, at the level `INFO` and above, as text.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// Seeing a finished lease in `running` is never an error: it is logged at `debug` at most (so, nothing at `info` or
// above). The subscriber is the test thread's own, so this test runs on one thread.
#[tokio::test]
async fn a_finished_lease_in_a_heartbeat_is_not_logged_above_debug() {
    let fx = Fx::new().await;
    let node = fx.node(4.0, 8192, 0).await;
    let job = fx.job(4.0, 1024, 0).await;
    let (_, lease, epoch) = fx.running(job).await;
    fx.finish_held(node, lease, epoch, Outcome::Exited, Some(0)).await;
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    fx.heartbeat(node, &[(lease, epoch)]).await;
    fx.heartbeat(node, &[(lease, epoch)]).await;
    drop(guard);
    let logged = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert_eq!(logged, "", "nothing at info or above for a listed finished lease");
}

// The T06e migration rebuilds `leases` so that a finished lease can hold its reservation. It loses no row and no
// reference, keeps the rule for active leases, and lets a `finished` lease have no `confirmed_dead_at`.
mt_test!(
    the_finished_lease_migration_keeps_every_lease_and_its_references,
    async {
        let dir = tempfile::tempdir().unwrap();
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("t.db"))
            .create_if_missing(true)
            .foreign_keys(true);
        // One connection, so the migration's pragma and its transaction share it.
        let db = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        // The migration under test runs last, on a database that has every other migration: the fixture code is
        // today's, so it needs today's tables (the H2 rebuild of `jobs` and `usage_records` among them), and no
        // later migration changes `leases` itself.
        let last = crate::store::MIGRATOR
            .migrations
            .iter()
            .find(|m| m.description.contains("finished lease holds"))
            .unwrap();
        let before = crate::store::MIGRATOR
            .migrations
            .iter()
            .filter(|m| m.version != last.version);
        for m in before {
            sqlx::raw_sql(m.sql.clone()).execute(&db).await.unwrap();
        }
        let fx = Fx::on(dir, db.clone()).await;
        // Before: one finished lease (the old rule: confirmed when it finished), one lost lease with a usage row, and one
        // offer still open.
        let a = fx.node(4.0, 8192, 0).await;
        let b = fx.node(4.0, 8192, 0).await;
        let pinned = |node: NodeId| {
            serde_json::json!({
            "image": "docker.io/library/python:3.12-slim", "command": ["true"],
            "resources": {"cpu": 1.0, "memory_mb": 512, "gpu": 0},
            "placement": {"node_id": node.to_string()}, "timeout_s": 100})
        };
        let done = fx.job_with(pinned(a)).await;
        let (_, done_lease, _) = fx.running(done).await;
        sqlx::query("UPDATE leases SET state = 'finished', ended_at = 1, confirmed_dead_at = 1 WHERE id = ?")
            .bind(done_lease.to_string())
            .execute(&db)
            .await
            .unwrap();
        let lost = fx.job_with(pinned(b)).await;
        let (_, lost_lease, _) = fx.running(lost).await;
        let last_contact = fx.now();
        fx.advance(60);
        fx.node_went_offline(b, last_contact).await;
        assert_eq!(fx.lease(lost_lease).await.state, LeaseState::Lost);
        let waiting = fx.job_with(pinned(a)).await;
        fx.sched.tick().await.clean();
        let (open_lease,): (String,) = sqlx::query_as("SELECT id FROM leases WHERE job_id = ?")
            .bind(waiting.to_string())
            .fetch_one(&db)
            .await
            .unwrap();
        let snapshot = || async {
            /// `id, state, epoch, confirmed_dead_at, gpu_uuid`.
            type Row = (String, String, i64, Option<i64>, Option<String>);
            let rows: Vec<Row> =
                sqlx::query_as("SELECT id, state, epoch, confirmed_dead_at, gpu_uuid FROM leases ORDER BY id")
                    .fetch_all(&db)
                    .await
                    .unwrap();
            let children: (i64, i64) =
                sqlx::query_as("SELECT (SELECT COUNT(*) FROM job_attempts), (SELECT COUNT(*) FROM usage_records)")
                    .fetch_one(&db)
                    .await
                    .unwrap();
            (rows, children)
        };
        let (rows_before, children_before) = snapshot().await;
        assert_eq!(rows_before.len(), 3);
        assert!(
            children_before.0 >= 2 && children_before.1 >= 1,
            "the fixture has children: {children_before:?}"
        );

        // The migration, as sqlx runs it: in one transaction.
        let mut tx = db.begin().await.unwrap();
        sqlx::raw_sql(last.sql.clone()).execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();

        assert_eq!(
            snapshot().await,
            (rows_before, children_before),
            "no lease and no reference is lost"
        );
        let violations: Vec<(String, i64, String, i64)> =
            sqlx::query_as("PRAGMA foreign_key_check").fetch_all(&db).await.unwrap();
        assert!(violations.is_empty(), "{violations:?}");
        // Both indexes that the rule of a held reservation depends on exist again.
        let indexes: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'leases' ORDER BY name",
        )
        .fetch_all(&db)
        .await
        .unwrap();
        for name in [
            "leases_node_held",
            "leases_one_active_per_job",
            "leases_one_holder_per_gpu",
            "leases_state",
        ] {
            assert!(indexes.iter().any(|i| i == name), "{name} in {indexes:?}");
        }
        // The new rule: a finished lease may hold its reservation; an active one still always does.
        sqlx::query("UPDATE leases SET confirmed_dead_at = NULL WHERE id = ?")
            .bind(done_lease.to_string())
            .execute(&db)
            .await
            .unwrap();
        assert!(fx.lease(done_lease).await.holds());
        let refused = sqlx::query("UPDATE leases SET confirmed_dead_at = 1 WHERE id = ?")
            .bind(open_lease)
            .execute(&db)
            .await;
        assert!(refused.is_err(), "an active lease cannot be confirmed dead");
    }
);
