// SPDX-License-Identifier: Apache-2.0

//! Unit tests of the executor, with a scripted fake [`Sandbox`] and a fake connection: the session's outbox is a
//! channel, and its upload streams are in-memory pipes to a fake upload server. One journal records, in order, what
//! the sandbox did, what the upload server stored and what reached the outbox, so the tests can check the order of
//! the phases and the messages. Time is tokio's paused clock: no real sleep anywhere.

use std::collections::HashMap;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use p2pc_proto::api::{JobSpec, LogStream, SmokeResult};
use p2pc_proto::ids::{AccountId, LeaseId};
use p2pc_proto::protocol::{
    AgentMsg, LeaseRejectReason, MAX_FRAME_LEN, Outcome, RunningLease, UploadAck, UploadHeader, Usage, read_frame,
    upload_reason, write_frame,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, DuplexStream};
use tokio::sync::{mpsc, watch};

use super::capacity::Offer;
use super::status::{LeasesFile, RunPhase};
use super::*;
use crate::connection::transport::{BoxRead, BoxWrite, ConnectError, StreamOpener};
use crate::connection::uplink::JobFrame;
use crate::connection::watchdog::Watchdog;
use crate::connection::{BoxFuture, LeaseDecision, LeaseHandler, LeaseOffer, LeaseSupervisor, Port, Uplink};
use crate::sandbox::cgroup::CgroupStats;
use crate::sandbox::logs::{LogChunk, LogSummary};
use crate::sandbox::{CancelHandle, CollectedOutputs, Finished, LeaseContext, Sandbox, SandboxError, SandboxEvent};

type Journal = Arc<Mutex<Vec<String>>>;
/// Every upload attempt the fake server saw: `(path, bytes)`.
type Uploads = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

fn note(journal: &Journal, line: impl Into<String>) {
    journal.lock().unwrap().push(line.into());
}

// ---------------------------------------------------------------------------------------------------------------
// The fake sandbox.

/// What one lease does in the fake sandbox.
#[derive(Debug, Clone, Default)]
struct Script {
    /// `prepare` waits for the cancel, then ends `Cancelled`.
    hang_in_prepare: bool,
    /// `prepare` fails so.
    prepare_error: Option<SandboxError>,
    /// What the job prints, in order.
    logs: Vec<(LogStream, Vec<u8>)>,
    /// `wait` waits for the cancel, then ends as `cancelled`.
    hang_in_wait: bool,
    /// The exit code otherwise.
    exit_code: i32,
    /// Files the job leaves in `outputs/`.
    outputs: Vec<(&'static str, Vec<u8>)>,
    /// Symlinks it leaves there, `(name, target)`.
    links: Vec<(&'static str, PathBuf)>,
    /// `cleanup` waits for a permit on it (the container removal and the directory deletion take a while).
    cleanup_gate: Option<Arc<tokio::sync::Notify>>,
    /// Events `start` sends after the logs (a service's health changes and usage samples).
    events: Vec<SandboxEvent>,
}

#[derive(Debug)]
struct FakeState {
    scripts: Mutex<HashMap<LeaseKey, Script>>,
    default: Mutex<Script>,
    journal: Journal,
    root: tempfile::TempDir,
}

#[derive(Debug, Clone)]
struct FakeSandbox(Arc<FakeState>);

impl FakeSandbox {
    fn new(journal: Journal) -> Self {
        Self(Arc::new(FakeState {
            scripts: Mutex::new(HashMap::new()),
            default: Mutex::new(Script::default()),
            journal,
            root: tempfile::tempdir().unwrap(),
        }))
    }

    fn script(&self, key: LeaseKey, script: Script) {
        self.0.scripts.lock().unwrap().insert(key, script);
    }

    fn set_default(&self, script: Script) {
        *self.0.default.lock().unwrap() = script;
    }

    fn note(&self, line: impl Into<String>) {
        note(&self.0.journal, line);
    }
}

#[derive(Debug)]
struct FakeJob {
    key: LeaseKey,
    events: mpsc::Sender<SandboxEvent>,
    cancel: CancelHandle,
    outputs: PathBuf,
    script: Script,
}

fn finished(outcome: Outcome, exit_code: Option<i32>) -> Finished {
    Finished {
        outcome,
        exit_code,
        error: None,
        usage: Usage {
            wall_ms: 1500,
            cpu_used_ms: 700,
            max_rss_mb: 42,
        },
        stats: CgroupStats::default(),
        logs: LogSummary::default(),
    }
}

impl Sandbox for FakeSandbox {
    type Job = FakeJob;

    async fn prepare(
        &self,
        enrolled: &AccountId,
        lease: LeaseContext,
        events: mpsc::Sender<SandboxEvent>,
        cancel: CancelHandle,
    ) -> Result<FakeJob, SandboxError> {
        let key = (lease.lease_id, lease.epoch);
        self.note(format!("prepare {}", key.1));
        if lease.account_id != *enrolled {
            return Err(SandboxError::Rejected(LeaseRejectReason::NotOwner));
        }
        let script = self
            .0
            .scripts
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .unwrap_or_else(|| self.0.default.lock().unwrap().clone());
        let _ = events.send(SandboxEvent::Phase(Phase::Pulling)).await;
        if script.hang_in_prepare {
            cancel.cancelled().await;
            return Err(SandboxError::Cancelled);
        }
        if let Some(e) = script.prepare_error.clone() {
            return Err(e);
        }
        let outputs = self.0.root.path().join(format!("{}-{}", key.0, key.1)).join("outputs");
        std::fs::create_dir_all(&outputs).unwrap();
        Ok(FakeJob {
            key,
            events,
            cancel,
            outputs,
            script,
        })
    }

    async fn start(&self, job: &mut FakeJob) -> Result<(), SandboxError> {
        self.note(format!("start {}", job.key.1));
        let _ = job.events.send(SandboxEvent::Started).await;
        for (seq, (stream, data)) in job.script.logs.iter().enumerate() {
            let chunk = LogChunk {
                stream: *stream,
                seq: seq as u64,
                data: data.clone(),
                marker: false,
            };
            let _ = job.events.send(SandboxEvent::Log(chunk)).await;
        }
        for event in &job.script.events {
            let _ = job.events.send(event.clone()).await;
        }
        Ok(())
    }

    async fn wait(&self, job: &mut FakeJob) -> Result<Finished, SandboxError> {
        if job.script.hang_in_wait {
            job.cancel.cancelled().await;
            self.note(format!("wait {} cancelled", job.key.1));
            return Ok(finished(Outcome::Cancelled, None));
        }
        self.note(format!("wait {} exited", job.key.1));
        Ok(finished(Outcome::Exited, Some(job.script.exit_code)))
    }

    async fn collect_outputs(&self, job: &FakeJob) -> Result<CollectedOutputs, SandboxError> {
        self.note(format!("collect {}", job.key.1));
        for (name, content) in &job.script.outputs {
            std::fs::write(job.outputs.join(name), content).unwrap();
        }
        for (name, target) in &job.script.links {
            symlink(target, job.outputs.join(name)).unwrap();
        }
        // The real SI-9 walk.
        Ok(crate::sandbox::outputs::collect(&job.outputs, u64::MAX).unwrap())
    }

    async fn cleanup(&self, job: FakeJob) {
        self.note(format!("cleanup {}", job.key.1));
        if let Some(gate) = &job.script.cleanup_gate {
            gate.notified().await;
        }
        let _ = std::fs::remove_dir_all(job.outputs.parent().unwrap());
    }

    async fn smoke(&self) -> SmokeResult {
        SmokeResult { ok: true, detail: None }
    }
}

impl Startup for FakeSandbox {
    async fn sweep_at_start(&self) -> SweepReport {
        self.note("sweep");
        SweepReport {
            job_dirs: vec!["left-by-the-last-process".into()],
            ..SweepReport::default()
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The fake connection.

/// How the fake upload server answers one upload attempt.
#[derive(Debug, Clone)]
enum Answer {
    Ok,
    Refuse(&'static str),
    /// Closes the stream without an ack: a transport error.
    Drop,
    /// Waits for the release before acking.
    Hold(Arc<tokio::sync::Notify>),
}

type Policy = Arc<dyn Fn(&str, usize) -> Answer + Send + Sync>;

#[derive(Debug)]
struct PipeStreams(mpsc::UnboundedSender<DuplexStream>);

impl StreamOpener for PipeStreams {
    fn open_bi(&self) -> BoxFuture<'_, Result<(BoxWrite, BoxRead), ConnectError>> {
        Box::pin(async move {
            let (agent, server) = tokio::io::duplex(1 << 20);
            self.0
                .send(server)
                .map_err(|_| ConnectError("the fake server is gone".into()))?;
            let (r, w) = tokio::io::split(agent);
            Ok((Box::new(w) as BoxWrite, Box::new(r) as BoxRead))
        })
    }
}

/// One fake session: its outbox (forwarded into the journal and a channel) and its upload server.
struct Session {
    /// Holds the session's outbox open (the port only has a weak handle on it).
    _outbox: mpsc::Sender<JobFrame>,
    msgs: mpsc::UnboundedReceiver<AgentMsg>,
    number: u64,
    /// Every upload attempt: `(path, bytes)`.
    uploads: Uploads,
    /// The confirmations of the reports written, when the session does not confirm them by itself.
    unconfirmed: Arc<Mutex<Vec<watch::Sender<bool>>>>,
}

fn kind(m: &AgentMsg) -> String {
    match m {
        AgentMsg::LogChunk { seq, epoch, .. } => format!("log {epoch} {seq}"),
        AgentMsg::JobStarted { epoch, .. } => format!("job_started {epoch}"),
        AgentMsg::JobFinished { epoch, .. } => format!("job_finished {epoch}"),
        other => other.kind().to_string(),
    }
}

fn connect(uplink: &Uplink, journal: &Journal, policy: Policy) -> Session {
    connect_with(uplink, journal, policy, true)
}

/// A session that never answers a heartbeat by itself: a report stays unconfirmed until [`Session::confirm_reports`].
fn connect_unconfirmed(uplink: &Uplink, journal: &Journal, policy: Policy) -> Session {
    connect_with(uplink, journal, policy, false)
}

fn connect_with(uplink: &Uplink, journal: &Journal, policy: Policy, auto_confirm: bool) -> Session {
    let (tx, mut rx) = mpsc::channel::<JobFrame>(1024);
    let (fwd_tx, msgs) = mpsc::unbounded_channel();
    let unconfirmed: Arc<Mutex<Vec<watch::Sender<bool>>>> = Arc::default();
    {
        let (journal, unconfirmed) = (journal.clone(), unconfirmed.clone());
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                // Written at once; a report is confirmed at once, as if the next heartbeat had been answered
                // (unless the test confirms it).
                let Some(m) = frame.msg().cloned() else { continue };
                if let Some(confirm) = frame.written() {
                    if auto_confirm {
                        confirm.send_replace(true);
                    } else {
                        unconfirmed.lock().unwrap().push(confirm);
                    }
                }
                note(&journal, format!("msg {}", kind(&m)));
                let _ = fwd_tx.send(m);
            }
        });
    }
    let (streams_tx, mut streams) = mpsc::unbounded_channel::<DuplexStream>();
    let uploads: Uploads = Arc::default();
    {
        let (journal, uploads) = (journal.clone(), uploads.clone());
        tokio::spawn(async move {
            while let Some(stream) = streams.recv().await {
                let (journal, uploads, policy) = (journal.clone(), uploads.clone(), policy.clone());
                tokio::spawn(async move {
                    let (mut r, mut w) = tokio::io::split(stream);
                    let header: UploadHeader = read_frame(&mut r, MAX_FRAME_LEN).await.unwrap().unwrap();
                    let mut body = vec![0u8; usize::try_from(header.size).unwrap()];
                    r.read_exact(&mut body).await.unwrap();
                    assert_eq!(
                        r.read(&mut [0u8; 1]).await.unwrap(),
                        0,
                        "exactly `size` bytes, then the end"
                    );
                    let attempt = {
                        let mut u = uploads.lock().unwrap();
                        u.push((header.path.clone(), body.clone()));
                        u.iter().filter(|(p, _)| *p == header.path).count()
                    };
                    assert_eq!(
                        header.sha256.0,
                        <[u8; 32]>::from(Sha256::digest(&body)),
                        "the header's sha256 is the bytes'"
                    );
                    let ack = match policy(&header.path, attempt) {
                        Answer::Drop => return,
                        Answer::Ok => UploadAck { ok: true, reason: None },
                        Answer::Refuse(reason) => UploadAck {
                            ok: false,
                            reason: Some(reason.into()),
                        },
                        Answer::Hold(release) => {
                            release.notified().await;
                            UploadAck { ok: true, reason: None }
                        }
                    };
                    note(&journal, format!("stored {} {}", header.path, ack.ok));
                    write_frame(&mut w, &ack).await.unwrap();
                });
            }
        });
    }
    let number = uplink.connect(Port::new(&tx, Arc::new(PipeStreams(streams_tx))));
    Session {
        _outbox: tx,
        msgs,
        number,
        uploads,
        unconfirmed,
    }
}

fn policy(f: impl Fn(&str, usize) -> Answer + Send + Sync + 'static) -> Policy {
    Arc::new(f)
}

fn accept_all() -> Policy {
    policy(|_, _| Answer::Ok)
}

impl Session {
    /// The server answers a heartbeat written after every report so far.
    fn confirm_reports(&self) {
        for confirm in self.unconfirmed.lock().unwrap().drain(..) {
            confirm.send_replace(true);
        }
    }

    /// The messages up to and including the next `JobFinished`.
    async fn until_finished(&mut self) -> Vec<AgentMsg> {
        let mut out = Vec::new();
        loop {
            let m = tokio::time::timeout(Duration::from_secs(600), self.msgs.recv())
                .await
                .expect("no JobFinished")
                .expect("the session ended");
            let done = matches!(m, AgentMsg::JobFinished { .. });
            out.push(m);
            if done {
                return out;
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The world.

#[derive(Debug)]
struct FixedClock(Mutex<OffsetDateTime>);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

struct World {
    exec: Executor<FakeSandbox>,
    sandbox: FakeSandbox,
    uplink: Uplink,
    offer: watch::Sender<Option<Offer>>,
    owner: AccountId,
    journal: Journal,
    clock: Arc<FixedClock>,
}

fn offer_of(cpu: f64, memory_mb: u64, disk_mb: u64, gpus: &[&str]) -> Offer {
    Offer {
        ready: true,
        platform: p2pc_proto::api::Platform::Linux,
        cpu,
        memory_mb,
        disk_mb,
        gpus: gpus.iter().map(|g| (*g).to_string()).collect(),
    }
}

fn world() -> World {
    let journal: Journal = Arc::default();
    let sandbox = FakeSandbox::new(journal.clone());
    let uplink = Uplink::new();
    let (offer, offer_rx) = watch::channel(Some(offer_of(4.0, 8192, 20_480, &[])));
    let owner = AccountId::generate();
    let clock = Arc::new(FixedClock(Mutex::new(now())));
    let exec = Executor::new(sandbox.clone(), owner, uplink.clone(), offer_rx, clock.clone());
    World {
        exec,
        sandbox,
        uplink,
        offer,
        owner,
        journal,
        clock,
    }
}

fn job(cpu: f64, memory_mb: u64) -> JobSpec {
    serde_json::from_value(json!({
        "name": "train",
        "image": "docker.io/library/python:3.12-slim",
        "command": ["python", "-c", "print(6*7)"],
        "env": {"API_TOKEN": "s3cr3t-value-example"},
        "resources": {"cpu": cpu, "memory_mb": memory_mb, "disk_mb": 1024},
    }))
    .unwrap()
}

impl World {
    fn offer(&self, lease_id: LeaseId, epoch: u64, job: JobSpec) -> LeaseOffer {
        LeaseOffer {
            lease_id,
            epoch,
            job,
            account_id: self.owner,
            deadline: now() + time::Duration::hours(1),
        }
    }

    async fn lease(&self, offer: LeaseOffer) -> LeaseDecision {
        self.exec.lease(offer).await
    }

    /// A lease of 1 vCPU and 512 MiB, accepted.
    async fn run(&self, epoch: u64) -> LeaseId {
        let id = LeaseId::generate();
        assert_eq!(
            self.lease(self.offer(id, epoch, job(1.0, 512))).await,
            LeaseDecision::Accept
        );
        id
    }

    fn journal(&self) -> Vec<String> {
        self.journal.lock().unwrap().clone()
    }

    fn held(&self) -> usize {
        self.exec.inner.lock().ledger.len()
    }

    /// Waits (virtual time) until no run is left, so every capacity is released.
    async fn idle(&self) {
        for _ in 0..10_000 {
            if self.exec.inner.lock().runs.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("runs left: {:?}", self.exec);
    }

    async fn settle(&self) {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
    }
}

fn outputs_of(msg: &AgentMsg) -> Vec<(String, u64)> {
    match msg {
        AgentMsg::JobFinished { outputs, .. } => outputs.iter().map(|o| (o.path.clone(), o.size)).collect(),
        other => panic!("not JobFinished: {other:?}"),
    }
}

fn outcome_of(msg: &AgentMsg) -> (Outcome, Option<i32>, Option<String>) {
    match msg {
        AgentMsg::JobFinished {
            outcome,
            exit_code,
            error,
            ..
        } => (*outcome, *exit_code, error.clone()),
        other => panic!("not JobFinished: {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Admission.

#[tokio::test(start_paused = true)]
async fn admission_checks_readiness_capacity_draining_deadline_and_duplicates() {
    let w = world();
    w.sandbox.set_default(Script {
        hang_in_wait: true,
        ..Script::default()
    });
    // No inventory yet, or a node that is not ready: agent_not_ready.
    w.offer.send_replace(None);
    let id = LeaseId::generate();
    assert_eq!(
        w.lease(w.offer(id, 1, job(1.0, 512))).await,
        LeaseDecision::Reject(LeaseRejectReason::AgentNotReady)
    );
    w.offer
        .send_replace(Some(Offer::not_ready(p2pc_proto::api::Platform::Linux)));
    assert_eq!(
        w.lease(w.offer(LeaseId::generate(), 1, job(1.0, 512))).await,
        LeaseDecision::Reject(LeaseRejectReason::AgentNotReady)
    );
    // 2 vCPUs, 1 GiB, 2 GiB of disk offered.
    w.offer.send_replace(Some(offer_of(2.0, 1024, 2048, &[])));
    // The first refusal is remembered: the same (lease_id, epoch) gets the same answer.
    assert_eq!(
        w.lease(w.offer(id, 1, job(1.0, 512))).await,
        LeaseDecision::Reject(LeaseRejectReason::AgentNotReady)
    );
    let a = w.run(1).await;
    // A duplicate is accepted again and starts nothing new.
    assert_eq!(w.lease(w.offer(a, 1, job(1.0, 512))).await, LeaseDecision::Accept);
    let big = LeaseId::generate();
    assert_eq!(
        w.lease(w.offer(big, 1, job(1.5, 256))).await,
        LeaseDecision::Reject(LeaseRejectReason::InsufficientCapacity),
        "1 + 1.5 > 2 vCPUs"
    );
    assert_eq!(
        w.lease(w.offer(LeaseId::generate(), 1, job(0.5, 600))).await,
        LeaseDecision::Reject(LeaseRejectReason::InsufficientCapacity),
        "512 + 600 > 1024 MiB"
    );
    let mut too_much_disk = job(0.5, 256);
    too_much_disk.resources.disk_mb = 1025;
    assert_eq!(
        w.lease(w.offer(LeaseId::generate(), 1, too_much_disk)).await,
        LeaseDecision::Reject(LeaseRejectReason::InsufficientCapacity),
        "1024 + 1025 > 2048 MiB of disk"
    );
    // A passed deadline.
    let mut late = w.offer(LeaseId::generate(), 1, job(0.5, 256));
    late.deadline = now();
    assert_eq!(
        w.lease(late).await,
        LeaseDecision::Reject(LeaseRejectReason::DeadlinePassed)
    );
    // Draining refuses; resume takes leases again.
    w.exec.drain().await;
    assert_eq!(
        w.lease(w.offer(LeaseId::generate(), 1, job(0.5, 256))).await,
        LeaseDecision::Reject(LeaseRejectReason::Draining)
    );
    w.exec.resume().await;
    let b = w.run(1).await;
    w.settle().await;
    assert_eq!(
        w.journal().iter().filter(|l| l.starts_with("prepare")).count(),
        2,
        "{:?}",
        w.journal()
    );
    let mut expected = vec![RunningLease::new(a, 1), RunningLease::new(b, 1)];
    expected.sort_by_key(|r| r.lease_id.to_string());
    assert_eq!(w.exec.running(), expected);
    assert_eq!(w.held(), 2);
    // The big one is still refused the same way when it comes again, even with room now.
    w.offer.send_replace(Some(offer_of(16.0, 65_536, 65_536, &[])));
    assert_eq!(
        w.lease(w.offer(big, 1, job(1.5, 256))).await,
        LeaseDecision::Reject(LeaseRejectReason::InsufficientCapacity)
    );
    // A terminal stop: every run stops, its capacity is released, and no lease is ever taken again.
    w.exec.stop_all("not_enrolled").await;
    assert!(w.exec.running().is_empty());
    assert_eq!(w.held(), 0);
    assert_eq!(
        w.lease(w.offer(LeaseId::generate(), 1, job(0.5, 256))).await,
        LeaseDecision::Reject(LeaseRejectReason::AgentNotReady)
    );
}

#[tokio::test(start_paused = true)]
async fn gpu_leases_get_a_free_offerable_uuid() {
    let w = world();
    let _s = connect(&w.uplink, &w.journal, accept_all());
    w.sandbox.set_default(Script {
        hang_in_wait: true,
        ..Script::default()
    });
    w.offer.send_replace(Some(offer_of(8.0, 8192, 20_480, &["GPU-1"])));
    let mut gpu_job = job(1.0, 512);
    gpu_job.resources.gpu = 1;
    let first = LeaseId::generate();
    assert_eq!(w.lease(w.offer(first, 1, gpu_job.clone())).await, LeaseDecision::Accept);
    assert_eq!(
        w.lease(w.offer(LeaseId::generate(), 1, gpu_job.clone())).await,
        LeaseDecision::Reject(LeaseRejectReason::InsufficientCapacity),
        "the only GPU is held"
    );
    // Released with its run.
    w.exec.cancel(first, 1, "user".into()).await;
    w.idle().await;
    assert_eq!(
        w.lease(w.offer(LeaseId::generate(), 1, gpu_job)).await,
        LeaseDecision::Accept
    );
    w.exec.stop_all("shutdown").await;
}

/// SI-1: a lease for another account is refused before `prepare` touches anything (the connection refuses it first;
/// this is the executor's own check).
#[tokio::test(start_paused = true)]
async fn si1_a_lease_for_another_account_never_reaches_prepare() {
    let w = world();
    let mut offer = w.offer(LeaseId::generate(), 1, job(1.0, 512));
    offer.account_id = AccountId::generate();
    assert_eq!(w.lease(offer).await, LeaseDecision::Reject(LeaseRejectReason::NotOwner));
    w.settle().await;
    assert!(w.journal().is_empty(), "{:?}", w.journal());
    assert!(w.exec.running().is_empty());
    assert_eq!(w.held(), 0);
}

// ---------------------------------------------------------------------------------------------------------------
// Runs.

/// The happy path: `JobStarted`, the logs in `seq` order, every upload stored, then `JobFinished` with the outputs,
/// then the cleanup; the capacity is released at the end.
#[tokio::test(start_paused = true)]
async fn a_job_runs_end_to_end_in_order() {
    let w = world();
    let mut s = connect(&w.uplink, &w.journal, accept_all());
    w.sandbox.set_default(Script {
        logs: vec![
            (LogStream::Stdout, b"42\n".to_vec()),
            (LogStream::Stderr, b"warning\n".to_vec()),
        ],
        exit_code: 3,
        outputs: vec![("a.txt", b"alpha".to_vec()), ("b.bin", vec![7u8; 300_000])],
        ..Script::default()
    });
    let id = w.run(1).await;
    let msgs = s.until_finished().await;
    let kinds: Vec<String> = msgs.iter().map(kind).collect();
    assert_eq!(kinds, ["job_started 1", "log 1 0", "log 1 1", "job_finished 1"]);
    for m in &msgs {
        let (lease_id, epoch) = match m {
            AgentMsg::JobStarted { lease_id, epoch, .. }
            | AgentMsg::LogChunk { lease_id, epoch, .. }
            | AgentMsg::JobFinished { lease_id, epoch, .. } => (*lease_id, *epoch),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            (lease_id, epoch),
            (id, 1),
            "every message carries its own lease and epoch"
        );
    }
    assert!(matches!(&msgs[0], AgentMsg::JobStarted { started_at, .. } if *started_at == now()));
    match &msgs[2] {
        AgentMsg::LogChunk { stream, data_b64, .. } => {
            assert_eq!(*stream, LogStream::Stderr);
            assert_eq!(data_b64.as_str(), "d2FybmluZwo=");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(outcome_of(&msgs[3]), (Outcome::Exited, Some(3), None));
    assert_eq!(outputs_of(&msgs[3]), [("a.txt".into(), 5), ("b.bin".into(), 300_000)]);
    let uploads = s.uploads.lock().unwrap().clone();
    assert_eq!(uploads.len(), 2);
    assert!(uploads.contains(&("b.bin".into(), vec![7u8; 300_000])));
    w.idle().await;
    let j = w.journal();
    let at = |line: &str| {
        j.iter()
            .position(|l| l == line)
            .unwrap_or_else(|| panic!("{line}: {j:?}"))
    };
    assert!(at("prepare 1") < at("start 1"));
    assert!(at("start 1") < at("wait 1 exited"));
    assert!(at("wait 1 exited") < at("collect 1"));
    assert!(at("collect 1") < at("stored a.txt true"));
    assert!(at("stored a.txt true") < at("msg job_finished 1"), "{j:?}");
    assert!(at("stored b.bin true") < at("msg job_finished 1"), "{j:?}");
    assert!(at("collect 1") < at("cleanup 1"));
    assert!(w.exec.running().is_empty());
    assert_eq!(w.held(), 0);
}

/// A failed phase is `outcome: "error"` with the short code only: never the driver's detail (stderr, paths).
#[tokio::test(start_paused = true)]
async fn a_failed_phase_reports_only_its_short_code() {
    let w = world();
    let mut s = connect(&w.uplink, &w.journal, accept_all());
    w.sandbox.set_default(Script {
        prepare_error: Some(SandboxError::Failed {
            code: crate::sandbox::error_code::IMAGE_PULL_FAILED,
            detail: "Error: /home/owner/.config/containers: denied".into(),
        }),
        ..Script::default()
    });
    w.run(1).await;
    let msgs = s.until_finished().await;
    assert_eq!(msgs.len(), 1, "no JobStarted for a job that never started");
    assert_eq!(
        outcome_of(&msgs[0]),
        (Outcome::Error, None, Some("image_pull_failed".into()))
    );
    assert!(!format!("{:?}", msgs[0]).contains("/home/owner"));
    // Accepted, then refused by the driver (the disk floor): the reason is the code.
    w.sandbox.set_default(Script {
        prepare_error: Some(SandboxError::Rejected(LeaseRejectReason::InsufficientCapacity)),
        ..Script::default()
    });
    w.run(1).await;
    let msgs = s.until_finished().await;
    assert_eq!(
        outcome_of(&msgs[0]),
        (Outcome::Error, None, Some("insufficient_capacity".into()))
    );
    w.idle().await;
    assert_eq!(w.held(), 0);
}

/// T10n: the wire carries only the short code, but the agent's own log says why (ACC-1 round 2: every egress job
/// ended in `egress_unavailable` and nothing said that the socket path was too long). The capture is the binary's one
/// global subscriber (`test_logs`), read by this lease's id: a thread-local one was flaky.
#[tokio::test(start_paused = true)]
async fn a_failed_phase_logs_its_cause_at_warn() {
    crate::test_logs::install();
    let w = world();
    let mut s = connect(&w.uplink, &w.journal, accept_all());
    w.sandbox.set_default(Script {
        prepare_error: Some(SandboxError::Failed {
            code: crate::sandbox::error_code::EGRESS_UNAVAILABLE,
            detail: "egress proxy could not start: bind /var/lib/x/egress.sock: path must be shorter than SUN_LEN"
                .into(),
        }),
        ..Script::default()
    });
    let id = w.run(1).await;
    let msgs = s.until_finished().await;
    assert_eq!(
        outcome_of(&msgs[0]),
        (Outcome::Error, None, Some("egress_unavailable".into()))
    );
    let lines = crate::test_logs::warnings(&id);
    let line = lines
        .iter()
        .find(|l| l.contains("egress proxy could not start"))
        .unwrap_or_else(|| panic!("the cause is not logged: {lines:?}"));
    assert!(line.starts_with("WARN"), "{line}");
    assert!(line.contains("path must be shorter than SUN_LEN"), "{line}");
    assert!(line.contains("egress_unavailable"), "{line}");
}

/// `Cancel` in each phase: while preparing (nothing ran, no outputs), while running (`cancelled`, and the outputs are
/// still uploaded), and while uploading (too late to stop anything: the run ends as it was). A cancel for an unknown
/// lease or an older epoch is ignored.
#[tokio::test(start_paused = true)]
async fn cancel_in_each_phase() {
    let w = world();
    let release = Arc::new(tokio::sync::Notify::new());
    let held = release.clone();
    let mut s = connect(
        &w.uplink,
        &w.journal,
        policy(move |path, _| {
            if path == "slow.txt" {
                Answer::Hold(held.clone())
            } else {
                Answer::Ok
            }
        }),
    );
    // While preparing.
    w.sandbox.set_default(Script {
        hang_in_prepare: true,
        ..Script::default()
    });
    let id = w.run(1).await;
    w.settle().await;
    w.exec.cancel(LeaseId::generate(), 1, "user".into()).await;
    w.exec.cancel(id, 0, "user".into()).await;
    w.settle().await;
    assert_eq!(w.exec.running().len(), 1, "unknown and stale cancels are ignored");
    w.exec.cancel(id, 1, "user".into()).await;
    let msgs = s.until_finished().await;
    assert_eq!(msgs.len(), 1);
    assert_eq!(outcome_of(&msgs[0]), (Outcome::Cancelled, None, None));
    assert!(outputs_of(&msgs[0]).is_empty());
    assert!(!w.journal().iter().any(|l| l.starts_with("start")), "it never started");
    // While running: cancelled, outputs uploaded anyway.
    w.sandbox.set_default(Script {
        hang_in_wait: true,
        outputs: vec![("partial.txt", b"half".to_vec())],
        ..Script::default()
    });
    let id = w.run(1).await;
    w.settle().await;
    w.exec.cancel(id, 1, "user".into()).await;
    let msgs = s.until_finished().await;
    assert_eq!(kind(&msgs[0]), "job_started 1");
    let last = msgs.last().unwrap();
    assert_eq!(outcome_of(last), (Outcome::Cancelled, None, None));
    assert_eq!(outputs_of(last), [("partial.txt".into(), 4)]);
    // While uploading: the job is over; the run ends as it was.
    w.sandbox.set_default(Script {
        outputs: vec![("slow.txt", b"s".to_vec())],
        ..Script::default()
    });
    let id = w.run(1).await;
    for _ in 0..100 {
        if s.uploads.lock().unwrap().iter().any(|(p, _)| p == "slow.txt") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(w.exec.status().leases[0].phase, RunPhase::Uploading);
    w.exec.cancel(id, 1, "user".into()).await;
    release.notify_one();
    let msgs = s.until_finished().await;
    let last = msgs.last().unwrap();
    assert_eq!(outcome_of(last), (Outcome::Exited, Some(0), None));
    assert_eq!(outputs_of(last), [("slow.txt".into(), 1)]);
    w.idle().await;
    assert_eq!(w.held(), 0);
}

/// Back-pressure: with the connection down, at most the cap of log chunks stays queued per run; the oldest are
/// dropped, the pump never waits, and the rest (`JobStarted`, the newest chunks, `JobFinished`) arrives in order once a
/// session is up.
#[tokio::test(start_paused = true)]
async fn the_log_queue_overflows_by_dropping_the_oldest_chunks() {
    let w = world();
    // Room for 3 chunks of 3 bytes (4 bytes of base64 each).
    let exec = w.exec.clone().with_log_cap(12);
    w.sandbox.set_default(Script {
        logs: (0..10)
            .map(|i| (LogStream::Stdout, format!("{i:02}\n").into_bytes()))
            .collect(),
        ..Script::default()
    });
    let id = LeaseId::generate();
    assert_eq!(exec.lease(w.offer(id, 1, job(1.0, 512))).await, LeaseDecision::Accept);
    // The job ran to its end with nobody connected: the pump never blocked.
    for _ in 0..1000 {
        if w.journal().iter().any(|l| l == "cleanup 1") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(w.journal().iter().any(|l| l == "cleanup 1"), "{:?}", w.journal());
    // Still listed: its JobFinished has not been handed to a server yet.
    assert_eq!(exec.running(), [RunningLease::new(id, 1)]);
    let mut s = connect(&w.uplink, &w.journal, accept_all());
    let kinds: Vec<String> = s.until_finished().await.iter().map(kind).collect();
    assert_eq!(
        kinds,
        ["job_started 1", "log 1 7", "log 1 8", "log 1 9", "job_finished 1"]
    );
    w.idle().await;
    assert!(exec.running().is_empty());
}

/// A refused upload is not retried and is left out of `JobFinished`; the other files are still uploaded.
#[tokio::test(start_paused = true)]
async fn a_refused_upload_is_left_out_and_the_others_still_go() {
    let w = world();
    let mut s = connect(
        &w.uplink,
        &w.journal,
        policy(|path, _| {
            if path == "b.txt" {
                Answer::Refuse("sha256 mismatch")
            } else {
                Answer::Ok
            }
        }),
    );
    w.sandbox.set_default(Script {
        outputs: vec![
            ("a.txt", b"a".to_vec()),
            ("b.txt", b"bb".to_vec()),
            ("c.txt", b"ccc".to_vec()),
        ],
        ..Script::default()
    });
    w.run(1).await;
    let msgs = s.until_finished().await;
    assert_eq!(
        outputs_of(msgs.last().unwrap()),
        [("a.txt".into(), 1), ("c.txt".into(), 3)]
    );
    let attempts = s.uploads.lock().unwrap().iter().filter(|(p, _)| p == "b.txt").count();
    assert_eq!(attempts, 1, "a refusal is never retried");
}

/// A transport error gets exactly one retry: a file that fails once is stored on the retry, one that fails twice is
/// left out.
#[tokio::test(start_paused = true)]
async fn an_upload_is_retried_once_on_a_transport_error() {
    let w = world();
    let mut s = connect(
        &w.uplink,
        &w.journal,
        policy(|path, attempt| match (path, attempt) {
            ("flaky.txt", 1) | ("broken.txt", _) => Answer::Drop,
            _ => Answer::Ok,
        }),
    );
    w.sandbox.set_default(Script {
        outputs: vec![
            ("broken.txt", b"x".to_vec()),
            ("flaky.txt", b"yy".to_vec()),
            ("good.txt", b"zzz".to_vec()),
        ],
        ..Script::default()
    });
    w.run(1).await;
    let msgs = s.until_finished().await;
    assert_eq!(
        outputs_of(msgs.last().unwrap()),
        [("flaky.txt".into(), 2), ("good.txt".into(), 3)]
    );
    let count = |name: &str| s.uploads.lock().unwrap().iter().filter(|(p, _)| p == name).count();
    assert_eq!((count("broken.txt"), count("flaky.txt"), count("good.txt")), (2, 2, 1));
}

/// T10c: after a transport error the retry waits for another session instead of landing on the one that is dying.
/// Session 1's uploads all fail; session 2 stores the file.
#[tokio::test(start_paused = true)]
async fn the_upload_retry_waits_for_the_next_session() {
    let w = world();
    let first_attempt = Arc::new(tokio::sync::Notify::new());
    let s1 = connect(&w.uplink, &w.journal, {
        let first_attempt = first_attempt.clone();
        policy(move |_, _| {
            first_attempt.notify_one();
            Answer::Drop
        })
    });
    w.sandbox.set_default(Script {
        outputs: vec![("f.txt", b"data".to_vec())],
        ..Script::default()
    });
    w.run(1).await;
    first_attempt.notified().await;
    // The connection is going down: the next session comes up with a healthy server.
    w.uplink.disconnect(s1.number);
    let mut s2 = connect(&w.uplink, &w.journal, accept_all());
    let msgs = s2.until_finished().await;
    assert_eq!(outputs_of(msgs.last().unwrap()), [("f.txt".into(), 4)]);
    assert_eq!(
        s1.uploads.lock().unwrap().len(),
        1,
        "no second attempt on the dying session"
    );
    assert_eq!(s2.uploads.lock().unwrap().len(), 1);
}

/// T10c: `too_many_uploads` is contention, not a failure: it is retried with a backoff for as long as the lease lives,
/// and none of it counts against the one retry a transport error gets.
#[tokio::test(start_paused = true)]
async fn too_many_uploads_is_retried_with_a_backoff_and_does_not_use_the_retry() {
    let w = world();
    let mut s = connect(
        &w.uplink,
        &w.journal,
        policy(|path, attempt| match (path, attempt) {
            // Busy five times, one transport error, busy again; then it goes through.
            ("a.txt", 1..=5 | 7) => Answer::Refuse(upload_reason::TOO_MANY_UPLOADS),
            ("a.txt", 6) => Answer::Drop,
            _ => Answer::Ok,
        }),
    );
    w.sandbox.set_default(Script {
        outputs: vec![("a.txt", b"a".to_vec()), ("b.txt", b"bb".to_vec())],
        ..Script::default()
    });
    let started = tokio::time::Instant::now();
    w.run(1).await;
    let msgs = s.until_finished().await;
    assert_eq!(
        outputs_of(msgs.last().unwrap()),
        [("a.txt".into(), 1), ("b.txt".into(), 2)]
    );
    let count = |name: &str| s.uploads.lock().unwrap().iter().filter(|(p, _)| p == name).count();
    assert_eq!((count("a.txt"), count("b.txt")), (8, 1));
    // 1 + 2 + 4 + 8 + 15 s of backoff before the sixth attempt, and 15 s more before the eighth.
    assert!(started.elapsed() >= Duration::from_secs(1 + 2 + 4 + 8 + 15 + 15));
}

/// T10c: `stale_epoch`, `unknown_lease` and `finalized` end the lease's uploads: no retry, and no other file of the
/// lease is started or kept going.
#[tokio::test(start_paused = true)]
async fn a_dead_lease_stops_all_of_its_uploads() {
    for reason in [
        upload_reason::STALE_EPOCH,
        upload_reason::UNKNOWN_LEASE,
        upload_reason::FINALIZED,
    ] {
        let w = world();
        let release = Arc::new(tokio::sync::Notify::new());
        let mut s = connect(
            &w.uplink,
            &w.journal,
            policy({
                let release = release.clone();
                move |path, _| match path {
                    "a.txt" => Answer::Refuse(reason),
                    // Still in flight when the refusal comes: abandoned, not kept.
                    "b.txt" => Answer::Hold(release.clone()),
                    _ => Answer::Ok,
                }
            }),
        );
        w.sandbox.set_default(Script {
            outputs: vec![
                ("a.txt", b"a".to_vec()),
                ("b.txt", b"b".to_vec()),
                ("c.txt", b"c".to_vec()),
                ("d.txt", b"d".to_vec()),
            ],
            ..Script::default()
        });
        w.run(1).await;
        let msgs = s.until_finished().await;
        assert!(outputs_of(msgs.last().unwrap()).is_empty(), "{reason}");
        let count = |name: &str| s.uploads.lock().unwrap().iter().filter(|(p, _)| p == name).count();
        assert_eq!((count("a.txt"), count("c.txt"), count("d.txt")), (1, 0, 0), "{reason}");
        release.notify_one();
    }
}

/// T10c: `size_mismatch`, `too_large`, `too_many_files`, `invalid_path` and `duplicate_path` leave that file out; it is
/// not retried and the others still go.
#[tokio::test(start_paused = true)]
async fn a_file_the_server_refuses_for_itself_is_left_out_without_a_retry() {
    for reason in [
        upload_reason::SIZE_MISMATCH,
        upload_reason::TOO_LARGE,
        upload_reason::TOO_MANY_FILES,
        upload_reason::INVALID_PATH,
        upload_reason::DUPLICATE_PATH,
    ] {
        let w = world();
        let mut s = connect(
            &w.uplink,
            &w.journal,
            policy(move |path, _| {
                if path == "b.txt" {
                    Answer::Refuse(reason)
                } else {
                    Answer::Ok
                }
            }),
        );
        w.sandbox.set_default(Script {
            outputs: vec![
                ("a.txt", b"a".to_vec()),
                ("b.txt", b"bb".to_vec()),
                ("c.txt", b"ccc".to_vec()),
            ],
            ..Script::default()
        });
        w.run(1).await;
        let msgs = s.until_finished().await;
        assert_eq!(
            outputs_of(msgs.last().unwrap()),
            [("a.txt".into(), 1), ("c.txt".into(), 3)],
            "{reason}"
        );
        let count = |name: &str| s.uploads.lock().unwrap().iter().filter(|(p, _)| p == name).count();
        assert_eq!(count("b.txt"), 1, "{reason}: never retried");
    }
}

/// SI-9: a symlink in `outputs/` is never uploaded, whatever it points to.
#[tokio::test(start_paused = true)]
async fn si9_a_symlinked_output_is_never_uploaded() {
    let w = world();
    let secret_dir = tempfile::tempdir().unwrap();
    let secret = secret_dir.path().join("id_ed25519");
    std::fs::write(&secret, b"host secret").unwrap();
    let mut s = connect(&w.uplink, &w.journal, accept_all());
    w.sandbox.set_default(Script {
        outputs: vec![("result.txt", b"ok".to_vec())],
        links: vec![("key", secret.clone()), ("etc", PathBuf::from("/etc"))],
        ..Script::default()
    });
    w.run(1).await;
    let msgs = s.until_finished().await;
    assert_eq!(outputs_of(msgs.last().unwrap()), [("result.txt".into(), 2)]);
    let uploads = s.uploads.lock().unwrap().clone();
    assert_eq!(uploads, [("result.txt".to_string(), b"ok".to_vec())]);
}

/// Fencing on the node: a newer epoch of a running lease replaces it. The old run is cancelled and sends nothing more
/// (no `JobFinished`), the new one runs; an older epoch is never run; a `Cancel` with a newer epoch silences the run.
#[tokio::test(start_paused = true)]
async fn a_stale_epoch_goes_silent() {
    let w = world();
    let mut s = connect(&w.uplink, &w.journal, accept_all());
    let id = LeaseId::generate();
    w.sandbox.script(
        (id, 1),
        Script {
            hang_in_wait: true,
            outputs: vec![("old.txt", b"old".to_vec())],
            ..Script::default()
        },
    );
    w.sandbox.script(
        (id, 2),
        Script {
            outputs: vec![("new.txt", b"new".to_vec())],
            ..Script::default()
        },
    );
    assert_eq!(w.lease(w.offer(id, 1, job(1.0, 512))).await, LeaseDecision::Accept);
    let first = s.msgs.recv().await.unwrap();
    assert_eq!(kind(&first), "job_started 1");
    assert_eq!(w.lease(w.offer(id, 2, job(1.0, 512))).await, LeaseDecision::Accept);
    assert_eq!(
        w.lease(w.offer(id, 1, job(1.0, 512))).await,
        LeaseDecision::Accept,
        "epoch 1 again is a duplicate: answered as before, not run again"
    );
    let msgs = s.until_finished().await;
    let kinds: Vec<String> = msgs.iter().map(kind).collect();
    assert_eq!(kinds, ["job_started 2", "job_finished 2"]);
    assert_eq!(outputs_of(msgs.last().unwrap()), [("new.txt".into(), 3)]);
    w.idle().await;
    assert!(
        w.journal().iter().any(|l| l == "wait 1 cancelled"),
        "the old run was stopped"
    );
    assert!(w.journal().iter().any(|l| l == "cleanup 1"), "and cleaned up");
    assert!(s.msgs.try_recv().is_err(), "nothing more for epoch 1");
    assert!(!s.uploads.lock().unwrap().iter().any(|(p, _)| p == "old.txt"));
    // An older epoch than the one running is never run.
    w.sandbox.set_default(Script {
        hang_in_wait: true,
        ..Script::default()
    });
    let other = LeaseId::generate();
    assert_eq!(w.lease(w.offer(other, 5, job(1.0, 512))).await, LeaseDecision::Accept);
    assert_eq!(
        w.lease(w.offer(other, 4, job(1.0, 512))).await,
        LeaseDecision::Reject(LeaseRejectReason::AgentNotReady)
    );
    // A cancel for a newer epoch than ours: ours is stale; stopped and silent.
    let _ = s.msgs.recv().await;
    w.exec.cancel(other, 6, "stale_epoch".into()).await;
    w.idle().await;
    assert!(s.msgs.try_recv().is_err(), "no JobFinished for the stale run");
    assert!(w.exec.running().is_empty());
}

/// SI-13: the agent-side lease timer (tokio's clock) fires after 45 s of silence from the server: every run is
/// stopped at once, forgotten, and its `JobFinished` is dropped, not queued for the next connection: the server has
/// requeued the job.
#[tokio::test(start_paused = true)]
async fn si13_lease_lost_stops_every_run_and_drops_its_job_finished() {
    let w = world();
    let mut s = connect(&w.uplink, &w.journal, accept_all());
    w.sandbox.set_default(Script {
        hang_in_wait: true,
        outputs: vec![("out.txt", b"x".to_vec())],
        ..Script::default()
    });
    let watchdog = Watchdog::new(Duration::from_secs(45));
    let timer = watchdog.spawn(Arc::new(w.exec.clone()));
    let started = tokio::time::Instant::now();
    let a = w.run(1).await;
    let _b = w.run(1).await;
    assert_eq!(kind(&s.msgs.recv().await.unwrap()), "job_started 1");
    assert_eq!(kind(&s.msgs.recv().await.unwrap()), "job_started 1");
    // The server goes silent; the connection drops.
    w.uplink.disconnect(s.number);
    tokio::time::sleep_until(started + Duration::from_secs(44)).await;
    assert_eq!(w.exec.running().len(), 2, "44 s: still running");
    w.idle().await;
    let at = started.elapsed();
    assert!(
        at >= Duration::from_secs(45) && at <= Duration::from_millis(45_010),
        "stopped when the timer fired: {at:?}"
    );
    assert!(w.exec.running().is_empty());
    assert_eq!(w.held(), 0);
    assert_eq!(w.journal().iter().filter(|l| l.ends_with("cancelled")).count(), 2);
    // A new connection gets nothing of them.
    let mut again = connect(&w.uplink, &w.journal, accept_all());
    w.settle().await;
    assert!(again.msgs.try_recv().is_err(), "no JobFinished after lease_lost");
    assert!(again.uploads.lock().unwrap().is_empty() && s.uploads.lock().unwrap().is_empty());
    // lease_lost is not terminal: the next lease from a live server is taken.
    watchdog.heard();
    w.sandbox.set_default(Script::default());
    assert_ne!(a, w.run(1).await);
    assert!(matches!(
        again.until_finished().await.last(),
        Some(AgentMsg::JobFinished { .. })
    ));
    timer.abort();
}

/// Start: what an earlier process left is swept before anything else, nothing is running, and the leases file says
/// so.
#[tokio::test(start_paused = true)]
async fn startup_sweeps_the_leftovers_and_reports_nothing_running() {
    let w = world();
    let report = w.exec.startup().await;
    assert_eq!(report.job_dirs, ["left-by-the-last-process"]);
    assert_eq!(w.journal(), ["sweep"]);
    assert!(w.exec.running().is_empty());
    let dir = tempfile::tempdir().unwrap();
    let file = LeasesFile::in_dir(dir.path());
    let writer = w.exec.spawn_status_writer(file.clone());
    for _ in 0..1000 {
        if file.read().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let state = file.read().expect("the leases file is written");
    assert!(state.leases.is_empty());
    writer.abort();
}

/// `status`: the running leases with their phase, job name, start and log bytes; never the job's env or command.
#[tokio::test(start_paused = true)]
async fn status_shows_the_phase_and_never_the_job_content() {
    let w = world();
    let mut s = connect(&w.uplink, &w.journal, accept_all());
    w.sandbox.set_default(Script {
        hang_in_wait: true,
        logs: vec![(LogStream::Stdout, b"hello\n".to_vec())],
        ..Script::default()
    });
    *w.clock.0.lock().unwrap() = now() + time::Duration::seconds(10);
    let id = w.run(1).await;
    let _ = s.msgs.recv().await;
    let _ = s.msgs.recv().await;
    w.settle().await;
    let status = w.exec.status();
    assert_eq!(status.leases.len(), 1);
    let l = &status.leases[0];
    assert_eq!((l.lease_id, l.epoch, l.phase), (id, 1, RunPhase::Running));
    assert_eq!(l.job_name.as_deref(), Some("train"));
    assert_eq!(l.started_at, Some(now() + time::Duration::seconds(10)));
    assert_eq!(l.log_bytes_sent, 6);
    let json = serde_json::to_string(&status).unwrap();
    assert!(
        !json.contains("s3cr3t-value-example") && !json.contains("print(6*7)"),
        "{json}"
    );
    w.exec.stop_all("shutdown").await;
}

/// `stop_all` waits for the runs it stops, and a decision cannot slip in between: it is all or nothing under one lock.
#[tokio::test(start_paused = true)]
async fn stop_all_waits_for_cleanup_and_shutdown_is_final() {
    let w = world();
    w.sandbox.set_default(Script {
        hang_in_wait: true,
        ..Script::default()
    });
    w.run(1).await;
    w.run(1).await;
    w.settle().await;
    w.exec.stop_all("shutdown").await;
    assert_eq!(
        w.journal().iter().filter(|l| l.starts_with("cleanup")).count(),
        2,
        "{:?}",
        w.journal()
    );
    assert_eq!(w.held(), 0);
    assert_eq!(
        w.lease(w.offer(LeaseId::generate(), 1, job(0.5, 256))).await,
        LeaseDecision::Reject(LeaseRejectReason::AgentNotReady)
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Through the real session and daemon, over in-memory pipes.

mod through_the_session {
    use std::sync::atomic::{AtomicBool, Ordering};

    use p2pc_proto::api::Inventory;
    use p2pc_proto::ids::NodeId;
    use p2pc_proto::protocol::Load;
    use serde_json::Value;
    use tokio::io::{ReadHalf, WriteHalf};
    use tokio::sync::Semaphore;
    use tokio::time::Instant;

    use super::*;
    use crate::connection::daemon::{Daemon, DaemonExit};
    use crate::connection::load::LoadSource;
    use crate::connection::session::{INVENTORY_INTERVAL, InventorySource, MAX_PENDING_DECISIONS, Shared};
    use crate::connection::transport::{Connector, Link};
    use crate::connection::watchdog::Watchdog;

    /// The server's halves of one connection.
    struct ServerEnd {
        r: ReadHalf<DuplexStream>,
        w: WriteHalf<DuplexStream>,
    }

    impl ServerEnd {
        async fn recv(&mut self) -> Option<Value> {
            read_frame::<Value, _>(&mut self.r, MAX_FRAME_LEN).await.ok().flatten()
        }

        async fn send(&mut self, v: Value) {
            write_frame(&mut self.w, &v).await.unwrap();
        }

        /// The next message that is not a heartbeat, acknowledging heartbeats on the way.
        async fn next_acking(&mut self) -> Option<Value> {
            loop {
                let m = self.recv().await?;
                if m["type"] == "heartbeat" {
                    let seq = m["seq"].clone();
                    self.send(json!({"type": "heartbeat_ack", "seq": seq})).await;
                    continue;
                }
                return Some(m);
            }
        }
    }

    /// Pipes of `buffer` bytes; the server end of each connection goes to the test.
    #[derive(Debug)]
    struct Pipes {
        accepted: mpsc::UnboundedSender<ServerEnd>,
        buffer: usize,
        refuse: AtomicBool,
    }

    impl std::fmt::Debug for ServerEnd {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("ServerEnd")
        }
    }

    impl Connector for Pipes {
        fn connect(&self) -> BoxFuture<'_, Result<Link, ConnectError>> {
            Box::pin(async move {
                if self.refuse.load(Ordering::SeqCst) {
                    return Err(ConnectError("refused".into()));
                }
                let (agent, server) = tokio::io::duplex(self.buffer);
                let (ar, aw) = tokio::io::split(agent);
                let (sr, sw) = tokio::io::split(server);
                let _ = self.accepted.send(ServerEnd { r: sr, w: sw });
                Ok(Link::new(Box::new(aw), Box::new(ar), Box::new(|| {})))
            })
        }

        fn set_addresses(&self, _: Vec<p2pc_proto::net::SelectedAddr>) -> BoxFuture<'_, ()> {
            Box::pin(async {})
        }

        fn shutdown(&self) -> BoxFuture<'_, ()> {
            Box::pin(async {})
        }
    }

    #[derive(Debug)]
    struct Inv;

    impl InventorySource for Inv {
        fn detect(&self) -> BoxFuture<'_, Result<Inventory, String>> {
            Box::pin(async {
                Ok(serde_json::from_value(json!({
                    "hostname": "node-1", "platform": "linux", "cpu": {"model": "Example CPU", "cores": 4},
                    "memory_mb": 8192, "os": "Ubuntu 24.04", "arch": "x86_64", "gpu_status": {"status": "not_found"},
                    "offered": {"cpu": 3.0, "memory_mb": 6144, "gpu": 0}, "agent_version": "0.1.0",
                }))
                .unwrap())
            })
        }
    }

    #[derive(Debug)]
    struct NoLoad;

    impl LoadSource for NoLoad {
        fn sample(&self) -> BoxFuture<'_, Load> {
            Box::pin(async { serde_json::from_value(json!({"cpu_pct": 0, "mem_used_mb": 0})).unwrap() })
        }
    }

    struct Running {
        accepted: mpsc::UnboundedReceiver<ServerEnd>,
        stop: watch::Sender<bool>,
        daemon: tokio::task::JoinHandle<DaemonExit>,
    }

    /// `p2pc-agent run` with the world's executor, over pipes of `buffer` bytes.
    fn run_agent(w: &World, buffer: usize) -> Running {
        let (tx, accepted) = mpsc::unbounded_channel();
        let ttl = Duration::from_secs(45);
        let exec = Arc::new(w.exec.clone());
        let daemon = Daemon {
            shared: Shared {
                owner: w.owner,
                agent_lease_ttl: ttl,
                watchdog: Watchdog::new(ttl),
                supervisor: exec.clone(),
                handler: exec,
                inventory: Arc::new(Inv),
                load: Arc::new(NoLoad),
                inventory_interval: INVENTORY_INTERVAL,
                decisions: Arc::new(Semaphore::new(MAX_PENDING_DECISIONS)),
                uplink: w.uplink.clone(),
            },
            connector: Arc::new(Pipes {
                accepted: tx,
                buffer,
                refuse: AtomicBool::new(false),
            }),
            backoff_seed: 3,
            state_file: None,
            server_node_id: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into(),
            agent_node_id: NodeId::generate().to_string(),
        };
        let (stop, stop_rx) = watch::channel(false);
        let (_net, net_rx) = mpsc::channel(1);
        let daemon = tokio::spawn(async move {
            let _net = _net;
            daemon.run(stop_rx, net_rx).await
        });
        Running { accepted, stop, daemon }
    }

    fn welcome(owner: AccountId) -> Value {
        json!({
            "type": "welcome", "server_version": "0.1.0", "node_id": NodeId::generate(), "account_id": owner,
            "heartbeat_interval_s": 5, "lease_ttl_s": 60,
        })
    }

    fn lease(owner: AccountId, id: LeaseId) -> Value {
        json!({
            "type": "lease", "lease_id": id, "epoch": 1, "account_id": owner, "deadline": "2099-01-01T00:00:00Z",
            "job": {"image": "docker.io/library/busybox:1.36.1", "command": ["true"],
                    "resources": {"cpu": 1, "memory_mb": 256, "disk_mb": 1024}},
        })
    }

    /// T10a review P2-1: a job logging at full speed over a slow link never starves the control frames. The server
    /// reads one frame every 50 ms through a 64 KiB pipe while a job pours out 300 chunks of 64 KiB. Every heartbeat
    /// and the `LeaseAccepted` of a second lease still arrive within 1 s (before the fix, 64 queued job frames, about
    /// 3 s, sat ahead of each one), and every log chunk is either delivered or counted as dropped.
    #[tokio::test(start_paused = true)]
    async fn a_chatty_job_never_starves_heartbeats_or_lease_answers() {
        const CHUNKS: usize = 300;
        const READ_EVERY: Duration = Duration::from_millis(50);
        let w = world();
        let chatty = LeaseId::generate();
        let quiet = LeaseId::generate();
        w.sandbox.script(
            (chatty, 1),
            Script {
                logs: (0..CHUNKS)
                    .map(|_| (LogStream::Stdout, vec![b'x'; 64 * 1024]))
                    .collect(),
                ..Script::default()
            },
        );
        w.sandbox.script(
            (quiet, 1),
            Script {
                prepare_error: Some(SandboxError::Failed {
                    code: crate::sandbox::error_code::IMAGE_PULL_FAILED,
                    detail: String::new(),
                }),
                ..Script::default()
            },
        );
        let mut agent = run_agent(&w, 64 * 1024);
        let mut s = agent.accepted.recv().await.unwrap();
        assert_eq!(s.recv().await.unwrap()["type"], "hello");
        s.send(welcome(w.owner)).await;
        let welcomed = Instant::now();
        s.send(lease(w.owner, chatty)).await;
        let ServerEnd { mut r, w: mut sw } = s;
        // The server's writer: heartbeat acks, and the second lease at 7 s.
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel::<Value>();
        let owner = w.owner;
        let writer = tokio::spawn(async move {
            let second = tokio::time::sleep_until(welcomed + Duration::from_secs(7));
            tokio::pin!(second);
            let mut sent = false;
            loop {
                tokio::select! {
                    () = &mut second, if !sent => {
                        sent = true;
                        write_frame(&mut sw, &lease(owner, quiet)).await.unwrap();
                    }
                    ack = ack_rx.recv() => match ack {
                        Some(ack) => write_frame(&mut sw, &ack).await.unwrap(),
                        None => return,
                    },
                }
            }
        });
        // The slow reader.
        let (mut logs, mut finished, mut heartbeat_late, mut accepted_late) = (0usize, 0, Duration::ZERO, None);
        while finished < 2 {
            let m: Value = read_frame(&mut r, MAX_FRAME_LEN).await.unwrap().unwrap();
            let at = Instant::now() - welcomed;
            match m["type"].as_str().unwrap() {
                "heartbeat" => {
                    let seq = m["seq"].as_u64().unwrap();
                    heartbeat_late = heartbeat_late.max(at.saturating_sub(Duration::from_secs(5 * seq)));
                    ack_tx.send(json!({"type": "heartbeat_ack", "seq": seq})).unwrap();
                }
                "lease_accepted" if m["lease_id"] == json!(quiet) => {
                    accepted_late = Some(at.saturating_sub(Duration::from_secs(7)));
                }
                "log_chunk" => logs += 1,
                "job_finished" => finished += 1,
                _ => {}
            }
            tokio::time::sleep(READ_EVERY).await;
        }
        assert!(
            heartbeat_late <= Duration::from_secs(1),
            "a heartbeat waited {heartbeat_late:?} behind job frames"
        );
        let accepted_late = accepted_late.expect("the second lease was answered");
        assert!(
            accepted_late <= Duration::from_secs(1),
            "LeaseAccepted waited {accepted_late:?}"
        );
        // Keep acknowledging until both reports are confirmed and the runs are over.
        let drain = tokio::spawn(async move {
            while let Ok(Some(m)) = read_frame::<Value, _>(&mut r, MAX_FRAME_LEN).await {
                if m["type"] == "heartbeat" {
                    let _ = ack_tx.send(json!({"type": "heartbeat_ack", "seq": m["seq"]}));
                }
            }
        });
        w.idle().await;
        assert_eq!(
            logs as u64 + w.exec.dropped_log_chunks(),
            CHUNKS as u64,
            "every chunk was delivered or counted ({logs} delivered)"
        );
        assert!(w.exec.dropped_log_chunks() > 0, "the 8 MiB cap was reached");
        agent.stop.send(true).unwrap();
        assert_eq!(agent.daemon.await.unwrap(), DaemonExit::Shutdown);
        drain.abort();
        writer.abort();
    }

    /// §6 (amended 2026-11-06): the connection drops right after `JobFinished` is written, before any later heartbeat
    /// is answered. After the reconnect the lease is still listed in `Hello.running`, so the server does not declare
    /// it lost, and the report is sent again right after `Welcome`; once a later heartbeat is answered, the lease is
    /// gone from the next `Hello`.
    #[tokio::test(start_paused = true)]
    async fn a_job_finished_lost_with_its_connection_is_resent_after_the_reconnect() {
        let w = world();
        w.sandbox.set_default(Script {
            exit_code: 0,
            ..Script::default()
        });
        let mut agent = run_agent(&w, 1 << 20);
        let id = LeaseId::generate();
        let mut s = agent.accepted.recv().await.unwrap();
        assert_eq!(s.recv().await.unwrap()["running"], json!([]));
        s.send(welcome(w.owner)).await;
        s.send(lease(w.owner, id)).await;
        let mut kinds = Vec::new();
        loop {
            let m = s.recv().await.unwrap();
            if m["type"] == "heartbeat" {
                continue; // never answered on this connection
            }
            kinds.push(m["type"].as_str().unwrap().to_string());
            if m["type"] == "job_finished" {
                break;
            }
        }
        assert_eq!(kinds, ["lease_accepted", "job_started", "job_finished"]);
        // The connection drops right after the report.
        drop(s);
        let mut again = agent.accepted.recv().await.unwrap();
        let hello = again.recv().await.unwrap();
        assert_eq!(
            hello["running"],
            json!([{"lease_id": id, "epoch": 1}]),
            "still listed: the report is not confirmed"
        );
        again.send(welcome(w.owner)).await;
        let resent = again.next_acking().await.unwrap();
        assert_eq!(resent["type"], "job_finished", "{resent}");
        assert_eq!(resent["lease_id"], json!(id));
        assert_eq!(resent["outcome"], "exited");
        // A heartbeat after it is answered: confirmed, and the run is over.
        let serve = tokio::spawn(async move {
            if let Some(m) = again.next_acking().await {
                panic!("nothing more for the job: {m}");
            }
        });
        w.idle().await;
        assert!(w.exec.running().is_empty());
        agent.stop.send(true).unwrap();
        assert_eq!(agent.daemon.await.unwrap(), DaemonExit::Shutdown);
        serve.abort();
    }
}

/// T10a review P3-3: a `Cancel` that says the server no longer holds the lease (`stale_epoch`, `unknown_lease`) stops
/// the run silently: no upload and no `JobFinished`, which the server would only fence again.
#[tokio::test(start_paused = true)]
async fn a_fenced_cancel_stops_the_run_silently() {
    for reason in ["stale_epoch", "unknown_lease"] {
        let w = world();
        let mut s = connect(&w.uplink, &w.journal, accept_all());
        w.sandbox.set_default(Script {
            hang_in_wait: true,
            outputs: vec![("out.txt", b"x".to_vec())],
            ..Script::default()
        });
        let id = w.run(1).await;
        assert_eq!(kind(&s.msgs.recv().await.unwrap()), "job_started 1");
        w.exec.cancel(id, 1, reason.into()).await;
        w.idle().await;
        assert!(
            w.journal().iter().any(|l| l == "wait 1 cancelled"),
            "{reason}: the job was stopped"
        );
        assert!(w.journal().iter().any(|l| l == "cleanup 1"), "{reason}: and cleaned up");
        w.settle().await;
        assert!(s.msgs.try_recv().is_err(), "{reason}: no JobFinished");
        assert!(s.uploads.lock().unwrap().is_empty(), "{reason}: no upload");
        assert_eq!(w.held(), 0);
    }
}

/// T10a review P3-6: the same `(lease_id, epoch)` as a running lease is a duplicate even once its first answer is
/// forgotten: accepted again, and nothing new starts (the running one is not replaced).
#[tokio::test(start_paused = true)]
async fn the_same_epoch_as_a_running_lease_is_a_duplicate() {
    let w = world();
    w.sandbox.set_default(Script {
        hang_in_wait: true,
        ..Script::default()
    });
    let id = w.run(3).await;
    w.settle().await;
    w.exec.inner.lock().recent.clear();
    assert_eq!(w.lease(w.offer(id, 3, job(1.0, 512))).await, LeaseDecision::Accept);
    w.settle().await;
    assert_eq!(
        w.journal().iter().filter(|l| l.starts_with("prepare")).count(),
        1,
        "{:?}",
        w.journal()
    );
    assert!(
        !w.journal().iter().any(|l| l.ends_with("cancelled")),
        "the running one goes on"
    );
    assert_eq!(w.exec.running(), [RunningLease::new(id, 3)]);
    assert_eq!(w.held(), 1);
    w.exec.stop_all("shutdown").await;
}

// ---------------------------------------------------------------------------------------------------------------
// T06e: a lease's resources are freed when its cleanup ends, not when the server confirms its `JobFinished`.

/// The key of a lease `epoch` of `id`, as `Heartbeat.running` and `Hello.running` list it.
fn listed(id: LeaseId, epoch: u64) -> RunningLease {
    RunningLease::new(id, epoch)
}

#[tokio::test(start_paused = true)]
async fn the_capacity_is_released_when_cleanup_ends_before_any_heartbeat_ack() {
    let w = world();
    let mut session = connect_unconfirmed(&w.uplink, &w.journal, accept_all());
    let id = w.run(1).await;
    // The job ends and its report reaches the session, but no heartbeat answers it.
    session.until_finished().await;
    w.settle().await;
    assert!(w.journal().contains(&"cleanup 1".to_string()), "{:?}", w.journal());
    assert_eq!(
        w.held(),
        0,
        "the reservation is released with the cleanup, unconfirmed or not"
    );
    assert!(
        w.exec.holding().is_empty(),
        "nothing is held: Heartbeat.running no longer lists it"
    );
    assert_eq!(
        w.exec.running(),
        [listed(id, 1)],
        "Hello.running still lists the lease whose report is not confirmed"
    );
    // The slot is usable at once: a lease of all four vCPUs is accepted.
    assert_eq!(
        w.lease(w.offer(LeaseId::generate(), 1, job(4.0, 512))).await,
        LeaseDecision::Accept
    );
    session.until_finished().await;
    // The confirmation comes later and only forgets the runs.
    session.confirm_reports();
    w.idle().await;
}

#[tokio::test(start_paused = true)]
async fn holding_lists_a_lease_in_cleanup_and_drops_it_when_it_is_released() {
    let w = world();
    let gate = Arc::new(tokio::sync::Notify::new());
    w.sandbox.set_default(Script {
        cleanup_gate: Some(gate.clone()),
        ..Script::default()
    });
    let mut session = connect(&w.uplink, &w.journal, accept_all());
    let id = w.run(1).await;
    session.until_finished().await;
    w.settle().await;
    // The report is confirmed (this session confirms at once), but the container and the directory are still being
    // removed: the lease holds its resources.
    assert!(w.journal().contains(&"cleanup 1".to_string()));
    assert_eq!(w.exec.holding(), [listed(id, 1)]);
    assert_eq!(w.held(), 1);
    assert_eq!(
        w.exec.running(),
        [listed(id, 1)],
        "a reconnect now lists the lease in cleanup in Hello, so the server never reconciles it as lost"
    );
    assert_eq!(
        w.lease(w.offer(LeaseId::generate(), 1, job(4.0, 512))).await,
        LeaseDecision::Reject(LeaseRejectReason::InsufficientCapacity),
        "its capacity is still taken"
    );
    // Nothing woke the session yet.
    assert!(
        tokio::time::timeout(Duration::from_millis(1), w.exec.released())
            .await
            .is_err()
    );
    // The cleanup ends: the lease leaves the list and the session is woken for its immediate heartbeat.
    gate.notify_one();
    w.settle().await;
    assert!(w.exec.holding().is_empty());
    assert_eq!(w.held(), 0);
    tokio::time::timeout(Duration::from_millis(1), w.exec.released())
        .await
        .expect("a release wakes the session");
    assert!(
        tokio::time::timeout(Duration::from_millis(1), w.exec.released())
            .await
            .is_err(),
        "one release, one wake-up"
    );
    w.idle().await;
}

#[tokio::test(start_paused = true)]
async fn an_unconfirmed_job_finished_is_sent_again_after_a_reconnect_although_the_resources_are_free() {
    let w = world();
    let mut first = connect_unconfirmed(&w.uplink, &w.journal, accept_all());
    let id = w.run(1).await;
    first.until_finished().await;
    w.settle().await;
    assert_eq!(w.held(), 0);
    // The connection drops before the report is confirmed.
    w.uplink.disconnect(first.number);
    w.settle().await;
    assert_eq!(
        w.exec.running(),
        [listed(id, 1)],
        "the next Hello lists the unconfirmed lease"
    );
    assert!(w.exec.holding().is_empty());
    // The next session gets the report again, right after its Welcome, and confirms it.
    let mut second = connect(&w.uplink, &w.journal, accept_all());
    let again = second.until_finished().await;
    assert!(matches!(again.last(), Some(AgentMsg::JobFinished { lease_id, epoch: 1, .. }) if *lease_id == id));
    w.idle().await;
    assert!(w.exec.running().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_fenced_cancel_during_cleanup_does_not_free_the_resources_early() {
    // A reconnect lists a lease in cleanup in `Hello`; the server, which has it finished already, answers `Cancel` with
    // `stale_epoch`. The run goes silent, but its container and directory are still there: it keeps holding.
    let w = world();
    let gate = Arc::new(tokio::sync::Notify::new());
    w.sandbox.set_default(Script {
        cleanup_gate: Some(gate.clone()),
        ..Script::default()
    });
    let mut session = connect(&w.uplink, &w.journal, accept_all());
    let id = w.run(1).await;
    session.until_finished().await;
    w.settle().await;
    assert_eq!(w.exec.holding(), [listed(id, 1)]);
    w.exec.cancel(id, 1, "stale_epoch".into()).await;
    w.settle().await;
    assert_eq!(w.exec.holding(), [listed(id, 1)], "still cleaning up: still held");
    assert_eq!(w.held(), 1);
    assert!(
        w.exec.running().is_empty(),
        "it is silenced, so a later Hello does not list it"
    );
    gate.notify_one();
    w.settle().await;
    assert!(w.exec.holding().is_empty());
    assert_eq!(w.held(), 0);
    w.idle().await;
}

// ---------------------------------------------------------------------------------------------------------------
// Services (H2 §6.1, §11.4).

fn service_job() -> JobSpec {
    serde_json::from_value(json!({
        "kind": "service",
        "name": "chat",
        "image": "docker.io/ollama/ollama:0.5.7",
        "command": ["/bin/ollama", "serve"],
        "resources": {"cpu": 1.0, "memory_mb": 512, "disk_mb": 1024},
        "service": {"ports": [{"port": 11434, "name": "api"}]},
    }))
    .unwrap()
}

fn health(state: p2pc_proto::protocol::HealthState, detail: Option<&str>) -> SandboxEvent {
    SandboxEvent::Health(crate::sandbox::HealthChange {
        state,
        detail: detail.map(String::from),
    })
}

fn usage(used_cpu_ms: u64, max_rss_mb: u64) -> SandboxEvent {
    SandboxEvent::Usage(crate::sandbox::UsageSample {
        used_cpu_ms,
        max_rss_mb,
    })
}

impl Session {
    async fn next(&mut self) -> AgentMsg {
        tokio::time::timeout(Duration::from_secs(600), self.msgs.recv())
            .await
            .expect("no message")
            .expect("the session ended")
    }
}

/// Every health change becomes a `ServiceHealth` (after `JobStarted`, stamped with the executor's clock), and each
/// heartbeat repeats the last state. Each usage sample (at most one a minute, from the driver) goes into the next
/// heartbeat only. `Hello` keeps H1's list, and a batch lease gets none of these fields.
#[tokio::test(start_paused = true)]
async fn a_service_reports_its_health_and_each_usage_sample_once() {
    use p2pc_proto::protocol::{HealthState, ServiceHealth};
    let w = world();
    let mut session = connect(&w.uplink, &w.journal, accept_all());
    let later = now() + time::Duration::minutes(5);
    *w.clock.0.lock().unwrap() = later;
    w.sandbox.set_default(Script {
        hang_in_wait: true,
        ..Script::default()
    });
    let id = LeaseId::generate();
    w.sandbox.script(
        (id, 1),
        Script {
            hang_in_wait: true,
            events: vec![
                health(HealthState::Starting, None),
                health(HealthState::Healthy, None),
                usage(1500, 300),
            ],
            ..Script::default()
        },
    );
    assert_eq!(w.lease(w.offer(id, 1, service_job())).await, LeaseDecision::Accept);
    let batch = w.run(1).await;
    // In order, for the service: JobStarted, then its two health changes.
    let mut service_msgs = Vec::new();
    while service_msgs.len() < 3 {
        match session.next().await {
            AgentMsg::JobStarted { lease_id, .. } if lease_id == batch => {}
            m => service_msgs.push(m),
        }
    }
    assert!(matches!(service_msgs[0], AgentMsg::JobStarted { lease_id, .. } if lease_id == id));
    let reported: Vec<ServiceHealth> = service_msgs[1..]
        .iter()
        .map(|m| match m {
            AgentMsg::ServiceHealth(h) => h.clone(),
            other => panic!("not ServiceHealth: {other:?}"),
        })
        .collect();
    let expected = |state| ServiceHealth {
        lease_id: id,
        epoch: 1,
        state,
        since: later,
        detail: None,
    };
    assert_eq!(
        reported,
        [expected(HealthState::Starting), expected(HealthState::Healthy)]
    );
    for h in &reported {
        assert_eq!(AgentMsg::ServiceHealth(h.clone()).validate(), Ok(()));
    }
    w.settle().await;
    let service_entry = |r: &[RunningLease]| r.iter().find(|l| l.lease_id == id).copied().unwrap();
    // The first heartbeat carries the sample; the next ones only the state, until a new sample comes.
    let first = w.exec.holding();
    assert_eq!(
        service_entry(&first),
        RunningLease {
            health: Some(HealthState::Healthy),
            used_cpu_ms: Some(1500),
            max_rss_mb: Some(300),
            ..RunningLease::new(id, 1)
        }
    );
    assert_eq!(
        first.iter().find(|l| l.lease_id == batch),
        Some(&RunningLease::new(batch, 1))
    );
    let second = w.exec.holding();
    assert_eq!(
        service_entry(&second),
        RunningLease {
            health: Some(HealthState::Healthy),
            ..RunningLease::new(id, 1)
        }
    );
    // `Hello.running` keeps H1's entries.
    assert!(
        w.exec
            .running()
            .iter()
            .all(|l| *l == RunningLease::new(l.lease_id, l.epoch))
    );
    // Stopping a service is the H1 cancel sequence.
    w.exec.cancel(id, 1, "stopped".into()).await;
    w.exec.cancel(batch, 1, "user".into()).await;
    let msgs = session.until_finished().await;
    assert_eq!(outcome_of(msgs.last().unwrap()).0, Outcome::Cancelled);
    session.until_finished().await;
    w.idle().await;
}

/// A stale service run (a newer epoch replaced it) is still held until its cleanup ends, but its health and usage
/// are no longer reported: the server fences that epoch.
#[tokio::test(start_paused = true)]
async fn a_stale_service_run_reports_no_health() {
    use p2pc_proto::protocol::HealthState;
    let w = world();
    let _session = connect(&w.uplink, &w.journal, accept_all());
    let gate = Arc::new(tokio::sync::Notify::new());
    w.sandbox.set_default(Script {
        hang_in_wait: true,
        events: vec![health(HealthState::Starting, None), usage(10, 1)],
        cleanup_gate: Some(gate.clone()),
        ..Script::default()
    });
    let id = LeaseId::generate();
    assert_eq!(w.lease(w.offer(id, 1, service_job())).await, LeaseDecision::Accept);
    w.settle().await;
    w.exec.cancel(id, 2, "stale_epoch".into()).await;
    w.settle().await;
    assert_eq!(w.exec.holding(), [RunningLease::new(id, 1)], "held, without H2 fields");
    gate.notify_one();
    w.idle().await;
}

/// H2 §11.4: a service keeps the most recent log bytes, in whole segments. While the server cannot take them, the
/// oldest segment goes first, and one marker, numbered with the first dropped `seq`, records the dropped range.
#[tokio::test(start_paused = true)]
async fn a_service_keeps_its_most_recent_logs_in_a_ring() {
    let w = world();
    // Room for 40 bytes, in segments of 10 bytes: two chunks of 5 bytes each.
    let exec = w.exec.clone().with_service_log_ring(40, 10);
    w.sandbox.set_default(Script {
        hang_in_wait: true,
        logs: (0..12).map(|i| (LogStream::Stdout, vec![b'a' + i; 5])).collect(),
        ..Script::default()
    });
    let id = LeaseId::generate();
    assert_eq!(exec.lease(w.offer(id, 1, service_job())).await, LeaseDecision::Accept);
    w.settle().await;
    // Only now does a session come.
    let mut session = connect(&w.uplink, &w.journal, accept_all());
    let mut got = Vec::new();
    while got.len() < 10 {
        got.push(session.next().await);
    }
    let kinds: Vec<String> = got.iter().map(kind).collect();
    assert_eq!(
        kinds,
        [
            "job_started 1",
            "log 1 0",
            "log 1 4",
            "log 1 5",
            "log 1 6",
            "log 1 7",
            "log 1 8",
            "log 1 9",
            "log 1 10",
            "log 1 11"
        ]
    );
    let AgentMsg::LogChunk { stream, data_b64, .. } = &got[1] else {
        panic!()
    };
    assert_eq!(*stream, LogStream::Stderr);
    let marker = String::from_utf8(data_encoding::BASE64.decode(data_b64.as_str().as_bytes()).unwrap()).unwrap();
    assert!(marker.contains("0-3") && marker.contains("20 bytes"), "{marker}");
    let AgentMsg::LogChunk { data_b64, .. } = &got[2] else {
        panic!()
    };
    assert_eq!(
        data_encoding::BASE64.decode(data_b64.as_str().as_bytes()).unwrap(),
        vec![b'e'; 5],
        "the kept chunks are intact"
    );
    exec.cancel(id, 1, "stopped".into()).await;
    session.until_finished().await;
    w.idle().await;
    assert_eq!(exec.dropped_log_chunks(), 4);
}
