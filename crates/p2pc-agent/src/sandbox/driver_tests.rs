// SPDX-License-Identifier: Apache-2.0

//! Lifecycle tests of [`PodmanDriver`] against a mock [`Engine`], a fake cgroup tree in a temporary directory and
//! paused Tokio time (no real sleeps). The CLI mapping and real processes are covered by
//! `tests/sandbox_fake_podman.rs`; real Podman by `tests/podman_real.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use p2pc_proto::api::{
    Egress as JobEgress, InputFile, JobSpec, Outputs, Placement, Platform, Resources, Retry, SmokeResult,
};
use p2pc_proto::ids::{AccountId, LeaseId};
use p2pc_proto::protocol::{LeaseRejectReason, Outcome};
use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use super::*;
use crate::sandbox::cgroup::FsCgroups;
use crate::sandbox::engine::{EngineError, LeaseContainer, PULL_TIMEOUT};
use crate::sandbox::{LeaseReport, apply_smoke, smoke_once_per_boot};

// ---------------------------------------------------------------------------------------------------------------
// The mock engine

#[derive(Default)]
struct MockState {
    calls: Vec<String>,
    create_argv: Option<Vec<String>>,
    env_file_at_create: Option<String>,
    fail_create: bool,
    fail_start: bool,
    pull_hangs: bool,
    image_size: u64,
    image_present: bool,
    manifest_size: u64,
    manifest_unreadable: bool,
    /// Reading the manifest never finishes (a registry that does not answer).
    manifest_hangs: bool,
    /// Told when a manifest read starts ([`MockEngine::manifest_started`]).
    manifest_started: Option<oneshot::Sender<()>>,
    fail_pull: bool,
    /// The text of a failed pull (default: a registry refusal).
    pull_error: Option<String>,
    /// The next this-many pulls fail, and then they work.
    pulls_failing: u32,
    /// A pull runs into the pull timeout: it fails after [`PULL_TIMEOUT`] of (tokio) time, as a hung registry does.
    pull_times_out: bool,
    /// The store cannot be asked whether an image is there.
    image_exists_fails: bool,
    /// The store cannot tell the size of an image.
    image_size_fails: bool,
    /// A pull waits for a permit before it finishes ([`MockEngine::gate_pulls`]).
    pull_gate: Option<Arc<tokio::sync::Semaphore>>,
    /// Exit code right after start.
    exit_now: Option<i32>,
    /// Exit code when SIGTERM arrives; `None` ignores it.
    on_term: Option<i32>,
    exit_tx: Option<oneshot::Sender<i32>>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    sizes: VecDeque<u64>,
    oom_killed: bool,
    inspect_fails: bool,
    /// The exit future fails (Podman lost track of the container).
    exit_errors: bool,
    /// SIGKILL is accepted but nothing exits (a hung runtime).
    ignores_kill: bool,
    /// `inspect` shows a container that never started (`podman start` itself failed).
    never_started: bool,
    containers: Vec<LeaseContainer>,
}

#[derive(Clone, Default)]
struct MockEngine(Arc<Mutex<MockState>>);

impl MockEngine {
    fn with(f: impl FnOnce(&mut MockState)) -> Self {
        let e = Self::default();
        f(&mut e.0.lock().unwrap());
        e
    }
    fn calls(&self) -> Vec<String> {
        self.0.lock().unwrap().calls.clone()
    }
    fn record(&self, call: impl Into<String>) {
        self.0.lock().unwrap().calls.push(call.into());
    }
    /// Resolves when the next manifest read starts: an event to await instead of polling [`Self::calls`].
    fn manifest_started(&self) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.0.lock().unwrap().manifest_started = Some(tx);
        rx
    }
    /// Makes every pull wait until a permit is added to the returned semaphore, so a test can
    /// line leases up behind one running pull.
    fn gate_pulls(&self) -> Arc<tokio::sync::Semaphore> {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        self.0.lock().unwrap().pull_gate = Some(Arc::clone(&gate));
        gate
    }
    /// How many calls start with `prefix`.
    fn count(&self, prefix: &str) -> usize {
        self.calls().iter().filter(|c| c.starts_with(prefix)).count()
    }
    fn exit(&self, code: i32) {
        if let Some(tx) = self.0.lock().unwrap().exit_tx.take() {
            let _ = tx.send(code);
        }
    }
}

impl Engine for MockEngine {
    async fn pull(&self, image: &str) -> Result<(), EngineError> {
        self.record(format!("pull {image}"));
        let (hangs, fails, gate, times_out) = {
            let s = self.0.lock().unwrap();
            (s.pull_hangs, s.fail_pull, s.pull_gate.clone(), s.pull_times_out)
        };
        if hangs {
            std::future::pending::<()>().await;
        }
        if let Some(gate) = gate {
            gate.acquire().await.unwrap().forget();
        }
        let fails = fails || {
            let mut s = self.0.lock().unwrap();
            let failing = s.pulls_failing > 0;
            s.pulls_failing = s.pulls_failing.saturating_sub(1);
            failing
        };
        if times_out {
            tokio::time::sleep(PULL_TIMEOUT).await;
            return Err(EngineError::timed_out(format!(
                "podman pull: timed out after {} s",
                PULL_TIMEOUT.as_secs()
            )));
        }
        if fails {
            let text = self.0.lock().unwrap().pull_error.clone();
            return Err(EngineError::new(text.unwrap_or_else(|| {
                "podman pull exited with 125: Error: manifest unknown".into()
            })));
        }
        // What a real pull does: the image is in the store afterwards.
        self.0.lock().unwrap().image_present = true;
        Ok(())
    }

    async fn image_size(&self, _: &str) -> Result<u64, EngineError> {
        self.record("image_size");
        let s = self.0.lock().unwrap();
        if s.image_size_fails {
            return Err(EngineError::new("podman image inspect: no size".into()));
        }
        Ok(s.image_size)
    }

    async fn image_exists(&self, _: &str) -> Result<bool, EngineError> {
        self.record("image_exists");
        let s = self.0.lock().unwrap();
        if s.image_exists_fails {
            return Err(EngineError::new("podman image exists: storage".into()));
        }
        Ok(s.image_present)
    }

    async fn manifest_size(&self, _: &str) -> Result<u64, EngineError> {
        self.record("manifest");
        let hangs = {
            let mut s = self.0.lock().unwrap();
            if let Some(started) = s.manifest_started.take() {
                let _ = started.send(());
            }
            s.manifest_hangs
        };
        if hangs {
            std::future::pending::<()>().await;
        }
        let s = self.0.lock().unwrap();
        if s.manifest_unreadable {
            return Err(EngineError::new("podman manifest inspect: unsupported".into()));
        }
        Ok(s.manifest_size)
    }

    async fn remove_image(&self, image: &str) -> Result<(), EngineError> {
        self.record(format!("rmi {image}"));
        self.0.lock().unwrap().image_present = false;
        Ok(())
    }

    async fn create(&self, argv: &[String]) -> Result<(), EngineError> {
        self.record("create");
        let mut s = self.0.lock().unwrap();
        let env_at = argv.iter().position(|a| a == "--env-file").unwrap();
        s.env_file_at_create = fs::read_to_string(&argv[env_at + 1]).ok();
        s.create_argv = Some(argv.to_vec());
        if s.fail_create {
            return Err(EngineError::new("podman create exited with 125: Error: boom".into()));
        }
        Ok(())
    }

    fn start_attached(&self, name: &str) -> Result<Attached, EngineError> {
        self.record(format!("start {name}"));
        let mut s = self.0.lock().unwrap();
        if s.fail_start {
            return Err(EngineError::new("podman start: boom".into()));
        }
        let (tx, rx) = oneshot::channel();
        if let Some(code) = s.exit_now {
            let _ = tx.send(code);
        } else if s.exit_errors {
            // The attached `podman start` dies: the exit code is lost, the container may still run.
            drop(tx);
        } else {
            s.exit_tx = Some(tx);
        }
        Ok(Attached {
            stdout: Box::pin(std::io::Cursor::new(std::mem::take(&mut s.stdout))),
            stderr: Box::pin(std::io::Cursor::new(std::mem::take(&mut s.stderr))),
            exit: Box::pin(async move { rx.await.map_err(|_| EngineError::new("no exit".into())) }),
        })
    }

    async fn kill(&self, _: &str, signal: StopSignal) -> Result<(), EngineError> {
        self.record(format!("kill {signal:?} at {}s", now_s()));
        let (on_term, ignores_kill) = {
            let s = self.0.lock().unwrap();
            (s.on_term, s.ignores_kill)
        };
        match signal {
            StopSignal::Term => {
                if let Some(code) = on_term {
                    self.exit(code);
                }
            }
            StopSignal::Kill if ignores_kill => {}
            StopSignal::Kill => self.exit(137),
        }
        Ok(())
    }

    async fn inspect(&self, _: &str) -> Result<ContainerState, EngineError> {
        self.record("inspect");
        let mut s = self.0.lock().unwrap();
        if s.inspect_fails {
            return Err(EngineError::new(
                "podman container inspect exited with 125: Error: boom".into(),
            ));
        }
        let size = if s.sizes.len() > 1 {
            s.sizes.pop_front()
        } else {
            s.sizes.front().copied()
        };
        Ok(ContainerState {
            oom_killed: s.oom_killed,
            size_rw: size.or(Some(0)),
            started: Some(!s.never_started),
        })
    }

    async fn remove(&self, name: &str) -> Result<(), EngineError> {
        self.record(format!("rm {name}"));
        Ok(())
    }

    async fn lease_containers(&self) -> Result<Vec<LeaseContainer>, EngineError> {
        self.record("ps");
        Ok(self.0.lock().unwrap().containers.clone())
    }

    async fn remove_tree(&self, path: &Path) -> Result<(), EngineError> {
        self.record("unshare rm");
        // What `podman unshare` can do and the agent cannot: get past the permissions.
        for p in walk(path) {
            if p.is_dir() {
                let _ = fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o700));
            }
        }
        fs::remove_dir_all(path).map_err(|e| EngineError::new(e.to_string()))
    }
}

thread_local! {
    static T0: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

/// Seconds of (paused) Tokio time since the test's [`mark_t0`].
fn now_s() -> u64 {
    T0.with(|t| t.get().map_or(0, |t0| Instant::now().duration_since(t0).as_secs()))
}

fn mark_t0() {
    T0.with(|t| t.set(Some(Instant::now())));
}

// ---------------------------------------------------------------------------------------------------------------
// The hang guard

/// Real time after which a driver test counts as hung. Every test here finishes in milliseconds; this is above the
/// 30 s FIFO watchdog of `prepare_does_its_file_work_off_the_runtime_thread`, so that one still reports its own
/// assertion.
const TEST_DEADLINE: Duration = Duration::from_secs(60);

/// Tokio's clock for one test.
#[derive(Debug, Clone, Copy)]
enum Clock {
    Real,
    /// Paused: time advances only when the runtime has nothing else to do.
    Paused,
}

/// Runs one async test on its own current-thread runtime, in its own thread, and fails it once [`TEST_DEADLINE`]
/// of **real** time passes without the body finishing.
///
/// The deadline is kept by the test's own thread with `std`'s clock, outside the runtime: an in-runtime
/// `tokio::time::timeout` cannot see a hang under a paused clock, because a task that keeps waking itself (a
/// `yield_now` loop) never lets the runtime go idle, so time never auto-advances. That is how 05-11's run spun at
/// 100 % CPU for 4 hours instead of failing. A hung body's thread is left behind and ends with the test process.
fn guarded<F, Fut>(clock: Clock, body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    guarded_within(TEST_DEADLINE, clock, body);
}

/// [`guarded`] with another deadline, for the guard's own test.
fn guarded_within<F, Fut>(deadline: Duration, clock: Clock, body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let name = std::thread::current().name().unwrap_or("driver-test").to_string();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::Builder::new()
        .name(name)
        .spawn(move || {
            let mut rt = tokio::runtime::Builder::new_current_thread();
            rt.enable_all();
            if matches!(clock, Clock::Paused) {
                rt.start_paused(true);
            }
            rt.build().unwrap().block_on(body());
            let _ = done_tx.send(());
        })
        .unwrap();
    match done_rx.recv_timeout(deadline) {
        // Finished, or panicked (the sender is dropped while unwinding): report the body's own panic.
        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            if let Err(panic) = worker.join() {
                std::panic::resume_unwind(panic);
            }
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("hung: the test did not finish within {deadline:?} of real time")
        }
    }
}

/// The 05-11 shape: a task waits for a condition that never comes by yielding in a loop, under a paused clock, with
/// a Tokio timeout around it. The timeout never fires (the runtime is never idle, so time never advances); the
/// guard's real-clock deadline does, and the test fails instead of spinning.
#[test]
fn the_guard_fails_a_test_that_spins_under_a_paused_clock() {
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let spin = Arc::clone(&release);
    let hung = std::panic::catch_unwind(move || {
        guarded_within(Duration::from_millis(200), Clock::Paused, move || async move {
            let waited = tokio::time::timeout(Duration::from_secs(5), async {
                while !spin.load(std::sync::atomic::Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
            })
            .await;
            assert!(waited.is_ok(), "the paused clock advanced while a task was spinning");
        });
    });
    // Let the left-behind spinner end, so it does not burn a core for the rest of the run.
    release.store(true, std::sync::atomic::Ordering::SeqCst);
    let panic = hung.expect_err("the guard did not fail the spinning test");
    let msg = panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(ToString::to_string))
        .unwrap_or_default();
    assert!(msg.starts_with("hung:"), "{msg}");
}

// ---------------------------------------------------------------------------------------------------------------
// Fixtures

/// A data disk far above the §9 floor. The tests never read the host's real free space: their temporary
/// directories may sit on a small tmpfs (on the build machine `$TMPDIR` is one, with less free space than the 5 GiB
/// floor), and then the driver rightly refuses every lease with `insufficient_capacity`.
#[derive(Debug)]
struct RoomyDisk;

impl disk::FreeSpace for RoomyDisk {
    fn space(&self, _: &Path) -> std::io::Result<disk::DiskSpace> {
        Ok(disk::DiskSpace {
            free_bytes: 90 << 30,
            total_bytes: 100 << 30,
        })
    }
}

struct Fx {
    data: TempDir,
    cg: TempDir,
    shim: PathBuf,
    owner: AccountId,
}

impl Fx {
    fn new() -> Self {
        let data = tempfile::tempdir().unwrap();
        let cg = tempfile::tempdir().unwrap();
        let shim = data.path().join("p2pc-shim");
        fs::write(&shim, b"\x7fELF shim").unwrap();
        Self {
            data,
            cg,
            shim,
            owner: AccountId::generate(),
        }
    }

    fn cfg(&self, platform: Platform) -> DriverConfig {
        let mut cfg = DriverConfig::new(self.data.path(), platform, &self.shim, true);
        cfg.free_space = Arc::new(RoomyDisk);
        cfg
    }

    fn driver(&self, engine: MockEngine) -> PodmanDriver<MockEngine, FsCgroups> {
        PodmanDriver::new(
            self.cfg(Platform::Wsl2),
            engine,
            FsCgroups::new(self.cg.path()),
            NoEgress,
        )
    }

    fn driver_with(&self, cfg: DriverConfig, engine: MockEngine) -> PodmanDriver<MockEngine, FsCgroups> {
        PodmanDriver::new(cfg, engine, FsCgroups::new(self.cg.path()), NoEgress)
    }

    fn lease(&self) -> LeaseContext {
        LeaseContext {
            lease_id: LeaseId::generate(),
            epoch: 1,
            account_id: self.owner,
            job: job(),
            gpu: None,
        }
    }

    fn lease_of(&self, image: &str) -> LeaseContext {
        let mut lease = self.lease();
        lease.job.image = image.into();
        lease
    }

    fn jobs_dir(&self) -> PathBuf {
        self.data.path().join("jobs")
    }

    /// Every path under the data dir, except the shim source.
    fn data_entries(&self) -> Vec<PathBuf> {
        walk(self.data.path()).into_iter().filter(|p| *p != self.shim).collect()
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).unwrap().flatten() {
        out.push(e.path());
        if e.file_type().unwrap().is_dir() {
            out.extend(walk(&e.path()));
        }
    }
    out
}

fn job() -> JobSpec {
    let mut env = BTreeMap::new();
    env.insert("API_TOKEN".to_string(), "s3cr3t-value".to_string());
    JobSpec {
        name: Some("weird; $(rm -rf /) `name`".into()),
        image: "docker.io/library/python:3.12-slim".into(),
        command: vec!["python".into(), "-c".into(), "print(6*7)".into()],
        env,
        files: vec![InputFile {
            path: "/inputs/data.csv".into(),
            content_b64: data_encoding::BASE64.encode(b"a,b\n1,2\n"),
        }],
        resources: Resources {
            cpu: 1.0,
            memory_mb: 512,
            gpu: 0,
            disk_mb: 1,
        },
        timeout_s: 5,
        egress: JobEgress::default(),
        outputs: Outputs { max_mb: 1 },
        placement: Placement::default(),
        retry: Retry::default(),
        idempotency_key: None,
        kind: p2pc_proto::api::JobKind::Batch,
        service: None,
        volumes: Vec::new(),
        inputs: Vec::new(),
        template: None,
    }
}

fn events() -> (mpsc::Sender<SandboxEvent>, mpsc::Receiver<SandboxEvent>) {
    mpsc::channel(1024)
}

async fn run(
    d: &PodmanDriver<MockEngine, FsCgroups>,
    fx: &Fx,
    lease: LeaseContext,
) -> (LeaseReport, Vec<SandboxEvent>) {
    let (tx, mut rx) = events();
    let report = run_lease(d, &fx.owner, lease, tx, CancelHandle::new()).await;
    let mut evs = Vec::new();
    while let Ok(e) = rx.try_recv() {
        evs.push(e);
    }
    (report, evs)
}

fn finished(r: LeaseReport) -> Finished {
    match r {
        LeaseReport::Finished { finished, .. } => finished,
        LeaseReport::Rejected(r) => panic!("rejected: {r}"),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// SI-1 and lease checks

/// SI-1: a lease of another account is refused before any file, cgroup or command exists.
#[test]
fn si1_not_owner_is_refused_before_anything() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.exit_now = Some(0));
        let d = fx.driver(engine.clone());
        let mut lease = fx.lease();
        lease.account_id = AccountId::generate();
        let (tx, mut rx) = events();
        let r = d.prepare(&fx.owner, lease, tx, CancelHandle::new()).await;
        assert_eq!(r.unwrap_err(), SandboxError::Rejected(LeaseRejectReason::NotOwner));
        assert_eq!(engine.calls(), Vec::<String>::new(), "no command ran");
        assert_eq!(fx.data_entries(), Vec::<PathBuf>::new(), "no file was created");
        assert_eq!(walk(fx.cg.path()), Vec::<PathBuf>::new(), "no cgroup was created");
        assert!(rx.try_recv().is_err(), "no event");
        // Also through run_lease, which T05b uses.
        let mut lease = fx.lease();
        lease.account_id = AccountId::generate();
        assert_eq!(
            run(&d, &fx, lease).await.0,
            LeaseReport::Rejected(LeaseRejectReason::NotOwner)
        );
        assert!(engine.calls().is_empty());
    });
}

#[test]
fn other_refusals_also_create_nothing() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::default();
        // Not ready: never fall back to a weaker sandbox.
        let mut cfg = fx.cfg(Platform::Linux);
        cfg.ready = false;
        let d = fx.driver_with(cfg, engine.clone());
        assert_eq!(
            run(&d, &fx, fx.lease()).await.0,
            LeaseReport::Rejected(LeaseRejectReason::UnsupportedSandbox)
        );
        // An env value with a newline would inject a variable into the env file.
        let d = fx.driver(engine.clone());
        let mut lease = fx.lease();
        lease.job.env.insert("X".into(), "a\nP2PC_EVIL=1".into());
        assert_eq!(
            run(&d, &fx, lease).await.0,
            LeaseReport::Rejected(LeaseRejectReason::InvalidJob)
        );
        assert!(engine.calls().is_empty());
        assert!(fx.data_entries().is_empty());
    });
}

#[test]
fn gpu_selection_per_profile() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let uuid = "GPU-6a3d0a2e-1b2c-4d5e-8f90-123456789abc".to_string();
        let other = "GPU-0b1c2d3e-0000-4000-8000-000000000001".to_string();
        let gpu_lease = |gpu: Option<&str>| {
            let mut l = fx.lease();
            l.job.resources.gpu = 1;
            l.gpu = gpu.map(|u| GpuRef { uuid: u.into() });
            l
        };

        // Linux: the assigned GPU, by UUID.
        let engine = MockEngine::with(|s| s.exit_now = Some(0));
        let mut cfg = fx.cfg(Platform::Linux);
        cfg.offerable_gpus = vec![uuid.clone(), other.clone()];
        let d = fx.driver_with(cfg.clone(), engine.clone());
        finished(run(&d, &fx, gpu_lease(Some(&uuid))).await.0);
        let argv = engine.0.lock().unwrap().create_argv.clone().unwrap();
        assert!(argv.contains(&format!("nvidia.com/gpu={uuid}")), "{argv:?}");
        // No assignment, or an unknown GPU: refused.
        for gpu in [None, Some("GPU-ffffffff-0000-4000-8000-000000000000")] {
            let d = fx.driver_with(cfg.clone(), MockEngine::default());
            assert_eq!(
                run(&d, &fx, gpu_lease(gpu)).await.0,
                LeaseReport::Rejected(LeaseRejectReason::InsufficientCapacity)
            );
        }

        // WSL2: `all`, only with exactly one offerable GPU.
        let engine = MockEngine::with(|s| s.exit_now = Some(0));
        let mut cfg = fx.cfg(Platform::Wsl2);
        cfg.offerable_gpus = vec![uuid.clone()];
        let d = fx.driver_with(cfg.clone(), engine.clone());
        finished(run(&d, &fx, gpu_lease(Some(&uuid))).await.0);
        let argv = engine.0.lock().unwrap().create_argv.clone().unwrap();
        assert!(argv.contains(&"nvidia.com/gpu=all".to_string()), "{argv:?}");
        cfg.offerable_gpus = vec![uuid.clone(), other.clone()];
        let engine = MockEngine::default();
        let d = fx.driver_with(cfg.clone(), engine.clone());
        assert_eq!(
            run(&d, &fx, gpu_lease(Some(&uuid))).await.0,
            LeaseReport::Rejected(LeaseRejectReason::GpuSelectionUnsupported)
        );
        cfg.offerable_gpus = Vec::new();
        let d = fx.driver_with(cfg, engine.clone());
        assert_eq!(
            run(&d, &fx, gpu_lease(None)).await.0,
            LeaseReport::Rejected(LeaseRejectReason::GpuSelectionUnsupported)
        );
        assert!(engine.calls().is_empty());
        // A CPU job never gets a device.
        let engine = MockEngine::with(|s| s.exit_now = Some(0));
        let d = fx.driver_with(fx.cfg(Platform::Linux), engine.clone());
        finished(run(&d, &fx, fx.lease()).await.0);
        assert!(
            !engine
                .0
                .lock()
                .unwrap()
                .create_argv
                .clone()
                .unwrap()
                .contains(&"--device".to_string())
        );
    });
}

#[test]
fn runsc_when_configured() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.exit_now = Some(0));
        let mut cfg = fx.cfg(Platform::Linux);
        cfg.runtime = Runtime::Runsc;
        let d = fx.driver_with(cfg, engine.clone());
        finished(run(&d, &fx, fx.lease()).await.0);
        assert!(
            engine
                .0
                .lock()
                .unwrap()
                .create_argv
                .clone()
                .unwrap()
                .contains(&"--runtime=runsc".to_string())
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------
// The happy path

#[test]
fn a_job_runs_end_to_end_and_everything_is_cleaned_up() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| {
            s.exit_now = Some(0);
            s.stdout = b"42\n".to_vec();
            s.stderr = b"warn\n".to_vec();
        });
        let d = fx.driver(engine.clone());
        let lease = fx.lease();
        let id = lease.lease_id;
        let (tx, mut rx) = events();
        let mut job = d.prepare(&fx.owner, lease, tx, CancelHandle::new()).await.unwrap();
        let dir = job.dir().root().to_path_buf();
        assert_eq!(dir, fx.jobs_dir().join(id.to_string()));
        assert_eq!(fs::read(dir.join("inputs/data.csv")).unwrap(), b"a,b\n1,2\n");
        assert_eq!(fs::read(dir.join("p2pc/shim")).unwrap(), b"\x7fELF shim");
        // The env file was there for `podman create` and is gone right after.
        assert_eq!(
            engine.0.lock().unwrap().env_file_at_create.as_deref(),
            Some("API_TOKEN=s3cr3t-value\n")
        );
        assert!(!dir.join("env").exists());
        assert!(fx.cg.path().join("p2pc").join(id.to_string()).is_dir());

        d.start(&mut job).await.unwrap();
        fs::write(dir.join("outputs/result.txt"), b"42\n").unwrap();
        let f = d.wait(&mut job).await.unwrap();
        assert_eq!(
            (f.outcome, f.exit_code, f.error.as_deref()),
            (Outcome::Exited, Some(0), None)
        );
        let outputs = d.collect_outputs(&job).await.unwrap();
        assert_eq!(outputs.files.len(), 1);
        assert_eq!(outputs.files[0].path, "result.txt");
        d.cleanup(job).await;

        assert!(!dir.exists(), "job dir removed");
        assert!(
            !fx.cg.path().join("p2pc").join(id.to_string()).exists(),
            "cgroup removed"
        );
        let calls = engine.calls();
        let name = format!("p2pc-{id}");
        assert_eq!(
            calls[..6],
            [
                "image_exists".to_string(),
                "manifest".into(),
                "pull docker.io/library/python:3.12-slim".into(),
                "image_size".into(),
                "create".into(),
                format!("start {name}"),
            ]
        );
        assert!(calls.ends_with(&[format!("rm {name}")]));
        let argv = engine.0.lock().unwrap().create_argv.clone().unwrap();
        assert_eq!(argv[0], "create");
        assert!(argv.contains(&"--network=none".to_string()));
        assert!(argv.contains(&"--userns=auto".to_string()));
        assert!(argv.contains(&format!("--cgroup-parent=/p2pc/{id}")));
        assert!(argv.ends_with(&[
            "--".into(),
            "docker.io/library/python:3.12-slim".into(),
            "--".into(),
            "python".into(),
            "-c".into(),
            "print(6*7)".into()
        ]));
        // The job's env value and name never reach the argv.
        assert!(
            !argv.iter().any(|a| a.contains("s3cr3t") || a.contains("rm -rf")),
            "{argv:?}"
        );

        let mut evs = Vec::new();
        while let Ok(e) = rx.try_recv() {
            evs.push(e);
        }
        assert_eq!(evs[0], SandboxEvent::Phase(Phase::Pulling));
        assert_eq!(evs[1], SandboxEvent::Phase(Phase::Creating));
        assert_eq!(evs[2], SandboxEvent::Started);
        let logs: Vec<(p2pc_proto::api::LogStream, Vec<u8>)> = evs[3..]
            .iter()
            .map(|e| match e {
                SandboxEvent::Log(c) => (c.stream, c.data.clone()),
                other => panic!("{other:?}"),
            })
            .collect();
        assert!(logs.contains(&(p2pc_proto::api::LogStream::Stdout, b"42\n".to_vec())));
        assert!(logs.contains(&(p2pc_proto::api::LogStream::Stderr, b"warn\n".to_vec())));
    });
}

#[test]
fn collect_outputs_removes_the_container_first() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.exit_now = Some(0));
        let d = fx.driver(engine.clone());
        let (tx, _rx) = events();
        let mut job = d.prepare(&fx.owner, fx.lease(), tx, CancelHandle::new()).await.unwrap();
        d.start(&mut job).await.unwrap();
        d.wait(&mut job).await.unwrap();
        let before = engine.calls().len();
        d.collect_outputs(&job).await.unwrap();
        assert_eq!(engine.calls()[before..], [format!("rm {}", job.container_name())]);
        d.cleanup(job).await;
    });
}

// ---------------------------------------------------------------------------------------------------------------
// Cleanup on errors and panics

/// §9 (ruling of 2026-11-05): the env file goes right after `podman create`, whether or not it succeeded, not only
/// when the cleanup guard later removes the job directory.
#[test]
fn the_env_file_goes_right_after_a_failed_create() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.fail_create = true);
        let d = fx.driver(engine.clone());
        let lease = fx.lease();
        let dir = fx.jobs_dir().join(lease.lease_id.to_string());
        let (tx, _rx) = events();
        let err = d.prepare(&fx.owner, lease, tx, CancelHandle::new()).await.unwrap_err();
        assert!(
            matches!(
                err,
                SandboxError::Failed {
                    code: error_code::CREATE_FAILED,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(
            engine.0.lock().unwrap().env_file_at_create.is_some(),
            "Podman got to read it"
        );
        // On this single-threaded runtime the guard's background cleanup has not run yet: the job directory is still
        // there, the env file is not.
        assert!(dir.join("inputs/data.csv").exists());
        assert!(!dir.join("env").exists());
        d.drain_background().await;
        assert!(!dir.exists());
    });
}

#[test]
fn cleanup_runs_after_an_error_mid_start() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.fail_create = true);
        let d = fx.driver(engine.clone());
        let lease = fx.lease();
        let id = lease.lease_id;
        let (report, _) = run(&d, &fx, lease).await;
        let f = finished(report);
        assert_eq!(
            (f.outcome, f.error.as_deref()),
            (Outcome::Error, Some(error_code::CREATE_FAILED))
        );
        d.drain_background().await;
        assert!(!fx.jobs_dir().join(id.to_string()).exists());
        assert!(!fx.cg.path().join("p2pc").join(id.to_string()).exists());
        assert!(engine.calls().contains(&format!("rm p2pc-{id}")));

        // A failed `podman start` too.
        let engine = MockEngine::with(|s| s.fail_start = true);
        let d = fx.driver(engine.clone());
        let lease = fx.lease();
        let id = lease.lease_id;
        let f = finished(run(&d, &fx, lease).await.0);
        assert_eq!(f.error.as_deref(), Some(error_code::START_FAILED));
        d.drain_background().await;
        assert!(!fx.jobs_dir().join(id.to_string()).exists());
        assert!(engine.calls().contains(&format!("rm p2pc-{id}")));
    });
}

#[test]
fn files_the_agent_cannot_delete_are_removed_through_podman_unshare() {
    guarded(Clock::Real, || async {
        if rustix::process::geteuid().is_root() {
            eprintln!("SKIPPED: root ignores directory permissions, so the failure cannot be staged");
            return;
        }
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.exit_now = Some(0));
        let d = fx.driver(engine.clone());
        let (tx, _rx) = events();
        let mut job = d.prepare(&fx.owner, fx.lease(), tx, CancelHandle::new()).await.unwrap();
        d.start(&mut job).await.unwrap();
        d.wait(&mut job).await.unwrap();
        // As if a non-root container user (a subordinate UID on the host) had written it.
        let locked = job.dir().outputs().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::write(locked.join("f"), b"x").unwrap();
        fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o500)).unwrap();
        let root = job.dir().root().to_path_buf();
        d.cleanup(job).await;
        assert!(engine.calls().contains(&"unshare rm".to_string()));
        assert!(!root.exists());
    });
}

/// Removing a job directory never blocks the runtime thread: on this single-threaded runtime, a task that only
/// yields keeps running while a large tree is deleted. (If the deletion ran inline, `remove_job_dir` would never
/// yield and the ticker would only see the tree gone.)
#[test]
fn removing_a_large_job_dir_does_not_block_the_runtime() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let root = fx.jobs_dir().join(LeaseId::generate().to_string());
        for d in 0..20 {
            let sub = root.join(format!("outputs/d{d}"));
            fs::create_dir_all(&sub).unwrap();
            for f in 0..200 {
                fs::write(sub.join(f.to_string()), b"x").unwrap();
            }
        }
        let ticks = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let ticker = {
            let (ticks, root) = (Arc::clone(&ticks), root.clone());
            tokio::spawn(async move {
                while root.exists() {
                    ticks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            })
        };
        remove_job_dir(&MockEngine::default(), &JobDir::at(root.clone()))
            .await
            .unwrap();
        assert!(!root.exists());
        ticker.await.unwrap();
        let ticks = ticks.load(std::sync::atomic::Ordering::Relaxed);
        assert!(ticks > 10, "the runtime was blocked during the removal: {ticks} ticks");
    });
}

#[test]
fn cleanup_runs_after_a_panic_in_a_task() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::default();
        let d = Arc::new(fx.driver(engine.clone()));
        let lease = fx.lease();
        let id = lease.lease_id;
        let owner = fx.owner;
        let task = {
            let d = Arc::clone(&d);
            tokio::spawn(async move {
                let (tx, _rx) = events();
                let job = d.prepare(&owner, lease, tx, CancelHandle::new()).await.unwrap();
                assert!(job.dir().root().exists());
                panic!("the task holding the job panics");
            })
        };
        assert!(task.await.unwrap_err().is_panic());
        d.drain_background().await;
        assert!(
            !fx.jobs_dir().join(id.to_string()).exists(),
            "job dir removed by the guard"
        );
        assert!(
            !fx.cg.path().join("p2pc").join(id.to_string()).exists(),
            "cgroup removed by the guard"
        );
        assert!(
            engine.calls().contains(&format!("rm p2pc-{id}")),
            "container removed by the guard"
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------
// Timeout, cancel and disk limit (paused time)

async fn prepare_and_start(
    d: &PodmanDriver<MockEngine, FsCgroups>,
    fx: &Fx,
    lease: LeaseContext,
    cancel: CancelHandle,
) -> PodmanJob<MockEngine, FsCgroups, ()> {
    let (tx, rx) = events();
    std::mem::forget(rx);
    let mut job = d.prepare(&fx.owner, lease, tx, cancel).await.unwrap();
    d.start(&mut job).await.unwrap();
    job
}

#[test]
fn timeout_sends_term_then_kill_after_the_grace() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        let engine = MockEngine::default(); // ignores SIGTERM
        let d = fx.driver(engine.clone());
        mark_t0();
        let mut job = prepare_and_start(&d, &fx, fx.lease(), CancelHandle::new()).await;
        let f = d.wait(&mut job).await.unwrap();
        assert_eq!((f.outcome, f.exit_code, f.error), (Outcome::TimedOut, None, None));
        let kills: Vec<String> = engine.calls().into_iter().filter(|c| c.starts_with("kill")).collect();
        assert_eq!(kills, ["kill Term at 5s", "kill Kill at 15s"]);
        assert_eq!(f.usage.wall_ms, 15_000);
        d.cleanup(job).await;
    });
}

#[test]
fn timeout_stops_at_term_when_the_job_obeys() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.on_term = Some(143));
        let d = fx.driver(engine.clone());
        mark_t0();
        let mut job = prepare_and_start(&d, &fx, fx.lease(), CancelHandle::new()).await;
        let f = d.wait(&mut job).await.unwrap();
        assert_eq!(f.outcome, Outcome::TimedOut);
        let kills: Vec<String> = engine.calls().into_iter().filter(|c| c.starts_with("kill")).collect();
        assert_eq!(kills, ["kill Term at 5s"]);
        d.cleanup(job).await;
    });
}

/// §9 "Podman failures are not job exits": when the exit is lost, the container is stopped with the usual
/// sequence, removed, and the outcome is `lost_exit_code`.
#[test]
fn a_lost_exit_stops_and_removes_the_container() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.exit_errors = true);
        let d = fx.driver(engine.clone());
        let mut lease = fx.lease();
        lease.job.timeout_s = 3600;
        mark_t0();
        let mut job = prepare_and_start(&d, &fx, lease, CancelHandle::new()).await;
        let name = job.container_name().to_string();
        let f = d.wait(&mut job).await.unwrap();
        assert_eq!(
            (f.outcome, f.exit_code, f.error.as_deref()),
            (Outcome::Error, None, Some(error_code::LOST_EXIT))
        );
        assert_eq!(kills(&engine), ["kill Term at 0s", "kill Kill at 10s"]);
        assert!(engine.calls().contains(&format!("rm {name}")), "removed by wait itself");
        d.cleanup(job).await;
    });
}

/// Podman's own 125 for a container that never started is `start_failed`; the same 125 from a job that ran is its
/// exit code.
#[test]
fn start_failed_is_told_apart_from_a_job_exit() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| {
            s.exit_now = Some(125);
            s.never_started = true;
        });
        let d = fx.driver(engine);
        let f = finished(run(&d, &fx, fx.lease()).await.0);
        assert_eq!(
            (f.outcome, f.exit_code, f.error.as_deref()),
            (Outcome::Error, None, Some(error_code::START_FAILED))
        );
        let d = fx.driver(MockEngine::with(|s| s.exit_now = Some(125)));
        let f = finished(run(&d, &fx, fx.lease()).await.0);
        assert_eq!((f.outcome, f.exit_code), (Outcome::Exited, Some(125)));
    });
}

/// A runtime that ignores SIGKILL: after the grace the agent gives up, reports `lost_exit_code`, and cleanup still
/// runs `podman rm -f`.
#[test]
fn a_container_that_ignores_sigkill_is_still_removed() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.ignores_kill = true);
        let d = fx.driver(engine.clone());
        let lease = fx.lease(); // timeout 5 s
        let name = format!("p2pc-{}", lease.lease_id);
        mark_t0();
        let (tx, _rx) = events();
        let report = run_lease(&d, &fx.owner, lease, tx, CancelHandle::new()).await;
        let f = finished(report);
        assert_eq!(
            (f.outcome, f.error.as_deref()),
            (Outcome::Error, Some(error_code::LOST_EXIT))
        );
        assert_eq!(kills(&engine), ["kill Term at 5s", "kill Kill at 15s"]);
        let rms = engine.calls().iter().filter(|c| **c == format!("rm {name}")).count();
        assert!(rms >= 2, "wait and cleanup both run rm -f: {:?}", engine.calls());
    });
}

#[test]
fn cancel_uses_the_same_sequence() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        let engine = MockEngine::default();
        let d = fx.driver(engine.clone());
        let cancel = CancelHandle::new();
        let mut lease = fx.lease();
        lease.job.timeout_s = 3600;
        mark_t0();
        let mut job = prepare_and_start(&d, &fx, lease, cancel.clone()).await;
        let canceller = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                cancel.cancel();
            })
        };
        let f = d.wait(&mut job).await.unwrap();
        canceller.await.unwrap();
        assert_eq!((f.outcome, f.exit_code), (Outcome::Cancelled, None));
        let kills: Vec<String> = engine.calls().into_iter().filter(|c| c.starts_with("kill")).collect();
        assert_eq!(kills, ["kill Term at 2s", "kill Kill at 12s"]);
        // Cancelling again is harmless.
        d.cancel(&cancel);
        d.cleanup(job).await;
    });
}

#[test]
fn cancel_during_the_pull() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.pull_hangs = true);
        let d = fx.driver(engine.clone());
        let cancel = CancelHandle::new();
        cancel.cancel();
        let lease = fx.lease();
        let id = lease.lease_id;
        let (tx, _rx) = events();
        let r = run_lease(&d, &fx.owner, lease, tx, cancel).await;
        assert_eq!(finished(r).outcome, Outcome::Cancelled);
        d.drain_background().await;
        assert!(!fx.jobs_dir().join(id.to_string()).exists());
    });
}

/// A cancel that arrives while the registry's manifest is being read (before any pull) ends the lease at once: it
/// does not wait for the read, and it pulls and removes nothing.
#[test]
fn cancel_while_the_manifest_is_read() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.manifest_hangs = true);
        let reading = engine.manifest_started();
        let d = fx.driver(engine.clone());
        let cancel = CancelHandle::new();
        let lease = fx.lease();
        let id = lease.lease_id;
        let (tx, _rx) = events();
        // The cancel follows an event from the fake (the read has started, and never finishes by itself), not a
        // poll and not the clock: nothing here can spin, and nothing races the paused clock's auto-advance. A lease
        // that ends before the read (a refusal, say) fails the test at once instead of leaving it waiting.
        let lease_run = run_lease(&d, &fx.owner, lease, tx, cancel.clone());
        tokio::pin!(lease_run);
        tokio::select! {
            biased;
            r = &mut lease_run => panic!("the lease ended before its manifest was read: {r:?}"),
            started = reading => started.expect("the fake engine is gone"),
        }
        cancel.cancel();
        // Only the hung read is left, so the runtime goes idle and the paused clock reaches this timeout at once
        // if the cancel does not interrupt the read.
        let r = tokio::time::timeout(Duration::from_secs(5), lease_run)
            .await
            .expect("the cancel did not interrupt the manifest read");
        assert_eq!(finished(r).outcome, Outcome::Cancelled);
        let calls = engine.calls();
        assert!(!calls.iter().any(|c| c.starts_with("pull")), "{calls:?}");
        assert_eq!(rmi_calls(&engine), 0, "nothing was pulled, so nothing is removed");
        d.drain_background().await;
        assert!(!fx.jobs_dir().join(id.to_string()).exists());
    });
}

#[test]
fn disk_limit_kills_with_disk_limit() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        // disk_mb = 1: the writable layer grows to 2 MiB at the third measurement.
        let engine = MockEngine::with(|s| s.sizes = VecDeque::from([0, 1024, 2 * 1024 * 1024]));
        let d = fx.driver(engine.clone());
        let mut lease = fx.lease();
        lease.job.timeout_s = 3600;
        mark_t0();
        let mut job = prepare_and_start(&d, &fx, lease, CancelHandle::new()).await;
        let f = d.wait(&mut job).await.unwrap();
        assert_eq!(
            (f.outcome, f.error.as_deref()),
            (Outcome::Error, Some(error_code::DISK_LIMIT))
        );
        let kills: Vec<String> = engine.calls().into_iter().filter(|c| c.starts_with("kill")).collect();
        assert_eq!(kills, ["kill Kill at 6s"], "every 2 s; no grace for the disk limit");
        d.cleanup(job).await;
    });
}

fn kills(engine: &MockEngine) -> Vec<String> {
    engine.calls().into_iter().filter(|c| c.starts_with("kill")).collect()
}

/// More entries in `outputs/` than the measurement budget is over the limit, however small they are.
#[test]
fn disk_limit_counts_reaching_the_entry_budget_as_over() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        let engine = MockEngine::default();
        let mut cfg = fx.cfg(Platform::Wsl2);
        cfg.disk_entry_budget = 5;
        let d = fx.driver_with(cfg, engine.clone());
        let mut lease = fx.lease();
        lease.job.timeout_s = 3600;
        mark_t0();
        let mut job = prepare_and_start(&d, &fx, lease, CancelHandle::new()).await;
        for i in 0..6 {
            fs::write(job.dir().outputs().join(i.to_string()), b"").unwrap();
        }
        let f = d.wait(&mut job).await.unwrap();
        assert_eq!(f.error.as_deref(), Some(error_code::DISK_LIMIT));
        assert_eq!(kills(&engine), ["kill Kill at 2s"]);
        d.cleanup(job).await;
    });
}

/// A measurement that fails three times in a row is over the limit, never "0 bytes".
#[test]
fn disk_limit_counts_three_failed_measurements_as_over() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.inspect_fails = true);
        let d = fx.driver(engine.clone());
        let mut lease = fx.lease();
        lease.job.timeout_s = 3600;
        mark_t0();
        let mut job = prepare_and_start(&d, &fx, lease, CancelHandle::new()).await;
        let f = d.wait(&mut job).await.unwrap();
        assert_eq!(f.error.as_deref(), Some(error_code::DISK_LIMIT));
        assert_eq!(kills(&engine), ["kill Kill at 6s"], "failures at 2, 4 and 6 s");
        d.cleanup(job).await;

        // A success in between resets the count.
        let engine = MockEngine::default();
        let d = fx.driver(engine.clone());
        let mut lease = fx.lease();
        lease.job.timeout_s = 9;
        mark_t0();
        let mut job = prepare_and_start(&d, &fx, lease, CancelHandle::new()).await;
        let flip = {
            let engine = engine.clone();
            let t0 = Instant::now();
            tokio::spawn(async move {
                // Fails at 2 and 4 s, succeeds at 6 s, fails at 8 s: never three in a row.
                for (at, fails) in [(1, true), (5, false), (7, true)] {
                    tokio::time::sleep_until(t0 + std::time::Duration::from_secs(at)).await;
                    engine.0.lock().unwrap().inspect_fails = fails;
                }
            })
        };
        let f = d.wait(&mut job).await.unwrap();
        flip.await.unwrap();
        assert_eq!(f.outcome, Outcome::TimedOut, "{f:?}");
        d.cleanup(job).await;
    });
}

/// The free space of the data disk, set by the test.
#[derive(Debug, Default)]
struct FakeSpace(Mutex<Option<disk::DiskSpace>>);

impl FakeSpace {
    fn set(&self, free_gib: Option<u64>) {
        *self.0.lock().unwrap() = free_gib.map(|g| disk::DiskSpace {
            free_bytes: g << 30,
            total_bytes: 100 << 30,
        });
    }
}

impl disk::FreeSpace for FakeSpace {
    fn space(&self, _: &Path) -> std::io::Result<disk::DiskSpace> {
        self.0
            .lock()
            .unwrap()
            .ok_or_else(|| std::io::Error::other("statvfs failed"))
    }
}

/// `prepare` does its file work (job dir, inputs, shim copy, env file) and its `statvfs` on the blocking pool, never
/// on the async runtime's thread: a slow disk must not stall the heartbeat that runs on the same runtime.
#[test]
fn prepare_does_its_file_work_off_the_runtime_thread() {
    guarded(Clock::Real, || async {
        /// Records which thread asked for the free space.
        #[derive(Debug, Default)]
        struct WhereSpace(Mutex<Vec<std::thread::ThreadId>>);
        impl disk::FreeSpace for WhereSpace {
            fn space(&self, _: &Path) -> std::io::Result<disk::DiskSpace> {
                self.0.lock().unwrap().push(std::thread::current().id());
                Ok(disk::DiskSpace {
                    free_bytes: 90 << 30,
                    total_bytes: 100 << 30,
                })
            }
        }
        let fx = Fx::new();
        let space = Arc::new(WhereSpace::default());
        let mut cfg = fx.cfg(Platform::Wsl2);
        cfg.free_space = space.clone();
        // The shim is a FIFO: copying it blocks until somebody writes to it. This current-thread runtime has only this
        // thread, so the copy can finish only if it runs somewhere else (the blocking pool) while this thread feeds it.
        let fifo = fx.data.path().join("shim.fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        cfg.shim_path = fifo.clone();
        // A watchdog, so that a regression is an assertion and not a hang: after 30 s of real time it writes to the
        // FIFO itself. The test's own feeder below runs at once when the copy is off-thread.
        let rescued = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let (fifo, rescued) = (fifo.clone(), rescued.clone());
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(30));
                rescued.store(true, std::sync::atomic::Ordering::SeqCst);
                if let Ok(mut f) = fs::OpenOptions::new().write(true).open(&fifo) {
                    let _ = std::io::Write::write_all(&mut f, b"x");
                }
            });
        }
        let d = fx.driver_with(cfg, MockEngine::default());
        let (tx, _rx) = events();
        let runtime_thread = std::thread::current().id();
        let feed = async {
            let fifo = fifo.clone();
            tokio::task::spawn_blocking(move || {
                let mut w = fs::OpenOptions::new().write(true).open(&fifo).unwrap();
                std::io::Write::write_all(&mut w, b"\x7fELF shim").unwrap();
            })
            .await
            .unwrap();
        };
        let (job, ()) = tokio::join!(d.prepare(&fx.owner, fx.lease(), tx, CancelHandle::new()), feed);
        let job = job.unwrap();
        assert!(
            !rescued.load(std::sync::atomic::Ordering::SeqCst),
            "prepare blocked the runtime thread"
        );
        let threads = space.0.lock().unwrap().clone();
        assert!(
            !threads.is_empty() && threads.iter().all(|t| *t != runtime_thread),
            "{threads:?}"
        );
        d.cleanup(job).await;
    });
}

/// §9 "Disk floor": below max(5 GiB, 5 %) new leases are refused, and running jobs are killed.
#[test]
fn the_disk_floor_refuses_leases_and_kills_jobs() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        let space = Arc::new(FakeSpace::default());
        let mut cfg = fx.cfg(Platform::Wsl2);
        cfg.free_space = space.clone();
        let engine = MockEngine::default();
        let d = fx.driver_with(cfg, engine.clone());

        // 100 GiB disk: the floor is 5 GiB.
        for free in [Some(4), None] {
            space.set(free);
            assert_eq!(
                run(&d, &fx, fx.lease()).await.0,
                LeaseReport::Rejected(LeaseRejectReason::InsufficientCapacity),
                "{free:?}"
            );
        }
        assert!(
            engine.calls().is_empty() && fx.data_entries().is_empty(),
            "nothing was created"
        );

        space.set(Some(50));
        let mut lease = fx.lease();
        lease.job.timeout_s = 3600;
        mark_t0();
        let mut job = prepare_and_start(&d, &fx, lease, CancelHandle::new()).await;
        let drop_space = {
            let space = space.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                space.set(Some(1));
            })
        };
        let f = d.wait(&mut job).await.unwrap();
        drop_space.await.unwrap();
        assert_eq!(
            (f.outcome, f.error.as_deref()),
            (Outcome::Error, Some(error_code::DISK_FLOOR))
        );
        assert_eq!(kills(&engine), ["kill Kill at 4s"]);
        d.cleanup(job).await;
        // Space recovers: leases are taken again.
        space.set(Some(50));
        let engine2 = MockEngine::with(|s| s.exit_now = Some(0));
        let mut cfg = fx.cfg(Platform::Wsl2);
        cfg.free_space = space.clone();
        let d = fx.driver_with(cfg, engine2);
        assert_eq!(finished(run(&d, &fx, fx.lease()).await.0).outcome, Outcome::Exited);
    });
}

#[test]
fn disk_limit_counts_outputs_too() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.sizes = VecDeque::from([0]));
        let d = fx.driver(engine.clone());
        let mut lease = fx.lease();
        lease.job.timeout_s = 3600;
        mark_t0();
        let mut job = prepare_and_start(&d, &fx, lease, CancelHandle::new()).await;
        fs::write(job.dir().outputs().join("big"), vec![0u8; 1024 * 1024 + 1]).unwrap();
        let f = d.wait(&mut job).await.unwrap();
        assert_eq!(f.error.as_deref(), Some(error_code::DISK_LIMIT));
        assert_eq!(kills(&engine), ["kill Kill at 2s"]);
        d.cleanup(job).await;
    });
}

// ---------------------------------------------------------------------------------------------------------------
// Memory limit

async fn oom_case(oom_kill_in_cgroup: bool, podman_oom_killed: bool) -> Finished {
    let fx = Fx::new();
    let engine = MockEngine::with(|s| s.oom_killed = podman_oom_killed);
    let d = fx.driver(engine.clone());
    let mut job = prepare_and_start(&d, &fx, fx.lease(), CancelHandle::new()).await;
    if oom_kill_in_cgroup {
        // What the WSL2 test node showed: the lease cgroup counts the kill; Podman says nothing.
        let dir = fx.cg.path().join("p2pc").join(job.lease_id().to_string());
        fs::write(dir.join("memory.events"), "low 0\nhigh 0\nmax 9\noom 1\noom_kill 1\n").unwrap();
    }
    engine.exit(137);
    let f = d.wait(&mut job).await.unwrap();
    d.cleanup(job).await;
    f
}

#[test]
fn oom_from_the_lease_cgroup_with_oomkilled_false() {
    guarded(Clock::Real, || async {
        let f = oom_case(true, false).await;
        assert_eq!(
            (f.outcome, f.error.as_deref()),
            (Outcome::Error, Some(error_code::MEMORY_LIMIT))
        );
        assert_eq!(f.stats.oom_kill, 1);
    });
}

#[test]
fn oom_from_podman_oomkilled_true() {
    guarded(Clock::Real, || async {
        let f = oom_case(false, true).await;
        assert_eq!(
            (f.outcome, f.error.as_deref()),
            (Outcome::Error, Some(error_code::MEMORY_LIMIT))
        );
    });
}

#[test]
fn exit_137_alone_is_not_memory_limit() {
    guarded(Clock::Real, || async {
        let f = oom_case(false, false).await;
        assert_eq!((f.outcome, f.exit_code, f.error), (Outcome::Exited, Some(137), None));
    });
}

// ---------------------------------------------------------------------------------------------------------------
// Image cap, egress

#[test]
fn an_image_over_the_cap_is_refused_without_pulling_it() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        // The registry's manifest already says 30 GiB (the cap is 20 GiB).
        let engine = MockEngine::with(|s| s.manifest_size = 30 << 30);
        let d = fx.driver(engine.clone());
        let f = finished(run(&d, &fx, fx.lease()).await.0);
        assert_eq!(f.error.as_deref(), Some(error_code::IMAGE_TOO_LARGE));
        let calls = engine.calls();
        assert!(!calls.iter().any(|c| c.starts_with("pull")), "never pulled: {calls:?}");
        assert!(
            !calls.iter().any(|c| c.starts_with("rmi")),
            "nothing to remove: {calls:?}"
        );
        assert!(!calls.contains(&"create".to_string()));
    });
}

fn rmi_calls(engine: &MockEngine) -> usize {
    engine.calls().iter().filter(|c| c.starts_with("rmi")).count()
}

#[test]
fn an_unreadable_manifest_falls_back_to_the_size_after_the_pull() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| {
            s.manifest_unreadable = true;
            s.image_size = 30 << 30;
        });
        let d = fx.driver(engine.clone());
        let f = finished(run(&d, &fx, fx.lease()).await.0);
        assert_eq!(f.error.as_deref(), Some(error_code::IMAGE_TOO_LARGE));
        assert_eq!(
            rmi_calls(&engine),
            1,
            "what the pull brought in is removed: {:?}",
            engine.calls()
        );
        assert!(!engine.calls().contains(&"create".to_string()));

        // Within the cap, the job runs.
        let engine = MockEngine::with(|s| {
            s.manifest_unreadable = true;
            s.exit_now = Some(0);
        });
        let d = fx.driver(engine.clone());
        assert_eq!(finished(run(&d, &fx, fx.lease()).await.0).outcome, Outcome::Exited);
    });
}

#[test]
fn a_failed_pull_removes_what_it_left_but_never_a_present_image() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.fail_pull = true);
        let d = fx.driver(engine.clone());
        let f = finished(run(&d, &fx, fx.lease()).await.0);
        assert_eq!(f.error.as_deref(), Some(error_code::IMAGE_PULL_FAILED));
        assert_eq!(rmi_calls(&engine), 1);

        // The image was already in local storage (other jobs use it): never removed, refused or not.
        for (fail_pull, image_size) in [(true, 0), (false, 30 << 30)] {
            let engine = MockEngine::with(|s| {
                s.image_present = true;
                s.manifest_unreadable = true;
                s.fail_pull = fail_pull;
                s.image_size = image_size;
            });
            let d = fx.driver(engine.clone());
            // `latest` is pulled even when present (a tag other than `latest` would not be pulled at all).
            let f = finished(run(&d, &fx, fx.lease_of("docker.io/library/python:latest")).await.0);
            assert_eq!(f.outcome, Outcome::Error);
            assert_eq!(rmi_calls(&engine), 0, "{:?}", engine.calls());
        }
    });
}

// ---------------------------------------------------------------------------------------------------------------
// Images: pull only what is missing, share concurrent pulls (§9 "Images")

const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A present image that is not `latest` is used as it is: no manifest read, no pull. The cap is checked on its local
/// size.
#[test]
fn a_present_tag_is_neither_read_from_the_registry_nor_pulled() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        for image in [
            "docker.io/library/python:3.12-slim",
            "python:3.12-slim",
            "ghcr.io/example/tool:v1",
        ] {
            let engine = MockEngine::with(|s| {
                s.image_present = true;
                s.image_size = 124 << 20;
                s.exit_now = Some(0);
            });
            let d = fx.driver(engine.clone());
            let f = finished(run(&d, &fx, fx.lease_of(image)).await.0);
            assert_eq!(f.outcome, Outcome::Exited, "{image}");
            let calls = engine.calls();
            assert_eq!(engine.count("manifest"), 0, "{image}: {calls:?}");
            assert_eq!(engine.count("pull"), 0, "{image}: {calls:?}");
            assert_eq!(engine.count("rmi"), 0, "{image}: {calls:?}");
            assert_eq!(
                calls[..3],
                ["image_exists", "image_size", "create"],
                "{image}: {calls:?}"
            );
        }
    });
}

/// A digest never changes: a present one is used with no registry request, even when it also has a tag.
#[test]
fn a_present_digest_makes_no_registry_request() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        for image in [
            format!("docker.io/library/python@{DIGEST}"),
            format!("docker.io/library/python:3.12-slim@{DIGEST}"),
            format!("docker.io/library/python:latest@{DIGEST}"),
        ] {
            let engine = MockEngine::with(|s| {
                s.image_present = true;
                s.exit_now = Some(0);
            });
            let d = fx.driver(engine.clone());
            let f = finished(run(&d, &fx, fx.lease_of(&image)).await.0);
            assert_eq!(f.outcome, Outcome::Exited, "{image}");
            assert_eq!(
                engine.count("manifest") + engine.count("pull"),
                0,
                "{image}: {:?}",
                engine.calls()
            );
        }
    });
}

/// `latest`, spelled out or implied, is pulled for every attempt, present or not (like Kubernetes' default).
#[test]
fn latest_is_read_and_pulled_even_when_present() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        for image in [
            "docker.io/library/python:latest",
            "docker.io/library/python",
            "python",
            "ghcr.io/example/tool",
        ] {
            let engine = MockEngine::with(|s| {
                s.image_present = true;
                s.exit_now = Some(0);
            });
            let d = fx.driver(engine.clone());
            let f = finished(run(&d, &fx, fx.lease_of(image)).await.0);
            assert_eq!(f.outcome, Outcome::Exited, "{image}");
            assert_eq!(
                engine.calls()[..4],
                ["image_exists", "manifest", &format!("pull {image}"), "image_size"],
                "{image}"
            );
        }
    });
}

/// An absent image is read and pulled, as it always was (a tag other than `latest` makes no difference).
#[test]
fn an_absent_image_is_read_and_pulled() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.exit_now = Some(0));
        let d = fx.driver(engine.clone());
        let image = "docker.io/library/python:3.12-slim";
        finished(run(&d, &fx, fx.lease_of(image)).await.0);
        assert_eq!(
            engine.calls()[..4],
            ["image_exists", "manifest", &format!("pull {image}"), "image_size"]
        );
        // The pull put it in the store: the next job on it makes no registry request.
        finished(run(&d, &fx, fx.lease_of(image)).await.0);
        assert_eq!(
            (engine.count("manifest"), engine.count("pull")),
            (1, 1),
            "{:?}",
            engine.calls()
        );
    });
}

/// The cap was lowered after the pull: the present image is over it, so the lease is refused with `image_too_large`
/// and the image stays (other jobs may use it).
#[test]
fn a_present_image_over_the_cap_is_refused_and_not_removed() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| {
            s.image_present = true;
            s.image_size = 3 << 20;
        });
        let mut cfg = fx.cfg(Platform::Wsl2);
        cfg.max_image_mb = 2;
        let d = fx.driver_with(cfg, engine.clone());
        let f = finished(run(&d, &fx, fx.lease()).await.0);
        assert_eq!(f.error.as_deref(), Some(error_code::IMAGE_TOO_LARGE));
        let calls = engine.calls();
        assert_eq!(calls[..2], ["image_exists", "image_size"], "{calls:?}");
        assert_eq!(engine.count("manifest") + engine.count("pull"), 0, "{calls:?}");
        assert_eq!(rmi_calls(&engine), 0, "{calls:?}");
        assert!(!calls.contains(&"create".to_string()));
        // Just under the cap, it runs.
        let engine = MockEngine::with(|s| {
            s.image_present = true;
            s.image_size = 2 << 20;
            s.exit_now = Some(0);
        });
        let mut cfg = fx.cfg(Platform::Wsl2);
        cfg.max_image_mb = 2;
        let d = fx.driver_with(cfg, engine.clone());
        assert_eq!(finished(run(&d, &fx, fx.lease()).await.0).outcome, Outcome::Exited);
    });
}

type TestDriver = PodmanDriver<MockEngine, FsCgroups>;
type TestJob = <TestDriver as Sandbox>::Job;

/// Gives a few turns to the tasks that are not blocked: it lets every lease run up to the point where it waits for
/// something (the gated pull, or the pull of another lease). No clock is involved.
async fn settle() {
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
}

/// Starts `n` leases on `image` at once and returns when each has reached its pull phase and run as far as it can.
async fn leases_at_the_pull(
    d: &Arc<TestDriver>,
    fx: &Fx,
    image: &str,
    n: usize,
) -> (
    Vec<tokio::task::JoinHandle<Result<TestJob, SandboxError>>>,
    Vec<mpsc::Receiver<SandboxEvent>>,
) {
    let (mut tasks, mut receivers) = (Vec::new(), Vec::new());
    for _ in 0..n {
        let (tx, rx) = events();
        let (d, owner, lease) = (Arc::clone(d), fx.owner, fx.lease_of(image));
        tasks.push(tokio::spawn(async move {
            d.prepare(&owner, lease, tx, CancelHandle::new()).await
        }));
        receivers.push(rx);
    }
    for rx in &mut receivers {
        assert_eq!(rx.recv().await, Some(SandboxEvent::Phase(Phase::Pulling)));
    }
    settle().await;
    (tasks, receivers)
}

/// Five leases for the same absent image: one pull, and all five go on to start.
#[test]
fn concurrent_leases_for_an_absent_image_share_one_pull() {
    guarded(Clock::Real, || async {
        for image in [
            "docker.io/library/python:3.12-slim",
            // `latest` is pulled for every attempt, but a lease that waited for a pull that worked has the image
            // as fresh as a pull of its own would make it.
            "docker.io/library/python:latest",
            "docker.io/library/python@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            let fx = Fx::new();
            let engine = MockEngine::with(|s| s.exit_now = Some(0));
            let gate = engine.gate_pulls();
            let d = Arc::new(fx.driver(engine.clone()));
            let (tasks, _events) = leases_at_the_pull(&d, &fx, image, 5).await;
            gate.add_permits(100);
            for task in tasks {
                let mut job = task.await.unwrap().unwrap_or_else(|e| panic!("{image}: {e:?}"));
                d.start(&mut job).await.unwrap();
                assert_eq!(d.wait(&mut job).await.unwrap().outcome, Outcome::Exited);
                d.cleanup(job).await;
            }
            assert_eq!(engine.count("pull"), 1, "{image}: {:?}", engine.calls());
            assert_eq!(engine.count("manifest"), 1, "{image}: {:?}", engine.calls());
            assert_eq!(engine.count("create"), 5, "{image}");
        }
    });
}

/// A pull that failed is not retried by every lease that waited for it: one of them tries again, in case the failure
/// was a blip, and the others take that result. N leases never mean N pulls one after the other.
#[test]
fn after_a_failed_pull_one_waiting_lease_retries_and_the_rest_take_its_result() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.fail_pull = true);
        let gate = engine.gate_pulls();
        let d = Arc::new(fx.driver(engine.clone()));
        let (tasks, _events) = leases_at_the_pull(&d, &fx, "docker.io/library/python:3.12-slim", 5).await;
        assert_eq!(engine.count("pull"), 1, "the others wait: {:?}", engine.calls());
        gate.add_permits(100);
        for task in tasks {
            let e = task.await.unwrap().unwrap_err();
            assert!(
                matches!(&e, SandboxError::Failed { code, .. } if *code == error_code::IMAGE_PULL_FAILED),
                "{e:?}"
            );
        }
        assert_eq!(
            engine.count("pull"),
            2,
            "the first pull, and one retry: {:?}",
            engine.calls()
        );
        assert!(d.shared.pulls.is_empty(), "the pull step is forgotten");
    });
}

/// A retry that works serves everyone who waited: the failure of the first pull is not passed on.
#[test]
fn a_retry_that_works_serves_the_other_waiters() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| {
            s.pulls_failing = 1;
            s.exit_now = Some(0);
        });
        let gate = engine.gate_pulls();
        let d = Arc::new(fx.driver(engine.clone()));
        let (tasks, _events) = leases_at_the_pull(&d, &fx, "docker.io/library/python:3.12-slim", 4).await;
        gate.add_permits(100);
        let (mut failed, mut served) = (0, 0);
        for task in tasks {
            match task.await.unwrap() {
                Ok(job) => {
                    served += 1;
                    d.cleanup(job).await;
                }
                Err(_) => failed += 1,
            }
        }
        // The first pull failed; the retry worked, and the three leases behind it use its image.
        assert_eq!((failed, served), (1, 3));
        assert_eq!(engine.count("pull"), 2, "{:?}", engine.calls());
    });
}

/// A hung registry costs one pull timeout, not one per waiting lease: the leases behind a pull that timed out take
/// its result at once (a retry would very likely hang for another full timeout).
#[test]
fn five_waiters_on_a_hung_pull_end_within_one_pull_timeout() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.pull_times_out = true);
        let d = Arc::new(fx.driver(engine.clone()));
        let started = Instant::now();
        // The leader and five waiters.
        let (tasks, _events) = leases_at_the_pull(&d, &fx, "docker.io/library/python:3.12-slim", 6).await;
        assert_eq!(engine.count("pull"), 1, "the others wait: {:?}", engine.calls());
        for task in tasks {
            let e = task.await.unwrap().unwrap_err();
            assert!(
                matches!(&e, SandboxError::Failed { code, detail }
                    if *code == error_code::IMAGE_PULL_FAILED && detail.contains("timed out")),
                "{e:?}"
            );
        }
        let took = started.elapsed();
        assert!(
            took >= PULL_TIMEOUT && took < PULL_TIMEOUT + Duration::from_secs(60),
            "one pull timeout, not six: {took:?}"
        );
        assert_eq!(engine.count("pull"), 1, "{:?}", engine.calls());
        assert!(d.shared.pulls.is_empty());
    });
}

/// Whether a pull timed out is a fact about how it ended, not about its text: an error that Podman or the registry
/// words as "timed out after" is an ordinary failure, so one waiting lease still retries it.
#[test]
fn error_text_that_says_timed_out_does_not_make_a_failure_final() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| {
            s.fail_pull = true;
            s.pull_error =
                Some("podman pull exited with 125: Error: registry.example.invalid: timed out after 5 s".into());
        });
        let gate = engine.gate_pulls();
        let d = Arc::new(fx.driver(engine.clone()));
        let (tasks, _events) = leases_at_the_pull(&d, &fx, "docker.io/library/python:3.12-slim", 4).await;
        gate.add_permits(100);
        for task in tasks {
            assert!(task.await.unwrap().is_err());
        }
        assert_eq!(
            engine.count("pull"),
            2,
            "the first pull, and one retry: {:?}",
            engine.calls()
        );
    });
}

/// A pulled image that is over the cap is removed, and the leases that waited for that pull take the refusal: they do
/// not pull the same large image again.
#[test]
fn waiters_take_an_image_too_large_refusal_without_pulling_again() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| {
            s.manifest_unreadable = true;
            s.image_size = 30 << 30;
        });
        let gate = engine.gate_pulls();
        let d = Arc::new(fx.driver(engine.clone()));
        let (tasks, _events) = leases_at_the_pull(&d, &fx, "docker.io/library/python:3.12-slim", 4).await;
        gate.add_permits(100);
        for task in tasks {
            let e = task.await.unwrap().unwrap_err();
            assert!(
                matches!(&e, SandboxError::Failed { code, .. } if *code == error_code::IMAGE_TOO_LARGE),
                "{e:?}"
            );
        }
        assert_eq!(engine.count("pull"), 1, "{:?}", engine.calls());
    });
}

/// The store cannot be asked: the full path runs (manifest, pull, size check) even for a tag, and, when in doubt,
/// the image counts as present, so a failed or refused pull never removes it.
#[test]
fn when_image_exists_fails_the_full_path_runs_and_nothing_is_removed() {
    guarded(Clock::Real, || async {
        for (fail_pull, image_size) in [(true, 0), (false, 30 << 30)] {
            let fx = Fx::new();
            let engine = MockEngine::with(|s| {
                s.image_exists_fails = true;
                s.fail_pull = fail_pull;
                s.image_size = image_size;
            });
            let d = fx.driver(engine.clone());
            let f = finished(run(&d, &fx, fx.lease_of("docker.io/library/python:3.12-slim")).await.0);
            assert_eq!(f.outcome, Outcome::Error, "{fail_pull}");
            assert_eq!(engine.count("manifest"), 1, "{:?}", engine.calls());
            assert_eq!(engine.count("pull"), 1, "{:?}", engine.calls());
            assert_eq!(rmi_calls(&engine), 0, "{:?}", engine.calls());
        }
    });
}

/// A present image whose size cannot be read is not trusted: the full path runs, and the image is not removed when
/// that fails.
#[test]
fn when_image_size_fails_on_a_present_image_the_full_path_runs() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| {
            s.image_present = true;
            s.image_size_fails = true;
        });
        let d = fx.driver(engine.clone());
        let f = finished(run(&d, &fx, fx.lease_of("docker.io/library/python:3.12-slim")).await.0);
        assert_eq!(f.outcome, Outcome::Error);
        assert_eq!(engine.count("manifest"), 1, "{:?}", engine.calls());
        assert_eq!(engine.count("pull"), 1, "{:?}", engine.calls());
        assert_eq!(rmi_calls(&engine), 0, "it was there before: {:?}", engine.calls());
    });
}

/// A cancel ends a lease that waits for another lease's pull at once, and it starts no pull of its own.
#[test]
fn a_cancel_ends_a_lease_waiting_for_a_pull() {
    guarded(Clock::Paused, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.pull_hangs = true);
        let d = Arc::new(fx.driver(engine.clone()));
        let (first, _events) = leases_at_the_pull(&d, &fx, "docker.io/library/python:3.12-slim", 1).await;
        assert_eq!(engine.count("pull"), 1);

        let cancel = CancelHandle::new();
        let (tx, mut rx) = events();
        let waiting = {
            let (d, owner, lease, cancel) = (Arc::clone(&d), fx.owner, fx.lease(), cancel.clone());
            tokio::spawn(async move { run_lease(&*d, &owner, lease, tx, cancel).await })
        };
        assert_eq!(rx.recv().await, Some(SandboxEvent::Phase(Phase::Pulling)));
        settle().await;
        cancel.cancel();
        let r = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the cancel did not end the waiting lease")
            .unwrap();
        assert_eq!(finished(r).outcome, Outcome::Cancelled);
        assert_eq!(engine.count("pull"), 1, "{:?}", engine.calls());
        assert_eq!(rmi_calls(&engine), 0);
        // The map and the lease that is pulling hold the entry; the cancelled waiter has let go of it.
        assert_eq!(d.shared.pulls.holders(), [2]);
        for task in first {
            task.abort();
            let _ = task.await;
        }
        assert!(d.shared.pulls.is_empty(), "the pull step is forgotten");
    });
}

#[derive(Clone, Default)]
struct FakeEgress(Arc<Mutex<Vec<EgressRequest>>>);

impl Egress for FakeEgress {
    type Session = ();
    fn start(&self, request: &EgressRequest) -> Result<(), String> {
        // The proxy creates its socket in p2pc/ (a plain file stands in for it here).
        fs::write(&request.socket_path, b"").map_err(|e| e.to_string())?;
        self.0.lock().unwrap().push(request.clone());
        Ok(())
    }
}

#[test]
fn egress_gets_the_socket_dir_and_the_public_addrs() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.exit_now = Some(0));
        let mut cfg = fx.cfg(Platform::Wsl2);
        let (addrs_tx, addrs_rx) = tokio::sync::watch::channel(vec!["198.51.100.7".parse().unwrap()]);
        cfg.public_addrs = addrs_rx;
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(p2pc_net::EgressGate::Open);
        cfg.egress_ready = ready_rx;
        let egress = FakeEgress::default();
        let d = PodmanDriver::new(cfg, engine.clone(), FsCgroups::new(fx.cg.path()), egress.clone());
        let mut lease = fx.lease();
        lease.job.egress.allow = vec!["pypi.org".into()];
        let (tx, _rx) = events();
        let job = d.prepare(&fx.owner, lease, tx, CancelHandle::new()).await.unwrap();
        let requests = egress.0.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].socket_path, job.dir().root().join("p2pc/egress.sock"));
        assert_eq!(requests[0].allow, ["pypi.org"]);
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert_eq!(*requests[0].public_addrs.borrow(), [ip("198.51.100.7")]);
        // A live source: a later observation reaches the running proxy.
        addrs_tx.send_replace(vec![ip("203.0.113.9")]);
        assert_eq!(*requests[0].public_addrs.borrow(), [ip("203.0.113.9")]);
        // The gate's readiness is live too, apart from the addresses.
        assert!(requests[0].egress_ready.borrow().is_open());
        ready_tx.send_replace(p2pc_net::EgressGate::Closed);
        assert!(!requests[0].egress_ready.borrow().is_open());
        assert_eq!(*requests[0].public_addrs.borrow(), [ip("203.0.113.9")]);
        // Still no network: the socket directory is the only way out.
        let argv = engine.0.lock().unwrap().create_argv.clone().unwrap();
        assert!(argv.contains(&"--network=none".to_string()));
        assert!(argv.iter().any(|a| a.ends_with("/p2pc:/.p2pc:ro,U")));
        d.cleanup(job).await;

        // Without a proxy, a job that asks for egress fails closed.
        let d = fx.driver(MockEngine::default());
        let mut lease = fx.lease();
        lease.job.egress.allow = vec!["pypi.org".into()];
        let f = finished(run(&d, &fx, lease).await.0);
        assert_eq!(f.error.as_deref(), Some(error_code::EGRESS_UNAVAILABLE));
    });
}

/// An egress provider whose proxy cannot start.
struct BrokenEgress(&'static str);

impl Egress for BrokenEgress {
    type Session = ();
    fn start(&self, _: &EgressRequest) -> Result<(), String> {
        Err(self.0.to_string())
    }
}

/// T10n: the short code goes to the server; the cause stays in the error, for the agent's log.
#[test]
fn a_proxy_that_cannot_start_says_why() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let cause = "bind /var/lib/p2pc/jobs/x/egress.sock: path must be shorter than SUN_LEN";
        let d = PodmanDriver::new(
            fx.cfg(Platform::Wsl2),
            MockEngine::default(),
            FsCgroups::new(fx.cg.path()),
            BrokenEgress(cause),
        );
        let mut lease = fx.lease();
        lease.job.egress.allow = vec!["pypi.org".into()];
        let dir = fx.jobs_dir().join(lease.lease_id.to_string());
        let (tx, _rx) = events();
        let err = d.prepare(&fx.owner, lease, tx, CancelHandle::new()).await.unwrap_err();
        let SandboxError::Failed { code, detail } = err else {
            panic!("{err:?}")
        };
        assert_eq!(code, error_code::EGRESS_UNAVAILABLE);
        assert_eq!(detail, format!("egress proxy could not start: {cause}"));
        // The job directory goes with the failed attempt.
        d.drain_background().await;
        assert!(!dir.exists());
    });
}

/// T10n review: `run_lease` (the helper the smoke test and the tests use) logs the cause at `warn` too, and still
/// reports only the short code. The capture is the binary's one global subscriber (`test_logs`), read by lease id.
#[test]
fn run_lease_logs_why_a_proxy_could_not_start() {
    crate::test_logs::install();
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let cause = "bind /var/lib/p2pc/jobs/x/egress.sock: path must be shorter than SUN_LEN";
        let d = PodmanDriver::new(
            fx.cfg(Platform::Wsl2),
            MockEngine::default(),
            FsCgroups::new(fx.cg.path()),
            BrokenEgress(cause),
        );
        let mut lease = fx.lease();
        lease.job.egress.allow = vec!["pypi.org".into()];
        let lease_id = lease.lease_id;
        let (tx, _rx) = events();
        let report = run_lease(&d, &fx.owner, lease, tx, CancelHandle::new()).await;
        // The wire still carries only the code.
        assert_eq!(finished(report).error.as_deref(), Some(error_code::EGRESS_UNAVAILABLE));
        let lines = crate::test_logs::warnings(&lease_id);
        let line = lines
            .iter()
            .find(|l| l.contains("egress proxy could not start"))
            .unwrap_or_else(|| panic!("the cause is not logged: {lines:?}"));
        assert!(line.starts_with("WARN"), "{line}");
        assert!(line.contains("path must be shorter than SUN_LEN"), "{line}");
        assert!(line.contains(error_code::EGRESS_UNAVAILABLE), "{line}");
        d.drain_background().await;
    });
}

// ---------------------------------------------------------------------------------------------------------------
// Orphan sweep and smoke

#[test]
fn the_orphan_sweep_removes_only_unclaimed_leases() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let active = LeaseId::generate();
        let stale = LeaseId::generate();
        let engine = MockEngine::with(|s| {
            s.containers = vec![
                LeaseContainer {
                    name: format!("p2pc-{active}"),
                    lease: active.to_string(),
                },
                LeaseContainer {
                    name: format!("p2pc-{stale}"),
                    lease: stale.to_string(),
                },
                LeaseContainer {
                    name: "not-ours".into(),
                    lease: stale.to_string(),
                },
            ];
        });
        let d = fx.driver(engine.clone());
        for id in [active, stale] {
            fs::create_dir_all(fx.jobs_dir().join(id.to_string()).join("outputs")).unwrap();
            fs::create_dir_all(fx.cg.path().join("p2pc").join(id.to_string())).unwrap();
        }
        fs::create_dir_all(fx.jobs_dir().join("not-a-lease")).unwrap();
        let report = d.sweep_orphans(&HashSet::from([active])).await;
        assert_eq!(report.containers, [format!("p2pc-{stale}")]);
        assert_eq!(report.job_dirs, [stale.to_string()]);
        assert_eq!(report.cgroups, [stale.to_string()]);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(fx.jobs_dir().join(active.to_string()).exists());
        assert!(fx.jobs_dir().join("not-a-lease").exists());
        assert!(fx.cg.path().join("p2pc").join(active.to_string()).exists());
        assert!(!engine.calls().contains(&"rm not-ours".to_string()));
    });
}

#[test]
fn smoke_runs_true_with_the_fixed_argv() {
    guarded(Clock::Real, || async {
        let fx = Fx::new();
        let engine = MockEngine::with(|s| s.exit_now = Some(0));
        let d = fx.driver(engine.clone());
        assert_eq!(d.smoke().await, SmokeResult { ok: true, detail: None });
        let argv = engine.0.lock().unwrap().create_argv.clone().unwrap();
        assert!(argv.contains(&"--network=none".to_string()));
        assert!(argv.ends_with(&["--".into(), DEFAULT_SMOKE_IMAGE.into(), "--".into(), "true".into()]));
        assert!(fx.data_entries().iter().all(|p| p == &fx.jobs_dir()), "cleaned up");

        let d = fx.driver(MockEngine::with(|s| s.exit_now = Some(125)));
        let failed = d.smoke().await;
        assert_eq!(
            failed,
            SmokeResult {
                ok: false,
                detail: Some("exit 125".into())
            }
        );

        // Once per boot: the marker answers until it is removed (a reboot clears /run).
        let marker = fx.data.path().join("run/smoke.json");
        assert_eq!(smoke_once_per_boot(&d, &marker).await, failed);
        let ok = fx.driver(MockEngine::with(|s| s.exit_now = Some(0)));
        assert_eq!(smoke_once_per_boot(&ok, &marker).await, failed, "cached");
        fs::remove_file(&marker).unwrap();
        assert!(smoke_once_per_boot(&ok, &marker).await.ok);

        let mut inv: p2pc_proto::api::Inventory = serde_json::from_value(serde_json::json!({
            "hostname": "node.example.invalid", "platform": "wsl2", "cpu": {"model": "x", "cores": 4},
            "memory_mb": 1024, "os": "Ubuntu 24.04", "arch": "x86_64", "gpu_status": {"status": "not_found"},
            "wsl2": {"distro_version": "1", "podman_version": "4.9.3", "cdi_present": false, "cdi_stale": false},
            "offered": {"cpu": 1.0, "memory_mb": 512, "gpu": 0}, "agent_version": "0.1.0"
        }))
        .unwrap();
        apply_smoke(&mut inv, SmokeResult { ok: true, detail: None });
        assert_eq!(inv.wsl2.unwrap().smoke, Some(SmokeResult { ok: true, detail: None }));
    });
}
