// SPDX-License-Identifier: Apache-2.0

//! [`PodmanDriver`]: the §9 lifecycle on top of an [`Engine`], a [`Cgroups`] tree and an [`Egress`] provider.
//!
//! ```text
//! prepare: SI-1 owner check → validation, sandbox class, GPU → the lease's volumes (taken, in memory)
//!          → job dir, inputs, shim, env file → lease cgroup
//!          → egress socket (if asked) → ingress socket and ports file (a service)
//!          → pull if missing (phase "pulling") → size cap
//!          → volumes: lock on disk, then the no-follow check → podman create → delete env file
//! start:   podman start --attach (logs and exit code) → log pump
//! wait:    exit, or timeout / cancel (SIGTERM, grace, SIGKILL), or disk or volume limit (SIGKILL); then cgroup
//!          counters
//!          services also: health checks (a failure stops them with SIGTERM, grace, SIGKILL) and usage samples
//! collect: podman rm -f, then the SI-9 walk of outputs/
//! cleanup: podman rm -f, the volumes' lock (freed only if Podman confirms the container gone), remove the cgroup,
//!          remove the job dir; also run by the guard on errors and panics
//! ```
//!
//! **Services** (H2 §7.2, §11) are the same sandbox, with the same fixed argv, that lives longer: up to their
//! `timeout_s` of at most 30 days, enforced as H1 enforces a batch job's. While one runs, `wait` also runs its health
//! checks through the configured [`HealthProbe`] (one at a time, each bounded by its `timeout_s`) and reports every
//! change of its health ([`SandboxEvent::Health`]); a service still `starting` after its start period, or failing
//! `failure_threshold` checks in a row after it was healthy, is stopped with the cancel sequence and ends
//! `error="health_check_failed"`. Its usage is sampled from the lease cgroup once a minute ([`SandboxEvent::Usage`]),
//! and its logs are not capped in total (the executor keeps the most recent 64 MiB, H2 §11.4). A node without a probe
//! refuses services as `invalid_job`.
//!
//! **The ingress bridge** (H2 §11.2, [`super::ingress`]). A service's ports are reached only through the agent's own
//! `ingress.sock`, which `prepare` creates in the job's `p2pc/` next to `ports.json` before the container exists, and
//! which `cleanup` removes. Both sit in the read-only `/.p2pc` mount the container already has: the `podman create`
//! argv of a service is the batch job's, `--network=none` included, and no port is published anywhere.
//!
//! **Persistent volumes** (H2 §11.3, [`crate::volumes`]; hard rule 3's one exception). A lease with `volumes` is
//! taken only by a driver that has a [`VolumeStore`] ([`DriverConfig::volumes`]), and only for a service or a template
//! job of the enrolled account. The order is what keeps the exception narrow:
//! 1. the volumes are taken in memory at admission ([`Sandbox::admit`], and again in `prepare`): a second lease gets
//!    `insufficient_capacity`;
//! 2. right before `podman create`, the holder is written to each volume's `meta.json` and the whole tree is walked
//!    without following links ([`VolumeStore::lock_and_check`]); a refusal fails the lease with `volume_unsafe` and
//!    nothing is mounted;
//! 3. the argv gets one `-v <the agent's own directory>:<mount>:rw,U` per volume ([`argv`]);
//! 4. while the job runs, each volume is measured with the disk (`volume_limit`);
//! 5. the lock is freed **only** when Podman confirmed that the container is gone: `podman rm` succeeded, or
//!    `podman container exists` reports it absent. Otherwise it stays, and [`PodmanDriver::sweep_orphans`] (at start)
//!    and [`PodmanDriver::maintain_volumes`] (every minute) retry the removal.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use p2pc_proto::api::{
    Egress as JobEgress, JobKind, JobSpec, Outputs, Placement, Platform, Resources, Retry, SmokeResult,
};
use p2pc_proto::ids::{AccountId, LeaseId};
use p2pc_proto::protocol::{HealthState, LeaseRejectReason, MAX_NODE_MEMORY_MB, Outcome, Usage};
use p2pc_proto::validate::{H2Features, ImageRef, Limits, SpecContext};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, Interval, MissedTickBehavior, Sleep};

use super::argv::{self, ArgvParams, CONTAINER_PREFIX, GpuDevice};
use super::cgroup::{CgroupStats, Cgroups};
use super::disk::{self, FreeSpace, Statvfs, TreeUsage};
use super::engine::{Attached, ContainerState, Engine, ExitFuture, StopSignal};
use super::health::{HealthMachine, HealthPolicy, HealthProbe, ProbeTarget, Step};
use super::ingress::{self, Attach, IngressBridge, IngressSession};
use super::jobdir::{JOBS_DIR, JobDir};
use super::logs::{self, LogSummary};
use super::outputs::{self, CollectedOutputs};
use super::{
    CancelHandle, DISK_CHECK_INTERVAL, Egress, EgressRequest, Finished, GpuRef, HealthChange, LeaseContext, NoEgress,
    Phase, STOP_GRACE, Sandbox, SandboxError, SandboxEvent, UsageSample, error_code, run_lease,
};
use crate::config::Runtime;
use crate::volumes::{Mount, VolumeStore};

const MIB: u64 = 1024 * 1024;
/// Default largest image the agent accepts, in MiB.
pub const DEFAULT_MAX_IMAGE_MB: u64 = 20 * 1024;
/// Default image of the smoke container: tiny, and it has `true`.
pub const DEFAULT_SMOKE_IMAGE: &str = "docker.io/library/busybox:1.36.1";
/// The shortest interval between two usage samples of a service (H2 §11.4: at most once a minute).
pub const USAGE_INTERVAL: Duration = Duration::from_secs(60);

/// What the driver needs to know about the node.
#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// The agent's data dir; job directories go in `<data_dir>/jobs/`.
    pub data_dir: PathBuf,
    /// The §9.0 profile.
    pub platform: Platform,
    /// The configured OCI runtime (`runsc` adds `--runtime=runsc`).
    pub runtime: Runtime,
    /// Whether the node meets its profile's requirements for that runtime (T07's `SandboxCapability.ready`).
    /// When false, every lease is refused with `unsupported_sandbox`: a job never runs in a weaker sandbox.
    pub ready: bool,
    /// The static shim binary, copied into each job's `p2pc/`.
    pub shim_path: PathBuf,
    /// UUIDs of the GPUs the inventory offers (`ResolvedShare.gpus` after `inventory::Probe::report`). On WSL2 the
    /// inventory offers one only when the machine has exactly one; the driver checks that again
    /// (`gpu_selection_unsupported`).
    pub offerable_gpus: Vec<String>,
    /// Largest image accepted after a pull, in MiB.
    pub max_image_mb: u64,
    /// SIGTERM → SIGKILL grace.
    pub stop_grace: Duration,
    /// Disk measurement period (§9: 2 s).
    pub disk_check_interval: Duration,
    /// Most entries of `outputs/` one disk measurement walks; reaching it counts as over the limit.
    pub disk_entry_budget: usize,
    /// The data disk's free space, for the disk floor (§9).
    pub free_space: Arc<dyn FreeSpace>,
    /// The smoke container's image.
    pub smoke_image: String,
    /// The node's public addresses as observed by iroh, for the egress proxy (hairpin NAT). A live source fed by
    /// T05b; the default holds an empty list, which means no hairpin protection until T05b wires it.
    pub public_addrs: watch::Receiver<Vec<IpAddr>>,
    /// Whether the egress gate is open (T10e): [`KnownPublicAddrs`] refuses to start a proxy while it is `false`. The
    /// default is `false`: closed until the node says its public addresses are known.
    pub egress_ready: watch::Receiver<p2pc_net::EgressGate>,
    /// Runs the health checks of services (H2 §11.2: the ingress bridge, T2-21). `None`, the default: the node
    /// cannot check a service, so service leases are refused as `invalid_job`.
    pub health_probe: Option<Arc<dyn HealthProbe>>,
    /// The ingress bridge (H2 §11.2): each service lease gets its `ingress.sock` and `ports.json` from it, from
    /// `prepare` to `cleanup`. The agent sets it together with `health_probe`, to the same bridge. `None`, the
    /// default: no service gets either file, so nothing can reach its ports (tests with a scripted probe).
    pub ingress: Option<IngressBridge>,
    /// How often a service's usage is sampled from its lease cgroup for the heartbeat (H2 §11.4: at most once a
    /// minute). Shorter values are raised to [`USAGE_INTERVAL`].
    pub usage_interval: Duration,
    /// The node's persistent volumes (H2 §11.3). `None`, the default: the node mounts no volume, and a lease with
    /// `volumes` is refused as `invalid_job`.
    pub volumes: Option<VolumeStore>,
}

impl DriverConfig {
    /// A crun configuration with the §9 defaults. `ready` has no default on purpose: the caller must pass the
    /// node's measured readiness (T07's `SandboxCapability.ready`), so that a driver can never be built "ready" by
    /// accident.
    #[must_use]
    pub fn new(data_dir: impl Into<PathBuf>, platform: Platform, shim_path: impl Into<PathBuf>, ready: bool) -> Self {
        Self {
            data_dir: data_dir.into(),
            platform,
            runtime: Runtime::Crun,
            ready,
            shim_path: shim_path.into(),
            offerable_gpus: Vec::new(),
            max_image_mb: DEFAULT_MAX_IMAGE_MB,
            stop_grace: STOP_GRACE,
            disk_check_interval: DISK_CHECK_INTERVAL,
            disk_entry_budget: outputs::MAX_ENTRIES,
            free_space: Arc::new(Statvfs),
            smoke_image: DEFAULT_SMOKE_IMAGE.into(),
            public_addrs: watch::channel(Vec::new()).1,
            egress_ready: watch::channel(p2pc_net::EgressGate::Closed).1,
            health_probe: None,
            ingress: None,
            usage_interval: USAGE_INTERVAL,
            volumes: None,
        }
    }
}

struct Shared<E, C> {
    engine: E,
    cgroups: C,
    /// Cleanups started by dropped guards.
    background: Mutex<Vec<JoinHandle<()>>>,
    /// Whether the "cannot read image manifests" warning was logged (once per driver).
    manifest_warned: AtomicBool,
    /// One lock per image being pulled (§9 "Images": pulls of the same image on one node are shared).
    pulls: ImagePulls,
}

/// What one image's pulls share: the lock that lets one lease pull at a time, and how many pulls have worked.
#[derive(Default)]
struct ImagePull {
    gate: Arc<tokio::sync::Mutex<()>>,
    /// Pulls that ended with the image in the store, within the cap.
    pulled: AtomicU64,
    /// How the pulls that failed went.
    failures: Mutex<Failures>,
}

/// The failed pulls of one image (kept only while some lease is in its pull step).
#[derive(Default)]
struct Failures {
    /// Pulls that failed, ever.
    total: u64,
    /// Pulls that failed since one worked (or since the first).
    streak: u64,
    /// The last failure, and whether trying again could not change it.
    last: Option<(SandboxError, bool)>,
}

/// The images with a lease in their pull step, by normalized reference. An entry exists only while some lease holds
/// or waits for it.
#[derive(Default)]
struct ImagePulls(Mutex<HashMap<String, Arc<ImagePull>>>);

impl ImagePulls {
    /// Joins the pull step of `key`. Take it **before** looking at the store: a pull that ends after the look is then
    /// seen as one that ran while this lease waited.
    fn join(&self, key: &str) -> PullSlot<'_> {
        let pull = Arc::clone(
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(key.to_string())
                .or_default(),
        );
        let seen_failures = pull.failures.lock().unwrap_or_else(PoisonError::into_inner).total;
        PullSlot {
            pulls: self,
            key: key.to_string(),
            seen: pull.pulled.load(Ordering::Acquire),
            seen_failures,
            pull: Some(pull),
            held: None,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).len()
    }

    /// For each image in a pull step, how many hold its entry: the map itself and one per lease in the step.
    #[cfg(test)]
    fn holders(&self) -> Vec<usize> {
        let map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        map.values().map(Arc::strong_count).collect()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A lease's place in the pull step of one image. Dropping it (also when the lease is cancelled while it waits)
/// releases the lock and forgets the image once nobody else is in its pull step.
struct PullSlot<'a> {
    pulls: &'a ImagePulls,
    key: String,
    /// Pulls that had worked when the lease joined.
    seen: u64,
    /// Pulls that had failed when the lease joined.
    seen_failures: u64,
    pull: Option<Arc<ImagePull>>,
    held: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl PullSlot<'_> {
    /// Takes the image's lock; the answer says whether the lease had to wait for it.
    async fn lock(&mut self, cancel: &watch::Receiver<bool>) -> Result<bool, SandboxError> {
        let Some(pull) = &self.pull else {
            return Ok(false);
        };
        let gate = Arc::clone(&pull.gate);
        let (held, waited) = match Arc::clone(&gate).try_lock_owned() {
            Ok(held) => (held, false),
            Err(_) => {
                let held = tokio::select! {
                    held = gate.lock_owned() => held,
                    () = cancelled(cancel.clone()) => return Err(SandboxError::Cancelled),
                };
                (held, true)
            }
        };
        self.held = Some(held);
        Ok(waited)
    }

    /// Whether a pull of this image ended well since the lease joined: the image is as fresh as a pull of its own
    /// would make it.
    fn pulled_meanwhile(&self) -> bool {
        self.pull
            .as_ref()
            .is_some_and(|p| p.pulled.load(Ordering::Acquire) != self.seen)
    }

    /// Records a pull that ended well (call it while the lock is held).
    fn pulled(&self) {
        if let Some(p) = &self.pull {
            let mut failures = p.failures.lock().unwrap_or_else(PoisonError::into_inner);
            failures.streak = 0;
            failures.last = None;
            drop(failures);
            p.pulled.fetch_add(1, Ordering::Release);
        }
    }

    /// Records a pull that failed with `error` (call it while the lock is held). `final_` says that trying again
    /// would not change it: the image is over the cap, or the pull ran into its timeout.
    fn failed(&self, error: &SandboxError, final_: bool) {
        if let Some(p) = &self.pull {
            let mut failures = p.failures.lock().unwrap_or_else(PoisonError::into_inner);
            failures.total += 1;
            failures.streak += 1;
            failures.last = Some((error.clone(), final_));
        }
    }

    /// The failure this lease takes instead of pulling, if a pull failed while it waited: always when trying again
    /// is pointless, and otherwise when a retry has failed too. So of the leases that wait behind a failed pull, at
    /// most one tries again; the others take its result.
    fn failure_to_take(&self) -> Option<SandboxError> {
        let failures = self
            .pull
            .as_ref()?
            .failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if failures.total == self.seen_failures {
            return None;
        }
        match &failures.last {
            Some((error, final_)) if *final_ || failures.streak >= 2 => Some(error.clone()),
            _ => None,
        }
    }
}

impl Drop for PullSlot<'_> {
    fn drop(&mut self) {
        self.held = None;
        self.pull = None;
        let mut map = self.pulls.0.lock().unwrap_or_else(PoisonError::into_inner);
        if map.get(&self.key).is_some_and(|p| Arc::strong_count(p) == 1) {
            map.remove(&self.key);
        }
    }
}

/// The Podman sandbox driver.
pub struct PodmanDriver<E, C, X = NoEgress> {
    cfg: DriverConfig,
    shared: Arc<Shared<E, C>>,
    egress: X,
}

impl<E, C, X> fmt::Debug for PodmanDriver<E, C, X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PodmanDriver")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

/// What the orphan sweep removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Container names.
    pub containers: Vec<String>,
    /// Job directory names (lease IDs).
    pub job_dirs: Vec<String>,
    /// Lease cgroups (lease IDs).
    pub cgroups: Vec<String>,
    /// Leases whose volume locks were freed: Podman confirmed their containers gone (H2 §11.3).
    pub volume_locks: Vec<String>,
    /// What could not be listed or removed.
    pub errors: Vec<String>,
}

/// Removes the container, settles the lock of the lease's volumes, then removes the cgroup and the job directory.
/// Logs failures; never panics.
async fn cleanup_steps<E: Engine, C: Cgroups>(
    shared: &Shared<E, C>,
    lease: &LeaseId,
    name: &str,
    dir: &JobDir,
    volumes: Option<&VolumeStore>,
) {
    let removed = shared.engine.remove(name).await;
    if let Err(e) = &removed {
        tracing::warn!(lease = %lease, error = %e, "cannot remove the container; the next orphan sweep will");
    }
    if let Some(store) = volumes {
        settle_volume_lock(&shared.engine, store, lease, name, removed.is_ok()).await;
    }
    if let Err(e) = shared.cgroups.remove(lease).await {
        tracing::warn!(lease = %lease, error = %e, "cannot remove the lease cgroup");
    }
    if let Err(e) = remove_job_dir(&shared.engine, dir).await {
        tracing::warn!(lease = %lease, error = %e, "cannot remove the job directory");
    }
}

/// Whether Podman confirms that the container `name` is gone (H2 §11.3 "One holder at a time"): `podman rm` on it
/// succeeded (`removed`), or `podman container exists` reports it absent. A failure of either command confirms
/// nothing.
async fn container_gone<E: Engine>(engine: &E, name: &str, removed: bool) -> bool {
    removed || matches!(engine.container_exists(name).await, Ok(false))
}

/// The end of a lease's run, for its volumes: the lock is freed when Podman confirmed the container gone, and kept
/// otherwise (the volume is then reported `in_use_by` the lease, and every sweep retries the removal).
async fn settle_volume_lock<E: Engine>(engine: &E, store: &VolumeStore, lease: &LeaseId, name: &str, removed: bool) {
    let gone = container_gone(engine, name, removed).await;
    if !gone {
        tracing::warn!(
            lease_id = %lease,
            container = name,
            "the container could not be confirmed gone: its volumes stay locked, and the sweep retries the removal"
        );
    }
    let (store, lease) = (store.clone(), *lease);
    let settled = blocking(move || {
        if gone {
            store.release(&lease);
        } else {
            store.orphan(&lease);
        }
    })
    .await;
    if let Err(e) = settled {
        tracing::warn!(error = %e, "cannot settle the lock of a lease's volumes");
    }
}

/// What [`VolumeStore::reserve`] took for a lease, until the cleanup guard exists: dropped on an early return of
/// `prepare`, it gives the volumes back. Nothing was written for them yet, and no container was created.
struct Reservation {
    store: VolumeStore,
    lease_id: LeaseId,
    epoch: u64,
    armed: bool,
}

impl Reservation {
    /// The cleanup guard has the volumes now.
    fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.armed {
            self.store.cancel_reservation(&self.lease_id, self.epoch);
        }
    }
}

/// Removes a job directory. Rootless Podman maps a non-root container user to one of the agent's subordinate
/// UIDs, so the agent may lack the permission to delete what the job wrote; then it deletes from inside Podman's
/// user namespace instead.
///
/// The deletion runs in `spawn_blocking`: a job directory can hold a large tree, and the runtime thread must keep
/// serving heartbeats and other jobs meanwhile.
async fn remove_job_dir<E: Engine>(engine: &E, dir: &JobDir) -> Result<(), String> {
    let owned = dir.clone();
    match blocking(move || owned.remove()).await? {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            engine.remove_tree(dir.root()).await.map_err(|u| format!("{e}; {u}"))
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Runs blocking filesystem work off the runtime thread.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("blocking task failed: {e}"))
}

/// [`blocking`] for the setup steps of `prepare`: a panic in the file work is a setup failure.
async fn setup_blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, SandboxError> {
    blocking(f)
        .await
        .map_err(|e| SandboxError::failed(error_code::SANDBOX_SETUP, e))
}

/// The lease-ID-shaped entries of `<data_dir>/jobs/` that no active lease claims.
fn stale_job_dirs(jobs: &std::path::Path, active: &HashSet<String>) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(jobs) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| Some((e.file_name().to_str()?.to_string(), e.path())))
        .filter(|(name, _)| LeaseId::from_str(name).is_ok() && !active.contains(name))
        .collect()
}

/// Runs the cleanup when a job is dropped without [`Sandbox::cleanup`]: after an error in `prepare`, or when the
/// task holding the job panics or is aborted.
struct Guard<E: Engine, C: Cgroups> {
    shared: Arc<Shared<E, C>>,
    lease: LeaseId,
    name: String,
    dir: JobDir,
    /// The store that holds the lease's volumes, if it has any: their lock is settled with the container's removal.
    volumes: Option<VolumeStore>,
    armed: bool,
}

impl<E: Engine, C: Cgroups> Drop for Guard<E, C> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let (shared, lease, name, dir, volumes) = (
            Arc::clone(&self.shared),
            self.lease,
            self.name.clone(),
            self.dir.clone(),
            self.volumes.clone(),
        );
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                let task = rt.spawn(async move { cleanup_steps(&shared, &lease, &name, &dir, volumes.as_ref()).await });
                self.shared
                    .background
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(task);
            }
            Err(_) => {
                // No runtime (process exit): the directory now, the container and cgroup at the next sweep. A
                // volume's lock stays on disk until that sweep confirmed the container gone.
                let _ = dir.remove();
            }
        }
    }
}

/// A prepared, then running, lease.
pub struct PodmanJob<E: Engine, C: Cgroups, S> {
    lease_id: LeaseId,
    epoch: u64,
    name: String,
    dir: JobDir,
    timeout: Duration,
    disk_limit_bytes: u64,
    outputs_max_bytes: u64,
    events: mpsc::Sender<SandboxEvent>,
    cancel: watch::Receiver<bool>,
    /// In a mutex only to make the job `Sync` (the future is not); it is only ever reached through `&mut`.
    exit: Mutex<Option<ExitFuture>>,
    pump: Option<JoinHandle<LogSummary>>,
    started_at: Option<Instant>,
    egress: Option<S>,
    /// A service's place on the ingress bridge: its socket, until `cleanup`. `None` for a batch job.
    ingress: Option<IngressSession>,
    /// A service's health policy and probe; `None` for a batch job.
    service: Option<ServiceRun>,
    /// The persistent volumes the container mounts (H2 §11.3), locked for this lease.
    volumes: Vec<Mount>,
    guard: Guard<E, C>,
}

/// What `wait` needs to watch a service (H2 §7.2).
struct ServiceRun {
    policy: HealthPolicy,
    probe: Arc<dyn HealthProbe>,
}

/// One health check in flight.
type CheckFuture = Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>;

impl ServiceRun {
    /// Starts one check of `target`, failed when it takes longer than the policy's timeout.
    fn check(&self, target: &ProbeTarget) -> CheckFuture {
        let (probe, target, check, timeout) = (
            Arc::clone(&self.probe),
            target.clone(),
            self.policy.check.clone(),
            self.policy.timeout,
        );
        Box::pin(async move {
            match tokio::time::timeout(timeout, probe.check(&target, &check)).await {
                Ok(result) => result,
                Err(_) => Err(format!("no answer within {} s", timeout.as_secs())),
            }
        })
    }
}

impl<E: Engine, C: Cgroups, S> fmt::Debug for PodmanJob<E, C, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PodmanJob")
            .field("lease_id", &self.lease_id)
            .field("epoch", &self.epoch)
            .field("name", &self.name)
            .field("dir", &self.dir)
            .field("started", &self.started_at.is_some())
            .field("service", &self.service.is_some())
            .finish_non_exhaustive()
    }
}

impl<E: Engine, C: Cgroups, S> PodmanJob<E, C, S> {
    /// The lease.
    #[must_use]
    pub fn lease_id(&self) -> &LeaseId {
        &self.lease_id
    }

    /// The epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The job directory (T10 uploads from `outputs/` before cleanup).
    #[must_use]
    pub fn dir(&self) -> &JobDir {
        &self.dir
    }

    /// The container name.
    #[must_use]
    pub fn container_name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    TimedOut,
    Cancelled,
    Disk,
    Floor,
    /// A service's health check failed (H2 §7.2).
    Health,
    /// A volume went over its `max_mb` or could not be measured (H2 §11.3 "Size").
    Volume,
    /// The exit future failed.
    Lost,
}

/// Resolves when `rx` holds `true`; never if its sender is gone without cancelling.
async fn cancelled(mut rx: watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Awaits the timer if it is set; never resolves otherwise.
async fn armed(timer: &mut Option<Pin<Box<Sleep>>>) {
    match timer {
        Some(t) => t.await,
        None => std::future::pending().await,
    }
}

/// The next tick of the interval if it is set; never resolves otherwise.
async fn ticking(interval: &mut Option<Interval>) {
    match interval {
        Some(i) => {
            i.tick().await;
        }
        None => std::future::pending().await,
    }
}

/// The result of the check in flight; never resolves when there is none.
async fn in_flight(check: &mut Option<CheckFuture>) -> Result<(), String> {
    match check {
        Some(c) => c.await,
        None => std::future::pending().await,
    }
}

/// An interval whose first tick comes one `period` after `start`; a late tick delays the next ones.
fn every(start: Instant, period: Duration) -> Interval {
    let mut i = tokio::time::interval_at(start + period, period);
    i.set_missed_tick_behavior(MissedTickBehavior::Delay);
    i
}

/// A usage sample from the lease cgroup's counters (MiB, within the protocol's bound).
fn usage_sample(stats: &CgroupStats) -> UsageSample {
    UsageSample {
        used_cpu_ms: stats.cpu_usage_usec / 1000,
        max_rss_mb: (stats.memory_peak_bytes / MIB).min(MAX_NODE_MEMORY_MB),
    }
}

fn reject(reason: LeaseRejectReason) -> SandboxError {
    SandboxError::Rejected(reason)
}

impl<E: Engine, C: Cgroups, X: Egress> PodmanDriver<E, C, X> {
    /// A driver for `cfg`.
    pub fn new(cfg: DriverConfig, engine: E, cgroups: C, egress: X) -> Self {
        Self {
            cfg,
            shared: Arc::new(Shared {
                engine,
                cgroups,
                background: Mutex::new(Vec::new()),
                manifest_warned: AtomicBool::new(false),
                pulls: ImagePulls::default(),
            }),
            egress,
        }
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &DriverConfig {
        &self.cfg
    }

    /// The engine.
    #[must_use]
    pub fn engine(&self) -> &E {
        &self.shared.engine
    }

    /// The cgroups.
    #[must_use]
    pub fn cgroups(&self) -> &C {
        &self.shared.cgroups
    }

    /// Waits for the cleanups that dropped jobs started in the background.
    pub async fn drain_background(&self) {
        loop {
            let tasks = std::mem::take(&mut *self.shared.background.lock().unwrap_or_else(PoisonError::into_inner));
            if tasks.is_empty() {
                return;
            }
            for t in tasks {
                let _ = t.await;
            }
        }
    }

    /// The orphan sweep, at agent start: removes containers labelled `p2pc.lease`, job directories and lease
    /// cgroups that no lease in `active` claims.
    pub async fn sweep_orphans(&self, active: &HashSet<LeaseId>) -> SweepReport {
        let active: HashSet<String> = active.iter().map(ToString::to_string).collect();
        let mut report = SweepReport::default();
        let engine = &self.shared.engine;
        // Whether the node's containers were listed and every one of a lease this process does not run is gone.
        let mut swept = true;
        match engine.lease_containers().await {
            Ok(list) => {
                for c in list {
                    if active.contains(&c.lease) || !c.name.starts_with(CONTAINER_PREFIX) {
                        continue;
                    }
                    match engine.remove(&c.name).await {
                        Ok(()) => report.containers.push(c.name),
                        Err(e) => {
                            swept = false;
                            report.errors.push(e.msg);
                        }
                    }
                }
            }
            Err(e) => {
                swept = false;
                report.errors.push(e.msg);
            }
        }
        // H2 §11.3: only now, with their containers confirmed gone, do the volumes those leases held become free.
        if let Some(store) = &self.cfg.volumes {
            report.volume_locks = self.release_orphaned_locks(store, &active).await;
            if swept {
                store.sweep_finished();
            }
        }
        // Listing and removing run off the runtime thread (`blocking`, `remove_job_dir`).
        let jobs = self.cfg.data_dir.join(JOBS_DIR);
        let listed = {
            let active = active.clone();
            blocking(move || stale_job_dirs(&jobs, &active)).await
        };
        match listed {
            Ok(stale) => {
                for (name, path) in stale {
                    match remove_job_dir(engine, &JobDir::at(path)).await {
                        Ok(()) => report.job_dirs.push(name),
                        Err(e) => report.errors.push(format!("job dir {name}: {e}")),
                    }
                }
            }
            Err(e) => report.errors.push(e),
        }
        for name in self.shared.cgroups.present().await {
            let Ok(lease) = LeaseId::from_str(&name) else { continue };
            if active.contains(&name) {
                continue;
            }
            match self.shared.cgroups.remove(&lease).await {
                Ok(()) => report.cgroups.push(name),
                Err(e) => report.errors.push(format!("cgroup {name}: {e}")),
            }
        }
        report
    }

    /// Retries the removal of the containers that still hold a volume though their lease has no run in this process
    /// (it ended while `podman rm` failed, or an earlier agent process left it), and frees the lock of each one that
    /// Podman confirms gone (H2 §11.3). The container is named by the lease, never by a string read from disk.
    /// Returns the leases whose volumes were freed.
    async fn release_orphaned_locks(&self, store: &VolumeStore, active: &HashSet<String>) -> Vec<String> {
        let engine = &self.shared.engine;
        let mut released = Vec::new();
        for lease in store.orphaned() {
            if active.contains(&lease.to_string()) {
                continue;
            }
            let name = argv::container_name(&lease);
            let removed = match engine.remove(&name).await {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(lease_id = %lease, error = %e, "cannot remove a container that holds a volume");
                    false
                }
            };
            if !container_gone(engine, &name, removed).await {
                tracing::warn!(lease_id = %lease, container = %name, "a volume stays locked: its container is not confirmed gone");
                continue;
            }
            let store = store.clone();
            if blocking(move || store.release(&lease)).await.unwrap_or(false) {
                tracing::info!(lease_id = %lease, "the lock of a lease's volumes is free: its container is gone");
                released.push(lease.to_string());
            }
        }
        released
    }

    /// One round of volume upkeep (H2 §11.3), run every [`crate::volumes::MAINTENANCE_INTERVAL`]: retries the
    /// removal of containers that still hold a volume, then deletes the unused volumes past their retention.
    pub async fn maintain_volumes(&self) {
        let Some(store) = self.cfg.volumes.clone() else {
            return;
        };
        self.release_orphaned_locks(&store, &HashSet::new()).await;
        if let Err(e) = blocking(move || store.collect_garbage()).await {
            tracing::warn!(error = %e, "the volume collection failed");
        }
    }

    /// H2 §11.3 "Retention": under the disk floor, unused volumes go before a job is refused or killed. Whether
    /// the disk is above the floor afterwards.
    async fn evict_volumes_for_floor(&self) -> bool {
        let Some(store) = self.cfg.volumes.clone() else {
            return false;
        };
        let free_space = Arc::clone(&self.cfg.free_space);
        blocking(move || store.evict_for_floor(free_space.as_ref()))
            .await
            .unwrap_or(false)
    }

    /// Measures the lease's volumes as the disk is measured (H2 §11.3 "Size"): over `max_mb` or over the entry
    /// budget stops the job, and so do three measurements in a row that could not be made.
    async fn volumes_over<S>(&self, job: &PodmanJob<E, C, S>, failed: &mut u32) -> Option<Stop> {
        let store = job.guard.volumes.clone().filter(|_| !job.volumes.is_empty())?;
        let (lease_id, epoch, expected) = (job.lease_id, job.epoch, job.volumes.len());
        let usage = blocking(move || store.usage(&lease_id, epoch))
            .await
            .unwrap_or_default();
        // A volume that is not locked for this lease any more cannot be vouched for either.
        let mut unmeasured = usage.len() != expected;
        for volume in &usage {
            match &volume.used {
                Ok(TreeUsage::Bytes(bytes)) if *bytes <= volume.max_bytes => {}
                Ok(used) => {
                    tracing::warn!(lease_id = %lease_id, volume = %volume.name, ?used, max_bytes = volume.max_bytes, "a volume is over its limit; stopping the job");
                    return Some(Stop::Volume);
                }
                Err(e) => {
                    tracing::debug!(lease_id = %lease_id, volume = %volume.name, error = %e, "cannot measure a volume");
                    unmeasured = true;
                }
            }
        }
        if unmeasured {
            *failed += 1;
            (*failed >= disk::MAX_FAILED_MEASUREMENTS).then_some(Stop::Volume)
        } else {
            *failed = 0;
            None
        }
    }

    fn gpu_device(&self, job: &JobSpec, gpu: Option<&GpuRef>) -> Result<Option<GpuDevice>, SandboxError> {
        if job.resources.gpu == 0 {
            return Ok(None);
        }
        match self.cfg.platform {
            Platform::Wsl2 => {
                // The WSL CDI spec only has `nvidia.com/gpu=all`: it selects the one GPU only if there is one.
                let [only] = self.cfg.offerable_gpus.as_slice() else {
                    return Err(reject(LeaseRejectReason::GpuSelectionUnsupported));
                };
                if gpu.is_some_and(|g| g.uuid != *only) {
                    return Err(reject(LeaseRejectReason::InsufficientCapacity));
                }
                Ok(Some(GpuDevice::All))
            }
            Platform::Linux => match gpu {
                Some(g) if self.cfg.offerable_gpus.contains(&g.uuid) => Ok(Some(GpuDevice::Uuid(g.uuid.clone()))),
                _ => Err(reject(LeaseRejectReason::InsufficientCapacity)),
            },
        }
    }

    async fn terminate<S>(&self, job: &PodmanJob<E, C, S>, escalate: &mut Option<Pin<Box<Sleep>>>) {
        if let Err(e) = self.shared.engine.kill(&job.name, StopSignal::Term).await {
            tracing::debug!(lease = %job.lease_id, error = %e, "SIGTERM failed");
        }
        *escalate = Some(Box::pin(tokio::time::sleep(self.cfg.stop_grace)));
    }

    /// The writable layer plus `outputs/`, in bytes, and the container state.
    async fn measure<S>(&self, job: &PodmanJob<E, C, S>) -> Measurement {
        // The floor first: it protects the owner's disk whatever the job's own accounting says.
        let free_space = Arc::clone(&self.cfg.free_space);
        let data_dir = self.cfg.data_dir.clone();
        match tokio::task::spawn_blocking(move || free_space.space(&data_dir)).await {
            // Unused volumes go before the job does (H2 §11.3 "Retention").
            Ok(Ok(space)) if space.below_floor() => {
                if !self.evict_volumes_for_floor().await {
                    return Measurement::BelowFloor;
                }
            }
            Ok(Ok(_)) => {}
            _ => return Measurement::Failed,
        }
        let Ok(state) = self.shared.engine.inspect(&job.name).await else {
            return Measurement::Failed;
        };
        let Some(layer) = state.size_rw else {
            return Measurement::Failed;
        };
        let dir = job.dir.outputs();
        let budget = self.cfg.disk_entry_budget;
        match tokio::task::spawn_blocking(move || disk::tree_usage(&dir, budget)).await {
            Ok(Ok(TreeUsage::Bytes(outputs))) => Measurement::Used {
                state,
                bytes: layer.saturating_add(outputs),
            },
            Ok(Ok(TreeUsage::OverBudget)) => Measurement::OverBudget,
            _ => Measurement::Failed,
        }
    }

    /// Makes `image` available within the size cap (§9 "Images").
    ///
    /// 1. **Pull only what is missing.** An image already in the store is used as it is when its reference is a
    ///    digest, or a tag other than `latest` (an image with no tag is `latest`): no manifest read, no pull, so no
    ///    registry request at all (Docker Hub limits anonymous pulls per IP, and a batch of jobs on one image would
    ///    hit the limit). The cap is checked on its local size. An image that is over it is refused, never removed.
    ///    `latest` is pulled for every attempt, present or not. If the store cannot be asked, this step is skipped.
    /// 2. **Pulls of the same image are shared.** One lease at a time is in the pull step of an image; the others
    ///    wait for it (a cancel ends the wait at once), then look at the store again: an image that a pull has just
    ///    put there is used as it is. If the pull failed, they take its result when trying again cannot change it (the
    ///    pull ran into its timeout, or the image is over the cap); otherwise one of them tries again, and the others
    ///    take the result of that try. A hung registry therefore costs one pull timeout, not one per lease.
    /// 3. The registry's manifest gives the layer sizes **before** any pull ([`Engine::manifest_size`]: `skopeo
    ///    inspect --raw` where the node has it, else `podman manifest inspect`): over the cap, the image is refused
    ///    without being pulled.
    /// 4. If neither can read the manifest (Podman 4.9 cannot read a single-image OCI manifest), the pull goes
    ///    ahead, bounded by the pull timeout, and the cap is checked on the pulled image instead; a warning is
    ///    logged once per driver. The disk floor still protects the owner's disk.
    /// 5. A refused or failed pull removes what it left behind, but never an image that was already present
    ///    (other jobs may use it; `podman rmi` refuses an image in use anyway).
    ///
    /// The choice is logged once per attempt: `image present, no pull` or `pulling`.
    async fn pull_within_cap(&self, image: &str, cancel: &watch::Receiver<bool>) -> Result<(), SandboxError> {
        let engine = &self.shared.engine;
        let cap = self.cfg.max_image_mb.saturating_mul(MIB);
        let too_large = |size: u64, what: &str| {
            SandboxError::failed(
                error_code::IMAGE_TOO_LARGE,
                format!(
                    "{what} is {} MiB, over the {} MiB cap",
                    size / MIB,
                    self.cfg.max_image_mb
                ),
            )
        };
        // The jobs were validated, so the reference parses; if it did not, it is pulled like a `latest`.
        let parsed = ImageRef::parse(image);
        let key = parsed.as_ref().map_or_else(|_| image.to_string(), ToString::to_string);
        // A digest never changes and nor does a tag but `latest`, by the registry's convention: they are not pulled
        // again.
        let reusable = parsed
            .as_ref()
            .is_ok_and(|r| r.digest().is_some() || r.tag().is_some_and(|t| t != "latest"));
        let mut slot = self.shared.pulls.join(&key);

        // Whether the image is in the store; `None` when the store could not be asked.
        let mut present = engine.image_exists(image).await.ok();
        if reusable && present == Some(true) && self.local_size_within_cap(image, cap, &too_large).await? {
            return Ok(());
        }

        // Only one lease at a time pulls an image; the others look again once it is done.
        let waited = slot.lock(cancel).await?;
        if waited || slot.pulled_meanwhile() {
            present = engine.image_exists(image).await.ok();
            // A pull that worked while this lease waited is as good as one of its own, for `latest` too.
            if (reusable || slot.pulled_meanwhile())
                && present == Some(true)
                && self.local_size_within_cap(image, cap, &too_large).await?
            {
                return Ok(());
            }
        }

        // A pull failed while this lease waited, and it is not worth trying again: that is this lease's answer too.
        if let Some(error) = slot.failure_to_take() {
            tracing::info!(image, %error, "taking the result of the pull this lease waited for");
            return Err(error);
        }

        tracing::info!(image, "pulling");
        // When in doubt, the image is treated as present, so it is never removed.
        let present_before = present.unwrap_or(true);
        // A cancel during the manifest read ends the lease at once, as it does during the pull. Nothing has been
        // pulled yet, so there is nothing to remove.
        let manifest = tokio::select! {
            r = engine.manifest_size(image) => r,
            () = cancelled(cancel.clone()) => return Err(SandboxError::Cancelled),
        };
        match manifest {
            Ok(size) if size > cap => {
                let refused = too_large(size, "the image's manifest");
                slot.failed(&refused, true);
                return Err(refused);
            }
            Ok(_) => {}
            // Neither skopeo nor Podman could read it: pull, then check (§9). Warn once per driver, not per job.
            Err(e) => {
                if self.shared.manifest_warned.swap(true, Ordering::Relaxed) {
                    tracing::debug!(image, error = %e, "cannot read the image manifest; checking the size after the pull");
                } else {
                    tracing::warn!(
                        image,
                        error = %e,
                        "cannot read image manifests (install skopeo); the size cap is checked after each pull"
                    );
                }
            }
        }
        let left_behind = || async {
            if !present_before && let Err(e) = engine.remove_image(image).await {
                tracing::warn!(image, error = %e, "cannot remove what the pull left behind");
            }
        };
        let pulled = tokio::select! {
            r = engine.pull(image) => r,
            () = cancelled(cancel.clone()) => {
                left_behind().await;
                return Err(SandboxError::Cancelled);
            }
        };
        if let Err(e) = pulled {
            left_behind().await;
            let error = SandboxError::failed(error_code::IMAGE_PULL_FAILED, &e);
            slot.failed(&error, e.is_timeout());
            return Err(error);
        }
        match engine.image_size(image).await {
            Ok(size) if size > cap => {
                left_behind().await;
                let refused = too_large(size, "the pulled image");
                slot.failed(&refused, true);
                Err(refused)
            }
            Ok(_) => {
                slot.pulled();
                Ok(())
            }
            Err(e) => {
                left_behind().await;
                let error = SandboxError::failed(error_code::IMAGE_PULL_FAILED, e);
                slot.failed(&error, false);
                Err(error)
            }
        }
    }

    /// Step 1 of [`Self::pull_within_cap`] for an image in the store: `Ok(true)` when it is within the cap and can be
    /// used as it is, an `image_too_large` error when it is over (the image stays), and `Ok(false)` when its size
    /// cannot be read (the full path then decides).
    async fn local_size_within_cap(
        &self,
        image: &str,
        cap: u64,
        too_large: &impl Fn(u64, &str) -> SandboxError,
    ) -> Result<bool, SandboxError> {
        match self.shared.engine.image_size(image).await {
            Ok(size) if size > cap => Err(too_large(size, "the image in the node's store")),
            Ok(_) => {
                tracing::info!(image, "image present, no pull");
                Ok(true)
            }
            Err(e) => {
                tracing::debug!(image, error = %e, "cannot read the size of the image in the store");
                Ok(false)
            }
        }
    }

    /// The disk floor at lease time: below it, or unreadable, the lease is refused (fail closed). The `statvfs`
    /// runs on the blocking pool.
    async fn floor_allows_new_leases(&self) -> bool {
        let (free_space, data_dir) = (Arc::clone(&self.cfg.free_space), self.cfg.data_dir.clone());
        let above = blocking(move || free_space.space(&data_dir))
            .await
            .is_ok_and(|space| space.is_ok_and(|s| !s.below_floor()));
        // Below it (or unreadable, which evicts nothing): unused volumes go before a lease is refused.
        above || self.evict_volumes_for_floor().await
    }
}

/// One disk measurement (spec §9 "Disk"); everything but `Used` under the limit stops the job.
#[derive(Debug, Clone, Copy)]
enum Measurement {
    /// The writable layer plus `outputs/`, and the container's state.
    Used { state: ContainerState, bytes: u64 },
    /// `outputs/` has more entries than the budget.
    OverBudget,
    /// The data disk is below the floor.
    BelowFloor,
    /// Something could not be read; three in a row count as over the limit.
    Failed,
}

fn smoke_job(image: &str) -> JobSpec {
    JobSpec {
        name: None,
        image: image.into(),
        command: vec!["true".into()],
        env: std::collections::BTreeMap::new(),
        files: Vec::new(),
        resources: Resources {
            cpu: 0.25,
            memory_mb: 128,
            gpu: 0,
            disk_mb: 64,
        },
        timeout_s: 60,
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

impl<E: Engine, C: Cgroups, X: Egress> Sandbox for PodmanDriver<E, C, X> {
    type Job = PodmanJob<E, C, X::Session>;

    /// H2 §11.3: the lease's volumes are taken here, in memory, so that a lease that may not mount them, or whose
    /// volume another lease holds, or that does not fit the volume budget, is a `LeaseRejected` and never starts.
    fn admit(&self, lease: &LeaseContext) -> Result<(), LeaseRejectReason> {
        if lease.job.volumes.is_empty() {
            return Ok(());
        }
        match &self.cfg.volumes {
            Some(store) => store.reserve(lease.lease_id, lease.epoch, &lease.account_id, &lease.job),
            // H2 §6.1: a job this agent does not understand.
            None => Err(LeaseRejectReason::InvalidJob),
        }
    }

    async fn prepare(
        &self,
        enrolled: &AccountId,
        lease: LeaseContext,
        events: mpsc::Sender<SandboxEvent>,
        cancel: CancelHandle,
    ) -> Result<Self::Job, SandboxError> {
        // SI-1, before anything else: no file, cgroup or command exists for a lease of another account.
        if lease.account_id != *enrolled {
            return Err(reject(LeaseRejectReason::NotOwner));
        }
        let LeaseContext {
            lease_id,
            epoch,
            account_id,
            job,
            gpu,
        } = lease;
        // What admission took for the lease's volumes ([`Sandbox::admit`]) goes back on every return below, until
        // the cleanup guard has it.
        let volume_store = self.cfg.volumes.clone().filter(|_| !job.volumes.is_empty());
        let reservation = volume_store.clone().map(|store| Reservation {
            store,
            lease_id,
            epoch,
            armed: true,
        });
        // A lease's job was accepted by the hub (`Stored`). Services are understood only with a health probe, volumes
        // only with a volume store; blob inputs not at all yet (H2 §6.1: a job this agent does not understand is
        // `invalid_job`).
        let limits = Limits {
            h2: H2Features {
                services: self.cfg.health_probe.is_some(),
                volumes: self.cfg.volumes.is_some(),
                ..H2Features::default()
            },
            ..Limits::agent()
        };
        if job.validate_in(&limits, SpecContext::Stored).is_err() {
            return Err(reject(LeaseRejectReason::InvalidJob));
        }
        // H2 §11.3 "Who may mount", "One holder at a time", "Budget": the same answer as at admission (taking the
        // volumes again for the same lease changes nothing), for a lease that did not come through the executor.
        if let Some(store) = &volume_store {
            store.reserve(lease_id, epoch, &account_id, &job).map_err(reject)?;
        }
        let service = match (job.kind, &job.service, &self.cfg.health_probe) {
            (JobKind::Batch, None, _) => None,
            (JobKind::Service, Some(block), Some(probe)) => Some(ServiceRun {
                policy: HealthPolicy::of(block).ok_or(reject(LeaseRejectReason::InvalidJob))?,
                probe: Arc::clone(probe),
            }),
            // The validation already refused these.
            _ => return Err(reject(LeaseRejectReason::InvalidJob)),
        };
        // The ports the shim may forward (H2 §11.2), for a service on a node with the ingress bridge.
        let service_ports = match (&job.service, &self.cfg.ingress) {
            (Some(block), Some(_)) => Some(ingress::service_ports(block).ok_or(reject(LeaseRejectReason::InvalidJob))?),
            _ => None,
        };
        if !self.cfg.ready {
            return Err(reject(LeaseRejectReason::UnsupportedSandbox));
        }
        let gpu = self.gpu_device(&job, gpu.as_ref())?;
        // §9 "Disk floor": the owner's disk comes first. Unreadable free space refuses too (fail closed). `statvfs`
        // can stall on a sick disk, so it runs on the blocking pool.
        if !self.floor_allows_new_leases().await {
            return Err(reject(LeaseRejectReason::InsufficientCapacity));
        }
        let env = argv::env_file(&job.env).map_err(|_| reject(LeaseRejectReason::InvalidJob))?;
        let cancel = cancel.subscribe();

        // All the file work of `prepare` runs on the blocking pool: on a slow or sick disk it would otherwise stall
        // the async runtime, and the heartbeat with it.
        let dir = {
            let data_dir = self.cfg.data_dir.clone();
            setup_blocking(move || JobDir::create(&data_dir, &lease_id))
                .await?
                .map_err(|e| SandboxError::failed(error_code::SANDBOX_SETUP, e))?
        };
        let name = argv::container_name(&lease_id);
        // From here on, an early return drops the guard, which removes the container, cgroup and directory.
        let guard = Guard {
            shared: Arc::clone(&self.shared),
            lease: lease_id,
            name: name.clone(),
            dir: dir.clone(),
            volumes: volume_store.clone(),
            armed: true,
        };
        // The guard settles the volumes from here on: with the container's removal, as every other path does.
        if let Some(reservation) = reservation {
            reservation.keep();
        }
        let env_file = {
            let (dir, files, shim) = (dir.clone(), job.files.clone(), self.cfg.shim_path.clone());
            let ports = service_ports.clone();
            setup_blocking(move || {
                dir.write_inputs(&files)
                    .map_err(|e| SandboxError::failed(error_code::INVALID_INPUT, e))?;
                dir.install_shim(&shim)
                    .map_err(|e| SandboxError::failed(error_code::SANDBOX_SETUP, format!("shim: {e}")))?;
                if let Some(ports) = &ports {
                    ingress::write_ports_file(&dir.p2pc(), ports)
                        .map_err(|e| SandboxError::failed(error_code::SANDBOX_SETUP, format!("ports file: {e}")))?;
                }
                dir.write_env_file(&env)
                    .map_err(|e| SandboxError::failed(error_code::SANDBOX_SETUP, format!("env file: {e}")))
            })
            .await??
        };
        let engine = &self.shared.engine;
        let cgroups = &self.shared.cgroups;
        cgroups
            .create(&lease_id)
            .await
            .map_err(|e| SandboxError::failed(error_code::SANDBOX_SETUP, format!("cgroup: {e}")))?;
        let egress = if job.egress.allow.is_empty() {
            None
        } else {
            let request = EgressRequest {
                socket_path: dir.egress_socket(),
                allow: job.egress.allow.clone(),
                public_addrs: self.cfg.public_addrs.clone(),
                egress_ready: self.cfg.egress_ready.clone(),
            };
            Some(self.egress.start(&request).map_err(|e| {
                SandboxError::failed(
                    error_code::EGRESS_UNAVAILABLE,
                    format!("egress proxy could not start: {e}"),
                )
            })?)
        };

        // A service's ingress socket, before the container exists (the shim dials it as soon as it starts). An
        // early return below drops the session, which removes the socket and detaches the lease.
        let ingress = match (&service_ports, &self.cfg.ingress) {
            (Some(ports), Some(bridge)) => Some(
                bridge
                    .attach(Attach {
                        lease_id,
                        epoch,
                        ports,
                        dir: &dir.p2pc(),
                        cancel: cancel.clone(),
                    })
                    .map_err(|e| SandboxError::failed(error_code::SANDBOX_SETUP, e))?,
            ),
            _ => None,
        };

        let _ = events.send(SandboxEvent::Phase(Phase::Pulling)).await;
        self.pull_within_cap(&job.image, &cancel).await?;

        // H2 §11.3: the lock goes to disk and the tree is walked without following links, as late as possible and
        // before `podman create`. A refusal mounts nothing; the lock then stays with the lease until the guard has
        // made sure that no container of it exists.
        let volumes = match &volume_store {
            Some(store) => {
                let store = store.clone();
                setup_blocking(move || store.lock_and_check(&lease_id, epoch))
                    .await?
                    .map_err(|e| {
                        let code = if e.is_unsafe() {
                            error_code::VOLUME_UNSAFE
                        } else {
                            error_code::SANDBOX_SETUP
                        };
                        SandboxError::failed(code, e)
                    })?
            }
            None => Vec::new(),
        };

        let cgroup_parent = cgroups.parent_arg(&lease_id);
        let argv = argv::create_argv(&ArgvParams {
            platform: self.cfg.platform,
            gvisor: self.cfg.runtime == Runtime::Runsc,
            lease_id: &lease_id,
            job_dir: dir.root(),
            env_file: &env_file,
            cgroup_parent: &cgroup_parent,
            memory_mb: job.resources.memory_mb,
            cpu: job.resources.cpu,
            disk_mb: job.resources.disk_mb,
            gpu,
            image: &job.image,
            command: &job.command,
            volumes: &volumes,
        })
        .map_err(|e| SandboxError::failed(error_code::CREATE_FAILED, e))?;
        let _ = events.send(SandboxEvent::Phase(Phase::Creating)).await;
        let created = engine.create(&argv).await;
        // Podman copies the variables into the container's config at create time and never reads the file again,
        // so it goes now, before the container even starts. The guard removes it on every other path too.
        let removed = {
            let dir = dir.clone();
            blocking(move || dir.remove_env_file()).await
        };
        if let Err(e) = removed.unwrap_or_else(|e| Err(std::io::Error::other(e.to_string()))) {
            tracing::warn!(lease = %lease_id, error = %e, "cannot delete the env file");
        }
        created.map_err(|e| SandboxError::failed(error_code::CREATE_FAILED, e))?;

        Ok(PodmanJob {
            lease_id,
            epoch,
            name,
            dir,
            timeout: Duration::from_secs(u64::from(job.timeout_s)),
            disk_limit_bytes: job.resources.disk_mb.saturating_mul(MIB),
            outputs_max_bytes: job.outputs.max_mb.saturating_mul(MIB),
            events,
            cancel,
            exit: Mutex::new(None),
            pump: None,
            started_at: None,
            egress,
            ingress,
            service,
            volumes,
            guard,
        })
    }

    async fn start(&self, job: &mut Self::Job) -> Result<(), SandboxError> {
        if job.started_at.is_some() {
            return Err(SandboxError::failed(error_code::START_FAILED, "already started"));
        }
        let Attached { stdout, stderr, exit } = self
            .shared
            .engine
            .start_attached(&job.name)
            .map_err(|e| SandboxError::failed(error_code::START_FAILED, e))?;
        job.started_at = Some(Instant::now());
        *job.exit.get_mut().unwrap_or_else(PoisonError::into_inner) = Some(exit);
        let _ = job.events.send(SandboxEvent::Started).await;
        // A service is `starting` from its start (H2 §7.2).
        if job.service.is_some() {
            let starting = HealthChange {
                state: HealthState::Starting,
                detail: None,
            };
            let _ = job.events.send(SandboxEvent::Health(starting)).await;
        }
        // H2 §11.4: a service's logs are not capped in total; the executor keeps its most recent 64 MiB.
        let cap = if job.service.is_some() {
            u64::MAX
        } else {
            logs::LOG_CAP_BYTES
        };
        job.pump = Some(tokio::spawn(logs::pump_with_cap(
            stdout,
            stderr,
            job.events.clone(),
            cap,
        )));
        Ok(())
    }

    async fn wait(&self, job: &mut Self::Job) -> Result<Finished, SandboxError> {
        let exit = job.exit.get_mut().unwrap_or_else(PoisonError::into_inner).take();
        let (Some(mut exit), Some(started)) = (exit, job.started_at) else {
            return Err(SandboxError::failed(error_code::START_FAILED, "not started"));
        };
        let engine = &self.shared.engine;
        let cgroups = &self.shared.cgroups;
        let deadline = tokio::time::sleep_until(started + job.timeout);
        tokio::pin!(deadline);
        let period = self.cfg.disk_check_interval;
        let mut tick = tokio::time::interval_at(started + period, period);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut cancel = job.cancel.clone();
        let mut cancel_open = true;
        let mut stop: Option<Stop> = None;
        let mut escalate: Option<Pin<Box<Sleep>>> = None;
        let mut give_up: Option<Pin<Box<Sleep>>> = None;
        let mut stats = CgroupStats::default();
        let mut oom_reported = false;
        let mut failed_measurements = 0u32;
        let mut failed_volume_measurements = 0u32;

        // Set when the exit future failed: the container may still run, and nothing will tell us when it ends.
        let mut exit_lost = false;

        // A service's health checks and usage samples (nothing of it for a batch job).
        let target = ProbeTarget {
            lease_id: job.lease_id,
            job_dir: job.dir.root().to_path_buf(),
        };
        let mut health = job.service.as_ref().map(|s| HealthMachine::new(s.policy.limits));
        let mut health_tick = job.service.as_ref().map(|s| every(started, s.policy.interval));
        let mut start_period_end: Option<Pin<Box<Sleep>>> = job
            .service
            .as_ref()
            .and_then(|s| s.policy.limits)
            .map(|l| Box::pin(tokio::time::sleep_until(started + l.start_period)));
        let mut checking: Option<CheckFuture> = None;
        let mut usage_tick = job
            .service
            .as_ref()
            .map(|_| every(started, self.cfg.usage_interval.max(USAGE_INTERVAL)));

        let code = loop {
            if stop.is_none() && *cancel.borrow_and_update() {
                stop = Some(Stop::Cancelled);
                self.terminate(job, &mut escalate).await;
                continue;
            }
            tokio::select! {
                r = &mut exit, if !exit_lost => match r {
                    Ok(code) => break Some(code),
                    // §9: a lost exit is not a job exit. Stop the container with the usual sequence (unless a
                    // stop is already under way), then remove it below.
                    Err(e) => {
                        tracing::warn!(lease = %job.lease_id, error = %e, "lost the container's exit; stopping it");
                        exit_lost = true;
                        if stop.is_none() {
                            stop = Some(Stop::Lost);
                            self.terminate(job, &mut escalate).await;
                        }
                    }
                },
                () = &mut deadline, if stop.is_none() => {
                    stop = Some(Stop::TimedOut);
                    self.terminate(job, &mut escalate).await;
                }
                r = cancel.changed(), if stop.is_none() && cancel_open => {
                    // The top of the loop acts on a cancel; a gone sender just means "never".
                    cancel_open = r.is_ok();
                }
                _ = tick.tick(), if stop.is_none() => {
                    stats = stats.max(cgroups.stats(&job.lease_id));
                    // Fail closed: over the budget, below the floor or unmeasurable three times all stop the job.
                    let over = match self.measure(job).await {
                        Measurement::Used { state, bytes } => {
                            failed_measurements = 0;
                            oom_reported |= state.oom_killed;
                            (bytes > job.disk_limit_bytes).then_some(Stop::Disk)
                        }
                        Measurement::OverBudget => Some(Stop::Disk),
                        Measurement::BelowFloor => Some(Stop::Floor),
                        Measurement::Failed => {
                            failed_measurements += 1;
                            (failed_measurements >= disk::MAX_FAILED_MEASUREMENTS).then_some(Stop::Disk)
                        }
                    };
                    // The volumes, measured like the disk (H2 §11.3 "Size").
                    let over = match over {
                        Some(reason) => Some(reason),
                        None => self.volumes_over(job, &mut failed_volume_measurements).await,
                    };
                    if let Some(reason) = over {
                        stop = Some(reason);
                        let _ = engine.kill(&job.name, StopSignal::Kill).await;
                        give_up = Some(Box::pin(tokio::time::sleep(self.cfg.stop_grace)));
                    }
                }
                () = armed(&mut escalate) => {
                    escalate = None;
                    let _ = engine.kill(&job.name, StopSignal::Kill).await;
                    if exit_lost {
                        // Nothing can report the exit any more: SIGKILL was the last step.
                        break None;
                    }
                    give_up = Some(Box::pin(tokio::time::sleep(self.cfg.stop_grace)));
                }
                // Still no exit after SIGKILL and the grace: Podman lost track of it.
                () = armed(&mut give_up) => break None,
                () = ticking(&mut health_tick),
                    if stop.is_none() && checking.is_none() && health.as_ref().is_some_and(HealthMachine::wants_checks) =>
                {
                    checking = job.service.as_ref().map(|s| s.check(&target));
                }
                () = armed(&mut start_period_end), if stop.is_none() => {
                    start_period_end = None;
                    // Still starting: one more check now decides (unless one is under way, which then decides).
                    if health.as_mut().is_some_and(HealthMachine::start_period_ended) && checking.is_none() {
                        checking = job.service.as_ref().map(|s| s.check(&target));
                    }
                }
                result = in_flight(&mut checking), if stop.is_none() => {
                    checking = None;
                    let step = health.as_mut().map_or(Step::Stay, |h| h.record(result));
                    let (report, failed) = match step {
                        Step::Stay => (None, None),
                        Step::Report(state, detail) => (Some((state, detail)), None),
                        Step::Stop(state, detail) => (state.map(|s| (s, Some(detail.clone()))), Some(detail)),
                    };
                    if let Some((state, detail)) = report {
                        tracing::info!(lease = %job.lease_id, ?state, detail = ?detail, "service health changed");
                        let _ = job.events.send(SandboxEvent::Health(HealthChange { state, detail })).await;
                    }
                    if let Some(detail) = failed {
                        // `detail` comes from the container's answer: logged escaped.
                        tracing::warn!(lease = %job.lease_id, detail = ?detail, "the service's health check failed; stopping it");
                        stop = Some(Stop::Health);
                        self.terminate(job, &mut escalate).await;
                    }
                }
                () = ticking(&mut usage_tick), if stop.is_none() => {
                    stats = stats.max(cgroups.stats(&job.lease_id));
                    // Cumulative values: a sample the executor has no room for is replaced by the next one.
                    let _ = job.events.try_send(SandboxEvent::Usage(usage_sample(&stats)));
                }
            }
        };
        let wall = started.elapsed();
        if code.is_none() {
            // The exit was never seen: make sure the container is gone now, not only at cleanup.
            if let Err(e) = engine.remove(&job.name).await {
                tracing::warn!(lease = %job.lease_id, error = %e, "cannot remove a container whose exit was lost");
            }
        }

        // The pump ends when Podman closes the pipes; bound the wait anyway.
        let logs = match job.pump.take() {
            Some(mut pump) => match tokio::time::timeout(self.cfg.stop_grace, &mut pump).await {
                Ok(Ok(summary)) => summary,
                _ => {
                    pump.abort();
                    LogSummary::default()
                }
            },
            None => LogSummary::default(),
        };
        stats = stats.max(cgroups.stats(&job.lease_id));
        // With `--rm` a container that ran is usually gone by now; if not, take its word too. A container that is
        // still there and never started means `podman start` itself failed (§9 "Podman failures are not job
        // exits"): its 125/126/127 is Podman's, not the job's.
        let mut never_started = false;
        if let Ok(state) = engine.inspect(&job.name).await {
            oom_reported |= state.oom_killed;
            never_started = state.started == Some(false);
        }
        let oom = stats.oom_kill > 0 || oom_reported;
        let (outcome, exit_code, error) = match (stop, code) {
            // No exit was ever seen (the exit future failed, or nothing exited after SIGKILL): the agent cannot
            // vouch for how it ended, whatever stopped it (§9 "Podman failures are not job exits").
            (_, None) => (Outcome::Error, None, Some(error_code::LOST_EXIT)),
            (None, Some(_)) if never_started => (Outcome::Error, None, Some(error_code::START_FAILED)),
            (Some(Stop::TimedOut), _) => (Outcome::TimedOut, None, None),
            (Some(Stop::Cancelled), _) => (Outcome::Cancelled, None, None),
            (Some(Stop::Disk), _) => (Outcome::Error, None, Some(error_code::DISK_LIMIT)),
            (Some(Stop::Floor), _) => (Outcome::Error, None, Some(error_code::DISK_FLOOR)),
            (Some(Stop::Volume), _) => (Outcome::Error, None, Some(error_code::VOLUME_LIMIT)),
            (Some(Stop::Health), _) => (Outcome::Error, None, Some(error_code::HEALTH_CHECK_FAILED)),
            // Exit 137 alone is not an OOM: only the cgroup counter or Podman's flag say so (§9 "Memory").
            (None, _) if oom => (Outcome::Error, code, Some(error_code::MEMORY_LIMIT)),
            (None, Some(c)) => (Outcome::Exited, Some(c), None),
            (Some(Stop::Lost), Some(_)) => (Outcome::Error, None, Some(error_code::LOST_EXIT)),
        };
        Ok(Finished {
            outcome,
            exit_code,
            error: error.map(String::from),
            usage: Usage {
                wall_ms: u64::try_from(wall.as_millis()).unwrap_or(u64::MAX),
                cpu_used_ms: stats.cpu_usage_usec / 1000,
                max_rss_mb: stats.memory_peak_bytes / MIB,
            },
            stats,
            logs,
        })
    }

    async fn collect_outputs(&self, job: &Self::Job) -> Result<CollectedOutputs, SandboxError> {
        // Nothing may still write to outputs/ while it is walked.
        self.shared
            .engine
            .remove(&job.name)
            .await
            .map_err(|e| SandboxError::failed(error_code::OUTPUTS_FAILED, e))?;
        let root = job.dir.outputs();
        let max = job.outputs_max_bytes;
        tokio::task::spawn_blocking(move || outputs::collect(&root, max))
            .await
            .map_err(|e| SandboxError::failed(error_code::OUTPUTS_FAILED, e))?
            .map_err(|e| SandboxError::failed(error_code::OUTPUTS_FAILED, e))
    }

    async fn cleanup(&self, mut job: Self::Job) {
        job.guard.armed = false;
        if let Some(pump) = job.pump.take() {
            pump.abort();
        }
        // Stops the egress proxy and removes its socket.
        drop(job.egress.take());
        // Detaches the lease from the ingress bridge and removes its socket: no new port stream reaches it.
        drop(job.ingress.take());
        *job.exit.get_mut().unwrap_or_else(PoisonError::into_inner) = None;
        cleanup_steps(
            &self.shared,
            &job.lease_id,
            &job.name,
            &job.dir,
            job.guard.volumes.as_ref(),
        )
        .await;
    }

    async fn smoke(&self) -> SmokeResult {
        let account = AccountId::generate();
        let lease = LeaseContext {
            lease_id: LeaseId::generate(),
            epoch: 1,
            account_id: account,
            job: smoke_job(&self.cfg.smoke_image),
            gpu: None,
        };
        let (tx, mut rx) = mpsc::channel(64);
        let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let report = run_lease(self, &account, lease, tx, CancelHandle::new()).await;
        drain.abort();
        let detail = match report {
            super::LeaseReport::Finished { finished, .. } => match (finished.outcome, finished.exit_code) {
                (Outcome::Exited, Some(0)) => return SmokeResult { ok: true, detail: None },
                (Outcome::Exited, Some(code)) => format!("exit {code}"),
                (Outcome::Error, _) => finished.error.unwrap_or_else(|| "error".into()),
                (Outcome::TimedOut, _) => "timed_out".into(),
                (Outcome::Cancelled, _) => "cancelled".into(),
                (Outcome::Exited, None) => "no exit code".into(),
            },
            super::LeaseReport::Rejected(reason) => format!("rejected: {reason}"),
        };
        SmokeResult {
            ok: false,
            detail: Some(detail),
        }
    }
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;
