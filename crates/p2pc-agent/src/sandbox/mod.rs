// SPDX-License-Identifier: Apache-2.0

//! The sandbox driver (spec §9, T08): runs a validated lease in a hardened Podman container.
//!
//! - [`Sandbox`] is the lifecycle: `prepare`, `start`, `wait`, `cancel`, `collect_outputs`, `cleanup`, plus the
//!   once-per-boot `smoke` container. [`PodmanDriver`] is its first implementation; [`run_lease`] drives a lease
//!   through all of it.
//! - **SI-1:** `prepare` checks `lease.account_id` against the enrolled account **before anything else**; there
//!   is no other way in.
//! - [`argv`]: the §9 fixed `podman create` argv (SI-2), a pure function.
//! - [`jobdir`]: `<data_dir>/jobs/<lease_id>/` and the `O_NOFOLLOW` input writer.
//! - [`cgroup`]: the per-lease cgroup (`--cgroup-parent`), read for `oom_kill` and `pids.events`.
//! - [`engine`]: the Podman operations, behind a trait.
//! - [`logs`]: 64 KiB chunks, the 64 MiB cap with one marker, and draining after it (batch jobs; a service's logs
//!   are not capped in total, the executor keeps its most recent 64 MiB, H2 §11.4).
//! - [`health`]: a service's health check and state machine (H2 §7.2), run by the driver's `wait`.
//! - [`ingress`]: the ingress bridge (H2 §11.2): the agent's `ingress.sock` in a service's `p2pc/`, which the shim
//!   dials; port streams and health checks reach the service through it, and the container keeps `--network=none`.
//! - [`outputs`]: SI-9 collection with SHA-256.
//! - [`Egress`]: the seam to the per-job egress proxy; [`ProxyEgress`] plugs in T09's [`crate::egress`]. The
//!   socket directory is mounted with `:U`.

use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use p2pc_proto::api::{JobSpec, SmokeResult};
use p2pc_proto::ids::{AccountId, LeaseId};
use p2pc_proto::protocol::{LeaseRejectReason, Outcome, Usage};
use tokio::sync::{mpsc, watch};

pub mod argv;
pub mod cgroup;
pub mod disk;
mod driver;
pub mod engine;
pub mod health;
pub mod ingress;
pub mod jobdir;
pub mod logs;
pub mod outputs;
mod proxy;

pub use driver::{DriverConfig, PodmanDriver, PodmanJob, SweepReport};
pub use logs::LogChunk;
pub use outputs::{CollectedFile, CollectedOutputs, SkipReason, Skipped};
pub use proxy::{KnownPublicAddrs, PUBLIC_ADDRS_UNKNOWN, ProxyEgress};

/// The grace period between SIGTERM and SIGKILL (§9 "Timeout", "Cancel").
pub const STOP_GRACE: Duration = Duration::from_secs(10);
/// How often the disk use is measured (§9 "Disk").
pub const DISK_CHECK_INTERVAL: Duration = Duration::from_secs(2);
/// `error` codes in `JobFinished` (§6) for `outcome = "error"`.
pub mod error_code {
    /// The lease cgroup's `memory.events` showed `oom_kill > 0`, or Podman reported `OOMKilled` (§9 "Memory").
    pub const MEMORY_LIMIT: &str = "memory_limit";
    /// `outputs/` plus the writable layer went over `resources.disk_mb`, `outputs/` went over the entry budget, or
    /// the measurement failed three times in a row (§9 "Disk": it fails closed).
    pub const DISK_LIMIT: &str = "disk_limit";
    /// Free space on the agent's data disk fell below the larger of 5 GiB and 5 % (§9 "Disk floor").
    pub const DISK_FLOOR: &str = "disk_floor";
    /// `podman pull` failed or timed out.
    pub const IMAGE_PULL_FAILED: &str = "image_pull_failed";
    /// The pulled image is larger than the agent's cap.
    pub const IMAGE_TOO_LARGE: &str = "image_too_large";
    /// The job asked for egress and the proxy could not start.
    pub const EGRESS_UNAVAILABLE: &str = "egress_unavailable";
    /// An input file could not be written (traversal, symlink, bad content).
    pub const INVALID_INPUT: &str = "invalid_input";
    /// The job directory, env file, shim or cgroup could not be set up.
    pub const SANDBOX_SETUP: &str = "sandbox_setup";
    /// `podman create` failed.
    pub const CREATE_FAILED: &str = "create_failed";
    /// `podman start` failed.
    pub const START_FAILED: &str = "start_failed";
    /// The engine never reported an exit code, even after SIGKILL.
    pub const LOST_EXIT: &str = "lost_exit_code";
    /// The container could not be removed before collecting outputs, or `outputs/` could not be read.
    pub const OUTPUTS_FAILED: &str = "outputs_failed";
    /// A service was still `starting` after its start period, or failed `failure_threshold` consecutive checks after
    /// it was healthy, and the agent stopped it (H2 §7.2).
    pub const HEALTH_CHECK_FAILED: &str = "health_check_failed";
}

/// The GPU the scheduler assigned through the lease (T06), by UUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuRef {
    /// The GPU's `uuid` from the inventory.
    pub uuid: String,
}

/// A lease to run: the server's `Lease` message after `LeaseJob::parse_strict`.
#[derive(Debug, Clone)]
pub struct LeaseContext {
    /// Lease.
    pub lease_id: LeaseId,
    /// Epoch.
    pub epoch: u64,
    /// The job's account. Must be the node's enrolled owner (SI-1).
    pub account_id: AccountId,
    /// The job, strictly parsed. `Debug` redacts env values.
    pub job: JobSpec,
    /// The GPU assigned to a GPU job.
    pub gpu: Option<GpuRef>,
}

/// Progress of a lease, sent while it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxEvent {
    /// A phase began.
    Phase(Phase),
    /// The container started (`JobStarted`).
    Started,
    /// Output.
    Log(LogChunk),
    /// A service's health changed (H2 §6.1 `ServiceHealth`). The first one, `starting`, follows `Started`.
    Health(HealthChange),
    /// A service's cumulative usage from its lease cgroup, sampled at most once a minute (H2 §11.4).
    Usage(UsageSample),
}

/// A change of a service's health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthChange {
    /// The new state.
    pub state: p2pc_proto::protocol::HealthState,
    /// A short detail (at most [`health::MAX_DETAIL_LEN`] bytes, no control characters).
    pub detail: Option<String>,
}

/// A service's usage so far, from its lease cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageSample {
    /// CPU time, cumulative, in milliseconds.
    pub used_cpu_ms: u64,
    /// The attempt's peak resident memory so far, in MiB.
    pub max_rss_mb: u64,
}

/// The phases before the job runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// `podman pull`, in the agent's context.
    Pulling,
    /// `podman create`.
    Creating,
}

/// Cancels a running lease: SIGTERM, the grace period, then SIGKILL (§9 "Cancel"). Cloneable; cancelling twice is
/// harmless.
#[derive(Debug, Clone)]
pub struct CancelHandle {
    tx: Arc<watch::Sender<bool>>,
}

impl Default for CancelHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelHandle {
    /// A handle that has not been cancelled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx: Arc::new(watch::channel(false).0),
        }
    }

    /// Requests cancellation.
    pub fn cancel(&self) {
        self.tx.send_replace(true);
    }

    /// Whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.tx.borrow()
    }

    /// Resolves once cancellation was requested (at once if it already was).
    pub async fn cancelled(&self) {
        let mut rx = self.subscribe();
        // The sender lives in `self`, so `wait_for` can only end with the flag set.
        let _ = rx.wait_for(|cancelled| *cancelled).await;
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }
}

/// Why a lease did not run to completion in the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxError {
    /// The lease is refused (`LeaseRejected`); nothing was created.
    #[error("lease rejected: {0}")]
    Rejected(LeaseRejectReason),
    /// Cancelled before the container started.
    #[error("cancelled")]
    Cancelled,
    /// The sandbox failed; reported as `outcome = "error"` with `error = code`.
    #[error("{code}: {detail}")]
    Failed {
        /// One of [`error_code`].
        code: &'static str,
        /// Human detail. Never contains env values.
        detail: String,
    },
}

impl SandboxError {
    pub(crate) fn failed(code: &'static str, detail: impl std::fmt::Display) -> Self {
        Self::Failed {
            code,
            detail: detail.to_string(),
        }
    }
}

impl SandboxError {
    /// Logs the cause of a failure at `warn`. The server gets only the short code (`JobFinished.error`); this is
    /// where the owner finds out why (T10n: an egress socket path over `sun_path` was reported as
    /// `egress_unavailable` and nothing said so). `detail` never holds env values (see [`SandboxError::Failed`]); it is logged escaped, as it can echo job-supplied paths.
    /// A cancel or a refused lease is not a failure and logs nothing here.
    pub(crate) fn log_failure(&self, lease_id: &LeaseId, epoch: u64) {
        if let Self::Failed { code, detail } = self {
            tracing::warn!(%lease_id, epoch, code, detail = ?detail, "the sandbox failed the job");
        }
    }
}

/// How an attempt ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// `JobFinished.outcome`.
    pub outcome: Outcome,
    /// `JobFinished.exit_code`, when the process exited on its own.
    pub exit_code: Option<i32>,
    /// `JobFinished.error`, for `outcome = "error"`.
    pub error: Option<String>,
    /// `JobFinished.usage`.
    pub usage: Usage,
    /// The lease cgroup's counters.
    pub stats: cgroup::CgroupStats,
    /// What the log pump did.
    pub logs: logs::LogSummary,
}

impl Finished {
    /// A finish without a run (an error or cancel before the container started).
    #[must_use]
    pub fn without_run(outcome: Outcome, error: Option<String>) -> Self {
        Self {
            outcome,
            exit_code: None,
            error,
            usage: Usage {
                wall_ms: 0,
                cpu_used_ms: 0,
                max_rss_mb: 0,
            },
            stats: cgroup::CgroupStats::default(),
            logs: logs::LogSummary::default(),
        }
    }
}

/// The per-job egress proxy, as the driver needs it (T09 provides it).
///
/// T09's proxy fits directly:
///
/// ```text
/// EgressProxy::start_with(
///     &request.socket_path,
///     Policy::system(request.allow.clone(), request.public_addrs.clone(), request.egress_ready.clone()),
///     SocketOptions { owner: None },
/// )
/// ```
///
/// `owner: None` because the driver mounts the socket directory with `:U`: Podman gives the socket to the
/// container's mapped root, so the proxy does not `chown` it (spec §9 "Socket permissions"). `public_addrs` is the
/// live source of the node's public addresses (hairpin NAT). Dropping the session (T09's `EgressHandle`) stops the
/// proxy.
pub trait Egress: Send + Sync + 'static {
    /// A running proxy. Dropping it stops the proxy and removes the socket.
    type Session: Send + Sync + 'static;
    /// Creates the 0600 socket at `request.socket_path` and starts serving. Called inside a Tokio runtime.
    ///
    /// # Errors
    /// Why the proxy could not start.
    fn start(&self, request: &EgressRequest) -> Result<Self::Session, String>;
}

/// What the egress proxy of one job needs.
#[derive(Debug, Clone)]
pub struct EgressRequest {
    /// `<job>/p2pc/egress.sock`, seen as `/.p2pc/egress.sock` by the shim.
    pub socket_path: PathBuf,
    /// The job's `egress.allow` (non-empty).
    pub allow: Vec<String>,
    /// The node's public addresses as observed by iroh, refused by the proxy (hairpin NAT, §9). A live source, as
    /// T09's `Policy::public_addrs` takes it: T05b updates it when iroh observes a change.
    pub public_addrs: watch::Receiver<Vec<IpAddr>>,
    /// Whether the egress gate is open (T10e): the node's public addresses are known well enough to refuse
    /// hairpin NAT (a host with IPv4 needs a public IPv4 among them). Apart from `public_addrs` on purpose: the gate
    /// can close again (IPv4 came up after it opened on IPv6) while the addresses stay, so running proxies keep
    /// refusing them. [`KnownPublicAddrs`] checks it before a proxy starts, and a running proxy checks it for every
    /// new upstream connection (T10f): while it is closed, it refuses IPv4 destinations.
    pub egress_ready: watch::Receiver<p2pc_net::EgressGate>,
}

/// No egress proxy (tests, the smoke container): jobs that ask for egress fail with `egress_unavailable`. Jobs
/// without egress are unaffected (they have `--network=none` and no socket). The agent uses [`ProxyEgress`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEgress;

impl Egress for NoEgress {
    type Session = ();

    fn start(&self, _: &EgressRequest) -> Result<(), String> {
        Err("this driver has no egress proxy".into())
    }
}

/// The sandbox lifecycle.
pub trait Sandbox: Send + Sync {
    /// A prepared (and later running) job. Dropping it without [`Sandbox::cleanup`] still cleans up, in the
    /// background (the cleanup guard).
    type Job: Send;

    /// Checks the lease (SI-1 first), creates the job directory, inputs, env file and cgroup, starts the egress
    /// proxy if asked, pulls the image and creates the container.
    fn prepare(
        &self,
        enrolled: &AccountId,
        lease: LeaseContext,
        events: mpsc::Sender<SandboxEvent>,
        cancel: CancelHandle,
    ) -> impl Future<Output = Result<Self::Job, SandboxError>> + Send;

    /// Starts the container and the log capture.
    fn start(&self, job: &mut Self::Job) -> impl Future<Output = Result<(), SandboxError>> + Send;

    /// Waits for the exit while enforcing the timeout, cancel and disk limit; maps the outcome.
    fn wait(&self, job: &mut Self::Job) -> impl Future<Output = Result<Finished, SandboxError>> + Send;

    /// Requests cancellation of the job `handle` belongs to.
    fn cancel(&self, handle: &CancelHandle) {
        handle.cancel();
    }

    /// Collects `outputs/` (SI-9), after making sure the container is gone.
    fn collect_outputs(&self, job: &Self::Job) -> impl Future<Output = Result<CollectedOutputs, SandboxError>> + Send;

    /// Removes the container, the cgroup and the job directory.
    fn cleanup(&self, job: Self::Job) -> impl Future<Output = ()> + Send;

    /// Runs the tiny smoke container once (`--network=none`, the fixed argv, `true`).
    fn smoke(&self) -> impl Future<Output = SmokeResult> + Send;
}

/// The end of a lease, for `LeaseRejected` or `JobFinished`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseReport {
    /// `LeaseRejected{reason}`: nothing ran.
    Rejected(LeaseRejectReason),
    /// `JobFinished`.
    Finished {
        /// How it ended.
        finished: Finished,
        /// The files T10 uploads (empty when nothing ran).
        outputs: CollectedOutputs,
    },
}

/// Runs a lease through the whole lifecycle and always cleans up.
///
/// The caller keeps `cancel` to stop the job (`Cancel` from the server, or the agent's own lease timer). T10
/// uploads `outputs` **before** the job directory goes away: call [`Sandbox`] methods directly for that, as this
/// helper cleans up as soon as the outputs are listed. It is what the smoke test and the tests use.
pub async fn run_lease<S: Sandbox>(
    sandbox: &S,
    enrolled: &AccountId,
    lease: LeaseContext,
    events: mpsc::Sender<SandboxEvent>,
    cancel: CancelHandle,
) -> LeaseReport {
    let (lease_id, epoch) = (lease.lease_id, lease.epoch);
    let mut job = match sandbox.prepare(enrolled, lease, events, cancel).await {
        Ok(job) => job,
        Err(e) => return report_error(e, &lease_id, epoch),
    };
    if let Err(e) = sandbox.start(&mut job).await {
        sandbox.cleanup(job).await;
        return report_error(e, &lease_id, epoch);
    }
    let finished = match sandbox.wait(&mut job).await {
        Ok(f) => f,
        Err(e) => {
            sandbox.cleanup(job).await;
            return report_error(e, &lease_id, epoch);
        }
    };
    let outputs = sandbox.collect_outputs(&job).await.unwrap_or_default();
    sandbox.cleanup(job).await;
    LeaseReport::Finished { finished, outputs }
}

fn report_error(e: SandboxError, lease_id: &LeaseId, epoch: u64) -> LeaseReport {
    e.log_failure(lease_id, epoch);
    let finished = match e {
        SandboxError::Rejected(reason) => return LeaseReport::Rejected(reason),
        SandboxError::Cancelled => Finished::without_run(Outcome::Cancelled, None),
        SandboxError::Failed { code, .. } => Finished::without_run(Outcome::Error, Some(code.to_string())),
    };
    LeaseReport::Finished {
        finished,
        outputs: CollectedOutputs::default(),
    }
}

/// Puts the smoke result into the WSL2 health block (T07 leaves `smoke: null`). No-op on native Linux.
pub fn apply_smoke(inventory: &mut p2pc_proto::api::Inventory, smoke: SmokeResult) {
    if let Some(wsl2) = inventory.wsl2.as_mut() {
        wsl2.smoke = Some(smoke);
    }
}

/// Runs [`Sandbox::smoke`] once per boot: the result is kept in `marker` (put it on a tmpfs such as `/run/p2pc`,
/// which a reboot clears) and returned from there afterwards.
pub async fn smoke_once_per_boot<S: Sandbox>(sandbox: &S, marker: &std::path::Path) -> SmokeResult {
    if let Ok(text) = std::fs::read_to_string(marker)
        && let Ok(cached) = serde_json::from_str::<SmokeResult>(&text)
    {
        return cached;
    }
    let result = sandbox.smoke().await;
    if let Ok(json) = serde_json::to_string(&result) {
        if let Some(dir) = marker.parent() {
            let _ = crate::identity::create_private_dirs(dir);
        }
        let _ = std::fs::write(marker, json);
    }
    result
}
