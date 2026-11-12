// SPDX-License-Identifier: Apache-2.0

//! The production node, as `p2pc-agent run` builds it (T10a): the data directory's lock, what the machine is at
//! start, and the Podman driver with the lease executor on top of it.
//!
//! - **One agent at a time** (T10a review, P3-4): [`lock_data_dir`] makes the data dir private first (created or
//!   tightened to 0700, T10i), then takes an exclusive `flock` on `<data_dir>/agent.lock` before anything else is made
//!   in it. A second `run` exits with a clear error instead of sweeping the first one's containers.
//! - **The driver is built once**, from [`NodeFacts`] detected at start: the §9.0 platform, the sandbox readiness,
//!   the shim next to the agent binary, the lease cgroups of the profile, the offerable GPUs. What it cannot serve is
//!   never offered ([`DriverLimits`]), and the inventory says so (P3-5).
//! - **Persistent volumes** (H2 §11.3): [`open_volumes`] loads `<data_dir>/volumes` once, before the driver is built;
//!   every holder it finds stays held until the orphan sweep of [`crate::executor::Executor::startup`] confirmed its
//!   container gone. The driver always gets the store (leftover volumes still expire and are deleted). The node
//!   declares the `volumes` capability, and reports its volumes, only when the owner gave them a share of the disk
//!   (`share.volumes_mb` of at least one volume's minimum): [`Node::volumes`]. [`keep_volumes`] is the periodic upkeep.
//! - **Hairpin NAT** (§9, T10a review P2-2, T10e): the egress proxy gets the node's public addresses as a **live**
//!   source (iroh's observed addresses, [`crate::connection::endpoint::IrohConnector::public_addrs`]), which are kept
//!   until a fresh observation of the same family replaces them. Egress jobs fail with `egress_unavailable` while the
//!   egress gate is closed ([`crate::connection::endpoint::IrohConnector::egress_ready`], checked by
//!   [`KnownPublicAddrs`]): on a host with IPv4 the gate waits for a public IPv4 observed on the current network, and
//!   it closes again if IPv4 comes up after it opened on IPv6. **A move of the default route** (it moves to another
//!   interface, or goes away and comes back) closes it, and the gate's own watcher asks the daemon for a new endpoint
//!   (`p2pc_net::GateSinks::rebind`, [`crate::connection::Connector::rebind_signal`]), even with the same address
//!   selection and whatever the network watcher saw; the gate reopens only on the new endpoint's first public IPv4,
//!   never on what the endpoint bound before the move lists, however long it waits (T10l, R-2). Proxies already
//!   running follow it (T10f): while it is not open they refuse IPv4 destinations. When the host has IPv4 but iroh
//!   binds none, the gate says it can never open and the job's error says how to fix it. The gate says why it is in
//!   its state: in the log (`egress gate changed`), and in `p2pc-agent status` ([`crate::connection::gate`]).

use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use p2pc_proto::api::Platform;
use p2pc_proto::ids::AccountId;
use rustix::fs::{FlockOperation, Mode, OFlags};
use tokio::sync::watch;

use crate::config::Config;
use crate::connection::{OfferFeed, Uplink};
use crate::executor::capacity::{DriverLimits, Offer};
use crate::executor::{Clock, Executor, SystemClock};
use crate::host::Host;
use crate::identity::ensure_private_dir;
use crate::inventory::{self, Report};
use crate::runner::SystemRunner;
use crate::sandbox::cgroup::{FsCgroups, HostCgroups, SystemdCgroups, user_service_cgroup};
use crate::sandbox::engine::{PULL_TIMEOUT, PodmanEngine};
use crate::sandbox::ingress::IngressBridge;
use crate::sandbox::{DriverConfig, KnownPublicAddrs, PodmanDriver, ProxyEgress};
use crate::volumes::{MAINTENANCE_INTERVAL, StoreConfig, VOLUME_MB_RANGE, VolumeStore};

/// The lock file inside the data dir.
pub const LOCK_FILE: &str = "agent.lock";

/// The production sandbox: Podman, the host's lease cgroups, T09's egress proxy behind the public-address gate.
pub type NodeDriver =
    PodmanDriver<PodmanEngine<SystemRunner>, HostCgroups<SystemRunner>, KnownPublicAddrs<ProxyEgress>>;

/// Why the data dir could not be locked.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// Another agent holds it.
    #[error(
        "another p2pc-agent is already running with the data directory {0}; stop it first (only one agent may run \
         per data directory)"
    )]
    Held(PathBuf),
    /// The data dir cannot be used: it could not be created 0700, or it is open to others and holds files that are not
    /// the agent's (T10i: the same check as the identity's).
    #[error(transparent)]
    Dir(#[from] crate::identity::IdentityError),
    /// The lock file could not be opened or locked.
    #[error("cannot lock {path}: {source}")]
    Io {
        /// The lock file.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
}

/// The data dir's exclusive lock, held until it is dropped (the process's life for `run`).
#[derive(Debug)]
pub struct AgentLock {
    _fd: OwnedFd,
    path: PathBuf,
}

impl AgentLock {
    /// The lock file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Takes the exclusive lock on `<data_dir>/agent.lock` (created 0600 if missing), without blocking: a held lock is
/// tried again [`LOCK_RETRIES`] times, [`LOCK_RETRY_PAUSE`] apart, before it is reported. A missing data dir
/// is created 0700 first, and an open one is tightened or refused as the identity's check does.
///
/// # Errors
/// [`LockError::Held`] when another agent holds it; [`LockError::Dir`] when the data dir is refused; [`LockError::Io`]
/// when the lock file cannot be opened or locked.
pub fn lock_data_dir(data_dir: &Path) -> Result<AgentLock, LockError> {
    lock_data_dir_with(data_dir, LOCK_RETRIES, || std::thread::sleep(LOCK_RETRY_PAUSE))
}

/// How many times [`lock_data_dir`] tries again when the lock is held, and how long it waits before each: long enough
/// for a `p2pc-agent status` probe ([`agent_running`], a shared lock held for an instant) to be over, short enough that
/// a second real agent is told at once (T10l review P3 2).
pub const LOCK_RETRIES: u32 = 3;
/// See [`LOCK_RETRIES`].
pub const LOCK_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_millis(50);

/// [`lock_data_dir`] with `retries` more tries after the first, calling `pause` before each.
fn lock_data_dir_with(data_dir: &Path, retries: u32, mut pause: impl FnMut()) -> Result<AgentLock, LockError> {
    let path = data_dir.join(LOCK_FILE);
    let io = |e: rustix::io::Errno| LockError::Io {
        path: path.clone(),
        source: e.into(),
    };
    // The data dir is 0700 before anything is made in it (T10i): the lock file is the first file there.
    ensure_private_dir(data_dir)?;
    let fd = rustix::fs::open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(io)?;
    let mut left = retries;
    loop {
        match rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(AgentLock { _fd: fd, path }),
            Err(rustix::io::Errno::WOULDBLOCK) if left > 0 => {
                left -= 1;
                pause();
            }
            Err(rustix::io::Errno::WOULDBLOCK) => return Err(LockError::Held(data_dir.to_path_buf())),
            Err(e) => return Err(io(e)),
        }
    }
}

/// Whether an agent holds the data dir's lock now: `p2pc-agent status` uses it to tell the running agent's gate from a
/// file left by a run that is over. The lock is only probed (a shared lock, taken without waiting and released at
/// once), never created; no lock file means no agent has run here.
#[must_use]
pub fn agent_running(data_dir: &Path) -> bool {
    let Ok(fd) = rustix::fs::open(
        data_dir.join(LOCK_FILE),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return false;
    };
    matches!(
        rustix::fs::flock(&fd, FlockOperation::NonBlockingLockShared),
        Err(rustix::io::Errno::WOULDBLOCK)
    )
}

/// Where the static shim is: next to the agent's own binary (the release ships both, §9 "Shim").
#[must_use]
pub fn shim_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("p2pc-shim")))
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin/p2pc-shim"))
}

/// The lease cgroups of `platform`'s §9.0 profile on this host, or why there are none.
///
/// # Errors
/// On Linux, when the agent does not run in a systemd user service with cgroup delegation.
pub fn host_cgroups(platform: Platform) -> Result<HostCgroups<SystemRunner>, String> {
    match platform {
        Platform::Wsl2 => Ok(HostCgroups::Fs(FsCgroups::system())),
        Platform::Linux => {
            let own = std::fs::read_to_string("/proc/self/cgroup").map_err(|e| format!("/proc/self/cgroup: {e}"))?;
            let service = user_service_cgroup(&own)
                .ok_or("the agent does not run in a systemd user service with cgroup delegation")?;
            Ok(HostCgroups::Systemd(SystemdCgroups::new(
                SystemRunner::default(),
                Path::new("/sys/fs/cgroup").join(service),
            )))
        }
    }
}

/// What the machine is at agent start: what the driver is built from.
#[derive(Debug)]
pub struct NodeFacts {
    /// The §9.0 profile.
    pub platform: Platform,
    /// The detection, if it worked.
    pub report: Option<Report>,
    /// The shim's path (it may be missing).
    pub shim: PathBuf,
    /// The lease cgroups, or why there are none.
    pub cgroups: Result<HostCgroups<SystemRunner>, String>,
    /// The node's persistent volumes as found on disk ([`open_volumes`]); `None` when the node is not enrolled or
    /// they could not be opened: no volume is mounted then.
    pub volumes: Option<VolumeStore>,
}

/// Opens the persistent volumes of `owner` under the data dir (H2 §11.3), on the blocking pool. The budget starts
/// at 0: [`build`] sets it from the detected share. An error is logged and means "no volumes": nothing is mounted
/// from a `volumes/` directory that is not the agent's own.
pub async fn open_volumes(config: &Config, owner: AccountId, clock: Arc<dyn Clock>) -> Option<VolumeStore> {
    let cfg = StoreConfig {
        data_dir: config.data_dir.clone(),
        owner,
        budget_mb: 0,
        retention_days: config.volume_retention_days,
        // H1's entry budget of the disk measurement (H2 §11.3).
        entry_budget: crate::sandbox::outputs::MAX_ENTRIES,
        clock,
    };
    match tokio::task::spawn_blocking(move || VolumeStore::open(cfg)).await {
        Ok(Ok(store)) => Some(store),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "cannot open the node's volumes; no volume will be mounted");
            None
        }
        Err(_) => {
            tracing::error!("opening the node's volumes panicked; no volume will be mounted");
            None
        }
    }
}

/// Runs the volume upkeep of the node's driver every [`MAINTENANCE_INTERVAL`], for as long as the agent runs: it
/// retries the removal of containers that still hold a volume and deletes the unused volumes past their retention
/// ([`PodmanDriver::maintain_volumes`]).
pub async fn keep_volumes(executor: Arc<Executor<NodeDriver>>) {
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + MAINTENANCE_INTERVAL, MAINTENANCE_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        executor.sandbox().maintain_volumes().await;
    }
}

impl NodeFacts {
    /// Detects them on this machine.
    pub async fn detect(host: &Host, config: &Config) -> Self {
        let report = match inventory::detect(host, &SystemRunner::default(), config).await {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "cannot detect this machine; no lease will be taken until the agent restarts"
                );
                None
            }
        };
        let platform = report
            .as_ref()
            .map_or_else(|| crate::platform::detect(host), |r| r.inventory.platform);
        let volumes = match &config.server {
            Some(server) => open_volumes(config, server.account_id, Arc::new(SystemClock)).await,
            None => None,
        };
        Self {
            platform,
            report,
            shim: shim_path(),
            cgroups: host_cgroups(platform),
            volumes,
        }
    }
}

/// The executor and where each detection's offer goes.
#[derive(Debug)]
pub struct Node {
    /// The lease executor, on the production driver.
    pub executor: Executor<NodeDriver>,
    /// For [`crate::connection::DetectInventory`]: the offers, and the driver's limits the inventory reports.
    pub offers: OfferFeed,
    /// The ingress bridge (H2 §11.2), shared with the driver: the session opens service ports through it
    /// ([`crate::connection::session::Shared::ports`]).
    pub ingress: IngressBridge,
    /// The node's volumes, when the owner gave them a share of the disk: the session then declares the `volumes`
    /// capability and reports them ([`crate::connection::session::Shared::volumes`]). `None` otherwise; the driver
    /// has the store either way.
    pub volumes: Option<VolumeStore>,
}

/// Builds the driver and the executor from `facts`. `public_addrs` is the live source of the node's public addresses
/// (the connector's); the egress proxy refuses them. `egress_ready` is the egress gate (the connector's too): egress
/// jobs wait for it, and it can close again without the addresses being withdrawn.
#[must_use]
pub fn build(
    config: &Config,
    facts: NodeFacts,
    owner: AccountId,
    uplink: Uplink,
    public_addrs: watch::Receiver<Vec<IpAddr>>,
    egress_ready: watch::Receiver<p2pc_net::EgressGate>,
    clock: Arc<dyn Clock>,
) -> Node {
    let NodeFacts {
        platform,
        report,
        shim,
        cgroups,
        volumes,
    } = facts;
    let mut problems = Vec::new();
    match &report {
        None => problems.push("detection_failed: the machine could not be detected at agent start".to_string()),
        Some(r) if !r.inventory.sandbox.iter().any(|s| s.ready) => {
            problems.push("sandbox_not_ready: the sandbox was not ready at agent start".to_string());
        }
        Some(_) => {}
    }
    if !shim.is_file() {
        tracing::error!(
            path = %shim.display(),
            "the sandbox shim is missing; no lease will be taken (install p2pc-shim next to p2pc-agent)"
        );
        problems.push("shim_missing: install p2pc-shim next to p2pc-agent".to_string());
    }
    let cgroups = cgroups.unwrap_or_else(|e| {
        tracing::error!(error = %e, "no lease cgroups; no lease will be taken");
        problems.push(format!("lease_cgroups: {e}"));
        // Never used to run anything: the driver is built not ready.
        HostCgroups::Fs(FsCgroups::system())
    });
    let ready = problems.is_empty();
    if !ready {
        tracing::warn!(?problems, "the sandbox is not ready; the agent restarts it once fixed");
    }
    let gpus = report.as_ref().map(|r| r.local.share.gpus.clone()).unwrap_or_default();
    let mut cfg = DriverConfig::new(&config.data_dir, platform, shim, ready);
    cfg.runtime = config.runtime;
    cfg.offerable_gpus = gpus.clone();
    cfg.public_addrs = public_addrs;
    cfg.egress_ready = egress_ready;
    // One bridge for the three things that reach a service's ports: the driver attaches each service lease to it
    // and checks its health through it, and the session opens the hub's port streams through it (H2 §11.2).
    let ingress = IngressBridge::new();
    cfg.health_probe = Some(Arc::new(ingress.clone()));
    cfg.ingress = Some(ingress.clone());
    // Persistent volumes (H2 §11.3): the budget is the owner's `share.volumes_mb` as this detection resolved it
    // (nothing without a detection). The driver gets the store whatever the budget, so that what is on disk still
    // expires, is deleted, and stays locked while a container holds it.
    if let Some(store) = &volumes {
        store.set_budget_mb(report.as_ref().map_or(0, |r| r.local.share.volumes_mb));
    }
    cfg.volumes = volumes.clone();
    let driver = PodmanDriver::new(
        cfg,
        PodmanEngine::system("podman", PULL_TIMEOUT),
        cgroups,
        KnownPublicAddrs(ProxyEgress::system()),
    );
    let limits = DriverLimits { ready, gpus, problems };
    let first = report
        .as_ref()
        .map(|r| Offer::from_detection(&r.inventory, &r.local.share, &limits));
    let (tx, rx) = watch::channel(first);
    // A node that has no room for even the smallest volume never declares the capability: it could take no lease
    // that needs it (H2 §6.1).
    let volumes = volumes.filter(|store| ready && store.budget_mb() >= *VOLUME_MB_RANGE.start());
    Node {
        executor: Executor::new(driver, owner, uplink, rx, clock),
        offers: OfferFeed { tx, driver: limits },
        ingress,
        volumes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Env;
    use crate::executor::SystemClock;

    fn config(data: &Path) -> Config {
        Config::parse(
            &format!("data_dir = \"{}\"\n", data.display()),
            &Env {
                root: false,
                home: Some(data.to_path_buf()),
                config_env: None,
                ..Default::default()
            },
        )
        .unwrap()
    }

    /// P2-2: the production builder hands the driver the live source of public addresses, and gates egress on it.
    #[tokio::test]
    async fn the_driver_gets_a_live_source_of_public_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = watch::channel(Vec::new());
        let (ready_tx, ready_rx) = watch::channel(p2pc_net::EgressGate::Closed);
        let node = build(
            &config(dir.path()),
            NodeFacts {
                platform: Platform::Linux,
                report: None,
                shim: dir.path().join("no-shim"),
                cgroups: Err("no delegation".into()),
                volumes: None,
            },
            AccountId::generate(),
            Uplink::new(),
            rx,
            ready_rx,
            Arc::new(SystemClock),
        );
        let mut ready = node.executor.sandbox().config().egress_ready.clone();
        assert!(!ready.borrow_and_update().is_open(), "egress waits for the gate");
        ready_tx.send_replace(p2pc_net::EgressGate::Open);
        assert!(ready.has_changed().unwrap(), "live: the gate reaches the driver");
        let mut seen = node.executor.sandbox().config().public_addrs.clone();
        assert!(seen.borrow_and_update().is_empty());
        let public: IpAddr = "198.51.100.7".parse().unwrap();
        tx.send_replace(vec![public]);
        assert!(seen.has_changed().unwrap(), "live: a later address reaches the driver");
        assert_eq!(*seen.borrow(), [public]);
        // Built not ready, and the limits say why (the inventory reports it, P3-5).
        assert!(!node.executor.sandbox().config().ready);
        assert!(!node.offers.driver.ready);
        let problems = node.offers.driver.problems.join("\n");
        assert!(problems.contains("detection_failed"), "{problems}");
        assert!(problems.contains("shim_missing"), "{problems}");
        assert!(problems.contains("lease_cgroups: no delegation"), "{problems}");
    }

    /// P3-4: one agent per data dir; the lock goes with its holder.
    #[test]
    fn a_second_agent_cannot_take_the_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let first = lock_data_dir(dir.path()).unwrap();
        assert_eq!(first.path(), dir.path().join(LOCK_FILE));
        let second = lock_data_dir(dir.path()).unwrap_err();
        assert!(matches!(second, LockError::Held(_)), "{second}");
        assert!(second.to_string().contains("already running"), "{second}");
        drop(first);
        lock_data_dir(dir.path()).unwrap();
    }

    /// T10l review P3 2: `status` probes the lock with a shared `flock` for an instant. An agent that starts in that
    /// window gets `WOULDBLOCK` from its exclusive one: it waits a moment (the pause is injected, so the test needs no
    /// clock) instead of exiting with "another agent holds the lock".
    #[test]
    fn a_status_probe_in_flight_does_not_make_the_agent_fail_to_start() {
        let dir = tempfile::tempdir().unwrap();
        drop(lock_data_dir(dir.path()).unwrap());
        // The probe: a shared lock on its own descriptor, as `agent_running` takes it.
        let probe = rustix::fs::open(
            dir.path().join(LOCK_FILE),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        rustix::fs::flock(&probe, FlockOperation::NonBlockingLockShared).unwrap();
        let mut probe = Some(probe);
        let mut pauses = 0;
        let lock = lock_data_dir_with(dir.path(), LOCK_RETRIES, || {
            pauses += 1;
            drop(probe.take()); // the probe is over by the first pause
        })
        .expect("the agent starts once the probe is gone");
        assert_eq!(pauses, 1);
        assert!(agent_running(dir.path()));
        drop(lock);
    }

    /// An agent that really holds the lock is still reported, after the retries and not before.
    #[test]
    fn a_held_data_dir_is_reported_after_the_retries() {
        let dir = tempfile::tempdir().unwrap();
        let _first = lock_data_dir(dir.path()).unwrap();
        let mut pauses = 0;
        let err = lock_data_dir_with(dir.path(), LOCK_RETRIES, || pauses += 1).unwrap_err();
        assert!(matches!(err, LockError::Held(_)), "{err}");
        assert_eq!(pauses, LOCK_RETRIES);
    }

    /// T10i review P3 2: a refused data dir shows its message once in an error chain, not once as the error and again
    /// as its source.
    #[test]
    fn a_refused_data_dir_is_not_repeated_as_its_own_source() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foreign.txt"), b"x").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = lock_data_dir(dir.path()).unwrap_err();
        assert!(matches!(err, LockError::Dir(_)), "{err}");
        let top = err.to_string();
        let mut source = std::error::Error::source(&err);
        while let Some(inner) = source {
            assert_ne!(inner.to_string(), top, "the chain repeats {top:?}");
            source = inner.source();
        }
    }

    /// Review of PR #48, P3-3: `status` can tell a running agent from the file of a run that is over.
    #[test]
    fn an_agent_is_running_while_it_holds_the_data_dir_lock() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!agent_running(dir.path()), "no lock file: no agent has run here");
        let lock = lock_data_dir(dir.path()).unwrap();
        assert!(agent_running(dir.path()));
        drop(lock);
        assert!(
            !agent_running(dir.path()),
            "the lock file stays, the lock goes with its holder"
        );
        // Probing takes nothing: an agent can start right after.
        lock_data_dir(dir.path()).unwrap();
    }

    use std::os::unix::fs::PermissionsExt as _;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// A 0755 parent, as `/var/lib/p2pc` is on a fresh node (T10i).
    fn open_parent() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        tmp
    }

    /// T10i (ACC-1): the lock is the first thing to create the data dir, so it creates it 0700 (and the parents it
    /// has to make), and `identity` then goes on in it.
    #[test]
    fn a_missing_data_dir_is_created_0700_and_the_identity_goes_on() {
        let parent = open_parent();
        let data = parent.path().join(".local/share/p2pc-agent");
        // Under umask 022, as on a real node, whatever the test runner's umask is: a plain `create_dir_all` makes
        // these 0755 and the test fails on the code before T10i.
        let lock = crate::identity::with_umask(0o022, || lock_data_dir(&data)).unwrap();
        assert_eq!(mode(&data), 0o700);
        assert_eq!(mode(&parent.path().join(".local/share")), 0o700);
        assert_eq!(mode(&parent.path().join(".local")), 0o700);
        assert_eq!(mode(lock.path()), 0o600);
        crate::identity::Identity::load_or_create(&data).unwrap();
        assert!(data.join(crate::identity::IDENTITY_FILE).exists());
        assert!(data.join(LOCK_FILE).exists());
        assert_eq!(mode(&data), 0o700);
    }

    /// T10i: a 0755 data dir that holds only the agent's own files is tightened before the lock file is made in it.
    #[test]
    fn a_0755_data_dir_with_only_the_agents_files_is_tightened() {
        let parent = open_parent();
        let data = parent.path().join("data");
        drop(lock_data_dir(&data).unwrap());
        crate::identity::Identity::load_or_create(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
        let lock = lock_data_dir(&data).unwrap();
        assert_eq!(mode(&data), 0o700);
        drop(lock);
        crate::identity::Identity::load_or_create(&data).unwrap();
        assert_eq!(mode(&data), 0o700);
    }

    /// T10i: a 0755 data dir with a foreign file is refused as before, the message names that file (not
    /// `agent.lock`), and no lock file is made in it.
    #[test]
    fn a_0755_data_dir_with_a_foreign_file_is_refused() {
        let parent = open_parent();
        let data = parent.path().join("etc");
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(data.join("hosts"), b"192.0.2.1 example.invalid\n").unwrap();
        let err = lock_data_dir(&data).unwrap_err();
        let shown = err.to_string();
        assert!(shown.contains("\"hosts\""), "{shown}");
        assert!(!shown.contains("agent.lock"), "{shown}");
        assert_eq!(mode(&data), 0o755, "left as it was");
        assert!(
            !data.join(LOCK_FILE).exists(),
            "nothing was created in a refused directory"
        );
    }

    /// T10i review: `run` takes the same lock, so an enrolled node whose data dir became 0755 later (a manual
    /// `chmod`, a restore with the wrong modes) is tightened and goes on, though it holds the agent's own state, lease
    /// status, `jobs/` and the temporary files of their atomic writes. It must not call them foreign.
    #[test]
    fn an_enrolled_0755_data_dir_with_only_the_agents_files_is_tightened_by_run() {
        use crate::connection::state::STATE_FILE;
        use crate::executor::status::LEASES_FILE;
        use crate::identity::IDENTITY_FILE;
        use crate::sandbox::jobdir::JOBS_DIR;
        use crate::volumes::VOLUMES_DIR;

        let parent = open_parent();
        let data = parent.path().join("data");
        drop(lock_data_dir(&data).unwrap());
        crate::identity::Identity::load_or_create(&data).unwrap();
        std::fs::write(data.join(STATE_FILE), b"{}").unwrap();
        std::fs::write(data.join(LEASES_FILE), b"{}").unwrap();
        std::fs::create_dir(data.join(JOBS_DIR)).unwrap();
        std::fs::create_dir(data.join(VOLUMES_DIR)).unwrap();
        for own in [IDENTITY_FILE, STATE_FILE, LEASES_FILE] {
            std::fs::write(data.join(format!(".{own}.00000000deadbeef.tmp")), b"x").unwrap();
        }
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();

        let lock = lock_data_dir(&data).unwrap();
        assert_eq!(mode(&data), 0o700);
        drop(lock);

        // A foreign file next to them is still refused, and named; the dir stays as it was.
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
        for foreign in [
            "notes.txt",
            format!(".{STATE_FILE}.backup").as_str(),
            ".agent-other.json.0000.tmp",
        ] {
            std::fs::write(data.join(foreign), b"x").unwrap();
            let err = lock_data_dir(&data).unwrap_err().to_string();
            assert!(err.contains(&format!("{foreign:?}")), "{err}");
            assert_eq!(mode(&data), 0o755, "{foreign}");
            std::fs::remove_file(data.join(foreign)).unwrap();
        }
    }
}
