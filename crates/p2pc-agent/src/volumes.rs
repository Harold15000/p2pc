// SPDX-License-Identifier: Apache-2.0

//! Persistent volumes on the node (H2 spec §11.3, SI-H2-9, ADR-015).
//!
//! A volume is the one host path a sandbox may mount beyond its three per-job directories (CONTRIBUTING hard rule 3,
//! as amended by O-16), and this module keeps it inside that exception:
//!
//! - **Layout.** `<data_dir>/volumes/<account_id>/<hex(sha256(name))[..32]>/` with `data/` (what is mounted) and
//!   `meta.json` (name, created, last used, the holder). The agent creates every directory itself, 0700, with
//!   `mkdirat` under directory descriptors ([`fs`]). A volume's name only ever goes through SHA-256: no name and no
//!   path from the JobSpec becomes a host path.
//! - **Who may mount** ([`VolumeStore::reserve`]). Only a lease of the enrolled account whose job is a service or
//!   carries `template`; a `tpl:` name only for that template. Anything else is `invalid_job`.
//! - **One holder at a time.** A volume is held by at most one lease. The hold is taken in memory when the lease is
//!   admitted ([`VolumeStore::reserve`]: a second lease gets `insufficient_capacity`), written to `meta.json` with a
//!   temporary file, `fsync` and `rename` before `podman run` ([`VolumeStore::lock_and_check`]), and cleared only by
//!   [`VolumeStore::release`], which the sandbox driver calls once Podman confirmed that the lease's container is gone.
//!   A removal that fails keeps the hold ([`VolumeStore::orphan`]); the driver retries it at every sweep. A hold found
//!   in `meta.json` at start is held ([`VolumeStore::open`]) until the orphan sweep released it the same way.
//! - **The check before every mount** ([`VolumeStore::lock_and_check`]): the directory chain is recreated or verified,
//!   then the whole tree is walked without following links ([`fs::check_tree`]). A symbolic link, an entry that is
//!   neither a directory nor a regular file, a regular file with more than one hard link, or a tree over the entry
//!   budget refuses the mount (`volume_unsafe`). The volume is kept for the owner to delete, never repaired.
//! - **Size** ([`VolumeStore::usage`]): measured by the driver every 2 s with H1's fail-closed rules.
//! - **Budget** (`volumes_mb`). A lease needs `volumes_mb − Σ max_mb of the volumes other leases hold ≥ Σ max_mb of
//!   its own`. Unused volumes do not count: when a mount needs the room, unused volumes are evicted, least recently
//!   used first.
//! - **Retention and deletion.** An unused volume is deleted after `volume_retention_days`
//!   ([`VolumeStore::collect_garbage`]), on `VolumeDelete` ([`VolumeStore::delete`]) and, under the H1 disk floor,
//!   before a job is killed ([`VolumeStore::evict_for_floor`]); always with `unlinkat`, never following a link
//!   ([`fs::remove_volume`]).
//! - **Reports** ([`VolumeStore::report`], [`serve_session`]): `VolumeReport` after `Hello`, every 10 minutes, when a
//!   lease that held a volume ends, and in answer to `VolumeDelete`.
//!
//! Every method that touches the disk blocks: call it from the blocking pool.

pub mod fs;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use p2pc_proto::api::{JobKind, JobSpec};
use p2pc_proto::ids::{AccountId, LeaseId};
use p2pc_proto::protocol::{AgentMsg, LeaseRejectReason, MAX_VOLUMES_PER_REPORT, VolumeInfo, VolumeReport};
use p2pc_proto::validate::{VolumeName, validate_volume_mount};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch};

pub use self::fs::Unsafe;
use crate::executor::Clock;
use crate::sandbox::disk::{FreeSpace, TreeUsage};

/// The directory under the data dir that holds every volume.
pub const VOLUMES_DIR: &str = "volumes";
/// The directory of a volume that is mounted.
pub const DATA_DIR: &str = "data";
/// The file of a volume that records its name, its times and its holder.
pub const META_FILE: &str = "meta.json";
/// Default `volume_retention_days` (H2 §11.3).
pub const DEFAULT_RETENTION_DAYS: u32 = 30;
/// Most `volumes` of one job (H2 §7.1), checked again here.
pub const MAX_VOLUMES_PER_JOB: usize = 4;
/// Smallest and largest `volumes[].max_mb` (H2 §7.1), checked again here.
pub const VOLUME_MB_RANGE: std::ops::RangeInclusive<u64> = 64..=262_144;
/// How often the node retries the removal of containers that still hold a volume and collects expired volumes.
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);
/// `VolumeDelete`s waiting to be carried out in one session; more are dropped with a warning.
pub const MAX_PENDING_DELETES: usize = 16;
/// Most directories read per level when the volumes are loaded at start.
const MAX_SCAN: usize = 10_000;
const MIB: u64 = 1024 * 1024;

/// The directory name of the volume `name`: the first 32 hex digits of its SHA-256. The only way a volume's name
/// reaches the filesystem.
#[must_use]
pub fn dir_name(name: &str) -> String {
    use fmt::Write as _;
    let digest = Sha256::digest(name.as_bytes());
    let mut out = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Whether `dir` is a name [`dir_name`] makes.
fn is_dir_name(dir: &str) -> bool {
    dir.len() == 32 && dir.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Why a volume cannot be mounted.
#[derive(Debug, thiserror::Error)]
pub enum VolumeError {
    /// The tree holds something that may not be mounted, or cannot be vouched for (`volume_unsafe`).
    #[error("volume {name}: {why}")]
    Unsafe {
        /// The volume.
        name: String,
        /// What was found.
        why: Unsafe,
    },
    /// A directory of the chain is not what the agent made (`volume_unsafe`), or cannot be created or opened.
    #[error("volume {name}: {why}")]
    Chain {
        /// The volume.
        name: String,
        /// Which level, and why.
        why: fs::ChainError,
    },
    /// The lease holds no volume: it was not admitted with one.
    #[error("no volume is reserved for this lease")]
    NotReserved,
    /// The holder could not be written to `meta.json`, so nothing is mounted.
    #[error("volume {name}: cannot record the holder: {source}")]
    Lock {
        /// The volume.
        name: String,
        /// The error.
        source: io::Error,
    },
}

impl VolumeError {
    /// Whether the lease fails with `error="volume_unsafe"` (the volume itself is refused), as opposed to a setup
    /// failure of the node.
    #[must_use]
    pub fn is_unsafe(&self) -> bool {
        match self {
            Self::Unsafe { .. } => true,
            Self::Chain { why, .. } => why.is_unsafe(),
            Self::NotReserved | Self::Lock { .. } => false,
        }
    }
}

/// Why a volume was not deleted.
#[derive(Debug, thiserror::Error)]
pub enum DeleteError {
    /// Not a volume name (H2 §7.1).
    #[error("not a volume name")]
    InvalidName,
    /// The node has no volume of that name.
    #[error("no such volume")]
    NotFound,
    /// A lease holds it (or may hold it: its state is not known yet).
    #[error("the volume is in use")]
    InUse(Option<LeaseId>),
    /// The deletion failed half-way; it is finished at the next collection.
    #[error("cannot delete the volume: {0}")]
    Io(#[from] io::Error),
}

/// One volume to mount: what the `-v` argument is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// The volume's name (for messages; it never reaches the argv).
    pub name: String,
    /// The agent's own `<data_dir>/volumes/<account_id>/<hash>/data`.
    pub host: PathBuf,
    /// Where it is mounted in the container (validated: under `/volumes/`).
    pub mount: String,
    /// `max_mb`, in bytes.
    pub max_bytes: u64,
}

/// One measurement of a mounted volume.
#[derive(Debug)]
pub struct VolumeUsage {
    /// The volume.
    pub name: String,
    /// `max_mb`, in bytes.
    pub max_bytes: u64,
    /// What it holds now; an error is a failed measurement (fail closed).
    pub used: io::Result<TreeUsage>,
}

/// How far a hold has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HoldState {
    /// In memory only: nothing is written and no container can exist for it yet.
    Reserved,
    /// Written to `meta.json`; the lease's run is in progress in this process.
    Locked,
    /// Written to `meta.json`, with no run in this process: the lease ended while its container could not be
    /// removed, or the hold was found at start. The sweep retries.
    Orphaned,
}

#[derive(Debug, Clone)]
struct Hold {
    lease_id: LeaseId,
    epoch: u64,
    /// The container that mounts it, `p2pc-<lease_id>`.
    container: String,
    /// The volume's name, as the lease gave it.
    name: String,
    /// Where it is mounted in the container (empty for a hold found at start).
    mount: String,
    max_mb: u64,
    /// Its position in the job's `volumes`.
    index: usize,
    state: HoldState,
}

impl Hold {
    fn is(&self, lease_id: &LeaseId, epoch: u64) -> bool {
        self.lease_id == *lease_id && self.epoch == epoch
    }
}

#[derive(Debug, Clone)]
struct Entry {
    /// The volume's name; `None` when `meta.json` is missing or damaged.
    name: Option<String>,
    created_at: OffsetDateTime,
    last_used_at: OffsetDateTime,
    /// The `max_mb` of its last mount.
    max_mb: u64,
    /// Its last measured size, in bytes.
    size: Option<u64>,
    hold: Option<Hold>,
    /// A deletion is running.
    busy: bool,
    /// A deletion began and did not finish: it is never mounted again, and the next collection finishes it.
    doomed: bool,
    /// Its directory exists (false between a reservation of a new volume and its first lock).
    on_disk: bool,
}

/// A volume's place on disk: the account's directory and the volume's.
type Key = (String, String);

#[derive(Debug, Default)]
struct State {
    volumes: BTreeMap<Key, Entry>,
}

/// `meta.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Meta {
    name: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    last_used_at: OffsetDateTime,
    #[serde(default)]
    max_mb: u64,
    /// The lock (H2 §11.3 "It survives agent restarts").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    holder: Option<HolderRecord>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    deleting: bool,
}

/// The holder as `meta.json` records it: the lease and its container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HolderRecord {
    lease_id: LeaseId,
    #[serde(default)]
    epoch: u64,
    container: String,
    #[serde(default)]
    max_mb: u64,
}

/// What a [`VolumeStore`] is opened with.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// The agent's data dir; the volumes go in `<data_dir>/volumes/`.
    pub data_dir: PathBuf,
    /// The enrolled account: the only one whose leases mount anything (SI-1, SI-H2-9).
    pub owner: AccountId,
    /// `volumes_mb`: the disk share for volumes (H2 §8.2).
    pub budget_mb: u64,
    /// `volume_retention_days`.
    pub retention_days: u32,
    /// The entry budget of the check and of the measurement (H1's, of the disk measurement).
    pub entry_budget: usize,
    /// The wall clock, for `last_used_at` and the retention.
    pub clock: Arc<dyn Clock>,
}

struct Inner {
    data_dir: PathBuf,
    owner: String,
    retention: time::Duration,
    entry_budget: usize,
    clock: Arc<dyn Clock>,
    budget_mb: AtomicU64,
    /// The orphan sweep of this start listed the node's containers and none of an earlier process is left.
    swept: AtomicBool,
    state: Mutex<State>,
    /// One eviction for the disk floor at a time: the jobs that measure the disk at the same moment wait for the
    /// eviction under way and look at the disk again, instead of finding nothing left to evict.
    floor: Mutex<()>,
    /// Counts the changes a `VolumeReport` should follow.
    changes: watch::Sender<u64>,
}

/// The node's volumes. Clones share it.
#[derive(Clone)]
pub struct VolumeStore {
    inner: Arc<Inner>,
}

impl fmt::Debug for VolumeStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VolumeStore")
            .field("data_dir", &self.inner.data_dir)
            .field("budget_mb", &self.budget_mb())
            .field("volumes", &self.state().volumes.len())
            .finish_non_exhaustive()
    }
}

impl VolumeStore {
    /// Opens the node's volumes: creates `<data_dir>/volumes` (0700) if it is missing and loads what is there.
    /// Every holder recorded in a `meta.json` is held from now on (H2 §11.3): only [`VolumeStore::release`] frees
    /// it, once Podman confirmed its container gone.
    ///
    /// # Errors
    /// When `volumes/` cannot be created or is not the agent's own directory.
    pub fn open(cfg: StoreConfig) -> Result<Self, fs::ChainError> {
        let root = fs::open_root(&cfg.data_dir, true)?;
        let now = cfg.clock.now();
        let mut volumes = BTreeMap::new();
        let list = |dir: &std::os::fd::OwnedFd, what: &'static str| {
            fs::subdirs(dir.as_fd(), MAX_SCAN).map_err(|source| fs::ChainError::Io { what, source })
        };
        for account in list(&root, "volumes/")? {
            // Only directories this agent could have made; anything else is not touched.
            if AccountId::from_str(&account).is_err() {
                tracing::warn!(entry = ?account, "an entry of volumes/ that is not an account's; left alone");
                continue;
            }
            let dir = match fs::enter(root.as_fd(), &account, "the account's volume directory", false, true) {
                Ok(dir) => dir,
                Err(e) => {
                    tracing::warn!(account = %account, error = %e, "cannot read an account's volumes; left alone");
                    continue;
                }
            };
            for volume in list(&dir, "the account's volume directory")? {
                if !is_dir_name(&volume) {
                    tracing::warn!(account = %account, entry = ?volume, "not a volume directory; left alone");
                    continue;
                }
                let entry = load(&dir, &volume, now);
                if let Some(hold) = &entry.hold {
                    tracing::info!(
                        volume = ?entry.name,
                        lease_id = %hold.lease_id,
                        container = %hold.container,
                        "a volume was held when the agent stopped; it stays held until its container is confirmed gone"
                    );
                }
                volumes.insert((account.clone(), volume), entry);
            }
        }
        Ok(Self {
            inner: Arc::new(Inner {
                data_dir: cfg.data_dir,
                owner: cfg.owner.to_string(),
                retention: time::Duration::days(i64::from(cfg.retention_days)),
                entry_budget: cfg.entry_budget,
                clock: cfg.clock,
                budget_mb: AtomicU64::new(cfg.budget_mb),
                swept: AtomicBool::new(false),
                state: Mutex::new(State { volumes }),
                floor: Mutex::new(()),
                changes: watch::channel(0).0,
            }),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn changed(&self) {
        self.inner.changes.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Resolves each time the volumes change in a way the hub should hear of (a holder came or went, a volume was
    /// deleted).
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.inner.changes.subscribe()
    }

    /// `volumes_mb`.
    #[must_use]
    pub fn budget_mb(&self) -> u64 {
        self.inner.budget_mb.load(Ordering::Relaxed)
    }

    /// Changes `volumes_mb`. Leases already admitted keep their volumes.
    pub fn set_budget_mb(&self, budget_mb: u64) {
        self.inner.budget_mb.store(budget_mb, Ordering::Relaxed);
    }

    /// The orphan sweep of this start has finished: it listed the node's containers and none of an earlier process
    /// is left. Until then a volume whose `meta.json` cannot be read may still be mounted by one of them, so it is
    /// neither reused nor deleted.
    pub fn sweep_finished(&self) {
        self.inner.swept.store(true, Ordering::Relaxed);
    }

    fn swept(&self) -> bool {
        self.inner.swept.load(Ordering::Relaxed)
    }

    fn key(&self, name: &str) -> Key {
        (self.inner.owner.clone(), dir_name(name))
    }

    /// Takes the volumes of a lease, in memory, at admission (H2 §11.3 "Who may mount", "One holder at a time",
    /// "Budget"). It never touches the disk and never waits. Taking them again for the same lease and epoch changes
    /// nothing.
    ///
    /// # Errors
    /// - `not_owner`: the lease is not the enrolled account's.
    /// - `invalid_job`: the job is neither a service nor a template job, or a name, a mount or a size breaks the
    ///   rules of H2 §7.1 (checked again here, whatever the hub validated).
    /// - `insufficient_capacity`: another lease holds one of the volumes, one is being deleted, or they do not fit
    ///   in `volumes_mb` next to the volumes other leases hold. The reason is logged.
    pub fn reserve(
        &self,
        lease_id: LeaseId,
        epoch: u64,
        account: &AccountId,
        job: &JobSpec,
    ) -> Result<(), LeaseRejectReason> {
        use LeaseRejectReason as R;
        if job.volumes.is_empty() {
            return Ok(());
        }
        if account.to_string() != self.inner.owner {
            return Err(R::NotOwner);
        }
        if job.kind != JobKind::Service && job.template.is_none() {
            tracing::warn!(%lease_id, "volumes on a job that is neither a service nor a template job (invalid_job)");
            return Err(R::InvalidJob);
        }
        if job.volumes.len() > MAX_VOLUMES_PER_JOB {
            return Err(R::InvalidJob);
        }
        let mut wanted: Vec<(Key, Hold)> = Vec::with_capacity(job.volumes.len());
        for (index, volume) in job.volumes.iter().enumerate() {
            let allowed = match VolumeName::parse(&volume.name) {
                Ok(VolumeName::Plain(_)) => true,
                // SI-H2-9: a template's volume only for a job of that template.
                Ok(VolumeName::Template { template_id, .. }) => {
                    job.template.as_ref().is_some_and(|t| t.id == template_id)
                }
                Err(_) => false,
            };
            // `:` and `,` are the separators of Podman's `-v`: a mount with one could add an option or a path.
            let mount_ok = validate_volume_mount(&volume.mount).is_ok() && !volume.mount.contains([':', ',']);
            let key = self.key(&volume.name);
            if !allowed
                || !mount_ok
                || !VOLUME_MB_RANGE.contains(&volume.max_mb)
                || wanted.iter().any(|(k, _)| *k == key)
            {
                tracing::warn!(%lease_id, index, "a volume of the job breaks the volume rules (invalid_job)");
                return Err(R::InvalidJob);
            }
            wanted.push((
                key,
                Hold {
                    lease_id,
                    epoch,
                    container: crate::sandbox::argv::container_name(&lease_id),
                    name: volume.name.clone(),
                    mount: volume.mount.clone(),
                    max_mb: volume.max_mb,
                    index,
                    state: HoldState::Reserved,
                },
            ));
        }
        let now = self.inner.clock.now();
        let mut state = self.state();
        // Already this lease's: nothing to take, and nothing to count twice.
        if wanted.iter().all(|(key, _)| {
            state
                .volumes
                .get(key)
                .and_then(|e| e.hold.as_ref())
                .is_some_and(|h| h.is(&lease_id, epoch))
        }) {
            return Ok(());
        }
        for (key, hold) in &wanted {
            let Some(entry) = state.volumes.get(key) else { continue };
            if let Some(held) = entry.hold.as_ref().filter(|h| !h.is(&lease_id, epoch)) {
                tracing::info!(
                    %lease_id,
                    volume = %hold.name,
                    held_by = %held.lease_id,
                    "the volume is held by another lease (insufficient_capacity)"
                );
                return Err(R::InsufficientCapacity);
            }
            if entry.busy || entry.doomed {
                tracing::info!(%lease_id, volume = %hold.name, "the volume is being deleted (insufficient_capacity)");
                return Err(R::InsufficientCapacity);
            }
            if entry.name.is_none() && !self.swept() {
                tracing::info!(
                    %lease_id,
                    volume = %hold.name,
                    "the volume's meta.json cannot be read and the orphan sweep has not finished: it may still be \
                     mounted (insufficient_capacity)"
                );
                return Err(R::InsufficientCapacity);
            }
        }
        let others: u64 = state
            .volumes
            .values()
            .filter_map(|e| e.hold.as_ref())
            .filter(|h| !h.is(&lease_id, epoch))
            .fold(0, |sum, h| sum.saturating_add(h.max_mb));
        let own: u64 = wanted.iter().fold(0, |sum, (_, h)| sum.saturating_add(h.max_mb));
        let budget = self.budget_mb();
        if others.saturating_add(own) > budget {
            tracing::info!(
                %lease_id,
                volumes_mb = budget,
                held_by_others_mb = others,
                wanted_mb = own,
                "the lease's volumes do not fit in volumes_mb (insufficient_capacity)"
            );
            return Err(R::InsufficientCapacity);
        }
        for (key, hold) in wanted {
            let entry = state.volumes.entry(key).or_insert_with(|| Entry {
                name: Some(hold.name.clone()),
                created_at: now,
                last_used_at: now,
                max_mb: hold.max_mb,
                size: None,
                hold: None,
                busy: false,
                doomed: false,
                on_disk: false,
            });
            entry.hold = Some(hold);
        }
        Ok(())
    }

    /// Gives back what [`VolumeStore::reserve`] took for a lease that will not run, as long as nothing was written
    /// for it: a hold that reached `meta.json` is only ever cleared by [`VolumeStore::release`].
    pub fn cancel_reservation(&self, lease_id: &LeaseId, epoch: u64) {
        let mut state = self.state();
        state.volumes.retain(|_, entry| {
            let reserved = entry
                .hold
                .as_ref()
                .is_some_and(|h| h.is(lease_id, epoch) && h.state == HoldState::Reserved);
            if reserved {
                entry.hold = None;
            }
            !reserved || entry.on_disk
        });
    }

    /// Locks the lease's volumes on disk and checks them, right before `podman run` (H2 §11.3):
    ///
    /// 1. unused volumes are evicted, least recently used first, while the volumes in use and the unused ones do
    ///    not fit in `volumes_mb` together;
    /// 2. for each volume, the chain `volumes/<account_id>/<hash>/data` is recreated with `mkdirat` if it is
    ///    missing, and verified otherwise;
    /// 3. the holder goes into `meta.json` (temporary file, `fsync`, `rename`);
    /// 4. the whole tree is walked without following links. Nothing else can change it meanwhile: the lock is this
    ///    lease's, and no container of an earlier holder exists.
    ///
    /// The returned mounts are in the order of the job's `volumes`. Blocking.
    ///
    /// # Errors
    /// [`VolumeError`]; nothing may be mounted then. The holds stay with the lease until
    /// [`VolumeStore::release`].
    pub fn lock_and_check(&self, lease_id: &LeaseId, epoch: u64) -> Result<Vec<Mount>, VolumeError> {
        let mut held: Vec<(Key, Hold, OffsetDateTime)> = self
            .state()
            .volumes
            .iter()
            .filter_map(|(key, entry)| {
                let hold = entry.hold.as_ref().filter(|h| h.is(lease_id, epoch))?;
                // A volume whose meta.json was unreadable starts over: its times are not known.
                let created_at = entry
                    .name
                    .as_ref()
                    .map_or_else(|| self.inner.clock.now(), |_| entry.created_at);
                Some((key.clone(), hold.clone(), created_at))
            })
            .collect();
        if held.is_empty() {
            return Err(VolumeError::NotReserved);
        }
        held.sort_by_key(|(_, hold, _)| hold.index);
        self.make_room();
        let chain_error = |name: &str, why| VolumeError::Chain {
            name: name.to_string(),
            why,
        };
        let root = fs::open_root(&self.inner.data_dir, true).map_err(|why| chain_error(&held[0].1.name, why))?;
        let mut mounts = Vec::with_capacity(held.len());
        for (key, hold, created_at) in held {
            let name = hold.name.clone();
            let chain = fs::open_chain(root.as_fd(), &key.0, &key.1, true).map_err(|why| chain_error(&name, why))?;
            let now = self.inner.clock.now();
            // The lock first: from here on the volume is this lease's on disk too, before anything looks at the tree
            // and long before `podman run`.
            let meta = Meta {
                name: name.clone(),
                created_at,
                last_used_at: now,
                max_mb: hold.max_mb,
                holder: Some(HolderRecord {
                    lease_id: hold.lease_id,
                    epoch: hold.epoch,
                    container: hold.container.clone(),
                    max_mb: hold.max_mb,
                }),
                deleting: false,
            };
            write_meta(&chain, &meta).map_err(|source| VolumeError::Lock {
                name: name.clone(),
                source,
            })?;
            if let Some(entry) = self.state().volumes.get_mut(&key) {
                entry.name = Some(name.clone());
                entry.created_at = created_at;
                entry.last_used_at = now;
                entry.max_mb = hold.max_mb;
                entry.on_disk = true;
                if let Some(h) = entry.hold.as_mut().filter(|h| h.is(lease_id, epoch)) {
                    h.state = HoldState::Locked;
                }
            }
            self.changed();
            let tree =
                fs::check_tree(chain.data.as_fd(), self.inner.entry_budget).map_err(|why| VolumeError::Unsafe {
                    name: name.clone(),
                    why,
                })?;
            if let Some(entry) = self.state().volumes.get_mut(&key) {
                entry.size = Some(tree.bytes);
            }
            mounts.push(Mount {
                name,
                host: self
                    .inner
                    .data_dir
                    .join(VOLUMES_DIR)
                    .join(&key.0)
                    .join(&key.1)
                    .join(DATA_DIR),
                mount: hold.mount,
                max_bytes: hold.max_mb.saturating_mul(MIB),
            });
        }
        Ok(mounts)
    }

    /// Measures the volumes the lease has locked, as H1 measures job disk. Blocking.
    #[must_use]
    pub fn usage(&self, lease_id: &LeaseId, epoch: u64) -> Vec<VolumeUsage> {
        let held: Vec<(Key, Hold)> = self
            .state()
            .volumes
            .iter()
            .filter_map(|(key, entry)| {
                let hold = entry
                    .hold
                    .as_ref()
                    .filter(|h| h.is(lease_id, epoch) && h.state == HoldState::Locked)?;
                Some((key.clone(), hold.clone()))
            })
            .collect();
        held.into_iter()
            .map(|(key, hold)| VolumeUsage {
                name: hold.name,
                max_bytes: hold.max_mb.saturating_mul(MIB),
                used: self.measure(&key),
            })
            .collect()
    }

    /// Measures one volume and remembers its size.
    fn measure(&self, key: &Key) -> io::Result<TreeUsage> {
        let root = fs::open_root(&self.inner.data_dir, false)?;
        let chain = fs::open_chain(root.as_fd(), &key.0, &key.1, false)?;
        let used = fs::tree_usage(chain.data.as_fd(), self.inner.entry_budget)?;
        if let (TreeUsage::Bytes(bytes), Some(entry)) = (used, self.state().volumes.get_mut(key)) {
            entry.size = Some(bytes);
        }
        Ok(used)
    }

    /// Writes `meta.json` from what the store knows of the volume.
    fn persist(&self, key: &Key) -> io::Result<()> {
        let Some(entry) = self.state().volumes.get(key).cloned() else {
            return Ok(());
        };
        let Some(name) = entry.name else { return Ok(()) };
        let root = fs::open_root(&self.inner.data_dir, false)?;
        let chain = fs::open_chain(root.as_fd(), &key.0, &key.1, false)?;
        let holder = entry
            .hold
            .filter(|h| h.state != HoldState::Reserved)
            .map(|h| HolderRecord {
                lease_id: h.lease_id,
                epoch: h.epoch,
                container: h.container,
                max_mb: h.max_mb,
            });
        let meta = Meta {
            name,
            created_at: entry.created_at,
            last_used_at: entry.last_used_at,
            max_mb: entry.max_mb,
            holder,
            deleting: entry.doomed,
        };
        write_meta(&chain, &meta)
    }

    /// Frees every volume the lease holds: call it **only** once Podman confirmed that the lease's container is gone
    /// (`podman rm` succeeded, or `podman container exists` reports it absent; H2 §11.3). Clears the holder in
    /// `meta.json` and stamps `last_used_at`. Returns whether the lease held anything. Blocking.
    pub fn release(&self, lease_id: &LeaseId) -> bool {
        let held: Vec<(Key, HoldState)> = self
            .state()
            .volumes
            .iter()
            .filter_map(|(key, entry)| {
                let hold = entry.hold.as_ref().filter(|h| h.lease_id == *lease_id)?;
                Some((key.clone(), hold.state))
            })
            .collect();
        if held.is_empty() {
            return false;
        }
        let now = self.inner.clock.now();
        for (key, hold_state) in held {
            let written = hold_state != HoldState::Reserved;
            if written {
                // Its size as the lease left it, for the reports and the eviction.
                let _ = self.measure(&key);
            }
            {
                let mut state = self.state();
                let mut never_made = false;
                if let Some(entry) = state.volumes.get_mut(&key) {
                    entry.hold = None;
                    if written {
                        entry.last_used_at = now;
                    }
                    never_made = !entry.on_disk;
                }
                if never_made {
                    state.volumes.remove(&key);
                }
            }
            if written && let Err(e) = self.persist(&key) {
                // Free in memory, still held on disk: the next start treats it as held and its sweep frees it.
                tracing::warn!(%lease_id, error = %e, "cannot clear a volume's holder in meta.json");
            }
        }
        self.changed();
        true
    }

    /// The lease's run is over but its container could not be confirmed gone: the lock stays, the volume is
    /// reported `in_use_by` the lease, and the sweep retries the removal ([`VolumeStore::orphaned`]). A hold that
    /// was never written (no container was created for it) is simply given back.
    pub fn orphan(&self, lease_id: &LeaseId) {
        {
            let mut state = self.state();
            state.volumes.retain(|_, entry| {
                let Some(hold) = entry.hold.as_mut().filter(|h| h.lease_id == *lease_id) else {
                    return true;
                };
                if hold.state == HoldState::Reserved {
                    entry.hold = None;
                    return entry.on_disk;
                }
                hold.state = HoldState::Orphaned;
                true
            });
        }
        self.changed();
    }

    /// The leases that hold a volume without a run in this process, each once: their containers are what the sweep
    /// removes (by the name the agent derives from the lease, never by a string from `meta.json`).
    #[must_use]
    pub fn orphaned(&self) -> Vec<LeaseId> {
        let mut leases: Vec<LeaseId> = self
            .state()
            .volumes
            .values()
            .filter_map(|e| e.hold.as_ref())
            .filter(|h| h.state == HoldState::Orphaned)
            .map(|h| h.lease_id)
            .collect();
        leases.sort();
        leases.dedup();
        leases
    }

    /// The unused volumes that may be deleted, least recently used first.
    fn unused(&self) -> Vec<(Key, Entry)> {
        let swept = self.swept();
        let mut unused: Vec<(Key, Entry)> = self
            .state()
            .volumes
            .iter()
            .filter(|(_, e)| e.hold.is_none() && !e.busy && e.on_disk && (e.name.is_some() || swept))
            .map(|(key, e)| (key.clone(), e.clone()))
            .collect();
        unused.sort_by_key(|(_, e)| e.last_used_at);
        unused
    }

    /// Evicts unused volumes, least recently used first, until the volumes in use (at their `max_mb`) and the unused
    /// ones (at their size) fit in `volumes_mb` together.
    fn make_room(&self) {
        loop {
            let in_use: u64 = self
                .state()
                .volumes
                .values()
                .filter_map(|e| e.hold.as_ref())
                .fold(0, |sum, h| sum.saturating_add(h.max_mb));
            let unused = self.unused();
            let mut bytes = in_use.saturating_mul(MIB);
            for (key, entry) in &unused {
                let size = match entry.size {
                    Some(size) => size,
                    // Unknown: measure it; if that fails, it counts as full.
                    None => match self.measure(key) {
                        Ok(TreeUsage::Bytes(size)) => size,
                        _ => entry.max_mb.saturating_mul(MIB),
                    },
                };
                bytes = bytes.saturating_add(size);
            }
            if bytes <= self.budget_mb().saturating_mul(MIB) {
                return;
            }
            let Some((key, entry)) = unused.into_iter().next() else {
                return;
            };
            tracing::info!(volume = ?entry.name, last_used_at = %entry.last_used_at, "evicting an unused volume to make room");
            if let Err(e) = self.remove(&key) {
                tracing::warn!(volume = ?entry.name, error = %e, "cannot evict an unused volume");
                return;
            }
        }
    }

    /// Deletes the unused volume at `key`, without following a link.
    fn remove(&self, key: &Key) -> io::Result<()> {
        {
            let mut state = self.state();
            let Some(entry) = state.volumes.get_mut(key) else {
                return Ok(());
            };
            if entry.hold.is_some() || entry.busy {
                return Err(io::Error::other("the volume is in use"));
            }
            entry.busy = true;
            entry.doomed = true;
        }
        // Marked on disk first, as far as it can be: a deletion that is interrupted is finished later, and the volume
        // is never mounted half-deleted.
        if let Err(e) = self.persist(key) {
            tracing::debug!(error = %e, "cannot mark a volume as being deleted; deleting it anyway");
        }
        let result = self.remove_on_disk(key);
        {
            let mut state = self.state();
            match &result {
                Ok(()) => {
                    state.volumes.remove(key);
                }
                Err(_) => {
                    if let Some(entry) = state.volumes.get_mut(key) {
                        entry.busy = false;
                    }
                }
            }
        }
        self.changed();
        result
    }

    fn remove_on_disk(&self, key: &Key) -> io::Result<()> {
        let root = match fs::open_root(&self.inner.data_dir, false) {
            Ok(root) => root,
            Err(fs::ChainError::Missing { .. }) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let account = match fs::enter(root.as_fd(), &key.0, "the account's volume directory", false, true) {
            Ok(account) => account,
            Err(fs::ChainError::Missing { .. }) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        fs::remove_volume(account.as_fd(), &key.1)
    }

    /// `VolumeDelete{name}` (H2 §6.1): deletes a volume of the enrolled account that no lease uses, without
    /// following a link. Blocking.
    ///
    /// # Errors
    /// [`DeleteError`]; a volume that a lease holds is never deleted.
    pub fn delete(&self, name: &str) -> Result<(), DeleteError> {
        if VolumeName::parse(name).is_err() {
            return Err(DeleteError::InvalidName);
        }
        let key = self.key(name);
        {
            let state = self.state();
            let entry = state.volumes.get(&key).ok_or(DeleteError::NotFound)?;
            if let Some(hold) = &entry.hold {
                return Err(DeleteError::InUse(Some(hold.lease_id)));
            }
            if entry.busy || (entry.name.is_none() && !self.swept()) {
                return Err(DeleteError::InUse(None));
            }
        }
        Ok(self.remove(&key)?)
    }

    /// Deletes the unused volumes that were last used more than `volume_retention_days` ago, and finishes the
    /// deletions that did not finish. Returns how many volumes went. Blocking.
    pub fn collect_garbage(&self) -> usize {
        let now = self.inner.clock.now();
        let mut removed = 0;
        for (key, entry) in self.unused() {
            if !entry.doomed && now - entry.last_used_at < self.inner.retention {
                continue;
            }
            match self.remove(&key) {
                Ok(()) => {
                    tracing::info!(volume = ?entry.name, last_used_at = %entry.last_used_at, "deleted an unused volume");
                    removed += 1;
                }
                Err(e) => tracing::warn!(volume = ?entry.name, error = %e, "cannot delete an unused volume"),
            }
        }
        removed
    }

    /// H1's disk floor: evicts unused volumes, least recently used first, while the data disk is below it, so that
    /// no job is killed for space an unused volume holds (H2 §11.3 "Retention"). Returns whether the disk is above
    /// the floor now; an unreadable disk is not (fail closed). Blocking.
    pub fn evict_for_floor(&self, free_space: &dyn FreeSpace) -> bool {
        let _one_at_a_time = self.inner.floor.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            match free_space.space(&self.inner.data_dir) {
                Ok(space) if !space.below_floor() => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
            let Some((key, entry)) = self.unused().into_iter().next() else {
                return false;
            };
            tracing::warn!(volume = ?entry.name, "the data disk is below its floor: evicting an unused volume");
            if self.remove(&key).is_err() {
                return false;
            }
        }
    }

    /// The enrolled account's volumes, as `VolumeReport` lists them. Measures the unused ones whose size is not
    /// known. Blocking.
    #[must_use]
    pub fn report_now(&self) -> VolumeReport {
        let listed: Vec<(Key, Entry)> = self
            .state()
            .volumes
            .iter()
            .filter(|(key, e)| key.0 == self.inner.owner && e.on_disk && !e.busy && e.name.is_some())
            .map(|(key, e)| (key.clone(), e.clone()))
            .collect();
        let mut volumes: Vec<VolumeInfo> = listed
            .into_iter()
            .filter_map(|(key, entry)| {
                let bytes = match entry.size {
                    Some(bytes) => bytes,
                    None => match self.measure(&key) {
                        Ok(TreeUsage::Bytes(bytes)) => bytes,
                        // Over the entry budget or unreadable: reported as full, never as empty.
                        _ => entry.max_mb.saturating_mul(MIB),
                    },
                };
                Some(VolumeInfo {
                    name: entry.name?,
                    size_mb: bytes.div_ceil(MIB),
                    last_used_at: entry.last_used_at,
                    in_use_by: entry.hold.map(|h| h.lease_id),
                })
            })
            .collect();
        if volumes.len() > MAX_VOLUMES_PER_REPORT {
            tracing::warn!(
                volumes = volumes.len(),
                reported = MAX_VOLUMES_PER_REPORT,
                "more volumes than one VolumeReport holds; the least recently used unused ones are left out"
            );
            volumes.sort_by_key(|v| (v.in_use_by.is_none(), std::cmp::Reverse(v.last_used_at)));
            volumes.truncate(MAX_VOLUMES_PER_REPORT);
        }
        volumes.sort_by(|a, b| a.name.cmp(&b.name));
        VolumeReport { volumes }
    }

    /// [`VolumeStore::report_now`], on the blocking pool.
    pub async fn report(&self) -> VolumeReport {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.report_now())
            .await
            .unwrap_or_else(|_| VolumeReport { volumes: Vec::new() })
    }
}

fn write_meta(chain: &fs::Chain, meta: &Meta) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(meta).map_err(io::Error::other)?;
    fs::write_meta(chain.volume.as_fd(), &bytes)
}

/// Loads the volume directory `dir` of an account. A volume whose `meta.json` is missing, unreadable or not this
/// directory's is kept without a name: it is never mounted as it is.
fn load(account: &std::os::fd::OwnedFd, dir: &str, now: OffsetDateTime) -> Entry {
    let damaged = |at: Option<OffsetDateTime>| Entry {
        name: None,
        created_at: at.unwrap_or(now),
        last_used_at: at.unwrap_or(now),
        max_mb: 0,
        size: None,
        hold: None,
        busy: false,
        doomed: false,
        on_disk: true,
    };
    let Ok(volume) = fs::enter(account.as_fd(), dir, "the volume directory", false, true) else {
        return damaged(None);
    };
    let meta = fs::read_meta(volume.as_fd())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Meta>(&bytes).ok())
        .filter(|meta| VolumeName::parse(&meta.name).is_ok() && dir_name(&meta.name) == dir);
    let Some(meta) = meta else {
        tracing::warn!(
            dir,
            "a volume whose meta.json cannot be read; it is not mounted as it is"
        );
        return damaged(fs::modified(volume.as_fd()));
    };
    Entry {
        hold: meta.holder.map(|h| Hold {
            lease_id: h.lease_id,
            epoch: h.epoch,
            container: h.container,
            name: meta.name.clone(),
            mount: String::new(),
            max_mb: if h.max_mb == 0 { meta.max_mb } else { h.max_mb },
            index: 0,
            state: HoldState::Orphaned,
        }),
        name: Some(meta.name),
        created_at: meta.created_at,
        last_used_at: meta.last_used_at,
        max_mb: meta.max_mb,
        size: None,
        busy: false,
        doomed: meta.deleting,
        on_disk: true,
    }
}

/// One session's volume traffic (H2 §6.1): a `VolumeReport` at once (the session is welcomed, so it follows `Hello`),
/// then one every `every`, one each time the volumes change (a lease that held one ended), and one in answer to each
/// `VolumeDelete`, whose names arrive on `deletes`. Ends with the session: when `outbox` or `deletes` closes.
pub async fn serve_session(
    store: VolumeStore,
    outbox: mpsc::Sender<AgentMsg>,
    mut deletes: mpsc::Receiver<String>,
    every: Duration,
) {
    let mut changes = store.subscribe();
    loop {
        // Seen before the report is built: a change during the build gets a report of its own.
        let _seen = *changes.borrow_and_update();
        let report = store.report().await;
        match report.validate() {
            Ok(()) => {
                if outbox.send(AgentMsg::VolumeReport(report)).await.is_err() {
                    return;
                }
            }
            Err(e) => tracing::warn!(error = %e, "the volume report is not valid; not sent"),
        }
        tokio::select! {
            () = tokio::time::sleep(every) => {}
            changed = changes.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            name = deletes.recv() => {
                let Some(name) = name else { return };
                delete_for_session(&store, name).await;
                while let Ok(name) = deletes.try_recv() {
                    delete_for_session(&store, name).await;
                }
            }
        }
    }
}

/// Carries out one `VolumeDelete` on the blocking pool and logs how it went. The name is logged escaped: it comes
/// from the network.
async fn delete_for_session(store: &VolumeStore, name: String) {
    let (store, shown) = (store.clone(), name.clone());
    let result = tokio::task::spawn_blocking(move || store.delete(&name)).await;
    match result {
        Ok(Ok(())) => tracing::info!(volume = ?shown, "volume deleted (VolumeDelete)"),
        Ok(Err(e)) => tracing::warn!(volume = ?shown, error = %e, "VolumeDelete refused"),
        Err(_) => tracing::warn!(volume = ?shown, "VolumeDelete failed: the deletion panicked"),
    }
}
