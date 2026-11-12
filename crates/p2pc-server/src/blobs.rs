// SPDX-License-Identifier: AGPL-3.0-only

//! The hub's blob files and what it keeps in memory about uploads (H2 §7.5, §13). The rows are in
//! [`crate::store::blobs`]; the routes in [`crate::blobs_api`]; delivery to a node in `gateway::blob_fetch`.
//!
//! - **Files.** A blob of an account lives at `<data>/blobs/<account_id>/sha256/<aa>/<bb>/<hex>`. `<account_id>` is
//!   the hub's own ID of the account (a fixed format, never a string from a request), so a digest has one file per
//!   account and only rows of that account refer to it (SI-H2-8). Uploads are written to
//!   `<data>/blobs/staging/<name>`, then `fsync`ed and renamed into place. Every path is walked with
//!   [`crate::fsutil`], which never follows a link.
//! - **Uploads in progress.** The names of the staging files that uploads hold (the staging sweep skips them), the
//!   uploads per principal (at most [`MAX_UPLOADS_PER_PRINCIPAL`]) and the bytes reserved per account and per device.
//!   A [`Reservation`] and a [`Staging`] give theirs back when dropped, so every exit path releases them. At start
//!   none exists: nothing survives a restart.
//! - **The lock per `(account_id, digest)`** ([`BlobStore::lock`]). The GC and `DELETE` hold it from before the
//!   tombstone until the row is gone; an upload from its check of the row until its rename and row insert. The same
//!   digest in two accounts takes two locks. Entries are dropped when nobody holds or waits for them, so the map stays
//!   as small as the work in progress.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use p2pc_proto::api::{Principal as PrincipalId, Sha256Digest};
use p2pc_proto::ids::{AccountId, DeviceId};
use rustix::fs::AtFlags;
use time::OffsetDateTime;
use tokio::time::Instant;

use crate::fsutil;

/// The directory of every blob under the data dir.
pub const BLOBS_DIR: &str = "blobs";
/// The staging directory, under [`BLOBS_DIR`].
pub const STAGING_DIR: &str = "staging";
/// Uploads one principal may have in progress at once (H2 §7.5: beyond it `429 too_many_uploads`).
pub const MAX_UPLOADS_PER_PRINCIPAL: usize = 2;
/// A staging file no upload holds is swept once its last write is this old (H2 §13).
pub const STAGING_MAX_AGE: time::Duration = time::Duration::hours(1);

/// The time limits of an upload body (H2 §7.5 "Timeouts"): no 30 s whole-request limit, but an idle limit and a
/// floor on the average rate over any `window`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadLimits {
    /// No byte for this long ends the upload (60 s).
    pub idle: Duration,
    /// The slowest average rate allowed over any `window`, in bytes per second (16 KiB/s).
    pub floor_bytes_per_s: u64,
    /// The window of the floor (60 s).
    pub window: Duration,
}

impl Default for UploadLimits {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(60),
            floor_bytes_per_s: 16 * 1024,
            window: Duration::from_secs(60),
        }
    }
}

/// The blob files and the uploads in progress. Cheap to clone.
#[derive(Debug, Clone)]
pub struct BlobStore {
    inner: Arc<Inner>,
    limits: UploadLimits,
}

/// The lock of each `(account, digest)` that someone holds or waits for.
type LockMap = HashMap<(AccountId, Sha256Digest), Arc<tokio::sync::Mutex<()>>>;

#[derive(Debug)]
struct Inner {
    data_dir: PathBuf,
    memory: Mutex<Memory>,
    locks: Mutex<LockMap>,
}

#[derive(Debug, Default)]
struct Memory {
    /// Staging file names held by uploads in progress.
    staging: HashSet<String>,
    /// Uploads in progress per principal.
    uploads: HashMap<PrincipalId, usize>,
    /// Bytes reserved by uploads in progress, per account.
    account_reserved: HashMap<AccountId, u64>,
    /// Bytes reserved by uploads in progress, per device.
    device_reserved: HashMap<DeviceId, u64>,
}

impl Inner {
    fn memory(&self) -> MutexGuard<'_, Memory> {
        self.memory.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Why an upload cannot be reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The principal already has [`MAX_UPLOADS_PER_PRINCIPAL`] uploads in progress.
    TooManyUploads,
    /// The account's quota, or the device's, would be exceeded.
    QuotaExceeded,
}

/// What a reservation is checked against, read from the database in the reserving transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quotas {
    /// Bytes the account stores in blobs.
    pub account_stored: u64,
    /// The account's quota, in bytes.
    pub account_quota: u64,
    /// For a device with a quota: the bytes of the blobs it holds a claim on, and its quota in bytes.
    pub device: Option<(u64, u64)>,
}

/// One upload's slot and reserved bytes, given back when dropped.
#[derive(Debug)]
pub struct Reservation {
    inner: Arc<Inner>,
    account: AccountId,
    principal: PrincipalId,
    size: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut m = self.inner.memory();
        if let Some(n) = m.uploads.get_mut(&self.principal) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.uploads.remove(&self.principal);
            }
        }
        release(&mut m.account_reserved, self.account, self.size);
        if let Some(device) = self.principal.device_id() {
            release(&mut m.device_reserved, device, self.size);
        }
    }
}

fn release<K: std::hash::Hash + Eq>(map: &mut HashMap<K, u64>, key: K, size: u64) {
    if let Some(v) = map.get_mut(&key) {
        *v = v.saturating_sub(size);
        if *v == 0 {
            map.remove(&key);
        }
    }
}

/// The lock of one `(account_id, digest)`, held until dropped.
#[derive(Debug)]
pub struct BlobLock {
    inner: Arc<Inner>,
    key: (AccountId, Sha256Digest),
    mutex: Arc<tokio::sync::Mutex<()>>,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for BlobLock {
    fn drop(&mut self) {
        self.guard.take();
        let mut locks = self
            .inner
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The map's reference and this one: nobody else holds or waits for it (clones are made under this lock).
        if Arc::strong_count(&self.mutex) == 2 {
            locks.remove(&self.key);
        }
    }
}

/// A staging file of an upload in progress: held (the sweep skips it) until published or dropped. Dropped
/// unpublished, the file is deleted.
#[derive(Debug)]
pub struct Staging {
    inner: Arc<Inner>,
    name: String,
    /// The open file, until it is published.
    pub file: Option<tokio::fs::File>,
    published: bool,
}

impl Staging {
    /// Deletes the file now (on the blocking pool) and lets go of its name.
    pub async fn discard(mut self) {
        self.file.take();
        let (dir, name) = (self.inner.data_dir.clone(), self.name.clone());
        let removed = tokio::task::spawn_blocking(move || {
            let staging = fsutil::open_dir(&dir, [BLOBS_DIR, STAGING_DIR], false)?;
            fsutil::unlink(&staging, &name)
        })
        .await;
        if !matches!(removed, Ok(Ok(()))) {
            tracing::warn!("cannot delete a blob staging file; the staging sweep will");
        }
        // Deleted (or left to the sweep): nothing to do on drop but give the name back.
        self.published = true;
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.published {
            // A path that did not discard it (a panic, a dropped future): delete it here. One `unlinkat`.
            if let Ok(staging) = fsutil::open_dir(&self.inner.data_dir, [BLOBS_DIR, STAGING_DIR], false) {
                let _ = fsutil::unlink(&staging, &self.name);
            }
        }
        self.inner.memory().staging.remove(&self.name);
    }
}

impl BlobStore {
    /// The store of the data dir `data_dir`, with the default upload limits.
    #[must_use]
    pub fn new(data_dir: &Path) -> Self {
        Self {
            inner: Arc::new(Inner {
                data_dir: data_dir.to_path_buf(),
                memory: Mutex::new(Memory::default()),
                locks: Mutex::new(HashMap::new()),
            }),
            limits: UploadLimits::default(),
        }
    }

    /// The same store with other upload limits (tests use short ones).
    #[must_use]
    pub fn with_upload_limits(mut self, limits: UploadLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The upload limits.
    #[must_use]
    pub fn upload_limits(&self) -> UploadLimits {
        self.limits
    }

    /// `<data>/blobs/staging`.
    #[must_use]
    pub fn staging_dir(&self) -> PathBuf {
        self.inner.data_dir.join(BLOBS_DIR).join(STAGING_DIR)
    }

    /// Takes a slot and reserves `size` bytes for an upload of `principal` in `account`, if the principal has a free
    /// slot and `stored + reserved + size` fits the account's quota and, for a device with a quota, the device's
    /// (with `checked_add`). Call it inside the transaction that read `quotas`, so no row is inserted in between.
    pub fn try_reserve(
        &self,
        account: AccountId,
        principal: PrincipalId,
        size: u64,
        quotas: Quotas,
    ) -> Result<Reservation, Refusal> {
        let mut m = self.inner.memory();
        if m.uploads.get(&principal).copied().unwrap_or(0) >= MAX_UPLOADS_PER_PRINCIPAL {
            return Err(Refusal::TooManyUploads);
        }
        let fits = |stored: u64, reserved: u64, quota: u64| {
            stored
                .checked_add(reserved)
                .and_then(|v| v.checked_add(size))
                .is_some_and(|total| total <= quota)
        };
        let account_reserved = m.account_reserved.get(&account).copied().unwrap_or(0);
        if !fits(quotas.account_stored, account_reserved, quotas.account_quota) {
            return Err(Refusal::QuotaExceeded);
        }
        let device = principal.device_id();
        if let (Some(d), Some((stored, quota))) = (device, quotas.device) {
            let reserved = m.device_reserved.get(&d).copied().unwrap_or(0);
            if !fits(stored, reserved, quota) {
                return Err(Refusal::QuotaExceeded);
            }
        }
        *m.uploads.entry(principal).or_insert(0) += 1;
        *m.account_reserved.entry(account).or_insert(0) += size;
        if let Some(d) = device {
            *m.device_reserved.entry(d).or_insert(0) += size;
        }
        Ok(Reservation {
            inner: self.inner.clone(),
            account,
            principal,
            size,
        })
    }

    /// Waits for, then holds, the lock of `(account, digest)`.
    pub async fn lock(&self, account: AccountId, digest: Sha256Digest) -> BlobLock {
        let key = (account, digest);
        let mutex = self
            .inner
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(key)
            .or_default()
            .clone();
        let mut lock = BlobLock {
            inner: self.inner.clone(),
            key,
            mutex: mutex.clone(),
            guard: None,
        };
        // If this future is dropped while waiting, `lock` is dropped too and cleans the entry up.
        lock.guard = Some(mutex.lock_owned().await);
        lock
    }

    /// Creates a new staging file, held by the caller until it is published or dropped. Its name is registered
    /// before the file exists, so the sweep never sees it unheld.
    pub async fn create_staging(&self) -> io::Result<Staging> {
        for _ in 0..8 {
            let name = staging_name();
            if !self.inner.memory().staging.insert(name.clone()) {
                continue;
            }
            let mut staging = Staging {
                inner: self.inner.clone(),
                name: name.clone(),
                file: None,
                // Nothing to delete until the file exists.
                published: true,
            };
            let dir = self.inner.data_dir.clone();
            let created = tokio::task::spawn_blocking(move || {
                let staging = fsutil::open_dir(&dir, [BLOBS_DIR, STAGING_DIR], true)?;
                fsutil::create_new(&staging, &name)
            })
            .await
            .map_err(io::Error::other)?;
            match created {
                Ok(file) => {
                    staging.file = Some(tokio::fs::File::from_std(file));
                    staging.published = false;
                    return Ok(staging);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("no free staging name"))
    }

    /// Flushes `staging` to disk and renames it to the blob's file of `account`, then flushes both directories. A
    /// file already there (a leftover of a crash between the rename and the row) is replaced: it has the same digest.
    pub async fn publish(&self, mut staging: Staging, account: AccountId, digest: Sha256Digest) -> io::Result<()> {
        if let Some(file) = staging.file.take() {
            file.sync_all().await?;
        }
        let dir = self.inner.data_dir.clone();
        let name = staging.name.clone();
        tokio::task::spawn_blocking(move || {
            let from = fsutil::open_dir(&dir, [BLOBS_DIR, STAGING_DIR], false)?;
            let to = blob_dir(&dir, account, digest, true)?;
            fsutil::rename(&from, &name, &to, &digest.to_string())?;
            fsutil::fsync(&to)?;
            fsutil::fsync(&from)
        })
        .await
        .map_err(io::Error::other)??;
        staging.published = true;
        Ok(())
    }

    /// Opens the blob's file of `account` for reading (a regular file reached without following a link) and returns
    /// it with its size.
    pub async fn open(&self, account: AccountId, digest: Sha256Digest) -> io::Result<(std::fs::File, u64)> {
        let dir = self.inner.data_dir.clone();
        tokio::task::spawn_blocking(move || {
            let d = blob_dir(&dir, account, digest, false)?;
            let file = fsutil::open_read(&d, &digest.to_string())?;
            let size = file.metadata()?.len();
            Ok((file, size))
        })
        .await
        .map_err(io::Error::other)?
    }

    /// Deletes the blob's file of `account` (a missing one is not an error). Never follows a link.
    pub async fn remove(&self, account: AccountId, digest: Sha256Digest) -> io::Result<()> {
        let dir = self.inner.data_dir.clone();
        tokio::task::spawn_blocking(move || {
            let hex = digest.to_string();
            let d = match blob_dir(&dir, account, digest, false) {
                Ok(d) => d,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            };
            fsutil::unlink(&d, &hex)?;
            fsutil::fsync(&d)?;
            // The hash directories stay: another digest's upload may be renaming into them right now (it holds its
            // own digest's lock, not this one), and at most 65,536 empty ones per account cost nothing.
            Ok(())
        })
        .await
        .map_err(io::Error::other)?
    }

    /// Deletes up to `limit` staging files that no upload holds: those whose last write is before `written_before`,
    /// or every one with `None` (at start, when no upload is in progress). Returns how many went. Never by creation
    /// time: a slow upload may legitimately run for hours (H2 §13).
    pub async fn sweep_staging(&self, written_before: Option<OffsetDateTime>, limit: usize) -> io::Result<usize> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || sweep(&inner, written_before.map(OffsetDateTime::unix_timestamp), limit))
            .await
            .map_err(io::Error::other)?
    }
}

fn sweep(inner: &Inner, written_before: Option<i64>, limit: usize) -> io::Result<usize> {
    let dir = match fsutil::open_dir(&inner.data_dir, [BLOBS_DIR, STAGING_DIR], false) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut names = Vec::new();
    let mut entries = rustix::fs::Dir::read_from(&dir)?;
    while let Some(entry) = entries.read() {
        let name = entry?.file_name().to_owned();
        if name.as_bytes() != b"." && name.as_bytes() != b".." {
            names.push(name);
        }
    }
    let mut swept = 0;
    for name in names {
        if swept >= limit {
            break;
        }
        // A name that is not UTF-8 was not made by the hub; it is never held.
        let held = name.to_str().is_ok_and(|n| inner.memory().staging.contains(n));
        if held {
            continue;
        }
        let stat = match rustix::fs::statat(&dir, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(s) => s,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(e) => return Err(e.into()),
        };
        if written_before.is_some_and(|cut| stat.st_mtime >= cut) {
            continue;
        }
        let flags = if rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Directory {
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        match rustix::fs::unlinkat(&dir, &name, flags) {
            Ok(()) => swept += 1,
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => {
                tracing::warn!(error = %e, "staging sweep: cannot delete an entry");
            }
        }
    }
    if swept > 0 {
        fsutil::fsync(&dir)?;
    }
    Ok(swept)
}

/// `<data>/blobs/<account>/sha256/<aa>/<bb>`, created (`0700`) if asked.
fn blob_dir(data_dir: &Path, account: AccountId, digest: Sha256Digest, create: bool) -> io::Result<OwnedFd> {
    let hex = digest.to_string();
    let account = account.to_string();
    fsutil::open_dir(
        data_dir,
        [BLOBS_DIR, account.as_str(), "sha256", &hex[..2], &hex[2..4]],
        create,
    )
}

/// A staging name, unique in this process and unlikely to meet a leftover (which `O_EXCL` refuses anyway).
fn staging_name() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{}-{nanos:x}-{n}", std::process::id())
}

/// The pace of one upload body (H2 §7.5 "Timeouts"): when it must have received its next byte. Two limits:
///
/// - **idle**: no byte for [`UploadLimits::idle`];
/// - **floor**: over any [`UploadLimits::window`] (from the upload's start on), fewer than `floor × window` bytes.
///
/// The bytes received are sampled at most once a second (a sample keeps the total at the end of its second), so the
/// floor is checked with a granularity of one second, never laxer than the rule. At most one sample per second of the
/// last window is kept: the memory is bounded whatever the client sends.
#[derive(Debug, Clone)]
pub struct Pace {
    limits: UploadLimits,
    last_byte: Instant,
    total: u64,
    /// `(when, total bytes received by then)`, oldest first; the first is the start, with 0 bytes.
    samples: VecDeque<(Instant, u64)>,
}

impl Pace {
    /// An upload that starts at `start`.
    #[must_use]
    pub fn new(limits: UploadLimits, start: Instant) -> Self {
        Self {
            limits,
            last_byte: start,
            total: 0,
            samples: VecDeque::from([(start, 0)]),
        }
    }

    fn floor_bytes(&self) -> u64 {
        self.limits
            .floor_bytes_per_s
            .saturating_mul(self.limits.window.as_secs())
    }

    /// `n` bytes arrived at `now`.
    pub fn record(&mut self, now: Instant, n: u64) {
        if n == 0 {
            return;
        }
        self.total = self.total.saturating_add(n);
        self.last_byte = now;
        match self.samples.back_mut() {
            Some((at, total)) if now.saturating_duration_since(*at) < Duration::from_secs(1) => *total = self.total,
            _ => self.samples.push_back((now, self.total)),
        }
        // A sample whose total is at least `floor` below the current one can never decide the floor again.
        let floor = self.floor_bytes();
        while self.samples.len() > 1
            && self
                .samples
                .front()
                .is_some_and(|(_, t)| t.saturating_add(floor) <= self.total)
        {
            self.samples.pop_front();
        }
    }

    /// The instant at which the upload has failed a limit if no byte arrives before it.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        let idle = self.last_byte + self.limits.idle;
        let floor = self.floor_bytes();
        // Without new bytes, the window ending at `t` holds `total - total(t - window)`, which falls below the floor
        // once `t - window` passes the first sample whose total is within `floor` of the current one.
        let floor_deadline = self
            .samples
            .iter()
            .find(|(_, t)| t.saturating_add(floor) > self.total)
            .map(|(at, _)| *at + self.limits.window);
        match floor_deadline {
            Some(f) => idle.min(f),
            None => idle,
        }
    }

    /// Bytes received.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIB: u64 = 1024;

    fn limits() -> UploadLimits {
        UploadLimits::default()
    }

    /// Feeds `per_s` bytes every second for `secs` seconds; returns whether every chunk came before the deadline.
    fn steady(pace: &mut Pace, start: Instant, from_s: u64, secs: u64, per_s: u64) -> bool {
        for s in from_s..from_s + secs {
            let now = start + Duration::from_secs(s);
            if now >= pace.deadline() {
                return false;
            }
            pace.record(now, per_s);
        }
        true
    }

    #[test]
    fn the_floor_rate_passes_for_hours() {
        let start = Instant::now();
        let mut pace = Pace::new(limits(), start);
        // One-second chunks a little over the floor (exactly the floor would put a window's last chunk on its
        // deadline instant).
        assert!(steady(&mut pace, start, 1, 4 * 3600, 17 * KIB));
        // The kept samples stay bounded.
        assert!(pace.samples.len() <= 62, "{}", pace.samples.len());
    }

    #[test]
    fn half_the_floor_fails_after_one_window() {
        let start = Instant::now();
        let mut pace = Pace::new(limits(), start);
        assert!(!steady(&mut pace, start, 1, 120, 8 * KIB));
        let d = pace.deadline();
        assert!(
            d >= start + Duration::from_secs(60) && d <= start + Duration::from_secs(61),
            "{d:?}"
        );
    }

    #[test]
    fn a_burst_then_a_trickle_fails_one_window_after_the_burst() {
        let start = Instant::now();
        let mut pace = Pace::new(limits(), start);
        pace.record(start + Duration::from_millis(500), 4 * 1024 * KIB);
        assert!(!steady(&mut pace, start, 1, 200, KIB));
        let d = pace.deadline();
        assert!(d <= start + Duration::from_secs(61), "{d:?}");
        assert!(d >= start + Duration::from_secs(60), "{d:?}");
    }

    #[test]
    fn the_idle_limit_comes_first_when_it_is_shorter() {
        let start = Instant::now();
        let short = UploadLimits {
            idle: Duration::from_secs(5),
            ..limits()
        };
        let mut pace = Pace::new(short, start);
        pace.record(start + Duration::from_secs(1), 10 * 1024 * KIB);
        assert_eq!(pace.deadline(), start + Duration::from_secs(6));
        assert_eq!(pace.total(), 10 * 1024 * KIB);
    }

    #[test]
    fn reservations_count_slots_and_bytes_and_are_released_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BlobStore::new(tmp.path());
        let account = AccountId::generate();
        let device = PrincipalId::Device(DeviceId::generate());
        let quotas = Quotas {
            account_stored: 10,
            account_quota: 100,
            device: Some((0, 50)),
        };
        let a = store.try_reserve(account, device, 30, quotas).unwrap();
        // The device's quota: 30 reserved + 30 > 50.
        assert_eq!(
            store.try_reserve(account, device, 30, quotas).unwrap_err(),
            Refusal::QuotaExceeded
        );
        let b = store.try_reserve(account, device, 20, quotas).unwrap();
        assert_eq!(
            store.try_reserve(account, device, 0, quotas).unwrap_err(),
            Refusal::TooManyUploads
        );
        // The account's quota: 10 + 50 reserved + 41 > 100, for another principal.
        let key = PrincipalId::Key(p2pc_proto::ids::KeyId::generate());
        let no_device = Quotas { device: None, ..quotas };
        assert_eq!(
            store.try_reserve(account, key, 41, no_device).unwrap_err(),
            Refusal::QuotaExceeded
        );
        // An overflowing size is refused, never wrapped.
        assert_eq!(
            store.try_reserve(account, key, u64::MAX, no_device).unwrap_err(),
            Refusal::QuotaExceeded
        );
        drop((a, b));
        let m = store.inner.memory();
        assert!(m.uploads.is_empty() && m.account_reserved.is_empty() && m.device_reserved.is_empty());
    }

    #[tokio::test]
    async fn the_lock_map_forgets_unused_locks() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BlobStore::new(tmp.path());
        let (a, d) = (AccountId::generate(), Sha256Digest([1; 32]));
        let held = store.lock(a, d).await;
        let waiter = {
            let store = store.clone();
            tokio::spawn(async move { drop(store.lock(a, d).await) })
        };
        drop(held);
        waiter.await.unwrap();
        assert!(store.inner.locks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_staging_file_dropped_unpublished_is_deleted() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BlobStore::new(tmp.path());
        let staging = store.create_staging().await.unwrap();
        assert_eq!(std::fs::read_dir(store.staging_dir()).unwrap().count(), 1);
        assert_eq!(store.inner.memory().staging.len(), 1);
        drop(staging);
        assert_eq!(std::fs::read_dir(store.staging_dir()).unwrap().count(), 0);
        assert!(store.inner.memory().staging.is_empty());
        store.create_staging().await.unwrap().discard().await;
        assert_eq!(std::fs::read_dir(store.staging_dir()).unwrap().count(), 0);
    }
}
