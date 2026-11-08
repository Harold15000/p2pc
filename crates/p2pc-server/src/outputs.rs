// SPDX-License-Identifier: AGPL-3.0-only

//! Job outputs (spec §6 "Uploads", §7, §12, SI-8, SI-9): staging fenced uploads, publishing them on `JobFinished`,
//! and opening published files for download.
//!
//! Layout under `<data>/artifacts/<job_id>/<attempt>/`: `.staging/<path>` while a file is staged, `files/<path>`
//! once published. Publishing moves a file out of `.staging` (a rename in the same file system). Keeping the two
//! roots apart means no output path, `.staging/…` included, can ever land in the other.
//!
//! - **Uploads** ([`OutputStore::begin`], [`receive`], [`Upload::commit`]): the header is fenced (the job's current
//!   lease, held by this node, SI-8), its path is **reserved in memory before the database is asked** (so two streams
//!   for one path can never both pass), and it is validated (the path, SI-9; the job's `outputs.max_mb`; 10 000
//!   files; at most 2 uploads at once per node and 8 in total; the attempt not finalised; the path not staged yet).
//!   The bytes go to a temporary file of this stream alone (`<attempt>/.incoming/<name>`, created `O_EXCL`), hashed as
//!   they are written and counted exactly. A good file is fsynced, then, in one transaction that checks the lease, the
//!   caps and the path again, renamed to `.staging/<path>` with `RENAME_NOREPLACE` and recorded. An upload only ever
//!   removes the file it created: a failure can never truncate or unlink a file another upload staged (review P2).
//! - **Publishing** ([`OutputsFinalizer::finalize`]): once per attempt, idempotent. Listed files staged with the same
//!   size and sha256 are moved to `files/` and recorded in `job_outputs`; staged files that are not listed (or do not
//!   match) are deleted; the job's `error` gets `outputs_incomplete: N` for the listed files left out.
//! - **Downloads** ([`OutputStore::open_published`]): the path is validated again and every segment is opened with
//!   `O_NOFOLLOW` under `files/`, so a link planted in the store is never followed.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use p2pc_proto::api::{MAX_OUTPUT_FILES, OutputFile, Sha256Digest};
use p2pc_proto::ids::{JobId, LeaseId, NodeId};
use p2pc_proto::protocol::{UploadHeader, upload_reason};
use p2pc_proto::validate::validate_output_path;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::clock::Clock;
use crate::fsutil;
use crate::gateway::BoxFuture;
use crate::logs::LogStore;
use crate::scheduler::OutputsFinalizer;
use crate::store::leases::{self, LeaseState};
use crate::store::{self, Db, StoreError, jobs, outputs};

/// The directory under the data dir.
pub const ARTIFACTS_DIR: &str = "artifacts";
/// Where staged files go, under an attempt's directory.
pub const STAGING_DIR: &str = ".staging";
/// Where published files go, under an attempt's directory.
pub const FILES_DIR: &str = "files";
/// Where an upload's bytes are written, each stream under its own temporary name, until its commit moves them to
/// `.staging/<path>` without replacing anything.
pub const INCOMING_DIR: &str = ".incoming";

/// The limits of upload streams (§6 "Uploads"; T10b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadLimits {
    /// Uploads at once from one node.
    pub per_node: usize,
    /// Uploads at once in total.
    pub total: usize,
    /// A stream with no bytes for this long fails.
    pub idle: Duration,
    /// After `grace`, a stream must have averaged at least this many bytes per second since then.
    pub min_rate: u64,
    /// See `min_rate`.
    pub grace: Duration,
    /// Upload streams of one node whose header is still being read (each may buffer up to 1 MiB for `idle`);
    /// beyond it a stream is refused unread.
    pub headers_per_node: usize,
}

impl Default for UploadLimits {
    fn default() -> Self {
        Self {
            per_node: 2,
            total: 8,
            idle: Duration::from_secs(30),
            min_rate: 64 * 1024,
            grace: Duration::from_secs(10),
            headers_per_node: 4,
        }
    }
}

/// Why an upload is refused: an [`upload_reason`] code, and whether the node also gets `Cancel` for the lease
/// (SI-8: a stale epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    /// The `UploadAck.reason`.
    pub reason: &'static str,
    /// `Some((lease, epoch))` when the node must be told to cancel that lease.
    pub cancel: Option<(LeaseId, u64)>,
}

impl Refused {
    fn because(reason: &'static str) -> Self {
        Self { reason, cancel: None }
    }
}

impl From<StoreError> for Refused {
    fn from(e: StoreError) -> Self {
        tracing::warn!(error = %e, "an upload failed on a storage error");
        Self::because(upload_reason::INTERNAL)
    }
}

type Key = (JobId, u32);

/// What uploads in progress hold.
#[derive(Debug, Default)]
struct InFlight {
    per_node: HashMap<NodeId, usize>,
    total: usize,
    /// Per attempt: bytes and paths being received.
    attempts: HashMap<Key, (u64, HashSet<String>)>,
}

/// The output store. Cheap to clone.
#[derive(Debug, Clone)]
pub struct OutputStore {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    data_dir: PathBuf,
    db: Db,
    clock: Arc<dyn Clock>,
    logs: LogStore,
    in_flight: Mutex<InFlight>,
    /// Tests only: runs on the blocking pool when finalisation starts moving files.
    #[cfg(test)]
    publish_hook: Mutex<Option<PublishHook>>,
}

/// See [`Inner::publish_hook`].
#[cfg(test)]
#[derive(Clone)]
struct PublishHook(Arc<dyn Fn() + Send + Sync>);

#[cfg(test)]
impl std::fmt::Debug for PublishHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PublishHook")
    }
}

/// How [`OutputStore::begin`] answers a valid header.
#[derive(Debug)]
pub enum Begun {
    /// Receive the bytes.
    Receive(Upload),
    /// The same path, size and sha256 are already staged (a retry after a lost ack): nothing to receive.
    AlreadyStaged,
}

/// An upload in progress: it holds the reservation of its path (and its slot), released when it is dropped.
#[derive(Debug)]
pub struct Upload {
    store: OutputStore,
    node_id: NodeId,
    lease_id: LeaseId,
    epoch: u64,
    job_id: JobId,
    attempt: u32,
    max_bytes: u64,
    file: OutputFile,
    /// The name of this stream's own file under `.incoming/`.
    temp: String,
}

/// A name for a stream's temporary file: unique in this process, and unlikely to meet a leftover of another (which
/// `O_EXCL` refuses anyway; the next name is tried then).
fn temp_name() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{}-{nanos:x}-{n}", std::process::id())
}

impl Drop for Upload {
    fn drop(&mut self) {
        let mut f = self.store.in_flight();
        if let Some(n) = f.per_node.get_mut(&self.node_id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                f.per_node.remove(&self.node_id);
            }
        }
        f.total = f.total.saturating_sub(1);
        let key = (self.job_id, self.attempt);
        if let Some((bytes, paths)) = f.attempts.get_mut(&key) {
            *bytes = bytes.saturating_sub(self.file.size);
            paths.remove(&self.file.path);
            if paths.is_empty() {
                f.attempts.remove(&key);
            }
        }
    }
}

impl OutputStore {
    /// The store of the data dir.
    #[must_use]
    pub fn new(data_dir: &Path, db: Db, clock: Arc<dyn Clock>, logs: LogStore) -> Self {
        Self {
            inner: Arc::new(Inner {
                data_dir: data_dir.to_path_buf(),
                db,
                clock,
                logs,
                in_flight: Mutex::new(InFlight::default()),
                #[cfg(test)]
                publish_hook: Mutex::new(None),
            }),
        }
    }

    fn in_flight(&self) -> std::sync::MutexGuard<'_, InFlight> {
        self.inner.in_flight.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The directory of a job's artifacts.
    #[must_use]
    pub fn job_dir(&self, job_id: JobId) -> PathBuf {
        self.inner.data_dir.join(ARTIFACTS_DIR).join(job_id.to_string())
    }

    /// The staging directory of an attempt.
    #[must_use]
    pub fn staging_dir(&self, job_id: JobId, attempt: u32) -> PathBuf {
        self.job_dir(job_id).join(attempt.to_string()).join(STAGING_DIR)
    }

    /// The directory of an attempt's uploads in progress (their temporary files).
    #[must_use]
    pub fn incoming_dir(&self, job_id: JobId, attempt: u32) -> PathBuf {
        self.job_dir(job_id).join(attempt.to_string()).join(INCOMING_DIR)
    }

    /// The published directory of an attempt.
    #[must_use]
    pub fn files_dir(&self, job_id: JobId, attempt: u32) -> PathBuf {
        self.job_dir(job_id).join(attempt.to_string()).join(FILES_DIR)
    }

    /// Removes a job's whole artifacts directory, following no link, not even one in front of it. Blocking: call it
    /// from `spawn_blocking`. Whether something was removed.
    pub fn remove_job(&self, job_id: JobId) -> std::io::Result<bool> {
        fsutil::remove_tree(&self.inner.data_dir, &[ARTIFACTS_DIR, job_id.to_string().as_str()])
    }

    /// Removes an attempt's `.staging` and `.incoming`, following no link. Blocking: call it from `spawn_blocking`.
    pub fn remove_staging(&self, job_id: JobId, attempt: u32) -> std::io::Result<()> {
        remove_staging_dirs(&self.inner.data_dir, job_id, attempt)
    }

    /// Uploads in progress (tests).
    #[must_use]
    pub fn uploads_in_progress(&self) -> usize {
        self.in_flight().total
    }

    /// Checks an upload header from `node_id` and reserves its place, or refuses it.
    pub async fn begin(&self, node_id: NodeId, header: &UploadHeader, limits: &UploadLimits) -> Result<Begun, Refused> {
        // The cheap, global limit first: a node cannot make the server read the database for every stream it opens.
        {
            let f = self.in_flight();
            if f.total >= limits.total || f.per_node.get(&node_id).copied().unwrap_or(0) >= limits.per_node {
                return Err(Refused::because(upload_reason::TOO_MANY_UPLOADS));
            }
        }
        if header.validate().is_err() {
            return Err(Refused::because(upload_reason::INVALID_PATH));
        }
        let mut conn = self.inner.db.acquire().await.map_err(StoreError::from)?;
        let lease = fenced(&mut conn, node_id, header.lease_id, header.epoch).await?;
        let job = jobs::get(&mut conn, lease.account_id, lease.project_id, lease.job_id)
            .await?
            .ok_or(StoreError::Corrupt("leases.job_id"))?;
        let max_bytes = job.spec_view.outputs.max_mb.saturating_mul(1024 * 1024);
        // The size is the node's word: a file over the whole cap is refused before anything is reserved, so the
        // per-attempt byte counter below only ever holds sizes that fit (and cannot overflow).
        if header.size > max_bytes {
            return Err(Refused::because(upload_reason::TOO_LARGE));
        }
        let key = (lease.job_id, lease.attempt);
        // Reserve the path (and the slot) BEFORE the database says whether it is staged (review P2): a second stream
        // for the path is refused here while this one runs, and once this one has committed and released it, the
        // database read below sees its row. Any refusal from here on drops `upload`, which releases the reservation.
        let upload = {
            let mut f = self.in_flight();
            if f.total >= limits.total || f.per_node.get(&node_id).copied().unwrap_or(0) >= limits.per_node {
                return Err(Refused::because(upload_reason::TOO_MANY_UPLOADS));
            }
            if f.attempts
                .get(&key)
                .is_some_and(|(_, paths)| paths.contains(&header.path))
            {
                return Err(Refused::because(upload_reason::DUPLICATE_PATH));
            }
            // Checked before anything is counted, so a refusal here leaves no slot behind. Each size is at most
            // `max_bytes`, which `outputs.max_mb` can make huge: the sum must not wrap.
            let Some(reserved) = f
                .attempts
                .get(&key)
                .map_or(0, |(bytes, _)| *bytes)
                .checked_add(header.size)
            else {
                return Err(Refused::because(upload_reason::TOO_LARGE));
            };
            *f.per_node.entry(node_id).or_insert(0) += 1;
            f.total += 1;
            let entry = f.attempts.entry(key).or_default();
            entry.0 = reserved;
            entry.1.insert(header.path.clone());
            Upload {
                store: self.clone(),
                node_id,
                lease_id: header.lease_id,
                epoch: header.epoch,
                job_id: lease.job_id,
                attempt: lease.attempt,
                max_bytes,
                file: OutputFile {
                    path: header.path.clone(),
                    size: header.size,
                    sha256: header.sha256,
                },
                temp: temp_name(),
            }
        };
        let uploads = outputs::attempt_uploads(&mut conn, lease.job_id, lease.attempt).await?;
        if uploads.finalized {
            return Err(Refused::because(upload_reason::FINALIZED));
        }
        if let Some(existing) = outputs::staged(&mut conn, lease.job_id, lease.attempt, &header.path).await? {
            return if existing.size == header.size && existing.sha256 == header.sha256 {
                Ok(Begun::AlreadyStaged)
            } else {
                Err(Refused::because(upload_reason::DUPLICATE_PATH))
            };
        }
        drop(conn);
        // The other uploads in flight for this attempt (this one excluded).
        let (others_bytes, others_files) = {
            let f = self.in_flight();
            let (bytes, paths) = f.attempts.get(&key).cloned().unwrap_or_default();
            (bytes.saturating_sub(header.size), paths.len().saturating_sub(1) as u64)
        };
        if uploads.staged_files + others_files >= u64::from(MAX_OUTPUT_FILES) {
            return Err(Refused::because(upload_reason::TOO_MANY_FILES));
        }
        if header.size
            > max_bytes
                .saturating_sub(uploads.staged_bytes)
                .saturating_sub(others_bytes)
        {
            return Err(Refused::because(upload_reason::TOO_LARGE));
        }
        Ok(Begun::Receive(upload))
    }

    /// Opens a published file of an attempt for reading, under `files/` only, following no link. Returns the file
    /// and its size. `NotFound` for anything that is not a regular file reached without a link.
    pub async fn open_published(
        &self,
        job_id: JobId,
        attempt: u32,
        path: &str,
    ) -> std::io::Result<(std::fs::File, u64)> {
        validate_output_path(path).map_err(|_| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        let dir = self.inner.data_dir.clone();
        let path = path.to_string();
        tokio::task::spawn_blocking(move || {
            let job = job_id.to_string();
            let attempt = attempt.to_string();
            let segments: Vec<&str> = path.split('/').collect();
            let (name, parents) = segments.split_last().ok_or(std::io::ErrorKind::NotFound)?;
            let base = [ARTIFACTS_DIR, job.as_str(), attempt.as_str(), FILES_DIR];
            let file = fsutil::open_dir(&dir, base.into_iter().chain(parents.iter().copied()), false)
                .and_then(|d| fsutil::open_read(&d, name))
                // A link (ELOOP), a file where a directory should be, a FIFO: all simply not there.
                .map_err(|e| {
                    tracing::debug!(error = %e, "an output could not be opened");
                    std::io::Error::from(std::io::ErrorKind::NotFound)
                })?;
            let size = file.metadata()?.len();
            Ok((file, size))
        })
        .await
        .map_err(std::io::Error::other)?
    }

    /// Publishes an attempt's outputs in three steps, so SQLite's write lock is never held while files move:
    ///
    /// 1. A short transaction marks the attempt as being finalised ([`outputs::begin_finalizing`]) and reads the staged
    ///    files. Upload commits take the same lock, so an upload either committed before (and is in that list) or finds
    ///    the attempt closed.
    /// 2. With no lock held, the listed files are moved to `files/`, the directories that got them are fsynced and the
    ///    staging is removed ([`publish`]).
    /// 3. A second short transaction records the published files and sets `finalized_at`.
    ///
    /// A crash between the steps, or an error in step 2 (a failed fsync), leaves the attempt marked and its files in
    /// `.staging` or `files/`. The scheduler does not retry: it ends the job with `outputs_incomplete`. The attempt is
    /// finished by a repeated `JobFinished` (which redoes step 2; a file already in `files/` counts as published) or,
    /// if none comes, by the GC's staging sweep ([`OutputStore::finish_interrupted`]).
    async fn finalize_attempt(
        &self,
        job_id: JobId,
        attempt: u32,
        listed: &[OutputFile],
    ) -> Result<Option<String>, StoreError> {
        let staged = {
            let mut tx = store::begin_immediate(&self.inner.db).await?;
            if let Some(note) = outputs::finalized_note(&mut tx, job_id, attempt).await? {
                return Ok(note);
            }
            outputs::begin_finalizing(&mut tx, job_id, attempt, self.inner.clock.now()).await?;
            let staged = outputs::staged_files(&mut tx, job_id, attempt).await?;
            tx.commit().await?;
            staged
        };
        let dir = self.inner.data_dir.clone();
        let listed = listed.to_vec();
        #[cfg(test)]
        let hook = self
            .inner
            .publish_hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let (published, missing, staging_removed) = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            if let Some(PublishHook(hook)) = hook {
                hook();
            }
            publish(&dir, job_id, attempt, &listed, &staged)
        })
        .await
        .map_err(|_| StoreError::Corrupt("finalize task"))??;
        self.record_finalization(job_id, attempt, &published, missing, staging_removed)
            .await
    }

    /// Step 3: records the publication (unless a concurrent finalisation of the attempt got there first).
    async fn record_finalization(
        &self,
        job_id: JobId,
        attempt: u32,
        published: &[OutputFile],
        missing: usize,
        staging_removed: bool,
    ) -> Result<Option<String>, StoreError> {
        let note = (missing > 0).then(|| format!("outputs_incomplete: {missing}"));
        let mut tx = store::begin_immediate(&self.inner.db).await?;
        // Another finalisation of the same attempt (a repeated `JobFinished`) may have got here first.
        if let Some(note) = outputs::finalized_note(&mut tx, job_id, attempt).await? {
            return Ok(note);
        }
        outputs::finalize(
            &mut tx,
            job_id,
            attempt,
            published,
            note.as_deref(),
            staging_removed,
            self.inner.clock.now(),
        )
        .await?;
        tx.commit().await?;
        tracing::info!(%job_id, attempt, published = published.len(), missing, "outputs finalised");
        Ok(note)
    }

    /// Whether the attempt began finalising and never finished ([`outputs::begin_finalizing`] ran, `finalized_at` is
    /// not set).
    pub async fn is_interrupted(&self, job_id: JobId, attempt: u32) -> Result<bool, StoreError> {
        let mut conn = self.inner.db.acquire().await?;
        outputs::finalization_interrupted(&mut conn, job_id, attempt).await
    }

    /// Finishes an interrupted finalisation without its list of outputs (that came with `JobFinished` and was not
    /// kept). The files an earlier finalisation already moved into `files/` were listed, so they are published; whatever
    /// is still in `.staging` is discarded, as the staging sweep does for an attempt that never finalised. Used by the
    /// GC. Idempotent; an error (the directories could not be synced) leaves everything as it was, to be retried.
    pub async fn finish_interrupted(&self, job_id: JobId, attempt: u32) -> Result<(), StoreError> {
        let staged = {
            let mut tx = store::begin_immediate(&self.inner.db).await?;
            if outputs::finalized_note(&mut tx, job_id, attempt).await?.is_some() {
                return Ok(());
            }
            outputs::staged_files(&mut tx, job_id, attempt).await?
        };
        let dir = self.inner.data_dir.clone();
        let (published, _, staging_removed) = tokio::task::spawn_blocking(move || {
            let moved: Vec<OutputFile> = staged
                .iter()
                .filter(|f| already_published(&dir, job_id, attempt, f))
                .cloned()
                .collect();
            publish(&dir, job_id, attempt, &moved, &staged)
        })
        .await
        .map_err(|_| StoreError::Corrupt("finalize task"))??;
        self.record_finalization(job_id, attempt, &published, 0, staging_removed)
            .await
            .map(|_| ())
    }
}

impl OutputsFinalizer for OutputStore {
    fn finalize<'a>(&'a self, job_id: JobId, attempt: u32, outputs: &'a [OutputFile]) -> BoxFuture<'a, Option<String>> {
        Box::pin(async move {
            // Every `LogChunk` of the attempt came before its `JobFinished` on the ordered control stream: the log is
            // complete, so it is flushed and fsynced now.
            self.inner.logs.end_attempt(job_id, attempt).await;
            match self.finalize_attempt(job_id, attempt, outputs).await {
                Ok(note) => note,
                Err(e) => {
                    tracing::warn!(error = %e, %job_id, attempt, "cannot finalise outputs");
                    (!outputs.is_empty()).then(|| format!("outputs_incomplete: {}", outputs.len()))
                }
            }
        })
    }
}

/// The lease of an upload header, if it is the job's current lease, accepted or running, on `node_id` (SI-8).
async fn fenced(
    conn: &mut store::Conn,
    node_id: NodeId,
    lease_id: LeaseId,
    epoch: u64,
) -> Result<leases::LeaseRow, Refused> {
    match leases::get(conn, lease_id).await? {
        Some(l)
            if l.node_id == node_id
                && l.epoch == epoch
                && l.is_current()
                && matches!(l.state, LeaseState::Accepted | LeaseState::Running) =>
        {
            Ok(l)
        }
        // This node's lease of the attempt that already reported `JobFinished` (no later lease of the job exists):
        // the execution ended normally, so no `Cancel`; the agent stops uploading for that lease (review P3).
        Some(l)
            if l.node_id == node_id
                && l.epoch == epoch
                && l.state == LeaseState::Finished
                && l.epoch == l.job_epoch =>
        {
            Err(Refused::because(upload_reason::FINALIZED))
        }
        // This node's lease, but not the current one (or an offer it never accepted): fenced, and cancelled.
        Some(l) if l.node_id == node_id => Err(Refused {
            reason: upload_reason::STALE_EPOCH,
            cancel: Some((lease_id, epoch)),
        }),
        // Unknown, or another node's: the same answer, which says nothing about other nodes.
        _ => Err(Refused::because(upload_reason::UNKNOWN_LEASE)),
    }
}

impl Upload {
    /// The job and attempt the upload is for.
    #[must_use]
    pub fn target(&self) -> (JobId, u32) {
        (self.job_id, self.attempt)
    }

    /// Moves this stream's verified file to `.staging/<path>` and records it, in one transaction that first checks
    /// again that the lease is current, the attempt not finalised, the path not staged and the caps held. The move is
    /// `RENAME_NOREPLACE`, so a file already at that path is never replaced. On a refusal only this stream's own file
    /// is removed: its temporary file, or the staged file it placed itself if the transaction then fails.
    async fn commit(&self) -> Result<(), Refused> {
        let mut placed = false;
        let result = async {
            let mut tx = store::begin_immediate(&self.store.inner.db).await?;
            fenced(&mut tx, self.node_id, self.lease_id, self.epoch).await?;
            let uploads = outputs::attempt_uploads(&mut tx, self.job_id, self.attempt).await?;
            if uploads.finalized {
                return Err(Refused::because(upload_reason::FINALIZED));
            }
            if outputs::staged(&mut tx, self.job_id, self.attempt, &self.file.path)
                .await?
                .is_some()
            {
                return Err(Refused::because(upload_reason::DUPLICATE_PATH));
            }
            if uploads.staged_files >= u64::from(MAX_OUTPUT_FILES) {
                return Err(Refused::because(upload_reason::TOO_MANY_FILES));
            }
            if uploads.staged_bytes.saturating_add(self.file.size) > self.max_bytes {
                return Err(Refused::because(upload_reason::TOO_LARGE));
            }
            self.place().await?;
            placed = true;
            let now = self.store.inner.clock.now();
            outputs::stage(&mut tx, self.job_id, self.attempt, self.lease_id, &self.file, now).await?;
            tx.commit().await.map_err(StoreError::from)?;
            Ok(())
        }
        .await;
        if result.is_err() {
            if placed {
                // Placed by this stream, with no row: nobody else can own it (the path is reserved by this stream).
                self.remove_placed().await;
            } else {
                self.remove_temp().await;
            }
        }
        result
    }

    /// `rename(.incoming/<temp>, .staging/<path>)` with `RENAME_NOREPLACE`.
    async fn place(&self) -> Result<(), Refused> {
        let dir = self.store.inner.data_dir.clone();
        let (job_id, attempt) = (self.job_id, self.attempt);
        let (path, temp) = (self.file.path.clone(), self.temp.clone());
        let moved = tokio::task::spawn_blocking(move || {
            let from = incoming_dir(&dir, job_id, attempt, false)?;
            let (to, name) = staging_parent(&dir, job_id, attempt, &path, true)?;
            fsutil::rename_noreplace(&from, &temp, &to, &name)
        })
        .await
        .map_err(std::io::Error::other)
        .and_then(|r| r);
        match moved {
            Ok(()) => Ok(()),
            // Something is already there (a file staged by another upload, or a leftover), or the path runs through
            // a staged file (`a` then `a/b`), or the reverse: nothing is replaced.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::AlreadyExists
                        | std::io::ErrorKind::NotADirectory
                        | std::io::ErrorKind::IsADirectory
                        | std::io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                Err(Refused::because(upload_reason::DUPLICATE_PATH))
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot move an upload into staging");
                Err(Refused::because(upload_reason::INTERNAL))
            }
        }
    }

    /// Removes this stream's temporary file (missing is fine).
    async fn remove_temp(&self) {
        let dir = self.store.inner.data_dir.clone();
        let (job_id, attempt, temp) = (self.job_id, self.attempt, self.temp.clone());
        let _ = tokio::task::spawn_blocking(move || {
            let d = incoming_dir(&dir, job_id, attempt, false)?;
            fsutil::unlink(&d, &temp)
        })
        .await;
    }

    /// Removes this stream's temporary file and, if that left it empty, the attempt's `.incoming`. Used when the attempt
    /// turns out to be finalised: finalisation already removed the staging directories, so a directory recreated for
    /// this stream would stay until the job expires. Another refused stream does the same with its own file, so the last
    /// one out removes it.
    async fn remove_temp_and_incoming(&self) {
        let dir = self.store.inner.data_dir.clone();
        let (job_id, attempt, temp) = (self.job_id, self.attempt, self.temp.clone());
        let _ = tokio::task::spawn_blocking(move || {
            let d = incoming_dir(&dir, job_id, attempt, false)?;
            fsutil::unlink(&d, &temp)?;
            drop(d);
            let (job, attempt) = (job_id.to_string(), attempt.to_string());
            let parent = fsutil::open_dir(&dir, [ARTIFACTS_DIR, job.as_str(), attempt.as_str()], false)?;
            fsutil::remove_dir_if_empty(&parent, INCOMING_DIR)
        })
        .await;
    }

    /// Why creating the temporary file failed. `NotFound` can mean a refused stream of a finalised attempt removed the
    /// empty `.incoming` between this stream's `open_dir` and `create_new`: re-check the mark, and refuse as finalised
    /// when it is set (nothing is left on disk). Anything else is the server's.
    async fn refusal_for_create_error(&self, e: &std::io::Error) -> Refused {
        if e.kind() == std::io::ErrorKind::NotFound && matches!(self.attempt_closed().await, Ok(true)) {
            Refused::because(upload_reason::FINALIZED)
        } else {
            Refused::because(upload_reason::INTERNAL)
        }
    }

    /// Whether the attempt began finalising: from then on it takes no upload.
    async fn attempt_closed(&self) -> Result<bool, StoreError> {
        let mut conn = self.store.inner.db.acquire().await?;
        Ok(outputs::attempt_uploads(&mut conn, self.job_id, self.attempt)
            .await?
            .finalized)
    }

    /// Removes the staged file this stream placed itself, when its transaction failed after the move.
    async fn remove_placed(&self) {
        let dir = self.store.inner.data_dir.clone();
        let (job_id, attempt) = (self.job_id, self.attempt);
        let path = self.file.path.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let (parent, name) = staging_parent(&dir, job_id, attempt, &path, false)?;
            fsutil::unlink(&parent, &name)
        })
        .await;
    }
}

/// Opens (creating it if asked) an attempt's `.incoming` directory.
fn incoming_dir(dir: &Path, job_id: JobId, attempt: u32, create: bool) -> std::io::Result<std::os::fd::OwnedFd> {
    let job = job_id.to_string();
    let attempt = attempt.to_string();
    fsutil::open_dir(
        dir,
        [ARTIFACTS_DIR, job.as_str(), attempt.as_str(), INCOMING_DIR],
        create,
    )
}

/// Opens (creating it if asked) the staging directory that holds `path`, and returns it with the file name.
fn staging_parent(
    dir: &Path,
    job_id: JobId,
    attempt: u32,
    path: &str,
    create: bool,
) -> std::io::Result<(std::os::fd::OwnedFd, String)> {
    let job = job_id.to_string();
    let attempt = attempt.to_string();
    let segments: Vec<&str> = path.split('/').collect();
    let (name, parents) = segments.split_last().ok_or(std::io::ErrorKind::InvalidInput)?;
    let base = [ARTIFACTS_DIR, job.as_str(), attempt.as_str(), STAGING_DIR];
    let d = fsutil::open_dir(dir, base.into_iter().chain(parents.iter().copied()), create)?;
    Ok((d, (*name).to_string()))
}

/// Receives the bytes of `upload` from `body` into this stream's own temporary file: exactly `size` bytes, then the
/// end of the stream, within the limits (`idle` between reads; after `grace`, at least `min_rate` bytes per second).
/// Hashes them as they are written, fsyncs, then commits (which moves the file into staging). On any failure only
/// this stream's own file is removed.
pub async fn receive<R: AsyncRead + Unpin>(
    upload: &Upload,
    body: &mut R,
    limits: &UploadLimits,
) -> Result<(), Refused> {
    let dir = upload.store.inner.data_dir.clone();
    let (job_id, attempt, temp) = (upload.job_id, upload.attempt, upload.temp.clone());
    let opened = tokio::task::spawn_blocking(move || {
        let d = incoming_dir(&dir, job_id, attempt, true)?;
        fsutil::create_new(&d, &temp)
    })
    .await
    .map_err(std::io::Error::other)
    .and_then(|r| r);
    let file = match opened {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "cannot create an upload's temporary file");
            return Err(upload.refusal_for_create_error(&e).await);
        }
    };
    // The attempt may have been finalised after `begin` checked, and finalisation removed `.incoming` before it was
    // recreated just now. Finalisation marks the attempt before it removes anything, so a check made after this
    // stream created its directory either sees the mark (and this stream cleans up) or runs before it (and the removal
    // is still to come, and takes the directory with it).
    match upload.attempt_closed().await {
        Ok(false) => {}
        Ok(true) => {
            drop(file);
            upload.remove_temp_and_incoming().await;
            return Err(Refused::because(upload_reason::FINALIZED));
        }
        Err(e) => {
            tracing::warn!(error = %e, "cannot check whether an attempt is finalised");
            drop(file);
            upload.remove_temp().await;
            return Err(Refused::because(upload_reason::INTERNAL));
        }
    }
    let result = copy(upload, tokio::fs::File::from_std(file), body, limits).await;
    match result {
        Ok(()) => upload.commit().await,
        Err(r) => {
            upload.remove_temp().await;
            Err(r)
        }
    }
}

async fn copy<R: AsyncRead + Unpin>(
    upload: &Upload,
    mut out: tokio::fs::File,
    body: &mut R,
    limits: &UploadLimits,
) -> Result<(), Refused> {
    let size = upload.file.size;
    let start = tokio::time::Instant::now();
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match tokio::time::timeout(limits.idle, body.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return Err(Refused::because(upload_reason::SIZE_MISMATCH)),
            Err(_) => return Err(Refused::because(upload_reason::TIMEOUT)),
        };
        if n == 0 {
            break;
        }
        received = received.saturating_add(n as u64);
        // A long stream: refused as soon as it passes `size`, before the extra bytes are written.
        if received > size {
            return Err(Refused::because(upload_reason::SIZE_MISMATCH));
        }
        hasher.update(&buf[..n]);
        if out.write_all(&buf[..n]).await.is_err() {
            return Err(Refused::because(upload_reason::INTERNAL));
        }
        if too_slow(received, start.elapsed(), limits) {
            return Err(Refused::because(upload_reason::TIMEOUT));
        }
    }
    if received != size {
        return Err(Refused::because(upload_reason::SIZE_MISMATCH));
    }
    if Sha256Digest(hasher.finalize().into()) != upload.file.sha256 {
        return Err(Refused::because(upload_reason::SHA256_MISMATCH));
    }
    if out.flush().await.is_err() || out.sync_all().await.is_err() {
        return Err(Refused::because(upload_reason::INTERNAL));
    }
    Ok(())
}

/// Whether a stream that received `received` bytes in `elapsed` is below the minimum rate: after `grace`, it must
/// have averaged `min_rate` bytes per second since the grace ended.
fn too_slow(received: u64, elapsed: Duration, limits: &UploadLimits) -> bool {
    elapsed
        .checked_sub(limits.grace)
        .is_some_and(|past| u128::from(received) < u128::from(limits.min_rate) * past.as_millis() / 1000)
}

/// Moves the listed files that are staged with the same size and sha256 to `files/`, fsyncs the directories that got
/// them, deletes every other staged file and the staging directories. Returns the published files, how many listed
/// ones were left out, and whether the staging directories are gone (if not, the GC sweeps them). An error only if
/// the directories could not be synced.
///
/// A staged file that is no longer in `.staging` but is in `files/` with its size was moved by an earlier
/// finalisation that crashed before its commit (review P3): it is published.
fn publish(
    dir: &Path,
    job_id: JobId,
    attempt: u32,
    listed: &[OutputFile],
    staged: &[OutputFile],
) -> std::io::Result<(Vec<OutputFile>, usize, bool)> {
    let staged: HashMap<&str, &OutputFile> = staged.iter().map(|f| (f.path.as_str(), f)).collect();
    let mut seen = HashSet::new();
    let mut published = Vec::new();
    let mut missing = 0;
    for want in listed {
        if !seen.insert(want.path.as_str()) {
            continue;
        }
        match staged.get(want.path.as_str()) {
            Some(have) if have.size == want.size && have.sha256 == want.sha256 => {
                match move_to_files(dir, job_id, attempt, &want.path) {
                    Ok(()) => published.push(want.clone()),
                    Err(e)
                        if e.kind() == std::io::ErrorKind::NotFound
                            && already_published(dir, job_id, attempt, want) =>
                    {
                        published.push(want.clone());
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, %job_id, attempt, "cannot publish a staged output");
                        missing += 1;
                    }
                }
            }
            _ => missing += 1,
        }
    }
    // The renames reach the disk, one fsync per directory, before the caller records anything in the database: a
    // published row must never name a file that a crash could take back. On a failure nothing is recorded and the
    // staging is not touched, but the attempt is NOT retried by itself: the caller reports `outputs_incomplete` and the
    // scheduler ends the job anyway. It is finalised again only if `JobFinished` is delivered again, or else by the
    // GC's staging sweep ([`OutputStore::finish_interrupted`]) an hour after its lease ended.
    sync_dirs(
        dir,
        &dirs_to_sync(job_id, attempt, published.iter().map(|f| f.path.as_str())),
    )?;
    // Whatever is left in staging (unlisted, mismatched, or a partial file) goes.
    let removed = match remove_staging_dirs(dir, job_id, attempt) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %e, %job_id, attempt, "cannot remove the staging directories; the GC will");
            false
        }
    };
    Ok((published, missing, removed))
}

/// The directories that got an entry when `paths` were published into `files/` of an attempt, as segments below the
/// data dir: the data dir itself (no segments; `artifacts/` may have been created since the data dir was last synced,
/// by the first upload or by this publication, and that entry must survive a crash too), then `artifacts/` down to the parent of every file. Each appears
/// once, however many files it holds, in path order (parents first). With no file published there is nothing to sync.
fn dirs_to_sync<'a>(
    job_id: JobId,
    attempt: u32,
    paths: impl Iterator<Item = &'a str>,
) -> std::collections::BTreeSet<Vec<String>> {
    let mut dirs = std::collections::BTreeSet::new();
    for path in paths {
        let mut dir = vec![
            ARTIFACTS_DIR.to_string(),
            job_id.to_string(),
            attempt.to_string(),
            FILES_DIR.to_string(),
        ];
        dirs.insert(Vec::new());
        dirs.insert(vec![ARTIFACTS_DIR.to_string()]);
        dirs.insert(dir[..2].to_vec());
        dirs.insert(dir[..3].to_vec());
        dirs.insert(dir.clone());
        let segments: Vec<&str> = path.split('/').collect();
        for segment in &segments[..segments.len().saturating_sub(1)] {
            dir.push((*segment).to_string());
            dirs.insert(dir.clone());
        }
    }
    dirs
}

/// fsyncs each of `dirs` (below `base`, no link followed), so the renames into them survive a crash.
fn sync_dirs(base: &Path, dirs: &std::collections::BTreeSet<Vec<String>>) -> std::io::Result<()> {
    for dir in dirs {
        let fd = fsutil::open_dir(base, dir.iter().map(String::as_str), false)?;
        fsutil::fsync(&fd)?;
    }
    Ok(())
}

/// Removes `.staging` and `.incoming` of an attempt (both are tried; the first error is returned). No link is
/// followed, in the directories or in front of them.
fn remove_staging_dirs(dir: &Path, job_id: JobId, attempt: u32) -> std::io::Result<()> {
    let job = job_id.to_string();
    let attempt = attempt.to_string();
    let mut first = Ok(());
    for sub in [STAGING_DIR, INCOMING_DIR] {
        if let Err(e) = fsutil::remove_tree(dir, &[ARTIFACTS_DIR, job.as_str(), attempt.as_str(), sub])
            && first.is_ok()
        {
            first = Err(e);
        }
    }
    first
}

/// Whether `files/<path>` of the attempt is a regular file with exactly this size and sha256, reached without a link.
/// The size alone is not enough: a damaged or foreign file of the same length would be published as the node's output.
fn already_published(dir: &Path, job_id: JobId, attempt: u32, file: &OutputFile) -> bool {
    let job = job_id.to_string();
    let attempt = attempt.to_string();
    let segments: Vec<&str> = file.path.split('/').collect();
    let Some((name, parents)) = segments.split_last() else {
        return false;
    };
    let base = [ARTIFACTS_DIR, job.as_str(), attempt.as_str(), FILES_DIR];
    let Ok(mut f) = fsutil::open_dir(dir, base.into_iter().chain(parents.iter().copied()), false)
        .and_then(|d| fsutil::open_read(&d, name))
    else {
        return false;
    };
    if f.metadata().map_or(true, |m| m.len() != file.size) {
        return false;
    }
    sha256_of_exactly(&mut f, file.size).is_some_and(|d| d == file.sha256)
}

/// The sha256 of the first `size` bytes of `r`, or `None` when it has fewer or a read fails. At most `size` bytes are
/// read, so a file that grows meanwhile cannot make this run on. An interrupted read is retried: it says nothing about
/// the content.
fn sha256_of_exactly(r: &mut impl std::io::Read, size: u64) -> Option<Sha256Digest> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut left = size;
    while left > 0 {
        let want = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
        match r.read(&mut buf[..want]) {
            Ok(0) => return None,
            Ok(n) => {
                hasher.update(&buf[..n]);
                left -= n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some(Sha256Digest(hasher.finalize().into()))
}

fn move_to_files(dir: &Path, job_id: JobId, attempt: u32, path: &str) -> std::io::Result<()> {
    let (from, name) = staging_parent(dir, job_id, attempt, path, false)?;
    let job = job_id.to_string();
    let attempt = attempt.to_string();
    let segments: Vec<&str> = path.split('/').collect();
    let parents = &segments[..segments.len() - 1];
    let base = [ARTIFACTS_DIR, job.as_str(), attempt.as_str(), FILES_DIR];
    let to = fsutil::open_dir(dir, base.into_iter().chain(parents.iter().copied()), true)?;
    fsutil::rename(&from, &name, &to, &name)
}

#[cfg(test)]
mod tests;
