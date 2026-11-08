// SPDX-License-Identifier: AGPL-3.0-only

//! Uploads, finalisation and opening published files, against the scheduler's fixture (a real database with jobs,
//! nodes and fenced leases) and in-memory streams.

use std::os::unix::fs::symlink;

use p2pc_proto::api::JobStatus;
use p2pc_proto::protocol::Outcome;

use super::*;
use crate::scheduler::tests::{Clean as _, Fx};

struct T {
    fx: Fx,
    dir: tempfile::TempDir,
    store: OutputStore,
}

async fn setup() -> T {
    let fx = Fx::new().await;
    let dir = tempfile::tempdir().unwrap();
    let logs = LogStore::new(dir.path());
    let store = OutputStore::new(dir.path(), fx.db.clone(), fx.clock.clone(), logs);
    T { fx, dir, store }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn header(lease: LeaseId, epoch: u64, path: &str, bytes: &[u8]) -> UploadHeader {
    UploadHeader {
        lease_id: lease,
        epoch,
        path: path.into(),
        size: bytes.len() as u64,
        sha256: digest(bytes),
    }
}

fn file(path: &str, bytes: &[u8]) -> OutputFile {
    OutputFile {
        path: path.into(),
        size: bytes.len() as u64,
        sha256: digest(bytes),
    }
}

/// Begins an upload with `header` and streams `body`. `Ok(true)` when staged now, `Ok(false)` when it already was.
async fn upload(t: &T, node: NodeId, header: &UploadHeader, mut body: &[u8]) -> Result<bool, &'static str> {
    match t.store.begin(node, header, &UploadLimits::default()).await {
        Ok(Begun::Receive(u)) => receive(&u, &mut body, &UploadLimits::default())
            .await
            .map(|()| true)
            .map_err(|r| r.reason),
        Ok(Begun::AlreadyStaged) => Ok(false),
        Err(r) => Err(r.reason),
    }
}

impl T {
    fn staging(&self, job: JobId, path: &str) -> PathBuf {
        self.store.staging_dir(job, 1).join(path)
    }

    fn published(&self, job: JobId, path: &str) -> PathBuf {
        self.store.files_dir(job, 1).join(path)
    }

    async fn staged_count(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM output_staging")
            .fetch_one(&self.fx.db)
            .await
            .unwrap()
    }

    async fn published_rows(&self, job: JobId) -> Vec<(String, i64)> {
        sqlx::query_as("SELECT path, size FROM job_outputs WHERE job_id = ? ORDER BY path")
            .bind(job.to_string())
            .fetch_all(&self.fx.db)
            .await
            .unwrap()
    }

    /// A running job (attempt 1) with `outputs.max_mb`, on a node of its own (sized for exactly one job).
    async fn running(&self, max_mb: u64) -> (JobId, NodeId, LeaseId, u64) {
        self.fx.node(1.0, 256, 0).await;
        let job = self
            .fx
            .job_with(serde_json::json!({
                "image": "docker.io/library/python:3.12-slim",
                "command": ["true"],
                "resources": {"cpu": 1, "memory_mb": 256},
                "outputs": {"max_mb": max_mb},
            }))
            .await;
        let (node, lease, epoch) = self.fx.running(job).await;
        (job, node, lease, epoch)
    }
}

#[tokio::test]
async fn a_good_upload_is_staged_then_published_by_finalize() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    let body = b"hello outputs\n";
    assert_eq!(
        upload(&t, node, &header(lease, epoch, "results/a.txt", body), body).await,
        Ok(true)
    );
    assert_eq!(std::fs::read(t.staging(job, "results/a.txt")).unwrap(), body);
    assert_eq!(t.staged_count().await, 1);
    assert_eq!(t.store.uploads_in_progress(), 0, "the reservation is released");
    let note = t.store.finalize(job, 1, &[file("results/a.txt", body)]).await;
    assert_eq!(note, None);
    assert_eq!(std::fs::read(t.published(job, "results/a.txt")).unwrap(), body);
    assert!(!t.store.staging_dir(job, 1).exists(), "staging is gone");
    assert_eq!(
        t.published_rows(job).await,
        vec![("results/a.txt".into(), body.len() as i64)]
    );
    let (mut f, size) = t.store.open_published(job, 1, "results/a.txt").await.unwrap();
    let mut back = Vec::new();
    std::io::Read::read_to_end(&mut f, &mut back).unwrap();
    assert_eq!((back.as_slice(), size), (&body[..], body.len() as u64));
}

#[tokio::test]
async fn a_wrong_sha256_or_size_removes_the_partial_file() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    let mut h = header(lease, epoch, "a.bin", b"right");
    h.sha256 = digest(b"wrong");
    assert_eq!(
        upload(&t, node, &h, b"right").await,
        Err(upload_reason::SHA256_MISMATCH)
    );
    // Short: fewer bytes than announced, then the end of the stream.
    let h = header(lease, epoch, "short.bin", b"0123456789");
    assert_eq!(upload(&t, node, &h, b"01234").await, Err(upload_reason::SIZE_MISMATCH));
    // Long: more bytes than announced.
    let h = header(lease, epoch, "long.bin", b"0123");
    assert_eq!(
        upload(&t, node, &h, b"0123456789").await,
        Err(upload_reason::SIZE_MISMATCH)
    );
    for p in ["a.bin", "short.bin", "long.bin"] {
        assert!(!t.staging(job, p).exists(), "{p} left behind");
    }
    assert_eq!(t.staged_count().await, 0);
    assert_eq!(t.store.uploads_in_progress(), 0);
}

#[tokio::test]
async fn sizes_are_capped_by_outputs_max_mb_across_the_attempt() {
    let t = setup().await;
    let (_job, node, lease, epoch) = t.running(1).await;
    let mut big = header(lease, epoch, "big.bin", b"");
    big.size = 1024 * 1024 + 1;
    assert_eq!(upload(&t, node, &big, b"").await, Err(upload_reason::TOO_LARGE));
    let half = vec![7u8; 600 * 1024];
    assert_eq!(
        upload(&t, node, &header(lease, epoch, "one.bin", &half), &half).await,
        Ok(true)
    );
    // What is left is under 600 KiB now.
    assert_eq!(
        upload(&t, node, &header(lease, epoch, "two.bin", &half), &half).await,
        Err(upload_reason::TOO_LARGE)
    );
}

#[tokio::test]
async fn a_path_is_uploaded_once_and_an_identical_retry_is_acknowledged() {
    let t = setup().await;
    let (_job, node, lease, epoch) = t.running(1).await;
    let h = header(lease, epoch, "a.txt", b"one");
    assert_eq!(upload(&t, node, &h, b"one").await, Ok(true));
    // The same content again (a retry after a lost ack): acknowledged, nothing received.
    assert_eq!(upload(&t, node, &h, b"").await, Ok(false));
    assert_eq!(
        upload(&t, node, &header(lease, epoch, "a.txt", b"two"), b"two").await,
        Err(upload_reason::DUPLICATE_PATH)
    );
    // A path through a staged file.
    assert_eq!(
        upload(&t, node, &header(lease, epoch, "a.txt/b", b"x"), b"x").await,
        Err(upload_reason::DUPLICATE_PATH)
    );
    // Two streams for one path at once: the second is refused while the first is in flight.
    let h = header(lease, epoch, "b.txt", b"b");
    let Ok(Begun::Receive(first)) = t.store.begin(node, &h, &UploadLimits::default()).await else {
        panic!("first upload refused");
    };
    assert_eq!(
        t.store
            .begin(node, &h, &UploadLimits::default())
            .await
            .unwrap_err()
            .reason,
        upload_reason::DUPLICATE_PATH
    );
    drop(first);
}

/// SI-9 on upload: traversal, absolute paths, `.` segments, NUL and backslashes are refused before anything is
/// written.
#[tokio::test]
async fn si9_traversal_is_refused_on_upload() {
    let t = setup().await;
    let (_job, node, lease, epoch) = t.running(1).await;
    for bad in [
        "../escape",
        "a/../../escape",
        "/etc/passwd",
        "./a",
        "a//b",
        "a/\0b",
        "a\\b",
        "",
        ".",
    ] {
        let h = header(lease, epoch, bad, b"x");
        assert_eq!(
            upload(&t, node, &h, b"x").await,
            Err(upload_reason::INVALID_PATH),
            "{bad:?}"
        );
    }
    assert!(!t.dir.path().join("escape").exists());
    assert_eq!(t.staged_count().await, 0);
}

/// SI-8 on upload: a stale epoch is refused and the node is told to cancel; another node's lease is unknown.
#[tokio::test]
async fn si8_a_stale_epoch_is_refused_with_cancel() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    let refused = t
        .store
        .begin(node, &header(lease, epoch + 1, "a", b"x"), &UploadLimits::default())
        .await
        .unwrap_err();
    assert_eq!(refused.reason, upload_reason::STALE_EPOCH);
    assert_eq!(refused.cancel, Some((lease, epoch + 1)));
    // Another node presents this node's lease: unknown, and no cancel for a lease it does not hold.
    let other = t.fx.node(4.0, 4096, 0).await;
    let refused = t
        .store
        .begin(other, &header(lease, epoch, "a", b"x"), &UploadLimits::default())
        .await
        .unwrap_err();
    assert_eq!((refused.reason, refused.cancel), (upload_reason::UNKNOWN_LEASE, None));
    // The job finishes: its lease takes no more uploads (see the next test for the answer).
    t.fx.finish(node, lease, epoch, Outcome::Exited, Some(0)).await;
    assert_eq!(t.fx.status(job).await, JobStatus::Succeeded);
    let refused = t
        .store
        .begin(node, &header(lease, epoch, "late", b"x"), &UploadLimits::default())
        .await
        .unwrap_err();
    assert_eq!(refused.reason, upload_reason::FINALIZED);
}

/// Review P3: an upload for this node's lease of the current attempt that already reported `JobFinished` gets
/// `finalized` and no `Cancel` (the execution ended normally; the agent stops uploading for that lease). A lease that
/// was replaced (lost, then requeued) is still fenced with `stale_epoch` and `Cancel`.
#[tokio::test]
async fn an_upload_after_job_finished_gets_finalized_without_cancel() {
    let t = setup().await;
    let limits = UploadLimits::default();
    let (job, node, lease, epoch) = t.running(1).await;
    t.fx.finish(node, lease, epoch, Outcome::Exited, Some(0)).await;
    assert_eq!(t.fx.status(job).await, JobStatus::Succeeded);
    let refused = t
        .store
        .begin(node, &header(lease, epoch, "late.txt", b"x"), &limits)
        .await
        .unwrap_err();
    assert_eq!((refused.reason, refused.cancel), (upload_reason::FINALIZED, None));
    assert_eq!(t.store.uploads_in_progress(), 0);
    // The node's lease of a job that was requeued after node loss: stale, and cancelled.
    let (job2, node2, lease2, epoch2) = t.running(1).await;
    t.fx.node_went_offline(node2, t.fx.now()).await;
    t.fx.advance(61);
    t.fx.sched.tick().await.clean();
    assert_eq!(t.fx.status(job2).await, JobStatus::Queued);
    let refused = t
        .store
        .begin(node2, &header(lease2, epoch2, "late.txt", b"x"), &limits)
        .await
        .unwrap_err();
    assert_eq!(
        (refused.reason, refused.cancel),
        (upload_reason::STALE_EPOCH, Some((lease2, epoch2)))
    );
}

#[tokio::test]
async fn uploads_are_capped_per_node_and_in_total() {
    let t = setup().await;
    let (_j1, node, lease, epoch) = t.running(1).await;
    let limits = UploadLimits {
        per_node: 2,
        total: 3,
        ..UploadLimits::default()
    };
    let begin = |path: &'static str, node, lease, epoch| {
        let h = header(lease, epoch, path, b"x");
        let store = t.store.clone();
        async move { store.begin(node, &h, &limits).await }
    };
    let a = begin("a", node, lease, epoch).await.unwrap();
    let b = begin("b", node, lease, epoch).await.unwrap();
    assert_eq!(
        begin("c", node, lease, epoch).await.unwrap_err().reason,
        upload_reason::TOO_MANY_UPLOADS
    );
    // A second node gets the last slot in total, then the cap is reached for everyone.
    let (_j2, node2, lease2, epoch2) = t.running(1).await;
    assert_ne!(node2, node, "the fixture places the second job on a new node");
    let c = begin("c", node2, lease2, epoch2).await.unwrap();
    assert_eq!(
        begin("d", node2, lease2, epoch2).await.unwrap_err().reason,
        upload_reason::TOO_MANY_UPLOADS
    );
    drop((a, b, c));
    assert_eq!(t.store.uploads_in_progress(), 0);
    assert!(begin("d", node2, lease2, epoch2).await.is_ok());
}

/// Review P3: a crash between finalisation's renames and its commit leaves the staged rows and the files already in
/// `files/`. The next `JobFinished` publishes such a file (in `files/`, with the right size) instead of calling it
/// missing; one with the wrong size is still left out.
#[tokio::test]
async fn finalize_after_a_crash_counts_files_already_moved_as_published() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    for (path, body) in [("moved.txt", &b"moved"[..]), ("short.txt", b"full length")] {
        assert_eq!(
            upload(&t, node, &header(lease, epoch, path, body), body).await,
            Ok(true)
        );
    }
    // The crash: both files were renamed into `files/`, nothing was committed; one was then damaged.
    std::fs::create_dir_all(t.store.files_dir(job, 1)).unwrap();
    for path in ["moved.txt", "short.txt"] {
        std::fs::rename(t.staging(job, path), t.published(job, path)).unwrap();
    }
    std::fs::write(t.published(job, "short.txt"), b"cut").unwrap();
    let note = t
        .store
        .finalize(
            job,
            1,
            &[file("moved.txt", b"moved"), file("short.txt", b"full length")],
        )
        .await;
    assert_eq!(note.as_deref(), Some("outputs_incomplete: 1"));
    assert_eq!(t.published_rows(job).await, vec![("moved.txt".into(), 5)]);
}

/// T10g item 4: a file in `files/` counts as published only if its sha256 matches too, not just its size. Same size,
/// other content (a damaged or foreign file): left out, for both the `JobFinished` path and the GC's.
#[tokio::test]
async fn a_file_in_files_with_the_right_size_but_other_content_is_not_published() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    for (path, body) in [("good.txt", &b"good"[..]), ("swapped.txt", b"abcd")] {
        assert_eq!(
            upload(&t, node, &header(lease, epoch, path, body), body).await,
            Ok(true)
        );
    }
    std::fs::create_dir_all(t.store.files_dir(job, 1)).unwrap();
    for path in ["good.txt", "swapped.txt"] {
        std::fs::rename(t.staging(job, path), t.published(job, path)).unwrap();
    }
    // Same length as the staged `abcd`, other bytes.
    std::fs::write(t.published(job, "swapped.txt"), b"wxyz").unwrap();
    let note = t
        .store
        .finalize(job, 1, &[file("good.txt", b"good"), file("swapped.txt", b"abcd")])
        .await;
    assert_eq!(note.as_deref(), Some("outputs_incomplete: 1"));
    assert_eq!(t.published_rows(job).await, vec![("good.txt".into(), 4)]);
}

/// A reader that is interrupted once, then serves `bytes` (T10g review P3 1).
struct InterruptedOnce<'a> {
    bytes: &'a [u8],
    interrupted: bool,
}

impl std::io::Read for InterruptedOnce<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        std::io::Read::read(&mut self.bytes, buf)
    }
}

/// An interrupted read is retried, not taken for a wrong content; a short file or a real error still is.
#[test]
fn hashing_an_output_retries_an_interrupted_read() {
    let body = b"good bytes";
    let mut r = InterruptedOnce {
        bytes: body,
        interrupted: false,
    };
    assert_eq!(sha256_of_exactly(&mut r, body.len() as u64), Some(digest(body)));
    // Fewer bytes than `size`: not the file that was listed.
    assert_eq!(sha256_of_exactly(&mut &body[..], body.len() as u64 + 1), None);
    // Only `size` bytes are read, however much the file has.
    assert_eq!(sha256_of_exactly(&mut &body[..], 4), Some(digest(&body[..4])));
}

/// The same check on the GC's path ([`OutputStore::finish_interrupted`]), which has no list from `JobFinished`.
#[tokio::test]
async fn finishing_an_interrupted_attempt_checks_the_content_of_files_already_moved() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    for (path, body) in [("good.txt", &b"good"[..]), ("swapped.txt", b"abcd")] {
        assert_eq!(
            upload(&t, node, &header(lease, epoch, path, body), body).await,
            Ok(true)
        );
    }
    let mut tx = store::begin_immediate(&t.fx.db).await.unwrap();
    outputs::begin_finalizing(&mut tx, job, 1, t.fx.clock.now())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    std::fs::create_dir_all(t.store.files_dir(job, 1)).unwrap();
    for path in ["good.txt", "swapped.txt"] {
        std::fs::rename(t.staging(job, path), t.published(job, path)).unwrap();
    }
    std::fs::write(t.published(job, "swapped.txt"), b"wxyz").unwrap();
    t.store.finish_interrupted(job, 1).await.unwrap();
    assert_eq!(t.published_rows(job).await, vec![("good.txt".into(), 4)]);
}

/// T10g item 3: an upload that passed `begin` before finalisation removed the staging directories must not leave an
/// empty `.incoming` behind when it then opens its temporary file. It is refused as finalised, with nothing left that
/// only the job's expiry would remove.
#[tokio::test]
async fn an_upload_that_began_before_finalisation_leaves_no_incoming_directory() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    let body = b"late bytes";
    let limits = UploadLimits::default();
    let Ok(Begun::Receive(late)) = t
        .store
        .begin(node, &header(lease, epoch, "late.txt", body), &limits)
        .await
    else {
        panic!("the upload should begin");
    };
    // Finalisation runs to the end, and removes the staging directories, before the bytes are received.
    assert_eq!(t.store.finalize(job, 1, &[]).await, None);
    assert!(!t.store.incoming_dir(job, 1).exists());
    let mut stream = &body[..];
    let refused = receive(&late, &mut stream, &limits).await.unwrap_err();
    assert_eq!(refused.reason, upload_reason::FINALIZED);
    assert!(
        !t.store.incoming_dir(job, 1).exists(),
        "an empty .incoming was recreated after finalisation"
    );
    assert!(!t.store.staging_dir(job, 1).exists());
    assert_eq!(t.staged_count().await, 0);
}

/// T10g item 3(a): a stream whose `.incoming` was removed under it by a refused stream of a finalised attempt (its
/// `create_new` fails with `NotFound`) is refused as finalised, not as an internal error.
#[tokio::test]
async fn a_temp_file_that_cannot_be_created_because_the_attempt_was_finalised_is_refused_as_finalised() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    let limits = UploadLimits::default();
    let Ok(Begun::Receive(late)) = t
        .store
        .begin(node, &header(lease, epoch, "late.txt", b"x"), &limits)
        .await
    else {
        panic!("the upload should begin");
    };
    let not_found = std::io::Error::from(std::io::ErrorKind::NotFound);
    // Not finalised: the failure is the server's.
    assert_eq!(
        late.refusal_for_create_error(&not_found).await.reason,
        upload_reason::INTERNAL
    );
    assert_eq!(t.store.finalize(job, 1, &[]).await, None);
    assert_eq!(
        late.refusal_for_create_error(&not_found).await.reason,
        upload_reason::FINALIZED
    );
    // Another kind of error stays internal, finalised or not.
    let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        late.refusal_for_create_error(&denied).await.reason,
        upload_reason::INTERNAL
    );
}

/// T10g item 3(b): a database error while checking whether the attempt is finalised refuses the stream as internal and
/// leaves no temporary file behind.
#[tokio::test]
async fn a_database_error_while_checking_the_attempt_refuses_the_upload_and_removes_the_temp_file() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    let limits = UploadLimits::default();
    let body = b"bytes";
    let Ok(Begun::Receive(u)) = t.store.begin(node, &header(lease, epoch, "a.txt", body), &limits).await else {
        panic!("the upload should begin");
    };
    t.fx.db.close().await;
    let mut stream = &body[..];
    let refused = receive(&u, &mut stream, &limits).await.unwrap_err();
    assert_eq!(refused.reason, upload_reason::INTERNAL);
    let left: Vec<_> = std::fs::read_dir(t.store.incoming_dir(job, 1)).unwrap().collect();
    assert!(left.is_empty(), "the temporary file was left behind: {left:?}");
}

#[tokio::test]
async fn finalize_publishes_listed_files_drops_the_rest_and_notes_what_is_missing() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    for (path, body) in [
        ("keep.txt", &b"keep"[..]),
        ("unlisted.txt", b"drop"),
        ("changed.txt", b"v1"),
    ] {
        assert_eq!(
            upload(&t, node, &header(lease, epoch, path, body), body).await,
            Ok(true)
        );
    }
    let listed = [
        file("keep.txt", b"keep"),
        // Listed with other content than what was staged: left out.
        file("changed.txt", b"v2"),
        // Listed, never uploaded: left out.
        file("never.txt", b"?"),
    ];
    let note = t.store.finalize(job, 1, &listed).await;
    assert_eq!(note.as_deref(), Some("outputs_incomplete: 2"));
    assert_eq!(t.published_rows(job).await, vec![("keep.txt".into(), 4)]);
    assert!(t.published(job, "keep.txt").exists());
    for gone in ["unlisted.txt", "changed.txt"] {
        assert!(!t.published(job, gone).exists());
        assert!(!t.staging(job, gone).exists());
    }
    assert_eq!(t.staged_count().await, 0);
    // Idempotent: a second `JobFinished` changes nothing and gets the same note.
    assert_eq!(
        t.store.finalize(job, 1, &[]).await.as_deref(),
        Some("outputs_incomplete: 2")
    );
    assert_eq!(t.published_rows(job).await.len(), 1);
    // And no upload is taken for a finalised attempt.
    assert_eq!(
        upload(&t, node, &header(lease, epoch, "after.txt", b"x"), b"x").await,
        Err(upload_reason::FINALIZED)
    );
}

#[tokio::test]
async fn finalize_through_the_scheduler_sets_the_note_without_changing_the_outcome() {
    let t = setup().await;
    let fx = &t.fx;
    let sched = Scheduler::from_parts(
        fx.db.clone(),
        fx.clock.clone(),
        crate::scheduler::tests::timing(),
        crate::scheduler::Kick::default(),
        fx.link.clone(),
        Arc::new(crate::scheduler::DropLogs),
        Arc::new(t.store.clone()),
    );
    fx.node(1.0, 256, 0).await;
    let job = fx.job(1.0, 256, 0).await;
    sched.tick().await.clean();
    let (lease, node, epoch): (String, String, i64) =
        sqlx::query_as("SELECT id, node_id, epoch FROM leases WHERE job_id = ?")
            .bind(job.to_string())
            .fetch_one(&fx.db)
            .await
            .unwrap();
    let (lease, node, epoch): (LeaseId, NodeId, u64) =
        (lease.parse().unwrap(), node.parse().unwrap(), epoch.try_into().unwrap());
    sched
        .on_agent_message(
            node,
            p2pc_proto::protocol::AgentMsg::LeaseAccepted { lease_id: lease, epoch },
        )
        .await
        .unwrap();
    let mut msg = crate::scheduler::tests::finished(lease, epoch, Outcome::Exited, Some(0));
    if let p2pc_proto::protocol::AgentMsg::JobFinished { outputs, .. } = &mut msg {
        outputs.push(file("missing.txt", b"m"));
    }
    sched.on_agent_message(node, msg).await.unwrap();
    let row = fx.row(job).await;
    assert_eq!(row.status, JobStatus::Succeeded);
    assert_eq!(row.error.as_deref(), Some("outputs_incomplete: 1"));
}

/// SI-9 on download: a link planted in the store is never followed, and traversal never leaves `files/`.
#[tokio::test]
async fn si9_open_published_never_follows_a_link_or_leaves_files() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    assert_eq!(
        upload(&t, node, &header(lease, epoch, "d/ok.txt", b"ok"), b"ok").await,
        Ok(true)
    );
    t.store.finalize(job, 1, &[file("d/ok.txt", b"ok")]).await;
    let secret = t.dir.path().join("secret.txt");
    std::fs::write(&secret, b"server secret").unwrap();
    // A link as the file, and a link as a directory on the way.
    symlink(&secret, t.published(job, "link.txt")).unwrap();
    symlink(t.dir.path(), t.published(job, "dirlink")).unwrap();
    for bad in [
        "link.txt",
        "dirlink/secret.txt",
        "../../../../secret.txt",
        "/etc/passwd",
        "d/../d/ok.txt",
    ] {
        let err = t.store.open_published(job, 1, bad).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{bad}");
    }
    assert!(t.store.open_published(job, 1, "d/ok.txt").await.is_ok());
}

#[tokio::test]
async fn an_idle_stream_times_out() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    let limits = UploadLimits {
        idle: Duration::from_millis(50),
        ..UploadLimits::default()
    };
    let h = header(lease, epoch, "slow.bin", b"0123456789");
    let Ok(Begun::Receive(u)) = t.store.begin(node, &h, &limits).await else {
        panic!("refused");
    };
    // The peer sends half the file and then nothing, keeping the stream open.
    let (mut tx, mut rx) = tokio::io::duplex(64);
    tx.write_all(b"01234").await.unwrap();
    assert_eq!(
        receive(&u, &mut rx, &limits).await.unwrap_err().reason,
        upload_reason::TIMEOUT
    );
    assert!(!t.staging(job, "slow.bin").exists());
    drop(tx);
}

#[test]
fn the_minimum_rate_applies_after_the_grace() {
    let l = UploadLimits::default();
    let s = Duration::from_secs;
    assert!(!too_slow(0, s(10), &l), "nothing is required during the grace");
    assert!(!too_slow(64 * 1024, s(11), &l));
    assert!(too_slow(64 * 1024 - 1, s(11), &l));
    assert!(!too_slow(640 * 1024, s(20), &l));
    assert!(too_slow(600 * 1024, s(20), &l));
}

/// Review P2: a second upload of a path can never destroy the acknowledged first one. The interleaving of the
/// report: B begins before A commits, A commits (its file staged and recorded, `UploadAck{ok:true}`), then B fails,
/// or B completes. A's file stays intact and is published.
#[tokio::test]
async fn a_second_upload_never_destroys_an_acknowledged_file() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    let limits = UploadLimits::default();
    let a_body = b"from A, acknowledged";
    let b_body = b"from B, other content";
    // B passes `begin` first...
    let Ok(Begun::Receive(b)) = t
        .store
        .begin(node, &header(lease, epoch, "x.txt", b_body), &limits)
        .await
    else {
        panic!("B refused");
    };
    // ...then A's commit lands: its file is staged and recorded.
    let staged = t.staging(job, "x.txt");
    std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
    std::fs::write(&staged, a_body).unwrap();
    let mut conn = t.fx.db.acquire().await.unwrap();
    outputs::stage(&mut conn, job, 1, lease, &file("x.txt", a_body), t.fx.now())
        .await
        .unwrap();
    drop(conn);
    // B fails mid-stream: only its own temporary file goes.
    let short = &b_body[..5];
    assert_eq!(
        receive(&b, &mut &short[..], &limits).await.unwrap_err().reason,
        upload_reason::SIZE_MISMATCH
    );
    assert_eq!(std::fs::read(&staged).unwrap(), a_body, "A's file was touched");
    // B again, complete this time: its commit finds A there and replaces nothing.
    assert_eq!(
        receive(&b, &mut &b_body[..], &limits).await.unwrap_err().reason,
        upload_reason::DUPLICATE_PATH
    );
    assert_eq!(std::fs::read(&staged).unwrap(), a_body, "A's file was replaced");
    drop(b);
    assert_eq!(t.store.uploads_in_progress(), 0);
    assert_eq!(t.store.finalize(job, 1, &[file("x.txt", a_body)]).await, None);
    assert_eq!(std::fs::read(t.published(job, "x.txt")).unwrap(), a_body);
    assert_eq!(t.published_rows(job).await, vec![("x.txt".into(), a_body.len() as i64)]);
}

/// Review P2: a second stream for a path is refused while the first is in flight and once it is committed; the path
/// is reserved before the database is asked, so there is no window between the two checks.
#[tokio::test]
async fn a_second_stream_for_a_path_is_refused_in_flight_and_after_commit() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    let limits = UploadLimits::default();
    let a_body = b"first";
    let b_body = b"second, different";
    let Ok(Begun::Receive(a)) = t
        .store
        .begin(node, &header(lease, epoch, "x.txt", a_body), &limits)
        .await
    else {
        panic!("A refused");
    };
    let refused = t
        .store
        .begin(node, &header(lease, epoch, "x.txt", b_body), &limits)
        .await;
    assert_eq!(refused.unwrap_err().reason, upload_reason::DUPLICATE_PATH);
    assert_eq!(t.store.uploads_in_progress(), 1, "a refusal holds no reservation");
    receive(&a, &mut &a_body[..], &limits).await.unwrap();
    drop(a);
    assert_eq!(
        upload(&t, node, &header(lease, epoch, "x.txt", b_body), b_body).await,
        Err(upload_reason::DUPLICATE_PATH)
    );
    assert_eq!(std::fs::read(t.staging(job, "x.txt")).unwrap(), a_body);
    assert_eq!(t.store.uploads_in_progress(), 0);
    // No temporary file is left behind by any of them.
    let incoming = t.store.job_dir(job).join("1").join(INCOMING_DIR);
    assert!(std::fs::read_dir(&incoming).map_or(true, |mut d| d.next().is_none()));
}

use crate::scheduler::Scheduler;

/// T10d item 1: a header whose `size` is absurd is refused (`too_large`) before anything is reserved. It used to be
/// added to the attempt's byte counter first, which overflows (a panic in debug builds) and leaks the slot.
#[tokio::test]
async fn an_absurd_header_size_is_refused_before_it_reserves_anything() {
    let t = setup().await;
    let (_job, node, lease, epoch) = t.running(1).await;
    let mut huge = header(lease, epoch, "huge.bin", b"");
    huge.size = u64::MAX;
    for _ in 0..2 {
        assert_eq!(upload(&t, node, &huge, b"").await, Err(upload_reason::TOO_LARGE));
        assert_eq!(t.store.uploads_in_progress(), 0, "no slot is leaked");
    }
    // A header just over the cap is refused the same way, and one that fits still uploads (the node is not stuck).
    huge.size = 1024 * 1024 + 1;
    assert_eq!(upload(&t, node, &huge, b"").await, Err(upload_reason::TOO_LARGE));
    assert_eq!(
        upload(&t, node, &header(lease, epoch, "ok.txt", b"fine"), b"fine").await,
        Ok(true)
    );
    // Several of them in flight at once together with a huge one: the counter never overflows.
    let a = header(lease, epoch, "a.bin", b"a");
    let Ok(Begun::Receive(first)) = t.store.begin(node, &a, &UploadLimits::default()).await else {
        panic!("a normal upload was refused");
    };
    huge.size = u64::MAX;
    assert_eq!(
        t.store
            .begin(node, &huge, &UploadLimits::default())
            .await
            .unwrap_err()
            .reason,
        upload_reason::TOO_LARGE
    );
    drop(first);
    assert_eq!(t.store.uploads_in_progress(), 0);
}

impl T {
    /// Makes finalisation stop, on the blocking pool, when it starts moving files, until `release` is called.
    /// Returns what the test waits on for "the files are being moved now".
    fn pause_publish(&self) -> (tokio::sync::oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let entered_tx = Mutex::new(Some(entered_tx));
        let release_rx = Mutex::new(release_rx);
        *self.store.inner.publish_hook.lock().unwrap() = Some(PublishHook(Arc::new(move || {
            if let Some(tx) = entered_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            let _ = release_rx.lock().unwrap().recv();
        })));
        (entered_rx, release_tx)
    }
}

/// T10d item 3: the files are moved with SQLite's write lock free. Another writer commits while finalisation is in the
/// middle of its renames (it used to wait out the busy timeout and fail), and uploads are refused from the moment
/// finalisation begins.
#[tokio::test]
async fn finalize_moves_files_without_holding_the_write_lock() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    let body = b"hello outputs\n";
    assert_eq!(
        upload(&t, node, &header(lease, epoch, "a.txt", body), body).await,
        Ok(true)
    );
    let (entered, release) = t.pause_publish();
    let store = t.store.clone();
    let listed = vec![file("a.txt", body)];
    let finalizing = tokio::spawn(async move { store.finalize(job, 1, &listed).await });
    entered.await.expect("finalisation never started moving files");
    // Another write transaction goes through now.
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut tx = store::begin_immediate(&t.fx.db).await.unwrap();
        sqlx::query("UPDATE output_attempts SET last_upload_at = last_upload_at")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    })
    .await
    .expect("finalisation holds the write lock while it moves files");
    // A late upload of the attempt is refused: finalisation has begun.
    assert_eq!(
        upload(&t, node, &header(lease, epoch, "late.txt", b"late"), b"late").await,
        Err(upload_reason::FINALIZED)
    );
    release.send(()).unwrap();
    assert_eq!(finalizing.await.unwrap(), None);
    assert_eq!(std::fs::read(t.published(job, "a.txt")).unwrap(), body);
    assert_eq!(t.published_rows(job).await.len(), 1);
    assert!(!t.staging(job, "late.txt").exists());
}

/// T10d item 3: a crash between the moves and the commit leaves `finalizing_at` set and nothing published in the
/// database. The next finalisation of the attempt finishes it, and until then no upload is accepted.
#[tokio::test]
async fn an_interrupted_finalisation_is_finished_by_the_next_one() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    for (path, body) in [("one.txt", &b"one"[..]), ("two.txt", b"two")] {
        assert_eq!(
            upload(&t, node, &header(lease, epoch, path, body), body).await,
            Ok(true)
        );
    }
    // First transaction committed; one file moved; the process died.
    let mut tx = store::begin_immediate(&t.fx.db).await.unwrap();
    outputs::begin_finalizing(&mut tx, job, 1, t.fx.clock.now())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    std::fs::create_dir_all(t.store.files_dir(job, 1)).unwrap();
    std::fs::rename(t.staging(job, "one.txt"), t.published(job, "one.txt")).unwrap();
    assert_eq!(
        upload(&t, node, &header(lease, epoch, "three.txt", b"3"), b"3").await,
        Err(upload_reason::FINALIZED)
    );
    let note = t
        .store
        .finalize(job, 1, &[file("one.txt", b"one"), file("two.txt", b"two")])
        .await;
    assert_eq!(note, None);
    assert_eq!(
        t.published_rows(job).await,
        vec![("one.txt".into(), 3), ("two.txt".into(), 3)]
    );
    assert!(!t.store.staging_dir(job, 1).exists());
    // And it is final: a repeat changes nothing.
    assert_eq!(t.store.finalize(job, 1, &[]).await, None);
    assert_eq!(t.published_rows(job).await.len(), 2);
}

/// T10d item 3 (durability): every directory that got an entry is fsynced, each once, before the database commit.
/// T10g item 2: the data dir is one of them (an empty path below it), because the first finalisation of a fresh data dir
/// is what creates `artifacts/` there.
#[test]
fn published_directories_are_synced_once_each_from_the_artifacts_root_down() {
    let job = JobId::generate();
    let dirs = dirs_to_sync(
        job,
        1,
        ["a.txt", "results/x.csv", "results/y.csv", "results/deep/z.bin"].into_iter(),
    );
    let job = job.to_string();
    let root = |extra: &[&str]| -> Vec<String> {
        [ARTIFACTS_DIR, job.as_str(), "1"]
            .iter()
            .chain(extra)
            .map(ToString::to_string)
            .collect()
    };
    let expected: Vec<Vec<String>> = vec![
        vec![],
        vec![ARTIFACTS_DIR.to_string()],
        vec![ARTIFACTS_DIR.to_string(), job.clone()],
        root(&[]),
        root(&["files"]),
        root(&["files", "results"]),
        root(&["files", "results", "deep"]),
    ];
    assert_eq!(dirs.into_iter().collect::<Vec<_>>(), expected);
}

/// The directories a finalisation fsyncs on real files: the call works on the store's tree and fails on a missing one.
#[tokio::test]
async fn finalize_syncs_the_directories_it_touched() {
    let t = setup().await;
    let (job, node, lease, epoch) = t.running(1).await;
    assert_eq!(
        upload(&t, node, &header(lease, epoch, "d/e/f.txt", b"f"), b"f").await,
        Ok(true)
    );
    assert_eq!(t.store.finalize(job, 1, &[file("d/e/f.txt", b"f")]).await, None);
    let dirs = dirs_to_sync(job, 1, ["d/e/f.txt"].into_iter());
    assert!(dirs.contains(&Vec::new()), "the data dir is synced too");
    assert!(sync_dirs(t.dir.path(), &dirs).is_ok());
    let gone = dirs_to_sync(JobId::generate(), 1, ["x"].into_iter());
    assert!(
        sync_dirs(t.dir.path(), &gone).is_err(),
        "a directory that is not there cannot be synced"
    );
}
