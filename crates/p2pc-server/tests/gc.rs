// SPDX-License-Identifier: AGPL-3.0-only

//! The GC of logs and artifacts (spec §12), with the injectable clock: terminal jobs past `retention_days` lose their
//! logs and artifacts (the job rows stay, outputs show `expired: true` and downloads answer `410`), and staging that
//! never finalised goes an hour after its lease ended. Deletion never follows a link.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use axum::http::StatusCode;
use common::assert_problem;
use common::fleet::{Fleet, header as upload_header, output};
use p2pc_proto::api::LogStream;
use p2pc_proto::ids::JobId;
use p2pc_server::gc;
use time::Duration;

#[tokio::test]
async fn terminal_jobs_lose_logs_and_artifacts_after_the_retention_and_keep_their_rows() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    let job_id: JobId = job.parse().unwrap();
    agent.log(lease, epoch, 0, LogStream::Stdout, b"hello").await;
    let body = b"result";
    assert!(agent.upload(&upload_header(lease, epoch, "r.txt", body), body).await.ok);
    agent.finished(lease, epoch, 0, vec![output("r.txt", body)]).await;
    // A still-running job of the same age is never touched.
    let (busy, busy_lease, busy_epoch) = f.running(&mut agent).await;
    agent.log(busy_lease, busy_epoch, 0, LogStream::Stdout, b"busy").await;
    agent.sync().await;
    let logs_dir = f.app.state.logs.job_dir(job_id);
    let artifacts_dir = f.app.state.outputs.job_dir(job_id);
    assert!(logs_dir.exists() && artifacts_dir.exists());
    // A link planted in the job's directory, to a file outside the store.
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("keep"), b"keep").unwrap();
    std::os::unix::fs::symlink(outside.path(), artifacts_dir.join("link")).unwrap();

    f.app.clock.advance(Duration::days(7) - Duration::seconds(1));
    assert_eq!(gc::run_pass(&f.app.state, 100).await, gc::GcReport::default());
    assert!(artifacts_dir.exists());

    f.app.clock.advance(Duration::seconds(2));
    let report = gc::run_pass(&f.app.state, 100).await;
    assert_eq!((report.jobs_expired, report.errors), (1, 0));
    assert!(!logs_dir.exists() && !artifacts_dir.exists());
    assert_eq!(
        std::fs::read(outside.path().join("keep")).unwrap(),
        b"keep",
        "the link was followed"
    );
    // The job and its outputs list stay; the outputs are expired and their downloads gone.
    let v = f.app.get(&format!("/v1/jobs/{job}"), &f.app.admin).await;
    assert_eq!(
        (v.status, v.json()["status"].as_str()),
        (StatusCode::OK, Some("succeeded"))
    );
    let list = f.app.get(&format!("/v1/jobs/{job}/outputs"), &f.app.admin).await.json();
    assert_eq!(list["items"][0]["path"], "r.txt");
    assert_eq!(list["items"][0]["expired"], true);
    assert_problem(
        &f.app.get(&format!("/v1/jobs/{job}/outputs/r.txt"), &f.app.admin).await,
        StatusCode::GONE,
        "expired",
    );
    let logs = f.app.get(&format!("/v1/jobs/{job}/logs"), &f.app.admin).await;
    assert_eq!((logs.status, logs.body.is_empty()), (StatusCode::OK, true));
    // The running job kept its log; a second pass has nothing left to do.
    assert!(f.app.state.logs.job_dir(busy.parse().unwrap()).exists());
    assert_eq!(gc::run_pass(&f.app.state, 100).await, gc::GcReport::default());
    // What was deleted is recorded.
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM artifact_gc WHERE job_id = ?")
        .bind(&job)
        .fetch_one(&f.app.db)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn the_retention_is_configurable_and_each_pass_is_bounded() {
    let f = Fleet::start_with(|c| c.storage.retention_days = 1, Default::default()).await;
    let mut agent = f.agent().await;
    let mut jobs = Vec::new();
    for _ in 0..3 {
        let (job, lease, epoch) = f.running(&mut agent).await;
        agent.log(lease, epoch, 0, LogStream::Stdout, b"x").await;
        agent.finished(lease, epoch, 0, vec![]).await;
        jobs.push(job);
    }
    f.app.clock.advance(Duration::days(1) + Duration::seconds(1));
    assert_eq!(gc::run_pass(&f.app.state, 2).await.jobs_expired, 2);
    assert_eq!(gc::run_pass(&f.app.state, 2).await.jobs_expired, 1);
    for job in &jobs {
        assert!(!f.app.state.logs.job_dir(job.parse().unwrap()).exists());
    }
}

/// A lease lost before `JobFinished` loses its staged files: the GC removes them an hour after the lease ended.
#[tokio::test]
async fn staging_that_never_finalised_goes_an_hour_after_the_lease_ended() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    let job_id: JobId = job.parse().unwrap();
    assert!(
        agent
            .upload(&upload_header(lease, epoch, "half.bin", b"half"), b"half")
            .await
            .ok
    );
    let staging = f.app.state.outputs.staging_dir(job_id, 1);
    assert!(staging.join("half.bin").exists());
    // The agent restarts without the lease: lost at once, the job requeued for attempt 2.
    let _agent = f.restart(agent).await;
    let v = f.app.get(&format!("/v1/jobs/{job}"), &f.app.admin).await.json();
    assert_eq!((v["status"].as_str(), v["attempt"].as_u64()), (Some("queued"), Some(2)));

    f.app.clock.advance(Duration::minutes(59));
    assert_eq!(gc::run_pass(&f.app.state, 100).await.staging_removed, 0);
    assert!(staging.exists());
    f.app.clock.advance(Duration::minutes(2));
    let report = gc::run_pass(&f.app.state, 100).await;
    assert_eq!((report.staging_removed, report.errors), (1, 0));
    assert!(!staging.exists());
    let staged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM output_staging")
        .fetch_one(&f.app.db)
        .await
        .unwrap();
    assert_eq!(staged, 0);
    assert_eq!(gc::run_pass(&f.app.state, 100).await, gc::GcReport::default());
}

/// Review P3: a job's files that could not be deleted are retried on the next pass: `removed_at` is set only once
/// they are gone, and the job shows expired from the first pass on.
#[tokio::test]
async fn a_failed_deletion_is_retried_until_the_files_are_gone() {
    use std::os::unix::fs::PermissionsExt;

    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    let job_id: JobId = job.parse().unwrap();
    assert!(agent.upload(&upload_header(lease, epoch, "r.txt", b"r"), b"r").await.ok);
    agent.finished(lease, epoch, 0, vec![output("r.txt", b"r")]).await;
    let artifacts_dir = f.app.state.outputs.job_dir(job_id);
    let parent = artifacts_dir.parent().unwrap().to_path_buf();
    // The artifacts root cannot be written: the job's directory cannot be removed from it.
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();
    f.app.clock.advance(Duration::days(8));
    let report = gc::run_pass(&f.app.state, 100).await;
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!((report.jobs_expired, report.errors), (0, 1), "{report:?}");
    assert!(artifacts_dir.exists());
    let removed: Option<i64> = sqlx::query_scalar("SELECT removed_at FROM artifact_gc WHERE job_id = ?")
        .bind(&job)
        .fetch_one(&f.app.db)
        .await
        .unwrap();
    assert_eq!(
        removed, None,
        "nothing is recorded as removed while the files are there"
    );
    // Already expired for the API: the record came first.
    let list = f.app.get(&format!("/v1/jobs/{job}/outputs"), &f.app.admin).await.json();
    assert_eq!(list["items"][0]["expired"], true);
    // The next pass retries it.
    let report = gc::run_pass(&f.app.state, 100).await;
    assert_eq!((report.jobs_expired, report.errors), (1, 0), "{report:?}");
    assert!(!artifacts_dir.exists());
    let removed: Option<i64> = sqlx::query_scalar("SELECT removed_at FROM artifact_gc WHERE job_id = ?")
        .bind(&job)
        .fetch_one(&f.app.db)
        .await
        .unwrap();
    assert!(removed.is_some());
    assert_eq!(gc::run_pass(&f.app.state, 100).await, gc::GcReport::default());
}

/// Review P3: the staging of an attempt that was finalised, but whose `.staging` could not be removed then, is swept
/// by the GC (no hour to wait: no upload is taken for a finalised attempt).
#[tokio::test]
async fn leftover_staging_of_a_finalised_attempt_is_swept() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    let job_id: JobId = job.parse().unwrap();
    agent.finished(lease, epoch, 0, vec![]).await;
    // What a failed removal at finalisation leaves: the directory, and no `staging_removed_at`.
    let staging = f.app.state.outputs.staging_dir(job_id, 1);
    std::fs::create_dir_all(staging.join("sub")).unwrap();
    std::fs::write(staging.join("sub/left.bin"), b"x").unwrap();
    sqlx::query("UPDATE output_attempts SET staging_removed_at = NULL WHERE job_id = ?")
        .bind(&job)
        .execute(&f.app.db)
        .await
        .unwrap();
    let report = gc::run_pass(&f.app.state, 100).await;
    assert_eq!((report.staging_removed, report.errors), (1, 0), "{report:?}");
    assert!(!staging.exists());
    assert_eq!(gc::run_pass(&f.app.state, 100).await, gc::GcReport::default());
}

/// T10d item 2: a link planted where a job's directory should be, pointing at a tree outside the store, is removed
/// itself by the GC; the staging sweep of an attempt of that job resolves no link on the way and leaves the tree alone.
#[tokio::test]
async fn a_link_planted_at_the_job_directory_is_never_followed_by_the_gc() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    let job_id: JobId = job.parse().unwrap();
    assert!(
        agent
            .upload(&upload_header(lease, epoch, "half.bin", b"half"), b"half")
            .await
            .ok
    );
    // A tree outside the store, shaped like a job's directory, and a link to it where the job's directory is.
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(outside.path().join("1/.staging")).unwrap();
    std::fs::create_dir_all(outside.path().join("1/.incoming")).unwrap();
    std::fs::write(outside.path().join("1/.staging/keep"), b"keep").unwrap();
    std::fs::write(outside.path().join("1/.incoming/keep"), b"keep").unwrap();
    let job_dir = f.app.state.outputs.job_dir(job_id);
    std::fs::remove_dir_all(&job_dir).unwrap();
    std::os::unix::fs::symlink(outside.path(), &job_dir).unwrap();
    // The lease is lost: the staging is abandoned an hour later.
    let _agent = f.restart(agent).await;
    f.app.clock.advance(Duration::hours(2));
    let report = gc::run_pass(&f.app.state, 100).await;
    assert_eq!(
        report.staging_removed, 0,
        "nothing was removed through the link: {report:?}"
    );
    assert_eq!(std::fs::read(outside.path().join("1/.staging/keep")).unwrap(), b"keep");
    assert_eq!(std::fs::read(outside.path().join("1/.incoming/keep")).unwrap(), b"keep");
}

/// T10d item 2: when the job expires, a link in place of its directory is removed itself.
#[tokio::test]
async fn an_expired_jobs_planted_link_is_removed_without_touching_its_target() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    let job_id: JobId = job.parse().unwrap();
    agent.finished(lease, epoch, 0, vec![]).await;
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(outside.path().join("1/files")).unwrap();
    std::fs::write(outside.path().join("1/files/keep"), b"keep").unwrap();
    let job_dir = f.app.state.outputs.job_dir(job_id);
    // A job that uploaded nothing has no directory yet.
    let _ = std::fs::remove_dir_all(&job_dir);
    std::fs::create_dir_all(job_dir.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(outside.path(), &job_dir).unwrap();
    f.app.clock.advance(Duration::days(8));
    let report = gc::run_pass(&f.app.state, 100).await;
    assert_eq!((report.jobs_expired, report.errors), (1, 0), "{report:?}");
    assert!(std::fs::symlink_metadata(&job_dir).is_err(), "the link is gone");
    assert_eq!(std::fs::read(outside.path().join("1/files/keep")).unwrap(), b"keep");
}

/// Ids in the order the GC's queries break ties: the first is the one a pass with `limit = 1` meets first.
fn in_queue_order(a: String, b: String) -> (String, String) {
    if a <= b { (a, b) } else { (b, a) }
}

/// T10d item 5: a job whose files cannot be deleted goes to the back of the queue. With a limit of one job per pass,
/// the healthy job behind it is deleted by the second pass instead of waiting for ever behind the failing one.
#[tokio::test]
async fn an_undeletable_job_does_not_stall_the_jobs_behind_it() {
    use std::os::unix::fs::PermissionsExt;

    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let mut ids = Vec::new();
    for _ in 0..2 {
        let (job, lease, epoch) = f.running(&mut agent).await;
        assert!(agent.upload(&upload_header(lease, epoch, "r.txt", b"r"), b"r").await.ok);
        agent.finished(lease, epoch, 0, vec![output("r.txt", b"r")]).await;
        ids.push(job);
    }
    let (bad, good) = in_queue_order(ids.remove(0), ids.remove(0));
    let bad_files = f.app.state.outputs.files_dir(bad.parse().unwrap(), 1);
    let good_dir = f.app.state.outputs.job_dir(good.parse().unwrap());
    // A directory that cannot be emptied: its file cannot be unlinked.
    std::fs::set_permissions(&bad_files, std::fs::Permissions::from_mode(0o500)).unwrap();
    f.app.clock.advance(Duration::days(8));

    let first = gc::run_pass(&f.app.state, 1).await;
    assert_eq!((first.jobs_expired, first.errors), (0, 1), "{first:?}");
    let second = gc::run_pass(&f.app.state, 1).await;
    // The healthy job was reached on the second pass (the failing one's retry went to the back).
    let reached = !good_dir.exists();
    std::fs::set_permissions(&bad_files, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        reached,
        "the failing job was retried again, ahead of the healthy one: {second:?}"
    );
    assert_eq!(second.jobs_expired, 1, "{second:?}");
    // Once it can be deleted, the failing job is deleted too.
    let third = gc::run_pass(&f.app.state, 1).await;
    assert_eq!((third.jobs_expired, third.errors), (1, 0), "{third:?}");
    assert!(!f.app.state.outputs.job_dir(bad.parse().unwrap()).exists());
}

/// T10d item 5, for the staging sweep.
#[tokio::test]
async fn an_undeletable_staging_does_not_stall_the_attempts_behind_it() {
    use std::os::unix::fs::PermissionsExt;

    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let mut ids = Vec::new();
    for _ in 0..2 {
        let (job, lease, epoch) = f.running(&mut agent).await;
        assert!(
            agent
                .upload(&upload_header(lease, epoch, "half.bin", b"half"), b"half")
                .await
                .ok
        );
        ids.push(job);
    }
    let (bad, good) = in_queue_order(ids.remove(0), ids.remove(0));
    let bad_staging = f.app.state.outputs.staging_dir(bad.parse().unwrap(), 1);
    let good_staging = f.app.state.outputs.staging_dir(good.parse().unwrap(), 1);
    let _agent = f.restart(agent).await;
    std::fs::set_permissions(&bad_staging, std::fs::Permissions::from_mode(0o500)).unwrap();
    f.app.clock.advance(Duration::hours(2));

    let first = gc::run_pass(&f.app.state, 1).await;
    assert_eq!((first.staging_removed, first.errors), (0, 1), "{first:?}");
    let second = gc::run_pass(&f.app.state, 1).await;
    let reached = !good_staging.exists();
    std::fs::set_permissions(&bad_staging, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        reached,
        "the failing staging was retried again, ahead of the healthy one: {second:?}"
    );
    assert_eq!(second.staging_removed, 1, "{second:?}");
    let third = gc::run_pass(&f.app.state, 1).await;
    assert_eq!((third.staging_removed, third.errors), (1, 0), "{third:?}");
    assert!(!bad_staging.exists());
}

/// T10d review P3-3: an attempt whose finalisation was interrupted (`finalizing_at` set, never `finalized_at`: a crash,
/// or a failed fsync that the scheduler does not retry) is finished by the staging sweep an hour after its lease ended,
/// instead of being discarded: the files an earlier finalisation already moved into `files/` are published; what is
/// still in `.staging` was not listed (or was lost) and goes.
#[tokio::test]
async fn the_staging_sweep_finishes_an_interrupted_finalisation() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    let job_id: JobId = job.parse().unwrap();
    for (path, body) in [("moved.txt", &b"moved"[..]), ("stuck.txt", b"stuck")] {
        assert!(agent.upload(&upload_header(lease, epoch, path, body), body).await.ok);
    }
    // What a finalisation leaves when it dies after moving one file: marked, one file in `files/`, no record.
    sqlx::query("UPDATE output_attempts SET finalizing_at = strftime('%s', 'now') WHERE job_id = ?")
        .bind(&job)
        .execute(&f.app.db)
        .await
        .unwrap();
    let staging = f.app.state.outputs.staging_dir(job_id, 1);
    let files = f.app.state.outputs.files_dir(job_id, 1);
    std::fs::create_dir_all(&files).unwrap();
    std::fs::rename(staging.join("moved.txt"), files.join("moved.txt")).unwrap();
    // The lease is lost without `JobFinished`; an hour later the sweep reaches the attempt.
    let _agent = f.restart(agent).await;
    f.app.clock.advance(Duration::minutes(59));
    assert_eq!(gc::run_pass(&f.app.state, 100).await.staging_removed, 0);
    f.app.clock.advance(Duration::minutes(2));
    let report = gc::run_pass(&f.app.state, 100).await;
    assert_eq!((report.staging_removed, report.errors), (1, 0), "{report:?}");

    assert!(!staging.exists());
    assert!(files.join("moved.txt").exists());
    let list = f
        .app
        .get(&format!("/v1/jobs/{job}/outputs?attempt=1"), &f.app.admin)
        .await
        .json();
    let paths: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        vec!["moved.txt"],
        "the moved file is published, the stuck one is not"
    );
    let d = f
        .app
        .get(&format!("/v1/jobs/{job}/outputs/moved.txt?attempt=1"), &f.app.admin)
        .await;
    assert_eq!((d.status, d.body.as_ref()), (StatusCode::OK, &b"moved"[..]));
    let finalized: Option<i64> =
        sqlx::query_scalar("SELECT finalized_at FROM output_attempts WHERE job_id = ? AND attempt = 1")
            .bind(&job)
            .fetch_one(&f.app.db)
            .await
            .unwrap();
    assert!(finalized.is_some(), "the attempt is finalised now");
    let staged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM output_staging WHERE job_id = ?")
        .bind(&job)
        .fetch_one(&f.app.db)
        .await
        .unwrap();
    assert_eq!(staged, 0);
    assert_eq!(gc::run_pass(&f.app.state, 100).await, gc::GcReport::default());
}
