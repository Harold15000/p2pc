// SPDX-License-Identifier: AGPL-3.0-only

//! Logs and outputs end to end (spec §6 "Uploads", §7, §10, §12; SI-7, SI-8, SI-9): fake agents over real iroh
//! connections send `LogChunk`s, upload streams and `JobFinished` to the server as `serve` wires it, and the REST API
//! serves what was stored.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::fleet::{FakeAgent, Fleet, WAIT, header as upload_header, output, sha};
use common::{assert_problem, second_account};
use http_body_util::BodyExt;
use p2pc_proto::api::{LogLine, LogStream};
use p2pc_proto::protocol::{ServerMsg, upload_reason};
use p2pc_server::gateway::GatewayLimits;
use tower::ServiceExt;

fn lines(body: &[u8]) -> Vec<LogLine> {
    std::str::from_utf8(body)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn seqs(body: &[u8]) -> Vec<u64> {
    lines(body).into_iter().map(|l| l.seq).collect()
}

/// Reads frames of a streamed body until a whole line with `seq == last` arrived.
async fn read_until(body: &mut Body, got: &mut Vec<u8>, last: u64) {
    tokio::time::timeout(WAIT, async {
        while !got.ends_with(b"\n") || !seqs(got).contains(&last) {
            let frame = body.frame().await.expect("the stream ended early").unwrap();
            got.extend_from_slice(&frame.into_data().unwrap());
        }
    })
    .await
    .expect("the line never came");
}

async fn chatty_job(f: &Fleet, agent: &mut FakeAgent) -> (String, p2pc_proto::ids::LeaseId, u64) {
    let (job, lease, epoch) = f.running(agent).await;
    for seq in 0..5 {
        agent
            .log(lease, epoch, seq, LogStream::Stdout, format!("line {seq}\n").as_bytes())
            .await;
    }
    agent.sync().await;
    (job, lease, epoch)
}

#[tokio::test]
async fn a_job_with_no_logs_gives_an_empty_ndjson_page() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, _, _) = f.running(&mut agent).await;
    let r = f.app.get(&format!("/v1/jobs/{job}/logs"), &f.app.admin).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.content_type(), "application/x-ndjson");
    assert!(r.body.is_empty());
}

#[tokio::test]
async fn pages_start_at_since_seq_inclusive_and_dedupe_resent_chunks() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = chatty_job(&f, &mut agent).await;
    // A resent chunk, then a gap.
    agent.log(lease, epoch, 2, LogStream::Stdout, b"again").await;
    agent.log(lease, epoch, 9, LogStream::Stderr, b"\xffbad utf8").await;
    agent.sync().await;
    let all = f.app.get(&format!("/v1/jobs/{job}/logs"), &f.app.admin).await;
    assert_eq!(seqs(&all.body), vec![0, 1, 2, 3, 4, 9]);
    let got = lines(&all.body);
    assert_eq!(got[2].data, "line 2\n");
    assert_eq!(
        (got[5].stream, got[5].data.as_str()),
        (LogStream::Stderr, "\u{fffd}bad utf8")
    );
    let from = f
        .app
        .get(&format!("/v1/jobs/{job}/logs?since_seq=3&follow=false"), &f.app.admin)
        .await;
    assert_eq!(seqs(&from.body), vec![3, 4, 9]);
    let after = f
        .app
        .get(&format!("/v1/jobs/{job}/logs?since_seq=10"), &f.app.admin)
        .await;
    assert!(after.body.is_empty());
    // Attempts: 0 is invalid, one the job never reached does not exist.
    assert_problem(
        &f.app.get(&format!("/v1/jobs/{job}/logs?attempt=0"), &f.app.admin).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation_failed",
    );
    assert_problem(
        &f.app.get(&format!("/v1/jobs/{job}/logs?attempt=2"), &f.app.admin).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    let first = f.app.get(&format!("/v1/jobs/{job}/logs?attempt=1"), &f.app.admin).await;
    assert_eq!(first.body, all.body);
}

/// Follow mode: the stored lines, then new ones as they arrive, and the stream ends once the attempt is over.
#[tokio::test]
async fn follow_streams_new_lines_and_ends_when_the_attempt_ends() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = chatty_job(&f, &mut agent).await;
    let req = Request::get(format!("/v1/jobs/{job}/logs?follow=true&since_seq=1"))
        .header(header::AUTHORIZATION, format!("Bearer {}", f.app.admin))
        .body(Body::empty())
        .unwrap();
    let resp = f.app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();
    let mut got = Vec::new();
    read_until(&mut body, &mut got, 4).await;
    assert_eq!(seqs(&got), vec![1, 2, 3, 4]);
    // A line logged after the request started reaches the open stream.
    agent.log(lease, epoch, 5, LogStream::Stdout, b"live").await;
    agent.sync().await;
    read_until(&mut body, &mut got, 5).await;
    // The job ends: the stream ends too, with nothing lost.
    agent.log(lease, epoch, 6, LogStream::Stdout, b"last words").await;
    agent.finished(lease, epoch, 0, vec![]).await;
    let rest = tokio::time::timeout(WAIT, body.collect())
        .await
        .expect("the follow did not end at the terminal state")
        .unwrap()
        .to_bytes();
    got.extend_from_slice(&rest);
    assert_eq!(seqs(&got), vec![1, 2, 3, 4, 5, 6]);
    // The stored file was flushed and closed when the attempt ended.
    assert!(!f.app.state.logs.writing(job.parse().unwrap(), 1));
}

/// Follows `uri` as the admin and returns the body, for tests that read it frame by frame.
async fn stream(f: &Fleet, uri: &str) -> Body {
    let req = Request::get(uri)
        .header(header::AUTHORIZATION, format!("Bearer {}", f.app.admin))
        .body(Body::empty())
        .unwrap();
    let resp = f.app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    resp.into_body()
}

/// The next frame of `body`: `None` for a clean end, `Some(Err(_))` for a body that broke.
async fn next_frame(body: &mut Body) -> Option<Result<Vec<u8>, ()>> {
    let frame = tokio::time::timeout(WAIT, body.frame())
        .await
        .expect("the stream neither delivered nor ended");
    match frame {
        None => None,
        Some(Err(_)) => Some(Err(())),
        Some(Ok(f)) => Some(Ok(f.into_data().map(|d| d.to_vec()).unwrap_or_default())),
    }
}

/// §10, T10d item 4: a follow with no new line for the idle limit does NOT end cleanly: its body breaks, so a client
/// cannot take the end for "the attempt is over" (the client reconnects with `since_seq`, losing nothing).
#[tokio::test]
async fn an_idle_follow_ends_with_an_error_not_cleanly() {
    let f = Fleet::start_with(|c| c.http.keepalive_idle_ms = 300, GatewayLimits::default()).await;
    let mut agent = f.agent().await;
    let (job, _, _) = chatty_job(&f, &mut agent).await;
    let mut body = stream(&f, &format!("/v1/jobs/{job}/logs?follow=true")).await;
    let mut got = Vec::new();
    read_until(&mut body, &mut got, 4).await;
    assert_eq!(seqs(&got), vec![0, 1, 2, 3, 4]);
    // Nothing more comes: the idle limit ends the body with an error.
    loop {
        match next_frame(&mut body).await {
            Some(Err(())) => break,
            Some(Ok(more)) => assert!(more.is_empty(), "no new lines were logged"),
            None => panic!("an idle follow ended cleanly, as if the attempt were over"),
        }
    }
}

/// T10d item 4: a log that cannot be read (here a link planted where the file is) breaks the body, in follow mode
/// and in page mode; neither ends as if the log were complete.
#[tokio::test]
async fn a_log_that_cannot_be_read_breaks_the_body() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, _, _) = chatty_job(&f, &mut agent).await;
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("elsewhere"), b"x").unwrap();
    let path = f.app.state.logs.path(job.parse().unwrap(), 1);
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(outside.path().join("elsewhere"), &path).unwrap();
    for uri in [
        format!("/v1/jobs/{job}/logs"),
        format!("/v1/jobs/{job}/logs?follow=true"),
    ] {
        let mut body = stream(&f, &uri).await;
        loop {
            match next_frame(&mut body).await {
                Some(Err(())) => break,
                Some(Ok(data)) => assert!(data.is_empty(), "{uri}: served {} bytes", data.len()),
                None => panic!("{uri}: the body ended cleanly after a read error"),
            }
        }
    }
}

/// T10d item 4: the clean end is the attempt's: after `JobFinished`, the body ends without an error.
#[tokio::test]
async fn a_follow_ends_cleanly_only_when_the_attempt_is_over() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = chatty_job(&f, &mut agent).await;
    let mut body = stream(&f, &format!("/v1/jobs/{job}/logs?follow=true")).await;
    let mut got = Vec::new();
    read_until(&mut body, &mut got, 4).await;
    agent.log(lease, epoch, 5, LogStream::Stdout, b"tail").await;
    agent.finished(lease, epoch, 0, vec![]).await;
    loop {
        match next_frame(&mut body).await {
            None => break,
            Some(Ok(more)) => got.extend_from_slice(&more),
            Some(Err(())) => panic!("the body broke at the end of the attempt"),
        }
    }
    assert_eq!(seqs(&got), vec![0, 1, 2, 3, 4, 5]);
}

/// SI-7: another account's job is `404` for logs, outputs and downloads, exactly like a job that does not exist.
#[tokio::test]
async fn si7_logs_and_outputs_of_another_account_are_not_found() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = chatty_job(&f, &mut agent).await;
    let body = b"result";
    assert!(agent.upload(&upload_header(lease, epoch, "r.txt", body), body).await.ok);
    agent.finished(lease, epoch, 0, vec![output("r.txt", body)]).await;
    let (other, _) = second_account(&f.app).await;
    let missing = "job_01jcz3v3c3r1k0y7e4w4m0q9z8";
    for path in ["logs", "logs?follow=true", "outputs", "outputs/r.txt"] {
        let theirs = f.app.get(&format!("/v1/jobs/{job}/{path}"), &other).await;
        let nobody = f.app.get(&format!("/v1/jobs/{missing}/{path}"), &other).await;
        let a = assert_problem(&theirs, StatusCode::NOT_FOUND, "not_found");
        let b = assert_problem(&nobody, StatusCode::NOT_FOUND, "not_found");
        assert_eq!(a, b, "{path}");
        // The owner sees them.
        assert_eq!(
            f.app.get(&format!("/v1/jobs/{job}/{path}"), &f.app.admin).await.status,
            StatusCode::OK,
            "{path}"
        );
    }
}

#[tokio::test]
async fn uploaded_outputs_are_published_on_job_finished_and_downloaded() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    let a = b"col1,col2\n1,2\n".to_vec();
    let b = vec![0xA5u8; 300 * 1024];
    assert!(
        agent
            .upload(&upload_header(lease, epoch, "results/a.csv", &a), &a)
            .await
            .ok
    );
    assert!(agent.upload(&upload_header(lease, epoch, "b.bin", &b), &b).await.ok);
    // Unlisted: deleted at finalisation.
    assert!(
        agent
            .upload(&upload_header(lease, epoch, "tmp.txt", b"t"), b"t")
            .await
            .ok
    );
    // Nothing is listed before `JobFinished`.
    let list = f.app.get(&format!("/v1/jobs/{job}/outputs"), &f.app.admin).await;
    assert_eq!(list.json()["items"], serde_json::json!([]));
    agent
        .finished(lease, epoch, 0, vec![output("results/a.csv", &a), output("b.bin", &b)])
        .await;
    let v = f.app.get(&format!("/v1/jobs/{job}"), &f.app.admin).await.json();
    assert_eq!((v["status"].as_str(), v["error"].as_str()), (Some("succeeded"), None));
    let list = f.app.get(&format!("/v1/jobs/{job}/outputs"), &f.app.admin).await.json();
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["path"], "b.bin");
    assert_eq!(items[1]["path"], "results/a.csv");
    assert_eq!(items[1]["size"], a.len());
    assert_eq!(items[1]["sha256"], sha(&a).to_string());
    assert_eq!(items[1]["expired"], false);
    // Pagination by path.
    let page = f
        .app
        .get(&format!("/v1/jobs/{job}/outputs?limit=1"), &f.app.admin)
        .await
        .json();
    assert_eq!(page["items"][0]["path"], "b.bin");
    let cursor = page["next_cursor"].as_str().unwrap();
    let next = f
        .app
        .get(&format!("/v1/jobs/{job}/outputs?limit=1&cursor={cursor}"), &f.app.admin)
        .await
        .json();
    assert_eq!(
        (next["items"][0]["path"].as_str(), next["next_cursor"].as_str()),
        (Some("results/a.csv"), None)
    );
    // The download.
    let d = f
        .app
        .get(&format!("/v1/jobs/{job}/outputs/results/a.csv"), &f.app.admin)
        .await;
    assert_eq!(d.status, StatusCode::OK);
    assert_eq!(d.body.as_ref(), a.as_slice());
    assert_eq!(d.content_type(), "application/octet-stream");
    assert_eq!(d.headers["content-length"], a.len().to_string().as_str());
    assert_eq!(d.headers["x-p2pc-sha256"], sha(&a).to_string().as_str());
    assert_eq!(d.headers["content-disposition"], "attachment; filename=\"a.csv\"");
    let d = f
        .app
        .get(&format!("/v1/jobs/{job}/outputs/b.bin?attempt=1"), &f.app.admin)
        .await;
    assert_eq!(d.body.as_ref(), b.as_slice());
    // The unlisted file was never published.
    assert_problem(
        &f.app
            .get(&format!("/v1/jobs/{job}/outputs/tmp.txt"), &f.app.admin)
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
}

#[tokio::test]
async fn a_listed_file_that_was_not_uploaded_is_noted_without_changing_the_outcome() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    let ok = b"ok";
    assert!(agent.upload(&upload_header(lease, epoch, "ok.txt", ok), ok).await.ok);
    agent
        .finished(lease, epoch, 0, vec![output("ok.txt", ok), output("missing.txt", b"m")])
        .await;
    let v = f.app.get(&format!("/v1/jobs/{job}"), &f.app.admin).await.json();
    assert_eq!(v["status"], "succeeded");
    assert_eq!(v["error"], "outputs_incomplete: 1");
    // A second `JobFinished` changes nothing.
    agent.finished(lease, epoch, 0, vec![]).await;
    let list = f.app.get(&format!("/v1/jobs/{job}/outputs"), &f.app.admin).await.json();
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
}

/// SI-8 over the wire: an upload for a stale epoch is refused and the agent is told to cancel it.
#[tokio::test]
async fn si8_an_upload_with_a_stale_epoch_is_refused_and_cancelled() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (_job, lease, epoch) = f.running(&mut agent).await;
    let ack = agent.upload(&upload_header(lease, epoch + 1, "x", b"x"), b"x").await;
    assert_eq!(
        (ack.ok, ack.reason.as_deref()),
        (false, Some(upload_reason::STALE_EPOCH))
    );
    let other = agent.sync().await;
    assert!(
        other.contains(&ServerMsg::Cancel {
            lease_id: lease,
            epoch: epoch + 1,
            reason: "stale_epoch".into()
        }),
        "{other:?}"
    );
}

#[tokio::test]
async fn bad_uploads_are_refused_with_a_reason() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    // SI-9: traversal.
    let ack = agent
        .upload(&upload_header(lease, epoch, "../../etc/x", b"x"), b"x")
        .await;
    assert_eq!(ack.reason.as_deref(), Some(upload_reason::INVALID_PATH));
    // A header that is not one.
    let ack = agent.upload_raw(b"{\"not\":\"a header\"}", b"").await;
    assert_eq!(ack.reason.as_deref(), Some(upload_reason::INVALID_HEADER));
    // A wrong digest, and a short stream.
    let mut h = upload_header(lease, epoch, "a", b"abc");
    h.sha256 = sha(b"abd");
    assert_eq!(
        agent.upload(&h, b"abc").await.reason.as_deref(),
        Some(upload_reason::SHA256_MISMATCH)
    );
    let h = upload_header(lease, epoch, "b", b"abcdef");
    assert_eq!(
        agent.upload(&h, b"abc").await.reason.as_deref(),
        Some(upload_reason::SIZE_MISMATCH)
    );
    // Oversized for `outputs.max_mb` (1024 by default).
    let mut h = upload_header(lease, epoch, "c", b"");
    h.size = 1024 * 1024 * 1024 + 1;
    assert_eq!(
        agent.upload(&h, b"").await.reason.as_deref(),
        Some(upload_reason::TOO_LARGE)
    );
    // A duplicate path.
    assert!(agent.upload(&upload_header(lease, epoch, "d", b"1"), b"1").await.ok);
    assert_eq!(
        agent
            .upload(&upload_header(lease, epoch, "d", b"2"), b"2")
            .await
            .reason
            .as_deref(),
        Some(upload_reason::DUPLICATE_PATH)
    );
    // Nothing of the refused ones is staged.
    let staging = f.app.state.outputs.staging_dir(job.parse().unwrap(), 1);
    let mut left: Vec<String> = std::fs::read_dir(&staging)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    assert_eq!(left, vec!["d"]);
    assert!(!f.app.data_dir().join("etc").exists());
}

/// SI-9 on download: traversal never leaves the published root, and a link planted in the store is never followed.
#[tokio::test]
async fn si9_downloads_refuse_traversal_and_planted_links() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (job, lease, epoch) = f.running(&mut agent).await;
    for p in ["a.txt", "b.txt"] {
        assert!(
            agent
                .upload(&upload_header(lease, epoch, p, p.as_bytes()), p.as_bytes())
                .await
                .ok
        );
    }
    agent
        .finished(
            lease,
            epoch,
            0,
            vec![output("a.txt", b"a.txt"), output("b.txt", b"b.txt")],
        )
        .await;
    let secret = f.app.data_dir().join("server.toml");
    for path in [
        "..%2F..%2F..%2Fserver.toml",
        "%2E%2E/%2E%2E/server.toml",
        "a.txt%00",
        "%2Fetc%2Fpasswd",
    ] {
        let r = f.app.get(&format!("/v1/jobs/{job}/outputs/{path}"), &f.app.admin).await;
        assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    }
    // Someone with access to the data dir swaps a published file for a link to the server's config.
    let published = f.app.state.outputs.files_dir(job.parse().unwrap(), 1).join("b.txt");
    std::fs::remove_file(&published).unwrap();
    std::os::unix::fs::symlink(&secret, &published).unwrap();
    let r = f.app.get(&format!("/v1/jobs/{job}/outputs/b.txt"), &f.app.admin).await;
    assert_problem(&r, StatusCode::NOT_FOUND, "not_found");
    assert!(!String::from_utf8_lossy(&r.body).contains("data_dir"));
    assert_eq!(
        f.app
            .get(&format!("/v1/jobs/{job}/outputs/a.txt"), &f.app.admin)
            .await
            .status,
        StatusCode::OK
    );
}

/// At most 2 uploads at once per node: a third concurrent stream is refused, and a later one goes through.
#[tokio::test]
async fn concurrent_uploads_are_capped_per_node() {
    let mut limits = GatewayLimits::default();
    limits.uploads.per_node = 1;
    let f = Fleet::start_with(|_| {}, limits).await;
    let mut agent = f.agent().await;
    let (_job, lease, epoch) = f.running(&mut agent).await;
    // The first upload announces 10 bytes and sends only some: it holds its slot.
    let (mut send, _recv) = agent.conn.open_bi().await.unwrap();
    let h = serde_json::to_vec(&upload_header(lease, epoch, "slow", b"0123456789")).unwrap();
    let len = u32::try_from(h.len()).unwrap().to_be_bytes();
    tokio::io::AsyncWriteExt::write_all(&mut send, &len).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut send, &h).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut send, b"01").await.unwrap();
    tokio::time::timeout(WAIT, async {
        while f.app.state.outputs.uploads_in_progress() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let ack = agent.upload(&upload_header(lease, epoch, "second", b"2"), b"2").await;
    assert_eq!(ack.reason.as_deref(), Some(upload_reason::TOO_MANY_UPLOADS));
    // The slow upload ends short; the slot is free again.
    send.finish().unwrap();
    tokio::time::timeout(WAIT, async {
        while f.app.state.outputs.uploads_in_progress() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the slot was never released");
    assert!(
        agent
            .upload(&upload_header(lease, epoch, "second", b"2"), b"2")
            .await
            .ok
    );
}

/// Review P3: a node holds at most `headers_per_node` upload streams whose header is not read yet; another stream is
/// refused at once (no 1 MiB header buffer for it), and the slot frees as soon as the pending header is read.
#[tokio::test]
async fn upload_streams_waiting_for_their_header_are_capped_per_node() {
    let mut limits = GatewayLimits::default();
    limits.uploads.headers_per_node = 1;
    let f = Fleet::start_with(|_| {}, limits).await;
    let mut agent = f.agent().await;
    let (_job, lease, epoch) = f.running(&mut agent).await;
    // A stream that announces a header and sends only part of it: it holds the node's only header slot.
    let (mut slow, mut slow_recv) = agent.conn.open_bi().await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut slow, &1000u32.to_be_bytes())
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut slow, b"{\"lease_id\"")
        .await
        .unwrap();
    // Another stream gets its refusal without its header being read.
    let mut refused = None;
    tokio::time::timeout(WAIT, async {
        loop {
            let ack = agent.upload(&upload_header(lease, epoch, "x", b"x"), b"x").await;
            if ack.reason.as_deref() == Some(upload_reason::TOO_MANY_UPLOADS) {
                refused = Some(ack);
                return;
            }
            // The slow stream's bytes had not reached the server yet: this one took the slot. Try again.
            assert!(ack.ok, "{ack:?}");
        }
    })
    .await
    .expect("never refused");
    assert!(refused.is_some());
    // The slow stream ends: its header is invalid, and its slot is free again.
    slow.finish().unwrap();
    let frame = tokio::time::timeout(WAIT, p2pc_proto::protocol::read_frame_bytes(&mut slow_recv, 1 << 20))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let ack: p2pc_proto::protocol::UploadAck = serde_json::from_slice(&frame).unwrap();
    assert_eq!(ack.reason.as_deref(), Some(upload_reason::INVALID_HEADER));
    assert!(agent.upload(&upload_header(lease, epoch, "y", b"y"), b"y").await.ok);
}
