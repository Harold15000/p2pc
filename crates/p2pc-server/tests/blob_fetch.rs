// SPDX-License-Identifier: AGPL-3.0-only

//! The hub side of `BlobFetch` (H2 §6.1, SI-H2-6, SI-H2-8) and the dispatcher of agent-opened streams, over real iroh
//! connections on loopback: a fetch is answered only for the job's current lease on the asking node, only for a blob
//! that job references, from the job's own account; an unknown stream `type` resets the stream, not the connection;
//! H1 uploads (no `type`) still work.

// Helpers are not `#[test]` functions, so `allow-unwrap-in-tests` does not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::fleet::{FakeAgent, Fleet, WAIT, header as upload_header, sha};
use p2pc_proto::api::BLOB_SHA256_HEADER;
use p2pc_proto::ids::LeaseId;
use p2pc_proto::protocol::{AgentMsg, BlobFetchAck, MAX_FRAME_LEN, STREAM_RESET_UNSUPPORTED_STREAM, read_frame_bytes};
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;

async fn upload_blob(f: &Fleet, bytes: &[u8]) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/blobs")
        .header(header::AUTHORIZATION, format!("Bearer {}", f.app.admin))
        .header(header::CONTENT_LENGTH, bytes.len())
        .header(BLOB_SHA256_HEADER, sha(bytes).to_string())
        .body(Body::from(bytes.to_vec()))
        .unwrap();
    let r = f.app.send(req).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
}

/// An agent that declares `blob_inputs` (H2 §6.1), with a job whose input is `bytes` leased to it and accepted.
async fn leased(f: &Fleet, bytes: &[u8]) -> (FakeAgent, String, LeaseId, u64) {
    let agent = f.agent().await;
    let mut agent = f.restart_with(agent, &["blob_inputs"]).await;
    upload_blob(f, bytes).await;
    let job = f
        .submit(json!({"image": "docker.io/library/alpine:3", "command": ["true"],
            "resources": {"cpu": 1, "memory_mb": 256, "disk_mb": 1024},
            "inputs": [{"path": "/inputs/audio", "blob": format!("sha256:{}", sha(bytes))}]}))
        .await;
    assert_eq!(f.scheduler.tick().await.errors, 0);
    let (lease_id, epoch) = agent.next_lease().await;
    agent.send(&AgentMsg::LeaseAccepted { lease_id, epoch }).await;
    agent.sync().await;
    (agent, job, lease_id, epoch)
}

/// Opens a stream with `header`, and returns the ack and the bytes that follow it.
async fn fetch_raw(agent: &FakeAgent, header: &Value) -> (BlobFetchAck, Vec<u8>) {
    let (mut send, mut recv) = agent.conn.open_bi().await.unwrap();
    let frame = serde_json::to_vec(header).unwrap();
    send.write_all(&u32::try_from(frame.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    send.write_all(&frame).await.unwrap();
    let _ = send.finish();
    let ack = tokio::time::timeout(WAIT, read_frame_bytes(&mut recv, MAX_FRAME_LEN))
        .await
        .expect("no ack")
        .unwrap()
        .expect("the stream ended without an ack");
    let ack: BlobFetchAck = serde_json::from_slice(&ack).unwrap();
    ack.validate().unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(WAIT, AsyncReadExt::read_to_end(&mut recv, &mut rest))
        .await
        .expect("the blob did not end")
        .unwrap();
    (ack, rest)
}

async fn fetch(agent: &FakeAgent, lease_id: LeaseId, epoch: u64, digest: &str) -> (BlobFetchAck, Vec<u8>) {
    fetch_raw(
        agent,
        &json!({"type": "blob_fetch", "lease_id": lease_id, "epoch": epoch, "sha256": digest}),
    )
    .await
}

#[tokio::test]
async fn the_current_lease_fetches_the_blob_its_job_references() {
    let f = Fleet::start().await;
    let bytes = b"audio bytes for the job".repeat(50);
    let (agent, _job, lease_id, epoch) = leased(&f, &bytes).await;
    let (ack, body) = fetch(&agent, lease_id, epoch, &sha(&bytes).to_string()).await;
    assert_eq!(ack, BlobFetchAck::accepted(bytes.len() as u64));
    assert_eq!(body, bytes);
    // Several fetches of one lease, one after another, each get the whole blob.
    let (again, body) = fetch(&agent, lease_id, epoch, &sha(&bytes).to_string()).await;
    assert!(again.ok);
    assert_eq!(body.len(), bytes.len());
}

#[tokio::test]
async fn a_fetch_is_fenced_by_lease_and_epoch_and_limited_to_the_jobs_blobs() {
    let f = Fleet::start().await;
    let bytes = b"fenced input".to_vec();
    let (agent, _job, lease_id, epoch) = leased(&f, &bytes).await;
    let digest = sha(&bytes).to_string();
    // A stale epoch, and a lease that does not exist (SI-H2-6).
    let (ack, body) = fetch(&agent, lease_id, epoch + 1, &digest).await;
    assert_eq!(ack, BlobFetchAck::refused("stale_lease"));
    assert!(body.is_empty());
    let (ack, _) = fetch(&agent, LeaseId::generate(), epoch, &digest).await;
    assert_eq!(ack, BlobFetchAck::refused("stale_lease"));
    // A blob of the account that the job does not reference.
    let unrelated = b"not an input of this job".to_vec();
    upload_blob(&f, &unrelated).await;
    let (ack, body) = fetch(&agent, lease_id, epoch, &sha(&unrelated).to_string()).await;
    assert_eq!(ack, BlobFetchAck::refused("not_referenced"));
    assert!(body.is_empty());
    // Another node cannot fetch for this lease.
    let other = f.agent().await;
    let other = f.restart_with(other, &["blob_inputs"]).await;
    let (ack, _) = fetch(&other, lease_id, epoch, &digest).await;
    assert_eq!(ack, BlobFetchAck::refused("stale_lease"));
    // A referenced blob whose row is gone (a tombstone: absent to every reader).
    sqlx::query("UPDATE blobs SET deleting_at = 1 WHERE sha256 = ?")
        .bind(&digest)
        .execute(&f.app.db)
        .await
        .unwrap();
    let (ack, _) = fetch(&agent, lease_id, epoch, &digest).await;
    assert_eq!(ack, BlobFetchAck::refused("gone"));
}

#[tokio::test]
async fn an_unknown_stream_type_resets_the_stream_and_keeps_the_connection() {
    let f = Fleet::start().await;
    let mut agent = f.agent().await;
    let (mut send, mut recv) = agent.conn.open_bi().await.unwrap();
    let frame = serde_json::to_vec(&json!({"type": "teleport", "where": "elsewhere"})).unwrap();
    send.write_all(&u32::try_from(frame.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    send.write_all(&frame).await.unwrap();
    let _ = send.finish();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(WAIT, recv.read(&mut buf)).await.expect("no reset");
    match read {
        Err(iroh::endpoint::ReadError::Reset(code)) => {
            assert_eq!(code.into_inner(), u64::from(STREAM_RESET_UNSUPPORTED_STREAM));
        }
        other => panic!("expected a reset, got {other:?}"),
    }
    // The connection is still up: the control stream answers.
    agent.sync().await;
    // And an H1 upload (no `type`) is still read as an upload.
    let (job, lease_id, epoch) = f.running(&mut agent).await;
    let out = b"output".to_vec();
    let ack = agent.upload(&upload_header(lease_id, epoch, "a.txt", &out), &out).await;
    assert!(ack.ok, "{ack:?} for {job}");
}
