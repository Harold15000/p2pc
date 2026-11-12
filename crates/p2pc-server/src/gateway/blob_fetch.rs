// SPDX-License-Identifier: AGPL-3.0-only

//! The hub side of `BlobFetch` (H2 §6.1, §7.5 "Delivery to a node"): an agent opens a stream with
//! `BlobFetch{lease_id, epoch, sha256}`; the hub answers `BlobFetchAck{ok, size?, reason?}`, then exactly `size` raw
//! bytes, and finishes the stream. The agent hashes what it receives (`input_integrity` on a mismatch).
//!
//! **What is checked**, in this order, each refusal with its reason:
//! - `stale_lease`: `(lease_id, epoch)` is not the current lease of its job, held by the node of this connection
//!   (SI-H2-6). An unknown lease and another node's lease get the same answer;
//! - `not_referenced`: the lease's job has no blob input with that digest. A node can only fetch the inputs of the job
//!   it was leased, never another blob of the account;
//! - `gone`: no live blob of the **job's** account has that digest (it was tombstoned or deleted), or its file cannot
//!   be read as stored. The account comes from the job, never from the stream (SI-H2-8).
//!
//! **Limits.** At most [`p2pc_proto::protocol::MAX_BLOB_FETCHES_PER_CONNECTION`] fetches at once per agent connection
//! (a fetch beyond them waits for a slot, at most the stream idle limit, then the stream is reset). Each write has the
//! idle limit of upload streams, so a node that stops reading cannot hold a slot for ever. The file is read from one
//! descriptor opened without following a link.

use std::sync::Arc;

use iroh::endpoint::{RecvStream, SendStream, VarInt};
use p2pc_proto::ids::NodeId;
use p2pc_proto::protocol::{BlobFetch, BlobFetchAck, blob_fetch_reason, write_frame};
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;

use super::Inner;
use crate::store::{blobs, leases};

/// The stream reset code of a fetch the hub ends without an answer ("closed by the server").
const RESET_BY_HUB: u32 = 1;
/// The size of each read from the blob's file.
const CHUNK: usize = 64 * 1024;

/// Answers one `BlobFetch` stream of the node `node_id`.
pub(super) async fn serve(
    inner: &Inner,
    node_id: NodeId,
    fetch: &BlobFetch,
    mut send: SendStream,
    mut recv: RecvStream,
    fetches: &Arc<Semaphore>,
) {
    // Nothing follows the header on the agent's side.
    let _ = recv.stop(VarInt::from_u32(0));
    let idle = inner.limits.uploads.idle;
    let Ok(Ok(_slot)) = tokio::time::timeout(idle, fetches.clone().acquire_owned()).await else {
        let _ = send.reset(VarInt::from_u32(RESET_BY_HUB));
        return;
    };
    let answer = match check(inner, node_id, fetch).await {
        Ok(answer) => answer,
        Err(e) => {
            tracing::warn!(error = %e, %node_id, "blob fetch: cannot check the request");
            let _ = send.reset(VarInt::from_u32(RESET_BY_HUB));
            return;
        }
    };
    let (ack, file) = match answer {
        Ok((size, file)) => (BlobFetchAck::accepted(size), Some((size, file))),
        Err(reason) => (BlobFetchAck::refused(reason), None),
    };
    tracing::debug!(%node_id, lease_id = %fetch.lease_id, ok = ack.ok, reason = ?ack.reason, "blob fetch");
    if tokio::time::timeout(idle, write_frame(&mut send, &ack))
        .await
        .map_or(true, |r| r.is_err())
    {
        let _ = send.reset(VarInt::from_u32(RESET_BY_HUB));
        return;
    }
    if let Some((size, file)) = file
        && let Err(e) = copy(file, size, &mut send, idle).await
    {
        tracing::debug!(error = %e, %node_id, "blob fetch: the stream ended early");
        let _ = send.reset(VarInt::from_u32(RESET_BY_HUB));
        return;
    }
    if send.finish().is_ok() {
        let _ = tokio::time::timeout(idle, send.stopped()).await;
    }
}

/// The blob's size and file, or the refusal's reason. `Err` only when the database cannot be read.
async fn check(
    inner: &Inner,
    node_id: NodeId,
    fetch: &BlobFetch,
) -> Result<Result<(u64, std::fs::File), &'static str>, crate::store::StoreError> {
    let state = &inner.state;
    let mut conn = state.db.acquire().await?;
    let lease = match leases::get(&mut conn, fetch.lease_id).await? {
        Some(l) if l.node_id == node_id && l.epoch == fetch.epoch && l.is_current() => l,
        _ => return Ok(Err(blob_fetch_reason::STALE_LEASE)),
    };
    if !blobs::job_references(&mut conn, lease.account_id, lease.job_id, fetch.sha256).await? {
        return Ok(Err(blob_fetch_reason::NOT_REFERENCED));
    }
    let Some(view) = blobs::get_live(&mut conn, lease.account_id, fetch.sha256).await? else {
        return Ok(Err(blob_fetch_reason::GONE));
    };
    drop(conn);
    match state.blobs.open(lease.account_id, fetch.sha256).await {
        Ok((file, size)) if size == view.size => Ok(Ok((size, file))),
        Ok((_, size)) => {
            tracing::error!(sha256 = %fetch.sha256, size, expected = view.size, "a blob's file has the wrong size");
            Ok(Err(blob_fetch_reason::GONE))
        }
        Err(e) => {
            tracing::error!(error = %e, sha256 = %fetch.sha256, "cannot open a blob's file");
            Ok(Err(blob_fetch_reason::GONE))
        }
    }
}

/// Sends exactly `size` bytes of `file`, each write within `idle`.
async fn copy(file: std::fs::File, size: u64, send: &mut SendStream, idle: std::time::Duration) -> std::io::Result<()> {
    let mut file = tokio::fs::File::from_std(file).take(size);
    let mut buf = vec![0u8; CHUNK];
    let mut sent: u64 = 0;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        tokio::time::timeout(idle, send.write_all(&buf[..n]))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "the node stopped reading"))?
            .map_err(std::io::Error::other)?;
        sent += n as u64;
    }
    if sent == size {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the blob's file is shorter than its row",
        ))
    }
}
