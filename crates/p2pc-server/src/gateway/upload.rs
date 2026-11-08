// SPDX-License-Identifier: AGPL-3.0-only

//! Upload streams of `p2pc/agent/1` (spec §6 "Uploads"): every bidirectional stream an enrolled, connected agent
//! opens after its control stream carries one output file.
//!
//! The stream starts with an `UploadHeader` frame (at most 1 MiB, decoded under the global decode cap), then exactly
//! `size` raw bytes, then the end of the agent's side. The server answers one `UploadAck` frame and finishes its
//! side. What is checked, and where the bytes go, is [`crate::outputs`]. A stale epoch also gets `Cancel` on the
//! control stream (SI-8).

use std::sync::Arc;

use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use p2pc_proto::ids::NodeId;
use p2pc_proto::protocol::{
    MAX_FRAME_LEN, ServerMsg, UploadAck, UploadHeader, read_frame_bytes, upload_reason, write_frame,
};

use tokio::sync::OwnedSemaphorePermit;

use super::Inner;
use crate::outputs::{self, Begun};
use crate::scheduler::code;

/// Accepts upload streams on `conn` until it closes; each is handled in its own task.
///
/// A node may have at most `headers_per_node` streams (across its connections) whose header is still being read
/// (review P3): each such read may buffer up to 1 MiB for up to 30 s. A stream beyond that is answered
/// `too_many_uploads` at once, with nothing read from it.
pub(super) async fn accept(inner: Arc<Inner>, conn: Connection, node_id: NodeId) {
    let headers = inner.upload_headers(node_id);
    while let Ok((send, recv)) = conn.accept_bi().await {
        match headers.clone().try_acquire_owned() {
            Ok(permit) => {
                tokio::spawn(handle(inner.clone(), node_id, send, recv, permit));
            }
            Err(_) => {
                let idle = inner.limits.uploads.idle;
                tokio::spawn(answer(
                    send,
                    recv,
                    UploadAck::refused(upload_reason::TOO_MANY_UPLOADS),
                    idle,
                ));
            }
        }
    }
}

async fn handle(
    inner: Arc<Inner>,
    node_id: NodeId,
    send: SendStream,
    mut recv: RecvStream,
    header_slot: OwnedSemaphorePermit,
) {
    let limits = inner.limits.uploads;
    let header = match tokio::time::timeout(limits.idle, read_frame_bytes(&mut recv, MAX_FRAME_LEN)).await {
        Ok(Ok(Some(body))) => match inner.decodes.decode::<UploadHeader>(&body).await {
            Some(Ok(h)) => Some(h),
            _ => None,
        },
        _ => None,
    };
    // The header is read: the slot goes to the next stream (the body is bounded by the upload slots).
    drop(header_slot);
    let ack = match header {
        Some(h) => upload(&inner, node_id, &h, &mut recv).await,
        None => UploadAck::refused(upload_reason::INVALID_HEADER),
    };
    answer(send, recv, ack, limits.idle).await;
}

/// Stops reading `recv`, writes `ack` and finishes the stream, within `idle`.
async fn answer(mut send: SendStream, mut recv: RecvStream, ack: UploadAck, idle: std::time::Duration) {
    // Nothing more is read from this stream.
    let _ = recv.stop(VarInt::from_u32(0));
    let reply = async {
        write_frame(&mut send, &ack).await.ok()?;
        send.finish().ok()?;
        send.stopped().await.ok()
    };
    let _ = tokio::time::timeout(idle, reply).await;
}

async fn upload(inner: &Inner, node_id: NodeId, header: &UploadHeader, recv: &mut RecvStream) -> UploadAck {
    let limits = inner.limits.uploads;
    match inner.state.outputs.begin(node_id, header, &limits).await {
        Ok(Begun::AlreadyStaged) => UploadAck::accepted(),
        Ok(Begun::Receive(u)) => {
            let ack = match outputs::receive(&u, recv, &limits).await {
                Ok(()) => UploadAck::accepted(),
                Err(r) => UploadAck::refused(r.reason),
            };
            let (job_id, attempt) = u.target();
            // The path only at debug level: it names the job's files.
            tracing::debug!(%node_id, %job_id, attempt, ok = ack.ok, reason = ?ack.reason, "upload");
            ack
        }
        Err(r) => {
            if let Some((lease_id, epoch)) = r.cancel {
                let _ = inner.hub().send(
                    node_id,
                    ServerMsg::Cancel {
                        lease_id,
                        epoch,
                        reason: code::STALE_EPOCH.to_string(),
                    },
                );
            }
            UploadAck::refused(r.reason)
        }
    }
}
