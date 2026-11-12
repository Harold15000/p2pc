// SPDX-License-Identifier: Apache-2.0

//! The `BlobFetch` client (H2 §6.1, §7.5): how a lease's blob input reaches the node.
//!
//! Each fetch opens its own bidirectional stream on the agent connection and sends one header frame,
//! `BlobFetch{lease_id, epoch, sha256}` (tagged `"type": "blob_fetch"`, H2 §6.1 "New streams"), then finishes its side.
//! The hub answers `BlobFetchAck{ok, size?, reason?}` and, when `ok`, exactly `size` raw bytes.
//!
//! - **Fencing (SI-H2-6).** A fetch names the lease and epoch it is for; the hub refuses anything but the job's current
//!   lease (`stale_lease`) and a blob the job does not reference (`not_referenced`). A refusal is never retried here:
//!   [`FetchError::Refused`] carries the reason to the caller.
//! - **Integrity.** The bytes are hashed as they arrive. A digest that is not the one asked for is
//!   [`FetchError::Integrity`], whose job error is [`INPUT_INTEGRITY`] (`input_integrity`, a `start_failed`-class
//!   error, H2 §6.1 "Blob integrity"). The caller must then discard what was written.
//! - **Bounds.** At most [`MAX_BLOB_FETCHES_PER_CONNECTION`] fetches at once ([`BlobFetcher`]); the ack frame is at most
//!   [`MAX_ACK_FRAME`] bytes and must come within [`ACK_TIMEOUT`]; a blob larger than the caller's `max_bytes` is refused
//!   before any byte is read; opening the stream, each write and each read may stall for at most [`STALL_TIMEOUT`].
//!   There is no total deadline: a 2 GiB blob over a relay takes about half an hour (H2 §7.5), and a stream that
//!   keeps moving is allowed to finish.
//!
//! Errors never quote the hub's bytes beyond a cleaned, bounded refusal reason.

use std::sync::Arc;
use std::time::Duration;

use p2pc_proto::api::Sha256Digest;
use p2pc_proto::ids::LeaseId;
use p2pc_proto::protocol::{
    AgentStreamHeader, BlobFetch, BlobFetchAck, MAX_BLOB_FETCHES_PER_CONNECTION, blob_fetch_reason, read_frame,
    write_frame,
};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::Semaphore;

use crate::connection::transport::StreamOpener;

/// The job error of a blob whose bytes do not hash to its digest (H2 §6.1).
pub const INPUT_INTEGRITY: &str = "input_integrity";
/// Largest `BlobFetchAck` frame accepted.
pub const MAX_ACK_FRAME: u32 = 16 * 1024;
/// Longest wait for the hub's `BlobFetchAck` once the header is sent.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest stall of opening the stream, of writing the header, or of one read of the blob's bytes.
pub const STALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest refusal reason kept from the hub, in characters.
pub const MAX_REASON_CHARS: usize = 200;
/// How much is read at a time.
const CHUNK: usize = 256 * 1024;

/// Why the hub refused a fetch (`BlobFetchAck.reason`, H2 §6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `(lease_id, epoch)` is not the job's current lease (SI-H2-6).
    StaleLease,
    /// The lease's job does not reference that blob.
    NotReferenced,
    /// The blob no longer exists.
    Gone,
    /// A reason this version does not know: a generic refusal (H2 §6.1), cleaned and bounded for the logs.
    Other(String),
}

impl Refusal {
    fn from_reason(reason: Option<String>) -> Self {
        match reason.as_deref() {
            Some(blob_fetch_reason::STALE_LEASE) => Self::StaleLease,
            Some(blob_fetch_reason::NOT_REFERENCED) => Self::NotReferenced,
            Some(blob_fetch_reason::GONE) => Self::Gone,
            other => Self::Other(clean_reason(other)),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaleLease => f.write_str(blob_fetch_reason::STALE_LEASE),
            Self::NotReferenced => f.write_str(blob_fetch_reason::NOT_REFERENCED),
            Self::Gone => f.write_str(blob_fetch_reason::GONE),
            Self::Other(reason) => write!(f, "refused: {reason}"),
        }
    }
}

/// Why a fetch did not deliver the blob.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The hub refused it (`ok: false`).
    #[error("the hub refused the blob fetch: {0}")]
    Refused(Refusal),
    /// The bytes do not hash to the digest asked for: `input_integrity`.
    #[error("the blob's bytes do not match its digest (input_integrity)")]
    Integrity,
    /// The blob is larger than the caller allows; nothing was read.
    #[error("the blob is {size} bytes, more than the {max} allowed")]
    TooLarge {
        /// The size the hub announced.
        size: u64,
        /// The caller's limit.
        max: u64,
    },
    /// The hub broke the protocol: a malformed or invalid ack, or fewer bytes than announced.
    #[error("blob fetch protocol error: {0}")]
    Protocol(String),
    /// The stream, the connection or a timeout failed. The fetch may be tried again on another connection.
    #[error("blob fetch transport error: {0}")]
    Transport(String),
    /// Writing the bytes locally failed.
    #[error("cannot write the blob: {0}")]
    Write(String),
}

impl FetchError {
    /// The job error this failure maps to, when it has its own code: [`INPUT_INTEGRITY`] for a digest mismatch.
    #[must_use]
    pub fn job_error(&self) -> Option<&'static str> {
        match self {
            Self::Integrity => Some(INPUT_INTEGRITY),
            _ => None,
        }
    }
}

/// One blob to fetch for a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobRequest {
    /// The lease that needs it.
    pub lease_id: LeaseId,
    /// Its epoch.
    pub epoch: u64,
    /// The blob's digest.
    pub sha256: Sha256Digest,
}

/// Fetches blobs, at most [`MAX_BLOB_FETCHES_PER_CONNECTION`] at once. Clones share the bound.
///
/// The bound is per agent, so it holds per connection too (H2 §6.1: 8 concurrent blob fetches per agent connection).
#[derive(Debug, Clone)]
pub struct BlobFetcher {
    permits: Arc<Semaphore>,
}

impl Default for BlobFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobFetcher {
    /// A fetcher with the spec's bound.
    #[must_use]
    pub fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(MAX_BLOB_FETCHES_PER_CONNECTION)),
        }
    }

    /// Fetches `request` over a new stream of `streams` into `dest`, refusing a blob of more than `max_bytes`. Returns
    /// the blob's size once every byte is written, flushed and verified. Waits for a slot when
    /// [`MAX_BLOB_FETCHES_PER_CONNECTION`] fetches are in progress.
    ///
    /// # Errors
    /// See [`FetchError`]. On any error, what was already written to `dest` must be discarded by the caller.
    pub async fn fetch(
        &self,
        streams: &dyn StreamOpener,
        request: BlobRequest,
        max_bytes: u64,
        dest: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<u64, FetchError> {
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| FetchError::Transport("the fetcher is closed".into()))?;
        fetch_once(streams, request, max_bytes, dest).await
    }
}

/// A hub's refusal reason, safe to log: no control characters, bounded.
fn clean_reason(reason: Option<&str>) -> String {
    reason
        .unwrap_or("no reason given")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_REASON_CHARS)
        .collect()
}

async fn stall<T, E: std::fmt::Display>(
    what: &str,
    f: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, FetchError> {
    match tokio::time::timeout(STALL_TIMEOUT, f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(FetchError::Transport(format!("{what}: {e}"))),
        Err(_) => Err(FetchError::Transport(format!("{what}: timed out"))),
    }
}

/// The hub's `BlobFetchAck`, checked.
async fn read_ack(r: &mut (dyn AsyncRead + Send + Unpin)) -> Result<BlobFetchAck, FetchError> {
    let ack = match tokio::time::timeout(ACK_TIMEOUT, read_frame::<BlobFetchAck, _>(r, MAX_ACK_FRAME)).await {
        Ok(Ok(Some(ack))) => ack,
        Ok(Ok(None)) => return Err(FetchError::Protocol("the stream ended without a BlobFetchAck".into())),
        Ok(Err(e)) => return Err(FetchError::Protocol(format!("reading the BlobFetchAck: {e}"))),
        Err(_) => {
            return Err(FetchError::Transport(format!(
                "no BlobFetchAck within {} s",
                ACK_TIMEOUT.as_secs()
            )));
        }
    };
    ack.validate()
        .map_err(|e| FetchError::Protocol(format!("invalid BlobFetchAck: {e}")))?;
    Ok(ack)
}

/// Copies exactly `size` bytes from `r` to `dest`, hashing them, and checks the digest.
async fn copy_verified(
    r: &mut (dyn AsyncRead + Send + Unpin),
    size: u64,
    sha256: &Sha256Digest,
    dest: &mut (dyn AsyncWrite + Send + Unpin),
) -> Result<(), FetchError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut left = size;
    while left > 0 {
        let want = usize::try_from(left.min(CHUNK as u64)).unwrap_or(CHUNK);
        let n = stall("reading the blob", r.read(&mut buf[..want])).await?;
        if n == 0 {
            return Err(FetchError::Protocol(format!(
                "the stream ended {left} bytes short of the announced {size}"
            )));
        }
        hasher.update(&buf[..n]);
        dest.write_all(&buf[..n])
            .await
            .map_err(|e| FetchError::Write(e.to_string()))?;
        left -= n as u64;
    }
    dest.flush().await.map_err(|e| FetchError::Write(e.to_string()))?;
    if Sha256Digest(hasher.finalize().into()) != *sha256 {
        return Err(FetchError::Integrity);
    }
    Ok(())
}

async fn fetch_once(
    streams: &dyn StreamOpener,
    request: BlobRequest,
    max_bytes: u64,
    dest: &mut (dyn AsyncWrite + Send + Unpin),
) -> Result<u64, FetchError> {
    let (mut w, mut r) = stall("opening the blob stream", streams.open_bi()).await?;
    let header = AgentStreamHeader::BlobFetch(BlobFetch {
        lease_id: request.lease_id,
        epoch: request.epoch,
        sha256: request.sha256,
    });
    stall("writing the BlobFetch header", write_frame(&mut w, &header)).await?;
    // Nothing more goes this way: the hub sees the end of our side at once.
    stall("finishing the BlobFetch stream", w.shutdown()).await?;
    let ack = read_ack(&mut *r).await?;
    if !ack.ok {
        return Err(FetchError::Refused(Refusal::from_reason(ack.reason)));
    }
    let size = ack
        .size
        .ok_or_else(|| FetchError::Protocol("an accepted BlobFetchAck without a size".into()))?;
    if size > max_bytes {
        return Err(FetchError::TooLarge { size, max: max_bytes });
    }
    copy_verified(&mut *r, size, &request.sha256, dest).await?;
    Ok(size)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use p2pc_proto::protocol::{MAX_FRAME_LEN, read_frame_bytes};
    use serde_json::{Value, json};
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf};
    use tokio::sync::mpsc;

    use super::*;
    use crate::connection::BoxFuture;
    use crate::connection::transport::{BoxRead, BoxWrite, ConnectError};

    /// The hub's end of one stream the agent opened.
    struct HubEnd {
        r: ReadHalf<DuplexStream>,
        w: WriteHalf<DuplexStream>,
    }

    impl HubEnd {
        /// The header frame, as JSON.
        async fn header(&mut self) -> Value {
            let body = read_frame_bytes(&mut self.r, MAX_FRAME_LEN).await.unwrap().unwrap();
            serde_json::from_slice(&body).unwrap()
        }

        async fn ack(&mut self, ack: Value) {
            write_frame(&mut self.w, &ack).await.unwrap();
        }

        async fn bytes(&mut self, data: &[u8]) {
            self.w.write_all(data).await.unwrap();
        }
    }

    /// Opens in-memory streams and hands their hub end to the test.
    #[derive(Debug)]
    struct Pipes {
        hub: mpsc::UnboundedSender<HubEnd>,
        opened: AtomicUsize,
    }

    impl std::fmt::Debug for HubEnd {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("HubEnd")
        }
    }

    impl StreamOpener for Pipes {
        fn open_bi(&self) -> BoxFuture<'_, Result<(BoxWrite, BoxRead), ConnectError>> {
            Box::pin(async move {
                self.opened.fetch_add(1, Ordering::SeqCst);
                let (agent, hub) = tokio::io::duplex(1024 * 1024);
                let (ar, aw) = tokio::io::split(agent);
                let (hr, hw) = tokio::io::split(hub);
                let _ = self.hub.send(HubEnd { r: hr, w: hw });
                Ok((Box::new(aw) as BoxWrite, Box::new(ar) as BoxRead))
            })
        }
    }

    fn pipes() -> (Arc<Pipes>, mpsc::UnboundedReceiver<HubEnd>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Arc::new(Pipes {
                hub: tx,
                opened: AtomicUsize::new(0),
            }),
            rx,
        )
    }

    fn digest(data: &[u8]) -> Sha256Digest {
        Sha256Digest(Sha256::digest(data).into())
    }

    fn request(data: &[u8]) -> BlobRequest {
        BlobRequest {
            lease_id: LeaseId::generate(),
            epoch: 3,
            sha256: digest(data),
        }
    }

    /// Runs one fetch against a hub scripted by `hub`, and returns its result and what was written.
    async fn fetch_with<F, Fut>(req: BlobRequest, max: u64, hub: F) -> (Result<u64, FetchError>, Vec<u8>)
    where
        F: FnOnce(HubEnd) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let (streams, mut ends) = pipes();
        let script = tokio::spawn(async move {
            let end = ends.recv().await.unwrap();
            hub(end).await;
        });
        let mut out = Vec::new();
        let result = BlobFetcher::new().fetch(&*streams, req, max, &mut out).await;
        script.abort();
        (result, out)
    }

    #[tokio::test]
    async fn the_header_names_the_lease_and_the_blob_and_the_bytes_are_delivered_verified() {
        let data = b"some audio bytes".repeat(1000);
        let req = request(&data);
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let body = data.clone();
        let (result, out) = fetch_with(req, 1 << 20, move |mut hub| async move {
            let header = hub.header().await;
            let _ = seen_tx.send(header);
            hub.ack(json!({"ok": true, "size": body.len()})).await;
            hub.bytes(&body).await;
            // The hub keeps the stream open: the agent stops reading after `size` bytes.
            std::future::pending::<()>().await;
        })
        .await;
        assert_eq!(result, Ok(data.len() as u64));
        assert_eq!(out, data);
        let header = seen_rx.await.unwrap();
        assert_eq!(
            header,
            json!({
                "type": "blob_fetch",
                "lease_id": req.lease_id,
                "epoch": 3,
                "sha256": req.sha256.to_string(),
            })
        );
    }

    /// H2 §6.1 "Blob integrity": bytes that do not hash to the digest are refused with `input_integrity`.
    #[tokio::test]
    async fn bytes_that_do_not_match_the_digest_are_input_integrity() {
        let req = request(b"the real blob");
        let (result, _) = fetch_with(req, 1 << 20, |mut hub| async move {
            let _ = hub.header().await;
            hub.ack(json!({"ok": true, "size": 13})).await;
            hub.bytes(b"a forged blob").await;
            std::future::pending::<()>().await;
        })
        .await;
        let err = result.unwrap_err();
        assert_eq!(err, FetchError::Integrity);
        assert_eq!(err.job_error(), Some("input_integrity"));
    }

    #[tokio::test]
    async fn refusals_carry_their_reason_and_are_never_retried() {
        for (reason, expected) in [
            ("stale_lease", Refusal::StaleLease),
            ("not_referenced", Refusal::NotReferenced),
            ("gone", Refusal::Gone),
            ("from_a_newer_hub", Refusal::Other("from_a_newer_hub".into())),
        ] {
            let (streams, mut ends) = pipes();
            let script = tokio::spawn(async move {
                let mut hub = ends.recv().await.unwrap();
                let _ = hub.header().await;
                hub.ack(json!({"ok": false, "reason": reason})).await;
                std::future::pending::<()>().await;
            });
            let mut out = Vec::new();
            let result = BlobFetcher::new()
                .fetch(&*streams, request(b"x"), 1 << 20, &mut out)
                .await;
            script.abort();
            assert_eq!(result, Err(FetchError::Refused(expected)), "{reason}");
            assert_eq!(result.unwrap_err().job_error(), None);
            assert_eq!(
                streams.opened.load(Ordering::SeqCst),
                1,
                "{reason}: one stream, no retry"
            );
            assert!(out.is_empty());
        }
    }

    #[tokio::test]
    async fn a_blob_larger_than_allowed_is_refused_before_any_byte_is_read() {
        let req = request(b"0123456789");
        let (result, out) = fetch_with(req, 9, |mut hub| async move {
            let _ = hub.header().await;
            hub.ack(json!({"ok": true, "size": 10})).await;
            hub.bytes(b"0123456789").await;
            std::future::pending::<()>().await;
        })
        .await;
        assert_eq!(result, Err(FetchError::TooLarge { size: 10, max: 9 }));
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn a_short_stream_and_a_bad_ack_are_protocol_errors() {
        let req = request(b"0123456789");
        let (result, _) = fetch_with(req, 1 << 20, |mut hub| async move {
            let _ = hub.header().await;
            hub.ack(json!({"ok": true, "size": 10})).await;
            hub.bytes(b"01234").await;
            // The hub ends its side early.
        })
        .await;
        assert!(matches!(result, Err(FetchError::Protocol(_))), "{result:?}");
        for ack in [
            json!({"ok": true}),
            json!({"ok": false}),
            json!({"ok": true, "size": 1, "reason": "gone"}),
            json!({"ok": false, "reason": "a bell\u{7}"}),
            json!({"nonsense": 1}),
        ] {
            let (result, _) = fetch_with(req, 1 << 20, move |mut hub| async move {
                let _ = hub.header().await;
                hub.ack(ack).await;
                std::future::pending::<()>().await;
            })
            .await;
            assert!(matches!(result, Err(FetchError::Protocol(_))), "{result:?}");
        }
        // No ack at all: the stream ends.
        let (result, _) = fetch_with(req, 1 << 20, |mut hub| async move {
            let _ = hub.header().await;
        })
        .await;
        assert!(matches!(result, Err(FetchError::Protocol(_))), "{result:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_hub_times_out_on_the_ack_and_on_a_stalled_body() {
        let req = request(b"0123456789");
        let (result, _) = fetch_with(req, 1 << 20, |mut hub| async move {
            let _ = hub.header().await;
            std::future::pending::<()>().await;
        })
        .await;
        assert!(
            matches!(result, Err(FetchError::Transport(ref e)) if e.contains("BlobFetchAck")),
            "{result:?}"
        );
        let (result, _) = fetch_with(req, 1 << 20, |mut hub| async move {
            let _ = hub.header().await;
            hub.ack(json!({"ok": true, "size": 10})).await;
            hub.bytes(b"01234").await;
            std::future::pending::<()>().await;
        })
        .await;
        assert!(
            matches!(result, Err(FetchError::Transport(ref e)) if e.contains("timed out")),
            "{result:?}"
        );
    }

    /// H2 §6.1 "Limits": at most 8 blob fetches at once; the ninth waits for a slot.
    #[tokio::test]
    async fn at_most_eight_fetches_run_at_once() {
        let (streams, mut ends) = pipes();
        let fetcher = BlobFetcher::new();
        let mut held = Vec::new();
        let mut fetches = Vec::new();
        for _ in 0..=MAX_BLOB_FETCHES_PER_CONNECTION {
            let (fetcher, streams) = (fetcher.clone(), streams.clone());
            fetches.push(tokio::spawn(async move {
                let mut out = Vec::new();
                fetcher.fetch(&*streams, request(b""), 0, &mut out).await
            }));
        }
        for _ in 0..MAX_BLOB_FETCHES_PER_CONNECTION {
            let end = ends.recv().await.unwrap();
            held.push(end);
        }
        // Give the ninth every chance to open a stream: it must not.
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert_eq!(streams.opened.load(Ordering::SeqCst), MAX_BLOB_FETCHES_PER_CONNECTION);
        assert!(ends.try_recv().is_err());
        // One ends: the ninth gets its slot.
        let mut first = held.remove(0);
        let _ = first.header().await;
        first.ack(json!({"ok": true, "size": 0})).await;
        let mut ninth = ends.recv().await.unwrap();
        let _ = ninth.header().await;
        assert_eq!(
            streams.opened.load(Ordering::SeqCst),
            MAX_BLOB_FETCHES_PER_CONNECTION + 1
        );
        for f in fetches {
            f.abort();
        }
    }
}
