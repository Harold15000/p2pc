// SPDX-License-Identifier: Apache-2.0

//! Output uploads (§6 "Uploads", §9 "Outputs", SI-9).
//!
//! Each collected file gets its own bidirectional stream on the agent connection: an `UploadHeader{lease_id, epoch,
//! path, size, sha256}` frame, then exactly `size` raw bytes, then the server's `UploadAck{ok, reason?}`.
//!
//! - **SI-9 on the way out.** The file is opened again with `O_NOFOLLOW` (a symlink swapped in after the collection is
//!   refused), its directory must still resolve to itself (no symlinked directory on the way), the descriptor must be
//!   a regular file, and its size and SHA-256 must still be what the collection measured. The bytes are then sent from
//!   that same descriptor.
//! - **Bounds.** At most [`CONCURRENCY`] files at once. Opening the stream, each write and the finish may stall for
//!   at most [`STALL_TIMEOUT`]; the ack must come within [`ACK_TIMEOUT`] (60 s per file, §6).
//! - **Retries.** A transport error (the stream, a timeout, the connection) gets one retry, and the retry waits for
//!   another session ([`Uplink::changed_from`], at most [`STALL_TIMEOUT`]) so it does not land on the connection that
//!   just failed. Waiting for a connection is not an attempt; a silenced run stops uploading at once.
//! - **Refusals** (`ok: false`, [`upload_reason`]), by class:
//!   - `too_many_uploads` is contention, not a failure: it is retried after a backoff ([`BUSY_BACKOFF_START`],
//!     doubling up to [`BUSY_BACKOFF_MAX`]) for as long as the lease lives, and does not use the one retry;
//!   - `stale_epoch`, `unknown_lease` and `finalized` mean the lease is dead for uploads: every upload of the lease
//!     stops, with no retry ([`Halt`]);
//!   - anything else (`size_mismatch`, `too_large`, `too_many_files`, `invalid_path`, `duplicate_path`, ...) leaves
//!     that file out of `JobFinished.outputs`, is not retried, and its reason is logged once, with the path.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::FileExt as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use p2pc_proto::api::{OutputFile, Sha256Digest};
use p2pc_proto::ids::LeaseId;
use p2pc_proto::protocol::{UploadAck, UploadHeader, read_frame, upload_reason, write_frame};
use rustix::fs::{Mode, OFlags};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use super::outbox::RunOutbox;
use crate::connection::{Port, Uplink};
use crate::sandbox::CollectedFile;

/// Most files uploaded at once.
pub const CONCURRENCY: usize = 2;
/// Longest wait for the server's `UploadAck` once the bytes are sent (§6).
pub const ACK_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest stall of opening the stream, of one write, or of the finish.
pub const STALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest `UploadAck` frame accepted.
pub const MAX_ACK_FRAME: u32 = 16 * 1024;
/// Longest refusal reason kept from the server, in characters.
pub const MAX_REASON_CHARS: usize = 200;
/// How long a failed write waits for an `UploadAck` that may already be on its way (the server refused at once).
pub const EARLY_ACK_WAIT: Duration = Duration::from_secs(5);
/// First wait after `too_many_uploads`.
pub const BUSY_BACKOFF_START: Duration = Duration::from_secs(1);
/// Longest wait after `too_many_uploads`.
pub const BUSY_BACKOFF_MAX: Duration = Duration::from_secs(15);
/// How much is read and written at a time.
const CHUNK: usize = 256 * 1024;

/// The wait after `current` that follows another `too_many_uploads`: doubled, up to [`BUSY_BACKOFF_MAX`].
fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(BUSY_BACKOFF_MAX)
}

/// Whether `reason` says the lease can no longer upload anything.
fn lease_is_dead(reason: &str) -> bool {
    matches!(
        reason,
        upload_reason::STALE_EPOCH | upload_reason::UNKNOWN_LEASE | upload_reason::FINALIZED
    )
}

/// Tripped when the server says the lease is dead for uploads: every upload of the lease stops.
#[derive(Debug, Clone)]
pub struct Halt(Arc<watch::Sender<bool>>);

impl Default for Halt {
    fn default() -> Self {
        Self(Arc::new(watch::channel(false).0))
    }
}

impl Halt {
    fn trip(&self) {
        self.0.send_replace(true);
    }

    fn is_tripped(&self) -> bool {
        *self.0.borrow()
    }

    async fn tripped(&self) {
        let mut rx = self.0.subscribe();
        // The sender lives in `self`: `wait_for` cannot fail while we hold it.
        if rx.wait_for(|t| *t).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// How one file's upload ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Uploaded {
    /// The server stored it.
    Stored,
    /// The server refused it (`ok: false`), with its reason. The file is left out.
    Refused(String),
    /// The server says the lease is dead for uploads (`stale_epoch`, `unknown_lease`, `finalized`), with its reason:
    /// this file is left out and no other file of the lease is uploaded.
    Abandoned(String),
    /// Another file of the lease found it dead for uploads first: not (or no longer) uploaded.
    Halted,
    /// The transport failed twice.
    Failed(String),
    /// The file is no longer what was collected (SI-9): not sent. A short code.
    Changed(&'static str),
    /// The run was silenced first.
    Silenced,
}

/// A file opened again and checked against its collection (SI-9).
#[derive(Debug, Clone)]
struct Verified {
    file: Arc<File>,
    size: u64,
}

/// Opens `host` without following a symlink and checks it is still the regular file of `size` bytes and `sha256`.
fn verify(host: &Path, size: u64, sha256: &Sha256Digest) -> Result<Verified, &'static str> {
    // Every directory on the way must resolve to itself: the collection walked a canonical tree, so a difference means
    // a symlinked directory was swapped in.
    let parent = host.parent().ok_or("invalid_path")?;
    match std::fs::canonicalize(parent) {
        Ok(real) if real == parent => {}
        Ok(_) => return Err("symlink"),
        Err(_) => return Err("unreadable"),
    }
    let fd = match rustix::fs::open(
        host,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::LOOP) => return Err("symlink"),
        Err(_) => return Err("unreadable"),
    };
    let stat = rustix::fs::fstat(&fd).map_err(|_| "unreadable")?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err("not_regular");
    }
    if u64::try_from(stat.st_size).ok() != Some(size) {
        return Err("size_changed");
    }
    let mut file = File::from(fd);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut seen = 0u64;
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
                seen += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err("unreadable"),
        }
    }
    if seen != size {
        return Err("size_changed");
    }
    if Sha256Digest(hasher.finalize().into()) != *sha256 {
        return Err("sha256_changed");
    }
    Ok(Verified {
        file: Arc::new(file),
        size,
    })
}

/// A server's refusal reason, safe to log: no control characters, bounded.
fn clean_reason(reason: Option<String>) -> String {
    let text: String = reason
        .unwrap_or_else(|| "no reason given".into())
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_REASON_CHARS)
        .collect();
    text
}

async fn stall<T, E: std::fmt::Display>(
    what: &str,
    f: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, String> {
    match tokio::time::timeout(STALL_TIMEOUT, f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("{what}: {e}")),
        Err(_) => Err(format!("{what}: timed out")),
    }
}

/// The server's `UploadAck`, waiting at most `wait` for it.
async fn read_ack(r: &mut crate::connection::transport::BoxRead, wait: Duration) -> Result<UploadAck, String> {
    match tokio::time::timeout(wait, read_frame::<UploadAck, _>(r, MAX_ACK_FRAME)).await {
        Ok(Ok(Some(ack))) => Ok(ack),
        Ok(Ok(None)) => Err("the stream ended without an UploadAck".into()),
        Ok(Err(e)) => Err(format!("reading the UploadAck: {e}")),
        Err(_) => Err(format!("no UploadAck within {} s", wait.as_secs())),
    }
}

/// Writes the header and the file's bytes, and finishes the stream.
async fn write_upload(
    w: &mut crate::connection::transport::BoxWrite,
    header: &UploadHeader,
    file: &Verified,
) -> Result<(), String> {
    stall("writing the upload header", write_frame(w, header)).await?;
    let mut offset = 0u64;
    while offset < file.size {
        let want = usize::try_from((file.size - offset).min(CHUNK as u64)).unwrap_or(CHUNK);
        let f = Arc::clone(&file.file);
        let (n, buf) = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; want];
            let n = f.read_at(&mut buf, offset);
            (n, buf)
        })
        .await
        .map_err(|e| format!("reading the file: {e}"))?;
        let n = n.map_err(|e| format!("reading the file: {e}"))?;
        if n == 0 {
            // It shrank since it was verified: the server would refuse it anyway.
            return Err("the file shrank while it was sent".into());
        }
        stall("writing the file", w.write_all(&buf[..n])).await?;
        offset += n as u64;
    }
    stall("finishing the upload stream", w.shutdown()).await
}

/// One attempt: stream, header, bytes, finish, ack. `Err` is a transport error.
///
/// A server that refuses at once (`too_many_uploads`, `finalized`, ...) stops reading the stream and answers; our writes
/// then fail. Its ack is still on the way back, so a failed write reads the ack for a short while before it counts as a
/// transport error: the refusal's reason, not "stream stopped", decides what happens next.
async fn send_once(port: &Port, header: &UploadHeader, file: &Verified) -> Result<UploadAck, String> {
    let (mut w, mut r) = stall("opening the upload stream", port.streams().open_bi()).await?;
    match write_upload(&mut w, header, file).await {
        Ok(()) => read_ack(&mut r, ACK_TIMEOUT).await,
        Err(e) => read_ack(&mut r, EARLY_ACK_WAIT).await.map_err(|_| e),
    }
}

/// Waits `how_long`, unless the run is silenced or the lease halted first (`Some` then, with how it ended).
async fn pause(how_long: Duration, outbox: &RunOutbox, halt: &Halt) -> Option<Uploaded> {
    tokio::select! {
        () = tokio::time::sleep(how_long) => None,
        () = outbox.silenced() => Some(Uploaded::Silenced),
        () = halt.tripped() => Some(Uploaded::Halted),
    }
}

/// Uploads one collected file of lease `(lease_id, epoch)`.
pub async fn upload_one(
    lease_id: LeaseId,
    epoch: u64,
    file: &CollectedFile,
    uplink: &Uplink,
    outbox: &RunOutbox,
    halt: &Halt,
) -> Uploaded {
    let checked = {
        let (host, size, sha) = (file.host_path.clone(), file.size, file.sha256);
        match tokio::task::spawn_blocking(move || verify(&host, size, &sha)).await {
            Ok(Ok(v)) => v,
            Ok(Err(code)) => return Uploaded::Changed(code),
            Err(_) => return Uploaded::Changed("unreadable"),
        }
    };
    let header = UploadHeader {
        lease_id,
        epoch,
        path: file.path.clone(),
        size: file.size,
        sha256: file.sha256,
    };
    let mut transport_errors = 0u32;
    let mut busy = BUSY_BACKOFF_START;
    loop {
        if halt.is_tripped() {
            return Uploaded::Halted;
        }
        let port = tokio::select! {
            port = uplink.connected() => port,
            () = outbox.silenced() => return Uploaded::Silenced,
            () = halt.tripped() => return Uploaded::Halted,
        };
        let result = tokio::select! {
            r = send_once(&port, &header, &checked) => r,
            () = outbox.silenced() => return Uploaded::Silenced,
            () = halt.tripped() => return Uploaded::Halted,
        };
        match result {
            Ok(ack) if ack.ok => return Uploaded::Stored,
            Ok(ack) => {
                let reason = clean_reason(ack.reason);
                if reason == upload_reason::TOO_MANY_UPLOADS {
                    // Contention: try again later, for as long as the lease lives; not an attempt.
                    tracing::debug!(%lease_id, epoch, wait_ms = busy.as_millis(), "the server is busy; waiting to upload again");
                    if let Some(ended) = pause(busy, outbox, halt).await {
                        return ended;
                    }
                    busy = next_backoff(busy);
                } else if lease_is_dead(&reason) {
                    halt.trip();
                    return Uploaded::Abandoned(reason);
                } else {
                    return Uploaded::Refused(reason);
                }
            }
            Err(e) => {
                transport_errors += 1;
                tracing::debug!(%lease_id, epoch, attempt = transport_errors, error = %e, "an output upload failed");
                if transport_errors >= 2 {
                    return Uploaded::Failed(e);
                }
                // The retry must not land on the connection that just failed: wait for another session. If none
                // comes, the connection was fine after all, and the retry goes ahead.
                tokio::select! {
                    _ = tokio::time::timeout(STALL_TIMEOUT, uplink.changed_from(port.session())) => {}
                    () = outbox.silenced() => return Uploaded::Silenced,
                    () = halt.tripped() => return Uploaded::Halted,
                }
            }
        }
    }
}

/// Uploads `files`, at most [`CONCURRENCY`] at once, and returns those the server stored, in path order, for
/// `JobFinished.outputs`. Every file left out is logged at warning level with its path and why.
pub async fn upload_all(
    lease_id: LeaseId,
    epoch: u64,
    files: &[CollectedFile],
    uplink: &Uplink,
    outbox: &Arc<RunOutbox>,
) -> Vec<OutputFile> {
    let slots = Arc::new(Semaphore::new(CONCURRENCY));
    let halt = Halt::default();
    let mut tasks = JoinSet::new();
    for (i, file) in files.iter().enumerate() {
        let (slots, file, uplink, outbox, halt) = (
            slots.clone(),
            file.clone(),
            uplink.clone(),
            outbox.clone(),
            halt.clone(),
        );
        tasks.spawn(async move {
            let Ok(_slot) = slots.acquire_owned().await else {
                return (i, Uploaded::Silenced);
            };
            (i, upload_one(lease_id, epoch, &file, &uplink, &outbox, &halt).await)
        });
    }
    let mut results: Vec<(usize, Uploaded)> = Vec::with_capacity(files.len());
    while let Some(joined) = tasks.join_next().await {
        if let Ok(r) = joined {
            results.push(r);
        }
    }
    results.sort_by_key(|(i, _)| *i);
    let mut stored = Vec::new();
    let mut halted = 0usize;
    let mut abandoned = None;
    for (i, result) in results {
        let file = &files[i];
        match result {
            Uploaded::Stored => stored.push(file.to_wire()),
            Uploaded::Refused(reason) => tracing::warn!(
                %lease_id, epoch, path = %file.path, %reason,
                "the server refused an output; it is left out of JobFinished"
            ),
            Uploaded::Failed(error) => tracing::warn!(
                %lease_id, epoch, path = %file.path, %error,
                "an output could not be uploaded, after one retry; it is left out of JobFinished"
            ),
            Uploaded::Changed(code) => tracing::warn!(
                %lease_id, epoch, path = %file.path, reason = code,
                "an output changed after it was collected (SI-9); it is not uploaded"
            ),
            // Once for the lease, below.
            Uploaded::Abandoned(reason) => {
                halted += 1;
                abandoned.get_or_insert(reason);
            }
            Uploaded::Halted => halted += 1,
            Uploaded::Silenced => {}
        }
    }
    if halted > 0 {
        let reason = abandoned.unwrap_or_default();
        tracing::warn!(
            %lease_id, epoch, %reason, files_left_out = halted,
            "the server says this lease can no longer upload; its remaining outputs are left out of JobFinished"
        );
    }
    stored
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn collected(dir: &Path, name: &str, content: &[u8]) -> CollectedFile {
        let host = std::fs::canonicalize(dir).unwrap().join(name);
        std::fs::write(&host, content).unwrap();
        CollectedFile {
            path: name.into(),
            host_path: host,
            size: content.len() as u64,
            sha256: Sha256Digest(Sha256::digest(content).into()),
        }
    }

    /// SI-9: what is opened for the upload is the collected regular file, unchanged; a symlink swapped in (to a file
    /// or through a directory), a FIFO, or new content are refused before anything is sent.
    #[test]
    fn si9_an_output_swapped_for_a_symlink_is_never_opened_for_upload() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, b"host secret").unwrap();
        let ok = collected(dir.path(), "a.txt", b"hello");
        let v = verify(&ok.host_path, ok.size, &ok.sha256).unwrap();
        assert_eq!(v.size, 5);
        // Replaced by a symlink to a file of the same size after the collection.
        let swapped = collected(dir.path(), "b.txt", b"host secret");
        std::fs::remove_file(&swapped.host_path).unwrap();
        symlink(&secret, &swapped.host_path).unwrap();
        assert_eq!(
            verify(&swapped.host_path, swapped.size, &swapped.sha256).unwrap_err(),
            "symlink"
        );
        // A directory on the way replaced by a symlink.
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let inner = collected(&sub, "c.txt", b"x");
        let moved = dir.path().join("elsewhere");
        std::fs::rename(&sub, &moved).unwrap();
        symlink(&moved, &sub).unwrap();
        assert_eq!(
            verify(&inner.host_path, inner.size, &inner.sha256).unwrap_err(),
            "symlink"
        );
        // New content, same size; another size; a FIFO.
        let edited = collected(dir.path(), "d.txt", b"abc");
        std::fs::write(&edited.host_path, b"xyz").unwrap();
        assert_eq!(
            verify(&edited.host_path, 3, &edited.sha256).unwrap_err(),
            "sha256_changed"
        );
        assert_eq!(
            verify(&edited.host_path, 4, &edited.sha256).unwrap_err(),
            "size_changed"
        );
        let fifo = dir.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let fifo = std::fs::canonicalize(&fifo).unwrap();
        assert_eq!(verify(&fifo, 0, &ok.sha256).unwrap_err(), "not_regular");
    }

    #[test]
    fn the_busy_backoff_doubles_up_to_fifteen_seconds() {
        let mut wait = BUSY_BACKOFF_START;
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(wait.as_secs());
            wait = next_backoff(wait);
        }
        assert_eq!(seen, [1, 2, 4, 8, 15, 15]);
    }

    #[test]
    fn only_the_three_dead_lease_reasons_stop_the_lease() {
        for r in [
            upload_reason::STALE_EPOCH,
            upload_reason::UNKNOWN_LEASE,
            upload_reason::FINALIZED,
        ] {
            assert!(lease_is_dead(r), "{r}");
        }
        for r in [
            upload_reason::TOO_MANY_UPLOADS,
            upload_reason::SIZE_MISMATCH,
            upload_reason::TOO_LARGE,
            upload_reason::TOO_MANY_FILES,
            upload_reason::INVALID_PATH,
            upload_reason::DUPLICATE_PATH,
            upload_reason::INTERNAL,
        ] {
            assert!(!lease_is_dead(r), "{r}");
        }
    }

    /// A server that refuses at once stops reading the stream, so the agent's writes fail while the refusal is
    /// already on its way back: the reason is read, not reported as "stream stopped".
    #[tokio::test]
    async fn a_refusal_is_read_even_when_the_server_stopped_reading() {
        #[derive(Debug)]
        struct Refusing(UploadAck);
        impl crate::connection::transport::StreamOpener for Refusing {
            fn open_bi(
                &self,
            ) -> crate::connection::BoxFuture<
                '_,
                Result<
                    (
                        crate::connection::transport::BoxWrite,
                        crate::connection::transport::BoxRead,
                    ),
                    crate::connection::transport::ConnectError,
                >,
            > {
                let ack = self.0.clone();
                Box::pin(async move {
                    // agent -> server: nobody reads it (the server stopped), so a write fails once the pipe is full.
                    let (to_server, server_rx) = tokio::io::duplex(8);
                    drop(server_rx);
                    // server -> agent: the refusal, written before anything was read.
                    let (mut server_tx, from_server) = tokio::io::duplex(1024);
                    write_frame(&mut server_tx, &ack).await.unwrap();
                    Ok((
                        Box::new(to_server) as crate::connection::transport::BoxWrite,
                        Box::new(from_server) as crate::connection::transport::BoxRead,
                    ))
                })
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let content = vec![7u8; 100_000];
        let file = collected(dir.path(), "big.bin", &content);
        let checked = verify(&file.host_path, file.size, &file.sha256).unwrap();
        let header = UploadHeader {
            lease_id: LeaseId::generate(),
            epoch: 1,
            path: file.path.clone(),
            size: file.size,
            sha256: file.sha256,
        };
        let uplink = Uplink::new();
        let (jobs, _rx) = tokio::sync::mpsc::channel(1);
        let ack = UploadAck {
            ok: false,
            reason: Some(upload_reason::TOO_MANY_UPLOADS.into()),
        };
        uplink.connect(Port::new(&jobs, Arc::new(Refusing(ack.clone()))));
        let port = uplink.connected().await;
        assert_eq!(send_once(&port, &header, &checked).await, Ok(ack));
    }

    #[test]
    fn refusal_reasons_are_cleaned_and_bounded() {
        assert_eq!(clean_reason(Some("bad\nhash\u{1b}[31m".into())), "bad hash [31m");
        assert_eq!(clean_reason(None), "no reason given");
        assert_eq!(clean_reason(Some("x".repeat(1000))).len(), MAX_REASON_CHARS);
    }
}
