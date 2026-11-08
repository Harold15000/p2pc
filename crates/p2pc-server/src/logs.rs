// SPDX-License-Identifier: AGPL-3.0-only

//! Job logs (spec §7, §12): the [`LogSink`] that stores the fenced `LogChunk`s T06 forwards, and the reads behind
//! `GET /v1/jobs/{id}/logs`.
//!
//! - One NDJSON file per attempt, `<data>/logs/<job_id>/<attempt>.ndjson`, one [`LogLine`] per line, `data` as lossy
//!   UTF-8. Directories are `0700`, files `0600`, and no link is followed ([`crate::fsutil`]).
//! - **Deduplicated** by `seq`: a chunk whose `seq` is not above the last one stored is dropped; a gap is allowed. The
//!   last `seq` is read back from the file when a writer opens it, so a server restart does not store a resent chunk
//!   twice.
//! - **Capped** at [`MAX_LOG_BYTES_PER_ATTEMPT`] of NDJSON per attempt: the chunk that would pass the cap is replaced
//!   by one marker line (`stderr`, [`LOG_TRUNCATED_MESSAGE`]) and everything after it is dropped.
//! - **One writer task per attempt**, fed by a bounded queue (the agent's control stream waits when it is full), with
//!   buffered appends flushed whenever the queue is empty, so followers see lines promptly. The file is fsynced when
//!   the attempt ends ([`LogStore::end_attempt`], called when `JobFinished` is handled), and when the writer closes
//!   after [`WRITER_IDLE`] without chunks (an attempt that ended otherwise: lost, cancelled or timed out by the
//!   server, whose chunks are fenced from then on).

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use p2pc_proto::api::{LOG_TRUNCATED_MESSAGE, LogLine, LogStream, MAX_LOG_BYTES_PER_ATTEMPT};
use p2pc_proto::ids::JobId;
use tokio::sync::{mpsc, oneshot, watch};

use crate::fsutil;
use crate::gateway::BoxFuture;
use crate::scheduler::{LogChunk, LogSink};

/// The directory under the data dir.
pub const LOGS_DIR: &str = "logs";
/// A writer with no chunk for this long flushes, fsyncs and stops (the next chunk starts another).
pub const WRITER_IDLE: Duration = Duration::from_secs(60);
/// Chunks queued per attempt before the sender waits.
const QUEUE: usize = 64;
/// The most bytes one read returns. A stored line is at most ~400 KiB (a 64 KiB chunk, JSON-escaped), so a read
/// always holds at least one whole line.
pub const READ_CHUNK: usize = 1024 * 1024;

type Key = (JobId, u32);

/// The log store. Cheap to clone; every clone shares the writers.
#[derive(Debug, Clone)]
pub struct LogStore {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    data_dir: PathBuf,
    cap: u64,
    idle: Duration,
    attempts: Mutex<HashMap<Key, Entry>>,
}

/// What the store keeps per attempt while a writer runs or someone follows it.
#[derive(Debug)]
struct Entry {
    /// The running writer's queue.
    tx: Option<mpsc::Sender<Cmd>>,
    /// Bumped by the writer after each flush; followers wait on it.
    flushed: watch::Sender<u64>,
    /// Held by a writer for its whole life: a new writer waits until the previous one has flushed and closed.
    file: Arc<tokio::sync::Mutex<()>>,
    /// Which writer `tx` belongs to.
    generation: u64,
}

#[derive(Debug)]
enum Cmd {
    Chunk(LogChunk),
    /// Flush what is buffered; answer when done.
    Flush(oneshot::Sender<()>),
    /// Flush, fsync and stop; answer when done.
    Close(oneshot::Sender<()>),
    /// Tests only: the writer dies the way a panicking one does, dropping its queue's receiver without clearing the
    /// store's sender. Answers once the receiver is gone.
    #[cfg(test)]
    Die(oneshot::Sender<()>),
}

impl LogStore {
    /// The store of the data dir `data_dir`, with the spec's cap.
    #[must_use]
    pub fn new(data_dir: &Path) -> Self {
        Self::with_limits(data_dir, MAX_LOG_BYTES_PER_ATTEMPT, WRITER_IDLE)
    }

    /// With another cap and writer idle time (tests).
    #[must_use]
    pub fn with_limits(data_dir: &Path, cap: u64, idle: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                data_dir: data_dir.to_path_buf(),
                cap,
                idle,
                attempts: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn attempts(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Entry>> {
        self.inner.attempts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The file of an attempt, for the GC and tests.
    #[must_use]
    pub fn path(&self, job_id: JobId, attempt: u32) -> PathBuf {
        self.inner
            .data_dir
            .join(LOGS_DIR)
            .join(job_id.to_string())
            .join(file_name(attempt))
    }

    /// The directory of a job's logs.
    #[must_use]
    pub fn job_dir(&self, job_id: JobId) -> PathBuf {
        self.inner.data_dir.join(LOGS_DIR).join(job_id.to_string())
    }

    /// Removes the directory of a job's logs, following no link, not even one in front of it. Blocking: call it from
    /// `spawn_blocking`. Whether something was removed.
    pub fn remove_job(&self, job_id: JobId) -> std::io::Result<bool> {
        fsutil::remove_tree(&self.inner.data_dir, &[LOGS_DIR, job_id.to_string().as_str()])
    }

    /// Stores one chunk (through the attempt's writer, started if needed).
    pub async fn append(&self, job_id: JobId, attempt: u32, chunk: LogChunk) {
        let mut cmd = Cmd::Chunk(chunk);
        // A writer that just stopped refuses the command; the next round starts another. A writer never stops while
        // its queue is open, so this ends.
        loop {
            let tx = self.writer((job_id, attempt));
            match tx.send(cmd).await {
                Ok(()) => return,
                Err(mpsc::error::SendError(back)) => cmd = back,
            }
        }
    }

    /// Flushes what the attempt's writer has buffered (nothing if none runs).
    pub async fn flush(&self, job_id: JobId, attempt: u32) {
        self.command((job_id, attempt), Cmd::Flush).await;
    }

    /// The attempt ended: flush, fsync and stop its writer.
    pub async fn end_attempt(&self, job_id: JobId, attempt: u32) {
        self.command((job_id, attempt), Cmd::Close).await;
    }

    async fn command(&self, key: Key, make: fn(oneshot::Sender<()>) -> Cmd) {
        let tx = self.attempts().get(&key).and_then(|e| e.tx.clone());
        let Some(tx) = tx else { return };
        let (ack, done) = oneshot::channel();
        if tx.send(make(ack)).await.is_ok() {
            let _ = done.await;
        }
        // Refused: that writer is stopping, and flushes and fsyncs before it lets the next one open the file.
    }

    /// A receiver that changes whenever the attempt's file grew (followers wait on it). Subscribe before reading, so
    /// that no flush is missed.
    #[must_use]
    pub fn subscribe(&self, job_id: JobId, attempt: u32) -> Follow {
        let rx = self.with_entry((job_id, attempt), |e| e.flushed.subscribe());
        Follow {
            store: self.clone(),
            key: (job_id, attempt),
            rx: Some(rx),
        }
    }

    /// Runs `f` on the entry of `key`, created if missing, under the map's lock.
    fn with_entry<R>(&self, key: Key, f: impl FnOnce(&mut Entry) -> R) -> R {
        let mut map = self.attempts();
        let e = map.entry(key).or_insert_with(|| Entry {
            tx: None,
            flushed: watch::channel(0).0,
            file: Arc::new(tokio::sync::Mutex::new(())),
            generation: 0,
        });
        f(e)
    }

    /// The running writer's queue, started if none runs.
    fn writer(&self, key: Key) -> mpsc::Sender<Cmd> {
        let started = self.with_entry(key, |e| {
            // A closed queue whose writer did not clear it (it panicked) counts as none: start another, so a sender
            // never loops on a dead queue.
            if let Some(tx) = e.tx.as_ref().filter(|tx| !tx.is_closed()) {
                return (tx.clone(), None);
            }
            let (tx, rx) = mpsc::channel(QUEUE);
            e.generation += 1;
            e.tx = Some(tx.clone());
            let task = Writer {
                store: self.clone(),
                key,
                generation: e.generation,
                flushed: e.flushed.clone(),
                file_lock: e.file.clone(),
            };
            (tx, Some((task, rx)))
        });
        let (tx, task) = started;
        if let Some((task, rx)) = task {
            tokio::spawn(task.run(rx));
        }
        tx
    }

    /// Drops the entry of `key` when nothing uses it any more.
    fn forget_if_unused(&self, key: Key) {
        let mut map = self.attempts();
        if let Some(e) = map.get(&key)
            && e.tx.is_none()
            && e.flushed.receiver_count() == 0
            && Arc::strong_count(&e.file) == 1
        {
            map.remove(&key);
        }
    }

    /// Reads the whole lines stored for the attempt from byte `offset`, at most [`READ_CHUNK`] bytes, keeping only
    /// lines with `seq >= since_seq`. Returns them (NDJSON, each ending in `\n`) and the offset after the last whole
    /// line read. A missing file reads as empty.
    pub async fn read(&self, job_id: JobId, attempt: u32, offset: u64, since_seq: u64) -> std::io::Result<LogRead> {
        let dir = self.inner.data_dir.clone();
        tokio::task::spawn_blocking(move || read_lines(&dir, job_id, attempt, offset, since_seq))
            .await
            .map_err(std::io::Error::other)?
    }

    /// Tests only: kills the attempt's writer like a panic would (its queue is closed, the store still holds the
    /// sender). Returns once the writer's receiver is dropped.
    #[cfg(test)]
    pub(crate) async fn kill_writer(&self, job_id: JobId, attempt: u32) {
        let tx = self.attempts().get(&(job_id, attempt)).and_then(|e| e.tx.clone());
        let Some(tx) = tx else { return };
        let (ack, done) = oneshot::channel();
        if tx.send(Cmd::Die(ack)).await.is_ok() {
            let _ = done.await;
        }
    }

    /// Whether a writer runs for the attempt (tests).
    #[must_use]
    pub fn writing(&self, job_id: JobId, attempt: u32) -> bool {
        self.attempts().get(&(job_id, attempt)).is_some_and(|e| e.tx.is_some())
    }
}

impl LogSink for LogStore {
    fn on_chunk(&self, job_id: JobId, attempt: u32, chunk: LogChunk) -> BoxFuture<'_, ()> {
        Box::pin(self.append(job_id, attempt, chunk))
    }
}

/// What [`LogStore::read`] returns.
#[derive(Debug, Default)]
pub struct LogRead {
    /// Whole NDJSON lines with `seq >= since_seq`.
    pub lines: Vec<u8>,
    /// The offset after the last whole line read (filtered out or not).
    pub next: u64,
}

/// A follower's subscription; dropping it lets the store forget an idle attempt.
#[derive(Debug)]
pub struct Follow {
    store: LogStore,
    key: Key,
    rx: Option<watch::Receiver<u64>>,
}

impl Follow {
    /// Waits until the file grew.
    pub async fn changed(&mut self) {
        match self.rx.as_mut() {
            Some(rx) => {
                if rx.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
            None => std::future::pending().await,
        }
    }
}

impl Drop for Follow {
    fn drop(&mut self) {
        drop(self.rx.take());
        self.store.forget_if_unused(self.key);
    }
}

fn file_name(attempt: u32) -> String {
    format!("{attempt}.ndjson")
}

fn read_lines(dir: &Path, job_id: JobId, attempt: u32, offset: u64, since_seq: u64) -> std::io::Result<LogRead> {
    let job = job_id.to_string();
    let mut file = match fsutil::open_dir(dir, [LOGS_DIR, job.as_str()], false)
        .and_then(|d| fsutil::open_read(&d, &file_name(attempt)))
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LogRead {
                lines: Vec::new(),
                next: offset,
            });
        }
        Err(e) => return Err(e),
    };
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = Vec::new();
    file.take(READ_CHUNK as u64).read_to_end(&mut buf)?;
    let whole = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    buf.truncate(whole);
    let next = offset + whole as u64;
    let mut lines = Vec::with_capacity(buf.len());
    for line in buf.split_inclusive(|b| *b == b'\n') {
        match serde_json::from_slice::<SeqOnly>(line) {
            Ok(l) if l.seq < since_seq => {}
            Ok(_) => lines.extend_from_slice(line),
            // Not ours (the file was edited): skipped, never served.
            Err(_) => {}
        }
    }
    Ok(LogRead { lines, next })
}

/// Only the `seq` of a stored line.
#[derive(serde::Deserialize)]
struct SeqOnly {
    seq: u64,
}

/// One attempt's writer task.
struct Writer {
    store: LogStore,
    key: Key,
    generation: u64,
    flushed: watch::Sender<u64>,
    file_lock: Arc<tokio::sync::Mutex<()>>,
}

/// The open file and what was read back from it.
struct Open {
    out: std::fs::File,
    /// Dedup and cap bookkeeping, kept on the async side: encoding a chunk never touches the file.
    state: LogState,
    /// Encoded lines not written yet: written, in one go, by the next flush on the blocking pool (review P3: a line
    /// over 64 KiB never makes a blocking `write` on an async worker).
    pending: Vec<u8>,
}

/// What a writer knows of its file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LogState {
    /// NDJSON bytes stored, or encoded and about to be.
    bytes: u64,
    /// The last `seq` stored (`None` for an empty file).
    last_seq: Option<u64>,
    /// The truncation marker is written.
    truncated: bool,
}

impl Writer {
    async fn run(self, mut rx: mpsc::Receiver<Cmd>) {
        let Writer {
            store,
            key,
            generation,
            flushed,
            file_lock,
        } = self;
        // After the previous writer of this file has flushed and closed it.
        let guard = file_lock.lock_owned().await;
        let (job_id, attempt) = key;
        let dir = store.inner.data_dir.clone();
        let opened = tokio::task::spawn_blocking(move || open(&dir, job_id, attempt))
            .await
            .map_err(std::io::Error::other)
            .and_then(|r| r);
        let mut file = match opened {
            Ok(f) => Some(f),
            Err(e) => {
                // Chunks are dropped until the writer stops; the next one tries again.
                tracing::warn!(error = %e, %job_id, attempt, "cannot open a log file; dropping its chunks");
                None
            }
        };
        let cap = store.inner.cap;
        let mut acks: Vec<oneshot::Sender<()>> = Vec::new();
        let mut closing = false;
        while !closing {
            let cmd = match tokio::time::timeout(store.inner.idle, rx.recv()).await {
                Ok(Some(cmd)) => cmd,
                // Idle, or every sender is gone: stop.
                Ok(None) | Err(_) => break,
            };
            let mut next = Some(cmd);
            while let Some(cmd) = next.take().or_else(|| rx.try_recv().ok()) {
                match cmd {
                    Cmd::Chunk(c) => {
                        if let Some(f) = file.as_mut() {
                            encode_chunk(&mut f.state, &mut f.pending, c, cap);
                        }
                    }
                    Cmd::Flush(ack) => acks.push(ack),
                    Cmd::Close(ack) => {
                        acks.push(ack);
                        closing = true;
                    }
                    #[cfg(test)]
                    Cmd::Die(ack) => {
                        drop(rx);
                        let _ = ack.send(());
                        return;
                    }
                }
            }
            if closing {
                break;
            }
            file = flush(file, job_id, attempt).await;
            flushed.send_modify(|n| *n += 1);
            for ack in acks.drain(..) {
                let _ = ack.send(());
            }
        }
        // Stop taking commands (a sender that is refused starts the next writer, which waits for this one), then
        // store what is already queued.
        {
            let mut map = store.attempts();
            if let Some(e) = map.get_mut(&key)
                && e.generation == generation
            {
                e.tx = None;
            }
        }
        rx.close();
        while let Some(cmd) = rx.recv().await {
            match cmd {
                Cmd::Chunk(c) => {
                    if let Some(f) = file.as_mut() {
                        encode_chunk(&mut f.state, &mut f.pending, c, cap);
                    }
                }
                Cmd::Flush(ack) | Cmd::Close(ack) => acks.push(ack),
                #[cfg(test)]
                Cmd::Die(ack) => acks.push(ack),
            }
        }
        if let Some(mut f) = file {
            let r = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                f.out.write_all(&f.pending)?;
                f.out.sync_all()
            })
            .await
            .map_err(std::io::Error::other)
            .and_then(|r| r);
            if let Err(e) = r {
                tracing::warn!(error = %e, %job_id, attempt, "cannot write or fsync a log file");
            }
        }
        flushed.send_modify(|n| *n += 1);
        drop(flushed);
        drop(guard);
        store.forget_if_unused(key);
        for ack in acks {
            let _ = ack.send(());
        }
    }
}

/// Writes the encoded lines on the blocking pool; the file is dropped (and its chunks with it) on an error.
async fn flush(file: Option<Open>, job_id: JobId, attempt: u32) -> Option<Open> {
    let mut f = file?;
    if f.pending.is_empty() {
        return Some(f);
    }
    let r = tokio::task::spawn_blocking(move || {
        f.out.write_all(&f.pending)?;
        f.pending.clear();
        Ok::<Open, std::io::Error>(f)
    })
    .await
    .map_err(std::io::Error::other)
    .and_then(|r| r);
    match r {
        Ok(f) => Some(f),
        Err(e) => {
            tracing::warn!(error = %e, %job_id, attempt, "cannot write a log file; dropping its chunks");
            None
        }
    }
}

/// How far back from its end a writer reads an existing file to find its last line (review P3: never the whole
/// file, up to 64 MiB). A stored line is at most ~400 KiB, so the tail always holds the last whole one.
const READ_BACK: u64 = 1024 * 1024;

/// The member that marks the truncation line. A job cannot produce it: its output is always inside `data`, a JSON
/// string. Readers ignore unknown members, so the line is still a plain [`LogLine`] to them.
const TRUNCATED_MEMBER: &str = "truncated";

/// Opens (or creates) the attempt's file and reads back, from its last [`READ_BACK`] bytes only (the size comes from
/// `fstat`), its last `seq` and whether it is truncated. A last line cut short (a crash mid-write) is removed.
fn open(dir: &Path, job_id: JobId, attempt: u32) -> std::io::Result<Open> {
    let job = job_id.to_string();
    let d = fsutil::open_dir(dir, [LOGS_DIR, job.as_str()], true)?;
    let mut file = fsutil::open_append(&d, &file_name(attempt))?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(READ_BACK);
    let mut tail = Vec::new();
    file.seek(SeekFrom::Start(start))?;
    (&mut file).take(READ_BACK).read_to_end(&mut tail)?;
    // Read back from the middle of the file: the first, partial line is not ours to judge.
    let first = if start == 0 {
        0
    } else {
        tail.iter().position(|b| *b == b'\n').map_or(tail.len(), |i| i + 1)
    };
    let whole = tail.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1).max(first);
    let bytes = start + whole as u64;
    if bytes < len {
        file.set_len(bytes)?;
    }
    let state = last_line_state(&tail[first..whole], bytes);
    Ok(Open {
        out: file,
        state,
        pending: Vec::new(),
    })
}

/// The state after the whole lines `lines` (the end of a file of `bytes` bytes): the `seq` of the last line that is a
/// log record, and whether it is the truncation marker (by its [`TRUNCATED_MEMBER`], never by its text).
fn last_line_state(lines: &[u8], bytes: u64) -> LogState {
    let mut state = LogState {
        bytes,
        ..LogState::default()
    };
    for line in lines.split(|b| *b == b'\n').rev().filter(|l| !l.is_empty()) {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(line)
            && let Some(seq) = v.get("seq").and_then(serde_json::Value::as_u64)
        {
            state.last_seq = Some(seq);
            state.truncated = v.get(TRUNCATED_MEMBER) == Some(&serde_json::Value::Bool(true));
            break;
        }
    }
    state
}

/// Encodes one chunk into `out`: deduplicated by `seq`, capped. The chunk that would pass the cap is replaced by the
/// marker line, which carries [`TRUNCATED_MEMBER`]; everything after it is dropped.
fn encode_chunk(state: &mut LogState, out: &mut Vec<u8>, chunk: LogChunk, cap: u64) {
    if state.last_seq.is_some_and(|last| chunk.seq <= last) || state.truncated {
        return;
    }
    // Validated by the gateway (at most 64 KiB, standard base64); a chunk that does not decode is dropped.
    let Ok(bytes) = data_encoding::BASE64.decode(chunk.data_b64.0.as_bytes()) else {
        return;
    };
    let line = LogLine {
        seq: chunk.seq,
        stream: chunk.stream,
        ts: chunk.received_at,
        data: String::from_utf8_lossy(&bytes).into_owned(),
    };
    let Ok(mut text) = serde_json::to_vec(&line) else {
        return;
    };
    text.push(b'\n');
    if state.bytes + text.len() as u64 > cap {
        let marker = LogLine {
            seq: chunk.seq,
            stream: LogStream::Stderr,
            ts: chunk.received_at,
            data: LOG_TRUNCATED_MESSAGE.to_string(),
        };
        let Ok(serde_json::Value::Object(mut m)) = serde_json::to_value(&marker) else {
            return;
        };
        m.insert(TRUNCATED_MEMBER.to_string(), serde_json::Value::Bool(true));
        let Ok(mut m) = serde_json::to_vec(&m) else {
            return;
        };
        m.push(b'\n');
        text = m;
        state.truncated = true;
    }
    out.extend_from_slice(&text);
    state.bytes += text.len() as u64;
    state.last_seq = Some(chunk.seq);
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use p2pc_proto::protocol::LogData;
    use time::macros::datetime;

    use super::*;

    fn chunk(seq: u64, stream: LogStream, data: &[u8]) -> LogChunk {
        LogChunk {
            stream,
            seq,
            data_b64: LogData(data_encoding::BASE64.encode(data)),
            received_at: datetime!(2026-11-05 10:00:00 UTC),
        }
    }

    fn lines(store: &LogStore, job: JobId, attempt: u32) -> Vec<LogLine> {
        let text = std::fs::read_to_string(store.path(job, attempt)).unwrap_or_default();
        text.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    async fn all(store: &LogStore, job: JobId, attempt: u32, since: u64) -> Vec<LogLine> {
        let mut out = Vec::new();
        let mut offset = 0;
        loop {
            let r = store.read(job, attempt, offset, since).await.unwrap();
            if r.next == offset {
                break;
            }
            offset = r.next;
            for l in String::from_utf8(r.lines).unwrap().lines() {
                out.push(serde_json::from_str(l).unwrap());
            }
        }
        out
    }

    #[tokio::test]
    async fn chunks_are_stored_per_attempt_deduplicated_with_gaps_allowed() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LogStore::new(tmp.path());
        let job = JobId::generate();
        for (seq, data) in [
            (0, "a"),
            (1, "b"),
            (1, "dup"),
            (0, "old"),
            (5, "after a gap"),
            (3, "late"),
        ] {
            store
                .append(job, 1, chunk(seq, LogStream::Stdout, data.as_bytes()))
                .await;
        }
        store
            .append(job, 2, chunk(0, LogStream::Stderr, b"second attempt"))
            .await;
        store.end_attempt(job, 1).await;
        store.end_attempt(job, 2).await;
        let got: Vec<(u64, String)> = lines(&store, job, 1).into_iter().map(|l| (l.seq, l.data)).collect();
        assert_eq!(got, vec![(0, "a".into()), (1, "b".into()), (5, "after a gap".into())]);
        let second = lines(&store, job, 2);
        assert_eq!((second.len(), second[0].stream), (1, LogStream::Stderr));
        assert!(!store.writing(job, 1));
        // Private files in private directories.
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&store.path(job, 1)), 0o600);
        assert_eq!(mode(&store.job_dir(job)), 0o700);
    }

    #[tokio::test]
    async fn data_is_lossy_utf8() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LogStore::new(tmp.path());
        let job = JobId::generate();
        store
            .append(job, 1, chunk(0, LogStream::Stdout, b"ok \xff\xfe end\n"))
            .await;
        store.end_attempt(job, 1).await;
        assert_eq!(lines(&store, job, 1)[0].data, "ok \u{fffd}\u{fffd} end\n");
    }

    #[tokio::test]
    async fn the_cap_writes_one_marker_and_drops_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LogStore::with_limits(tmp.path(), 300, WRITER_IDLE);
        let job = JobId::generate();
        for seq in 0..20 {
            store.append(job, 1, chunk(seq, LogStream::Stdout, &[b'x'; 40])).await;
        }
        store.end_attempt(job, 1).await;
        let got = lines(&store, job, 1);
        let marker = got.last().unwrap();
        assert_eq!(marker.stream, LogStream::Stderr);
        assert_eq!(marker.data, LOG_TRUNCATED_MESSAGE);
        assert_eq!(got.iter().filter(|l| l.data == LOG_TRUNCATED_MESSAGE).count(), 1);
        let before_marker: u64 = got[..got.len() - 1]
            .iter()
            .map(|l| serde_json::to_vec(l).unwrap().len() as u64 + 1)
            .sum();
        assert!(before_marker <= 300, "{before_marker}");
        // The marker carries a member no job output can produce.
        let raw = std::fs::read_to_string(store.path(job, 1)).unwrap();
        let last: serde_json::Value = serde_json::from_str(raw.lines().last().unwrap()).unwrap();
        assert_eq!(last[TRUNCATED_MEMBER], true);
        // A writer started later (a restart) keeps it truncated.
        store.append(job, 1, chunk(99, LogStream::Stdout, b"after")).await;
        store.end_attempt(job, 1).await;
        assert_eq!(lines(&store, job, 1).len(), got.len());
    }

    /// Review P3: a job that prints the marker's text on stderr does not silence its own log after a writer restart.
    #[tokio::test]
    async fn a_job_cannot_silence_its_log_by_printing_the_marker_text() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LogStore::new(tmp.path());
        let job = JobId::generate();
        store
            .append(job, 1, chunk(0, LogStream::Stderr, LOG_TRUNCATED_MESSAGE.as_bytes()))
            .await;
        store.end_attempt(job, 1).await;
        store.append(job, 1, chunk(1, LogStream::Stdout, b"still here")).await;
        store.end_attempt(job, 1).await;
        let got: Vec<String> = lines(&store, job, 1).into_iter().map(|l| l.data).collect();
        assert_eq!(got, vec![LOG_TRUNCATED_MESSAGE.to_string(), "still here".to_string()]);
    }

    /// Review P3: a writer opening a file larger than what it reads back still finds the last `seq` and cuts a torn
    /// last line; lines up to 64 KiB of data (about 400 KiB once escaped) are stored whole.
    #[tokio::test]
    async fn a_writer_reads_back_the_tail_of_a_large_file() {
        let tmp = tempfile::tempdir().unwrap();
        let job = JobId::generate();
        let big = vec![0u8; 64 * 1024]; // NUL bytes: each is escaped to `\u0000`, six bytes
        {
            let store = LogStore::new(tmp.path());
            for seq in 0..6 {
                store.append(job, 1, chunk(seq, LogStream::Stdout, &big)).await;
            }
            store.end_attempt(job, 1).await;
        }
        let path = LogStore::new(tmp.path()).path(job, 1);
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(len > 2 * READ_BACK, "{len}");
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"seq\":6,\"stream\":\"std").unwrap();
        drop(f);
        let store = LogStore::new(tmp.path());
        store.append(job, 1, chunk(5, LogStream::Stdout, b"resent")).await;
        store.append(job, 1, chunk(6, LogStream::Stdout, b"next")).await;
        store.end_attempt(job, 1).await;
        let got = lines(&store, job, 1);
        assert_eq!(got.iter().map(|l| l.seq).collect::<Vec<_>>(), vec![0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(got[5].data.len(), big.len());
        assert_eq!(got[6].data, "next");
    }

    #[tokio::test]
    async fn a_new_writer_reads_the_last_seq_back_and_drops_resent_chunks() {
        let tmp = tempfile::tempdir().unwrap();
        let job = JobId::generate();
        {
            let store = LogStore::new(tmp.path());
            store.append(job, 1, chunk(0, LogStream::Stdout, b"a")).await;
            store.append(job, 1, chunk(1, LogStream::Stdout, b"b")).await;
            store.end_attempt(job, 1).await;
        }
        // A crash left half a line behind.
        let path = LogStore::new(tmp.path()).path(job, 1);
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"seq\":2,\"str").unwrap();
        drop(f);
        // A restarted server: the agent resends 1, then sends 2.
        let store = LogStore::new(tmp.path());
        store.append(job, 1, chunk(1, LogStream::Stdout, b"b again")).await;
        store.append(job, 1, chunk(2, LogStream::Stdout, b"c")).await;
        store.end_attempt(job, 1).await;
        let got: Vec<String> = lines(&store, job, 1).into_iter().map(|l| l.data).collect();
        assert_eq!(got, vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn reads_are_whole_lines_from_since_seq_inclusive() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LogStore::new(tmp.path());
        let job = JobId::generate();
        assert!(all(&store, job, 1, 0).await.is_empty(), "no file reads as empty");
        for seq in [0, 1, 2, 4, 7] {
            store.append(job, 1, chunk(seq, LogStream::Stdout, b"x")).await;
        }
        store.flush(job, 1).await;
        let seqs = |v: Vec<LogLine>| v.into_iter().map(|l| l.seq).collect::<Vec<_>>();
        assert_eq!(seqs(all(&store, job, 1, 0).await), vec![0, 1, 2, 4, 7]);
        assert_eq!(seqs(all(&store, job, 1, 2).await), vec![2, 4, 7]);
        assert_eq!(seqs(all(&store, job, 1, 3).await), vec![4, 7]);
        assert!(all(&store, job, 1, 8).await.is_empty());
        store.end_attempt(job, 1).await;
    }

    #[tokio::test]
    async fn followers_are_woken_by_each_flush() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LogStore::new(tmp.path());
        let job = JobId::generate();
        let mut follow = store.subscribe(job, 1);
        let woke = tokio::spawn(async move {
            follow.changed().await;
        });
        store.append(job, 1, chunk(0, LogStream::Stdout, b"x")).await;
        tokio::time::timeout(Duration::from_secs(10), woke)
            .await
            .expect("the follower was not woken")
            .unwrap();
        store.end_attempt(job, 1).await;
        assert!(store.attempts().is_empty(), "nothing is kept once idle");
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_writer_stops_after_fsyncing_and_the_next_chunk_starts_another() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LogStore::with_limits(tmp.path(), MAX_LOG_BYTES_PER_ATTEMPT, Duration::from_secs(5));
        let job = JobId::generate();
        store.append(job, 1, chunk(0, LogStream::Stdout, b"a")).await;
        assert!(store.writing(job, 1));
        // The paused clock jumps over the idle period once every task is waiting.
        let mut follow = store.subscribe(job, 1);
        while store.writing(job, 1) {
            follow.changed().await;
        }
        store.append(job, 1, chunk(1, LogStream::Stdout, b"b")).await;
        store.end_attempt(job, 1).await;
        assert_eq!(lines(&store, job, 1).len(), 2);
    }

    /// T10d item 6: a writer that died without clearing its sender (a panic) is replaced by the next chunk: the
    /// sender neither loops on the dead queue nor loses the chunk, and the lines flushed before stay.
    #[tokio::test]
    async fn a_dead_writer_is_replaced_by_the_next_chunk() {
        let tmp = tempfile::tempdir().unwrap();
        let store = LogStore::new(tmp.path());
        let job = JobId::generate();
        store.append(job, 1, chunk(0, LogStream::Stdout, b"before")).await;
        store.flush(job, 1).await;
        store.kill_writer(job, 1).await;
        // The store still holds the dead writer's sender: that is the state a panic leaves.
        assert!(store.writing(job, 1), "the dead writer's sender is still registered");
        assert!(
            store
                .attempts()
                .get(&(job, 1))
                .unwrap()
                .tx
                .as_ref()
                .unwrap()
                .is_closed()
        );
        // The next sender gets a live queue (checked first: an append on a dead queue would spin, not fail).
        assert!(
            !store.writer((job, 1)).is_closed(),
            "a sender was handed the dead writer's closed queue"
        );
        store.append(job, 1, chunk(1, LogStream::Stdout, b"after")).await;
        // A second kill (after a flush: a dying writer loses what it holds unflushed), and a flush and an end on the
        // dead queue, neither hang nor lose anything.
        store.flush(job, 1).await;
        store.kill_writer(job, 1).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            store.flush(job, 1).await;
            store.append(job, 1, chunk(2, LogStream::Stdout, b"again")).await;
            store.end_attempt(job, 1).await;
        })
        .await
        .expect("a command hung on the dead writer's queue");
        let got: Vec<String> = lines(&store, job, 1).into_iter().map(|l| l.data).collect();
        assert_eq!(got, vec!["before", "after", "again"]);
        assert!(!store.writing(job, 1), "the replacement writer stopped cleanly");
    }
}
