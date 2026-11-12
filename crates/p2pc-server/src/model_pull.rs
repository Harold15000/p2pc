// SPDX-License-Identifier: AGPL-3.0-only

//! The hub's own model pull and `service.setup` (H2 spec §7.2, §7.6; SI-H2-18 "The hub's own model pull").
//!
//! Models reach a template's volume only from the hub: every connection of a principal that is not `admin` is
//! filtered by the template's `allowed_routes`, which never include a model-writing route. So the hub itself sends
//! the one request that downloads the model, `POST /api/pull {"model": <template.pull>, "stream": true}`, to the
//! service through the bridge, and reports what comes back as `service.setup`. The model is the job's
//! `template.pull`, an enum value of the template stored with the job, so a hub restart or a node-loss restart
//! pulls the same model.
//!
//! - **Trigger** ([`ModelPuller::scan`], once a second and at start). For every running template service with a
//!   model: when its attempt is `healthy`, its setup is neither `done` nor `failed`, no pull of the hub runs for it
//!   and its node is connected, the hub starts a pull session. A try the database says is running while no session
//!   holds it was cut by a hub stop: it counts as failed with `stream_broken`.
//! - **Reading** ([`PullReader`]). The answer is untrusted. The response head is bounded, the body is read line by
//!   line, a line is at most 4 KiB, and only `status`, `completed`, `total` and `error` of a line are read. The
//!   pull is `done` only when the answer ends after a line whose `status` is `"success"`. A try fails on a line with
//!   `error` (`error_line`), a longer or malformed line (`bad_line`), the end of the answer without that final line
//!   (`eof`), a broken stream (`stream_broken`: the node cannot be reached, the agent reconnected, the hub
//!   restarted), or 2 h after it started on the hub's clock (`deadline`). Nothing of a line is logged or stored
//!   except the progress in MiB.
//! - **Retry.** After a first failed try the session retries once at once (`tries` = 2). After a second failure the
//!   setup is `failed` with its reason, and the hub does not pull again in that attempt.
//! - **Per attempt.** The setup always describes the current attempt ([`crate::store::setup`]): a new attempt starts
//!   fresh, and every write of a session is fenced by the lease it pulls for.
//! - **Idle accounting** (§7.4). A try counts as an open port connection of the service, outside the per-principal
//!   cap, and its end is the service's last activity; the idle cancel also waits while the setup is `pulling`.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration as StdDuration;

use p2pc_proto::api::{JobKind, JobStatus, ServiceSetup, SetupFailure, SetupState};
use p2pc_proto::ids::{JobId, LeaseId};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::Instant;

use crate::app::AppState;
use crate::gateway::ports;
use crate::scheduler::OpenConnections;
use crate::store::jobs::JobRow;
use crate::store::setup::{self, PullTarget};
use crate::store::{self, Conn, StoreError};

/// Longest line of a pull answer, in bytes, without its line end (H2 §7.6 "Reading").
pub const MAX_LINE_BYTES: usize = 4 * 1024;
/// Tries per attempt: the first, and one retry (H2 §7.6 "Retry").
pub const MAX_TRIES: u32 = 2;
/// How long a try may take (H2 §7.6 "Reading").
pub const TRY_DEADLINE: Duration = Duration::hours(2);
/// How often the hub looks for attempts to pull for.
pub const SCAN_INTERVAL: StdDuration = StdDuration::from_secs(1);
/// Longest response head (status line and headers) the hub reads.
const MAX_HEAD_BYTES: usize = 8 * 1024;
/// Longest chunk-size line of a chunked answer, and the most trailer bytes after its last chunk.
const MAX_FRAMING_BYTES: usize = 256;
/// Most download parts (model layers) whose progress is added up.
const MAX_PARTS: usize = 64;
/// Bytes read from the stream at a time.
const READ_BUFFER: usize = 16 * 1024;
const MIB: u64 = 1024 * 1024;

/// How a try ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The answer ended after a `status: "success"` line.
    Done,
    /// The try failed.
    Failed(SetupFailure),
}

/// What a pull has downloaded so far, as `service.setup` shows it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Progress {
    /// MiB downloaded.
    pub completed_mb: u64,
    /// MiB to download, once the service said so.
    pub total_mb: Option<u64>,
}

/// The four fields of a line the hub reads (H2 §7.6). Everything else in a line is skipped unread.
#[derive(Deserialize)]
struct Line {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    completed: Option<u64>,
    #[serde(default)]
    total: Option<u64>,
    /// Only whether there is one: its text is never kept.
    #[serde(default)]
    error: Option<serde::de::IgnoredAny>,
}

/// How the body of the answer is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// `Transfer-Encoding: chunked`.
    Chunked(Chunk),
    /// `Content-Length`: this many bytes are left.
    Length(u64),
    /// Neither: the body ends when the service ends the stream.
    UntilClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chunk {
    /// Reading a chunk-size line.
    Size,
    /// This many bytes of the chunk are left.
    Data(u64),
    /// The CRLF after a chunk: this many of its bytes are left.
    DataEnd(u8),
    /// After the last chunk: trailer lines, up to the empty one.
    Trailers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Head,
    Body(Framing),
}

/// Reads the answer to one `POST /api/pull`: an HTTP/1.1 response whose body is NDJSON (H2 §7.6 "Reading").
///
/// It is fed the bytes as they come and holds at most one response head or one line at a time, so its memory is
/// bounded whatever the service sends.
#[derive(Debug)]
pub struct PullReader {
    phase: Phase,
    /// The response head, or the chunk-size or trailer line being read, as far as it came.
    framing: Vec<u8>,
    /// Bytes of the chunk-size line being read, or of all the trailers so far.
    framing_bytes: usize,
    /// The line being read.
    line: Vec<u8>,
    /// Whether the last line read said `status: "success"`.
    last_success: bool,
    /// `(part, completed, total)` in bytes, per part of the download (a hash of its `status`).
    parts: Vec<(u64, u64, u64)>,
    verdict: Option<Outcome>,
}

impl Default for PullReader {
    fn default() -> Self {
        Self::new()
    }
}

impl PullReader {
    /// A reader at the start of an answer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            phase: Phase::Head,
            framing: Vec::new(),
            framing_bytes: 0,
            line: Vec::new(),
            last_success: false,
            parts: Vec::new(),
            verdict: None,
        }
    }

    fn fail(&mut self, reason: SetupFailure) -> Option<Outcome> {
        self.verdict = Some(Outcome::Failed(reason));
        self.verdict
    }

    /// What the lines read so far add up to.
    #[must_use]
    pub fn progress(&self) -> Progress {
        let sum = |pick: fn(&(u64, u64, u64)) -> u64| self.parts.iter().map(pick).fold(0u64, u64::saturating_add);
        Progress {
            completed_mb: sum(|p| p.1) / MIB,
            total_mb: (!self.parts.is_empty()).then(|| sum(|p| p.2) / MIB),
        }
    }

    /// Takes the next bytes of the answer. `Some` once the try is decided: a failure, or the end of the body.
    pub fn feed(&mut self, bytes: &[u8]) -> Option<Outcome> {
        if self.verdict.is_some() {
            return self.verdict;
        }
        match self.phase {
            Phase::Head => self.head(bytes),
            Phase::Body(_) => self.body(bytes),
        }
    }

    /// The stream ended: cleanly (the service finished it) or not (it broke).
    pub fn end(&mut self, clean: bool) -> Outcome {
        if let Some(verdict) = self.verdict {
            return verdict;
        }
        let outcome = match (clean, self.phase) {
            (false, _) => Outcome::Failed(SetupFailure::StreamBroken),
            // A body that ends with the stream is complete now.
            (true, Phase::Body(Framing::UntilClose)) => self.complete(),
            // No answer, or one cut before its announced end: the stream ended without the final line.
            (true, _) => Outcome::Failed(SetupFailure::Eof),
        };
        self.verdict = Some(outcome);
        outcome
    }

    fn head(&mut self, bytes: &[u8]) -> Option<Outcome> {
        // The end of the head may straddle two reads: search from three bytes before the new ones.
        let from = self.framing.len().saturating_sub(3);
        self.framing.extend_from_slice(bytes);
        let Some(end) = self.framing[from..]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| from + i)
        else {
            if self.framing.len() > MAX_HEAD_BYTES {
                return self.fail(SetupFailure::BadLine);
            }
            return None;
        };
        if end > MAX_HEAD_BYTES {
            return self.fail(SetupFailure::BadLine);
        }
        let rest = self.framing.split_off(end + 4);
        let head = std::mem::take(&mut self.framing);
        match parse_head(&head[..end]) {
            Ok(framing) => {
                self.phase = Phase::Body(framing);
                self.body(&rest)
            }
            Err(reason) => self.fail(reason),
        }
    }

    fn body(&mut self, mut bytes: &[u8]) -> Option<Outcome> {
        loop {
            let Phase::Body(framing) = self.phase else {
                return None;
            };
            match framing {
                Framing::UntilClose => return self.payload(bytes),
                Framing::Length(left) => {
                    let take = usize::try_from(left).map_or(bytes.len(), |l| l.min(bytes.len()));
                    if let Some(decided) = self.payload(&bytes[..take]) {
                        return Some(decided);
                    }
                    let left = left - take as u64;
                    self.phase = Phase::Body(Framing::Length(left));
                    // Whatever follows the announced length is not part of the answer.
                    return (left == 0).then(|| self.decide_complete());
                }
                Framing::Chunked(chunk) => {
                    if bytes.is_empty() {
                        return None;
                    }
                    let (next, used) = match self.chunk(chunk, bytes) {
                        Ok(step) => step,
                        Err(decided) => return Some(decided),
                    };
                    self.phase = Phase::Body(Framing::Chunked(next));
                    bytes = &bytes[used..];
                }
            }
        }
    }

    /// One step of the chunked decoder over `bytes`: the next state and how many bytes it used. `Err` once the try is
    /// decided.
    fn chunk(&mut self, chunk: Chunk, bytes: &[u8]) -> Result<(Chunk, usize), Outcome> {
        let bad = |this: &mut Self| {
            this.verdict = Some(Outcome::Failed(SetupFailure::BadLine));
            Outcome::Failed(SetupFailure::BadLine)
        };
        match chunk {
            Chunk::Size | Chunk::Trailers => {
                let newline = bytes.iter().position(|b| *b == b'\n');
                let (part, used) = match newline {
                    Some(at) => (&bytes[..at], at + 1),
                    None => (bytes, bytes.len()),
                };
                self.framing.extend_from_slice(part);
                // One chunk-size line, or all the trailers together, within the same small bound.
                self.framing_bytes += used;
                if self.framing_bytes > MAX_FRAMING_BYTES {
                    return Err(bad(self));
                }
                if newline.is_none() {
                    return Ok((chunk, used));
                }
                let line = std::mem::take(&mut self.framing);
                let line = line.strip_suffix(b"\r").unwrap_or(&line);
                if chunk == Chunk::Trailers {
                    // The empty line ends the trailers, and the answer. A trailer itself is skipped.
                    return if line.is_empty() {
                        Err(self.decide_complete())
                    } else {
                        Ok((Chunk::Trailers, used))
                    };
                }
                self.framing_bytes = 0;
                // `<hex size>[;extension]`.
                let size = line.split(|b| *b == b';').next().unwrap_or_default();
                let size = std::str::from_utf8(size)
                    .ok()
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && s.len() <= 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                    .and_then(|s| u64::from_str_radix(s, 16).ok());
                match size {
                    Some(0) => Ok((Chunk::Trailers, used)),
                    Some(size) => Ok((Chunk::Data(size), used)),
                    None => Err(bad(self)),
                }
            }
            Chunk::Data(left) => {
                let take = usize::try_from(left).map_or(bytes.len(), |l| l.min(bytes.len()));
                if let Some(decided) = self.payload(&bytes[..take]) {
                    return Err(decided);
                }
                let left = left - take as u64;
                Ok((
                    if left == 0 {
                        Chunk::DataEnd(2)
                    } else {
                        Chunk::Data(left)
                    },
                    take,
                ))
            }
            Chunk::DataEnd(left) => {
                let expected = if left == 2 { b'\r' } else { b'\n' };
                match bytes.first() {
                    Some(b) if *b == expected => Ok((if left == 2 { Chunk::DataEnd(1) } else { Chunk::Size }, 1)),
                    Some(_) => Err(bad(self)),
                    None => Ok((chunk, 0)),
                }
            }
        }
    }

    /// Body bytes: split into lines, each at most [`MAX_LINE_BYTES`] without its line end.
    fn payload(&mut self, bytes: &[u8]) -> Option<Outcome> {
        for piece in bytes.split_inclusive(|b| *b == b'\n') {
            let (content, ended) = match piece.split_last() {
                Some((b'\n', content)) => (content, true),
                _ => (piece, false),
            };
            // One byte more than a line may have, for the `\r` of a CRLF line end.
            if self.line.len() + content.len() > MAX_LINE_BYTES + 1 {
                return self.fail(SetupFailure::BadLine);
            }
            self.line.extend_from_slice(content);
            if ended {
                let line = std::mem::take(&mut self.line);
                if let Err(reason) = self.read_line(&line) {
                    return self.fail(reason);
                }
            }
        }
        None
    }

    /// One whole line. Only `status`, `completed`, `total` and `error` are read.
    fn read_line(&mut self, line: &[u8]) -> Result<(), SetupFailure> {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() > MAX_LINE_BYTES {
            return Err(SetupFailure::BadLine);
        }
        let line = line.trim_ascii();
        // An empty line between two lines says nothing.
        if line.is_empty() {
            return Ok(());
        }
        // A JSON object, nothing else: a struct would also be read from an array.
        if line.first() != Some(&b'{') {
            return Err(SetupFailure::BadLine);
        }
        let parsed: Line = serde_json::from_slice(line).map_err(|_| SetupFailure::BadLine)?;
        if parsed.error.is_some() {
            return Err(SetupFailure::ErrorLine);
        }
        self.last_success = parsed.status.as_deref() == Some("success");
        if let Some(total) = parsed.total {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            parsed.status.as_deref().unwrap_or_default().hash(&mut hasher);
            let part = hasher.finish();
            let completed = parsed.completed.unwrap_or(0).min(total);
            if let Some(known) = self.parts.iter_mut().find(|p| p.0 == part) {
                (known.1, known.2) = (completed, total);
            } else if self.parts.len() < MAX_PARTS {
                self.parts.push((part, completed, total));
            }
            // More parts than any model has: the progress stops growing, the pull goes on.
        }
        Ok(())
    }

    /// The body is complete: `done` only if its last line said `success`.
    fn complete(&mut self) -> Outcome {
        // A last line without a line end is still a line.
        let line = std::mem::take(&mut self.line);
        if let Err(reason) = self.read_line(&line) {
            return Outcome::Failed(reason);
        }
        if self.last_success {
            Outcome::Done
        } else {
            Outcome::Failed(SetupFailure::Eof)
        }
    }

    fn decide_complete(&mut self) -> Outcome {
        let outcome = self.complete();
        self.verdict = Some(outcome);
        outcome
    }
}

/// Reads the response head: the status must be `200`, and the headers say how the body is delimited. A status other
/// than `200` is the service saying the pull failed (`error_line`); anything that is not a response is `bad_line`.
fn parse_head(head: &[u8]) -> Result<Framing, SetupFailure> {
    let text = std::str::from_utf8(head).map_err(|_| SetupFailure::BadLine)?;
    let mut lines = text.split("\r\n");
    let mut status_line = lines.next().unwrap_or_default().splitn(3, ' ');
    let version = status_line.next().unwrap_or_default();
    let code = status_line.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") || code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SetupFailure::BadLine);
    }
    if code != "200" {
        return Err(SetupFailure::ErrorLine);
    }
    let (mut chunked, mut length) = (false, None);
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(SetupFailure::BadLine)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if !value.eq_ignore_ascii_case("chunked") {
                return Err(SetupFailure::BadLine);
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            let digits = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
            let parsed = value.parse::<u64>().ok().filter(|_| digits);
            length = Some(parsed.ok_or(SetupFailure::BadLine)?);
        }
    }
    Ok(match (chunked, length) {
        (true, _) => Framing::Chunked(Chunk::Size),
        (false, Some(length)) => Framing::Length(length),
        (false, None) => Framing::UntilClose,
    })
}

/// The one request of a pull (H2 §7.6 "Trigger"). The model is written by a JSON serializer, so nothing in it can
/// leave its string.
#[must_use]
pub fn pull_request(model: &str, port: u16) -> Vec<u8> {
    let body = serde_json::json!({"model": model, "stream": true}).to_string();
    format!(
        "POST /api/pull HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Accept: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// The limits of the pull. The defaults are the spec's; tests shorten the waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullLimits {
    /// How long a try may take, on the hub's clock; never longer than that in real time either.
    pub deadline: Duration,
    /// How often a try that reads nothing looks at the clock.
    pub poll: StdDuration,
    /// The least time between two writes of a try's progress.
    pub progress_interval: StdDuration,
    /// How often [`ModelPuller::spawn`] scans.
    pub scan_interval: StdDuration,
}

impl Default for PullLimits {
    fn default() -> Self {
        Self {
            deadline: TRY_DEADLINE,
            poll: StdDuration::from_secs(1),
            progress_interval: StdDuration::from_secs(1),
            scan_interval: SCAN_INTERVAL,
        }
    }
}

/// A pull session: the tries of the hub for one attempt of a service.
#[derive(Debug)]
struct Session {
    id: u64,
    lease_id: LeaseId,
    epoch: u64,
    abort: AbortHandle,
}

#[derive(Debug)]
struct Inner {
    limits: RwLock<PullLimits>,
    /// The sessions that run, by service: at most one pull of the hub per service.
    sessions: Mutex<HashMap<JobId, Session>>,
    next_id: AtomicU64,
}

/// The hub's model puller. Cheap to clone; every clone shares the same sessions. It keeps nothing across a hub
/// restart: what a restart finds is in the database, and [`ModelPuller::scan`] picks it up.
#[derive(Debug, Clone)]
pub struct ModelPuller {
    inner: Arc<Inner>,
}

impl Default for ModelPuller {
    fn default() -> Self {
        Self::new(PullLimits::default())
    }
}

/// Counts a try as an open port connection of its service until dropped (H2 §7.4 "Idle accounting").
#[derive(Debug)]
struct Open {
    connections: OpenConnections,
    job_id: JobId,
}

impl Open {
    fn new(connections: &OpenConnections, job_id: JobId) -> Self {
        connections.opened(job_id);
        Self {
            connections: connections.clone(),
            job_id,
        }
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        self.connections.closed(self.job_id);
    }
}

impl ModelPuller {
    /// A puller with `limits` and no session.
    #[must_use]
    pub fn new(limits: PullLimits) -> Self {
        Self {
            inner: Arc::new(Inner {
                limits: RwLock::new(limits),
                sessions: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(1),
            }),
        }
    }

    /// The limits in force.
    #[must_use]
    pub fn limits(&self) -> PullLimits {
        *self.inner.limits.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces the limits, for every clone. Tests shorten the waits with it.
    #[doc(hidden)]
    pub fn set_limits(&self, limits: PullLimits) {
        *self.inner.limits.write().unwrap_or_else(PoisonError::into_inner) = limits;
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, HashMap<JobId, Session>> {
        self.inner.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether a pull of the hub runs for `job_id` now.
    #[must_use]
    pub fn is_pulling(&self, job_id: JobId) -> bool {
        self.sessions().contains_key(&job_id)
    }

    /// Ends every session, as a hub stop does: their streams are reset and their tries stay as the database has
    /// them.
    pub fn shutdown(&self) {
        for (_, session) in self.sessions().drain() {
            session.abort.abort();
        }
    }

    /// One pass (H2 §7.6 "Trigger"): ends the sessions whose attempt is over, and starts one for every running
    /// template service with a model whose attempt is healthy, whose setup is neither `done` nor `failed`, that has
    /// no session and whose node is connected. Returns how many sessions it started.
    pub async fn scan(&self, state: &AppState) -> Result<usize, StoreError> {
        let targets = {
            let mut conn = state.db.acquire().await?;
            setup::targets(&mut conn).await?
        };
        let mut started = 0;
        let mut sessions = self.sessions();
        // A session lives as long as the attempt it pulls for: a new attempt, a stop or the end of the job ends it.
        sessions.retain(|job_id, session| {
            let current = targets
                .iter()
                .any(|t| t.job_id == *job_id && t.lease_id == session.lease_id && t.epoch == session.epoch);
            if !current {
                session.abort.abort();
            }
            current
        });
        for target in targets {
            let settled = matches!(target.setup.state, Some(SetupState::Done | SetupState::Failed));
            if settled
                || !target.healthy
                || sessions.contains_key(&target.job_id)
                || !state.hub.is_connected(target.node_id)
            {
                continue;
            }
            let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
            let (this, state, job_id) = (self.clone(), state.clone(), target.job_id);
            let (lease_id, epoch) = (target.lease_id, target.epoch);
            // Registered under the lock the session takes to leave, so it cannot leave before it is registered.
            let task = tokio::spawn(async move { this.session(state, target, id).await });
            sessions.insert(
                job_id,
                Session {
                    id,
                    lease_id,
                    epoch,
                    abort: task.abort_handle(),
                },
            );
            started += 1;
        }
        Ok(started)
    }

    /// Scans every `scan_interval` in a task. Abort the handle and call [`ModelPuller::shutdown`] to stop.
    #[must_use]
    pub fn spawn(&self, state: AppState) -> JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            // `interval` refuses a period of zero.
            let period = this.limits().scan_interval.max(StdDuration::from_millis(1));
            let mut tick = tokio::time::interval(period);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if let Err(e) = this.scan(&state).await {
                    tracing::warn!(error = %e, "cannot look for models to pull");
                }
            }
        })
    }

    /// The tries of one attempt: the first, and after a first failure one more at once.
    async fn session(&self, state: AppState, target: PullTarget, id: u64) {
        loop {
            let (started, tries) = match self.begin(&state, &target).await {
                Ok(Some(begun)) => begun,
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(error = %e, job_id = %target.job_id, "cannot start a model pull");
                    break;
                }
            };
            // From its start until its outcome is recorded the try is an open connection of the service (§7.4).
            let open = Open::new(&state.connections, target.job_id);
            let outcome = self.one_try(&state, &target, started).await;
            let again = match self.record(&state, &target, outcome, tries).await {
                Ok(again) => again,
                Err(e) => {
                    // The try stays "running" in the database: the next scan counts it as broken.
                    tracing::warn!(error = %e, job_id = %target.job_id, "cannot record a model pull");
                    false
                }
            };
            drop(open);
            if !again {
                break;
            }
        }
        let mut sessions = self.sessions();
        if sessions.get(&target.job_id).is_some_and(|s| s.id == id) {
            sessions.remove(&target.job_id);
        }
    }

    /// Begins the next try of `target`'s attempt, if there is one to begin: `(when it started, which try it is)`.
    ///
    /// `None` when the attempt is over or being stopped, is not healthy now, has a settled setup, or its node is not
    /// connected (a try is a request sent through the bridge: with no bridge there is none yet).
    async fn begin(&self, state: &AppState, target: &PullTarget) -> Result<Option<(OffsetDateTime, u32)>, StoreError> {
        if !state.hub.is_connected(target.node_id) {
            return Ok(None);
        }
        let mut tx = store::begin_immediate(&state.db).await?;
        let now = state.clock.now();
        let Some(current) = setup::target(&mut tx, target.lease_id, target.epoch).await? else {
            return Ok(None);
        };
        if !current.healthy || matches!(current.setup.state, Some(SetupState::Done | SetupState::Failed)) {
            return Ok(None);
        }
        let tries = current.setup.tries;
        let out_of_tries = tries >= MAX_TRIES;
        if current.setup.try_started_at.is_some() {
            // The database has a try running and this hub has none: it was running when the hub stopped.
            setup::try_failed(&mut tx, target, SetupFailure::StreamBroken, out_of_tries, now).await?;
        } else if out_of_tries {
            let reason = current.setup.reason.unwrap_or(SetupFailure::StreamBroken);
            setup::try_failed(&mut tx, target, reason, true, now).await?;
        }
        if out_of_tries {
            tx.commit().await?;
            return Ok(None);
        }
        let begun = setup::begin_try(&mut tx, target, tries + 1, now).await?;
        tx.commit().await?;
        Ok(begun.then_some((now, tries + 1)))
    }

    /// One try: opens a stream to the service's port, sends the request and reads the answer to its end.
    async fn one_try(&self, state: &AppState, target: &PullTarget, started: OffsetDateTime) -> Outcome {
        let broken = Outcome::Failed(SetupFailure::StreamBroken);
        let mut stream = match ports::open(state, target.job_id, target.port).await {
            Ok(stream) => stream,
            Err(e) => {
                // `node_unreachable` and the like. The agent's reason is a code, never a secret.
                tracing::debug!(job_id = %target.job_id, error = ?e, "the model pull could not reach its service");
                return broken;
            }
        };
        // The stream was opened for the job's current lease: it must be the one this session pulls for.
        let still_ours = match state.db.acquire().await {
            Ok(mut conn) => store::ports::still_current(&mut conn, target.lease_id, target.epoch)
                .await
                .unwrap_or(false),
            Err(_) => false,
        };
        if !still_ours {
            return broken;
        }
        let request = pull_request(&target.model, target.port);
        let outcome = {
            let (send, recv) = stream.io();
            let sent = tokio::time::timeout(state.ports.limits().body_timeout, async {
                send.write_all(&request).await.is_ok() && send.flush().await.is_ok()
            })
            .await;
            if matches!(sent, Ok(true)) {
                self.read_answer(state, target, recv, started).await
            } else {
                broken
            }
        };
        if outcome == Outcome::Done {
            stream.finish();
        }
        // Otherwise dropping the stream resets it, and the service sees the hub go away.
        outcome
    }

    /// Reads the answer from `answer` until the try is decided, writing its progress as it goes. The deadline is on
    /// the hub's clock, counted from `started`, and never later than that in real time.
    async fn read_answer<R>(
        &self,
        state: &AppState,
        target: &PullTarget,
        answer: &mut R,
        started: OffsetDateTime,
    ) -> Outcome
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        let limits = self.limits();
        let deadline = started + limits.deadline;
        let real_deadline = Instant::now() + limits.deadline.unsigned_abs();
        let mut reader = PullReader::new();
        let mut buf = vec![0u8; READ_BUFFER];
        let mut written = Progress::default();
        let mut last_write = Instant::now();
        loop {
            if state.clock.now() >= deadline || Instant::now() >= real_deadline {
                return Outcome::Failed(SetupFailure::Deadline);
            }
            // `read` is cancel safe: a read that the poll interval cuts short loses nothing.
            match tokio::time::timeout(limits.poll, answer.read(&mut buf)).await {
                Err(_) => continue,
                Ok(Ok(0)) => return reader.end(true),
                Ok(Ok(n)) => {
                    if let Some(outcome) = reader.feed(&buf[..n]) {
                        return outcome;
                    }
                }
                Ok(Err(_)) => return reader.end(false),
            }
            let progress = reader.progress();
            if progress != written && last_write.elapsed() >= limits.progress_interval {
                match self.write_progress(state, target, progress).await {
                    Ok(true) => {}
                    // The attempt is over: nothing this try reads matters any more.
                    Ok(false) => return Outcome::Failed(SetupFailure::StreamBroken),
                    Err(e) => tracing::debug!(error = %e, "cannot record the progress of a model pull"),
                }
                written = progress;
                last_write = Instant::now();
            }
        }
    }

    async fn write_progress(&self, state: &AppState, target: &PullTarget, p: Progress) -> Result<bool, StoreError> {
        let mut tx = store::begin_immediate(&state.db).await?;
        let written = setup::progress(&mut tx, target, p.completed_mb, p.total_mb, state.clock.now()).await?;
        tx.commit().await?;
        Ok(written)
    }

    /// Records how try number `tries` ended. Returns whether a retry may start at once: after a first failure, while
    /// the attempt is still the current one.
    async fn record(
        &self,
        state: &AppState,
        target: &PullTarget,
        outcome: Outcome,
        tries: u32,
    ) -> Result<bool, StoreError> {
        let mut tx = store::begin_immediate(&state.db).await?;
        let now = state.clock.now();
        let (written, again) = match outcome {
            Outcome::Done => (setup::done(&mut tx, target, now).await?, false),
            Outcome::Failed(reason) => {
                let last = tries >= MAX_TRIES;
                (setup::try_failed(&mut tx, target, reason, last, now).await?, !last)
            }
        };
        if written {
            // §7.4: the pull stream was an open connection, so its end is the service's last activity: the idle
            // timeout counts from here, not from before the download.
            store::ports::touch_activity(&mut tx, target.job_id, now).await?;
        }
        tx.commit().await?;
        if written {
            // The state and the reason code only: never a line of the answer, never the model's bytes.
            tracing::info!(job_id = %target.job_id, tries, outcome = ?outcome, "model pull try ended");
        }
        Ok(written && again)
    }
}

/// `service.setup` of `GET /v1/jobs/{id}` (H2 §7.2): the hub's model pull of the current attempt; `None` for a job
/// without one.
///
/// While the service runs it is the setup of the running attempt. Once the job has ended it is what the last
/// attempt came to (`done` or `failed`). While no attempt runs (queued, assigned) there is none: the next attempt
/// starts with a fresh one.
pub async fn setup_view(conn: &mut Conn, row: &JobRow) -> Result<Option<ServiceSetup>, StoreError> {
    let pulls =
        row.spec_view.kind == JobKind::Service && row.spec_view.template.as_ref().is_some_and(|t| t.pull.is_some());
    if !pulls {
        return Ok(None);
    }
    let setup = setup::get(conn, row.job_id).await?.and_then(|s| s.view());
    Ok(match row.status {
        JobStatus::Running => setup,
        status if status.is_terminal() => setup.filter(|s| s.state != SetupState::Pulling),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD_CHUNKED: &str =
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n";
    const HEAD_CLOSE: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\r\n";

    /// `lines` as one chunk each, then the last chunk.
    fn chunked(lines: &[&str]) -> Vec<u8> {
        let mut out = HEAD_CHUNKED.as_bytes().to_vec();
        for line in lines {
            out.extend_from_slice(format!("{:x}\r\n{line}\r\n", line.len()).as_bytes());
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    }

    /// Feeds `bytes` in pieces of `step` bytes, then ends the stream as `clean` says.
    fn read(bytes: &[u8], step: usize, clean: bool) -> (Outcome, Progress) {
        let mut reader = PullReader::new();
        for piece in bytes.chunks(step.max(1)) {
            if let Some(outcome) = reader.feed(piece) {
                return (outcome, reader.progress());
            }
        }
        (reader.end(clean), reader.progress())
    }

    fn outcome(bytes: &[u8]) -> Outcome {
        // However the bytes are cut into reads, the answer is the same.
        let whole = read(bytes, bytes.len(), true).0;
        for step in [1, 2, 3, 7, 64] {
            assert_eq!(read(bytes, step, true).0, whole, "in reads of {step} bytes");
        }
        whole
    }

    const PULLING: &str = "{\"status\":\"pulling manifest\"}\n";
    const SUCCESS: &str = "{\"status\":\"success\"}\n";
    const FAILED: fn(SetupFailure) -> Outcome = Outcome::Failed;

    #[test]
    fn the_spec_limits() {
        assert_eq!(MAX_LINE_BYTES, 4096);
        assert_eq!(MAX_TRIES, 2);
        assert_eq!(TRY_DEADLINE, Duration::hours(2));
        assert_eq!(PullLimits::default().deadline, Duration::hours(2));
    }

    #[test]
    fn the_request_is_one_pull_of_the_stored_model() {
        let text = String::from_utf8(pull_request("qwen3:4b-instruct", 11434)).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        assert_eq!(body, r#"{"model":"qwen3:4b-instruct","stream":true}"#);
        assert!(
            head.starts_with("POST /api/pull HTTP/1.1\r\nHost: 127.0.0.1:11434\r\n"),
            "{head}"
        );
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        assert!(head.ends_with("Connection: close"));
        // A model is an enum value of the template; whatever it holds, it stays inside its JSON string.
        let text = String::from_utf8(pull_request("x\"}\r\n\r\nDELETE /api/delete", 1)).unwrap();
        let (_, body) = text.split_once("\r\n\r\n").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["model"], "x\"}\r\n\r\nDELETE /api/delete");
        assert_eq!(text.matches("\r\n\r\n").count(), 1);
    }

    #[test]
    fn done_only_when_the_answer_ends_after_a_success_line() {
        assert_eq!(outcome(&chunked(&[PULLING, SUCCESS])), Outcome::Done);
        // Close-delimited and with a Content-Length too.
        let body = format!("{PULLING}{SUCCESS}");
        assert_eq!(outcome(format!("{HEAD_CLOSE}{body}").as_bytes()), Outcome::Done);
        let sized = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        assert_eq!(outcome(sized.as_bytes()), Outcome::Done);
        // A last line without a line end, and a CRLF line end.
        assert_eq!(
            outcome(format!("{HEAD_CLOSE}{PULLING}{{\"status\":\"success\"}}").as_bytes()),
            Outcome::Done
        );
        assert_eq!(
            outcome(format!("{HEAD_CLOSE}{{\"status\":\"success\"}}\r\n").as_bytes()),
            Outcome::Done
        );
        // `success` that is not the final line is not the end of a pull.
        assert_eq!(outcome(&chunked(&[SUCCESS, PULLING])), FAILED(SetupFailure::Eof));
        // Nor is a `success` anywhere but in `status`.
        assert_eq!(
            outcome(&chunked(&[
                "{\"state\":\"success\",\"detail\":{\"status\":\"success\"}}\n"
            ])),
            FAILED(SetupFailure::Eof)
        );
    }

    #[test]
    fn the_end_of_the_answer_without_success_is_eof() {
        assert_eq!(outcome(&chunked(&[PULLING])), FAILED(SetupFailure::Eof));
        assert_eq!(outcome(&chunked(&[])), FAILED(SetupFailure::Eof));
        assert_eq!(outcome(HEAD_CLOSE.as_bytes()), FAILED(SetupFailure::Eof));
        // No answer at all, and an answer cut before its announced end.
        assert_eq!(outcome(b""), FAILED(SetupFailure::Eof));
        assert_eq!(outcome(b"HTTP/1.1 200 OK\r\n"), FAILED(SetupFailure::Eof));
        let cut = chunked(&[PULLING, SUCCESS]);
        assert_eq!(outcome(&cut[..cut.len() - 5]), FAILED(SetupFailure::Eof));
        let sized = format!("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n{SUCCESS}");
        assert_eq!(outcome(sized.as_bytes()), FAILED(SetupFailure::Eof));
    }

    #[test]
    fn a_broken_stream_is_stream_broken_whatever_came_before() {
        for bytes in [
            Vec::new(),
            HEAD_CHUNKED.as_bytes().to_vec(),
            format!("{HEAD_CLOSE}{PULLING}{SUCCESS}").into_bytes(),
        ] {
            assert_eq!(read(&bytes, 5, false).0, FAILED(SetupFailure::StreamBroken));
        }
        // Once the answer is complete, what the stream does afterwards changes nothing.
        assert_eq!(read(&chunked(&[SUCCESS]), 5, false).0, Outcome::Done);
    }

    #[test]
    fn a_line_with_error_fails_the_try_and_nothing_after_it_matters() {
        let error = "{\"error\":\"pull model manifest: file does not exist\"}\n";
        assert_eq!(outcome(&chunked(&[PULLING, error])), FAILED(SetupFailure::ErrorLine));
        assert_eq!(outcome(&chunked(&[error, SUCCESS])), FAILED(SetupFailure::ErrorLine));
        // Whatever the `error` is, and whatever else the line says.
        for line in [
            "{\"status\":\"success\",\"error\":\"late\"}\n",
            "{\"error\":{\"code\":1}}\n",
            "{\"error\":false}\n",
            "{\"error\":\"\"}\n",
        ] {
            assert_eq!(outcome(&chunked(&[line])), FAILED(SetupFailure::ErrorLine), "{line}");
        }
        // `"error": null` is no error.
        assert_eq!(
            outcome(&chunked(&["{\"status\":\"success\",\"error\":null}\n"])),
            Outcome::Done
        );
        // The service answering with an error status is the same failure.
        for head in [
            "HTTP/1.1 500 Internal Server Error\r\n\r\n",
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        ] {
            assert_eq!(
                outcome(format!("{head}{SUCCESS}").as_bytes()),
                FAILED(SetupFailure::ErrorLine)
            );
        }
    }

    #[test]
    fn a_malformed_line_is_a_bad_line() {
        for line in [
            "not json\n",
            "{\"status\":\"pulling\"\n",
            "[\"success\"]\n",
            "[\"success\", 1, 2, null]\n",
            "\"success\"\n",
            "null\n",
            "{\"status\":5}\n",
            "{\"status\":[\"success\"]}\n",
            "{\"completed\":-1,\"total\":5}\n",
            "{\"completed\":1.5,\"total\":5}\n",
            "{\"total\":\"5\"}\n",
            "{\"status\":\"a\",\"status\":\"success\"}\n",
            "{\"status\":\"success\"} trailing\n",
            "\u{feff}{\"status\":\"success\"}\n",
        ] {
            assert_eq!(
                outcome(&chunked(&[line, SUCCESS])),
                FAILED(SetupFailure::BadLine),
                "{line:?}"
            );
        }
        // Fields the hub does not read may hold anything; an empty line says nothing.
        let extra =
            "{\"status\":\"success\",\"digest\":\"sha256:abc\",\"x\":[1,{\"y\":null}],\"completed\":3,\"total\":3}\n";
        assert_eq!(outcome(&chunked(&[PULLING, "\n", "  \r\n", extra])), Outcome::Done);
        assert_eq!(outcome(&chunked(&["{}\n", SUCCESS])), Outcome::Done);
    }

    #[test]
    fn a_line_over_4_kib_is_a_bad_line_and_one_of_4_kib_is_not() {
        let line = |len: usize| {
            let pad = len - "{\"status\":\"success\",\"p\":\"\"}".len();
            format!("{{\"status\":\"success\",\"p\":\"{}\"}}", "x".repeat(pad))
        };
        assert_eq!(line(MAX_LINE_BYTES).len(), MAX_LINE_BYTES);
        for end in ["\n", "\r\n"] {
            let exact = format!("{HEAD_CLOSE}{}{end}", line(MAX_LINE_BYTES));
            assert_eq!(outcome(exact.as_bytes()), Outcome::Done, "{end:?}");
            let over = format!("{HEAD_CLOSE}{}{end}", line(MAX_LINE_BYTES + 1));
            assert_eq!(outcome(over.as_bytes()), FAILED(SetupFailure::BadLine), "{end:?}");
        }
        // A line that never ends is refused as soon as it is too long, not when the memory runs out.
        let mut reader = PullReader::new();
        assert_eq!(reader.feed(HEAD_CLOSE.as_bytes()), None);
        let mut fed = 0;
        let decided = loop {
            fed += 512;
            if let Some(outcome) = reader.feed(&[b'x'; 512]) {
                break outcome;
            }
            assert!(
                fed <= 2 * MAX_LINE_BYTES,
                "the reader keeps taking a line of {fed} bytes"
            );
        };
        assert_eq!(decided, FAILED(SetupFailure::BadLine));
        assert!(reader.line.capacity() <= 4 * MAX_LINE_BYTES);
    }

    #[test]
    fn what_is_not_an_http_answer_is_a_bad_line() {
        for bytes in [
            &b"hello\r\n\r\n"[..],
            b"HTTP/2 200\r\n\r\n",
            b"HTTP/1.1 OK\r\n\r\n",
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: ten\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}XX",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n11111111111111111\r\n",
            b"\xff\xfe\r\n\r\n",
        ] {
            assert_eq!(
                outcome(bytes),
                FAILED(SetupFailure::BadLine),
                "{:?}",
                String::from_utf8_lossy(bytes)
            );
        }
        // A head that never ends, a chunk-size line that never ends and endless trailers are bounded.
        let endless = format!("HTTP/1.1 200 OK\r\nX: {}", "a".repeat(2 * MAX_HEAD_BYTES));
        assert_eq!(read(endless.as_bytes(), 100, true).0, FAILED(SetupFailure::BadLine));
        let size = format!("{HEAD_CHUNKED}{}", "1".repeat(2 * MAX_FRAMING_BYTES));
        assert_eq!(read(size.as_bytes(), 100, true).0, FAILED(SetupFailure::BadLine));
        let trailers = format!("{HEAD_CHUNKED}0\r\n{}", "X: y\r\n".repeat(MAX_FRAMING_BYTES));
        assert_eq!(read(trailers.as_bytes(), 100, true).0, FAILED(SetupFailure::BadLine));
        // A chunk extension and a trailer are fine.
        let ok = format!("{HEAD_CHUNKED}15;ext=1\r\n{SUCCESS}\r\n0\r\nX-Trailer: y\r\n\r\n");
        assert_eq!(outcome(ok.as_bytes()), Outcome::Done);
    }

    #[test]
    fn the_progress_adds_the_parts_of_the_download() {
        let lines = [
            "{\"status\":\"pulling manifest\"}\n".to_string(),
            format!(
                "{{\"status\":\"pulling aaa\",\"total\":{},\"completed\":{}}}\n",
                2000 * MIB,
                500 * MIB
            ),
            format!(
                "{{\"status\":\"pulling bbb\",\"total\":{},\"completed\":{}}}\n",
                100 * MIB,
                100 * MIB
            ),
            format!(
                "{{\"status\":\"pulling aaa\",\"total\":{},\"completed\":{}}}\n",
                2000 * MIB,
                1500 * MIB
            ),
            // `completed` above `total`, and a part with no `completed` yet.
            format!(
                "{{\"status\":\"pulling ccc\",\"total\":{},\"completed\":{}}}\n",
                10 * MIB,
                99 * MIB
            ),
            format!("{{\"status\":\"pulling ddd\",\"total\":{}}}\n", 5 * MIB),
        ];
        let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
        let mut body = HEAD_CLOSE.as_bytes().to_vec();
        for line in &lines {
            body.extend_from_slice(line.as_bytes());
        }
        let (_, progress) = read(&body, 9, true);
        assert_eq!(
            progress,
            Progress {
                completed_mb: 1500 + 100 + 10,
                total_mb: Some(2000 + 100 + 10 + 5)
            }
        );
        // Before any part says its size there is no total.
        assert_eq!(
            read(format!("{HEAD_CLOSE}{PULLING}").as_bytes(), 9, true).1,
            Progress::default()
        );
        // Parts are bounded, and sizes no disk has do not overflow.
        let mut many = HEAD_CLOSE.to_string();
        for i in 0..(2 * MAX_PARTS) {
            many.push_str(&format!(
                "{{\"status\":\"pulling {i}\",\"total\":{},\"completed\":{}}}\n",
                u64::MAX,
                u64::MAX
            ));
        }
        let (_, progress) = read(many.as_bytes(), 4096, true);
        assert_eq!(progress.completed_mb, u64::MAX / MIB);
        let mut reader = PullReader::new();
        reader.feed(many.as_bytes());
        assert_eq!(reader.parts.len(), MAX_PARTS);
    }
}
