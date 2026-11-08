// SPDX-License-Identifier: Apache-2.0

//! Following a job's logs live: `GET /v1/jobs/{id}/logs?follow=true` as a stream of [`LogLine`]s that survives dropped
//! connections (spec §7).

use std::collections::VecDeque;
use std::time::Duration;

use p2pc_proto::api::LogLine;
use p2pc_proto::ids::JobId;
use tokio::time::Instant;

use crate::client::{Client, Response};
use crate::error::{Error, UnexpectedResponse};
use crate::transfer::MAX_LOG_LINE_BYTES;

/// How a [`LogFollow`] reconnects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FollowOptions {
    /// How many reconnects in a row may fail (or end the stream early) before the error is returned. A reconnect
    /// that stayed up for [`FollowOptions::stable_after`] or delivered a line starts the count over. Default 8.
    pub max_failures: u32,
    /// A connection that lived this long, or delivered a line, was working: its end is not a failure to count.
    /// Default 10 s.
    pub stable_after: Duration,
    /// Stop reconnecting, and return the error, once the failures in a row have lasted this long, counted from the
    /// start of the first failed request ([`LogFollow::failing_since`]). A caller with a time budget for an outage sets
    /// it to what is left of the budget; the count of [`FollowOptions::max_failures`] still applies. Default: none.
    pub give_up_after: Option<Duration>,
}

impl Default for FollowOptions {
    fn default() -> Self {
        Self {
            max_failures: 8,
            stable_after: Duration::from_secs(10),
            give_up_after: None,
        }
    }
}

/// The live log of one attempt of a job: lines in order, each exactly once.
///
/// - It reads `GET /v1/jobs/{id}/logs?follow=true&since_seq=N`. When the connection drops it asks again from the last
///   `seq + 1` (`since_seq` is inclusive), after the wait of the client's [`crate::RetryPolicy`], so a drop never
///   repeats or loses a line. A line below the next expected `seq` is dropped even if the server sends it.
/// - It ends (`Ok(None)`) when the **server** ends the stream cleanly, and the server does that only when the attempt
///   is over and its log is flushed. Everything else ends the server's body with an error (a connection cut without
///   the end of the body): the idle limit (`http.keepalive_idle_ms`, 60 s by default, with no new line), a log that
///   cannot be read, a server error. Those are errors of the transport here, so the follow reconnects from the last
///   `seq + 1` and goes on; it never mistakes a quiet minute for the end of the log. (A server older than T10d ended
///   the body cleanly at the idle limit too; such an end is told from the attempt's by the caller, which checks the
///   job's state, as `p2pc run` does.)
/// - Without an explicit attempt the server follows the latest one. A job that is requeued after node loss starts a
///   new attempt: the caller asks for it with a new [`LogFollow`] (`seq` starts again at 0 there).
/// - Failures that are not the network's (`401`, `404`, a log line that is not a log record) are returned at once.
pub struct LogFollow {
    client: Client,
    id: JobId,
    attempt: Option<u32>,
    options: FollowOptions,
    /// The next `seq` to deliver, and the `since_seq` of the next request.
    next_seq: u64,
    stream: Option<Open>,
    /// Lines read but not delivered yet.
    ready: VecDeque<LogLine>,
    /// Reconnects that did not get anywhere, in a row.
    failures: u32,
    /// A connection has delivered a line, or stayed up for [`FollowOptions::stable_after`], since this follow began.
    worked: bool,
    /// When the first request of the current run of failures began; `None` while the last request was a success.
    failing_since: Option<Instant>,
    ended: bool,
}

struct Open {
    response: Response,
    /// When the request that opened it was sent, and when its headers came.
    requested: Instant,
    opened: Instant,
    delivered: bool,
    buf: Vec<u8>,
}

impl std::fmt::Debug for LogFollow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogFollow")
            .field("id", &self.id)
            .field("attempt", &self.attempt)
            .field("next_seq", &self.next_seq)
            .field("failures", &self.failures)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl LogFollow {
    pub(crate) fn new(client: Client, id: JobId, since_seq: u64, attempt: Option<u32>) -> Self {
        Self {
            client,
            id,
            attempt,
            options: FollowOptions::default(),
            next_seq: since_seq,
            stream: None,
            ready: VecDeque::new(),
            failures: 0,
            worked: false,
            failing_since: None,
            ended: false,
        }
    }

    /// Replaces the reconnect options.
    #[must_use]
    pub fn with_options(mut self, options: FollowOptions) -> Self {
        self.options = options;
        self
    }

    /// Whether a connection of this follow has worked: it delivered a line, or stayed up for
    /// [`FollowOptions::stable_after`] before it broke. A caller that gets an error after that knows the log route was
    /// healthy in between: what failed is what came after (spec §7, "How a follow ends").
    #[must_use]
    pub fn worked(&self) -> bool {
        self.worked
    }

    /// When the first request of the failures the next error ends began, if the last request was not a success: a caller
    /// that dates an outage of the log route (spec §7: from the start of its first failed request) uses this, because
    /// this follow reconnects by itself, up to [`FollowOptions::max_failures`] times, before it returns the error. A
    /// connection that delivered a line or stayed up for [`FollowOptions::stable_after`] is a success: the next failure
    /// starts a new run.
    #[must_use]
    pub fn failing_since(&self) -> Option<Instant> {
        self.failing_since
    }

    /// The `seq` that the next line will have at least: where a new follow of this attempt would start.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The next line, or `None` once the server has ended the stream.
    ///
    /// Dropping the future (a `select!` with Ctrl-C) is safe: the next call opens the stream again from
    /// [`LogFollow::next_seq`], so no line is lost or repeated.
    pub async fn next(&mut self) -> Result<Option<LogLine>, Error> {
        loop {
            if let Some(line) = self.ready.pop_front() {
                self.next_seq = line.seq.saturating_add(1);
                return Ok(Some(line));
            }
            if self.ended {
                return Ok(None);
            }
            let open = match self.stream.take() {
                Some(open) => open,
                None => self.reconnect().await?,
            };
            self.read(open).await?;
        }
    }

    /// Opens the stream from `next_seq`, waiting first if the last one failed.
    async fn reconnect(&mut self) -> Result<Open, Error> {
        loop {
            if self.failures > 0 {
                let wait = self.client.retry_policy().delay(self.failures - 1);
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
            }
            let requested = Instant::now();
            match self.client.open_log_stream(&self.id, self.next_seq, self.attempt).await {
                Ok(response) => {
                    return Ok(Open {
                        response,
                        requested,
                        opened: Instant::now(),
                        delivered: false,
                        buf: Vec::new(),
                    });
                }
                Err(e) if is_transient(&e) => {
                    self.failing_since.get_or_insert(requested);
                    self.fail(e)?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Reads one chunk of `open`: keeps the stream, or ends it, or reconnects later.
    async fn read(&mut self, mut open: Open) -> Result<(), Error> {
        match open.response.chunk().await {
            Ok(Some(chunk)) => {
                self.split(&mut open, &chunk)?;
                self.stream = Some(open);
                Ok(())
            }
            Ok(None) => {
                // The server ended the body. A last line without a newline still counts.
                if !open.buf.is_empty() {
                    let rest = std::mem::take(&mut open.buf);
                    self.line(&mut open, &rest)?;
                }
                self.ended = true;
                self.failing_since = None;
                Ok(())
            }
            Err(e) if is_transient(&e) => {
                // A dropped connection: if it was working, the next one starts a fresh count.
                if open.delivered || open.opened.elapsed() >= self.options.stable_after {
                    self.failures = 0;
                    self.worked = true;
                    self.failing_since = None;
                } else {
                    // It broke at once: a failed request, which began when it was sent.
                    self.failing_since.get_or_insert(open.requested);
                }
                self.fail(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Counts a failed (re)connect; the error once there have been too many in a row.
    fn fail(&mut self, error: Error) -> Result<(), Error> {
        self.failures = self.failures.saturating_add(1);
        let too_long = self
            .options
            .give_up_after
            .zip(self.failing_since)
            .is_some_and(|(limit, since)| since.elapsed() >= limit);
        if self.failures > self.options.max_failures || too_long {
            return Err(error);
        }
        Ok(())
    }

    fn split(&mut self, open: &mut Open, chunk: &[u8]) -> Result<(), Error> {
        let mut buf = std::mem::take(&mut open.buf);
        buf.extend_from_slice(chunk);
        let mut start = 0;
        while let Some(offset) = buf[start..].iter().position(|b| *b == b'\n') {
            let end = start + offset;
            self.line(open, &buf[start..end])?;
            start = end + 1;
        }
        buf.drain(..start);
        if buf.len() > MAX_LOG_LINE_BYTES {
            return Err(unexpected(format!(
                "a log line is longer than {MAX_LOG_LINE_BYTES} bytes"
            )));
        }
        open.buf = buf;
        Ok(())
    }

    fn line(&mut self, open: &mut Open, raw: &[u8]) -> Result<(), Error> {
        let text = raw.strip_suffix(b"\r").unwrap_or(raw);
        if text.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let line: LogLine = serde_json::from_slice(text).map_err(|e| {
            // The text is job output: say where it went wrong, never what it said.
            unexpected(format!(
                "a log line is not a log record (line {}, column {})",
                e.line(),
                e.column()
            ))
        })?;
        // Everything below `next_seq` was delivered already (or was asked to be skipped).
        let expected = self.ready.back().map_or(self.next_seq, |l| l.seq.saturating_add(1));
        if line.seq < expected {
            return Ok(());
        }
        open.delivered = true;
        self.worked = true;
        self.failures = 0;
        self.failing_since = None;
        self.ready.push_back(line);
        Ok(())
    }
}

/// Whether a failed request is worth repeating: the network, a gateway or server error, a timeout or a rate limit.
fn is_transient(error: &Error) -> bool {
    let retryable = |s: u16| matches!(s, 408 | 429 | 500..=599);
    match error {
        Error::Network(_) => true,
        Error::Api(e) => retryable(e.status),
        Error::Unexpected(e) => e.status.is_some_and(retryable),
        Error::Local(_) => false,
    }
}

fn unexpected(message: String) -> Error {
    Error::Unexpected(UnexpectedResponse::new(Some(200), message))
}
