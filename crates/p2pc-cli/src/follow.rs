// SPDX-License-Identifier: Apache-2.0

//! Following a job until it ends: the seam between `p2pc run` and how progress is observed.
//!
//! [`StreamFollower`] streams the job's logs live (`?follow=true`) into a [`LogSink`] and ends on the job's final state;
//! it is what `p2pc run` and `p2pc logs --follow` use. While a job waits in the queue it polls `GET /v1/jobs/{id}` every
//! second, backing off to five. (A poll-only follower for a server without the logs route was removed in T11b3: every
//! server of this version has the route, and nothing used it.)
//!
//! A transient failure (the network, a `5xx`, a `408` or `429`) does not end a follow: it is retried with a growing
//! wait (1 s, doubling, at most 30 s) for up to five minutes per outage, announced once. A permanent error (`401`,
//! `404`, a validation problem) ends it at once.

use std::cell::RefCell;
use std::io;
use std::time::Duration;

use p2pc_client::{Client, Error, FollowOptions, LogFollow};
use p2pc_proto::api::{Job, JobStatus, LogLine};

/// How a follower waits. The real one sleeps; tests record the waits and return at once.
#[allow(
    async_fn_in_trait,
    reason = "the CLI runs on a current-thread runtime: no `Send` bound is needed"
)]
pub trait Sleeper {
    /// Waits for `duration`.
    async fn sleep(&mut self, duration: Duration);

    /// The time, for timing outages. The Tokio clock; a test that must not depend on real time returns its own.
    fn now(&self) -> tokio::time::Instant {
        tokio::time::Instant::now()
    }
}

/// Sleeps with the Tokio timer.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioSleeper;

impl Sleeper for TokioSleeper {
    async fn sleep(&mut self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// Told about every change of the job's state (not about every poll).
pub trait Progress {
    /// The job is now in this state (or on this attempt). Called once for the job as it was submitted.
    fn on_status(&mut self, job: &Job);

    /// The server could not be reached, or failed for a while; the follower keeps trying. Called once per outage.
    fn on_reconnecting(&mut self, error: &Error) {
        let _ = error;
    }
}

/// Whether a failed poll is worth retrying: the network, a gateway or server error, a timeout or rate limit. Anything
/// else (`401`, `404`, a validation problem, an answer of the wrong shape, a local error) is permanent.
#[must_use]
pub fn is_transient(error: &Error) -> bool {
    let retryable_status = |s: u16| matches!(s, 408 | 429 | 500..=599);
    match error {
        Error::Network(_) => true,
        Error::Api(e) => retryable_status(e.status),
        Error::Unexpected(e) => e.status.is_some_and(retryable_status),
        Error::Local(_) => false,
    }
}

/// How a follow ended.
#[derive(Debug, Clone, PartialEq)]
pub enum Followed {
    /// The job reached a final state.
    Finished(Job),
    /// The user interrupted (Ctrl-C) before the job ended. The job keeps running: it is **not** cancelled.
    Interrupted(Job),
}

/// The waits between polls: `initial`, growing by half at every unchanged poll up to `max`; and while polls fail
/// transiently, `initial` doubling up to `reconnect_max`, for at most `give_up_after` per outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollSchedule {
    /// The first wait, and the wait after every change of state. Spec: 1 s.
    pub initial: Duration,
    /// The longest wait. Spec: 5 s.
    pub max: Duration,
    /// The longest wait between retries during an outage. 30 s.
    pub reconnect_max: Duration,
    /// How long an outage may last, in wall-clock time from the first failed poll (the time its requests take
    /// counts, not only the waits), before the follow fails. 5 minutes.
    pub give_up_after: Duration,
}

impl Default for PollSchedule {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(5),
            reconnect_max: Duration::from_secs(30),
            give_up_after: Duration::from_secs(300),
        }
    }
}

impl PollSchedule {
    fn grow(&self, wait: Duration) -> Duration {
        (wait + wait / 2).min(self.max)
    }
}

/// What counts as a change worth printing: a new state, or a new attempt after a node was lost.
fn state_key(job: &Job) -> (JobStatus, u32) {
    (job.status, job.attempt)
}

/// Where the lines of a job's log go.
pub trait LogSink {
    /// One line, in order, once. An error (a closed pipe) ends the follow.
    fn line(&mut self, line: &LogLine) -> io::Result<()>;
}

/// What a [`StreamFollower`] reports to: the state changes of the job and the lines of its log. One object, because
/// both usually go to the same terminal and must not interleave out of order.
pub trait Events: Progress + LogSink {}

impl<T: Progress + LogSink> Events for T {}

/// Why a [`StreamFollower`] stopped without an outcome.
#[derive(Debug)]
pub enum FollowError {
    /// A request failed, for good.
    Client(Error),
    /// The sink could not take a line (stdout was closed), and the latest state of the job the follow had seen. That
    /// state can be stale: the job may have ended since, so a caller that tells the user about it asks again.
    Sink(io::Error, Box<Job>),
}

impl From<Error> for FollowError {
    fn from(e: Error) -> Self {
        FollowError::Client(e)
    }
}

/// Follows a job's logs live, through every attempt, until the job is final.
///
/// - While the job waits in the queue it polls `GET /v1/jobs/{id}` (1 s, backing off to 5 s). Once an attempt has
///   started it streams `GET /v1/jobs/{id}/logs?follow=true&attempt=N` into the sink: dropped connections resume from
///   the last `seq + 1` without repeating a line ([`LogFollow`]).
/// - **An attempt's log is finished only by a read that began after the attempt was known to be over** (the job is
///   final, or a later attempt exists). Until then a `404` ("no log yet", or no such job: the server answers the same),
///   an empty `200` or a stream that ends early prove nothing, because the job may have run and written its output in
///   between: the read is repeated (after 1 s, backing off to 5 s). The moment the attempt is seen over, it is read once
///   more, at once, and that read decides. A `404` there ends a `--attempt K` follow with the error; otherwise the
///   attempt simply had no log.
/// - A requeued job (node lost) goes on with its next attempt, whose `seq` starts again at 0, after the tail of the
///   old one has been read.
/// - With a fixed attempt (`p2pc logs --attempt K --follow`) only that attempt is followed, and the follow ends with it.
/// - A transient failure of either request is retried with a growing wait, like the polls are.
#[derive(Debug, Clone)]
pub struct StreamFollower<S> {
    schedule: PollSchedule,
    sleeper: S,
    since_seq: u64,
    attempt: Option<u32>,
}

/// Where the reading of one attempt's log stands.
struct Reading {
    attempt: u32,
    /// The `since_seq` of the next read.
    next_seq: u64,
    /// A read that began after the attempt was over has ended: nothing more will come.
    final_done: bool,
    /// The last read was a `404`.
    no_log: Option<Error>,
}

/// Whether nothing more will be written to `attempt`'s log: the job is final, or a later attempt took over.
fn attempt_over(job: &Job, attempt: u32) -> bool {
    job.status.is_terminal() || attempt < job.attempt
}

impl<S: Sleeper> StreamFollower<S> {
    /// A follower that starts at `since_seq` (inclusive) of its first attempt, or of `attempt` if one is fixed.
    pub fn new(schedule: PollSchedule, sleeper: S, since_seq: u64, attempt: Option<u32>) -> Self {
        Self {
            schedule,
            sleeper,
            since_seq,
            attempt,
        }
    }

    /// Follows `job`, writing log lines to `sink` and state changes to `progress`, until the job is final or
    /// `interrupt` completes.
    pub async fn follow<I>(
        &mut self,
        client: &Client,
        job: Job,
        events: &mut dyn Events,
        interrupt: I,
    ) -> Result<Followed, FollowError>
    where
        I: Future<Output = ()>,
    {
        let latest = RefCell::new(job.clone());
        let mut interrupt = std::pin::pin!(interrupt);
        let work = self.run(client, job, events, &latest);
        tokio::select! {
            biased;
            () = &mut interrupt => Ok(Followed::Interrupted(latest.borrow().clone())),
            followed = work => followed,
        }
    }

    /// The attempt to read next: the fixed one; or, following the latest, the attempt being read if a later one has
    /// taken over before its tail was read; else the job's current attempt.
    fn target(&self, job: &Job, cur: Option<&Reading>) -> u32 {
        match (self.attempt, cur) {
            (Some(k), _) => k,
            (None, Some(c)) if c.attempt < job.attempt && !c.final_done => c.attempt,
            (None, _) => job.attempt,
        }
    }

    /// Whether `attempt` has a log to read: it has started, or a later attempt shows that it did.
    fn readable(job: &Job, attempt: u32) -> bool {
        job.attempt >= 1 && (job.status != JobStatus::Queued || attempt < job.attempt)
    }

    async fn run(
        &mut self,
        client: &Client,
        job: Job,
        events: &mut dyn Events,
        latest: &RefCell<Job>,
    ) -> Result<Followed, FollowError> {
        let mut job = job;
        events.on_status(&job);
        let mut last = state_key(&job);
        let mut cur: Option<Reading> = None;
        let mut backoff = self.schedule.initial;
        let mut wait = Duration::ZERO;
        // Outages are tracked per route (spec §7): each ends only with a success on its own route.
        let mut log_outage = Outage::new(self.schedule.initial);
        let mut job_outage = Outage::new(self.schedule.initial);
        loop {
            if !wait.is_zero() {
                self.sleeper.sleep(wait).await;
            }
            wait = Duration::ZERO;

            let target = self.target(&job, cur.as_ref());
            if Self::readable(&job, target) {
                if cur.as_ref().is_none_or(|c| c.attempt != target) {
                    // The first attempt starts where the user said; a later one starts again at 0.
                    let next_seq = if cur.is_none() { self.since_seq } else { 0 };
                    cur = Some(Reading {
                        attempt: target,
                        next_seq,
                        final_done: false,
                        no_log: None,
                    });
                }
                if let Some(reading) = cur.as_mut()
                    && !reading.final_done
                {
                    // Only a read that begins now, with the attempt already over, is conclusive.
                    let conclusive = attempt_over(&job, reading.attempt);
                    // `LogFollow` reconnects by itself: it is told what is left of the log route's outage budget, or
                    // it could spend a whole new one (a pass is eight reconnects, each as long as a request).
                    let mut follow = client
                        .follow_logs(&job.id, reading.next_seq, Some(reading.attempt))
                        .with_options(FollowOptions {
                            give_up_after: Some(self.outage_left(&log_outage)),
                            ..FollowOptions::default()
                        });
                    let read_started = self.sleeper.now();
                    let streamed = pump(&mut follow, events, &job).await;
                    reading.next_seq = follow.next_seq();
                    match streamed {
                        Ok(()) => {
                            reading.no_log = None;
                            reading.final_done = conclusive;
                            // The log route answered. It says nothing about the job route, whose outage only a
                            // good `get_job` ends (below).
                            log_outage.end(self.schedule.initial);
                        }
                        Err(e @ FollowError::Sink(..)) => return Err(e),
                        // No log (yet), or no such job: the job's state decides, below.
                        Err(FollowError::Client(e)) if e.status() == Some(404) => {
                            reading.no_log = Some(e);
                            reading.final_done = conclusive;
                            log_outage.end(self.schedule.initial);
                        }
                        Err(FollowError::Client(e)) if is_transient(&e) => {
                            if follow.worked() {
                                // A stream delivered, or stayed open, before this: that was a success of the log
                                // route, whatever broke after it. The outage counted from here is a new one.
                                log_outage.end(self.schedule.initial);
                            }
                            // `LogFollow` reconnects by itself before it gives the error up: the outage began with
                            // its first failed request, after its last success. It reads Tokio's clock; the sleeper's
                            // may differ (a test's), so only the age is taken from it.
                            let failing_since = follow
                                .failing_since()
                                .and_then(|at| self.sleeper.now().checked_sub(at.elapsed()))
                                .unwrap_or(read_started);
                            wait = self.outage(&mut log_outage, failing_since, e, events)?;
                            continue;
                        }
                        Err(FollowError::Client(e)) => return Err(FollowError::Client(e)),
                    }
                }
            }

            // Where is the job now?
            let check_started = self.sleeper.now();
            match client.get_job(&job.id).await {
                Ok(fresh) => {
                    job = fresh;
                    *latest.borrow_mut() = job.clone();
                    job_outage.end(self.schedule.initial);
                }
                Err(e) if is_transient(&e) => {
                    wait = self.outage(&mut job_outage, check_started, e, events)?;
                    continue;
                }
                Err(e) => return Err(FollowError::Client(e)),
            }
            let key = state_key(&job);
            if key != last {
                events.on_status(&job);
                last = key;
                backoff = self.schedule.initial;
            }

            let next = self.target(&job, cur.as_ref());
            let finished = match cur.as_ref() {
                // The attempt was read to its end after it was over. When following the latest, that must be the
                // job's own last attempt (an earlier one leaves the next to be read).
                Some(c) if c.final_done => self.attempt.is_some() || c.attempt >= job.attempt,
                // A final job with nothing to read: it never started.
                _ => job.status.is_terminal() && !Self::readable(&job, next),
            };
            if finished {
                if let (Some(c), Some(_)) = (cur.as_mut(), self.attempt)
                    && let Some(e) = c.no_log.take()
                {
                    // The attempt that was asked for has no log, now that it is over: say so.
                    return Err(FollowError::Client(e));
                }
                return Ok(Followed::Finished(job));
            }
            // Read again at once when that read would be the conclusive one, or is of another attempt; otherwise
            // (queued, a stream that ended early, a log that is not there yet) a beat.
            let immediate = match cur.as_ref() {
                Some(c) => {
                    Self::readable(&job, next) && (next != c.attempt || (!c.final_done && attempt_over(&job, next)))
                }
                None => Self::readable(&job, next),
            };
            if !immediate {
                wait = backoff;
                backoff = self.schedule.grow(backoff);
            }
        }
    }

    /// What is left of `outage`'s budget: all of it if the route is not failing.
    fn outage_left(&self, outage: &Outage) -> Duration {
        outage.since.map_or(self.schedule.give_up_after, |since| {
            self.schedule
                .give_up_after
                .saturating_sub(self.sleeper.now().saturating_duration_since(since))
        })
    }

    /// A transient failure of a request that began at `request_started`: announces the outage once, gives up when it is
    /// too old, and says how long to wait.
    ///
    /// An outage of a route (spec §7) is a run of failures of that route, timed from the **start** of its first failed
    /// request, with no success on that route and no gap longer than `reconnect_max` between two of its requests. A
    /// longer gap means the client was busy with healthy work on the other route: this failure starts a new outage.
    /// The gap is measured from when the next request was *expected* (the previous one's end plus the wait this method
    /// scheduled), so it counts only the other route's work, never the retry wait.
    fn outage(
        &self,
        outage: &mut Outage,
        request_started: tokio::time::Instant,
        error: Error,
        progress: &mut dyn Progress,
    ) -> Result<Duration, FollowError> {
        let now = self.sleeper.now();
        if let (Some(_), Some(expected)) = (outage.since, outage.next_expected)
            && request_started.saturating_duration_since(expected) > self.schedule.reconnect_max
        {
            outage.end(self.schedule.initial);
        }
        let started = *outage.since.get_or_insert_with(|| {
            progress.on_reconnecting(&error);
            request_started
        });
        let left = self
            .schedule
            .give_up_after
            .saturating_sub(now.saturating_duration_since(started));
        if left.is_zero() {
            return Err(FollowError::Client(error));
        }
        let wait = outage.retry_wait.min(left);
        outage.retry_wait = (outage.retry_wait * 2).min(self.schedule.reconnect_max);
        outage.next_expected = Some(now + wait);
        Ok(wait)
    }
}

/// An outage of one route (the log stream, or the job check): when its first failed request began, when the next request
/// of the route is expected to begin (the previous one's end plus the wait), and the next retry wait.
struct Outage {
    since: Option<tokio::time::Instant>,
    next_expected: Option<tokio::time::Instant>,
    retry_wait: Duration,
}

impl Outage {
    fn new(initial: Duration) -> Self {
        Self {
            since: None,
            next_expected: None,
            retry_wait: initial,
        }
    }

    /// The route worked, or a gap ended the outage without a success: the next failure starts a new outage, whose waits
    /// start again at `initial`.
    fn end(&mut self, initial: Duration) {
        *self = Self::new(initial);
    }
}

/// Moves every line of the stream to the sink, until the server ends it. `job` is the latest state known, for the error.
async fn pump(follow: &mut LogFollow, sink: &mut dyn Events, job: &Job) -> Result<(), FollowError> {
    while let Some(line) = follow.next().await? {
        sink.line(&line)
            .map_err(|e| FollowError::Sink(e, Box::new(job.clone())))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use p2pc_client::testing::fixtures;

    use super::*;

    fn unavailable() -> Error {
        Error::Unexpected(p2pc_client::UnexpectedResponse {
            status: Some(503),
            message: "bad gateway".into(),
        })
    }

    #[derive(Default)]
    struct Noted {
        reconnecting: u32,
    }

    impl Progress for Noted {
        fn on_status(&mut self, _job: &Job) {}

        fn on_reconnecting(&mut self, _error: &Error) {
            self.reconnecting += 1;
        }
    }

    fn follower() -> StreamFollower<TokioSleeper> {
        StreamFollower::new(PollSchedule::default(), TokioSleeper, 0, None)
    }

    /// Plays an outage in which every request fails after `request_takes`, the way the follower would: asks it what to
    /// do after each failure and waits that long. Returns the failures, the time that passed, and the announcements.
    async fn play_outage(request_takes: Duration) -> (u32, Duration, u32, Vec<Duration>) {
        let f = follower();
        let started = tokio::time::Instant::now();
        let mut outage = Outage::new(f.schedule.initial);
        let (mut noted, mut failures, mut waits) = (Noted::default(), 0, Vec::new());
        loop {
            let request_started = tokio::time::Instant::now();
            tokio::time::sleep(request_takes).await;
            failures += 1;
            match f.outage(&mut outage, request_started, unavailable(), &mut noted) {
                Ok(wait) => {
                    waits.push(wait);
                    tokio::time::sleep(wait).await;
                }
                Err(_) => return (failures, started.elapsed(), noted.reconnecting, waits),
            }
        }
    }

    /// T11a review: a short drop (Wi-Fi, a server restart) does not end the follow of an hour-long job. Transient
    /// failures are retried with a growing wait (1 s, doubling, at most 30 s), announced once per outage, and the
    /// follow gives up after five minutes of them.
    #[tokio::test(start_paused = true)]
    async fn an_outage_is_retried_with_a_capped_backoff_and_ends_after_five_minutes() {
        let (_, elapsed, announced, waits) = play_outage(Duration::ZERO).await;
        assert_eq!(announced, 1);
        assert_eq!(
            waits[..6],
            [1, 2, 4, 8, 16, 30].map(Duration::from_secs),
            "doubling up to the cap"
        );
        assert!(waits.iter().all(|w| *w <= Duration::from_secs(30)), "{waits:?}");
        // The last wait is cut to what is left of the budget.
        assert_eq!(waits.iter().sum::<Duration>(), Duration::from_secs(300), "{waits:?}");
        assert_eq!(elapsed, Duration::from_secs(300));
    }

    /// T11b1 review: the 5-minute budget is wall-clock time. Requests that each take a minute use it up in a few
    /// attempts; the waits alone would allow hours of them.
    #[tokio::test(start_paused = true)]
    async fn the_budget_counts_the_time_the_requests_take() {
        let (failures, elapsed, announced, _) = play_outage(Duration::from_secs(60)).await;
        assert_eq!(announced, 1);
        // The outage is timed from the start of its first failed request (t=0), not from its end. Requests of 60 s with
        // waits of 1, 2, 4 and 8 s: the fifth failure ends at 315 s, past the budget.
        assert_eq!(failures, 5);
        assert_eq!(elapsed, Duration::from_secs(315));
    }

    /// Spec §7: a gap longer than the longest wait between two requests of a route (the client was busy with healthy
    /// work on the other route) starts a new outage: announced again, with the first wait again.
    #[tokio::test(start_paused = true)]
    async fn a_gap_longer_than_the_longest_wait_starts_a_new_outage() {
        let f = follower();
        let mut noted = Noted::default();
        let mut outage = Outage::new(f.schedule.initial);
        let fail = |outage: &mut Outage, noted: &mut Noted| {
            f.outage(outage, tokio::time::Instant::now(), unavailable(), noted)
                .unwrap()
        };
        assert_eq!(fail(&mut outage, &mut noted), Duration::from_secs(1));
        // The retry comes after the wait, as usual: the same outage, so the wait grows.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(fail(&mut outage, &mut noted), Duration::from_secs(2));
        // Another 30 s (the longest wait): still the same outage.
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(fail(&mut outage, &mut noted), Duration::from_secs(4));
        assert_eq!(noted.reconnecting, 1);
        // Six minutes of healthy work elsewhere: a new outage, announced again, back to the first wait.
        tokio::time::sleep(Duration::from_secs(360)).await;
        assert_eq!(fail(&mut outage, &mut noted), Duration::from_secs(1));
        assert_eq!(noted.reconnecting, 2);
    }

    /// T13h: the gap is the time spent on the other route's work after the scheduled wait, not the wait itself. A retry
    /// that waited the full 30 s plus 2 s of other work is the same outage; 31 s of other work is a new one.
    #[tokio::test(start_paused = true)]
    async fn the_gap_does_not_count_the_scheduled_wait() {
        let f = follower();
        let mut noted = Noted::default();
        let mut outage = Outage::new(f.schedule.initial);
        let fail = |outage: &mut Outage, noted: &mut Noted| {
            f.outage(outage, tokio::time::Instant::now(), unavailable(), noted)
                .unwrap()
        };
        // Waits 1, 2, 4, 8, 16, 30: each retry comes after its wait and 2 s of other work.
        for expected in [1, 2, 4, 8, 16, 30, 30] {
            let wait = fail(&mut outage, &mut noted);
            assert_eq!(wait, Duration::from_secs(expected));
            tokio::time::sleep(wait + Duration::from_secs(2)).await;
        }
        assert_eq!(noted.reconnecting, 1, "the work in between is no gap");
        // 31 s of other work after the wait: a new outage.
        let wait = fail(&mut outage, &mut noted);
        tokio::time::sleep(wait + Duration::from_secs(31)).await;
        assert_eq!(fail(&mut outage, &mut noted), Duration::from_secs(1));
        assert_eq!(noted.reconnecting, 2);
    }

    #[test]
    fn a_requeued_attempt_is_a_change_but_a_poll_of_the_same_state_is_not() {
        let id = p2pc_proto::ids::JobId::generate();
        let at = |status, attempt| {
            let mut j = fixtures::job(id, status, None);
            j.attempt = attempt;
            state_key(&j)
        };
        assert_ne!(at(JobStatus::Running, 1), at(JobStatus::Queued, 2));
        assert_ne!(at(JobStatus::Queued, 1), at(JobStatus::Queued, 2));
        assert_eq!(at(JobStatus::Running, 1), at(JobStatus::Running, 1));
    }

    #[test]
    fn which_errors_are_transient() {
        let api = |status| {
            Error::Api(p2pc_client::ApiError {
                status,
                code: "x".into(),
                title: "x".into(),
                detail: None,
                errors: vec![],
            })
        };
        for status in [408, 429, 500, 502, 503, 504] {
            assert!(is_transient(&api(status)), "{status}");
        }
        for status in [400, 401, 403, 404, 409, 422] {
            assert!(!is_transient(&api(status)), "{status}");
        }
        assert!(is_transient(&unavailable()));
        let bad_shape = Error::Unexpected(p2pc_client::UnexpectedResponse {
            status: Some(200),
            message: "the response does not have the documented shape".into(),
        });
        assert!(!is_transient(&bad_shape));
    }
}
