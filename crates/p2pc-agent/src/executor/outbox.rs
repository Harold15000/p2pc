// SPDX-License-Identifier: Apache-2.0

//! One run's messages to the server, in order: `JobStarted`, the `LogChunk`s, `JobFinished` (§6).
//!
//! The sandbox's log pump must never block, or the job would block on a full pipe. So the run task takes each
//! event at once and queues it here without waiting; a sender task of its own ([`deliver`]) hands the queue to the
//! welcomed session's outbox, waiting for a connection when there is none.
//!
//! - **Back-pressure.** Log chunks queued here are bounded by [`LOG_QUEUE_BYTES`] (8 MiB of encoded chunks per
//!   run). Past it the **oldest** chunks are dropped and counted; `JobStarted` and `JobFinished` are never dropped.
//! - **Silence.** A run replaced by a newer epoch, or stopped by `stop_all`, is silenced: its queue is emptied and
//!   nothing more is ever sent for it (fencing on the node, SI-8; SI-13).
//! - **Delivery.** Each message goes to the session's job queue as a [`JobFrame`]. A log chunk whose session dies
//!   before writing it is counted as dropped ([`FrameLoss`]), like one dropped for the cap: none is lost silently.
//! - **`JobFinished` is confirmed** (§6, amended 2026-11-06): it is sent again on every new session, right after its
//!   `Welcome`, until the server answers a heartbeat written after it. Until then [`deliver`] does not return, so the
//!   run stays in `running()` and a reconnect lists it in `Hello`: a report lost with a connection never turns a
//!   finished job into a requeue.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use p2pc_proto::protocol::AgentMsg;
use p2pc_proto::validate::base64_decoded_len;
use tokio::sync::Notify;

use crate::connection::Uplink;
use crate::connection::uplink::{FrameLoss, JobFrame};

/// Most bytes of queued log chunks per run (their encoded size, as they sit in memory).
pub const LOG_QUEUE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
struct Item {
    msg: AgentMsg,
    /// For a log chunk: its encoded size and its raw size.
    log: Option<(usize, u64)>,
}

#[derive(Debug, Default)]
struct Inner {
    queue: VecDeque<Item>,
    log_bytes: usize,
    dropped_chunks: u64,
    dropped_bytes: u64,
    /// No more messages will be queued (`JobFinished` is in).
    closed: bool,
    /// Nothing more may be sent.
    silenced: bool,
}

/// What a run's queue dropped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Drops {
    /// Log chunks dropped: to stay within [`LOG_QUEUE_BYTES`], or with a session that ended before writing them.
    pub chunks: u64,
    /// Their raw bytes.
    pub bytes: u64,
}

/// One run's queue.
#[derive(Debug)]
pub struct RunOutbox {
    inner: Mutex<Inner>,
    /// Woken with `notify_waiters` (the sender and the run task may both wait on it); each waiter enables its
    /// `Notified` before it reads the state, so no change is missed.
    changed: Notify,
    cap: usize,
    log_bytes_sent: AtomicU64,
}

impl Default for RunOutbox {
    fn default() -> Self {
        Self::with_cap(LOG_QUEUE_BYTES)
    }
}

impl RunOutbox {
    /// A queue that keeps at most `cap` bytes of log chunks.
    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            changed: Notify::new(),
            cap,
            log_bytes_sent: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues a message that is never dropped (`JobStarted`, `JobFinished`). Never blocks.
    pub fn push(&self, msg: AgentMsg) {
        {
            let mut q = self.lock();
            if q.silenced || q.closed {
                return;
            }
            q.queue.push_back(Item { msg, log: None });
        }
        self.changed.notify_waiters();
    }

    /// Queues a `LogChunk` of `raw` bytes, dropping the oldest queued chunks if the queue would go over its cap.
    /// Never blocks.
    pub fn push_log(&self, msg: AgentMsg, raw: u64) {
        let size = match &msg {
            AgentMsg::LogChunk { data_b64, .. } => data_b64.as_str().len(),
            _ => 0,
        };
        {
            let mut q = self.lock();
            if q.silenced || q.closed {
                return;
            }
            while q.log_bytes + size > self.cap {
                let Some(at) = q.queue.iter().position(|i| i.log.is_some()) else {
                    break;
                };
                if let Some(Item {
                    log: Some((enc, bytes)),
                    ..
                }) = q.queue.remove(at)
                {
                    q.log_bytes -= enc;
                    q.dropped_chunks += 1;
                    q.dropped_bytes += bytes;
                }
            }
            if q.log_bytes + size > self.cap {
                // A single chunk larger than the whole cap (never with 64 KiB chunks): drop it.
                q.dropped_chunks += 1;
                q.dropped_bytes += raw;
                return;
            }
            q.log_bytes += size;
            q.queue.push_back(Item {
                msg,
                log: Some((size, raw)),
            });
        }
        self.changed.notify_waiters();
    }

    /// No more messages: the sender stops once the queue is empty.
    pub fn close(&self) {
        self.lock().closed = true;
        self.changed.notify_waiters();
    }

    /// Drops everything queued and sends nothing more, ever.
    pub fn silence(&self) {
        {
            let mut q = self.lock();
            q.silenced = true;
            q.queue.clear();
            q.log_bytes = 0;
        }
        self.changed.notify_waiters();
    }

    /// Whether the run was silenced.
    #[must_use]
    pub fn is_silenced(&self) -> bool {
        self.lock().silenced
    }

    /// What was dropped so far.
    #[must_use]
    pub fn drops(&self) -> Drops {
        let q = self.lock();
        Drops {
            chunks: q.dropped_chunks,
            bytes: q.dropped_bytes,
        }
    }

    /// Raw log bytes handed to a session so far (`p2pc-agent status`).
    #[must_use]
    pub fn log_bytes_sent(&self) -> u64 {
        self.log_bytes_sent.load(Ordering::Relaxed)
    }

    /// Resolves once the run is silenced.
    pub async fn silenced(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_silenced() {
                return;
            }
            notified.await;
        }
    }

    /// The next message, waiting for one; `None` once closed and empty, or silenced.
    async fn next(&self) -> Option<Item> {
        loop {
            // Registered before the state is read, so a change in between is never missed.
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut q = self.lock();
                if q.silenced {
                    return None;
                }
                if let Some(item) = q.queue.pop_front() {
                    if let Some((enc, _)) = item.log {
                        q.log_bytes -= enc;
                    }
                    return Some(item);
                }
                if q.closed {
                    return None;
                }
            }
            notified.await;
        }
    }
}

impl FrameLoss for RunOutbox {
    /// A frame its session never wrote: a log chunk counts as dropped (a silenced run's do not count: nothing of it
    /// was to be sent). A `JobFinished` is sent again by [`deliver`] until confirmed.
    fn lost(&self, msg: &AgentMsg) {
        if let AgentMsg::LogChunk { data_b64, .. } = msg {
            let raw = base64_decoded_len(data_b64.as_str()).unwrap_or(0) as u64;
            let mut q = self.lock();
            if q.silenced {
                return;
            }
            q.dropped_chunks += 1;
            q.dropped_bytes += raw;
            drop(q);
            let _ = self
                .log_bytes_sent
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |sent| {
                    Some(sent.saturating_sub(raw))
                });
        }
    }
}

/// Hands `outbox` to the welcomed session of the moment, in order, until it is closed and empty (the `JobFinished`
/// confirmed) or silenced. A message whose session ended before taking it waits for the next session.
///
/// Two messages are rebuilt for each session instead of being offered again as they were: `JobFinished`, until the
/// server confirms it, and `JobStarted`, until a session has written it (the server deduplicates it by kind, §6, so
/// a second copy is harmless). The logs queued behind a `JobStarted` wait for it.
pub async fn deliver(outbox: &Arc<RunOutbox>, uplink: &Uplink) {
    let loss: Arc<dyn FrameLoss> = outbox.clone();
    while let Some(item) = outbox.next().await {
        let report = matches!(item.msg, AgentMsg::JobFinished { .. });
        let started = matches!(item.msg, AgentMsg::JobStarted { .. });
        // A frame that comes back unsent is offered again as is; these two are rebuilt for each session.
        let mut kept = (!report && !started).then(|| JobFrame::new(item.msg.clone(), Some(loss.clone())));
        loop {
            let port = tokio::select! {
                port = uplink.connected() => port,
                () = outbox.silenced() => return,
            };
            let (frame, confirmation, written) = match kept.take() {
                Some(frame) => (frame, None, None),
                None if started => {
                    let (frame, written) = JobFrame::new(item.msg.clone(), None).signalled();
                    (frame, None, Some(written))
                }
                None => {
                    let (frame, confirmation) = JobFrame::new(item.msg.clone(), None).confirmed();
                    (frame, Some(confirmation), None)
                }
            };
            let sent = tokio::select! {
                r = port.send(frame) => r,
                () = outbox.silenced() => return,
            };
            match sent {
                // That session ended before taking it: the next one gets it.
                Err(back) => kept = (!report && !started).then_some(*back),
                Ok(()) => {
                    if let Some((_, raw)) = item.log {
                        outbox.log_bytes_sent.fetch_add(raw, Ordering::Relaxed);
                    }
                    if let Some(written) = written {
                        // Taken by the session's queue: done once its writer wrote it. If the session ends first
                        // the frame is dropped unwritten, and the next session gets a new one.
                        let done = tokio::select! {
                            r = written => r.is_ok(),
                            () = uplink.changed_from(port.session()) => false,
                            () = outbox.silenced() => return,
                        };
                        if done {
                            break;
                        }
                        tracing::info!(
                            session = port.session(),
                            "a JobStarted was not written before its session ended; sending it again on the next one"
                        );
                    } else if let Some(mut confirmation) = confirmation {
                        // §6: kept until a heartbeat written after it is answered; sent again on the next session.
                        let confirmed = tokio::select! {
                            r = confirmation.wait_for(|c| *c) => r.is_ok(),
                            () = uplink.changed_from(port.session()) => false,
                            () = outbox.silenced() => return,
                        };
                        if confirmed {
                            break;
                        }
                        tracing::info!(
                            session = port.session(),
                            "a JobFinished was not confirmed before its session ended; sending it again on the next one"
                        );
                    } else {
                        break;
                    }
                }
            }
            tokio::select! {
                () = uplink.changed_from(port.session()) => {}
                () = outbox.silenced() => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use p2pc_proto::api::LogStream;
    use p2pc_proto::ids::LeaseId;
    use p2pc_proto::protocol::{LogData, Outcome, Usage};
    use tokio::sync::mpsc;

    use super::*;
    use crate::connection::Port;
    use crate::connection::transport::NoStreams;
    use crate::connection::uplink::Acks;

    fn chunk(seq: u64, len: usize) -> AgentMsg {
        AgentMsg::LogChunk {
            lease_id: LeaseId::generate(),
            epoch: 1,
            stream: LogStream::Stdout,
            seq,
            data_b64: LogData::encode(&vec![b'x'; len]),
        }
    }

    fn finished() -> AgentMsg {
        AgentMsg::JobFinished {
            lease_id: LeaseId::generate(),
            epoch: 1,
            outcome: Outcome::Exited,
            exit_code: Some(0),
            error: None,
            usage: Usage {
                wall_ms: 1,
                cpu_used_ms: 1,
                max_rss_mb: 1,
            },
            outputs: vec![],
        }
    }

    fn seq(m: &AgentMsg) -> Option<u64> {
        match m {
            AgentMsg::LogChunk { seq, .. } => Some(*seq),
            _ => None,
        }
    }

    /// Takes the next frame as a session that wrote it, and returns its message.
    async fn take(rx: &mut mpsc::Receiver<JobFrame>) -> Option<AgentMsg> {
        let frame = rx.recv().await?;
        let msg = frame.msg().cloned();
        let _ = frame.written();
        msg
    }

    /// The log queue overflows while the connection is down: the oldest chunks go, counted; the never-dropped
    /// messages stay, in order.
    #[tokio::test]
    async fn the_log_queue_drops_the_oldest_chunks_and_counts_them() {
        // Room for 3 chunks of 3 bytes (4 encoded bytes each).
        let q = RunOutbox::with_cap(12);
        q.push(AgentMsg::Unknown);
        for s in 0..5 {
            q.push_log(chunk(s, 3), 3);
        }
        q.push(AgentMsg::Unknown);
        q.close();
        assert_eq!(q.drops(), Drops { chunks: 2, bytes: 6 });
        let mut got = Vec::new();
        while let Some(item) = q.next().await {
            got.push(item.msg);
        }
        let order: Vec<Option<u64>> = got.iter().map(seq).collect();
        assert_eq!(order, [None, Some(2), Some(3), Some(4), None]);
        // Closed: nothing more is queued.
        q.push(AgentMsg::Unknown);
        assert!(q.next().await.is_none());
    }

    #[tokio::test]
    async fn delivery_waits_for_a_session_and_survives_its_end() {
        let q = Arc::new(RunOutbox::default());
        let uplink = Uplink::new();
        let task = {
            let (q, uplink) = (q.clone(), uplink.clone());
            tokio::spawn(async move { deliver(&q, &uplink).await })
        };
        q.push(AgentMsg::Unknown);
        q.push_log(chunk(0, 5), 5);
        // A session that is gone before it takes anything.
        let (dead, dead_rx) = mpsc::channel(1);
        drop(dead_rx);
        let first = uplink.connect(Port::new(&dead, Arc::new(NoStreams)));
        tokio::task::yield_now().await;
        uplink.disconnect(first);
        // The next one gets everything, in order, and nothing was counted lost.
        let (tx, mut rx) = mpsc::channel(8);
        uplink.connect(Port::new(&tx, Arc::new(NoStreams)));
        assert_eq!(take(&mut rx).await, Some(AgentMsg::Unknown));
        assert_eq!(take(&mut rx).await.as_ref().and_then(seq), Some(0));
        q.close();
        task.await.unwrap();
        assert_eq!(q.log_bytes_sent(), 5);
        assert_eq!(q.drops(), Drops::default());
    }

    /// No frame is lost silently: a chunk its session took but never wrote counts as dropped.
    #[tokio::test]
    async fn a_chunk_its_session_never_wrote_is_counted() {
        let q = Arc::new(RunOutbox::default());
        let uplink = Uplink::new();
        let (tx, mut rx) = mpsc::channel(8);
        uplink.connect(Port::new(&tx, Arc::new(NoStreams)));
        q.push_log(chunk(0, 5), 5);
        q.push_log(chunk(1, 7), 7);
        q.close();
        deliver(&q, &uplink).await;
        assert_eq!(q.log_bytes_sent(), 12);
        // The session wrote the first and died with the second still queued.
        assert_eq!(take(&mut rx).await.as_ref().and_then(seq), Some(0));
        drop(rx);
        assert_eq!(q.drops(), Drops { chunks: 1, bytes: 7 });
        assert_eq!(q.log_bytes_sent(), 5);
    }

    fn started() -> AgentMsg {
        AgentMsg::JobStarted {
            lease_id: LeaseId::generate(),
            epoch: 1,
            started_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn is_started(m: &AgentMsg) -> bool {
        matches!(m, AgentMsg::JobStarted { .. })
    }

    /// T10c: a `JobStarted` its session took but never wrote (queued, or being written when the session ended) is
    /// rebuilt for the next session until one writes it; the logs behind it wait their turn. The server deduplicates
    /// it by kind (§6), so sending it twice is harmless.
    #[tokio::test]
    async fn a_job_started_its_session_never_wrote_goes_out_again_on_the_next_session() {
        let q = Arc::new(RunOutbox::default());
        let uplink = Uplink::new();
        q.push(started());
        q.push_log(chunk(0, 5), 5);
        q.close();
        let task = {
            let (q, uplink) = (q.clone(), uplink.clone());
            tokio::spawn(async move { deliver(&q, &uplink).await })
        };
        // Session 1 takes it and dies before writing it.
        let (tx, mut rx) = mpsc::channel(8);
        let first = uplink.connect(Port::new(&tx, Arc::new(NoStreams)));
        let frame = rx.recv().await.unwrap();
        assert!(frame.msg().is_some_and(is_started));
        drop(frame);
        drop(rx);
        uplink.disconnect(first);
        assert!(!task.is_finished(), "kept: not written");
        // Session 2 gets a fresh one, then the log; nothing was counted lost.
        let (tx2, mut rx2) = mpsc::channel(8);
        uplink.connect(Port::new(&tx2, Arc::new(NoStreams)));
        let msg = take(&mut rx2).await.unwrap();
        assert!(is_started(&msg), "{msg:?}");
        assert_eq!(take(&mut rx2).await.as_ref().and_then(seq), Some(0));
        task.await.unwrap();
        assert_eq!(q.drops(), Drops::default());
    }

    /// §6: `JobFinished` is sent again on the next session until a heartbeat written after it is answered.
    #[tokio::test]
    async fn job_finished_is_resent_until_a_later_heartbeat_is_answered() {
        let q = Arc::new(RunOutbox::default());
        let uplink = Uplink::new();
        q.push(finished());
        q.close();
        let task = {
            let (q, uplink) = (q.clone(), uplink.clone());
            tokio::spawn(async move { deliver(&q, &uplink).await })
        };
        // Session 1 writes it, and ends before any heartbeat after it is answered.
        let (tx, mut rx) = mpsc::channel(8);
        let first = uplink.connect(Port::new(&tx, Arc::new(NoStreams)));
        let acks = Acks::default();
        acks.heartbeat_written(4);
        let frame = rx.recv().await.unwrap();
        assert!(matches!(frame.msg(), Some(AgentMsg::JobFinished { .. })));
        acks.report_written(frame.written().unwrap());
        acks.acked(4);
        drop(acks);
        uplink.disconnect(first);
        assert!(!task.is_finished(), "kept: not confirmed");
        // Session 2 gets it again, and a later heartbeat's answer confirms it.
        let (tx2, mut rx2) = mpsc::channel(8);
        uplink.connect(Port::new(&tx2, Arc::new(NoStreams)));
        let frame = rx2.recv().await.unwrap();
        assert!(matches!(frame.msg(), Some(AgentMsg::JobFinished { .. })));
        let acks = Acks::default();
        acks.report_written(frame.written().unwrap());
        acks.heartbeat_written(1);
        acks.acked(1);
        task.await.unwrap();
        drop(tx);
    }

    #[tokio::test]
    async fn a_silenced_run_sends_nothing_more() {
        let q = Arc::new(RunOutbox::default());
        let uplink = Uplink::new();
        q.push(AgentMsg::Unknown);
        q.silence();
        q.push(AgentMsg::Unknown);
        q.push_log(chunk(0, 5), 5);
        let (tx, mut rx) = mpsc::channel(8);
        uplink.connect(Port::new(&tx, Arc::new(NoStreams)));
        deliver(&q, &uplink).await;
        drop(tx);
        assert!(rx.recv().await.is_none());
        // Silenced while waiting for a connection: the sender ends too.
        let q = Arc::new(RunOutbox::default());
        let idle = Uplink::new();
        q.push(AgentMsg::Unknown);
        let task = {
            let (q, idle) = (q.clone(), idle.clone());
            tokio::spawn(async move { deliver(&q, &idle).await })
        };
        tokio::task::yield_now().await;
        q.silence();
        task.await.unwrap();
    }
}
