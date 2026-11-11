// SPDX-License-Identifier: Apache-2.0

//! One run's messages to the server, in order: `JobStarted`, the `LogChunk`s, `JobFinished` (§6).
//!
//! The sandbox's log pump must never block, or the job would block on a full pipe. So the run task takes each
//! event at once and queues it here without waiting; a sender task of its own ([`deliver`]) hands the queue to the
//! welcomed session's outbox, waiting for a connection when there is none.
//!
//! - **Back-pressure.** Log chunks queued here are bounded by [`LOG_QUEUE_BYTES`] (8 MiB of encoded chunks per
//!   run). Past it the **oldest** chunks are dropped and counted; `JobStarted` and `JobFinished` are never dropped.
//! - **A service's ring** (H2 §11.4). A service's logs are not capped in total, so its queue keeps the **most
//!   recent** [`SERVICE_LOG_RING_BYTES`] (64 MiB of log bytes) as a ring of [`LOG_SEGMENT_BYTES`] (1 MiB) segments:
//!   past the cap the oldest whole segment is dropped and counted, and one marker chunk in its place (on `stderr`,
//!   numbered with the first dropped `seq`, which no chunk sent ever had) records the dropped range. A drop next to a
//!   marker still queued extends it. `JobStarted`, `ServiceHealth` and `JobFinished` are never dropped.
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

use p2pc_proto::api::LogStream;
use p2pc_proto::ids::LeaseId;
use p2pc_proto::protocol::{AgentMsg, LogData};
use p2pc_proto::validate::base64_decoded_len;
use tokio::sync::Notify;

use crate::connection::Uplink;
use crate::connection::uplink::{FrameLoss, JobFrame};

/// Most bytes of queued log chunks per run (their encoded size, as they sit in memory).
pub const LOG_QUEUE_BYTES: usize = 8 * 1024 * 1024;
/// Most log bytes a service run keeps queued (H2 §11.4: the most recent 64 MiB). Encoded, about 85 MiB of memory,
/// reached only while the server cannot take them (the agent stops every job after 45 s without it, SI-13).
pub const SERVICE_LOG_RING_BYTES: u64 = 64 * 1024 * 1024;
/// The segment of a service's ring (H2 §11.4: 1 MiB): whole segments are dropped, the oldest first.
pub const LOG_SEGMENT_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
struct Item {
    msg: AgentMsg,
    /// For a log chunk: its encoded size and its raw size.
    log: Option<(usize, u64)>,
    /// For a log chunk of a ring: its segment.
    segment: Option<u64>,
    /// For a ring's marker: the range it records.
    marker: Option<Dropped>,
}

/// A range of log chunks a ring dropped.
#[derive(Debug, Clone, Copy)]
struct Dropped {
    first: u64,
    last: u64,
    chunks: u64,
    bytes: u64,
}

impl Dropped {
    fn marker(&self, lease_id: LeaseId, epoch: u64, cap: u64) -> AgentMsg {
        let text = format!(
            "\n[p2pc] log chunks {}-{} ({} bytes) were dropped: the service wrote more than the {} MiB the agent \
             keeps while the server could not take them\n",
            self.first,
            self.last,
            self.bytes,
            cap / LOG_SEGMENT_BYTES
        );
        AgentMsg::LogChunk {
            lease_id,
            epoch,
            stream: LogStream::Stderr,
            seq: self.first,
            data_b64: LogData::encode(text.as_bytes()),
        }
    }
}

/// How a run's queue bounds its log chunks.
#[derive(Debug, Clone, Copy)]
enum Limit {
    /// A batch run (H1): at most this many bytes of encoded chunks; the oldest chunks go first.
    Queue(usize),
    /// A service run (H2 §11.4): at most `cap` raw bytes, in segments of `segment` raw bytes.
    Ring { cap: u64, segment: u64 },
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
    /// A ring's raw bytes queued.
    ring_bytes: u64,
    /// The ring's segment being filled, and its raw bytes so far.
    segment: u64,
    segment_bytes: u64,
}

impl Inner {
    /// Drops the oldest whole segment of a ring, and records it in a marker. False when there is none to drop but
    /// the one being filled.
    fn drop_oldest_segment(&mut self, cap: u64) -> bool {
        let Some(oldest) = self.queue.iter().find_map(|i| i.segment) else {
            return false;
        };
        if oldest == self.segment {
            return false;
        }
        let Some(at) = self.queue.iter().position(|i| i.segment == Some(oldest)) else {
            return false;
        };
        let mut range: Option<Dropped> = None;
        let mut owner = None;
        let (mut enc, mut raw) = (0usize, 0u64);
        self.queue.retain(|i| {
            if i.segment != Some(oldest) {
                return true;
            }
            if let AgentMsg::LogChunk {
                lease_id, epoch, seq, ..
            } = &i.msg
            {
                owner.get_or_insert((*lease_id, *epoch));
                let bytes = i.log.map_or(0, |(_, r)| r);
                let r = range.get_or_insert(Dropped {
                    first: *seq,
                    last: *seq,
                    chunks: 0,
                    bytes: 0,
                });
                r.first = r.first.min(*seq);
                r.last = r.last.max(*seq);
                r.chunks += 1;
                r.bytes += bytes;
            }
            if let Some((e, r)) = i.log {
                enc += e;
                raw += r;
            }
            false
        });
        self.log_bytes -= enc;
        self.ring_bytes -= raw;
        let (Some(range), Some((lease_id, epoch))) = (range, owner) else {
            return true;
        };
        self.dropped_chunks += range.chunks;
        self.dropped_bytes += range.bytes;
        // Next to a marker still queued: extend it (its `seq` stays the first dropped one).
        if let Some(prev) = at.checked_sub(1).and_then(|p| self.queue.get_mut(p))
            && let Some(m) = prev.marker.as_mut()
        {
            m.last = m.last.max(range.last);
            m.chunks += range.chunks;
            m.bytes += range.bytes;
            prev.msg = m.marker(lease_id, epoch, cap);
            return true;
        }
        self.queue.insert(
            at,
            Item {
                msg: range.marker(lease_id, epoch, cap),
                log: None,
                segment: None,
                marker: Some(range),
            },
        );
        true
    }
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
    limit: Limit,
    log_bytes_sent: AtomicU64,
}

impl Default for RunOutbox {
    fn default() -> Self {
        Self::with_cap(LOG_QUEUE_BYTES)
    }
}

impl RunOutbox {
    /// A queue that keeps at most `cap` bytes of log chunks (a batch run).
    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        Self::limited(Limit::Queue(cap))
    }

    /// A service run's ring: at most `cap` raw log bytes, dropped in whole segments of `segment` bytes
    /// ([`SERVICE_LOG_RING_BYTES`] and [`LOG_SEGMENT_BYTES`] in the agent). `cap` is raised to one segment if lower.
    #[must_use]
    pub fn ring(cap: u64, segment: u64) -> Self {
        let segment = segment.max(1);
        Self::limited(Limit::Ring {
            cap: cap.max(segment),
            segment,
        })
    }

    fn limited(limit: Limit) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            changed: Notify::new(),
            limit,
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
            q.queue.push_back(Item {
                msg,
                log: None,
                segment: None,
                marker: None,
            });
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
            let cap = match self.limit {
                Limit::Queue(cap) => cap,
                Limit::Ring { cap, segment } => {
                    // A new segment when this chunk would not fit in the one being filled.
                    if q.segment_bytes > 0 && q.segment_bytes + raw > segment {
                        q.segment += 1;
                        q.segment_bytes = 0;
                    }
                    q.segment_bytes += raw;
                    q.ring_bytes += raw;
                    q.log_bytes += size;
                    let segment = Some(q.segment);
                    q.queue.push_back(Item {
                        msg,
                        log: Some((size, raw)),
                        segment,
                        marker: None,
                    });
                    while q.ring_bytes > cap && q.drop_oldest_segment(cap) {}
                    drop(q);
                    self.changed.notify_waiters();
                    return;
                }
            };
            while q.log_bytes + size > cap {
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
            if q.log_bytes + size > cap {
                // A single chunk larger than the whole cap (never with 64 KiB chunks): drop it.
                q.dropped_chunks += 1;
                q.dropped_bytes += raw;
                return;
            }
            q.log_bytes += size;
            q.queue.push_back(Item {
                msg,
                log: Some((size, raw)),
                segment: None,
                marker: None,
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
            q.ring_bytes = 0;
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
                    if let Some((enc, raw)) = item.log {
                        q.log_bytes -= enc;
                        if item.segment.is_some() {
                            q.ring_bytes -= raw;
                        }
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

    fn text_of(m: &AgentMsg) -> String {
        match m {
            AgentMsg::LogChunk { data_b64, .. } => {
                String::from_utf8(data_encoding::BASE64.decode(data_b64.as_str().as_bytes()).unwrap()).unwrap()
            }
            other => panic!("not a log chunk: {other:?}"),
        }
    }

    /// H2 §11.4: a service's queue is a ring of segments. Over its cap, the oldest whole segment goes, counted, and one
    /// marker in its place, numbered with the first dropped `seq`, records the range; a second drop next to a marker
    /// still queued extends it.
    #[tokio::test]
    async fn a_ring_drops_the_oldest_whole_segment_and_marks_the_range() {
        // 40 raw bytes, segments of 10: two chunks of 5 bytes per segment.
        let q = RunOutbox::ring(40, 10);
        q.push(AgentMsg::Unknown);
        for s in 0..12 {
            q.push_log(chunk(s, 5), 5);
        }
        q.push(AgentMsg::Unknown);
        q.close();
        assert_eq!(q.drops(), Drops { chunks: 4, bytes: 20 });
        let mut got = Vec::new();
        while let Some(item) = q.next().await {
            got.push(item.msg);
        }
        let order: Vec<Option<u64>> = got.iter().map(seq).collect();
        assert_eq!(
            order,
            [
                None,
                Some(0),
                Some(4),
                Some(5),
                Some(6),
                Some(7),
                Some(8),
                Some(9),
                Some(10),
                Some(11),
                None
            ]
        );
        let marker = text_of(&got[1]);
        assert!(
            marker.starts_with("\n[p2pc] log chunks 0-3 (20 bytes) were dropped"),
            "{marker}"
        );
        assert!(matches!(
            got[1],
            AgentMsg::LogChunk {
                stream: LogStream::Stderr,
                ..
            }
        ));
        assert_eq!(AgentMsg::validate(&got[1]), Ok(()));
    }

    /// A marker already handed to a session is never changed: the next drop gets a marker of its own.
    #[tokio::test]
    async fn a_ring_marker_already_taken_starts_a_new_one() {
        let q = RunOutbox::ring(20, 10);
        for s in 0..6 {
            q.push_log(chunk(s, 5), 5);
        }
        let first = q.next().await.unwrap().msg;
        assert_eq!(seq(&first), Some(0));
        assert!(text_of(&first).contains("log chunks 0-1 (10 bytes)"));
        q.push_log(chunk(6, 5), 5);
        q.close();
        let mut got = Vec::new();
        while let Some(item) = q.next().await {
            got.push(item.msg);
        }
        let order: Vec<Option<u64>> = got.iter().map(seq).collect();
        assert_eq!(order, [Some(2), Some(4), Some(5), Some(6)]);
        assert!(text_of(&got[0]).contains("log chunks 2-3 (10 bytes)"));
        assert_eq!(q.drops(), Drops { chunks: 4, bytes: 20 });
    }

    /// While the server takes them, a ring drops nothing, however much the service writes in total.
    #[tokio::test]
    async fn a_ring_that_is_drained_drops_nothing() {
        let q = RunOutbox::ring(20, 10);
        for s in 0..1000 {
            q.push_log(chunk(s, 5), 5);
            assert_eq!(q.next().await.as_ref().map(|i| seq(&i.msg)), Some(Some(s)));
        }
        assert_eq!(q.drops(), Drops::default());
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
