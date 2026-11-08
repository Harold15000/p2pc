// SPDX-License-Identifier: Apache-2.0

//! The executor's way to the server (T10a): the welcomed session of the moment, if any.
//!
//! Sessions come and go; jobs outlive them. A session publishes a [`Port`] once its `Welcome` arrived (so nothing a job
//! sends can go out before `Hello`) and withdraws it when it ends. Its uploads open their own streams on the same
//! connection (§6 "Uploads").
//!
//! - **Job frames have their own small queue** ([`JOB_QUEUE`] frames per session), apart from the control frames
//!   (heartbeats, lease answers, inventory updates). The session's writer always takes a waiting control frame
//!   first, so a job logging at full speed delays a heartbeat or a `LeaseAccepted` by at most the job frame being
//!   written (T10a review, P2-1).
//! - **No frame is lost silently.** A [`JobFrame`] that is dropped unwritten (its session ended first) tells its
//!   run through [`FrameLoss`], which counts lost log chunks.
//! - **`JobFinished` is confirmed** (§6, amended 2026-11-06): the writer notes the last heartbeat written before it,
//!   and the report is confirmed when the server answers a later one ([`Acks`]). Until then its run keeps it.
//!
//! The port holds only a **weak** handle on the job queue: a session that ends must never be kept alive, or kept
//! flushing, by a job that still holds its port.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use p2pc_proto::protocol::AgentMsg;
use tokio::sync::{mpsc, oneshot, watch};

use super::transport::StreamOpener;

/// Job frames queued per session, beyond the one being written.
pub const JOB_QUEUE: usize = 4;

/// Why a message could not be handed to a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the connection to the server is gone")]
pub struct Gone;

/// Told when a job frame is dropped without being written.
pub trait FrameLoss: Send + Sync + 'static {
    /// `msg` was never written: its session ended first.
    fn lost(&self, msg: &AgentMsg);
}

/// Resolves when a `JobFinished` is confirmed (a later heartbeat was answered).
pub type Confirmation = watch::Receiver<bool>;

/// Resolves to `Ok` when a frame is written, and errs when it is dropped unwritten (its session ended first).
pub type WrittenSignal = oneshot::Receiver<()>;

/// A job's message on its way to the server.
pub struct JobFrame {
    msg: Option<AgentMsg>,
    loss: Option<Arc<dyn FrameLoss>>,
    confirm: Option<watch::Sender<bool>>,
    on_written: Option<oneshot::Sender<()>>,
}

impl fmt::Debug for JobFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JobFrame")
            .field("kind", &self.msg.as_ref().map(AgentMsg::kind))
            .field("confirmed_by_heartbeat", &self.confirm.is_some())
            .finish_non_exhaustive()
    }
}

impl JobFrame {
    /// `msg`, reporting to `loss` if it is dropped unwritten.
    #[must_use]
    pub fn new(msg: AgentMsg, loss: Option<Arc<dyn FrameLoss>>) -> Self {
        Self {
            msg: Some(msg),
            loss,
            confirm: None,
            on_written: None,
        }
    }

    /// The same frame, signalled when the session's writer has written it: the receiver resolves then, and errs if
    /// the frame is dropped unwritten.
    #[must_use]
    pub fn signalled(mut self) -> (Self, WrittenSignal) {
        let (tx, rx) = oneshot::channel();
        self.on_written = Some(tx);
        (self, rx)
    }

    /// The same frame, confirmed by a later answered heartbeat: the receiver resolves to `true` then, and errs if
    /// the session ends first.
    #[must_use]
    pub fn confirmed(mut self) -> (Self, Confirmation) {
        let (tx, rx) = watch::channel(false);
        self.confirm = Some(tx);
        (self, rx)
    }

    /// The message.
    #[must_use]
    pub fn msg(&self) -> Option<&AgentMsg> {
        self.msg.as_ref()
    }

    /// The frame was written: no loss is reported. Returns the confirmation to arm, if it wants one.
    pub fn written(mut self) -> Option<watch::Sender<bool>> {
        self.msg = None;
        if let Some(signal) = self.on_written.take() {
            let _ = signal.send(());
        }
        self.confirm.take()
    }
}

impl Drop for JobFrame {
    fn drop(&mut self) {
        if let (Some(msg), Some(loss)) = (self.msg.take(), self.loss.as_ref()) {
            loss.lost(&msg);
        }
    }
}

/// One session's heartbeat bookkeeping for `JobFinished` confirmations (§6).
#[derive(Debug, Default)]
pub struct Acks {
    inner: Mutex<AcksInner>,
}

#[derive(Debug, Default)]
struct AcksInner {
    /// The `seq` of the last heartbeat written.
    last_heartbeat: u64,
    /// Reports written, each with the last heartbeat written before it.
    pending: Vec<(u64, watch::Sender<bool>)>,
}

impl Acks {
    /// The writer wrote `Heartbeat{seq}`.
    pub fn heartbeat_written(&self, seq: u64) {
        let mut a = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        a.last_heartbeat = a.last_heartbeat.max(seq);
    }

    /// The writer wrote a report that wants a confirmation.
    pub fn report_written(&self, confirm: watch::Sender<bool>) {
        let mut a = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let after = a.last_heartbeat;
        a.pending.push((after, confirm));
    }

    /// `HeartbeatAck{seq}`: confirms every report written before heartbeat `seq`.
    pub fn acked(&self, seq: u64) {
        let mut a = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        a.pending.retain(|(after, confirm)| {
            if seq > *after {
                confirm.send_replace(true);
                false
            } else {
                true
            }
        });
    }
}

/// One welcomed session's job queue and stream opener.
#[derive(Clone)]
pub struct Port {
    jobs: mpsc::WeakSender<JobFrame>,
    streams: Arc<dyn StreamOpener>,
    session: u64,
}

impl fmt::Debug for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Port")
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

impl Port {
    /// A port on `jobs` (the session's job queue) and `streams`.
    #[must_use]
    pub fn new(jobs: &mpsc::Sender<JobFrame>, streams: Arc<dyn StreamOpener>) -> Self {
        Self {
            jobs: jobs.downgrade(),
            streams,
            session: 0,
        }
    }

    /// Queues `frame`, waiting for room (back-pressure from a slow peer).
    ///
    /// # Errors
    /// The frame back, when the session ended: it was not queued and nothing is reported lost.
    pub async fn send(&self, frame: JobFrame) -> Result<(), Box<JobFrame>> {
        let Some(tx) = self.jobs.upgrade() else {
            return Err(Box::new(frame));
        };
        tx.send(frame).await.map_err(|e| Box::new(e.0))
    }

    /// Opens streams on this session's connection.
    #[must_use]
    pub fn streams(&self) -> &Arc<dyn StreamOpener> {
        &self.streams
    }

    /// Which session this is (increases with each `Welcome`).
    #[must_use]
    pub fn session(&self) -> u64 {
        self.session
    }
}

/// The current port. Clones share it.
#[derive(Debug, Clone)]
pub struct Uplink {
    tx: Arc<watch::Sender<Option<Port>>>,
    /// The last session number given: numbers never repeat, even after a gap with no session.
    sessions: Arc<AtomicU64>,
}

impl Default for Uplink {
    fn default() -> Self {
        Self::new()
    }
}

impl Uplink {
    /// No session yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx: Arc::new(watch::channel(None).0),
            sessions: Arc::new(AtomicU64::new(0)),
        }
    }

    /// A session was welcomed: `port` is the way to the server until [`Uplink::disconnect`]. Returns its number.
    pub fn connect(&self, mut port: Port) -> u64 {
        let number = self.sessions.fetch_add(1, Ordering::Relaxed) + 1;
        port.session = number;
        self.tx.send_replace(Some(port));
        number
    }

    /// Session `session` ended. A later session's port is left alone.
    pub fn disconnect(&self, session: u64) {
        self.tx.send_if_modified(|slot| {
            if slot.as_ref().is_some_and(|p| p.session == session) {
                *slot = None;
                true
            } else {
                false
            }
        });
    }

    /// The port now, if a session is welcomed.
    #[must_use]
    pub fn current(&self) -> Option<Port> {
        self.tx.borrow().clone()
    }

    /// Waits for a welcomed session.
    pub async fn connected(&self) -> Port {
        let mut rx = self.tx.subscribe();
        loop {
            if let Some(port) = rx.borrow_and_update().clone() {
                return port;
            }
            // The sender lives in `self`: `changed` cannot fail while we hold it.
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    /// Waits until the current port is no longer session `session` (it ended, or another one replaced it).
    pub async fn changed_from(&self, session: u64) {
        let mut rx = self.tx.subscribe();
        loop {
            if rx.borrow_and_update().as_ref().map(Port::session) != Some(session) {
                return;
            }
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use crate::connection::transport::NoStreams;

    #[derive(Default)]
    struct Count(AtomicUsize);

    impl FrameLoss for Count {
        fn lost(&self, _: &AgentMsg) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn frame(count: &Arc<Count>) -> JobFrame {
        JobFrame::new(AgentMsg::Unknown, Some(count.clone() as Arc<dyn FrameLoss>))
    }

    #[tokio::test]
    async fn a_port_goes_with_its_session_and_never_keeps_the_queue_alive() {
        let lost = Arc::new(Count::default());
        let uplink = Uplink::new();
        assert!(uplink.current().is_none());
        let (tx, mut rx) = mpsc::channel(4);
        let first = uplink.connect(Port::new(&tx, Arc::new(NoStreams)));
        let port = uplink.connected().await;
        assert_eq!(port.session(), first);
        port.send(frame(&lost)).await.unwrap();
        let got = rx.recv().await.unwrap();
        assert_eq!(got.msg(), Some(&AgentMsg::Unknown));
        assert!(got.written().is_none());
        // A later session replaces it; the end of the old one does not withdraw the new one.
        let (tx2, _rx2) = mpsc::channel(4);
        let second = uplink.connect(Port::new(&tx2, Arc::new(NoStreams)));
        assert!(second > first);
        uplink.disconnect(first);
        assert_eq!(uplink.current().map(|p| p.session()), Some(second));
        uplink.disconnect(second);
        assert!(uplink.current().is_none());
        uplink.changed_from(second).await;
        // A session after a gap with none gets a new number too.
        let third = uplink.connect(Port::new(&tx2, Arc::new(NoStreams)));
        assert!(third > second);
        // The session's queue is gone once the session drops it, whoever still holds the port; the frame comes back
        // and is not counted lost.
        drop(tx);
        let back = port.send(frame(&lost)).await.unwrap_err();
        assert!(rx.recv().await.is_none(), "the port held no strong sender");
        assert_eq!(lost.0.load(Ordering::SeqCst), 0);
        // Dropped unwritten: counted.
        drop(back);
        assert_eq!(lost.0.load(Ordering::SeqCst), 1);
    }

    /// §6: a report is confirmed by the answer to a heartbeat written **after** it, never by one written before.
    #[test]
    fn a_report_is_confirmed_only_by_a_later_heartbeat() {
        let acks = Acks::default();
        acks.heartbeat_written(1);
        acks.heartbeat_written(2);
        let (frame, mut confirmed) = JobFrame::new(AgentMsg::Unknown, None).confirmed();
        acks.report_written(frame.written().unwrap());
        acks.acked(1);
        acks.acked(2);
        assert!(
            !*confirmed.borrow_and_update(),
            "heartbeats 1 and 2 went out before the report"
        );
        acks.heartbeat_written(3);
        acks.acked(3);
        assert!(*confirmed.borrow_and_update());
        // A session that ends first leaves it unconfirmed: the receiver errs.
        let acks = Acks::default();
        let (frame, unconfirmed) = JobFrame::new(AgentMsg::Unknown, None).confirmed();
        acks.report_written(frame.written().unwrap());
        drop(acks);
        assert!(unconfirmed.has_changed().is_err());
        assert!(!*unconfirmed.borrow());
    }
}
