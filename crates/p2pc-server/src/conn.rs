// SPDX-License-Identifier: AGPL-3.0-only

//! Per-connection header and keep-alive idle limits (spec §10 "Slow clients").
//!
//! hyper 1.x has one `header_read_timeout`, and its timer also starts while a keep-alive connection waits for its
//! next request, so on its own it would close idle connections after the header limit (10 s) instead of the idle
//! limit (60 s). [`ConnIo`] wraps the socket and enforces both, so hyper's own header timer is turned off:
//!
//! - **head**: from the accept (a new connection), or from the first byte of a later request, the request head must
//!   arrive within the header limit. Bytes that keep trickling in do not extend it;
//! - **busy**: while a request is being handled ([`Tracked`] counts them), the connection has no deadline here; the
//!   body and whole-request limits are tower layers on the router;
//! - **idle**: after a response, the next request's first byte must arrive within the idle limit.
//!
//! - **upgraded**: once the service answers `101 Switching Protocols` ([`Tracked`] sees it), the connection is a
//!   service port connection (H2 §7.4). It leaves the limits above: it closes after `port_idle_s` with no byte in
//!   either direction, as an upgraded device stream does (`gateway::device`).
//!
//! When a deadline passes, the read fails with `TimedOut` and hyper closes the connection; on an upgraded
//! connection every later read and write fails too, so both directions end.
//!
//! [`ConnIo`] also holds the connection's slot of `http.max_connections`. hyper hands the socket of an upgraded
//! connection to whoever holds the upgrade, and the slot goes with it: an upgraded port connection keeps counting
//! against the REST connection cap for its whole life (H2 §7.4 "Limits").

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{Instant, Sleep};

/// Requests of one connection currently being handled, and the read waiting while they are.
#[derive(Debug, Default)]
pub(crate) struct ConnState {
    in_flight: AtomicUsize,
    /// Set when a request was answered `101`: from then on the connection is a port connection.
    upgraded: AtomicBool,
    /// hyper may already be waiting on the socket while a request is handled. When the last request ends, this
    /// read must be woken, or the idle deadline would never be armed.
    busy_reader: Mutex<Option<Waker>>,
}

impl ConnState {
    fn park_reader(&self, waker: &Waker) {
        let mut slot = self
            .busy_reader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !slot.as_ref().is_some_and(|w| w.will_wake(waker)) {
            *slot = Some(waker.clone());
        }
    }

    fn wake_reader(&self) {
        let waker = self
            .busy_reader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(w) = waker {
            w.wake();
        }
    }
}

/// Counts a request as in flight until dropped.
#[derive(Debug)]
struct InFlight(Arc<ConnState>);

impl InFlight {
    fn enter(conn: &Arc<ConnState>) -> Self {
        conn.in_flight.fetch_add(1, Ordering::AcqRel);
        Self(conn.clone())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if self.0.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
            // The connection goes idle: let the pending read re-evaluate and arm the idle deadline.
            self.0.wake_reader();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Head,
    Busy,
    Idle,
    /// Upgraded: closed after `port_idle` with no byte in either direction.
    Upgraded,
}

/// The socket of one connection, with the deadlines described in the module docs and the connection's slot of the
/// REST connection cap.
#[derive(Debug)]
pub(crate) struct ConnIo {
    inner: TcpStream,
    conn: Arc<ConnState>,
    header: Duration,
    idle: Duration,
    port_idle: Duration,
    phase: Phase,
    deadline: Pin<Box<Sleep>>,
    /// Set when the idle limit of an upgraded connection passed: every later read and write fails too.
    timed_out: bool,
    /// The connection's slot of `http.max_connections`, given back when the socket is dropped.
    _slot: OwnedSemaphorePermit,
}

impl ConnIo {
    /// A newly accepted connection: its first request head is due within `header`. Once upgraded, it closes after
    /// `port_idle` with no byte in either direction. `slot` is held until the socket is dropped.
    pub(crate) fn new(
        inner: TcpStream,
        conn: Arc<ConnState>,
        header: Duration,
        idle: Duration,
        port_idle: Duration,
        slot: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            inner,
            conn,
            header,
            idle,
            port_idle,
            phase: Phase::Head,
            deadline: Box::pin(tokio::time::sleep(header)),
            timed_out: false,
            _slot: slot,
        }
    }

    fn arm(&mut self, after: Duration) {
        self.deadline.as_mut().reset(Instant::now() + after);
    }

    /// Follows what the service did since the last poll: an upgrade, a request that began or ended.
    fn follow_service(&mut self) {
        if self.conn.upgraded.load(Ordering::Acquire) {
            if self.phase != Phase::Upgraded {
                self.phase = Phase::Upgraded;
                let port_idle = self.port_idle;
                self.arm(port_idle);
            }
        } else if self.conn.in_flight.load(Ordering::Acquire) > 0 {
            self.phase = Phase::Busy;
        } else if self.phase == Phase::Busy {
            // The response is done: wait for the next request, at most the idle limit.
            self.phase = Phase::Idle;
            let idle = self.idle;
            self.arm(idle);
        }
    }

    fn expired(&self) -> io::Error {
        let what = match self.phase {
            Phase::Head => "request headers not received in time",
            Phase::Upgraded => "port connection idle for too long",
            Phase::Busy | Phase::Idle => "keep-alive connection idle for too long",
        };
        io::Error::new(io::ErrorKind::TimedOut, what)
    }
}

impl AsyncRead for ConnIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.timed_out {
            return Poll::Ready(Err(this.expired()));
        }
        this.follow_service();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    match this.phase {
                        // The first byte of the next request: its head is due within the header limit.
                        Phase::Idle => {
                            this.phase = Phase::Head;
                            let header = this.header;
                            this.arm(header);
                        }
                        Phase::Upgraded => {
                            let port_idle = this.port_idle;
                            this.arm(port_idle);
                        }
                        Phase::Head | Phase::Busy => {}
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                if this.phase == Phase::Busy {
                    this.conn.park_reader(cx.waker());
                    // The request may have ended between the check above and now.
                    if this.conn.in_flight.load(Ordering::Acquire) == 0 {
                        cx.waker().wake_by_ref();
                    }
                    return Poll::Pending;
                }
                if this.deadline.as_mut().poll(cx).is_ready() {
                    // Only an upgraded connection is written to after its read failed.
                    this.timed_out = this.phase == Phase::Upgraded;
                    return Poll::Ready(Err(this.expired()));
                }
                Poll::Pending
            }
        }
    }
}

impl ConnIo {
    /// What a write of an upgraded connection means for its idle limit: a byte written re-arms it, and a write that
    /// cannot progress is no byte, so the limit applies. Before an upgrade, the router's request limits bound a
    /// response the peer does not read.
    fn after_write(&mut self, cx: &mut Context<'_>, written: Poll<io::Result<usize>>) -> Poll<io::Result<usize>> {
        if self.phase != Phase::Upgraded {
            return written;
        }
        match written {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    let port_idle = self.port_idle;
                    self.arm(port_idle);
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                if self.deadline.as_mut().poll(cx).is_ready() {
                    self.timed_out = true;
                    return Poll::Ready(Err(self.expired()));
                }
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for ConnIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.timed_out {
            return Poll::Ready(Err(this.expired()));
        }
        this.follow_service();
        let written = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.after_write(cx, written)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.timed_out {
            return Poll::Ready(Err(this.expired()));
        }
        this.follow_service();
        let written = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.after_write(cx, written)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// A hyper service that marks its connection busy while a request is handled, for [`ConnIo`].
#[derive(Debug, Clone)]
pub(crate) struct Tracked<S> {
    inner: S,
    conn: Arc<ConnState>,
}

impl<S> Tracked<S> {
    pub(crate) fn new(inner: S, conn: Arc<ConnState>) -> Self {
        Self { inner, conn }
    }
}

impl<S, R, B> hyper::service::Service<R> for Tracked<S>
where
    S: hyper::service::Service<R, Response = hyper::Response<B>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn call(&self, req: R) -> Self::Future {
        let busy = InFlight::enter(&self.conn);
        let fut = self.inner.call(req);
        let conn = self.conn.clone();
        Box::pin(async move {
            let out = fut.await;
            if let Ok(response) = &out
                && response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS
            {
                // From here the connection is a port connection (H2 §7.4): `port_idle_s` replaces the HTTP limits.
                conn.upgraded.store(true, Ordering::Release);
            }
            drop(busy);
            out
        })
    }
}
