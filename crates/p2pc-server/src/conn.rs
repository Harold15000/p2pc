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
//! When a deadline passes, the read fails with `TimedOut` and hyper closes the connection.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{Instant, Sleep};

/// Requests of one connection currently being handled, and the read waiting while they are.
#[derive(Debug, Default)]
pub(crate) struct ConnState {
    in_flight: AtomicUsize,
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
}

/// The socket of one connection, with the head and idle deadlines described in the module docs.
#[derive(Debug)]
pub(crate) struct ConnIo {
    inner: TcpStream,
    conn: Arc<ConnState>,
    header: Duration,
    idle: Duration,
    phase: Phase,
    deadline: Pin<Box<Sleep>>,
}

impl ConnIo {
    /// A newly accepted connection: its first request head is due within `header`.
    pub(crate) fn new(inner: TcpStream, conn: Arc<ConnState>, header: Duration, idle: Duration) -> Self {
        Self {
            inner,
            conn,
            header,
            idle,
            phase: Phase::Head,
            deadline: Box::pin(tokio::time::sleep(header)),
        }
    }

    fn arm(&mut self, after: Duration) {
        self.deadline.as_mut().reset(Instant::now() + after);
    }
}

impl AsyncRead for ConnIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.conn.in_flight.load(Ordering::Acquire) > 0 {
            this.phase = Phase::Busy;
        } else if this.phase == Phase::Busy {
            // The response is done: wait for the next request, at most the idle limit.
            this.phase = Phase::Idle;
            let idle = this.idle;
            this.arm(idle);
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if this.phase == Phase::Idle && buf.filled().len() > before {
                    // The first byte of the next request: its head is due within the header limit.
                    this.phase = Phase::Head;
                    let header = this.header;
                    this.arm(header);
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
                    let what = if this.phase == Phase::Head {
                        "request headers not received in time"
                    } else {
                        "keep-alive connection idle for too long"
                    };
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, what)));
                }
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for ConnIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
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
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
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

impl<S, R> hyper::service::Service<R> for Tracked<S>
where
    S: hyper::service::Service<R>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn call(&self, req: R) -> Self::Future {
        let busy = InFlight::enter(&self.conn);
        let fut = self.inner.call(req);
        Box::pin(async move {
            let out = fut.await;
            drop(busy);
            out
        })
    }
}
