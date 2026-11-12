// SPDX-License-Identifier: Apache-2.0

//! The streams the **hub** opens on the agent's connection (H2 spec §6.1 "New streams on an agent connection").
//!
//! H1 lets only the agent open streams after the control stream (uploads). H2 adds hub-opened ones: today a
//! [`PortOpen`], a client's connection to a port of a service this node runs. The agent still accepts no
//! connection (SI-12): these are streams of the connection it dialed itself.
//!
//! [`serve`] is the dispatcher of one welcomed session. For every stream the hub opens:
//! 1. **The header.** One JSON frame, at most [`MAX_HEADER_LEN`] bytes, within [`HEADER_TIMEOUT`]. A `type` this
//!    agent does not know, or a header it cannot read at all (not JSON, too large, late, or none), resets **that
//!    stream** with `unsupported_stream`, never the connection.
//! 2. **`PortOpen{lease_id, epoch, port, conn_id}`.** The [`PortOpener`] decides (the ingress bridge: fencing by
//!    `(lease_id, epoch)`, the listed ports, the per-lease limit, the dial through the shim, SI-H2-6 and SI-H2-7).
//!    The agent's first frame is `PortOpenAck{ok, reason?}`; after `ok` raw bytes flow both ways.
//! 3. **The end.** A clean end of either side travels on as a clean end (a QUIC stream finish, a half-close of the
//!    bridged connection). An error on either side (a reset by the hub, a service that is gone) resets the stream
//!    and drops the bridged connection. An idle port stream is **not** timed out here (a chat may idle for minutes):
//!    the service's `idle_timeout_s` and the client side's `port_idle_s` do that on the hub.
//!
//! **Limits** (all per connection): at most [`MAX_PORT_STREAMS_PER_CONNECTION`] port streams at once, beyond which a
//! `PortOpen` is answered `too_many_connections`; at most [`MAX_PENDING_HEADERS`] streams whose header has not been
//! read and decided, beyond which a new stream is reset at once. So the tasks and buffers of one connection are
//! bounded whatever the hub sends. When the session ends, every stream of it ends with it.
//!
//! Nothing here logs or keeps a byte of what the streams carry.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use p2pc_proto::protocol::{
    HubStreamHeader, MAX_PORT_STREAMS_PER_CONNECTION, PortOpen, PortOpenAck, STREAM_RESET_UNSUPPORTED_STREAM,
    decode_frame, port_open_reason, read_frame_bytes, write_frame,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use super::BoxFuture;
use super::transport::ConnectError;

/// How long the hub has to send the header of a stream it opened.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest header frame of a hub-opened stream. A `PortOpen` is under 200 bytes.
pub const MAX_HEADER_LEN: u32 = 4 * 1024;
/// Longest write of the agent's `PortOpenAck`. A hub that does not read for this long loses the stream.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest a [`PortOpener`] may take to open one connection. The ingress bridge bounds itself below this (three
/// tries of at most 10 s); a slot is never held by an opener that hangs.
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(40);
/// Most hub-opened streams whose header is not yet read and decided; a stream beyond it is reset at once.
pub const MAX_PENDING_HEADERS: usize = 32;
/// The reset code of a stream the agent ends for a reason of its own (the same number as the connection's
/// [`super::endpoint::CLOSE_BY_AGENT`]): a port stream whose bridged connection broke, or one over a limit.
pub const STREAM_RESET_BY_AGENT: u32 = 0;

/// The sending half of a hub-opened stream.
pub trait HubSend: AsyncWrite + Send + Unpin {
    /// Abandons the stream: the hub reads a reset with `code` instead of a clean end.
    fn reset(&mut self, code: u32);
}

/// The receiving half of a hub-opened stream.
pub trait HubRecv: AsyncRead + Send + Unpin {
    /// Tells the hub to stop sending on the stream, with `code`.
    fn stop(&mut self, code: u32);
}

/// A stream the hub opened.
pub struct HubStream {
    /// Agent → hub.
    pub send: Box<dyn HubSend>,
    /// Hub → agent.
    pub recv: Box<dyn HubRecv>,
}

impl fmt::Debug for HubStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HubStream").finish_non_exhaustive()
    }
}

/// Where the hub-opened streams of one connection arrive.
pub trait StreamAcceptor: Send + Sync + fmt::Debug + 'static {
    /// The next stream the hub opened. An error means the connection is gone.
    fn accept(&self) -> BoxFuture<'_, Result<HubStream, ConnectError>>;
}

/// A connection to a service port, as the dispatcher copies it: any byte stream.
pub trait PortIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> PortIo for T {}

/// Opens connections to the ports of the services this node runs (the ingress bridge, H2 §11.2).
pub trait PortOpener: Send + Sync + fmt::Debug + 'static {
    /// A connection to `open.port` of the service of `(open.lease_id, open.epoch)`.
    ///
    /// # Errors
    /// One of the [`port_open_reason`] codes, which goes into the `PortOpenAck`.
    fn open<'a>(&'a self, open: &'a PortOpen) -> BoxFuture<'a, Result<Box<dyn PortIo>, &'static str>>;
}

/// The hub-opened streams of an iroh connection.
pub struct IrohAcceptor(Connection);

impl IrohAcceptor {
    /// The acceptor of `conn`, the connection the agent dialed.
    #[must_use]
    pub fn new(conn: Connection) -> Self {
        Self(conn)
    }
}

impl fmt::Debug for IrohAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohAcceptor").finish_non_exhaustive()
    }
}

impl StreamAcceptor for IrohAcceptor {
    fn accept(&self) -> BoxFuture<'_, Result<HubStream, ConnectError>> {
        Box::pin(async move {
            let (send, recv) = self
                .0
                .accept_bi()
                .await
                .map_err(|e| ConnectError(format!("no more streams from the server: {e}")))?;
            Ok(HubStream {
                send: Box::new(send),
                recv: Box::new(recv),
            })
        })
    }
}

impl HubSend for SendStream {
    fn reset(&mut self, code: u32) {
        // An error means the stream is already finished or reset.
        let _ = SendStream::reset(self, VarInt::from_u32(code));
    }
}

impl HubRecv for RecvStream {
    fn stop(&mut self, code: u32) {
        // An error means the stream already ended.
        let _ = RecvStream::stop(self, VarInt::from_u32(code));
    }
}

/// Serves the streams the hub opens on one connection until the connection is gone. Dropping (or aborting) the
/// future ends every stream it serves.
pub async fn serve(acceptor: Arc<dyn StreamAcceptor>, ports: Arc<dyn PortOpener>) {
    let waiting = Arc::new(Semaphore::new(MAX_PENDING_HEADERS));
    let slots = Arc::new(Semaphore::new(MAX_PORT_STREAMS_PER_CONNECTION));
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            // Reap the streams that ended, so the set stays as small as the streams in progress.
            Some(_) = streams.join_next(), if !streams.is_empty() => {}
            accepted = acceptor.accept() => {
                let mut stream = match accepted {
                    Ok(stream) => stream,
                    Err(e) => {
                        tracing::debug!(error = %e, "the connection takes no more streams from the server");
                        break;
                    }
                };
                // Every task below holds a place among the waiting headers or a port slot: both are bounded.
                let Ok(place) = Arc::clone(&waiting).try_acquire_owned() else {
                    tracing::debug!("too many streams from the server wait for their header; resetting a new one");
                    abort(&mut stream, STREAM_RESET_BY_AGENT);
                    continue;
                };
                streams.spawn(handle(stream, Arc::clone(&ports), place, Arc::clone(&slots)));
            }
        }
    }
    // The connection is gone: its streams go with it.
    streams.shutdown().await;
}

/// Ends a stream at once, in both directions: the hub reads a reset with `code`.
fn abort(stream: &mut HubStream, code: u32) {
    stream.send.reset(code);
    stream.recv.stop(code);
}

/// Reads and decodes the header frame of a hub-opened stream. The error never quotes the content.
async fn read_header(recv: &mut Box<dyn HubRecv>) -> Result<HubStreamHeader, String> {
    let body = read_frame_bytes(recv, MAX_HEADER_LEN)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("the stream ended before its header")?;
    decode_frame::<HubStreamHeader>(&body).map_err(|e| e.to_string())
}

/// Writes the agent's first frame within [`ACK_TIMEOUT`]; false when the stream is no good any more.
async fn send_ack(stream: &mut HubStream, ack: &PortOpenAck) -> bool {
    matches!(
        tokio::time::timeout(ACK_TIMEOUT, write_frame(&mut stream.send, ack)).await,
        Ok(Ok(()))
    )
}

/// Answers `PortOpenAck{ok: false, reason}` and ends the stream cleanly.
async fn refuse(mut stream: HubStream, reason: &'static str) {
    if send_ack(&mut stream, &PortOpenAck::refused(reason)).await
        && matches!(
            tokio::time::timeout(ACK_TIMEOUT, stream.send.shutdown()).await,
            Ok(Ok(()))
        )
    {
        // Answered: whatever the hub still sends on this stream is not read.
        stream.recv.stop(STREAM_RESET_BY_AGENT);
        return;
    }
    abort(&mut stream, STREAM_RESET_BY_AGENT);
}

/// One hub-opened stream, from its header to its end. `place` is its place among the streams whose header is not
/// decided yet; a `PortOpen` trades it for one of the connection's port `slots`.
async fn handle(mut stream: HubStream, ports: Arc<dyn PortOpener>, place: OwnedSemaphorePermit, slots: Arc<Semaphore>) {
    let header = tokio::time::timeout(HEADER_TIMEOUT, read_header(&mut stream.recv)).await;
    let open = match header {
        Ok(Ok(HubStreamHeader::PortOpen(open))) => open,
        Ok(Ok(HubStreamHeader::Unknown)) => {
            tracing::debug!("a stream of a type this agent does not know; resetting it (unsupported_stream)");
            return abort(&mut stream, STREAM_RESET_UNSUPPORTED_STREAM);
        }
        Ok(Err(error)) => {
            tracing::debug!(%error, "a stream from the server with an unreadable header; resetting it");
            return abort(&mut stream, STREAM_RESET_UNSUPPORTED_STREAM);
        }
        Err(_) => {
            tracing::debug!(
                timeout_s = HEADER_TIMEOUT.as_secs(),
                "a stream from the server sent no header in time; resetting it"
            );
            return abort(&mut stream, STREAM_RESET_UNSUPPORTED_STREAM);
        }
    };
    // Port 0 is never a port of a service (`HubStreamHeader::validate`).
    if open.port == 0 {
        return refuse(stream, port_open_reason::PORT_NOT_EXPOSED).await;
    }
    let Ok(slot) = slots.try_acquire_owned() else {
        tracing::debug!(lease_id = %open.lease_id, "too many port streams on this connection; refusing one");
        return refuse(stream, port_open_reason::TOO_MANY_CONNECTIONS).await;
    };
    drop(place);
    let conn = match tokio::time::timeout(OPEN_TIMEOUT, ports.open(&open)).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(reason)) => return refuse(stream, reason).await,
        Err(_) => return refuse(stream, port_open_reason::CONNECT_FAILED).await,
    };
    if !send_ack(&mut stream, &PortOpenAck::accepted()).await {
        return abort(&mut stream, STREAM_RESET_BY_AGENT);
    }
    tracing::debug!(lease_id = %open.lease_id, epoch = open.epoch, port = open.port, conn_id = open.conn_id, "port stream open");
    splice(stream, conn).await;
    drop(slot);
}

/// Copies both ways between the hub's stream and the bridged connection until both directions ended.
///
/// A clean end of one side ends the other side's direction cleanly (a stream finish toward the hub, a half-close
/// toward the service) and the other direction goes on. An error on either side ends everything at once: the
/// bridged connection is dropped, and each direction of the stream that had not ended cleanly is reset. A direction
/// that already ended cleanly stays that way: a response the service finished is never cut short because the client
/// wrote on afterwards. No timeout: see the module docs.
async fn splice(stream: HubStream, conn: Box<dyn PortIo>) {
    let HubStream { mut send, mut recv } = stream;
    let (mut from_service, mut to_service) = tokio::io::split(conn);
    // Which directions ended cleanly, and whether one failed.
    let (up_done, down_done, failed) = {
        let up = async {
            tokio::io::copy(&mut recv, &mut to_service).await?;
            to_service.shutdown().await
        };
        let down = async {
            tokio::io::copy(&mut from_service, &mut send).await?;
            send.shutdown().await
        };
        tokio::pin!(up, down);
        let (mut up_done, mut down_done) = (false, false);
        let failed = loop {
            tokio::select! {
                ended = &mut up, if !up_done => match ended {
                    Ok(()) => up_done = true,
                    Err(_) => break true,
                },
                ended = &mut down, if !down_done => match ended {
                    Ok(()) => down_done = true,
                    Err(_) => break true,
                },
                else => break false,
            }
        };
        (up_done, down_done, failed)
    };
    if failed {
        if !down_done {
            send.reset(STREAM_RESET_BY_AGENT);
        }
        if !up_done {
            recv.stop(STREAM_RESET_BY_AGENT);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::io;
    use std::pin::Pin;
    use std::str::FromStr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    use p2pc_proto::ids::LeaseId;
    use p2pc_proto::protocol::read_frame;
    use tokio::io::{AsyncReadExt as _, DuplexStream, ReadBuf};
    use tokio::sync::mpsc;

    use super::*;

    /// How long a test waits for something that must happen: a failure is then a failure, not a hang. Under a
    /// paused clock it only passes when nothing else can happen.
    const PATIENCE: Duration = Duration::from_secs(60);

    /// What the agent did to end a stream, as the hub would see it.
    #[derive(Debug, Default)]
    struct Ends {
        reset: Mutex<Option<u32>>,
        stopped: Mutex<Option<u32>>,
    }

    /// The agent's sending half: a pipe to the test's hub, recording a reset.
    struct TestSend {
        pipe: DuplexStream,
        ends: Arc<Ends>,
        /// Never takes a byte (a hub that does not read).
        stuck: bool,
    }

    impl AsyncWrite for TestSend {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            if self.stuck {
                return Poll::Pending;
            }
            Pin::new(&mut self.pipe).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.pipe).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.pipe).poll_shutdown(cx)
        }
    }

    impl HubSend for TestSend {
        fn reset(&mut self, code: u32) {
            *self.ends.reset.lock().unwrap() = Some(code);
        }
    }

    /// The agent's receiving half: chunks (or an error, a reset by the hub) pushed by the test.
    struct TestRecv {
        chunks: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
        current: Vec<u8>,
        ends: Arc<Ends>,
    }

    impl AsyncRead for TestRecv {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            loop {
                if !self.current.is_empty() {
                    let n = self.current.len().min(buf.remaining());
                    buf.put_slice(&self.current[..n]);
                    self.current.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                match self.chunks.poll_recv(cx) {
                    Poll::Ready(Some(Ok(chunk))) => self.current = chunk,
                    Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                    // The hub finished the stream.
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    impl HubRecv for TestRecv {
        fn stop(&mut self, code: u32) {
            *self.ends.stopped.lock().unwrap() = Some(code);
        }
    }

    /// The hub's end of one stream it opened.
    struct Hub {
        /// What the agent sends.
        from_agent: DuplexStream,
        /// What the hub sends; dropping it finishes the stream.
        to_agent: Option<mpsc::UnboundedSender<io::Result<Vec<u8>>>>,
        ends: Arc<Ends>,
    }

    impl Hub {
        fn send(&self, bytes: &[u8]) {
            self.to_agent.as_ref().unwrap().send(Ok(bytes.to_vec())).unwrap();
        }

        fn send_frame(&self, json: &serde_json::Value) {
            let body = serde_json::to_vec(json).unwrap();
            let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
            frame.extend_from_slice(&body);
            self.send(&frame);
        }

        fn port_open(&self, lease: &LeaseId, epoch: u64, port: u16) {
            self.send_frame(&serde_json::json!({
                "type": "port_open", "lease_id": lease.to_string(), "epoch": epoch, "port": port, "conn_id": 7
            }));
        }

        /// The hub resets its sending side.
        fn reset(&self) {
            let reset = io::Error::from(io::ErrorKind::ConnectionReset);
            self.to_agent.as_ref().unwrap().send(Err(reset)).unwrap();
        }

        /// The hub finishes its sending side.
        fn finish(&mut self) {
            self.to_agent = None;
        }

        async fn ack(&mut self) -> PortOpenAck {
            tokio::time::timeout(
                PATIENCE,
                read_frame::<PortOpenAck, _>(&mut self.from_agent, MAX_HEADER_LEN),
            )
            .await
            .expect("the agent sent no ack")
            .unwrap()
            .expect("an ack frame")
        }

        /// Everything the agent still sends, until it ends its side of the stream.
        async fn rest(&mut self) -> Vec<u8> {
            let mut rest = Vec::new();
            tokio::time::timeout(PATIENCE, self.from_agent.read_to_end(&mut rest))
                .await
                .expect("the agent did not end the stream")
                .unwrap();
            rest
        }

        fn reset_code(&self) -> Option<u32> {
            *self.ends.reset.lock().unwrap()
        }

        fn stop_code(&self) -> Option<u32> {
            *self.ends.stopped.lock().unwrap()
        }
    }

    /// The connection, as the test's hub drives it.
    struct Conn {
        streams: mpsc::UnboundedSender<HubStream>,
    }

    impl Conn {
        fn open_with(&self, stuck: bool) -> Hub {
            let (agent_pipe, hub_pipe) = tokio::io::duplex(64 * 1024);
            let (tx, rx) = mpsc::unbounded_channel();
            let ends = Arc::new(Ends::default());
            let stream = HubStream {
                send: Box::new(TestSend {
                    pipe: agent_pipe,
                    ends: Arc::clone(&ends),
                    stuck,
                }),
                recv: Box::new(TestRecv {
                    chunks: rx,
                    current: Vec::new(),
                    ends: Arc::clone(&ends),
                }),
            };
            self.streams.send(stream).unwrap();
            Hub {
                from_agent: hub_pipe,
                to_agent: Some(tx),
                ends,
            }
        }

        /// The hub opens a stream.
        fn open(&self) -> Hub {
            self.open_with(false)
        }
    }

    #[derive(Debug)]
    struct TestAcceptor(tokio::sync::Mutex<mpsc::UnboundedReceiver<HubStream>>);

    impl StreamAcceptor for TestAcceptor {
        fn accept(&self) -> BoxFuture<'_, Result<HubStream, ConnectError>> {
            Box::pin(async move {
                let mut streams = self.0.lock().await;
                streams
                    .recv()
                    .await
                    .ok_or_else(|| ConnectError("connection closed".into()))
            })
        }
    }

    /// A service connection whose reads fail: the service reset it.
    struct BrokenIo;

    impl AsyncRead for BrokenIo {
        fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
        }
    }

    impl AsyncWrite for BrokenIo {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A scripted opener: refuses with `refuse`, or hands the test the service's end of a fresh pipe.
    #[derive(Debug)]
    struct FakePorts {
        refuse: Mutex<Option<&'static str>>,
        hang: Mutex<bool>,
        /// Opens a connection that breaks at its first read.
        broken: Mutex<bool>,
        opened: Mutex<Vec<PortOpen>>,
        services: mpsc::UnboundedSender<DuplexStream>,
        calls: AtomicUsize,
    }

    impl PortOpener for FakePorts {
        fn open<'a>(&'a self, open: &'a PortOpen) -> BoxFuture<'a, Result<Box<dyn PortIo>, &'static str>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let refuse = *self.refuse.lock().unwrap();
            let hang = *self.hang.lock().unwrap();
            let broken = *self.broken.lock().unwrap();
            Box::pin(async move {
                if hang {
                    std::future::pending::<()>().await;
                }
                if let Some(reason) = refuse {
                    return Err(reason);
                }
                self.opened.lock().unwrap().push(open.clone());
                if broken {
                    return Ok(Box::new(BrokenIo) as Box<dyn PortIo>);
                }
                let (agent, service) = tokio::io::duplex(64 * 1024);
                self.services.send(service).unwrap();
                Ok(Box::new(agent) as Box<dyn PortIo>)
            })
        }
    }

    struct Fx {
        conn: Conn,
        ports: Arc<FakePorts>,
        services: mpsc::UnboundedReceiver<DuplexStream>,
        dispatcher: tokio::task::JoinHandle<()>,
    }

    impl Fx {
        /// The service's end of the connection the opener just opened.
        async fn service(&mut self) -> DuplexStream {
            tokio::time::timeout(PATIENCE, self.services.recv())
                .await
                .expect("no service connection was opened")
                .unwrap()
        }
    }

    fn fx() -> Fx {
        let (streams_tx, streams_rx) = mpsc::unbounded_channel();
        let (services_tx, services_rx) = mpsc::unbounded_channel();
        let ports = Arc::new(FakePorts {
            refuse: Mutex::new(None),
            hang: Mutex::new(false),
            broken: Mutex::new(false),
            opened: Mutex::new(Vec::new()),
            services: services_tx,
            calls: AtomicUsize::new(0),
        });
        let acceptor = Arc::new(TestAcceptor(tokio::sync::Mutex::new(streams_rx)));
        let dispatcher = tokio::spawn(serve(acceptor, Arc::clone(&ports) as Arc<dyn PortOpener>));
        Fx {
            conn: Conn { streams: streams_tx },
            ports,
            services: services_rx,
            dispatcher,
        }
    }

    fn lease() -> LeaseId {
        LeaseId::from_str("lse_01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap()
    }

    /// §6.1: `PortOpen`, the agent's `PortOpenAck{ok}` as its first frame, then raw bytes both ways; a clean end of
    /// either side is a clean end on the other, never a reset.
    #[tokio::test]
    async fn a_port_open_is_acked_then_bytes_flow_and_a_clean_end_stays_clean() {
        let mut fx = fx();
        let mut hub = fx.conn.open();
        hub.port_open(&lease(), 3, 11434);
        assert_eq!(hub.ack().await, PortOpenAck::accepted());
        let mut service = fx.service().await;
        assert_eq!(
            *fx.ports.opened.lock().unwrap(),
            [PortOpen {
                lease_id: lease(),
                epoch: 3,
                port: 11434,
                conn_id: 7
            }]
        );
        // Hub → service, and the hub's finish reaches the service as the end of its input.
        hub.send(b"POST /api/chat HTTP/1.1\r\n\r\n");
        hub.finish();
        let mut request = Vec::new();
        service.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"POST /api/chat HTTP/1.1\r\n\r\n");
        // Service → hub, then the service's end: the agent finishes the stream.
        service.write_all(b"HTTP/1.1 200 OK\r\n\r\nhello").await.unwrap();
        service.shutdown().await.unwrap();
        assert_eq!(hub.rest().await, b"HTTP/1.1 200 OK\r\n\r\nhello");
        assert_eq!(
            (hub.reset_code(), hub.stop_code()),
            (None, None),
            "a finish, not a reset"
        );
    }

    /// Bytes sent right behind the header, in the same write, are the first bytes of the connection.
    #[tokio::test]
    async fn bytes_right_behind_the_header_are_not_lost() {
        let mut fx = fx();
        let mut hub = fx.conn.open();
        let body = serde_json::to_vec(&serde_json::json!({
            "type": "port_open", "lease_id": lease().to_string(), "epoch": 1, "port": 80, "conn_id": 1
        }))
        .unwrap();
        let mut bytes = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(b"first bytes");
        hub.send(&bytes);
        hub.finish();
        assert_eq!(hub.ack().await, PortOpenAck::accepted());
        let mut service = fx.service().await;
        let mut got = Vec::new();
        service.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"first bytes");
    }

    /// Every refusal of the opener is the agent's first frame, with its reason, and the stream then ends cleanly.
    #[tokio::test]
    async fn a_refused_port_open_is_answered_with_the_reason() {
        let fx = fx();
        for reason in port_open_reason::ALL {
            *fx.ports.refuse.lock().unwrap() = Some(reason);
            let mut hub = fx.conn.open();
            hub.port_open(&lease(), 1, 11434);
            assert_eq!(hub.ack().await, PortOpenAck::refused(reason));
            assert!(hub.rest().await.is_empty(), "nothing follows a refusal");
            assert_eq!(hub.reset_code(), None, "{reason}");
        }
        assert!(fx.ports.opened.lock().unwrap().is_empty());
    }

    /// Port 0 is never a service port: refused without asking the opener.
    #[tokio::test]
    async fn port_zero_is_refused_without_opening_anything() {
        let fx = fx();
        let mut hub = fx.conn.open();
        hub.port_open(&lease(), 1, 0);
        assert_eq!(
            hub.ack().await,
            PortOpenAck::refused(port_open_reason::PORT_NOT_EXPOSED)
        );
        assert_eq!(fx.ports.calls.load(Ordering::SeqCst), 0);
    }

    /// §6.1: an unknown `type` resets the stream with `unsupported_stream`, never the connection.
    #[tokio::test]
    async fn an_unknown_type_resets_that_stream_and_the_connection_goes_on() {
        let mut fx = fx();
        let mut hub = fx.conn.open();
        hub.send_frame(&serde_json::json!({"type": "log_follow", "lease_id": lease().to_string()}));
        assert!(hub.rest().await.is_empty(), "no frame answers an unknown stream");
        assert_eq!(hub.reset_code(), Some(STREAM_RESET_UNSUPPORTED_STREAM));
        assert_eq!(hub.stop_code(), Some(STREAM_RESET_UNSUPPORTED_STREAM));
        assert_eq!(fx.ports.calls.load(Ordering::SeqCst), 0);
        // The next stream of the same connection is served.
        let mut hub = fx.conn.open();
        hub.port_open(&lease(), 1, 11434);
        assert_eq!(hub.ack().await, PortOpenAck::accepted());
        fx.service().await;
        assert!(!fx.dispatcher.is_finished());
    }

    /// A header the agent cannot read resets only its own stream: not JSON, no `type`, an H1 upload header, a
    /// frame over the limit, a stream that ends before its header.
    #[tokio::test]
    async fn an_unreadable_header_resets_only_its_own_stream() {
        let fx = fx();
        let oversized = {
            let mut frame = (MAX_HEADER_LEN + 1).to_be_bytes().to_vec();
            frame.extend_from_slice(b"{");
            frame
        };
        let untyped = {
            let body = br#"{"lease_id":"lse_01ARZ3NDEKTSV4RRFFQ69G5FAV","epoch":1,"port":80,"conn_id":1}"#;
            let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
            frame.extend_from_slice(body);
            frame
        };
        let cases: [(&str, Vec<u8>); 5] = [
            ("not json", b"\x00\x00\x00\x03{{{".to_vec()),
            ("not utf-8", b"\x00\x00\x00\x02\xff\xfe".to_vec()),
            ("no type", untyped),
            ("oversized", oversized),
            ("ends before its header", b"\x00\x00".to_vec()),
        ];
        for (what, bytes) in cases {
            let mut hub = fx.conn.open();
            hub.send(&bytes);
            hub.finish();
            assert!(hub.rest().await.is_empty(), "{what}");
            assert_eq!(hub.reset_code(), Some(STREAM_RESET_UNSUPPORTED_STREAM), "{what}");
        }
        // A `PortOpen` with a field of the wrong type is unreadable too, and nothing is opened for it.
        let mut hub = fx.conn.open();
        hub.send_frame(&serde_json::json!({
            "type": "port_open", "lease_id": lease().to_string(), "epoch": 1, "port": 70000, "conn_id": 1
        }));
        assert!(hub.rest().await.is_empty());
        assert_eq!(hub.reset_code(), Some(STREAM_RESET_UNSUPPORTED_STREAM));
        assert_eq!(fx.ports.calls.load(Ordering::SeqCst), 0);
        assert!(!fx.dispatcher.is_finished(), "the connection goes on");
    }

    /// A hub that opens a stream and sends no header loses the stream after [`HEADER_TIMEOUT`], not before.
    #[tokio::test(start_paused = true)]
    async fn a_header_that_does_not_come_in_time_resets_the_stream() {
        let fx = fx();
        let mut hub = fx.conn.open();
        tokio::time::sleep(HEADER_TIMEOUT - Duration::from_millis(1)).await;
        assert_eq!(hub.reset_code(), None);
        let started = tokio::time::Instant::now();
        assert!(hub.rest().await.is_empty());
        assert_eq!(started.elapsed(), Duration::from_millis(1));
        assert_eq!(hub.reset_code(), Some(STREAM_RESET_UNSUPPORTED_STREAM));
    }

    /// §6.1: at most 256 concurrent port streams per connection; the next `PortOpen` is refused, and a slot that
    /// is given back can be used again.
    #[tokio::test]
    async fn a_connection_serves_at_most_256_port_streams() {
        let mut fx = fx();
        let mut open = Vec::new();
        for _ in 0..MAX_PORT_STREAMS_PER_CONNECTION {
            let mut hub = fx.conn.open();
            hub.port_open(&lease(), 1, 11434);
            assert_eq!(hub.ack().await, PortOpenAck::accepted());
            open.push((hub, fx.service().await));
        }
        assert_eq!(fx.ports.calls.load(Ordering::SeqCst), MAX_PORT_STREAMS_PER_CONNECTION);
        let mut extra = fx.conn.open();
        extra.port_open(&lease(), 1, 11434);
        assert_eq!(
            extra.ack().await,
            PortOpenAck::refused(port_open_reason::TOO_MANY_CONNECTIONS)
        );
        assert_eq!(
            fx.ports.calls.load(Ordering::SeqCst),
            MAX_PORT_STREAMS_PER_CONNECTION,
            "the opener is not asked beyond the limit"
        );
        // One stream ends (both sides, cleanly): its slot is free again.
        let (mut hub, mut service) = open.pop().unwrap();
        hub.finish();
        service.shutdown().await.unwrap();
        assert!(hub.rest().await.is_empty());
        // The slot is given back when that stream's task ends: wait for the next accepted one.
        loop {
            let mut again = fx.conn.open();
            again.port_open(&lease(), 1, 11434);
            if again.ack().await == PortOpenAck::accepted() {
                break;
            }
            tokio::task::yield_now().await;
        }
    }

    /// Streams whose header has not come are bounded too: beyond [`MAX_PENDING_HEADERS`] a new stream is reset at
    /// once, and the waiting ones give their places back when their time is up.
    #[tokio::test(start_paused = true)]
    async fn streams_waiting_for_their_header_are_bounded() {
        let mut fx = fx();
        let silent: Vec<Hub> = (0..MAX_PENDING_HEADERS).map(|_| fx.conn.open()).collect();
        let mut extra = fx.conn.open();
        extra.port_open(&lease(), 1, 11434);
        assert!(extra.rest().await.is_empty());
        assert_eq!(extra.reset_code(), Some(STREAM_RESET_BY_AGENT));
        assert_eq!(fx.ports.calls.load(Ordering::SeqCst), 0);
        assert!(silent.iter().all(|h| h.reset_code().is_none()));
        // Their time is up: every one is reset, and new streams are served again.
        tokio::time::sleep(HEADER_TIMEOUT + Duration::from_millis(1)).await;
        for mut hub in silent {
            assert!(hub.rest().await.is_empty());
            assert_eq!(hub.reset_code(), Some(STREAM_RESET_UNSUPPORTED_STREAM));
        }
        let mut hub = fx.conn.open();
        hub.port_open(&lease(), 1, 11434);
        assert_eq!(hub.ack().await, PortOpenAck::accepted());
        fx.service().await;
    }

    /// A reset by the hub is not a clean end: the bridged connection is dropped at once, both directions, and the
    /// agent resets its own side.
    #[tokio::test]
    async fn a_reset_from_the_hub_drops_the_service_connection() {
        let mut fx = fx();
        let mut hub = fx.conn.open();
        hub.port_open(&lease(), 1, 11434);
        assert_eq!(hub.ack().await, PortOpenAck::accepted());
        let mut service = fx.service().await;
        hub.send(b"partial request");
        let mut got = [0u8; 15];
        service.read_exact(&mut got).await.unwrap();
        hub.reset();
        // The service's connection ends, and the agent's side of the stream is a reset.
        let mut rest = Vec::new();
        service.read_to_end(&mut rest).await.unwrap();
        assert!(hub.rest().await.is_empty());
        assert_eq!(hub.reset_code(), Some(STREAM_RESET_BY_AGENT));
        assert_eq!(hub.stop_code(), Some(STREAM_RESET_BY_AGENT));
        assert!(
            service.write_all(b"late answer").await.is_err(),
            "the connection is gone"
        );
    }

    /// A service connection that breaks resets the stream: the hub reads a reset, not a clean end.
    #[tokio::test]
    async fn a_broken_service_connection_resets_the_stream() {
        let fx = fx();
        *fx.ports.broken.lock().unwrap() = true;
        let mut hub = fx.conn.open();
        hub.port_open(&lease(), 1, 11434);
        assert_eq!(hub.ack().await, PortOpenAck::accepted());
        assert!(hub.rest().await.is_empty());
        assert_eq!(hub.reset_code(), Some(STREAM_RESET_BY_AGENT));
        assert_eq!(hub.stop_code(), Some(STREAM_RESET_BY_AGENT));
    }

    /// A direction that ended cleanly is not reset by what happens later: the service answers and closes, the hub
    /// reads the whole answer and a clean end, and when the client then writes on (into a connection that is
    /// gone) only its own direction is stopped.
    #[tokio::test]
    async fn a_direction_that_ended_cleanly_is_not_reset_by_a_later_error() {
        let mut fx = fx();
        let mut hub = fx.conn.open();
        hub.port_open(&lease(), 1, 11434);
        assert_eq!(hub.ack().await, PortOpenAck::accepted());
        let mut service = fx.service().await;
        service.write_all(b"HTTP/1.0 200 OK\r\n\r\nbye").await.unwrap();
        drop(service);
        assert_eq!(hub.rest().await, b"HTTP/1.0 200 OK\r\n\r\nbye");
        hub.send(b"one more request");
        tokio::time::timeout(PATIENCE, async {
            while hub.stop_code().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the client's direction was not stopped");
        assert_eq!(hub.stop_code(), Some(STREAM_RESET_BY_AGENT));
        assert_eq!(hub.reset_code(), None, "the finished answer is not reset");
    }

    /// §6.1: an idle port stream is not timed out on the agent connection.
    #[tokio::test(start_paused = true)]
    async fn an_idle_port_stream_is_not_timed_out() {
        let mut fx = fx();
        let mut hub = fx.conn.open();
        hub.port_open(&lease(), 1, 11434);
        assert_eq!(hub.ack().await, PortOpenAck::accepted());
        let mut service = fx.service().await;
        tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        hub.send(b"still here");
        let mut got = [0u8; 10];
        service.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"still here");
        assert_eq!(hub.reset_code(), None);
    }

    /// A hub that does not read the ack loses the stream after [`ACK_TIMEOUT`], and the connection opened for it is
    /// closed.
    #[tokio::test(start_paused = true)]
    async fn an_ack_the_hub_does_not_read_is_abandoned() {
        let mut fx = fx();
        let hub = fx.conn.open_with(true);
        hub.port_open(&lease(), 1, 11434);
        let mut service = fx.service().await;
        let started = tokio::time::Instant::now();
        let mut rest = Vec::new();
        service.read_to_end(&mut rest).await.unwrap();
        assert_eq!(started.elapsed(), ACK_TIMEOUT);
        assert_eq!(hub.reset_code(), Some(STREAM_RESET_BY_AGENT));
    }

    /// An opener that never answers does not hold the stream for ever.
    #[tokio::test(start_paused = true)]
    async fn an_opener_that_hangs_is_answered_connect_failed() {
        let fx = fx();
        *fx.ports.hang.lock().unwrap() = true;
        let mut hub = fx.conn.open();
        hub.port_open(&lease(), 1, 11434);
        let started = tokio::time::Instant::now();
        assert_eq!(hub.ack().await, PortOpenAck::refused(port_open_reason::CONNECT_FAILED));
        assert_eq!(started.elapsed(), OPEN_TIMEOUT);
    }

    /// The dispatcher lives as long as the connection, and its streams end with it.
    #[tokio::test]
    async fn the_streams_end_with_the_connection() {
        let mut fx = fx();
        let mut hub = fx.conn.open();
        hub.port_open(&lease(), 1, 11434);
        assert_eq!(hub.ack().await, PortOpenAck::accepted());
        let mut service = fx.service().await;
        // The connection is gone: no more streams.
        drop(fx.conn);
        fx.dispatcher.await.unwrap();
        let mut rest = Vec::new();
        service.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }
}
