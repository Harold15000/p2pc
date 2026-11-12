// SPDX-License-Identifier: Apache-2.0

//! The ingress bridge, agent side (H2 spec §11.2, SI-H2-6, SI-H2-7): how a client's connection, and the agent's own
//! health checks, reach a port of a service whose container has **no network**.
//!
//! - **Reverse dial.** For a service lease the agent listens on `<job>/p2pc/ingress.sock`, created exactly like the
//!   egress socket (0600, inside a 0700 staging directory, bound through a directory descriptor, hard-linked into
//!   place, never replacing anything: [`crate::egress`]). The shim inside the container connects to it and keeps
//!   idle connections open. The agent **never connects** to a path in a job's directories: `connect()` on a unix
//!   socket follows symlinks, and a link planted by a container could point the agent at a host socket such as
//!   Podman's. The only socket is the agent's own, in a mount the container cannot write (SI-H2-7).
//! - **`ports.json`** next to it lists the ports the shim may forward ([`write_ports_file`]); the shim starts its
//!   side of the bridge only when the file exists. The container keeps `--network=none` and the fixed argv of H1 §9:
//!   both files live in the existing read-only `/.p2pc` mount, and no port is published on any interface.
//! - **A connection.** The agent takes an idle connection and writes a 3-byte header (version [`VERSION`], the port
//!   as a big-endian `u16`). The shim answers one status byte: [`STATUS_OK`], [`STATUS_REFUSED`] or
//!   [`STATUS_NOT_LISTED`]. Then bytes flow both ways.
//! - **The peer is untrusted.** Any process of the container can connect to the socket, not only the shim. So:
//!   - connections are kept **per lease**: such a process only ever receives connections meant for its own service;
//!   - at most [`MAX_IDLE`] idle connections are kept per lease, and extra ones are closed at once;
//!   - an idle connection that sent anything, or that was closed, is never used;
//!   - a header answer is waited for [`HEADER_TIMEOUT`], then another connection is tried: `connect_failed` after
//!     [`MAX_ATTEMPTS`]; a byte that is no status counts as no answer;
//!   - the agent checks the port against the lease's own list **before** it sends anything, whatever the peer would
//!     answer.
//! - **Fencing** (SI-H2-6). A port stream names `(lease_id, epoch)`: it is refused (`stale_lease`) unless that
//!   lease is attached here with that epoch and has not been cancelled. A lease is attached from `prepare` to
//!   `cleanup`, so no stream reaches a container of another lease or of an earlier epoch.
//! - **Limits.** At most [`MAX_PORT_STREAMS_PER_LEASE`] port streams per lease (`too_many_connections`).
//! - **Health checks** ([`HealthProbe`]) use the same bridge. `tcp: true` passes on status byte 0. `http_get` sends
//!   `GET <path> HTTP/1.1` with `Host: localhost` and `Connection: close`, and reads **only the status line, at most
//!   [`MAX_STATUS_LINE`] bytes**: a longer line, or one that is not `HTTP/1.x <3 digits> …` ending in CRLF, fails;
//!   any 2xx or 3xx passes. The connection is then closed without reading headers or body. The detail of a failed
//!   check is the agent's own words and the three digits, never text from the container.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use p2pc_proto::api::ServiceSpec;
use p2pc_proto::ids::LeaseId;
use p2pc_proto::protocol::{MAX_PORT_STREAMS_PER_LEASE, PortOpen, port_open_reason};
use rustix::fs::{Mode, OFlags};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::UnixListener;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::health::{HealthCheck, HealthProbe, ProbeTarget};
use crate::connection::BoxFuture;
use crate::connection::streams::{PortIo, PortOpener};
use crate::egress::{self, Listener, SocketOptions, StartError};

/// The socket's name in the job's `p2pc/` directory (`/.p2pc/ingress.sock` in the container).
pub const SOCKET_NAME: &str = "ingress.sock";
/// The ports file's name in the job's `p2pc/` directory (`/.p2pc/ports.json` in the container).
pub const PORTS_FILE: &str = "ports.json";
/// Mode of the ports file: read by the shim, whatever user the image runs as.
pub const PORTS_FILE_MODE: u32 = 0o644;
/// Most ports of one service (H2 §7.1).
pub const MAX_PORTS: usize = 8;
/// Idle connections kept per lease; extra ones are closed (§11.2). The shim keeps 4.
pub const MAX_IDLE: usize = 8;
/// How long the agent waits for the status byte after its header, and for an idle connection to use.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
/// Connections tried for one port stream or health check before `connect_failed`.
pub const MAX_ATTEMPTS: usize = 3;
/// The version byte of the header.
pub const VERSION: u8 = 1;
/// Status byte: the shim connected the port; bytes follow.
pub const STATUS_OK: u8 = 0;
/// Status byte: nothing accepted the connection on the port.
pub const STATUS_REFUSED: u8 = 1;
/// Status byte: the shim does not list the port.
pub const STATUS_NOT_LISTED: u8 = 2;
/// Most bytes the agent reads of a health check's response: its status line (§11.2, SI-H2-7).
pub const MAX_STATUS_LINE: usize = 1024;
/// Longest one health check may take here, whatever the caller does (the driver bounds it by the check's own
/// `timeout_s`, at most 60 s).
pub const MAX_CHECK_TIME: Duration = Duration::from_secs(60);

/// One bridged connection, or an idle one.
type Conn = Box<dyn PortIo>;

/// Why a port stream was not opened. Each is a `reason` of `PortOpenAck` (H2 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    /// `(lease_id, epoch)` is not a lease attached here, or it was cancelled (SI-H2-6).
    #[error("not the current lease of a service on this node")]
    StaleLease,
    /// The service does not list the port (or the shim says so).
    #[error("the service does not expose that port")]
    PortNotExposed,
    /// No connection from the container is there to use: it has not started, or its shim has not dialed yet.
    #[error("no bridge connection from the service's container yet")]
    NotReady,
    /// The lease already has [`MAX_PORT_STREAMS_PER_LEASE`] port streams.
    #[error("the lease has too many port streams")]
    TooManyConnections,
    /// Nothing accepted the connection on the port, or no bridge connection answered in [`MAX_ATTEMPTS`] tries.
    #[error("could not connect to the port through the bridge")]
    ConnectFailed,
}

impl OpenError {
    /// The `PortOpenAck.reason` code.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            OpenError::StaleLease => port_open_reason::STALE_LEASE,
            OpenError::PortNotExposed => port_open_reason::PORT_NOT_EXPOSED,
            OpenError::NotReady => port_open_reason::NOT_READY,
            OpenError::TooManyConnections => port_open_reason::TOO_MANY_CONNECTIONS,
            OpenError::ConnectFailed => port_open_reason::CONNECT_FAILED,
        }
    }
}

/// Why a lease could not be attached to the bridge.
#[derive(Debug, thiserror::Error)]
pub enum AttachError {
    /// Not 1 to [`MAX_PORTS`] distinct ports of 1-65535.
    #[error("the service's ports are not 1 to 8 distinct ports")]
    InvalidPorts,
    /// The lease is attached already.
    #[error("the lease already has an ingress bridge")]
    AlreadyAttached,
    /// The socket's directory is unsafe, or something already exists at the socket's path (it is never replaced).
    #[error("ingress socket: {0}")]
    Refused(String),
    /// An I/O error while creating the socket.
    #[error("ingress socket: {0}")]
    Io(#[source] io::Error),
}

impl From<StartError> for AttachError {
    fn from(e: StartError) -> Self {
        match e {
            StartError::Io(e) => AttachError::Io(e),
            other => AttachError::Refused(other.to_string()),
        }
    }
}

/// The ports of a validated `service` block, as the bridge takes them: 1 to [`MAX_PORTS`] distinct ports of 1-65535.
/// `None` for anything else.
#[must_use]
pub fn service_ports(service: &ServiceSpec) -> Option<Vec<u16>> {
    let ports: Vec<u16> = service
        .ports
        .iter()
        .map(|p| u16::try_from(p.port).ok())
        .collect::<Option<_>>()?;
    valid_ports(&ports).then_some(ports)
}

fn valid_ports(ports: &[u16]) -> bool {
    (1..=MAX_PORTS).contains(&ports.len())
        && ports.iter().all(|p| *p != 0)
        && ports.iter().enumerate().all(|(i, p)| !ports[..i].contains(p))
}

/// The content of `ports.json`: `{"ports":[11434,8080]}`. The shim reads exactly this form.
#[must_use]
pub fn ports_json(ports: &[u16]) -> String {
    let list: Vec<String> = ports.iter().map(u16::to_string).collect();
    format!("{{\"ports\":[{}]}}", list.join(","))
}

/// Writes `ports.json` (0644) into the job's `p2pc/` directory `dir`, with `O_EXCL | O_NOFOLLOW`: an existing entry
/// or a symlink there is refused, never written through.
///
/// # Errors
/// `InvalidInput` for ports that are not 1 to [`MAX_PORTS`] distinct ports; any I/O error.
pub fn write_ports_file(dir: &Path, ports: &[u16]) -> io::Result<()> {
    if !valid_ports(ports) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            AttachError::InvalidPorts.to_string(),
        ));
    }
    let fd = rustix::fs::open(
        dir.join(PORTS_FILE),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(PORTS_FILE_MODE),
    )?;
    // Exact mode whatever the umask.
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(PORTS_FILE_MODE))?;
    let mut file = std::fs::File::from(fd);
    file.write_all(ports_json(ports).as_bytes())?;
    file.sync_all()
}

/// Whether an idle connection can still be used: the peer has sent nothing and has not closed it. One poll that
/// never waits; a byte it reads makes the connection unusable anyway.
fn still_idle(conn: &mut Conn) -> bool {
    let mut byte = [0u8; 1];
    let mut buf = ReadBuf::new(&mut byte);
    let mut cx = Context::from_waker(Waker::noop());
    Pin::new(conn).poll_read(&mut cx, &mut buf).is_pending()
}

/// The idle connections of one lease.
#[derive(Default)]
struct Pool {
    idle: Mutex<VecDeque<Conn>>,
    /// Signalled when a connection arrives.
    arrived: Notify,
    /// Connections closed because [`MAX_IDLE`] were already kept.
    extra_closed: AtomicU64,
    /// Connections accepted so far, kept or not.
    accepted: AtomicU64,
}

impl Pool {
    /// Keeps a new connection, or closes it when the lease already has [`MAX_IDLE`].
    fn offer(&self, conn: Conn) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        // Connections the container closed, or wrote on, do not take the room of live ones.
        idle.retain_mut(still_idle);
        if idle.len() >= MAX_IDLE {
            // Dropped here: closed at once.
            self.extra_closed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        idle.push_back(conn);
        drop(idle);
        self.arrived.notify_one();
    }

    /// The oldest idle connection that is still usable; the others on the way are dropped.
    fn pop(&self) -> Option<Conn> {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some(mut conn) = idle.pop_front() {
            if still_idle(&mut conn) {
                return Some(conn);
            }
        }
        None
    }

    /// An idle connection, waiting for one to arrive until `deadline`.
    async fn take(&self, deadline: Instant) -> Option<Conn> {
        loop {
            let arrived = self.arrived.notified();
            tokio::pin!(arrived);
            // Registered before the look, so an arrival in between is not missed.
            arrived.as_mut().enable();
            if let Some(conn) = self.pop() {
                return Some(conn);
            }
            if tokio::time::timeout_at(deadline, arrived).await.is_err() {
                return None;
            }
        }
    }

    /// Closes every idle connection.
    fn clear(&self) {
        self.idle.lock().unwrap_or_else(PoisonError::into_inner).clear();
    }
}

/// One attached service lease.
struct Lease {
    epoch: u64,
    ports: Vec<u16>,
    pool: Pool,
    /// The lease's port streams ([`MAX_PORT_STREAMS_PER_LEASE`] permits).
    streams: Arc<Semaphore>,
    /// The lease's cancel flag: once set, no new port stream is opened.
    cancel: watch::Receiver<bool>,
}

impl Lease {
    /// One connection to `port` through the bridge: an idle connection, the header, the shim's status byte.
    ///
    /// Only status 0 hands the connection out. Status 1 and 2 are the shim's own answers and end the try. Anything
    /// else (no answer within [`HEADER_TIMEOUT`], a connection that broke, a byte that is no status) is not the
    /// shim's answer: that connection is dropped and another is tried, [`MAX_ATTEMPTS`] in all.
    async fn bridge_to(&self, port: u16) -> Result<Conn, OpenError> {
        let [hi, lo] = port.to_be_bytes();
        for attempt in 0..MAX_ATTEMPTS {
            let Some(mut conn) = self.pool.take(Instant::now() + HEADER_TIMEOUT).await else {
                // Nothing from the container to use: it never dialed, or what it dialed is used up.
                return Err(if attempt == 0 {
                    OpenError::NotReady
                } else {
                    OpenError::ConnectFailed
                });
            };
            let answer = tokio::time::timeout(HEADER_TIMEOUT, async {
                conn.write_all(&[VERSION, hi, lo]).await?;
                let mut status = [0u8; 1];
                conn.read_exact(&mut status).await?;
                io::Result::Ok(status[0])
            })
            .await;
            match answer {
                Ok(Ok(STATUS_OK)) => return Ok(conn),
                Ok(Ok(STATUS_REFUSED)) => return Err(OpenError::ConnectFailed),
                Ok(Ok(STATUS_NOT_LISTED)) => return Err(OpenError::PortNotExposed),
                _ => {}
            }
        }
        Err(OpenError::ConnectFailed)
    }

    /// One health check (§11.2).
    async fn check(&self, check: &HealthCheck) -> Result<(), String> {
        let (port, path) = match check {
            HealthCheck::Http { port, path } => (*port, Some(path.as_str())),
            HealthCheck::Tcp { port } => (*port, None),
        };
        // The validation of the job already made sure of it; a check never goes to another port.
        if !self.ports.contains(&port) {
            return Err(format!("port {port} is not a port of the service"));
        }
        // Validated with the job (H2 §7.1: absolute, no CR, LF or NUL). Checked again where it is used: nothing that
        // could end the request line early is ever written, and no connection is spent on it.
        if path.is_some_and(|p| !p.starts_with('/') || p.bytes().any(|b| b <= b' ' || b == 0x7f)) {
            return Err("the check's path cannot be sent in a request line".into());
        }
        let mut conn = self.bridge_to(port).await.map_err(|e| match e {
            OpenError::ConnectFailed => format!("cannot connect to port {port}"),
            other => other.to_string(),
        })?;
        match path {
            // `tcp: true`: the status byte 0 passes.
            None => Ok(()),
            Some(path) => http_check(&mut conn, path).await,
        }
        // The connection is dropped here: closed without reading anything more.
    }
}

/// Sends the request of an `http_get` check on a bridged connection and judges the status line.
async fn http_check(conn: &mut Conn, path: &str) -> Result<(), String> {
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    conn.write_all(request.as_bytes())
        .await
        .map_err(|e| format!("cannot send the request: {}", e.kind()))?;
    let line = read_status_line(conn).await?;
    let code = parse_status_line(&line)?;
    if (200..400).contains(&code) {
        Ok(())
    } else {
        Err(format!("HTTP {code}"))
    }
}

/// Reads the response up to its first line feed, and never more than [`MAX_STATUS_LINE`] bytes in all.
///
/// The buffer is the limit: every read goes into what is left of [`MAX_STATUS_LINE`] bytes, so an endless line or
/// an endless body costs the agent 1 KiB and no more.
async fn read_status_line(conn: &mut Conn) -> Result<Vec<u8>, String> {
    let mut line = [0u8; MAX_STATUS_LINE];
    let mut filled = 0;
    while filled < line.len() {
        let n = conn
            .read(&mut line[filled..])
            .await
            .map_err(|e| format!("cannot read the response: {}", e.kind()))?;
        if n == 0 {
            return Err("the response ended before a status line".into());
        }
        let line_feed = line[filled..filled + n].iter().position(|b| *b == b'\n');
        if let Some(at) = line_feed {
            return Ok(line[..=filled + at].to_vec());
        }
        filled += n;
    }
    Err("the status line is longer than 1 KiB".into())
}

/// The status code of a status line (with its line end): `HTTP/1.x <3 digits>`, then nothing or a space and a
/// reason, ending in CRLF.
fn parse_status_line(line: &[u8]) -> Result<u16, String> {
    let bad = || "the response does not start with an HTTP/1.x status line".to_string();
    let line = line.strip_suffix(b"\r\n").ok_or_else(bad)?;
    let rest = line.strip_prefix(b"HTTP/1.").ok_or_else(bad)?;
    let [minor, b' ', d1, d2, d3, reason @ ..] = rest else {
        return Err(bad());
    };
    let digits = [*d1, *d2, *d3];
    if !minor.is_ascii_digit() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(bad());
    }
    // After the code: the end of the line, or a space and the reason. A carriage return inside is no line end.
    if !(reason.is_empty() || reason[0] == b' ') || reason.contains(&b'\r') {
        return Err(bad());
    }
    Ok(digits.iter().fold(0u16, |code, d| code * 10 + u16::from(d - b'0')))
}

/// A bridged connection of a port stream; it holds one of its lease's stream slots until it is dropped.
struct Bridged {
    conn: Conn,
    _slot: OwnedSemaphorePermit,
}

impl AsyncRead for Bridged {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for Bridged {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.conn).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}

/// Accepts the container's connections for one lease, for as long as the lease is attached.
async fn accept_loop<L: Listener>(mut listener: L, lease: Arc<Lease>) {
    loop {
        match listener.next_conn().await {
            Ok(conn) => lease.pool.offer(Box::new(conn)),
            Err(e) => {
                tracing::warn!(error = %e, "ingress accept failed");
                // Out of file descriptors and similar: back off instead of spinning.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

type Leases = Arc<Mutex<HashMap<LeaseId, Arc<Lease>>>>;

/// The node's ingress bridge: the attached service leases and their idle connections. Clones share it.
///
/// It is the driver's [`HealthProbe`] and the connection's [`PortOpener`]: the same object, so a health check and a
/// port stream go through the same socket and the same rules.
#[derive(Clone, Default)]
pub struct IngressBridge {
    leases: Leases,
    /// Tests only: attach without a socket file (see [`IngressBridge::without_sockets`]).
    #[cfg(test)]
    no_sockets: bool,
}

impl fmt::Debug for IngressBridge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let leases = self.leases.lock().unwrap_or_else(PoisonError::into_inner);
        f.debug_struct("IngressBridge").field("leases", &leases.len()).finish()
    }
}

/// What a service lease needs from the bridge.
#[derive(Debug)]
pub struct Attach<'a> {
    /// The lease.
    pub lease_id: LeaseId,
    /// Its epoch: a port stream for another one is refused.
    pub epoch: u64,
    /// The service's ports ([`service_ports`]).
    pub ports: &'a [u16],
    /// The job's `p2pc/` directory, where the socket goes.
    pub dir: &'a Path,
    /// The lease's cancel flag.
    pub cancel: watch::Receiver<bool>,
}

/// An attached lease. Dropping it detaches the lease: its socket is removed, its idle connections are closed, and
/// every later port stream for it is `stale_lease`.
pub struct IngressSession {
    leases: Leases,
    lease_id: LeaseId,
    lease: Arc<Lease>,
    task: JoinHandle<()>,
    socket: Option<PathBuf>,
}

impl fmt::Debug for IngressSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IngressSession")
            .field("lease_id", &self.lease_id)
            .field("epoch", &self.lease.epoch)
            .finish_non_exhaustive()
    }
}

impl Drop for IngressSession {
    fn drop(&mut self) {
        self.task.abort();
        {
            let mut leases = self.leases.lock().unwrap_or_else(PoisonError::into_inner);
            if leases.get(&self.lease_id).is_some_and(|l| Arc::ptr_eq(l, &self.lease)) {
                leases.remove(&self.lease_id);
            }
        }
        self.lease.pool.clear();
        if let Some(socket) = &self.socket {
            let _ = std::fs::remove_file(socket);
        }
    }
}

impl IngressBridge {
    /// A bridge with no lease.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A bridge whose [`IngressBridge::attach`] registers the lease but makes no socket file, for the tests of its
    /// callers: some build sandboxes forbid unix sockets, and what the driver does with the bridge can be checked
    /// without one.
    #[cfg(test)]
    pub(crate) fn without_sockets() -> Self {
        Self {
            leases: Leases::default(),
            no_sockets: true,
        }
    }

    /// The epoch and ports of an attached lease (tests).
    #[cfg(test)]
    pub(crate) fn attached(&self, lease_id: &LeaseId) -> Option<(u64, Vec<u16>)> {
        self.lease(lease_id).map(|l| (l.epoch, l.ports.clone()))
    }

    /// Attaches a service lease: creates its `ingress.sock` in `attach.dir` and starts accepting the container's
    /// connections. Call it before the container is created, inside a Tokio runtime. `ports.json` is written apart
    /// ([`write_ports_file`]).
    ///
    /// # Errors
    /// [`AttachError`]: nothing is left behind.
    pub fn attach(&self, attach: Attach<'_>) -> Result<IngressSession, AttachError> {
        if !valid_ports(attach.ports) {
            return Err(AttachError::InvalidPorts);
        }
        if self.lease(&attach.lease_id).is_some() {
            return Err(AttachError::AlreadyAttached);
        }
        #[cfg(test)]
        if self.no_sockets {
            return self.attach_listener(&attach, tests::NoConnections, None);
        }
        let socket = attach.dir.join(SOCKET_NAME);
        // The egress socket's own code: 0600 in a 0700 staging directory, bound by directory descriptor (the path
        // may be longer than `sun_path`), linked into place, never replacing anything. The owner stays the agent:
        // the driver mounts the directory with `:U`.
        let listener = egress::create_socket(&socket, SocketOptions { owner: None })?;
        let listener = listener
            .set_nonblocking(true)
            .and_then(|()| UnixListener::from_std(listener));
        let attached = match listener {
            Ok(listener) => self.attach_listener(&attach, listener, Some(socket.clone())),
            Err(e) => Err(AttachError::Io(e)),
        };
        if attached.is_err() {
            let _ = std::fs::remove_file(&socket);
        }
        attached
    }

    /// [`IngressBridge::attach`] on a listener that already exists (tests use an in-memory one).
    pub(crate) fn attach_listener<L: Listener>(
        &self,
        attach: &Attach<'_>,
        listener: L,
        socket: Option<PathBuf>,
    ) -> Result<IngressSession, AttachError> {
        if !valid_ports(attach.ports) {
            return Err(AttachError::InvalidPorts);
        }
        let lease = Arc::new(Lease {
            epoch: attach.epoch,
            ports: attach.ports.to_vec(),
            pool: Pool::default(),
            streams: Arc::new(Semaphore::new(MAX_PORT_STREAMS_PER_LEASE)),
            cancel: attach.cancel.clone(),
        });
        {
            let mut leases = self.leases.lock().unwrap_or_else(PoisonError::into_inner);
            if leases.contains_key(&attach.lease_id) {
                return Err(AttachError::AlreadyAttached);
            }
            leases.insert(attach.lease_id, Arc::clone(&lease));
        }
        let task = tokio::spawn(accept_loop(listener, Arc::clone(&lease)));
        Ok(IngressSession {
            leases: Arc::clone(&self.leases),
            lease_id: attach.lease_id,
            lease,
            task,
            socket,
        })
    }

    fn lease(&self, lease_id: &LeaseId) -> Option<Arc<Lease>> {
        self.leases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(lease_id)
            .cloned()
    }

    /// Opens a port stream: a connection to `port` of the service of `(lease_id, epoch)`.
    ///
    /// # Errors
    /// [`OpenError`], in this order: the lease (SI-H2-6), the port, the lease's stream limit, the bridge.
    pub async fn open_port(&self, lease_id: LeaseId, epoch: u64, port: u16) -> Result<Box<dyn PortIo>, OpenError> {
        // SI-H2-6: this lease, this epoch, and not cancelled.
        let lease = self
            .lease(&lease_id)
            .filter(|lease| lease.epoch == epoch && !*lease.cancel.borrow())
            .ok_or(OpenError::StaleLease)?;
        // The agent's own check of the port, before anything is sent to the container.
        if !lease.ports.contains(&port) {
            return Err(OpenError::PortNotExposed);
        }
        let slot = Arc::clone(&lease.streams)
            .try_acquire_owned()
            .map_err(|_| OpenError::TooManyConnections)?;
        let conn = lease.bridge_to(port).await?;
        Ok(Box::new(Bridged { conn, _slot: slot }))
    }
}

impl PortOpener for IngressBridge {
    fn open<'a>(&'a self, open: &'a PortOpen) -> BoxFuture<'a, Result<Box<dyn PortIo>, &'static str>> {
        Box::pin(async move {
            self.open_port(open.lease_id, open.epoch, open.port)
                .await
                .map_err(|e| {
                    tracing::info!(lease_id = %open.lease_id, epoch = open.epoch, port = open.port, reason = e.reason(), "port stream refused");
                    e.reason()
                })
        })
    }
}

impl HealthProbe for IngressBridge {
    fn check<'a>(&'a self, target: &'a ProbeTarget, check: &'a HealthCheck) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            // The lease's own bridge, found by its ID: no path is derived from the target, and nothing is connected.
            let Some(lease) = self.lease(&target.lease_id) else {
                return Err("the lease has no ingress bridge".to_string());
            };
            match tokio::time::timeout(MAX_CHECK_TIME, lease.check(check)).await {
                Ok(result) => result,
                Err(_) => Err(format!("no answer within {} s", MAX_CHECK_TIME.as_secs())),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _, symlink};
    use std::str::FromStr;
    use std::sync::atomic::AtomicUsize;

    use tokio::io::DuplexStream;
    use tokio::sync::mpsc;

    use super::*;

    fn lease_a() -> LeaseId {
        LeaseId::from_str("lse_01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap()
    }

    fn lease_b() -> LeaseId {
        LeaseId::from_str("lse_01BX5ZZKBKACTAV9WEVGEMMVRZ").unwrap()
    }

    /// The agent's end of a test connection: a pipe that counts the bytes the agent read from it.
    struct Counted {
        pipe: DuplexStream,
        read: Arc<AtomicUsize>,
    }

    impl AsyncRead for Counted {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let before = buf.filled().len();
            let polled = Pin::new(&mut self.pipe).poll_read(cx, buf);
            self.read.fetch_add(buf.filled().len() - before, Ordering::SeqCst);
            polled
        }
    }

    impl AsyncWrite for Counted {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.pipe).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.pipe).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.pipe).poll_shutdown(cx)
        }
    }

    /// A listener nothing ever connects to ([`IngressBridge::without_sockets`]).
    pub(crate) struct NoConnections;

    impl Listener for NoConnections {
        type Conn = DuplexStream;
        async fn next_conn(&mut self) -> io::Result<DuplexStream> {
            std::future::pending().await
        }
    }

    /// An in-memory `ingress.sock`: the test connects by sending the agent's end of a pipe.
    struct PipeListener(mpsc::UnboundedReceiver<Counted>);

    impl Listener for PipeListener {
        type Conn = Counted;
        async fn next_conn(&mut self) -> io::Result<Counted> {
            match self.0.recv().await {
                Some(conn) => Ok(conn),
                None => std::future::pending().await,
            }
        }
    }

    /// The container's side of one lease's socket.
    struct Container {
        socket: mpsc::UnboundedSender<Counted>,
        /// Bytes the agent read from this container's connections, in all.
        agent_read: Arc<AtomicUsize>,
    }

    impl Container {
        /// A process of the container connects to `ingress.sock`: its end of the connection.
        fn connect(&self) -> DuplexStream {
            let (agent, container) = tokio::io::duplex(64 * 1024);
            let conn = Counted {
                pipe: agent,
                read: Arc::clone(&self.agent_read),
            };
            self.socket.send(conn).unwrap();
            container
        }

        /// Like [`Container::connect`], once the agent has taken the connection into its pool.
        async fn idle(&self, session: &IngressSession) -> DuplexStream {
            let before = session.accepted();
            let conn = self.connect();
            while session.accepted() == before {
                tokio::task::yield_now().await;
            }
            conn
        }
    }

    impl IngressSession {
        fn idle_len(&self) -> usize {
            self.lease.pool.idle.lock().unwrap().len()
        }

        fn extra_closed(&self) -> u64 {
            self.lease.pool.extra_closed.load(Ordering::SeqCst)
        }

        /// Connections the accept loop has handled so far: kept or closed.
        fn accepted(&self) -> u64 {
            self.lease.pool.accepted.load(Ordering::SeqCst)
        }
    }

    struct Fx {
        bridge: IngressBridge,
        session: IngressSession,
        container: Container,
        cancel: watch::Sender<bool>,
    }

    fn attach_to(bridge: &IngressBridge, lease_id: LeaseId, epoch: u64, ports: &[u16]) -> Fx {
        let (socket, accepted) = mpsc::unbounded_channel();
        let (cancel, cancel_rx) = watch::channel(false);
        let attach = Attach {
            lease_id,
            epoch,
            ports,
            dir: Path::new("/nonexistent.invalid"),
            cancel: cancel_rx,
        };
        let session = bridge.attach_listener(&attach, PipeListener(accepted), None).unwrap();
        Fx {
            bridge: bridge.clone(),
            session,
            container: Container {
                socket,
                agent_read: Arc::new(AtomicUsize::new(0)),
            },
            cancel,
        }
    }

    /// Lease A, epoch 3, ports 11434 and 8080.
    fn fx() -> Fx {
        attach_to(&IngressBridge::new(), lease_a(), 3, &[11434, 8080])
    }

    /// How long a test waits for something that must happen: a failure is then a failure, not a hang. Under a
    /// paused clock it only passes when nothing else can happen.
    const PATIENCE: Duration = Duration::from_secs(30);

    /// Reads the agent's header on a container connection.
    async fn header(conn: &mut DuplexStream) -> [u8; 3] {
        let mut header = [0u8; 3];
        tokio::time::timeout(PATIENCE, conn.read_exact(&mut header))
            .await
            .expect("the agent sent no header")
            .unwrap();
        header
    }

    /// A shim that answers the next header on `conn` with `status`.
    async fn answer(conn: &mut DuplexStream, status: u8) -> [u8; 3] {
        let header = header(conn).await;
        conn.write_all(&[status]).await.unwrap();
        header
    }

    /// Whether the agent has written anything to this container connection.
    fn untouched(conn: &mut DuplexStream) -> bool {
        let mut byte = [0u8; 1];
        let mut buf = ReadBuf::new(&mut byte);
        let mut cx = Context::from_waker(Waker::noop());
        Pin::new(conn).poll_read(&mut cx, &mut buf).is_pending()
    }

    fn http(port: u16, path: &str) -> HealthCheck {
        HealthCheck::Http {
            port,
            path: path.into(),
        }
    }

    fn target(lease_id: LeaseId) -> ProbeTarget {
        ProbeTarget {
            lease_id,
            job_dir: PathBuf::from("/nonexistent.invalid/jobs").join(lease_id.to_string()),
        }
    }

    /// One health check of `lease` through `bridge`.
    async fn probe(bridge: &IngressBridge, lease: LeaseId, check: HealthCheck) -> Result<(), String> {
        bridge.check(&target(lease), &check).await
    }

    async fn opened(r: Result<Box<dyn PortIo>, OpenError>) -> Result<(), OpenError> {
        r.map(|_| ())
    }

    // -----------------------------------------------------------------------------------------------------------
    // The bridge protocol

    /// §11.2: the agent takes an idle connection, writes version 1 and the port big-endian, reads one status byte,
    /// and the connection then carries the stream's bytes both ways.
    #[tokio::test]
    async fn a_port_stream_takes_an_idle_connection_and_sends_the_header() {
        let fx = fx();
        let mut shim = fx.container.idle(&fx.session).await;
        let (stream, header) = tokio::join!(fx.bridge.open_port(lease_a(), 3, 11434), answer(&mut shim, STATUS_OK));
        assert_eq!(header, [1, 0x2c, 0xaa], "version 1, then 11434 big-endian");
        let mut stream = stream.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        shim.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        shim.write_all(b"pong").await.unwrap();
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong");
        // A half-close travels: the shim sees the end of the client's bytes.
        stream.shutdown().await.unwrap();
        let mut rest = Vec::new();
        shim.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        assert_eq!(fx.session.idle_len(), 0, "the connection is not idle any more");
    }

    /// Status 1 and 2 are the shim's answers: no other connection is tried for them.
    #[tokio::test]
    async fn refused_is_connect_failed_and_not_listed_is_port_not_exposed() {
        let fx = fx();
        for (status, error) in [
            (STATUS_REFUSED, OpenError::ConnectFailed),
            (STATUS_NOT_LISTED, OpenError::PortNotExposed),
        ] {
            let mut first = fx.container.idle(&fx.session).await;
            let mut second = fx.container.idle(&fx.session).await;
            let (stream, _) = tokio::join!(fx.bridge.open_port(lease_a(), 3, 8080), answer(&mut first, status));
            assert_eq!(opened(stream).await, Err(error));
            assert!(untouched(&mut second), "no second try after the shim's own answer");
            // Use the second one up, so the next round starts with an empty pool.
            let (stream, _) = tokio::join!(fx.bridge.open_port(lease_a(), 3, 8080), answer(&mut second, STATUS_OK));
            stream.unwrap();
        }
        assert_eq!(OpenError::ConnectFailed.reason(), "connect_failed");
        assert_eq!(OpenError::PortNotExposed.reason(), "port_not_exposed");
        assert_eq!(OpenError::StaleLease.reason(), "stale_lease");
        assert_eq!(OpenError::NotReady.reason(), "not_ready");
        assert_eq!(OpenError::TooManyConnections.reason(), "too_many_connections");
    }

    /// §11.2: a header answer is waited for 5 s, then another connection is tried.
    #[tokio::test(start_paused = true)]
    async fn a_header_that_is_not_answered_in_5_s_moves_on_to_another_connection() {
        let fx = fx();
        let mut silent = fx.container.idle(&fx.session).await;
        let mut shim = fx.container.idle(&fx.session).await;
        let started = Instant::now();
        let (stream, (), header) = tokio::join!(
            fx.bridge.open_port(lease_a(), 3, 8080),
            async {
                assert_eq!(header(&mut silent).await, [1, 0x1f, 0x90]);
            },
            answer(&mut shim, STATUS_OK)
        );
        stream.unwrap();
        assert_eq!(header, [1, 0x1f, 0x90]);
        assert_eq!(started.elapsed(), HEADER_TIMEOUT);
        // The connection that did not answer was closed.
        let mut rest = Vec::new();
        silent.read_to_end(&mut rest).await.unwrap();
    }

    /// §11.2: `connect_failed` after 3 connections that did not answer; a fourth is never tried.
    #[tokio::test(start_paused = true)]
    async fn three_connections_that_do_not_answer_are_connect_failed() {
        let fx = fx();
        let mut silent = Vec::new();
        for _ in 0..4 {
            silent.push(fx.container.idle(&fx.session).await);
        }
        let started = Instant::now();
        let r = fx.bridge.open_port(lease_a(), 3, 8080).await;
        assert_eq!(opened(r).await, Err(OpenError::ConnectFailed));
        assert_eq!(started.elapsed(), HEADER_TIMEOUT * 3);
        let mut fourth = silent.pop().unwrap();
        assert!(untouched(&mut fourth), "the fourth connection got no header");
        for mut conn in silent {
            assert_eq!(header(&mut conn).await, [1, 0x1f, 0x90]);
        }
        assert_eq!(MAX_ATTEMPTS, 3);
    }

    /// SI-H2-7, a fake shim: a process that answers with a byte that is no status, or closes the connection, is
    /// not believed; the agent tries another connection.
    #[tokio::test]
    async fn a_fake_shim_that_answers_nonsense_is_skipped() {
        let fx = fx();
        for nonsense in [3u8, 7, 0x48, 255] {
            let mut fake = fx.container.idle(&fx.session).await;
            let mut shim = fx.container.idle(&fx.session).await;
            let (stream, _, _) = tokio::join!(
                fx.bridge.open_port(lease_a(), 3, 11434),
                answer(&mut fake, nonsense),
                answer(&mut shim, STATUS_OK)
            );
            stream.unwrap();
        }
        // One that hangs up on the header.
        let mut fake = fx.container.idle(&fx.session).await;
        let mut shim = fx.container.idle(&fx.session).await;
        let (stream, (), _) = tokio::join!(
            fx.bridge.open_port(lease_a(), 3, 11434),
            async {
                header(&mut fake).await;
                drop(fake);
            },
            answer(&mut shim, STATUS_OK)
        );
        stream.unwrap();
        // Three of them in a row: the stream fails, it is never handed a connection that did not say 0.
        let mut fakes = Vec::new();
        for _ in 0..3 {
            fakes.push(fx.container.idle(&fx.session).await);
        }
        let (stream, ..) = tokio::join!(fx.bridge.open_port(lease_a(), 3, 11434), async {
            for fake in &mut fakes {
                answer(fake, 9).await;
            }
        });
        assert_eq!(opened(stream).await, Err(OpenError::ConnectFailed));
    }

    /// An idle connection that spoke first, or that was closed, is never used: a status byte sent ahead of the
    /// header is not an answer to it.
    #[tokio::test]
    async fn an_idle_connection_that_spoke_first_or_closed_is_never_used() {
        let fx = fx();
        let mut eager = fx.container.idle(&fx.session).await;
        eager.write_all(&[STATUS_OK]).await.unwrap();
        let closed = fx.container.idle(&fx.session).await;
        drop(closed);
        let mut shim = fx.container.idle(&fx.session).await;
        let (stream, header) = tokio::join!(fx.bridge.open_port(lease_a(), 3, 11434), answer(&mut shim, STATUS_OK));
        stream.unwrap();
        assert_eq!(header, [1, 0x2c, 0xaa]);
        // The eager one got no header: it was dropped.
        let mut rest = Vec::new();
        eager.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "{rest:?}");
    }

    /// §11.2: at most 8 idle connections per lease; extra ones are closed.
    #[tokio::test]
    async fn at_most_8_idle_connections_are_kept_and_extra_ones_are_closed() {
        let fx = fx();
        let mut kept = Vec::new();
        for _ in 0..MAX_IDLE {
            kept.push(fx.container.idle(&fx.session).await);
        }
        assert_eq!(fx.session.idle_len(), 8);
        for n in 1..=20u64 {
            let mut extra = fx.container.idle(&fx.session).await;
            let mut rest = Vec::new();
            tokio::time::timeout(PATIENCE, extra.read_to_end(&mut rest))
                .await
                .expect("an extra connection was kept open")
                .unwrap();
            assert!(rest.is_empty(), "closed at once, with nothing sent");
            assert_eq!(fx.session.extra_closed(), n);
            assert_eq!(fx.session.idle_len(), 8);
        }
        assert!(kept.iter_mut().all(untouched), "the kept ones are untouched");
        // One is used: there is room for one more, and no more.
        let (stream, _) = tokio::join!(
            fx.bridge.open_port(lease_a(), 3, 11434),
            answer(&mut kept[0], STATUS_OK)
        );
        stream.unwrap();
        let _ninth = fx.container.idle(&fx.session).await;
        assert_eq!((fx.session.idle_len(), fx.session.extra_closed()), (8, 20));
        // Idle connections the container closed do not take the room of live ones.
        drop(kept);
        for _ in 0..3 {
            let _ = fx.container.idle(&fx.session).await;
        }
        assert_eq!(fx.session.extra_closed(), 20, "closed ones were pruned to make room");
    }

    /// Without any connection from the container the stream is `not_ready`, after waiting for one; one that
    /// arrives during the wait is used.
    #[tokio::test(start_paused = true)]
    async fn no_bridge_connection_is_not_ready() {
        let fx = fx();
        let started = Instant::now();
        let r = fx.bridge.open_port(lease_a(), 3, 11434).await;
        assert_eq!(opened(r).await, Err(OpenError::NotReady));
        assert_eq!(started.elapsed(), HEADER_TIMEOUT);

        let (stream, ()) = tokio::join!(fx.bridge.open_port(lease_a(), 3, 11434), async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let mut shim = fx.container.connect();
            answer(&mut shim, STATUS_OK).await;
        });
        stream.unwrap();
    }

    // -----------------------------------------------------------------------------------------------------------
    // Fencing, the port list and the limits

    /// SI-H2-6: a port stream is refused for anything but the attached lease and its epoch, and after its cancel.
    /// Nothing is sent to the container for it.
    #[tokio::test]
    async fn a_port_stream_for_another_lease_or_epoch_is_stale() {
        let fx = fx();
        let mut shim = fx.container.idle(&fx.session).await;
        for (lease, epoch) in [(lease_a(), 2), (lease_a(), 4), (lease_a(), 0), (lease_b(), 3)] {
            let r = fx.bridge.open_port(lease, epoch, 11434).await;
            assert_eq!(opened(r).await, Err(OpenError::StaleLease), "{lease} {epoch}");
        }
        assert!(untouched(&mut shim));
        // The right one works.
        let (stream, _) = tokio::join!(fx.bridge.open_port(lease_a(), 3, 11434), answer(&mut shim, STATUS_OK));
        stream.unwrap();
        // Cancelled (stopped, replaced by a newer epoch, lease lost): no new stream, though it is still attached.
        let mut shim = fx.container.idle(&fx.session).await;
        fx.cancel.send_replace(true);
        let r = fx.bridge.open_port(lease_a(), 3, 11434).await;
        assert_eq!(opened(r).await, Err(OpenError::StaleLease));
        assert!(untouched(&mut shim));
    }

    /// Once the lease is detached (its cleanup), its idle connections are closed and every stream for it is stale.
    #[tokio::test]
    async fn a_detached_lease_is_stale_and_its_connections_are_closed() {
        let Fx {
            bridge,
            session,
            container,
            cancel: _cancel,
        } = fx();
        let mut shim = container.idle(&session).await;
        drop(session);
        let r = bridge.open_port(lease_a(), 3, 11434).await;
        assert_eq!(opened(r).await, Err(OpenError::StaleLease));
        let mut rest = Vec::new();
        shim.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        // The same lease can be attached again (a later attempt gets a new lease ID in practice).
        let again = attach_to(&bridge, lease_a(), 4, &[11434]);
        assert!(matches!(
            bridge.attach_listener(
                &Attach {
                    lease_id: lease_a(),
                    epoch: 5,
                    ports: &[11434],
                    dir: Path::new("/nonexistent.invalid"),
                    cancel: watch::channel(false).1,
                },
                PipeListener(mpsc::unbounded_channel().1),
                None,
            ),
            Err(AttachError::AlreadyAttached)
        ));
        drop(again);
    }

    /// SI-H2-7: the agent checks the port against the lease's own list before it sends anything; what a fake shim
    /// would answer does not matter.
    #[tokio::test]
    async fn a_port_the_service_does_not_list_is_refused_before_anything_is_sent() {
        let fx = fx();
        let mut fake = fx.container.idle(&fx.session).await;
        for port in [80u16, 11435, 8081, 22, 65535] {
            let r = fx.bridge.open_port(lease_a(), 3, port).await;
            assert_eq!(opened(r).await, Err(OpenError::PortNotExposed), "{port}");
        }
        assert!(untouched(&mut fake), "no header left the agent");
        assert_eq!(fx.session.idle_len(), 1);
        // A health check for such a port goes nowhere either.
        let e = probe(&fx.bridge, lease_a(), HealthCheck::Tcp { port: 80 })
            .await
            .unwrap_err();
        assert!(e.contains("not a port of the service"), "{e}");
        assert!(untouched(&mut fake));
    }

    /// §6.1: at most 64 concurrent port streams per lease; a health check is not one of them.
    #[tokio::test]
    async fn a_lease_has_at_most_64_port_streams() {
        let fx = fx();
        let mut open = Vec::new();
        for _ in 0..MAX_PORT_STREAMS_PER_LEASE {
            let mut shim = fx.container.idle(&fx.session).await;
            let (stream, _) = tokio::join!(fx.bridge.open_port(lease_a(), 3, 8080), answer(&mut shim, STATUS_OK));
            open.push((stream.unwrap(), shim));
        }
        assert_eq!(MAX_PORT_STREAMS_PER_LEASE, 64);
        let mut shim = fx.container.idle(&fx.session).await;
        let r = fx.bridge.open_port(lease_a(), 3, 8080).await;
        assert_eq!(opened(r).await, Err(OpenError::TooManyConnections));
        assert!(untouched(&mut shim), "nothing was sent for the refused stream");
        // The agent's own health check still goes through.
        let (check, _) = tokio::join!(
            probe(&fx.bridge, lease_a(), HealthCheck::Tcp { port: 8080 }),
            answer(&mut shim, STATUS_OK)
        );
        check.unwrap();
        // A stream that ends gives its slot back.
        open.pop();
        let mut shim = fx.container.idle(&fx.session).await;
        let (stream, _) = tokio::join!(fx.bridge.open_port(lease_a(), 3, 8080), answer(&mut shim, STATUS_OK));
        stream.unwrap();
        // Another lease has its own 64.
        let other = attach_to(&fx.bridge, lease_b(), 1, &[8080]);
        let mut shim = other.container.idle(&other.session).await;
        let (stream, _) = tokio::join!(fx.bridge.open_port(lease_b(), 1, 8080), answer(&mut shim, STATUS_OK));
        stream.unwrap();
    }

    /// §11.2 "A job that is not the shim": what connects to a lease's socket only ever receives connections meant
    /// for that lease's service.
    #[tokio::test(start_paused = true)]
    async fn a_lease_only_gets_connections_meant_for_its_own_service() {
        let a = fx();
        let b = attach_to(&a.bridge, lease_b(), 1, &[11434]);
        // A process of lease A's container fills A's socket; lease B's container has not dialed.
        let mut fakes = Vec::new();
        for _ in 0..MAX_IDLE {
            fakes.push(a.container.idle(&a.session).await);
        }
        let r = a.bridge.open_port(lease_b(), 1, 11434).await;
        assert_eq!(opened(r).await, Err(OpenError::NotReady));
        let check = probe(&a.bridge, lease_b(), HealthCheck::Tcp { port: 11434 }).await;
        assert!(check.unwrap_err().contains("no bridge connection"));
        assert!(
            fakes.iter_mut().all(untouched),
            "lease B's streams never reach lease A's container"
        );
        assert_eq!(b.session.idle_len(), 0);
    }

    // -----------------------------------------------------------------------------------------------------------
    // Health checks

    /// `tcp: true`: a status byte 0 passes, and nothing else is sent or read.
    #[tokio::test]
    async fn a_tcp_check_passes_on_status_0() {
        let fx = fx();
        let mut shim = fx.container.idle(&fx.session).await;
        let (check, header) = tokio::join!(
            probe(&fx.bridge, lease_a(), HealthCheck::Tcp { port: 8080 }),
            answer(&mut shim, STATUS_OK)
        );
        assert_eq!(check, Ok(()));
        assert_eq!(header, [1, 0x1f, 0x90]);
        let mut rest = Vec::new();
        shim.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "no request follows a tcp check");
        let mut shim = fx.container.idle(&fx.session).await;
        let (check, _) = tokio::join!(
            probe(&fx.bridge, lease_a(), HealthCheck::Tcp { port: 8080 }),
            answer(&mut shim, STATUS_REFUSED)
        );
        assert_eq!(check, Err("cannot connect to port 8080".to_string()));
    }

    /// Runs one `http_get` check against a service that answers `response` (and then keeps the connection open).
    /// Returns the check's result and the request the service received.
    async fn http_check_against(fx: &Fx, path: &str, response: &[u8]) -> (Result<(), String>, Vec<u8>) {
        let mut shim = fx.container.idle(&fx.session).await;
        let service = async {
            answer(&mut shim, STATUS_OK).await;
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                if shim.read(&mut byte).await.unwrap() == 0 {
                    break;
                }
                request.push(byte[0]);
            }
            shim.write_all(response).await.unwrap();
            (request, shim)
        };
        let (check, (request, _shim)) = tokio::join!(probe(&fx.bridge, lease_a(), http(11434, path)), service);
        (check, request)
    }

    /// §11.2: `GET <path> HTTP/1.1` with `Host: localhost` and `Connection: close`; any 2xx or 3xx passes.
    #[tokio::test]
    async fn an_http_check_sends_the_request_and_passes_on_2xx_and_3xx() {
        let fx = fx();
        let (check, request) = http_check_against(&fx, "/api/version", b"HTTP/1.1 200 OK\r\n").await;
        assert_eq!(check, Ok(()));
        assert_eq!(
            request,
            b"GET /api/version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        );
        for pass in [
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
            "HTTP/1.0 204 No Content\r\n",
            "HTTP/1.1 301 Moved Permanently\r\n",
            "HTTP/1.1 399 \r\n",
            "HTTP/1.1 200\r\n",
            "HTTP/1.9 299 reason with  spaces and \t tabs\r\n",
        ] {
            let (check, _) = http_check_against(&fx, "/", pass.as_bytes()).await;
            assert_eq!(check, Ok(()), "{pass:?}");
        }
        for (fail, code) in [
            ("HTTP/1.1 404 Not Found\r\n", 404),
            ("HTTP/1.1 500 Internal Server Error\r\n", 500),
            ("HTTP/1.1 503 Service Unavailable\r\n", 503),
            ("HTTP/1.1 199 Early\r\n", 199),
            ("HTTP/1.1 400 Bad Request\r\n", 400),
            ("HTTP/1.1 101 Switching Protocols\r\n", 101),
            ("HTTP/1.1 000 \r\n", 0),
        ] {
            let (check, _) = http_check_against(&fx, "/", fail.as_bytes()).await;
            assert_eq!(check, Err(format!("HTTP {code}")), "{fail:?}");
        }
    }

    /// §11.2: a line that is not `HTTP/1.x <3 digits> …` ending in CRLF fails the check.
    #[tokio::test]
    async fn a_response_that_is_not_an_http_1_status_line_fails() {
        let fx = fx();
        for bad in [
            "HTTP/2 200 OK\r\n",
            "HTTP/2.0 200 OK\r\n",
            "HTTP/1.1 200 OK\n",
            "HTTP/1.1 200\n",
            "http/1.1 200 OK\r\n",
            "HTTP/1.1 20 OK\r\n",
            "HTTP/1.1 2000 OK\r\n",
            "HTTP/1.1  200 OK\r\n",
            "HTTP/1.1 200OK\r\n",
            "HTTP/1.1 2x0 OK\r\n",
            "HTTP/1.1 +20 OK\r\n",
            "HTTP/1.1\t200 OK\r\n",
            "HTTP/1. 200 OK\r\n",
            "HTTP/1.11 200 OK\r\n",
            "HTTP/1.x 200 OK\r\n",
            " HTTP/1.1 200 OK\r\n",
            "ICY 200 OK\r\n",
            "200 OK\r\n",
            "\r\n",
            "\n",
            "HTTP/1.1 200 O\rK\r\n",
            "SSH-2.0-OpenSSH\r\n",
        ] {
            let (check, _) = http_check_against(&fx, "/", bad.as_bytes()).await;
            let e = check.expect_err(bad);
            assert!(e.contains("status line"), "{bad:?}: {e}");
        }
        // The details are the agent's own words: nothing of the response is echoed.
        let (check, _) = http_check_against(&fx, "/", b"\x1b[31mHTTP/1.1 200 pwned\r\n").await;
        let e = check.unwrap_err();
        assert!(!e.contains("pwned") && !e.contains('\x1b'), "{e}");
        let (check, _) = http_check_against(&fx, "/", b"HTTP/1.1 503 \x1b[31m<script>\r\n").await;
        assert_eq!(check, Err("HTTP 503".to_string()));
    }

    /// SI-H2-7: an endless status line fails the check, and the agent reads no more than 1 KiB of it.
    #[tokio::test]
    async fn an_endless_status_line_fails_and_no_more_than_1_kib_is_read() {
        let fx = fx();
        let mut shim = fx.container.idle(&fx.session).await;
        let endless = async {
            answer(&mut shim, STATUS_OK).await;
            // Until the agent closes the connection.
            while shim.write_all(&[b'A'; 4096]).await.is_ok() {}
        };
        let (check, ()) = tokio::join!(probe(&fx.bridge, lease_a(), http(11434, "/")), endless);
        let e = check.unwrap_err();
        assert!(e.contains("longer than 1 KiB"), "{e}");
        // The status byte of the bridge, then at most 1 KiB of the response.
        assert_eq!(fx.container.agent_read.load(Ordering::SeqCst), 1 + MAX_STATUS_LINE);
        assert_eq!(MAX_STATUS_LINE, 1024);
        // The same with a line that looks right at first.
        let fx = self::fx();
        let mut shim = fx.container.idle(&fx.session).await;
        let endless = async {
            answer(&mut shim, STATUS_OK).await;
            let _ = shim.write_all(b"HTTP/1.1 200 ").await;
            while shim.write_all(&[b'k'; 4096]).await.is_ok() {}
        };
        let (check, ()) = tokio::join!(probe(&fx.bridge, lease_a(), http(11434, "/")), endless);
        assert!(check.unwrap_err().contains("longer than 1 KiB"));
        assert_eq!(fx.container.agent_read.load(Ordering::SeqCst), 1 + MAX_STATUS_LINE);
    }

    /// SI-H2-7: an endless body does not matter: the check passes (or fails) on the status line alone, and the
    /// agent reads no more than 1 KiB.
    #[tokio::test]
    async fn an_endless_body_is_never_read_the_status_line_alone_decides() {
        for (status_line, expected) in [
            ("HTTP/1.1 200 OK\r\n", Ok(())),
            ("HTTP/1.1 503 Busy\r\n", Err("HTTP 503".to_string())),
        ] {
            let fx = fx();
            let mut shim = fx.container.idle(&fx.session).await;
            let endless = async {
                answer(&mut shim, STATUS_OK).await;
                let _ = shim.write_all(status_line.as_bytes()).await;
                let _ = shim.write_all(b"Content-Type: text/plain\r\n\r\n").await;
                while shim.write_all(&[b'z'; 4096]).await.is_ok() {}
            };
            let (check, ()) = tokio::join!(probe(&fx.bridge, lease_a(), http(11434, "/")), endless);
            assert_eq!(check, expected);
            let read = fx.container.agent_read.load(Ordering::SeqCst);
            assert!(read <= 1 + MAX_STATUS_LINE, "the agent read {read} bytes");
        }
    }

    /// The limit is exact: a status line of 1 KiB with its CRLF passes, one byte more fails.
    #[tokio::test]
    async fn a_status_line_of_exactly_1_kib_passes_and_one_byte_more_fails() {
        let fx = fx();
        let line = |len: usize| {
            let head = "HTTP/1.1 200 ";
            format!("{head}{}\r\n", "r".repeat(len - head.len() - 2))
        };
        assert_eq!(line(MAX_STATUS_LINE).len(), 1024);
        let (check, _) = http_check_against(&fx, "/", line(MAX_STATUS_LINE).as_bytes()).await;
        assert_eq!(check, Ok(()));
        let (check, _) = http_check_against(&fx, "/", line(MAX_STATUS_LINE + 1).as_bytes()).await;
        assert!(check.unwrap_err().contains("longer than 1 KiB"));
    }

    #[tokio::test]
    async fn a_response_that_ends_before_its_status_line_fails() {
        let fx = fx();
        for partial in ["", "HTTP/1.1 200 OK", "HTTP/1.1 200 OK\r"] {
            let mut shim = fx.container.idle(&fx.session).await;
            let service = async {
                answer(&mut shim, STATUS_OK).await;
                shim.write_all(partial.as_bytes()).await.unwrap();
                shim.shutdown().await.unwrap();
                shim
            };
            let (check, _shim) = tokio::join!(probe(&fx.bridge, lease_a(), http(11434, "/")), service);
            let e = check.expect_err(partial);
            assert!(e.contains("before a status line"), "{partial:?}: {e}");
        }
    }

    /// A path that could end the request line early is never written (the job validation refuses CR, LF and NUL;
    /// this is the second lock).
    #[tokio::test]
    async fn a_path_that_cannot_go_into_a_request_line_is_never_sent() {
        let fx = fx();
        for path in [
            "/a b",
            "/a\r\nX-Injected: 1",
            "/a\n",
            "/a\0",
            "/a\tb",
            "relative",
            "",
            "/\x7f",
        ] {
            let mut shim = fx.container.idle(&fx.session).await;
            let check = probe(&fx.bridge, lease_a(), http(11434, path)).await;
            let e = check.expect_err(path);
            assert!(e.contains("request line"), "{path:?}: {e}");
            assert!(untouched(&mut shim), "{path:?}: not even a header was sent");
            drop(shim);
        }
    }

    #[tokio::test]
    async fn a_check_of_a_lease_that_is_not_attached_fails() {
        let fx = fx();
        let e = probe(&fx.bridge, lease_b(), HealthCheck::Tcp { port: 11434 })
            .await
            .unwrap_err();
        assert_eq!(e, "the lease has no ingress bridge");
    }

    /// A check that finds no bridge connection fails with the agent's own words.
    #[tokio::test(start_paused = true)]
    async fn a_check_without_a_bridge_connection_fails() {
        let fx = fx();
        let e = probe(&fx.bridge, lease_a(), http(11434, "/")).await.unwrap_err();
        assert!(e.contains("no bridge connection"), "{e}");
    }

    // -----------------------------------------------------------------------------------------------------------
    // The files: ports.json and the socket

    #[test]
    fn the_ports_file_is_what_the_shim_reads() {
        assert_eq!(ports_json(&[11434]), r#"{"ports":[11434]}"#);
        assert_eq!(ports_json(&[1, 8080, 65535]), r#"{"ports":[1,8080,65535]}"#);
        let dir = tempfile::tempdir().unwrap();
        write_ports_file(dir.path(), &[11434, 8080]).unwrap();
        let path = dir.path().join(PORTS_FILE);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"ports":[11434,8080]}"#);
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o644);
        // Never overwritten.
        assert_eq!(
            write_ports_file(dir.path(), &[80]).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"ports":[11434,8080]}"#);
    }

    #[test]
    fn ports_that_are_not_1_to_8_distinct_ports_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [&[][..], &[0], &[80, 0], &[80, 80], &[1, 2, 3, 4, 5, 6, 7, 8, 9]] {
            assert!(!valid_ports(bad), "{bad:?}");
            assert_eq!(
                write_ports_file(dir.path(), bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert!(!dir.path().join(PORTS_FILE).exists());
        assert!(valid_ports(&[1, 2, 3, 4, 5, 6, 7, 8]));
        // From a service block: every port must fit a u16.
        let service = |ports: serde_json::Value| -> ServiceSpec {
            serde_json::from_value(serde_json::json!({ "ports": ports })).unwrap()
        };
        assert_eq!(
            service_ports(&service(
                serde_json::json!([{"port": 11434, "name": "api"}, {"port": 8080, "name": "web"}])
            )),
            Some(vec![11434, 8080])
        );
        assert_eq!(
            service_ports(&service(serde_json::json!([{"port": 70000, "name": "api"}]))),
            None
        );
        assert_eq!(
            service_ports(&service(serde_json::json!([{"port": 0, "name": "api"}]))),
            None
        );
        assert_eq!(service_ports(&service(serde_json::json!([]))), None);
    }

    /// A symlink planted where the ports file goes is refused, not written through.
    #[test]
    fn a_symlink_where_the_ports_file_goes_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, dir.path().join(PORTS_FILE)).unwrap();
        assert!(write_ports_file(dir.path(), &[80]).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        // A dangling link is not followed to create its target either.
        let dir = tempfile::tempdir().unwrap();
        symlink(outside.path().join("created"), dir.path().join(PORTS_FILE)).unwrap();
        assert!(write_ports_file(dir.path(), &[80]).is_err());
        assert!(!outside.path().join("created").exists());
    }

    /// A job's `p2pc/` directory as the driver makes it (0755, the agent's), in a private parent.
    fn p2pc_dir() -> (tempfile::TempDir, PathBuf) {
        let job = tempfile::tempdir().unwrap();
        let dir = job.path().join("p2pc");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        (job, dir)
    }

    /// Whether this environment lets a test make unix sockets at all (some build sandboxes do not).
    fn unix_sockets_allowed() -> bool {
        let forbidden = std::os::unix::net::UnixListener::bind("/nonexistent.invalid/probe")
            .is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied);
        if forbidden {
            eprintln!("SKIPPED: this environment forbids unix sockets");
        }
        !forbidden
    }

    fn attach_in(bridge: &IngressBridge, dir: &Path) -> Result<IngressSession, AttachError> {
        bridge.attach(Attach {
            lease_id: lease_a(),
            epoch: 3,
            ports: &[11434],
            dir,
            cancel: watch::channel(false).1,
        })
    }

    /// A unix listener that stands for a host socket the agent must never reach (Podman's, say).
    fn decoy(dir: &Path) -> (std::os::unix::net::UnixListener, PathBuf) {
        let path = dir.join("host.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        (listener, path)
    }

    fn nobody_connected(decoy: &std::os::unix::net::UnixListener) -> bool {
        decoy.accept().is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock)
    }

    /// The real socket: 0600 in the job's `p2pc/`, served for port streams and health checks, removed on detach.
    #[tokio::test]
    async fn the_socket_is_0600_served_and_removed_with_the_lease() {
        if !unix_sockets_allowed() {
            return;
        }
        let (_job, dir) = p2pc_dir();
        let bridge = IngressBridge::new();
        let session = attach_in(&bridge, &dir).unwrap();
        let socket = dir.join(SOCKET_NAME);
        let meta = std::fs::symlink_metadata(&socket).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "no staging directory is left"
        );

        // The shim's side: it connects, the agent never does.
        let mut shim = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let (stream, header) = tokio::join!(bridge.open_port(lease_a(), 3, 11434), async {
            let mut header = [0u8; 3];
            shim.read_exact(&mut header).await.unwrap();
            shim.write_all(&[STATUS_OK]).await.unwrap();
            header
        });
        assert_eq!(header, [1, 0x2c, 0xaa]);
        let mut stream = stream.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        shim.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");

        // A second lease in the same directory is refused: the socket is never replaced.
        assert!(matches!(attach_in(&bridge, &dir), Err(AttachError::AlreadyAttached)));
        drop(session);
        assert!(std::fs::symlink_metadata(&socket).is_err(), "removed with the lease");
        let r = bridge.open_port(lease_a(), 3, 11434).await;
        assert_eq!(opened(r).await, Err(OpenError::StaleLease));
    }

    /// SI-H2-7: a symlink planted where the socket goes. The agent refuses to attach: it neither follows the link,
    /// nor replaces it, nor connects to what it points at. The refusal comes before any socket is made, so this
    /// runs everywhere; where unix sockets are allowed, the link also points at a listening "host socket", which
    /// must see no connection.
    #[tokio::test]
    async fn a_symlink_planted_where_the_socket_goes_is_refused() {
        let host = tempfile::tempdir().unwrap();
        let host_file = host.path().join("host-file");
        std::fs::write(&host_file, b"untouched").unwrap();
        let decoy = unix_sockets_allowed().then(|| decoy(host.path()));
        let mut targets = vec![host_file.clone(), host.path().join("dangling")];
        targets.extend(decoy.as_ref().map(|(_, path)| path.clone()));
        for points_at in targets {
            let (_job, dir) = p2pc_dir();
            let link = dir.join(SOCKET_NAME);
            symlink(&points_at, &link).unwrap();
            let bridge = IngressBridge::new();
            let e = attach_in(&bridge, &dir).unwrap_err();
            assert!(matches!(e, AttachError::Refused(_)), "{e}");
            assert!(e.to_string().contains("already exists"), "{e}");
            assert_eq!(
                std::fs::read_link(&link).unwrap(),
                points_at,
                "the link is left as it was"
            );
            assert!(!host.path().join("dangling").exists());
            // Nothing is attached, so a stream or a check for the lease goes nowhere.
            let r = bridge.open_port(lease_a(), 3, 11434).await;
            assert_eq!(opened(r).await, Err(OpenError::StaleLease));
            let check = probe(&bridge, lease_a(), HealthCheck::Tcp { port: 11434 }).await;
            assert_eq!(check, Err("the lease has no ingress bridge".to_string()));
        }
        assert_eq!(std::fs::read(&host_file).unwrap(), b"untouched");
        if let Some((decoy, _)) = &decoy {
            assert!(nobody_connected(decoy), "the agent connected to a host socket");
        }

        // A directory others could write to (where a container could swap the socket) is refused too.
        let (_job, dir) = p2pc_dir();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = attach_in(&IngressBridge::new(), &dir).unwrap_err();
        assert!(e.to_string().contains("unsafe socket directory"), "{e}");
        assert!(!dir.join(SOCKET_NAME).exists());
    }

    /// SI-H2-7: symlinks planted where a socket could be, all over the job's directories, while the bridge is used.
    /// The agent only ever accepts on its own socket: the host socket behind the links sees no connection.
    #[tokio::test]
    async fn symlinks_planted_in_the_job_directories_are_never_connected() {
        if !unix_sockets_allowed() {
            return;
        }
        let host = tempfile::tempdir().unwrap();
        let (decoy, decoy_path) = decoy(host.path());
        let job = tempfile::tempdir().unwrap();
        let dir = job.path().join("p2pc");
        for sub in ["p2pc", "outputs", "inputs"] {
            std::fs::create_dir(job.path().join(sub)).unwrap();
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        // What a container could plant in the directory it can write, and beside the real socket if it ever could.
        for planted in [
            "outputs/ingress.sock",
            "outputs/egress.sock",
            "outputs/podman.sock",
            "inputs/ingress.sock",
            "ingress.sock",
            "p2pc/ingress.sock.1",
            "p2pc/egress.sock",
        ] {
            symlink(&decoy_path, job.path().join(planted)).unwrap();
        }
        let bridge = IngressBridge::new();
        let session = attach_in(&bridge, &dir).unwrap();
        // The target of a check names the job directory; the bridge finds the lease by its ID, not by a path.
        let probe_target = ProbeTarget {
            lease_id: lease_a(),
            job_dir: job.path().to_path_buf(),
        };
        let mut shim = tokio::net::UnixStream::connect(dir.join(SOCKET_NAME)).await.unwrap();
        let shim_answers = async {
            let mut header = [0u8; 3];
            shim.read_exact(&mut header).await.unwrap();
            shim.write_all(&[STATUS_OK]).await.unwrap();
            shim.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
        };
        let health = http(11434, "/healthz");
        let (check, ()) = tokio::join!(bridge.check(&probe_target, &health), shim_answers);
        assert_eq!(check, Ok(()));
        let mut shim = tokio::net::UnixStream::connect(dir.join(SOCKET_NAME)).await.unwrap();
        let (stream, ()) = tokio::join!(bridge.open_port(lease_a(), 3, 11434), async {
            let mut header = [0u8; 3];
            shim.read_exact(&mut header).await.unwrap();
            shim.write_all(&[STATUS_OK]).await.unwrap();
        });
        stream.unwrap();
        drop(session);
        assert!(nobody_connected(&decoy), "the agent connected to a host socket");
        // Detaching removed the agent's own socket and nothing else.
        assert!(std::fs::symlink_metadata(job.path().join("outputs/ingress.sock")).is_ok());
        assert!(decoy_path.exists());
    }

    /// SI-H2-7, structurally: this module accepts connections and never makes one. It has no `connect` call at
    /// all, so no path, planted or not, can ever be dialed from here.
    #[test]
    fn the_agent_side_of_the_bridge_never_connects() {
        let source = include_str!("ingress.rs");
        let code = source.split("#[cfg(test)]").next().unwrap();
        let calls: Vec<&str> = code
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && l.contains("connect("))
            .collect();
        assert!(calls.is_empty(), "{calls:?}");
    }
}
