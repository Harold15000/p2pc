// SPDX-License-Identifier: Apache-2.0

//! The per-job egress proxy (spec §9, SI-3/SI-4/SI-5, `CONTRIBUTING.md` hard rule 2).
//!
//! A job runs with `--network=none`. Its only way out is this HTTP proxy, which listens on a **unix socket** in the
//! job's `p2pc/` directory; the shim bridges `127.0.0.1:3128` inside the container to it (T08). On the WSL2
//! profile all distros share one network namespace (§9.0), so this proxy is the only thing between a job and the
//! owner's LAN, the host's services and the tailnet.
//!
//! For every request the proxy, in this order:
//! 1. parses the host and refuses **any** IP literal ([`request::is_ip_literal`]);
//! 2. checks the name with [`p2pc_proto::validate::domain_allowed`] (whole labels);
//! 3. checks the port (default `{80, 443}`);
//! 4. resolves the name **once**, with a timeout;
//! 5. drops every address in the deny set ([`deny::check_addr`]): the static table, plus the host's own addresses
//!    and interface networks, the /56 around every global-unicast IPv6 address, the on-link routes of both families
//!    (no gateway; never the default route, and nothing wider than /8 for IPv4 or /32 for IPv6) and the node's
//!    public addresses ([`deny::host_deny_set`]); and, while the egress gate is not open
//!    ([`p2pc_net::EgressGate`]), every IPv4 address too, because the node's public IPv4 may be missing from the set
//!    (hairpin NAT, T10f). IPv6 stays allowed. When that leaves no address the verdict is `egress-unavailable`;
//!    the gate is read live, once per request, before the deny set;
//! 6. connects to **exactly one** surviving address, the first, so DNS rebinding cannot change the destination
//!    after the check.
//!
//! The proxy records the destination host, port, byte counts and verdict. It never records or logs payloads.

mod body;
mod conn;
pub mod deny;
pub mod net;
mod request;
#[cfg(test)]
mod tests;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use p2pc_net::EgressGate;
use rustix::fs::{AtFlags, Mode, OFlags};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;

pub use deny::{Cidr, DEFAULT_LAN_IPV6_PREFIX, DENY_TABLE, DenyRange, HostNets};
pub use net::{
    BoxFuture, Connector, HostNetworks, Resolver, SystemHostNetworks, SystemResolver, TcpConnector, UpstreamStream,
};

/// Mode of the proxy's socket file (spec §9: the socket directory is mounted with `:U`, so the container's mapped
/// root owns it, and nobody else needs access).
pub const SOCKET_MODE: u32 = 0o600;

/// Log lines for the same destination (one for allowed connections, one for refusals) are written at most once
/// per this period. The rest are aggregated into the next line, and counted.
pub const LOG_PERIOD: Duration = Duration::from_secs(60);

/// Most destinations each log limiter remembers.
const LOG_MAX_KEYS: usize = 1024;

/// Most distinct excluded routes warned about per proxy.
const MAX_WARNED_ROUTES: usize = 64;

/// Limits of one proxy (one job).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Concurrent client connections. Extra connections get `503` and are closed.
    pub max_connections: usize,
    /// Largest request head, in bytes. Larger → `400`.
    pub max_header_bytes: usize,
    /// The request head must arrive within this time (slowloris), and a tunnel with no traffic in either direction
    /// for this long is closed.
    pub idle_timeout: Duration,
    /// Timeout for the single DNS lookup.
    pub resolve_timeout: Duration,
    /// Timeout for the outbound TCP connect.
    pub connect_timeout: Duration,
    /// Optional cap on the bytes relayed in both directions, over the proxy's whole life.
    pub max_total_bytes: Option<u64>,
    /// Most records kept. Later connections are still counted in [`Stats`] but not recorded.
    pub max_records: usize,
    /// DNS lookups in flight at once. Waiting for a slot counts against `resolve_timeout`.
    pub max_concurrent_lookups: usize,
}

/// Most concurrent connections or DNS lookups [`Limits::validate`] accepts (`Semaphore::MAX_PERMITS` panics).
pub const MAX_CONCURRENCY: usize = 65_536;
/// Largest request head [`Limits::validate`] accepts: 1 MiB.
pub const MAX_HEAD_BYTES_LIMIT: usize = 1024 * 1024;
/// Longest timeout [`Limits::validate`] accepts: one day. Longer is never useful for a job, and `Instant + Duration`
/// overflows near `Duration::MAX`.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
/// Most records [`Limits::validate`] accepts.
pub const MAX_RECORDS_LIMIT: usize = 1_000_000;

impl Limits {
    /// Checks that every limit is in a range the proxy handles without panicking.
    ///
    /// # Errors
    /// [`StartError::InvalidLimits`], naming the first field out of range.
    pub fn validate(&self) -> Result<(), StartError> {
        let bad = |field: &str, range: String| Err(StartError::InvalidLimits(format!("{field} must be {range}")));
        for (field, v, max) in [
            ("max_connections", self.max_connections, MAX_CONCURRENCY),
            ("max_concurrent_lookups", self.max_concurrent_lookups, MAX_CONCURRENCY),
            ("max_header_bytes", self.max_header_bytes, MAX_HEAD_BYTES_LIMIT),
        ] {
            if !(1..=max).contains(&v) {
                return bad(field, format!("between 1 and {max}"));
            }
        }
        for (field, v) in [
            ("idle_timeout", self.idle_timeout),
            ("resolve_timeout", self.resolve_timeout),
            ("connect_timeout", self.connect_timeout),
        ] {
            if v.is_zero() || v > MAX_TIMEOUT {
                return bad(field, format!("between 1 ms and {} s", MAX_TIMEOUT.as_secs()));
            }
        }
        if self.max_records > MAX_RECORDS_LIMIT {
            return bad("max_records", format!("at most {MAX_RECORDS_LIMIT}"));
        }
        Ok(())
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_header_bytes: 16 * 1024,
            idle_timeout: Duration::from_secs(120),
            resolve_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(10),
            max_total_bytes: None,
            max_records: 4096,
            max_concurrent_lookups: 8,
        }
    }
}

/// What the proxy may let through, and how it reaches the outside world.
#[derive(Debug, Clone)]
pub struct Policy {
    /// The job's `egress.allow` list. Matched with [`p2pc_proto::validate::domain_allowed`].
    pub allow: Vec<String>,
    /// Allowed destination ports.
    pub ports: BTreeSet<u16>,
    /// DNS.
    pub resolver: Arc<dyn Resolver>,
    /// The host's own addresses and interface networks, all refused.
    pub host_networks: Arc<dyn HostNetworks>,
    /// Outbound TCP.
    pub connector: Arc<dyn Connector>,
    /// The prefix length of the "LAN" around each global-unicast IPv6 address of the host (default 56). See
    /// [`deny::host_deny_set`].
    pub lan_ipv6_prefix: u8,
    /// The node's own public addresses, as observed by iroh (QUIC address discovery). It is a **live** source:
    /// the current value is read on every request, like [`HostNetworks`], so an address change applies to the next
    /// request. T05b feeds it from iroh's observed addresses. The addresses are refused, which stops hairpin NAT
    /// into port-forwarded LAN services (a NAS on 443, say).
    ///
    /// **An empty list means no hairpin protection.** The proxy cannot know the node's public addresses by itself.
    pub public_addrs: watch::Receiver<Vec<IpAddr>>,
    /// The egress gate (T10f): not open while the node's public IPv4 may be missing from `public_addrs` (IPv4 came up
    /// after the gate opened on IPv6, or the network changed). A live source, read on every request: while it is
    /// not open, the proxy refuses **IPv4** destinations ([`Verdict::EgressUnavailable`]) and still serves IPv6 ones.
    pub egress_ready: watch::Receiver<EgressGate>,
    /// Limits.
    pub limits: Limits,
}

impl Policy {
    /// The default ports.
    pub const DEFAULT_PORTS: [u16; 2] = [80, 443];

    /// A policy for `allow` with the system resolver, interfaces and TCP, ports `{80, 443}`, a /56 IPv6 LAN, the
    /// given live sources of public addresses and of the egress gate, and default limits.
    #[must_use]
    pub fn system(
        allow: Vec<String>,
        public_addrs: watch::Receiver<Vec<IpAddr>>,
        egress_ready: watch::Receiver<EgressGate>,
    ) -> Self {
        Self {
            allow,
            ports: Self::DEFAULT_PORTS.into_iter().collect(),
            resolver: Arc::new(SystemResolver),
            host_networks: Arc::new(SystemHostNetworks),
            connector: Arc::new(TcpConnector),
            lan_ipv6_prefix: DEFAULT_LAN_IPV6_PREFIX,
            public_addrs,
            egress_ready,
            limits: Limits::default(),
        }
    }
}

/// Who owns the socket file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SocketOptions {
    /// `(uid, gid)` to `chown` the socket to, if not the agent's own user. T08 mounts the directory with `:U`, so
    /// Podman sets the owner to the container's mapped root itself and passes `None`.
    pub owner: Option<(u32, u32)>,
}

/// The outcome of one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Connected and relayed.
    Allowed,
    /// The host is an IP literal.
    IpLiteral,
    /// The host is not in the allowlist.
    DeniedDomain,
    /// The port is not allowed.
    DeniedPort,
    /// Every resolved address is in the deny set (or the host's interfaces could not be listed).
    DeniedAddress,
    /// The byte cap is used up.
    ByteCap,
    /// Every resolved address is IPv4 (or the rest are denied) and the egress gate is closed: the node's public IPv4
    /// may be missing from the deny list, so an IPv4 connection could hairpin into the LAN (T10f).
    EgressUnavailable,
    /// The name did not resolve.
    ResolveFailed,
    /// The lookup timed out.
    ResolveTimeout,
    /// The connection to the checked address failed.
    ConnectFailed,
    /// The connection to the checked address timed out.
    ConnectTimeout,
    /// The upstream was connected, but the client was gone before `200 Connection Established` could be written
    /// (or the proxy shut down first). Nothing was relayed.
    ClientGone,
}

impl Verdict {
    /// The value of the `X-P2PC-Egress` response header.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Verdict::Allowed => "allowed",
            Verdict::IpLiteral => "ip-literal",
            Verdict::DeniedDomain => "denied-domain",
            Verdict::DeniedPort => "denied-port",
            Verdict::DeniedAddress => "denied-address",
            Verdict::ByteCap => "byte-cap",
            Verdict::EgressUnavailable => "egress-unavailable",
            Verdict::ResolveFailed => "resolve-failed",
            Verdict::ResolveTimeout => "resolve-timeout",
            Verdict::ConnectFailed => "connect-failed",
            Verdict::ConnectTimeout => "connect-timeout",
            Verdict::ClientGone => "client-gone",
        }
    }

    /// The HTTP status sent to the client for a refusal.
    #[must_use]
    pub fn status(self) -> &'static str {
        match self {
            Verdict::Allowed => "200 Connection Established",
            Verdict::IpLiteral
            | Verdict::DeniedDomain
            | Verdict::DeniedPort
            | Verdict::DeniedAddress
            | Verdict::ByteCap => "403 Forbidden",
            Verdict::EgressUnavailable => "503 Service Unavailable",
            Verdict::ResolveFailed | Verdict::ConnectFailed => "502 Bad Gateway",
            Verdict::ResolveTimeout | Verdict::ConnectTimeout => "504 Gateway Timeout",
            // Never sent: there is no client left to send it to.
            Verdict::ClientGone => "499 Client Closed Request",
        }
    }
}

/// One proxied request. There is deliberately no field for payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The requested host, as the client wrote it (at most 255 bytes).
    pub host: String,
    /// The requested port.
    pub port: u16,
    /// Bytes sent upstream (for plain HTTP this includes the rewritten request head).
    pub bytes_up: u64,
    /// Bytes sent back to the client from upstream.
    pub bytes_down: u64,
    /// The outcome.
    pub verdict: Verdict,
}

/// Counters over the proxy's life.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Bytes sent upstream.
    pub bytes_up: u64,
    /// Bytes sent back to clients.
    pub bytes_down: u64,
    /// Accepted connections.
    pub connections: u64,
    /// Connections turned away because `max_connections` were open.
    pub rejected_busy: u64,
    /// Requests answered with `400`.
    pub bad_requests: u64,
    /// Records not kept because `max_records` was reached.
    pub records_dropped: u64,
    /// Requests refused before anything was relayed (the `403`, `502` and `504` verdicts, including a
    /// `ByteCap` refusal of a new request).
    pub refusals: u64,
    /// Connected requests whose client was gone before `200 Connection Established` (verdict `ClientGone`).
    pub client_gone: u64,
    /// Tunnels and plain-HTTP bodies cut short by the byte cap (verdict `ByteCap` on a connected request).
    pub byte_cap_cuts: u64,
    /// Refusal log lines not written because the same destination was logged less than a minute before.
    pub refusal_logs_suppressed: u64,
    /// Allowed-connection log lines not written for the same reason (they are aggregated into the next line).
    pub allowed_logs_suppressed: u64,
}

/// What a [`LogLimiter`] held back for one destination since its last line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Held {
    /// Events not logged.
    pub(crate) events: u64,
    /// Their bytes sent upstream.
    pub(crate) bytes_up: u64,
    /// Their bytes sent back.
    pub(crate) bytes_down: u64,
}

/// Rate-limits a log per destination `(host, port)`: at most one line per [`LOG_PERIOD`]. The events in between
/// are aggregated and reported by the next line for that destination, or by [`LogLimiter::drain`] at shutdown.
/// The exact data is always in `records()` and `stats()`; only the log is aggregated.
#[derive(Debug)]
pub(crate) struct LogLimiter {
    /// What is logged: `"allowed"` or `"refused"`.
    kind: &'static str,
    seen: Mutex<HashMap<(String, u16), (Instant, Held)>>,
}

impl LogLimiter {
    pub(crate) fn new(kind: &'static str) -> Self {
        Self {
            kind,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// The line for events that were held back.
    fn emit_held(&self, host: &str, port: u16, held: Held) {
        tracing::info!(
            kind = self.kind,
            %host,
            port,
            held_events = held.events,
            held_bytes_up = held.bytes_up,
            held_bytes_down = held.bytes_down,
            "egress (aggregated)"
        );
    }

    /// `Some(held)` if a line should be written now, `held` being what was aggregated since the last line. `None`
    /// if this event is held back (and added to the aggregate).
    pub(crate) fn admit(&self, host: &str, port: u16, bytes_up: u64, bytes_down: u64, now: Instant) -> Option<Held> {
        let Ok(mut seen) = self.seen.lock() else {
            return None;
        };
        let key = (host.to_ascii_lowercase(), port);
        if let Some((last, held)) = seen.get_mut(&key) {
            if now.saturating_duration_since(*last) < LOG_PERIOD {
                held.events += 1;
                held.bytes_up = held.bytes_up.saturating_add(bytes_up);
                held.bytes_down = held.bytes_down.saturating_add(bytes_down);
                return None;
            }
            let out = *held;
            *last = now;
            *held = Held::default();
            return Some(out);
        }
        if seen.len() >= LOG_MAX_KEYS {
            // Evict the expired destinations; what they still held back is logged now, not lost.
            seen.retain(|(host, port), (last, held)| {
                let keep = now.saturating_duration_since(*last) < LOG_PERIOD;
                if !keep && held.events > 0 {
                    self.emit_held(host, *port, *held);
                }
                keep
            });
            if seen.len() >= LOG_MAX_KEYS {
                // Flooded with distinct destinations: count, do not log.
                return None;
            }
        }
        seen.insert(key, (now, Held::default()));
        Some(Held::default())
    }

    /// At shutdown: logs what every destination still holds back, and forgets them. Returns how many lines it
    /// wrote.
    pub(crate) fn drain(&self) -> usize {
        let Ok(mut seen) = self.seen.lock() else {
            return 0;
        };
        let mut lines = 0;
        for ((host, port), (_, held)) in seen.drain() {
            if held.events > 0 {
                self.emit_held(&host, port, held);
                lines += 1;
            }
        }
        lines
    }
}

/// Why the proxy could not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// The socket path has no parent directory.
    #[error("the socket path has no parent directory")]
    NoParent,
    /// The parent is not a directory, is writable by everyone, or is not owned by the agent.
    #[error("unsafe socket directory: {0}")]
    UnsafeDirectory(&'static str),
    /// Something already exists at the socket path.
    #[error("the socket path already exists")]
    AlreadyExists,
    /// A [`Limits`] value is out of range.
    #[error("invalid egress limits: {0}")]
    InvalidLimits(String),
    /// An I/O error.
    #[error("egress socket: {0}")]
    Io(#[from] io::Error),
}

/// State shared by the accept loop and the connections.
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) policy: Policy,
    pub(crate) bytes_up: AtomicU64,
    pub(crate) bytes_down: AtomicU64,
    /// Bytes counted against `max_total_bytes` (reserved before they are written).
    pub(crate) cap_used: AtomicU64,
    pub(crate) connections: AtomicU64,
    pub(crate) rejected_busy: AtomicU64,
    pub(crate) bad_requests: AtomicU64,
    pub(crate) records_dropped: AtomicU64,
    pub(crate) records: Mutex<Vec<Record>>,
    pub(crate) refusals: AtomicU64,
    pub(crate) client_gone: AtomicU64,
    pub(crate) byte_cap_cuts: AtomicU64,
    /// Default and very wide on-link routes already warned about (bounded).
    pub(crate) warned_routes: Mutex<HashSet<Cidr>>,
    pub(crate) refusal_logs_suppressed: AtomicU64,
    pub(crate) allowed_logs_suppressed: AtomicU64,
    pub(crate) refusal_log: LogLimiter,
    pub(crate) allowed_log: LogLimiter,
    /// Slots for DNS lookups in flight.
    pub(crate) dns_slots: Arc<Semaphore>,
}

impl Shared {
    pub(crate) fn new(policy: Policy) -> Self {
        Self {
            refusals: AtomicU64::new(0),
            client_gone: AtomicU64::new(0),
            byte_cap_cuts: AtomicU64::new(0),
            warned_routes: Mutex::new(HashSet::new()),
            refusal_logs_suppressed: AtomicU64::new(0),
            allowed_logs_suppressed: AtomicU64::new(0),
            refusal_log: LogLimiter::new("refused"),
            allowed_log: LogLimiter::new("allowed"),
            dns_slots: Arc::new(Semaphore::new(
                policy.limits.max_concurrent_lookups.clamp(1, Semaphore::MAX_PERMITS),
            )),
            policy,
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            cap_used: AtomicU64::new(0),
            connections: AtomicU64::new(0),
            rejected_busy: AtomicU64::new(0),
            bad_requests: AtomicU64::new(0),
            records_dropped: AtomicU64::new(0),
            records: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn stats(&self) -> Stats {
        Stats {
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            connections: self.connections.load(Ordering::Relaxed),
            rejected_busy: self.rejected_busy.load(Ordering::Relaxed),
            bad_requests: self.bad_requests.load(Ordering::Relaxed),
            records_dropped: self.records_dropped.load(Ordering::Relaxed),
            refusals: self.refusals.load(Ordering::Relaxed),
            client_gone: self.client_gone.load(Ordering::Relaxed),
            byte_cap_cuts: self.byte_cap_cuts.load(Ordering::Relaxed),
            refusal_logs_suppressed: self.refusal_logs_suppressed.load(Ordering::Relaxed),
            allowed_logs_suppressed: self.allowed_logs_suppressed.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn records(&self) -> Vec<Record> {
        self.records.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// Logs a default or very wide on-link route that is not denied, once per route per proxy.
    pub(crate) fn warn_excluded_routes(&self, routes: &[Cidr]) {
        if routes.is_empty() {
            return;
        }
        let Ok(mut warned) = self.warned_routes.lock() else {
            return;
        };
        for route in routes {
            if warned.len() < MAX_WARNED_ROUTES && warned.insert(*route) {
                tracing::warn!(
                    %route,
                    "egress: on-link default or very wide route (point-to-point link or full-tunnel VPN) is not \
                     denied; destinations behind it are a residual path"
                );
            }
        }
    }

    /// Keeps the record and logs it. `connected` says whether the upstream was connected: if not, the request was
    /// refused.
    pub(crate) fn push_record(&self, record: Record, connected: bool) {
        let now = Instant::now();
        if connected {
            match record.verdict {
                Verdict::ClientGone => {
                    self.client_gone.fetch_add(1, Ordering::Relaxed);
                }
                Verdict::ByteCap => {
                    self.byte_cap_cuts.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
        if connected {
            match self
                .allowed_log
                .admit(&record.host, record.port, record.bytes_up, record.bytes_down, now)
            {
                Some(held) => tracing::info!(
                    host = %record.host,
                    port = record.port,
                    bytes_up = record.bytes_up,
                    bytes_down = record.bytes_down,
                    verdict = record.verdict.reason(),
                    held_connections = held.events,
                    held_bytes_up = held.bytes_up,
                    held_bytes_down = held.bytes_down,
                    "egress"
                ),
                None => {
                    self.allowed_logs_suppressed.fetch_add(1, Ordering::Relaxed);
                }
            }
        } else {
            self.refusals.fetch_add(1, Ordering::Relaxed);
            match self.refusal_log.admit(&record.host, record.port, 0, 0, now) {
                Some(held) => tracing::info!(
                    host = %record.host,
                    port = record.port,
                    verdict = record.verdict.reason(),
                    suppressed_since_last = held.events,
                    "egress refused"
                ),
                None => {
                    self.refusal_logs_suppressed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        if let Ok(mut records) = self.records.lock()
            && records.len() < self.policy.limits.max_records
        {
            records.push(record);
            return;
        }
        self.records_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

/// The egress proxy.
#[derive(Debug)]
pub struct EgressProxy;

/// Checks the socket's directory, as a pure function of its metadata and the agent's uid: it must be a directory
/// owned by the agent, and not writable by its group or by others (who could replace the socket).
///
/// # Errors
/// [`StartError::UnsafeDirectory`] with the reason.
pub fn check_socket_dir(is_dir: bool, dir_mode: u32, dir_uid: u32, agent_uid: u32) -> Result<(), StartError> {
    if !is_dir {
        return Err(StartError::UnsafeDirectory("not a directory"));
    }
    if dir_uid != agent_uid {
        return Err(StartError::UnsafeDirectory("not owned by the agent"));
    }
    if dir_mode & 0o022 != 0 {
        return Err(StartError::UnsafeDirectory("writable by its group or by others"));
    }
    Ok(())
}

/// Name of the socket inside the staging directory.
const STAGED_NAME: &str = "egress.sock";

/// Opens `dir` as a file descriptor, refusing a symlink at the end. The staging directory is new and private; this
/// is the handle that every later step goes through, so a rename of the path cannot change where they land.
fn open_dir(dir: &Path) -> io::Result<OwnedFd> {
    Ok(rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// A short path to `name` inside the directory open as `dir`: `/proc/self/fd/<fd>/<name>`.
///
/// `bind(2)` takes its path in `sockaddr_un.sun_path`, 108 bytes with the trailing NUL, so a socket cannot be bound
/// at a path longer than that. The agent's data dir is the owner's to choose (and `/var/lib/p2pc/.local/share/…` is
/// already 90 bytes at the job's final path), so the socket is bound through the directory's descriptor instead.
/// This path is under 40 bytes, whatever the directory's own path is, and it resolves to the very directory that
/// `dir` holds open.
fn via_fd(dir: &OwnedFd, name: &str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/{name}", dir.as_raw_fd()))
}

/// Adds the operation and the path to an I/O error, keeping its kind: "No such file or directory" alone is no help to
/// whoever reads the agent's log. Paths here are the agent's own data dir, never job data.
fn context(e: impl Into<io::Error>, what: &str, path: &Path) -> io::Error {
    let e = e.into();
    io::Error::new(e.kind(), format!("{what} {}: {e}", path.display()))
}

/// Binds a unix socket called `name` inside the directory open as `dir`, through [`via_fd`].
fn bind_in(dir: &OwnedFd, name: &str) -> io::Result<StdUnixListener> {
    let via = via_fd(dir, name);
    StdUnixListener::bind(&via).map_err(|e| context(e, "bind (through /proc/self/fd)", &via))
}

/// Everything [`EgressProxy::start_with`] does up to the running accept loop: checks the directory, binds the socket
/// in a fresh 0700 staging directory, sets it to 0600, hard-links it into place and `chown`s it. The staging
/// directory is gone on return, on success or not.
///
/// # Errors
/// [`StartError`].
fn create_socket(socket_path: &Path, options: SocketOptions) -> Result<StdUnixListener, StartError> {
    static STAGING_SEQ: AtomicU32 = AtomicU32::new(0);
    let dir = socket_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or(StartError::NoParent)?;
    let dir_meta = std::fs::symlink_metadata(dir).map_err(|e| context(e, "stat", dir))?;
    if std::fs::symlink_metadata(socket_path).is_ok() {
        return Err(StartError::AlreadyExists);
    }

    // Check before creating anything.
    check_socket_dir(dir_meta.is_dir(), dir_meta.mode(), dir_meta.uid(), agent_uid())?;

    let staging = dir.join(format!(
        ".egress-staging-{}-{}",
        std::process::id(),
        STAGING_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|e| context(e, "create the staging directory", &staging))?;
    // From here on, the staging directory is only reached through this descriptor.
    let staging_fd = match open_dir(&staging) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = std::fs::remove_dir(&staging);
            return Err(context(e, "open the staging directory", &staging).into());
        }
    };
    let result = (|| {
        let listener = bind_in(&staging_fd, STAGED_NAME)?;
        // The mode first, then the link: at no moment is the socket reachable at its final path with a wider one.
        rustix::fs::chmodat(
            &staging_fd,
            STAGED_NAME,
            Mode::from_raw_mode(SOCKET_MODE),
            AtFlags::empty(),
        )
        .map_err(|e| context(e, "chmod the socket in", &staging))?;
        // Fails with `EEXIST` rather than replace anything.
        rustix::fs::linkat(&staging_fd, STAGED_NAME, rustix::fs::CWD, socket_path, AtFlags::empty()).map_err(|e| {
            match io::Error::from(e) {
                e if e.kind() == io::ErrorKind::AlreadyExists => StartError::AlreadyExists,
                e => StartError::Io(context(e, "link the socket to", socket_path)),
            }
        })?;
        if let Some((uid, gid)) = options.owner
            && let Err(e) = std::os::unix::fs::chown(socket_path, Some(uid), Some(gid))
        {
            let _ = std::fs::remove_file(socket_path);
            return Err(StartError::Io(context(e, "chown the socket", socket_path)));
        }
        Ok(listener)
    })();
    let _ = rustix::fs::unlinkat(&staging_fd, STAGED_NAME, AtFlags::empty());
    let _ = std::fs::remove_dir(&staging);
    result
}

/// What `p2pc-agent doctor` checks: that a socket can be created in a directory like a job's `p2pc/`, by the same
/// code that serves a job's proxy. The socket is removed again.
///
/// # Errors
/// Why the socket could not be made, with the paths involved.
pub fn check_socket_creation(dir: &Path) -> Result<(), StartError> {
    let socket = dir.join(STAGED_NAME);
    let listener = create_socket(&socket, SocketOptions::default())?;
    drop(listener);
    std::fs::remove_file(&socket).map_err(|e| context(e, "remove the test socket", &socket))?;
    Ok(())
}

impl EgressProxy {
    /// [`EgressProxy::start_with`] with the default [`SocketOptions`] (the socket stays owned by the agent).
    ///
    /// # Errors
    /// [`StartError`] if the directory is unsafe or the socket cannot be created.
    pub fn start(socket_path: impl AsRef<Path>, policy: Policy) -> Result<EgressHandle, StartError> {
        Self::start_with(socket_path, policy, SocketOptions::default())
    }

    /// Creates the socket at `socket_path` (mode 0600) and starts serving. Must be called from within a Tokio
    /// runtime.
    ///
    /// The parent directory must pass [`check_socket_dir`], and nothing may exist at `socket_path` yet. The socket
    /// is bound inside a fresh 0700 staging directory, set to 0600, then hard-linked into place (which fails rather
    /// than replace anything) and only then `chown`ed to `options.owner`. So at no moment is it reachable with
    /// wider permissions, whatever the process umask is. The agent never changes the umask itself: it is
    /// process-wide and would race with other threads.
    ///
    /// The socket is bound through the staging directory's file descriptor, so the length of `socket_path` does not
    /// matter (T10n; see [`via_fd`]). Only `PATH_MAX` limits it.
    ///
    /// # Errors
    /// [`StartError`] if the directory is unsafe or the socket cannot be created.
    pub fn start_with(
        socket_path: impl AsRef<Path>,
        policy: Policy,
        options: SocketOptions,
    ) -> Result<EgressHandle, StartError> {
        policy.limits.validate()?;
        let socket_path = socket_path.as_ref().to_path_buf();
        let std_listener = create_socket(&socket_path, options)?;
        let listener = std_listener
            .set_nonblocking(true)
            .and_then(|()| UnixListener::from_std(std_listener));
        match listener {
            Ok(listener) => Ok(spawn(listener, policy, socket_path)),
            Err(e) => {
                let _ = std::fs::remove_file(&socket_path);
                Err(StartError::Io(context(e, "serve the socket", &socket_path)))
            }
        }
    }
}

/// The agent's effective uid, from `geteuid(2)`. Not the owner of `/proc/self`: that belongs to root instead of the
/// process once it is made non-dumpable (`PR_SET_DUMPABLE 0`, or a setuid binary), which would make every socket
/// directory look foreign.
fn agent_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// A source of client connections: the unix socket in production, an in-memory channel in tests.
pub(crate) trait Listener: Send + 'static {
    type Conn: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn next_conn(&mut self) -> impl Future<Output = io::Result<Self::Conn>> + Send;
}

impl Listener for UnixListener {
    type Conn = UnixStream;
    async fn next_conn(&mut self) -> io::Result<UnixStream> {
        UnixListener::accept(self).await.map(|(stream, _)| stream)
    }
}

/// Starts the accept loop on `listener`. `socket_path` is removed when the loop ends.
pub(crate) fn spawn<L: Listener>(listener: L, policy: Policy, socket_path: PathBuf) -> EgressHandle {
    let shared = Arc::new(Shared::new(policy));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(accept_loop(
        listener,
        Arc::clone(&shared),
        shutdown_rx,
        socket_path.clone(),
    ));
    EgressHandle {
        shared,
        shutdown: shutdown_tx,
        task: Some(task),
        socket_path,
    }
}

/// A running proxy. Dropping it stops the proxy too (without waiting).
#[derive(Debug)]
pub struct EgressHandle {
    shared: Arc<Shared>,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    socket_path: PathBuf,
}

impl EgressHandle {
    /// The socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// The counters.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.shared.stats()
    }

    /// The records of finished requests, oldest first.
    #[must_use]
    pub fn records(&self) -> Vec<Record> {
        self.shared.records()
    }

    /// Stops accepting, closes every open connection, waits for them and removes the socket file.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for EgressHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

const BUSY_RESPONSE: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nX-P2PC-Egress: too-many-connections\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

async fn accept_loop<L: Listener>(
    mut listener: L,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
    path: PathBuf,
) {
    let permits = Arc::new(Semaphore::new(
        shared.policy.limits.max_connections.min(Semaphore::MAX_PERMITS),
    ));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.next_conn() => match accepted {
                Ok(mut stream) => match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => {
                        shared.connections.fetch_add(1, Ordering::Relaxed);
                        let shared = Arc::clone(&shared);
                        let shutdown = shutdown.clone();
                        tasks.spawn(async move {
                            conn::serve(stream, &shared, shutdown).await;
                            drop(permit);
                        });
                    }
                    Err(_) => {
                        shared.rejected_busy.fetch_add(1, Ordering::Relaxed);
                        // One non-blocking attempt (`biased` polls the write once): a busy proxy must not wait on a
                        // client that does not read.
                        tokio::select! {
                            biased;
                            _ = stream.write_all(BUSY_RESPONSE) => {}
                            () = std::future::ready(()) => {}
                        }
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "egress accept failed");
                    // Out of file descriptors and similar: back off instead of spinning.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        }
    }
    drop(listener);
    if !path.as_os_str().is_empty() {
        let _ = std::fs::remove_file(&path);
    }
    // Every connection watches `shutdown` and closes at once; wait for them so their records are kept.
    while tasks.join_next().await.is_some() {}
    // Report what the log limiters were still holding back.
    shared.allowed_log.drain();
    shared.refusal_log.drain();
}
