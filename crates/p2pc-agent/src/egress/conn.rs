// SPDX-License-Identifier: Apache-2.0

//! One client connection: read the head, run the checks in order, connect to the one checked address, relay.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use p2pc_proto::validate::domain_allowed;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::{Instant, timeout, timeout_at};

use super::body::{Sink, Source, Stop, forward_body};
use super::deny::{check_addr, excluded_onlink_routes, host_deny_set};
use super::net::UpstreamStream;
use super::request::{self, Body, Request, Target};
use super::{BoxFuture, Record, Shared, Verdict};

/// Longest host kept in a record (the head is already capped at 16 KiB; this keeps records small).
const MAX_RECORDED_HOST: usize = 255;
/// Relay buffer, per direction.
const RELAY_BUF: usize = 16 * 1024;
/// Bound on writing the proxy's own short responses to a client that does not read.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// `from + by`, clamped to about a century ahead instead of panicking on overflow (`Duration::MAX`).
fn after(from: Instant, by: Duration) -> Instant {
    from.checked_add(by)
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(100 * 365 * 24 * 3600))
}

/// Serves one client connection to the end. Never panics on client input; every wait is bounded by a timeout or
/// by `shutdown`.
pub(crate) async fn serve<S>(mut client: S, shared: &Shared, mut shutdown: watch::Receiver<bool>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let limits = &shared.policy.limits;
    // The whole head must arrive within the idle timeout, so trickling one byte at a time does not keep a slot.
    let deadline = after(Instant::now(), limits.idle_timeout);
    let head = tokio::select! {
        head = timeout_at(deadline, read_head(&mut client, limits.max_header_bytes)) => match head {
            Ok(head) => head,
            Err(_) => return,
        },
        () = wait_shutdown(&mut shutdown) => return,
    };
    let (head, early) = match head {
        Head::Complete { head, early } => (head, early),
        Head::TooLarge => return bad_request(&mut client, shared, &mut shutdown).await,
        Head::Closed => return,
    };
    let Ok(req) = request::parse_head(&head) else {
        return bad_request(&mut client, shared, &mut shutdown).await;
    };

    let target = req.target().clone();
    let mut record = Record {
        host: target.host.chars().take(MAX_RECORDED_HOST).collect(),
        port: target.port,
        bytes_up: 0,
        bytes_down: 0,
        verdict: Verdict::Allowed,
    };
    let opened = tokio::select! {
        opened = open(shared, &target) => opened,
        () = wait_shutdown(&mut shutdown) => return,
    };
    let upstream = match opened {
        Ok(upstream) => upstream,
        Err(verdict) => {
            record.verdict = verdict;
            // The record is pushed before the client can see the response or EOF, so `records()` already holds
            // it when the client learns the outcome.
            shared.push_record(record, false);
            respond(&mut client, verdict.status(), verdict.reason(), &mut shutdown).await;
            return;
        }
    };

    let mode = match req {
        Request::Connect(_) => {
            let written = tokio::select! {
                written = timeout(RESPONSE_TIMEOUT, client.write_all(ESTABLISHED)) => matches!(written, Ok(Ok(()))),
                () = wait_shutdown(&mut shutdown) => false,
            };
            if !written {
                record.verdict = Verdict::ClientGone;
                shared.push_record(record, true);
                return;
            }
            Mode::Tunnel { early }
        }
        Request::Http { head, body, .. } => Mode::Http { head, early, body },
    };
    let counters = Counters::default();
    let stop = relay(client, upstream, mode, shared, &counters, &mut shutdown).await;
    record.bytes_up = counters.up.load(Ordering::Relaxed);
    record.bytes_down = counters.down.load(Ordering::Relaxed);
    if stop == Some(Stop::Cap) {
        record.verdict = Verdict::ByteCap;
    }
    shared.push_record(record, true);
}

/// Checks 1-6 of the module docs, in order. Returns the connected upstream or the refusal.
async fn open(shared: &Shared, target: &Target) -> Result<Box<dyn UpstreamStream>, Verdict> {
    let policy = &shared.policy;
    let limits = &policy.limits;
    // 1. IP literals, in every spelling, before anything else.
    if request::is_ip_literal(&target.host) {
        return Err(Verdict::IpLiteral);
    }
    // 2. The allowlist, on whole labels.
    if !domain_allowed(&policy.allow, &target.host) {
        return Err(Verdict::DeniedDomain);
    }
    // 3. The port.
    if !policy.ports.contains(&target.port) {
        return Err(Verdict::DeniedPort);
    }
    if limits
        .max_total_bytes
        .is_some_and(|max| shared.cap_used.load(Ordering::Relaxed) >= max)
    {
        return Err(Verdict::ByteCap);
    }
    // 4. Resolve once. `domain_allowed` accepted the name, so it is a valid LDH name; normalize it the same way.
    let lower = target.host.to_ascii_lowercase();
    let name = lower.strip_suffix('.').unwrap_or(&lower);
    // At most `max_concurrent_lookups` lookups in flight per proxy, so one job cannot fill the agent's blocking
    // pool with `getaddrinfo` calls. The owned slot moves into a spawned lookup task, and only the task's
    // `JoinHandle` is under the timeout. When the timeout fires, the handle is dropped, but the task keeps running
    // and keeps the slot until the resolver really returns. (`SystemResolver` awaits its own `spawn_blocking`, so
    // that is when `getaddrinfo` returns.) Waiting for a slot counts against the lookup timeout too.
    let slots = Arc::clone(&shared.dns_slots);
    let resolver = Arc::clone(&policy.resolver);
    let (owned_name, port) = (name.to_string(), target.port);
    let lookup = async move {
        let slot = slots
            .acquire_owned()
            .await
            .map_err(|_| std::io::Error::other("proxy shutting down"))?;
        let task = tokio::spawn(async move {
            let addrs = resolver.resolve(&owned_name, port).await;
            drop(slot);
            addrs
        });
        task.await.map_err(std::io::Error::other)?
    };
    let addrs = match timeout(limits.resolve_timeout, lookup).await {
        Err(_) => return Err(Verdict::ResolveTimeout),
        Ok(Err(_)) => return Err(Verdict::ResolveFailed),
        Ok(Ok(addrs)) if addrs.is_empty() => return Err(Verdict::ResolveFailed),
        Ok(Ok(addrs)) => addrs,
    };
    // 5. Drop every address in the deny set. If the host's interfaces cannot be listed, refuse: fail closed.
    let host_nets = match timeout(limits.resolve_timeout, policy.host_networks.networks()).await {
        Ok(Ok(nets)) => nets,
        _ => {
            tracing::warn!("egress: cannot list the host's interfaces; refusing");
            return Err(Verdict::DeniedAddress);
        }
    };
    shared.warn_excluded_routes(&excluded_onlink_routes(&host_nets));
    // The egress gate (T10f) is read before the deny list: it opens only after the list holds the public IPv4, so a
    // gate seen open means the list read next already has it.
    let gate_open = policy.egress_ready.borrow().is_open();
    // The node's public addresses are a live source (iroh's observed addresses): read the current value now.
    let public_addrs = policy.public_addrs.borrow().clone();
    let deny_set = host_deny_set(&host_nets, policy.lan_ipv6_prefix, &public_addrs);
    let mut chosen = None;
    let mut gate_refused = false;
    for addr in &addrs {
        match check_addr(*addr, &deny_set) {
            // Gate closed: the node's public IPv4 may be missing from the deny list, so no IPv4 destination. IPv6
            // ones are covered by the host's own networks and stay allowed.
            Ok(ip) if !gate_open && ip.is_ipv4() => gate_refused = true,
            Ok(ip) => {
                chosen = Some(ip);
                break;
            }
            Err(why) => tracing::debug!(host = name, %addr, ?why, "egress: address refused"),
        }
    }
    let ip = chosen.ok_or(if gate_refused {
        Verdict::EgressUnavailable
    } else {
        Verdict::DeniedAddress
    })?;
    // 6. Connect to exactly that address. No fallback to another address and no second lookup.
    let addr = SocketAddr::new(ip, target.port);
    match timeout(limits.connect_timeout, policy.connector.connect(addr)).await {
        Err(_) => Err(Verdict::ConnectTimeout),
        Ok(Err(_)) => Err(Verdict::ConnectFailed),
        Ok(Ok(stream)) => Ok(stream),
    }
}

enum Head {
    /// The head, and any bytes the client sent after it (early TLS data, a request body).
    Complete {
        head: Vec<u8>,
        early: Vec<u8>,
    },
    TooLarge,
    Closed,
}

/// Reads until `\r\n\r\n`, never holding more than `max` bytes.
async fn read_head<S: AsyncRead + Unpin>(client: &mut S, max: usize) -> Head {
    let mut buf = Vec::with_capacity(1024.min(max));
    let mut chunk = vec![0u8; 4096];
    loop {
        let room = max.saturating_sub(buf.len());
        if room == 0 {
            return Head::TooLarge;
        }
        let want = room.min(chunk.len());
        let Some(dst) = chunk.get_mut(..want) else {
            return Head::TooLarge;
        };
        let n = match client.read(dst).await {
            Ok(0) | Err(_) => return Head::Closed,
            Ok(n) => n,
        };
        let searched = buf.len().saturating_sub(3);
        buf.extend_from_slice(dst.get(..n).unwrap_or_default());
        if let Some(len) = buf.get(searched..).and_then(request::head_len) {
            let early = buf.split_off(searched + len);
            return Head::Complete { head: buf, early };
        }
    }
}

async fn bad_request<S: AsyncWrite + Unpin>(client: &mut S, shared: &Shared, shutdown: &mut watch::Receiver<bool>) {
    shared.bad_requests.fetch_add(1, Ordering::Relaxed);
    respond(client, "400 Bad Request", "bad-request", shutdown).await;
}

/// Writes the proxy's own short response and closes. Bounded by [`RESPONSE_TIMEOUT`], and abandoned at once on
/// shutdown, so a client that does not read can never hold up the proxy's shutdown.
async fn respond<S: AsyncWrite + Unpin>(
    client: &mut S,
    status: &str,
    reason: &str,
    shutdown: &mut watch::Receiver<bool>,
) {
    let msg = format!("HTTP/1.1 {status}\r\nX-P2PC-Egress: {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let write = timeout(RESPONSE_TIMEOUT, async {
        client.write_all(msg.as_bytes()).await?;
        client.shutdown().await
    });
    tokio::select! {
        _ = write => {}
        () = wait_shutdown(shutdown) => {}
    }
}

async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            // The handle is gone: shut down too.
            return;
        }
    }
}

#[derive(Debug, Default)]
struct Counters {
    up: AtomicU64,
    down: AtomicU64,
}

/// When either direction last moved a byte.
#[derive(Debug)]
struct Activity {
    base: Instant,
    nanos: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            nanos: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let nanos = u64::try_from(self.base.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.nanos.store(nanos, Ordering::Relaxed);
    }

    fn last(&self) -> Instant {
        self.base + Duration::from_nanos(self.nanos.load(Ordering::Relaxed))
    }
}

/// Returns when nothing moved in either direction for `idle`.
async fn idle_watch(activity: &Activity, idle: Duration) {
    loop {
        let deadline = after(activity.last(), idle);
        tokio::time::sleep_until(deadline).await;
        if after(activity.last(), idle) <= Instant::now() {
            return;
        }
    }
}

/// Counts `n` bytes against the byte cap. False once the cap would be exceeded.
fn reserve(shared: &Shared, n: usize) -> bool {
    match shared.policy.limits.max_total_bytes {
        None => true,
        Some(max) => {
            let n = n as u64;
            shared.cap_used.fetch_add(n, Ordering::Relaxed).saturating_add(n) <= max
        }
    }
}

/// The relay ended: the peer closed (`Ok`), or the byte cap or an error stopped it (`Err`).
type Flow = Result<(), Stop>;

/// Writes `bytes` if the byte cap allows it.
async fn send<W: AsyncWrite + Unpin>(to: &mut W, bytes: &[u8], shared: &Shared) -> Flow {
    if !reserve(shared, bytes.len()) {
        return Err(Stop::Cap);
    }
    to.write_all(bytes).await.map_err(|_| Stop::Other)?;
    to.flush().await.map_err(|_| Stop::Other)
}

/// Copies one direction, writing `first` before anything read from `from`.
async fn pipe<R, W>(
    mut from: R,
    mut to: W,
    first: Vec<u8>,
    shared: &Shared,
    total: &AtomicU64,
    conn: &AtomicU64,
    activity: &Activity,
) -> Flow
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if !first.is_empty() {
        send(&mut to, &first, shared).await?;
        total.fetch_add(first.len() as u64, Ordering::Relaxed);
        conn.fetch_add(first.len() as u64, Ordering::Relaxed);
        activity.touch();
    }
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        let n = from.read(&mut buf).await.map_err(|_| Stop::Other)?;
        let Some(bytes) = buf.get(..n).filter(|b| !b.is_empty()) else {
            let _ = to.shutdown().await;
            return Ok(());
        };
        activity.touch();
        send(&mut to, bytes, shared).await?;
        total.fetch_add(n as u64, Ordering::Relaxed);
        conn.fetch_add(n as u64, Ordering::Relaxed);
        activity.touch();
    }
}

/// What is relayed after the checks.
enum Mode {
    /// A `CONNECT` tunnel: `early` is what the client sent after the head (early TLS data).
    Tunnel { early: Vec<u8> },
    /// One plain-HTTP request: the rewritten head, then exactly the body framed as `body`.
    Http { head: Vec<u8>, early: Vec<u8>, body: Body },
}

/// The upstream write side, through the byte cap and the counters.
struct UpSink<'a, W> {
    to: W,
    shared: &'a Shared,
    conn: &'a AtomicU64,
    activity: &'a Activity,
}

impl<W: AsyncWrite + Unpin + Send> Sink for UpSink<'_, W> {
    async fn put(&mut self, bytes: &[u8]) -> Flow {
        send(&mut self.to, bytes, self.shared).await?;
        self.shared.bytes_up.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        self.conn.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        self.activity.touch();
        Ok(())
    }
}

/// Relays both directions until done, idle, or shutdown.
///
/// A `CONNECT` tunnel ends when both sides have closed. A plain HTTP request forwards its head and exactly its
/// declared body, then never reads from the client again; it ends when the upstream finishes its response (it was
/// sent `Connection: close`), so a keep-alive client is not left waiting for the idle timeout.
///
/// Returns why it stopped early, if it did (`Some(Stop::Cap)` when the byte cap cut it).
async fn relay<S>(
    client: S,
    upstream: Box<dyn UpstreamStream>,
    mode: Mode,
    shared: &Shared,
    counters: &Counters,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<Stop>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (client_r, client_w) = tokio::io::split(client);
    let (up_r, up_w) = tokio::io::split(upstream);
    let activity = Activity::new();
    let (http, up): (bool, BoxFuture<'_, Flow>) = match mode {
        Mode::Tunnel { early } => (
            false,
            Box::pin(pipe(
                client_r,
                up_w,
                early,
                shared,
                &shared.bytes_up,
                &counters.up,
                &activity,
            )),
        ),
        Mode::Http { head, early, body } => {
            let activity = &activity;
            let conn = &counters.up;
            (
                true,
                Box::pin(async move {
                    let mut sink = UpSink {
                        to: up_w,
                        shared,
                        conn,
                        activity,
                    };
                    sink.put(&head).await?;
                    let mut src = Source::new(client_r, early);
                    forward_body(&mut src, body, &mut sink).await
                }),
            )
        }
    };
    let down = pipe(
        up_r,
        client_w,
        Vec::new(),
        shared,
        &shared.bytes_down,
        &counters.down,
        &activity,
    );
    let transfer = async {
        if http {
            tokio::pin!(up);
            tokio::pin!(down);
            tokio::select! {
                flow = &mut down => flow,
                flow = &mut up => match flow {
                    Ok(()) => down.await,
                    Err(stop) => Err(stop),
                },
            }
        } else {
            tokio::try_join!(up, down).map(|_| ())
        }
    };
    tokio::select! {
        flow = transfer => flow.err(),
        () = idle_watch(&activity, shared.policy.limits.idle_timeout) => {
            tracing::debug!("egress: idle tunnel closed");
            None
        }
        () = wait_shutdown(shutdown) => None,
    }
}
