// SPDX-License-Identifier: Apache-2.0

//! Egress proxy tests (SI-4, SI-5). Hermetic: a fake resolver, fake host interfaces and a fake connector, so no test
//! opens an outbound socket. The "public" addresses (`1.1.1.1`, `2606:4700:4700::1111`) are never contacted: the
//! fake connector hands back an in-memory stream. TEST-NET addresses cannot be used as "public" ones because they
//! are in the deny set by design.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::body::chunk_size;
use super::deny::{
    Cidr, DENY_TABLE, MIN_ONLINK_ROUTE_PREFIX_V4, MIN_ONLINK_ROUTE_PREFIX_V6, check_addr, excluded_onlink_routes,
    host_deny_set, parse_ipv4_route, parse_ipv6_route,
};
use super::request::{BadRequest, Request, is_ip_literal, parse_head};
use super::*;

const PUBLIC_V4: &str = "1.1.1.1";
const PUBLIC_V4_B: &str = "1.0.0.1";
const PUBLIC_V6: &str = "2606:4700:4700::1111";
/// The fake host's own address, and its on-link IPv6 network.
const HOST_V4: &str = "1.0.0.2";
const HOST_V6_NET: &str = "2606:4700:f00d::1";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn sa(s: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip(s), port)
}

// ---------------------------------------------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct FakeResolver {
    answers: HashMap<String, Vec<IpAddr>>,
    queries: Mutex<Vec<String>>,
    hang: bool,
    /// Answers only after this long (a slow `getaddrinfo`).
    delay: Option<Duration>,
}

impl FakeResolver {
    fn queries(&self) -> Vec<String> {
        self.queries.lock().unwrap().clone()
    }
}

impl Resolver for FakeResolver {
    fn resolve<'a>(&'a self, host: &'a str, _port: u16) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            self.queries.lock().unwrap().push(host.to_string());
            if self.hang {
                std::future::pending::<()>().await;
            }
            if let Some(delay) = self.delay {
                tokio::time::sleep(delay).await;
            }
            self.answers
                .get(host)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such name"))
        })
    }
}

#[derive(Debug)]
struct FakeHostNets(Option<HostNets>);

impl HostNetworks for FakeHostNets {
    fn networks(&self) -> BoxFuture<'_, io::Result<HostNets>> {
        Box::pin(async { self.0.clone().ok_or_else(|| io::Error::other("no interfaces")) })
    }
}

fn default_host_nets() -> Vec<Cidr> {
    vec![
        Cidr::V4(HOST_V4.parse().unwrap(), 32),
        Cidr::V6(HOST_V6_NET.parse().unwrap(), 64),
        Cidr::V4("127.0.0.1".parse().unwrap(), 8),
    ]
}

#[derive(Debug, Clone)]
enum Upstream {
    /// Echoes everything back.
    Echo,
    /// Reads one request head, sends this response and closes its write side. Records **every** byte received
    /// until the proxy closes the connection, so a test can prove what was (not) forwarded.
    Http(&'static [u8]),
    /// Connection refused.
    Refuse,
    /// Never completes.
    Hang,
    /// Connects for real to a local test server (end-to-end test only; always a loopback address).
    Local(SocketAddr),
}

#[derive(Debug)]
struct FakeConnector {
    upstream: Upstream,
    attempts: Mutex<Vec<SocketAddr>>,
    received: Arc<Mutex<Vec<u8>>>,
    upstream_tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl FakeConnector {
    fn new(upstream: Upstream) -> Self {
        Self {
            upstream,
            attempts: Mutex::new(Vec::new()),
            received: Arc::new(Mutex::new(Vec::new())),
            upstream_tasks: Mutex::new(Vec::new()),
        }
    }

    /// Waits until every fake upstream has seen the proxy close the connection, so `received` is final.
    async fn settle(&self) {
        let tasks: Vec<_> = self.upstream_tasks.lock().unwrap().drain(..).collect();
        for t in tasks {
            t.await.unwrap();
        }
    }

    fn attempts(&self) -> Vec<SocketAddr> {
        self.attempts.lock().unwrap().clone()
    }

    fn received(&self) -> String {
        String::from_utf8_lossy(&self.received.lock().unwrap()).into_owned()
    }
}

impl Connector for FakeConnector {
    fn connect(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<Box<dyn UpstreamStream>>> {
        Box::pin(async move {
            self.attempts.lock().unwrap().push(addr);
            match self.upstream.clone() {
                Upstream::Echo => {
                    let (ours, mut theirs) = duplex(1 << 16);
                    tokio::spawn(async move {
                        let (mut r, mut w) = tokio::io::split(&mut theirs);
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                        let _ = w.shutdown().await;
                    });
                    Ok(Box::new(ours) as Box<dyn UpstreamStream>)
                }
                Upstream::Http(response) => {
                    let (ours, mut theirs) = duplex(1 << 16);
                    let received = Arc::clone(&self.received);
                    let task = tokio::spawn(async move {
                        let mut buf = Vec::new();
                        let mut byte = [0u8; 1];
                        while request::head_len(&buf).is_none() {
                            match theirs.read(&mut byte).await {
                                Ok(1) => buf.push(byte[0]),
                                _ => break,
                            }
                        }
                        received.lock().unwrap().extend_from_slice(&buf);
                        let _ = theirs.write_all(response).await;
                        let _ = theirs.shutdown().await;
                        // Keep recording until the proxy drops the connection.
                        let mut rest = Vec::new();
                        let _ = theirs.read_to_end(&mut rest).await;
                        received.lock().unwrap().extend_from_slice(&rest);
                    });
                    self.upstream_tasks.lock().unwrap().push(task);
                    Ok(Box::new(ours) as Box<dyn UpstreamStream>)
                }
                Upstream::Refuse => Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
                Upstream::Hang => std::future::pending().await,
                Upstream::Local(local) => {
                    let s = tokio::net::TcpStream::connect(local).await?;
                    Ok(Box::new(s) as Box<dyn UpstreamStream>)
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Harness: drives `conn::serve` over an in-memory stream, so paused-time tests are deterministic.
// ---------------------------------------------------------------------------------------------------------------

struct Setup {
    allow: Vec<&'static str>,
    answers: Vec<(&'static str, Vec<&'static str>)>,
    host_nets: Option<HostNets>,
    upstream: Upstream,
    limits: Limits,
    hang_resolver: bool,
    public_addrs: Vec<&'static str>,
    /// A live source of public addresses; when set, `public_addrs` is ignored.
    public_rx: Option<watch::Receiver<Vec<IpAddr>>>,
    /// A live egress gate; when unset, the gate is open.
    ready_rx: Option<watch::Receiver<EgressGate>>,
    resolver_delay: Option<Duration>,
    lan_ipv6_prefix: u8,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            allow: vec!["example.com"],
            answers: vec![
                ("example.com", vec![PUBLIC_V4]),
                ("a.example.com", vec![PUBLIC_V4]),
                ("evilexample.com", vec![PUBLIC_V4]),
                ("example.com.evil.net", vec![PUBLIC_V4]),
                ("forbidden.example.net", vec![PUBLIC_V4]),
            ],
            host_nets: Some(HostNets {
                interfaces: default_host_nets(),
                onlink_routes: Vec::new(),
            }),
            upstream: Upstream::Echo,
            limits: Limits::default(),
            hang_resolver: false,
            public_addrs: Vec::new(),
            public_rx: None,
            ready_rx: None,
            resolver_delay: None,
            lan_ipv6_prefix: DEFAULT_LAN_IPV6_PREFIX,
        }
    }
}

struct Harness {
    shared: Arc<Shared>,
    resolver: Arc<FakeResolver>,
    connector: Arc<FakeConnector>,
    shutdown: watch::Sender<bool>,
}

impl Setup {
    fn policy(self) -> (Policy, Arc<FakeResolver>, Arc<FakeConnector>) {
        let resolver = Arc::new(FakeResolver {
            answers: self
                .answers
                .into_iter()
                .map(|(h, ips)| (h.to_string(), ips.into_iter().map(ip).collect()))
                .collect(),
            queries: Mutex::new(Vec::new()),
            hang: self.hang_resolver,
            delay: self.resolver_delay,
        });
        let connector = Arc::new(FakeConnector::new(self.upstream));
        let policy = Policy {
            allow: self.allow.into_iter().map(String::from).collect(),
            ports: Policy::DEFAULT_PORTS.into_iter().collect(),
            resolver: Arc::clone(&resolver) as Arc<dyn Resolver>,
            host_networks: Arc::new(FakeHostNets(self.host_nets)),
            connector: Arc::clone(&connector) as Arc<dyn Connector>,
            lan_ipv6_prefix: self.lan_ipv6_prefix,
            public_addrs: match self.public_rx {
                Some(rx) => rx,
                None => watch::channel(self.public_addrs.into_iter().map(ip).collect()).1,
            },
            egress_ready: self.ready_rx.unwrap_or_else(|| watch::channel(EgressGate::Open).1),
            limits: self.limits,
        };
        (policy, resolver, connector)
    }

    fn build(self) -> Harness {
        let (policy, resolver, connector) = self.policy();
        let (shutdown, _) = watch::channel(false);
        Harness {
            shared: Arc::new(Shared::new(policy)),
            resolver,
            connector,
            shutdown,
        }
    }
}

impl Harness {
    fn client(&self) -> (DuplexStream, JoinHandle<()>) {
        self.client_with_buffer(1 << 16)
    }

    /// A client whose stream holds at most `capacity` unread bytes: one that stops reading blocks the proxy's
    /// writes after that many bytes.
    fn client_with_buffer(&self, capacity: usize) -> (DuplexStream, JoinHandle<()>) {
        let (client, server) = duplex(capacity);
        let shared = Arc::clone(&self.shared);
        let rx = self.shutdown.subscribe();
        let task = tokio::spawn(async move { conn::serve(server, &shared, rx).await });
        (client, task)
    }

    /// Sends `raw`, reads the whole response until the proxy closes, and waits for the connection to finish.
    async fn exchange(&self, raw: &[u8]) -> String {
        let (mut c, task) = self.client();
        let _ = c.write_all(raw).await;
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out).await;
        drop(c);
        task.await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Sends a `CONNECT` and returns the response head and the open stream.
    async fn connect(&self, authority: &str) -> (String, DuplexStream, JoinHandle<()>) {
        let (mut c, task) = self.client();
        c.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_head(&mut c).await;
        (head, c, task)
    }
}

async fn read_head(c: &mut DuplexStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while request::head_len(&buf).is_none() {
        match c.read(&mut byte).await {
            Ok(1) => buf.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn reason(response: &str) -> Option<&str> {
    response.split("\r\n").find_map(|l| l.strip_prefix("X-P2PC-Egress: "))
}

fn status(response: &str) -> &str {
    response.split("\r\n").next().unwrap_or("")
}

fn connect_req(authority: &str) -> Vec<u8> {
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").into_bytes()
}

// ---------------------------------------------------------------------------------------------------------------
// SI-4: the deny set
// ---------------------------------------------------------------------------------------------------------------

/// Every range the task and the spec list, by a sample address, plus the host's own addresses. The proxy is driven
/// end to end: the resolver returns the address for an allowlisted name, and the proxy must refuse without ever
/// calling the connector.
const DENIED_SAMPLES: &[(&str, &str)] = &[
    ("0.0.0.0", "0.0.0.0/8"),
    ("0.1.2.3", "0.0.0.0/8"),
    ("10.0.0.1", "10.0.0.0/8"),
    ("10.255.255.255", "10.0.0.0/8"),
    ("100.64.0.1", "100.64.0.0/10"),
    ("100.100.100.100", "100.64.0.0/10 (Tailscale DNS)"),
    ("100.127.255.254", "100.64.0.0/10"),
    ("127.0.0.1", "127.0.0.0/8"),
    ("127.255.255.254", "127.0.0.0/8"),
    ("169.254.0.1", "169.254.0.0/16"),
    ("169.254.169.254", "169.254.0.0/16 (cloud metadata)"),
    ("172.16.0.1", "172.16.0.0/12"),
    ("172.31.255.255", "172.16.0.0/12"),
    ("192.0.0.1", "192.0.0.0/24"),
    ("192.0.2.1", "192.0.2.0/24"),
    ("192.88.99.1", "192.88.99.0/24"),
    ("192.168.0.1", "192.168.0.0/16"),
    ("192.168.255.255", "192.168.0.0/16"),
    ("198.18.0.1", "198.18.0.0/15"),
    ("198.19.255.255", "198.18.0.0/15"),
    ("198.51.100.1", "198.51.100.0/24"),
    ("203.0.113.1", "203.0.113.0/24"),
    ("224.0.0.1", "224.0.0.0/4"),
    ("239.255.255.250", "224.0.0.0/4"),
    ("240.0.0.1", "240.0.0.0/4"),
    ("255.255.255.255", "255.255.255.255/32"),
    ("::", "::/128"),
    ("::1", "::1/128"),
    ("::ffff:127.0.0.1", "::ffff:0:0/96 → 127.0.0.0/8"),
    ("::ffff:10.1.2.3", "::ffff:0:0/96 → 10.0.0.0/8"),
    ("::ffff:192.168.1.1", "::ffff:0:0/96 → 192.168.0.0/16"),
    ("::ffff:100.64.0.1", "::ffff:0:0/96 → 100.64.0.0/10"),
    ("::ffff:169.254.169.254", "::ffff:0:0/96 → 169.254.0.0/16"),
    ("::ffff:0.0.0.0", "::ffff:0:0/96 → 0.0.0.0/8"),
    ("::127.0.0.1", "::/96 IPv4-compatible"),
    ("::ffff:0:7f00:1", "::ffff:0:0:0/96 IPv4-translated"),
    ("64:ff9b::7f00:1", "64:ff9b::/96"),
    ("64:ff9b::a00:1", "64:ff9b::/96"),
    ("64:ff9b:1::1", "64:ff9b:1::/48"),
    ("100::1", "100::/64"),
    ("2001::1", "2001::/23 (Teredo)"),
    ("2001:2::1", "2001::/23 (benchmarking)"),
    ("2001:10::1", "2001::/23 (ORCHID)"),
    ("2001:db8::1", "2001:db8::/32"),
    ("2002:c0a8:101::1", "2002::/16 (6to4 of 192.168.1.1)"),
    ("3fff::1", "3fff::/20"),
    ("5f00::1", "5f00::/16"),
    ("fc00::1", "fc00::/7"),
    ("fd7a:115c:a1e0::1", "fc00::/7 (Tailscale ULA)"),
    ("fdff:ffff::1", "fc00::/7"),
    ("fe80::1", "fe80::/10"),
    ("febf::1", "fe80::/10"),
    ("fec0::1", "fec0::/10"),
    ("ff02::1", "ff00::/8"),
    ("ff0e::1", "ff00::/8"),
    ("1::1", "outside 2000::/3"),
    ("4000::1", "outside 2000::/3"),
    (HOST_V4, "the host's own address"),
    ("::ffff:1.0.0.2", "the host's own address, IPv4-mapped"),
    ("2606:4700:f00d::beef", "the host's on-link IPv6 network"),
    ("127.0.0.53", "loopback (also a host network)"),
];

#[tokio::test]
async fn every_deny_range_is_refused_through_the_proxy() {
    for (addr, range) in DENIED_SAMPLES {
        let h = Setup {
            answers: vec![("example.com", vec![addr])],
            ..Setup::default()
        }
        .build();
        let resp = h.exchange(&connect_req("example.com:443")).await;
        assert_eq!(status(&resp), "HTTP/1.1 403 Forbidden", "{addr} ({range}): {resp:?}");
        assert_eq!(reason(&resp), Some("denied-address"), "{addr} ({range})");
        assert!(
            h.connector.attempts().is_empty(),
            "{addr} ({range}) reached the connector"
        );
        let records = h.shared.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].verdict, Verdict::DeniedAddress);
    }
}

#[test]
fn every_deny_table_entry_refuses_its_first_and_last_address() {
    for range in DENY_TABLE {
        let (first, last): (IpAddr, IpAddr) = match range.net {
            Cidr::V4(a, len) => {
                let base = u32::from(a);
                let span = u32::MAX.checked_shr(len.into()).unwrap_or(0);
                (a.into(), std::net::Ipv4Addr::from(base | span).into())
            }
            Cidr::V6(a, len) => {
                let base = u128::from(a);
                let span = u128::MAX.checked_shr(len.into()).unwrap_or(0);
                (a.into(), std::net::Ipv6Addr::from(base | span).into())
            }
        };
        for probe in [first, last] {
            // `::ffff:0:0/96` is not in the table (it is mapped to IPv4); everything the table lists is refused.
            assert!(
                check_addr(probe, &[]).is_err(),
                "{probe} in {} ({})",
                range.net,
                range.why
            );
        }
    }
}

#[test]
fn deny_ranges_have_exact_boundaries() {
    for allowed in [
        "9.255.255.255",
        "11.0.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "126.255.255.255",
        "128.0.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.169.0.0",
        "223.255.255.255",
        PUBLIC_V4,
        PUBLIC_V6,
        "::ffff:1.1.1.1",
        "2001:200::1",
        "2003::1",
    ] {
        assert!(check_addr(ip(allowed), &[]).is_ok(), "{allowed} should be allowed");
    }
    // IPv4-mapped public addresses are connected to as plain IPv4.
    assert_eq!(check_addr(ip("::ffff:1.1.1.1"), &[]), Ok(ip(PUBLIC_V4)));
    // The host's networks are refused on top of the table.
    let nets = default_host_nets();
    assert!(check_addr(ip(HOST_V4), &nets).is_err());
    assert!(check_addr(ip("2606:4700:f00d::2"), &nets).is_err());
    assert!(check_addr(ip(PUBLIC_V4), &nets).is_ok());
    // An interface reported as IPv4-mapped IPv6 still covers its IPv4 address.
    let mapped = [Cidr::V6("::ffff:1.0.0.9".parse().unwrap(), 128)];
    assert!(check_addr(ip("1.0.0.9"), &mapped).is_err());
}

#[tokio::test]
async fn host_interfaces_that_cannot_be_listed_fail_closed() {
    let h = Setup {
        host_nets: None,
        ..Setup::default()
    }
    .build();
    let resp = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(reason(&resp), Some("denied-address"), "{resp:?}");
    assert!(h.connector.attempts().is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// IP literals
// ---------------------------------------------------------------------------------------------------------------

const IP_LITERAL_AUTHORITIES: &[&str] = &[
    "127.0.0.1:443",
    "1.1.1.1:443",
    "1.1.1.1.:443",
    "[::1]:443",
    "[::]:443",
    "[::ffff:127.0.0.1]:443",
    "[::ffff:7f00:1]:443",
    "[2606:4700:4700::1111]:443",
    "[fe80::1%eth0]:443",
    "[fe80::1%25eth0]:443",
    "2130706433:443",
    "017700000001:443",
    "0x7f000001:443",
    "0x7f.1:443",
    "0X7F.0.0.1:443",
    "0177.0.0.1:443",
    "127.1:443",
    "127.0.1:443",
    "0:443",
    "0x:443",
    "::1:443",
    "a.b.0x7f:443",
    "example.com.1:443",
    "127.0.0.1%2e:443",
];

#[tokio::test]
async fn ip_literals_are_refused_in_every_form() {
    assert!(IP_LITERAL_AUTHORITIES.len() >= 15);
    for auth in IP_LITERAL_AUTHORITIES {
        // Even an allowlist naming the literal does not help.
        let host = auth.rsplit_once(':').map_or(*auth, |(h, _)| h);
        let h = Setup {
            allow: vec!["example.com", host],
            ..Setup::default()
        }
        .build();
        let resp = h.exchange(&connect_req(auth)).await;
        assert_eq!(status(&resp), "HTTP/1.1 403 Forbidden", "{auth}: {resp:?}");
        assert_eq!(reason(&resp), Some("ip-literal"), "{auth}");
        assert!(h.resolver.queries().is_empty(), "{auth} was resolved");
        assert!(h.connector.attempts().is_empty(), "{auth} was connected");
    }
}

#[tokio::test]
async fn ip_literals_are_refused_in_absolute_uris() {
    for uri in [
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]:80/x",
        "http://2130706433/",
        "http://0x7f.1/",
        "http://0177.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
    ] {
        let h = Setup::default().build();
        let resp = h
            .exchange(format!("GET {uri} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await;
        assert_eq!(reason(&resp), Some("ip-literal"), "{uri}: {resp:?}");
        assert!(h.connector.attempts().is_empty());
    }
}

#[test]
fn ip_literal_detection() {
    for host in [
        "example.com",
        "a.example.com",
        "1.example.com",
        "xn--bcher-kva.example",
        "0x7f.example",
    ] {
        assert!(!is_ip_literal(host), "{host}");
    }
    for auth in IP_LITERAL_AUTHORITIES {
        let host = auth.rsplit_once(':').map_or(*auth, |(h, _)| h);
        assert!(is_ip_literal(host), "{host}");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// SI-5: the allowlist, and ports
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn only_allowlisted_domains_pass_on_whole_labels() {
    for host in [
        "evilexample.com",
        "example.com.evil.net",
        "forbidden.example.net",
        "com",
        "localhost",
    ] {
        let h = Setup::default().build();
        let resp = h.exchange(&connect_req(&format!("{host}:443"))).await;
        assert_eq!(reason(&resp), Some("denied-domain"), "{host}: {resp:?}");
        assert!(h.resolver.queries().is_empty(), "{host} was resolved");
        assert!(h.connector.attempts().is_empty());
    }
    for host in ["example.com", "a.example.com", "EXAMPLE.com", "example.com."] {
        let h = Setup::default().build();
        let (head, c, task) = h.connect(&format!("{host}:443")).await;
        assert_eq!(status(&head), "HTTP/1.1 200 Connection Established", "{host}: {head:?}");
        drop(c);
        task.await.unwrap();
        assert_eq!(h.connector.attempts(), vec![sa(PUBLIC_V4, 443)], "{host}");
    }
}

#[tokio::test]
async fn ports_outside_the_policy_are_refused() {
    for auth in ["example.com:22", "example.com:8080", "example.com:25"] {
        let h = Setup::default().build();
        let resp = h.exchange(&connect_req(auth)).await;
        assert_eq!(reason(&resp), Some("denied-port"), "{auth}: {resp:?}");
        assert!(h.resolver.queries().is_empty());
    }
    let h = Setup::default().build();
    let resp = h
        .exchange(b"GET http://example.com:22/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await;
    assert_eq!(reason(&resp), Some("denied-port"), "{resp:?}");

    for port in [443, 80] {
        let h = Setup::default().build();
        let (head, c, task) = h.connect(&format!("example.com:{port}")).await;
        assert_eq!(status(&head), "HTTP/1.1 200 Connection Established");
        drop(c);
        task.await.unwrap();
        assert_eq!(h.connector.attempts(), vec![sa(PUBLIC_V4, port)]);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// DNS rebinding and mixed answers
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn dns_rebinding_connects_only_to_the_checked_ip() {
    let h = Setup {
        answers: vec![("example.com", vec![PUBLIC_V4, "127.0.0.1"])],
        ..Setup::default()
    }
    .build();
    let (head, c, task) = h.connect("example.com:443").await;
    assert_eq!(status(&head), "HTTP/1.1 200 Connection Established");
    drop(c);
    task.await.unwrap();
    assert_eq!(h.connector.attempts(), vec![sa(PUBLIC_V4, 443)]);
    // Resolved exactly once: there is no second lookup to rebind.
    assert_eq!(h.resolver.queries(), vec!["example.com".to_string()]);
}

#[tokio::test]
async fn only_one_checked_ip_is_tried_even_when_it_fails() {
    let h = Setup {
        answers: vec![("example.com", vec![PUBLIC_V4, PUBLIC_V4_B])],
        upstream: Upstream::Refuse,
        ..Setup::default()
    }
    .build();
    let resp = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(status(&resp), "HTTP/1.1 502 Bad Gateway", "{resp:?}");
    assert_eq!(reason(&resp), Some("connect-failed"));
    assert_eq!(h.connector.attempts(), vec![sa(PUBLIC_V4, 443)]);
}

#[tokio::test]
async fn mixed_answers_use_only_the_public_address() {
    for answers in [
        vec!["10.0.0.1", PUBLIC_V4],
        vec!["127.0.0.1", "::1", "fd00::1", PUBLIC_V4],
        vec!["::ffff:192.168.0.1", PUBLIC_V4],
    ] {
        let h = Setup {
            answers: vec![("example.com", answers.clone())],
            ..Setup::default()
        }
        .build();
        let (head, c, task) = h.connect("example.com:443").await;
        assert_eq!(status(&head), "HTTP/1.1 200 Connection Established", "{answers:?}");
        drop(c);
        task.await.unwrap();
        assert_eq!(h.connector.attempts(), vec![sa(PUBLIC_V4, 443)], "{answers:?}");
    }
    let h = Setup {
        answers: vec![("example.com", vec!["fe80::1", PUBLIC_V6])],
        ..Setup::default()
    }
    .build();
    let (_, c, task) = h.connect("example.com:443").await;
    drop(c);
    task.await.unwrap();
    assert_eq!(h.connector.attempts(), vec![sa(PUBLIC_V6, 443)]);

    let h = Setup {
        answers: vec![("example.com", vec!["10.0.0.1", "192.168.1.1", "fd00::1", "::1"])],
        ..Setup::default()
    }
    .build();
    let resp = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(reason(&resp), Some("denied-address"));
    assert!(h.connector.attempts().is_empty());
}

#[tokio::test]
async fn names_that_do_not_resolve_get_502() {
    let h = Setup {
        answers: vec![("example.com", vec![])],
        ..Setup::default()
    }
    .build();
    let resp = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(reason(&resp), Some("resolve-failed"), "{resp:?}");
    // NXDOMAIN (this harness only knows `example.com`).
    let resp = h.exchange(&connect_req("A.Example.com.:443")).await;
    assert_eq!(status(&resp), "HTTP/1.1 502 Bad Gateway", "{resp:?}");
    // The resolver gets the normalized name: lowercase, no trailing dot.
    assert_eq!(h.resolver.queries(), vec!["example.com", "a.example.com"]);
}

// ---------------------------------------------------------------------------------------------------------------
// Plain HTTP: origin-form, header stripping, a single request, redirects not followed
// ---------------------------------------------------------------------------------------------------------------

const REDIRECT: &[u8] = b"HTTP/1.1 302 Found\r\nLocation: http://forbidden.example.net/\r\nContent-Length: 0\r\n\r\n";

#[tokio::test]
async fn plain_http_is_rewritten_and_redirects_are_not_followed() {
    let h = Setup {
        upstream: Upstream::Http(REDIRECT),
        ..Setup::default()
    }
    .build();
    let resp = h
        .exchange(
            b"GET http://example.com/path?q=1 HTTP/1.1\r\n\
              Host: example.com\r\n\
              User-Agent: test\r\n\
              Proxy-Authorization: Basic c2VjcmV0\r\n\
              Proxy-Connection: keep-alive\r\n\
              Connection: keep-alive, X-Hop\r\n\
              X-Hop: 1\r\n\
              Keep-Alive: timeout=5\r\n\
              TE: trailers\r\n\
              Upgrade: websocket\r\n\r\n",
        )
        .await;
    // The client gets the redirect itself; the proxy did not follow it.
    assert_eq!(resp.as_bytes(), REDIRECT);
    assert_eq!(h.connector.attempts(), vec![sa(PUBLIC_V4, 80)]);
    assert_eq!(h.resolver.queries(), vec!["example.com"]);

    let sent = h.connector.received();
    assert_eq!(
        sent,
        "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nConnection: close\r\n\r\n"
    );

    // Following the redirect is a new request, checked again.
    let resp = h
        .exchange(b"GET http://forbidden.example.net/ HTTP/1.1\r\nHost: forbidden.example.net\r\n\r\n")
        .await;
    assert_eq!(reason(&resp), Some("denied-domain"));
    assert_eq!(h.connector.attempts().len(), 1);
}

#[test]
fn absolute_uris_become_origin_form() {
    let cases = [
        ("http://example.com", "GET / HTTP/1.1\r\nHost: example.com\r\n"),
        ("http://example.com?x=1", "GET /?x=1 HTTP/1.1\r\nHost: example.com\r\n"),
        ("HTTP://example.com/a#frag", "GET /a HTTP/1.1\r\nHost: example.com\r\n"),
        (
            "http://example.com:8080/a",
            "GET /a HTTP/1.1\r\nHost: example.com:8080\r\n",
        ),
    ];
    for (uri, want) in cases {
        let req = parse_head(format!("GET {uri} HTTP/1.1\r\nHost: evil.example.net\r\n\r\n").as_bytes()).unwrap();
        let Request::Http { head, .. } = req else {
            panic!("{uri} is not plain HTTP");
        };
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with(want), "{uri}: {head:?}");
        assert!(
            !head.contains("evil"),
            "the client's Host header must be replaced: {head:?}"
        );
    }
}

#[test]
fn malformed_heads_are_bad_requests() {
    let cases: &[&[u8]] = &[
        b"\r\n\r\n",
        b"GET\r\n\r\n",
        b"GET  http://example.com/ HTTP/1.1\r\n\r\n",
        b"get http://example.com/ HTTP/1.1\r\n\r\n",
        b"GET /relative HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET https://example.com/ HTTP/1.1\r\n\r\n",
        b"GET ftp://example.com/ HTTP/1.1\r\n\r\n",
        b"GET http://user:pw@example.com/ HTTP/1.1\r\n\r\n",
        b"GET http:// HTTP/1.1\r\n\r\n",
        b"GET http://example.com/ HTTP/2.0\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1 extra\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\n folded\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\nNo colon\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\nBad Name: x\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\nX: a\rb\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\nX: a\nb\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\nX: a\x00b\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
        b"GET http://ex\xc3\xa1mple.com/ HTTP/1.1\r\n\r\n",
        b"GET http://example.com/\xff HTTP/1.1\r\n\r\n",
        b"CONNECT example.com HTTP/1.1\r\n\r\n",
        b"CONNECT :443 HTTP/1.1\r\n\r\n",
        b"CONNECT example.com: HTTP/1.1\r\n\r\n",
        b"CONNECT example.com:0 HTTP/1.1\r\n\r\n",
        b"CONNECT example.com:65536 HTTP/1.1\r\n\r\n",
        b"CONNECT example.com:+443 HTTP/1.1\r\n\r\n",
        b"CONNECT example.com:443x HTTP/1.1\r\n\r\n",
        b"CONNECT [::1 HTTP/1.1\r\n\r\n",
        b"CONNECT [::1]x HTTP/1.1\r\n\r\n",
        b"CONNECT user@example.com:443 HTTP/1.1\r\n\r\n",
    ];
    for raw in cases {
        let r: Result<Request, BadRequest> = parse_head(raw);
        assert!(r.is_err(), "{:?} parsed as {r:?}", String::from_utf8_lossy(raw));
    }
}

#[tokio::test]
async fn bad_requests_get_400_through_the_proxy() {
    let h = Setup::default().build();
    for raw in [
        &b"GET /relative HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
        b"GET https://example.com/ HTTP/1.1\r\n\r\n",
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\r\n\r\n",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    ] {
        let resp = h.exchange(raw).await;
        assert_eq!(status(&resp), "HTTP/1.1 400 Bad Request", "{resp:?}");
    }
    assert_eq!(h.shared.stats().bad_requests, 4);
    assert!(h.connector.attempts().is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// Limits: header size, slowloris, idle tunnels, timeouts, byte cap
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_head_over_16_kib_gets_400() {
    let h = Setup::default().build();
    let mut raw = b"GET http://example.com/ HTTP/1.1\r\n".to_vec();
    raw.extend_from_slice(format!("X-Big: {}\r\n", "a".repeat(16 * 1024)).as_bytes());
    raw.extend_from_slice(b"\r\n");
    let resp = h.exchange(&raw).await;
    assert_eq!(status(&resp), "HTTP/1.1 400 Bad Request", "{resp:?}");
    assert!(h.connector.attempts().is_empty());

    // Just under the limit is fine.
    let h = Setup {
        upstream: Upstream::Http(REDIRECT),
        ..Setup::default()
    }
    .build();
    let mut raw = b"GET http://example.com/ HTTP/1.1\r\n".to_vec();
    let filler = 16 * 1024 - raw.len() - "X-Big: \r\n\r\n".len();
    raw.extend_from_slice(format!("X-Big: {}\r\n\r\n", "a".repeat(filler)).as_bytes());
    assert_eq!(raw.len(), 16 * 1024);
    let resp = h.exchange(&raw).await;
    assert_eq!(resp.as_bytes(), REDIRECT);
}

#[tokio::test(start_paused = true)]
async fn slowloris_heads_are_closed_after_the_idle_timeout() {
    let h = Setup::default().build();
    let (c, task) = h.client();
    let (mut r, mut w) = tokio::io::split(c);
    let start = tokio::time::Instant::now();
    w.write_all(b"CONNECT exa").await.unwrap();
    // Trickle a byte every 50 s: each one is within the idle timeout, but the head as a whole is not.
    let trickle = tokio::spawn(async move {
        for b in b"mple.com:4" {
            tokio::time::sleep(Duration::from_secs(50)).await;
            if w.write_all(&[*b]).await.is_err() {
                break;
            }
        }
    });
    let mut out = Vec::new();
    let _ = r.read_to_end(&mut out).await;
    trickle.abort();
    task.await.unwrap();
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_secs(120), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(121), "{elapsed:?}");
    assert!(h.connector.attempts().is_empty());
}

#[tokio::test(start_paused = true)]
async fn idle_tunnels_are_closed_after_the_idle_timeout() {
    let h = Setup::default().build();
    let (head, mut c, task) = h.connect("example.com:443").await;
    assert_eq!(status(&head), "HTTP/1.1 200 Connection Established");
    let start = tokio::time::Instant::now();
    // Traffic resets the timer.
    tokio::time::sleep(Duration::from_secs(100)).await;
    c.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    c.read_exact(&mut buf).await.unwrap();
    // Then silence: the tunnel closes 120 s after the last byte.
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out).await;
    task.await.unwrap();
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_secs(220), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(221), "{elapsed:?}");
    assert_eq!(h.shared.records()[0].bytes_up, 4);
}

#[tokio::test(start_paused = true)]
async fn the_lookup_times_out_after_5_s() {
    let h = Setup {
        hang_resolver: true,
        ..Setup::default()
    }
    .build();
    let start = tokio::time::Instant::now();
    let resp = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(status(&resp), "HTTP/1.1 504 Gateway Timeout", "{resp:?}");
    assert_eq!(reason(&resp), Some("resolve-timeout"));
    assert_eq!(start.elapsed().as_secs(), 5);
}

#[tokio::test(start_paused = true)]
async fn the_connect_times_out_after_10_s() {
    let h = Setup {
        upstream: Upstream::Hang,
        ..Setup::default()
    }
    .build();
    let start = tokio::time::Instant::now();
    let resp = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(reason(&resp), Some("connect-timeout"), "{resp:?}");
    assert_eq!(start.elapsed().as_secs(), 10);
    assert_eq!(h.connector.attempts(), vec![sa(PUBLIC_V4, 443)]);
}

#[tokio::test]
async fn the_byte_cap_stops_relaying_and_refuses_new_connections() {
    let h = Setup {
        limits: Limits {
            max_total_bytes: Some(8),
            ..Limits::default()
        },
        ..Setup::default()
    }
    .build();
    let (_, mut c, task) = h.connect("example.com:443").await;
    c.write_all(b"hi").await.unwrap();
    let mut buf = [0u8; 2];
    c.read_exact(&mut buf).await.unwrap();
    // 4 of 8 used. Five more bytes up would exceed the cap: the tunnel closes and nothing more is relayed.
    c.write_all(b"hello").await.unwrap();
    let mut rest = Vec::new();
    let _ = c.read_to_end(&mut rest).await;
    task.await.unwrap();
    assert!(rest.is_empty(), "{rest:?}");
    let stats = h.shared.stats();
    assert!(stats.bytes_up + stats.bytes_down <= 8, "{stats:?}");

    let resp = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(reason(&resp), Some("byte-cap"), "{resp:?}");
}

// ---------------------------------------------------------------------------------------------------------------
// Accounting
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn counters_and_records_are_exact_and_hold_no_payload() {
    let h = Setup::default().build();
    let (_, mut c, task) = h.connect("a.example.com:443").await;
    c.write_all(b"secret-payload").await.unwrap();
    let mut buf = [0u8; 14];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"secret-payload");
    c.shutdown().await.unwrap();
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).await.unwrap();
    task.await.unwrap();

    let _ = h.exchange(&connect_req("evilexample.com:443")).await;
    let _ = h.exchange(&connect_req("example.com:22")).await;
    let _ = h.exchange(&connect_req("[::1]:443")).await;

    let records = h.shared.records();
    let short = |r: &Record| (r.host.clone(), r.port, r.bytes_up, r.bytes_down, r.verdict);
    assert_eq!(
        records.iter().map(short).collect::<Vec<_>>(),
        vec![
            ("a.example.com".to_string(), 443, 14, 14, Verdict::Allowed),
            ("evilexample.com".to_string(), 443, 0, 0, Verdict::DeniedDomain),
            ("example.com".to_string(), 22, 0, 0, Verdict::DeniedPort),
            ("[::1]".to_string(), 443, 0, 0, Verdict::IpLiteral),
        ]
    );
    let stats = h.shared.stats();
    assert_eq!((stats.bytes_up, stats.bytes_down), (14, 14));
    assert!(!format!("{records:?} {stats:?}").contains("secret"));
}

#[tokio::test]
async fn records_are_bounded() {
    let h = Setup {
        limits: Limits {
            max_records: 2,
            ..Limits::default()
        },
        ..Setup::default()
    }
    .build();
    for _ in 0..5 {
        let _ = h.exchange(&connect_req("evilexample.com:443")).await;
    }
    assert_eq!(h.shared.records().len(), 2);
    assert_eq!(h.shared.stats().records_dropped, 3);
}

#[tokio::test]
async fn shutdown_closes_open_tunnels() {
    let h = Setup::default().build();
    let (_, mut c, task) = h.connect("example.com:443").await;
    h.shutdown.send(true).unwrap();
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out).await;
    task.await.unwrap();
    assert_eq!(h.shared.records().len(), 1);
}

// ---------------------------------------------------------------------------------------------------------------
// The unix socket and end to end through a test-only TCP → unix bridge (the shim's job, T08)
// ---------------------------------------------------------------------------------------------------------------

/// A fresh directory for one test, mode 0700, removed on drop.
struct TestDir(std::path::PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("p2pc-egress-{}-{name}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An in-memory stand-in for the unix socket: the AI development sandbox forbids `AF_UNIX`, so most socket-level
/// tests run the real accept loop over this instead. `unix_socket_end_to_end` covers the real socket.
#[derive(Debug)]
struct MemListener(tokio::sync::mpsc::Receiver<DuplexStream>);

impl Listener for MemListener {
    type Conn = DuplexStream;
    async fn next_conn(&mut self) -> io::Result<DuplexStream> {
        self.0
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

/// Starts the real accept loop on an in-memory listener. Returns the handle and the "connect" side.
fn start_in_memory(policy: Policy) -> (EgressHandle, tokio::sync::mpsc::Sender<DuplexStream>) {
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    (spawn(MemListener(rx), policy, std::path::PathBuf::new()), tx)
}

/// Opens a client connection to an in-memory proxy.
async fn dial(tx: &tokio::sync::mpsc::Sender<DuplexStream>) -> DuplexStream {
    let (ours, theirs) = duplex(1 << 16);
    tx.send(theirs).await.unwrap();
    ours
}

/// What the shim does inside the container (T08): accept on loopback TCP and bridge each connection to the proxy.
/// This one bridges to the in-memory listener.
async fn test_bridge_to_memory(tx: tokio::sync::mpsc::Sender<DuplexStream>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let mut proxy_side = dial(&tx).await;
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut proxy_side).await;
            });
        }
    });
    addr
}

/// The same bridge, to the real unix socket.
async fn test_bridge(socket: std::path::PathBuf) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let socket = socket.clone();
            tokio::spawn(async move {
                if let Ok(mut unix) = tokio::net::UnixStream::connect(&socket).await {
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut unix).await;
                }
            });
        }
    });
    addr
}

/// A TLS-less echo server on loopback, standing in for the "public" server.
async fn echo_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Drives one `CONNECT` through `bridge` to the echo server and back, then one refused request.
async fn connect_through(bridge: SocketAddr) {
    let mut c = tokio::net::TcpStream::connect(bridge).await.unwrap();
    c.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while request::head_len(&head).is_none() {
        c.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    assert_eq!(head, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    c.write_all(b"ping over the tunnel").await.unwrap();
    let mut buf = [0u8; 20];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping over the tunnel");
    c.shutdown().await.unwrap();
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());

    let mut c = tokio::net::TcpStream::connect(bridge).await.unwrap();
    c.write_all(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n").await.unwrap();
    let mut resp = Vec::new();
    c.read_to_end(&mut resp).await.unwrap();
    assert_eq!(reason(&String::from_utf8_lossy(&resp)), Some("ip-literal"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_connect_through_the_bridge() {
    let echo = echo_server().await;
    let (policy, resolver, connector) = Setup {
        upstream: Upstream::Local(echo),
        ..Setup::default()
    }
    .policy();
    let (handle, tx) = start_in_memory(policy);
    let bridge = test_bridge_to_memory(tx).await;

    connect_through(bridge).await;

    // The fake resolver mapped example.com to the "public" 1.1.1.1; the fake connector reached the echo server.
    assert_eq!(connector.attempts(), vec![sa(PUBLIC_V4, 443)]);
    assert_eq!(resolver.queries(), vec!["example.com"]);
    handle.shutdown().await;
}

#[tokio::test]
#[ignore = "needs AF_UNIX sockets, which the AI development sandbox forbids; CI runs it with \
            `cargo test -p p2pc-agent --lib -- --ignored egress::tests::unix_socket`"]
async fn unix_socket_end_to_end() {
    let dir = TestDir::new("e2e");
    let socket = dir.0.join("egress.sock");
    let echo = echo_server().await;
    let (policy, resolver, connector) = Setup {
        upstream: Upstream::Local(echo),
        ..Setup::default()
    }
    .policy();
    let handle = EgressProxy::start(&socket, policy).unwrap();
    assert_eq!(handle.socket_path(), socket);

    let meta = std::fs::symlink_metadata(&socket).unwrap();
    assert!(std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type()));
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    // The staging directory is gone: only the socket is left in the job's directory.
    let entries: Vec<_> = std::fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(entries, vec!["egress.sock".to_string()]);

    let bridge = test_bridge(socket.clone()).await;
    connect_through(bridge).await;
    assert_eq!(connector.attempts(), vec![sa(PUBLIC_V4, 443)]);
    assert_eq!(resolver.queries(), vec!["example.com"]);
    assert_eq!(handle.stats().connections, 2);

    // A second proxy cannot take over the same path.
    let (policy, _, _) = Setup::default().policy();
    assert!(matches!(
        EgressProxy::start(&socket, policy),
        Err(StartError::AlreadyExists)
    ));

    handle.shutdown().await;
    assert!(
        std::fs::symlink_metadata(&socket).is_err(),
        "the socket file is removed on shutdown"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn records_are_kept_by_the_handle() {
    let (policy, _, _) = Setup::default().policy();
    let (handle, tx) = start_in_memory(policy);
    let mut c = dial(&tx).await;
    c.write_all(&connect_req("evilexample.com:443")).await.unwrap();
    let mut resp = Vec::new();
    c.read_to_end(&mut resp).await.unwrap();
    assert_eq!(reason(&String::from_utf8_lossy(&resp)), Some("denied-domain"));
    // The record is pushed before the connection is closed, so it is visible as soon as the client sees EOF.
    let records = handle.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].verdict, Verdict::DeniedDomain);
    assert_eq!(handle.stats().connections, 1);
    handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connections_over_the_limit_get_503() {
    let (policy, _, _) = Setup {
        limits: Limits {
            max_connections: 1,
            ..Limits::default()
        },
        ..Setup::default()
    }
    .policy();
    let (handle, tx) = start_in_memory(policy);
    // The first connection holds the only slot (its head never completes). The channel is FIFO, so it is
    // accepted before the second one.
    let mut first = dial(&tx).await;
    first.write_all(b"CONNECT exa").await.unwrap();
    let mut second = dial(&tx).await;
    let mut resp = Vec::new();
    second.read_to_end(&mut resp).await.unwrap();
    let resp = String::from_utf8_lossy(&resp);
    assert_eq!(status(&resp), "HTTP/1.1 503 Service Unavailable", "{resp:?}");
    assert_eq!(reason(&resp), Some("too-many-connections"));
    assert_eq!(handle.stats().rejected_busy, 1);
    assert_eq!(handle.stats().connections, 1);
    // Shutdown closes the first connection too, and waits for it.
    handle.shutdown().await;
    let mut rest = Vec::new();
    first.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_handle_stops_the_proxy() {
    let (policy, _, _) = Setup::default().policy();
    let (handle, tx) = start_in_memory(policy);
    let mut c = dial(&tx).await;
    c.write_all(b"CONNECT exa").await.unwrap();
    drop(handle);
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
}

#[tokio::test]
async fn the_socket_directory_must_be_safe() {
    let dir = TestDir::new("unsafe");
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    let (policy, _, _) = Setup::default().policy();
    let err = EgressProxy::start(dir.0.join("egress.sock"), policy).unwrap_err();
    assert!(matches!(err, StartError::UnsafeDirectory(_)), "{err:?}");

    let dir = TestDir::new("exists");
    let socket = dir.0.join("egress.sock");
    std::fs::write(&socket, b"").unwrap();
    let (policy, _, _) = Setup::default().policy();
    let err = EgressProxy::start(&socket, policy).unwrap_err();
    assert!(matches!(err, StartError::AlreadyExists), "{err:?}");

    let (policy, _, _) = Setup::default().policy();
    let err = EgressProxy::start(dir.0.join("missing").join("egress.sock"), policy).unwrap_err();
    assert!(matches!(err, StartError::Io(_)), "{err:?}");
}

// ---------------------------------------------------------------------------------------------------------------
// T10n: a socket path longer than `sun_path` (108 bytes, ACC-1 round 2). `bind(2)` takes the path in a 108-byte field,
// so the socket is bound through `/proc/self/fd/<dir>/<name>`, which is short whatever the directory's own path is.
// ---------------------------------------------------------------------------------------------------------------

/// `sun_path` in bytes, with its trailing NUL.
const SUN_PATH_LEN: usize = 108;

/// A directory under `base` whose own path is `len` bytes or more, made of nested components. Every component is
/// created 0700 and set to 0700 explicitly, so the result passes `check_socket_dir` whatever the umask is.
fn long_dir(base: &Path, len: usize) -> std::path::PathBuf {
    let mut dir = base.to_path_buf();
    while dir.as_os_str().len() < len {
        dir.push("a-long-directory-name-for-a-data-dir");
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

/// The path the old code bound: `<dir>/.egress-staging-<pid>-<seq>/egress.sock`.
fn old_staging_path_len(dir: &Path) -> usize {
    dir.join(format!(".egress-staging-{}-{}", std::process::id(), 0))
        .join("egress.sock")
        .as_os_str()
        .len()
}

#[test]
fn the_fd_path_is_short_and_reaches_the_directory() {
    let base = TestDir::new("fdpath");
    let dir = long_dir(&base.0, 300);
    let fd = open_dir(&dir).unwrap();
    let via = via_fd(&fd, STAGED_NAME);
    assert!(via.as_os_str().len() < SUN_PATH_LEN, "{via:?}");
    assert!(dir.as_os_str().len() >= SUN_PATH_LEN);
    // Creating a file through it creates it inside the directory, and nothing else resolves it.
    std::fs::write(&via, b"x").unwrap();
    assert_eq!(std::fs::read(dir.join(STAGED_NAME)).unwrap(), b"x");
    // A renamed directory is still the same directory: the fd, not the name, is what the path follows.
    let moved = base.0.join("moved");
    std::fs::rename(&dir, &moved).unwrap();
    assert_eq!(std::fs::read(&via).unwrap(), b"x");
}

#[test]
fn a_socket_that_cannot_be_made_says_where_and_why() {
    let base = TestDir::new("why");
    let dir = base.0.join("missing");
    let err = check_socket_creation(&dir).unwrap_err().to_string();
    assert!(err.contains(&dir.display().to_string()), "{err}");
}

#[test]
#[ignore = "needs AF_UNIX sockets, which the AI development sandbox forbids; CI runs it with \
            `cargo test --locked -p p2pc-agent --lib -- --ignored egress::tests::unix_socket`"]
fn unix_socket_is_bound_inside_the_directory_whatever_its_path_length() {
    let base = TestDir::new("bindfd");
    let dir = long_dir(&base.0, 300);
    let fd = open_dir(&dir).unwrap();
    let listener = bind_in(&fd, STAGED_NAME).unwrap();
    let meta = std::fs::symlink_metadata(dir.join(STAGED_NAME)).unwrap();
    assert!(std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type()));
    drop(listener);
}

#[tokio::test]
#[ignore = "needs AF_UNIX sockets, which the AI development sandbox forbids; CI runs it with \
            `cargo test --locked -p p2pc-agent --lib -- --ignored egress::tests::unix_socket`"]
async fn unix_socket_in_a_long_data_dir_is_made_whole() {
    let base = TestDir::new("longdir");
    // The job's `p2pc/` directory under a data dir long enough that the old staging path is over `sun_path`.
    let dir = long_dir(&base.0, 100);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        old_staging_path_len(&dir) > SUN_PATH_LEN,
        "{}",
        old_staging_path_len(&dir)
    );
    let socket = dir.join("egress.sock");
    let (policy, _, _) = Setup::default().policy();
    let me = (rustix::process::geteuid().as_raw(), rustix::process::getegid().as_raw());
    let handle = EgressProxy::start_with(&socket, policy, SocketOptions { owner: Some(me) }).unwrap();

    let meta = std::fs::symlink_metadata(&socket).unwrap();
    assert!(std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type()));
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!((meta.uid(), meta.gid()), me);
    // No staging directory is left behind: only the socket is in the job's directory.
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(entries, vec!["egress.sock".to_string()]);

    // A second start does not take over the path.
    let (policy, _, _) = Setup::default().policy();
    assert!(matches!(
        EgressProxy::start(&socket, policy),
        Err(StartError::AlreadyExists)
    ));
    handle.shutdown().await;
    assert!(std::fs::symlink_metadata(&socket).is_err());
}

#[test]
#[ignore = "needs AF_UNIX sockets, which the AI development sandbox forbids; CI runs it with \
            `cargo test --locked -p p2pc-agent --lib -- --ignored egress::tests::unix_socket`"]
fn unix_socket_doctor_check_works_in_a_long_data_dir_and_leaves_nothing() {
    use p2pc_proto::ids::LeaseId;

    let base = TestDir::new("doctorok");
    // A data dir for which the old staging path of a job's socket, `<data>/jobs/<lease>/p2pc/.egress-staging-…/
    // egress.sock`, is over `sun_path`.
    let data_dir = long_dir(&base.0, 60);
    let job_p2pc = crate::sandbox::jobdir::job_dir_path(&data_dir, &LeaseId::generate()).join("p2pc");
    assert!(
        old_staging_path_len(&job_p2pc) > SUN_PATH_LEN,
        "{}",
        old_staging_path_len(&job_p2pc)
    );
    // The check that `p2pc-agent doctor` runs, with the job directory made the way a job's is.
    assert_eq!(
        crate::doctor::check_egress_socket(&data_dir),
        crate::doctor::EgressSocketState::Ok
    );
    // Nothing is left: `jobs/` did not exist before, so it does not exist now.
    assert!(!data_dir.join("jobs").exists());
}

/// The doctor check leaves `jobs/` as it found it: made by the check, it is removed; already there, it stays.
#[test]
#[ignore = "needs AF_UNIX sockets, which the AI development sandbox forbids; CI runs it with \
            `cargo test --locked -p p2pc-agent --lib -- --ignored egress::tests::unix_socket`"]
fn unix_socket_doctor_check_leaves_jobs_as_it_found_it() {
    let base = TestDir::new("doctorjobs");
    let data_dir = long_dir(&base.0, 20);
    let jobs = data_dir.join("jobs");
    assert_eq!(
        crate::doctor::check_egress_socket(&data_dir),
        crate::doctor::EgressSocketState::Ok
    );
    assert!(!jobs.exists(), "the check made jobs/ and must remove it");
    // With a `jobs/` already there (and a job in it), the check leaves both alone.
    std::fs::create_dir_all(jobs.join("someone-elses-job")).unwrap();
    assert_eq!(
        crate::doctor::check_egress_socket(&data_dir),
        crate::doctor::EgressSocketState::Ok
    );
    let left: Vec<_> = std::fs::read_dir(&jobs)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(left, vec!["someone-elses-job".to_string()]);
}

// ---------------------------------------------------------------------------------------------------------------
// Spec §9 "Egress proxy" test vectors (from experiment E8). One named, table-driven test per vector, each driven
// through the whole proxy with the allowlist `["example.com"]`.
// ---------------------------------------------------------------------------------------------------------------

/// Sends `raw` and asserts the exact status and `X-P2PC-Egress` reason, and that nothing was resolved or connected.
async fn assert_refused_before_dns(raw: &str, want_status: &str, want_reason: &str, allow: Vec<&'static str>) {
    let h = Setup {
        allow,
        ..Setup::default()
    }
    .build();
    let resp = h.exchange(raw.as_bytes()).await;
    assert_eq!(status(&resp), want_status, "{raw:?}: {resp:?}");
    assert_eq!(reason(&resp), Some(want_reason), "{raw:?}: {resp:?}");
    assert!(h.resolver.queries().is_empty(), "{raw:?} was resolved");
    assert!(h.connector.attempts().is_empty(), "{raw:?} reached the connector");
}

/// Vector 1: look-alike names are refused on whole labels (SI-5).
#[tokio::test]
async fn vector_1_lookalike_domains_are_refused() {
    for host in [
        "evilexample.com",
        "example.com.evil.net",
        "a.evilexample.com",
        "EVILEXAMPLE.COM",
        "example.com.evil.net.",
    ] {
        assert_refused_before_dns(
            &format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 403 Forbidden",
            "denied-domain",
            vec!["example.com"],
        )
        .await;
        assert_refused_before_dns(
            &format!("GET http://{host}/ HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 403 Forbidden",
            "denied-domain",
            vec!["example.com"],
        )
        .await;
    }
}

/// Vector 2: a trailing dot and uppercase are **allowed**: they are normalized (lowercase, one trailing dot
/// stripped) to `example.com` before matching and before the lookup. Whole-label matching still holds after
/// normalization, and a double trailing dot is refused.
#[tokio::test]
async fn vector_2_trailing_dot_and_uppercase_are_normalised() {
    let allowed = [
        ("example.com.", "example.com"),
        ("EXAMPLE.com", "example.com"),
        ("EXAMPLE.COM.", "example.com"),
        ("A.Example.Com.", "a.example.com"),
    ];
    for (host, resolved_as) in allowed {
        let h = Setup::default().build();
        let (head, c, task) = h.connect(&format!("{host}:443")).await;
        assert_eq!(status(&head), "HTTP/1.1 200 Connection Established", "{host}: {head:?}");
        drop(c);
        task.await.unwrap();
        assert_eq!(h.resolver.queries(), vec![resolved_as], "{host}");
        assert_eq!(h.connector.attempts(), vec![sa(PUBLIC_V4, 443)], "{host}");
        // The record keeps the host as the client wrote it.
        assert_eq!(h.shared.records()[0].host, host);
    }
    for host in [
        "EVILEXAMPLE.COM.",
        "example.com..",
        ".example.com",
        "Example.Com.Evil.Net.",
    ] {
        assert_refused_before_dns(
            &format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 403 Forbidden",
            "denied-domain",
            vec!["example.com"],
        )
        .await;
    }
}

/// Vector 3: IPv4 and IPv6 literals, bracketed, IPv4-mapped, and the decimal, octal and hex IPv4 spellings of
/// `192.0.2.1` (`3221225985`, `0300.0.2.1`, `0xc0.0.2.1`, `0xc0000201`, `192.0.513`). All are refused before any
/// lookup, even when the allowlist names the literal itself.
#[tokio::test]
async fn vector_3_ip_literals_are_refused() {
    let connect_targets = [
        ("192.0.2.1:443", "192.0.2.1"),
        ("192.0.2.1.:443", "192.0.2.1."),
        ("[2001:db8::1]:443", "[2001:db8::1]"),
        ("2001:db8::1:443", "2001:db8::1"),
        ("[::ffff:192.0.2.1]:443", "[::ffff:192.0.2.1]"),
        ("[::ffff:c000:201]:443", "[::ffff:c000:201]"),
        ("[::192.0.2.1]:443", "[::192.0.2.1]"),
        ("[2001:db8::1%25eth0]:443", "[2001:db8::1%25eth0]"),
        ("3221225985:443", "3221225985"),
        ("0300.0.2.1:443", "0300.0.2.1"),
        ("0300.0000.0002.0001:443", "0300.0000.0002.0001"),
        ("0xc0.0.2.1:443", "0xc0.0.2.1"),
        ("0xc0000201:443", "0xc0000201"),
        ("0XC0.0X0.0X2.0X1:443", "0XC0.0X0.0X2.0X1"),
        ("192.0.513:443", "192.0.513"),
        ("192.513:443", "192.513"),
    ];
    for (target, literal) in connect_targets {
        assert_refused_before_dns(
            &format!("CONNECT {target} HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 403 Forbidden",
            "ip-literal",
            vec!["example.com", literal],
        )
        .await;
    }
    for uri in [
        "http://192.0.2.1/",
        "http://[2001:db8::1]/",
        "http://[2001:db8::1]:80/",
        "http://[::ffff:192.0.2.1]/",
        "http://3221225985/",
        "http://0300.0.2.1/",
        "http://0xc0.0.2.1/",
    ] {
        assert_refused_before_dns(
            &format!("GET {uri} HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            "HTTP/1.1 403 Forbidden",
            "ip-literal",
            vec!["example.com"],
        )
        .await;
    }
}

/// Vector 4: `user@host` and `host/path`. Decision: **refused as malformed (`400 bad-request`)**, never parsed
/// leniently. Userinfo is refused anywhere in an authority (a `CONNECT` target or an absolute URI), and a
/// `CONNECT` authority may not contain `/`, `?`, `#` or `\`, so no parser differential can make the proxy check
/// one host and a client or upstream use another.
#[tokio::test]
async fn vector_4_userinfo_and_paths_are_refused() {
    for raw in [
        "CONNECT user@example.com:443 HTTP/1.1\r\n\r\n",
        "CONNECT user:pw@example.com:443 HTTP/1.1\r\n\r\n",
        "CONNECT example.com@evil.example.net:443 HTTP/1.1\r\n\r\n",
        "CONNECT example.com/path:443 HTTP/1.1\r\n\r\n",
        "CONNECT example.com:443/path HTTP/1.1\r\n\r\n",
        "CONNECT example.com?x:443 HTTP/1.1\r\n\r\n",
        "CONNECT example.com#x:443 HTTP/1.1\r\n\r\n",
        "CONNECT example.com\\evil.example.net:443 HTTP/1.1\r\n\r\n",
        "GET http://user@example.com/ HTTP/1.1\r\n\r\n",
        "GET http://user:pw@example.com/path HTTP/1.1\r\n\r\n",
        "GET http://example.com@evil.example.net/ HTTP/1.1\r\n\r\n",
        "GET http://example.com\\@evil.example.net/ HTTP/1.1\r\n\r\n",
    ] {
        assert_refused_before_dns(raw, "HTTP/1.1 400 Bad Request", "bad-request", vec!["example.com"]).await;
    }
}

/// Vector 5: `CONNECT` (and plain HTTP) to a port outside `{80, 443}` is refused before the lookup.
#[tokio::test]
async fn vector_5_disallowed_ports_are_refused() {
    for port in [22, 25, 1, 21, 3128, 6443, 8080, 8443, 65535] {
        assert_refused_before_dns(
            &format!("CONNECT example.com:{port} HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 403 Forbidden",
            "denied-port",
            vec!["example.com"],
        )
        .await;
        assert_refused_before_dns(
            &format!("GET http://example.com:{port}/ HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 403 Forbidden",
            "denied-port",
            vec!["example.com"],
        )
        .await;
    }
    // The allowed ports, as a control.
    for port in [80, 443] {
        let h = Setup::default().build();
        let (head, c, task) = h.connect(&format!("example.com:{port}")).await;
        assert_eq!(status(&head), "HTTP/1.1 200 Connection Established", "{port}");
        drop(c);
        task.await.unwrap();
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Review of PR #5. P2: the owner's IPv6 LAN (/56 around global-unicast addresses, on-link routes)
// ---------------------------------------------------------------------------------------------------------------

fn v6net(s: &str, len: u8) -> Cidr {
    Cidr::V6(s.parse().unwrap(), len)
}

/// A setup whose only host network is `interfaces` (plus `onlink_routes`), resolving `example.com` to `answer`.
fn lan_setup(interfaces: Vec<Cidr>, onlink_routes: Vec<Cidr>, answer: &'static str) -> Setup {
    Setup {
        answers: vec![("example.com", vec![answer])],
        host_nets: Some(HostNets {
            interfaces,
            onlink_routes,
        }),
        ..Setup::default()
    }
}

#[tokio::test]
async fn a_dhcpv6_slash128_still_blocks_its_slash64_and_sibling_slash64s_in_the_slash56() {
    // The host got a /128 from DHCPv6: the interface prefix says nothing about the LAN around it.
    let iface = vec![v6net("2606:4700:aa00:1::5", 128)];
    for (answer, why) in [
        ("2606:4700:aa00:1::5", "the host's own address"),
        ("2606:4700:aa00:1::9", "a neighbour in the same /64"),
        ("2606:4700:aa00:2::1", "a sibling /64 in the same /56"),
        ("2606:4700:aa00:ff:ffff:ffff:ffff:ffff", "the last address of the /56"),
    ] {
        let h = lan_setup(iface.clone(), vec![], answer).build();
        let resp = h.exchange(&connect_req("example.com:443")).await;
        assert_eq!(reason(&resp), Some("denied-address"), "{answer} ({why}): {resp:?}");
        assert!(h.connector.attempts().is_empty(), "{answer} ({why})");
    }
    // Just outside the /56: allowed.
    let h = lan_setup(iface, vec![], "2606:4700:aa00:100::1").build();
    let (head, c, task) = h.connect("example.com:443").await;
    assert_eq!(status(&head), "HTTP/1.1 200 Connection Established", "{head:?}");
    drop(c);
    task.await.unwrap();
}

#[test]
fn the_lan_prefix_is_configurable_and_never_narrows_the_interface_prefix() {
    let addr = |s: &str| ip(s);
    let nets = |ifaces: Vec<Cidr>| HostNets {
        interfaces: ifaces,
        onlink_routes: vec![],
    };
    // Default /56.
    let set = host_deny_set(&nets(vec![v6net("2606:4700:aa00:1::5", 128)]), 56, &[]);
    assert_eq!(set, vec![v6net("2606:4700:aa00:1::5", 56)]);
    assert!(check_addr(addr("2606:4700:aa00:2::1"), &set).is_err());
    // Configured /64: the sibling /64 is no longer refused, the own /64 still is.
    let set = host_deny_set(&nets(vec![v6net("2606:4700:aa00:1::5", 128)]), 64, &[]);
    assert!(check_addr(addr("2606:4700:aa00:1::9"), &set).is_err());
    assert!(check_addr(addr("2606:4700:aa00:2::1"), &set).is_ok());
    // An interface prefix wider than /56 (a /48) is kept: the /56 only ever adds.
    let set = host_deny_set(&nets(vec![v6net("2606:4700:aa00:1::5", 48)]), 56, &[]);
    assert_eq!(set, vec![v6net("2606:4700:aa00:1::5", 48)]);
    assert!(check_addr(addr("2606:4700:aa00:4200::1"), &set).is_err());
    // IPv4 interfaces and non-global IPv6 (ULA, link-local) are not widened (the static table refuses the latter).
    let v4 = Cidr::V4("1.0.0.2".parse().unwrap(), 32);
    let set = host_deny_set(&nets(vec![v4, v6net("fd00::1", 128), v6net("fe80::1", 64)]), 56, &[]);
    assert_eq!(set, vec![v4, v6net("fd00::1", 128), v6net("fe80::1", 64)]);
    // Out-of-range settings saturate at /128.
    let set = host_deny_set(&nets(vec![v6net("2606:4700:aa00:1::5", 128)]), 200, &[]);
    assert_eq!(set, vec![v6net("2606:4700:aa00:1::5", 128)]);
}

#[tokio::test]
async fn on_link_ipv6_routes_are_refused() {
    // The host's address is in one /56, but the router announces another on-link prefix too.
    let routes = vec![v6net("2606:4700:bb00::", 48)];
    let h = lan_setup(
        vec![v6net("2606:4700:aa00:1::5", 64)],
        routes.clone(),
        "2606:4700:bb00:5::1",
    )
    .build();
    let resp = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(reason(&resp), Some("denied-address"), "{resp:?}");
    assert!(h.connector.attempts().is_empty());

    // A full-tunnel VPN's catch-all "on-link" routes are ignored, or they would refuse all IPv6.
    let catch_all = vec![v6net("::", 1), v6net("8000::", 1), v6net("2000::", 3)];
    let set = host_deny_set(
        &HostNets {
            interfaces: vec![],
            onlink_routes: catch_all,
        },
        56,
        &[],
    );
    assert!(set.is_empty(), "{set:?}");
    let set = host_deny_set(
        &HostNets {
            interfaces: vec![],
            onlink_routes: vec![v6net("2606:4700::", MIN_ONLINK_ROUTE_PREFIX_V6)],
        },
        56,
        &[],
    );
    assert_eq!(set.len(), 1, "a /32 on-link route is still refused");
}

/// A `/proc/net/ipv6_route` sample (fields: dest, dest_len, src, src_len, next_hop, metric, refcnt, use, flags,
/// device).
const IPV6_ROUTE_SAMPLE: &str = "\
20010db8000100000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
20010db8000200000000000000000000 38 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001     wg0
20010db8000300000000000000000000 40 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001     ppp0
20010db8000100000000000000000005 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001       lo
20010db8000400000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
20010db8000500000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000000     eth1
ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
garbage line
20010db8 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
zz010db8000100000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
";

#[test]
fn ipv6_route_parser_keeps_only_on_link_destinations() {
    assert_eq!(
        parse_ipv6_route(IPV6_ROUTE_SAMPLE),
        vec![
            v6net("2001:db8:1::", 64),   // on-link /64 on eth0
            v6net("2001:db8:2::", 56),   // on-link /56 on wg0
            v6net("fe80::", 64),         // link-local (also in the static table)
            v6net("::", 0),              // the on-link default route on ppp0 (left out by host_deny_set)
            v6net("2001:db8:1::5", 128), // the host's own address (a local route on lo)
            v6net("ff00::", 8),          // multicast (also in the static table)
        ],
        // Skipped: the route through a gateway, the default route via a gateway, the reject route, the route that
        // is not up, and the malformed lines.
    );
    assert!(parse_ipv6_route("").is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// Review P3-2: hairpin NAT. The node's public addresses (from iroh) are refused.
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_nodes_public_addresses_are_refused() {
    for answer in [
        "1.0.0.7",
        "::ffff:1.0.0.7",
        "2606:4700:cc00:1::1",
        "2606:4700:cc00:9::1",
    ] {
        let h = Setup {
            answers: vec![("example.com", vec![answer])],
            public_addrs: vec!["1.0.0.7", "2606:4700:cc00:1::1"],
            ..Setup::default()
        }
        .build();
        let resp = h.exchange(&connect_req("example.com:443")).await;
        assert_eq!(reason(&resp), Some("denied-address"), "{answer}: {resp:?}");
        assert!(h.connector.attempts().is_empty(), "{answer}");
    }
    // Another public address is still reachable.
    let h = Setup {
        public_addrs: vec!["1.0.0.7"],
        ..Setup::default()
    }
    .build();
    let (head, c, task) = h.connect("example.com:443").await;
    assert_eq!(status(&head), "HTTP/1.1 200 Connection Established");
    drop(c);
    task.await.unwrap();
    assert_eq!(h.connector.attempts(), vec![sa(PUBLIC_V4, 443)]);
}

// ---------------------------------------------------------------------------------------------------------------
// Review P3-3/P3-4: framing headers, and exactly one plain-HTTP request per connection
// ---------------------------------------------------------------------------------------------------------------

const OK_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

#[tokio::test]
async fn a_connection_header_naming_a_framing_header_gets_400() {
    for value in [
        "content-length",
        "Content-Length",
        "close, transfer-encoding",
        "Host",
        "keep-alive,HOST",
    ] {
        let raw = format!("POST http://example.com/ HTTP/1.1\r\nConnection: {value}\r\nContent-Length: 0\r\n\r\n");
        assert_refused_before_dns(&raw, "HTTP/1.1 400 Bad Request", "bad-request", vec!["example.com"]).await;
    }
}

/// RFC 9112 §6.1: `Transfer-Encoding` in an HTTP/1.0 message is faulty framing (a 1.0 recipient would not decode
/// it). The proxy answers 400 and closes, before it resolves or connects anything.
#[tokio::test]
async fn transfer_encoding_in_an_http_1_0_request_gets_400() {
    for raw in [
        "POST http://example.com/u HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "POST http://example.com/u HTTP/1.0\r\ntransfer-encoding: chunked\r\nHost: example.com\r\n\r\n",
        "GET http://example.com/ HTTP/1.0\r\nTransfer-Encoding: identity\r\n\r\n",
    ] {
        assert_refused_before_dns(raw, "HTTP/1.1 400 Bad Request", "bad-request", vec!["example.com"]).await;
    }
    // The connection is closed after the 400.
    let h = Setup::default().build();
    let resp = h
        .exchange(b"POST http://example.com/u HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n")
        .await;
    assert!(resp.to_ascii_lowercase().contains("connection: close"), "{resp:?}");
}

/// HTTP/1.0 without `Transfer-Encoding`, and HTTP/1.1 with it, still work.
#[tokio::test]
async fn http_1_0_alone_and_chunked_http_1_1_are_still_forwarded() {
    let got = http_forwarded(b"GET http://example.com/ HTTP/1.0\r\n\r\n").await;
    assert!(got.starts_with("GET / HTTP/1.0\r\n"), "{got:?}");
    let got =
        http_forwarded(b"POST http://example.com/u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").await;
    assert!(got.contains("Transfer-Encoding: chunked"), "{got:?}");
}

/// Sends `raw` as one write to a plain-HTTP upstream, and returns what the upstream received in total.
async fn http_forwarded(raw: &[u8]) -> String {
    let h = Setup {
        upstream: Upstream::Http(OK_RESPONSE),
        ..Setup::default()
    }
    .build();
    let resp = h.exchange(raw).await;
    assert_eq!(resp.as_bytes(), OK_RESPONSE);
    h.connector.settle().await;
    assert_eq!(h.connector.attempts().len(), 1);
    h.connector.received()
}

#[tokio::test]
async fn a_pipelined_second_request_is_never_forwarded() {
    let got = http_forwarded(
        b"GET http://example.com/a HTTP/1.1\r\nHost: example.com\r\n\r\n\
          GET http://example.com/b HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    assert_eq!(got, "GET /a HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
}

#[tokio::test]
async fn a_body_in_the_same_write_as_the_head_is_forwarded_exactly() {
    let got = http_forwarded(
        b"POST http://example.com/u HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello\
          GET http://evil.example.net/ HTTP/1.1\r\n\r\n",
    )
    .await;
    assert_eq!(
        got,
        "POST /u HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
    );
}

#[tokio::test]
async fn a_chunked_body_is_forwarded_up_to_its_trailers_and_no_further() {
    let body = "5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Checksum: 1\r\n\r\n";
    let raw = format!(
        "POST http://example.com/u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{body}\
         GET http://evil.example.net/ HTTP/1.1\r\n\r\n"
    );
    let got = http_forwarded(raw.as_bytes()).await;
    assert_eq!(
        got,
        format!(
            "POST /u HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{body}"
        )
    );
}

#[tokio::test]
async fn a_malformed_chunked_body_is_not_forwarded() {
    let h = Setup {
        upstream: Upstream::Http(OK_RESPONSE),
        ..Setup::default()
    }
    .build();
    let _ = h
        .exchange(b"POST http://example.com/u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n")
        .await;
    h.connector.settle().await;
    assert_eq!(
        h.connector.received(),
        "POST /u HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
}

#[test]
fn chunk_size_lines() {
    for (line, want) in [
        (&b"5\r\n"[..], Some(5)),
        (b"A\r\n", Some(10)),
        (b"ff;name=value\r\n", Some(255)),
        (b"5 ;ext\r\n", Some(5)),
        (b"0\r\n", Some(0)),
        (b"ffffffffffffffff\r\n", Some(u64::MAX)),
        (b"10000000000000000\r\n", None),
        (b"\r\n", None),
        (b" 5\r\n", None),
        (b"5\n", None),
        (b"5 junk\r\n", None),
        (b"-5\r\n", None),
        (b"+5\r\n", None),
        (b"0x5\r\n", None),
        (b"5;\x01\r\n", None),
    ] {
        assert_eq!(chunk_size(line).ok(), want, "{:?}", String::from_utf8_lossy(line));
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Review P3-6: load on the agent (DNS slots, rate-limited refusal logs)
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn dns_lookups_in_flight_are_capped() {
    let h = Setup {
        hang_resolver: true,
        limits: Limits {
            max_concurrent_lookups: 2,
            ..Limits::default()
        },
        ..Setup::default()
    }
    .build();
    let mut clients = Vec::new();
    for _ in 0..3 {
        let (mut c, task) = h.client();
        c.write_all(&connect_req("example.com:443")).await.unwrap();
        clients.push((c, task));
    }
    // Let every connection run until it blocks (under the 5 s lookup timeout).
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(h.resolver.queries().len(), 2, "the third lookup must wait for a slot");
    assert_eq!(Limits::default().max_concurrent_lookups, 8);
}

#[tokio::test(start_paused = true)]
async fn refusal_logs_are_limited_to_one_per_destination_per_minute() {
    let log = LogLimiter::new("refused");
    let t0 = tokio::time::Instant::now();
    let held = |events| {
        Some(Held {
            events,
            ..Held::default()
        })
    };
    assert_eq!(log.admit("evilexample.com", 443, 0, 0, t0), held(0));
    for s in 1..=9 {
        assert_eq!(
            log.admit("EVILEXAMPLE.com", 443, 0, 0, t0 + Duration::from_secs(s)),
            None
        );
    }
    // Another destination is logged at once.
    assert_eq!(log.admit("evilexample.com", 22, 0, 0, t0), held(0));
    // A minute later: logged again, with the count of what was suppressed.
    assert_eq!(
        log.admit("evilexample.com", 443, 0, 0, t0 + Duration::from_secs(60)),
        held(9)
    );
    assert_eq!(
        log.admit("evilexample.com", 443, 0, 0, t0 + Duration::from_secs(61)),
        None
    );

    // Through the proxy: every refusal is counted, only the first is logged.
    let h = Setup::default().build();
    for _ in 0..5 {
        let _ = h.exchange(&connect_req("evilexample.com:443")).await;
    }
    let stats = h.shared.stats();
    assert_eq!((stats.refusals, stats.refusal_logs_suppressed), (5, 4));
    assert_eq!(h.shared.records().len(), 5, "records are still kept for every refusal");
}

#[test]
fn the_log_limiter_is_bounded() {
    let log = LogLimiter::new("refused");
    let t0 = tokio::time::Instant::now();
    for i in 0..LOG_MAX_KEYS {
        assert!(log.admit(&format!("h{i}.example.com"), 443, 0, 0, t0).is_some());
    }
    // One destination has an event held back.
    assert_eq!(log.admit("h0.example.com", 443, 0, 0, t0), None);
    // Full of fresh entries: a new destination is counted, not logged, and the map does not grow.
    assert_eq!(log.admit("new.example.com", 443, 0, 0, t0), None);
    assert_eq!(log.seen.lock().unwrap().len(), LOG_MAX_KEYS);
    // Once the old entries expire, they are evicted (the held one is logged as it goes, not kept or lost).
    assert_eq!(
        log.admit("new.example.com", 443, 0, 0, t0 + Duration::from_secs(61)),
        Some(Held::default())
    );
    assert_eq!(log.seen.lock().unwrap().len(), 1);
    assert_eq!(log.drain(), 0, "nothing is held back any more");
}

// ---------------------------------------------------------------------------------------------------------------
// Review P3-7: socket permissions. Review P3-8: CONNECT early data.
// ---------------------------------------------------------------------------------------------------------------

/// Limits come from the agent's own configuration, but a bad value must never panic: `Semaphore::new` panics above
/// `Semaphore::MAX_PERMITS`, and `Instant + Duration` panics on overflow. `start_with` refuses them; the
/// internals clamp them anyway.
#[test]
fn extreme_limits_are_refused_by_start_and_never_panic() {
    let ok = Limits::default();
    assert!(ok.validate().is_ok());
    let bad: [(&str, Limits); 10] = [
        (
            "max_connections",
            Limits {
                max_connections: usize::MAX,
                ..ok.clone()
            },
        ),
        (
            "max_connections",
            Limits {
                max_connections: 0,
                ..ok.clone()
            },
        ),
        (
            "max_concurrent_lookups",
            Limits {
                max_concurrent_lookups: usize::MAX,
                ..ok.clone()
            },
        ),
        (
            "max_concurrent_lookups",
            Limits {
                max_concurrent_lookups: 0,
                ..ok.clone()
            },
        ),
        (
            "max_header_bytes",
            Limits {
                max_header_bytes: usize::MAX,
                ..ok.clone()
            },
        ),
        (
            "idle_timeout",
            Limits {
                idle_timeout: Duration::MAX,
                ..ok.clone()
            },
        ),
        (
            "idle_timeout",
            Limits {
                idle_timeout: Duration::ZERO,
                ..ok.clone()
            },
        ),
        (
            "resolve_timeout",
            Limits {
                resolve_timeout: Duration::MAX,
                ..ok.clone()
            },
        ),
        (
            "connect_timeout",
            Limits {
                connect_timeout: Duration::MAX,
                ..ok.clone()
            },
        ),
        (
            "max_records",
            Limits {
                max_records: usize::MAX,
                ..ok.clone()
            },
        ),
    ];
    for (field, limits) in bad {
        let dir = TestDir::new("limits");
        let (mut policy, _, _) = Setup::default().policy();
        policy.limits = limits;
        // Refused before anything touches the filesystem or a socket.
        match EgressProxy::start(dir.0.join("egress.sock"), policy) {
            Err(StartError::InvalidLimits(msg)) => assert!(msg.contains(field), "{field}: {msg}"),
            other => panic!("{field}: {:?}", other.map(|_| ())),
        }
        assert!(
            std::fs::read_dir(&dir.0).unwrap().next().is_none(),
            "{field}: left files behind"
        );
    }
}

#[tokio::test]
async fn extreme_limits_reaching_the_internals_are_clamped() {
    // The crate-private `spawn` skips `start_with`'s validation: nothing may panic there either.
    let (mut policy, _, _) = Setup::default().policy();
    policy.limits = Limits {
        max_connections: usize::MAX,
        max_concurrent_lookups: usize::MAX,
        max_header_bytes: usize::MAX,
        idle_timeout: Duration::MAX,
        resolve_timeout: Duration::MAX,
        connect_timeout: Duration::MAX,
        max_total_bytes: Some(u64::MAX),
        max_records: usize::MAX,
    };
    let (handle, tx) = start_in_memory(policy);
    let mut c = dial(&tx).await;
    c.write_all(&connect_req("example.com:443")).await.unwrap();
    let mut buf = [0u8; 39];
    c.read_exact(&mut buf).await.unwrap();
    assert!(
        buf.starts_with(b"HTTP/1.1 200 Connection Established"),
        "{:?}",
        String::from_utf8_lossy(&buf)
    );
    c.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    c.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");
    handle.shutdown().await;
}

/// The agent's uid comes from `geteuid(2)`: a directory the process creates is owned by it, and so is `/proc/self`
/// while the process is dumpable (which is why it used to work, and why it is not a reliable source).
#[test]
fn the_agent_uid_is_the_owner_of_what_it_creates() {
    let dir = TestDir::new("uid");
    assert_eq!(std::fs::symlink_metadata(&dir.0).unwrap().uid(), agent_uid());
    assert_eq!(Some(agent_uid()), crate::host::Host::system().euid());
}

#[test]
fn the_socket_directory_check_is_a_pure_function_of_both_uids() {
    assert!(check_socket_dir(true, 0o700, 1000, 1000).is_ok());
    assert!(check_socket_dir(true, 0o750, 1000, 1000).is_ok());
    assert!(check_socket_dir(true, 0o40755, 0, 0).is_ok());
    for (is_dir, mode, dir_uid, agent_uid, why) in [
        (false, 0o700, 1000, 1000, "not a directory"),
        (true, 0o700, 0, 1000, "not owned by the agent"),
        (true, 0o700, 1000, 0, "not owned by the agent"),
        (true, 0o700, 2_147_483_648, 1000, "not owned by the agent"),
        (true, 0o770, 1000, 1000, "writable by its group or by others"),
        (true, 0o702, 1000, 1000, "writable by its group or by others"),
        (true, 0o1777, 1000, 1000, "writable by its group or by others"),
    ] {
        match check_socket_dir(is_dir, mode, dir_uid, agent_uid) {
            Err(StartError::UnsafeDirectory(got)) => assert_eq!(got, why, "{mode:o} {dir_uid} {agent_uid}"),
            other => panic!("{mode:o} {dir_uid} {agent_uid}: {other:?}"),
        }
    }
    assert_eq!(SOCKET_MODE, 0o600);
}

#[tokio::test]
async fn connect_early_data_in_the_same_write_is_forwarded() {
    let h = Setup::default().build();
    let (mut c, task) = h.client();
    c.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nearly-bytes")
        .await
        .unwrap();
    let head = read_head(&mut c).await;
    assert_eq!(head, "HTTP/1.1 200 Connection Established\r\n\r\n");
    let mut echoed = [0u8; 11];
    c.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"early-bytes");
    c.shutdown().await.unwrap();
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).await.unwrap();
    task.await.unwrap();
    let r = &h.shared.records()[0];
    assert_eq!((r.bytes_up, r.bytes_down), (11, 11));
}

// ---------------------------------------------------------------------------------------------------------------
// Second review of PR #5 (P3 × 4)
// ---------------------------------------------------------------------------------------------------------------

/// P3-1: a lookup that outlives its 5 s timeout keeps its DNS slot until the resolver really returns, so timed-out
/// lookups cannot pile up beyond the cap.
#[tokio::test(start_paused = true)]
async fn a_lookup_that_outlives_its_timeout_keeps_its_slot() {
    let h = Setup {
        resolver_delay: Some(Duration::from_secs(30)),
        limits: Limits {
            max_concurrent_lookups: 1,
            ..Limits::default()
        },
        ..Setup::default()
    }
    .build();
    let t0 = tokio::time::Instant::now();
    // The first lookup times out at 5 s, but the resolver keeps running until t = 30 s.
    let resp = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(reason(&resp), Some("resolve-timeout"), "{resp:?}");
    assert_eq!(t0.elapsed(), Duration::from_secs(5));
    // A second request at t = 5 s finds no free slot and times out without reaching the resolver.
    let resp = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(reason(&resp), Some("resolve-timeout"), "{resp:?}");
    assert_eq!(t0.elapsed(), Duration::from_secs(10));
    assert_eq!(
        h.resolver.queries().len(),
        1,
        "the slot is still held by the first lookup"
    );
    // After the first resolver call returns (t = 30 s), the slot is free again.
    tokio::time::sleep_until(t0 + Duration::from_secs(31)).await;
    let _ = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(h.resolver.queries().len(), 2);
}

/// P3-2: the node's public addresses are a live source, read on every request.
#[tokio::test]
async fn public_address_updates_apply_to_the_next_request() {
    let (tx, rx) = watch::channel(Vec::<IpAddr>::new());
    let h = Setup {
        answers: vec![("example.com", vec!["1.0.0.7"])],
        public_rx: Some(rx),
        ..Setup::default()
    }
    .build();
    // An empty list means no hairpin protection: the node's own address is reachable.
    let (head, c, task) = h.connect("example.com:443").await;
    assert_eq!(status(&head), "HTTP/1.1 200 Connection Established", "{head:?}");
    drop(c);
    task.await.unwrap();
    // iroh observes the node's public address: the next request is refused.
    tx.send(vec![ip("1.0.0.7")]).unwrap();
    let resp = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(reason(&resp), Some("denied-address"), "{resp:?}");
    // The address changes: the old one is reachable again and the new one is refused.
    tx.send(vec![ip("1.0.0.8")]).unwrap();
    let (head, c, task) = h.connect("example.com:443").await;
    assert_eq!(status(&head), "HTTP/1.1 200 Connection Established", "{head:?}");
    drop(c);
    task.await.unwrap();
    assert_eq!(h.connector.attempts(), vec![sa("1.0.0.7", 443), sa("1.0.0.7", 443)]);
}

/// T10f, item 1: a proxy that is already running follows the egress gate. While the gate is closed (IPv4 came up
/// after it opened on IPv6) it refuses IPv4 destinations with the gate's own error and keeps allowing IPv6 ones; once
/// the gate opens again with the WAN IPv4 in the deny list, that address is refused as a hairpin.
#[tokio::test]
async fn a_running_proxy_refuses_ipv4_while_the_gate_is_closed() {
    let (ready_tx, ready_rx) = watch::channel(EgressGate::Open);
    let (public_tx, public_rx) = watch::channel(vec![ip("2606:4700:7000::5")]);
    let h = Setup {
        allow: vec![
            "v4.example.com",
            "v6.example.com",
            "mixed.example.com",
            "wan.example.com",
        ],
        answers: vec![
            ("v4.example.com", vec![PUBLIC_V4]),
            ("v6.example.com", vec![PUBLIC_V6]),
            ("mixed.example.com", vec![PUBLIC_V4, PUBLIC_V6]),
            ("wan.example.com", vec!["1.0.0.7"]),
        ],
        public_rx: Some(public_rx),
        ready_rx: Some(ready_rx),
        ..Setup::default()
    }
    .build();
    // Open: IPv4 goes through.
    let (head, c, task) = h.connect("v4.example.com:443").await;
    assert_eq!(status(&head), "HTTP/1.1 200 Connection Established", "{head:?}");
    drop(c);
    task.await.unwrap();

    // IPv4 came up on the host: the gate closes, the deny list is untouched.
    ready_tx.send_replace(EgressGate::Closed);
    let resp = h.exchange(&connect_req("v4.example.com:443")).await;
    assert_eq!(status(&resp), "HTTP/1.1 503 Service Unavailable", "{resp:?}");
    assert_eq!(reason(&resp), Some("egress-unavailable"), "{resp:?}");
    assert_eq!(h.shared.records().last().unwrap().verdict, Verdict::EgressUnavailable);
    assert_eq!(
        h.connector.attempts(),
        vec![sa(PUBLIC_V4, 443)],
        "the refused one never connected"
    );
    // IPv6 keeps working.
    let (head, c, task) = h.connect("v6.example.com:443").await;
    assert_eq!(status(&head), "HTTP/1.1 200 Connection Established", "{head:?}");
    drop(c);
    task.await.unwrap();
    // A name with both families is served over IPv6, never over IPv4.
    let (head, c, task) = h.connect("mixed.example.com:443").await;
    assert_eq!(status(&head), "HTTP/1.1 200 Connection Established", "{head:?}");
    drop(c);
    task.await.unwrap();
    assert_eq!(
        h.connector.attempts(),
        vec![sa(PUBLIC_V4, 443), sa(PUBLIC_V6, 443), sa(PUBLIC_V6, 443)]
    );
    // An IPv4 address the deny list does not hold yet is refused too: that is the hairpin the closed gate guards.
    let resp = h.exchange(&connect_req("wan.example.com:443")).await;
    assert_eq!(reason(&resp), Some("egress-unavailable"), "{resp:?}");

    // The WAN IPv4 is learned (the deny list first, then the gate): open again, and that address is refused.
    public_tx.send_replace(vec![ip("1.0.0.7"), ip("2606:4700:7000::5")]);
    ready_tx.send_replace(EgressGate::Open);
    let resp = h.exchange(&connect_req("wan.example.com:443")).await;
    assert_eq!(status(&resp), "HTTP/1.1 403 Forbidden", "{resp:?}");
    assert_eq!(reason(&resp), Some("denied-address"), "{resp:?}");
    let (head, c, task) = h.connect("v4.example.com:443").await;
    assert_eq!(
        status(&head),
        "HTTP/1.1 200 Connection Established",
        "IPv4 is back: {head:?}"
    );
    drop(c);
    task.await.unwrap();
}

/// P3-3: allowed connections are logged at most once per destination per minute, aggregated; `records()` and
/// `stats()` stay exact.
#[tokio::test(start_paused = true)]
async fn allowed_connection_logs_are_aggregated_per_destination_per_minute() {
    let log = LogLimiter::new("allowed");
    let t0 = tokio::time::Instant::now();
    assert_eq!(log.admit("example.com", 443, 10, 20, t0), Some(Held::default()));
    assert_eq!(log.admit("example.com", 443, 1, 2, t0 + Duration::from_secs(1)), None);
    assert_eq!(log.admit("Example.com", 443, 3, 4, t0 + Duration::from_secs(2)), None);
    // The next line, a minute later, carries what was held back.
    assert_eq!(
        log.admit("example.com", 443, 5, 6, t0 + Duration::from_secs(60)),
        Some(Held {
            events: 2,
            bytes_up: 4,
            bytes_down: 6,
        })
    );
    // At shutdown, what is still held back is logged.
    assert_eq!(log.admit("example.com", 443, 7, 8, t0 + Duration::from_secs(61)), None);
    assert_eq!(log.drain(), 1);
    assert_eq!(log.drain(), 0);

    // Through the proxy: three connections, one line, exact records and stats.
    let h = Setup::default().build();
    for payload in [&b"a"[..], b"bb", b"ccc"] {
        let (_, mut c, task) = h.connect("example.com:443").await;
        c.write_all(payload).await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        c.read_exact(&mut buf).await.unwrap();
        c.shutdown().await.unwrap();
        let mut rest = Vec::new();
        c.read_to_end(&mut rest).await.unwrap();
        task.await.unwrap();
    }
    let stats = h.shared.stats();
    assert_eq!(stats.allowed_logs_suppressed, 2);
    assert_eq!((stats.bytes_up, stats.bytes_down), (6, 6));
    let bytes: Vec<_> = h.shared.records().iter().map(|r| (r.bytes_up, r.bytes_down)).collect();
    assert_eq!(bytes, vec![(1, 1), (2, 2), (3, 3)]);
}

/// P3-4: trailer lines are `token ":" value`, with no `\r` except in the final CRLF.
#[test]
fn trailer_lines() {
    for ok in [
        &b"\r\n"[..],
        b"X-Checksum: 1\r\n",
        b"x:\r\n",
        b"Server-Timing: db;dur=53\r\n",
        b"X-A:\tvalue with spaces\r\n",
        b"!#$%&'*+-.^_`|~09az: v\r\n",
    ] {
        assert!(body::trailer_line_ok(ok), "{:?}", String::from_utf8_lossy(ok));
    }
    for bad in [
        &b"X-A: 1\rX-B: 2\r\n"[..],
        b"X-A\r: 1\r\n",
        b"\r\r\n",
        b"X-A: 1\r",
        b"X-A: 1\n",
        b"no colon\r\n",
        b"novalue\r\n",
        b": empty name\r\n",
        b"Bad Name: x\r\n",
        b"X-A : x\r\n",
        b" folded: x\r\n",
        b"\tfolded\r\n",
        b"X(A): x\r\n",
        b"X-A: a\x00b\r\n",
        b"X-A: a\x7fb\r\n",
    ] {
        assert!(!body::trailer_line_ok(bad), "{:?}", String::from_utf8_lossy(bad));
    }
}

#[tokio::test]
async fn malformed_trailers_are_not_forwarded() {
    let head = "POST /u HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    for bad in [
        "X-A: 1\rX-B: 2\r\n",
        "no colon\r\n",
        "Bad Name: x\r\n",
        " folded: x\r\n",
    ] {
        let h = Setup {
            upstream: Upstream::Http(OK_RESPONSE),
            ..Setup::default()
        }
        .build();
        let raw = format!(
            "POST http://example.com/u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n{bad}\r\n"
        );
        let _ = h.exchange(raw.as_bytes()).await;
        h.connector.settle().await;
        // Everything up to the last chunk went through; the bad trailer line did not.
        assert_eq!(h.connector.received(), format!("{head}5\r\nhello\r\n0\r\n"), "{bad:?}");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Third review of PR #5 (P2 × 1, P3 × 4)
// ---------------------------------------------------------------------------------------------------------------

/// P2: a refusal's record is pushed before the client can see the response, so it is in `records()` as soon as
/// the client reads it (not only at EOF). Run on the multi-thread runtime, where the old order was flaky.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_record_is_visible_before_the_response_is() {
    for _ in 0..20 {
        let h = Setup::default().build();
        let (mut c, task) = h.client();
        c.write_all(&connect_req("evilexample.com:443")).await.unwrap();
        let head = read_head(&mut c).await;
        assert_eq!(reason(&head), Some("denied-domain"), "{head:?}");
        assert_eq!(
            h.shared.records().len(),
            1,
            "the record must exist once the response does"
        );
        drop(c);
        task.await.unwrap();
    }
}

/// P3: the socket directory is checked before anything is created in it.
#[test]
fn a_refused_socket_directory_is_left_untouched() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = rt.enter();
    // 0o575 is group-writable but not writable by the agent: checking first refuses it as unsafe, while creating
    // the staging directory first would fail with an I/O error instead.
    for mode in [0o777, 0o770, 0o722, 0o575] {
        let dir = TestDir::new("untouched");
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(mode)).unwrap();
        let (policy, _, _) = Setup::default().policy();
        let err = EgressProxy::start(dir.0.join("egress.sock"), policy).unwrap_err();
        assert!(matches!(err, StartError::UnsafeDirectory(_)), "{mode:o}: {err:?}");
        let entries: Vec<_> = std::fs::read_dir(&dir.0).unwrap().collect();
        assert!(entries.is_empty(), "{mode:o}: {entries:?}");
    }
}

/// P3: a refused client that stops reading cannot hold up shutdown (the `403` is not waited for).
#[tokio::test(start_paused = true)]
async fn shutdown_does_not_wait_for_a_refused_client_that_stops_reading() {
    let h = Setup::default().build();
    // 16 bytes of buffer: the 403 response does not fit, and the client never reads it.
    let (mut c, task) = h.client_with_buffer(16);
    c.write_all(&connect_req("evilexample.com:443")).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    // The record is already there, even though the response is stuck.
    assert_eq!(h.shared.records()[0].verdict, Verdict::DeniedDomain);
    let start = tokio::time::Instant::now();
    h.shutdown.send(true).unwrap();
    task.await.unwrap();
    assert!(start.elapsed() < Duration::from_secs(1), "{:?}", start.elapsed());
    drop(c);
}

/// P3: a `CONNECT` client that stops reading cannot hold up shutdown either, and its record says `ClientGone`.
#[tokio::test(start_paused = true)]
async fn shutdown_does_not_wait_for_a_connect_client_that_stops_reading() {
    let h = Setup::default().build();
    // 8 bytes of buffer: `200 Connection Established` (39 bytes) cannot be written.
    let (mut c, task) = h.client_with_buffer(8);
    c.write_all(&connect_req("example.com:443")).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let start = tokio::time::Instant::now();
    h.shutdown.send(true).unwrap();
    task.await.unwrap();
    assert!(start.elapsed() < Duration::from_secs(1), "{:?}", start.elapsed());
    let records = h.shared.records();
    assert_eq!(records[0].verdict, Verdict::ClientGone);
    assert_eq!((records[0].bytes_up, records[0].bytes_down), (0, 0));
    assert_eq!(h.shared.stats().client_gone, 1);
    assert_eq!(h.shared.stats().refusals, 0);
    drop(c);
}

/// P3: a client that is gone before the `200` gets an honest `ClientGone` record.
#[tokio::test]
async fn a_client_gone_before_the_200_is_recorded_as_client_gone() {
    let h = Setup::default().build();
    let (mut c, task) = h.client();
    c.write_all(&connect_req("example.com:443")).await.unwrap();
    // Gone before the proxy has even read the request.
    drop(c);
    task.await.unwrap();
    let records = h.shared.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].verdict, Verdict::ClientGone);
    assert_eq!(h.connector.attempts(), vec![sa(PUBLIC_V4, 443)]);
    assert_eq!(h.shared.stats().client_gone, 1);
    assert_eq!(Verdict::ClientGone.reason(), "client-gone");
}

/// P3: when the byte cap cuts a tunnel or a plain-HTTP body, the record says `ByteCap`, not `Allowed`.
#[tokio::test]
async fn byte_cap_cuts_are_recorded_as_byte_cap() {
    let capped = || Setup {
        upstream: Upstream::Http(OK_RESPONSE),
        limits: Limits {
            max_total_bytes: Some(8),
            ..Limits::default()
        },
        ..Setup::default()
    };
    // A tunnel.
    let h = Setup {
        limits: Limits {
            max_total_bytes: Some(8),
            ..Limits::default()
        },
        ..Setup::default()
    }
    .build();
    let (_, mut c, task) = h.connect("example.com:443").await;
    c.write_all(b"more than eight bytes").await.unwrap();
    let mut rest = Vec::new();
    let _ = c.read_to_end(&mut rest).await;
    task.await.unwrap();
    assert_eq!(h.shared.records()[0].verdict, Verdict::ByteCap);
    // The next request is refused outright: a refusal, not a cut.
    let resp = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(reason(&resp), Some("byte-cap"));
    let stats = h.shared.stats();
    assert_eq!((stats.byte_cap_cuts, stats.refusals), (1, 1));

    // A plain-HTTP request: the head alone is over the cap.
    let h = capped().build();
    let _ = h
        .exchange(b"POST http://example.com/u HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello")
        .await;
    assert_eq!(h.shared.records()[0].verdict, Verdict::ByteCap);
    assert_eq!(h.shared.stats().byte_cap_cuts, 1);

    // A request within the cap stays `Allowed`.
    let h = Setup::default().build();
    let (_, c, task) = h.connect("example.com:443").await;
    drop(c);
    task.await.unwrap();
    assert_eq!(h.shared.records()[0].verdict, Verdict::Allowed);
    assert_eq!(h.shared.stats().byte_cap_cuts, 0);
}

/// P3 (spec §9, 9444b44): `/proc/net/route` sample, native endianness (the kernel prints `__be32` as a native
/// `%08X`). Fields: iface, destination, gateway, flags, refcnt, use, metric, mask, mtu, window, irtt.
const IPV4_ROUTE_SAMPLE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
ppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
tun0\t00000000\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0
tun0\t00000080\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
eth0\t0000000A\t00000000\t0201\t0\t0\t0\t000000FF\t0\t0\t0
eth1\t0001A8C0\t00000000\t0000\t0\t0\t0\t00FFFFFF\t0\t0\t0
eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FF00FF\t0\t0\t0
eth0\t0000A8C0\t0100A8C0\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
garbage
";

fn v4net(s: &str, len: u8) -> Cidr {
    Cidr::V4(s.parse().unwrap(), len)
}

#[cfg(target_endian = "little")]
#[test]
fn ipv4_route_parser_keeps_only_on_link_destinations() {
    assert_eq!(
        parse_ipv4_route(IPV4_ROUTE_SAMPLE),
        vec![
            v4net("192.168.0.0", 24), // the LAN on eth0
            v4net("0.0.0.0", 0),      // default dev ppp0, no gateway (left out by host_deny_set)
            v4net("0.0.0.0", 1),      // full-tunnel VPN, first half (left out)
            v4net("128.0.0.0", 1),    // full-tunnel VPN, second half (left out)
            v4net("172.17.0.0", 16),  // a container bridge
        ],
        // Skipped: the header, the default route via a gateway, the reject route, the route that is not up, the
        // non-contiguous mask, a gateway without RTF_GATEWAY, and the malformed line.
    );
    assert!(parse_ipv4_route("").is_empty());
}

/// The IPv6 fixture for the same three shapes: a LAN route, an on-link default on PPP, and a full-tunnel /1 pair.
const IPV6_ROUTE_TUNNEL_SAMPLE: &str = "\
20010db8000100000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001     ppp0
00000000000000000000000000000000 01 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001      wg0
80000000000000000000000000000000 01 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001      wg0
";

#[test]
fn ipv6_route_parser_reports_ppp_default_and_full_tunnel_routes() {
    assert_eq!(
        parse_ipv6_route(IPV6_ROUTE_TUNNEL_SAMPLE),
        vec![
            v6net("2001:db8:1::", 64),
            v6net("::", 0),
            v6net("::", 1),
            v6net("8000::", 1),
        ]
    );
}

#[cfg(target_endian = "little")]
#[test]
fn default_and_too_wide_on_link_routes_are_never_denied() {
    let mut onlink_routes = parse_ipv4_route(IPV4_ROUTE_SAMPLE);
    onlink_routes.extend(parse_ipv6_route(IPV6_ROUTE_TUNNEL_SAMPLE));
    let nets = HostNets {
        interfaces: vec![],
        onlink_routes,
    };
    assert_eq!(
        host_deny_set(&nets, 56, &[]),
        vec![
            v4net("192.168.0.0", 24),
            v4net("172.17.0.0", 16),
            v6net("2001:db8:1::", 64)
        ]
    );
    assert_eq!(
        excluded_onlink_routes(&nets),
        vec![
            v4net("0.0.0.0", 0),
            v4net("0.0.0.0", 1),
            v4net("128.0.0.0", 1),
            v6net("::", 0),
            v6net("::", 1),
            v6net("8000::", 1),
        ]
    );
    // The limits themselves: /8 and /32 are still denied, one bit wider is not.
    for (route, denied) in [
        (v4net("10.0.0.0", MIN_ONLINK_ROUTE_PREFIX_V4), true),
        (v4net("10.0.0.0", MIN_ONLINK_ROUTE_PREFIX_V4 - 1), false),
        (v6net("2606:4700::", MIN_ONLINK_ROUTE_PREFIX_V6), true),
        (v6net("2606:4700::", MIN_ONLINK_ROUTE_PREFIX_V6 - 1), false),
    ] {
        let nets = HostNets {
            interfaces: vec![],
            onlink_routes: vec![route],
        };
        assert_eq!(host_deny_set(&nets, 56, &[]).len(), usize::from(denied), "{route}");
    }
}

#[tokio::test]
async fn an_ipv4_on_link_route_is_refused_and_wide_routes_are_warned_once() {
    let routes = vec![
        v4net("1.0.0.0", 24), // a public-looking on-link route
        v4net("0.0.0.0", 0),  // default dev ppp0
        v4net("0.0.0.0", 1),
        v4net("128.0.0.0", 1),
        v6net("::", 0),
    ];
    let h = lan_setup(vec![], routes.clone(), "1.0.0.9").build();
    let resp = h.exchange(&connect_req("example.com:443")).await;
    assert_eq!(reason(&resp), Some("denied-address"), "{resp:?}");
    // The default and /1 routes did not deny everything: another address passes.
    let h = lan_setup(vec![], routes, PUBLIC_V4).build();
    for _ in 0..3 {
        let (head, c, task) = h.connect("example.com:443").await;
        assert_eq!(status(&head), "HTTP/1.1 200 Connection Established", "{head:?}");
        drop(c);
        task.await.unwrap();
    }
    // Each excluded route was warned about once, however many requests saw it.
    assert_eq!(h.shared.warned_routes.lock().unwrap().len(), 4);
}

// ---------------------------------------------------------------------------------------------------------------
// Hostile input never panics
// ---------------------------------------------------------------------------------------------------------------

proptest::proptest! {
    #[test]
    fn parsing_arbitrary_heads_never_panics(raw in proptest::collection::vec(proptest::num::u8::ANY, 0..512)) {
        let _ = request::head_len(&raw);
        let _ = parse_head(&raw);
        if let Ok(s) = std::str::from_utf8(&raw) {
            let _ = is_ip_literal(s);
        }
    }

    #[test]
    fn parsing_near_valid_heads_never_panics(
        method in "(CONNECT|GET|POST|[A-Z]{0,8})",
        target in "(http://)?[a-z0-9.:\\[\\]%@/?#_-]{0,40}",
        headers in proptest::collection::vec("[A-Za-z-]{0,12}:[ -~]{0,20}", 0..6),
    ) {
        let raw = format!("{method} {target} HTTP/1.1\r\n{}\r\n\r\n", headers.join("\r\n"));
        if let Ok(req) = parse_head(raw.as_bytes()) {
            let _ = is_ip_literal(&req.target().host);
        }
    }

    #[test]
    fn serving_arbitrary_bytes_never_panics(raw in proptest::collection::vec(proptest::num::u8::ANY, 0..2048)) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().start_paused(true).build().unwrap();
        rt.block_on(async {
            let h = Setup::default().build();
            let (mut c, task) = h.client();
            let _ = c.write_all(&raw).await;
            let _ = c.shutdown().await;
            let mut out = Vec::new();
            let _ = c.read_to_end(&mut out).await;
            // A panic in the connection task would surface here as a `JoinError`.
            task.await.unwrap();
        });
    }
}

#[test]
fn the_system_resolver_asks_for_absolute_names() {
    assert_eq!(net::absolute_name("example.com"), "example.com.");
}
