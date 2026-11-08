// SPDX-License-Identifier: Apache-2.0

//! The proxy's three seams to the outside world: DNS, the host's interfaces and outbound TCP. Each is a trait with a
//! system implementation; tests use fakes so they never touch the real network.

use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

use super::deny::{Cidr, HostNets, parse_ipv4_route, parse_ipv6_route};

/// A boxed, sendable future (the traits below must be object-safe).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A bidirectional byte stream to an upstream server.
pub trait UpstreamStream: AsyncRead + AsyncWrite + Unpin + Send + Debug {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Debug> UpstreamStream for T {}

/// Resolves a host name. The proxy calls it **once** per request and connects only to an address it returned.
pub trait Resolver: Send + Sync + Debug {
    /// All addresses of `host` (already lowercase, without a trailing dot), in preference order.
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<Vec<IpAddr>>>;
}

/// Enumerates the host's interface networks and on-link routes (IPv4 and IPv6, with no gateway).
pub trait HostNetworks: Send + Sync + Debug {
    /// The current state. Called on every request, so a DHCP renewal or a new VPN interface is seen at once.
    fn networks(&self) -> BoxFuture<'_, io::Result<HostNets>>;
}

/// Opens outbound TCP connections.
pub trait Connector: Send + Sync + Debug {
    /// Connects to exactly `addr`.
    fn connect(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<Box<dyn UpstreamStream>>>;
}

/// The system resolver (`getaddrinfo`, run on Tokio's blocking pool).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

/// Makes the name absolute so the resolver never appends the host's search domains (which could turn
/// `example.com` into `example.com.corp.lan`).
pub(crate) fn absolute_name(host: &str) -> String {
    format!("{host}.")
}

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let name = absolute_name(host);
            // `getaddrinfo` blocks: run it on the blocking pool and await it to the end. The proxy's lookup task
            // holds its DNS slot across this await, so the slot is free again only when `getaddrinfo` returns.
            let found = tokio::task::spawn_blocking(move || {
                std::net::ToSocketAddrs::to_socket_addrs(&(name.as_str(), port)).map(Iterator::collect::<Vec<_>>)
            })
            .await
            .map_err(io::Error::other)??;
            let mut out = Vec::new();
            for sa in found {
                if !out.contains(&sa.ip()) {
                    out.push(sa.ip());
                }
            }
            Ok(out)
        })
    }
}

/// The host's interfaces, from `getifaddrs` (through the `if-addrs` crate), and its on-link routes, from
/// `/proc/net/route` (IPv4) and `/proc/net/ipv6_route` (IPv6).
///
/// On the WSL2 profile all distros share one network namespace (spec §9.0), so this also lists the other distros'
/// bridges and the Tailscale interface: all of them are refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemHostNetworks;

/// Where Linux lists the IPv4 routing table (main table).
const IPV4_ROUTE_PATH: &str = "/proc/net/route";

/// Where Linux lists the IPv6 routing table.
const IPV6_ROUTE_PATH: &str = "/proc/net/ipv6_route";

fn read_host_nets() -> io::Result<HostNets> {
    let interfaces = if_addrs::get_if_addrs()?
        .into_iter()
        .map(|i| match i.addr {
            if_addrs::IfAddr::V4(a) => Cidr::V4(a.ip, a.prefixlen),
            if_addrs::IfAddr::V6(a) => Cidr::V6(a.ip, a.prefixlen),
        })
        .collect();
    let mut onlink_routes = match std::fs::read_to_string(IPV4_ROUTE_PATH) {
        Ok(text) => parse_ipv4_route(&text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    match std::fs::read_to_string(IPV6_ROUTE_PATH) {
        Ok(text) => onlink_routes.extend(parse_ipv6_route(&text)),
        // IPv6 is disabled on this host (WSL2 in NAT mode, for one): there are no IPv6 routes.
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(HostNets {
        interfaces,
        onlink_routes,
    })
}

impl HostNetworks for SystemHostNetworks {
    fn networks(&self) -> BoxFuture<'_, io::Result<HostNets>> {
        Box::pin(async {
            tokio::task::spawn_blocking(read_host_nets)
                .await
                .map_err(io::Error::other)?
        })
    }
}

/// Plain outbound TCP.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpConnector;

impl Connector for TcpConnector {
    fn connect(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<Box<dyn UpstreamStream>>> {
        Box::pin(async move {
            let s = tokio::net::TcpStream::connect(addr).await?;
            s.set_nodelay(true)?;
            Ok(Box::new(s) as Box<dyn UpstreamStream>)
        })
    }
}
