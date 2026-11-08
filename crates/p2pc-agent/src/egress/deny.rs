// SPDX-License-Identifier: Apache-2.0

//! The address deny set (spec §9, SI-4, `CONTRIBUTING.md` hard rule 2).
//!
//! Every resolved address goes through [`check_addr`] before the proxy connects to it. The check is done on the
//! **canonical** form: an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is turned into its IPv4 address first, so
//! `::ffff:127.0.0.1` is refused as loopback and `::ffff:1.1.1.1` is connected to as `1.1.1.1`.
//!
//! On top of the static table, the host's own addresses **and the on-link networks of its interfaces** are refused.
//! The second part matters for home IPv6: the LAN's /64 is global unicast, so the static table alone would let a job
//! reach the owner's other machines through it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IPv4 or IPv6 network in CIDR form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cidr {
    /// An IPv4 network.
    V4(Ipv4Addr, u8),
    /// An IPv6 network.
    V6(Ipv6Addr, u8),
}

impl Cidr {
    /// Whether `ip` is inside this network. IPv4 networks never contain IPv6 addresses and vice versa: callers
    /// canonicalize first (see [`canonical`]).
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (*self, ip) {
            (Cidr::V4(net, len), IpAddr::V4(ip)) => {
                let mask = mask_v4(len);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (Cidr::V6(net, len), IpAddr::V6(ip)) => {
                let mask = mask_v6(len);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cidr::V4(ip, len) => write!(f, "{ip}/{len}"),
            Cidr::V6(ip, len) => write!(f, "{ip}/{len}"),
        }
    }
}

fn mask_v4(len: u8) -> u32 {
    match len {
        0 => 0,
        l if l >= 32 => u32::MAX,
        l => u32::MAX << (32 - u32::from(l)),
    }
}

fn mask_v6(len: u8) -> u128 {
    match len {
        0 => 0,
        l if l >= 128 => u128::MAX,
        l => u128::MAX << (128 - u32::from(l)),
    }
}

/// One entry of the deny table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenyRange {
    /// The refused network.
    pub net: Cidr,
    /// Why it is refused (shown in the PR's deny table and in debug logs).
    pub why: &'static str,
}

const fn v4(a: u8, b: u8, c: u8, d: u8, len: u8, why: &'static str) -> DenyRange {
    DenyRange {
        net: Cidr::V4(Ipv4Addr::new(a, b, c, d), len),
        why,
    }
}

const fn v6(segs: [u16; 8], len: u8, why: &'static str) -> DenyRange {
    let [a, b, c, d, e, f, g, h] = segs;
    DenyRange {
        net: Cidr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h), len),
        why,
    }
}

/// The static deny table. Order does not matter for the decision; the first match only names the reason.
///
/// IPv4-mapped IPv6 (`::ffff:0:0/96`) is not listed: [`canonical`] maps it to IPv4 before the lookup, so it is
/// checked against the IPv4 entries. The three last IPv6 entries refuse everything outside global unicast
/// `2000::/3`, so a range IANA has not assigned yet can never slip through.
pub const DENY_TABLE: &[DenyRange] = &[
    // --- IPv4 ---
    v4(
        0,
        0,
        0,
        0,
        8,
        "\"this network\"; 0.0.0.0 reaches the host itself on Linux (RFC 791, RFC 1122)",
    ),
    v4(10, 0, 0, 0, 8, "private network (RFC 1918)"),
    v4(
        100,
        64,
        0,
        0,
        10,
        "shared address space / CGNAT, includes Tailscale (RFC 6598)",
    ),
    v4(127, 0, 0, 0, 8, "loopback (RFC 1122)"),
    v4(
        169,
        254,
        0,
        0,
        16,
        "link-local, includes cloud metadata 169.254.169.254 (RFC 3927)",
    ),
    v4(172, 16, 0, 0, 12, "private network (RFC 1918)"),
    v4(192, 0, 0, 0, 24, "IETF protocol assignments (RFC 6890)"),
    v4(192, 0, 2, 0, 24, "documentation TEST-NET-1 (RFC 5737)"),
    v4(192, 88, 99, 0, 24, "deprecated 6to4 relay anycast (RFC 7526)"),
    v4(192, 168, 0, 0, 16, "private network (RFC 1918)"),
    v4(198, 18, 0, 0, 15, "benchmarking (RFC 2544)"),
    v4(198, 51, 100, 0, 24, "documentation TEST-NET-2 (RFC 5737)"),
    v4(203, 0, 113, 0, 24, "documentation TEST-NET-3 (RFC 5737)"),
    v4(224, 0, 0, 0, 4, "multicast (RFC 5771)"),
    v4(240, 0, 0, 0, 4, "reserved for future use (RFC 1112)"),
    v4(255, 255, 255, 255, 32, "limited broadcast (RFC 919)"),
    // --- IPv6 ---
    v6(
        [0, 0, 0, 0, 0, 0, 0, 0],
        128,
        "unspecified; reaches the host itself on Linux (RFC 4291)",
    ),
    v6([0, 0, 0, 0, 0, 0, 0, 1], 128, "loopback (RFC 4291)"),
    v6(
        [0, 0, 0, 0, 0, 0, 0, 0],
        96,
        "deprecated IPv4-compatible IPv6, ::a.b.c.d (RFC 4291 §2.5.5.1)",
    ),
    v6(
        [0, 0, 0, 0, 0xffff, 0, 0, 0],
        96,
        "IPv4-translated, ::ffff:0:a.b.c.d (RFC 2765)",
    ),
    v6(
        [0x64, 0xff9b, 0, 0, 0, 0, 0, 0],
        96,
        "NAT64 well-known prefix, can embed private IPv4 (RFC 6052)",
    ),
    v6(
        [0x64, 0xff9b, 1, 0, 0, 0, 0, 0],
        48,
        "NAT64 local-use prefix (RFC 8215)",
    ),
    v6([0x100, 0, 0, 0, 0, 0, 0, 0], 64, "discard-only (RFC 6666)"),
    v6(
        [0x2001, 0, 0, 0, 0, 0, 0, 0],
        23,
        "IETF protocol assignments: Teredo, benchmarking, ORCHID, AMT (RFC 2928)",
    ),
    v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32, "documentation (RFC 3849)"),
    v6(
        [0x2002, 0, 0, 0, 0, 0, 0, 0],
        16,
        "deprecated 6to4, embeds an IPv4 address (RFC 7526)",
    ),
    v6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20, "documentation (RFC 9637)"),
    v6([0x5f00, 0, 0, 0, 0, 0, 0, 0], 16, "SRv6 segment identifiers (RFC 9602)"),
    v6(
        [0xfc00, 0, 0, 0, 0, 0, 0, 0],
        7,
        "unique local addresses / ULA (RFC 4193)",
    ),
    v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10, "link-local (RFC 4291)"),
    v6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10, "deprecated site-local (RFC 3879)"),
    v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8, "multicast (RFC 4291)"),
    v6(
        [0, 0, 0, 0, 0, 0, 0, 0],
        3,
        "outside global unicast 2000::/3 (RFC 4291)",
    ),
    v6(
        [0x4000, 0, 0, 0, 0, 0, 0, 0],
        2,
        "outside global unicast 2000::/3 (RFC 4291)",
    ),
    v6(
        [0x8000, 0, 0, 0, 0, 0, 0, 0],
        1,
        "outside global unicast 2000::/3 (RFC 4291)",
    ),
];

/// Maps an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to IPv4. Every other address is returned unchanged.
#[must_use]
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Why an address was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// It is in the static table.
    Table(&'static DenyRange),
    /// It is one of the host's addresses, or inside the on-link network of one of its interfaces.
    HostNetwork(Cidr),
}

/// Checks a resolved address. `host_nets` are the host's interface networks (address plus prefix length); both the
/// exact addresses and the whole networks are refused.
///
/// # Errors
/// [`Denied`] says which rule refused it.
pub fn check_addr(ip: IpAddr, host_nets: &[Cidr]) -> Result<IpAddr, Denied> {
    let ip = canonical(ip);
    if let Some(range) = DENY_TABLE.iter().find(|r| r.net.contains(ip)) {
        return Err(Denied::Table(range));
    }
    for net in host_nets {
        let net = canonical_net(*net);
        let exact = match net {
            Cidr::V4(a, _) => Cidr::V4(a, 32),
            Cidr::V6(a, _) => Cidr::V6(a, 128),
        };
        if exact.contains(ip) || net.contains(ip) {
            return Err(Denied::HostNetwork(net));
        }
    }
    Ok(ip)
}

/// The default `lan_ipv6_prefix`: a home LAN is usually delegated a /56, and each of its /64s may be a different
/// segment (spec §9, "The owner's LAN, beyond RFC 1918").
pub const DEFAULT_LAN_IPV6_PREFIX: u8 = 56;

/// On-link IPv4 routes wider than this (a smaller prefix length) are never added to the deny set, and neither is
/// the default route. They come from point-to-point links (`default dev ppp0`) or full-tunnel VPNs (`0.0.0.0/1`
/// plus `128.0.0.0/1`), not from a LAN, and denying them would deny everything (spec §9). They are logged once
/// as a warning instead.
pub const MIN_ONLINK_ROUTE_PREFIX_V4: u8 = 8;

/// The same limit for IPv6: no LAN is wider than a /32 (the usual allocation to a whole ISP).
pub const MIN_ONLINK_ROUTE_PREFIX_V6: u8 = 32;

/// Whether an on-link route is a default route or too wide to be a LAN, and so is not denied.
#[must_use]
pub fn is_excluded_onlink_route(route: Cidr) -> bool {
    match canonical_net(route) {
        Cidr::V4(_, len) => len < MIN_ONLINK_ROUTE_PREFIX_V4,
        Cidr::V6(_, len) => len < MIN_ONLINK_ROUTE_PREFIX_V6,
    }
}

/// The on-link routes that [`host_deny_set`] leaves out (the caller logs them once as a warning).
#[must_use]
pub fn excluded_onlink_routes(nets: &HostNets) -> Vec<Cidr> {
    nets.onlink_routes
        .iter()
        .copied()
        .filter(|r| is_excluded_onlink_route(*r))
        .collect()
}

/// What the host knows about its own networks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostNets {
    /// Every interface address with its prefix length, as `getifaddrs` reports it.
    pub interfaces: Vec<Cidr>,
    /// The destinations of on-link routes (no gateway), IPv4 from `/proc/net/route` and IPv6 from
    /// `/proc/net/ipv6_route`. This includes default and very wide routes: [`host_deny_set`] leaves those out.
    pub onlink_routes: Vec<Cidr>,
}

/// Builds the host part of the deny set:
/// - every interface address, and the interface's own network;
/// - for a **global-unicast** IPv6 interface address, the containing `/lan_ipv6_prefix` (default /56). If the
///   interface's own prefix is wider (a smaller number, such as /48), that wider network is kept instead: the
///   /56 only ever adds to what the interface prefix already denies. A DHCPv6 /128 therefore still blocks the /56
///   around it;
/// - the on-link routes of both families, except the default route and routes wider than /8 (IPv4) or /32
///   (IPv6), see [`is_excluded_onlink_route`];
/// - the node's public addresses as observed by iroh (hairpin NAT into port-forwarded LAN services). A public IPv6
///   address gets the same /56 treatment.
#[must_use]
pub fn host_deny_set(nets: &HostNets, lan_ipv6_prefix: u8, public_addrs: &[IpAddr]) -> Vec<Cidr> {
    let lan = lan_ipv6_prefix.min(128);
    let widen = |net: Cidr| -> Cidr {
        match canonical_net(net) {
            Cidr::V6(a, len) if is_global_unicast(a) => Cidr::V6(a, len.min(lan)),
            other => other,
        }
    };
    let mut out: Vec<Cidr> = nets.interfaces.iter().map(|n| widen(*n)).collect();
    out.extend(
        nets.onlink_routes
            .iter()
            .map(|n| canonical_net(*n))
            .filter(|n| !is_excluded_onlink_route(*n)),
    );
    out.extend(public_addrs.iter().map(|ip| match canonical(*ip) {
        IpAddr::V4(a) => Cidr::V4(a, 32),
        IpAddr::V6(a) => widen(Cidr::V6(a, 128)),
    }));
    out
}

/// `2000::/3`, minus everything the static table refuses anyway.
fn is_global_unicast(a: Ipv6Addr) -> bool {
    Cidr::V6(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3).contains(IpAddr::V6(a))
}

/// `RTF_UP` in `/proc/net/ipv6_route` flags.
const RTF_UP: u32 = 0x0001;
/// `RTF_GATEWAY`: the route goes through a next hop, so its destination is not on-link.
const RTF_GATEWAY: u32 = 0x0002;
/// `RTF_REJECT`: an unreachable or prohibit route.
const RTF_REJECT: u32 = 0x0200;

/// Parses `/proc/net/ipv6_route` and returns the destinations of the on-link routes: up, no gateway and not a
/// reject route. An on-link default route (`::/0` on a PPP link) is returned too: [`host_deny_set`] leaves it and
/// other very wide routes out, and the caller logs them.
///
/// Each line is `dest dest_len src src_len next_hop metric refcnt use flags device`, with addresses as 32 hex
/// digits and lengths and flags in hex. Malformed lines are skipped.
#[must_use]
pub fn parse_ipv6_route(text: &str) -> Vec<Cidr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [
            dest,
            dest_len,
            _src,
            _src_len,
            next_hop,
            _metric,
            _refcnt,
            _use,
            flags,
            ..,
        ] = fields.as_slice()
        else {
            continue;
        };
        let (Some(dest), Ok(len), Some(next_hop), Ok(flags)) = (
            parse_hex_v6(dest),
            u8::from_str_radix(dest_len, 16),
            parse_hex_v6(next_hop),
            u32::from_str_radix(flags, 16),
        ) else {
            continue;
        };
        let onlink = flags & RTF_UP != 0 && flags & (RTF_GATEWAY | RTF_REJECT) == 0 && next_hop.is_unspecified();
        if onlink && len <= 128 {
            out.push(Cidr::V6(dest, len));
        }
    }
    out
}

/// Parses `/proc/net/route` (IPv4) and returns the destinations of the on-link routes: up, no gateway (no
/// `RTF_GATEWAY` and a zero gateway) and not a reject route. Default and very wide routes are returned too, for
/// [`host_deny_set`] to leave out.
///
/// The first line is a header. Each line is `iface destination gateway flags refcnt use metric mask mtu window
/// irtt`. Addresses and masks are the kernel's `__be32` printed as a native-endian `%08X`, so the address is
/// `u32::to_ne_bytes` of the parsed value. Malformed lines and non-contiguous masks are skipped.
#[must_use]
pub fn parse_ipv4_route(text: &str) -> Vec<Cidr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [_iface, dest, gateway, flags, _refcnt, _use, _metric, mask, ..] = fields.as_slice() else {
            continue;
        };
        let (Some(dest), Some(gateway), Ok(flags), Some(mask)) = (
            parse_hex_v4(dest),
            parse_hex_v4(gateway),
            u32::from_str_radix(flags, 16),
            parse_hex_v4(mask),
        ) else {
            continue;
        };
        let mask = u32::from(mask);
        let len = mask.leading_ones();
        if mask.count_ones() != len {
            continue;
        }
        let onlink = flags & RTF_UP != 0 && flags & (RTF_GATEWAY | RTF_REJECT) == 0 && gateway.is_unspecified();
        if onlink {
            out.push(Cidr::V4(dest, u8::try_from(len).unwrap_or(32)));
        }
    }
    out
}

fn parse_hex_v4(s: &str) -> Option<Ipv4Addr> {
    if s.len() != 8 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(s, 16).ok().map(|v| Ipv4Addr::from(v.to_ne_bytes()))
}

fn parse_hex_v6(s: &str) -> Option<Ipv6Addr> {
    if s.len() != 32 {
        return None;
    }
    u128::from_str_radix(s, 16).ok().map(Ipv6Addr::from)
}

/// An interface network reported as IPv4-mapped IPv6 is checked as IPv4.
fn canonical_net(net: Cidr) -> Cidr {
    match net {
        Cidr::V6(a, len) => match a.to_ipv4_mapped() {
            Some(v4) => Cidr::V4(v4, len.saturating_sub(96)),
            None => net,
        },
        Cidr::V4(..) => net,
    }
}
