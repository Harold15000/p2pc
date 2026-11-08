// SPDX-License-Identifier: Apache-2.0

//! Address hygiene for the iroh endpoints of the server and the agent (spec §10, experiment E4).
//!
//! iroh advertises every local address by default. E4 saw the public IP, a Tailscale address and container-bridge
//! addresses, and iroh picked the Tailscale path on its own. Both ends therefore bind their QUIC sockets only to the
//! addresses [`select_addresses`] returns: iroh advertises the addresses it is bound to (plus the public address
//! the relay observes), so binding is what controls advertising.
//!
//! This module is a pure function over a snapshot of the interfaces, with std types only, so that the agent
//! (Apache-2.0) and the server share it without either depending on how the other enumerates interfaces.
//!
//! Rules, whatever the policy:
//! - never an address in `100.64.0.0/10` (CGNAT, Tailscale), Tailscale's IPv6 range `fd7a:115c:a1e0::/48`, a
//!   link-local address (`169.254.0.0/16`, `fe80::/10`), a multicast, broadcast or unspecified address;
//! - never an address of a container, VM or overlay interface ([`is_virtual_interface`]: `docker*`, `br-*`,
//!   `podman*`, `cni*`, `virbr*`, `vEthernet*`, …), nor of an interface that is down;
//! - loopback only when a CIDR of the policy names it explicitly (for tests and single-machine setups).
//!
//! Policies ([`DirectAddresses`]):
//! - `"default-route"` (the default): only the addresses of the interface that carries the default route;
//! - `"none"`: no direct address at all, relay only;
//! - `[<cidr>, …]`: the addresses inside one of the CIDRs, on any interface that passes the rules above.
//!
//! Networks change (a laptop roams, DHCP renews, the server starts before its network is up). [`Reselector`]
//! debounces change notifications and reports a new selection only when it differs, so both ends re-bind with the
//! same rules. It is pure as well: each binary feeds it notifications and snapshots from its own interface monitor.
//!
//! **Remote** addresses: iroh 1.4 has no stable hook to filter the transport addresses a peer advertises, so these
//! rules cover only what each end binds and advertises. See `docs/security/residual-risks.md` (R-1).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Most CIDRs in a [`DirectAddresses::Cidrs`] policy.
pub const MAX_CIDRS: usize = 64;

/// Interface name prefixes of container, VM and overlay networks, never used (§10). Compared ASCII
/// case-insensitively.
pub const VIRTUAL_INTERFACE_PREFIXES: &[&str] = &[
    "docker",
    "br-",
    "podman",
    "cni",
    "virbr",
    "vethernet",
    "veth",
    "lxcbr",
    "lxdbr",
    "vmnet",
    "vboxnet",
    "flannel",
    "cali",
    "tailscale",
    "zt",
];

/// One address of an interface, with its prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IfAddr {
    /// The address.
    pub ip: IpAddr,
    /// Its network prefix length (for example 24).
    pub prefix_len: u8,
}

/// A network interface, as the caller enumerated it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// Its name, for example `eth0`.
    pub name: String,
    /// Whether it is up.
    pub is_up: bool,
    /// Its addresses.
    pub addrs: Vec<IfAddr>,
}

/// A chosen address: the address, its prefix and the interface it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SelectedAddr {
    /// The address and prefix.
    pub addr: IfAddr,
    /// The interface name.
    pub interface: String,
}

/// An IP network, `<address>/<prefix>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    /// The network address (host bits cleared).
    pub network: IpAddr,
    /// The prefix length (0-32 for IPv4, 0-128 for IPv6).
    pub prefix_len: u8,
}

/// Why a CIDR or a policy is not valid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    /// Not `<ip>/<prefix>` with a valid prefix.
    #[error("{0:?} is not a CIDR such as 192.0.2.0/24 or 2001:db8::/32")]
    InvalidCidr(String),
    /// Neither `"default-route"`, `"none"` nor a list of CIDRs.
    #[error("direct_addresses must be \"default-route\", \"none\" or a list of CIDRs")]
    InvalidPolicy,
    /// More than [`MAX_CIDRS`] CIDRs, or none at all.
    #[error("direct_addresses must list 1-{MAX_CIDRS} CIDRs")]
    CidrCount,
}

impl IfAddr {
    /// An address with its prefix length.
    #[must_use]
    pub const fn new(ip: IpAddr, prefix_len: u8) -> Self {
        Self { ip, prefix_len }
    }
}

impl Interface {
    /// An interface snapshot: its name, whether it is up, and its addresses.
    #[must_use]
    pub fn new(name: impl Into<String>, is_up: bool, addrs: Vec<IfAddr>) -> Self {
        Self {
            name: name.into(),
            is_up,
            addrs,
        }
    }
}

impl SelectedAddr {
    /// A chosen address on `interface`.
    #[must_use]
    pub fn new(addr: IfAddr, interface: impl Into<String>) -> Self {
        Self {
            addr,
            interface: interface.into(),
        }
    }
}

impl Cidr {
    /// A CIDR from an address and a prefix length; the host bits are cleared.
    pub fn new(ip: IpAddr, prefix_len: u8) -> Result<Self, NetError> {
        let (ip, prefix_len) = canonical_net(ip, prefix_len);
        let bad = || NetError::InvalidCidr(format!("{ip}/{prefix_len}"));
        let network = match ip {
            IpAddr::V4(v4) => {
                if prefix_len > 32 {
                    return Err(bad());
                }
                let mask = u32::MAX.checked_shl(32 - u32::from(prefix_len)).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
            }
            IpAddr::V6(v6) => {
                if prefix_len > 128 {
                    return Err(bad());
                }
                let mask = u128::MAX.checked_shl(128 - u32::from(prefix_len)).unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
        };
        Ok(Self { network, prefix_len })
    }

    /// Whether `ip` is inside this network. An IPv4-mapped IPv6 address counts as its IPv4 address.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, canonical(ip)) {
            (IpAddr::V4(_), ip @ IpAddr::V4(_)) | (IpAddr::V6(_), ip @ IpAddr::V6(_)) => {
                Cidr::new(ip, self.prefix_len).is_ok_and(|c| c.network == self.network)
            }
            _ => false,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for Cidr {
    type Err = NetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || NetError::InvalidCidr(s.to_string());
        let (ip, prefix) = s.split_once('/').ok_or_else(bad)?;
        if prefix.is_empty() || prefix.len() > 3 || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        let ip: IpAddr = ip.parse().map_err(|_| bad())?;
        let prefix: u8 = prefix.parse().map_err(|_| bad())?;
        Cidr::new(ip, prefix).map_err(|_| bad())
    }
}

/// The `direct_addresses` policy of a server or agent config (§10).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DirectAddresses {
    /// Only the addresses of the interface that carries the default route. The default.
    #[default]
    DefaultRoute,
    /// No direct addresses: relay only.
    None,
    /// The addresses inside one of these networks (1-[`MAX_CIDRS`] of them).
    Cidrs(Vec<Cidr>),
}

impl DirectAddresses {
    /// Checks the CIDR count.
    pub fn validate(&self) -> Result<(), NetError> {
        match self {
            DirectAddresses::Cidrs(c) if c.is_empty() || c.len() > MAX_CIDRS => Err(NetError::CidrCount),
            _ => Ok(()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum PolicyRepr {
    Word(String),
    List(Vec<String>),
}

impl Serialize for DirectAddresses {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let repr = match self {
            DirectAddresses::DefaultRoute => PolicyRepr::Word("default-route".into()),
            DirectAddresses::None => PolicyRepr::Word("none".into()),
            DirectAddresses::Cidrs(c) => PolicyRepr::List(c.iter().map(ToString::to_string).collect()),
        };
        repr.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DirectAddresses {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let policy =
            match PolicyRepr::deserialize(deserializer).map_err(|_| D::Error::custom(NetError::InvalidPolicy))? {
                PolicyRepr::Word(w) if w == "default-route" => DirectAddresses::DefaultRoute,
                PolicyRepr::Word(w) if w == "none" => DirectAddresses::None,
                PolicyRepr::Word(_) => return Err(D::Error::custom(NetError::InvalidPolicy)),
                PolicyRepr::List(items) => DirectAddresses::Cidrs(
                    items
                        .iter()
                        .map(|s| s.parse())
                        .collect::<Result<_, NetError>>()
                        .map_err(D::Error::custom)?,
                ),
            };
        policy.validate().map_err(D::Error::custom)?;
        Ok(policy)
    }
}

/// An IPv4-mapped IPv6 address as its IPv4 address; anything else unchanged.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// An IPv4-mapped IPv6 network with a prefix of at least 96 bits as the IPv4 network; anything else unchanged.
fn canonical_net(ip: IpAddr, prefix_len: u8) -> (IpAddr, u8) {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) if prefix_len >= 96 => (IpAddr::V4(v4), prefix_len - 96),
            _ => (ip, prefix_len),
        },
        IpAddr::V4(_) => (ip, prefix_len),
    }
}

/// Whether an interface name is a container, VM or overlay network ([`VIRTUAL_INTERFACE_PREFIXES`]).
#[must_use]
pub fn is_virtual_interface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    VIRTUAL_INTERFACE_PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// Whether an address may never be advertised or used, whatever the policy: CGNAT and Tailscale, link-local,
/// multicast, broadcast and unspecified.
#[must_use]
pub fn is_forbidden_address(ip: IpAddr) -> bool {
    const CGNAT: Cidr = Cidr {
        network: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)),
        prefix_len: 10,
    };
    const TAILSCALE_V6: Cidr = Cidr {
        network: IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0)),
        prefix_len: 48,
    };
    match canonical(ip) {
        IpAddr::V4(v4) => {
            CGNAT.contains(ip) || v4.is_link_local() || v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            TAILSCALE_V6.contains(ip) || v6.is_unicast_link_local() || v6.is_multicast() || v6.is_unspecified()
        }
    }
}

/// The addresses to bind (and so to advertise) under `policy`.
///
/// `default_route` is the name of the interface that carries the default route, if the caller knows it; without
/// it, `"default-route"` selects nothing (relay only), which fails closed. The result is sorted and has no
/// duplicates.
#[must_use]
pub fn select_addresses(
    interfaces: &[Interface],
    default_route: Option<&str>,
    policy: &DirectAddresses,
) -> Vec<SelectedAddr> {
    let mut out: Vec<SelectedAddr> = interfaces
        .iter()
        .filter(|i| i.is_up && !is_virtual_interface(&i.name))
        .filter(|i| match policy {
            DirectAddresses::DefaultRoute => default_route.is_some_and(|d| d == i.name),
            DirectAddresses::None => false,
            DirectAddresses::Cidrs(_) => true,
        })
        .flat_map(|i| {
            i.addrs.iter().map(move |a| {
                let (ip, prefix_len) = canonical_net(a.ip, a.prefix_len);
                SelectedAddr {
                    addr: IfAddr { ip, prefix_len },
                    interface: i.name.clone(),
                }
            })
        })
        .filter(|s| !is_forbidden_address(s.addr.ip))
        .filter(|s| match policy {
            DirectAddresses::DefaultRoute => !s.addr.ip.is_loopback(),
            DirectAddresses::None => false,
            DirectAddresses::Cidrs(cidrs) => cidrs.iter().any(|c| c.contains(s.addr.ip)),
        })
        .collect();
    out.sort();
    out.dedup_by(|a, b| a.addr.ip == b.addr.ip);
    out
}

/// How long a burst of network change notifications must be quiet before the addresses are selected again.
pub const NETWORK_CHANGE_DEBOUNCE: Duration = Duration::from_secs(2);

/// Re-selects the advertised addresses when the network changes (T05 review, carry-over 6), for the server and the
/// agent alike.
///
/// It is pure: the caller feeds it change notifications ([`Reselector::notify`], for example from `netwatch`) and,
/// once [`Reselector::deadline`] has passed, a fresh interface snapshot ([`Reselector::poll`]). Notifications are
/// debounced: the selection runs once the network has been quiet for the debounce period, so a DHCP renewal or a
/// Wi-Fi roam that fires a dozen events re-binds once. Only a selection that differs from the current one is
/// reported, as an [`AddressChange`] whose `Display` lists **interface names only**, never addresses.
#[derive(Debug, Clone)]
pub struct Reselector {
    policy: DirectAddresses,
    current: Vec<SelectedAddr>,
    debounce: Duration,
    due: Option<Instant>,
}

/// A new selection of addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressChange {
    /// The addresses to bind now (empty: relay only).
    pub addrs: Vec<SelectedAddr>,
    /// Their interfaces, sorted, without duplicates: what to log.
    pub interfaces: Vec<String>,
}

impl fmt::Display for AddressChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.interfaces.is_empty() {
            f.write_str("none (relay only)")
        } else {
            f.write_str(&self.interfaces.join(", "))
        }
    }
}

impl Reselector {
    /// A reselector for `policy`, starting from the `current` selection (what the endpoint is bound to).
    #[must_use]
    pub fn new(policy: DirectAddresses, current: Vec<SelectedAddr>, debounce: Duration) -> Self {
        Self {
            policy,
            current,
            debounce,
            due: None,
        }
    }

    /// Whether network changes matter at all: `"none"` (relay only) never selects an address.
    #[must_use]
    pub fn watches(&self) -> bool {
        self.policy != DirectAddresses::None
    }

    /// A change notification arrived at `now`: select again once `now + debounce` passes quietly.
    pub fn notify(&mut self, now: Instant) {
        if self.watches() {
            self.due = Some(now + self.debounce);
        }
    }

    /// When [`Reselector::poll`] should run, if a change is pending.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.due
    }

    /// The selection now in force.
    #[must_use]
    pub fn current(&self) -> &[SelectedAddr] {
        &self.current
    }

    /// If a change is pending and due at `now`, selects from this snapshot. Returns the new selection when it
    /// differs from the current one (which it then replaces).
    pub fn poll(
        &mut self,
        now: Instant,
        interfaces: &[Interface],
        default_route: Option<&str>,
    ) -> Option<AddressChange> {
        match self.due {
            Some(due) if now >= due => self.due = None,
            _ => return None,
        }
        let addrs = select_addresses(interfaces, default_route, &self.policy);
        if addrs == self.current {
            return None;
        }
        self.current.clone_from(&addrs);
        let mut interfaces: Vec<String> = addrs.iter().map(|a| a.interface.clone()).collect();
        interfaces.sort();
        interfaces.dedup();
        Some(AddressChange { addrs, interfaces })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ifc(name: &str, addrs: &[&str]) -> Interface {
        Interface {
            name: name.into(),
            is_up: true,
            addrs: addrs
                .iter()
                .map(|a| {
                    let (ip, prefix) = a.split_once('/').unwrap();
                    IfAddr {
                        ip: ip.parse().unwrap(),
                        prefix_len: prefix.parse().unwrap(),
                    }
                })
                .collect(),
        }
    }

    /// A machine like E4's: a LAN interface with the default route, Tailscale, Docker and Podman bridges, a VM
    /// bridge, a Hyper-V switch and loopback.
    fn host() -> Vec<Interface> {
        vec![
            ifc("lo", &["127.0.0.1/8", "::1/128"]),
            ifc(
                "eth0",
                &[
                    "192.0.2.10/24",
                    "169.254.10.1/16",
                    "fe80::1/64",
                    "2001:db8::10/64",
                    "100.64.1.2/10",
                ],
            ),
            ifc("tailscale0", &["100.100.1.1/32", "fd7a:115c:a1e0::1/128"]),
            ifc("docker0", &["198.51.100.1/24"]),
            ifc("br-1a2b3c", &["198.51.100.129/25"]),
            ifc("podman0", &["203.0.113.1/24"]),
            ifc("cni-podman1", &["203.0.113.129/25"]),
            ifc("virbr0", &["192.0.2.129/25"]),
            ifc("vEthernet (WSL)", &["198.18.0.1/24"]),
            ifc("wlan0", &["198.51.100.200/24"]),
        ]
    }

    fn ips(selected: &[SelectedAddr]) -> Vec<String> {
        selected.iter().map(|s| s.addr.ip.to_string()).collect()
    }

    #[test]
    fn default_route_keeps_only_the_default_interface_and_drops_bad_ranges() {
        let got = select_addresses(&host(), Some("eth0"), &DirectAddresses::DefaultRoute);
        assert_eq!(ips(&got), ["192.0.2.10", "2001:db8::10"]);
        assert!(got.iter().all(|s| s.interface == "eth0"));
        assert_eq!(got[0].addr.prefix_len, 24);
    }

    #[test]
    fn default_route_unknown_selects_nothing() {
        assert!(select_addresses(&host(), None, &DirectAddresses::DefaultRoute).is_empty());
        // A default route through a bridge or Tailscale is never used either.
        for bridge in ["docker0", "tailscale0", "vEthernet (WSL)", "br-1a2b3c"] {
            assert!(
                select_addresses(&host(), Some(bridge), &DirectAddresses::DefaultRoute).is_empty(),
                "{bridge}"
            );
        }
        // Loopback is never the default-route choice.
        assert!(select_addresses(&host(), Some("lo"), &DirectAddresses::DefaultRoute).is_empty());
    }

    #[test]
    fn none_means_relay_only() {
        assert!(select_addresses(&host(), Some("eth0"), &DirectAddresses::None).is_empty());
    }

    #[test]
    fn cidr_lists_select_inside_them_but_never_bridges_or_forbidden_ranges() {
        let all = DirectAddresses::Cidrs(vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]);
        let got = select_addresses(&host(), Some("eth0"), &all);
        // Every interface except the bridges, Tailscale and the forbidden addresses; loopback is inside /0.
        assert_eq!(
            ips(&got),
            ["127.0.0.1", "192.0.2.10", "198.51.100.200", "::1", "2001:db8::10"]
        );
        let lan = DirectAddresses::Cidrs(vec!["198.51.100.0/24".parse().unwrap()]);
        let got = select_addresses(&host(), Some("eth0"), &lan);
        assert_eq!(ips(&got), ["198.51.100.200"]);
        assert_eq!(got[0].interface, "wlan0");
        // Naming a forbidden range explicitly still selects nothing from it.
        let cgnat = DirectAddresses::Cidrs(vec![
            "100.64.0.0/10".parse().unwrap(),
            "169.254.0.0/16".parse().unwrap(),
            "fe80::/10".parse().unwrap(),
            "fd7a:115c:a1e0::/48".parse().unwrap(),
        ]);
        assert!(select_addresses(&host(), Some("eth0"), &cgnat).is_empty());
        // Loopback only when named.
        let lo = DirectAddresses::Cidrs(vec!["127.0.0.0/8".parse().unwrap()]);
        assert_eq!(ips(&select_addresses(&host(), None, &lo)), ["127.0.0.1"]);
    }

    #[test]
    fn interfaces_that_are_down_are_skipped() {
        let mut h = host();
        for i in &mut h {
            i.is_up = i.name != "eth0";
        }
        assert!(select_addresses(&h, Some("eth0"), &DirectAddresses::DefaultRoute).is_empty());
    }

    #[test]
    fn virtual_interface_names() {
        for name in [
            "docker0",
            "br-0123abcd",
            "podman1",
            "cni0",
            "cni-podman0",
            "virbr0",
            "vEthernet (Default Switch)",
            "VETHERNET (WSL)",
            "veth1234",
            "tailscale0",
        ] {
            assert!(is_virtual_interface(name), "{name}");
        }
        for name in ["eth0", "enp3s0", "wlan0", "wlp2s0", "lo", "bond0", "eno1"] {
            assert!(!is_virtual_interface(name), "{name}");
        }
    }

    #[test]
    fn forbidden_addresses() {
        for ip in [
            "100.64.0.0",
            "100.127.255.255",
            "169.254.1.1",
            "fe80::1",
            "febf::1",
            "fd7a:115c:a1e0:ab12::1",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "0.0.0.0",
            "::",
            "::ffff:100.64.0.1",
            "::ffff:169.254.0.1",
        ] {
            assert!(is_forbidden_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "100.63.255.255",
            "100.128.0.0",
            "192.0.2.1",
            "2001:db8::1",
            "fd00::1",
            "127.0.0.1",
        ] {
            assert!(!is_forbidden_address(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn ipv4_mapped_addresses_are_treated_as_ipv4() {
        let h = vec![ifc("eth0", &["::ffff:192.0.2.7/120", "::ffff:100.64.0.9/120"])];
        let got = select_addresses(&h, Some("eth0"), &DirectAddresses::DefaultRoute);
        assert_eq!(ips(&got), ["192.0.2.7"]);
        assert_eq!(got[0].addr.prefix_len, 24);
    }

    #[test]
    fn cidr_parsing_and_containment() {
        let c: Cidr = "192.0.2.77/24".parse().unwrap();
        assert_eq!(c.to_string(), "192.0.2.0/24");
        assert!(c.contains("192.0.2.1".parse().unwrap()));
        assert!(c.contains("::ffff:192.0.2.1".parse().unwrap()));
        assert!(!c.contains("192.0.3.1".parse().unwrap()));
        assert!(!c.contains("2001:db8::1".parse().unwrap()));
        let v6: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        assert!(
            "0.0.0.0/0"
                .parse::<Cidr>()
                .unwrap()
                .contains("203.0.113.1".parse().unwrap())
        );
        for bad in [
            "",
            "192.0.2.0",
            "192.0.2.0/",
            "192.0.2.0/33",
            "2001:db8::/129",
            "x/8",
            "192.0.2.0/+8",
            "1.2.3.4/0008",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
    }

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn reselection_is_debounced_and_reports_only_real_changes() {
        let start = t0();
        let first = select_addresses(&host(), Some("eth0"), &DirectAddresses::DefaultRoute);
        let mut r = Reselector::new(DirectAddresses::DefaultRoute, first.clone(), NETWORK_CHANGE_DEBOUNCE);
        assert_eq!(r.deadline(), None, "nothing pending");
        assert_eq!(
            r.poll(start, &host(), Some("eth0")),
            None,
            "nothing pending, nothing done"
        );
        // A burst of notifications: the deadline moves with the last one (trailing debounce).
        r.notify(start);
        r.notify(start + Duration::from_millis(500));
        let due = start + Duration::from_millis(500) + NETWORK_CHANGE_DEBOUNCE;
        assert_eq!(r.deadline(), Some(due));
        assert_eq!(
            r.poll(due - Duration::from_millis(1), &host(), Some("wlan0")),
            None,
            "not yet"
        );
        // Due, but the selection is the same: no change to report, and nothing pending any more.
        assert_eq!(r.poll(due, &host(), Some("eth0")), None);
        assert_eq!(r.deadline(), None);
        // The default route moves to wlan0: a change, reported by interface name.
        r.notify(due);
        let change = r
            .poll(due + NETWORK_CHANGE_DEBOUNCE, &host(), Some("wlan0"))
            .expect("a change");
        assert_eq!(change.interfaces, ["wlan0"]);
        assert_eq!(ips(&change.addrs), ["198.51.100.200"]);
        assert_eq!(r.current(), change.addrs.as_slice());
        assert_eq!(change.to_string(), "wlan0");
        // The network goes away: relay only.
        r.notify(due);
        let gone = r.poll(due + NETWORK_CHANGE_DEBOUNCE, &[], None).expect("a change");
        assert!(gone.addrs.is_empty());
        assert_eq!(gone.to_string(), "none (relay only)");
        // ... and comes back.
        r.notify(due);
        let back = r
            .poll(due + NETWORK_CHANGE_DEBOUNCE, &host(), Some("eth0"))
            .expect("a change");
        assert_eq!(back.addrs, first);
        assert_eq!(back.to_string(), "eth0");
    }

    /// The log line carries interface names only, never an address (§10: addresses travel only inside join tokens
    /// and connections).
    #[test]
    fn a_change_never_shows_addresses() {
        let all = DirectAddresses::Cidrs(vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]);
        let mut r = Reselector::new(all, Vec::new(), NETWORK_CHANGE_DEBOUNCE);
        let now = t0();
        r.notify(now);
        let change = r.poll(now + NETWORK_CHANGE_DEBOUNCE, &host(), Some("eth0")).unwrap();
        let shown = format!("{change} {change:?}");
        assert_eq!(change.to_string(), "eth0, lo, wlan0");
        let display = change.to_string();
        for a in &change.addrs {
            assert!(!display.contains(&a.addr.ip.to_string()), "{display}");
        }
        assert!(shown.contains("eth0"));
    }

    #[test]
    fn the_none_policy_never_changes() {
        let mut r = Reselector::new(DirectAddresses::None, Vec::new(), NETWORK_CHANGE_DEBOUNCE);
        let now = t0();
        r.notify(now);
        assert_eq!(r.poll(now + NETWORK_CHANGE_DEBOUNCE, &host(), Some("eth0")), None);
        assert!(!r.watches(), "relay-only needs no watcher");
        assert!(Reselector::new(DirectAddresses::DefaultRoute, Vec::new(), NETWORK_CHANGE_DEBOUNCE).watches());
    }

    #[test]
    fn policy_serde() {
        #[derive(Debug, Deserialize, Serialize, PartialEq)]
        struct C {
            d: DirectAddresses,
        }
        let parse = |j: &str| serde_json::from_str::<C>(j).map(|c| c.d);
        assert_eq!(
            parse(r#"{"d":"default-route"}"#).unwrap(),
            DirectAddresses::DefaultRoute
        );
        assert_eq!(parse(r#"{"d":"none"}"#).unwrap(), DirectAddresses::None);
        let list = parse(r#"{"d":["192.0.2.0/24","2001:db8::/32"]}"#).unwrap();
        assert_eq!(
            list,
            DirectAddresses::Cidrs(vec!["192.0.2.0/24".parse().unwrap(), "2001:db8::/32".parse().unwrap()])
        );
        assert_eq!(
            serde_json::to_string(&C { d: list }).unwrap(),
            r#"{"d":["192.0.2.0/24","2001:db8::/32"]}"#
        );
        for bad in [r#"{"d":"all"}"#, r#"{"d":[]}"#, r#"{"d":["nope"]}"#, r#"{"d":5}"#] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        let many = format!(r#"{{"d":[{}]}}"#, vec![r#""192.0.2.0/24""#; MAX_CIDRS + 1].join(","));
        assert!(parse(&many).is_err());
        assert_eq!(DirectAddresses::default(), DirectAddresses::DefaultRoute);
    }
}
