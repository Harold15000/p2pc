// SPDX-License-Identifier: Apache-2.0

//! The iroh endpoint plumbing of P2PC (spec §10), shared by the server and the agent.
//!
//! [`p2pc_proto::net`] holds the pure rules (which addresses may be bound, and [`Reselector`] for network changes);
//! this crate applies them to iroh and `netwatch`, so both ends bind, advertise and re-select in exactly one way:
//!
//! - [`bind_endpoint`]: an endpoint with **no port mapping** (iroh is built without `portmapper` and the builder
//!   disables it too), **no address lookup** (the `Minimal` preset, every lookup cleared: addresses travel only inside
//!   join tokens, server addresses and connections), and exactly one UDP socket per address
//!   [`select_addresses`](p2pc_proto::net::select_addresses) chose (iroh advertises what it is bound to, so binding
//!   is what controls advertising). No address and no relay is refused: nothing could reach the endpoint.
//! - [`interfaces_from`], [`host_interfaces`] and [`current_selection`]: the interface snapshot in
//!   `p2pc_proto::net`'s form, from `netwatch`.
//! - [`relay_mode`]: the relay mode for a list of relays (none at all when it is empty).
//! - [`watch_network`]: `netwatch`'s change notifications, debounced by [`Reselector`], sent on as an
//!   [`AddressChange`] only when the selection differs, and logged with **interface names only**, never addresses.
//! - [`watch_public_addresses`]: the node's **public** addresses as its endpoint knows them (QUIC address discovery
//!   through the relays, or a public address it is bound to), for the egress proxy's hairpin-NAT protection (§9).
//!   [`PublicAddrTracker`] keeps IPv4 and IPv6 apart and says apart from the address list whether the gate may open:
//!   on a **host** with IPv4 connectivity ([`host_has_ipv4`], never judged from what iroh is bound to; container, VM
//!   and overlay interfaces do not count) not before a public IPv4 is observed on the current network, and it closes
//!   again, without dropping any address, when IPv4 comes up or the network changes; a move of the default route
//!   makes the watcher ask the agent for a new endpoint itself ([`GateSinks::rebind`]), and only that endpoint's first
//!   public IPv4 reopens it. The gate is an
//!   [`EgressGate`]: besides open and closed it says when it can never open ([`IPV4_NOT_BOUND`], or
//!   [`IPV4_UPLINK_NAMED_LIKE_BRIDGE`] when the uplink's name looks like a container bridge).
//!
//! Remote peers' addresses cannot be filtered with iroh 1.4: see `docs/security/residual-risks.md` (R-1).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{BindOpts, PortmapperConfig, presets};
use iroh::{Endpoint, EndpointAddr, RelayMode, RelayUrl, SecretKey, Watcher};
use p2pc_proto::net::{
    AddressChange, DirectAddresses, IfAddr, Interface, NETWORK_CHANGE_DEBOUNCE, Reselector, SelectedAddr,
    is_forbidden_address, is_virtual_interface, select_addresses,
};
use tokio::sync::{Notify, mpsc, watch};

/// Why an endpoint could not be bound.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    /// The builder refused an address.
    #[error("invalid bind address {0}")]
    Address(SocketAddr),
    /// iroh could not bind.
    #[error("cannot bind the iroh endpoint: {0}")]
    Bind(String),
    /// Nothing to bind and no relays: the endpoint would be unreachable.
    #[error("the iroh endpoint has no direct address and no relay; set iroh.direct_addresses or iroh.relays")]
    Unreachable,
}

/// What to bind.
#[derive(Debug, Clone)]
pub struct BindSpec {
    /// The relays (`RelayMode::Disabled` in tests).
    pub relay_mode: RelayMode,
    /// One IP socket per address. Empty means relay only.
    pub addrs: Vec<SelectedAddr>,
    /// The port of every IP socket (0: the OS picks one per socket).
    pub port: u16,
    /// The ALPNs the endpoint **accepts**. Empty (the agent) accepts no connection at all.
    pub alpns: Vec<Vec<u8>>,
}

/// The relay mode for `relays`: exactly those relays, or [`RelayMode::Disabled`] when there are none (never the
/// public defaults by accident).
#[must_use]
pub fn relay_mode(relays: impl IntoIterator<Item = RelayUrl>) -> RelayMode {
    let relays: Vec<RelayUrl> = relays.into_iter().collect();
    if relays.is_empty() {
        RelayMode::Disabled
    } else {
        RelayMode::custom(relays)
    }
}

/// Binds an endpoint with `secret` under the §10 rules (see the crate docs).
pub async fn bind_endpoint(secret: SecretKey, spec: &BindSpec) -> Result<Endpoint, BindError> {
    if spec.addrs.is_empty() && spec.relay_mode == RelayMode::Disabled {
        return Err(BindError::Unreachable);
    }
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .alpns(spec.alpns.clone())
        .relay_mode(spec.relay_mode.clone())
        .portmapper_config(PortmapperConfig::Disabled)
        .clear_address_lookup()
        .clear_ip_transports();
    let (mut have_v4, mut have_v6) = (false, false);
    for selected in &spec.addrs {
        let socket = SocketAddr::new(selected.addr.ip, spec.port);
        // The first address of each family carries the default route; the others serve their own subnets.
        let seen = if socket.is_ipv4() { &mut have_v4 } else { &mut have_v6 };
        let opts = BindOpts::default()
            .set_prefix_len(selected.addr.prefix_len)
            .set_is_default_route(!*seen);
        *seen = true;
        builder = builder
            .bind_addr_with_opts(socket, opts)
            .map_err(|_| BindError::Address(socket))?;
    }
    builder.bind().await.map_err(|e| BindError::Bind(e.to_string()))
}

/// A `netwatch` snapshot in `p2pc_proto::net`'s form, and the default-route interface. Deprecated, tentative and
/// duplicated IPv6 addresses are left out.
#[must_use]
pub fn interfaces_from(state: &netwatch::interfaces::State) -> (Vec<Interface>, Option<String>) {
    let interfaces = state
        .interfaces
        .values()
        .map(|i| {
            let addrs = i
                .addrs()
                .filter_map(|net| match net {
                    netwatch::interfaces::IpNet::V4(v4) => Some(IfAddr::new(IpAddr::V4(v4.addr()), v4.prefix_len())),
                    netwatch::interfaces::IpNet::V6 { net, flags, .. } => {
                        let usable = !(flags.deprecated || flags.tentative || flags.duplicated);
                        usable.then(|| IfAddr::new(IpAddr::V6(net.addr()), net.prefix_len()))
                    }
                })
                .collect();
            Interface::new(i.name(), i.is_up(), addrs)
        })
        .collect();
    (interfaces, state.default_route_interface.clone())
}

/// The interfaces of this machine now, and the default-route interface.
pub async fn host_interfaces() -> (Vec<Interface>, Option<String>) {
    interfaces_from(&netwatch::interfaces::State::new().await)
}

/// The addresses `policy` selects on this machine now (none under `"none"`, without looking).
pub async fn current_selection(policy: &DirectAddresses) -> Vec<SelectedAddr> {
    if *policy == DirectAddresses::None {
        return Vec::new();
    }
    let (interfaces, default_route) = host_interfaces().await;
    select_addresses(&interfaces, default_route.as_deref(), policy)
}

/// Watches the network: each new selection (debounced, and only when it differs from the last one) is logged with
/// its interface names and sent to `changes`. Starts from `initial`, what the endpoint is bound to. Returns at once
/// under `"none"`, when `changes` is closed, or when the network cannot be watched.
pub async fn watch_network(policy: DirectAddresses, initial: Vec<SelectedAddr>, changes: mpsc::Sender<AddressChange>) {
    let mut reselector = Reselector::new(policy, initial, NETWORK_CHANGE_DEBOUNCE);
    if !reselector.watches() {
        return;
    }
    let monitor = match netwatch::netmon::Monitor::new().await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "cannot watch the network; the iroh addresses stay as selected at start");
            return;
        }
    };
    let mut state = monitor.interface_state();
    loop {
        let due = reselector.deadline().map(tokio::time::Instant::from_std);
        tokio::select! {
            updated = state.updated() => {
                if updated.is_err() {
                    return;
                }
                reselector.notify(tokio::time::Instant::now().into_std());
            }
            () = async {
                match due {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => {
                let (interfaces, default_route) = interfaces_from(&state.get());
                let now = tokio::time::Instant::now().into_std();
                if let Some(change) = reselector.poll(now, &interfaces, default_route.as_deref()) {
                    // Interface names only: never the addresses (§10).
                    tracing::info!(interfaces = %change, "network changed: re-binding the iroh endpoint");
                    if changes.send(change).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// Whether `ip` can be seen from the internet: not loopback, private (RFC 1918), unique-local (`fc00::/7`), CGNAT,
/// link-local, multicast, broadcast or unspecified.
#[must_use]
pub fn is_public_address(ip: IpAddr) -> bool {
    if is_forbidden_address(ip) || ip.is_loopback() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_private(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_address(IpAddr::V4(v4)),
            None => !v6.is_unique_local(),
        },
    }
}

/// The public addresses among `addrs`, sorted, without duplicates.
pub fn public_addresses<'a>(addrs: impl IntoIterator<Item = &'a SocketAddr>) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = addrs
        .into_iter()
        .map(SocketAddr::ip)
        .filter(|ip| is_public_address(*ip))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Whether `ip` is an IPv4 address a host could reach the internet from: not loopback, link-local, unspecified,
/// multicast or broadcast. A private or CGNAT one counts: that is a host behind NAT.
fn is_ipv4_connectivity(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified() && !v4.is_multicast() && !v4.is_broadcast()
        }
        IpAddr::V6(_) => false,
    }
}

/// Whether the **host** has IPv4 connectivity: an interface that is up has an IPv4 address that is not loopback,
/// link-local, unspecified, multicast or broadcast (private and CGNAT ones count: that is a host behind NAT).
/// Container, VM and overlay interfaces ([`is_virtual_interface`]: `podman*`, `docker*`, `virbr*`, `tailscale*`…) are
/// left out, whatever their addresses: a bridge's `10.88.0.1` or Tailscale's `100.64/10` address is not a way to the
/// internet, and counting it would close the egress gate on a host that has no IPv4 route (T10f).
///
/// This is read from the host's interfaces, never from what iroh is bound to: the agent binds only the addresses
/// `select_addresses` picks, which drops CGNAT ones and honours an IPv6-only `direct_addresses`, yet the egress proxy
/// uses the host's network stack, so it can reach the internet over the host's IPv4 whatever iroh is bound to (T10e).
/// An interface list that is empty means the enumeration failed, not that the host has no network: that is taken as
/// "has IPv4", so the egress gate fails closed.
#[must_use]
pub fn host_has_ipv4(interfaces: &[Interface]) -> bool {
    host_has_ipv4_via(interfaces, None)
}

/// [`host_has_ipv4`], where the interface that carries the default route always counts, whatever its name (T10f review,
/// P3-1). The name filter cannot tell a real uplink called `br-lan` or `br-ex` from a container bridge, and getting
/// that wrong would open the gate on IPv6 on a host that has IPv4.
#[must_use]
pub fn host_has_ipv4_via(interfaces: &[Interface], default_route: Option<&str>) -> bool {
    interfaces.is_empty()
        || interfaces
            .iter()
            .filter(|i| i.is_up && (!is_virtual_interface(&i.name) || default_route == Some(i.name.as_str())))
            .flat_map(|i| &i.addrs)
            .any(|a| is_ipv4_connectivity(a.ip))
}

/// Interface-name prefixes of bridges (a subset of [`is_virtual_interface`]'s): names a real uplink can have too
/// (`br-lan`), where renaming the interface is advice that can work. Overlays (`tailscale*`, `zt*`) and `veth*` are not
/// in it: nobody should rename those (T10h review P3-1).
const BRIDGE_PREFIXES: &[&str] = &["br-", "virbr", "lxcbr", "lxdbr", "docker", "podman", "cni"];

/// Whether an interface name looks like a bridge ([`BRIDGE_PREFIXES`]), case-insensitively like
/// [`is_virtual_interface`].
fn is_bridge_like_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    BRIDGE_PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// What the egress gate needs to know about the host's network: whether it has IPv4 ([`host_has_ipv4`]) and which
/// interface carries the default route. A change of the route is a move to another network (T10f).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostNet {
    /// [`host_has_ipv4`].
    pub ipv4: bool,
    /// The default-route interface, if any.
    pub default_route: Option<String>,
    /// The default-route interface is up, has an IPv4 address that iroh could bind (not CGNAT or link-local) and is
    /// named like a bridge ([`BRIDGE_PREFIXES`]: `br-lan`, `br-ex`, `docker0`…), whatever the other interfaces have. It
    /// counts for [`HostNet::ipv4`], yet `select_addresses` drops every virtual-named interface under every policy, so
    /// iroh never binds it. Binding another interface's address (a real-named `eth1`) by CIDR is not a supported fix:
    /// what it does depends on the host's routing ([`IPV4_UPLINK_NAMED_LIKE_BRIDGE`]).
    pub bridge_named_uplink: bool,
}

impl HostNet {
    /// A `netwatch` snapshot as the gate needs it.
    #[must_use]
    pub fn from_state(state: &netwatch::interfaces::State) -> Self {
        let (interfaces, default_route) = interfaces_from(state);
        Self::from_interfaces(&interfaces, default_route)
    }

    /// An interface list and its default-route interface as the gate needs them.
    #[must_use]
    pub fn from_interfaces(interfaces: &[Interface], default_route: Option<String>) -> Self {
        let ipv4 = host_has_ipv4_via(interfaces, default_route.as_deref());
        let bridge_named_uplink = interfaces.iter().any(|i| {
            default_route.as_deref() == Some(i.name.as_str())
                && i.is_up
                && is_bridge_like_name(&i.name)
                && i.addrs
                    .iter()
                    .any(|a| is_ipv4_connectivity(a.ip) && !is_forbidden_address(a.ip))
        });
        Self {
            ipv4,
            bridge_named_uplink,
            default_route,
        }
    }
}

/// [`HostNet`] for this machine now.
pub async fn host_net_now() -> HostNet {
    HostNet::from_state(&netwatch::interfaces::State::new().await)
}

/// Keeps `tx` at the host's [`HostNet`], re-measured on each network change (`netwatch`), until every receiver of `tx`
/// is gone. The monitor's own first state is measured at once, so a change between the caller's measurement and the
/// monitor's creation (boot before DHCPv4) is not missed until the next network event. Without a working network
/// monitor the value measured at the start stays (and a warning says so). `tx` should start at the value measured by
/// the caller.
pub async fn watch_host_net(tx: watch::Sender<HostNet>) {
    let monitor = match netwatch::netmon::Monitor::new().await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "cannot watch the network; the egress gate keeps the network state measured at start"
            );
            tx.closed().await;
            return;
        }
    };
    keep_host_net(tx, monitor.interface_state()).await;
}

/// [`watch_host_net`] over a given source of interface states.
async fn keep_host_net<W>(tx: watch::Sender<HostNet>, mut state: W)
where
    W: Watcher<Value = netwatch::interfaces::State>,
{
    let measure = |tx: &watch::Sender<HostNet>, state: &mut W| {
        let now = HostNet::from_state(&state.get());
        tx.send_if_modified(|known| std::mem::replace(known, now.clone()) != now);
    };
    // The state may already differ from what the caller measured before the monitor existed.
    measure(&tx, &mut state);
    loop {
        tokio::select! {
            updated = state.updated() => {
                if updated.is_err() {
                    tx.closed().await;
                    return;
                }
                measure(&tx, &mut state);
            }
            () = tx.closed() => return,
        }
    }
}

/// The egress gate's state (T10a, T10e, T10f). Only [`EgressGate::Open`] lets an egress proxy start, and a running
/// proxy refuses IPv4 destinations in any other state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EgressGate {
    /// The node's public addresses are not known well enough yet (no public IPv4 on a host with IPv4, or the network
    /// changed). Closed until the endpoint observes them.
    #[default]
    Closed,
    /// Known well enough to refuse hairpin NAT.
    Open,
    /// Closed, and it cannot open by waiting: the host has IPv4 but the iroh endpoint is bound to no IPv4 address,
    /// so the public IPv4 is never learned ([`IPV4_NOT_BOUND`]).
    NoIpv4Bound,
    /// Closed, and it cannot open by waiting: the host's default-route interface has IPv4 and a name that looks like
    /// a container bridge, so it is never bound and the public IPv4 is never learned
    /// ([`IPV4_UPLINK_NAMED_LIKE_BRIDGE`]).
    BridgeNamedUplink,
}

impl EgressGate {
    /// Whether egress proxies may start and IPv4 destinations are allowed.
    #[must_use]
    pub fn is_open(self) -> bool {
        self == Self::Open
    }

    /// The state's name, as the agent's log and `p2pc-agent status` say it (T10l).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::NoIpv4Bound => "no_ipv4_bound",
            Self::BridgeNamedUplink => "bridge_named_uplink",
        }
    }
}

/// What a verdict of the egress gate was made from (T10l). The agent logs it at each change of the gate and shows the
/// reason in `p2pc-agent status`, so a gate that stays closed says why. No public address is ever in it, only whether
/// one was seen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GateInputs {
    /// [`HostNet::ipv4`].
    pub host_ipv4: bool,
    /// [`HostNet::default_route`]: an interface name.
    pub default_route: Option<String>,
    /// Whether the iroh endpoint is bound to an IPv4 address.
    pub ipv4_bound: bool,
    /// Whether a public IPv4 is known (kept across network changes).
    pub public_ipv4_known: bool,
    /// Whether a public IPv4 was observed since the network last changed.
    pub public_ipv4_here: bool,
    /// Whether a public IPv6 is known.
    pub public_ipv6_known: bool,
    /// The network changed since this endpoint was bound (its default route moved, or the agent is rebinding it): it is
    /// not trusted again, and the new endpoint's first public IPv4 opens the gate.
    pub network_changed: bool,
}

/// The egress gate and why (T10l).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GateReport {
    /// The gate.
    pub state: EgressGate,
    /// What it was decided from.
    pub inputs: GateInputs,
}

impl GateReport {
    /// Why the gate is in its state, in words (no addresses).
    #[must_use]
    pub fn reason(&self) -> &'static str {
        let i = &self.inputs;
        match self.state {
            EgressGate::Open if i.public_ipv4_here => "a public IPv4 was observed on this network",
            EgressGate::Open => "the host has no IPv4 and a public IPv6 was observed",
            EgressGate::NoIpv4Bound => "the host has IPv4 but the iroh endpoint is bound to no IPv4 address",
            EgressGate::BridgeNamedUplink => {
                "the default-route interface has IPv4 but is named like a container bridge"
            }
            EgressGate::Closed if i.network_changed && i.host_ipv4 => {
                "the network changed; waiting for the rebound endpoint to observe a public IPv4 on the new network"
            }
            EgressGate::Closed if i.public_ipv4_known && i.host_ipv4 => {
                "a public IPv4 was seen on an earlier network; none on this one yet"
            }
            EgressGate::Closed if i.host_ipv4 => {
                "waiting for a public IPv4 from the relay (QUIC address discovery); none seen yet"
            }
            EgressGate::Closed => "the host has no IPv4; waiting for a public IPv6; none seen yet",
        }
    }

    /// One line for `p2pc-agent status`: the same words as the log.
    #[must_use]
    pub fn line(&self) -> String {
        format!("{}: {}", self.state.label(), self.reason())
    }

    fn log(&self) {
        let i = &self.inputs;
        tracing::info!(
            state = self.state.label(),
            reason = self.reason(),
            host_ipv4 = i.host_ipv4,
            default_route = i.default_route.as_deref().unwrap_or("none"),
            ipv4_bound = i.ipv4_bound,
            public_ipv4_known = i.public_ipv4_known,
            public_ipv4_on_this_network = i.public_ipv4_here,
            public_ipv6_known = i.public_ipv6_known,
            "egress gate changed"
        );
    }
}

/// `ip` for a log: a public address is masked (`203.0.x.x`, `2001:db8:x`), a private one is shown (T10l).
#[must_use]
pub fn mask_ip(ip: IpAddr) -> String {
    if !is_public_address(ip) {
        return ip.to_string();
    }
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            format!("{a}.{b}.x.x")
        }
        IpAddr::V6(v6) => {
            let [a, b, ..] = v6.segments();
            format!("{a:x}:{b:x}:x")
        }
    }
}

/// The addresses of an endpoint for the debug log, public ones masked ([`mask_ip`]).
#[must_use]
pub fn describe_addrs<'a>(addrs: impl IntoIterator<Item = &'a SocketAddr>) -> String {
    let list: Vec<String> = addrs
        .into_iter()
        .map(|a| match a.ip() {
            IpAddr::V4(_) => format!("{}:{}", mask_ip(a.ip()), a.port()),
            IpAddr::V6(_) => format!("[{}]:{}", mask_ip(a.ip()), a.port()),
        })
        .collect();
    if list.is_empty() {
        "none".to_string()
    } else {
        list.join(", ")
    }
}

/// Why egress jobs cannot run on a node whose gate is [`EgressGate::NoIpv4Bound`], and what to do. Shown to the owner
/// in the job's error and in the agent's log. No addresses.
pub const IPV4_NOT_BOUND: &str = "this node has IPv4 but its iroh endpoint is bound to no IPv4 address, so its public \
     IPv4 can never be learned and egress jobs cannot run on it until iroh binds an IPv4 address (set \
     iroh.direct_addresses to \"default-route\" or to a list that includes an IPv4 network of the default-route \
     interface, then restart the agent; a CGNAT 100.64.0.0/10 address is never bound)";

/// Why egress jobs cannot run on a node whose gate is [`EgressGate::BridgeNamedUplink`], and what to do. Shown to the
/// owner in the job's error and in the agent's log. No addresses.
///
/// `direct_addresses` cannot help here: `select_addresses` drops every interface whose name looks like a container,
/// VM or overlay network (`br-*`, `docker*`, `podman*`…) under every policy, an explicit CIDR included. The only fix
/// is a name that does not look like one. Binding another interface's address by CIDR is not a supported fix: what it
/// does depends on the host's routing.
pub const IPV4_UPLINK_NAMED_LIKE_BRIDGE: &str = "this node's default-route interface has IPv4 but its name looks like \
     a container bridge (\"br-*\", \"docker*\", \"podman*\"…), so iroh never binds it, its public IPv4 can never be \
     learned and egress jobs cannot run on it; setting iroh.direct_addresses does not help, rename the interface to \
     a name that does not start with one of those prefixes (for example \"lan0\"), then restart the agent";

/// What [`PublicAddrTracker`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicAddrs {
    /// Every public address known so far (the last known value of each family), sorted. Known addresses are kept even
    /// while the gate is closed (the proxy refuses them either way) until a fresh observation of the same family
    /// replaces them ([`PublicAddrTracker::observe`]).
    pub addrs: Vec<IpAddr>,
    /// Whether the egress gate may be open: see [`PublicAddrTracker`].
    pub ready: bool,
}

/// The node's public addresses as the egress gate needs them: the last known value of each family, and when the gate
/// may open.
///
/// iroh's `EndpointAddr` lists the addresses QUIC address discovery saw (the WAN IPv4 and IPv6) **and** every bound
/// interface's own address (iroh 1.4 `DirectAddrType::Qad` and `Local`). So a global IPv6 address of an interface is
/// listed at once, long before QAD learns the WAN IPv4; a gate that opened on "any public address" would start egress
/// jobs while the IPv4 side of the hairpin-NAT protection (a NAS behind the router's port forward, §9) was still
/// unknown (T10a review, P3). Therefore:
/// - IPv4 and IPv6 are tracked apart, and each keeps its last known value when a later observation has none;
/// - a **host** with IPv4 connectivity ([`host_has_ipv4`], not what iroh is bound to) is ready only once a public IPv4
///   has been **observed on the current network**; a host without it (IPv6 only) is ready with a public IPv6;
/// - what was known before a move to another network does not count as observed there: a tracker [`seeded`]
///   (after an endpoint rebind) or told [`network_changed`] keeps the old addresses (denied, kept until a fresh
///   observation of the same family replaces them) but waits for a fresh public IPv4 (T10f);
/// - readiness is a verdict apart from the address list: it can go back to `false` (IPv4 came up after the gate opened
///   on IPv6, or the network changed) while the addresses stay known, so running proxies keep refusing them.
///
/// [`seeded`]: PublicAddrTracker::seeded
/// [`network_changed`]: PublicAddrTracker::network_changed
#[derive(Debug, Default, Clone)]
pub struct PublicAddrTracker {
    v4: Vec<IpAddr>,
    v6: Vec<IpAddr>,
    /// Whether a public IPv4 was observed since the network last changed.
    v4_seen_here: bool,
}

impl PublicAddrTracker {
    /// A tracker that already knows `known` (what was published before an endpoint rebind). An endpoint is rebound
    /// when the network changed, so the known IPv4 is not confirmed on this network yet.
    #[must_use]
    pub fn seeded(known: &[IpAddr]) -> Self {
        let mut t = Self::default();
        for ip in known {
            match ip {
                IpAddr::V4(_) => t.v4.push(*ip),
                IpAddr::V6(_) => t.v6.push(*ip),
            }
        }
        t
    }

    /// The address selection or the default route changed: the IPv4 known so far may not be this network's. It stays
    /// known (and denied), but the gate closes until a public IPv4 is observed again. A host without IPv4 is not
    /// affected (see [`PublicAddrTracker::verdict`]).
    pub fn network_changed(&mut self) {
        self.v4_seen_here = false;
    }

    /// Takes the endpoint's current addresses and whether the host has IPv4 ([`host_has_ipv4`]). Returns the public
    /// addresses known and whether the gate may be open. The addresses must be a **fresh** observation: one that
    /// came after the last [`network_changed`](Self::network_changed).
    pub fn observe<'a>(&mut self, addrs: impl IntoIterator<Item = &'a SocketAddr>, host_ipv4: bool) -> PublicAddrs {
        let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = public_addresses(addrs).into_iter().partition(IpAddr::is_ipv4);
        if !v4.is_empty() {
            self.v4 = v4;
            self.v4_seen_here = true;
        }
        if !v6.is_empty() {
            self.v6 = v6;
        }
        self.verdict(host_ipv4)
    }

    /// What the tracker knows, for [`GateInputs`]: a public IPv4 is known, one was observed since the network last
    /// changed, a public IPv6 is known.
    #[must_use]
    pub fn knows(&self) -> (bool, bool, bool) {
        (!self.v4.is_empty(), self.v4_seen_here, !self.v6.is_empty())
    }

    /// The verdict from what is known, without a new observation (the host's network state changed).
    #[must_use]
    pub fn verdict(&self, host_ipv4: bool) -> PublicAddrs {
        let ready = self.v4_seen_here || (!host_ipv4 && !self.v6.is_empty());
        let mut addrs: Vec<IpAddr> = self.v4.iter().chain(&self.v6).copied().collect();
        addrs.sort();
        PublicAddrs { addrs, ready }
    }
}

/// How long after the host's IPv4 state changes, or after the endpoint's address watcher started (agent start, each
/// rebind), the endpoint's bind is taken to be current: the [`Reselector`]'s debounce twice (once for the debounce,
/// once as a margin for the rebind). Before that, "the endpoint has no IPv4 bound" may only mean that the rebind with
/// the new IPv4 is still coming, so the gate is just closed and [`EgressGate::NoIpv4Bound`] and
/// [`EgressGate::BridgeNamedUplink`] are not reported (T10f review, P3-2; T10h).
pub const NO_IPV4_BOUND_SETTLE: Duration = Duration::from_secs(2 * NETWORK_CHANGE_DEBOUNCE.as_secs());

/// How long without a move of the default route ends a run of move-triggered rebinds ([`RebindLoopGuard`]).
pub const REBIND_LOOP_STABLE: Duration = Duration::from_secs(60);

/// How many move-triggered rebinds in a run, with less than [`REBIND_LOOP_STABLE`] between them, are named in a
/// warning.
pub const REBIND_LOOP_AFTER: u32 = 5;

/// Counts the rebinds the gate watchers ask for because the default route moved, across watchers (each rebind starts a
/// new one), so a loop is named. Each watcher measures its route baseline apart from the network monitor's own first
/// measurement; if the two ever disagreed systematically, every new watcher would see a "move" and ask for another
/// rebind, and the gate would never open. Nothing is changed by it: it only counts and says (T10l review P3-3).
#[derive(Debug, Default)]
pub struct RebindLoopGuard {
    consecutive: u32,
    last: Option<std::time::Instant>,
    warned: bool,
}

impl RebindLoopGuard {
    /// A rebind is asked for at `now`, because the route moved. Returns the run's length the one time it reaches
    /// [`REBIND_LOOP_AFTER`] (the caller warns); a gap of [`REBIND_LOOP_STABLE`] or more starts a new run.
    pub fn requested(&mut self, now: std::time::Instant) -> Option<u32> {
        let stable = self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) >= REBIND_LOOP_STABLE);
        if stable {
            self.consecutive = 0;
            self.warned = false;
        }
        self.last = Some(now);
        self.consecutive = self.consecutive.saturating_add(1);
        let name_it = self.consecutive >= REBIND_LOOP_AFTER && !self.warned;
        self.warned |= name_it;
        name_it.then_some(self.consecutive)
    }

    /// How many rebinds are in the current run.
    #[must_use]
    pub fn consecutive(&self) -> u32 {
        self.consecutive
    }
}

/// What a gate watcher writes to, and what it asks of the agent (T10l). Clone it to share it: every field is shared.
#[derive(Debug, Clone)]
pub struct GateSinks {
    /// The node's public addresses ([`PublicAddrTracker`]): kept across rebinds.
    pub public: Arc<watch::Sender<Vec<IpAddr>>>,
    /// The egress gate.
    pub gate: Arc<watch::Sender<EgressGate>>,
    /// The gate and what it was decided from.
    pub report: Arc<watch::Sender<GateReport>>,
    /// Asked by the watcher when the default route moved: the agent must bind a new endpoint ([`REBIND_RETRY`]). A
    /// [`Notify`] keeps one permit, so requests made before anyone waits, or many in a row, give one rebind.
    pub rebind: Arc<Notify>,
    /// How many rebinds in a row a move of the route asked for ([`RebindLoopGuard`]).
    pub rebinds: Arc<std::sync::Mutex<RebindLoopGuard>>,
}

impl Default for GateSinks {
    fn default() -> Self {
        Self {
            public: Arc::new(watch::channel(Vec::new()).0),
            gate: Arc::new(watch::channel(EgressGate::Closed).0),
            report: Arc::new(watch::channel(GateReport::default()).0),
            rebind: Arc::new(Notify::new()),
            rebinds: Arc::default(),
        }
    }
}

/// Closes the gate for a network change the caller has just acted on (the agent re-binds its endpoint) until the new
/// endpoint observes a public IPv4 again: [`EgressGate::Open`] becomes [`EgressGate::Closed`], on a host with IPv4
/// (`net`, [`host_net_now`], measured by the caller or fixed by a test). The report says the network changed, with
/// `net`'s inputs, and is logged once the sender's lock is released. The published addresses are not touched. A host
/// without IPv4 keeps its gate: it has no IPv4 hairpin to guard.
///
/// **The endpoint's address watcher ([`watch_public_addresses`]) must be stopped, and awaited, before this is called.**
/// A watcher still running could write a verdict computed on the old network right after the gate closed and reopen
/// it (T10f review, P2).
pub fn close_gate_if(sinks: &GateSinks, net: &HostNet) {
    if !net.ipv4 {
        return;
    }
    let closed = sinks.gate.send_if_modified(|g| {
        let was_open = g.is_open();
        if was_open {
            *g = EgressGate::Closed;
        }
        was_open
    });
    if closed {
        let mut after = GateReport::default();
        sinks.report.send_modify(|r| {
            r.state = EgressGate::Closed;
            r.inputs.host_ipv4 = net.ipv4;
            r.inputs.default_route.clone_from(&net.default_route);
            r.inputs.public_ipv4_here = false;
            r.inputs.network_changed = true;
            after = r.clone();
        });
        after.log();
    }
}

/// Whether a verdict is logged: when the gate changed, and the first one of a watcher (so an endpoint's start says
/// where the gate stands even when it did not change).
fn needs_log(changed: bool, logged_once: &mut bool) -> bool {
    let first = !std::mem::replace(logged_once, true);
    changed || first
}

/// How long the debounced move of the default route waits for the agent's rebind before asking again, with a
/// warning: twice [`NO_IPV4_BOUND_SETTLE`]. A request is a [`Notify`] the daemon is waiting on, so this is only the
/// net under it (a daemon that is busy, a request lost to a restart of the daemon's loop), never the way it works.
pub const REBIND_RETRY: Duration = Duration::from_secs(2 * NO_IPV4_BOUND_SETTLE.as_secs());

/// Whether the `retries`-th repeat (1 for the first) of a rebind request that nobody answered is worth a `warn`. The
/// daemon is legitimately busy inside `connect()` and the pre-Welcome handshake for up to 30 s (the agent's 15 s
/// timeouts, twice), and the request waits meanwhile, so the first four repeats of [`REBIND_RETRY`] are only "still
/// pending" at `info`; a fifth means something else is wrong (T10l review P3-5).
fn rebind_retry_is_warning(retries: u32) -> bool {
    retries > 4
}

/// Sleeps until `at`, or forever.
async fn sleep_until_opt(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Publishes the public addresses of an endpoint's address watcher (`Endpoint::watch_addr`) and the egress gate, with
/// what each verdict was made from ([`GateSinks`]), each time they change, until the endpoint is gone (or `host` has
/// no sender left), as [`PublicAddrTracker`] decides, with the host's network given as a live value (the caller keeps
/// it with [`watch_host_net`]). Known addresses are not dropped when the gate closes, and a tracker is seeded from
/// what `sinks.public` already holds, so a rebind after a network change keeps them too; they are kept until a fresh
/// observation of the same family replaces them, as [`PublicAddrTracker::observe`] does. Only the gate goes back to
/// closed. `ipv4_bound` says whether the endpoint is bound to an IPv4 address: a host with IPv4 whose endpoint has
/// none can never learn its public IPv4, and the gate says so ([`EgressGate::NoIpv4Bound`]) and the log too. The
/// watcher, not the endpoint, is passed, so this never keeps an endpoint alive.
///
/// **A move of the default route is the watcher's to see and to act on.** Once it sees one, this endpoint's list proves
/// nothing about the new network (it can be the old network's QAD address under the new network's local ones), so
/// only a new endpoint can reopen the gate. The watcher therefore asks for the rebind itself (`sinks.rebind`, once the
/// events of a burst have been quiet for the network-change debounce), and asks again every [`REBIND_RETRY`] until it
/// is stopped, which is what the rebind does: it needs nothing of any other network monitor. The repeats are logged as
/// "still pending" at `info`, and as a `warn` only from the fifth on (see `rebind_retry_is_warning`). Every change of
/// the gate is logged at `info`, with its inputs and why it is not open, and each look at the
/// endpoint's addresses at `debug` (public addresses masked, [`mask_ip`]).
pub async fn watch_public_addresses<W>(
    mut addrs: W,
    mut host: watch::Receiver<HostNet>,
    ipv4_bound: bool,
    sinks: GateSinks,
) where
    W: Watcher<Value = EndpointAddr>,
{
    let GateSinks {
        public,
        gate,
        report,
        rebind,
        rebinds,
    } = sinks;
    let mut tracker = PublicAddrTracker::seeded(&public.borrow());
    let mut route = host.borrow().default_route.clone();
    // The route before the last move, for the warning of a rebind loop.
    let mut route_before = route.clone();
    // The first look at the endpoint is fresh (a new endpoint knows nothing from before); one caused by a change of
    // the host's network is not (iroh may still list the old network's address).
    let mut fresh = true;
    // When the host's IPv4 state last changed: the endpoint's bind is only known to be current once
    // `NO_IPV4_BOUND_SETTLE` has passed since (P3-2).
    let mut last_ipv4 = host.borrow().ipv4;
    // A new watcher with a host IPv4 and none bound is in the same position as after a change of the host's IPv4: the
    // endpoint may be about to be rebound, so the advice waits one settle time from the start (T10h).
    let mut ipv4_since = (last_ipv4 && !ipv4_bound).then(tokio::time::Instant::now);
    // Whether the default route moved since this endpoint was bound: only a new endpoint reopens the gate then, however
    // long ago the move was (review of PR #48, P2).
    let mut moved = false;
    // When to ask the agent for the new endpoint, and how many times it was asked since the last move (the repeats are
    // logged as "still pending", and as a warning only after several).
    let mut ask_at: Option<tokio::time::Instant> = None;
    let mut requests = 0u32;
    // Whether the first report was logged: every change of the gate is, and the first one even if it equals the
    // default report.
    let mut logged_once = false;
    loop {
        let net = host.borrow_and_update().clone();
        // The route is compared here, not only when `host` wakes the loop: `borrow_and_update` marks the change as
        // seen, so a loop woken by the endpoint's update at the same moment would never see the move, and a node that
        // changed network would keep a gate that was open on the old one. The look in this iteration came with the
        // move, so it is not taken as an observation on the new route (T10l).
        if net.default_route != route {
            route_before = std::mem::replace(&mut route, net.default_route.clone());
            tracker.network_changed();
            moved = true;
            // Each event of a burst restarts the wait: one rebind for all of it.
            ask_at = Some(tokio::time::Instant::now() + NETWORK_CHANGE_DEBOUNCE);
            requests = 0;
        }
        if moved {
            fresh = false;
        }
        if net.ipv4 != last_ipv4 {
            last_ipv4 = net.ipv4;
            ipv4_since = Some(tokio::time::Instant::now());
        }
        let settle_at = ipv4_since.map(|since| since + NO_IPV4_BOUND_SETTLE);
        let settled = settle_at.is_none_or(|at| tokio::time::Instant::now() >= at);
        let seen = if fresh {
            let listed = addrs.get();
            tracing::debug!(
                addresses = %describe_addrs(listed.ip_addrs()),
                fresh = true,
                "egress gate: the endpoint's addresses"
            );
            tracker.observe(listed.ip_addrs(), net.ipv4)
        } else {
            tracing::debug!(fresh = false, "egress gate: no new look at the endpoint's addresses");
            tracker.verdict(net.ipv4)
        };
        public.send_if_modified(|known| {
            if *known == seen.addrs {
                false
            } else {
                *known = seen.addrs;
                true
            }
        });
        let state = if seen.ready {
            EgressGate::Open
        } else if net.ipv4 && !ipv4_bound && settled {
            if net.bridge_named_uplink {
                EgressGate::BridgeNamedUplink
            } else {
                EgressGate::NoIpv4Bound
            }
        } else {
            EgressGate::Closed
        };
        let (v4_known, v4_here, v6_known) = tracker.knows();
        let now = GateReport {
            state,
            inputs: GateInputs {
                host_ipv4: net.ipv4,
                default_route: net.default_route.clone(),
                ipv4_bound,
                public_ipv4_known: v4_known,
                public_ipv4_here: v4_here,
                public_ipv6_known: v6_known,
                network_changed: moved && !v4_here,
            },
        };
        let changed = gate.send_if_modified(|known| std::mem::replace(known, state) != state);
        // The report changes with its inputs too (a new reason for the same state), but only a change of the gate, or
        // the first report of this watcher, is logged. The first one is always sent, even when it equals the default
        // report, so whoever follows the report (the status file) hears a verdict was made.
        let first = !logged_once;
        if first {
            report.send_modify(|known| known.clone_from(&now));
        } else {
            report.send_if_modified(|known| std::mem::replace(known, now.clone()) != now);
        }
        if needs_log(changed, &mut logged_once) {
            now.log();
        }
        if changed {
            match state {
                EgressGate::NoIpv4Bound => tracing::warn!("{IPV4_NOT_BOUND}"),
                EgressGate::BridgeNamedUplink => tracing::warn!("{IPV4_UPLINK_NAMED_LIKE_BRIDGE}"),
                EgressGate::Open | EgressGate::Closed => {}
            }
        }
        // Wake up when the wait for a rebind is over, only if that changes what is reported.
        let wake_at = settle_at.filter(|_| !settled && net.ipv4 && !ipv4_bound);
        tokio::select! {
            updated = addrs.updated() => {
                if updated.is_err() {
                    return;
                }
                fresh = true;
            }
            () = sleep_until_opt(wake_at) => {
                fresh = false;
            }
            () = sleep_until_opt(ask_at) => {
                requests = requests.saturating_add(1);
                let retries = requests - 1;
                if retries == 0 {
                    tracing::info!(
                        "the default route moved: asking for a new iroh endpoint \
                         (the egress gate stays closed until it observes a public IPv4)"
                    );
                    let run = rebinds
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .requested(tokio::time::Instant::now().into_std());
                    if let Some(count) = run {
                        tracing::warn!(
                            rebinds = count,
                            route_before = route_before.as_deref().unwrap_or("none"),
                            route_now = route.as_deref().unwrap_or("none"),
                            "the default route keeps moving: {count} rebinds in a row with no stable period between \
                             them, so the egress gate has not been able to stay open; if the network is not really \
                             changing, this is a bug"
                        );
                    }
                } else if rebind_retry_is_warning(retries) {
                    tracing::warn!(
                        retries,
                        retry_s = REBIND_RETRY.as_secs(),
                        "the default route moved and the iroh endpoint has still not been rebound; asking again \
                         (the egress gate stays closed until it is)"
                    );
                } else {
                    tracing::info!(
                        retries,
                        retry_s = REBIND_RETRY.as_secs(),
                        "the new iroh endpoint is still pending (the daemon may be connecting); asking again \
                         (the egress gate stays closed until it is bound)"
                    );
                }
                rebind.notify_one();
                ask_at = Some(tokio::time::Instant::now() + REBIND_RETRY);
                fresh = false;
            }
            changed = host.changed() => {
                if changed.is_err() {
                    return;
                }
                fresh = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn loopback() -> Vec<SelectedAddr> {
        vec![SelectedAddr::new(IfAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8), "lo")]
    }

    #[tokio::test]
    async fn nothing_to_reach_it_by_is_refused() {
        let spec = BindSpec {
            relay_mode: RelayMode::Disabled,
            addrs: Vec::new(),
            port: 0,
            alpns: Vec::new(),
        };
        assert!(matches!(
            bind_endpoint(SecretKey::generate(), &spec).await,
            Err(BindError::Unreachable)
        ));
    }

    /// Bound to loopback only, the endpoint is bound and advertises only loopback: no other interface, no bridge.
    #[tokio::test]
    async fn only_the_selected_addresses_are_bound_and_advertised() {
        let spec = BindSpec {
            relay_mode: RelayMode::Disabled,
            addrs: loopback(),
            port: 0,
            alpns: Vec::new(),
        };
        let ep = bind_endpoint(SecretKey::generate(), &spec).await.unwrap();
        let bound = ep.bound_sockets();
        assert!(!bound.is_empty());
        assert!(bound.iter().all(|a| a.ip().is_loopback()), "{bound:?}");
        let mut watch = ep.watch_addr();
        let addr = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let addr = watch.get();
                if addr.ip_addrs().next().is_some() {
                    return addr;
                }
                let _ = watch.updated().await;
            }
        })
        .await
        .unwrap();
        assert!(addr.ip_addrs().all(|a| a.ip().is_loopback()), "{addr:?}");
        assert_eq!(addr.relay_urls().count(), 0);
        ep.close().await;
    }

    #[test]
    fn relay_mode_is_exactly_the_relays_or_none() {
        assert_eq!(relay_mode(Vec::new()), RelayMode::Disabled);
        let url: RelayUrl = "https://relay.example.invalid".parse().unwrap();
        let mode = relay_mode(vec![url.clone()]);
        assert_eq!(mode.relay_map().urls::<Vec<_>>(), vec![url]);
    }

    #[test]
    fn a_netwatch_snapshot_converts() {
        let (interfaces, _) = interfaces_from(&netwatch::interfaces::State::fake());
        assert!(!interfaces.is_empty());
        assert!(interfaces.iter().all(|i| !i.name.is_empty()));
    }

    #[test]
    fn only_public_addresses_are_kept() {
        let at = |ip: &str| SocketAddr::new(ip.parse().unwrap(), 4433);
        let all = [
            at("198.51.100.7"),
            at("192.0.2.1"),
            at("198.51.100.7"),
            at("2001:db8::5"),
            at("127.0.0.1"),
            at("10.1.2.3"),
            at("172.16.0.9"),
            at("192.168.1.20"),
            at("100.64.1.1"),
            at("169.254.3.3"),
            at("::1"),
            at("fd00::1"),
            at("fe80::1"),
            at("::ffff:192.168.1.20"),
            at("0.0.0.0"),
        ];
        let kept: Vec<String> = public_addresses(all.iter()).iter().map(ToString::to_string).collect();
        assert_eq!(kept, ["192.0.2.1", "198.51.100.7", "2001:db8::5"]);
        assert!(is_public_address("::ffff:198.51.100.7".parse().unwrap()));
    }

    fn socks(addrs: &[&str]) -> Vec<SocketAddr> {
        addrs
            .iter()
            .map(|a| SocketAddr::new(a.parse().unwrap(), 4433))
            .collect()
    }

    /// `(known addresses, ready)` after an observation.
    fn observe(t: &mut PublicAddrTracker, addrs: &[&str], host_ipv4: bool) -> (Vec<String>, bool) {
        let seen = t.observe(socks(addrs).iter(), host_ipv4);
        (seen.addrs.iter().map(ToString::to_string).collect(), seen.ready)
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(ToString::to_string).collect()
    }

    fn iface(name: &str, up: bool, addrs: &[&str]) -> Interface {
        Interface::new(
            name,
            up,
            addrs
                .iter()
                .map(|a| IfAddr::new(a.parse().unwrap(), if a.contains(':') { 64 } else { 24 }))
                .collect(),
        )
    }

    /// T10e: IPv4 connectivity is read from the host's interfaces: a usable IPv4 address on an interface that is up.
    #[test]
    fn the_host_has_ipv4_when_an_up_interface_has_a_usable_address() {
        // A LAN address, a CGNAT one (iroh would not bind it, the host still uses it), a public one.
        assert!(host_has_ipv4(&[iface("eth0", true, &["192.0.2.20", "2001:db8::5"])]));
        assert!(host_has_ipv4(&[iface("eth0", true, &["100.64.1.9", "2001:db8::5"])]));
        assert!(host_has_ipv4(&[iface("eth0", true, &["198.51.100.7"])]));
        // Not usable: loopback, link-local, a down interface, IPv6 only.
        assert!(!host_has_ipv4(&[
            iface("lo", true, &["127.0.0.1", "::1"]),
            iface("eth0", true, &["169.254.3.3", "fe80::1", "2001:db8::5"]),
            iface("wlan0", false, &["192.0.2.30"]),
        ]));
        // No interface at all: the enumeration failed; fail closed.
        assert!(host_has_ipv4(&[]));
    }

    /// T10f, item 3: container, VM and overlay interfaces are not a way to the internet. A host whose only IPv4
    /// addresses are on them has no IPv4, and one that also has a real interface is judged by the real one.
    #[test]
    fn bridges_and_overlays_do_not_count_as_host_ipv4() {
        let bridges = [
            iface("lo", true, &["127.0.0.1"]),
            iface("podman0", true, &["10.88.0.1"]),
            iface("docker0", true, &["172.17.0.1"]),
            iface("br-1a2b3c", true, &["172.18.0.1"]),
            iface("virbr0", true, &["192.168.122.1"]),
            iface("tailscale0", true, &["100.101.102.103", "fd7a:115c:a1e0::1"]),
            iface("veth1234", true, &["10.1.1.1"]),
            iface("eth0", true, &["fe80::1", "2001:db8::5"]),
        ];
        assert!(!host_has_ipv4(&bridges), "only IPv6 on a real interface");
        let mut with_real = bridges.to_vec();
        with_real.push(iface("wlan0", true, &["192.0.2.30"]));
        assert!(host_has_ipv4(&with_real));
        // Only virtual interfaces listed: not the failed-enumeration case, there is just no IPv4.
        assert!(!host_has_ipv4(&[iface("podman1", true, &["10.89.0.1"])]));
        // The interface list could not be read: still fail closed.
        assert!(host_has_ipv4(&[]));
    }

    /// T10f review, P3-1: the virtual-interface filter goes by name, so a real uplink called `br-lan` or `br-ex` must
    /// still count when it carries the default route; otherwise the gate would open on IPv6 on a host with IPv4.
    #[test]
    fn the_default_route_interface_counts_whatever_its_name() {
        let host = [
            iface("lo", true, &["127.0.0.1"]),
            iface("br-lan", true, &["192.0.2.20"]),
            iface("eth1", true, &["fe80::1", "2001:db8::5"]),
        ];
        assert!(!host_has_ipv4(&host), "by name alone, br-lan is a bridge");
        assert!(
            host_has_ipv4_via(&host, Some("br-lan")),
            "but it carries the default route"
        );
        assert!(
            !host_has_ipv4_via(&host, Some("eth1")),
            "another route: the bridge is still ignored"
        );
        assert!(!host_has_ipv4_via(&host, None));
        // A default route on a down interface proves nothing.
        let down = [
            iface("br-ex", false, &["192.0.2.21"]),
            iface("eth1", true, &["2001:db8::5"]),
        ];
        assert!(!host_has_ipv4_via(&down, Some("br-ex")));
        // The gate: IPv6 alone does not open it on such a host.
        let mut t = PublicAddrTracker::default();
        let (_, ready) = observe(&mut t, &["2001:db8::5"], host_has_ipv4_via(&host, Some("br-lan")));
        assert!(!ready);
    }

    /// T10e, item 1: the host has IPv4 but iroh is bound to IPv6 only (`direct_addresses` = IPv6 CIDRs) or lost its
    /// CGNAT address: the endpoint's addresses show no IPv4 at all, yet the gate must wait for a public IPv4.
    #[test]
    fn an_ipv6_only_bind_on_a_host_with_ipv4_keeps_the_gate_closed_until_a_public_ipv4() {
        let mut t = PublicAddrTracker::default();
        // iroh lists only the global IPv6; the host has IPv4 (e.g. through the router, or CGNAT).
        let (addrs, ready) = observe(&mut t, &["2001:db8::5"], true);
        assert!(!ready, "the WAN IPv4 hairpin is not covered yet");
        assert_eq!(addrs, strings(&["2001:db8::5"]), "the IPv6 address is already denied");
        // QAD (through a relay) learned the WAN IPv4.
        assert_eq!(
            observe(&mut t, &["2001:db8::5", "198.51.100.7"], true),
            (strings(&["198.51.100.7", "2001:db8::5"]), true)
        );
    }

    /// T10e: a CGNAT-only host (the only IPv4 address is 100.64.0.0/10, which iroh never binds) is still a host with
    /// IPv4: the gate stays closed on a global IPv6 alone.
    #[test]
    fn a_cgnat_only_host_keeps_the_gate_closed() {
        let host = [iface("eth0", true, &["100.64.1.9", "2001:db8::5"])];
        let mut t = PublicAddrTracker::default();
        // The CGNAT address is dropped before it reaches iroh, so iroh only shows the IPv6 address.
        let (_, ready) = observe(&mut t, &["2001:db8::5"], host_has_ipv4(&host));
        assert!(!ready);
    }

    /// T10e: a truly IPv6-only host has no hairpin through an IPv4 address: its public IPv6 opens the gate.
    #[test]
    fn a_truly_ipv6_only_host_opens_on_its_public_ipv6() {
        let host = [
            iface("lo", true, &["127.0.0.1", "::1"]),
            iface("eth0", true, &["fe80::1", "2001:db8::5"]),
        ];
        let mut t = PublicAddrTracker::default();
        assert_eq!(
            observe(&mut t, &["fe80::1", "2001:db8::5"], host_has_ipv4(&host)),
            (strings(&["2001:db8::5"]), true)
        );
        // Nothing public at all: not ready, nothing known.
        let mut t = PublicAddrTracker::default();
        assert_eq!(observe(&mut t, &["fe80::1", "127.0.0.1"], false), (Vec::new(), false));
    }

    /// With IPv4 on the host, iroh listing the interface's own private IPv4 changes nothing: still a public IPv4 is
    /// needed (T10c).
    #[test]
    fn with_ipv4_connectivity_the_gate_waits_for_a_public_ipv4() {
        let mut t = PublicAddrTracker::default();
        assert!(!observe(&mut t, &["192.168.1.20", "2001:db8::5"], true).1);
        assert_eq!(
            observe(&mut t, &["192.168.1.20", "2001:db8::5", "198.51.100.7"], true),
            (strings(&["198.51.100.7", "2001:db8::5"]), true)
        );
    }

    /// T10e, item 2: the gate opened on IPv6 alone (IPv4 not up yet at boot); then IPv4 comes up. Readiness goes back
    /// to `false` until a public IPv4 is learned, and no address is ever dropped.
    #[test]
    fn the_gate_closes_when_ipv4_comes_up_without_forgetting_any_address() {
        let mut t = PublicAddrTracker::default();
        assert_eq!(
            observe(&mut t, &["2001:db8::5"], false),
            (strings(&["2001:db8::5"]), true)
        );
        // DHCPv4 answered: the host has IPv4 now, the WAN IPv4 is not known.
        assert_eq!(
            observe(&mut t, &["2001:db8::5"], true),
            (strings(&["2001:db8::5"]), false)
        );
        assert_eq!(
            observe(&mut t, &["2001:db8::5"], true),
            (strings(&["2001:db8::5"]), false)
        );
        // The public IPv4 is learned: open again, both addresses denied.
        assert_eq!(
            observe(&mut t, &["2001:db8::5", "198.51.100.7"], true),
            (strings(&["198.51.100.7", "2001:db8::5"]), true)
        );
    }

    /// The last known value of each family is kept when a later observation has none of that family.
    #[test]
    fn the_last_known_value_per_family_is_kept() {
        let mut t = PublicAddrTracker::default();
        assert!(observe(&mut t, &["10.0.0.2", "198.51.100.7", "2001:db8::5"], true).1);
        // The IPv6 address went away (a rebind): it is remembered.
        assert_eq!(
            observe(&mut t, &["10.0.0.2", "198.51.100.7"], true),
            (strings(&["198.51.100.7", "2001:db8::5"]), true)
        );
        // The IPv4 one is replaced when a new one is seen, not accumulated.
        assert_eq!(
            observe(&mut t, &["10.0.0.2", "192.0.2.9", "2001:db8::5"], true),
            (strings(&["192.0.2.9", "2001:db8::5"]), true)
        );
        // The endpoint lists nothing any more: the known public IPv4 still opens the gate.
        assert_eq!(
            observe(&mut t, &["fe80::1"], true),
            (strings(&["192.0.2.9", "2001:db8::5"]), true)
        );
    }

    /// T10f, item 2: a tracker seeded with what was published before a rebind (the network changed) does not forget
    /// it, but does not trust its IPv4 either: the gate stays closed until a public IPv4 is observed again.
    #[test]
    fn a_seeded_tracker_remembers_across_rebinds_but_waits_for_a_fresh_ipv4() {
        let before: Vec<IpAddr> = vec!["198.51.100.7".parse().unwrap(), "2001:db8::5".parse().unwrap()];
        let mut t = PublicAddrTracker::seeded(&before);
        assert_eq!(
            observe(&mut t, &["10.0.0.2"], true),
            (strings(&["198.51.100.7", "2001:db8::5"]), false),
            "the old WAN IPv4 is still denied, but the new one is not known"
        );
        // The new network's WAN IPv4 is observed: the old address is replaced and the gate opens.
        assert_eq!(
            observe(&mut t, &["10.0.0.2", "192.0.2.9"], true),
            (strings(&["192.0.2.9", "2001:db8::5"]), true)
        );
        // A host without IPv4 is the exception: its public IPv6 is enough.
        let mut t = PublicAddrTracker::seeded(&before);
        assert!(observe(&mut t, &["2001:db8::5"], false).1);
    }

    /// T10f, item 2: IPv4 network A is ready, the network changes (a move to B), the gate closes without withdrawing
    /// A's address, and a public IPv4 on B opens it again.
    #[test]
    fn a_network_change_closes_the_gate_until_ipv4_is_observed_again() {
        let mut t = PublicAddrTracker::default();
        assert!(
            observe(&mut t, &["192.168.1.20", "198.51.100.7"], true).1,
            "network A is ready"
        );
        t.network_changed();
        assert_eq!(
            t.verdict(true),
            PublicAddrs {
                addrs: vec!["198.51.100.7".parse().unwrap()],
                ready: false
            },
            "closed, and A's address is still denied"
        );
        // B's interface address is not a public IPv4.
        assert!(!observe(&mut t, &["10.9.8.7"], true).1);
        assert_eq!(
            observe(&mut t, &["10.9.8.7", "192.0.2.9"], true),
            (strings(&["192.0.2.9"]), true)
        );
        // A host without IPv4 keeps its gate across a network change.
        let mut v6 = PublicAddrTracker::default();
        assert!(observe(&mut v6, &["2001:db8::5"], false).1);
        v6.network_changed();
        assert!(v6.verdict(false).ready);
    }

    /// T10f, item 2: an endpoint rebound for a network change closes the gate at once (the new endpoint is bound on
    /// the next connection), and only on a host with IPv4. It never touches a gate that is already closed or blocked.
    #[test]
    fn a_rebind_closes_an_open_gate_on_a_host_with_ipv4() {
        let sinks = GateSinks::default();
        let rx = sinks.gate.subscribe();
        sinks.gate.send_replace(EgressGate::Open);
        close_gate_if(&sinks, &host(false, "eth0"));
        assert_eq!(*rx.borrow(), EgressGate::Open, "no IPv4 on the host: nothing to guard");
        close_gate_if(&sinks, &host(true, "eth0"));
        assert_eq!(*rx.borrow(), EgressGate::Closed);
        sinks.gate.send_replace(EgressGate::NoIpv4Bound);
        close_gate_if(&sinks, &host(true, "eth0"));
        assert_eq!(
            *rx.borrow(),
            EgressGate::NoIpv4Bound,
            "the more specific closed state is kept"
        );
    }

    /// T10e review, P3-1: the host got IPv4 between the first measurement (`host_net_now`) and the creation of the
    /// network monitor (boot before DHCPv4). The monitor's own first state is measured at once, so the verdict is
    /// right without waiting for the next network event.
    #[tokio::test]
    async fn the_host_state_is_measured_again_when_the_monitor_starts() {
        let state = netwatch::interfaces::State::fake();
        assert!(host_has_ipv4(&interfaces_from(&state).0), "the fake host has IPv4");
        let source = n0_watcher::Watchable::new(state);
        // What `host_net_now` saw before: no IPv4 yet.
        let (tx, mut rx) = watch::channel(HostNet::default());
        let task = tokio::spawn(keep_host_net(tx, source.watch()));
        tokio::time::timeout(std::time::Duration::from_secs(10), rx.wait_for(|v| v.ipv4))
            .await
            .expect("the gate learns the host has IPv4 without a network event")
            .unwrap();
        // It ends once nobody listens any more.
        drop(rx);
        tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .expect("the host watcher ends with its receivers")
            .unwrap();
    }

    /// Awaits `fut` for at most 10 s: a regression fails the named test instead of hanging the whole run.
    async fn within<T>(what: &str, fut: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(10), fut)
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for: {what}"))
    }

    fn host(ipv4: bool, route: &str) -> HostNet {
        HostNet {
            ipv4,
            default_route: Some(route.to_string()),
            bridge_named_uplink: false,
        }
    }

    fn want(ips: &[&str]) -> Vec<IpAddr> {
        ips.iter().map(|i| i.parse().unwrap()).collect()
    }

    /// The watcher, end to end with a controllable address watcher and host state: IPv6 first (the gate opens on an
    /// IPv6-only host), then the host gets IPv4 (the gate closes), then a public IPv4 is learned (it opens). The
    /// published list holds the IPv6 address from the first moment to the last.
    #[tokio::test]
    async fn the_watcher_closes_the_gate_without_withdrawing_the_deny_list() {
        let id = SecretKey::generate().public();
        let v6 = SocketAddr::new("2001:db8::5".parse().unwrap(), 4433);
        let v4 = SocketAddr::new("198.51.100.7".parse().unwrap(), 4433);
        let endpoint_addr = n0_watcher::Watchable::new(EndpointAddr::new(id).with_ip_addr(v6));
        let (host_tx, host_rx) = watch::channel(host(false, "eth0"));
        let public = Arc::new(watch::channel(Vec::new()).0);
        let gate = Arc::new(watch::channel(EgressGate::Closed).0);
        let mut public_rx = public.subscribe();
        let mut gate_rx = gate.subscribe();
        let task = tokio::spawn(watch_public_addresses(
            endpoint_addr.watch(),
            host_rx,
            true,
            GateSinks {
                public: public.clone(),
                gate: gate.clone(),
                ..GateSinks::default()
            },
        ));

        // An IPv6-only host: ready on the IPv6 address.
        within("the gate to open on IPv6", gate_rx.wait_for(|g| g.is_open()))
            .await
            .unwrap();
        assert_eq!(*public_rx.borrow(), want(&["2001:db8::5"]));
        // IPv4 comes up on the host.
        host_tx.send_replace(host(true, "eth0"));
        within(
            "the gate to close when the host gets IPv4",
            gate_rx.wait_for(|g| !g.is_open()),
        )
        .await
        .unwrap();
        assert_eq!(
            *public_rx.borrow(),
            want(&["2001:db8::5"]),
            "still denied by running proxies"
        );
        // The public IPv4 is learned.
        endpoint_addr
            .set(EndpointAddr::new(id).with_ip_addr(v6).with_ip_addr(v4))
            .unwrap();
        within("the gate to open on the public IPv4", gate_rx.wait_for(|g| g.is_open()))
            .await
            .unwrap();
        within("both addresses to be published", public_rx.wait_for(|a| a.len() == 2))
            .await
            .unwrap();
        assert_eq!(*public_rx.borrow(), want(&["198.51.100.7", "2001:db8::5"]));
        // The watcher ends with the endpoint's watchable.
        drop(endpoint_addr);
        tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .expect("the watcher ends with its source")
            .unwrap();
    }

    /// T10f, item 2, end to end, as T10l (review of PR #48, P2) has it: IPv4 network A is ready; the default route
    /// moves (network B) while iroh still lists A's address: the gate closes and A's address stays published. The
    /// endpoint that was bound on A never reopens it, whatever it lists afterwards and for as long as it takes: its
    /// list can be A's QAD address under B's local addresses. The agent rebinds on every move; the new endpoint's
    /// watcher (seeded with A's address) opens the gate on its first public IPv4.
    #[tokio::test(start_paused = true)]
    async fn a_default_route_change_closes_the_gate_and_only_the_rebound_endpoint_opens_it() {
        let id = SecretKey::generate().public();
        let a = SocketAddr::new("198.51.100.7".parse().unwrap(), 4433);
        let b = SocketAddr::new("192.0.2.9".parse().unwrap(), 4433);
        let lan = SocketAddr::new("192.168.0.10".parse().unwrap(), 4433);
        let endpoint_addr = n0_watcher::Watchable::new(EndpointAddr::new(id).with_ip_addr(a));
        let (host_tx, host_rx) = watch::channel(host(true, "eth0"));
        let public = Arc::new(watch::channel(Vec::new()).0);
        let gate = Arc::new(watch::channel(EgressGate::Closed).0);
        let public_rx = public.subscribe();
        let mut gate_rx = gate.subscribe();
        let old_watcher = tokio::spawn(watch_public_addresses(
            endpoint_addr.watch(),
            host_rx,
            true,
            GateSinks {
                public: public.clone(),
                gate: gate.clone(),
                ..GateSinks::default()
            },
        ));
        within("network A to be ready", gate_rx.wait_for(|g| g.is_open()))
            .await
            .unwrap();
        // The route moves to another interface; iroh has not noticed yet and still lists A's address.
        host_tx.send_replace(host(true, "wlan0"));
        within("the gate to close on the move", gate_rx.wait_for(|g| !g.is_open()))
            .await
            .unwrap();
        assert_eq!(
            *public_rx.borrow(),
            want(&["198.51.100.7"]),
            "A's address is still denied"
        );
        // Longer than any timer the watcher ever had: still closed, with A's address listed.
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert!(
            !gate_rx.borrow().is_open(),
            "the same endpoint keeps listing A's address"
        );
        // Even an update that lists a public IPv4 (B's, or A's again) on that endpoint does not reopen it.
        endpoint_addr
            .set(EndpointAddr::new(id).with_ip_addr(lan).with_ip_addr(b))
            .unwrap();
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert!(
            !gate_rx.borrow().is_open(),
            "only a rebound endpoint observes the new network"
        );
        // The agent rebinds: the old watcher goes, a new one starts on the new endpoint, seeded with what was known.
        old_watcher.abort();
        let _ = old_watcher.await;
        let endpoint_b = n0_watcher::Watchable::new(EndpointAddr::new(id).with_ip_addr(lan));
        let (host_tx, host_rx) = watch::channel(host(true, "wlan0"));
        let report = Arc::new(watch::channel(GateReport::default()).0);
        let _new_watcher = tokio::spawn(watch_public_addresses(
            endpoint_b.watch(),
            host_rx,
            true,
            GateSinks {
                public: public.clone(),
                gate: gate.clone(),
                report: report.clone(),
                ..GateSinks::default()
            },
        ));
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(
            !gate_rx.borrow().is_open(),
            "the new endpoint has not observed a public IPv4 yet"
        );
        assert!(
            report.subscribe().borrow().reason().contains("earlier network"),
            "{:?}",
            report.subscribe().borrow()
        );
        // Its first net report: B's public IPv4.
        endpoint_b
            .set(EndpointAddr::new(id).with_ip_addr(lan).with_ip_addr(b))
            .unwrap();
        within("the gate to open on B's IPv4", gate_rx.wait_for(|g| g.is_open()))
            .await
            .unwrap();
        assert_eq!(*public_rx.borrow(), want(&["192.0.2.9"]));
        // Same network, same route, a host event: nothing closes. With paused time the timeout below runs only once
        // the watcher has handled the event and gone idle, so it proves the gate did not move.
        gate_rx.mark_unchanged();
        host_tx.send_replace(host(true, "wlan0"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), gate_rx.changed())
                .await
                .is_err(),
            "the gate stays as it was"
        );
        assert!(gate_rx.borrow().is_open());
    }

    /// T10f, item 3: the host has IPv4 but the endpoint is bound to none (CGNAT only, or IPv6-only
    /// `direct_addresses`): the gate says it can never open, instead of "not known yet".
    #[tokio::test(start_paused = true)]
    async fn a_host_with_ipv4_and_no_ipv4_bound_says_the_gate_cannot_open() {
        let id = SecretKey::generate().public();
        let v6 = SocketAddr::new("2001:db8::5".parse().unwrap(), 4433);
        let endpoint_addr = n0_watcher::Watchable::new(EndpointAddr::new(id).with_ip_addr(v6));
        let (host_tx, host_rx) = watch::channel(host(true, "eth0"));
        let public = Arc::new(watch::channel(Vec::new()).0);
        let gate = Arc::new(watch::channel(EgressGate::Closed).0);
        let mut gate_rx = gate.subscribe();
        let _task = tokio::spawn(watch_public_addresses(
            endpoint_addr.watch(),
            host_rx,
            false,
            GateSinks {
                public,
                gate,
                ..GateSinks::default()
            },
        ));
        within("the blocked state", gate_rx.wait_for(|g| *g == EgressGate::NoIpv4Bound))
            .await
            .unwrap();
        // The host loses its IPv4: nothing blocks any more, the IPv6 address opens the gate.
        host_tx.send_replace(host(false, "eth0"));
        within("the gate to open without host IPv4", gate_rx.wait_for(|g| g.is_open()))
            .await
            .unwrap();
        assert!(!IPV4_NOT_BOUND.contains("not known yet"));
        assert!(IPV4_NOT_BOUND.contains("direct_addresses"));
    }

    /// T10f review, P3-2: right after DHCPv4 the endpoint is still bound without IPv4 and the Reselector is about to
    /// rebind it with IPv4. Until a rebind had its time, the gate is only closed; "bind an IPv4 address" is said when
    /// nothing changed it.
    #[tokio::test(start_paused = true)]
    async fn no_ipv4_bound_is_said_only_once_the_rebind_had_its_time() {
        let id = SecretKey::generate().public();
        let v6 = SocketAddr::new("2001:db8::5".parse().unwrap(), 4433);
        let endpoint_addr = n0_watcher::Watchable::new(EndpointAddr::new(id).with_ip_addr(v6));
        let (host_tx, host_rx) = watch::channel(host(false, "eth0"));
        let public = Arc::new(watch::channel(Vec::new()).0);
        let gate = Arc::new(watch::channel(EgressGate::Closed).0);
        let mut gate_rx = gate.subscribe();
        let _task = tokio::spawn(watch_public_addresses(
            endpoint_addr.watch(),
            host_rx,
            false,
            GateSinks {
                public,
                gate,
                ..GateSinks::default()
            },
        ));
        within("the gate to open on IPv6", gate_rx.wait_for(|g| g.is_open()))
            .await
            .unwrap();
        // DHCPv4 answered.
        host_tx.send_replace(host(true, "eth0"));
        within("the gate to close", gate_rx.wait_for(|g| !g.is_open()))
            .await
            .unwrap();
        assert_eq!(
            *gate_rx.borrow(),
            EgressGate::Closed,
            "a rebind may be pending: no advice yet"
        );
        tokio::time::advance(NO_IPV4_BOUND_SETTLE).await;
        within("the blocked state", gate_rx.wait_for(|g| *g == EgressGate::NoIpv4Bound))
            .await
            .unwrap();
    }

    /// T10h, item 3: a watcher that starts on a host with IPv4 and an endpoint bound to none (the agent starts, or the
    /// endpoint is rebound) cannot know yet whether a rebind is coming: it reports `Closed` first and the advice only
    /// after the settle time, not at once.
    #[tokio::test(start_paused = true)]
    async fn a_new_watcher_waits_before_saying_to_bind_an_ipv4_address() {
        let id = SecretKey::generate().public();
        let v6 = SocketAddr::new("2001:db8::5".parse().unwrap(), 4433);
        let endpoint_addr = n0_watcher::Watchable::new(EndpointAddr::new(id).with_ip_addr(v6));
        let (_host_tx, host_rx) = watch::channel(host(true, "eth0"));
        let public = Arc::new(watch::channel(Vec::new()).0);
        let gate = Arc::new(watch::channel(EgressGate::Closed).0);
        let mut gate_rx = gate.subscribe();
        let _task = tokio::spawn(watch_public_addresses(
            endpoint_addr.watch(),
            host_rx,
            false,
            GateSinks {
                public,
                gate,
                ..GateSinks::default()
            },
        ));
        // With paused time this runs only once the watcher has handled its first look and gone idle. Up to just under
        // the settle time there is no advice, so a delay shorter than it (T10h review P3-3) fails here.
        let just_under = NO_IPV4_BOUND_SETTLE - Duration::from_millis(1);
        assert!(
            tokio::time::timeout(just_under, gate_rx.changed()).await.is_err(),
            "no advice before the settle time"
        );
        assert_eq!(*gate_rx.borrow(), EgressGate::Closed);
        tokio::time::advance(Duration::from_millis(2)).await;
        within("the blocked state", gate_rx.wait_for(|g| *g == EgressGate::NoIpv4Bound))
            .await
            .unwrap();
    }

    /// T10h, item 1, end to end: a host whose only IPv4 is on its default-route interface `br-lan` gets the gate state
    /// that says to rename the interface, not the `direct_addresses` advice, once the rebind had its time.
    #[tokio::test(start_paused = true)]
    async fn a_bridge_named_uplink_gets_its_own_reason() {
        let id = SecretKey::generate().public();
        let v6 = SocketAddr::new("2001:db8::5".parse().unwrap(), 4433);
        let endpoint_addr = n0_watcher::Watchable::new(EndpointAddr::new(id).with_ip_addr(v6));
        let interfaces = [
            Interface::new("br-lan", true, vec![IfAddr::new("192.0.2.20".parse().unwrap(), 24)]),
            Interface::new("eth1", true, vec![IfAddr::new("2001:db8::5".parse().unwrap(), 64)]),
        ];
        let net = HostNet::from_interfaces(&interfaces, Some("br-lan".into()));
        assert!(net.ipv4 && net.bridge_named_uplink);
        let (_host_tx, host_rx) = watch::channel(net);
        let public = Arc::new(watch::channel(Vec::new()).0);
        let gate = Arc::new(watch::channel(EgressGate::Closed).0);
        let mut gate_rx = gate.subscribe();
        let _task = tokio::spawn(watch_public_addresses(
            endpoint_addr.watch(),
            host_rx,
            false,
            GateSinks {
                public,
                gate,
                ..GateSinks::default()
            },
        ));
        within(
            "the bridge-name reason",
            gate_rx.wait_for(|g| *g == EgressGate::BridgeNamedUplink),
        )
        .await
        .unwrap();
        for text in [IPV4_UPLINK_NAMED_LIKE_BRIDGE, IPV4_NOT_BOUND] {
            assert!(!text.contains("not known yet"));
        }
        assert!(IPV4_UPLINK_NAMED_LIKE_BRIDGE.contains("rename"));
        assert!(IPV4_UPLINK_NAMED_LIKE_BRIDGE.contains("does not help"));
    }

    /// T10h, item 1 (PR #41 review, P3-1): the flag is about the default-route interface alone: up, named like a
    /// bridge, with IPv4. IPv4 on a real-named interface that does not carry the default route changes nothing: a
    /// socket bound to its address still routes through the bridge-named uplink, so no policy can help.
    #[test]
    fn a_bridge_named_default_route_with_ipv4_is_flagged_whatever_else_has_ipv4() {
        let lan = || Interface::new("br-lan", true, vec![IfAddr::new("192.0.2.20".parse().unwrap(), 24)]);
        let eth = |ip: &str| Interface::new("eth0", true, vec![IfAddr::new(ip.parse().unwrap(), 24)]);
        let flagged =
            |ifs: &[Interface], route: &str| HostNet::from_interfaces(ifs, Some(route.into())).bridge_named_uplink;
        assert!(flagged(&[lan()], "br-lan"));
        assert!(!flagged(&[eth("192.0.2.30")], "eth0"), "a real name");
        assert!(
            flagged(&[lan(), eth("198.51.100.5")], "br-lan"),
            "a real interface has IPv4 too, but the route goes through br-lan"
        );
        assert!(
            !flagged(&[lan(), eth("198.51.100.5")], "eth0"),
            "the real interface carries the default route: iroh can bind it"
        );
        let down = Interface::new("br-lan", false, vec![IfAddr::new("192.0.2.20".parse().unwrap(), 24)]);
        assert!(
            !flagged(&[down, eth("198.51.100.5")], "br-lan"),
            "a down interface proves nothing"
        );
        let v6 = Interface::new("br-lan", true, vec![IfAddr::new("2001:db8::7".parse().unwrap(), 64)]);
        assert!(!flagged(&[v6], "br-lan"), "no IPv4 on the bridge-named uplink");
        assert!(
            !flagged(&[lan()], "eth9"),
            "br-lan is not the default route: no IPv4 at all"
        );
        assert!(
            !flagged(&[], "br-lan"),
            "enumeration failed: the ordinary fail-closed path"
        );
    }

    /// T10h review P3-1: "rename it" is advice only where a rename helps. A CGNAT-only `br-lan` is never bound after
    /// the rename either (`NoIpv4Bound` is the honest state), and an overlay like `tailscale0` or `zt*` must not be
    /// told to be renamed.
    #[test]
    fn the_rename_advice_needs_a_bindable_ipv4_on_a_bridge_like_name() {
        let on = |name: &str, ip: &str| {
            let ifs = [Interface::new(name, true, vec![IfAddr::new(ip.parse().unwrap(), 24)])];
            HostNet::from_interfaces(&ifs, Some(name.into()))
        };
        // A CGNAT address is never bound, whatever the name: the host has IPv4, the rename does not help.
        let cgnat = on("br-lan", "100.64.1.9");
        assert!(cgnat.ipv4 && !cgnat.bridge_named_uplink, "CGNAT is never bound");
        // Overlays and veth pairs are not bridges, even when the default route sits on them (an exit node).
        for name in ["tailscale0", "zt5u4abcde", "veth1234", "flannel.1", "vmnet8"] {
            let net = on(name, "192.0.2.20");
            assert!(net.ipv4 && !net.bridge_named_uplink, "{name} is not a bridge");
        }
        // The bridge-like names still get the advice.
        for name in [
            "br-lan",
            "BR-EX",
            "virbr0",
            "lxcbr0",
            "lxdbr0",
            "docker0",
            "podman1",
            "cni-podman0",
        ] {
            assert!(on(name, "192.0.2.20").bridge_named_uplink, "{name} is bridge-like");
        }
    }

    /// A loopback endpoint has no public address: nothing is published, and the watcher ends with the endpoint.
    #[tokio::test]
    async fn a_loopback_endpoint_publishes_nothing_and_the_watcher_ends_with_it() {
        let spec = BindSpec {
            relay_mode: RelayMode::Disabled,
            addrs: loopback(),
            port: 0,
            alpns: Vec::new(),
        };
        let ep = bind_endpoint(SecretKey::generate(), &spec).await.unwrap();
        let tx = Arc::new(watch::channel(Vec::new()).0);
        let gate = Arc::new(watch::channel(EgressGate::Closed).0);
        let rx = tx.subscribe();
        let gate_rx = gate.subscribe();
        let (_host_tx, host_rx) = watch::channel(host(true, "lo"));
        let task = tokio::spawn(watch_public_addresses(
            ep.watch_addr(),
            host_rx,
            true,
            GateSinks {
                public: tx,
                gate,
                ..GateSinks::default()
            },
        ));
        ep.close().await;
        drop(ep);
        tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .expect("the watcher ends with the endpoint")
            .unwrap();
        assert!(rx.borrow().is_empty());
        assert!(!gate_rx.borrow().is_open(), "a loopback endpoint never opens the gate");
    }

    /// T10l, the Omarchy node of ACC-1: an IPv4 socket on the Wi-Fi's private address and an IPv6 ULA socket, one
    /// default route, a host with IPv4. The endpoint lists only its own two addresses at first; the net report's QAD
    /// IPv4 comes a few seconds later. The gate opens, and the ULA is no public address.
    #[tokio::test(start_paused = true)]
    async fn a_native_node_with_a_private_ipv4_and_a_ula_opens_when_qad_arrives_late() {
        let id = SecretKey::generate().public();
        let lan = SocketAddr::new("192.168.0.10".parse().unwrap(), 40001);
        let ula = SocketAddr::new("fd00:db8::48".parse().unwrap(), 40002);
        let qad = SocketAddr::new("203.0.113.9".parse().unwrap(), 40001);
        let endpoint_addr = n0_watcher::Watchable::new(EndpointAddr::new(id).with_ip_addr(lan).with_ip_addr(ula));
        let (_host_tx, host_rx) = watch::channel(host(true, "wlan0"));
        let public = Arc::new(watch::channel(Vec::new()).0);
        let gate = Arc::new(watch::channel(EgressGate::Closed).0);
        let public_rx = public.subscribe();
        let mut gate_rx = gate.subscribe();
        let _task = tokio::spawn(watch_public_addresses(
            endpoint_addr.watch(),
            host_rx,
            true,
            GateSinks {
                public: public.clone(),
                gate: gate.clone(),
                ..GateSinks::default()
            },
        ));
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(*gate_rx.borrow(), EgressGate::Closed, "no public IPv4 yet");
        assert!(public_rx.borrow().is_empty(), "a ULA and a LAN address are not public");
        endpoint_addr
            .set(
                EndpointAddr::new(id)
                    .with_ip_addr(lan)
                    .with_ip_addr(ula)
                    .with_ip_addr(qad),
            )
            .unwrap();
        within("the gate to open on the QAD IPv4", gate_rx.wait_for(|g| g.is_open()))
            .await
            .unwrap();
        assert_eq!(*public_rx.borrow(), want(&["203.0.113.9"]));
    }

    /// T10l, candidate "a host event that changes nothing closes the gate", as the review of PR #48 (P2) settled it:
    /// the route disappears and comes back (a Wi-Fi roam, a DHCP renewal) and iroh's addresses never change (QAD sees
    /// the same address). The gate does not trust the endpoint it closed on, however long it waits: the agent rebinds
    /// on every route move (the watcher asks for it), and the gate opens on the new endpoint's first public IPv4.
    #[tokio::test(start_paused = true)]
    async fn a_route_flap_closes_the_gate_until_the_rebound_endpoint_observes_a_public_ipv4() {
        let id = SecretKey::generate().public();
        let lan = SocketAddr::new("192.168.0.10".parse().unwrap(), 40001);
        let qad = SocketAddr::new("203.0.113.9".parse().unwrap(), 40001);
        let endpoint_addr = n0_watcher::Watchable::new(EndpointAddr::new(id).with_ip_addr(lan).with_ip_addr(qad));
        let (host_tx, host_rx) = watch::channel(host(true, "wlan0"));
        let public = Arc::new(watch::channel(Vec::new()).0);
        let gate = Arc::new(watch::channel(EgressGate::Closed).0);
        let mut gate_rx = gate.subscribe();
        let old_watcher = tokio::spawn(watch_public_addresses(
            endpoint_addr.watch(),
            host_rx,
            true,
            GateSinks {
                public: public.clone(),
                gate: gate.clone(),
                ..GateSinks::default()
            },
        ));
        within("the gate to open", gate_rx.wait_for(|g| g.is_open()))
            .await
            .unwrap();
        // The default route goes away and comes back; iroh's addresses never change.
        host_tx.send_replace(HostNet {
            ipv4: true,
            default_route: None,
            bridge_named_uplink: false,
        });
        within("the gate to close", gate_rx.wait_for(|g| !g.is_open()))
            .await
            .unwrap();
        host_tx.send_replace(host(true, "wlan0"));
        tokio::time::sleep(Duration::from_secs(300)).await;
        assert!(
            !gate_rx.borrow().is_open(),
            "the same route is back, but nothing was observed on it by a new endpoint"
        );
        // The rebind: a new endpoint, a new watcher; its first net report gives the current public IPv4.
        old_watcher.abort();
        let _ = old_watcher.await;
        let endpoint_b = n0_watcher::Watchable::new(EndpointAddr::new(id).with_ip_addr(lan));
        let (_host_tx, host_rx) = watch::channel(host(true, "wlan0"));
        let _new_watcher = tokio::spawn(watch_public_addresses(
            endpoint_b.watch(),
            host_rx,
            true,
            GateSinks {
                public: public.clone(),
                gate: gate.clone(),
                ..GateSinks::default()
            },
        ));
        endpoint_b
            .set(EndpointAddr::new(id).with_ip_addr(lan).with_ip_addr(qad))
            .unwrap();
        within(
            "the gate to open on the new endpoint's QAD IPv4",
            gate_rx.wait_for(|g| g.is_open()),
        )
        .await
        .unwrap();
    }

    /// T10l: after a move the endpoint that was bound before it is never taken at its word, whether it lists no public
    /// IPv4 (iroh dropped it: the host is offline) or still lists the old one, and the report says why.
    #[tokio::test(start_paused = true)]
    async fn after_a_move_the_endpoint_bound_before_it_does_not_reopen_the_gate() {
        let id = SecretKey::generate().public();
        let lan = SocketAddr::new("192.168.0.10".parse().unwrap(), 40001);
        let qad = SocketAddr::new("203.0.113.9".parse().unwrap(), 40001);
        let endpoint_addr = n0_watcher::Watchable::new(EndpointAddr::new(id).with_ip_addr(lan).with_ip_addr(qad));
        let (host_tx, host_rx) = watch::channel(host(true, "wlan0"));
        let public = Arc::new(watch::channel(Vec::new()).0);
        let gate = Arc::new(watch::channel(EgressGate::Closed).0);
        let report = Arc::new(watch::channel(GateReport::default()).0);
        let mut gate_rx = gate.subscribe();
        let report_rx = report.subscribe();
        let _task = tokio::spawn(watch_public_addresses(
            endpoint_addr.watch(),
            host_rx,
            true,
            GateSinks {
                public: public.clone(),
                gate: gate.clone(),
                report: report.clone(),
                ..GateSinks::default()
            },
        ));
        within("the gate to open", gate_rx.wait_for(|g| g.is_open()))
            .await
            .unwrap();
        let open = report_rx.borrow().clone();
        assert_eq!(open.state, EgressGate::Open);
        assert!(open.inputs.public_ipv4_here && open.inputs.host_ipv4 && open.inputs.ipv4_bound);
        assert_eq!(open.inputs.default_route.as_deref(), Some("wlan0"));
        // The route moves, and iroh loses its public address (offline) without being rebound.
        host_tx.send_replace(host(true, "eth9"));
        endpoint_addr.set(EndpointAddr::new(id).with_ip_addr(lan)).unwrap();
        within("the gate to close", gate_rx.wait_for(|g| !g.is_open()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(300)).await;
        assert_eq!(*gate_rx.borrow(), EgressGate::Closed);
        let closed = report_rx.borrow().clone();
        assert!(!closed.inputs.public_ipv4_here, "{closed:?}");
        assert!(closed.inputs.network_changed, "{closed:?}");
        assert!(
            closed.reason().contains("the network changed"),
            "{closed:?}: {}",
            closed.reason()
        );
    }

    /// T10l: a route move that arrives with an update of the endpoint's addresses is not missed. The loop used to
    /// compare the route only when the host's change woke it; an update that woke it first marked the change as seen,
    /// and the move was never noticed (the gate stayed open on a new network). Both are delivered before the watcher
    /// runs again, so this holds whichever branch `select!` takes first. The update lists no public IPv4, so
    /// whichever is handled first, the gate is closed by the move and stays closed (the old address stays denied).
    #[tokio::test(start_paused = true)]
    async fn a_route_move_is_not_missed_when_the_endpoint_updates_at_the_same_moment() {
        let id = SecretKey::generate().public();
        let lan = SocketAddr::new("192.168.0.10".parse().unwrap(), 40001);
        let a = SocketAddr::new("203.0.113.9".parse().unwrap(), 40001);
        let other = SocketAddr::new("192.168.0.11".parse().unwrap(), 40001);
        let endpoint_addr = n0_watcher::Watchable::new(EndpointAddr::new(id).with_ip_addr(lan).with_ip_addr(a));
        let (host_tx, host_rx) = watch::channel(host(true, "wlan0"));
        let public = Arc::new(watch::channel(Vec::new()).0);
        let gate = Arc::new(watch::channel(EgressGate::Closed).0);
        let mut gate_rx = gate.subscribe();
        let _task = tokio::spawn(watch_public_addresses(
            endpoint_addr.watch(),
            host_rx,
            true,
            GateSinks {
                public: public.clone(),
                gate: gate.clone(),
                ..GateSinks::default()
            },
        ));
        within("network A to be ready", gate_rx.wait_for(|g| g.is_open()))
            .await
            .unwrap();
        host_tx.send_replace(host(true, "eth9"));
        endpoint_addr
            .set(EndpointAddr::new(id).with_ip_addr(lan).with_ip_addr(other))
            .unwrap();
        within("the gate to close on the move", gate_rx.wait_for(|g| !g.is_open()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(300)).await;
        assert!(
            !gate_rx.borrow().is_open(),
            "the endpoint lists no public IPv4 on the new route: nothing to reopen on"
        );
        assert_eq!(*public.subscribe().borrow(), want(&["203.0.113.9"]), "still denied");
    }

    /// Review of PR #48, P3-1: the first verdict of a watcher is logged once, even when it equals the default report;
    /// after that only a change of the gate is.
    #[test]
    fn the_first_verdict_is_logged_once_and_then_only_changes() {
        let mut logged_once = false;
        assert!(needs_log(false, &mut logged_once), "the first one, unchanged or not");
        assert!(
            !needs_log(false, &mut logged_once),
            "an unchanged verdict is not logged again"
        );
        assert!(!needs_log(false, &mut logged_once));
        assert!(needs_log(true, &mut logged_once), "a change is");
        assert!(!needs_log(false, &mut logged_once));
    }

    /// T10l: every state says what it is and why, in the words the log and `p2pc-agent status` share.
    #[test]
    fn every_state_of_the_gate_has_a_label_and_a_reason() {
        let inputs = GateInputs {
            host_ipv4: true,
            default_route: Some("wlan0".into()),
            ipv4_bound: true,
            ..GateInputs::default()
        };
        let report = |state, inputs: &GateInputs| GateReport {
            state,
            inputs: inputs.clone(),
        };
        let line = |state, inputs: &GateInputs| report(state, inputs).line();
        assert_eq!(
            line(EgressGate::Closed, &inputs),
            "closed: waiting for a public IPv4 from the relay (QUIC address discovery); none seen yet"
        );
        let moved = GateInputs {
            network_changed: true,
            public_ipv4_known: true,
            ..inputs.clone()
        };
        assert_eq!(
            line(EgressGate::Closed, &moved),
            "closed: the network changed; waiting for the rebound endpoint to observe a public IPv4 on the new network"
        );
        let earlier = GateInputs {
            public_ipv4_known: true,
            ..inputs.clone()
        };
        assert_eq!(
            line(EgressGate::Closed, &earlier),
            "closed: a public IPv4 was seen on an earlier network; none on this one yet"
        );
        let earlier_no_ipv4 = GateInputs {
            host_ipv4: false,
            public_ipv4_known: true,
            ..inputs.clone()
        };
        assert_eq!(
            line(EgressGate::Closed, &earlier_no_ipv4),
            "closed: the host has no IPv4; waiting for a public IPv6; none seen yet"
        );
        let no_ipv4 = GateInputs {
            host_ipv4: false,
            ..inputs.clone()
        };
        assert_eq!(
            line(EgressGate::Closed, &no_ipv4),
            "closed: the host has no IPv4; waiting for a public IPv6; none seen yet"
        );
        let here = GateInputs {
            public_ipv4_here: true,
            public_ipv4_known: true,
            ..inputs.clone()
        };
        assert_eq!(
            line(EgressGate::Open, &here),
            "open: a public IPv4 was observed on this network"
        );
        let v6 = GateInputs {
            public_ipv6_known: true,
            ..no_ipv4.clone()
        };
        assert_eq!(
            line(EgressGate::Open, &v6),
            "open: the host has no IPv4 and a public IPv6 was observed"
        );
        let unbound = GateInputs {
            ipv4_bound: false,
            ..inputs.clone()
        };
        assert_eq!(
            line(EgressGate::NoIpv4Bound, &unbound),
            "no_ipv4_bound: the host has IPv4 but the iroh endpoint is bound to no IPv4 address"
        );
        assert_eq!(
            line(EgressGate::BridgeNamedUplink, &unbound),
            "bridge_named_uplink: the default-route interface has IPv4 but is named like a container bridge"
        );
    }

    /// T10l: the debug log shows private addresses and masks public ones; the masked form never holds the address.
    #[test]
    fn public_addresses_are_masked_in_the_log_and_private_ones_are_not() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(mask_ip(ip("203.0.113.9")), "203.0.x.x");
        assert_eq!(mask_ip(ip("2001:db8:1234:5678::9")), "2001:db8:x");
        assert_eq!(mask_ip(ip("192.168.0.10")), "192.168.0.10");
        assert_eq!(mask_ip(ip("fd00:db8::48")), "fd00:db8::48");
        assert_eq!(mask_ip(ip("100.64.0.7")), "100.64.0.7", "CGNAT is not public");
        let addrs: Vec<SocketAddr> = ["192.168.0.10:40001", "[fd00:db8::48]:40002", "203.0.113.9:40001"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let shown = describe_addrs(&addrs);
        assert_eq!(shown, "192.168.0.10:40001, [fd00:db8::48]:40002, 203.0.x.x:40001");
        assert!(!shown.contains("113"), "{shown}");
        assert_eq!(describe_addrs(&[]), "none");
    }

    /// T10l: closing the gate for a network change tells the report, with the new network's inputs (review of PR #48,
    /// P3-3).
    #[test]
    fn closing_the_gate_for_a_network_change_updates_the_report() {
        let sinks = GateSinks::default();
        sinks.gate.send_replace(EgressGate::Open);
        sinks.report.send_replace(GateReport {
            state: EgressGate::Open,
            inputs: GateInputs {
                host_ipv4: true,
                default_route: Some("eth0".into()),
                public_ipv4_here: true,
                public_ipv4_known: true,
                ..GateInputs::default()
            },
        });
        let report_rx = sinks.report.subscribe();
        close_gate_if(&sinks, &host(false, "wlan0"));
        assert!(
            report_rx.borrow().state.is_open(),
            "no IPv4 on the host: nothing to guard"
        );
        close_gate_if(&sinks, &host(true, "wlan0"));
        let r = report_rx.borrow().clone();
        assert_eq!(r.state, EgressGate::Closed);
        assert_eq!(
            r.inputs.default_route.as_deref(),
            Some("wlan0"),
            "the new network's route"
        );
        assert!(r.inputs.network_changed && !r.inputs.public_ipv4_here && r.inputs.public_ipv4_known);
        assert!(r.line().starts_with("closed: the network changed"), "{}", r.line());
    }

    /// A watcher over a public IPv4 on `wlan0`, started and open, with its sinks.
    async fn open_watcher(
        id: iroh::EndpointId,
    ) -> (
        n0_watcher::Watchable<EndpointAddr>,
        watch::Sender<HostNet>,
        GateSinks,
        tokio::task::JoinHandle<()>,
    ) {
        let lan = SocketAddr::new("192.168.0.10".parse().unwrap(), 40001);
        let qad = SocketAddr::new("203.0.113.9".parse().unwrap(), 40001);
        let endpoint_addr = n0_watcher::Watchable::new(EndpointAddr::new(id).with_ip_addr(lan).with_ip_addr(qad));
        let (host_tx, host_rx) = watch::channel(host(true, "wlan0"));
        let sinks = GateSinks::default();
        let mut gate_rx = sinks.gate.subscribe();
        let task = tokio::spawn(watch_public_addresses(
            endpoint_addr.watch(),
            host_rx,
            true,
            sinks.clone(),
        ));
        within("the gate to open", gate_rx.wait_for(|g| g.is_open()))
            .await
            .unwrap();
        (endpoint_addr, host_tx, sinks, task)
    }

    /// Review of PR #48, round 2, P2: the watcher that sees a route move asks for the rebind itself. Nothing else runs
    /// here (no network monitor, no daemon): the request is still made, after the debounce, and not before.
    #[tokio::test(start_paused = true)]
    async fn a_route_move_makes_the_watcher_ask_for_a_rebind_by_itself() {
        let (_addrs, host_tx, sinks, _task) = open_watcher(SecretKey::generate().public()).await;
        let rebind = sinks.rebind.clone();
        // Nothing moved: nothing is asked, however long it takes.
        tokio::time::timeout(Duration::from_secs(60), rebind.notified())
            .await
            .unwrap_err();
        host_tx.send_replace(host(true, "eth9"));
        // Not at once: the burst's events get the debounce.
        tokio::time::timeout(NETWORK_CHANGE_DEBOUNCE / 2, rebind.notified())
            .await
            .unwrap_err();
        within("the request for a rebind", rebind.notified()).await;
        assert!(!sinks.gate.subscribe().borrow().is_open());
    }

    /// T10l review P3-3 (doubtful): consecutive move-triggered rebinds with no stable period between them are counted,
    /// and the loop is named once, after `REBIND_LOOP_AFTER` of them; a stable period starts over.
    #[test]
    fn consecutive_move_rebinds_are_counted_and_named_once() {
        let t0 = std::time::Instant::now();
        let mut guard = RebindLoopGuard::default();
        let gap = REBIND_LOOP_STABLE / 4;
        let mut named = Vec::new();
        for i in 0..REBIND_LOOP_AFTER + 3 {
            if let Some(n) = guard.requested(t0 + gap * i) {
                named.push(n);
            }
        }
        assert_eq!(named, [REBIND_LOOP_AFTER], "named once, at the threshold");
        assert_eq!(guard.consecutive(), REBIND_LOOP_AFTER + 3);
        // A stable period (no move for REBIND_LOOP_STABLE) ends the run; a later loop is named again.
        let later = t0 + gap * (REBIND_LOOP_AFTER + 3) + REBIND_LOOP_STABLE;
        assert_eq!(guard.requested(later), None);
        assert_eq!(guard.consecutive(), 1, "starts over after a stable period");
        let named_again: Vec<u32> = (1..REBIND_LOOP_AFTER)
            .filter_map(|i| guard.requested(later + gap * i))
            .collect();
        assert_eq!(named_again, [REBIND_LOOP_AFTER]);
    }

    /// The same, as the watcher drives it: a route that moves again right after every rebind is counted, whatever the
    /// daemon does; one move per long while is not a loop.
    #[tokio::test(start_paused = true)]
    async fn a_route_that_moves_again_after_every_rebind_is_counted_by_the_watcher() {
        let (_addrs, host_tx, sinks, _task) = open_watcher(SecretKey::generate().public()).await;
        let rebind = sinks.rebind.clone();
        for i in 0..REBIND_LOOP_AFTER {
            host_tx.send_replace(host(true, if i % 2 == 0 { "eth9" } else { "wlan0" }));
            within("the request for a rebind", rebind.notified()).await;
        }
        assert_eq!(sinks.rebinds.lock().unwrap().consecutive(), REBIND_LOOP_AFTER);
        // Long after, one more move is the first of a new run.
        tokio::time::sleep(REBIND_LOOP_STABLE * 2).await;
        host_tx.send_replace(host(true, "eth7"));
        // (The unanswered requests left a permit behind, so waiting on the `Notify` would not wait for this one.)
        tokio::time::sleep(NETWORK_CHANGE_DEBOUNCE * 2).await;
        assert_eq!(sinks.rebinds.lock().unwrap().consecutive(), 1);
    }

    /// T10l review P3-5: a rebind request that is still pending is not a fault while the daemon may legitimately be
    /// inside `connect()` or the pre-Welcome handshake (up to 30 s). The retries are logged at `info` as "still
    /// pending",
    /// and only after more than that is a `warn` worth reading.
    #[test]
    fn a_pending_rebind_request_warns_only_after_the_daemon_could_be_busy() {
        let busiest = Duration::from_secs(15 + 15); // CONNECT_TIMEOUT + WELCOME_TIMEOUT of the agent
        let quiet_retries = (1..).take_while(|r| !rebind_retry_is_warning(*r)).count();
        assert!(quiet_retries >= 1, "the first retry is not a warning");
        assert!(
            REBIND_RETRY * u32::try_from(quiet_retries).unwrap() >= busiest,
            "{quiet_retries} quiet retries of {REBIND_RETRY:?} cover a daemon that is busy for {busiest:?}"
        );
        assert!(rebind_retry_is_warning(u32::try_from(quiet_retries).unwrap() + 1));
        assert!(rebind_retry_is_warning(1000), "and it stays a warning");
    }

    /// Several requests in a row, or a burst of events, are one rebind; and with nobody rebinding the watcher asks
    /// again every `REBIND_RETRY` (as "still pending", warning only after several), until it is stopped.
    #[tokio::test(start_paused = true)]
    async fn a_burst_of_route_events_is_one_request_and_an_unanswered_one_is_repeated() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (_addrs, host_tx, sinks, task) = open_watcher(SecretKey::generate().public()).await;
        let asked = Arc::new(AtomicUsize::new(0));
        let consumer = {
            let (asked, rebind) = (asked.clone(), sinks.rebind.clone());
            tokio::spawn(async move {
                loop {
                    rebind.notified().await;
                    asked.fetch_add(1, Ordering::SeqCst);
                }
            })
        };
        for i in 0..10 {
            host_tx.send_replace(host(true, if i % 2 == 0 { "eth9" } else { "wlan0" }));
            tokio::time::sleep(NETWORK_CHANGE_DEBOUNCE / 4).await;
        }
        tokio::time::sleep(NETWORK_CHANGE_DEBOUNCE * 2).await;
        assert_eq!(asked.load(Ordering::SeqCst), 1, "one request for the whole burst");
        tokio::time::sleep(REBIND_RETRY).await;
        assert_eq!(asked.load(Ordering::SeqCst), 2, "nobody rebound: asked again");
        // The rebind stops the watcher: nothing is asked any more.
        task.abort();
        let _ = task.await;
        tokio::time::sleep(REBIND_RETRY * 3).await;
        assert_eq!(asked.load(Ordering::SeqCst), 2);
        consumer.abort();
    }

    /// Review of PR #48, P3-1: a first verdict that equals the default report is still sent, so whoever follows the
    /// report (the status file) hears that a verdict was made.
    #[tokio::test(start_paused = true)]
    async fn the_first_report_is_sent_even_when_it_equals_the_default() {
        let id = SecretKey::generate().public();
        let endpoint_addr = n0_watcher::Watchable::new(EndpointAddr::new(id));
        let (_host_tx, host_rx) = watch::channel(HostNet::default());
        let sinks = GateSinks::default();
        let mut report_rx = sinks.report.subscribe();
        let _task = tokio::spawn(watch_public_addresses(
            endpoint_addr.watch(),
            host_rx,
            false,
            sinks.clone(),
        ));
        within("the first report", report_rx.changed()).await.unwrap();
        assert_eq!(*report_rx.borrow(), GateReport::default());
    }

    #[tokio::test]
    async fn relay_only_needs_no_watcher() {
        let (tx, mut rx) = mpsc::channel(1);
        watch_network(DirectAddresses::None, Vec::new(), tx).await;
        assert!(rx.recv().await.is_none(), "returned at once, sending nothing");
    }
}
