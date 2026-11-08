# Residual risks

Known gaps that the code cannot close today, with their impact and what limits it. Each entry names the spec rule it
falls short of, so that a later change can retire it.

## R-1 · Remote peers can make an endpoint use addresses in forbidden ranges (spec §10)

- **Rule.** §10 "Address hygiene": agents and the server MUST "not advertise **or use**" addresses in
  `100.64.0.0/10` (CGNAT, Tailscale), link-local addresses, or container and VM bridge networks.
- **What is enforced.** The *local* half: each endpoint binds, and so advertises, only the addresses that
  `p2pc_proto::net::select_addresses` picks (never those ranges, never a bridge), and selects them again when the
  network changes (`Reselector`). The agent dials the server with its NodeId and relay URLs only, never with direct
  addresses taken from anywhere else.
- **What is not.** The *remote* half. In iroh 1.4 a peer's candidate addresses arrive in QUIC NAT-traversal frames
  (noq's `n0_nat_traversal`), and iroh hole-punches to every candidate on its own (`socket/remote_map/remote_state.rs`,
  `trigger_holepunching`). iroh 1.4 has **no stable API to filter them**:
  - `Builder::addr_filter` filters only what is *published* to address-lookup services, which we do not use;
  - `Builder::path_selector` (`PathSelector`) exists only behind the `unstable-custom-transports` feature, with no
    semver guarantee, and it only chooses among paths that are already open: the probes to the forbidden addresses
    are sent before it runs.
- **Impact.**
  - A misbehaving peer can make the other end send QUIC hole-punching probes to addresses of its choosing in those
    ranges, for example a Tailscale `100.x` address or a Docker bridge. For the server, the peer can be any NodeId
    (connecting costs nothing before `Join`). The probes are small, rate-limited by iroh, and carry no
    application data; they cannot open a connection to anything but an iroh endpoint holding the expected key.
  - If the peer *is* reachable on such an address (it really is on the same tailnet or bridge), the connection may
    move to that path, as E4 saw. The traffic stays end-to-end encrypted and authenticated by the NodeIds, so this is
    a routing and privacy issue (it can reveal that both ends share a tailnet), not a confidentiality one.
  - It does not give a **job** any network access: jobs run with `--network=none` behind the egress proxy (hard rule
    2), which is unaffected.
- **Limits in place.** Both ends bind only hygienic addresses, so the probes leave from the default-route interface
  (a probe to a bridge address from a socket bound elsewhere follows the host's routing table); the server caps
  connections from unknown NodeIds (§6 "Before `Join`").
- **To retire it.** Filter remote candidates with the same rules as the local side (`is_forbidden_address`, plus the
  bridge networks) once iroh offers a stable hook, either upstream or through a stable `PathSelector`. Track it on
  every iroh upgrade.

## R-2 · The egress gate fails closed, and some hosts can never open it (spec §9 "hairpin NAT")

- **Rule.** §9: the provider's IP and LAN are never used or touched. The egress proxy refuses the node's own public
  addresses, so a job cannot reach a port-forwarded LAN service through the router. It can only do that once the node
  knows its public IPv4, which iroh learns by QUIC address discovery through a relay.
- **What is enforced.**
  - On a host with IPv4, the egress gate (`p2pc_net::EgressGate`) is open only after a public IPv4 has been observed
    **on the current network**. It closes again when IPv4 comes up after it opened on IPv6, and when the network
    changes (the endpoint is rebound, or the default route moves). The published list of public addresses is kept
    when the gate closes, until a fresh observation of the same family replaces it (a new public IPv4 replaces the
    old one; an observation with no IPv4 changes nothing).
  - **A move of the default route is fail-closed until a fresh observation on a new endpoint (T10l, review of
    PR #48).** The watcher of the endpoint that was bound before the move closes the gate and never reopens it: what
    that endpoint lists afterwards can be the old network's QAD address under the new network's local addresses, so
    nothing it lists is an observation on the new route, however long ago the move was (there is no timer). **The
    watcher that sees the move is the one that asks for the new endpoint**, so a move it sees always leads to a
    rebind, whatever any other network monitor saw: after the events of a burst have been quiet for the
    network-change debounce it signals the connector (`p2pc_net::GateSinks::rebind`, a `Notify`: requests in a row,
    or made while the daemon is busy, give one rebind), the daemon ends the session, the connector binds a new
    endpoint with the same addresses and the daemon reconnects. If no rebind has come `p2pc_net::REBIND_RETRY` (8 s)
    later, the watcher logs "still pending" at `info` and asks again, and keeps asking every `REBIND_RETRY` until the
    rebind stops it; only the fifth repeat (more than the 30 s the daemon can legitimately spend connecting) is a
    `warn`.
    One rebind covers the requests made before it starts, not those made after: when a move of the route also changes
    the address selection, the network watcher's change and the gate watcher's request each wait their own debounce,
    and whichever is handled second can cause one more rebind (the first binds the old selection, the second the new
    one). That costs an extra session teardown and reconnect; it does not weaken the gate, which stays closed until
    the endpoint of the last rebind observes a public IPv4 on the current network.
    Move-triggered rebinds are counted across endpoints: when `p2pc_net::REBIND_LOOP_AFTER` (5) of them come with
    less than `p2pc_net::REBIND_LOOP_STABLE` (60 s) between them, one `warn` names the loop with the interface names
    before and after the move (a route that really flaps, or two readings of the default route that disagree); the
    gate stays closed all the same.
    The address selection can be the same (a multi-homed host with `direct_addresses` CIDRs, a route that flaps inside
    the debounce); the rebind happens all the same. A new endpoint cannot list a stale QAD address: its first net
    report gives the current network's public IPv4, and that opens the gate. Until then the old IPv4 stays denied and
    the gate says "a public IPv4 was seen on an earlier network; none on this one yet". What is not covered: a move
    that shows no route event (a Wi-Fi network change that keeps the interface, its route and its private address),
    for which the endpoint's list is whatever iroh's own net report has measured; and a host where the network cannot
    be watched (the log says so), where the gate keeps the state measured at start.
  - **The gate says why.** Every change of the gate is logged at `info` ("egress gate changed") with its state, the
    reason and the inputs: whether the host has IPv4, the default-route interface, whether the endpoint is bound to
    an IPv4 address, and whether a public IPv4 (known; seen on this network) and a public IPv6 were seen. Public
    addresses are never in it; at `debug` each look at the endpoint's addresses is logged with public ones masked
    (`203.0.x.x`). `p2pc-agent status` prints the same state and reason on an `Egress gate:` line (from
    `<data_dir>/egress-gate.json`, 0600, no addresses), marked `(last run)` when no agent holds the data dir's lock.
  - Egress proxies that are already running follow the gate for every new upstream connection: while it is not open
    they refuse IPv4 destinations (`X-P2PC-Egress: egress-unavailable`) and keep allowing IPv6 ones. IPv6 is covered by
    the host's own networks, the /56 around its global addresses, and its public IPv6 addresses.
- **What is not.**
  - **A node that can never open the gate.** On a host with IPv4 whose iroh endpoint is bound to no IPv4 address, the
    public IPv4 is never learned. That is the case for `iroh.direct_addresses = "none"` (no IP socket is bound at all),
    for a dual-stack host with IPv6-only `iroh.direct_addresses`, and for a CGNAT-only host. The gate stays closed:
    that is safe, but the node cannot run egress jobs. The job's error and the agent's log say so and name the setting
    (`iroh.direct_addresses`). A CGNAT `100.64.0.0/10` address is never bound, so a node whose only IPv4 address is one
    cannot run egress jobs at all. The message is given only once a rebind had its time
    (`p2pc_net::NO_IPV4_BOUND_SETTLE`, twice the network-change debounce) after the host's IPv4 state changed, or
    since the endpoint's address watcher started (agent start, each rebind); until then the error is the plain
    "not known yet". Jobs without egress are not affected.
  - **An uplink named like a container bridge is never bound.** `select_addresses` drops every interface named like
    a container, VM or overlay network (`br-*`, `docker*`, `podman*`…) under every policy, an explicit CIDR in
    `iroh.direct_addresses` included. The default-route interface still counts as host IPv4 (see the next point), so
    when the default route is on an up interface with a bridge-like name (`br-*`, `virbr*`, `lxcbr*`, `lxdbr*`,
    `docker*`, `podman*`, `cni*`, for example `br-lan` or `br-ex`) that has an IPv4 address iroh could bind (not
    CGNAT or link-local), iroh does not bind it, the public IPv4 is never learned, and the gate stays closed. A
    CGNAT-only interface, or an overlay such as `tailscale*` or `zt*`, is not given this advice: renaming it would
    not help, and the gate says `NoIpv4Bound` instead. This holds whatever the other interfaces have: a real-named
    `eth1` with IPv4 but without the default route can be bound by a CIDR, but that is not a supported fix; what it
    does depends on the host's routing. Setting `iroh.direct_addresses` is therefore not the advice given. The gate
    reports a separate state (`EgressGate::BridgeNamedUplink`, in place of `NoIpv4Bound`), and the job's error and
    the agent's log say that the uplink's name looks like a container bridge and that the reliable way out is to
    rename the interface (for example `lan0`). The state is reported after the same settle time as the previous
    point.
  - **"Has IPv4" is judged from interface names, except for the default route.** Interfaces named like containers,
    VMs and overlays (`podman*`, `docker*`, `br-*`, `virbr*`, `veth*`, `tailscale*`, and the rest of
    `p2pc_proto::net::VIRTUAL_INTERFACE_PREFIXES`) are ignored, whatever their addresses, *unless* they carry the
    default route: that interface always counts, so a real uplink called `br-lan` or `br-ex` is not mistaken for a
    bridge. What is left: an interface with such a name that is a real uplink but does **not** carry the default route
    (a second uplink reached by policy routing) is ignored, so a host whose only IPv4 is there is taken for IPv6-only
    and the gate opens on its public IPv6. A bridge with an unusual name, or a Tailscale interface renamed by the
    owner, still counts as IPv4: the gate then waits for a public IPv4 that may never come. That direction fails
    closed. When the interface list cannot be read, the host is taken to have IPv4, again closed.
  - **A route change without a rebind is best effort.** When the endpoint is rebound (the usual case: the default
    selection follows the default route), the new endpoint knows nothing from before, so the gate is exact once the
    rebind lands, and best effort during the Reselector's 2 s debounce before it. When it
    is not (a fixed list of networks in `direct_addresses`), the gate closes on a change of the default-route
    interface, but iroh may still list the old network's WAN IPv4 until address discovery runs again; if the next
    update of its address list still carries that address, the gate reopens on it. The old address stays denied; the
    new WAN IPv4 may be missing from the deny list until iroh reports it. A running proxy then refuses IPv4 only
    while the gate is closed.
- **To retire it.** Learn the public IPv4 without an IPv4 socket bound to iroh (a one-off STUN or HTTPS probe through the
  agent, which needs the owner's consent under hard rule 6), and ask iroh for a signal that says an address was
  re-observed.
