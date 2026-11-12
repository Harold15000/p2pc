// SPDX-License-Identifier: Apache-2.0

//! The agent's iroh endpoint (§10) and the connector that dials the server with it.
//!
//! The §10 plumbing is `p2pc-net`'s, shared with the server (T05b review, P2-3): no port mapping, no address lookup,
//! one UDP socket per address `p2pc_proto::net::select_addresses` picks under `[iroh] direct_addresses`, and the
//! debounced network watcher ([`p2pc_net::watch_network`]). What is the agent's own:
//!
//! - **Outbound only.** The endpoint is bound with **no ALPN**, so it accepts no connection at all: it only dials
//!   the server, on `p2pc/agent/1` (SI-12, hard rule 4). The streams the server opens for service ports (H2 §6.1)
//!   are streams of that dialed connection ([`super::streams`]), not connections to the agent.
//! - The server is dialled by its NodeId and the relay URLs of the join token (or `[iroh] relays`), never by
//!   addresses from anywhere else.
//! - A network change makes the daemon call [`IrohConnector::set_addresses`] and reconnect at once.
//! - [`IrohConnector::public_addrs`]: the node's public addresses as its current endpoint observes them (QUIC address
//!   discovery), kept across rebinds. The egress proxy refuses them (§9 hairpin NAT). [`IrohConnector::egress_ready`]
//!   is the egress gate apart from that list (T10a review, P2-2; T10e): judged from the **host's** IPv4, not from what
//!   this endpoint is bound to, and able to close again without withdrawing any address: when IPv4 comes up, and when
//!   the network changes ([`IrohConnector::set_addresses`] closes it until the new endpoint observes a public IPv4).
//!   The gate's own watcher asks for a rebind when it sees the default route move ([`Connector::rebind_signal`], which
//!   the daemon waits on), even when the address selection is the same, and the gate never reopens on what the endpoint
//!   bound before the move lists (T10l, R-2).
//!   [`IrohConnector::egress_report`] says why (T10l): the log and `p2pc-agent status` use it.
//!
//! Remote peers' addresses cannot be filtered with iroh 1.4: see `docs/security/residual-risks.md` (R-1).

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use iroh::endpoint::{Connection, VarInt};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey};
use p2pc_net::BindSpec;
use p2pc_proto::PROTOCOL_ALPN_AGENT;
use p2pc_proto::net::SelectedAddr;

use super::BoxFuture;
use super::streams::IrohAcceptor;
use super::transport::{BoxRead, BoxWrite, ConnectError, Connector, Link, StreamOpener};

/// The QUIC close code of a clean shutdown by the agent.
pub const CLOSE_BY_AGENT: u32 = 0;

/// The relay mode for a list of relay URLs: those relays, or none at all when the list is empty.
pub fn relay_mode(relays: &[String]) -> Result<RelayMode, ConnectError> {
    if relays.is_empty() {
        return Ok(RelayMode::Disabled);
    }
    let urls = relays
        .iter()
        .map(|r| {
            r.parse::<RelayUrl>()
                .map_err(|_| ConnectError(format!("`{r}` is not a relay URL")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RelayMode::custom(urls))
}

/// The server's address: its NodeId and relays. No direct address: those come only from the connection itself.
pub fn server_addr(node_id: &str, relays: &[String]) -> Result<EndpointAddr, ConnectError> {
    let id: EndpointId = node_id
        .parse()
        .map_err(|_| ConnectError("the server NodeId is not valid".into()))?;
    let mut addr = EndpointAddr::new(id);
    for r in relays {
        let url: RelayUrl = r
            .parse()
            .map_err(|_| ConnectError(format!("`{r}` is not a relay URL")))?;
        addr = addr.with_relay_url(url);
    }
    Ok(addr)
}

/// The longest a clean close of the endpoint may take (its connections are told, then it lets go).
pub const CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Closes `ep` cleanly within [`CLOSE_TIMEOUT`]; past it, logs and drops it (T05b review P3).
async fn close_bounded(ep: Endpoint) {
    if tokio::time::timeout(CLOSE_TIMEOUT, ep.close()).await.is_err() {
        tracing::warn!(
            timeout_s = CLOSE_TIMEOUT.as_secs(),
            "the iroh endpoint did not close in time; dropping it"
        );
    }
}

/// Opens the upload streams (§6 "Uploads") on the connection whose first stream is the control stream.
struct IrohStreams(Connection);

impl fmt::Debug for IrohStreams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohStreams").finish_non_exhaustive()
    }
}

impl StreamOpener for IrohStreams {
    fn open_bi(&self) -> BoxFuture<'_, Result<(BoxWrite, BoxRead), ConnectError>> {
        Box::pin(async move {
            let (send, recv) = self
                .0
                .open_bi()
                .await
                .map_err(|e| ConnectError(format!("cannot open a stream: {e}")))?;
            Ok((Box::new(send) as BoxWrite, Box::new(recv) as BoxRead))
        })
    }
}

/// Dials the server over iroh (production [`Connector`]).
pub struct IrohConnector {
    secret: SecretKey,
    relay_mode: RelayMode,
    server: EndpointAddr,
    bind: std::sync::Mutex<Vec<SelectedAddr>>,
    endpoint: tokio::sync::Mutex<Option<Endpoint>>,
    /// The public addresses, the egress gate, what it was decided from (T10l: what the log and `p2pc-agent status`
    /// say) and the request for a rebind: shared by the watchers of every endpoint this connector binds.
    sinks: p2pc_net::GateSinks,
    /// The task keeping them for the current endpoint.
    watcher: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// What the watcher is fed with instead of the real host and endpoint, in tests only ([`GateFeed`]).
    #[cfg(feature = "test-seams")]
    feed: Option<GateFeed>,
}

/// What a connector's gate watcher is fed with instead of the host's network monitor and the endpoint's address
/// watcher. Only tests use it: a real loopback endpoint has no relay to learn a public IPv4 from, and a test cannot
/// move the host's default route. Everything else is the real thing: the connector, its watcher, the rebind request,
/// the daemon.
///
/// **Tests only, never set in `run`:** this type, [`IrohConnector::with_gate_feed`] and the `n0-watcher` dependency
/// exist only under the `test-seams` cargo feature, which the binary does not enable (T10l review P3 4).
#[cfg(feature = "test-seams")]
#[derive(Debug)]
pub struct GateFeed {
    /// The host's network, as the watcher and the connector's network-change measurement see it.
    pub host: tokio::sync::watch::Receiver<p2pc_net::HostNet>,
    /// Each new endpoint's address list (its own sockets at first), handed to the test, which adds what the net report
    /// would learn: `watchable.set(...)`.
    pub endpoints: tokio::sync::mpsc::UnboundedSender<n0_watcher::Watchable<EndpointAddr>>,
}

impl fmt::Debug for IrohConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohConnector")
            .field("node_id", &self.secret.public().to_string())
            .field("server", &self.server.id.to_string())
            .finish_non_exhaustive()
    }
}

impl IrohConnector {
    /// A connector with our key, the relays, the server's address and the addresses to bind. The endpoint is bound
    /// at the first connection.
    #[must_use]
    pub fn new(secret: SecretKey, relay_mode: RelayMode, server: EndpointAddr, bind: Vec<SelectedAddr>) -> Self {
        Self {
            secret,
            relay_mode,
            server,
            bind: std::sync::Mutex::new(bind),
            endpoint: tokio::sync::Mutex::new(None),
            sinks: p2pc_net::GateSinks::default(),
            watcher: std::sync::Mutex::new(None),
            #[cfg(feature = "test-seams")]
            feed: None,
        }
    }

    /// Feeds the gate watcher from `feed` instead of the host and the endpoint (tests, [`GateFeed`]).
    #[cfg(feature = "test-seams")]
    #[must_use]
    pub fn with_gate_feed(mut self, feed: GateFeed) -> Self {
        self.feed = Some(feed);
        self
    }

    /// The host's network now: measured, or the test's.
    async fn host_now(&self) -> p2pc_net::HostNet {
        #[cfg(feature = "test-seams")]
        if let Some(feed) = &self.feed {
            return feed.host.borrow().clone();
        }
        p2pc_net::host_net_now().await
    }

    /// Starts the gate watcher of `ep`: on the host's real network and the endpoint's real address list, or on a test's
    /// (`GateFeed`, `test-seams` only).
    fn spawn_watcher(&self, ep: &Endpoint, ipv4_bound: bool) -> tokio::task::JoinHandle<()> {
        let sinks = self.sinks.clone();
        #[cfg(feature = "test-seams")]
        if let Some(feed) = &self.feed {
            let mut list = EndpointAddr::new(ep.id());
            for socket in ep.bound_sockets() {
                list = list.with_ip_addr(socket);
            }
            let list = n0_watcher::Watchable::new(list);
            let _ = feed.endpoints.send(list.clone());
            return tokio::spawn(p2pc_net::watch_public_addresses(
                list.watch(),
                feed.host.clone(),
                ipv4_bound,
                sinks,
            ));
        }
        let addrs = ep.watch_addr();
        tokio::spawn(async move {
            let (host_tx, host_rx) = tokio::sync::watch::channel(p2pc_net::host_net_now().await);
            tokio::select! {
                () = p2pc_net::watch_host_net(host_tx) => {}
                () = p2pc_net::watch_public_addresses(addrs, host_rx, ipv4_bound, sinks) => {}
            }
        })
    }

    /// The node's public addresses as observed by iroh: empty until the first one is known, then the last known
    /// list, across rebinds. A live source: it changes as the endpoint learns.
    #[must_use]
    pub fn public_addrs(&self) -> tokio::sync::watch::Receiver<Vec<IpAddr>> {
        self.sinks.public.subscribe()
    }

    /// The egress gate: closed until the node's public addresses are known well enough (a host with IPv4 needs a public
    /// IPv4), closed again if IPv4 comes up later or the network changes, and `NoIpv4Bound` or `BridgeNamedUplink`
    /// when the host has IPv4 but the endpoint is bound to none (it can never open). A live source, kept across
    /// rebinds.
    #[must_use]
    pub fn egress_ready(&self) -> tokio::sync::watch::Receiver<p2pc_net::EgressGate> {
        self.sinks.gate.subscribe()
    }

    /// The egress gate with what it was decided from and why (T10l): the same state as [`Self::egress_ready`]. A live
    /// source, kept across rebinds.
    #[must_use]
    pub fn egress_report(&self) -> tokio::sync::watch::Receiver<p2pc_net::GateReport> {
        self.sinks.report.subscribe()
    }

    /// Stops the watcher of the current endpoint and waits until it is gone.
    async fn stop_watcher(&self) {
        let task = self
            .watcher
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }

    /// The endpoint, binding it if needed.
    pub async fn endpoint(&self) -> Result<Endpoint, ConnectError> {
        let mut slot = self.endpoint.lock().await;
        if let Some(ep) = slot.as_ref() {
            return Ok(ep.clone());
        }
        let addrs = self
            .bind
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let spec = BindSpec {
            relay_mode: self.relay_mode.clone(),
            addrs,
            port: 0,
            // No ALPN: the agent accepts nothing (SI-12).
            alpns: Vec::new(),
        };
        let ep = p2pc_net::bind_endpoint(self.secret.clone(), &spec)
            .await
            .map_err(|e| ConnectError(e.to_string()))?;
        tracing::debug!(
            sockets = %p2pc_net::describe_addrs(ep.bound_sockets().iter()),
            "iroh endpoint bound"
        );
        // Ends with this endpoint (it holds only its address watcher). Its handle is kept: `drop_endpoint` stops it
        // before the gate is closed for a network change, so a verdict from the old network cannot reopen the gate
        // (T10f review, P2). Any watcher still stored is stopped first: there is only ever one.
        let ipv4_bound = ep.bound_sockets().iter().any(std::net::SocketAddr::is_ipv4);
        self.stop_watcher().await;
        let task = self.spawn_watcher(&ep, ipv4_bound);
        *self.watcher.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
        *slot = Some(ep.clone());
        Ok(ep)
    }

    /// Drops the current endpoint for a network change (or for good). Under the endpoint lock, so no `endpoint()` call
    /// can interleave, in this order: stop the endpoint's watcher and wait until it is gone, close the egress gate (on
    /// a host with IPv4, `net`), close the endpoint. Once the watcher is gone, no verdict computed on the old
    /// network can be written, so nothing reopens the gate until the next endpoint's watcher has observed a public
    /// IPv4.
    async fn drop_endpoint(&self, net: &p2pc_net::HostNet) {
        let mut slot = self.endpoint.lock().await;
        self.stop_watcher().await;
        // A request the dead watcher made before this point is answered by this rebind: it must not cause another one.
        // One made after it (or the network watcher's change, with its own debounce) can still cause one more rebind
        // when a route move also changes the address selection: harmless for the gate, an extra reconnect (T10l).
        tokio::select! {
            biased;
            () = self.sinks.rebind.notified() => {}
            () = std::future::ready(()) => {}
        }
        p2pc_net::close_gate_if(&self.sinks, net);
        if let Some(old) = slot.take() {
            close_bounded(old).await;
        }
    }
}

impl Connector for IrohConnector {
    fn connect(&self) -> BoxFuture<'_, Result<Link, ConnectError>> {
        Box::pin(async move {
            let ep = self.endpoint().await?;
            let conn = ep
                .connect(self.server.clone(), PROTOCOL_ALPN_AGENT)
                .await
                .map_err(|e| ConnectError(format!("cannot connect to the server: {e}")))?;
            let (send, recv) = conn
                .open_bi()
                .await
                .map_err(|e| ConnectError(format!("cannot open the control stream: {e}")))?;
            let streams = Arc::new(IrohStreams(conn.clone()));
            let incoming = Arc::new(IrohAcceptor::new(conn.clone()));
            Ok(Link::new(
                Box::new(send),
                Box::new(recv),
                Box::new(move || conn.close(VarInt::from_u32(CLOSE_BY_AGENT), b"")),
            )
            .with_streams(streams)
            .with_incoming(incoming))
        })
    }

    fn set_addresses(&self, addrs: Vec<SelectedAddr>) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            *self.bind.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = addrs;
            // The network changed: what was learned about the old one proves nothing about the new one. The old
            // endpoint's watcher is stopped, then the gate closes now, not when the next endpoint is bound (T10f).
            let net = self.host_now().await;
            self.drop_endpoint(&net).await;
        })
    }

    fn rebind_signal(&self) -> Arc<tokio::sync::Notify> {
        self.sinks.rebind.clone()
    }

    fn renew_endpoint(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            // The default route moved (the gate watcher saw it): same addresses, a new endpoint, whose first net report
            // is the only thing that reopens the gate.
            tracing::info!("re-binding the iroh endpoint: the default route moved");
            let net = self.host_now().await;
            self.drop_endpoint(&net).await;
        })
    }

    fn shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            // The gate is left as it is: the process is going away. Only the watcher must not outlive the endpoint.
            let mut slot = self.endpoint.lock().await;
            self.stop_watcher().await;
            if let Some(ep) = slot.take() {
                close_bounded(ep).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use p2pc_net::EgressGate;
    use p2pc_proto::net::IfAddr;

    use super::*;

    fn loopback() -> Vec<SelectedAddr> {
        vec![SelectedAddr::new(
            IfAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8),
            "lo",
        )]
    }

    /// The host's network for a rebind: with or without IPv4.
    fn net(ipv4: bool) -> p2pc_net::HostNet {
        p2pc_net::HostNet {
            ipv4,
            default_route: Some("wlan0".into()),
            bridge_named_uplink: false,
        }
    }

    fn connector() -> IrohConnector {
        let server = EndpointAddr::new(SecretKey::generate().public());
        IrohConnector::new(SecretKey::generate(), RelayMode::Disabled, server, loopback())
    }

    /// T10f review, P2: `endpoint()` keeps its watcher's handle, and a rebind stops that watcher before it closes the
    /// gate. A watcher left running keeps its tracker from the old network, so any host event that keeps the route
    /// would reopen the gate that was just closed.
    #[tokio::test]
    async fn a_rebind_stops_the_old_watcher_and_the_gate_stays_closed() {
        let c = connector();
        let _ep = c.endpoint().await.unwrap();
        let old = c
            .watcher
            .lock()
            .unwrap()
            .as_ref()
            .expect("endpoint() stores its watcher")
            .abort_handle();
        assert!(!old.is_finished(), "the watcher runs with its endpoint");
        // Network A was ready.
        c.sinks.gate.send_replace(EgressGate::Open);
        let gate = c.egress_ready();

        c.drop_endpoint(&net(true)).await;
        assert!(old.is_finished(), "the old watcher is gone before the rebind returns");
        assert_eq!(*gate.borrow(), EgressGate::Closed);
        assert!(c.watcher.lock().unwrap().is_none());
        // Nothing of the old network can write a verdict any more.
        tokio::task::yield_now().await;
        assert_eq!(*gate.borrow(), EgressGate::Closed, "no stale verdict reopened the gate");

        // The next endpoint has one watcher of its own, and the old one is not resurrected.
        c.set_addresses(loopback()).await;
        let _ep = c.endpoint().await.unwrap();
        let new = c
            .watcher
            .lock()
            .unwrap()
            .as_ref()
            .expect("a new watcher")
            .abort_handle();
        assert!(!new.is_finished());
        // A second endpoint() on the same endpoint does not spawn another one.
        let _ep = c.endpoint().await.unwrap();
        assert!(!new.is_finished());
        // Shutdown stops it too.
        c.shutdown().await;
        assert!(new.is_finished());
    }

    /// T10l: the connector's report follows the gate across a rebind, so the log and `status` can say why.
    #[tokio::test]
    async fn a_rebind_tells_the_report_the_network_changed() {
        let c = connector();
        let _ep = c.endpoint().await.unwrap();
        c.sinks.gate.send_replace(EgressGate::Open);
        c.sinks.report.send_replace(p2pc_net::GateReport {
            state: EgressGate::Open,
            inputs: p2pc_net::GateInputs {
                host_ipv4: true,
                public_ipv4_here: true,
                public_ipv4_known: true,
                ..Default::default()
            },
        });
        let report = c.egress_report();
        c.drop_endpoint(&net(true)).await;
        let r = report.borrow().clone();
        assert_eq!(r.state, EgressGate::Closed);
        assert!(r.line().starts_with("closed: the network changed"), "{}", r.line());
    }

    /// A host without IPv4 keeps its gate across a rebind (it has no IPv4 hairpin to guard), and the watcher is stopped
    /// all the same.
    #[tokio::test]
    async fn a_rebind_on_a_host_without_ipv4_keeps_the_gate() {
        let c = connector();
        let _ep = c.endpoint().await.unwrap();
        let old = c.watcher.lock().unwrap().as_ref().unwrap().abort_handle();
        c.sinks.gate.send_replace(EgressGate::Open);
        c.drop_endpoint(&net(false)).await;
        assert!(old.is_finished());
        assert_eq!(*c.egress_ready().borrow(), EgressGate::Open);
    }
}
