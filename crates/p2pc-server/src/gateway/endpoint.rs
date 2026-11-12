// SPDX-License-Identifier: AGPL-3.0-only

//! The server's iroh endpoint (spec §10).
//!
//! The §10 plumbing (no port mapping, no address lookup, one socket per selected address, the interface snapshot
//! and the debounced network watcher) is `p2pc-net`'s, shared with the agent (T05b review, P2-3). This module adds
//! what is the server's own: its identity and relays, the ALPNs it accepts ([`accepted_alpns`]), and the options read
//! from `server.toml`.
//!
//! - **What it accepts** (hard rule 4, H2 §10.5): `p2pc/agent/1`, `p2pc/http/1` and `p2pc/device/1` always, each
//!   behind a join token, an API key or a paired NodeId, and `p2pc/pair/1` only while a pairing ticket is open. The
//!   list is the TLS ALPN list, so a connection that offers anything else fails its handshake before any message.
//! - The public address that the relay observes (QUIC address discovery) is still advertised: it is the
//!   default route's own address as seen from the internet.
//! - **Network changes** (T05 review, carry-over 6): when [`p2pc_net::watch_network`] reports a new selection (the
//!   server started before its network was up, a DHCP change), the gateway binds a new endpoint on the new addresses
//!   and closes the old one ([`super::Gateway`]); agents reconnect within seconds.

use std::fmt;
use std::net::IpAddr;

use iroh::{Endpoint, EndpointId, RelayMode, RelayUrl, SecretKey};
use p2pc_net::BindSpec;
use p2pc_proto::api::ServerInfo;
use p2pc_proto::auth::ServerAddress;
use p2pc_proto::net::{DirectAddresses, IfAddr, SelectedAddr, select_addresses};
use p2pc_proto::{PROTOCOL_ALPN_AGENT, PROTOCOL_ALPN_DEVICE, PROTOCOL_ALPN_HTTP, PROTOCOL_ALPN_PAIR};
use url::Url;

pub use p2pc_net::BindError as EndpointError;
pub use p2pc_net::{host_interfaces, interfaces_from};

use crate::config::Config;

/// The server's iroh identity and relays: what join tokens, the server address and `GET /v1/server` describe.
#[derive(Clone)]
pub struct ServerIdentity {
    secret_key: SecretKey,
    relays: Vec<Url>,
}

impl fmt::Debug for ServerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerIdentity")
            .field("node_id", &self.node_id().to_string())
            .field("relays", &self.relays.iter().map(Url::as_str).collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// The relay URLs for `iroh.relays`: the configured ones, or n0's public relays when the list is empty.
#[must_use]
pub fn effective_relays(configured: &[String]) -> Vec<Url> {
    if configured.is_empty() {
        let urls: Vec<RelayUrl> = RelayMode::Default.relay_map().urls();
        urls.iter().map(|u| Url::clone(u)).collect()
    } else {
        configured.iter().filter_map(|r| Url::parse(r).ok()).collect()
    }
}

impl ServerIdentity {
    /// The identity for a key and the configured relays (empty means n0's public relays).
    #[must_use]
    pub fn new(secret_key: SecretKey, configured_relays: &[String]) -> Self {
        Self {
            secret_key,
            relays: effective_relays(configured_relays),
        }
    }

    /// The secret key, for binding the endpoint. Never log it.
    #[must_use]
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// The server's NodeId.
    #[must_use]
    pub fn node_id(&self) -> EndpointId {
        self.secret_key.public()
    }

    /// The relay URLs (the hints of join tokens and of the server address).
    #[must_use]
    pub fn relays(&self) -> &[Url] {
        &self.relays
    }

    /// The relay mode for the endpoint.
    #[must_use]
    pub fn relay_mode(&self) -> RelayMode {
        RelayMode::custom(self.relays.iter().cloned().map(RelayUrl::from))
    }

    /// The server address `p2pc_srv_…` (§10).
    #[must_use]
    pub fn address(&self) -> ServerAddress {
        ServerAddress::new(self.node_id().to_string(), self.relays.clone())
    }

    /// The endpoint's part of `GET /v1/server`: address and version, with the H1 defaults for the rest
    /// ([`crate::nodes_api::server_info`] fills the H2 fields).
    #[must_use]
    pub fn info(&self) -> ServerInfo {
        ServerInfo::new(self.address(), env!("CARGO_PKG_VERSION"))
    }
}

/// How to bind the endpoint: relays and the IP sockets.
#[derive(Debug, Clone)]
pub struct EndpointOptions {
    /// Relay servers. `RelayMode::Disabled` in tests.
    pub relay_mode: RelayMode,
    /// One IP socket per address (port 0: the OS picks). Empty means relay only.
    pub bind: Vec<SelectedAddr>,
    /// Port of every IP socket (0: the OS picks one per socket).
    pub port: u16,
    /// The `direct_addresses` policy to apply again when the network changes; `None` never re-selects (tests, and
    /// `"none"`, which selects nothing anyway).
    pub reselect: Option<DirectAddresses>,
}

impl EndpointOptions {
    /// The options `server.toml` asks for: the configured relays, and the addresses `direct_addresses` selects from
    /// the current interfaces.
    pub async fn from_config(config: &Config, identity: &ServerIdentity) -> Self {
        let bind = match config.iroh.direct_addresses {
            DirectAddresses::None => Vec::new(),
            _ => {
                let (interfaces, default_route) = host_interfaces().await;
                let selected = select_addresses(&interfaces, default_route.as_deref(), &config.iroh.direct_addresses);
                if selected.is_empty() {
                    tracing::warn!(
                        policy = ?config.iroh.direct_addresses,
                        default_route = ?default_route,
                        "iroh.direct_addresses selected no local address: the endpoint is relay-only until the \
                         network changes"
                    );
                }
                selected
            }
        };
        let reselect =
            (config.iroh.direct_addresses != DirectAddresses::None).then(|| config.iroh.direct_addresses.clone());
        Self {
            relay_mode: identity.relay_mode(),
            bind,
            port: 0,
            reselect,
        }
    }

    /// Loopback only, no relays: for in-process tests.
    #[must_use]
    pub fn loopback_without_relays() -> Self {
        Self {
            relay_mode: RelayMode::Disabled,
            bind: vec![SelectedAddr::new(
                IfAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8),
                "lo",
            )],
            port: 0,
            reselect: None,
        }
    }
}

/// The ALPNs the hub's endpoint accepts (H2 §10.5), and nothing else: `p2pc/agent/1`, `p2pc/http/1` and
/// `p2pc/device/1`, plus `p2pc/pair/1` only when `pair_open` (a pairing ticket is open). Without it a `p2pc/pair/1`
/// connection fails its TLS handshake before any message.
#[must_use]
pub fn accepted_alpns(pair_open: bool) -> Vec<Vec<u8>> {
    let mut alpns = vec![
        PROTOCOL_ALPN_AGENT.to_vec(),
        PROTOCOL_ALPN_HTTP.to_vec(),
        PROTOCOL_ALPN_DEVICE.to_vec(),
    ];
    if pair_open {
        alpns.push(PROTOCOL_ALPN_PAIR.to_vec());
    }
    alpns
}

/// Binds the server's endpoint: `p2pc_net::bind_endpoint` with the ALPNs the server always accepts
/// ([`accepted_alpns`] with no pairing ticket open) and exactly the IP sockets of `options`. The gateway adds
/// `p2pc/pair/1` while a ticket is open (`Endpoint::set_alpns`).
pub async fn bind(secret_key: SecretKey, options: &EndpointOptions) -> Result<Endpoint, EndpointError> {
    let spec = BindSpec {
        relay_mode: options.relay_mode.clone(),
        addrs: options.bind.clone(),
        port: options.port,
        alpns: accepted_alpns(false),
    };
    p2pc_net::bind_endpoint(secret_key, &spec).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_relays_mean_the_n0_defaults_and_others_are_kept() {
        let defaults = effective_relays(&[]);
        assert!(!defaults.is_empty());
        assert!(defaults.iter().all(|u| u.scheme() == "https"));
        let custom = effective_relays(&["https://relay.example.invalid/".to_string()]);
        assert_eq!(custom, vec![Url::parse("https://relay.example.invalid/").unwrap()]);
    }

    #[test]
    fn identity_info_and_address_agree() {
        let id = ServerIdentity::new(SecretKey::generate(), &["https://relay.example.invalid/".to_string()]);
        let info = id.info();
        assert_eq!(info.node_id, id.node_id().to_string());
        assert_eq!(info.node_id.len(), 64);
        assert_eq!(info.relays, ["https://relay.example.invalid/"]);
        assert_eq!(
            ServerAddress::parse(&info.address.encode().unwrap()).unwrap(),
            id.address()
        );
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
        // Debug never shows the secret key.
        let hex = data_encoding::HEXLOWER.encode(&id.secret_key().to_bytes());
        assert!(!format!("{id:?}").contains(&hex));
    }

    /// Hard rule 4, H2 §10.5: the accepted ALPNs are exactly the listed ones, and `p2pc/pair/1` only with a ticket
    /// open. `p2pc/invite/1` is never the hub's.
    #[test]
    fn the_accepted_alpns_are_exactly_the_ones_of_10_5() {
        let closed = accepted_alpns(false);
        assert_eq!(
            closed,
            [&b"p2pc/agent/1"[..], b"p2pc/http/1", b"p2pc/device/1"].map(<[u8]>::to_vec)
        );
        let open = accepted_alpns(true);
        assert_eq!(open[..3], closed[..]);
        assert_eq!(open[3..], [b"p2pc/pair/1".to_vec()]);
        assert!(!open.contains(&p2pc_proto::PROTOCOL_ALPN_INVITE.to_vec()));
    }

    #[tokio::test]
    async fn an_endpoint_with_nothing_to_reach_it_by_is_refused() {
        let opts = EndpointOptions {
            relay_mode: RelayMode::Disabled,
            bind: vec![],
            port: 0,
            reselect: None,
        };
        assert!(matches!(
            bind(SecretKey::generate(), &opts).await,
            Err(EndpointError::Unreachable)
        ));
    }

    /// Bound to loopback only, the endpoint advertises exactly that address: no other interface, no bridge.
    #[tokio::test]
    async fn a_loopback_endpoint_advertises_only_loopback() {
        let ep = bind(SecretKey::generate(), &EndpointOptions::loopback_without_relays())
            .await
            .unwrap();
        let bound = ep.bound_sockets();
        assert!(!bound.is_empty());
        assert!(bound.iter().all(|a| a.ip().is_loopback()), "{bound:?}");
        // Wait until iroh has gathered its direct addresses, so the check below is not vacuous.
        let mut watch = ep.watch_addr();
        let addr = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let addr = iroh::Watcher::get(&mut watch);
                if addr.ip_addrs().next().is_some() {
                    return addr;
                }
                let _ = iroh::Watcher::updated(&mut watch).await;
            }
        })
        .await
        .unwrap();
        assert!(addr.ip_addrs().all(|a| a.ip().is_loopback()), "{addr:?}");
        assert_eq!(addr.relay_urls().count(), 0);
        ep.close().await;
    }
}
