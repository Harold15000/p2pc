// SPDX-License-Identifier: Apache-2.0

//! [`ProxyEgress`]: T09's per-job egress proxy ([`crate::egress`]) behind the driver's [`Egress`] seam.
//!
//! The driver asks for the proxy only when `egress.allow` is non-empty, with the socket at `<job>/p2pc/egress.sock`.
//! The socket is created 0600 and owned by the agent (`SocketOptions { owner: None }`): the driver mounts `p2pc/`
//! with `:U`, so Podman hands it to the container's mapped root (spec §9 "Socket permissions"). Dropping the
//! returned [`EgressHandle`] stops the proxy and removes the socket.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use p2pc_net::EgressGate;
use tokio::sync::watch;

use super::{Egress, EgressRequest};
use crate::egress::{EgressHandle, EgressProxy, Policy, SocketOptions};

type PolicyFn = dyn Fn(Vec<String>, watch::Receiver<Vec<IpAddr>>, watch::Receiver<EgressGate>) -> Policy + Send + Sync;

/// The real egress proxy.
#[derive(Clone)]
pub struct ProxyEgress {
    policy: Arc<PolicyFn>,
}

impl fmt::Debug for ProxyEgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyEgress")
    }
}

impl Default for ProxyEgress {
    fn default() -> Self {
        Self::system()
    }
}

impl ProxyEgress {
    /// [`Policy::system`]: the system resolver, interfaces and TCP, ports `{80, 443}`, default limits.
    #[must_use]
    pub fn system() -> Self {
        Self::with_policy(Policy::system)
    }

    /// A proxy whose policy `make` builds from the job's allowlist, the live public addresses and the live egress gate
    /// (tests inject fake resolvers and connectors this way).
    pub fn with_policy(
        make: impl Fn(Vec<String>, watch::Receiver<Vec<IpAddr>>, watch::Receiver<EgressGate>) -> Policy
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self { policy: Arc::new(make) }
    }
}

impl Egress for ProxyEgress {
    type Session = EgressHandle;

    fn start(&self, request: &EgressRequest) -> Result<EgressHandle, String> {
        let policy = (self.policy)(
            request.allow.clone(),
            request.public_addrs.clone(),
            request.egress_ready.clone(),
        );
        EgressProxy::start_with(&request.socket_path, policy, SocketOptions { owner: None }).map_err(|e| e.to_string())
    }
}

/// The reason [`KnownPublicAddrs`] gives while the egress gate is closed.
pub const PUBLIC_ADDRS_UNKNOWN: &str =
    "the node's public addresses are not known yet, so the egress proxy could not refuse hairpin NAT (spec §9)";

/// The reason [`KnownPublicAddrs`] gives when the gate cannot open by waiting: [`p2pc_net::IPV4_NOT_BOUND`] (T10f).
pub const PUBLIC_IPV4_NEVER_KNOWN: &str = p2pc_net::IPV4_NOT_BOUND;

/// The reason [`KnownPublicAddrs`] gives when the node's uplink is named like a container bridge, so its IPv4 is never
/// bound: [`p2pc_net::IPV4_UPLINK_NAMED_LIKE_BRIDGE`] (T10h).
pub const UPLINK_NAMED_LIKE_BRIDGE: &str = p2pc_net::IPV4_UPLINK_NAMED_LIKE_BRIDGE;

/// An egress provider that starts a proxy only while the egress gate is open (T10a review, P2-2; T10e).
///
/// The proxy refuses the node's own public addresses, so a job cannot reach a port-forwarded LAN service through the
/// router (hairpin NAT, §9). Until the node knows enough of them (`p2pc_net::PublicAddrTracker`: on a host with IPv4,
/// a public IPv4), an egress job would run without that protection; so it fails instead, with
/// `error = "egress_unavailable"`. The gate is `request.egress_ready`, not "the address list is not empty": it can
/// close again without withdrawing addresses, and proxies already running keep refusing the ones they were given.
/// Jobs without egress are unaffected.
#[derive(Debug, Clone)]
pub struct KnownPublicAddrs<X>(pub X);

impl<X: Egress> Egress for KnownPublicAddrs<X> {
    type Session = X::Session;

    fn start(&self, request: &EgressRequest) -> Result<X::Session, String> {
        match *request.egress_ready.borrow() {
            EgressGate::Open => {}
            EgressGate::Closed => return Err(PUBLIC_ADDRS_UNKNOWN.into()),
            EgressGate::NoIpv4Bound => return Err(PUBLIC_IPV4_NEVER_KNOWN.into()),
            EgressGate::BridgeNamedUplink => return Err(UPLINK_NAMED_LIKE_BRIDGE.into()),
        }
        self.0.start(request)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use super::*;

    fn request(dir: &std::path::Path) -> EgressRequest {
        EgressRequest {
            socket_path: dir.join("egress.sock"),
            allow: vec!["pypi.org".into()],
            public_addrs: watch::channel(vec!["198.51.100.7".parse().unwrap()]).1,
            egress_ready: watch::channel(EgressGate::Open).1,
        }
    }

    /// Each policy the adapter asked for: the allowlist and the public addresses at that moment.
    type Seen = Arc<Mutex<Vec<(Vec<String>, Vec<IpAddr>)>>>;

    /// The adapter hands T09 the job's allowlist and the live public addresses, unchanged.
    fn recording() -> (ProxyEgress, Seen) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let egress = ProxyEgress::with_policy(move |allow, addrs, ready| {
            log.lock().unwrap().push((allow.clone(), addrs.borrow().clone()));
            Policy::system(allow, addrs, ready)
        });
        (egress, seen)
    }

    /// P2-2, T10e: no egress proxy until the gate says it is ready; once it is, the inner provider starts. Known
    /// public addresses alone do not open it (an IPv4 host knowing only its IPv6 address).
    #[tokio::test]
    async fn egress_waits_for_the_gate() {
        let (egress, seen) = recording();
        let gated = KnownPublicAddrs(egress);
        let dir = tempfile::tempdir().unwrap();
        let (_addrs_tx, addrs_rx) = watch::channel(vec!["2001:db8::5".parse::<IpAddr>().unwrap()]);
        let (ready_tx, ready_rx) = watch::channel(EgressGate::Closed);
        let mut req = request(dir.path());
        req.public_addrs = addrs_rx;
        req.egress_ready = ready_rx;
        assert_eq!(gated.start(&req).err().as_deref(), Some(PUBLIC_ADDRS_UNKNOWN));
        assert!(seen.lock().unwrap().is_empty(), "the proxy was never asked");
        ready_tx.send_replace(EgressGate::Open);
        // Past the gate: the inner provider runs (here it refuses the lax directory, which proves it ran).
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(gated.start(&req).unwrap_err().contains("unsafe socket directory"));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    /// T10e, item 2: the gate opened, then closed again (IPv4 came up): new egress jobs are refused, while the proxy
    /// already running keeps the addresses it was given (the list is a live source nobody withdraws from).
    #[tokio::test]
    async fn the_gate_closes_again_and_running_proxies_keep_their_addresses() {
        let (egress, seen) = recording();
        let gated = KnownPublicAddrs(egress);
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let v6: IpAddr = "2001:db8::5".parse().unwrap();
        let (addrs_tx, addrs_rx) = watch::channel(vec![v6]);
        let (ready_tx, ready_rx) = watch::channel(EgressGate::Open);
        let mut req = request(dir.path());
        req.public_addrs = addrs_rx;
        req.egress_ready = ready_rx;
        assert!(
            gated.start(&req).unwrap_err().contains("unsafe socket directory"),
            "open: the inner ran"
        );
        // IPv4 came up: closed, the list untouched.
        ready_tx.send_replace(EgressGate::Closed);
        assert_eq!(gated.start(&req).err().as_deref(), Some(PUBLIC_ADDRS_UNKNOWN));
        assert_eq!(*req.public_addrs.borrow(), [v6], "the deny list is not withdrawn");
        assert_eq!(seen.lock().unwrap().len(), 1, "the closed gate never reached the proxy");
        // The public IPv4 is learned: open again, both addresses denied.
        let v4: IpAddr = "198.51.100.7".parse().unwrap();
        addrs_tx.send_replace(vec![v4, v6]);
        ready_tx.send_replace(EgressGate::Open);
        assert!(gated.start(&req).unwrap_err().contains("unsafe socket directory"));
        assert_eq!(*req.public_addrs.borrow(), [v4, v6]);
    }

    /// T10f, item 3: a gate that cannot open by waiting (the host has IPv4, iroh has none bound) says so, and does not
    /// say "not known yet".
    #[tokio::test]
    async fn a_gate_that_can_never_open_says_how_to_fix_it() {
        let (egress, seen) = recording();
        let gated = KnownPublicAddrs(egress);
        let dir = tempfile::tempdir().unwrap();
        let mut req = request(dir.path());
        req.egress_ready = watch::channel(EgressGate::NoIpv4Bound).1;
        let e = gated.start(&req).unwrap_err();
        assert!(!e.contains("not known yet"), "{e}");
        assert!(
            e.contains("iroh") && e.contains("IPv4") && e.contains("direct_addresses"),
            "{e}"
        );
        assert!(seen.lock().unwrap().is_empty(), "the proxy was never asked");
    }

    /// T10h, item 1: an uplink named like a bridge is never bound, so `direct_addresses` is no fix: the error says to
    /// rename the interface.
    #[tokio::test]
    async fn an_uplink_named_like_a_bridge_says_to_rename_it() {
        let (egress, seen) = recording();
        let gated = KnownPublicAddrs(egress);
        let dir = tempfile::tempdir().unwrap();
        let mut req = request(dir.path());
        req.egress_ready = watch::channel(EgressGate::BridgeNamedUplink).1;
        let e = gated.start(&req).unwrap_err();
        assert!(!e.contains("not known yet"), "{e}");
        assert!(e.contains("default-route interface") && e.contains("rename"), "{e}");
        assert!(e.contains("does not help"), "{e}");
        assert!(seen.lock().unwrap().is_empty(), "the proxy was never asked");
    }

    #[tokio::test]
    async fn refusals_from_the_proxy_become_errors() {
        let (egress, seen) = recording();
        // Something already at the socket path: never replaced.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("egress.sock"), b"").unwrap();
        let e = egress.start(&request(dir.path())).unwrap_err();
        assert!(e.contains("already exists"), "{e}");
        // A directory others could write to: refused before any socket exists.
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = egress.start(&request(dir.path())).unwrap_err();
        assert!(e.contains("unsafe socket directory"), "{e}");
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen[0],
            (
                vec!["pypi.org".to_string()],
                vec!["198.51.100.7".parse::<IpAddr>().unwrap()]
            )
        );
    }

    /// End to end through the driver's seam: a 0600 socket in the job's `p2pc/`, removed when the session drops.
    #[tokio::test]
    async fn creates_the_0600_socket_and_removes_it_on_drop() {
        if std::os::unix::net::UnixListener::bind(PathBuf::from("/nonexistent.invalid/probe"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
        {
            eprintln!("SKIPPED: this environment forbids unix sockets");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let (egress, _) = recording();
        let req = request(dir.path());
        let session = egress.start(&req).unwrap();
        let meta = std::fs::symlink_metadata(&req.socket_path).unwrap();
        assert!(std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type()));
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        session.shutdown().await;
        assert!(std::fs::symlink_metadata(&req.socket_path).is_err());
    }
}
