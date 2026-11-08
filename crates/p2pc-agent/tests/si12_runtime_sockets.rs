// SPDX-License-Identifier: Apache-2.0

//! SI-12, the runtime half (spec §13, hard rule 4): while `run` is connected, enumerate the sockets of this process
//! (the agent's connection loop and a fake server, nothing else: this file is its own test binary with one test).
//!
//! - No TCP socket is listening, and no TCP socket exists at all (relays are disabled here).
//! - Every UDP socket is one of the two iroh endpoints' sockets, and the agent's are bound to the address its
//!   `direct_addresses` policy selected (loopback here), never to `0.0.0.0` or `[::]`.
//! - No unix socket is listening.
//!
//! Linux only: it reads `/proc/self/fd` and `/proc/net/*`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use iroh::{EndpointAddr, RelayMode, SecretKey};
use p2pc_agent::connection::BoxFuture;
use p2pc_agent::connection::daemon::Daemon;
use p2pc_agent::connection::endpoint::IrohConnector;
use p2pc_agent::connection::lease::{NoLeases, NotReady};
use p2pc_agent::connection::session::{INVENTORY_INTERVAL, InventorySource, MAX_PENDING_DECISIONS, Shared};
use p2pc_agent::connection::watchdog::Watchdog;
use p2pc_net::{BindSpec, bind_endpoint};
use p2pc_proto::PROTOCOL_ALPN_AGENT;
use p2pc_proto::api::Inventory;
use p2pc_proto::ids::{AccountId, NodeId};
use p2pc_proto::net::{IfAddr, SelectedAddr};
use p2pc_proto::protocol::{Load, MAX_FRAME_LEN, read_frame, write_frame};
use serde_json::{Value, json};
use tokio::sync::{Semaphore, mpsc, watch};

const WAIT: Duration = Duration::from_secs(20);

#[derive(Debug)]
struct Inv;

impl InventorySource for Inv {
    fn detect(&self) -> BoxFuture<'_, Result<Inventory, String>> {
        Box::pin(async {
            Ok(serde_json::from_value(json!({
                "hostname": "node-1", "platform": "linux", "cpu": {"model": "Example CPU", "cores": 4},
                "memory_mb": 8192, "os": "Ubuntu 24.04", "arch": "x86_64", "gpu_status": {"status": "not_found"},
                "offered": {"cpu": 3.0, "memory_mb": 6144, "gpu": 0}, "agent_version": "0.1.0",
            }))
            .unwrap())
        })
    }
}

#[derive(Debug)]
struct NoLoad;

impl p2pc_agent::connection::load::LoadSource for NoLoad {
    fn sample(&self) -> BoxFuture<'_, Load> {
        Box::pin(async { serde_json::from_value(json!({"cpu_pct": 0, "mem_used_mb": 0})).unwrap() })
    }
}

/// The inodes of this process's sockets.
fn my_socket_inodes() -> BTreeSet<u64> {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter_map(|target| {
            let t = target.to_string_lossy().into_owned();
            t.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
        })
        .collect()
}

/// `/proc/net/{tcp,udp}{,6}`: (local address, state, inode) of each socket.
fn inet_table(name: &str) -> Vec<(SocketAddr, String, u64)> {
    let Ok(text) = std::fs::read_to_string(format!("/proc/net/{name}")) else {
        return Vec::new();
    };
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (ip_hex, port_hex) = f.get(1)?.split_once(':')?;
            let port = u16::from_str_radix(port_hex, 16).ok()?;
            let ip = parse_proc_ip(ip_hex)?;
            Some((
                SocketAddr::new(ip, port),
                f.get(3)?.to_string(),
                f.get(9)?.parse().ok()?,
            ))
        })
        .collect()
}

/// `/proc/net` writes addresses as 32-bit words in host (little-endian) order.
fn parse_proc_ip(hex: &str) -> Option<IpAddr> {
    let words: Vec<u32> = (0..hex.len() / 8)
        .map(|i| u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).map(u32::swap_bytes))
        .collect::<Result<_, _>>()
        .ok()?;
    match words.as_slice() {
        [a] => Some(IpAddr::V4(Ipv4Addr::from(*a))),
        [a, b, c, d] => {
            let mut bytes = [0u8; 16];
            for (i, w) in [a, b, c, d].iter().enumerate() {
                bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Listening unix sockets (flag `__SO_ACCEPTCON`, 0x10000) of this process.
fn listening_unix(mine: &BTreeSet<u64>) -> Vec<String> {
    let text = std::fs::read_to_string("/proc/net/unix").unwrap_or_default();
    text.lines()
        .skip(1)
        .filter(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let flags = f.get(3).and_then(|x| u32::from_str_radix(x, 16).ok()).unwrap_or(0);
            let inode: u64 = f.get(6).and_then(|x| x.parse().ok()).unwrap_or(0);
            mine.contains(&inode) && flags & 0x10000 != 0
        })
        .map(String::from)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn si12_runtime_the_running_agent_opens_only_its_iroh_udp_sockets() {
    let loopback = vec![SelectedAddr::new(IfAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8), "lo")];
    // The fake server.
    let spec = BindSpec {
        relay_mode: RelayMode::Disabled,
        addrs: loopback.clone(),
        port: 0,
        alpns: vec![PROTOCOL_ALPN_AGENT.to_vec()],
    };
    let server = bind_endpoint(SecretKey::generate(), &spec).await.unwrap();
    let server_addr = EndpointAddr::new(server.id()).with_ip_addr(server.bound_sockets()[0]);
    // The agent's connection loop, as `run` builds it.
    let owner = AccountId::generate();
    let ttl = Duration::from_secs(45);
    let connector = Arc::new(IrohConnector::new(
        SecretKey::generate(),
        RelayMode::Disabled,
        server_addr,
        loopback,
    ));
    let daemon = Daemon {
        shared: Shared {
            owner,
            agent_lease_ttl: ttl,
            watchdog: Watchdog::new(ttl),
            supervisor: Arc::new(NoLeases),
            handler: Arc::new(NotReady),
            inventory: Arc::new(Inv),
            load: Arc::new(NoLoad),
            inventory_interval: INVENTORY_INTERVAL,
            decisions: Arc::new(Semaphore::new(MAX_PENDING_DECISIONS)),
            uplink: p2pc_agent::connection::Uplink::new(),
        },
        connector: connector.clone(),
        backoff_seed: 1,
        state_file: None,
        server_node_id: server.id().to_string(),
        agent_node_id: NodeId::generate().to_string(),
    };
    let (stop, stop_rx) = watch::channel(false);
    let (_net, net_rx) = mpsc::channel(1);
    let running = tokio::spawn(daemon.run(stop_rx, net_rx));

    // Connected and welcomed, with a heartbeat through.
    let (conn, mut w, mut r) = tokio::time::timeout(WAIT, async {
        let conn = server.accept().await.unwrap().await.unwrap();
        let (w, r) = conn.accept_bi().await.unwrap();
        (conn, w, r)
    })
    .await
    .unwrap();
    let hello: Value = read_frame(&mut r, MAX_FRAME_LEN).await.unwrap().unwrap();
    assert_eq!(hello["type"], "hello");
    let welcome = json!({"type": "welcome", "server_version": "0.1.0", "node_id": NodeId::generate(),
        "account_id": owner, "heartbeat_interval_s": 1, "lease_ttl_s": 60});
    write_frame(&mut w, &welcome).await.unwrap();
    let beat: Value = tokio::time::timeout(WAIT, read_frame(&mut r, MAX_FRAME_LEN))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(beat["type"], "heartbeat");

    // Enumerate.
    let mine = my_socket_inodes();
    let agent_sockets: BTreeSet<SocketAddr> = connector
        .endpoint()
        .await
        .unwrap()
        .bound_sockets()
        .into_iter()
        .collect();
    let server_sockets: BTreeSet<SocketAddr> = server.bound_sockets().into_iter().collect();
    assert!(!agent_sockets.is_empty());
    for s in &agent_sockets {
        assert_eq!(
            s.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "bound only where the policy says: {s}"
        );
    }
    let tcp: Vec<_> = ["tcp", "tcp6"]
        .iter()
        .flat_map(|t| inet_table(t))
        .filter(|(_, _, inode)| mine.contains(inode))
        .collect();
    assert!(
        tcp.iter().all(|(_, state, _)| state != "0A"),
        "a TCP socket is listening: {tcp:?}"
    );
    assert!(tcp.is_empty(), "no TCP socket at all with relays disabled: {tcp:?}");
    let udp: Vec<SocketAddr> = ["udp", "udp6"]
        .iter()
        .flat_map(|t| inet_table(t))
        .filter(|(_, _, inode)| mine.contains(inode))
        .map(|(addr, _, _)| addr)
        .collect();
    assert!(!udp.is_empty(), "the enumeration found the iroh sockets");
    for addr in &udp {
        assert!(
            agent_sockets.contains(addr) || server_sockets.contains(addr),
            "a UDP socket that is not an iroh endpoint's: {addr} (agent {agent_sockets:?}, server {server_sockets:?})"
        );
        assert!(!addr.ip().is_unspecified(), "a wildcard UDP socket: {addr}");
    }
    for s in &agent_sockets {
        assert!(udp.contains(s), "the agent's socket {s} was enumerated");
    }
    assert_eq!(listening_unix(&mine), Vec::<String>::new());

    stop.send(true).unwrap();
    tokio::time::timeout(WAIT, running).await.unwrap().unwrap();
    drop(conn);
    server.close().await;
}

#[test]
fn proc_addresses_parse() {
    assert_eq!(parse_proc_ip("0100007F"), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert_eq!(
        parse_proc_ip("00000000000000000000000001000000"),
        Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
    );
}
