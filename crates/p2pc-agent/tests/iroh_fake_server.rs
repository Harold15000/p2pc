// SPDX-License-Identifier: Apache-2.0

//! `join` and `run` over real iroh, against a fake server inside the test: an in-process endpoint on loopback, relays
//! disabled, speaking the `p2pc-proto` codec. No dependency on `p2pc-server` (it is AGPL-3.0; the end-to-end tests
//! are T15's), no relay, no internet.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use p2pc_agent::config::{Config, ConfigSource, Env};
use p2pc_agent::connection::daemon::{Daemon, DaemonExit};
use p2pc_agent::connection::endpoint::IrohConnector;
use p2pc_agent::connection::join::{JoinError, enroll};
use p2pc_agent::connection::lease::{LeaseSupervisor, NotReady};
use p2pc_agent::connection::session::{INVENTORY_INTERVAL, InventorySource, MAX_PENDING_DECISIONS, Shared};
use p2pc_agent::connection::watchdog::Watchdog;
use p2pc_agent::connection::{BoxFuture, exit};
use p2pc_net::{BindSpec, bind_endpoint};
use p2pc_proto::PROTOCOL_ALPN_AGENT;
use p2pc_proto::api::Inventory;
use p2pc_proto::auth::JoinToken;
use p2pc_proto::ids::{AccountId, NodeId};
use p2pc_proto::net::{IfAddr, SelectedAddr};
use p2pc_proto::protocol::{Load, MAX_FRAME_LEN, RunningLease, read_frame, write_frame};
use serde_json::{Value, json};
use tokio::sync::{Semaphore, mpsc, watch};

/// Generous bound for real network steps on loopback; never a sleep.
const WAIT: Duration = Duration::from_secs(20);

fn loopback() -> Vec<SelectedAddr> {
    vec![SelectedAddr::new(IfAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8), "lo")]
}

/// The fake server: a loopback endpoint that accepts `p2pc/agent/1`.
async fn fake_server() -> (Endpoint, EndpointAddr) {
    let spec = BindSpec {
        relay_mode: RelayMode::Disabled,
        addrs: loopback(),
        port: 0,
        alpns: vec![PROTOCOL_ALPN_AGENT.to_vec()],
    };
    let ep = bind_endpoint(SecretKey::generate(), &spec).await.unwrap();
    let addr = EndpointAddr::new(ep.id()).with_ip_addr(ep.bound_sockets()[0]);
    (ep, addr)
}

/// Accepts the next connection and its control stream.
async fn accept(ep: &Endpoint) -> (Connection, SendStream, RecvStream) {
    tokio::time::timeout(WAIT, async {
        let conn = ep.accept().await.unwrap().await.unwrap();
        let (send, recv) = conn.accept_bi().await.unwrap();
        (conn, send, recv)
    })
    .await
    .expect("no agent connection")
}

async fn recv(r: &mut RecvStream) -> Option<Value> {
    tokio::time::timeout(WAIT, read_frame::<Value, _>(r, MAX_FRAME_LEN))
        .await
        .expect("no frame")
        .ok()
        .flatten()
}

async fn send(w: &mut SendStream, v: Value) {
    write_frame(w, &v).await.unwrap();
}

fn welcome(node: NodeId, account: AccountId) -> Value {
    json!({
        "type": "welcome",
        "server_version": "0.1.0",
        "node_id": node,
        "account_id": account,
        "heartbeat_interval_s": 5,
        "lease_ttl_s": 60,
    })
}

fn token_for(server: &Endpoint, ttl: time::Duration, now: time::OffsetDateTime) -> JoinToken {
    let relay = url::Url::parse("https://relay.example.invalid/").unwrap();
    JoinToken::generate(server.id().to_string(), vec![relay], ttl, now).unwrap()
}

fn inventory() -> Inventory {
    serde_json::from_value(json!({
        "hostname": "node-1",
        "platform": "linux",
        "cpu": {"model": "Example CPU", "cores": 4},
        "memory_mb": 8192,
        "os": "Ubuntu 24.04",
        "arch": "x86_64",
        "gpu_status": {"status": "not_found"},
        "offered": {"cpu": 3.0, "memory_mb": 6144, "gpu": 0},
        "agent_version": "0.1.0",
    }))
    .unwrap()
}

fn env(home: &std::path::Path) -> Env {
    Env {
        root: false,
        home: Some(home.to_path_buf()),
        config_env: None,
        ..Default::default()
    }
}

fn agent_connector(server: EndpointAddr) -> IrohConnector {
    IrohConnector::new(SecretKey::generate(), RelayMode::Disabled, server, loopback())
}

/// A `tracing` writer into a shared buffer, to check what the agent logs.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

/// The one capture of this test binary: a **global** TRACE subscriber writing into a shared buffer.
///
/// A thread-local `set_default` misses what other threads log (iroh's tasks, `spawn_blocking`), so whether it saw
/// anything depended on timing: the CI flake of PR #18. Every test of this binary installs it first, so callsites
/// are registered against it, and the SI-6 checks see everything the process logged.
fn capture() -> &'static Logs {
    static LOGS: std::sync::OnceLock<Logs> = std::sync::OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = Logs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("the only global subscriber of this binary");
        logs
    })
}

impl Logs {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Logs;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// join

/// A `Join` that gets `Welcome` writes `[server]` (mode 0600) with the token's server and relays and the
/// `Welcome`'s owner account and node ID. The token appears in no log line and no `Debug`.
#[tokio::test]
async fn join_success_writes_the_server_section_with_mode_0600() {
    let logs = capture();

    let (server, addr) = fake_server().await;
    let token = token_for(&server, time::Duration::minutes(15), time::OffsetDateTime::now_utc());
    let token_text = token.encode().unwrap();
    let (account, node) = (AccountId::generate(), NodeId::generate());
    let server_task = tokio::spawn(async move {
        let (conn, mut w, mut r) = accept(&server).await;
        let join = recv(&mut r).await.unwrap();
        send(&mut w, welcome(node, account)).await;
        let _ = tokio::time::timeout(WAIT, conn.closed()).await;
        server.close().await;
        join
    });
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("agent.toml");
    // Already enrolled once (`join --force`): the old [server] is replaced, the owner's comment kept.
    std::fs::write(
        &path,
        "# the owner's comment\n\n[server]\nnode_id = \"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\"\n\
         account_id = \"acc_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4\"\nagent_node_id = \"node_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4\"\n",
    )
    .unwrap();
    let connector = agent_connector(addr);
    let (joined, section) = enroll(&connector, &token, inventory(), &path, &env(home.path()), home.path())
        .await
        .unwrap();
    let join = server_task.await.unwrap();

    // What the server received: the token and the inventory.
    assert_eq!(join["type"], "join");
    assert_eq!(join["token"], token_text);
    assert_eq!(join["inventory"]["hostname"], "node-1");
    // What was written.
    assert_eq!((joined.account_id, joined.node_id), (account, node));
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("# the owner's comment"), "{text}");
    assert!(
        !text.contains("acc_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4"),
        "the old enrollment is gone: {text}"
    );
    let config = Config::load(&ConfigSource::Flag(path.clone()), &env(home.path())).unwrap();
    let stored = config.server.unwrap();
    assert_eq!(stored, section);
    assert_eq!(stored.account_id, account, "the owner for SI-1");
    assert_eq!(stored.agent_node_id, node);
    assert_eq!(stored.node_id, token.server);
    assert_eq!(stored.relays, ["https://relay.example.invalid/"]);
    // SI-6: the token never shows in the logs, nor in the file, nor in Debug.
    let secret_part = &token_text["p2pc_join_".len()..];
    let logged = logs.text();
    // This test's own activity is in the capture: enroll logs the node ID it was given.
    assert!(
        logged
            .lines()
            .any(|l| l.contains("enrolled with the server") && l.contains(&node.to_string())),
        "the capture missed this test's join"
    );
    assert!(!logged.contains(secret_part), "the token is in the logs");
    assert!(!text.contains(secret_part));
    assert!(!format!("{token:?}").contains(secret_part));
}

#[tokio::test]
async fn each_join_error_maps_to_its_exit_code() {
    let logs = capture();
    for (answer, expected, code) in [
        (Some("invalid_token"), JoinError::InvalidToken, exit::INVALID_TOKEN),
        (Some("agent_too_old"), JoinError::AgentTooOld, exit::AGENT_TOO_OLD),
        (None, JoinError::NoAnswer, exit::FAILURE),
    ] {
        let (server, addr) = fake_server().await;
        let token = token_for(&server, time::Duration::minutes(15), time::OffsetDateTime::now_utc());
        let server_task = tokio::spawn(async move {
            let (conn, mut w, mut r) = accept(&server).await;
            let _ = recv(&mut r).await.unwrap();
            match answer {
                Some(c) => {
                    send(&mut w, json!({"type": "error", "code": c, "message": "refused"})).await;
                    let _ = w.finish();
                    let _ = tokio::time::timeout(WAIT, conn.closed()).await;
                }
                // Over a limit: the server closes with no detail.
                None => conn.close(1u32.into(), b""),
            }
            server.close().await;
        });
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("agent.toml");
        let err = enroll(
            &agent_connector(addr),
            &token,
            inventory(),
            &path,
            &env(home.path()),
            home.path(),
        )
        .await
        .unwrap_err();
        server_task.await.unwrap();
        assert_eq!(err, expected);
        assert_eq!(err.exit_code(), code);
        assert!(!path.exists(), "nothing is written on failure");
        let secret = token.encode().unwrap();
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains(&secret["p2pc_join_".len()..]));
        assert!(
            !logs.text().contains(&secret["p2pc_join_".len()..]),
            "the token is in the logs"
        );
    }
}

/// An expired token is refused before anything is sent.
#[tokio::test]
async fn an_expired_token_is_refused_without_dialling() {
    let logs = capture();
    let (server, addr) = fake_server().await;
    let long_ago = time::OffsetDateTime::now_utc() - time::Duration::hours(2);
    let token = token_for(&server, time::Duration::minutes(15), long_ago);
    let home = tempfile::tempdir().unwrap();
    let err = enroll(
        &agent_connector(addr),
        &token,
        inventory(),
        &home.path().join("a.toml"),
        &env(home.path()),
        home.path(),
    )
    .await
    .unwrap_err();
    assert_eq!(err, JoinError::Expired);
    assert_eq!(err.exit_code(), exit::TOKEN_EXPIRED);
    let secret = token.encode().unwrap();
    assert!(!logs.text().contains(&secret["p2pc_join_".len()..]));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server.accept())
            .await
            .is_err(),
        "no connection was made"
    );
    server.close().await;
}

/// T05b final review: a token that looks expired by this machine's clock by less than 5 minutes (a WSL2 clock that ran
/// ahead) is still sent; the server's row decides (SI-11).
#[tokio::test]
async fn a_token_that_only_looks_expired_is_sent_and_the_server_decides() {
    let _ = capture();
    let (server, addr) = fake_server().await;
    let issued = time::OffsetDateTime::now_utc() - time::Duration::minutes(17);
    let token = token_for(&server, time::Duration::minutes(15), issued);
    let (account, node) = (AccountId::generate(), NodeId::generate());
    let server_task = tokio::spawn(async move {
        let (conn, mut w, mut r) = accept(&server).await;
        let join = recv(&mut r).await.unwrap();
        send(&mut w, welcome(node, account)).await;
        let _ = tokio::time::timeout(WAIT, conn.closed()).await;
        server.close().await;
        join
    });
    let home = tempfile::tempdir().unwrap();
    let (joined, _) = enroll(
        &agent_connector(addr),
        &token,
        inventory(),
        &home.path().join("agent.toml"),
        &env(home.path()),
        home.path(),
    )
    .await
    .unwrap();
    assert_eq!(server_task.await.unwrap()["type"], "join");
    assert_eq!(joined.node_id, node);
}

/// T05b real run, round 2: `join`, `run`, the node removed on the server (`p2pc machines rm`), then `join --force` to
/// the **same** server: before `run` starts again, `status` must not show the previous enrollment's "stopped: … not
/// enrolled" and its old Welcome.
#[tokio::test(flavor = "multi_thread")]
async fn status_after_join_force_to_the_same_server_is_a_fresh_enrollment() {
    use p2pc_agent::connection::state::{ConnectionState, StateFile, render_status};

    let _ = capture();
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let path = home.path().join("agent.toml");
    std::fs::write(&path, format!("data_dir = \"{}\"\n", data.display())).unwrap();
    let account = AccountId::generate();
    let (server, addr) = fake_server().await;
    let server_id = server.id().to_string();
    // join: node 1.
    let first_node = NodeId::generate();
    let token = token_for(&server, time::Duration::minutes(15), time::OffsetDateTime::now_utc());
    let joining = {
        let server = server.clone();
        tokio::spawn(async move {
            let (conn, mut w, mut r) = accept(&server).await;
            let _ = recv(&mut r).await.unwrap();
            send(&mut w, welcome(first_node, account)).await;
            let _ = tokio::time::timeout(WAIT, conn.closed()).await;
        })
    };
    enroll(
        &agent_connector(addr.clone()),
        &token,
        inventory(),
        &path,
        &env(home.path()),
        &data,
    )
    .await
    .unwrap();
    joining.await.unwrap();
    // run: welcomed, then removed (`not_enrolled`).
    let state = StateFile::in_dir(&data);
    let ttl = Duration::from_secs(45);
    let (tx, _supervised) = mpsc::unbounded_channel();
    let daemon = Daemon {
        shared: Shared {
            owner: account,
            agent_lease_ttl: ttl,
            watchdog: Watchdog::new(ttl),
            supervisor: Arc::new(Drains(tx)),
            handler: Arc::new(NotReady),
            inventory: Arc::new(FixedInventory),
            load: Arc::new(ZeroLoad),
            inventory_interval: INVENTORY_INTERVAL,
            decisions: Arc::new(Semaphore::new(MAX_PENDING_DECISIONS)),
            uplink: p2pc_agent::connection::Uplink::new(),
            ports: None,
        },
        connector: Arc::new(agent_connector(addr.clone())),
        backoff_seed: 1,
        state_file: Some(state.clone()),
        server_node_id: server_id.clone(),
        agent_node_id: first_node.to_string(),
    };
    let (_stop, stop_rx) = watch::channel(false);
    let (_net_tx, net_rx) = mpsc::channel(1);
    let running = tokio::spawn(daemon.run(stop_rx, net_rx));
    let (conn, mut w, mut r) = accept(&server).await;
    let _ = recv(&mut r).await.unwrap();
    send(&mut w, welcome(first_node, account)).await;
    send(
        &mut w,
        json!({"type": "error", "code": "not_enrolled", "message": "removed"}),
    )
    .await;
    assert_eq!(
        tokio::time::timeout(WAIT, running).await.unwrap().unwrap(),
        DaemonExit::NotEnrolled
    );
    drop(conn);
    let before = state.read().unwrap();
    assert_eq!(before.connection, ConnectionState::NotEnrolled);
    assert!(before.last_welcome_at.is_some());
    // join --force to the same server: node 2.
    let second_node = NodeId::generate();
    let token = token_for(&server, time::Duration::minutes(15), time::OffsetDateTime::now_utc());
    let joining = {
        let server = server.clone();
        tokio::spawn(async move {
            let (conn, mut w, mut r) = accept(&server).await;
            let _ = recv(&mut r).await.unwrap();
            send(&mut w, welcome(second_node, account)).await;
            let _ = tokio::time::timeout(WAIT, conn.closed()).await;
        })
    };
    enroll(
        &agent_connector(addr),
        &token,
        inventory(),
        &path,
        &env(home.path()),
        &data,
    )
    .await
    .unwrap();
    joining.await.unwrap();
    server.close().await;
    // status, before `run`: a fresh enrollment.
    assert_eq!(state.read(), None, "join deleted the old state file");
    let config = Config::load(&ConfigSource::Flag(path.clone()), &env(home.path())).unwrap();
    let text = render_status(&config, None);
    assert!(text.contains("has not run yet"), "{text}");
    // Even a state file of the earlier node, left by a `join` that could not delete it, is not this enrollment's.
    let text = render_status(&config, Some(&before));
    assert!(text.contains("Connection:    not run since this enrollment"), "{text}");
    assert!(!text.contains("not enrolled;"), "{text}");
    assert!(text.contains("Last Welcome:  never"), "{text}");
}

// ---------------------------------------------------------------------------------------------------------------
// run

#[derive(Debug)]
struct FixedInventory;

impl InventorySource for FixedInventory {
    fn detect(&self) -> BoxFuture<'_, Result<Inventory, String>> {
        Box::pin(async { Ok(inventory()) })
    }
}

#[derive(Debug)]
struct ZeroLoad;

impl p2pc_agent::connection::load::LoadSource for ZeroLoad {
    fn sample(&self) -> BoxFuture<'_, Load> {
        Box::pin(async { serde_json::from_value(json!({"cpu_pct": 0, "mem_used_mb": 0})).unwrap() })
    }
}

#[derive(Debug)]
struct Drains(mpsc::UnboundedSender<&'static str>);

impl LeaseSupervisor for Drains {
    fn running(&self) -> Vec<RunningLease> {
        Vec::new()
    }
    fn stop_all(&self, reason: &'static str) -> BoxFuture<'_, ()> {
        let _ = self.0.send(reason);
        Box::pin(async {})
    }
    fn drain(&self) -> BoxFuture<'_, ()> {
        let _ = self.0.send("drain");
        Box::pin(async {})
    }
    fn resume(&self) -> BoxFuture<'_, ()> {
        let _ = self.0.send("resume");
        Box::pin(async {})
    }
}

/// `run` over iroh: `Hello` with the right fields, `Welcome`, heartbeats, a lease refused with `agent_not_ready`,
/// `Drain` to the supervisor, and a clean close at shutdown.
#[tokio::test(flavor = "multi_thread")]
async fn run_says_hello_heartbeats_and_routes_over_iroh() {
    let _ = capture();
    let (server, addr) = fake_server().await;
    let owner = AccountId::generate();
    let (tx, mut supervised) = mpsc::unbounded_channel();
    let ttl = Duration::from_secs(45);
    let shared = Shared {
        owner,
        agent_lease_ttl: ttl,
        watchdog: Watchdog::new(ttl),
        supervisor: Arc::new(Drains(tx)),
        handler: Arc::new(NotReady),
        inventory: Arc::new(FixedInventory),
        load: Arc::new(ZeroLoad),
        inventory_interval: INVENTORY_INTERVAL,
        decisions: Arc::new(Semaphore::new(MAX_PENDING_DECISIONS)),
        uplink: p2pc_agent::connection::Uplink::new(),
        ports: None,
    };
    let connector = Arc::new(agent_connector(addr));
    let daemon = Daemon {
        shared,
        connector: connector.clone(),
        backoff_seed: 1,
        state_file: None,
        server_node_id: server.id().to_string(),
        agent_node_id: NodeId::generate().to_string(),
    };
    let (stop, stop_rx) = watch::channel(false);
    let (_net_tx, net_rx) = mpsc::channel(1);
    let running = tokio::spawn(daemon.run(stop_rx, net_rx));

    let (conn, mut w, mut r) = accept(&server).await;
    // The peer is the agent's own key: iroh authenticated it.
    assert_eq!(conn.remote_id(), connector.endpoint().await.unwrap().id());
    let hello = recv(&mut r).await.unwrap();
    assert_eq!(hello["type"], "hello");
    assert_eq!(hello["agent_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(hello["features"], json!([]));
    assert_eq!(hello["running"], json!([]));
    assert_eq!(hello["inventory"]["hostname"], "node-1");
    send(&mut w, welcome(NodeId::generate(), owner)).await;
    let lease_id = p2pc_proto::ids::LeaseId::generate();
    send(
        &mut w,
        json!({
            "type": "lease", "lease_id": lease_id, "epoch": 1, "account_id": owner, "deadline": "2030-01-01T00:00:00Z",
            "job": {"image": "docker.io/library/alpine:3.20", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 256}},
        }),
    )
    .await;
    let answer = loop {
        let m = recv(&mut r).await.unwrap();
        if m["type"] != "heartbeat" {
            break m;
        }
    };
    assert_eq!(
        answer,
        json!({"type": "lease_rejected", "lease_id": lease_id, "epoch": 1, "reason": "agent_not_ready"})
    );
    send(&mut w, json!({"type": "drain"})).await;
    assert_eq!(
        tokio::time::timeout(WAIT, supervised.recv()).await.unwrap(),
        Some("drain")
    );
    // Shutdown closes the connection cleanly.
    stop.send(true).unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, running).await.unwrap().unwrap(),
        DaemonExit::Shutdown
    );
    tokio::time::timeout(WAIT, conn.closed()).await.unwrap();
    server.close().await;
}

/// A port opener that connects every port of epoch 1 to an echo and refuses any other epoch as stale.
#[derive(Debug)]
struct EchoPorts;

impl p2pc_agent::connection::streams::PortOpener for EchoPorts {
    fn open<'a>(
        &'a self,
        open: &'a p2pc_proto::protocol::PortOpen,
    ) -> BoxFuture<'a, Result<Box<dyn p2pc_agent::connection::streams::PortIo>, &'static str>> {
        Box::pin(async move {
            if open.epoch != 1 {
                return Err(p2pc_proto::protocol::port_open_reason::STALE_LEASE);
            }
            let (agent, service) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(service);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Ok(Box::new(agent) as Box<dyn p2pc_agent::connection::streams::PortIo>)
        })
    }
}

/// H2 §6.1 over real iroh: an agent with a port opener declares `service_jobs`; the server opens streams on the
/// agent's own connection; a `PortOpen` is acked and carries bytes both ways with a clean end; a refused one gets
/// its reason; a stream of an unknown type is reset with `unsupported_stream` (3) and the connection goes on.
#[tokio::test(flavor = "multi_thread")]
async fn the_server_opens_port_streams_on_the_agents_connection_over_iroh() {
    use iroh::endpoint::{ReadError, ReadToEndError, VarInt};
    use p2pc_proto::protocol::STREAM_RESET_UNSUPPORTED_STREAM;

    let _ = capture();
    let (server, addr) = fake_server().await;
    let owner = AccountId::generate();
    let (tx, mut supervised) = mpsc::unbounded_channel();
    let ttl = Duration::from_secs(45);
    let shared = Shared {
        owner,
        agent_lease_ttl: ttl,
        watchdog: Watchdog::new(ttl),
        supervisor: Arc::new(Drains(tx)),
        handler: Arc::new(NotReady),
        inventory: Arc::new(FixedInventory),
        load: Arc::new(ZeroLoad),
        inventory_interval: INVENTORY_INTERVAL,
        decisions: Arc::new(Semaphore::new(MAX_PENDING_DECISIONS)),
        uplink: p2pc_agent::connection::Uplink::new(),
        ports: Some(Arc::new(EchoPorts)),
    };
    let daemon = Daemon {
        shared,
        connector: Arc::new(agent_connector(addr)),
        backoff_seed: 1,
        state_file: None,
        server_node_id: server.id().to_string(),
        agent_node_id: NodeId::generate().to_string(),
    };
    let (stop, stop_rx) = watch::channel(false);
    let (_net_tx, net_rx) = mpsc::channel(1);
    let running = tokio::spawn(daemon.run(stop_rx, net_rx));

    let (conn, mut w, mut r) = accept(&server).await;
    let hello = recv(&mut r).await.unwrap();
    assert_eq!(hello["features"], json!(["service_jobs"]));
    send(&mut w, welcome(NodeId::generate(), owner)).await;
    let lease_id = p2pc_proto::ids::LeaseId::generate();
    let port_open =
        |epoch: u64| json!({"type": "port_open", "lease_id": lease_id, "epoch": epoch, "port": 11434, "conn_id": 1});

    // A port stream: the agent's ack is its first frame, then the bytes of the port, then a clean end.
    let (mut ps, mut pr) = tokio::time::timeout(WAIT, conn.open_bi()).await.unwrap().unwrap();
    send(&mut ps, port_open(1)).await;
    assert_eq!(recv(&mut pr).await.unwrap(), json!({"ok": true}));
    ps.write_all(b"ping").await.unwrap();
    ps.finish().unwrap();
    let echoed = tokio::time::timeout(WAIT, pr.read_to_end(64)).await.unwrap().unwrap();
    assert_eq!(echoed, b"ping", "a finish, after the echoed bytes");

    // A refused one: the reason, then a clean end.
    let (mut ps, mut pr) = tokio::time::timeout(WAIT, conn.open_bi()).await.unwrap().unwrap();
    send(&mut ps, port_open(2)).await;
    assert_eq!(
        recv(&mut pr).await.unwrap(),
        json!({"ok": false, "reason": "stale_lease"})
    );
    let rest = tokio::time::timeout(WAIT, pr.read_to_end(64)).await.unwrap().unwrap();
    assert!(rest.is_empty());

    // A stream of a type this agent does not know: reset with `unsupported_stream`, in both directions.
    let (mut us, mut ur) = tokio::time::timeout(WAIT, conn.open_bi()).await.unwrap().unwrap();
    send(&mut us, json!({"type": "log_follow", "lease_id": lease_id})).await;
    let end = tokio::time::timeout(WAIT, ur.read_to_end(64)).await.unwrap();
    let unsupported = VarInt::from_u32(STREAM_RESET_UNSUPPORTED_STREAM);
    assert!(
        matches!(end, Err(ReadToEndError::Read(ReadError::Reset(code))) if code == unsupported),
        "{end:?}"
    );
    let stopped = tokio::time::timeout(WAIT, us.stopped()).await.unwrap().unwrap();
    assert_eq!(stopped, Some(unsupported));

    // Never the connection: the control stream still routes.
    send(&mut w, json!({"type": "drain"})).await;
    assert_eq!(
        tokio::time::timeout(WAIT, supervised.recv()).await.unwrap(),
        Some("drain")
    );
    assert!(conn.close_reason().is_none());
    stop.send(true).unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, running).await.unwrap().unwrap(),
        DaemonExit::Shutdown
    );
    tokio::time::timeout(WAIT, conn.closed()).await.unwrap();
    server.close().await;
}

/// The agent's endpoint accepts no connection: it has no ALPN at all (SI-12).
#[tokio::test]
async fn the_agents_endpoint_accepts_nothing() {
    let _ = capture();
    // The endpoint the agent's connector really binds.
    let (dialer, dialer_addr) = fake_server().await;
    let connector = agent_connector(dialer_addr);
    let agent = connector.endpoint().await.unwrap();
    let target = EndpointAddr::new(agent.id()).with_ip_addr(agent.bound_sockets()[0]);
    // Refused, or never answered: either way no connection is ever established.
    let attempt = tokio::time::timeout(Duration::from_secs(3), dialer.connect(target, PROTOCOL_ALPN_AGENT)).await;
    assert!(!matches!(attempt, Ok(Ok(_))), "the agent accepted a connection");
    dialer.close().await;
    agent.close().await;
}

/// Review of PR #48, round 2, P2, the whole chain with nothing stood in for: the egress gate watcher of a real
/// connector sees the default route move, asks for the rebind itself (no network watcher runs: the daemon is given a
/// channel nobody sends on), the real daemon ends the session and calls the connector, a new iroh endpoint is bound
/// and dialled, and the gate opens on that endpoint's first public IPv4, not before. Only what a hermetic test cannot
/// have is fed: the host's network and each endpoint's net report ([`GateFeed`]).
#[tokio::test(flavor = "multi_thread")]
async fn a_route_move_ends_in_a_rebind_and_the_new_endpoint_opens_the_gate() {
    use p2pc_agent::connection::endpoint::GateFeed;
    use p2pc_net::{EgressGate, HostNet};

    let _ = capture();
    let (server, addr) = fake_server().await;
    let owner = AccountId::generate();
    let net = |route: &str| HostNet {
        ipv4: true,
        default_route: Some(route.to_string()),
        bridge_named_uplink: false,
    };
    let (host_tx, host_rx) = watch::channel(net("wlan0"));
    let (endpoints_tx, mut endpoints) = mpsc::unbounded_channel();
    let connector = Arc::new(agent_connector(addr).with_gate_feed(GateFeed {
        host: host_rx,
        endpoints: endpoints_tx,
    }));
    let mut gate = connector.egress_ready();
    let mut public = connector.public_addrs();
    let (tx, _supervised) = mpsc::unbounded_channel();
    let ttl = Duration::from_secs(45);
    let daemon = Daemon {
        shared: Shared {
            owner,
            agent_lease_ttl: ttl,
            watchdog: Watchdog::new(ttl),
            supervisor: Arc::new(Drains(tx)),
            handler: Arc::new(NotReady),
            inventory: Arc::new(FixedInventory),
            load: Arc::new(ZeroLoad),
            inventory_interval: INVENTORY_INTERVAL,
            decisions: Arc::new(Semaphore::new(MAX_PENDING_DECISIONS)),
            uplink: p2pc_agent::connection::Uplink::new(),
            ports: None,
        },
        connector: connector.clone(),
        backoff_seed: 1,
        state_file: None,
        server_node_id: server.id().to_string(),
        agent_node_id: NodeId::generate().to_string(),
    };
    let (stop, stop_rx) = watch::channel(false);
    // No network watcher: its sender stays open and silent for the whole test.
    let (_net_tx, net_rx) = mpsc::channel(1);
    let running = tokio::spawn(daemon.run(stop_rx, net_rx));

    // Endpoint A: connected, welcomed; its net report learns the public IPv4 of network A.
    let (conn_a, mut w, mut r) = accept(&server).await;
    let _ = recv(&mut r).await.unwrap();
    send(&mut w, welcome(NodeId::generate(), owner)).await;
    let list_a = tokio::time::timeout(WAIT, endpoints.recv())
        .await
        .unwrap()
        .expect("endpoint A's list");
    let socket_a = list_a.get().ip_addrs().copied().next().expect("A's own socket");
    let qad_a = std::net::SocketAddr::new("203.0.113.9".parse().unwrap(), 40001);
    list_a
        .set(
            EndpointAddr::new(server.id())
                .with_ip_addr(socket_a)
                .with_ip_addr(qad_a),
        )
        .unwrap();
    tokio::time::timeout(WAIT, gate.wait_for(|g| g.is_open()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*public.borrow_and_update(), ["203.0.113.9".parse::<IpAddr>().unwrap()]);

    // The default route moves: the gate closes at once, and (after the debounce) the agent binds again by itself.
    host_tx.send_replace(net("eth0"));
    tokio::time::timeout(WAIT, gate.wait_for(|g| !g.is_open()))
        .await
        .unwrap()
        .unwrap();
    let (conn_b, mut w2, mut r2) = accept(&server).await;
    let hello = recv(&mut r2).await.unwrap();
    assert_eq!(hello["type"], "hello");
    send(&mut w2, welcome(NodeId::generate(), owner)).await;
    tokio::time::timeout(WAIT, conn_a.closed()).await.unwrap();
    // The new endpoint has its own address list. Until its net report learns a public IPv4 the gate stays closed, and
    // the old address stays denied.
    let list_b = tokio::time::timeout(WAIT, endpoints.recv())
        .await
        .unwrap()
        .expect("endpoint B's list");
    assert!(!gate.borrow().is_open(), "nothing observed on the new network yet");
    assert_eq!(
        *public.borrow(),
        ["203.0.113.9".parse::<IpAddr>().unwrap()],
        "still denied"
    );
    let socket_b = list_b.get().ip_addrs().copied().next().expect("B's own socket");
    let qad_b = std::net::SocketAddr::new("198.51.100.4".parse().unwrap(), 40002);
    list_b
        .set(
            EndpointAddr::new(server.id())
                .with_ip_addr(socket_b)
                .with_ip_addr(qad_b),
        )
        .unwrap();
    tokio::time::timeout(WAIT, gate.wait_for(|g| *g == EgressGate::Open))
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(WAIT, public.wait_for(|p| p.contains(&"198.51.100.4".parse().unwrap())))
        .await
        .unwrap()
        .unwrap();

    stop.send(true).unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, running).await.unwrap().unwrap(),
        DaemonExit::Shutdown
    );
    drop(conn_b);
    server.close().await;
}
