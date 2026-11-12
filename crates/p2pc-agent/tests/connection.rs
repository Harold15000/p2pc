// SPDX-License-Identifier: Apache-2.0

//! `p2pc-agent run`'s connection logic against a fake server over in-memory pipes, on tokio's paused clock: the
//! timing of heartbeats, the agent-side lease timer (SI-13), the backoff and the inventory updates is checked
//! without a single real sleep. The same logic over real iroh (QUIC on loopback) is in `iroh_fake_server.rs`.
//!
//! The fake server speaks the `p2pc-proto` codec but writes and reads plain JSON values, so these tests never build
//! protocol structs by hand (they grow).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use p2pc_agent::config::Share;
use p2pc_agent::connection::daemon::{Daemon, DaemonExit};
use p2pc_agent::connection::lease::{LeaseDecision, LeaseHandler, LeaseOffer, LeaseSupervisor, NotReady};
use p2pc_agent::connection::load::LoadSource;
use p2pc_agent::connection::session::{
    Approval, INVENTORY_INTERVAL, InventorySource, LeaveEnd, LeaveRequest, MAX_LEAVE_CONNECTIONS,
    MAX_PENDING_DECISIONS, NodeControls, Shared, leave_node,
};
use p2pc_agent::connection::state::{AgentState, ConnectionState, StateFile};
use p2pc_agent::connection::streams::{HubRecv, HubSend, HubStream, PortIo, PortOpener, StreamAcceptor};
use p2pc_agent::connection::transport::{ConnectError, Connector, Link};
use p2pc_agent::connection::watchdog::Watchdog;
use p2pc_agent::connection::{BoxFuture, Uplink, exit};
use p2pc_agent::executor::SystemClock;
use p2pc_agent::volumes::{StoreConfig, VolumeStore, dir_name};
use p2pc_proto::api::Inventory;
use p2pc_proto::ids::{AccountId, LeaseId, NodeId};
use p2pc_proto::net::{AddressChange, SelectedAddr};
use p2pc_proto::protocol::{Load, MAX_FRAME_LEN, PortOpen, RunningLease, read_frame, write_frame};
use serde_json::{Value, json};
use tokio::io::{DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::{Notify, Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

const SERVER_ID: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
/// This node's ID on the server, from the `Welcome` of its `join`.
const AGENT_NODE_ID: &str = "node_01JBQ6Z5E8Y1V8Y6Y3C8V9N2W4";
/// The longest any helper waits, in (virtual) time: past it the test fails instead of letting the paused clock run on
/// forever (each virtual hour costs only some 720 heartbeats).
const TEST_WAIT: Duration = Duration::from_secs(2 * 3600);
/// Most unread messages [`ServerEnd::serve`] keeps.
const SERVE_BUFFER: usize = 4096;

/// `f`, or a panic after [`TEST_WAIT`].
async fn bounded<T>(what: &str, f: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(TEST_WAIT, f).await {
        Ok(v) => v,
        Err(_) => panic!("no {what} within {} s of (virtual) time", TEST_WAIT.as_secs()),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The fake world: a connector over pipes, a fake server end, recording traits.

/// Hands the server end of every connection to the test.
#[derive(Debug)]
struct PipeConnector {
    accepted: mpsc::UnboundedSender<ServerEnd>,
    refuse: AtomicBool,
    attempts: Mutex<Vec<Instant>>,
    rebinds: Mutex<Vec<Vec<SelectedAddr>>>,
    /// Where the streams the fake server opens arrive, for the tests of H2 §6.1.
    incoming: Option<Arc<dyn StreamAcceptor>>,
}

impl Connector for PipeConnector {
    fn connect(&self) -> BoxFuture<'_, Result<Link, ConnectError>> {
        Box::pin(async move {
            self.attempts.lock().unwrap().push(Instant::now());
            if self.refuse.load(Ordering::SeqCst) {
                return Err(ConnectError("refused by the test".into()));
            }
            let (agent, server) = tokio::io::duplex(4 * 1024 * 1024);
            let (ar, aw) = tokio::io::split(agent);
            let (sr, sw) = tokio::io::split(server);
            let _ = self.accepted.send(ServerEnd { r: sr, w: sw });
            let link = Link::new(Box::new(aw), Box::new(ar), Box::new(|| {}));
            Ok(match &self.incoming {
                Some(incoming) => link.with_incoming(incoming.clone()),
                None => link,
            })
        })
    }

    fn set_addresses(&self, addrs: Vec<SelectedAddr>) -> BoxFuture<'_, ()> {
        self.rebinds.lock().unwrap().push(addrs);
        Box::pin(async {})
    }

    fn shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

/// The server's side of one connection.
struct ServerEnd {
    r: ReadHalf<DuplexStream>,
    w: WriteHalf<DuplexStream>,
}

impl ServerEnd {
    /// The next agent message, as JSON; `None` when the agent closed. Panics after [`TEST_WAIT`] of (virtual) time.
    async fn recv(&mut self) -> Option<Value> {
        bounded("an agent message", self.recv_raw()).await
    }

    async fn recv_raw(&mut self) -> Option<Value> {
        read_frame::<Value, _>(&mut self.r, MAX_FRAME_LEN).await.ok().flatten()
    }

    /// The next agent message that is not a heartbeat, within [`TEST_WAIT`] in all.
    async fn recv_not_heartbeat(&mut self) -> Option<Value> {
        bounded("an agent message that is not a heartbeat", async {
            loop {
                let m = self.recv_raw().await?;
                if m["type"] != "heartbeat" {
                    return Some(m);
                }
            }
        })
        .await
    }

    async fn send(&mut self, msg: Value) {
        write_frame(&mut self.w, &msg).await.unwrap();
    }

    async fn welcome(&mut self, account: AccountId, lease_ttl_s: u32) {
        self.send(json!({
            "type": "welcome",
            "server_version": "0.1.0",
            "node_id": NodeId::generate(),
            "account_id": account,
            "heartbeat_interval_s": 5,
            "lease_ttl_s": lease_ttl_s,
        }))
        .await;
    }

    /// Reads `Hello`, answers `Welcome`, and returns the `Hello`.
    async fn handshake(&mut self, account: AccountId) -> Value {
        let hello = self.recv().await.unwrap();
        assert_eq!(hello["type"], "hello", "{hello}");
        self.welcome(account, 60).await;
        hello
    }

    /// Drains whatever the agent sends, in the background, acknowledging heartbeats when `ack` is set. Keeps at most
    /// [`SERVE_BUFFER`] unread messages and drops the rest: on the paused clock a test that waits on something else lets
    /// virtual time run, and the heartbeats with it, so an unbounded buffer grows without limit (it once took one test
    /// binary to 13.8 GB).
    fn serve(mut self, ack: bool) -> (JoinHandle<()>, mpsc::Receiver<Value>) {
        let (tx, rx) = mpsc::channel(SERVE_BUFFER);
        let task = tokio::spawn(async move {
            while let Some(m) = self.recv_raw().await {
                if ack && m["type"] == "heartbeat" {
                    let seq = m["seq"].clone();
                    self.send(json!({"type": "heartbeat_ack", "seq": seq})).await;
                }
                let _ = tx.try_send(m);
            }
        });
        (task, rx)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Event {
    StopAll(&'static str),
    Drain,
    Resume,
    /// A lease decision still in progress was dropped (aborted).
    DecisionDropped,
}

#[derive(Debug)]
struct Supervisor {
    events: mpsc::UnboundedSender<(Instant, Event)>,
    running: Mutex<Vec<RunningLease>>,
    /// What `Heartbeat.running` lists; `None` lists `running`, like a supervisor without the T06e split.
    holding: Mutex<Option<Vec<RunningLease>>>,
    /// A lease released its resources.
    release: Notify,
    stops: AtomicUsize,
}

impl LeaseSupervisor for Supervisor {
    fn running(&self) -> Vec<RunningLease> {
        self.running.lock().unwrap().clone()
    }

    fn holding(&self) -> Vec<RunningLease> {
        self.holding.lock().unwrap().clone().unwrap_or_else(|| self.running())
    }

    fn released(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.release.notified())
    }

    fn stop_all(&self, reason: &'static str) -> BoxFuture<'_, ()> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        let _ = self.events.send((Instant::now(), Event::StopAll(reason)));
        Box::pin(async {})
    }

    fn drain(&self) -> BoxFuture<'_, ()> {
        let _ = self.events.send((Instant::now(), Event::Drain));
        Box::pin(async {})
    }

    fn resume(&self) -> BoxFuture<'_, ()> {
        let _ = self.events.send((Instant::now(), Event::Resume));
        Box::pin(async {})
    }
}

/// Accepts every lease and records it, to check what reaches a handler.
#[derive(Debug, Default)]
struct Recorder {
    offers: Mutex<Vec<LeaseId>>,
    cancels: Mutex<Vec<LeaseId>>,
}

impl LeaseHandler for Recorder {
    fn lease(&self, offer: LeaseOffer) -> BoxFuture<'_, LeaseDecision> {
        self.offers.lock().unwrap().push(offer.lease_id);
        Box::pin(async { LeaseDecision::Accept })
    }

    fn cancel(&self, lease_id: LeaseId, _epoch: u64, _reason: String) -> BoxFuture<'_, ()> {
        self.cancels.lock().unwrap().push(lease_id);
        Box::pin(async {})
    }
}

fn inventory(hostname: &str) -> Inventory {
    serde_json::from_value(json!({
        "hostname": hostname,
        "platform": "linux",
        "cpu": {"model": "Example CPU", "cores": 4},
        "memory_mb": 8192,
        "os": "Ubuntu 24.04",
        "arch": "x86_64",
        "gpus": [],
        "gpu_status": {"status": "not_found"},
        "dxg": false,
        "sandbox": [],
        "offered": {"cpu": 3.0, "memory_mb": 6144, "gpu": 0},
        "agent_version": "0.1.0",
    }))
    .unwrap()
}

/// An inventory the test can change.
#[derive(Debug)]
/// The inventory, how long a detection takes, and how many detections ran.
struct FakeInventory(Mutex<Inventory>, Mutex<Duration>, AtomicUsize);

impl InventorySource for FakeInventory {
    /// Takes the configured (virtual) time, like a slow `nvidia-smi` or the WSL2 boot wait.
    fn detect(&self) -> BoxFuture<'_, Result<Inventory, String>> {
        let delay = *self.1.lock().unwrap();
        self.2.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Ok(self.0.lock().unwrap().clone())
        })
    }
}

#[derive(Debug)]
struct FixedLoad;

impl LoadSource for FixedLoad {
    fn sample(&self) -> BoxFuture<'_, Load> {
        Box::pin(async { serde_json::from_value(json!({"cpu_pct": 12, "mem_used_mb": 2048})).unwrap() })
    }
}

struct World {
    owner: AccountId,
    connector: Arc<PipeConnector>,
    accepted: mpsc::UnboundedReceiver<ServerEnd>,
    events: mpsc::UnboundedReceiver<(Instant, Event)>,
    supervisor: Arc<Supervisor>,
    inventory: Arc<FakeInventory>,
    stop: watch::Sender<bool>,
    network: mpsc::Sender<AddressChange>,
    daemon: JoinHandle<DaemonExit>,
    _dir: tempfile::TempDir,
    state: StateFile,
}

/// Builds the handler with the world's event channel, for handlers that report into it.
type HandlerWithEvents = Box<dyn FnOnce(mpsc::UnboundedSender<(Instant, Event)>) -> Arc<dyn LeaseHandler>>;

struct Options {
    handler: Arc<dyn LeaseHandler>,
    /// Overrides `handler`.
    handler_with_events: Option<HandlerWithEvents>,
    agent_lease_ttl: Duration,
    /// A state file left by an earlier `run`, written before the daemon starts.
    earlier_state: Option<AgentState>,
    /// The node's port opener (its ingress bridge); `None` is an H1 agent.
    ports: Option<Arc<dyn PortOpener>>,
    /// The H2 node controls (the owner's share, the approval); `None` is an H1 agent.
    node: Option<NodeControls>,
    /// Where the streams the fake server opens arrive.
    incoming: Option<Arc<dyn StreamAcceptor>>,
    /// The node's owner, when the test needs it before the daemon starts (to open its volumes).
    owner: Option<AccountId>,
    /// The node's volumes (H2 §11.3); `None` is an agent that declares no `volumes`.
    volumes: Option<VolumeStore>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            handler: Arc::new(NotReady),
            handler_with_events: None,
            agent_lease_ttl: Duration::from_secs(45),
            earlier_state: None,
            ports: None,
            node: None,
            incoming: None,
            owner: None,
            volumes: None,
        }
    }
}

fn start(opts: Options) -> World {
    let owner = opts.owner.unwrap_or_else(AccountId::generate);
    let (acc_tx, accepted) = mpsc::unbounded_channel();
    let connector = Arc::new(PipeConnector {
        accepted: acc_tx,
        refuse: AtomicBool::new(false),
        attempts: Mutex::new(Vec::new()),
        rebinds: Mutex::new(Vec::new()),
        incoming: opts.incoming,
    });
    let (ev_tx, events) = mpsc::unbounded_channel();
    let handler = match opts.handler_with_events {
        Some(make) => make(ev_tx.clone()),
        None => opts.handler,
    };
    let supervisor = Arc::new(Supervisor {
        events: ev_tx,
        running: Mutex::new(Vec::new()),
        holding: Mutex::new(None),
        release: Notify::new(),
        stops: AtomicUsize::new(0),
    });
    let inventory = Arc::new(FakeInventory(
        Mutex::new(inventory("node-1")),
        Mutex::new(Duration::ZERO),
        AtomicUsize::new(0),
    ));
    let dir = tempfile::tempdir().unwrap();
    let state = StateFile::in_dir(dir.path());
    if let Some(earlier) = &opts.earlier_state {
        state.write(earlier);
    }
    let shared = Shared {
        owner,
        agent_lease_ttl: opts.agent_lease_ttl,
        watchdog: Watchdog::new(opts.agent_lease_ttl),
        supervisor: supervisor.clone(),
        handler,
        inventory: inventory.clone(),
        load: Arc::new(FixedLoad),
        inventory_interval: INVENTORY_INTERVAL,
        decisions: Arc::new(Semaphore::new(MAX_PENDING_DECISIONS)),
        uplink: Uplink::new(),
        ports: opts.ports,
        node: opts.node,
        volumes: opts.volumes,
    };
    let daemon = Daemon {
        shared,
        connector: connector.clone(),
        backoff_seed: 7,
        state_file: Some(state.clone()),
        server_node_id: SERVER_ID.into(),
        agent_node_id: AGENT_NODE_ID.into(),
    };
    let (stop, stop_rx) = watch::channel(false);
    let (network, net_rx) = mpsc::channel(4);
    let daemon = tokio::spawn(daemon.run(stop_rx, net_rx));
    World {
        owner,
        connector,
        accepted,
        events,
        supervisor,
        inventory,
        stop,
        network,
        daemon,
        _dir: dir,
        state,
    }
}

impl World {
    /// The state file is written off the runtime: wait (a few virtual milliseconds at most) for `expected`.
    async fn state_becomes(&self, expected: ConnectionState) {
        for _ in 0..200 {
            if self.state.read().is_some_and(|s| s.connection == expected) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("the state file never said {expected:?}: {:?}", self.state.read());
    }

    /// Like [`World::state_becomes`], for any condition on the state file.
    async fn state_matches(&self, what: &str, check: impl Fn(&AgentState) -> bool) {
        for _ in 0..200 {
            if self.state.read().is_some_and(|s| check(&s)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("the state file never had {what}: {:?}", self.state.read());
    }

    async fn next_connection(&mut self) -> ServerEnd {
        bounded("a new connection", self.accepted.recv()).await.unwrap()
    }

    async fn next_event(&mut self) -> (Instant, Event) {
        bounded("a supervisor event", self.events.recv()).await.unwrap()
    }

    async fn shutdown(self) -> DaemonExit {
        self.stop.send(true).unwrap();
        self.daemon.await.unwrap()
    }
}

fn lease_msg(account: AccountId, job: Value) -> (LeaseId, Value) {
    let id = LeaseId::generate();
    let msg = json!({
        "type": "lease",
        "lease_id": id,
        "epoch": 1,
        "job": job,
        "account_id": account,
        "deadline": "2030-01-01T00:00:00Z",
    });
    (id, msg)
}

fn good_job() -> Value {
    json!({
        "image": "docker.io/library/python:3.12-slim",
        "command": ["python", "-c", "print(6*7)"],
        "env": {"API_TOKEN": "s3cr3t-value-example"},
        "resources": {"cpu": 1, "memory_mb": 512},
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Hello / Welcome

#[tokio::test(start_paused = true)]
async fn hello_carries_the_version_an_empty_feature_list_the_inventory_and_the_running_leases() {
    let mut w = start(Options::default());
    let lease = RunningLease::new(LeaseId::generate(), 3);
    w.supervisor.running.lock().unwrap().push(lease);
    let mut s = w.next_connection().await;
    let hello = s.handshake(w.owner).await;
    assert_eq!(hello["agent_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(hello["features"], json!([]), "no capability in v0.1");
    assert_eq!(hello["inventory"]["hostname"], "node-1");
    assert_eq!(hello["running"], json!([{"lease_id": lease.lease_id, "epoch": 3}]));
    // Connected: the state file says so, with the Welcome time.
    let _ = s.recv().await; // the first heartbeat: the Welcome was processed
    let state = w.state.read().unwrap();
    assert_eq!(state.connection, ConnectionState::Connected);
    assert!(state.last_welcome_at.is_some());
    assert_eq!(state.server_node_id, SERVER_ID);
    let (_task, _rx) = s.serve(true);
    assert_eq!(w.shutdown().await, DaemonExit::Shutdown);
}

/// The server allows 10 s from the handshake to the first message (§6 "Before Join", T05's first-message
/// timeout). A detection that takes 14 s must therefore happen **before** the dial (T05b review, P2-1): the fake
/// server here enforces the deadline. Each connection still gets a fresh detection.
#[tokio::test(start_paused = true)]
async fn a_slow_detection_happens_before_the_dial_so_hello_beats_the_10_s_deadline() {
    const FIRST_MESSAGE_DEADLINE: Duration = Duration::from_secs(10);
    let mut w = start(Options::default());
    *w.inventory.1.lock().unwrap() = Duration::from_secs(14);
    for (round, hostname) in [(0, "node-1"), (1, "node-after-a-driver-install")] {
        let mut s = w.next_connection().await;
        let hello = tokio::time::timeout(FIRST_MESSAGE_DEADLINE, s.recv())
            .await
            .unwrap_or_else(|_| panic!("round {round}: no Hello within 10 s of the dial"))
            .unwrap();
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["inventory"]["hostname"], hostname, "fresh for every connection");
        s.welcome(w.owner, 60).await;
        let _ = s.recv().await; // a heartbeat: welcomed
        // A driver is installed, and the connection drops: the next Hello carries the new inventory.
        w.inventory.0.lock().unwrap().hostname = "node-after-a-driver-install".into();
        drop(s);
    }
    w.shutdown().await;
}

/// SI-1: a `Welcome` for another account is refused: the connection is closed, no lease is taken from it, and the
/// agent backs off and tries again.
#[tokio::test(start_paused = true)]
async fn a_welcome_for_another_account_is_refused() {
    let recorder = Arc::new(Recorder::default());
    let mut w = start(Options {
        handler: recorder.clone(),
        ..Options::default()
    });
    let mut s = w.next_connection().await;
    let _ = s.recv().await.unwrap();
    s.welcome(AccountId::generate(), 60).await;
    // A lease right behind it, for the other account's jobs: never handled.
    let (_, lease) = lease_msg(AccountId::generate(), good_job());
    s.send(lease).await;
    // The agent closes this connection without answering anything.
    assert_eq!(s.recv().await, None, "closed, and no LeaseAccepted/LeaseRejected");
    assert!(recorder.offers.lock().unwrap().is_empty());
    // It backs off (1 s base, jitter in [0.5, 1] s) and reconnects.
    let mut again = w.next_connection().await;
    let attempts = w.connector.attempts.lock().unwrap().clone();
    let gap = attempts[1] - attempts[0];
    assert!(
        gap >= Duration::from_millis(500) && gap <= Duration::from_secs(1),
        "{gap:?}"
    );
    w.state_becomes(ConnectionState::Connecting).await;
    let _ = again.handshake(w.owner).await;
    let (_task, _rx) = again.serve(true);
    w.shutdown().await;
}

/// SI-1 and SI-13: a server that only ever welcomes for another account is no contact: the lease timer runs out
/// 45 s after the agent started, however often that server answers.
#[tokio::test(start_paused = true)]
async fn a_wrong_owner_welcome_does_not_keep_jobs_alive() {
    let started = Instant::now();
    let mut w = start(Options::default());
    let mut accepted = std::mem::replace(&mut w.accepted, mpsc::unbounded_channel().1);
    let server = tokio::spawn(async move {
        while let Some(mut c) = accepted.recv().await {
            let _ = c.recv().await;
            c.welcome(AccountId::generate(), 60).await;
        }
    });
    let (at, event) = w.next_event().await;
    assert_eq!(event, Event::StopAll("lease_lost"));
    assert_eq!(at - started, Duration::from_secs(45));
    assert!(w.connector.attempts.lock().unwrap().len() > 3);
    server.abort();
    w.shutdown().await;
}

/// SI-13: a server `lease_ttl_s` too small for the configured agent timer lowers the agent's timer.
#[tokio::test(start_paused = true)]
async fn a_small_lease_ttl_lowers_the_agent_timer() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.recv().await.unwrap();
    s.welcome(w.owner, 40).await;
    let welcomed = Instant::now();
    // Never acknowledge anything: the timer runs out after 40 - 10 = 30 s, not 45.
    let (_task, _rx) = s.serve(false);
    let (at, event) = w.next_event().await;
    assert_eq!(event, Event::StopAll("lease_lost"));
    let after = at - welcomed;
    assert!(
        after >= Duration::from_secs(30) && after < Duration::from_secs(31),
        "{after:?}"
    );
    w.shutdown().await;
}

// ---------------------------------------------------------------------------------------------------------------
// Heartbeats and the lease timer (SI-13)

#[tokio::test(start_paused = true)]
async fn heartbeats_honour_the_interval_and_seq_increases_and_acks_keep_the_timer_alive() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let welcomed = Instant::now();
    let (_task, mut rx) = s.serve(true);
    let mut beats = Vec::new();
    while beats.len() < 40 {
        let m = rx.recv().await.unwrap();
        if m["type"] == "heartbeat" {
            beats.push((Instant::now() - welcomed, m));
        }
    }
    for (i, (at, m)) in beats.iter().enumerate() {
        let n = u64::try_from(i).unwrap() + 1;
        assert_eq!(m["seq"], json!(n));
        assert_eq!(*at, Duration::from_secs(5 * n), "heartbeat {n}");
        assert_eq!(m["load"]["cpu_pct"], 12);
        assert_eq!(m["load"]["mem_used_mb"], 2048);
        assert_eq!(m["running"], json!([]));
    }
    // 200 s with acks: the lease timer never fired.
    assert_eq!(w.supervisor.stops.load(Ordering::SeqCst), 0);
    assert!(w.events.try_recv().is_err());
    w.shutdown().await;
}

/// T06e (§6): `Heartbeat.running` lists the leases that hold resources, and a lease's release is followed by a
/// heartbeat at once, not at the next 5 s tick. `seq` goes on increasing, and the ticks keep their rhythm.
#[tokio::test(start_paused = true)]
async fn a_release_sends_a_heartbeat_at_once_listing_what_is_still_held() {
    let mut w = start(Options::default());
    let lease = |epoch| RunningLease::new(LeaseId::generate(), epoch);
    let (cleaning, running) = (lease(1), lease(2));
    // `Hello` lists the leases that run or whose report is unconfirmed; `Heartbeat` those that hold resources.
    *w.supervisor.running.lock().unwrap() = vec![running];
    *w.supervisor.holding.lock().unwrap() = Some(vec![cleaning, running]);
    let mut s = w.next_connection().await;
    let hello = s.handshake(w.owner).await;
    assert_eq!(hello["running"], json!([running]));
    let welcomed = Instant::now();
    let (_task, mut rx) = s.serve(true);
    let next_beat = async |rx: &mut mpsc::Receiver<Value>| loop {
        let m = rx.recv().await.unwrap();
        if m["type"] == "heartbeat" {
            return (Instant::now() - welcomed, m);
        }
    };
    let (at, first) = next_beat(&mut rx).await;
    assert_eq!((at, first["seq"].clone()), (Duration::from_secs(5), json!(1)));
    assert_eq!(
        first["running"],
        json!([cleaning, running]),
        "Heartbeat lists what holds resources"
    );

    // At 7 s the cleanup ends: the lease leaves the list and a heartbeat goes out at that very instant.
    tokio::time::sleep_until(welcomed + Duration::from_secs(7)).await;
    *w.supervisor.holding.lock().unwrap() = Some(vec![running]);
    w.supervisor.release.notify_one();
    let (at, now) = next_beat(&mut rx).await;
    assert_eq!(at, Duration::from_secs(7), "not at the 10 s tick");
    assert_eq!(now["seq"], json!(2), "seq keeps increasing");
    assert_eq!(
        now["running"],
        json!([running]),
        "the released lease is no longer listed"
    );

    // The periodic heartbeats go on at their own pace.
    let (at, tick) = next_beat(&mut rx).await;
    assert_eq!((at, tick["seq"].clone()), (Duration::from_secs(10), json!(3)));
    w.shutdown().await;
}

/// SI-13: no server message for 45 s: `stop_all("lease_lost")`, exactly once.
#[tokio::test(start_paused = true)]
async fn no_server_message_for_45_s_stops_all_jobs_exactly_once() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let last_message = Instant::now();
    // The server reads but never answers.
    let (_task, _rx) = s.serve(false);
    let (at, event) = w.next_event().await;
    assert_eq!(event, Event::StopAll("lease_lost"));
    assert_eq!(at - last_message, Duration::from_secs(45));
    // Much later: still exactly one call.
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert_eq!(w.supervisor.stops.load(Ordering::SeqCst), 1);
    w.shutdown().await;
}

/// SI-13: a server message that arrives late (here: the `Welcome` of a reconnect, 44 s after the last message)
/// starts the timer again. The precise 44 s case is in the watchdog's unit tests.
#[tokio::test(start_paused = true)]
async fn a_late_message_on_a_new_connection_resets_the_timer() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let last_message = Instant::now();
    // The server stops answering; the agent drops the silent connection (15 s) and reconnects on its own. The server
    // answers again only at 44 s, on a connection still waiting for its Welcome (each waits 15 s).
    let (_task, _rx) = s.serve(false);
    // Connections kept open and unanswered: each waits out its 15 s, so the next one comes after ~30 s.
    let mut unanswered = Vec::new();
    let mut late = loop {
        let mut c = w.next_connection().await;
        if Instant::now() - last_message >= Duration::from_secs(29) {
            break c;
        }
        let _ = c.recv().await; // its Hello
        unanswered.push(c);
    };
    let _ = late.recv().await.unwrap();
    tokio::time::sleep_until(last_message + Duration::from_secs(44)).await;
    late.welcome(w.owner, 60).await;
    let reset_at = Instant::now();
    let (_late_task, _late_rx) = late.serve(true);
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(
        w.supervisor.stops.load(Ordering::SeqCst),
        0,
        "the message before 45 s kept the jobs running ({:?} after the last one)",
        reset_at - last_message
    );
    w.shutdown().await;
}

/// SI-13: the timer keeps running while the agent is disconnected and backing off.
#[tokio::test(start_paused = true)]
async fn the_timer_keeps_running_while_disconnected() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let last_message = Instant::now();
    // The server goes away and refuses every reconnect.
    w.connector.refuse.store(true, Ordering::SeqCst);
    drop(s);
    let (at, event) = w.next_event().await;
    assert_eq!(event, Event::StopAll("lease_lost"));
    assert_eq!(at - last_message, Duration::from_secs(45));
    assert!(
        w.connector.attempts.lock().unwrap().len() > 3,
        "it kept trying meanwhile"
    );
    w.state_becomes(ConnectionState::BackingOff).await;
    w.shutdown().await;
}

// ---------------------------------------------------------------------------------------------------------------
// Backoff

/// While leases run, reconnect attempts are at most 5 s apart; after a `Welcome` the backoff starts again from 1 s.
#[tokio::test(start_paused = true)]
async fn backoff_is_capped_at_5_s_with_running_leases_and_reset_after_welcome() {
    let mut w = start(Options::default());
    w.supervisor
        .running
        .lock()
        .unwrap()
        .push(RunningLease::new(LeaseId::generate(), 1));
    w.connector.refuse.store(true, Ordering::SeqCst);
    // Let it fail for a while.
    tokio::time::sleep(Duration::from_secs(120)).await;
    let attempts = w.connector.attempts.lock().unwrap().clone();
    assert!(attempts.len() > 20, "{}", attempts.len());
    for pair in attempts.windows(2) {
        assert!(pair[1] - pair[0] <= Duration::from_secs(5), "{:?}", pair[1] - pair[0]);
    }
    // Without leases the cap is 30 s, and the delays have grown past 5 s.
    w.supervisor.running.lock().unwrap().clear();
    tokio::time::sleep(Duration::from_secs(300)).await;
    let attempts = w.connector.attempts.lock().unwrap().clone();
    let gaps: Vec<Duration> = attempts.windows(2).map(|p| p[1] - p[0]).collect();
    assert!(gaps.iter().any(|g| *g > Duration::from_secs(5)), "{gaps:?}");
    assert!(gaps.iter().all(|g| *g <= Duration::from_secs(30)), "{gaps:?}");
    // A Welcome resets it: the next failure waits at most 1 s.
    w.connector.refuse.store(false, Ordering::SeqCst);
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let _ = s.recv().await;
    let welcomed_attempts = w.connector.attempts.lock().unwrap().len();
    drop(s);
    let mut again = w.next_connection().await;
    let attempts = w.connector.attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), welcomed_attempts + 1);
    let gap = attempts[attempts.len() - 1] - attempts[attempts.len() - 2];
    assert!(
        gap <= Duration::from_secs(6),
        "about 1 s after the drop, not 30: {gap:?}"
    );
    let _ = again.handshake(w.owner).await;
    let (_task, _rx) = again.serve(true);
    w.shutdown().await;
}

/// A network change re-binds and reconnects at once, without a backoff delay.
#[tokio::test(start_paused = true)]
async fn a_network_change_rebinds_and_reconnects_at_once() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let (_task, _rx) = s.serve(true);
    let changed = Instant::now();
    w.network
        .send(AddressChange {
            addrs: Vec::new(),
            interfaces: Vec::new(),
        })
        .await
        .unwrap();
    let mut again = w.next_connection().await;
    assert!(
        Instant::now() - changed < Duration::from_millis(500),
        "no backoff delay"
    );
    assert_eq!(w.connector.rebinds.lock().unwrap().len(), 1);
    let _ = again.handshake(w.owner).await;
    let (_task2, _rx2) = again.serve(true);
    w.shutdown().await;
}

// ---------------------------------------------------------------------------------------------------------------
// InventoryUpdate

#[tokio::test(start_paused = true)]
async fn inventory_update_is_sent_only_on_a_change() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let (_task, mut rx) = s.serve(true);
    // 25 minutes, two re-detections, nothing changed: no update.
    tokio::time::sleep(Duration::from_secs(25 * 60)).await;
    let mut updates = 0;
    while let Ok(m) = rx.try_recv() {
        updates += usize::from(m["type"] == "inventory_update");
    }
    assert_eq!(updates, 0);
    // A driver is installed: the next re-detection (at 30 min) sends the new inventory, once.
    w.inventory.0.lock().unwrap().hostname = "node-renamed".into();
    tokio::time::sleep(Duration::from_secs(25 * 60)).await;
    let mut sent = Vec::new();
    while let Ok(m) = rx.try_recv() {
        if m["type"] == "inventory_update" {
            sent.push(m);
        }
    }
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["inventory"]["hostname"], "node-renamed");
    w.shutdown().await;
}

// ---------------------------------------------------------------------------------------------------------------
// Routing

#[tokio::test(start_paused = true)]
async fn a_lease_gets_agent_not_ready_by_default() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let (id, lease) = lease_msg(w.owner, good_job());
    s.send(lease).await;
    let answer = s.recv_not_heartbeat().await.unwrap();
    assert_eq!(
        answer,
        json!({"type": "lease_rejected", "lease_id": id, "epoch": 1, "reason": "agent_not_ready"})
    );
    // A cancel for that unknown lease is ignored, and the connection stays up.
    s.send(json!({"type": "cancel", "lease_id": id, "epoch": 1, "reason": "user"}))
        .await;
    s.send(json!({"type": "drain"})).await;
    assert_eq!(w.next_event().await.1, Event::Drain);
    let (_task, _rx) = s.serve(true);
    w.shutdown().await;
}

/// SI-1 and §6 "must understand": a lease for another account gets `not_owner`, a job the agent does not accept gets
/// `invalid_job`; neither reaches the handler, and the connection stays open.
#[tokio::test(start_paused = true)]
async fn si1_not_owner_is_refused_before_anything() {
    let recorder = Arc::new(Recorder::default());
    let mut w = start(Options {
        handler: recorder.clone(),
        ..Options::default()
    });
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let (other, lease) = lease_msg(AccountId::generate(), good_job());
    s.send(lease).await;
    let answer = s.recv_not_heartbeat().await.unwrap();
    assert_eq!(answer["type"], "lease_rejected");
    assert_eq!(answer["lease_id"], json!(other));
    assert_eq!(answer["reason"], "not_owner");
    let bad_jobs = [
        json!({"image": "docker.io/library/python:3.12-slim", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 512}, "from_the_future": 1}),
        json!({"image": "docker.io/library/python:3.12-slim", "command": ["true"], "env": {"BAD": "a\nINJECTED=1"}, "resources": {"cpu": 1, "memory_mb": 512}}),
        json!({"image": "docker.io/library/python:3.12-slim", "command": ["true"], "files": [{"path": "/etc/passwd", "content_b64": ""}], "resources": {"cpu": 1, "memory_mb": 512}}),
        json!({"command": ["true"]}),
    ];
    for job in bad_jobs {
        let (id, lease) = lease_msg(w.owner, job.clone());
        s.send(lease).await;
        let answer = s.recv_not_heartbeat().await.unwrap();
        assert_eq!(answer["lease_id"], json!(id), "{job}");
        assert_eq!(answer["reason"], "invalid_job", "{job}");
    }
    assert!(recorder.offers.lock().unwrap().is_empty(), "no handler saw any of them");
    // A good lease for the owner reaches the handler, on the same connection.
    let (id, lease) = lease_msg(w.owner, good_job());
    s.send(lease).await;
    let answer = s.recv_not_heartbeat().await.unwrap();
    assert_eq!(answer, json!({"type": "lease_accepted", "lease_id": id, "epoch": 1}));
    assert_eq!(*recorder.offers.lock().unwrap(), [id]);
    s.send(json!({"type": "cancel", "lease_id": id, "epoch": 1, "reason": "user"}))
        .await;
    s.send(json!({"type": "resume"})).await;
    assert_eq!(w.next_event().await.1, Event::Resume);
    assert_eq!(*recorder.cancels.lock().unwrap(), [id]);
    assert_eq!(w.connector.attempts.lock().unwrap().len(), 1, "never reconnected");
    let (_task, _rx) = s.serve(true);
    w.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn drain_and_resume_reach_the_supervisor_and_unknown_messages_are_ignored() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    s.send(json!({"type": "drain"})).await;
    s.send(json!({"type": "a_message_from_a_newer_server", "with": ["fields"]}))
        .await;
    s.send(json!({"type": "error", "code": "unsupported_message", "message": "x"}))
        .await;
    s.send(json!({"type": "resume"})).await;
    assert_eq!(w.next_event().await.1, Event::Drain);
    assert_eq!(w.next_event().await.1, Event::Resume);
    assert_eq!(
        w.connector.attempts.lock().unwrap().len(),
        1,
        "the unknown message did not close anything"
    );
    let (_task, _rx) = s.serve(true);
    w.shutdown().await;
}

/// H2 §6.1: `NodeApproved` is not used yet, and `VolumeDelete` is for agents that declared `volumes`: an agent
/// that did not ignores both, like an unknown type, and nothing closes.
#[tokio::test(start_paused = true)]
async fn h2_server_messages_are_ignored_for_now() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    s.send(json!({"type": "drain"})).await;
    s.send(json!({"type": "volume_delete", "name": "cache"})).await;
    s.send(json!({"type": "node_approved"})).await;
    s.send(json!({"type": "resume"})).await;
    assert_eq!(w.next_event().await.1, Event::Drain);
    assert_eq!(w.next_event().await.1, Event::Resume);
    assert_eq!(
        w.connector.attempts.lock().unwrap().len(),
        1,
        "the H2 messages did not close anything"
    );
    let (_task, _rx) = s.serve(true);
    w.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn not_enrolled_and_agent_too_old_stop_the_agent_with_their_exit_codes() {
    for (code, exit_code, state) in [
        ("not_enrolled", exit::NOT_ENROLLED, ConnectionState::NotEnrolled),
        ("agent_too_old", exit::AGENT_TOO_OLD, ConnectionState::AgentTooOld),
    ] {
        // Before the Welcome (the answer to Hello) ...
        let mut w = start(Options::default());
        let mut s = w.next_connection().await;
        let _ = s.recv().await.unwrap();
        s.send(json!({"type": "error", "code": code, "message": "x"})).await;
        let end = w.daemon.await.unwrap();
        assert_eq!(end.code(), exit_code, "{code}");
        assert_eq!(w.state.read().unwrap().connection, state);
        // The running jobs were stopped before the agent exited, with the code as the reason.
        assert_eq!(w.events.try_recv().map(|e| e.1), Ok(Event::StopAll(code)), "{code}");
        assert_eq!(w.supervisor.stops.load(Ordering::SeqCst), 1);
        // ... and after it.
        let mut w = start(Options::default());
        let mut s = w.next_connection().await;
        let _ = s.handshake(w.owner).await;
        s.send(json!({"type": "error", "code": code, "message": "x"})).await;
        assert_eq!(w.daemon.await.unwrap().code(), exit_code, "{code}");
        assert_eq!(w.events.try_recv().map(|e| e.1), Ok(Event::StopAll(code)), "{code}");
    }
}

/// SI-10: a malformed frame from the server closes the connection; the agent reconnects.
#[tokio::test(start_paused = true)]
async fn a_malformed_frame_closes_the_connection() {
    use tokio::io::AsyncWriteExt as _;
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    s.w.write_all(&[0, 0, 0, 3, b'{', b'{', b'{']).await.unwrap();
    let mut again = w.next_connection().await;
    let _ = again.handshake(w.owner).await;
    let (_task, _rx) = again.serve(true);
    assert_eq!(w.shutdown().await, DaemonExit::Shutdown);
}

/// A server that welcomes and then stays silent is dropped after three heartbeats, and the agent reconnects.
#[tokio::test(start_paused = true)]
async fn a_silent_server_is_dropped_and_reconnected() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let welcomed = Instant::now();
    let (_task, _rx) = s.serve(false);
    let _again = w.next_connection().await;
    let after = Instant::now() - welcomed;
    assert!(
        after >= Duration::from_secs(15) && after <= Duration::from_secs(17),
        "{after:?}"
    );
    w.shutdown().await;
}

/// A handler that never decides, to fill the decision slots and hit the decision timeout.
#[derive(Debug, Default)]
struct Undecided(AtomicUsize);

impl LeaseHandler for Undecided {
    fn lease(&self, _offer: LeaseOffer) -> BoxFuture<'_, LeaseDecision> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::pending())
    }

    fn cancel(&self, _lease_id: LeaseId, _epoch: u64, _reason: String) -> BoxFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
}

/// At most 16 decisions in flight: the 17th lease is refused with `insufficient_capacity` at once. A decision that
/// takes longer than 8 s is answered `agent_not_ready`, within the server's 10 s. A `cancel` that never returns does
/// not stall the connection.
#[tokio::test(start_paused = true)]
async fn the_decision_cap_and_the_decision_timeout() {
    let handler = Arc::new(Undecided::default());
    let mut w = start(Options {
        handler: handler.clone(),
        ..Options::default()
    });
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let sent_at = Instant::now();
    let mut ids = Vec::new();
    for _ in 0..=MAX_PENDING_DECISIONS {
        let (id, lease) = lease_msg(w.owner, good_job());
        s.send(lease).await;
        ids.push(id);
    }
    let first = s.recv_not_heartbeat().await.unwrap();
    assert_eq!(
        first["lease_id"],
        json!(ids[MAX_PENDING_DECISIONS]),
        "the 17th, at once"
    );
    assert_eq!(first["reason"], "insufficient_capacity");
    assert_eq!(Instant::now() - sent_at, Duration::ZERO);
    assert_eq!(handler.0.load(Ordering::SeqCst), MAX_PENDING_DECISIONS);
    // A cancel that never returns is abandoned after its budget; meanwhile acks keep arriving.
    s.send(json!({"type": "cancel", "lease_id": ids[0], "epoch": 1, "reason": "user"}))
        .await;
    let mut timed_out = std::collections::BTreeSet::new();
    while timed_out.len() < MAX_PENDING_DECISIONS {
        let m = s.recv().await.unwrap();
        if m["type"] == "heartbeat" {
            let seq = m["seq"].clone();
            s.send(json!({"type": "heartbeat_ack", "seq": seq})).await;
            continue;
        }
        assert_eq!(m["type"], "lease_rejected");
        assert_eq!(m["reason"], "agent_not_ready");
        assert_eq!(Instant::now() - sent_at, Duration::from_secs(8), "the decision budget");
        timed_out.insert(m["lease_id"].as_str().unwrap().to_string());
    }
    assert_eq!(
        w.connector.attempts.lock().unwrap().len(),
        1,
        "the connection stayed up"
    );
    // The slots are free again: a new lease reaches the handler.
    let (_, lease) = lease_msg(w.owner, good_job());
    s.send(lease).await;
    let (_task, _rx) = s.serve(true);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(handler.0.load(Ordering::SeqCst), MAX_PENDING_DECISIONS + 1);
    w.shutdown().await;
}

/// SI-10: a frame that decodes but fails `validate()` (an error message over the text limit) closes the
/// connection; the agent reconnects.
#[tokio::test(start_paused = true)]
async fn a_message_that_fails_validation_closes_the_connection() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let long = "x".repeat(2000);
    s.send(json!({"type": "error", "code": "something", "message": long}))
        .await;
    let mut again = w.next_connection().await;
    assert_eq!(w.connector.attempts.lock().unwrap().len(), 2);
    let _ = again.handshake(w.owner).await;
    let (_task, _rx) = again.serve(true);
    assert_eq!(w.shutdown().await, DaemonExit::Shutdown);
}

/// T05b review P3: in the handshake only a Welcome for the owner is contact. A server that answers every Hello with an
/// Error keeps no job alive: `lease_lost` fires 45 s after the start.
#[tokio::test(start_paused = true)]
async fn errors_in_the_handshake_do_not_reset_the_lease_timer() {
    let started = Instant::now();
    let mut w = start(Options::default());
    let mut accepted = std::mem::replace(&mut w.accepted, mpsc::unbounded_channel().1);
    let server = tokio::spawn(async move {
        while let Some(mut c) = accepted.recv().await {
            let _ = c.recv().await;
            c.send(json!({"type": "error", "code": "x", "message": "not now"}))
                .await;
        }
    });
    // Bounded: if errors reset the timer, it never fires, and this fails instead of spinning.
    let (at, event) = tokio::time::timeout(Duration::from_secs(120), w.next_event())
        .await
        .expect("lease_lost never fired: the handshake errors kept the jobs alive");
    assert_eq!(event, Event::StopAll("lease_lost"));
    assert_eq!(at - started, Duration::from_secs(45));
    assert!(w.connector.attempts.lock().unwrap().len() > 3, "it kept trying");
    server.abort();
    w.shutdown().await;
}

/// T05b review P3: a detection that takes 15 s (a hung GPU tool) does not run before every dial during an outage. The
/// inventory of a failed dial is reused, so with a lease running the agent retries at least every 5 s and reconnects
/// within 5 s of the server coming back, well before the 45 s lease timer.
#[tokio::test(start_paused = true)]
async fn a_slow_detection_is_not_repeated_before_every_dial_during_an_outage() {
    let mut w = start(Options::default());
    w.supervisor
        .running
        .lock()
        .unwrap()
        .push(RunningLease::new(LeaseId::generate(), 1));
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let _ = s.recv().await;
    *w.inventory.1.lock().unwrap() = Duration::from_secs(15);
    let detections_before = w.inventory.2.load(Ordering::SeqCst);
    // The server goes away; the agent's lease timer counts from the last message.
    w.connector.refuse.store(true, Ordering::SeqCst);
    let last_contact = Instant::now();
    drop(s);
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_eq!(
        w.inventory.2.load(Ordering::SeqCst) - detections_before,
        1,
        "one detection for the whole outage, not one per dial"
    );
    // Back at 30 s: Hello within the 5 s cap of the backoff with leases.
    w.connector.refuse.store(false, Ordering::SeqCst);
    let back = Instant::now();
    let mut again = w.next_connection().await;
    let _ = again.handshake(w.owner).await;
    assert!(
        Instant::now() - back <= Duration::from_secs(5),
        "{:?}",
        Instant::now() - back
    );
    assert!(Instant::now() - last_contact < Duration::from_secs(45));
    let (_task, _rx) = again.serve(true);
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(w.supervisor.stops.load(Ordering::SeqCst), 0, "no lease_lost");
    w.shutdown().await;
}

/// T05b review P3: `run` keeps the last Welcome of this enrollment across a restart, and only of this enrollment. An
/// enrollment is the server **and** this node's ID on it: a `join --force` to the same server is a new one (T05b
/// real run, round 2).
#[tokio::test(start_paused = true)]
async fn the_last_welcome_survives_a_restart_of_run_for_the_same_enrollment() {
    let at = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    for (server, node, kept) in [
        (SERVER_ID, Some(AGENT_NODE_ID), true),
        ("another-server", Some(AGENT_NODE_ID), false),
        (SERVER_ID, Some("node_01JBQ7AAAAAAAAAAAAAAAAAAAA"), false),
        (SERVER_ID, None, false),
    ] {
        let mut earlier = AgentState::new(ConnectionState::Stopped, at, server.into(), node.map(String::from));
        earlier.last_welcome_at = Some(at);
        let w = start(Options {
            earlier_state: Some(earlier),
            ..Options::default()
        });
        w.connector.refuse.store(true, Ordering::SeqCst);
        w.state_becomes(ConnectionState::BackingOff).await;
        let state = w.state.read().unwrap();
        assert_eq!(state.server_node_id, SERVER_ID);
        assert_eq!(state.agent_node_id.as_deref(), Some(AGENT_NODE_ID));
        assert_eq!(state.last_welcome_at, kept.then_some(at), "{server} {node:?}");
        w.shutdown().await;
    }
}

/// A handler whose decisions never end; each one reports, when it is dropped, that it was aborted.
#[derive(Debug)]
struct Hanging(mpsc::UnboundedSender<(Instant, Event)>);

struct DropReport(mpsc::UnboundedSender<(Instant, Event)>);

impl Drop for DropReport {
    fn drop(&mut self) {
        let _ = self.0.send((Instant::now(), Event::DecisionDropped));
    }
}

impl LeaseHandler for Hanging {
    fn lease(&self, _offer: LeaseOffer) -> BoxFuture<'_, LeaseDecision> {
        let guard = DropReport(self.0.clone());
        Box::pin(async move {
            let _guard = guard;
            std::future::pending().await
        })
    }

    fn cancel(&self, _lease_id: LeaseId, _epoch: u64, _reason: String) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

fn hanging() -> Options {
    Options {
        handler_with_events: Some(Box::new(|events| Arc::new(Hanging(events)) as Arc<dyn LeaseHandler>)),
        ..Options::default()
    }
}

/// T05b review (carry-over to T10a): a lease decision belongs to its session. When the connection drops, the decision
/// still in progress is aborted before the agent dials again: with the real executor, a job could otherwise start
/// for a connection that no longer exists.
#[tokio::test(start_paused = true)]
async fn a_lease_decision_does_not_outlive_its_session() {
    let mut w = start(hanging());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let (_, lease) = lease_msg(w.owner, good_job());
    s.send(lease).await;
    // The decision is in progress; then the connection is lost.
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(w.events.try_recv().is_err(), "still deciding");
    drop(s);
    let mut again = w.next_connection().await;
    assert_eq!(
        w.events.try_recv().map(|e| e.1),
        Ok(Event::DecisionDropped),
        "aborted before the next dial"
    );
    let _ = again.handshake(w.owner).await;
    let (_task, _rx) = again.serve(true);
    w.shutdown().await;
}

/// The same, on the way out: `not_enrolled` aborts the decision in progress **before** `stop_all`, so no job can start
/// after the jobs were stopped.
#[tokio::test(start_paused = true)]
async fn decisions_in_progress_are_aborted_before_stop_all() {
    let mut w = start(hanging());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let (_, lease) = lease_msg(w.owner, good_job());
    s.send(lease).await;
    // The decision is under way (one that never began is simply never run).
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(w.events.try_recv().is_err(), "still deciding");
    s.send(json!({"type": "error", "code": "not_enrolled", "message": "removed"}))
        .await;
    assert_eq!(w.daemon.await.unwrap(), DaemonExit::NotEnrolled);
    assert_eq!(w.events.try_recv().map(|e| e.1), Ok(Event::DecisionDropped));
    assert_eq!(w.events.try_recv().map(|e| e.1), Ok(Event::StopAll("not_enrolled")));
}

/// No checkpointing in v0.1 (§9): a stopped agent (SIGTERM) stops its jobs before it exits, so no container
/// outlives it.
#[tokio::test(start_paused = true)]
async fn shutdown_stops_every_job_before_the_agent_exits() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let (_task, _rx) = s.serve(true);
    let mut events = std::mem::replace(&mut w.events, mpsc::unbounded_channel().1);
    assert_eq!(w.shutdown().await, DaemonExit::Shutdown);
    assert_eq!(events.try_recv().map(|e| e.1), Ok(Event::StopAll("shutdown")));
}

// ---------------------------------------------------------------------------------------------------------------
// Service ports (H2 §6.1): the capability, service leases, and the streams the server opens

/// The agent's sending half of a server-opened stream, over a pipe.
struct PipeSend(DuplexStream);

impl tokio::io::AsyncWrite for PipeSend {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl HubSend for PipeSend {
    fn reset(&mut self, _code: u32) {}
}

/// The agent's receiving half of a server-opened stream, over a pipe.
struct PipeRecv(DuplexStream);

impl tokio::io::AsyncRead for PipeRecv {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl HubRecv for PipeRecv {
    fn stop(&mut self, _code: u32) {}
}

/// The streams the fake server opened, in order.
#[derive(Debug)]
struct PipeAcceptor(tokio::sync::Mutex<mpsc::UnboundedReceiver<HubStream>>);

impl StreamAcceptor for PipeAcceptor {
    fn accept(&self) -> BoxFuture<'_, Result<HubStream, ConnectError>> {
        Box::pin(async move {
            match self.0.lock().await.recv().await {
                Some(stream) => Ok(stream),
                None => Err(ConnectError("no more streams".into())),
            }
        })
    }
}

/// The fake server's end of a stream it opened.
struct ServerStream {
    to_agent: DuplexStream,
    from_agent: DuplexStream,
}

/// The fake server opens a stream on the agent's connection.
fn open_stream(streams: &mpsc::UnboundedSender<HubStream>) -> ServerStream {
    let (agent_send, from_agent) = tokio::io::duplex(64 * 1024);
    let (to_agent, agent_recv) = tokio::io::duplex(64 * 1024);
    let stream = HubStream {
        send: Box::new(PipeSend(agent_send)),
        recv: Box::new(PipeRecv(agent_recv)),
    };
    streams.send(stream).unwrap();
    ServerStream { to_agent, from_agent }
}

/// A port opener that connects every port to an echo, and records what it was asked for.
#[derive(Debug, Default)]
struct EchoPorts {
    opened: Mutex<Vec<PortOpen>>,
}

impl PortOpener for EchoPorts {
    fn open<'a>(&'a self, open: &'a PortOpen) -> BoxFuture<'a, Result<Box<dyn PortIo>, &'static str>> {
        self.opened.lock().unwrap().push(open.clone());
        Box::pin(async move {
            let (agent, service) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(service);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Ok(Box::new(agent) as Box<dyn PortIo>)
        })
    }
}

fn service_job() -> Value {
    json!({
        "kind": "service",
        "image": "docker.io/library/python:3.12-slim",
        "command": ["python", "-m", "http.server", "8080"],
        "resources": {"cpu": 1, "memory_mb": 512},
        "service": {"ports": [{"port": 8080, "name": "web"}]},
    })
}

/// H2 §6.1: an agent whose node can serve the ports of a service declares `service_jobs` and takes service leases.
/// Without that it is an H1 agent: no capability, and a service lease is `invalid_job` before any handler sees it.
#[tokio::test(start_paused = true)]
async fn service_jobs_is_declared_and_service_leases_are_taken_only_with_a_port_opener() {
    for with_ports in [false, true] {
        let recorder = Arc::new(Recorder::default());
        let mut w = start(Options {
            handler: recorder.clone(),
            ports: with_ports.then(|| Arc::new(EchoPorts::default()) as Arc<dyn PortOpener>),
            ..Options::default()
        });
        let mut s = w.next_connection().await;
        let hello = s.handshake(w.owner).await;
        let expected = if with_ports { json!(["service_jobs"]) } else { json!([]) };
        assert_eq!(hello["features"], expected, "with_ports = {with_ports}");
        let (id, lease) = lease_msg(w.owner, service_job());
        s.send(lease).await;
        let answer = s.recv_not_heartbeat().await.unwrap();
        if with_ports {
            assert_eq!(answer, json!({"type": "lease_accepted", "lease_id": id, "epoch": 1}));
            assert_eq!(*recorder.offers.lock().unwrap(), [id]);
        } else {
            assert_eq!(
                answer,
                json!({"type": "lease_rejected", "lease_id": id, "epoch": 1, "reason": "invalid_job"})
            );
            assert!(recorder.offers.lock().unwrap().is_empty());
        }
        // A batch lease is taken either way.
        let (batch, lease) = lease_msg(w.owner, good_job());
        s.send(lease).await;
        let answer = s.recv_not_heartbeat().await.unwrap();
        assert_eq!(answer, json!({"type": "lease_accepted", "lease_id": batch, "epoch": 1}));
        let (_task, _rx) = s.serve(true);
        assert_eq!(w.shutdown().await, DaemonExit::Shutdown);
    }
}

/// H2 §6.1: the streams the server opens are served once the session is welcomed, never before, and they end with
/// the session.
#[tokio::test(start_paused = true)]
async fn the_servers_streams_are_served_only_after_the_welcome_and_end_with_the_session() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (streams, accepted) = mpsc::unbounded_channel();
    let ports = Arc::new(EchoPorts::default());
    let mut w = start(Options {
        ports: Some(ports.clone()),
        incoming: Some(Arc::new(PipeAcceptor(tokio::sync::Mutex::new(accepted)))),
        ..Options::default()
    });
    let lease = LeaseId::generate();
    let port_open = json!({"type": "port_open", "lease_id": lease, "epoch": 4, "port": 8080, "conn_id": 9});
    let mut s = w.next_connection().await;
    assert_eq!(s.recv().await.unwrap()["type"], "hello");

    // Before its Welcome the server opens a stream: nothing takes it.
    let mut early = open_stream(&streams);
    write_frame(&mut early.to_agent, &port_open).await.unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        ports.opened.lock().unwrap().is_empty(),
        "a stream was served before the Welcome"
    );

    // Welcomed: it is served, with the agent's ack first and then the bytes of the port.
    s.welcome(w.owner, 60).await;
    let ack: Value = read_frame(&mut early.from_agent, MAX_FRAME_LEN).await.unwrap().unwrap();
    assert_eq!(ack, json!({"ok": true}));
    assert_eq!(
        *ports.opened.lock().unwrap(),
        [PortOpen {
            lease_id: lease,
            epoch: 4,
            port: 8080,
            conn_id: 9
        }]
    );
    early.to_agent.write_all(b"ping").await.unwrap();
    drop(early.to_agent);
    let mut echoed = Vec::new();
    early.from_agent.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"ping");

    // A stream that is open when the connection goes away ends with it.
    let mut open = open_stream(&streams);
    write_frame(&mut open.to_agent, &port_open).await.unwrap();
    let ack: Value = read_frame(&mut open.from_agent, MAX_FRAME_LEN).await.unwrap().unwrap();
    assert_eq!(ack, json!({"ok": true}));
    drop(s);
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), open.from_agent.read_to_end(&mut rest))
        .await
        .expect("the port stream outlived its session")
        .unwrap();
    assert!(rest.is_empty());

    // The next session serves streams again.
    let mut s = w.next_connection().await;
    s.handshake(w.owner).await;
    let mut again = open_stream(&streams);
    write_frame(&mut again.to_agent, &port_open).await.unwrap();
    let ack: Value = read_frame(&mut again.from_agent, MAX_FRAME_LEN).await.unwrap().unwrap();
    assert_eq!(ack, json!({"ok": true}));
    let (_task, _rx) = s.serve(true);
    assert_eq!(w.shutdown().await, DaemonExit::Shutdown);
}

// ---------------------------------------------------------------------------------------------------------------
// H2 node controls (T2-23): the owner's pause and share changes, the node's approval, and `leave`.

fn node_controls() -> (NodeControls, watch::Sender<Share>) {
    let (tx, rx) = watch::channel(Share::default());
    (
        NodeControls {
            share: rx,
            approval: Approval::new(),
        },
        tx,
    )
}

/// H2 §5.5, §6.1: an H2 node declares `leave` and `approval`; `Welcome.pending_approval` and `NodeApproved` reach the
/// state file that `p2pc-agent status --json` reads, with the hub's version (H2 §14.2).
#[tokio::test(start_paused = true)]
async fn an_h2_node_declares_leave_and_approval_and_the_state_file_follows_the_approval() {
    let (node, _share) = node_controls();
    let approval = node.approval.clone();
    let mut w = start(Options {
        node: Some(node),
        ..Options::default()
    });
    let mut s = w.next_connection().await;
    let hello = s.recv().await.unwrap();
    assert_eq!(hello["features"], json!(["leave", "approval"]));
    assert_eq!(approval.pending(), None, "unknown before the first Welcome");
    s.send(json!({
        "type": "welcome",
        "server_version": "0.2.0",
        "node_id": NodeId::generate(),
        "account_id": w.owner,
        "heartbeat_interval_s": 5,
        "lease_ttl_s": 60,
        "pending_approval": true,
    }))
    .await;
    let _ = s.recv().await; // a heartbeat: welcomed
    assert_eq!(approval.pending(), Some(true));
    w.state_matches("pending_approval and the hub version", |st| {
        st.connection == ConnectionState::Connected
            && st.pending_approval == Some(true)
            && st.server_version.as_deref() == Some("0.2.0")
    })
    .await;
    // An admin approves the node: the state file says so at once, in the middle of the session.
    s.send(json!({"type": "node_approved"})).await;
    s.send(json!({"type": "drain"})).await;
    assert_eq!(w.next_event().await.1, Event::Drain);
    assert_eq!(approval.pending(), Some(false));
    w.state_matches("the approval", |st| st.pending_approval == Some(false))
        .await;
    // A later Welcome without the field (absent means false) keeps it approved.
    drop(s);
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let _ = s.recv().await;
    assert_eq!(approval.pending(), Some(false));
    let (_task, _rx) = s.serve(true);
    w.shutdown().await;
}

/// H2 §6.1, §8.4: while the owner paused sharing, a new lease of the owner gets `draining` and never reaches the
/// handler; the owner check comes first (SI-1); a resume reconnects (a new `Hello`), and the new session takes leases
/// again.
#[tokio::test(start_paused = true)]
async fn a_paused_node_refuses_new_leases_with_draining_until_resumed() {
    let recorder = Arc::new(Recorder::default());
    let (node, share) = node_controls();
    share.send_replace(Share {
        paused: true,
        ..Share::default()
    });
    let mut w = start(Options {
        handler: recorder.clone(),
        node: Some(node),
        ..Options::default()
    });
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let (other, lease) = lease_msg(AccountId::generate(), good_job());
    s.send(lease).await;
    let answer = s.recv_not_heartbeat().await.unwrap();
    assert_eq!(answer["lease_id"], json!(other));
    assert_eq!(answer["reason"], "not_owner", "SI-1 before the pause");
    let (id, lease) = lease_msg(w.owner, good_job());
    s.send(lease).await;
    let answer = s.recv_not_heartbeat().await.unwrap();
    assert_eq!(
        answer,
        json!({"type": "lease_rejected", "lease_id": id, "epoch": 1, "reason": "draining"})
    );
    assert!(recorder.offers.lock().unwrap().is_empty());
    // Resume: a new connection (review P2, see `a_resume_reconnects_at_once_…`), which takes leases again.
    share.send_replace(Share::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let (id, lease) = lease_msg(w.owner, good_job());
    s.send(lease).await;
    let answer = s.recv_not_heartbeat().await.unwrap();
    assert_eq!(answer, json!({"type": "lease_accepted", "lease_id": id, "epoch": 1}));
    assert_eq!(*recorder.offers.lock().unwrap(), [id]);
    assert_eq!(w.connector.attempts.lock().unwrap().len(), 2);
    let (_task, _rx) = s.serve(true);
    w.shutdown().await;
}

/// H2 §8.4: a share change re-detects the inventory at once, and a changed offer goes out as `InventoryUpdate` within
/// seconds, not at the 10-minute tick. A change that leaves the inventory as it was sends nothing.
#[tokio::test(start_paused = true)]
async fn a_share_change_sends_inventory_update_within_seconds() {
    let (node, share) = node_controls();
    let mut w = start(Options {
        node: Some(node),
        ..Options::default()
    });
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let (_task, mut rx) = s.serve(true);
    let detections = w.inventory.2.load(Ordering::SeqCst);
    // The pause alone does not change the wire inventory: a detection, but no update.
    share.send_replace(Share {
        paused: true,
        ..Share::default()
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(w.inventory.2.load(Ordering::SeqCst), detections + 1);
    while let Ok(m) = rx.try_recv() {
        assert_ne!(m["type"], "inventory_update", "{m}");
    }
    // Fewer cores offered (still paused, so the session stays): the new offer is sent at once.
    w.inventory.0.lock().unwrap().offered =
        serde_json::from_value(json!({"cpu": 2.0, "memory_mb": 4096, "gpu": 0})).unwrap();
    share.send_replace(Share {
        cpu_cores: Some(2.0),
        memory_mb: Some(4096),
        paused: true,
        ..Share::default()
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut sent = Vec::new();
    while let Ok(m) = rx.try_recv() {
        if m["type"] == "inventory_update" {
            sent.push(m);
        }
    }
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["inventory"]["offered"]["cpu"], json!(2.0));
    assert_eq!(sent[0]["inventory"]["offered"]["memory_mb"], 4096);
    assert_eq!(
        w.connector.attempts.lock().unwrap().len(),
        1,
        "a share change is no reconnect"
    );
    w.shutdown().await;
}

/// A link over pipes, for `leave`.
fn pipe_link() -> (Link, ServerEnd) {
    let (agent, server) = tokio::io::duplex(1024 * 1024);
    let (ar, aw) = tokio::io::split(agent);
    let (sr, sw) = tokio::io::split(server);
    (
        Link::new(Box::new(aw), Box::new(ar), Box::new(|| {})),
        ServerEnd { r: sr, w: sw },
    )
}

fn leave_reason() -> p2pc_proto::protocol::Leave {
    serde_json::from_value(json!({"reason": "uninstall"})).unwrap()
}

/// Runs `leave` against a fake hub scripted by `hub`.
async fn leave_with<F, Fut>(owner: AccountId, running: Vec<RunningLease>, hub: F) -> LeaveEnd
where
    F: FnOnce(ServerEnd) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (link, server) = pipe_link();
    let script = tokio::spawn(hub(server));
    let end = p2pc_agent::connection::session::leave(
        link,
        owner,
        inventory("node-1"),
        running,
        leave_reason(),
        Duration::from_secs(10),
    )
    .await;
    script.await.unwrap();
    end
}

/// H2 §6.1: `Hello` with `leave` and the leases still held, the owner's `Welcome`, `Leave{reason}`, and the hub's close
/// is the node removed.
#[tokio::test(start_paused = true)]
async fn leave_sends_leave_after_the_owners_welcome_and_ends_when_the_hub_closes() {
    let owner = AccountId::generate();
    let lease = RunningLease::new(LeaseId::generate(), 2);
    let end = leave_with(owner, vec![lease], move |mut s| async move {
        let hello = s.recv().await.unwrap();
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["features"], json!(["leave"]));
        assert_eq!(hello["running"], json!([{"lease_id": lease.lease_id, "epoch": 2}]));
        s.welcome(owner, 60).await;
        // A lease offered in between is refused: this connection takes no work.
        let (id, offer) = lease_msg(owner, good_job());
        s.send(offer).await;
        let mut got = Vec::new();
        for _ in 0..2 {
            got.push(s.recv().await.unwrap());
        }
        assert!(
            got.contains(&json!({"type": "leave", "reason": "uninstall"})),
            "{got:?}"
        );
        assert!(
            got.contains(&json!({"type": "lease_rejected", "lease_id": id, "epoch": 1, "reason": "draining"})),
            "{got:?}"
        );
        // The hub deletes the node and closes, answering nothing.
        drop(s);
    })
    .await;
    assert_eq!(end, LeaveEnd::Left);
}

#[tokio::test(start_paused = true)]
async fn leave_reports_why_the_node_was_not_removed() {
    let owner = AccountId::generate();
    // A hub without `Leave`.
    let end = leave_with(owner, vec![], move |mut s| async move {
        let _ = s.recv().await.unwrap();
        s.welcome(owner, 60).await;
        assert_eq!(s.recv().await.unwrap()["type"], "leave");
        s.send(json!({"type": "error", "code": "unsupported_message", "message": "leave"}))
            .await;
        let _ = s.recv().await;
    })
    .await;
    assert_eq!(end, LeaveEnd::Unsupported);
    // SI-1: a Welcome for another account gets no `Leave`.
    let end = leave_with(owner, vec![], |mut s| async move {
        let _ = s.recv().await.unwrap();
        s.welcome(AccountId::generate(), 60).await;
        assert_eq!(s.recv().await, None, "nothing after Hello");
    })
    .await;
    assert_eq!(end, LeaveEnd::WrongOwner);
    // Already removed.
    let end = leave_with(owner, vec![], |mut s| async move {
        let _ = s.recv().await.unwrap();
        s.send(json!({"type": "error", "code": "not_enrolled", "message": "x"}))
            .await;
        assert_eq!(s.recv().await, None);
    })
    .await;
    assert_eq!(end, LeaveEnd::NotEnrolled);
    // The hub closes before anything was sent: not removed.
    let end = leave_with(owner, vec![], |mut s| async move {
        let _ = s.recv().await.unwrap();
        drop(s);
    })
    .await;
    assert_eq!(end, LeaveEnd::Lost);
    // A silent hub: bounded by the deadline.
    let started = Instant::now();
    let end = leave_with(owner, vec![], move |mut s| async move {
        let _ = s.recv().await.unwrap();
        s.welcome(owner, 60).await;
        assert_eq!(s.recv().await.unwrap()["type"], "leave");
        // Holds the connection open past the deadline, then lets the agent close it.
        let _ = s.recv().await;
    })
    .await;
    assert_eq!(end, LeaveEnd::TimedOut);
    let took = started.elapsed();
    assert!(
        took >= Duration::from_secs(10) && took < Duration::from_secs(13),
        "{took:?}"
    );
}

/// Review P2: a paused node's `draining` refusals count against the hub's offer cap, and a pause or resume does not
/// change the wire inventory, so only a new `Hello` re-arms the queued jobs (`node_changed`). A resume therefore ends
/// the session and reconnects at once, without backoff; a pause, or a share change that keeps sharing on, does not.
#[tokio::test(start_paused = true)]
async fn a_resume_reconnects_at_once_so_the_hub_offers_the_queued_jobs_again() {
    let (node, share) = node_controls();
    share.send_replace(Share {
        paused: true,
        ..Share::default()
    });
    let mut w = start(Options {
        node: Some(node),
        ..Options::default()
    });
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let (_task, _rx) = s.serve(true);
    // Still paused, other values: no reconnect.
    share.send_replace(Share {
        paused: true,
        cpu_cores: Some(2.0),
        ..Share::default()
    });
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        w.connector.attempts.lock().unwrap().len(),
        1,
        "no reconnect while paused"
    );
    // Resume: a new connection and a new Hello at once, well inside the first backoff step (1 s).
    let resumed_at = Instant::now();
    share.send_replace(Share::default());
    let mut s = tokio::time::timeout(Duration::from_millis(500), w.next_connection())
        .await
        .expect("no new connection after the resume");
    let hello = s.recv().await.unwrap();
    assert_eq!(hello["type"], "hello");
    assert!(
        resumed_at.elapsed() < Duration::from_millis(500),
        "{:?}",
        resumed_at.elapsed()
    );
    s.welcome(w.owner, 60).await;
    let (_task, _rx) = s.serve(true);
    // Pausing again, and changing the share while sharing, keep the connection.
    share.send_replace(Share {
        paused: true,
        ..Share::default()
    });
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        w.connector.attempts.lock().unwrap().len(),
        2,
        "a pause does not reconnect"
    );
    w.shutdown().await;
}

fn pipe_connector() -> (Arc<PipeConnector>, mpsc::UnboundedReceiver<ServerEnd>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (
        Arc::new(PipeConnector {
            accepted: tx,
            refuse: AtomicBool::new(false),
            attempts: Mutex::new(Vec::new()),
            rebinds: Mutex::new(Vec::new()),
            incoming: None,
        }),
        rx,
    )
}

fn leave_request(owner: AccountId) -> LeaveRequest {
    LeaveRequest {
        owner,
        running: vec![],
        leave: leave_reason(),
    }
}

/// The hub's side of a connection on which the node is still enrolled: `Welcome`, read `Leave`, close.
async fn hub_takes_leave(mut s: ServerEnd, owner: AccountId) {
    assert_eq!(s.recv().await.unwrap()["type"], "hello");
    s.welcome(owner, 60).await;
    assert_eq!(s.recv().await.unwrap()["type"], "leave");
}

/// The hub's side of a connection after the node was removed.
async fn hub_says_not_enrolled(mut s: ServerEnd) {
    assert_eq!(s.recv().await.unwrap()["type"], "hello");
    s.send(json!({"type": "error", "code": "not_enrolled", "message": "x"}))
        .await;
    assert_eq!(s.recv().await, None);
}

async fn detected() -> Result<Inventory, String> {
    Ok(inventory("node-1"))
}

/// Review P3 of T2-23: a close after `Leave` is "removed" only once a second connection confirms it with `not_enrolled`;
/// a node still enrolled gets `Leave` again.
#[tokio::test(start_paused = true)]
async fn leave_node_confirms_the_removal_on_a_second_connection() {
    let owner = AccountId::generate();
    let (connector, mut ends) = pipe_connector();
    let hub = tokio::spawn(async move {
        hub_takes_leave(ends.recv().await.unwrap(), owner).await;
        hub_says_not_enrolled(ends.recv().await.unwrap()).await;
    });
    let end = leave_node(&*connector, detected(), leave_request(owner), Duration::from_secs(10)).await;
    hub.await.unwrap();
    assert_eq!(end, LeaveEnd::Left);
    assert_eq!(connector.attempts.lock().unwrap().len(), 2);
    // The first `Leave` was lost (the node is still there at the confirmation): sent again, then confirmed.
    let (connector, mut ends) = pipe_connector();
    let hub = tokio::spawn(async move {
        hub_takes_leave(ends.recv().await.unwrap(), owner).await;
        hub_takes_leave(ends.recv().await.unwrap(), owner).await;
        hub_says_not_enrolled(ends.recv().await.unwrap()).await;
    });
    let end = leave_node(&*connector, detected(), leave_request(owner), Duration::from_secs(10)).await;
    hub.await.unwrap();
    assert_eq!(end, LeaveEnd::Left);
    assert_eq!(connector.attempts.lock().unwrap().len(), MAX_LEAVE_CONNECTIONS);
    // Already gone before anything was sent.
    let (connector, mut ends) = pipe_connector();
    let hub = tokio::spawn(async move { hub_says_not_enrolled(ends.recv().await.unwrap()).await });
    let end = leave_node(&*connector, detected(), leave_request(owner), Duration::from_secs(10)).await;
    hub.await.unwrap();
    assert_eq!(end, LeaveEnd::NotEnrolled);
    assert_eq!(connector.attempts.lock().unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn leave_node_reports_a_removal_it_cannot_confirm() {
    let owner = AccountId::generate();
    // The hub cannot be dialled again after the first `Leave`.
    let (connector, mut ends) = pipe_connector();
    let refuse = connector.clone();
    let hub = tokio::spawn(async move {
        hub_takes_leave(ends.recv().await.unwrap(), owner).await;
        refuse.refuse.store(true, Ordering::SeqCst);
    });
    let end = leave_node(&*connector, detected(), leave_request(owner), Duration::from_secs(10)).await;
    hub.await.unwrap();
    assert_eq!(end, LeaveEnd::Unconfirmed);
    // Every connection takes the `Leave` and closes, and none ever says `not_enrolled`.
    let (connector, mut ends) = pipe_connector();
    let hub = tokio::spawn(async move {
        for _ in 0..MAX_LEAVE_CONNECTIONS {
            hub_takes_leave(ends.recv().await.unwrap(), owner).await;
        }
    });
    let end = leave_node(&*connector, detected(), leave_request(owner), Duration::from_secs(10)).await;
    hub.await.unwrap();
    assert_eq!(end, LeaveEnd::Unconfirmed);
    assert_eq!(connector.attempts.lock().unwrap().len(), MAX_LEAVE_CONNECTIONS);
    // The hub cannot be dialled at all: nothing reached it.
    let (connector, _ends) = pipe_connector();
    connector.refuse.store(true, Ordering::SeqCst);
    let end = leave_node(&*connector, detected(), leave_request(owner), Duration::from_secs(10)).await;
    assert!(
        matches!(end, LeaveEnd::Failed(ref e) if e.contains("cannot connect")),
        "{end:?}"
    );
}

/// Review P3 of T2-23: the detection is inside the 10 s budget; a slow one ends as `TimedOut` at the deadline, before
/// any dial.
#[tokio::test(start_paused = true)]
async fn leave_node_bounds_the_detection_by_the_deadline() {
    let owner = AccountId::generate();
    let (connector, _ends) = pipe_connector();
    let slow = async {
        tokio::time::sleep(Duration::from_secs(15)).await;
        Ok(inventory("node-1"))
    };
    let started = Instant::now();
    let end = leave_node(&*connector, slow, leave_request(owner), Duration::from_secs(10)).await;
    assert_eq!(end, LeaveEnd::TimedOut);
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    assert!(connector.attempts.lock().unwrap().is_empty(), "never dialled");
    // A failed detection: nothing is sent either.
    let end = leave_node(
        &*connector,
        async { Err("no RAM size".to_string()) },
        leave_request(owner),
        Duration::from_secs(10),
    )
    .await;
    assert!(
        matches!(end, LeaveEnd::Failed(ref e) if e.contains("no RAM size")),
        "{end:?}"
    );
    assert!(connector.attempts.lock().unwrap().is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// Volumes (H2 §6.1, §11.3)

/// The node's volumes in `dir`, for `owner`, with `budget_mb` of volume space.
fn volume_store(dir: &std::path::Path, owner: AccountId, budget_mb: u64) -> VolumeStore {
    VolumeStore::open(StoreConfig {
        data_dir: dir.to_path_buf(),
        owner,
        budget_mb,
        retention_days: 30,
        entry_budget: 1000,
        clock: Arc::new(SystemClock),
    })
    .unwrap()
}

/// A volume that a lease used and left: on disk, unused. `extra` says what kind of job the lease had.
fn used_volume(store: &VolumeStore, owner: &AccountId, extra: Value, name: &str) {
    let job = serde_json::from_value(volume_job(extra, name)).unwrap();
    let lease = LeaseId::generate();
    store.reserve(lease, 1, owner, &job).unwrap();
    store.lock_and_check(&lease, 1).unwrap();
    assert!(store.release(&lease, 1));
}

/// A job with one volume called `name`; `extra` says what kind of job it is.
fn volume_job(extra: Value, name: &str) -> Value {
    let mut job = json!({
        "image": "docker.io/library/python:3.12-slim",
        "command": ["python", "-m", "http.server", "8080"],
        "resources": {"cpu": 1, "memory_mb": 512},
        "volumes": [{"name": name, "mount": "/volumes/models", "max_mb": 64}],
    });
    if extra["kind"] == "service" {
        job["service"] = json!({"ports": [{"port": 8080, "name": "web"}]});
    }
    for (key, value) in extra.as_object().unwrap() {
        job[key] = value.clone();
    }
    job
}

/// Longest (virtual) wait of [`ServerEnd::recv_acking`] and [`answer_of`]: well over the 10 minutes between two
/// volume reports, and short enough that a test waiting for a message that never comes fails at once instead of
/// acknowledging heartbeats for ever under the paused clock.
const RECV_DEADLINE: Duration = Duration::from_secs(30 * 60);

impl ServerEnd {
    /// The next agent message that is not a heartbeat, acknowledging the heartbeats on the way (a server that
    /// stays silent is dropped). Panics after [`RECV_DEADLINE`] of virtual time without one.
    async fn recv_acking(&mut self) -> Value {
        let next = async {
            loop {
                let m = self.recv().await.expect("the agent closed the connection");
                if m["type"] != "heartbeat" {
                    return m;
                }
                let seq = m["seq"].clone();
                self.send(json!({"type": "heartbeat_ack", "seq": seq})).await;
            }
        };
        tokio::time::timeout(RECV_DEADLINE, next)
            .await
            .expect("no message but heartbeats before the deadline")
    }
}

/// The helper gives up: with nothing but heartbeats coming, it fails after its deadline of virtual time instead of
/// spinning until something outside kills the test.
#[tokio::test(start_paused = true)]
#[should_panic(expected = "no message but heartbeats before the deadline")]
async fn recv_acking_gives_up_after_its_deadline() {
    let mut w = start(Options::default());
    let mut s = w.next_connection().await;
    let _ = s.handshake(w.owner).await;
    let started = Instant::now();
    // The whole test is bounded in real time too, in case the bound itself is what broke.
    let _ = tokio::time::timeout(RECV_DEADLINE * 2, s.recv_acking()).await;
    unreachable!("recv_acking returned after {:?}", started.elapsed());
}

/// H2 §6.1: an agent with volume space declares `volumes` and takes leases whose job has volumes; one without is as
/// before: no capability, and such a lease is `invalid_job` before any handler sees it. With or without, a batch job
/// that is not a template job never gets a volume (SI-H2-9), and a template's volume only goes to that template.
#[tokio::test(start_paused = true)]
async fn volumes_is_declared_and_leases_with_volumes_are_taken_only_with_a_volume_store() {
    for with_volumes in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let owner = AccountId::generate();
        let recorder = Arc::new(Recorder::default());
        let mut w = start(Options {
            handler: recorder.clone(),
            ports: Some(Arc::new(EchoPorts::default()) as Arc<dyn PortOpener>),
            owner: Some(owner),
            volumes: with_volumes.then(|| volume_store(dir.path(), owner, 1024)),
            ..Options::default()
        });
        let mut s = w.next_connection().await;
        let hello = s.handshake(owner).await;
        let expected = if with_volumes {
            json!(["service_jobs", "volumes"])
        } else {
            json!(["service_jobs"])
        };
        assert_eq!(hello["features"], expected, "with_volumes = {with_volumes}");
        let rejected =
            |id: LeaseId| json!({"type": "lease_rejected", "lease_id": id, "epoch": 1, "reason": "invalid_job"});
        let accepted = |id: LeaseId| json!({"type": "lease_accepted", "lease_id": id, "epoch": 1});

        // A service with a volume, and the batch job of a template with that template's volume.
        let service = volume_job(json!({"kind": "service"}), "models");
        let template = volume_job(
            json!({"template": {"id": "transcribe", "version": 1}}),
            "tpl:transcribe/models",
        );
        let mut taken = Vec::new();
        for job in [service, template] {
            let (id, lease) = lease_msg(owner, job);
            s.send(lease).await;
            let answer = answer_of(&mut s).await;
            if with_volumes {
                assert_eq!(answer, accepted(id));
                taken.push(id);
            } else {
                assert_eq!(answer, rejected(id));
            }
        }
        assert_eq!(*recorder.offers.lock().unwrap(), taken);

        // Never, whatever the agent has: a batch job that is not a template job, a template's volume on a plain
        // service or on another template's job, and a name that is a path.
        let refused = [
            volume_job(json!({}), "data"),
            volume_job(json!({"kind": "service"}), "tpl:transcribe/models"),
            volume_job(
                json!({"template": {"id": "private-chat", "version": 1}}),
                "tpl:transcribe/models",
            ),
            volume_job(json!({"kind": "service"}), "../../etc"),
            volume_job(json!({"kind": "service"}), "a/b"),
        ];
        for job in refused {
            let (id, lease) = lease_msg(owner, job.clone());
            s.send(lease).await;
            assert_eq!(answer_of(&mut s).await, rejected(id), "{job}");
        }
        assert_eq!(
            *recorder.offers.lock().unwrap(),
            taken,
            "no handler saw a refused lease"
        );
        let (_task, _rx) = s.serve(true);
        assert_eq!(w.shutdown().await, DaemonExit::Shutdown);
    }
}

/// The next answer to a lease, skipping the session's volume reports. Bounded like [`ServerEnd::recv_acking`]: the
/// reports alone would keep it going.
async fn answer_of(s: &mut ServerEnd) -> Value {
    let answer = async {
        loop {
            let m = s.recv_acking().await;
            if m["type"] != "volume_report" {
                return m;
            }
        }
    };
    tokio::time::timeout(RECV_DEADLINE, answer)
        .await
        .expect("no answer to the lease before the deadline")
}

/// H2 §6.1: `VolumeReport` after `Hello` (once welcomed), every 10 minutes, and in answer to `VolumeDelete`, which
/// deletes a volume no lease uses. Nothing of it before the `Welcome`.
#[tokio::test(start_paused = true)]
async fn volume_reports_follow_the_welcome_and_answer_volume_delete() {
    let dir = tempfile::tempdir().unwrap();
    let owner = AccountId::generate();
    let store = volume_store(dir.path(), owner, 1024);
    used_volume(&store, &owner, json!({"kind": "service"}), "cache");
    // A template's volume, left by a service of that template.
    let chat = json!({"kind": "service", "template": {"id": "private-chat", "version": 1}});
    used_volume(&store, &owner, chat, "tpl:private-chat/models");
    let held = LeaseId::generate();
    let job = serde_json::from_value(volume_job(json!({"kind": "service"}), "held")).unwrap();
    store.reserve(held, 1, &owner, &job).unwrap();
    store.lock_and_check(&held, 1).unwrap();
    let volume_dir = |name: &str| dir.path().join("volumes").join(owner.to_string()).join(dir_name(name));

    let mut w = start(Options {
        owner: Some(owner),
        volumes: Some(store.clone()),
        ..Options::default()
    });
    let mut s = w.next_connection().await;
    // `Hello` first; no report before the `Welcome`.
    assert_eq!(s.recv().await.unwrap()["type"], "hello");
    s.welcome(owner, 60).await;
    let names = |report: &Value| -> Vec<(String, Value)> {
        assert_eq!(report["type"], "volume_report", "{report}");
        report["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| (v["name"].as_str().unwrap().to_string(), v["in_use_by"].clone()))
            .collect()
    };
    let all = [
        ("cache".to_string(), Value::Null),
        ("held".to_string(), json!(held)),
        ("tpl:private-chat/models".to_string(), Value::Null),
    ];
    let first = s.recv_acking().await;
    assert_eq!(names(&first), all);
    assert!(first["volumes"][0]["size_mb"].is_u64() && first["volumes"][0]["last_used_at"].is_string());

    // Every 10 minutes.
    let before = Instant::now();
    assert_eq!(names(&s.recv_acking().await), all);
    let waited = before.elapsed();
    assert!(
        (Duration::from_secs(590)..=Duration::from_secs(630)).contains(&waited),
        "{waited:?}"
    );

    // `VolumeDelete` of a `tpl:` volume that no lease uses: it goes, and a fresh report answers.
    s.send(json!({"type": "volume_delete", "name": "tpl:private-chat/models"}))
        .await;
    assert_eq!(names(&s.recv_acking().await), all[..2]);
    assert!(!volume_dir("tpl:private-chat/models").exists());
    // A volume in use is never deleted, and a name that is a path deletes nothing; both are answered.
    for name in ["held", "../../etc", "unknown"] {
        s.send(json!({"type": "volume_delete", "name": name})).await;
        assert_eq!(names(&s.recv_acking().await), all[..2], "{name}");
    }
    assert!(volume_dir("held").join("data").exists());
    assert!(volume_dir("cache").exists());

    // The lease ended and Podman confirmed its container gone: a report at once.
    assert!(store.release(&held, 1));
    let after = names(&s.recv_acking().await);
    assert_eq!(after[1], ("held".to_string(), Value::Null));
    assert_eq!(
        w.connector.attempts.lock().unwrap().len(),
        1,
        "one connection all along"
    );
    let (_task, _rx) = s.serve(true);
    assert_eq!(w.shutdown().await, DaemonExit::Shutdown);
}
