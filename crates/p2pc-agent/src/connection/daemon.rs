// SPDX-License-Identifier: Apache-2.0

//! `p2pc-agent run`: one healthy control connection at a time, for as long as the agent runs (§6 "Reconnects").
//!
//! The loop: detect the inventory, connect (bounded by [`CONNECT_TIMEOUT`]), run a [`session`], and when it ends, wait
//! [`Backoff::next_delay`] before the next attempt (reset after every `Welcome`; capped at 5 s while leases run). A
//! network change re-binds the endpoint and reconnects at once, without waiting. The lease timer
//! ([`super::watchdog`]) runs on its own task the whole time, connected or not.
//!
//! It ends only on SIGTERM/SIGINT ([`DaemonExit::Shutdown`]) or when the server says this agent must stop
//! (`not_enrolled`, `agent_too_old`). Either way, it stops every running job ([`super::LeaseSupervisor::stop_all`])
//! before it returns: v0.1 has no checkpointing (§9), so no container may outlive the agent. A `Welcome` for another account (SI-1) never ends it: it backs off and tries
//! again, so that a server fixed by its owner is picked up again, and it never takes a lease from the wrong one.

use std::sync::Arc;
use std::time::Duration;

use p2pc_proto::net::AddressChange;
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch};

use super::backoff::Backoff;
use super::exit;
use super::session::{self, NetworkEvents, SessionEnd, Shared};
use super::state::{AgentState, ConnectionState, StateFile, StateWriter};
use super::transport::Connector;

/// The `reason` of [`super::LeaseSupervisor::stop_all`] when the server says this node is not enrolled.
pub const STOP_NOT_ENROLLED: &str = "not_enrolled";
/// The `reason` of [`super::LeaseSupervisor::stop_all`] when the server refuses this agent version.
pub const STOP_AGENT_TOO_OLD: &str = "agent_too_old";
/// The `reason` of [`super::LeaseSupervisor::stop_all`] when the agent itself stops (SIGTERM, SIGINT).
pub const STOP_SHUTDOWN: &str = "shutdown";

/// How long an inventory detected for an attempt whose dial failed (no `Hello` went out) may be reused by the next
/// attempts. A slow detection (a hung GPU tool takes the whole 15 s deadline) must not run before every dial during a
/// server outage, or the reconnect would land after the 45 s lease timer (T05b review P3).
pub const INVENTORY_REUSE: Duration = Duration::from_secs(60);

/// Longest a connection attempt (dial and control stream) may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Why the daemon stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonExit {
    /// SIGTERM or SIGINT.
    Shutdown,
    /// The server says this machine is not enrolled: it was removed.
    NotEnrolled,
    /// The server refuses this agent version.
    AgentTooOld,
}

impl DaemonExit {
    /// The process exit code ([`exit`]).
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            DaemonExit::Shutdown => exit::OK,
            DaemonExit::NotEnrolled => exit::NOT_ENROLLED,
            DaemonExit::AgentTooOld => exit::AGENT_TOO_OLD,
        }
    }
}

/// The daemon.
#[derive(Debug)]
pub struct Daemon {
    /// What sessions share.
    pub shared: Shared,
    /// How to reach the server.
    pub connector: Arc<dyn Connector>,
    /// The jitter seed of the backoff (fixed in tests).
    pub backoff_seed: u64,
    /// The state file for `p2pc-agent status`, if any.
    pub state_file: Option<StateFile>,
    /// The server's NodeId, for the state file.
    pub server_node_id: String,
    /// This node's ID on the server (`[server] agent_node_id`), for the state file: with the server's NodeId, it
    /// names the enrollment.
    pub agent_node_id: String,
}

struct StateTracker<'a> {
    writer: Option<StateWriter>,
    server: &'a str,
    node: &'a str,
    current: Option<ConnectionState>,
    since: OffsetDateTime,
    last_welcome_at: Option<OffsetDateTime>,
}

impl StateTracker<'_> {
    fn set(&mut self, state: ConnectionState) {
        let Some(writer) = &self.writer else { return };
        if self.current == Some(state) {
            return;
        }
        self.current = Some(state);
        self.since = OffsetDateTime::now_utc();
        let mut file = AgentState::new(state, self.since, self.server.to_string(), Some(self.node.to_string()));
        file.last_welcome_at = self.last_welcome_at;
        writer.set(file);
    }

    fn welcomed(&mut self) {
        self.last_welcome_at = Some(OffsetDateTime::now_utc());
        self.current = None;
        self.set(ConnectionState::Connected);
    }
}

impl Daemon {
    /// Runs until shutdown or until the server says to stop. `network` carries the address changes of the
    /// network watcher ([`super::endpoint::watch_network`]).
    pub async fn run(self, mut shutdown: watch::Receiver<bool>, network: mpsc::Receiver<AddressChange>) -> DaemonExit {
        // The network watcher's changes, and the connector's own request to bind again (T10l): the egress gate's
        // watcher asks for it when the default route moves, so a move it sees always leads to a rebind, whatever the
        // network watcher saw.
        let mut network = NetworkEvents {
            changes: network,
            rebind: self.connector.rebind_signal(),
        };
        let watchdog_task = self.shared.watchdog.spawn(self.shared.supervisor.clone());
        let mut backoff = Backoff::new(self.backoff_seed);
        // The last Welcome of this enrollment survives a restart of `run` (T05b review P3): read once, off the runtime.
        let last_welcome_at = match self.state_file.clone() {
            Some(file) => tokio::task::spawn_blocking(move || file.read())
                .await
                .ok()
                .flatten()
                .filter(|s| s.is_of(&self.server_node_id, &self.agent_node_id))
                .and_then(|s| s.last_welcome_at),
            None => None,
        };
        let mut state = StateTracker {
            writer: self.state_file.clone().map(StateFile::spawn_writer),
            server: &self.server_node_id,
            node: &self.agent_node_id,
            current: None,
            since: OffsetDateTime::now_utc(),
            last_welcome_at,
        };
        // An inventory detected for an attempt whose dial failed, and when (see INVENTORY_REUSE).
        let mut unsent: Option<(tokio::time::Instant, p2pc_proto::api::Inventory)> = None;
        let result = loop {
            if *shutdown.borrow() {
                break DaemonExit::Shutdown;
            }
            state.set(ConnectionState::Connecting);
            // The inventory first, then the dial: the server allows 10 s from the handshake to `Hello`, and a
            // detection can take longer (T05b review, P2-1). Every `Hello` gets a fresh one (§6): a detection is reused
            // only when no `Hello` carried it, for at most INVENTORY_REUSE.
            let reusable = unsent.take().filter(|(at, _)| at.elapsed() < INVENTORY_REUSE);
            let detected = match reusable {
                Some((at, inventory)) => {
                    unsent = Some((at, inventory.clone()));
                    Ok(inventory)
                }
                None => {
                    let r = tokio::select! {
                        r = self.shared.inventory.detect() => r,
                        _ = shutdown.changed() => break DaemonExit::Shutdown,
                    };
                    if let Ok(inventory) = &r {
                        unsent = Some((tokio::time::Instant::now(), inventory.clone()));
                    }
                    r
                }
            };
            let end = match detected {
                Err(e) => SessionEnd::Failed(format!("cannot detect the inventory for Hello: {e}")),
                Ok(inventory) => {
                    let attempt = tokio::select! {
                        r = tokio::time::timeout(CONNECT_TIMEOUT, self.connector.connect()) => r,
                        _ = shutdown.changed() => break DaemonExit::Shutdown,
                    };
                    match attempt {
                        Ok(Ok(link)) => {
                            // This inventory goes out in `Hello`: the next connection detects afresh.
                            unsent = None;
                            let on_welcome = |_: &session::Welcomed| {
                                backoff.reset();
                                state.welcomed();
                            };
                            session::run(&self.shared, link, inventory, &mut shutdown, &mut network, on_welcome).await
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "cannot connect to the server");
                            SessionEnd::Lost { welcomed: false }
                        }
                        Err(_) => {
                            tracing::warn!(
                                timeout_s = CONNECT_TIMEOUT.as_secs(),
                                "connecting to the server timed out"
                            );
                            SessionEnd::Lost { welcomed: false }
                        }
                    }
                }
            };
            match end {
                SessionEnd::Shutdown => break DaemonExit::Shutdown,
                SessionEnd::NotEnrolled => {
                    tracing::error!("this machine was removed from the server; join again (`p2pc-agent join`)");
                    // Never leave jobs running for a server that disowned this node (T05b review P3).
                    self.shared.supervisor.stop_all(STOP_NOT_ENROLLED).await;
                    state.set(ConnectionState::NotEnrolled);
                    break DaemonExit::NotEnrolled;
                }
                SessionEnd::AgentTooOld => {
                    tracing::error!(
                        version = crate::inventory::AGENT_VERSION,
                        "the server refuses this agent version (agent_too_old); upgrade p2pc-agent, then start it again"
                    );
                    self.shared.supervisor.stop_all(STOP_AGENT_TOO_OLD).await;
                    state.set(ConnectionState::AgentTooOld);
                    break DaemonExit::AgentTooOld;
                }
                SessionEnd::AddressesChanged(addrs) => {
                    self.connector.set_addresses(addrs).await;
                    continue;
                }
                SessionEnd::Rebind => {
                    self.connector.renew_endpoint().await;
                    continue;
                }
                SessionEnd::WrongOwner => state.set(ConnectionState::WrongOwner),
                SessionEnd::Lost { .. } => state.set(ConnectionState::BackingOff),
                SessionEnd::Failed(e) => {
                    tracing::warn!(error = %e, "the connection could not start");
                    state.set(ConnectionState::BackingOff);
                }
            }
            let delay = backoff.next_delay(!self.shared.supervisor.running().is_empty());
            tracing::info!(
                delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                "reconnecting"
            );
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                _ = shutdown.changed() => break DaemonExit::Shutdown,
                Some(change) = network.changes.recv() => {
                    self.connector.set_addresses(change.addrs).await;
                }
                () = network.rebind.notified() => {
                    self.connector.renew_endpoint().await;
                }
            }
        };
        if result == DaemonExit::Shutdown {
            self.shared.supervisor.stop_all(STOP_SHUTDOWN).await;
            state.set(ConnectionState::Stopped);
        }
        watchdog_task.abort();
        if let Some(writer) = state.writer.take() {
            writer.finish().await;
        }
        self.connector.shutdown().await;
        result
    }
}
