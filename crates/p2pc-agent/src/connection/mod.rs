// SPDX-License-Identifier: Apache-2.0

//! The agent's connection to the control plane (T05b, spec §6 and §10): `join`, then `run`.
//!
//! - [`join`]: `p2pc-agent join <token>`: one connection, `Join{token, inventory}`, then `[server]` is written into
//!   `agent.toml` from the token and the `Welcome`.
//! - [`daemon`]: `p2pc-agent run`: one healthy control connection at a time, kept up with fast reconnects. Each
//!   connection ([`session`]) sends `Hello`, checks the `Welcome` (owner, TTLs), heartbeats, re-detects the
//!   inventory every 10 minutes and routes the server's messages.
//! - [`watchdog`]: the agent-side lease timer (§6 "Liveness on both sides", SI-13). It runs on its own task, so it
//!   keeps counting while the agent is disconnected.
//! - [`backoff`]: reconnect delays, 1 s doubling to 30 s, capped at 5 s while leases run, with jitter.
//! - [`lease`]: the [`LeaseSupervisor`] and [`LeaseHandler`] traits that T10a implements, and their defaults.
//! - [`transport`]: what a session runs over ([`Connector`], [`Link`]); [`endpoint`]: the iroh implementation, with
//!   the §10 address hygiene and re-binding on network changes; [`uplink`]: the welcomed session's outbox and upload
//!   streams, as the lease executor (T10a) reaches them.
//! - [`streams`]: the streams the hub opens on the connection (H2 §6.1): the dispatcher of `PortOpen` streams, served
//!   by the sandbox's ingress bridge.
//! - [`load`]: the `load` of heartbeats; [`state`]: the state file behind `p2pc-agent status`; [`gate`]: the egress gate
//!   file behind its `Egress gate:` line (T10l); [`exit`]: the exit
//!   codes; [`token`]: reading the join token without ever showing it (SI-6).

pub mod backoff;
pub mod daemon;
pub mod endpoint;
pub mod exit;
pub mod gate;
pub mod join;
pub mod lease;
pub mod load;
pub mod session;
pub mod state;
pub mod streams;
pub mod token;
pub mod transport;
pub mod uplink;
pub mod watchdog;

use std::future::Future;
use std::pin::Pin;

use p2pc_proto::api::Inventory;

pub use self::lease::{LeaseDecision, LeaseHandler, LeaseOffer, LeaseSupervisor, NoLeases, NotReady};
pub use self::session::InventorySource;
pub use self::transport::{Connector, Link, StreamOpener};
pub use self::uplink::{Port, Uplink};
use crate::config::Config;
use crate::executor::capacity::{DriverLimits, Offer};
use crate::host::Host;
use crate::runner::SystemRunner;

/// A boxed, sendable future, for the object-safe traits of this module.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Where each detection's offer goes: the lease executor admits leases against the latest one (T10a).
#[derive(Debug)]
pub struct OfferFeed {
    /// The latest offer.
    pub tx: tokio::sync::watch::Sender<Option<Offer>>,
    /// What the sandbox driver can serve.
    pub driver: DriverLimits,
}

/// The real inventory: [`crate::inventory::detect_periodic`] on this machine, never cached.
#[derive(Debug)]
pub struct DetectInventory {
    /// The machine. Keep one for the life of the agent (its blocking reads are single-flight).
    pub host: Host,
    /// The config (share limits, runtime, data dir).
    pub config: Config,
    /// Where each successful detection publishes its offer, if anywhere. A failed detection keeps the last one.
    pub offers: Option<OfferFeed>,
}

impl InventorySource for DetectInventory {
    fn detect(&self) -> BoxFuture<'_, Result<Inventory, String>> {
        Box::pin(async move {
            let mut report = crate::inventory::detect_periodic(&self.host, &SystemRunner::default(), &self.config)
                .await
                .map_err(|e| e.to_string())?;
            if let Some(feed) = &self.offers {
                let offer = Offer::from_detection(&report.inventory, &report.local.share, &feed.driver);
                feed.tx.send_replace(Some(offer));
                // What the driver cannot serve is not reported ready (T10a review, P3-5).
                feed.driver.apply(&mut report.inventory);
            }
            Ok(report.inventory)
        })
    }
}
