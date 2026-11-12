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
use crate::config::{Config, ResolvedShare};
use crate::executor::capacity::{DriverLimits, Offer};
use crate::host::Host;
use crate::runner::SystemRunner;
use crate::volumes::VolumeStore;

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
    /// The owner's share in force, when it can change while the agent runs (`p2pc-agent share set`, H2 §8.4): each
    /// detection uses it instead of `config.share`.
    pub live_share: Option<tokio::sync::watch::Receiver<crate::config::Share>>,
    /// The node's volume store, when it started with volume space (H2 §11.3): each detection sets its budget to the
    /// `share.volumes_mb` in force.
    pub volumes: Option<VolumeStore>,
}

/// What a successful detection does with its result before the inventory goes to the server.
///
/// - **The offer** goes to the executor, limited to what the sandbox driver serves ([`Offer::from_detection`]).
/// - **`offered.gpu` is what the executor admits.** The share can change while the agent runs (`share set`), but the
///   driver serves only the GPUs it was built with at start. A GPU the owner turned on since then is not reported as
///   offered: the hub would send GPU leases that this agent refuses with `insufficient_capacity`, and count them
///   against the job's offers. Such a GPU is offered once the agent restarts; turning one off is live.
/// - **What the driver cannot serve is not reported ready** (T10a review, P3-5).
/// - **The volume budget** follows `share.volumes_mb`, so a lower disk limit is in force at once. A node that started
///   without volume space has no store here: it declares `volumes` only after a restart.
/// - **`Inventory.volumes_mb`** is that share as resolved (H2 §6.1, §11.3). The session sends it only with
///   `share_update` ([`session::Shared::share_fields`]).
fn settle(offers: Option<&OfferFeed>, volumes: Option<&VolumeStore>, inventory: &mut Inventory, share: &ResolvedShare) {
    inventory.volumes_mb = Some(share.volumes_mb);
    if let Some(feed) = offers {
        let offer = Offer::from_detection(inventory, share, &feed.driver);
        let served = u32::try_from(offer.gpus.len()).unwrap_or(u32::MAX);
        if inventory.offered.gpu > served {
            tracing::warn!(
                in_share = inventory.offered.gpu,
                served,
                "the share lists GPUs the sandbox driver was not started with; they are offered once the agent restarts"
            );
            inventory.offered.gpu = served;
        }
        feed.tx.send_replace(Some(offer));
        feed.driver.apply(inventory);
    }
    if let Some(store) = volumes {
        store.set_budget_mb(share.volumes_mb);
    }
}

impl InventorySource for DetectInventory {
    fn detect(&self) -> BoxFuture<'_, Result<Inventory, String>> {
        Box::pin(async move {
            let config = match &self.live_share {
                Some(share) => Config {
                    share: share.borrow().clone(),
                    ..self.config.clone()
                },
                None => self.config.clone(),
            };
            let mut report = crate::inventory::detect_periodic(&self.host, &SystemRunner::default(), &config)
                .await
                .map_err(|e| e.to_string())?;
            settle(
                self.offers.as_ref(),
                self.volumes.as_ref(),
                &mut report.inventory,
                &report.local.share,
            );
            Ok(report.inventory)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use p2pc_proto::ids::AccountId;

    use super::*;
    use crate::executor::SystemClock;
    use crate::volumes::StoreConfig;

    /// An inventory as a detection builds it for `share`: it offers every GPU of the share.
    fn detected(share: &ResolvedShare) -> Inventory {
        serde_json::from_value(serde_json::json!({
            "hostname": "node-1", "platform": "linux", "cpu": {"model": "Example CPU", "cores": 8},
            "memory_mb": 16384, "os": "Ubuntu 24.04", "arch": "x86_64", "gpu_status": {"status": "ok"},
            "sandbox": [{"driver": "podman", "class": "container", "runtimes": ["crun"], "ready": true}],
            "offered": {"cpu": share.cpu_cores, "memory_mb": share.memory_mb, "gpu": share.gpus.len()},
            "agent_version": "0.1.0",
        }))
        .unwrap()
    }

    fn share(gpus: &[&str], volumes_mb: u64) -> ResolvedShare {
        ResolvedShare {
            cpu_cores: 6.0,
            memory_mb: 12_288,
            gpus: gpus.iter().map(ToString::to_string).collect(),
            disk_mb: 50_000,
            volumes_mb,
            warnings: vec![],
        }
    }

    fn feed(driver_gpus: &[&str]) -> OfferFeed {
        OfferFeed {
            tx: tokio::sync::watch::channel(None).0,
            driver: DriverLimits {
                ready: true,
                gpus: driver_gpus.iter().map(ToString::to_string).collect(),
                problems: vec![],
            },
        }
    }

    /// Review P2 of T2-23 (round 2): the share can change while the agent runs, but the driver serves only the GPUs it
    /// was started with. A GPU the owner turned on since then (`share set --gpu all`) is never reported to the hub as
    /// offered: `offered.gpu` is what the executor admits, so the hub offers no GPU lease this agent would refuse.
    #[test]
    fn the_inventory_never_offers_a_gpu_the_driver_was_not_started_with() {
        // Started with `gpus = "none"`, then `share set --gpu all` on a two-GPU machine.
        let now = share(&["GPU-a", "GPU-b"], 0);
        let feed_none = feed(&[]);
        let mut inventory = detected(&now);
        assert_eq!(inventory.offered.gpu, 2, "what the detection alone would report");
        settle(Some(&feed_none), None, &mut inventory, &now);
        assert_eq!(inventory.offered.gpu, 0);
        assert!(feed_none.tx.borrow().as_ref().unwrap().gpus.is_empty());
        // Started with one GPU, now two in the share: the one the driver has is offered, to the hub and the executor.
        let feed_one = feed(&["GPU-a"]);
        let mut inventory = detected(&now);
        settle(Some(&feed_one), None, &mut inventory, &now);
        assert_eq!(inventory.offered.gpu, 1);
        assert_eq!(feed_one.tx.borrow().as_ref().unwrap().gpus, ["GPU-a"]);
        // Turning a GPU off is live, and a share the driver fully serves is reported as it is.
        let fewer = share(&["GPU-b"], 0);
        let feed_both = feed(&["GPU-a", "GPU-b"]);
        let mut inventory = detected(&fewer);
        settle(Some(&feed_both), None, &mut inventory, &fewer);
        assert_eq!(inventory.offered.gpu, 1);
        assert_eq!(feed_both.tx.borrow().as_ref().unwrap().gpus, ["GPU-b"]);
        let mut inventory = detected(&now);
        settle(Some(&feed_both), None, &mut inventory, &now);
        assert_eq!(inventory.offered.gpu, 2);
        // Without an offer feed (no executor), the inventory is the detection's.
        let mut inventory = detected(&now);
        settle(None, None, &mut inventory, &now);
        assert_eq!(inventory.offered.gpu, 2);
    }

    /// Review P3 of T2-23 (round 2): `share set --volumes-mb` reaches the volume store with the next detection, so a
    /// lower disk limit is in force without a restart (and a higher one too).
    #[test]
    fn a_detection_sets_the_volume_budget_to_the_share_in_force() {
        let dir = tempfile::tempdir().unwrap();
        let store = VolumeStore::open(StoreConfig {
            data_dir: dir.path().to_path_buf(),
            owner: AccountId::generate(),
            budget_mb: 40_000,
            retention_days: 30,
            entry_budget: 1000,
            clock: Arc::new(SystemClock),
        })
        .unwrap();
        for volumes_mb in [10_000, 60_000, 0] {
            let now = share(&[], volumes_mb);
            let mut inventory = detected(&now);
            settle(None, Some(&store), &mut inventory, &now);
            assert_eq!(store.budget_mb(), volumes_mb);
            // H2 §6.1: the same resolved share is what `Inventory.volumes_mb` reports (with `share_update`).
            assert_eq!(inventory.volumes_mb, Some(volumes_mb));
        }
        // A node without volume space reports its share too: the hub learns it has none.
        let none = share(&[], 0);
        let mut inventory = detected(&none);
        settle(None, None, &mut inventory, &none);
        assert_eq!(inventory.volumes_mb, Some(0));
    }
}
