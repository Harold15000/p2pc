// SPDX-License-Identifier: Apache-2.0

//! What the node offers (§8) and what the running leases hold of it.
//!
//! The server reserves CPU, memory, disk and a GPU **count**; the agent checks the same against the **offered**
//! capacity that is still free, and picks the concrete GPU: a free, offerable UUID (§8, amended in `a8ef531`). The
//! device argument then follows §9 (the driver's business): `nvidia.com/gpu=<uuid>` on Linux, `nvidia.com/gpu=all`
//! on WSL2, which selects one GPU only when the node offers exactly one.

use std::collections::HashMap;

use p2pc_proto::api::{Inventory, Platform, Resources};
use p2pc_proto::ids::LeaseId;
use p2pc_proto::protocol::{LeaseRejectReason, MAX_SANDBOX_PROBLEMS};

use crate::config::ResolvedShare;
use crate::inventory::UNKNOWN_MEMORY_MB;

/// A lease's key: a lease and its epoch.
pub type LeaseKey = (LeaseId, u64);

/// Tolerance of the CPU sums (fractions of a vCPU add up in binary floating point).
const CPU_EPSILON: f64 = 1e-9;

/// The capacity the owner offers, as the last inventory detection resolved it.
#[derive(Debug, Clone, PartialEq)]
pub struct Offer {
    /// Whether the node can take leases: its RAM is known and its sandbox is ready. Otherwise every lease gets
    /// `agent_not_ready` (§6).
    pub ready: bool,
    /// The §9.0 profile (the GPU rule depends on it).
    pub platform: Platform,
    /// vCPUs offered.
    pub cpu: f64,
    /// Memory offered, in MiB.
    pub memory_mb: u64,
    /// Disk offered for job directories, in MiB.
    pub disk_mb: u64,
    /// UUIDs of the offerable GPUs.
    pub gpus: Vec<String>,
}

impl Offer {
    /// An offer of nothing, not ready.
    #[must_use]
    pub fn not_ready(platform: Platform) -> Self {
        Self {
            ready: false,
            platform,
            cpu: 0.0,
            memory_mb: 0,
            disk_mb: 0,
            gpus: Vec::new(),
        }
    }
}

/// What the sandbox driver, built once at agent start, can serve whatever later detections say: its readiness then
/// and the GPUs it was given. A node that becomes ready later, or a GPU that appears later, needs an agent restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverLimits {
    /// The driver was built ready (sandbox ready, shim present, lease cgroups available).
    pub ready: bool,
    /// The GPUs the driver accepts (`DriverConfig::offerable_gpus`).
    pub gpus: Vec<String>,
    /// Why it is not ready, one `<code>: <detail>` per reason (empty when ready).
    pub problems: Vec<String>,
}

impl DriverLimits {
    /// Makes `inventory` honest about the driver (T10a review, P3-5): when the driver was built not ready (no shim, no
    /// lease cgroups…), every sandbox is reported not ready with the reasons, in `Hello` and `InventoryUpdate`, so the
    /// scheduler stops offering leases this agent would refuse.
    pub fn apply(&self, inventory: &mut Inventory) {
        if self.ready {
            return;
        }
        for sandbox in &mut inventory.sandbox {
            sandbox.ready = false;
            for problem in &self.problems {
                if sandbox.problems.len() >= MAX_SANDBOX_PROBLEMS {
                    break;
                }
                let problem = crate::inventory::clean(problem);
                if !sandbox.problems.contains(&problem) {
                    sandbox.problems.push(problem);
                }
            }
        }
    }
}

impl Offer {
    /// The offer of a detection: the owner's share as resolved, ready when the RAM is known and a sandbox driver is
    /// ready, and limited to what the driver can serve.
    #[must_use]
    pub fn from_detection(inventory: &Inventory, share: &ResolvedShare, driver: &DriverLimits) -> Self {
        let ready =
            driver.ready && inventory.memory_mb != UNKNOWN_MEMORY_MB && inventory.sandbox.iter().any(|s| s.ready);
        let mut gpus: Vec<String> = share
            .gpus
            .iter()
            .filter(|uuid| driver.gpus.contains(uuid))
            .cloned()
            .collect();
        gpus.sort();
        Self {
            ready,
            platform: inventory.platform,
            cpu: share.cpu_cores,
            memory_mb: share.memory_mb,
            disk_mb: share.disk_mb,
            gpus,
        }
    }
}

/// What one lease holds.
#[derive(Debug, Clone, PartialEq)]
pub struct Reservation {
    /// vCPUs.
    pub cpu: f64,
    /// Memory, in MiB.
    pub memory_mb: u64,
    /// Disk, in MiB.
    pub disk_mb: u64,
    /// The GPU picked for it, by UUID.
    pub gpu: Option<String>,
}

/// The reservations of the leases the executor holds, from acceptance to cleanup.
#[derive(Debug, Default)]
pub struct Ledger {
    held: HashMap<LeaseKey, Reservation>,
}

impl Ledger {
    /// Reserves `resources` for `key` within what `offer` has free, picking a GPU when one is asked for.
    ///
    /// # Errors
    /// `insufficient_capacity` when something does not fit or no offered GPU is free; `gpu_selection_unsupported`
    /// for a GPU job on WSL2 when the node does not offer exactly one GPU (§9: `nvidia.com/gpu=all` could not select
    /// one).
    pub fn reserve(
        &mut self,
        key: LeaseKey,
        offer: &Offer,
        resources: &Resources,
    ) -> Result<Reservation, LeaseRejectReason> {
        let (mut cpu, mut memory_mb, mut disk_mb) = (0.0, 0u64, 0u64);
        for r in self.held.values() {
            cpu += r.cpu;
            memory_mb = memory_mb.saturating_add(r.memory_mb);
            disk_mb = disk_mb.saturating_add(r.disk_mb);
        }
        let fits = cpu + resources.cpu <= offer.cpu + CPU_EPSILON
            && memory_mb.saturating_add(resources.memory_mb) <= offer.memory_mb
            && disk_mb.saturating_add(resources.disk_mb) <= offer.disk_mb;
        if !fits {
            return Err(LeaseRejectReason::InsufficientCapacity);
        }
        let gpu = match resources.gpu {
            0 => None,
            // One device per lease in v0.1 (the driver passes one `--device`).
            1 => {
                if offer.platform == Platform::Wsl2 && offer.gpus.len() != 1 {
                    return Err(LeaseRejectReason::GpuSelectionUnsupported);
                }
                let mut free: Vec<&String> = offer
                    .gpus
                    .iter()
                    .filter(|uuid| !self.held.values().any(|r| r.gpu.as_ref() == Some(*uuid)))
                    .collect();
                free.sort();
                Some(
                    free.first()
                        .map(|uuid| (*uuid).clone())
                        .ok_or(LeaseRejectReason::InsufficientCapacity)?,
                )
            }
            _ => return Err(LeaseRejectReason::InsufficientCapacity),
        };
        let reservation = Reservation {
            cpu: resources.cpu,
            memory_mb: resources.memory_mb,
            disk_mb: resources.disk_mb,
            gpu,
        };
        self.held.insert(key, reservation.clone());
        Ok(reservation)
    }

    /// Releases what `key` held. Releasing twice is harmless.
    pub fn release(&mut self, key: &LeaseKey) {
        self.held.remove(key);
    }

    /// How many leases hold something.
    #[must_use]
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(gpus: &[&str]) -> Offer {
        Offer {
            ready: true,
            platform: Platform::Linux,
            cpu: 3.0,
            memory_mb: 6144,
            disk_mb: 20_480,
            gpus: gpus.iter().map(|g| (*g).to_string()).collect(),
        }
    }

    fn res(cpu: f64, memory_mb: u64, disk_mb: u64, gpu: u32) -> Resources {
        Resources {
            cpu,
            memory_mb,
            gpu,
            disk_mb,
        }
    }

    fn key() -> LeaseKey {
        (LeaseId::generate(), 1)
    }

    #[test]
    fn cpu_memory_and_disk_fit_the_free_offer_exactly() {
        let mut l = Ledger::default();
        let o = offer(&[]);
        let a = key();
        // Fractions add up to the offer exactly.
        for _ in 0..3 {
            l.reserve(key(), &o, &res(0.1, 1, 1, 0)).unwrap();
        }
        l.reserve(a, &o, &res(2.7, 6141, 20_477, 0)).unwrap();
        for over in [res(0.01, 0, 0, 0), res(0.0, 1, 0, 0), res(0.0, 0, 1, 0)] {
            assert_eq!(
                l.reserve(key(), &o, &over),
                Err(LeaseRejectReason::InsufficientCapacity),
                "{over:?}"
            );
        }
        // Released capacity is free again.
        l.release(&a);
        l.release(&a);
        assert_eq!(l.len(), 3);
        l.reserve(key(), &o, &res(2.7, 6141, 20_477, 0)).unwrap();
    }

    #[test]
    fn gpus_are_picked_by_uuid_and_held_until_released() {
        let mut l = Ledger::default();
        let o = offer(&["GPU-b", "GPU-a"]);
        let (a, b) = (key(), key());
        let first = l.reserve(a, &o, &res(0.5, 1, 1, 1)).unwrap();
        assert_eq!(first.gpu.as_deref(), Some("GPU-a"), "the lowest free UUID");
        let second = l.reserve(b, &o, &res(0.5, 1, 1, 1)).unwrap();
        assert_eq!(second.gpu.as_deref(), Some("GPU-b"));
        assert_eq!(
            l.reserve(key(), &o, &res(0.5, 1, 1, 1)),
            Err(LeaseRejectReason::InsufficientCapacity),
            "no GPU is free"
        );
        l.release(&a);
        assert_eq!(
            l.reserve(key(), &o, &res(0.5, 1, 1, 1)).unwrap().gpu.as_deref(),
            Some("GPU-a")
        );
        // A CPU job never takes a GPU, and a GPU job on a node with none is refused.
        assert_eq!(l.reserve(key(), &o, &res(0.5, 1, 1, 0)).unwrap().gpu, None);
        assert_eq!(
            Ledger::default().reserve(key(), &offer(&[]), &res(0.5, 1, 1, 1)),
            Err(LeaseRejectReason::InsufficientCapacity)
        );
        assert_eq!(
            Ledger::default().reserve(key(), &o, &res(0.5, 1, 1, 2)),
            Err(LeaseRejectReason::InsufficientCapacity),
            "one device per lease in v0.1"
        );
    }

    #[test]
    fn the_offer_of_a_detection_is_limited_to_what_the_driver_serves() {
        let mut inventory: Inventory = serde_json::from_value(serde_json::json!({
            "hostname": "node-1", "platform": "wsl2", "cpu": {"model": "Example CPU", "cores": 8},
            "memory_mb": 16384, "os": "Ubuntu 24.04", "arch": "x86_64", "gpu_status": {"status": "ok"},
            "sandbox": [{"driver": "podman", "class": "container", "runtimes": ["crun"], "ready": true}],
            "offered": {"cpu": 6.0, "memory_mb": 12288, "gpu": 0}, "agent_version": "0.1.0",
        }))
        .unwrap();
        let share = ResolvedShare {
            cpu_cores: 6.0,
            memory_mb: 12_288,
            gpus: vec!["GPU-b".into(), "GPU-a".into()],
            disk_mb: 50_000,
            volumes_mb: 0,
            warnings: vec![],
        };
        let driver = DriverLimits {
            ready: true,
            gpus: vec!["GPU-a".into()],
            problems: vec![],
        };
        let o = Offer::from_detection(&inventory, &share, &driver);
        assert_eq!(
            o,
            Offer {
                ready: true,
                platform: Platform::Wsl2,
                cpu: 6.0,
                memory_mb: 12_288,
                disk_mb: 50_000,
                gpus: vec!["GPU-a".into()],
            },
            "a GPU found after the driver was built is not offered"
        );
        // Not ready: the driver was not, the sandbox is not, or the RAM is unknown.
        let not_ready = DriverLimits {
            ready: false,
            ..driver.clone()
        };
        assert!(!Offer::from_detection(&inventory, &share, &not_ready).ready);
        inventory.memory_mb = UNKNOWN_MEMORY_MB;
        assert!(!Offer::from_detection(&inventory, &share, &driver).ready);
        inventory.memory_mb = 16_384;
        inventory.sandbox[0].ready = false;
        assert!(!Offer::from_detection(&inventory, &share, &driver).ready);
        // The inventory is honest: a driver built not ready marks the sandbox not ready, with its reasons.
        inventory.sandbox[0].ready = true;
        let before = inventory.clone();
        driver.apply(&mut inventory);
        assert_eq!(inventory, before, "a ready driver changes nothing");
        let broken = DriverLimits {
            ready: false,
            problems: vec!["shim_missing: install p2pc-shim next to p2pc-agent".into()],
            ..driver
        };
        broken.apply(&mut inventory);
        broken.apply(&mut inventory);
        assert!(!inventory.sandbox[0].ready);
        assert_eq!(
            inventory.sandbox[0].problems,
            ["shim_missing: install p2pc-shim next to p2pc-agent"]
        );
        p2pc_proto::protocol::validate_inventory(&inventory).unwrap();
    }

    #[test]
    fn wsl2_selects_a_gpu_only_when_it_offers_exactly_one() {
        let mut two = offer(&["GPU-a", "GPU-b"]);
        two.platform = Platform::Wsl2;
        assert_eq!(
            Ledger::default().reserve(key(), &two, &res(0.5, 1, 1, 1)),
            Err(LeaseRejectReason::GpuSelectionUnsupported)
        );
        let mut one = offer(&["GPU-a"]);
        one.platform = Platform::Wsl2;
        let mut l = Ledger::default();
        assert_eq!(
            l.reserve(key(), &one, &res(0.5, 1, 1, 1)).unwrap().gpu.as_deref(),
            Some("GPU-a")
        );
        assert_eq!(
            l.reserve(key(), &one, &res(0.5, 1, 1, 1)),
            Err(LeaseRejectReason::InsufficientCapacity)
        );
    }
}
