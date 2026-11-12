// SPDX-License-Identifier: AGPL-3.0-only

//! Placement arithmetic (spec §8): what a node offers, what its leases hold, whether a job fits, and which node fits
//! best. Pure functions, no I/O: the scheduler feeds them rows it read inside its placement transaction.
//!
//! **Capacity.** CPUs are counted in milli-vCPUs (the request is a multiple of 0.001, §7), memory and disk in MiB,
//! GPUs by UUID. Disk is placed only when the node reports `offered.disk_mb`; an agent without it (older than the
//! 2026-11-07 amendment) is placed by CPU, memory and GPU only. A node offers `inventory.offered`; its free capacity is that minus **every held reservation**, meaning
//! every lease of the node not yet confirmed dead (§8 "Reservations are held until confirmed"): active leases, and
//! leases whose job already ended but whose execution may still be running.
//!
//! **GPUs.** The node's offerable GPUs (MIG off, VRAM known, §6) sorted by index, of which the first
//! `inventory.offered.gpu` are offered. A GPU job reserves one of those UUIDs that no held lease holds.
//!
//! **Best fit** ([`Score`]): the node with the least free capacity left after placement, compared as a tuple, most
//! significant first:
//! 1. the fraction of the node's offered GPUs left free;
//! 2. the fraction of its offered memory left free;
//! 3. the fraction of its offered CPU left free;
//! 4. the fraction of its offered disk left free (0 for a node that does not report disk).
//!
//! Each fraction is in parts per million of what the node offers (a node offering none of a resource counts 0 for
//! it). GPU first means a CPU-only job prefers a node without free GPUs, which keeps GPU nodes for GPU jobs. Ties go
//! to the node idle longest (its last lease offered or released earliest), then to the smaller node ID, so the choice
//! is deterministic. On a retry, every node other than the one that just lost the lease ranks before it (§8
//! "Retries"); that node is still used when it is the only one that fits.
//!
//! **H2 eligibility** (H2 §5.5, §6.1). A node gets a job only if its agent declared every capability the job needs
//! (`service_jobs`, `volumes`, `blob_inputs`: [`needs`]) and the node is `approved`: a `pending_approval` node is
//! never a fit, whatever it offers (SI-H2-19). Both are reported as their own [`Misfit`], so the scheduler can say why
//! a job waits ([`why_nowhere`]).
//!
//! **Volumes on the node** (H2 §11.3). A volume is mounted by one container at a time, and the node's volume share
//! (`Inventory.volumes_mb`) covers every volume on it. A job with volumes therefore never goes to a node where one of
//! its volumes is in use ([`Candidate::volumes_in_use`]: held by a lease the hub has not seen end, or reported
//! `in_use_by` a lease in the node's last `VolumeReport`), and needs `volumes_mb − Σ max_mb of the volumes in use ≥
//! Σ max_mb of its own volumes`. Both pass with time ([`Misfit::Busy`]). A share that cannot hold the job's volumes
//! even with none in use makes the node ineligible ([`Misfit::NoVolumeSpace`]). A node that does not report
//! `volumes_mb` (an agent without `share_update`) is placed without the budget; its agent still enforces it.
//!
//! **Volume affinity** ([`affinity`], H2 §7.2). A requeued service with a volume goes back to the node that holds the
//! volume when that node fits; while that node is eligible but offline or busy, the scheduler waits for it (for a
//! bounded time, which the caller checks) before it places the job elsewhere.

use std::collections::{BTreeMap, BTreeSet};

use p2pc_proto::api::{Capacity, Inventory, JobKind, POOL_MINE};
use p2pc_proto::ids::NodeId;
use p2pc_proto::protocol::capability;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Milli-vCPUs of a vCPU count, rounded to the nearest (the same rule as the units of §11). Negative or non-finite
/// values count as zero.
#[must_use]
pub fn cpu_milli(cpu: f64) -> u64 {
    if cpu.is_finite() && cpu > 0.0 {
        // `as` saturates out-of-range floats.
        (cpu * 1000.0).round() as u64
    } else {
        0
    }
}

/// What a job asks for, as the scheduler reads it from the redacted spec view.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Request {
    /// Milli-vCPUs.
    pub cpu_milli: u64,
    /// MiB.
    pub memory_mb: u64,
    /// MiB of disk for the job directory (`resources.disk_mb`).
    pub disk_mb: u64,
    /// Whole GPUs (0 or 1 in v0.1).
    pub gpu: u32,
    /// Pools (only `mine` exists in v0.1).
    pub pools: Vec<String>,
    /// Node labels that must all match.
    pub labels: BTreeMap<String, String>,
    /// A pinned node, if any.
    pub node_id: Option<NodeId>,
    /// The agent capabilities the job needs (H2 §6.1, see [`needs`]). Empty for an H1 batch job.
    pub needs: Vec<&'static str>,
    /// Its volumes (H2 §7.1), for the one-holder rule and the volume budget (§11.3). Empty for most jobs.
    pub volumes: Vec<VolumeNeed>,
}

/// One volume a job mounts, as placement sees it (H2 §11.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeNeed {
    /// The volume's name (one holder at a time per name on a node).
    pub name: String,
    /// Its `max_mb`, which the node's volume share must hold.
    pub max_mb: u64,
}

impl Request {
    /// The MiB of volume share the job's volumes need: the sum of their `max_mb`.
    #[must_use]
    pub fn volumes_mb(&self) -> u64 {
        self.volumes.iter().fold(0, |sum, v| sum.saturating_add(v.max_mb))
    }
}

/// The agent capabilities a job needs (H2 §6.1): `service_jobs` for a service, `volumes` for a job with volumes,
/// `blob_inputs` for a job with blob inputs. A lease that needs one goes only to an agent that declared it.
#[must_use]
pub fn needs(kind: JobKind, volumes: bool, blob_inputs: bool) -> Vec<&'static str> {
    let mut out = Vec::new();
    if kind == JobKind::Service {
        out.push(capability::SERVICE_JOBS);
    }
    if volumes {
        out.push(capability::VOLUMES);
    }
    if blob_inputs {
        out.push(capability::BLOB_INPUTS);
    }
    out
}

/// What a lease holds on its node: the `leases.reserved` JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reserved {
    /// vCPUs.
    pub cpu: f64,
    /// MiB.
    pub memory_mb: u64,
    /// MiB of disk. Leases written before disk was placed read as 0.
    #[serde(default)]
    pub disk_mb: u64,
    /// The reserved GPU, if the job asked for one.
    pub gpu_uuid: Option<String>,
}

impl Reserved {
    /// What an unreadable `leases.reserved` counts as: everything a node could offer, so a corrupt row fails closed
    /// (the node is full) instead of freeing capacity that may be in use.
    #[must_use]
    pub fn unreadable() -> Self {
        Self {
            // Saturates `cpu_milli` to `u64::MAX`.
            cpu: 1e30,
            memory_mb: u64::MAX,
            disk_mb: u64::MAX,
            gpu_uuid: None,
        }
    }
}

/// The sum of a node's held reservations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Held {
    /// Milli-vCPUs.
    pub cpu_milli: u64,
    /// MiB.
    pub memory_mb: u64,
    /// MiB of disk.
    pub disk_mb: u64,
    /// Held GPU UUIDs.
    pub gpus: BTreeSet<String>,
}

impl Held {
    /// Adds one reservation.
    pub fn add(&mut self, r: &Reserved) {
        self.cpu_milli = self.cpu_milli.saturating_add(cpu_milli(r.cpu));
        self.memory_mb = self.memory_mb.saturating_add(r.memory_mb);
        self.disk_mb = self.disk_mb.saturating_add(r.disk_mb);
        if let Some(g) = &r.gpu_uuid {
            self.gpus.insert(g.clone());
        }
    }
}

/// The GPU UUIDs a node offers: offerable ones (§6), by index, at most `offered.gpu` of them.
#[must_use]
pub fn offered_gpus(inv: &Inventory) -> Vec<String> {
    let mut gpus: Vec<_> = inv.gpus.iter().filter(|g| g.is_offerable()).collect();
    gpus.sort_by(|a, b| a.index.cmp(&b.index).then_with(|| a.uuid.cmp(&b.uuid)));
    gpus.into_iter()
        .take(inv.offered.gpu as usize)
        .map(|g| g.uuid.clone())
        .collect()
}

/// The free capacity of a node: offered minus held, never negative (`free` of `GET /v1/nodes`).
#[must_use]
pub fn free_capacity(inv: &Inventory, held: &Held) -> Capacity {
    let gpus = offered_gpus(inv);
    let free_gpus = gpus.iter().filter(|g| !held.gpus.contains(*g)).count();
    Capacity {
        cpu: cpu_milli(inv.offered.cpu).saturating_sub(held.cpu_milli) as f64 / 1000.0,
        memory_mb: inv.offered.memory_mb.saturating_sub(held.memory_mb),
        gpu: u32::try_from(free_gpus).unwrap_or(u32::MAX),
        disk_mb: inv.offered.disk_mb.map(|d| d.saturating_sub(held.disk_mb)),
    }
}

/// A node as the placement sees it.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The node.
    pub node_id: NodeId,
    /// Its last inventory.
    pub inventory: Inventory,
    /// Its labels (none can be set in v0.1).
    pub labels: BTreeMap<String, String>,
    /// Online, not draining, and connected now.
    pub available: bool,
    /// Whether an `admin` approved the node (H2 §5.5). A `pending_approval` node gets no lease (SI-H2-19).
    pub approved: bool,
    /// The capabilities its agent declared in its last `Hello` (H2 §6.1).
    pub features: Vec<String>,
    /// Its held reservations.
    pub held: Held,
    /// The volumes in use on the node now, by name, with the `max_mb` each counts against the volume share (H2
    /// §11.3): those of its leases not yet confirmed dead, and those its last `VolumeReport` says a lease holds.
    pub volumes_in_use: BTreeMap<String, u64>,
    /// When it last got or released work (its enrollment, if never): the tie-break.
    pub idle_since: OffsetDateTime,
}

/// Why a node cannot take a job. Static reasons hold whatever the node is doing; the others pass with time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misfit {
    /// Another pool, a pinned other node, or labels that do not match.
    Placement,
    /// No ready sandbox driver.
    NoSandbox,
    /// Its agent did not declare a capability the job needs (H2 §6.1): the capability.
    MissingCapability(&'static str),
    /// The node offers less than the job asks for, even when idle.
    TooSmall,
    /// Its volume share (`Inventory.volumes_mb`) cannot hold the job's volumes even with no volume in use (H2 §11.3).
    NoVolumeSpace,
    /// The node could run the job, but no `admin` has approved it yet (H2 §5.5, SI-H2-19).
    PendingApproval,
    /// Offline, draining or not connected.
    Unavailable,
    /// Not enough free capacity right now.
    Busy,
}

impl Misfit {
    /// Whether the node is ineligible whatever it is doing: it does not count in `matching_nodes` of
    /// `POST /v1/estimate`, and the volume affinity does not wait for it. A `pending_approval` node is ineligible
    /// until an `admin` approves it (H2 §5.5).
    #[must_use]
    pub const fn is_static(self) -> bool {
        matches!(
            self,
            Misfit::Placement
                | Misfit::NoSandbox
                | Misfit::MissingCapability(_)
                | Misfit::TooSmall
                | Misfit::NoVolumeSpace
                | Misfit::PendingApproval
        )
    }
}

/// Whether `c` can take `req` now. On success, the GPU the lease would reserve (`None` for a CPU job).
pub fn fits(c: &Candidate, req: &Request) -> Result<Option<String>, Misfit> {
    if !req.pools.iter().any(|p| p == POOL_MINE) {
        return Err(Misfit::Placement);
    }
    if req.node_id.is_some_and(|n| n != c.node_id) {
        return Err(Misfit::Placement);
    }
    if !req.labels.iter().all(|(k, v)| c.labels.get(k) == Some(v)) {
        return Err(Misfit::Placement);
    }
    if !c.inventory.sandbox.iter().any(|s| s.ready) {
        return Err(Misfit::NoSandbox);
    }
    if let Some(missing) = req.needs.iter().find(|n| !c.features.iter().any(|f| f == *n)) {
        return Err(Misfit::MissingCapability(missing));
    }
    let gpus = offered_gpus(&c.inventory);
    if cpu_milli(c.inventory.offered.cpu) < req.cpu_milli
        || c.inventory.offered.memory_mb < req.memory_mb
        || c.inventory.offered.disk_mb.is_some_and(|d| d < req.disk_mb)
        || gpus.len() < req.gpu as usize
    {
        return Err(Misfit::TooSmall);
    }
    // The volume budget applies only to a job with volumes, on a node that reports its share.
    let volume_share = c.inventory.volumes_mb.filter(|_| !req.volumes.is_empty());
    if volume_share.is_some_and(|share| share < req.volumes_mb()) {
        return Err(Misfit::NoVolumeSpace);
    }
    // After every other static rule: `PendingApproval` then means "approval is all this node lacks for the job".
    if !c.approved {
        return Err(Misfit::PendingApproval);
    }
    if !c.available {
        return Err(Misfit::Unavailable);
    }
    let free = cpu_milli(c.inventory.offered.cpu).saturating_sub(c.held.cpu_milli);
    let free_mem = c.inventory.offered.memory_mb.saturating_sub(c.held.memory_mb);
    // Disk: only when the node reports it (§6 `Inventory`); the same held reservations as CPU.
    let disk_busy = c
        .inventory
        .offered
        .disk_mb
        .is_some_and(|d| d.saturating_sub(c.held.disk_mb) < req.disk_mb);
    if free < req.cpu_milli || free_mem < req.memory_mb || disk_busy {
        return Err(Misfit::Busy);
    }
    // One holder at a time: a volume in use on the node cannot be mounted by this job's container too.
    if req.volumes.iter().any(|v| c.volumes_in_use.contains_key(&v.name)) {
        return Err(Misfit::Busy);
    }
    if let Some(share) = volume_share {
        let in_use = c.volumes_in_use.values().fold(0u64, |sum, mb| sum.saturating_add(*mb));
        if share.saturating_sub(in_use) < req.volumes_mb() {
            return Err(Misfit::Busy);
        }
    }
    if req.gpu == 0 {
        return Ok(None);
    }
    gpus.into_iter()
        .find(|g| !c.held.gpus.contains(g))
        .map(Some)
        .ok_or(Misfit::Busy)
}

/// Parts per million of `total` that `left` is (0 when `total` is 0).
fn ppm(left: u64, total: u64) -> u64 {
    if total == 0 {
        0
    } else {
        u64::try_from(u128::from(left) * 1_000_000 / u128::from(total)).unwrap_or(u64::MAX)
    }
}

/// The best-fit score of placing `req` on `c` (see the module docs): lower is better.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Score {
    /// Fraction of offered GPUs left free, in ppm.
    pub gpu_left: u64,
    /// Fraction of offered memory left free, in ppm.
    pub memory_left: u64,
    /// Fraction of offered CPU left free, in ppm.
    pub cpu_left: u64,
    /// Fraction of offered disk left free, in ppm (0 for a node that does not report disk).
    pub disk_left: u64,
}

/// The score of a node that [`fits`] the request.
#[must_use]
pub fn score(c: &Candidate, req: &Request) -> Score {
    let inv = &c.inventory;
    let gpus = offered_gpus(inv);
    let free_gpus = gpus.iter().filter(|g| !c.held.gpus.contains(*g)).count() as u64;
    let cpu = cpu_milli(inv.offered.cpu);
    Score {
        gpu_left: ppm(free_gpus.saturating_sub(u64::from(req.gpu)), gpus.len() as u64),
        memory_left: ppm(
            inv.offered
                .memory_mb
                .saturating_sub(c.held.memory_mb)
                .saturating_sub(req.memory_mb),
            inv.offered.memory_mb,
        ),
        cpu_left: ppm(cpu.saturating_sub(c.held.cpu_milli).saturating_sub(req.cpu_milli), cpu),
        disk_left: inv.offered.disk_mb.map_or(0, |total| {
            ppm(total.saturating_sub(c.held.disk_mb).saturating_sub(req.disk_mb), total)
        }),
    }
}

/// The chosen node and the GPU it reserves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    /// The node.
    pub node_id: NodeId,
    /// The GPU to reserve, for a GPU job.
    pub gpu_uuid: Option<String>,
}

/// Picks the node for `req` among `candidates` (see the module docs for the order). `avoid` is the node that just
/// lost the job's lease. `None` when no node fits.
#[must_use]
pub fn choose(candidates: &[Candidate], req: &Request, avoid: Option<NodeId>) -> Option<Choice> {
    let key = |c: &Candidate| {
        (
            avoid == Some(c.node_id),
            score(c, req),
            c.idle_since,
            c.node_id.to_string(),
        )
    };
    candidates
        .iter()
        .filter_map(|c| fits(c, req).ok().map(|gpu| (c, gpu)))
        .min_by_key(|(c, _)| key(c))
        .map(|(c, gpu_uuid)| Choice {
            node_id: c.node_id,
            gpu_uuid,
        })
}

/// What the affinity of a requeued service to the node that holds its volume asks for (H2 §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Affinity {
    /// The holder fits now: place the job there.
    Holder(Choice),
    /// The holder is eligible but offline, busy or cooling down for this job: wait for it (the caller bounds the
    /// wait).
    Wait,
    /// The holder is gone or ineligible (deleted, not approved, too small, another placement): nothing to wait for.
    Elsewhere,
}

/// Where a requeued service with a volume goes, as far as `holder` (the node that holds the volume) decides it.
/// `cooling` says whether a node may not be offered this job right now (§8 "Offer cap").
#[must_use]
pub fn affinity(candidates: &[Candidate], req: &Request, holder: NodeId, cooling: &dyn Fn(NodeId) -> bool) -> Affinity {
    let Some(c) = candidates.iter().find(|c| c.node_id == holder) else {
        return Affinity::Elsewhere;
    };
    match fits(c, req) {
        Ok(_) if cooling(holder) => Affinity::Wait,
        Ok(gpu_uuid) => Affinity::Holder(Choice {
            node_id: holder,
            gpu_uuid,
        }),
        Err(e) if e.is_static() => Affinity::Elsewhere,
        Err(_) => Affinity::Wait,
    }
}

/// Why no node will take `req` however long it waits, when that is something the owner can act on (H2 §5.5, §6.1,
/// §11.3): [`Misfit::PendingApproval`] when approval is all a node lacks, else [`Misfit::MissingCapability`] when a
/// node lacks only a capability, else [`Misfit::NoVolumeSpace`] when a node's volume share is too small. `None` when
/// some node is eligible (the job just waits for room, as in H1) or when no node comes that close.
#[must_use]
pub fn why_nowhere(candidates: &[Candidate], req: &Request) -> Option<Misfit> {
    let misfits: Vec<Misfit> = candidates.iter().filter_map(|c| fits(c, req).err()).collect();
    if misfits.len() < candidates.len() || misfits.iter().any(|m| !m.is_static()) {
        return None;
    }
    misfits
        .iter()
        .find(|m| matches!(m, Misfit::PendingApproval))
        .or_else(|| misfits.iter().find(|m| matches!(m, Misfit::MissingCapability(_))))
        .or_else(|| misfits.iter().find(|m| matches!(m, Misfit::NoVolumeSpace)))
        .copied()
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    const T: OffsetDateTime = datetime!(2026-11-05 10:00:00 UTC);

    /// An inventory offering `cpu` vCPUs, `mem` MiB and `gpus` offerable GPUs (plus one MIG card, never offerable).
    fn inv(cpu: f64, mem: u64, gpus: u32) -> Inventory {
        inv_disk(cpu, mem, gpus, Some(51_200))
    }

    /// Like [`inv`], offering `disk` MiB of disk (`None`: an agent that does not report it).
    fn inv_disk(cpu: f64, mem: u64, gpus: u32, disk: Option<u64>) -> Inventory {
        let mut list: Vec<serde_json::Value> = (0..gpus)
            .map(|i| {
                serde_json::json!({"uuid": format!("GPU-{i}"), "index": i, "name": "Example GPU",
                    "driver_version": "1", "vram_mb": 8192, "mig": false})
            })
            .collect();
        list.push(
            serde_json::json!({"uuid": "MIG-x", "index": 99, "name": "Example GPU", "driver_version": "1",
            "vram_mb": 8192, "mig": true}),
        );
        serde_json::from_value(serde_json::json!({
            "hostname": "node", "platform": "linux", "cpu": {"model": "Example CPU", "cores": 64},
            "memory_mb": 262_144, "os": "Ubuntu 24.04", "arch": "x86_64", "gpus": list,
            "gpu_status": {"status": "ok"},
            "sandbox": [{"driver": "podman", "class": "container", "runtimes": ["crun"], "ready": true}],
            "offered": {"cpu": cpu, "memory_mb": mem, "gpu": gpus, "disk_mb": disk}, "agent_version": "0.1.0",
        }))
        .unwrap()
    }

    fn node(cpu: f64, mem: u64, gpus: u32) -> Candidate {
        Candidate {
            node_id: NodeId::generate(),
            inventory: inv(cpu, mem, gpus),
            labels: BTreeMap::new(),
            available: true,
            approved: true,
            features: Vec::new(),
            held: Held::default(),
            volumes_in_use: BTreeMap::new(),
            idle_since: T,
        }
    }

    fn req(cpu: f64, mem: u64, gpu: u32) -> Request {
        Request {
            cpu_milli: cpu_milli(cpu),
            memory_mb: mem,
            disk_mb: 1024,
            gpu,
            pools: vec![POOL_MINE.to_string()],
            ..Request::default()
        }
    }

    fn hold(c: &mut Candidate, cpu: f64, mem: u64, gpu: Option<&str>) {
        c.held.add(&Reserved {
            cpu,
            memory_mb: mem,
            disk_mb: 1024,
            gpu_uuid: gpu.map(str::to_string),
        });
    }

    #[test]
    fn eligibility_checks_each_rule() {
        let c = node(4.0, 8192, 1);
        assert_eq!(fits(&c, &req(4.0, 8192, 1)), Ok(Some("GPU-0".to_string())));
        assert_eq!(fits(&c, &req(4.001, 1024, 0)), Err(Misfit::TooSmall));
        assert_eq!(fits(&c, &req(1.0, 8193, 0)), Err(Misfit::TooSmall));
        // The MIG card is never offerable, so a second GPU does not exist.
        let two = node(4.0, 8192, 1);
        assert_eq!(offered_gpus(&two.inventory), ["GPU-0"]);
        let mut r = req(1.0, 1024, 1);
        r.pools = vec!["public".into()];
        assert_eq!(fits(&c, &r), Err(Misfit::Placement));
        let mut r = req(1.0, 1024, 0);
        r.labels.insert("zone".into(), "a".into());
        assert_eq!(fits(&c, &r), Err(Misfit::Placement), "nodes have no labels in v0.1");
        let mut labelled = c.clone();
        labelled.labels.insert("zone".into(), "a".into());
        assert!(fits(&labelled, &r).is_ok());
        let mut r = req(1.0, 1024, 0);
        r.node_id = Some(NodeId::generate());
        assert_eq!(fits(&c, &r), Err(Misfit::Placement), "pinned to another node");
        r.node_id = Some(c.node_id);
        assert!(fits(&c, &r).is_ok());
        let mut off = c.clone();
        off.available = false;
        assert_eq!(fits(&off, &req(1.0, 1024, 0)), Err(Misfit::Unavailable));
        let mut no_sandbox = c.clone();
        no_sandbox.inventory.sandbox[0].ready = false;
        assert_eq!(fits(&no_sandbox, &req(1.0, 1024, 0)), Err(Misfit::NoSandbox));
    }

    #[test]
    fn held_reservations_count_against_free_capacity() {
        let mut c = node(4.0, 8192, 1);
        hold(&mut c, 3.5, 4096, Some("GPU-0"));
        assert_eq!(fits(&c, &req(0.5, 4096, 0)), Ok(None), "exactly the rest fits");
        assert_eq!(fits(&c, &req(0.501, 1024, 0)), Err(Misfit::Busy));
        assert_eq!(fits(&c, &req(0.25, 4097, 0)), Err(Misfit::Busy));
        assert_eq!(fits(&c, &req(0.25, 128, 1)), Err(Misfit::Busy), "the only GPU is held");
        let free = free_capacity(&c.inventory, &c.held);
        assert_eq!((free.cpu, free.memory_mb, free.gpu), (0.5, 4096, 0));
        // Over-held (an inventory that shrank): free never goes negative.
        hold(&mut c, 10.0, 100_000, None);
        let free = free_capacity(&c.inventory, &c.held);
        assert_eq!((free.cpu, free.memory_mb, free.gpu), (0.0, 0, 0));
    }

    fn disk_req(disk_mb: u64) -> Request {
        Request {
            disk_mb,
            ..req(1.0, 1024, 0)
        }
    }

    /// T06f: a default job holds 2 048 MiB, so the default 50 GiB share takes 25 of them by disk and the 26th waits.
    #[test]
    fn a_node_offering_51_200_mb_fits_25_default_jobs_by_disk_and_not_the_26th() {
        let mut c = node(8.0, 16_384, 0); // 51 200 MiB of disk offered
        let default_job = Request {
            disk_mb: p2pc_proto::api::DEFAULT_DISK_MB,
            ..req(0.25, 128, 0)
        };
        for n in 1..=25 {
            assert_eq!(fits(&c, &default_job), Ok(None), "default job {n} fits");
            c.held.add(&Reserved {
                cpu: 0.25,
                memory_mb: 128,
                disk_mb: default_job.disk_mb,
                gpu_uuid: None,
            });
        }
        // CPU (6.25 of 8) and memory (3 200 of 16 384) are far from full: only the disk says no.
        assert_eq!(fits(&c, &default_job), Err(Misfit::Busy), "the 26th does not fit");
    }

    /// §8 "Eligible nodes" (amended 2026-11-07): free disk = offered `disk_mb` − the disk of the held reservations.
    #[test]
    fn a_node_whose_free_disk_does_not_fit_is_not_eligible() {
        let mut c = node(8.0, 16_384, 0); // 51 200 MiB of disk offered
        assert_eq!(fits(&c, &disk_req(51_200)), Ok(None), "all of it fits when idle");
        assert_eq!(
            fits(&c, &disk_req(51_201)),
            Err(Misfit::TooSmall),
            "never, even when idle"
        );
        // Two jobs of 10 GiB hold 20 GiB (the helper holds 1024 MiB each; add the rest by hand).
        for _ in 0..2 {
            c.held.add(&Reserved {
                cpu: 1.0,
                memory_mb: 1024,
                disk_mb: 10_240,
                gpu_uuid: None,
            });
        }
        assert_eq!(fits(&c, &disk_req(30_720)), Ok(None), "exactly the rest fits");
        assert_eq!(
            fits(&c, &disk_req(30_721)),
            Err(Misfit::Busy),
            "passes with time: busy, not too small"
        );
        assert!(!Misfit::Busy.is_static());
        let free = free_capacity(&c.inventory, &c.held);
        assert_eq!(free.disk_mb, Some(30_720));
        // Over-held: free never goes negative.
        c.held.add(&Reserved {
            cpu: 0.0,
            memory_mb: 0,
            disk_mb: 100_000,
            gpu_uuid: None,
        });
        assert_eq!(free_capacity(&c.inventory, &c.held).disk_mb, Some(0));
    }

    /// The same node becomes eligible when a lease ends: its reservation is no longer held.
    #[test]
    fn the_node_is_eligible_again_when_a_reservation_is_released() {
        let mut c = node(8.0, 16_384, 0);
        let full = Reserved {
            cpu: 1.0,
            memory_mb: 1024,
            disk_mb: 51_200,
            gpu_uuid: None,
        };
        c.held.add(&full);
        assert_eq!(fits(&c, &disk_req(10_240)), Err(Misfit::Busy));
        c.held = Held::default();
        assert_eq!(fits(&c, &disk_req(10_240)), Ok(None));
    }

    /// An agent without `offered.disk_mb` is placed by CPU, memory and GPU only.
    #[test]
    fn a_node_that_does_not_report_disk_is_placed_without_it() {
        let mut c = node(8.0, 16_384, 0);
        c.inventory = inv_disk(8.0, 16_384, 0, None);
        assert_eq!(fits(&c, &disk_req(u64::MAX)), Ok(None));
        c.held.add(&Reserved {
            cpu: 0.0,
            memory_mb: 0,
            disk_mb: u64::MAX,
            gpu_uuid: None,
        });
        assert_eq!(fits(&c, &disk_req(10_240)), Ok(None));
        assert_eq!(free_capacity(&c.inventory, &c.held).disk_mb, None);
    }

    /// Leases stored before disk was placed have no `disk_mb` in `leases.reserved`: they read as 0.
    #[test]
    fn an_old_reservation_row_reads_with_no_disk() {
        let r: Reserved = serde_json::from_str(r#"{"cpu":1.0,"memory_mb":512,"gpu_uuid":null}"#).unwrap();
        assert_eq!(r.disk_mb, 0);
    }

    #[test]
    fn a_gpu_job_gets_a_free_offered_gpu_by_index() {
        let mut c = node(8.0, 16_384, 2);
        assert_eq!(fits(&c, &req(1.0, 1024, 1)), Ok(Some("GPU-0".into())));
        hold(&mut c, 1.0, 1024, Some("GPU-0"));
        assert_eq!(fits(&c, &req(1.0, 1024, 1)), Ok(Some("GPU-1".into())));
        // The owner offers only one of the two GPUs: the second is not offered.
        let mut one = node(8.0, 16_384, 2);
        one.inventory.offered.gpu = 1;
        hold(&mut one, 1.0, 1024, Some("GPU-0"));
        assert_eq!(fits(&one, &req(1.0, 1024, 1)), Err(Misfit::Busy));
    }

    #[test]
    fn the_score_is_gpu_then_memory_then_cpu_left() {
        let gpu_node = node(8.0, 16_384, 1);
        let cpu_node = node(8.0, 16_384, 0);
        // A CPU job leaves the GPU node's GPU free (1e6 ppm) but the CPU node has none to leave (0).
        let r = req(1.0, 1024, 0);
        assert!(score(&cpu_node, &r) < score(&gpu_node, &r));
        assert_eq!(
            choose(&[gpu_node.clone(), cpu_node.clone()], &r, None).unwrap().node_id,
            cpu_node.node_id
        );
        // Memory before CPU: the node left with less memory wins even with more CPU left.
        let mut a = node(8.0, 16_384, 0);
        hold(&mut a, 0.0, 12_288, None);
        let mut b = node(8.0, 16_384, 0);
        hold(&mut b, 6.0, 0, None);
        let r = req(1.0, 1024, 0);
        assert_eq!(
            score(&a, &r),
            Score {
                gpu_left: 0,
                memory_left: 187_500,
                cpu_left: 875_000,
                disk_left: 960_000
            }
        );
        assert!(score(&a, &r) < score(&b, &r));
        assert_eq!(choose(&[b.clone(), a.clone()], &r, None).unwrap().node_id, a.node_id);
        // Same memory left: the CPU decides.
        let mut c = node(8.0, 16_384, 0);
        hold(&mut c, 4.0, 0, None);
        let d = node(8.0, 16_384, 0);
        assert_eq!(choose(&[d, c.clone()], &r, None).unwrap().node_id, c.node_id);
    }

    /// §8 "Choice" (T06c review P3 3): with CPU and memory equal, the node left with less free disk wins.
    #[test]
    fn with_cpu_and_memory_equal_the_node_with_less_free_disk_left_wins() {
        let mut emptier = node(8.0, 16_384, 0);
        let mut fuller = node(8.0, 16_384, 0);
        // The id tie-break would pick `emptier`, so only the disk can make `fuller` win.
        if fuller.node_id < emptier.node_id {
            std::mem::swap(&mut fuller.node_id, &mut emptier.node_id);
        }
        fuller.held.disk_mb = 40_000; // of 51 200 MiB offered
        let r = req(1.0, 1024, 0);
        assert!(score(&fuller, &r) < score(&emptier, &r));
        assert_eq!(
            choose(&[emptier.clone(), fuller.clone()], &r, None).unwrap().node_id,
            fuller.node_id
        );
        // A node that does not report disk scores 0 for it, like any resource it does not offer.
        emptier.inventory = inv_disk(8.0, 16_384, 0, None);
        assert_eq!(score(&emptier, &r).disk_left, 0);
    }

    #[test]
    fn ties_go_to_the_node_idle_longest_then_the_smaller_id() {
        let mut a = node(4.0, 8192, 0);
        let mut b = node(4.0, 8192, 0);
        a.idle_since = T;
        b.idle_since = T - time::Duration::minutes(5);
        let r = req(1.0, 1024, 0);
        assert_eq!(score(&a, &r), score(&b, &r));
        assert_eq!(choose(&[a.clone(), b.clone()], &r, None).unwrap().node_id, b.node_id);
        b.idle_since = T;
        let smaller = if a.node_id.to_string() < b.node_id.to_string() {
            a.node_id
        } else {
            b.node_id
        };
        assert_eq!(choose(&[a.clone(), b.clone()], &r, None).unwrap().node_id, smaller);
        assert_eq!(
            choose(&[b, a], &r, None).unwrap().node_id,
            smaller,
            "the order does not matter"
        );
    }

    #[test]
    fn a_retry_prefers_another_node_but_falls_back_to_the_same_one() {
        let mut a = node(4.0, 8192, 0);
        hold(&mut a, 3.0, 0, None);
        let b = node(4.0, 8192, 0);
        let r = req(1.0, 1024, 0);
        // Best fit is `a` …
        assert_eq!(choose(&[a.clone(), b.clone()], &r, None).unwrap().node_id, a.node_id);
        // … but `a` just lost the lease, so `b` comes first.
        assert_eq!(
            choose(&[a.clone(), b.clone()], &r, Some(a.node_id)).unwrap().node_id,
            b.node_id
        );
        // Alone, `a` is still used.
        assert_eq!(choose(&[a.clone()], &r, Some(a.node_id)).unwrap().node_id, a.node_id);
        assert_eq!(choose(&[], &r, None), None);
    }

    /// SI-H2-19: a `pending_approval` node never fits, whatever it offers; approval is checked after the other
    /// static rules, so the misfit says that approval is all the node lacks.
    #[test]
    fn a_pending_node_never_fits() {
        let mut c = node(4.0, 8192, 1);
        c.approved = false;
        assert_eq!(fits(&c, &req(1.0, 1024, 0)), Err(Misfit::PendingApproval));
        assert_eq!(fits(&c, &req(1.0, 1024, 1)), Err(Misfit::PendingApproval));
        assert_eq!(fits(&c, &req(8.0, 1024, 0)), Err(Misfit::TooSmall));
        assert!(Misfit::PendingApproval.is_static(), "ineligible, not busy");
        assert_eq!(choose(&[c.clone()], &req(1.0, 1024, 0), None), None);
        // Offline and pending: still pending (the approval is what the owner must act on).
        c.available = false;
        assert_eq!(fits(&c, &req(1.0, 1024, 0)), Err(Misfit::PendingApproval));
        let approved = node(4.0, 8192, 0);
        let picked = choose(&[c, approved.clone()], &req(1.0, 1024, 0), None).unwrap();
        assert_eq!(picked.node_id, approved.node_id);
    }

    /// H2 §6.1: a job that needs a capability goes only to an agent that declared it.
    #[test]
    fn a_job_needs_the_capabilities_of_its_kind_volumes_and_blob_inputs() {
        assert!(needs(JobKind::Batch, false, false).is_empty());
        assert_eq!(needs(JobKind::Service, false, false), ["service_jobs"]);
        assert_eq!(
            needs(JobKind::Service, true, true),
            ["service_jobs", "volumes", "blob_inputs"]
        );
        assert_eq!(needs(JobKind::Batch, false, true), ["blob_inputs"]);
        let h1 = node(4.0, 8192, 0);
        let mut h2 = node(4.0, 8192, 0);
        h2.features = vec!["service_jobs".into(), "leave".into()];
        let mut service = req(1.0, 1024, 0);
        service.needs = needs(JobKind::Service, false, false);
        assert_eq!(fits(&h1, &service), Err(Misfit::MissingCapability("service_jobs")));
        assert_eq!(fits(&h2, &service), Ok(None));
        assert!(Misfit::MissingCapability("service_jobs").is_static());
        // A batch job needs none: an H1 agent takes it as before.
        assert_eq!(fits(&h1, &req(1.0, 1024, 0)), Ok(None));
        service.needs = needs(JobKind::Service, true, false);
        assert_eq!(fits(&h2, &service), Err(Misfit::MissingCapability("volumes")));
        assert_eq!(choose(&[h1, h2], &service, None), None, "no node declares `volumes`");
    }

    #[test]
    fn why_nowhere_names_approval_then_a_missing_capability() {
        let mut service = req(1.0, 1024, 0);
        service.needs = needs(JobKind::Service, false, false);
        let h1 = node(4.0, 8192, 0);
        let mut pending = node(4.0, 8192, 0);
        pending.features = vec!["service_jobs".into()];
        pending.approved = false;
        assert_eq!(why_nowhere(&[], &service), None);
        assert_eq!(
            why_nowhere(std::slice::from_ref(&h1), &service),
            Some(Misfit::MissingCapability("service_jobs"))
        );
        assert_eq!(
            why_nowhere(&[h1.clone(), pending.clone()], &service),
            Some(Misfit::PendingApproval)
        );
        // An eligible node that is only busy or offline: the job just waits, as in H1.
        let mut offline = pending.clone();
        offline.approved = true;
        offline.available = false;
        assert_eq!(why_nowhere(&[h1.clone(), pending, offline.clone()], &service), None);
        offline.available = true;
        assert_eq!(why_nowhere(&[h1, offline], &service), None, "it fits");
        // Too small is nothing the reasons explain.
        assert_eq!(why_nowhere(&[node(0.5, 8192, 0)], &req(1.0, 1024, 0)), None);
    }

    /// H2 §7.2 "Waiting for the same node".
    #[test]
    fn affinity_goes_to_the_holder_waits_for_it_or_gives_up() {
        let r = req(1.0, 1024, 0);
        let holder = node(4.0, 8192, 0);
        let other = node(4.0, 8192, 0);
        let all = [holder.clone(), other.clone()];
        let never = |_: NodeId| false;
        assert_eq!(
            affinity(&all, &r, holder.node_id, &never),
            Affinity::Holder(Choice {
                node_id: holder.node_id,
                gpu_uuid: None
            })
        );
        let cooling = |n: NodeId| n == holder.node_id;
        assert_eq!(affinity(&all, &r, holder.node_id, &cooling), Affinity::Wait);
        let mut offline = holder.clone();
        offline.available = false;
        assert_eq!(
            affinity(&[offline, other.clone()], &r, holder.node_id, &never),
            Affinity::Wait
        );
        let mut busy = holder.clone();
        hold(&mut busy, 3.5, 0, None);
        assert_eq!(
            affinity(&[busy, other.clone()], &r, holder.node_id, &never),
            Affinity::Wait
        );
        let mut pending = holder.clone();
        pending.approved = false;
        assert_eq!(
            affinity(&[pending, other.clone()], &r, holder.node_id, &never),
            Affinity::Elsewhere
        );
        assert_eq!(
            affinity(&[other], &r, holder.node_id, &never),
            Affinity::Elsewhere,
            "deleted"
        );
    }

    fn volume(name: &str, max_mb: u64) -> VolumeNeed {
        VolumeNeed {
            name: name.into(),
            max_mb,
        }
    }

    /// H2 §11.3 "Budget": `volumes_mb − Σ max_mb of the volumes in use ≥ Σ max_mb of the job's volumes`; unused
    /// volumes do not count, and a share too small even when nothing is in use makes the node ineligible.
    #[test]
    fn the_volume_share_must_hold_the_volumes_in_use_and_the_jobs_own() {
        let mut r = req(1.0, 1024, 0);
        r.volumes = vec![volume("models", 20_480), volume("cache", 1024)];
        assert_eq!(r.volumes_mb(), 21_504);
        let mut c = node(4.0, 8192, 0);
        c.inventory.volumes_mb = Some(21_504);
        assert_eq!(fits(&c, &r), Ok(None), "exactly enough");
        c.volumes_in_use.insert("other".into(), 1);
        assert_eq!(fits(&c, &r), Err(Misfit::Busy), "another lease's volume counts");
        c.volumes_in_use.clear();

        c.inventory.volumes_mb = Some(21_503);
        assert_eq!(fits(&c, &r), Err(Misfit::NoVolumeSpace));
        assert!(Misfit::NoVolumeSpace.is_static(), "ineligible, not busy");
        assert_eq!(why_nowhere(std::slice::from_ref(&c), &r), Some(Misfit::NoVolumeSpace));
        // One volume larger than the whole share: the same.
        c.inventory.volumes_mb = Some(1024);
        r.volumes = vec![volume("models", 20_480)];
        assert_eq!(fits(&c, &r), Err(Misfit::NoVolumeSpace));
        // Ineligible before it is unapproved, offline or busy: the share is what the owner must change.
        c.approved = false;
        c.available = false;
        assert_eq!(fits(&c, &r), Err(Misfit::NoVolumeSpace));

        // A job without volumes ignores the share, even a share of 0.
        let mut idle = node(4.0, 8192, 0);
        idle.inventory.volumes_mb = Some(0);
        assert_eq!(fits(&idle, &req(1.0, 1024, 0)), Ok(None));
        // A node that does not report its share (no `share_update`) is placed without the budget.
        idle.inventory.volumes_mb = None;
        assert_eq!(fits(&idle, &r), Ok(None));
    }

    /// H2 §11.3 "One holder at a time": a job never goes to a node where one of its volumes is in use; it is busy
    /// there (it passes with time), so the affinity of a requeued service waits for that node.
    #[test]
    fn a_volume_in_use_on_a_node_keeps_its_jobs_off_that_node() {
        let mut r = req(1.0, 1024, 0);
        r.volumes = vec![volume("models", 20_480)];
        let mut holder = node(4.0, 8192, 0);
        holder.inventory.volumes_mb = Some(102_400);
        holder.volumes_in_use.insert("models".into(), 20_480);
        let other = node(4.0, 8192, 0);
        assert_eq!(fits(&holder, &r), Err(Misfit::Busy));
        assert_eq!(why_nowhere(std::slice::from_ref(&holder), &r), None, "it just waits");
        let picked = choose(&[holder.clone(), other.clone()], &r, None).unwrap();
        assert_eq!(picked.node_id, other.node_id);
        let never = |_: NodeId| false;
        assert_eq!(
            affinity(&[holder.clone(), other.clone()], &r, holder.node_id, &never),
            Affinity::Wait
        );
        // The same name is held on the node whatever share is left; another volume is not.
        holder.inventory.volumes_mb = None;
        assert_eq!(fits(&holder, &r), Err(Misfit::Busy));
        r.volumes = vec![volume("cache", 64)];
        assert_eq!(fits(&holder, &r), Ok(None));
        // A job without volumes is not concerned.
        assert_eq!(fits(&holder, &req(1.0, 1024, 0)), Ok(None));
    }

    #[test]
    fn cpu_is_rounded_to_the_milli_vcpu() {
        assert_eq!(cpu_milli(0.29), 290);
        assert_eq!(cpu_milli(4.03), 4030);
        assert_eq!(cpu_milli(-1.0), 0);
        assert_eq!(cpu_milli(f64::NAN), 0);
    }
}
