// SPDX-License-Identifier: Apache-2.0

//! `p2pc-agent` library: the pieces of the node daemon, used by the `p2pc-agent` binary.
//!
//! The agent's local core (T07): who it is, what it may offer, and what the machine can do. None of it installs
//! anything.
//!
//! - [`connection`]: the connection to the control plane (T05b): `join`, then `run`'s single control connection
//!   with heartbeats, the agent-side lease timer (SI-13), reconnects, inventory updates and lease routing. It only
//!   dials out, over iroh (SI-12).
//! - [`config`]: `agent.toml`, the owner's share limits (U9), `[iroh]` and the `[server]` written by `join`.
//! - [`identity`]: the persistent Ed25519 node key, iroh-compatible (§5).
//! - [`inventory`]: CPU, RAM, OS, GPUs, Podman, CDI and gVisor, built into `p2pc_proto`'s `Inventory` (§6).
//! - [`platform`]: the §9.0 platform profiles and their readiness checks.
//! - [`doctor`]: human-readable readiness with fix hints.
//! - [`egress`]: the per-job egress proxy (T09, §9). Besides [`connection`], it is the one module that opens network connections,
//!   and only on behalf of a job, through the deny rules of SI-4 and SI-5.
//! - [`runner`]: every external command, behind a trait with an argv API and a timeout.
//! - [`sandbox`]: the Podman sandbox driver (T08): the §9 argv, the job lifecycle, limits, logs and outputs.
//! - [`executor`]: the lease executor (T10a): admission, runs in the sandbox, logs, output uploads, `JobFinished`,
//!   drain and the SI-13 stop, behind [`connection`]'s lease traits.
//! - [`node`]: the production node as `run` builds it: the data dir's lock, the driver and the executor.
//! - [`host`] and [`parse`]: file access under a configurable root, and pure parsers.

pub mod config;
pub mod connection;
pub mod doctor;
pub mod egress;
pub mod executor;
pub mod host;
pub mod identity;
pub mod inventory;
pub mod node;
pub mod parse;
pub mod platform;
pub mod runner;
pub mod sandbox;
#[cfg(test)]
mod test_logs;
