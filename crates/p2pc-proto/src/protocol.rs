// SPDX-License-Identifier: Apache-2.0

//! Agent protocol messages and length-prefixed JSON framing (spec §6).
//!
//! The control stream carries frames: a `u32` big-endian length, then that many bytes of UTF-8 JSON. Messages are
//! serde enums tagged by `"type"` ([`AgentMsg`], [`ServerMsg`]). Each output upload uses its own stream: an
//! [`UploadHeader`] frame, then the raw bytes, answered by an [`UploadAck`] frame.
//!
//! [`read_frame`] is safe on hostile input (SI-10): it checks the length prefix against the maximum **before**
//! allocating, grows its buffer only as bytes actually arrive, and reports truncation, invalid UTF-8 and invalid
//! JSON as errors, never as panics. A peer that sends such a frame should be disconnected.
//!
//! Decoding a frame only checks shapes. Call [`AgentMsg::validate`] or [`ServerMsg::validate`] on every message
//! from the network to enforce sizes (for example the 64 KiB cap of [`AgentMsg::LogChunk`]).
//!
//! # Compatibility within `p2pc/agent/1` (spec §6)
//!
//! - Receivers **ignore unknown fields**, so additive changes need no new ALPN. The `job` of a
//!   [`ServerMsg::Lease`] decodes as any JSON object ([`LeaseJob`]); the agent then parses it strictly with
//!   [`LeaseJob::parse_strict`] and answers `LeaseRejected{reason: "invalid_job"}` if it does not understand it.
//! - An unknown message `type` is not fatal: it decodes to [`AgentMsg::Unknown`] or [`ServerMsg::Unknown`]. The
//!   server answers [`ServerMsg::Error`] with [`error_code::UNSUPPORTED_MESSAGE`] and keeps the connection; the agent
//!   (which has no error message) ignores it.
//! - A change a peer **must understand to stay safe** (for example a new restriction on a lease) is never just an
//!   added field: it requires a capability the agent declared in `Hello.features`, or a new ALPN.
//! - Versions are semver; the server refuses agents older than its `min_agent_version` with
//!   [`error_code::AGENT_TOO_OLD`].

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::api::{Inventory, JobSpec, LogStream, OutputFile, Sha256Digest};
use crate::auth::JoinToken;
use crate::ids::{AccountId, LeaseId, NodeId};
use crate::validate::{Base64Error, decode_base64_bounded, validate_output_path};

/// Default and spec maximum frame size: 1 MiB (§6).
pub const MAX_FRAME_LEN: u32 = 1024 * 1024;
/// Frame limit for connections that have not joined yet (T05, with [`read_frame_with_limit`]): 64 KiB, which caps
/// the decode amplification an unauthenticated peer can cause.
pub const PRE_JOIN_MAX_FRAME_LEN: u32 = 64 * 1024;
/// Largest decoded `LogChunk.data_b64` (§6: 64 KiB).
pub const MAX_LOG_CHUNK_BYTES: usize = 64 * 1024;
/// Most leases listed in `Hello.running` or `Heartbeat.running`.
pub const MAX_RUNNING_LEASES: usize = 256;
/// Most entries in `JobFinished.outputs`.
pub const MAX_OUTPUT_FILES: usize = 10_000;
/// Longest free-text string in a message (versions, reasons, error messages, inventory names).
pub const MAX_TEXT_LEN: usize = 1024;
/// Most GPUs in an inventory.
pub const MAX_GPUS: usize = 64;
/// Most sandbox drivers in an inventory.
pub const MAX_SANDBOXES: usize = 16;
/// Most runtimes per sandbox driver.
pub const MAX_RUNTIMES: usize = 16;
/// Most readiness problems per sandbox driver.
pub const MAX_SANDBOX_PROBLEMS: usize = 32;
/// Most logical CPUs an inventory may report.
pub const MAX_CORES: u32 = 4096;
/// Most RAM an inventory may report, in MiB (64 TiB).
pub const MAX_NODE_MEMORY_MB: u64 = 64 * 1024 * 1024;
/// Most disk an inventory may report, in MiB (64 PiB).
pub const MAX_NODE_DISK_MB: u64 = 64 * 1024 * 1024 * 1024;
/// Most video memory per GPU, in MiB (1 TiB).
pub const MAX_GPU_VRAM_MB: u64 = 1024 * 1024;
/// Longest GPU UUID.
pub const MAX_GPU_UUID_LEN: usize = 128;
/// Longest reported hostname (a DNS name's maximum).
pub const MAX_HOSTNAME_LEN: usize = 253;
/// Default heartbeat interval (§6).
pub const DEFAULT_HEARTBEAT_INTERVAL_S: u32 = 5;
/// Default server-side lease TTL: a lease expires if the node sends no heartbeat for this long (§6: 60 s).
pub const DEFAULT_LEASE_TTL_S: u32 = 60;
/// Default agent-side lease timer: the agent stops its jobs after hearing nothing from the server for this long
/// (§6 "Liveness on both sides": 45 s, on a monotonic clock).
pub const DEFAULT_AGENT_LEASE_TTL_S: u32 = 45;
/// Required gap between the two timers: `agent_lease_ttl_s + 10 <= lease_ttl_s`, so a partitioned agent always
/// stops its jobs before the server requeues them (SI-13).
pub const AGENT_LEASE_TTL_MARGIN_S: u32 = 10;
// SI-13 for the defaults: a partitioned agent stops before the server requeues. Checked at compile time.
const _: () = assert!(DEFAULT_AGENT_LEASE_TTL_S + AGENT_LEASE_TTL_MARGIN_S <= DEFAULT_LEASE_TTL_S);
/// Time the agent has to answer a `Lease` (§6).
pub const LEASE_ACCEPT_TIMEOUT_S: u32 = 10;
/// Most entries in `Hello.features`.
pub const MAX_FEATURES: usize = 64;
/// Longest entry in `Hello.features`.
pub const MAX_FEATURE_LEN: usize = 64;

/// Stable `code` values of [`ServerMsg::Error`] (spec §6).
pub mod error_code {
    /// The server received a message `type` it does not know ([`super::AgentMsg::Unknown`]). The connection stays
    /// open.
    pub const UNSUPPORTED_MESSAGE: &str = "unsupported_message";
    /// The agent's `agent_version` is older than the server's `min_agent_version`. The server closes the
    /// connection after it.
    pub const AGENT_TOO_OLD: &str = "agent_too_old";
    /// A `Hello` from a NodeId that is not enrolled (§5 "Deletion"). The same answer whether or not that NodeId was
    /// ever enrolled.
    pub const NOT_ENROLLED: &str = "not_enrolled";
    /// A `Join` whose token is unknown, expired, revoked or consumed by another NodeId (§5 "Join tokens").
    pub const INVALID_TOKEN: &str = "invalid_token";
}

/// A lease the agent runs or still holds resources for, as listed in `Hello` and `Heartbeat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunningLease {
    /// Lease.
    pub lease_id: LeaseId,
    /// Its epoch (the attempt number, a fencing token).
    pub epoch: u64,
}

/// Node load, reported in every heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Load {
    /// CPU use of the whole node, 0-100.
    pub cpu_pct: u32,
    /// Memory in use, in MiB.
    pub mem_used_mb: u64,
    /// GPU utilization, 0-100, when the node has a GPU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_util_pct: Option<u32>,
}

/// Why the agent refused a lease (spec §6, the list amended 2026-11-05 for T05b). Every rejection counts as a
/// rejected offer, never as an attempt.
///
/// A reason this version does not know decodes to [`LeaseRejectReason::Unknown`]: §6 says a receiver treats it as a
/// generic rejection, so a newer agent's reason never breaks the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseRejectReason {
    /// The job's `account_id` is not the node's enrolled owner (SI-1).
    NotOwner,
    /// The node cannot provide the sandbox the job needs.
    UnsupportedSandbox,
    /// The node does not have the free capacity.
    InsufficientCapacity,
    /// The node is draining.
    Draining,
    /// The job spec failed validation on the agent.
    InvalidJob,
    /// The node cannot select the GPU the lease names. On WSL2 the CDI spec only offers `nvidia.com/gpu=all`, so a
    /// GPU lease is refused unless the node has exactly one offerable GPU (§9 fixed arguments).
    GpuSelectionUnsupported,
    /// The agent has no lease executor yet, or it is not ready to take leases (T05b's default `LeaseHandler`).
    /// Like every rejection, a rejected offer, never an attempt. Also the answer while the node is not ready, for
    /// example while its RAM size is unknown.
    AgentNotReady,
    /// The lease's `deadline` has already passed when it arrives.
    DeadlinePassed,
    /// A reason this version does not know (from a newer peer): a generic rejection. Never send it.
    #[serde(other)]
    Unknown,
}

/// How an attempt ended, as reported by the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The process exited (see `exit_code`).
    Exited,
    /// Killed at `timeout_s`.
    TimedOut,
    /// Killed after a `Cancel`.
    Cancelled,
    /// The sandbox failed (see `error`, for example `disk_limit`).
    Error,
}

/// Resource use of a finished attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Wall-clock time from start to exit, in milliseconds.
    pub wall_ms: u64,
    /// CPU time used (cgroup stats), in milliseconds.
    pub cpu_used_ms: u64,
    /// Peak resident memory, in MiB.
    pub max_rss_mb: u64,
}

/// Messages from the agent to the server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMsg {
    /// Enrollment, only on the first connection. `Debug` hides the token's code.
    Join {
        /// The join token.
        token: JoinToken,
        /// The node's inventory.
        inventory: Inventory,
    },
    /// First message of every later connection.
    Hello {
        /// Agent version.
        agent_version: String,
        /// Current inventory.
        inventory: Inventory,
        /// Leases the agent is still running, and the ones whose `JobFinished` the server has not confirmed yet, for
        /// reconciliation.
        running: Vec<RunningLease>,
        /// Capabilities the agent understands, for example `"lease_restrictions_v1"`. Absent means none.
        ///
        /// Receivers ignore unknown fields, so a new field is only safe when a peer that ignores it stays safe. A
        /// change the agent **must understand** (such as a new restriction on a lease) needs either a capability
        /// listed here, so the server sends such leases only to agents that declared it, or a new ALPN.
        #[serde(default)]
        features: Vec<String>,
    },
    /// Liveness and load, every `heartbeat_interval_s`.
    Heartbeat {
        /// Sequence number.
        seq: u64,
        /// Current load.
        load: Load,
        /// Every lease that still holds resources on the node: running, uploading or being cleaned up (spec §6). A
        /// lease leaves the list when its container is removed and its job directory deleted, whether or not the
        /// server confirmed its `JobFinished`. The server frees a finished lease's reservation at the first heartbeat
        /// that no longer lists it. An older agent lists only the leases that run.
        running: Vec<RunningLease>,
    },
    /// The agent's periodic re-detection (every 10 minutes) found a change, for example a driver installed after
    /// start. The server replaces the stored inventory and recomputes the offered capacity (§6).
    InventoryUpdate {
        /// The new inventory, validated like the one in `Hello` and `Join`.
        inventory: Inventory,
    },
    /// The agent accepts a lease.
    LeaseAccepted {
        /// Lease.
        lease_id: LeaseId,
        /// Epoch.
        epoch: u64,
    },
    /// The agent refuses a lease.
    LeaseRejected {
        /// Lease.
        lease_id: LeaseId,
        /// Epoch.
        epoch: u64,
        /// Why.
        reason: LeaseRejectReason,
    },
    /// The job process started.
    JobStarted {
        /// Lease.
        lease_id: LeaseId,
        /// Epoch.
        epoch: u64,
        /// When it started.
        #[serde(with = "crate::timestamp")]
        started_at: OffsetDateTime,
    },
    /// A chunk of output.
    LogChunk {
        /// Lease.
        lease_id: LeaseId,
        /// Epoch.
        epoch: u64,
        /// Source stream.
        stream: LogStream,
        /// Sequence number within the attempt.
        seq: u64,
        /// The bytes, standard padded base64; at most 64 KiB decoded.
        data_b64: LogData,
    },
    /// The attempt ended.
    JobFinished {
        /// Lease.
        lease_id: LeaseId,
        /// Epoch.
        epoch: u64,
        /// How it ended.
        outcome: Outcome,
        /// Exit code, when the process exited.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        /// Short error code, for `outcome = "error"`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        /// Resource use.
        usage: Usage,
        /// Files uploaded from `/outputs`.
        outputs: Vec<OutputFile>,
    },
    /// A message `type` this version does not know (sent by a newer agent). Not fatal: the server answers
    /// `Error{code: "unsupported_message"}` and keeps the connection. Never send it.
    #[serde(other)]
    Unknown,
}

/// Messages from the server to the agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Answer to `Join` or `Hello`.
    Welcome {
        /// Server version (semver).
        server_version: String,
        /// The node's ID.
        node_id: NodeId,
        /// The account the node is enrolled into. The agent stores it at `Join` and checks every `Lease` against it
        /// (SI-1); it refuses a later `Welcome` with a different one.
        account_id: AccountId,
        /// How often to heartbeat.
        heartbeat_interval_s: u32,
        /// The server-side lease TTL. The agent checks `agent_lease_ttl_s + 10 <= lease_ttl_s`, and lowers its own
        /// timer (with a warning) if not.
        lease_ttl_s: u32,
    },
    /// The answer to every `Heartbeat`, echoing its `seq`: the agent's proof that the server is alive
    /// (§6 "Liveness on both sides").
    HeartbeatAck {
        /// The `seq` of the heartbeat being acknowledged.
        seq: u64,
    },
    /// Run a job. `Debug` hides the job's env values.
    Lease {
        /// Lease.
        lease_id: LeaseId,
        /// Epoch (the attempt number).
        epoch: u64,
        /// The job, decoded **leniently** (any JSON object) so that the agent can always read `lease_id`. The agent
        /// then calls [`LeaseJob::parse_strict`] and answers `LeaseRejected{reason: "invalid_job"}` if it fails.
        job: LeaseJob,
        /// The job's account. The agent MUST refuse a lease for another account (SI-1).
        account_id: AccountId,
        /// When the lease must be done by.
        #[serde(with = "crate::timestamp")]
        deadline: OffsetDateTime,
    },
    /// Stop a lease.
    Cancel {
        /// Lease.
        lease_id: LeaseId,
        /// Epoch.
        epoch: u64,
        /// Why (for example `user`, `stale_epoch`).
        reason: String,
    },
    /// Stop taking new leases (`Drain{}` in §6).
    Drain {},
    /// Take new leases again (`Resume{}` in §6).
    Resume {},
    /// A protocol error. See [`error_code`] for the codes and whether the connection stays open.
    Error {
        /// Stable code.
        code: String,
        /// Human message.
        message: String,
    },
    /// A message `type` this version does not know (sent by a newer server). Not fatal: the agent ignores it.
    /// Never send it.
    #[serde(other)]
    Unknown,
}

/// First frame of an upload stream, followed by exactly `size` raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadHeader {
    /// Lease.
    pub lease_id: LeaseId,
    /// Epoch.
    pub epoch: u64,
    /// Path relative to `/outputs`.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256 of the bytes.
    pub sha256: Sha256Digest,
}

/// The server's answer to an upload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadAck {
    /// Whether the file was stored.
    pub ok: bool,
    /// Why not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl UploadAck {
    /// The file is staged.
    #[must_use]
    pub fn accepted() -> Self {
        Self { ok: true, reason: None }
    }

    /// The upload was refused, with one of the [`upload_reason`] codes.
    #[must_use]
    pub fn refused(reason: &str) -> Self {
        Self {
            ok: false,
            reason: Some(reason.to_string()),
        }
    }
}

/// The `reason` codes of a refused [`UploadAck`] (§6 "Uploads", T10b). Stable; a receiver treats an unknown code as a
/// generic refusal.
pub mod upload_reason {
    /// The header frame is missing, over 1 MiB, malformed or invalid.
    pub const INVALID_HEADER: &str = "invalid_header";
    /// `(lease_id, epoch)` is not the job's current lease (SI-8). The node also gets `Cancel`.
    pub const STALE_EPOCH: &str = "stale_epoch";
    /// The lease is unknown, or held by another node.
    pub const UNKNOWN_LEASE: &str = "unknown_lease";
    /// The path is not a plain relative path (SI-9).
    pub const INVALID_PATH: &str = "invalid_path";
    /// The path was already uploaded for this attempt, with other content.
    pub const DUPLICATE_PATH: &str = "duplicate_path";
    /// The file does not fit in what is left of the job's `outputs.max_mb`.
    pub const TOO_LARGE: &str = "too_large";
    /// The attempt already has the most output files allowed.
    pub const TOO_MANY_FILES: &str = "too_many_files";
    /// Too many uploads at once (2 per node, 8 in total): retry later.
    pub const TOO_MANY_UPLOADS: &str = "too_many_uploads";
    /// The attempt's outputs were already finalised (`JobFinished`), or the lease already reported `JobFinished`:
    /// stop uploading for that lease. No `Cancel` comes with it (the execution ended normally).
    pub const FINALIZED: &str = "finalized";
    /// The stream did not carry exactly `size` bytes.
    pub const SIZE_MISMATCH: &str = "size_mismatch";
    /// The bytes do not hash to `sha256`.
    pub const SHA256_MISMATCH: &str = "sha256_mismatch";
    /// The stream was idle for 30 s, or slower than 64 KiB/s after its first 10 s.
    pub const TIMEOUT: &str = "timeout";
    /// The server could not store the file.
    pub const INTERNAL: &str = "internal";
}

/// A message that is well-formed JSON but breaks a protocol limit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("protocol violation in `{field}`: {reason}")]
pub struct ProtocolViolation {
    /// The offending field.
    pub field: &'static str,
    /// What is wrong.
    pub reason: &'static str,
}

fn violation(field: &'static str, reason: &'static str) -> ProtocolViolation {
    ProtocolViolation { field, reason }
}

fn check_text(field: &'static str, s: &str) -> Result<(), ProtocolViolation> {
    if s.len() > MAX_TEXT_LEN {
        return Err(violation(field, "too long"));
    }
    if s.chars().any(char::is_control) {
        return Err(violation(field, "control characters"));
    }
    Ok(())
}

fn check_pct(field: &'static str, v: u32) -> Result<(), ProtocolViolation> {
    if v > 100 {
        Err(violation(field, "must be 0-100"))
    } else {
        Ok(())
    }
}

fn check_running(running: &[RunningLease]) -> Result<(), ProtocolViolation> {
    if running.len() > MAX_RUNNING_LEASES {
        Err(violation("running", "too many leases"))
    } else {
        Ok(())
    }
}

/// Checks the size limits of an inventory received from the network.
pub fn validate_inventory(inv: &Inventory) -> Result<(), ProtocolViolation> {
    check_text("inventory.cpu.model", &inv.cpu.model)?;
    check_text("inventory.os", &inv.os)?;
    check_text("inventory.arch", &inv.arch)?;
    check_text("inventory.agent_version", &inv.agent_version)?;
    if inv.gpus.len() > MAX_GPUS {
        return Err(violation("inventory.gpus", "too many GPUs"));
    }
    let host = inv.hostname.as_bytes();
    let host_ok = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_');
    if host.is_empty() || host.len() > MAX_HOSTNAME_LEN || !host.iter().all(host_ok) {
        return Err(violation(
            "inventory.hostname",
            "must be 1-253 characters of A-Z, a-z, 0-9, '-', '.', '_'",
        ));
    }
    let mut uuids = std::collections::BTreeSet::new();
    for gpu in &inv.gpus {
        let u = gpu.uuid.as_bytes();
        let uuid_ok = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.' | b'/');
        if u.is_empty() || u.len() > MAX_GPU_UUID_LEN || !u.iter().all(uuid_ok) {
            return Err(violation(
                "inventory.gpus.uuid",
                "must be 1-128 characters of A-Z, a-z, 0-9, - _ : . /",
            ));
        }
        if !uuids.insert(gpu.uuid.as_str()) {
            return Err(violation("inventory.gpus.uuid", "duplicate GPU UUID"));
        }
        check_text("inventory.gpus.name", &gpu.name)?;
        check_text("inventory.gpus.driver_version", &gpu.driver_version)?;
        for (field, value) in [
            ("inventory.gpus.cuda_driver_version", &gpu.cuda_driver_version),
            ("inventory.gpus.compute_capability", &gpu.compute_capability),
            ("inventory.gpus.pci_bdf", &gpu.pci_bdf),
        ] {
            if let Some(v) = value {
                check_text(field, v)?;
            }
        }
        if gpu.vram_mb.is_some_and(|v| v > MAX_GPU_VRAM_MB) {
            return Err(violation("inventory.gpus.vram_mb", "must be at most 1 TiB"));
        }
    }
    if let Some(reason) = &inv.gpu_status.reason {
        check_text("inventory.gpu_status.reason", reason)?;
    }
    if let Some(w) = &inv.wsl2 {
        if let Some(v) = &w.distro_version {
            check_text("inventory.wsl2.distro_version", v)?;
        }
        if let Some(v) = &w.podman_version {
            check_text("inventory.wsl2.podman_version", v)?;
        }
        if let Some(detail) = w.smoke.as_ref().and_then(|s| s.detail.as_ref()) {
            check_text("inventory.wsl2.smoke.detail", detail)?;
        }
    }
    if inv.sandbox.len() > MAX_SANDBOXES {
        return Err(violation("inventory.sandbox", "too many sandbox drivers"));
    }
    for sb in &inv.sandbox {
        check_text("inventory.sandbox.driver", &sb.driver)?;
        if sb.runtimes.len() > MAX_RUNTIMES {
            return Err(violation("inventory.sandbox.runtimes", "too many runtimes"));
        }
        for rt in &sb.runtimes {
            check_text("inventory.sandbox.runtimes", rt)?;
        }
        if sb.problems.len() > MAX_SANDBOX_PROBLEMS {
            return Err(violation("inventory.sandbox.problems", "too many problems"));
        }
        for problem in &sb.problems {
            check_text("inventory.sandbox.problems", problem)?;
        }
    }
    // Hardware bounds: anything outside them is a broken or lying agent.
    if !(1..=MAX_CORES).contains(&inv.cpu.cores) {
        return Err(violation("inventory.cpu.cores", "must be 1-4096"));
    }
    if !(1..=MAX_NODE_MEMORY_MB).contains(&inv.memory_mb) {
        return Err(violation("inventory.memory_mb", "must be 1 MiB to 64 TiB"));
    }
    // The scheduler (§8) trusts `offered`, so it never exceeds the reported hardware.
    let o = &inv.offered;
    if !(o.cpu.is_finite() && o.cpu >= 0.0 && o.cpu <= f64::from(inv.cpu.cores)) {
        return Err(violation(
            "inventory.offered.cpu",
            "must be between 0 and the logical CPU count",
        ));
    }
    if o.memory_mb > inv.memory_mb {
        return Err(violation("inventory.offered.memory_mb", "must not exceed memory_mb"));
    }
    // Only offerable GPUs count: MIG disabled and VRAM known (§6 "GPU inventory").
    let offerable = inv.gpus.iter().filter(|g| g.is_offerable()).count();
    if usize::try_from(o.gpu).map_or(true, |g| g > offerable) {
        return Err(violation(
            "inventory.offered.gpu",
            "must not exceed the number of offerable GPUs",
        ));
    }
    // The offered disk (§6, §8) never exceeds the filesystem the agent reports. An agent without the fields is placed
    // by CPU, memory and GPU only.
    if inv.disk_total_mb.is_some_and(|t| t > MAX_NODE_DISK_MB) {
        return Err(violation("inventory.disk_total_mb", "must be at most 64 PiB"));
    }
    if let Some(disk) = o.disk_mb {
        if disk > MAX_NODE_DISK_MB {
            return Err(violation("inventory.offered.disk_mb", "must be at most 64 PiB"));
        }
        if inv.disk_total_mb.is_some_and(|total| disk > total) {
            return Err(violation(
                "inventory.offered.disk_mb",
                "must not exceed the filesystem (disk_total_mb)",
            ));
        }
    }
    Ok(())
}

/// The `data_b64` of a [`AgentMsg::LogChunk`]: job output as standard padded base64. On the wire it is a plain JSON
/// string. `Debug` shows only its length, because job output can contain anything, secrets included (the same
/// treatment as [`InputFile`](crate::api::InputFile)'s content).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LogData(pub String);

impl LogData {
    /// `bytes` as standard padded base64, the form `data_b64` carries. The caller keeps chunks within
    /// [`MAX_LOG_CHUNK_BYTES`].
    #[must_use]
    pub fn encode(bytes: &[u8]) -> Self {
        Self(data_encoding::BASE64.encode(bytes))
    }

    /// The base64 text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for LogData {
    fn from(b64: String) -> Self {
        Self(b64)
    }
}

impl From<&str> for LogData {
    fn from(b64: &str) -> Self {
        Self(b64.to_string())
    }
}

impl fmt::Debug for LogData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogData").field("len", &self.0.len()).finish()
    }
}

/// Checks that `data_b64` is padded base64 of at most 64 KiB decoded, and returns the decoded size.
///
/// The size comes from the encoded length and is checked first; only a chunk within the limit is decoded (to check
/// its alphabet), so an oversized chunk costs nothing.
pub fn validate_log_chunk_data(data_b64: &str) -> Result<usize, Base64Error> {
    decode_base64_bounded(data_b64, MAX_LOG_CHUNK_BYTES).map(|v| v.len())
}

impl AgentMsg {
    /// The `"type"` tag of this message.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            AgentMsg::Join { .. } => "join",
            AgentMsg::Hello { .. } => "hello",
            AgentMsg::Heartbeat { .. } => "heartbeat",
            AgentMsg::InventoryUpdate { .. } => "inventory_update",
            AgentMsg::LeaseAccepted { .. } => "lease_accepted",
            AgentMsg::LeaseRejected { .. } => "lease_rejected",
            AgentMsg::JobStarted { .. } => "job_started",
            AgentMsg::LogChunk { .. } => "log_chunk",
            AgentMsg::JobFinished { .. } => "job_finished",
            AgentMsg::Unknown => "unknown",
        }
    }

    /// Enforces the protocol's size limits. The server calls it on every message from an agent.
    pub fn validate(&self) -> Result<(), ProtocolViolation> {
        match self {
            AgentMsg::Join { inventory, .. } | AgentMsg::InventoryUpdate { inventory } => validate_inventory(inventory),
            AgentMsg::Hello {
                agent_version,
                inventory,
                running,
                features,
            } => {
                check_text("agent_version", agent_version)?;
                validate_inventory(inventory)?;
                check_running(running)?;
                if features.len() > MAX_FEATURES {
                    return Err(violation("features", "too many features"));
                }
                for f in features {
                    if f.len() > MAX_FEATURE_LEN {
                        return Err(violation("features", "feature name too long"));
                    }
                    check_text("features", f)?;
                }
                Ok(())
            }
            AgentMsg::Heartbeat { load, running, .. } => {
                check_pct("load.cpu_pct", load.cpu_pct)?;
                if let Some(g) = load.gpu_util_pct {
                    check_pct("load.gpu_util_pct", g)?;
                }
                check_running(running)
            }
            AgentMsg::LeaseAccepted { .. }
            | AgentMsg::LeaseRejected { .. }
            | AgentMsg::JobStarted { .. }
            | AgentMsg::Unknown => Ok(()),
            AgentMsg::LogChunk { data_b64, .. } => {
                validate_log_chunk_data(data_b64.as_str())
                    .map(|_| ())
                    .map_err(|e| match e {
                        Base64Error::TooLarge => violation("data_b64", "over 64 KiB decoded"),
                        Base64Error::Invalid => violation("data_b64", "not padded base64"),
                    })
            }
            AgentMsg::JobFinished { error, outputs, .. } => {
                if let Some(e) = error {
                    check_text("error", e)?;
                }
                if outputs.len() > MAX_OUTPUT_FILES {
                    return Err(violation("outputs", "too many files"));
                }
                for o in outputs {
                    validate_output_path(&o.path).map_err(|_| violation("outputs.path", "invalid output path"))?;
                }
                // The same set rules as input files: no duplicates, no path that is a directory of another.
                if !crate::validate::path_set_issues(outputs.iter().map(|o| o.path.as_str())).is_empty() {
                    return Err(violation(
                        "outputs.path",
                        "duplicate output path, or one output path is a directory of another",
                    ));
                }
                Ok(())
            }
        }
    }
}

impl ServerMsg {
    /// The `"type"` tag of this message.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            ServerMsg::Welcome { .. } => "welcome",
            ServerMsg::HeartbeatAck { .. } => "heartbeat_ack",
            ServerMsg::Lease { .. } => "lease",
            ServerMsg::Cancel { .. } => "cancel",
            ServerMsg::Drain {} => "drain",
            ServerMsg::Resume {} => "resume",
            ServerMsg::Error { .. } => "error",
            ServerMsg::Unknown => "unknown",
        }
    }

    /// Enforces size limits on text fields. The agent also validates a lease's job with
    /// [`JobSpec::validate`](crate::api::JobSpec::validate) before running it.
    pub fn validate(&self) -> Result<(), ProtocolViolation> {
        match self {
            ServerMsg::Welcome {
                server_version,
                heartbeat_interval_s,
                lease_ttl_s,
                ..
            } => {
                check_text("server_version", server_version)?;
                if *heartbeat_interval_s == 0 {
                    return Err(violation("heartbeat_interval_s", "must be positive"));
                }
                if lease_ttl_s <= heartbeat_interval_s {
                    return Err(violation("lease_ttl_s", "must be longer than heartbeat_interval_s"));
                }
                Ok(())
            }
            ServerMsg::HeartbeatAck { .. } => Ok(()),
            ServerMsg::Lease { .. } | ServerMsg::Drain {} | ServerMsg::Resume {} | ServerMsg::Unknown => Ok(()),
            ServerMsg::Cancel { reason, .. } => check_text("reason", reason),
            ServerMsg::Error { code, message } => {
                check_text("code", code)?;
                check_text("message", message)
            }
        }
    }
}

impl UploadHeader {
    /// Checks the path (no traversal, SI-9).
    pub fn validate(&self) -> Result<(), ProtocolViolation> {
        validate_output_path(&self.path).map_err(|_| violation("path", "invalid output path"))
    }
}

/// Why a frame could not be read or written. Messages never contain frame content (they could carry secrets).
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The length prefix is over the maximum. Nothing was allocated.
    #[error("frame of {len} bytes is over the maximum of {max}")]
    TooLarge {
        /// Announced length.
        len: u32,
        /// The maximum in force.
        max: u32,
    },
    /// The stream ended inside a frame.
    #[error("the stream ended inside a frame")]
    Truncated,
    /// The payload is not UTF-8.
    #[error("the frame is not valid UTF-8")]
    InvalidUtf8,
    /// The payload is not valid JSON for the expected message.
    #[error("invalid JSON message ({category}) at line {line}, column {column}")]
    InvalidJson {
        /// `syntax`, `data` or `eof`.
        category: &'static str,
        /// Line of the error.
        line: usize,
        /// Column of the error.
        column: usize,
    },
    /// The message could not be encoded.
    #[error("the message could not be encoded")]
    Encode,
    /// An I/O error of the underlying stream.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Writes one frame: the JSON of `msg`, prefixed by its length as a big-endian `u32`, then flushes.
///
/// Refuses (with [`FrameError::TooLarge`]) a message whose JSON is over [`MAX_FRAME_LEN`].
pub async fn write_frame<W, T>(writer: &mut W, msg: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin + ?Sized,
    T: Serialize + ?Sized,
{
    let mut buf = vec![0u8; 4];
    serde_json::to_writer(&mut buf, msg).map_err(|_| FrameError::Encode)?;
    let len = buf.len() - 4;
    let len32 = u32::try_from(len).ok().filter(|l| *l <= MAX_FRAME_LEN);
    let Some(len32) = len32 else {
        return Err(FrameError::TooLarge {
            len: u32::try_from(len).unwrap_or(u32::MAX),
            max: MAX_FRAME_LEN,
        });
    };
    buf[..4].copy_from_slice(&len32.to_be_bytes());
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

/// Size of the read chunk, and the first allocation for a frame body.
const READ_CHUNK: usize = 4 * 1024;

/// Reads one frame and decodes it as `T`.
///
/// - Returns `Ok(None)` on a clean end of stream before the first byte of a frame.
/// - The length prefix is checked against `min(max_len, MAX_FRAME_LEN)` before anything is allocated
///   ([`FrameError::TooLarge`]): a larger `max_len` is clamped to the spec's 1 MiB.
/// - A stream that ends inside the prefix or the body gives [`FrameError::Truncated`].
/// - Bad UTF-8 and bad JSON give their own errors.
/// - An unknown `"type"` is **not** an error: it decodes to the message enum's `Unknown` variant (spec §6).
///
/// It reads exactly one frame and nothing more, so on an upload stream the raw bytes that follow the header frame
/// stay unread.
///
/// It is **not** cancellation-safe: if the future is dropped mid-frame (for example by a `select!` timeout), the
/// stream is out of sync and must be closed. It sets no timeout itself; callers wrap it in one.
///
/// # Decode amplification
///
/// `max_len` bounds the **frame**, not the memory used to decode it. [`AgentMsg`] and [`ServerMsg`] are internally
/// tagged enums, and serde buffers their whole content into an intermediate tree before choosing the variant. Each
/// small JSON token (for example the `0,` of a long array) becomes a node of 16-32 bytes plus vector overhead, so a
/// hostile 1 MiB frame can transiently cost roughly **16-30× its size** (tens of MiB) while it is decoded. It is
/// freed when decoding ends, and the result is still bounded. Where the peer is not yet authenticated, use
/// [`read_frame_with_limit`] with a smaller limit: T05 uses [`PRE_JOIN_MAX_FRAME_LEN`] (64 KiB) before `Join`.
pub async fn read_frame<T, R>(reader: &mut R, max_len: u32) -> Result<Option<T>, FrameError>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin + ?Sized,
{
    let Some(body) = read_frame_bytes(reader, max_len).await? else {
        return Ok(None);
    };
    decode_frame(&body).map(Some)
}

/// The first half of [`read_frame`]: reads one frame's raw body without decoding it, with the same limits (the
/// effective maximum is `min(max_len, MAX_FRAME_LEN)`) and the same memory behaviour. `Ok(None)` on a clean end of
/// stream.
///
/// With [`decode_frame`], it lets a server bound how many frames are **decoded** at once (the costly part, see
/// "Decode amplification" on [`read_frame`]) without holding that bound while a slow peer trickles bytes.
pub async fn read_frame_bytes<R>(reader: &mut R, max_len: u32) -> Result<Option<Vec<u8>>, FrameError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    // Never above the spec's 1 MiB, whatever the caller passes (T02 review P3).
    read_frame_body(reader, max_len.min(MAX_FRAME_LEN)).await
}

/// The second half of [`read_frame`]: decodes a frame body read by [`read_frame_bytes`]. Errors never quote the
/// content.
pub fn decode_frame<T: DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    let text = std::str::from_utf8(body).map_err(|_| FrameError::InvalidUtf8)?;
    serde_json::from_str::<T>(text).map_err(|e| classify_json_error(&e))
}

/// [`read_frame`] with a smaller limit: the effective maximum is `min(limit, MAX_FRAME_LEN)`, so it can never exceed
/// the spec's 1 MiB. Use it to cap the decode cost (see "Decode amplification" on [`read_frame`]) on unauthenticated
/// connections, for example [`PRE_JOIN_MAX_FRAME_LEN`] before `Join`.
pub async fn read_frame_with_limit<T, R>(reader: &mut R, limit: u32) -> Result<Option<T>, FrameError>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin + ?Sized,
{
    read_frame(reader, limit).await
}

/// Reads the raw bytes of one frame.
///
/// Memory: the buffer starts at 4 KiB (or the frame length, if smaller) and at most doubles each time it fills,
/// never past the announced length. So it never holds more than `max_len` bytes, and never more than about twice
/// what the peer actually sent: a peer that announces 1 MiB and sends nothing costs 4 KiB.
async fn read_frame_body<R>(reader: &mut R, max_len: u32) -> Result<Option<Vec<u8>>, FrameError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut prefix = [0u8; 4];
    let mut filled = 0;
    while filled < prefix.len() {
        let n = reader.read(&mut prefix[filled..]).await?;
        if n == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(FrameError::Truncated)
            };
        }
        filled += n;
    }
    let len = u32::from_be_bytes(prefix);
    if len > max_len {
        return Err(FrameError::TooLarge { len, max: max_len });
    }
    let len = len as usize;
    let mut body: Vec<u8> = Vec::with_capacity(len.min(READ_CHUNK));
    let mut chunk = [0u8; READ_CHUNK];
    while body.len() < len {
        let want = (len - body.len()).min(READ_CHUNK);
        let n = reader.read(&mut chunk[..want]).await?;
        if n == 0 {
            return Err(FrameError::Truncated);
        }
        if body.capacity() - body.len() < n {
            let target = body.capacity().saturating_mul(2).max(body.len() + n).min(len);
            body.reserve_exact(target - body.len());
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok(Some(body))
}

/// Keeps only the category and position of a JSON error: serde messages can quote frame content (secrets).
fn classify_json_error(err: &serde_json::Error) -> FrameError {
    let category = match err.classify() {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "eof",
    };
    FrameError::InvalidJson {
        category,
        line: err.line(),
        column: err.column(),
    }
}

/// A [`ServerMsg::Lease`] carrying `spec` **as given**, with worst-case envelope values: IDs (always 26-character
/// ULIDs), `epoch = u64::MAX` and the longest RFC 3339 deadline (`9999-12-31T23:59:59.999999999Z`). Any real lease
/// for the same job serializes to at most this size. See [`lease_frame_len`].
#[must_use]
pub fn worst_case_lease(spec: &JobSpec) -> ServerMsg {
    ServerMsg::Lease {
        lease_id: LeaseId::from_ulid(ulid::Ulid::nil()),
        epoch: u64::MAX,
        job: LeaseJob::from_spec(spec),
        account_id: AccountId::from_ulid(ulid::Ulid::nil()),
        deadline: worst_case_deadline(),
    }
}

/// The longest deadline a `Lease` can carry: `9999-12-31T23:59:59.999999999Z`, the last instant RFC 3339 can
/// write. It is built from the calendar date and time, so it does not depend on the `time/large-dates` feature
/// (with it, a saturating add would reach a year RFC 3339 cannot format).
///
/// The fallback (only if the constant date or time were rejected, which they are not) is the Unix epoch pushed to
/// the maximum. That fails closed: under `large-dates` it cannot be formatted, so [`lease_frame_len`] returns
/// `usize::MAX` and the job is refused, never accepted on an underestimate.
#[must_use]
pub fn worst_case_deadline() -> OffsetDateTime {
    let date = time::Date::from_calendar_date(9999, time::Month::December, 31);
    let clock = time::Time::from_hms_nano(23, 59, 59, 999_999_999);
    match (date, clock) {
        (Ok(d), Ok(t)) => time::PrimitiveDateTime::new(d, t).assume_utc(),
        _ => OffsetDateTime::UNIX_EPOCH.saturating_add(time::Duration::new(i64::MAX, 999_999_999)),
    }
}

/// The exact JSON size, in bytes, of the worst-case `Lease` frame body for this job, measured on the job **as the
/// server stores it**, with the image normalized (it only grows). Spec §7 `files`: the server refuses a job when
/// this exceeds [`MAX_FRAME_LEN`] (`422 too_large`; [`JobSpec::validate`] does it). `usize::MAX` if the job cannot
/// be serialized.
#[must_use]
pub fn lease_frame_len(spec: &JobSpec) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(buf.len());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let normalized;
    let stored = match crate::validate::ImageRef::parse(&spec.image) {
        Ok(image) => {
            normalized = JobSpec {
                image: image.to_string(),
                ..spec.clone()
            };
            &normalized
        }
        Err(_) => spec,
    };
    let mut counter = Counter(0);
    match serde_json::to_writer(&mut counter, &worst_case_lease(stored)) {
        Ok(()) => counter.0,
        Err(_) => usize::MAX,
    }
}

/// The `job` of a [`ServerMsg::Lease`] as it travels: any JSON object (spec §6, 9c5b740).
///
/// Decoding a `Lease` frame never fails because of the job, so the agent always learns the `lease_id` it must
/// answer. It then applies the "must understand" rule explicitly with [`LeaseJob::parse_strict`] (strict
/// [`JobSpec`] parse, unknown fields refused, then the §7 validation) and answers
/// `LeaseRejected{reason: "invalid_job"}` ([`LeaseRejectReason::InvalidJob`]) on failure. That counts as a rejected
/// offer, not as an attempt.
///
/// `Debug` lists the top-level keys only: values may hold env secrets or file contents.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LeaseJob(serde_json::Map<String, serde_json::Value>);

impl LeaseJob {
    /// The server builds the lease's job from a validated spec.
    ///
    /// Serializing a `JobSpec` to a JSON object cannot fail; if it ever did, the result is an empty object, which
    /// the agent refuses as `invalid_job` (a safe failure, never a silently different job).
    #[must_use]
    pub fn from_spec(spec: &JobSpec) -> Self {
        match serde_json::to_value(spec) {
            Ok(serde_json::Value::Object(map)) => Self(map),
            _ => Self(serde_json::Map::new()),
        }
    }

    /// The raw JSON object.
    #[must_use]
    pub fn as_object(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.0
    }

    /// The agent's check: strict parse as [`JobSpec`] (unknown fields refused), then [`JobSpec::validate`] with
    /// [`Limits::agent`](crate::validate::Limits::agent).
    ///
    /// Every structural and safety rule applies. Server policy (the allowed registries) is skipped, because the
    /// server enforced it when the job was created, so a job on a registry the server allows by configuration is
    /// accepted.
    pub fn parse_strict(&self) -> Result<JobSpec, crate::validate::ValidationErrors> {
        self.parse_strict_with(&crate::validate::Limits::agent())
    }

    /// Strict parse as [`JobSpec`], then [`JobSpec::validate`] with `limits`.
    ///
    /// A parse failure is reported as one `job` error with code `invalid_format`. The message never quotes the
    /// input, because serde's messages can contain values (env secrets).
    pub fn parse_strict_with(
        &self,
        limits: &crate::validate::Limits,
    ) -> Result<JobSpec, crate::validate::ValidationErrors> {
        let spec: JobSpec = serde_json::from_value(serde_json::Value::Object(self.0.clone())).map_err(|_| {
            crate::validate::ValidationErrors::single(
                "job",
                crate::validate::ErrorCode::InvalidFormat,
                "not a JobSpec this agent understands (unknown field, missing field or wrong type)",
            )
        })?;
        spec.validate(limits)?;
        Ok(spec)
    }
}

impl fmt::Debug for LeaseJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseJob")
            .field("keys", &self.0.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl LeaseRejectReason {
    /// Wire value of [`LeaseRejectReason::InvalidJob`]: the agent's answer when [`LeaseJob::parse_strict`] fails.
    pub const INVALID_JOB: &'static str = "invalid_job";
    /// Wire value of [`LeaseRejectReason::AgentNotReady`].
    pub const AGENT_NOT_READY: &'static str = "agent_not_ready";
    /// Wire value of [`LeaseRejectReason::DeadlinePassed`].
    pub const DEADLINE_PASSED: &'static str = "deadline_passed";
    /// Every reason this version sends, as on the wire: exactly the list of spec §6.
    pub const ALL: [LeaseRejectReason; 8] = [
        LeaseRejectReason::NotOwner,
        LeaseRejectReason::UnsupportedSandbox,
        LeaseRejectReason::InsufficientCapacity,
        LeaseRejectReason::Draining,
        LeaseRejectReason::InvalidJob,
        LeaseRejectReason::GpuSelectionUnsupported,
        LeaseRejectReason::AgentNotReady,
        LeaseRejectReason::DeadlinePassed,
    ];
}

impl fmt::Display for LeaseRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LeaseRejectReason::NotOwner => "not_owner",
            LeaseRejectReason::UnsupportedSandbox => "unsupported_sandbox",
            LeaseRejectReason::InsufficientCapacity => "insufficient_capacity",
            LeaseRejectReason::Draining => "draining",
            LeaseRejectReason::InvalidJob => "invalid_job",
            LeaseRejectReason::GpuSelectionUnsupported => "gpu_selection_unsupported",
            LeaseRejectReason::AgentNotReady => "agent_not_ready",
            LeaseRejectReason::DeadlinePassed => "deadline_passed",
            LeaseRejectReason::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::api::{
        Capacity, CpuInfo, GpuInfo, GpuStatus, GpuStatusKind, Platform, SandboxCapability, SandboxClass, SmokeResult,
        Wsl2Health,
    };
    use serde_json::json;
    use time::macros::datetime;

    pub(crate) fn inventory() -> Inventory {
        Inventory {
            hostname: "node-1".into(),
            platform: Platform::Linux,
            cpu: CpuInfo {
                model: "Example CPU 9000".into(),
                cores: 16,
            },
            memory_mb: 65_536,
            os: "Ubuntu 24.04".into(),
            arch: "x86_64".into(),
            gpus: vec![GpuInfo {
                uuid: "GPU-00000000-0000-4000-8000-000000000001".into(),
                index: 0,
                name: "Example GPU".into(),
                driver_version: "550.54".into(),
                cuda_driver_version: Some("12.4".into()),
                compute_capability: Some("8.9".into()),
                vram_mb: Some(24_576),
                pci_bdf: Some("0000:01:00.0".into()),
                mig: false,
            }],
            gpu_status: GpuStatus {
                status: GpuStatusKind::Ok,
                reason: None,
            },
            dxg: false,
            wsl2: None,
            sandbox: vec![SandboxCapability {
                driver: "podman".into(),
                class: SandboxClass::Container,
                runtimes: vec!["crun".into()],
                ready: true,
                problems: Vec::new(),
            }],
            offered: Capacity {
                cpu: 8.0,
                memory_mb: 32_768,
                gpu: 1,
                disk_mb: Some(51_200),
            },
            disk_total_mb: Some(512_000),
            agent_version: "0.1.0".into(),
        }
    }

    fn lease() -> LeaseId {
        "lse_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
    }

    async fn round_trip<T: Serialize + DeserializeOwned>(msg: &T) -> T {
        let mut buf = Vec::new();
        write_frame(&mut buf, msg).await.unwrap();
        let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(len, buf.len() - 4);
        let mut r = buf.as_slice();
        let out = read_frame::<T, _>(&mut r, MAX_FRAME_LEN).await.unwrap().unwrap();
        assert!(read_frame::<T, _>(&mut r, MAX_FRAME_LEN).await.unwrap().is_none());
        out
    }

    #[test]
    fn reject_reasons_display_as_their_wire_value() {
        for reason in [
            LeaseRejectReason::NotOwner,
            LeaseRejectReason::UnsupportedSandbox,
            LeaseRejectReason::InsufficientCapacity,
            LeaseRejectReason::Draining,
            LeaseRejectReason::InvalidJob,
            LeaseRejectReason::GpuSelectionUnsupported,
            LeaseRejectReason::AgentNotReady,
        ] {
            assert_eq!(serde_json::to_value(reason).unwrap(), json!(reason.to_string()));
        }
        assert_eq!(LeaseRejectReason::AgentNotReady.to_string(), "agent_not_ready");
        assert_eq!(LeaseRejectReason::AGENT_NOT_READY, "agent_not_ready");
        assert_eq!(LeaseRejectReason::DEADLINE_PASSED, "deadline_passed");
    }

    /// Spec §6 (amended 2026-11-05): the full list of reasons, and an unknown one is a generic rejection that never
    /// breaks the frame.
    #[test]
    fn reject_reasons_match_the_spec_list_and_unknown_ones_decode() {
        let wire: std::collections::BTreeSet<String> = LeaseRejectReason::ALL.iter().map(ToString::to_string).collect();
        let spec: std::collections::BTreeSet<String> = [
            "not_owner",
            "invalid_job",
            "agent_not_ready",
            "insufficient_capacity",
            "draining",
            "deadline_passed",
            "unsupported_sandbox",
            "gpu_selection_unsupported",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(wire, spec);
        for reason in LeaseRejectReason::ALL {
            let json = serde_json::to_value(reason).unwrap();
            assert_eq!(serde_json::from_value::<LeaseRejectReason>(json).unwrap(), reason);
        }
        assert_eq!(
            serde_json::from_value::<LeaseRejectReason>(json!("a_reason_from_the_future")).unwrap(),
            LeaseRejectReason::Unknown
        );
        let msg: AgentMsg = serde_json::from_value(json!({
            "type": "lease_rejected",
            "lease_id": lease(),
            "epoch": 1,
            "reason": "a_reason_from_the_future",
        }))
        .unwrap();
        assert!(matches!(
            msg,
            AgentMsg::LeaseRejected {
                reason: LeaseRejectReason::Unknown,
                ..
            }
        ));
        assert_eq!(
            LeaseRejectReason::GpuSelectionUnsupported.to_string(),
            "gpu_selection_unsupported"
        );
    }

    #[test]
    fn wire_format_matches_the_spec() {
        let msg = AgentMsg::LeaseRejected {
            lease_id: lease(),
            epoch: 2,
            reason: LeaseRejectReason::NotOwner,
        };
        assert_eq!(
            serde_json::to_value(&msg).unwrap(),
            json!({"type": "lease_rejected", "lease_id": "lse_01ARZ3NDEKTSV4RRFFQ69G5FAV", "epoch": 2, "reason": "not_owner"})
        );
        assert_eq!(
            serde_json::to_value(ServerMsg::Drain {}).unwrap(),
            json!({"type": "drain"})
        );
        assert_eq!(
            serde_json::from_value::<ServerMsg>(json!({"type": "resume"})).unwrap(),
            ServerMsg::Resume {}
        );
        let hb = AgentMsg::Heartbeat {
            seq: 7,
            load: Load {
                cpu_pct: 12,
                mem_used_mb: 2048,
                gpu_util_pct: None,
            },
            running: vec![RunningLease {
                lease_id: lease(),
                epoch: 1,
            }],
        };
        assert_eq!(
            serde_json::to_value(&hb).unwrap(),
            json!({"type": "heartbeat", "seq": 7, "load": {"cpu_pct": 12, "mem_used_mb": 2048},
                   "running": [{"lease_id": "lse_01ARZ3NDEKTSV4RRFFQ69G5FAV", "epoch": 1}]})
        );
        let fin = json!({"type": "job_finished", "lease_id": "lse_01ARZ3NDEKTSV4RRFFQ69G5FAV", "epoch": 1,
            "outcome": "timed_out", "usage": {"wall_ms": 1, "cpu_used_ms": 2, "max_rss_mb": 3}, "outputs": []});
        let parsed: AgentMsg = serde_json::from_value(fin.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), fin);
        assert_eq!(parsed.kind(), "job_finished");
    }

    #[test]
    /// Spec §6 "Compatibility within `p2pc/agent/1`": receivers ignore unknown fields, in both directions.
    fn unknown_fields_are_ignored_in_both_directions() {
        // Server → agent.
        assert_eq!(
            serde_json::from_value::<ServerMsg>(json!({"type": "drain", "extra": 1})).unwrap(),
            ServerMsg::Drain {}
        );
        let welcome = json!({"type": "welcome", "server_version": "0.2.0", "node_id": "node_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "account_id": "acc_01ARZ3NDEKTSV4RRFFQ69G5FAV", "heartbeat_interval_s": 5, "lease_ttl_s": 60,
            "new_field": {"nested": true}});
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(welcome).unwrap(),
            ServerMsg::Welcome { .. }
        ));
        // Agent → server, including unknown fields nested in the inventory and the load.
        assert_eq!(
            serde_json::from_value::<AgentMsg>(
                json!({"type": "lease_accepted", "lease_id": lease(), "epoch": 1, "x": 0})
            )
            .unwrap(),
            AgentMsg::LeaseAccepted {
                lease_id: lease(),
                epoch: 1
            }
        );
        let mut inv = serde_json::to_value(inventory()).unwrap();
        inv["future"] = json!("x");
        inv["cpu"]["flags"] = json!(["avx2"]);
        inv["offered"]["fan_curve"] = json!(1);
        let hello = json!({"type": "hello", "agent_version": "0.2.0", "inventory": inv, "running": [], "uptime_s": 9});
        match serde_json::from_value::<AgentMsg>(hello).unwrap() {
            AgentMsg::Hello { inventory: got, .. } => assert_eq!(got, inventory()),
            other => panic!("{other:?}"),
        }
        let hb = json!({"type": "heartbeat", "seq": 1, "load": {"cpu_pct": 1, "mem_used_mb": 2, "disk_pct": 3},
            "running": [{"lease_id": lease(), "epoch": 1, "pid": 7}]});
        assert!(matches!(
            serde_json::from_value::<AgentMsg>(hb).unwrap(),
            AgentMsg::Heartbeat { .. }
        ));
        // Upload frames.
        assert_eq!(
            serde_json::from_value::<UploadAck>(json!({"ok": true, "extra": 1})).unwrap(),
            UploadAck { ok: true, reason: None }
        );
        // A missing tag is still an error.
        assert!(serde_json::from_value::<ServerMsg>(json!({"kind": "drain"})).is_err());
    }

    #[test]
    fn unknown_message_types_decode_to_unknown() {
        assert_eq!(
            serde_json::from_value::<ServerMsg>(json!({"type": "nope"})).unwrap(),
            ServerMsg::Unknown
        );
        assert_eq!(
            serde_json::from_value::<ServerMsg>(json!({"type": "rotate_keys", "deadline": 5})).unwrap(),
            ServerMsg::Unknown
        );
        assert_eq!(
            serde_json::from_value::<AgentMsg>(json!({"type": "gpu_report", "temps": [70]})).unwrap(),
            AgentMsg::Unknown
        );
        assert_eq!(ServerMsg::Unknown.kind(), "unknown");
        assert_eq!(AgentMsg::Unknown.validate(), Ok(()));
        assert_eq!(error_code::UNSUPPORTED_MESSAGE, "unsupported_message");
        assert_eq!(error_code::AGENT_TOO_OLD, "agent_too_old");
        assert_eq!(error_code::NOT_ENROLLED, "not_enrolled");
        assert_eq!(error_code::INVALID_TOKEN, "invalid_token");
    }

    /// Spec §6 (13f7657, e57a172): `HeartbeatAck`, `InventoryUpdate` and the new `Welcome` fields.
    #[test]
    fn liveness_and_inventory_messages_wire_format() {
        assert_eq!(
            serde_json::to_value(ServerMsg::HeartbeatAck { seq: 42 }).unwrap(),
            json!({"type": "heartbeat_ack", "seq": 42})
        );
        assert_eq!(
            serde_json::from_value::<ServerMsg>(json!({"type": "heartbeat_ack", "seq": 7})).unwrap(),
            ServerMsg::HeartbeatAck { seq: 7 }
        );
        assert!(serde_json::from_value::<ServerMsg>(json!({"type": "heartbeat_ack"})).is_err());
        assert_eq!(ServerMsg::HeartbeatAck { seq: 1 }.kind(), "heartbeat_ack");
        assert_eq!(ServerMsg::HeartbeatAck { seq: 1 }.validate(), Ok(()));

        let update = AgentMsg::InventoryUpdate { inventory: inventory() };
        let v = serde_json::to_value(&update).unwrap();
        assert_eq!(v["type"], json!("inventory_update"));
        assert_eq!(v["inventory"], serde_json::to_value(inventory()).unwrap());
        assert_eq!(serde_json::from_value::<AgentMsg>(v).unwrap(), update);
        assert_eq!(update.kind(), "inventory_update");
        assert!(serde_json::from_value::<AgentMsg>(json!({"type": "inventory_update"})).is_err());

        let welcome = ServerMsg::Welcome {
            server_version: "0.1.0".into(),
            node_id: "node_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            account_id: "acc_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            heartbeat_interval_s: DEFAULT_HEARTBEAT_INTERVAL_S,
            lease_ttl_s: DEFAULT_LEASE_TTL_S,
        };
        let v = serde_json::to_value(&welcome).unwrap();
        assert_eq!(
            v,
            json!({"type": "welcome", "server_version": "0.1.0", "node_id": "node_01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "account_id": "acc_01ARZ3NDEKTSV4RRFFQ69G5FAV", "heartbeat_interval_s": 5, "lease_ttl_s": 60})
        );
        // Both new fields are required: nothing is deployed yet, so there is no compatibility default.
        for field in ["account_id", "lease_ttl_s"] {
            let mut missing = v.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<ServerMsg>(missing).is_err(), "{field}");
        }
        // The spec defaults (the SI-13 ordering of the two timers is checked at compile time, next to them).
        assert_eq!(
            (DEFAULT_LEASE_TTL_S, DEFAULT_AGENT_LEASE_TTL_S, AGENT_LEASE_TTL_MARGIN_S),
            (60, 45, 10)
        );
    }

    /// `InventoryUpdate` is validated exactly like the inventory of `Hello` and `Join`.
    #[test]
    fn inventory_update_is_validated_like_hello_and_join() {
        let token = crate::auth::JoinToken::generate(
            "a".repeat(64),
            vec![],
            crate::auth::DEFAULT_JOIN_TOKEN_TTL,
            datetime!(2026-11-05 10:00:00 UTC),
        )
        .unwrap();
        let carriers = |inv: Inventory| {
            [
                AgentMsg::InventoryUpdate { inventory: inv.clone() },
                AgentMsg::Hello {
                    agent_version: "0.1.0".into(),
                    inventory: inv.clone(),
                    running: vec![],
                    features: vec![],
                },
                AgentMsg::Join {
                    token: token.clone(),
                    inventory: inv,
                },
            ]
        };
        let breakers: [&dyn Fn(&mut Inventory); 6] = [
            &|i| i.os = "x".repeat(MAX_TEXT_LEN + 1),
            &|i| i.gpus = vec![i.gpus[0].clone(); MAX_GPUS + 1],
            &|i| i.cpu.model = "evil\nline".into(),
            &|i| i.offered.cpu = 17.0,
            &|i| i.offered.gpu = 2,
            &|i| i.memory_mb = MAX_NODE_MEMORY_MB + 1,
        ];
        for msg in carriers(inventory()) {
            assert_eq!(msg.validate(), Ok(()), "{}", msg.kind());
        }
        for (n, breaker) in breakers.iter().enumerate() {
            let mut inv = inventory();
            breaker(&mut inv);
            let expected = validate_inventory(&inv);
            assert!(expected.is_err(), "breaker {n}");
            for msg in carriers(inv.clone()) {
                assert_eq!(msg.validate(), expected, "breaker {n} via {}", msg.kind());
            }
        }
    }

    #[test]
    fn hello_features_default_to_empty() {
        let hello = json!({"type": "hello", "agent_version": "0.1.0", "inventory": inventory(), "running": []});
        match serde_json::from_value::<AgentMsg>(hello).unwrap() {
            AgentMsg::Hello { features, .. } => assert!(features.is_empty()),
            other => panic!("{other:?}"),
        }
        let with = AgentMsg::Hello {
            agent_version: "0.1.0".into(),
            inventory: inventory(),
            running: vec![],
            features: vec!["lease_restrictions_v1".into()],
        };
        let v = serde_json::to_value(&with).unwrap();
        assert_eq!(v["features"], json!(["lease_restrictions_v1"]));
        assert_eq!(serde_json::from_value::<AgentMsg>(v).unwrap(), with);
        let too_many = AgentMsg::Hello {
            agent_version: "0.1.0".into(),
            inventory: inventory(),
            running: vec![],
            features: vec!["f".into(); MAX_FEATURES + 1],
        };
        assert!(too_many.validate().is_err());
    }

    #[test]
    /// Spec §6 (9c5b740): the frame decodes `job` leniently, so the agent can always read `lease_id` and answer
    /// `LeaseRejected{invalid_job}`; the strict parse is the agent's explicit step.
    fn a_lease_with_an_unknown_job_field_decodes_but_fails_strict_parsing() {
        let spec: JobSpec = serde_json::from_value(
            json!({"image": "python:3.12", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 256}}),
        )
        .unwrap();
        let mut job = serde_json::to_value(&spec).unwrap();
        let lease_msg = |job: serde_json::Value| {
            json!({"type": "lease", "lease_id": lease(), "epoch": 1, "job": job,
                "account_id": "acc_01ARZ3NDEKTSV4RRFFQ69G5FAV", "deadline": "2026-11-05T11:00:00Z"})
        };
        let parse_job = |v: serde_json::Value| match serde_json::from_value::<ServerMsg>(lease_msg(v)).unwrap() {
            ServerMsg::Lease { lease_id, job, .. } => {
                assert_eq!(lease_id, lease());
                job
            }
            other => panic!("{other:?}"),
        };
        // A known job parses strictly to the same spec.
        assert_eq!(parse_job(job.clone()).parse_strict().unwrap(), spec);
        // An unknown field (top-level or nested) still decodes, and the strict parse refuses it.
        job["sandbox_class"] = json!("vm");
        let errs = parse_job(job.clone()).parse_strict().unwrap_err();
        assert!(
            errs.contains("job", crate::validate::ErrorCode::InvalidFormat),
            "{errs}"
        );
        let mut nested = serde_json::to_value(&spec).unwrap();
        nested["resources"]["tpu"] = json!(1);
        assert!(parse_job(nested).parse_strict().is_err());
        // A job that parses but breaks the §7 table fails too.
        let mut bad = serde_json::to_value(&spec).unwrap();
        bad["timeout_s"] = json!(0);
        let errs = parse_job(bad).parse_strict().unwrap_err();
        assert!(
            errs.contains("timeout_s", crate::validate::ErrorCode::OutOfRange),
            "{errs}"
        );
        // Any JSON object decodes, even garbage; a non-object `job` is still a frame error.
        assert!(parse_job(json!({"nonsense": [1, 2, 3]})).parse_strict().is_err());
        assert!(serde_json::from_value::<ServerMsg>(lease_msg(json!("not an object"))).is_err());
        // The reason the agent answers with.
        assert_eq!(
            serde_json::to_value(LeaseRejectReason::InvalidJob).unwrap(),
            json!("invalid_job")
        );
        assert_eq!(LeaseRejectReason::INVALID_JOB, "invalid_job");
    }

    /// The envelope of `worst_case_lease` really is the longest one a lease can have.
    /// Review P3: the deadline is built from the calendar, so it never depends on `time/large-dates` (with which a
    /// saturating add would reach a year RFC 3339 cannot format).
    #[test]
    fn worst_case_deadline_is_the_last_rfc3339_instant() {
        use time::format_description::well_known::Rfc3339;
        let d = worst_case_deadline();
        assert_eq!(d.format(&Rfc3339).unwrap(), "9999-12-31T23:59:59.999999999Z");
        assert_eq!(d.offset(), time::UtcOffset::UTC);
    }

    #[test]
    fn log_data_encodes_what_validation_accepts() {
        let full = vec![0xa5u8; MAX_LOG_CHUNK_BYTES];
        let data = LogData::encode(&full);
        assert_eq!(validate_log_chunk_data(data.as_str()), Ok(MAX_LOG_CHUNK_BYTES));
        assert_eq!(LogData::encode(b"hi\n").as_str(), "aGkK");
        assert_eq!(LogData::encode(b"").as_str(), "");
    }

    /// Review P3: a log chunk's bytes are job output; `Debug` shows only their length.
    #[test]
    fn log_chunk_debug_shows_only_the_length() {
        let secret_b64 = data_encoding::BASE64.encode(b"job printed a secret: hunter2");
        let msg = AgentMsg::LogChunk {
            lease_id: lease(),
            epoch: 1,
            stream: LogStream::Stdout,
            seq: 9,
            data_b64: LogData(secret_b64.clone()),
        };
        let dbg = format!("{msg:?}");
        assert!(!dbg.contains(&secret_b64), "{dbg}");
        assert!(dbg.contains(&format!("len: {}", secret_b64.len())), "{dbg}");
        assert!(dbg.contains("seq: 9"), "{dbg}");
        // The wire format is unchanged: a plain string.
        assert_eq!(serde_json::to_value(&msg).unwrap()["data_b64"], json!(secret_b64));
    }

    #[test]
    fn worst_case_lease_envelope_is_maximal() {
        let spec: JobSpec = serde_json::from_value(
            json!({"image": "python:3.12", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 256}}),
        )
        .unwrap();
        let v = serde_json::to_value(worst_case_lease(&spec)).unwrap();
        assert_eq!(v["epoch"], json!(u64::MAX));
        assert_eq!(v["deadline"], json!("9999-12-31T23:59:59.999999999Z"));
        assert_eq!(v["lease_id"].as_str().unwrap().len(), "lse_".len() + 26);
        assert_eq!(v["account_id"].as_str().unwrap().len(), "acc_".len() + 26);
        // Any real envelope is no longer.
        let real = ServerMsg::Lease {
            lease_id: LeaseId::generate(),
            epoch: 3,
            job: LeaseJob::from_spec(&spec),
            account_id: AccountId::generate(),
            deadline: datetime!(2026-11-05 11:00:00.123 UTC),
        };
        assert!(
            serde_json::to_vec(&real).unwrap().len() <= serde_json::to_vec(&worst_case_lease(&spec)).unwrap().len()
        );
    }

    #[test]
    /// Ruling for T05b/T07: the agent keeps every structural and safety check but skips server policy (the allowed
    /// registries), which the server enforced when the job was created.
    fn agent_side_parsing_skips_server_policy_only() {
        let spec: JobSpec = serde_json::from_value(json!({
            "image": "registry.example.com/app:1", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 256}
        }))
        .unwrap();
        let job = LeaseJob::from_spec(&spec);
        // A registry outside the defaults parses on the agent side…
        assert_eq!(job.parse_strict().unwrap(), spec);
        // …while the server's default limits refuse it.
        let errs = job.parse_strict_with(&crate::validate::Limits::default()).unwrap_err();
        assert!(errs.contains("image", crate::validate::ErrorCode::NotAllowed), "{errs}");
        let limits = crate::validate::Limits {
            allowed_registries: Some(vec!["registry.example.com".into()]),
            ..crate::validate::Limits::default()
        };
        assert_eq!(job.parse_strict_with(&limits).unwrap(), spec);

        // Every structural and safety check still applies on the agent.
        type JobBreaker<'a> = (
            &'static str,
            crate::validate::ErrorCode,
            &'a dyn Fn(&mut serde_json::Value),
        );
        let breakers: [JobBreaker<'_>; 6] = [
            ("image", crate::validate::ErrorCode::InvalidFormat, &|j| {
                j["image"] = json!("Not A Ref")
            }),
            ("env.A", crate::validate::ErrorCode::InvalidFormat, &|j| {
                j["env"] = json!({"A": "x\nP2PC_Y=1"})
            }),
            ("env.P2PC_X", crate::validate::ErrorCode::Reserved, &|j| {
                j["env"] = json!({"P2PC_X": "1"})
            }),
            ("files[0].path", crate::validate::ErrorCode::InvalidFormat, &|j| {
                j["files"] = json!([{"path": "/inputs/../etc/passwd", "content_b64": ""}])
            }),
            (
                "files[1].path",
                crate::validate::ErrorCode::PathConflict,
                &|j| {
                    j["files"] =
                        json!([{"path": "/inputs/a", "content_b64": ""}, {"path": "/inputs/a/b", "content_b64": ""}])
                },
            ),
            ("resources.memory_mb", crate::validate::ErrorCode::OutOfRange, &|j| {
                j["resources"]["memory_mb"] = json!(1)
            }),
        ];
        for (field, code, breaker) in breakers {
            let mut v = serde_json::to_value(&spec).unwrap();
            breaker(&mut v);
            let job: LeaseJob = serde_json::from_value(v).unwrap();
            let errs = job.parse_strict().unwrap_err();
            assert!(errs.contains(field, code), "{field}: {errs}");
        }
        assert_eq!(crate::validate::Limits::agent().allowed_registries, None);
        assert_eq!(
            crate::validate::Limits {
                allowed_registries: None,
                ..crate::validate::Limits::default()
            },
            crate::validate::Limits::agent(),
            "only the server policy differs"
        );
    }

    #[test]
    fn lease_job_errors_and_debug_never_show_values() {
        let job: serde_json::Value = json!({
            "image": "python:3.12", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 256},
            "env": {"TOKEN": "lease-secret-value"}, "files": [{"path": "/inputs/k", "content_b64": "c2VjcmV0"}],
            "retry": {"max_attempts": "lease-secret-in-wrong-type"}
        });
        let lease_job: LeaseJob = serde_json::from_value(job).unwrap();
        let dbg = format!("{lease_job:?}");
        assert!(!dbg.contains("lease-secret"), "{dbg}");
        assert!(!dbg.contains("c2VjcmV0"), "{dbg}");
        assert!(dbg.contains("env"), "{dbg}");
        let errs = lease_job.parse_strict().unwrap_err();
        let text = format!("{errs} {errs:?}");
        assert!(!text.contains("lease-secret"), "{text}");
    }

    #[tokio::test]
    async fn frames_round_trip() {
        let msgs = vec![
            AgentMsg::Hello {
                agent_version: "0.1.0".into(),
                inventory: inventory(),
                running: vec![],
                features: vec!["x".into()],
            },
            AgentMsg::Unknown,
            AgentMsg::JobStarted {
                lease_id: lease(),
                epoch: 1,
                started_at: datetime!(2026-11-05 10:00:00.5 UTC),
            },
            AgentMsg::LogChunk {
                lease_id: lease(),
                epoch: 1,
                stream: LogStream::Stderr,
                seq: 3,
                data_b64: "aGk=".into(),
            },
        ];
        for m in msgs {
            assert_eq!(round_trip(&m).await, m);
        }
        let h = UploadHeader {
            lease_id: lease(),
            epoch: 1,
            path: "a/b.csv".into(),
            size: 5,
            sha256: Sha256Digest([9; 32]),
        };
        assert_eq!(round_trip(&h).await, h);
    }

    #[tokio::test]
    async fn clean_eof_is_none_and_partial_prefix_is_truncated() {
        let mut empty: &[u8] = &[];
        assert!(
            read_frame::<ServerMsg, _>(&mut empty, MAX_FRAME_LEN)
                .await
                .unwrap()
                .is_none()
        );
        let mut partial: &[u8] = &[0, 0];
        assert!(matches!(
            read_frame::<ServerMsg, _>(&mut partial, MAX_FRAME_LEN).await,
            Err(FrameError::Truncated)
        ));
        let mut short_body: &[u8] = &[0, 0, 0, 10, b'{'];
        assert!(matches!(
            read_frame::<ServerMsg, _>(&mut short_body, MAX_FRAME_LEN).await,
            Err(FrameError::Truncated)
        ));
    }

    #[tokio::test]
    async fn oversize_frames_are_rejected_before_reading_the_body() {
        let mut r: &[u8] = &[0x00, 0x10, 0x00, 0x01]; // 1 MiB + 1, no body at all
        match read_frame::<ServerMsg, _>(&mut r, MAX_FRAME_LEN).await {
            Err(FrameError::TooLarge { len, max }) => {
                assert_eq!(len, MAX_FRAME_LEN + 1);
                assert_eq!(max, MAX_FRAME_LEN);
            }
            other => panic!("{other:?}"),
        }
        let mut r: &[u8] = &[0xff, 0xff, 0xff, 0xff];
        assert!(matches!(
            read_frame::<ServerMsg, _>(&mut r, MAX_FRAME_LEN).await,
            Err(FrameError::TooLarge { .. })
        ));
        // A smaller caller-chosen maximum applies.
        let mut buf = Vec::new();
        write_frame(&mut buf, &ServerMsg::Drain {}).await.unwrap();
        let mut r = buf.as_slice();
        assert!(matches!(
            read_frame::<ServerMsg, _>(&mut r, 4).await,
            Err(FrameError::TooLarge { .. })
        ));
    }

    /// Review P3: a smaller limit (T05 uses 64 KiB before `Join`) that can never exceed the spec maximum.
    #[tokio::test]
    async fn read_frame_with_limit_applies_the_smaller_limit() {
        let hello = AgentMsg::Hello {
            agent_version: "0.1.0".into(),
            inventory: inventory(),
            running: vec![],
            features: vec![],
        };
        let mut small = Vec::new();
        write_frame(&mut small, &hello).await.unwrap();
        let mut r = small.as_slice();
        assert_eq!(
            read_frame_with_limit::<AgentMsg, _>(&mut r, PRE_JOIN_MAX_FRAME_LEN)
                .await
                .unwrap(),
            Some(hello)
        );
        // Just over 64 KiB: refused before the body is read.
        let big = ServerMsg::Error {
            code: "x".into(),
            message: "m".repeat(64 * 1024),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &big).await.unwrap();
        let mut r = buf.as_slice();
        match read_frame_with_limit::<ServerMsg, _>(&mut r, PRE_JOIN_MAX_FRAME_LEN).await {
            Err(FrameError::TooLarge { max, .. }) => assert_eq!(max, PRE_JOIN_MAX_FRAME_LEN),
            other => panic!("{other:?}"),
        }
        // A limit above the spec maximum is clamped to it.
        let mut r: &[u8] = &(MAX_FRAME_LEN + 1).to_be_bytes();
        match read_frame_with_limit::<ServerMsg, _>(&mut r, u32::MAX).await {
            Err(FrameError::TooLarge { len, max }) => {
                assert_eq!(len, MAX_FRAME_LEN + 1);
                assert_eq!(max, MAX_FRAME_LEN);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(PRE_JOIN_MAX_FRAME_LEN, 64 * 1024);
    }

    #[tokio::test]
    async fn read_frame_bytes_then_decode_frame_is_read_frame() {
        let msg = AgentMsg::Heartbeat {
            seq: 3,
            load: Load {
                cpu_pct: 1,
                mem_used_mb: 2,
                gpu_util_pct: None,
            },
            running: vec![],
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).await.unwrap();
        let mut r = buf.as_slice();
        let body = read_frame_bytes(&mut r, MAX_FRAME_LEN).await.unwrap().unwrap();
        assert_eq!(decode_frame::<AgentMsg>(&body).unwrap(), msg);
        assert!(read_frame_bytes(&mut r, MAX_FRAME_LEN).await.unwrap().is_none());
        assert!(matches!(
            decode_frame::<AgentMsg>(b"{"),
            Err(FrameError::InvalidJson { .. })
        ));
        assert!(matches!(
            decode_frame::<AgentMsg>(&[0xff]),
            Err(FrameError::InvalidUtf8)
        ));
        let mut r: &[u8] = &(MAX_FRAME_LEN + 1).to_be_bytes();
        assert!(matches!(
            read_frame_bytes(&mut r, u32::MAX).await,
            Err(FrameError::TooLarge { max: MAX_FRAME_LEN, .. })
        ));
    }

    /// T02 review P3 (fixed in T05): `read_frame` itself clamps `max_len` to the spec's 1 MiB, so no caller can
    /// raise the limit by passing a larger value.
    #[tokio::test]
    async fn read_frame_clamps_max_len_to_the_spec_maximum() {
        for max_len in [MAX_FRAME_LEN + 1, u32::MAX] {
            let mut r: &[u8] = &(MAX_FRAME_LEN + 1).to_be_bytes();
            match read_frame::<ServerMsg, _>(&mut r, max_len).await {
                Err(FrameError::TooLarge { len, max }) => {
                    assert_eq!(len, MAX_FRAME_LEN + 1);
                    assert_eq!(max, MAX_FRAME_LEN, "{max_len}");
                }
                other => panic!("{max_len}: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn a_frame_exactly_at_the_limit_is_accepted() {
        // {"type":"error","code":"x","message":"<pad>"}
        let overhead = r#"{"type":"error","code":"x","message":""}"#.len();
        let msg = ServerMsg::Error {
            code: "x".into(),
            message: "m".repeat(MAX_FRAME_LEN as usize - overhead),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).await.unwrap();
        assert_eq!(buf.len(), MAX_FRAME_LEN as usize + 4);
        let mut r = buf.as_slice();
        assert_eq!(
            read_frame::<ServerMsg, _>(&mut r, MAX_FRAME_LEN).await.unwrap(),
            Some(msg)
        );
        let too_big = ServerMsg::Error {
            code: "xy".into(),
            message: "m".repeat(MAX_FRAME_LEN as usize - overhead),
        };
        let mut sink = Vec::new();
        assert!(matches!(
            write_frame(&mut sink, &too_big).await,
            Err(FrameError::TooLarge { .. })
        ));
        assert!(sink.is_empty());
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    #[tokio::test]
    async fn bad_payloads_give_typed_errors() {
        let read = |bytes: Vec<u8>| async move {
            let mut r = bytes.as_slice();
            read_frame::<ServerMsg, _>(&mut r, MAX_FRAME_LEN).await
        };
        assert!(matches!(read(frame(&[0xff, 0xfe])).await, Err(FrameError::InvalidUtf8)));
        assert!(matches!(
            read(frame(b"{not json")).await,
            Err(FrameError::InvalidJson { category: "syntax", .. })
        ));
        assert!(matches!(
            read(frame(b"")).await,
            Err(FrameError::InvalidJson { category: "eof", .. })
        ));
        assert!(matches!(
            read(frame(br#"{"type":"drain"} x"#)).await,
            Err(FrameError::InvalidJson { .. })
        ));
        assert!(matches!(
            read(frame(br#"{"type":"cancel"}"#)).await,
            Err(FrameError::InvalidJson { category: "data", .. })
        ));
        // An unknown type is a normal message (§6): the receiver answers `unsupported_message` and keeps going.
        assert_eq!(
            read(frame(br#"{"type":"self_destruct"}"#)).await.unwrap(),
            Some(ServerMsg::Unknown)
        );
        assert_eq!(
            read(frame(br#"{"type":"EVIL\u001b[2J","x":[1,2]}"#)).await.unwrap(),
            Some(ServerMsg::Unknown)
        );
        let mut two = frame(br#"{"type":"future_thing"}"#);
        two.extend(frame(br#"{"type":"resume"}"#));
        let mut r = two.as_slice();
        assert_eq!(
            read_frame::<ServerMsg, _>(&mut r, MAX_FRAME_LEN).await.unwrap(),
            Some(ServerMsg::Unknown)
        );
        assert_eq!(
            read_frame::<ServerMsg, _>(&mut r, MAX_FRAME_LEN).await.unwrap(),
            Some(ServerMsg::Resume {})
        );
        // The tag must still be a string.
        assert!(matches!(
            read(frame(br#"{"type":7}"#)).await,
            Err(FrameError::InvalidJson { .. })
        ));
        // A bad value of a closed nested enum is a data error, not an unknown message type. (`LeaseRejectReason` is
        // open since §6 was amended: an unknown reason is a generic rejection, see
        // `reject_reasons_match_the_spec_list_and_unknown_ones_decode`.)
        let bad_outcome = br#"{"type":"job_finished","lease_id":"lse_01ARZ3NDEKTSV4RRFFQ69G5FAV","epoch":1,"outcome":"exploded","usage":{"wall_ms":1,"cpu_used_ms":1,"max_rss_mb":1},"outputs":[]}"#;
        let mut r = &frame(bad_outcome)[..];
        assert!(matches!(
            read_frame::<AgentMsg, _>(&mut r, MAX_FRAME_LEN).await,
            Err(FrameError::InvalidJson { .. })
        ));
    }

    #[tokio::test]
    async fn frame_errors_do_not_echo_content() {
        let secret = "p2pc_sk_abcdefgh2345_secretsecretsecret"; // gitleaks:allow
        let payload =
            format!(r#"{{"type":"welcome","server_version":1,"node_id":"{secret}","heartbeat_interval_s":5}}"#);
        let bytes = frame(payload.as_bytes());
        let mut r = bytes.as_slice();
        let err = read_frame::<ServerMsg, _>(&mut r, MAX_FRAME_LEN).await.unwrap_err();
        assert!(!format!("{err} {err:?}").contains("secret"), "{err}");
    }

    #[test]
    fn upload_acks_carry_a_stable_reason_only_when_refused() {
        assert_eq!(
            serde_json::to_value(UploadAck::accepted()).unwrap(),
            json!({"ok": true})
        );
        assert_eq!(
            serde_json::to_value(UploadAck::refused(upload_reason::STALE_EPOCH)).unwrap(),
            json!({"ok": false, "reason": "stale_epoch"})
        );
    }

    #[tokio::test]
    async fn read_frame_leaves_trailing_upload_bytes_unread() {
        let h = UploadHeader {
            lease_id: lease(),
            epoch: 1,
            path: "out.bin".into(),
            size: 3,
            sha256: Sha256Digest([0; 32]),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &h).await.unwrap();
        buf.extend_from_slice(b"raw");
        let mut r = buf.as_slice();
        assert_eq!(
            read_frame::<UploadHeader, _>(&mut r, MAX_FRAME_LEN).await.unwrap(),
            Some(h)
        );
        assert_eq!(r, b"raw");
    }

    #[test]
    fn log_chunks_are_capped_at_64_kib_decoded() {
        let ok = data_encoding::BASE64.encode(&vec![1u8; MAX_LOG_CHUNK_BYTES]);
        let over = data_encoding::BASE64.encode(&vec![1u8; MAX_LOG_CHUNK_BYTES + 1]);
        assert_eq!(validate_log_chunk_data(&ok), Ok(MAX_LOG_CHUNK_BYTES));
        assert_eq!(validate_log_chunk_data(&over), Err(Base64Error::TooLarge));
        assert_eq!(validate_log_chunk_data("aGk"), Err(Base64Error::Invalid));
        assert_eq!(validate_log_chunk_data("a!k="), Err(Base64Error::Invalid));
        let chunk = |data_b64: String| AgentMsg::LogChunk {
            lease_id: lease(),
            epoch: 1,
            stream: LogStream::Stdout,
            seq: 0,
            data_b64: LogData(data_b64),
        };
        assert_eq!(chunk(ok).validate(), Ok(()));
        assert_eq!(
            chunk(over).validate(),
            Err(violation("data_b64", "over 64 KiB decoded"))
        );
    }

    #[test]
    fn message_validation_limits() {
        let mut inv = inventory();
        assert_eq!(validate_inventory(&inv), Ok(()));
        inv.os = "x".repeat(MAX_TEXT_LEN + 1);
        assert!(validate_inventory(&inv).is_err());
        let mut inv = inventory();
        inv.gpus = vec![inv.gpus[0].clone(); MAX_GPUS + 1];
        assert!(validate_inventory(&inv).is_err());
        let mut inv = inventory();
        inv.offered.cpu = f64::NAN;
        assert!(validate_inventory(&inv).is_err());
        let mut inv = inventory();
        inv.cpu.model = "evil\nline".into();
        assert!(validate_inventory(&inv).is_err());
    }

    fn gpu(uuid: &str, vram_mb: Option<u64>, mig: bool) -> GpuInfo {
        GpuInfo {
            uuid: uuid.into(),
            index: 0,
            name: "Example GPU".into(),
            driver_version: "550.54".into(),
            cuda_driver_version: Some("12.4".into()),
            compute_capability: Some("8.9".into()),
            vram_mb,
            pci_bdf: Some("0000:01:00.0".into()),
            mig,
        }
    }

    /// §6 "GPU inventory": a MIG card or a card with unknown VRAM is reported but not offerable.
    #[test]
    fn offered_gpus_are_bounded_by_offerable_gpus() {
        let with = |gpus: Vec<GpuInfo>, offered: u32| {
            let mut inv = inventory();
            inv.gpus = gpus;
            inv.offered.gpu = offered;
            validate_inventory(&inv).map_err(|v| v.field)
        };
        let ok = gpu("GPU-1", Some(24_576), false);
        let mig = gpu("GPU-2", Some(81_920), true);
        let unknown = gpu("GPU-3", None, false);
        assert!(ok.is_offerable() && !mig.is_offerable() && !unknown.is_offerable());
        assert_eq!(with(vec![ok.clone()], 1), Ok(()));
        // Reported, but not counted.
        assert_eq!(with(vec![ok.clone(), mig.clone()], 1), Ok(()));
        assert_eq!(with(vec![ok.clone(), mig.clone()], 2), Err("inventory.offered.gpu"));
        assert_eq!(with(vec![mig.clone()], 1), Err("inventory.offered.gpu"));
        assert_eq!(with(vec![unknown.clone()], 1), Err("inventory.offered.gpu"));
        assert_eq!(with(vec![mig, unknown], 0), Ok(()));
        let mut ok2 = ok.clone();
        ok2.uuid = "GPU-4".into();
        assert_eq!(with(vec![ok, ok2], 2), Ok(()));
    }

    #[test]
    fn gpu_uuids_are_unique_and_well_formed() {
        let with = |gpus: Vec<GpuInfo>| {
            let mut inv = inventory();
            inv.gpus = gpus;
            inv.offered.gpu = 0;
            validate_inventory(&inv).map_err(|v| v.field)
        };
        let a = gpu("GPU-6a3d0a2e-1b2c-4d5e-8f90-123456789abc", Some(1), false);
        assert_eq!(with(vec![a.clone()]), Ok(()));
        // The UUID is the key: the same card twice (even at another index) is refused.
        let mut dup = a.clone();
        dup.index = 1;
        assert_eq!(with(vec![a.clone(), dup]), Err("inventory.gpus.uuid"));
        for bad in ["", "GPU 1", "GPU-1\n", &"G".repeat(MAX_GPU_UUID_LEN + 1)] {
            assert_eq!(
                with(vec![gpu(bad, Some(1), false)]),
                Err("inventory.gpus.uuid"),
                "{bad:?}"
            );
        }
        assert_eq!(with(vec![gpu("MIG-0/1/2", Some(1), true)]), Ok(()));
        let mut big = a;
        big.vram_mb = Some(MAX_GPU_VRAM_MB + 1);
        assert_eq!(with(vec![big]), Err("inventory.gpus.vram_mb"));
    }

    #[test]
    fn hostname_is_bounded() {
        let with = |h: &str| {
            let mut inv = inventory();
            inv.hostname = h.into();
            validate_inventory(&inv).map_err(|v| v.field)
        };
        for ok in ["node-1", "Desktop_ABC.example.invalid", "a"] {
            assert_eq!(with(ok), Ok(()), "{ok:?}");
        }
        let long = "h".repeat(MAX_HOSTNAME_LEN + 1);
        for bad in ["", "evil\nhost", "white space", "émoji", "a/b", long.as_str()] {
            assert_eq!(with(bad), Err("inventory.hostname"), "{bad:?}");
        }
    }

    #[test]
    fn unknown_wsl2_versions_are_null_on_the_wire() {
        let mut inv = inventory();
        inv.platform = Platform::Wsl2;
        inv.wsl2 = Some(Wsl2Health {
            distro_version: None,
            podman_version: None,
            cdi_present: false,
            cdi_stale: false,
            smoke: None,
        });
        let v = serde_json::to_value(&inv).unwrap();
        // Explicit nulls, not empty strings and not missing keys.
        assert_eq!(v["wsl2"]["distro_version"], json!(null));
        assert_eq!(v["wsl2"]["podman_version"], json!(null));
        assert!(v["wsl2"].as_object().unwrap().contains_key("distro_version"));
        assert_eq!(serde_json::from_value::<Inventory>(v).unwrap(), inv);
        // An older or minimal sender may leave the keys out: unknown as well.
        let w: Wsl2Health = serde_json::from_value(json!({"cdi_present": true, "cdi_stale": false})).unwrap();
        assert_eq!((w.distro_version, w.podman_version), (None, None));
        validate_inventory(&inv).unwrap();
    }

    /// The §6 field names, and defaults for the fields a sensible default exists for.
    #[test]
    fn gpu_inventory_wire_format() {
        let mut inv = inventory();
        inv.platform = Platform::Wsl2;
        inv.dxg = true;
        inv.gpu_status = GpuStatus {
            status: GpuStatusKind::CdiStale,
            reason: Some("spec older than driver".into()),
        };
        inv.wsl2 = Some(Wsl2Health {
            distro_version: Some("p2pc-wsl 2026.11".into()),
            podman_version: Some("4.9.3".into()),
            cdi_present: true,
            cdi_stale: true,
            smoke: Some(SmokeResult {
                ok: false,
                detail: Some("exit 125".into()),
            }),
        });
        let v = serde_json::to_value(&inv).unwrap();
        assert_eq!(v["platform"], json!("wsl2"));
        assert_eq!(v["dxg"], json!(true));
        assert_eq!(
            v["gpu_status"],
            json!({"status": "cdi_stale", "reason": "spec older than driver"})
        );
        assert_eq!(v["wsl2"]["smoke"], json!({"ok": false, "detail": "exit 125"}));
        let g = &v["gpus"][0];
        for field in [
            "uuid",
            "index",
            "name",
            "driver_version",
            "cuda_driver_version",
            "compute_capability",
            "vram_mb",
            "pci_bdf",
            "mig",
        ] {
            assert!(g.get(field).is_some(), "gpus[0].{field}");
        }
        assert_eq!(serde_json::from_value::<Inventory>(v).unwrap(), inv);
        for (kind, name) in [
            (GpuStatusKind::Ok, "ok"),
            (GpuStatusKind::NoDriver, "no_driver"),
            (GpuStatusKind::NvmlError, "nvml_error"),
            (GpuStatusKind::NotFound, "not_found"),
            (GpuStatusKind::CdiMissing, "cdi_missing"),
            (GpuStatusKind::CdiStale, "cdi_stale"),
        ] {
            assert_eq!(serde_json::to_value(kind).unwrap(), json!(name));
        }
        // Defaults: optional GPU fields, `mig`, `dxg` and the WSL2 block may be absent.
        let mut minimal = serde_json::to_value(inventory()).unwrap();
        let obj = minimal.as_object_mut().unwrap();
        obj.remove("dxg");
        obj.remove("wsl2");
        let g = minimal["gpus"][0].as_object_mut().unwrap();
        for f in ["cuda_driver_version", "compute_capability", "vram_mb", "pci_bdf", "mig"] {
            g.remove(f);
        }
        let parsed: Inventory = serde_json::from_value(minimal).unwrap();
        assert!(!parsed.dxg && parsed.wsl2.is_none());
        assert_eq!(parsed.gpus[0].vram_mb, None);
        assert!(!parsed.gpus[0].mig);
        assert!(!parsed.gpus[0].is_offerable(), "unknown VRAM is never guessed");
        // Required: uuid, hostname, platform and gpu_status.
        for path in [&["hostname"][..], &["platform"], &["gpu_status"]] {
            let mut v = serde_json::to_value(inventory()).unwrap();
            v.as_object_mut().unwrap().remove(path[0]);
            assert!(serde_json::from_value::<Inventory>(v).is_err(), "{path:?}");
        }
        let mut v = serde_json::to_value(inventory()).unwrap();
        v["gpus"][0].as_object_mut().unwrap().remove("uuid");
        assert!(serde_json::from_value::<Inventory>(v).is_err());
        // Enums stay closed (§6).
        let mut v = serde_json::to_value(inventory()).unwrap();
        v["platform"] = json!("macos");
        assert!(serde_json::from_value::<Inventory>(v).is_err());
    }

    /// T07: the §9.0 readiness of each sandbox driver travels as `ready` plus `problems`. Both are additive, so an
    /// inventory without them still decodes, and then the driver counts as **not** ready (fail closed).
    #[test]
    fn sandbox_readiness_wire_format() {
        let mut inv = inventory();
        inv.sandbox[0].ready = false;
        inv.sandbox[0].problems = vec!["podman_not_found: podman is not installed".into()];
        let v = serde_json::to_value(&inv).unwrap();
        assert_eq!(
            v["sandbox"][0],
            json!({
                "driver": "podman",
                "class": "container",
                "runtimes": ["crun"],
                "ready": false,
                "problems": ["podman_not_found: podman is not installed"],
            })
        );
        assert_eq!(serde_json::from_value::<Inventory>(v).unwrap(), inv);
        // An older agent omits both fields.
        let mut v = serde_json::to_value(inventory()).unwrap();
        let sb = v["sandbox"][0].as_object_mut().unwrap();
        sb.remove("ready");
        sb.remove("problems");
        let parsed: Inventory = serde_json::from_value(v).unwrap();
        assert!(!parsed.sandbox[0].ready);
        assert!(parsed.sandbox[0].problems.is_empty());
    }

    #[test]
    fn sandbox_problems_are_bounded() {
        let mut inv = inventory();
        inv.sandbox[0].problems = vec!["x".into(); MAX_SANDBOX_PROBLEMS];
        assert_eq!(validate_inventory(&inv), Ok(()));
        inv.sandbox[0].problems.push("x".into());
        assert_eq!(
            validate_inventory(&inv).map_err(|v| v.field),
            Err("inventory.sandbox.problems")
        );
        for bad in ["x".repeat(MAX_TEXT_LEN + 1), "a\u{1b}[2Jb".into()] {
            let mut inv = inventory();
            inv.sandbox[0].problems = vec![bad];
            assert_eq!(
                validate_inventory(&inv).map_err(|v| v.field),
                Err("inventory.sandbox.problems")
            );
        }
    }

    type Breaker<'a> = (&'static str, &'a dyn Fn(&mut Inventory));

    #[test]
    fn inventory_text_fields_are_bounded() {
        let long = "x".repeat(MAX_TEXT_LEN + 1);
        let breakers: [Breaker<'_>; 6] = [
            ("inventory.gpus.driver_version", &|i| {
                i.gpus[0].driver_version = long.clone()
            }),
            ("inventory.gpus.pci_bdf", &|i| i.gpus[0].pci_bdf = Some("a\nb".into())),
            ("inventory.gpu_status.reason", &|i| {
                i.gpu_status.reason = Some(long.clone())
            }),
            ("inventory.wsl2.podman_version", &|i| {
                i.wsl2 = Some(Wsl2Health {
                    distro_version: Some("1".into()),
                    podman_version: Some(long.clone()),
                    cdi_present: true,
                    cdi_stale: false,
                    smoke: None,
                })
            }),
            ("inventory.wsl2.smoke.detail", &|i| {
                i.wsl2 = Some(Wsl2Health {
                    distro_version: Some("1".into()),
                    podman_version: Some("4.9.3".into()),
                    cdi_present: true,
                    cdi_stale: false,
                    smoke: Some(SmokeResult {
                        ok: false,
                        detail: Some("\u{1b}[2J".into()),
                    }),
                })
            }),
            ("inventory.gpus.compute_capability", &|i| {
                i.gpus[0].compute_capability = Some(long.clone())
            }),
        ];
        for (field, f) in breakers {
            let mut inv = inventory();
            f(&mut inv);
            assert_eq!(validate_inventory(&inv).map_err(|v| v.field), Err(field));
        }
    }

    /// §6 (amended 2026-11-07): `offered.disk_mb` is optional on the wire and never exceeds the reported filesystem.
    #[test]
    fn offered_disk_is_optional_and_cannot_exceed_the_filesystem() {
        let with = |f: &dyn Fn(&mut Inventory)| {
            let mut inv = inventory();
            f(&mut inv);
            validate_inventory(&inv).map_err(|v| v.field)
        };
        // The fixture: 51 200 MiB offered on a 512 000 MiB filesystem.
        assert_eq!(with(&|_| {}), Ok(()));
        assert_eq!(
            with(&|i| i.offered.disk_mb = Some(512_000)),
            Ok(()),
            "all of it is fine"
        );
        assert_eq!(
            with(&|i| i.offered.disk_mb = Some(512_001)),
            Err("inventory.offered.disk_mb")
        );
        // An agent without the fields (older than the amendment) still validates.
        assert_eq!(
            with(&|i| {
                i.offered.disk_mb = None;
                i.disk_total_mb = None;
            }),
            Ok(())
        );
        // Offered disk with an unknown filesystem is bounded by the absolute ceiling only.
        assert_eq!(
            with(&|i| i.disk_total_mb = None),
            Ok(()),
            "unknown filesystem: nothing to compare"
        );
        assert_eq!(
            with(&|i| {
                i.disk_total_mb = None;
                i.offered.disk_mb = Some(MAX_NODE_DISK_MB + 1);
            }),
            Err("inventory.offered.disk_mb")
        );
        assert_eq!(
            with(&|i| i.disk_total_mb = Some(MAX_NODE_DISK_MB + 1)),
            Err("inventory.disk_total_mb")
        );
    }

    /// The wire form: `disk_mb` and `disk_total_mb` are left out when unknown and read as `None` when missing.
    #[test]
    fn the_disk_fields_round_trip_with_and_without_a_value() {
        let with = inventory();
        let json = serde_json::to_value(&with).unwrap();
        assert_eq!(json["offered"]["disk_mb"], 51_200);
        assert_eq!(json["disk_total_mb"], 512_000);
        assert_eq!(serde_json::from_value::<Inventory>(json).unwrap(), with);

        let mut without = inventory();
        without.offered.disk_mb = None;
        without.disk_total_mb = None;
        let json = serde_json::to_value(&without).unwrap();
        assert!(json["offered"].get("disk_mb").is_none(), "{json}");
        assert!(json.get("disk_total_mb").is_none(), "{json}");
        assert_eq!(serde_json::from_value::<Inventory>(json).unwrap(), without);

        // An older agent's inventory has neither field.
        let old = serde_json::to_value(&without).unwrap();
        let parsed: Inventory = serde_json::from_value(old).unwrap();
        assert_eq!((parsed.offered.disk_mb, parsed.disk_total_mb), (None, None));
    }

    /// Review P3: the scheduler trusts `offered`, so it can never exceed what the node reports having.
    #[test]
    fn offered_capacity_cannot_exceed_the_hardware() {
        // The fixture: 16 logical cores, 65 536 MiB, 1 GPU.
        let with = |f: &dyn Fn(&mut Inventory)| {
            let mut inv = inventory();
            f(&mut inv);
            validate_inventory(&inv)
        };
        let field = |r: Result<(), ProtocolViolation>| r.map_err(|v| v.field);
        // At the limit is fine: an owner may share everything.
        assert_eq!(
            with(&|i| i.offered = Capacity {
                cpu: 16.0,
                memory_mb: 65_536,
                gpu: 1,
                disk_mb: Some(512_000),
            }),
            Ok(())
        );
        assert_eq!(with(&|i| i.offered = Capacity::default()), Ok(()));
        assert_eq!(with(&|i| i.offered.cpu = 2.5), Ok(()));
        // Over the hardware.
        assert_eq!(field(with(&|i| i.offered.cpu = 16.01)), Err("inventory.offered.cpu"));
        assert_eq!(
            field(with(&|i| i.offered.memory_mb = 65_537)),
            Err("inventory.offered.memory_mb")
        );
        assert_eq!(field(with(&|i| i.offered.gpu = 2)), Err("inventory.offered.gpu"));
        assert_eq!(
            field(with(&|i| {
                i.gpus.clear();
                i.offered.gpu = 1;
            })),
            Err("inventory.offered.gpu")
        );
        // Not a number, or negative.
        for cpu in [f64::NAN, f64::INFINITY, -1.0, -0.0001] {
            assert_eq!(
                field(with(&|i| i.offered.cpu = cpu)),
                Err("inventory.offered.cpu"),
                "{cpu}"
            );
        }
        // Absurd hardware.
        assert_eq!(field(with(&|i| i.cpu.cores = 0)), Err("inventory.cpu.cores"));
        assert_eq!(
            field(with(&|i| i.cpu.cores = MAX_CORES + 1)),
            Err("inventory.cpu.cores")
        );
        assert_eq!(field(with(&|i| i.memory_mb = 0)), Err("inventory.memory_mb"));
        assert_eq!(
            field(with(&|i| i.memory_mb = MAX_NODE_MEMORY_MB + 1)),
            Err("inventory.memory_mb")
        );
        assert_eq!(
            field(with(&|i| i.gpus[0].vram_mb = Some(MAX_GPU_VRAM_MB + 1))),
            Err("inventory.gpus.vram_mb")
        );
        // Lies paired with a matching `offered` are still caught by the hardware bounds.
        assert_eq!(
            field(with(&|i| {
                i.cpu.cores = u32::MAX;
                i.offered.cpu = f64::from(u32::MAX);
            })),
            Err("inventory.cpu.cores")
        );
        // The largest sane node passes.
        assert_eq!(
            with(&|i| {
                i.cpu.cores = MAX_CORES;
                i.memory_mb = MAX_NODE_MEMORY_MB;
                i.offered = Capacity {
                    cpu: f64::from(MAX_CORES),
                    memory_mb: MAX_NODE_MEMORY_MB,
                    gpu: 1,
                    disk_mb: Some(MAX_NODE_DISK_MB),
                };
                i.disk_total_mb = Some(MAX_NODE_DISK_MB);
            }),
            Ok(())
        );

        let hb = |cpu_pct, gpu| AgentMsg::Heartbeat {
            seq: 1,
            load: Load {
                cpu_pct,
                mem_used_mb: 0,
                gpu_util_pct: gpu,
            },
            running: vec![],
        };
        assert!(hb(100, Some(100)).validate().is_ok());
        assert!(hb(101, None).validate().is_err());
        assert!(hb(0, Some(101)).validate().is_err());
        let many = AgentMsg::Hello {
            agent_version: "0.1.0".into(),
            inventory: inventory(),
            features: vec![],
            running: vec![
                RunningLease {
                    lease_id: lease(),
                    epoch: 1
                };
                MAX_RUNNING_LEASES + 1
            ],
        };
        assert!(many.validate().is_err());

        let finished = |path: &str| AgentMsg::JobFinished {
            lease_id: lease(),
            epoch: 1,
            outcome: Outcome::Exited,
            exit_code: Some(0),
            error: None,
            usage: Usage {
                wall_ms: 0,
                cpu_used_ms: 0,
                max_rss_mb: 0,
            },
            outputs: vec![OutputFile {
                path: path.into(),
                size: 1,
                sha256: Sha256Digest([0; 32]),
            }],
        };
        assert!(finished("ok/file.txt").validate().is_ok());
        for bad in ["../escape", "/etc/passwd", "a/../../b", ""] {
            assert!(finished(bad).validate().is_err(), "{bad:?}");
        }
        // Review P3: outputs follow the input-path set rules too (no duplicates, no directory of another).
        let finished_many = |paths: &[&str]| AgentMsg::JobFinished {
            lease_id: lease(),
            epoch: 1,
            outcome: Outcome::Exited,
            exit_code: Some(0),
            error: None,
            usage: Usage {
                wall_ms: 0,
                cpu_used_ms: 0,
                max_rss_mb: 0,
            },
            outputs: paths
                .iter()
                .map(|p| OutputFile {
                    path: (*p).into(),
                    size: 1,
                    sha256: Sha256Digest([0; 32]),
                })
                .collect(),
        };
        assert_eq!(finished_many(&["a.txt", "b/c.txt", "b/d.txt", "ab"]).validate(), Ok(()));
        for bad in [&["a.txt", "a.txt"][..], &["out", "out/x"], &["out/x/y", "out/x"]] {
            assert_eq!(
                finished_many(bad).validate().map_err(|v| v.field),
                Err("outputs.path"),
                "{bad:?}"
            );
        }
        let up = |path: &str| UploadHeader {
            lease_id: lease(),
            epoch: 1,
            path: path.into(),
            size: 0,
            sha256: Sha256Digest([0; 32]),
        };
        assert!(up("a.txt").validate().is_ok());
        assert!(up("../a.txt").validate().is_err());

        let welcome = |heartbeat_interval_s, lease_ttl_s| ServerMsg::Welcome {
            server_version: "0.1.0".into(),
            node_id: NodeId::generate(),
            account_id: AccountId::generate(),
            heartbeat_interval_s,
            lease_ttl_s,
        };
        assert!(welcome(5, 60).validate().is_ok());
        assert!(welcome(0, 60).validate().is_err());
        assert!(welcome(5, 0).validate().is_err());
        // A lease TTL that is not longer than the heartbeat interval would expire every lease between heartbeats.
        assert!(welcome(60, 60).validate().is_err());
        assert!(welcome(61, 60).validate().is_err());
        assert!(
            ServerMsg::Error {
                code: "x".into(),
                message: "y".repeat(MAX_TEXT_LEN + 1)
            }
            .validate()
            .is_err()
        );
    }

    /// SI-10: hostile byte streams never panic and never make the decoder hold more than the maximum.
    mod fuzz {
        use super::*;
        use proptest::collection::vec;
        use proptest::prelude::*;

        fn block_on<F: std::future::Future>(f: F) -> F::Output {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(f)
        }

        fn valid_frame() -> Vec<u8> {
            let msg = AgentMsg::Hello {
                agent_version: "0.1.0".into(),
                inventory: inventory(),
                running: vec![],
                features: vec!["lease_restrictions_v1".into()],
            };
            let mut buf = Vec::new();
            block_on(write_frame(&mut buf, &msg)).unwrap();
            buf
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            #[test]
            fn random_streams_never_panic_and_stay_bounded(bytes in vec(any::<u8>(), 0..4096), max_len in 0u32..=2048) {
                block_on(async {
                    let mut r = bytes.as_slice();
                    while let Ok(Some(body)) = read_frame_body(&mut r, max_len).await {
                        prop_assert!(body.len() <= max_len as usize);
                        prop_assert!(body.capacity() <= max_len as usize);
                    }
                    let mut r = bytes.as_slice();
                    while let Ok(Some(_)) = read_frame::<AgentMsg, _>(&mut r, max_len).await {}
                    let mut r = bytes.as_slice();
                    while let Ok(Some(_)) = read_frame::<ServerMsg, _>(&mut r, MAX_FRAME_LEN).await {}
                    Ok(())
                })?;
            }

            #[test]
            fn announced_lengths_allocate_only_what_arrives(len in any::<u32>(), body in vec(any::<u8>(), 0..9000)) {
                let mut input = len.to_be_bytes().to_vec();
                input.extend_from_slice(&body);
                block_on(async {
                    // No maximum at all: only the bytes that actually arrive bound the buffer.
                    let mut r = input.as_slice();
                    match read_frame_body(&mut r, u32::MAX).await {
                        Ok(Some(b)) => {
                            prop_assert_eq!(b.len(), len as usize);
                            prop_assert!(b.capacity() <= len as usize);
                        }
                        Err(FrameError::Truncated) => prop_assert!((len as usize) > body.len()),
                        other => prop_assert!(false, "unexpected {:?}", other),
                    }
                    Ok(())
                })?;
            }

            #[test]
            fn json_like_payloads_never_panic(payload in "\\PC{0,300}") {
                let mut input = (payload.len() as u32).to_be_bytes().to_vec();
                input.extend_from_slice(payload.as_bytes());
                block_on(async {
                    let mut r = input.as_slice();
                    let _ = read_frame::<AgentMsg, _>(&mut r, MAX_FRAME_LEN).await;
                    let mut r = input.as_slice();
                    let _ = read_frame::<ServerMsg, _>(&mut r, MAX_FRAME_LEN).await;
                });
            }

            #[test]
            fn mutated_valid_frames_never_panic(flips in vec((any::<prop::sample::Index>(), any::<u8>()), 1..8)) {
                let mut bytes = valid_frame();
                for (i, b) in flips {
                    let i = i.index(bytes.len());
                    bytes[i] = b;
                }
                block_on(async {
                    let mut r = bytes.as_slice();
                    while let Ok(Some(m)) = read_frame::<AgentMsg, _>(&mut r, MAX_FRAME_LEN).await {
                        let _ = m.validate();
                    }
                });
            }
        }
    }

    #[test]
    fn debug_of_join_and_lease_hides_secrets() {
        let token = crate::auth::JoinToken::generate(
            "a".repeat(64),
            vec![],
            crate::auth::DEFAULT_JOIN_TOKEN_TTL,
            datetime!(2026-11-05 10:00:00 UTC),
        )
        .unwrap();
        let encoded = token.encode().unwrap();
        let join = AgentMsg::Join {
            token,
            inventory: inventory(),
        };
        let dbg = format!("{join:?}");
        assert!(!dbg.contains(&encoded["p2pc_join_".len()..]), "{dbg}");

        let mut job: JobSpec = serde_json::from_value(json!({
            "image": "python:3.12", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 256},
            "env": {"API_TOKEN": "tok-very-secret-value"}
        }))
        .unwrap();
        job.files.push(crate::api::InputFile {
            path: "/inputs/k".into(),
            content_b64: "c2VjcmV0LWtleQ==".into(),
        });
        let lease = ServerMsg::Lease {
            lease_id: lease(),
            epoch: 1,
            job: LeaseJob::from_spec(&job),
            account_id: AccountId::generate(),
            deadline: datetime!(2026-11-05 11:00:00 UTC),
        };
        let dbg = format!("{lease:?}");
        assert!(!dbg.contains("tok-very-secret-value"), "{dbg}");
        assert!(!dbg.contains("c2VjcmV0LWtleQ=="), "{dbg}");
    }
}
