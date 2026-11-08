// SPDX-License-Identifier: Apache-2.0

//! What this machine has and can do (spec §6 `Inventory`, §9.0), and what the owner offers of it (§8, U9).
//!
//! [`detect`] is the entry point. It never caches: T05b calls it on every `Hello` and every 10 minutes, so a driver
//! installed after start, or a failure that went away, shows up on the next call. It works in two steps:
//!
//! 1. [`probe`] reads `/proc`, `/etc`, `/sys` and `/dev` through [`Host`] and runs the external tools through
//!    [`CommandRunner`] (each with its 5 s timeout, concurrently, all under one overall deadline, 15 s by default).
//!    The file reads run on the blocking pool. It never fails: a missing tool is reported as
//!    unavailable.
//! 2. [`Probe::report`] applies the owner's share limits ([`crate::config::Share::resolve`]), builds the wire
//!    [`Inventory`] and validates it with `p2pc-proto`, exactly as the server will.
//!
//! The agent never installs or changes anything here.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, SystemTime};

use tokio::time::Instant;

use p2pc_proto::api::{
    Capacity, CpuInfo, GpuInfo, GpuStatus, GpuStatusKind, Inventory, Platform, SandboxCapability, Wsl2Health,
};
use p2pc_proto::protocol::{MAX_TEXT_LEN, ProtocolViolation, validate_inventory};
use serde::Serialize;

use crate::config::{Config, ConfigError, Hardware, MissingGpu, ResolvedShare, Runtime};
use crate::host::Host;
use crate::parse;
use crate::platform::{self, PodmanFacts, Problem, SandboxFacts, Tool};
use crate::runner::{CommandOutput, CommandRunner, RunError};

pub mod boot;

pub use self::boot::BootStatus;

/// Where `nvidia-smi` is looked for, in order: the `PATH`, then the WSL2 driver directory.
pub const NVIDIA_SMI_PATHS: [&str; 2] = ["nvidia-smi", "/usr/lib/wsl/lib/nvidia-smi"];
/// Directories that hold CDI spec files.
pub const CDI_DIRS: [&str; 2] = ["/etc/cdi", "/var/run/cdi"];
/// The CDI kind of NVIDIA GPUs.
pub const NVIDIA_CDI_KIND: &str = "nvidia.com/gpu";
/// The WSL2 driver libraries the CDI spec must not be older than (§9.0 "CDI at boot").
pub const WSL_LIB_DIR: &str = "/usr/lib/wsl/lib";
/// The distro version stamp written by the WSL image builder (T14a).
pub const DISTRO_VERSION_FILE: &str = "/etc/p2pc-distro-version";
/// The agent's version.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The wire value of `memory_mb` when the RAM size could not be read. The wire field must be 1 MiB to 64 TiB, so
/// "unknown" is sent as the smallest value, always together with `ready = false`, a `memory_unknown` problem and an
/// offer of nothing (T07b review, carry-over 1). The scheduler never places a job on such a node.
pub const UNKNOWN_MEMORY_MB: u64 = 1;
/// The deadline of the first read, the RAM size, which every offer depends on (at most half the detection deadline).
pub const RAM_DEADLINE: Duration = Duration::from_secs(2);
/// Single-flight key of the RAM size read ([`crate::host::SingleFlight`]).
pub const FLIGHT_MEMINFO: &str = "/proc/meminfo";
/// Single-flight key of the other host files (`/proc`, `/etc`, `/dev`).
pub const FLIGHT_HOST_FILES: &str = "host files";
/// Single-flight key of the data dir's filesystem size.
pub const FLIGHT_DISK_SIZE: &str = "data dir filesystem size";
/// Single-flight key of the CDI spec files scan.
pub const FLIGHT_CDI_FILES: &str = "CDI spec files";

const MAX_CDI_FILES: usize = 64;
const MAX_WSL_LIB_FILES: usize = 4096;

/// Why an inventory cannot be built.
#[derive(Debug, thiserror::Error)]
pub enum DetectError {
    /// The share limits do not fit this machine.
    #[error(transparent)]
    Share(#[from] ConfigError),
    /// The built inventory breaks a `p2pc-proto` rule (a bug, or a very unusual machine).
    #[error("the detected inventory is invalid: {0}")]
    Invalid(#[from] ProtocolViolation),
}

/// GPU detection.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GpuProbe {
    /// The `nvidia-smi` that answered, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nvidia_smi: Option<String>,
    /// The GPUs, keyed by UUID.
    #[serde(skip)]
    pub gpus: Vec<GpuInfo>,
    /// The outcome before CDI is considered.
    #[serde(skip)]
    pub status: GpuStatus,
    /// Lines that could not be parsed, and other details that did not stop detection.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl GpuProbe {
    fn failed(kind: GpuStatusKind, reason: impl Into<String>, nvidia_smi: Option<&str>) -> Self {
        Self {
            nvidia_smi: nvidia_smi.map(String::from),
            gpus: Vec::new(),
            status: GpuStatus {
                status: kind,
                reason: Some(reason.into()),
            },
            notes: Vec::new(),
        }
    }

    /// Whether `nvidia-smi` itself worked (whatever it found).
    #[must_use]
    pub fn detection_ok(&self) -> bool {
        matches!(self.status.status, GpuStatusKind::Ok | GpuStatusKind::NotFound)
    }
}

/// CDI detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CdiProbe {
    /// `nvidia-ctk`.
    pub nvidia_ctk: Tool,
    /// Fully qualified CDI devices, for example `nvidia.com/gpu=all`.
    pub devices: Vec<String>,
    /// NVIDIA CDI spec files found in [`CDI_DIRS`].
    pub spec_files: Vec<String>,
    /// Whether an NVIDIA CDI spec is present.
    pub present: bool,
    /// WSL2 only: whether the newest NVIDIA spec is older than the newest file in [`WSL_LIB_DIR`].
    pub stale: bool,
}

/// Everything detected on the machine, before the owner's share limits.
#[derive(Debug, Clone)]
pub struct Probe {
    /// Native Linux or WSL2.
    pub platform: Platform,
    /// Hostname, sanitized to the inventory's character set.
    pub hostname: String,
    /// CPU model and logical cores.
    pub cpu: CpuInfo,
    /// RAM in MiB, if `/proc/meminfo` was readable.
    pub memory_mb: Option<u64>,
    /// `NAME VERSION_ID` from os-release.
    pub os: String,
    /// `uname -m`.
    pub arch: String,
    /// Size of the data dir's filesystem, in MiB.
    pub disk_mb: Option<u64>,
    /// GPUs.
    pub gpu: GpuProbe,
    /// CDI.
    pub cdi: CdiProbe,
    /// Whether `/dev/dxg` exists.
    pub dxg: bool,
    /// The WSL distro stamp, if the file exists.
    pub distro_version: Option<String>,
    /// The §9.0 inputs.
    pub sandbox: SandboxFacts,
    /// gVisor's `runsc`, whatever the configured runtime.
    pub runsc: Tool,
    /// crun, whatever the configured runtime.
    pub crun: Tool,
    /// Unmet §9.0 requirements.
    pub problems: Vec<Problem>,
    /// Parts of the detection that hit the deadline.
    pub notes: Vec<String>,
    /// WSL2 with `/dev/dxg` only: the distro's boot status ([`boot`]).
    pub boot: Option<BootStatus>,
}

/// Agent-side facts that are not part of the wire inventory, for `p2pc-agent inventory --json` and `doctor`.
#[derive(Debug, Clone, Serialize)]
pub struct LocalDetails {
    /// The share limits with every default applied.
    pub share: ResolvedShare,
    /// Podman.
    pub podman: PodmanFacts,
    /// crun.
    pub crun: Tool,
    /// gVisor's runsc.
    pub runsc: Tool,
    /// GPU detection details.
    pub gpu: GpuProbe,
    /// CDI.
    pub cdi: CdiProbe,
    /// Size of the data dir's filesystem, in MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_total_mb: Option<u64>,
    /// Unmet §9.0 requirements, with fix hints.
    pub problems: Vec<Problem>,
    /// Parts of the detection that hit the deadline (`detect_timeout_s`) and are reported as unknown.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// WSL2 with `/dev/dxg` only: the distro's boot status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot: Option<BootStatus>,
}

/// An inventory, ready to send, and the local details behind it.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// What the server receives (§6).
    pub inventory: Inventory,
    /// What stays on the node.
    pub local: LocalDetails,
}

/// Probes the machine and builds a validated inventory. Never cached. A GPU UUID in `share.gpus` that is not on the
/// machine is an error: use this at start and in `doctor`, where it is most likely a typo.
pub async fn detect(host: &Host, runner: &impl CommandRunner, config: &Config) -> Result<Report, DetectError> {
    probe(host, runner, config.runtime, &config.data_dir, config.detect_timeout())
        .await
        .report(config)
}

/// [`detect`] for the periodic re-detection (every 10 minutes, and on every `Hello`): a listed GPU that is not
/// there any more (an unplugged eGPU) is skipped with a warning, so it never stops the whole detection.
pub async fn detect_periodic(host: &Host, runner: &impl CommandRunner, config: &Config) -> Result<Report, DetectError> {
    probe(host, runner, config.runtime, &config.data_dir, config.detect_timeout())
        .await
        .report_with(config, MissingGpu::Skip)
}

/// What the plain file reads of one detection found (`/proc`, `/etc`, `/dev`).
#[derive(Debug)]
struct HostFacts {
    platform: Platform,
    hostname: String,
    cpu_model: Option<String>,
    cpu_logical: u32,
    os: String,
    dxg: bool,
    distro_version: Option<String>,
    euid: Option<u32>,
    cgroup_v2_mounted: bool,
    /// The `user@<uid>.service` above the agent: only looked for on the Linux profile (T10j).
    user_manager: Option<platform::UserManager>,
    subuid: Option<String>,
    subgid: Option<String>,
    windows_mounts: Vec<String>,
    wsl_interop_env: bool,
    wsl_conf: Option<String>,
    windows_path: Vec<String>,
    binfmt_interop: bool,
}

impl HostFacts {
    /// Nothing could be read in time.
    fn unknown() -> Self {
        Self {
            platform: Platform::Linux,
            hostname: "node".into(),
            cpu_model: None,
            cpu_logical: 0,
            os: "Linux".into(),
            dxg: false,
            distro_version: None,
            euid: None,
            cgroup_v2_mounted: false,
            user_manager: None,
            subuid: None,
            subgid: None,
            windows_mounts: Vec::new(),
            wsl_interop_env: false,
            wsl_conf: None,
            windows_path: Vec::new(),
            binfmt_interop: false,
        }
    }
}

/// Blocking: reads the machine's files. Run it only from `spawn_blocking`.
fn read_host_facts(host: &Host) -> HostFacts {
    let cpu = host.read("/proc/cpuinfo").map(|t| parse::cpuinfo(&t)).ok();
    let platform = platform::detect(host);
    HostFacts {
        platform,
        hostname: hostname(host),
        cpu_model: cpu.as_ref().and_then(|c| c.model.clone()),
        cpu_logical: cpu.map_or(0, |c| c.logical),
        os: ["/etc/os-release", "/usr/lib/os-release"]
            .iter()
            .find_map(|p| host.read(p).ok().and_then(|t| parse::os_release(&t)))
            .unwrap_or_else(|| "Linux".into()),
        dxg: host.exists("/dev/dxg"),
        distro_version: host
            .read(DISTRO_VERSION_FILE)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
        euid: host.euid(),
        cgroup_v2_mounted: host.exists("/sys/fs/cgroup/cgroup.controllers"),
        user_manager: (platform == Platform::Linux)
            .then(|| platform::read_user_manager(host))
            .flatten(),
        subuid: host.read("/etc/subuid").ok(),
        subgid: host.read("/etc/subgid").ok(),
        windows_mounts: host
            .read("/proc/mounts")
            .map(|m| parse::windows_mounts(&m))
            .unwrap_or_default(),
        wsl_interop_env: host.has_wsl_interop_env(),
        wsl_conf: host.read("/etc/wsl.conf").ok(),
        windows_path: host.path_var().map(parse::windows_path_entries).unwrap_or_default(),
        binfmt_interop: platform::binfmt_interop_visible(host),
    }
}

/// What became of a piece of blocking work.
#[derive(Debug)]
enum Blocking<T> {
    /// It finished in time.
    Done(T),
    /// It did not finish by the deadline, or panicked. A stuck thread is left behind, holding its flight.
    Late,
    /// The previous run of the same work is still stuck: it was not started again.
    Busy,
}

impl<T> Blocking<T> {
    /// The result, or the note that explains why there is none.
    fn or_note(self, what: &str, timeout: Duration, notes: &mut Vec<String>) -> Option<T> {
        match self {
            Blocking::Done(v) => Some(v),
            Blocking::Late => {
                notes.push(format!(
                    "{what} did not answer within the {timeout:?} detection deadline; reported as unknown"
                ));
                None
            }
            Blocking::Busy => {
                notes.push(format!(
                    "{what} is still running from an earlier detection (stuck); not started again; reported as unknown"
                ));
                None
            }
        }
    }
}

/// Runs blocking file work on the blocking pool, and gives up on it at `deadline`: a hung `/proc` or network
/// filesystem must not stall the async runtime (heartbeats run on it), nor the detection. The work is single-flight
/// per `key` ([`crate::host::SingleFlight`]): while an earlier run is still stuck, it is not started again.
async fn blocking_until<T: Send + 'static>(
    host: &Host,
    key: &'static str,
    deadline: Instant,
    work: impl FnOnce() -> T + Send + 'static,
) -> Blocking<T> {
    let Some(token) = host.flights().start(key) else {
        return Blocking::Busy;
    };
    let task = tokio::task::spawn_blocking(move || {
        let result = work();
        drop(token);
        result
    });
    match tokio::time::timeout_at(deadline, task).await {
        Ok(Ok(v)) => Blocking::Done(v),
        _ => Blocking::Late,
    }
}

/// Reads and runs everything the inventory needs, within one overall `timeout`. Never fails; missing things are
/// reported in the result. A part that has not answered by the deadline is reported as unknown, with a note in
/// [`Probe::notes`]; the rest of the inventory is still reported. The file reads run on the blocking pool.
pub async fn probe(
    host: &Host,
    runner: &impl CommandRunner,
    runtime: Runtime,
    data_dir: &Path,
    timeout: Duration,
) -> Probe {
    let start = Instant::now();
    let deadline = start + timeout;
    let mut notes = Vec::new();
    // The RAM size first, with its own short deadline: every offer depends on it (T07b review, carry-over 1).
    let memory_mb = {
        let h = host.clone();
        let read = move || h.read("/proc/meminfo").ok().and_then(|t| parse::meminfo_total_mb(&t));
        // At most half the detection budget, so a hung read leaves time for the rest.
        let ram_deadline = RAM_DEADLINE.min(timeout / 2);
        blocking_until(host, FLIGHT_MEMINFO, start + ram_deadline, read)
            .await
            .or_note("reading the RAM size (/proc/meminfo)", ram_deadline, &mut notes)
            .flatten()
    };
    let mut facts = {
        let h = host.clone();
        blocking_until(host, FLIGHT_HOST_FILES, deadline, move || read_host_facts(&h))
            .await
            .or_note("reading /proc and /etc", timeout, &mut notes)
            .unwrap_or_else(HostFacts::unknown)
    };
    let platform = facts.platform;
    let wsl = platform == Platform::Wsl2;
    let disk_path = host.path(data_dir);
    // §9.0 on WSL2: the boot step's status gates the GPU offer (carry-over 9). The wait runs **alongside** the probes
    // (T05b review, P2-2), so it never eats their deadline: a detection takes the longer of the two, not their sum.
    // Without /dev/dxg there is no GPU to wait for.
    let wait_for_boot = wsl && facts.dxg;
    let (boot, (gpu, cdi, podman, crun, runsc, arch, disk_mb), delegated) = tokio::join!(
        async {
            if wait_for_boot {
                Some(boot::wait(host).await)
            } else {
                None
            }
        },
        probe_parts(host, runner, wsl, deadline, disk_path),
        systemctl_delegation(runner, facts.user_manager.as_ref(), deadline),
    );
    let systemctl_late = delegated.is_err();
    if let (Some(manager), Ok(Some(delegated))) = (facts.user_manager.as_mut(), delegated) {
        manager.delegated = Some(delegated);
    }
    let mut late = |what: &str| {
        notes.push(format!(
            "{what} did not answer within the {timeout:?} detection deadline; reported as unknown"
        ))
    };

    if systemctl_late {
        // `podman info` decides the delegation instead; say why, or its answer reads as the only one asked.
        late("`systemctl show` (the delegation of the user manager)");
    }
    let gpu = gpu.unwrap_or_else(|| {
        late("GPU detection (nvidia-smi)");
        GpuProbe::failed(
            GpuStatusKind::NvmlError,
            format!("GPU detection did not finish within the {timeout:?} deadline"),
            None,
        )
    });
    let cdi = cdi.map(|(cdi, scanned)| {
        if !scanned {
            late("scanning the CDI spec files");
        }
        cdi
    });
    let cdi = cdi.unwrap_or_else(|| {
        late("CDI detection (nvidia-ctk and the spec files)");
        CdiProbe {
            nvidia_ctk: Tool::Failed {
                reason: format!("no answer within the {timeout:?} deadline"),
            },
            devices: Vec::new(),
            spec_files: Vec::new(),
            present: false,
            stale: false,
        }
    });
    let podman = podman.unwrap_or_else(|| {
        late("Podman");
        let reason = format!("no answer within the {timeout:?} deadline");
        PodmanFacts {
            tool: Tool::Failed { reason: reason.clone() },
            info: None,
            info_error: Some(reason),
        }
    });
    let mut tool = |t: Option<Tool>, name: &str| {
        t.unwrap_or_else(|| {
            late(name);
            Tool::Failed {
                reason: format!("no answer within the {timeout:?} deadline"),
            }
        })
    };
    let crun = tool(crun, "crun");
    let runsc = tool(runsc, "runsc");
    let disk_mb = match disk_mb {
        Blocking::Done(v) => v,
        other => other
            .or_note("the data dir's filesystem size", timeout, &mut notes)
            .flatten(),
    };
    let logical = Some(facts.cpu_logical)
        .filter(|&n| n > 0)
        .or_else(|| {
            std::thread::available_parallelism()
                .ok()
                .and_then(|n| u32::try_from(n.get()).ok())
        })
        .unwrap_or(1);
    let arch = match arch {
        Some(Ok(out)) if out.success() && !out.stdout.trim().is_empty() => out.stdout.trim().to_string(),
        _ => std::env::consts::ARCH.to_string(),
    };
    let runtime_tool = match runtime {
        Runtime::Crun => crun.clone(),
        Runtime::Runsc => runsc.clone(),
    };
    let sandbox = SandboxFacts {
        euid: facts.euid,
        podman,
        cgroup_v2_mounted: facts.cgroup_v2_mounted,
        user_manager: facts.user_manager,
        subuid: facts.subuid,
        subgid: facts.subgid,
        windows_mounts: facts.windows_mounts,
        wsl_interop_env: facts.wsl_interop_env,
        wsl_conf: facts.wsl_conf,
        windows_path: facts.windows_path,
        binfmt_interop: facts.binfmt_interop,
        runtime,
        runtime_tool,
    };
    let mut problems = platform::check(platform, &sandbox);
    if memory_mb.is_none() {
        problems.push(Problem::new(
            "memory_unknown",
            "the RAM size could not be read from /proc/meminfo, so nothing is offered",
            "check that /proc/meminfo is readable; the next detection (at most 10 minutes) tries again",
        ));
    }
    Probe {
        platform,
        hostname: facts.hostname,
        cpu: CpuInfo {
            model: facts.cpu_model.unwrap_or_else(|| "unknown".into()),
            cores: logical,
        },
        memory_mb,
        os: facts.os,
        arch,
        disk_mb,
        gpu,
        cdi,
        dxg: facts.dxg,
        distro_version: facts.distro_version,
        sandbox,
        runsc,
        crun,
        problems,
        notes,
        boot,
    }
}

/// T10j: what `systemd` is configured to delegate to `user@<uid>.service`, asked only when its running cgroup's
/// `cgroup.controllers` could not be read (the same fallback as `setup-host.sh`'s `delegated_controllers`).
///
/// `Ok(None)`: not asked, or it did not answer usefully. `Err(())`: it missed the deadline, which the caller notes.
async fn systemctl_delegation(
    runner: &impl CommandRunner,
    manager: Option<&platform::UserManager>,
    deadline: Instant,
) -> Result<Option<platform::Delegated>, ()> {
    let Some(manager) = manager.filter(|m| m.delegated.is_none()) else {
        return Ok(None);
    };
    let unit = manager.unit();
    let args = ["show", unit.as_str(), "--property=DelegateControllers", "--value"];
    match tokio::time::timeout_at(deadline, runner.run("systemctl", &args)).await {
        Ok(Ok(out)) if out.success() && !out.stdout.trim().is_empty() => {
            Ok(Some(platform::Delegated::from_systemctl(manager.uid, &out.stdout)))
        }
        Ok(_) => Ok(None),
        Err(_) => Err(()),
    }
}

/// What the probes answered, each `None` (or `Late`/`Busy`) when it missed the deadline.
type Parts = (
    Option<GpuProbe>,
    Option<(CdiProbe, bool)>,
    Option<PodmanFacts>,
    Option<Tool>,
    Option<Tool>,
    Option<Result<CommandOutput, RunError>>,
    Blocking<Option<u64>>,
);

/// The tools and the disk size, concurrently, each under the detection deadline.
async fn probe_parts(
    host: &Host,
    runner: &impl CommandRunner,
    wsl: bool,
    deadline: Instant,
    disk_path: std::path::PathBuf,
) -> Parts {
    tokio::join!(
        async { tokio::time::timeout_at(deadline, probe_gpus(runner, wsl)).await.ok() },
        async {
            tokio::time::timeout_at(deadline, probe_cdi(host, runner, wsl))
                .await
                .ok()
        },
        async { tokio::time::timeout_at(deadline, probe_podman(runner)).await.ok() },
        async {
            tokio::time::timeout_at(deadline, probe_version(runner, "crun"))
                .await
                .ok()
        },
        async {
            tokio::time::timeout_at(deadline, probe_version(runner, "runsc"))
                .await
                .ok()
        },
        async {
            tokio::time::timeout_at(deadline, runner.run("uname", &["-m"]))
                .await
                .ok()
        },
        blocking_until(host, FLIGHT_DISK_SIZE, deadline, move || filesystem_size_mb(&disk_path)),
    )
}

impl Probe {
    /// The GPU status once CDI is taken into account (§6, §9.0).
    #[must_use]
    pub fn gpu_status(&self) -> GpuStatus {
        if self.gpu.status.status != GpuStatusKind::Ok {
            return self.gpu.status.clone();
        }
        let generate = match self.platform {
            Platform::Linux => "nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml",
            Platform::Wsl2 => "nvidia-ctk cdi generate --mode=wsl --output=/etc/cdi/nvidia.yaml",
        };
        if !self.cdi.present {
            return GpuStatus {
                status: GpuStatusKind::CdiMissing,
                reason: Some(format!(
                    "no {NVIDIA_CDI_KIND} CDI spec in /etc/cdi or /var/run/cdi; generate it with `{generate}`"
                )),
            };
        }
        if self.cdi.stale {
            return GpuStatus {
                status: GpuStatusKind::CdiStale,
                reason: Some(format!(
                    "the CDI spec is older than the driver libraries in {WSL_LIB_DIR}; regenerate it with `{generate}`"
                )),
            };
        }
        self.gpu.status.clone()
    }

    /// The facts the share limits are checked against; `None` while the RAM size is unknown.
    #[must_use]
    pub fn hardware(&self) -> Option<Hardware<'_>> {
        Some(Hardware {
            cores: self.cpu.cores,
            memory_mb: self.memory_mb?,
            disk_mb: self.disk_mb,
            gpus: &self.gpu.gpus,
            gpu_detection_ok: self.gpu.detection_ok(),
        })
    }

    /// Applies the share limits and builds the validated wire inventory.
    pub fn report(self, config: &Config) -> Result<Report, DetectError> {
        self.report_with(config, MissingGpu::Error)
    }

    /// Like [`Probe::report`], with the choice of what a missing GPU UUID in `share.gpus` does.
    pub fn report_with(self, config: &Config, missing: MissingGpu) -> Result<Report, DetectError> {
        // Unknown RAM: report the node, not ready (the `memory_unknown` problem) and offering nothing.
        let (memory_mb, mut share) = match self.hardware() {
            Some(hardware) => (hardware.memory_mb, config.share.resolve_with(&hardware, missing)?),
            None => (
                UNKNOWN_MEMORY_MB,
                ResolvedShare {
                    cpu_cores: 0.0,
                    memory_mb: 0,
                    gpus: Vec::new(),
                    disk_mb: 0,
                    warnings: vec!["nothing is offered: the RAM size is unknown".into()],
                },
            ),
        };
        let gpu_status = self.gpu_status();
        // Podman reaches a GPU only through a CDI spec: without one, offering it would only make GPU jobs fail.
        if gpu_status.status == GpuStatusKind::CdiMissing && !share.gpus.is_empty() {
            share
                .warnings
                .push("GPUs are not offered: there is no NVIDIA CDI spec".into());
            share.gpus.clear();
        }
        // §9: the WSL2 CDI spec only has `nvidia.com/gpu=all`, which hands a job every GPU of the machine. A GPU can
        // be pinned only when there is exactly one, so with more none is offered (even if the owner lists one).
        // The driver's `gpu_selection_unsupported` stays a fallback (§6).
        let present = self.gpu.gpus.len();
        if self.platform == Platform::Wsl2 && present > 1 && !share.gpus.is_empty() {
            share.warnings.push(format!(
                "GPUs are not offered: on WSL2 the CDI spec only has nvidia.com/gpu=all, which cannot select one \
                 of the {present} GPUs"
            ));
            share.gpus.clear();
        }
        // WSL2: the boot step failed, or has not reported for this start yet (carry-over 9).
        if let Some(why) = self.boot.as_ref().and_then(BootStatus::blocks_gpus)
            && !share.gpus.is_empty()
        {
            share.warnings.push(format!("GPUs are not offered: {why}"));
            share.gpus.clear();
        }
        let wsl2 = (self.platform == Platform::Wsl2).then(|| Wsl2Health {
            // Unknown is `null` on the wire, never an empty string.
            distro_version: self.distro_version.as_deref().map(clean).filter(|v| !v.is_empty()),
            podman_version: self.sandbox.podman.tool.version().map(clean).filter(|v| !v.is_empty()),
            cdi_present: self.cdi.present,
            cdi_stale: self.cdi.stale,
            smoke: None, // T08 runs the once-per-boot smoke container.
        });
        let runtimes = [("crun", &self.crun), ("runsc", &self.runsc)]
            .into_iter()
            .filter(|(_, t)| t.is_available())
            .map(|(name, _)| name.to_string())
            .collect();
        let gpus = self
            .gpu
            .gpus
            .iter()
            .map(|g| GpuInfo {
                name: clean(&g.name),
                driver_version: clean(&g.driver_version),
                cuda_driver_version: g.cuda_driver_version.as_deref().map(clean),
                compute_capability: g.compute_capability.as_deref().map(clean),
                pci_bdf: g.pci_bdf.as_deref().map(clean),
                ..g.clone()
            })
            .collect();
        let inventory = Inventory {
            hostname: self.hostname.clone(),
            platform: self.platform,
            cpu: CpuInfo {
                model: clean(&self.cpu.model),
                cores: self.cpu.cores,
            },
            memory_mb,
            os: clean(&self.os),
            arch: clean(&self.arch),
            gpus,
            gpu_status: GpuStatus {
                status: gpu_status.status,
                reason: gpu_status.reason.as_deref().map(clean),
            },
            dxg: self.dxg,
            wsl2,
            sandbox: vec![SandboxCapability {
                driver: "podman".into(),
                class: platform::sandbox_class(config.runtime),
                runtimes,
                ready: self.problems.is_empty(),
                problems: self.problems.iter().map(|p| clean(&p.wire())).collect(),
            }],
            offered: Capacity {
                cpu: share.cpu_cores,
                memory_mb: share.memory_mb,
                gpu: u32::try_from(share.gpus.len()).unwrap_or(u32::MAX),
                // The disk the executor checks leases against (`executor::capacity`), so server and agent agree.
                disk_mb: Some(share.disk_mb),
            },
            disk_total_mb: self.disk_mb,
            agent_version: AGENT_VERSION.into(),
        };
        validate_inventory(&inventory)?;
        Ok(Report {
            inventory,
            local: LocalDetails {
                share,
                podman: self.sandbox.podman,
                crun: self.crun,
                runsc: self.runsc,
                gpu: self.gpu,
                cdi: self.cdi,
                disk_total_mb: self.disk_mb,
                problems: self.problems,
                notes: self.notes,
                boot: self.boot,
            },
        })
    }
}

/// Makes tool output fit the inventory's text rules: no control characters, at most [`MAX_TEXT_LEN`] bytes.
#[must_use]
pub fn clean(s: &str) -> String {
    let mut out: String = s.trim().chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    if out.len() > MAX_TEXT_LEN {
        let mut end = MAX_TEXT_LEN;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    out
}

/// The hostname, mapped onto the inventory's character set (`A-Z a-z 0-9 - . _`, 1-253 bytes).
fn hostname(host: &Host) -> String {
    let raw = ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|p| {
            host.read(p)
                .ok()
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_default();
    let mut name: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_') {
                c
            } else {
                '-'
            }
        })
        .take(253)
        .collect();
    if name.is_empty() {
        name = "node".into();
    }
    name
}

/// Size of the filesystem holding `path` (or its nearest existing ancestor), in MiB.
fn filesystem_size_mb(path: &Path) -> Option<u64> {
    let existing = path.ancestors().find(|p| p.exists())?;
    let st = rustix::fs::statvfs(existing).ok()?;
    Some(st.f_blocks.saturating_mul(st.f_frsize) / (1024 * 1024))
}

fn tool_from(result: Result<CommandOutput, RunError>, version: impl Fn(&str) -> Option<String>) -> Tool {
    match result {
        Err(RunError::NotFound) => Tool::Unavailable,
        Err(e) => Tool::Failed {
            reason: clean(&e.to_string()),
        },
        Ok(out) if !out.success() => Tool::Failed {
            reason: clean(out.first_line()),
        },
        Ok(out) => Tool::Available {
            version: version(&out.stdout).map(|v| clean(&v)),
        },
    }
}

async fn probe_version(runner: &impl CommandRunner, program: &str) -> Tool {
    tool_from(runner.run(program, &["--version"]).await, parse::runtime_version)
}

async fn probe_podman(runner: &impl CommandRunner) -> PodmanFacts {
    let tool = tool_from(
        runner.run("podman", &["version", "--format", "json"]).await,
        parse::podman_version,
    );
    let (info, info_error) = if tool == Tool::Unavailable {
        (None, None)
    } else {
        match runner.run("podman", &["info", "--format", "json"]).await {
            Ok(out) if out.success() => match parse::podman_info(&out.stdout) {
                Some(info) => (Some(info), None),
                None => (None, Some("output is not JSON".to_string())),
            },
            Ok(out) => (None, Some(clean(out.first_line()))),
            Err(e) => (None, Some(e.to_string())),
        }
    };
    PodmanFacts { tool, info, info_error }
}

async fn probe_gpus(runner: &impl CommandRunner, wsl: bool) -> GpuProbe {
    let query = format!("--query-gpu={}", parse::GPU_QUERY_FIELDS);
    let format = "--format=csv,noheader,nounits";
    let mut found = None;
    for bin in NVIDIA_SMI_PATHS {
        match runner.run(bin, &[&query, format]).await {
            Err(RunError::NotFound) => {}
            result => {
                found = Some((bin, result));
                break;
            }
        }
    }
    let Some((bin, mut result)) = found else {
        return GpuProbe::failed(
            GpuStatusKind::NoDriver,
            format!("nvidia-smi not found (looked on PATH and at {})", NVIDIA_SMI_PATHS[1]),
            None,
        );
    };
    let mut with_compute_cap = true;
    if let Ok(out) = &result
        && !out.success()
        && format!("{}{}", out.stdout, out.stderr).contains("is not a valid field")
    {
        // Drivers before compute_cap existed: ask again without it.
        with_compute_cap = false;
        let legacy = format!("--query-gpu={}", parse::GPU_QUERY_FIELDS_LEGACY);
        result = runner.run(bin, &[&legacy, format]).await;
    }
    let out = match result {
        Err(e) => return GpuProbe::failed(GpuStatusKind::NvmlError, format!("nvidia-smi: {e}"), Some(bin)),
        Ok(out) if !out.success() => return classify_smi_failure(&out, bin),
        Ok(out) => out,
    };
    let (mut gpus, mut notes) = parse::nvidia_smi_gpus(&out.stdout, with_compute_cap);
    if gpus.is_empty() {
        return if notes.is_empty() {
            GpuProbe::failed(GpuStatusKind::NotFound, "nvidia-smi lists no GPU", Some(bin))
        } else {
            let mut probe = GpuProbe::failed(
                GpuStatusKind::NvmlError,
                "cannot parse the output of nvidia-smi",
                Some(bin),
            );
            probe.notes = notes;
            probe
        };
    }
    probe_mig(runner, bin, &mut gpus, &mut notes).await;
    let cuda = match runner.run(bin, &[]).await {
        Ok(o) if o.success() => parse::nvidia_smi_cuda_version(&o.stdout),
        _ => None,
    };
    for g in &mut gpus {
        g.cuda_driver_version.clone_from(&cuda);
        if wsl {
            // The bus ID nvidia-smi shows inside WSL2 is virtual, not the host's PCI address.
            g.pci_bdf = None;
        }
    }
    GpuProbe {
        nvidia_smi: Some(bin.into()),
        gpus,
        status: GpuStatus {
            status: GpuStatusKind::Ok,
            reason: None,
        },
        notes,
    }
}

/// Fills in `GpuInfo::mig`. Only an old driver that does not know the field (no MIG at all) means `false` for every
/// card. When the state cannot be read, or a card is missing from the answer, that card is marked `mig = true`: on
/// the wire "MIG enabled or unknown", which makes it not offerable (§6) instead of guessing that it is safe.
async fn probe_mig(runner: &impl CommandRunner, bin: &str, gpus: &mut [GpuInfo], notes: &mut Vec<String>) {
    let answer = runner
        .run(bin, &["--query-gpu=uuid,mig.mode.current", "--format=csv,noheader"])
        .await;
    match answer {
        Ok(o) if o.success() => {
            let mig = parse::nvidia_smi_mig(&o.stdout);
            for g in gpus.iter_mut() {
                match mig.get(&g.uuid) {
                    Some(parse::MigMode::Enabled) => g.mig = true,
                    Some(parse::MigMode::Disabled) => g.mig = false,
                    Some(parse::MigMode::Unknown(value)) => {
                        g.mig = true;
                        notes.push(format!(
                            "MIG mode of {} reads {:?}; treating it as MIG-enabled, so it is not offered",
                            g.uuid,
                            clean(value)
                        ));
                    }
                    None => {
                        g.mig = true;
                        notes.push(format!(
                            "MIG mode of {} is missing from the nvidia-smi answer; treating it as MIG-enabled, so it is not offered",
                            g.uuid
                        ));
                    }
                }
            }
        }
        Ok(o) if format!("{}{}", o.stdout, o.stderr).contains("is not a valid field") => {
            // A driver before MIG: no card can have it.
            for g in gpus.iter_mut() {
                g.mig = false;
            }
        }
        failure => {
            let why = match failure {
                Ok(o) => clean(o.first_line()),
                Err(e) => e.to_string(),
            };
            for g in gpus.iter_mut() {
                g.mig = true;
            }
            notes.push(format!(
                "MIG mode could not be read ({why}); treating every GPU as MIG-enabled, so none is offered"
            ));
        }
    }
}

fn classify_smi_failure(out: &CommandOutput, bin: &str) -> GpuProbe {
    let text = format!("{}\n{}", out.stdout, out.stderr).to_ascii_lowercase();
    let reason = clean(out.first_line());
    let kind = if text.contains("no devices were found") {
        GpuStatusKind::NotFound
    } else if text.contains("couldn't communicate with the nvidia driver")
        || text.contains("driver is not loaded")
        || text.contains("no nvidia driver")
    {
        GpuStatusKind::NoDriver
    } else {
        GpuStatusKind::NvmlError
    };
    GpuProbe::failed(kind, format!("nvidia-smi: {reason}"), Some(bin))
}

/// CDI from `nvidia-ctk cdi list` and the spec files. The second value is `false` when the spec files were not
/// scanned, because an earlier scan is still stuck.
async fn probe_cdi(host: &Host, runner: &impl CommandRunner, wsl: bool) -> (CdiProbe, bool) {
    let listed = runner.run("nvidia-ctk", &["cdi", "list"]).await;
    let mut devices: BTreeSet<String> = match &listed {
        Ok(out) if out.success() => parse::cdi_list(&format!("{}\n{}", out.stdout, out.stderr))
            .into_iter()
            .collect(),
        _ => BTreeSet::new(),
    };
    let nvidia_ctk = tool_from(listed, |_| None);
    // The spec files and the driver libraries' mtimes: file work, on the blocking pool.
    // The caller's deadline bounds the wait; the scan itself is single-flight.
    let far = Instant::now() + Duration::from_secs(24 * 3600);
    let h = host.clone();
    let (scan, scanned) = match blocking_until(host, FLIGHT_CDI_FILES, far, move || scan_cdi_files(&h, wsl)).await {
        Blocking::Done(scan) => (scan, true),
        Blocking::Late => (CdiScan::default(), true),
        Blocking::Busy => (CdiScan::default(), false),
    };
    devices.extend(scan.devices);
    let present = !scan.spec_files.is_empty() || devices.iter().any(|d| d.starts_with("nvidia.com/gpu="));
    let probe = CdiProbe {
        nvidia_ctk,
        devices: devices.into_iter().collect(),
        spec_files: scan.spec_files,
        present,
        stale: scan.stale,
    };
    (probe, scanned)
}

/// What the CDI spec files on disk say.
#[derive(Debug, Default)]
struct CdiScan {
    devices: Vec<String>,
    spec_files: Vec<String>,
    stale: bool,
}

/// Blocking: reads the spec files in [`CDI_DIRS`] and, on WSL2, stats the files of [`WSL_LIB_DIR`].
fn scan_cdi_files(host: &Host, wsl: bool) -> CdiScan {
    let mut scan = CdiScan::default();
    let mut newest_spec: Option<SystemTime> = None;
    for dir in CDI_DIRS {
        for name in host.list_dir(dir, MAX_CDI_FILES) {
            let json = name.ends_with(".json");
            if !(json || name.ends_with(".yaml") || name.ends_with(".yml")) {
                continue;
            }
            let path = format!("{dir}/{name}");
            let Some(spec) = host.read(&path).ok().and_then(|t| parse::cdi_spec(&t, json)) else {
                continue;
            };
            if spec.kind != NVIDIA_CDI_KIND {
                continue;
            }
            scan.devices.extend(spec.qualified());
            if let Ok(modified) = host.modified(&path) {
                newest_spec = newest_spec.max(Some(modified));
            }
            scan.spec_files.push(path);
        }
    }
    scan.stale = wsl
        && newest_spec.is_some_and(|spec| {
            host.list_dir(WSL_LIB_DIR, MAX_WSL_LIB_FILES)
                .iter()
                .filter_map(|f| host.modified(format!("{WSL_LIB_DIR}/{f}")).ok())
                .max()
                .is_some_and(|newest_lib| spec < newest_lib)
        });
    scan
}

#[cfg(test)]
mod tests;
