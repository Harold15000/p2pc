// SPDX-License-Identifier: Apache-2.0

//! The real [`SetupHost`]: first run's Windows and WSL actions over `p2pc-wsl` (H2 §8.2, §8.3, §8.5, §10.5).
//!
//! Every program runs through `p2pc_wsl::runner` ([`CommandRunner`]): an argument vector, never a shell string; no
//! secret on a command line (the runner refuses one); `wsl.exe` retried on the WSL service timeout. The tests below
//! use a fake runner, so no test starts `wsl.exe` or PowerShell.
//!
//! Inside the distro (as root, `wsl.exe -d p2pc-node -u root --exec …`):
//!
//! - the agent runs with `--config /var/lib/p2pc/agent.toml`, the file `p2pc-run` gives it (created empty, 0600, when
//!   missing, as `p2pc-run` does);
//! - the hub's data dir is `/var/lib/p2pc-server` (§8.5), which `p2pc-run` requires;
//! - the hub's `server.toml` is changed by reading it, setting one key, and writing it back through stdin to a
//!   temporary file that is then renamed over it (never through `/mnt/c`: hard rule 8).

use std::ops::ControlFlow;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use p2pc_wsl::Layout;
use p2pc_wsl::checks::{ChecksReport, DiskState, Thresholds, run_checks};
use p2pc_wsl::image::{ImagePin, Progress, RangeFetch, download_image, verify_image};
use p2pc_wsl::import;
use p2pc_wsl::runner::{CommandRunner, Host, Invocation, Pause, in_distro, powershell};
use p2pc_wsl::task::{self, TaskContext};

use crate::autostart::{RUN_VALUE_NAME, RunKey, open_command_line};

use super::errors::{SetupError, SetupErrorCode, from_image_error, from_import_error};
use super::host::{HubInit, JoinResult, JoinToken, NodeFacts, SetupHost, WslInstall};
use super::record::{NetworkingMode, ShareRecord};

/// The agent in the image.
pub const AGENT_BIN: &str = "/usr/local/bin/p2pc-agent";
/// The hub in the image (T2-41).
pub const SERVER_BIN: &str = "/usr/local/bin/p2pc-server";
/// The agent's config, as `p2pc-run` passes it (`P2PC_AGENT_CONFIG`).
pub const AGENT_CONFIG: &str = "/var/lib/p2pc/agent.toml";
/// The hub's data dir (§8.5).
pub const HUB_DIR: &str = "/var/lib/p2pc-server";
/// The hub's config.
pub const SERVER_TOML: &str = "/var/lib/p2pc-server/server.toml";
/// The temporary name `server.toml` is written to before it is renamed.
pub const SERVER_TOML_TEMP: &str = "/var/lib/p2pc-server/server.toml.p2pc-app.tmp";
/// The flag `p2pc-run` starts the hub on (§8.5).
pub const HUB_FLAG: &str = "/var/lib/p2pc-server/hub.enabled";
/// WSL's own tool for its settings, in every WSL 2 distro.
pub const WSLINFO: &str = "/usr/bin/wslinfo";
/// The downloaded image's file name under `%LOCALAPPDATA%\P2PC\images`.
pub const IMAGE_FILE: &str = "p2pc-node.tar";

/// The time limit of the elevated `wsl --install` (it downloads WSL; the UAC prompt waits for the user).
pub const WSL_INSTALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// The time limit of a command inside the distro.
pub const IN_DISTRO_TIMEOUT: Duration = Duration::from_secs(120);

/// Exit codes of `p2pc-agent join` (`p2pc-agent`'s `connection::exit`).
const AGENT_ALREADY_ENROLLED: i32 = 3;
const AGENT_INVALID_TOKEN: i32 = 4;
const AGENT_TOKEN_EXPIRED: i32 = 5;

/// Windows Installer's "success, reboot required" codes (`ERROR_SUCCESS_REBOOT_REQUIRED`, `…_INITIATED`).
const REBOOT_CODES: [i32; 2] = [3010, 1641];

/// Step 2a: `wsl.exe --install --no-distribution`, elevated through UAC (`Start-Process -Verb RunAs`), waiting for it.
/// It prints `exit=<code>`, or `declined` when the prompt was refused or the process could not start. The app never
/// runs anything else elevated (§8.1).
pub const INSTALL_WSL_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
try {
    $p = Start-Process -FilePath $wsl -ArgumentList @('--install', '--no-distribution') -Verb RunAs -Wait -PassThru
    'exit=' + [string]$p.ExitCode
} catch {
    'declined'
}
"#;

/// The node image this app build is pinned to (§8.3: "URL and SHA-256 compiled into the app build for its matching
/// image version"), from `P2PC_NODE_IMAGE_URL` and `P2PC_NODE_IMAGE_SHA256` at build time (the release pipeline, T2-52,
/// sets them). A build without them, or with an unusable pin, has none: the download is then `not_available`.
pub fn compiled_image_pin() -> Option<ImagePin> {
    image_pin_from(
        option_env!("P2PC_NODE_IMAGE_URL"),
        option_env!("P2PC_NODE_IMAGE_SHA256"),
    )
}

/// [`compiled_image_pin`] from its two values.
pub fn image_pin_from(url: Option<&str>, sha256: Option<&str>) -> Option<ImagePin> {
    ImagePin::new(url?, sha256?).ok()
}

/// What `p2pc-agent inventory --json` prints, the fields first run reads.
#[derive(Debug, Deserialize)]
struct InventoryReport {
    inventory: Inventory,
}

#[derive(Debug, Deserialize)]
struct Inventory {
    cpu: Cpu,
    memory_mb: u64,
    #[serde(default)]
    gpus: Vec<serde_json::Value>,
    gpu_status: GpuStatus,
    offered: Offered,
}

#[derive(Debug, Deserialize)]
struct Cpu {
    cores: u32,
}

#[derive(Debug, Deserialize)]
struct GpuStatus {
    status: String,
}

#[derive(Debug, Deserialize)]
struct Offered {
    cpu: f64,
    memory_mb: u64,
    #[serde(default)]
    gpu: u32,
}

/// The node's hardware from `p2pc-agent inventory --json`.
pub fn parse_inventory(json: &str) -> Option<NodeFacts> {
    let report: InventoryReport = serde_json::from_str(json).ok()?;
    let inv = report.inventory;
    let cores = inv.cpu.cores.max(1);
    let offered_cpu = if inv.offered.cpu.is_finite() && inv.offered.cpu >= 1.0 {
        // Whole cores; `as` saturates, and the clamp keeps it within the VM.
        (inv.offered.cpu.floor() as u32).clamp(1, cores)
    } else {
        1
    };
    Some(NodeFacts {
        cpu_cores: cores,
        memory_mb: inv.memory_mb,
        gpu_offerable: inv.gpu_status.status == "ok" && !inv.gpus.is_empty() && inv.offered.gpu > 0,
        default_cpu: offered_cpu,
        default_memory_mb: inv.offered.memory_mb.min(inv.memory_mb),
    })
}

/// WSL's networking mode from `wslinfo --networking-mode`.
pub fn parse_networking_mode(output: &str) -> NetworkingMode {
    match output.trim().to_ascii_lowercase().as_str() {
        "" => NetworkingMode::Unknown,
        "nat" => NetworkingMode::Nat,
        "mirrored" => NetworkingMode::Mirrored,
        _ => NetworkingMode::Other,
    }
}

/// How the elevated install ended, from [`INSTALL_WSL_SCRIPT`]'s output.
pub fn parse_install_output(output: &str) -> WslInstall {
    let line = output
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("exit=") || *l == "declined");
    match line.and_then(|l| l.strip_prefix("exit=")).map(|c| c.parse::<i32>()) {
        Some(Ok(0)) => WslInstall::Installed,
        Some(Ok(code)) if REBOOT_CODES.contains(&code) => WslInstall::RebootRequired,
        Some(Ok(code)) => WslInstall::Failed { exit_code: Some(code) },
        Some(Err(_)) | None => WslInstall::Failed { exit_code: None },
    }
}

/// What `p2pc-server init --owner-device` printed: `OWNER DEVICE: <id>` and `SERVER ADDRESS: <address>`.
pub fn parse_init_output(output: &str) -> Option<HubInit> {
    let field = |key: &str| {
        output
            .lines()
            .find_map(|l| l.trim().strip_prefix(key))
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    Some(HubInit {
        owner_device_id: field("OWNER DEVICE:")?,
        server_address: field("SERVER ADDRESS:")?,
    })
}

/// The `SERVER ADDRESS:` line of `p2pc-server info`.
pub fn parse_server_address(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|l| l.trim().strip_prefix("SERVER ADDRESS:"))
        .map(|v| v.trim().to_owned())
        .filter(|v| v.starts_with("p2pc_srv_"))
}

/// An iroh NodeId as `init --owner-device` takes it: 64 lowercase hex characters.
pub fn is_node_id(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `server.toml` with `[blobs] blobs_quota_mb` set. Every other key is kept. Refused (`None`) when the text is not
/// TOML, or when the file's `max_blob_mb` is above the new quota (the hub would refuse to start).
pub fn with_blobs_quota(server_toml: &str, quota_mb: u64) -> Option<String> {
    let mut table: toml::Table = server_toml.parse().ok()?;
    let blobs = table
        .entry("blobs")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()?;
    if let Some(max_blob) = blobs.get("max_blob_mb") {
        let max_blob = max_blob.as_integer()?;
        if u64::try_from(max_blob).ok()? > quota_mb {
            return None;
        }
    }
    blobs.insert(
        "blobs_quota_mb".into(),
        toml::Value::Integer(i64::try_from(quota_mb).ok()?),
    );
    Some(table.to_string())
}

/// The value of `p2pc-agent share set --gpu` for the Share step's on/off switch. The agent takes `all`, `none` or a
/// list of GPU UUIDs (`GpuShare`), not a boolean: "on" offers every GPU the node can serve, "off" none.
pub fn gpu_share_arg(gpu: bool) -> &'static str {
    if gpu { "all" } else { "none" }
}

/// `p2pc-agent share set …` (§8.4) for a share.
pub fn share_set_command(share: &ShareRecord) -> Vec<String> {
    [
        AGENT_BIN,
        "--config",
        AGENT_CONFIG,
        "share",
        "set",
        "--cpu",
        &share.cpu.to_string(),
        "--memory-mb",
        &share.memory_mb.to_string(),
        "--gpu",
        gpu_share_arg(share.gpu),
        "--disk-mb",
        &share.disk_mb.to_string(),
        "--volumes-mb",
        &share.volumes_mb.to_string(),
    ]
    .map(String::from)
    .to_vec()
}

/// The real host.
pub struct WslHost<R, P> {
    runner: R,
    pause: P,
    fetch: Box<dyn RangeFetch + Send + Sync>,
    run_once: Box<dyn RunKey + Send + Sync>,
    layout: Layout,
    /// The image this app build is pinned to; `None` in a build without one (download: `not_available`).
    pin: Option<ImagePin>,
    /// The app's own executable, for the `RunOnce` entry.
    exe: Option<PathBuf>,
    /// `%SystemRoot%`, for the task's `conhost.exe`.
    system_root: PathBuf,
}

impl<R, P> std::fmt::Debug for WslHost<R, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WslHost")
            .field("layout", &self.layout)
            .field("pin", &self.pin)
            .finish_non_exhaustive()
    }
}

/// What [`WslHost::new`] needs.
#[allow(missing_debug_implementations)] // Holds trait objects; `WslHost` has its own `Debug`.
pub struct WslHostParts<R, P> {
    pub runner: R,
    pub pause: P,
    pub fetch: Box<dyn RangeFetch + Send + Sync>,
    pub run_once: Box<dyn RunKey + Send + Sync>,
    pub layout: Layout,
    pub pin: Option<ImagePin>,
    pub exe: Option<PathBuf>,
    pub system_root: PathBuf,
}

impl<R: CommandRunner, P: Pause> WslHost<R, P> {
    pub fn new(parts: WslHostParts<R, P>) -> Self {
        Self {
            runner: parts.runner,
            pause: parts.pause,
            fetch: parts.fetch,
            run_once: parts.run_once,
            layout: parts.layout,
            pin: parts.pin,
            exe: parts.exe,
            system_root: parts.system_root,
        }
    }

    fn host(&self) -> Host<'_> {
        Host::new(&self.runner, &self.pause)
    }

    fn image_path(&self) -> PathBuf {
        self.layout.images_dir().join(IMAGE_FILE)
    }

    /// A command in the distro, with the retry and [`IN_DISTRO_TIMEOUT`].
    fn run_in_distro(&self, command: &[&str], stdin: Option<Vec<u8>>) -> Option<p2pc_wsl::runner::Output> {
        let mut inv: Invocation = in_distro(command).timeout(IN_DISTRO_TIMEOUT);
        if let Some(bytes) = stdin {
            inv = inv.stdin(bytes);
        }
        self.host().run_wsl(&inv).ok()
    }

    /// `true` when the command ran and exited 0.
    fn ok_in_distro(&self, command: &[&str]) -> bool {
        self.run_in_distro(command, None).is_some_and(|o| o.success())
    }

    /// The agent's config file exists (created empty and 0600 when missing, as `p2pc-run` does): the agent refuses a
    /// named config file that does not exist.
    fn ensure_agent_config(&self) -> bool {
        self.ok_in_distro(&["/usr/bin/test", "-e", AGENT_CONFIG])
            || self.ok_in_distro(&["/usr/bin/install", "-m", "0600", "/dev/null", AGENT_CONFIG])
    }

    fn task_context(&self) -> Result<TaskContext, SetupError> {
        let identity = task::current_identity(self.host()).map_err(|_| {
            SetupError::with_detail(
                SetupErrorCode::ImportFailed,
                "the Windows user could not be read for the task",
            )
        })?;
        Ok(TaskContext {
            system_root: self.system_root.clone(),
            identity,
            start_boundary: task::start_boundary(SystemTime::now()),
        })
    }

    fn hub_failed(detail: &str) -> SetupError {
        SetupError::with_detail(SetupErrorCode::HubFailed, detail)
    }
}

impl<R: CommandRunner + Send + Sync, P: Pause + Send + Sync> SetupHost for WslHost<R, P> {
    fn checks(&self) -> Result<ChecksReport, SetupError> {
        run_checks(self.host(), &self.layout.distro_dir(), Thresholds::default())
            .map_err(|_| SetupError::with_detail(SetupErrorCode::ChecksFailed, "the system checks could not run"))
    }

    fn free_bytes(&self) -> Result<u64, SetupError> {
        match self.checks()?.disk {
            DiskState::Free(bytes) => Ok(bytes),
            DiskState::NotLocal | DiskState::Unknown => Err(SetupError::with_detail(
                SetupErrorCode::ChecksFailed,
                "the free space on your drive could not be read",
            )),
        }
    }

    fn install_wsl(&self) -> WslInstall {
        match self
            .host()
            .run(&powershell(INSTALL_WSL_SCRIPT).timeout(WSL_INSTALL_TIMEOUT))
        {
            Ok(out) => parse_install_output(&out.stdout_text()),
            Err(_) => WslInstall::Failed { exit_code: None },
        }
    }

    fn reopen_after_reboot(&self) -> Result<(), SetupError> {
        let unusable = || SetupError::new(SetupErrorCode::WslInstallFailed);
        let exe = self.exe.as_deref().ok_or_else(unusable)?;
        let line = open_command_line(exe).map_err(|_| unusable())?;
        self.run_once.set(RUN_VALUE_NAME, &line).map_err(|_| unusable())
    }

    fn download_image(&self, progress: &mut dyn FnMut(Progress) -> ControlFlow<()>) -> Result<(), SetupError> {
        let pin = self
            .pin
            .as_ref()
            .ok_or_else(|| SetupError::new(SetupErrorCode::NotAvailable))?;
        download_image(self.fetch.as_ref(), pin, &self.image_path(), progress)
            .map(|_| ())
            .map_err(|e| from_image_error(&e))
    }

    fn install_distro(&self) -> Result<String, SetupError> {
        let pin = self
            .pin
            .as_ref()
            .ok_or_else(|| SetupError::new(SetupErrorCode::NotAvailable))?;
        let image = verify_image(&self.image_path(), pin.sha256()).map_err(|e| from_image_error(&e))?;
        let installed = import::install(self.host(), &self.layout, &image).map_err(|e| from_import_error(&e))?;
        let ctx = self.task_context()?;
        // Disabled: an agent started before it joined would stop for good (exit 8) and `p2pc-run` would not start it
        // again. Step 4 enables and starts the task once there is a cloud.
        task::register(self.host(), &self.layout, &ctx, false).map_err(|_| {
            SetupError::with_detail(
                SetupErrorCode::ImportFailed,
                "the scheduled task could not be registered",
            )
        })?;
        Ok(installed.image_version)
    }

    fn node_facts(&self) -> Result<NodeFacts, SetupError> {
        let unreadable = || {
            SetupError::with_detail(
                SetupErrorCode::DistroUnhealthy,
                "the node could not report its hardware",
            )
        };
        if !self.ensure_agent_config() {
            return Err(unreadable());
        }
        let out = self
            .run_in_distro(&[AGENT_BIN, "--config", AGENT_CONFIG, "inventory", "--json"], None)
            .filter(|o| o.success())
            .ok_or_else(unreadable)?;
        parse_inventory(&out.stdout_text()).ok_or_else(unreadable)
    }

    fn networking_mode(&self) -> NetworkingMode {
        match self.run_in_distro(&[WSLINFO, "--networking-mode"], None) {
            Some(out) if out.success() => parse_networking_mode(&out.stdout_text()),
            _ => NetworkingMode::Unknown,
        }
    }

    fn apply_share(&self, share: &ShareRecord) -> Result<(), SetupError> {
        if !self.ensure_agent_config() {
            return Err(SetupError::with_detail(
                SetupErrorCode::ShareFailed,
                "the agent's config file could not be created",
            ));
        }
        let command = share_set_command(share);
        let args: Vec<&str> = command.iter().map(String::as_str).collect();
        match self.run_in_distro(&args, None) {
            Some(out) if out.success() => Ok(()),
            Some(out) => Err(SetupError::with_detail(
                SetupErrorCode::ShareFailed,
                format!("p2pc-agent share set ended with exit code {}", out.code.unwrap_or(-1)),
            )),
            None => Err(SetupError::with_detail(
                SetupErrorCode::ShareFailed,
                "p2pc-agent could not run",
            )),
        }
    }

    fn hub_initialised(&self) -> Result<bool, SetupError> {
        match self.run_in_distro(&["/usr/bin/test", "-e", SERVER_TOML], None) {
            Some(out) if out.code == Some(0) => Ok(true),
            Some(out) if out.code == Some(1) => Ok(false),
            _ => Err(Self::hub_failed("the hub's data dir could not be checked")),
        }
    }

    fn init_hub(&self, owner_node_id: &str, label: &str) -> Result<HubInit, SetupError> {
        if !is_node_id(owner_node_id) {
            return Err(Self::hub_failed("this app's device NodeId is not valid"));
        }
        let out = self
            .run_in_distro(
                &[
                    SERVER_BIN,
                    "init",
                    "--data-dir",
                    HUB_DIR,
                    "--owner-device",
                    owner_node_id,
                    "--label",
                    label,
                ],
                None,
            )
            .ok_or_else(|| Self::hub_failed("p2pc-server init could not run"))?;
        if !out.success() {
            return Err(SetupError::with_detail(
                SetupErrorCode::HubFailed,
                format!("p2pc-server init ended with exit code {}", out.code.unwrap_or(-1)),
            ));
        }
        parse_init_output(&out.stdout_text()).ok_or_else(|| Self::hub_failed("p2pc-server init printed no address"))
    }

    fn hub_address(&self) -> Result<String, SetupError> {
        self.run_in_distro(&[SERVER_BIN, "info", "--config", SERVER_TOML], None)
            .filter(|o| o.success())
            .and_then(|o| parse_server_address(&o.stdout_text()))
            .ok_or_else(|| Self::hub_failed("the hub's address could not be read"))
    }

    fn set_blobs_quota(&self, quota_mb: u64) -> Result<(), SetupError> {
        let current = self
            .run_in_distro(&["/bin/cat", SERVER_TOML], None)
            .filter(|o| o.success())
            .ok_or_else(|| Self::hub_failed("the hub's server.toml could not be read"))?;
        let updated = with_blobs_quota(&current.stdout_text(), quota_mb)
            .ok_or_else(|| Self::hub_failed("the hub's server.toml could not be updated"))?;
        let written = self
            .run_in_distro(
                &["/usr/bin/dd", &format!("of={SERVER_TOML_TEMP}"), "status=none"],
                Some(updated.into_bytes()),
            )
            .is_some_and(|o| o.success())
            && self.ok_in_distro(&["/bin/chmod", "0600", SERVER_TOML_TEMP])
            && self.ok_in_distro(&["/bin/mv", "-f", SERVER_TOML_TEMP, SERVER_TOML]);
        if written {
            Ok(())
        } else {
            let _ = self.run_in_distro(&["/bin/rm", "-f", SERVER_TOML_TEMP], None);
            Err(Self::hub_failed("the hub's server.toml could not be written"))
        }
    }

    fn enable_hub(&self) -> Result<(), SetupError> {
        if !self.ok_in_distro(&["/usr/bin/touch", HUB_FLAG]) {
            return Err(Self::hub_failed("hub.enabled could not be written"));
        }
        task::resume(self.host()).map_err(|_| Self::hub_failed("the scheduled task could not be started"))
    }

    fn join_agent(&self, token: &JoinToken) -> JoinResult {
        if !self.ensure_agent_config() {
            return JoinResult::Failed { exit_code: None };
        }
        // The token goes on stdin (H1 §7), never on the command line; the runner refuses one there anyway.
        // Sized once, so no reallocation leaves an un-wiped copy behind; the runner wipes this buffer when dropped.
        let secret = token.expose().as_bytes();
        let mut stdin = Vec::with_capacity(secret.len() + 1);
        stdin.extend_from_slice(secret);
        stdin.push(b'\n');
        match self.run_in_distro(&[AGENT_BIN, "--config", AGENT_CONFIG, "join", "-"], Some(stdin)) {
            None => JoinResult::Failed { exit_code: None },
            Some(out) => match out.code {
                Some(0) => JoinResult::Joined,
                Some(AGENT_ALREADY_ENROLLED) => JoinResult::AlreadyEnrolled,
                Some(AGENT_INVALID_TOKEN | AGENT_TOKEN_EXPIRED) => JoinResult::Rejected,
                code => JoinResult::Failed { exit_code: code },
            },
        }
    }

    fn restart_node(&self) -> Result<(), SetupError> {
        // Best effort: what could not be stopped is started again below anyway.
        let _ = task::suspend(self.host());
        task::resume(self.host()).map_err(|_| Self::hub_failed("the scheduled task could not be started"))
    }
}

#[cfg(test)]
#[path = "wsl_host_tests.rs"]
mod tests;
