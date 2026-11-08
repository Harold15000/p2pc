// SPDX-License-Identifier: Apache-2.0

//! Platform profiles (spec §9.0): which one this machine is, and whether it meets that profile's requirements.
//!
//! The agent only detects and reports. It never installs or fixes anything; `p2pc-agent doctor` prints a hint for
//! each problem instead.

use p2pc_proto::api::{Platform, SandboxClass};
use serde::Serialize;

use crate::config::Runtime;
use crate::host::Host;
use crate::parse::{self, PodmanInfo};

/// Oldest supported Podman (§9 "The node needs").
pub const MIN_PODMAN: (u64, u64) = (4, 9);
/// Smallest `containers` subordinate ID range for `--userns=auto` on WSL2 (§9.0).
pub const MIN_SUBID_RANGE: u64 = 65_536;
/// cgroup controllers the rootless Linux profile needs delegated.
pub const REQUIRED_CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];

/// Paths a WSL distro has and a Linux container on a WSL2 kernel has not: the per-distro runtime directory of WSL's
/// init, the libraries WSL mounts into each distro, and the distro's own `wsl.conf`.
pub const WSL_DISTRO_MARKERS: [&str; 3] = ["/run/WSL", "/usr/lib/wsl", "/etc/wsl.conf"];

/// `wsl2` when this is a **WSL distro**: a WSL kernel (`/proc/version` mentions `microsoft` or `WSL`) **and** a distro
/// marker: `WSL_DISTRO_NAME` in the environment, or one of [`WSL_DISTRO_MARKERS`]. Otherwise `linux`.
///
/// The kernel alone is not enough (T14b2 real run): a Linux container running on a WSL2 kernel (Docker Desktop, a
/// CI runner) has that kernel string and none of the distro's setup, and its profile is native Linux. The
/// `WSLInterop` binfmt entry is no marker either: it is shared by the whole WSL VM (§9.0).
#[must_use]
pub fn detect(host: &Host) -> Platform {
    let wsl_kernel = host.read("/proc/version").is_ok_and(|v| parse::proc_version_is_wsl(&v));
    let distro = host.has_wsl_distro_env() || WSL_DISTRO_MARKERS.iter().any(|m| host.exists(m));
    if wsl_kernel && distro {
        Platform::Wsl2
    } else {
        Platform::Linux
    }
}

/// The `binfmt_misc` entries WSL registers for Windows interop.
const INTEROP_ENTRIES: [&str; 2] = ["WSLInterop", "WSLInterop-late"];

/// Whether a `WSLInterop` / `WSLInterop-late` entry is registered and enabled in `binfmt_misc`.
///
/// **Only a note** (spec §9.0 "Windows interop", amended after the T05b real run): `binfmt_misc` is shared by every
/// distro of the WSL VM, so the entry is there whenever another distro keeps interop on, which is nearly every
/// developer PC, and it cannot be removed per distro. The real signals are in [`SandboxFacts`].
#[must_use]
pub fn binfmt_interop_visible(host: &Host) -> bool {
    INTEROP_ENTRIES.iter().any(|name| {
        host.read(format!("/proc/sys/fs/binfmt_misc/{name}"))
            .is_ok_and(|t| parse::binfmt_enabled(&t))
    })
}

/// The note `doctor` shows for [`binfmt_interop_visible`], worded like `test-distro.sh`'s INFO line.
pub const BINFMT_INTEROP_NOTE: &str = "the WSLInterop binfmt entry is visible, because binfmt_misc is shared by all \
     distros of the WSL VM and other distros keep interop on; it cannot be removed per distro. This distro is \
     protected by interop=false (wsl.conf), no WSL_INTEROP, and no Windows PATH.";

/// The state of an external tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Tool {
    /// It ran.
    Available {
        /// Its version, when it could be read.
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
    /// It is not installed. Not an error: the inventory reports it.
    Unavailable,
    /// It exists but failed.
    Failed {
        /// The first line of its error output, or the run error.
        reason: String,
    },
}

impl Tool {
    /// Whether it ran.
    #[must_use]
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// Its version, if it ran and printed one.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        match self {
            Self::Available { version } => version.as_deref(),
            _ => None,
        }
    }
}

/// What Podman said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PodmanFacts {
    /// `podman version`.
    pub tool: Tool,
    /// `podman info`, when it worked.
    #[serde(skip)]
    pub info: Option<PodmanInfo>,
    /// Why `podman info` failed, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info_error: Option<String>,
}

/// What systemd delegates to a user manager, and where that was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegated {
    /// The controllers, in the order they were read.
    pub controllers: Vec<String>,
    /// What was read: a `cgroup.controllers` path, or the `systemctl` command.
    pub source: String,
}

/// The systemd user manager (`user@<uid>.service`) the agent runs under: where cgroup delegation is decided (T10j).
///
/// Delegation is read here and not from the agent's own cgroup, because systemd turns a controller on in a
/// sub-cgroup (`app.slice`, the agent's unit) only when some unit there asks for it; the containers Podman starts
/// get their own scopes, for which `user@` delegates the controller on demand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserManager {
    /// The UID in the unit's name.
    pub uid: u32,
    /// What the unit delegates, when it could be read.
    pub delegated: Option<Delegated>,
}

impl UserManager {
    /// The unit's name, `user@<uid>.service`.
    #[must_use]
    pub fn unit(&self) -> String {
        format!("user@{}.service", self.uid)
    }
}

/// Where systemd shows the controllers `user@<uid>.service` has (a running unit's cgroup).
fn controllers_file(cgroup_path: &str) -> String {
    format!("/sys/fs/cgroup{cgroup_path}/cgroup.controllers")
}

/// The user manager above the agent's own cgroup (`/proc/self/cgroup`) and its `cgroup.controllers`, as
/// `setup-host.sh` reads them. `None` when the agent is not under a `user@<uid>.service`. When the file cannot be
/// read, `delegated` is `None`: ask `systemctl` next ([`Delegated::from_systemctl`]).
///
/// Blocking: reads files.
#[must_use]
pub fn read_user_manager(host: &Host) -> Option<UserManager> {
    let own = host.read("/proc/self/cgroup").ok()?;
    let cgroup = parse::user_manager_cgroup(&own)?;
    let file = controllers_file(&cgroup.path);
    let delegated = host.read(&file).ok().map(|text| Delegated {
        controllers: parse::controller_words(&text),
        source: file,
    });
    Some(UserManager {
        uid: cgroup.uid,
        delegated,
    })
}

impl Delegated {
    /// The controllers in the output of `systemctl show user@<uid>.service --property=DelegateControllers --value`.
    #[must_use]
    pub fn from_systemctl(uid: u32, stdout: &str) -> Self {
        Self {
            controllers: parse::controller_words(stdout),
            source: format!("systemctl show user@{uid}.service --property=DelegateControllers"),
        }
    }
}

/// Everything the §9.0 checks look at.
#[derive(Debug, Clone)]
pub struct SandboxFacts {
    /// The agent's effective UID.
    pub euid: Option<u32>,
    /// Podman.
    pub podman: PodmanFacts,
    /// Whether the unified cgroup v2 hierarchy is mounted (`/sys/fs/cgroup/cgroup.controllers`).
    pub cgroup_v2_mounted: bool,
    /// The `user@<uid>.service` above the agent, if any (T10j): the source of truth for cgroup delegation on the
    /// Linux profile. Without one, `podman info` is.
    pub user_manager: Option<UserManager>,
    /// `/etc/subuid`, if readable.
    pub subuid: Option<String>,
    /// `/etc/subgid`, if readable.
    pub subgid: Option<String>,
    /// Windows filesystems mounted in the distro: 9p and drvfs mounts (and drive letters over virtiofs), except the
    /// read-only `/usr/lib/wsl/drivers` ([`parse::windows_mounts`]).
    pub windows_mounts: Vec<String>,
    /// Whether `WSL_INTEROP` is in the agent's environment.
    pub wsl_interop_env: bool,
    /// `/etc/wsl.conf`, if readable. Missing means interop is on (WSL's defaults).
    pub wsl_conf: Option<String>,
    /// The agent's `PATH` entries under `/mnt/` (Windows directories).
    pub windows_path: Vec<String>,
    /// The VM-wide `WSLInterop` binfmt entry: a note only ([`binfmt_interop_visible`]).
    pub binfmt_interop: bool,
    /// The configured OCI runtime.
    pub runtime: Runtime,
    /// Whether that runtime's binary ran.
    pub runtime_tool: Tool,
}

/// One unmet requirement, with how to fix it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    /// Stable identifier, for example `podman_not_found`.
    pub code: &'static str,
    /// What is wrong on this machine.
    pub detail: String,
    /// How the owner can fix it. The agent never applies it.
    pub hint: String,
}

impl Problem {
    pub(crate) fn new(code: &'static str, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            hint: hint.into(),
        }
    }

    /// The form sent in the inventory: `<code>: <detail>`.
    #[must_use]
    pub fn wire(&self) -> String {
        format!("{}: {}", self.code, self.detail)
    }
}

/// The sandbox class the configured runtime provides (§9 "Optional gVisor").
#[must_use]
pub fn sandbox_class(runtime: Runtime) -> SandboxClass {
    match runtime {
        Runtime::Crun => SandboxClass::Container,
        Runtime::Runsc => SandboxClass::ContainerGvisor,
    }
}

/// Checks the §9.0 requirements of `platform`. An empty list means ready.
#[must_use]
pub fn check(platform: Platform, f: &SandboxFacts) -> Vec<Problem> {
    let mut problems = Vec::new();
    match platform {
        Platform::Linux => check_linux_user(f, &mut problems),
        Platform::Wsl2 => check_wsl2_host(f, &mut problems),
    }
    check_podman(platform, f, &mut problems);
    check_runtime(f, &mut problems);
    problems
}

fn check_linux_user(f: &SandboxFacts, out: &mut Vec<Problem>) {
    match f.euid {
        Some(0) => out.push(Problem::new(
            "running_as_root",
            "the agent runs as root, but the Linux profile is rootless",
            "run the agent as the unprivileged `p2pc` user (its systemd user service), never as root",
        )),
        Some(_) => {}
        None => out.push(Problem::new(
            "uid_unknown",
            "cannot read the agent's UID from /proc/self/status",
            "check that /proc is mounted",
        )),
    }
}

fn check_wsl2_host(f: &SandboxFacts, out: &mut Vec<Problem>) {
    if f.euid != Some(0) {
        out.push(Problem::new(
            "not_root",
            "on WSL2 the agent must run as root inside the dedicated distro",
            "run the agent as root inside the `p2pc-node` distro (the installer's service does this)",
        ));
    }
    for (file, text) in [("/etc/subuid", &f.subuid), ("/etc/subgid", &f.subgid)] {
        let range = text.as_deref().and_then(|t| parse::subid_range(t, "containers"));
        if range.is_none_or(|r| r < MIN_SUBID_RANGE) {
            let found = range.map_or_else(|| "none".to_string(), |r| r.to_string());
            out.push(Problem::new(
                if file == "/etc/subuid" {
                    "subuid_range_missing"
                } else {
                    "subgid_range_missing"
                },
                format!("{file} needs a `containers` range of at least {MIN_SUBID_RANGE} IDs (found: {found})"),
                format!("add the line `containers:2147483647:2147483648` to {file}"),
            ));
        }
    }
    // §9.0 "Windows interop": off, and checked. Any of these makes the node not ready; the VM-wide binfmt entry does
    // not (it is a note in doctor).
    if !f.windows_mounts.is_empty() {
        out.push(Problem::new(
            "windows_mounts",
            format!(
                "Windows filesystems are mounted (9p or drvfs): {}",
                f.windows_mounts.join(", ")
            ),
            "set `[automount] enabled=false` in /etc/wsl.conf, then `wsl --terminate p2pc-node`",
        ));
    }
    if f.wsl_interop_env {
        out.push(Problem::new(
            "interop_env",
            "WSL_INTEROP is set in the agent's environment",
            "start the agent from the distro's service, never from a shell that has Windows interop",
        ));
    }
    let conf = |key| {
        f.wsl_conf
            .as_deref()
            .and_then(|t| parse::ini_get(t, "interop", key))
            .is_some_and(|v| v.eq_ignore_ascii_case("false"))
    };
    if !conf("enabled") {
        out.push(Problem::new(
            "interop_enabled",
            "/etc/wsl.conf does not set `[interop] enabled=false` (a missing file or key means interop is on)",
            "set `[interop] enabled=false` in /etc/wsl.conf, then `wsl --terminate p2pc-node`",
        ));
    }
    if !conf("appendWindowsPath") {
        out.push(Problem::new(
            "windows_path_appended",
            "/etc/wsl.conf does not set `[interop] appendWindowsPath=false` (a missing key means Windows directories \
             are added to PATH)",
            "set `[interop] appendWindowsPath=false` in /etc/wsl.conf, then `wsl --terminate p2pc-node`",
        ));
    }
    if !f.windows_path.is_empty() {
        out.push(Problem::new(
            "windows_path",
            format!("PATH has Windows entries: {}", f.windows_path.join(":")),
            "remove the /mnt/ entries from the agent's PATH (set `appendWindowsPath=false`, then restart the distro)",
        ));
    }
}

fn check_podman(platform: Platform, f: &SandboxFacts, out: &mut Vec<Problem>) {
    let install = match platform {
        Platform::Linux => "install Podman 4.9 or later from your distribution",
        Platform::Wsl2 => "reinstall the `p2pc-node` distro, which ships Podman",
    };
    match &f.podman.tool {
        Tool::Unavailable => out.push(Problem::new("podman_not_found", "podman is not installed", install)),
        Tool::Failed { reason } => out.push(Problem::new(
            "podman_error",
            format!("`podman version` failed: {reason}"),
            "run `podman version` to see the full error",
        )),
        Tool::Available { version } => {
            let (major, minor) = MIN_PODMAN;
            let ok = version
                .as_deref()
                .and_then(|v| parse::version_at_least(v, major, minor));
            if ok != Some(true) {
                out.push(Problem::new(
                    "podman_too_old",
                    format!(
                        "Podman {} is older than {major}.{minor}",
                        version.as_deref().unwrap_or("(unknown version)")
                    ),
                    install,
                ));
            }
        }
    }
    let cgroup_v2 = f
        .podman
        .info
        .as_ref()
        .and_then(|i| i.cgroup_version.as_deref())
        .map_or(f.cgroup_v2_mounted, |v| v == "v2");
    if !cgroup_v2 {
        out.push(Problem::new(
            "cgroup_v1",
            "the unified cgroup v2 hierarchy is not in use",
            "boot with cgroup v2 only (`systemd.unified_cgroup_hierarchy=1`)",
        ));
    }
    if !f.podman.tool.is_available() {
        return;
    }
    let Some(info) = &f.podman.info else {
        out.push(Problem::new(
            "podman_info_failed",
            format!(
                "`podman info` failed: {}",
                f.podman.info_error.as_deref().unwrap_or("no output")
            ),
            "run `podman info` to see the full error",
        ));
        return;
    };
    match platform {
        Platform::Linux => {
            if info.rootless != Some(true) {
                out.push(Problem::new(
                    "podman_not_rootless",
                    "`podman info` does not report a rootless setup",
                    "run the agent as the unprivileged `p2pc` user so that Podman runs rootless",
                ));
            }
            check_delegation(f, info, out);
        }
        Platform::Wsl2 => {
            if info.cgroup_manager.as_deref() != Some("cgroupfs") {
                out.push(Problem::new(
                    "cgroup_manager_not_cgroupfs",
                    format!(
                        "Podman's cgroup manager is {}, not cgroupfs",
                        info.cgroup_manager.as_deref().unwrap_or("unknown")
                    ),
                    "set `cgroup_manager = \"cgroupfs\"` under [engine] in /etc/containers/containers.conf, \
                     and `systemd=false` under [boot] in /etc/wsl.conf",
                ));
            }
        }
    }
}

/// The fix `setup-host.sh` prints, for a user manager that lacks controllers; the agent never applies it.
fn delegation_fix(uid: u32) -> String {
    format!(
        "as root, write `[Service]\\nDelegate=cpu cpuset io memory pids` to \
         /etc/systemd/system/user@.service.d/p2pc-delegate.conf (mkdir -p its directory first), run \
         `systemctl daemon-reload && systemctl restart user@{uid}.service` (or reboot), then restart the agent: it \
         checks its sandbox when it starts"
    )
}

/// The rootless Linux profile needs [`REQUIRED_CONTROLLERS`] delegated (T10j).
///
/// Read where systemd delegates them, `user@<uid>.service`, not from the agent's own cgroup: systemd turns a
/// controller on in `app.slice` and in the agent's unit only when a unit there asks for it, but Podman's container
/// scopes get theirs from `user@` on demand. So `podman info` (which reports the agent's own cgroup) says `memory
/// pids` on a node that is fine. `podman info` decides only without a `user@` ancestor, or when the unit's
/// delegation could not be read at all.
fn check_delegation(f: &SandboxFacts, info: &PodmanInfo, out: &mut Vec<Problem>) {
    let manager = f.user_manager.as_ref();
    let delegated = manager.and_then(|m| m.delegated.as_ref());
    let (have, read) = match delegated {
        Some(d) => (&d.controllers, d.source.as_str()),
        None => (&info.cgroup_controllers, "`podman info` (cgroupControllers)"),
    };
    let missing: Vec<&str> = REQUIRED_CONTROLLERS
        .into_iter()
        .filter(|c| !have.iter().any(|h| h == c))
        .collect();
    if missing.is_empty() {
        return;
    }
    let missing = missing.join(", ");
    let have = if have.is_empty() {
        "nothing".to_string()
    } else {
        have.join(" ")
    };
    let (detail, fix) = match (manager, delegated) {
        (Some(m), Some(_)) => (
            format!(
                "cgroup controllers not delegated to this user: {missing} ({} delegates: {have}; read from {read})",
                m.unit(),
            ),
            delegation_fix(m.uid),
        ),
        _ => (
            format!("cgroup controllers not delegated to this user: {missing} (read from {read}: {have})"),
            "delegate them to the user's systemd instance (`Delegate=cpu cpuset io memory pids` in a \
             user@.service.d drop-in), run `loginctl enable-linger p2pc`, then restart the agent: it checks its \
             sandbox when it starts"
                .to_string(),
        ),
    };
    out.push(Problem::new(
        "cgroup_not_delegated",
        format!("{detail}. Fix: {fix}"),
        fix,
    ));
}

fn check_runtime(f: &SandboxFacts, out: &mut Vec<Problem>) {
    match (&f.runtime_tool, f.runtime) {
        (Tool::Available { .. }, _) => {}
        (Tool::Unavailable, Runtime::Crun) => out.push(Problem::new(
            "runtime_not_found",
            "the OCI runtime crun is not installed",
            "install crun (Podman's default runtime on most distributions)",
        )),
        (Tool::Unavailable, Runtime::Runsc) => out.push(Problem::new(
            "runtime_not_found",
            "the config asks for runtime = \"runsc\", but gVisor's runsc is not installed",
            "install gVisor (runsc), or set runtime = \"crun\" in agent.toml",
        )),
        (Tool::Failed { reason }, rt) => out.push(Problem::new(
            "runtime_error",
            format!("`{rt} --version` failed: {reason}"),
            format!("run `{rt} --version` to see the full error"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/", $name))
        };
    }

    fn podman(info: &str) -> PodmanFacts {
        PodmanFacts {
            tool: Tool::Available {
                version: Some("4.9.3".into()),
            },
            info: parse::podman_info(info),
            info_error: None,
        }
    }

    fn good_linux() -> SandboxFacts {
        SandboxFacts {
            euid: Some(1001),
            podman: podman(fixture!("podman-info-rootless.json")),
            cgroup_v2_mounted: true,
            user_manager: None,
            subuid: None,
            subgid: None,
            windows_mounts: Vec::new(),
            wsl_interop_env: false,
            wsl_conf: None,
            windows_path: Vec::new(),
            binfmt_interop: false,
            runtime: Runtime::Crun,
            runtime_tool: Tool::Available {
                version: Some("1.14.1".into()),
            },
        }
    }

    fn good_wsl2() -> SandboxFacts {
        let ids = "containers:2147483647:2147483648\n".to_string();
        SandboxFacts {
            euid: Some(0),
            podman: podman(fixture!("podman-info-wsl.json")),
            subuid: Some(ids.clone()),
            subgid: Some(ids),
            wsl_conf: Some("[interop]\nenabled=false\nappendWindowsPath=false\n".into()),
            // VM-wide, shared with the other distros: a note, never a problem (§9.0).
            binfmt_interop: true,
            ..good_linux()
        }
    }

    fn codes(platform: Platform, f: &SandboxFacts) -> Vec<&'static str> {
        check(platform, f).iter().map(|p| p.code).collect()
    }

    #[test]
    fn detects_wsl_and_native() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("proc/sys/fs/binfmt_misc")).unwrap();
        let host = Host::with_root(dir.path());
        assert_eq!(detect(&host), Platform::Linux, "nothing readable: native");
        fs::write(dir.path().join("proc/version"), fixture!("proc-version-linux.txt")).unwrap();
        assert_eq!(detect(&host), Platform::Linux);
        fs::write(dir.path().join("proc/sys/fs/binfmt_misc/WSLInterop"), "enabled\n").unwrap();
        assert_eq!(detect(&host), Platform::Linux, "the VM-wide interop entry is no marker");
        fs::write(dir.path().join("proc/version"), fixture!("proc-version-wsl.txt")).unwrap();
        // T14b2 real run: a Linux container on a WSL2 kernel has the kernel string and nothing of a distro.
        assert_eq!(
            detect(&host),
            Platform::Linux,
            "a container on a WSL2 kernel is native Linux"
        );
        assert_eq!(
            detect(&host.clone().wsl_distro_env(true)),
            Platform::Wsl2,
            "WSL_DISTRO_NAME"
        );
        for marker in WSL_DISTRO_MARKERS {
            let path = dir.path().join(marker.trim_start_matches('/'));
            fs::create_dir_all(&path).unwrap();
            assert_eq!(detect(&host), Platform::Wsl2, "{marker}");
            fs::remove_dir(&path).unwrap();
        }
        // A marker without the WSL kernel is not WSL either.
        fs::write(dir.path().join("proc/version"), fixture!("proc-version-linux.txt")).unwrap();
        fs::create_dir_all(dir.path().join("run/WSL")).unwrap();
        assert_eq!(detect(&host), Platform::Linux);
    }

    #[test]
    fn ready_profiles_have_no_problems() {
        assert_eq!(check(Platform::Linux, &good_linux()), []);
        assert_eq!(check(Platform::Wsl2, &good_wsl2()), []);
    }

    #[test]
    fn linux_profile_problems() {
        let with = |f: &dyn Fn(&mut SandboxFacts)| {
            let mut facts = good_linux();
            f(&mut facts);
            codes(Platform::Linux, &facts)
        };
        assert_eq!(with(&|f| f.euid = Some(0)), ["running_as_root"]);
        assert_eq!(with(&|f| f.euid = None), ["uid_unknown"]);
        assert_eq!(
            with(&|f| f.podman.info.as_mut().unwrap().rootless = Some(false)),
            ["podman_not_rootless"]
        );
        assert_eq!(
            with(&|f| f.podman.info.as_mut().unwrap().cgroup_controllers = vec!["memory".into()]),
            ["cgroup_not_delegated"]
        );
        let problems = check(Platform::Linux, &{
            let mut f = good_linux();
            f.podman.info.as_mut().unwrap().cgroup_controllers = vec!["memory".into()];
            f
        });
        assert!(problems[0].detail.contains(": cpu, pids ("), "{:?}", problems[0]);
        assert_eq!(
            with(&|f| f.podman.info.as_mut().unwrap().cgroup_version = Some("v1".into())),
            ["cgroup_v1"]
        );
        assert_eq!(
            with(&|f| f.podman = PodmanFacts {
                tool: Tool::Unavailable,
                info: None,
                info_error: None
            }),
            ["podman_not_found"]
        );
        assert_eq!(
            with(&|f| f.podman.tool = Tool::Available {
                version: Some("4.4.1".into())
            }),
            ["podman_too_old"]
        );
        assert_eq!(
            with(&|f| {
                f.podman.info = None;
                f.podman.info_error = Some("cannot set up namespace".into());
            }),
            ["podman_info_failed"]
        );
        assert_eq!(with(&|f| f.runtime_tool = Tool::Unavailable), ["runtime_not_found"]);
        // Linux ignores the WSL-only checks.
        assert_eq!(
            with(&|f| {
                f.windows_mounts = vec!["/mnt/c".into()];
                f.wsl_interop_env = true;
                f.windows_path = vec!["/mnt/c/Windows".into()];
                f.binfmt_interop = true;
            }),
            Vec::<&str>::new()
        );
    }

    /// A fake cgroup tree like the ACC-1 node's (uid 959): the agent in `app.slice/p2pc-agent.service`, `user@`
    /// delegating `user_controllers` (when `Some`), `app.slice` having turned on only `memory pids`.
    fn acc1_machine(user_controllers: Option<&str>) -> (tempfile::TempDir, Host) {
        let dir = tempfile::tempdir().unwrap();
        let w = |p: &str, text: &str| {
            let path = dir.path().join(p.trim_start_matches('/'));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        };
        w(
            "/proc/self/cgroup",
            "0::/user.slice/user-959.slice/user@959.service/app.slice/p2pc-agent.service\n",
        );
        let user = "/sys/fs/cgroup/user.slice/user-959.slice/user@959.service";
        if let Some(c) = user_controllers {
            w(&format!("{user}/cgroup.controllers"), c);
        }
        w(&format!("{user}/cgroup.subtree_control"), "cpu memory pids\n");
        w(&format!("{user}/app.slice/cgroup.controllers"), "cpu memory pids\n");
        w(&format!("{user}/app.slice/cgroup.subtree_control"), "memory pids\n");
        w(
            &format!("{user}/app.slice/p2pc-agent.service/cgroup.controllers"),
            "memory pids\n",
        );
        let host = Host::with_root(dir.path());
        (dir, host)
    }

    /// `good_linux()` on `host`, with `podman info` reporting `podman_controllers` (what the agent's own cgroup has).
    fn linux_on(host: &Host, podman_controllers: &[&str]) -> SandboxFacts {
        let mut f = good_linux();
        f.user_manager = read_user_manager(host);
        f.podman.info.as_mut().unwrap().cgroup_controllers = podman_controllers.iter().map(|c| (*c).into()).collect();
        f
    }

    /// T10j (ACC-1): `user@` delegates cpu, memory and pids; systemd turned on only `memory pids` in `app.slice`, so
    /// `podman info` says `memory pids`. The sandbox is ready: the containers get their own scopes.
    #[test]
    fn delegation_is_read_from_the_user_manager_not_from_the_agents_cgroup() {
        let (_dir, host) = acc1_machine(Some("cpu memory pids\n"));
        let f = linux_on(&host, &["memory", "pids"]);
        let um = f.user_manager.as_ref().expect("user@959.service is above the agent");
        assert_eq!((um.uid, um.unit().as_str()), (959, "user@959.service"));
        assert_eq!(check(Platform::Linux, &f), []);
    }

    /// T10j: `user@` really lacks `cpu`. Not ready; the message names the unit, the file read and the fix, and says to
    /// restart the agent (it checks its sandbox when it starts).
    #[test]
    fn a_controller_user_manager_lacks_is_named_with_the_file_and_the_fix() {
        let (_dir, host) = acc1_machine(Some("memory pids\n"));
        // Even if podman info (wrongly) claimed all three, the user manager decides.
        let f = linux_on(&host, &["cpu", "memory", "pids"]);
        let problems = check(Platform::Linux, &f);
        assert_eq!(problems.len(), 1, "{problems:?}");
        let p = &problems[0];
        assert_eq!(p.code, "cgroup_not_delegated");
        let wire = p.wire();
        for needle in [
            "user@959.service",
            "/sys/fs/cgroup/user.slice/user-959.slice/user@959.service/cgroup.controllers",
            "cpu",
            "Delegate=cpu cpuset io memory pids",
            "/etc/systemd/system/user@.service.d/p2pc-delegate.conf",
            "systemctl daemon-reload && systemctl restart user@959.service",
            "restart the agent",
        ] {
            assert!(wire.contains(needle), "{needle:?} missing from {wire}");
        }
        assert!(!wire.contains("cpu, memory"), "only the missing ones are named: {wire}");
        assert!(
            wire.len() < p2pc_proto::protocol::MAX_TEXT_LEN,
            "fits the inventory: {}",
            wire.len()
        );
        assert!(
            p.hint.contains("restart the agent") && p.hint.contains("user@959.service"),
            "{}",
            p.hint
        );
    }

    /// T10j: no `user@` ancestor (a system service, root in the WSL distro): `podman info` decides, as before.
    #[test]
    fn without_a_user_manager_podman_info_decides() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("proc/self")).unwrap();
        fs::write(
            dir.path().join("proc/self/cgroup"),
            "0::/system.slice/p2pc-agent.service\n",
        )
        .unwrap();
        let host = Host::with_root(dir.path());
        assert_eq!(read_user_manager(&host), None);
        assert_eq!(check(Platform::Linux, &linux_on(&host, &["cpu", "memory", "pids"])), []);
        let problems = check(Platform::Linux, &linux_on(&host, &["memory", "pids"]));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].code, "cgroup_not_delegated");
        assert!(problems[0].detail.contains("cpu"), "{}", problems[0].detail);
        assert!(
            problems[0].detail.contains("podman info"),
            "names what it read: {}",
            problems[0].detail
        );
        assert!(
            problems[0].detail.contains("restart the agent"),
            "{}",
            problems[0].detail
        );
        // T10j review P3 3: `podman info` listing no controller at all says "nothing", not an empty list.
        let problems = check(Platform::Linux, &linux_on(&host, &[]));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].detail.contains("(cgroupControllers): nothing)"),
            "{}",
            problems[0].detail
        );
        // No /proc/self/cgroup at all: the same.
        let empty = Host::with_root(tempfile::tempdir().unwrap().path());
        assert_eq!(read_user_manager(&empty), None);
    }

    /// T10j: `user@` is above the agent but its `cgroup.controllers` cannot be read: `systemctl show` fills in
    /// ([`Delegated::from_systemctl`]); when that fails too, `podman info` is the last resort.
    #[test]
    fn the_unit_configuration_is_the_fallback_for_an_unreadable_cgroup_file() {
        let (_dir, host) = acc1_machine(None);
        let mut f = linux_on(&host, &["memory", "pids"]);
        assert_eq!(f.user_manager.as_ref().map(|u| u.delegated.is_none()), Some(true));
        // Nothing else to ask: podman info, as before.
        assert_eq!(codes(Platform::Linux, &f), ["cgroup_not_delegated"]);
        f.user_manager.as_mut().unwrap().delegated =
            Some(Delegated::from_systemctl(959, "cpu cpuset io memory pids\n"));
        assert_eq!(check(Platform::Linux, &f), []);
        f.user_manager.as_mut().unwrap().delegated = Some(Delegated::from_systemctl(959, "memory pids\n"));
        let problems = check(Platform::Linux, &f);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0]
                .detail
                .contains("systemctl show user@959.service --property=DelegateControllers"),
            "{}",
            problems[0].detail
        );
    }

    /// WSL2 does not use the Linux delegation check at all.
    #[test]
    fn wsl2_ignores_the_user_manager() {
        let (_dir, host) = acc1_machine(Some("memory\n"));
        let mut f = good_wsl2();
        f.user_manager = read_user_manager(&host);
        assert_eq!(check(Platform::Wsl2, &f), []);
    }

    #[test]
    fn wsl2_profile_problems() {
        let with = |f: &dyn Fn(&mut SandboxFacts)| {
            let mut facts = good_wsl2();
            f(&mut facts);
            codes(Platform::Wsl2, &facts)
        };
        assert_eq!(with(&|f| f.euid = Some(1000)), ["not_root"]);
        assert_eq!(with(&|f| f.subuid = None), ["subuid_range_missing"]);
        assert_eq!(
            with(&|f| f.subgid = Some("containers:100000:65535\n".into())),
            ["subgid_range_missing"]
        );
        assert_eq!(
            with(&|f| f.subuid = Some("containers:100000:65536\n".into())),
            Vec::<&str>::new(),
            "65 536 is enough"
        );
        assert_eq!(
            with(&|f| f.podman.info.as_mut().unwrap().cgroup_manager = Some("systemd".into())),
            ["cgroup_manager_not_cgroupfs"]
        );
        // §9.0 "Windows interop": each signal on its own.
        assert_eq!(
            with(&|f| f.windows_mounts = parse::windows_mounts(fixture!("proc-mounts-wsl.txt"))),
            ["windows_mounts"]
        );
        assert_eq!(with(&|f| f.wsl_interop_env = true), ["interop_env"]);
        assert_eq!(
            with(&|f| f.wsl_conf = None),
            ["interop_enabled", "windows_path_appended"]
        );
        assert_eq!(
            with(&|f| f.wsl_conf = Some("[interop]\nenabled=true\nappendWindowsPath=false\n".into())),
            ["interop_enabled"]
        );
        assert_eq!(
            with(&|f| f.wsl_conf = Some("[interop]\nenabled=false\n".into())),
            ["windows_path_appended"]
        );
        assert_eq!(
            with(&|f| f.windows_path = vec!["/mnt/c/Windows/system32".into()]),
            ["windows_path"]
        );
        assert_eq!(
            with(&|f| f.binfmt_interop = true),
            Vec::<&str>::new(),
            "the binfmt entry is a note"
        );
        // WSL2 runs Podman as root: not rootless, and that is right.
        assert_eq!(
            with(&|f| f.podman.info.as_mut().unwrap().rootless = Some(false)),
            Vec::<&str>::new()
        );
        // A fresh, unconfigured WSL distro: everything at once, each with a hint.
        let problems = check(Platform::Wsl2, &{
            let mut f = good_wsl2();
            f.euid = Some(1000);
            f.subuid = None;
            f.subgid = None;
            f.windows_mounts = vec!["/mnt/c".into()];
            f.wsl_interop_env = true;
            f.wsl_conf = None;
            f.podman = PodmanFacts {
                tool: Tool::Unavailable,
                info: None,
                info_error: None,
            };
            f
        });
        assert_eq!(problems.len(), 8, "{problems:?}");
        assert!(problems.iter().all(|p| !p.hint.is_empty()));
    }

    #[test]
    fn gvisor_runtime() {
        assert_eq!(sandbox_class(Runtime::Crun), SandboxClass::Container);
        assert_eq!(sandbox_class(Runtime::Runsc), SandboxClass::ContainerGvisor);
        let mut f = good_linux();
        f.runtime = Runtime::Runsc;
        f.runtime_tool = Tool::Unavailable;
        let problems = check(Platform::Linux, &f);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].detail.contains("runsc"));
        assert_eq!(
            problems[0].wire(),
            "runtime_not_found: the config asks for runtime = \"runsc\", but gVisor's runsc is not installed"
        );
    }
}
