// SPDX-License-Identifier: Apache-2.0

//! Pure parsers for the system files and tool outputs the inventory reads. No I/O here: detection reads the input
//! through [`crate::host::Host`] and [`crate::runner::CommandRunner`], and these functions turn it into facts.

use std::collections::BTreeMap;

use p2pc_proto::api::GpuInfo;
use p2pc_proto::protocol::MAX_GPU_UUID_LEN;
use serde_json::Value;

/// CPU facts from `/proc/cpuinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuFacts {
    /// The first `model name`, if any (ARM kernels may not print one).
    pub model: Option<String>,
    /// Number of `processor` entries: the logical CPUs.
    pub logical: u32,
}

fn key_value(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once(':')?;
    Some((k.trim(), v.trim()))
}

/// Parses `/proc/cpuinfo`.
#[must_use]
pub fn cpuinfo(text: &str) -> CpuFacts {
    let mut model = None;
    let mut logical = 0u32;
    for (k, v) in text.lines().filter_map(key_value) {
        match k {
            "processor" => logical = logical.saturating_add(1),
            "model name" if model.is_none() && !v.is_empty() => model = Some(v.to_string()),
            _ => {}
        }
    }
    CpuFacts { model, logical }
}

/// `MemTotal` from `/proc/meminfo`, in MiB.
#[must_use]
pub fn meminfo_total_mb(text: &str) -> Option<u64> {
    let (_, v) = text.lines().filter_map(key_value).find(|(k, _)| *k == "MemTotal")?;
    let kib: u64 = v.strip_suffix("kB").unwrap_or(v).trim().parse().ok()?;
    Some(kib / 1024)
}

fn unquote(v: &str) -> &str {
    let v = v.trim();
    for q in ['"', '\''] {
        if let Some(inner) = v.strip_prefix(q).and_then(|s| s.strip_suffix(q)) {
            return inner;
        }
    }
    v
}

/// A display name from `os-release`: `NAME VERSION_ID` (for example `Ubuntu 24.04`), else `PRETTY_NAME` (rolling
/// releases such as Arch have no `VERSION_ID`), else `NAME`.
#[must_use]
pub fn os_release(text: &str) -> Option<String> {
    let vars: BTreeMap<&str, &str> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim(), unquote(v)))
        .collect();
    let non_empty = |k: &str| vars.get(k).copied().filter(|v| !v.is_empty());
    match (non_empty("NAME"), non_empty("VERSION_ID")) {
        (Some(name), Some(version)) => Some(format!("{name} {version}")),
        (name, _) => non_empty("PRETTY_NAME").or(name).map(String::from),
    }
}

/// The effective UID (second field of `Uid:`) from `/proc/self/status`.
#[must_use]
pub fn effective_uid(status: &str) -> Option<u32> {
    let (_, v) = status.lines().filter_map(key_value).find(|(k, _)| *k == "Uid")?;
    v.split_whitespace().nth(1)?.parse().ok()
}

/// Whether `/proc/version` describes a WSL kernel (`…-microsoft-standard-WSL2`).
#[must_use]
pub fn proc_version_is_wsl(text: &str) -> bool {
    text.to_ascii_lowercase().contains("microsoft") || text.contains("WSL")
}

/// Whether a GPU UUID is acceptable: the same character set and length as `p2pc-proto`'s inventory validation.
#[must_use]
pub fn is_gpu_uuid(u: &str) -> bool {
    let ok = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.' | b'/');
    !u.is_empty() && u.len() <= MAX_GPU_UUID_LEN && u.as_bytes().iter().all(ok)
}

/// `nvidia-smi` prints `[N/A]`, `[Not Supported]`, `[Unknown Error]`… for values it does not know.
fn known(v: &str) -> Option<&str> {
    let v = v.trim();
    (!v.is_empty() && !v.starts_with('[')).then_some(v)
}

/// `00000000:01:00.0` (nvidia-smi's 8-digit PCI domain) → `0000:01:00.0`.
fn pci_bdf(v: &str) -> String {
    let v = v.trim();
    match v.split_once(':') {
        Some((domain, rest)) if domain.len() == 8 && domain.starts_with("0000") => {
            format!("{}:{rest}", &domain[4..]).to_ascii_lowercase()
        }
        _ => v.to_ascii_lowercase(),
    }
}

/// The `--query-gpu` fields the agent asks for, in order.
pub const GPU_QUERY_FIELDS: &str = "index,uuid,name,driver_version,memory.total,compute_cap,pci.bus_id";
/// The same without `compute_cap`, for drivers that predate that field.
pub const GPU_QUERY_FIELDS_LEGACY: &str = "index,uuid,name,driver_version,memory.total,pci.bus_id";

/// Parses `nvidia-smi --query-gpu=<GPU_QUERY_FIELDS> --format=csv,noheader,nounits`.
///
/// Each line is one GPU. A line that cannot be parsed is skipped with a message, so one broken GPU never hides the
/// others. `cuda_driver_version` and `mig` are left for the caller (other queries). Unknown VRAM stays `None`: it
/// is never guessed (§6). Duplicate UUIDs keep the first line.
#[must_use]
pub fn nvidia_smi_gpus(csv: &str, with_compute_cap: bool) -> (Vec<GpuInfo>, Vec<String>) {
    let expected = if with_compute_cap { 7 } else { 6 };
    let mut gpus: Vec<GpuInfo> = Vec::new();
    let mut errors = Vec::new();
    for (n, line) in csv.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let line_no = n + 1;
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        if fields.len() < expected {
            errors.push(format!("nvidia-smi line {line_no}: expected {expected} fields"));
            continue;
        }
        // A model name containing commas spreads over several fields: the fixed fields are at both ends.
        let extra = fields.len() - expected;
        let name = fields[2..=2 + extra].join(", ");
        let tail = &fields[3 + extra..];
        let Some(index) = known(fields[0]).and_then(|v| v.parse::<u32>().ok()) else {
            errors.push(format!("nvidia-smi line {line_no}: bad index"));
            continue;
        };
        let Some(uuid) = known(fields[1]).filter(|u| is_gpu_uuid(u)) else {
            errors.push(format!("nvidia-smi line {line_no}: missing or malformed UUID"));
            continue;
        };
        if gpus.iter().any(|g| g.uuid == uuid) {
            errors.push(format!("nvidia-smi line {line_no}: duplicate UUID"));
            continue;
        }
        let (compute_capability, pci) = if with_compute_cap {
            (known(tail[2]).map(String::from), tail[3])
        } else {
            (None, tail[2])
        };
        gpus.push(GpuInfo {
            uuid: uuid.to_string(),
            index,
            name: known(&name).unwrap_or("unknown").to_string(),
            driver_version: known(tail[0]).unwrap_or("unknown").to_string(),
            cuda_driver_version: None,
            compute_capability,
            vram_mb: known(tail[1]).and_then(|v| v.parse().ok()),
            pci_bdf: known(pci).map(pci_bdf),
            mig: false,
        });
    }
    (gpus, errors)
}

/// The MIG mode of one card, as `nvidia-smi` printed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigMode {
    /// `Enabled`.
    Enabled,
    /// `Disabled`, or `[N/A]` (a card without MIG support).
    Disabled,
    /// Anything else, for example `[Unknown Error]` or `[Insufficient Permissions]`: the state is not known, so the
    /// card must be treated as MIG-enabled (not offerable, §6).
    Unknown(String),
}

/// Parses `nvidia-smi --query-gpu=uuid,mig.mode.current --format=csv,noheader` into UUID → MIG mode. Cards that do
/// not support MIG print `[N/A]`, which is "disabled"; any other value besides `Enabled` and `Disabled` is
/// [`MigMode::Unknown`].
#[must_use]
pub fn nvidia_smi_mig(csv: &str) -> BTreeMap<String, MigMode> {
    csv.lines()
        .filter_map(|l| l.split_once(','))
        .map(|(uuid, mode)| {
            let mode = mode.trim();
            let parsed = if mode.eq_ignore_ascii_case("enabled") {
                MigMode::Enabled
            } else if mode.eq_ignore_ascii_case("disabled") || mode.eq_ignore_ascii_case("[n/a]") {
                MigMode::Disabled
            } else {
                MigMode::Unknown(mode.to_string())
            };
            (uuid.trim().to_string(), parsed)
        })
        .collect()
}

/// The CUDA version the driver supports, from the `nvidia-smi` header (`CUDA Version: 12.4`) or `nvidia-smi -q`
/// (`CUDA Version : 12.4`).
#[must_use]
pub fn nvidia_smi_cuda_version(text: &str) -> Option<String> {
    let (_, rest) = text.split_once("CUDA Version")?;
    let rest = rest.trim_start_matches([' ', ':']);
    let version: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    (!version.is_empty()).then_some(version)
}

/// The Podman client version from `podman version --format json`.
#[must_use]
pub fn podman_version(json: &str) -> Option<String> {
    let v: Value = serde_json::from_str(json).ok()?;
    ["/Client/Version", "/Server/Version", "/Version"]
        .iter()
        .find_map(|p| v.pointer(p).and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// What `podman info --format json` says about the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PodmanInfo {
    /// `host.security.rootless`.
    pub rootless: Option<bool>,
    /// `host.cgroupManager`: `systemd` or `cgroupfs`.
    pub cgroup_manager: Option<String>,
    /// `host.cgroupVersion`: `v1` or `v2`.
    pub cgroup_version: Option<String>,
    /// `host.cgroupControllers`: the controllers available to this user (delegated, when rootless).
    pub cgroup_controllers: Vec<String>,
    /// `host.ociRuntime.name`.
    pub oci_runtime: Option<String>,
}

/// Parses `podman info --format json`. `None` if it is not JSON.
#[must_use]
pub fn podman_info(json: &str) -> Option<PodmanInfo> {
    let v: Value = serde_json::from_str(json).ok()?;
    let s = |p: &str| v.pointer(p).and_then(Value::as_str).map(String::from);
    Some(PodmanInfo {
        rootless: v.pointer("/host/security/rootless").and_then(Value::as_bool),
        cgroup_manager: s("/host/cgroupManager"),
        cgroup_version: s("/host/cgroupVersion"),
        cgroup_controllers: v
            .pointer("/host/cgroupControllers")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
            .unwrap_or_default(),
        oci_runtime: s("/host/ociRuntime/name"),
    })
}

/// The systemd user manager an agent runs under, from its own `/proc/self/cgroup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserManagerCgroup {
    /// The UID in the unit's name, `user@<uid>.service`.
    pub uid: u32,
    /// The unit's cgroup directory, from the cgroup root: `/user.slice/user-<uid>.slice/user@<uid>.service`.
    pub path: String,
}

/// The `user@<uid>.service` ancestor of the cgroup in `/proc/self/cgroup` (the cgroup v2 line, `0::<path>`).
///
/// `None` when the agent is not under a user manager (a system service, root in the WSL distro).
#[must_use]
pub fn user_manager_cgroup(proc_self_cgroup: &str) -> Option<UserManagerCgroup> {
    let path = proc_self_cgroup.lines().find_map(|l| l.strip_prefix("0::"))?;
    let mut dir = String::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        dir.push('/');
        dir.push_str(part);
        let uid = part
            .strip_prefix("user@")
            .and_then(|r| r.strip_suffix(".service"))
            .filter(|u| !u.is_empty() && u.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|u| u.parse().ok());
        if let Some(uid) = uid {
            return Some(UserManagerCgroup { uid, path: dir });
        }
    }
    None
}

/// The words of a `cgroup.controllers` file, or of systemd's `DelegateControllers=` value.
#[must_use]
pub fn controller_words(text: &str) -> Vec<String> {
    text.split_whitespace().map(String::from).collect()
}

/// Whether a version string such as `4.9.3` or `5.0.0-rc1` is at least `major.minor`. `None` if unparseable.
#[must_use]
pub fn version_at_least(version: &str, major: u64, minor: u64) -> Option<bool> {
    let mut parts = version.trim().trim_start_matches('v').split(['.', '-', '+']);
    let ma: u64 = parts.next()?.parse().ok()?;
    let mi: u64 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((ma, mi) >= (major, minor))
}

/// The version from `crun --version` (`crun version 1.14.1`) or `runsc --version` (`runsc version release-…`).
#[must_use]
pub fn runtime_version(stdout: &str) -> Option<String> {
    let first = stdout.lines().map(str::trim).find(|l| !l.is_empty())?;
    let version = first.split_once(" version ").map_or(first, |(_, v)| v).trim();
    (!version.is_empty()).then(|| version.to_string())
}

/// Fully qualified CDI device names (`vendor/class=name`) from `nvidia-ctk cdi list`, skipping its log lines.
#[must_use]
pub fn cdi_list(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| {
            l.split_once('=').is_some_and(|(kind, name)| {
                kind.contains('/') && !name.is_empty() && !kind.contains(char::is_whitespace)
            }) && !l.contains(char::is_whitespace)
        })
        .map(String::from)
        .collect()
}

/// The parts of a CDI spec file the agent needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdiSpec {
    /// `kind`, for example `nvidia.com/gpu`.
    pub kind: String,
    /// `devices[].name`.
    pub devices: Vec<String>,
}

impl CdiSpec {
    /// Fully qualified device names, `kind=name`.
    #[must_use]
    pub fn qualified(&self) -> Vec<String> {
        self.devices.iter().map(|d| format!("{}={d}", self.kind)).collect()
    }
}

/// Parses a CDI spec file: JSON when `json`, else YAML.
///
/// The YAML reader is deliberately small: it reads only the top-level `kind` and the `name` of each top-level
/// `devices` entry, which is all the agent needs from the files `nvidia-ctk cdi generate` writes. It is not a
/// general YAML parser, and it returns `None` when it finds no `kind`.
#[must_use]
pub fn cdi_spec(text: &str, json: bool) -> Option<CdiSpec> {
    if json {
        let v: Value = serde_json::from_str(text).ok()?;
        let kind = v.get("kind")?.as_str()?.to_string();
        let devices = v
            .get("devices")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|d| d.get("name")?.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        return Some(CdiSpec { kind, devices });
    }
    let mut kind = None;
    let mut devices = Vec::new();
    let mut in_devices = false;
    // Indentation of the `- ` that starts each device entry, once seen.
    let mut item_indent: Option<usize> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" {
            continue;
        }
        let indent = line.len() - trimmed.len();
        if indent == 0 && !trimmed.starts_with("- ") {
            in_devices = false;
            if let Some(v) = trimmed.strip_prefix("kind:") {
                kind = Some(unquote(v).to_string());
            } else if trimmed.starts_with("devices:") {
                in_devices = true;
                item_indent = None;
            }
            continue;
        }
        if !in_devices {
            continue;
        }
        let item = trimmed.strip_prefix("- ");
        if item.is_some() && item_indent.is_none() {
            item_indent = Some(indent);
        }
        let Some(item_indent) = item_indent else { continue };
        let key = match item {
            Some(rest) if indent == item_indent => rest.trim_start(),
            None if indent == item_indent + 2 => trimmed,
            _ => continue,
        };
        if let Some(name) = key.strip_prefix("name:") {
            devices.push(unquote(name).to_string());
        }
    }
    Some(CdiSpec { kind: kind?, devices })
}

/// The largest range count for `name` in `/etc/subuid` or `/etc/subgid` (`name:start:count`).
#[must_use]
pub fn subid_range(text: &str, name: &str) -> Option<u64> {
    text.lines()
        .filter_map(|l| {
            let mut parts = l.trim().split(':');
            let (who, _start, count) = (parts.next()?, parts.next()?, parts.next()?);
            (who == name).then(|| count.parse::<u64>().ok()).flatten()
        })
        .max()
}

/// Whether a `binfmt_misc` entry (such as `WSLInterop`) is enabled: its first line is `enabled`.
#[must_use]
pub fn binfmt_enabled(text: &str) -> bool {
    text.lines().next().is_some_and(|l| l.trim() == "enabled")
}

/// Mount points of Windows filesystems (spec §9.0 "Windows interop", the rule of `deploy/wsl/test-distro.sh`'s
/// `windows_mounts`): every `9p` or `drvfs` mount, and a `virtiofs` mount of a drive letter (newer WSL kernels),
/// **except** the read-only GPU driver store WSL mounts at `/usr/lib/wsl/drivers` when a GPU is passed through.
/// Only the mount table is read; the drives themselves are never touched.
#[must_use]
pub fn windows_mounts(proc_mounts: &str) -> Vec<String> {
    proc_mounts
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (source, target, fstype, options) = (f.next()?, f.next()?, f.next()?, f.next().unwrap_or(""));
            let drive_letter = {
                let b = source.as_bytes();
                b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
            };
            let windows = matches!(fstype, "9p" | "drvfs") || (fstype == "virtiofs" && drive_letter);
            let driver_store = target == "/usr/lib/wsl/drivers" && options.split(',').any(|o| o == "ro");
            (windows && !driver_store).then(|| target.to_string())
        })
        .collect()
}

/// The value of `key` in `[section]` of an INI file such as `/etc/wsl.conf`, as `test-distro.sh`'s `ini_get` reads
/// it: `#` and `;` lines are comments, names are compared exactly, spaces around them are trimmed, the first match
/// wins.
#[must_use]
pub fn ini_get(text: &str, section: &str, key: &str) -> Option<String> {
    let mut current: Option<&str> = None;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.starts_with(';') {
            continue;
        }
        if let Some(name) = t.strip_prefix('[') {
            current = Some(name.trim_end_matches(']').trim());
            continue;
        }
        if current == Some(section)
            && let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

/// The `PATH` entries under `/mnt/`: Windows directories appended by WSL (`appendWindowsPath`).
#[must_use]
pub fn windows_path_entries(path: &str) -> Vec<String> {
    path.split(':')
        .filter(|e| e.starts_with("/mnt/"))
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/", $name))
        };
    }

    #[test]
    fn cpuinfo_intel_and_amd() {
        assert_eq!(
            cpuinfo(fixture!("cpuinfo-intel.txt")),
            CpuFacts {
                model: Some("Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz".into()),
                logical: 16
            }
        );
        assert_eq!(
            cpuinfo(fixture!("cpuinfo-amd.txt")),
            CpuFacts {
                model: Some("AMD Ryzen 9 7950X 16-Core Processor".into()),
                logical: 32
            }
        );
        // ARM kernels print no `model name`.
        let arm = "processor\t: 0\nBogoMIPS\t: 48.00\nCPU part\t: 0xd0c\n\nprocessor\t: 1\n";
        assert_eq!(
            cpuinfo(arm),
            CpuFacts {
                model: None,
                logical: 2
            }
        );
        assert_eq!(cpuinfo("").logical, 0);
    }

    #[test]
    fn meminfo_total() {
        assert_eq!(meminfo_total_mb(fixture!("meminfo.txt")), Some(32_014));
        assert_eq!(meminfo_total_mb("MemFree: 10 kB\n"), None);
        assert_eq!(meminfo_total_mb("MemTotal: lots kB\n"), None);
    }

    #[test]
    fn os_release_ubuntu_and_arch() {
        assert_eq!(
            os_release(fixture!("os-release-ubuntu")).as_deref(),
            Some("Ubuntu 24.04")
        );
        assert_eq!(os_release(fixture!("os-release-arch")).as_deref(), Some("Arch Linux"));
        assert_eq!(os_release("ID=x\n"), None);
        assert_eq!(
            os_release("NAME='Debian GNU/Linux'\n").as_deref(),
            Some("Debian GNU/Linux")
        );
    }

    #[test]
    fn effective_uid_is_the_second_field() {
        assert_eq!(
            effective_uid("Name:\tp2pc-agent\nUid:\t1000\t1001\t1000\t1000\n"),
            Some(1001)
        );
        assert_eq!(effective_uid("Uid:\t0\t0\t0\t0\n"), Some(0));
        assert_eq!(effective_uid("Gid:\t0\t0\t0\t0\n"), None);
    }

    #[test]
    fn wsl_and_native_proc_version() {
        assert!(proc_version_is_wsl(fixture!("proc-version-wsl.txt")));
        assert!(!proc_version_is_wsl(fixture!("proc-version-linux.txt")));
        assert!(proc_version_is_wsl("Linux version 4.4.0-19041-Microsoft"));
    }

    #[test]
    fn nvidia_smi_zero_gpus() {
        let (gpus, errors) = nvidia_smi_gpus("", true);
        assert!(gpus.is_empty() && errors.is_empty());
    }

    #[test]
    fn nvidia_smi_one_gpu() {
        let (gpus, errors) = nvidia_smi_gpus(fixture!("nvidia-smi-1gpu.csv"), true);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            gpus,
            vec![GpuInfo {
                uuid: "GPU-00000000-0000-4000-8000-000000000001".into(),
                index: 0,
                name: "NVIDIA GeForce RTX 4090".into(),
                driver_version: "550.54.14".into(),
                cuda_driver_version: None,
                compute_capability: Some("8.9".into()),
                vram_mb: Some(24_564),
                pci_bdf: Some("0000:01:00.0".into()),
                mig: false,
            }]
        );
    }

    #[test]
    fn nvidia_smi_two_gpus_with_unknown_vram() {
        let (gpus, errors) = nvidia_smi_gpus(fixture!("nvidia-smi-2gpu.csv"), true);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(gpus.len(), 2);
        assert_eq!(gpus[0].vram_mb, Some(40_960));
        assert_eq!(gpus[1].uuid, "GPU-00000000-0000-4000-8000-0000000000a1");
        assert_eq!(gpus[1].vram_mb, None, "[N/A] VRAM is unknown, never zero or host RAM");
        assert_eq!(gpus[1].pci_bdf.as_deref(), Some("0000:0a:00.0"));
        let mig = nvidia_smi_mig(fixture!("nvidia-smi-mig-2gpu.csv"));
        assert_eq!(
            mig.get("GPU-00000000-0000-4000-8000-0000000000a0"),
            Some(&MigMode::Enabled)
        );
        assert_eq!(
            mig.get("GPU-00000000-0000-4000-8000-0000000000a1"),
            Some(&MigMode::Disabled)
        );
    }

    /// T07b review, carry-over 3: only `Enabled`, `Disabled` and `[N/A]` are known states. Anything else (an error
    /// in brackets, a pending change) is unknown, never "disabled".
    #[test]
    fn mig_values_other_than_enabled_or_disabled_are_unknown() {
        let csv = "GPU-a, Enabled\nGPU-b, Disabled\nGPU-c, [N/A]\nGPU-d, [Unknown Error]\n\
                   GPU-e, [Insufficient Permissions]\nGPU-f, \nGPU-g, enabled\nGPU-h, Pending\n";
        let mig = nvidia_smi_mig(csv);
        let get = |u: &str| mig.get(u).cloned();
        assert_eq!(get("GPU-a"), Some(MigMode::Enabled));
        assert_eq!(get("GPU-b"), Some(MigMode::Disabled));
        assert_eq!(get("GPU-c"), Some(MigMode::Disabled), "[N/A]: the card has no MIG");
        assert_eq!(get("GPU-d"), Some(MigMode::Unknown("[Unknown Error]".into())));
        assert_eq!(
            get("GPU-e"),
            Some(MigMode::Unknown("[Insufficient Permissions]".into()))
        );
        assert_eq!(get("GPU-f"), Some(MigMode::Unknown(String::new())));
        assert_eq!(get("GPU-g"), Some(MigMode::Enabled), "case does not matter");
        assert_eq!(get("GPU-h"), Some(MigMode::Unknown("Pending".into())));
    }

    #[test]
    fn nvidia_smi_wsl_style() {
        let (gpus, errors) = nvidia_smi_gpus(fixture!("nvidia-smi-wsl.csv"), true);
        assert!(errors.is_empty());
        assert_eq!(gpus[0].name, "NVIDIA GeForce RTX 5070 Ti");
        assert_eq!(gpus[0].driver_version, "576.02");
        assert_eq!(gpus[0].compute_capability.as_deref(), Some("12.0"));
        assert_eq!(
            nvidia_smi_cuda_version(fixture!("nvidia-smi-header-wsl.txt")).as_deref(),
            Some("12.9")
        );
        assert_eq!(
            nvidia_smi_cuda_version(fixture!("nvidia-smi-header-linux.txt")).as_deref(),
            Some("12.4")
        );
        assert_eq!(
            nvidia_smi_cuda_version("CUDA Version                              : 13.0\n").as_deref(),
            Some("13.0")
        );
        assert_eq!(nvidia_smi_cuda_version("no header"), None);
    }

    #[test]
    fn one_bad_gpu_line_does_not_hide_the_others() {
        let csv = "0, GPU-00000000-0000-4000-8000-000000000001, Good GPU, 550.54, 8192, 8.6, 00000000:01:00.0\n\
                   1, [N/A], Broken GPU, 550.54, 8192, 8.6, 00000000:02:00.0\n\
                   garbage\n\
                   2, GPU-00000000-0000-4000-8000-000000000003, Board, Rev 2, 550.54, 4096, 7.5, 00000000:03:00.0\n\
                   3, GPU-00000000-0000-4000-8000-000000000001, Duplicate, 550.54, 8192, 8.6, 00000000:04:00.0\n";
        let (gpus, errors) = nvidia_smi_gpus(csv, true);
        assert_eq!(gpus.len(), 2);
        assert_eq!(gpus[1].name, "Board, Rev 2", "commas in the model name");
        assert_eq!(gpus[1].vram_mb, Some(4096));
        assert_eq!(errors.len(), 3, "{errors:?}");
    }

    #[test]
    fn nvidia_smi_legacy_fields() {
        let (gpus, errors) = nvidia_smi_gpus("0, GPU-0a, Old GPU, 470.1, 4096, 00000000:01:00.0\n", false);
        assert!(errors.is_empty());
        assert_eq!(gpus[0].compute_capability, None);
        assert_eq!(gpus[0].pci_bdf.as_deref(), Some("0000:01:00.0"));
    }

    #[test]
    fn podman_version_and_info() {
        assert_eq!(
            podman_version(fixture!("podman-version.json")).as_deref(),
            Some("4.9.3")
        );
        assert_eq!(podman_version("not json"), None);
        let info = podman_info(fixture!("podman-info-rootless.json")).unwrap();
        assert_eq!(info.rootless, Some(true));
        assert_eq!(info.cgroup_manager.as_deref(), Some("systemd"));
        assert_eq!(info.cgroup_version.as_deref(), Some("v2"));
        assert_eq!(info.cgroup_controllers, ["cpu", "memory", "pids"]);
        assert_eq!(info.oci_runtime.as_deref(), Some("crun"));
        let wsl = podman_info(fixture!("podman-info-wsl.json")).unwrap();
        assert_eq!(wsl.rootless, Some(false));
        assert_eq!(wsl.cgroup_manager.as_deref(), Some("cgroupfs"));
        assert_eq!(podman_info("{}"), Some(PodmanInfo::default()));
    }

    #[test]
    fn versions() {
        assert_eq!(version_at_least("4.9.3", 4, 9), Some(true));
        assert_eq!(version_at_least("4.8.9", 4, 9), Some(false));
        assert_eq!(version_at_least("5.0.0-rc1", 4, 9), Some(true));
        assert_eq!(version_at_least("3.4", 4, 9), Some(false));
        assert_eq!(version_at_least("", 4, 9), None);
        assert_eq!(
            runtime_version("crun version 1.14.1\ncommit: x\n").as_deref(),
            Some("1.14.1")
        );
        assert_eq!(
            runtime_version("runsc version release-20240513.0\nspec: 1.1.0-rc.1\n").as_deref(),
            Some("release-20240513.0")
        );
        assert_eq!(runtime_version("\n"), None);
    }

    #[test]
    fn cdi_list_skips_log_lines() {
        assert_eq!(
            cdi_list(fixture!("nvidia-ctk-cdi-list.txt")),
            [
                "nvidia.com/gpu=0",
                "nvidia.com/gpu=GPU-00000000-0000-4000-8000-000000000001",
                "nvidia.com/gpu=all"
            ]
        );
    }

    #[test]
    fn cdi_yaml_specs() {
        let wsl = cdi_spec(fixture!("cdi-nvidia-wsl.yaml"), false).unwrap();
        assert_eq!(wsl.kind, "nvidia.com/gpu");
        assert_eq!(wsl.devices, ["all"]);
        let linux = cdi_spec(fixture!("cdi-nvidia-linux.yaml"), false).unwrap();
        assert_eq!(linux.kind, "nvidia.com/gpu");
        assert_eq!(linux.devices, ["0", "GPU-00000000-0000-4000-8000-000000000001", "all"]);
        assert_eq!(linux.qualified()[2], "nvidia.com/gpu=all");
        assert_eq!(cdi_spec("devices:\n- name: x\n", false), None, "no kind");
    }

    #[test]
    fn cdi_json_spec() {
        let json = r#"{"cdiVersion":"0.5.0","kind":"nvidia.com/gpu","devices":[{"name":"all","containerEdits":{}}]}"#;
        assert_eq!(
            cdi_spec(json, true),
            Some(CdiSpec {
                kind: "nvidia.com/gpu".into(),
                devices: vec!["all".into()]
            })
        );
        assert_eq!(cdi_spec("{", true), None);
    }

    #[test]
    fn subid_ranges() {
        let text = "p2pc:100000:65536\ncontainers:2147483647:2147483648\ncontainers:1:10\n";
        assert_eq!(subid_range(text, "containers"), Some(2_147_483_648));
        assert_eq!(subid_range(text, "p2pc"), Some(65_536));
        assert_eq!(subid_range(text, "nobody"), None);
    }

    #[test]
    fn windows_mounts_follow_test_distro() {
        // The fixture: the read-only driver store (allowed), C: over 9p and D: over drvfs (not allowed).
        assert_eq!(windows_mounts(fixture!("proc-mounts-wsl.txt")), ["/mnt/c", "/mnt/d"]);
        assert!(windows_mounts("/dev/sda1 / ext4 rw 0 0\n").is_empty());
        // The driver store only when it is read-only, and only at its own path.
        assert_eq!(
            windows_mounts("drivers /usr/lib/wsl/drivers 9p rw,noatime,aname=drivers 0 0\n"),
            ["/usr/lib/wsl/drivers"]
        );
        assert_eq!(windows_mounts("drivers /srv/drivers 9p ro 0 0\n"), ["/srv/drivers"]);
        // Any other 9p share counts, drive letter or not.
        assert_eq!(windows_mounts("share /srv/share 9p rw,trans=fd 0 0\n"), ["/srv/share"]);
        // Newer WSL kernels mount drive letters over virtiofs. A virtiofs mount that is not a drive is not one.
        assert_eq!(
            windows_mounts("C:\\134 /mnt/c virtiofs rw,noatime 0 0\nE: /mnt/e virtiofs rw 0 0\n"),
            ["/mnt/c", "/mnt/e"]
        );
        assert!(windows_mounts("shared /srv/shared virtiofs rw 0 0\n").is_empty());
    }

    #[test]
    fn wsl_conf_values() {
        let conf =
            "# p2pc-node\n[boot]\nsystemd=false\n\n[interop]\n; comment\n enabled = false \nappendWindowsPath=false\n";
        assert_eq!(ini_get(conf, "interop", "enabled").as_deref(), Some("false"));
        assert_eq!(ini_get(conf, "interop", "appendWindowsPath").as_deref(), Some("false"));
        assert_eq!(ini_get(conf, "boot", "systemd").as_deref(), Some("false"));
        assert_eq!(ini_get(conf, "interop", "missing"), None);
        assert_eq!(
            ini_get(conf, "automount", "enabled"),
            None,
            "keys belong to their section"
        );
        assert_eq!(ini_get("[interop]\n# enabled=false\n", "interop", "enabled"), None);
    }

    #[test]
    fn windows_path_entries_are_under_mnt() {
        assert_eq!(
            windows_path_entries("/usr/bin:/mnt/c/Windows/system32:/bin:/mnt/c/Program Files/x"),
            ["/mnt/c/Windows/system32", "/mnt/c/Program Files/x"]
        );
        assert!(windows_path_entries("/usr/local/sbin:/usr/bin:/mntx/y").is_empty());
    }

    #[test]
    fn binfmt_interop_state() {
        assert!(binfmt_enabled(
            "enabled\ninterpreter /init\nflags: PF\noffset 0\nmagic 4d5a\n"
        ));
        assert!(!binfmt_enabled("disabled\n"));
        assert!(!binfmt_enabled(""));
    }

    #[test]
    fn user_manager_is_found_in_the_cgroup_path() {
        let found =
            user_manager_cgroup("0::/user.slice/user-959.slice/user@959.service/app.slice/p2pc-agent.service\n");
        assert_eq!(
            found,
            Some(UserManagerCgroup {
                uid: 959,
                path: "/user.slice/user-959.slice/user@959.service".into()
            })
        );
        // Not under a user manager: a system service, a login session scope, the root, a cgroup v1 file.
        for text in [
            "0::/system.slice/p2pc-agent.service\n",
            "0::/user.slice/user-959.slice/session-3.scope\n",
            "0::/\n",
            "",
            "12:cpu:/user.slice/user-959.slice/user@959.service\n",
            "0::/a/user@.service/b\n0::/a/user@x1.service/b\n",
        ] {
            assert_eq!(user_manager_cgroup(text), None, "{text:?}");
        }
        assert_eq!(
            controller_words("cpuset cpu io memory pids\n"),
            ["cpuset", "cpu", "io", "memory", "pids"]
        );
        assert!(controller_words("\n").is_empty());
    }
}
