// SPDX-License-Identifier: Apache-2.0

//! The checks of the first run's step 2 (H2 §8.2): `install.ps1`'s checks (`Test-Prerequisites`), with its thresholds,
//! plus the H2 additions the spec names.
//!
//! | Check | `install.ps1` | Here |
//! |---|---|---|
//! | Windows build | ≥ 19044 (exit 10) | ≥ **22000**: H2 §8.2, the beta app supports Windows 11 only |
//! | WSL present, `wsl --version` works | exit 11 | [`CheckFailure::WslMissing`] (→ step 2a) |
//! | WSL ≥ 2.0.0 | exit 12 | [`CheckFailure::WslTooOld`] (→ step 2a, then `wsl_too_old`) |
//! | WSL default version 2 (unset counts as 2) | exit 13 | [`CheckFailure::WslDefaultVersion`] |
//! | Virtualization: a running hypervisor, else the firmware flag | exit 14; unknown only warns | the same |
//! | ≥ 20 GiB free on the install drive, local drive only | exit 15; a network path is exit 2 | [`CheckFailure::DiskLow`], [`CheckFailure::InstallDirNotLocal`] |
//! | NVIDIA driver present | — | warning only (H2 §8.2) |
//! | free space under `20 GiB + I + 50 GiB` | — | warning only (H2 §8.2, the templates' minimum) |
//!
//! Unlike the script, which stops at the first failure, [`run_checks`] gathers every fact and the [`ChecksReport`]
//! lists every failure and warning in `install.ps1`'s order, so step 2 can show them all at once. Every Windows fact
//! comes from one PowerShell probe ([`PROBE_SCRIPT`], read-only) and one `wsl.exe --version` (with the service-timeout
//! retry).

use std::fmt;
use std::path::Path;

use std::time::Duration;

use crate::runner::{Host, Invocation, RunError, WSL_EXE, powershell};

/// The time limit of `wsl --version` (a WSL that hangs counts as missing; step 2a reinstalls it).
pub const WSL_VERSION_TIMEOUT: Duration = Duration::from_secs(60);

/// 2^30 bytes: `install.ps1`'s `-MinFreeGB` counts in these units (H2 §8.2: "so GiB").
pub const GIB: u64 = 1 << 30;

/// A WSL version (`wsl --version`'s first `a.b.c[.d]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WslVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub build: u32,
}

impl WslVersion {
    /// `major.minor.patch` (build 0).
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            build: 0,
        }
    }

    /// The first `\d+\.\d+\.\d+(\.\d+)?` in a text, as `Test-Wsl` reads `wsl --version`.
    pub fn find_in(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_digit()) {
                let rest = &text[i..];
                let run: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
                let parts: Vec<&str> = run.split('.').collect();
                let numbers: Vec<u32> = parts
                    .iter()
                    .take(4)
                    .map_while(|p| (!p.is_empty()).then(|| p.parse().ok()).flatten())
                    .collect();
                if numbers.len() >= 3 {
                    return Some(Self {
                        major: numbers[0],
                        minor: numbers[1],
                        patch: numbers[2],
                        build: numbers.get(3).copied().unwrap_or(0),
                    });
                }
                i += run.len().max(1);
            } else {
                i += 1;
            }
        }
        None
    }
}

impl fmt::Display for WslVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.major, self.minor, self.patch, self.build)
    }
}

/// The thresholds of the checks. [`Default`] is H2's: `install.ps1`'s, with the Windows 11 build floor, and the
/// warning for the templates' minimum share with the default image allowance and no hub blob quota (step 2 does not
/// know yet whether this PC will host the hub, §8.2 "Disk arithmetic").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    /// The oldest Windows build (H2 §8.2: 22000, Windows 11).
    pub min_windows_build: u32,
    /// The oldest WSL (`$MinWslVersion`, 2.0.0).
    pub min_wsl: WslVersion,
    /// The free space the distro needs, in GiB (`-MinFreeGB`, 20). Below it: [`CheckFailure::DiskLow`].
    pub min_free_gib: u64,
    /// `I`, the container image store's allowance, in GiB (H2 §8.2, 16 until E11 measures it).
    pub image_allowance_gib: u64,
    /// The share both templates need, in GiB (H2 §8.2, 50).
    pub templates_share_gib: u64,
    /// `B`, the hub's blob quota, in GiB (0 at step 2; 20 on a PC meant to be the hub).
    pub blob_quota_gib: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            min_windows_build: 22000,
            min_wsl: WslVersion::new(2, 0, 0),
            min_free_gib: 20,
            image_allowance_gib: 16,
            templates_share_gib: 50,
            blob_quota_gib: 0,
        }
    }
}

impl Thresholds {
    /// Under this much free space step 2 warns that the templates may not run: `20 GiB + I + 50 GiB (+ B)`, 86 GiB
    /// with the defaults (106 GiB with the default hub quota).
    pub fn templates_warning_gib(&self) -> u64 {
        self.min_free_gib + self.image_allowance_gib + self.templates_share_gib + self.blob_quota_gib
    }
}

/// What `wsl.exe` said about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WslState {
    /// `wsl.exe` was not found, or `wsl --version` failed or printed no version (the inbox stub, or a WSL too old to
    /// know `--version`): `install.ps1`'s exit 11.
    Missing,
    /// `wsl --version` reported this version.
    Installed(WslVersion),
}

/// The virtualization facts, read like `Test-Virtualization`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Virtualization {
    /// The hypervisor is running (as it is once WSL2 works): trusted first, because the firmware flag can then read
    /// false.
    HypervisorRunning,
    /// A processor reports virtualization enabled in the firmware.
    FirmwareEnabled,
    /// The processors report it disabled in the firmware.
    Disabled,
    /// Neither could be read (in a VM, for example): a warning; the import fails clearly if it is really off.
    Unknown,
}

/// The free space on the install directory's drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskState {
    /// Bytes available to this user.
    Free(u64),
    /// The install directory is on a network path, not a local drive (`install.ps1` refuses it).
    NotLocal,
    /// It could not be read.
    Unknown,
}

/// Every fact of step 2, and the thresholds they are judged by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksReport {
    /// The Windows build, if it could be read.
    pub windows_build: Option<u32>,
    pub wsl: WslState,
    /// `HKCU\…\Lxss\DefaultVersion` as written, or `None` when it is unset (which means 2).
    pub wsl_default_version: Option<String>,
    pub virtualization: Virtualization,
    pub disk: DiskState,
    /// The driver versions of the NVIDIA display adapters (empty: no NVIDIA driver).
    pub nvidia_drivers: Vec<String>,
    pub thresholds: Thresholds,
}

/// A check that stops step 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckFailure {
    /// The Windows build is older than the floor (or could not be read).
    WindowsTooOld { build: Option<u32>, min: u32 },
    /// WSL is not installed, or too old to report its version: step 2a installs it.
    WslMissing,
    /// WSL is older than the minimum: step 2a updates it; if it is still too old afterwards, `wsl_too_old`.
    WslTooOld { version: WslVersion, min: WslVersion },
    /// The WSL default version is set and is not 2.
    WslDefaultVersion { value: String },
    /// Virtualization is disabled in the firmware.
    VirtualizationOff,
    /// Less free space than the distro needs (`floor(free / GiB) < min`, as `Test-DiskSpace` counts).
    DiskLow { free_gib: u64, needed_gib: u64 },
    /// The install directory is on a network path.
    InstallDirNotLocal,
    /// The free space could not be read.
    DiskUnknown,
}

impl CheckFailure {
    /// The H2 §8.8 error code, where the spec defines one. `None` where it does not: WSL missing is not an error but
    /// step 2a; the Windows build, the default version and the two disk-reading failures have no code in §8.8 yet
    /// (see the PR's spec questions), and the app shows their [`message`](Self::message).
    pub fn code(&self) -> Option<&'static str> {
        match self {
            CheckFailure::WslTooOld { .. } => Some("wsl_too_old"),
            CheckFailure::VirtualizationOff => Some("virtualization_off"),
            CheckFailure::DiskLow { .. } => Some("disk_low"),
            CheckFailure::WindowsTooOld { .. }
            | CheckFailure::WslMissing
            | CheckFailure::WslDefaultVersion { .. }
            | CheckFailure::InstallDirNotLocal
            | CheckFailure::DiskUnknown => None,
        }
    }

    /// Step 2a (`wsl --install --no-distribution`, elevated) can fix it.
    pub fn wsl_install_fixes(&self) -> bool {
        matches!(self, CheckFailure::WslMissing | CheckFailure::WslTooOld { .. })
    }

    /// A fixed message, with `install.ps1`'s advice (the app never shows a raw PowerShell error, §8.2).
    pub fn message(&self) -> String {
        match self {
            CheckFailure::WindowsTooOld { build: Some(b), min } => {
                format!("Windows build {b} is too old: P2PC needs Windows 11 (build {min} or newer).")
            }
            CheckFailure::WindowsTooOld { build: None, min } => format!(
                "The Windows build could not be read: P2PC needs Windows 11 (build {min} or newer)."
            ),
            CheckFailure::WslMissing => {
                "WSL is not installed, or it is too old to report its version.".to_owned()
            }
            CheckFailure::WslTooOld { version, min } => {
                format!("WSL {version} is older than the minimum {min}. Update it from the Microsoft Store or with: wsl --update")
            }
            CheckFailure::WslDefaultVersion { value } => format!(
                "The WSL default version is {value}, not 2. Set it with: wsl --set-default-version 2"
            ),
            CheckFailure::VirtualizationOff => "Virtualization is disabled in the firmware (BIOS/UEFI). Turn on Intel VT-x or AMD-V (SVM) in your PC's firmware settings.".to_owned(),
            CheckFailure::DiskLow {
                free_gib,
                needed_gib,
            } => format!(
                "Only {free_gib} GiB free; P2PC needs at least {needed_gib} GiB (image, container images, job data)."
            ),
            CheckFailure::InstallDirNotLocal => {
                "Your local app data folder is on a network path; P2PC needs a local drive.".to_owned()
            }
            CheckFailure::DiskUnknown => {
                "The free space on your drive could not be read.".to_owned()
            }
        }
    }
}

/// A check that only warns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckWarning {
    /// Virtualization could not be determined (`Test-Virtualization`'s warning).
    VirtualizationUnknown,
    /// No NVIDIA driver: GPU jobs will not run on this PC (H2 §8.2, warning only).
    NoNvidiaDriver,
    /// Enough for the distro, but under the templates' minimum (H2 §8.2).
    DiskBelowTemplates { free_gib: u64, wanted_gib: u64 },
}

impl CheckWarning {
    /// A fixed message.
    pub fn message(&self) -> String {
        match self {
            CheckWarning::VirtualizationUnknown => "Virtualization could not be checked (is this a virtual machine?). Setup goes on; the import fails clearly if it is off.".to_owned(),
            CheckWarning::NoNvidiaDriver => "No NVIDIA driver was found: GPU jobs will not run on this PC.".to_owned(),
            CheckWarning::DiskBelowTemplates {
                free_gib,
                wanted_gib,
            } => format!(
                "{free_gib} GiB free: the AI chat and transcription may not run on this PC (they need about {wanted_gib} GiB free)."
            ),
        }
    }
}

impl ChecksReport {
    /// Every failure, in `install.ps1`'s order (`Test-Prerequisites`: build, WSL, default version, virtualization,
    /// disk).
    pub fn failures(&self) -> Vec<CheckFailure> {
        let t = &self.thresholds;
        let mut out = Vec::new();
        match self.windows_build {
            Some(b) if b >= t.min_windows_build => {}
            build => out.push(CheckFailure::WindowsTooOld {
                build,
                min: t.min_windows_build,
            }),
        }
        match self.wsl {
            WslState::Missing => out.push(CheckFailure::WslMissing),
            WslState::Installed(v) if v < t.min_wsl => out.push(CheckFailure::WslTooOld {
                version: v,
                min: t.min_wsl,
            }),
            WslState::Installed(_) => {}
        }
        if let Some(v) = &self.wsl_default_version
            && v.trim() != "2"
        {
            out.push(CheckFailure::WslDefaultVersion { value: v.clone() });
        }
        if self.virtualization == Virtualization::Disabled {
            out.push(CheckFailure::VirtualizationOff);
        }
        match self.disk {
            DiskState::Free(bytes) => {
                let free_gib = bytes / GIB;
                if free_gib < t.min_free_gib {
                    out.push(CheckFailure::DiskLow {
                        free_gib,
                        needed_gib: t.min_free_gib,
                    });
                }
            }
            DiskState::NotLocal => out.push(CheckFailure::InstallDirNotLocal),
            DiskState::Unknown => out.push(CheckFailure::DiskUnknown),
        }
        out
    }

    /// Every warning.
    pub fn warnings(&self) -> Vec<CheckWarning> {
        let t = &self.thresholds;
        let mut out = Vec::new();
        if self.virtualization == Virtualization::Unknown {
            out.push(CheckWarning::VirtualizationUnknown);
        }
        if let DiskState::Free(bytes) = self.disk {
            let free_gib = bytes / GIB;
            let wanted = t.templates_warning_gib();
            if free_gib >= t.min_free_gib && free_gib < wanted {
                out.push(CheckWarning::DiskBelowTemplates {
                    free_gib,
                    wanted_gib: wanted,
                });
            }
        }
        if self.nvidia_drivers.is_empty() {
            out.push(CheckWarning::NoNvidiaDriver);
        }
        out
    }

    /// No failure: setup goes on to step 3.
    pub fn passed(&self) -> bool {
        self.failures().is_empty()
    }

    /// Step 2a is needed: WSL is missing or too old.
    pub fn needs_wsl_install(&self) -> bool {
        self.failures().iter().any(CheckFailure::wsl_install_fixes)
    }
}

/// The probe could not run at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckError {
    /// PowerShell could not be started, or answered nothing usable.
    #[error("the system checks could not run: {detail}")]
    Probe { detail: String },
}

/// The read-only PowerShell probe of step 2. It prints one `key=value` line per fact and changes nothing. The install
/// directory reaches it through `P2PC_INSTALL_DIR`, never pasted into the script.
pub const PROBE_SCRIPT: &str = r#"$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$build = $null
try { $build = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).BuildNumber } catch { $build = [Environment]::OSVersion.Version.Build }
'build=' + [string]$build
$hv = ''
try { $hv = [string](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).HypervisorPresent } catch { }
'hypervisor=' + $hv
$fw = @()
try { $fw = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | ForEach-Object { [string]$_.VirtualizationFirmwareEnabled }) } catch { }
'firmware=' + ($fw -join ',')
$dv = ''
$p = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -Name DefaultVersion -ErrorAction SilentlyContinue
if ($p) { $dv = [string]$p.DefaultVersion }
'default_version=' + $dv
try {
    $full = [System.IO.Path]::GetFullPath($env:P2PC_INSTALL_DIR)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($root.StartsWith('\\')) { 'disk=unc' } else { 'disk_free=' + [string](New-Object System.IO.DriveInfo($root)).AvailableFreeSpace }
} catch { 'disk=unknown' }
$nv = @()
try { $nv = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | Where-Object { ([string]$_.AdapterCompatibility -match 'NVIDIA') -or ([string]$_.Name -match 'NVIDIA') } | ForEach-Object { [string]$_.DriverVersion }) } catch { }
'nvidia=' + ($nv -join ',')
'probe=done'
"#;

/// The probe invocation for this install directory.
pub fn probe_invocation(install_dir: &Path) -> Invocation {
    powershell(PROBE_SCRIPT).env("P2PC_INSTALL_DIR", install_dir.display().to_string())
}

/// The value of the first `key=` line.
fn field<'t>(text: &'t str, key: &str) -> Option<&'t str> {
    text.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim() {
        v if v.eq_ignore_ascii_case("true") => Some(true),
        v if v.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// Reads `wsl --version` (`Test-Wsl`): not found, a failure or no version is [`WslState::Missing`].
pub fn wsl_state(host: Host<'_>) -> WslState {
    match host.run_wsl(&Invocation::new(WSL_EXE).arg("--version").timeout(WSL_VERSION_TIMEOUT)) {
        Ok(out) if out.success() => match WslVersion::find_in(&out.text()) {
            Some(v) => WslState::Installed(v),
            None => WslState::Missing,
        },
        Ok(_) => WslState::Missing,
        Err(e) => {
            tracing::info!(error = %e, "wsl --version could not run");
            WslState::Missing
        }
    }
}

/// Runs every check of step 2 for this install directory (normally [`crate::Layout::distro_dir`]).
pub fn run_checks(host: Host<'_>, install_dir: &Path, thresholds: Thresholds) -> Result<ChecksReport, CheckError> {
    let probe = host
        .run(&probe_invocation(install_dir))
        .map_err(|e: RunError| CheckError::Probe { detail: e.to_string() })?;
    let text = probe.stdout_text();
    if !probe.success() || field(&text, "probe") != Some("done") {
        return Err(CheckError::Probe {
            detail: format!("PowerShell exited {:?} without finishing the probe", probe.code),
        });
    }
    let windows_build = field(&text, "build").and_then(|b| b.trim().parse().ok());
    let hypervisor = field(&text, "hypervisor").and_then(parse_bool);
    let firmware: Vec<Option<bool>> = field(&text, "firmware")
        .unwrap_or_default()
        .split(',')
        .map(parse_bool)
        .collect();
    let virtualization = if hypervisor == Some(true) {
        Virtualization::HypervisorRunning
    } else if firmware.contains(&Some(true)) {
        Virtualization::FirmwareEnabled
    } else if firmware.contains(&Some(false)) {
        Virtualization::Disabled
    } else {
        Virtualization::Unknown
    };
    let wsl_default_version = field(&text, "default_version")
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    let disk = match (field(&text, "disk_free"), field(&text, "disk")) {
        (Some(free), _) => free.trim().parse().map_or(DiskState::Unknown, DiskState::Free),
        (None, Some("unc")) => DiskState::NotLocal,
        _ => DiskState::Unknown,
    };
    let nvidia_drivers = field(&text, "nvidia")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect();
    Ok(ChecksReport {
        windows_build,
        wsl: wsl_state(host),
        wsl_default_version,
        virtualization,
        disk,
        nvidia_drivers,
        thresholds,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::runner::fake::*;
    use crate::runner::{Output, POWERSHELL_EXE};

    const GOOD_PROBE: &str = "build=26100\nhypervisor=True\nfirmware=False\ndefault_version=\ndisk_free=214748364800\nnvidia=32.0.15.6094\nprobe=done\n";

    fn report(probe: &str, wsl: Output) -> (Result<ChecksReport, CheckError>, FakeRunner) {
        let runner = FakeRunner::new();
        let script = PROBE_SCRIPT;
        runner.on(move |i| runs_script(i, script), Output::with(0, probe));
        runner.on(|i| starts(i, WSL_EXE, &["--version"]), wsl);
        let pause = FakePause::default();
        let r = run_checks(
            Host::new(&runner, &pause),
            &PathBuf::from("C:\\Users\\someone\\AppData\\Local\\P2PC\\wsl\\p2pc-node"),
            Thresholds::default(),
        );
        (r, runner)
    }

    fn wsl_ok() -> Output {
        Output::with(
            0,
            utf16("WSL version: 2.3.26.0\r\nKernel version: 5.15.167.4-1\r\nWSLg version: 1.0.65\r\n"),
        )
    }

    #[test]
    fn a_ready_pc_passes_with_no_warning() {
        let (r, runner) = report(GOOD_PROBE, wsl_ok());
        let r = r.unwrap();
        assert_eq!(r.windows_build, Some(26100));
        assert_eq!(
            r.wsl,
            WslState::Installed(WslVersion {
                major: 2,
                minor: 3,
                patch: 26,
                build: 0
            })
        );
        assert_eq!(r.virtualization, Virtualization::HypervisorRunning);
        assert_eq!(r.disk, DiskState::Free(200 * GIB));
        assert!(r.passed(), "{:?}", r.failures());
        assert!(r.warnings().is_empty(), "{:?}", r.warnings());
        assert!(!r.needs_wsl_install());
        // The install directory goes to the probe through the environment, not the script.
        let probe = runner
            .calls()
            .into_iter()
            .find(|i| i.program() == POWERSHELL_EXE)
            .unwrap();
        assert!(
            probe
                .environment()
                .iter()
                .any(|(k, v)| k == "P2PC_INSTALL_DIR" && v.ends_with("p2pc-node"))
        );
        assert!(!PROBE_SCRIPT.contains("p2pc-node"));
    }

    #[test]
    fn the_windows_build_floor_is_22000_for_the_beta_app() {
        let probe = GOOD_PROBE.replace("build=26100", "build=19045");
        let r = report(&probe, wsl_ok()).0.unwrap();
        assert_eq!(
            r.failures(),
            vec![CheckFailure::WindowsTooOld {
                build: Some(19045),
                min: 22000
            }]
        );
        let probe = GOOD_PROBE.replace("build=26100", "build=22000");
        assert!(report(&probe, wsl_ok()).0.unwrap().passed());
        let probe = GOOD_PROBE.replace("build=26100", "build=");
        assert_eq!(
            report(&probe, wsl_ok()).0.unwrap().failures(),
            vec![CheckFailure::WindowsTooOld {
                build: None,
                min: 22000
            }]
        );
    }

    #[test]
    fn wsl_missing_not_found_failing_or_versionless_goes_to_step_2a() {
        let failing = Output::with(1, utf16("Invalid command line option: --version"));
        let versionless = Output::with(0, utf16("Usage: wsl.exe [Argument]"));
        for wsl in [failing, versionless] {
            let r = report(GOOD_PROBE, wsl).0.unwrap();
            assert_eq!(r.wsl, WslState::Missing);
            assert_eq!(r.failures(), vec![CheckFailure::WslMissing]);
            assert!(r.needs_wsl_install());
            assert_eq!(r.failures()[0].code(), None);
        }
        // wsl.exe not on the PC at all.
        let runner = FakeRunner::new();
        runner.on_seq(
            |i| starts(i, WSL_EXE, &[]),
            vec![Err(RunError::Spawn {
                program: WSL_EXE.into(),
                kind: std::io::ErrorKind::NotFound,
                message: "not found".into(),
            })],
        );
        let pause = FakePause::default();
        assert_eq!(wsl_state(Host::new(&runner, &pause)), WslState::Missing);
    }

    #[test]
    fn wsl_older_than_2_0_0_is_too_old() {
        let r = report(GOOD_PROBE, Output::with(0, utf16("WSL version: 1.2.5.0\r\n")))
            .0
            .unwrap();
        assert_eq!(
            r.failures(),
            vec![CheckFailure::WslTooOld {
                version: WslVersion {
                    major: 1,
                    minor: 2,
                    patch: 5,
                    build: 0
                },
                min: WslVersion::new(2, 0, 0)
            }]
        );
        assert!(r.needs_wsl_install());
        assert_eq!(r.failures()[0].code(), Some("wsl_too_old"));
        let r = report(GOOD_PROBE, Output::with(0, utf16("WSL version: 2.0.0.0")))
            .0
            .unwrap();
        assert!(r.passed());
    }

    #[test]
    fn wsl_version_is_the_first_dotted_triple_in_any_language() {
        assert_eq!(
            WslVersion::find_in("Versión de WSL: 2.0.14.0\nVersión de kernel: 5.15"),
            Some(WslVersion {
                major: 2,
                minor: 0,
                patch: 14,
                build: 0
            })
        );
        assert_eq!(WslVersion::find_in("WSL 2.6.1"), Some(WslVersion::new(2, 6, 1)));
        assert_eq!(WslVersion::find_in("version 2.6 only"), None);
        assert_eq!(WslVersion::find_in(""), None);
    }

    #[test]
    fn the_default_version_must_be_2_or_unset() {
        let r = report(&GOOD_PROBE.replace("default_version=", "default_version=1"), wsl_ok())
            .0
            .unwrap();
        assert_eq!(
            r.failures(),
            vec![CheckFailure::WslDefaultVersion { value: "1".into() }]
        );
        let r = report(&GOOD_PROBE.replace("default_version=", "default_version=2"), wsl_ok())
            .0
            .unwrap();
        assert!(r.passed());
    }

    #[test]
    fn virtualization_trusts_the_hypervisor_then_the_firmware_flag() {
        let cases = [
            ("hypervisor=True\nfirmware=False", Virtualization::HypervisorRunning),
            ("hypervisor=False\nfirmware=False,True", Virtualization::FirmwareEnabled),
            ("hypervisor=False\nfirmware=False", Virtualization::Disabled),
            ("hypervisor=\nfirmware=", Virtualization::Unknown),
        ];
        for (facts, want) in cases {
            let probe = GOOD_PROBE.replace("hypervisor=True\nfirmware=False", facts);
            let r = report(&probe, wsl_ok()).0.unwrap();
            assert_eq!(r.virtualization, want, "{facts}");
            assert_eq!(
                r.failures().contains(&CheckFailure::VirtualizationOff),
                want == Virtualization::Disabled
            );
            assert_eq!(
                r.warnings().contains(&CheckWarning::VirtualizationUnknown),
                want == Virtualization::Unknown
            );
        }
        assert_eq!(CheckFailure::VirtualizationOff.code(), Some("virtualization_off"));
    }

    #[test]
    fn free_space_is_counted_in_whole_gib_like_min_free_gb() {
        // 20 GiB minus one byte floors to 19: refused. Exactly 20 GiB: accepted, with the templates warning.
        let probe = GOOD_PROBE.replace("disk_free=214748364800", &format!("disk_free={}", 20 * GIB - 1));
        let r = report(&probe, wsl_ok()).0.unwrap();
        assert_eq!(
            r.failures(),
            vec![CheckFailure::DiskLow {
                free_gib: 19,
                needed_gib: 20
            }]
        );
        assert_eq!(r.failures()[0].code(), Some("disk_low"));
        assert!(
            !r.warnings()
                .iter()
                .any(|w| matches!(w, CheckWarning::DiskBelowTemplates { .. }))
        );
        let probe = GOOD_PROBE.replace("disk_free=214748364800", &format!("disk_free={}", 20 * GIB));
        let r = report(&probe, wsl_ok()).0.unwrap();
        assert!(r.passed());
        assert_eq!(
            r.warnings(),
            vec![CheckWarning::DiskBelowTemplates {
                free_gib: 20,
                wanted_gib: 86
            }]
        );
    }

    #[test]
    fn the_templates_warning_is_86_gib_by_default_and_106_on_the_hub() {
        let t = Thresholds::default();
        assert_eq!(t.templates_warning_gib(), 86);
        assert_eq!(
            Thresholds {
                blob_quota_gib: 20,
                ..t
            }
            .templates_warning_gib(),
            106
        );
        let probe = GOOD_PROBE.replace("disk_free=214748364800", &format!("disk_free={}", 86 * GIB));
        assert!(report(&probe, wsl_ok()).0.unwrap().warnings().is_empty());
        let probe = GOOD_PROBE.replace("disk_free=214748364800", &format!("disk_free={}", 86 * GIB - 1));
        assert_eq!(
            report(&probe, wsl_ok()).0.unwrap().warnings(),
            vec![CheckWarning::DiskBelowTemplates {
                free_gib: 85,
                wanted_gib: 86
            }]
        );
    }

    #[test]
    fn a_network_install_dir_or_an_unreadable_disk_fails() {
        let probe = GOOD_PROBE.replace("disk_free=214748364800", "disk=unc");
        assert_eq!(
            report(&probe, wsl_ok()).0.unwrap().failures(),
            vec![CheckFailure::InstallDirNotLocal]
        );
        let probe = GOOD_PROBE.replace("disk_free=214748364800", "disk=unknown");
        assert_eq!(
            report(&probe, wsl_ok()).0.unwrap().failures(),
            vec![CheckFailure::DiskUnknown]
        );
        let probe = GOOD_PROBE.replace("disk_free=214748364800", "disk_free=lots");
        assert_eq!(
            report(&probe, wsl_ok()).0.unwrap().failures(),
            vec![CheckFailure::DiskUnknown]
        );
    }

    #[test]
    fn a_missing_nvidia_driver_only_warns() {
        let probe = GOOD_PROBE.replace("nvidia=32.0.15.6094", "nvidia=");
        let r = report(&probe, wsl_ok()).0.unwrap();
        assert!(r.passed());
        assert_eq!(r.warnings(), vec![CheckWarning::NoNvidiaDriver]);
    }

    #[test]
    fn every_failure_is_listed_in_install_ps1_order() {
        let probe =
            "build=19041\nhypervisor=False\nfirmware=False\ndefault_version=1\ndisk_free=1\nnvidia=\nprobe=done\n";
        let r = report(probe, Output::with(1, Vec::new())).0.unwrap();
        let kinds: Vec<_> = r.failures().iter().map(std::mem::discriminant).collect();
        let want = [
            CheckFailure::WindowsTooOld { build: None, min: 0 },
            CheckFailure::WslMissing,
            CheckFailure::WslDefaultVersion { value: String::new() },
            CheckFailure::VirtualizationOff,
            CheckFailure::DiskLow {
                free_gib: 0,
                needed_gib: 0,
            },
        ];
        assert_eq!(kinds, want.iter().map(std::mem::discriminant).collect::<Vec<_>>());
        for f in r.failures() {
            assert!(!f.message().is_empty());
        }
    }

    #[test]
    fn a_probe_that_did_not_finish_is_an_error_not_a_verdict() {
        let (r, _) = report("build=26100\n", wsl_ok());
        assert!(matches!(r, Err(CheckError::Probe { .. })));
        let runner = FakeRunner::new();
        runner.on(|i| i.program() == POWERSHELL_EXE, Output::with(1, ""));
        let pause = FakePause::default();
        let r = run_checks(Host::new(&runner, &pause), Path::new("C:\\x"), Thresholds::default());
        assert!(matches!(r, Err(CheckError::Probe { .. })));
    }

    #[test]
    fn the_probe_changes_nothing() {
        // Read-only: no Set-, New-Item, Remove-, Enable-, wsl or schtasks in it.
        for verb in [
            "Set-", "New-Item", "Remove-", "Enable-", "Disable-", "wsl", "schtasks", "Invoke-",
        ] {
            assert!(!PROBE_SCRIPT.contains(verb), "{verb}");
        }
    }
}
