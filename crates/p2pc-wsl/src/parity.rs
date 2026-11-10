// SPDX-License-Identifier: Apache-2.0

//! The parity test with `deploy/wsl/install.ps1` (H2 §8.3: two implementations of the same rules).
//!
//! [`PORTED`] lists every `install.ps1` behaviour this crate ports, with the Rust item that does it. The tests below
//! read the script itself (compiled in with `include_str!`) and fail when a ported function disappears or is renamed,
//! or when a constant, a threshold, a command, the SDDL or a line of the task's wrapper differs between the two. The
//! behaviours themselves are unit-tested in each module; the run of both implementations side by side on the Windows CI
//! runner (checks, install, upgrade, uninstall, comparing the resulting state) is T2-45's.

use crate::{checks, image, import, runner, task};

/// The script, as it is in the repository.
const INSTALL_PS1: &str = include_str!("../../../deploy/wsl/install.ps1");

/// Every ported behaviour: (`install.ps1` function, the Rust item, what it does).
pub(crate) const PORTED: &[(&str, &str, &str)] = &[
    // The wsl.exe rules.
    (
        "Test-WslServiceTimeout",
        "runner::is_wsl_service_timeout",
        "matches Wsl/Service/0x8007274c in any case",
    ),
    (
        "Invoke-WithWslRetry",
        "runner::Host::run_wsl",
        "retries only that error, 3 times, 5 s apart",
    ),
    (
        "Invoke-WslOnce",
        "runner::decode_text",
        "reads wsl.exe's UTF-16LE messages, strips NULs and the BOM",
    ),
    (
        "Invoke-InDistro",
        "runner::in_distro",
        "wsl -d p2pc-node -u root --exec <argv>, no shell",
    ),
    (
        "Test-TokenLikeParameters",
        "runner::Invocation::check_no_secret",
        "no join token (nor API key) on a command line",
    ),
    // The checks.
    (
        "Test-WindowsBuild",
        "checks::ChecksReport::failures",
        "the build floor (22000 for the H2 app, §8.2)",
    ),
    (
        "Test-Wsl",
        "checks::wsl_state",
        "wsl.exe missing or `--version` failing is missing; < 2.0.0 is too old",
    ),
    (
        "Test-WslDefaultVersion",
        "checks::ChecksReport::failures",
        "DefaultVersion unset or 2",
    ),
    (
        "Test-Virtualization",
        "checks::run_checks",
        "the hypervisor first, then the firmware flag; unknown warns",
    ),
    (
        "Test-DiskSpace",
        "checks::ChecksReport::failures",
        "floor(free / 2^30) >= 20 on a local drive",
    ),
    (
        "Test-Prerequisites",
        "checks::ChecksReport::failures",
        "the checks' order",
    ),
    // The image.
    (
        "Test-Image",
        "image::verify_with_checksum_file",
        "<tar>.sha256, its first line's 64 hex digits, SHA-256 match",
    ),
    // The import.
    ("Get-DistroNames", "import::distro_names", "wsl --list --quiet"),
    ("Test-DistroExists", "import::distro_exists", "an exact p2pc-node line"),
    (
        "Test-DistroDirNames",
        "import::check_distro_dir",
        "only ext4.vhdx and shortcut.ico, any case",
    ),
    (
        "Get-ForeignNames",
        "import::foreign_names",
        "the names that are not WSL's own",
    ),
    (
        "Import-Distro",
        "import::import_distro",
        "wsl --import p2pc-node <dir> <tar> --version 2",
    ),
    (
        "Test-NewDistro",
        "import::verify_distro",
        "version file, /var/lib/p2pc 700, no /mnt/c, p2pc-boot",
    ),
    (
        "Get-ProcStarttime",
        "import::proc_starttime",
        "field 22 after the last ')'",
    ),
    (
        "Get-BootStatusFields",
        "import::BootStatus::parse",
        "init_starttime, time, cdi, errors, notes",
    ),
    (
        "Test-BootStatusFresh",
        "import::BootStatus::is_fresh",
        "fresh by init identity, never by time",
    ),
    (
        "Wait-BootStatus",
        "import::wait_boot_status",
        "polls once a second for 30 s; none is a warning",
    ),
    (
        "Show-BootStatus",
        "import::BootStatus::has_problems",
        "nvidia_smi_failed or any error warns",
    ),
    (
        "Invoke-Install",
        "import::install",
        "import unless it exists, verify, wait for the boot status",
    ),
    // The scheduled task.
    (
        "Get-NodeTaskDefinition",
        "task::task_xml",
        "conhost --headless, no time limit, 999 restarts 1 min apart, battery, IgnoreNew, StartWhenAvailable, Limited",
    ),
    (
        "Get-NodeTaskTriggerKinds",
        "task::Triggers::WatchdogAndLogon",
        "every 5 minutes with no end, and at this user's logon",
    ),
    (
        "Get-TimeTriggerOnlyAdvice",
        "task::Triggers::WATCHDOG_ONLY_ADVICE",
        "what the user is told after the fallback",
    ),
    (
        "Get-NodeTaskWrapperPath",
        "Layout::task_wrapper",
        "%LOCALAPPDATA%\\P2PC\\node-task.cmd",
    ),
    (
        "Get-NodeStopRecordPath",
        "Layout::stop_record",
        "%LOCALAPPDATA%\\P2PC\\stopped-by-node",
    ),
    (
        "Get-NodeTaskWrapperContent",
        "task::wrapper_lines",
        "the wrapper: exit 64 disables the task, records why, terminates",
    ),
    (
        "Write-NodeTaskWrapper",
        "task::write_wrapper",
        "ASCII, CRLF, only on a cmd-safe path",
    ),
    ("Test-CmdSafePath", "task::is_cmd_safe_path", "no % and no \""),
    (
        "Get-NodeTaskSddl",
        "task::task_sddl",
        "full control for SYSTEM, Administrators and the user",
    ),
    (
        "Set-NodeTaskRights",
        "task::register",
        "set after registering; a refusal only warns",
    ),
    (
        "Set-NodeTaskSddl",
        "task::SDDL_SCRIPT",
        "Schedule.Service GetTask(...).SetSecurityDescriptor(sddl, 0)",
    ),
    (
        "Get-CurrentUserSid",
        "task::current_identity",
        "WindowsIdentity.GetCurrent().User.Value",
    ),
    (
        "Get-CurrentUserName",
        "task::current_identity",
        "WindowsIdentity.GetCurrent().Name",
    ),
    (
        "Register-NodeTaskWithTriggers",
        "task::register",
        "wrapper first, then create or replace, then the rights",
    ),
    (
        "Register-NodeTask",
        "task::register",
        "both triggers, else the watchdog alone, else an error",
    ),
    ("Get-NodeTaskState", "task::state", "Get-ScheduledTask's State"),
    ("Start-NodeTask", "task::start", "schtasks /Run"),
    ("Stop-NodeTask", "task::end", "schtasks /End"),
    ("Disable-NodeTask", "task::disable", "schtasks /Change /DISABLE"),
    ("Enable-NodeTask", "task::enable", "schtasks /Change /ENABLE"),
    (
        "Suspend-NodeTask",
        "task::suspend",
        "disable, end, wsl --terminate p2pc-node",
    ),
    ("Resume-NodeTask", "task::resume", "enable, then start"),
    (
        "Read-NodeStopRecord",
        "task::StopRecord::parse",
        "exit_code, time, reason, disabled (the file part)",
    ),
];

/// The PowerShell array literal `@('a', 'b')` of an argument vector, as `install.ps1` writes it.
fn ps_array(args: &[&str]) -> String {
    let quoted: Vec<String> = args.iter().map(|a| format!("'{}'", a.replace('\'', "''"))).collect();
    format!("@({})", quoted.join(", "))
}

/// The lines `Get-NodeTaskWrapperContent` returns, rendered: `'literal'` or `('format' -f $Var, $Var)`.
fn ps_wrapper_lines() -> Vec<String> {
    let body = INSTALL_PS1
        .split("function Get-NodeTaskWrapperContent {")
        .nth(1)
        .and_then(|rest| rest.split("return @(").nth(1))
        .and_then(|rest| rest.split("\n    )").next())
        .unwrap_or_else(|| panic!("Get-NodeTaskWrapperContent not found in install.ps1"));
    let var = |name: &str| match name.trim() {
        "$DistroName" => crate::DISTRO_NAME,
        "$NodeRunPath" => task::NODE_RUN_PATH,
        "$NodeRunStatusPath" => task::NODE_RUN_STATUS_PATH,
        "$TaskName" => task::TASK_NAME,
        other => panic!("unknown variable {other} in the wrapper"),
    };
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            let l = l.trim_end_matches(',');
            let rendered = if let Some(f) = l.strip_prefix("('") {
                let (fmt, args) = f.split_once("' -f ").unwrap_or_else(|| panic!("bad line {l}"));
                let args = args.trim_end_matches(')');
                args.split(',')
                    .enumerate()
                    .fold(fmt.to_owned(), |acc, (i, a)| acc.replace(&format!("{{{i}}}"), var(a)))
            } else {
                l.strip_prefix('\'')
                    .and_then(|s| s.strip_suffix('\''))
                    .unwrap_or_else(|| panic!("bad line {l}"))
                    .to_owned()
            };
            rendered.replace("''", "'")
        })
        .collect()
}

#[test]
fn every_ported_function_still_exists_in_install_ps1() {
    for (function, rust, what) in PORTED {
        assert!(
            INSTALL_PS1.contains(&format!("function {function} {{")),
            "install.ps1 no longer has {function} (ported as {rust}: {what}); update the port and this table"
        );
    }
    // No function is listed twice.
    let mut names: Vec<&str> = PORTED.iter().map(|p| p.0).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), PORTED.len());
}

#[test]
fn the_wsl_rules_match() {
    assert!(INSTALL_PS1.contains(&format!("$DistroName = '{}'", crate::DISTRO_NAME)));
    assert!(INSTALL_PS1.contains(&format!("$WslRetryCount = {}", runner::WSL_RETRY_COUNT)));
    assert!(INSTALL_PS1.contains(&format!(
        "$WslRetryDelaySeconds = {}",
        runner::WSL_RETRY_DELAY.as_secs()
    )));
    assert!(INSTALL_PS1.contains(&format!("'(?i){}'", runner::WSL_SERVICE_TIMEOUT)));
    assert!(INSTALL_PS1.contains("@('-d', $DistroName, '-u', 'root', '--exec')"));
    assert!(INSTALL_PS1.contains("-match '^\\s*p2pc_join_'"));
}

#[test]
fn the_check_thresholds_match() {
    let t = checks::Thresholds::default();
    let v = t.min_wsl;
    assert!(INSTALL_PS1.contains(&format!(
        "$MinWslVersion = [version]'{}.{}.{}'",
        v.major, v.minor, v.patch
    )));
    assert!(INSTALL_PS1.contains(&format!("[int]$MinFreeGB = {}", t.min_free_gib)));
    // `-MinFreeGB` counts with PowerShell's 1GB, which is 2^30 bytes, floored.
    assert!(INSTALL_PS1.contains("[math]::Floor($drive.AvailableFreeSpace / 1GB)"));
    assert_eq!(checks::GIB, 1 << 30);
    // The one deliberate difference: H2 §8.2 supports Windows 11 only.
    assert!(INSTALL_PS1.contains("$MinWindowsBuild = 19044"));
    assert_eq!(t.min_windows_build, 22000);
    // The same sources of truth.
    for source in [
        "Win32_OperatingSystem",
        "[Environment]::OSVersion.Version.Build",
        "Win32_ComputerSystem",
        ".HypervisorPresent",
        "Win32_Processor",
        "VirtualizationFirmwareEnabled",
        "-Name DefaultVersion",
        "[System.IO.Path]::GetPathRoot($full)",
        "$root.StartsWith('\\\\')",
        "AvailableFreeSpace",
    ] {
        assert!(INSTALL_PS1.contains(source), "install.ps1: {source}");
        assert!(checks::PROBE_SCRIPT.contains(source), "probe: {source}");
    }
    assert!(INSTALL_PS1.contains("'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss'"));
    assert!(checks::PROBE_SCRIPT.contains("'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss'"));
    assert!(INSTALL_PS1.contains("Invoke-Wsl @('--version')"));
    assert!(INSTALL_PS1.contains("'\\d+\\.\\d+\\.\\d+(\\.\\d+)?'"));
}

#[test]
fn the_image_check_matches() {
    assert!(INSTALL_PS1.contains("$shaFile = $Tar + '.sha256'"));
    assert!(INSTALL_PS1.contains("'^\\s*([0-9a-fA-F]{64})\\b'"));
    assert!(INSTALL_PS1.contains("Get-FileHash -LiteralPath $Tar -Algorithm SHA256"));
    let hex = "ab".repeat(32);
    assert!(image::Sha256Digest::from_checksum_file(&format!("{hex}  p2pc-node.tar.gz")).is_ok());
}

#[test]
fn the_import_matches() {
    assert!(INSTALL_PS1.contains(&format!("$WslOwnedFiles = {}", ps_array(&import::WSL_OWNED_FILES))));
    assert!(INSTALL_PS1.contains("Invoke-Wsl @('--import', $DistroName, $Dir, $TarPath, '--version', '2')"));
    assert!(INSTALL_PS1.contains("Invoke-Wsl @('--list', '--quiet')"));
    for check in [
        &import::VERIFY_VERSION[..],
        &import::VERIFY_STATE_MODE[..],
        &import::VERIFY_NO_MNT_C[..],
        &import::VERIFY_BOOT[..],
    ] {
        assert!(
            INSTALL_PS1.contains(&format!("Invoke-InDistro {}", ps_array(check))),
            "{check:?}"
        );
    }
    assert!(INSTALL_PS1.contains("$mode.Output.Trim() -ne '700'"));
    assert!(INSTALL_PS1.contains(&format!(
        "$BootStatusWaitSeconds = {}",
        import::BOOT_STATUS_WAIT.as_secs()
    )));
    assert!(INSTALL_PS1.contains(&format!("Invoke-InDistro {}", ps_array(&["/bin/cat", "/proc/1/stat"]))));
    assert!(INSTALL_PS1.contains(&format!(
        "Invoke-InDistro {}",
        ps_array(&["/bin/cat", import::BOOT_STATUS_PATH])
    )));
    assert!(INSTALL_PS1.contains("$fields[19]"));
    assert!(INSTALL_PS1.contains("$f.Cdi -eq 'nvidia_smi_failed' -or $f.Errors.Count -gt 0"));
}

#[test]
fn the_task_definition_matches() {
    assert!(INSTALL_PS1.contains(&format!("$TaskName = '{}'", task::TASK_NAME)));
    assert!(INSTALL_PS1.contains(&format!("$NodeRunPath = '{}'", task::NODE_RUN_PATH)));
    assert!(INSTALL_PS1.contains(&format!("$NodeRunStatusPath = '{}'", task::NODE_RUN_STATUS_PATH)));
    assert!(INSTALL_PS1.contains(&format!("RepeatMinutes = {}", task::REPEAT_MINUTES)));
    assert!(INSTALL_PS1.contains(&format!("RestartCount = {} ", task::RESTART_COUNT)));
    assert!(INSTALL_PS1.contains(&format!("RestartIntervalMinutes = {} ", task::RESTART_INTERVAL_MINUTES)));
    assert!(INSTALL_PS1.contains("ExecutionTimeLimit = [TimeSpan]::Zero"));
    assert!(INSTALL_PS1.contains("AllowOnBattery = $true"));
    assert!(INSTALL_PS1.contains("RunLevel = 'Limited'"));
    assert!(INSTALL_PS1.contains("MultipleInstances = 'IgnoreNew'"));
    assert!(INSTALL_PS1.contains("StartWhenAvailable = $true"));
    assert!(INSTALL_PS1.contains("-LogonType Interactive"));
    assert!(INSTALL_PS1.contains("New-ScheduledTaskTrigger -AtLogOn -User $user"));
    assert!(INSTALL_PS1.contains("$t.Repetition.Duration = ''"));
    assert!(INSTALL_PS1.contains("return @('Every5Minutes', 'AtLogOn')"));
    assert!(INSTALL_PS1.contains("$kinds = @('Every5Minutes')"));
    // The action, the wrapper's place, the SDDL and how it is set.
    assert!(
        INSTALL_PS1.contains("Argument = ('--headless cmd.exe /d /s /c \"\"{0}\"\"' -f (Get-NodeTaskWrapperPath))")
    );
    assert_eq!(task::action_arguments("{0}"), "--headless cmd.exe /d /s /c \"\"{0}\"\"");
    assert!(INSTALL_PS1.contains("'\\System32\\conhost.exe'"));
    assert!(INSTALL_PS1.contains("'\\P2PC\\node-task.cmd'"));
    assert!(INSTALL_PS1.contains("'\\P2PC\\stopped-by-node'"));
    assert!(INSTALL_PS1.contains("return ('D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{0})' -f $UserSid)"));
    assert_eq!(
        task::task_sddl("S-1-5-21-1-2-3-1001").ok().as_deref(),
        Some("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)")
    );
    assert!(INSTALL_PS1.contains("New-Object -ComObject Schedule.Service"));
    assert!(INSTALL_PS1.contains("GetFolder('\\').GetTask($TaskName).SetSecurityDescriptor($Sddl, 0)"));
    assert!(
        task::SDDL_SCRIPT
            .contains("GetFolder('\\').GetTask('P2PC node').SetSecurityDescriptor($env:P2PC_TASK_SDDL, 0)")
    );
    assert!(INSTALL_PS1.contains("[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"));
    assert!(task::IDENTITY_SCRIPT.contains("[System.Security.Principal.WindowsIdentity]::GetCurrent()"));
    assert!(INSTALL_PS1.contains("Get-ScheduledTask -TaskName $TaskName -TaskPath '\\'"));
    assert!(task::STATE_SCRIPT.contains("Get-ScheduledTask -TaskName 'P2PC node' -TaskPath '\\'"));
    assert!(INSTALL_PS1.contains("Invoke-Wsl @('--terminate', $DistroName)"));
    assert!(INSTALL_PS1.contains("[System.Text.Encoding]::ASCII"));
    assert!(INSTALL_PS1.contains("-join \"`r`n\") + \"`r`n\""));
}

#[test]
fn the_wrapper_lines_match_except_the_comments() {
    let not_rem = |l: &&String| !l.starts_with("rem ");
    let ps: Vec<String> = ps_wrapper_lines();
    let rust = task::wrapper_lines();
    assert_eq!(
        ps.iter().filter(not_rem).collect::<Vec<_>>(),
        rust.iter().filter(not_rem).collect::<Vec<_>>()
    );
    assert_eq!(ps.len(), rust.len(), "the same number of lines (comments included)");
}
