// SPDX-License-Identifier: Apache-2.0

//! The parity test with `deploy/wsl/install.ps1` (H2 §8.3: two implementations of the same rules).
//!
//! [`PORTED`] lists every `install.ps1` behaviour this crate ports, with the Rust item that does it. The tests below
//! read the script itself (compiled in with `include_str!`) and fail when a ported function disappears or is renamed,
//! or when a constant, a threshold, a command, a script run in the distro, a regular expression, the SDDL or a line of
//! the task's wrapper differs between the two. The behaviours themselves are unit-tested in each module.
//!
//! The deliberate differences, each pinned below so that it cannot drift silently:
//!
//! - the Windows build floor (22000 for the H2 app, §8.2);
//! - the upgrade's copy out of the distro: `install.ps1` redirects with `cmd.exe` (PowerShell 5.1 re-encodes piped
//!   bytes); Rust streams the child's stdout to the file itself. Both are byte-exact and both check the SHA-256;
//! - the task is removed with `schtasks /Delete` (the app never loads the ScheduledTasks module) instead of
//!   `Unregister-ScheduledTask`, and an unreadable task state stops the uninstall instead of reading as "no task";
//! - the backup's time stamp is UTC here and local time in `install.ps1` (`Get-Date -Format 'yyyyMMddHHmmss'`), so the
//!   names of backups from both do not order by time: the upgrade never prunes the backup it just verified;
//! - the uninstall deletes the whole of `%LOCALAPPDATA%\P2PC` (§8.7 step 5) where the script deletes its own files
//!   only; both apply the same backup rule.
//!
//! Running both implementations side by side on a Windows test node (install, upgrade carrying state, uninstall,
//! comparing the distro listing, the two state listings and the task XML) needs a node image and a real WSL; it is
//! listed as a follow-up of T2-45 (see its PR).

use crate::{checks, image, import, runner, task, uninstall, upgrade};

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
    // The upgrade (T2-45).
    (
        "Test-LinuxSafePath",
        "upgrade::is_linux_safe_path",
        "an absolute path of [A-Za-z0-9._/-]",
    ),
    (
        "Get-StateArchiveScript",
        "upgrade::state_archive_script",
        "the archive script writing to a validated path",
    ),
    (
        "Invoke-WslCopyOut",
        "upgrade::copy_out",
        "cat in the distro, stdout to a Windows file, byte-exact, not retried",
    ),
    (
        "Invoke-WslStream",
        "upgrade::copy_in",
        "a Windows file to the stdin of dd in the distro, retried on the WSL timeout",
    ),
    (
        "Assert-UpgradeDirClean",
        "upgrade::upgrade",
        "the distro directory holds only WSL's files, before anything is touched",
    ),
    (
        "Get-StateProbe",
        "upgrade::StateProbe::parse",
        "exit 0 and exactly one marker; anything else is unknown",
    ),
    (
        "Get-StateSize",
        "upgrade::StateSize::parse",
        "one p2pc line, at most one p2pc-server line",
    ),
    (
        "Get-VolumeRoot",
        "upgrade::FREE_SPACE_SCRIPT",
        "GetPathRoot(GetFullPath(path))",
    ),
    (
        "Get-FreeBytes",
        "upgrade::FREE_SPACE_SCRIPT",
        "DriveInfo.AvailableFreeSpace",
    ),
    (
        "Get-UpgradeSpaceNeeds",
        "upgrade::space_needs",
        "state + floor on the distro's volume, state on the backup's; both on one",
    ),
    (
        "Test-UpgradeSpace",
        "upgrade::upgrade",
        "refused (23) when a volume cannot hold its need",
    ),
    (
        "Get-ConfigMigrationResult",
        "upgrade::ConfigMigration::parse",
        "present, moved or created",
    ),
    (
        "Test-StateListingIgnored",
        "upgrade::is_listing_ignored",
        "sockets, FIFOs, p2pc/tmp and the boot status",
    ),
    ("Get-BackupDir", "Layout::backups_dir", "%LOCALAPPDATA%\\P2PC\\backups"),
    (
        "Get-BackupsToPrune",
        "upgrade::backups_to_prune",
        "verified backups beyond the newest N, nothing else",
    ),
    (
        "Get-StateListing",
        "upgrade::STATE_LISTING",
        "mode:uid:gid:type:path of both directories, sorted",
    ),
    (
        "Get-DistroFileHash",
        "upgrade::distro_file_hash",
        "sha256sum in the distro",
    ),
    (
        "Invoke-UpgradeAction",
        "upgrade::upgrade",
        "the task suspended and put back as it was",
    ),
    (
        "Invoke-UpgradeSteps",
        "upgrade::upgrade",
        "archive, copy out, unregister, import, copy in, restore, verify, prune",
    ),
    ("Get-DistroNow", "upgrade::upgrade", "date -u +%s in the distro"),
    (
        "Test-ServerSection",
        "upgrade::SERVER_SECTION_CHECK",
        "grep -q ^[server] agent.toml",
    ),
    ("Get-StatusField", "upgrade::status_field", "the value after <label>:"),
    (
        "Test-ConnectedSince",
        "upgrade::connected_since",
        "connected (since T), T no more than 2 s before the start",
    ),
    (
        "Wait-NodeConnected",
        "upgrade::wait_came_back",
        "a 60 s deadline on a monotonic clock, polled every 2 s",
    ),
    (
        "Get-NodeRunStop",
        "upgrade::node_run_stop",
        "state=stopped and exit_code=N",
    ),
    (
        "Clear-NodeStop",
        "upgrade::upgrade",
        "the stop record and node-run.status, after a fix of exit 6",
    ),
    (
        "Write-KeptBackupWarning",
        "upgrade::UpgradeFailure::kept_backup",
        "the backup of an unfinished upgrade is named",
    ),
    // The uninstall (T2-45).
    (
        "Test-StateBackupName",
        "upgrade::is_state_backup_name",
        "p2pc-state-<14 digits>(.ok).tar",
    ),
    (
        "Test-StateBackupVerified",
        "upgrade::is_verified_backup_name",
        "p2pc-state-<14 digits>.ok.tar",
    ),
    (
        "Get-StateBackupFiles",
        "uninstall::state_backup_files",
        "regular files with a backup's name, by kind",
    ),
    (
        "Get-UninstallPrompt",
        "uninstall::UninstallPlan",
        "what is deleted and what is kept, by full path",
    ),
    (
        "Remove-StateBackups",
        "uninstall::remove_local",
        "the rule's backups, then the folder when empty",
    ),
    (
        "Remove-NodeTaskFiles",
        "uninstall::remove_local",
        "the wrapper and the stop record (the whole folder in the app)",
    ),
    (
        "Remove-NodeTask",
        "uninstall::remove_task",
        "end, then delete; a failure stops before the distro (37)",
    ),
    (
        "Invoke-UninstallAction",
        "uninstall::uninstall",
        "the task, then wsl --unregister (29), then the backups",
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

/// The body of `function <name> {` up to the next top-level function.
fn ps_function(name: &str) -> &'static str {
    INSTALL_PS1
        .split(&format!("function {name} {{"))
        .nth(1)
        .and_then(|rest| rest.split("\nfunction ").next())
        .unwrap_or_else(|| panic!("{name} not found in install.ps1"))
}

/// `a` comes before `b` in `text`.
fn before(text: &str, a: &str, b: &str) -> bool {
    match (text.find(a), text.find(b)) {
        (Some(x), Some(y)) => x < y,
        _ => panic!("{a:?} or {b:?} missing"),
    }
}

#[test]
fn the_scripts_run_in_the_distro_match_byte_for_byte() {
    for (var, quote, rust) in [
        ("StateProbeScript", '\'', upgrade::STATE_PROBE_SCRIPT),
        ("StateSizeScript", '\'', upgrade::STATE_SIZE_SCRIPT),
        ("StateArchiveScript", '"', upgrade::STATE_ARCHIVE_SCRIPT),
        ("ConfigMigrationScript", '"', upgrade::CONFIG_MIGRATION_SCRIPT),
    ] {
        let line = format!("${var} = {quote}{rust}{quote}\n");
        assert!(INSTALL_PS1.contains(&line), "${var} differs from upgrade.rs");
    }
    assert!(INSTALL_PS1.contains("$StateArchiveScript.Replace('@OUT@', $OutPath)"));
    assert!(INSTALL_PS1.contains(&format!("$AgentConfigPath = '{}'", upgrade::AGENT_CONFIG_PATH)));
    assert!(INSTALL_PS1.contains(&format!("$AgentPath = '{}'", upgrade::AGENT_PATH)));
    // `p2pc-agent status` with the agent config named, without a shell (Get-AgentCommand on the 0.2.2 layout).
    assert!(INSTALL_PS1.contains("@('/usr/bin/env', ('P2PC_AGENT_CONFIG=' + $AgentConfigPath), $AgentPath)"));
    assert!(INSTALL_PS1.contains("(Invoke-InDistro (@(Get-AgentCommand) + @('status')))"));
}

#[test]
fn the_upgrade_commands_and_constants_match() {
    let mut listing: Vec<&str> = upgrade::STATE_LISTING.to_vec();
    listing.push(upgrade::STATE_LISTING_FORMAT);
    assert!(INSTALL_PS1.contains(&format!("Invoke-InDistro {}", ps_array(&listing))));
    assert!(INSTALL_PS1.contains("Invoke-InDistro @('/bin/grep', '-q', '^\\[server\\]', $AgentConfigPath)"));
    assert_eq!(upgrade::SERVER_SECTION_CHECK[..3], ["/bin/grep", "-q", "^\\[server\\]"]);
    assert!(INSTALL_PS1.contains(&format!("$inDistroTar = '{}'", upgrade::IN_DISTRO_TAR)));
    assert!(INSTALL_PS1.contains("('/var/tmp/p2pc-state-{0}.tar' -f $stamp)"));
    assert!(INSTALL_PS1.contains("('p2pc-state-{0}.tar' -f $stamp)"));
    assert!(INSTALL_PS1.contains("$stamp = Get-Date -Format 'yyyyMMddHHmmss'"));
    assert!(INSTALL_PS1.contains("$doneFile = $stateFile -replace '\\.tar$', '.ok.tar'"));
    assert!(INSTALL_PS1.contains(&format!("$BackupKeep = {}", upgrade::BACKUP_KEEP)));
    assert!(
        INSTALL_PS1.contains("$keep = 1"),
        "one verified backup when it holds the hub's data"
    );
    // The pipes.
    assert!(INSTALL_PS1.contains("Invoke-InDistro @('/bin/bash', '-c', (Get-StateArchiveScript $inDistroBackup))"));
    assert!(INSTALL_PS1.contains("--exec /bin/cat {1} > \"{2}\""));
    assert!(INSTALL_PS1.contains("\"-d {0} -u root --exec /bin/dd of={1} bs=1M status=none\""));
    assert!(INSTALL_PS1.contains("Invoke-InDistro @('/usr/bin/install', '-m', '0600', '/dev/null', $inDistroTar)"));
    assert!(INSTALL_PS1.contains("Invoke-InDistro @('/usr/bin/sha256sum', $LinuxPath)"));
    assert!(
        INSTALL_PS1
            .contains("Invoke-InDistro @('/bin/tar', '--numeric-owner', '-C', '/var/lib', '-xpf', $inDistroTar)")
    );
    assert!(INSTALL_PS1.contains("Invoke-InDistro @('/bin/rm', '-f', $inDistroBackup)"));
    assert!(INSTALL_PS1.contains("Invoke-InDistro @('/bin/rm', '-f', $inDistroTar)"));
    assert!(INSTALL_PS1.contains("Invoke-InDistro @('/bin/rm', '-f', $NodeRunStatusPath)"));
    assert!(INSTALL_PS1.contains("Invoke-InDistro @('/bin/date', '-u', '+%s')"));
    assert!(INSTALL_PS1.contains("Invoke-Wsl @('--unregister', $DistroName)"));
    // The space rule.
    let needs = ps_function("Get-UpgradeSpaceNeeds");
    for line in [
        "$needs[$d] = $StateBytes + $MinFree",
        "if ($needs.Contains($b)) { $needs[$b] += $StateBytes } else { $needs[$b] = $StateBytes }",
    ] {
        assert!(needs.contains(line), "{line}");
    }
    assert!(INSTALL_PS1.contains("[System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($Path))"));
    assert!(upgrade::FREE_SPACE_SCRIPT.contains("[System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($p))"));
    assert!(INSTALL_PS1.contains("(New-Object System.IO.DriveInfo($Root)).AvailableFreeSpace"));
    assert!(upgrade::FREE_SPACE_SCRIPT.contains("(New-Object System.IO.DriveInfo($root)).AvailableFreeSpace"));
    assert!(INSTALL_PS1.contains("[long]$Size.TotalKB * 1KB"));
    assert!(INSTALL_PS1.contains("([long]$MinFreeGB * 1GB)"));
    // The coming back.
    assert!(INSTALL_PS1.contains(&format!("$ConnectWaitSeconds = {}", upgrade::CONNECT_WAIT.as_secs())));
    assert!(INSTALL_PS1.contains(&format!(
        "$ConnectedSinceSlackSeconds = {}",
        upgrade::CONNECTED_SINCE_SLACK_SECS
    )));
    assert!(
        ps_function("Wait-NodeConnected")
            .contains(&format!("Start-Sleep -Seconds {}", upgrade::CONNECT_POLL.as_secs()))
    );
    assert!(INSTALL_PS1.contains("'^connected \\(since ([^)]+)\\)'"));
    assert!(INSTALL_PS1.contains("'(?m)^state=stopped\\s*$'"));
    assert!(INSTALL_PS1.contains("'(?m)^exit_code=([0-9]+)\\s*$'"));
    assert!(INSTALL_PS1.contains("Get-StatusField $text 'Connection'"));
    // Only 6 is fixed by a newer image; a stop record decides whatever the task's state.
    assert!(INSTALL_PS1.contains("$taskWasEnabled = ($stop.Code -eq 6)"));
    assert!(INSTALL_PS1.contains("$null = Register-NodeTask -Disabled -WarnOnFailure"));
}

#[test]
fn the_regular_expressions_and_their_ports_agree() {
    assert!(INSTALL_PS1.contains("$Path -match '^/[A-Za-z0-9._/-]+$'"));
    assert!(INSTALL_PS1.contains("$Line -match '^[0-9]+:[0-9]+:[0-9]+:[sp]:'"));
    assert!(INSTALL_PS1.contains("$Line -match ':p2pc/(tmp|tmp/.*|boot-status\\.json|\\.boot-status\\..*)$'"));
    assert!(INSTALL_PS1.contains("$_ -match '^p2pc-state-[0-9]{14}\\.ok\\.tar$'"));
    assert!(INSTALL_PS1.contains("$Name -match '^p2pc-state-[0-9]{14}(\\.ok)?\\.tar$'"));
    assert!(INSTALL_PS1.contains("$Name -match '^p2pc-state-[0-9]{14}\\.ok\\.tar$'"));
    // The probe's and the migration's markers.
    for m in ["P2PC_STATE=present", "P2PC_STATE=absent", "P2PC_STATE=hub-only"] {
        assert!(ps_function("Get-StateProbe").contains(&format!("'{m}'")), "{m}");
    }
    for m in ["P2PC_CONFIG=present", "P2PC_CONFIG=moved", "P2PC_CONFIG=created"] {
        assert!(
            ps_function("Get-ConfigMigrationResult").contains(&format!("'{m}'")),
            "{m}"
        );
    }
    assert!(ps_function("Get-StateSize").contains("'^([0-9]+)\\s+(/var/lib/p2pc|/var/lib/p2pc-server)$'"));
}

#[test]
fn the_uninstall_order_and_its_stops_match() {
    let body = ps_function("Invoke-UninstallAction");
    assert!(before(
        body,
        "if (Test-NodeTaskRegistered) { Remove-NodeTask }",
        "Invoke-Wsl @('--unregister', $DistroName)"
    ));
    assert!(before(
        body,
        "Invoke-Wsl @('--unregister', $DistroName)",
        "Remove-StateBackups"
    ));
    assert!(body.contains("Fail 29 'wsl --unregister failed.'"));
    let rm = ps_function("Remove-NodeTask");
    assert!(before(rm, "Stop-NodeTask", "Unregister-ScheduledTask"));
    assert!(rm.contains("Fail 37"));
    // The default rule: verified ones go; unfinished ones stay unless -DeleteFailedBackups.
    assert!(body.contains("$kind = 'Verified'"));
    assert!(body.contains("if ($mode -eq 'DeleteAll') { $kind = 'All' }"));
    // The deliberate difference: the app deletes the task with schtasks.
    let inv = uninstall::delete_task_invocation();
    assert_eq!(inv.program(), runner::SCHTASKS_EXE);
    assert_eq!(inv.arguments(), ["/Delete", "/TN", task::TASK_PATH, "/F"]);
}
