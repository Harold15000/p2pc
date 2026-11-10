// SPDX-License-Identifier: Apache-2.0

//! The scheduled task "P2PC node" (H2 §8.3, H1 §9.0 "How the Windows agent stays up"): `install.ps1`'s
//! `Register-NodeTask` and its helpers, registered from a task XML through `schtasks /Create /XML` under the user's own
//! token.
//!
//! - **The action** is a small wrapper the app writes and owns, `%LOCALAPPDATA%\P2PC\node-task.cmd`, run as
//!   `conhost.exe --headless cmd.exe /d /s /c ""<wrapper>""` (no window). It runs the node's supervisor in the distro;
//!   when that exits 64 (the agent stopped for good: 6 too old, 7 removed, 8 not joined) it writes why in
//!   `stopped-by-node`, disables the task (the watchdog must not start such a node again and again) and terminates the
//!   distro. Its lines are `install.ps1`'s, byte for byte apart from the comments (the parity test pins them).
//! - **The triggers**: a time trigger repeating every 5 minutes with no end (the watchdog: with `IgnoreNew` it does
//!   nothing while the node runs) and a logon trigger for this user only. If Windows refuses the registration, it is
//!   registered again with the time trigger alone ([`Triggers::WatchdogOnly`]: the node starts within 5 minutes of
//!   sign-in). Nothing else is ever a fallback.
//! - **The settings**: as you, never elevated (`InteractiveToken`, `LeastPrivilege`); no time limit; restarted on
//!   failure every minute, 999 times; allowed on battery; `IgnoreNew`; `StartWhenAvailable`.
//! - **The rights**: after registering, full control for SYSTEM, Administrators and the user
//!   (`D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<SID>)`) through the Task Scheduler COM API, so that the user's own
//!   non-elevated wrapper can always disable it. A refusal only warns: the task stays registered.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::runner::{Host, RunError, powershell, schtasks as schtasks_invocation};
use crate::{DISTRO_NAME, Layout};

/// The task's name (`$TaskName`).
pub const TASK_NAME: &str = "P2PC node";
/// The task's full path in the root folder, as `schtasks /TN` takes it.
pub const TASK_PATH: &str = "\\P2PC node";
/// The node's supervisor in the distro (`$NodeRunPath`). H2 §8.5's `p2pc-run` keeps this path as a symlink for one
/// release.
pub const NODE_RUN_PATH: &str = "/usr/local/sbin/p2pc-node-run";
/// Where the supervisor records why it stopped (`$NodeRunStatusPath`).
pub const NODE_RUN_STATUS_PATH: &str = "/var/lib/p2pc/node-run.status";
/// The supervisor's exit code for "stopped for good".
pub const TERMINAL_EXIT: i32 = 64;
/// The watchdog's period (`RepeatMinutes`).
pub const REPEAT_MINUTES: u32 = 5;
/// Restart on failure: this many times (`RestartCount`)…
pub const RESTART_COUNT: u32 = 999;
/// …this many minutes apart (`RestartIntervalMinutes`).
pub const RESTART_INTERVAL_MINUTES: u32 = 1;
/// The task's description.
pub const DESCRIPTION: &str =
    "P2PC node: keeps the p2pc-node WSL distro and its agent running (installed by the P2PC app).";

/// What can go wrong with the task.
#[derive(Debug, thiserror::Error)]
pub enum TaskError {
    /// The wrapper's path holds `%` or `"`, which cannot sit inside quotes on a cmd.exe command line.
    #[error("the task wrapper path cannot be quoted for cmd.exe (it holds a percent sign or a double quote): {0}")]
    UnsafeWrapperPath(String),
    /// The user's SID is not a SID.
    #[error("not a Windows SID: {0}")]
    BadSid(String),
    /// The current user could not be read.
    #[error("the current Windows user could not be read: {0}")]
    Identity(String),
    /// Not even the time trigger alone could be registered (`install.ps1` exit 35).
    #[error("could not register the scheduled task '{TASK_NAME}', even with the 5-minute trigger only: {message}")]
    Register { message: String },
    /// A `schtasks` operation failed.
    #[error("schtasks {op} failed (exit {code:?}): {message}")]
    Schtasks {
        op: &'static str,
        code: Option<i32>,
        message: String,
    },
    /// The task's state could not be read.
    #[error("the state of the scheduled task could not be read: {0}")]
    State(String),
    #[error(transparent)]
    Run(#[from] RunError),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

/// A Windows path that can sit inside double quotes on a cmd.exe command line: inside quotes cmd treats everything
/// literally except `%VAR%` expansion, and a quote ends the string; so those two are refused (`Test-CmdSafePath`).
pub fn is_cmd_safe_path(path: &str) -> bool {
    !path.is_empty() && !path.contains(['%', '"'])
}

/// The lines of `node-task.cmd` (`Get-NodeTaskWrapperContent`). ASCII only.
pub fn wrapper_lines() -> Vec<String> {
    vec![
        "@echo off".to_owned(),
        "rem P2PC node: the action of the Scheduled Task \"P2PC node\". Written by the P2PC app; do not edit.".to_owned(),
        "rem On exit 64 (the agent stopped for good) it disables the task and writes why in stopped-by-node, next to it.".to_owned(),
        "rem The app enables the task again when the node is started on purpose (H1 spec 9.0, H2 spec 8.3).".to_owned(),
        format!("wsl.exe -d {DISTRO_NAME} -u root --exec {NODE_RUN_PATH}"),
        "set \"P2PC_RC=%ERRORLEVEL%\"".to_owned(),
        format!("if not \"%P2PC_RC%\"==\"{TERMINAL_EXIT}\" exit /b %P2PC_RC%"),
        format!("> \"%~dp0stopped-by-node\" echo node_exit={TERMINAL_EXIT}"),
        format!(
            ">> \"%~dp0stopped-by-node\" wsl.exe -d {DISTRO_NAME} -u root --exec /bin/grep -E \"^(exit_code|time|reason)=\" {NODE_RUN_STATUS_PATH}"
        ),
        format!("schtasks /Change /TN \"{TASK_PATH}\" /DISABLE >nul 2>&1"),
        "if errorlevel 1 (>> \"%~dp0stopped-by-node\" echo disabled=no) else (>> \"%~dp0stopped-by-node\" echo disabled=yes)".to_owned(),
        format!(">nul 2>&1 wsl.exe --terminate {DISTRO_NAME}"),
        format!("exit /b {TERMINAL_EXIT}"),
    ]
}

/// The wrapper file's bytes: the lines, CRLF, ASCII (`Write-NodeTaskWrapper`).
pub fn wrapper_content() -> String {
    let mut s = wrapper_lines().join("\r\n");
    s.push_str("\r\n");
    s
}

/// Writes the wrapper, after checking its path can be quoted for cmd.exe. Returns its path.
pub fn write_wrapper(layout: &Layout) -> Result<PathBuf, TaskError> {
    let path = layout.task_wrapper();
    let shown = path.display().to_string();
    if !is_cmd_safe_path(&shown) {
        return Err(TaskError::UnsafeWrapperPath(shown));
    }
    fs::create_dir_all(layout.root()).map_err(|source| TaskError::Io {
        context: format!("creating {}", layout.root().display()),
        source,
    })?;
    fs::write(&path, wrapper_content()).map_err(|source| TaskError::Io {
        context: format!("writing {shown}"),
        source,
    })?;
    Ok(path)
}

/// The action's arguments: `--headless cmd.exe /d /s /c ""<wrapper>""`. `/d` skips AutoRun; `/s` makes cmd strip
/// exactly the outer pair of quotes, so the quoted path survives spaces and `& ( )` in a user name.
pub fn action_arguments(wrapper: &str) -> String {
    format!("--headless cmd.exe /d /s /c \"\"{wrapper}\"\"")
}

/// `S-1-<digits>(-<digits>)+`.
pub fn is_valid_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-1-") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('-').collect();
    parts.len() >= 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The task's security descriptor: full control for SYSTEM, Administrators and the user (`Get-NodeTaskSddl`).
pub fn task_sddl(user_sid: &str) -> Result<String, TaskError> {
    if !is_valid_sid(user_sid) {
        return Err(TaskError::BadSid(user_sid.to_owned()));
    }
    Ok(format!("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user_sid})"))
}

/// Who the task runs as: the current user (`WindowsIdentity.GetCurrent()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskIdentity {
    /// `DOMAIN\user`, as the principal and the logon trigger name it.
    pub user: String,
    /// The user's SID, for the security descriptor.
    pub sid: String,
}

/// Reads the current user's name and SID. Read-only.
pub const IDENTITY_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
'name=' + $id.Name
'sid=' + $id.User.Value
"#;

/// Sets the task's security descriptor (`P2PC_TASK_SDDL`) through the Task Scheduler COM API, flags 0
/// (`Set-NodeTaskSddl`).
pub const SDDL_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
try {
    $svc = New-Object -ComObject Schedule.Service
    $svc.Connect()
    $null = $svc.GetFolder('\').GetTask('P2PC node').SetSecurityDescriptor($env:P2PC_TASK_SDDL, 0)
    'rights=set'
} catch {
    'rights=failed: ' + $_.Exception.Message
    exit 1
}
"#;

/// Prints the task's state (`Ready`, `Running`, `Disabled`, …), or `none` when it is not registered. Read-only.
pub const STATE_SCRIPT: &str = r#"$ErrorActionPreference = 'SilentlyContinue'
$t = Get-ScheduledTask -TaskName 'P2PC node' -TaskPath '\' -ErrorAction SilentlyContinue
if ($t) { 'state=' + [string]$t.State } else { 'state=none' }
"#;

fn field<'t>(text: &'t str, key: &str) -> Option<&'t str> {
    text.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
}

/// The current user, from PowerShell.
pub fn current_identity(host: Host<'_>) -> Result<TaskIdentity, TaskError> {
    let out = host.run(&powershell(IDENTITY_SCRIPT))?;
    let text = out.stdout_text();
    let (Some(user), Some(sid)) = (field(&text, "name"), field(&text, "sid")) else {
        return Err(TaskError::Identity(format!(
            "PowerShell exited {:?} without naming the user",
            out.code
        )));
    };
    if !out.success() || user.is_empty() {
        return Err(TaskError::Identity(format!("PowerShell exited {:?}", out.code)));
    }
    if !is_valid_sid(sid) {
        return Err(TaskError::BadSid(sid.to_owned()));
    }
    Ok(TaskIdentity {
        user: user.to_owned(),
        sid: sid.to_owned(),
    })
}

/// Which triggers the task has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Triggers {
    /// The 5-minute watchdog and the logon trigger for this user (`Get-NodeTaskTriggerKinds`).
    WatchdogAndLogon,
    /// The watchdog alone, after Windows refused the logon trigger.
    WatchdogOnly,
}

impl Triggers {
    /// What the user is told after [`Triggers::WatchdogOnly`] (`Get-TimeTriggerOnlyAdvice`).
    pub const WATCHDOG_ONLY_ADVICE: &'static str = "Windows refused the sign-in trigger, so only the 5-minute trigger was registered: the node starts within 5 minutes of signing in.";
}

/// Everything the task XML is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSpec {
    /// `%SystemRoot%\System32\conhost.exe`.
    pub conhost: String,
    /// The wrapper's path ([`Layout::task_wrapper`]).
    pub wrapper: String,
    /// `DOMAIN\user`.
    pub user: String,
    /// The time trigger's start, `YYYY-MM-DDTHH:MM:SSZ` ([`start_boundary`]).
    pub start_boundary: String,
    pub triggers: Triggers,
    /// Registered enabled (`false`: no trigger can start it before the caller decides, as `-Upgrade` does).
    pub enabled: bool,
}

/// XML text escaping.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// A UTC time as the time trigger's start boundary (`2026-11-10T09:30:00Z`).
pub fn start_boundary(at: SystemTime) -> String {
    let secs = at.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

/// The task XML (`Register-NodeTaskWithTriggers`'s definition, `Get-NodeTaskDefinition`). The time trigger's
/// repetition has no duration: it repeats with no end.
pub fn task_xml(spec: &TaskSpec) -> String {
    let user = xml_escape(&spec.user);
    let logon = match spec.triggers {
        Triggers::WatchdogAndLogon => format!(
            "    <LogonTrigger>\r\n      <Enabled>true</Enabled>\r\n      <UserId>{user}</UserId>\r\n    </LogonTrigger>\r\n"
        ),
        Triggers::WatchdogOnly => String::new(),
    };
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n",
            "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n",
            "  <RegistrationInfo>\r\n",
            "    <Description>{description}</Description>\r\n",
            "  </RegistrationInfo>\r\n",
            "  <Triggers>\r\n",
            "    <TimeTrigger>\r\n",
            "      <Repetition>\r\n",
            "        <Interval>PT{repeat}M</Interval>\r\n",
            "        <StopAtDurationEnd>false</StopAtDurationEnd>\r\n",
            "      </Repetition>\r\n",
            "      <StartBoundary>{start}</StartBoundary>\r\n",
            "      <Enabled>true</Enabled>\r\n",
            "    </TimeTrigger>\r\n",
            "{logon}",
            "  </Triggers>\r\n",
            "  <Principals>\r\n",
            "    <Principal id=\"Author\">\r\n",
            "      <UserId>{user}</UserId>\r\n",
            "      <LogonType>InteractiveToken</LogonType>\r\n",
            "      <RunLevel>LeastPrivilege</RunLevel>\r\n",
            "    </Principal>\r\n",
            "  </Principals>\r\n",
            "  <Settings>\r\n",
            "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n",
            "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n",
            "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n",
            "    <AllowHardTerminate>true</AllowHardTerminate>\r\n",
            "    <StartWhenAvailable>true</StartWhenAvailable>\r\n",
            "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n",
            "    <IdleSettings>\r\n",
            "      <StopOnIdleEnd>false</StopOnIdleEnd>\r\n",
            "      <RestartOnIdle>false</RestartOnIdle>\r\n",
            "    </IdleSettings>\r\n",
            "    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n",
            "    <Enabled>{enabled}</Enabled>\r\n",
            "    <Hidden>false</Hidden>\r\n",
            "    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n",
            "    <WakeToRun>false</WakeToRun>\r\n",
            "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n",
            "    <Priority>7</Priority>\r\n",
            "    <RestartOnFailure>\r\n",
            "      <Interval>PT{restart_interval}M</Interval>\r\n",
            "      <Count>{restart_count}</Count>\r\n",
            "    </RestartOnFailure>\r\n",
            "  </Settings>\r\n",
            "  <Actions Context=\"Author\">\r\n",
            "    <Exec>\r\n",
            "      <Command>{command}</Command>\r\n",
            "      <Arguments>{arguments}</Arguments>\r\n",
            "    </Exec>\r\n",
            "  </Actions>\r\n",
            "</Task>\r\n",
        ),
        description = xml_escape(DESCRIPTION),
        repeat = REPEAT_MINUTES,
        start = xml_escape(&spec.start_boundary),
        logon = logon,
        user = user,
        enabled = spec.enabled,
        restart_interval = RESTART_INTERVAL_MINUTES,
        restart_count = RESTART_COUNT,
        command = xml_escape(&spec.conhost),
        arguments = xml_escape(&action_arguments(&spec.wrapper)),
    )
}

/// UTF-16LE with a BOM, the encoding the XML declares.
pub fn utf16_with_bom(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    out.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    out
}

/// What registering needs besides the layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskContext {
    /// `%SystemRoot%` (for `conhost.exe`).
    pub system_root: PathBuf,
    pub identity: TaskIdentity,
    /// The time trigger's start ([`start_boundary`] of now).
    pub start_boundary: String,
}

impl TaskContext {
    /// `%SystemRoot%\System32\conhost.exe`.
    pub fn conhost(&self) -> PathBuf {
        self.system_root.join("System32").join("conhost.exe")
    }
}

/// The outcome of a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub triggers: Triggers,
    /// `None`: the user has full control of the task. `Some`: Windows refused the security descriptor; the task is
    /// registered with its default rights (a warning; the supervisor's own stamp still keeps a stopped node from
    /// dialing the server).
    pub rights_warning: Option<String>,
}

fn schtasks_error(op: &'static str, out: &crate::runner::Output) -> TaskError {
    TaskError::Schtasks {
        op,
        code: out.code,
        message: crate::import::sanitize_message(&out.text()),
    }
}

/// One `schtasks /Create /XML` attempt with these triggers.
fn create(host: Host<'_>, layout: &Layout, spec: &TaskSpec) -> Result<(), TaskError> {
    let xml_path = layout.task_xml();
    fs::write(&xml_path, utf16_with_bom(&task_xml(spec))).map_err(|source| TaskError::Io {
        context: format!("writing {}", xml_path.display()),
        source,
    })?;
    let out = host.run(&schtasks_invocation([
        "/Create".to_owned(),
        "/TN".to_owned(),
        TASK_PATH.to_owned(),
        "/XML".to_owned(),
        xml_path.display().to_string(),
        "/F".to_owned(),
    ]));
    if let Err(e) = fs::remove_file(&xml_path) {
        tracing::debug!(error = %e, "could not delete the task XML");
    }
    let out = out?;
    if out.success() {
        Ok(())
    } else {
        Err(schtasks_error("/Create", &out))
    }
}

/// Writes the wrapper, then creates or replaces (`/F`, idempotent) the task with both triggers; if Windows refuses,
/// with the watchdog alone (`Register-NodeTask`). Then gives the user full control of it (`Set-NodeTaskRights`).
///
/// `install.ps1` retries with the watchdog alone only on "access denied"; `schtasks` reports that as localized text
/// only, so here any refusal of the two-trigger registration is retried once with the watchdog alone. A refusal of
/// that too is [`TaskError::Register`].
pub fn register(host: Host<'_>, layout: &Layout, ctx: &TaskContext, enabled: bool) -> Result<Registration, TaskError> {
    let sddl = task_sddl(&ctx.identity.sid)?;
    let wrapper = write_wrapper(layout)?;
    let mut spec = TaskSpec {
        conhost: ctx.conhost().display().to_string(),
        wrapper: wrapper.display().to_string(),
        user: ctx.identity.user.clone(),
        start_boundary: ctx.start_boundary.clone(),
        triggers: Triggers::WatchdogAndLogon,
        enabled,
    };
    if let Err(first) = create(host, layout, &spec) {
        tracing::warn!(error = %first, "registering '{TASK_NAME}' with the sign-in trigger failed: trying the 5-minute trigger only");
        spec.triggers = Triggers::WatchdogOnly;
        create(host, layout, &spec).map_err(|second| TaskError::Register {
            message: format!("{first}; then: {second}"),
        })?;
        tracing::warn!("{}", Triggers::WATCHDOG_ONLY_ADVICE);
    }
    let rights = host.run(&powershell(SDDL_SCRIPT).env("P2PC_TASK_SDDL", sddl));
    let rights_warning = match rights {
        Ok(out) if out.success() && field(&out.stdout_text(), "rights") == Some("set") => None,
        Ok(out) => Some(crate::import::sanitize_message(&out.text())),
        Err(e) => Some(e.to_string()),
    };
    if let Some(w) = &rights_warning {
        tracing::warn!(reason = %w, "could not give the user full control of the scheduled task; it stays registered");
    }
    Ok(Registration {
        triggers: spec.triggers,
        rights_warning,
    })
}

/// The task's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    NotRegistered,
    Ready,
    Running,
    Disabled,
    Queued,
    /// Anything else Task Scheduler reports (`Unknown`, …).
    Other(String),
}

/// Reads the task's state (`Get-NodeTaskState`).
pub fn state(host: Host<'_>) -> Result<TaskState, TaskError> {
    let out = host.run(&powershell(STATE_SCRIPT))?;
    let text = out.stdout_text();
    match field(&text, "state") {
        Some("none") => Ok(TaskState::NotRegistered),
        Some("Ready") => Ok(TaskState::Ready),
        Some("Running") => Ok(TaskState::Running),
        Some("Disabled") => Ok(TaskState::Disabled),
        Some("Queued") => Ok(TaskState::Queued),
        Some(other) if !other.is_empty() => Ok(TaskState::Other(other.to_owned())),
        _ => Err(TaskError::State(format!("PowerShell exited {:?}", out.code))),
    }
}

fn schtasks(host: Host<'_>, op: &'static str, args: &[&str]) -> Result<(), TaskError> {
    let inv = schtasks_invocation(args.iter().copied()).args(["/TN", TASK_PATH]);
    let out = host.run(&inv)?;
    if out.success() {
        Ok(())
    } else {
        Err(schtasks_error(op, &out))
    }
}

/// `schtasks /Change /ENABLE`.
pub fn enable(host: Host<'_>) -> Result<(), TaskError> {
    schtasks(host, "/Change /ENABLE", &["/Change", "/ENABLE"])
}

/// `schtasks /Change /DISABLE`.
pub fn disable(host: Host<'_>) -> Result<(), TaskError> {
    schtasks(host, "/Change /DISABLE", &["/Change", "/DISABLE"])
}

/// `schtasks /Run`.
pub fn start(host: Host<'_>) -> Result<(), TaskError> {
    schtasks(host, "/Run", &["/Run"])
}

/// `schtasks /End`. Ending the task kills only conhost: its `wsl.exe` and the agent keep running (H1 §9.0), which is
/// why [`suspend`] also terminates the distro.
pub fn end(host: Host<'_>) -> Result<(), TaskError> {
    schtasks(host, "/End", &["/End"])
}

/// Really stops the node (`Suspend-NodeTask`): disabled first (neither the watchdog nor a sign-in starts it again
/// meanwhile), ended, then `wsl --terminate p2pc-node`. Each step is best effort; the failures come back as warnings.
pub fn suspend(host: Host<'_>) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Err(e) = disable(host) {
        warnings.push(e.to_string());
    }
    if let Err(e) = end(host) {
        warnings.push(e.to_string());
    }
    match host.wsl(["--terminate", DISTRO_NAME]) {
        Ok(out) if out.success() => {}
        Ok(out) => warnings.push(format!(
            "wsl --terminate {DISTRO_NAME} failed (exit {:?}): {}",
            out.code,
            crate::import::sanitize_message(&out.text())
        )),
        Err(e) => warnings.push(e.to_string()),
    }
    for w in &warnings {
        tracing::warn!("{w}");
    }
    warnings
}

/// Enables the task and starts it (`Resume-NodeTask`).
pub fn resume(host: Host<'_>) -> Result<(), TaskError> {
    enable(host)?;
    start(host)
}

/// What the wrapper wrote when the node stopped for good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopRecord {
    /// 6, 7 or 8; `None` when the wrapper could not read it from the distro.
    pub code: Option<u32>,
    pub time: String,
    pub reason: String,
    /// Whether the wrapper's `/DISABLE` worked (`None`: not recorded).
    pub disabled: Option<bool>,
}

impl StopRecord {
    /// Parses `stopped-by-node` (the file part of `Read-NodeStopRecord`).
    pub fn parse(text: &str) -> Self {
        let get = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(k)?.strip_prefix('='))
                .map(|v| v.trim_end().to_owned())
                .unwrap_or_default()
        };
        let code = get("exit_code");
        Self {
            code: (!code.is_empty() && code.bytes().all(|b| b.is_ascii_digit()))
                .then(|| code.parse().ok())
                .flatten(),
            time: get("time"),
            reason: get("reason"),
            disabled: match get("disabled").as_str() {
                "yes" => Some(true),
                "no" => Some(false),
                _ => None,
            },
        }
    }
}

/// Reads `stopped-by-node`, or `None` when there is none.
pub fn read_stop_record(layout: &Layout) -> Option<StopRecord> {
    let path: &Path = &layout.stop_record();
    let bytes = fs::read(path).ok()?;
    Some(StopRecord::parse(&String::from_utf8_lossy(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::*;
    use crate::runner::{Invocation, Output, POWERSHELL_EXE, SCHTASKS_EXE, SCHTASKS_TIMEOUT, WSL_EXE};

    const SID: &str = "S-1-5-21-1000000001-1000000002-1000000003-1001";

    fn ctx() -> TaskContext {
        TaskContext {
            system_root: PathBuf::from("C:\\Windows"),
            identity: TaskIdentity {
                user: "PC\\Ana & Bo".to_owned(),
                sid: SID.to_owned(),
            },
            start_boundary: "2026-11-10T09:30:00Z".to_owned(),
        }
    }

    fn is_create(i: &Invocation) -> bool {
        starts(i, SCHTASKS_EXE, &["/Create", "/TN", TASK_PATH, "/XML"])
    }

    #[test]
    fn the_wrapper_runs_the_supervisor_and_stops_for_good_on_64() {
        let lines = wrapper_lines();
        assert_eq!(lines[0], "@echo off");
        assert!(lines.contains(&"wsl.exe -d p2pc-node -u root --exec /usr/local/sbin/p2pc-node-run".to_owned()));
        assert!(lines.contains(&"if not \"%P2PC_RC%\"==\"64\" exit /b %P2PC_RC%".to_owned()));
        assert!(lines.contains(&"schtasks /Change /TN \"\\P2PC node\" /DISABLE >nul 2>&1".to_owned()));
        assert_eq!(lines.last().unwrap(), "exit /b 64");
        let content = wrapper_content();
        assert!(content.is_ascii());
        assert!(content.ends_with("exit /b 64\r\n"));
        assert_eq!(content.matches("\r\n").count(), lines.len());
        assert!(!content.replace("\r\n", "").contains('\n'));
    }

    #[test]
    fn the_wrapper_path_must_be_quotable_for_cmd() {
        assert!(is_cmd_safe_path(
            "C:\\Users\\Ana & Bo (x)\\AppData\\Local\\P2PC\\node-task.cmd"
        ));
        assert!(!is_cmd_safe_path("C:\\Users\\100%\\node-task.cmd"));
        assert!(!is_cmd_safe_path("C:\\Users\\a\"b\\node-task.cmd"));
        assert!(!is_cmd_safe_path(""));
        let dir = tempfile::tempdir().unwrap();
        let bad = Layout::new(dir.path().join("50%"));
        assert!(matches!(write_wrapper(&bad), Err(TaskError::UnsafeWrapperPath(_))));
        let good = Layout::new(dir.path());
        let path = write_wrapper(&good).unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), wrapper_content());
    }

    #[test]
    fn the_action_is_the_wrapper_through_headless_conhost() {
        assert_eq!(
            action_arguments("C:\\Users\\a b\\AppData\\Local\\P2PC\\node-task.cmd"),
            "--headless cmd.exe /d /s /c \"\"C:\\Users\\a b\\AppData\\Local\\P2PC\\node-task.cmd\"\""
        );
    }

    #[test]
    fn the_sddl_gives_full_control_to_system_administrators_and_the_user() {
        assert_eq!(
            task_sddl(SID).unwrap(),
            format!("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{SID})")
        );
        for bad in ["", "S-1-", "S-1-5", "S-1-5-x", "S-1-5-21)(A;;FA;;;WD", "s-1-5-18"] {
            assert!(matches!(task_sddl(bad), Err(TaskError::BadSid(_))), "{bad}");
        }
        assert!(is_valid_sid("S-1-5-18"));
    }

    #[test]
    fn the_task_xml_has_the_h1_triggers_settings_and_action() {
        let spec = TaskSpec {
            conhost: "C:\\Windows\\System32\\conhost.exe".into(),
            wrapper: "C:\\Users\\Ana & Bo\\AppData\\Local\\P2PC\\node-task.cmd".into(),
            user: "PC\\Ana & Bo".into(),
            start_boundary: "2026-11-10T09:30:00Z".into(),
            triggers: Triggers::WatchdogAndLogon,
            enabled: true,
        };
        let xml = task_xml(&spec);
        for want in [
            "<Interval>PT5M</Interval>",
            "<StopAtDurationEnd>false</StopAtDurationEnd>",
            "<StartBoundary>2026-11-10T09:30:00Z</StartBoundary>",
            "<LogonTrigger>\r\n      <Enabled>true</Enabled>\r\n      <UserId>PC\\Ana &amp; Bo</UserId>",
            "<Principal id=\"Author\">\r\n      <UserId>PC\\Ana &amp; Bo</UserId>\r\n      <LogonType>InteractiveToken</LogonType>\r\n      <RunLevel>LeastPrivilege</RunLevel>",
            "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
            "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
            "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
            "<StartWhenAvailable>true</StartWhenAvailable>",
            "<Enabled>true</Enabled>\r\n    <Hidden>false</Hidden>",
            "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
            "<RestartOnFailure>\r\n      <Interval>PT1M</Interval>\r\n      <Count>999</Count>",
            "<Command>C:\\Windows\\System32\\conhost.exe</Command>",
            "<Arguments>--headless cmd.exe /d /s /c &quot;&quot;C:\\Users\\Ana &amp; Bo\\AppData\\Local\\P2PC\\node-task.cmd&quot;&quot;</Arguments>",
        ] {
            assert!(xml.contains(want), "missing {want:?} in\n{xml}");
        }
        // No duration on the repetition (it repeats with no end), no logon trigger for any user, never elevated.
        assert!(!xml.contains("<Duration>"));
        assert!(!xml.contains("HighestAvailable"));
        assert_eq!(xml.matches("<UserId>").count(), 2);
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-16\"?>"));

        let alone = task_xml(&TaskSpec {
            triggers: Triggers::WatchdogOnly,
            enabled: false,
            ..spec
        });
        assert!(!alone.contains("<LogonTrigger>"));
        assert!(alone.contains("<TimeTrigger>"));
        assert!(alone.contains("<Enabled>false</Enabled>\r\n    <Hidden>false</Hidden>"));
    }

    #[test]
    fn the_xml_file_is_utf16_with_a_bom() {
        assert_eq!(
            utf16_with_bom("<a/>"),
            vec![0xFF, 0xFE, b'<', 0, b'a', 0, b'/', 0, b'>', 0]
        );
    }

    #[test]
    fn start_boundary_is_utc_civil_time() {
        assert_eq!(start_boundary(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_794_303_000);
        assert_eq!(start_boundary(t), "2026-11-10T09:30:00Z");
        let leap = UNIX_EPOCH + std::time::Duration::from_secs(951_825_599);
        assert_eq!(start_boundary(leap), "2000-02-29T11:59:59Z");
    }

    #[test]
    fn register_writes_the_wrapper_creates_the_task_and_sets_its_rights() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        let runner = FakeRunner::new();
        let xml_path = layout.task_xml();
        let seen_xml = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let seen = seen_xml.clone();
        runner.on(
            move |i| {
                if is_create(i) {
                    seen.borrow_mut().push(fs::read(&xml_path).unwrap_or_default());
                    true
                } else {
                    false
                }
            },
            Output::with(
                0,
                "SUCCESS: The scheduled task \"P2PC node\" has successfully been created.\r\n",
            ),
        );
        runner.on(|i| runs_script(i, SDDL_SCRIPT), Output::with(0, "rights=set\r\n"));
        let pause = FakePause::default();
        let reg = register(Host::new(&runner, &pause), &layout, &ctx(), true).unwrap();
        assert_eq!(
            reg,
            Registration {
                triggers: Triggers::WatchdogAndLogon,
                rights_warning: None
            }
        );
        assert_eq!(fs::read_to_string(layout.task_wrapper()).unwrap(), wrapper_content());
        assert!(!layout.task_xml().exists(), "the XML is deleted afterwards");
        let create = runner.calls().into_iter().find(is_create).unwrap();
        assert_eq!(create.time_limit(), Some(SCHTASKS_TIMEOUT));
        assert_eq!(
            create.arguments(),
            &[
                "/Create",
                "/TN",
                "\\P2PC node",
                "/XML",
                &layout.task_xml().display().to_string(),
                "/F"
            ]
        );
        let written = seen_xml.borrow()[0].clone();
        let mut want = TaskSpec {
            conhost: PathBuf::from("C:\\Windows")
                .join("System32")
                .join("conhost.exe")
                .display()
                .to_string(),
            wrapper: layout.task_wrapper().display().to_string(),
            user: "PC\\Ana & Bo".into(),
            start_boundary: "2026-11-10T09:30:00Z".into(),
            triggers: Triggers::WatchdogAndLogon,
            enabled: true,
        };
        assert_eq!(written, utf16_with_bom(&task_xml(&want)));
        // The SDDL goes through the environment; the SID is never pasted into the script.
        let rights = runner
            .calls()
            .into_iter()
            .find(|i| i.program() == POWERSHELL_EXE)
            .unwrap();
        assert_eq!(
            rights.environment(),
            &[(
                "P2PC_TASK_SDDL".to_owned(),
                format!("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{SID})")
            )]
        );
        want.enabled = false;
        assert_ne!(
            task_xml(&want),
            task_xml(&TaskSpec {
                enabled: true,
                ..want.clone()
            })
        );
    }

    #[test]
    fn a_refused_logon_trigger_falls_back_to_the_watchdog_alone() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        let runner = FakeRunner::new();
        let xml_path = layout.task_xml();
        runner.on(
            move |i| {
                is_create(i)
                    && String::from_utf8_lossy(&fs::read(&xml_path).unwrap_or_default())
                        .replace('\0', "")
                        .contains("<LogonTrigger>")
            },
            Output::with(1, "ERROR: Access is denied.\r\n"),
        );
        runner.on(is_create, Output::with(0, "SUCCESS"));
        runner.on(|i| runs_script(i, SDDL_SCRIPT), Output::with(0, "rights=set"));
        let pause = FakePause::default();
        let reg = register(Host::new(&runner, &pause), &layout, &ctx(), true).unwrap();
        assert_eq!(reg.triggers, Triggers::WatchdogOnly);
        assert_eq!(runner.count(is_create), 2);
    }

    #[test]
    fn a_refusal_of_both_registrations_is_an_error_and_nothing_else_is_tried() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        let runner = FakeRunner::new();
        runner.on(is_create, Output::with(1, "ERROR: Access is denied."));
        let pause = FakePause::default();
        let err = register(Host::new(&runner, &pause), &layout, &ctx(), true).unwrap_err();
        assert!(
            matches!(&err, TaskError::Register { message } if message.contains("Access is denied")),
            "{err:?}"
        );
        assert_eq!(
            runner.calls().len(),
            2,
            "two creates, no rights call, no other way to start the agent"
        );
        assert!(!layout.task_xml().exists());
    }

    #[test]
    fn refused_rights_only_warn() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        let runner = FakeRunner::new();
        runner.on(is_create, Output::with(0, "SUCCESS"));
        runner.on(
            |i| runs_script(i, SDDL_SCRIPT),
            Output::with(1, "rights=failed: Access is denied. (0x80070005)"),
        );
        let pause = FakePause::default();
        let reg = register(Host::new(&runner, &pause), &layout, &ctx(), true).unwrap();
        assert_eq!(reg.triggers, Triggers::WatchdogAndLogon);
        assert!(reg.rights_warning.unwrap().contains("0x80070005"));
    }

    #[test]
    fn a_bad_sid_stops_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        let runner = FakeRunner::new();
        let pause = FakePause::default();
        let mut c = ctx();
        c.identity.sid = "S-1-5-21)(A;;FA;;;WD".into();
        assert!(matches!(
            register(Host::new(&runner, &pause), &layout, &c, true),
            Err(TaskError::BadSid(_))
        ));
        assert!(runner.calls().is_empty());
        assert!(!layout.task_wrapper().exists());
    }

    #[test]
    fn the_identity_comes_from_powershell_and_is_validated() {
        let runner = FakeRunner::new();
        runner.on(
            |i| runs_script(i, IDENTITY_SCRIPT),
            Output::with(0, format!("name=PC\\Ana\r\nsid={SID}\r\n")),
        );
        let pause = FakePause::default();
        let id = current_identity(Host::new(&runner, &pause)).unwrap();
        assert_eq!(
            id,
            TaskIdentity {
                user: "PC\\Ana".into(),
                sid: SID.into()
            }
        );
        let runner = FakeRunner::new();
        runner.on(
            |i| runs_script(i, IDENTITY_SCRIPT),
            Output::with(0, "name=PC\\Ana\r\nsid=nope\r\n"),
        );
        assert!(matches!(
            current_identity(Host::new(&runner, &pause)),
            Err(TaskError::BadSid(_))
        ));
        let runner = FakeRunner::new();
        runner.on(|i| runs_script(i, IDENTITY_SCRIPT), Output::with(1, ""));
        assert!(matches!(
            current_identity(Host::new(&runner, &pause)),
            Err(TaskError::Identity(_))
        ));
    }

    #[test]
    fn the_state_is_read_from_powershell() {
        let pause = FakePause::default();
        for (answer, want) in [
            ("state=none", TaskState::NotRegistered),
            ("state=Ready", TaskState::Ready),
            ("state=Running", TaskState::Running),
            ("state=Disabled", TaskState::Disabled),
            ("state=Queued", TaskState::Queued),
            ("state=Unknown", TaskState::Other("Unknown".into())),
        ] {
            let runner = FakeRunner::new();
            runner.on(|i| runs_script(i, STATE_SCRIPT), Output::with(0, answer));
            assert_eq!(state(Host::new(&runner, &pause)).unwrap(), want, "{answer}");
        }
        let runner = FakeRunner::new();
        runner.on(|i| runs_script(i, STATE_SCRIPT), Output::with(1, ""));
        assert!(matches!(state(Host::new(&runner, &pause)), Err(TaskError::State(_))));
    }

    #[test]
    fn suspend_disables_ends_and_terminates_the_distro_best_effort() {
        let runner = FakeRunner::new();
        runner.on(
            |i| starts(i, SCHTASKS_EXE, &["/Change", "/DISABLE"]),
            Output::with(1, "ERROR: Access is denied."),
        );
        runner.on(|i| starts(i, SCHTASKS_EXE, &["/End"]), Output::with(0, ""));
        runner.on(
            |i| starts(i, WSL_EXE, &["--terminate", "p2pc-node"]),
            Output::with(0, ""),
        );
        let pause = FakePause::default();
        let warnings = suspend(Host::new(&runner, &pause));
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let order: Vec<String> = runner
            .calls()
            .iter()
            .map(|i| format!("{} {}", i.program(), i.arguments().join(" ")))
            .collect();
        assert_eq!(
            order,
            vec![
                "schtasks.exe /Change /DISABLE /TN \\P2PC node",
                "schtasks.exe /End /TN \\P2PC node",
                "wsl.exe --terminate p2pc-node",
            ]
        );
    }

    #[test]
    fn resume_enables_then_starts_and_stops_at_a_failure() {
        let runner = FakeRunner::new();
        runner.on(
            |i| starts(i, SCHTASKS_EXE, &["/Change", "/ENABLE"]),
            Output::with(0, ""),
        );
        runner.on(|i| starts(i, SCHTASKS_EXE, &["/Run"]), Output::with(0, ""));
        let pause = FakePause::default();
        resume(Host::new(&runner, &pause)).unwrap();
        assert_eq!(runner.calls().len(), 2);
        let runner = FakeRunner::new();
        runner.on(
            |i| starts(i, SCHTASKS_EXE, &["/Change", "/ENABLE"]),
            Output::with(1, "ERROR"),
        );
        assert!(matches!(
            resume(Host::new(&runner, &pause)),
            Err(TaskError::Schtasks {
                op: "/Change /ENABLE",
                ..
            })
        ));
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn the_stop_record_is_read_like_read_node_stop_record() {
        let r = StopRecord::parse(
            "node_exit=64\r\nexit_code=7\r\ntime=2026-11-10T09:00:00Z\r\nreason=removed from the server\r\ndisabled=yes\r\n",
        );
        assert_eq!(
            r,
            StopRecord {
                code: Some(7),
                time: "2026-11-10T09:00:00Z".into(),
                reason: "removed from the server".into(),
                disabled: Some(true)
            }
        );
        let r = StopRecord::parse("node_exit=64\ndisabled=no\n");
        assert_eq!(r.code, None);
        assert_eq!(r.disabled, Some(false));
        assert_eq!(StopRecord::parse("exit_code=x7\n").code, None);
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        assert_eq!(read_stop_record(&layout), None);
        fs::create_dir_all(layout.root()).unwrap();
        fs::write(layout.stop_record(), "node_exit=64\nexit_code=6\n").unwrap();
        assert_eq!(read_stop_record(&layout).unwrap().code, Some(6));
    }
}
