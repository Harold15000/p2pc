// SPDX-License-Identifier: Apache-2.0

//! Upgrading the distro and keeping its state (H2 §8.3 second half, §14.2): `install.ps1 -Upgrade`
//! (`Invoke-UpgradeAction`, `Invoke-UpgradeSteps`) ported to Rust.
//!
//! What it carries is `/var/lib/p2pc` (the agent's identity, enrollment and state) and, on the hub PC,
//! `/var/lib/p2pc-server` (the cloud's database, keys, blobs and `hub.enabled`). The procedure, in order:
//!
//! 1. **Before anything is touched**: the distro exists, its directory holds only WSL's own files, the state probe gives
//!    a positive answer (an unknown answer, or the hub's data without the agent state, stops here; no state at all
//!    stops too unless the caller says to go on without it), both directories are measured and the Windows drives can
//!    hold the archive. Every refusal here leaves the old distro as it was (`install.ps1` exit 23).
//! 2. **Archive** inside the distro (mode 0600, hashed there), **copy it out** byte-exact to
//!    `%LOCALAPPDATA%\P2PC\backups\p2pc-state-<time>.tar` (the child's stdout streamed to the file, never decoded), and
//!    check the copy's SHA-256 against the one computed inside. The in-distro copy is deleted on every path.
//! 3. **Unregister** the old distro and **import** the verified image.
//! 4. **Copy in** (the file streamed to the stdin of `dd` inside the new distro), check the hash there, extract with
//!    the same modes and owners; the in-distro copy is deleted on every path.
//! 5. **Verify**: the distro checks, the before/after listing of both directories (names, modes, owners), and that a
//!    node that was enrolled still holds `[server]`. Only then is the backup renamed `p2pc-state-<time>.ok.tar`; the
//!    newest 3 of those are kept, or only that one when it holds the hub's data.
//!
//! The backup of an upgrade that failed after the old distro was unregistered is the only copy of the node's identity
//! (and on the hub PC of the cloud's database): it is never deleted, and [`UpgradeFailure::kept_backup`] names it.
//!
//! The scheduled task is disabled and stopped around the upgrade and put back as it was (`Invoke-UpgradeAction`): a
//! node the user stopped stays stopped, a node that stopped for good comes back only when it stopped as too old (6),
//! and a node whose new distro does not hold its identity yet stays stopped.
//!
//! The same byte-exact pipes deliver a template bundle into the distro ([`write_file_in_distro`], §14.1).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::image::{Sha256Digest, VerifiedImage, sha256_file};
use crate::import::{
    BOOT_STATUS_WAIT, BootStatus, ImportError, check_distro_dir, distro_exists, import_distro, sanitize_message,
    verify_distro, wait_boot_status,
};
use crate::runner::{Host, Invocation, Output, RunError, in_distro, powershell};
use crate::task::{self, NODE_RUN_STATUS_PATH, TaskContext, TaskError, TaskState};
use crate::{DISTRO_NAME, Layout};

/// The agent's config, the one `install.ps1` and `p2pc-node-run` name through `P2PC_AGENT_CONFIG`
/// (`$AgentConfigPath`).
pub const AGENT_CONFIG_PATH: &str = "/var/lib/p2pc/agent.toml";
/// The agent (`$AgentPath`).
pub const AGENT_PATH: &str = "/usr/local/bin/p2pc-agent";

/// Prints exactly one marker: is there agent state to carry (`$StateProbeScript`)?
pub const STATE_PROBE_SCRIPT: &str = "if [ -d /var/lib/p2pc ]; then echo P2PC_STATE=present; elif [ -e /var/lib/p2pc-server ]; then echo P2PC_STATE=hub-only; else echo P2PC_STATE=absent; fi";
/// How much will be carried, in KiB per directory (`$StateSizeScript`).
pub const STATE_SIZE_SCRIPT: &str =
    "set -e; du -sk /var/lib/p2pc; if [ -e /var/lib/p2pc-server ]; then du -sk /var/lib/p2pc-server; fi";
/// The state archive, written inside the distro to `@OUT@` (mode 0600) and hashed there (`$StateArchiveScript`):
/// sockets, FIFOs and the boot step's own files are left out.
pub const STATE_ARCHIVE_SCRIPT: &str = "set -e; set -o pipefail; umask 077; cd /var/lib; find . -mindepth 1 ! -path ./p2pc ! -path './p2pc/*' ! -path ./p2pc-server ! -path './p2pc-server/*' -prune -o -type s -prune -o -type p -prune -o -path ./p2pc/tmp -prune -o -path ./p2pc/boot-status.json -prune -o -path './p2pc/.boot-status.*' -prune -o -printf '%P\\0' | tar --numeric-owner --no-recursion --null -T - -cpf @OUT@; sha256sum @OUT@";
/// Moves the agent config of an image up to 0.2.1 into `/var/lib/p2pc` before the archive (`$ConfigMigrationScript`).
pub const CONFIG_MIGRATION_SCRIPT: &str = "if [ -e /var/lib/p2pc/agent.toml ]; then echo P2PC_CONFIG=present; elif [ -s /etc/p2pc/agent.toml ]; then install -m 0600 -o 0 -g 0 /etc/p2pc/agent.toml /var/lib/p2pc/agent.toml; echo P2PC_CONFIG=moved; else install -m 0600 -o 0 -g 0 /dev/null /var/lib/p2pc/agent.toml; echo P2PC_CONFIG=created; fi";
/// One line per carried entry, `mode:uid:gid:type:path` (`Get-StateListing`).
pub const STATE_LISTING: [&str; 25] = [
    "/usr/bin/find",
    "/var/lib",
    "-mindepth",
    "1",
    "!",
    "-path",
    "/var/lib/p2pc",
    "!",
    "-path",
    "/var/lib/p2pc/*",
    "!",
    "-path",
    "/var/lib/p2pc-server",
    "!",
    "-path",
    "/var/lib/p2pc-server/*",
    "-prune",
    "-o",
    "!",
    "-type",
    "s",
    "!",
    "-type",
    "p",
    "-printf",
];
/// The format of [`STATE_LISTING`]'s `-printf` (find reads the `\n`).
pub const STATE_LISTING_FORMAT: &str = "%m:%U:%G:%y:%P\\n";
/// `/var/lib/p2pc/agent.toml` holds the enrollment (`Test-ServerSection`).
pub const SERVER_SECTION_CHECK: [&str; 4] = ["/bin/grep", "-q", "^\\[server\\]", AGENT_CONFIG_PATH];
/// Where the archive is restored from in the new distro.
pub const IN_DISTRO_TAR: &str = "/tmp/p2pc-state.tar";
/// How many verified backups are kept (`$BackupKeep`); one when it holds the hub's data.
pub const BACKUP_KEEP: usize = 3;
/// How long the node has to come back connected after the upgrade (`$ConnectWaitSeconds`).
pub const CONNECT_WAIT: Duration = Duration::from_secs(60);
/// How often its status is read meanwhile.
pub const CONNECT_POLL: Duration = Duration::from_secs(2);
/// How far a `since` may be before the start and still count (`$ConnectedSinceSlackSeconds`).
pub const CONNECTED_SINCE_SLACK_SECS: i64 = 2;

/// The free space of the volumes that hold the distro (`P2PC_DISTRO_DIR`) and the backups (`P2PC_BACKUP_DIR`), one
/// line each, in that order (`Get-VolumeRoot`, `Get-FreeBytes`). Read-only.
pub const FREE_SPACE_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
foreach ($p in @($env:P2PC_DISTRO_DIR, $env:P2PC_BACKUP_DIR)) {
    $root = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($p))
    'volume=' + $root + '|free=' + (New-Object System.IO.DriveInfo($root)).AvailableFreeSpace
}
"#;

// ---------------------------------------------------------------------------------------------------------------
// The answers of the distro, parsed exactly (each one a pure function, tested on its own).
// ---------------------------------------------------------------------------------------------------------------

/// The state probe's answer (`Get-StateProbe`). `Absent` is a positive answer; anything unclear is `Unknown`, which
/// is never taken as "nothing to save".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateProbe {
    Present,
    Absent,
    /// `/var/lib/p2pc-server` without `/var/lib/p2pc`: refused, with or without force.
    HubOnly,
    Unknown,
}

impl StateProbe {
    /// Exit 0 and exactly one marker line.
    pub fn parse(out: &Output) -> Self {
        if !out.success() {
            return Self::Unknown;
        }
        let text = out.stdout_text();
        let markers: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("P2PC_STATE="))
            .collect();
        match markers.as_slice() {
            ["P2PC_STATE=present"] => Self::Present,
            ["P2PC_STATE=absent"] => Self::Absent,
            ["P2PC_STATE=hub-only"] => Self::HubOnly,
            _ => Self::Unknown,
        }
    }
}

/// What will be carried, in KiB (`Get-StateSize`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateSize {
    pub agent_kib: u64,
    /// `None` without the hub's data.
    pub hub_kib: Option<u64>,
}

impl StateSize {
    /// Both together, in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.agent_kib
            .saturating_add(self.hub_kib.unwrap_or(0))
            .saturating_mul(1024)
    }

    /// Exit 0, one `/var/lib/p2pc` line and at most one `/var/lib/p2pc-server` line, nothing else. An unknown size is
    /// never small enough.
    pub fn parse(out: &Output) -> Option<Self> {
        if !out.success() {
            return None;
        }
        let (mut agent, mut hub) = (Vec::new(), Vec::new());
        for line in out.stdout_text().lines().map(str::trim).filter(|l| !l.is_empty()) {
            let (kib, path) = line.split_once(char::is_whitespace)?;
            if kib.is_empty() || !kib.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let kib: u64 = kib.parse().ok()?;
            match path.trim_start() {
                "/var/lib/p2pc" => agent.push(kib),
                "/var/lib/p2pc-server" => hub.push(kib),
                _ => return None,
            }
        }
        match (agent.as_slice(), hub.as_slice()) {
            ([a], []) => Some(Self {
                agent_kib: *a,
                hub_kib: None,
            }),
            ([a], [h]) => Some(Self {
                agent_kib: *a,
                hub_kib: Some(*h),
            }),
            _ => None,
        }
    }
}

/// The config migration's answer (`Get-ConfigMigrationResult`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigMigration {
    Present,
    Moved,
    Created,
}

impl ConfigMigration {
    /// Exit 0 and exactly one known marker; `None` otherwise.
    pub fn parse(out: &Output) -> Option<Self> {
        if !out.success() {
            return None;
        }
        let text = out.stdout_text();
        let markers: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("P2PC_CONFIG="))
            .collect();
        match markers.as_slice() {
            ["P2PC_CONFIG=present"] => Some(Self::Present),
            ["P2PC_CONFIG=moved"] => Some(Self::Moved),
            ["P2PC_CONFIG=created"] => Some(Self::Created),
            _ => None,
        }
    }
}

/// A listing line that is not compared (`Test-StateListingIgnored`): sockets and FIFOs, and the boot step's own files.
pub fn is_listing_ignored(line: &str) -> bool {
    let mut parts = line.splitn(5, ':');
    let (mode, uid, gid, kind) = (parts.next(), parts.next(), parts.next(), parts.next());
    let digits = |s: Option<&str>| s.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
    if digits(mode) && digits(uid) && digits(gid) && matches!(kind, Some("s" | "p")) {
        return true;
    }
    // `:p2pc/(tmp|tmp/.*|boot-status\.json|\.boot-status\..*)$`, matched against the text after any colon.
    line.match_indices(':').any(|(i, _)| {
        let rest = &line[i + 1..];
        rest == "p2pc/tmp"
            || rest.starts_with("p2pc/tmp/")
            || rest == "p2pc/boot-status.json"
            || rest.starts_with("p2pc/.boot-status.")
    })
}

/// The listing's lines, ignored ones dropped, sorted.
pub fn parse_listing(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty() && !is_listing_ignored(l))
        .map(str::to_owned)
        .collect();
    lines.sort();
    lines
}

/// `p2pc-state-<14 digits>.tar` or `.ok.tar` (`Test-StateBackupName`).
pub fn is_state_backup_name(name: &str) -> bool {
    backup_stamp_of(name).is_some()
}

/// `p2pc-state-<14 digits>.ok.tar`: the backup of an upgrade that was verified (`Test-StateBackupVerified`).
pub fn is_verified_backup_name(name: &str) -> bool {
    backup_stamp_of(name).is_some() && name.ends_with(".ok.tar")
}

fn backup_stamp_of(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("p2pc-state-")?;
    let stamp = rest.strip_suffix(".ok.tar").or_else(|| rest.strip_suffix(".tar"))?;
    (stamp.len() == 14 && stamp.bytes().all(|b| b.is_ascii_digit())).then_some(stamp)
}

/// Of the verified backups, all but the newest `keep` (`Get-BackupsToPrune`). Nothing else is ever listed: an
/// unfinished backup is the only copy of an identity.
pub fn backups_to_prune(names: &[String], keep: usize) -> Vec<String> {
    let mut done: Vec<&String> = names.iter().filter(|n| is_verified_backup_name(n)).collect();
    done.sort_unstable_by(|a, b| b.cmp(a));
    done.into_iter().skip(keep).cloned().collect()
}

/// An absolute Linux path that needs no quoting anywhere (`Test-LinuxSafePath`).
pub fn is_linux_safe_path(path: &str) -> bool {
    path.len() > 1
        && path.starts_with('/')
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
}

/// [`STATE_ARCHIVE_SCRIPT`] writing to `out` (`Get-StateArchiveScript`); `None` for an unsafe path.
pub fn state_archive_script(out: &str) -> Option<String> {
    is_linux_safe_path(out).then(|| STATE_ARCHIVE_SCRIPT.replace("@OUT@", out))
}

/// The bytes each Windows volume needs (`Get-UpgradeSpaceNeeds`): the distro's volume holds the archive while it is
/// made and restored, plus the floor; the backup's volume holds its copy. The same volume (compared without case)
/// needs both.
pub fn space_needs(state_bytes: u64, distro_root: &str, backup_root: &str, min_free: u64) -> Vec<(String, u64)> {
    let mut needs = vec![(distro_root.to_owned(), state_bytes.saturating_add(min_free))];
    if distro_root.eq_ignore_ascii_case(backup_root) {
        needs[0].1 = needs[0].1.saturating_add(state_bytes);
    } else {
        needs.push((backup_root.to_owned(), state_bytes));
    }
    needs
}

/// `volume=<root>|free=<bytes>` lines of [`FREE_SPACE_SCRIPT`], in order.
pub fn parse_free_space(text: &str) -> Option<Vec<(String, u64)>> {
    let vols: Option<Vec<(String, u64)>> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            let (vol, free) = l.strip_prefix("volume=")?.rsplit_once("|free=")?;
            Some((vol.to_owned(), free.parse().ok()?))
        })
        .collect();
    vols.filter(|v| v.len() == 2)
}

/// A UTC time as the backup's 14 digits, `YYYYMMDDHHMMSS`.
pub fn backup_stamp(at: SystemTime) -> String {
    task::start_boundary(at).chars().filter(char::is_ascii_digit).collect()
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Seconds since the epoch of an RFC 3339 time (`2026-11-12T10:00:00Z`, `…T10:00:00.5+01:00`); `None` when it is not
/// one.
pub fn rfc3339_seconds(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = text.get(r)?;
        (!s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (y, mo, d, h, mi, s) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    let offset = match text.get(i..)? {
        "Z" | "z" => 0,
        o if o.len() == 6 && matches!(o.as_bytes()[0], b'+' | b'-') && o.as_bytes()[3] == b':' => {
            let oh = num(i + 1..i + 3)?;
            let om = num(i + 4..i + 6)?;
            let v = oh * 3600 + om * 60;
            if o.as_bytes()[0] == b'-' { -v } else { v }
        }
        _ => return None,
    };
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s - offset)
}

/// The value after `<label>:` in `p2pc-agent status` (`Get-StatusField`).
pub fn status_field<'t>(text: &'t str, label: &str) -> &'t str {
    text.lines()
        .find_map(|l| l.strip_prefix(label)?.strip_prefix(':'))
        .map(str::trim)
        .unwrap_or("")
}

/// The agent says it connected at or after `not_before` (less the slack), both read from the distro's clock
/// (`Test-ConnectedSince`).
pub fn connected_since(connection: &str, not_before: Option<i64>) -> bool {
    if !connection.starts_with("connected") {
        return false;
    }
    let Some(not_before) = not_before else {
        return true;
    };
    let Some(since) = connection
        .strip_prefix("connected (since ")
        .and_then(|r| r.split_once(')'))
        .map(|(t, _)| t)
    else {
        return false;
    };
    rfc3339_seconds(since).is_some_and(|s| s >= not_before - CONNECTED_SINCE_SLACK_SECS)
}

/// The exit code the supervisor stopped for good on (`state=stopped`, `exit_code=N` in `node-run.status`;
/// `Get-NodeRunStop`).
pub fn node_run_stop(out: &Output) -> Option<u32> {
    if !out.success() {
        return None;
    }
    let text = out.stdout_text();
    if !text.lines().any(|l| l.trim_end() == "state=stopped") {
        return None;
    }
    let code = text.lines().find_map(|l| l.trim_end().strip_prefix("exit_code="))?;
    (!code.is_empty() && code.bytes().all(|b| b.is_ascii_digit()))
        .then(|| code.parse().ok())
        .flatten()
}

// ---------------------------------------------------------------------------------------------------------------
// Byte-exact pipes through wsl.exe.
// ---------------------------------------------------------------------------------------------------------------

/// Why a copy into or out of the distro failed.
#[derive(Debug, thiserror::Error)]
pub enum PipeError {
    /// A path or a name that would need quoting.
    #[error("unsafe path: {0}")]
    UnsafePath(String),
    #[error(transparent)]
    Run(#[from] RunError),
    /// A command in the distro failed.
    #[error("{what} failed (exit {code:?}): {message}")]
    Failed {
        what: String,
        code: Option<i32>,
        message: String,
    },
    /// The bytes changed on their way.
    #[error("{0} changed on its way (SHA-256 mismatch)")]
    HashMismatch(String),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

fn failed(what: impl Into<String>, out: &Output) -> PipeError {
    PipeError::Failed {
        what: what.into(),
        code: out.code,
        message: sanitize_message(&out.text()),
    }
}

/// Copies a file out of the distro to `dest`, byte for byte: `cat` in the distro, its stdout streamed to the file.
/// Not retried (as `Invoke-WslCopyOut`): the caller checks the copy's hash.
pub fn copy_out(host: Host<'_>, linux_path: &str, dest: &Path) -> Result<(), PipeError> {
    if !is_linux_safe_path(linux_path) {
        return Err(PipeError::UnsafePath(linux_path.to_owned()));
    }
    let out = host.run(&in_distro(&["/bin/cat", linux_path]).stdout_file(dest))?;
    if !out.success() {
        return Err(failed(format!("copying {linux_path} out of the distro"), &out));
    }
    Ok(())
}

/// Copies `src` into the distro at `linux_path`, byte for byte: the file streamed to the stdin of `dd` there
/// (`Invoke-WslStream`), retried on the WSL service timeout. The caller checks the hash in the distro.
pub fn copy_in(host: Host<'_>, src: &Path, linux_path: &str) -> Result<(), PipeError> {
    if !is_linux_safe_path(linux_path) {
        return Err(PipeError::UnsafePath(linux_path.to_owned()));
    }
    let out = host.run_wsl(&dd_into(linux_path).stdin_file(src))?;
    if !out.success() {
        return Err(failed(format!("copying into {linux_path}"), &out));
    }
    Ok(())
}

/// `dd of=<path> bs=1M status=none` in the distro: truncates the file and keeps its mode.
fn dd_into(linux_path: &str) -> Invocation {
    in_distro(&["/bin/dd", &format!("of={linux_path}"), "bs=1M", "status=none"])
}

/// The SHA-256 of a file in the distro (`Get-DistroFileHash`), or `None`.
pub fn distro_file_hash(host: Host<'_>, linux_path: &str) -> Option<Sha256Digest> {
    let out = host.in_distro(&["/usr/bin/sha256sum", linux_path]).ok()?;
    if !out.success() {
        return None;
    }
    let text = out.stdout_text();
    Sha256Digest::from_hex(text.get(..64)?).ok()
}

/// A file name that needs no quoting and is not hidden.
fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Writes `bytes` to `<dir>/<name>` in the distro, as root, byte-exact (§14.1: each file goes to the stdin of a
/// command run inside the distro, never through `/mnt/c` or `\\wsl$`). The directory is created (0700) when missing; the
/// bytes go to a hidden temporary file there (0600), its SHA-256 is checked inside the distro, and only then is it
/// renamed over `<name>`, so a reader never sees half a file. A failure removes the temporary file.
pub fn write_file_in_distro(host: Host<'_>, bytes: &[u8], dir: &str, name: &str) -> Result<(), PipeError> {
    if !is_linux_safe_path(dir) || dir.split('/').any(|c| c == "..") {
        return Err(PipeError::UnsafePath(dir.to_owned()));
    }
    if !is_safe_name(name) {
        return Err(PipeError::UnsafePath(name.to_owned()));
    }
    let target = format!("{dir}/{name}");
    let part = format!("{dir}/.{name}.p2pc-part");
    let mk = host.in_distro(&["/bin/mkdir", "-p", "-m", "0700", dir])?;
    if !mk.success() {
        return Err(failed(format!("creating {dir}"), &mk));
    }
    let result = (|| {
        let create = host.in_distro(&["/usr/bin/install", "-m", "0600", "/dev/null", &part])?;
        if !create.success() {
            return Err(failed(format!("creating {part}"), &create));
        }
        let out = host.run_wsl(&dd_into(&part).stdin(bytes.to_vec()))?;
        if !out.success() {
            return Err(failed(format!("copying into {part}"), &out));
        }
        let want = Sha256Digest::of(bytes);
        if distro_file_hash(host, &part) != Some(want) {
            return Err(PipeError::HashMismatch(target.clone()));
        }
        let mv = host.in_distro(&["/bin/mv", "-f", &part, &target])?;
        if !mv.success() {
            return Err(failed(format!("renaming {part}"), &mv));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = host.in_distro(&["/bin/rm", "-f", &part]);
    }
    result
}

// ---------------------------------------------------------------------------------------------------------------
// The upgrade.
// ---------------------------------------------------------------------------------------------------------------

/// What can stop an upgrade. [`UpgradeError::exit_code`] is `install.ps1`'s for the same case.
#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    /// 22.
    #[error("{DISTRO_NAME} is not installed, so there is nothing to upgrade")]
    NotInstalled,
    /// 23: refused before the old distro was touched.
    #[error("{0} The old distro was NOT touched.")]
    Refused(String),
    /// 24.
    #[error("wsl --unregister {DISTRO_NAME} failed (exit {code:?}): {message}")]
    Unregister { code: Option<i32>, message: String },
    /// 19 (the directory), 20 (the import) or 21 (the verification).
    #[error(transparent)]
    Import(ImportError),
    /// 25.
    #[error("restoring /var/lib/p2pc and /var/lib/p2pc-server failed: {0}")]
    Restore(String),
    /// 26.
    #[error("/var/lib/p2pc or /var/lib/p2pc-server after the restore differs from before (names, modes or owners)")]
    ListingDiffers,
    /// 38.
    #[error("{0}")]
    NotEnrolled(String),
    /// The task's state could not be read (nothing was touched).
    #[error(transparent)]
    Task(#[from] TaskError),
    #[error(transparent)]
    Run(#[from] RunError),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

impl UpgradeError {
    /// `install.ps1 -Upgrade`'s exit code for the same case.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::NotInstalled => 22,
            Self::Refused(_) => 23,
            Self::Unregister { .. } => 24,
            Self::Import(ImportError::DirNotEmpty { .. }) => 19,
            Self::Import(ImportError::Unhealthy { .. }) => 21,
            Self::Import(_) => 20,
            Self::Restore(_) => 25,
            Self::ListingDiffers => 26,
            Self::NotEnrolled(_) => 38,
            Self::Task(_) | Self::Run(_) | Self::Io { .. } => 1,
        }
    }
}

/// Why the task was left stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeptStopped {
    /// The node had stopped for good (7, 8 or unknown): it stays stopped until it is joined again.
    StoppedForGood { code: Option<u32> },
    /// The user had stopped it (the task was disabled).
    DisabledBefore,
    /// The upgrade failed after the old distro was gone: the new one does not hold the identity yet.
    NoIdentityYet,
}

/// What became of the scheduled task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskOutcome {
    /// The upgrade stopped before the task was touched.
    Untouched,
    NotRegistered,
    /// Enabled and started again; `not_before` is the distro's clock just before (seconds since the epoch).
    Started {
        not_before: Option<i64>,
    },
    /// It should have been started again, but enabling or starting it failed (a warning).
    NotStarted {
        reason: String,
    },
    KeptStopped(KeptStopped),
}

/// Whether the node came back after the upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CameBack {
    /// Connected since the task was started.
    Connected,
    /// Not yet (a warning: the agent keeps trying by itself). The last `Connection:` value.
    NotYet { connection: String },
}

/// What [`upgrade`] needs besides the host, the layout and the image.
#[derive(Debug, Clone)]
pub struct UpgradeOptions<'a> {
    /// To register the task again (so an older task gets the current wrapper); `None` leaves its registration.
    pub task: Option<&'a TaskContext>,
    /// Go on when the old distro has no `/var/lib/p2pc` (`-Force`): the node will have to join again.
    pub force_without_state: bool,
    /// The free-space floor on the distro's drive, in GiB (`-MinFreeGB`).
    pub min_free_gib: u64,
    /// When the upgrade starts (the backup's name).
    pub now: SystemTime,
    /// How long to wait for the node to come back connected.
    pub connect_wait: Duration,
}

impl<'a> UpgradeOptions<'a> {
    /// `install.ps1`'s defaults: no force, 20 GiB, 60 s.
    pub fn new(now: SystemTime) -> Self {
        Self {
            task: None,
            force_without_state: false,
            min_free_gib: crate::checks::Thresholds::default().min_free_gib,
            now,
            connect_wait: CONNECT_WAIT,
        }
    }
}

/// A finished upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upgraded {
    /// The new image's `image_version=` line.
    pub image_version: String,
    /// The verified backup (`p2pc-state-<time>.ok.tar`), `None` when there was no state to carry.
    pub backup: Option<PathBuf>,
    /// The archive held the hub's data.
    pub carried_hub: bool,
    /// How many entries were restored identically.
    pub entries: usize,
    pub boot_status: Option<BootStatus>,
    pub task: TaskOutcome,
    /// `None` when the task was not started again.
    pub came_back: Option<CameBack>,
    pub warnings: Vec<String>,
}

/// An upgrade that did not finish.
#[derive(Debug)]
pub struct UpgradeFailure {
    pub error: UpgradeError,
    /// The backup of the state, when it is the only copy of the identity (and on the hub PC of the cloud's
    /// database): never deleted; the app names it by its full path.
    pub kept_backup: Option<PathBuf>,
    /// The old distro was unregistered.
    pub touched: bool,
    pub task: TaskOutcome,
    pub warnings: Vec<String>,
}

/// The stop record, with the code read from `node-run.status` when the wrapper could not record it
/// (`Read-NodeStopRecord`).
fn read_stop(host: Host<'_>, layout: &Layout) -> Option<task::StopRecord> {
    let mut stop = task::read_stop_record(layout)?;
    if stop.code.is_none()
        && let Ok(out) = host.in_distro(&["/bin/cat", NODE_RUN_STATUS_PATH])
        && let Some(code) = node_run_stop(&out)
    {
        stop.code = Some(code);
        let text = out.stdout_text();
        if stop.time.is_empty() {
            stop.time = status_value(&text, "time");
        }
        if stop.reason.is_empty() {
            stop.reason = status_value(&text, "reason");
        }
    }
    Some(stop)
}

fn status_value(text: &str, key: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .map(|v| v.trim_end().to_owned())
        .unwrap_or_default()
}

/// Forgets a terminal stop (`Clear-NodeStop`): the wrapper's record and the supervisor's.
fn clear_stop(host: Host<'_>, layout: &Layout) -> Vec<String> {
    let mut warnings = Vec::new();
    match fs::remove_file(layout.stop_record()) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warnings.push(format!("could not delete {}: {e}", layout.stop_record().display())),
    }
    let _ = host.in_distro(&["/bin/rm", "-f", NODE_RUN_STATUS_PATH]);
    warnings
}

/// The distro's clock in seconds (`Get-DistroNow`); Windows' when the distro cannot be asked.
fn distro_now(host: Host<'_>) -> i64 {
    host.in_distro(&["/bin/date", "-u", "+%s"])
        .ok()
        .filter(Output::success)
        .and_then(|o| o.stdout_text().parse().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        })
}

/// `p2pc-agent status` with the agent's config named (`Get-AgentStatus` on the 0.2.2 layout).
fn agent_status(host: Host<'_>) -> String {
    let env = format!("P2PC_AGENT_CONFIG={AGENT_CONFIG_PATH}");
    host.in_distro(&["/usr/bin/env", &env, AGENT_PATH, "status"])
        .map(|o| o.text())
        .unwrap_or_default()
}

/// Waits up to `wait` (a deadline on the monotonic clock, not a count of turns) for a connection made since
/// `not_before` (`Wait-NodeConnected`). When none came, a supervisor that stopped for good on 7 or 8 is
/// [`UpgradeError::NotEnrolled`]; anything else is [`CameBack::NotYet`].
pub fn wait_came_back(host: Host<'_>, not_before: Option<i64>, wait: Duration) -> Result<CameBack, UpgradeError> {
    let pause = host.pause();
    let deadline = pause.now() + wait;
    let mut connection;
    loop {
        connection = status_field(&agent_status(host), "Connection").to_owned();
        if connected_since(&connection, not_before) {
            return Ok(CameBack::Connected);
        }
        if pause.now() >= deadline {
            break;
        }
        pause.sleep(CONNECT_POLL);
    }
    let stop = host
        .in_distro(&["/bin/cat", NODE_RUN_STATUS_PATH])
        .ok()
        .and_then(|o| node_run_stop(&o));
    match stop {
        Some(8) => Err(UpgradeError::NotEnrolled(format!(
            "after the upgrade the agent stopped with exit 8: it finds no enrollment in {AGENT_CONFIG_PATH}; join this PC again"
        ))),
        Some(7) => Err(UpgradeError::NotEnrolled(
            "after the upgrade the agent stopped with exit 7: the hub says this node is not enrolled (it was removed); join this PC again".to_owned(),
        )),
        _ => Ok(CameBack::NotYet { connection }),
    }
}

/// Upgrades `p2pc-node` to `image`, carrying `/var/lib/p2pc` and `/var/lib/p2pc-server` (see the module docs).
///
/// The caller has asked the user (§14.2: "Update now", "Tonight at 03:00", "Later") and checked the image.
pub fn upgrade(
    host: Host<'_>,
    layout: &Layout,
    image: &VerifiedImage,
    opts: &UpgradeOptions<'_>,
) -> Result<Upgraded, Box<UpgradeFailure>> {
    let early = |error: UpgradeError| {
        Box::new(UpgradeFailure {
            error,
            kept_backup: None,
            touched: false,
            task: TaskOutcome::Untouched,
            warnings: Vec::new(),
        })
    };
    match distro_exists(host) {
        Ok(true) => {}
        Ok(false) => return Err(early(UpgradeError::NotInstalled)),
        Err(e) => return Err(early(e.into())),
    }
    // `Assert-UpgradeDirClean`: after the unregister the new image could not be imported into a directory that holds
    // somebody's files.
    check_distro_dir(&layout.distro_dir()).map_err(|e| early(UpgradeError::Import(e)))?;
    let task_state = task::state(host).map_err(|e| early(e.into()))?;
    let registered = task_state != TaskState::NotRegistered;
    // A stop record decides, whatever the task's state: only 6 (too old) is fixed by a newer image.
    let stop = read_stop(host, layout);
    let was_enabled = match &stop {
        Some(s) => s.code == Some(6),
        None => task_state != TaskState::Disabled,
    };
    let mut warnings = Vec::new();
    if registered {
        warnings.extend(task::suspend(host));
    }

    let mut steps = Steps {
        host,
        layout,
        opts,
        touched: false,
        kept_backup: None,
        carried_hub: false,
        was_enrolled: false,
    };
    let result = steps.run(image);

    let mut task_outcome = TaskOutcome::NotRegistered;
    if registered {
        // Registered again, disabled, so an older task gets the current wrapper and rights; a failure only warns.
        if let Some(ctx) = opts.task
            && let Err(e) = task::register(host, layout, ctx, false)
        {
            warnings.push(format!(
                "the scheduled task could not be registered again (the old one stays): {e}"
            ));
        }
        let done = result.is_ok();
        task_outcome = if !was_enabled {
            if let Err(e) = task::disable(host) {
                warnings.push(e.to_string());
            }
            TaskOutcome::KeptStopped(match &stop {
                Some(s) => KeptStopped::StoppedForGood { code: s.code },
                None => KeptStopped::DisabledBefore,
            })
        } else if done || !steps.touched {
            if done && stop.is_some() {
                warnings.extend(clear_stop(host, layout));
            }
            let not_before = distro_now(host);
            match task::resume(host) {
                Ok(()) => TaskOutcome::Started {
                    not_before: Some(not_before),
                },
                Err(e) => {
                    warnings.push(e.to_string());
                    TaskOutcome::NotStarted { reason: e.to_string() }
                }
            }
        } else {
            if let Err(e) = task::disable(host) {
                warnings.push(e.to_string());
            }
            TaskOutcome::KeptStopped(KeptStopped::NoIdentityYet)
        };
    }

    let done = match result {
        Ok(done) => done,
        Err(error) => {
            return Err(Box::new(UpgradeFailure {
                error,
                kept_backup: steps.kept_backup.filter(|p| p.exists()),
                touched: steps.touched,
                task: task_outcome,
                warnings,
            }));
        }
    };
    let came_back = match &task_outcome {
        TaskOutcome::Started { not_before } => match wait_came_back(host, *not_before, opts.connect_wait) {
            Ok(c) => {
                if let CameBack::NotYet { connection } = &c {
                    warnings.push(format!(
                        "the agent is not connected since the task started, after {} s ({connection}); it keeps trying by itself",
                        opts.connect_wait.as_secs()
                    ));
                }
                Some(c)
            }
            Err(error) => {
                return Err(Box::new(UpgradeFailure {
                    error,
                    kept_backup: None,
                    touched: true,
                    task: task_outcome,
                    warnings,
                }));
            }
        },
        _ => None,
    };
    Ok(Upgraded {
        image_version: done.image_version,
        backup: done.backup,
        carried_hub: steps.carried_hub,
        entries: done.entries,
        boot_status: done.boot_status,
        task: task_outcome,
        came_back,
        warnings,
    })
}

struct Done {
    image_version: String,
    backup: Option<PathBuf>,
    entries: usize,
    boot_status: Option<BootStatus>,
}

struct Steps<'a, 'h> {
    host: Host<'h>,
    layout: &'a Layout,
    opts: &'a UpgradeOptions<'a>,
    touched: bool,
    kept_backup: Option<PathBuf>,
    carried_hub: bool,
    was_enrolled: bool,
}

fn io_err(context: String) -> impl FnOnce(std::io::Error) -> UpgradeError {
    move |source| UpgradeError::Io { context, source }
}

impl Steps<'_, '_> {
    fn sh(&self, script: &str) -> Result<Output, RunError> {
        self.host.in_distro(&["/bin/sh", "-c", script])
    }

    fn has_server_section(&self) -> Result<bool, RunError> {
        Ok(self.host.in_distro(&SERVER_SECTION_CHECK)?.success())
    }

    fn listing(&self) -> Result<Option<Vec<String>>, RunError> {
        let mut argv: Vec<&str> = STATE_LISTING.to_vec();
        argv.push(STATE_LISTING_FORMAT);
        let out = self.host.in_distro(&argv)?;
        Ok(out.success().then(|| parse_listing(&out.stdout_text())))
    }

    /// `Test-UpgradeSpace`: refuses (23) when a volume cannot hold what it needs, or its free space is unknown.
    fn check_space(&self, size: &StateSize, backups: &Path) -> Result<(), UpgradeError> {
        let out = self.host.run(
            &powershell(FREE_SPACE_SCRIPT)
                .env("P2PC_DISTRO_DIR", self.layout.distro_dir().display().to_string())
                .env("P2PC_BACKUP_DIR", backups.display().to_string()),
        )?;
        let vols = out
            .success()
            .then(|| parse_free_space(&out.stdout_text()))
            .flatten()
            .ok_or_else(|| UpgradeError::Refused("Could not read the free space of the Windows drives.".to_owned()))?;
        let min_free = self.opts.min_free_gib.saturating_mul(crate::checks::GIB);
        let state = size.total_bytes();
        for (root, need) in space_needs(state, &vols[0].0, &vols[1].0, min_free) {
            let free = vols
                .iter()
                .find(|(r, _)| r.eq_ignore_ascii_case(&root))
                .map_or(0, |(_, f)| *f);
            if free < need {
                return Err(UpgradeError::Refused(format!(
                    "Not enough free space on {root} for the upgrade: the state to carry is {} MB; {} GB needed, {} GB free.",
                    state.div_ceil(1 << 20),
                    need.div_ceil(crate::checks::GIB),
                    free / crate::checks::GIB
                )));
            }
        }
        Ok(())
    }

    /// Archives inside the distro, copies out, checks the hash. Returns the hash of the copy.
    fn export(&self, in_distro_backup: &str, state_file: &Path) -> Result<Sha256Digest, UpgradeError> {
        let refused = |what: String| UpgradeError::Refused(what);
        let script = state_archive_script(in_distro_backup)
            .ok_or_else(|| refused(format!("unsafe archive path: {in_distro_backup}")))?;
        let a = self.host.in_distro(&["/bin/bash", "-c", &script])?;
        let text = a.stdout_text();
        let inside = text
            .lines()
            .find_map(|l| {
                let (hash, path) = l.split_once("  ")?;
                (path.trim_end() == in_distro_backup).then(|| Sha256Digest::from_hex(hash).ok())?
            })
            .filter(|_| a.success())
            .ok_or_else(|| {
                refused(format!(
                    "Could not archive /var/lib/p2pc and /var/lib/p2pc-server inside the old distro: {}",
                    sanitize_message(&a.text())
                ))
            })?;
        let discard = || {
            let _ = fs::remove_file(state_file);
        };
        if let Err(e) = copy_out(self.host, in_distro_backup, state_file) {
            discard();
            return Err(refused(format!(
                "Could not copy the state archive out of the old distro: {e}."
            )));
        }
        let outside = match sha256_file(state_file) {
            Ok(h) => h,
            Err(e) => {
                discard();
                return Err(refused(format!("Could not read the copy of the state archive: {e}.")));
            }
        };
        if outside != inside {
            discard();
            return Err(refused(format!(
                "The state archive changed on its way out of the old distro (SHA-256 inside {inside}, of the copy {outside})."
            )));
        }
        Ok(outside)
    }

    /// Streams the backup into the new distro, checks it there, extracts it.
    fn restore(&self, state_file: &Path, hash: Sha256Digest) -> Result<(), UpgradeError> {
        let h = self.host;
        let mk = h.in_distro(&["/usr/bin/install", "-m", "0600", "/dev/null", IN_DISTRO_TAR])?;
        if !mk.success() {
            return Err(UpgradeError::Restore(format!(
                "could not create the state file in the new distro: {}",
                sanitize_message(&mk.text())
            )));
        }
        copy_in(h, state_file, IN_DISTRO_TAR)
            .map_err(|e| UpgradeError::Restore(format!("could not copy the state file into the new distro: {e}")))?;
        if distro_file_hash(h, IN_DISTRO_TAR) != Some(hash) {
            return Err(UpgradeError::Restore(
                "the state file was corrupted on its way into the new distro".to_owned(),
            ));
        }
        let x = h.in_distro(&["/bin/tar", "--numeric-owner", "-C", "/var/lib", "-xpf", IN_DISTRO_TAR])?;
        if !x.success() {
            return Err(UpgradeError::Restore(sanitize_message(&x.text())));
        }
        Ok(())
    }

    fn run(&mut self, image: &VerifiedImage) -> Result<Done, UpgradeError> {
        let h = self.host;
        let _ = h.wsl(["--terminate", DISTRO_NAME]);
        let stamp = backup_stamp(self.opts.now);
        let backups = self.layout.backups_dir();
        let state_file = backups.join(format!("p2pc-state-{stamp}.tar"));
        let in_distro_backup = format!("/var/tmp/p2pc-state-{stamp}.tar");

        // 1. Only a positive answer lets the upgrade go on.
        let probe_out = self.sh(STATE_PROBE_SCRIPT)?;
        let has_state = match StateProbe::parse(&probe_out) {
            StateProbe::Present => true,
            StateProbe::Absent if self.opts.force_without_state => {
                tracing::warn!("/var/lib/p2pc does not exist in the old distro: going on; the node has to join again");
                false
            }
            StateProbe::Absent => {
                return Err(UpgradeError::Refused(
                    "/var/lib/p2pc does not exist in the old distro, so there is no agent identity to carry over."
                        .to_owned(),
                ));
            }
            StateProbe::HubOnly => {
                return Err(UpgradeError::Refused(
                    "/var/lib/p2pc-server (the hub data: the database, keys and blobs of your cloud) exists, but /var/lib/p2pc (the agent state) does not; they are carried only together.".to_owned(),
                ));
            }
            StateProbe::Unknown => {
                return Err(UpgradeError::Refused(format!(
                    "Could not tell whether /var/lib/p2pc exists in the old distro (probe exit {:?}: {}).",
                    probe_out.code,
                    sanitize_message(&probe_out.text())
                )));
            }
        };

        let mut before = Vec::new();
        let mut hash = None;
        if has_state {
            let size_out = self.sh(STATE_SIZE_SCRIPT)?;
            let size = StateSize::parse(&size_out).ok_or_else(|| {
                UpgradeError::Refused(format!(
                    "Could not measure /var/lib/p2pc and /var/lib/p2pc-server in the old distro (exit {:?}: {}).",
                    size_out.code,
                    sanitize_message(&size_out.text())
                ))
            })?;
            self.check_space(&size, &backups)?;
            self.carried_hub = size.hub_kib.is_some();
            let mig = self.sh(CONFIG_MIGRATION_SCRIPT)?;
            if ConfigMigration::parse(&mig).is_none() {
                return Err(UpgradeError::Refused(format!(
                    "Could not put the agent config into /var/lib/p2pc in the old distro (exit {:?}).",
                    mig.code
                )));
            }
            self.was_enrolled = self.has_server_section()?;
            before = self.listing()?.ok_or_else(|| {
                UpgradeError::Refused(
                    "Could not list /var/lib/p2pc and /var/lib/p2pc-server in the old distro.".to_owned(),
                )
            })?;
            fs::create_dir_all(&backups).map_err(io_err(format!("creating {}", backups.display())))?;
            let exported = self.export(&in_distro_backup, &state_file);
            // On every path: the archive holds the identity key and must not stay in the old distro.
            let _ = h.in_distro(&["/bin/rm", "-f", &in_distro_backup]);
            hash = Some(exported?);
            self.kept_backup = Some(state_file.clone());
            tracing::info!(backup = %state_file.display(), "exported the node state");
        }

        // 2. Unregister the old distro and import the new one.
        self.touched = true;
        let u = h.wsl(["--unregister", DISTRO_NAME])?;
        if !u.success() {
            return Err(UpgradeError::Unregister {
                code: u.code,
                message: sanitize_message(&u.text()),
            });
        }
        import_distro(h, &self.layout.distro_dir(), image).map_err(UpgradeError::Import)?;

        // 3. Restore.
        if let Some(hash) = hash {
            let restored = self.restore(&state_file, hash);
            // On every path: the copy of the identity must not stay in the new distro's /tmp.
            let _ = h.in_distro(&["/bin/rm", "-f", IN_DISTRO_TAR]);
            restored?;
        }
        // Restart the distro so that p2pc-boot runs again.
        let _ = h.wsl(["--terminate", DISTRO_NAME]);

        // 4. Verify.
        let image_version = verify_distro(h).map_err(UpgradeError::Import)?;
        if !has_state {
            return Ok(Done {
                image_version,
                backup: None,
                entries: 0,
                boot_status: wait_boot_status(h, BOOT_STATUS_WAIT),
            });
        }
        let after = self.listing()?;
        if after.as_ref() != Some(&before) {
            return Err(UpgradeError::ListingDiffers);
        }
        if self.was_enrolled && !self.has_server_section()? {
            return Err(UpgradeError::NotEnrolled(format!(
                "the node was enrolled, but after the upgrade {AGENT_CONFIG_PATH} holds no [server]: the agent would stop with exit 8"
            )));
        }
        // Verified: the backup is marked done, the only kind that is ever pruned.
        let ok = backups.join(format!("p2pc-state-{stamp}.ok.tar"));
        fs::rename(&state_file, &ok).map_err(io_err(format!("renaming {}", state_file.display())))?;
        self.kept_backup = None;
        let keep = if self.carried_hub { 1 } else { BACKUP_KEEP };
        let names: Vec<String> = fs::read_dir(&backups)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        for old in backups_to_prune(&names, keep) {
            if let Err(e) = fs::remove_file(backups.join(&old)) {
                tracing::warn!(backup = %old, error = %e, "could not delete an old verified backup");
            }
        }
        Ok(Done {
            image_version,
            backup: Some(ok),
            entries: before.len(),
            boot_status: wait_boot_status(h, BOOT_STATUS_WAIT),
        })
    }
}

#[cfg(test)]
#[path = "upgrade_tests.rs"]
mod tests;
