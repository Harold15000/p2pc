// SPDX-License-Identifier: Apache-2.0

//! Uninstall (H2 §8.7, task T2-45).
//!
//! The NSIS uninstaller runs `P2PC.exe --uninstall-cleanup` ([`CLEANUP_FLAG`]) before it removes the app's files, and
//! goes on only when it exits 0 ([`exit`]). The cleanup first shows a confirmation ([`UninstallView`]); then, in order,
//! each step logged to `%TEMP%\p2pc-uninstall-<time>.log` ([`log::UninstallLog`], the only file left afterwards):
//!
//! 1. **Hub PC:** only after the explicit checkbox ("This PC hosts your cloud. Uninstalling deletes your cloud: …";
//!    cancelling stops the uninstall), and before anything is stopped, every other node is deleted through the app's
//!    device connection (`DELETE /v1/nodes/{id}`, best effort, 30 s in total).
//! 2. **Joined PC:** `p2pc-agent leave` (best effort, 10 s).
//! 3. to 5. `p2pc-wsl`'s uninstall: the scheduled task (a failure stops everything here), `wsl --unregister p2pc-node`
//!    (a failure stops here), and `%LOCALAPPDATA%\P2PC` with the backup rule: a failed upgrade's backup is kept and
//!    listed unless "Also delete these backups" was ticked.
//! 6. The app's data folders and its `Run` and `RunOnce` values. (The NSIS hook removes the data folders once more
//!    after the app has exited, for files the webview still held.)
//! 7. WSL stays installed; the final page says how to remove it.
//!
//! The steps are plain Rust behind [`CleanupHost`] and [`HubNodes`], tested with fakes; [`host`] holds the real ones.

#[cfg(feature = "app")]
pub mod glue;
pub mod host;
pub mod log;

use std::path::PathBuf;
use std::time::Duration;

use p2pc_wsl::runner::Pause;
use p2pc_wsl::uninstall::{BackupRule, DistroRemoval, UninstallError, UninstallPlan, Uninstalled};
use serde::{Deserialize, Serialize};

use crate::state::Role;
use log::UninstallLog;

/// The uninstaller's argument.
pub const CLEANUP_FLAG: &str = "--uninstall-cleanup";

/// Step 1's budget for all the deletions together.
pub const HUB_DELETE_BUDGET: Duration = Duration::from_secs(30);
/// Step 2's budget.
pub const LEAVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Step 1's confirmation (§8.7).
pub const HUB_CONSEQUENCE: &str =
    "This PC hosts your cloud. Uninstalling deletes your cloud: your phone and your other PCs will lose it.";
/// The checkbox of the kept backups (§8.7 step 5), unchecked by default.
pub const DELETE_BACKUPS_LABEL: &str = "Also delete these backups";
/// Why a backup is kept.
pub const KEPT_BACKUP_REASON: &str = "Each is the backup of an update that did not finish: it can be the only copy of this PC's identity and, on the hub PC, of your cloud's database.";
/// Step 7.
pub const WSL_STAYS: &str = "WSL itself stays installed: it is part of Windows and may serve other things. To remove it, open Settings > Apps > Installed apps and uninstall \"Windows Subsystem for Linux\".";

/// The process exit codes the NSIS hook reads: anything but [`exit::DONE`] stops the uninstall.
pub mod exit {
    /// The cleanup finished: the uninstaller goes on.
    pub const DONE: u8 = 0;
    /// The user cancelled (or closed the window): nothing was changed.
    pub const CANCELLED: u8 = 1;
    /// A step that must not be skipped failed (the task, or `wsl --unregister`).
    pub const STOPPED: u8 = 3;
}

/// What the confirmation shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UninstallView {
    pub role: Option<Role>,
    /// The hub PC's sentence, with its checkbox.
    pub hub_consequence: Option<&'static str>,
    /// The kept backups, by full path, with [`DELETE_BACKUPS_LABEL`] unchecked.
    pub kept_backups: Vec<String>,
    pub kept_backup_reason: Option<&'static str>,
    pub delete_backups_label: Option<&'static str>,
}

impl UninstallView {
    /// The confirmation for this role and these backups.
    pub fn new(role: Option<Role>, plan: &UninstallPlan) -> Self {
        let kept: Vec<String> = plan.unfinished.iter().map(|p| p.display().to_string()).collect();
        let any = !kept.is_empty();
        Self {
            role,
            hub_consequence: (role == Some(Role::Hub)).then_some(HUB_CONSEQUENCE),
            kept_backups: kept,
            kept_backup_reason: any.then_some(KEPT_BACKUP_REASON),
            delete_backups_label: any.then_some(DELETE_BACKUPS_LABEL),
        }
    }
}

/// The user's answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub struct Confirmation {
    /// The hub PC's checkbox. Without it the hub PC's uninstall does not start.
    #[serde(default)]
    pub hub_confirmed: bool,
    /// "Also delete these backups".
    #[serde(default)]
    pub delete_failed_backups: bool,
}

/// The hub's nodes, over the app's own device connection (§8.7 step 1). Unwired until the device connection lands
/// (T2-30), like [`crate::setup::hub::HubApi`].
pub trait HubNodes {
    /// The ids of every node of the cloud (`GET /v1/nodes`).
    fn node_ids(&self) -> Result<Vec<String>, String>;
    /// `DELETE /v1/nodes/{id}`, within `timeout`.
    fn delete_node(&self, id: &str, timeout: Duration) -> Result<(), String>;
}

/// [`HubNodes`] of a build without the device connection.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnwiredHubNodes;

impl HubNodes for UnwiredHubNodes {
    fn node_ids(&self) -> Result<Vec<String>, String> {
        Err("the device connection is not available in this version".to_owned())
    }
    fn delete_node(&self, _: &str, _: Duration) -> Result<(), String> {
        Err("the device connection is not available in this version".to_owned())
    }
}

/// The PC's side of the cleanup.
pub trait CleanupHost {
    /// This PC's own node id on the hub (`p2pc-agent status --json`), when it has one.
    fn own_node_id(&self) -> Option<String>;
    /// `p2pc-agent leave` within `timeout`.
    fn agent_leave(&self, timeout: Duration) -> Result<(), String>;
    /// Steps 3 to 5 (`p2pc-wsl`'s uninstall).
    fn remove_node(&self, rule: BackupRule) -> Result<Uninstalled, UninstallError>;
    /// Step 6: the app's data folders and the `Run` and `RunOnce` values. Returns what could not be removed.
    fn remove_app_traces(&self) -> Vec<String>;
    /// The distro holds the hub's data (`/var/lib/p2pc-server`).
    fn hub_data_present(&self) -> bool;
}

/// The role the confirmation and the cleanup use: the one `setup.json` recorded, or, when that is unknown (a missing or
/// unreadable record), the hub's when the distro holds the hub's data. The hub PC's explicit checkbox (§8.7 step 1) is
/// then never skipped because a record was lost.
pub fn effective_role(recorded: Option<Role>, host: &dyn CleanupHost) -> Option<Role> {
    recorded.or_else(|| host.hub_data_present().then_some(Role::Hub))
}

/// How the cleanup ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CleanupOutcome {
    /// Nothing was changed.
    Cancelled,
    /// A step that must not be skipped failed; what follows it did not run.
    Stopped { message: String, log: String },
    /// Done: the final page.
    Done {
        lines: Vec<String>,
        kept_backups: Vec<String>,
        log: String,
    },
}

impl CleanupOutcome {
    /// The process exit code for the NSIS hook.
    pub fn exit_code(&self) -> u8 {
        match self {
            CleanupOutcome::Cancelled => exit::CANCELLED,
            CleanupOutcome::Stopped { .. } => exit::STOPPED,
            CleanupOutcome::Done { .. } => exit::DONE,
        }
    }
}

/// Step 1: every node but this PC's own, best effort, within the budget on a monotonic clock.
fn delete_other_nodes(hub: &dyn HubNodes, own: Option<&str>, clock: &dyn Pause, log: &mut UninstallLog) {
    let start = clock.now();
    let ids = match hub.node_ids() {
        Ok(ids) => ids,
        Err(e) => {
            log.line(&format!("step 1: could not list the cloud's nodes: {e}"));
            return;
        }
    };
    let others: Vec<&String> = ids.iter().filter(|id| Some(id.as_str()) != own).collect();
    log.line(&format!("step 1: deleting {} other node(s)", others.len()));
    for id in others {
        let spent = clock.now().saturating_sub(start);
        let Some(left) = HUB_DELETE_BUDGET.checked_sub(spent).filter(|l| !l.is_zero()) else {
            log.line(&format!("step 1: the 30 s budget is spent; node {id} was not deleted"));
            break;
        };
        match hub.delete_node(id, left) {
            Ok(()) => log.line(&format!("step 1: deleted node {id}")),
            Err(e) => log.line(&format!("step 1: could not delete node {id}: {e}")),
        }
    }
}

/// The cleanup, after the confirmation.
pub fn run_cleanup(
    host: &dyn CleanupHost,
    hub: &dyn HubNodes,
    clock: &dyn Pause,
    log: &mut UninstallLog,
    role: Option<Role>,
    confirm: Confirmation,
) -> CleanupOutcome {
    if role == Some(Role::Hub) && !confirm.hub_confirmed {
        log.line("cancelled: the hub PC's confirmation was not given; nothing was changed");
        return CleanupOutcome::Cancelled;
    }
    let log_path = log.path_text();
    match role {
        Some(Role::Hub) => delete_other_nodes(hub, host.own_node_id().as_deref(), clock, log),
        Some(Role::Joined) => match host.agent_leave(LEAVE_TIMEOUT) {
            Ok(()) => log.line("step 2: p2pc-agent leave: the hub removed this node"),
            Err(e) => log.line(&format!("step 2: p2pc-agent leave did not finish: {e}")),
        },
        None => log.line("steps 1-2: this PC never joined or created a cloud"),
    }
    let rule = if confirm.delete_failed_backups {
        BackupRule::DeleteAll
    } else {
        BackupRule::Default
    };
    let removed = match host.remove_node(rule) {
        Ok(r) => r,
        Err(e) => {
            let message = e.to_string();
            log.line(&format!("stopped (install.ps1 exit {}): {message}", e.exit_code()));
            return CleanupOutcome::Stopped { message, log: log_path };
        }
    };
    log.line(&format!(
        "step 3: scheduled task {}",
        if removed.task_removed {
            "removed"
        } else {
            "was not registered"
        }
    ));
    log.line(match removed.distro {
        DistroRemoval::Unregistered => "step 4: wsl --unregister p2pc-node: done",
        DistroRemoval::NotInstalled => "step 4: p2pc-node was not installed",
        DistroRemoval::WslMissing => "step 4: WSL is not installed: no distro to remove",
    });
    log.line(&format!(
        "step 5: %LOCALAPPDATA%\\P2PC deleted ({} state backup(s) deleted, {} kept)",
        removed.removed_backups,
        removed.kept_backups.len()
    ));
    let mut lines = vec!["P2PC was removed from this PC.".to_owned()];
    let kept: Vec<String> = removed.kept_backups.iter().map(|p| p.display().to_string()).collect();
    for k in &kept {
        log.line(&format!("step 5: kept {k}"));
    }
    if !kept.is_empty() {
        lines.push(format!(
            "These backups were kept: {}. {KEPT_BACKUP_REASON}",
            kept.join("; ")
        ));
    }
    let left: Vec<String> = removed.left.iter().map(|p: &PathBuf| p.display().to_string()).collect();
    for l in &left {
        log.line(&format!("could not delete: {l}"));
    }
    if !left.is_empty() {
        lines.push(format!(
            "These could not be deleted; delete them yourself: {}.",
            left.join("; ")
        ));
    }
    // The app's own folders can still be in use by this window's webview: the uninstaller removes them again after
    // the app has exited (the NSIS hook), so what is left here is logged, not shown.
    for l in host.remove_app_traces() {
        log.line(&format!("step 6: left for the uninstaller's last step: {l}"));
    }
    log.line("step 6: the app's data folders and its Run and RunOnce values removed");
    lines.push(WSL_STAYS.to_owned());
    log.line("step 7: WSL stays installed");
    CleanupOutcome::Done {
        lines,
        kept_backups: kept,
        log: log_path,
    }
}

#[cfg(test)]
mod tests;
