// SPDX-License-Identifier: Apache-2.0

//! Removing the node from this PC (H2 §8.7 steps 3 to 5): `install.ps1 -Uninstall` (`Invoke-UninstallAction`) ported,
//! plus the app's own folder.
//!
//! In order, each step stopping the next when it fails:
//!
//! 3. **The scheduled task** "P2PC node" is ended and deleted (it would otherwise start the agent of a distro that no
//!    longer exists at the next sign-in). If it cannot be removed, nothing else is touched (`install.ps1` exit 37) and
//!    the user is told.
//! 4. **`wsl --unregister p2pc-node`**: the distro, its images, its volumes and, on the hub PC, the cloud's database and
//!    blobs. A failure stops here (exit 29): `%LOCALAPPDATA%\P2PC` still holds the virtual disk of a registered distro.
//!    A distro that is not installed, or a PC without `wsl.exe`, goes on to step 5.
//! 5. **`%LOCALAPPDATA%\P2PC`** is deleted, with `install.ps1 -Uninstall`'s backup rule: verified upgrade backups
//!    (`p2pc-state-<time>.ok.tar`) are deleted; the backup of an upgrade that failed (`p2pc-state-<time>.tar`) is
//!    **kept**, because it can be the only copy of the node identity and, on the hub PC, of the cloud's database,
//!    unless the user ticked "Also delete these backups" ([`BackupRule::DeleteAll`]). Kept backups and the folders that
//!    hold them stay; with none, the folder goes entirely. Nothing is deleted through a link.
//!
//! Steps 1, 2, 6 and 7 (the hub's other nodes, `p2pc-agent leave`, the app's data folders and `Run` values, the final
//! page) are the app's (`apps/desktop`, `uninstall/`).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use std::time::Duration;

use crate::import::sanitize_message;
use crate::runner::{Host, Invocation, RunError, WSL_EXE, schtasks};
use crate::task::{self, TASK_PATH, TaskState};
use crate::upgrade::{is_state_backup_name, is_verified_backup_name};
use crate::{DISTRO_NAME, Layout};

/// The time limit of `wsl --list --quiet`: a hung `wsl.exe` must not freeze the uninstaller.
pub const LIST_TIMEOUT: Duration = Duration::from_secs(120);
/// The time limit of `wsl --unregister p2pc-node`: generous, it deletes the distro's whole virtual disk.
pub const UNREGISTER_TIMEOUT: Duration = Duration::from_secs(1800);

/// Which state backups (`Get-StateBackupFiles -Kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupKind {
    All,
    /// `p2pc-state-<time>.ok.tar`.
    Verified,
    /// `p2pc-state-<time>.tar`: an upgrade that failed or never finished.
    Unfinished,
}

/// The state backups of a directory, by full path, sorted: regular files with a backup's name only; nothing else in
/// the folder is ever touched.
pub fn state_backup_files(dir: &Path, kind: BackupKind) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = rd
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            is_state_backup_name(&name)
                && match kind {
                    BackupKind::All => true,
                    BackupKind::Verified => is_verified_backup_name(&name),
                    BackupKind::Unfinished => !is_verified_backup_name(&name),
                }
        })
        .map(|e| e.path())
        .collect();
    files.sort();
    files
}

/// What happens to the state backups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackupRule {
    /// Delete the verified ones, keep the unfinished ones (`install.ps1 -Uninstall`'s default, the app's default).
    #[default]
    Default,
    /// Keep every backup (`-KeepBackups`; not offered by the app).
    KeepAll,
    /// Delete them all (`-DeleteFailedBackups`; the app's "Also delete these backups").
    DeleteAll,
}

/// What the confirmation shows before anything is deleted (§8.7: each kept backup by its full path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallPlan {
    pub backups_dir: PathBuf,
    pub verified: Vec<PathBuf>,
    pub unfinished: Vec<PathBuf>,
}

impl UninstallPlan {
    /// Reads the backups folder. Read-only.
    pub fn read(layout: &Layout) -> Self {
        let backups_dir = layout.backups_dir();
        Self {
            verified: state_backup_files(&backups_dir, BackupKind::Verified),
            unfinished: state_backup_files(&backups_dir, BackupKind::Unfinished),
            backups_dir,
        }
    }

    /// The backups this rule keeps.
    pub fn kept(&self, rule: BackupRule) -> Vec<PathBuf> {
        match rule {
            BackupRule::Default => self.unfinished.clone(),
            BackupRule::KeepAll => self.verified.iter().chain(&self.unfinished).cloned().collect(),
            BackupRule::DeleteAll => Vec::new(),
        }
    }

    /// The backups this rule deletes.
    pub fn deleted(&self, rule: BackupRule) -> Vec<PathBuf> {
        match rule {
            BackupRule::Default => self.verified.clone(),
            BackupRule::KeepAll => Vec::new(),
            BackupRule::DeleteAll => self.verified.iter().chain(&self.unfinished).cloned().collect(),
        }
    }
}

/// What stops an uninstall. [`UninstallError::exit_code`] is `install.ps1`'s for the same case.
#[derive(Debug, thiserror::Error)]
pub enum UninstallError {
    /// 37: nothing else was touched.
    #[error(
        "could not remove the scheduled task '{}': {message}. The distro was NOT touched. Remove it in Task Scheduler, then uninstall again.",
        task::TASK_NAME
    )]
    TaskNotRemoved { message: String },
    /// The distros could not be listed (`wsl.exe` exists but failed to run): nothing was unregistered or deleted.
    #[error("could not list the WSL distros: {0}. Nothing was unregistered or deleted.")]
    Wsl(RunError),
    /// 29: `%LOCALAPPDATA%\P2PC` was not touched.
    #[error(
        "wsl --unregister {DISTRO_NAME} failed (exit {code:?}): {message}. Nothing in %LOCALAPPDATA%\\P2PC was deleted."
    )]
    Unregister { code: Option<i32>, message: String },
}

impl UninstallError {
    /// `install.ps1 -Uninstall`'s exit code for the same case.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::TaskNotRemoved { .. } => 37,
            Self::Wsl(_) => 1,
            Self::Unregister { .. } => 29,
        }
    }
}

/// What became of the distro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistroRemoval {
    Unregistered,
    NotInstalled,
    /// There is no `wsl.exe`: no distro to remove.
    WslMissing,
}

/// A finished uninstall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uninstalled {
    /// The task was registered and is now removed.
    pub task_removed: bool,
    pub distro: DistroRemoval,
    /// How many state backups were deleted.
    pub removed_backups: usize,
    /// The backups kept, by full path (the final page names them).
    pub kept_backups: Vec<PathBuf>,
    /// What could not be deleted (in use, or refused), by full path.
    pub left: Vec<PathBuf>,
}

/// `schtasks /Delete /TN "\P2PC node" /F`.
pub fn delete_task_invocation() -> crate::runner::Invocation {
    schtasks(["/Delete", "/TN", TASK_PATH, "/F"])
}

/// Step 3 (`Remove-NodeTask`): ends and deletes the task. `Ok(false)` when it was not registered. Its state must be
/// readable: an unknown task is never assumed absent.
pub fn remove_task(host: Host<'_>) -> Result<bool, UninstallError> {
    let state = task::state(host).map_err(|e| UninstallError::TaskNotRemoved {
        message: format!("its state could not be read ({e})"),
    })?;
    if state == TaskState::NotRegistered {
        return Ok(false);
    }
    if let Err(e) = task::end(host) {
        tracing::debug!(error = %e, "ending the task before deleting it");
    }
    let out = host
        .run(&delete_task_invocation())
        .map_err(|e| UninstallError::TaskNotRemoved { message: e.to_string() })?;
    if !out.success() {
        return Err(UninstallError::TaskNotRemoved {
            message: sanitize_message(&out.text()),
        });
    }
    Ok(true)
}

/// Step 4: `wsl --unregister p2pc-node` when it is registered. Never touches another distro.
pub fn remove_distro(host: Host<'_>) -> Result<DistroRemoval, UninstallError> {
    let list = Invocation::new(WSL_EXE)
        .args(["--list", "--quiet"])
        .timeout(LIST_TIMEOUT);
    let names: Vec<String> = match host.run_wsl(&list) {
        Ok(out) => out
            .text()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect(),
        Err(e) if e.is_not_found() => return Ok(DistroRemoval::WslMissing),
        Err(e) => return Err(UninstallError::Wsl(e)),
    };
    if !names.iter().any(|n| n == DISTRO_NAME) {
        return Ok(DistroRemoval::NotInstalled);
    }
    let unregister = Invocation::new(WSL_EXE)
        .args(["--unregister", DISTRO_NAME])
        .timeout(UNREGISTER_TIMEOUT);
    let out = host.run_wsl(&unregister).map_err(UninstallError::Wsl)?;
    if !out.success() {
        return Err(UninstallError::Unregister {
            code: out.code,
            message: sanitize_message(&out.text()),
        });
    }
    Ok(DistroRemoval::Unregistered)
}

/// Deletes one entry without following a link: a directory with everything in it (std's `remove_dir_all` does not
/// follow links inside), a file, or the link itself.
fn remove_entry(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_dir() {
        fs::remove_dir_all(path)
    } else {
        // A directory symbolic link or a junction on Windows is removed as a directory, never through.
        fs::remove_file(path).or_else(|e| {
            if meta.file_type().is_symlink() {
                fs::remove_dir(path)
            } else {
                Err(e)
            }
        })
    }
}

/// Step 5: `%LOCALAPPDATA%\P2PC` with the backup rule. Returns (deleted backups, kept backups, left over). Best effort:
/// what cannot be deleted is listed, never retried.
pub fn remove_local(layout: &Layout, rule: BackupRule) -> (usize, Vec<PathBuf>, Vec<PathBuf>) {
    let plan = UninstallPlan::read(layout);
    let kept = plan.kept(rule);
    let mut left = Vec::new();
    let mut removed = 0;
    for f in plan.deleted(rule) {
        match fs::remove_file(&f) {
            Ok(()) => removed += 1,
            Err(e) => {
                tracing::warn!(backup = %f.display(), error = %e, "could not delete a state backup: delete it yourself, it holds the node identity key");
                left.push(f);
            }
        }
    }
    let root = layout.root();
    if let Ok(rd) = fs::read_dir(root) {
        for entry in rd.filter_map(Result::ok) {
            let path = entry.path();
            if path == plan.backups_dir && !kept.is_empty() {
                continue;
            }
            if let Err(e) = remove_entry(&path) {
                tracing::warn!(path = %path.display(), error = %e, "could not delete");
                left.push(path);
            }
        }
    }
    for dir in [plan.backups_dir.as_path(), root] {
        if fs::read_dir(dir).is_ok_and(|mut rd| rd.next().is_none()) {
            let _ = fs::remove_dir(dir);
        }
    }
    left.sort();
    (removed, kept, left)
}

/// Steps 3, 4 and 5 in order (`Invoke-UninstallAction`, without its prompt: the app asks before, §8.7).
pub fn uninstall(host: Host<'_>, layout: &Layout, rule: BackupRule) -> Result<Uninstalled, UninstallError> {
    let task_removed = remove_task(host)?;
    let distro = remove_distro(host)?;
    let (removed_backups, kept_backups, left) = remove_local(layout, rule);
    Ok(Uninstalled {
        task_removed,
        distro,
        removed_backups,
        kept_backups,
        left,
    })
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use super::*;
    use crate::runner::fake::*;
    use crate::runner::{Invocation, Output, SCHTASKS_EXE, WSL_EXE};
    use crate::task::STATE_SCRIPT;

    struct Rig {
        _dir: tempfile::TempDir,
        layout: Layout,
        runner: FakeRunner,
        pause: FakePause,
    }

    const VERIFIED: &str = "p2pc-state-20261101000000.ok.tar";
    const UNFINISHED: &str = "p2pc-state-20261102000000.tar";

    /// A `%LOCALAPPDATA%\P2PC` as the app leaves it: the distro's disk, logs, setup.json, device.key, the wrapper and
    /// both kinds of backup.
    fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        fs::create_dir_all(layout.distro_dir()).unwrap();
        fs::write(layout.distro_dir().join("ext4.vhdx"), b"disk").unwrap();
        fs::create_dir_all(layout.logs_dir()).unwrap();
        fs::write(layout.logs_dir().join("app.log"), b"log").unwrap();
        fs::write(layout.root().join("setup.json"), b"{}").unwrap();
        fs::write(layout.root().join("device.key"), b"k").unwrap();
        fs::write(layout.task_wrapper(), b"@echo off").unwrap();
        fs::create_dir_all(layout.backups_dir()).unwrap();
        fs::write(layout.backups_dir().join(VERIFIED), b"v").unwrap();
        fs::write(layout.backups_dir().join(UNFINISHED), b"u").unwrap();
        Rig {
            _dir: dir,
            layout,
            runner: FakeRunner::new(),
            pause: FakePause::default(),
        }
    }

    impl Rig {
        fn host(&self) -> Host<'_> {
            Host::new(&self.runner, &self.pause)
        }

        fn task(&self, state: &str) -> &Self {
            self.runner.on(
                move |i| runs_script(i, STATE_SCRIPT),
                Output::with(0, format!("state={state}\n")),
            );
            self
        }

        fn distros(&self, list: &str) -> &Self {
            self.runner
                .on(|i| starts(i, WSL_EXE, &["--list"]), Output::with(0, utf16(list)));
            self
        }

        fn ok(&self, f: impl Fn(&Invocation) -> bool + 'static) -> &Self {
            self.runner.on(f, Output::with(0, ""));
            self
        }

        fn order(&self) -> Vec<String> {
            self.runner
                .calls()
                .iter()
                .filter(|i| i.program() != crate::runner::POWERSHELL_EXE)
                .map(|i| format!("{} {}", i.program(), i.arguments()[..1].join(" ")))
                .collect()
        }
    }

    fn is_delete(i: &Invocation) -> bool {
        starts(i, SCHTASKS_EXE, &["/Delete", "/TN", TASK_PATH, "/F"])
    }

    fn healthy(r: &Rig) {
        r.task("Running")
            .distros("Ubuntu\r\np2pc-node\r\n")
            .ok(|i| starts(i, SCHTASKS_EXE, &["/End"]))
            .ok(is_delete)
            .ok(|i| starts(i, WSL_EXE, &["--unregister", "p2pc-node"]));
    }

    #[test]
    fn the_task_goes_first_then_the_distro_then_the_folder_keeping_a_failed_upgrade_s_backup() {
        let r = rig();
        healthy(&r);
        let plan = UninstallPlan::read(&r.layout);
        assert_eq!(plan.verified, [r.layout.backups_dir().join(VERIFIED)]);
        assert_eq!(plan.unfinished, [r.layout.backups_dir().join(UNFINISHED)]);
        let got = uninstall(r.host(), &r.layout, BackupRule::Default).unwrap();
        assert_eq!(
            r.order(),
            [
                "schtasks.exe /End",
                "schtasks.exe /Delete",
                "wsl.exe --list",
                "wsl.exe --unregister"
            ]
        );
        assert!(got.task_removed);
        assert_eq!(got.distro, DistroRemoval::Unregistered);
        assert_eq!(got.removed_backups, 1);
        let kept = r.layout.backups_dir().join(UNFINISHED);
        assert_eq!(got.kept_backups, std::slice::from_ref(&kept));
        assert!(got.left.is_empty(), "{:?}", got.left);
        // Only the kept backup and the folders that hold it stay.
        let rest: Vec<_> = fs::read_dir(r.layout.root())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(rest, ["backups"]);
        let rest: Vec<_> = fs::read_dir(r.layout.backups_dir())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(rest, [UNFINISHED]);
        assert_eq!(fs::read(kept).unwrap(), b"u");
    }

    #[test]
    fn with_the_box_ticked_the_folder_goes_entirely() {
        let r = rig();
        healthy(&r);
        let got = uninstall(r.host(), &r.layout, BackupRule::DeleteAll).unwrap();
        assert_eq!(got.removed_backups, 2);
        assert!(got.kept_backups.is_empty());
        assert!(!r.layout.root().exists());
    }

    #[test]
    fn with_no_failed_backup_the_folder_goes_entirely() {
        let r = rig();
        fs::remove_file(r.layout.backups_dir().join(UNFINISHED)).unwrap();
        fs::write(r.layout.backups_dir().join("notes.txt"), b"x").unwrap();
        healthy(&r);
        let got = uninstall(r.host(), &r.layout, BackupRule::Default).unwrap();
        assert!(got.kept_backups.is_empty());
        assert!(!r.layout.root().exists());
    }

    #[test]
    fn keep_all_keeps_both_kinds() {
        let r = rig();
        healthy(&r);
        let got = uninstall(r.host(), &r.layout, BackupRule::KeepAll).unwrap();
        assert_eq!(got.removed_backups, 0);
        assert_eq!(got.kept_backups.len(), 2);
        assert!(r.layout.backups_dir().join(VERIFIED).exists());
        assert!(!r.layout.distro_dir().exists());
    }

    #[test]
    fn a_task_that_cannot_be_removed_stops_everything() {
        for refuse in [
            Ok(Output::with(1, "ERROR: Access is denied.")),
            Err(RunError::TimedOut {
                program: SCHTASKS_EXE.into(),
                limit: std::time::Duration::from_secs(60),
            }),
        ] {
            let r = rig();
            r.task("Ready").ok(|i| starts(i, SCHTASKS_EXE, &["/End"]));
            r.runner.on_seq(is_delete, vec![refuse]);
            let err = uninstall(r.host(), &r.layout, BackupRule::DeleteAll).unwrap_err();
            assert_eq!(err.exit_code(), 37);
            assert!(err.to_string().contains("The distro was NOT touched"));
            assert_eq!(r.runner.count(|i| i.program() == WSL_EXE), 0);
            assert!(r.layout.backups_dir().join(UNFINISHED).exists());
            assert!(r.layout.distro_dir().join("ext4.vhdx").exists());
        }
    }

    #[test]
    fn an_unreadable_task_state_is_never_taken_as_no_task() {
        let r = rig();
        r.runner.on(|i| runs_script(i, STATE_SCRIPT), Output::with(1, ""));
        let err = uninstall(r.host(), &r.layout, BackupRule::Default).unwrap_err();
        assert_eq!(err.exit_code(), 37);
        assert!(r.layout.root().join("device.key").exists());
    }

    #[test]
    fn a_failed_unregister_leaves_the_folder() {
        let r = rig();
        r.task("none").distros("p2pc-node\r\n").runner.on(
            |i| starts(i, WSL_EXE, &["--unregister"]),
            Output::with(1, utf16("Error code: x")),
        );
        let err = uninstall(r.host(), &r.layout, BackupRule::Default).unwrap_err();
        assert_eq!(err.exit_code(), 29);
        assert!(r.layout.distro_dir().join("ext4.vhdx").exists());
        assert_eq!(r.runner.count(is_delete), 0, "no task was registered");
    }

    #[test]
    fn a_wsl_that_fails_to_answer_stops_but_a_missing_one_does_not() {
        let r = rig();
        r.task("none").runner.on_seq(
            |i| starts(i, WSL_EXE, &["--list"]),
            vec![Err(RunError::TimedOut {
                program: WSL_EXE.into(),
                limit: std::time::Duration::from_secs(1),
            })],
        );
        let err = uninstall(r.host(), &r.layout, BackupRule::Default).unwrap_err();
        assert!(matches!(err, UninstallError::Wsl(_)));
        assert!(r.layout.root().join("setup.json").exists());

        let r = rig();
        r.task("none").runner.on_seq(
            |i| starts(i, WSL_EXE, &["--list"]),
            vec![Err(RunError::Spawn {
                program: WSL_EXE.into(),
                kind: ErrorKind::NotFound,
                message: "not found".into(),
            })],
        );
        let got = uninstall(r.host(), &r.layout, BackupRule::Default).unwrap();
        assert_eq!(got.distro, DistroRemoval::WslMissing);
        assert!(!got.task_removed);
        assert!(!r.layout.root().join("setup.json").exists());
    }

    #[test]
    fn a_hung_wsl_stops_the_uninstall_within_its_time_limit() {
        let r = rig();
        r.task("none").distros("p2pc-node\r\n").runner.on_seq(
            |i| starts(i, WSL_EXE, &["--unregister"]),
            vec![Err(RunError::TimedOut {
                program: WSL_EXE.into(),
                limit: UNREGISTER_TIMEOUT,
            })],
        );
        let err = uninstall(r.host(), &r.layout, BackupRule::Default).unwrap_err();
        assert!(matches!(err, UninstallError::Wsl(RunError::TimedOut { .. })), "{err:?}");
        assert!(r.layout.root().join("setup.json").exists(), "nothing deleted");
        let calls = r.runner.calls();
        let limit = |args: &[&str]| {
            calls
                .iter()
                .find(|i| starts(i, WSL_EXE, args))
                .and_then(Invocation::time_limit)
        };
        assert_eq!(limit(&["--list"]), Some(LIST_TIMEOUT));
        assert_eq!(limit(&["--unregister"]), Some(UNREGISTER_TIMEOUT));
    }

    #[test]
    fn another_distro_is_never_unregistered() {
        let r = rig();
        r.task("none").distros("Ubuntu\r\np2pc-node-old\r\nP2PC-NODE\r\n");
        let got = uninstall(r.host(), &r.layout, BackupRule::Default).unwrap();
        assert_eq!(got.distro, DistroRemoval::NotInstalled);
        assert_eq!(r.runner.count(|i| starts(i, WSL_EXE, &["--unregister"])), 0);
    }

    #[cfg(unix)]
    #[test]
    fn nothing_is_deleted_through_a_link() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("precious"), b"keep").unwrap();
        let r = rig();
        std::os::unix::fs::symlink(outside.path(), r.layout.root().join("link-dir")).unwrap();
        std::os::unix::fs::symlink(outside.path(), r.layout.logs_dir().join("inner-link")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("precious"),
            r.layout.backups_dir().join(VERIFIED.replace("01", "03")),
        )
        .unwrap();
        let (_, _, left) = remove_local(&r.layout, BackupRule::DeleteAll);
        assert!(left.is_empty(), "{left:?}");
        assert!(!r.layout.root().exists());
        assert_eq!(fs::read(outside.path().join("precious")).unwrap(), b"keep");
    }

    #[test]
    fn only_regular_files_with_a_backup_s_name_are_backups() {
        let r = rig();
        fs::create_dir(r.layout.backups_dir().join("p2pc-state-20261103000000.tar")).unwrap();
        fs::write(r.layout.backups_dir().join("p2pc-state-x.tar"), b"").unwrap();
        assert_eq!(state_backup_files(&r.layout.backups_dir(), BackupKind::All).len(), 2);
        assert!(state_backup_files(&r.layout.root().join("missing"), BackupKind::All).is_empty());
    }
}
