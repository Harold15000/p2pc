// SPDX-License-Identifier: Apache-2.0

//! Tests of the uninstall cleanup (§8.7), with a fake PC and a fake hub.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use p2pc_wsl::runner::Pause;
use p2pc_wsl::uninstall::{DistroRemoval, UninstallError, UninstallPlan, Uninstalled};

use super::log::UninstallLog;
use super::*;

/// A fake PC: records the steps in order.
#[derive(Default)]
struct Pc {
    steps: RefCell<Vec<String>>,
    task_fails: bool,
    kept: Vec<PathBuf>,
    leave_fails: bool,
    hub_data: bool,
}

impl CleanupHost for Pc {
    fn own_node_id(&self) -> Option<String> {
        Some("node-hub".into())
    }
    fn hub_data_present(&self) -> bool {
        self.hub_data
    }
    fn agent_leave(&self, timeout: Duration) -> Result<(), String> {
        assert_eq!(timeout, LEAVE_TIMEOUT);
        self.steps.borrow_mut().push("leave".into());
        if self.leave_fails {
            Err("timed out".into())
        } else {
            Ok(())
        }
    }
    fn remove_node(&self, rule: BackupRule) -> Result<Uninstalled, UninstallError> {
        self.steps.borrow_mut().push(format!("remove {rule:?}"));
        if self.task_fails {
            return Err(UninstallError::TaskNotRemoved {
                message: "Access is denied".into(),
            });
        }
        Ok(Uninstalled {
            task_removed: true,
            distro: DistroRemoval::Unregistered,
            removed_backups: 1,
            kept_backups: if rule == BackupRule::DeleteAll {
                vec![]
            } else {
                self.kept.clone()
            },
            left: vec![],
        })
    }
    fn remove_app_traces(&self) -> Vec<String> {
        self.steps.borrow_mut().push("app traces".into());
        Vec::new()
    }
}

/// A fake hub: each deletion takes `cost` on the clock.
struct Hub<'a> {
    ids: Vec<String>,
    deleted: RefCell<Vec<String>>,
    clock: &'a Clock,
    cost: Duration,
    steps: &'a RefCell<Vec<String>>,
}

impl HubNodes for Hub<'_> {
    fn node_ids(&self) -> Result<Vec<String>, String> {
        Ok(self.ids.clone())
    }
    fn delete_node(&self, id: &str, timeout: Duration) -> Result<(), String> {
        assert!(timeout <= HUB_DELETE_BUDGET && !timeout.is_zero());
        self.clock.0.set(self.clock.0.get() + self.cost);
        self.deleted.borrow_mut().push(id.to_owned());
        self.steps.borrow_mut().push(format!("delete {id}"));
        Ok(())
    }
}

#[derive(Default)]
struct Clock(Cell<Duration>);
impl Pause for Clock {
    fn sleep(&self, d: Duration) {
        self.0.set(self.0.get() + d);
    }
    fn now(&self) -> Duration {
        self.0.get()
    }
}

fn log(dir: &std::path::Path) -> UninstallLog {
    UninstallLog::create(dir, UNIX_EPOCH + Duration::from_secs(1_762_939_800))
}

fn ids(n: usize) -> Vec<String> {
    let mut v = vec!["node-hub".to_owned()];
    v.extend((1..=n).map(|i| format!("node-{i}")));
    v
}

#[test]
fn the_hub_pc_deletes_every_other_node_before_anything_is_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let pc = Pc::default();
    let clock = Clock::default();
    let hub = Hub {
        ids: ids(3),
        deleted: RefCell::default(),
        clock: &clock,
        cost: Duration::from_secs(1),
        steps: &pc.steps,
    };
    let mut l = log(dir.path());
    let confirm = Confirmation {
        hub_confirmed: true,
        delete_failed_backups: false,
    };
    let out = run_cleanup(&pc, &hub, &clock, &mut l, Some(Role::Hub), confirm);
    assert_eq!(out.exit_code(), exit::DONE);
    assert_eq!(
        *pc.steps.borrow(),
        [
            "delete node-1",
            "delete node-2",
            "delete node-3",
            "remove Default",
            "app traces"
        ]
    );
    assert!(
        !hub.deleted.borrow().contains(&"node-hub".to_owned()),
        "never its own node"
    );
    let text = std::fs::read_to_string(l.path()).unwrap();
    for line in [
        "step 1: deleted node node-1",
        "step 3:",
        "step 4:",
        "step 5:",
        "step 6:",
        "step 7:",
    ] {
        assert!(text.contains(line), "{line} in {text}");
    }
}

#[test]
fn without_the_hub_checkbox_nothing_happens_and_the_uninstall_stops() {
    let dir = tempfile::tempdir().unwrap();
    let pc = Pc::default();
    let clock = Clock::default();
    let hub = Hub {
        ids: ids(2),
        deleted: RefCell::default(),
        clock: &clock,
        cost: Duration::ZERO,
        steps: &pc.steps,
    };
    let out = run_cleanup(
        &pc,
        &hub,
        &clock,
        &mut log(dir.path()),
        Some(Role::Hub),
        Confirmation::default(),
    );
    assert_eq!(out, CleanupOutcome::Cancelled);
    assert_eq!(out.exit_code(), exit::CANCELLED);
    assert!(pc.steps.borrow().is_empty());
}

#[test]
fn the_deletions_stop_at_thirty_seconds_in_total() {
    let dir = tempfile::tempdir().unwrap();
    let pc = Pc::default();
    let clock = Clock::default();
    let hub = Hub {
        ids: ids(10),
        deleted: RefCell::default(),
        clock: &clock,
        cost: Duration::from_secs(7),
        steps: &pc.steps,
    };
    let confirm = Confirmation {
        hub_confirmed: true,
        ..Confirmation::default()
    };
    let out = run_cleanup(&pc, &hub, &clock, &mut log(dir.path()), Some(Role::Hub), confirm);
    assert_eq!(out.exit_code(), exit::DONE, "best effort: the uninstall goes on");
    assert_eq!(hub.deleted.borrow().len(), 5, "0, 7, 14, 21, 28 s; none at 35 s");
    assert!(pc.steps.borrow().contains(&"remove Default".to_owned()));
}

#[test]
fn a_joined_pc_leaves_best_effort_then_removes_the_node() {
    for fails in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let pc = Pc {
            leave_fails: fails,
            ..Pc::default()
        };
        let clock = Clock::default();
        let out = run_cleanup(
            &pc,
            &UnwiredHubNodes,
            &clock,
            &mut log(dir.path()),
            Some(Role::Joined),
            Confirmation::default(),
        );
        assert_eq!(out.exit_code(), exit::DONE);
        assert_eq!(*pc.steps.borrow(), ["leave", "remove Default", "app traces"]);
    }
}

#[test]
fn a_task_that_cannot_be_removed_stops_the_uninstall_and_leaves_the_app_data() {
    let dir = tempfile::tempdir().unwrap();
    let pc = Pc {
        task_fails: true,
        ..Pc::default()
    };
    let out = run_cleanup(
        &pc,
        &UnwiredHubNodes,
        &Clock::default(),
        &mut log(dir.path()),
        Some(Role::Joined),
        Confirmation::default(),
    );
    assert_eq!(out.exit_code(), exit::STOPPED);
    assert!(matches!(&out, CleanupOutcome::Stopped { message, .. } if message.contains("The distro was NOT touched")));
    assert!(!pc.steps.borrow().contains(&"app traces".to_owned()));
}

#[test]
fn a_failed_upgrade_s_backup_is_kept_and_named_unless_the_box_is_ticked() {
    let dir = tempfile::tempdir().unwrap();
    let kept = PathBuf::from("C:\\Users\\u\\AppData\\Local\\P2PC\\backups\\p2pc-state-20261101000000.tar");
    let pc = Pc {
        kept: vec![kept.clone()],
        ..Pc::default()
    };
    let out = run_cleanup(
        &pc,
        &UnwiredHubNodes,
        &Clock::default(),
        &mut log(dir.path()),
        None,
        Confirmation::default(),
    );
    match &out {
        CleanupOutcome::Done {
            lines, kept_backups, ..
        } => {
            assert_eq!(kept_backups, &[kept.display().to_string()]);
            assert!(lines.iter().any(|l| l.contains(&kept.display().to_string())));
            assert_eq!(lines.last().map(String::as_str), Some(WSL_STAYS));
        }
        other => panic!("{other:?}"),
    }
    let pc = Pc {
        kept: vec![kept],
        ..Pc::default()
    };
    let ticked = Confirmation {
        delete_failed_backups: true,
        ..Confirmation::default()
    };
    let out = run_cleanup(
        &pc,
        &UnwiredHubNodes,
        &Clock::default(),
        &mut log(dir.path()),
        None,
        ticked,
    );
    assert!(matches!(&out, CleanupOutcome::Done { kept_backups, .. } if kept_backups.is_empty()));
    assert_eq!(pc.steps.borrow()[0], "remove DeleteAll");
}

#[test]
fn an_unknown_role_on_a_pc_with_the_hub_s_data_needs_the_hub_checkbox() {
    let hub_pc = Pc {
        hub_data: true,
        ..Pc::default()
    };
    assert_eq!(effective_role(None, &hub_pc), Some(Role::Hub));
    assert_eq!(
        effective_role(Some(Role::Joined), &hub_pc),
        Some(Role::Joined),
        "a recorded role stands"
    );
    assert_eq!(effective_role(None, &Pc::default()), None);
    // Without the checkbox nothing is deleted.
    let dir = tempfile::tempdir().unwrap();
    let role = effective_role(None, &hub_pc);
    let out = run_cleanup(
        &hub_pc,
        &UnwiredHubNodes,
        &Clock::default(),
        &mut log(dir.path()),
        role,
        Confirmation::default(),
    );
    assert_eq!(out, CleanupOutcome::Cancelled);
    assert!(hub_pc.steps.borrow().is_empty());
    let plan = UninstallPlan {
        backups_dir: PathBuf::from("B"),
        verified: vec![],
        unfinished: vec![],
    };
    assert_eq!(UninstallView::new(role, &plan).hub_consequence, Some(HUB_CONSEQUENCE));
}

#[test]
fn the_confirmation_names_the_consequence_and_each_kept_backup() {
    let plan = UninstallPlan {
        backups_dir: PathBuf::from("B"),
        verified: vec![PathBuf::from("B/p2pc-state-20261101000000.ok.tar")],
        unfinished: vec![PathBuf::from("B/p2pc-state-20261102000000.tar")],
    };
    let hub = UninstallView::new(Some(Role::Hub), &plan);
    assert_eq!(hub.hub_consequence, Some(HUB_CONSEQUENCE));
    assert_eq!(
        hub.kept_backups,
        [PathBuf::from("B/p2pc-state-20261102000000.tar").display().to_string()]
    );
    assert_eq!(hub.delete_backups_label, Some(DELETE_BACKUPS_LABEL));
    let joined = UninstallView::new(
        Some(Role::Joined),
        &UninstallPlan {
            unfinished: vec![],
            ..plan
        },
    );
    assert_eq!(joined.hub_consequence, None);
    assert_eq!(joined.delete_backups_label, None);
    // The checkbox is unchecked by default.
    let c: Confirmation = serde_json::from_str("{}").unwrap();
    assert!(!c.delete_failed_backups && !c.hub_confirmed);
}
