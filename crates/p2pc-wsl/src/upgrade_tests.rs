// SPDX-License-Identifier: Apache-2.0

//! Tests of the upgrade, against a simulated distro behind the fake runner: it keeps the files the upgrade writes inside
//! the distro, answers the probes, and records the order of what was done.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, UNIX_EPOCH};

use super::*;
use crate::import::{BOOT_STATUS_PATH, VERIFY_BOOT, VERIFY_NO_MNT_C, VERIFY_STATE_MODE, VERIFY_VERSION};
use crate::runner::fake::*;
use crate::runner::{Invocation, Output, POWERSHELL_EXE, SCHTASKS_EXE, WSL_EXE};
use crate::task::{SDDL_SCRIPT, STATE_SCRIPT, TaskIdentity};

/// The archive the simulated distro writes: every byte value, CRLFs and NULs, as a tar would hold.
fn archive() -> Vec<u8> {
    let mut a: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
    a.extend_from_slice(b"\r\n\0\x1a");
    a
}

const LISTING: &str = "700:0:0:d:p2pc\n600:0:0:f:p2pc/agent.toml\n600:0:0:f:p2pc/identity.key\n644:0:0:f:p2pc/boot-status.json\n700:0:0:d:p2pc/tmp\n755:0:0:s:p2pc/agent.sock\n700:0:0:d:p2pc-server\n600:0:0:f:p2pc-server/p2pc.db\n";

/// 2023-11-14T22:13:20Z.
const DISTRO_NOW: i64 = 1_700_000_000;

struct Sim {
    registered: bool,
    files: HashMap<String, Vec<u8>>,
    probe: String,
    size: String,
    /// Free bytes of the distro's and the backup's volume, and whether they are one volume.
    free: (u64, u64),
    same_volume: bool,
    migration: String,
    corrupt_copy_out: bool,
    corrupt_copy_in: bool,
    import_fails: bool,
    restored: bool,
    listing_after: Option<String>,
    server_after_restore: bool,
    task_state: String,
    connection: String,
    node_run_status: Option<String>,
    events: Vec<String>,
}

impl Default for Sim {
    fn default() -> Self {
        Self {
            registered: true,
            files: HashMap::new(),
            probe: "P2PC_STATE=present\n".into(),
            size: "1024\t/var/lib/p2pc\n2048\t/var/lib/p2pc-server\n".into(),
            free: (500 << 30, 500 << 30),
            same_volume: true,
            migration: "P2PC_CONFIG=present\n".into(),
            corrupt_copy_out: false,
            corrupt_copy_in: false,
            import_fails: false,
            restored: false,
            listing_after: None,
            server_after_restore: true,
            task_state: "Ready".into(),
            connection: "connected (since 2023-11-14T22:13:21Z)".into(),
            node_run_status: None,
            events: Vec::new(),
        }
    }
}

fn ok(text: impl Into<Vec<u8>>) -> Result<Output, RunError> {
    Ok(Output::with(0, text))
}

fn exit(code: i32) -> Result<Output, RunError> {
    Ok(Output::with(code, ""))
}

impl Sim {
    fn wsl(&mut self, inv: &Invocation) -> Result<Output, RunError> {
        let a: Vec<&str> = inv.arguments().iter().map(String::as_str).collect();
        match a.as_slice() {
            ["--list", "--quiet"] => {
                let list = if self.registered {
                    "Ubuntu\r\np2pc-node\r\n"
                } else {
                    "Ubuntu\r\n"
                };
                Ok(Output::with(0, utf16(list)))
            }
            ["--terminate", _] => {
                self.events.push("terminate".into());
                ok("")
            }
            ["--unregister", _] => {
                self.events.push("unregister".into());
                self.registered = false;
                self.files.clear();
                ok("")
            }
            ["--import", ..] => {
                self.events.push("import".into());
                if self.import_fails {
                    return Ok(Output::with(
                        1,
                        utf16("Error code: Wsl/Service/RegisterDistro/0x80070005"),
                    ));
                }
                self.registered = true;
                ok("")
            }
            ["-d", "p2pc-node", "-u", "root", "--exec", cmd @ ..] => self.exec(inv, cmd),
            _ => exit(127),
        }
    }

    fn exec(&mut self, inv: &Invocation, cmd: &[&str]) -> Result<Output, RunError> {
        fn sh(s: &str) -> [&str; 3] {
            ["/bin/sh", "-c", s]
        }
        if cmd == sh(STATE_PROBE_SCRIPT) {
            return ok(self.probe.clone());
        }
        if cmd == sh(STATE_SIZE_SCRIPT) {
            return ok(self.size.clone());
        }
        if cmd == sh(CONFIG_MIGRATION_SCRIPT) {
            return ok(self.migration.clone());
        }
        if cmd == VERIFY_VERSION {
            return ok("image_version=0.3.0\n");
        }
        if cmd == VERIFY_STATE_MODE {
            return ok("700\n");
        }
        if cmd == VERIFY_NO_MNT_C || cmd == VERIFY_BOOT {
            return ok("");
        }
        if cmd == SERVER_SECTION_CHECK {
            return exit(if !self.restored || self.server_after_restore {
                0
            } else {
                1
            });
        }
        if cmd.first() == Some(&"/usr/bin/find") {
            assert_eq!(cmd.last(), Some(&STATE_LISTING_FORMAT));
            let text = match (&self.listing_after, self.restored) {
                (Some(after), true) => after.clone(),
                _ => LISTING.to_owned(),
            };
            return ok(text);
        }
        match cmd {
            ["/bin/bash", "-c", script] => {
                let out = script
                    .split("-cpf ")
                    .nth(1)
                    .and_then(|r| r.split(';').next())
                    .unwrap_or_default()
                    .to_owned();
                assert_eq!(state_archive_script(&out).as_deref(), Some(*script));
                self.events.push("archive".into());
                self.files.insert(out.clone(), archive());
                ok(format!("{}  {out}\n", Sha256Digest::of(&archive()).to_hex()))
            }
            ["/bin/cat", path] if inv.stdout_path().is_some() => {
                self.events.push("copy-out".into());
                let mut bytes = self.files.get(*path).cloned().unwrap_or_default();
                if self.corrupt_copy_out {
                    // What PowerShell 5.1 would have done to it: LF re-encoded as CRLF.
                    bytes = String::from_utf8_lossy(&bytes).replace('\n', "\r\n").into_bytes();
                }
                fs::write(inv.stdout_path().unwrap(), bytes).unwrap();
                ok("")
            }
            ["/bin/cat", "/proc/1/stat"] => {
                ok("1 (init) S 0 1 1 0 -1 4194560 1 2 3 4 5 6 7 8 20 0 1 0 4242 2252800 300 18446744073709551615")
            }
            ["/bin/cat", p] if *p == BOOT_STATUS_PATH => {
                ok(r#"{"init_starttime":4242,"cdi":"no_nvidia_gpu","errors":[],"notes":[]}"#)
            }
            ["/bin/cat", p] if *p == NODE_RUN_STATUS_PATH => match &self.node_run_status {
                Some(s) => ok(s.clone()),
                None => exit(1),
            },
            ["/bin/rm", "-f", path] => {
                self.events.push(format!("rm {path}"));
                self.files.remove(*path);
                ok("")
            }
            ["/usr/bin/install", "-m", "0600", "/dev/null", path] => {
                self.files.insert((*path).to_owned(), Vec::new());
                ok("")
            }
            ["/bin/dd", of, "bs=1M", "status=none"] => {
                let path = of.strip_prefix("of=").unwrap().to_owned();
                self.events.push(format!("copy-in {path}"));
                let mut bytes = match (inv.stdin_path(), inv.stdin_bytes()) {
                    (Some(p), _) => fs::read(p).unwrap(),
                    (None, Some(b)) => b.to_vec(),
                    (None, None) => panic!("dd without stdin"),
                };
                if self.corrupt_copy_in {
                    bytes.truncate(bytes.len() / 2);
                }
                self.files.insert(path, bytes);
                ok("")
            }
            ["/usr/bin/sha256sum", path] => match self.files.get(*path) {
                Some(b) => ok(format!("{}  {path}\n", Sha256Digest::of(b).to_hex())),
                None => exit(1),
            },
            ["/bin/tar", "--numeric-owner", "-C", "/var/lib", "-xpf", path] => {
                assert_eq!(
                    self.files.get(*path),
                    Some(&archive()),
                    "the archive arrived byte-exact"
                );
                self.events.push("extract".into());
                self.restored = true;
                ok("")
            }
            ["/bin/date", "-u", "+%s"] => ok(format!("{DISTRO_NOW}\n")),
            ["/usr/bin/env", env, agent, "status"] => {
                assert_eq!(*env, format!("P2PC_AGENT_CONFIG={AGENT_CONFIG_PATH}"));
                assert_eq!(*agent, AGENT_PATH);
                ok(format!("Enrolled:      yes\nConnection:    {}\n", self.connection))
            }
            ["/bin/mkdir", "-p", "-m", "0700", _] => ok(""),
            ["/bin/mv", "-f", from, to] => {
                let b = self.files.remove(*from).unwrap();
                self.files.insert((*to).to_owned(), b);
                ok("")
            }
            _ => exit(127),
        }
    }

    fn powershell(&mut self, inv: &Invocation) -> Result<Output, RunError> {
        if runs_script(inv, STATE_SCRIPT) {
            return ok(format!("state={}\n", self.task_state));
        }
        if runs_script(inv, SDDL_SCRIPT) {
            return ok("rights=set\n");
        }
        if runs_script(inv, FREE_SPACE_SCRIPT) {
            let names: Vec<&str> = inv.environment().iter().map(|(k, _)| k.as_str()).collect();
            assert_eq!(names, ["P2PC_DISTRO_DIR", "P2PC_BACKUP_DIR"]);
            let backup_vol = if self.same_volume { "C:\\" } else { "D:\\" };
            return ok(format!(
                "volume=C:\\|free={}\r\nvolume={backup_vol}|free={}\r\n",
                self.free.0, self.free.1
            ));
        }
        exit(1)
    }

    fn schtasks(&mut self, inv: &Invocation) -> Result<Output, RunError> {
        let op = inv.arguments()[..2].join(" ");
        let op = if op.starts_with("/Create") || op.starts_with("/Run") || op.starts_with("/End") {
            op.split(' ').next().unwrap().to_owned()
        } else {
            op
        };
        self.events.push(format!("schtasks {op}"));
        if op == "/Change /DISABLE" {
            self.task_state = "Disabled".into();
        }
        ok("")
    }
}

struct Rig {
    dir: tempfile::TempDir,
    layout: Layout,
    sim: Rc<RefCell<Sim>>,
    runner: FakeRunner,
    pause: FakePause,
    ctx: TaskContext,
}

impl Rig {
    fn new(sim: Sim) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        fs::create_dir_all(layout.root()).unwrap();
        let sim = Rc::new(RefCell::new(sim));
        let runner = FakeRunner::new();
        let s = Rc::clone(&sim);
        runner.on_fn(|i| i.program() == WSL_EXE, move |i| s.borrow_mut().wsl(i));
        let s = Rc::clone(&sim);
        runner.on_fn(|i| i.program() == POWERSHELL_EXE, move |i| s.borrow_mut().powershell(i));
        let s = Rc::clone(&sim);
        runner.on_fn(|i| i.program() == SCHTASKS_EXE, move |i| s.borrow_mut().schtasks(i));
        let ctx = TaskContext {
            system_root: "C:\\Windows".into(),
            identity: TaskIdentity {
                user: "PC\\user".into(),
                sid: "S-1-5-21-1-2-3-1001".into(),
            },
            start_boundary: "2026-11-12T09:00:00Z".into(),
        };
        Self {
            dir,
            layout,
            sim,
            runner,
            pause: FakePause::default(),
            ctx,
        }
    }

    fn run(&self, force: bool) -> Result<Upgraded, Box<UpgradeFailure>> {
        let image = VerifiedImage::for_tests(self.dir.path().join("p2pc-node-0.3.0.tar.gz"));
        let mut opts = UpgradeOptions::new(UNIX_EPOCH + Duration::from_secs(1_762_939_800)); // 2025-11-12T09:30:00Z
        opts.task = Some(&self.ctx);
        opts.force_without_state = force;
        upgrade(Host::new(&self.runner, &self.pause), &self.layout, &image, &opts)
    }

    fn events(&self) -> Vec<String> {
        self.sim.borrow().events.clone()
    }

    fn backups(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.layout.backups_dir())
            .map(|rd| {
                rd.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }
}

const STAMP: &str = "20251112093000";

fn pos(events: &[String], what: &str) -> usize {
    events
        .iter()
        .position(|e| e == what)
        .unwrap_or_else(|| panic!("{what} not in {events:?}"))
}

#[test]
fn a_hub_pc_upgrade_carries_both_directories_byte_exact_and_keeps_one_verified_backup() {
    let rig = Rig::new(Sim::default());
    let b = rig.layout.backups_dir();
    fs::create_dir_all(&b).unwrap();
    for old in [
        "p2pc-state-20240101000000.ok.tar",
        "p2pc-state-20240201000000.ok.tar",
        "p2pc-state-20240301000000.tar",
        "notes.txt",
    ] {
        fs::write(b.join(old), b"old").unwrap();
    }
    let got = rig.run(false).unwrap();
    assert!(got.carried_hub);
    assert_eq!(got.image_version, "image_version=0.3.0");
    assert_eq!(got.entries, 5, "sockets, tmp/ and boot-status.json are not compared");
    let ok_file = b.join(format!("p2pc-state-{STAMP}.ok.tar"));
    assert_eq!(got.backup.as_deref(), Some(ok_file.as_path()));
    assert_eq!(fs::read(&ok_file).unwrap(), archive(), "the backup is byte-exact");
    // The hub's data: only this verified backup is kept; the unfinished one and somebody's file are never touched.
    assert_eq!(
        rig.backups(),
        [
            "notes.txt".to_owned(),
            "p2pc-state-20240301000000.tar".to_owned(),
            format!("p2pc-state-{STAMP}.ok.tar"),
        ]
    );
    // Nothing of the identity stays in either distro.
    assert!(rig.sim.borrow().files.is_empty(), "{:?}", rig.sim.borrow().files.keys());
    let ev = rig.events();
    assert!(ev.contains(&format!("rm /var/tmp/p2pc-state-{STAMP}.tar")));
    assert!(ev.contains(&format!("rm {IN_DISTRO_TAR}")));
    // The order: the task stopped, the state out and checked, then unregister, import, restore, and the task back.
    assert!(pos(&ev, "schtasks /Change /DISABLE") < pos(&ev, "archive"));
    assert!(pos(&ev, "archive") < pos(&ev, "copy-out"));
    assert!(pos(&ev, "copy-out") < pos(&ev, "unregister"));
    assert!(pos(&ev, "unregister") < pos(&ev, "import"));
    assert!(pos(&ev, "import") < pos(&ev, "extract"));
    assert!(pos(&ev, "extract") < pos(&ev, "schtasks /Create"));
    assert!(pos(&ev, "schtasks /Create") < pos(&ev, "schtasks /Change /ENABLE"));
    assert!(pos(&ev, "schtasks /Change /ENABLE") < pos(&ev, "schtasks /Run"));
    assert_eq!(
        got.task,
        TaskOutcome::Started {
            not_before: Some(DISTRO_NOW)
        }
    );
    assert_eq!(got.came_back, Some(CameBack::Connected));
    // Byte-exact pipes: the copy out went to a file, the copy in came from it; nothing binary went through text.
    let calls = rig.runner.calls();
    let out = calls.iter().find(|i| i.stdout_path().is_some()).unwrap();
    assert_eq!(
        out.stdout_path(),
        Some(b.join(format!("p2pc-state-{STAMP}.tar")).as_path())
    );
    let into = calls.iter().find(|i| i.stdin_path().is_some()).unwrap();
    assert_eq!(into.stdin_path(), out.stdout_path());
    assert!(calls.iter().all(|i| i.stdin_bytes().is_none()));
    // Re-registered disabled, so the trigger cannot start a half-upgraded node.
    assert!(!rig.layout.task_xml().exists());
}

#[test]
fn an_agent_only_upgrade_keeps_the_newest_three_verified_backups() {
    let rig = Rig::new(Sim {
        size: "1024 /var/lib/p2pc\n".into(),
        ..Sim::default()
    });
    let b = rig.layout.backups_dir();
    fs::create_dir_all(&b).unwrap();
    for t in ["20240101000000", "20240201000000", "20240301000000"] {
        fs::write(b.join(format!("p2pc-state-{t}.ok.tar")), b"old").unwrap();
    }
    let got = rig.run(false).unwrap();
    assert!(!got.carried_hub);
    assert_eq!(
        rig.backups(),
        [
            "p2pc-state-20240201000000.ok.tar".to_owned(),
            "p2pc-state-20240301000000.ok.tar".to_owned(),
            format!("p2pc-state-{STAMP}.ok.tar"),
        ]
    );
}

#[test]
fn the_backup_just_verified_is_never_pruned_even_when_another_sorts_newer() {
    // A backup install.ps1 made an hour ago on a PC at UTC+2 carries a later (local) stamp than this one (UTC).
    let rig = Rig::new(Sim::default());
    let b = rig.layout.backups_dir();
    fs::create_dir_all(&b).unwrap();
    fs::write(b.join("p2pc-state-20251112103000.ok.tar"), b"older, stamped later").unwrap();
    let got = rig.run(false).unwrap();
    assert!(got.carried_hub, "the hub keeps one verified backup");
    assert_eq!(rig.backups(), [format!("p2pc-state-{STAMP}.ok.tar")]);
    assert_eq!(
        fs::read(b.join(format!("p2pc-state-{STAMP}.ok.tar"))).unwrap(),
        archive()
    );
}

#[test]
fn every_refusal_before_the_unregister_leaves_the_old_distro_and_restarts_the_node() {
    let cases: Vec<(&str, Sim, bool)> = vec![
        (
            "unknown probe",
            Sim {
                probe: "garbled\n".into(),
                ..Sim::default()
            },
            false,
        ),
        (
            "two markers",
            Sim {
                probe: "P2PC_STATE=absent\nP2PC_STATE=present\n".into(),
                ..Sim::default()
            },
            true,
        ),
        (
            "hub data only, even with force",
            Sim {
                probe: "P2PC_STATE=hub-only\n".into(),
                ..Sim::default()
            },
            true,
        ),
        (
            "no state without force",
            Sim {
                probe: "P2PC_STATE=absent\n".into(),
                ..Sim::default()
            },
            false,
        ),
        (
            "size unknown",
            Sim {
                size: "1024 /var/lib/other\n".into(),
                ..Sim::default()
            },
            false,
        ),
        (
            "one volume: twice the state plus 20 GiB",
            Sim {
                free: ((20 << 30) + 2 * 3072 * 1024 - 1, 0),
                ..Sim::default()
            },
            false,
        ),
        (
            "the backup's volume",
            Sim {
                same_volume: false,
                free: (500 << 30, 3072 * 1024 - 1),
                ..Sim::default()
            },
            false,
        ),
        (
            "config migration",
            Sim {
                migration: "P2PC_CONFIG=what\n".into(),
                ..Sim::default()
            },
            false,
        ),
        (
            "copy out corrupted",
            Sim {
                corrupt_copy_out: true,
                ..Sim::default()
            },
            false,
        ),
    ];
    for (name, sim, force) in cases {
        let rig = Rig::new(sim);
        let f = rig.run(force).expect_err(name);
        assert_eq!(f.error.exit_code(), 23, "{name}: {}", f.error);
        assert!(
            f.error.to_string().ends_with("The old distro was NOT touched."),
            "{name}"
        );
        assert!(!f.touched, "{name}");
        assert_eq!(f.kept_backup, None, "{name}");
        let ev = rig.events();
        assert!(!ev.contains(&"unregister".to_owned()), "{name}: {ev:?}");
        assert!(rig.sim.borrow().registered, "{name}");
        assert!(
            rig.backups().is_empty(),
            "{name}: no partial copy left: {:?}",
            rig.backups()
        );
        assert!(
            rig.sim.borrow().files.is_empty(),
            "{name}: the in-distro archive is deleted"
        );
        // Untouched: the node is started again.
        assert!(matches!(f.task, TaskOutcome::Started { .. }), "{name}: {:?}", f.task);
    }
}

#[test]
fn with_force_a_distro_without_state_is_upgraded_without_a_restore() {
    let rig = Rig::new(Sim {
        probe: "P2PC_STATE=absent\n".into(),
        ..Sim::default()
    });
    let got = rig.run(true).unwrap();
    assert_eq!(got.backup, None);
    let ev = rig.events();
    assert!(!ev.contains(&"archive".to_owned()) && !ev.contains(&"extract".to_owned()));
    assert!(ev.contains(&"import".to_owned()));
}

#[test]
fn a_failure_after_the_unregister_keeps_the_backup_and_leaves_the_node_stopped() {
    let cases: Vec<(&str, Sim, i32)> = vec![
        (
            "import",
            Sim {
                import_fails: true,
                ..Sim::default()
            },
            20,
        ),
        (
            "copy in",
            Sim {
                corrupt_copy_in: true,
                ..Sim::default()
            },
            25,
        ),
        (
            "listing",
            Sim {
                listing_after: Some(LISTING.replace("600:0:0:f:p2pc/identity.key", "644:0:0:f:p2pc/identity.key")),
                ..Sim::default()
            },
            26,
        ),
        (
            "lost [server]",
            Sim {
                server_after_restore: false,
                ..Sim::default()
            },
            38,
        ),
    ];
    for (name, sim, code) in cases {
        let rig = Rig::new(sim);
        let f = rig.run(false).expect_err(name);
        assert_eq!(f.error.exit_code(), code, "{name}: {}", f.error);
        assert!(f.touched, "{name}");
        let kept = rig.layout.backups_dir().join(format!("p2pc-state-{STAMP}.tar"));
        assert_eq!(f.kept_backup.as_deref(), Some(kept.as_path()), "{name}");
        assert_eq!(fs::read(&kept).unwrap(), archive(), "{name}: the only copy is intact");
        assert_eq!(f.task, TaskOutcome::KeptStopped(KeptStopped::NoIdentityYet), "{name}");
        let ev = rig.events();
        assert!(!ev.contains(&"schtasks /Run".to_owned()), "{name}: {ev:?}");
        assert_eq!(rig.sim.borrow().task_state, "Disabled", "{name}");
        assert!(!rig.sim.borrow().files.contains_key(IN_DISTRO_TAR), "{name}");
    }
}

#[test]
fn a_node_that_stopped_for_good_comes_back_only_when_it_was_too_old() {
    for (code, back) in [(7, false), (8, false), (6, true)] {
        let rig = Rig::new(Sim::default());
        fs::write(
            rig.layout.stop_record(),
            format!("node_exit=64\r\nexit_code={code}\r\ntime=t\r\ndisabled=no\r\n"),
        )
        .unwrap();
        let got = rig.run(false).unwrap();
        let ev = rig.events();
        if back {
            assert!(matches!(got.task, TaskOutcome::Started { .. }));
            assert!(!rig.layout.stop_record().exists(), "the record of 6 goes");
            assert!(ev.contains(&format!("rm {NODE_RUN_STATUS_PATH}")));
        } else {
            assert_eq!(
                got.task,
                TaskOutcome::KeptStopped(KeptStopped::StoppedForGood { code: Some(code) })
            );
            assert!(!ev.contains(&"schtasks /Run".to_owned()), "{code}: {ev:?}");
            assert!(rig.layout.stop_record().exists());
            assert_eq!(got.came_back, None);
        }
    }
}

#[test]
fn a_record_without_a_code_takes_it_from_the_distro() {
    let rig = Rig::new(Sim {
        node_run_status: Some("state=stopped\nexit_code=7\ntime=t2\nreason=removed\n".into()),
        ..Sim::default()
    });
    fs::write(rig.layout.stop_record(), "node_exit=64\r\ndisabled=yes\r\n").unwrap();
    let got = rig.run(false).unwrap();
    assert_eq!(
        got.task,
        TaskOutcome::KeptStopped(KeptStopped::StoppedForGood { code: Some(7) })
    );
}

#[test]
fn a_node_the_user_stopped_stays_stopped() {
    let rig = Rig::new(Sim {
        task_state: "Disabled".into(),
        ..Sim::default()
    });
    let got = rig.run(false).unwrap();
    assert_eq!(got.task, TaskOutcome::KeptStopped(KeptStopped::DisabledBefore));
    assert!(!rig.events().contains(&"schtasks /Run".to_owned()));
}

#[test]
fn without_a_task_nothing_is_registered() {
    let rig = Rig::new(Sim {
        task_state: "none".into(),
        ..Sim::default()
    });
    let got = rig.run(false).unwrap();
    assert_eq!(got.task, TaskOutcome::NotRegistered);
    assert!(!rig.events().iter().any(|e| e.starts_with("schtasks")));
}

#[test]
fn an_agent_that_stops_with_8_or_7_after_the_start_fails_the_upgrade() {
    for code in [8, 7] {
        let rig = Rig::new(Sim {
            connection: "not run since this enrollment".into(),
            node_run_status: Some(format!("state=stopped\nexit_code={code}\n")),
            ..Sim::default()
        });
        let f = rig.run(false).expect_err("38");
        assert_eq!(f.error.exit_code(), 38);
        // 60 s on the monotonic clock, polled every 2 s.
        assert_eq!(rig.pause.slept().iter().filter(|d| **d == CONNECT_POLL).count(), 30);
    }
}

#[test]
fn a_connection_from_before_the_start_does_not_count_and_is_only_a_warning() {
    let rig = Rig::new(Sim {
        connection: "connected (since 2023-11-14T22:13:10Z)".into(),
        ..Sim::default()
    });
    let got = rig.run(false).unwrap();
    assert!(matches!(got.came_back, Some(CameBack::NotYet { .. })));
    assert!(got.warnings.iter().any(|w| w.contains("keeps trying")));
}

#[test]
fn a_missing_distro_or_a_dirty_directory_touches_nothing() {
    let rig = Rig::new(Sim {
        registered: false,
        ..Sim::default()
    });
    let f = rig.run(false).unwrap_err();
    assert_eq!(f.error.exit_code(), 22);
    assert_eq!(f.task, TaskOutcome::Untouched);

    let rig = Rig::new(Sim::default());
    fs::create_dir_all(rig.layout.distro_dir()).unwrap();
    fs::write(rig.layout.distro_dir().join("mine.txt"), b"x").unwrap();
    let f = rig.run(false).unwrap_err();
    assert_eq!(f.error.exit_code(), 19);
    assert!(rig.events().is_empty(), "{:?}", rig.events());
}

// --- write_file_in_distro (the template bundle's delivery, §14.1) ---

#[test]
fn a_file_is_written_byte_exact_through_a_temporary_name() {
    let rig = Rig::new(Sim::default());
    let host = Host::new(&rig.runner, &rig.pause);
    let bytes = archive();
    write_file_in_distro(host, &bytes, "/var/lib/p2pc-server/templates", "templates.json").unwrap();
    let sim = rig.sim.borrow();
    assert_eq!(
        sim.files.get("/var/lib/p2pc-server/templates/templates.json"),
        Some(&bytes)
    );
    assert!(
        !sim.files
            .contains_key("/var/lib/p2pc-server/templates/.templates.json.p2pc-part")
    );
    assert!(
        sim.events
            .contains(&"copy-in /var/lib/p2pc-server/templates/.templates.json.p2pc-part".to_owned())
    );
    // On stdin, never as an argument, never through /mnt/c.
    let calls = rig.runner.calls();
    assert!(calls.iter().all(|i| !i.arguments().iter().any(|a| a.contains("/mnt/"))));
    assert!(calls.iter().any(|i| i.stdin_bytes() == Some(&bytes[..])));
}

#[test]
fn a_corrupted_copy_removes_the_temporary_file_and_never_replaces_the_old_one() {
    let rig = Rig::new(Sim {
        corrupt_copy_in: true,
        ..Sim::default()
    });
    rig.sim
        .borrow_mut()
        .files
        .insert("/var/lib/p2pc-server/templates/templates.json".into(), b"old".to_vec());
    let host = Host::new(&rig.runner, &rig.pause);
    let err =
        write_file_in_distro(host, b"new bundle", "/var/lib/p2pc-server/templates", "templates.json").unwrap_err();
    assert!(matches!(err, PipeError::HashMismatch(_)), "{err:?}");
    let sim = rig.sim.borrow();
    assert_eq!(
        sim.files
            .get("/var/lib/p2pc-server/templates/templates.json")
            .map(Vec::as_slice),
        Some(&b"old"[..])
    );
    assert!(
        !sim.files
            .contains_key("/var/lib/p2pc-server/templates/.templates.json.p2pc-part")
    );
}

#[test]
fn unsafe_directories_and_names_are_refused_before_anything_runs() {
    let rig = Rig::new(Sim::default());
    let host = Host::new(&rig.runner, &rig.pause);
    for (dir, name) in [
        ("relative/dir", "a"),
        ("/var/lib/p2pc server", "a"),
        ("/var/lib/../etc", "a"),
        ("/var/lib/x", ".hidden"),
        ("/var/lib/x", "a/b"),
        ("/var/lib/x", "a;rm"),
        ("/var/lib/x", ""),
    ] {
        let err = write_file_in_distro(host, b"x", dir, name).unwrap_err();
        assert!(matches!(err, PipeError::UnsafePath(_)), "{dir} {name}");
    }
    assert!(rig.runner.calls().is_empty());
}

// --- the pure parts ---

#[test]
fn the_probe_believes_only_one_known_marker_after_exit_0() {
    let p = |code, text: &str| StateProbe::parse(&Output::with(code, text));
    assert_eq!(p(0, "P2PC_STATE=present\n"), StateProbe::Present);
    assert_eq!(p(0, "noise\nP2PC_STATE=absent\n"), StateProbe::Absent);
    assert_eq!(p(0, "P2PC_STATE=hub-only"), StateProbe::HubOnly);
    assert_eq!(p(1, "P2PC_STATE=absent"), StateProbe::Unknown);
    assert_eq!(p(0, ""), StateProbe::Unknown);
    assert_eq!(p(0, "P2PC_STATE=Absent"), StateProbe::Unknown);
    assert_eq!(p(0, "P2PC_STATE=absent\nP2PC_STATE=absent"), StateProbe::Unknown);
}

#[test]
fn the_size_needs_exactly_one_agent_line_and_at_most_one_hub_line() {
    let s = |text: &str| StateSize::parse(&Output::with(0, text));
    assert_eq!(
        s("12\t/var/lib/p2pc\n"),
        Some(StateSize {
            agent_kib: 12,
            hub_kib: None
        })
    );
    assert_eq!(
        s("12 /var/lib/p2pc\n30  /var/lib/p2pc-server").unwrap().total_bytes(),
        42 * 1024
    );
    assert_eq!(s(""), None);
    assert_eq!(s("12 /var/lib/p2pc\n12 /var/lib/p2pc"), None);
    assert_eq!(s("x /var/lib/p2pc"), None);
    assert_eq!(s("1 /var/lib/p2pc-server"), None);
    assert_eq!(StateSize::parse(&Output::with(1, "12 /var/lib/p2pc")), None);
}

#[test]
fn the_config_migration_has_three_answers() {
    let m = |t: &str| ConfigMigration::parse(&Output::with(0, t));
    assert_eq!(m("P2PC_CONFIG=moved\n"), Some(ConfigMigration::Moved));
    assert_eq!(m("P2PC_CONFIG=created"), Some(ConfigMigration::Created));
    assert_eq!(m("P2PC_CONFIG=present"), Some(ConfigMigration::Present));
    assert_eq!(m("P2PC_CONFIG=other"), None);
    assert_eq!(ConfigMigration::parse(&Output::with(2, "P2PC_CONFIG=present")), None);
}

#[test]
fn the_listing_ignores_sockets_fifos_and_the_boot_files_only() {
    for l in [
        "755:0:0:s:p2pc/agent.sock",
        "600:0:0:p:p2pc-server/fifo",
        "700:0:0:d:p2pc/tmp",
        "600:0:0:f:p2pc/tmp/x",
        "644:0:0:f:p2pc/boot-status.json",
        "600:0:0:f:p2pc/.boot-status.tmp",
    ] {
        assert!(is_listing_ignored(l), "{l}");
    }
    for l in [
        "600:0:0:f:p2pc/agent.toml",
        "600:0:0:f:p2pc-server/tmp",
        "600:0:0:f:p2pc/tmpfile",
        "600:0:0:f:p2pc-server/boot-status.json",
    ] {
        assert!(!is_listing_ignored(l), "{l}");
    }
    assert_eq!(parse_listing("b\r\na\n\n755:0:0:s:p2pc/s\n"), ["a", "b"]);
}

#[test]
fn backup_names_and_pruning() {
    assert!(is_state_backup_name("p2pc-state-20261112093000.tar"));
    assert!(is_verified_backup_name("p2pc-state-20261112093000.ok.tar"));
    assert!(!is_verified_backup_name("p2pc-state-20261112093000.tar"));
    for bad in [
        "p2pc-state-2026111209300.tar",
        "p2pc-state-2026111209300x.tar",
        "p2pc-state-20261112093000.tar.bak",
        "P2PC-state-20261112093000.tar",
        "p2pc-state-20261112093000.ok.ok.tar",
    ] {
        assert!(!is_state_backup_name(bad), "{bad}");
    }
    let names: Vec<String> = [
        "p2pc-state-20240101000000.ok.tar",
        "p2pc-state-20240301000000.ok.tar",
        "p2pc-state-20240201000000.ok.tar",
        "p2pc-state-20230101000000.tar",
        "other.ok.tar",
    ]
    .map(String::from)
    .into();
    assert_eq!(
        backups_to_prune(&names, 1),
        ["p2pc-state-20240201000000.ok.tar", "p2pc-state-20240101000000.ok.tar"]
    );
    assert!(backups_to_prune(&names, 3).is_empty());
}

#[test]
fn space_needs_add_up_on_one_volume() {
    assert_eq!(space_needs(10, "C:\\", "c:\\", 5), [("C:\\".to_owned(), 25)]);
    assert_eq!(
        space_needs(10, "C:\\", "D:\\", 5),
        [("C:\\".to_owned(), 15), ("D:\\".to_owned(), 10)]
    );
    assert_eq!(
        parse_free_space("volume=C:\\|free=7\r\nvolume=\\\\srv\\share\\|free=9\r\n"),
        Some(vec![("C:\\".to_owned(), 7), ("\\\\srv\\share\\".to_owned(), 9)])
    );
    assert_eq!(parse_free_space("volume=C:\\|free=7"), None);
    assert_eq!(parse_free_space("volume=C:\\|free=x\nvolume=C:\\|free=1"), None);
}

#[test]
fn linux_paths_and_the_archive_script() {
    assert!(is_linux_safe_path("/var/tmp/p2pc-state-20261112093000.tar"));
    for bad in [
        "",
        "/",
        "var/tmp/x",
        "/var/tmp/a b",
        "/var/tmp/$(x)",
        "/var/tmp/a'b",
        "/tmp/x;y",
    ] {
        assert!(!is_linux_safe_path(bad), "{bad}");
        assert_eq!(state_archive_script(bad), None);
    }
    let s = state_archive_script("/var/tmp/x.tar").unwrap();
    assert!(s.ends_with("-cpf /var/tmp/x.tar; sha256sum /var/tmp/x.tar"));
    assert!(!s.contains("@OUT@"));
}

#[test]
fn times_and_the_connection_rule() {
    assert_eq!(backup_stamp(UNIX_EPOCH + Duration::from_secs(1_762_939_800)), STAMP);
    assert_eq!(rfc3339_seconds("2023-11-14T22:13:20Z"), Some(DISTRO_NOW));
    assert_eq!(rfc3339_seconds("2023-11-14T22:13:20.123456789Z"), Some(DISTRO_NOW));
    assert_eq!(rfc3339_seconds("2023-11-14T23:13:20+01:00"), Some(DISTRO_NOW));
    assert_eq!(rfc3339_seconds("2023-11-14T21:13:20-01:00"), Some(DISTRO_NOW));
    assert_eq!(rfc3339_seconds("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(rfc3339_seconds("2024-02-29T00:00:00Z"), Some(1_709_164_800));
    for bad in [
        "2023-11-14",
        "2023-11-14T22:13:20",
        "2023-13-14T22:13:20Z",
        "2023-11-14T22:13:20.Z",
        "x",
    ] {
        assert_eq!(rfc3339_seconds(bad), None, "{bad}");
    }
    assert!(connected_since(
        "connected (since 2023-11-14T22:13:18Z)",
        Some(DISTRO_NOW)
    ));
    assert!(!connected_since(
        "connected (since 2023-11-14T22:13:17Z)",
        Some(DISTRO_NOW)
    ));
    assert!(connected_since("connected", None));
    assert!(!connected_since("connected", Some(DISTRO_NOW)));
    assert!(!connected_since(
        "reconnecting (since 2023-11-14T22:13:30Z)",
        Some(DISTRO_NOW)
    ));
    assert_eq!(
        status_field("Enrolled:      yes\nConnection:    connected (since x)\n", "Connection"),
        "connected (since x)"
    );
    assert_eq!(status_field("", "Connection"), "");
    assert_eq!(node_run_stop(&Output::with(0, "state=stopped\nexit_code=6\n")), Some(6));
    assert_eq!(node_run_stop(&Output::with(0, "state=running\nexit_code=6\n")), None);
    assert_eq!(node_run_stop(&Output::with(1, "state=stopped\nexit_code=6\n")), None);
    assert_eq!(node_run_stop(&Output::with(0, "state=stopped\nexit_code=x\n")), None);
}

#[test]
fn every_error_has_install_ps1_s_exit_code() {
    let path = Path::new("d").to_owned();
    assert_eq!(UpgradeError::NotInstalled.exit_code(), 22);
    assert_eq!(
        UpgradeError::Import(ImportError::DirNotEmpty {
            dir: path,
            found: vec![]
        })
        .exit_code(),
        19
    );
    assert_eq!(
        UpgradeError::Import(ImportError::Unhealthy { problems: vec![] }).exit_code(),
        21
    );
    assert_eq!(
        UpgradeError::Unregister {
            code: Some(1),
            message: String::new()
        }
        .exit_code(),
        24
    );
}
