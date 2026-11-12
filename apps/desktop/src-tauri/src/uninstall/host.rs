// SPDX-License-Identifier: Apache-2.0

//! The real [`CleanupHost`]: the agent through `wsl.exe`, `p2pc-wsl`'s uninstall, the app's data folders and its
//! `HKCU` values.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use p2pc_wsl::Layout;
use p2pc_wsl::runner::{CommandRunner, Host, Pause, in_distro};
use p2pc_wsl::uninstall::{BackupRule, UninstallError, Uninstalled};

use super::CleanupHost;
use crate::autostart::{RUN_VALUE_NAME, RunKey};
use crate::setup::wsl_host::{AGENT_BIN, AGENT_CONFIG};

/// The app's identifier (`tauri.conf.json`), the last component of every data folder the cleanup deletes.
pub const APP_IDENTIFIER: &str = "p2pc.desktop";

/// `p2pc-agent leave`'s exit code once the hub removed the node (`p2pc-agent`'s `exit::NOT_ENROLLED`).
const LEAVE_REMOVED: i32 = 7;

/// The hub's data directory in the distro (`P2PC_DATA_DIR`, §8.5).
pub const HUB_DATA_DIR: &str = "/var/lib/p2pc-server";

/// The time limit of `p2pc-agent status --json`.
const STATUS_TIMEOUT: Duration = Duration::from_secs(30);

/// The real host.
pub struct WslCleanupHost<R, P> {
    pub runner: R,
    pub pause: P,
    pub layout: Layout,
    /// `%APPDATA%\p2pc.desktop` and `%LOCALAPPDATA%\p2pc.desktop` (WebView2's `EBWebView` included).
    pub app_dirs: Vec<PathBuf>,
    pub run: Box<dyn RunKey + Send + Sync>,
    pub run_once: Box<dyn RunKey + Send + Sync>,
}

impl<R, P> std::fmt::Debug for WslCleanupHost<R, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WslCleanupHost")
            .field("layout", &self.layout)
            .field("app_dirs", &self.app_dirs)
            .finish_non_exhaustive()
    }
}

/// A data folder of this app: an absolute path whose last component is the app's identifier.
pub fn is_app_dir(path: &Path) -> bool {
    path.is_absolute() && path.file_name().is_some_and(|n| n == APP_IDENTIFIER)
}

impl<R: CommandRunner, P: Pause> WslCleanupHost<R, P> {
    fn host(&self) -> Host<'_> {
        Host::new(&self.runner, &self.pause)
    }
}

impl<R: CommandRunner, P: Pause> CleanupHost for WslCleanupHost<R, P> {
    fn own_node_id(&self) -> Option<String> {
        let inv = in_distro(&[AGENT_BIN, "--config", AGENT_CONFIG, "status", "--json"]).timeout(STATUS_TIMEOUT);
        let out = self.host().run_wsl(&inv).ok().filter(|o| o.success())?;
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
        v.get("node_id")?.as_str().map(str::to_owned)
    }

    fn agent_leave(&self, timeout: Duration) -> Result<(), String> {
        let inv = in_distro(&[AGENT_BIN, "--config", AGENT_CONFIG, "leave"]).timeout(timeout);
        let out = self.host().run_wsl(&inv).map_err(|e| e.to_string())?;
        match out.code {
            Some(LEAVE_REMOVED) => Ok(()),
            code => Err(format!(
                "exit {code:?}: {}",
                p2pc_wsl::import::sanitize_message(&out.stderr_text())
            )),
        }
    }

    fn hub_data_present(&self) -> bool {
        let inv = in_distro(&["/usr/bin/test", "-e", HUB_DATA_DIR]).timeout(STATUS_TIMEOUT);
        self.host().run_wsl(&inv).is_ok_and(|o| o.success())
    }

    fn remove_node(&self, rule: BackupRule) -> Result<Uninstalled, UninstallError> {
        p2pc_wsl::uninstall::uninstall(self.host(), &self.layout, rule)
    }

    fn remove_app_traces(&self) -> Vec<String> {
        let mut left = Vec::new();
        for dir in &self.app_dirs {
            if !is_app_dir(dir) {
                left.push(format!("{} (not this app's folder: left alone)", dir.display()));
                continue;
            }
            match fs::symlink_metadata(dir) {
                Ok(m) if m.file_type().is_dir() => {
                    if let Err(e) = fs::remove_dir_all(dir) {
                        left.push(format!("{} ({e})", dir.display()));
                    }
                }
                Ok(_) => {
                    if let Err(e) = fs::remove_file(dir) {
                        left.push(format!("{} ({e})", dir.display()));
                    }
                }
                Err(_) => {}
            }
        }
        for (name, key) in [("Run", &self.run), ("RunOnce", &self.run_once)] {
            if let Err(e) = key.remove(RUN_VALUE_NAME) {
                left.push(format!("HKCU\\…\\{name}\\{RUN_VALUE_NAME} ({e})"));
            }
        }
        left
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use p2pc_wsl::runner::{Invocation, Output, RunError};

    use super::*;
    use crate::autostart::AutostartError;

    struct Agent {
        reply: Output,
        calls: RefCell<Vec<Invocation>>,
    }

    impl CommandRunner for Agent {
        fn run(&self, inv: &Invocation) -> Result<Output, RunError> {
            self.calls.borrow_mut().push(inv.clone());
            Ok(self.reply.clone())
        }
    }

    struct NoPause;
    impl Pause for NoPause {
        fn sleep(&self, _: Duration) {}
    }

    #[derive(Default)]
    struct Key(Mutex<HashMap<String, String>>);
    impl RunKey for Key {
        fn get(&self, name: &str) -> Result<Option<String>, AutostartError> {
            Ok(self.0.lock().unwrap().get(name).cloned())
        }
        fn set(&self, name: &str, value: &str) -> Result<(), AutostartError> {
            self.0.lock().unwrap().insert(name.into(), value.into());
            Ok(())
        }
        fn remove(&self, name: &str) -> Result<(), AutostartError> {
            self.0.lock().unwrap().remove(name);
            Ok(())
        }
    }

    struct Shared(std::sync::Arc<Key>);
    impl RunKey for Shared {
        fn get(&self, name: &str) -> Result<Option<String>, AutostartError> {
            self.0.get(name)
        }
        fn set(&self, name: &str, value: &str) -> Result<(), AutostartError> {
            self.0.set(name, value)
        }
        fn remove(&self, name: &str) -> Result<(), AutostartError> {
            self.0.remove(name)
        }
    }

    fn host(
        reply: Output,
        dir: &Path,
        app_dirs: Vec<PathBuf>,
    ) -> (WslCleanupHost<Agent, NoPause>, [std::sync::Arc<Key>; 2]) {
        let run = std::sync::Arc::new(Key::default());
        let once = std::sync::Arc::new(Key::default());
        run.set(RUN_VALUE_NAME, "\"C:\\P2PC.exe\" --autostart").unwrap();
        once.set(RUN_VALUE_NAME, "\"C:\\P2PC.exe\"").unwrap();
        let h = WslCleanupHost {
            runner: Agent {
                reply,
                calls: RefCell::new(Vec::new()),
            },
            pause: NoPause,
            layout: Layout::new(dir),
            app_dirs,
            run: Box::new(Shared(run.clone())),
            run_once: Box::new(Shared(once.clone())),
        };
        (h, [run, once])
    }

    #[test]
    fn leave_succeeds_only_when_the_hub_removed_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let (h, _) = host(
            Output::with(7, "This node was removed from its cloud."),
            dir.path(),
            vec![],
        );
        assert_eq!(h.agent_leave(Duration::from_secs(10)), Ok(()));
        let inv = h.runner.calls.borrow()[0].clone();
        assert_eq!(
            &inv.arguments()[5..],
            [
                "/usr/local/bin/p2pc-agent",
                "--config",
                "/var/lib/p2pc/agent.toml",
                "leave"
            ]
        );
        assert_eq!(inv.time_limit(), Some(Duration::from_secs(10)));
        let (h, _) = host(Output::with(1, ""), dir.path(), vec![]);
        assert!(h.agent_leave(Duration::from_secs(10)).is_err());
    }

    #[test]
    fn the_hub_s_data_is_probed_in_the_distro() {
        let dir = tempfile::tempdir().unwrap();
        let (h, _) = host(Output::with(0, ""), dir.path(), vec![]);
        assert!(h.hub_data_present());
        let inv = h.runner.calls.borrow()[0].clone();
        assert_eq!(&inv.arguments()[5..], ["/usr/bin/test", "-e", "/var/lib/p2pc-server"]);
        assert!(inv.time_limit().is_some());
        let (h, _) = host(Output::with(1, ""), dir.path(), vec![]);
        assert!(!h.hub_data_present());
    }

    #[test]
    fn the_own_node_id_comes_from_status_json() {
        let dir = tempfile::tempdir().unwrap();
        let (h, _) = host(
            Output::with(0, r#"{"enrolled":true,"node_id":"01JBEXAMPLE0000000000000000"}"#),
            dir.path(),
            vec![],
        );
        assert_eq!(h.own_node_id().as_deref(), Some("01JBEXAMPLE0000000000000000"));
        let (h, _) = host(
            Output::with(0, r#"{"enrolled":false,"node_id":null}"#),
            dir.path(),
            vec![],
        );
        assert_eq!(h.own_node_id(), None);
    }

    #[test]
    fn only_this_app_s_folders_and_values_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let roaming = dir.path().join("Roaming").join(APP_IDENTIFIER);
        let local = dir.path().join("Local").join(APP_IDENTIFIER);
        let other = dir.path().join("Local").join("someone.else");
        for d in [&roaming, &local.join("EBWebView"), &other] {
            fs::create_dir_all(d).unwrap();
        }
        fs::write(roaming.join("settings.json"), b"{}").unwrap();
        let (h, [run, once]) = host(
            Output::with(0, ""),
            dir.path(),
            vec![
                roaming.clone(),
                local.clone(),
                other.clone(),
                dir.path().join("missing").join(APP_IDENTIFIER),
            ],
        );
        let left = h.remove_app_traces();
        assert_eq!(left.len(), 1, "{left:?}");
        assert!(left[0].contains("someone.else"));
        assert!(!roaming.exists() && !local.exists());
        assert!(other.exists());
        assert_eq!(run.get(RUN_VALUE_NAME).unwrap(), None);
        assert_eq!(once.get(RUN_VALUE_NAME).unwrap(), None);
        assert!(!is_app_dir(Path::new("p2pc.desktop")), "relative");
    }
}
