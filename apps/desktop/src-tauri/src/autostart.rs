// SPDX-License-Identifier: Apache-2.0

//! Start at sign-in: one value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (H2 §8.1), opt-out in
//! Settings.
//!
//! [`reconcile`] makes the registry match the setting: it writes `"<exe>" --autostart` when the setting is on and the
//! value is missing or different (an app moved by a reinstall), and deletes the value when the setting is off. It
//! touches only its own value name ([`RUN_VALUE_NAME`]) in `HKCU` (never `HKLM`: no administrator rights, §8.1). If the
//! user disabled the entry in Task Manager, Windows records that under `StartupApproved`, which the app never touches,
//! so the user's choice there wins.
//!
//! The registry sits behind [`RunKey`]: [`WindowsRunKey`] on Windows, a fake in the tests.

use std::path::Path;

/// The `Run` key under `HKEY_CURRENT_USER`.
pub const RUN_KEY_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// The `RunOnce` key under `HKEY_CURRENT_USER`: first-run step 2a reopens the app there after the reboot (H2 §8.2).
pub const RUN_ONCE_KEY_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\RunOnce";

/// The app's value name under the `Run` and `RunOnce` keys (§8.7 step 6 deletes both on uninstall).
pub const RUN_VALUE_NAME: &str = "P2PC";

/// The argument the `Run` entry passes, so that a start at sign-in stays in the tray (see [`crate::launch`]).
pub const AUTOSTART_FLAG: &str = "--autostart";

/// Why the autostart entry could not be read or changed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AutostartError {
    /// The executable path cannot be written as a `Run` command line.
    #[error("the app's path cannot be used as a start-up command")]
    UnusablePath,
    /// The registry refused (the Windows `HRESULT`).
    #[error("the registry refused (code {0:#010x})")]
    Registry(i32),
    /// There is no `Run` key on this OS (the Linux build of the app).
    #[error("start at sign-in is not supported on this system")]
    Unsupported,
}

/// String values under `HKCU\…\Run` (or `RunOnce`).
pub trait RunKey {
    /// The value `name`, or `None` when there is none.
    fn get(&self, name: &str) -> Result<Option<String>, AutostartError>;
    /// Writes the string value `name`.
    fn set(&self, name: &str, value: &str) -> Result<(), AutostartError>;
    /// Deletes the value `name`. Deleting a missing value is not an error.
    fn remove(&self, name: &str) -> Result<(), AutostartError>;
}

/// What [`reconcile`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// The registry already matched the setting.
    Unchanged,
    /// The value was written (missing, or pointing elsewhere).
    Written,
    /// The value was deleted.
    Removed,
}

/// The `Run` command line for `exe`: the quoted path, then [`AUTOSTART_FLAG`]. Refuses a relative path, or one with a
/// quote or a control character, which could not be quoted safely.
pub fn command_line(exe: &Path) -> Result<String, AutostartError> {
    let text = exe.to_str().ok_or(AutostartError::UnusablePath)?;
    if text.is_empty() || !exe.is_absolute() || text.chars().any(|c| c == '"' || c.is_control()) {
        return Err(AutostartError::UnusablePath);
    }
    Ok(format!("\"{text}\" {AUTOSTART_FLAG}"))
}

/// The `RunOnce` command line for `exe`: the quoted path alone, so the app opens its window (at first-run step 2, which
/// `setup.json` resumes at). The same path rules as [`command_line`].
pub fn open_command_line(exe: &Path) -> Result<String, AutostartError> {
    let line = command_line(exe)?;
    Ok(line.trim_end_matches(AUTOSTART_FLAG).trim_end().to_owned())
}

/// Makes the `Run` value match `enabled` for the app at `exe`.
pub fn reconcile(key: &dyn RunKey, enabled: bool, exe: &Path) -> Result<Change, AutostartError> {
    // A value that cannot be read (for example of another registry type) counts as "present and different", so that
    // it is rewritten or deleted rather than left in place.
    let current = key.get(RUN_VALUE_NAME).unwrap_or_else(|_| Some(String::new()));
    if enabled {
        let wanted = command_line(exe)?;
        if current.as_deref() == Some(wanted.as_str()) {
            return Ok(Change::Unchanged);
        }
        key.set(RUN_VALUE_NAME, &wanted)?;
        Ok(Change::Written)
    } else if current.is_some() {
        key.remove(RUN_VALUE_NAME)?;
        Ok(Change::Removed)
    } else {
        Ok(Change::Unchanged)
    }
}

/// The real `HKCU\…\Run` key.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsRunKey;

/// The real `HKCU\…\RunOnce` key (Windows deletes the value before it runs the command).
#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsRunOnceKey;

#[cfg(windows)]
mod windows_impl {
    use windows_registry::CURRENT_USER;

    use super::{AutostartError, RUN_KEY_PATH, RUN_ONCE_KEY_PATH, RunKey, WindowsRunKey, WindowsRunOnceKey};

    /// `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)`: the key or the value does not exist.
    const NOT_FOUND: i32 = 0x8007_0002_u32 as i32;

    fn registry(e: windows_registry::Result<()>) -> Result<(), AutostartError> {
        e.map_err(|e| AutostartError::Registry(e.code().0))
    }

    fn get(path: &str, name: &str) -> Result<Option<String>, AutostartError> {
        let key = match CURRENT_USER.open(path) {
            Ok(key) => key,
            Err(e) if e.code().0 == NOT_FOUND => return Ok(None),
            Err(e) => return Err(AutostartError::Registry(e.code().0)),
        };
        match key.get_string(name) {
            Ok(value) => Ok(Some(value)),
            Err(e) if e.code().0 == NOT_FOUND => Ok(None),
            Err(e) => Err(AutostartError::Registry(e.code().0)),
        }
    }

    fn set(path: &str, name: &str, value: &str) -> Result<(), AutostartError> {
        let key = CURRENT_USER
            .create(path)
            .map_err(|e| AutostartError::Registry(e.code().0))?;
        registry(key.set_string(name, value))
    }

    fn remove(path: &str, name: &str) -> Result<(), AutostartError> {
        let key = match CURRENT_USER.options().read().write().open(path) {
            Ok(key) => key,
            Err(e) if e.code().0 == NOT_FOUND => return Ok(()),
            Err(e) => return Err(AutostartError::Registry(e.code().0)),
        };
        match key.remove_value(name) {
            Err(e) if e.code().0 == NOT_FOUND => Ok(()),
            other => registry(other),
        }
    }

    impl RunKey for WindowsRunKey {
        fn get(&self, name: &str) -> Result<Option<String>, AutostartError> {
            get(RUN_KEY_PATH, name)
        }
        fn set(&self, name: &str, value: &str) -> Result<(), AutostartError> {
            set(RUN_KEY_PATH, name, value)
        }
        fn remove(&self, name: &str) -> Result<(), AutostartError> {
            remove(RUN_KEY_PATH, name)
        }
    }

    impl RunKey for WindowsRunOnceKey {
        fn get(&self, name: &str) -> Result<Option<String>, AutostartError> {
            get(RUN_ONCE_KEY_PATH, name)
        }
        fn set(&self, name: &str, value: &str) -> Result<(), AutostartError> {
            set(RUN_ONCE_KEY_PATH, name, value)
        }
        fn remove(&self, name: &str) -> Result<(), AutostartError> {
            remove(RUN_ONCE_KEY_PATH, name)
        }
    }
}

/// The `Run` key on an OS that has none: reads nothing, refuses to write.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRunKey;

impl RunKey for NoRunKey {
    fn get(&self, _: &str) -> Result<Option<String>, AutostartError> {
        Ok(None)
    }
    fn set(&self, _: &str, _: &str) -> Result<(), AutostartError> {
        Err(AutostartError::Unsupported)
    }
    fn remove(&self, _: &str) -> Result<(), AutostartError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;

    #[derive(Debug, Default)]
    struct FakeRunKey {
        values: RefCell<BTreeMap<String, String>>,
        unreadable: bool,
        writes: RefCell<u32>,
    }

    impl RunKey for FakeRunKey {
        fn get(&self, name: &str) -> Result<Option<String>, AutostartError> {
            if self.unreadable {
                return Err(AutostartError::Registry(0x8007_000d_u32 as i32));
            }
            Ok(self.values.borrow().get(name).cloned())
        }
        fn set(&self, name: &str, value: &str) -> Result<(), AutostartError> {
            *self.writes.borrow_mut() += 1;
            self.values.borrow_mut().insert(name.into(), value.into());
            Ok(())
        }
        fn remove(&self, name: &str) -> Result<(), AutostartError> {
            *self.writes.borrow_mut() += 1;
            self.values.borrow_mut().remove(name);
            Ok(())
        }
    }

    fn exe() -> PathBuf {
        // An absolute path on the OS running the tests (the logic is the same on Windows).
        if cfg!(windows) {
            PathBuf::from(r"C:\Users\Example User\AppData\Local\P2PC App\P2PC.exe")
        } else {
            PathBuf::from("/opt/P2PC App/p2pc-desktop")
        }
    }

    #[test]
    fn the_command_line_quotes_the_path_and_passes_the_flag() {
        let line = command_line(&exe()).expect("command line");
        assert_eq!(line, format!("\"{}\" --autostart", exe().display()));
    }

    #[test]
    fn the_run_once_command_line_opens_the_window() {
        let line = open_command_line(&exe()).expect("command line");
        assert_eq!(line, format!("\"{}\"", exe().display()));
        assert_eq!(
            open_command_line(Path::new("relative.exe")),
            Err(AutostartError::UnusablePath)
        );
    }

    #[test]
    fn unusable_paths_are_refused() {
        for bad in [
            "",
            "relative/p2pc.exe",
            "/opt/with\"quote/p2pc",
            "/opt/with\nnewline/p2pc",
        ] {
            assert_eq!(
                command_line(Path::new(bad)),
                Err(AutostartError::UnusablePath),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn enabling_writes_the_value_once() {
        let key = FakeRunKey::default();
        assert_eq!(reconcile(&key, true, &exe()), Ok(Change::Written));
        assert_eq!(reconcile(&key, true, &exe()), Ok(Change::Unchanged));
        assert_eq!(*key.writes.borrow(), 1);
        assert_eq!(
            key.values.borrow().get(RUN_VALUE_NAME).cloned(),
            Some(command_line(&exe()).expect("line"))
        );
    }

    #[test]
    fn a_value_pointing_elsewhere_is_rewritten() {
        let key = FakeRunKey::default();
        key.values
            .borrow_mut()
            .insert(RUN_VALUE_NAME.into(), "\"/old/place/p2pc\" --autostart".into());
        assert_eq!(reconcile(&key, true, &exe()), Ok(Change::Written));
        assert_eq!(
            key.values.borrow().get(RUN_VALUE_NAME).cloned(),
            Some(command_line(&exe()).expect("line"))
        );
    }

    #[test]
    fn disabling_removes_only_our_value() {
        let key = FakeRunKey::default();
        key.values
            .borrow_mut()
            .insert("SomethingElse".into(), "other.exe".into());
        reconcile(&key, true, &exe()).expect("enable");
        assert_eq!(reconcile(&key, false, &exe()), Ok(Change::Removed));
        assert_eq!(reconcile(&key, false, &exe()), Ok(Change::Unchanged));
        let values = key.values.borrow();
        assert!(!values.contains_key(RUN_VALUE_NAME));
        assert_eq!(values.get("SomethingElse").map(String::as_str), Some("other.exe"));
    }

    #[test]
    fn an_unreadable_value_is_rewritten_or_removed() {
        let key = FakeRunKey {
            unreadable: true,
            ..FakeRunKey::default()
        };
        assert_eq!(reconcile(&key, true, &exe()), Ok(Change::Written));
        assert_eq!(reconcile(&key, false, &exe()), Ok(Change::Removed));
    }

    #[test]
    fn an_unusable_path_writes_nothing() {
        let key = FakeRunKey::default();
        assert_eq!(
            reconcile(&key, true, Path::new("relative.exe")),
            Err(AutostartError::UnusablePath)
        );
        assert_eq!(*key.writes.borrow(), 0);
    }

    #[test]
    fn without_a_run_key_enabling_is_unsupported_and_disabling_is_a_no_op() {
        assert_eq!(reconcile(&NoRunKey, true, &exe()), Err(AutostartError::Unsupported));
        assert_eq!(reconcile(&NoRunKey, false, &exe()), Ok(Change::Unchanged));
    }
}
