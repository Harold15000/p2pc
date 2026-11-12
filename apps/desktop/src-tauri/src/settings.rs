// SPDX-License-Identifier: Apache-2.0

//! The app's own settings, in `settings.json` in the app's config folder (`%APPDATA%\<app identifier>`, which the
//! uninstaller deletes, H2 §8.7 step 6).
//!
//! The settings: start at sign-in (§8.1: "started at sign-in from `HKCU\…\Run` (opt-out in Settings)"), the
//! update-check choice of §8.2 step 1 (T2-43; T2-45's updater reads it), and "Keep this PC awake while sharing" of §8.2
//! step 3 and §8.6 (T2-43 records it). New fields take their default (`#[serde(default)]`), so an older file still
//! loads; unknown fields are ignored, so a newer file still loads after a downgrade.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The file name in the app's config folder.
pub const SETTINGS_FILE: &str = "settings.json";

/// The largest settings file the app reads.
pub const MAX_FILE_LEN: u64 = 64 * 1024;

/// The settings. `Default` is a fresh install's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Start the app at sign-in (`HKCU\…\Run`). On by default, opt-out (§8.1).
    pub autostart: bool,
    /// "Check for updates and verify the web app automatically" (§8.2 step 1, §14.1, hard rule 6). `None` until the
    /// user picked one: nothing is preselected, and without a yes the app never checks on its own.
    pub update_checks: Option<bool>,
    /// "Keep this PC awake while sharing" (§8.2 step 3, §8.6). Off by default.
    pub keep_awake: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            autostart: true,
            update_checks: None,
            keep_awake: false,
        }
    }
}

/// Why the settings could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    /// Reading or writing the file failed.
    #[error("settings file: {0}")]
    Io(#[from] io::Error),
    /// The file is not valid settings JSON, or is too large.
    #[error("settings file is not valid")]
    Invalid,
}

/// What the app starts with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Startup {
    /// The settings to use. The defaults when the file could not be used: a damaged settings file must not keep the
    /// app from starting.
    pub settings: Settings,
    /// Whether the settings are the user's (a file that loaded, or a fresh install with no file yet), so that the
    /// `Run` entry may be made to match them. When they are only a fallback, the registry is left alone, so that a
    /// damaged or unreadable file never undoes the user's opt-out (§8.1).
    pub trusted: bool,
}

/// The settings to start with from `file` (`None` when the OS gives no config folder).
pub fn startup(file: Option<&SettingsFile>) -> Startup {
    match file.map(SettingsFile::load) {
        // A file that loaded, or none yet (`load` gives the defaults for a missing file): the user's settings.
        Some(Ok(settings)) => Startup {
            settings,
            trusted: true,
        },
        // Invalid or unreadable file, or no config folder: defaults, as a fallback only.
        Some(Err(_)) | None => Startup {
            settings: Settings::default(),
            trusted: false,
        },
    }
}

/// `settings.json` on disk.
#[derive(Debug, Clone)]
pub struct SettingsFile {
    path: PathBuf,
}

impl SettingsFile {
    /// The settings file in `config_dir`.
    pub fn in_dir(config_dir: &Path) -> Self {
        Self {
            path: config_dir.join(SETTINGS_FILE),
        }
    }

    /// The file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The stored settings, or the defaults when there is no file yet.
    pub fn load(&self) -> Result<Settings, SettingsError> {
        let file = match fs::File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Settings::default()),
            Err(e) => return Err(e.into()),
        };
        let mut data = Vec::new();
        file.take(MAX_FILE_LEN + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_FILE_LEN {
            return Err(SettingsError::Invalid);
        }
        // An object only: serde would also read a struct from a JSON array, field by field in order.
        let value: serde_json::Value = serde_json::from_slice(&data).map_err(|_| SettingsError::Invalid)?;
        if !value.is_object() {
            return Err(SettingsError::Invalid);
        }
        serde_json::from_value(value).map_err(|_| SettingsError::Invalid)
    }

    /// Writes `settings` atomically (temporary file, flush, rename).
    pub fn save(&self, settings: &Settings) -> Result<(), SettingsError> {
        let data = serde_json::to_vec_pretty(settings).map_err(|_| SettingsError::Invalid)?;
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let temp = self.path.with_file_name(format!("{SETTINGS_FILE}.tmp"));
        let written = (|| -> io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp)?;
            file.write_all(&data)?;
            file.sync_all()
        })();
        if let Err(e) = written.and_then(|()| fs::rename(&temp, &self.path)) {
            let _ = fs::remove_file(&temp);
            return Err(e.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_install_starts_at_sign_in() {
        assert!(Settings::default().autostart);
    }

    #[test]
    fn a_fresh_install_has_no_update_choice_and_does_not_keep_the_pc_awake() {
        let s = Settings::default();
        assert_eq!(s.update_checks, None, "nothing preselected (§8.2 step 1)");
        assert!(!s.keep_awake, "off by default (§8.6)");
    }

    #[test]
    fn an_older_file_without_the_new_fields_still_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = SettingsFile::in_dir(dir.path());
        fs::write(file.path(), br#"{"autostart": false}"#).expect("write");
        let s = file.load().expect("load");
        assert_eq!((s.autostart, s.update_checks, s.keep_awake), (false, None, false));
        let chosen = Settings {
            update_checks: Some(true),
            keep_awake: true,
            ..Settings::default()
        };
        file.save(&chosen).expect("save");
        assert_eq!(file.load().expect("load"), chosen);
    }

    #[test]
    fn no_file_means_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = SettingsFile::in_dir(dir.path());
        assert_eq!(file.load().expect("load"), Settings::default());
    }

    #[test]
    fn saved_settings_load_back_and_no_temporary_file_is_left() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = SettingsFile::in_dir(&dir.path().join("nested"));
        let off = Settings {
            autostart: false,
            ..Settings::default()
        };
        file.save(&off).expect("save");
        assert_eq!(file.load().expect("load"), off);
        let names: Vec<_> = fs::read_dir(dir.path().join("nested"))
            .expect("read dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(SETTINGS_FILE)]);
    }

    #[test]
    fn missing_fields_take_their_default_and_unknown_fields_are_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = SettingsFile::in_dir(dir.path());
        fs::write(file.path(), br#"{}"#).expect("write");
        assert_eq!(file.load().expect("load"), Settings::default());
        fs::write(file.path(), br#"{"autostart": false, "from_a_newer_app": 1}"#).expect("write");
        assert_eq!(
            file.load().expect("load"),
            Settings {
                autostart: false,
                ..Settings::default()
            }
        );
    }

    #[test]
    fn an_invalid_file_is_an_error_and_start_up_falls_back_to_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = SettingsFile::in_dir(dir.path());
        for bad in [
            &b"not json"[..],
            br#"{"autostart": "yes"}"#,
            b"[]",
            b"[false]",
            b"null",
            b"true",
        ] {
            fs::write(file.path(), bad).expect("write");
            assert!(matches!(file.load(), Err(SettingsError::Invalid)), "{bad:?}");
            let start = startup(Some(&file));
            assert_eq!(start.settings, Settings::default(), "{bad:?}");
            assert!(!start.trusted, "a fallback must not rewrite the Run entry: {bad:?}");
        }
    }

    #[test]
    fn an_unreadable_file_is_not_trusted() {
        // A directory where the file should be: opening it for reading fails (Io, not NotFound).
        let dir = tempfile::tempdir().expect("tempdir");
        let file = SettingsFile::in_dir(dir.path());
        fs::create_dir(file.path()).expect("mkdir");
        let start = startup(Some(&file));
        assert_eq!(start.settings, Settings::default());
        assert!(!start.trusted);
    }

    #[test]
    fn no_config_folder_is_not_trusted() {
        assert_eq!(
            startup(None),
            Startup {
                settings: Settings::default(),
                trusted: false
            }
        );
    }

    #[test]
    fn a_loaded_file_or_a_fresh_install_is_trusted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = SettingsFile::in_dir(dir.path());
        assert_eq!(
            startup(Some(&file)),
            Startup {
                settings: Settings::default(),
                trusted: true
            }
        );
        let off = Settings {
            autostart: false,
            ..Settings::default()
        };
        file.save(&off).expect("save");
        assert_eq!(
            startup(Some(&file)),
            Startup {
                settings: off,
                trusted: true
            }
        );
    }

    #[test]
    fn an_oversized_file_is_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = SettingsFile::in_dir(dir.path());
        let mut data = br#"{"autostart": false, "pad": ""#.to_vec();
        data.resize(MAX_FILE_LEN as usize + 10, b'x');
        data.extend_from_slice(br#""}"#);
        fs::write(file.path(), data).expect("write");
        assert!(matches!(file.load(), Err(SettingsError::Invalid)));
    }
}
