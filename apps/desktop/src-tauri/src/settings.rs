// SPDX-License-Identifier: Apache-2.0

//! The app's own settings, in `settings.json` in the app's config folder (`%APPDATA%\<app identifier>`, which the
//! uninstaller deletes, H2 §8.7 step 6).
//!
//! This task has one setting: start at sign-in (§8.1: "started at sign-in from `HKCU\…\Run` (opt-out in Settings)").
//! Later tasks add theirs (the update-check choice of §8.2 step 1, "Keep this PC awake" of §8.6) as new fields with
//! `#[serde(default)]`, so an older file still loads; unknown fields are ignored, so a newer file still loads after a
//! downgrade.

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
}

impl Default for Settings {
    fn default() -> Self {
        Self { autostart: true }
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

    /// The stored settings, or the defaults when the file is missing or invalid. What the app uses at start: a
    /// damaged settings file must not keep the app from starting.
    pub fn load_or_default(&self) -> Settings {
        self.load().unwrap_or_default()
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
    fn no_file_means_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = SettingsFile::in_dir(dir.path());
        assert_eq!(file.load().expect("load"), Settings::default());
    }

    #[test]
    fn saved_settings_load_back_and_no_temporary_file_is_left() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = SettingsFile::in_dir(&dir.path().join("nested"));
        let off = Settings { autostart: false };
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
        assert_eq!(file.load().expect("load"), Settings { autostart: false });
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
            assert_eq!(file.load_or_default(), Settings::default());
        }
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
