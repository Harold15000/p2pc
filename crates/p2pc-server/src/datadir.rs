// SPDX-License-Identifier: AGPL-3.0-only

//! Data dir resolution (spec §12): `$P2PC_DATA_DIR`, then `--data-dir`, then `$XDG_DATA_HOME/p2pc-server`, then
//! `~/.local/share/p2pc-server`.
//!
//! The system-service default (`/var/lib/p2pc-server`) is set by the service unit, `deploy/linux/p2pc-server.service`,
//! through `P2PC_DATA_DIR`. It is not `/var/lib/p2pc`, which is a node's home on the same machine.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Environment variable that overrides everything else.
pub const ENV_DATA_DIR: &str = "P2PC_DATA_DIR";
/// Directory name under `$XDG_DATA_HOME` or `~/.local/share`.
pub const APP_DIR: &str = "p2pc-server";

/// No data dir could be determined.
#[derive(Debug, thiserror::Error)]
#[error("cannot determine the data dir: set P2PC_DATA_DIR or pass --data-dir")]
pub struct NoDataDir;

/// Resolves the data dir. `env` looks up an environment variable (injected for tests).
pub fn resolve(env: impl Fn(&str) -> Option<OsString>, flag: Option<&Path>) -> Result<PathBuf, NoDataDir> {
    let non_empty = |name: &str| env(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(dir) = non_empty(ENV_DATA_DIR) {
        return Ok(dir);
    }
    if let Some(dir) = flag {
        return Ok(dir.to_path_buf());
    }
    // The XDG spec says relative values are invalid and must be ignored.
    if let Some(xdg) = non_empty("XDG_DATA_HOME").filter(|p| p.is_absolute()) {
        return Ok(xdg.join(APP_DIR));
    }
    if let Some(home) = non_empty("HOME").filter(|p| p.is_absolute()) {
        return Ok(home.join(".local").join("share").join(APP_DIR));
    }
    Err(NoDataDir)
}

/// [`resolve`] with the process environment.
pub fn resolve_from_env(flag: Option<&Path>) -> Result<PathBuf, NoDataDir> {
    resolve(|name| std::env::var_os(name), flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| vars.iter().find(|(k, _)| *k == name).map(|(_, v)| OsString::from(v))
    }

    #[test]
    fn precedence() {
        let all = [
            ("P2PC_DATA_DIR", "/env"),
            ("XDG_DATA_HOME", "/xdg"),
            ("HOME", "/home/u"),
        ];
        let flag = Some(Path::new("/flag"));
        assert_eq!(resolve(env(&all), flag).unwrap(), PathBuf::from("/env"));
        assert_eq!(resolve(env(&all[1..]), flag).unwrap(), PathBuf::from("/flag"));
        assert_eq!(
            resolve(env(&all[1..]), None).unwrap(),
            PathBuf::from("/xdg/p2pc-server")
        );
        assert_eq!(
            resolve(env(&all[2..]), None).unwrap(),
            PathBuf::from("/home/u/.local/share/p2pc-server")
        );
        assert!(resolve(env(&[]), None).is_err());
    }

    #[test]
    fn empty_and_relative_values_are_ignored() {
        let vars = [
            ("P2PC_DATA_DIR", ""),
            ("XDG_DATA_HOME", "relative"),
            ("HOME", "/home/u"),
        ];
        assert_eq!(
            resolve(env(&vars), None).unwrap(),
            PathBuf::from("/home/u/.local/share/p2pc-server")
        );
        assert!(resolve(env(&[("HOME", "")]), None).is_err());
    }
}
