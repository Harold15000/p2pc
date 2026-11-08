// SPDX-License-Identifier: AGPL-3.0-only

//! The server's iroh identity (spec §5 "Server identity"): `<data_dir>/server.key`.
//!
//! The file holds the 32 raw bytes of an Ed25519 secret key and has mode 0600. `p2pc-server init` creates it, and so
//! does the first `serve` if it is missing. Loading refuses a file that the group or others can access, a file that
//! is not a regular file (symlinks included) and a file of the wrong size. Its public half, the server NodeId, is
//! how agents and `p2pc proxy` address the server.
//!
//! - **Load** opens the file with `O_NOFOLLOW` and checks the opened file itself, so a symlink swapped in after a
//!   check is never followed.
//! - **Create** writes a temporary file (0600) in the same directory, `fsync`s it, and renames it into place with
//!   `RENAME_NOREPLACE`, then `fsync`s the directory. An interrupted create therefore never leaves a partial
//!   (0-byte) `server.key`, and an existing key is never replaced.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use iroh::SecretKey;

/// File name inside the data dir.
pub const SERVER_KEY_FILE: &str = "server.key";
/// Size of the file: one Ed25519 secret key.
const KEY_LEN: usize = 32;

/// Why the server key cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The file does not exist.
    #[error("{0} does not exist: run `p2pc-server init` first")]
    Missing(PathBuf),
    /// Group or others can access the file.
    #[error("{path} has mode {mode:o}; it must not be readable by group or others (chmod 600 it)")]
    TooOpen {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// Not a regular file, or not 32 bytes.
    #[error("{0} is not a server key (a regular file of 32 bytes)")]
    Invalid(PathBuf),
    /// A file system error.
    #[error("{what} {path}: {source}")]
    Io {
        /// What was being done.
        what: &'static str,
        /// The file.
        path: PathBuf,
        /// The error.
        source: std::io::Error,
    },
}

fn io<'a>(what: &'static str, path: &'a Path) -> impl FnOnce(std::io::Error) -> IdentityError + 'a {
    move |source| IdentityError::Io {
        what,
        path: path.to_path_buf(),
        source,
    }
}

/// The path of the key in `data_dir`.
#[must_use]
pub fn key_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SERVER_KEY_FILE)
}

/// Creates a new key file (mode 0600, refusing to overwrite one) and returns the key. See the module docs for the
/// temporary file and the rename.
pub fn create(data_dir: &Path) -> Result<SecretKey, IdentityError> {
    let path = key_path(data_dir);
    // Unique enough for one data dir; `create_new` refuses a clash anyway.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = data_dir.join(format!(".{SERVER_KEY_FILE}.tmp-{}-{nanos}", std::process::id()));
    let key = SecretKey::generate();
    let result = write_then_rename(&tmp, &path, &key);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result?;
    // The rename is durable once the directory is.
    std::fs::File::open(data_dir)
        .and_then(|d| d.sync_all())
        .map_err(io("cannot sync", data_dir))?;
    Ok(key)
}

fn write_then_rename(tmp: &Path, path: &Path, key: &SecretKey) -> Result<(), IdentityError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)
        .map_err(io("cannot create", tmp))?;
    file.write_all(&key.to_bytes()).map_err(io("cannot write", tmp))?;
    file.sync_all().map_err(io("cannot sync", tmp))?;
    drop(file);
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        tmp,
        rustix::fs::CWD,
        path,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|e| io("cannot create", path)(e.into()))
}

/// Loads the key, checking the file's type, permissions and size.
pub fn load(data_dir: &Path) -> Result<SecretKey, IdentityError> {
    let path = key_path(data_dir);
    // `O_NOFOLLOW`: a symlink fails to open (ELOOP) instead of being followed. The checks below run on the opened
    // file itself, so nothing can be swapped between a check and the read.
    let nofollow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).unwrap_or(i32::MAX);
    let mut file = match OpenOptions::new().read(true).custom_flags(nofollow).open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(IdentityError::Missing(path)),
        Err(e) if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => {
            return Err(IdentityError::Invalid(path));
        }
        Err(e) => return Err(io("cannot open", &path)(e)),
    };
    let meta = file.metadata().map_err(io("cannot stat", &path))?;
    if !meta.file_type().is_file() {
        return Err(IdentityError::Invalid(path));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(IdentityError::TooOpen { path, mode });
    }
    if meta.len() != KEY_LEN as u64 {
        return Err(IdentityError::Invalid(path));
    }
    let mut bytes = [0u8; KEY_LEN];
    file.read_exact(&mut bytes).map_err(io("cannot read", &path))?;
    Ok(SecretKey::from_bytes(&bytes))
}

/// Loads the key, creating it first if the file does not exist (first `serve` after an `init` that predates it).
pub fn load_or_create(data_dir: &Path) -> Result<SecretKey, IdentityError> {
    match load(data_dir) {
        Err(IdentityError::Missing(_)) => match create(data_dir) {
            Err(IdentityError::Io { source, .. }) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                load(data_dir)
            }
            other => other,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::Permissions;

    use super::*;

    #[test]
    fn create_then_load_round_trips_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let key = create(dir.path()).unwrap();
        let mode = std::fs::metadata(key_path(dir.path())).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(load(dir.path()).unwrap().public(), key.public());
        // Never overwritten.
        assert!(create(dir.path()).is_err());
        assert_eq!(load_or_create(dir.path()).unwrap().public(), key.public());
    }

    /// No temporary file is left behind, and a stale one from an interrupted create is ignored: the key is either
    /// absent (created afresh) or complete, never a 0-byte `server.key`.
    #[test]
    fn create_leaves_no_temporary_file_and_ignores_stale_ones() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join(".server.key.tmp-0000000000000000");
        std::fs::write(&stale, b"").unwrap();
        assert!(matches!(load(dir.path()), Err(IdentityError::Missing(_))));
        let key = load_or_create(dir.path()).unwrap();
        assert_eq!(std::fs::metadata(key_path(dir.path())).unwrap().len(), 32);
        assert_eq!(load(dir.path()).unwrap().public(), key.public());
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2, "only the key and the stale file: {names:?}");
        // A second create refuses to replace the key, and cleans up its own temporary file.
        assert!(create(dir.path()).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        assert_eq!(load(dir.path()).unwrap().public(), key.public());
    }

    #[test]
    fn load_or_create_creates_a_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(load(dir.path()), Err(IdentityError::Missing(_))));
        let key = load_or_create(dir.path()).unwrap();
        assert_eq!(load(dir.path()).unwrap().public(), key.public());
    }

    #[test]
    fn a_key_readable_by_others_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        create(dir.path()).unwrap();
        for mode in [0o644, 0o640, 0o604, 0o660, 0o601] {
            std::fs::set_permissions(key_path(dir.path()), Permissions::from_mode(mode)).unwrap();
            let err = load(dir.path()).unwrap_err();
            assert!(matches!(err, IdentityError::TooOpen { .. }), "{mode:o}: {err}");
            // load_or_create refuses too: it never replaces a key that exists.
            assert!(load_or_create(dir.path()).is_err());
        }
        std::fs::set_permissions(key_path(dir.path()), Permissions::from_mode(0o400)).unwrap();
        assert!(load(dir.path()).is_ok());
    }

    #[test]
    fn wrong_size_and_symlinks_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(dir.path());
        std::fs::write(&path, [1u8; 31]).unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(load(dir.path()), Err(IdentityError::Invalid(_))));
        std::fs::remove_file(&path).unwrap();
        let other = dir.path().join("elsewhere");
        create(dir.path()).unwrap();
        std::fs::rename(&path, &other).unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert!(matches!(load(dir.path()), Err(IdentityError::Invalid(_))));
    }

    #[test]
    fn errors_never_print_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = create(dir.path()).unwrap();
        std::fs::set_permissions(key_path(dir.path()), Permissions::from_mode(0o644)).unwrap();
        let err = load(dir.path()).unwrap_err();
        let hex = data_encoding::HEXLOWER.encode(&key.to_bytes());
        assert!(!format!("{err} {err:?} {key:?}").contains(&hex));
    }
}
