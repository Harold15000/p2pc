// SPDX-License-Identifier: Apache-2.0

//! The node's persistent identity (spec §5 "Node identity").
//!
//! On first start the agent generates an Ed25519 secret key: 32 random bytes, stored raw at
//! `<data_dir>/identity.key` with mode 0600, written atomically. The data dir is mode 0700. The format is exactly
//! what `iroh_base::SecretKey::from_bytes` takes, so T05b loads the same file as its iroh endpoint key, and the
//! public key printed here is the node's iroh `NodeId` (`EndpointId`).
//!
//! The agent refuses to start when the key file is readable or writable by anyone but its owner, is not a regular
//! file, has the wrong size, or belongs to another user. The secret is never printed, logged or put in an error, and
//! [`Identity`]'s `Debug` shows only the public `NodeId`.

use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use iroh_base::{PublicKey, SecretKey};
use zeroize::Zeroizing;

/// The key file's name inside the data dir.
pub const IDENTITY_FILE: &str = "identity.key";
/// Size of the key file: a raw Ed25519 secret key.
pub const KEY_LEN: usize = 32;

/// Why the identity cannot be loaded or created. Never contains key material.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// A filesystem operation failed.
    #[error("{action} {}: {source}", path.display())]
    Io {
        /// What was being done.
        action: &'static str,
        /// The path.
        path: PathBuf,
        /// The error.
        source: io::Error,
    },
    /// The key file's permissions let other users read or write it.
    #[error(
        "refusing to use {}: its mode is {mode:04o}, wider than 0600; fix it with `chmod 600 {}`",
        path.display(),
        path.display()
    )]
    TooOpen {
        /// The key file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// The key file or the data dir belongs to another user.
    #[error("refusing to use {}: it belongs to UID {owner}, not to the agent's UID {euid}", path.display())]
    WrongOwner {
        /// The path.
        path: PathBuf,
        /// Its owner.
        owner: u32,
        /// The agent's effective UID.
        euid: u32,
    },
    /// The data dir is open to other users and holds files that are not ours, so the agent will not `chmod` it.
    #[error(
        "refusing to use {}: its mode is {mode:04o}, wider than 0700, and it holds files that are not the agent's \
         (for example {example:?}); use a dedicated directory, or fix it with `chmod 700 {}`",
        path.display(),
        path.display()
    )]
    DirTooOpen {
        /// The data dir.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
        /// The name of one foreign entry.
        example: String,
    },
    /// The key file is a symlink, a directory or another special file.
    #[error("refusing to use {}: not a regular file", path.display())]
    NotAFile {
        /// The path.
        path: PathBuf,
    },
    /// The key file does not hold exactly 32 bytes.
    #[error("refusing to use {}: expected {KEY_LEN} bytes, found {len}; the file is damaged", path.display())]
    BadLength {
        /// The key file.
        path: PathBuf,
        /// Its size.
        len: u64,
    },
}

fn io_err(action: &'static str, path: &Path) -> impl FnOnce(io::Error) -> IdentityError + use<> {
    let path = path.to_path_buf();
    move |source| IdentityError::Io { action, path, source }
}

/// The node's key pair.
pub struct Identity {
    secret: SecretKey,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("node_id", &self.node_id().to_string())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Identity {
    /// Loads `<data_dir>/identity.key`, creating the data dir (0700) and the key (0600) on first start.
    pub fn load_or_create(data_dir: &Path) -> Result<Self, IdentityError> {
        ensure_private_dir(data_dir)?;
        let path = data_dir.join(IDENTITY_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => Self::load_file(&path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::create(data_dir, &path),
            Err(e) => Err(io_err("cannot inspect", &path)(e)),
        }
    }

    /// Loads an existing `<data_dir>/identity.key`, with the same checks.
    pub fn load(data_dir: &Path) -> Result<Self, IdentityError> {
        Self::load_file(&data_dir.join(IDENTITY_FILE))
    }

    /// The public key: the node's iroh `NodeId`. Its `Display` is the lowercase hex form iroh uses.
    #[must_use]
    pub fn node_id(&self) -> PublicKey {
        self.secret.public()
    }

    /// The secret key, for the iroh endpoint (T05b). Never log it.
    #[must_use]
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    fn load_file(path: &Path) -> Result<Self, IdentityError> {
        let meta = fs::symlink_metadata(path).map_err(io_err("cannot inspect", path))?;
        if !meta.file_type().is_file() {
            return Err(IdentityError::NotAFile { path: path.into() });
        }
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            return Err(IdentityError::TooOpen {
                path: path.into(),
                mode,
            });
        }
        check_owner(path, &meta)?;
        if meta.len() != KEY_LEN as u64 {
            return Err(IdentityError::BadLength {
                path: path.into(),
                len: meta.len(),
            });
        }
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        // O_NOFOLLOW: the file was checked not to be a symlink; make sure it is still not one when opened.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .map_err(io_err("cannot open", path))?;
        file.read_exact(&mut bytes[..]).map_err(io_err("cannot read", path))?;
        Ok(Self {
            secret: SecretKey::from_bytes(&bytes),
        })
    }

    fn create(data_dir: &Path, path: &Path) -> Result<Self, IdentityError> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        rand::fill(&mut bytes[..]);
        let tmp = data_dir.join(format!(".{IDENTITY_FILE}.{:016x}.tmp", rand::random::<u64>()));
        let written = write_new(&tmp, &bytes[..]).and_then(|()| {
            // A hard link never replaces an existing file, so two agents starting at once cannot overwrite each
            // other's key: the loser loads the winner's.
            match fs::hard_link(&tmp, path) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
                Err(e) => Err(io_err("cannot install", path)(e)),
            }
        });
        let _ = fs::remove_file(&tmp);
        if written? {
            File::open(data_dir)
                .and_then(|d| d.sync_all())
                .map_err(io_err("cannot sync", data_dir))?;
        }
        Self::load_file(path)
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io_err("cannot create", path))?;
    file.write_all(bytes).map_err(io_err("cannot write", path))?;
    file.sync_all().map_err(io_err("cannot sync", path))
}

fn check_owner(path: &Path, meta: &fs::Metadata) -> Result<(), IdentityError> {
    let euid = rustix::process::geteuid().as_raw();
    if meta.uid() != euid {
        return Err(IdentityError::WrongOwner {
            path: path.into(),
            owner: meta.uid(),
            euid,
        });
    }
    Ok(())
}

/// Whether a directory entry is one of the agent's own: everything the agent itself puts in its data dir.
///
/// - the key, the lock file, the connection state, the lease status and the `jobs/` and `volumes/` directories by
///   name;
/// - the temporary file of the atomic install of the key and of each of those files (`.<name>.<hex>.tmp`, see
///   `connection::state::write_atomic`).
///
/// This is the single list [`IdentityError::DirTooOpen`] judges by (T10i). `run` goes through the same check as `join`
/// ([`crate::node::lock_data_dir`]), so an enrolled node whose data dir became 0755 later is tightened, not refused,
/// and the agent never calls its own files foreign.
fn is_agent_file(name: &str) -> bool {
    use crate::connection::state::STATE_FILE;
    use crate::executor::status::LEASES_FILE;
    use crate::node::LOCK_FILE;
    use crate::sandbox::jobdir::JOBS_DIR;
    use crate::volumes::VOLUMES_DIR;

    let by_name = [IDENTITY_FILE, LOCK_FILE, STATE_FILE, LEASES_FILE, JOBS_DIR, VOLUMES_DIR];
    let atomic = [IDENTITY_FILE, STATE_FILE, LEASES_FILE];
    by_name.contains(&name)
        || atomic.iter().any(|own| {
            name.strip_prefix('.')
                .and_then(|n| n.strip_prefix(own))
                .and_then(|n| n.strip_prefix('.'))
                .is_some_and(|n| n.ends_with(".tmp"))
        })
}

/// Creates `dir` and the missing parents, each with mode exactly 0700 whatever the umask or a setgid parent says, and
/// leaves the directories that exist as they are. Returns whether `dir` itself was created by this call.
///
/// The mode is set on creation and checked (set again) afterwards, so no file is ever made in a directory that does
/// not have its final mode (T10i, ACC-1).
pub(crate) fn create_private_dirs(dir: &Path) -> Result<bool, IdentityError> {
    let mut missing = Vec::new();
    let mut here = Some(dir);
    while let Some(p) = here.filter(|p| !p.as_os_str().is_empty()) {
        match fs::symlink_metadata(p) {
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::NotFound => missing.push(p),
            Err(e) => return Err(io_err("cannot inspect", p)(e)),
        }
        here = p.parent();
    }
    let mut created_dir = false;
    for p in missing.into_iter().rev() {
        match DirBuilder::new().mode(0o700).create(p) {
            Ok(()) => {
                // `mkdir` applies the umask (and a setgid parent adds a bit): make the mode exact, then check it.
                fs::set_permissions(p, fs::Permissions::from_mode(0o700)).map_err(io_err("cannot chmod", p))?;
                let mode = fs::metadata(p)
                    .map_err(io_err("cannot inspect", p))?
                    .permissions()
                    .mode()
                    & 0o7777;
                if mode != 0o700 {
                    return Err(io_err("cannot make private", p)(io::Error::other(format!(
                        "got mode {mode:04o}, not 0700"
                    ))));
                }
                created_dir = p == dir;
            }
            // Another process made it first; it is not ours to change.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_err("cannot create", p)(e)),
        }
    }
    Ok(created_dir)
}

/// Makes the data dir ready: created 0700 (with any missing parents, also 0700) when missing. An existing dir that is
/// open to others is tightened to 0700 only when it holds nothing but the agent's own files (see [`is_agent_file`]);
/// otherwise the agent refuses, rather than `chmod` a directory such as `/etc` or `$HOME` that somebody pointed
/// `data_dir` at. Whoever creates a file in the data dir calls this first ([`crate::node::lock_data_dir`] does).
///
/// # Errors
/// [`IdentityError::DirTooOpen`], [`IdentityError::WrongOwner`], or an I/O error.
pub fn ensure_private_dir(dir: &Path) -> Result<(), IdentityError> {
    if create_private_dirs(dir)? {
        return Ok(());
    }
    let meta = fs::metadata(dir).map_err(io_err("cannot inspect", dir))?;
    if !meta.is_dir() {
        return Err(io_err("cannot use as a directory", dir)(io::Error::new(
            io::ErrorKind::NotADirectory,
            "not a directory",
        )));
    }
    check_owner(dir, &meta)?;
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        for entry in fs::read_dir(dir).map_err(io_err("cannot list", dir))? {
            let name = entry.map_err(io_err("cannot list", dir))?.file_name();
            let name = name.to_string_lossy();
            if !is_agent_file(&name) {
                return Err(IdentityError::DirTooOpen {
                    path: dir.into(),
                    mode,
                    example: name.into_owned(),
                });
            }
        }
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(io_err("cannot chmod", dir))?;
    }
    Ok(())
}

/// Runs `f` with the process umask set to `mask`, then puts the old one back. A test that depends on the umask (the
/// bug of T10i showed only under 022) must not leave it to the runner's. Calls are serialized, but the umask is
/// process-wide: only files created by `f` itself should be judged by it.
#[cfg(test)]
pub(crate) fn with_umask<T>(mask: u32, f: impl FnOnce() -> T) -> T {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    struct Restore(rustix::fs::Mode);
    impl Drop for Restore {
        fn drop(&mut self) {
            rustix::process::umask(self.0);
        }
    }
    let _serial = LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let _restore = Restore(rustix::process::umask(rustix::fs::Mode::from_raw_mode(mask)));
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// A temp dir that is private whatever the umask or setgid parent of `$TMPDIR` is.
    fn private_tmp() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        tmp
    }

    #[test]
    fn created_with_mode_0600_in_a_0700_dir() {
        let tmp = private_tmp();
        let data_dir = tmp.path().join("state/p2pc");
        let id = Identity::load_or_create(&data_dir).unwrap();
        let key = data_dir.join(IDENTITY_FILE);
        assert_eq!(mode(&key), 0o600);
        assert_eq!(mode(&data_dir), 0o700);
        assert_eq!(fs::metadata(&key).unwrap().len(), 32);
        assert_eq!(fs::read(&key).unwrap(), id.secret_key().to_bytes());
        // No temporary file is left behind.
        assert_eq!(fs::read_dir(&data_dir).unwrap().count(), 1);
    }

    #[test]
    fn same_node_id_across_restarts() {
        let tmp = private_tmp();
        let first = Identity::load_or_create(tmp.path()).unwrap().node_id();
        let second = Identity::load_or_create(tmp.path()).unwrap().node_id();
        let third = Identity::load(tmp.path()).unwrap().node_id();
        assert_eq!(first, second);
        assert_eq!(first, third);
        // iroh's NodeId form: 64 lowercase hex characters.
        let s = first.to_string();
        assert_eq!(s.len(), 64);
        assert!(s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    #[test]
    fn known_key_gives_the_iroh_node_id() {
        // RFC 8032 test vector 1: this secret has this public key.
        let tmp = private_tmp();
        let secret = data_encoding::HEXLOWER
            .decode(b"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let path = tmp.path().join(IDENTITY_FILE);
        write_new(&path, &secret).unwrap();
        assert_eq!(
            Identity::load(tmp.path()).unwrap().node_id().to_string(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }

    #[test]
    fn refused_with_mode_0644() {
        let tmp = private_tmp();
        Identity::load_or_create(tmp.path()).unwrap();
        let key = tmp.path().join(IDENTITY_FILE);
        for wide in [0o644, 0o640, 0o604, 0o660, 0o666] {
            fs::set_permissions(&key, fs::Permissions::from_mode(wide)).unwrap();
            let err = Identity::load_or_create(tmp.path()).unwrap_err();
            assert!(
                matches!(err, IdentityError::TooOpen { mode, .. } if mode == wide),
                "{wide:o}: {err}"
            );
            assert!(err.to_string().contains("chmod 600"));
        }
        // Narrower than 0600 is fine.
        fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(Identity::load(tmp.path()).is_ok());
    }

    #[test]
    fn refuses_symlinks_and_damaged_files() {
        let tmp = private_tmp();
        let key = tmp.path().join(IDENTITY_FILE);
        write_new(&tmp.path().join("real.key"), &[7u8; 32]).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("real.key"), &key).unwrap();
        assert!(matches!(
            Identity::load_or_create(tmp.path()),
            Err(IdentityError::NotAFile { .. })
        ));
        fs::remove_file(&key).unwrap();
        write_new(&key, &[7u8; 31]).unwrap();
        assert!(matches!(
            Identity::load_or_create(tmp.path()),
            Err(IdentityError::BadLength { len: 31, .. })
        ));
    }

    #[test]
    fn tightens_an_existing_data_dir() {
        let tmp = private_tmp();
        let dir = tmp.path().join("data");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        Identity::load_or_create(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
    }

    #[test]
    fn tightens_a_dir_holding_only_the_key_and_its_temporary_files() {
        let tmp = private_tmp();
        let dir = tmp.path().join("data");
        Identity::load_or_create(&dir).unwrap();
        write_new(&dir.join(format!(".{IDENTITY_FILE}.00000000deadbeef.tmp")), &[1u8; 32]).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        Identity::load_or_create(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
    }

    #[test]
    fn refuses_to_chmod_a_shared_dir_with_other_files() {
        let tmp = private_tmp();
        let dir = tmp.path().join("etc");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("hosts"), b"192.0.2.1 example.invalid\n").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let err = Identity::load_or_create(&dir).unwrap_err();
        assert!(matches!(err, IdentityError::DirTooOpen { mode: 0o755, .. }), "{err}");
        let shown = err.to_string();
        assert!(shown.contains(&format!("chmod 700 {}", dir.display())), "{shown}");
        // Untouched: the dir keeps its mode and no key was written.
        assert_eq!(mode(&dir), 0o755);
        assert!(!dir.join(IDENTITY_FILE).exists());
        // A look-alike name is not ours either.
        fs::remove_file(dir.join("hosts")).unwrap();
        fs::write(dir.join(".identity.key.backup"), b"x").unwrap();
        assert!(matches!(
            Identity::load_or_create(&dir),
            Err(IdentityError::DirTooOpen { .. })
        ));
        assert_eq!(mode(&dir), 0o755);
    }

    #[test]
    fn a_private_dir_with_other_files_is_accepted_as_is() {
        let tmp = private_tmp();
        let dir = tmp.path().join("data");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(dir.join("other.txt"), b"x").unwrap();
        Identity::load_or_create(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
    }

    #[test]
    fn secret_never_in_debug_or_errors() {
        let tmp = private_tmp();
        let id = Identity::load_or_create(tmp.path()).unwrap();
        let secret = id.secret_key().to_bytes();
        let debug = format!("{id:?} {id:#?}");
        assert!(debug.contains(&id.node_id().to_string()), "{debug}");
        assert!(debug.contains("<redacted>"));
        let hex = data_encoding::HEXLOWER.encode(&secret);
        let forms = [
            hex.clone(),
            hex.to_uppercase(),
            hex[..16].to_string(),
            data_encoding::BASE32_NOPAD.encode(&secret).to_lowercase(),
            data_encoding::BASE32_NOPAD.encode(&secret),
            format!("{secret:?}"),
            format!("{:?}", &secret[..8]),
        ];
        for form in &forms {
            assert!(!debug.contains(form.as_str()), "secret leaked in Debug as {form}");
        }
        // Errors carry paths and modes, never the key.
        let key = tmp.path().join(IDENTITY_FILE);
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        let err = Identity::load(tmp.path()).unwrap_err();
        let shown = format!("{err} {err:?}");
        for form in &forms {
            assert!(!shown.contains(form.as_str()));
        }
    }

    /// T10i: `agent.lock` is the agent's own, so a 0755 dir holding it and the key is tightened.
    #[test]
    fn a_dir_holding_the_lock_file_is_the_agents() {
        let tmp = private_tmp();
        let dir = tmp.path().join("data");
        Identity::load_or_create(&dir).unwrap();
        write_new(&dir.join(crate::node::LOCK_FILE), b"").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        Identity::load_or_create(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
    }

    /// T10i: every directory made for the agent's state is 0700 whatever the parent is, existing ones are left as
    /// they are.
    #[test]
    fn private_dirs_are_created_0700_and_existing_ones_left_alone() {
        let tmp = private_tmp();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        with_umask(0o022, || create_private_dirs(&tmp.path().join("a/b/c"))).unwrap();
        for d in ["a", "a/b", "a/b/c"] {
            assert_eq!(mode(&tmp.path().join(d)), 0o700, "{d}");
        }
        assert_eq!(mode(tmp.path()), 0o755);
        // The first call made `c`; a second one makes nothing, so it says `false`, and `a/b` (widened by its owner) is
        // not touched. `ensure_private_dir` skips its owner and listing checks on `true` only.
        fs::set_permissions(tmp.path().join("a/b"), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(!create_private_dirs(&tmp.path().join("a/b/c")).unwrap());
        assert!(!create_private_dirs(&tmp.path().join("a/b")).unwrap());
        assert_eq!(mode(&tmp.path().join("a/b")), 0o750);
        assert_eq!(mode(&tmp.path().join("a/b/c")), 0o700);
        // A new dir: `true`, and only the last one asked for counts.
        assert!(create_private_dirs(&tmp.path().join("a/b/d/e")).unwrap());
        assert_eq!(mode(&tmp.path().join("a/b")), 0o750);
    }

    /// T10i review P3 4: a setgid parent adds its bit to what `mkdir` makes; the new dir is exactly 0700 anyway.
    #[test]
    fn a_setgid_parent_does_not_leave_its_bit_on_a_new_dir() {
        let tmp = private_tmp();
        let parent = tmp.path().join("shared");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o2755)).unwrap();
        // The test cannot make a setgid parent where the filesystem or the user's groups forbid it.
        if mode(&parent) & 0o2000 == 0 {
            return;
        }
        assert!(create_private_dirs(&parent.join("child/grandchild")).unwrap());
        assert_eq!(mode(&parent.join("child")), 0o700);
        assert_eq!(mode(&parent.join("child/grandchild")), 0o700);
        assert_eq!(mode(&parent), 0o2755, "the existing parent is left as it is");
    }

    /// T10i review P3 1: the error names the directory that failed, not the one the caller asked for.
    #[test]
    fn a_failure_in_a_parent_is_reported_against_that_parent() {
        if rustix::process::geteuid().is_root() {
            return; // root ignores the read-only mode this test relies on
        }
        let tmp = private_tmp();
        let locked = tmp.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
        let wanted = locked.join("p2pc-agent/data");
        let err = ensure_private_dir(&wanted).unwrap_err();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
        match err {
            IdentityError::Io { path, .. } => assert_eq!(path, locked.join("p2pc-agent")),
            other => panic!("unexpected error: {other}"),
        }
    }
}
