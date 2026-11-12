// SPDX-License-Identifier: Apache-2.0

//! The upload directory of `p2pc_blob_put` (H2 §7.8, SI-H2-21).
//!
//! An AI agent behind MCP is steerable by untrusted job output, so the one tool that reads a local file on its behalf
//! reads from a single directory the user set aside, and from nowhere else. [`UploadDir::prepare`] checks and creates
//! that directory when `p2pc mcp` starts; [`UploadDir::open`] turns the agent's path into an open file, or into a
//! [`PathNotAllowed`] that names the rule that failed. Nothing is opened before the path has passed the lexical rules.
//!
//! Unix only. On other targets `p2pc mcp` has no upload directory and `p2pc_blob_put` refuses every call: a Windows
//! implementation is a task of its own (it needs the canonical directory re-checked on each call and
//! `FILE_FLAG_OPEN_REPARSE_POINT` with a check of the handle), and none of it is compiled here.
//!
//! - **Lexical rules**: the path is relative to the upload directory (an absolute path is accepted
//!   only when it starts with the upload directory's own text, and is then handled as the rest). Empty, `.` and `..`
//!   components, and any component that starts with `.`, are refused.
//! - **No link anywhere** (Unix): the directory is opened with `O_NOFOLLOW | O_DIRECTORY` and each component below it
//!   with `openat(O_NOFOLLOW)`, so no link is followed in any component. The last component is checked with
//!   `fstatat(AT_SYMLINK_NOFOLLOW)` to be a regular file, opened with `O_NOFOLLOW | O_NONBLOCK` (a FIFO swapped in
//!   cannot block), and the descriptor's `fstat` must show a regular file with the same device and inode.
//! - **The directory is pinned.** `prepare` stores its canonical path. On every call the directory must still not be a
//!   symbolic link and must still canonicalize to that same path, so a link put in place of the directory or of one of
//!   its parents after start-up refuses the call.
//!
//! The caller reads the returned descriptor, never the path again.

use std::fs::File;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

/// The most characters in a path the agent gives. Longer is refused before anything is opened.
const MAX_REQUEST_LEN: usize = 4096;

/// A path the tool will not read, and the rule that failed. It is the text of the `path_not_allowed` tool error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PathNotAllowed(pub String);

impl PathNotAllowed {
    fn rule(text: impl Into<String>) -> Self {
        Self(text.into())
    }
}

/// A regular file opened inside the upload directory.
#[derive(Debug)]
pub struct OpenedUpload {
    /// The descriptor. Hash and upload both read this, never the path.
    pub file: File,
    /// Its size from `fstat` when it was opened.
    pub size: u64,
}

/// The upload directory, checked at start-up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadDir {
    /// As the user gave it, made absolute: what an absolute path of the agent is compared with.
    path: PathBuf,
    /// Its real location when `prepare` ran, with no link in it. Every call checks that it is still this.
    canonical: PathBuf,
}

impl UploadDir {
    /// Checks `dir` (creating it with mode 0700 when it is missing) and returns it as the upload directory.
    ///
    /// Refused: a symbolic link; something that is not a directory owned by the user; a directory that grants group
    /// or other access; the user's home directory itself (`home`); and a directory that is, contains or lies inside
    /// the p2pc configuration and credentials directory (`config_dir`). The message says which.
    pub fn prepare(dir: &Path, home: Option<&Path>, config_dir: &Path) -> Result<Self, String> {
        let shown = dir.display();
        let path = lexical_absolute(dir).map_err(|e| format!("the upload directory {shown}: {e}"))?;
        if path.to_str().is_none() {
            return Err(format!("the upload directory {shown} must be valid UTF-8"));
        }
        create_private(&path).map_err(|e| format!("the upload directory {shown} could not be created: {e}"))?;
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("the upload directory {shown} cannot be read: {e}"))?;
        if meta.file_type().is_symlink() {
            return Err(format!("the upload directory {shown} is a symbolic link"));
        }
        if !meta.is_dir() {
            return Err(format!("the upload directory {shown} is not a directory"));
        }
        check_owner_and_mode(&meta).map_err(|e| format!("the upload directory {shown} {e}"))?;

        // Compare the real locations, so that a link in a parent does not hide the overlap.
        let real = std::fs::canonicalize(&path)
            .map_err(|e| format!("the upload directory {shown} cannot be resolved: {e}"))?;
        if home.is_some_and(|home| real == real_or_lexical(home)) {
            return Err(format!("the upload directory {shown} is the home directory itself"));
        }
        let config = real_or_lexical(config_dir);
        if same_or_inside(&real, &config) {
            return Err(format!(
                "the upload directory {shown} is, or lies inside, the p2pc configuration directory (credentials)"
            ));
        }
        if same_or_inside(&config, &real) {
            return Err(format!(
                "the upload directory {shown} contains the p2pc configuration directory (credentials)"
            ));
        }
        Ok(Self { path, canonical: real })
    }

    /// The directory, as an absolute path without `.` or `..`.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Opens `requested`, a path as the agent gave it, for reading. See the module documentation for the rules.
    pub fn open(&self, requested: &str) -> Result<OpenedUpload, PathNotAllowed> {
        let components = self.components_of(requested)?;
        self.still_pinned()?;
        open_checked(&self.canonical, &components)
    }

    /// The directory is still the one `prepare` checked: not a link now, and the same real location.
    fn still_pinned(&self) -> Result<(), PathNotAllowed> {
        let moved = || {
            PathNotAllowed::rule("the upload directory changed since `p2pc mcp` started (it or a parent is a link now)")
        };
        let meta = std::fs::symlink_metadata(&self.path).map_err(|_| moved())?;
        if meta.file_type().is_symlink() {
            return Err(moved());
        }
        match std::fs::canonicalize(&self.path) {
            Ok(real) if real == self.canonical => Ok(()),
            _ => Err(moved()),
        }
    }

    /// The components of `requested` below the upload directory, after the lexical rules.
    fn components_of(&self, requested: &str) -> Result<Vec<String>, PathNotAllowed> {
        if requested.is_empty() {
            return Err(PathNotAllowed::rule("the path is empty"));
        }
        if requested.len() > MAX_REQUEST_LEN {
            return Err(PathNotAllowed::rule("the path is too long"));
        }
        if requested.contains('\0') {
            return Err(PathNotAllowed::rule("the path holds a NUL character"));
        }
        let rest = if Path::new(requested).is_absolute() {
            let base = self.path.to_str().unwrap_or_default();
            let after = requested.strip_prefix(base).and_then(|r| r.strip_prefix('/'));
            match after {
                Some(rest) => rest,
                None => {
                    return Err(PathNotAllowed::rule(
                        "an absolute path must lie under the upload directory; give a path relative to it",
                    ));
                }
            }
        } else {
            requested
        };
        let mut out = Vec::new();
        for part in rest.split('/') {
            if part.is_empty() {
                return Err(PathNotAllowed::rule("the path has an empty component"));
            }
            if part == "." || part == ".." {
                return Err(PathNotAllowed::rule("the path has a `.` or `..` component"));
            }
            if part.starts_with('.') {
                return Err(PathNotAllowed::rule("hidden files and directories are not read"));
            }
            out.push(part.to_string());
        }
        Ok(out)
    }
}

/// `dir` as an absolute path, with `.` and the trailing separator removed. A `..` is refused: it would make the
/// lexical comparison of a requested path with the directory meaningless.
fn lexical_absolute(dir: &Path) -> Result<PathBuf, String> {
    let absolute = std::path::absolute(dir).map_err(|e| format!("cannot be made absolute: {e}"))?;
    let mut out = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => return Err("must not contain `..`".into()),
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    Ok(out)
}

/// The real location of `path` when it exists, its lexical absolute form otherwise.
fn real_or_lexical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path)
        .or_else(|_| lexical_absolute(path).map_err(std::io::Error::other))
        .unwrap_or_else(|_| path.to_path_buf())
}

/// Whether `inner` is `outer` or lies below it (by whole components).
fn same_or_inside(inner: &Path, outer: &Path) -> bool {
    inner.starts_with(outer)
}

/// Creates `path` (and its parents) when it is missing; the last directory with mode 0700.
fn create_private(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        other => other,
    }
}

fn check_owner_and_mode(meta: &std::fs::Metadata) -> Result<(), String> {
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err("is not owned by the user".into());
    }
    if meta.mode() & 0o077 != 0 {
        return Err("grants access to its group or to others (use mode 0700: `chmod 700`)".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Reading the descriptor
// ---------------------------------------------------------------------------------------------------------------

/// Why a descriptor could not be read as the `size` it had when it was opened.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The file yielded fewer bytes than `size`.
    #[error("the file got shorter while it was read")]
    Shrank,
    /// The file yielded more bytes than `size`.
    #[error("the file got longer while it was read")]
    Grew,
    /// The read or the write failed.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Reads exactly `size` bytes from `reader` and returns their SHA-256, writing them to `sink` too when there is one.
///
/// It never reads more than `size` bytes and one more to find out whether there are more: a file that grows while it
/// is read is refused ([`ReadError::Grew`]) and never makes the upload larger than the size that was checked against
/// `max_blob_mb`.
pub fn read_exact_hashed<R, W>(
    reader: &mut R,
    size: u64,
    mut sink: Option<&mut W>,
) -> Result<p2pc_proto::api::Sha256Digest, ReadError>
where
    R: std::io::Read,
    W: std::io::Write,
{
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut remaining = size;
    while remaining > 0 {
        let want = usize::try_from(remaining).map_or(buf.len(), |n| n.min(buf.len()));
        let n = match reader.read(buf.get_mut(..want).unwrap_or_default()) {
            Ok(0) => return Err(ReadError::Shrank),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        let chunk = buf.get(..n).unwrap_or_default();
        hasher.update(chunk);
        if let Some(sink) = sink.as_mut() {
            sink.write_all(chunk)?;
        }
        remaining = remaining.saturating_sub(n as u64);
    }
    // One more byte means the file grew.
    let mut probe = [0u8; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(0) => break,
            Ok(_) => return Err(ReadError::Grew),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(p2pc_proto::api::Sha256Digest(hasher.finalize().into()))
}

// ---------------------------------------------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------------------------------------------

fn open_checked(dir: &Path, components: &[String]) -> Result<OpenedUpload, PathNotAllowed> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, open, openat, statat};

    let refused =
        |what: &str, e: rustix::io::Errno| PathNotAllowed::rule(format!("{what}: {}", std::io::Error::from(e)));
    let directory = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;

    // The upload directory itself: a link in its place is refused by `O_NOFOLLOW`.
    let mut current = open(dir, directory, Mode::empty()).map_err(|e| {
        refused(
            "the upload directory cannot be opened (it must not be a symbolic link)",
            e,
        )
    })?;
    // Still private? (It could have been changed since start-up.)
    let root = fstat(&current).map_err(|e| refused("the upload directory cannot be inspected", e))?;
    if root.st_uid != rustix::process::geteuid().as_raw() || root.st_mode & 0o077 != 0 {
        return Err(PathNotAllowed::rule(
            "the upload directory is not private any more (owned by the user, mode 0700)",
        ));
    }

    let Some((last, middle)) = components.split_last() else {
        return Err(PathNotAllowed::rule("the path is empty"));
    };
    for name in middle {
        current = openat(&current, name.as_str(), directory, Mode::empty()).map_err(|e| {
            refused(
                "a directory of the path cannot be opened (no symbolic link is followed)",
                e,
            )
        })?;
    }

    // Before opening: it must be a regular file, and not a link to one.
    let before = statat(&current, last.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| refused("the file cannot be read (no symbolic link is followed)", e))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
        return Err(PathNotAllowed::rule(
            "only regular files are read (not links, directories, FIFOs, sockets or devices)",
        ));
    }
    let fd = openat(
        &current,
        last.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| refused("the file cannot be opened (no symbolic link is followed)", e))?;
    // The descriptor, not the name, is what counts: a regular file, the one that was checked.
    let after = fstat(&fd).map_err(|e| refused("the file cannot be inspected", e))?;
    if FileType::from_raw_mode(after.st_mode) != FileType::RegularFile
        || after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
    {
        return Err(PathNotAllowed::rule("the file changed while it was opened"));
    }
    Ok(OpenedUpload {
        size: u64::try_from(after.st_size).unwrap_or(0),
        file: File::from(fd),
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    struct Fixture {
        // Keeps the directories alive.
        _root: tempfile::TempDir,
        base: PathBuf,
        up: UploadDir,
        config: PathBuf,
    }

    fn private(path: &Path) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn fixture() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        // The temporary directory may be a link (macOS); work from its real location.
        let base = std::fs::canonicalize(root.path()).unwrap();
        private(&base);
        let dir = base.join("uploads");
        let config = base.join("config");
        std::fs::create_dir(&config).unwrap();
        let up = UploadDir::prepare(&dir, Some(&base), &config).unwrap();
        Fixture {
            _root: root,
            base,
            up,
            config,
        }
    }

    fn refused(f: &Fixture, path: &str) -> String {
        match f.up.open(path) {
            Ok(_) => panic!("{path:?} must be refused"),
            Err(e) => e.0,
        }
    }

    #[test]
    fn a_regular_file_is_opened_by_a_relative_path_and_by_an_absolute_one_under_the_directory() {
        let f = fixture();
        std::fs::create_dir(f.up.path().join("sub")).unwrap();
        std::fs::write(f.up.path().join("sub/a.txt"), b"hello").unwrap();
        let opened = f.up.open("sub/a.txt").unwrap();
        assert_eq!(opened.size, 5);
        let absolute = format!("{}/sub/a.txt", f.up.path().display());
        assert_eq!(f.up.open(&absolute).unwrap().size, 5);
    }

    #[test]
    fn traversal_and_odd_components_are_refused_before_anything_is_opened() {
        let f = fixture();
        std::fs::write(f.base.join("outside.txt"), b"secret").unwrap();
        std::fs::create_dir(f.up.path().join("sub")).unwrap();
        std::fs::write(f.up.path().join("sub/a.txt"), b"x").unwrap();
        for bad in [
            "../outside.txt",
            "sub/../../outside.txt",
            "sub/../sub/a.txt",
            "./sub/a.txt",
            "sub//a.txt",
            "sub/./a.txt",
            "sub/",
            "/sub/a.txt",
            "",
            ".",
            "..",
        ] {
            assert!(f.up.open(bad).is_err(), "{bad:?} must be refused");
        }
        // Even under the directory's own name, a `..` in the rest is refused.
        let tricky = format!("{}/../outside.txt", f.up.path().display());
        assert!(refused(&f, &tricky).contains("`..`"), "{tricky}");
        assert!(f.up.open("a\0b").is_err());
        assert!(f.up.open(&"a/".repeat(3000)).is_err());
    }

    #[test]
    fn an_absolute_path_outside_the_directory_is_refused() {
        let f = fixture();
        std::fs::write(f.base.join("outside.txt"), b"secret").unwrap();
        for bad in [
            "/etc/passwd".to_string(),
            f.base.join("outside.txt").display().to_string(),
            f.config.join("credentials.toml").display().to_string(),
            // A sibling that merely starts with the directory's name.
            format!("{}-evil/a", f.up.path().display()),
        ] {
            assert!(refused(&f, &bad).contains("under the upload directory"), "{bad}");
        }
    }

    #[test]
    fn hidden_files_and_files_under_hidden_directories_are_refused() {
        let f = fixture();
        std::fs::write(f.up.path().join(".secret"), b"x").unwrap();
        std::fs::create_dir(f.up.path().join(".git")).unwrap();
        std::fs::write(f.up.path().join(".git/config"), b"x").unwrap();
        assert!(refused(&f, ".secret").contains("hidden"));
        assert!(refused(&f, ".git/config").contains("hidden"));
        assert!(refused(&f, "dir/.env").contains("hidden"));
    }

    #[test]
    fn a_symbolic_link_is_refused_in_every_position() {
        let f = fixture();
        std::fs::write(f.base.join("outside.txt"), b"secret").unwrap();
        std::fs::create_dir(f.base.join("outdir")).unwrap();
        std::fs::write(f.base.join("outdir/inner.txt"), b"secret").unwrap();
        // A link to a file outside, as the last component.
        symlink(f.base.join("outside.txt"), f.up.path().join("link.txt")).unwrap();
        // A link to a directory outside, as a middle component.
        symlink(f.base.join("outdir"), f.up.path().join("linkdir")).unwrap();
        // A link to a file inside the directory is a link all the same.
        std::fs::write(f.up.path().join("real.txt"), b"x").unwrap();
        symlink(f.up.path().join("real.txt"), f.up.path().join("inside.txt")).unwrap();
        for bad in ["link.txt", "linkdir/inner.txt", "inside.txt"] {
            assert!(f.up.open(bad).is_err(), "{bad} must be refused");
        }
        assert!(f.up.open("real.txt").is_ok());
    }

    #[test]
    fn the_upload_directory_replaced_by_a_link_is_refused() {
        let f = fixture();
        std::fs::write(f.up.path().join("a.txt"), b"x").unwrap();
        let moved = f.base.join("moved");
        std::fs::rename(f.up.path(), &moved).unwrap();
        symlink(&moved, f.up.path()).unwrap();
        assert!(f.up.open("a.txt").is_err());
    }

    #[test]
    fn a_parent_of_the_directory_replaced_by_a_link_after_start_up_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        let parent = base.join("parent");
        std::fs::create_dir(&parent).unwrap();
        let up = UploadDir::prepare(&parent.join("uploads"), None, &base.join("config")).unwrap();
        std::fs::write(up.path().join("a.txt"), b"x").unwrap();
        assert!(up.open("a.txt").is_ok());
        // Another private directory with an `uploads` of the same name, holding a file of the same name.
        let other = base.join("other");
        std::fs::create_dir_all(other.join("uploads")).unwrap();
        private(&other.join("uploads"));
        std::fs::write(other.join("uploads/a.txt"), b"TOPSECRET").unwrap();
        std::fs::rename(&parent, base.join("parent-moved")).unwrap();
        symlink(&other, &parent).unwrap();
        // `parent/uploads` is a real directory (no link in its last component), but it is not the one that was checked.
        assert!(!std::fs::symlink_metadata(up.path()).unwrap().file_type().is_symlink());
        assert!(up.open("a.txt").unwrap_err().0.contains("changed since"));
    }

    #[test]
    fn a_fifo_does_not_block_and_a_socket_a_device_and_a_directory_are_refused() {
        use rustix::fs::{CWD, FileType, Mode, mknodat};
        let f = fixture();
        let fifo = f.up.path().join("pipe");
        mknodat(CWD, &fifo, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
        // Refused by the type check, before it is opened: a reader that nobody writes to would block otherwise.
        assert!(refused(&f, "pipe").contains("regular files"));
        let socket = f.up.path().join("sock");
        // A restricted sandbox may forbid binding a socket at all; the type check is the one that refused the FIFO.
        let _listener = std::os::unix::net::UnixListener::bind(&socket);
        if _listener.is_ok() {
            assert!(refused(&f, "sock").contains("regular files"));
        }
        std::fs::create_dir(f.up.path().join("adir")).unwrap();
        assert!(refused(&f, "adir").contains("regular files"));
        // A device node needs privilege to create; try, and say what was covered when it cannot be made.
        let device = f.up.path().join("null");
        let dev_null = rustix::fs::makedev(1, 3);
        match mknodat(
            CWD,
            &device,
            FileType::CharacterDevice,
            Mode::RUSR | Mode::WUSR,
            dev_null,
        ) {
            Ok(()) => assert!(refused(&f, "null").contains("regular files")),
            // Without CAP_MKNOD the node cannot be made here; the type check is the same one that refused the
            // FIFO and the socket (it accepts `RegularFile` only).
            Err(_) => assert_ne!(FileType::CharacterDevice, FileType::RegularFile),
        }
    }

    /// A reader that keeps yielding bytes after `size`, as a file that grows during the upload does.
    struct Growing {
        left: usize,
    }

    impl std::io::Read for Growing {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.left);
            buf[..n].fill(b'x');
            self.left -= n;
            Ok(n)
        }
    }

    #[test]
    fn the_bounded_read_hashes_exactly_size_bytes_and_refuses_a_file_that_grew_or_shrank() {
        use sha2::{Digest, Sha256};
        let mut exact: &[u8] = b"hello world";
        let digest = read_exact_hashed(&mut exact, 11, None::<&mut Vec<u8>>).unwrap();
        assert_eq!(digest.0, <[u8; 32]>::from(Sha256::digest(b"hello world")));
        // A sink gets the same bytes.
        let (mut sink, mut again): (Vec<u8>, &[u8]) = (Vec::new(), b"hello world");
        read_exact_hashed(&mut again, 11, Some(&mut sink)).unwrap();
        assert_eq!(sink, b"hello world");
        // Longer than the size that was checked against `max_blob_mb`: refused, and never read in full.
        let mut grows = Growing { left: 11 + 1_000_000 };
        assert!(matches!(
            read_exact_hashed(&mut grows, 11, None::<&mut Vec<u8>>),
            Err(ReadError::Grew)
        ));
        assert!(
            grows.left >= 1_000_000 - 1,
            "it read far beyond the size: {} left",
            grows.left
        );
        // One byte more is enough.
        let mut one_more: &[u8] = b"hello world!";
        assert!(matches!(
            read_exact_hashed(&mut one_more, 11, None::<&mut Vec<u8>>),
            Err(ReadError::Grew)
        ));
        let mut shorter: &[u8] = b"hello";
        assert!(matches!(
            read_exact_hashed(&mut shorter, 11, None::<&mut Vec<u8>>),
            Err(ReadError::Shrank)
        ));
    }

    #[test]
    fn a_directory_that_stopped_being_private_is_refused_at_open() {
        let f = fixture();
        std::fs::write(f.up.path().join("a.txt"), b"x").unwrap();
        std::fs::set_permissions(f.up.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(refused(&f, "a.txt").contains("not private"));
    }

    #[test]
    fn a_missing_directory_is_created_with_mode_0700() {
        let root = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        let dir = base.join("a/b/uploads");
        let up = UploadDir::prepare(&dir, None, &base.join("config")).unwrap();
        let mode = std::fs::metadata(up.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn start_up_refuses_an_unsafe_directory() {
        let root = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        let config = base.join("config");
        std::fs::create_dir(&config).unwrap();
        let prepare = |dir: &Path, home: Option<&Path>| UploadDir::prepare(dir, home, &config);

        // Group or other access.
        for mode in [0o750, 0o705, 0o770, 0o755] {
            let dir = base.join(format!("open{mode:o}"));
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(prepare(&dir, None).unwrap_err().contains("grants access"), "{mode:o}");
        }
        // A symbolic link, even to a good directory.
        let good = base.join("good");
        std::fs::create_dir(&good).unwrap();
        private(&good);
        let link = base.join("link");
        symlink(&good, &link).unwrap();
        assert!(prepare(&link, None).unwrap_err().contains("symbolic link"));
        // Not a directory.
        let file = base.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(prepare(&file, None).unwrap_err().contains("not a directory"));
        // `..` in the argument.
        assert!(prepare(&good.join("../good"), None).unwrap_err().contains(".."));
        // The home directory itself (also through a link in its name).
        private(&base);
        assert!(prepare(&base, Some(&base)).unwrap_err().contains("home directory"));
        // The good one passes, and a home that merely contains it is fine.
        assert!(prepare(&good, Some(&base)).is_ok());
    }

    #[test]
    fn start_up_refuses_a_directory_that_is_contains_or_lies_inside_the_credentials_directory() {
        let root = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        private(&base);
        let config = base.join("cfg");
        std::fs::create_dir(&config).unwrap();
        private(&config);
        // Is it.
        assert!(
            UploadDir::prepare(&config, None, &config)
                .unwrap_err()
                .contains("configuration")
        );
        // Inside it.
        let inside = config.join("uploads");
        let err = UploadDir::prepare(&inside, None, &config).unwrap_err();
        assert!(err.contains("configuration"), "{err}");
        // Contains it.
        let err = UploadDir::prepare(&base, None, &config).unwrap_err();
        assert!(err.contains("contains"), "{err}");
        // Through a link in the parent: the real locations are compared.
        let alias = tempfile::tempdir().unwrap();
        let alias_link = alias.path().join("alias");
        symlink(&base, &alias_link).unwrap();
        let err = UploadDir::prepare(&alias_link.join("cfg"), None, &config).unwrap_err();
        assert!(err.contains("configuration"), "{err}");
        // An unrelated sibling is fine.
        assert!(UploadDir::prepare(&base.join("uploads"), None, &config).is_ok());
    }
}
