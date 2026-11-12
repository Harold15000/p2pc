// SPDX-License-Identifier: Apache-2.0

//! The per-job scratch directory (spec §9): `<data_dir>/jobs/<lease_id>/`, mode 0700, with
//!
//! - `inputs/`: the job's decoded `files` and its blob `inputs` (H2 §7.5), mounted read-only at `/inputs`;
//! - `outputs/`: mounted read-write at `/outputs`, collected after exit (SI-9, [`super::outputs`]);
//! - `p2pc/`: a copy of the shim and, with egress, the proxy's socket; mounted read-only at `/.p2pc`;
//! - `env`: the 0600 `--env-file`, deleted as soon as Podman has read it.
//!
//! Inputs are written **relative to an open directory**, one path segment at a time (`openat`/`mkdirat` with
//! `O_NOFOLLOW`), so a symlink anywhere on the way is refused instead of followed and nothing is ever created
//! outside `inputs/`. Files are created with `O_EXCL`: an existing entry is never overwritten.

use std::fs;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use p2pc_proto::api::InputFile;
use p2pc_proto::ids::LeaseId;
use p2pc_proto::validate::{INPUTS_DIR, decode_base64_bounded, validate_input_path};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

/// Mode of the job directory.
pub const JOB_DIR_MODE: u32 = 0o700;
/// Mode of `inputs/`, `outputs/`, `p2pc/` and the directories under `inputs/`. The job directory above them is
/// 0700, so the host sees none of it; inside the container a non-root image user can still read its inputs.
pub const SUBDIR_MODE: u32 = 0o755;
/// Mode of each input file.
pub const INPUT_FILE_MODE: u32 = 0o644;
/// Mode of the env file.
pub const ENV_FILE_MODE: u32 = 0o600;
/// Mode of the shim copy.
pub const SHIM_MODE: u32 = 0o755;
/// The directory under the data dir that holds every job directory.
pub const JOBS_DIR: &str = "jobs";
/// Largest decoded input file set (§7: 512 KiB in total). Checked again here, before decoding.
pub const MAX_INPUT_BYTES: usize = 512 * 1024;

/// Why an input file was not written.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    /// The path is not under `/inputs/`, or has `..`, `.` or empty segments.
    #[error("input {path}: invalid path")]
    InvalidPath {
        /// The path, as given by the job.
        path: String,
    },
    /// The content is not valid base64, or the inputs are over 512 KiB.
    #[error("input {path}: invalid or oversized content")]
    InvalidContent {
        /// The path.
        path: String,
    },
    /// A symlink, an existing entry, or a non-directory on the way.
    #[error("input {path}: refused ({reason})")]
    Refused {
        /// The path.
        path: String,
        /// What was in the way.
        reason: &'static str,
    },
    /// Any other I/O error.
    #[error("input {path}: {source}")]
    Io {
        /// The path.
        path: String,
        /// The error.
        source: io::Error,
    },
}

/// A job directory.
#[derive(Debug, Clone)]
pub struct JobDir {
    root: PathBuf,
}

/// Creates `path` with `mode` (ignoring the umask), failing if it exists.
fn mkdir_exact(path: &Path, mode: u32) -> io::Result<()> {
    fs::DirBuilder::new().mode(mode).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

/// `<data_dir>/jobs/<lease_id>`.
#[must_use]
pub fn job_dir_path(data_dir: &Path, lease_id: &LeaseId) -> PathBuf {
    data_dir.join(JOBS_DIR).join(lease_id.to_string())
}

impl JobDir {
    /// Creates `<data_dir>/jobs/<lease_id>/` (0700) with `inputs/`, `outputs/` and `p2pc/`.
    ///
    /// `<data_dir>/jobs` is created (0700) if missing; it must be a real directory, not a symlink. The job
    /// directory itself must not exist yet: a stale one is the orphan sweep's job, never silently reused.
    ///
    /// # Errors
    /// Any I/O error; `AlreadyExists` if the job directory exists.
    pub fn create(data_dir: &Path, lease_id: &LeaseId) -> io::Result<Self> {
        let jobs = data_dir.join(JOBS_DIR);
        match mkdir_exact(&jobs, JOB_DIR_MODE) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let meta = fs::symlink_metadata(&jobs)?;
                if !meta.is_dir() {
                    return Err(io::Error::other(format!("{} is not a directory", jobs.display())));
                }
            }
            Err(e) => return Err(e),
        }
        let root = job_dir_path(data_dir, lease_id);
        mkdir_exact(&root, JOB_DIR_MODE)?;
        let dir = Self { root };
        for sub in ["inputs", "outputs", "p2pc"] {
            if let Err(e) = mkdir_exact(&dir.root.join(sub), SUBDIR_MODE) {
                // Never leave a half-made job directory behind.
                let _ = dir.remove();
                return Err(e);
            }
        }
        Ok(dir)
    }

    /// Wraps an existing job directory (for cleanup).
    #[must_use]
    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    /// The job directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `inputs/`.
    #[must_use]
    pub fn inputs(&self) -> PathBuf {
        self.root.join("inputs")
    }

    /// `outputs/`.
    #[must_use]
    pub fn outputs(&self) -> PathBuf {
        self.root.join("outputs")
    }

    /// `p2pc/`.
    #[must_use]
    pub fn p2pc(&self) -> PathBuf {
        self.root.join("p2pc")
    }

    /// The env file.
    #[must_use]
    pub fn env_file(&self) -> PathBuf {
        self.root.join("env")
    }

    /// The egress socket path (`p2pc/egress.sock`, `/.p2pc/egress.sock` in the container).
    #[must_use]
    pub fn egress_socket(&self) -> PathBuf {
        self.p2pc().join("egress.sock")
    }

    /// Writes every input file under `inputs/`. Refuses traversal, symlinks and existing entries.
    ///
    /// # Errors
    /// [`InputError`] for the first file that cannot be written. Files already written stay; the cleanup removes
    /// the whole job directory.
    pub fn write_inputs(&self, files: &[InputFile]) -> Result<(), InputError> {
        let inputs = open_dir(rustix::fs::CWD, &self.inputs()).map_err(|e| InputError::Io {
            path: INPUTS_DIR.into(),
            source: e.into(),
        })?;
        let mut total = 0usize;
        for file in files {
            let path = file.path.clone();
            validate_input_path(&path).map_err(|_| InputError::InvalidPath { path: path.clone() })?;
            let remaining = MAX_INPUT_BYTES.saturating_sub(total);
            let content = decode_base64_bounded(&file.content_b64, remaining)
                .map_err(|_| InputError::InvalidContent { path: path.clone() })?;
            total += content.len();
            let rel = path
                .strip_prefix(INPUTS_DIR)
                .and_then(|r| r.strip_prefix('/'))
                .ok_or_else(|| InputError::InvalidPath { path: path.clone() })?;
            write_relative(&inputs, rel, &content).map_err(|e| match e {
                WriteError::Refused(reason) => InputError::Refused { path, reason },
                WriteError::Io(source) => InputError::Io { path, source },
            })?;
        }
        Ok(())
    }

    /// Creates the empty file of a blob input at `path` (under `/inputs/`), with its parents, by the same rules as
    /// [`JobDir::write_inputs`]: a validated path, walked one segment at a time without following links, the file new
    /// (`O_EXCL`), 0644. The caller writes the blob into it (H2 §7.5).
    ///
    /// # Errors
    /// [`InputError`]: an invalid path, a symlink or an existing entry on the way, or an I/O error.
    pub fn create_input_file(&self, path: &str) -> Result<fs::File, InputError> {
        validate_input_path(path).map_err(|_| InputError::InvalidPath { path: path.into() })?;
        let rel = path
            .strip_prefix(INPUTS_DIR)
            .and_then(|r| r.strip_prefix('/'))
            .ok_or_else(|| InputError::InvalidPath { path: path.into() })?;
        let inputs = open_dir(rustix::fs::CWD, &self.inputs()).map_err(|e| InputError::Io {
            path: INPUTS_DIR.into(),
            source: e.into(),
        })?;
        create_relative(&inputs, rel).map(fs::File::from).map_err(|e| match e {
            WriteError::Refused(reason) => InputError::Refused {
                path: path.into(),
                reason,
            },
            WriteError::Io(source) => InputError::Io {
                path: path.into(),
                source,
            },
        })
    }

    /// Writes the env file (0600, `O_EXCL | O_NOFOLLOW`) with `content` (from [`super::argv::env_file`]).
    ///
    /// # Errors
    /// Any I/O error, including an existing entry.
    pub fn write_env_file(&self, content: &str) -> io::Result<PathBuf> {
        let path = self.env_file();
        let fd = rustix::fs::open(
            &path,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(ENV_FILE_MODE),
        )?;
        // Exact mode whatever the umask.
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(ENV_FILE_MODE))?;
        let mut f = fs::File::from(fd);
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
        Ok(path)
    }

    /// Deletes the env file. Missing is fine.
    ///
    /// # Errors
    /// Any I/O error other than `NotFound`.
    pub fn remove_env_file(&self) -> io::Result<()> {
        match fs::remove_file(self.env_file()) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// Copies the shim binary to `p2pc/shim` (0755).
    ///
    /// # Errors
    /// Any I/O error.
    pub fn install_shim(&self, shim: &Path) -> io::Result<()> {
        let dst = self.p2pc().join("shim");
        let mut src = fs::File::open(shim)?;
        let fd = rustix::fs::open(
            &dst,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(SHIM_MODE),
        )?;
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(SHIM_MODE))?;
        let mut out = fs::File::from(fd);
        io::copy(&mut src, &mut out)?;
        out.sync_all()
    }

    /// Removes the whole job directory. Missing is fine. Symlinks inside are removed, never followed.
    ///
    /// # Errors
    /// Any I/O error other than `NotFound`.
    pub fn remove(&self) -> io::Result<()> {
        match fs::remove_dir_all(&self.root) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

enum WriteError {
    Refused(&'static str),
    Io(io::Error),
}

impl From<Errno> for WriteError {
    fn from(e: Errno) -> Self {
        match e {
            // O_NOFOLLOW on a symlink gives ELOOP, or ENOTDIR together with O_DIRECTORY (which a file gives too);
            // O_EXCL gives EEXIST.
            Errno::LOOP => Self::Refused("symlink"),
            Errno::NOTDIR => Self::Refused("symlink or not a directory"),
            Errno::EXIST => Self::Refused("already exists"),
            other => Self::Io(other.into()),
        }
    }
}

fn open_dir<Fd: std::os::fd::AsFd>(at: Fd, name: &Path) -> Result<OwnedFd, Errno> {
    rustix::fs::openat(
        at,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Writes `content` at `rel` (validated: no `..`, `.` or empty segments) below the directory `base`.
fn write_relative(base: &OwnedFd, rel: &str, content: &[u8]) -> Result<(), WriteError> {
    let mut f = fs::File::from(create_relative(base, rel)?);
    f.write_all(content).map_err(WriteError::Io)
}

/// Creates the new file `rel` (validated: no `..`, `.` or empty segments) below the directory `base`, with its
/// parents, never following a link, and returns it open for writing.
fn create_relative(base: &OwnedFd, rel: &str) -> Result<OwnedFd, WriteError> {
    let segments: Vec<&str> = rel.split('/').collect();
    let Some((name, parents)) = segments.split_last() else {
        return Err(WriteError::Refused("empty path"));
    };
    let mut dir: Option<OwnedFd> = None;
    for seg in parents {
        let here = dir.as_ref().unwrap_or(base);
        match rustix::fs::mkdirat(here, *seg, Mode::from_raw_mode(SUBDIR_MODE)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(e.into()),
        }
        let next = open_dir(here, Path::new(seg))?;
        // mkdirat honours the umask: set the exact mode.
        rustix::fs::fchmod(&next, Mode::from_raw_mode(SUBDIR_MODE)).map_err(WriteError::from)?;
        dir = Some(next);
    }
    let here = dir.as_ref().unwrap_or(base);
    let fd = rustix::fs::openat(
        here,
        *name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(INPUT_FILE_MODE),
    )?;
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(INPUT_FILE_MODE)).map_err(WriteError::from)?;
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::str::FromStr;

    use super::*;

    fn lease() -> LeaseId {
        LeaseId::from_str("lse_01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap()
    }

    fn file(path: &str, content: &[u8]) -> InputFile {
        InputFile {
            path: path.into(),
            content_b64: data_encoding::BASE64.encode(content),
        }
    }

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().mode() & 0o7777
    }

    #[test]
    fn creates_the_layout_with_exact_modes() {
        let data = tempfile::tempdir().unwrap();
        let dir = JobDir::create(data.path(), &lease()).unwrap();
        assert_eq!(dir.root(), data.path().join("jobs/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert_eq!(mode(dir.root()), 0o700);
        for sub in [dir.inputs(), dir.outputs(), dir.p2pc()] {
            assert_eq!(mode(&sub), 0o755, "{}", sub.display());
        }
        // A second create for the same lease fails: stale directories are never reused.
        assert_eq!(
            JobDir::create(data.path(), &lease()).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        dir.remove().unwrap();
        assert!(!dir.root().exists());
        dir.remove().unwrap();
    }

    #[test]
    fn refuses_a_symlinked_jobs_dir() {
        let data = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        symlink(elsewhere.path(), data.path().join("jobs")).unwrap();
        assert!(JobDir::create(data.path(), &lease()).is_err());
        assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
    }

    #[test]
    fn writes_inputs_with_parents() {
        let data = tempfile::tempdir().unwrap();
        let dir = JobDir::create(data.path(), &lease()).unwrap();
        dir.write_inputs(&[
            file("/inputs/data.csv", b"a,b\n"),
            file("/inputs/x/y/z.bin", &[0, 1, 2]),
        ])
        .unwrap();
        assert_eq!(fs::read(dir.inputs().join("data.csv")).unwrap(), b"a,b\n");
        assert_eq!(fs::read(dir.inputs().join("x/y/z.bin")).unwrap(), [0, 1, 2]);
        assert_eq!(mode(&dir.inputs().join("x/y")), 0o755);
        assert_eq!(mode(&dir.inputs().join("x/y/z.bin")), 0o644);
    }

    #[test]
    fn refuses_traversal() {
        let data = tempfile::tempdir().unwrap();
        let dir = JobDir::create(data.path(), &lease()).unwrap();
        for path in [
            "/inputs/../escape",
            "/inputs/a/../../escape",
            "/etc/passwd",
            "inputs/rel",
            "/inputs/./x",
            "/inputs//x",
            "/inputs/",
        ] {
            let e = dir.write_inputs(&[file(path, b"x")]).unwrap_err();
            assert!(matches!(e, InputError::InvalidPath { .. }), "{path}: {e}");
        }
        assert!(!dir.root().join("escape").exists());
        assert!(!data.path().join("jobs/escape").exists());
    }

    #[test]
    fn refuses_symlinks_on_the_way_and_at_the_end() {
        let data = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let dir = JobDir::create(data.path(), &lease()).unwrap();
        // Planted symlinks (a fresh job directory has none; this is what the checks are for).
        symlink(outside.path(), dir.inputs().join("link")).unwrap();
        symlink(outside.path().join("target"), dir.inputs().join("file")).unwrap();

        let e = dir.write_inputs(&[file("/inputs/link/x", b"x")]).unwrap_err();
        assert!(
            matches!(e, InputError::Refused { reason, .. } if reason.contains("symlink")),
            "{e}"
        );
        let e = dir.write_inputs(&[file("/inputs/link/deep/x", b"x")]).unwrap_err();
        assert!(matches!(e, InputError::Refused { .. }), "{e}");
        let e = dir.write_inputs(&[file("/inputs/file", b"x")]).unwrap_err();
        assert!(matches!(e, InputError::Refused { .. }), "{e}");
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0, "nothing escaped");

        // A file where a directory is needed.
        fs::write(dir.inputs().join("plain"), b"").unwrap();
        let e = dir.write_inputs(&[file("/inputs/plain/x", b"x")]).unwrap_err();
        assert!(matches!(e, InputError::Refused { .. }), "{e}");
        // An existing file is never overwritten.
        let e = dir.write_inputs(&[file("/inputs/plain", b"x")]).unwrap_err();
        assert!(
            matches!(
                e,
                InputError::Refused {
                    reason: "already exists",
                    ..
                }
            ),
            "{e}"
        );
    }

    #[test]
    fn refuses_bad_or_oversized_content() {
        let data = tempfile::tempdir().unwrap();
        let dir = JobDir::create(data.path(), &lease()).unwrap();
        let bad = InputFile {
            path: "/inputs/a".into(),
            content_b64: "!!!".into(),
        };
        assert!(matches!(
            dir.write_inputs(&[bad]),
            Err(InputError::InvalidContent { .. })
        ));
        let half = vec![0u8; MAX_INPUT_BYTES / 2 + 1];
        let e = dir
            .write_inputs(&[file("/inputs/b", &half), file("/inputs/c", &half)])
            .unwrap_err();
        assert!(matches!(e, InputError::InvalidContent { .. }), "{e}");
    }

    /// H2 §7.5: a blob input is delivered into `inputs/` like an inline file: created there with its parents, by the
    /// same `O_NOFOLLOW`/`O_EXCL` walk, never outside it.
    #[test]
    fn creates_a_blob_input_file_with_the_inline_file_rules() {
        use std::io::Write as _;
        let data = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let dir = JobDir::create(data.path(), &lease()).unwrap();
        let mut f = dir.create_input_file("/inputs/models/audio.wav").unwrap();
        f.write_all(b"RIFF").unwrap();
        drop(f);
        assert_eq!(fs::read(dir.inputs().join("models/audio.wav")).unwrap(), b"RIFF");
        assert_eq!(mode(&dir.inputs().join("models")), 0o755);
        assert_eq!(mode(&dir.inputs().join("models/audio.wav")), 0o644);

        for path in ["/inputs/../escape", "/etc/passwd", "/inputs/", "/inputs//x"] {
            let e = dir.create_input_file(path).unwrap_err();
            assert!(matches!(e, InputError::InvalidPath { .. }), "{path}: {e}");
        }
        symlink(outside.path(), dir.inputs().join("link")).unwrap();
        let e = dir.create_input_file("/inputs/link/x").unwrap_err();
        assert!(matches!(e, InputError::Refused { .. }), "{e}");
        let e = dir.create_input_file("/inputs/models/audio.wav").unwrap_err();
        assert!(
            matches!(
                e,
                InputError::Refused {
                    reason: "already exists",
                    ..
                }
            ),
            "{e}"
        );
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0, "nothing escaped");
        assert_eq!(fs::read(dir.inputs().join("models/audio.wav")).unwrap(), b"RIFF");
    }

    #[test]
    fn env_file_is_0600_and_removable() {
        let data = tempfile::tempdir().unwrap();
        let dir = JobDir::create(data.path(), &lease()).unwrap();
        let path = dir.write_env_file("A=1\n").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(fs::read_to_string(&path).unwrap(), "A=1\n");
        assert!(dir.write_env_file("B=2\n").is_err(), "O_EXCL");
        dir.remove_env_file().unwrap();
        assert!(!path.exists());
        dir.remove_env_file().unwrap();
    }

    #[test]
    fn installs_the_shim() {
        let data = tempfile::tempdir().unwrap();
        let dir = JobDir::create(data.path(), &lease()).unwrap();
        let shim = data.path().join("shim-src");
        fs::write(&shim, b"\x7fELF fake").unwrap();
        dir.install_shim(&shim).unwrap();
        let dst = dir.p2pc().join("shim");
        assert_eq!(fs::read(&dst).unwrap(), b"\x7fELF fake");
        assert_eq!(mode(&dst), 0o755);
    }
}
