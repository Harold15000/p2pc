// SPDX-License-Identifier: Apache-2.0

//! Importing the distro and declaring it ready (H2 §8.3): `install.ps1`'s `Import-Distro`, `Test-NewDistro` and the
//! boot-status freshness rule (`Wait-BootStatus`).
//!
//! - **The install directory** holds nothing but the files WSL itself keeps there ([`WSL_OWNED_FILES`]), or nothing:
//!   the app never deletes files it did not create.
//! - **The import** is `wsl --import p2pc-node <dir> <tar> --version 2`, of a [`VerifiedImage`] only.
//! - **Resumable** (§8.2): an existing `p2pc-node` is not imported again; it is verified like a new one.
//! - **Verified**: `/etc/p2pc-distro-version` exists, `/var/lib/p2pc` is mode 700, `/mnt/c` does not exist (automount
//!   off: hard rule 8), `p2pc-boot` is there. A failure is §8.8 `distro_unhealthy`, naming the check.
//! - **Fresh boot status**: `p2pc-boot` runs asynchronously at each start of the distro, so an older
//!   `boot-status.json` can still be there. It is fresh when its `init_starttime` equals field 22 of `/proc/1/stat`
//!   read now: decided by identity, never by time (a clock step after sleep broke the time rule, T14a2).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::image::VerifiedImage;
use crate::runner::{Host, RunError};
use crate::{DISTRO_NAME, Layout};

/// The files WSL itself keeps in a distro's directory (`$WslOwnedFiles`, WSL 2.7.8 measured), compared
/// case-insensitively. Anything else there is somebody's file.
pub const WSL_OWNED_FILES: [&str; 2] = ["ext4.vhdx", "shortcut.ico"];

/// How long [`wait_boot_status`] waits for a fresh boot status (`$BootStatusWaitSeconds`), polling once a second.
pub const BOOT_STATUS_WAIT: Duration = Duration::from_secs(30);

/// The boot status file `p2pc-boot` writes.
pub const BOOT_STATUS_PATH: &str = "/var/lib/p2pc/boot-status.json";

/// The checks of a new distro (`Test-NewDistro`), each one command run in the distro as root, without a shell.
pub const VERIFY_VERSION: [&str; 2] = ["/bin/cat", "/etc/p2pc-distro-version"];
pub const VERIFY_STATE_MODE: [&str; 4] = ["/usr/bin/stat", "-c", "%a", "/var/lib/p2pc"];
pub const VERIFY_NO_MNT_C: [&str; 4] = ["/usr/bin/test", "!", "-e", "/mnt/c"];
pub const VERIFY_BOOT: [&str; 3] = ["/usr/bin/test", "-x", "/usr/local/sbin/p2pc-boot"];

/// How much of WSL's own message an error keeps.
const MAX_MESSAGE_CHARS: usize = 600;

/// What can go wrong while importing or verifying.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// `install.ps1` exit 19: the directory holds files WSL does not own.
    #[error("the install directory {} is not empty: it holds {} (WSL's own files, which are fine, are ext4.vhdx and shortcut.ico)", dir.display(), found.join(", "))]
    DirNotEmpty { dir: PathBuf, found: Vec<String> },
    /// `wsl.exe` resolves a relative path against its own directory: only absolute paths are used.
    #[error("not an absolute path: {}", .0.display())]
    RelativePath(PathBuf),
    /// `install.ps1` exit 20.
    #[error("wsl --import failed (exit {code:?}): {message}")]
    Import { code: Option<i32>, message: String },
    /// `install.ps1` exit 21; §8.8 `distro_unhealthy`.
    #[error("the distro did not pass verification: {}", problems.join("; "))]
    Unhealthy { problems: Vec<String> },
    #[error(transparent)]
    Run(#[from] RunError),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

impl ImportError {
    /// The H2 §8.8 code.
    pub fn code(&self) -> &'static str {
        match self {
            ImportError::Unhealthy { .. } => "distro_unhealthy",
            _ => "import_failed",
        }
    }
}

/// WSL's message, sanitized for the app (§8.8): control characters become spaces, runs of spaces one, and it is
/// capped at 600 characters.
pub fn sanitize_message(text: &str) -> String {
    let cleaned: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let mut out = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if out.chars().count() > MAX_MESSAGE_CHARS {
        out = out.chars().take(MAX_MESSAGE_CHARS).collect::<String>() + "...";
    }
    out
}

/// The registered distros (`wsl --list --quiet`, `Get-DistroNames`).
pub fn distro_names(host: Host<'_>) -> Result<Vec<String>, RunError> {
    let out = host.wsl(["--list", "--quiet"])?;
    Ok(out
        .text()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect())
}

/// `p2pc-node` is registered (`Test-DistroExists`).
pub fn distro_exists(host: Host<'_>) -> Result<bool, RunError> {
    Ok(distro_names(host)?.iter().any(|n| n == DISTRO_NAME))
}

/// The names that are not WSL's own (`Get-ForeignNames`).
pub fn foreign_names(names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter(|n| !n.is_empty() && !WSL_OWNED_FILES.iter().any(|w| w.eq_ignore_ascii_case(n)))
        .cloned()
        .collect()
}

/// The directory is missing, empty, or holds only WSL's own files (`Test-DistroDirNames`). Otherwise
/// [`ImportError::DirNotEmpty`], before anything is touched.
pub fn check_distro_dir(dir: &Path) -> Result<(), ImportError> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(ImportError::Io {
                context: format!("reading {}", dir.display()),
                source,
            });
        }
    };
    let names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let mut found = foreign_names(&names);
    if found.is_empty() {
        return Ok(());
    }
    found.sort();
    Err(ImportError::DirNotEmpty {
        dir: dir.to_owned(),
        found,
    })
}

/// `wsl --import p2pc-node <dir> <tar> --version 2` (`Import-Distro`), after the directory check.
pub fn import_distro(host: Host<'_>, dir: &Path, image: &VerifiedImage) -> Result<(), ImportError> {
    for p in [dir, image.path()] {
        if !p.is_absolute() {
            return Err(ImportError::RelativePath(p.to_owned()));
        }
    }
    check_distro_dir(dir)?;
    fs::create_dir_all(dir).map_err(|source| ImportError::Io {
        context: format!("creating {}", dir.display()),
        source,
    })?;
    tracing::info!(dir = %dir.display(), "importing {DISTRO_NAME}");
    let out = host.wsl([
        "--import".to_owned(),
        DISTRO_NAME.to_owned(),
        dir.display().to_string(),
        image.path().display().to_string(),
        "--version".to_owned(),
        "2".to_owned(),
    ])?;
    if !out.success() {
        return Err(ImportError::Import {
            code: out.code,
            message: sanitize_message(&out.text()),
        });
    }
    Ok(())
}

/// The checks of a new distro (`Test-NewDistro`). Returns its `image_version=` line (empty when it has none).
pub fn verify_distro(host: Host<'_>) -> Result<String, ImportError> {
    let mut problems = Vec::new();
    let version = host.in_distro(&VERIFY_VERSION)?;
    if !version.success() {
        problems.push("/etc/p2pc-distro-version is missing".to_owned());
    }
    let mode = host.in_distro(&VERIFY_STATE_MODE)?;
    let got = mode.stdout_text();
    if !mode.success() || got != "700" {
        problems.push(format!(
            "/var/lib/p2pc mode is not 700 (got: {})",
            sanitize_message(&got)
        ));
    }
    if !host.in_distro(&VERIFY_NO_MNT_C)?.success() {
        problems.push("/mnt/c exists inside the distro (automount is not off)".to_owned());
    }
    if !host.in_distro(&VERIFY_BOOT)?.success() {
        problems.push("/usr/local/sbin/p2pc-boot is missing".to_owned());
    }
    if !problems.is_empty() {
        return Err(ImportError::Unhealthy { problems });
    }
    let text = version.stdout_text();
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("image_version="))
        .unwrap_or_default()
        .to_owned();
    tracing::info!(version = %line, "distro verified");
    Ok(line)
}

/// Field 22 of a `/proc/<pid>/stat` line (starttime, raw clock ticks): after the last `)`, because the command name
/// sits in parentheses and may hold spaces (`Get-ProcStarttime`).
pub fn proc_starttime(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 2..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let f = fields.get(19)?;
    if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    f.parse().ok()
}

/// What `p2pc-boot` wrote in `boot-status.json` (one line:
/// `{"time":…,"init_starttime":N|null,"cdi":…,"cdi_regenerated":…,"errors":[…],"notes":[…]}`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BootStatus {
    /// The start ticks of the init this status was written in (`null` when `p2pc-boot` could not read them: never
    /// fresh).
    pub init_starttime: Option<u64>,
    /// When it was written (shown, never compared).
    #[serde(default)]
    pub time: Option<String>,
    /// The CDI state (`ok`, `no_nvidia_gpu`, `nvidia_smi_failed`, …).
    #[serde(default)]
    pub cdi: String,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl BootStatus {
    /// Parses the file; `None` when it is not the expected JSON.
    pub fn parse(json: &str) -> Option<Self> {
        serde_json::from_str(json.trim()).ok()
    }

    /// It records exactly this start of the distro's init (`Test-BootStatusFresh`).
    pub fn is_fresh(&self, init_starttime: u64) -> bool {
        self.init_starttime == Some(init_starttime)
    }

    /// `p2pc-boot` reported a problem: `cdi = nvidia_smi_failed` or any error (a warning, `Show-BootStatus`).
    pub fn has_problems(&self) -> bool {
        self.cdi == "nvidia_smi_failed" || !self.errors.is_empty()
    }
}

/// Polls once a second, up to `wait`, for the boot status of this start of the distro (`Wait-BootStatus`). `None`
/// when none appeared: a warning, not an error.
pub fn wait_boot_status(host: Host<'_>, wait: Duration) -> Option<BootStatus> {
    let polls = wait.as_secs();
    let mut init = None;
    for i in 0..=polls {
        if init.is_none()
            && let Ok(out) = host.in_distro(&["/bin/cat", "/proc/1/stat"])
            && out.success()
        {
            init = proc_starttime(&out.stdout_text());
        }
        if let Some(start) = init
            && let Ok(out) = host.in_distro(&["/bin/cat", BOOT_STATUS_PATH])
            && out.success()
            && let Some(status) = BootStatus::parse(&out.stdout_text())
            && status.is_fresh(start)
        {
            return Some(status);
        }
        if i < polls {
            host.pause().sleep(Duration::from_secs(1));
        }
    }
    None
}

/// The distro is in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The `image_version=` line of `/etc/p2pc-distro-version`.
    pub image_version: String,
    /// It was imported now (`false`: it already existed and passed its checks, §8.2 "Resumable").
    pub imported: bool,
    /// The fresh boot status, or `None` when it did not come within [`BOOT_STATUS_WAIT`] (a warning).
    pub boot_status: Option<BootStatus>,
}

/// Step 3's import (`Invoke-Install` without the checks and the hash, done before): imports the verified image
/// unless `p2pc-node` exists, verifies the distro, then waits for its fresh boot status.
pub fn install(host: Host<'_>, layout: &Layout, image: &VerifiedImage) -> Result<Installed, ImportError> {
    let imported = if distro_exists(host)? {
        tracing::info!("{DISTRO_NAME} already exists: not imported again, verified");
        false
    } else {
        import_distro(host, &layout.distro_dir(), image)?;
        true
    };
    let image_version = verify_distro(host)?;
    let boot_status = wait_boot_status(host, BOOT_STATUS_WAIT);
    match &boot_status {
        None => tracing::warn!(
            "p2pc-boot has not written a fresh boot status within {} s of this start of the distro",
            BOOT_STATUS_WAIT.as_secs()
        ),
        Some(s) if s.has_problems() => {
            tracing::warn!(cdi = %s.cdi, errors = ?s.errors, "p2pc-boot reported problems")
        }
        Some(s) => tracing::info!(cdi = %s.cdi, "p2pc-boot: no errors"),
    }
    Ok(Installed {
        image_version,
        imported,
        boot_status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::*;
    use crate::runner::{Output, WSL_EXE};

    /// A `/proc/1/stat` line whose command name holds spaces and a parenthesis, with starttime `start`.
    fn stat(start: u64) -> String {
        format!(
            "1 (init (p2pc) x) S 0 1 1 0 -1 4194560 1 2 3 4 5 6 7 8 20 0 1 0 {start} 2252800 300 18446744073709551615"
        )
    }

    fn status(start: &str) -> String {
        format!(
            r#"{{"time":"2026-11-10T09:00:00Z","init_starttime":{start},"cdi":"no_nvidia_gpu","cdi_regenerated":false,"errors":[],"notes":["a \"quoted\" note"]}}"#
        )
    }

    fn healthy(runner: &FakeRunner) {
        runner
            .on(
                |i| in_distro_is(i, &VERIFY_VERSION),
                Output::with(0, "image_version=0.3.0\nbuilt=2026-11-01\n"),
            )
            .on(|i| in_distro_is(i, &VERIFY_STATE_MODE), Output::with(0, "700\n"))
            .on(|i| in_distro_is(i, &VERIFY_NO_MNT_C), Output::with(0, ""))
            .on(|i| in_distro_is(i, &VERIFY_BOOT), Output::with(0, ""))
            .on(
                |i| in_distro_is(i, &["/bin/cat", "/proc/1/stat"]),
                Output::with(0, stat(4242)),
            )
            .on(
                |i| in_distro_is(i, &["/bin/cat", BOOT_STATUS_PATH]),
                Output::with(0, status("4242")),
            );
    }

    #[test]
    fn install_imports_a_verified_image_with_version_2_then_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        let runner = FakeRunner::new();
        runner.on(
            |i| starts(i, WSL_EXE, &["--list"]),
            Output::with(0, utf16("Ubuntu\r\ndocker-desktop\r\n")),
        );
        runner.on(|i| starts(i, WSL_EXE, &["--import"]), Output::with(0, ""));
        healthy(&runner);
        let pause = FakePause::default();
        let tar = dir.path().join("p2pc-node-0.3.0.tar.gz");
        let got = install(Host::new(&runner, &pause), &layout, &VerifiedImage::for_tests(&tar)).unwrap();
        assert!(got.imported);
        assert_eq!(got.image_version, "image_version=0.3.0");
        assert_eq!(got.boot_status.unwrap().notes, vec!["a \"quoted\" note".to_owned()]);
        let import = runner
            .calls()
            .into_iter()
            .find(|i| starts(i, WSL_EXE, &["--import"]))
            .unwrap();
        assert_eq!(
            import.arguments(),
            &[
                "--import".to_owned(),
                "p2pc-node".to_owned(),
                layout.distro_dir().display().to_string(),
                tar.display().to_string(),
                "--version".to_owned(),
                "2".to_owned()
            ]
        );
        assert!(layout.distro_dir().is_dir());
        assert!(pause.slept().is_empty(), "the status was fresh at once");
    }

    #[test]
    fn an_existing_distro_is_verified_not_imported_again() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new();
        runner.on(
            |i| starts(i, WSL_EXE, &["--list"]),
            Output::with(0, utf16("Ubuntu\r\np2pc-node\r\n")),
        );
        healthy(&runner);
        let pause = FakePause::default();
        let tar = dir.path().join("i.tar.gz");
        let got = install(
            Host::new(&runner, &pause),
            &Layout::new(dir.path()),
            &VerifiedImage::for_tests(tar),
        )
        .unwrap();
        assert!(!got.imported);
        assert_eq!(runner.count(|i| starts(i, WSL_EXE, &["--import"])), 0);
    }

    #[test]
    fn a_failed_import_returns_wsls_message_sanitized() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new();
        runner.on(
            |i| starts(i, WSL_EXE, &["--import"]),
            Output::with(
                1,
                utf16(
                    "The operation could not be completed.\r\n\tError code: Wsl/Service/RegisterDistro/0x80070005\r\n",
                ),
            ),
        );
        let pause = FakePause::default();
        let err = import_distro(
            Host::new(&runner, &pause),
            &dir.path().join("d"),
            &VerifiedImage::for_tests(dir.path().join("i.tar.gz")),
        )
        .unwrap_err();
        match &err {
            ImportError::Import { code, message } => {
                assert_eq!(*code, Some(1));
                assert_eq!(
                    message,
                    "The operation could not be completed. Error code: Wsl/Service/RegisterDistro/0x80070005"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(err.code(), "import_failed");
    }

    #[test]
    fn the_import_is_retried_on_the_wsl_service_timeout_only() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new();
        runner.on_seq(
            |i| starts(i, WSL_EXE, &["--import"]),
            vec![
                Ok(Output::with(-1, utf16("Wsl/Service/0x8007274c"))),
                Ok(Output::with(0, "")),
            ],
        );
        let pause = FakePause::default();
        import_distro(
            Host::new(&runner, &pause),
            &dir.path().join("d"),
            &VerifiedImage::for_tests(dir.path().join("i")),
        )
        .unwrap();
        assert_eq!(runner.count(|i| starts(i, WSL_EXE, &["--import"])), 2);
    }

    #[test]
    fn the_install_dir_may_hold_only_wsls_own_files() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("p2pc-node");
        assert!(check_distro_dir(&d).is_ok(), "missing is fine");
        fs::create_dir(&d).unwrap();
        assert!(check_distro_dir(&d).is_ok(), "empty is fine");
        fs::write(d.join("EXT4.VHDX"), b"").unwrap();
        fs::write(d.join("shortcut.ico"), b"").unwrap();
        assert!(check_distro_dir(&d).is_ok(), "WSL's own files, any case");
        fs::write(d.join("notes.txt"), b"mine").unwrap();
        let runner = FakeRunner::new();
        let pause = FakePause::default();
        let err = import_distro(
            Host::new(&runner, &pause),
            &d,
            &VerifiedImage::for_tests(dir.path().join("i")),
        )
        .unwrap_err();
        assert!(
            matches!(&err, ImportError::DirNotEmpty { found, .. } if found == &vec!["notes.txt".to_owned()]),
            "{err:?}"
        );
        assert!(runner.calls().is_empty(), "nothing ran");
        assert!(d.join("notes.txt").exists(), "nothing was deleted");
    }

    #[test]
    fn relative_paths_are_refused() {
        let runner = FakeRunner::new();
        let pause = FakePause::default();
        let err = import_distro(
            Host::new(&runner, &pause),
            Path::new("wsl\\p2pc-node"),
            &VerifiedImage::for_tests("/abs/i"),
        )
        .unwrap_err();
        assert!(matches!(err, ImportError::RelativePath(_)));
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn every_failed_verification_is_named() {
        let runner = FakeRunner::new();
        runner
            .on(|i| in_distro_is(i, &VERIFY_VERSION), Output::with(1, ""))
            .on(|i| in_distro_is(i, &VERIFY_STATE_MODE), Output::with(0, "755\n"))
            .on(|i| in_distro_is(i, &VERIFY_NO_MNT_C), Output::with(1, ""))
            .on(|i| in_distro_is(i, &VERIFY_BOOT), Output::with(1, ""));
        let pause = FakePause::default();
        let err = verify_distro(Host::new(&runner, &pause)).unwrap_err();
        assert_eq!(err.code(), "distro_unhealthy");
        match err {
            ImportError::Unhealthy { problems } => assert_eq!(
                problems,
                vec![
                    "/etc/p2pc-distro-version is missing",
                    "/var/lib/p2pc mode is not 700 (got: 755)",
                    "/mnt/c exists inside the distro (automount is not off)",
                    "/usr/local/sbin/p2pc-boot is missing",
                ]
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn proc_starttime_reads_field_22_after_the_command_name() {
        assert_eq!(proc_starttime(&stat(987654)), Some(987654));
        assert_eq!(proc_starttime("1 (init) S 0 1"), None);
        assert_eq!(proc_starttime("no parenthesis"), None);
        assert_eq!(proc_starttime(&stat(1).replace(" 1 2252800", " x 2252800")), None);
    }

    #[test]
    fn a_boot_status_is_fresh_only_for_this_init() {
        let s = BootStatus::parse(&status("4242")).unwrap();
        assert!(s.is_fresh(4242));
        assert!(!s.is_fresh(4243));
        let null = BootStatus::parse(&status("null")).unwrap();
        assert!(!null.is_fresh(0), "null is never fresh");
        assert_eq!(BootStatus::parse("{not json"), None);
        let failed =
            BootStatus::parse(r#"{"init_starttime":1,"cdi":"nvidia_smi_failed","errors":[],"notes":[]}"#).unwrap();
        assert!(failed.has_problems());
        assert!(!s.has_problems());
    }

    #[test]
    fn a_stale_status_is_waited_for_then_given_up_after_30_s() {
        let runner = FakeRunner::new();
        runner
            .on(
                |i| in_distro_is(i, &["/bin/cat", "/proc/1/stat"]),
                Output::with(0, stat(500)),
            )
            .on(
                |i| in_distro_is(i, &["/bin/cat", BOOT_STATUS_PATH]),
                Output::with(0, status("499")),
            );
        let pause = FakePause::default();
        assert_eq!(wait_boot_status(Host::new(&runner, &pause), BOOT_STATUS_WAIT), None);
        assert_eq!(pause.slept(), vec![Duration::from_secs(1); 30]);
        assert_eq!(
            runner.count(|i| in_distro_is(i, &["/bin/cat", "/proc/1/stat"])),
            1,
            "init is read once"
        );
        assert_eq!(runner.count(|i| in_distro_is(i, &["/bin/cat", BOOT_STATUS_PATH])), 31);
    }

    #[test]
    fn a_status_that_turns_fresh_ends_the_wait() {
        let runner = FakeRunner::new();
        runner
            .on(
                |i| in_distro_is(i, &["/bin/cat", "/proc/1/stat"]),
                Output::with(0, stat(77)),
            )
            .on_seq(
                |i| in_distro_is(i, &["/bin/cat", BOOT_STATUS_PATH]),
                vec![
                    Ok(Output::with(1, "")),
                    Ok(Output::with(0, status("76"))),
                    Ok(Output::with(0, status("77"))),
                ],
            );
        let pause = FakePause::default();
        let s = wait_boot_status(Host::new(&runner, &pause), BOOT_STATUS_WAIT).unwrap();
        assert_eq!(s.init_starttime, Some(77));
        assert_eq!(pause.slept().len(), 2);
    }

    #[test]
    fn sanitize_strips_control_characters_and_caps_the_length() {
        assert_eq!(sanitize_message("a\r\n\tb\u{1b}[31m  c"), "a b [31m c");
        let long = "x".repeat(700);
        let s = sanitize_message(&long);
        assert_eq!(s.chars().count(), 603);
        assert!(s.ends_with("..."));
    }
}
