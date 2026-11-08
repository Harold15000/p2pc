// SPDX-License-Identifier: Apache-2.0

//! The container engine: the few Podman operations the driver needs, behind a trait.
//!
//! [`PodmanEngine`] runs the `podman` CLI: short commands through [`CommandRunner`] (argv only, never a shell,
//! with a timeout), and the one long-running command, `podman start --attach`, as a child process whose stdout and
//! stderr are the job's logs and whose exit code is the job's. Attaching **before** the container starts means no
//! output is lost and the exit code is known even though the container runs with `--rm`.
//!
//! The lifecycle logic in [`super::driver`] is tested against a mock of this trait (with paused time); the CLI
//! mapping is tested with [`crate::runner::FakeRunner`] and, end to end, with a fake `podman` script.

use std::fmt;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncRead;

use super::argv::LEASE_LABEL;
use crate::runner::{CommandOutput, CommandRunner, RunError, SystemRunner};

/// Timeout of the short Podman commands (`create`, `kill`, `inspect`, `rm`, `ps`). `create` may chown the job
/// directories (`:U`) and set up a user namespace, so it gets more than the inventory's 5 s.
pub const PODMAN_TIMEOUT: Duration = Duration::from_secs(60);
/// Default timeout of `podman pull`.
pub const PULL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Timeout of one manifest read (`skopeo inspect --raw` or `podman manifest inspect`): a manifest is a few KiB, so a
/// registry that has not answered in this time is not going to, and the lease must not wait for the pull timeout.
pub const MANIFEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The `--events-backend` of the agent's own Podman: a file, never the system journal (T10m).
pub const EVENTS_BACKEND: &str = "file";

/// A signal for the container's PID 1 (the shim, which forwards SIGTERM to the job).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopSignal {
    /// SIGTERM: the polite request.
    Term,
    /// SIGKILL: after the grace period, or for the disk limit.
    Kill,
}

impl StopSignal {
    fn name(self) -> &'static str {
        match self {
            Self::Term => "TERM",
            Self::Kill => "KILL",
        }
    }
}

/// What `podman container inspect --size` says, when the container still exists.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContainerState {
    /// `State.OOMKilled`. Podman 4.9.3 with cgroupfs never sets it; the lease cgroup is the primary source.
    pub oom_killed: bool,
    /// `SizeRw`: the writable layer, in bytes.
    pub size_rw: Option<u64>,
    /// Whether the container ever started: `State.StartedAt` is not Go's zero time. `None` when not reported.
    pub started: Option<bool>,
}

/// A failed engine operation. The message is Podman's first line of output, never job env values (which Podman
/// reads from the env file and does not print).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{msg}")]
pub struct EngineError {
    /// What failed.
    pub msg: String,
    /// Whether the command ran into its timeout. A fact about how it ended, set where the timeout is detected: the
    /// text of Podman's or a registry's own message never decides it.
    pub timed_out: bool,
}

impl EngineError {
    /// A failure that is not a timeout.
    pub fn new(msg: String) -> Self {
        Self { msg, timed_out: false }
    }

    /// A command that ran into its timeout and was killed.
    pub fn timed_out(msg: String) -> Self {
        Self { msg, timed_out: true }
    }

    /// Whether the command ran into its timeout.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        self.timed_out
    }
}

/// The exit code of the job, or why it is unknown.
pub type ExitFuture = Pin<Box<dyn Future<Output = Result<i32, EngineError>> + Send>>;

/// A started container, attached.
pub struct Attached {
    /// The job's standard output.
    pub stdout: Pin<Box<dyn AsyncRead + Send>>,
    /// The job's standard error.
    pub stderr: Pin<Box<dyn AsyncRead + Send>>,
    /// Resolves to the exit code: the container's, or `128 + signal`.
    pub exit: ExitFuture,
}

impl fmt::Debug for Attached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Attached { .. }")
    }
}

/// A container that carries the `p2pc.lease` label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseContainer {
    /// Its name.
    pub name: String,
    /// The value of its `p2pc.lease` label.
    pub lease: String,
}

/// The container engine.
pub trait Engine: Send + Sync + 'static {
    /// `podman pull`, in the agent's context (the job's network policy does not apply to pulls).
    fn pull(&self, image: &str) -> impl Future<Output = Result<(), EngineError>> + Send;
    /// The size of a pulled image, in bytes.
    fn image_size(&self, image: &str) -> impl Future<Output = Result<u64, EngineError>> + Send;
    /// Whether the image is already in local storage (`podman image exists`).
    fn image_exists(&self, image: &str) -> impl Future<Output = Result<bool, EngineError>> + Send;
    /// The total size of the image's layers (and config) for this node's platform, read from the registry's
    /// manifest **without pulling** (`podman manifest inspect`; for a multi-platform list, a second inspect of this
    /// platform's manifest by digest).
    fn manifest_size(&self, image: &str) -> impl Future<Output = Result<u64, EngineError>> + Send;
    /// `podman rmi --ignore`: removes what a refused or failed pull left behind.
    fn remove_image(&self, image: &str) -> impl Future<Output = Result<(), EngineError>> + Send;
    /// `podman <argv>`, where `argv` is from [`super::argv::create_argv`].
    fn create(&self, argv: &[String]) -> impl Future<Output = Result<(), EngineError>> + Send;
    /// Starts the created container, attached to its output.
    fn start_attached(&self, name: &str) -> Result<Attached, EngineError>;
    /// Sends `signal` to the container.
    fn kill(&self, name: &str, signal: StopSignal) -> impl Future<Output = Result<(), EngineError>> + Send;
    /// The container's state, if it still exists.
    fn inspect(&self, name: &str) -> impl Future<Output = Result<ContainerState, EngineError>> + Send;
    /// `podman rm -f`. A missing container is not an error.
    fn remove(&self, name: &str) -> impl Future<Output = Result<(), EngineError>> + Send;
    /// Every container with the `p2pc.lease` label, running or not.
    fn lease_containers(&self) -> impl Future<Output = Result<Vec<LeaseContainer>, EngineError>> + Send;
    /// Removes a job directory inside Podman's user namespace (`podman unshare rm -rf`). With rootless Podman, files
    /// that a non-root user in the container created belong to one of the agent's subordinate UIDs, which the agent
    /// itself may not delete.
    fn remove_tree(&self, path: &Path) -> impl Future<Output = Result<(), EngineError>> + Send;
}

/// The `podman` CLI (plus `skopeo`, when the node has it, to read remote manifests).
#[derive(Debug)]
pub struct PodmanEngine<R> {
    program: String,
    skopeo: String,
    runner: R,
    pull_runner: R,
    manifest_timeout: Duration,
    /// Podman's `--events-backend`, a global option that goes before the subcommand.
    events_backend: Option<String>,
}

/// The tool that reads a remote manifest (§9 "Images").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManifestTool {
    /// `skopeo inspect --raw docker://<ref>`: reads single-image and list manifests alike.
    Skopeo,
    /// `podman manifest inspect <ref>`: on Podman 4.9, only manifest lists (measured in T08 on the WSL2 node).
    Podman,
}

impl PodmanEngine<SystemRunner> {
    /// `podman` on `PATH`, with [`PODMAN_TIMEOUT`] and `pull_timeout`.
    #[must_use]
    ///
    /// Podman's events go to a file, not to the journal: on systemd hosts the default `events_logger` is
    /// `journald`, which would put one event per container step (and per image pull) in the host's system journal.
    pub fn system(program: impl Into<String>, pull_timeout: Duration) -> Self {
        Self::new(
            program,
            SystemRunner::with_timeout(PODMAN_TIMEOUT),
            SystemRunner::with_timeout(pull_timeout),
        )
        .with_events_backend(EVENTS_BACKEND)
    }
}

impl<R: CommandRunner> PodmanEngine<R> {
    /// `program` (normally `podman`), with `runner` for short commands and `pull_runner` for pulls.
    pub fn new(program: impl Into<String>, runner: R, pull_runner: R) -> Self {
        Self {
            program: program.into(),
            skopeo: "skopeo".into(),
            runner,
            pull_runner,
            manifest_timeout: MANIFEST_TIMEOUT,
            events_backend: None,
        }
    }

    /// Runs every `podman` command with `--events-backend=<backend>` (default: Podman's own configuration).
    #[must_use]
    pub fn with_events_backend(mut self, backend: impl Into<String>) -> Self {
        self.events_backend = Some(format!("--events-backend={}", backend.into()));
        self
    }

    /// The options that go before every `podman` subcommand.
    fn global_args(&self) -> Vec<&str> {
        self.events_backend.as_deref().into_iter().collect()
    }

    /// `args` with the global options in front.
    fn podman_args<'a>(&'a self, args: &[&'a str]) -> Vec<&'a str> {
        let mut all = self.global_args();
        all.extend_from_slice(args);
        all
    }

    /// Changes the timeout of one manifest read (default [`MANIFEST_TIMEOUT`]).
    #[must_use]
    pub fn with_manifest_timeout(mut self, timeout: Duration) -> Self {
        self.manifest_timeout = timeout;
        self
    }

    /// Uses `skopeo` at `program` (default: `skopeo` on `PATH`). A missing program just means "no skopeo".
    #[must_use]
    pub fn with_skopeo(mut self, program: impl Into<String>) -> Self {
        self.skopeo = program.into();
        self
    }

    async fn ok(&self, runner: &R, args: &[&str]) -> Result<CommandOutput, EngineError> {
        run_ok(runner, &self.program, "podman", &self.global_args(), args).await
    }

    /// Reads the raw manifest of `reference` with `tool`, within [`MANIFEST_TIMEOUT`] (not the pull timeout).
    async fn read_manifest(&self, tool: ManifestTool, reference: &str) -> Result<String, EngineError> {
        let read = async {
            match tool {
                ManifestTool::Skopeo => {
                    let transport = format!("docker://{reference}");
                    run_ok(
                        &self.pull_runner,
                        &self.skopeo,
                        "skopeo",
                        &[],
                        &["inspect", "--raw", "--", &transport],
                    )
                    .await
                }
                ManifestTool::Podman => {
                    self.ok(&self.pull_runner, &["manifest", "inspect", "--", reference])
                        .await
                }
            }
        };
        // Dropping the read kills the child (`kill_on_drop` in the system runner).
        match tokio::time::timeout(self.manifest_timeout, read).await {
            Ok(out) => Ok(out?.stdout),
            Err(_) => Err(EngineError::timed_out(format!(
                "{}: timed out after {} s reading the manifest",
                match tool {
                    ManifestTool::Skopeo => "skopeo inspect",
                    ManifestTool::Podman => "podman manifest inspect",
                },
                self.manifest_timeout.as_secs()
            ))),
        }
    }

    /// The layer and config sizes of `image` for this platform, read with `tool`; a manifest list or OCI index is
    /// followed to this platform's manifest by digest.
    async fn manifest_size_with(&self, tool: ManifestTool, image: &str) -> Result<u64, EngineError> {
        let label = match tool {
            ManifestTool::Skopeo => "skopeo inspect",
            ManifestTool::Podman => "podman manifest inspect",
        };
        let unexpected = || EngineError::new(format!("{label}: unexpected output"));
        let name =
            p2pc_proto::validate::ImageRef::parse(image).map_err(|e| EngineError::new(format!("{label}: {e}")))?;
        // skopeo needs the fully qualified name; podman is given the reference exactly as the job wrote it.
        // With a digest, both tools are asked about `registry/repository@digest`: the digest is what identifies the
        // image, and a tag next to it (`name:tag@sha256:…`) is read differently by each tool and registry.
        let reference = match (name.digest(), tool) {
            (Some(digest), _) => format!("{}/{}@{digest}", name.registry(), name.repository()),
            (None, ManifestTool::Skopeo) => name.to_string(),
            (None, ManifestTool::Podman) => image.to_string(),
        };
        match parse_manifest(&self.read_manifest(tool, &reference).await?, oci_arch()).ok_or_else(unexpected)? {
            Manifest::Image(size) => Ok(size),
            Manifest::List(None) => Err(EngineError::new(format!(
                "{label}: no linux/{} image in the list",
                oci_arch()
            ))),
            Manifest::List(Some(digest)) => {
                let by_digest = format!("{}/{}@{digest}", name.registry(), name.repository());
                match parse_manifest(&self.read_manifest(tool, &by_digest).await?, oci_arch()).ok_or_else(unexpected)? {
                    Manifest::Image(size) => Ok(size),
                    Manifest::List(_) => Err(unexpected()),
                }
            }
        }
    }
}

/// Runs `program args…` and requires exit 0; errors are labelled `label <first arg>`.
async fn run_ok<R: CommandRunner>(
    runner: &R,
    program: &str,
    label: &str,
    global: &[&str],
    args: &[&str],
) -> Result<CommandOutput, EngineError> {
    let verb = args.first().copied().unwrap_or("");
    let all: Vec<&str> = global.iter().chain(args).copied().collect();
    let out = runner
        .run(program, &all)
        .await
        .map_err(|e| describe_run(&format!("{label} {verb}"), &e))?;
    if out.success() {
        Ok(out)
    } else {
        Err(EngineError::new(format!(
            "{label} {verb} exited with {}: {}",
            out.code.map_or_else(|| "a signal".to_string(), |c| c.to_string()),
            out.first_line()
        )))
    }
}

fn describe(args: &[&str], e: &RunError) -> EngineError {
    describe_run(&format!("podman {}", args.first().copied().unwrap_or("")), e)
}

/// `what: why`, a timeout marked as such.
fn describe_run(what: &str, e: &RunError) -> EngineError {
    let msg = format!("{what}: {e}");
    if matches!(e, RunError::TimedOut(_)) {
        EngineError::timed_out(msg)
    } else {
        EngineError::new(msg)
    }
}

/// Parses `podman container inspect --size` output (a JSON array with one object).
#[must_use]
pub fn parse_inspect(json: &str) -> Option<ContainerState> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let c = v.as_array()?.first()?;
    Some(ContainerState {
        oom_killed: c
            .pointer("/State/OOMKilled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        size_rw: c.get("SizeRw").and_then(serde_json::Value::as_u64),
        started: c
            .pointer("/State/StartedAt")
            .and_then(serde_json::Value::as_str)
            .map(|t| !t.is_empty() && !t.starts_with("0001-01-01")),
    })
}

/// What `podman manifest inspect` printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Manifest {
    /// An image manifest: the sum of its layer and config sizes, in bytes.
    Image(u64),
    /// A manifest list or OCI index: the digest of this node's platform's manifest, if listed.
    List(Option<String>),
}

/// This node's OCI architecture name.
#[must_use]
pub fn oci_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Parses `podman manifest inspect` output (Docker schema 2 or OCI) for `linux/<arch>`.
#[must_use]
pub fn parse_manifest(json: &str, arch: &str) -> Option<Manifest> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    if let Some(layers) = v.get("layers").and_then(serde_json::Value::as_array) {
        let mut total = v
            .pointer("/config/size")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        for layer in layers {
            // A layer without a size cannot be bounded: refuse to guess.
            total = total.checked_add(layer.get("size")?.as_u64()?)?;
        }
        return Some(Manifest::Image(total));
    }
    let list = v.get("manifests")?.as_array()?;
    let digest = list.iter().find_map(|m| {
        let os = m.pointer("/platform/os")?.as_str()?;
        let a = m.pointer("/platform/architecture")?.as_str()?;
        (os == "linux" && a == arch)
            .then(|| m.get("digest")?.as_str().map(String::from))
            .flatten()
    });
    Some(Manifest::List(digest))
}

/// Parses `podman ps --all --format json` output into the lease containers.
#[must_use]
pub fn parse_ps(json: &str) -> Option<Vec<LeaseContainer>> {
    let v: serde_json::Value = serde_json::from_str(json.trim()).ok()?;
    let rows = match &v {
        serde_json::Value::Null => return Some(Vec::new()),
        serde_json::Value::Array(rows) => rows,
        _ => return None,
    };
    Some(
        rows.iter()
            .filter_map(|row| {
                let lease = row.get("Labels")?.get(LEASE_LABEL)?;
                let name = row.get("Names")?.as_array()?.first()?.as_str()?;
                Some(LeaseContainer {
                    name: name.to_string(),
                    lease: lease.as_str()?.to_string(),
                })
            })
            .collect(),
    )
}

impl<R: CommandRunner + 'static> Engine for PodmanEngine<R> {
    async fn pull(&self, image: &str) -> Result<(), EngineError> {
        self.ok(&self.pull_runner, &["pull", "--quiet", "--", image])
            .await
            .map(|_| ())
    }

    async fn image_size(&self, image: &str) -> Result<u64, EngineError> {
        let out = self
            .ok(
                &self.runner,
                &["image", "inspect", "--format", "{{.Size}}", "--", image],
            )
            .await?;
        out.stdout
            .trim()
            .parse()
            .map_err(|_| EngineError::new("podman image inspect: no size".into()))
    }

    async fn image_exists(&self, image: &str) -> Result<bool, EngineError> {
        let args = ["image", "exists", "--", image];
        match self.runner.run(&self.program, &self.podman_args(&args)).await {
            Ok(out) if out.code == Some(0) => Ok(true),
            Ok(out) if out.code == Some(1) => Ok(false),
            Ok(out) => Err(EngineError::new(format!("podman image exists: {}", out.first_line()))),
            Err(e) => Err(describe(&args, &e)),
        }
    }

    /// §9 "Images": `skopeo inspect --raw` first (it reads every manifest kind), then `podman manifest inspect`
    /// (Podman 4.9 reads only lists). If neither answers, the error names both; the driver then pulls and checks.
    async fn manifest_size(&self, image: &str) -> Result<u64, EngineError> {
        let skopeo = match self.manifest_size_with(ManifestTool::Skopeo, image).await {
            Ok(size) => return Ok(size),
            Err(e) => e,
        };
        self.manifest_size_with(ManifestTool::Podman, image)
            .await
            .map_err(|podman| EngineError::new(format!("{skopeo}; {podman}")))
    }

    async fn remove_image(&self, image: &str) -> Result<(), EngineError> {
        self.ok(&self.runner, &["rmi", "--ignore", "--", image])
            .await
            .map(|_| ())
    }

    async fn create(&self, argv: &[String]) -> Result<(), EngineError> {
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        self.ok(&self.runner, &args).await.map(|_| ())
    }

    fn start_attached(&self, name: &str) -> Result<Attached, EngineError> {
        // `runner::command`: no host proxy variables reach Podman (§9).
        let mut child = crate::runner::command(&self.program, &self.podman_args(&["start", "--attach", "--", name]))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Dropping the handle only detaches; the container is still removed by the cleanup guard.
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| EngineError::new(format!("podman start: {e}")))?;
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            return Err(EngineError::new("podman start: no output pipes".into()));
        };
        let exit = Box::pin(async move {
            let status = child
                .wait()
                .await
                .map_err(|e| EngineError::new(format!("podman start: {e}")))?;
            use std::os::unix::process::ExitStatusExt;
            Ok(status.code().or_else(|| status.signal().map(|s| 128 + s)).unwrap_or(1))
        });
        Ok(Attached {
            stdout: Box::pin(stdout),
            stderr: Box::pin(stderr),
            exit,
        })
    }

    async fn kill(&self, name: &str, signal: StopSignal) -> Result<(), EngineError> {
        let sig = format!("--signal={}", signal.name());
        self.ok(&self.runner, &["kill", &sig, "--", name]).await.map(|_| ())
    }

    async fn inspect(&self, name: &str) -> Result<ContainerState, EngineError> {
        let out = self
            .ok(&self.runner, &["container", "inspect", "--size", "--", name])
            .await?;
        parse_inspect(&out.stdout).ok_or_else(|| EngineError::new("podman container inspect: unexpected output".into()))
    }

    async fn remove(&self, name: &str) -> Result<(), EngineError> {
        self.ok(&self.runner, &["rm", "--force", "--ignore", "--time=0", "--", name])
            .await
            .map(|_| ())
    }

    async fn lease_containers(&self) -> Result<Vec<LeaseContainer>, EngineError> {
        let filter = format!("label={LEASE_LABEL}");
        let out = self
            .ok(&self.runner, &["ps", "--all", "--filter", &filter, "--format", "json"])
            .await?;
        parse_ps(&out.stdout).ok_or_else(|| EngineError::new("podman ps: unexpected output".into()))
    }

    async fn remove_tree(&self, path: &Path) -> Result<(), EngineError> {
        let path = path
            .to_str()
            .filter(|p| p.starts_with('/'))
            .ok_or_else(|| EngineError::new("podman unshare: the path must be absolute UTF-8".into()))?;
        // `rm -rf` never follows symlinks; `--` keeps the path from being read as an option.
        self.ok(&self.runner, &["unshare", "rm", "-rf", "--", path])
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::FakeRunner;

    fn engine(r: FakeRunner) -> PodmanEngine<FakeRunner> {
        PodmanEngine::new("podman", r, FakeRunner::new())
    }

    #[test]
    fn parses_inspect() {
        let j = r#"[{"Id":"abc","SizeRw":1048576,
            "State":{"Status":"running","OOMKilled":true,"StartedAt":"2026-11-05T15:00:00.1Z"}}]"#;
        assert_eq!(
            parse_inspect(j),
            Some(ContainerState {
                oom_killed: true,
                size_rw: Some(1_048_576),
                started: Some(true),
            })
        );
        // Created but never started (a failed `podman start`): Go's zero time.
        let j = r#"[{"State":{"Status":"created","StartedAt":"0001-01-01T00:00:00Z","Error":"crun: CDI"}}]"#;
        assert_eq!(parse_inspect(j).unwrap().started, Some(false));
        assert_eq!(parse_inspect(r#"[{"State":{}}]"#), Some(ContainerState::default()));
        assert_eq!(parse_inspect("[]"), None);
        assert_eq!(parse_inspect("nope"), None);
    }

    #[test]
    fn parses_ps() {
        let j = r#"[
          {"Names":["p2pc-lse_01ARZ3NDEKTSV4RRFFQ69G5FAV"],"Labels":{"p2pc.lease":"lse_01ARZ3NDEKTSV4RRFFQ69G5FAV"}},
          {"Names":["unrelated"],"Labels":null},
          {"Names":["p2pc-x"],"Labels":{"p2pc.lease":"lse_x"}}
        ]"#;
        let got = parse_ps(j).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "p2pc-lse_01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(got[1].lease, "lse_x");
        assert_eq!(parse_ps("null"), Some(Vec::new()));
        assert_eq!(parse_ps("[]\n"), Some(Vec::new()));
        assert_eq!(parse_ps("{}"), None);
    }

    #[tokio::test]
    async fn every_command_is_an_argv_with_double_dash_before_names() {
        let r = FakeRunner::new()
            .ok(&["podman", "kill", "--signal=TERM", "--", "p2pc-l"], "")
            .ok(&["podman", "kill", "--signal=KILL", "--", "p2pc-l"], "")
            .ok(&["podman", "rm", "--force", "--ignore", "--time=0", "--", "p2pc-l"], "")
            .ok(
                &[
                    "podman",
                    "image",
                    "inspect",
                    "--format",
                    "{{.Size}}",
                    "--",
                    "docker.io/x:1",
                ],
                "123\n",
            )
            .ok(
                &["podman", "container", "inspect", "--size", "--", "p2pc-l"],
                r#"[{"SizeRw":5,"State":{"OOMKilled":false}}]"#,
            )
            .ok(
                &[
                    "podman",
                    "ps",
                    "--all",
                    "--filter",
                    "label=p2pc.lease",
                    "--format",
                    "json",
                ],
                "[]",
            )
            .ok(
                &["podman", "unshare", "rm", "-rf", "--", "/var/lib/p2pc/jobs/lse_x"],
                "",
            )
            .exits(&["podman", "create", "--rm"], 125, "", "Error: bad flag\n");
        let e = engine(r);
        e.kill("p2pc-l", StopSignal::Term).await.unwrap();
        e.kill("p2pc-l", StopSignal::Kill).await.unwrap();
        e.remove("p2pc-l").await.unwrap();
        assert_eq!(e.image_size("docker.io/x:1").await.unwrap(), 123);
        assert_eq!(e.inspect("p2pc-l").await.unwrap().size_rw, Some(5));
        assert!(e.lease_containers().await.unwrap().is_empty());
        e.remove_tree(Path::new("/var/lib/p2pc/jobs/lse_x")).await.unwrap();
        assert!(e.remove_tree(Path::new("relative")).await.is_err());
        let err = e.create(&["create".into(), "--rm".into()]).await.unwrap_err();
        assert_eq!(err.msg, "podman create exited with 125: Error: bad flag");
    }

    const IMAGE_MANIFEST: &str = r#"{"schemaVersion":2,"config":{"size":1500,"digest":"sha256:c"},
        "layers":[{"size":3000000,"digest":"sha256:a"},{"size":2000000,"digest":"sha256:b"}]}"#;

    fn list(digest_amd64: &str) -> String {
        format!(
            r#"{{"schemaVersion":2,"manifests":[
              {{"digest":"sha256:arm","platform":{{"os":"linux","architecture":"arm64"}}}},
              {{"digest":"{digest_amd64}","platform":{{"os":"linux","architecture":"amd64"}}}},
              {{"digest":"sha256:win","platform":{{"os":"windows","architecture":"amd64"}}}}]}}"#
        )
    }

    #[test]
    fn parses_manifests_and_lists() {
        assert_eq!(
            parse_manifest(IMAGE_MANIFEST, "amd64"),
            Some(Manifest::Image(5_001_500))
        );
        let d = format!("sha256:{}", "0".repeat(64));
        assert_eq!(
            parse_manifest(&list(&d), "amd64"),
            Some(Manifest::List(Some(d.clone())))
        );
        assert_eq!(
            parse_manifest(&list(&d), "arm64"),
            Some(Manifest::List(Some("sha256:arm".into())))
        );
        assert_eq!(parse_manifest(&list(&d), "riscv64"), Some(Manifest::List(None)));
        // A layer without a size cannot be bounded.
        assert_eq!(parse_manifest(r#"{"layers":[{"digest":"sha256:a"}]}"#, "amd64"), None);
        assert_eq!(parse_manifest("not json", "amd64"), None);
        assert_eq!(parse_manifest("{}", "amd64"), None);
    }

    const IMAGE: &str = "docker.io/library/python:3.12-slim";

    /// A manifest list whose entry for this node's platform is `digest`.
    fn list_for_this_platform(digest: &str) -> String {
        let json = list(digest);
        if oci_arch() == "amd64" {
            json
        } else {
            json.replace("sha256:arm", digest)
        }
    }

    fn programs(r: &FakeRunner) -> Vec<String> {
        r.calls().into_iter().map(|c| c[0].clone()).collect()
    }

    /// The skopeo path: one `skopeo inspect --raw` of a single-image OCI manifest (which Podman 4.9 cannot read),
    /// and Podman is never asked.
    #[tokio::test]
    async fn skopeo_reads_a_single_image_manifest() {
        let pull = FakeRunner::new().ok(
            &["skopeo", "inspect", "--raw", "--", &format!("docker://{IMAGE}")],
            IMAGE_MANIFEST,
        );
        let e = PodmanEngine::new("podman", FakeRunner::new(), pull);
        assert_eq!(e.manifest_size(IMAGE).await.unwrap(), 5_001_500);
        assert_eq!(programs(&e.pull_runner), ["skopeo"]);
        // A short name is qualified for skopeo.
        let pull = FakeRunner::new().ok(
            &[
                "skopeo",
                "inspect",
                "--raw",
                "--",
                "docker://docker.io/library/busybox:1.36.1",
            ],
            IMAGE_MANIFEST,
        );
        let e = PodmanEngine::new("podman", FakeRunner::new(), pull);
        assert_eq!(e.manifest_size("busybox:1.36.1").await.unwrap(), 5_001_500);
    }

    /// The manifest-list path, with skopeo: the list, then this platform's manifest by digest.
    #[tokio::test]
    async fn skopeo_follows_a_manifest_list_to_this_platform() {
        let d = format!("sha256:{}", "1".repeat(64));
        let pull = FakeRunner::new()
            .ok(
                &["skopeo", "inspect", "--raw", "--", &format!("docker://{IMAGE}")],
                &list_for_this_platform(&d),
            )
            .ok(
                &[
                    "skopeo",
                    "inspect",
                    "--raw",
                    "--",
                    &format!("docker://docker.io/library/python@{d}"),
                ],
                IMAGE_MANIFEST,
            );
        let e = PodmanEngine::new("podman", FakeRunner::new(), pull);
        assert_eq!(e.manifest_size(IMAGE).await.unwrap(), 5_001_500);
        assert_eq!(programs(&e.pull_runner), ["skopeo", "skopeo"]);
    }

    /// A reference with both a tag and a digest (`name:tag@sha256:...`): the digest is what the pull verifies, and
    /// registries and tools disagree about a tag next to it. Both tools are asked about `registry/repository@digest`.
    #[tokio::test]
    async fn a_tag_and_a_digest_inspect_the_digest_form() {
        let d = format!("sha256:{}", "2".repeat(64));
        let with_both = format!("docker.io/library/python:3.12-slim@{d}");
        let by_digest = format!("docker.io/library/python@{d}");
        // skopeo
        let pull = FakeRunner::new().ok(
            &["skopeo", "inspect", "--raw", "--", &format!("docker://{by_digest}")],
            IMAGE_MANIFEST,
        );
        let e = PodmanEngine::new("podman", FakeRunner::new(), pull);
        assert_eq!(e.manifest_size(&with_both).await.unwrap(), 5_001_500);
        // podman, when skopeo is missing; a short name is qualified too
        let pull = FakeRunner::new().ok(&["podman", "manifest", "inspect", "--", &by_digest], IMAGE_MANIFEST);
        let e = PodmanEngine::new("podman", FakeRunner::new(), pull);
        assert_eq!(
            e.manifest_size(&format!("python:3.12-slim@{d}")).await.unwrap(),
            5_001_500
        );
        assert_eq!(e.pull_runner.calls().last().unwrap().last(), Some(&by_digest));
        // Without a digest nothing changes: skopeo gets the qualified name, podman the reference as written.
        let tag_only = FakeRunner::new().ok(
            &["skopeo", "inspect", "--raw", "--", &format!("docker://{IMAGE}")],
            IMAGE_MANIFEST,
        );
        let e = PodmanEngine::new("podman", FakeRunner::new(), tag_only);
        assert_eq!(e.manifest_size(IMAGE).await.unwrap(), 5_001_500);
    }

    /// No skopeo on the node: `podman manifest inspect`, which on Podman 4.9 only reads lists.
    #[tokio::test]
    async fn without_skopeo_podman_reads_a_manifest_list() {
        let d = format!("sha256:{}", "1".repeat(64));
        let pull = FakeRunner::new()
            .ok(
                &["podman", "manifest", "inspect", "--", IMAGE],
                &list_for_this_platform(&d),
            )
            .ok(
                &[
                    "podman",
                    "manifest",
                    "inspect",
                    "--",
                    &format!("docker.io/library/python@{d}"),
                ],
                IMAGE_MANIFEST,
            );
        let e = PodmanEngine::new("podman", FakeRunner::new(), pull);
        assert_eq!(e.manifest_size(IMAGE).await.unwrap(), 5_001_500);
        assert_eq!(
            programs(&e.pull_runner),
            ["skopeo", "podman", "podman"],
            "skopeo was tried first"
        );
    }

    /// Neither tool can read it (no skopeo, and Podman 4.9 on a single OCI manifest): an error naming both, never
    /// a size. The driver then pulls and checks (`an_unreadable_manifest_falls_back_to_the_size_after_the_pull`).
    #[tokio::test]
    async fn neither_tool_reads_it() {
        let pull = FakeRunner::new()
            .exits(
                &["skopeo", "inspect", "--raw", "--", &format!("docker://{IMAGE}")],
                1,
                "",
                "FATA[0000] Error reading manifest: unauthorized\n",
            )
            .exits(
                &["podman", "manifest", "inspect", "--", IMAGE],
                125,
                "",
                "Error: parsing manifest blob: unsupported format \"application/vnd.oci.image.manifest.v1+json\"\n",
            );
        let e = PodmanEngine::new("podman", FakeRunner::new(), pull);
        let err = e.manifest_size(IMAGE).await.unwrap_err();
        assert!(err.msg.contains("skopeo inspect exited with 1"), "{err}");
        assert!(err.msg.contains("podman manifest exited with 125"), "{err}");
        // A missing skopeo and an unreachable registry: an error too.
        let e = PodmanEngine::new("podman", FakeRunner::new(), FakeRunner::new());
        assert!(e.manifest_size(IMAGE).await.is_err());
        // A configured skopeo path is used.
        let pull = FakeRunner::new().ok(
            &["/opt/skopeo", "inspect", "--raw", "--", &format!("docker://{IMAGE}")],
            IMAGE_MANIFEST,
        );
        let e = PodmanEngine::new("podman", FakeRunner::new(), pull).with_skopeo("/opt/skopeo");
        assert_eq!(e.manifest_size(IMAGE).await.unwrap(), 5_001_500);
    }

    /// A registry that does not answer must not hold the lease for the pull timeout (15 min): a manifest read has
    /// its own short timeout, and the next tool is tried.
    #[tokio::test(start_paused = true)]
    async fn a_manifest_read_has_its_own_short_timeout() {
        let by_skopeo = ["skopeo", "inspect", "--raw", "--", &format!("docker://{IMAGE}")];
        let by_podman = ["podman", "manifest", "inspect", "--", IMAGE];
        let pull = FakeRunner::new().hang(&by_skopeo).hang(&by_podman);
        let e = PodmanEngine::new("podman", FakeRunner::new(), pull);
        let started = tokio::time::Instant::now();
        let err = e.manifest_size(IMAGE).await.unwrap_err();
        assert!(err.msg.contains("timed out"), "{err}");
        assert_eq!(
            started.elapsed(),
            MANIFEST_TIMEOUT * 2,
            "30 s for each of the two tools, not 15 min"
        );
        // skopeo hangs, podman answers: the second tool still gets its chance.
        let pull = FakeRunner::new()
            .hang(&by_skopeo)
            .ok(&by_podman, &list_for_this_platform("sha256:x"))
            .ok(
                &[
                    "podman",
                    "manifest",
                    "inspect",
                    "--",
                    "docker.io/library/python@sha256:x",
                ],
                IMAGE_MANIFEST,
            );
        let e = PodmanEngine::new("podman", FakeRunner::new(), pull).with_manifest_timeout(Duration::from_secs(3));
        let started = tokio::time::Instant::now();
        assert_eq!(e.manifest_size(IMAGE).await.unwrap(), 5_001_500);
        assert_eq!(started.elapsed(), Duration::from_secs(3));
    }

    #[tokio::test]
    async fn image_exists_and_rmi() {
        let r = FakeRunner::new()
            .exits(&["podman", "image", "exists", "--", "docker.io/a:1"], 0, "", "")
            .exits(&["podman", "image", "exists", "--", "docker.io/b:1"], 1, "", "")
            .exits(
                &["podman", "image", "exists", "--", "docker.io/c:1"],
                125,
                "",
                "Error: storage\n",
            )
            .ok(&["podman", "rmi", "--ignore", "--", "docker.io/b:1"], "");
        let e = engine(r);
        assert!(e.image_exists("docker.io/a:1").await.unwrap());
        assert!(!e.image_exists("docker.io/b:1").await.unwrap());
        assert!(e.image_exists("docker.io/c:1").await.is_err());
        e.remove_image("docker.io/b:1").await.unwrap();
    }

    /// T10m: Podman's events logger is `journald` on systemd hosts, which writes one event per container step into
    /// the system journal. The agent's own Podman is told to use a file instead, on every command it runs.
    #[tokio::test]
    async fn every_podman_command_names_the_events_backend() {
        let flag = "--events-backend=file";
        let short = FakeRunner::new()
            .ok(&["podman", flag, "kill", "--signal=TERM", "--", "p2pc-l"], "")
            .exits(&["podman", flag, "image", "exists", "--", "docker.io/a:1"], 0, "", "")
            .ok(
                &["podman", flag, "unshare", "rm", "-rf", "--", "/var/lib/p2pc/jobs/lse_x"],
                "",
            )
            .ok(&["podman", flag, "create", "--rm"], "");
        let pull = FakeRunner::new().ok(&["podman", flag, "pull", "--quiet", "--", "docker.io/a:1"], "");
        let e = PodmanEngine::new("podman", short, pull).with_events_backend("file");
        e.kill("p2pc-l", StopSignal::Term).await.unwrap();
        assert!(e.image_exists("docker.io/a:1").await.unwrap());
        e.remove_tree(Path::new("/var/lib/p2pc/jobs/lse_x")).await.unwrap();
        e.create(&["create".into(), "--rm".into()]).await.unwrap();
        e.pull("docker.io/a:1").await.unwrap();
        // A failure is still labelled by the Podman verb, not by the global flag.
        let err = e.remove("p2pc-l").await.unwrap_err();
        assert!(err.msg.starts_with("podman rm: "), "{err}");
        let calls: Vec<_> = [e.runner.calls(), e.pull_runner.calls()].concat();
        assert_eq!(calls.len(), 6);
        assert!(calls.iter().all(|c| c[..2] == ["podman", flag]), "{calls:?}");
    }

    #[tokio::test]
    async fn a_command_that_times_out_says_so() {
        let r = FakeRunner::new().error(
            &["podman", "pull", "--quiet", "--", "docker.io/a:1"],
            RunError::TimedOut(Duration::from_secs(900)),
        );
        let e = PodmanEngine::new("podman", FakeRunner::new(), r);
        let err = e.pull("docker.io/a:1").await.unwrap_err();
        assert!(err.is_timeout(), "{err}");
        // Text from Podman or a registry never decides it, only how the command ended.
        let text = "Error: registry.example.invalid: timed out after 5 s";
        let r = FakeRunner::new().exits(&["podman", "pull", "--quiet", "--", "docker.io/a:1"], 125, "", text);
        let err = PodmanEngine::new("podman", FakeRunner::new(), r)
            .pull("docker.io/a:1")
            .await
            .unwrap_err();
        assert!(err.msg.contains("timed out after") && !err.is_timeout(), "{err}");
        assert!(!EngineError::new("timed out after 1 s".into()).is_timeout());
    }

    #[test]
    fn the_system_engine_keeps_podman_events_out_of_the_journal() {
        let e = PodmanEngine::system("podman", Duration::from_secs(1));
        assert_eq!(e.global_args(), ["--events-backend=file"]);
        assert_eq!(engine(FakeRunner::new()).global_args(), Vec::<&str>::new());
    }

    #[tokio::test]
    async fn pulls_use_their_own_runner() {
        let pull = FakeRunner::new().ok(&["podman", "pull", "--quiet", "--", "docker.io/x:1"], "sha256:00\n");
        let e = PodmanEngine::new("podman", FakeRunner::new(), pull);
        e.pull("docker.io/x:1").await.unwrap();
        let missing = engine(FakeRunner::new()).pull("docker.io/x:1").await.unwrap_err();
        assert!(missing.msg.contains("not found"), "{missing}");
    }
}
