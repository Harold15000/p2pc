// SPDX-License-Identifier: Apache-2.0

//! External commands, behind a trait so that tests never run real tools.
//!
//! Every command the agent runs goes through [`CommandRunner`]: a program and an **argv** (never a shell string),
//! with a timeout ([`COMMAND_TIMEOUT`], 5 s, in production). A missing program is [`RunError::NotFound`], which
//! callers report as "unavailable", not as an error. Tests use [`FakeRunner`] with recorded outputs.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::process::Stdio;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Timeout of each external command.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// Most bytes kept from each of stdout and stderr. A tool that writes more is stopped by the timeout.
pub const MAX_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;

/// What a finished command printed, and how it exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Exit code; `None` when a signal killed it.
    pub code: Option<i32>,
    /// Standard output, lossily decoded as UTF-8.
    pub stdout: String,
    /// Standard error, lossily decoded as UTF-8.
    pub stderr: String,
}

impl CommandOutput {
    /// Whether it exited with code 0.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// The first non-empty line of stderr, else of stdout: a short reason for a failure.
    #[must_use]
    pub fn first_line(&self) -> &str {
        self.stderr
            .lines()
            .chain(self.stdout.lines())
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("")
    }
}

/// Why a command could not produce an output.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    /// The program does not exist (not on `PATH`, or the absolute path is missing).
    #[error("not found")]
    NotFound,
    /// It did not finish in time and was killed.
    #[error("timed out after {} s", .0.as_secs())]
    TimedOut(Duration),
    /// Any other failure to start or wait for it.
    #[error("{0}")]
    Io(String),
}

/// Runs external programs. Implementations never go through a shell.
pub trait CommandRunner: Send + Sync {
    /// Runs `program` with `args`, with stdin closed, and waits for it within the runner's timeout.
    fn run(&self, program: &str, args: &[&str]) -> impl Future<Output = Result<CommandOutput, RunError>> + Send;
}

/// The real runner: `tokio::process`, a per-command timeout, and the child killed when the timeout fires.
#[derive(Debug, Clone)]
pub struct SystemRunner {
    timeout: Duration,
}

impl SystemRunner {
    /// A runner with a custom timeout.
    #[must_use]
    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for SystemRunner {
    fn default() -> Self {
        Self::with_timeout(COMMAND_TIMEOUT)
    }
}

/// Proxy variables removed from the environment of every external command (spec §9 fixed arguments). They may hold
/// the owner's credentials, and Podman would otherwise copy them into containers. Pulls that need a proxy get it
/// from Podman's own configuration (`containers.conf`), never from the agent's environment.
pub const PROXY_ENV_VARS: [&str; 8] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "FTP_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "ftp_proxy",
    "no_proxy",
];

/// `program args…` with the environment every external command gets: `LC_ALL=C` (stable, parseable output
/// whatever the owner's locale is) and no proxy variables ([`PROXY_ENV_VARS`]). Never a shell.
#[must_use]
pub fn command(program: &str, args: &[&str]) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args).env("LC_ALL", "C");
    for var in PROXY_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd
}

async fn read_capped(pipe: Option<impl AsyncRead + Unpin>) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    if let Some(pipe) = pipe {
        pipe.take(MAX_OUTPUT_BYTES).read_to_end(&mut buf).await?;
    }
    Ok(buf)
}

impl CommandRunner for SystemRunner {
    async fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, RunError> {
        let mut child = command(program, args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => RunError::NotFound,
                _ => RunError::Io(e.to_string()),
            })?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let finished = tokio::time::timeout(self.timeout, async {
            tokio::try_join!(read_capped(stdout), read_capped(stderr), child.wait())
        })
        .await;
        match finished {
            Ok(Ok((out, err, status))) => Ok(CommandOutput {
                code: status.code(),
                stdout: String::from_utf8_lossy(&out).into_owned(),
                stderr: String::from_utf8_lossy(&err).into_owned(),
            }),
            Ok(Err(e)) => Err(RunError::Io(e.to_string())),
            Err(_) => {
                // `kill_on_drop` also covers this, but do not wait for the drop.
                let _ = child.start_kill();
                Err(RunError::TimedOut(self.timeout))
            }
        }
    }
}

/// A runner that replays recorded outputs, for tests. An argv it has no record for behaves like a missing program
/// ([`RunError::NotFound`]), so a test only lists the tools that exist on its fake machine.
#[derive(Debug, Default)]
pub struct FakeRunner {
    responses: HashMap<Vec<String>, Result<CommandOutput, RunError>>,
    hung: Vec<Vec<String>>,
    calls: Mutex<Vec<Vec<String>>>,
    /// How long every command takes before it answers (tokio time: virtual under a paused clock).
    latency: Duration,
}

fn argv(program: &str, args: &[&str]) -> Vec<String> {
    std::iter::once(program)
        .chain(args.iter().copied())
        .map(String::from)
        .collect()
}

impl FakeRunner {
    /// A runner on which no program exists.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `argv` (program first) exits 0 and prints `stdout`.
    #[must_use]
    pub fn ok(self, argv: &[&str], stdout: &str) -> Self {
        self.exits(argv, 0, stdout, "")
    }

    /// `argv` exits with `code`, printing `stdout` and `stderr`.
    #[must_use]
    pub fn exits(mut self, argv: &[&str], code: i32, stdout: &str, stderr: &str) -> Self {
        let output = CommandOutput {
            code: Some(code),
            stdout: stdout.into(),
            stderr: stderr.into(),
        };
        self.responses.insert(owned(argv), Ok(output));
        self
    }

    /// `argv` fails to run with `error`.
    #[must_use]
    pub fn error(mut self, argv: &[&str], error: RunError) -> Self {
        self.responses.insert(owned(argv), Err(error));
        self
    }

    /// `argv` never finishes (a hung tool), whatever the runner's own timeout: for testing the callers' deadlines.
    #[must_use]
    pub fn hang(mut self, argv: &[&str]) -> Self {
        self.hung.push(owned(argv));
        self
    }

    /// Every command takes `latency` (tokio time) before it answers, like real tools do: for testing that deadlines
    /// and waits overlap as they should.
    #[must_use]
    pub fn latency(mut self, latency: Duration) -> Self {
        self.latency = latency;
        self
    }

    /// Every argv run so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

fn owned(argv: &[&str]) -> Vec<String> {
    argv.iter().copied().map(String::from).collect()
}

impl CommandRunner for FakeRunner {
    async fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, RunError> {
        let key = argv(program, args);
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(key.clone());
        if self.hung.contains(&key) {
            std::future::pending::<()>().await;
        }
        if !self.latency.is_zero() {
            tokio::time::sleep(self.latency).await;
        }
        self.responses.get(&key).cloned().unwrap_or(Err(RunError::NotFound))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_runner_replays_and_records() {
        let runner = FakeRunner::new()
            .ok(&["podman", "version"], "4.9.3\n")
            .exits(&["nvidia-smi"], 9, "", "NVIDIA-SMI has failed\n")
            .error(&["slow"], RunError::TimedOut(COMMAND_TIMEOUT));
        let out = runner.run("podman", &["version"]).await.unwrap();
        assert!(out.success());
        assert_eq!(out.stdout, "4.9.3\n");
        let out = runner.run("nvidia-smi", &[]).await.unwrap();
        assert!(!out.success());
        assert_eq!(out.first_line(), "NVIDIA-SMI has failed");
        assert_eq!(runner.run("slow", &[]).await, Err(RunError::TimedOut(COMMAND_TIMEOUT)));
        assert_eq!(runner.run("missing", &["x"]).await, Err(RunError::NotFound));
        assert_eq!(runner.calls().len(), 4);
        assert_eq!(runner.calls()[3], vec!["missing".to_string(), "x".to_string()]);
    }

    // The tests below run tiny coreutils programs, never `nvidia-smi` or `podman`.

    /// Spec §9: the host's proxy variables may hold the owner's credentials; no external command gets them (Podman
    /// would copy them into containers).
    #[test]
    fn commands_never_inherit_proxy_variables() {
        let cmd = command("podman", &["info"]);
        let envs: Vec<(String, Option<String>)> = cmd
            .as_std()
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for var in PROXY_ENV_VARS {
            assert!(
                envs.contains(&(var.to_string(), None)),
                "{var} is not removed: {envs:?}"
            );
        }
        for upper in ["HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "NO_PROXY"] {
            assert!(PROXY_ENV_VARS.contains(&upper));
            assert!(PROXY_ENV_VARS.contains(&upper.to_lowercase().as_str()));
        }
        assert!(envs.contains(&("LC_ALL".to_string(), Some("C".to_string()))));
    }

    #[tokio::test]
    async fn system_runner_drops_proxy_variables_from_the_child() {
        // Whatever this test process has (build sandboxes often set a proxy), the child sees none of it.
        let out = SystemRunner::default().run("env", &[]).await.unwrap();
        for line in out.stdout.lines() {
            let name = line.split('=').next().unwrap_or("");
            assert!(!PROXY_ENV_VARS.contains(&name), "leaked {name}");
        }
    }

    #[tokio::test]
    async fn system_runner_passes_argv_verbatim_without_a_shell() {
        let out = SystemRunner::default()
            .run("echo", &["a;b", "$HOME", "`x`"])
            .await
            .unwrap();
        assert!(out.success());
        assert_eq!(out.stdout, "a;b $HOME `x`\n");
    }

    #[tokio::test]
    async fn system_runner_reports_missing_programs() {
        let missing = SystemRunner::default().run("p2pc-test-no-such-program", &[]).await;
        assert_eq!(missing, Err(RunError::NotFound));
        let missing = SystemRunner::default().run("/nonexistent.invalid/tool", &[]).await;
        assert_eq!(missing, Err(RunError::NotFound));
    }

    #[tokio::test]
    async fn system_runner_reports_exit_codes() {
        let out = SystemRunner::default().run("false", &[]).await.unwrap();
        assert_eq!(out.code, Some(1));
        assert!(!out.success());
    }

    #[tokio::test]
    async fn system_runner_kills_on_timeout() {
        // `sleep` is the program under test here, not a synchronization device: the runner must give up on it.
        let runner = SystemRunner::with_timeout(Duration::from_millis(200));
        let started = std::time::Instant::now();
        let out = runner.run("sleep", &["30"]).await;
        assert_eq!(out, Err(RunError::TimedOut(Duration::from_millis(200))));
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
