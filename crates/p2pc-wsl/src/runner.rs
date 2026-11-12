// SPDX-License-Identifier: Apache-2.0

//! Running Windows programs behind a small trait.
//!
//! Every call this crate makes to `wsl.exe`, `schtasks.exe` or PowerShell is an [`Invocation`] handed to a
//! [`CommandRunner`]. [`SystemRunner`] starts the real process; the tests use a fake runner, so every behaviour is
//! tested on any OS without a real Windows call. [`Host`] bundles a runner with a [`Pause`] (the retry delay, also
//! faked in tests) and adds the `wsl.exe` rules of `install.ps1`:
//!
//! - **The WSL service timeout.** Under load `wsl.exe` fails with `Wsl/Service/0x8007274c` before anything runs in the
//!   distro. Only that error is retried, up to [`WSL_RETRY_COUNT`] times, [`WSL_RETRY_DELAY`] apart: the command never
//!   reached the distro, so running it again is safe (`Invoke-WithWslRetry`).
//! - **wsl.exe's own messages are UTF-16LE**; the Linux commands' output is plain text. [`decode_text`] reads both and
//!   strips NULs and the BOM, as `Invoke-WslOnce` does.
//! - **No secret on a command line** (a command line is visible to every program on the PC): an invocation whose
//!   arguments or environment values look like a join token or an API key is refused before anything starts
//!   ([`RunError::SecretInArguments`]). Secrets go on stdin ([`Invocation::stdin`]), which is wiped when dropped and
//!   never shown by `Debug`.
//! - **Byte-exact files.** Large binary data (the state archive of an upgrade, H2 §8.3; a template bundle, §14.1) goes
//!   through files: [`Invocation::stdin_file`] streams a file to the child's stdin and [`Invocation::stdout_file`]
//!   streams the child's stdout to a file, raw bytes, never decoded and never capped. This is what `install.ps1` had
//!   to work around with `cmd.exe` redirections and .NET streams, because PowerShell 5.1 re-encodes piped bytes.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::DISTRO_NAME;

/// `wsl.exe`.
pub const WSL_EXE: &str = "wsl.exe";
/// `schtasks.exe`.
pub const SCHTASKS_EXE: &str = "schtasks.exe";
/// Windows PowerShell 5.1 (`powershell.exe`), present on every Windows 11.
pub const POWERSHELL_EXE: &str = "powershell.exe";

/// How many times a `wsl.exe` call that hit the WSL service timeout is run again (`$WslRetryCount`).
pub const WSL_RETRY_COUNT: u32 = 3;
/// The pause before each of those retries (`$WslRetryDelaySeconds`).
pub const WSL_RETRY_DELAY: Duration = Duration::from_secs(5);
/// The error code `wsl.exe` prints on a WSL service timeout (matched case-insensitively, `Test-WslServiceTimeout`).
pub const WSL_SERVICE_TIMEOUT: &str = "0x8007274c";

/// The most of each output stream a run keeps (the rest is read and dropped, so a chatty child never blocks).
pub const MAX_CAPTURED_BYTES: usize = 1 << 20;

/// Prefixes of P2PC secrets that must never be on a command line: join tokens and API keys (`p2pc-proto`).
const SECRET_PREFIXES: [&str; 2] = ["p2pc_join_", "p2pc_sk_"];

/// One program to run: its name, its argument vector (never a shell string), extra environment variables, optional
/// bytes for its stdin and an optional time limit.
#[derive(Clone, PartialEq, Eq)]
pub struct Invocation {
    program: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    stdin: Option<Zeroizing<Vec<u8>>>,
    stdin_file: Option<PathBuf>,
    stdout_file: Option<PathBuf>,
    timeout: Option<Duration>,
}

impl Invocation {
    /// A program with no arguments.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            stdin: None,
            stdin_file: None,
            stdout_file: None,
            timeout: None,
        }
    }

    /// Adds one argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Adds arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Sets an environment variable for the child (added to the inherited environment).
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Bytes written to the child's stdin, then EOF. They are wiped when the invocation is dropped and never shown.
    pub fn stdin(mut self, bytes: Vec<u8>) -> Self {
        self.stdin = Some(Zeroizing::new(bytes));
        self.stdin_file = None;
        self
    }

    /// A file whose bytes are streamed, unchanged, to the child's stdin, then EOF. Replaces [`Invocation::stdin`].
    pub fn stdin_file(mut self, path: impl AsRef<Path>) -> Self {
        self.stdin_file = Some(path.as_ref().to_owned());
        self.stdin = None;
        self
    }

    /// A file the child's stdout is streamed to, unchanged and uncapped (created or truncated). [`Output::stdout`] is
    /// then empty.
    pub fn stdout_file(mut self, path: impl AsRef<Path>) -> Self {
        self.stdout_file = Some(path.as_ref().to_owned());
        self
    }

    /// A time limit: the child is killed when it runs longer ([`RunError::TimedOut`]).
    pub fn timeout(mut self, limit: Duration) -> Self {
        self.timeout = Some(limit);
        self
    }

    /// The program.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// The arguments.
    pub fn arguments(&self) -> &[String] {
        &self.args
    }

    /// The extra environment variables.
    pub fn environment(&self) -> &[(String, String)] {
        &self.env
    }

    /// The stdin bytes, if any.
    pub fn stdin_bytes(&self) -> Option<&[u8]> {
        self.stdin.as_ref().map(|b| b.as_slice())
    }

    /// The file streamed to stdin, if any.
    pub fn stdin_path(&self) -> Option<&Path> {
        self.stdin_file.as_deref()
    }

    /// The file stdout is streamed to, if any.
    pub fn stdout_path(&self) -> Option<&Path> {
        self.stdout_file.as_deref()
    }

    /// The time limit, if any.
    pub fn time_limit(&self) -> Option<Duration> {
        self.timeout
    }

    /// Refuses an invocation that carries something that looks like a secret in an argument or an environment value
    /// (`Test-TokenLikeParameters`, extended to API keys). The value is never shown.
    pub fn check_no_secret(&self) -> Result<(), RunError> {
        let values = self.args.iter().chain(self.env.iter().map(|(_, v)| v));
        for v in values {
            if SECRET_PREFIXES.iter().any(|p| v.contains(p)) {
                return Err(RunError::SecretInArguments {
                    program: self.program.clone(),
                });
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Invocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The arguments are shown (they never hold a secret: check_no_secret), the environment by name only, stdin by
        // its length only.
        f.debug_struct("Invocation")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env", &self.env.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>())
            .field("stdin", &self.stdin.as_ref().map(|b| format!("<{} bytes>", b.len())))
            .field("stdin_file", &self.stdin_file)
            .field("stdout_file", &self.stdout_file)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// What a finished run produced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Output {
    /// The exit code, or `None` when the process ended without one (killed by a signal on Unix).
    pub code: Option<i32>,
    /// Raw stdout (at most [`MAX_CAPTURED_BYTES`]).
    pub stdout: Vec<u8>,
    /// Raw stderr (at most [`MAX_CAPTURED_BYTES`]).
    pub stderr: Vec<u8>,
}

impl Output {
    /// An output with this exit code and this stdout text (handy for fakes).
    pub fn with(code: i32, stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            code: Some(code),
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    /// Exit code 0.
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// stdout as text ([`decode_text`]).
    pub fn stdout_text(&self) -> String {
        decode_text(&self.stdout)
    }

    /// stderr as text ([`decode_text`]).
    pub fn stderr_text(&self) -> String {
        decode_text(&self.stderr)
    }

    /// stdout and stderr as one text, as `install.ps1` reads a `wsl.exe` call (`2>&1`).
    pub fn text(&self) -> String {
        let (o, e) = (self.stdout_text(), self.stderr_text());
        match (o.is_empty(), e.is_empty()) {
            (_, true) => o,
            (true, false) => e,
            (false, false) => format!("{o}\n{e}"),
        }
    }
}

/// Why a program could not be run to its end.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    /// The program could not be started (`kind` is `NotFound` when it does not exist).
    #[error("{program} could not be started: {message}")]
    Spawn {
        program: String,
        kind: io::ErrorKind,
        message: String,
    },
    /// The program ran longer than its time limit and was killed.
    #[error("{program} did not finish within {} s and was stopped", limit.as_secs())]
    TimedOut { program: String, limit: Duration },
    /// Waiting for the program failed.
    #[error("{program}: {message}")]
    Wait { program: String, message: String },
    /// A file of [`Invocation::stdin_file`] or [`Invocation::stdout_file`] could not be opened, read or written.
    #[error("{program}: {message}")]
    File { program: String, message: String },
    /// An argument or an environment value looks like a secret: nothing was started (the value is not shown).
    #[error(
        "refused to run {program}: an argument looks like a secret (not shown); secrets go on stdin, never on a command line"
    )]
    SecretInArguments { program: String },
}

impl RunError {
    /// The program does not exist.
    pub fn is_not_found(&self) -> bool {
        matches!(self, RunError::Spawn { kind, .. } if *kind == io::ErrorKind::NotFound)
    }
}

/// Runs an [`Invocation`] to its end.
pub trait CommandRunner {
    /// Runs it and returns what it produced. A non-zero exit is an `Ok` output, not an error.
    fn run(&self, invocation: &Invocation) -> Result<Output, RunError>;
}

/// Waits between retries (and between boot-status polls). Faked in tests, so no test sleeps.
pub trait Pause {
    /// Waits this long.
    fn sleep(&self, duration: Duration);

    /// A monotonic clock (time since an arbitrary start), for deadlines: the wall clock can jump after the host slept.
    /// The fake advances it by the pauses it records.
    fn now(&self) -> Duration {
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed()
    }
}

/// The real [`Pause`]: `std::thread::sleep`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadPause;

impl Pause for ThreadPause {
    fn sleep(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

/// The real [`CommandRunner`]: starts the process with [`std::process::Command`] (an argument vector, never a shell),
/// no console window on Windows, and Windows' own programs taken from `%SystemRoot%\System32` (not from `PATH`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

#[cfg(windows)]
fn resolve_program(program: &str) -> std::path::PathBuf {
    use std::path::PathBuf;
    let Some(root) = std::env::var_os("SystemRoot").filter(|r| !r.is_empty()) else {
        return PathBuf::from(program);
    };
    let system32 = PathBuf::from(root).join("System32");
    match program {
        WSL_EXE | SCHTASKS_EXE => system32.join(program),
        POWERSHELL_EXE => system32.join("WindowsPowerShell").join("v1.0").join(program),
        _ => PathBuf::from(program),
    }
}

#[cfg(not(windows))]
fn resolve_program(program: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(program)
}

/// Reads a stream to its end, keeping at most [`MAX_CAPTURED_BYTES`].
fn drain<R: Read + Send + 'static>(stream: Option<R>) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut kept = Vec::new();
        let Some(mut s) = stream else {
            return kept;
        };
        let mut buf = [0u8; 8192];
        loop {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = MAX_CAPTURED_BYTES.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
        kept
    })
}

impl CommandRunner for SystemRunner {
    fn run(&self, inv: &Invocation) -> Result<Output, RunError> {
        inv.check_no_secret()?;
        let program = inv.program.clone();
        let file_err = |what: &str, path: &Path, e: io::Error| RunError::File {
            program: program.clone(),
            message: format!("{what} {}: {e}", path.display()),
        };
        // Both files are opened before the child starts: a missing input starts nothing.
        let stdin_file = match &inv.stdin_file {
            Some(p) => Some(File::open(p).map_err(|e| file_err("cannot read", p, e))?),
            None => None,
        };
        let stdout_file = match &inv.stdout_file {
            Some(p) => Some(File::create(p).map_err(|e| file_err("cannot write", p, e))?),
            None => None,
        };
        let mut cmd = Command::new(resolve_program(&inv.program));
        cmd.args(&inv.args)
            .stdin(if inv.stdin.is_some() || stdin_file.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in &inv.env {
            cmd.env(k, v);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // CREATE_NO_WINDOW: the app is a GUI process; no console window flashes for wsl.exe or schtasks.
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        tracing::debug!(invocation = ?inv, "running");
        let mut child = cmd.spawn().map_err(|e| RunError::Spawn {
            program: program.clone(),
            kind: e.kind(),
            message: e.to_string(),
        })?;
        let (out, to_file) = match stdout_file {
            Some(file) => (None, Some(copy_to_file(child.stdout.take(), file))),
            None => (Some(drain(child.stdout.take())), None),
        };
        let err = drain(child.stderr.take());
        let feeder = match (child.stdin.take(), &inv.stdin, stdin_file) {
            (Some(mut pipe), Some(bytes), _) => {
                let bytes = bytes.clone();
                // A child that never reads its stdin must not block us: the write runs on its own thread, and
                // dropping the pipe is the child's EOF.
                Some(thread::spawn(move || {
                    let _ = pipe.write_all(&bytes);
                }))
            }
            (Some(mut pipe), None, Some(mut file)) => Some(thread::spawn(move || {
                // Raw bytes from the file to the pipe; a child that stops reading ends the copy with an error.
                let _ = io::copy(&mut file, &mut pipe);
            })),
            _ => None,
        };
        let status = match inv.timeout {
            None => child.wait().map_err(|e| RunError::Wait {
                program: program.clone(),
                message: e.to_string(),
            })?,
            Some(limit) => {
                let deadline = Instant::now() + limit;
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => break status,
                        Ok(None) if Instant::now() >= deadline => {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Err(RunError::TimedOut { program, limit });
                        }
                        // Polling a child with a deadline: std has no wait-with-timeout. Not a test synchronisation.
                        Ok(None) => thread::sleep(Duration::from_millis(20)),
                        Err(e) => {
                            return Err(RunError::Wait {
                                program,
                                message: e.to_string(),
                            });
                        }
                    }
                }
            }
        };
        if let Some(f) = feeder {
            let _ = f.join();
        }
        let stdout = out.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
        let stderr = err.join().unwrap_or_default();
        if let (Some(handle), Some(path)) = (to_file, &inv.stdout_file) {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(file_err("cannot write", path, e)),
                Err(_) => {
                    return Err(file_err(
                        "cannot write",
                        path,
                        io::Error::other("the copy thread panicked"),
                    ));
                }
            }
        }
        Ok(Output {
            code: status.code(),
            stdout,
            stderr,
        })
    }
}

/// Streams a child's stdout to a file, uncapped, and flushes it to disk.
fn copy_to_file<R: Read + Send + 'static>(stream: Option<R>, mut file: File) -> thread::JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        if let Some(mut s) = stream {
            io::copy(&mut s, &mut file)?;
        }
        file.sync_all()
    })
}

/// Decodes the output of a Windows program: UTF-16LE when it looks like it (a BOM, or NULs in the odd bytes, which is
/// how `wsl.exe` writes its own messages), UTF-8 otherwise; then strips NULs and BOMs and trims (`Invoke-WslOnce`).
pub fn decode_text(bytes: &[u8]) -> String {
    let utf16 = if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        Some(rest)
    } else if bytes.len() >= 2 {
        let pairs = bytes.len() / 2;
        let odd_nuls = bytes.as_chunks::<2>().0.iter().filter(|c| c[1] == 0).count();
        (odd_nuls * 2 > pairs).then_some(bytes)
    } else {
        None
    };
    let text = match utf16 {
        Some(b) => {
            let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            String::from_utf16_lossy(&units)
        }
        None => String::from_utf8_lossy(bytes).into_owned(),
    };
    text.replace(['\0', '\u{FEFF}'], "").trim().to_owned()
}

/// The output of a `wsl.exe` call names the WSL service timeout (`Test-WslServiceTimeout`).
pub fn is_wsl_service_timeout(text: &str) -> bool {
    text.to_ascii_lowercase().contains(WSL_SERVICE_TIMEOUT)
}

/// The time limit of a PowerShell script: a broken WMI repository can make a CIM query hang, and setup must not.
pub const POWERSHELL_TIMEOUT: Duration = Duration::from_secs(120);
/// The time limit of a `schtasks` call.
pub const SCHTASKS_TIMEOUT: Duration = Duration::from_secs(60);

/// A PowerShell invocation running a fixed script: `-EncodedCommand` (base64 of UTF-16LE), so the script never goes
/// through command-line quoting, and no profile, no prompt, [`POWERSHELL_TIMEOUT`]. Values reach the script only
/// through environment variables ([`Invocation::env`]), never by being pasted into it.
pub fn powershell(script: &str) -> Invocation {
    Invocation::new(POWERSHELL_EXE)
        .args([
            "-NoLogo".to_owned(),
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-EncodedCommand".to_owned(),
            encode_powershell(script),
        ])
        .timeout(POWERSHELL_TIMEOUT)
}

/// A `schtasks.exe` invocation with [`SCHTASKS_TIMEOUT`].
pub fn schtasks<I, S>(args: I) -> Invocation
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Invocation::new(SCHTASKS_EXE).args(args).timeout(SCHTASKS_TIMEOUT)
}

/// Base64 of the UTF-16LE bytes of a script, the form `-EncodedCommand` takes.
pub fn encode_powershell(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    data_encoding::BASE64.encode(&bytes)
}

/// A runner and a pause: the handle every operation of this crate takes.
#[derive(Clone, Copy)]
pub struct Host<'a> {
    runner: &'a dyn CommandRunner,
    pause: &'a dyn Pause,
}

impl fmt::Debug for Host<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Host").finish_non_exhaustive()
    }
}

impl<'a> Host<'a> {
    /// A host over this runner and pause.
    pub fn new(runner: &'a dyn CommandRunner, pause: &'a dyn Pause) -> Self {
        Self { runner, pause }
    }

    /// The pause (also used for polling, never for test synchronisation).
    pub fn pause(&self) -> &'a dyn Pause {
        self.pause
    }

    /// Runs an invocation once.
    pub fn run(&self, inv: &Invocation) -> Result<Output, RunError> {
        self.runner.run(inv)
    }

    /// Runs a `wsl.exe` invocation, and runs it again while it fails with the WSL service timeout
    /// (`Invoke-WithWslRetry`): at most [`WSL_RETRY_COUNT`] retries, [`WSL_RETRY_DELAY`] apart. Any other failure, and
    /// success, is returned as it is.
    pub fn run_wsl(&self, inv: &Invocation) -> Result<Output, RunError> {
        let mut out = self.runner.run(inv)?;
        for retry in 1..=WSL_RETRY_COUNT {
            if out.success() || !is_wsl_service_timeout(&out.text()) {
                return Ok(out);
            }
            tracing::warn!(
                retry,
                of = WSL_RETRY_COUNT,
                "wsl.exe failed with Wsl/Service/0x8007274c (a WSL service timeout); retrying in {} s",
                WSL_RETRY_DELAY.as_secs()
            );
            self.pause.sleep(WSL_RETRY_DELAY);
            out = self.runner.run(inv)?;
        }
        Ok(out)
    }

    /// `wsl.exe <args>` with the retry.
    pub fn wsl<I, S>(&self, args: I) -> Result<Output, RunError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.run_wsl(&Invocation::new(WSL_EXE).args(args))
    }

    /// A command inside the distro, as root, without a shell (`Invoke-InDistro`), with the retry.
    pub fn in_distro(&self, command: &[&str]) -> Result<Output, RunError> {
        self.run_wsl(&in_distro(command))
    }
}

/// `wsl.exe -d p2pc-node -u root --exec <command>`.
pub fn in_distro(command: &[&str]) -> Invocation {
    Invocation::new(WSL_EXE)
        .args(["-d", DISTRO_NAME, "-u", "root", "--exec"])
        .args(command.iter().copied())
}

#[cfg(test)]
pub(crate) mod fake {
    //! A fake [`CommandRunner`] and [`Pause`] for the tests: canned outputs chosen by a matcher, every call recorded.

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::Duration;

    use super::*;

    type Matcher = Box<dyn Fn(&Invocation) -> bool>;
    type Handler = Box<dyn Fn(&Invocation) -> Result<Output, RunError>>;

    struct Rule {
        matcher: Matcher,
        replies: VecDeque<Result<Output, RunError>>,
        handler: Option<Handler>,
    }

    /// Answers each invocation with the first rule that matches it. A rule's replies are used in order and its last
    /// one repeats. An invocation no rule matches gets exit 127 and "fake: no rule". Every invocation is recorded, and
    /// one carrying something that looks like a secret makes the test fail.
    #[derive(Default)]
    pub(crate) struct FakeRunner {
        rules: RefCell<Vec<Rule>>,
        calls: RefCell<Vec<Invocation>>,
    }

    impl FakeRunner {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        pub(crate) fn on(&self, matcher: impl Fn(&Invocation) -> bool + 'static, reply: Output) -> &Self {
            self.on_seq(matcher, vec![Ok(reply)])
        }

        pub(crate) fn on_seq(
            &self,
            matcher: impl Fn(&Invocation) -> bool + 'static,
            replies: Vec<Result<Output, RunError>>,
        ) -> &Self {
            assert!(!replies.is_empty());
            self.rules.borrow_mut().push(Rule {
                matcher: Box::new(matcher),
                replies: replies.into(),
                handler: None,
            });
            self
        }

        /// A rule whose reply is computed (and which may read `stdin_file` or write `stdout_file`, as a real child
        /// would).
        pub(crate) fn on_fn(
            &self,
            matcher: impl Fn(&Invocation) -> bool + 'static,
            handler: impl Fn(&Invocation) -> Result<Output, RunError> + 'static,
        ) -> &Self {
            self.rules.borrow_mut().push(Rule {
                matcher: Box::new(matcher),
                replies: VecDeque::new(),
                handler: Some(Box::new(handler)),
            });
            self
        }

        pub(crate) fn calls(&self) -> Vec<Invocation> {
            self.calls.borrow().clone()
        }

        pub(crate) fn count(&self, matcher: impl Fn(&Invocation) -> bool) -> usize {
            self.calls.borrow().iter().filter(|i| matcher(i)).count()
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, inv: &Invocation) -> Result<Output, RunError> {
            assert_eq!(
                inv.check_no_secret(),
                Ok(()),
                "a secret-looking value on a command line"
            );
            self.calls.borrow_mut().push(inv.clone());
            let mut rules = self.rules.borrow_mut();
            for rule in rules.iter_mut() {
                if (rule.matcher)(inv) {
                    if let Some(handler) = &rule.handler {
                        return handler(inv);
                    }
                    return if rule.replies.len() > 1 {
                        rule.replies.pop_front().unwrap_or_else(|| Ok(Output::default()))
                    } else {
                        rule.replies[0].clone()
                    };
                }
            }
            Ok(Output {
                code: Some(127),
                stdout: Vec::new(),
                stderr: b"fake: no rule".to_vec(),
            })
        }
    }

    /// Records the pauses instead of sleeping; its clock moves only by them.
    #[derive(Default)]
    pub(crate) struct FakePause {
        slept: RefCell<Vec<Duration>>,
    }

    impl FakePause {
        pub(crate) fn slept(&self) -> Vec<Duration> {
            self.slept.borrow().clone()
        }
    }

    impl Pause for FakePause {
        fn sleep(&self, duration: Duration) {
            self.slept.borrow_mut().push(duration);
        }

        fn now(&self) -> Duration {
            self.slept.borrow().iter().sum()
        }
    }

    /// The invocation runs `program` with exactly these leading arguments.
    pub(crate) fn starts(inv: &Invocation, program: &str, prefix: &[&str]) -> bool {
        inv.program() == program
            && inv.arguments().len() >= prefix.len()
            && inv.arguments().iter().zip(prefix).all(|(a, p)| a == p)
    }

    /// The invocation runs exactly this command inside the distro.
    pub(crate) fn in_distro_is(inv: &Invocation, command: &[&str]) -> bool {
        inv.program() == WSL_EXE
            && inv.arguments().len() == 5 + command.len()
            && starts(inv, WSL_EXE, &["-d", DISTRO_NAME, "-u", "root", "--exec"])
            && inv.arguments()[5..].iter().zip(command).all(|(a, c)| a == c)
    }

    /// The invocation is PowerShell running this script.
    pub(crate) fn runs_script(inv: &Invocation, script: &str) -> bool {
        inv.program() == POWERSHELL_EXE
            && inv.arguments().last().map(String::as_str) == Some(&encode_powershell(script))
    }

    /// UTF-16LE bytes, the way wsl.exe writes its own messages.
    pub(crate) fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::fake::*;
    use super::*;

    fn timeout_reply() -> Output {
        Output {
            code: Some(-1),
            stdout: utf16("Error code: Wsl/Service/0x8007274c\r\n"),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn a_wsl_service_timeout_is_retried_three_times_five_seconds_apart() {
        let runner = FakeRunner::new();
        runner.on(|i| starts(i, WSL_EXE, &["--version"]), timeout_reply());
        let pause = FakePause::default();
        let out = Host::new(&runner, &pause).wsl(["--version"]).unwrap();
        assert!(!out.success());
        assert_eq!(runner.calls().len(), 4, "one try plus three retries");
        assert_eq!(pause.slept(), vec![WSL_RETRY_DELAY; 3]);
        assert_eq!(WSL_RETRY_DELAY, Duration::from_secs(5));
    }

    #[test]
    fn the_retry_stops_at_the_first_answer_that_is_not_the_timeout() {
        let runner = FakeRunner::new();
        runner.on_seq(
            |i| starts(i, WSL_EXE, &["--list"]),
            vec![Ok(timeout_reply()), Ok(Output::with(0, "p2pc-node\n"))],
        );
        let pause = FakePause::default();
        let out = Host::new(&runner, &pause).wsl(["--list", "--quiet"]).unwrap();
        assert!(out.success());
        assert_eq!(runner.calls().len(), 2);
        assert_eq!(pause.slept().len(), 1);
    }

    #[test]
    fn other_failures_are_never_retried() {
        let runner = FakeRunner::new();
        runner.on(
            |i| starts(i, WSL_EXE, &["--import"]),
            Output::with(1, utf16("The distribution already exists. 0x8000000d")),
        );
        let pause = FakePause::default();
        let out = Host::new(&runner, &pause).wsl(["--import"]).unwrap();
        assert_eq!(out.code, Some(1));
        assert_eq!(runner.calls().len(), 1);
        assert!(pause.slept().is_empty());
    }

    #[test]
    fn the_timeout_is_matched_in_any_case_and_on_stderr() {
        assert!(is_wsl_service_timeout("wsl/service/0X8007274C"));
        let out = Output {
            code: Some(1),
            stdout: Vec::new(),
            stderr: utf16("Wsl/Service/0x8007274c"),
        };
        assert!(is_wsl_service_timeout(&out.text()));
        assert!(!is_wsl_service_timeout("Wsl/Service/0x80070005"));
    }

    #[test]
    fn wsl_messages_in_utf16_and_linux_output_in_utf8_both_decode() {
        assert_eq!(
            decode_text(&utf16("\u{FEFF}WSL version: 2.3.26.0\r\n")),
            "WSL version: 2.3.26.0"
        );
        let mut bom = vec![0xFF, 0xFE];
        bom.extend(utf16("Versión de WSL: 2.0.9.0"));
        assert_eq!(decode_text(&bom), "Versión de WSL: 2.0.9.0");
        assert_eq!(decode_text(b"700\n"), "700");
        assert_eq!(decode_text("caf\u{e9}\n".as_bytes()), "caf\u{e9}");
        assert_eq!(decode_text(b""), "");
    }

    #[test]
    fn a_secret_on_a_command_line_is_refused_before_anything_starts() {
        let token = "p2pc_join_example.invalid_fake"; // gitleaks:allow
        let inv = Invocation::new("definitely-not-a-program-p2pc").arg(token);
        let err = SystemRunner.run(&inv).unwrap_err();
        assert_eq!(
            err,
            RunError::SecretInArguments {
                program: "definitely-not-a-program-p2pc".into()
            }
        );
        assert!(!err.to_string().contains(token));
        let key = "p2pc_sk_fakefakefake"; // gitleaks:allow
        let inv = Invocation::new("x").env("P2PC_KEY", key);
        assert!(inv.check_no_secret().is_err());
        // On stdin it is fine, and Debug does not show it.
        let inv = Invocation::new("x").stdin(token.as_bytes().to_vec());
        assert_eq!(inv.check_no_secret(), Ok(()));
        let shown = format!("{inv:?}");
        assert!(!shown.contains(token), "{shown}");
        assert!(shown.contains("<30 bytes>"), "{shown}");
    }

    #[test]
    fn powershell_scripts_are_encoded_not_quoted() {
        let inv = powershell("'a' + \"b\" | Out-Null");
        assert_eq!(inv.program(), POWERSHELL_EXE);
        assert_eq!(
            &inv.arguments()[..4],
            &["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand"]
        );
        // "ab" in UTF-16LE is 61 00 62 00.
        assert_eq!(encode_powershell("ab"), "YQBiAA==");
        // Bounded: a hung CIM query or schtasks never hangs setup.
        assert_eq!(inv.time_limit(), Some(POWERSHELL_TIMEOUT));
        assert_eq!(schtasks(["/Run"]).time_limit(), Some(SCHTASKS_TIMEOUT));
    }

    #[test]
    fn in_distro_runs_as_root_without_a_shell() {
        let inv = in_distro(&["/bin/cat", "/proc/1/stat"]);
        assert_eq!(inv.program(), WSL_EXE);
        assert_eq!(
            inv.arguments(),
            &["-d", "p2pc-node", "-u", "root", "--exec", "/bin/cat", "/proc/1/stat"]
        );
    }

    #[test]
    fn a_missing_program_is_reported_as_not_found() {
        let err = SystemRunner
            .run(&Invocation::new("definitely-not-a-program-p2pc"))
            .unwrap_err();
        assert!(err.is_not_found(), "{err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn the_system_runner_passes_args_env_and_stdin_and_reports_the_exit_code() {
        let inv = Invocation::new("/bin/sh")
            .args([
                "-c",
                "read line; printf '%s|%s|%s' \"$1\" \"$P2PC_TEST_VALUE\" \"$line\"; echo err >&2; exit 3",
                "sh",
                "a b",
            ])
            .env("P2PC_TEST_VALUE", "v")
            .stdin(b"from stdin\n".to_vec());
        let out = SystemRunner.run(&inv).unwrap();
        assert_eq!(out.code, Some(3));
        assert_eq!(out.stdout_text(), "a b|v|from stdin");
        assert_eq!(out.stderr_text(), "err");
    }

    #[cfg(unix)]
    #[test]
    fn file_pipes_are_byte_exact_and_not_capped() {
        // Every byte value, CRLFs and NULs included, and more than the capture cap: the state archive of an upgrade
        // (H2 §8.3) and a template bundle (§14.1) go through these pipes and must arrive unchanged.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.bin");
        let dst = dir.path().join("out.bin");
        let mut bytes: Vec<u8> = (0..=255u8).cycle().take(MAX_CAPTURED_BYTES + 4099).collect();
        bytes.extend_from_slice(b"\r\n\0\xff\xfe");
        std::fs::write(&src, &bytes).unwrap();
        let inv = Invocation::new("/bin/cat").stdin_file(&src).stdout_file(&dst);
        let out = SystemRunner.run(&inv).unwrap();
        assert!(out.success());
        assert!(out.stdout.is_empty(), "stdout went to the file");
        assert_eq!(std::fs::read(&dst).unwrap(), bytes);
        let shown = format!("{inv:?}");
        assert!(shown.contains("in.bin") && shown.contains("out.bin"), "{shown}");
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_stdin_file_is_an_error_before_anything_starts() {
        let dir = tempfile::tempdir().unwrap();
        let inv = Invocation::new("/bin/cat").stdin_file(dir.path().join("missing"));
        let err = SystemRunner.run(&inv).unwrap_err();
        assert!(matches!(err, RunError::File { .. }), "{err:?}");
    }

    #[test]
    fn stdin_bytes_and_a_stdin_file_replace_each_other() {
        let inv = Invocation::new("x").stdin(b"a".to_vec()).stdin_file("f");
        assert_eq!(inv.stdin_bytes(), None);
        assert_eq!(inv.stdin_path(), Some(std::path::Path::new("f")));
        let inv = inv.stdin(b"b".to_vec());
        assert_eq!(inv.stdin_path(), None);
        assert_eq!(inv.stdin_bytes(), Some(&b"b"[..]));
    }

    #[test]
    fn the_fake_pause_is_a_monotonic_clock() {
        let pause = FakePause::default();
        let t0 = pause.now();
        pause.sleep(Duration::from_secs(2));
        assert_eq!(pause.now() - t0, Duration::from_secs(2));
        let real = ThreadPause;
        assert!(real.now() <= real.now());
    }

    #[cfg(unix)]
    #[test]
    fn the_system_runner_stops_a_child_at_its_time_limit() {
        let inv = Invocation::new("/bin/sh")
            .args(["-c", "exec sleep 30"])
            .timeout(Duration::from_millis(100));
        let err = SystemRunner.run(&inv).unwrap_err();
        assert!(matches!(err, RunError::TimedOut { .. }), "{err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn the_system_runner_keeps_at_most_the_cap_of_a_chatty_child() {
        let inv = Invocation::new("/bin/sh").args(["-c", "head -c 3000000 /dev/zero | tr '\\0' 'a'"]);
        let out = SystemRunner.run(&inv).unwrap();
        assert!(out.success());
        assert_eq!(out.stdout.len(), MAX_CAPTURED_BYTES);
    }
}
