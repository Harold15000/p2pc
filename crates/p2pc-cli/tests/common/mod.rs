// SPDX-License-Identifier: Apache-2.0

//! Shared harness: runs the whole CLI in process against a mock server, with a temporary configuration directory
//! and no real terminal.

#![allow(dead_code, reason = "each test file uses a different part of the harness")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Cursor;
use std::path::PathBuf;

use p2pc_cli::app::{self, Host, Interrupt, TunnelSettings};
use p2pc_client::RetryPolicy;
use p2pc_client::testing::{MockServer, MockTunnelServer};
use p2pc_proto::auth::ApiKey;
use p2pc_proto::net::DirectAddresses;
use time::OffsetDateTime;

/// What one run of the CLI produced.
#[derive(Debug)]
pub struct Out {
    pub code: u8,
    pub stdout: String,
    pub stderr: String,
}

/// A temporary configuration directory, an optional server and key, and how the "terminal" behaves.
pub struct Cli {
    pub dir: tempfile::TempDir,
    pub env: HashMap<String, String>,
    pub stdin: String,
    pub tty: bool,
    /// Whether stdout and stderr are terminals (job output is then shown with its control characters escaped).
    pub out_tty: bool,
    pub interrupt: bool,
    /// Every write to stdout fails with this kind of error (`BrokenPipe`: `p2pc run … | head -1` after `head` has left).
    pub failing_stdout: Option<std::io::ErrorKind>,
    /// Every write to stderr fails with this kind of error (`2>&-`, a closed terminal).
    pub failing_stderr: Option<std::io::ErrorKind>,
    /// stderr is not an open file descriptor (`2>&-`): every write fails with `EBADF`.
    pub invalid_stderr: bool,
    /// Ctrl-C arrives once this is notified (from a mock server's handler, for example).
    pub interrupt_on: Option<std::sync::Arc<tokio::sync::Notify>>,
    pub key: ApiKey,
    pub tunnel: TunnelSettings,
}

impl Cli {
    /// No server, no key: a first run.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = HashMap::new();
        env.insert("P2PC_CONFIG_DIR".to_string(), dir.path().display().to_string());
        Self {
            dir,
            env,
            stdin: String::new(),
            tty: false,
            out_tty: false,
            interrupt: false,
            failing_stdout: None,
            failing_stderr: None,
            invalid_stderr: false,
            interrupt_on: None,
            key: ApiKey::generate(),
            tunnel: TunnelSettings::default(),
        }
    }

    /// Points `P2PC_SERVER` at the mock server and sets `P2PC_API_KEY`.
    pub fn with_server(mut self, server: &MockServer) -> Self {
        self.env.insert("P2PC_SERVER".into(), server.url());
        self.env.insert("P2PC_API_KEY".into(), self.key.expose());
        self
    }

    /// Points `P2PC_SERVER` at the fake tunnel server's address `p2pc_srv_…`, sets `P2PC_API_KEY`, and binds the
    /// tunnel to loopback with the server's sockets as hints (there is no relay in tests).
    pub fn with_tunnel_server(mut self, server: &MockTunnelServer) -> Self {
        self = self.with_tunnel_hints(server);
        self.env.insert("P2PC_SERVER".into(), server.address_text());
        self.env.insert("P2PC_API_KEY".into(), self.key.expose());
        self
    }

    /// Only the tunnel settings for `server`: loopback binding and its sockets as hints.
    pub fn with_tunnel_hints(mut self, server: &MockTunnelServer) -> Self {
        self.tunnel = loopback_tunnel(server);
        self
    }

    pub fn with_stdin(mut self, text: &str) -> Self {
        self.stdin = text.to_string();
        self
    }

    pub fn with_tty(mut self) -> Self {
        self.tty = true;
        self
    }

    /// stdout and stderr are terminals.
    pub fn with_terminal_output(mut self) -> Self {
        self.out_tty = true;
        self
    }

    pub fn with_env(mut self, name: &str, value: &str) -> Self {
        self.env.insert(name.into(), value.into());
        self
    }

    pub fn without_env(mut self, name: &str) -> Self {
        self.env.remove(name);
        self
    }

    pub fn interrupted(mut self) -> Self {
        self.interrupt = true;
        self
    }

    /// stdout is a pipe whose reader has gone: every write to it fails with `BrokenPipe`.
    pub fn with_closed_stdout(self) -> Self {
        self.with_failing_stdout(std::io::ErrorKind::BrokenPipe)
    }

    /// stderr whose every write fails with an error of this kind (`BrokenPipe` for a closed one).
    pub fn with_failing_stderr(mut self, kind: std::io::ErrorKind) -> Self {
        self.failing_stderr = Some(kind);
        self
    }

    /// stderr closed with `2>&-`: every write fails with `EBADF`, an error that has no `ErrorKind` of its own.
    pub fn with_invalid_stderr(mut self) -> Self {
        self.invalid_stderr = true;
        self
    }

    /// stdout whose every write fails with an error of this kind (a full disk, for example).
    pub fn with_failing_stdout(mut self, kind: std::io::ErrorKind) -> Self {
        self.failing_stdout = Some(kind);
        self
    }

    /// Ctrl-C arrives when `signal` is notified.
    pub fn interrupted_on(mut self, signal: std::sync::Arc<tokio::sync::Notify>) -> Self {
        self.interrupt_on = Some(signal);
        self
    }

    pub fn config_dir(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }

    /// Runs `p2pc <args>`.
    pub fn run(&self, args: &[&str]) -> Out {
        let argv: Vec<OsString> = std::iter::once("p2pc")
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect();
        let mut stdout = Vec::new();
        let mut failing_err = FailingStdout(if self.invalid_stderr {
            Failure::BadFd
        } else {
            Failure::Kind(self.failing_stderr.unwrap_or(std::io::ErrorKind::BrokenPipe))
        });
        let mut failing = FailingStdout(Failure::Kind(
            self.failing_stdout.unwrap_or(std::io::ErrorKind::BrokenPipe),
        ));
        let mut stderr = Vec::new();
        let mut stdin = Cursor::new(self.stdin.clone().into_bytes());
        let env = |name: &str| self.env.get(name).cloned();
        let prompt = |_: &str| Ok(String::new());
        let interrupt: Option<Interrupt<'_>> = match &self.interrupt_on {
            Some(signal) => {
                let signal = signal.clone();
                Some(Box::pin(async move { signal.notified().await }) as Interrupt<'_>)
            }
            None => self
                .interrupt
                .then(|| Box::pin(std::future::ready(())) as Interrupt<'_>),
        };
        let code = {
            let mut host = Host {
                env: &env,
                out: if self.failing_stdout.is_some() {
                    &mut failing
                } else {
                    &mut stdout
                },
                err: if self.failing_stderr.is_some() || self.invalid_stderr {
                    &mut failing_err
                } else {
                    &mut stderr
                },
                stdin: &mut stdin,
                stdin_is_tty: self.tty,
                stdout_is_tty: self.out_tty,
                stderr_is_tty: self.out_tty,
                prompt_secret: &prompt,
                interrupt,
                terminate: None,
                // A real clock has sub-second precision: the server refuses fractional timestamps (real-run bug).
                now: OffsetDateTime::from_unix_timestamp_nanos(1_700_000_100_123_456_789).expect("timestamp"),
                // No waiting between retries: the tests would otherwise sleep.
                retry: RetryPolicy::immediate(3),
                tunnel: self.tunnel.clone(),
            };
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(app::run(&argv, &mut host))
        };
        Out {
            code,
            stdout: String::from_utf8(stdout).expect("utf-8 stdout"),
            stderr: String::from_utf8(stderr).expect("utf-8 stderr"),
        }
    }
}

/// Tunnel settings for the fake tunnel server: the client binds loopback only and knows the server's sockets.
pub fn loopback_tunnel(server: &MockTunnelServer) -> TunnelSettings {
    TunnelSettings {
        bind: DirectAddresses::Cidrs(vec!["127.0.0.0/8".parse().unwrap()]),
        server_addrs: server.addrs(),
        connect_timeout: None,
    }
}

/// How a writer fails.
#[derive(Clone, Copy)]
enum Failure {
    Kind(std::io::ErrorKind),
    /// `EBADF`: the descriptor is not open.
    BadFd,
}

impl Failure {
    fn error(self) -> std::io::Error {
        match self {
            Failure::Kind(kind) => kind.into(),
            Failure::BadFd => std::io::Error::from_raw_os_error(9),
        }
    }
}

/// A stream whose every write fails.
struct FailingStdout(Failure);

impl std::io::Write for FailingStdout {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(self.0.error())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(self.0.error())
    }
}
