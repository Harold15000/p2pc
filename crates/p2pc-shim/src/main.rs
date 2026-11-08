// SPDX-License-Identifier: Apache-2.0

//! `p2pc-shim`: the static (musl) helper injected into every job sandbox as the container entrypoint (spec §9
//! "Shim").
//!
//! The agent always runs it as `/.p2pc/shim -- <user argv…>`. The shim parses only its own flags, and only before
//! the first `--`; everything after it is the job's argv, verbatim, so a job argv such as `--help` is never read by
//! the shim (T01 review). Without `--` it refuses to run.
//!
//! What it does, in order:
//! 1. **Egress bridge.** If `/.p2pc/egress.sock` exists (the agent's per-job proxy, T09), it listens on
//!    `127.0.0.1:3128` inside the container and copies each connection to and from the socket, one thread per
//!    direction. It then sets `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` and
//!    `NO_PROXY=localhost,127.0.0.1` for the child. With no socket file, nothing listens and no proxy is set.
//! 2. **PID 1 duties.** It becomes a child subreaper (a no-op as PID 1, where it already is the reaper), spawns
//!    the job's command, forwards SIGTERM, SIGINT and SIGHUP to it, and reaps every child that exits, including
//!    orphans re-parented to it.
//! 3. **Exit.** It exits with the child's code, or `128 + signal` if a signal killed it. Its own failures: 2 for
//!    usage errors, 126 if the command cannot be executed, 127 if it does not exist.

use std::ffi::OsString;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use rustix::process::{Pid, Signal, WaitOptions};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

/// Where the agent puts the egress proxy's socket (the job's `p2pc/` directory is mounted at `/.p2pc`).
const EGRESS_SOCKET: &str = "/.p2pc/egress.sock";
/// The bridge's listen address inside the container.
const LISTEN: &str = "127.0.0.1:3128";
/// The value of `NO_PROXY`.
const NO_PROXY: &str = "localhost,127.0.0.1";
/// Most bridged connections at once; more are closed at once. The proxy has its own, lower limits.
const MAX_CONNECTIONS: usize = 256;
/// Signals forwarded to the child.
const FORWARDED: [i32; 3] = [SIGTERM, SIGINT, SIGHUP];

/// Exit code for usage errors.
const EXIT_USAGE: u8 = 2;
/// Exit code when the command exists but cannot be executed (as in POSIX shells).
const EXIT_CANNOT_EXECUTE: u8 = 126;
/// Exit code when the command does not exist (as in POSIX shells).
const EXIT_NOT_FOUND: u8 = 127;

const USAGE: &str = "usage: p2pc-shim [--egress-socket <path>] [--listen <loopback addr>] -- <command> [args...]";

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    /// Print the version.
    Version,
    /// Print the help.
    Help,
    /// Run a job.
    Run(Run),
}

/// A job to run.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    egress_socket: PathBuf,
    listen: SocketAddr,
    argv: Vec<OsString>,
}

/// Parses the shim's own flags, up to the first `--`. Everything after it is the job's argv.
fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Invocation, String> {
    let mut egress_socket = PathBuf::from(EGRESS_SOCKET);
    let mut listen: SocketAddr = LISTEN.parse().map_err(|_| "bad built-in listen address".to_string())?;
    loop {
        let Some(arg) = args.next() else {
            return Err(format!("missing `--` before the command\n{USAGE}"));
        };
        match arg.to_str() {
            Some("--") => break,
            Some("--version") => return Ok(Invocation::Version),
            Some("--help" | "-h") => return Ok(Invocation::Help),
            Some("--egress-socket") => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("--egress-socket needs a value\n{USAGE}"))?;
                egress_socket = PathBuf::from(value);
            }
            Some("--listen") => {
                let value = args.next().ok_or_else(|| format!("--listen needs a value\n{USAGE}"))?;
                listen = value
                    .to_str()
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| format!("--listen: not an address\n{USAGE}"))?;
                if !listen.ip().is_loopback() {
                    return Err(format!("--listen must be a loopback address\n{USAGE}"));
                }
            }
            _ => {
                return Err(format!(
                    "unexpected argument {arg:?} (the command goes after `--`)\n{USAGE}"
                ));
            }
        }
    }
    let argv: Vec<OsString> = args.collect();
    if argv.is_empty() {
        return Err(format!("no command after `--`\n{USAGE}"));
    }
    Ok(Invocation::Run(Run {
        egress_socket,
        listen,
        argv,
    }))
}

/// A full-duplex byte stream that can be split into two handles and half-closed: a TCP or unix stream.
trait Duplex: io::Read + io::Write + Send + Sized + 'static {
    fn split(&self) -> io::Result<Self>;
    fn close_write(&self);
}

impl Duplex for TcpStream {
    fn split(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn close_write(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

impl Duplex for UnixStream {
    fn split(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn close_write(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

/// Copies `from` to `to` until EOF, then half-closes `to`, so that the peer sees the end of the request.
fn pump<A: Duplex, B: Duplex>(mut from: A, mut to: B) {
    let _ = io::copy(&mut from, &mut to);
    to.close_write();
}

/// Copies both directions between `client` and `upstream` until both are done.
fn bridge<A: Duplex, B: Duplex>(client: A, upstream: B) -> io::Result<()> {
    let (client_r, upstream_w) = (client.split()?, upstream.split()?);
    let up = thread::spawn(move || pump(client_r, upstream_w));
    pump(upstream, client);
    let _ = up.join();
    Ok(())
}

/// Starts the bridge on `listen` and returns the bound address.
fn start_bridge(listen: SocketAddr, socket: PathBuf) -> io::Result<SocketAddr> {
    // `listen` is checked to be a loopback address in `parse`: the bridge is only reachable inside the container.
    let listener = TcpListener::bind(listen)?;
    let bound = listener.local_addr()?;
    let active = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for conn in listener.incoming() {
            let tcp = match conn {
                Ok(tcp) => tcp,
                Err(_) => {
                    // For example EMFILE: back off instead of spinning.
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };
            if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                active.fetch_sub(1, Ordering::SeqCst);
                drop(tcp);
                continue;
            }
            let socket = socket.clone();
            let active = Arc::clone(&active);
            thread::spawn(move || {
                if let Ok(upstream) = UnixStream::connect(&socket) {
                    let _ = bridge(tcp, upstream);
                }
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Ok(bound)
}

/// The exit code for a wait status: the child's code, or `128 + signal`.
fn exit_code(exited: Option<i32>, killed_by: Option<i32>) -> u8 {
    let code = match (exited, killed_by) {
        (Some(code), _) => code,
        (None, Some(sig)) => 128 + sig,
        (None, None) => 1,
    };
    u8::try_from(code & 0xff).unwrap_or(1)
}

fn run(job: Run) -> ExitCode {
    // Register the handlers before the child exists, so that a signal that arrives in between is queued, not lost
    // (as PID 1, an unhandled SIGTERM would simply be ignored by the kernel).
    let mut signals = match Signals::new(FORWARDED) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("p2pc-shim: cannot install signal handlers: {e}");
            return ExitCode::from(1);
        }
    };
    // Orphans of the job are re-parented to us, so that we can reap them. As PID 1 this is already the case.
    let _ = rustix::process::set_child_subreaper(Some(rustix::process::getpid()));

    let mut command = Command::new(&job.argv[0]);
    command.args(&job.argv[1..]);
    if job.egress_socket.exists() {
        match start_bridge(job.listen, job.egress_socket.clone()) {
            Ok(addr) => {
                let url = format!("http://{addr}");
                for var in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
                    command.env(var, &url);
                }
                command.env("NO_PROXY", NO_PROXY).env("no_proxy", NO_PROXY);
            }
            Err(e) => {
                // Fail closed and loudly: the job asked for egress and would otherwise fail in confusing ways.
                eprintln!("p2pc-shim: cannot start the egress bridge on {}: {e}", job.listen);
                return ExitCode::from(1);
            }
        }
    }

    let child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("p2pc-shim: cannot run {:?}: {e}", job.argv[0]);
            return ExitCode::from(match e.kind() {
                io::ErrorKind::NotFound => EXIT_NOT_FOUND,
                _ => EXIT_CANNOT_EXECUTE,
            });
        }
    };
    let child_pid = Pid::from_child(&child);

    thread::spawn(move || {
        for sig in signals.forever() {
            if let Some(sig) = Signal::from_named_raw(sig) {
                let _ = rustix::process::kill_process(child_pid, sig);
            }
        }
    });

    // Reap every child; stop when ours exits.
    loop {
        match rustix::process::wait(WaitOptions::empty()) {
            Ok(Some((pid, status))) if pid == child_pid => {
                return ExitCode::from(exit_code(status.exit_status(), status.terminating_signal()));
            }
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => {
                eprintln!("p2pc-shim: wait failed: {e}");
                return ExitCode::from(1);
            }
        }
    }
}

fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1)) {
        Ok(Invocation::Version) => {
            println!("p2pc-shim {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Invocation::Help) => {
            println!("P2PC sandbox shim (container entrypoint).\n\n{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Invocation::Run(job)) => run(job),
        Err(message) => {
            eprintln!("p2pc-shim: {message}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::path::Path;

    use super::*;

    fn args(a: &[&str]) -> impl Iterator<Item = OsString> {
        a.iter().map(OsString::from).collect::<Vec<_>>().into_iter()
    }

    #[test]
    fn the_job_argv_starts_after_the_first_double_dash() {
        let Ok(Invocation::Run(run)) = parse(args(&["--", "--help", "--", "-x"])) else {
            panic!("expected a run");
        };
        assert_eq!(run.argv, ["--help", "--", "-x"]);
        assert_eq!(run.egress_socket, Path::new(EGRESS_SOCKET));
        assert_eq!(run.listen, LISTEN.parse().unwrap());
    }

    #[test]
    fn own_flags_only_before_the_double_dash() {
        assert_eq!(parse(args(&["--version"])), Ok(Invocation::Version));
        assert_eq!(parse(args(&["--help", "--", "x"])), Ok(Invocation::Help));
        let Ok(Invocation::Run(run)) = parse(args(&["--listen", "[::1]:1", "--egress-socket", "/s", "--", "x"])) else {
            panic!("expected a run");
        };
        assert_eq!(run.listen, "[::1]:1".parse().unwrap());
        assert_eq!(run.egress_socket, Path::new("/s"));
    }

    /// The copy logic of the bridge, with a loopback TCP upstream standing in for the unix socket (some sandboxes
    /// forbid `AF_UNIX`; `tests/cli.rs` covers the real socket where it is allowed).
    #[test]
    fn bridge_copies_both_ways_and_propagates_half_close() {
        use std::io::{Read, Write};

        let upstream_srv = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream_srv.local_addr().unwrap();
        let echo = thread::spawn(move || {
            let (mut conn, _) = upstream_srv.accept().unwrap();
            let mut got = Vec::new();
            conn.read_to_end(&mut got).unwrap(); // ends only when the bridge half-closes
            conn.write_all(b"echo:").unwrap();
            conn.write_all(&got).unwrap();
        });
        let front = TcpListener::bind("127.0.0.1:0").unwrap();
        let front_addr = front.local_addr().unwrap();
        let bridged = thread::spawn(move || {
            let (client, _) = front.accept().unwrap();
            let upstream = TcpStream::connect(upstream_addr).unwrap();
            bridge(client, upstream).unwrap();
        });
        let mut client = TcpStream::connect(front_addr).unwrap();
        client.write_all(b"CONNECT example.invalid:443").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"echo:CONNECT example.invalid:443");
        echo.join().unwrap();
        bridged.join().unwrap();
    }

    #[test]
    fn exit_codes_follow_the_shell_convention() {
        assert_eq!(exit_code(Some(0), None), 0);
        assert_eq!(exit_code(Some(3), None), 3);
        assert_eq!(exit_code(None, Some(9)), 137);
        assert_eq!(exit_code(None, Some(15)), 143);
        assert_eq!(exit_code(None, None), 1);
    }

    #[test]
    fn usage_errors() {
        for bad in [
            &[][..],
            &["x"],
            &["--"],
            &["--listen"],
            &["--listen", "nope", "--", "x"],
            &["--listen", "0.0.0.0:3128", "--", "x"],
            &["--listen", "198.51.100.7:3128", "--", "x"],
        ] {
            assert!(parse(args(bad)).is_err(), "{bad:?}");
        }
    }
}
