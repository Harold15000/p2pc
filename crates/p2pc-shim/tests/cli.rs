// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `p2pc-shim` (spec §9 "Shim"): the `--` contract, exit codes, signal forwarding, zombie
//! reaping, the egress bridge and the ingress bridge (H2 §11.2).
//!
//! The child commands are tiny `sh` scripts. Every wait is on a pipe or a process exit, never a sleep; the only
//! deadline is `timeout`, which turns "the shim never reaped" into a failure instead of a hang.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, ChildStdout, Command, Stdio};

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::str::contains;

/// The shim, with any proxy settings of the test environment removed, so that only the shim's own show up.
fn shim() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_p2pc-shim"));
    for var in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

/// Starts the shim with piped stdin and stdout.
fn spawn(args: &[&str]) -> (Child, BufReader<ChildStdout>) {
    let mut child = shim()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let out = BufReader::new(child.stdout.take().unwrap());
    (child, out)
}

fn line(out: &mut BufReader<ChildStdout>) -> String {
    let mut l = String::new();
    out.read_line(&mut l).unwrap();
    l.trim_end().to_string()
}

#[test]
fn version_prints_name_and_version() {
    cargo_bin_cmd!("p2pc-shim")
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("p2pc-shim {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_succeeds() {
    cargo_bin_cmd!("p2pc-shim")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("-- <command>"));
}

#[test]
fn refuses_to_run_without_the_double_dash() {
    for args in [&[][..], &["echo", "hi"], &["--bogus"], &["--egress-socket"]] {
        cargo_bin_cmd!("p2pc-shim")
            .args(args)
            .assert()
            .code(2)
            .stderr(contains("usage: p2pc-shim"));
    }
    // `--` with nothing after it is refused too.
    cargo_bin_cmd!("p2pc-shim")
        .arg("--")
        .assert()
        .code(2)
        .stderr(contains("no command"));
}

#[test]
fn everything_after_the_double_dash_belongs_to_the_job() {
    // The T01 review: a job argv such as `--help` or `--version` is never parsed by the shim.
    cargo_bin_cmd!("p2pc-shim")
        .args(["--", "echo", "--help", "--version", "--"])
        .assert()
        .success()
        .stdout("--help --version --\n");
}

#[test]
fn propagates_exit_codes() {
    cargo_bin_cmd!("p2pc-shim").args(["--", "true"]).assert().code(0);
    cargo_bin_cmd!("p2pc-shim")
        .args(["--", "sh", "-c", "exit 3"])
        .assert()
        .code(3);
    // Killed by a signal: 128 + the signal number, as a shell reports it.
    cargo_bin_cmd!("p2pc-shim")
        .args(["--", "sh", "-c", "kill -KILL $$"])
        .assert()
        .code(128 + 9);
    cargo_bin_cmd!("p2pc-shim")
        .args(["--", "sh", "-c", "kill -TERM $$"])
        .assert()
        .code(128 + 15);
}

#[test]
fn a_missing_command_is_127() {
    cargo_bin_cmd!("p2pc-shim")
        .args(["--", "/nonexistent.invalid/tool"])
        .assert()
        .code(127)
        .stderr(contains("cannot run"));
}

#[test]
fn forwards_sigterm_sigint_and_sighup_to_the_child() {
    for (signal, code) in [
        (rustix::process::Signal::TERM, 71),
        (rustix::process::Signal::INT, 72),
        (rustix::process::Signal::HUP, 73),
    ] {
        let script = "trap 'echo got TERM; exit 71' TERM; trap 'echo got INT; exit 72' INT; \
                      trap 'echo got HUP; exit 73' HUP; echo ready; while :; do read never; done";
        let (mut child, mut out) = spawn(&["--", "sh", "-c", script]);
        assert_eq!(line(&mut out), "ready");
        let pid = rustix::process::Pid::from_child(&child);
        rustix::process::kill_process(pid, signal).unwrap();
        // `read` is interrupted by the trap; the trap's exit code comes back through the shim.
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(code), "{signal:?}");
        assert!(line(&mut out).starts_with("got "));
    }
}

#[test]
fn reaps_orphaned_zombies() {
    // The subshell starts a grandchild and exits, so the grandchild is re-parented to the shim (PID 1 in a
    // container; a child subreaper here). It exits at once. Its /proc entry stays until someone reaps it: the
    // script waits, up to `timeout`, for the entry to disappear.
    let script = r#"pid=$( (sh -c 'exit 0' & echo $!) ); \
                    if timeout 10 sh -c "while [ -e /proc/$pid ]; do :; done"; then echo reaped; else echo zombie; fi"#;
    cargo_bin_cmd!("p2pc-shim")
        .args(["--", "sh", "-c", script])
        .assert()
        .success()
        .stdout("reaped\n");
}

/// The bridge: a unix-socket echo server stands in for the agent's egress proxy (T09).
#[test]
fn bridges_loopback_tcp_to_the_egress_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("egress.sock");
    let server = match UnixListener::bind(&sock) {
        Ok(s) => s,
        // Some build sandboxes forbid creating AF_UNIX sockets at all (EPERM at socket(2)). Only that case is
        // skipped, loudly; the copy logic is also covered by a TCP-only unit test in `src/main.rs`.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("SKIPPED: this environment forbids unix sockets ({e})");
            return;
        }
        Err(e) => panic!("cannot bind the test socket: {e}"),
    };
    let echo = std::thread::spawn(move || {
        let (mut conn, _) = server.accept().unwrap();
        let mut buf = [0u8; 5];
        conn.read_exact(&mut buf).unwrap();
        conn.write_all(b"pong:").unwrap();
        conn.write_all(&buf).unwrap();
        // Then copy until the client closes, to check that half-close travels through.
        let mut rest = Vec::new();
        conn.read_to_end(&mut rest).unwrap();
        conn.write_all(&rest).unwrap();
    });

    let script = "echo \"$HTTP_PROXY|$HTTPS_PROXY|$http_proxy|$https_proxy|$NO_PROXY\"; read done";
    let (mut child, mut out) = spawn(&[
        "--egress-socket",
        sock.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--",
        "sh",
        "-c",
        script,
    ]);
    let env = line(&mut out);
    let parts: Vec<&str> = env.split('|').collect();
    assert_eq!(parts.len(), 5, "{env}");
    let url = parts[0];
    assert!(url.starts_with("http://127.0.0.1:"), "{env}");
    assert!(parts[..4].iter().all(|p| *p == url), "{env}");
    assert_eq!(parts[4], "localhost,127.0.0.1");

    let addr = url.trim_start_matches("http://");
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.write_all(b"ping!").unwrap();
    let mut reply = [0u8; 10];
    tcp.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"pong:ping!");
    tcp.write_all(b"tail").unwrap();
    tcp.shutdown(std::net::Shutdown::Write).unwrap();
    let mut tail = Vec::new();
    tcp.read_to_end(&mut tail).unwrap();
    assert_eq!(tail, b"tail");
    echo.join().unwrap();

    child.stdin.take().unwrap().write_all(b"x\n").unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn without_a_socket_file_nothing_listens_and_no_proxy_is_set() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("egress.sock");
    let script = "echo \"${HTTP_PROXY-unset}|${https_proxy-unset}|${NO_PROXY-unset}\"; read done";
    let (mut child, mut out) = spawn(&[
        "--egress-socket",
        missing.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--",
        "sh",
        "-c",
        script,
    ]);
    assert_eq!(line(&mut out), "unset|unset|unset");
    // While the job runs, none of the shim's sockets is a listening TCP socket. (It does hold signal-hook's
    // internal socketpair, which is not a listener.)
    assert_eq!(listening_tcp(child.id()), Vec::<String>::new());
    child.stdin.take().unwrap().write_all(b"x\n").unwrap();
    assert!(child.wait().unwrap().success());

    // Control: the same check sees the listener when the socket file exists. A plain file is enough here, since
    // nothing connects; that keeps this test runnable where AF_UNIX sockets are forbidden.
    std::fs::write(&missing, b"").unwrap();
    let (mut child, mut out) = spawn(&[
        "--egress-socket",
        missing.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--",
        "sh",
        "-c",
        "echo \"${HTTP_PROXY-unset}\"; read done",
    ]);
    assert!(line(&mut out).starts_with("http://127.0.0.1:"));
    assert_eq!(listening_tcp(child.id()).len(), 1);
    child.stdin.take().unwrap().write_all(b"x\n").unwrap();
    assert!(child.wait().unwrap().success());
}

/// The rows of `/proc/<pid>/net/tcp{,6}` in state LISTEN whose socket `pid` holds.
fn listening_tcp(pid: u32) -> Vec<String> {
    let inodes: Vec<String> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .filter_map(|fd| std::fs::read_link(fd.unwrap().path()).ok())
        .filter_map(|t| {
            let t = t.to_string_lossy().into_owned();
            Some(t.strip_prefix("socket:[")?.strip_suffix(']')?.to_string())
        })
        .collect();
    let mut found = Vec::new();
    for table in ["tcp", "tcp6"] {
        let text = std::fs::read_to_string(format!("/proc/{pid}/net/{table}")).unwrap_or_default();
        for row in text.lines().skip(1) {
            let cols: Vec<&str> = row.split_whitespace().collect();
            if cols.len() > 9 && cols[3] == "0A" && inodes.iter().any(|i| i == cols[9]) {
                found.push(row.trim().to_string());
            }
        }
    }
    found
}

#[test]
fn refuses_a_non_loopback_listen_address() {
    cargo_bin_cmd!("p2pc-shim")
        .args(["--listen", "192.0.2.1:3128", "--", "true"])
        .assert()
        .code(2)
        .stderr(contains("loopback"));
}

/// A header of the agent's side of the ingress bridge: the version, then the port, big-endian.
fn header(version: u8, port: u16) -> [u8; 3] {
    let [hi, lo] = port.to_be_bytes();
    [version, hi, lo]
}

/// The next idle connection the shim dials. A read that never ends fails the test after a while instead of hanging
/// it.
fn next_idle(agent: &UnixListener) -> UnixStream {
    let (conn, _) = agent.accept().unwrap();
    conn.set_read_timeout(Some(std::time::Duration::from_secs(60))).unwrap();
    conn
}

/// The ingress bridge end to end (H2 §11.2, SI-H2-7): a unix listener stands in for the agent's `ingress.sock`, a
/// loopback TCP listener for the service inside the container.
#[test]
fn the_ingress_bridge_forwards_listed_ports_and_refuses_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("ingress.sock");
    let agent = match UnixListener::bind(&sock) {
        Ok(s) => s,
        // As for the egress bridge: only a sandbox that forbids AF_UNIX skips this, loudly. The request handling
        // is also covered by unit tests in `src/ingress.rs`, over TCP.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("SKIPPED: this environment forbids unix sockets ({e})");
            return;
        }
        Err(e) => panic!("cannot bind the test socket: {e}"),
    };
    let service = TcpListener::bind("127.0.0.1:0").unwrap();
    let listed = service.local_addr().unwrap().port();
    // A second service of the same "container", which `ports.json` does not list.
    let hidden = TcpListener::bind("127.0.0.1:0").unwrap();
    let unlisted = hidden.local_addr().unwrap().port();
    hidden.set_nonblocking(true).unwrap();
    let ports = dir.path().join("ports.json");
    std::fs::write(&ports, format!("{{\"ports\":[{listed}]}}")).unwrap();

    let (mut child, mut out) = spawn(&[
        "--egress-socket",
        dir.path().join("egress.sock").to_str().unwrap(),
        "--ports-file",
        ports.to_str().unwrap(),
        "--ingress-socket",
        sock.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        "echo ready; read done",
    ]);
    assert_eq!(line(&mut out), "ready");

    // The shim keeps 4 idle connections open.
    let mut idle: Vec<UnixStream> = (0..4).map(|_| next_idle(&agent)).collect();

    // A port that is not listed: status 2, the connection ends, and nothing reached that port.
    let mut conn = idle.pop().unwrap();
    conn.write_all(&header(1, unlisted)).unwrap();
    let mut answer = Vec::new();
    conn.read_to_end(&mut answer).unwrap();
    assert_eq!(answer, [2], "not listed");
    assert_eq!(
        hidden.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "the shim connected to a port that is not listed"
    );
    // It dials a fresh idle connection after each request.
    idle.push(next_idle(&agent));

    // A header of another version is not answered at all.
    let mut conn = idle.pop().unwrap();
    conn.write_all(&header(2, listed)).unwrap();
    let mut answer = Vec::new();
    conn.read_to_end(&mut answer).unwrap();
    assert!(answer.is_empty(), "{answer:?}");
    idle.push(next_idle(&agent));

    // A listed port: status 0, then bytes both ways, and a half-close travels through.
    let mut conn = idle.pop().unwrap();
    conn.write_all(&header(1, listed)).unwrap();
    let mut status = [9u8; 1];
    conn.read_exact(&mut status).unwrap();
    assert_eq!(status, [0], "ok");
    let (mut served, peer) = service.accept().unwrap();
    assert!(peer.ip().is_loopback());
    conn.write_all(b"ping").unwrap();
    let mut got = [0u8; 4];
    served.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ping");
    served.write_all(b"pong").unwrap();
    conn.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"pong");
    conn.shutdown(Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    served.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "the client's end reached the service");
    served.write_all(b"bye").unwrap();
    drop(served);
    conn.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"bye");
    idle.push(next_idle(&agent));
    assert_eq!(idle.len(), 4);

    // The bridge listens on nothing: the service's port is reachable only through the agent's socket.
    assert_eq!(listening_tcp(child.id()), Vec::<String>::new());

    child.stdin.take().unwrap().write_all(b"x\n").unwrap();
    assert!(child.wait().unwrap().success());
}

/// A ports file the shim cannot read exactly stops it before the job runs: it never guesses which ports to forward.
#[test]
fn a_malformed_ports_file_stops_the_shim_before_the_job() {
    let dir = tempfile::tempdir().unwrap();
    let ports = dir.path().join("ports.json");
    for bad in ["{\"ports\":\"all\"}", "{\"ports\":[0]}", "{\"ports\":[80],\"x\":1}", ""] {
        std::fs::write(&ports, bad).unwrap();
        shim()
            .args(["--ports-file", ports.to_str().unwrap(), "--", "echo", "ran"])
            .assert_output(1, "", "cannot read");
    }
}

/// Runs a command and checks its exit code, its exact stdout and a part of its stderr.
trait AssertOutput {
    fn assert_output(&mut self, code: i32, stdout: &str, stderr_has: &str);
}

impl AssertOutput for Command {
    fn assert_output(&mut self, code: i32, stdout: &str, stderr_has: &str) {
        let out = self.output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(code), "{stderr}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), stdout);
        assert!(stderr.contains(stderr_has), "{stderr}");
    }
}
