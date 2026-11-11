// SPDX-License-Identifier: Apache-2.0

//! The ingress bridge, container side (H2 spec §11.2, SI-H2-7).
//!
//! A service's container has no network (`--network=none`), so nothing outside can connect to its port. The bridge
//! is a **reverse dial**: the agent listens on its own unix socket, `/.p2pc/ingress.sock`, in the read-only `/.p2pc`
//! mount, and the shim connects to it. Nothing here listens: the shim opens no socket that anything could connect
//! to, inside the container or outside it.
//!
//! - **When.** Only when `/.p2pc/ports.json` exists (the agent writes it for a service, next to the socket). It
//!   lists the ports the shim may forward: `{"ports":[11434]}`. A file that cannot be read exactly as that stops the
//!   shim before the job starts.
//! - **Idle connections.** [`IDLE_CONNECTIONS`] threads each keep one connection open to the socket and wait for
//!   the agent's 3-byte header on it: version [`VERSION`], then the port as a big-endian `u16`.
//! - **A request.** The port is checked against `ports.json` first: a port that is not listed gets
//!   [`STATUS_NOT_LISTED`] and nothing is connected. A listed port is connected at `127.0.0.1:<port>`, then at
//!   `[::1]:<port>`; the shim answers [`STATUS_OK`] and copies both ways, or [`STATUS_REFUSED`]. Either way the
//!   thread dials a fresh idle connection at once.
//! - **Only loopback.** The destination is always a loopback address of the container's own network namespace, and
//!   the port always one of the listed ones. The agent sends a port, never a host.
//! - **A header with another version** is not answered: the connection is closed. The agent and the shim always come
//!   from the same release (the agent injects the shim), so this is a peer that is not the agent's bridge.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use crate::Duplex;

/// Where the agent lists the ports the shim may forward.
pub const PORTS_FILE: &str = "/.p2pc/ports.json";
/// The agent's ingress socket.
pub const INGRESS_SOCKET: &str = "/.p2pc/ingress.sock";
/// Idle connections the shim keeps open to the agent (§11.2).
pub const IDLE_CONNECTIONS: usize = 4;
/// The version byte of the agent's header.
pub const VERSION: u8 = 1;
/// Status byte: connected to the port; bytes follow both ways.
pub const STATUS_OK: u8 = 0;
/// Status byte: nothing accepted the connection on the port.
pub const STATUS_REFUSED: u8 = 1;
/// Status byte: the port is not in `ports.json`; nothing was connected.
pub const STATUS_NOT_LISTED: u8 = 2;
/// Most ports in `ports.json` (H2 §7.1: a service has 1-8).
pub const MAX_PORTS: usize = 8;
/// Largest `ports.json` the shim reads.
const MAX_PORTS_FILE_BYTES: u64 = 4096;
/// Most forwarded connections at once; more are refused. The agent allows 64 port streams per lease, plus its
/// health checks; each connection costs the container two threads of its PID limit.
const MAX_ACTIVE: usize = 128;
/// Longest one connection attempt to the service may take. Two attempts (IPv4, IPv6) stay under the 5 s the agent
/// waits for the status byte.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// The first wait before dialing the agent again after a failed dial or a connection closed without a request.
const REDIAL_MIN: Duration = Duration::from_millis(100);
/// The longest such wait (it doubles each time).
const REDIAL_MAX: Duration = Duration::from_secs(2);

/// Parses `ports.json`: exactly `{"ports":[<port>, …]}`, 1 to [`MAX_PORTS`] distinct ports of 1-65535 in plain
/// decimal, with optional whitespace between the tokens and nothing else.
///
/// The agent writes the file and the shim of the same release reads it, so there is no other form to accept: an
/// unknown key, a duplicate or a port out of range is an error, never skipped.
pub fn parse_ports(text: &str) -> Result<Vec<u16>, &'static str> {
    let mut rest = text.as_bytes();
    let mut ports = Vec::new();
    token(&mut rest, b"{")?;
    token(&mut rest, b"\"ports\"")?;
    token(&mut rest, b":")?;
    token(&mut rest, b"[")?;
    loop {
        let port = number(&mut rest)?;
        if ports.contains(&port) {
            return Err("a port is listed twice");
        }
        if ports.len() == MAX_PORTS {
            return Err("more than 8 ports");
        }
        ports.push(port);
        if token(&mut rest, b",").is_err() {
            break;
        }
    }
    token(&mut rest, b"]")?;
    token(&mut rest, b"}")?;
    skip_whitespace(&mut rest);
    if !rest.is_empty() {
        return Err("text after the object");
    }
    Ok(ports)
}

fn skip_whitespace(rest: &mut &[u8]) {
    while let [b' ' | b'\t' | b'\n' | b'\r', tail @ ..] = rest {
        *rest = tail;
    }
}

/// Consumes `expected` after optional whitespace.
fn token(rest: &mut &[u8], expected: &[u8]) -> Result<(), &'static str> {
    skip_whitespace(rest);
    *rest = rest.strip_prefix(expected).ok_or("not of the form {\"ports\":[…]}")?;
    Ok(())
}

/// Consumes a port after optional whitespace: 1-65535, plain decimal, no sign and no leading zero.
fn number(rest: &mut &[u8]) -> Result<u16, &'static str> {
    skip_whitespace(rest);
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    let (text, tail) = rest.split_at(digits);
    if text.is_empty() || text[0] == b'0' || digits > 5 {
        return Err("a port is not a number from 1 to 65535");
    }
    let value = text.iter().fold(0u32, |n, d| n * 10 + u32::from(d - b'0'));
    let port = u16::try_from(value).map_err(|_| "a port is not a number from 1 to 65535")?;
    *rest = tail;
    Ok(port)
}

/// Reads the ports file. `Ok(None)` when there is none: the job is not a service and no bridge starts.
pub fn load_ports(path: &Path) -> Result<Option<Vec<u16>>, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let mut text = String::new();
    file.take(MAX_PORTS_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() as u64 > MAX_PORTS_FILE_BYTES {
        return Err("the file is too large".into());
    }
    parse_ports(&text).map(Some).map_err(String::from)
}

/// What the agent asks for on an idle connection.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    /// A connection to this port.
    Port(u16),
    /// A header of a version this shim does not speak.
    UnknownVersion,
}

/// Reads the agent's header. Blocks for as long as the connection is idle.
fn read_request(conn: &mut impl Read) -> io::Result<Request> {
    let mut header = [0u8; 3];
    conn.read_exact(&mut header)?;
    if header[0] != VERSION {
        return Ok(Request::UnknownVersion);
    }
    Ok(Request::Port(u16::from_be_bytes([header[1], header[2]])))
}

/// Connects to the service: `127.0.0.1:<port>`, then `[::1]:<port>` (§11.2). Never any other address.
fn connect_loopback(port: u16) -> io::Result<TcpStream> {
    let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    TcpStream::connect_timeout(&v4, CONNECT_TIMEOUT).or_else(|_| TcpStream::connect_timeout(&v6, CONNECT_TIMEOUT))
}

/// How the shim reaches a service port. Always [`connect_loopback`] outside tests.
type Connect = dyn Fn(u16) -> io::Result<TcpStream> + Send + Sync;

/// The ports the shim may forward, and the connections it forwards now.
struct Forwarder {
    ports: Vec<u16>,
    active: AtomicUsize,
    connect: Box<Connect>,
}

impl std::fmt::Debug for Forwarder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forwarder")
            .field("ports", &self.ports)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

/// What became of a request.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    /// Answered at once with this status byte; nothing was connected.
    Status(u8),
    /// A listed port: connect and copy, on another thread.
    Forward(u16),
    /// Not answered: the connection is closed.
    Close,
}

impl Forwarder {
    fn new(ports: Vec<u16>, connect: Box<Connect>) -> Self {
        Self {
            ports,
            active: AtomicUsize::new(0),
            connect,
        }
    }

    /// Decides a request without connecting anything: the port must be listed, before any connection is tried.
    fn decide(&self, request: &Request) -> Answer {
        match request {
            Request::UnknownVersion => Answer::Close,
            Request::Port(port) if !self.ports.contains(port) => Answer::Status(STATUS_NOT_LISTED),
            Request::Port(port) => Answer::Forward(*port),
        }
    }

    /// Connects `conn` to the listed `port`, answers the status byte and copies both ways until both are done.
    fn forward<C: Duplex>(&self, mut conn: C, port: u16) {
        // Checked again here: nothing but a listed port is ever connected, whoever calls this.
        if !self.ports.contains(&port) {
            let _ = conn.write_all(&[STATUS_NOT_LISTED]);
            return;
        }
        if self.active.fetch_add(1, Ordering::SeqCst) >= MAX_ACTIVE {
            self.active.fetch_sub(1, Ordering::SeqCst);
            let _ = conn.write_all(&[STATUS_REFUSED]);
            return;
        }
        match (self.connect)(port) {
            Ok(service) => {
                if conn.write_all(&[STATUS_OK]).is_ok() {
                    let _ = splice(conn, service);
                }
            }
            Err(_) => {
                let _ = conn.write_all(&[STATUS_REFUSED]);
            }
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Copies `from` to `to` until the end of `from`, then half-closes `to`, so that the peer sees the end. An error
/// (a reset, a peer that is gone) closes both in both directions instead, which ends the other direction too: a
/// broken connection is torn down, never left half open.
fn pump_or_abort<A: Duplex, B: Duplex>(mut from: A, mut to: B) {
    match io::copy(&mut from, &mut to) {
        Ok(_) => to.close_write(),
        Err(_) => {
            from.close_both();
            to.close_both();
        }
    }
}

/// Copies both directions between the agent's connection and the service until both are done.
fn splice<A: Duplex, B: Duplex>(agent: A, service: B) -> io::Result<()> {
    let (agent_r, service_w) = (agent.split()?, service.split()?);
    // `Builder::spawn` reports a failure (the container's PID limit) instead of panicking; the connections then
    // close as they are dropped.
    let up = thread::Builder::new()
        .name("ingress-up".into())
        .spawn(move || pump_or_abort(agent_r, service_w))?;
    pump_or_abort(service, agent);
    let _ = up.join();
    Ok(())
}

/// One idle connection after another, for the life of the shim: dial the agent, wait for a request, hand it over,
/// dial again.
fn dialer(socket: &Path, forwarder: &Arc<Forwarder>) {
    let mut delay = REDIAL_MIN;
    let wait = |delay: &mut Duration| {
        thread::sleep(*delay);
        *delay = (*delay * 2).min(REDIAL_MAX);
    };
    loop {
        let Ok(mut conn) = UnixStream::connect(socket) else {
            wait(&mut delay);
            continue;
        };
        let Ok(request) = read_request(&mut conn) else {
            // The agent closed it without a request (it keeps a bounded number of idle connections): back off
            // instead of spinning.
            wait(&mut delay);
            continue;
        };
        delay = REDIAL_MIN;
        match forwarder.decide(&request) {
            Answer::Close => {}
            Answer::Status(status) => {
                // One byte into an empty socket buffer: it cannot block this thread.
                let _ = conn.write_all(&[status]);
            }
            Answer::Forward(port) => {
                let forwarder = Arc::clone(forwarder);
                // The connect and the copy run on their own thread, so this one dials a fresh idle connection at
                // once. If no thread can start, the closure is dropped and the connection closes with it.
                let _ = thread::Builder::new()
                    .name("ingress-conn".into())
                    .spawn(move || forwarder.forward(conn, port));
            }
        }
    }
}

/// Starts the bridge: [`IDLE_CONNECTIONS`] threads that keep one idle connection each to `socket`.
///
/// # Errors
/// When a thread cannot be started.
pub fn start(socket: &Path, ports: Vec<u16>) -> io::Result<()> {
    let forwarder = Arc::new(Forwarder::new(ports, Box::new(connect_loopback)));
    for _ in 0..IDLE_CONNECTIONS {
        let (socket, forwarder): (PathBuf, _) = (socket.to_path_buf(), Arc::clone(&forwarder));
        thread::Builder::new()
            .name("ingress-idle".into())
            .spawn(move || dialer(&socket, &forwarder))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::net::{Shutdown, TcpListener};
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn ports_json_is_read_strictly() {
        assert_eq!(parse_ports(r#"{"ports":[11434]}"#), Ok(vec![11434]));
        assert_eq!(
            parse_ports("{ \"ports\" : [ 1 , 8080,65535 ]\n}\n"),
            Ok(vec![1, 8080, 65535])
        );
        assert_eq!(
            parse_ports(r#"{"ports":[1,2,3,4,5,6,7,8]}"#).map(|p| p.len()),
            Ok(MAX_PORTS)
        );
        for bad in [
            "",
            "{}",
            r#"{"ports":[]}"#,
            r#"{"ports":[0]}"#,
            r#"{"ports":[65536]}"#,
            r#"{"ports":[99999999999999999999]}"#,
            r#"{"ports":[080]}"#,
            r#"{"ports":[-1]}"#,
            r#"{"ports":[+1]}"#,
            r#"{"ports":[1.0]}"#,
            r#"{"ports":["80"]}"#,
            r#"{"ports":[80,]}"#,
            r#"{"ports":[80,80]}"#,
            r#"{"ports":[1,2,3,4,5,6,7,8,9]}"#,
            r#"{"ports":[80]"#,
            r#"{"ports":[80]} x"#,
            r#"{"ports":[80]}{"ports":[81]}"#,
            r#"{"ports":[80],"all":true}"#,
            r#"{"all":true,"ports":[80]}"#,
            r#"{"Ports":[80]}"#,
            r#"["ports",80]"#,
            "null",
        ] {
            assert!(parse_ports(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn no_ports_file_means_no_bridge_and_a_bad_one_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ports.json");
        assert_eq!(load_ports(&path), Ok(None));
        std::fs::write(&path, r#"{"ports":[8080,9090]}"#).unwrap();
        assert_eq!(load_ports(&path), Ok(Some(vec![8080, 9090])));
        std::fs::write(&path, r#"{"ports":"all"}"#).unwrap();
        assert!(load_ports(&path).is_err());
        // Bounded: a huge file is refused, not read to its end.
        let padded = format!("{}{}", " ".repeat(8192), r#"{"ports":[8080]}"#);
        std::fs::write(&path, padded).unwrap();
        assert!(load_ports(&path).unwrap_err().contains("too large"));
    }

    #[test]
    fn the_header_is_version_then_the_port_big_endian() {
        assert_eq!(read_request(&mut &[1u8, 0x2c, 0xaa][..]).unwrap(), Request::Port(11434));
        assert_eq!(read_request(&mut &[1u8, 0, 80, 9, 9][..]).unwrap(), Request::Port(80));
        for version in [0u8, 2, 255] {
            assert_eq!(
                read_request(&mut &[version, 0, 80][..]).unwrap(),
                Request::UnknownVersion
            );
        }
        // A connection closed before a whole header is no request.
        assert!(read_request(&mut &[1u8, 0][..]).is_err());
        assert!(read_request(&mut &[][..]).is_err());
    }

    /// The ports a forwarder tried to connect, and what its connector answers with.
    fn recording(ports: &[u16], to: Option<SocketAddr>) -> (Forwarder, Arc<Mutex<Vec<u16>>>) {
        let tried = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&tried);
        let connect = move |port: u16| {
            log.lock().unwrap().push(port);
            match to {
                Some(addr) => TcpStream::connect(addr),
                None => Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
            }
        };
        (Forwarder::new(ports.to_vec(), Box::new(connect)), tried)
    }

    /// A connected pair of loopback TCP streams, standing in for the unix connection to the agent (some sandboxes
    /// forbid `AF_UNIX`; `tests/cli.rs` covers the real socket where it is allowed).
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let near = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (far, _) = listener.accept().unwrap();
        (near, far)
    }

    /// SI-H2-7: a port that is not in `ports.json` is refused with status 2, and nothing is connected for it.
    #[test]
    fn an_unlisted_port_is_refused_and_never_connected() {
        let (forwarder, tried) = recording(&[8080], None);
        for port in [80u16, 8081, 22, 65535, 1] {
            assert_eq!(
                forwarder.decide(&Request::Port(port)),
                Answer::Status(STATUS_NOT_LISTED),
                "{port}"
            );
            // Even if a request for it reached `forward`, it would answer 2 and connect nothing.
            let (mut agent, shim) = pair();
            forwarder.forward(shim, port);
            let mut answer = Vec::new();
            agent.read_to_end(&mut answer).unwrap();
            assert_eq!(answer, [STATUS_NOT_LISTED], "{port}");
        }
        assert!(tried.lock().unwrap().is_empty(), "no connection was tried");
        assert_eq!(forwarder.decide(&Request::Port(8080)), Answer::Forward(8080));
        assert_eq!(forwarder.decide(&Request::UnknownVersion), Answer::Close);
    }

    #[test]
    fn a_listed_port_with_nothing_behind_it_answers_refused() {
        let (forwarder, tried) = recording(&[8080], None);
        let (mut agent, shim) = pair();
        forwarder.forward(shim, 8080);
        let mut answer = Vec::new();
        agent.read_to_end(&mut answer).unwrap();
        assert_eq!(answer, [STATUS_REFUSED]);
        assert_eq!(*tried.lock().unwrap(), [8080]);
        assert_eq!(forwarder.active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_listed_port_is_connected_and_copied_both_ways_with_half_close() {
        let service = TcpListener::bind("127.0.0.1:0").unwrap();
        let (forwarder, tried) = recording(&[8080], Some(service.local_addr().unwrap()));
        let echo = thread::spawn(move || {
            let (mut conn, _) = service.accept().unwrap();
            let mut got = Vec::new();
            conn.read_to_end(&mut got).unwrap(); // ends only when the half-close arrives
            conn.write_all(b"echo:").unwrap();
            conn.write_all(&got).unwrap();
        });
        let (mut agent, shim) = pair();
        let forwarder = Arc::new(forwarder);
        let serving = {
            let forwarder = Arc::clone(&forwarder);
            thread::spawn(move || forwarder.forward(shim, 8080))
        };
        let mut status = [9u8; 1];
        agent.read_exact(&mut status).unwrap();
        assert_eq!(status, [STATUS_OK]);
        agent.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        agent.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        agent.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"echo:GET / HTTP/1.1\r\n\r\n");
        echo.join().unwrap();
        serving.join().unwrap();
        assert_eq!(*tried.lock().unwrap(), [8080]);
        assert_eq!(forwarder.active.load(Ordering::SeqCst), 0, "the slot is given back");
    }

    #[test]
    fn beyond_the_connection_limit_a_request_is_refused_without_connecting() {
        let (forwarder, tried) = recording(&[8080], None);
        forwarder.active.store(MAX_ACTIVE, Ordering::SeqCst);
        let (mut agent, shim) = pair();
        forwarder.forward(shim, 8080);
        let mut answer = Vec::new();
        agent.read_to_end(&mut answer).unwrap();
        assert_eq!(answer, [STATUS_REFUSED]);
        assert!(tried.lock().unwrap().is_empty());
        assert_eq!(forwarder.active.load(Ordering::SeqCst), MAX_ACTIVE);
    }

    /// A reset is not a clean end: the whole connection is torn down, both directions.
    #[test]
    fn an_error_in_one_direction_closes_both() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::ConnectionReset))
            }
        }
        impl Write for Broken {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl Duplex for Broken {
            fn split(&self) -> io::Result<Self> {
                Ok(Broken)
            }
            fn close_write(&self) {}
            fn close_both(&self) {}
        }
        let (mut peer, to) = pair();
        pump_or_abort(Broken, to);
        // Both directions of `to` were shut down: the peer reads the end, and what it writes goes nowhere.
        let mut rest = Vec::new();
        peer.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }

    /// The numbers of §11.2, which the agent's side of the bridge shares.
    #[test]
    fn the_protocol_constants_are_the_specs() {
        assert_eq!(IDLE_CONNECTIONS, 4);
        assert_eq!(VERSION, 1);
        assert_eq!((STATUS_OK, STATUS_REFUSED, STATUS_NOT_LISTED), (0, 1, 2));
        assert!(CONNECT_TIMEOUT * 2 < Duration::from_secs(5));
    }
}
