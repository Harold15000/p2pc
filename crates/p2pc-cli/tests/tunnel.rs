// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is a test failure"
)]

//! Profiles whose server is an address `p2pc_srv_…`, and `p2pc proxy`, end to end in process: the CLI against a fake
//! `p2pc/http/1` server (iroh on loopback with relays disabled, hyper on each stream, like the real tunnel). No real
//! network, no public relay, no `p2pc-server`.

mod common;

use std::ffi::OsString;
use std::io::Write;

use common::{Cli, loopback_tunnel};
use p2pc_cli::app::{self, Host, Interrupt};
use p2pc_client::testing::{MockResponse, MockServer, MockTunnelServer, fixtures};
use p2pc_client::{Client, RetryPolicy};
use p2pc_proto::api::{JobStatus, Scope, ServerInfo};
use p2pc_proto::auth::ApiKey;
use p2pc_proto::ids::{JobId, KeyId};
use serde_json::json;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn secret_part(key: &ApiKey) -> String {
    key.expose().rsplit('_').next().unwrap().to_string()
}

/// A fake API: whoami for `key_id`, a one-job list, `/healthz`.
fn api(key_id: KeyId) -> MockTunnelServer {
    let who = serde_json::to_value(fixtures::whoami(key_id, vec![Scope::JobsRead, Scope::JobsWrite])).unwrap();
    let job = serde_json::to_value(fixtures::job(JobId::generate(), JobStatus::Succeeded, Some(0))).unwrap();
    MockTunnelServer::start(move |r| match r.route().as_str() {
        "GET /healthz" => MockResponse::json(200, &json!({"status": "ok"})),
        "GET /v1/whoami" if r.header("authorization").is_some() => MockResponse::json(200, &who),
        "GET /v1/whoami" => MockResponse::problem(401, "unauthorized", "missing API key"),
        "GET /v1/jobs" => MockResponse::json(200, &json!({"items": [job], "next_cursor": null})),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    })
}

#[test]
fn login_with_a_server_address_then_whoami_and_jobs_go_through_the_tunnel() {
    let cli = Cli::new();
    let server = api(cli.key.key_id());
    let address = server.address_text();
    let key_line = format!("{}\n", cli.key.expose());
    let cli = cli.with_tunnel_hints(&server).with_stdin(&key_line);

    let login = cli.run(&["login", "--server", &address, "--key-stdin"]);
    assert_eq!(login.code, 0, "{login:?}");
    assert!(
        login.stderr.contains(&format!("Logged in to {address}")),
        "{}",
        login.stderr
    );
    // The profile stores the address, and the key in the private credentials file.
    let config = std::fs::read_to_string(cli.config_dir().join("config.toml")).unwrap();
    assert!(config.contains(&address), "{config}");
    // No warning about clear text: the tunnel is encrypted end to end.
    assert!(!login.stderr.contains("unencrypted"), "{}", login.stderr);

    let who = cli.run(&["whoami"]);
    assert_eq!(who.code, 0, "{who:?}");
    assert!(who.stdout.contains(&cli.key.key_id().to_string()), "{}", who.stdout);
    let jobs = cli.run(&["--json", "jobs"]);
    assert_eq!(jobs.code, 0, "{jobs:?}");
    let listed: serde_json::Value = serde_json::from_str(&jobs.stdout).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);

    let routes: Vec<String> = server.requests().iter().map(|r| r.route()).collect();
    assert_eq!(routes, ["GET /v1/whoami", "GET /v1/whoami", "GET /v1/jobs"]);
    let bearer = format!("Bearer {}", cli.key.expose());
    assert!(
        server
            .requests()
            .iter()
            .all(|r| r.header("authorization") == Some(bearer.as_str()))
    );
    // SI-6: the key went in through stdin, and never comes out.
    for out in [&login, &who, &jobs] {
        assert!(!out.stdout.contains(&secret_part(&cli.key)));
        assert!(!out.stderr.contains(&secret_part(&cli.key)));
    }
}

#[test]
fn login_via_tunnel_reads_the_address_from_the_server_and_stores_it() {
    let cli = Cli::new();
    let tunnel_server = api(cli.key.key_id());
    let info = serde_json::to_value(ServerInfo::new(tunnel_server.address(), "0.1.0")).unwrap();
    let who = serde_json::to_value(fixtures::whoami(cli.key.key_id(), vec![Scope::JobsRead])).unwrap();
    let url_server = MockServer::start(move |r| match r.route().as_str() {
        "GET /v1/whoami" => MockResponse::json(200, &who),
        "GET /v1/server" => MockResponse::json(200, &info),
        _ => MockResponse::problem(404, "not_found", "no such route"),
    });
    let key_line = format!("{}\n", cli.key.expose());
    let cli = cli.with_tunnel_hints(&tunnel_server).with_stdin(&key_line);
    let out = cli.run(&["login", "--server", &url_server.url(), "--key-stdin", "--via-tunnel"]);
    assert_eq!(out.code, 0, "{out:?}");
    let config = std::fs::read_to_string(cli.config_dir().join("config.toml")).unwrap();
    assert!(config.contains(&tunnel_server.address_text()), "{config}");
    assert!(!config.contains(&url_server.url()), "{config}");
    // The key was checked over both: the URL, then the tunnel.
    assert_eq!(url_server.requests_to("GET /v1/whoami").len(), 1);
    assert_eq!(tunnel_server.requests_to("GET /v1/whoami").len(), 1);
}

/// T11b1 review: `--via-tunnel` with a server address is refused before any request, not after `GET /v1/whoami`.
#[test]
fn login_via_tunnel_with_a_server_address_is_refused_before_any_request() {
    let cli = Cli::new();
    let server = api(cli.key.key_id());
    let key_line = format!("{}\n", cli.key.expose());
    let cli = cli.with_tunnel_hints(&server).with_stdin(&key_line);
    let out = cli.run(&[
        "login",
        "--server",
        &server.address_text(),
        "--key-stdin",
        "--via-tunnel",
    ]);
    assert_eq!(out.code, 125, "{out:?}");
    assert!(out.stderr.contains("--via-tunnel needs the server's URL"), "{out:?}");
    assert!(
        server.requests().is_empty(),
        "no request may precede the refusal: {:?}",
        server.requests()
    );
    assert_eq!(server.connections(), 0, "not even a connection");
    assert!(!cli.config_dir().join("credentials.toml").exists());
}

#[test]
fn an_unreachable_server_address_fails_with_a_network_error_and_stores_nothing() {
    let cli = Cli::new();
    let gone = api(cli.key.key_id());
    let (address, settings) = (gone.address_text(), loopback_tunnel(&gone));
    drop(gone);
    let key_line = format!("{}\n", cli.key.expose());
    let mut cli = cli.with_stdin(&key_line);
    cli.tunnel = settings;
    // Each of the four attempts (one and three retries) would otherwise wait the full 15 s.
    cli.tunnel.connect_timeout = Some(std::time::Duration::from_millis(300));
    let out = cli.run(&["--json", "login", "--server", &address, "--key-stdin"]);
    assert_eq!(out.code, 125, "{out:?}");
    let err: serde_json::Value = serde_json::from_str(out.stderr.trim()).unwrap();
    assert_eq!(err["error"]["kind"], "network", "{err}");
    assert!(!out.stderr.contains(&secret_part(&cli.key)));
    assert!(!cli.config_dir().join("credentials.toml").exists());
}

// ---------------------------------------------------------------------------------------------------------------
// p2pc proxy
// ---------------------------------------------------------------------------------------------------------------

/// Sends stderr lines to the test as they are written.
struct Lines {
    buf: Vec<u8>,
    tx: tokio::sync::mpsc::UnboundedSender<String>,
    all: std::sync::Arc<std::sync::Mutex<String>>,
}

impl Write for Lines {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        while let Some(end) = self.buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=end).collect();
            let line = String::from_utf8_lossy(&line).trim_end().to_string();
            self.all.lock().unwrap().push_str(&format!("{line}\n"));
            let _ = self.tx.send(line);
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The two ways to stop a running command: Ctrl-C (SIGINT) and SIGTERM.
struct Signals {
    ctrl_c: tokio::sync::oneshot::Sender<()>,
    sigterm: tokio::sync::oneshot::Sender<()>,
}

/// Runs `p2pc <args>` in process next to `test`, which gets the stderr lines and the signal triggers. Returns the
/// exit code, the whole stderr and what `test` returned.
fn with_running_cli<T>(
    cli: &Cli,
    args: &[&str],
    test: impl AsyncFnOnce(tokio::sync::mpsc::UnboundedReceiver<String>, Signals) -> T,
) -> (u8, String, T) {
    let argv: Vec<OsString> = std::iter::once("p2pc")
        .chain(args.iter().copied())
        .map(OsString::from)
        .collect();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let all = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let mut err = Lines {
        buf: Vec::new(),
        tx,
        all: all.clone(),
    };
    let mut out = Vec::new();
    let mut stdin = std::io::Cursor::new(Vec::new());
    let env = |name: &str| cli.env.get(name).cloned();
    let prompt = |_: &str| Ok(String::new());
    let (ctrl_c, ctrl_c_rx) = tokio::sync::oneshot::channel::<()>();
    let (sigterm, sigterm_rx) = tokio::sync::oneshot::channel::<()>();
    let interrupt: Interrupt<'_> = Box::pin(async move {
        if ctrl_c_rx.await.is_err() {
            std::future::pending::<()>().await;
        }
    });
    let terminate: Interrupt<'_> = Box::pin(async move {
        if sigterm_rx.await.is_err() {
            std::future::pending::<()>().await;
        }
    });
    let stop = Signals { ctrl_c, sigterm };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (code, value) = {
        let mut host = Host {
            env: &env,
            out: &mut out,
            err: &mut err,
            stdin: &mut stdin,
            stdin_is_tty: false,
            stdout_is_tty: false,
            stderr_is_tty: false,
            prompt_secret: &prompt,
            interrupt: Some(interrupt),
            terminate: Some(terminate),
            now: OffsetDateTime::from_unix_timestamp_nanos(1_700_000_100_123_456_789).unwrap(),
            retry: RetryPolicy::immediate(3),
            tunnel: cli.tunnel.clone(),
        };
        runtime.block_on(async { tokio::join!(app::run(&argv, &mut host), test(rx, stop)) })
    };
    let stderr = all.lock().unwrap().clone();
    (code, stderr, value)
}

/// The `http://ADDR` of the "listening on" line.
async fn listening(rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> String {
    loop {
        let line = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
            .await
            .expect("the proxy said where it listens")
            .expect("the proxy is running");
        if let Some(rest) = line.split("listening on http://").nth(1) {
            return rest.split(',').next().unwrap().to_string();
        }
    }
}

#[test]
fn the_proxy_tunnels_local_connections_and_never_adds_the_key() {
    let cli = Cli::new();
    let server = api(cli.key.key_id());
    let cli = cli
        .with_tunnel_hints(&server)
        .with_env("P2PC_SERVER", &server.address_text());
    let key = cli.key.clone();
    let (code, stderr, _ctrl_c) =
        with_running_cli(&cli, &["proxy", "--listen", "127.0.0.1:0"], async |mut lines, stop| {
            let addr = listening(&mut lines).await;
            // "curl": a plain HTTP/1.1 request with no key, on a fresh connection.
            let mut tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
            tcp.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut answer = Vec::new();
            tokio::time::timeout(std::time::Duration::from_secs(10), tcp.read_to_end(&mut answer))
                .await
                .unwrap()
                .unwrap();
            let answer = String::from_utf8_lossy(&answer);
            assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
            assert!(answer.contains(r#"{"status":"ok"}"#), "{answer}");
            // whoami without a key: the proxy does not add one, so the server refuses it.
            let mut tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
            tcp.write_all(b"GET /v1/whoami HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut answer = Vec::new();
            tcp.read_to_end(&mut answer).await.unwrap();
            assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 401"));
            // The client's own key works through the proxy (the client and the key's whoami).
            let client = Client::builder(format!("http://{addr}"), key.clone())
                .retry(RetryPolicy::none())
                .build()
                .unwrap();
            let who = client.whoami().await.unwrap();
            assert_eq!(who.key_id, key.key_id());
            stop.ctrl_c.send(()).unwrap();
        });
    // Ctrl-C: 130, as spec §7 says for SIGINT.
    assert_eq!(code, 130, "{stderr}");
    assert!(stderr.contains("p2pc proxy: stopped"), "{stderr}");
    let requests = server.requests();
    let routes: Vec<String> = requests.iter().map(|r| r.route()).collect();
    assert_eq!(routes, ["GET /healthz", "GET /v1/whoami", "GET /v1/whoami"]);
    assert_eq!(
        requests[0].header("authorization"),
        None,
        "the proxy never injects a key"
    );
    assert_eq!(requests[1].header("authorization"), None);
    assert_eq!(
        requests[2].header("authorization"),
        Some(format!("Bearer {}", cli.key.expose()).as_str())
    );
    assert_eq!(
        server.connections(),
        1,
        "one tunnel connection for every local connection"
    );
    assert!(!stderr.contains(&secret_part(&cli.key)), "{stderr}");
}

/// Spec §7 (amended for T11b1): SIGTERM, a service manager's stop, ends the proxy cleanly with 0.
#[test]
fn sigterm_stops_the_proxy_cleanly_with_exit_code_0() {
    let cli = Cli::new();
    let server = api(cli.key.key_id());
    let cli = cli
        .with_tunnel_hints(&server)
        .with_env("P2PC_SERVER", &server.address_text());
    let (code, stderr, _ctrl_c) =
        with_running_cli(&cli, &["proxy", "--listen", "127.0.0.1:0"], async |mut lines, stop| {
            let addr = listening(&mut lines).await;
            // One request through it, so a tunnel connection is open when the stop comes.
            let mut tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
            tcp.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut answer = Vec::new();
            tcp.read_to_end(&mut answer).await.unwrap();
            assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200"));
            let Signals { ctrl_c, sigterm } = stop;
            sigterm.send(()).unwrap();
            // Only SIGTERM is sent: Ctrl-C must not fire because its sender went away.
            ctrl_c
        });
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.contains("p2pc proxy: stopped"), "{stderr}");
}

#[test]
fn the_proxy_listens_on_loopback_by_default_and_refuses_other_addresses_without_the_flag() {
    use clap::Parser;
    let parsed = p2pc_cli::cli::Cli::try_parse_from(["p2pc", "proxy"]).unwrap();
    match parsed.command {
        p2pc_cli::cli::Command::Proxy(args) => {
            assert_eq!(args.listen, "127.0.0.1:7477".parse().unwrap());
            assert!(args.listen.ip().is_loopback());
            assert!(!args.allow_non_loopback);
        }
        other => panic!("{other:?}"),
    }
    let cli = Cli::new().with_env("P2PC_SERVER", &api(KeyId::generate()).address_text());
    for listen in ["192.0.2.10:7477", "0.0.0.0:7477", "[::]:7477"] {
        let out = cli.run(&["proxy", "--listen", listen]);
        assert_eq!(out.code, 125, "{listen}: {out:?}");
        assert!(out.stderr.contains("--allow-non-loopback"), "{}", out.stderr);
    }
    // With the flag it warns first. 192.0.2.10 (TEST-NET-1) is not on this machine, so the bind itself fails.
    let out = cli.run(&["proxy", "--listen", "192.0.2.10:7477", "--allow-non-loopback"]);
    assert!(
        out.stderr.contains("warning: listening on 192.0.2.10:7477"),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("exposed"), "{}", out.stderr);
}

#[test]
fn the_proxy_needs_a_server_address() {
    let out = Cli::new()
        .with_env("P2PC_SERVER", "https://p2pc.example.invalid")
        .run(&["proxy"]);
    assert_eq!(out.code, 125);
    assert!(out.stderr.contains("needs a server address"), "{}", out.stderr);
}
