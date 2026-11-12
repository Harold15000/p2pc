// SPDX-License-Identifier: Apache-2.0

//! One job end to end through the whole agent: the daemon and its session over real iroh (QUIC on loopback, relays
//! disabled), the lease executor, and the real Podman driver, against a fake server inside the test that speaks the
//! `p2pc-proto` codec and stores uploads (§6). It checks the logs, two outputs with their sha256, the order (every
//! upload before `JobFinished`) and the cleanup. No dependency on `p2pc-server` (AGPL-3.0).
//!
//! - `a_job_runs_end_to_end_with_fake_podman`: hermetic, with the fake `podman` of `tests/fixtures` (the "container"
//!   is a host shell script that writes the outputs into the job directory).
//! - `a_job_runs_end_to_end_with_real_podman`: `#[ignore]`d, like T08's real-Podman tests. On a test node (the rootless
//!   `p2pc` user, or root in the `p2pc-node` WSL2 distro):
//!
//!   ```text
//!   cargo build -p p2pc-shim --target x86_64-unknown-linux-musl --release
//!   cargo test -p p2pc-agent --test executor_end_to_end -- --ignored --test-threads=1
//!   ```
//!
//!   `P2PC_SHIM` and `P2PC_TEST_IMAGE` work as in `podman_real.rs` (the image needs `sh` and `head`; busybox by
//!   default). The first run pulls the image.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use p2pc_agent::connection::daemon::{Daemon, DaemonExit};
use p2pc_agent::connection::endpoint::IrohConnector;
use p2pc_agent::connection::session::{INVENTORY_INTERVAL, InventorySource, MAX_PENDING_DECISIONS, Shared};
use p2pc_agent::connection::watchdog::Watchdog;
use p2pc_agent::connection::{BoxFuture, Uplink};
use p2pc_agent::executor::capacity::Offer;
use p2pc_agent::executor::{Executor, Startup, SystemClock};
use p2pc_agent::host::Host;
use p2pc_agent::runner::SystemRunner;
use p2pc_agent::sandbox::cgroup::{FsCgroups, HostCgroups, SystemdCgroups, user_service_cgroup};
use p2pc_agent::sandbox::disk::{DiskSpace, FreeSpace};
use p2pc_agent::sandbox::engine::{PULL_TIMEOUT, PodmanEngine};
use p2pc_agent::sandbox::{DriverConfig, NoEgress, PodmanDriver, Sandbox};
use p2pc_net::{BindSpec, bind_endpoint};
use p2pc_proto::PROTOCOL_ALPN_AGENT;
use p2pc_proto::api::{Inventory, Platform};
use p2pc_proto::ids::{AccountId, LeaseId, NodeId};
use p2pc_proto::net::{IfAddr, SelectedAddr};
use p2pc_proto::protocol::{Load, MAX_FRAME_LEN, UploadAck, UploadHeader, read_frame, write_frame};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::sync::{Semaphore, mpsc, watch};

/// What the job leaves in `/outputs`.
const ALPHA: &[u8] = b"alpha";
const B_LEN: usize = 100_000;

fn loopback() -> Vec<SelectedAddr> {
    vec![SelectedAddr::new(IfAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8), "lo")]
}

#[derive(Debug)]
struct FixedInventory;

impl InventorySource for FixedInventory {
    fn detect(&self) -> BoxFuture<'_, Result<Inventory, String>> {
        Box::pin(async {
            Ok(serde_json::from_value(json!({
                "hostname": "node-1", "platform": "linux", "cpu": {"model": "Example CPU", "cores": 4},
                "memory_mb": 8192, "os": "Ubuntu 24.04", "arch": "x86_64", "gpu_status": {"status": "not_found"},
                "offered": {"cpu": 3.0, "memory_mb": 6144, "gpu": 0}, "agent_version": "0.1.0",
            }))
            .unwrap())
        })
    }
}

#[derive(Debug)]
struct ZeroLoad;

impl p2pc_agent::connection::load::LoadSource for ZeroLoad {
    fn sample(&self) -> BoxFuture<'_, Load> {
        Box::pin(async { serde_json::from_value(json!({"cpu_pct": 0, "mem_used_mb": 0})).unwrap() })
    }
}

/// What the fake server saw.
#[derive(Debug, Default)]
struct Seen {
    /// Control messages, heartbeats left out.
    msgs: Vec<Value>,
    /// Uploads: path, header sha256 (hex), bytes.
    uploads: BTreeMap<String, (String, Vec<u8>)>,
    /// Upload acks and control messages, in the order the server handled them.
    journal: Vec<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Serves one upload stream: header, exactly `size` bytes, a sha256 check, `UploadAck{ok}`.
async fn upload(conn: Connection, seen: Arc<Mutex<Seen>>) {
    while let Ok((mut w, mut r)) = conn.accept_bi().await {
        let seen = seen.clone();
        tokio::spawn(async move {
            let header: UploadHeader = read_frame(&mut r, MAX_FRAME_LEN).await.unwrap().unwrap();
            let mut body = vec![0u8; usize::try_from(header.size).unwrap()];
            r.read_exact(&mut body).await.unwrap();
            let rest = r.read_to_end(1).await.unwrap();
            assert!(rest.is_empty(), "exactly `size` bytes");
            let sha: [u8; 32] = Sha256::digest(&body).into();
            let ok = sha == header.sha256.0;
            {
                let mut s = seen.lock().unwrap();
                s.journal.push(format!("upload {}", header.path));
                s.uploads.insert(header.path.clone(), (hex(&header.sha256.0), body));
            }
            write_frame(&mut w, &UploadAck { ok, reason: None }).await.unwrap();
            w.finish().unwrap();
            let _ = w.stopped().await;
        });
    }
}

/// The fake server's side of one connection: Hello → Welcome, one Lease, heartbeat acks, every message recorded
/// until `JobFinished`.
async fn serve(server: Endpoint, owner: AccountId, lease_id: LeaseId, job: Value, wait: Duration) -> Seen {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let conn = tokio::time::timeout(wait, async { server.accept().await.unwrap().await.unwrap() })
        .await
        .expect("no agent connection");
    let (mut w, mut r) = conn.accept_bi().await.unwrap();
    let uploads = tokio::spawn(upload(conn.clone(), seen.clone()));
    let hello: Value = read_frame(&mut r, MAX_FRAME_LEN).await.unwrap().unwrap();
    assert_eq!(hello["type"], "hello");
    assert_eq!(hello["running"], json!([]), "nothing runs at start");
    let welcome = json!({
        "type": "welcome", "server_version": "0.1.0", "node_id": NodeId::generate(), "account_id": owner,
        "heartbeat_interval_s": 5, "lease_ttl_s": 60,
    });
    write_frame(&mut w, &welcome).await.unwrap();
    let lease = json!({
        "type": "lease", "lease_id": lease_id, "epoch": 1, "account_id": owner, "deadline": "2099-01-01T00:00:00Z",
        "job": job,
    });
    write_frame(&mut w, &lease).await.unwrap();
    loop {
        let m: Value = tokio::time::timeout(wait, read_frame(&mut r, MAX_FRAME_LEN))
            .await
            .expect("the agent went silent")
            .unwrap()
            .expect("the agent closed the control stream");
        if m["type"] == "heartbeat" {
            write_frame(&mut w, &json!({"type": "heartbeat_ack", "seq": m["seq"]}))
                .await
                .unwrap();
            continue;
        }
        let done = m["type"] == "job_finished";
        {
            let mut s = seen.lock().unwrap();
            s.journal.push(format!("msg {}", m["type"].as_str().unwrap_or("?")));
            s.msgs.push(m);
        }
        if done {
            break;
        }
    }
    uploads.abort();
    // Keep answering heartbeats: the next answered one confirms the report (§6), and the run ends then.
    tokio::spawn(async move {
        while let Ok(Some(m)) = read_frame::<Value, _>(&mut r, MAX_FRAME_LEN).await {
            if m["type"] == "heartbeat" {
                let ack = json!({"type": "heartbeat_ack", "seq": m["seq"]});
                if write_frame(&mut w, &ack).await.is_err() {
                    return;
                }
            }
        }
    });
    let mut s = seen.lock().unwrap();
    std::mem::take(&mut *s)
}

/// Runs one lease of `job` through the whole agent with `driver`, and returns what the server saw.
async fn run_one_job<S>(driver: S, data_dir: &Path, job: Value, wait: Duration) -> Seen
where
    S: Sandbox + Startup + Send + Sync + 'static,
    S::Job: Send + Sync + 'static,
{
    let spec = BindSpec {
        relay_mode: RelayMode::Disabled,
        addrs: loopback(),
        port: 0,
        alpns: vec![PROTOCOL_ALPN_AGENT.to_vec()],
    };
    let server = bind_endpoint(SecretKey::generate(), &spec).await.unwrap();
    let addr = EndpointAddr::new(server.id()).with_ip_addr(server.bound_sockets()[0]);
    let owner = AccountId::generate();
    let lease_id = LeaseId::generate();
    let served = tokio::spawn(serve(server.clone(), owner, lease_id, job, wait));

    let uplink = Uplink::new();
    let offer = Offer {
        ready: true,
        platform: Platform::Linux,
        cpu: 4.0,
        memory_mb: 8192,
        disk_mb: 20_480,
        gpus: vec![],
    };
    let (_offers, offer_rx) = watch::channel(Some(offer));
    let executor = Executor::new(driver, owner, uplink.clone(), offer_rx, Arc::new(SystemClock));
    executor.startup().await;
    let executor = Arc::new(executor);
    let ttl = Duration::from_secs(45);
    let daemon = Daemon {
        shared: Shared {
            owner,
            agent_lease_ttl: ttl,
            watchdog: Watchdog::new(ttl),
            supervisor: executor.clone(),
            handler: executor.clone(),
            inventory: Arc::new(FixedInventory),
            load: Arc::new(ZeroLoad),
            inventory_interval: INVENTORY_INTERVAL,
            decisions: Arc::new(Semaphore::new(MAX_PENDING_DECISIONS)),
            uplink,
            ports: None,
            node: None,
            volumes: None,
        },
        connector: Arc::new(IrohConnector::new(
            SecretKey::generate(),
            RelayMode::Disabled,
            addr,
            loopback(),
        )),
        backoff_seed: 1,
        state_file: None,
        server_node_id: server.id().to_string(),
        agent_node_id: NodeId::generate().to_string(),
    };
    let (stop, stop_rx) = watch::channel(false);
    let (_net, net_rx) = mpsc::channel(1);
    let running = tokio::spawn(daemon.run(stop_rx, net_rx));
    let seen = served.await.unwrap();
    // The run ends once a heartbeat written after its JobFinished is answered (§6): at most one heartbeat
    // interval (5 s) later. Then nothing is listed.
    let confirmed = tokio::time::timeout(Duration::from_secs(20), async {
        while !executor.status().leases.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(confirmed.is_ok(), "the JobFinished was never confirmed");
    stop.send(true).unwrap();
    assert_eq!(
        tokio::time::timeout(wait, running).await.unwrap().unwrap(),
        DaemonExit::Shutdown
    );
    server.close().await;
    let jobs = data_dir.join("jobs");
    assert!(
        std::fs::read_dir(&jobs).map_or(true, |mut e| e.next().is_none()),
        "the job directory is removed"
    );
    seen
}

fn decode(b64: &Value) -> Vec<u8> {
    data_encoding::BASE64.decode(b64.as_str().unwrap().as_bytes()).unwrap()
}

/// What every variant checks: the message order, the logs, two outputs with matching sha256, uploads before
/// `JobFinished`.
fn check(seen: &Seen) {
    let kinds: Vec<&str> = seen.msgs.iter().map(|m| m["type"].as_str().unwrap()).collect();
    assert_eq!(kinds.first(), Some(&"lease_accepted"), "{kinds:?}");
    assert_eq!(kinds.get(1), Some(&"job_started"), "{kinds:?}");
    assert_eq!(kinds.last(), Some(&"job_finished"), "{kinds:?}");
    assert!(kinds[2..kinds.len() - 1].iter().all(|k| *k == "log_chunk"), "{kinds:?}");
    let (mut out, mut err, mut seqs) = (Vec::new(), Vec::new(), Vec::new());
    for m in seen.msgs.iter().filter(|m| m["type"] == "log_chunk") {
        assert_eq!(m["epoch"], 1);
        seqs.push(m["seq"].as_u64().unwrap());
        match m["stream"].as_str().unwrap() {
            "stdout" => out.extend(decode(&m["data_b64"])),
            _ => err.extend(decode(&m["data_b64"])),
        }
    }
    assert_eq!(
        seqs,
        (0..seqs.len() as u64).collect::<Vec<_>>(),
        "seq from the pump, across both streams"
    );
    assert!(String::from_utf8_lossy(&out).contains("hello from the job"), "{out:?}");
    assert!(String::from_utf8_lossy(&err).contains("a warning"), "{err:?}");
    let finished = seen.msgs.last().unwrap();
    assert_eq!(finished["outcome"], "exited", "{finished}");
    assert_eq!(finished["exit_code"], 0, "{finished}");
    let outputs = finished["outputs"].as_array().unwrap();
    let listed: Vec<(&str, u64, &str)> = outputs
        .iter()
        .map(|o| {
            (
                o["path"].as_str().unwrap(),
                o["size"].as_u64().unwrap(),
                o["sha256"].as_str().unwrap(),
            )
        })
        .collect();
    let b = vec![0u8; B_LEN];
    let expect = [
        ("a.txt", ALPHA.len() as u64, hex(&Sha256::digest(ALPHA))),
        ("sub/b.bin", B_LEN as u64, hex(&Sha256::digest(&b))),
    ];
    assert_eq!(listed.len(), 2, "{listed:?}");
    for ((path, size, sha), (want_path, want_size, want_sha)) in listed.iter().zip(expect.iter()) {
        assert_eq!((*path, *size), (*want_path, *want_size));
        assert!(sha.eq_ignore_ascii_case(want_sha), "{path}: {sha} != {want_sha}");
        let (header_sha, bytes) = &seen.uploads[*path];
        assert_eq!(header_sha, want_sha, "the upload header's sha256");
        assert_eq!(hex(&Sha256::digest(bytes)), *want_sha, "the uploaded bytes");
    }
    let at = |line: &str| seen.journal.iter().position(|l| l == line).unwrap();
    assert!(at("upload a.txt") < at("msg job_finished"), "{:?}", seen.journal);
    assert!(at("upload sub/b.bin") < at("msg job_finished"), "{:?}", seen.journal);
}

// ---------------------------------------------------------------------------------------------------------------
// With the fake podman.

/// A data disk far above the §9 floor (the test's tmpfs may be small).
#[derive(Debug)]
struct RoomyDisk;

impl FreeSpace for RoomyDisk {
    fn space(&self, _: &Path) -> std::io::Result<DiskSpace> {
        Ok(DiskSpace {
            free_bytes: 90 << 30,
            total_bytes: 100 << 30,
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_runs_end_to_end_with_fake_podman() {
    let state = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let cg = tempfile::tempdir().unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    symlink(fixtures.join("fake-podman"), state.path().join("podman")).unwrap();
    symlink(fixtures.join("fake-skopeo"), state.path().join("skopeo")).unwrap();
    // The "container": the fake podman runs this on the host at `podman start --attach`, so it writes the outputs
    // into the one job directory itself.
    let job_sh = format!(
        "echo 'hello from the job'\necho 'a warning' >&2\nfor d in '{jobs}'/*/outputs; do\n  printf alpha > \"$d/a.txt\"\n  \
         mkdir -p \"$d/sub\"\n  head -c {B_LEN} /dev/zero > \"$d/sub/b.bin\"\n  ln -s /etc/hostname \"$d/link\"\ndone\n",
        jobs = data.path().join("jobs").display(),
    );
    std::fs::write(state.path().join("job.sh"), job_sh).unwrap();
    std::fs::write(data.path().join("shim"), b"\x7fELF shim").unwrap();
    let runner = || SystemRunner::with_timeout(Duration::from_secs(30));
    let engine = PodmanEngine::new(state.path().join("podman").to_str().unwrap(), runner(), runner())
        .with_skopeo(state.path().join("skopeo").to_str().unwrap());
    let mut cfg = DriverConfig::new(data.path(), Platform::Wsl2, data.path().join("shim"), true);
    cfg.free_space = Arc::new(RoomyDisk);
    let driver = PodmanDriver::new(cfg, engine, FsCgroups::new(cg.path()), NoEgress);
    let job = json!({
        "name": "e2e", "image": "docker.io/library/busybox:1.36.1", "command": ["sh", "-c", "true"],
        "env": {"API_TOKEN": "s3cr3t-value-example"},
        "resources": {"cpu": 1, "memory_mb": 256, "disk_mb": 1024},
    });
    let seen = run_one_job(driver, data.path(), job, Duration::from_secs(60)).await;
    check(&seen);
    assert!(!seen.uploads.contains_key("link"), "a symlink is never uploaded (SI-9)");
}

// ---------------------------------------------------------------------------------------------------------------
// With real Podman (a test node).

fn shim() -> PathBuf {
    std::env::var_os("P2PC_SHIM").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/x86_64-unknown-linux-musl/release/p2pc-shim"),
        PathBuf::from,
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs real Podman on a test node; see the module docs"]
async fn a_job_runs_end_to_end_with_real_podman() {
    let platform = p2pc_agent::platform::detect(&Host::system());
    let cgroups = match platform {
        Platform::Wsl2 => HostCgroups::Fs(FsCgroups::system()),
        Platform::Linux => {
            let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
            let service = user_service_cgroup(&own).expect("run as a user with a systemd user session (p2pc)");
            HostCgroups::Systemd(SystemdCgroups::new(
                SystemRunner::default(),
                Path::new("/sys/fs/cgroup").join(service),
            ))
        }
    };
    let shim = shim();
    assert!(
        shim.is_file(),
        "build the shim first, or set P2PC_SHIM: {}",
        shim.display()
    );
    let data = tempfile::tempdir().unwrap();
    let cfg = DriverConfig::new(data.path(), platform, shim, true);
    let driver = PodmanDriver::new(cfg, PodmanEngine::system("podman", PULL_TIMEOUT), cgroups, NoEgress);
    let image = std::env::var("P2PC_TEST_IMAGE")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "docker.io/library/busybox:1.36.1".into());
    let script = format!(
        "echo 'hello from the job'; echo 'a warning' >&2; printf alpha > /outputs/a.txt; mkdir -p /outputs/sub; \
         head -c {B_LEN} /dev/zero > /outputs/sub/b.bin; ln -s /etc/hostname /outputs/link"
    );
    let job = json!({
        "name": "e2e", "image": image, "command": ["sh", "-c", script],
        "env": {"GREETING": "hello"},
        "resources": {"cpu": 1, "memory_mb": 256, "disk_mb": 1024},
    });
    // The first run pulls the image.
    let seen = run_one_job(driver, data.path(), job, Duration::from_secs(900)).await;
    eprintln!("{:#?}", seen.journal);
    check(&seen);
    assert!(!seen.uploads.contains_key("link"), "a symlink is never uploaded (SI-9)");
}
