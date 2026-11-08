// SPDX-License-Identifier: Apache-2.0

//! The sandbox driver against **real Podman**. Every test is `#[ignore]`: they need a test node (the rootless
//! Linux user `p2pc`, or root inside the `p2pc-node` WSL2 distro), Podman ≥ 4.9 and a registry to pull from.
//!
//! On the test node:
//!
//! ```text
//! cargo build -p p2pc-shim --target x86_64-unknown-linux-musl --release
//! cargo test -p p2pc-agent --test podman_real -- --ignored --test-threads=1
//! ```
//!
//! Environment:
//! - `P2PC_SHIM`: the shim binary (default: the musl release build above);
//! - `P2PC_TEST_IMAGE`: the CPU image (default `docker.io/library/busybox:1.36.1`; it needs `sh`, `nc`, `dd`);
//! - `P2PC_TEST_CAP_IMAGE`: an image no other test uses, for the image-cap test (default
//!   `docker.io/library/alpine:3.20.3`);
//! - `P2PC_TEST_GPU_IMAGE`, `P2PC_TEST_GPU_UUID` and optionally `P2PC_TEST_GPU_COMMAND` (default
//!   `/cuda-samples/vectorAdd`): the GPU test, for example with `nvcr.io/nvidia/k8s/cuda-sample:vectoradd-cuda12.5.0`
//!   and the UUID from `nvidia-smi -L`. Without them the GPU test fails with a message saying what to set.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]

use std::path::{Path, PathBuf};

use p2pc_agent::host::Host;
use p2pc_agent::platform;
use p2pc_agent::runner::SystemRunner;
use p2pc_agent::sandbox::cgroup::{FsCgroups, HostCgroups, SystemdCgroups, user_service_cgroup};
use p2pc_agent::sandbox::engine::{Engine, PULL_TIMEOUT, PodmanEngine};
use p2pc_agent::sandbox::{
    CancelHandle, DriverConfig, Finished, GpuRef, LeaseContext, LeaseReport, NoEgress, PodmanDriver, Sandbox,
    SandboxEvent, error_code, run_lease,
};
use p2pc_proto::api::{Egress, InputFile, JobSpec, LogStream, Outputs, Placement, Platform, Resources, Retry};
use p2pc_proto::ids::{AccountId, LeaseId};
use p2pc_proto::protocol::Outcome;
use tokio::sync::mpsc;

type RealDriver = PodmanDriver<PodmanEngine<SystemRunner>, HostCgroups<SystemRunner>>;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn shim() -> PathBuf {
    std::env::var_os("P2PC_SHIM").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/x86_64-unknown-linux-musl/release/p2pc-shim"),
        PathBuf::from,
    )
}

fn driver(data: &Path, offerable_gpus: Vec<String>) -> RealDriver {
    driver_with(data, offerable_gpus, |_| {})
}

fn driver_with(data: &Path, offerable_gpus: Vec<String>, tweak: impl FnOnce(&mut DriverConfig)) -> RealDriver {
    let platform = platform::detect(&Host::system());
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
    // The test node is set up for its §9.0 profile (`p2pc-agent doctor` reports it ready).
    let mut cfg = DriverConfig::new(data, platform, shim, true);
    cfg.offerable_gpus = offerable_gpus;
    cfg.smoke_image = env_or("P2PC_TEST_IMAGE", "docker.io/library/busybox:1.36.1");
    tweak(&mut cfg);
    PodmanDriver::new(cfg, PodmanEngine::system("podman", PULL_TIMEOUT), cgroups, NoEgress)
}

fn job(command: &[&str]) -> JobSpec {
    JobSpec {
        name: None,
        image: env_or("P2PC_TEST_IMAGE", "docker.io/library/busybox:1.36.1"),
        command: command.iter().map(|s| (*s).to_string()).collect(),
        env: [("GREETING".to_string(), "hello".to_string())].into_iter().collect(),
        files: vec![InputFile {
            path: "/inputs/data.txt".into(),
            content_b64: data_encoding::BASE64.encode(b"input-ok\n"),
        }],
        resources: Resources {
            cpu: 1.0,
            memory_mb: 256,
            gpu: 0,
            disk_mb: 1024,
        },
        timeout_s: 300,
        egress: Egress::default(),
        outputs: Outputs { max_mb: 16 },
        placement: Placement::default(),
        retry: Retry::default(),
        idempotency_key: None,
    }
}

struct Ran {
    finished: Finished,
    stdout: String,
    stderr: String,
    outputs: Vec<(String, u64)>,
}

async fn run(d: &RealDriver, job: JobSpec, gpu: Option<GpuRef>) -> Ran {
    let owner = AccountId::generate();
    let lease = LeaseContext {
        lease_id: LeaseId::generate(),
        epoch: 1,
        account_id: owner,
        job,
        gpu,
    };
    let (tx, mut rx) = mpsc::channel(256);
    let logs = tokio::spawn(async move {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        while let Some(ev) = rx.recv().await {
            if let SandboxEvent::Log(c) = ev {
                match c.stream {
                    LogStream::Stdout => out.extend_from_slice(&c.data),
                    LogStream::Stderr => err.extend_from_slice(&c.data),
                }
            }
        }
        (
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    });
    let report = run_lease(d, &owner, lease, tx, CancelHandle::new()).await;
    d.drain_background().await;
    let (stdout, stderr) = logs.await.unwrap();
    eprintln!("stdout:\n{stdout}\nstderr:\n{stderr}");
    match report {
        LeaseReport::Finished { finished, outputs } => Ran {
            outputs: outputs.files.iter().map(|f| (f.path.clone(), f.size)).collect(),
            finished,
            stdout,
            stderr,
        },
        LeaseReport::Rejected(r) => panic!("rejected: {r}"),
    }
}

#[tokio::test]
#[ignore = "needs real Podman on a test node; see the module docs"]
async fn cpu_job_round_trip() {
    let data = tempfile::tempdir().unwrap();
    let d = driver(data.path(), Vec::new());
    let ran = run(
        &d,
        job(&[
            "sh",
            "-c",
            "echo \"$GREETING from $(id -u)\"; cat /inputs/data.txt; echo 42 > /outputs/answer; echo to-stderr >&2",
        ]),
        None,
    )
    .await;
    assert_eq!(
        (ran.finished.outcome, ran.finished.exit_code),
        (Outcome::Exited, Some(0)),
        "{:?}",
        ran.finished
    );
    assert!(ran.stdout.contains("hello from 0"), "{}", ran.stdout);
    assert!(ran.stdout.contains("input-ok"));
    assert!(ran.stderr.contains("to-stderr"));
    assert_eq!(ran.outputs, [("answer".to_string(), 3)]);
    assert!(
        std::fs::read_dir(data.path().join("jobs")).unwrap().next().is_none(),
        "job dir removed"
    );
}

/// Writes `line` to the user's journal with `systemd-cat` or `logger`; `false` if neither could.
fn write_to_journal(line: &str) -> bool {
    use std::process::{Command, Stdio};
    let cat = Command::new("systemd-cat")
        .args(["--identifier=p2pc-t10m", "echo", line])
        .stdout(Stdio::null())
        .status();
    if cat.is_ok_and(|s| s.success()) {
        return true;
    }
    Command::new("logger")
        .args(["--tag", "p2pc-t10m", line])
        .status()
        .is_ok_and(|s| s.success())
}

/// The user's journal since `since` (epoch seconds) as JSON, or `None` when `journalctl` cannot be run.
fn journal_since(since: u64) -> Option<String> {
    use std::process::Command;
    let uid = Command::new("id").arg("-u").output().ok()?;
    let uid = String::from_utf8(uid.stdout).ok()?;
    let out = Command::new("journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "--since",
            &format!("@{since}"),
            &format!("_UID={}", uid.trim()),
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// T10m: a job writes one line to stdout and one to stderr, in a container created with the agent's own argument
/// builder (`create_argv`, through the driver) and `--log-driver=none`: both lines reach the job's log, each on its
/// own stream, and nothing reaches Podman's log store or the host's system journal, which is where rootless Podman's
/// `log_driver` and `events_logger` point on a systemd host. The lines are built inside the container, so they are
/// not in any command line either.
///
/// The journal part is only trusted if the journal can be read: a sentinel line is written to the user's journal
/// first, and if the same query cannot show it (no systemd, as in the WSL2 distro, no `systemd-cat`/`logger`, or a
/// journal that the user cannot read), that part is skipped with the reason and never passes by reading nothing.
/// Podman 6.1.4 rootless (Arch) and 4.9.3 as root (WSL2) were checked by hand for the same sequence.
#[tokio::test]
#[ignore = "needs real Podman on a test node; see the module docs"]
async fn a_jobs_output_stays_out_of_the_journal() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let id = AccountId::generate().to_string();
    let sentinel = format!("t10m-sentinel-{id}");
    let sentinel_written = write_to_journal(&sentinel);

    let data = tempfile::tempdir().unwrap();
    let d = driver(data.path(), Vec::new());
    let mut j = job(&["sh", "-c", "echo \"out-$MARK\"; echo \"err-$MARK\" >&2"]);
    j.env.insert("MARK".into(), format!("t10m-marker-{id}"));
    let ran = run(&d, j, None).await;
    let (out, err) = (format!("out-t10m-marker-{id}"), format!("err-t10m-marker-{id}"));
    assert_eq!(ran.finished.outcome, Outcome::Exited, "{:?}", ran.finished);
    assert!(
        ran.stdout.contains(&out) && !ran.stdout.contains(&err),
        "attach works with --log-driver=none, stdout: {}",
        ran.stdout
    );
    assert!(
        ran.stderr.contains(&err) && !ran.stderr.contains(&out),
        "attach works with --log-driver=none, stderr: {}",
        ran.stderr
    );

    let marker = format!("t10m-marker-{id}");
    let Some(journal) = journal_since(since) else {
        eprintln!("SKIPPED the journal check: journalctl cannot be run here; only the job log was checked");
        return;
    };
    if !sentinel_written || !journal.contains(&sentinel) {
        eprintln!(
            "SKIPPED the journal check: the sentinel line (written: {sentinel_written}) is not in what journalctl shows, \
             so an empty answer would prove nothing; only the job log was checked"
        );
        return;
    }
    assert!(
        !journal.contains(&marker),
        "the job's output reached the system journal"
    );
    // Podman's own events (`container init/start/died/remove`, `image pull`) stay out of it too.
    assert!(
        !journal.contains("PODMAN_EVENT"),
        "Podman events reached the system journal"
    );
}

/// SI-3: with no egress list the container has no network: a TCP connect to 1.1.1.1:443 fails. (The one real
/// address in the test suite, named by the spec.)
#[tokio::test]
#[ignore = "needs real Podman on a test node; see the module docs"]
async fn si3_network_none_blocks_the_internet() {
    let data = tempfile::tempdir().unwrap();
    let d = driver(data.path(), Vec::new());
    let ran = run(
        &d,
        job(&[
            "sh",
            "-c",
            "if nc -w 3 1.1.1.1 443 </dev/null; then echo CONNECTED; else echo BLOCKED; fi; ip -o link 2>/dev/null || true",
        ]),
        None,
    )
    .await;
    assert_eq!(ran.finished.outcome, Outcome::Exited);
    assert!(ran.stdout.contains("BLOCKED"), "{}", ran.stdout);
    assert!(!ran.stdout.contains("CONNECTED"));
}

#[tokio::test]
#[ignore = "needs real Podman on a test node; see the module docs"]
async fn memory_limit_is_reported_from_the_lease_cgroup() {
    let data = tempfile::tempdir().unwrap();
    let d = driver(data.path(), Vec::new());
    let mut j = job(&[
        "sh",
        "-c",
        "dd if=/dev/zero of=/tmp/fill bs=1M count=600; echo survived",
    ]);
    j.resources.memory_mb = 128;
    let ran = run(&d, j, None).await;
    assert_eq!(
        (ran.finished.outcome, ran.finished.error.as_deref()),
        (Outcome::Error, Some(error_code::MEMORY_LIMIT)),
        "{:?}",
        ran.finished
    );
    assert!(ran.finished.stats.oom_kill > 0 || ran.finished.exit_code == Some(137));
}

#[tokio::test]
#[ignore = "needs real Podman on a test node; see the module docs"]
async fn pids_limit_stops_a_fork_bomb() {
    let data = tempfile::tempdir().unwrap();
    let d = driver(data.path(), Vec::new());
    // A bomb of 3000 background `sleep 30` against --pids-limit=2048: the forks past the limit fail. The first real
    // run (WSL2, 256 MiB) hit the memory limit first: 2048 busybox processes do not fit in 256 MiB. With 4 GiB the
    // pids limit is what stops it.
    //
    // The main process must stay alive for many disk ticks (every 2 s), so the agent reads `pids.events` while
    // Podman's child cgroup still exists, and it must not fork after the bomb (a fork at the limit would fail and
    // end the job with a non-zero exit). So the bomb runs in a background subshell, and the main shell only
    // `wait`s (a builtin) for one `sleep 10` started *before* the bomb, then exits 0. The job's outcome is the
    // proof that the main process survived the bomb.
    let mut j = job(&[
        "sh",
        "-c",
        "sleep 10 & k=$!; (while :; do sleep 30 & done) 2>/dev/null & wait $k; exit 0",
    ]);
    j.resources.memory_mb = 4096;
    let ran = run(&d, j, None).await;
    assert_eq!(
        (ran.finished.outcome, ran.finished.exit_code),
        (Outcome::Exited, Some(0)),
        "the main process did not survive the bomb to a clean exit: {:?}",
        ran.finished
    );
    assert!(
        ran.finished.stats.pids_max > 0,
        "the lease cgroup's pids.events shows no `max` event: {:?}",
        ran.finished
    );
}

#[tokio::test]
#[ignore = "needs real Podman and an NVIDIA GPU with a CDI spec; see the module docs"]
async fn gpu_vector_add() {
    let (Ok(image), Ok(uuid)) = (
        std::env::var("P2PC_TEST_GPU_IMAGE"),
        std::env::var("P2PC_TEST_GPU_UUID"),
    ) else {
        panic!("set P2PC_TEST_GPU_IMAGE (a CUDA vectorAdd image) and P2PC_TEST_GPU_UUID (from `nvidia-smi -L`)");
    };
    let command = env_or("P2PC_TEST_GPU_COMMAND", "/cuda-samples/vectorAdd");
    let data = tempfile::tempdir().unwrap();
    let d = driver(data.path(), vec![uuid.clone()]);
    let mut j = job(&[&command]);
    j.image = image;
    j.resources.gpu = 1;
    j.resources.memory_mb = 2048;
    let ran = run(&d, j, Some(GpuRef { uuid })).await;
    assert_eq!(
        (ran.finished.outcome, ran.finished.exit_code),
        (Outcome::Exited, Some(0)),
        "{:?}",
        ran.finished
    );
    assert!(ran.stdout.contains("PASSED"), "{}", ran.stdout);
}

/// §9 "Images", as behaviour: an image over the cap is refused and nothing is left behind, whichever path the node
/// takes (skopeo, `podman manifest inspect`, or pull-then-check). The path taken is printed.
///
/// `P2PC_TEST_CAP_IMAGE` (default `docker.io/library/alpine:3.20.3`) should be an image the other tests do not use,
/// so that "nothing left behind" is checked against an image that was not present before.
#[tokio::test]
#[ignore = "needs real Podman and registry access on a test node; see the module docs"]
async fn an_image_over_the_cap_is_refused_and_nothing_is_left_behind() {
    let image = env_or("P2PC_TEST_CAP_IMAGE", "docker.io/library/alpine:3.20.3");
    let engine = PodmanEngine::system("podman", PULL_TIMEOUT);
    let present_before = engine.image_exists(&image).await.unwrap();
    match engine.manifest_size(&image).await {
        Ok(size) => eprintln!("path: manifest read before the pull ({size} bytes)"),
        Err(e) => eprintln!("path: pull, then check ({e})"),
    }
    let data = tempfile::tempdir().unwrap();
    let d = driver_with(data.path(), Vec::new(), |c| c.max_image_mb = 0);
    let mut j = job(&["true"]);
    j.image = image.clone();
    let ran = run(&d, j, None).await;
    assert_eq!(
        (ran.finished.outcome, ran.finished.error.as_deref()),
        (Outcome::Error, Some(error_code::IMAGE_TOO_LARGE))
    );
    if present_before {
        eprintln!(
            "NOTE: {image} was already present, so only the refusal is checked; pick another P2PC_TEST_CAP_IMAGE"
        );
    } else {
        assert!(
            !engine.image_exists(&image).await.unwrap(),
            "the refused image was left in local storage"
        );
    }
    assert!(
        engine.lease_containers().await.unwrap().is_empty(),
        "no container is left"
    );
    assert!(
        std::fs::read_dir(data.path().join("jobs")).map_or(true, |mut e| e.next().is_none()),
        "no job directory is left"
    );
}

#[tokio::test]
#[ignore = "needs real Podman on a test node; see the module docs"]
async fn smoke_container() {
    let data = tempfile::tempdir().unwrap();
    let d = driver(data.path(), Vec::new());
    let smoke = d.smoke().await;
    assert!(smoke.ok, "{smoke:?}");
}
