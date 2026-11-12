// SPDX-License-Identifier: Apache-2.0

//! The sandbox driver end to end against a fake `podman` (`tests/fixtures/fake-podman`): real processes, real
//! pipes, the real [`SystemRunner`], a fake cgroup tree. The fake records every argv, so these tests also check the
//! exact `podman create` argv the driver sends (SI-2) and the env-file lifetime. Real Podman: `podman_real.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use p2pc_agent::runner::SystemRunner;
use p2pc_agent::sandbox::argv::{ArgvParams, create_argv};
use p2pc_agent::sandbox::cgroup::FsCgroups;
use p2pc_agent::sandbox::disk::{DiskSpace, FreeSpace};
use p2pc_agent::sandbox::engine::PodmanEngine;
use p2pc_agent::sandbox::logs::LOG_CAP_BYTES;
use p2pc_agent::sandbox::{
    CancelHandle, DriverConfig, LeaseContext, LeaseReport, NoEgress, PodmanDriver, SandboxEvent, error_code, run_lease,
};
use p2pc_proto::api::{Egress, InputFile, JobSpec, LogStream, Outputs, Placement, Platform, Resources, Retry};
use p2pc_proto::ids::{AccountId, LeaseId};
use p2pc_proto::protocol::Outcome;
use tempfile::TempDir;
use tokio::sync::mpsc;

type Driver = PodmanDriver<PodmanEngine<SystemRunner>, FsCgroups>;

/// A data disk far above the §9 floor. The tests never read the host's real free space: their temporary
/// directories may sit on a small tmpfs (on the build machine `$TMPDIR` is one, with less free space than the 5 GiB
/// floor), and then the driver rightly refuses every lease with `insufficient_capacity`.
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

struct Fake {
    state: TempDir,
    data: TempDir,
    cg: TempDir,
    owner: AccountId,
}

impl Fake {
    fn new(job_sh: &str) -> Self {
        let state = tempfile::tempdir().unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-podman");
        // A symlink, not a copy: nothing is ever executed while a test still holds it open for writing.
        symlink(&fixture, state.path().join("podman")).unwrap();
        fs::write(state.path().join("job.sh"), job_sh).unwrap();
        let data = tempfile::tempdir().unwrap();
        fs::write(data.path().join("shim"), b"\x7fELF shim").unwrap();
        Self {
            state,
            data,
            cg: tempfile::tempdir().unwrap(),
            owner: AccountId::generate(),
        }
    }

    /// Puts the fake `skopeo` where the driver looks for it. Without this call there is no skopeo at all, even on a
    /// host that has a real one, so the tests never reach a registry.
    fn with_skopeo(self) -> Self {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-skopeo");
        symlink(&fixture, self.state.path().join("skopeo")).unwrap();
        self
    }

    fn driver(&self) -> Driver {
        let runner = || SystemRunner::with_timeout(Duration::from_secs(30));
        let engine = PodmanEngine::new(self.state.path().join("podman").to_str().unwrap(), runner(), runner())
            .with_events_backend("file")
            .with_skopeo(self.state.path().join("skopeo").to_str().unwrap());
        let mut cfg = DriverConfig::new(self.data.path(), Platform::Wsl2, self.data.path().join("shim"), true);
        cfg.free_space = Arc::new(RoomyDisk);
        PodmanDriver::new(cfg, engine, FsCgroups::new(self.cg.path()), NoEgress)
    }

    fn lease(&self) -> LeaseContext {
        let mut env = BTreeMap::new();
        env.insert("API_TOKEN".to_string(), "s3cr3t-value".to_string());
        LeaseContext {
            lease_id: LeaseId::generate(),
            epoch: 1,
            account_id: self.owner,
            job: JobSpec {
                name: None,
                image: "docker.io/library/python:3.12-slim".into(),
                command: vec!["python".into(), "-c".into(), "print(6*7)".into()],
                env,
                files: vec![InputFile {
                    path: "/inputs/data.csv".into(),
                    content_b64: data_encoding::BASE64.encode(b"1,2\n"),
                }],
                resources: Resources {
                    cpu: 2.0,
                    memory_mb: 4096,
                    gpu: 0,
                    disk_mb: 10_240,
                },
                timeout_s: 60,
                egress: Egress::default(),
                outputs: Outputs { max_mb: 16 },
                placement: Placement::default(),
                retry: Retry::default(),
                idempotency_key: None,
                kind: p2pc_proto::api::JobKind::Batch,
                service: None,
                volumes: Vec::new(),
                inputs: Vec::new(),
                template: None,
            },
            gpu: None,
        }
    }

    /// Every recorded `podman` argv, in order.
    fn calls(&self) -> Vec<Vec<String>> {
        let raw = fs::read_to_string(self.state.path().join("calls")).unwrap_or_default();
        raw.split('\u{1e}')
            .filter(|c| !c.is_empty())
            .map(|c| c.split('\u{1f}').filter(|a| !a.is_empty()).map(String::from).collect())
            .collect()
    }

    /// The global options of every `podman` call, one entry per call, in order.
    fn globals(&self) -> Vec<String> {
        let raw = fs::read_to_string(self.state.path().join("globals")).unwrap_or_default();
        raw.lines().map(|l| l.trim().to_string()).collect()
    }

    fn job_dir(&self, id: &LeaseId) -> PathBuf {
        self.data.path().join("jobs").join(id.to_string())
    }
}

/// Runs a lease while a consumer task counts the log bytes (as T05b/T10 would spool them).
async fn run(fake: &Fake, lease: LeaseContext) -> (LeaseReport, Vec<SandboxEvent>, u64, usize) {
    let driver = fake.driver();
    let (tx, mut rx) = mpsc::channel(64);
    let consumer = tokio::spawn(async move {
        let (mut small, mut bytes, mut markers) = (Vec::new(), 0u64, 0usize);
        while let Some(ev) = rx.recv().await {
            match &ev {
                SandboxEvent::Log(c) if c.marker => markers += 1,
                SandboxEvent::Log(c) => bytes += c.data.len() as u64,
                _ => {}
            }
            // Keep the events of small jobs for inspection, never 64 MiB of them.
            if small.len() < 64 {
                small.push(ev);
            }
        }
        (small, bytes, markers)
    });
    let report = run_lease(&driver, &fake.owner, lease, tx, CancelHandle::new()).await;
    driver.drain_background().await;
    let (events, bytes, markers) = consumer.await.unwrap();
    (report, events, bytes, markers)
}

fn finished(r: LeaseReport) -> p2pc_agent::sandbox::Finished {
    match r {
        LeaseReport::Finished { finished, .. } => finished,
        LeaseReport::Rejected(r) => panic!("rejected: {r}"),
    }
}

#[tokio::test]
async fn a_cpu_job_through_the_podman_cli() {
    let fake = Fake::new("echo 42; echo warning >&2; exit 3\n");
    let lease = fake.lease();
    let id = lease.lease_id;
    let (report, events, _, _) = run(&fake, lease).await;
    let f = finished(report);
    assert_eq!((f.outcome, f.exit_code, f.error), (Outcome::Exited, Some(3), None));

    let logs: Vec<(LogStream, Vec<u8>)> = events
        .iter()
        .filter_map(|e| match e {
            SandboxEvent::Log(c) => Some((c.stream, c.data.clone())),
            _ => None,
        })
        .collect();
    assert!(logs.contains(&(LogStream::Stdout, b"42\n".to_vec())), "{logs:?}");
    assert!(logs.contains(&(LogStream::Stderr, b"warning\n".to_vec())), "{logs:?}");

    let calls = fake.calls();
    let verbs: Vec<&str> = calls.iter().map(|c| c[0].as_str()).collect();
    assert_eq!(
        verbs[..6],
        ["image", "manifest", "pull", "image", "create", "start"],
        "{verbs:?}"
    );
    assert_eq!(verbs.last(), Some(&"rm"));
    // T10m: Podman's events stay out of the journal on every command, the attached `start` included; and the
    // container keeps no log of its own, the agent reads the output by attaching.
    let globals = fake.globals();
    assert_eq!(globals.len(), calls.len());
    assert!(globals.iter().all(|g| g == "--events-backend=file"), "{globals:?}");
    let create = calls.iter().find(|c| c[0] == "create").unwrap();
    assert!(create.iter().any(|a| a == "--log-driver=none"), "{create:?}");
    let image = "docker.io/library/python:3.12-slim";
    assert_eq!(calls[0], ["image", "exists", "--", image]);
    assert_eq!(
        calls[1],
        ["manifest", "inspect", "--", image],
        "the size is read before the pull"
    );
    assert_eq!(calls[2], ["pull", "--quiet", "--", image]);
    assert_eq!(calls[5], ["start", "--attach", "--", &format!("p2pc-{id}")]);
    // §9: no `podman` command, the attached `start` included, sees a host proxy variable.
    let env_names = fs::read_to_string(fake.state.path().join("env_names")).unwrap();
    assert!(env_names.lines().any(|n| n == "LC_ALL"), "the probe works");
    for name in env_names.lines() {
        assert!(!p2pc_agent::runner::PROXY_ENV_VARS.contains(&name), "podman got {name}");
    }
    assert!(calls[4].contains(&"--http-proxy=false".to_string()));

    // SI-2 end to end: the argv Podman received is exactly the builder's.
    let dir = fake.job_dir(&id);
    let job = fake.lease().job;
    let cgroup = format!("/p2pc/{id}");
    let expected = create_argv(&ArgvParams {
        platform: Platform::Wsl2,
        gvisor: false,
        lease_id: &id,
        job_dir: &dir,
        env_file: &dir.join("env"),
        cgroup_parent: &cgroup,
        memory_mb: 4096,
        cpu: 2.0,
        disk_mb: 10_240,
        gpu: None,
        image: &job.image,
        command: &job.command,
        volumes: &[],
    })
    .unwrap();
    assert_eq!(calls[4], expected);

    // The env file existed (0600) when Podman read it, and nothing of it is left.
    assert_eq!(
        fs::read_to_string(fake.state.path().join("env_at_create")).unwrap(),
        "API_TOKEN=s3cr3t-value\n"
    );
    assert!(!dir.exists(), "the job directory is gone");
    assert!(
        !fake.cg.path().join("p2pc").join(id.to_string()).exists(),
        "the cgroup is gone"
    );
}

/// §9 "Logs on the node": a job printing more than 64 MiB still finishes, because the pipe keeps draining, and at
/// most 64 MiB plus one marker are passed on.
#[tokio::test]
async fn more_than_64_mib_of_logs_still_finishes() {
    let fake = Fake::new("head -c 70000000 /dev/zero; echo done >&2; exit 0\n");
    let (report, _, bytes, markers) = run(&fake, fake.lease()).await;
    let f = finished(report);
    assert_eq!((f.outcome, f.exit_code), (Outcome::Exited, Some(0)));
    assert_eq!(bytes, LOG_CAP_BYTES, "exactly the cap was passed on");
    assert_eq!(markers, 1, "one truncation marker");
    assert!(f.logs.truncated);
    assert_eq!(
        f.logs.bytes_kept + f.logs.bytes_discarded,
        70_000_000 + 5,
        "everything was read"
    );
}

#[tokio::test]
async fn a_failed_create_is_cleaned_up() {
    let fake = Fake::new("exit 0\n");
    fs::write(fake.state.path().join("create_fails"), b"").unwrap();
    let lease = fake.lease();
    let id = lease.lease_id;
    let (report, _, _, _) = run(&fake, lease).await;
    let f = finished(report);
    assert_eq!(
        (f.outcome, f.error.as_deref()),
        (Outcome::Error, Some(error_code::CREATE_FAILED))
    );
    let calls = fake.calls();
    assert_eq!(calls.last().unwrap()[0], "rm", "{calls:?}");
    assert!(!fake.job_dir(&id).exists());
    assert!(!fake.cg.path().join("p2pc").join(id.to_string()).exists());
}

/// §9 "Podman failures are not job exits": `podman start` failing with 125 before the container ran is
/// `start_failed`, never `exited(125)`. A job that itself exits 125 or 127 is still `exited`.
#[tokio::test]
async fn a_container_that_never_started_is_start_failed() {
    let fake = Fake::new("exit 0\n");
    fs::write(fake.state.path().join("start_fails"), b"").unwrap();
    let lease = fake.lease();
    let id = lease.lease_id;
    let f = finished(run(&fake, lease).await.0);
    assert_eq!(
        (f.outcome, f.exit_code, f.error.as_deref()),
        (Outcome::Error, None, Some(error_code::START_FAILED))
    );
    assert_eq!(fake.calls().last().unwrap()[0], "rm");
    assert!(!fake.job_dir(&id).exists());

    for code in [125, 126, 127] {
        let fake = Fake::new(&format!("echo ran; exit {code}\n"));
        let f = finished(run(&fake, fake.lease()).await.0);
        assert_eq!(
            (f.outcome, f.exit_code),
            (Outcome::Exited, Some(code)),
            "the job's own {code}"
        );
    }
}

/// §9 "Images": the manifest's layer sizes are read first, and an image over the cap is never pulled.
#[tokio::test]
async fn an_image_over_the_cap_is_never_pulled() {
    // Through `podman manifest inspect` (no skopeo; a manifest Podman can read).
    let fake = Fake::new("exit 0\n");
    fs::write(fake.state.path().join("manifest_size"), (30u64 << 30).to_string()).unwrap();
    let verbs = refused_over_cap(&fake).await;
    assert!(verbs.contains(&"manifest".to_string()), "{verbs:?}");
    assert!(!verbs.contains(&"pull".to_string()), "{verbs:?}");
}

/// §9 "Images", skopeo first: it reads the single-image OCI manifest Podman 4.9 cannot, and nothing is pulled.
#[tokio::test]
async fn skopeo_reads_what_podman_4_9_cannot_and_nothing_is_pulled() {
    let fake = Fake::new("exit 0\n").with_skopeo();
    fs::write(fake.state.path().join("podman_manifest_unsupported"), b"").unwrap();
    fs::write(fake.state.path().join("manifest_size"), (30u64 << 30).to_string()).unwrap();
    let verbs = refused_over_cap(&fake).await;
    assert!(verbs.contains(&"skopeo".to_string()), "{verbs:?}");
    assert!(
        !verbs.contains(&"manifest".to_string()),
        "podman was not needed: {verbs:?}"
    );
    assert!(!verbs.contains(&"pull".to_string()), "{verbs:?}");
    let skopeo = fake.calls().into_iter().find(|c| c[0] == "skopeo").unwrap();
    assert_eq!(
        skopeo,
        [
            "skopeo",
            "inspect",
            "--raw",
            "--",
            "docker://docker.io/library/python:3.12-slim"
        ]
    );
}

/// §9 "Images", the fallback: neither tool reads the manifest (no skopeo, Podman 4.9 on a single OCI manifest).
/// The image is pulled, found over the cap, and removed again.
#[tokio::test]
async fn without_a_readable_manifest_the_pulled_image_is_checked_and_removed() {
    let fake = Fake::new("exit 0\n");
    fs::write(fake.state.path().join("podman_manifest_unsupported"), b"").unwrap();
    fs::write(fake.state.path().join("image_size"), (30u64 << 30).to_string()).unwrap();
    let verbs = refused_over_cap(&fake).await;
    assert!(verbs.contains(&"pull".to_string()), "{verbs:?}");
    assert!(
        fake.calls().contains(&vec![
            "rmi".into(),
            "--ignore".into(),
            "--".into(),
            "docker.io/library/python:3.12-slim".into()
        ]),
        "the over-cap image is removed"
    );
}

/// Runs a lease that must be refused as over the cap, with nothing created; returns the verbs called.
async fn refused_over_cap(fake: &Fake) -> Vec<String> {
    let lease = fake.lease();
    let id = lease.lease_id;
    let f = finished(run(fake, lease).await.0);
    assert_eq!(f.error.as_deref(), Some(error_code::IMAGE_TOO_LARGE));
    let verbs: Vec<String> = fake.calls().iter().map(|c| c[0].clone()).collect();
    assert!(!verbs.contains(&"create".to_string()), "{verbs:?}");
    assert!(!fake.job_dir(&id).exists());
    verbs
}

#[tokio::test]
async fn a_failed_pull_is_reported_and_cleaned_up() {
    let fake = Fake::new("exit 0\n");
    fs::write(fake.state.path().join("pull_fails"), b"").unwrap();
    let lease = fake.lease();
    let id = lease.lease_id;
    let f = finished(run(&fake, lease).await.0);
    assert_eq!(f.error.as_deref(), Some(error_code::IMAGE_PULL_FAILED));
    let calls = fake.calls();
    assert!(!calls.iter().any(|c| c[0] == "create"));
    // What the failed pull left behind is removed (the image was not present before).
    assert!(calls.contains(&vec![
        "rmi".to_string(),
        "--ignore".into(),
        "--".into(),
        "docker.io/library/python:3.12-slim".into()
    ]));
    assert!(!fake.job_dir(&id).exists());
}
