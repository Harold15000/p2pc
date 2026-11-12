// SPDX-License-Identifier: Apache-2.0

//! Inventory detection against a fake machine: a temporary root directory and a [`FakeRunner`]. Nothing here runs
//! `nvidia-smi`, `podman` or any other real tool.

use std::fs::{self, File};
use std::path::Path;
use std::time::{Duration, SystemTime};

use p2pc_proto::api::{GpuStatusKind, Platform, SandboxClass};
use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::config::{Env, GpuShare};
use crate::runner::{COMMAND_TIMEOUT, FakeRunner, RunError};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/", $name))
    };
}

const SMI_QUERY: [&str; 3] = [
    "nvidia-smi",
    "--query-gpu=index,uuid,name,driver_version,memory.total,compute_cap,pci.bus_id",
    "--format=csv,noheader,nounits",
];
const SMI_MIG: [&str; 3] = [
    "nvidia-smi",
    "--query-gpu=uuid,mig.mode.current",
    "--format=csv,noheader",
];
const WSL_SMI: &str = "/usr/lib/wsl/lib/nvidia-smi";
const UUID_1: &str = "GPU-00000000-0000-4000-8000-000000000001";

fn write(root: &Path, path: &str, content: &str) {
    let full = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(full.parent().unwrap()).unwrap();
    fs::write(full, content).unwrap();
}

fn set_mtime(root: &Path, path: &str, t: SystemTime) {
    File::options()
        .write(true)
        .open(root.join(path.trim_start_matches('/')))
        .unwrap()
        .set_modified(t)
        .unwrap();
}

/// A fake machine: 16 logical cores, 32 014 MiB of RAM, Ubuntu 24.04, cgroup v2.
fn machine(platform: Platform, euid: u32) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path();
    write(r, "/proc/cpuinfo", fixture!("cpuinfo-intel.txt"));
    write(r, "/proc/meminfo", fixture!("meminfo.txt"));
    write(r, "/etc/os-release", fixture!("os-release-ubuntu"));
    write(r, "/proc/sys/kernel/hostname", "node-1\n");
    write(
        r,
        "/proc/self/status",
        &format!("Name:\tp2pc-agent\nUid:\t{euid}\t{euid}\t{euid}\t{euid}\n"),
    );
    write(r, "/sys/fs/cgroup/cgroup.controllers", "cpuset cpu io memory pids\n");
    write(r, "/proc/mounts", "/dev/sda1 / ext4 rw,relatime 0 0\n");
    match platform {
        Platform::Linux => write(r, "/proc/version", fixture!("proc-version-linux.txt")),
        Platform::Wsl2 => {
            write(r, "/proc/version", fixture!("proc-version-wsl.txt"));
            // A WSL distro, not just its kernel: WSL's init makes /run/WSL in every distro.
            write(r, "/run/WSL/.marker", "");
            write(r, "/dev/dxg", "");
            let ids = "containers:2147483647:2147483648\n";
            write(r, "/etc/subuid", ids);
            write(r, "/etc/subgid", ids);
            // The image's wsl.conf: interop off, no Windows PATH (§9.0).
            write(r, "/etc/wsl.conf", WSL_CONF);
            // This start of the distro, and a fresh boot status from p2pc-boot (carry-over 9).
            write(r, "/proc/stat", &format!("cpu  1 2 3 4\nbtime {BOOT_TIME}\n"));
            write(r, "/proc/1/stat", INIT_STAT);
            boot_status(r, BOOT_TIME_RFC3339, "fresh", &[]);
        }
    }
    dir
}

/// The `p2pc-node` image's `/etc/wsl.conf` (the parts §9.0 checks).
const WSL_CONF: &str = "[boot]\nsystemd=false\ncommand=/usr/local/sbin/p2pc-boot\n\n[automount]\nenabled=false\n\n\
                        [interop]\nenabled=false\nappendWindowsPath=false\n\n[user]\ndefault=root\n";

/// `btime` of the fake WSL2 machine (2023-11-14T22:13:20Z). Its init started at the same second.
const BOOT_TIME: i64 = 1_700_000_000;
const BOOT_TIME_RFC3339: &str = "2023-11-14T22:13:20Z";
/// `/proc/1/stat` with `starttime` (field 22) 0: the init started at `btime`, whatever `CLK_TCK` is.
const INIT_STAT: &str = "1 (init) S 0 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 0 2000000 100\n";

/// Writes `/var/lib/p2pc/boot-status.json` as `p2pc-boot` does.
fn boot_status(root: &Path, time: &str, cdi: &str, errors: &[&str]) {
    let line = json!({"time": time, "cdi": cdi, "cdi_regenerated": false, "errors": errors, "notes": []});
    write(root, "/var/lib/p2pc/boot-status.json", &format!("{line}\n"));
}

/// A WSL2 machine with one GPU, a fresh CDI spec and the boot status `p2pc-boot` would write.
fn wsl2_one_gpu() -> (TempDir, FakeRunner) {
    let m = machine(Platform::Wsl2, 0);
    write(m.path(), "/etc/cdi/nvidia.yaml", fixture!("cdi-nvidia-wsl.yaml"));
    let runner = base_runner(Platform::Wsl2)
        .ok(&[WSL_SMI, SMI_QUERY[1], SMI_QUERY[2]], fixture!("nvidia-smi-wsl.csv"))
        .ok(
            &[WSL_SMI, SMI_MIG[1], SMI_MIG[2]],
            "GPU-00000000-0000-4000-8000-0000000000b0, [N/A]\n",
        )
        .ok(&[WSL_SMI], fixture!("nvidia-smi-header-wsl.txt"))
        .ok(&["nvidia-ctk", "cdi", "list"], "nvidia.com/gpu=all\n");
    (m, runner)
}

/// Carry-over 9: a boot status that reports `nvidia_smi_failed`, or any error, makes the GPUs not offerable, with
/// the reason for `doctor`.
#[tokio::test]
async fn wsl2_boot_failures_make_the_gpus_not_offerable() {
    for (cdi, errors) in [
        (
            "nvidia_smi_failed",
            vec!["nvidia-smi -L failed (exit 9); the existing CDI spec was kept"],
        ),
        ("failed", vec!["nvidia-ctk timed out after 20s"]),
        ("fresh", vec!["a stale spec could not be renamed"]),
    ] {
        let (m, runner) = wsl2_one_gpu();
        boot_status(m.path(), BOOT_TIME_RFC3339, cdi, &errors);
        let report = detect(&Host::with_root(m.path()), &runner, &config(Path::new("/var/lib/p2pc")))
            .await
            .unwrap();
        assert_eq!(report.inventory.gpus.len(), 1, "still reported");
        assert_eq!(report.inventory.offered.gpu, 0, "{cdi}");
        let warnings = report.local.share.warnings.join("; ");
        assert!(warnings.contains(cdi) && warnings.contains(errors[0]), "{warnings}");
        assert!(matches!(report.local.boot, Some(BootStatus::Failed { .. })));
    }
    // The fresh, clean status of the fixture offers the GPU.
    let (m, runner) = wsl2_one_gpu();
    let report = detect(&Host::with_root(m.path()), &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    assert_eq!(report.inventory.offered.gpu, 1);
    assert_eq!(report.local.boot, Some(BootStatus::Ok { cdi: "fresh".into() }));
}

/// Carry-over 9: a status from an earlier start of the distro, or none at all, is "not ready yet". The agent waits
/// for a fresh one (30 s at most over the process's life), and the GPUs are not offered without one.
#[tokio::test(start_paused = true)]
async fn wsl2_waits_for_a_fresh_boot_status_then_gives_up() {
    let (m, runner) = wsl2_one_gpu();
    boot_status(m.path(), "2023-11-14T22:13:19Z", "fresh", &[]);
    let host = Host::with_root(m.path());
    let c = config(Path::new("/var/lib/p2pc"));
    let started = Instant::now();
    let report = detect(&host, &runner, &c).await.unwrap();
    let waited = started.elapsed();
    assert!(
        waited >= boot::BOOT_STATUS_WAIT && waited < boot::BOOT_STATUS_WAIT + Duration::from_secs(5),
        "{waited:?}"
    );
    assert_eq!(report.inventory.offered.gpu, 0);
    assert!(matches!(&report.local.boot, Some(BootStatus::NotReady { reason }) if reason.contains("earlier start")));
    // The budget is spent: the next (periodic) detection does not wait again, and still offers nothing.
    let again = Instant::now();
    let report = detect_periodic(&host, &runner, &c).await.unwrap();
    assert!(again.elapsed() < Duration::from_secs(5), "{:?}", again.elapsed());
    assert_eq!(report.inventory.offered.gpu, 0);
    // A missing file is "not ready" too, never "no GPU".
    fs::remove_file(m.path().join("var/lib/p2pc/boot-status.json")).unwrap();
    let report = detect(&host, &runner, &c).await.unwrap();
    assert!(matches!(&report.local.boot, Some(BootStatus::NotReady { reason }) if reason.contains("missing")));
    assert_eq!(report.inventory.gpus.len(), 1);
}

/// T05b review, P2-2: the boot wait runs alongside the probes. With tools that each take 3 s and a boot status that
/// never comes (a 30 s wait), every probe still answers within its 15 s deadline, and the whole detection takes
/// about 30 s (the longer of the two), not 30 + 15.
#[tokio::test(start_paused = true)]
async fn the_boot_wait_does_not_use_up_the_probe_deadline() {
    let (m, runner) = wsl2_one_gpu();
    let runner = runner.latency(Duration::from_secs(3));
    boot_status(m.path(), "2023-11-14T22:13:19Z", "fresh", &[]);
    let started = Instant::now();
    let report = detect(&Host::with_root(m.path()), &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    let took = started.elapsed();
    assert!(
        took >= boot::BOOT_STATUS_WAIT && took < boot::BOOT_STATUS_WAIT + Duration::from_secs(5),
        "{took:?}"
    );
    assert!(
        report.local.notes.iter().all(|n| !n.contains("did not answer")),
        "a probe missed its deadline: {:?}",
        report.local.notes
    );
    assert_eq!(report.local.podman.tool.version(), Some("4.9.3"));
    assert_eq!(report.inventory.gpu_status.status, GpuStatusKind::Ok);
    assert_eq!(report.inventory.gpus.len(), 1, "the GPU was detected");
    // Only the GPU offer is gated on the boot status.
    assert_eq!(report.inventory.offered.gpu, 0);
    assert!(report.inventory.offered.cpu > 0.0);
    assert!(matches!(report.local.boot, Some(BootStatus::NotReady { .. })));
}

/// Carry-over 9: a status that arrives during the wait is used as soon as it is there.
#[tokio::test(start_paused = true)]
async fn wsl2_uses_a_boot_status_that_arrives_while_waiting() {
    let (m, runner) = wsl2_one_gpu();
    fs::remove_file(m.path().join("var/lib/p2pc/boot-status.json")).unwrap();
    let root = m.path().to_path_buf();
    // p2pc-boot finishes 10 s (of paused, virtual time) after the agent starts looking.
    let writer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(10)).await;
        boot_status(&root, "2023-11-14T22:13:25Z", "regenerated", &[]);
    });
    let started = Instant::now();
    let report = detect(&Host::with_root(m.path()), &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    writer.await.unwrap();
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(10) && waited < Duration::from_secs(13),
        "{waited:?}"
    );
    assert_eq!(
        report.local.boot,
        Some(BootStatus::Ok {
            cdi: "regenerated".into()
        })
    );
    assert_eq!(report.inventory.offered.gpu, 1);
}

/// Without `/dev/dxg` there is no GPU to wait for: no wait, no boot status.
#[tokio::test(start_paused = true)]
async fn wsl2_without_dxg_does_not_wait() {
    let m = machine(Platform::Wsl2, 0);
    fs::remove_file(m.path().join("dev/dxg")).unwrap();
    fs::remove_file(m.path().join("var/lib/p2pc/boot-status.json")).unwrap();
    let started = Instant::now();
    let report = detect_on(&m, &base_runner(Platform::Wsl2), &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(report.local.boot, None);
}

/// Podman, crun and uname, all fine, on the given profile.
fn base_runner(platform: Platform) -> FakeRunner {
    let info = match platform {
        Platform::Linux => fixture!("podman-info-rootless.json"),
        Platform::Wsl2 => fixture!("podman-info-wsl.json"),
    };
    FakeRunner::new()
        .ok(
            &["podman", "version", "--format", "json"],
            fixture!("podman-version.json"),
        )
        .ok(&["podman", "info", "--format", "json"], info)
        .ok(&["crun", "--version"], "crun version 1.14.1\ncommit: 0\n")
        .ok(&["uname", "-m"], "x86_64\n")
}

fn with_gpu(runner: FakeRunner, csv: &str) -> FakeRunner {
    runner
        .ok(&SMI_QUERY, csv)
        .ok(&SMI_MIG, &format!("{UUID_1}, [N/A]\n"))
        .ok(&["nvidia-smi"], fixture!("nvidia-smi-header-linux.txt"))
}

fn config(data_dir: &Path) -> Config {
    let env = Env {
        root: false,
        home: Some("/home/p2pc".into()),
        config_env: None,
        ..Default::default()
    };
    let mut c = Config::parse("", &env).unwrap();
    c.data_dir = data_dir.to_path_buf();
    c
}

async fn detect_on(dir: &TempDir, runner: &FakeRunner, config: &Config) -> Result<Report, DetectError> {
    detect(&Host::with_root(dir.path()), runner, config).await
}

/// H2 §8.2, §11.3: the volume share is resolved with the rest of the share (it is the budget of the volume store).
/// The detection's own inventory does not carry it: `Inventory.volumes_mb` comes with `share_update` (H2 §6.1), so the
/// run path adds it (`connection::settle`) and the session sends it only when it declares the capability.
#[tokio::test]
async fn the_volume_share_is_resolved_on_the_node_and_not_in_the_detection() {
    let m = machine(Platform::Linux, 1001);
    let runner = base_runner(Platform::Linux);
    let mut cfg = config(Path::new("/var/lib/p2pc"));
    let report = detect_on(&m, &runner, &cfg).await.unwrap();
    assert_eq!(report.local.share.volumes_mb, 0, "nothing unless the owner says so");

    cfg.share.disk_mb = Some(64);
    cfg.share.volumes_mb = Some(128);
    let report = detect_on(&m, &runner, &cfg).await.unwrap();
    assert_eq!(report.local.share.volumes_mb, 128);
    assert_eq!(report.inventory.offered.disk_mb, Some(64), "apart from the job share");
    assert!(report.local.share.warnings.iter().all(|w| !w.contains("volumes")));
    let local = serde_json::to_value(&report.local).unwrap();
    assert_eq!(local["share"]["volumes_mb"], 128);
    let wire = serde_json::to_string(&report.inventory).unwrap();
    assert!(!wire.contains("volumes_mb"), "{wire}");

    // A share that could hold no volume at all says so.
    cfg.share.volumes_mb = Some(63);
    let report = detect_on(&m, &runner, &cfg).await.unwrap();
    assert!(
        report
            .local
            .share
            .warnings
            .iter()
            .any(|w| w.contains("share.volumes_mb is 63 MiB")),
        "{:?}",
        report.local.share.warnings
    );
    // More than the disk holds next to the job share: the detection names the key.
    cfg.share.volumes_mb = Some(u64::MAX / 2);
    let err = detect_on(&m, &runner, &cfg).await.unwrap_err();
    assert!(err.to_string().contains("share.volumes_mb"), "{err}");
}

#[tokio::test]
async fn native_linux_node_with_a_gpu() {
    let m = machine(Platform::Linux, 1001);
    write(m.path(), "/etc/cdi/nvidia.yaml", fixture!("cdi-nvidia-linux.yaml"));
    let runner = with_gpu(base_runner(Platform::Linux), fixture!("nvidia-smi-1gpu.csv"));
    let report = detect_on(&m, &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    let inv = &report.inventory;
    assert_eq!(inv.platform, Platform::Linux);
    assert_eq!(inv.hostname, "node-1");
    assert_eq!(inv.cpu.model, "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz");
    assert_eq!(inv.cpu.cores, 16);
    assert_eq!(inv.memory_mb, 32_014);
    assert_eq!(inv.os, "Ubuntu 24.04");
    assert_eq!(inv.arch, "x86_64");
    assert_eq!(inv.agent_version, env!("CARGO_PKG_VERSION"));
    assert!(!inv.dxg);
    assert!(inv.wsl2.is_none());
    assert_eq!(inv.gpu_status.status, GpuStatusKind::Ok);
    assert_eq!(inv.gpus.len(), 1);
    let g = &inv.gpus[0];
    assert_eq!(g.uuid, UUID_1);
    assert_eq!(g.cuda_driver_version.as_deref(), Some("12.4"));
    assert_eq!(g.pci_bdf.as_deref(), Some("0000:01:00.0"));
    assert!(!g.mig);
    let sb = &inv.sandbox[0];
    assert_eq!((sb.driver.as_str(), sb.class), ("podman", SandboxClass::Container));
    assert_eq!(sb.runtimes, ["crun"]);
    assert!(sb.ready, "{:?}", sb.problems);
    assert!(sb.problems.is_empty());
    assert_eq!(inv.offered.cpu, 12.0);
    assert_eq!(inv.offered.memory_mb, 24_010);
    assert_eq!(inv.offered.gpu, 1);
    assert_eq!(report.local.share.gpus, [UUID_1]);
    assert_eq!(report.local.podman.tool.version(), Some("4.9.3"));
    assert_eq!(report.local.cdi.devices.len(), 3);
    assert_eq!(report.local.cdi.spec_files, ["/etc/cdi/nvidia.yaml"]);
    // Every command went through the runner as an argv; nothing through a shell.
    let calls = runner.calls();
    assert!(calls.iter().all(|c| !["sh", "bash"].contains(&c[0].as_str())));
    assert!(calls.contains(&SMI_QUERY.map(String::from).to_vec()));
    assert!(calls.contains(&vec!["nvidia-ctk".into(), "cdi".into(), "list".into()]));
}

/// The ACC-1 node (uid 959, systemd): the agent runs in `app.slice/p2pc-agent.service`, where systemd has turned on
/// only `memory pids`, so `podman info` says so; `user@959.service` delegates `user_controllers` (when `Some`).
fn acc1_linux(user_controllers: Option<&str>) -> (TempDir, FakeRunner) {
    let m = machine(Platform::Linux, 959);
    let user = "/sys/fs/cgroup/user.slice/user-959.slice/user@959.service";
    write(
        m.path(),
        "/proc/self/cgroup",
        "0::/user.slice/user-959.slice/user@959.service/app.slice/p2pc-agent.service\n",
    );
    if let Some(c) = user_controllers {
        write(m.path(), &format!("{user}/cgroup.controllers"), c);
    }
    write(
        m.path(),
        &format!("{user}/app.slice/cgroup.subtree_control"),
        "memory pids\n",
    );
    let narrow = fixture!("podman-info-rootless.json").replace("\"cpu\",\n      \"memory\"", "\"memory\"");
    assert!(!narrow.contains("\"cpu\""), "the fixture edit applied");
    let runner = base_runner(Platform::Linux).ok(&["podman", "info", "--format", "json"], &narrow);
    (m, runner)
}

/// T10j (ACC-1): `user@` delegates cpu, memory and pids, but `podman info` (the agent's own cgroup) shows only
/// `memory pids`. The sandbox is ready, and nothing is asked of systemctl because the cgroup file was readable.
#[tokio::test]
async fn delegation_comes_from_the_user_manager_not_podman_info() {
    let (m, runner) = acc1_linux(Some("cpu memory pids\n"));
    let report = detect_on(&m, &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    let sb = &report.inventory.sandbox[0];
    assert!(sb.ready, "{:?}", sb.problems);
    assert!(sb.problems.is_empty());
    assert!(
        runner.calls().iter().all(|c| c[0] != "systemctl"),
        "{:?}",
        runner.calls()
    );
}

/// T10j: `user@` really lacks `cpu`: not ready, and the wire message names the unit, the file and the fix.
#[tokio::test]
async fn a_user_manager_without_cpu_makes_the_node_not_ready_with_the_fix() {
    let (m, runner) = acc1_linux(Some("memory pids\n"));
    let report = detect_on(&m, &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    let sb = &report.inventory.sandbox[0];
    assert!(!sb.ready);
    assert_eq!(sb.problems.len(), 1, "{:?}", sb.problems);
    let p = &sb.problems[0];
    assert!(p.starts_with("cgroup_not_delegated: "), "{p}");
    for needle in [
        "user@959.service",
        "user@959.service/cgroup.controllers",
        "Delegate=",
        "restart the agent",
    ] {
        assert!(p.contains(needle), "{needle:?} missing from {p}");
    }
}

/// T10j: the cgroup file is unreadable: `systemctl show user@959.service` is asked, and decides.
#[tokio::test]
async fn systemctl_is_asked_when_the_cgroup_file_cannot_be_read() {
    let show = [
        "systemctl",
        "show",
        "user@959.service",
        "--property=DelegateControllers",
        "--value",
    ];
    let (m, runner) = acc1_linux(None);
    let ready = runner.ok(&show, "cpu cpuset io memory pids\n");
    let report = detect_on(&m, &ready, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    assert!(
        report.inventory.sandbox[0].ready,
        "{:?}",
        report.inventory.sandbox[0].problems
    );
    assert!(ready.calls().contains(&show.map(String::from).to_vec()));

    let (m, runner) = acc1_linux(None);
    let report = detect_on(
        &m,
        &runner.ok(&show, "memory pids\n"),
        &config(Path::new("/var/lib/p2pc")),
    )
    .await
    .unwrap();
    let sb = &report.inventory.sandbox[0];
    assert!(!sb.ready);
    assert!(
        sb.problems[0].contains("systemctl show user@959.service"),
        "{:?}",
        sb.problems
    );

    // No systemctl either: `podman info` is the last resort, as it was before T10j.
    let (m, runner) = acc1_linux(None);
    let report = detect_on(&m, &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    assert!(!report.inventory.sandbox[0].ready);
    assert!(report.inventory.sandbox[0].problems[0].contains("podman info"));
}

#[tokio::test]
async fn wsl2_node_with_health_block() {
    let m = machine(Platform::Wsl2, 0);
    write(m.path(), "/etc/p2pc-distro-version", "p2pc-node 2026.11.1\n");
    write(m.path(), "/etc/cdi/nvidia.yaml", fixture!("cdi-nvidia-wsl.yaml"));
    write(m.path(), "/usr/lib/wsl/lib/libcuda.so.1", "");
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    set_mtime(m.path(), "/usr/lib/wsl/lib/libcuda.so.1", t0);
    set_mtime(m.path(), "/etc/cdi/nvidia.yaml", t0 + Duration::from_secs(60));
    // nvidia-smi is not on PATH inside the distro: only the WSL driver directory has it.
    let runner = base_runner(Platform::Wsl2)
        .ok(&[WSL_SMI, SMI_QUERY[1], SMI_QUERY[2]], fixture!("nvidia-smi-wsl.csv"))
        .ok(
            &[WSL_SMI, SMI_MIG[1], SMI_MIG[2]],
            "GPU-00000000-0000-4000-8000-0000000000b0, [N/A]\n",
        )
        .ok(&[WSL_SMI], fixture!("nvidia-smi-header-wsl.txt"))
        .ok(&["nvidia-ctk", "cdi", "list"], "nvidia.com/gpu=all\n");
    let host = Host::with_root(m.path());
    let report = detect(&host, &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    let inv = &report.inventory;
    assert_eq!(inv.platform, Platform::Wsl2);
    assert!(inv.dxg);
    assert_eq!(inv.gpu_status.status, GpuStatusKind::Ok, "{:?}", inv.gpu_status);
    assert_eq!(inv.gpus[0].cuda_driver_version.as_deref(), Some("12.9"));
    assert_eq!(inv.gpus[0].pci_bdf, None, "WSL2 has no host PCI address");
    assert_eq!(inv.offered.gpu, 1);
    assert!(inv.sandbox[0].ready, "{:?}", inv.sandbox[0].problems);
    assert_eq!(report.local.gpu.nvidia_smi.as_deref(), Some(WSL_SMI));
    let health = inv.wsl2.as_ref().unwrap();
    assert_eq!(health.distro_version.as_deref(), Some("p2pc-node 2026.11.1"));
    assert_eq!(health.podman_version.as_deref(), Some("4.9.3"));
    assert!(health.cdi_present && !health.cdi_stale);
    let v = serde_json::to_value(&report).unwrap();
    assert_eq!(
        v["inventory"]["wsl2"]["smoke"],
        json!(null),
        "T08 fills the smoke result"
    );

    // A driver update on Windows makes the spec stale.
    set_mtime(m.path(), "/usr/lib/wsl/lib/libcuda.so.1", t0 + Duration::from_secs(120));
    let report = detect(&host, &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    assert_eq!(report.inventory.gpu_status.status, GpuStatusKind::CdiStale);
    assert!(report.inventory.wsl2.as_ref().unwrap().cdi_stale);
    assert!(
        report
            .inventory
            .gpu_status
            .reason
            .as_deref()
            .unwrap()
            .contains("--mode=wsl"),
        "{:?}",
        report.inventory.gpu_status
    );
}

/// §6/§9: on WSL2 the CDI spec only has `nvidia.com/gpu=all`, which hands a job every GPU of the machine. With two
/// GPUs none can be pinned, so none is offered, even when the owner lists just one; `gpu_selection_unsupported`
/// stays a fallback the scheduler never needs.
#[tokio::test]
async fn wsl2_with_two_gpus_offers_none() {
    const A: &str = "GPU-00000000-0000-4000-8000-0000000000b0";
    const B: &str = "GPU-00000000-0000-4000-8000-0000000000b1";
    let m = machine(Platform::Wsl2, 0);
    write(m.path(), "/etc/cdi/nvidia.yaml", fixture!("cdi-nvidia-wsl.yaml"));
    let csv = format!(
        "0, {A}, NVIDIA GeForce RTX 5070 Ti, 576.02, 16303, 12.0, 00000000:01:00.0\n\
         1, {B}, NVIDIA GeForce RTX 4060, 576.02, 8188, 8.9, 00000000:02:00.0\n"
    );
    let runner = base_runner(Platform::Wsl2)
        .ok(&[WSL_SMI, SMI_QUERY[1], SMI_QUERY[2]], &csv)
        .ok(&[WSL_SMI, SMI_MIG[1], SMI_MIG[2]], &format!("{A}, [N/A]\n{B}, [N/A]\n"))
        .ok(&[WSL_SMI], fixture!("nvidia-smi-header-wsl.txt"))
        .ok(&["nvidia-ctk", "cdi", "list"], "nvidia.com/gpu=all\n");
    let host = Host::with_root(m.path());
    for share in [GpuShare::All, GpuShare::List(vec![A.into()])] {
        let mut cfg = config(Path::new("/var/lib/p2pc"));
        cfg.share.gpus = share.clone();
        let report = detect(&host, &runner, &cfg).await.unwrap();
        let inv = &report.inventory;
        assert_eq!(inv.gpus.len(), 2, "both are still reported");
        assert!(
            inv.gpus.iter().all(GpuInfo::is_offerable),
            "each card on its own is fine"
        );
        assert_eq!(inv.offered.gpu, 0, "{share:?}");
        assert!(
            report
                .local
                .share
                .warnings
                .iter()
                .any(|w| w.contains("nvidia.com/gpu=all")),
            "{:?}",
            report.local.share.warnings
        );
        assert!(report.local.share.gpus.is_empty());
    }
}

/// §9.0 "Windows interop" (T05b real run): the `WSLInterop` binfmt entry is shared by every distro of the WSL VM, so
/// on its own it is only a note. The real case: the entry is there and everything else is clean, so the node is
/// ready.
#[tokio::test]
async fn wsl2_binfmt_entry_alone_is_only_a_note() {
    for entry in ["WSLInterop", "WSLInterop-late"] {
        let m = machine(Platform::Wsl2, 0);
        write(
            m.path(),
            &format!("/proc/sys/fs/binfmt_misc/{entry}"),
            "enabled\ninterpreter /init\n",
        );
        let host = Host::with_root(m.path()).path_env("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        let probe = probe(
            &host,
            &base_runner(Platform::Wsl2),
            Runtime::Crun,
            Path::new("/var/lib/p2pc"),
            Duration::from_secs(15),
        )
        .await;
        assert!(probe.problems.is_empty(), "{entry}: {:?}", probe.problems);
        assert!(probe.sandbox.binfmt_interop);
        let report = probe.clone().report(&config(Path::new("/var/lib/p2pc"))).unwrap();
        assert!(report.inventory.sandbox[0].ready, "{entry}");
        let (text, ready) = crate::doctor::render(&crate::doctor::Findings {
            config_source: "x".into(),
            config_error: None,
            identity: crate::doctor::IdentityState::Ok("d75a98".into()),
            probe: &probe,
            report: &Ok(report),
            egress_socket: crate::doctor::EgressSocketState::Ok,
        });
        assert!(ready, "{text}");
        assert!(
            text.contains("[i] note: the WSLInterop binfmt entry is visible"),
            "{text}"
        );
    }
}

/// §9.0 "Windows interop": each signal, on its own, makes the node not ready.
#[tokio::test]
async fn each_wsl_interop_signal_on_its_own_makes_the_node_not_ready() {
    type Setup = fn(&Path, Host) -> Host;
    let cases: [(&[&str], Setup); 8] = [
        (&["interop_env"], |_, h| h.wsl_interop_env(true)),
        // A missing file means interop is on, and Windows directories are appended to PATH.
        (&["interop_enabled", "windows_path_appended"], |r, h| {
            fs::remove_file(r.join("etc/wsl.conf")).unwrap();
            h
        }),
        (&["interop_enabled"], |r, h| {
            write(
                r,
                "/etc/wsl.conf",
                &WSL_CONF.replace("[interop]\nenabled=false", "[interop]\nenabled=true"),
            );
            h
        }),
        (&["interop_enabled"], |r, h| {
            write(
                r,
                "/etc/wsl.conf",
                &WSL_CONF.replace("[interop]\nenabled=false\n", "[interop]\n"),
            );
            h
        }),
        (&["windows_path_appended"], |r, h| {
            write(r, "/etc/wsl.conf", &WSL_CONF.replace("appendWindowsPath=false\n", ""));
            h
        }),
        (&["windows_path"], |_, h| {
            h.path_env("/usr/bin:/mnt/c/Windows/system32:/bin")
        }),
        (&["windows_mounts"], |r, h| {
            write(r, "/proc/mounts", "C:\\134 /mnt/c 9p rw,aname=drvfs;path=C:\\ 0 0\n");
            h
        }),
        (&["windows_mounts"], |r, h| {
            write(
                r,
                "/proc/mounts",
                "drivers /usr/lib/wsl/drivers 9p rw,aname=drivers 0 0\n",
            );
            h
        }),
    ];
    for (expected, setup) in cases {
        let m = machine(Platform::Wsl2, 0);
        let host = setup(m.path(), Host::with_root(m.path()).path_env("/usr/sbin:/usr/bin"));
        let report = detect(&host, &base_runner(Platform::Wsl2), &config(Path::new("/var/lib/p2pc")))
            .await
            .unwrap();
        let codes: Vec<&str> = report.local.problems.iter().map(|p| p.code).collect();
        assert_eq!(codes, expected);
        assert!(!report.inventory.sandbox[0].ready, "{expected:?}");
    }
    // The read-only driver store alone is fine.
    let m = machine(Platform::Wsl2, 0);
    write(
        m.path(),
        "/proc/mounts",
        fixture!("proc-mounts-wsl.txt")
            .lines()
            .filter(|l| !l.contains("/mnt/"))
            .collect::<Vec<_>>()
            .join("\n")
            .as_str(),
    );
    let report = detect(
        &Host::with_root(m.path()),
        &base_runner(Platform::Wsl2),
        &config(Path::new("/var/lib/p2pc")),
    )
    .await
    .unwrap();
    assert!(report.local.problems.is_empty(), "{:?}", report.local.problems);
}

#[tokio::test]
async fn wsl2_without_a_stamp_or_podman() {
    let m = machine(Platform::Wsl2, 1000);
    write(m.path(), "/proc/mounts", fixture!("proc-mounts-wsl.txt"));
    let runner = FakeRunner::new();
    let host = Host::with_root(m.path()).wsl_interop_env(true);
    let report = detect(&host, &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    let inv = &report.inventory;
    let health = inv.wsl2.as_ref().unwrap();
    assert_eq!(health.distro_version, None, "no stamp file");
    assert_eq!(health.podman_version, None, "no podman");
    assert!(!health.cdi_present);
    let codes: Vec<&str> = report.local.problems.iter().map(|p| p.code).collect();
    assert_eq!(
        codes,
        [
            "not_root",
            "windows_mounts",
            "interop_env",
            "podman_not_found",
            "runtime_not_found"
        ]
    );
    assert!(!inv.sandbox[0].ready);
    assert_eq!(inv.sandbox[0].problems.len(), 5);
    assert_eq!(
        inv.sandbox[0].problems[1], "windows_mounts: Windows filesystems are mounted (9p or drvfs): /mnt/c, /mnt/d",
        "the read-only driver store is not one"
    );
    assert_eq!(inv.arch, std::env::consts::ARCH, "uname missing: the build's arch");
}

#[tokio::test]
async fn missing_tools_are_unavailable_not_errors() {
    let m = machine(Platform::Linux, 1001);
    let runner = FakeRunner::new();
    let report = detect_on(&m, &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    let inv = &report.inventory;
    assert_eq!(inv.gpu_status.status, GpuStatusKind::NoDriver);
    assert!(
        inv.gpu_status
            .reason
            .as_deref()
            .unwrap()
            .contains("nvidia-smi not found")
    );
    assert!(inv.gpus.is_empty());
    assert_eq!(inv.offered.gpu, 0);
    assert!(inv.sandbox[0].runtimes.is_empty());
    assert!(!inv.sandbox[0].ready);
    assert_eq!(report.local.podman.tool, Tool::Unavailable);
    assert_eq!(report.local.runsc, Tool::Unavailable);
    assert_eq!(report.local.cdi.nvidia_ctk, Tool::Unavailable);
    // Both nvidia-smi locations were tried, PATH first.
    let calls = runner.calls();
    let smi: Vec<&str> = calls
        .iter()
        .filter(|c| c[0].ends_with("nvidia-smi"))
        .map(|c| c[0].as_str())
        .collect();
    assert_eq!(smi, NVIDIA_SMI_PATHS);
}

#[tokio::test]
async fn nvidia_smi_failures_map_to_gpu_status() {
    let cases: [(FakeRunner, GpuStatusKind); 5] = [
        (
            FakeRunner::new().exits(&SMI_QUERY, 6, "No devices were found\n", ""),
            GpuStatusKind::NotFound,
        ),
        (FakeRunner::new().ok(&SMI_QUERY, ""), GpuStatusKind::NotFound),
        (
            FakeRunner::new().exits(
                &SMI_QUERY,
                9,
                "NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver. Make sure that \
                 the latest NVIDIA driver is installed and running.\n",
                "",
            ),
            GpuStatusKind::NoDriver,
        ),
        (
            FakeRunner::new().exits(
                &SMI_QUERY,
                18,
                "",
                "Failed to initialize NVML: Driver/library version mismatch\n",
            ),
            GpuStatusKind::NvmlError,
        ),
        (
            FakeRunner::new().error(&SMI_QUERY, RunError::TimedOut(COMMAND_TIMEOUT)),
            GpuStatusKind::NvmlError,
        ),
    ];
    let m = machine(Platform::Linux, 1001);
    for (runner, expected) in cases {
        let report = detect_on(&m, &runner, &config(Path::new("/var/lib/p2pc")))
            .await
            .unwrap();
        let status = &report.inventory.gpu_status;
        assert_eq!(status.status, expected, "{status:?}");
        assert!(status.reason.is_some());
        assert_eq!(report.inventory.offered.gpu, 0);
    }
}

#[tokio::test]
async fn mig_and_unknown_vram_are_reported_but_not_offered() {
    let m = machine(Platform::Linux, 1001);
    write(
        m.path(),
        "/var/run/cdi/nvidia.json",
        r#"{"kind":"nvidia.com/gpu","devices":[{"name":"all"}]}"#,
    );
    let runner = base_runner(Platform::Linux)
        .ok(&SMI_QUERY, fixture!("nvidia-smi-2gpu.csv"))
        .ok(&SMI_MIG, fixture!("nvidia-smi-mig-2gpu.csv"));
    let report = detect_on(&m, &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    let inv = &report.inventory;
    assert_eq!(inv.gpu_status.status, GpuStatusKind::Ok);
    assert_eq!(inv.gpus.len(), 2, "both are reported");
    assert!(inv.gpus[0].mig);
    assert_eq!(inv.gpus[1].vram_mb, None);
    assert_eq!(
        inv.gpus[0].cuda_driver_version, None,
        "plain nvidia-smi was not recorded"
    );
    assert_eq!(inv.offered.gpu, 0, "neither is offerable");
    assert_eq!(report.local.cdi.spec_files, ["/var/run/cdi/nvidia.json"]);
}

/// Two cards, the second one known to `nvidia-smi`'s main query but possibly missing from the MIG query.
const UUID_2: &str = "GPU-00000000-0000-4000-8000-000000000002";

fn two_gpus_csv() -> String {
    format!(
        "0, {UUID_1}, GPU A, 550.54, 8192, 8.9, 00000000:01:00.0\n1, {UUID_2}, GPU B, 550.54, 8192, 8.9, 00000000:02:00.0\n"
    )
}

async fn mig_scenario(mig_answer: FakeRunner) -> Report {
    let m = machine(Platform::Linux, 1001);
    write(m.path(), "/etc/cdi/nvidia.yaml", fixture!("cdi-nvidia-linux.yaml"));
    detect_on(&m, &mig_answer, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap()
}

fn two_gpu_runner() -> FakeRunner {
    base_runner(Platform::Linux)
        .ok(&SMI_QUERY, &two_gpus_csv())
        .ok(&["nvidia-smi"], fixture!("nvidia-smi-header-linux.txt"))
}

#[tokio::test]
async fn mig_field_unknown_to_an_old_driver_means_no_mig() {
    let runner = two_gpu_runner().exits(
        &SMI_MIG,
        2,
        "Field \"mig.mode.current\" is not a valid field to query.\n",
        "",
    );
    let report = mig_scenario(runner).await;
    assert!(report.inventory.gpus.iter().all(|g| !g.mig));
    assert_eq!(report.inventory.offered.gpu, 2);
}

#[tokio::test]
async fn any_other_mig_query_failure_makes_every_card_not_offerable() {
    for failure in [
        two_gpu_runner().error(&SMI_MIG, RunError::TimedOut(COMMAND_TIMEOUT)),
        two_gpu_runner().exits(
            &SMI_MIG,
            9,
            "",
            "NVIDIA-SMI has failed because it could not communicate\n",
        ),
        two_gpu_runner(), // the MIG query cannot even be started: nothing recorded for it
    ] {
        let report = mig_scenario(failure).await;
        assert_eq!(report.inventory.gpus.len(), 2, "still reported");
        assert_eq!(report.inventory.offered.gpu, 0, "MIG state unknown: not offerable");
        assert!(
            report.local.gpu.notes.iter().any(|n| n.contains("MIG")),
            "{:?}",
            report.local.gpu.notes
        );
    }
}

#[tokio::test]
async fn a_card_missing_from_the_mig_output_is_not_offerable() {
    let runner = two_gpu_runner().ok(&SMI_MIG, &format!("{UUID_1}, [N/A]\n"));
    let report = mig_scenario(runner).await;
    assert_eq!(report.local.share.gpus, [UUID_1], "only the card MIG answered for");
    assert_eq!(report.inventory.offered.gpu, 1);
    let notes = report.local.gpu.notes.join("; ");
    assert!(notes.contains(UUID_2) && notes.contains("MIG"), "{notes}");
    assert!(!notes.contains(UUID_1), "{notes}");
}

/// T07b review, carry-over 3: an error value in the MIG column marks that card not offerable, with a note, like a
/// failed query does.
#[tokio::test]
async fn an_error_value_in_the_mig_column_makes_that_card_not_offerable() {
    for value in ["[Unknown Error]", "[Insufficient Permissions]"] {
        let runner = two_gpu_runner().ok(&SMI_MIG, &format!("{UUID_1}, Disabled\n{UUID_2}, {value}\n"));
        let report = mig_scenario(runner).await;
        assert_eq!(report.inventory.gpus.len(), 2, "still reported");
        assert!(!report.inventory.gpus[0].mig);
        assert!(report.inventory.gpus[1].mig, "unknown MIG state counts as enabled");
        assert_eq!(report.local.share.gpus, [UUID_1]);
        let notes = report.local.gpu.notes.join("; ");
        assert!(
            notes.contains(UUID_2) && notes.contains(value) && notes.contains("not offered"),
            "{notes}"
        );
        assert!(!notes.contains(UUID_1), "{notes}");
    }
}

#[tokio::test]
async fn cdi_missing_means_no_gpu_is_offered() {
    let m = machine(Platform::Linux, 1001);
    let runner = with_gpu(base_runner(Platform::Linux), fixture!("nvidia-smi-1gpu.csv"));
    let report = detect_on(&m, &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    assert_eq!(report.inventory.gpu_status.status, GpuStatusKind::CdiMissing);
    assert!(
        report
            .inventory
            .gpu_status
            .reason
            .as_deref()
            .unwrap()
            .contains("nvidia-ctk cdi generate")
    );
    assert_eq!(report.inventory.gpus.len(), 1, "still reported");
    assert_eq!(report.inventory.offered.gpu, 0);
    assert_eq!(report.local.share.warnings.len(), 1);
}

#[tokio::test]
async fn old_drivers_without_compute_cap() {
    let m = machine(Platform::Linux, 1001);
    write(m.path(), "/etc/cdi/nvidia.yaml", fixture!("cdi-nvidia-linux.yaml"));
    let runner = base_runner(Platform::Linux)
        .exits(
            &SMI_QUERY,
            2,
            "Field \"compute_cap\" is not a valid field to query.\n",
            "",
        )
        .ok(
            &[
                "nvidia-smi",
                "--query-gpu=index,uuid,name,driver_version,memory.total,pci.bus_id",
                "--format=csv,noheader,nounits",
            ],
            &format!("0, {UUID_1}, Tesla T4, 470.57, 15109, 00000000:00:04.0\n"),
        )
        .ok(&SMI_MIG, &format!("{UUID_1}, [N/A]\n"));
    let report = detect_on(&m, &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    let g = &report.inventory.gpus[0];
    assert_eq!(
        (g.name.as_str(), g.vram_mb, g.compute_capability.as_deref()),
        ("Tesla T4", Some(15_109), None)
    );
    assert_eq!(report.inventory.offered.gpu, 1);
}

#[tokio::test]
async fn share_limits_are_applied_and_checked() {
    let m = machine(Platform::Linux, 1001);
    write(m.path(), "/etc/cdi/nvidia.yaml", fixture!("cdi-nvidia-linux.yaml"));
    let runner = with_gpu(base_runner(Platform::Linux), fixture!("nvidia-smi-1gpu.csv"));
    let mut c = config(Path::new("/var/lib/p2pc"));
    c.share.cpu_cores = Some(2.5);
    c.share.memory_mb = Some(4096);
    c.share.gpus = GpuShare::None;
    let inv = detect_on(&m, &runner, &c).await.unwrap().inventory;
    assert_eq!(
        (inv.offered.cpu, inv.offered.memory_mb, inv.offered.gpu),
        (2.5, 4096, 0)
    );
    c.share.cpu_cores = Some(17.0);
    let err = detect_on(&m, &runner, &c).await.unwrap_err();
    assert!(matches!(err, DetectError::Share(ConfigError::Invalid { ref field, .. }) if field == "share.cpu_cores"));
    c.share.cpu_cores = None;
    c.share.gpus = GpuShare::List(vec!["GPU-00000000-0000-4000-8000-00000000ffff".into()]);
    let err = detect_on(&m, &runner, &c).await.unwrap_err();
    assert!(err.to_string().contains("not a GPU of this machine"), "{err}");
}

/// §6 `Inventory` (amended 2026-11-07, ACC-1 round 2): `offered.disk_mb` is the resolved share's disk for job
/// directories, so the scheduler stops offering leases that the executor would refuse for disk.
#[tokio::test]
async fn the_inventory_carries_the_resolved_share_disk() {
    let m = machine(Platform::Linux, 1001);
    let runner = base_runner(Platform::Linux);
    let mut c = config(Path::new("/var/lib/p2pc"));
    // The default share (50 GiB, or less on a small disk).
    let report = detect_on(&m, &runner, &c).await.unwrap();
    assert_eq!(report.inventory.offered.disk_mb, Some(report.local.share.disk_mb));
    assert!(report.local.share.disk_mb > 0);
    assert_eq!(report.inventory.disk_total_mb, report.local.disk_total_mb);
    // An explicit one.
    c.share.disk_mb = Some(4096);
    let report = detect_on(&m, &runner, &c).await.unwrap();
    assert_eq!(report.local.share.disk_mb, 4096);
    assert_eq!(report.inventory.offered.disk_mb, Some(4096));
    assert!(report.inventory.offered.disk_mb <= report.inventory.disk_total_mb);
}

#[tokio::test]
async fn periodic_redetection_skips_a_missing_uuid_with_a_warning() {
    let m = machine(Platform::Linux, 1001);
    write(m.path(), "/etc/cdi/nvidia.yaml", fixture!("cdi-nvidia-linux.yaml"));
    let runner = with_gpu(base_runner(Platform::Linux), fixture!("nvidia-smi-1gpu.csv"));
    let mut c = config(Path::new("/var/lib/p2pc"));
    // One card is here, the other (an eGPU) was unplugged.
    let unplugged = "GPU-00000000-0000-4000-8000-00000000ffff";
    c.share.gpus = GpuShare::List(vec![unplugged.into(), UUID_1.into()]);
    // At load and in `doctor` the typo or the missing card is a hard error.
    let err = detect_on(&m, &runner, &c).await.unwrap_err();
    assert!(err.to_string().contains(unplugged), "{err}");
    // Periodic re-detection keeps going: the missing UUID is skipped with a warning, the rest is offered.
    let report = detect_periodic(&Host::with_root(m.path()), &runner, &c).await.unwrap();
    assert_eq!(report.local.share.gpus, [UUID_1]);
    assert_eq!(report.inventory.offered.gpu, 1);
    let warnings = report.local.share.warnings.join("; ");
    assert!(warnings.contains(unplugged), "{warnings}");
}

#[tokio::test]
async fn a_hung_tool_gives_a_partial_inventory_with_a_note_at_the_deadline() {
    let m = machine(Platform::Linux, 1001);
    write(m.path(), "/etc/cdi/nvidia.yaml", fixture!("cdi-nvidia-linux.yaml"));
    // `nvidia-smi` hangs (a wedged driver) and so does `podman info`; everything else answers.
    let runner = base_runner(Platform::Linux)
        .hang(&SMI_QUERY)
        .hang(&["podman", "info", "--format", "json"]);
    let mut c = config(Path::new("/var/lib/p2pc"));
    c.detect_timeout_s = 1;
    let started = std::time::Instant::now();
    let report = detect_on(&m, &runner, &c).await.expect("a timeout is not a failure");
    assert!(started.elapsed() < Duration::from_secs(10), "stopped at the deadline");
    let inv = &report.inventory;
    // What answered is there ...
    assert_eq!(inv.hostname, "node-1");
    assert_eq!(inv.memory_mb, 32_014);
    assert_eq!(inv.arch, "x86_64");
    assert_eq!(report.local.crun.version(), Some("1.14.1"));
    assert_eq!(report.local.cdi.spec_files, ["/etc/cdi/nvidia.yaml"]);
    // ... what hung is unknown, and says why. It is retried at the next detection, never cached.
    assert!(inv.gpus.is_empty());
    assert_eq!(inv.gpu_status.status, GpuStatusKind::NvmlError);
    assert!(
        inv.gpu_status.reason.as_deref().unwrap().contains("deadline"),
        "{:?}",
        inv.gpu_status
    );
    assert_eq!(inv.offered.gpu, 0);
    assert!(!inv.sandbox[0].ready);
    let notes = report.local.notes.join("; ");
    assert!(notes.contains("GPU") && notes.contains("Podman"), "{notes}");
}

/// T10j review P3 2: `systemctl show` hangs, so `podman info` decides; the note says why, like every other probe.
#[tokio::test]
async fn a_hung_systemctl_leaves_a_note() {
    let show = [
        "systemctl",
        "show",
        "user@959.service",
        "--property=DelegateControllers",
        "--value",
    ];
    let (m, runner) = acc1_linux(None);
    let mut c = config(Path::new("/var/lib/p2pc"));
    c.detect_timeout_s = 1;
    let report = detect_on(&m, &runner.hang(&show), &c)
        .await
        .expect("a timeout is not a failure");
    let notes = report.local.notes.join("; ");
    assert!(
        notes.contains("systemctl") && notes.contains("did not answer"),
        "{notes}"
    );
    // Not asked (the cgroup file was readable) or answered: no note.
    let (m, runner) = acc1_linux(None);
    let report = detect_on(&m, &runner.ok(&show, "cpu cpuset io memory pids\n"), &c)
        .await
        .unwrap();
    assert!(
        report.local.notes.iter().all(|n| !n.contains("systemctl")),
        "{:?}",
        report.local.notes
    );
}

#[tokio::test]
async fn a_hung_nvidia_ctk_is_reported_as_unknown_cdi_with_a_note() {
    let m = machine(Platform::Linux, 1001);
    write(m.path(), "/etc/cdi/nvidia.yaml", fixture!("cdi-nvidia-linux.yaml"));
    let runner =
        with_gpu(base_runner(Platform::Linux), fixture!("nvidia-smi-1gpu.csv")).hang(&["nvidia-ctk", "cdi", "list"]);
    let mut c = config(Path::new("/var/lib/p2pc"));
    c.detect_timeout_s = 1;
    let report = detect_on(&m, &runner, &c).await.unwrap();
    assert!(matches!(report.local.cdi.nvidia_ctk, Tool::Failed { .. }));
    assert_eq!(report.inventory.gpus.len(), 1, "the GPU query answered");
    assert!(
        report.local.notes.iter().any(|n| n.contains("CDI")),
        "{:?}",
        report.local.notes
    );
}

#[tokio::test]
async fn detection_is_never_cached() {
    let m = machine(Platform::Linux, 1001);
    write(m.path(), "/etc/cdi/nvidia.yaml", fixture!("cdi-nvidia-linux.yaml"));
    let c = config(Path::new("/var/lib/p2pc"));
    let before = detect_on(&m, &FakeRunner::new(), &c).await.unwrap();
    assert_eq!(before.inventory.gpu_status.status, GpuStatusKind::NoDriver);
    // A driver installed after start shows up on the next call.
    let after = detect_on(&m, &with_gpu(FakeRunner::new(), fixture!("nvidia-smi-1gpu.csv")), &c)
        .await
        .unwrap();
    assert_eq!(after.inventory.gpu_status.status, GpuStatusKind::Ok);
    assert_eq!(after.inventory.offered.gpu, 1);
}

#[tokio::test]
async fn gvisor_class_and_runtimes() {
    let m = machine(Platform::Linux, 1001);
    let runner = base_runner(Platform::Linux).ok(&["runsc", "--version"], "runsc version release-20240513.0\n");
    let mut c = config(Path::new("/var/lib/p2pc"));
    c.runtime = Runtime::Runsc;
    let report = detect_on(&m, &runner, &c).await.unwrap();
    let sb = &report.inventory.sandbox[0];
    assert_eq!(sb.class, SandboxClass::ContainerGvisor);
    assert_eq!(sb.runtimes, ["crun", "runsc"]);
    assert!(sb.ready);
    assert_eq!(report.local.runsc.version(), Some("release-20240513.0"));
}

#[tokio::test]
async fn hostile_tool_output_is_cleaned_or_rejected() {
    let m = machine(Platform::Linux, 1001);
    write(m.path(), "/proc/sys/kernel/hostname", "bad host/name\n");
    write(m.path(), "/etc/cdi/nvidia.yaml", fixture!("cdi-nvidia-linux.yaml"));
    let runner = with_gpu(
        base_runner(Platform::Linux),
        &format!("0, {UUID_1}, GPU\u{1b}[2J, 550.54, 8192, 8.9, 00000000:01:00.0\n"),
    );
    let inv = detect_on(&m, &runner, &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap()
        .inventory;
    assert_eq!(inv.hostname, "bad-host-name");
    assert_eq!(inv.gpus[0].name, "GPU [2J", "control characters removed");
    assert_eq!(clean(&"é".repeat(MAX_TEXT_LEN)).len(), MAX_TEXT_LEN);
}

/// T07b review, carry-over 1: an unknown RAM size no longer fails the detection (which would stop every `Hello` and
/// heartbeat behind it). The node is reported, not ready, offering nothing, with a note.
#[tokio::test]
async fn unknown_ram_reports_a_node_that_is_not_ready() {
    let m = machine(Platform::Linux, 1001);
    fs::remove_file(m.path().join("proc/meminfo")).unwrap();
    let report = detect_on(&m, &base_runner(Platform::Linux), &config(Path::new("/var/lib/p2pc")))
        .await
        .unwrap();
    let inv = &report.inventory;
    assert_eq!(inv.memory_mb, UNKNOWN_MEMORY_MB);
    assert_eq!((inv.offered.cpu, inv.offered.memory_mb, inv.offered.gpu), (0.0, 0, 0));
    assert!(!inv.sandbox[0].ready);
    assert!(
        inv.sandbox[0]
            .problems
            .iter()
            .any(|p| p.starts_with("memory_unknown: ")),
        "{:?}",
        inv.sandbox[0].problems
    );
    assert!(report.local.problems.iter().any(|p| p.code == "memory_unknown"));
    assert!(
        report.local.share.warnings.iter().any(|w| w.contains("RAM")),
        "{:?}",
        report.local.share.warnings
    );
}

/// A FIFO with no writer: opening it for reading blocks, like a hung `/proc` or network filesystem. The guard lets
/// the stuck reader finish when it is dropped (even when the test fails), so the runtime can shut down.
fn hang_file(root: &Path, path: &str) -> Hung {
    let full = root.join(path.trim_start_matches('/'));
    let _ = fs::remove_file(&full);
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &full,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    Hung(full)
}

struct Hung(std::path::PathBuf);

impl Drop for Hung {
    fn drop(&mut self) {
        release(&self.0, "");
    }
}

/// Lets the reader of a [`hang_file`] finish, if one is waiting: it gets `content`, then end of file. Opening
/// without blocking fails when no reader waits, which is fine.
fn release(fifo: &Path, content: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Ok(mut w) = fs::OpenOptions::new()
        .write(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(fifo)
    {
        let _ = w.write_all(content.as_bytes());
    }
}

/// T07b review, carry-over 1: the RAM size is read first, with its own short deadline, so a hung read of the other
/// host files cannot make it unknown.
#[tokio::test(flavor = "multi_thread")]
async fn the_ram_size_is_read_first_with_its_own_deadline() {
    let m = machine(Platform::Linux, 1001);
    let _hung = hang_file(m.path(), "/proc/cpuinfo");
    let mut c = config(Path::new("/var/lib/p2pc"));
    c.detect_timeout_s = 1;
    let report = detect_on(&m, &base_runner(Platform::Linux), &c).await.unwrap();
    assert_eq!(report.inventory.memory_mb, 32_014, "RAM known despite the hung read");
    assert!(
        report.local.notes.iter().any(|n| n.contains("/proc")),
        "{:?}",
        report.local.notes
    );
}

/// T07b review, carry-over 2: a blocking read that is still stuck from an earlier detection is not started again.
#[tokio::test(flavor = "multi_thread")]
async fn a_stuck_blocking_probe_is_never_started_twice() {
    let m = machine(Platform::Linux, 1001);
    let hung = hang_file(m.path(), "/proc/meminfo");
    let host = Host::with_root(m.path());
    let mut c = config(Path::new("/var/lib/p2pc"));
    c.detect_timeout_s = 1;
    let runner = base_runner(Platform::Linux);
    let first = detect(&host, &runner, &c).await.unwrap();
    assert_eq!(first.inventory.memory_mb, UNKNOWN_MEMORY_MB);
    assert_eq!(host.flights().started(FLIGHT_MEMINFO), 1);
    let second = detect(&host, &runner, &c).await.unwrap();
    assert_eq!(
        host.flights().started(FLIGHT_MEMINFO),
        1,
        "the stuck read was not started a second time"
    );
    let notes = second.local.notes.join("; ");
    assert!(notes.contains("still running"), "{notes}");
    // The other blocking reads were not stuck: each detection ran them again.
    assert_eq!(host.flights().started(FLIGHT_HOST_FILES), 2);
    drop(hung);
}
