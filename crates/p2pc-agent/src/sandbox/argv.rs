// SPDX-License-Identifier: Apache-2.0

//! The `podman create` argv (spec §9 "Fixed `podman run` arguments", SI-2), as a pure function.
//!
//! The job cannot change any of the fixed flags. Every value that comes from the job is either a number the agent
//! formats itself, or goes **after** a `--`, where Podman no longer parses options:
//!
//! ```text
//! podman create <fixed flags…> -- <image> -- <command…>
//! ```
//!
//! The first `--` ends Podman's options, so the image can never be read as a flag. Podman passes everything after
//! the image to the entrypoint, `/.p2pc/shim`, which therefore always runs as `/.p2pc/shim -- <command…>` and
//! never parses the job's argv either (the T01 review).
//!
//! The env values go into the `--env-file`, never into the argv. [`env_file`] refuses values with NUL, `\n` or
//! `\r`, which would inject another variable into Podman's line-based format.
//!
//! **Persistent volumes** (H2 §11.1, §11.3; CONTRIBUTING hard rule 3 as amended by O-16) add the one host path
//! beyond the three per-job directories: `-v <volume dir>:<mount>:rw,U` per volume. `<volume dir>` is never a string
//! from the JobSpec: it must be the agent's own `<data_dir>/volumes/<account_id>/<hash>/data`, which [`create_argv`]
//! checks again by its shape, next to the job directory's data dir. `<mount>` is the job's, so it is checked again
//! too: under `/volumes/`, and free of the characters of Podman's mount syntax.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use p2pc_proto::api::Platform;
use p2pc_proto::ids::{AccountId, LeaseId};
use p2pc_proto::validate::validate_volume_mount;

use super::jobdir::JOBS_DIR;
use crate::volumes::{DATA_DIR, Mount, VOLUMES_DIR};

/// `--pids-limit` (§9).
pub const PIDS_LIMIT: u32 = 2048;
/// Largest `/tmp` tmpfs, in MiB (§9: `size=<min(disk, 4096)>m`).
pub const MAX_TMPFS_MB: u64 = 4096;
/// The shim's path inside the container.
pub const SHIM_IN_CONTAINER: &str = "/.p2pc/shim";
/// The label that marks every P2PC container with its lease, used by the orphan sweep.
pub const LEASE_LABEL: &str = "p2pc.lease";
/// Prefix of every container name.
pub const CONTAINER_PREFIX: &str = "p2pc-";

/// The GPU device to pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpuDevice {
    /// `nvidia.com/gpu=<uuid>` (Linux, CDI per device).
    Uuid(String),
    /// `nvidia.com/gpu=all` (WSL2, only with exactly one offerable GPU).
    All,
}

/// Everything the argv depends on. All of it is chosen by the agent, except `image` and `command`, which go after
/// `--`.
#[derive(Debug, Clone)]
pub struct ArgvParams<'a> {
    /// The §9.0 profile.
    pub platform: Platform,
    /// Add `--runtime=runsc` (gVisor configured and ready).
    pub gvisor: bool,
    /// The lease.
    pub lease_id: &'a LeaseId,
    /// `<data_dir>/jobs/<lease_id>`.
    pub job_dir: &'a Path,
    /// The 0600 env file.
    pub env_file: &'a Path,
    /// `--cgroup-parent`.
    pub cgroup_parent: &'a str,
    /// `resources.memory_mb`.
    pub memory_mb: u64,
    /// `resources.cpu`.
    pub cpu: f64,
    /// `resources.disk_mb`.
    pub disk_mb: u64,
    /// The GPU, for GPU jobs.
    pub gpu: Option<GpuDevice>,
    /// The job's image (after `--`).
    pub image: &'a str,
    /// The job's argv (after the second `--`).
    pub command: &'a [String],
    /// The persistent volumes to mount (H2 §11.3), locked and checked by [`crate::volumes::VolumeStore`]. Empty for
    /// every job without volumes: the argv is then H1's.
    pub volumes: &'a [Mount],
}

/// A value that cannot be put into the argv safely. The message never contains env values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot build the podman argv: {0}")]
pub struct ArgvError(pub String);

fn err(msg: impl Into<String>) -> ArgvError {
    ArgvError(msg.into())
}

/// The container name of a lease: `p2pc-<lease_id>`.
#[must_use]
pub fn container_name(lease_id: &LeaseId) -> String {
    format!("{CONTAINER_PREFIX}{lease_id}")
}

/// `--cpus` value: the CPU count rounded to milli-vCPUs, without trailing zeros (`2`, `0.25`, `1.5`).
#[must_use]
pub fn format_cpus(cpu: f64) -> String {
    let milli = (cpu * 1000.0).round();
    // Validated jobs have 0.25-256 vCPUs, so this always fits.
    let milli = if milli.is_finite() && milli > 0.0 {
        milli as u64
    } else {
        0
    };
    let (whole, frac) = (milli / 1000, milli % 1000);
    if frac == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{frac:03}").trim_end_matches('0').to_string()
    }
}

/// A host path for `-v`: absolute, UTF-8, and free of the characters Podman's mount syntax uses (`:` and `,`).
fn mount_path(p: &Path) -> Result<&str, ArgvError> {
    let s = p.to_str().ok_or_else(|| err("the job directory is not valid UTF-8"))?;
    if !p.is_absolute() || s.contains([':', ',']) || s.chars().any(char::is_control) {
        return Err(err(
            "the job directory must be an absolute path without ':', ',' or control characters",
        ));
    }
    Ok(s)
}

/// The `-v` argument of one persistent volume: `<volume dir>:<mount>:rw,U`.
///
/// The host side must be `<data_dir>/volumes/<account_id>/<hash>/data` of the data dir that holds the job directory
/// (`<data_dir>/jobs/<lease_id>`): an account id, 32 hex digits and `data`, nothing else. The container side must be
/// a path under `/volumes/` without `:` or `,`, which would add an option or another path to the argument.
fn volume_arg(job_dir: &Path, volume: &Mount) -> Result<String, ArgvError> {
    let refused = || err("a volume directory is not the agent's own <data_dir>/volumes/<account_id>/<hash>/data");
    let host = mount_path(&volume.host).map_err(|_| refused())?;
    let data_dir = job_dir
        .parent()
        .filter(|jobs| jobs.file_name().is_some_and(|name| name == JOBS_DIR))
        .and_then(Path::parent)
        .ok_or_else(refused)?;
    let below = volume
        .host
        .strip_prefix(data_dir.join(VOLUMES_DIR))
        .map_err(|_| refused())?;
    let parts: Vec<&str> = below.iter().filter_map(|part| part.to_str()).collect();
    let [account, hash, data] = parts.as_slice() else {
        return Err(refused());
    };
    let hash_ok = hash.len() == 32 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if account.parse::<AccountId>().is_err() || !hash_ok || *data != DATA_DIR {
        return Err(refused());
    }
    if validate_volume_mount(&volume.mount).is_err() || volume.mount.contains([':', ',']) {
        return Err(err("a volume mount must be a path under /volumes/ without ':' or ','"));
    }
    Ok(format!("{host}:{}:rw,U", volume.mount))
}

fn check_gpu_uuid(uuid: &str) -> Result<(), ArgvError> {
    let ok = uuid.len() <= 128
        && uuid
            .strip_prefix("GPU-")
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    if ok { Ok(()) } else { Err(err("invalid GPU UUID")) }
}

/// The full argv after `podman`, starting with `create`.
///
/// # Errors
/// [`ArgvError`] when a value cannot be passed safely: an image that is empty, starts with `-` or contains
/// whitespace or control characters, an empty command, an unsafe job directory or cgroup path, a GPU UUID that is
/// not `GPU-…`, a non-positive CPU or memory amount, or a volume whose host directory is not the agent's own or
/// whose mount is not a plain path under `/volumes/`.
pub fn create_argv(p: &ArgvParams<'_>) -> Result<Vec<String>, ArgvError> {
    // The image goes after `--`, so Podman cannot read it as a flag; refusing these is defence in depth (the §7
    // validation already requires a valid OCI reference).
    if p.image.is_empty() || p.image.starts_with('-') || p.image.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(err(
            "the image must be a non-empty OCI reference that does not start with '-'",
        ));
    }
    if p.command.is_empty() {
        return Err(err("the command is empty"));
    }
    if p.command.iter().any(|a| a.contains('\0')) {
        return Err(err("a command argument contains NUL"));
    }
    if !(p.cpu.is_finite() && p.cpu > 0.0) || format_cpus(p.cpu) == "0" {
        return Err(err("cpu must be positive"));
    }
    if p.memory_mb == 0 || p.disk_mb == 0 {
        return Err(err("memory and disk must be positive"));
    }
    let cgroup_ok = !p.cgroup_parent.is_empty()
        && p.cgroup_parent
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'));
    if !cgroup_ok {
        return Err(err("invalid cgroup parent"));
    }
    let job = mount_path(p.job_dir)?;
    let env_file = mount_path(p.env_file)?;
    let volumes = p
        .volumes
        .iter()
        .map(|volume| volume_arg(p.job_dir, volume))
        .collect::<Result<Vec<String>, ArgvError>>()?;

    let mut a: Vec<String> = vec![
        "create".into(),
        "--rm".into(),
        "--network=none".into(),
        // Podman would otherwise copy the host's HTTP(S)_PROXY, FTP_PROXY and NO_PROXY into the container (§9).
        "--http-proxy=false".into(),
        "--cap-drop=all".into(),
        "--security-opt=no-new-privileges".into(),
        format!("--pids-limit={PIDS_LIMIT}"),
        // The agent reads the output by attaching (`podman start --attach`), so Podman keeps no copy: not in its
        // own log store and, where `log_driver` defaults to `journald`, not in the host's system journal either
        // (§7 and §12: a job's output lives only in the lease, under P2PC's retention).
        "--log-driver=none".into(),
    ];
    if p.platform == Platform::Wsl2 {
        a.push("--userns=auto".into());
    }
    if p.gvisor {
        a.push("--runtime=runsc".into());
    }
    let tmpfs_mb = p.disk_mb.min(MAX_TMPFS_MB);
    a.extend([
        format!("--memory={}m", p.memory_mb),
        format!("--memory-swap={}m", p.memory_mb),
        format!("--cpus={}", format_cpus(p.cpu)),
        "--tmpfs".into(),
        format!("/tmp:rw,nosuid,nodev,size={tmpfs_mb}m"),
        // `U`: Podman chowns each directory to the container's (mapped) root, so the job can read its inputs and
        // write its outputs under `--userns=auto` (§9 "Socket permissions"); a no-op for rootless Podman, where
        // that root is the agent's own user.
        "-v".into(),
        format!("{job}/inputs:/inputs:ro,U"),
        "-v".into(),
        format!("{job}/outputs:/outputs:rw,U"),
        "-v".into(),
        format!("{job}/p2pc:/.p2pc:ro,U"),
    ]);
    // The one host path beyond the three per-job directories (hard rule 3's exception, H2 §11.1): the agent's own
    // volume directories, read-write, chowned by `U` to the container's user like the job directories.
    for volume in volumes {
        a.extend(["-v".into(), volume]);
    }
    a.extend([
        "--entrypoint".into(),
        SHIM_IN_CONTAINER.into(),
        "--env-file".into(),
        env_file.into(),
        "--label".into(),
        format!("{LEASE_LABEL}={}", p.lease_id),
        format!("--cgroup-parent={}", p.cgroup_parent),
        "--name".into(),
        container_name(p.lease_id),
    ]);
    match &p.gpu {
        None => {}
        Some(GpuDevice::All) => a.extend(["--device".into(), "nvidia.com/gpu=all".into()]),
        Some(GpuDevice::Uuid(uuid)) => {
            check_gpu_uuid(uuid)?;
            a.extend(["--device".into(), format!("nvidia.com/gpu={uuid}")]);
        }
    }
    // Options end here. The image, then the shim's own `--`, then the job's argv, verbatim.
    a.push("--".into());
    a.push(p.image.into());
    a.push("--".into());
    a.extend(p.command.iter().cloned());
    Ok(a)
}

/// Whether `name` is a valid env name (`[A-Z_][A-Z0-9_]*`, §7).
fn is_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_uppercase() || b == b'_')
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// The content of the `--env-file`: one `NAME=value` line per variable.
///
/// # Errors
/// [`ArgvError`] naming the variable (never its value) if a name is not `[A-Z_][A-Z0-9_]*`, or a value contains
/// NUL, `\n` or `\r`.
pub fn env_file(env: &BTreeMap<String, String>) -> Result<String, ArgvError> {
    let mut out = String::new();
    for (name, value) in env {
        if !is_env_name(name) {
            return Err(err("an env name is not [A-Z_][A-Z0-9_]*"));
        }
        if value.contains(['\0', '\n', '\r']) {
            return Err(err(format!("the value of env {name} contains NUL, \\n or \\r")));
        }
        out.push_str(name);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    Ok(out)
}

/// Shows an argv one argument per line, for golden tests and the PR.
#[derive(Debug)]
pub struct Shown<'a>(pub &'a [String]);

impl fmt::Display for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for a in self.0 {
            writeln!(f, "{a}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use super::*;

    fn lease() -> LeaseId {
        LeaseId::from_str("lse_01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap()
    }

    struct Fixture {
        lease: LeaseId,
        job_dir: PathBuf,
        env_file: PathBuf,
        command: Vec<String>,
    }

    fn fixture() -> Fixture {
        Fixture {
            lease: lease(),
            job_dir: PathBuf::from("/var/lib/p2pc/jobs/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            env_file: PathBuf::from("/var/lib/p2pc/jobs/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV/env"),
            command: vec!["python".into(), "-c".into(), "print(6*7)".into()],
        }
    }

    fn params<'a>(f: &'a Fixture, platform: Platform, cgroup: &'a str) -> ArgvParams<'a> {
        ArgvParams {
            platform,
            gvisor: false,
            lease_id: &f.lease,
            job_dir: &f.job_dir,
            env_file: &f.env_file,
            cgroup_parent: cgroup,
            memory_mb: 4096,
            cpu: 2.0,
            disk_mb: 10_240,
            gpu: None,
            image: "docker.io/library/python:3.12-slim",
            command: &f.command,
            volumes: &[],
        }
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    /// SI-2: the exact argv of the WSL2 profile.
    #[test]
    fn si2_golden_argv_wsl2() {
        let f = fixture();
        let argv = create_argv(&params(&f, Platform::Wsl2, "/p2pc/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV")).unwrap();
        let job = "/var/lib/p2pc/jobs/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let expected = strings(&[
            "create",
            "--rm",
            "--network=none",
            "--http-proxy=false",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--pids-limit=2048",
            "--log-driver=none",
            "--userns=auto",
            "--memory=4096m",
            "--memory-swap=4096m",
            "--cpus=2",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=4096m",
            "-v",
            &format!("{job}/inputs:/inputs:ro,U"),
            "-v",
            &format!("{job}/outputs:/outputs:rw,U"),
            "-v",
            &format!("{job}/p2pc:/.p2pc:ro,U"),
            "--entrypoint",
            "/.p2pc/shim",
            "--env-file",
            &format!("{job}/env"),
            "--label",
            "p2pc.lease=lse_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "--cgroup-parent=/p2pc/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "--name",
            "p2pc-lse_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "--",
            "docker.io/library/python:3.12-slim",
            "--",
            "python",
            "-c",
            "print(6*7)",
        ]);
        assert_eq!(argv, expected, "\n{}", Shown(&argv));
    }

    /// SI-2: the exact argv of the rootless Linux profile: no `--userns=auto`, a systemd slice as the parent.
    #[test]
    fn si2_golden_argv_linux() {
        let f = fixture();
        let mut p = params(&f, Platform::Linux, "p2pc-lse_01ARZ3NDEKTSV4RRFFQ69G5FAV.slice");
        p.cpu = 0.25;
        p.memory_mb = 512;
        p.disk_mb = 1024;
        let argv = create_argv(&p).unwrap();
        let job = "/var/lib/p2pc/jobs/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let expected = strings(&[
            "create",
            "--rm",
            "--network=none",
            "--http-proxy=false",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--pids-limit=2048",
            "--log-driver=none",
            "--memory=512m",
            "--memory-swap=512m",
            "--cpus=0.25",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=1024m",
            "-v",
            &format!("{job}/inputs:/inputs:ro,U"),
            "-v",
            &format!("{job}/outputs:/outputs:rw,U"),
            "-v",
            &format!("{job}/p2pc:/.p2pc:ro,U"),
            "--entrypoint",
            "/.p2pc/shim",
            "--env-file",
            &format!("{job}/env"),
            "--label",
            "p2pc.lease=lse_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "--cgroup-parent=p2pc-lse_01ARZ3NDEKTSV4RRFFQ69G5FAV.slice",
            "--name",
            "p2pc-lse_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "--",
            "docker.io/library/python:3.12-slim",
            "--",
            "python",
            "-c",
            "print(6*7)",
        ]);
        assert_eq!(argv, expected, "\n{}", Shown(&argv));
    }

    fn flags(argv: &[String]) -> &[String] {
        let dash = argv.iter().position(|a| a == "--").unwrap();
        &argv[..dash]
    }

    const ACCOUNT: &str = "acc_01ARZ3NDEKTSV4RRFFQ69G5FAV";

    /// A volume as [`crate::volumes::VolumeStore::lock_and_check`] hands it over: the agent's own directory.
    fn volume(name: &str, mount: &str) -> Mount {
        Mount {
            name: name.into(),
            host: PathBuf::from(format!(
                "/var/lib/p2pc/volumes/{ACCOUNT}/{}/data",
                crate::volumes::dir_name(name)
            )),
            mount: mount.into(),
            max_bytes: 64 << 20,
        }
    }

    /// SI-H2-9: the exact `-v` arguments of persistent volumes (H2 §11.1). They come after the three per-job
    /// directories, read-write with `U`, and nothing else in the argv changes.
    #[test]
    fn si_h2_9_golden_argv_of_the_volume_mounts() {
        let f = fixture();
        let volumes = [
            volume("tpl:private-chat/models", "/volumes/models"),
            volume("models", "/volumes/cache/hf"),
        ];
        let mut p = params(&f, Platform::Wsl2, "/p2pc/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV");
        p.volumes = &volumes;
        let argv = create_argv(&p).unwrap();
        let job = "/var/lib/p2pc/jobs/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let expected = strings(&[
            "create",
            "--rm",
            "--network=none",
            "--http-proxy=false",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--pids-limit=2048",
            "--log-driver=none",
            "--userns=auto",
            "--memory=4096m",
            "--memory-swap=4096m",
            "--cpus=2",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=4096m",
            "-v",
            &format!("{job}/inputs:/inputs:ro,U"),
            "-v",
            &format!("{job}/outputs:/outputs:rw,U"),
            "-v",
            &format!("{job}/p2pc:/.p2pc:ro,U"),
            "-v",
            &format!("/var/lib/p2pc/volumes/{ACCOUNT}/5faf9d87fa1a7df25ef30f96a1d2ffba/data:/volumes/models:rw,U"),
            "-v",
            &format!("/var/lib/p2pc/volumes/{ACCOUNT}/8edcc26c0f6c7256a71a8ede6b954ad9/data:/volumes/cache/hf:rw,U"),
            "--entrypoint",
            "/.p2pc/shim",
            "--env-file",
            &format!("{job}/env"),
            "--label",
            "p2pc.lease=lse_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "--cgroup-parent=/p2pc/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "--name",
            "p2pc-lse_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "--",
            "docker.io/library/python:3.12-slim",
            "--",
            "python",
            "-c",
            "print(6*7)",
        ]);
        assert_eq!(argv, expected, "\n{}", Shown(&argv));
        // The volume's name never reaches the argv: only its hash does.
        assert!(argv.iter().all(|a| !a.contains("tpl:") && !a.contains("private-chat")));
        // Without the volumes the argv is H1's, to the letter: the mounts are the only difference.
        let mut h1 = argv.clone();
        h1.drain(20..24);
        p.volumes = &[];
        assert_eq!(create_argv(&p).unwrap(), h1);
        // Every host path that is mounted is a per-job directory or a volume's `data/`, on both profiles.
        p.volumes = &volumes;
        for platform in [Platform::Linux, Platform::Wsl2] {
            p.platform = platform;
            let argv = create_argv(&p).unwrap();
            let mounted: Vec<&str> = argv
                .iter()
                .zip(argv.iter().skip(1))
                .filter(|(flag, _)| *flag == "-v")
                .map(|(_, spec)| spec.split(':').next().unwrap())
                .collect();
            assert_eq!(mounted.len(), 5, "{platform:?}");
            assert!(
                mounted
                    .iter()
                    .all(|host| host.starts_with(job) || host.starts_with("/var/lib/p2pc/volumes/")),
                "{mounted:?}"
            );
        }
    }

    /// Hard rule 3's exception is exact: a volume directory is the agent's own, named by a hash, and no string from
    /// the JobSpec can turn the `-v` argument into another path or add an option to it.
    #[test]
    fn a_volume_that_is_not_the_agents_own_directory_or_a_hostile_mount_is_refused() {
        let f = fixture();
        let good = volume("models", "/volumes/models");
        let with = |change: &dyn Fn(&mut Mount)| {
            let mut v = good.clone();
            change(&mut v);
            let volumes = [v];
            let mut p = params(&f, Platform::Wsl2, "/p2pc/x");
            p.volumes = &volumes;
            create_argv(&p)
        };
        assert!(with(&|_| {}).is_ok());
        let hash = crate::volumes::dir_name("models");
        let hosts = [
            // A path the JobSpec could name.
            "/etc".to_string(),
            "/".to_string(),
            "/var/lib/p2pc".to_string(),
            "/run/podman/podman.sock".to_string(),
            // The volume directory itself (with `meta.json`), not its `data/`.
            format!("/var/lib/p2pc/volumes/{ACCOUNT}/{hash}"),
            // Not a hash: a volume's name used as a directory.
            format!("/var/lib/p2pc/volumes/{ACCOUNT}/models/data"),
            format!("/var/lib/p2pc/volumes/{ACCOUNT}/{}/data", hash.to_uppercase()),
            // Not an account's directory.
            format!("/var/lib/p2pc/volumes/shared/{hash}/data"),
            // Another data dir, a job directory, a deeper path, a relative one.
            format!("/srv/other/volumes/{ACCOUNT}/{hash}/data"),
            "/var/lib/p2pc/jobs/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV/outputs".to_string(),
            format!("/var/lib/p2pc/volumes/{ACCOUNT}/{hash}/data/sub"),
            format!("/var/lib/p2pc/volumes/{ACCOUNT}/{hash}/data/../../.."),
            format!("volumes/{ACCOUNT}/{hash}/data"),
        ];
        for host in hosts {
            let refused = with(&|v| v.host = PathBuf::from(&host));
            assert!(refused.is_err(), "{host}");
        }
        let mounts = [
            "/etc",
            "/",
            "/volumes",
            "/volumes/",
            "/volumes/../etc",
            "/inputs/x",
            "/.p2pc",
            "volumes/x",
            "/volumes/x:ro",
            "/volumes/x:/etc",
            "/volumes/x,ro",
            "/volumes/x:rw,U,exec",
            "/volumes/x\0",
            "",
        ];
        for mount in mounts {
            let refused = with(&|v| v.mount = mount.into());
            assert!(refused.is_err(), "{mount:?}");
        }
        // A job directory that is not `<data_dir>/jobs/<lease_id>` gives no data dir to compare with.
        let elsewhere = PathBuf::from("/var/lib/p2pc/work/lse_01ARZ3NDEKTSV4RRFFQ69G5FAV");
        let volumes = [good.clone()];
        let mut p = params(&f, Platform::Wsl2, "/p2pc/x");
        p.job_dir = &elsewhere;
        p.volumes = &volumes;
        assert!(create_argv(&p).is_err());
    }

    /// T10m: a job's output never reaches Podman's log store or the host's journal; the agent reads it by attaching.
    #[test]
    fn the_container_keeps_no_log_of_its_own() {
        let f = fixture();
        for platform in [Platform::Linux, Platform::Wsl2] {
            let argv = create_argv(&params(&f, platform, "p2pc-x.slice")).unwrap();
            let logs: Vec<_> = flags(&argv).iter().filter(|a| a.starts_with("--log-")).collect();
            assert_eq!(logs, ["--log-driver=none"], "{platform:?}");
        }
    }

    #[test]
    fn gpu_on_and_off() {
        let f = fixture();
        let mut p = params(&f, Platform::Linux, "p2pc-x.slice");
        assert!(!create_argv(&p).unwrap().iter().any(|a| a.contains("nvidia")));
        p.gpu = Some(GpuDevice::Uuid("GPU-6a3d0a2e-1b2c-4d5e-8f90-123456789abc".into()));
        let argv = create_argv(&p).unwrap();
        let at = argv.iter().position(|a| a == "--device").unwrap();
        assert_eq!(argv[at + 1], "nvidia.com/gpu=GPU-6a3d0a2e-1b2c-4d5e-8f90-123456789abc");
        assert!(
            at < argv.iter().position(|a| a == "--").unwrap(),
            "the device is a flag, before `--`"
        );
        p.platform = Platform::Wsl2;
        p.gpu = Some(GpuDevice::All);
        let argv = create_argv(&p).unwrap();
        let at = argv.iter().position(|a| a == "--device").unwrap();
        assert_eq!(argv[at + 1], "nvidia.com/gpu=all");
    }

    #[test]
    fn runsc_on_and_off() {
        let f = fixture();
        let mut p = params(&f, Platform::Wsl2, "/p2pc/x");
        assert!(!create_argv(&p).unwrap().iter().any(|a| a.starts_with("--runtime")));
        p.gvisor = true;
        let argv = create_argv(&p).unwrap();
        assert_eq!(flags(&argv).iter().filter(|a| *a == "--runtime=runsc").count(), 1);
    }

    #[test]
    fn hostile_values_cannot_inject_flags() {
        let f = fixture();
        // An image that looks like a flag is refused outright.
        for image in [
            "--privileged",
            "-v/:/host",
            "",
            "docker.io/x y",
            "docker.io/x\n--privileged",
        ] {
            let mut p = params(&f, Platform::Linux, "p2pc-x.slice");
            p.image = image;
            assert!(create_argv(&p).is_err(), "{image:?}");
        }
        // Hostile command arguments only ever appear after the second `--`, verbatim.
        let hostile: Vec<String> = strings(&["--privileged", "--network=host", "-v", "/:/host", "--", "$(id)"]);
        let mut p = params(&f, Platform::Linux, "p2pc-x.slice");
        p.command = &hostile;
        let argv = create_argv(&p).unwrap();
        let first = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(argv[first + 1], p.image);
        assert_eq!(argv[first + 2], "--");
        assert_eq!(&argv[first + 3..], hostile.as_slice());
        assert!(
            !flags(&argv)
                .iter()
                .any(|a| a == "--privileged" || a == "--network=host")
        );
        assert_eq!(flags(&argv).iter().filter(|a| a.starts_with("--network")).count(), 1);
        // An empty command is refused (the shim would refuse it anyway).
        let empty: Vec<String> = Vec::new();
        p.command = &empty;
        assert!(create_argv(&p).is_err());
    }

    #[test]
    fn the_job_name_never_reaches_the_argv() {
        // The argv has no field for the job's name: a name full of shell metacharacters cannot appear in it. The
        // container name is derived from the lease ID only.
        let f = fixture();
        let argv = create_argv(&params(&f, Platform::Linux, "p2pc-x.slice")).unwrap();
        let name_at = argv.iter().position(|a| a == "--name").unwrap();
        assert_eq!(argv[name_at + 1], container_name(&f.lease));
        assert!(argv.iter().all(|a| !a.contains(['$', '`', ';', '|', '&'])), "{argv:?}");
    }

    #[test]
    fn unsafe_agent_values_are_refused() {
        let f = fixture();
        let mut p = params(&f, Platform::Linux, "p2pc-x.slice");
        let bad_dir = PathBuf::from("/var/lib/p2pc:/etc/jobs/x");
        p.job_dir = &bad_dir;
        assert!(create_argv(&p).is_err(), "':' would split the -v spec");
        let relative = PathBuf::from("jobs/x");
        p.job_dir = &relative;
        assert!(create_argv(&p).is_err());
        let mut p = params(&f, Platform::Linux, "p2pc-x.slice --privileged");
        assert!(create_argv(&p).is_err());
        p.cgroup_parent = "p2pc-x.slice";
        for uuid in [
            "GPU-1,nvidia.com/gpu=all",
            "GPU-",
            "MIG-1234",
            "GPU-1 --privileged",
            "all",
        ] {
            p.gpu = Some(GpuDevice::Uuid(uuid.into()));
            assert!(create_argv(&p).is_err(), "{uuid}");
        }
        p.gpu = None;
        p.cpu = 0.0;
        assert!(create_argv(&p).is_err());
        p.cpu = 1.0;
        p.memory_mb = 0;
        assert!(create_argv(&p).is_err());
    }

    #[test]
    fn cpus_are_formatted_in_milli_vcpus() {
        assert_eq!(format_cpus(2.0), "2");
        assert_eq!(format_cpus(0.25), "0.25");
        assert_eq!(format_cpus(1.5), "1.5");
        assert_eq!(format_cpus(0.001), "0.001");
        assert_eq!(format_cpus(0.1 + 0.2), "0.3");
        assert_eq!(format_cpus(256.0), "256");
    }

    #[test]
    fn tmpfs_is_capped_at_4096() {
        let f = fixture();
        let mut p = params(&f, Platform::Linux, "p2pc-x.slice");
        p.disk_mb = 100;
        assert!(
            create_argv(&p)
                .unwrap()
                .contains(&"/tmp:rw,nosuid,nodev,size=100m".to_string())
        );
        p.disk_mb = 1_000_000;
        assert!(
            create_argv(&p)
                .unwrap()
                .contains(&"/tmp:rw,nosuid,nodev,size=4096m".to_string())
        );
    }

    #[test]
    fn env_file_lines_and_injection() {
        let mut env = BTreeMap::new();
        env.insert("A".to_string(), "1".to_string());
        env.insert("KEY_2".to_string(), "x=y z".to_string());
        assert_eq!(env_file(&env).unwrap(), "A=1\nKEY_2=x=y z\n");
        assert_eq!(env_file(&BTreeMap::new()).unwrap(), "");
        for value in ["a\nINJECTED=1", "a\rb", "a\0b"] {
            let mut env = BTreeMap::new();
            env.insert("SECRET".to_string(), value.to_string());
            let e = env_file(&env).unwrap_err();
            assert!(e.0.contains("SECRET"));
            assert!(
                !e.0.contains("INJECTED") && !e.0.contains('\n'),
                "never echoes the value: {e}"
            );
        }
        for name in ["lower", "1ABC", "A-B", "A*", "", "A=B"] {
            let mut env = BTreeMap::new();
            env.insert(name.to_string(), "v".to_string());
            assert!(env_file(&env).is_err(), "{name:?}");
        }
    }
}
