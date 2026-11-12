// SPDX-License-Identifier: Apache-2.0

//! `p2pc-agent doctor` and the human form of `p2pc-agent inventory`: readiness in plain text, with a fix hint for
//! each problem. Nothing here changes the machine, except the egress socket check, which makes a test job directory
//! and socket under the data dir and removes them again.
//!
//! The relay check (H2 §10.2-§10.3) is doctor's only network traffic: one `GET /ping` to each relay this node uses,
//! within [`RELAY_PROBE_TIMEOUT`], for its reachability and latency, next to the map's rules from `p2pc-net` (which
//! relays offer QUIC address discovery, without which no egress job starts).

use std::fmt::Write as _;
use std::os::unix::fs::MetadataExt;

use std::path::Path;
use std::sync::Arc;

use iroh::RelayUrl;
use p2pc_net::relays::{
    AddressDiscovery, RELAY_PROBE_TIMEOUT, Reachability, RelayMapReport, RelayProber, Role, Severity, check_relay_map,
    probe_relays,
};

use p2pc_proto::api::{GpuStatusKind, Inventory, Platform};
use p2pc_proto::ids::LeaseId;

use crate::inventory::{BootStatus, DetectError, Probe, Report, clean};
use crate::platform::Problem;
use crate::sandbox::jobdir::{JOBS_DIR, JobDir};

/// What doctor found about the identity key.
#[derive(Debug)]
pub enum IdentityState {
    /// The key loaded: its public NodeId.
    Ok(String),
    /// No key yet; `p2pc-agent identity` (or the first start) creates it.
    Missing,
    /// The key exists but is refused, with the reason.
    Refused(String),
}

/// Everything doctor reports on.
#[derive(Debug)]
pub struct Findings<'a> {
    /// Where the config came from, as a sentence.
    pub config_source: String,
    /// The config error, when it did not load (defaults were used to keep checking).
    pub config_error: Option<String>,
    /// The identity key.
    pub identity: IdentityState,
    /// The machine probe.
    pub probe: &'a Probe,
    /// The inventory built from it, or why it could not be built.
    pub report: &'a Result<Report, DetectError>,
    /// Whether a job's egress socket can be created under the data dir ([`check_egress_socket`]).
    pub egress_socket: EgressSocketState,
    /// The relays: the map's rules and each relay's probe ([`check_relays`]).
    pub relays: RelayState,
}

/// What [`check_relays`] found (H2 §10.2-§10.3).
#[derive(Debug)]
pub enum RelayState {
    /// No relay to check: the node has not joined, and `[iroh] relays` is empty.
    NotEnrolled,
    /// The map's rules were checked, but no relay was probed: why.
    NotProbed {
        /// The map's rules.
        map: RelayMapReport,
        /// Why nothing was probed.
        why: String,
    },
    /// The map's rules, and each usable relay's probe in the map's order.
    Checked {
        /// The map's rules.
        map: RelayMapReport,
        /// Each relay's reachability.
        probes: Vec<(RelayUrl, Reachability)>,
    },
}

/// Checks the relays the agent uses (`relays`, from [`crate::config::Config::relays`]) under the node rules of H2 §10.3,
/// and probes each one with `prober` (or says why it cannot). `enrolled`: whether the node has joined.
pub async fn check_relays<P: RelayProber>(
    prober: Result<Arc<P>, String>,
    relays: &[String],
    enrolled: bool,
) -> RelayState {
    if relays.is_empty() && !enrolled {
        return RelayState::NotEnrolled;
    }
    let map = check_relay_map(relays, Role::Node);
    match prober {
        Err(why) => RelayState::NotProbed { map, why },
        Ok(prober) => {
            let urls: Vec<RelayUrl> = map.relays.iter().map(|r| r.url.clone()).collect();
            let probes = probe_relays(prober, &urls, RELAY_PROBE_TIMEOUT).await;
            RelayState::Checked { map, probes }
        }
    }
}

/// What to do about a relay problem, by its code.
fn relay_fix(code: &str) -> &'static str {
    match code {
        "relay_invalid_url" => {
            "write each relay as `https://<host>/` in `[iroh] relays` of the config, or join again with a token whose \
             relays are valid"
        }
        "relay_not_https" => "use the relay's https URL; plain http is for a development relay on this machine",
        "relay_host_not_allowed" => "use the relay's public DNS name",
        "relay_no_address_discovery" => {
            "add n0's public relays to `[iroh] relays` in the config, next to the hub's (H2 §10.3); until then every \
             job with an egress list fails with `egress_unavailable`"
        }
        "relays_unreachable" => {
            "check this machine's internet access, and that no firewall blocks https to the relays; without a relay \
             the node reaches the hub only directly"
        }
        _ => "fix the relay list in the config",
    }
}

/// The relay section of doctor's report. Returns how many blocking problems it shows.
fn relay_lines(out: &mut String, state: &RelayState) -> usize {
    let (map, probes, not_probed) = match state {
        RelayState::NotEnrolled => {
            let _ = writeln!(out, "Relays: none yet (`p2pc-agent join` stores the hub's)");
            return 0;
        }
        RelayState::NotProbed { map, why } => (map, None, Some(why)),
        RelayState::Checked { map, probes } => (map, Some(probes), None),
    };
    let discovery = if map.has_address_discovery() {
        "address discovery through n0's public relays"
    } else {
        "address discovery: NONE"
    };
    let count = map.relays.len();
    let _ = match (count, not_probed, probes) {
        (0, _, _) => writeln!(out, "Relays: none; {discovery}"),
        (_, Some(why), _) => writeln!(out, "Relays: {count}, not probed ({}); {discovery}", clean(why)),
        (_, None, probes) => {
            let reachable = probes
                .into_iter()
                .flatten()
                .filter(|(_, r)| matches!(r, Reachability::Reachable(_)))
                .count();
            writeln!(out, "Relays: {count}, {reachable} reachable; {discovery}")
        }
    };
    for (i, relay) in map.relays.iter().enumerate() {
        let reach = match probes.and_then(|p| p.get(i)) {
            Some((_, Reachability::Reachable(latency))) => format!("reachable, {} ms; ", latency.as_millis()),
            Some((_, Reachability::Unreachable(why))) => format!("unreachable: {}; ", clean(why)),
            Some((_, Reachability::TimedOut(after))) => format!("no answer within {} s; ", after.as_secs()),
            None => String::new(),
        };
        let discovery = match relay.address_discovery {
            AddressDiscovery::Offered => "yes (n0's public relay)",
            AddressDiscovery::Unknown => "unknown (only with TLS and UDP on the relay)",
            AddressDiscovery::NotOffered => "no (plain http)",
        };
        // A relay URL displays parsed: the parser percent-encodes control characters (relays.rs).
        let _ = writeln!(out, "  - {}: {reach}address discovery: {discovery}", relay.url);
    }
    let mut blocking = 0;
    for f in &map.findings {
        let mark = match f.severity {
            Severity::Error => {
                blocking += 1;
                "[x]"
            }
            Severity::Warning => "[!]",
        };
        let code = f.problem.code();
        let _ = writeln!(out, "  {mark} {code}: {}", f.problem);
        let _ = writeln!(out, "      fix: {}", relay_fix(code));
    }
    if let Some(probes) = probes
        && !probes.is_empty()
        && !probes.iter().any(|(_, r)| matches!(r, Reachability::Reachable(_)))
    {
        blocking += 1;
        let _ = writeln!(out, "  [x] relays_unreachable: no relay answered its probe");
        let _ = writeln!(out, "      fix: {}", relay_fix("relays_unreachable"));
    }
    blocking
}

/// What [`check_egress_socket`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressSocketState {
    /// A test socket was made in a job-like directory and removed.
    Ok,
    /// It could not be made: what failed, with the paths involved.
    Failed(String),
    /// Not checked, and not a problem of the node: why (no data dir yet, or doctor runs as another user).
    NotChecked(String),
}

/// Why `p2pc-agent doctor` says a job's egress socket cannot be created, and what to do.
const EGRESS_SOCKET_FIX: &str = "jobs with an egress list fail with `egress_unavailable` until this works; check that \
     /proc is mounted, that the data dir is on a local filesystem owned by the agent's user, and that no security \
     policy (AppArmor, SELinux) refuses unix sockets there";

/// Creates a socket in a job-like directory under `data_dir` (`<data_dir>/jobs/<lease>/p2pc/`), the way the egress
/// proxy does for a job, and removes it again, `<data_dir>/jobs` too when the check made it.
///
/// It is skipped, and says so, when the data dir does not exist yet or belongs to another user than the one doctor
/// runs as: `sudo p2pc-agent doctor` would make a root-owned `jobs/` in the agent's data dir and report on root, not on
/// the agent.
#[must_use]
pub fn check_egress_socket(data_dir: &Path) -> EgressSocketState {
    check_egress_socket_as(data_dir, rustix::process::geteuid().as_raw())
}

/// [`check_egress_socket`] for a doctor whose effective uid is `euid` (a parameter so the other-user case can be tested).
fn check_egress_socket_as(data_dir: &Path, euid: u32) -> EgressSocketState {
    // Follow a symlink, as `JobDir::create` does: the owner that counts is the target's.
    match std::fs::metadata(data_dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return EgressSocketState::NotChecked("the data dir does not exist yet".into());
        }
        Ok(meta) if meta.is_dir() && meta.uid() != euid => {
            return EgressSocketState::NotChecked(format!(
                "the data dir belongs to uid {}, and doctor runs as uid {euid}; run it as the agent's user: \
                 sudo -u p2pc p2pc-agent doctor",
                meta.uid()
            ));
        }
        // Anything else (a file instead of a directory, no access) fails below, naming the path.
        _ => {}
    }
    let jobs = data_dir.join(JOBS_DIR);
    let jobs_existed = std::fs::symlink_metadata(&jobs).is_ok();
    let made = match JobDir::create(data_dir, &LeaseId::generate()) {
        Err(e) => Err(format!(
            "cannot make a test job directory under {}: {e}",
            data_dir.display()
        )),
        Ok(dir) => {
            let made = crate::egress::check_socket_creation(&dir.p2pc()).map_err(|e| e.to_string());
            if let Err(e) = dir.remove() {
                tracing::warn!(dir = %dir.root().display(), error = %e, "doctor: cannot remove the test job directory");
            }
            made
        }
    };
    // Leave `jobs/` as it was. `remove_dir` refuses a directory with something in it (a running agent's job).
    if !jobs_existed
        && let Err(e) = std::fs::remove_dir(&jobs)
        && !matches!(
            e.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
        )
    {
        tracing::warn!(dir = %jobs.display(), error = %e, "doctor: cannot remove the test jobs directory");
    }
    match made {
        Ok(()) => EgressSocketState::Ok,
        Err(e) => EgressSocketState::Failed(e),
    }
}

fn gpu_hint(kind: GpuStatusKind, platform: Platform) -> Option<&'static str> {
    match (kind, platform) {
        (GpuStatusKind::Ok, _) => None,
        (GpuStatusKind::NoDriver, Platform::Linux) => {
            Some("install the NVIDIA driver; on a CPU-only node there is nothing to do")
        }
        (GpuStatusKind::NoDriver, Platform::Wsl2) => Some(
            "install or update the NVIDIA driver on Windows (the distro has no driver of its own); on a CPU-only \
             node there is nothing to do",
        ),
        (GpuStatusKind::NvmlError, Platform::Linux) => {
            Some("run `nvidia-smi` to see the error; after a driver update, reboot")
        }
        (GpuStatusKind::NvmlError, Platform::Wsl2) => {
            Some("run `nvidia-smi` to see the error; after a driver update, run `wsl --shutdown` on Windows")
        }
        (GpuStatusKind::NotFound, _) => Some("no NVIDIA GPU was found; on a CPU-only node there is nothing to do"),
        (GpuStatusKind::CdiMissing | GpuStatusKind::CdiStale, Platform::Linux) => {
            Some("run the command above as root; the agent never generates the spec itself")
        }
        (GpuStatusKind::CdiMissing | GpuStatusKind::CdiStale, Platform::Wsl2) => Some(
            "run the command above as root, or restart the distro so that its boot step regenerates the spec; the \
             agent never generates it itself",
        ),
    }
}

fn platform_name(p: Platform) -> &'static str {
    match p {
        Platform::Linux => "linux (rootless Podman as the `p2pc` user)",
        Platform::Wsl2 => "wsl2 (root inside the dedicated `p2pc-node` distro)",
    }
}

fn problem_lines(out: &mut String, problems: &[Problem]) {
    for p in problems {
        let _ = writeln!(out, "  [x] {}: {}", p.code, p.detail);
        let _ = writeln!(out, "      fix: {}", p.hint);
    }
}

/// Renders doctor's report. Returns the text and whether the node is ready to run jobs.
#[must_use]
pub fn render(f: &Findings<'_>) -> (String, bool) {
    let mut out = String::new();
    let mut blocking = 0usize;
    let probe = f.probe;
    let _ = writeln!(out, "p2pc-agent doctor {}", crate::inventory::AGENT_VERSION);
    let _ = writeln!(out);
    let _ = writeln!(out, "Platform: {}", platform_name(probe.platform));
    let _ = writeln!(out, "Config:   {}", f.config_source);
    if let Some(e) = &f.config_error {
        blocking += 1;
        let _ = writeln!(out, "  [x] config_invalid: {e}");
        let _ = writeln!(out, "      fix: edit the file (the checks below use the defaults)");
    }
    match &f.identity {
        IdentityState::Ok(id) => {
            let _ = writeln!(out, "Identity: {id}");
        }
        IdentityState::Missing => {
            let _ = writeln!(out, "Identity: not created yet (`p2pc-agent identity` creates it)");
        }
        IdentityState::Refused(e) => {
            blocking += 1;
            let _ = writeln!(out, "Identity: refused");
            let _ = writeln!(out, "  [x] identity_refused: {e}");
            let _ = writeln!(
                out,
                "      fix: see the message; if the key is lost, delete the node and join again"
            );
        }
    }
    let _ = writeln!(out);
    let ready = probe.problems.is_empty();
    blocking += probe.problems.len();
    let class = probe.sandbox.runtime;
    let _ = writeln!(
        out,
        "Sandbox (podman, runtime {class}): {}",
        if ready { "ready" } else { "NOT READY" }
    );
    problem_lines(&mut out, &probe.problems);
    // §9.0: the VM-wide WSLInterop binfmt entry is information, not a verdict.
    if probe.platform == Platform::Wsl2 && probe.sandbox.binfmt_interop {
        let _ = writeln!(out, "  [i] note: {}", crate::platform::BINFMT_INTEROP_NOTE);
    }
    match &f.egress_socket {
        EgressSocketState::NotChecked(why) => {
            let _ = writeln!(out, "Egress socket: not checked ({})", clean(why));
        }
        EgressSocketState::Ok => {
            let _ = writeln!(
                out,
                "Egress socket: ok (a test socket was made and removed under the data dir)"
            );
        }
        EgressSocketState::Failed(e) => {
            blocking += 1;
            let _ = writeln!(out, "Egress socket: cannot be created");
            let _ = writeln!(out, "  [x] egress_socket_failed: {}", clean(e));
            let _ = writeln!(out, "      fix: {EGRESS_SOCKET_FIX}");
        }
    }
    blocking += relay_lines(&mut out, &f.relays);
    let gpu = probe.gpu_status();
    let _ = write!(out, "GPU: {}", gpu_status_name(gpu.status));
    if let Some(reason) = &gpu.reason {
        let _ = write!(out, ": {}", clean(reason));
    }
    let _ = writeln!(out);
    for g in &probe.gpu.gpus {
        let _ = writeln!(out, "  - {}", gpu_line(g));
    }
    for note in &probe.gpu.notes {
        let _ = writeln!(out, "  [!] {}", clean(note));
    }
    if let Some(hint) = gpu_hint(gpu.status, probe.platform) {
        let _ = writeln!(out, "      fix: {hint}");
    }
    // WSL2: the boot step's report, which decides whether GPUs are offered (carry-over 9).
    match &probe.boot {
        None => {}
        Some(BootStatus::Ok { cdi }) => {
            let _ = writeln!(out, "Boot status: ok (CDI {})", clean(cdi));
        }
        Some(status @ (BootStatus::Failed { .. } | BootStatus::NotReady { .. })) => {
            let state = if matches!(status, BootStatus::Failed { .. }) {
                "failed"
            } else {
                "not ready"
            };
            let why = status.blocks_gpus().unwrap_or_default();
            let _ = writeln!(out, "Boot status: {state}; GPUs are not offered");
            let _ = writeln!(out, "  [!] {}", clean(&why));
            let _ = writeln!(
                out,
                "      fix: read {}; restarting the distro (`wsl --terminate p2pc-node`) runs p2pc-boot again",
                crate::inventory::boot::BOOT_STATUS_FILE
            );
        }
    }
    match f.report {
        Ok(report) => {
            let s = &report.local.share;
            let _ = writeln!(
                out,
                "Share: {} vCPU, {} MiB RAM, {} GPU, {} MiB disk",
                s.cpu_cores,
                s.memory_mb,
                s.gpus.len(),
                s.disk_mb
            );
            for w in &s.warnings {
                let _ = writeln!(out, "  [!] {w}");
            }
        }
        Err(e) => {
            blocking += 1;
            let _ = writeln!(out, "Share: cannot build the inventory");
            let _ = writeln!(out, "  [x] {e}");
            let _ = writeln!(out, "      fix: adjust [share] in the config file");
        }
    }
    // Parts of the detection that hit the deadline (or are still stuck): their own block, since they can concern
    // any section (T07b review, carry-over 5).
    if !probe.notes.is_empty() {
        let _ = writeln!(out, "Detection:");
        for note in &probe.notes {
            let _ = writeln!(out, "  [!] {}", clean(note));
        }
    }
    let _ = writeln!(out);
    if blocking == 0 {
        let _ = writeln!(out, "Result: ready.");
    } else {
        let _ = writeln!(
            out,
            "Result: NOT READY ({blocking} problem{}). Nothing was changed: apply the fixes above, then run \
             `p2pc-agent doctor` again.",
            if blocking == 1 { "" } else { "s" }
        );
    }
    (out, blocking == 0)
}

fn gpu_status_name(kind: GpuStatusKind) -> &'static str {
    match kind {
        GpuStatusKind::Ok => "ok",
        GpuStatusKind::NoDriver => "no_driver",
        GpuStatusKind::NvmlError => "nvml_error",
        GpuStatusKind::NotFound => "not_found",
        GpuStatusKind::CdiMissing => "cdi_missing",
        GpuStatusKind::CdiStale => "cdi_stale",
    }
}

fn gpu_line(g: &p2pc_proto::api::GpuInfo) -> String {
    let vram = g
        .vram_mb
        .map_or_else(|| "VRAM unknown".to_string(), |v| format!("{v} MiB"));
    let offerable = if g.mig {
        ", MIG enabled or unknown: not offerable"
    } else if g.vram_mb.is_none() {
        ": not offerable"
    } else {
        ""
    };
    // The name and the driver version are the tool's text: clean them like the inventory does.
    format!(
        "{} {} ({vram}, driver {}){offerable}",
        clean(&g.uuid),
        clean(&g.name),
        clean(&g.driver_version)
    )
}

/// The human form of `p2pc-agent inventory`.
#[must_use]
pub fn inventory_text(report: &Report) -> String {
    let inv: &Inventory = &report.inventory;
    let mut out = String::new();
    let _ = writeln!(out, "hostname    {}", inv.hostname);
    let _ = writeln!(out, "platform    {}", platform_name(inv.platform));
    let _ = writeln!(out, "os          {} ({})", inv.os, inv.arch);
    let _ = writeln!(out, "cpu         {} ({} logical cores)", inv.cpu.model, inv.cpu.cores);
    let _ = writeln!(out, "memory      {} MiB", inv.memory_mb);
    let _ = write!(out, "gpu status  {}", gpu_status_name(inv.gpu_status.status));
    if let Some(reason) = &inv.gpu_status.reason {
        let _ = write!(out, ": {reason}");
    }
    let _ = writeln!(out);
    for g in &inv.gpus {
        let _ = writeln!(out, "gpu         {}", gpu_line(g));
    }
    let _ = writeln!(out, "/dev/dxg    {}", if inv.dxg { "present" } else { "absent" });
    if let Some(w) = &inv.wsl2 {
        let unknown = |s: &Option<String>| s.clone().unwrap_or_else(|| "unknown".to_string());
        let _ = writeln!(
            out,
            "wsl2        distro {}, podman {}, CDI {}{}",
            unknown(&w.distro_version),
            unknown(&w.podman_version),
            if w.cdi_present { "present" } else { "missing" },
            if w.cdi_stale { " (stale)" } else { "" }
        );
    }
    let local = &report.local;
    let tool = |t: &crate::platform::Tool| match t {
        crate::platform::Tool::Available { version } => version.clone().unwrap_or_else(|| "available".into()),
        crate::platform::Tool::Unavailable => "unavailable".into(),
        crate::platform::Tool::Failed { reason } => format!("error: {reason}"),
    };
    let _ = writeln!(
        out,
        "tools       podman {}, crun {}, runsc {}, nvidia-ctk {}",
        tool(&local.podman.tool),
        tool(&local.crun),
        tool(&local.runsc),
        tool(&local.cdi.nvidia_ctk)
    );
    if !local.cdi.devices.is_empty() {
        let _ = writeln!(out, "cdi         {}", local.cdi.devices.join(", "));
    }
    for sb in &inv.sandbox {
        let class = serde_json::to_value(sb.class)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "sandbox     {} {class} [{}]: {}",
            sb.driver,
            sb.runtimes.join(", "),
            if sb.ready {
                "ready".to_string()
            } else {
                format!("not ready ({} problems; run `p2pc-agent doctor`)", sb.problems.len())
            }
        );
    }
    let _ = writeln!(
        out,
        "offered     {} vCPU, {} MiB RAM, {} GPU, {} MiB disk",
        inv.offered.cpu, inv.offered.memory_mb, inv.offered.gpu, local.share.disk_mb
    );
    for w in &local.share.warnings {
        let _ = writeln!(out, "warning     {w}");
    }
    let _ = writeln!(out, "agent       {}", inv.agent_version);
    out
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use p2pc_net::relays::RelayProber;

    use super::*;
    use crate::config::{Config, Env};
    use crate::host::Host;
    use crate::runner::FakeRunner;

    fn fake_probe(platform_file: &str) -> (tempfile::TempDir, Probe) {
        let dir = tempfile::tempdir().unwrap();
        let w = |p: &str, c: &str| {
            let full = dir.path().join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, c).unwrap();
        };
        w("proc/version", platform_file);
        if platform_file.contains("microsoft") {
            // A WSL distro, not just its kernel (WSL's init makes /run/WSL in every distro).
            w("run/WSL/.marker", "");
        }
        w(
            "proc/cpuinfo",
            "processor : 0\nmodel name : Example CPU\nprocessor : 1\n",
        );
        w("proc/meminfo", "MemTotal: 8192000 kB\n");
        w("proc/self/status", "Uid:\t1000\t1000\t1000\t1000\n");
        let probe = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(crate::inventory::probe(
                &Host::with_root(dir.path()),
                &FakeRunner::new(),
                crate::config::Runtime::Crun,
                Path::new("/var/lib/p2pc"),
                std::time::Duration::from_secs(crate::config::DEFAULT_DETECT_TIMEOUT_S),
            ));
        (dir, probe)
    }

    fn config() -> Config {
        Config::parse(
            "",
            &Env {
                root: false,
                home: Some("/home/p2pc".into()),
                config_env: None,
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn doctor_lists_every_problem_with_a_fix() {
        let (_dir, probe) = fake_probe("Linux version 6.6.87.2-microsoft-standard-WSL2\n");
        let report = probe.clone().report(&config());
        let findings = Findings {
            config_source: "/home/p2pc/.config/p2pc-agent/agent.toml (not found: defaults)".into(),
            config_error: None,
            identity: IdentityState::Missing,
            probe: &probe,
            report: &report,
            egress_socket: EgressSocketState::Ok,
            relays: RelayState::NotEnrolled,
        };
        let (text, ready) = render(&findings);
        assert!(!ready);
        assert!(text.contains("Platform: wsl2"), "{text}");
        for code in [
            "not_root",
            "subuid_range_missing",
            "podman_not_found",
            "runtime_not_found",
        ] {
            assert!(text.contains(&format!("[x] {code}: ")), "{code} missing in:\n{text}");
        }
        assert_eq!(
            text.matches("[x] ").count(),
            text.matches("      fix: ").count() - 1,
            "one fix per problem, plus the GPU hint:\n{text}"
        );
        assert!(text.contains("GPU: no_driver"));
        assert!(text.contains("Result: NOT READY"));
    }

    /// T10n: a node where a job's egress socket cannot be made is not ready, whatever else is fine, and doctor says
    /// why and what to check (ACC-1 round 2: every egress job failed in 14 ms with nothing in the log).
    #[test]
    fn doctor_fails_when_the_egress_socket_cannot_be_made() {
        let (_dir, mut probe) = fake_probe("Linux version 6.8.0-48-generic\n");
        probe.problems.clear();
        let report = probe.clone().report(&config());
        let findings = |egress_socket| Findings {
            config_source: "x".into(),
            config_error: None,
            identity: IdentityState::Missing,
            probe: &probe,
            report: &report,
            egress_socket,
            relays: RelayState::NotEnrolled,
        };
        let (text, ready) = render(&findings(EgressSocketState::Failed(
            "bind (through /proc/self/fd) /proc/self/fd/9/egress.sock: Operation not permitted".into(),
        )));
        assert!(!ready, "{text}");
        assert!(
            text.contains("[x] egress_socket_failed: bind (through /proc/self/fd)"),
            "{text}"
        );
        assert!(
            text.contains("fix: jobs with an egress list fail with `egress_unavailable`"),
            "{text}"
        );
        assert!(text.contains("(1 problem)"), "{text}");
        let (text, ready) = render(&findings(EgressSocketState::Ok));
        assert!(ready && text.contains("Egress socket: ok"), "{text}");
        // Not checked is not a problem of the node, and says why.
        let (text, ready) = render(&findings(EgressSocketState::NotChecked(
            "run it as the agent's user: sudo -u p2pc p2pc-agent doctor".into(),
        )));
        assert!(
            ready
                && text.contains(
                    "Egress socket: not checked (run it as the agent's user: sudo -u p2pc p2pc-agent doctor)"
                ),
            "{text}"
        );
    }

    /// The check names the path it could not use, and a failed check leaves nothing behind: not the test job
    /// directory, and not the `jobs/` it made.
    #[test]
    fn the_egress_socket_check_names_the_path_and_cleans_up() {
        let data = tempfile::tempdir().unwrap();
        let not_a_dir = data.path().join("file");
        std::fs::write(&not_a_dir, b"").unwrap();
        let EgressSocketState::Failed(err) = check_egress_socket(&not_a_dir) else {
            panic!("a file is not a data dir");
        };
        assert!(err.contains(&not_a_dir.display().to_string()), "{err}");

        // Whether the socket can be made depends on the machine (the AI development sandbox forbids AF_UNIX); what is
        // left behind does not: `jobs/` did not exist before, so it does not exist after.
        let outcome = check_egress_socket(data.path());
        assert!(!data.path().join("jobs").exists(), "{outcome:?}");
        // A `jobs/` that was there is kept, empty.
        std::fs::create_dir(data.path().join("jobs")).unwrap();
        let outcome = check_egress_socket(data.path());
        assert_eq!(
            std::fs::read_dir(data.path().join("jobs")).unwrap().count(),
            0,
            "{outcome:?}"
        );
    }

    /// `sudo p2pc-agent doctor` runs as root on a data dir that belongs to `p2pc`: the check is skipped, with how to
    /// run it, and creates nothing there.
    #[test]
    fn a_doctor_run_as_another_user_skips_the_egress_socket_check() {
        let data = tempfile::tempdir().unwrap();
        let owner = std::fs::metadata(data.path()).unwrap().uid();
        let EgressSocketState::NotChecked(why) = check_egress_socket_as(data.path(), owner + 1) else {
            panic!("another user's data dir must be skipped");
        };
        assert!(why.contains("sudo -u p2pc p2pc-agent doctor"), "{why}");
        assert_eq!(std::fs::read_dir(data.path()).unwrap().count(), 0, "nothing is created");
        // A data dir that does not exist yet is skipped too.
        let missing = data.path().join("missing");
        assert!(matches!(
            check_egress_socket_as(&missing, owner),
            EgressSocketState::NotChecked(_)
        ));
        assert!(!missing.exists());
    }

    /// T10n review P3 1: a data dir that is a symlink is judged by what it points to, as `JobDir::create` follows it,
    /// so another user's data dir behind a symlink is skipped too.
    #[test]
    fn a_symlinked_data_dir_of_another_user_is_skipped_too() {
        let real = tempfile::tempdir().unwrap();
        let owner = std::fs::metadata(real.path()).unwrap().uid();
        let holder = tempfile::tempdir().unwrap();
        let link = holder.path().join("data");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();
        let EgressSocketState::NotChecked(why) = check_egress_socket_as(&link, owner + 1) else {
            panic!("another user's data dir must be skipped through a symlink");
        };
        assert!(why.contains("sudo -u p2pc p2pc-agent doctor"), "{why}");
        assert_eq!(std::fs::read_dir(real.path()).unwrap().count(), 0, "nothing is created");
        // A dangling link is a data dir that does not exist yet.
        let dangling = holder.path().join("dangling");
        std::os::unix::fs::symlink(holder.path().join("nowhere"), &dangling).unwrap();
        assert!(matches!(
            check_egress_socket_as(&dangling, owner),
            EgressSocketState::NotChecked(_)
        ));
    }

    #[test]
    fn doctor_counts_config_and_identity_errors() {
        let (_dir, mut probe) = fake_probe("Linux version 6.8.0-48-generic\n");
        probe.problems.clear();
        let report = probe.clone().report(&config());
        let ok = Findings {
            config_source: "x".into(),
            config_error: None,
            identity: IdentityState::Ok("d75a98".into()),
            probe: &probe,
            report: &report,
            egress_socket: EgressSocketState::Ok,
            relays: RelayState::NotEnrolled,
        };
        let (text, ready) = render(&ok);
        assert!(ready, "{text}");
        assert!(text.contains("Result: ready."));
        let bad = Findings {
            config_error: Some("invalid config: `share.cpu_cores` must be a number greater than 0".into()),
            identity: IdentityState::Refused("mode 0644".into()),
            ..ok
        };
        let (text, ready) = render(&bad);
        assert!(!ready);
        assert!(text.contains("2 problems"), "{text}");
    }

    /// A GPU name or a tool's message comes from another program's output: no control character of it may reach the
    /// owner's terminal (an ESC sequence can rewrite what the screen shows).
    #[test]
    fn control_characters_from_tools_never_reach_the_terminal() {
        let (_dir, mut probe) = fake_probe("Linux version 6.8.0-48-generic\n");
        probe.gpu.gpus = vec![p2pc_proto::api::GpuInfo {
            uuid: "GPU-00000000-0000-4000-8000-000000000001".into(),
            index: 0,
            name: "RTX\u{1b}[2J\u{1b}]0;pwned\u{7} 5070".into(),
            driver_version: "570.\u{1b}[31m1".into(),
            cuda_driver_version: None,
            compute_capability: None,
            vram_mb: Some(16_384),
            pci_bdf: None,
            mig: false,
        }];
        probe.gpu.notes = vec!["bad line \u{1b}[2J from nvidia-smi".into()];
        let report = probe.clone().report(&config());
        let findings = Findings {
            config_source: "x".into(),
            config_error: None,
            identity: IdentityState::Missing,
            probe: &probe,
            report: &report,
            egress_socket: EgressSocketState::NotChecked("test".into()),
            relays: RelayState::NotEnrolled,
        };
        let (text, _) = render(&findings);
        assert!(text.contains("RTX"), "the name is still shown:\n{text}");
        assert!(text.contains("bad line"), "{text}");
        let stray: Vec<char> = text.chars().filter(|c| c.is_control() && *c != '\n').collect();
        assert!(
            stray.is_empty(),
            "control characters in the doctor output: {stray:?}\n{text}"
        );
    }

    fn render_probe(probe: &Probe) -> String {
        let report = probe.clone().report(&config());
        render(&Findings {
            config_source: "x".into(),
            config_error: None,
            identity: IdentityState::Missing,
            probe,
            report: &report,
            egress_socket: EgressSocketState::NotChecked("test".into()),
            relays: RelayState::NotEnrolled,
        })
        .0
    }

    const N0: &str = "https://use1-1.relay.n0.iroh.link./";
    const OURS: &str = "https://relay.example.com/";

    /// Answers by host: n0's in 81 ms, ours in 40 ms, `hang` never, anything else refused (with a control character in
    /// the error, as an OS message could carry).
    struct FakeProber;

    impl RelayProber for FakeProber {
        async fn probe(&self, url: &RelayUrl) -> Result<Duration, String> {
            match url.host_str() {
                Some("use1-1.relay.n0.iroh.link.") => Ok(Duration::from_millis(81)),
                Some("relay.example.com") => Ok(Duration::from_millis(40)),
                Some("hang.example.com") => std::future::pending().await,
                _ => Err("connection refused\u{1b}[2J".into()),
            }
        }
    }

    /// Runs `f` on its own runtime with a paused clock: `fake_probe` builds a runtime of its own, so the relay tests
    /// cannot be `#[tokio::test]`s, and a probe that never answers times out without waiting.
    fn paused<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(f)
    }

    fn relays_of(map: &[&str]) -> RelayState {
        let map: Vec<String> = map.iter().map(|s| (*s).to_string()).collect();
        paused(check_relays(Ok(Arc::new(FakeProber)), &map, true))
    }

    fn render_relays(relays: RelayState) -> (String, bool) {
        let (_dir, mut probe) = fake_probe("Linux version 6.8.0-48-generic\n");
        probe.problems.clear();
        let report = probe.clone().report(&config());
        render(&Findings {
            config_source: "x".into(),
            config_error: None,
            identity: IdentityState::Missing,
            probe: &probe,
            report: &report,
            egress_socket: EgressSocketState::Ok,
            relays,
        })
    }

    /// H2 §10.2-§10.3: each relay with its reachability, latency and whether it offers address discovery; the official
    /// mixed map (n0's relays plus our HTTP relay) is fine.
    #[test]
    fn doctor_reports_each_relay_with_its_latency_and_address_discovery() {
        let (text, ready) = render_relays(relays_of(&[N0, OURS]));
        assert!(ready, "{text}");
        assert!(
            text.contains("Relays: 2, 2 reachable; address discovery through n0's public relays"),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "  - {N0}: reachable, 81 ms; address discovery: yes (n0's public relay)"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "  - {OURS}: reachable, 40 ms; address discovery: unknown (only with TLS and UDP on the relay)"
            )),
            "{text}"
        );
        assert!(!text.contains("relay_no_address_discovery"), "{text}");
    }

    /// §10.3: with no address-discovery relay, doctor says so in the spec's words. A warning: the node still runs jobs
    /// without internet access, and the egress gate stays closed on its own.
    #[test]
    fn doctor_says_jobs_with_internet_access_will_not_start_without_address_discovery() {
        let (text, ready) = render_relays(relays_of(&[OURS]));
        assert!(ready, "{text}");
        assert!(text.contains("address discovery: NONE"), "{text}");
        assert!(
            text.contains(
                "  [!] relay_no_address_discovery: jobs with internet access will not start: no relay offers address \
                 discovery"
            ),
            "{text}"
        );
        assert!(text.contains("fix: add n0's public relays"), "{text}");
    }

    /// A relay that does not answer, or not in time, is shown as such; when none answers, the node is not ready.
    #[test]
    fn doctor_fails_when_no_relay_answers() {
        let (text, ready) = render_relays(relays_of(&[N0, "https://down.example.com/"]));
        assert!(ready, "one relay still answers:\n{text}");
        assert!(
            text.contains("  - https://down.example.com/: unreachable: connection refused"),
            "{text}"
        );
        let (text, ready) = render_relays(relays_of(&["https://down.example.com/", "https://hang.example.com/"]));
        assert!(!ready, "{text}");
        assert!(
            text.contains("  - https://hang.example.com/: no answer within 5 s"),
            "{text}"
        );
        assert!(text.contains("  [x] relays_unreachable: "), "{text}");
        assert!(text.contains("(1 problem)"), "{text}");
        let stray: Vec<char> = text.chars().filter(|c| c.is_control() && *c != '\n').collect();
        assert!(stray.is_empty(), "control characters in the doctor output: {stray:?}");
    }

    /// An entry iroh cannot use as written blocks; the others are still probed.
    #[test]
    fn doctor_fails_on_a_relay_entry_iroh_cannot_use() {
        let (text, ready) = render_relays(relays_of(&[N0, "https://relay.example.com/sub/"]));
        assert!(!ready, "{text}");
        assert!(
            text.contains("  [x] relay_invalid_url: relay #2: a path is not allowed"),
            "{text}"
        );
        assert!(text.contains(&format!("  - {N0}: reachable")), "{text}");
        // Plain http to a remote relay is a warning for a node.
        let (text, ready) = render_relays(relays_of(&[N0, "http://relay.example.com/"]));
        assert!(ready, "{text}");
        assert!(text.contains("  [!] relay_not_https: "), "{text}");
        assert!(
            text.contains("http://relay.example.com/: reachable, 40 ms; address discovery: no (plain http)"),
            "{text}"
        );
    }

    /// Before `join` there are no relays to check; when the prober cannot be built, the map's rules are still checked.
    #[test]
    fn doctor_without_relays_or_prober() {
        let state = paused(check_relays(Ok(Arc::new(FakeProber)), &[], false));
        let (text, ready) = render_relays(state);
        assert!(ready, "{text}");
        assert!(
            text.contains("Relays: none yet (`p2pc-agent join` stores the hub's)"),
            "{text}"
        );
        // Enrolled with no relay at all: no address discovery, said so.
        let (text, _) = render_relays(paused(check_relays(Ok(Arc::new(FakeProber)), &[], true)));
        assert!(text.contains("Relays: none"), "{text}");
        assert!(text.contains("[!] relay_no_address_discovery"), "{text}");
        let state = paused(check_relays::<FakeProber>(
            Err("no TLS roots".into()),
            &[OURS.to_string()],
            true,
        ));
        let (text, ready) = render_relays(state);
        assert!(ready, "{text}");
        assert!(text.contains("Relays: 1, not probed (no TLS roots)"), "{text}");
        assert!(
            text.contains(&format!("  - {OURS}: address discovery: unknown")),
            "{text}"
        );
        assert!(text.contains("[!] relay_no_address_discovery"), "{text}");
    }

    /// T07b review, carry-over 5: the detection deadline notes have their own block, outside the GPU section.
    #[test]
    fn detection_notes_have_their_own_block() {
        let (_dir, mut probe) = fake_probe("Linux version 6.8.0-48-generic\n");
        probe.notes = vec!["Podman did not answer within the 15s detection deadline; reported as unknown".into()];
        probe.gpu.notes = vec!["a GPU note".into()];
        let text = render_probe(&probe);
        let gpu = text.find("GPU: ").unwrap();
        let share = text.find("Share: ").unwrap();
        let detection = text.find("Detection:\n").expect(&text);
        let note = text.find("Podman did not answer").unwrap();
        assert!(detection < note, "{text}");
        assert!(
            !(gpu..share).contains(&note),
            "the note is not in the GPU section:\n{text}"
        );
        assert!((gpu..share).contains(&text.find("a GPU note").unwrap()), "{text}");
        // No block at all when nothing hit the deadline.
        probe.notes.clear();
        assert!(!render_probe(&probe).contains("Detection:"));
    }

    /// Carry-over 9: doctor shows why the boot status keeps the GPUs from being offered.
    #[test]
    fn doctor_shows_the_boot_status_reason() {
        let (_dir, mut probe) = fake_probe("Linux version 6.6.87.2-microsoft-standard-WSL2\n");
        probe.boot = Some(BootStatus::Failed {
            cdi: "nvidia_smi_failed".into(),
            errors: vec!["nvidia-smi -L failed (exit 9)".into()],
        });
        let text = render_probe(&probe);
        assert!(text.contains("Boot status: failed; GPUs are not offered"), "{text}");
        assert!(
            text.contains("nvidia_smi_failed: nvidia-smi -L failed (exit 9)"),
            "{text}"
        );
        probe.boot = Some(BootStatus::Ok { cdi: "fresh".into() });
        let text = render_probe(&probe);
        assert!(text.contains("Boot status: ok (CDI fresh)"), "{text}");
    }

    #[test]
    fn inventory_text_mentions_the_essentials() {
        let (_dir, probe) = fake_probe("Linux version 6.8.0-48-generic\n");
        let report = probe.report(&config()).unwrap();
        let text = inventory_text(&report);
        for needle in [
            "hostname",
            "Example CPU (2 logical cores)",
            "gpu status  no_driver",
            "podman unavailable",
        ] {
            assert!(text.contains(needle), "{needle} missing in:\n{text}");
        }
    }
}
