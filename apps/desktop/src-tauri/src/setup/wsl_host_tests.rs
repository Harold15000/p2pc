// SPDX-License-Identifier: Apache-2.0

//! Tests of the real host over a fake [`CommandRunner`]: the exact programs and argument vectors first run uses, the
//! token only on stdin, and the parsing of what the distro answers. Nothing here starts a process.

use std::sync::Mutex;
use std::time::Duration;

use p2pc_wsl::image::FetchResponse;
use p2pc_wsl::runner::{Output, POWERSHELL_EXE, RunError, WSL_EXE, encode_powershell};

use super::*;
use crate::autostart::AutostartError;

type Matcher = Box<dyn Fn(&Invocation) -> bool + Send + Sync>;

/// Answers each invocation with the first matching rule (exit 127 without one) and records every call.
#[derive(Default)]
struct FakeRunner {
    rules: Mutex<Vec<(Matcher, Output)>>,
    calls: Mutex<Vec<Invocation>>,
}

impl FakeRunner {
    fn on(&self, matcher: impl Fn(&Invocation) -> bool + Send + Sync + 'static, reply: Output) {
        self.rules.lock().expect("lock").push((Box::new(matcher), reply));
    }
    fn calls(&self) -> Vec<Invocation> {
        self.calls.lock().expect("lock").clone()
    }
    /// The commands run inside the distro (after `--exec`).
    fn distro_commands(&self) -> Vec<Vec<String>> {
        self.calls()
            .iter()
            .filter(|i| i.program() == WSL_EXE && i.arguments().get(4).map(String::as_str) == Some("--exec"))
            .map(|i| i.arguments()[5..].to_vec())
            .collect()
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, inv: &Invocation) -> Result<Output, RunError> {
        assert_eq!(inv.check_no_secret(), Ok(()), "a secret on a command line: {inv:?}");
        self.calls.lock().expect("lock").push(inv.clone());
        for (matcher, reply) in self.rules.lock().expect("lock").iter() {
            if matcher(inv) {
                return Ok(reply.clone());
            }
        }
        Ok(Output {
            code: Some(127),
            stdout: Vec::new(),
            stderr: b"fake: no rule".to_vec(),
        })
    }
}

#[derive(Default)]
struct NoPause;

impl Pause for NoPause {
    fn sleep(&self, _: Duration) {}
}

struct NoFetch;

impl RangeFetch for NoFetch {
    fn fetch(&self, _: &str, _: u64) -> Result<FetchResponse, String> {
        Err("no network in tests".into())
    }
}

#[derive(Default)]
struct FakeRunOnce(Mutex<Vec<(String, String)>>);

impl RunKey for FakeRunOnce {
    fn get(&self, _: &str) -> Result<Option<String>, AutostartError> {
        Ok(None)
    }
    fn set(&self, name: &str, value: &str) -> Result<(), AutostartError> {
        self.0.lock().expect("lock").push((name.into(), value.into()));
        Ok(())
    }
    fn remove(&self, _: &str) -> Result<(), AutostartError> {
        Ok(())
    }
}

/// The distro command `cmd`, exactly.
fn runs(cmd: &'static [&'static str]) -> impl Fn(&Invocation) -> bool + Send + Sync {
    move |i| {
        i.program() == WSL_EXE
            && i.arguments().len() == 5 + cmd.len()
            && i.arguments()[..5] == ["-d", "p2pc-node", "-u", "root", "--exec"]
            && i.arguments()[5..].iter().zip(cmd).all(|(a, c)| a == c)
    }
}

/// A distro command starting with `prefix`.
fn starts(prefix: &'static [&'static str]) -> impl Fn(&Invocation) -> bool + Send + Sync {
    move |i| {
        i.program() == WSL_EXE
            && i.arguments().len() >= 5 + prefix.len()
            && i.arguments()[5..].iter().zip(prefix).all(|(a, c)| a == c)
    }
}

fn exe() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\Users\Example\AppData\Local\P2PC App\P2PC.exe")
    } else {
        PathBuf::from("/opt/P2PC App/p2pc-desktop")
    }
}

fn host(runner: FakeRunner) -> WslHost<FakeRunner, NoPause> {
    WslHost::new(WslHostParts {
        runner,
        pause: NoPause,
        fetch: Box::new(NoFetch),
        run_once: Box::new(FakeRunOnce::default()),
        layout: Layout::new("LAD"),
        pin: None,
        exe: Some(exe()),
        system_root: PathBuf::from("SYSROOT"),
    })
}

const INVENTORY: &str = r#"{
  "inventory": {
    "hostname": "pc", "platform": "wsl2", "cpu": {"model": "Example CPU", "cores": 16},
    "memory_mb": 31890, "os": "Debian", "arch": "x86_64",
    "gpus": [{"uuid": "GPU-00000000-0000-0000-0000-000000000000", "name": "Example GPU", "vram_mb": 8192}],
    "gpu_status": {"status": "ok"},
    "offered": {"cpu": 15.0, "memory_mb": 27000, "gpu": 1, "disk_mb": 10240}
  },
  "local": {}
}"#;

// --- Parsing ---

#[test]
fn the_inventory_gives_the_controls_ranges_and_defaults() {
    assert_eq!(
        parse_inventory(INVENTORY),
        Some(NodeFacts {
            cpu_cores: 16,
            memory_mb: 31_890,
            gpu_offerable: true,
            default_cpu: 15,
            default_memory_mb: 27_000,
        })
    );
    // A GPU whose driver or CDI is not ok, or none at all, is not offered.
    let not_ok = INVENTORY.replace(r#""status": "ok""#, r#""status": "cdi_missing""#);
    assert!(!parse_inventory(&not_ok).expect("parse").gpu_offerable);
    let none = INVENTORY.replace(r#""gpu": 1,"#, r#""gpu": 0,"#);
    assert!(!parse_inventory(&none).expect("parse").gpu_offerable);
    assert_eq!(parse_inventory("not json"), None);
    assert_eq!(parse_inventory(r#"{"inventory": {}}"#), None);
}

#[test]
fn a_fractional_or_odd_offered_cpu_stays_within_the_vm() {
    let half = INVENTORY.replace(r#""cpu": 15.0"#, r#""cpu": 0.5"#);
    assert_eq!(parse_inventory(&half).expect("parse").default_cpu, 1);
    let many = INVENTORY.replace(r#""cpu": 15.0"#, r#""cpu": 64.0"#);
    assert_eq!(parse_inventory(&many).expect("parse").default_cpu, 16);
}

#[test]
fn the_networking_mode_is_read_from_wslinfo() {
    assert_eq!(parse_networking_mode("nat\n"), NetworkingMode::Nat);
    assert_eq!(parse_networking_mode("Mirrored"), NetworkingMode::Mirrored);
    assert_eq!(parse_networking_mode("virtioproxy"), NetworkingMode::Other);
    assert_eq!(parse_networking_mode("  "), NetworkingMode::Unknown);
}

#[test]
fn the_install_outcome_is_read_from_the_script() {
    assert_eq!(parse_install_output("exit=0\r\n"), WslInstall::Installed);
    assert_eq!(parse_install_output("exit=3010"), WslInstall::RebootRequired);
    assert_eq!(parse_install_output("exit=1641"), WslInstall::RebootRequired);
    assert_eq!(
        parse_install_output("exit=1"),
        WslInstall::Failed { exit_code: Some(1) }
    );
    assert_eq!(parse_install_output("declined"), WslInstall::Failed { exit_code: None });
    assert_eq!(parse_install_output(""), WslInstall::Failed { exit_code: None });
}

#[test]
fn init_s_output_gives_the_owner_device_and_the_address() {
    let out = "OWNER DEVICE: dev_01J\nSERVER ADDRESS: p2pc_srv_ABC\n";
    assert_eq!(
        parse_init_output(out),
        Some(HubInit {
            owner_device_id: "dev_01J".into(),
            server_address: "p2pc_srv_ABC".into(),
        })
    );
    assert_eq!(parse_init_output("OWNER DEVICE: dev\n"), None);
    assert_eq!(
        parse_server_address("NODE ID: ab\nSERVER ADDRESS: p2pc_srv_X\nRELAY: https://relay.example.invalid\n"),
        Some("p2pc_srv_X".into())
    );
    assert_eq!(parse_server_address("SERVER ADDRESS: something else"), None);
}

#[test]
fn node_ids_are_64_lowercase_hex() {
    assert!(is_node_id(&"ab".repeat(32)));
    assert!(!is_node_id(&"AB".repeat(32)));
    assert!(!is_node_id(&"ab".repeat(31)));
    assert!(!is_node_id("--label"));
}

#[test]
fn the_blob_quota_is_set_and_everything_else_kept() {
    let toml_text = "bind = \"127.0.0.1:7477\"\ndata_dir = \"/var/lib/p2pc-server\"\n\n[blobs]\nmax_blob_mb = 2048\nblobs_quota_mb = 20480\n\n[log]\nlevel = \"info\"\n";
    let out = with_blobs_quota(toml_text, 14_336).expect("updated");
    let table: toml::Table = out.parse().expect("toml");
    assert_eq!(table["blobs"]["blobs_quota_mb"].as_integer(), Some(14_336));
    assert_eq!(table["blobs"]["max_blob_mb"].as_integer(), Some(2048));
    assert_eq!(table["bind"].as_str(), Some("127.0.0.1:7477"));
    assert_eq!(table["data_dir"].as_str(), Some("/var/lib/p2pc-server"));
    assert_eq!(table["log"]["level"].as_str(), Some("info"));
    // The root keys stay before the first table: p2pc-run reads `bind` and `data_dir` there, line by line.
    let first_table = out.find('[').expect("a table");
    assert!(out.find("bind").expect("bind") < first_table);
    assert!(out.find("data_dir").expect("data_dir") < first_table);
    // No [blobs] table yet: it is added.
    let out = with_blobs_quota("bind = \"127.0.0.1:7477\"\n", 4096).expect("updated");
    assert!(out.contains("blobs_quota_mb = 4096"), "{out}");
}

#[test]
fn a_quota_under_the_largest_blob_or_a_broken_file_is_refused() {
    assert_eq!(with_blobs_quota("[blobs]\nmax_blob_mb = 8192\n", 4096), None);
    assert_eq!(with_blobs_quota("this is = = not toml", 4096), None);
    assert_eq!(with_blobs_quota("blobs = 3\n", 4096), None);
}

// --- Invocations ---

#[test]
fn step_2a_runs_the_one_elevated_install_and_reads_its_exit_code() {
    let runner = FakeRunner::default();
    runner.on(|i| i.program() == POWERSHELL_EXE, Output::with(0, "exit=3010\r\n"));
    let h = host(runner);
    assert_eq!(h.install_wsl(), WslInstall::RebootRequired);
    let calls = h.runner.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].arguments().last().map(String::as_str),
        Some(encode_powershell(INSTALL_WSL_SCRIPT).as_str())
    );
    assert_eq!(calls[0].time_limit(), Some(WSL_INSTALL_TIMEOUT));
    assert!(INSTALL_WSL_SCRIPT.contains("'--install', '--no-distribution'"));
    assert!(INSTALL_WSL_SCRIPT.contains("-Verb RunAs"));
}

#[test]
fn the_run_once_entry_reopens_the_window() {
    let run_once = std::sync::Arc::new(FakeRunOnce::default());
    struct Shared(std::sync::Arc<FakeRunOnce>);
    impl RunKey for Shared {
        fn get(&self, n: &str) -> Result<Option<String>, AutostartError> {
            self.0.get(n)
        }
        fn set(&self, n: &str, v: &str) -> Result<(), AutostartError> {
            self.0.set(n, v)
        }
        fn remove(&self, n: &str) -> Result<(), AutostartError> {
            self.0.remove(n)
        }
    }
    let h = WslHost::new(WslHostParts {
        runner: FakeRunner::default(),
        pause: NoPause,
        fetch: Box::new(NoFetch),
        run_once: Box::new(Shared(run_once.clone())),
        layout: Layout::new("LAD"),
        pin: None,
        exe: Some(exe()),
        system_root: PathBuf::from("SYSROOT"),
    });
    h.reopen_after_reboot().expect("run once");
    assert_eq!(
        *run_once.0.lock().expect("lock"),
        vec![("P2PC".to_owned(), format!("\"{}\"", exe().display()))]
    );
}

#[test]
fn a_build_without_a_pinned_image_cannot_download() {
    let h = host(FakeRunner::default());
    let err = h
        .download_image(&mut |_| ControlFlow::Continue(()))
        .expect_err("no pin");
    assert_eq!(err.code, SetupErrorCode::NotAvailable);
    assert!(h.runner.calls().is_empty());
}

#[test]
fn node_facts_create_the_agent_config_then_read_the_inventory() {
    let runner = FakeRunner::default();
    runner.on(runs(&["/usr/bin/test", "-e", AGENT_CONFIG]), Output::with(1, ""));
    runner.on(
        runs(&["/usr/bin/install", "-m", "0600", "/dev/null", AGENT_CONFIG]),
        Output::with(0, ""),
    );
    runner.on(
        runs(&[AGENT_BIN, "--config", AGENT_CONFIG, "inventory", "--json"]),
        Output::with(0, INVENTORY),
    );
    let h = host(runner);
    assert_eq!(h.node_facts().expect("facts").cpu_cores, 16);
    assert_eq!(h.runner.distro_commands().len(), 3);
    for inv in h.runner.calls() {
        assert_eq!(inv.time_limit(), Some(IN_DISTRO_TIMEOUT));
    }
}

#[test]
fn an_unreadable_inventory_is_distro_unhealthy() {
    let runner = FakeRunner::default();
    runner.on(runs(&["/usr/bin/test", "-e", AGENT_CONFIG]), Output::with(0, ""));
    runner.on(starts(&[AGENT_BIN]), Output::with(1, ""));
    let err = host(runner).node_facts().expect_err("unreadable");
    assert_eq!(err.code, SetupErrorCode::DistroUnhealthy);
}

#[test]
fn the_networking_mode_comes_from_wslinfo_in_the_distro() {
    let runner = FakeRunner::default();
    runner.on(runs(&[WSLINFO, "--networking-mode"]), Output::with(0, "mirrored\n"));
    assert_eq!(host(runner).networking_mode(), NetworkingMode::Mirrored);
    // wslinfo missing or failing: unknown, never "nat".
    assert_eq!(host(FakeRunner::default()).networking_mode(), NetworkingMode::Unknown);
}

#[test]
fn the_share_is_set_with_the_agent_s_share_set() {
    let runner = FakeRunner::default();
    runner.on(runs(&["/usr/bin/test", "-e", AGENT_CONFIG]), Output::with(0, ""));
    runner.on(
        starts(&[AGENT_BIN, "--config", AGENT_CONFIG, "share", "set"]),
        Output::with(0, ""),
    );
    let h = host(runner);
    let share = ShareRecord {
        cpu: 6,
        memory_mb: 8192,
        gpu: true,
        share_gib: 120,
        disk_mb: 51_200,
        volumes_mb: 71_680,
    };
    h.apply_share(&share).expect("share");
    assert_eq!(
        h.runner.distro_commands().last().expect("a command"),
        &[
            AGENT_BIN,
            "--config",
            AGENT_CONFIG,
            "share",
            "set",
            "--cpu",
            "6",
            "--memory-mb",
            "8192",
            "--gpu",
            "true",
            "--disk-mb",
            "51200",
            "--volumes-mb",
            "71680"
        ]
        .map(String::from)
    );
}

#[test]
fn a_refused_share_is_share_failed_with_the_exit_code() {
    let runner = FakeRunner::default();
    runner.on(runs(&["/usr/bin/test", "-e", AGENT_CONFIG]), Output::with(0, ""));
    runner.on(starts(&[AGENT_BIN]), Output::with(2, "error: --gpu: no GPU"));
    let share = ShareRecord {
        cpu: 1,
        memory_mb: 1024,
        gpu: false,
        share_gib: 1,
        disk_mb: 512,
        volumes_mb: 512,
    };
    let err = host(runner).apply_share(&share).expect_err("refused");
    assert_eq!(err.code, SetupErrorCode::ShareFailed);
    assert_eq!(
        err.detail.as_deref(),
        Some("p2pc-agent share set ended with exit code 2")
    );
}

#[test]
fn the_hub_is_initialised_with_the_owner_device_in_its_data_dir() {
    let id = "ab".repeat(32);
    let runner = FakeRunner::default();
    runner.on(
        starts(&[SERVER_BIN, "init"]),
        Output::with(0, "OWNER DEVICE: dev_1\nSERVER ADDRESS: p2pc_srv_X\n"),
    );
    let h = host(runner);
    let init = h.init_hub(&id, "P2PC app on the hub PC").expect("init");
    assert_eq!(init.server_address, "p2pc_srv_X");
    assert_eq!(
        h.runner.distro_commands(),
        vec![
            [
                SERVER_BIN,
                "init",
                "--data-dir",
                HUB_DIR,
                "--owner-device",
                id.as_str(),
                "--label",
                "P2PC app on the hub PC"
            ]
            .map(String::from)
            .to_vec()
        ]
    );
}

#[test]
fn a_bad_node_id_or_a_failed_init_is_hub_failed() {
    let err = host(FakeRunner::default())
        .init_hub("--label", "x")
        .expect_err("bad id");
    assert_eq!(err.code, SetupErrorCode::HubFailed);
    let runner = FakeRunner::default();
    runner.on(
        starts(&[SERVER_BIN, "init"]),
        Output::with(1, "error: already initialised"),
    );
    let err = host(runner).init_hub(&"ab".repeat(32), "x").expect_err("failed");
    assert_eq!(err.detail.as_deref(), Some("p2pc-server init ended with exit code 1"));
}

#[test]
fn the_hub_s_data_dir_is_detected_by_its_server_toml() {
    let runner = FakeRunner::default();
    runner.on(runs(&["/usr/bin/test", "-e", SERVER_TOML]), Output::with(0, ""));
    assert_eq!(host(runner).hub_initialised(), Ok(true));
    let runner = FakeRunner::default();
    runner.on(runs(&["/usr/bin/test", "-e", SERVER_TOML]), Output::with(1, ""));
    assert_eq!(host(runner).hub_initialised(), Ok(false));
    // wsl.exe failing is not "absent".
    assert!(host(FakeRunner::default()).hub_initialised().is_err());
}

#[test]
fn the_quota_is_written_through_stdin_to_a_temporary_file_then_renamed() {
    let runner = FakeRunner::default();
    runner.on(
        runs(&["/bin/cat", SERVER_TOML]),
        Output::with(0, "bind = \"127.0.0.1:7477\"\n[blobs]\nmax_blob_mb = 2048\n"),
    );
    runner.on(starts(&["/usr/bin/dd"]), Output::with(0, ""));
    runner.on(starts(&["/bin/chmod"]), Output::with(0, ""));
    runner.on(starts(&["/bin/mv"]), Output::with(0, ""));
    let h = host(runner);
    h.set_blobs_quota(20_480).expect("quota");
    let commands = h.runner.distro_commands();
    assert_eq!(
        commands,
        vec![
            vec!["/bin/cat".to_owned(), SERVER_TOML.into()],
            vec![
                "/usr/bin/dd".to_owned(),
                format!("of={SERVER_TOML_TEMP}"),
                "status=none".into()
            ],
            vec!["/bin/chmod".to_owned(), "0600".into(), SERVER_TOML_TEMP.into()],
            vec![
                "/bin/mv".to_owned(),
                "-f".into(),
                SERVER_TOML_TEMP.into(),
                SERVER_TOML.into()
            ],
        ]
    );
    let dd = &h.runner.calls()[1];
    let written = String::from_utf8(dd.stdin_bytes().expect("stdin").to_vec()).expect("utf-8");
    assert!(written.contains("blobs_quota_mb = 20480"), "{written}");
}

#[test]
fn a_failed_write_leaves_server_toml_alone_and_removes_the_temporary_file() {
    let runner = FakeRunner::default();
    runner.on(runs(&["/bin/cat", SERVER_TOML]), Output::with(0, "[blobs]\n"));
    runner.on(starts(&["/usr/bin/dd"]), Output::with(1, ""));
    runner.on(starts(&["/bin/rm"]), Output::with(0, ""));
    let h = host(runner);
    assert!(h.set_blobs_quota(4096).is_err());
    let commands = h.runner.distro_commands();
    assert!(!commands.iter().any(|c| c[0] == "/bin/mv"));
    assert_eq!(
        commands.last().expect("rm"),
        &["/bin/rm", "-f", SERVER_TOML_TEMP].map(String::from)
    );
}

#[test]
fn enabling_the_hub_writes_its_flag_then_enables_and_starts_the_task() {
    let runner = FakeRunner::default();
    runner.on(runs(&["/usr/bin/touch", HUB_FLAG]), Output::with(0, ""));
    runner.on(|i| i.program() == "schtasks.exe", Output::with(0, ""));
    let h = host(runner);
    h.enable_hub().expect("enable");
    let calls = h.runner.calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[1].arguments()[..2], ["/Change", "/ENABLE"]);
    assert_eq!(calls[2].arguments()[..1], ["/Run"]);
}

#[test]
fn a_flag_that_cannot_be_written_starts_nothing() {
    let h = host(FakeRunner::default());
    assert!(h.enable_hub().is_err());
    assert_eq!(h.runner.calls().len(), 1);
}

#[test]
fn the_join_token_goes_on_stdin_only() {
    let token = "p2pc_join_EXAMPLEONLYNOTAREALTOKEN"; // gitleaks:allow
    let runner = FakeRunner::default();
    runner.on(runs(&["/usr/bin/test", "-e", AGENT_CONFIG]), Output::with(0, ""));
    runner.on(
        runs(&[AGENT_BIN, "--config", AGENT_CONFIG, "join", "-"]),
        Output::with(0, ""),
    );
    let h = host(runner);
    assert_eq!(h.join_agent(&JoinToken::new(token.into())), JoinResult::Joined);
    let join = h.runner.calls().pop().expect("join");
    assert_eq!(join.stdin_bytes(), Some(format!("{token}\n").as_bytes()));
    assert!(!join.arguments().iter().any(|a| a.contains("p2pc_join_")));
    assert!(
        !format!("{join:?}").contains("p2pc_join_"),
        "Debug shows stdin by length only"
    );
}

#[test]
fn the_join_exit_codes_map_to_their_outcomes() {
    for (code, expected) in [
        (0, JoinResult::Joined),
        (3, JoinResult::AlreadyEnrolled),
        (4, JoinResult::Rejected),
        (5, JoinResult::Rejected),
        (1, JoinResult::Failed { exit_code: Some(1) }),
    ] {
        let runner = FakeRunner::default();
        runner.on(runs(&["/usr/bin/test", "-e", AGENT_CONFIG]), Output::with(0, ""));
        runner.on(starts(&[AGENT_BIN]), Output::with(code, ""));
        assert_eq!(
            host(runner).join_agent(&JoinToken::new("p2pc_join_X".into())), // gitleaks:allow
            expected,
            "exit {code}"
        );
    }
}

#[test]
fn restarting_the_node_stops_the_task_and_distro_then_starts_the_task() {
    let runner = FakeRunner::default();
    runner.on(|i| i.program() == "schtasks.exe", Output::with(0, ""));
    runner.on(|i| i.program() == WSL_EXE, Output::with(0, ""));
    let h = host(runner);
    h.restart_node().expect("restart");
    let summary: Vec<String> = h
        .runner
        .calls()
        .iter()
        .map(|i| format!("{} {}", i.program(), i.arguments()[0]))
        .collect();
    assert_eq!(
        summary,
        [
            "schtasks.exe /Change",
            "schtasks.exe /End",
            "wsl.exe --terminate",
            "schtasks.exe /Change",
            "schtasks.exe /Run"
        ]
    );
}
