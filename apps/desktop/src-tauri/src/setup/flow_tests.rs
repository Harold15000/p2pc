// SPDX-License-Identifier: Apache-2.0

//! Tests of the first-run flow, with a fake host, hub and device: every step, the resume rules, the §8.8 errors, the
//! disk arithmetic at steps 3 and 4, the hub PC's own pre-approved token and the mirrored-networking warning.

use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use p2pc_wsl::checks::{ChecksReport, DiskState, Thresholds, Virtualization, WslState, WslVersion};
use p2pc_wsl::image::Progress;

use super::*;
use crate::keystore::KeyError;
use crate::setup::disk::GIB;
use crate::setup::host::{HubInit, JoinToken, NodeFacts};
use crate::setup::hub::PairedDevice;

const NODE_ID: &str = "4f1c9d5c3b2a19e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4";
const TOKEN: &str = "p2pc_join_EXAMPLEONLYNOTAREALTOKEN"; // gitleaks:allow
const TICKET_URL: &str = "https://app.example.invalid/pair#p2pc_pair_EXAMPLEONLYNOTAREALTICKET"; // gitleaks:allow

fn good_report() -> ChecksReport {
    ChecksReport {
        windows_build: Some(26100),
        wsl: WslState::Installed(WslVersion::new(2, 6, 1)),
        wsl_default_version: None,
        virtualization: Virtualization::HypervisorRunning,
        disk: DiskState::Free(200 * GIB),
        nvidia_drivers: vec!["32.0.15.6094".into()],
        thresholds: Thresholds::default(),
    }
}

/// What the fake host answers. Defaults: the happy path on a PC with 200 GiB free.
struct Script {
    checks: VecDeque<Result<ChecksReport, SetupError>>,
    free: VecDeque<u64>,
    install: WslInstall,
    download: VecDeque<Result<(), SetupError>>,
    install_distro: Result<String, SetupError>,
    facts: NodeFacts,
    networking: NetworkingMode,
    apply_share: Result<(), SetupError>,
    hub_initialised: bool,
    init_hub: Result<HubInit, SetupError>,
    enable_hub: VecDeque<Result<(), SetupError>>,
    join: VecDeque<JoinResult>,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            checks: VecDeque::from([Ok(good_report())]),
            free: VecDeque::from([200 * GIB]),
            install: WslInstall::Installed,
            download: VecDeque::from([Ok(())]),
            install_distro: Ok("image_version=0.2.0".into()),
            facts: NodeFacts {
                cpu_cores: 16,
                memory_mb: 32_000,
                gpu_offerable: true,
                default_cpu: 15,
                default_memory_mb: 24_000,
            },
            networking: NetworkingMode::Nat,
            apply_share: Ok(()),
            hub_initialised: false,
            init_hub: Ok(HubInit {
                owner_device_id: "dev_owner".into(),
                server_address: "p2pc_srv_EXAMPLE".into(),
            }),
            enable_hub: VecDeque::from([Ok(())]),
            join: VecDeque::from([JoinResult::Joined]),
        }
    }
}

/// Takes the next answer; the last one repeats.
fn next<T: Clone>(q: &mut VecDeque<T>) -> T {
    if q.len() > 1 {
        q.pop_front().expect("non-empty")
    } else {
        q.front().cloned().expect("an answer")
    }
}

#[derive(Default)]
struct FakeHost {
    script: Mutex<Script>,
    calls: Mutex<Vec<String>>,
    shares: Mutex<Vec<ShareRecord>>,
    tokens: Mutex<Vec<String>>,
    /// When set, `checks` reports it started, then waits to be released.
    gate: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
}

impl FakeHost {
    fn call(&self, name: impl Into<String>) {
        self.calls.lock().expect("lock").push(name.into());
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("lock").clone()
    }
    fn count(&self, name: &str) -> usize {
        self.calls().iter().filter(|c| c.as_str() == name).count()
    }
    fn script(&self) -> std::sync::MutexGuard<'_, Script> {
        self.script.lock().expect("lock")
    }
}

impl SetupHost for FakeHost {
    fn checks(&self) -> Result<ChecksReport, SetupError> {
        self.call("checks");
        if let Some((started, release)) = self.gate.lock().expect("lock").as_ref() {
            started.send(()).expect("send");
            release.recv().expect("release");
        }
        next(&mut self.script().checks)
    }
    fn free_bytes(&self) -> Result<u64, SetupError> {
        self.call("free_bytes");
        Ok(next(&mut self.script().free))
    }
    fn install_wsl(&self) -> WslInstall {
        self.call("install_wsl");
        self.script().install
    }
    fn reopen_after_reboot(&self) -> Result<(), SetupError> {
        self.call("reopen_after_reboot");
        Ok(())
    }
    fn download_image(&self, progress: &mut dyn FnMut(Progress) -> ControlFlow<()>) -> Result<(), SetupError> {
        self.call("download_image");
        let _ = progress(Progress {
            done: 10 << 20,
            total: Some(10 << 20),
        });
        next(&mut self.script().download)
    }
    fn install_distro(&self) -> Result<String, SetupError> {
        self.call("install_distro");
        self.script().install_distro.clone()
    }
    fn node_facts(&self) -> Result<NodeFacts, SetupError> {
        self.call("node_facts");
        Ok(self.script().facts)
    }
    fn networking_mode(&self) -> NetworkingMode {
        self.call("networking_mode");
        self.script().networking
    }
    fn apply_share(&self, share: &ShareRecord) -> Result<(), SetupError> {
        self.call("apply_share");
        self.shares.lock().expect("lock").push(*share);
        self.script().apply_share.clone()
    }
    fn hub_initialised(&self) -> Result<bool, SetupError> {
        self.call("hub_initialised");
        Ok(self.script().hub_initialised)
    }
    fn init_hub(&self, owner_node_id: &str, label: &str) -> Result<HubInit, SetupError> {
        self.call(format!("init_hub {owner_node_id} {label}"));
        let result = self.script().init_hub.clone();
        if result.is_ok() {
            self.script().hub_initialised = true;
        }
        result
    }
    fn hub_address(&self) -> Result<String, SetupError> {
        self.call("hub_address");
        Ok("p2pc_srv_EXISTING".into())
    }
    fn set_blobs_quota(&self, quota_mb: u64) -> Result<(), SetupError> {
        self.call(format!("set_blobs_quota {quota_mb}"));
        Ok(())
    }
    fn enable_hub(&self) -> Result<(), SetupError> {
        self.call("enable_hub");
        next(&mut self.script().enable_hub)
    }
    fn join_agent(&self, token: &JoinToken) -> JoinResult {
        self.call("join_agent");
        self.tokens.lock().expect("lock").push(token.expose().to_owned());
        next(&mut self.script().join)
    }
    fn restart_node(&self) -> Result<(), SetupError> {
        self.call("restart_node");
        Ok(())
    }
}

#[derive(Default)]
struct FakeHub {
    unwired: bool,
    calls: Mutex<Vec<String>>,
    token_requests: Mutex<Vec<JoinTokenRequest>>,
    devices: Mutex<Vec<PairedDevice>>,
    tickets: Mutex<u32>,
    /// The next mints that fail as unreachable.
    mint_failures: Mutex<u32>,
}

impl FakeHub {
    fn call(&self, name: impl Into<String>) -> Result<(), HubError> {
        self.calls.lock().expect("lock").push(name.into());
        if self.unwired {
            Err(HubError::NotAvailable)
        } else {
            Ok(())
        }
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("lock").clone()
    }
}

impl HubApi for FakeHub {
    fn set_hub_name(&self, name: &str) -> Result<(), HubError> {
        self.call(format!("set_hub_name {name}"))
    }
    fn mint_join_token(&self, request: &JoinTokenRequest) -> Result<JoinToken, HubError> {
        self.call("mint_join_token")?;
        {
            let mut failures = self.mint_failures.lock().expect("lock");
            if *failures > 0 {
                *failures -= 1;
                return Err(HubError::Unreachable);
            }
        }
        self.token_requests.lock().expect("lock").push(*request);
        Ok(JoinToken::new(TOKEN.into()))
    }
    fn create_pairing_ticket(&self, request: &PairingTicketRequest) -> Result<PairingTicket, HubError> {
        self.call(format!("create_pairing_ticket {}", request.expires_in_s))?;
        let mut n = self.tickets.lock().expect("lock");
        *n += 1;
        Ok(PairingTicket {
            id: format!("pt_{n}"),
            url: Zeroizing::new(TICKET_URL.into()),
            expires_at: "2026-11-12T10:10:00Z".into(),
        })
    }
    fn revoke_pairing_ticket(&self, id: &str) -> Result<(), HubError> {
        self.call(format!("revoke_pairing_ticket {id}"))
    }
    fn devices(&self) -> Result<Vec<PairedDevice>, HubError> {
        self.call("devices")?;
        Ok(self.devices.lock().expect("lock").clone())
    }
}

struct FakeDevice;

impl OwnerDevice for FakeDevice {
    fn node_id(&self) -> Result<String, KeyError> {
        Ok(NODE_ID.into())
    }
}

struct World {
    host: Arc<FakeHost>,
    hub: Arc<FakeHub>,
    dir: tempfile::TempDir,
}

impl World {
    fn new() -> Self {
        Self::with(FakeHost::default(), FakeHub::default())
    }

    fn with(host: FakeHost, hub: FakeHub) -> Self {
        Self {
            host: Arc::new(host),
            hub: Arc::new(hub),
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn file(&self) -> RecordFile {
        RecordFile::in_dir(self.dir.path())
    }

    /// The app (re)started: a new flow loaded from `setup.json`.
    fn start(&self) -> Setup {
        Setup::load(
            self.host.clone(),
            self.hub.clone(),
            Arc::new(FakeDevice),
            Some(self.file()),
        )
    }

    fn saved(&self) -> SetupRecord {
        self.file().load().expect("load")
    }
}

fn share(gib: u64) -> ShareRequest {
    ShareRequest {
        cpu: 8,
        memory_mb: 16_384,
        gpu: false,
        share_gib: gib,
    }
}

/// Runs steps 1-3 with the happy path.
fn to_create(w: &World) -> Setup {
    let s = w.start();
    s.welcome(true).expect("welcome");
    s.run_checks().expect("checks");
    s.prepare_node(false).expect("prepare");
    let v = s.apply_share(share(90)).expect("share");
    assert_eq!(v.step, Step::CreateOrJoin, "{v:?}");
    s
}

fn error_code(v: &SetupView) -> Option<SetupErrorCode> {
    v.error.as_ref().map(|e| e.code)
}

// --- Step 1 ---

#[test]
fn welcome_has_nothing_preselected_and_records_the_choice() {
    for choice in [true, false] {
        let w = World::new();
        let s = w.start();
        let v = s.view().expect("view");
        assert_eq!((v.step, v.update_checks), (Step::Welcome, None));
        let v = s.welcome(choice).expect("welcome");
        assert_eq!((v.step, v.update_checks), (Step::Checks, Some(choice)));
        assert_eq!(w.saved().update_checks, Some(choice));
        // Step 1 is never redone: the choice changes in Settings afterwards.
        assert_eq!(s.welcome(!choice), Err(CommandError::NotAllowed));
        assert_eq!(w.saved().update_checks, Some(choice));
    }
}

#[test]
fn no_command_runs_outside_its_step() {
    let w = World::new();
    let s = w.start();
    assert_eq!(s.run_checks(), Err(CommandError::NotAllowed));
    assert_eq!(s.prepare_node(false), Err(CommandError::NotAllowed));
    assert_eq!(s.apply_share(share(90)), Err(CommandError::NotAllowed));
    assert_eq!(s.create_cloud(), Err(CommandError::NotAllowed));
    assert_eq!(s.pair_phone(), Err(CommandError::NotAllowed));
    assert_eq!(s.finish_phone().map(|_| ()), Err(CommandError::NotAllowed));
    assert_eq!(s.download_image(false), Err(CommandError::NotAllowed));
    assert!(w.host.calls().is_empty(), "{:?}", w.host.calls());
}

// --- Step 2 ---

#[test]
fn passing_checks_go_on_to_step_3() {
    let w = World::new();
    let s = w.start();
    s.welcome(false).expect("welcome");
    let v = s.run_checks().expect("checks");
    assert_eq!(v.step, Step::Share);
    assert_eq!(v.error, None);
    let checks = v.checks.expect("checks shown");
    assert!(checks.passed && !checks.install_wsl);
    assert!(w.saved().checks_passed);
}

#[test]
fn virtualization_off_stays_at_step_2_with_the_guide() {
    let w = World::new();
    w.host.script().checks = VecDeque::from([Ok(ChecksReport {
        virtualization: Virtualization::Disabled,
        ..good_report()
    })]);
    let s = w.start();
    s.welcome(true).expect("welcome");
    let v = s.run_checks().expect("checks");
    assert_eq!(v.step, Step::Checks);
    let e = v.error.expect("error");
    assert_eq!(e.code, SetupErrorCode::VirtualizationOff);
    assert_eq!(e.guide_url, Some(crate::setup::errors::VIRTUALIZATION_GUIDE_URL));
    assert!(!w.saved().checks_passed);
}

#[test]
fn under_20_gib_is_disk_low_with_how_much_is_needed() {
    let w = World::new();
    w.host.script().checks = VecDeque::from([Ok(ChecksReport {
        disk: DiskState::Free(12 * GIB),
        ..good_report()
    })]);
    let s = w.start();
    s.welcome(true).expect("welcome");
    let v = s.run_checks().expect("checks");
    let e = v.error.expect("error");
    assert_eq!(e.code, SetupErrorCode::DiskLow);
    assert!(e.detail.expect("detail").contains("at least 20 GiB"));
    assert_eq!(v.step, Step::Checks);
}

#[test]
fn missing_wsl_offers_step_2a_which_installs_and_checks_again() {
    let w = World::new();
    w.host.script().checks = VecDeque::from([
        Ok(ChecksReport {
            wsl: WslState::Missing,
            ..good_report()
        }),
        Ok(good_report()),
    ]);
    let s = w.start();
    s.welcome(true).expect("welcome");
    let v = s.run_checks().expect("checks");
    assert_eq!(v.error, None, "a missing WSL is step 2a, not an error");
    assert!(v.checks.expect("checks").install_wsl);
    let v = s.install_wsl().expect("2a");
    assert_eq!(v.step, Step::Share);
    assert!(!v.reboot_pending);
    let r = w.saved();
    assert!(r.wsl_installed && r.checks_passed);
    assert_eq!(w.host.count("checks"), 2);
}

#[test]
fn step_2a_is_refused_when_the_checks_do_not_offer_it() {
    let w = World::new();
    w.host.script().checks = VecDeque::from([Ok(ChecksReport {
        virtualization: Virtualization::Disabled,
        ..good_report()
    })]);
    let s = w.start();
    s.welcome(true).expect("welcome");
    assert_eq!(s.install_wsl(), Err(CommandError::NotAllowed), "no checks yet");
    s.run_checks().expect("checks");
    assert_eq!(s.install_wsl(), Err(CommandError::NotAllowed), "WSL is fine");
    assert_eq!(w.host.count("install_wsl"), 0);
}

#[test]
fn a_reboot_is_asked_once_with_the_run_once_entry_and_resumes_at_step_2() {
    let w = World::new();
    w.host.script().checks = VecDeque::from([
        Ok(ChecksReport {
            wsl: WslState::Missing,
            ..good_report()
        }),
        Ok(good_report()),
    ]);
    w.host.script().install = WslInstall::RebootRequired;
    let s = w.start();
    s.welcome(true).expect("welcome");
    s.run_checks().expect("checks");
    let v = s.install_wsl().expect("2a");
    assert!(v.reboot_pending);
    assert_eq!(v.step, Step::Checks);
    assert_eq!(w.host.count("reopen_after_reboot"), 1);
    drop(s);

    // The reboot: the app starts again at step 2 and the checks pass.
    let s = w.start();
    let v = s.view().expect("view");
    assert_eq!((v.step, v.reboot_pending), (Step::Checks, true));
    let v = s.run_checks().expect("checks");
    assert_eq!((v.step, v.reboot_pending), (Step::Share, false));
}

#[test]
fn an_install_that_leaves_wsl_missing_asks_for_the_reboot() {
    let w = World::new();
    w.host.script().checks = VecDeque::from([Ok(ChecksReport {
        wsl: WslState::Missing,
        ..good_report()
    })]);
    let s = w.start();
    s.welcome(true).expect("welcome");
    s.run_checks().expect("checks");
    let v = s.install_wsl().expect("2a");
    assert!(v.reboot_pending);
    assert_eq!(w.host.count("reopen_after_reboot"), 1);
}

#[test]
fn a_failed_or_declined_install_is_wsl_install_failed_and_stays() {
    for (exit_code, needle) in [(Some(5), "exit code 5"), (None, "declined")] {
        let w = World::new();
        w.host.script().checks = VecDeque::from([Ok(ChecksReport {
            wsl: WslState::Missing,
            ..good_report()
        })]);
        w.host.script().install = WslInstall::Failed { exit_code };
        let s = w.start();
        s.welcome(true).expect("welcome");
        s.run_checks().expect("checks");
        let v = s.install_wsl().expect("2a");
        let e = v.error.expect("error");
        assert_eq!(e.code, SetupErrorCode::WslInstallFailed);
        assert!(e.try_again);
        assert!(e.detail.expect("detail").contains(needle));
        assert_eq!(v.step, Step::Checks);
        assert!(!w.saved().wsl_installed);
    }
}

#[test]
fn wsl_still_too_old_after_2a_is_wsl_too_old_and_2a_is_not_offered_again() {
    let old = ChecksReport {
        wsl: WslState::Installed(WslVersion::new(1, 2, 5)),
        ..good_report()
    };
    let w = World::new();
    w.host.script().checks = VecDeque::from([Ok(old)]);
    let s = w.start();
    s.welcome(true).expect("welcome");
    let v = s.run_checks().expect("checks");
    assert_eq!(v.error, None);
    assert!(v.checks.expect("checks").install_wsl, "2a updates it");
    let v = s.install_wsl().expect("2a");
    assert_eq!(error_code(&v), Some(SetupErrorCode::WslTooOld));
    assert!(!v.checks.expect("checks").install_wsl);
    assert_eq!(s.install_wsl(), Err(CommandError::NotAllowed));
    assert_eq!(v.step, Step::Checks);
}

#[test]
fn a_check_that_could_not_run_is_an_error_and_stays() {
    let w = World::new();
    w.host.script().checks = VecDeque::from([Err(SetupError::with_detail(
        SetupErrorCode::ChecksFailed,
        "the system checks could not run",
    ))]);
    let s = w.start();
    s.welcome(true).expect("welcome");
    let v = s.run_checks().expect("checks");
    assert_eq!(error_code(&v), Some(SetupErrorCode::ChecksFailed));
    assert_eq!(v.step, Step::Checks);
}

// --- Download and step 3 ---

#[test]
fn the_download_runs_in_the_background_of_step_2_and_reports_progress() {
    let w = World::new();
    let s = w.start();
    s.welcome(true).expect("welcome");
    let v = s.download_image(false).expect("download");
    assert_eq!(v.download.state, "done");
    assert_eq!(v.step, Step::Checks, "the download finishes no step");
}

#[test]
fn a_hash_mismatch_stays_at_step_3_and_is_retried_only_when_asked() {
    let w = World::new();
    w.host.script().download = VecDeque::from([Err(SetupError::new(SetupErrorCode::ImageHashMismatch)), Ok(())]);
    let s = w.start();
    s.welcome(true).expect("welcome");
    s.run_checks().expect("checks");
    let v = s.prepare_node(false).expect("prepare");
    assert_eq!(error_code(&v), Some(SetupErrorCode::ImageHashMismatch));
    assert_eq!(v.download.state, "failed");
    assert_eq!(v.step, Step::Share);
    assert!(w.saved().node.is_none());
    assert_eq!(w.host.count("install_distro"), 0, "nothing imported");
    assert_eq!(w.host.count("download_image"), 1, "not retried silently");
    // "Try again".
    let v = s.prepare_node(true).expect("prepare");
    assert_eq!(v.error, None);
    assert!(w.saved().node.is_some());
}

#[test]
fn an_import_failure_stays_at_step_3() {
    let w = World::new();
    w.host.script().install_distro = Err(SetupError::with_detail(
        SetupErrorCode::ImportFailed,
        "exit code 1: The operation timed out",
    ));
    let s = w.start();
    s.welcome(true).expect("welcome");
    s.run_checks().expect("checks");
    let v = s.prepare_node(false).expect("prepare");
    assert_eq!(error_code(&v), Some(SetupErrorCode::ImportFailed));
    assert_eq!(v.step, Step::Share);
    assert!(w.saved().node.is_none());
}

#[test]
fn the_import_is_never_repeated_after_a_restart() {
    let w = World::new();
    let s = w.start();
    s.welcome(true).expect("welcome");
    s.run_checks().expect("checks");
    s.prepare_node(false).expect("prepare");
    drop(s);
    let s = w.start();
    let v = s.view().expect("view");
    assert_eq!(v.step, Step::Share);
    // The controls are known; the disk range waits for a fresh measurement.
    let share = v.share.expect("share");
    assert_eq!(share.disk_max_gib, None);
    let v = s.prepare_node(false).expect("prepare again");
    assert_eq!(v.share.expect("share").disk_max_gib, Some(200 - 36));
    assert_eq!(w.host.count("install_distro"), 1);
    assert_eq!(w.host.count("download_image"), 1);
    assert_eq!(w.host.count("checks"), 1, "step 2 is not redone");
}

#[test]
fn step_3_offers_the_node_s_hardware_and_the_disk_arithmetic() {
    let w = World::new();
    w.host.script().free = VecDeque::from([126 * GIB]);
    let s = w.start();
    s.welcome(true).expect("welcome");
    s.run_checks().expect("checks");
    let v = s.prepare_node(false).expect("prepare");
    let share = v.share.expect("share");
    assert_eq!((share.cpu_max, share.cpu_default), (16, 15));
    assert_eq!(
        (share.memory_mb_min, share.memory_mb_max, share.memory_mb_default),
        (1024, 32_000, 24_000)
    );
    assert!(share.gpu_offerable && share.gpu_default);
    assert_eq!(
        (share.disk_min_gib, share.disk_max_gib, share.disk_default_gib),
        (Some(1), Some(90), Some(90))
    );
    assert_eq!(share.templates_gib, 50);
}

#[test]
fn too_little_room_for_any_share_is_disk_low_at_step_3() {
    let w = World::new();
    w.host.script().free = VecDeque::from([30 * GIB]);
    let s = w.start();
    s.welcome(true).expect("welcome");
    s.run_checks().expect("checks");
    let v = s.prepare_node(false).expect("prepare");
    let e = v.error.expect("error");
    assert_eq!(e.code, SetupErrorCode::DiskLow);
    assert!(e.detail.expect("detail").contains("37 GiB"));
    assert_eq!(
        s.apply_share(share(1)).map(|v| error_code(&v)),
        Ok(Some(SetupErrorCode::DiskLow))
    );
    assert_eq!(w.host.count("apply_share"), 0);
}

#[test]
fn the_share_is_validated_in_rust_before_anything_runs() {
    let w = World::new();
    w.host.script().facts.gpu_offerable = false;
    let s = w.start();
    s.welcome(true).expect("welcome");
    s.run_checks().expect("checks");
    s.prepare_node(false).expect("prepare");
    let bad = [
        ShareRequest { cpu: 0, ..share(90) },
        ShareRequest { cpu: 17, ..share(90) },
        ShareRequest {
            memory_mb: 1023,
            ..share(90)
        },
        ShareRequest {
            memory_mb: 32_001,
            ..share(90)
        },
        ShareRequest { gpu: true, ..share(90) },
        share(0),
        share(200 - 36 + 1),
    ];
    for request in bad {
        assert_eq!(
            s.apply_share(request),
            Err(CommandError::InvalidArgument),
            "{request:?}"
        );
    }
    assert_eq!(w.host.count("apply_share"), 0);
    assert!(w.saved().share.is_none());
}

#[test]
fn the_share_is_split_and_applied() {
    let w = World::new();
    let s = w.start();
    s.welcome(true).expect("welcome");
    s.run_checks().expect("checks");
    s.prepare_node(false).expect("prepare");
    let v = s
        .apply_share(ShareRequest {
            cpu: 6,
            memory_mb: 8192,
            gpu: true,
            share_gib: 120,
        })
        .expect("share");
    assert_eq!(v.step, Step::CreateOrJoin);
    let applied = w.host.shares.lock().expect("lock")[0];
    assert_eq!(
        applied,
        ShareRecord {
            cpu: 6,
            memory_mb: 8192,
            gpu: true,
            share_gib: 120,
            disk_mb: 50 * 1024,
            volumes_mb: 70 * 1024,
        }
    );
    assert_eq!(w.saved().share, Some(applied));
}

#[test]
fn a_share_the_agent_refuses_stays_at_step_3() {
    let w = World::new();
    w.host.script().apply_share = Err(SetupError::with_detail(
        SetupErrorCode::ShareFailed,
        "p2pc-agent share set ended with exit code 2",
    ));
    let s = w.start();
    s.welcome(true).expect("welcome");
    s.run_checks().expect("checks");
    s.prepare_node(false).expect("prepare");
    let v = s.apply_share(share(90)).expect("share");
    assert_eq!(error_code(&v), Some(SetupErrorCode::ShareFailed));
    assert_eq!(v.step, Step::Share);
    assert!(w.saved().share.is_none());
}

// --- Step 4 ---

#[test]
fn create_my_cloud_runs_every_sub_step_in_order_with_a_pre_approved_300_s_token() {
    let w = World::new();
    let s = to_create(&w);
    let before = w.host.calls().len();
    let v = s.create_cloud().expect("create");
    assert_eq!(v.error, None, "{v:?}");
    assert_eq!(v.step, Step::AddPhone);
    assert_eq!(v.role, Some(Role::Hub));
    assert_eq!(v.hub_notice, Some(HUB_NOTICE));
    assert_eq!(
        w.host.calls()[before..],
        [
            "free_bytes".to_owned(),
            "hub_initialised".into(),
            format!("init_hub {NODE_ID} {OWNER_DEVICE_LABEL}"),
            // 200 − 20 − 16 − 90 = 74, capped at 20 GiB.
            "set_blobs_quota 20480".into(),
            "enable_hub".into(),
            "join_agent".into(),
            "restart_node".into(),
        ]
    );
    assert_eq!(
        w.hub.calls(),
        ["set_hub_name My cloud".to_owned(), "mint_join_token".into()]
    );
    assert_eq!(
        *w.hub.token_requests.lock().expect("lock"),
        vec![JoinTokenRequest {
            ttl_s: 300,
            pre_approved: true
        }]
    );
    // The token went to the agent, and nowhere else.
    assert_eq!(*w.host.tokens.lock().expect("lock"), vec![TOKEN.to_owned()]);
    let file = std::fs::read_to_string(w.file().path()).expect("read");
    assert!(!file.contains("p2pc_join_"), "{file}");
    let json = serde_json::to_string(&v).expect("json");
    assert!(!json.contains("p2pc_join_"), "{json}");
    let r = w.saved();
    assert_eq!(r.role, Some(Role::Hub));
    let hub = r.hub.expect("hub");
    assert_eq!(hub.blobs_quota_mb, Some(20 * 1024));
    assert_eq!(hub.server_address.as_deref(), Some("p2pc_srv_EXAMPLE"));
    assert!(hub.initialised && hub.quota_written && hub.hub_enabled && hub.named && hub.joined && hub.node_started);
}

#[test]
fn the_hub_quota_comes_from_the_free_space_at_create_time() {
    let w = World::new();
    let s = to_create(&w);
    // 140 GiB free now: 140 − 36 − 90 = 14 GiB.
    w.host.script().free = VecDeque::from([140 * GIB]);
    s.create_cloud().expect("create");
    assert!(w.host.calls().contains(&"set_blobs_quota 14336".to_owned()));
}

#[test]
fn a_share_that_leaves_the_hub_under_4_gib_goes_back_to_step_3_before_anything_is_created() {
    let w = World::new();
    let s = to_create(&w);
    // 129 GiB free: 129 − 36 − 90 = 3 GiB, under 4. The largest share that leaves 4 GiB is 89.
    w.host.script().free = VecDeque::from([129 * GIB]);
    let v = s.create_cloud().expect("create");
    let e = v.error.expect("error");
    assert_eq!(e.code, SetupErrorCode::ShareTooLarge);
    assert!(e.detail.expect("detail").contains("89 GiB"));
    assert_eq!(v.step, Step::Share);
    assert_eq!(v.share.expect("share").disk_max_gib, Some(89));
    assert!(
        !w.host.calls().iter().any(|c| c.starts_with("init_hub")),
        "nothing created"
    );
    assert!(w.hub.calls().is_empty());
    let r = w.saved();
    assert!(r.share.is_none());
    assert_eq!(r.hub.as_ref().and_then(|h| h.share_cap_gib), Some(89));

    // A share above the cap is refused; one under it goes on, and the quota is computed for it.
    assert_eq!(s.apply_share(share(90)), Err(CommandError::InvalidArgument));
    let v = s.apply_share(share(80)).expect("smaller share");
    assert_eq!(v.step, Step::CreateOrJoin);
    let v = s.create_cloud().expect("create");
    assert_eq!(v.error, None);
    // 129 − 36 − 80 = 13 GiB.
    assert!(w.host.calls().contains(&"set_blobs_quota 13312".to_owned()));
}

#[test]
fn a_failure_in_the_middle_resumes_at_the_sub_step_that_failed_even_after_a_restart() {
    let w = World::new();
    w.host.script().enable_hub = VecDeque::from([
        Err(SetupError::with_detail(
            SetupErrorCode::HubFailed,
            "schtasks /Run failed",
        )),
        Ok(()),
    ]);
    let s = to_create(&w);
    let v = s.create_cloud().expect("create");
    assert_eq!(error_code(&v), Some(SetupErrorCode::HubFailed));
    assert_eq!(v.step, Step::CreateOrJoin);
    drop(s);
    let s = w.start();
    let v = s.create_cloud().expect("create again");
    assert_eq!(v.error, None);
    assert_eq!(v.step, Step::AddPhone);
    let inits = w.host.calls().iter().filter(|c| c.starts_with("init_hub")).count();
    assert_eq!(inits, 1, "init never runs twice");
    let quota_writes = w
        .host
        .calls()
        .iter()
        .filter(|c| c.starts_with("set_blobs_quota"))
        .count();
    assert_eq!(quota_writes, 1);
    assert_eq!(w.host.count("enable_hub"), 2);
}

#[test]
fn a_hub_data_dir_from_an_unrecorded_attempt_is_not_initialised_again() {
    let w = World::new();
    w.host.script().hub_initialised = true;
    w.host.script().join = VecDeque::from([JoinResult::AlreadyEnrolled]);
    let s = to_create(&w);
    let v = s.create_cloud().expect("create");
    assert_eq!(v.error, None, "{v:?}");
    assert!(!w.host.calls().iter().any(|c| c.starts_with("init_hub")));
    let hub = w.saved().hub.expect("hub");
    assert!(hub.found_existing);
    assert_eq!(hub.server_address.as_deref(), Some("p2pc_srv_EXISTING"));
}

#[test]
fn an_agent_enrolled_elsewhere_is_not_taken_for_ours() {
    let w = World::new();
    w.host.script().join = VecDeque::from([JoinResult::AlreadyEnrolled]);
    let s = to_create(&w);
    let v = s.create_cloud().expect("create");
    let e = v.error.expect("error");
    assert_eq!(e.code, SetupErrorCode::HubFailed);
    assert!(e.detail.expect("detail").contains("another cloud"));
    assert_eq!(v.step, Step::CreateOrJoin);
    assert!(!w.saved().hub.expect("hub").joined);
}

#[test]
fn an_answer_lost_in_a_crash_is_recognised_on_the_retry() {
    // The first join enrolled the agent but its answer was lost (Failed); the retry gets "already enrolled".
    let w = World::new();
    w.host.script().join = VecDeque::from([JoinResult::Failed { exit_code: None }, JoinResult::AlreadyEnrolled]);
    let s = to_create(&w);
    assert!(s.create_cloud().expect("create").error.is_some());
    let v = s.create_cloud().expect("retry");
    assert_eq!(v.error, None);
    assert_eq!(v.step, Step::AddPhone);
}

#[test]
fn a_refused_token_is_join_rejected_and_the_retry_mints_a_new_one() {
    let w = World::new();
    w.host.script().join = VecDeque::from([JoinResult::Rejected, JoinResult::Joined]);
    let s = to_create(&w);
    let v = s.create_cloud().expect("create");
    assert_eq!(error_code(&v), Some(SetupErrorCode::JoinRejected));
    assert_eq!(v.step, Step::CreateOrJoin);
    let v = s.create_cloud().expect("retry");
    assert_eq!(v.error, None);
    assert_eq!(w.hub.token_requests.lock().expect("lock").len(), 2);
}

#[test]
fn without_the_device_connection_create_stops_with_not_available() {
    let w = World::with(
        FakeHost::default(),
        FakeHub {
            unwired: true,
            ..FakeHub::default()
        },
    );
    let s = to_create(&w);
    let v = s.create_cloud().expect("create");
    assert_eq!(error_code(&v), Some(SetupErrorCode::NotAvailable));
    assert_eq!(v.step, Step::CreateOrJoin);
    assert_eq!(w.host.count("join_agent"), 0);
    let hub = w.saved().hub.expect("hub");
    assert!(hub.initialised && hub.hub_enabled && !hub.named);
}

// --- Mirrored networking (§10.5) ---

#[test]
fn mirrored_networking_is_warned_about_from_step_4_on() {
    let w = World::new();
    w.host.script().networking = NetworkingMode::Mirrored;
    let s = w.start();
    s.welcome(true).expect("welcome");
    s.run_checks().expect("checks");
    let v = s.prepare_node(false).expect("prepare");
    assert!(v.warnings.is_empty(), "the role is not chosen yet");
    let v = s.apply_share(share(90)).expect("share");
    assert_eq!(v.warnings, vec![MIRRORED_WARNING]);
    let v = s.create_cloud().expect("create");
    assert_eq!(v.warnings, vec![MIRRORED_WARNING]);
    assert_eq!(w.saved().node.expect("node").networking, NetworkingMode::Mirrored);
}

#[test]
fn nat_networking_has_no_warning_and_an_unknown_mode_a_note() {
    for (mode, expected) in [
        (NetworkingMode::Nat, vec![]),
        (NetworkingMode::Other, vec![]),
        (NetworkingMode::Unknown, vec![NETWORKING_UNKNOWN_NOTE]),
    ] {
        let w = World::new();
        w.host.script().networking = mode;
        let s = to_create(&w);
        assert_eq!(s.view().expect("view").warnings, expected, "{mode:?}");
    }
}

// --- Step 5 ---

fn to_phone(w: &World) -> Setup {
    let s = to_create(w);
    assert_eq!(s.create_cloud().expect("create").step, Step::AddPhone);
    s
}

#[test]
fn add_my_phone_shows_a_qr_code_and_the_web_app_s_address_never_the_ticket() {
    let w = World::new();
    let s = to_phone(&w);
    let v = s.pair_phone().expect("pair");
    let phone = v.phone.clone().expect("phone");
    let qr = phone.qr.expect("qr");
    assert_eq!(qr.rows.len(), qr.size);
    assert!(
        qr.rows
            .iter()
            .all(|r| r.len() == qr.size && r.chars().all(|c| c == '0' || c == '1'))
    );
    assert_eq!(qr, qr_of(TICKET_URL).expect("qr"));
    assert_eq!(phone.web_app_url.as_deref(), Some("https://app.example.invalid"));
    assert_eq!(phone.expires_at.as_deref(), Some("2026-11-12T10:10:00Z"));
    let json = serde_json::to_string(&v).expect("json");
    assert!(!json.contains("p2pc_pair_"), "{json}");
    assert!(w.hub.calls().contains(&"create_pairing_ticket 600".to_owned()));
    let file = std::fs::read_to_string(w.file().path()).expect("read");
    assert!(!file.contains("p2pc_pair_"));
}

#[test]
fn a_paired_phone_is_shown_and_continue_finishes_first_run() {
    let w = World::new();
    w.hub.devices.lock().expect("lock").push(PairedDevice {
        id: "dev_owner".into(),
        platform: "Windows".into(),
    });
    let s = to_phone(&w);
    s.pair_phone().expect("pair");
    let v = s.phone_status().expect("status");
    assert_eq!(v.phone.expect("phone").paired, None);
    w.hub.devices.lock().expect("lock").push(PairedDevice {
        id: "dev_phone".into(),
        platform: "iOS\u{7} Safari".into(),
    });
    let v = s.phone_status().expect("status");
    assert_eq!(v.phone.expect("phone").paired.as_deref(), Some("iOS  Safari"));
    let (v, role) = s.finish_phone().expect("finish");
    assert_eq!(role, Some(Role::Hub));
    assert_eq!(v.step, Step::Ready);
    assert_eq!(v.hub_notice, Some(HUB_NOTICE));
    assert!(w.hub.calls().contains(&"revoke_pairing_ticket pt_1".to_owned()));
    assert_eq!(
        w.saved().phone,
        Some(PhoneOutcome::Paired {
            platform: "iOS  Safari".into()
        })
    );
    assert_eq!(w.saved().finished(), Some(Role::Hub));
}

#[test]
fn skip_for_now_revokes_the_ticket_and_finishes() {
    let w = World::new();
    let s = to_phone(&w);
    s.pair_phone().expect("pair");
    s.pair_phone().expect("a new QR revokes the first");
    assert!(w.hub.calls().contains(&"revoke_pairing_ticket pt_1".to_owned()));
    let (v, role) = s.finish_phone().expect("skip");
    assert_eq!((v.step, role), (Step::Ready, Some(Role::Hub)));
    assert!(w.hub.calls().contains(&"revoke_pairing_ticket pt_2".to_owned()));
    assert_eq!(w.saved().phone, Some(PhoneOutcome::Skipped));
    // Finished: nothing of first run runs again.
    assert_eq!(s.pair_phone(), Err(CommandError::NotAllowed));
}

#[test]
fn skipping_without_a_qr_code_works_without_the_device_connection() {
    let w = World::new();
    let s = to_phone(&w);
    let (v, role) = s.finish_phone().expect("skip");
    assert_eq!((v.step, role), (Step::Ready, Some(Role::Hub)));
}

#[test]
fn a_blank_platform_is_shown_as_a_device_and_a_long_one_is_cut() {
    assert_eq!(clean_platform(" \n "), "a device");
    assert_eq!(clean_platform(&"x".repeat(200)).chars().count(), MAX_PLATFORM_CHARS);
}

#[test]
fn only_an_https_ticket_url_gives_an_address() {
    assert_eq!(
        https_origin("https://app.example.invalid:8443/pair#x").as_deref(),
        Some("https://app.example.invalid:8443")
    );
    assert_eq!(https_origin("http://app.example.invalid/pair#x"), None);
    assert_eq!(https_origin("not a url"), None);
}

// --- One action at a time ---

#[test]
fn a_second_action_while_one_runs_is_busy_and_status_still_answers() {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let host = FakeHost::default();
    *host.gate.lock().expect("lock") = Some((started_tx, release_rx));
    let w = World::with(host, FakeHub::default());
    let s = Arc::new(w.start());
    s.welcome(true).expect("welcome");
    let running = {
        let s = Arc::clone(&s);
        std::thread::spawn(move || s.run_checks())
    };
    started_rx.recv().expect("checks started");
    assert_eq!(s.run_checks(), Err(CommandError::Busy));
    assert_eq!(s.install_wsl(), Err(CommandError::Busy));
    let v = s.view().expect("status answers while an action runs");
    assert!(v.busy);
    release_tx.send(()).expect("release");
    let v = running.join().expect("thread").expect("checks");
    assert_eq!(v.step, Step::Share);
    assert!(!s.view().expect("view").busy);
}

#[test]
fn the_view_s_json_has_the_window_s_fields() {
    let w = World::new();
    let v = serde_json::to_value(w.start().view().expect("view")).expect("json");
    let keys: std::collections::BTreeSet<&str> = v.as_object().expect("object").keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        std::collections::BTreeSet::from([
            "step",
            "busy",
            "update_checks",
            "checks",
            "reboot_pending",
            "download",
            "share",
            "warnings",
            "phone",
            "role",
            "hub_notice",
            "error"
        ])
    );
    assert_eq!(v["step"], "welcome");
    assert_eq!(v["update_checks"], serde_json::Value::Null);
}

// --- Review fixes ---

fn mismatch() -> SetupError {
    SetupError::new(SetupErrorCode::ImageHashMismatch)
}

#[test]
fn a_mismatch_in_the_background_download_is_never_retried_silently() {
    let w = World::new();
    w.host.script().download = VecDeque::from([Err(mismatch()), Ok(())]);
    let s = w.start();
    s.welcome(true).expect("welcome");
    // The background download of step 2: its failure is the view's error, so the window stops its automatic actions.
    let v = s.download_image(false).expect("download");
    assert_eq!(error_code(&v), Some(SetupErrorCode::ImageHashMismatch));
    assert_eq!(v.download.state, "failed");
    s.run_checks().expect("checks");
    // Step 3 opens and the window prepares the node by itself: no second download.
    let v = s.prepare_node(false).expect("prepare");
    assert_eq!(error_code(&v), Some(SetupErrorCode::ImageHashMismatch));
    assert_eq!(
        s.download_image(false).map(|v| error_code(&v)),
        Ok(Some(SetupErrorCode::ImageHashMismatch))
    );
    assert_eq!(
        w.host.count("download_image"),
        1,
        "never downloaded again without the user"
    );
    assert_eq!(w.host.count("install_distro"), 0);
    assert!(w.saved().node.is_none());
    // "Try again" is the user asking.
    let v = s.prepare_node(true).expect("retry");
    assert_eq!(v.error, None);
    assert_eq!(w.host.count("download_image"), 2);
    assert!(w.saved().node.is_some());
    assert!(!w.saved().image_hash_mismatch);
}

#[test]
fn a_mismatch_stays_sticky_across_a_restart() {
    let w = World::new();
    w.host.script().download = VecDeque::from([Err(mismatch()), Ok(())]);
    let s = w.start();
    s.welcome(true).expect("welcome");
    s.download_image(false).expect("download");
    assert!(w.saved().image_hash_mismatch);
    drop(s);
    let s = w.start();
    assert_eq!(s.view().expect("view").download.state, "failed");
    let v = s.download_image(false).expect("download after restart");
    assert_eq!(error_code(&v), Some(SetupErrorCode::ImageHashMismatch));
    s.run_checks().expect("checks");
    assert_eq!(
        s.prepare_node(false).map(|v| error_code(&v)),
        Ok(Some(SetupErrorCode::ImageHashMismatch))
    );
    assert_eq!(w.host.count("download_image"), 1);
    s.download_image(true).expect("explicit retry");
    assert_eq!(w.host.count("download_image"), 2);
    assert!(!w.saved().image_hash_mismatch);
}

#[test]
fn a_background_download_failure_is_shown_and_may_be_resumed() {
    let w = World::new();
    w.host.script().download = VecDeque::from([Err(SetupError::new(SetupErrorCode::ImageDownloadFailed)), Ok(())]);
    let s = w.start();
    s.welcome(true).expect("welcome");
    let v = s.download_image(false).expect("download");
    assert_eq!(error_code(&v), Some(SetupErrorCode::ImageDownloadFailed));
    assert!(!w.saved().image_hash_mismatch);
    s.run_checks().expect("checks");
    // Not a mismatch: the import's own download resumes it.
    let v = s.prepare_node(false).expect("prepare");
    assert_eq!(v.error, None);
    assert_eq!(w.host.count("download_image"), 2);
}

#[test]
fn a_failed_mint_does_not_make_a_foreign_enrollment_ours() {
    let w = World::new();
    w.host.script().join = VecDeque::from([JoinResult::AlreadyEnrolled]);
    *w.hub.mint_failures.lock().expect("lock") = 1;
    let s = to_create(&w);
    let v = s.create_cloud().expect("create");
    assert_eq!(error_code(&v), Some(SetupErrorCode::HubFailed));
    assert!(!w.saved().hub.expect("hub").join_started, "no token was minted");
    let v = s.create_cloud().expect("retry");
    let e = v.error.expect("error");
    assert_eq!(e.code, SetupErrorCode::HubFailed);
    assert!(e.detail.expect("detail").contains("another cloud"));
    assert_eq!(v.step, Step::CreateOrJoin);
    assert_eq!(v.role, None);
}

#[test]
fn an_unreadable_setup_json_fails_closed_and_is_not_overwritten() {
    let w = World::new();
    // A directory where the file should be: opening it works, reading it fails (an I/O error, not "not found").
    std::fs::create_dir(w.file().path()).expect("mkdir");
    let s = w.start();
    assert_eq!(s.view(), Err(CommandError::Internal));
    assert_eq!(s.record(), Err(CommandError::Internal));
    assert_eq!(s.welcome(true), Err(CommandError::Internal));
    assert_eq!(s.run_checks(), Err(CommandError::Internal));
    assert_eq!(s.download_image(false), Err(CommandError::Internal));
    assert!(w.file().path().is_dir(), "left as it was");
    assert!(w.host.calls().is_empty());
}

#[test]
fn a_missing_or_invalid_setup_json_starts_over() {
    let w = World::new();
    assert_eq!(w.start().view().expect("view").step, Step::Welcome);
    std::fs::write(w.file().path(), b"not json").expect("write");
    let s = w.start();
    assert_eq!(s.view().expect("view").step, Step::Welcome);
    s.welcome(true).expect("welcome");
    assert_eq!(w.saved().update_checks, Some(true));
}

#[test]
fn closing_the_window_revokes_the_open_pairing_ticket() {
    let w = World::new();
    let s = to_phone(&w);
    s.pair_phone().expect("pair");
    s.close_pairing().expect("close");
    assert!(w.hub.calls().contains(&"revoke_pairing_ticket pt_1".to_owned()));
    let v = s.view().expect("view");
    assert_eq!(v.step, Step::AddPhone, "first run goes on");
    assert_eq!(v.phone.expect("phone").qr, None, "the QR code is gone with its ticket");
    // Nothing open: nothing to revoke, and no hub call.
    let before = w.hub.calls().len();
    s.close_pairing().expect("close again");
    assert_eq!(w.hub.calls().len(), before);
}

// --- Review round 2 ---

#[test]
fn try_again_never_takes_an_agent_enrolled_elsewhere_for_ours() {
    let w = World::new();
    w.host.script().join = VecDeque::from([JoinResult::AlreadyEnrolled, JoinResult::AlreadyEnrolled]);
    let s = to_create(&w);
    for attempt in ["first", "try again"] {
        let v = s.create_cloud().expect("create");
        let e = v.error.expect("error");
        assert_eq!(e.code, SetupErrorCode::HubFailed, "{attempt}");
        assert!(e.detail.expect("detail").contains("another cloud"), "{attempt}");
        assert_eq!(v.role, None, "{attempt}");
        let hub = w.saved().hub.expect("hub");
        assert!(!hub.joined && !hub.join_started, "{attempt}");
    }
    // And after a restart.
    drop(s);
    let s = w.start();
    let v = s.create_cloud().expect("create after restart");
    assert!(
        v.error
            .expect("error")
            .detail
            .expect("detail")
            .contains("another cloud")
    );
    assert_eq!(v.role, None);
    assert!(!w.saved().hub.expect("hub").joined);
    assert_eq!(w.saved().role, None);
}

#[test]
fn the_share_cap_is_cleared_once_a_smaller_share_is_applied() {
    let w = World::new();
    let s = to_create(&w);
    w.host.script().free = VecDeque::from([129 * GIB]);
    s.create_cloud().expect("create: share too large");
    assert_eq!(w.saved().hub.and_then(|h| h.share_cap_gib), Some(89));
    s.apply_share(share(80)).expect("smaller share");
    assert_eq!(
        w.saved().hub.expect("hub").share_cap_gib,
        None,
        "the create-time check applies the limit again"
    );
}
