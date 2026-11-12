// SPDX-License-Identifier: Apache-2.0

//! The first-run flow (H2 §8.2 steps 1-5): which step runs when, what it records in `setup.json`, and what the
//! window is shown.
//!
//! [`Setup`] is the only way through first run. Each window command is one method; each method:
//!
//! - refuses a command its step does not offer ([`CommandError::NotAllowed`]) or arguments out of range
//!   ([`CommandError::InvalidArgument`]), before anything runs;
//! - runs one action at a time ([`CommandError::Busy`] for a second one), without holding the state's lock while it
//!   waits for `wsl.exe`, so the window's `setup_status` always answers;
//! - writes each result to `setup.json` as soon as it has one, so a crash resumes at the first unfinished step and a
//!   finished step is never redone (§8.2 "Resumable");
//! - reports a step's failure as a [`SetupError`] in the view (a code and a fixed message, §8.8), not as a command
//!   error: the window shows it with "Try again" where the spec offers one.
//!
//! The image download of step 2 runs beside the other actions ("In the background the node image download starts"):
//! it has its own slot, and the import of step 3 waits for it.

use std::ops::ControlFlow;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

use serde::{Deserialize, Serialize};

use p2pc_wsl::checks::{ChecksReport, WslState};
use p2pc_wsl::image::Progress;

use crate::core::CommandError;
use crate::state::Role;
use crate::tray::HUB_NOTICE;

use super::disk::{self, ShareRange};
use super::errors::{SetupError, SetupErrorCode, SetupErrorView, from_check_failure};
use super::host::{JoinResult, SetupHost, WslInstall};
use super::hub::{
    HUB_NAME, HubApi, HubError, JoinTokenRequest, OWNER_DEVICE_LABEL, OwnerDevice, PairingTicket, PairingTicketRequest,
};
use super::record::{
    HubRecord, NetworkingMode, NodeRecord, PhoneOutcome, RecordError, RecordFile, SetupRecord, ShareRecord, Step,
};

/// The warning of §10.5 when WSL runs with mirrored networking.
pub const MIRRORED_WARNING: &str = "WSL on this PC uses mirrored networking: devices on your network that know the \
     port can reach your cloud's hub directly, not only through a relay. Every connection still needs a ticket, a \
     token, a key or a paired device. To keep the hub behind your PC's NAT, remove networkingMode=mirrored from \
     .wslconfig.";

/// When WSL's networking mode could not be read.
pub const NETWORKING_UNKNOWN_NOTE: &str = "P2PC could not check WSL's networking mode on this PC. If you turned on mirrored networking in .wslconfig, devices \
     on your network can reach your cloud's hub directly.";

/// The least memory the RAM control offers (§8.2 step 3: "1 GiB … the WSL VM's memory").
pub const MIN_MEMORY_MB: u64 = 1024;

/// The longest platform hint shown for a paired phone (§5.3: at most 64 bytes).
pub const MAX_PLATFORM_CHARS: usize = 64;

/// Step 3's choice, as the window sends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareRequest {
    /// CPU cores, 1 … the WSL VM's processors.
    pub cpu: u32,
    /// RAM in MiB, 1 GiB … the WSL VM's memory.
    pub memory_mb: u64,
    /// GPU on or off; on only if the node offers one.
    pub gpu: bool,
    /// "Disk space for P2PC", `D`, in GiB.
    pub share_gib: u64,
}

/// The image download.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Download {
    Idle,
    Running(Progress),
    Done,
    Failed(SetupError),
}

/// Step 5's pairing ticket and what came of it. In memory only: the ticket is never written anywhere.
#[derive(Debug, Default)]
struct Phone {
    ticket: Option<PairingTicket>,
    qr: Option<QrView>,
    web_app_url: Option<String>,
    /// The devices that existed when the ticket was made.
    known: Vec<String>,
    paired: Option<String>,
}

#[derive(Debug)]
struct Inner {
    record: SetupRecord,
    checks: Option<ChecksReport>,
    download: Download,
    share_range: Option<ShareRange>,
    error: Option<SetupError>,
    phone: Phone,
}

/// A failed check of step 2, as the window lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckLine {
    /// The §8.8 code, where the spec has one.
    pub code: Option<&'static str>,
    pub message: String,
}

/// The last checks of step 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChecksView {
    pub passed: bool,
    pub failures: Vec<CheckLine>,
    pub warnings: Vec<String>,
    /// Step 2a is offered: WSL is missing, or too old and not yet updated by 2a.
    pub install_wsl: bool,
}

/// The image download, as the window shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DownloadView {
    /// `idle`, `running`, `done` or `failed`.
    pub state: &'static str,
    pub done: u64,
    pub total: Option<u64>,
    pub error: Option<SetupErrorView>,
}

/// Step 3's controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShareView {
    pub cpu_max: u32,
    pub cpu_default: u32,
    pub memory_mb_min: u64,
    pub memory_mb_max: u64,
    pub memory_mb_default: u64,
    /// The GPU switch is shown only when the node reports an offerable GPU.
    pub gpu_offerable: bool,
    pub gpu_default: bool,
    /// The disk control: `None` until the free space was measured (`setup_prepare_node`).
    pub disk_min_gib: Option<u64>,
    pub disk_max_gib: Option<u64>,
    pub disk_default_gib: Option<u64>,
    /// The mark below which the AI chat and transcription may not run (§8.2).
    pub templates_gib: u64,
    /// The share already applied, if any.
    pub chosen: Option<ShareRecord>,
}

/// A QR code as rows of modules, `'1'` dark and `'0'` light, without the quiet zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QrView {
    pub size: usize,
    pub rows: Vec<String>,
}

/// Step 5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PhoneView {
    /// The QR code of the pairing ticket's URL. The ticket itself never reaches the window as text.
    pub qr: Option<QrView>,
    /// The web app's address, shown as text.
    pub web_app_url: Option<String>,
    pub expires_at: Option<String>,
    /// "Paired: <platform>".
    pub paired: Option<String>,
}

/// What the window shows during first run (the `setup_status` command and every setup command's answer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupView {
    /// Where first run is.
    pub step: Step,
    /// An action is running.
    pub busy: bool,
    /// Step 1's choice; `null` until the user picked one.
    pub update_checks: Option<bool>,
    pub checks: Option<ChecksView>,
    /// Step 2a asked for the reboot.
    pub reboot_pending: bool,
    pub download: DownloadView,
    pub share: Option<ShareView>,
    /// Warnings to show from step 4 on (mirrored networking, §10.5).
    pub warnings: Vec<&'static str>,
    pub phone: Option<PhoneView>,
    pub role: Option<Role>,
    /// The §8.6 sentence on the hub PC.
    pub hub_notice: Option<&'static str>,
    /// The last action's failure.
    pub error: Option<SetupErrorView>,
}

/// First run.
pub struct Setup {
    host: Arc<dyn SetupHost>,
    hub: Arc<dyn HubApi>,
    device: Arc<dyn OwnerDevice>,
    /// `None`: in memory only (no `%LOCALAPPDATA%`).
    file: Option<RecordFile>,
    /// One action at a time.
    op: Mutex<()>,
    /// The image download (beside the other actions).
    download: Mutex<()>,
    inner: Mutex<Inner>,
    /// `setup.json` exists but could not be read (an I/O error, not "missing" or "invalid"): every command fails
    /// closed with `internal`, and the file is never overwritten. Restarting the app reads it again.
    unreadable: bool,
}

impl std::fmt::Debug for Setup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Setup")
            .field("file", &self.file)
            .finish_non_exhaustive()
    }
}

fn hub_error(e: HubError) -> SetupError {
    match e {
        HubError::NotAvailable => SetupError::new(SetupErrorCode::NotAvailable),
        HubError::Unreachable => SetupError::with_detail(SetupErrorCode::HubFailed, "the hub did not answer"),
        HubError::Refused(status) => {
            SetupError::with_detail(SetupErrorCode::HubFailed, format!("the hub refused (HTTP {status})"))
        }
    }
}

/// A QR code of `text`.
pub fn qr_of(text: &str) -> Option<QrView> {
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let size = code.width();
    let rows = code
        .to_colors()
        .chunks(size)
        .map(|row| {
            row.iter()
                .map(|c| if *c == qrcode::Color::Dark { '1' } else { '0' })
                .collect()
        })
        .collect();
    Some(QrView { size, rows })
}

/// The origin of an `https://` URL (the web app's address, without the ticket in the fragment).
fn https_origin(text: &str) -> Option<String> {
    let url = url::Url::parse(text).ok()?;
    (url.scheme() == "https" && url.host().is_some()).then(|| url.origin().ascii_serialization())
}

/// A platform hint as the window shows it: no control characters, at most [`MAX_PLATFORM_CHARS`].
fn clean_platform(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_PLATFORM_CHARS)
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        "a device".to_owned()
    } else {
        cleaned.to_owned()
    }
}

impl Setup {
    /// First run over `host` and `hub`, resuming from `record`.
    pub fn new(
        host: Arc<dyn SetupHost>,
        hub: Arc<dyn HubApi>,
        device: Arc<dyn OwnerDevice>,
        file: Option<RecordFile>,
        record: SetupRecord,
    ) -> Self {
        Self {
            host,
            hub,
            device,
            file,
            op: Mutex::new(()),
            download: Mutex::new(()),
            inner: Mutex::new(Inner {
                // A mismatch stays reported across restarts: no download runs until the user asks (§8.8).
                download: if record.image_hash_mismatch {
                    Download::Failed(SetupError::new(SetupErrorCode::ImageHashMismatch))
                } else {
                    Download::Idle
                },
                record,
                checks: None,
                share_range: None,
                error: None,
                phone: Phone::default(),
            }),
            unreadable: false,
        }
    }

    /// First run resuming from `file`. A missing file, or one that is not a valid record, starts over: every step is
    /// safe to run again (the import is not repeated for a distro that exists, the hub's init not for a data dir that
    /// exists). A file that exists but cannot be read (locked, denied) fails closed instead: starting over would
    /// overwrite a good record at the next step, so every command answers `internal` and nothing is written.
    pub fn load(
        host: Arc<dyn SetupHost>,
        hub: Arc<dyn HubApi>,
        device: Arc<dyn OwnerDevice>,
        file: Option<RecordFile>,
    ) -> Self {
        let (record, unreadable) = match file.as_ref().map(RecordFile::load) {
            None => (SetupRecord::default(), false),
            Some(Ok(record)) => (record, false),
            Some(Err(RecordError::Invalid)) => (SetupRecord::default(), false),
            Some(Err(RecordError::Io(_))) => (SetupRecord::default(), true),
        };
        Self {
            unreadable,
            ..Self::new(host, hub, device, file, record)
        }
    }

    /// A copy of the record.
    pub fn record(&self) -> Result<SetupRecord, CommandError> {
        Ok(self.inner()?.record.clone())
    }

    /// The role, once first run has finished.
    pub fn finished(&self) -> Result<Option<Role>, CommandError> {
        Ok(self.inner()?.record.finished())
    }

    fn inner(&self) -> Result<MutexGuard<'_, Inner>, CommandError> {
        if self.unreadable {
            return Err(CommandError::Internal);
        }
        self.inner.lock().map_err(|_| CommandError::Internal)
    }

    fn begin(&self) -> Result<MutexGuard<'_, ()>, CommandError> {
        match self.op.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::WouldBlock) => Err(CommandError::Busy),
            Err(TryLockError::Poisoned(_)) => Err(CommandError::Internal),
        }
    }

    /// The record, if setup is at `step`.
    fn at(&self, step: Step) -> Result<SetupRecord, CommandError> {
        let inner = self.inner()?;
        if inner.record.step() == step {
            Ok(inner.record.clone())
        } else {
            Err(CommandError::NotAllowed)
        }
    }

    /// Applies `change` to the record and writes it to `setup.json`.
    fn commit(&self, change: impl FnOnce(&mut SetupRecord)) -> Result<(), CommandError> {
        let mut inner = self.inner()?;
        change(&mut inner.record);
        if let Some(file) = &self.file {
            file.save(&inner.record).map_err(|_| CommandError::Failed)?;
        }
        Ok(())
    }

    fn set_error(&self, error: SetupError) -> Result<(), CommandError> {
        self.inner()?.error = Some(error);
        Ok(())
    }

    /// Runs one action: the slot, a cleared error, the action, then the view (once the slot is free again).
    fn act(&self, action: impl FnOnce(&Self) -> Result<(), CommandError>) -> Result<SetupView, CommandError> {
        {
            let _op = self.begin()?;
            self.inner()?.error = None;
            action(self)?;
        }
        self.view()
    }

    /// What the window shows.
    pub fn view(&self) -> Result<SetupView, CommandError> {
        let busy = matches!(self.op.try_lock(), Err(TryLockError::WouldBlock));
        let inner = self.inner()?;
        let r = &inner.record;
        let step = r.step();
        let checks = inner.checks.as_ref().map(|report| {
            let failures = report.failures();
            ChecksView {
                passed: failures.is_empty(),
                install_wsl: install_offered(report, r.wsl_installed),
                failures: failures
                    .iter()
                    .map(|f| CheckLine {
                        code: f.code(),
                        message: f.message(),
                    })
                    .collect(),
                warnings: report.warnings().iter().map(|w| w.message()).collect(),
            }
        });
        let download = match &inner.download {
            Download::Idle => DownloadView {
                state: "idle",
                done: 0,
                total: None,
                error: None,
            },
            Download::Running(p) => DownloadView {
                state: "running",
                done: p.done,
                total: p.total,
                error: None,
            },
            Download::Done => DownloadView {
                state: "done",
                done: 0,
                total: None,
                error: None,
            },
            Download::Failed(e) => DownloadView {
                state: "failed",
                done: 0,
                total: None,
                error: Some(e.view()),
            },
        };
        let cap = r.hub.as_ref().and_then(|h| h.share_cap_gib);
        let share = r.node.as_ref().map(|n| {
            let range = inner.share_range;
            let max = range.map(|g| cap.map_or(g.max_gib, |c| g.max_gib.min(c)));
            ShareView {
                cpu_max: n.cpu_cores,
                cpu_default: n.default_cpu.clamp(1, n.cpu_cores.max(1)),
                memory_mb_min: MIN_MEMORY_MB,
                memory_mb_max: n.memory_mb,
                memory_mb_default: n.default_memory_mb.clamp(MIN_MEMORY_MB, n.memory_mb.max(MIN_MEMORY_MB)),
                gpu_offerable: n.gpu_offerable,
                gpu_default: n.gpu_offerable,
                disk_min_gib: range.map(|g| g.min_gib),
                disk_max_gib: max,
                disk_default_gib: range.zip(max).map(|(g, m)| g.default_gib.min(m)),
                templates_gib: disk::TEMPLATES_SHARE_GIB,
                chosen: r.share,
            }
        });
        let mut warnings = Vec::new();
        if step >= Step::CreateOrJoin && r.role != Some(Role::Joined) {
            match r.node.as_ref().map(|n| n.networking) {
                Some(NetworkingMode::Mirrored) => warnings.push(MIRRORED_WARNING),
                Some(NetworkingMode::Unknown) => warnings.push(NETWORKING_UNKNOWN_NOTE),
                _ => {}
            }
        }
        let phone = (step == Step::AddPhone).then(|| PhoneView {
            qr: inner.phone.qr.clone(),
            web_app_url: inner.phone.web_app_url.clone(),
            expires_at: inner.phone.ticket.as_ref().map(|t| t.expires_at.clone()),
            paired: inner.phone.paired.clone(),
        });
        Ok(SetupView {
            step,
            busy,
            update_checks: r.update_checks,
            checks,
            reboot_pending: r.reboot_pending,
            download,
            share,
            warnings,
            phone,
            role: r.role,
            hub_notice: (r.role == Some(Role::Hub)).then_some(HUB_NOTICE),
            error: inner.error.as_ref().map(SetupError::view),
        })
    }

    // --- Step 1 ---

    /// Step 1: "Check for updates and verify the web app automatically: Yes / No". Only at the welcome step, once.
    pub fn welcome(&self, update_checks: bool) -> Result<SetupView, CommandError> {
        self.act(|s| {
            s.at(Step::Welcome)?;
            s.commit(|r| r.update_checks = Some(update_checks))
        })
    }

    // --- Step 2 ---

    /// Step 2: every check. All passed: on to step 3.
    pub fn run_checks(&self) -> Result<SetupView, CommandError> {
        self.act(Self::checks_now)
    }

    fn checks_now(&self) -> Result<(), CommandError> {
        let record = self.at(Step::Checks)?;
        let report = match self.host.checks() {
            Ok(report) => report,
            Err(e) => return self.set_error(e),
        };
        let passed = report.passed();
        let error = report
            .failures()
            .iter()
            .find_map(|f| from_check_failure(f, record.wsl_installed));
        self.inner()?.checks = Some(report);
        if let Some(e) = error {
            return self.set_error(e);
        }
        if passed {
            self.commit(|r| {
                r.checks_passed = true;
                r.reboot_pending = false;
            })?;
        }
        Ok(())
    }

    /// Step 2a: installs WSL (elevated), when the last checks offer it.
    pub fn install_wsl(&self) -> Result<SetupView, CommandError> {
        self.act(|s| {
            let record = s.at(Step::Checks)?;
            let offered = s
                .inner()?
                .checks
                .as_ref()
                .is_some_and(|c| install_offered(c, record.wsl_installed));
            if !offered {
                return Err(CommandError::NotAllowed);
            }
            match s.host.install_wsl() {
                WslInstall::Installed => {
                    s.commit(|r| r.wsl_installed = true)?;
                    s.checks_now()?;
                    // Installed but still not usable: Windows needs its reboot first.
                    let missing = s.inner()?.checks.as_ref().is_some_and(|c| c.wsl == WslState::Missing);
                    if missing {
                        s.ask_reboot()?;
                    }
                    Ok(())
                }
                WslInstall::RebootRequired => {
                    s.commit(|r| r.wsl_installed = true)?;
                    s.ask_reboot()
                }
                WslInstall::Failed { exit_code } => s.set_error(SetupError::with_detail(
                    SetupErrorCode::WslInstallFailed,
                    match exit_code {
                        Some(code) => format!("wsl --install ended with exit code {code}"),
                        None => "the administrator prompt was declined, or wsl --install could not start".to_owned(),
                    },
                )),
            }
        })
    }

    fn ask_reboot(&self) -> Result<(), CommandError> {
        // Best effort: without the entry the user opens the app again by hand, and it resumes at step 2 anyway.
        let _ = self.host.reopen_after_reboot();
        self.commit(|r| r.reboot_pending = true)
    }

    // --- The image download (from step 2 on) ---

    /// Downloads the node image in the background of steps 2 and 3. A download already running is not started
    /// twice; once the distro is imported there is nothing to download. A failure becomes the view's error, so the
    /// window stops its automatic actions. After a hash mismatch nothing is downloaded again unless `retry` (the user's
    /// "Try again"): a mismatch is never retried silently (§8.8).
    pub fn download_image(&self, retry: bool) -> Result<SetupView, CommandError> {
        {
            let record = self.record()?;
            if !matches!(record.step(), Step::Checks | Step::Share) || record.node.is_some() {
                return Err(CommandError::NotAllowed);
            }
            let _slot = match self.download.try_lock() {
                Ok(slot) => slot,
                Err(TryLockError::WouldBlock) => return self.view(),
                Err(TryLockError::Poisoned(_)) => return Err(CommandError::Internal),
            };
            if let Err(e) = self.download_now(retry)? {
                self.set_error(e)?;
            }
        }
        self.view()
    }

    /// Runs the download with the download slot held by the caller. After a hash mismatch it returns that error again
    /// without downloading, unless `retry`; a new mismatch is recorded in `setup.json`, so a restart keeps it.
    fn download_now(&self, retry: bool) -> Result<Result<(), SetupError>, CommandError> {
        {
            let mut inner = self.inner()?;
            if let Download::Failed(e) = &inner.download
                && e.code == SetupErrorCode::ImageHashMismatch
                && !retry
            {
                return Ok(Err(e.clone()));
            }
            inner.download = Download::Running(Progress { done: 0, total: None });
        }
        if retry && self.record()?.image_hash_mismatch {
            self.commit(|r| r.image_hash_mismatch = false)?;
        }
        let mut last = 0u64;
        let mut progress = |p: Progress| {
            // At most one update per MiB (and the last one).
            if p.done.saturating_sub(last) >= 1 << 20 || Some(p.done) == p.total {
                last = p.done;
                if let Ok(mut inner) = self.inner.lock() {
                    inner.download = Download::Running(p);
                }
            }
            ControlFlow::Continue(())
        };
        let result = self.host.download_image(&mut progress);
        self.inner()?.download = match &result {
            Ok(()) => Download::Done,
            Err(e) => Download::Failed(e.clone()),
        };
        if matches!(&result, Err(e) if e.code == SetupErrorCode::ImageHashMismatch) {
            self.commit(|r| r.image_hash_mismatch = true)?;
        }
        Ok(result)
    }

    // --- Step 3 ---

    /// Step 3, first half: waits for the download, imports and verifies the distro, registers the task (disabled),
    /// reads the node's hardware and WSL's networking mode; then measures the free space for the Share control. Run
    /// again after a restart, it only measures the free space: the import is never repeated. `retry` is the user's "Try
    /// again": only then is an image that failed its hash check downloaded again.
    pub fn prepare_node(&self, retry: bool) -> Result<SetupView, CommandError> {
        self.act(|s| {
            let record = s.at(Step::Share)?;
            if record.node.is_none() {
                {
                    let _slot = s.download.lock().map_err(|_| CommandError::Internal)?;
                    if let Err(e) = s.download_now(retry)? {
                        return s.set_error(e);
                    }
                }
                let image_version = match s.host.install_distro() {
                    Ok(v) => v,
                    Err(e) => return s.set_error(e),
                };
                let facts = match s.host.node_facts() {
                    Ok(f) => f,
                    Err(e) => return s.set_error(e),
                };
                let networking = s.host.networking_mode();
                s.commit(|r| {
                    r.node = Some(NodeRecord {
                        image_version,
                        cpu_cores: facts.cpu_cores.max(1),
                        memory_mb: facts.memory_mb,
                        gpu_offerable: facts.gpu_offerable,
                        default_cpu: facts.default_cpu,
                        default_memory_mb: facts.default_memory_mb,
                        networking,
                    });
                })?;
            }
            s.measure_share_range().map(|_| ())
        })
    }

    /// Measures the free space and stores the Share control's range. `None` (with the error set) when not even the
    /// smallest share fits.
    fn measure_share_range(&self) -> Result<Option<ShareRange>, CommandError> {
        let free = match self.host.free_bytes() {
            Ok(free) => free,
            Err(e) => {
                self.set_error(e)?;
                return Ok(None);
            }
        };
        match disk::share_range(free) {
            Ok(range) => {
                self.inner()?.share_range = Some(range);
                Ok(Some(range))
            }
            Err(e) => {
                self.inner()?.share_range = None;
                self.set_error(SetupError::with_detail(SetupErrorCode::DiskLow, e.to_string()))?;
                Ok(None)
            }
        }
    }

    /// Step 3, second half: applies the share (`p2pc-agent share set`).
    pub fn apply_share(&self, request: ShareRequest) -> Result<SetupView, CommandError> {
        self.act(|s| {
            let record = s.at(Step::Share)?;
            let node = record.node.as_ref().ok_or(CommandError::NotAllowed)?;
            let cpu_ok = (1..=node.cpu_cores).contains(&request.cpu);
            let memory_ok = (MIN_MEMORY_MB..=node.memory_mb).contains(&request.memory_mb);
            let gpu_ok = !request.gpu || node.gpu_offerable;
            if !(cpu_ok && memory_ok && gpu_ok) {
                return Err(CommandError::InvalidArgument);
            }
            // The range is measured again now: the free space may have changed since the window got it.
            let Some(range) = s.measure_share_range()? else {
                return Ok(());
            };
            let cap = record.hub.as_ref().and_then(|h| h.share_cap_gib);
            let max = cap.map_or(range.max_gib, |c| range.max_gib.min(c));
            if !(range.min_gib..=max).contains(&request.share_gib) {
                return Err(CommandError::InvalidArgument);
            }
            let split = disk::split(request.share_gib);
            let share = ShareRecord {
                cpu: request.cpu,
                memory_mb: request.memory_mb,
                gpu: request.gpu,
                share_gib: request.share_gib,
                disk_mb: split.disk_mb,
                volumes_mb: split.volumes_mb,
            };
            if let Err(e) = s.host.apply_share(&share) {
                return s.set_error(e);
            }
            s.commit(|r| {
                r.share = Some(share);
                // A new share: the hub's quota is computed again from it, and the cap of an earlier "share too large"
                // is dropped (the quota check at "Create my cloud" applies the limit again, from fresh free space).
                if let Some(hub) = r.hub.as_mut() {
                    hub.blobs_quota_mb = None;
                    hub.quota_written = false;
                    hub.share_cap_gib = None;
                }
            })
        })
    }

    // --- Step 4 ---

    /// Step 4, "Create my cloud": the hub's blob quota from the disk arithmetic, `p2pc-server init --owner-device`,
    /// the quota in `server.toml`, `hub.enabled` and the task, the hub's name, the hub PC's own node joined with a
    /// `pre_approved` token through stdin, then the node started. Each sub-step is recorded; "Try again" resumes at
    /// the one that failed.
    pub fn create_cloud(&self) -> Result<SetupView, CommandError> {
        self.act(|s| {
            let record = s.at(Step::CreateOrJoin)?;
            let share = record.share.ok_or(CommandError::NotAllowed)?;
            let mut hub = record.hub.clone().unwrap_or_default();
            if record.hub.is_none() {
                s.commit(|r| r.hub = Some(HubRecord::default()))?;
            }
            let save = |s: &Self, hub: &HubRecord| s.commit(|r| r.hub = Some(hub.clone()));

            // The quota first: a share too large goes back to step 3 before anything is created.
            let quota_mb = match hub.blobs_quota_mb {
                Some(q) => q,
                None => {
                    let free = match s.host.free_bytes() {
                        Ok(free) => free,
                        Err(e) => return s.set_error(e),
                    };
                    match disk::hub_blob_quota(free, share.share_gib) {
                        Ok(q) => {
                            hub.blobs_quota_mb = Some(q);
                            save(s, &hub)?;
                            q
                        }
                        Err(too_large) => {
                            hub.share_cap_gib = Some(too_large.max_share_gib);
                            let hub = hub.clone();
                            s.commit(|r| {
                                r.share = None;
                                r.hub = Some(hub);
                            })?;
                            s.measure_share_range()?;
                            return s.set_error(SetupError::with_detail(
                                SetupErrorCode::ShareTooLarge,
                                format!("Choose at most {} GiB.", too_large.max_share_gib),
                            ));
                        }
                    }
                }
            };

            if !hub.initialised {
                match s.host.hub_initialised() {
                    Err(e) => return s.set_error(e),
                    Ok(true) => {
                        hub.found_existing = true;
                        match s.host.hub_address() {
                            Ok(address) => hub.server_address = Some(address),
                            Err(e) => return s.set_error(e),
                        }
                    }
                    Ok(false) => {
                        let node_id = match s.device.node_id() {
                            Ok(id) => id,
                            Err(_) => {
                                return s.set_error(SetupError::with_detail(
                                    SetupErrorCode::HubFailed,
                                    "this app's device key could not be read",
                                ));
                            }
                        };
                        match s.host.init_hub(&node_id, OWNER_DEVICE_LABEL) {
                            Ok(init) => {
                                hub.owner_device_id = Some(init.owner_device_id);
                                hub.server_address = Some(init.server_address);
                            }
                            Err(e) => return s.set_error(e),
                        }
                    }
                }
                hub.initialised = true;
                save(s, &hub)?;
            }

            if !hub.quota_written {
                if let Err(e) = s.host.set_blobs_quota(quota_mb) {
                    return s.set_error(e);
                }
                hub.quota_written = true;
                save(s, &hub)?;
            }

            if !hub.hub_enabled {
                if let Err(e) = s.host.enable_hub() {
                    return s.set_error(e);
                }
                hub.hub_enabled = true;
                save(s, &hub)?;
            }

            if !hub.named {
                if let Err(e) = s.hub.set_hub_name(HUB_NAME) {
                    return s.set_error(hub_error(e));
                }
                hub.named = true;
                save(s, &hub)?;
            }

            if !hub.joined {
                // An "already enrolled" answer is ours only if an earlier attempt minted a token, or the hub's data
                // dir was there before (an attempt whose record was lost).
                let ours_if_enrolled = hub.join_started || hub.found_existing;
                let token = match s.hub.mint_join_token(&JoinTokenRequest::OWN_NODE) {
                    Ok(token) => token,
                    Err(e) => return s.set_error(hub_error(e)),
                };
                // Recorded once a token exists, before it is used: a join whose answer is lost is ours on the retry.
                hub.join_started = true;
                save(s, &hub)?;
                match s.host.join_agent(&token) {
                    JoinResult::Joined => {}
                    JoinResult::AlreadyEnrolled if ours_if_enrolled => {}
                    JoinResult::AlreadyEnrolled => {
                        // A definite answer: enrolled before our token, so in another cloud. It clears the "maybe ours"
                        // evidence, so "Try again" (or a restart) cannot take it for ours. Only an unknown answer
                        // (`Failed`) keeps `join_started`.
                        hub.join_started = false;
                        save(s, &hub)?;
                        return s.set_error(SetupError::with_detail(
                            SetupErrorCode::HubFailed,
                            "this PC's node is already enrolled in another cloud",
                        ));
                    }
                    JoinResult::Rejected => return s.set_error(SetupError::new(SetupErrorCode::JoinRejected)),
                    JoinResult::Failed { exit_code } => {
                        return s.set_error(SetupError::with_detail(
                            SetupErrorCode::HubFailed,
                            match exit_code {
                                Some(code) => format!("p2pc-agent join ended with exit code {code}"),
                                None => "p2pc-agent join could not run".to_owned(),
                            },
                        ));
                    }
                }
                hub.joined = true;
                save(s, &hub)?;
            }

            if !hub.node_started {
                if let Err(e) = s.host.restart_node() {
                    return s.set_error(e);
                }
                hub.node_started = true;
            }
            let hub = hub.clone();
            s.commit(|r| {
                r.hub = Some(hub);
                r.role = Some(Role::Hub);
            })
        })
    }

    // --- Step 5 ---

    /// Step 5: a pairing ticket (phone profile, 10 minutes) and its QR code. A ticket shown before is revoked first.
    pub fn pair_phone(&self) -> Result<SetupView, CommandError> {
        self.act(|s| {
            s.at(Step::AddPhone)?;
            s.revoke_ticket()?;
            let known = match s.hub.devices() {
                Ok(devices) => devices.into_iter().map(|d| d.id).collect(),
                Err(e) => return s.set_error(hub_error(e)),
            };
            let ticket = match s.hub.create_pairing_ticket(&PairingTicketRequest::PHONE) {
                Ok(t) => t,
                Err(e) => return s.set_error(hub_error(e)),
            };
            let qr = qr_of(&ticket.url);
            let web_app_url = https_origin(&ticket.url);
            let mut inner = s.inner()?;
            inner.phone = Phone {
                ticket: Some(ticket),
                qr,
                web_app_url,
                known,
                paired: None,
            };
            Ok(())
        })
    }

    /// Step 5: looks for the phone that paired with the ticket ("Paired: <platform>").
    pub fn phone_status(&self) -> Result<SetupView, CommandError> {
        self.act(|s| {
            s.at(Step::AddPhone)?;
            let (open, known) = {
                let inner = s.inner()?;
                (
                    inner.phone.ticket.is_some() && inner.phone.paired.is_none(),
                    inner.phone.known.clone(),
                )
            };
            if !open {
                return Ok(());
            }
            let devices = match s.hub.devices() {
                Ok(devices) => devices,
                Err(e) => return s.set_error(hub_error(e)),
            };
            if let Some(new) = devices.into_iter().find(|d| !known.contains(&d.id)) {
                s.inner()?.phone.paired = Some(clean_platform(&new.platform));
            }
            Ok(())
        })
    }

    /// Step 5 ends ("Continue" after pairing, or "Skip for now"): the ticket is revoked (§5.2: when the QR screen
    /// closes) and first run is finished. Returns the view and the role, for the app's state machine.
    pub fn finish_phone(&self) -> Result<(SetupView, Option<Role>), CommandError> {
        let view = self.act(|s| {
            s.at(Step::AddPhone)?;
            s.revoke_ticket()?;
            let paired = s.inner()?.phone.paired.take();
            let outcome = match paired {
                Some(platform) => PhoneOutcome::Paired { platform },
                None => PhoneOutcome::Skipped,
            };
            s.inner()?.phone = Phone::default();
            s.commit(|r| r.phone = Some(outcome))
        })?;
        Ok((view, self.finished()?))
    }

    /// The QR screen closes without finishing step 5 (the window is closed to the tray, or the app quits): the open
    /// ticket is revoked, best effort (§5.2), and its QR code is gone; step 5 shows "Show the pairing code" again. Not
    /// an action: it runs while another one does, and never fails because of the step.
    pub fn close_pairing(&self) -> Result<(), CommandError> {
        self.revoke_ticket()
    }

    /// Revokes the open ticket, best effort (it expires within 10 minutes anyway).
    fn revoke_ticket(&self) -> Result<(), CommandError> {
        let ticket = {
            let mut inner = self.inner()?;
            inner.phone.qr = None;
            inner.phone.web_app_url = None;
            inner.phone.ticket.take()
        };
        if let Some(t) = ticket {
            let _ = self.hub.revoke_pairing_ticket(&t.id);
        }
        Ok(())
    }
}

/// Step 2a is offered: WSL is missing, or too old and 2a has not run yet.
fn install_offered(report: &ChecksReport, wsl_installed: bool) -> bool {
    match report.wsl {
        WslState::Missing => true,
        WslState::Installed(v) => v < report.thresholds.min_wsl && !wsl_installed,
    }
}

#[cfg(test)]
#[path = "flow_tests.rs"]
mod tests;
