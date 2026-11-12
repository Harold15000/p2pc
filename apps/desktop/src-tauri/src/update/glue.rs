// SPDX-License-Identifier: Apache-2.0

//! The Tauri glue of the updates (feature `app`): the updater plugin, the checks on a blocking thread, the background
//! loop of automatic checks, and the distro's upgrade. Every decision is made by the plain modules next to it; this file
//! only connects them to Tauri and to this PC.
//!
//! - **App update** (§14.1): Tauri's updater plugin with the compiled-in key and endpoint (`requireSignedVersion` in
//!   `tauri.conf.json`), then [`super::artifact::check_artifact`] on the downloaded bytes; the update is kept on disk
//!   ([`super::pending`]) and installed when the user agrees or at the next start, never in first run.
//! - **Template bundle** (§14.1, hub PC): [`super::templates::check_templates`]. Until the device connection lands
//!   (T2-30) the app cannot ask the hub which bundle it serves (`GET /v1/templates`), so it delivers none
//!   ([`HubTemplates::Unknown`]).
//! - **Web app** (§9.6): [`super::web::verify_web_app`] at the official origin, its mark kept in `update-state.json`.
//! - **Distro** (§14.2): [`super::distro::plan`], then `p2pc-wsl`'s upgrade with the pinned image, now or deferred.
//! - **Background** (hard rule 6): one thread wakes every hour; it checks only when [`policy::auto_check_due`] says so.

use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p2pc_wsl::Layout;
use p2pc_wsl::runner::{Host, SystemRunner, ThreadPause, in_distro, powershell};
use serde::Serialize;
use tauri::{AppHandle, Manager, Url};
use tauri_plugin_updater::{Updater, UpdaterExt};

use super::WslBundleSink;
use super::artifact::check_artifact;
use super::distro::{self, Choice, Deferral, DistroFacts, DistroPlan};
use super::fetch::HttpsGet;
use super::pending::PendingFiles;
use super::policy::{self, InstallMoment, UpdateState, UpdateStateFile};
use super::release::Release;
use super::signature::{ReleaseKey, UpdaterKey};
use super::templates::{HubTemplates, check_templates};
use super::web::{Offer, WebCheck, WebVerdict, verify_web_app};
use crate::core::CommandError;
use crate::setup::wsl_host::{AGENT_BIN, AGENT_CONFIG, compiled_image_pin};
use crate::state::Role;

/// The update requests' time limit (the check and the artifact's download).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);
/// How often the background thread wakes.
const LOOP_PERIOD: Duration = Duration::from_secs(3600);
/// A command run in the distro by these checks.
const IN_DISTRO_TIMEOUT: Duration = Duration::from_secs(60);
/// Reads the local time's offset from UTC, in seconds (for "Tonight at 03:00").
const UTC_OFFSET_SCRIPT: &str = "[int][System.TimeZoneInfo]::Local.GetUtcOffset([DateTime]::UtcNow).TotalSeconds";

/// The web app's last verdict, as the window shows it.
#[derive(Debug, Clone, Serialize)]
pub struct WebShown {
    pub origin: String,
    pub verdict: WebVerdict,
    pub messages: Vec<String>,
    pub offers: Vec<Offer>,
    pub warning: bool,
}

/// What the window shows about updates.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateView {
    /// This build has an update key and endpoint.
    pub configured: bool,
    pub update_checks: Option<bool>,
    pub last_check: Option<String>,
    pub notice: Option<String>,
    /// A downloaded update that passed the gate, by version.
    pub ready_to_install: Option<String>,
    pub web: Option<WebShown>,
    pub distro: Option<DistroPlan>,
    pub distro_deferred: bool,
    /// The last distro upgrade's failure, with the backup it kept.
    pub distro_error: Option<String>,
}

/// The updates' state, managed by Tauri.
pub struct Updates {
    release: Release,
    state_file: Option<UpdateStateFile>,
    pending: Option<PendingFiles>,
    ready: Mutex<Option<String>>,
    web: Mutex<Option<WebShown>>,
    distro: Mutex<Option<DistroPlan>>,
    deferral: Mutex<Option<Deferral>>,
    distro_error: Mutex<Option<String>>,
    busy: Mutex<bool>,
}

impl std::fmt::Debug for Updates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Updates").finish_non_exhaustive()
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn lock<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>, CommandError> {
    m.lock().map_err(|_| CommandError::Internal)
}

/// One check at a time.
struct Busy<'a>(&'a Mutex<bool>);

impl<'a> Busy<'a> {
    fn take(m: &'a Mutex<bool>) -> Result<Self, CommandError> {
        let mut b = lock(m)?;
        if *b {
            return Err(CommandError::Busy);
        }
        *b = true;
        Ok(Self(m))
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        if let Ok(mut b) = self.0.lock() {
            *b = false;
        }
    }
}

impl Updates {
    /// The updates of this app: its compiled-in release values and its local data folder.
    pub fn new(app: &AppHandle) -> Self {
        let local: Option<PathBuf> = app.path().app_local_data_dir().ok();
        let pending = local.as_deref().map(PendingFiles::in_dir);
        let ready = pending
            .as_ref()
            .and_then(PendingFiles::load)
            .and_then(|(answer, _)| answer.get("version").and_then(|v| v.as_str()).map(str::to_owned));
        Self {
            release: Release::compiled(),
            state_file: local.as_deref().map(UpdateStateFile::in_dir),
            pending,
            ready: Mutex::new(ready),
            web: Mutex::new(None),
            distro: Mutex::new(None),
            deferral: Mutex::new(None),
            distro_error: Mutex::new(None),
            busy: Mutex::new(false),
        }
    }

    fn state(&self) -> UpdateState {
        self.state_file.as_ref().map(UpdateStateFile::load).unwrap_or_default()
    }

    fn update_state(&self, change: impl FnOnce(&mut UpdateState)) {
        if let Some(f) = &self.state_file {
            let mut s = f.load();
            change(&mut s);
            if let Err(e) = f.save(&s) {
                tracing_free_warn(&format!("could not save the update state: {e}"));
            }
        }
    }

    /// The window's view.
    pub fn view(&self, update_checks: Option<bool>) -> Result<UpdateView, CommandError> {
        let state = self.state();
        Ok(UpdateView {
            configured: self.release.updater_pubkey.is_some() && self.release.update_endpoint.is_some(),
            update_checks,
            last_check: state.last_attempt.map(policy::date),
            notice: policy::notice(update_checks, &state, now()).map(|n| n.message()),
            ready_to_install: lock(&self.ready)?.clone(),
            web: lock(&self.web)?.clone(),
            distro: lock(&self.distro)?.clone(),
            distro_deferred: lock(&self.deferral)?.is_some(),
            distro_error: lock(&self.distro_error)?.clone(),
        })
    }
}

/// The app has no logger of its own yet: a warning goes to stderr (nothing secret is ever in one).
fn tracing_free_warn(text: &str) {
    eprintln!("p2pc: {text}");
}

/// The updater for this build's key and endpoint.
fn updater(app: &AppHandle, release: &Release) -> Result<Option<(Updater, UpdaterKey)>, CommandError> {
    let (Some(pk), Some(ep)) = (&release.updater_pubkey, &release.update_endpoint) else {
        return Ok(None);
    };
    let key = UpdaterKey::parse(pk).map_err(|_| CommandError::NotAvailable)?;
    let url = Url::parse(ep).map_err(|_| CommandError::NotAvailable)?;
    let updater = app
        .updater_builder()
        .pubkey(pk.clone())
        .timeout(REQUEST_TIMEOUT)
        .endpoints(vec![url])
        .and_then(|b| b.build())
        .map_err(|_| CommandError::NotAvailable)?;
    Ok(Some((updater, key)))
}

/// Checks the endpoint; a newer update is downloaded, gated and kept. `Ok(true)` when the endpoint answered.
async fn check_app(app: &AppHandle) -> Result<bool, CommandError> {
    let updates = app.state::<Updates>();
    let Some((updater, key)) = updater(app, &updates.release)? else {
        return Ok(false);
    };
    let Some(update) = updater.check().await.map_err(|_| CommandError::Failed)? else {
        return Ok(true);
    };
    if update.download_url.scheme() != "https" {
        return Ok(true);
    }
    let bytes = update
        .download(|_, _| {}, || {})
        .await
        .map_err(|_| CommandError::Failed)?;
    if let Err(refused) = check_artifact(
        &key,
        &bytes,
        &update.signature,
        &update.version,
        &Release::app_version(),
    ) {
        tracing_free_warn(&format!("update refused: {refused}"));
        return Ok(true);
    }
    if let Some(p) = &updates.pending
        && p.save(&update.raw_json, &bytes).is_ok()
    {
        *lock(&updates.ready)? = Some(update.version.clone());
    }
    Ok(true)
}

/// Installs the kept update: when the user agreed or at start, never in first run. The installer replaces this
/// process (`passive`). `Ok(false)` when there was nothing to install.
pub async fn install(app: &AppHandle, moment: InstallMoment, in_first_run: bool) -> Result<bool, CommandError> {
    if !policy::may_install(moment, in_first_run) {
        return Err(CommandError::NotAllowed);
    }
    let updates = app.state::<Updates>();
    let Some(files) = &updates.pending else {
        return Ok(false);
    };
    let Some((answer, bytes)) = files.load() else {
        return Ok(false);
    };
    let Some((updater, key)) = updater(app, &updates.release)? else {
        return Ok(false);
    };
    // Restored from the kept answer: the plugin requires its signed version, and the gate runs again.
    let restored = updater.restore_update(answer).ok().flatten();
    let Some(update) =
        restored.filter(|u| check_artifact(&key, &bytes, &u.signature, &u.version, &Release::app_version()).is_ok())
    else {
        files.clear();
        *lock(&updates.ready)? = None;
        return Ok(false);
    };
    files.clear();
    *lock(&updates.ready)? = None;
    update.install(&bytes).map_err(|_| CommandError::Failed)?;
    Ok(true)
}

/// Verifies the web app at the official origin (§9.6) and keeps the verdict and the mark.
pub async fn verify_web(app: &AppHandle) -> Result<WebShown, CommandError> {
    let updates = app.state::<Updates>();
    let release = updates.release.clone();
    let origin = release.web_origin.clone().ok_or(CommandError::NotAvailable)?;
    let stored = updates.state().web_mark;
    let checked_origin = origin.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let key = release
            .release_pubkey
            .as_deref()
            .and_then(|k| ReleaseKey::parse(k).ok());
        let own = release.own_web_version();
        let check = WebCheck {
            origin: &checked_origin,
            official_origin: release.web_origin.as_deref(),
            own_web_version: &own,
            stored_mark: stored.as_deref(),
            local_hub_version: None,
        };
        match HttpsGet::new() {
            Ok(fetch) => verify_web_app(&fetch, key.as_ref(), &check),
            Err(e) => super::web::WebResult {
                verdict: WebVerdict::Unreachable { reason: e.to_string() },
                new_mark: None,
            },
        }
    })
    .await
    .map_err(|_| CommandError::Internal)?;
    if let Some(mark) = &result.new_mark {
        updates.update_state(|s| s.web_mark = Some(mark.clone()));
    }
    let shown = WebShown {
        messages: result.verdict.messages(&origin),
        offers: result.verdict.offers(),
        warning: result.verdict.is_warning(),
        verdict: result.verdict,
        origin,
    };
    *lock(&updates.web)? = Some(shown.clone());
    Ok(shown)
}

/// On the hub PC: the template bundle (§14.1).
async fn check_bundle(app: &AppHandle) {
    let updates = app.state::<Updates>();
    let release = updates.release.clone();
    let Some(endpoint) = release.templates_endpoint.clone() else {
        return;
    };
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        let key = release
            .release_pubkey
            .as_deref()
            .and_then(|k| ReleaseKey::parse(k).ok());
        let fetch = HttpsGet::new().map_err(|e| e.to_string())?;
        let (runner, pause) = (SystemRunner, ThreadPause);
        let sink = WslBundleSink(Host::new(&runner, &pause));
        check_templates(&fetch, key.as_ref(), &endpoint, HubTemplates::Unknown, &sink).map_err(|e| e.to_string())
    })
    .await;
    if let Ok(Err(e)) = outcome {
        tracing_free_warn(&format!("template bundle: {e}"));
    }
}

/// What `p2pc-agent status --json` says that the distro decision needs: the hub's version and whether the agent runs.
fn agent_facts(host: Host<'_>) -> (Option<semver::Version>, bool) {
    let inv = in_distro(&[AGENT_BIN, "--config", AGENT_CONFIG, "status", "--json"]).timeout(IN_DISTRO_TIMEOUT);
    let Some(v) = host
        .run_wsl(&inv)
        .ok()
        .filter(|o| o.success())
        .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
    else {
        // Unknown: taken as running, so the user is asked rather than interrupted.
        return (None, true);
    };
    let hub = v
        .get("server_version")
        .and_then(|s| s.as_str())
        .and_then(|s| semver::Version::parse(s).ok());
    let running = v
        .get("agent_running")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    (hub, running)
}

/// The distro's facts and the decision (§14.2). `None` without a distro to manage.
fn read_distro_plan(release: &Release, role: Role) -> Option<(DistroPlan, bool)> {
    Layout::from_env()?;
    let pinned = release.image_version.clone()?;
    let (runner, pause) = (SystemRunner, ThreadPause);
    let host = Host::new(&runner, &pause);
    let version = host
        .run_wsl(&in_distro(&p2pc_wsl::import::VERIFY_VERSION).timeout(IN_DISTRO_TIMEOUT))
        .ok()
        .filter(|o| o.success())
        .and_then(|o| distro::parse_image_version(&o.stdout_text()));
    let (hub_version, work_running) = agent_facts(host);
    let facts = DistroFacts {
        role,
        distro_version: version,
        pinned,
        min_server_version: release.image_min_server_version.clone(),
        hub_version,
        work_running,
    };
    Some((distro::plan(&facts), work_running))
}

/// Reads the distro's plan and keeps it for the window.
pub async fn refresh_distro_plan(app: &AppHandle, role: Option<Role>) -> Result<Option<DistroPlan>, CommandError> {
    let updates = app.state::<Updates>();
    let Some(role) = role else {
        return Ok(None);
    };
    let release = updates.release.clone();
    let plan = tauri::async_runtime::spawn_blocking(move || read_distro_plan(&release, role).map(|(p, _)| p))
        .await
        .map_err(|_| CommandError::Internal)?;
    *lock(&updates.distro)? = plan.clone();
    Ok(plan)
}

/// A manual or automatic check: the app, the bundle (hub PC), the web app and the distro's plan.
pub async fn check_now(app: &AppHandle, role: Option<Role>) -> Result<(), CommandError> {
    let updates = app.state::<Updates>();
    let _busy = Busy::take(&updates.busy)?;
    let started = now();
    updates.update_state(|s| s.attempted(started));
    let reached = check_app(app).await.unwrap_or(false);
    if role == Some(Role::Hub) {
        check_bundle(app).await;
    }
    let _ = verify_web(app).await;
    let _ = refresh_distro_plan(app, role).await;
    if reached {
        updates.update_state(|s| s.succeeded(started));
    }
    Ok(())
}

fn utc_offset() -> i64 {
    let (runner, pause) = (SystemRunner, ThreadPause);
    Host::new(&runner, &pause)
        .run(&powershell(UTC_OFFSET_SCRIPT))
        .ok()
        .filter(|o| o.success())
        .and_then(|o| o.stdout_text().parse().ok())
        .unwrap_or(0)
}

/// The user's answer to "Update now / Tonight at 03:00 / Later". `Ok(true)` when the upgrade should run now.
pub async fn choose_distro_upgrade(app: &AppHandle, choice: Choice) -> Result<bool, CommandError> {
    let updates = app.state::<Updates>();
    // Only an upgrade the plan offers: never while a joined PC waits for its hub, never a downgrade.
    if !lock(&updates.distro)?.as_ref().is_some_and(may_upgrade) {
        return Err(CommandError::NotAllowed);
    }
    let offset = tauri::async_runtime::spawn_blocking(utc_offset).await.unwrap_or(0);
    let deferral = distro::defer(choice, now(), offset);
    if deferral.due(now(), false) && choice == Choice::Now {
        *lock(&updates.deferral)? = None;
        return Ok(true);
    }
    *lock(&updates.deferral)? = Some(deferral);
    Ok(false)
}

/// The plan lets the distro be upgraded (now, or at the user's chosen time).
fn may_upgrade(plan: &DistroPlan) -> bool {
    matches!(plan, DistroPlan::UpgradeNow | DistroPlan::Ask)
}

/// The upgrade itself (§8.3): the pinned image downloaded and verified, then `p2pc-wsl`'s state-preserving upgrade.
/// The caller puts the app in `updating` around it.
pub async fn run_distro_upgrade(app: &AppHandle) -> Result<(), CommandError> {
    let updates = app.state::<Updates>();
    let _busy = Busy::take(&updates.busy)?;
    let outcome = tauri::async_runtime::spawn_blocking(|| -> Result<(), String> {
        let layout = Layout::from_env().ok_or("not on Windows")?;
        let pin = compiled_image_pin().ok_or("this build has no node image pin")?;
        let fetch = p2pc_wsl::image::HttpFetcher::new().map_err(|e| e.to_string())?;
        let dest = layout
            .images_dir()
            .join(format!("p2pc-node-{}.tar.gz", &pin.sha256().to_hex()[..16]));
        std::fs::create_dir_all(layout.images_dir()).map_err(|e| e.to_string())?;
        let image = p2pc_wsl::image::download_image(&fetch, &pin, &dest, &mut |_| ControlFlow::Continue(()))
            .map_err(|e| e.to_string())?;
        let (runner, pause) = (SystemRunner, ThreadPause);
        let host = Host::new(&runner, &pause);
        let identity = p2pc_wsl::task::current_identity(host).map_err(|e| e.to_string())?;
        let ctx = p2pc_wsl::task::TaskContext {
            system_root: std::env::var_os("SystemRoot")
                .filter(|v| !v.is_empty())
                .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from),
            identity,
            start_boundary: p2pc_wsl::task::start_boundary(SystemTime::now()),
        };
        let mut opts = p2pc_wsl::upgrade::UpgradeOptions::new(SystemTime::now());
        opts.task = Some(&ctx);
        match p2pc_wsl::upgrade::upgrade(host, &layout, &image, &opts) {
            Ok(_) => {
                let _ = std::fs::remove_file(&dest);
                Ok(())
            }
            Err(f) => Err(match &f.kept_backup {
                Some(b) => format!("{} The backup of this PC's state was kept: {}", f.error, b.display()),
                None => f.error.to_string(),
            }),
        }
    })
    .await
    .map_err(|_| CommandError::Internal)?;
    *lock(&updates.deferral)? = None;
    *lock(&updates.distro_error)? = outcome.as_ref().err().cloned();
    outcome.map_err(|_| CommandError::Failed)
}

/// What the background thread asks the app each time it wakes.
#[derive(Debug, Clone, Copy)]
pub struct AppFacts {
    pub update_checks: Option<bool>,
    pub in_first_run: bool,
    pub role: Option<Role>,
}

/// Starts the background thread: the kept update at start (never in first run), then, every hour, the automatic check
/// when it is due (opt-in only), and the distro's plan (local: `wsl.exe` only). The distro is upgraded when the plan
/// says so with nothing running (§14.2: "as soon as it can"), or at the time the user chose. The image download that
/// upgrade needs is part of the app update the user installed. `facts` reads the app's state; `distro` runs the
/// distro's upgrade with the app in `updating`.
pub fn spawn_background<F, D>(app: AppHandle, facts: F, distro: D)
where
    F: Fn(&AppHandle) -> AppFacts + Send + 'static,
    D: Fn(&AppHandle) + Send + 'static,
{
    std::thread::spawn(move || {
        let start = facts(&app);
        let _ = tauri::async_runtime::block_on(install(&app, InstallMoment::AppStart, start.in_first_run));
        loop {
            let f = facts(&app);
            let state = app.state::<Updates>().state();
            if policy::auto_check_due(f.update_checks, f.in_first_run, &state, now()) {
                let _ = tauri::async_runtime::block_on(check_now(&app, f.role));
            }
            if let (Some(role), false) = (f.role, f.in_first_run) {
                let updates = app.state::<Updates>();
                let release = updates.release.clone();
                let read = read_distro_plan(&release, role);
                if let Ok(mut shown) = updates.distro.lock() {
                    *shown = read.as_ref().map(|(p, _)| p.clone());
                }
                let deferral = updates.deferral.lock().ok().and_then(|d| *d);
                // After a failed upgrade nothing is retried on its own: the user sees why, and tries again.
                let failed = updates.distro_error.lock().map_or(true, |e| e.is_some());
                let due = match (&read, deferral) {
                    _ if failed => false,
                    (Some((DistroPlan::UpgradeNow, _)), _) => true,
                    (Some((plan, running)), Some(d)) => may_upgrade(plan) && d.due(now(), *running),
                    _ => false,
                };
                if due {
                    distro(&app);
                }
            }
            std::thread::sleep(LOOP_PERIOD);
        }
    });
}
