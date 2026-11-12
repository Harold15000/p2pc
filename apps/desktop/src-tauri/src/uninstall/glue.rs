// SPDX-License-Identifier: Apache-2.0

//! The Tauri glue of the uninstall cleanup (feature `app`): `P2PC.exe --uninstall-cleanup` (§8.7).
//!
//! A separate, minimal app: one window on the bundled `uninstall.html`, the three uninstall commands and nothing else
//! (no tray, no single-instance plugin, no updater, no first run). The other app commands are not registered here, and
//! these three are not registered in the normal app, so the normal window can never start an uninstall. The process's
//! exit code is the cleanup's ([`super::exit`]): the NSIS hook goes on only on 0; closing the window before the cleanup
//! ran is a cancel.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::SystemTime;

use p2pc_wsl::Layout;
use p2pc_wsl::runner::{SystemRunner, ThreadPause};
use p2pc_wsl::uninstall::UninstallPlan;
use tauri::webview::NewWindowResponse;
use tauri::{AppHandle, Context, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent, Wry};

use super::host::WslCleanupHost;
use super::log::UninstallLog;
use super::{CleanupOutcome, Confirmation, UninstallView, UnwiredHubNodes, effective_role, exit, run_cleanup};
use crate::autostart;
use crate::capabilities::MAIN_WINDOW;
use crate::core::CommandError;
use crate::navigation::{self, Navigation};
use crate::setup::record::RecordFile;
use crate::state::Role;

/// The cleanup's page.
const PAGE: &str = "uninstall.html";

#[derive(Debug, Default)]
struct Cleanup {
    /// Done or stopped: the cleanup runs once.
    outcome: Mutex<Option<CleanupOutcome>>,
    running: Mutex<bool>,
}

impl Cleanup {
    fn exit_code(&self) -> u8 {
        match self.outcome.lock() {
            Ok(o) => o.as_ref().map_or(exit::CANCELLED, CleanupOutcome::exit_code),
            Err(_) => exit::STOPPED,
        }
    }

    fn running(&self) -> bool {
        self.running.lock().map(|r| *r).unwrap_or(true)
    }
}

fn role(layout: Option<&Layout>) -> Option<Role> {
    layout
        .and_then(|l| RecordFile::in_dir(l.root()).load().ok())
        .and_then(|r| r.role)
}

#[cfg(windows)]
fn run_keys() -> (
    Box<dyn autostart::RunKey + Send + Sync>,
    Box<dyn autostart::RunKey + Send + Sync>,
) {
    (
        Box::new(autostart::WindowsRunKey),
        Box::new(autostart::WindowsRunOnceKey),
    )
}

#[cfg(not(windows))]
fn run_keys() -> (
    Box<dyn autostart::RunKey + Send + Sync>,
    Box<dyn autostart::RunKey + Send + Sync>,
) {
    (Box::new(autostart::NoRunKey), Box::new(autostart::NoRunKey))
}

/// Runs the cleanup app; its exit code is the cleanup's.
pub fn run(context: Context<Wry>) -> ExitCode {
    let builder = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            uninstall_view,
            uninstall_run,
            uninstall_finish
        ])
        .setup(|app| {
            app.manage(Cleanup::default());
            build_window(app.handle())?;
            Ok(())
        });
    let Ok(app) = builder.build(context) else {
        return ExitCode::from(exit::STOPPED);
    };
    let code = app.run_return(|_, _| {});
    ExitCode::from(u8::try_from(code).unwrap_or(exit::STOPPED))
}

fn build_window(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == MAIN_WINDOW)
        .cloned()
        .ok_or("tauri.conf.json has no main window")?;
    config.url = WebviewUrl::App(PAGE.into());
    config.title = "Uninstall P2PC".to_owned();
    let window = WebviewWindowBuilder::from_config(app, &config)?
        .on_navigation(|url| navigation::decide(url) == Navigation::Allow)
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .build()?;
    let handle = app.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::CloseRequested { api, .. } = event {
            let cleanup = handle.state::<Cleanup>();
            if cleanup.running() {
                // Never interrupted halfway: the window stays until the cleanup ends.
                api.prevent_close();
            } else {
                handle.exit(i32::from(cleanup.exit_code()));
            }
        }
    });
    window.show()?;
    window.set_focus()?;
    Ok(())
}

/// The host the cleanup runs on (the app's folders are only needed by step 6).
fn cleanup_host(layout: Layout, app_dirs: Vec<PathBuf>) -> WslCleanupHost<SystemRunner, ThreadPause> {
    let (run, run_once) = run_keys();
    WslCleanupHost {
        runner: SystemRunner,
        pause: ThreadPause,
        layout,
        app_dirs,
        run,
        run_once,
    }
}

/// The confirmation: the hub PC's consequence and the kept backups. On a blocking thread: it may ask the distro.
#[tauri::command]
async fn uninstall_view() -> Result<UninstallView, CommandError> {
    tauri::async_runtime::spawn_blocking(|| {
        let Some(layout) = Layout::from_env() else {
            let none = UninstallPlan {
                backups_dir: PathBuf::new(),
                verified: Vec::new(),
                unfinished: Vec::new(),
            };
            return UninstallView::new(None, &none);
        };
        let plan = UninstallPlan::read(&layout);
        let recorded = role(Some(&layout));
        let host = cleanup_host(layout, Vec::new());
        UninstallView::new(effective_role(recorded, &host), &plan)
    })
    .await
    .map_err(|_| CommandError::Internal)
}

/// The cleanup, once, on a blocking thread.
#[tauri::command]
async fn uninstall_run(app: AppHandle, confirm: Confirmation) -> Result<CleanupOutcome, CommandError> {
    let cleanup = app.state::<Cleanup>();
    {
        let done = cleanup.outcome.lock().map_err(|_| CommandError::Internal)?;
        if let Some(o) = done.as_ref() {
            return Ok(o.clone());
        }
        let mut running = cleanup.running.lock().map_err(|_| CommandError::Internal)?;
        if *running {
            return Err(CommandError::Busy);
        }
        *running = true;
    }
    let path = app.path();
    let mut app_dirs: Vec<PathBuf> = [
        path.app_config_dir(),
        path.app_data_dir(),
        path.app_local_data_dir(),
        path.app_cache_dir(),
    ]
    .into_iter()
    .filter_map(Result::ok)
    .collect();
    app_dirs.sort();
    app_dirs.dedup();
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        let temp = std::env::temp_dir();
        let mut log = UninstallLog::create(&temp, SystemTime::now());
        let Some(layout) = Layout::from_env() else {
            log.line("stopped: %LOCALAPPDATA% is not set");
            return CleanupOutcome::Stopped {
                message: "This is not a Windows user session.".to_owned(),
                log: log.path_text(),
            };
        };
        let recorded = role(Some(&layout));
        let host = cleanup_host(layout, app_dirs);
        let role = effective_role(recorded, &host);
        run_cleanup(&host, &UnwiredHubNodes, &ThreadPause, &mut log, role, confirm)
    })
    .await
    .map_err(|_| CommandError::Internal);
    if let Ok(mut running) = cleanup.running.lock() {
        *running = false;
    }
    let outcome = outcome?;
    if outcome != CleanupOutcome::Cancelled
        && let Ok(mut done) = cleanup.outcome.lock()
    {
        *done = Some(outcome.clone());
    }
    Ok(outcome)
}

/// Closes the cleanup with its exit code (cancelled when it never ran).
#[tauri::command]
fn uninstall_finish(app: AppHandle) {
    let cleanup = app.state::<Cleanup>();
    if cleanup.running() {
        return;
    }
    let code = cleanup.exit_code();
    app.exit(i32::from(code));
}
