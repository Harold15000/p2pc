// SPDX-License-Identifier: Apache-2.0

//! The Tauri glue (feature `app`): the builder, the single-instance plugin, the main window and its navigation guard,
//! the tray, and the window's commands. Every decision is made by the plain modules of this crate; this module only
//! connects them to Tauri.
//!
//! - **Single instance** (§8.1): the plugin is registered first; a second start hands its arguments to this process,
//!   which shows its window ([`crate::launch::second_instance`]), and exits.
//! - **Tray** (§8.1, §8.4): built in Rust from [`crate::tray`]; its icon, tooltip and menu are redrawn after every
//!   state change. Closing the window hides it; the app keeps running in the tray until "Quit". Quitting does not stop
//!   the node (the scheduled task runs it, §8.5).
//! - **Window** (§8.9): created in Rust from `tauri.conf.json` (`create: false`) so that the navigation guard
//!   ([`crate::navigation`]) is installed before it loads anything; `window.open` never opens a window.
//! - **Autostart** (§8.1): the `Run` entry is reconciled with the setting at every start and on every change.
//! - **Commands** (§8.9): [`crate::commands::COMMANDS`], each validating its arguments in Rust.
//! - **First run** (§8.2, T2-43): [`crate::setup`]'s flow over the real WSL host (`%LOCALAPPDATA%\P2PC`), the
//!   DPAPI device key and, until T2-30 lands, the unwired hub API. Its commands run on a blocking thread; the app
//!   starts in `setup` until `setup.json` says first run has finished.

use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, MutexGuard};

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::webview::NewWindowResponse;
use tauri::{AppHandle, Manager, RunEvent, State, Url, WebviewWindow, WebviewWindowBuilder, WindowEvent, Wry};

use crate::autostart::{self, AutostartError};
use crate::capabilities::MAIN_WINDOW;
use crate::core::{CommandError, ControlError, Core, NodeControl, StatusView, Unwired};
use crate::launch::{self, Launch, SecondInstance};
use crate::navigation::{self, Navigation};
use crate::settings::{Settings, SettingsFile, Startup, startup};
use crate::setup::flow::{Setup, SetupView, ShareRequest};
use crate::setup::host::{SetupHost, UnavailableHost};
use crate::setup::hub::{NoDevice, OwnerDevice, UnwiredHub};
use crate::setup::record::RecordFile;
use crate::setup::starting_machine;
use crate::setup::wsl_host::{WslHost, WslHostParts, compiled_image_pin};
use crate::state::{Event, Machine};
use crate::tray::{self as tray_model, Effect, ICON_SIZE, MenuEntry};

/// The tray icon's id.
const TRAY_ID: &str = "main";

/// The `HKCU\…\Run` key of this OS.
#[cfg(windows)]
static RUN_KEY: autostart::WindowsRunKey = autostart::WindowsRunKey;
#[cfg(not(windows))]
static RUN_KEY: autostart::NoRunKey = autostart::NoRunKey;

/// The app's state, managed by Tauri.
struct Shared {
    core: Mutex<Core>,
    settings: Mutex<Settings>,
    /// `None` when the OS gives no config folder: settings then live in memory only.
    settings_file: Option<SettingsFile>,
    node: Arc<dyn NodeControl>,
    /// First run (§8.2).
    setup: Arc<Setup>,
}

impl Shared {
    fn core(&self) -> Result<MutexGuard<'_, Core>, CommandError> {
        self.core.lock().map_err(|_| CommandError::Internal)
    }

    fn settings(&self) -> Result<MutexGuard<'_, Settings>, CommandError> {
        self.settings.lock().map_err(|_| CommandError::Internal)
    }
}

/// Starts the app. Exit code 2 for unknown arguments, 1 if Tauri cannot start.
pub fn run() -> ExitCode {
    let args = std::env::args_os().skip(1).map(|a| a.to_string_lossy().into_owned());
    let Ok(launch) = launch::parse(args) else {
        return ExitCode::from(2);
    };
    let builder = tauri::Builder::default()
        // First, so that a second start hands over and exits before anything else runs.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if launch::second_instance(argv.as_slice()) == SecondInstance::ShowWindow {
                show_main(app);
            }
        }))
        .invoke_handler(tauri::generate_handler![
            status,
            control,
            settings,
            set_autostart,
            setup_status,
            setup_welcome,
            setup_checks,
            setup_install_wsl,
            setup_download,
            setup_prepare_node,
            setup_share,
            setup_create_cloud,
            setup_pair_phone,
            setup_phone_status,
            setup_finish_phone
        ])
        .setup(move |app| setup(app, launch));
    let Ok(app) = builder.build(tauri::generate_context!()) else {
        return ExitCode::FAILURE;
    };
    app.run(|app, event| match event {
        // Closing the window is not quitting: the app stays in the tray. Only "Quit" (an explicit exit, which has an
        // exit code) ends the process.
        RunEvent::ExitRequested { code: None, api, .. } => api.prevent_exit(),
        // Quitting closes step 5's QR screen too: its pairing ticket is revoked (§5.2), best effort, before the
        // process ends.
        RunEvent::Exit => {
            if let Some(shared) = app.try_state::<Shared>() {
                let _ = shared.setup.close_pairing();
            }
        }
        _ => {}
    });
    ExitCode::SUCCESS
}

fn setup(app: &mut tauri::App, launch: Launch) -> Result<(), Box<dyn Error>> {
    let settings_file = app.path().app_config_dir().ok().map(|dir| SettingsFile::in_dir(&dir));
    let Startup { settings, trusted } = startup(settings_file.as_ref());
    // Only the user's own settings may change the Run entry: a damaged or unreadable file (defaults as a fallback)
    // must not undo an opt-out. Best effort: a refused registry write must not keep the app from starting; Settings
    // shows the stored choice and the next start tries again.
    if trusted {
        let _ = reconcile_autostart(settings.autostart);
    }
    let first_run = Arc::new(build_setup());
    // `setup` until `setup.json` says first run has finished, then `sharing` with the recorded role.
    let machine = first_run
        .record()
        .map(|r| starting_machine(&r))
        .unwrap_or_else(|_| Machine::new());
    app.manage(Shared {
        core: Mutex::new(Core::new(machine)),
        settings: Mutex::new(settings),
        settings_file,
        node: Arc::new(Unwired),
        setup: first_run,
    });
    let window = build_main_window(app.handle())?;
    build_tray(app.handle())?;
    if launch == Launch::Window {
        window.show()?;
        window.set_focus()?;
    }
    Ok(())
}

// --- First run ---

/// First run over this PC: the real WSL host under `%LOCALAPPDATA%\P2PC`, or, without it (not Windows) or without an
/// HTTP client, a host that refuses every action. The hub API is unwired until the device connection (T2-30) lands.
fn build_setup() -> Setup {
    let layout = p2pc_wsl::Layout::from_env();
    let file = layout.as_ref().map(|l| RecordFile::in_dir(l.root()));
    let device = owner_device(layout.as_ref());
    let host: Arc<dyn SetupHost> = match (layout, p2pc_wsl::image::HttpFetcher::new()) {
        (Some(layout), Ok(fetch)) => Arc::new(WslHost::new(WslHostParts {
            runner: p2pc_wsl::runner::SystemRunner,
            pause: p2pc_wsl::runner::ThreadPause,
            fetch: Box::new(fetch),
            run_once: Box::new(RUN_ONCE_KEY),
            layout,
            pin: compiled_image_pin(),
            exe: std::env::current_exe().ok(),
            system_root: std::env::var_os("SystemRoot")
                .filter(|v| !v.is_empty())
                .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from),
        })),
        _ => Arc::new(UnavailableHost),
    };
    Setup::load(host, Arc::new(UnwiredHub), device, file)
}

/// The `HKCU\…\RunOnce` key of this OS (first-run step 2a).
#[cfg(windows)]
const RUN_ONCE_KEY: autostart::WindowsRunOnceKey = autostart::WindowsRunOnceKey;
#[cfg(not(windows))]
const RUN_ONCE_KEY: autostart::NoRunKey = autostart::NoRunKey;

/// The app's device key, DPAPI-protected in `%LOCALAPPDATA%\P2PC\device.key` (§8.9).
#[cfg(windows)]
fn owner_device(layout: Option<&p2pc_wsl::Layout>) -> Arc<dyn OwnerDevice> {
    use crate::keystore::{DEVICE_KEY_FILE, Dpapi, FileKeyStore};
    use crate::setup::hub::StoredDevice;
    match layout {
        Some(l) => Arc::new(StoredDevice::new(FileKeyStore::new(
            l.root().join(DEVICE_KEY_FILE),
            Dpapi,
        ))),
        None => Arc::new(NoDevice),
    }
}

#[cfg(not(windows))]
fn owner_device(_: Option<&p2pc_wsl::Layout>) -> Arc<dyn OwnerDevice> {
    Arc::new(NoDevice)
}

fn reconcile_autostart(enabled: bool) -> Result<(), AutostartError> {
    let exe = std::env::current_exe().map_err(|_| AutostartError::UnusablePath)?;
    autostart::reconcile(&RUN_KEY, enabled, &exe).map(|_| ())
}

// --- Window ---

fn build_main_window(app: &AppHandle) -> Result<WebviewWindow, Box<dyn Error>> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == MAIN_WINDOW)
        .cloned()
        .ok_or("tauri.conf.json has no main window")?;
    let window = WebviewWindowBuilder::from_config(app, &config)?
        .on_navigation(|url| match navigation::decide(url) {
            Navigation::Allow => true,
            Navigation::OpenInBrowser => {
                open_in_browser(url);
                false
            }
            Navigation::Deny => false,
        })
        .on_new_window(|url, _features| {
            if navigation::decide(&url) == Navigation::OpenInBrowser {
                open_in_browser(&url);
            }
            NewWindowResponse::Deny
        })
        .build()?;
    let to_hide = window.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::CloseRequested { api, .. } = event {
            api.prevent_close();
            let _ = to_hide.hide();
            // The QR screen of first-run step 5 closes with the window: its pairing ticket is revoked (§5.2), off the
            // UI thread, best effort.
            if let Some(shared) = to_hide.app_handle().try_state::<Shared>() {
                let setup = Arc::clone(&shared.setup);
                tauri::async_runtime::spawn_blocking(move || {
                    let _ = setup.close_pairing();
                });
            }
        }
    });
    Ok(window)
}

/// Opens a web link in the system browser. Only URLs [`navigation::decide`] classified as web links reach here. The
/// opener plugin is used from Rust only: it is not registered with the webview, which gets none of its commands.
fn open_in_browser(url: &Url) {
    let _ = tauri_plugin_opener::open_url(url.as_str(), None::<&str>);
}

fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

// --- Tray ---

fn current_machine(app: &AppHandle) -> Machine {
    let Some(shared) = app.try_state::<Shared>() else {
        return Machine::new();
    };
    match shared.core.lock() {
        Ok(core) => core.machine().clone(),
        Err(_) => Machine::new(),
    }
}

fn tray_icon(machine: &Machine) -> Image<'static> {
    Image::new_owned(
        tray_model::icon_rgba(machine.state().tray_color()),
        ICON_SIZE,
        ICON_SIZE,
    )
}

fn build_menu(app: &AppHandle, machine: &Machine) -> tauri::Result<Menu<Wry>> {
    let menu = Menu::new(app)?;
    for entry in tray_model::menu(machine) {
        match entry {
            MenuEntry::Text(text) => menu.append(&MenuItem::new(app, text, false, None::<&str>)?)?,
            MenuEntry::Separator => menu.append(&PredefinedMenuItem::separator(app)?)?,
            MenuEntry::Item { action, label } => {
                menu.append(&MenuItem::with_id(app, action.id(), label, true, None::<&str>)?)?
            }
        }
    }
    Ok(menu)
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let machine = current_machine(app);
    let menu = build_menu(app, &machine)?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(tray_icon(&machine))
        .tooltip(tray_model::tooltip(&machine))
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| on_menu(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

fn refresh_tray(app: &AppHandle) {
    let machine = current_machine(app);
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    let _ = tray.set_icon(Some(tray_icon(&machine)));
    let _ = tray.set_tooltip(Some(tray_model::tooltip(&machine)));
    if let Ok(menu) = build_menu(app, &machine) {
        let _ = tray.set_menu(Some(menu));
    }
}

fn on_menu(app: &AppHandle, id: &str) {
    match tray_model::on_menu(&current_machine(app), id) {
        Effect::ShowWindow => show_main(app),
        Effect::Confirm(control) => {
            // The window asks on its next `status` (it refreshes when it gets the focus).
            if let Some(shared) = app.try_state::<Shared>()
                && let Ok(mut core) = shared.core.lock()
            {
                core.ask_confirmation(control);
            }
            show_main(app);
        }
        Effect::Quit => app.exit(0),
        Effect::RunControl(control) => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                // The outcome shows in the tray (redrawn either way) and in the window's next `status`.
                let _ = run_control(&app, control.as_str()).await;
            });
        }
        Effect::Nothing => {}
    }
}

// --- Commands (crate::commands::COMMANDS) ---

/// Runs a control: validate and reserve under the lock, run the node action on a blocking thread without it, then
/// apply the transition under the lock (see [`Core`]).
async fn run_control(app: &AppHandle, name: &str) -> Result<StatusView, CommandError> {
    let shared = app.state::<Shared>();
    let ticket = shared.core()?.begin(name)?;
    let (control, role) = (ticket.control(), ticket.role());
    let node = Arc::clone(&shared.node);
    let outcome = tauri::async_runtime::spawn_blocking(move || node.run(control, role))
        .await
        .unwrap_or(Err(ControlError::Failed));
    let view = shared.core()?.finish(ticket, outcome);
    refresh_tray(app);
    view
}

#[tauri::command]
fn status(shared: State<'_, Shared>) -> Result<StatusView, CommandError> {
    Ok(shared.core()?.take_status())
}

#[tauri::command]
async fn control(app: AppHandle, name: String) -> Result<StatusView, CommandError> {
    run_control(&app, &name).await
}

#[tauri::command]
fn settings(shared: State<'_, Shared>) -> Result<Settings, CommandError> {
    Ok(shared.settings()?.clone())
}

/// Async, with the registry write and the file's `fsync` on a blocking thread: a sync command would run them on the
/// main (UI) thread.
#[tauri::command]
async fn set_autostart(app: AppHandle, enabled: bool) -> Result<Settings, CommandError> {
    tauri::async_runtime::spawn_blocking(move || apply_autostart(&app, enabled))
        .await
        .unwrap_or(Err(CommandError::Failed))
}

/// Writes the `Run` entry, then the settings file. The settings lock is held throughout, so two toggles never
/// interleave.
fn apply_autostart(app: &AppHandle, enabled: bool) -> Result<Settings, CommandError> {
    let shared = app.state::<Shared>();
    let mut current = shared.settings()?;
    reconcile_autostart(enabled).map_err(|e| match e {
        AutostartError::Unsupported => CommandError::NotAvailable,
        AutostartError::UnusablePath | AutostartError::Registry(_) => CommandError::Failed,
    })?;
    let mut next = current.clone();
    next.autostart = enabled;
    if let Some(file) = &shared.settings_file {
        file.save(&next).map_err(|_| CommandError::Failed)?;
    }
    *current = next.clone();
    Ok(next)
}

/// Changes one setting and writes the file, under the settings lock (as [`apply_autostart`]).
fn save_setting(app: &AppHandle, change: impl FnOnce(&mut Settings)) -> Result<Settings, CommandError> {
    let shared = app.state::<Shared>();
    let mut current = shared.settings()?;
    let mut next = current.clone();
    change(&mut next);
    if let Some(file) = &shared.settings_file {
        file.save(&next).map_err(|_| CommandError::Failed)?;
    }
    *current = next.clone();
    Ok(next)
}

// --- First-run commands (§8.2). Every one but `setup_status` waits for `wsl.exe` or the hub: a blocking thread. ---

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, CommandError> + Send + 'static,
) -> Result<T, CommandError> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .unwrap_or(Err(CommandError::Failed))
}

fn first_run(app: &AppHandle) -> Arc<Setup> {
    Arc::clone(&app.state::<Shared>().setup)
}

#[tauri::command]
fn setup_status(shared: State<'_, Shared>) -> Result<SetupView, CommandError> {
    shared.setup.view()
}

#[tauri::command(rename_all = "snake_case")]
async fn setup_welcome(app: AppHandle, update_checks: bool) -> Result<SetupView, CommandError> {
    let s = first_run(&app);
    let view = blocking(move || s.welcome(update_checks)).await?;
    // Settings shows the same toggle (§8.2 step 1). `setup.json` already holds the choice; a settings file that
    // cannot be written keeps it in memory until the next change.
    let app2 = app.clone();
    let _ = blocking(move || save_setting(&app2, |s| s.update_checks = Some(update_checks))).await;
    Ok(view)
}

#[tauri::command]
async fn setup_checks(app: AppHandle) -> Result<SetupView, CommandError> {
    let s = first_run(&app);
    blocking(move || s.run_checks()).await
}

#[tauri::command]
async fn setup_install_wsl(app: AppHandle) -> Result<SetupView, CommandError> {
    let s = first_run(&app);
    blocking(move || s.install_wsl()).await
}

/// `retry` is the user's "Try again": only then is an image that failed its hash check downloaded again (§8.8).
#[tauri::command]
async fn setup_download(app: AppHandle, retry: bool) -> Result<SetupView, CommandError> {
    let s = first_run(&app);
    blocking(move || s.download_image(retry)).await
}

/// `retry` as for `setup_download`.
#[tauri::command]
async fn setup_prepare_node(app: AppHandle, retry: bool) -> Result<SetupView, CommandError> {
    let s = first_run(&app);
    blocking(move || s.prepare_node(retry)).await
}

#[tauri::command(rename_all = "snake_case")]
async fn setup_share(app: AppHandle, request: ShareRequest, keep_awake: bool) -> Result<SetupView, CommandError> {
    let s = first_run(&app);
    let view = blocking(move || s.apply_share(request)).await?;
    if view.error.is_none() {
        let app2 = app.clone();
        let _ = blocking(move || save_setting(&app2, |s| s.keep_awake = keep_awake)).await;
    }
    Ok(view)
}

#[tauri::command]
async fn setup_create_cloud(app: AppHandle) -> Result<SetupView, CommandError> {
    let s = first_run(&app);
    blocking(move || s.create_cloud()).await
}

#[tauri::command]
async fn setup_pair_phone(app: AppHandle) -> Result<SetupView, CommandError> {
    let s = first_run(&app);
    blocking(move || s.pair_phone()).await
}

#[tauri::command]
async fn setup_phone_status(app: AppHandle) -> Result<SetupView, CommandError> {
    let s = first_run(&app);
    blocking(move || s.phone_status()).await
}

/// Ends step 5; when first run has finished, the app leaves `setup` for `sharing` (§8.4 "setup done").
#[tauri::command]
async fn setup_finish_phone(app: AppHandle) -> Result<SetupView, CommandError> {
    let s = first_run(&app);
    let (view, role) = blocking(move || s.finish_phone()).await?;
    if let Some(role) = role {
        {
            let shared = app.state::<Shared>();
            let mut core = shared.core()?;
            let _ = core.apply(Event::SetupDone(role));
        }
        refresh_tray(&app);
    }
    Ok(view)
}
