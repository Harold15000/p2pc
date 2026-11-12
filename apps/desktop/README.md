# apps/desktop

The P2PC desktop app (H2 spec §8): a per-user Tauri 2 app for Windows 11 with the tray, first run, the states and
controls, the install of the `p2pc-node` WSL2 distro (through `crates/p2pc-wsl`), the join flow, updates and uninstall.

## Layout

- `src-tauri/`: the Rust crate `p2pc-desktop` (its own Cargo workspace, excluded from the root one; lock file
  `src-tauri/Cargo.lock`).
  - Plain Rust, built and tested anywhere: `state` (§8.4 states and controls), `core` (the window's commands over
    them), `tray` (menu, tooltip, icons as data), `settings`, `autostart` (`HKCU\…\Run` and `RunOnce`), `launch`
    (single instance, start in the tray at sign-in), `keystore` (the DPAPI-protected device key, §8.9), `navigation`
    (bundled pages only, links to the system browser), `commands` and `capabilities` (the checks that pin the
    capability, the CSP and the plugin list), `setup/` (first run, §8.2: the flow, `setup.json`, the disk
    arithmetic, the §8.8 errors, the WSL host over `crates/p2pc-wsl`, the hub API trait), `update/` (§14, §9.6: the
    update policy, the artifact gate, the web app verification, the template bundle's delivery, the distro's upgrade
    plan) and `uninstall/` (§8.7: the cleanup the uninstaller runs).
  - The Tauri glue, `src/app.rs` and `src/main.rs`, behind the cargo feature **`app`** (off by default).
  - `tauri.conf.json`, `capabilities/main.json` (the main window gets the app's own commands only), `icons/`
    (placeholders written by `icons/generate.py`), `nsis/hooks.nsh` (the uninstaller runs the cleanup, never during
    an update).
- `ui/`: a placeholder window until the web app build (`apps/web`, T2-31) replaces it (`build.frontendDist`): plain
  HTML and JS modules with no build step. `ui/setup.js` shows first run over the `setup_*` commands; the web app's
  `apps/web/src/desktop/` pages replace it and call the same commands with the same JSON (`SetupView` in
  `src/setup/flow.rs`).
- `check.sh`: the crate's gates. CI does not run them (the workspace gates stay green without a webview toolkit).
  `cargo deny` checks licenses, bans and sources on every target, and advisories on Windows only: Tauri's Linux
  stack (GTK, D-Bus through `zbus` 5) brings four "unmaintained" notices with no known vulnerability
  (RUSTSEC-2024-0370, RUSTSEC-2026-0370, -0371, -0372), which the root `deny.toml` does not ignore.

## Checks

```sh
apps/desktop/check.sh          # fmt, clippy, tests, cargo-deny; no webview toolkit needed
apps/desktop/check.sh --app    # plus clippy, tests and a build with the `app` feature
```

Without the webview toolkit, the `app` glue can still be type-checked and linted (nothing is linked): put a
`pkg-config` that answers every query on `PATH` and run
`cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets --features app -- -D warnings`.

## Building the app

Needs the Rust toolchain of `rust-toolchain.toml` and the Tauri 2 prerequisites: on Linux the WebKitGTK 4.1, GTK 3,
libappindicator (or libayatana-appindicator) and librsvg development packages; on Windows WebView2 (in Windows 11)
and the MSVC build tools. The Tauri CLI is only needed for the installer.

```sh
# Debug build and run, from the repository root (any OS with the prerequisites):
CARGO_TARGET_DIR=target/desktop cargo run --manifest-path apps/desktop/src-tauri/Cargo.toml --features app

# Windows installer (NSIS, per-user), from apps/desktop/src-tauri:
cargo install tauri-cli --version "^2" --locked
cargo tauri build --features app
```

What to expect in this version (T2-42, T2-43):

- The app starts in the state `setup` with a **grey** tray icon and shows first run (§8.2): the welcome and its
  update-check choice (nothing preselected), the checks (with the elevated WSL install and its one reboot), the image
  download, the import and the share, then "Create my cloud" and "Add my phone". Its progress is in
  `%LOCALAPPDATA%\P2PC\setup.json`: a closed window, a crash or the reboot resumes at the first unfinished step.
- Not wired yet: the node image pin (set at build time with `P2PC_NODE_IMAGE_URL` and `P2PC_NODE_IMAGE_SHA256`, which
  the release pipeline, T2-52, provides; without them the download says it is not available), and the hub API over the
  app's device connection (`p2pc-device`, T2-30): "Create my cloud" stops at naming the hub with "not available in this
  version", and "Add my phone" can only be skipped. "Join my cloud" is T2-44.
- Started by hand, it opens the window "P2PC" (the placeholder). Started with `--autostart` (the `Run` entry), it
  stays in the tray. Any other argument: it exits with code 2.
- Closing the window hides it; the tray icon stays. A left click on the tray icon (Windows) or "Open P2PC" in its
  menu shows the window again. "Quit" ends the app.
- Starting the app a second time does not start a second process: the running one shows its window.
- The tray menu shows "P2PC: Setting up", then "Open P2PC" and "Quit". The controls of §8.4 appear only once first
  run has finished.
- Settings: "Start P2PC when I sign in" is on by default and writes
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\P2PC` = `"<path>\P2PC.exe" --autostart`; turning it off
  deletes that value. On Linux the switch reports that it is not available.
- The window cannot navigate away from the bundled page; web links open in the system browser.
- Updates (T2-45): Settings has "Check for updates and verify the web app automatically", "Check for updates",
  "Verify web app" and, once an update passed its checks, "Install". A build without the release values
  (`P2PC_UPDATER_PUBKEY`, `P2PC_UPDATE_ENDPOINT`, `P2PC_RELEASE_PUBKEY`, `P2PC_TEMPLATES_ENDPOINT`,
  `P2PC_WEB_ORIGIN`, `P2PC_WEB_VERSION`, `P2PC_NODE_IMAGE_VERSION`, `P2PC_NODE_IMAGE_MIN_SERVER_VERSION`; see
  `src/update/release.rs`) checks nothing. Without the user's yes the app never contacts the update endpoint by
  itself.
- Uninstall (T2-45): Windows' "Uninstall" runs `P2PC.exe --uninstall-cleanup`, which asks first (on the hub PC with
  an explicit checkbox), then removes the node and logs each step to `%TEMP%\p2pc-uninstall-<time>.log`. Cancelling
  stops the uninstall. An app update never runs it.

Filled by:

- T2-42: the Tauri app shell (§8.1, §8.4, §8.9).
- T2-43: first run (`setup/`, §8.2).
- T2-44: the join flow (`invite/`, §5.4).
- T2-45: updates and uninstall (`update/`, `uninstall/`, §8.7, §14.1).
