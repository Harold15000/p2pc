# apps/desktop

The P2PC desktop app (H2 spec §8): a per-user Tauri 2 app for Windows 11 with the tray, first run, the states and
controls, the install of the `p2pc-node` WSL2 distro (through `crates/p2pc-wsl`), the join flow, updates and uninstall.

## Layout

- `src-tauri/`: the Rust crate `p2pc-desktop` (its own Cargo workspace, excluded from the root one; lock file
  `src-tauri/Cargo.lock`).
  - Plain Rust, built and tested anywhere: `state` (§8.4 states and controls), `core` (the window's commands over
    them), `tray` (menu, tooltip, icons as data), `settings`, `autostart` (`HKCU\…\Run`), `launch` (single instance,
    start in the tray at sign-in), `keystore` (the DPAPI-protected device key, §8.9), `navigation` (bundled pages only,
    links to the system browser), `commands` and `capabilities` (the checks that pin the capability, the CSP and the
    plugin list).
  - The Tauri glue, `src/app.rs` and `src/main.rs`, behind the cargo feature **`app`** (off by default).
  - `tauri.conf.json`, `capabilities/main.json` (the main window gets the app's own commands only), `icons/`
    (placeholders written by `icons/generate.py`).
- `ui/`: a placeholder window until the web app build (`apps/web`, T2-31) replaces it (`build.frontendDist`).
- `check.sh`: the crate's gates. CI does not run them (the workspace gates stay green without a webview toolkit).
  `cargo deny` checks licenses, bans and sources on every target, and advisories on Windows only: Tauri's Linux
  stack (GTK, D-Bus through `zbus` 5) brings four "unmaintained" notices with no known vulnerability
  (RUSTSEC-2024-0370, RUSTSEC-2026-0370, -0371, -0372), which the root `deny.toml` does not ignore.

## Checks

```sh
apps/desktop/check.sh          # fmt, clippy, tests, cargo-deny; no webview toolkit needed
apps/desktop/check.sh --app    # plus clippy, tests and a build with the `app` feature
```

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

What to expect in this version (T2-42):

- The app starts in the state `setup` with a **grey** tray icon; first run is T2-43, so it stays there.
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

Filled by:

- T2-42: the Tauri app shell (§8.1, §8.4, §8.9).
- T2-43: first run (`setup/`, §8.2).
- T2-44: the join flow (`invite/`, §5.4).
- T2-45: updates and uninstall (`update/`, `uninstall/`, §8.7, §14.1).
