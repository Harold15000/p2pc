// SPDX-License-Identifier: Apache-2.0

//! The app's own commands, the only thing the main window may call (H2 §8.9).
//!
//! This file is shared with `build.rs` (through `#[path]`), which declares the list in Tauri's app manifest. With an
//! app manifest, Tauri checks every app command against the capabilities, so a command that is not in this list, or
//! not granted in `capabilities/main.json`, is refused at the IPC layer (fail closed). `capabilities::tests` checks
//! that the capability grants exactly this list. Keep it free of dependencies: `build.rs` compiles it on its own.

/// The commands, in snake case. Tauri's permission for each is `allow-<name with dashes>`.
pub const COMMANDS: &[&str] = &[
    // The state, tray colour, role and offered controls (§8.4).
    "status",
    // One of the offered controls of §8.4, by name.
    "control",
    // The app's settings.
    "settings",
    // Start at sign-in on or off (§8.1).
    "set_autostart",
    // First run (§8.2, T2-43): where it is and what the window shows.
    "setup_status",
    // Step 1: the update-check choice.
    "setup_welcome",
    // Step 2: the checks.
    "setup_checks",
    // Step 2a: install WSL (elevated).
    "setup_install_wsl",
    // Steps 2-3: the node image download, in the background.
    "setup_download",
    // Step 3: import the distro and measure the disk.
    "setup_prepare_node",
    // Step 3: apply the share.
    "setup_share",
    // Step 4: "Create my cloud".
    "setup_create_cloud",
    // Step 5: the pairing QR code.
    "setup_pair_phone",
    // Step 5: has the phone paired?
    "setup_phone_status",
    // Step 5: "Continue" or "Skip for now"; first run ends.
    "setup_finish_phone",
];
