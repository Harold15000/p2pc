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
];
