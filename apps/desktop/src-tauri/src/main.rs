// SPDX-License-Identifier: Apache-2.0

// No console window on Windows in release builds (a tray app).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! `P2PC.exe`: the desktop app. Built only with the `app` feature.

fn main() -> std::process::ExitCode {
    p2pc_desktop::app::run()
}
