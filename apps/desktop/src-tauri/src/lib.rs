// SPDX-License-Identifier: Apache-2.0

//! The P2PC desktop app (H2 spec §8): a per-user Tauri 2 app that lives in the tray.
//!
//! This crate is the app shell (T2-42: §8.1, §8.4 states, §8.9). Everything except the Tauri glue is plain Rust,
//! built and tested without a webview toolkit:
//!
//! - [`state`]: the six states and the controls of §8.4, as a state machine that refuses illegal transitions;
//! - [`core`]: the window's commands over that machine, one control at a time, with the node actions behind a trait;
//! - [`tray`]: the tray's menu, tooltip and icons as data;
//! - [`settings`]: the app's settings file (start at sign-in, opt-out);
//! - [`autostart`]: the `HKCU\…\Run` entry behind a trait;
//! - [`launch`]: start in the window or in the tray, and what a second start does (single instance);
//! - [`keep_awake`]: "Keep this PC awake while sharing" (§8.6), `SetThreadExecutionState` behind a trait;
//! - [`keystore`]: the device key, DPAPI-protected in `%LOCALAPPDATA%\P2PC\device.key`;
//! - [`navigation`]: bundled pages only, web links to the system browser;
//! - [`commands`] and [`capabilities`]: the window's commands and the checks that pin the capability, the CSP and the
//!   plugin list.
//!
//! The Tauri glue (builder, tray, window, commands) is the `app` module, behind the cargo feature `app` (off by
//! default; see `apps/desktop/README.md`).

pub mod autostart;
pub mod capabilities;
pub mod commands;
pub mod core;
pub mod keep_awake;
pub mod keystore;
pub mod launch;
pub mod navigation;
pub mod settings;
pub mod setup;
pub mod state;
pub mod tray;

#[cfg(feature = "app")]
pub mod app;
