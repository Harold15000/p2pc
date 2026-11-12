// SPDX-License-Identifier: Apache-2.0

//! Without the `app` feature this does nothing. With it, it runs `tauri-build` and declares the app's commands in
//! Tauri's app manifest: with a manifest, Tauri checks every app command against the capabilities (fail closed);
//! without one, it would let the window call any registered command.

#[cfg(feature = "app")]
#[path = "src/commands.rs"]
mod commands;

fn main() {
    #[cfg(feature = "app")]
    {
        let manifest = tauri_build::AppManifest::new().commands(commands::COMMANDS);
        if let Err(e) = tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest)) {
            eprintln!("tauri-build failed: {e:#}");
            std::process::exit(1);
        }
    }
}
