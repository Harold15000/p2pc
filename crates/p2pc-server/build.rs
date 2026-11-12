// SPDX-License-Identifier: AGPL-3.0-only

//! Compiles the repository's `templates/` into the bundle the hub embeds (H2 spec §7.6: "The hub embeds the bundle
//! of its own release"), with the same compiler and the same rules as the release pipeline
//! (`scripts/templates-bundle`). A template that breaks a rule stops the build.
//!
//! Two build-time inputs, both optional:
//!
//! - `P2PC_TEMPLATES_RELEASE`: when set (to anything but `0` or the empty string), the release rules apply, so a
//!   placeholder image digest stops the build. The release pipeline sets it.
//! - `P2PC_RELEASE_PUBLIC_KEY`: the release key's public half (the base64 line of a minisign public key file), which
//!   `src/templates.rs` compiles in with `option_env!`. Checked here, so a hub is never built with a key it cannot
//!   parse. Without it the hub trusts no bundle file and serves its embedded bundle only.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use templates_bundle::bundle::compile_dir;
use templates_bundle::check::Mode;

const RELEASE_ENV: &str = "P2PC_TEMPLATES_RELEASE";
const KEY_ENV: &str = "P2PC_RELEASE_PUBLIC_KEY";

fn run() -> Result<(), String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").map_err(|e| format!("CARGO_MANIFEST_DIR: {e}"))?;
    let out_dir = std::env::var("OUT_DIR").map_err(|e| format!("OUT_DIR: {e}"))?;
    let templates = Path::new(&manifest_dir).join("../../templates");
    println!("cargo:rerun-if-changed={}", templates.display());
    println!("cargo:rerun-if-env-changed={RELEASE_ENV}");
    println!("cargo:rerun-if-env-changed={KEY_ENV}");

    let release = std::env::var(RELEASE_ENV).is_ok_and(|v| !v.is_empty() && v != "0");
    let mode = if release { Mode::Release } else { Mode::Dev };
    let (_, bytes) = compile_dir(&templates, mode).map_err(|e| format!("the template bundle does not compile: {e}"))?;
    let out = PathBuf::from(out_dir).join("templates.json");
    std::fs::write(&out, bytes).map_err(|e| format!("cannot write {}: {e}", out.display()))?;

    if let Ok(key) = std::env::var(KEY_ENV)
        && !key.is_empty()
    {
        minisign::PublicKey::from_base64(&key).map_err(|e| format!("{KEY_ENV} is not a minisign public key: {e}"))?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
