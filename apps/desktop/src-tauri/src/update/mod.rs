// SPDX-License-Identifier: Apache-2.0

//! Updates (H2 §14.1, §14.2, §9.6; task T2-45). Plain Rust, tested with fakes; the Tauri updater plugin is wired in the
//! `app` glue.
//!
//! - [`policy`]: opt-in automatic checks (at most daily, never in first run), the 14-day and 30-day notices, when a
//!   downloaded update may be installed, and `update-state.json`;
//! - [`artifact`]: the gate every app update passes (SI-H2-15): a valid signature, a signed version, the announced
//!   version, and newer than the app;
//! - [`templates`]: the template bundle's delivery into the distro on the hub PC (§14.1);
//! - [`web`]: the web app verification against its signed manifest, with its high-water mark (§9.6, SI-H2-22);
//! - [`distro`]: when and whether to upgrade the distro after the app updated (§14.2);
//! - [`pending`]: a downloaded update kept until it is installed;
//! - [`signature`]: minisign verification with the compiled-in keys; [`fetch`]: bounded HTTPS GETs; [`release`]: what a
//!   release build compiles in;
//! - `glue` (feature `app`): the updater plugin, the checks, the background thread and the distro's upgrade.

pub mod artifact;
pub mod distro;
pub mod fetch;
#[cfg(feature = "app")]
pub mod glue;
pub mod pending;
pub mod policy;
pub mod release;
pub mod signature;
pub mod templates;
pub mod web;

use p2pc_wsl::runner::Host;

/// The real [`templates::BundleSink`]: `p2pc-wsl`'s byte-exact write into the distro, through a temporary name.
#[derive(Debug)]
pub struct WslBundleSink<'a>(pub Host<'a>);

impl templates::BundleSink for WslBundleSink<'_> {
    fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        p2pc_wsl::upgrade::write_file_in_distro(self.0, bytes, templates::TEMPLATES_DIR, name)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use p2pc_wsl::image::Sha256Digest;
    use p2pc_wsl::runner::{CommandRunner, Invocation, Output, Pause, RunError};

    use super::templates::BundleSink;
    use super::*;

    /// Answers like a distro that keeps the bytes it was given.
    #[derive(Default)]
    struct Distro {
        calls: Mutex<Vec<Invocation>>,
        part: Mutex<Vec<u8>>,
    }

    impl CommandRunner for Distro {
        fn run(&self, inv: &Invocation) -> Result<Output, RunError> {
            self.calls.lock().unwrap().push(inv.clone());
            let args = inv.arguments();
            if let Some(bytes) = inv.stdin_bytes() {
                *self.part.lock().unwrap() = bytes.to_vec();
            }
            if args.iter().any(|a| a == "/usr/bin/sha256sum") {
                let hex = Sha256Digest::of(&self.part.lock().unwrap()).to_hex();
                return Ok(Output::with(0, format!("{hex}  x\n")));
            }
            Ok(Output::with(0, ""))
        }
    }

    struct NoPause;
    impl Pause for NoPause {
        fn sleep(&self, _: Duration) {}
    }

    #[test]
    fn the_bundle_goes_to_the_hub_s_templates_directory_on_stdin() {
        let distro = Distro::default();
        let sink = WslBundleSink(Host::new(&distro, &NoPause));
        sink.write("templates.json", b"{\"bundle_version\":5}").unwrap();
        let calls = distro.calls.lock().unwrap();
        let mv = calls.last().unwrap();
        assert_eq!(
            &mv.arguments()[5..],
            [
                "/bin/mv",
                "-f",
                "/var/lib/p2pc-server/templates/.templates.json.p2pc-part",
                "/var/lib/p2pc-server/templates/templates.json"
            ]
        );
        assert!(calls.iter().all(|i| i.program() == "wsl.exe"));
        assert!(
            calls
                .iter()
                .any(|i| i.stdin_bytes() == Some(&b"{\"bundle_version\":5}"[..]))
        );
    }
}
