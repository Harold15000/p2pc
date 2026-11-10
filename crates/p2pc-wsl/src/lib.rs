// SPDX-License-Identifier: Apache-2.0

//! WSL management for the P2PC desktop app (H2 spec §4.1 and §8.3).
//!
//! A Windows-only library (the checks and the distro operations will be gated on `cfg(windows)` by the tasks that
//! fill it): WSL checks and installation, distro import, upgrade with state backup, uninstall and the scheduled task.
//! It is a Rust port of the parts of `deploy/wsl/install.ps1` the app needs, with a parity test (§8.3, §8.7).
//!
//! This crate is an empty scaffold (T2-00). T2-40 adds checks, image, import and task; T2-45 adds upgrade and
//! uninstall.

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_builds() {
        assert_eq!(env!("CARGO_PKG_NAME"), "p2pc-wsl");
    }
}
