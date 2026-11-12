// SPDX-License-Identifier: Apache-2.0

//! First run (H2 spec §8.2, task T2-43).
//!
//! | Step | Screen | Here |
//! |---|---|---|
//! | 1 | Welcome: the update-check choice, nothing preselected | [`flow::Setup::welcome`] |
//! | 2 | Checks; the image download starts in the background | [`flow::Setup::run_checks`], [`flow::Setup::download_image`] |
//! | 2a | Install WSL (elevated), the one reboot and its `RunOnce` entry | [`flow::Setup::install_wsl`] |
//! | 3 | Share: import, then CPU, RAM, GPU and the disk share | [`flow::Setup::prepare_node`], [`flow::Setup::apply_share`] |
//! | 4 | "Create my cloud": hub quota, init, `hub.enabled`, the own node's `pre_approved` token | [`flow::Setup::create_cloud`] |
//! | 5 | "Add my phone": the pairing QR code, "Skip for now" | [`flow::Setup::pair_phone`], [`flow::Setup::finish_phone`] |
//!
//! - [`disk`]: the disk arithmetic (the share, its split, the hub's blob quota);
//! - [`record`]: `setup.json`, the resume point;
//! - [`errors`]: the §8.8 codes and their fixed messages;
//! - [`host`]: the Windows and WSL actions behind [`host::SetupHost`]; [`wsl_host`] is the real one, over `p2pc-wsl`;
//! - [`hub`]: the hub's REST calls over the app's device connection, behind [`hub::HubApi`] (unwired until T2-30), and
//!   the app's device NodeId;
//! - [`flow`]: the steps themselves and what the window is shown.
//!
//! "Join my cloud" (§5.4) is T2-44 (`invite/`).

use crate::state::{Machine, State};

/// The state the app starts in: `setup` until first run has finished, then `sharing` (§8.4: "Entered by: resume,
/// setup done"), with the role step 4 chose.
pub fn starting_machine(record: &record::SetupRecord) -> Machine {
    record
        .finished()
        .and_then(|role| Machine::settled(role, State::Sharing))
        .unwrap_or_default()
}

pub mod disk;
pub mod errors;
pub mod flow;
pub mod host;
pub mod hub;
pub mod record;
pub mod wsl_host;

#[cfg(test)]
mod tests {
    use super::record::{PhoneOutcome, SetupRecord};
    use super::*;
    use crate::state::Role;

    #[test]
    fn the_app_starts_in_setup_until_first_run_has_finished() {
        let mut r = SetupRecord {
            update_checks: Some(true),
            checks_passed: true,
            role: Some(Role::Hub),
            ..SetupRecord::default()
        };
        assert_eq!(starting_machine(&r).state(), State::Setup);
        assert_eq!(starting_machine(&SetupRecord::default()).state(), State::Setup);
        r = SetupRecord {
            node: Some(super::record::NodeRecord {
                image_version: String::new(),
                cpu_cores: 1,
                memory_mb: 1024,
                gpu_offerable: false,
                default_cpu: 1,
                default_memory_mb: 1024,
                networking: super::record::NetworkingMode::Nat,
            }),
            share: Some(super::record::ShareRecord {
                cpu: 1,
                memory_mb: 1024,
                gpu: false,
                share_gib: 1,
                disk_mb: 512,
                volumes_mb: 512,
            }),
            phone: Some(PhoneOutcome::Skipped),
            ..r
        };
        let m = starting_machine(&r);
        assert_eq!((m.state(), m.role()), (State::Sharing, Some(Role::Hub)));
    }
}
