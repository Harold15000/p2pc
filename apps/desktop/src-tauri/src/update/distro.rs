// SPDX-License-Identifier: Apache-2.0

//! Upgrading the distro after the app updated (H2 §14.2, §14.3).
//!
//! - Each app release pins one node image version ([`crate::setup::wsl_host::compiled_image_pin`]). The app manages
//!   exactly that version and never downgrades a distro: a distro newer than the app (another tool upgraded it) means
//!   the app updates itself first.
//! - **Hub first.** The hub PC's app upgrades its distro (hub and local agent) as soon as it can. A joined PC's app
//!   reads the hub's version (`server_version` of `p2pc-agent status --json`); while the new image's
//!   `min_server_version` is above it, or the hub's version is not known yet, it waits: "Waiting for your hub PC to
//!   update".
//! - **Interruptions.** An upgrade stops the distro. If anything runs, the app asks: "Update now", "Tonight at 03:00"
//!   or "Later" (at most 72 h, then at the next moment with nothing running).
//!
//! The upgrade itself is `p2pc-wsl`'s state-preserving procedure ([`p2pc_wsl::upgrade::upgrade`]).

use semver::Version;
use serde::Serialize;

use crate::state::Role;

/// "Later": at most this long.
pub const LATER_MAX_SECS: u64 = 72 * 3600;
/// "Tonight at 03:00", local time.
pub const TONIGHT_HOUR: u64 = 3;

/// The message while a joined PC waits for its hub.
pub const WAITING_FOR_HUB: &str = "Waiting for your hub PC to update";

/// What the decision needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistroFacts {
    pub role: Role,
    /// The distro's image version (`/etc/p2pc-distro-version`), `None` when it could not be read.
    pub distro_version: Option<Version>,
    /// The image version this app build pins.
    pub pinned: Version,
    /// The pinned image's `min_server_version`, when it has one.
    pub min_server_version: Option<Version>,
    /// The hub's version as the local agent last saw it (joined PC).
    pub hub_version: Option<Version>,
    /// Jobs or services run on this node now.
    pub work_running: bool,
}

/// What to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "plan", rename_all = "snake_case")]
pub enum DistroPlan {
    /// The distro runs the pinned image.
    UpToDate,
    /// Its version is not known: nothing is done.
    Unknown,
    /// The distro is newer than the app: the app updates itself first, and never downgrades it.
    UpdateAppFirst { distro: String },
    /// A joined PC whose hub is older than the image needs.
    WaitForHub { needs: String, hub: Option<String> },
    /// Nothing runs: upgrade now.
    UpgradeNow,
    /// Something runs: ask "Update now", "Tonight at 03:00" or "Later".
    Ask,
}

/// The `image_version=` value of `/etc/p2pc-distro-version` (or of its line), as a version.
pub fn parse_image_version(text: &str) -> Option<Version> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("image_version="))
        .and_then(|v| Version::parse(v.trim()).ok())
}

/// The decision of §14.2.
pub fn plan(f: &DistroFacts) -> DistroPlan {
    let Some(distro) = &f.distro_version else {
        return DistroPlan::Unknown;
    };
    if *distro > f.pinned {
        return DistroPlan::UpdateAppFirst {
            distro: distro.to_string(),
        };
    }
    if *distro == f.pinned {
        return DistroPlan::UpToDate;
    }
    if f.role == Role::Joined
        && let Some(needs) = &f.min_server_version
        && f.hub_version.as_ref().is_none_or(|hub| hub < needs)
    {
        return DistroPlan::WaitForHub {
            needs: needs.to_string(),
            hub: f.hub_version.as_ref().map(ToString::to_string),
        };
    }
    if f.work_running {
        DistroPlan::Ask
    } else {
        DistroPlan::UpgradeNow
    }
}

/// The user's answer to [`DistroPlan::Ask`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Now,
    Tonight,
    Later,
}

/// When a chosen upgrade runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deferral {
    /// Not before this time (seconds since the epoch).
    pub at: u64,
    /// Then only at a moment with nothing running ("Later").
    pub only_when_idle: bool,
}

impl Deferral {
    /// The upgrade runs now.
    pub fn due(&self, now: u64, work_running: bool) -> bool {
        now >= self.at && !(self.only_when_idle && work_running)
    }
}

/// The next `hour`:00 local time strictly after `now` (UTC seconds), for a fixed UTC offset in seconds.
pub fn next_local_hour(now: u64, utc_offset_secs: i64, hour: u64) -> u64 {
    let local = i128::from(now) + i128::from(utc_offset_secs);
    let day = local.div_euclid(86_400) * 86_400;
    let mut at = day + i128::from(hour) * 3600;
    if at <= local {
        at += 86_400;
    }
    u64::try_from(at - i128::from(utc_offset_secs)).unwrap_or(now)
}

/// The deferral of an answer.
pub fn defer(choice: Choice, now: u64, utc_offset_secs: i64) -> Deferral {
    match choice {
        Choice::Now => Deferral {
            at: now,
            only_when_idle: false,
        },
        Choice::Tonight => Deferral {
            at: next_local_hour(now, utc_offset_secs, TONIGHT_HOUR),
            only_when_idle: false,
        },
        Choice::Later => Deferral {
            at: now + LATER_MAX_SECS,
            only_when_idle: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn facts(role: Role) -> DistroFacts {
        DistroFacts {
            role,
            distro_version: Some(v("0.2.0")),
            pinned: v("0.3.0"),
            min_server_version: Some(v("0.3.0")),
            hub_version: None,
            work_running: false,
        }
    }

    #[test]
    fn the_hub_pc_upgrades_as_soon_as_it_can() {
        assert_eq!(plan(&facts(Role::Hub)), DistroPlan::UpgradeNow);
        let busy = DistroFacts {
            work_running: true,
            ..facts(Role::Hub)
        };
        assert_eq!(plan(&busy), DistroPlan::Ask);
    }

    #[test]
    fn a_joined_pc_waits_for_its_hub() {
        let f = facts(Role::Joined);
        assert_eq!(
            plan(&f),
            DistroPlan::WaitForHub {
                needs: "0.3.0".into(),
                hub: None
            }
        );
        let old_hub = DistroFacts {
            hub_version: Some(v("0.2.9")),
            ..f.clone()
        };
        assert!(matches!(plan(&old_hub), DistroPlan::WaitForHub { .. }));
        let new_hub = DistroFacts {
            hub_version: Some(v("0.3.0")),
            ..f.clone()
        };
        assert_eq!(plan(&new_hub), DistroPlan::UpgradeNow);
        let no_min = DistroFacts {
            min_server_version: None,
            ..f
        };
        assert_eq!(plan(&no_min), DistroPlan::UpgradeNow);
    }

    #[test]
    fn a_distro_is_never_downgraded() {
        let newer = DistroFacts {
            distro_version: Some(v("0.4.0")),
            ..facts(Role::Hub)
        };
        assert_eq!(plan(&newer), DistroPlan::UpdateAppFirst { distro: "0.4.0".into() });
        let same = DistroFacts {
            distro_version: Some(v("0.3.0")),
            ..facts(Role::Joined)
        };
        assert_eq!(plan(&same), DistroPlan::UpToDate);
        let unknown = DistroFacts {
            distro_version: None,
            ..facts(Role::Hub)
        };
        assert_eq!(plan(&unknown), DistroPlan::Unknown);
    }

    #[test]
    fn the_image_version_is_read_from_its_line() {
        assert_eq!(parse_image_version("image_version=0.3.0\nbuilt=x"), Some(v("0.3.0")));
        assert_eq!(parse_image_version("built=x"), None);
        assert_eq!(parse_image_version("image_version=latest"), None);
    }

    #[test]
    fn now_tonight_and_later() {
        let now = 1_762_939_800; // 2025-11-12T09:30:00Z
        assert_eq!(
            defer(Choice::Now, now, 0),
            Deferral {
                at: now,
                only_when_idle: false
            }
        );
        // 03:00 UTC the next day; at UTC+1 it is 02:00 UTC.
        assert_eq!(defer(Choice::Tonight, now, 0).at, 1_762_916_400 + 86_400);
        assert_eq!(defer(Choice::Tonight, now, 3600).at, 1_762_916_400 + 86_400 - 3600);
        // Just before 03:00 local: today's.
        let at_0259 = 1_762_916_400 - 60;
        assert_eq!(next_local_hour(at_0259, 0, 3), 1_762_916_400);
        assert_eq!(next_local_hour(1_762_916_400, 0, 3), 1_762_916_400 + 86_400);
        let later = defer(Choice::Later, now, 0);
        assert!(!later.due(now + LATER_MAX_SECS - 1, false));
        assert!(!later.due(now + LATER_MAX_SECS, true), "then only with nothing running");
        assert!(later.due(now + LATER_MAX_SECS + 5, false));
        let tonight = defer(Choice::Tonight, now, 0);
        assert!(
            tonight.due(tonight.at, true),
            "tonight runs even with work running: the user chose it"
        );
    }
}
