// SPDX-License-Identifier: Apache-2.0

//! The disk arithmetic of first run (H2 §8.2 "Disk arithmetic").
//!
//! P2PC's disk use on a PC has four parts, all on the profile's drive (the distro's virtual disk):
//!
//! - `D`, the share of step 3, split with one formula: jobs `offered.disk_mb = min(50 GiB, D / 2)` and volumes
//!   `volumes_mb = D − that` ([`split`]);
//! - `I`, the node's container image store: an allowance of 16 GiB ([`IMAGE_ALLOWANCE_GIB`]);
//! - `B`, on the hub PC only, the hub's blob quota (`blobs_quota_mb`, §7.5);
//! - the 20 GiB floor of step 2, which stays free ([`FLOOR_GIB`]).
//!
//! So `D ≤ free − 20 GiB − I − B`, and the control's default is `min(90 GiB, that)` ([`share_range`], which step 3
//! computes with `B = 0`). "Create my cloud" (step 4) then sets `blobs_quota_mb = min(20 GiB, free − 20 GiB − I − D)`,
//! and when that is under 4 GiB, twice the largest blob, it goes back to step 3 for a smaller share ([`hub_blob_quota`]).
//!
//! Everything counts in whole GiB of 2^30 bytes, as step 2 counts free space (`install.ps1 -MinFreeGB`, and
//! `p2pc_wsl::checks`): the free space is rounded down, so the arithmetic never promises a byte that is not there. The
//! values the agent and the hub take are in MiB.

use serde::Serialize;

/// 2^30 bytes.
pub const GIB: u64 = 1 << 30;

/// MiB in a GiB.
pub const MIB_PER_GIB: u64 = 1024;

/// The floor of step 2 that stays free (`install.ps1 -MinFreeGB 20`).
pub const FLOOR_GIB: u64 = 20;

/// `I`, the node's container image store (§8.2: 16 GiB, T2-50's measurement keeps it).
pub const IMAGE_ALLOWANCE_GIB: u64 = 16;

/// The cap of the Share control's default (§8.2: `min(90 GiB, …)`).
pub const DEFAULT_SHARE_CAP_GIB: u64 = 90;

/// The cap of the jobs' half of the share (§8.2: `offered.disk_mb = min(50 GiB, D / 2)`).
pub const JOBS_DISK_CAP_GIB: u64 = 50;

/// The cap of the hub's blob quota (§8.2: `min(20 GiB, …)`; the hub's default, §7.5).
pub const BLOB_QUOTA_CAP_GIB: u64 = 20;

/// The least blob quota the hub PC accepts: twice the largest blob (§8.2: "under 4 GiB (twice the largest blob)").
pub const MIN_BLOB_QUOTA_GIB: u64 = 4;

/// The share both templates need (§8.2 "Minimum for the templates"): the Share control marks it.
pub const TEMPLATES_SHARE_GIB: u64 = 50;

/// The smallest share the Share control offers. The spec gives no lower bound; a share of nothing would offer jobs no
/// disk at all, so the control starts at 1 GiB (see the PR's spec questions).
pub const MIN_SHARE_GIB: u64 = 1;

/// Free bytes as whole GiB, rounded down (as step 2 counts them).
pub fn free_gib(free_bytes: u64) -> u64 {
    free_bytes / GIB
}

/// The range of the Share control (step 3), computed with `B = 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ShareRange {
    /// The smallest share, [`MIN_SHARE_GIB`].
    pub min_gib: u64,
    /// `free − 20 GiB − I`.
    pub max_gib: u64,
    /// `min(90 GiB, max)`.
    pub default_gib: u64,
    /// The mark of [`TEMPLATES_SHARE_GIB`]: below it, the AI chat and transcription may not run on this PC.
    pub templates_gib: u64,
}

/// Not even the smallest share fits: the free space is under `20 GiB + I + 1 GiB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{free_gib} GiB free; P2PC needs at least {needed_gib} GiB free")]
pub struct NotEnoughDisk {
    /// The free space, in whole GiB.
    pub free_gib: u64,
    /// The free space the smallest share needs, in GiB.
    pub needed_gib: u64,
}

/// The Share control's range for this much free space (step 3: the PC's role is not known yet, so `B = 0`).
pub fn share_range(free_bytes: u64) -> Result<ShareRange, NotEnoughDisk> {
    let free = free_gib(free_bytes);
    let max_gib = free.saturating_sub(FLOOR_GIB + IMAGE_ALLOWANCE_GIB);
    if max_gib < MIN_SHARE_GIB {
        return Err(NotEnoughDisk {
            free_gib: free,
            needed_gib: FLOOR_GIB + IMAGE_ALLOWANCE_GIB + MIN_SHARE_GIB,
        });
    }
    Ok(ShareRange {
        min_gib: MIN_SHARE_GIB,
        max_gib,
        default_gib: max_gib.min(DEFAULT_SHARE_CAP_GIB),
        templates_gib: TEMPLATES_SHARE_GIB,
    })
}

/// The share split between jobs and volumes, in MiB (the values of `p2pc-agent share set --disk-mb … --volumes-mb …`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DiskSplit {
    /// `offered.disk_mb = min(50 GiB, D / 2)`.
    pub disk_mb: u64,
    /// `volumes_mb = D − disk_mb`.
    pub volumes_mb: u64,
}

/// Splits a share of `share_gib` (§8.2).
pub fn split(share_gib: u64) -> DiskSplit {
    let share_mb = share_gib.saturating_mul(MIB_PER_GIB);
    let disk_mb = (share_mb / 2).min(JOBS_DISK_CAP_GIB * MIB_PER_GIB);
    DiskSplit {
        disk_mb,
        volumes_mb: share_mb - disk_mb,
    }
}

/// Whether a share leaves both templates room (§8.2: `D ≥ 50 GiB`).
pub fn templates_fit(share_gib: u64) -> bool {
    share_gib >= TEMPLATES_SHARE_GIB
}

/// The hub's blob quota does not fit next to this share: step 4 goes back to step 3 for a smaller one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the share leaves the hub {quota_gib} GiB for blobs; at most {max_share_gib} GiB of share leaves it 4 GiB")]
pub struct ShareTooLarge {
    /// What the quota would be (`free − 20 GiB − I − D`, at least 0), in GiB.
    pub quota_gib: u64,
    /// The largest share that leaves [`MIN_BLOB_QUOTA_GIB`] (0 when none does).
    pub max_share_gib: u64,
}

/// `blobs_quota_mb` for the hub PC at "Create my cloud": `min(20 GiB, free − 20 GiB − I − D)`, refused under 4 GiB.
pub fn hub_blob_quota(free_bytes: u64, share_gib: u64) -> Result<u64, ShareTooLarge> {
    let room = free_gib(free_bytes).saturating_sub(FLOOR_GIB + IMAGE_ALLOWANCE_GIB);
    let quota_gib = room.saturating_sub(share_gib).min(BLOB_QUOTA_CAP_GIB);
    if quota_gib < MIN_BLOB_QUOTA_GIB {
        return Err(ShareTooLarge {
            quota_gib,
            max_share_gib: room.saturating_sub(MIN_BLOB_QUOTA_GIB),
        });
    }
    Ok(quota_gib * MIB_PER_GIB)
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn gib(n: u64) -> u64 {
        n * GIB
    }

    #[test]
    fn the_spec_s_default_pc_needs_126_gib_and_the_hub_pc_146() {
        // "With the defaults, a PC needs 90 + 16 + 20 = 126 GiB free for the default share, and the hub PC 146 GiB."
        let r = share_range(gib(126)).expect("fits");
        assert_eq!((r.max_gib, r.default_gib), (90, 90));
        assert_eq!(hub_blob_quota(gib(146), 90), Ok(20 * MIB_PER_GIB));
        let r = share_range(gib(125)).expect("fits");
        assert_eq!((r.max_gib, r.default_gib), (89, 89));
    }

    #[test]
    fn the_default_is_capped_at_90_gib_and_the_max_is_free_minus_36() {
        let r = share_range(gib(500)).expect("fits");
        assert_eq!(
            r,
            ShareRange {
                min_gib: 1,
                max_gib: 500 - 20 - 16,
                default_gib: 90,
                templates_gib: 50,
            }
        );
    }

    #[test]
    fn free_space_is_counted_in_whole_gib_rounded_down() {
        assert_eq!(free_gib(gib(100) - 1), 99);
        let r = share_range(gib(100) - 1).expect("fits");
        assert_eq!(r.max_gib, 99 - 36);
    }

    #[test]
    fn under_37_gib_not_even_the_smallest_share_fits() {
        assert_eq!(share_range(gib(37)).map(|r| r.max_gib), Ok(1));
        assert_eq!(
            share_range(gib(36)),
            Err(NotEnoughDisk {
                free_gib: 36,
                needed_gib: 37
            })
        );
        assert_eq!(
            share_range(gib(20)),
            Err(NotEnoughDisk {
                free_gib: 20,
                needed_gib: 37
            })
        );
        assert_eq!(
            share_range(0),
            Err(NotEnoughDisk {
                free_gib: 0,
                needed_gib: 37
            })
        );
    }

    #[test]
    fn the_split_gives_jobs_half_up_to_50_gib_and_volumes_the_rest() {
        assert_eq!(
            split(90),
            DiskSplit {
                disk_mb: 45 * 1024,
                volumes_mb: 45 * 1024
            }
        );
        // Both templates: 25 GiB for jobs and 25 GiB for volumes.
        assert_eq!(
            split(50),
            DiskSplit {
                disk_mb: 25 * 1024,
                volumes_mb: 25 * 1024
            }
        );
        assert_eq!(
            split(300),
            DiskSplit {
                disk_mb: 50 * 1024,
                volumes_mb: 250 * 1024
            }
        );
        // An odd share: MiB, nothing lost.
        let s = split(1);
        assert_eq!((s.disk_mb, s.volumes_mb), (512, 512));
        let s = split(3);
        assert_eq!(s.disk_mb + s.volumes_mb, 3 * 1024);
        assert_eq!(s.disk_mb, 1536);
    }

    #[test]
    fn the_templates_need_50_gib() {
        assert!(templates_fit(50));
        assert!(templates_fit(90));
        assert!(!templates_fit(49));
    }

    #[test]
    fn the_hub_quota_is_what_is_left_up_to_20_gib() {
        assert_eq!(hub_blob_quota(gib(200), 90), Ok(20 * 1024));
        // 140 − 36 − 90 = 14 GiB.
        assert_eq!(hub_blob_quota(gib(140), 90), Ok(14 * 1024));
        // Exactly 4 GiB is enough.
        assert_eq!(hub_blob_quota(gib(130), 90), Ok(4 * 1024));
    }

    #[test]
    fn a_quota_under_4_gib_goes_back_for_a_smaller_share() {
        // 129 − 36 − 90 = 3 GiB: the largest share leaving 4 GiB is 89.
        assert_eq!(
            hub_blob_quota(gib(129), 90),
            Err(ShareTooLarge {
                quota_gib: 3,
                max_share_gib: 89
            })
        );
        // The default share of a PC with exactly 126 GiB leaves nothing.
        assert_eq!(
            hub_blob_quota(gib(126), 90),
            Err(ShareTooLarge {
                quota_gib: 0,
                max_share_gib: 86
            })
        );
        // Less free space than the share itself: nothing fits, no underflow.
        assert_eq!(
            hub_blob_quota(gib(30), 90),
            Err(ShareTooLarge {
                quota_gib: 0,
                max_share_gib: 0
            })
        );
        assert_eq!(
            hub_blob_quota(u64::MAX, u64::MAX),
            Err(ShareTooLarge {
                quota_gib: 0,
                max_share_gib: free_gib(u64::MAX) - 40
            })
        );
    }
}
