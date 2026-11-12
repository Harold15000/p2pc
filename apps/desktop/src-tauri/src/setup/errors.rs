// SPDX-License-Identifier: Apache-2.0

//! The errors of first run: codes and fixed messages (H2 §8.2 "Errors", §8.8).
//!
//! The app never shows a raw stack trace or a PowerShell error. A [`SetupError`] is a code from §8.8's table (or one of
//! the few first-run codes the table does not have, marked below), its fixed message, the step it stays at, and at
//! most a short detail that the app built itself or sanitized: the exit code of a step, which check failed, WSL's own
//! message with control characters removed and capped (`p2pc_wsl::import::sanitize_message`). A detail never holds a
//! join token, a pairing ticket or a key: the values that carry them go on stdin or stay in memory, and no detail is
//! built from them.

use serde::Serialize;

use p2pc_wsl::checks::CheckFailure;
use p2pc_wsl::image::ImageError;
use p2pc_wsl::import::{ImportError, sanitize_message};

use super::record::Step;

/// The manufacturer-neutral Microsoft page on turning virtualization on (§8.2: "a short guide and a link to the
/// manufacturer-neutral Microsoft page"); the short link WSL's own error messages give.
pub const VIRTUALIZATION_GUIDE_URL: &str = "https://aka.ms/enablevirtualization";

/// A first-run error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupErrorCode {
    /// §8.8: firmware virtualization disabled. Stays at step 2.
    VirtualizationOff,
    /// §8.8: `wsl --install` failed or was declined at UAC. Stays at 2a.
    WslInstallFailed,
    /// §8.8: WSL < 2.0 and no update possible. Stays at 2.
    WslTooOld,
    /// §8.8: under 20 GiB free (or, at step 3, not even the smallest share fits). Stays at 2.
    DiskLow,
    /// §8.8: the image download failed. Stays at 3.
    ImageDownloadFailed,
    /// §8.8: a corrupt or tampered image. Never retried silently. Stays at 3.
    ImageHashMismatch,
    /// §8.8: `wsl --import` failed. Stays at 3.
    ImportFailed,
    /// §8.8: the boot status or the isolation checks of the distro fail. During first run it stays at 3 (the state
    /// machine has no `attention` before setup is done; see the PR's spec questions).
    DistroUnhealthy,
    /// §8.8: the join token was refused (expired, used, revoked). Stays at 4.
    JoinRejected,
    /// Not in §8.8: a step-2 check that has no code there (Windows build, WSL default version, a network path, an
    /// unreadable disk). The detail is `p2pc_wsl`'s fixed message for it. Stays at 2.
    ChecksFailed,
    /// Not in §8.8: `p2pc-agent share set` refused the share or did not run. Stays at 3.
    ShareFailed,
    /// Not in §8.8: the hub's blob quota would be under 4 GiB: back to step 3 for a smaller share (§8.2).
    ShareTooLarge,
    /// Not in §8.8: a sub-step of "Create my cloud" failed (hub init, its config, starting it, the hub's answers).
    /// Stays at 4, and "Try again" resumes at the sub-step that failed.
    HubFailed,
    /// Not in §8.8: this build cannot do it yet (no pinned node image, or no device connection to the hub).
    NotAvailable,
}

impl SetupErrorCode {
    /// The fixed message.
    pub fn message(self) -> &'static str {
        match self {
            SetupErrorCode::VirtualizationOff => "Turn on virtualization in your PC's firmware settings",
            SetupErrorCode::WslInstallFailed => "WSL could not be installed",
            SetupErrorCode::WslTooOld => {
                "WSL is too old and could not be updated. Update it from the Microsoft Store: open the Store, search for \
                 \"Windows Subsystem for Linux\" and select Update, then check again"
            }
            SetupErrorCode::DiskLow => "There is not enough free space on this PC's drive",
            SetupErrorCode::ImageDownloadFailed => "The P2PC node image could not be downloaded",
            SetupErrorCode::ImageHashMismatch => {
                "The downloaded node image is corrupt or is not the one this app expects. It was deleted"
            }
            SetupErrorCode::ImportFailed => "WSL could not import the P2PC distro",
            SetupErrorCode::DistroUnhealthy => "The P2PC distro failed a check",
            SetupErrorCode::JoinRejected => "The join token was refused: ask for a new invite",
            SetupErrorCode::ChecksFailed => "This PC does not meet P2PC's requirements",
            SetupErrorCode::ShareFailed => "The share could not be applied",
            SetupErrorCode::ShareTooLarge => {
                "Your cloud's hub needs room for files on this PC: choose a smaller disk share"
            }
            SetupErrorCode::HubFailed => "Your cloud could not be created",
            SetupErrorCode::NotAvailable => "This is not available in this version of the app yet",
        }
    }

    /// The step the app stays at (or goes back to) with this error.
    pub fn step(self) -> Step {
        match self {
            SetupErrorCode::VirtualizationOff
            | SetupErrorCode::WslInstallFailed
            | SetupErrorCode::WslTooOld
            | SetupErrorCode::DiskLow
            | SetupErrorCode::ChecksFailed => Step::Checks,
            SetupErrorCode::ImageDownloadFailed
            | SetupErrorCode::ImageHashMismatch
            | SetupErrorCode::ImportFailed
            | SetupErrorCode::DistroUnhealthy
            | SetupErrorCode::ShareFailed
            | SetupErrorCode::ShareTooLarge => Step::Share,
            SetupErrorCode::JoinRejected | SetupErrorCode::HubFailed => Step::CreateOrJoin,
            // Wherever it happened.
            SetupErrorCode::NotAvailable => Step::Welcome,
        }
    }

    /// Whether the window offers "Try again". A hash mismatch is never retried silently (§8.8): the user must ask.
    pub fn try_again(self) -> bool {
        !matches!(
            self,
            SetupErrorCode::VirtualizationOff | SetupErrorCode::NotAvailable | SetupErrorCode::ShareTooLarge
        )
    }
}

/// The longest detail an error carries.
pub const MAX_DETAIL_CHARS: usize = 300;

/// An error of a first-run step.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", code.message())]
pub struct SetupError {
    pub code: SetupErrorCode,
    /// A short, sanitized detail (see the module documentation).
    pub detail: Option<String>,
}

impl SetupError {
    /// An error with no detail.
    pub fn new(code: SetupErrorCode) -> Self {
        Self { code, detail: None }
    }

    /// An error with a detail, sanitized and capped.
    pub fn with_detail(code: SetupErrorCode, detail: impl AsRef<str>) -> Self {
        let mut d = sanitize_message(detail.as_ref());
        if d.chars().count() > MAX_DETAIL_CHARS {
            d = d.chars().take(MAX_DETAIL_CHARS).collect::<String>() + "...";
        }
        Self {
            code,
            detail: (!d.is_empty()).then_some(d),
        }
    }

    /// What the window gets.
    pub fn view(&self) -> SetupErrorView {
        SetupErrorView {
            code: self.code,
            message: self.code.message(),
            detail: self.detail.clone(),
            try_again: self.code.try_again(),
            guide_url: (self.code == SetupErrorCode::VirtualizationOff).then_some(VIRTUALIZATION_GUIDE_URL),
        }
    }
}

/// An error as the window shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupErrorView {
    pub code: SetupErrorCode,
    pub message: &'static str,
    pub detail: Option<String>,
    pub try_again: bool,
    /// For `virtualization_off`: the guide's link (opened in the system browser).
    pub guide_url: Option<&'static str>,
}

/// A failed check of step 2 as a first-run error. `None` for "WSL is missing", which is not an error but step 2a, and
/// for "WSL too old" before step 2a ran (2a updates it).
pub fn from_check_failure(failure: &CheckFailure, wsl_install_ran: bool) -> Option<SetupError> {
    match failure {
        CheckFailure::WslMissing => None,
        CheckFailure::WslTooOld { .. } if !wsl_install_ran => None,
        CheckFailure::WslTooOld { .. } => Some(SetupError::with_detail(SetupErrorCode::WslTooOld, failure.message())),
        CheckFailure::VirtualizationOff => Some(SetupError::new(SetupErrorCode::VirtualizationOff)),
        CheckFailure::DiskLow { .. } => Some(SetupError::with_detail(SetupErrorCode::DiskLow, failure.message())),
        CheckFailure::WindowsTooOld { .. }
        | CheckFailure::WslDefaultVersion { .. }
        | CheckFailure::InstallDirNotLocal
        | CheckFailure::DiskUnknown => Some(SetupError::with_detail(SetupErrorCode::ChecksFailed, failure.message())),
    }
}

/// An image error as a first-run error.
pub fn from_image_error(e: &ImageError) -> SetupError {
    match e {
        ImageError::HashMismatch { .. } => SetupError::new(SetupErrorCode::ImageHashMismatch),
        ImageError::TooLarge { .. } => SetupError::with_detail(
            SetupErrorCode::ImageDownloadFailed,
            "the server sent more than the image's size cap",
        ),
        ImageError::Cancelled => SetupError::with_detail(SetupErrorCode::ImageDownloadFailed, "cancelled"),
        // The pin compiled into the app is unusable: a build problem, which the user cannot fix.
        ImageError::BadDigest | ImageError::BadUrl => SetupError::new(SetupErrorCode::NotAvailable),
        ImageError::Download(_)
        | ImageError::ImageMissing(_)
        | ImageError::ChecksumFileMissing(_)
        | ImageError::BadChecksumFile
        | ImageError::Io { .. } => SetupError::new(SetupErrorCode::ImageDownloadFailed),
    }
}

/// An import or verification error as a first-run error.
pub fn from_import_error(e: &ImportError) -> SetupError {
    match e {
        ImportError::Unhealthy { problems } => {
            SetupError::with_detail(SetupErrorCode::DistroUnhealthy, problems.join("; "))
        }
        // Already sanitized by p2pc-wsl.
        ImportError::Import { code, message } => SetupError::with_detail(
            SetupErrorCode::ImportFailed,
            match code {
                Some(c) => format!("exit code {c}: {message}"),
                None => message.clone(),
            },
        ),
        ImportError::DirNotEmpty { found, .. } => SetupError::with_detail(
            SetupErrorCode::ImportFailed,
            format!("the distro folder holds other files: {}", found.join(", ")),
        ),
        ImportError::RelativePath(_) | ImportError::Io { .. } => {
            SetupError::with_detail(SetupErrorCode::ImportFailed, "the distro folder could not be prepared")
        }
        ImportError::Run(_) => SetupError::with_detail(SetupErrorCode::ImportFailed, "wsl.exe could not run"),
    }
}

#[cfg(test)]
mod tests {
    use p2pc_wsl::checks::WslVersion;
    use p2pc_wsl::image::Sha256Digest;

    use super::*;

    const ALL: [SetupErrorCode; 14] = [
        SetupErrorCode::VirtualizationOff,
        SetupErrorCode::WslInstallFailed,
        SetupErrorCode::WslTooOld,
        SetupErrorCode::DiskLow,
        SetupErrorCode::ImageDownloadFailed,
        SetupErrorCode::ImageHashMismatch,
        SetupErrorCode::ImportFailed,
        SetupErrorCode::DistroUnhealthy,
        SetupErrorCode::JoinRejected,
        SetupErrorCode::ChecksFailed,
        SetupErrorCode::ShareFailed,
        SetupErrorCode::ShareTooLarge,
        SetupErrorCode::HubFailed,
        SetupErrorCode::NotAvailable,
    ];

    #[test]
    fn codes_serialize_as_the_spec_s_names() {
        let names: Vec<String> = ALL
            .iter()
            .map(|c| serde_json::to_value(c).expect("json").as_str().expect("str").to_owned())
            .collect();
        for spec in [
            "virtualization_off",
            "wsl_install_failed",
            "wsl_too_old",
            "disk_low",
            "image_download_failed",
            "image_hash_mismatch",
            "import_failed",
            "distro_unhealthy",
            "join_rejected",
        ] {
            assert!(names.iter().any(|n| n == spec), "{spec}");
        }
    }

    #[test]
    fn each_code_stays_at_the_spec_s_step() {
        use SetupErrorCode as C;
        for (code, step) in [
            (C::VirtualizationOff, Step::Checks),
            (C::WslInstallFailed, Step::Checks),
            (C::WslTooOld, Step::Checks),
            (C::DiskLow, Step::Checks),
            (C::ImageDownloadFailed, Step::Share),
            (C::ImageHashMismatch, Step::Share),
            (C::ImportFailed, Step::Share),
            (C::JoinRejected, Step::CreateOrJoin),
            (C::ShareTooLarge, Step::Share),
        ] {
            assert_eq!(code.step(), step, "{code:?}");
        }
    }

    #[test]
    fn every_message_is_fixed_and_short() {
        for code in ALL {
            let m = code.message();
            assert!(!m.is_empty() && m.len() < 300, "{code:?}");
        }
        assert_eq!(
            SetupErrorCode::VirtualizationOff.message(),
            "Turn on virtualization in your PC's firmware settings"
        );
    }

    #[test]
    fn virtualization_off_links_the_guide_and_offers_no_retry() {
        let v = SetupError::new(SetupErrorCode::VirtualizationOff).view();
        assert_eq!(v.guide_url, Some(VIRTUALIZATION_GUIDE_URL));
        assert!(!v.try_again);
        assert!(SetupError::new(SetupErrorCode::ImageHashMismatch).view().try_again);
    }

    #[test]
    fn details_are_sanitized_and_capped() {
        let e = SetupError::with_detail(SetupErrorCode::ImportFailed, "line one\r\n\tline\u{1b}[31m two");
        assert_eq!(e.detail.as_deref(), Some("line one line [31m two"));
        let long = "x".repeat(2000);
        let e = SetupError::with_detail(SetupErrorCode::ImportFailed, &long);
        assert_eq!(e.detail.expect("detail").chars().count(), MAX_DETAIL_CHARS + 3);
        assert_eq!(SetupError::with_detail(SetupErrorCode::HubFailed, " \n ").detail, None);
    }

    #[test]
    fn wsl_missing_is_step_2a_and_too_old_is_an_error_only_after_2a() {
        assert_eq!(from_check_failure(&CheckFailure::WslMissing, false), None);
        assert_eq!(from_check_failure(&CheckFailure::WslMissing, true), None);
        let old = CheckFailure::WslTooOld {
            version: WslVersion::new(1, 2, 5),
            min: WslVersion::new(2, 0, 0),
        };
        assert_eq!(from_check_failure(&old, false), None);
        assert_eq!(
            from_check_failure(&old, true).map(|e| e.code),
            Some(SetupErrorCode::WslTooOld)
        );
    }

    #[test]
    fn check_failures_map_to_their_codes() {
        let cases = [
            (CheckFailure::VirtualizationOff, SetupErrorCode::VirtualizationOff),
            (
                CheckFailure::DiskLow {
                    free_gib: 12,
                    needed_gib: 20,
                },
                SetupErrorCode::DiskLow,
            ),
            (
                CheckFailure::WindowsTooOld {
                    build: Some(19045),
                    min: 22000,
                },
                SetupErrorCode::ChecksFailed,
            ),
            (CheckFailure::InstallDirNotLocal, SetupErrorCode::ChecksFailed),
            (CheckFailure::DiskUnknown, SetupErrorCode::ChecksFailed),
        ];
        for (failure, code) in cases {
            assert_eq!(
                from_check_failure(&failure, false).map(|e| e.code),
                Some(code),
                "{failure:?}"
            );
        }
        let disk = from_check_failure(
            &CheckFailure::DiskLow {
                free_gib: 12,
                needed_gib: 20,
            },
            false,
        )
        .expect("error");
        assert!(disk.detail.expect("detail").contains("12 GiB"), "how much is needed");
    }

    #[test]
    fn image_errors_map_to_download_or_mismatch() {
        let digest = Sha256Digest::from_hex(&"ab".repeat(32)).expect("digest");
        assert_eq!(
            from_image_error(&ImageError::HashMismatch {
                expected: digest,
                actual: digest
            })
            .code,
            SetupErrorCode::ImageHashMismatch
        );
        for e in [
            ImageError::Download("connection reset".into()),
            ImageError::TooLarge { max_bytes: 1 },
            ImageError::Cancelled,
        ] {
            assert_eq!(from_image_error(&e).code, SetupErrorCode::ImageDownloadFailed, "{e:?}");
        }
        assert_eq!(from_image_error(&ImageError::BadUrl).code, SetupErrorCode::NotAvailable);
    }

    #[test]
    fn import_errors_map_to_import_failed_or_unhealthy_naming_the_check() {
        let e = from_import_error(&ImportError::Unhealthy {
            problems: vec!["/mnt/c exists inside the distro (automount is not off)".into()],
        });
        assert_eq!(e.code, SetupErrorCode::DistroUnhealthy);
        assert!(e.detail.expect("detail").contains("/mnt/c"));
        let e = from_import_error(&ImportError::Import {
            code: Some(-1),
            message: "The operation timed out".into(),
        });
        assert_eq!(e.code, SetupErrorCode::ImportFailed);
        assert_eq!(e.detail.as_deref(), Some("exit code -1: The operation timed out"));
    }
}
