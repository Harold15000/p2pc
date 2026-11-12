// SPDX-License-Identifier: Apache-2.0

//! The gate every app update passes before it is installed (H2 §14.1, SI-H2-15).
//!
//! The update endpoint's `latest.json` is not signed; only the artifact is. So the version that matters is the one in
//! the artifact signature's trusted comment, which the signature covers (Tauri's CLI writes it as tab-separated
//! `key:value` pairs, `timestamp:…\tfile:…\tversion:1.2.3`). The app refuses an artifact:
//!
//! - whose signature does not verify with the updater key compiled into the app;
//! - whose signature carries no version (`requireSignedVersion`);
//! - whose signed version is not the one the endpoint announced (an old artifact paired with a new number);
//! - whose signed version is not greater than the app's own (no downgrade, no reinstall of the same version).
//!
//! Tauri's updater plugin does the same checks when it is configured as §14.1 says; this gate runs them again on the
//! downloaded bytes, in the app's own tested code, before `install` is called.

use semver::Version;

use super::signature::{SignatureError, UpdaterKey};

/// Why an update artifact was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactRefused {
    #[error("the update's signature is not valid: {0}")]
    BadSignature(SignatureError),
    #[error("the update's signature does not say which version it is")]
    NoSignedVersion,
    #[error("the update's signed version {0:?} is not a version")]
    BadVersion(String),
    #[error("the update says it is {announced} but is signed as {signed}")]
    AnnouncedMismatch { signed: Version, announced: String },
    #[error("the update {signed} is not newer than this app ({own})")]
    NotNewer { signed: Version, own: Version },
}

/// The `version:` field of a trusted comment, if any.
pub fn signed_version(trusted_comment: &str) -> Option<&str> {
    trusted_comment
        .split('\t')
        .find_map(|field| field.trim().strip_prefix("version:"))
}

fn parse_version(text: &str) -> Option<Version> {
    Version::parse(text.trim().trim_start_matches('v')).ok()
}

/// Checks a downloaded artifact; returns its signed version.
pub fn check_artifact(
    key: &UpdaterKey,
    bytes: &[u8],
    tauri_signature: &str,
    announced: &str,
    own: &Version,
) -> Result<Version, ArtifactRefused> {
    let comment = key
        .verify(bytes, tauri_signature)
        .map_err(ArtifactRefused::BadSignature)?;
    let signed_text = signed_version(&comment).ok_or(ArtifactRefused::NoSignedVersion)?;
    let signed = parse_version(signed_text).ok_or_else(|| ArtifactRefused::BadVersion(signed_text.to_owned()))?;
    if parse_version(announced).as_ref() != Some(&signed) {
        return Err(ArtifactRefused::AnnouncedMismatch {
            signed,
            announced: announced.to_owned(),
        });
    }
    if signed <= *own {
        return Err(ArtifactRefused::NotNewer {
            signed,
            own: own.clone(),
        });
    }
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::super::signature::testkeys::TestKey;
    use super::*;

    fn comment(version: &str) -> String {
        format!("timestamp:1762939800\tfile:P2PC_{version}_x64-setup.exe\tversion:{version}")
    }

    fn own() -> Version {
        Version::new(0, 2, 0)
    }

    /// SI-H2-15: a newer, validly signed artifact passes; each refusal case is refused.
    #[test]
    fn the_updater_refuses_a_bad_signature_no_signed_version_or_no_newer_version() {
        let k = TestKey::new();
        let key = UpdaterKey::parse(&k.public_tauri()).unwrap();
        let art = b"MZ\x90\x00 installer bytes";

        let good = k.sign_tauri(art, &comment("0.3.0"));
        assert_eq!(
            check_artifact(&key, art, &good, "0.3.0", &own()),
            Ok(Version::new(0, 3, 0))
        );
        assert_eq!(
            check_artifact(&key, art, &good, "v0.3.0", &own()),
            Ok(Version::new(0, 3, 0))
        );

        // A bad signature: other bytes, another key, garbage.
        let other_bytes = check_artifact(&key, b"tampered", &good, "0.3.0", &own());
        assert_eq!(other_bytes, Err(ArtifactRefused::BadSignature(SignatureError::Invalid)));
        let other_key = TestKey::new().sign_tauri(art, &comment("0.3.0"));
        assert_eq!(
            check_artifact(&key, art, &other_key, "0.3.0", &own()),
            Err(ArtifactRefused::BadSignature(SignatureError::Invalid))
        );
        assert_eq!(
            check_artifact(&key, art, "not base64 !", "0.3.0", &own()),
            Err(ArtifactRefused::BadSignature(SignatureError::Malformed))
        );

        // No signed version (a signature made before the CLI recorded it).
        let unversioned = k.sign_tauri(art, "timestamp:1762939800\tfile:P2PC_0.3.0_x64-setup.exe");
        assert_eq!(
            check_artifact(&key, art, &unversioned, "0.3.0", &own()),
            Err(ArtifactRefused::NoSignedVersion)
        );

        // Not greater than the app's own: the same version and an older one (downgrade).
        for v in ["0.2.0", "0.1.9"] {
            let sig = k.sign_tauri(art, &comment(v));
            assert!(
                matches!(
                    check_artifact(&key, art, &sig, v, &own()),
                    Err(ArtifactRefused::NotNewer { .. })
                ),
                "{v}"
            );
        }

        // An old artifact under a new number from an unsigned latest.json.
        let old = k.sign_tauri(art, &comment("0.1.0"));
        assert!(matches!(
            check_artifact(&key, art, &old, "9.0.0", &own()),
            Err(ArtifactRefused::AnnouncedMismatch { .. })
        ));

        let bad = k.sign_tauri(art, "version:latest");
        assert_eq!(
            check_artifact(&key, art, &bad, "latest", &own()),
            Err(ArtifactRefused::BadVersion("latest".into()))
        );
    }

    #[test]
    fn the_signed_version_is_read_from_its_own_field_only() {
        assert_eq!(signed_version("timestamp:1\tversion:1.2.3"), Some("1.2.3"));
        assert_eq!(signed_version("file:version:9.9.9"), None);
        assert_eq!(signed_version("timestamp:1"), None);
    }
}
