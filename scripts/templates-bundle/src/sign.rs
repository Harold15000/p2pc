// SPDX-License-Identifier: Apache-2.0

//! Signing and verifying the bundle with the release key (minisign, H2 §5.1 and §7.6).
//!
//! The signature covers the exact bytes of `templates.json`. Its trusted comment carries the bundle's version
//! (`p2pc-templates bundle_version=<n>`), and [`verify_bundle`] requires it to equal the version inside the bytes, so
//! a signature cannot vouch for a version other than the one the key signed. The hub still applies its own
//! anti-rollback rule to what it loads (§7.6).
//!
//! No key lives in the repository. The release manager's secret key file is read by the CLI; tests make a throwaway
//! key at test time.

use std::io::Cursor;

use minisign::{PublicKey, SecretKey, SignatureBox};

use crate::bundle::{Bundle, MAX_BUNDLE_BYTES};

/// The trusted comment a signature of a bundle of `bundle_version` carries.
#[must_use]
pub fn trusted_comment(bundle_version: u64) -> String {
    format!("p2pc-templates bundle_version={bundle_version}")
}

/// Why a bundle could not be signed.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The bytes are not a bundle, or are too large to be one.
    #[error("the bytes are not a template bundle: {0}")]
    NotABundle(String),
    /// minisign refused to sign (an encrypted key that was not decrypted, for example).
    #[error("cannot sign: {0}")]
    Minisign(String),
}

/// Why a bundle did not verify.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Over [`MAX_BUNDLE_BYTES`]: refused before anything else is read.
    #[error("the bundle is over the {MAX_BUNDLE_BYTES} byte limit")]
    TooLarge,
    /// The signature is malformed, or does not match these bytes and this key.
    #[error("the signature does not verify: {0}")]
    BadSignature(String),
    /// The signature is good but the signed bytes are not a bundle.
    #[error("the signed bytes are not a template bundle: {0}")]
    NotABundle(String),
    /// The signature is good but its trusted comment names another version than the bundle has.
    #[error("the signature says {signed:?} but the bundle is version {bundle}")]
    VersionMismatch {
        /// The trusted comment, as signed.
        signed: String,
        /// The bundle's own `bundle_version`.
        bundle: u64,
    },
}

fn parse_bundle(bytes: &[u8]) -> Result<Bundle, String> {
    serde_json::from_slice(bytes).map_err(|e| e.to_string())
}

/// Signs `bundle_json` (the bytes of `templates.json`) with `secret_key`, which must not be encrypted. Returns the
/// text of the `.minisig` file.
pub fn sign_bundle(bundle_json: &[u8], secret_key: &SecretKey) -> Result<String, SignError> {
    if bundle_json.len() > MAX_BUNDLE_BYTES {
        return Err(SignError::NotABundle("over the size limit".to_string()));
    }
    let bundle = parse_bundle(bundle_json).map_err(SignError::NotABundle)?;
    let comment = trusted_comment(bundle.bundle_version);
    minisign::sign(
        None,
        secret_key,
        Cursor::new(bundle_json),
        Some(&comment),
        Some("signature from the p2pc template bundle release key"),
    )
    .map(SignatureBox::into_string)
    .map_err(|e| SignError::Minisign(e.to_string()))
}

/// Verifies `bundle_json` against `signature` (the text of the `.minisig` file) and `public_key`, and returns the
/// parsed bundle. The size is checked first, the signature second, and the bytes are parsed only once the key has
/// vouched for them.
pub fn verify_bundle(bundle_json: &[u8], signature: &str, public_key: &PublicKey) -> Result<Bundle, VerifyError> {
    if bundle_json.len() > MAX_BUNDLE_BYTES {
        return Err(VerifyError::TooLarge);
    }
    let signature = SignatureBox::from_string(signature).map_err(|e| VerifyError::BadSignature(e.to_string()))?;
    minisign::verify(public_key, &signature, Cursor::new(bundle_json), true, false, false)
        .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
    let bundle = parse_bundle(bundle_json).map_err(VerifyError::NotABundle)?;
    let signed = signature
        .trusted_comment()
        .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
    if signed != trusted_comment(bundle.bundle_version) {
        return Err(VerifyError::VersionMismatch {
            signed,
            bundle: bundle.bundle_version,
        });
    }
    Ok(bundle)
}
