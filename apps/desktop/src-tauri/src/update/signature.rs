// SPDX-License-Identifier: Apache-2.0

//! minisign verification with keys compiled into the app (H2 §5.1, §9.6, §14.1).
//!
//! Two keys, two encodings:
//!
//! - the **release key** signs the web manifest (`web-manifest.json.minisig`) and the template bundle
//!   (`templates.json.minisig`); its public half is minisign's one-line base64 (or the two-line `.pub` text), and a
//!   signature is the text of a `.minisig` file;
//! - the **updater key** signs the app's update artifacts; Tauri wraps both its public key and its signatures in one
//!   more layer of base64 ([`UpdaterKey`], [`super::artifact`]).
//!
//! Every input is bounded before it is decoded, and the trusted comment is returned only after the signature, which
//! covers it, verified.

use std::fmt;

use minisign_verify::{PublicKey, Signature};

/// The largest public key or signature text the app decodes.
pub const MAX_SIGNATURE_TEXT: usize = 4096;

/// Why a key or a signature was refused. Nothing secret is in them; the texts are not repeated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// The compiled-in public key cannot be decoded (a broken build).
    #[error("the public key compiled into this app cannot be read")]
    BadKey,
    /// The signature is not a minisign signature (or too large to be one).
    #[error("the signature is not a minisign signature")]
    Malformed,
    /// A well-formed signature that does not verify with this key over these bytes (another key, other bytes).
    #[error("the signature does not verify")]
    Invalid,
}

fn decode_key(text: &str) -> Result<PublicKey, SignatureError> {
    let text = text.trim();
    if text.is_empty() || text.len() > MAX_SIGNATURE_TEXT {
        return Err(SignatureError::BadKey);
    }
    if text.contains('\n') {
        PublicKey::decode(text)
    } else {
        PublicKey::from_base64(text)
    }
    .map_err(|_| SignatureError::BadKey)
}

/// Verifies `signature_text` over `bytes`, returning the trusted comment it vouches for.
fn verify_with(key: &PublicKey, bytes: &[u8], signature_text: &str) -> Result<String, SignatureError> {
    if signature_text.len() > MAX_SIGNATURE_TEXT {
        return Err(SignatureError::Malformed);
    }
    let sig = Signature::decode(signature_text).map_err(|_| SignatureError::Malformed)?;
    // `false`: no legacy (non-prehashed) signatures; the release tooling signs prehashed.
    key.verify(bytes, &sig, false).map_err(|_| SignatureError::Invalid)?;
    Ok(sig.trusted_comment().to_owned())
}

/// The release key's public half (§5.1).
pub struct ReleaseKey(PublicKey);

impl fmt::Debug for ReleaseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReleaseKey")
    }
}

impl ReleaseKey {
    /// From minisign's one-line base64, or the two lines of a `.pub` file.
    pub fn parse(text: &str) -> Result<Self, SignatureError> {
        decode_key(text).map(Self)
    }

    /// Verifies a `.minisig` text over `bytes`; returns its trusted comment.
    pub fn verify(&self, bytes: &[u8], signature_text: &str) -> Result<String, SignatureError> {
        verify_with(&self.0, bytes, signature_text)
    }
}

/// The updater key's public half, in Tauri's encoding (base64 of the `.pub` text, §14.1).
pub struct UpdaterKey(PublicKey);

impl fmt::Debug for UpdaterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UpdaterKey")
    }
}

/// Base64 (standard alphabet, padding optional) to UTF-8 text, bounded.
pub(crate) fn base64_text(b64: &str) -> Option<String> {
    let b64 = b64.trim();
    if b64.is_empty() || b64.len() > MAX_SIGNATURE_TEXT * 2 {
        return None;
    }
    let bytes = data_encoding::BASE64
        .decode(b64.as_bytes())
        .or_else(|_| data_encoding::BASE64_NOPAD.decode(b64.as_bytes()))
        .ok()?;
    String::from_utf8(bytes).ok()
}

impl UpdaterKey {
    /// From Tauri's `pubkey` value.
    pub fn parse(tauri_pubkey: &str) -> Result<Self, SignatureError> {
        let text = base64_text(tauri_pubkey).ok_or(SignatureError::BadKey)?;
        decode_key(&text).map(Self)
    }

    /// Verifies a Tauri signature (base64 of a `.sig` text) over `bytes`; returns its trusted comment.
    pub fn verify(&self, bytes: &[u8], tauri_signature: &str) -> Result<String, SignatureError> {
        let text = base64_text(tauri_signature).ok_or(SignatureError::Malformed)?;
        verify_with(&self.0, bytes, &text)
    }
}

#[cfg(test)]
pub(crate) mod testkeys {
    //! Throwaway keys made at test time; nothing is kept.

    use std::io::Cursor;

    use minisign::KeyPair;

    /// A key pair for one test.
    pub(crate) struct TestKey(KeyPair);

    impl TestKey {
        pub(crate) fn new() -> Self {
            Self(KeyPair::generate_unencrypted_keypair().expect("a throwaway key"))
        }

        /// The release-key form: minisign's one-line base64.
        pub(crate) fn public_base64(&self) -> String {
            self.0.pk.to_base64()
        }

        /// Tauri's form: base64 of the `.pub` text.
        pub(crate) fn public_tauri(&self) -> String {
            let text = self.0.pk.to_box().expect("pk box").into_string();
            data_encoding::BASE64.encode(text.as_bytes())
        }

        /// A `.minisig` text over `bytes` with this trusted comment.
        pub(crate) fn sign(&self, bytes: &[u8], trusted: &str) -> String {
            minisign::sign(None, &self.0.sk, Cursor::new(bytes), Some(trusted), Some("test"))
                .expect("sign")
                .into_string()
        }

        /// Tauri's form of [`TestKey::sign`].
        pub(crate) fn sign_tauri(&self, bytes: &[u8], trusted: &str) -> String {
            data_encoding::BASE64.encode(self.sign(bytes, trusted).as_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkeys::TestKey;
    use super::*;

    #[test]
    fn a_release_signature_verifies_and_yields_its_trusted_comment() {
        let k = TestKey::new();
        let key = ReleaseKey::parse(&k.public_base64()).unwrap();
        let sig = k.sign(b"bytes", "p2pc-templates bundle_version=3");
        assert_eq!(key.verify(b"bytes", &sig).unwrap(), "p2pc-templates bundle_version=3");
        assert_eq!(key.verify(b"other", &sig), Err(SignatureError::Invalid));
        let other = ReleaseKey::parse(&TestKey::new().public_base64()).unwrap();
        assert_eq!(other.verify(b"bytes", &sig), Err(SignatureError::Invalid));
        assert_eq!(key.verify(b"bytes", "not a signature"), Err(SignatureError::Malformed));
        assert_eq!(
            key.verify(b"bytes", &"x".repeat(MAX_SIGNATURE_TEXT + 1)),
            Err(SignatureError::Malformed)
        );
        // A changed trusted comment breaks the global signature.
        let forged = sig.replace("bundle_version=3", "bundle_version=9");
        assert!(key.verify(b"bytes", &forged).is_err());
    }

    #[test]
    fn keys_that_do_not_decode_are_refused() {
        for bad in ["", "not base64!", "RWQ", &"A".repeat(MAX_SIGNATURE_TEXT + 1)] {
            assert_eq!(ReleaseKey::parse(bad).map(|_| ()), Err(SignatureError::BadKey), "{bad}");
            assert_eq!(UpdaterKey::parse(bad).map(|_| ()), Err(SignatureError::BadKey), "{bad}");
        }
    }

    #[test]
    fn tauri_s_encoding_wraps_the_same_minisign() {
        let k = TestKey::new();
        let key = UpdaterKey::parse(&k.public_tauri()).unwrap();
        let sig = k.sign_tauri(b"artifact", "timestamp:1\tfile:P2PC_0.3.0_x64-setup.exe\tversion:0.3.0");
        assert_eq!(
            key.verify(b"artifact", &sig).unwrap(),
            "timestamp:1\tfile:P2PC_0.3.0_x64-setup.exe\tversion:0.3.0"
        );
        assert_eq!(key.verify(b"artifact", "%%%"), Err(SignatureError::Malformed));
        assert!(format!("{key:?}").starts_with("UpdaterKey"));
    }
}
