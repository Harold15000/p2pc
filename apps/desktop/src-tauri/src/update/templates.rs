// SPDX-License-Identifier: Apache-2.0

//! Template bundles (H2 §14.1, §7.6): part of the update check on the hub PC, under the same opt-in, carrying no
//! identifier.
//!
//! 1. Fetch the channel's `templates-latest.json` (`{"bundle_version": N, "url": "https://…/templates.json"}`, unsigned;
//!    the signature is at `<url>.minisig` unless it names `signature_url`).
//! 2. Only when `N` is above the hub's current bundle (`GET /v1/templates`), or the hub serves none, download the
//!    bundle and its signature. When the hub's bundle is not known (the hub did not answer), nothing is delivered: an
//!    older or equal bundle written over the one at the hub's high-water mark would leave it serving none (SI-H2-14).
//! 3. Verify the signature with the release key compiled into the app, and that both its trusted comment
//!    (`p2pc-templates bundle_version=N`) and the bundle's own `bundle_version` are the `N` that was named.
//! 4. Copy the signature, then the bundle, into the distro's `/var/lib/p2pc-server/templates/` through `wsl.exe` with
//!    byte-exact pipes ([`BundleSink`]; the real one is `p2pc-wsl`'s `write_file_in_distro`: each file to the stdin of
//!    a command inside the distro, never through `/mnt/c` or `\\wsl$`, renamed into place only after its hash checks).
//!
//! The hub verifies again and applies its anti-rollback rule; a stale or hostile endpoint can at most withhold a bundle
//! or offer an older one, which step 2 or the hub refuses.

use serde::Deserialize;

use super::fetch::{Fetch, FetchError};
use super::signature::{ReleaseKey, SignatureError};

/// The hub's templates directory inside the distro (`<data>/templates/`, `P2PC_DATA_DIR=/var/lib/p2pc-server`).
pub const TEMPLATES_DIR: &str = "/var/lib/p2pc-server/templates";
/// The bundle's file name there.
pub const BUNDLE_FILE: &str = "templates.json";
/// Its signature's.
pub const SIGNATURE_FILE: &str = "templates.json.minisig";
/// The largest `templates-latest.json` read.
pub const MAX_LATEST_BYTES: u64 = 64 * 1024;
/// The largest bundle read (the release tool's own cap is lower).
pub const MAX_BUNDLE_BYTES: u64 = 4 << 20;
/// The largest signature read.
pub const MAX_SIGNATURE_BYTES: u64 = 4096;

/// `templates-latest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TemplatesLatest {
    pub bundle_version: u64,
    pub url: String,
    #[serde(default)]
    pub signature_url: Option<String>,
}

/// The bundle as far as this check reads it.
#[derive(Deserialize)]
struct BundleHead {
    bundle_version: u64,
}

/// What the hub serves now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubTemplates {
    Serving(u64),
    /// The hub serves no bundle (`503 templates_unavailable`, or none loaded).
    NoneServed,
    /// The hub did not say.
    Unknown,
}

/// Writes one file into the hub's templates directory, byte-exact.
pub trait BundleSink {
    fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String>;
}

/// What a check did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplatesOutcome {
    /// The hub already has this bundle or a newer one.
    UpToDate { hub: u64, latest: u64 },
    /// The hub's bundle is not known: nothing was downloaded.
    HubUnknown,
    /// Verified and copied into the distro.
    Delivered { version: u64 },
}

/// Why a check failed. Nothing was written into the distro.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TemplatesError {
    #[error("this build has no release key")]
    NoKey,
    #[error("templates-latest.json: {0}")]
    Endpoint(FetchError),
    #[error("templates-latest.json is not valid")]
    BadLatest,
    #[error("templates-latest.json names a URL that is not https")]
    BadUrl,
    #[error("downloading the template bundle: {0}")]
    Download(FetchError),
    #[error("the template bundle's signature: {0}")]
    Signature(SignatureError),
    #[error("the template bundle is signed as {signed:?}, not as bundle_version {named}")]
    VersionMismatch { signed: String, named: u64 },
    #[error("copying the template bundle into the distro: {0}")]
    Deliver(String),
}

fn https(url: &str) -> Result<String, TemplatesError> {
    let u = url::Url::parse(url).map_err(|_| TemplatesError::BadUrl)?;
    if u.scheme() != "https" || u.host_str().is_none() || !u.username().is_empty() || u.password().is_some() {
        return Err(TemplatesError::BadUrl);
    }
    Ok(u.into())
}

/// The trusted comment a bundle of `version` is signed with (`scripts/templates-bundle`).
pub fn trusted_comment(version: u64) -> String {
    format!("p2pc-templates bundle_version={version}")
}

/// One check (§14.1). Blocking.
pub fn check_templates(
    fetch: &dyn Fetch,
    key: Option<&ReleaseKey>,
    latest_url: &str,
    hub: HubTemplates,
    sink: &dyn BundleSink,
) -> Result<TemplatesOutcome, TemplatesError> {
    let latest_url = https(latest_url)?;
    let body = fetch
        .get(&latest_url, MAX_LATEST_BYTES)
        .map_err(TemplatesError::Endpoint)?;
    let latest: TemplatesLatest = serde_json::from_slice(&body).map_err(|_| TemplatesError::BadLatest)?;
    match hub {
        HubTemplates::Serving(current) if latest.bundle_version <= current => {
            return Ok(TemplatesOutcome::UpToDate {
                hub: current,
                latest: latest.bundle_version,
            });
        }
        HubTemplates::Unknown => return Ok(TemplatesOutcome::HubUnknown),
        HubTemplates::Serving(_) | HubTemplates::NoneServed => {}
    }
    let key = key.ok_or(TemplatesError::NoKey)?;
    let bundle_url = https(&latest.url)?;
    let sig_url = match &latest.signature_url {
        Some(u) => https(u)?,
        None => https(&format!("{bundle_url}.minisig"))?,
    };
    let bundle = fetch
        .get(&bundle_url, MAX_BUNDLE_BYTES)
        .map_err(TemplatesError::Download)?;
    let sig = fetch
        .get(&sig_url, MAX_SIGNATURE_BYTES)
        .map_err(TemplatesError::Download)?;
    let sig_text = String::from_utf8(sig).map_err(|_| TemplatesError::Signature(SignatureError::Malformed))?;
    let signed = key.verify(&bundle, &sig_text).map_err(TemplatesError::Signature)?;
    let named = latest.bundle_version;
    let inner = serde_json::from_slice::<BundleHead>(&bundle).map(|b| b.bundle_version);
    if signed != trusted_comment(named) || inner.ok() != Some(named) {
        return Err(TemplatesError::VersionMismatch { signed, named });
    }
    // The signature first, then the bundle: a hub that reads between the two sees a pair that does not verify and keeps
    // what it serves.
    sink.write(SIGNATURE_FILE, sig_text.as_bytes())
        .map_err(TemplatesError::Deliver)?;
    sink.write(BUNDLE_FILE, &bundle).map_err(TemplatesError::Deliver)?;
    Ok(TemplatesOutcome::Delivered { version: named })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::super::fetch::fake::FakeFetch;
    use super::super::signature::testkeys::TestKey;
    use super::*;

    const LATEST: &str = "https://releases.example.invalid/beta/templates-latest.json";
    const BUNDLE: &str = "https://releases.example.invalid/v0.3.0/templates.json";

    #[derive(Default)]
    struct Sink(Mutex<Vec<(String, Vec<u8>)>>);

    impl BundleSink for Sink {
        fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
            self.0.lock().unwrap().push((name.to_owned(), bytes.to_vec()));
            Ok(())
        }
    }

    impl Sink {
        fn written(&self) -> Vec<(String, Vec<u8>)> {
            self.0.lock().unwrap().clone()
        }
    }

    fn bundle(version: u64) -> Vec<u8> {
        format!("{{\"bundle_version\":{version},\"min_hub_version\":\"0.2.0\",\"templates\":[]}}\r\n").into_bytes()
    }

    fn serve(f: &FakeFetch, named: u64, bytes: &[u8], sig: &str) {
        f.serve(LATEST, format!("{{\"bundle_version\":{named},\"url\":\"{BUNDLE}\"}}"));
        f.serve(BUNDLE, bytes.to_vec());
        f.serve(&format!("{BUNDLE}.minisig"), sig);
    }

    #[test]
    fn a_newer_bundle_is_verified_and_copied_byte_exact_signature_first() {
        let k = TestKey::new();
        let key = ReleaseKey::parse(&k.public_base64()).unwrap();
        let b = bundle(5);
        let sig = k.sign(&b, &trusted_comment(5));
        for hub in [HubTemplates::Serving(4), HubTemplates::NoneServed] {
            let f = FakeFetch::default();
            serve(&f, 5, &b, &sig);
            let sink = Sink::default();
            let got = check_templates(&f, Some(&key), LATEST, hub, &sink).unwrap();
            assert_eq!(got, TemplatesOutcome::Delivered { version: 5 });
            assert_eq!(
                sink.written(),
                [
                    (SIGNATURE_FILE.to_owned(), sig.clone().into_bytes()),
                    (BUNDLE_FILE.to_owned(), b.clone())
                ]
            );
            // The URLs as published, nothing added (no identifier).
            assert_eq!(
                f.requests(),
                [LATEST.to_owned(), BUNDLE.to_owned(), format!("{BUNDLE}.minisig")]
            );
        }
    }

    #[test]
    fn nothing_is_downloaded_when_the_hub_is_current_or_unknown() {
        let k = TestKey::new();
        let key = ReleaseKey::parse(&k.public_base64()).unwrap();
        for (hub, want) in [
            (
                HubTemplates::Serving(5),
                TemplatesOutcome::UpToDate { hub: 5, latest: 5 },
            ),
            (
                HubTemplates::Serving(9),
                TemplatesOutcome::UpToDate { hub: 9, latest: 5 },
            ),
            (HubTemplates::Unknown, TemplatesOutcome::HubUnknown),
        ] {
            let f = FakeFetch::default();
            serve(&f, 5, &bundle(5), &k.sign(&bundle(5), &trusted_comment(5)));
            let sink = Sink::default();
            assert_eq!(check_templates(&f, Some(&key), LATEST, hub, &sink), Ok(want));
            assert_eq!(f.requests(), [LATEST.to_owned()]);
            assert!(sink.written().is_empty());
        }
    }

    #[test]
    fn a_bundle_that_does_not_verify_or_is_another_version_is_never_written() {
        let k = TestKey::new();
        let key = ReleaseKey::parse(&k.public_base64()).unwrap();
        let other = TestKey::new();
        let cases: Vec<(&str, u64, Vec<u8>, String)> = vec![
            ("another key", 5, bundle(5), other.sign(&bundle(5), &trusted_comment(5))),
            ("other bytes", 5, bundle(5), k.sign(&bundle(6), &trusted_comment(5))),
            (
                "an older bundle under a new number",
                5,
                bundle(3),
                k.sign(&bundle(3), &trusted_comment(3)),
            ),
            (
                "a comment of another version",
                5,
                bundle(5),
                k.sign(&bundle(5), &trusted_comment(4)),
            ),
            (
                "a bundle of another version",
                5,
                bundle(4),
                k.sign(&bundle(4), &trusted_comment(5)),
            ),
            ("not a signature", 5, bundle(5), "nope".into()),
        ];
        for (name, named, b, sig) in cases {
            let f = FakeFetch::default();
            serve(&f, named, &b, &sig);
            let sink = Sink::default();
            let err = check_templates(&f, Some(&key), LATEST, HubTemplates::Serving(1), &sink).unwrap_err();
            assert!(
                matches!(
                    err,
                    TemplatesError::Signature(_) | TemplatesError::VersionMismatch { .. }
                ),
                "{name}: {err:?}"
            );
            assert!(sink.written().is_empty(), "{name}");
        }
    }

    #[test]
    fn only_https_urls_and_valid_answers() {
        let k = TestKey::new();
        let key = ReleaseKey::parse(&k.public_base64()).unwrap();
        let sink = Sink::default();
        let f = FakeFetch::default();
        assert_eq!(
            check_templates(
                &f,
                Some(&key),
                "http://releases.example.invalid/x",
                HubTemplates::NoneServed,
                &sink
            ),
            Err(TemplatesError::BadUrl)
        );
        f.serve(
            LATEST,
            "{\"bundle_version\":5,\"url\":\"http://releases.example.invalid/t.json\"}",
        );
        assert_eq!(
            check_templates(&f, Some(&key), LATEST, HubTemplates::NoneServed, &sink),
            Err(TemplatesError::BadUrl)
        );
        f.serve(LATEST, "{\"bundle_version\":-1}");
        assert_eq!(
            check_templates(&f, Some(&key), LATEST, HubTemplates::NoneServed, &sink),
            Err(TemplatesError::BadLatest)
        );
        f.serve(LATEST, format!("{{\"bundle_version\":5,\"url\":\"{BUNDLE}\"}}"));
        assert_eq!(
            check_templates(&f, None, LATEST, HubTemplates::NoneServed, &sink),
            Err(TemplatesError::NoKey)
        );
        assert!(sink.written().is_empty());
    }
}
