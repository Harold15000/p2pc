// SPDX-License-Identifier: Apache-2.0

//! Verifying the deployed web app against its signed manifest (H2 §9.6 item 2, SI-H2-22).
//!
//! The app fetches `<origin>/web-manifest.json` and `<origin>/web-manifest.json.minisig`, verifies the signature with the
//! release key compiled into it, then fetches every listed file and compares its SHA-256. It keeps a **high-water mark**,
//! the highest `web_version` it verified; the mark starts at, and on every app update rises to at least, the version of
//! its own release's web build ([`effective_mark`]), and never goes down. When: at start and daily with automatic
//! checks on, otherwise only on "Verify web app" ([`super::policy`]).
//!
//! | What the origin serves | Verdict |
//! |---|---|
//! | a valid signature, `web_version` ≥ the mark, every file matching | [`WebVerdict::Verified`]: the mark rises; a build newer than the app's is a notice; a `min_hub_version` above the local hub is the update-the-hub notice |
//! | no manifest, no signature, a bad one or another key's | [`WebVerdict::NotSigned`]: the warning, or "Not verified: self-built copy" off the official origin |
//! | a valid signature below the mark | [`WebVerdict::Rollback`] |
//! | a valid signature and a file that does not match (or is missing) | [`WebVerdict::Tampered`]: the red warning |
//! | no answer (DNS, TLS, timeout, a 5xx) | [`WebVerdict::Unreachable`]: nothing is concluded; the mark stays |
//!
//! It detects untargeted tampering only: a host can serve different bytes to different clients (§9.6).
//!
//! The manifest's shape (T2-34 writes it): `{"web_version": "<semver>", "min_hub_version": "<semver>", "files":
//! [{"path": "<relative path>", "sha256": "<64 hex>"}, …]}`; unknown fields are ignored. Every listed path is checked
//! before anything is fetched: relative, `/`-separated, of `[A-Za-z0-9._~-]` segments, none empty, `.` or `..`.

use p2pc_wsl::image::Sha256Digest;
use semver::Version;
use serde::{Deserialize, Serialize};

use super::fetch::{Fetch, FetchError};
use super::signature::ReleaseKey;

/// The manifest's path at the origin.
pub const MANIFEST_PATH: &str = "web-manifest.json";
/// Its signature's.
pub const SIGNATURE_PATH: &str = "web-manifest.json.minisig";
/// The largest manifest read.
pub const MAX_MANIFEST_BYTES: u64 = 1 << 20;
/// The largest signature read.
pub const MAX_SIGNATURE_BYTES: u64 = 4096;
/// The largest web app file read.
pub const MAX_FILE_BYTES: u64 = 64 << 20;
/// The most files a manifest may list.
pub const MAX_FILES: usize = 10_000;

/// One listed file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ManifestFile {
    pub path: String,
    pub sha256: String,
}

/// `web-manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WebManifest {
    pub web_version: String,
    pub min_hub_version: String,
    pub files: Vec<ManifestFile>,
}

/// What the app concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum WebVerdict {
    Verified {
        version: String,
        /// Newer than the web build of this app's release: a notice, never the tampering warning.
        newer_than_app: bool,
        /// The build needs a newer hub than this PC's (hub PC only).
        hub_too_old: bool,
    },
    /// Missing, unsigned, badly signed or signed with another key.
    NotSigned {
        /// `web_app_origin` is not the official origin: "Not verified: self-built copy", without the warning.
        self_built: bool,
    },
    /// Validly signed, but older than a build this app already verified.
    Rollback { version: String, mark: String },
    /// Validly signed, and a file does not match (or is missing).
    Tampered { path: String },
    /// No answer: nothing concluded.
    Unreachable { reason: String },
    /// This build has no release key compiled in.
    NoKey,
}

/// What the window may offer with a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Offer {
    /// Use a self-hosted copy (`web_app_origin`, §9.6 item 3).
    SelfHostedCopy,
    /// Revoke the phone devices (§5.5).
    RevokePhones,
}

impl WebVerdict {
    /// The fixed sentences (§9.6), for the origin that was checked.
    pub fn messages(&self, origin: &str) -> Vec<String> {
        match self {
            WebVerdict::Verified {
                newer_than_app,
                hub_too_old,
                ..
            } => {
                let mut m = vec![format!(
                    "The web app at {origin} is a signed P2PC build and matches it."
                )];
                if *newer_than_app {
                    m.push("The web app is newer than this app.".to_owned());
                }
                if *hub_too_old {
                    m.push("Your phone's web app needs a newer hub: update P2PC on this PC.".to_owned());
                }
                m
            }
            WebVerdict::NotSigned { self_built: true } => vec!["Not verified: self-built copy".to_owned()],
            WebVerdict::NotSigned { self_built: false } => {
                vec![format!("The web app at {origin} is not a signed P2PC build")]
            }
            WebVerdict::Rollback { .. } => {
                vec![format!(
                    "The web app at {origin} is older than one this app has already verified"
                )]
            }
            WebVerdict::Tampered { path } => vec![format!(
                "The web app at {origin} does not match its signed build ({path}): it may have been tampered with. Do not use it on your phone until this is solved."
            )],
            WebVerdict::Unreachable { .. } => vec![format!("Could not reach the web app at {origin} to verify it.")],
            WebVerdict::NoKey => vec!["Web app verification is not available in this version.".to_owned()],
        }
    }

    /// What the window offers with it.
    pub fn offers(&self) -> Vec<Offer> {
        match self {
            WebVerdict::NotSigned { self_built: false } | WebVerdict::Tampered { .. } => {
                vec![Offer::SelfHostedCopy, Offer::RevokePhones]
            }
            WebVerdict::Rollback { .. } => vec![Offer::SelfHostedCopy],
            _ => Vec::new(),
        }
    }

    /// A warning (as opposed to a notice or nothing).
    pub fn is_warning(&self) -> bool {
        matches!(
            self,
            WebVerdict::NotSigned { self_built: false } | WebVerdict::Rollback { .. } | WebVerdict::Tampered { .. }
        )
    }
}

/// What one check needs.
#[derive(Debug, Clone)]
pub struct WebCheck<'a> {
    /// The configured `web_app_origin`.
    pub origin: &'a str,
    /// The official origin compiled into the app (`None` in a build without one: every origin is then self-built).
    pub official_origin: Option<&'a str>,
    /// The web build version of this app's release.
    pub own_web_version: &'a Version,
    /// The stored high-water mark.
    pub stored_mark: Option<&'a str>,
    /// The local hub's version (hub PC only).
    pub local_hub_version: Option<&'a Version>,
}

/// The result: the verdict and the mark to store (`None`: leave it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebResult {
    pub verdict: WebVerdict,
    pub new_mark: Option<String>,
}

/// The mark in force: the stored one, never below the app's own release's web build.
pub fn effective_mark(stored: Option<&str>, own: &Version) -> Version {
    stored
        .and_then(|s| Version::parse(s).ok())
        .filter(|m| m > own)
        .unwrap_or_else(|| own.clone())
}

/// The origin as `https://host[:port]`, without a trailing slash; `None` for anything else (a path, a query, another
/// scheme, user info).
pub fn normalize_origin(origin: &str) -> Option<String> {
    let url = url::Url::parse(origin.trim()).ok()?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

/// A listed path that can be fetched as it is under the origin.
pub fn is_safe_manifest_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && path.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
        })
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256Digest::of(bytes).to_hex()
}

/// A signed manifest whose content the app can use.
fn parse_manifest(bytes: &[u8]) -> Option<(WebManifest, Version, Version)> {
    let m: WebManifest = serde_json::from_slice(bytes).ok()?;
    let version = Version::parse(&m.web_version).ok()?;
    let min_hub = Version::parse(&m.min_hub_version).ok()?;
    let files_ok = !m.files.is_empty()
        && m.files.len() <= MAX_FILES
        && m.files.iter().all(|f| {
            is_safe_manifest_path(&f.path) && f.sha256.len() == 64 && f.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        });
    files_ok.then_some((m, version, min_hub))
}

/// One check (§9.6 item 2). Blocking.
pub fn verify_web_app(fetch: &dyn Fetch, key: Option<&ReleaseKey>, check: &WebCheck<'_>) -> WebResult {
    let keep = |verdict| WebResult {
        verdict,
        new_mark: None,
    };
    let Some(origin) = normalize_origin(check.origin) else {
        return keep(WebVerdict::Unreachable {
            reason: "the web app origin is not an https origin".to_owned(),
        });
    };
    let Some(key) = key else {
        return keep(WebVerdict::NoKey);
    };
    let self_built = check
        .official_origin
        .and_then(normalize_origin)
        .is_none_or(|official| official != origin);
    let not_signed = WebVerdict::NotSigned { self_built };
    let unreachable = |e: FetchError| WebVerdict::Unreachable { reason: e.to_string() };

    let manifest = match fetch.get(&format!("{origin}/{MANIFEST_PATH}"), MAX_MANIFEST_BYTES) {
        Ok(b) => b,
        Err(FetchError::NotFound | FetchError::TooLarge(_)) => return keep(not_signed),
        Err(e) => return keep(unreachable(e)),
    };
    let signature = match fetch.get(&format!("{origin}/{SIGNATURE_PATH}"), MAX_SIGNATURE_BYTES) {
        Ok(b) => b,
        Err(FetchError::NotFound | FetchError::TooLarge(_)) => return keep(not_signed),
        Err(e) => return keep(unreachable(e)),
    };
    let Ok(signature) = String::from_utf8(signature) else {
        return keep(not_signed);
    };
    if key.verify(&manifest, &signature).is_err() {
        return keep(not_signed);
    }
    // Signed by the release key: only now is the content used.
    let Some((m, version, min_hub)) = parse_manifest(&manifest) else {
        return keep(not_signed);
    };
    let mark = effective_mark(check.stored_mark, check.own_web_version);
    if version < mark {
        return keep(WebVerdict::Rollback {
            version: version.to_string(),
            mark: mark.to_string(),
        });
    }
    for f in &m.files {
        let body = match fetch.get(&format!("{origin}/{}", f.path), MAX_FILE_BYTES) {
            Ok(b) => b,
            Err(FetchError::Network(e)) => return keep(unreachable(FetchError::Network(e))),
            Err(_) => return keep(WebVerdict::Tampered { path: f.path.clone() }),
        };
        if !sha256_hex(&body).eq_ignore_ascii_case(&f.sha256) {
            return keep(WebVerdict::Tampered { path: f.path.clone() });
        }
    }
    WebResult {
        verdict: WebVerdict::Verified {
            version: version.to_string(),
            newer_than_app: version > *check.own_web_version,
            hub_too_old: check.local_hub_version.is_some_and(|hub| min_hub > *hub),
        },
        new_mark: Some(mark.max(version).to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::fetch::fake::FakeFetch;
    use super::super::policy::{UpdateState, UpdateStateFile};
    use super::super::signature::testkeys::TestKey;
    use super::*;

    const ORIGIN: &str = "https://app.example.invalid";

    struct Build {
        manifest: Vec<u8>,
        files: Vec<(String, Vec<u8>)>,
    }

    fn build(version: &str, min_hub: &str) -> Build {
        let files = vec![
            (
                "index.html".to_owned(),
                format!("<!doctype html><title>{version}</title>").into_bytes(),
            ),
            ("assets/app-1a2b.js".to_owned(), b"export const x = 1;\n".to_vec()),
            ("p2pc_device_bg.wasm".to_owned(), vec![0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]),
        ];
        let listed: Vec<serde_json::Value> = files
            .iter()
            .map(|(p, b)| serde_json::json!({"path": p, "sha256": sha256_hex(b)}))
            .collect();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "web_version": version, "min_hub_version": min_hub, "files": listed, "future_field": true
        }))
        .unwrap();
        Build { manifest, files }
    }

    fn serve(fetch: &FakeFetch, origin: &str, b: &Build, signature: Option<&str>) {
        fetch.serve(&format!("{origin}/{MANIFEST_PATH}"), b.manifest.clone());
        if let Some(sig) = signature {
            fetch.serve(&format!("{origin}/{SIGNATURE_PATH}"), sig);
        }
        for (p, bytes) in &b.files {
            fetch.serve(&format!("{origin}/{p}"), bytes.clone());
        }
    }

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn check<'a>(own: &'a Version, mark: Option<&'a str>, hub: Option<&'a Version>) -> WebCheck<'a> {
        WebCheck {
            origin: ORIGIN,
            official_origin: Some(ORIGIN),
            own_web_version: own,
            stored_mark: mark,
            local_hub_version: hub,
        }
    }

    /// SI-H2-22, every outcome in order, with the mark persisted across an app restart.
    #[test]
    fn the_web_app_verification_accepts_only_signed_builds_at_or_above_its_mark() {
        let k = TestKey::new();
        let key = ReleaseKey::parse(&k.public_base64()).unwrap();
        let own = v("0.2.0");
        let dir = tempfile::tempdir().unwrap();
        let store = UpdateStateFile::in_dir(dir.path());

        // The app's own build: verified, no notice, the mark is the app's.
        let fetch = FakeFetch::default();
        let b = build("0.2.0", "0.2.0");
        serve(&fetch, ORIGIN, &b, Some(&k.sign(&b.manifest, "web")));
        let r = verify_web_app(&fetch, Some(&key), &check(&own, None, None));
        assert_eq!(
            r.verdict,
            WebVerdict::Verified {
                version: "0.2.0".into(),
                newer_than_app: false,
                hub_too_old: false
            }
        );
        assert_eq!(r.new_mark.as_deref(), Some("0.2.0"));
        assert!(fetch.requests().iter().any(|u| u.ends_with("/p2pc_device_bg.wasm")));

        // A newer valid build: verified, a notice (never the warning), and the mark rises; it is persisted.
        let fetch = FakeFetch::default();
        let b = build("0.2.1", "0.2.0");
        serve(&fetch, ORIGIN, &b, Some(&k.sign(&b.manifest, "web")));
        let r = verify_web_app(&fetch, Some(&key), &check(&own, Some("0.2.0"), None));
        assert!(matches!(
            r.verdict,
            WebVerdict::Verified {
                newer_than_app: true,
                ..
            }
        ));
        assert!(!r.verdict.is_warning());
        assert!(
            r.verdict
                .messages(ORIGIN)
                .contains(&"The web app is newer than this app.".to_owned())
        );
        let mut state = UpdateState::default();
        state.web_mark = r.new_mark;
        store.save(&state).unwrap();

        // Then the previous build, validly signed: the rollback warning, also after a restart (the mark is read back).
        let restarted = store.load();
        let fetch = FakeFetch::default();
        let b = build("0.2.0", "0.2.0");
        serve(&fetch, ORIGIN, &b, Some(&k.sign(&b.manifest, "web")));
        let r = verify_web_app(&fetch, Some(&key), &check(&own, restarted.web_mark.as_deref(), None));
        assert_eq!(
            r.verdict,
            WebVerdict::Rollback {
                version: "0.2.0".into(),
                mark: "0.2.1".into()
            }
        );
        assert_eq!(r.new_mark, None, "the mark never goes down");
        assert_eq!(
            r.verdict.messages(ORIGIN),
            [format!(
                "The web app at {ORIGIN} is older than one this app has already verified"
            )]
        );
        assert_eq!(r.verdict.offers(), [Offer::SelfHostedCopy]);
        assert!(
            !fetch.requests().iter().any(|u| u.ends_with("index.html")),
            "no file is fetched"
        );
    }

    #[test]
    fn missing_bad_or_foreign_signatures_are_the_unsigned_warning_or_a_self_built_copy() {
        let k = TestKey::new();
        let key = ReleaseKey::parse(&k.public_base64()).unwrap();
        let own = v("0.2.0");
        let b = build("0.2.0", "0.2.0");
        let other = TestKey::new().sign(&b.manifest, "web");
        let cases: Vec<(&str, Option<String>, bool)> = vec![
            ("no manifest", None, true),
            ("no signature", None, false),
            ("another key", Some(other), false),
            ("not a signature", Some("hello".into()), false),
            ("signature of other bytes", Some(k.sign(b"other", "web")), false),
        ];
        for (name, sig, drop_manifest) in cases {
            for (origin, official, self_built) in [
                (ORIGIN, Some(ORIGIN), false),
                ("https://mine.example.invalid", Some(ORIGIN), true),
                (ORIGIN, None, true),
            ] {
                let fetch = FakeFetch::default();
                if !drop_manifest {
                    serve(&fetch, origin, &b, sig.as_deref());
                }
                let c = WebCheck {
                    origin,
                    official_origin: official,
                    ..check(&own, None, None)
                };
                let r = verify_web_app(&fetch, Some(&key), &c);
                assert_eq!(r.verdict, WebVerdict::NotSigned { self_built }, "{name} at {origin}");
                assert_eq!(r.new_mark, None);
                if self_built {
                    assert_eq!(r.verdict.messages(origin), ["Not verified: self-built copy"]);
                    assert!(!r.verdict.is_warning());
                } else {
                    assert_eq!(
                        r.verdict.messages(origin),
                        [format!("The web app at {origin} is not a signed P2PC build")]
                    );
                    assert_eq!(r.verdict.offers(), [Offer::SelfHostedCopy, Offer::RevokePhones]);
                }
            }
        }
    }

    #[test]
    fn one_changed_or_missing_file_is_the_red_warning() {
        let k = TestKey::new();
        let key = ReleaseKey::parse(&k.public_base64()).unwrap();
        let own = v("0.2.0");
        let b = build("0.2.0", "0.2.0");
        let fetch = FakeFetch::default();
        serve(&fetch, ORIGIN, &b, Some(&k.sign(&b.manifest, "web")));
        fetch.serve(
            &format!("{ORIGIN}/assets/app-1a2b.js"),
            b"fetch('https://evil.example.invalid')".to_vec(),
        );
        let r = verify_web_app(&fetch, Some(&key), &check(&own, None, None));
        assert_eq!(
            r.verdict,
            WebVerdict::Tampered {
                path: "assets/app-1a2b.js".into()
            }
        );
        assert!(r.verdict.is_warning());
        assert_eq!(r.new_mark, None);
        assert_eq!(r.verdict.offers(), [Offer::SelfHostedCopy, Offer::RevokePhones]);

        let fetch = FakeFetch::default();
        serve(&fetch, ORIGIN, &b, Some(&k.sign(&b.manifest, "web")));
        fetch.fail(&format!("{ORIGIN}/index.html"), FetchError::NotFound);
        let r = verify_web_app(&fetch, Some(&key), &check(&own, None, None));
        assert_eq!(
            r.verdict,
            WebVerdict::Tampered {
                path: "index.html".into()
            }
        );
    }

    #[test]
    fn a_build_that_needs_a_newer_hub_says_so() {
        let k = TestKey::new();
        let key = ReleaseKey::parse(&k.public_base64()).unwrap();
        let own = v("0.2.0");
        let b = build("0.2.0", "0.3.0");
        let fetch = FakeFetch::default();
        serve(&fetch, ORIGIN, &b, Some(&k.sign(&b.manifest, "web")));
        let hub = v("0.2.5");
        let r = verify_web_app(&fetch, Some(&key), &check(&own, None, Some(&hub)));
        assert!(matches!(r.verdict, WebVerdict::Verified { hub_too_old: true, .. }));
        assert!(
            r.verdict
                .messages(ORIGIN)
                .contains(&"Your phone's web app needs a newer hub: update P2PC on this PC.".to_owned())
        );
        // A joined PC (no local hub) says nothing about it.
        let r = verify_web_app(&fetch, Some(&key), &check(&own, None, None));
        assert!(matches!(r.verdict, WebVerdict::Verified { hub_too_old: false, .. }));
    }

    #[test]
    fn no_answer_concludes_nothing() {
        let k = TestKey::new();
        let key = ReleaseKey::parse(&k.public_base64()).unwrap();
        let own = v("0.2.0");
        let fetch = FakeFetch::default();
        fetch.fail(
            &format!("{ORIGIN}/{MANIFEST_PATH}"),
            FetchError::Network("timeout".into()),
        );
        let r = verify_web_app(&fetch, Some(&key), &check(&own, None, None));
        assert!(matches!(r.verdict, WebVerdict::Unreachable { .. }));
        assert!(!r.verdict.is_warning());
        let fetch = FakeFetch::default();
        fetch.fail(&format!("{ORIGIN}/{MANIFEST_PATH}"), FetchError::Status(503));
        assert!(matches!(
            verify_web_app(&fetch, Some(&key), &check(&own, None, None)).verdict,
            WebVerdict::Unreachable { .. }
        ));
        assert_eq!(
            verify_web_app(&fetch, None, &check(&own, None, None)).verdict,
            WebVerdict::NoKey
        );
    }

    #[test]
    fn a_signed_manifest_with_an_unsafe_path_is_not_used() {
        let k = TestKey::new();
        let key = ReleaseKey::parse(&k.public_base64()).unwrap();
        let own = v("0.2.0");
        for path in [
            "../secret",
            "/etc/passwd",
            "a//b",
            "a/./b",
            "a?x=1",
            "a#b",
            "%2e%2e/x",
            "a\\b",
            "",
        ] {
            let manifest = serde_json::to_vec(&serde_json::json!({
                "web_version": "0.2.0", "min_hub_version": "0.2.0",
                "files": [{"path": path, "sha256": "ab".repeat(32)}]
            }))
            .unwrap();
            let fetch = FakeFetch::default();
            fetch.serve(&format!("{ORIGIN}/{MANIFEST_PATH}"), manifest.clone());
            fetch.serve(&format!("{ORIGIN}/{SIGNATURE_PATH}"), k.sign(&manifest, "web"));
            let r = verify_web_app(&fetch, Some(&key), &check(&own, None, None));
            assert!(matches!(r.verdict, WebVerdict::NotSigned { .. }), "{path}");
            assert_eq!(fetch.requests().len(), 2, "{path}: nothing else fetched");
        }
        assert!(is_safe_manifest_path("assets/app-1a2b.js"));
    }

    #[test]
    fn origins_and_marks() {
        assert_eq!(
            normalize_origin("https://app.example.invalid/").as_deref(),
            Some(ORIGIN)
        );
        assert_eq!(
            normalize_origin("https://app.example.invalid:8443").as_deref(),
            Some("https://app.example.invalid:8443")
        );
        for bad in [
            "http://app.example.invalid",
            "https://app.example.invalid/pair",
            "https://u:p@app.example.invalid",
            "https://app.example.invalid/?x",
            "file:///c:/web",
            "app.example.invalid",
        ] {
            assert_eq!(normalize_origin(bad), None, "{bad}");
        }
        let own = v("0.2.0");
        assert_eq!(effective_mark(None, &own), own);
        assert_eq!(
            effective_mark(Some("0.1.0"), &own),
            own,
            "never below the app's own release"
        );
        assert_eq!(effective_mark(Some("0.3.0"), &own), v("0.3.0"));
        assert_eq!(effective_mark(Some("garbage"), &own), own);
    }
}
