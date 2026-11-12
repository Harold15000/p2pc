// SPDX-License-Identifier: Apache-2.0

//! What a release build compiles in (H2 §14.1, §9.6): the keys, the endpoints and the versions this app trusts. The
//! release pipeline (T2-52) sets them as environment variables at build time, like the node image pin of first run;
//! no key lives in the repository. A build without them (a developer build) checks nothing: each check reports "not
//! available in this version" instead of trusting something else.
//!
//! | Variable | What |
//! |---|---|
//! | `P2PC_UPDATER_PUBKEY` | the updater key, in Tauri's encoding (§14.1) |
//! | `P2PC_UPDATE_ENDPOINT` | the channel's `latest.json` URL (https) |
//! | `P2PC_RELEASE_PUBKEY` | the release key (§5.1): web manifest and template bundle |
//! | `P2PC_TEMPLATES_ENDPOINT` | the channel's `templates-latest.json` URL (https) |
//! | `P2PC_WEB_ORIGIN` | the official web app origin |
//! | `P2PC_WEB_VERSION` | the version of this release's web build (the start of the high-water mark) |
//! | `P2PC_NODE_IMAGE_VERSION` | the pinned node image's version (§8.3; the URL and SHA-256 are first run's pin) |
//! | `P2PC_NODE_IMAGE_MIN_SERVER_VERSION` | the pinned node image's `min_server_version` (§14.2) |

use semver::Version;

/// The compiled-in release values. Each one is `None` when missing or unusable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Release {
    pub updater_pubkey: Option<String>,
    pub update_endpoint: Option<String>,
    pub release_pubkey: Option<String>,
    pub templates_endpoint: Option<String>,
    pub web_origin: Option<String>,
    pub web_version: Option<Version>,
    pub image_version: Option<Version>,
    pub image_min_server_version: Option<Version>,
}

fn non_empty(v: Option<&str>) -> Option<String> {
    v.map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned)
}

fn https_url(v: Option<&str>) -> Option<String> {
    let s = non_empty(v)?;
    let u = url::Url::parse(&s).ok()?;
    (u.scheme() == "https" && u.host_str().is_some()).then_some(s)
}

impl Release {
    /// The values this binary was built with.
    pub fn compiled() -> Self {
        Self::from_values(
            option_env!("P2PC_UPDATER_PUBKEY"),
            option_env!("P2PC_UPDATE_ENDPOINT"),
            option_env!("P2PC_RELEASE_PUBKEY"),
            option_env!("P2PC_TEMPLATES_ENDPOINT"),
            option_env!("P2PC_WEB_ORIGIN"),
            option_env!("P2PC_WEB_VERSION"),
            option_env!("P2PC_NODE_IMAGE_VERSION"),
            option_env!("P2PC_NODE_IMAGE_MIN_SERVER_VERSION"),
        )
    }

    /// From the raw values, each checked.
    #[allow(clippy::too_many_arguments)]
    pub fn from_values(
        updater_pubkey: Option<&str>,
        update_endpoint: Option<&str>,
        release_pubkey: Option<&str>,
        templates_endpoint: Option<&str>,
        web_origin: Option<&str>,
        web_version: Option<&str>,
        image_version: Option<&str>,
        image_min_server_version: Option<&str>,
    ) -> Self {
        let version = |v: Option<&str>| non_empty(v).and_then(|s| Version::parse(&s).ok());
        Self {
            updater_pubkey: non_empty(updater_pubkey),
            update_endpoint: https_url(update_endpoint),
            release_pubkey: non_empty(release_pubkey),
            templates_endpoint: https_url(templates_endpoint),
            web_origin: non_empty(web_origin).and_then(|o| super::web::normalize_origin(&o)),
            web_version: version(web_version),
            image_version: version(image_version),
            image_min_server_version: version(image_min_server_version),
        }
    }

    /// This app's own version.
    pub fn app_version() -> Version {
        Version::parse(env!("CARGO_PKG_VERSION")).unwrap_or_else(|_| Version::new(0, 0, 0))
    }

    /// The web build version the high-water mark starts at: the release's, or the app's own version when the build
    /// does not say.
    pub fn own_web_version(&self) -> Version {
        self.web_version.clone().unwrap_or_else(Self::app_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_checked_and_missing_ones_are_none() {
        let r = Release::from_values(
            Some("key"),
            Some("http://releases.example.invalid/latest.json"),
            Some("  "),
            Some("https://releases.example.invalid/templates-latest.json"),
            Some("https://app.example.invalid/"),
            Some("0.3.0"),
            Some("0.3.1"),
            Some("not a version"),
        );
        assert_eq!(r.updater_pubkey.as_deref(), Some("key"));
        assert_eq!(r.update_endpoint, None, "https only");
        assert_eq!(r.release_pubkey, None);
        assert!(r.templates_endpoint.is_some());
        assert_eq!(r.web_origin.as_deref(), Some("https://app.example.invalid"));
        assert_eq!(r.own_web_version(), Version::new(0, 3, 0));
        assert_eq!(r.image_version, Some(Version::new(0, 3, 1)));
        assert_eq!(r.image_min_server_version, None);
        assert_eq!(Release::default().own_web_version(), Release::app_version());
    }
}
