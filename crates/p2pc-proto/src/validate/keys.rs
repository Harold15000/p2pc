// SPDX-License-Identifier: Apache-2.0

//! Validation of the admin request bodies `POST /v1/keys` ([`CreateApiKey`]) and `POST /v1/nodes/join-tokens`
//! ([`CreateJoinToken`]), plus the pure no-escalation check of spec §5 ([`check_no_escalation`]).
//!
//! The validators return [`ValidationErrors`] with field paths, like [`JobSpec::validate`](crate::api::JobSpec):
//! the server answers `422`. A no-escalation violation is a `403 escalation_denied` instead, so it has its own error.

use std::collections::BTreeSet;
use std::fmt;

use time::OffsetDateTime;

use super::glob::validate_pattern;
use super::{Collector, ErrorCode, ValidationErrors};
use crate::api::{ApiKeyInfo, CreateApiKey, CreateJoinToken, Scope};
use crate::auth::MAX_JOIN_TOKEN_TTL;

/// Longest `label`, in characters.
pub const MAX_LABEL_CHARS: usize = 64;
/// Most `allowed_images` patterns on one key.
pub const MAX_ALLOWED_IMAGES: usize = 32;
/// Longest `allowed_images` pattern, in bytes.
pub const MAX_IMAGE_PATTERN_LEN: usize = 256;
/// The `code` of the `403` for a key-creation request that asks for more than its creator has (§5).
pub const ESCALATION_DENIED: &str = "escalation_denied";

/// `label`: 1-64 characters, no control characters.
fn check_label(label: Option<&str>, c: &mut Collector) {
    let Some(label) = label else { return };
    if label.is_empty() || label.chars().any(char::is_control) {
        c.push(
            "label",
            ErrorCode::InvalidFormat,
            "must be non-empty, without control characters",
        );
    } else if label.chars().count() > MAX_LABEL_CHARS {
        c.push(
            "label",
            ErrorCode::TooLarge,
            format!("must be at most {MAX_LABEL_CHARS} characters"),
        );
    }
}

impl CreateApiKey {
    /// Validates a key-creation request. `now` is injectable, for `expires_at`.
    ///
    /// - `label`: 1-64 characters, no control characters.
    /// - `scopes`: not empty, no duplicates (only known values deserialize at all).
    /// - `allowed_images`: at most 32 distinct patterns of 1-256 bytes with valid syntax (`*` and `**` only).
    ///   `None` allows every image; `Some([])` allows none.
    /// - `expires_at`: strictly after `now`.
    pub fn validate(&self, now: OffsetDateTime) -> Result<(), ValidationErrors> {
        let mut c = Collector(Vec::new());
        check_label(self.label.as_deref(), &mut c);
        if self.scopes.is_empty() {
            c.push("scopes", ErrorCode::OutOfRange, "must contain at least one scope");
        }
        let mut seen = BTreeSet::new();
        for (i, scope) in self.scopes.iter().enumerate() {
            if !seen.insert(*scope) {
                c.push(
                    format!("scopes[{i}]"),
                    ErrorCode::Duplicate,
                    "the same scope appears twice",
                );
            }
        }
        if let Some(patterns) = &self.allowed_images {
            if patterns.len() > MAX_ALLOWED_IMAGES {
                c.push(
                    "allowed_images",
                    ErrorCode::TooMany,
                    format!("at most {MAX_ALLOWED_IMAGES} patterns"),
                );
            } else {
                let mut seen = BTreeSet::new();
                for (i, p) in patterns.iter().enumerate() {
                    let field = format!("allowed_images[{i}]");
                    if p.len() > MAX_IMAGE_PATTERN_LEN {
                        c.push(
                            field,
                            ErrorCode::TooLarge,
                            format!("at most {MAX_IMAGE_PATTERN_LEN} bytes"),
                        );
                    } else if let Err(e) = validate_pattern(p) {
                        c.push(field, ErrorCode::InvalidFormat, e.to_string());
                    } else if !seen.insert(p.as_str()) {
                        c.push(field, ErrorCode::Duplicate, "the same pattern appears twice");
                    }
                }
            }
        }
        if self.expires_at.is_some_and(|at| at <= now) {
            c.push("expires_at", ErrorCode::OutOfRange, "must be in the future");
        }
        c.finish()
    }
}

impl CreateJoinToken {
    /// Validates a join-token request: `label` as for keys, and `ttl_s` from 1 to 86 400 (24 h) when given.
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut c = Collector(Vec::new());
        check_label(self.label.as_deref(), &mut c);
        let max = u32::try_from(MAX_JOIN_TOKEN_TTL.whole_seconds()).unwrap_or(u32::MAX);
        if self.ttl_s.is_some_and(|t| !(1..=max).contains(&t)) {
            c.push("ttl_s", ErrorCode::OutOfRange, format!("must be 1-{max} seconds"));
        }
        c.finish()
    }
}

/// A key-creation request that asks for more power than its creator has (§5 "No escalation"). The server answers
/// `403` with code [`ESCALATION_DENIED`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct EscalationDenied {
    /// The request fields that exceed the creator: `scopes`, `daily_unit_cap`, `allowed_images` and/or `expires_at`.
    pub fields: Vec<&'static str>,
}

impl fmt::Display for EscalationDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{ESCALATION_DENIED}: {}", self.fields.join(", "))
    }
}

/// The §5 no-escalation rule, as a pure function. A key can never create a key with more power than it has:
/// - the new key's scopes are a subset of the creator's (`admin` covers every scope);
/// - if the creator has a `daily_unit_cap`, the new key has one too, at or below it;
/// - if the creator has `allowed_images`, the new key has a list made only of the creator's patterns, compared
///   exactly;
/// - if the creator has `expires_at`, the new key has one too, at or before the creator's (a longer life is more
///   power).
///
/// Every violated rule is listed. The server still checks that the creator key is valid (not revoked or expired).
pub fn check_no_escalation(creator: &ApiKeyInfo, request: &CreateApiKey) -> Result<(), EscalationDenied> {
    let mut fields = Vec::new();
    let creator_is_admin = creator.scopes.contains(&Scope::Admin);
    if !creator_is_admin && !request.scopes.iter().all(|s| creator.scopes.contains(s)) {
        fields.push("scopes");
    }
    if let Some(cap) = creator.daily_unit_cap
        && request.daily_unit_cap.is_none_or(|asked| asked > cap)
    {
        fields.push("daily_unit_cap");
    }
    if let Some(allowed) = &creator.allowed_images {
        let within = request
            .allowed_images
            .as_ref()
            .is_some_and(|asked| asked.iter().all(|p| allowed.contains(p)));
        if !within {
            fields.push("allowed_images");
        }
    }
    // §5 (0658bbe): a longer life is more power.
    if let Some(limit) = creator.expires_at
        && request.expires_at.is_none_or(|asked| asked > limit)
    {
        fields.push("expires_at");
    }
    if fields.is_empty() {
        Ok(())
    } else {
        Err(EscalationDenied { fields })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::units::Units;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-05 10:00:00 UTC);

    fn req() -> CreateApiKey {
        CreateApiKey {
            label: Some("ci".into()),
            scopes: vec![Scope::JobsWrite, Scope::JobsRead],
            expires_at: Some(datetime!(2027-01-01 00:00:00 UTC)),
            daily_unit_cap: Some(Units::from_units(5)),
            allowed_images: Some(vec!["docker.io/library/python:*".into(), "ghcr.io/me/**".into()]),
        }
    }

    fn with(f: impl FnOnce(&mut CreateApiKey)) -> CreateApiKey {
        let mut r = req();
        f(&mut r);
        r
    }

    #[test]
    fn create_api_key_valid_cases() {
        let cases = [
            req(),
            with(|r| r.label = None),
            with(|r| r.label = Some("é".repeat(64))),
            with(|r| r.expires_at = None),
            with(|r| r.allowed_images = None),
            with(|r| r.allowed_images = Some(vec![])),
            with(|r| r.allowed_images = Some((0..32).map(|i| format!("ghcr.io/me/app{i}:*")).collect())),
            with(|r| r.allowed_images = Some(vec![format!("{}*", "a".repeat(255))])),
            with(|r| r.expires_at = Some(NOW + time::Duration::seconds(1))),
            with(|r| r.scopes = vec![Scope::Admin]),
        ];
        for (i, r) in cases.iter().enumerate() {
            assert_eq!(r.validate(NOW), Ok(()), "case {i}");
        }
    }

    #[test]
    fn create_api_key_invalid_cases() {
        use ErrorCode::*;
        let cases: Vec<(CreateApiKey, &str, ErrorCode)> = vec![
            (with(|r| r.label = Some("x".repeat(65))), "label", TooLarge),
            (with(|r| r.label = Some(String::new())), "label", InvalidFormat),
            (with(|r| r.label = Some("evil\u{1b}[2J".into())), "label", InvalidFormat),
            (with(|r| r.scopes.clear()), "scopes", OutOfRange),
            (with(|r| r.scopes.push(Scope::JobsWrite)), "scopes[2]", Duplicate),
            (
                with(|r| r.allowed_images = Some((0..33).map(|i| format!("a{i}")).collect())),
                "allowed_images",
                TooMany,
            ),
            (
                with(|r| r.allowed_images = Some(vec!["a".repeat(257)])),
                "allowed_images[0]",
                TooLarge,
            ),
            (
                with(|r| r.allowed_images = Some(vec![String::new()])),
                "allowed_images[0]",
                InvalidFormat,
            ),
            (
                with(|r| r.allowed_images = Some(vec!["ghcr.io/me/ app".into()])),
                "allowed_images[0]",
                InvalidFormat,
            ),
            (
                with(|r| r.allowed_images = Some(vec!["ghcr.io/m?/app".into()])),
                "allowed_images[0]",
                InvalidFormat,
            ),
            (
                with(|r| r.allowed_images = Some(vec!["ghcr.io/[ab]/x".into()])),
                "allowed_images[0]",
                InvalidFormat,
            ),
            (
                with(|r| r.allowed_images = Some(vec!["ghcr.io/***".into()])),
                "allowed_images[0]",
                InvalidFormat,
            ),
            (
                with(|r| r.allowed_images = Some(vec!["ghcr.io/é".into()])),
                "allowed_images[0]",
                InvalidFormat,
            ),
            (
                with(|r| r.allowed_images = Some(vec!["a/*".into(), "a/*".into()])),
                "allowed_images[1]",
                Duplicate,
            ),
            (with(|r| r.expires_at = Some(NOW)), "expires_at", OutOfRange),
            (
                with(|r| r.expires_at = Some(datetime!(2020-01-01 00:00:00 UTC))),
                "expires_at",
                OutOfRange,
            ),
        ];
        for (r, field, code) in cases {
            let errs = r.validate(NOW).unwrap_err();
            assert!(errs.contains(field, code), "{field} {code}: {errs}");
            assert_eq!(errs.len(), 1, "{field}: {errs}");
        }
    }

    #[test]
    fn create_join_token_cases() {
        let t = |label: Option<&str>, ttl_s: Option<u32>| CreateJoinToken {
            label: label.map(String::from),
            ttl_s,
        };
        for ok in [
            t(None, None),
            t(Some("laptop"), Some(1)),
            t(None, Some(86_400)),
            t(Some(&"x".repeat(64)), None),
        ] {
            assert_eq!(ok.validate(), Ok(()), "{ok:?}");
        }
        let bad = [
            (t(None, Some(0)), "ttl_s", ErrorCode::OutOfRange),
            (t(None, Some(86_401)), "ttl_s", ErrorCode::OutOfRange),
            (t(Some(&"x".repeat(65)), None), "label", ErrorCode::TooLarge),
            (t(Some("a\nb"), None), "label", ErrorCode::InvalidFormat),
        ];
        for (r, field, code) in bad {
            let errs = r.validate().unwrap_err();
            assert!(errs.contains(field, code), "{field}: {errs}");
        }
    }

    fn creator(scopes: Vec<Scope>, cap: Option<u64>, images: Option<Vec<&str>>) -> ApiKeyInfo {
        ApiKeyInfo {
            id: "abcdefgh2345".parse().unwrap(),
            project_id: "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            label: None,
            scopes,
            daily_unit_cap: cap.map(Units::from_units),
            allowed_images: images.map(|v| v.into_iter().map(String::from).collect()),
            created_at: NOW,
            expires_at: None,
            last_used_at: None,
            revoked_at: None,
        }
    }

    fn ask(scopes: Vec<Scope>, cap: Option<u64>, images: Option<Vec<&str>>) -> CreateApiKey {
        CreateApiKey {
            label: None,
            scopes,
            expires_at: None,
            daily_unit_cap: cap.map(Units::from_units),
            allowed_images: images.map(|v| v.into_iter().map(String::from).collect()),
        }
    }

    #[test]
    fn no_escalation_scopes() {
        use Scope::*;
        let admin = creator(vec![Admin], None, None);
        assert_eq!(
            check_no_escalation(&admin, &ask(vec![Admin, NodesWrite], None, None)),
            Ok(())
        );
        let rw = creator(vec![JobsWrite, JobsRead], None, None);
        assert_eq!(check_no_escalation(&rw, &ask(vec![JobsRead], None, None)), Ok(()));
        assert_eq!(
            check_no_escalation(&rw, &ask(vec![JobsWrite, JobsRead], None, None)),
            Ok(())
        );
        for asked in [vec![Admin], vec![JobsRead, NodesRead], vec![NodesWrite]] {
            let denied = check_no_escalation(&rw, &ask(asked.clone(), None, None)).unwrap_err();
            assert_eq!(denied.fields, ["scopes"], "{asked:?}");
        }
    }

    #[test]
    fn no_escalation_cap() {
        let capped = creator(vec![Scope::Admin], Some(5), None);
        assert_eq!(
            check_no_escalation(&capped, &ask(vec![Scope::JobsRead], Some(5), None)),
            Ok(())
        );
        assert_eq!(
            check_no_escalation(&capped, &ask(vec![Scope::JobsRead], Some(1), None)),
            Ok(())
        );
        for asked in [None, Some(6)] {
            let denied = check_no_escalation(&capped, &ask(vec![Scope::JobsRead], asked, None)).unwrap_err();
            assert_eq!(denied.fields, ["daily_unit_cap"], "{asked:?}");
        }
        // An uncapped creator may set any cap, or none.
        let free = creator(vec![Scope::Admin], None, None);
        assert_eq!(
            check_no_escalation(&free, &ask(vec![Scope::JobsRead], None, None)),
            Ok(())
        );
    }

    #[test]
    fn no_escalation_images() {
        let limited = creator(
            vec![Scope::Admin],
            None,
            Some(vec!["docker.io/library/*", "ghcr.io/me/**"]),
        );
        let ok = ask(vec![Scope::JobsRead], None, Some(vec!["ghcr.io/me/**"]));
        assert_eq!(check_no_escalation(&limited, &ok), Ok(()));
        assert_eq!(
            check_no_escalation(&limited, &ask(vec![Scope::JobsRead], None, Some(vec![]))),
            Ok(())
        );
        for asked in [
            None,
            Some(vec!["docker.io/**"]),
            Some(vec!["ghcr.io/me/**", "quay.io/*"]),
        ] {
            let denied = check_no_escalation(&limited, &ask(vec![Scope::JobsRead], None, asked.clone())).unwrap_err();
            assert_eq!(denied.fields, ["allowed_images"], "{asked:?}");
        }
    }

    /// Spec §5 (0658bbe): a longer life is more power.
    #[test]
    fn no_escalation_expiry() {
        let mut expiring = creator(vec![Scope::Admin], None, None);
        expiring.expires_at = Some(datetime!(2027-01-01 00:00:00 UTC));
        let with_expiry = |at: Option<OffsetDateTime>| CreateApiKey {
            expires_at: at,
            ..ask(vec![Scope::JobsRead], None, None)
        };
        for ok in [datetime!(2027-01-01 00:00:00 UTC), datetime!(2026-12-01 00:00:00 UTC)] {
            assert_eq!(check_no_escalation(&expiring, &with_expiry(Some(ok))), Ok(()), "{ok}");
        }
        for asked in [None, Some(datetime!(2027-01-01 00:00:01 UTC))] {
            let denied = check_no_escalation(&expiring, &with_expiry(asked)).unwrap_err();
            assert_eq!(denied.fields, ["expires_at"], "{asked:?}");
        }
        // A creator without an expiry may create keys with or without one.
        let forever = creator(vec![Scope::Admin], None, None);
        assert_eq!(check_no_escalation(&forever, &with_expiry(None)), Ok(()));
        assert_eq!(check_no_escalation(&forever, &with_expiry(Some(NOW))), Ok(()));
    }

    #[test]
    fn no_escalation_lists_every_violation() {
        let creator = creator(vec![Scope::JobsRead], Some(1), Some(vec!["a/*"]));
        let denied = check_no_escalation(&creator, &ask(vec![Scope::JobsWrite], None, None)).unwrap_err();
        assert_eq!(denied.fields, ["scopes", "daily_unit_cap", "allowed_images"]);
        assert_eq!(
            denied.to_string(),
            "escalation_denied: scopes, daily_unit_cap, allowed_images"
        );
    }
}
