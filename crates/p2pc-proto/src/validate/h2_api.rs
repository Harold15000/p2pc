// SPDX-License-Identifier: Apache-2.0

//! Validation of the H2 request bodies (H2 spec §5.2, §5.4, §7.3, §7.6) and the no-escalation rule for every
//! principal (H2 §5.2, §5.5).
//!
//! Like [`keys`](super::keys), the validators return [`ValidationErrors`] with field paths (the server answers
//! `422`, with the code the endpoint names), and an escalation is an [`EscalationDenied`] (`403 escalation_denied`).
//! Nothing here needs the database: checks that do (a blob exists, a NodeId is an Ed25519 point, a template's
//! parameters) are the server's.

use time::{Duration, OffsetDateTime};

use super::keys::{check_allowed_images, check_label, check_scopes};
use super::{Collector, ErrorCode, EscalationDenied, ValidationErrors, check_idempotency_key};
use crate::api::{
    ApiKeyInfo, CreateApiKey, CreateJoinRequest, CreatePairingTicket, DeviceInfo, LaunchTemplate, PHONE_PROFILE,
    RevealJoinRequest, Scope, UpdateServer,
};
use crate::units::Units;

/// Default `expires_in_s` of a pairing ticket (H2 §5.2): 10 minutes.
pub const DEFAULT_PAIRING_TICKET_TTL_S: u32 = 600;
/// Largest `expires_in_s` of a pairing ticket (H2 §5.2): 1 hour.
pub const MAX_PAIRING_TICKET_TTL_S: u32 = 3_600;
/// How long a join request lives (H2 §5.4): 15 minutes.
pub const JOIN_REQUEST_TTL_S: i64 = 900;
/// The clock skew allowed between the joining PC and the hub for `invite_expires_at` (H2 §5.4): 120 s.
pub const INVITE_CLOCK_SKEW_S: i64 = 120;
/// Longest `hub_name`, in characters (H2 §7.3).
pub const MAX_HUB_NAME_CHARS: usize = 64;
/// Most `params` in a template launch. Templates have a handful; the cap bounds the work on a hostile body.
pub const MAX_LAUNCH_PARAMS: usize = 32;

/// What a principal may do, compared by the no-escalation rule (H1 §5, H2 §5.2): its scopes, daily cap, image
/// allowlist, expiry and blob quota. Keys have no blob quota.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalLimits {
    /// Scopes (`admin` covers every scope).
    pub scopes: Vec<Scope>,
    /// Daily cap; `None` is uncapped.
    pub daily_unit_cap: Option<Units>,
    /// Image allowlist; `None` allows every image.
    pub allowed_images: Option<Vec<String>>,
    /// Expiry; `None` never expires.
    pub expires_at: Option<OffsetDateTime>,
    /// Blob quota in MiB; `None` is only bound by the account's quota.
    pub blobs_quota_mb: Option<u64>,
}

impl From<&ApiKeyInfo> for PrincipalLimits {
    fn from(k: &ApiKeyInfo) -> Self {
        Self {
            scopes: k.scopes.clone(),
            daily_unit_cap: k.daily_unit_cap,
            allowed_images: k.allowed_images.clone(),
            expires_at: k.expires_at,
            blobs_quota_mb: None,
        }
    }
}

impl From<&CreateApiKey> for PrincipalLimits {
    fn from(r: &CreateApiKey) -> Self {
        Self {
            scopes: r.scopes.clone(),
            daily_unit_cap: r.daily_unit_cap,
            allowed_images: r.allowed_images.clone(),
            expires_at: r.expires_at,
            blobs_quota_mb: None,
        }
    }
}

impl From<&DeviceInfo> for PrincipalLimits {
    fn from(d: &DeviceInfo) -> Self {
        Self {
            scopes: d.scopes.clone(),
            daily_unit_cap: d.daily_unit_cap,
            allowed_images: d.allowed_images.clone(),
            expires_at: d.expires_at,
            blobs_quota_mb: d.blobs_quota_mb,
        }
    }
}

/// The no-escalation rule for any principal, as a pure function (H1 §5, H2 §5.2, §5.5): `asked` has no more power
/// than `creator`:
/// - its scopes are a subset of the creator's (`admin` covers every scope);
/// - if the creator has a `daily_unit_cap`, `asked` has one too, at or below it;
/// - if the creator has `allowed_images`, `asked` has a list made only of the creator's patterns, compared exactly;
/// - if the creator has `expires_at`, `asked` has one too, at or before it (a longer life is more power);
/// - if the creator has `blobs_quota_mb`, `asked` has one too, at or below it.
///
/// Every violated rule is listed, in that order. It serves key creation ([`check_no_escalation`]), pairing tickets
/// (with [`CreatePairingTicket::requested_limits`]) and device revocation by an `admin` (H2 §5.5: only a device it
/// could have created).
///
/// [`check_no_escalation`]: super::check_no_escalation
pub fn check_limits_no_escalation(creator: &PrincipalLimits, asked: &PrincipalLimits) -> Result<(), EscalationDenied> {
    let mut fields = Vec::new();
    let creator_is_admin = creator.scopes.contains(&Scope::Admin);
    if !creator_is_admin && !asked.scopes.iter().all(|s| creator.scopes.contains(s)) {
        fields.push("scopes");
    }
    if let Some(cap) = creator.daily_unit_cap
        && asked.daily_unit_cap.is_none_or(|a| a > cap)
    {
        fields.push("daily_unit_cap");
    }
    if let Some(allowed) = &creator.allowed_images {
        let within = asked
            .allowed_images
            .as_ref()
            .is_some_and(|a| a.iter().all(|p| allowed.contains(p)));
        if !within {
            fields.push("allowed_images");
        }
    }
    if let Some(limit) = creator.expires_at
        && asked.expires_at.is_none_or(|a| a > limit)
    {
        fields.push("expires_at");
    }
    if let Some(quota) = creator.blobs_quota_mb
        && asked.blobs_quota_mb.is_none_or(|a| a > quota)
    {
        fields.push("blobs_quota_mb");
    }
    if fields.is_empty() {
        Ok(())
    } else {
        Err(EscalationDenied { fields })
    }
}

impl CreatePairingTicket {
    /// The ticket's validity in seconds: `expires_in_s`, or 600.
    #[must_use]
    pub fn ttl_s(&self) -> u32 {
        self.expires_in_s.unwrap_or(DEFAULT_PAIRING_TICKET_TTL_S)
    }

    /// The device's scopes: `scopes`, or the phone profile.
    #[must_use]
    pub fn device_scopes(&self) -> Vec<Scope> {
        self.scopes.clone().unwrap_or_else(|| PHONE_PROFILE.to_vec())
    }

    /// The device's `expires_at` for a ticket created at `created_at`: `Ok(None)` when the device never expires,
    /// `Err(())` when the sum overflows (which [`CreatePairingTicket::validate`] refuses).
    #[allow(clippy::result_unit_err)]
    pub fn device_expires_at(&self, created_at: OffsetDateTime) -> Result<Option<OffsetDateTime>, ()> {
        let Some(secs) = self.device_expires_in_s else {
            return Ok(None);
        };
        let secs = i64::try_from(secs).map_err(|_| ())?;
        created_at.checked_add(Duration::seconds(secs)).map(Some).ok_or(())
    }

    /// The limits of the device this ticket would create at `created_at`, for
    /// [`check_limits_no_escalation`] against the creator. `None` if the device expiry overflows.
    #[must_use]
    pub fn requested_limits(&self, created_at: OffsetDateTime) -> Option<PrincipalLimits> {
        Some(PrincipalLimits {
            scopes: self.device_scopes(),
            daily_unit_cap: self.daily_unit_cap,
            allowed_images: self.allowed_images.clone(),
            expires_at: self.device_expires_at(created_at).ok()?,
            blobs_quota_mb: self.blobs_quota_mb,
        })
    }

    /// Validates a pairing-ticket request created at `now` (H2 §5.2):
    /// - `label`, `scopes` (when given) and `allowed_images` as for API keys;
    /// - `expires_in_s` 1-3 600;
    /// - `device_expires_in_s` greater than the ticket's validity, so a device is never born expired, and with no
    ///   overflow when added to `now` (`422 out_of_range`).
    pub fn validate(&self, now: OffsetDateTime) -> Result<(), ValidationErrors> {
        let mut c = Collector(Vec::new());
        check_label(self.label.as_deref(), &mut c);
        if let Some(scopes) = &self.scopes {
            check_scopes(scopes, &mut c);
        }
        check_allowed_images(self.allowed_images.as_deref(), &mut c);
        if self
            .expires_in_s
            .is_some_and(|t| !(1..=MAX_PAIRING_TICKET_TTL_S).contains(&t))
        {
            c.push(
                "expires_in_s",
                ErrorCode::OutOfRange,
                format!("must be 1-{MAX_PAIRING_TICKET_TTL_S} seconds"),
            );
        }
        if let Some(device) = self.device_expires_in_s
            && (device <= u64::from(self.ttl_s()) || self.device_expires_at(now).is_err())
        {
            c.push(
                "device_expires_in_s",
                ErrorCode::OutOfRange,
                "must be greater than the ticket's expires_in_s, and representable",
            );
        }
        c.finish()
    }
}

/// Whether `s` is 32 bytes as 64 lowercase hex characters: the JSON form of NodeIds, the listener commitment and
/// the nonces of a join request (H2 §5.4).
#[must_use]
pub fn is_hex32(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl CreateJoinRequest {
    /// Validates a join request at `now` (H2 §5.4 step 3): `invite_expires_at` within `(now, now + 15 min + 120 s]`,
    /// and both NodeIds and the commitment 32 bytes of lowercase hex. The server answers `422 invalid_join_request`
    /// with these errors, after also checking that both NodeIds are Ed25519 points.
    pub fn validate(&self, now: OffsetDateTime) -> Result<(), ValidationErrors> {
        let mut c = Collector(Vec::new());
        let latest = now.checked_add(Duration::seconds(JOIN_REQUEST_TTL_S + INVITE_CLOCK_SKEW_S));
        let in_window = latest.is_some_and(|latest| self.invite_expires_at > now && self.invite_expires_at <= latest);
        if !in_window {
            c.push(
                "invite_expires_at",
                ErrorCode::OutOfRange,
                "must be in the future and at most 15 minutes and 120 seconds from now",
            );
        }
        for (field, value) in [
            ("listener_node_id", &self.listener_node_id),
            ("iroh_node_id", &self.iroh_node_id),
            ("listener_commitment", &self.listener_commitment),
        ] {
            if !is_hex32(value) {
                c.push(
                    field,
                    ErrorCode::InvalidFormat,
                    "must be 32 bytes as 64 lowercase hex characters",
                );
            }
        }
        c.finish()
    }
}

impl RevealJoinRequest {
    /// Validates the reveal body: `listener_nonce` is 32 bytes of lowercase hex. The value is never echoed.
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        if is_hex32(&self.listener_nonce) {
            Ok(())
        } else {
            Err(ValidationErrors::single(
                "listener_nonce",
                ErrorCode::InvalidFormat,
                "must be 32 bytes as 64 lowercase hex characters",
            ))
        }
    }
}

impl UpdateServer {
    /// Validates `PATCH /v1/server` (H2 §7.3): `hub_name` is 1-64 printable characters.
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let n = self.hub_name.chars().count();
        if n == 0 || self.hub_name.chars().any(char::is_control) {
            Err(ValidationErrors::single(
                "hub_name",
                ErrorCode::InvalidFormat,
                "must be non-empty, without control characters",
            ))
        } else if n > MAX_HUB_NAME_CHARS {
            Err(ValidationErrors::single(
                "hub_name",
                ErrorCode::TooLarge,
                "must be at most 64 characters",
            ))
        } else {
            Ok(())
        }
    }
}

impl LaunchTemplate {
    /// Validates the launch body itself: `idempotency_key` as for jobs, and at most [`MAX_LAUNCH_PARAMS`]
    /// parameters. The parameters are then checked against the template by the hub (`422 invalid_params`), and the
    /// built JobSpec with [`JobSpec::validate_in`](crate::api::JobSpec::validate_in) and
    /// [`SpecContext::Launch`](super::SpecContext::Launch).
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut c = Collector(Vec::new());
        if self.params.len() > MAX_LAUNCH_PARAMS {
            c.push(
                "params",
                ErrorCode::TooMany,
                format!("at most {MAX_LAUNCH_PARAMS} parameters"),
            );
        }
        check_idempotency_key(self.idempotency_key.as_deref(), &mut c);
        c.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::ErrorCode::*;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-05 10:00:00 UTC);

    fn limits(scopes: Vec<Scope>) -> PrincipalLimits {
        PrincipalLimits {
            scopes,
            daily_unit_cap: None,
            allowed_images: None,
            expires_at: None,
            blobs_quota_mb: None,
        }
    }

    #[test]
    fn no_escalation_covers_the_blob_quota_and_device_expiry() {
        let creator = PrincipalLimits {
            blobs_quota_mb: Some(100),
            expires_at: Some(datetime!(2027-01-01 00:00:00 UTC)),
            ..limits(vec![Scope::Admin])
        };
        let ok = PrincipalLimits {
            blobs_quota_mb: Some(100),
            expires_at: Some(datetime!(2026-12-01 00:00:00 UTC)),
            ..limits(crate::api::PHONE_PROFILE.to_vec())
        };
        assert_eq!(check_limits_no_escalation(&creator, &ok), Ok(()));
        for (asked, field) in [
            (
                PrincipalLimits {
                    blobs_quota_mb: None,
                    ..ok.clone()
                },
                "blobs_quota_mb",
            ),
            (
                PrincipalLimits {
                    blobs_quota_mb: Some(101),
                    ..ok.clone()
                },
                "blobs_quota_mb",
            ),
            (
                PrincipalLimits {
                    expires_at: None,
                    ..ok.clone()
                },
                "expires_at",
            ),
        ] {
            assert_eq!(
                check_limits_no_escalation(&creator, &asked).unwrap_err().fields,
                [field]
            );
        }
        // A phone cannot create an admin, nor a scope it lacks.
        let phone = limits(crate::api::PHONE_PROFILE.to_vec());
        for asked in [vec![Scope::Admin], vec![Scope::JobsWrite], vec![Scope::NodesJoin]] {
            let denied = check_limits_no_escalation(&phone, &limits(asked.clone())).unwrap_err();
            assert_eq!(denied.fields, ["scopes"], "{asked:?}");
        }
        // Every violation is listed, in order.
        let tight = PrincipalLimits {
            daily_unit_cap: Some(Units::from_units(1)),
            allowed_images: Some(vec!["a/*".into()]),
            expires_at: Some(NOW),
            blobs_quota_mb: Some(1),
            ..limits(vec![Scope::JobsRead])
        };
        let denied = check_limits_no_escalation(&tight, &limits(vec![Scope::JobsWrite])).unwrap_err();
        assert_eq!(
            denied.fields,
            [
                "scopes",
                "daily_unit_cap",
                "allowed_images",
                "expires_at",
                "blobs_quota_mb"
            ]
        );
    }

    #[test]
    fn pairing_ticket_requests() {
        let base = CreatePairingTicket::default();
        assert_eq!(base.validate(NOW), Ok(()));
        assert_eq!(base.ttl_s(), 600);
        assert_eq!(base.device_scopes(), crate::api::PHONE_PROFILE);
        let limits = base.requested_limits(NOW).unwrap();
        assert_eq!((limits.expires_at, limits.blobs_quota_mb), (None, None));
        let full = CreatePairingTicket {
            label: Some("phone".into()),
            scopes: Some(vec![Scope::NodesRead]),
            expires_in_s: Some(3_600),
            device_expires_in_s: Some(3_601),
            blobs_quota_mb: Some(512),
            allowed_images: Some(vec!["ghcr.io/me/**".into()]),
            daily_unit_cap: Some(Units::from_units(3)),
        };
        assert_eq!(full.validate(NOW), Ok(()));
        assert_eq!(full.device_expires_at(NOW), Ok(Some(NOW + Duration::seconds(3_601))));
        assert_eq!(full.requested_limits(NOW).unwrap().scopes, [Scope::NodesRead]);
        let bad = [
            (
                CreatePairingTicket {
                    expires_in_s: Some(0),
                    ..base.clone()
                },
                "expires_in_s",
                OutOfRange,
            ),
            (
                CreatePairingTicket {
                    expires_in_s: Some(3_601),
                    ..base.clone()
                },
                "expires_in_s",
                OutOfRange,
            ),
            // A device is never born expired: its life must exceed the ticket's (default 600).
            (
                CreatePairingTicket {
                    device_expires_in_s: Some(600),
                    ..base.clone()
                },
                "device_expires_in_s",
                OutOfRange,
            ),
            (
                CreatePairingTicket {
                    device_expires_in_s: Some(0),
                    ..base.clone()
                },
                "device_expires_in_s",
                OutOfRange,
            ),
            (
                CreatePairingTicket {
                    device_expires_in_s: Some(u64::MAX),
                    ..base.clone()
                },
                "device_expires_in_s",
                OutOfRange,
            ),
            (
                CreatePairingTicket {
                    scopes: Some(vec![]),
                    ..base.clone()
                },
                "scopes",
                OutOfRange,
            ),
            (
                CreatePairingTicket {
                    scopes: Some(vec![Scope::NodesRead, Scope::NodesRead]),
                    ..base.clone()
                },
                "scopes[1]",
                Duplicate,
            ),
            (
                CreatePairingTicket {
                    label: Some("a\nb".into()),
                    ..base.clone()
                },
                "label",
                InvalidFormat,
            ),
            (
                CreatePairingTicket {
                    allowed_images: Some(vec![String::new()]),
                    ..base.clone()
                },
                "allowed_images[0]",
                InvalidFormat,
            ),
        ];
        for (req, field, code) in bad {
            let errs = req.validate(NOW).unwrap_err();
            assert!(errs.contains(field, code), "{field}: {errs}");
            assert_eq!(errs.len(), 1, "{field}: {errs}");
        }
        // An overflowing device expiry gives no limits, so it can never pass the escalation check by accident.
        let overflow = CreatePairingTicket {
            device_expires_in_s: Some(u64::MAX),
            ..base
        };
        assert_eq!(overflow.requested_limits(NOW), None);
    }

    fn join_request(expires: OffsetDateTime) -> CreateJoinRequest {
        CreateJoinRequest {
            listener_node_id: "a".repeat(64),
            iroh_node_id: "0123456789abcdef".repeat(4),
            invite_expires_at: expires,
            listener_commitment: "f".repeat(64),
        }
    }

    #[test]
    fn join_request_window_and_formats() {
        for ok in [NOW + Duration::seconds(1), NOW + Duration::seconds(900 + 120)] {
            assert_eq!(join_request(ok).validate(NOW), Ok(()), "{ok}");
        }
        for bad in [NOW, NOW - Duration::seconds(1), NOW + Duration::seconds(1_021)] {
            let errs = join_request(bad).validate(NOW).unwrap_err();
            assert!(errs.contains("invite_expires_at", OutOfRange), "{bad}: {errs}");
        }
        let ok = join_request(NOW + Duration::minutes(10));
        for (field, value) in [
            ("listener_node_id", "A".repeat(64)),
            ("iroh_node_id", "a".repeat(63)),
            ("listener_commitment", "g".repeat(64)),
            ("listener_commitment", "a".repeat(66)),
        ] {
            let mut r = ok.clone();
            match field {
                "listener_node_id" => r.listener_node_id = value,
                "iroh_node_id" => r.iroh_node_id = value,
                _ => r.listener_commitment = value,
            }
            let errs = r.validate(NOW).unwrap_err();
            assert!(errs.contains(field, InvalidFormat), "{field}: {errs}");
            assert_eq!(errs.len(), 1);
        }
        assert_eq!(
            RevealJoinRequest {
                listener_nonce: "0".repeat(64)
            }
            .validate(),
            Ok(())
        );
        let secret = "Z".repeat(64);
        let errs = RevealJoinRequest {
            listener_nonce: secret.clone(),
        }
        .validate()
        .unwrap_err();
        assert!(!errs.to_string().contains(&secret), "the nonce is never echoed");
    }

    #[test]
    fn hub_name_and_launch_bodies() {
        for ok in ["Home", "Family cloud ☀", &"é".repeat(64)] {
            assert_eq!(UpdateServer { hub_name: ok.into() }.validate(), Ok(()), "{ok}");
        }
        for (bad, code) in [
            ("", InvalidFormat),
            ("a\u{1b}[2J", InvalidFormat),
            (&"x".repeat(65)[..], TooLarge),
        ] {
            let errs = UpdateServer { hub_name: bad.into() }.validate().unwrap_err();
            assert!(errs.contains("hub_name", code), "{bad:?}: {errs}");
        }
        let launch = LaunchTemplate::default();
        assert_eq!(launch.validate(), Ok(()));
        let many = LaunchTemplate {
            params: (0..33)
                .map(|i| (format!("p{i}"), crate::api::ParamValue::Bool(true)))
                .collect(),
            idempotency_key: Some("a b".into()),
        };
        let errs = many.validate().unwrap_err();
        assert!(
            errs.contains("params", TooMany) && errs.contains("idempotency_key", InvalidFormat),
            "{errs}"
        );
    }
}
