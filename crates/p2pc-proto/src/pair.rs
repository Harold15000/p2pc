// SPDX-License-Identifier: Apache-2.0

//! Pairing tickets and the `p2pc/pair/1` messages (H2 spec §5.2, §5.3, §6.2).
//!
//! - A pairing ticket is `p2pc_pair_` plus lowercase unpadded base32 of a compact JSON payload, in the H1 join-token
//!   style: the hub's NodeId, its relay URLs, a 16-byte random code and the expiry. The hub stores only
//!   [`PairingTicket::code_hash`]. The QR code carries it in the fragment of `https://<web app origin>/pair#…`
//!   ([`PairingTicket::link`]), which browsers never send to the static host.
//! - On `p2pc/pair/1` the device sends one [`PairRequest::Pair`] and the hub answers one [`PairResponse`], then
//!   closes the connection. Frames use the H1 framing ([`crate::protocol::read_frame_with_limit`]) with
//!   [`PAIR_MAX_FRAME_LEN`] (4 KiB).
//! - [`EndpointKey`] is an iroh NodeId (an Ed25519 public key) as raw bytes, used here and by [`crate::invite`].
//!
//! # The payload is not authenticated
//!
//! As for H1 join tokens, whoever holds a ticket can re-encode it with another expiry, hub or relays. Only the code
//! is a secret the holder cannot forge, so the hub (T2-10, T2-11) MUST look the ticket up by [`PairingTicket::code_hash`]
//! with a constant-time comparison and use the expiry, the scopes and the single-use flag **of its own row**, never
//! the payload's.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use url::{Host, Url};

use crate::api::Scope;
use crate::auth::{MAX_RELAY_URL_LEN, MAX_RELAYS, SecretHash, ServerAddress};
use crate::ids::AccountId;
use crate::protocol::{ProtocolViolation, check_display_text, check_text, error_code};

/// Prefix of every pairing ticket.
pub const PAIRING_TICKET_PREFIX: &str = "p2pc_pair_";
/// Bytes in a pairing code (§5.2: 16 random bytes).
pub const PAIRING_CODE_LEN: usize = 16;
/// Default validity of a pairing ticket (§5.2: 600 s).
pub const DEFAULT_PAIRING_TICKET_TTL: Duration = Duration::seconds(600);
/// Longest validity of a pairing ticket (§5.2: 3,600 s).
pub const MAX_PAIRING_TICKET_TTL: Duration = Duration::seconds(3600);
/// Longest pairing ticket string, so that the largest `Pair` fits in one [`PAIR_MAX_FRAME_LEN`] frame and the QR code
/// stays scannable. [`PairingTicket::encode`] refuses a longer one (too many or too long relay URLs).
pub const MAX_PAIRING_TICKET_LEN: usize = 2048;
/// Longest device label in `Pair`, in bytes.
pub const MAX_DEVICE_LABEL_LEN: usize = 128;
/// Longest `platform` hint in `Pair`, in bytes (§5.3: at most 64 bytes).
pub const MAX_PLATFORM_LEN: usize = 64;
/// Longest hub name in `Paired` (and in the invite's `Invite`), in bytes.
pub const MAX_HUB_NAME_LEN: usize = 128;
/// Longest `device_id` in `Paired`, in bytes.
pub const MAX_DEVICE_ID_LEN: usize = 64;
/// Most scopes in `Paired`.
pub const MAX_SCOPES: usize = 32;

/// Frame limit on `p2pc/pair/1` (§5.3: 4 KiB).
pub const PAIR_MAX_FRAME_LEN: u32 = 4 * 1024;
/// The one `Pair` of a connection must arrive within this time (§5.3: 10 s).
pub const PAIR_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
/// Most `p2pc/pair/1` connections at once, counted apart from the other ALPNs (§5.3).
pub const PAIR_MAX_CONNECTIONS: usize = 32;
/// Most `Pair` exchanges being checked at once (§5.3).
pub const PAIR_MAX_PENDING: usize = 8;
/// Failed pairings a minute per NodeId; beyond it the NodeId is refused when it connects (§5.3).
pub const PAIR_FAILURES_PER_NODE_PER_MINUTE: u32 = 10;
/// Failed pairings a minute per ticket-hash prefix ([`PairingTicket::hash_prefix`]); beyond it failing attempts in
/// that prefix are closed with no detail (§5.3). A valid ticket still pairs.
pub const PAIR_FAILURES_PER_PREFIX_PER_MINUTE: u32 = 10;
/// The aggregate failure cap of **every** pre-auth ALPN (§5.3): beyond this many failures a minute on one ALPN,
/// failures get no detailed answer and are only counted into one aggregated audit event a minute. It limits answers
/// and logging, never the credential lookup.
pub const AGGREGATE_FAILURE_CAP_PER_MINUTE: u32 = 60;

/// Version of the pairing ticket payload.
const TICKET_VERSION: u8 = 1;

// The largest `Pair` fits in one frame: a JSON string escape at most doubles the bytes of a label or platform
// (control characters, which would take six, are refused), plus the envelope.
const _: () = assert!(
    MAX_PAIRING_TICKET_LEN + 2 * MAX_DEVICE_LABEL_LEN + 2 * MAX_PLATFORM_LEN + 64 <= PAIR_MAX_FRAME_LEN as usize
);

/// Lowercase unpadded base32 (RFC 4648 alphabet), as in H1 tokens.
pub(crate) fn b32_encode(bytes: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(bytes).to_ascii_lowercase()
}

/// The inverse of [`b32_encode`]: lowercase only, canonical (trailing bits zero).
pub(crate) fn b32_decode(text: &str) -> Option<Vec<u8>> {
    if !text.bytes().all(|b| crate::ids::BASE32_LOWER.contains(&b)) {
        return None;
    }
    data_encoding::BASE32_NOPAD
        .decode(text.to_ascii_uppercase().as_bytes())
        .ok()
}

/// Relay URLs as H1 join tokens accept them: `http` or `https`, a host, no credentials, at most 8 of at most 512
/// bytes each. The check is H1's own ([`ServerAddress::validate`]), so the formats cannot drift.
pub(crate) fn relays_ok(relays: &[Url]) -> bool {
    ServerAddress::new("0".repeat(64), relays.to_vec()).validate().is_ok()
}

/// Parses the relay strings of a payload, with the count and lengths checked before parsing.
pub(crate) fn parse_relays(raw: &[String]) -> Option<Vec<Url>> {
    if raw.len() > MAX_RELAYS {
        return None;
    }
    let relays = raw
        .iter()
        .map(|r| (r.len() <= MAX_RELAY_URL_LEN).then(|| Url::parse(r).ok()).flatten())
        .collect::<Option<Vec<_>>>()?;
    relays_ok(&relays).then_some(relays)
}

/// Unix seconds to a time, refusing what cannot be represented.
pub(crate) fn from_unix(seconds: i64) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(seconds).ok()
}

/// `now + ttl` in whole seconds (H1 tokens' precision), or `None` on overflow.
pub(crate) fn expiry_after(now: OffsetDateTime, ttl: Duration) -> Option<OffsetDateTime> {
    from_unix(now.unix_timestamp().checked_add(ttl.whole_seconds())?)
}

/// An iroh NodeId: the 32 bytes of an Ed25519 public key.
///
/// Its text form is iroh's own `Display`: 64 lowercase hex characters, and parsing accepts exactly that. It does
/// **not** check that the bytes decode to a curve point: whoever must know (the hub for the NodeIds of a join request,
/// H2 §5.4 step 3) checks it with iroh's `PublicKey::from_bytes`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EndpointKey([u8; 32]);

/// The text is not an iroh NodeId as 64 lowercase hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("expected an iroh NodeId as 64 lowercase hex characters")]
pub struct InvalidEndpointKey;

impl EndpointKey {
    /// Bytes in a key.
    pub const LEN: usize = 32;

    /// Wraps raw key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw key bytes: what the check phrases and the commitment hash.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for EndpointKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&data_encoding::HEXLOWER.encode(&self.0))
    }
}

impl fmt::Debug for EndpointKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EndpointKey({self})")
    }
}

impl FromStr for EndpointKey {
    type Err = InvalidEndpointKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 2 * Self::LEN || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(InvalidEndpointKey);
        }
        let bytes = data_encoding::HEXLOWER
            .decode(s.as_bytes())
            .map_err(|_| InvalidEndpointKey)?;
        bytes.try_into().map(Self).map_err(|_| InvalidEndpointKey)
    }
}

impl Serialize for EndpointKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for EndpointKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::ids::deserialize_from_str(deserializer)
    }
}

/// Why a pairing ticket is refused. Messages never contain the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TicketError {
    /// The string is not a well-formed pairing ticket.
    #[error("malformed pairing ticket")]
    Malformed,
    /// The hub NodeId is not 64 lowercase hex characters.
    #[error("invalid hub NodeId in pairing ticket")]
    InvalidHub,
    /// A relay URL is not plain `http(s)://host…` without credentials, or there are too many.
    #[error("invalid relay URL in pairing ticket")]
    InvalidRelay,
    /// The requested validity is not between 1 second and 3,600 seconds.
    #[error("the pairing ticket validity must be between 1 and 3600 seconds")]
    InvalidTtl,
    /// The expiry cannot be represented.
    #[error("invalid pairing ticket expiry")]
    InvalidExpiry,
    /// The ticket would be longer than [`MAX_PAIRING_TICKET_LEN`].
    #[error("the pairing ticket is too long (too many or too long relay URLs)")]
    TooLong,
    /// The web app origin is not `https` (or `http` on loopback, for development), or carries credentials.
    #[error("the web app origin must be https, without credentials")]
    InvalidOrigin,
}

/// A one-time pairing ticket (§5.2): single-use, short-lived, and secret because of its `code`.
///
/// `Debug` hides the code. [`PairingTicket::encode`] and `Serialize` give the full `p2pc_pair_…` string. Equality
/// compares the code in constant time. See the module documentation: the payload is not authenticated.
#[derive(Clone)]
pub struct PairingTicket {
    /// The hub's iroh NodeId, which the device dials and then pins.
    pub hub: EndpointKey,
    /// The hub's relay URLs (`http` or `https`, at most 8).
    pub relays: Vec<Url>,
    /// 16 random bytes. The hub stores only their SHA-256 ([`PairingTicket::code_hash`]).
    pub code: [u8; PAIRING_CODE_LEN],
    /// Expiry, with whole-second precision. A hint only: the hub uses its own row's.
    pub expires_at: OffsetDateTime,
}

/// The compact JSON inside a pairing ticket.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketPayload {
    v: u8,
    h: String,
    r: Vec<String>,
    c: String,
    e: i64,
}

impl PairingTicket {
    /// Creates a ticket with a random code (from the OS-seeded CSPRNG) that expires `ttl` after `now` (1 to 3,600
    /// seconds).
    pub fn generate(
        hub: EndpointKey,
        relays: Vec<Url>,
        ttl: Duration,
        now: OffsetDateTime,
    ) -> Result<Self, TicketError> {
        if ttl < Duration::seconds(1) || ttl > MAX_PAIRING_TICKET_TTL {
            return Err(TicketError::InvalidTtl);
        }
        let expires_at = expiry_after(now, ttl).ok_or(TicketError::InvalidExpiry)?;
        let mut code = [0u8; PAIRING_CODE_LEN];
        rand::fill(&mut code);
        let ticket = Self {
            hub,
            relays,
            code,
            expires_at,
        };
        ticket.encode()?;
        Ok(ticket)
    }

    /// Checks the relay URLs.
    pub fn validate(&self) -> Result<(), TicketError> {
        if relays_ok(&self.relays) {
            Ok(())
        } else {
            Err(TicketError::InvalidRelay)
        }
    }

    /// Encodes the ticket as `p2pc_pair_<base32>`. This is the secret string: never log it.
    pub fn encode(&self) -> Result<String, TicketError> {
        self.validate()?;
        let payload = TicketPayload {
            v: TICKET_VERSION,
            h: self.hub.to_string(),
            r: self.relays.iter().map(|u| u.as_str().to_string()).collect(),
            c: b32_encode(&self.code),
            e: self.expires_at.unix_timestamp(),
        };
        let json = serde_json::to_vec(&payload).map_err(|_| TicketError::Malformed)?;
        let text = format!("{PAIRING_TICKET_PREFIX}{}", b32_encode(&json));
        if text.len() > MAX_PAIRING_TICKET_LEN {
            return Err(TicketError::TooLong);
        }
        Ok(text)
    }

    /// Decodes a ticket string and checks its format and sizes. This does **not** authenticate it and does not check
    /// the expiry.
    pub fn decode(text: &str) -> Result<Self, TicketError> {
        if text.len() > MAX_PAIRING_TICKET_LEN {
            return Err(TicketError::TooLong);
        }
        let body = text.strip_prefix(PAIRING_TICKET_PREFIX).ok_or(TicketError::Malformed)?;
        let json = b32_decode(body).ok_or(TicketError::Malformed)?;
        let p: TicketPayload = serde_json::from_slice(&json).map_err(|_| TicketError::Malformed)?;
        if p.v != TICKET_VERSION {
            return Err(TicketError::Malformed);
        }
        let hub = p.h.parse().map_err(|_| TicketError::InvalidHub)?;
        let code = b32_decode(&p.c).ok_or(TicketError::Malformed)?;
        let code = code.try_into().map_err(|_| TicketError::Malformed)?;
        let relays = parse_relays(&p.r).ok_or(TicketError::InvalidRelay)?;
        let expires_at = from_unix(p.e).ok_or(TicketError::InvalidExpiry)?;
        Ok(Self {
            hub,
            relays,
            code,
            expires_at,
        })
    }

    /// Whether the ticket's **own, unauthenticated** expiry has passed at `now` (equal counts as expired). For an
    /// early, friendly error on the device only: the hub decides with its own row.
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }

    /// SHA-256 of the code: what the hub stores and compares, in constant time, with [`SecretHash::ct_eq`].
    #[must_use]
    pub fn code_hash(&self) -> SecretHash {
        SecretHash::from_bytes(Sha256::digest(self.code).into())
    }

    /// The first 16 bits of the SHA-256 of the presented code: the bucket of the per-prefix failure counter (§5.3).
    /// It reveals 16 bits of a hash of a 128-bit secret, which costs nothing.
    #[must_use]
    pub fn hash_prefix(&self) -> u16 {
        let h = self.code_hash();
        u16::from_be_bytes([h.as_bytes()[0], h.as_bytes()[1]])
    }

    /// The URL the QR code encodes (§5.2): `<origin>/pair#p2pc_pair_…`, with the ticket in the fragment, which
    /// browsers never send to the static host. `origin` is the web app's origin; its path, query and fragment are
    /// replaced. It must be `https` (plain `http` only on a loopback host, for development) and carry no
    /// credentials.
    pub fn link(&self, origin: &Url) -> Result<Url, TicketError> {
        let mut url = web_app_url(origin, "/pair")?;
        url.set_fragment(Some(&self.encode()?));
        Ok(url)
    }
}

/// `origin` with `path`, no query and no fragment, if it is a usable web app origin (see [`PairingTicket::link`]).
pub(crate) fn web_app_url(origin: &Url, path: &str) -> Result<Url, TicketError> {
    let loopback = match origin.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => return Err(TicketError::InvalidOrigin),
    };
    let scheme_ok = origin.scheme() == "https" || (origin.scheme() == "http" && loopback);
    if !scheme_ok || !origin.username().is_empty() || origin.password().is_some() {
        return Err(TicketError::InvalidOrigin);
    }
    let mut url = origin.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

impl PartialEq for PairingTicket {
    fn eq(&self, other: &Self) -> bool {
        // The code is compared in constant time; `&` (not `&&`) so the result does not short-circuit on it.
        let code_eq: bool = self.code.ct_eq(&other.code).into();
        code_eq & (self.hub == other.hub) & (self.relays == other.relays) & (self.expires_at == other.expires_at)
    }
}

impl Eq for PairingTicket {}

impl fmt::Debug for PairingTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingTicket")
            .field("hub", &self.hub)
            .field("relays", &self.relays.iter().map(Url::as_str).collect::<Vec<_>>())
            .field("code", &"***")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Serialize for PairingTicket {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = self.encode().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for PairingTicket {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        PairingTicket::decode(&text).map_err(serde::de::Error::custom)
    }
}

/// Messages from the device to the hub on `p2pc/pair/1`: exactly one per connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PairRequest {
    /// Pair this device (§5.3 step 2). The device's NodeId is the connection's, authenticated by iroh's TLS. A
    /// frame whose ticket does not decode fails to decode as a whole; the hub answers it as `invalid_ticket`, the one
    /// code for every bad ticket.
    Pair {
        /// The ticket from the QR code. `Debug` hides its code.
        ticket: PairingTicket,
        /// The device's name, for the owner's list of devices (at most [`MAX_DEVICE_LABEL_LEN`] bytes).
        label: String,
        /// A short free-text hint such as `"iOS Safari"` (at most [`MAX_PLATFORM_LEN`] bytes).
        platform: String,
    },
    /// A message `type` this version does not know. The hub answers [`PairResponse::unsupported_message`]. Never send
    /// it.
    #[serde(other)]
    Unknown,
}

/// Messages from the hub to the device on `p2pc/pair/1`: exactly one, then the hub closes the connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PairResponse {
    /// The device is paired (§5.3 step 3). The device stores `device_id`, the hub NodeId and relays, and from then on
    /// uses `p2pc/device/1`. The same ticket from the same NodeId gets the same answer again while that device is
    /// live (§5.2 "Retry is idempotent").
    Paired {
        /// The new device's ID.
        device_id: String,
        /// The hub's name, for the device's screens.
        hub_name: String,
        /// The account the device belongs to.
        account_id: AccountId,
        /// The device's scopes, from the ticket's row.
        scopes: Vec<Scope>,
        /// The hub's version (semver).
        server_version: String,
        /// The hub's REST API version (`GET /v1/server`, 2 for H2).
        api_version: u32,
    },
    /// Pairing failed. Then the hub closes the connection.
    PairError {
        /// Why. `invalid_ticket` is the one answer for an unknown, expired, revoked or used ticket.
        code: PairErrorCode,
    },
    /// A protocol error, for example [`error_code::UNSUPPORTED_MESSAGE`] for an unknown `type` (H1 §6).
    Error {
        /// Stable code.
        code: String,
        /// Human message.
        message: String,
    },
    /// A message `type` this version does not know (from a newer hub): a generic failure. Never send it.
    #[serde(other)]
    Unknown,
}

/// The `code` of [`PairResponse::PairError`] (§5.3 step 3).
///
/// A code this version does not know decodes to [`PairErrorCode::Unknown`], a generic failure, so a newer hub's code
/// never breaks the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairErrorCode {
    /// Unknown, expired, revoked or used ticket: one code for all (H1 §5), and also a retry from the same NodeId
    /// after its device was revoked (§5.2).
    InvalidTicket,
    /// The device or the ticket's prefix is over a failure limit (§5.3). Retry later with backoff.
    RateLimited,
    /// The hub is too old for this device's pairing.
    HubTooOld,
    /// A code this version does not know: a generic failure. Never send it.
    #[serde(other)]
    Unknown,
}

impl PairErrorCode {
    /// Every code this version sends, as in §5.3.
    pub const ALL: [PairErrorCode; 3] = [
        PairErrorCode::InvalidTicket,
        PairErrorCode::RateLimited,
        PairErrorCode::HubTooOld,
    ];
}

impl fmt::Display for PairErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PairErrorCode::InvalidTicket => "invalid_ticket",
            PairErrorCode::RateLimited => "rate_limited",
            PairErrorCode::HubTooOld => "hub_too_old",
            PairErrorCode::Unknown => "unknown",
        })
    }
}

fn violation(field: &'static str, reason: &'static str) -> ProtocolViolation {
    ProtocolViolation { field, reason }
}

impl PairRequest {
    /// The `"type"` tag of this message.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            PairRequest::Pair { .. } => "pair",
            PairRequest::Unknown => "unknown",
        }
    }

    /// Enforces the size and character limits. The hub calls it on every `Pair`.
    pub fn validate(&self) -> Result<(), ProtocolViolation> {
        match self {
            PairRequest::Pair {
                ticket,
                label,
                platform,
            } => {
                ticket
                    .validate()
                    .map_err(|_| violation("ticket", "invalid relay URL"))?;
                check_display_text("label", label, MAX_DEVICE_LABEL_LEN)?;
                check_display_text("platform", platform, MAX_PLATFORM_LEN)
            }
            PairRequest::Unknown => Ok(()),
        }
    }
}

impl PairResponse {
    /// The answer to a [`PairRequest::Unknown`]: `Error{code: "unsupported_message"}` (H1 §6). Then the hub closes the
    /// connection, since `p2pc/pair/1` carries one exchange.
    #[must_use]
    pub fn unsupported_message() -> Self {
        PairResponse::Error {
            code: error_code::UNSUPPORTED_MESSAGE.to_string(),
            message: "unknown message type".to_string(),
        }
    }

    /// The `"type"` tag of this message.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            PairResponse::Paired { .. } => "paired",
            PairResponse::PairError { .. } => "pair_error",
            PairResponse::Error { .. } => "error",
            PairResponse::Unknown => "unknown",
        }
    }

    /// Enforces the size and character limits. The device calls it on the hub's answer.
    pub fn validate(&self) -> Result<(), ProtocolViolation> {
        match self {
            PairResponse::Paired {
                device_id,
                hub_name,
                scopes,
                server_version,
                ..
            } => {
                let id_ok = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
                if device_id.is_empty() || device_id.len() > MAX_DEVICE_ID_LEN || !device_id.bytes().all(id_ok) {
                    return Err(violation("device_id", "must be 1-64 characters of A-Z, a-z, 0-9, '_'"));
                }
                check_display_text("hub_name", hub_name, MAX_HUB_NAME_LEN)?;
                if scopes.len() > MAX_SCOPES {
                    return Err(violation("scopes", "too many scopes"));
                }
                check_text("server_version", server_version)
            }
            PairResponse::Error { code, message } => {
                check_text("code", code)?;
                check_text("message", message)
            }
            PairResponse::PairError { .. } | PairResponse::Unknown => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{FrameError, read_frame_with_limit, write_frame};
    use proptest::prelude::*;
    use serde_json::json;
    use time::macros::datetime;

    const HUB: &str = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6";

    fn hub() -> EndpointKey {
        HUB.parse().unwrap()
    }

    fn relays() -> Vec<Url> {
        vec![Url::parse("https://relay.example.invalid/").unwrap()]
    }

    fn now() -> OffsetDateTime {
        datetime!(2026-11-10 10:00:00 UTC)
    }

    fn ticket() -> PairingTicket {
        PairingTicket::generate(hub(), relays(), DEFAULT_PAIRING_TICKET_TTL, now()).unwrap()
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn endpoint_keys_are_64_lowercase_hex_characters() {
        let key = hub();
        assert_eq!(key.to_string(), HUB);
        assert_eq!(key.as_bytes()[0], 0xae);
        assert_eq!(EndpointKey::from_bytes(*key.as_bytes()), key);
        assert_eq!(serde_json::to_value(key).unwrap(), json!(HUB));
        assert_eq!(serde_json::from_value::<EndpointKey>(json!(HUB)).unwrap(), key);
        assert_eq!(format!("{key:?}"), format!("EndpointKey({HUB})"));
        for bad in [
            &HUB.to_ascii_uppercase()[..],
            &HUB[..63],
            &format!("{HUB}0")[..],
            &format!("{}g", &HUB[..63])[..],
            "",
            // The 52-character base32 form that iroh also parses is not the canonical text form.
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert_eq!(bad.parse::<EndpointKey>(), Err(InvalidEndpointKey), "{bad}");
        }
        assert!(serde_json::from_value::<EndpointKey>(json!(1)).is_err());
    }

    #[test]
    fn a_ticket_round_trips_in_the_join_token_style() {
        let t = ticket();
        let text = t.encode().unwrap();
        assert!(text.starts_with(PAIRING_TICKET_PREFIX));
        let body = &text[PAIRING_TICKET_PREFIX.len()..];
        assert!(
            body.bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        );
        assert!(text.len() <= MAX_PAIRING_TICKET_LEN);
        let back = PairingTicket::decode(&text).unwrap();
        assert_eq!(back, t);
        assert_eq!(back.hub, hub());
        assert_eq!(back.relays, relays());
        assert_eq!(back.code, t.code);
        // Serde uses the same string.
        assert_eq!(serde_json::to_value(&t).unwrap(), json!(text));
        assert_eq!(serde_json::from_value::<PairingTicket>(json!(text)).unwrap(), t);
        // Two tickets never share a code.
        assert_ne!(ticket().code, t.code);
    }

    #[test]
    fn the_payload_is_the_compact_json_of_the_spec() {
        let mut t = ticket();
        t.code = [7; PAIRING_CODE_LEN];
        let text = t.encode().unwrap();
        let json = data_encoding::BASE32_NOPAD
            .decode(text[PAIRING_TICKET_PREFIX.len()..].to_ascii_uppercase().as_bytes())
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(
            v,
            json!({"v": 1, "h": HUB, "r": ["https://relay.example.invalid/"],
                   "c": b32_encode(&[7; PAIRING_CODE_LEN]), "e": now().unix_timestamp() + 600})
        );
    }

    #[test]
    fn debug_never_shows_the_code() {
        let t = ticket();
        let debug = format!("{t:?}");
        assert!(debug.contains("***"), "{debug}");
        assert!(!debug.contains(&b32_encode(&t.code)), "{debug}");
        assert!(!debug.contains(&data_encoding::HEXLOWER.encode(&t.code)), "{debug}");
        let request = PairRequest::Pair {
            ticket: t.clone(),
            label: "Phone".into(),
            platform: "iOS Safari".into(),
        };
        assert!(!format!("{request:?}").contains(&b32_encode(&t.code)));
    }

    #[test]
    fn ticket_lifetimes_follow_the_spec() {
        assert_eq!(DEFAULT_PAIRING_TICKET_TTL, Duration::seconds(600));
        assert_eq!(MAX_PAIRING_TICKET_TTL, Duration::seconds(3600));
        let t = PairingTicket::generate(hub(), vec![], MAX_PAIRING_TICKET_TTL, now()).unwrap();
        assert_eq!(t.expires_at, now() + Duration::hours(1));
        for bad in [Duration::ZERO, Duration::seconds(-1), Duration::seconds(3601)] {
            assert_eq!(
                PairingTicket::generate(hub(), vec![], bad, now()).unwrap_err(),
                TicketError::InvalidTtl
            );
        }
        // Whole seconds, as in H1 join tokens.
        let t = PairingTicket::generate(
            hub(),
            vec![],
            Duration::seconds(1),
            datetime!(2026-11-10 10:00:00.7 UTC),
        )
        .unwrap();
        assert_eq!(t.expires_at, datetime!(2026-11-10 10:00:01 UTC));
        assert!(!t.is_expired(datetime!(2026-11-10 10:00:00.9 UTC)));
        assert!(t.is_expired(datetime!(2026-11-10 10:00:01 UTC)));
    }

    #[test]
    fn the_hub_stores_the_sha256_of_the_code_and_limits_by_its_prefix() {
        let t = ticket();
        let digest: [u8; 32] = Sha256::digest(t.code).into();
        assert!(t.code_hash().ct_eq(&SecretHash::from_bytes(digest)));
        assert_eq!(t.hash_prefix(), u16::from_be_bytes([digest[0], digest[1]]));
        let mut other = t.clone();
        other.code[0] ^= 1;
        assert!(!t.code_hash().ct_eq(&other.code_hash()));
        assert_ne!(t, other);
    }

    #[test]
    fn malformed_tickets_are_refused() {
        let good = ticket().encode().unwrap();
        let body = &good[PAIRING_TICKET_PREFIX.len()..];
        let payload = |v: serde_json::Value| {
            format!(
                "{PAIRING_TICKET_PREFIX}{}",
                b32_encode(&serde_json::to_vec(&v).unwrap())
            )
        };
        let code = b32_encode(&[1; PAIRING_CODE_LEN]);
        let cases = [
            format!("p2pc_join_{body}"),
            format!("p2pc_inv_{body}"),
            good.to_ascii_uppercase(),
            format!("{good}1"),
            PAIRING_TICKET_PREFIX.to_string(),
            format!("{PAIRING_TICKET_PREFIX}{}", "a".repeat(MAX_PAIRING_TICKET_LEN)),
            payload(json!({"v": 2, "h": HUB, "r": [], "c": code, "e": 1})),
            payload(json!({"v": 1, "h": HUB, "r": [], "c": code, "e": 1, "x": 0})),
            payload(json!({"v": 1, "h": HUB, "r": [], "c": b32_encode(&[1; 15]), "e": 1})),
            payload(json!({"v": 1, "h": HUB.to_ascii_uppercase(), "r": [], "c": code, "e": 1})),
            payload(json!({"v": 1, "h": &HUB[..62], "r": [], "c": code, "e": 1})),
            payload(json!({"v": 1, "h": HUB, "r": ["ftp://relay.example.invalid/"], "c": code, "e": 1})),
            payload(json!({"v": 1, "h": HUB, "r": ["https://u:p@relay.example.invalid/"], "c": code, "e": 1})),
            payload(json!({"v": 1, "h": HUB, "r": ["not a url"], "c": code, "e": 1})),
            payload(json!({"v": 1, "h": HUB, "r": vec!["https://relay.example.invalid/"; 9], "c": code, "e": 1})),
            payload(json!({"v": 1, "h": HUB, "r": [], "c": code, "e": i64::MAX})),
            payload(json!({"v": 1, "h": HUB, "r": [], "c": code})),
        ];
        for (n, text) in cases.iter().enumerate() {
            assert!(PairingTicket::decode(text).is_err(), "case {n}");
        }
        // The control: the same builder with valid values decodes.
        assert!(PairingTicket::decode(&payload(json!({"v": 1, "h": HUB, "r": [], "c": code, "e": 1}))).is_ok());
        // Errors never echo the input.
        let err = PairingTicket::decode(&cases[0]).unwrap_err().to_string();
        assert!(!err.contains(body), "{err}");
    }

    #[test]
    fn tickets_too_long_for_a_pair_frame_are_not_encoded() {
        let long = (0..8)
            .map(|i| Url::parse(&format!("https://relay-{i}.{}.example.invalid/", "r".repeat(300))).unwrap())
            .collect::<Vec<_>>();
        let t = PairingTicket::generate(hub(), long, DEFAULT_PAIRING_TICKET_TTL, now());
        assert_eq!(t.unwrap_err(), TicketError::TooLong);
    }

    #[test]
    fn the_qr_link_carries_the_ticket_in_the_fragment() {
        let t = ticket();
        let origin = Url::parse("https://app.example.invalid/some/path?x=1#old").unwrap();
        let link = t.link(&origin).unwrap();
        assert_eq!(link.scheme(), "https");
        assert_eq!(link.host_str(), Some("app.example.invalid"));
        assert_eq!(link.path(), "/pair");
        assert_eq!(link.query(), None);
        let fragment = link.fragment().unwrap();
        assert_eq!(fragment, t.encode().unwrap());
        assert_eq!(PairingTicket::decode(fragment).unwrap(), t);
        assert_eq!(
            link.as_str(),
            format!("https://app.example.invalid/pair#{}", t.encode().unwrap())
        );
        for bad in [
            "http://app.example.invalid/",
            "https://u:p@app.example.invalid/",
            "data:text/plain,x",
        ] {
            assert_eq!(
                t.link(&Url::parse(bad).unwrap()).unwrap_err(),
                TicketError::InvalidOrigin,
                "{bad}"
            );
        }
        // Plain http only for a loopback development origin.
        assert!(t.link(&Url::parse("http://localhost:5173/").unwrap()).is_ok());
        assert!(t.link(&Url::parse("http://127.0.0.1:5173/").unwrap()).is_ok());
    }

    fn paired() -> PairResponse {
        PairResponse::Paired {
            device_id: "dev_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            hub_name: "Home cloud".into(),
            account_id: "acc_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            scopes: vec![Scope::NodesRead],
            server_version: "0.2.0".into(),
            api_version: 2,
        }
    }

    #[test]
    fn pair_messages_wire_format_matches_the_spec() {
        let t = ticket();
        let request = PairRequest::Pair {
            ticket: t.clone(),
            label: "Phone".into(),
            platform: "iOS Safari".into(),
        };
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({"type": "pair", "ticket": t.encode().unwrap(), "label": "Phone", "platform": "iOS Safari"})
        );
        assert_eq!(request.kind(), "pair");
        assert_eq!(
            serde_json::to_value(paired()).unwrap(),
            json!({"type": "paired", "device_id": "dev_01ARZ3NDEKTSV4RRFFQ69G5FAV", "hub_name": "Home cloud",
                   "account_id": "acc_01ARZ3NDEKTSV4RRFFQ69G5FAV", "scopes": ["nodes:read"],
                   "server_version": "0.2.0", "api_version": 2})
        );
        assert_eq!(paired().kind(), "paired");
        for (code, wire) in [
            (PairErrorCode::InvalidTicket, "invalid_ticket"),
            (PairErrorCode::RateLimited, "rate_limited"),
            (PairErrorCode::HubTooOld, "hub_too_old"),
        ] {
            let msg = PairResponse::PairError { code };
            assert_eq!(
                serde_json::to_value(&msg).unwrap(),
                json!({"type": "pair_error", "code": wire})
            );
            assert_eq!(code.to_string(), wire);
            assert_eq!(msg.kind(), "pair_error");
        }
        assert_eq!(PairErrorCode::ALL.len(), 3);
    }

    /// H2 §6: unknown fields are ignored, an unknown `type` decodes to `Unknown`, an unknown error code is a generic
    /// failure.
    #[test]
    fn pair_messages_follow_the_compatibility_rules() {
        let t = ticket().encode().unwrap();
        let request: PairRequest = serde_json::from_value(
            json!({"type": "pair", "ticket": t, "label": "", "platform": "x", "future": {"a": 1}}),
        )
        .unwrap();
        assert!(matches!(request, PairRequest::Pair { .. }));
        assert_eq!(
            serde_json::from_value::<PairRequest>(json!({"type": "pair_v2", "x": 1})).unwrap(),
            PairRequest::Unknown
        );
        assert_eq!(
            serde_json::from_value::<PairResponse>(json!({"type": "re_pair"})).unwrap(),
            PairResponse::Unknown
        );
        assert_eq!(
            serde_json::from_value::<PairResponse>(json!({"type": "pair_error", "code": "from_the_future", "n": 1}))
                .unwrap(),
            PairResponse::PairError {
                code: PairErrorCode::Unknown
            }
        );
        let mut v = serde_json::to_value(paired()).unwrap();
        v["new_field"] = json!([1, 2]);
        assert_eq!(serde_json::from_value::<PairResponse>(v).unwrap(), paired());
        // The answer to an unknown type (H1 §6).
        let error = PairResponse::unsupported_message();
        assert_eq!(
            serde_json::to_value(&error).unwrap()["code"],
            json!(crate::protocol::error_code::UNSUPPORTED_MESSAGE)
        );
        assert_eq!(error.validate(), Ok(()));
        // A missing tag or field is an error, and so is a malformed ticket.
        assert!(serde_json::from_value::<PairRequest>(json!({"ticket": t})).is_err());
        assert!(serde_json::from_value::<PairRequest>(json!({"type": "pair", "ticket": t, "label": "x"})).is_err());
        assert!(
            serde_json::from_value::<PairRequest>(
                json!({"type": "pair", "ticket": "p2pc_pair_zz", "label": "x", "platform": "y"})
            )
            .is_err()
        );
    }

    #[test]
    fn pair_requests_are_validated() {
        let with = |label: &str, platform: &str| PairRequest::Pair {
            ticket: ticket(),
            label: label.into(),
            platform: platform.into(),
        };
        assert_eq!(with("", "").validate(), Ok(()));
        assert_eq!(
            with(&"é".repeat(MAX_DEVICE_LABEL_LEN / 2), &"p".repeat(MAX_PLATFORM_LEN)).validate(),
            Ok(())
        );
        assert!(with(&"l".repeat(MAX_DEVICE_LABEL_LEN + 1), "x").validate().is_err());
        assert!(with("x", &"p".repeat(MAX_PLATFORM_LEN + 1)).validate().is_err());
        assert!(with("evil\nlabel", "x").validate().is_err());
        assert!(with("x", "tab\there").validate().is_err());
        assert!(with("x", "bidi\u{202e}").validate().is_err());
        assert_eq!(PairRequest::Unknown.validate(), Ok(()));
    }

    #[test]
    fn pair_responses_are_validated() {
        assert_eq!(paired().validate(), Ok(()));
        let with = |f: &dyn Fn(&mut PairResponse)| {
            let mut msg = paired();
            f(&mut msg);
            msg.validate()
        };
        let set_device = |id: &'static str| {
            move |m: &mut PairResponse| {
                if let PairResponse::Paired { device_id, .. } = m {
                    *device_id = id.into();
                }
            }
        };
        assert!(with(&set_device("")).is_err());
        assert!(with(&set_device("dev_../x")).is_err());
        assert!(with(&set_device("dev 1")).is_err());
        assert!(
            with(&|m| if let PairResponse::Paired { device_id, .. } = m {
                *device_id = "d".repeat(MAX_DEVICE_ID_LEN + 1);
            })
            .is_err()
        );
        assert!(
            with(&|m| if let PairResponse::Paired { hub_name, .. } = m {
                *hub_name = "h".repeat(MAX_HUB_NAME_LEN + 1);
            })
            .is_err()
        );
        assert!(
            with(&|m| if let PairResponse::Paired { hub_name, .. } = m {
                *hub_name = "a\u{0}b".into();
            })
            .is_err()
        );
        assert!(
            with(&|m| if let PairResponse::Paired { scopes, .. } = m {
                *scopes = vec![Scope::Admin; MAX_SCOPES + 1];
            })
            .is_err()
        );
        assert!(
            with(&|m| if let PairResponse::Paired { server_version, .. } = m {
                *server_version = "v".repeat(crate::protocol::MAX_TEXT_LEN + 1);
            })
            .is_err()
        );
        let long_error = PairResponse::Error {
            code: "c".repeat(crate::protocol::MAX_TEXT_LEN + 1),
            message: String::new(),
        };
        assert!(long_error.validate().is_err());
    }

    #[test]
    fn the_limits_match_the_spec() {
        assert_eq!(PAIR_MAX_FRAME_LEN, 4096);
        assert_eq!(PAIR_DEADLINE, std::time::Duration::from_secs(10));
        assert_eq!((PAIR_MAX_CONNECTIONS, PAIR_MAX_PENDING), (32, 8));
        assert_eq!(
            (
                PAIR_FAILURES_PER_NODE_PER_MINUTE,
                PAIR_FAILURES_PER_PREFIX_PER_MINUTE,
                AGGREGATE_FAILURE_CAP_PER_MINUTE
            ),
            (10, 10, 60)
        );
        assert_eq!(MAX_PLATFORM_LEN, 64);
        assert_eq!(PAIRING_CODE_LEN, 16);
    }

    /// The largest `Pair` this crate accepts fits in the 4 KiB pre-auth frame, with every escapable character
    /// escaped.
    #[test]
    fn the_largest_pair_fits_in_one_frame() {
        // The longest ticket: add relay characters, spread over the 8 relays, until the encoding reaches the limit.
        let mut best = None;
        for total in 8..3200 {
            let relays = (0..8)
                .map(|i| {
                    let n = total / 8 + usize::from(i < total % 8);
                    Url::parse(&format!("https://{}.example.invalid/", "r".repeat(n))).unwrap()
                })
                .collect();
            match PairingTicket::generate(hub(), relays, DEFAULT_PAIRING_TICKET_TTL, now()) {
                Ok(t) => best = Some(t),
                Err(TicketError::TooLong) => break,
                Err(other) => panic!("{other:?}"),
            }
        }
        let t = best.unwrap();
        assert!(t.encode().unwrap().len() > MAX_PAIRING_TICKET_LEN - 16);
        let msg = PairRequest::Pair {
            ticket: t,
            label: "\"".repeat(MAX_DEVICE_LABEL_LEN),
            platform: "\\".repeat(MAX_PLATFORM_LEN),
        };
        assert_eq!(msg.validate(), Ok(()));
        let mut buf = Vec::new();
        block_on(write_frame(&mut buf, &msg)).unwrap();
        assert!(buf.len() - 4 <= PAIR_MAX_FRAME_LEN as usize, "{}", buf.len());
        let mut r = buf.as_slice();
        let back = block_on(read_frame_with_limit::<PairRequest, _>(&mut r, PAIR_MAX_FRAME_LEN)).unwrap();
        assert_eq!(back, Some(msg));
    }

    #[test]
    fn frames_over_4_kib_are_refused_before_decoding() {
        let mut buf = (PAIR_MAX_FRAME_LEN + 1).to_be_bytes().to_vec();
        buf.extend(std::iter::repeat_n(b' ', PAIR_MAX_FRAME_LEN as usize + 1));
        let mut r = buf.as_slice();
        let err = block_on(read_frame_with_limit::<PairRequest, _>(&mut r, PAIR_MAX_FRAME_LEN)).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge { len: 4097, max: 4096 }), "{err:?}");
    }

    fn arb_ticket() -> impl Strategy<Value = PairingTicket> {
        (
            any::<[u8; 32]>(),
            proptest::collection::vec("[a-z]{1,20}", 0..3),
            any::<[u8; PAIRING_CODE_LEN]>(),
            0i64..4_102_444_800,
        )
            .prop_map(|(hub, hosts, code, e)| PairingTicket {
                hub: EndpointKey::from_bytes(hub),
                relays: hosts
                    .iter()
                    .map(|h| Url::parse(&format!("https://{h}.example.invalid/")).unwrap())
                    .collect(),
                code,
                expires_at: OffsetDateTime::from_unix_timestamp(e).unwrap(),
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn tickets_round_trip(t in arb_ticket()) {
            let text = t.encode().unwrap();
            prop_assert_eq!(PairingTicket::decode(&text).unwrap(), t);
        }

        #[test]
        fn messages_round_trip_through_a_frame(
            t in arb_ticket(),
            label in "\\PC{0,32}",
            platform in "[ -~]{0,64}",
            code in prop_oneof![
                Just(PairErrorCode::InvalidTicket),
                Just(PairErrorCode::RateLimited),
                Just(PairErrorCode::HubTooOld),
            ],
        ) {
            let request = PairRequest::Pair { ticket: t, label, platform };
            let mut buf = Vec::new();
            block_on(write_frame(&mut buf, &request)).unwrap();
            let mut r = buf.as_slice();
            prop_assert_eq!(
                block_on(read_frame_with_limit::<PairRequest, _>(&mut r, PAIR_MAX_FRAME_LEN)).unwrap(),
                Some(request)
            );
            for response in [paired(), PairResponse::PairError { code }, PairResponse::unsupported_message()] {
                let mut buf = Vec::new();
                block_on(write_frame(&mut buf, &response)).unwrap();
                let mut r = buf.as_slice();
                prop_assert_eq!(
                    block_on(read_frame_with_limit::<PairResponse, _>(&mut r, PAIR_MAX_FRAME_LEN)).unwrap(),
                    Some(response)
                );
            }
        }

        /// SI-H2-17: the decoders never panic on hostile input.
        #[test]
        fn hostile_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048), text in "\\PC{0,256}") {
            let _ = PairingTicket::decode(&text);
            let _ = PairingTicket::decode(&format!("{PAIRING_TICKET_PREFIX}{text}"));
            let _ = text.parse::<EndpointKey>();
            let mut r = bytes.as_slice();
            while let Ok(Some(msg)) = block_on(read_frame_with_limit::<PairRequest, _>(&mut r, PAIR_MAX_FRAME_LEN)) {
                let _ = msg.validate();
            }
            let mut r = bytes.as_slice();
            while let Ok(Some(msg)) = block_on(read_frame_with_limit::<PairResponse, _>(&mut r, PAIR_MAX_FRAME_LEN)) {
                let _ = msg.validate();
            }
            let _ = crate::protocol::decode_frame::<PairRequest>(&bytes);
            let _ = crate::protocol::decode_frame::<PairResponse>(&bytes);
        }

        /// SI-H2-17: random JSON objects with the right tag never panic either.
        #[test]
        fn tagged_garbage_never_panics(
            kind in prop_oneof![
                Just("pair".to_string()),
                Just("paired".to_string()),
                Just("pair_error".to_string()),
                Just("error".to_string()),
                "[a-z_]{0,12}",
            ],
            key in "[a-z_]{1,12}",
            n in any::<i64>(),
            s in "\\PC{0,64}",
        ) {
            let v = json!({"type": kind, key.clone(): n, "label": s, "code": s, "ticket": s});
            if let Ok(msg) = serde_json::from_value::<PairRequest>(v.clone()) {
                let _ = msg.validate();
            }
            if let Ok(msg) = serde_json::from_value::<PairResponse>(v) {
                let _ = msg.validate();
            }
        }
    }
}
