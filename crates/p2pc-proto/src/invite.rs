// SPDX-License-Identifier: Apache-2.0

//! Phone-assisted invites and the `p2pc/invite/1` messages (H2 spec §5.4, §6.2), and the three 6-word check phrases
//! (§5.4 steps 4-7, §5.5).
//!
//! - An invite is `p2pc_inv_` plus lowercase unpadded base32 of a compact JSON payload: the listener's NodeId, the
//!   local agent's NodeId, the listener's relays, a 16-byte code, the **listener commitment** and the expiry (15
//!   minutes). The QR code carries it in the fragment of `https://<web app origin>/invite#…` ([`Invite::link`]).
//! - The listener commitment is `BLAKE3("p2pc-join-commit-v1" || listener nonce)` ([`ListenerNonce::commitment`]).
//!   The QR carries the commitment, never the nonce, which the app keeps in memory and reveals once, in
//!   [`InviteResponse::InviteReveal`], to the first phone that opens the invite with the valid code.
//! - The check phrases are 6 words (66 bits) of the fixed 2,048-word list (the BIP-39 English list), taken from the
//!   first 66 bits of a BLAKE3 hash, most significant bit first, 11 bits per word:
//!   - the **hub phrase** [`hub_phrase`]: `BLAKE3("p2pc-invite-v1" || hub NodeId || listener NodeId || code)`;
//!   - the **approval phrase** [`approval_phrase`]: `BLAKE3("p2pc-join-request-v2" || hub NodeId || agent NodeId ||
//!     listener nonce || hub nonce)`;
//!   - the **node phrase** [`node_phrase`]: `BLAKE3("p2pc-node-v1" || node NodeId)`.
//!
//!   Every input has a fixed length (NodeIds and nonces 32 bytes, the code 16), so the concatenation is unambiguous.
//!   NodeIds are hashed as their 32 raw key bytes ([`EndpointKey::as_bytes`]).
//! - On `p2pc/invite/1` the phone sends one [`InviteRequest`] per connection and the app answers one
//!   [`InviteResponse`]. Frames use the H1 framing with [`INVITE_MAX_FRAME_LEN`] (4 KiB).
//!
//! The payload is not authenticated: the hub and the app use their own records (the stored commitment, the code they
//! drew), never values a holder could re-encode.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::auth::JoinToken;
use crate::pair::{MAX_HUB_NAME_LEN, b32_decode, b32_encode, expiry_after, from_unix, parse_relays, relays_ok};
use crate::protocol::{ProtocolViolation, check_display_text, check_text, error_code};

pub use crate::pair::EndpointKey;

mod wordlist;

/// Prefix of every invite.
pub const INVITE_PREFIX: &str = "p2pc_inv_";
/// Bytes in an invite code (§5.4 step 2: 16 bytes).
pub const INVITE_CODE_LEN: usize = 16;
/// Bytes in the listener nonce and in the hub nonce (§5.4, §6.2: 32 bytes).
pub const NONCE_LEN: usize = 32;
/// Validity of an invite, and of the join request made from it (§5.4: 15 minutes).
pub const INVITE_TTL: Duration = Duration::minutes(15);
/// Clock skew between the two PCs that the hub allows on `invite_expires_at` (§5.4 step 3: 120 s).
pub const INVITE_CLOCK_SKEW: Duration = Duration::seconds(120);
/// Longest invite string, so that the QR code stays scannable. [`Invite::encode`] refuses a longer one.
pub const MAX_INVITE_LEN: usize = 2048;
/// Frame limit on `p2pc/invite/1` (§6.2: 4 KiB).
pub const INVITE_MAX_FRAME_LEN: u32 = 4 * 1024;
/// The one message of a connection must arrive within this time (§6.2: 10 s).
pub const INVITE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
/// Most connections to the invite listener at once (§6.2).
pub const INVITE_MAX_CONNECTIONS: usize = 8;
/// Most exchanges being checked at once (§6.2).
pub const INVITE_MAX_PENDING: usize = 2;
/// Failed exchanges (`invalid_code`) a minute per NodeId; beyond it the NodeId is refused when it connects (§6.2).
pub const INVITE_FAILURES_PER_NODE_PER_MINUTE: u32 = 5;
/// Words in a check phrase.
pub const PHRASE_WORDS: usize = 6;
/// Bits in a check phrase: 11 per word (§5.4: 66 bits).
pub const PHRASE_BITS: usize = 66;

/// Domain of the hub phrase (§5.4 step 7).
pub const HUB_PHRASE_DOMAIN: &[u8] = b"p2pc-invite-v1";
/// Domain of the approval phrase (§5.4 step 4).
pub const APPROVAL_PHRASE_DOMAIN: &[u8] = b"p2pc-join-request-v2";
/// Domain of the node phrase (§5.5).
pub const NODE_PHRASE_DOMAIN: &[u8] = b"p2pc-node-v1";
/// Domain of the listener commitment (§5.4 step 2).
pub const LISTENER_COMMITMENT_DOMAIN: &[u8] = b"p2pc-join-commit-v1";

/// Version of the invite payload.
const INVITE_VERSION: u8 = 1;

/// Why an invite cannot be encoded or decoded. Messages never contain the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InviteFormatError {
    /// The string is not a well-formed invite.
    #[error("malformed invite")]
    Malformed,
    /// A NodeId is not 64 lowercase hex characters.
    #[error("invalid NodeId in invite")]
    InvalidKey,
    /// A relay URL is not plain `http(s)://host…` without credentials, or there are too many.
    #[error("invalid relay URL in invite")]
    InvalidRelay,
    /// The expiry cannot be represented.
    #[error("invalid invite expiry")]
    InvalidExpiry,
    /// The invite would be longer than [`MAX_INVITE_LEN`].
    #[error("the invite is too long (too many or too long relay URLs)")]
    TooLong,
    /// The web app origin is not `https` (or `http` on loopback, for development), or carries credentials.
    #[error("the web app origin must be https, without credentials")]
    InvalidOrigin,
}

fn hex32_from_str(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    data_encoding::HEXLOWER.decode(s.as_bytes()).ok()?.try_into().ok()
}

/// A 32-byte value whose text form is 64 lowercase hex characters, one spelling only.
macro_rules! hex32 {
    ($(#[$meta:meta])* $name:ident, debug: $debug:ident) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wraps raw bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// 32 fresh bytes from the OS-seeded CSPRNG.
            #[must_use]
            pub fn generate() -> Self {
                let mut bytes = [0u8; 32];
                rand::fill(&mut bytes);
                Self(bytes)
            }

            /// Constant-time comparison.
            #[must_use]
            pub fn ct_eq(&self, other: &Self) -> bool {
                self.0.ct_eq(&other.0).into()
            }

            fn hex(&self) -> String {
                data_encoding::HEXLOWER.encode(&self.0)
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other)
            }
        }

        impl Eq for $name {}

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
                hex32_from_str(&text)
                    .map(Self)
                    .ok_or_else(|| serde::de::Error::custom("expected 32 bytes as 64 lowercase hex characters"))
            }
        }

        hex32!(@debug $name, $debug);
    };
    (@debug $name:ident, secret) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(***)", stringify!($name))
            }
        }
    };
    (@debug $name:ident, public) => {
        impl $name {
            /// The raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl Copy for $name {}

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.hex())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }
    };
}

hex32!(
    /// The listener nonce (§5.4 step 2): 32 bytes the joining PC's app draws from the platform CSPRNG and keeps in
    /// memory only. It reveals it once, in [`InviteResponse::InviteReveal`], and the phone passes it to the hub, which
    /// checks it against the commitment from the QR. A secret until then: `Debug` prints `***`.
    ListenerNonce,
    debug: secret
);

hex32!(
    /// The hub nonce (§5.4 step 3): 32 bytes the hub draws when it stores a join request, after the request's agent
    /// NodeId and commitment are fixed. It travels to the phone and to the listener, and is not a secret.
    HubNonce,
    debug: public
);

hex32!(
    /// `BLAKE3("p2pc-join-commit-v1" || listener nonce)` (§5.4 step 2): what the QR carries instead of the nonce.
    ListenerCommitment,
    debug: public
);

impl ListenerNonce {
    /// The raw bytes. Never log them.
    #[must_use]
    pub const fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The commitment the QR carries.
    #[must_use]
    pub fn commitment(&self) -> ListenerCommitment {
        let mut h = blake3::Hasher::new();
        h.update(LISTENER_COMMITMENT_DOMAIN);
        h.update(&self.0);
        ListenerCommitment(*h.finalize().as_bytes())
    }
}

impl ListenerCommitment {
    /// Whether `nonce` is the one this commits to, compared in constant time (the hub's reveal check, §5.4 step 4).
    #[must_use]
    pub fn verify(&self, nonce: &ListenerNonce) -> bool {
        self.ct_eq(&nonce.commitment())
    }
}

/// The 16-byte invite code (§5.4 step 2): the secret the phone proves it saw the QR with. Its text form is lowercase
/// unpadded base32 (26 characters), as the codes of H1 tokens. `Debug` prints `***`; equality is constant-time.
#[derive(Clone)]
pub struct InviteCode([u8; INVITE_CODE_LEN]);

impl InviteCode {
    /// Wraps raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; INVITE_CODE_LEN]) -> Self {
        Self(bytes)
    }

    /// A fresh code from the OS-seeded CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; INVITE_CODE_LEN];
        rand::fill(&mut bytes);
        Self(bytes)
    }

    /// The raw bytes. Never log them.
    #[must_use]
    pub const fn expose_bytes(&self) -> &[u8; INVITE_CODE_LEN] {
        &self.0
    }

    /// Constant-time comparison: the listener's check of `InviteOpen.code` and `Invite.code`.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    fn parse(text: &str) -> Option<Self> {
        b32_decode(text)?.try_into().ok().map(Self)
    }
}

impl PartialEq for InviteCode {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for InviteCode {}

impl fmt::Debug for InviteCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InviteCode(***)")
    }
}

impl Serialize for InviteCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&b32_encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for InviteCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        InviteCode::parse(&text).ok_or_else(|| serde::de::Error::custom("expected 16 bytes as lowercase base32"))
    }
}

/// An invite (§5.4 step 2), shown by the joining PC's app as a QR code. `Debug` hides the code.
#[derive(Clone, PartialEq, Eq)]
pub struct Invite {
    /// The NodeId of the app's temporary, relay-only invite listener.
    pub listener: EndpointKey,
    /// The NodeId of the PC's agent: the join token will be bound to it (§5.4 step 6).
    pub agent: EndpointKey,
    /// The listener's relay URLs (`http` or `https`, at most 8).
    pub relays: Vec<Url>,
    /// The one-time code.
    pub code: InviteCode,
    /// The commitment to the listener nonce, never the nonce.
    pub commitment: ListenerCommitment,
    /// Expiry, with whole-second precision: 15 minutes after creation.
    pub expires_at: OffsetDateTime,
}

/// The compact JSON inside an invite.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitePayload {
    v: u8,
    l: String,
    a: String,
    r: Vec<String>,
    c: String,
    m: String,
    e: i64,
}

impl Invite {
    /// A new invite with a random code, committing to `nonce`, that expires [`INVITE_TTL`] after `now`.
    pub fn generate(
        listener: EndpointKey,
        agent: EndpointKey,
        relays: Vec<Url>,
        nonce: &ListenerNonce,
        now: OffsetDateTime,
    ) -> Result<Self, InviteFormatError> {
        let invite = Self {
            listener,
            agent,
            relays,
            code: InviteCode::generate(),
            commitment: nonce.commitment(),
            expires_at: expiry_after(now, INVITE_TTL).ok_or(InviteFormatError::InvalidExpiry)?,
        };
        invite.encode()?;
        Ok(invite)
    }

    /// Encodes the invite as `p2pc_inv_<base32>`. It holds the code: show it only as the QR, never log it.
    pub fn encode(&self) -> Result<String, InviteFormatError> {
        if !relays_ok(&self.relays) {
            return Err(InviteFormatError::InvalidRelay);
        }
        let payload = InvitePayload {
            v: INVITE_VERSION,
            l: self.listener.to_string(),
            a: self.agent.to_string(),
            r: self.relays.iter().map(|u| u.as_str().to_string()).collect(),
            c: b32_encode(&self.code.0),
            m: self.commitment.to_string(),
            e: self.expires_at.unix_timestamp(),
        };
        let json = serde_json::to_vec(&payload).map_err(|_| InviteFormatError::Malformed)?;
        let text = format!("{INVITE_PREFIX}{}", b32_encode(&json));
        if text.len() > MAX_INVITE_LEN {
            return Err(InviteFormatError::TooLong);
        }
        Ok(text)
    }

    /// Decodes an invite string and checks its format and sizes. It does not check the expiry, and checks no NodeId
    /// against the curve (the hub does that for the join request, §5.4 step 3).
    pub fn decode(text: &str) -> Result<Self, InviteFormatError> {
        if text.len() > MAX_INVITE_LEN {
            return Err(InviteFormatError::TooLong);
        }
        let body = text.strip_prefix(INVITE_PREFIX).ok_or(InviteFormatError::Malformed)?;
        let json = b32_decode(body).ok_or(InviteFormatError::Malformed)?;
        let p: InvitePayload = serde_json::from_slice(&json).map_err(|_| InviteFormatError::Malformed)?;
        if p.v != INVITE_VERSION {
            return Err(InviteFormatError::Malformed);
        }
        let key = |s: &str| s.parse::<EndpointKey>().map_err(|_| InviteFormatError::InvalidKey);
        Ok(Self {
            listener: key(&p.l)?,
            agent: key(&p.a)?,
            relays: parse_relays(&p.r).ok_or(InviteFormatError::InvalidRelay)?,
            code: InviteCode::parse(&p.c).ok_or(InviteFormatError::Malformed)?,
            commitment: hex32_from_str(&p.m)
                .map(ListenerCommitment)
                .ok_or(InviteFormatError::Malformed)?,
            expires_at: from_unix(p.e).ok_or(InviteFormatError::InvalidExpiry)?,
        })
    }

    /// Whether the invite's own expiry has passed at `now` (equal counts as expired).
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }

    /// The URL the QR code encodes (§5.4 step 2): `<origin>/invite#p2pc_inv_…`. The same origin rules as
    /// [`crate::pair::PairingTicket::link`].
    pub fn link(&self, origin: &Url) -> Result<Url, InviteFormatError> {
        let mut url = crate::pair::web_app_url(origin, "/invite").map_err(|_| InviteFormatError::InvalidOrigin)?;
        url.set_fragment(Some(&self.encode()?));
        Ok(url)
    }

    /// The hub phrase of this invite with the hub NodeId the listener was told in `InviteOpen` (§5.4 step 7).
    #[must_use]
    pub fn hub_phrase(&self, hub: &EndpointKey) -> CheckPhrase {
        hub_phrase(hub, &self.listener, &self.code)
    }
}

impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("listener", &self.listener)
            .field("agent", &self.agent)
            .field("relays", &self.relays.iter().map(Url::as_str).collect::<Vec<_>>())
            .field("code", &"***")
            .field("commitment", &self.commitment)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Serialize for Invite {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = self.encode().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for Invite {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Invite::decode(&text).map_err(serde::de::Error::custom)
    }
}

/// The hub's check of `invite_expires_at` in `POST /v1/nodes/join-requests` (§5.4 step 3): it must lie in
/// `(now, now + 15 min + 120 s]` on the hub's clock; otherwise `422 invalid_join_request`.
#[must_use]
pub fn invite_expiry_acceptable(invite_expires_at: OffsetDateTime, now: OffsetDateTime) -> bool {
    invite_expires_at > now && invite_expires_at <= now + INVITE_TTL + INVITE_CLOCK_SKEW
}

/// Whether `token` names `hub` as its server (the listener's check before it answers `Invite`, §5.4 step 6). The
/// token's server must be `hub` in the canonical text form (64 lowercase hex characters); any other spelling fails
/// closed, as `hub_mismatch`.
#[must_use]
pub fn join_token_names_hub(token: &JoinToken, hub: &EndpointKey) -> bool {
    token.server.parse::<EndpointKey>().is_ok_and(|k| k == *hub)
}

/// A check phrase: 6 words of the fixed list (66 bits), which two screens show so the owner can compare them. Its
/// text form is the words separated by single spaces.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckPhrase([&'static str; PHRASE_WORDS]);

impl CheckPhrase {
    /// The phrase of the first 66 bits of `hash`, most significant first, 11 bits per word.
    #[must_use]
    pub fn from_hash(hash: &[u8; 32]) -> Self {
        let mut head = [0u8; 16];
        head[..9].copy_from_slice(&hash[..9]);
        // The first 72 bits, right-aligned, then shifted down to the first 66.
        let bits = u128::from_be_bytes(head) >> (128 - 72 + 6);
        Self(std::array::from_fn(|i| {
            let shift = 11 * (PHRASE_WORDS - 1 - i);
            // The mask keeps 11 bits, so the index is always below 2,048.
            wordlist::WORDS[((bits >> shift) & 0x7ff) as usize]
        }))
    }

    /// The six words.
    #[must_use]
    pub const fn words(&self) -> [&'static str; PHRASE_WORDS] {
        self.0
    }
}

impl fmt::Display for CheckPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join(" "))
    }
}

impl fmt::Debug for CheckPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CheckPhrase(\"{self}\")")
    }
}

impl Serialize for CheckPhrase {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

fn phrase_of(domain: &[u8], parts: &[&[u8]]) -> CheckPhrase {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    for part in parts {
        h.update(part);
    }
    CheckPhrase::from_hash(h.finalize().as_bytes())
}

/// The hub phrase (§5.4 step 7): `BLAKE3("p2pc-invite-v1" || hub NodeId || listener NodeId || code)`. The phone and
/// the joining PC show it before the owner taps "Join".
#[must_use]
pub fn hub_phrase(hub: &EndpointKey, listener: &EndpointKey, code: &InviteCode) -> CheckPhrase {
    phrase_of(HUB_PHRASE_DOMAIN, &[hub.as_bytes(), listener.as_bytes(), &code.0])
}

/// The approval phrase (§5.4 steps 4-5): `BLAKE3("p2pc-join-request-v2" || hub NodeId || agent NodeId || listener
/// nonce || hub nonce)`. The joining PC shows it after `InviteReveal`; the hub PC shows it for a `pending` join
/// request, which the owner approves only if the words match.
#[must_use]
pub fn approval_phrase(
    hub: &EndpointKey,
    agent: &EndpointKey,
    listener_nonce: &ListenerNonce,
    hub_nonce: &HubNonce,
) -> CheckPhrase {
    phrase_of(
        APPROVAL_PHRASE_DOMAIN,
        &[hub.as_bytes(), agent.as_bytes(), &listener_nonce.0, &hub_nonce.0],
    )
}

/// The node phrase (§5.5): `BLAKE3("p2pc-node-v1" || node NodeId)`, a fingerprint of the node's long-lived key, shown
/// by the hub PC for a `pending_approval` node and by the joined PC (`join_pending`, `p2pc-agent status`).
#[must_use]
pub fn node_phrase(node: &EndpointKey) -> CheckPhrase {
    phrase_of(NODE_PHRASE_DOMAIN, &[node.as_bytes()])
}

/// Messages from the phone to the invite listener on `p2pc/invite/1`: exactly one per connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InviteRequest {
    /// Open the invite (§5.4 step 4). The listener checks the code in constant time, keeps the hub NodeId, the hub
    /// nonce and the phone's NodeId, and answers [`InviteResponse::InviteReveal`]. From then on it accepts only that
    /// NodeId; a repeat with the same hub NodeId and hub nonce gets the same answer, one with other values
    /// `already_open` (§6.2).
    InviteOpen {
        /// The code from the QR. `Debug` hides it.
        code: InviteCode,
        /// The hub the join request was made to: the join token must name it (`hub_mismatch` otherwise).
        hub_node_id: EndpointKey,
        /// The hub nonce of the join request.
        hub_nonce: HubNonce,
    },
    /// Hand over the join token (§5.4 step 6), on a new connection, from the NodeId of the accepted `InviteOpen`. The
    /// listener answers [`InviteResponse::InviteAck`] once, and accepts no new connection after it.
    Invite {
        /// The code from the QR. `Debug` hides it.
        code: InviteCode,
        /// The join token, bound to the invite's agent NodeId. `Debug` hides its code.
        join_token: JoinToken,
        /// The hub's name, for the "Join" screen.
        hub_name: String,
    },
    /// A message `type` this version does not know. The listener answers [`InviteResponse::unsupported_message`].
    /// Never send it.
    #[serde(other)]
    Unknown,
}

/// Messages from the invite listener to the phone on `p2pc/invite/1`: exactly one per connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InviteResponse {
    /// The answer to an accepted `InviteOpen`: the nonce the QR committed to. `Debug` hides it.
    InviteReveal {
        /// The listener nonce.
        listener_nonce: ListenerNonce,
    },
    /// The answer to an accepted `Invite`.
    InviteAck {},
    /// The exchange failed.
    InviteError {
        /// Why.
        code: InviteErrorCode,
    },
    /// A protocol error, for example [`error_code::UNSUPPORTED_MESSAGE`] for an unknown `type` (H1 §6).
    Error {
        /// Stable code.
        code: String,
        /// Human message.
        message: String,
    },
    /// A message `type` this version does not know (from a newer app): a generic failure. Never send it.
    #[serde(other)]
    Unknown,
}

/// The `code` of [`InviteResponse::InviteError`] (§6.2). An unknown code decodes to [`InviteErrorCode::Unknown`], a
/// generic failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteErrorCode {
    /// The code is wrong, or an `Invite` came before any accepted `InviteOpen`.
    InvalidCode,
    /// The invite has expired.
    Expired,
    /// The listener is bound to another phone, or this phone repeated `InviteOpen` with other values.
    AlreadyOpen,
    /// The join token names another hub than the accepted `InviteOpen`: the app shows "This invite is for another
    /// cloud: do not join" and does not join.
    HubMismatch,
    /// A code this version does not know: a generic failure. Never send it.
    #[serde(other)]
    Unknown,
}

impl InviteErrorCode {
    /// Every code this version sends, as in §6.2.
    pub const ALL: [InviteErrorCode; 4] = [
        InviteErrorCode::InvalidCode,
        InviteErrorCode::Expired,
        InviteErrorCode::AlreadyOpen,
        InviteErrorCode::HubMismatch,
    ];
}

impl fmt::Display for InviteErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            InviteErrorCode::InvalidCode => "invalid_code",
            InviteErrorCode::Expired => "expired",
            InviteErrorCode::AlreadyOpen => "already_open",
            InviteErrorCode::HubMismatch => "hub_mismatch",
            InviteErrorCode::Unknown => "unknown",
        })
    }
}

impl InviteRequest {
    /// The `"type"` tag of this message.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            InviteRequest::InviteOpen { .. } => "invite_open",
            InviteRequest::Invite { .. } => "invite",
            InviteRequest::Unknown => "unknown",
        }
    }

    /// Enforces the size and character limits. The listener calls it on every message.
    pub fn validate(&self) -> Result<(), ProtocolViolation> {
        match self {
            InviteRequest::Invite {
                join_token, hub_name, ..
            } => {
                join_token.validate().map_err(|_| ProtocolViolation {
                    field: "join_token",
                    reason: "invalid server NodeId or relay URL",
                })?;
                check_display_text("hub_name", hub_name, MAX_HUB_NAME_LEN)
            }
            InviteRequest::InviteOpen { .. } | InviteRequest::Unknown => Ok(()),
        }
    }
}

impl InviteResponse {
    /// The answer to an [`InviteRequest::Unknown`]: `Error{code: "unsupported_message"}` (H1 §6).
    #[must_use]
    pub fn unsupported_message() -> Self {
        InviteResponse::Error {
            code: error_code::UNSUPPORTED_MESSAGE.to_string(),
            message: "unknown message type".to_string(),
        }
    }

    /// The `"type"` tag of this message.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            InviteResponse::InviteReveal { .. } => "invite_reveal",
            InviteResponse::InviteAck {} => "invite_ack",
            InviteResponse::InviteError { .. } => "invite_error",
            InviteResponse::Error { .. } => "error",
            InviteResponse::Unknown => "unknown",
        }
    }

    /// Enforces the size limits. The phone calls it on the listener's answer.
    pub fn validate(&self) -> Result<(), ProtocolViolation> {
        match self {
            InviteResponse::Error { code, message } => {
                check_text("code", code)?;
                check_text("message", message)
            }
            InviteResponse::InviteReveal { .. }
            | InviteResponse::InviteAck {}
            | InviteResponse::InviteError { .. }
            | InviteResponse::Unknown => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::JoinToken;
    use crate::protocol::{FrameError, read_frame_with_limit, write_frame};
    use proptest::prelude::*;
    use serde_json::json;
    use time::macros::datetime;

    fn rep(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// `(i * mul + add) mod 256` for `i` in `0..N`: the second vector set, so that byte order matters.
    fn seq<const N: usize>(mul: u8, add: u8) -> [u8; N] {
        std::array::from_fn(|i| (i as u8).wrapping_mul(mul).wrapping_add(add))
    }

    fn key(bytes: [u8; 32]) -> EndpointKey {
        EndpointKey::from_bytes(bytes)
    }

    fn now() -> OffsetDateTime {
        datetime!(2026-11-10 10:00:00 UTC)
    }

    fn relays() -> Vec<Url> {
        vec![Url::parse("https://relay.example.invalid/").unwrap()]
    }

    fn invite() -> (Invite, ListenerNonce) {
        let nonce = ListenerNonce::generate();
        let inv = Invite::generate(key(rep(0x22)), key(rep(0x33)), relays(), &nonce, now()).unwrap();
        (inv, nonce)
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// The pinned list is exactly BIP-39's `english.txt`, whose SHA-256 is published with BIP-39.
    #[test]
    fn the_word_list_is_the_bip39_english_list() {
        let words = &wordlist::WORDS;
        assert_eq!(words.len(), 2048);
        let mut text = String::new();
        for w in words {
            text.push_str(w);
            text.push('\n');
        }
        assert_eq!(
            data_encoding::HEXLOWER.encode(&<sha2::Sha256 as sha2::Digest>::digest(text.as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        assert!(words.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
        assert!(
            words
                .iter()
                .all(|w| (3..=8).contains(&w.len()) && w.bytes().all(|b| b.is_ascii_lowercase()))
        );
        let prefixes: std::collections::BTreeSet<&str> = words.iter().map(|w| &w[..w.len().min(4)]).collect();
        assert_eq!(prefixes.len(), 2048, "the first four letters identify a word");
    }

    /// SI-H2-16: test vectors, computed independently of this crate (Python `blake3` and the BIP-39 list).
    #[test]
    fn the_phrases_match_the_vectors() {
        let code = InviteCode::from_bytes(seq::<16>(1, 0));
        assert_eq!(
            hub_phrase(&key(rep(0x11)), &key(rep(0x22)), &code).to_string(),
            "boring seek carry absurd promote credit"
        );
        assert_eq!(
            approval_phrase(
                &key(rep(0x11)),
                &key(rep(0x33)),
                &ListenerNonce::from_bytes(rep(0x55)),
                &HubNonce::from_bytes(rep(0x66))
            )
            .to_string(),
            "proof cheese clay parrot treat dove"
        );
        assert_eq!(
            node_phrase(&key(rep(0x44))).to_string(),
            "blame swim enroll fire wagon custom"
        );
        assert_eq!(
            ListenerNonce::from_bytes(rep(0x55)).commitment().to_string(),
            "42687bb3b48f92994ef1eacfb585362833ca91c7fa815ec7c34031ef95bb6846"
        );

        let (hub, listener, agent, node) = (seq(7, 1), seq(13, 2), seq(29, 3), seq(31, 4));
        let code = InviteCode::from_bytes(seq::<16>(17, 5));
        let (ln, hn) = (ListenerNonce::from_bytes(seq(37, 6)), HubNonce::from_bytes(seq(41, 7)));
        assert_eq!(
            hub_phrase(&key(hub), &key(listener), &code).to_string(),
            "ride spray mammal purse mixed regret"
        );
        assert_eq!(
            approval_phrase(&key(hub), &key(agent), &ln, &hn).to_string(),
            "prize egg invest recipe camp feature"
        );
        assert_eq!(
            node_phrase(&key(node)).to_string(),
            "bless type depend like purpose unlock"
        );
        assert_eq!(
            ln.commitment().to_string(),
            "13072cfe3230b12fbde325942223900a2f54ce4ea57559a792ca61257eda3f62"
        );
    }

    /// The 66 bits are the first ones of the hash, most significant first, 11 per word.
    #[test]
    fn a_phrase_takes_the_first_66_bits_of_the_hash() {
        assert_eq!(CheckPhrase::from_hash(&[0; 32]).words(), ["abandon"; 6]);
        assert_eq!(CheckPhrase::from_hash(&[0xff; 32]).words(), ["zoo"; 6]);
        let mut h = [0u8; 32];
        h[1] = 0x20; // bit 10 of the first 11-bit group: index 1.
        assert_eq!(CheckPhrase::from_hash(&h).words()[0], "ability");
        let mut h = [0u8; 32];
        h[8] = 0x40; // bit 65, the last bit of the sixth group: index 1.
        assert_eq!(
            CheckPhrase::from_hash(&h).words(),
            ["abandon", "abandon", "abandon", "abandon", "abandon", "ability"]
        );
        // Bits 66 and beyond are not used.
        let mut h = [0xffu8; 32];
        h[..8].fill(0);
        h[8] = 0x3f;
        assert_eq!(CheckPhrase::from_hash(&h).words(), ["abandon"; 6]);
        assert_eq!(PHRASE_WORDS * 11, PHRASE_BITS);
        let p = CheckPhrase::from_hash(&[0; 32]);
        assert_eq!(
            format!("{p:?}"),
            "CheckPhrase(\"abandon abandon abandon abandon abandon abandon\")"
        );
        assert_eq!(
            serde_json::to_value(p).unwrap(),
            json!("abandon abandon abandon abandon abandon abandon")
        );
    }

    /// SI-H2-16: each phrase is a pure function of its inputs and of nothing else, and every input counts.
    #[test]
    fn every_input_of_a_phrase_counts() {
        let (hub, other_hub) = (key(rep(1)), key(rep(2)));
        let (listener, agent) = (key(rep(3)), key(rep(4)));
        let code = InviteCode::from_bytes([5; 16]);
        let (ln, hn) = (ListenerNonce::from_bytes(rep(6)), HubNonce::from_bytes(rep(7)));
        let base = hub_phrase(&hub, &listener, &code);
        assert_eq!(base, hub_phrase(&hub, &listener, &code));
        assert_ne!(base, hub_phrase(&other_hub, &listener, &code));
        assert_ne!(base, hub_phrase(&hub, &agent, &code));
        assert_ne!(base, hub_phrase(&hub, &listener, &InviteCode::from_bytes([6; 16])));
        // The order of the NodeIds matters.
        assert_ne!(base, hub_phrase(&listener, &hub, &code));

        let base = approval_phrase(&hub, &agent, &ln, &hn);
        assert_eq!(base, approval_phrase(&hub, &agent, &ln, &hn));
        assert_ne!(base, approval_phrase(&other_hub, &agent, &ln, &hn));
        assert_ne!(base, approval_phrase(&hub, &listener, &ln, &hn));
        assert_ne!(
            base,
            approval_phrase(&hub, &agent, &ListenerNonce::from_bytes(rep(8)), &hn)
        );
        assert_ne!(base, approval_phrase(&hub, &agent, &ln, &HubNonce::from_bytes(rep(8))));
        // Swapping the two nonces gives another phrase.
        assert_ne!(
            base,
            approval_phrase(
                &hub,
                &agent,
                &ListenerNonce::from_bytes(rep(7)),
                &HubNonce::from_bytes(rep(6))
            )
        );

        assert_eq!(node_phrase(&agent), node_phrase(&agent));
        assert_ne!(node_phrase(&agent), node_phrase(&listener));
        // Domain separation: the node phrase of a key is not the hash of the same bytes under another domain.
        assert_ne!(
            node_phrase(&agent),
            CheckPhrase::from_hash(blake3::hash(agent.as_bytes()).as_bytes())
        );
    }

    #[test]
    fn the_commitment_binds_the_listener_nonce() {
        let nonce = ListenerNonce::generate();
        let c = nonce.commitment();
        let expected = {
            let mut h = blake3::Hasher::new();
            h.update(b"p2pc-join-commit-v1");
            h.update(nonce.expose_bytes());
            *h.finalize().as_bytes()
        };
        assert_eq!(c.as_bytes(), &expected);
        assert!(c.verify(&nonce));
        let mut other = *nonce.expose_bytes();
        other[31] ^= 1;
        assert!(!c.verify(&ListenerNonce::from_bytes(other)));
        assert_ne!(ListenerNonce::generate(), nonce);
        assert_ne!(HubNonce::generate(), HubNonce::generate());
        assert_ne!(InviteCode::generate(), InviteCode::generate());
    }

    #[test]
    fn byte_values_use_one_text_form_each() {
        let nonce = ListenerNonce::from_bytes(seq(3, 9));
        let hex = data_encoding::HEXLOWER.encode(nonce.expose_bytes());
        assert_eq!(serde_json::to_value(&nonce).unwrap(), json!(hex));
        assert_eq!(serde_json::from_value::<ListenerNonce>(json!(hex)).unwrap(), nonce);
        let hub_nonce = HubNonce::from_bytes(seq(3, 9));
        assert_eq!(serde_json::to_value(hub_nonce).unwrap(), json!(hex));
        assert_eq!(hub_nonce.to_string(), hex);
        let commitment = nonce.commitment();
        assert_eq!(
            serde_json::from_value::<ListenerCommitment>(serde_json::to_value(commitment).unwrap()).unwrap(),
            commitment
        );
        for bad in [
            hex.to_ascii_uppercase(),
            hex[..62].to_string(),
            format!("{hex}00"),
            String::new(),
        ] {
            assert!(serde_json::from_value::<ListenerNonce>(json!(bad)).is_err(), "{bad}");
            assert!(serde_json::from_value::<HubNonce>(json!(bad)).is_err(), "{bad}");
            assert!(
                serde_json::from_value::<ListenerCommitment>(json!(bad)).is_err(),
                "{bad}"
            );
        }
        let code = InviteCode::from_bytes(seq::<16>(1, 0));
        let b32 = crate::pair::b32_encode(code.expose_bytes());
        assert_eq!(b32.len(), 26);
        assert_eq!(serde_json::to_value(&code).unwrap(), json!(b32));
        assert_eq!(serde_json::from_value::<InviteCode>(json!(b32)).unwrap(), code);
        for bad in [
            b32.to_ascii_uppercase(),
            b32[..25].to_string(),
            crate::pair::b32_encode(&[1; 15]),
        ] {
            assert!(serde_json::from_value::<InviteCode>(json!(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn secrets_never_show_in_debug() {
        let nonce = ListenerNonce::from_bytes(rep(0xab));
        let code = InviteCode::from_bytes([0xcd; 16]);
        for debug in [format!("{nonce:?}"), format!("{code:?}")] {
            assert!(debug.contains("***"), "{debug}");
            assert!(!debug.contains("abab") && !debug.contains("cdcd"), "{debug}");
        }
        let b32 = crate::pair::b32_encode(code.expose_bytes());
        let (mut inv, _) = invite();
        inv.code = code.clone();
        assert!(!format!("{inv:?}").contains(&b32));
        let open = InviteRequest::InviteOpen {
            code: code.clone(),
            hub_node_id: key(rep(1)),
            hub_nonce: HubNonce::from_bytes(rep(2)),
        };
        assert!(!format!("{open:?}").contains(&b32));
        let reveal = InviteResponse::InviteReveal { listener_nonce: nonce };
        assert!(!format!("{reveal:?}").contains("abab"));
    }

    #[test]
    fn an_invite_round_trips_and_carries_the_commitment_never_the_nonce() {
        let (inv, nonce) = invite();
        assert_eq!(inv.expires_at, now() + Duration::minutes(15));
        assert_eq!(inv.commitment, nonce.commitment());
        let text = inv.encode().unwrap();
        assert!(text.starts_with(INVITE_PREFIX));
        assert!(text.len() <= MAX_INVITE_LEN);
        assert_eq!(Invite::decode(&text).unwrap(), inv);
        assert_eq!(
            serde_json::from_value::<Invite>(serde_json::to_value(&inv).unwrap()).unwrap(),
            inv
        );

        let json = data_encoding::BASE32_NOPAD
            .decode(text[INVITE_PREFIX.len()..].to_ascii_uppercase().as_bytes())
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(
            v,
            json!({"v": 1, "l": key(rep(0x22)).to_string(), "a": key(rep(0x33)).to_string(),
                   "r": ["https://relay.example.invalid/"], "c": crate::pair::b32_encode(inv.code.expose_bytes()),
                   "m": nonce.commitment().to_string(), "e": (now() + Duration::minutes(15)).unix_timestamp()})
        );
        let raw = String::from_utf8(json).unwrap();
        assert!(!raw.contains(&data_encoding::HEXLOWER.encode(nonce.expose_bytes())));
        assert!(!raw.contains(&crate::pair::b32_encode(nonce.expose_bytes())));

        assert!(!inv.is_expired(now() + Duration::minutes(14)));
        assert!(inv.is_expired(now() + Duration::minutes(15)));
        assert_eq!(
            inv.hub_phrase(&key(rep(0x11))),
            hub_phrase(&key(rep(0x11)), &inv.listener, &inv.code)
        );
    }

    #[test]
    fn malformed_invites_are_refused() {
        let (inv, _) = invite();
        let good = inv.encode().unwrap();
        let body = &good[INVITE_PREFIX.len()..];
        let l = key(rep(0x22)).to_string();
        let a = key(rep(0x33)).to_string();
        let c = crate::pair::b32_encode(&[1; 16]);
        let m = key(rep(0x44)).to_string();
        let payload = |v: serde_json::Value| {
            format!(
                "{INVITE_PREFIX}{}",
                crate::pair::b32_encode(&serde_json::to_vec(&v).unwrap())
            )
        };
        let cases = [
            format!("p2pc_pair_{body}"),
            format!("p2pc_join_{body}"),
            good.to_ascii_uppercase(),
            format!("{INVITE_PREFIX}{}", "a".repeat(MAX_INVITE_LEN)),
            payload(json!({"v": 2, "l": l, "a": a, "r": [], "c": c, "m": m, "e": 1})),
            payload(json!({"v": 1, "l": l, "a": a, "r": [], "c": c, "m": m, "e": 1, "n": m})),
            payload(json!({"v": 1, "l": l, "a": a, "r": [], "c": c, "e": 1})),
            payload(json!({"v": 1, "l": &l[..62], "a": a, "r": [], "c": c, "m": m, "e": 1})),
            payload(
                json!({"v": 1, "l": l, "a": key(rep(0xab)).to_string().to_ascii_uppercase(), "r": [], "c": c, "m": m, "e": 1}),
            ),
            payload(json!({"v": 1, "l": l, "a": a, "r": [], "c": crate::pair::b32_encode(&[1; 17]), "m": m, "e": 1})),
            payload(json!({"v": 1, "l": l, "a": a, "r": [], "c": c, "m": &m[..60], "e": 1})),
            payload(json!({"v": 1, "l": l, "a": a, "r": ["ftp://relay.example.invalid/"], "c": c, "m": m, "e": 1})),
            payload(json!({"v": 1, "l": l, "a": a, "r": [], "c": c, "m": m, "e": i64::MIN})),
        ];
        for (n, text) in cases.iter().enumerate() {
            assert!(Invite::decode(text).is_err(), "case {n}");
        }
        assert!(
            Invite::decode(&payload(
                json!({"v": 1, "l": l, "a": a, "r": [], "c": c, "m": m, "e": 1})
            ))
            .is_ok()
        );
        assert!(!Invite::decode(&cases[0]).unwrap_err().to_string().contains(body));
    }

    #[test]
    fn invites_too_long_for_a_qr_code_are_not_encoded() {
        let long = (0..8)
            .map(|i| Url::parse(&format!("https://relay-{i}.{}.example.invalid/", "r".repeat(300))).unwrap())
            .collect();
        let nonce = ListenerNonce::generate();
        assert_eq!(
            Invite::generate(key(rep(1)), key(rep(2)), long, &nonce, now()).unwrap_err(),
            InviteFormatError::TooLong
        );
    }

    #[test]
    fn the_qr_link_carries_the_invite_in_the_fragment() {
        let (inv, _) = invite();
        let link = inv
            .link(&Url::parse("https://app.example.invalid/x?y#z").unwrap())
            .unwrap();
        assert_eq!(
            link.as_str(),
            format!("https://app.example.invalid/invite#{}", inv.encode().unwrap())
        );
        assert_eq!(Invite::decode(link.fragment().unwrap()).unwrap(), inv);
        assert_eq!(
            inv.link(&Url::parse("http://app.example.invalid/").unwrap())
                .unwrap_err(),
            InviteFormatError::InvalidOrigin
        );
    }

    /// SI-H2-16: the hub refuses `invite_expires_at` outside `(now, now + 15 min + 120 s]`.
    #[test]
    fn the_hub_accepts_an_invite_expiry_only_within_the_window() {
        let n = now();
        assert!(!invite_expiry_acceptable(n, n), "equal to now");
        assert!(!invite_expiry_acceptable(n - Duration::seconds(1), n), "in the past");
        assert!(invite_expiry_acceptable(n + Duration::seconds(1), n));
        assert!(invite_expiry_acceptable(n + Duration::minutes(15), n));
        assert!(
            invite_expiry_acceptable(n + Duration::seconds(15 * 60 + 120), n),
            "the edge"
        );
        assert!(
            !invite_expiry_acceptable(n + Duration::seconds(15 * 60 + 121), n),
            "1 s beyond"
        );
        assert_eq!(INVITE_TTL, Duration::minutes(15));
        assert_eq!(INVITE_CLOCK_SKEW, Duration::seconds(120));
    }

    #[test]
    fn a_join_token_names_the_hub_by_its_canonical_node_id() {
        let hub = key(seq(7, 1));
        let token =
            |server: String| JoinToken::generate(server, vec![], crate::auth::DEFAULT_JOIN_TOKEN_TTL, now()).unwrap();
        assert!(join_token_names_hub(&token(hub.to_string()), &hub));
        assert!(!join_token_names_hub(&token(key(seq(7, 2)).to_string()), &hub));
        // Anything but the canonical hex form fails closed (`hub_mismatch`).
        assert!(!join_token_names_hub(&token("a".repeat(52)), &hub));
        assert!(!join_token_names_hub(&token(format!("{hub}00")), &hub));
    }

    fn token() -> JoinToken {
        JoinToken::generate(
            key(rep(0x11)).to_string(),
            relays(),
            crate::auth::DEFAULT_JOIN_TOKEN_TTL,
            now(),
        )
        .unwrap()
    }

    #[test]
    fn invite_messages_wire_format_matches_the_spec() {
        let code = InviteCode::from_bytes([9; 16]);
        let c = crate::pair::b32_encode(&[9; 16]);
        let open = InviteRequest::InviteOpen {
            code: code.clone(),
            hub_node_id: key(rep(0x11)),
            hub_nonce: HubNonce::from_bytes(rep(0x66)),
        };
        assert_eq!(
            serde_json::to_value(&open).unwrap(),
            json!({"type": "invite_open", "code": c, "hub_node_id": key(rep(0x11)).to_string(),
                   "hub_nonce": HubNonce::from_bytes(rep(0x66)).to_string()})
        );
        assert_eq!(open.kind(), "invite_open");
        let t = token();
        let hand_over = InviteRequest::Invite {
            code,
            join_token: t.clone(),
            hub_name: "Home cloud".into(),
        };
        assert_eq!(
            serde_json::to_value(&hand_over).unwrap(),
            json!({"type": "invite", "code": c, "join_token": t.encode().unwrap(), "hub_name": "Home cloud"})
        );
        assert_eq!(hand_over.kind(), "invite");
        let reveal = InviteResponse::InviteReveal {
            listener_nonce: ListenerNonce::from_bytes(rep(0x55)),
        };
        assert_eq!(
            serde_json::to_value(&reveal).unwrap(),
            json!({"type": "invite_reveal", "listener_nonce": data_encoding::HEXLOWER.encode(&rep(0x55))})
        );
        assert_eq!(
            serde_json::to_value(InviteResponse::InviteAck {}).unwrap(),
            json!({"type": "invite_ack"})
        );
        for (code, wire) in [
            (InviteErrorCode::InvalidCode, "invalid_code"),
            (InviteErrorCode::Expired, "expired"),
            (InviteErrorCode::AlreadyOpen, "already_open"),
            (InviteErrorCode::HubMismatch, "hub_mismatch"),
        ] {
            let msg = InviteResponse::InviteError { code };
            assert_eq!(
                serde_json::to_value(&msg).unwrap(),
                json!({"type": "invite_error", "code": wire})
            );
            assert_eq!(code.to_string(), wire);
            assert_eq!(msg.kind(), "invite_error");
        }
        assert_eq!(InviteErrorCode::ALL.len(), 4);
        for msg in [
            reveal,
            InviteResponse::InviteAck {},
            InviteResponse::unsupported_message(),
        ] {
            let back: InviteResponse = serde_json::from_value(serde_json::to_value(&msg).unwrap()).unwrap();
            assert_eq!(back, msg);
        }
    }

    #[test]
    fn invite_messages_follow_the_compatibility_rules() {
        let c = crate::pair::b32_encode(&[9; 16]);
        let open = json!({"type": "invite_open", "code": c, "hub_node_id": key(rep(1)).to_string(),
                          "hub_nonce": key(rep(2)).to_string(), "future": [1]});
        assert!(matches!(
            serde_json::from_value::<InviteRequest>(open).unwrap(),
            InviteRequest::InviteOpen { .. }
        ));
        assert_eq!(
            serde_json::from_value::<InviteRequest>(json!({"type": "invite_close"})).unwrap(),
            InviteRequest::Unknown
        );
        assert_eq!(
            serde_json::from_value::<InviteResponse>(json!({"type": "invite_wait", "s": 1})).unwrap(),
            InviteResponse::Unknown
        );
        assert_eq!(
            serde_json::from_value::<InviteResponse>(json!({"type": "invite_error", "code": "later"})).unwrap(),
            InviteResponse::InviteError {
                code: InviteErrorCode::Unknown
            }
        );
        assert_eq!(
            serde_json::from_value::<InviteResponse>(json!({"type": "invite_ack", "x": 1})).unwrap(),
            InviteResponse::InviteAck {}
        );
        // `InviteOpen` requires the hub NodeId and the hub nonce (§5.4 "Direct tokens": no join without the phrase).
        for missing in ["hub_node_id", "hub_nonce", "code"] {
            let mut v = json!({"type": "invite_open", "code": c, "hub_node_id": key(rep(1)).to_string(),
                               "hub_nonce": key(rep(2)).to_string()});
            v.as_object_mut().unwrap().remove(missing);
            assert!(serde_json::from_value::<InviteRequest>(v).is_err(), "{missing}");
        }
        assert!(
            serde_json::from_value::<InviteRequest>(
                json!({"type": "invite", "code": c, "join_token": "p2pc_join_aa", "hub_name": "x"})
            )
            .is_err()
        );
    }

    #[test]
    fn invite_messages_are_validated() {
        let with_name = |hub_name: String| InviteRequest::Invite {
            code: InviteCode::from_bytes([1; 16]),
            join_token: token(),
            hub_name,
        };
        assert_eq!(with_name("Home".into()).validate(), Ok(()));
        assert_eq!(with_name("h".repeat(MAX_HUB_NAME_LEN)).validate(), Ok(()));
        assert!(with_name("h".repeat(MAX_HUB_NAME_LEN + 1)).validate().is_err());
        assert!(with_name("Ho\u{202e}me".into()).validate().is_err());
        assert!(with_name("a\nb".into()).validate().is_err());
        let open = InviteRequest::InviteOpen {
            code: InviteCode::from_bytes([1; 16]),
            hub_node_id: key(rep(1)),
            hub_nonce: HubNonce::from_bytes(rep(2)),
        };
        assert_eq!(open.validate(), Ok(()));
        assert_eq!(InviteRequest::Unknown.validate(), Ok(()));
        let long = InviteResponse::Error {
            code: "x".into(),
            message: "m".repeat(crate::protocol::MAX_TEXT_LEN + 1),
        };
        assert!(long.validate().is_err());
        assert_eq!(InviteResponse::InviteAck {}.validate(), Ok(()));
    }

    #[test]
    fn the_limits_match_the_spec() {
        assert_eq!(INVITE_MAX_FRAME_LEN, 4096);
        assert_eq!(INVITE_DEADLINE, std::time::Duration::from_secs(10));
        assert_eq!((INVITE_MAX_CONNECTIONS, INVITE_MAX_PENDING), (8, 2));
        assert_eq!(INVITE_FAILURES_PER_NODE_PER_MINUTE, 5);
        assert_eq!((INVITE_CODE_LEN, NONCE_LEN), (16, 32));
    }

    #[test]
    fn the_messages_fit_in_one_frame_and_oversized_frames_are_refused() {
        let messages = [
            InviteRequest::InviteOpen {
                code: InviteCode::generate(),
                hub_node_id: key(rep(1)),
                hub_nonce: HubNonce::generate(),
            },
            InviteRequest::Invite {
                code: InviteCode::generate(),
                join_token: token(),
                hub_name: "\"".repeat(MAX_HUB_NAME_LEN),
            },
        ];
        for msg in messages {
            let mut buf = Vec::new();
            block_on(write_frame(&mut buf, &msg)).unwrap();
            assert!(buf.len() - 4 <= INVITE_MAX_FRAME_LEN as usize);
            let mut r = buf.as_slice();
            assert_eq!(
                block_on(read_frame_with_limit::<InviteRequest, _>(&mut r, INVITE_MAX_FRAME_LEN)).unwrap(),
                Some(msg)
            );
        }
        let mut buf = (INVITE_MAX_FRAME_LEN + 1).to_be_bytes().to_vec();
        buf.extend(std::iter::repeat_n(b'{', 16));
        let mut r = buf.as_slice();
        assert!(matches!(
            block_on(read_frame_with_limit::<InviteRequest, _>(&mut r, INVITE_MAX_FRAME_LEN)),
            Err(FrameError::TooLarge { .. })
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn invites_round_trip(
            l in any::<[u8; 32]>(),
            a in any::<[u8; 32]>(),
            n in any::<[u8; 32]>(),
            hosts in proptest::collection::vec("[a-z]{1,20}", 0..3),
            t in 0i64..4_102_444_800,
        ) {
            let relays = hosts.iter().map(|h| Url::parse(&format!("https://{h}.example.invalid/")).unwrap()).collect();
            let nonce = ListenerNonce::from_bytes(n);
            let now = OffsetDateTime::from_unix_timestamp(t).unwrap();
            let inv = Invite::generate(key(l), key(a), relays, &nonce, now).unwrap();
            prop_assert!(inv.commitment.verify(&nonce));
            prop_assert_eq!(Invite::decode(&inv.encode().unwrap()).unwrap(), inv);
        }

        #[test]
        fn phrases_are_six_words_of_the_list(k in any::<[u8; 32]>(), c in any::<[u8; 16]>(), x in any::<[u8; 32]>()) {
            for p in [
                node_phrase(&key(k)),
                hub_phrase(&key(k), &key(x), &InviteCode::from_bytes(c)),
                approval_phrase(&key(k), &key(x), &ListenerNonce::from_bytes(x), &HubNonce::from_bytes(k)),
            ] {
                prop_assert_eq!(p.to_string().split(' ').count(), PHRASE_WORDS);
                prop_assert!(p.words().iter().all(|w| wordlist::WORDS.binary_search(w).is_ok()));
            }
        }

        /// SI-H2-17: the decoders never panic on hostile input.
        #[test]
        fn hostile_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048), text in "\\PC{0,256}") {
            let _ = Invite::decode(&text);
            let _ = Invite::decode(&format!("{INVITE_PREFIX}{text}"));
            let mut r = bytes.as_slice();
            while let Ok(Some(msg)) = block_on(read_frame_with_limit::<InviteRequest, _>(&mut r, INVITE_MAX_FRAME_LEN)) {
                let _ = msg.validate();
            }
            let mut r = bytes.as_slice();
            while let Ok(Some(msg)) = block_on(read_frame_with_limit::<InviteResponse, _>(&mut r, INVITE_MAX_FRAME_LEN)) {
                let _ = msg.validate();
            }
            let _ = crate::protocol::decode_frame::<InviteRequest>(&bytes);
            let _ = crate::protocol::decode_frame::<InviteResponse>(&bytes);
        }

        #[test]
        fn tagged_garbage_never_panics(
            kind in prop_oneof![
                Just("invite_open".to_string()),
                Just("invite".to_string()),
                Just("invite_reveal".to_string()),
                Just("invite_error".to_string()),
                "[a-z_]{0,12}",
            ],
            s in "\\PC{0,80}",
            n in any::<i64>(),
        ) {
            let v = json!({"type": kind, "code": s, "hub_node_id": s, "hub_nonce": s, "join_token": s,
                           "hub_name": s, "listener_nonce": s, "n": n});
            if let Ok(msg) = serde_json::from_value::<InviteRequest>(v.clone()) {
                let _ = msg.validate();
            }
            if let Ok(msg) = serde_json::from_value::<InviteResponse>(v) {
                let _ = msg.validate();
            }
        }
    }
}
