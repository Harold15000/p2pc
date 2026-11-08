// SPDX-License-Identifier: Apache-2.0

//! API keys, join tokens and secret redaction (spec §5, SI-6, SI-11).
//!
//! - An API key is `p2pc_sk_<key_id>_<secret>`: a 12-character [`KeyId`] and 32 random bytes in lowercase unpadded
//!   base32. The server stores the key ID and [`hash_secret`] of the secret (SHA-256: the secret has 256 bits of
//!   entropy, so a slow hash is not needed) and compares hashes in constant time.
//! - A join token is `p2pc_join_` plus lowercase unpadded base32 of a compact JSON payload with the server's iroh
//!   NodeId, relay hints, a 16-byte random code and the expiry. The server stores only [`JoinToken::code_hash`].
//! - A server address is `p2pc_srv_` plus the same payload without the code and the expiry ([`ServerAddress`],
//!   §10). It is not a secret.
//!
//! No secret is ever printed: `Debug` and `Display` of [`ApiKey`] give `p2pc_sk_<key_id>_***`, [`Secret`] prints
//! `***`, and [`JoinToken`]'s `Debug` hides the code. The full values are only available through explicitly named
//! methods ([`ApiKey::expose`], [`JoinToken::encode`]) and through `Serialize`, which the API needs to return a new
//! key or token exactly once.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::ids::{BASE32_LOWER, KEY_ID_LEN, KeyId};

/// Prefix of every API key.
pub const API_KEY_PREFIX: &str = "p2pc_sk_";
/// Prefix of every join token.
pub const JOIN_TOKEN_PREFIX: &str = "p2pc_join_";
/// Prefix of a server address (§10 "Server address").
pub const SERVER_ADDRESS_PREFIX: &str = "p2pc_srv_";
/// Bytes of entropy in an API key secret.
pub const SECRET_LEN: usize = 32;
/// Base32 characters of an API key secret (32 bytes, unpadded).
const SECRET_B32_LEN: usize = 52;
/// Total length of an API key string.
pub const API_KEY_LEN: usize = API_KEY_PREFIX.len() + KEY_ID_LEN + 1 + SECRET_B32_LEN;
/// Bytes in a join code.
pub const JOIN_CODE_LEN: usize = 16;
/// Default validity of a join token (§5: 15 minutes).
pub const DEFAULT_JOIN_TOKEN_TTL: Duration = Duration::minutes(15);
/// Longest validity of a join token (§5: 24 hours).
pub const MAX_JOIN_TOKEN_TTL: Duration = Duration::hours(24);
/// Longest join token string accepted by [`JoinToken::decode`].
pub const MAX_JOIN_TOKEN_LEN: usize = 8192;
/// Most relay hints in a join token.
pub const MAX_RELAYS: usize = 8;
/// Longest relay URL.
pub const MAX_RELAY_URL_LEN: usize = 512;
/// Shortest server NodeId string.
pub const MIN_SERVER_ID_LEN: usize = 32;
/// Longest server NodeId string.
pub const MAX_SERVER_ID_LEN: usize = 128;
/// Version of the join token payload.
const JOIN_TOKEN_VERSION: u8 = 1;

/// Why a key or token is refused. Messages never contain the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// The string is not a well-formed API key.
    #[error("malformed API key")]
    MalformedApiKey,
    /// The string is not a well-formed join token.
    #[error("malformed join token")]
    MalformedJoinToken,
    /// The join token's server NodeId has the wrong length or characters.
    #[error("invalid server NodeId in join token")]
    InvalidServerId,
    /// A stored digest is not `sha256:` plus 64 lowercase hex characters.
    #[error("malformed stored digest")]
    MalformedStoredDigest,
    /// A relay URL is not plain `http(s)://host…` without credentials, or there are too many.
    #[error("invalid relay URL in join token")]
    InvalidRelay,
    /// The requested validity is not between 1 second and 24 hours.
    #[error("the join token validity must be between 1 second and 24 hours")]
    InvalidTtl,
    /// The expiry cannot be represented.
    #[error("invalid join token expiry")]
    InvalidExpiry,
    /// The string is not a well-formed server address (`p2pc_srv_…`).
    #[error("malformed server address")]
    MalformedServerAddress,
}

/// Lowercase unpadded base32 (RFC 4648 alphabet), canonical: trailing bits must be zero.
fn b32_encode(bytes: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(bytes).to_ascii_lowercase()
}

fn b32_decode(text: &str) -> Option<Vec<u8>> {
    if !text.bytes().all(|b| BASE32_LOWER.contains(&b)) {
        return None;
    }
    data_encoding::BASE32_NOPAD
        .decode(text.to_ascii_uppercase().as_bytes())
        .ok()
}

/// The 32 random bytes of an API key. `Debug` prints `***`; equality is constant-time.
#[derive(Clone)]
pub struct Secret([u8; SECRET_LEN]);

impl Secret {
    /// Generates a new random secret from the thread-local CSPRNG (seeded by the OS).
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_LEN];
        rand::fill(&mut bytes);
        Self(bytes)
    }

    /// The raw bytes. Never log them.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Secret {}

/// SHA-256 of a secret, as stored by the server. Equality is constant-time.
#[derive(Clone, Copy)]
pub struct SecretHash([u8; 32]);

impl SecretHash {
    /// Wraps a stored hash.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The hash bytes, for storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time comparison.
    #[must_use]
    pub fn ct_eq(&self, other: &SecretHash) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    /// The versioned stored form (§5 "Stored digest"): `sha256:` plus 64 lowercase hex characters
    /// ([`STORED_DIGEST_LEN`] in total, which the database CHECKs).
    #[must_use]
    pub fn to_stored(&self) -> String {
        format!("{STORED_DIGEST_PREFIX}{}", data_encoding::HEXLOWER.encode(&self.0))
    }

    /// Parses the stored form, checking the prefix, the length and the charset (lowercase hex only, so each digest
    /// has exactly one spelling). The error never echoes the input.
    pub fn from_stored(stored: &str) -> Result<Self, AuthError> {
        let bad = AuthError::MalformedStoredDigest;
        if stored.len() != STORED_DIGEST_LEN {
            return Err(bad);
        }
        let hex = stored.strip_prefix(STORED_DIGEST_PREFIX).ok_or(bad)?;
        if !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(bad);
        }
        let bytes = data_encoding::HEXLOWER.decode(hex.as_bytes()).map_err(|_| bad)?;
        bytes.try_into().map(SecretHash).map_err(|_| bad)
    }
}

/// Prefix of a stored digest (§5): the algorithm, so it can change later.
pub const STORED_DIGEST_PREFIX: &str = "sha256:";
/// Length of a stored digest: `sha256:` plus 64 hex characters.
pub const STORED_DIGEST_LEN: usize = STORED_DIGEST_PREFIX.len() + 64;

impl PartialEq for SecretHash {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for SecretHash {}

impl fmt::Debug for SecretHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A hash of a 128- or 256-bit secret reveals nothing, but there is no reason to print it either.
        f.write_str("SecretHash(…)")
    }
}

/// SHA-256 of an API key secret (of its 32 raw bytes).
#[must_use]
pub fn hash_secret(secret: &Secret) -> SecretHash {
    SecretHash(Sha256::digest(secret.0).into())
}

/// A full API key, `p2pc_sk_<key_id>_<secret>`.
///
/// This is the redacting wrapper of SI-6: `Debug` and `Display` print `p2pc_sk_<key_id>_***`. Use
/// [`ApiKey::expose`] to get the full string (only to show it once, or to send it in an `Authorization` header).
/// `Serialize` writes the full key, because `POST /v1/keys` must return it.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKey {
    key_id: KeyId,
    secret: Secret,
}

impl ApiKey {
    /// Generates a new key with a random key ID and secret.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            key_id: KeyId::generate(),
            secret: Secret::generate(),
        }
    }

    /// Builds a key from its parts.
    #[must_use]
    pub fn from_parts(key_id: KeyId, secret: Secret) -> Self {
        Self { key_id, secret }
    }

    /// Parses `p2pc_sk_<key_id>_<secret>`. The error never contains the input.
    pub fn parse(text: &str) -> Result<Self, AuthError> {
        if text.len() != API_KEY_LEN {
            return Err(AuthError::MalformedApiKey);
        }
        let rest = text.strip_prefix(API_KEY_PREFIX).ok_or(AuthError::MalformedApiKey)?;
        let (key_id, rest) = rest.split_at_checked(KEY_ID_LEN).ok_or(AuthError::MalformedApiKey)?;
        let secret = rest.strip_prefix('_').ok_or(AuthError::MalformedApiKey)?;
        let key_id = KeyId::from_str(key_id).map_err(|_| AuthError::MalformedApiKey)?;
        let bytes = b32_decode(secret).ok_or(AuthError::MalformedApiKey)?;
        let bytes: [u8; SECRET_LEN] = bytes.try_into().map_err(|_| AuthError::MalformedApiKey)?;
        Ok(Self {
            key_id,
            secret: Secret(bytes),
        })
    }

    /// The public key ID.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The secret part.
    #[must_use]
    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    /// The hash to store: [`hash_secret`] of the secret.
    #[must_use]
    pub fn hash(&self) -> SecretHash {
        hash_secret(&self.secret)
    }

    /// Whether this key's secret matches a stored hash, in constant time.
    #[must_use]
    pub fn verify(&self, stored: &SecretHash) -> bool {
        self.hash().ct_eq(stored)
    }

    /// The full key string. Show it once; never log it.
    #[must_use]
    pub fn expose(&self) -> String {
        format!("{API_KEY_PREFIX}{}_{}", self.key_id, b32_encode(&self.secret.0))
    }
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{API_KEY_PREFIX}{}_***", self.key_id)
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApiKey({self})")
    }
}

impl FromStr for ApiKey {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for ApiKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.expose())
    }
}

impl<'de> Deserialize<'de> for ApiKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::ids::deserialize_from_str(deserializer)
    }
}

/// A node enrollment token (§5): single-use, short-lived, and secret because of its `code`.
///
/// `Debug` hides the code. [`JoinToken::encode`] and `Serialize` produce the full `p2pc_join_…` string. Equality
/// compares the code in constant time.
///
/// # The payload is not authenticated
///
/// The token is plain base32 JSON with no MAC or signature: whoever holds it can re-encode it with another expiry,
/// server or relays. Only the 16-byte `code` is a secret the holder cannot forge. So the server (T05) MUST:
/// 1. look the token up by [`JoinToken::code_hash`], comparing stored hashes with [`SecretHash::ct_eq`];
/// 2. use the **expiry and the single-use flag of its own row**, never `expires_at` from the payload;
/// 3. mark the row used in the same transaction that enrolls the node (SI-11).
///
/// `server` and `relays` are hints for the agent: a holder who tampers with them only misdirects their own agent.
#[derive(Clone)]
pub struct JoinToken {
    /// The server's iroh NodeId, as an opaque string (lowercase letters and digits, 32-128 characters).
    pub server: String,
    /// Relay URL hints (`http` or `https`, at most 8).
    pub relays: Vec<Url>,
    /// 16 random bytes. The server stores only their SHA-256 ([`JoinToken::code_hash`]).
    pub code: [u8; JOIN_CODE_LEN],
    /// Expiry, with whole-second precision.
    pub expires_at: OffsetDateTime,
}

/// The compact JSON inside a join token.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinPayload {
    v: u8,
    s: String,
    r: Vec<String>,
    c: String,
    e: i64,
}

impl JoinToken {
    /// Creates a token with a random code that expires `ttl` after `now` (1 second to 24 hours).
    pub fn generate(server: String, relays: Vec<Url>, ttl: Duration, now: OffsetDateTime) -> Result<Self, AuthError> {
        if ttl < Duration::seconds(1) || ttl > MAX_JOIN_TOKEN_TTL {
            return Err(AuthError::InvalidTtl);
        }
        let expires = now
            .unix_timestamp()
            .checked_add(ttl.whole_seconds())
            .ok_or(AuthError::InvalidExpiry)?;
        let expires_at = OffsetDateTime::from_unix_timestamp(expires).map_err(|_| AuthError::InvalidExpiry)?;
        let mut code = [0u8; JOIN_CODE_LEN];
        rand::fill(&mut code);
        let token = Self {
            server,
            relays,
            code,
            expires_at,
        };
        token.validate()?;
        Ok(token)
    }

    /// Checks the server NodeId and the relay URLs.
    pub fn validate(&self) -> Result<(), AuthError> {
        validate_hints(&self.server, &self.relays)
    }

    /// Encodes the token as `p2pc_join_<base32>`. This is the secret string: never log it.
    pub fn encode(&self) -> Result<String, AuthError> {
        self.validate()?;
        let payload = JoinPayload {
            v: JOIN_TOKEN_VERSION,
            s: self.server.clone(),
            r: relay_strings(&self.relays),
            c: b32_encode(&self.code),
            e: self.expires_at.unix_timestamp(),
        };
        let json = serde_json::to_vec(&payload).map_err(|_| AuthError::MalformedJoinToken)?;
        Ok(format!("{JOIN_TOKEN_PREFIX}{}", b32_encode(&json)))
    }

    /// Decodes a token string and checks its format and sizes. This does **not** authenticate it (see
    /// [`JoinToken`]) and does not check the expiry.
    pub fn decode(text: &str) -> Result<Self, AuthError> {
        if text.len() > MAX_JOIN_TOKEN_LEN {
            return Err(AuthError::MalformedJoinToken);
        }
        let body = text
            .strip_prefix(JOIN_TOKEN_PREFIX)
            .ok_or(AuthError::MalformedJoinToken)?;
        let json = b32_decode(body).ok_or(AuthError::MalformedJoinToken)?;
        let p: JoinPayload = serde_json::from_slice(&json).map_err(|_| AuthError::MalformedJoinToken)?;
        if p.v != JOIN_TOKEN_VERSION {
            return Err(AuthError::MalformedJoinToken);
        }
        let code = b32_decode(&p.c).ok_or(AuthError::MalformedJoinToken)?;
        let code: [u8; JOIN_CODE_LEN] = code.try_into().map_err(|_| AuthError::MalformedJoinToken)?;
        let relays = parse_relays(&p.r)?;
        let expires_at = OffsetDateTime::from_unix_timestamp(p.e).map_err(|_| AuthError::InvalidExpiry)?;
        let token = Self {
            server: p.s,
            relays,
            code,
            expires_at,
        };
        token.validate()?;
        Ok(token)
    }

    /// Whether the token's **own, unauthenticated** `expires_at` has passed at `now` (an expiry equal to `now` counts
    /// as expired).
    ///
    /// Good for an early, friendly error on the agent or the CLI. It is **not** a security check: the payload can be
    /// re-encoded with any expiry, so the server decides with the expiry stored in its own row (see [`JoinToken`]).
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }

    /// SHA-256 of the code: what the server stores and compares (in constant time, with [`SecretHash::ct_eq`]).
    #[must_use]
    pub fn code_hash(&self) -> SecretHash {
        SecretHash(Sha256::digest(self.code).into())
    }
}

/// The server NodeId and relay checks shared by [`JoinToken`] and [`ServerAddress`], so the two formats cannot
/// drift.
fn validate_hints(server: &str, relays: &[Url]) -> Result<(), AuthError> {
    let s = server.as_bytes();
    if !(MIN_SERVER_ID_LEN..=MAX_SERVER_ID_LEN).contains(&s.len())
        || !s.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(AuthError::InvalidServerId);
    }
    if relays.len() > MAX_RELAYS || !relays.iter().all(relay_ok) {
        return Err(AuthError::InvalidRelay);
    }
    Ok(())
}

/// The `r` field of a payload.
fn relay_strings(relays: &[Url]) -> Vec<String> {
    relays.iter().map(|u| u.as_str().to_string()).collect()
}

/// Parses the `r` field of a payload (count and length checked before parsing).
fn parse_relays(raw: &[String]) -> Result<Vec<Url>, AuthError> {
    if raw.len() > MAX_RELAYS {
        return Err(AuthError::InvalidRelay);
    }
    raw.iter()
        .map(|r| {
            if r.len() > MAX_RELAY_URL_LEN {
                return Err(AuthError::InvalidRelay);
            }
            Url::parse(r).map_err(|_| AuthError::InvalidRelay)
        })
        .collect()
}

fn relay_ok(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some_and(|h| !h.is_empty())
        && url.username().is_empty()
        && url.password().is_none()
        && url.as_str().len() <= MAX_RELAY_URL_LEN
}

impl PartialEq for JoinToken {
    fn eq(&self, other: &Self) -> bool {
        // The code is compared in constant time; `&` (not `&&`) so the result does not short-circuit on it.
        let code_eq: bool = self.code.ct_eq(&other.code).into();
        code_eq & (self.server == other.server) & (self.relays == other.relays) & (self.expires_at == other.expires_at)
    }
}

impl Eq for JoinToken {}

impl fmt::Debug for JoinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinToken")
            .field("server", &self.server)
            .field("relays", &self.relays.iter().map(Url::as_str).collect::<Vec<_>>())
            .field("code", &"***")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Serialize for JoinToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = self.encode().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for JoinToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        JoinToken::decode(&text).map_err(serde::de::Error::custom)
    }
}

/// The server's non-secret address (§10 "Server address"): `p2pc_srv_<base32 payload>`, where the payload is the
/// join-token payload without the code and the expiry (`{"v":1,"s":<NodeId>,"r":[<relay URLs>]}`).
///
/// A CLI profile whose `server` is such an address reaches the API through the `p2pc/http/1` tunnel. It is not a
/// secret, and holding it grants nothing: the API key is still required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddress {
    /// The server's iroh NodeId (the same format as [`JoinToken::server`]).
    pub server: String,
    /// Relay URL hints (`http` or `https`, at most 8).
    pub relays: Vec<Url>,
}

/// The compact JSON inside a server address: the join-token payload's `v`, `s` and `r`, nothing else.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddressPayload {
    v: u8,
    s: String,
    r: Vec<String>,
}

impl ServerAddress {
    /// The address of a server NodeId with its relay hints. Not validated: [`ServerAddress::encode`] does that.
    #[must_use]
    pub fn new(server: impl Into<String>, relays: Vec<Url>) -> Self {
        Self {
            server: server.into(),
            relays,
        }
    }

    /// The address that the hints of a join token describe.
    #[must_use]
    pub fn from_join_token(token: &JoinToken) -> Self {
        Self {
            server: token.server.clone(),
            relays: token.relays.clone(),
        }
    }

    /// Checks the server NodeId and the relay URLs, exactly as for a join token.
    pub fn validate(&self) -> Result<(), AuthError> {
        validate_hints(&self.server, &self.relays)
    }

    /// Encodes the address as `p2pc_srv_<base32>`.
    pub fn encode(&self) -> Result<String, AuthError> {
        self.validate()?;
        let payload = AddressPayload {
            v: JOIN_TOKEN_VERSION,
            s: self.server.clone(),
            r: relay_strings(&self.relays),
        };
        let json = serde_json::to_vec(&payload).map_err(|_| AuthError::MalformedServerAddress)?;
        Ok(format!("{SERVER_ADDRESS_PREFIX}{}", b32_encode(&json)))
    }

    /// Parses `p2pc_srv_<base32>`. A join token is refused (other prefix, and its payload has extra fields).
    pub fn parse(text: &str) -> Result<Self, AuthError> {
        let bad = AuthError::MalformedServerAddress;
        if text.len() > MAX_JOIN_TOKEN_LEN {
            return Err(bad);
        }
        let body = text.strip_prefix(SERVER_ADDRESS_PREFIX).ok_or(bad)?;
        let json = b32_decode(body).ok_or(bad)?;
        let p: AddressPayload = serde_json::from_slice(&json).map_err(|_| bad)?;
        if p.v != JOIN_TOKEN_VERSION {
            return Err(bad);
        }
        let address = Self {
            relays: parse_relays(&p.r)?,
            server: p.s,
        };
        address.validate()?;
        Ok(address)
    }
}

impl fmt::Display for ServerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.encode() {
            Ok(text) => f.write_str(&text),
            Err(_) => f.write_str("p2pc_srv_<invalid>"),
        }
    }
}

impl FromStr for ServerAddress {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for ServerAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = self.encode().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for ServerAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::ids::deserialize_from_str(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const SERVER: &str = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6";

    fn relays() -> Vec<Url> {
        vec![Url::parse("https://relay.example.invalid/").unwrap()]
    }

    fn token() -> JoinToken {
        JoinToken::generate(
            SERVER.into(),
            relays(),
            DEFAULT_JOIN_TOKEN_TTL,
            datetime!(2026-11-05 10:00:00 UTC),
        )
        .unwrap()
    }

    #[test]
    fn api_key_round_trip() {
        let key = ApiKey::generate();
        let text = key.expose();
        assert_eq!(text.len(), API_KEY_LEN);
        assert!(text.starts_with("p2pc_sk_"));
        let back = ApiKey::parse(&text).unwrap();
        assert_eq!(back, key);
        assert_eq!(back.key_id(), key.key_id());
        assert_eq!(text.as_bytes()[API_KEY_PREFIX.len() + KEY_ID_LEN], b'_');
        // Serialize writes the full key (returned once by POST /v1/keys).
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(json, format!("\"{text}\""));
        assert_eq!(serde_json::from_str::<ApiKey>(&json).unwrap(), key);
    }

    /// Spec §5 "Stored digest": `sha256:<64 lowercase hex>`, checked on the way back in.
    #[test]
    fn secret_hash_stored_format() {
        let key = ApiKey::generate();
        let stored = key.hash().to_stored();
        assert!(stored.starts_with("sha256:"));
        assert_eq!(stored.len(), STORED_DIGEST_LEN);
        assert!(
            stored["sha256:".len()..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let back = SecretHash::from_stored(&stored).unwrap();
        assert!(key.verify(&back));
        // A known vector: SHA-256 of 32 zero bytes.
        assert_eq!(
            hash_secret(&Secret([0; 32])).to_stored(),
            "sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
        );
        let hex = &stored["sha256:".len()..];
        let rejects = [
            String::new(),
            hex.to_string(),
            format!("SHA256:{hex}"),
            format!("sha512:{hex}"),
            format!("sha256:{}", hex.to_uppercase()),
            format!("sha256:{}", &hex[..63]),
            format!("sha256:{hex}0"),
            format!("sha256:{}g", &hex[..63]),
            format!("sha256: {}", &hex[..63]),
            format!("{stored}\n"),
            "sha256:".to_string(),
        ];
        for bad in rejects {
            assert_eq!(
                SecretHash::from_stored(&bad),
                Err(AuthError::MalformedStoredDigest),
                "{bad:?}"
            );
        }
        // The error never echoes the input.
        let err = SecretHash::from_stored(&format!("sha256:{}", hex.to_uppercase())).unwrap_err();
        assert!(!err.to_string().to_lowercase().contains(hex));
    }

    #[test]
    fn api_key_hash_and_constant_time_verify() {
        let key = ApiKey::generate();
        let stored = key.hash();
        assert!(key.verify(&stored));
        assert_eq!(stored, hash_secret(key.secret()));
        let other = ApiKey::generate();
        assert!(!other.verify(&stored));
        // Same key ID, different secret.
        let forged = ApiKey::from_parts(key.key_id(), Secret::generate());
        assert!(!forged.verify(&stored));
        // SHA-256 of 32 zero bytes, a known vector.
        let zero = hash_secret(&Secret([0; 32]));
        assert_eq!(
            data_encoding::HEXLOWER.encode(zero.as_bytes()),
            "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
        );
    }

    #[test]
    fn malformed_api_keys_are_rejected() {
        let good = ApiKey::generate().expose();
        let mut cases = vec![
            String::new(),
            "p2pc_sk_".to_string(),
            good[..good.len() - 1].to_string(),
            format!("{good}a"),
            good.replacen("p2pc_sk_", "p2pc_pk_", 1),
            good.to_uppercase(),
        ];
        // Separator replaced.
        let mut b = good.clone().into_bytes();
        b[API_KEY_PREFIX.len() + KEY_ID_LEN] = b'-';
        cases.push(String::from_utf8(b).unwrap());
        // Invalid base32 character in the secret.
        let mut b = good.clone().into_bytes();
        let last = b.len() - 2;
        b[last] = b'1';
        cases.push(String::from_utf8(b).unwrap());
        // Non-zero trailing bits in the last character (a non-canonical alias).
        let mut b = good.clone().into_bytes();
        let last = b.len() - 1;
        b[last] = if b[last] == b'b' { b'c' } else { b'b' };
        cases.push(String::from_utf8(b).unwrap());
        for case in cases {
            let err = ApiKey::parse(&case).unwrap_err();
            assert_eq!(err, AuthError::MalformedApiKey, "{case:?}");
        }
    }

    #[test]
    fn api_key_is_redacted_everywhere_but_expose_and_serialize() {
        let key = ApiKey::generate();
        let full = key.expose();
        let secret_part = &full[API_KEY_PREFIX.len() + KEY_ID_LEN + 1..];
        let redacted = format!("p2pc_sk_{}_***", key.key_id());
        assert_eq!(key.to_string(), redacted);
        let debug = format!("{key:?} {:?} {:?} {:?}", key.secret(), key.hash(), Some(&key));
        assert!(debug.contains(&redacted));
        assert!(!debug.contains(secret_part), "{debug}");
        // Errors do not echo the input.
        let err = ApiKey::parse(&format!("{full}x")).unwrap_err();
        assert!(!format!("{err} {err:?}").contains(secret_part));
        let err = serde_json::from_str::<ApiKey>(&format!("\"{full}x\"")).unwrap_err();
        assert!(!err.to_string().contains(secret_part), "{err}");
    }

    #[test]
    fn join_token_round_trip() {
        let t = token();
        let text = t.encode().unwrap();
        assert!(text.starts_with("p2pc_join_"));
        let body = &text["p2pc_join_".len()..];
        assert!(body.bytes().all(|b| BASE32_LOWER.contains(&b)), "{body}");
        let back = JoinToken::decode(&text).unwrap();
        assert_eq!(back, t);
        assert_eq!(back.code_hash(), t.code_hash());
        assert_eq!(back.expires_at, datetime!(2026-11-05 10:15:00 UTC));
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(serde_json::from_str::<JoinToken>(&json).unwrap(), t);
        // No relays is fine.
        let bare = JoinToken {
            relays: vec![],
            ..t.clone()
        };
        assert_eq!(JoinToken::decode(&bare.encode().unwrap()).unwrap(), bare);
    }

    #[test]
    fn join_codes_are_random() {
        assert_ne!(token().code, token().code);
        assert_ne!(token().code_hash(), token().code_hash());
    }

    #[test]
    fn join_token_expiry() {
        let t = token();
        assert!(!t.is_expired(datetime!(2026-11-05 10:14:59 UTC)));
        assert!(t.is_expired(datetime!(2026-11-05 10:15:00 UTC)));
        assert!(t.is_expired(datetime!(2026-11-06 00:00:00 UTC)));
        let now = datetime!(2026-11-05 10:00:00 UTC);
        let max = JoinToken::generate(SERVER.into(), vec![], MAX_JOIN_TOKEN_TTL, now).unwrap();
        assert_eq!(max.expires_at, datetime!(2026-11-06 10:00:00 UTC));
        for ttl in [
            Duration::ZERO,
            Duration::seconds(-5),
            MAX_JOIN_TOKEN_TTL + Duration::seconds(1),
        ] {
            assert_eq!(
                JoinToken::generate(SERVER.into(), vec![], ttl, now),
                Err(AuthError::InvalidTtl),
                "{ttl}"
            );
        }
    }

    #[test]
    fn tampered_join_tokens_never_redeem_with_another_code() {
        // A fixed code (not `generate`), so the set of tampers that decode, and the branch counts, are
        // deterministic: the test used to depend on which random code was drawn.
        let t = JoinToken {
            code: [0x5a; JOIN_CODE_LEN],
            ..token()
        };
        let issued_at = datetime!(2026-11-05 10:00:00 UTC);
        // One explicit "other code" tamper, so that branch never depends on chance either.
        let other = JoinToken {
            code: [0x5b; JOIN_CODE_LEN],
            ..t.clone()
        };
        let other = JoinToken::decode(&other.encode().unwrap()).unwrap();
        assert_eq!(
            TokenStore::issue(&t, issued_at).redeem(&other, issued_at + Duration::minutes(1)),
            Err("unknown")
        );
        let text = t.encode().unwrap();
        let prefix = JOIN_TOKEN_PREFIX.len();
        let (mut undecodable, mut other_code, mut same_code) = (0, 0, 0);
        for i in prefix..text.len() {
            let mut b = text.clone().into_bytes();
            b[i] = if b[i] == b'a' { b'b' } else { b'a' };
            let tampered = String::from_utf8(b).unwrap();
            let Ok(decoded) = JoinToken::decode(&tampered) else {
                undecodable += 1;
                continue;
            };
            assert_ne!(decoded, t, "position {i}");
            let mut store = TokenStore::issue(&t, issued_at);
            let redeemed = store.redeem(&decoded, issued_at + Duration::minutes(1));
            if decoded.code == t.code {
                // Only the hints or the expiry changed: the row still decides, with its own expiry.
                same_code += 1;
                assert_eq!(redeemed, Ok(()), "position {i}");
            } else {
                // A different code is simply not found.
                other_code += 1;
                assert_eq!(redeemed, Err("unknown"), "position {i}");
            }
        }
        // The loop really exercised every branch.
        assert!(
            undecodable > 0 && other_code > 0 && same_code > 0,
            "{undecodable} {other_code} {same_code}"
        );
        let bad = [
            String::new(),
            "p2pc_join_".to_string(),
            text[..text.len() - 3].to_string(),
            text.to_uppercase(),
            text.replacen("p2pc_join_", "p2pc_jion_", 1),
            format!("{text}===="),
            format!("{text}a"),
            format!("p2pc_join_{}", "a".repeat(MAX_JOIN_TOKEN_LEN)),
        ];
        for case in bad {
            assert!(JoinToken::decode(&case).is_err(), "{case:?}");
        }
    }

    /// A model of what the server (T05) must do, since the payload is not authenticated: look the token up by
    /// `code_hash()` with a constant-time comparison, then apply the expiry and single-use flag of its own row.
    struct TokenStore {
        rows: Vec<(SecretHash, OffsetDateTime, bool)>,
    }

    impl TokenStore {
        fn issue(t: &JoinToken, now: OffsetDateTime) -> Self {
            Self {
                rows: vec![(t.code_hash(), now + DEFAULT_JOIN_TOKEN_TTL, false)],
            }
        }

        fn redeem(&mut self, presented: &JoinToken, now: OffsetDateTime) -> Result<(), &'static str> {
            let hash = presented.code_hash();
            let row = self.rows.iter_mut().find(|r| r.0.ct_eq(&hash)).ok_or("unknown")?;
            if now >= row.1 {
                return Err("expired");
            }
            if row.2 {
                return Err("used");
            }
            row.2 = true;
            Ok(())
        }
    }

    #[test]
    fn a_forged_expiry_does_not_extend_a_token() {
        let issued_at = datetime!(2026-11-05 10:00:00 UTC);
        let t = token();
        // Anyone holding the token can re-encode it with a later expiry: there is no MAC.
        let forged = JoinToken {
            expires_at: datetime!(2027-11-05 10:00:00 UTC),
            ..t.clone()
        };
        let forged = JoinToken::decode(&forged.encode().unwrap()).unwrap();
        let later = issued_at + Duration::minutes(20);
        assert!(
            !forged.is_expired(later),
            "the payload alone would say it is still valid"
        );
        let mut store = TokenStore::issue(&t, issued_at);
        assert_eq!(store.redeem(&forged, later), Err("expired"));
    }

    #[test]
    fn a_token_redeems_once() {
        let issued_at = datetime!(2026-11-05 10:00:00 UTC);
        let t = token();
        let mut store = TokenStore::issue(&t, issued_at);
        assert_eq!(store.redeem(&t, issued_at + Duration::minutes(1)), Ok(()));
        assert_eq!(store.redeem(&t, issued_at + Duration::minutes(2)), Err("used"));
    }

    #[test]
    fn join_token_equality_compares_every_field() {
        let t = token();
        assert_eq!(t, t.clone());
        let mut other = t.clone();
        other.code[15] ^= 1;
        assert_ne!(t, other);
        assert_ne!(
            t,
            JoinToken {
                server: "b".repeat(64),
                ..t.clone()
            }
        );
        assert_ne!(
            t,
            JoinToken {
                relays: vec![],
                ..t.clone()
            }
        );
        assert_ne!(
            t,
            JoinToken {
                expires_at: t.expires_at + Duration::seconds(1),
                ..t.clone()
            }
        );
    }

    fn encode_payload(json: &str) -> String {
        format!("{JOIN_TOKEN_PREFIX}{}", b32_encode(json.as_bytes()))
    }

    #[test]
    fn join_token_payload_is_validated() {
        let code = b32_encode(&[1u8; 16]);
        let good =
            format!(r#"{{"v":1,"s":"{SERVER}","r":["https://relay.example.invalid/"],"c":"{code}","e":1800000000}}"#);
        assert!(JoinToken::decode(&encode_payload(&good)).is_ok());
        let cases = [
            (good.replace(r#""v":1"#, r#""v":2"#), AuthError::MalformedJoinToken),
            (
                good.replace(r#","e":1800000000"#, r#","e":1800000000,"x":1"#),
                AuthError::MalformedJoinToken,
            ),
            (
                good.replace(&code, &b32_encode(&[1u8; 15])),
                AuthError::MalformedJoinToken,
            ),
            (good.replace(&code, "not-base32!"), AuthError::MalformedJoinToken),
            (good.replace(SERVER, "short"), AuthError::InvalidServerId),
            (good.replace(SERVER, &SERVER.to_uppercase()), AuthError::InvalidServerId),
            (
                good.replace(SERVER, &format!("{SERVER}/../x")),
                AuthError::InvalidServerId,
            ),
            (good.replace(SERVER, &"a".repeat(129)), AuthError::InvalidServerId),
            (
                good.replace("https://relay.example.invalid/", "ftp://relay.example.invalid/"),
                AuthError::InvalidRelay,
            ),
            (
                good.replace(
                    "https://relay.example.invalid/",
                    "https://user:pw@relay.example.invalid/",
                ),
                AuthError::InvalidRelay,
            ),
            (
                good.replace("https://relay.example.invalid/", "not a url"),
                AuthError::InvalidRelay,
            ),
            (
                good.replace("https://relay.example.invalid/", "data:text/plain,hi"),
                AuthError::InvalidRelay,
            ),
            (
                good.replace(
                    r#"["https://relay.example.invalid/"]"#,
                    &format!("[{}]", [r#""https://r.example.invalid/""#; 9].join(",")),
                ),
                AuthError::InvalidRelay,
            ),
            (
                good.replace("1800000000", "999999999999999999"),
                AuthError::InvalidExpiry,
            ),
            ("[]".to_string(), AuthError::MalformedJoinToken),
            ("not json".to_string(), AuthError::MalformedJoinToken),
        ];
        for (json, want) in cases {
            assert_eq!(JoinToken::decode(&encode_payload(&json)), Err(want), "{json}");
        }
    }

    #[test]
    fn join_token_debug_never_shows_the_code_or_the_token() {
        let t = token();
        let text = t.encode().unwrap();
        let code_b32 = b32_encode(&t.code);
        let resp = crate::api::JoinTokenResponse {
            id: crate::ids::JoinTokenId::generate(),
            join_token: t.clone(),
            expires_at: t.expires_at,
        };
        let debug = format!("{t:?} {resp:?} {:?}", t.code_hash());
        assert!(
            !debug.contains(&text[JOIN_TOKEN_PREFIX.len()..JOIN_TOKEN_PREFIX.len() + 20]),
            "{debug}"
        );
        assert!(!debug.contains(&code_b32), "{debug}");
        assert!(!debug.contains(&format!("{:?}", t.code)), "{debug}");
        assert!(debug.contains("***"));
        // Decode errors do not echo the token either.
        let err = serde_json::from_str::<JoinToken>(&format!("\"{text}x\"")).unwrap_err();
        assert!(!err.to_string().contains(&text[JOIN_TOKEN_PREFIX.len()..]), "{err}");
    }

    #[test]
    fn new_api_key_debug_is_redacted() {
        let key = ApiKey::generate();
        let full = key.expose();
        let info = crate::api::ApiKeyInfo {
            id: key.key_id(),
            project_id: crate::ids::ProjectId::generate(),
            label: None,
            scopes: vec![crate::api::Scope::Admin],
            daily_unit_cap: None,
            allowed_images: None,
            created_at: datetime!(2026-11-05 10:00:00 UTC),
            expires_at: None,
            last_used_at: None,
            revoked_at: None,
        };
        let new = crate::api::NewApiKey { key, info };
        let debug = format!("{new:?}");
        assert!(
            !debug.contains(&full[API_KEY_PREFIX.len() + KEY_ID_LEN + 1..]),
            "{debug}"
        );
        // The JSON response carries the full key, once.
        assert!(serde_json::to_string(&new).unwrap().contains(&full));
    }

    fn address() -> ServerAddress {
        ServerAddress {
            server: SERVER.into(),
            relays: relays(),
        }
    }

    #[test]
    fn server_address_round_trip() {
        let a = address();
        let text = a.encode().unwrap();
        assert!(text.starts_with("p2pc_srv_"), "{text}");
        let body = &text[SERVER_ADDRESS_PREFIX.len()..];
        assert!(body.bytes().all(|b| BASE32_LOWER.contains(&b)), "{body}");
        assert_eq!(ServerAddress::parse(&text).unwrap(), a);
        assert_eq!(text.parse::<ServerAddress>().unwrap(), a);
        assert_eq!(a.to_string(), text);
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, format!("\"{text}\""));
        assert_eq!(serde_json::from_str::<ServerAddress>(&json).unwrap(), a);
        // No relays is fine; the address is deterministic (no randomness, it is not a secret).
        let bare = ServerAddress {
            relays: vec![],
            ..a.clone()
        };
        assert_eq!(ServerAddress::parse(&bare.encode().unwrap()).unwrap(), bare);
        assert_eq!(a.encode().unwrap(), address().encode().unwrap());
    }

    /// The address and the join token share the payload format (§10), minus the code and the expiry: the same
    /// server and relay hints decode identically from both.
    #[test]
    fn server_address_shares_the_join_token_payload_format() {
        let t = token();
        let a = ServerAddress::from_join_token(&t);
        assert_eq!(a.server, t.server);
        assert_eq!(a.relays, t.relays);
        let json = String::from_utf8(b32_decode(&a.encode().unwrap()[SERVER_ADDRESS_PREFIX.len()..]).unwrap()).unwrap();
        assert_eq!(
            json,
            format!(r#"{{"v":1,"s":"{SERVER}","r":["https://relay.example.invalid/"]}}"#)
        );
    }

    #[test]
    fn server_address_and_join_token_never_parse_as_each_other() {
        let token_text = token().encode().unwrap();
        let addr_text = address().encode().unwrap();
        assert_eq!(
            ServerAddress::parse(&token_text),
            Err(AuthError::MalformedServerAddress)
        );
        assert_eq!(JoinToken::decode(&addr_text), Err(AuthError::MalformedJoinToken));
        // Swapping the prefixes is refused too: the payloads differ (the token has `c` and `e`).
        let swapped_token = token_text.replacen(JOIN_TOKEN_PREFIX, SERVER_ADDRESS_PREFIX, 1);
        assert_eq!(
            ServerAddress::parse(&swapped_token),
            Err(AuthError::MalformedServerAddress)
        );
        let swapped_addr = addr_text.replacen(SERVER_ADDRESS_PREFIX, JOIN_TOKEN_PREFIX, 1);
        assert_eq!(JoinToken::decode(&swapped_addr), Err(AuthError::MalformedJoinToken));
    }

    #[test]
    fn server_address_payload_is_validated() {
        let enc = |json: &str| format!("{SERVER_ADDRESS_PREFIX}{}", b32_encode(json.as_bytes()));
        let good = format!(r#"{{"v":1,"s":"{SERVER}","r":["https://relay.example.invalid/"]}}"#);
        assert!(ServerAddress::parse(&enc(&good)).is_ok());
        let cases = [
            (good.replace(r#""v":1"#, r#""v":2"#), AuthError::MalformedServerAddress),
            (good.replace(r#"]}"#, r#"],"x":1}"#), AuthError::MalformedServerAddress),
            (good.replace(SERVER, "short"), AuthError::InvalidServerId),
            (
                good.replace("https://relay.example.invalid/", "ftp://relay.example.invalid/"),
                AuthError::InvalidRelay,
            ),
            ("not json".to_string(), AuthError::MalformedServerAddress),
        ];
        for (json, want) in cases {
            assert_eq!(ServerAddress::parse(&enc(&json)), Err(want), "{json}");
        }
        for bad in [
            String::new(),
            "p2pc_srv_".to_string(),
            address().encode().unwrap().to_uppercase(),
            format!("p2pc_srv_{}", "a".repeat(MAX_JOIN_TOKEN_LEN)),
        ] {
            assert!(ServerAddress::parse(&bad).is_err(), "{bad:?}");
        }
    }
}
