// SPDX-License-Identifier: Apache-2.0

//! Typed identifiers (spec §5, §7).
//!
//! Object IDs are a short lowercase prefix plus a ULID in its canonical form (26 characters of uppercase Crockford
//! base32), for example `job_01ARZ3NDEKTSV4RRFFQ69G5FAV`. Parsing is strict: the prefix must match the type, and the
//! ULID must be canonical (no lowercase aliases, no overflow), so that every ID has exactly one spelling.
//!
//! [`KeyId`] is different: it is the 12-character lowercase base32 ID that is embedded in an API key.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ulid::Ulid;

/// Length of a canonical ULID string.
const ULID_LEN: usize = 26;

/// Why a string is not a valid ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// The ID does not start with the prefix of its type.
    #[error("the ID must start with `{expected}`")]
    WrongPrefix {
        /// The prefix the type expects, for example `job_`.
        expected: &'static str,
    },
    /// The part after the prefix is not a canonical ULID.
    #[error("the ID does not contain a valid ULID")]
    InvalidUlid,
    /// The key ID is not 12 characters of lowercase base32.
    #[error("the key ID must be 12 characters of lowercase base32")]
    InvalidKeyId,
}

macro_rules! prefixed_ulid {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema), schema(value_type = String))]
        pub struct $name(Ulid);

        impl $name {
            /// The string prefix of this ID type.
            pub const PREFIX: &'static str = $prefix;

            /// Generates a new random ID stamped with the current time.
            #[must_use]
            pub fn generate() -> Self {
                Self(Ulid::generate())
            }

            /// Wraps an existing ULID.
            #[must_use]
            pub const fn from_ulid(ulid: Ulid) -> Self {
                Self(ulid)
            }

            /// The ULID inside this ID.
            #[must_use]
            pub const fn ulid(&self) -> Ulid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", Self::PREFIX, self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(\"{}\")", stringify!($name), self)
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let rest = s.strip_prefix(Self::PREFIX).ok_or(IdError::WrongPrefix { expected: Self::PREFIX })?;
                parse_canonical_ulid(rest).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserialize_from_str(deserializer)
            }
        }
    };
}

prefixed_ulid!(
    /// Identifies a job (`job_…`).
    JobId,
    "job_"
);
prefixed_ulid!(
    /// Identifies an enrolled node (`node_…`).
    NodeId,
    "node_"
);
prefixed_ulid!(
    /// Identifies one lease, that is, one attempt of a job on a node (`lse_…`).
    LeaseId,
    "lse_"
);
prefixed_ulid!(
    /// Identifies a project (`prj_…`).
    ProjectId,
    "prj_"
);
prefixed_ulid!(
    /// Identifies an account (`acc_…`).
    AccountId,
    "acc_"
);
prefixed_ulid!(
    /// Identifies a join token row (`jtk_…`), as listed and revoked by the admin API (§5). Never the token itself.
    JoinTokenId,
    "jtk_"
);
prefixed_ulid!(
    /// Identifies an audit event (`aud_…`, §5 "Audit").
    AuditEventId,
    "aud_"
);

/// Parses a ULID and accepts it only in its canonical spelling.
fn parse_canonical_ulid(s: &str) -> Result<Ulid, IdError> {
    if s.len() != ULID_LEN {
        return Err(IdError::InvalidUlid);
    }
    let ulid = Ulid::from_string(s).map_err(|_| IdError::InvalidUlid)?;
    // Rejects lowercase aliases and values that overflow 128 bits (the decoder wraps silently).
    if ulid.to_string() != s {
        return Err(IdError::InvalidUlid);
    }
    Ok(ulid)
}

/// Deserializes any `FromStr` type from a JSON string, keeping the parse error message.
pub(crate) fn deserialize_from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
}

/// The lowercase RFC 4648 base32 alphabet used by key IDs and API key secrets.
pub(crate) const BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Number of characters in a [`KeyId`].
pub const KEY_ID_LEN: usize = 12;

/// The public ID of an API key: 12 characters of lowercase base32 (spec §5).
///
/// It is not secret. It appears in the key itself (`p2pc_sk_<key_id>_<secret>`) and in `GET /v1/keys`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema), schema(value_type = String))]
pub struct KeyId([u8; KEY_ID_LEN]);

impl KeyId {
    /// Generates a random key ID (60 bits of entropy).
    #[must_use]
    pub fn generate() -> Self {
        let bits: u64 = rand::random();
        let mut out = [0u8; KEY_ID_LEN];
        for (i, c) in out.iter_mut().enumerate() {
            // 12 groups of 5 bits; the index is always < 32.
            let idx = ((bits >> (5 * i)) & 0x1f) as usize;
            *c = BASE32_LOWER[idx];
        }
        Self(out)
    }

    /// The key ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Construction guarantees ASCII; the fallback is unreachable.
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId(\"{}\")", self.as_str())
    }
}

impl FromStr for KeyId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; KEY_ID_LEN] = s.as_bytes().try_into().map_err(|_| IdError::InvalidKeyId)?;
        if !bytes.iter().all(|b| BASE32_LOWER.contains(b)) {
            return Err(IdError::InvalidKeyId);
        }
        Ok(Self(bytes))
    }
}

impl Serialize for KeyId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_from_str(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    #[test]
    fn every_id_type_round_trips_through_display_and_from_str() {
        let job: JobId = format!("job_{ULID}").parse().unwrap();
        assert_eq!(job.to_string(), format!("job_{ULID}"));
        let node: NodeId = format!("node_{ULID}").parse().unwrap();
        assert_eq!(node.to_string(), format!("node_{ULID}"));
        let lease: LeaseId = format!("lse_{ULID}").parse().unwrap();
        assert_eq!(lease.to_string(), format!("lse_{ULID}"));
        let project: ProjectId = format!("prj_{ULID}").parse().unwrap();
        assert_eq!(project.to_string(), format!("prj_{ULID}"));
        let account: AccountId = format!("acc_{ULID}").parse().unwrap();
        assert_eq!(account.to_string(), format!("acc_{ULID}"));
        let token: JoinTokenId = format!("jtk_{ULID}").parse().unwrap();
        assert_eq!(token.to_string(), format!("jtk_{ULID}"));
        let audit: AuditEventId = format!("aud_{ULID}").parse().unwrap();
        assert_eq!(audit.to_string(), format!("aud_{ULID}"));
        assert!(format!("aud_{ULID}").parse::<JoinTokenId>().is_err());
    }

    #[test]
    fn generated_ids_parse_back() {
        let id = JobId::generate();
        assert_eq!(id.to_string().parse::<JobId>().unwrap(), id);
        assert!(id.to_string().starts_with("job_"));
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        assert_eq!(
            format!("node_{ULID}").parse::<JobId>(),
            Err(IdError::WrongPrefix { expected: "job_" })
        );
        assert_eq!(ULID.parse::<JobId>(), Err(IdError::WrongPrefix { expected: "job_" }));
        assert_eq!(
            format!("JOB_{ULID}").parse::<JobId>(),
            Err(IdError::WrongPrefix { expected: "job_" })
        );
        assert_eq!(
            format!(" job_{ULID}").parse::<JobId>(),
            Err(IdError::WrongPrefix { expected: "job_" })
        );
    }

    #[test]
    fn invalid_ulids_are_rejected() {
        let cases = [
            "job_".to_string(),
            format!("job_{}", &ULID[..25]),
            format!("job_{ULID}0"),
            format!("job_{}", ULID.to_lowercase()),       // non-canonical alias
            "job_81ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), // overflows 128 bits
            "job_01ARZ3NDEKTSV4RRFFQ69G5FAU".to_string(), // U is not Crockford base32
            "job_01ARZ3NDEKTSV4RRFFQ69G5FA!".to_string(),
            format!("job_{ULID} "),
            format!("job_{}é", &ULID[..24]),
        ];
        for case in cases {
            assert_eq!(case.parse::<JobId>(), Err(IdError::InvalidUlid), "{case:?}");
        }
    }

    #[test]
    fn ids_serialize_as_json_strings() {
        let id: LeaseId = format!("lse_{ULID}").parse().unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"lse_{ULID}\""));
        assert_eq!(serde_json::from_str::<LeaseId>(&json).unwrap(), id);
        assert!(serde_json::from_str::<LeaseId>(&format!("\"job_{ULID}\"")).is_err());
        assert!(serde_json::from_str::<LeaseId>("42").is_err());
    }

    #[test]
    fn ids_order_by_time_and_hash_by_value() {
        let a = JobId::from_ulid(Ulid::from_parts(1, 0));
        let b = JobId::from_ulid(Ulid::from_parts(2, 0));
        assert!(a < b);
        let set: HashSet<_> = [a, b, a].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn key_id_accepts_only_twelve_lowercase_base32_chars() {
        let id: KeyId = "abcdefgh2345".parse().unwrap();
        assert_eq!(id.to_string(), "abcdefgh2345");
        for bad in [
            "",
            "abcdefgh234",
            "abcdefgh23456",
            "ABCDEFGH2345",
            "abcdefgh2341",
            "abcdefgh234_",
            "abcdefgh234é",
        ] {
            assert_eq!(bad.parse::<KeyId>(), Err(IdError::InvalidKeyId), "{bad:?}");
        }
    }

    #[test]
    fn generated_key_ids_are_valid_and_differ() {
        let a = KeyId::generate();
        let b = KeyId::generate();
        assert_eq!(a.to_string().parse::<KeyId>().unwrap(), a);
        assert_ne!(a, b);
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<KeyId>(&json).unwrap(), a);
    }
}
