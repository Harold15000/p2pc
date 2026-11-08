// SPDX-License-Identifier: Apache-2.0

//! Serde helpers for timestamps: RFC 3339, always written in UTC.
//!
//! Use with `#[serde(with = "crate::timestamp")]` or `#[serde(with = "crate::timestamp::option")]`. Input with any
//! offset is accepted and converted to UTC, so values compare and print consistently.

use serde::{Deserialize, Deserializer, Serializer};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

/// Serializes as RFC 3339 in UTC.
pub(crate) fn serialize<S: Serializer>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error> {
    let text = value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&text)
}

/// Deserializes RFC 3339 and converts to UTC.
pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<OffsetDateTime, D::Error> {
    let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
    OffsetDateTime::parse(&text, &Rfc3339)
        .map(|t| t.to_offset(UtcOffset::UTC))
        .map_err(|_| serde::de::Error::custom("expected an RFC 3339 timestamp"))
}

/// The same, for `Option<OffsetDateTime>` (`null` or absent is `None`).
pub(crate) mod option {
    use super::*;

    /// Serializes `Some` as RFC 3339 in UTC and `None` as `null`.
    pub(crate) fn serialize<S: Serializer>(value: &Option<OffsetDateTime>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => super::serialize(v, serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes `null` as `None`, anything else as an RFC 3339 timestamp.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error> {
        #[derive(Deserialize)]
        struct Wrap(#[serde(with = "super")] OffsetDateTime);
        Ok(Option::<Wrap>::deserialize(deserializer)?.map(|w| w.0))
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use time::macros::datetime;

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct T {
        #[serde(with = "crate::timestamp")]
        at: OffsetDateTime,
        #[serde(default, with = "crate::timestamp::option")]
        maybe: Option<OffsetDateTime>,
    }

    #[test]
    fn writes_utc_and_reads_any_offset() {
        let t = T {
            at: datetime!(2026-11-05 12:00:00 +02:00),
            maybe: None,
        };
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, r#"{"at":"2026-11-05T10:00:00Z","maybe":null}"#);
        let back: T = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
        assert_eq!(back.at.offset(), UtcOffset::UTC);
        let absent: T = serde_json::from_str(r#"{"at":"2026-11-05T10:00:00.5+01:00"}"#).unwrap();
        assert_eq!(absent.at, datetime!(2026-11-05 09:00:00.5 UTC));
        assert_eq!(absent.maybe, None);
    }

    #[test]
    fn rejects_non_rfc3339() {
        assert!(serde_json::from_str::<T>(r#"{"at":"2026-11-05 10:00:00"}"#).is_err());
        assert!(serde_json::from_str::<T>(r#"{"at":1700000000}"#).is_err());
    }
}
