// SPDX-License-Identifier: AGPL-3.0-only

//! The hash that tells an idempotent replay from a different request (spec §7 `idempotency_key`).
//!
//! `spec_hash` is `sha256:` and the SHA-256 of the **canonical JSON** of the normalized spec: object keys sorted at
//! every level, no whitespace, numbers and strings as `serde_json` writes them. Two bodies that differ only in key
//! order, whitespace, or how an equal number is written (`1` and `1.0` CPUs) hash the same. The idempotency key is
//! part of the spec, so a key sent in the header and one sent in the body give the same hash.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The canonical JSON text of `value`.
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (i, (key, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // A string always serializes.
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                write_canonical(v, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&serde_json::to_string(scalar).unwrap_or_default()),
    }
}

/// `sha256:<64 lowercase hex>` of the canonical JSON of `value`.
#[must_use]
pub fn spec_hash(value: &Value) -> String {
    let digest = Sha256::digest(canonical_json(value).as_bytes());
    format!("sha256:{}", data_encoding::HEXLOWER.encode(&digest))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn keys_are_sorted_at_every_level() {
        let v = json!({"b": 1, "a": {"d": [3, {"z": 1, "y": 2}], "c": null}});
        assert_eq!(canonical_json(&v), r#"{"a":{"c":null,"d":[3,{"y":2,"z":1}]},"b":1}"#);
    }

    #[test]
    fn the_hash_ignores_order_and_whitespace_but_not_content() {
        let a: Value = serde_json::from_str(r#"{ "x": 1, "y": [1, 2], "z": {"p": "q"} }"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"z":{"p":"q"},"y":[1,2],"x":1}"#).unwrap();
        assert_eq!(spec_hash(&a), spec_hash(&b));
        // Array order matters (argv order is meaning), and so does every value.
        for other in [
            json!({"x": 1, "y": [2, 1], "z": {"p": "q"}}),
            json!({"x": 2, "y": [1, 2], "z": {"p": "q"}}),
            json!({"x": 1, "y": [1, 2], "z": {"p": "r"}}),
            json!({"x": 1, "y": [1, 2]}),
        ] {
            assert_ne!(spec_hash(&a), spec_hash(&other), "{other}");
        }
    }

    #[test]
    fn the_hash_has_the_stored_format() {
        let h = spec_hash(&json!({}));
        assert_eq!(h.len(), 71);
        assert!(h.starts_with("sha256:"));
        assert!(h[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        // The SHA-256 of `{}`: a fixed vector, so the canonical form cannot drift unnoticed.
        assert_eq!(
            h,
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn strings_are_escaped_like_json() {
        assert_eq!(canonical_json(&json!({"k\"": "a\nb"})), r#"{"k\"":"a\nb"}"#);
    }
}
