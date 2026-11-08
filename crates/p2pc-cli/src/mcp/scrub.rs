// SPDX-License-Identifier: Apache-2.0

//! SI-6 on the way out: the API key never reaches an MCP answer.
//!
//! The client already keeps the key out of its own errors. This is the second line of defence, for text that comes
//! from elsewhere: a server error that echoes the `Authorization` header, a job that prints a key. Everything that is
//! sent to the agent passes through [`Scrubber::scrub_value`].

use p2pc_proto::auth::ApiKey;
use serde_json::Value;

/// What replaces the session's own key.
const REDACTED_KEY: &str = "[redacted-key]";
/// What replaces any other string that looks like a P2PC key.
const REDACTED_OTHER: &str = "p2pc_sk_[redacted]";
const KEY_PREFIX: &str = "p2pc_sk_";

/// Removes the session's key, and anything shaped like a P2PC key, from text.
#[derive(Clone)]
pub struct Scrubber {
    needles: Vec<String>,
}

impl std::fmt::Debug for Scrubber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scrubber").finish_non_exhaustive()
    }
}

impl Scrubber {
    /// A scrubber for `key`: its full text, and its secret part on its own.
    #[must_use]
    pub fn new(key: &ApiKey) -> Self {
        let full = key.expose();
        let mut needles = vec![full.clone()];
        if let Some(secret) = full.rsplit('_').next()
            && secret.len() >= 16
        {
            needles.push(secret.to_string());
        }
        Self { needles }
    }

    /// The text with every occurrence removed.
    #[must_use]
    pub fn scrub(&self, text: &str) -> String {
        let mut out = text.to_string();
        for needle in &self.needles {
            if out.contains(needle.as_str()) {
                out = out.replace(needle.as_str(), REDACTED_KEY);
            }
        }
        redact_key_shapes(&out)
    }

    /// Scrubs every string of a JSON value, keys included.
    pub fn scrub_value(&self, value: &mut Value) {
        match value {
            Value::String(s) => *s = self.scrub(s),
            Value::Array(items) => items.iter_mut().for_each(|v| self.scrub_value(v)),
            Value::Object(map) => {
                let old = std::mem::take(map);
                for (k, mut v) in old {
                    self.scrub_value(&mut v);
                    map.insert(self.scrub(&k), v);
                }
            }
            _ => {}
        }
    }
}

/// Replaces `p2pc_sk_` and the key characters after it (`[a-z0-9_]`).
fn redact_key_shapes(text: &str) -> String {
    if !text.contains(KEY_PREFIX) {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(KEY_PREFIX) {
        out.push_str(&rest[..at]);
        let after = &rest[at + KEY_PREFIX.len()..];
        let len = after
            .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(after.len());
        out.push_str(REDACTED_OTHER);
        rest = &after[len..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_key_and_its_secret_are_removed_wherever_they_are() {
        let key = ApiKey::generate();
        let full = key.expose();
        let secret = full.rsplit('_').next().unwrap().to_string();
        let scrubber = Scrubber::new(&key);
        let mut v = json!({
            "a": format!("Bearer {full}"),
            "b": [format!("secret={secret}")],
            full.clone(): "as a key",
            "n": 5,
        });
        scrubber.scrub_value(&mut v);
        let text = v.to_string();
        assert!(!text.contains(&full) && !text.contains(&secret), "{text}");
        assert!(text.contains("Bearer [redacted-key]"), "{text}");
        assert_eq!(v["n"], 5);
    }

    #[test]
    fn another_key_shaped_string_is_redacted_but_other_text_is_left_alone() {
        let scrubber = Scrubber::new(&ApiKey::generate());
        let other = ApiKey::generate().expose();
        let s = scrubber.scrub(&format!("x {other}, and p2pc_sk_ alone, but p2pc is fine"));
        assert!(!s.contains(&other), "{s}");
        assert!(s.contains("but p2pc is fine"), "{s}");
        assert_eq!(scrubber.scrub("nothing here"), "nothing here");
    }

    #[test]
    fn debug_does_not_print_the_needles() {
        let key = ApiKey::generate();
        let text = format!("{:?}", Scrubber::new(&key));
        assert!(!text.contains(&key.expose()));
    }
}
