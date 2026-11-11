// SPDX-License-Identifier: Apache-2.0

//! The bundle: `templates.json` (H2 §7.6 "Bundle").
//!
//! ```json
//! {"bundle_version": 3, "min_hub_version": "0.1.0", "templates": [ { …a p2pc_proto::api::Template… } ]}
//! ```
//!
//! The bytes are canonical (compact, object keys sorted at every level, no trailing newline), so compiling the same
//! sources twice gives the same bytes and the signature covers exactly what the hub parses.

use std::path::Path;

use p2pc_proto::api::Template;
use serde::{Deserialize, Serialize};

use crate::check::{Mode, Problem, check_bundle};
use crate::source::{SourceError, load_dir};

/// Largest bundle the compiler writes and the verifier reads, in bytes. The hub reads a bundle file from disk every
/// 60 s: the bound keeps a damaged or hostile file from costing memory.
pub const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

/// The signed bundle (H2 §7.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bundle {
    /// Raised by every bundle release; the hub's anti-rollback compares it with its high-water mark.
    pub bundle_version: u64,
    /// The oldest hub that may load this bundle (semantic version).
    pub min_hub_version: String,
    /// The templates, sorted by id.
    pub templates: Vec<Template>,
}

impl Bundle {
    /// A bundle of `templates`.
    #[must_use]
    pub fn new(bundle_version: u64, min_hub_version: &str, templates: Vec<Template>) -> Self {
        Self {
            bundle_version,
            min_hub_version: min_hub_version.to_string(),
            templates,
        }
    }

    /// The canonical bytes: compact JSON with the keys of every object sorted.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        let value = serde_json::to_value(self)?;
        serde_json::to_vec(&sorted(value))
    }
}

/// The same value with every object's keys in sorted order, whatever order `serde_json` keeps them in.
fn sorted(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().map(|(k, v)| (k, sorted(v))).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// Why a directory did not compile.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    /// The sources could not be read or parsed.
    #[error("{0}")]
    Source(#[from] SourceError),
    /// A rule is broken; every problem is listed.
    #[error("the bundle breaks {} rule(s):\n{}", .0.len(), list(.0))]
    Rules(Vec<Problem>),
    /// The JSON could not be written.
    #[error("cannot write the bundle: {0}")]
    Json(#[from] serde_json::Error),
    /// The bundle is over [`MAX_BUNDLE_BYTES`].
    #[error("the bundle is {0} bytes, over the {MAX_BUNDLE_BYTES} byte limit")]
    TooLarge(usize),
}

fn list(problems: &[Problem]) -> String {
    problems
        .iter()
        .map(|p| format!("  - {p}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Reads `dir`, checks every rule in `mode` and returns the bundle with its canonical bytes. Nothing is returned
/// for a bundle that breaks a rule: a release never carries a template that fails the checks.
pub fn compile_dir(dir: &Path, mode: Mode) -> Result<(Bundle, Vec<u8>), CompileError> {
    let bundle = load_dir(dir)?;
    let problems = check_bundle(&bundle, mode);
    if !problems.is_empty() {
        return Err(CompileError::Rules(problems));
    }
    let bytes = bundle.to_canonical_json()?;
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(CompileError::TooLarge(bytes.len()));
    }
    Ok((bundle, bytes))
}
