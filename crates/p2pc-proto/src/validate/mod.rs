// SPDX-License-Identifier: Apache-2.0

//! `JobSpec` validation rules: image, command, env, files, resources and egress (spec §7).
//!
//! [`JobSpec::validate`] implements the §7 validation table. It collects every problem instead of stopping at the
//! first, and each [`FieldError`] has a field path (`resources.cpu`, `env.NAME`, `files[2].path`), a stable
//! [`ErrorCode`] and a message. Messages never contain environment values or file contents.
//!
//! The building blocks are public because other components reuse them:
//! - [`ImageRef`]: OCI reference parsing and normalization;
//! - [`image_allowed`]: a key's `allowed_images` globs;
//! - [`domain_allowed`] and [`validate_egress_domain`]: the egress allowlist (the T09 proxy uses them);
//! - [`validate_input_path`] and [`validate_output_path`]: path traversal checks (SI-9);
//! - [`base64_decoded_len`] and [`decode_base64_bounded`]: size-bounded base64.

pub mod domain;
pub mod glob;
pub mod image;
pub mod keys;

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

pub use domain::{DomainError, domain_allowed, validate_egress_domain};
pub use glob::{glob_match, image_allowed, validate_pattern};
pub use image::{ImageRef, ImageRefError};
pub use keys::{EscalationDenied, check_no_escalation};

use crate::api::{JobSpec, POOL_MINE};

/// A stable, machine-readable validation error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// A number or a count is outside its allowed range.
    OutOfRange,
    /// The value does not have the required syntax.
    InvalidFormat,
    /// A size limit is exceeded.
    TooLarge,
    /// Too many items.
    TooMany,
    /// The name is reserved (for example the `P2PC_` env prefix).
    Reserved,
    /// The placement pool is not supported (only `mine` in v0.1).
    UnsupportedPool,
    /// The value is valid but not allowed by policy (for example a registry outside the allowed list).
    NotAllowed,
    /// The same item appears twice.
    Duplicate,
    /// One input file path is a directory of another (`/inputs/a` and `/inputs/a/b`).
    PathConflict,
}

impl ErrorCode {
    /// The snake_case name used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::OutOfRange => "out_of_range",
            ErrorCode::InvalidFormat => "invalid_format",
            ErrorCode::TooLarge => "too_large",
            ErrorCode::TooMany => "too_many",
            ErrorCode::Reserved => "reserved",
            ErrorCode::UnsupportedPool => "unsupported_pool",
            ErrorCode::NotAllowed => "not_allowed",
            ErrorCode::Duplicate => "duplicate",
            ErrorCode::PathConflict => "path_conflict",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One validation problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FieldError {
    /// Path of the offending field, for example `resources.cpu` or `files[0].path`.
    pub field: String,
    /// Stable code.
    pub code: ErrorCode,
    /// Human explanation. Never contains env values or file contents.
    pub message: String,
}

/// The non-empty list of problems found by [`JobSpec::validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrors(Vec<FieldError>);

impl ValidationErrors {
    /// A single error.
    pub(crate) fn single(field: &str, code: ErrorCode, message: &str) -> Self {
        Self(vec![FieldError {
            field: field.to_string(),
            code,
            message: message.to_string(),
        }])
    }

    /// Iterates over the errors, in the order of the §7 table.
    pub fn iter(&self) -> std::slice::Iter<'_, FieldError> {
        self.0.iter()
    }

    /// Number of errors (at least 1).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false`: a `ValidationErrors` holds at least one error.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The errors as a vector.
    #[must_use]
    pub fn into_vec(self) -> Vec<FieldError> {
        self.0
    }

    /// Whether some error is about `field` with `code`.
    #[must_use]
    pub fn contains(&self, field: &str, code: ErrorCode) -> bool {
        self.0.iter().any(|e| e.field == field && e.code == code)
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, e) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{}: {} ({})", e.field, e.message, e.code)?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}

impl<'a> IntoIterator for &'a ValidationErrors {
    type Item = &'a FieldError;
    type IntoIter = std::slice::Iter<'a, FieldError>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// The configurable parts of validation: allowed registries and size limits.
///
/// - [`Limits::default`] gives the §7 values. The **server** validates `POST /v1/jobs` with it, or with its own
///   configured registries.
/// - [`Limits::agent`] is for the **agent** re-checking a lease ([`crate::protocol::LeaseJob::parse_strict`]). It
///   keeps every structural and safety check (image syntax, command, env names and values, paths, sizes, counts,
///   ranges) and skips only server policy, the allowed registries, which the server already enforced when the job
///   was created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Registries an image may come from, compared with the normalized registry (`host[:port]`, lowercase).
    ///
    /// `None` skips this server-policy check. Only [`Limits::agent`] uses `None`: on the server it would allow every
    /// registry.
    pub allowed_registries: Option<Vec<String>>,
    /// Most arguments in `command` (256).
    pub max_command_args: usize,
    /// Most bytes in `command`, summed over all arguments (64 KiB).
    pub max_command_bytes: usize,
    /// Most environment variables (64).
    pub max_env_vars: usize,
    /// Most bytes in `env`, names plus values (32 KiB).
    pub max_env_bytes: usize,
    /// Most input files (256).
    pub max_files: usize,
    /// Most bytes in all input files together, **decoded** (512 KiB, §7). The whole job must also fit in its `Lease`
    /// frame; [`JobSpec::validate`] checks that separately.
    pub max_files_bytes: usize,
    /// Most `egress.allow` entries (32).
    pub max_egress_domains: usize,
    /// Largest `resources.disk_mb` (1 048 576, that is 1 TiB).
    pub max_disk_mb: u64,
    /// Largest `outputs.max_mb` (10 240, the default disk size).
    pub max_outputs_mb: u64,
}

/// The default allowed registries (§7).
pub const DEFAULT_ALLOWED_REGISTRIES: [&str; 5] = ["docker.io", "ghcr.io", "quay.io", "nvcr.io", "registry.gitlab.com"];

impl Default for Limits {
    fn default() -> Self {
        Self {
            allowed_registries: Some(DEFAULT_ALLOWED_REGISTRIES.iter().map(|s| (*s).to_string()).collect()),
            max_command_args: 256,
            max_command_bytes: 64 * 1024,
            max_env_vars: 64,
            max_env_bytes: 32 * 1024,
            max_files: 256,
            max_files_bytes: 512 * 1024,
            max_egress_domains: 32,
            max_disk_mb: 1_048_576,
            max_outputs_mb: 10_240,
        }
    }
}

impl Limits {
    /// The agent's limits (ruling for T05b and T07): [`Limits::default`] without the server-policy registry check.
    #[must_use]
    pub fn agent() -> Self {
        Self {
            allowed_registries: None,
            ..Self::default()
        }
    }
}

/// How far (in milli-vCPU) `resources.cpu × 1000` may be from an integer and still count as a 0.001 step: float
/// noise is about 1e-10 at 256, while real sub-milli values are at least 1e-4 away (one more decimal digit).
const CPU_STEP_TOLERANCE: f64 = 1e-6;

/// Smallest `resources.cpu`.
pub const MIN_CPU: f64 = 0.25;
/// Largest `resources.cpu`.
pub const MAX_CPU: f64 = 256.0;
/// Smallest `resources.memory_mb`.
pub const MIN_MEMORY_MB: u64 = 128;
/// Largest `resources.memory_mb`.
pub const MAX_MEMORY_MB: u64 = 1_048_576;
/// Largest `resources.gpu` in v0.1 (one whole GPU).
pub const MAX_GPU: u32 = 1;
/// Largest `timeout_s` (24 h).
pub const MAX_TIMEOUT_S: u32 = 86_400;
/// Largest `retry.max_attempts`.
pub const MAX_ATTEMPTS: u32 = 5;
/// Longest `name`, in bytes.
pub const MAX_NAME_LEN: usize = 256;
/// Longest `idempotency_key`, in bytes.
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 255;
/// Most `placement.labels`.
pub const MAX_LABELS: usize = 32;
/// Longest label value, in bytes.
pub const MAX_LABEL_VALUE_LEN: usize = 255;
/// Reserved environment prefix.
pub const RESERVED_ENV_PREFIX: &str = "P2PC_";
/// Directory that input files go under.
pub const INPUTS_DIR: &str = "/inputs";
/// Longest input or output path, in bytes.
pub const MAX_PATH_LEN: usize = 4096;
/// Longest path segment, in bytes.
pub const MAX_SEGMENT_LEN: usize = 255;

struct Collector(Vec<FieldError>);

impl Collector {
    fn push(&mut self, field: impl Into<String>, code: ErrorCode, message: impl Into<String>) {
        self.0.push(FieldError {
            field: field.into(),
            code,
            message: message.into(),
        });
    }

    fn finish(self) -> Result<(), ValidationErrors> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(self.0))
        }
    }
}

impl JobSpec {
    /// Validates the spec against the §7 table, collecting every problem.
    pub fn validate(&self, limits: &Limits) -> Result<(), ValidationErrors> {
        let mut c = Collector(Vec::new());
        self.check_name(&mut c);
        self.check_image(limits, &mut c);
        self.check_command(limits, &mut c);
        self.check_env(limits, &mut c);
        self.check_files(limits, &mut c);
        self.check_resources(limits, &mut c);
        if !(1..=MAX_TIMEOUT_S).contains(&self.timeout_s) {
            c.push(
                "timeout_s",
                ErrorCode::OutOfRange,
                format!("must be 1-{MAX_TIMEOUT_S} seconds"),
            );
        }
        self.check_egress(limits, &mut c);
        if !(1..=limits.max_outputs_mb).contains(&self.outputs.max_mb) {
            c.push(
                "outputs.max_mb",
                ErrorCode::OutOfRange,
                format!("must be 1-{} MiB", limits.max_outputs_mb),
            );
        }
        self.check_placement(&mut c);
        if !(1..=MAX_ATTEMPTS).contains(&self.retry.max_attempts) {
            c.push(
                "retry.max_attempts",
                ErrorCode::OutOfRange,
                format!("must be 1-{MAX_ATTEMPTS}"),
            );
        }
        self.check_idempotency_key(&mut c);
        // Spec §7 `files` (908b42c): the job as delivered must fit in one `Lease` frame. Measured only once every
        // other rule holds, so every field is already bounded and the measurement is cheap (about 1.3 MiB at most).
        if c.0.is_empty() {
            let size = crate::protocol::lease_frame_len(self);
            let max = crate::protocol::MAX_FRAME_LEN as usize;
            if size > max {
                c.push(
                    "job",
                    ErrorCode::TooLarge,
                    format!("the job as delivered in a Lease would be {size} bytes; the frame limit is {max}"),
                );
            }
        }
        if c.0.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(c.0))
        }
    }

    /// The image reference, parsed and normalized.
    pub fn normalized_image(&self) -> Result<ImageRef, ImageRefError> {
        ImageRef::parse(&self.image)
    }

    fn check_name(&self, c: &mut Collector) {
        if let Some(name) = &self.name {
            if name.len() > MAX_NAME_LEN {
                c.push(
                    "name",
                    ErrorCode::TooLarge,
                    format!("must be at most {MAX_NAME_LEN} bytes"),
                );
            } else if name.chars().any(char::is_control) {
                c.push("name", ErrorCode::InvalidFormat, "must not contain control characters");
            }
        }
    }

    fn check_image(&self, limits: &Limits, c: &mut Collector) {
        match ImageRef::parse(&self.image) {
            Err(e) => c.push("image", ErrorCode::InvalidFormat, e.to_string()),
            Ok(r) => {
                // `None` (the agent's limits) skips this server-policy check; the syntax was checked above.
                let refused = limits
                    .allowed_registries
                    .as_ref()
                    .is_some_and(|allowed| !allowed.iter().any(|a| a.eq_ignore_ascii_case(r.registry())));
                if refused {
                    c.push(
                        "image",
                        ErrorCode::NotAllowed,
                        format!("registry `{}` is not allowed", r.registry()),
                    );
                }
            }
        }
    }

    fn check_command(&self, limits: &Limits, c: &mut Collector) {
        let n = self.command.len();
        if n == 0 || n > limits.max_command_args {
            c.push(
                "command",
                ErrorCode::OutOfRange,
                format!("must have 1-{} arguments", limits.max_command_args),
            );
        }
        let total: usize = self.command.iter().map(String::len).sum();
        if total > limits.max_command_bytes {
            c.push(
                "command",
                ErrorCode::TooLarge,
                format!("must be at most {} bytes in total", limits.max_command_bytes),
            );
        }
        if self.command.first().is_some_and(String::is_empty) {
            c.push("command[0]", ErrorCode::InvalidFormat, "the program must not be empty");
        }
        for (i, arg) in self.command.iter().enumerate() {
            if arg.contains('\0') {
                c.push(
                    format!("command[{i}]"),
                    ErrorCode::InvalidFormat,
                    "arguments must not contain NUL",
                );
            }
        }
    }

    fn check_env(&self, limits: &Limits, c: &mut Collector) {
        if self.env.len() > limits.max_env_vars {
            c.push(
                "env",
                ErrorCode::TooMany,
                format!("at most {} variables", limits.max_env_vars),
            );
        }
        let total: usize = self.env.iter().map(|(k, v)| k.len() + v.len()).sum();
        if total > limits.max_env_bytes {
            c.push(
                "env",
                ErrorCode::TooLarge,
                format!("must be at most {} bytes in total", limits.max_env_bytes),
            );
        }
        for (name, value) in &self.env {
            if !is_env_name(name) {
                // The name is not echoed: it may be arbitrary bytes.
                c.push(
                    "env",
                    ErrorCode::InvalidFormat,
                    "variable names must match [A-Z_][A-Z0-9_]*",
                );
                continue;
            }
            if name.starts_with(RESERVED_ENV_PREFIX) {
                c.push(
                    format!("env.{name}"),
                    ErrorCode::Reserved,
                    "names starting with P2PC_ are reserved",
                );
            }
            // §7 `env` row: the agent passes env to Podman through `--env-file`, which is line-based, so a `\n` or `\r`
            // in a value would inject another variable (even a reserved `P2PC_` one), and NUL cannot be passed at
            // all. Values are never echoed (§7).
            if value.contains(['\0', '\n', '\r']) {
                c.push(
                    format!("env.{name}"),
                    ErrorCode::InvalidFormat,
                    "values must not contain NUL, \\n or \\r (they go into Podman's line-based --env-file); \
                     encode multi-line values as base64, or pass them as files",
                );
            }
        }
    }

    fn check_files(&self, limits: &Limits, c: &mut Collector) {
        if self.files.len() > limits.max_files {
            // Over the cap, nothing is checked per entry: the work stays bounded whatever the request holds.
            c.push(
                "files",
                ErrorCode::TooMany,
                format!("at most {} files", limits.max_files),
            );
            return;
        }
        // Individually valid paths, with their indices, for the duplicate and directory-conflict check below.
        let mut valid: Vec<(usize, &str)> = Vec::new();
        let mut total: usize = 0;
        let mut over = false;
        for (i, file) in self.files.iter().enumerate() {
            match validate_input_path(&file.path) {
                Err(e) => c.push(format!("files[{i}].path"), ErrorCode::InvalidFormat, e.to_string()),
                Ok(()) => valid.push((i, file.path.as_str())),
            }
            if over {
                continue;
            }
            // The decoded size comes from the encoded length: nothing is decoded past the limit.
            match base64_decoded_len(&file.content_b64) {
                None => c.push(
                    format!("files[{i}].content_b64"),
                    ErrorCode::InvalidFormat,
                    "must be padded base64",
                ),
                Some(len) => {
                    total = total.saturating_add(len);
                    if total > limits.max_files_bytes {
                        over = true;
                        c.push(
                            "files",
                            ErrorCode::TooLarge,
                            format!("must be at most {} bytes in total, decoded", limits.max_files_bytes),
                        );
                    } else if decode_base64_bounded(&file.content_b64, limits.max_files_bytes).is_err() {
                        c.push(
                            format!("files[{i}].content_b64"),
                            ErrorCode::InvalidFormat,
                            "must be padded base64",
                        );
                    }
                }
            }
        }
        // Duplicates, and a path that is a directory of another (`/inputs/a` with `/inputs/a/b`).
        for issue in path_set_issues(valid.iter().map(|(_, p)| *p)) {
            match issue {
                PathSetIssue::Duplicate { index, .. } => c.push(
                    format!("files[{}].path", valid[index].0),
                    ErrorCode::Duplicate,
                    "the same path appears twice",
                ),
                PathSetIssue::Conflict { index, other } => c.push(
                    format!("files[{}].path", valid[index].0),
                    ErrorCode::PathConflict,
                    format!(
                        "conflicts with files[{}].path: one path is a directory of the other",
                        valid[other].0
                    ),
                ),
            }
        }
    }

    fn check_resources(&self, limits: &Limits, c: &mut Collector) {
        let r = &self.resources;
        if !(r.cpu.is_finite() && (MIN_CPU..=MAX_CPU).contains(&r.cpu)) {
            c.push(
                "resources.cpu",
                ErrorCode::OutOfRange,
                format!("must be {MIN_CPU}-{MAX_CPU}"),
            );
        } else {
            // §7: a multiple of 0.001 (milli-vCPU steps). The tolerance only absorbs float noise such as
            // `0.1 + 0.2 + 0.7`; `0.2505` is half a milli-vCPU away and is refused.
            let milli = r.cpu * 1000.0;
            if (milli - milli.round()).abs() > CPU_STEP_TOLERANCE {
                c.push("resources.cpu", ErrorCode::InvalidFormat, "must be a multiple of 0.001");
            }
        }
        if !(MIN_MEMORY_MB..=MAX_MEMORY_MB).contains(&r.memory_mb) {
            c.push(
                "resources.memory_mb",
                ErrorCode::OutOfRange,
                format!("must be {MIN_MEMORY_MB}-{MAX_MEMORY_MB}"),
            );
        }
        if r.gpu > MAX_GPU {
            c.push("resources.gpu", ErrorCode::OutOfRange, "must be 0 or 1 (a whole GPU)");
        }
        if !(1..=limits.max_disk_mb).contains(&r.disk_mb) {
            c.push(
                "resources.disk_mb",
                ErrorCode::OutOfRange,
                format!("must be 1-{}", limits.max_disk_mb),
            );
        }
    }

    fn check_egress(&self, limits: &Limits, c: &mut Collector) {
        let allow = &self.egress.allow;
        if allow.len() > limits.max_egress_domains {
            c.push(
                "egress.allow",
                ErrorCode::TooMany,
                format!("at most {} domains", limits.max_egress_domains),
            );
        }
        let mut seen = BTreeSet::new();
        for (i, d) in allow.iter().enumerate() {
            if let Err(e) = validate_egress_domain(d) {
                c.push(format!("egress.allow[{i}]"), ErrorCode::InvalidFormat, e.to_string());
            } else if !seen.insert(d.as_str()) {
                c.push(
                    format!("egress.allow[{i}]"),
                    ErrorCode::Duplicate,
                    "the same domain appears twice",
                );
            }
        }
    }

    fn check_placement(&self, c: &mut Collector) {
        let p = &self.placement;
        if p.pools.len() != 1 || p.pools[0] != POOL_MINE {
            c.push(
                "placement.pools",
                ErrorCode::UnsupportedPool,
                "only [\"mine\"] is supported in v0.1",
            );
        }
        if p.labels.len() > MAX_LABELS {
            c.push(
                "placement.labels",
                ErrorCode::TooMany,
                format!("at most {MAX_LABELS} labels"),
            );
        }
        for (k, v) in &p.labels {
            if !is_label_key(k) {
                c.push(
                    "placement.labels",
                    ErrorCode::InvalidFormat,
                    "label keys must match [a-z0-9]([a-z0-9._/-]{0,61}[a-z0-9])?",
                );
            } else if v.len() > MAX_LABEL_VALUE_LEN {
                c.push(
                    format!("placement.labels.{k}"),
                    ErrorCode::TooLarge,
                    format!("at most {MAX_LABEL_VALUE_LEN} bytes"),
                );
            } else if v.chars().any(char::is_control) {
                c.push(
                    format!("placement.labels.{k}"),
                    ErrorCode::InvalidFormat,
                    "must not contain control characters",
                );
            }
        }
    }

    fn check_idempotency_key(&self, c: &mut Collector) {
        if let Some(key) = &self.idempotency_key {
            let printable = key.bytes().all(|b| b.is_ascii_graphic());
            if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_LEN || !printable {
                c.push(
                    "idempotency_key",
                    ErrorCode::InvalidFormat,
                    format!("must be 1-{MAX_IDEMPOTENCY_KEY_LEN} printable ASCII characters without spaces"),
                );
            }
        }
    }
}

/// Whether `dir` is a strict path-prefix of `path` on whole segments (`/inputs/a` of `/inputs/a/b`, not of
/// `/inputs/ab`). The reference definition the tests check [`path_set_issues`] against.
#[cfg(test)]
fn is_dir_of(dir: &str, path: &str) -> bool {
    path.strip_prefix(dir).is_some_and(|rest| rest.starts_with('/'))
}

/// A problem in a set of file paths, found by [`path_set_issues`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSetIssue {
    /// `index` repeats the path at `first`.
    Duplicate {
        /// The repeated entry.
        index: usize,
        /// Its first occurrence.
        first: usize,
    },
    /// One of the paths at `index` and `other` is a directory of the other (`a` and `a/b`): both cannot be files.
    Conflict {
        /// The refused entry.
        index: usize,
        /// An earlier entry it conflicts with.
        other: usize,
    },
}

/// Finds duplicates and directory conflicts in a list of (already individually valid) paths, in order: the first
/// of two clashing entries is kept and the later one is reported. A reported entry is not kept, so it causes no
/// further reports.
///
/// Used for input files (§7) and for `JobFinished.outputs`. It is `O(n log n)` in the number of paths (times the
/// path depth): kept paths live in a sorted map, ancestors are looked up directly, and descendants with one range
/// query.
pub fn path_set_issues<'a>(paths: impl IntoIterator<Item = &'a str>) -> Vec<PathSetIssue> {
    use std::collections::BTreeMap;
    use std::ops::Bound;
    let mut kept: BTreeMap<&str, usize> = BTreeMap::new();
    let mut issues = Vec::new();
    for (index, path) in paths.into_iter().enumerate() {
        if let Some(&first) = kept.get(path) {
            issues.push(PathSetIssue::Duplicate { index, first });
            continue;
        }
        // An ancestor of `path` that is a kept file. (Kept paths never conflict with each other, so at most one.)
        let ancestor = path
            .match_indices('/')
            .map(|(i, _)| &path[..i])
            .filter(|prefix| !prefix.is_empty())
            .find_map(|prefix| kept.get(prefix).copied());
        // A kept file below `path`: the first key at or after `path/` starts with it if any does.
        let below = format!("{path}/");
        let descendant = kept
            .range::<str, _>((Bound::Included(below.as_str()), Bound::Unbounded))
            .next()
            .filter(|(k, _)| k.starts_with(below.as_str()))
            .map(|(_, &i)| i);
        match ancestor.or(descendant) {
            Some(other) => issues.push(PathSetIssue::Conflict { index, other }),
            None => {
                kept.insert(path, index);
            }
        }
    }
    issues
}

/// `[A-Z_][A-Z0-9_]*`
fn is_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_uppercase() || b == b'_' => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Whether `key` is a valid label key: `[a-z0-9]([a-z0-9._/-]{0,61}[a-z0-9])?`. The same rule applies to
/// `placement.labels` and to the labels a node owner sets in the agent config.
#[must_use]
pub fn is_label_key(key: &str) -> bool {
    let b = key.as_bytes();
    let edge = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let inner = |c: &u8| edge(c) || matches!(c, b'.' | b'_' | b'/' | b'-');
    !b.is_empty() && b.len() <= 63 && b.first().is_some_and(edge) && b.last().is_some_and(edge) && b.iter().all(inner)
}

/// Why a file path is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// An input path must be absolute and under `/inputs/`.
    #[error("the path must be absolute and under /inputs/")]
    NotUnderInputs,
    /// An output path must be relative to `/outputs`.
    #[error("the path must be relative")]
    Absolute,
    /// Empty, `.` or `..` segment, or a segment longer than 255 bytes.
    #[error("the path must not contain empty, `.` or `..` segments, or segments over 255 bytes")]
    InvalidSegment,
    /// NUL, control characters or backslashes.
    #[error("the path must not contain NUL, control characters or backslashes")]
    InvalidChar,
    /// Longer than 4096 bytes.
    #[error("the path is longer than 4096 bytes")]
    TooLong,
}

/// Checks the segments of a relative path: non-empty, not `.` or `..`, at most 255 bytes, no NUL, control
/// characters or backslashes.
fn check_relative(rel: &str) -> Result<(), PathError> {
    if rel.chars().any(|ch| ch.is_control() || ch == '\\') {
        return Err(PathError::InvalidChar);
    }
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg.len() > MAX_SEGMENT_LEN {
            return Err(PathError::InvalidSegment);
        }
    }
    Ok(())
}

/// Checks an input file path (§7): absolute under `/inputs/`, naming a file below it, with no `..`, `.` or empty
/// segments.
pub fn validate_input_path(path: &str) -> Result<(), PathError> {
    if path.len() > MAX_PATH_LEN {
        return Err(PathError::TooLong);
    }
    let rest = path
        .strip_prefix(INPUTS_DIR)
        .and_then(|r| r.strip_prefix('/'))
        .ok_or(PathError::NotUnderInputs)?;
    check_relative(rest)
}

/// Checks an output path, relative to `/outputs` (SI-9): not absolute, with no `..`, `.` or empty segments. Use it
/// on the agent before uploading and on the server before storing or serving a download.
pub fn validate_output_path(path: &str) -> Result<(), PathError> {
    if path.len() > MAX_PATH_LEN {
        return Err(PathError::TooLong);
    }
    if path.starts_with('/') {
        return Err(PathError::Absolute);
    }
    check_relative(path)
}

/// Why base64 input is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Base64Error {
    /// Not standard padded base64.
    #[error("not valid padded base64")]
    Invalid,
    /// The decoded size is over the limit.
    #[error("the decoded size is over the limit")]
    TooLarge,
}

/// The exact decoded size of standard padded base64, computed from its length and padding only (no decoding).
/// `None` if the length is not a multiple of 4 or the padding is malformed.
#[must_use]
pub fn base64_decoded_len(encoded: &str) -> Option<usize> {
    let b = encoded.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let pad = b.iter().rev().take_while(|&&c| c == b'=').count();
    // Padding is at most two characters, and only at the very end.
    if pad > 2 || b[..b.len() - pad].contains(&b'=') {
        return None;
    }
    Some(b.len() / 4 * 3 - pad)
}

/// Decodes standard padded base64, refusing input whose decoded size is over `max` **before** decoding anything.
pub fn decode_base64_bounded(encoded: &str, max: usize) -> Result<Vec<u8>, Base64Error> {
    let len = base64_decoded_len(encoded).ok_or(Base64Error::Invalid)?;
    if len > max {
        return Err(Base64Error::TooLarge);
    }
    data_encoding::BASE64
        .decode(encoded.as_bytes())
        .map_err(|_| Base64Error::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Egress, InputFile, Outputs, Placement, Resources, Retry};
    use std::collections::BTreeMap;

    fn base() -> JobSpec {
        JobSpec {
            name: Some("label".into()),
            image: "python:3.12-slim".into(),
            command: vec!["python".into(), "-c".into(), "print(6*7)".into()],
            env: BTreeMap::from([("KEY".into(), "value".into())]),
            files: vec![InputFile {
                path: "/inputs/data.csv".into(),
                content_b64: "aGk=".into(),
            }],
            resources: Resources {
                cpu: 2.0,
                memory_mb: 4096,
                gpu: 0,
                disk_mb: 10_240,
            },
            timeout_s: 3600,
            egress: Egress {
                allow: vec!["pypi.org".into(), "files.pythonhosted.org".into()],
            },
            outputs: Outputs { max_mb: 1024 },
            placement: Placement::default(),
            retry: Retry { max_attempts: 2 },
            idempotency_key: Some("abc-123".into()),
        }
    }

    fn with(f: impl FnOnce(&mut JobSpec)) -> JobSpec {
        let mut s = base();
        f(&mut s);
        s
    }

    fn b64_of_len(n: usize) -> String {
        data_encoding::BASE64.encode(&vec![7u8; n])
    }

    #[test]
    fn the_spec_example_is_valid() {
        assert_eq!(base().validate(&Limits::default()), Ok(()));
    }

    /// Valid boundary cases, one or more per row of the §7 table.
    #[test]
    fn valid_rows() {
        let limits = Limits::default();
        let cases: Vec<(&str, JobSpec)> = vec![
            ("image: hub short name", with(|s| s.image = "python".into())),
            ("image: ghcr", with(|s| s.image = "ghcr.io/org/app:1".into())),
            ("image: quay", with(|s| s.image = "quay.io/org/app".into())),
            (
                "image: nvcr",
                with(|s| s.image = "nvcr.io/nvidia/pytorch:24.01-py3".into()),
            ),
            (
                "image: gitlab",
                with(|s| s.image = "registry.gitlab.com/g/p/i:main".into()),
            ),
            (
                "image: uppercase registry",
                with(|s| s.image = "GHCR.IO/org/app".into()),
            ),
            (
                "image: digest",
                with(|s| s.image = format!("python@sha256:{}", "a".repeat(64))),
            ),
            ("command: 1 arg", with(|s| s.command = vec!["true".into()])),
            ("command: 256 args", with(|s| s.command = vec!["x".into(); 256])),
            ("command: 64 KiB", with(|s| s.command = vec!["x".repeat(64 * 1024)])),
            (
                "command: empty later arg",
                with(|s| s.command = vec!["echo".into(), String::new()]),
            ),
            ("env: none", with(|s| s.env.clear())),
            (
                "env: 64 vars",
                with(|s| s.env = (0..64).map(|i| (format!("V{i}"), "x".into())).collect()),
            ),
            (
                "env: 32 KiB",
                with(|s| s.env = BTreeMap::from([("A".into(), "x".repeat(32 * 1024 - 1))])),
            ),
            (
                "env: underscore names",
                with(|s| s.env = BTreeMap::from([("_A_1".into(), String::new())])),
            ),
            (
                "env: P2PC without underscore",
                with(|s| s.env = BTreeMap::from([("P2PCX".into(), "v".into())])),
            ),
            (
                "env: unicode value",
                with(|s| s.env = BTreeMap::from([("A".into(), "héllo wörld\t".into())])),
            ),
            ("files: none", with(|s| s.files.clear())),
            ("files: nested", with(|s| s.files[0].path = "/inputs/a/b/c.txt".into())),
            ("files: dotfile", with(|s| s.files[0].path = "/inputs/.config".into())),
            (
                "files: exactly 512 KiB",
                with(|s| s.files[0].content_b64 = b64_of_len(512 * 1024)),
            ),
            ("files: empty", with(|s| s.files[0].content_b64 = String::new())),
            (
                "files: siblings and shared name prefixes are not path prefixes",
                with(|s| {
                    s.files = [
                        "/inputs/a/b",
                        "/inputs/a/c",
                        "/inputs/ab",
                        "/inputs/a.txt",
                        "/inputs/abc/d",
                    ]
                    .iter()
                    .map(|p| InputFile {
                        path: (*p).into(),
                        content_b64: String::new(),
                    })
                    .collect()
                }),
            ),
            (
                "files: 512 KiB split",
                with(|s| {
                    s.files = vec![
                        InputFile {
                            path: "/inputs/a".into(),
                            content_b64: b64_of_len(256 * 1024),
                        },
                        InputFile {
                            path: "/inputs/b".into(),
                            content_b64: b64_of_len(256 * 1024),
                        },
                    ]
                }),
            ),
            ("cpu: 0.25", with(|s| s.resources.cpu = 0.25)),
            ("cpu: 256", with(|s| s.resources.cpu = 256.0)),
            ("cpu: fractional", with(|s| s.resources.cpu = 1.5)),
            ("cpu: milli step", with(|s| s.resources.cpu = 1.234)),
            (
                "cpu: float noise of a milli step",
                with(|s| s.resources.cpu = 0.1 + 0.2 + 0.7),
            ),
            ("cpu: two decimals", with(|s| s.resources.cpu = 4.03)),
            ("memory: 128", with(|s| s.resources.memory_mb = 128)),
            ("memory: 1048576", with(|s| s.resources.memory_mb = 1_048_576)),
            ("gpu: 0", with(|s| s.resources.gpu = 0)),
            ("gpu: 1", with(|s| s.resources.gpu = 1)),
            ("disk: 1", with(|s| s.resources.disk_mb = 1)),
            ("disk: max", with(|s| s.resources.disk_mb = 1_048_576)),
            ("timeout: 1", with(|s| s.timeout_s = 1)),
            ("timeout: 86400", with(|s| s.timeout_s = 86_400)),
            ("egress: none", with(|s| s.egress.allow.clear())),
            (
                "egress: 32",
                with(|s| s.egress.allow = (0..32).map(|i| format!("d{i}.example.com")).collect()),
            ),
            (
                "egress: punycode",
                with(|s| s.egress.allow = vec!["xn--bcher-kva.example".into()]),
            ),
            ("pools: mine", with(|s| s.placement.pools = vec!["mine".into()])),
            (
                "labels",
                with(|s| s.placement.labels = BTreeMap::from([("gpu.vendor/model-x".into(), "rtx 4090".into())])),
            ),
            (
                "node pin",
                with(|s| s.placement.node_id = Some(crate::ids::NodeId::generate())),
            ),
            ("retry: 1", with(|s| s.retry.max_attempts = 1)),
            ("retry: 5", with(|s| s.retry.max_attempts = 5)),
            ("outputs: 1", with(|s| s.outputs.max_mb = 1)),
            ("outputs: max", with(|s| s.outputs.max_mb = 10_240)),
            ("idempotency key: absent", with(|s| s.idempotency_key = None)),
            (
                "idempotency key: 255",
                with(|s| s.idempotency_key = Some("k".repeat(255))),
            ),
            ("name: absent", with(|s| s.name = None)),
            ("name: 256", with(|s| s.name = Some("n".repeat(256)))),
        ];
        for (label, spec) in cases {
            assert_eq!(spec.validate(&limits), Ok(()), "{label}");
        }
    }

    /// Invalid cases for every row of the §7 table, with the expected field path and code.
    #[test]
    fn invalid_rows() {
        use ErrorCode::*;
        let limits = Limits::default();
        let cases: Vec<(&str, JobSpec, &str, ErrorCode)> = vec![
            (
                "image: garbage",
                with(|s| s.image = "Not A Ref".into()),
                "image",
                InvalidFormat,
            ),
            (
                "image: empty",
                with(|s| s.image = String::new()),
                "image",
                InvalidFormat,
            ),
            (
                "image: registry",
                with(|s| s.image = "registry.example.com/app".into()),
                "image",
                NotAllowed,
            ),
            (
                "image: localhost",
                with(|s| s.image = "localhost:5000/app".into()),
                "image",
                NotAllowed,
            ),
            (
                "image: bad digest",
                with(|s| s.image = "python@sha256:abc".into()),
                "image",
                InvalidFormat,
            ),
            ("command: empty", with(|s| s.command.clear()), "command", OutOfRange),
            (
                "command: 257 args",
                with(|s| s.command = vec!["x".into(); 257]),
                "command",
                OutOfRange,
            ),
            (
                "command: 64 KiB + 1",
                with(|s| s.command = vec!["x".repeat(64 * 1024 + 1)]),
                "command",
                TooLarge,
            ),
            (
                "command: empty program",
                with(|s| s.command = vec![String::new()]),
                "command[0]",
                InvalidFormat,
            ),
            (
                "command: NUL",
                with(|s| s.command.push("a\0b".into())),
                "command[3]",
                InvalidFormat,
            ),
            (
                "env: 65 vars",
                with(|s| s.env = (0..65).map(|i| (format!("V{i}"), "x".into())).collect()),
                "env",
                TooMany,
            ),
            (
                "env: 32 KiB + 1",
                with(|s| s.env = BTreeMap::from([("A".into(), "x".repeat(32 * 1024))])),
                "env",
                TooLarge,
            ),
            (
                "env: lowercase",
                with(|s| s.env = BTreeMap::from([("key".into(), "v".into())])),
                "env",
                InvalidFormat,
            ),
            (
                "env: digit first",
                with(|s| s.env = BTreeMap::from([("1A".into(), "v".into())])),
                "env",
                InvalidFormat,
            ),
            (
                "env: dash",
                with(|s| s.env = BTreeMap::from([("A-B".into(), "v".into())])),
                "env",
                InvalidFormat,
            ),
            (
                "env: empty name",
                with(|s| s.env = BTreeMap::from([(String::new(), "v".into())])),
                "env",
                InvalidFormat,
            ),
            (
                "env: equals",
                with(|s| s.env = BTreeMap::from([("A=B".into(), "v".into())])),
                "env",
                InvalidFormat,
            ),
            (
                "env: reserved",
                with(|s| s.env = BTreeMap::from([("P2PC_TOKEN".into(), "v".into())])),
                "env.P2PC_TOKEN",
                Reserved,
            ),
            (
                "env: reserved bare prefix",
                with(|s| s.env = BTreeMap::from([("P2PC_".into(), "v".into())])),
                "env.P2PC_",
                Reserved,
            ),
            (
                "env: newline in value",
                with(|s| s.env = BTreeMap::from([("A".into(), "x\nP2PC_X=1".into())])),
                "env.A",
                InvalidFormat,
            ),
            (
                "env: NUL in value",
                with(|s| s.env = BTreeMap::from([("A".into(), "x\0".into())])),
                "env.A",
                InvalidFormat,
            ),
            (
                "files: relative",
                with(|s| s.files[0].path = "inputs/a".into()),
                "files[0].path",
                InvalidFormat,
            ),
            (
                "files: outside",
                with(|s| s.files[0].path = "/etc/passwd".into()),
                "files[0].path",
                InvalidFormat,
            ),
            (
                "files: prefix trick",
                with(|s| s.files[0].path = "/inputsx/a".into()),
                "files[0].path",
                InvalidFormat,
            ),
            (
                "files: dir itself",
                with(|s| s.files[0].path = "/inputs".into()),
                "files[0].path",
                InvalidFormat,
            ),
            (
                "files: dir slash",
                with(|s| s.files[0].path = "/inputs/".into()),
                "files[0].path",
                InvalidFormat,
            ),
            (
                "files: dotdot",
                with(|s| s.files[0].path = "/inputs/../etc/x".into()),
                "files[0].path",
                InvalidFormat,
            ),
            (
                "files: inner dotdot",
                with(|s| s.files[0].path = "/inputs/a/../../x".into()),
                "files[0].path",
                InvalidFormat,
            ),
            (
                "files: dot",
                with(|s| s.files[0].path = "/inputs/./a".into()),
                "files[0].path",
                InvalidFormat,
            ),
            (
                "files: empty seg",
                with(|s| s.files[0].path = "/inputs/a//b".into()),
                "files[0].path",
                InvalidFormat,
            ),
            (
                "files: trailing slash",
                with(|s| s.files[0].path = "/inputs/a/".into()),
                "files[0].path",
                InvalidFormat,
            ),
            (
                "files: NUL",
                with(|s| s.files[0].path = "/inputs/a\0".into()),
                "files[0].path",
                InvalidFormat,
            ),
            (
                "files: backslash",
                with(|s| s.files[0].path = "/inputs/..\\x".into()),
                "files[0].path",
                InvalidFormat,
            ),
            (
                "files: duplicate",
                with(|s| {
                    s.files.push(InputFile {
                        path: "/inputs/data.csv".into(),
                        content_b64: String::new(),
                    })
                }),
                "files[1].path",
                Duplicate,
            ),
            (
                "files: path is a directory of another",
                with(|s| {
                    s.files = vec![
                        InputFile {
                            path: "/inputs/a".into(),
                            content_b64: String::new(),
                        },
                        InputFile {
                            path: "/inputs/a/b".into(),
                            content_b64: String::new(),
                        },
                    ]
                }),
                "files[1].path",
                PathConflict,
            ),
            (
                "files: path conflict in reverse order",
                with(|s| {
                    s.files = vec![
                        InputFile {
                            path: "/inputs/a/b/c".into(),
                            content_b64: String::new(),
                        },
                        InputFile {
                            path: "/inputs/x".into(),
                            content_b64: String::new(),
                        },
                        InputFile {
                            path: "/inputs/a".into(),
                            content_b64: String::new(),
                        },
                    ]
                }),
                "files[2].path",
                PathConflict,
            ),
            (
                "files: not base64",
                with(|s| s.files[0].content_b64 = "!!!!".into()),
                "files[0].content_b64",
                InvalidFormat,
            ),
            (
                "files: unpadded",
                with(|s| s.files[0].content_b64 = "aGk".into()),
                "files[0].content_b64",
                InvalidFormat,
            ),
            (
                "files: inner padding",
                with(|s| s.files[0].content_b64 = "aGk=aGk=".into()),
                "files[0].content_b64",
                InvalidFormat,
            ),
            (
                "files: 512 KiB + 1",
                with(|s| s.files[0].content_b64 = b64_of_len(512 * 1024 + 1)),
                "files",
                TooLarge,
            ),
            (
                "files: 512 KiB + 1 split",
                with(|s| {
                    s.files = vec![
                        InputFile {
                            path: "/inputs/a".into(),
                            content_b64: b64_of_len(256 * 1024),
                        },
                        InputFile {
                            path: "/inputs/b".into(),
                            content_b64: b64_of_len(256 * 1024 + 1),
                        },
                    ]
                }),
                "files",
                TooLarge,
            ),
            (
                "files: too many",
                with(|s| {
                    s.files = (0..257)
                        .map(|i| InputFile {
                            path: format!("/inputs/{i}"),
                            content_b64: String::new(),
                        })
                        .collect()
                }),
                "files",
                TooMany,
            ),
            (
                "cpu: 0.24",
                with(|s| s.resources.cpu = 0.24),
                "resources.cpu",
                OutOfRange,
            ),
            ("cpu: 0", with(|s| s.resources.cpu = 0.0), "resources.cpu", OutOfRange),
            (
                "cpu: negative",
                with(|s| s.resources.cpu = -1.0),
                "resources.cpu",
                OutOfRange,
            ),
            (
                "cpu: 256.01",
                with(|s| s.resources.cpu = 256.01),
                "resources.cpu",
                OutOfRange,
            ),
            (
                "cpu: NaN",
                with(|s| s.resources.cpu = f64::NAN),
                "resources.cpu",
                OutOfRange,
            ),
            (
                "cpu: inf",
                with(|s| s.resources.cpu = f64::INFINITY),
                "resources.cpu",
                OutOfRange,
            ),
            (
                "cpu: finer than 0.001",
                with(|s| s.resources.cpu = 0.2505),
                "resources.cpu",
                InvalidFormat,
            ),
            (
                "cpu: a ten-thousandth",
                with(|s| s.resources.cpu = 1.0001),
                "resources.cpu",
                InvalidFormat,
            ),
            (
                "memory: 127",
                with(|s| s.resources.memory_mb = 127),
                "resources.memory_mb",
                OutOfRange,
            ),
            (
                "memory: too big",
                with(|s| s.resources.memory_mb = 1_048_577),
                "resources.memory_mb",
                OutOfRange,
            ),
            ("gpu: 2", with(|s| s.resources.gpu = 2), "resources.gpu", OutOfRange),
            (
                "disk: 0",
                with(|s| s.resources.disk_mb = 0),
                "resources.disk_mb",
                OutOfRange,
            ),
            (
                "disk: too big",
                with(|s| s.resources.disk_mb = 1_048_577),
                "resources.disk_mb",
                OutOfRange,
            ),
            ("timeout: 0", with(|s| s.timeout_s = 0), "timeout_s", OutOfRange),
            (
                "timeout: 86401",
                with(|s| s.timeout_s = 86_401),
                "timeout_s",
                OutOfRange,
            ),
            (
                "egress: 33",
                with(|s| s.egress.allow = (0..33).map(|i| format!("d{i}.example.com")).collect()),
                "egress.allow",
                TooMany,
            ),
            (
                "egress: uppercase",
                with(|s| s.egress.allow = vec!["PyPI.org".into()]),
                "egress.allow[0]",
                InvalidFormat,
            ),
            (
                "egress: wildcard",
                with(|s| s.egress.allow = vec!["*.pypi.org".into()]),
                "egress.allow[0]",
                InvalidFormat,
            ),
            (
                "egress: ipv4",
                with(|s| s.egress.allow = vec!["192.0.2.1".into()]),
                "egress.allow[0]",
                InvalidFormat,
            ),
            (
                "egress: ipv6",
                with(|s| s.egress.allow = vec!["2001:db8::1".into()]),
                "egress.allow[0]",
                InvalidFormat,
            ),
            (
                "egress: url",
                with(|s| s.egress.allow = vec!["https://pypi.org".into()]),
                "egress.allow[0]",
                InvalidFormat,
            ),
            (
                "egress: duplicate",
                with(|s| s.egress.allow = vec!["pypi.org".into(), "pypi.org".into()]),
                "egress.allow[1]",
                Duplicate,
            ),
            (
                "pools: other",
                with(|s| s.placement.pools = vec!["community".into()]),
                "placement.pools",
                UnsupportedPool,
            ),
            (
                "pools: empty",
                with(|s| s.placement.pools.clear()),
                "placement.pools",
                UnsupportedPool,
            ),
            (
                "pools: mine twice",
                with(|s| s.placement.pools = vec!["mine".into(), "mine".into()]),
                "placement.pools",
                UnsupportedPool,
            ),
            (
                "pools: mine and more",
                with(|s| s.placement.pools = vec!["mine".into(), "cloud".into()]),
                "placement.pools",
                UnsupportedPool,
            ),
            (
                "pools: case",
                with(|s| s.placement.pools = vec!["Mine".into()]),
                "placement.pools",
                UnsupportedPool,
            ),
            (
                "labels: bad key",
                with(|s| s.placement.labels = BTreeMap::from([("Bad Key".into(), "v".into())])),
                "placement.labels",
                InvalidFormat,
            ),
            (
                "labels: long value",
                with(|s| s.placement.labels = BTreeMap::from([("k".into(), "v".repeat(256))])),
                "placement.labels.k",
                TooLarge,
            ),
            (
                "labels: too many",
                with(|s| s.placement.labels = (0..33).map(|i| (format!("k{i}"), String::new())).collect()),
                "placement.labels",
                TooMany,
            ),
            (
                "retry: 0",
                with(|s| s.retry.max_attempts = 0),
                "retry.max_attempts",
                OutOfRange,
            ),
            (
                "retry: 6",
                with(|s| s.retry.max_attempts = 6),
                "retry.max_attempts",
                OutOfRange,
            ),
            (
                "outputs: 0",
                with(|s| s.outputs.max_mb = 0),
                "outputs.max_mb",
                OutOfRange,
            ),
            (
                "outputs: too big",
                with(|s| s.outputs.max_mb = 10_241),
                "outputs.max_mb",
                OutOfRange,
            ),
            (
                "idempotency key: empty",
                with(|s| s.idempotency_key = Some(String::new())),
                "idempotency_key",
                InvalidFormat,
            ),
            (
                "idempotency key: 256",
                with(|s| s.idempotency_key = Some("k".repeat(256))),
                "idempotency_key",
                InvalidFormat,
            ),
            (
                "idempotency key: space",
                with(|s| s.idempotency_key = Some("a b".into())),
                "idempotency_key",
                InvalidFormat,
            ),
            ("name: 257", with(|s| s.name = Some("n".repeat(257))), "name", TooLarge),
            (
                "name: control",
                with(|s| s.name = Some("a\u{1b}[31m".into())),
                "name",
                InvalidFormat,
            ),
        ];
        for (label, spec, field, code) in cases {
            let errs = spec.validate(&limits).expect_err(label);
            assert!(
                errs.contains(field, code),
                "{label}: expected {field} {code}, got {errs}"
            );
            assert_eq!(errs.len(), 1, "{label}: expected exactly one error, got {errs}");
        }
    }

    #[test]
    fn all_errors_are_collected_in_table_order() {
        let spec = with(|s| {
            s.resources.cpu = 0.0;
            s.timeout_s = 0;
            s.placement.pools = vec!["cloud".into()];
        });
        let errs = spec.validate(&Limits::default()).unwrap_err();
        let fields: Vec<_> = errs.iter().map(|e| e.field.as_str()).collect();
        assert_eq!(fields, ["resources.cpu", "timeout_s", "placement.pools"]);
        let problem = crate::api::Problem::from_validation(&errs);
        assert_eq!(problem.status, 422);
        assert_eq!(problem.code, "unsupported_pool");
        assert_eq!(problem.errors.len(), 3);
        let only_cpu = with(|s| s.resources.cpu = 0.0)
            .validate(&Limits::default())
            .unwrap_err();
        assert_eq!(
            crate::api::Problem::from_validation(&only_cpu).code,
            "validation_failed"
        );
    }

    #[test]
    fn env_line_breaks_are_refused_with_a_helpful_message() {
        for value in ["a\nb", "a\rb", "a\r\nb", "trailing\n", "a\0b"] {
            let spec = with(|s| s.env = BTreeMap::from([("CERT".into(), value.into())]));
            let errs = spec.validate(&Limits::default()).unwrap_err();
            let e = errs.iter().find(|e| e.field == "env.CERT").unwrap();
            assert_eq!(e.code, ErrorCode::InvalidFormat);
            // The message explains why (Podman's line-based --env-file) and how to fix it.
            assert!(e.message.contains("--env-file"), "{}", e.message);
            assert!(e.message.contains("base64"), "{}", e.message);
            assert!(e.message.contains("files"), "{}", e.message);
        }
        // Tabs and other characters are fine.
        let ok = with(|s| s.env = BTreeMap::from([("A".into(), "x\ty z=1;".into())]));
        assert_eq!(ok.validate(&Limits::default()), Ok(()));
    }

    #[test]
    fn errors_never_echo_env_values() {
        let secret = "s3cr3t-value-\n-P2PC_EVIL=1";
        let spec = with(|s| {
            s.env = BTreeMap::from([("P2PC_X".into(), secret.into()), ("bad name".into(), secret.into())]);
        });
        let errs = spec.validate(&Limits::default()).unwrap_err();
        let text = format!(
            "{errs} {errs:?} {}",
            serde_json::to_string(&errs.clone().into_vec()).unwrap()
        );
        assert!(!text.contains("s3cr3t"), "{text}");
        assert!(!text.contains("bad name"), "{text}");
    }

    /// The largest job that validates, with worst-case JSON escaping (control characters become `\u00XX`, six bytes
    /// each) in `command` and `env`. Its worst-case `Lease` is exactly `MAX_FRAME_LEN` bytes.
    fn largest_deliverable_spec() -> JobSpec {
        use crate::protocol::{MAX_FRAME_LEN, lease_frame_len};
        let mut s = base();
        s.image = "docker.io/library/python:3.12-slim".into(); // already normalized
        s.command = vec!["python".into(), "\u{1}".repeat(40 * 1024), String::new()];
        s.env = BTreeMap::from([("A".into(), "\u{1f}".repeat(30 * 1024))]);
        s.files = vec![InputFile {
            path: "/inputs/data.bin".into(),
            content_b64: String::new(),
        }];
        // Fill with file content, in whole base64 quanta, up to a little under the frame limit.
        let room = MAX_FRAME_LEN as usize - lease_frame_len(&s) - 64;
        s.files[0].content_b64 = b64_of_len(room / 4 * 3);
        // Then close the gap byte by byte: each plain ASCII character adds exactly one byte.
        let gap = MAX_FRAME_LEN as usize - lease_frame_len(&s);
        s.command[2] = "x".repeat(gap);
        assert_eq!(lease_frame_len(&s), MAX_FRAME_LEN as usize);
        s
    }

    /// Review P2 (spec §7 `files`, 908b42c): a job that validates always fits in its `Lease` frame.
    #[tokio::test]
    async fn the_largest_valid_job_fits_its_lease_frame_and_one_byte_more_does_not() {
        use crate::protocol::{MAX_FRAME_LEN, worst_case_lease, write_frame};
        let s = largest_deliverable_spec();
        assert_eq!(s.validate(&Limits::default()), Ok(()));
        // Every other limit holds with room to spare: only the frame check is at its edge.
        let raw_command: usize = s.command.iter().map(String::len).sum();
        assert!(raw_command < 64 * 1024 && s.env["A"].len() < 32 * 1024);
        let mut frame = Vec::new();
        write_frame(&mut frame, &worst_case_lease(&s)).await.unwrap();
        assert_eq!(frame.len(), 4 + MAX_FRAME_LEN as usize);

        // One byte more, in any field, is refused with `too_large`.
        type Grow<'a> = (&'static str, &'a dyn Fn(&mut JobSpec));
        let grow: [Grow<'_>; 5] = [
            ("command", &|s| s.command[2].push('x')),
            ("command escape", &|s| s.command[2].replace_range(0..1, "\u{2}")),
            ("env", &|s| s.env.get_mut("A").unwrap().push('y')),
            ("name", &|s| s.name.as_mut().unwrap().push('n')),
            ("file", &|s| {
                s.files[0].content_b64 = b64_of_len(base64_decoded_len(&s.files[0].content_b64).unwrap() + 1)
            }),
        ];
        for (label, f) in grow {
            let mut bigger = s.clone();
            f(&mut bigger);
            let errs = bigger.validate(&Limits::default()).unwrap_err();
            assert!(errs.contains("job", ErrorCode::TooLarge), "{label}: {errs}");
            assert_eq!(errs.len(), 1, "{label}: {errs}");
            let mut sink = Vec::new();
            assert!(
                write_frame(&mut sink, &worst_case_lease(&bigger)).await.is_err(),
                "{label}"
            );
        }
    }

    /// Review P2 (spec §7 `files`): a job that does not fit its Lease is `422 too_large`, not `validation_failed`.
    #[test]
    fn a_job_too_big_for_its_lease_is_a_too_large_problem() {
        let mut s = largest_deliverable_spec();
        s.command[2].push('x');
        let problem = crate::api::Problem::from_validation(&s.validate(&Limits::default()).unwrap_err());
        assert_eq!(problem.status, 422);
        assert_eq!(problem.code, "too_large");
        assert_eq!(problem.errors.len(), 1);
        assert_eq!(problem.errors[0].field, "job");
        // A `too_large` on another field is an ordinary validation failure.
        let big_file = with(|s| s.files[0].content_b64 = b64_of_len(512 * 1024 + 1));
        let problem = crate::api::Problem::from_validation(&big_file.validate(&Limits::default()).unwrap_err());
        assert_eq!(problem.code, "validation_failed");
    }

    /// The server stores the image normalized (`python:3.12-slim` → `docker.io/library/python:3.12-slim`), so the
    /// lease carries the longer form. The check measures that, not the request as typed.
    #[test]
    fn the_frame_check_measures_the_normalized_image() {
        use crate::protocol::{MAX_FRAME_LEN, lease_frame_len, worst_case_lease};
        let full = largest_deliverable_spec();
        let mut short = full.clone();
        short.image = "python:3.12-slim".into();
        assert_eq!(lease_frame_len(&short), lease_frame_len(&full));
        assert_eq!(short.validate(&Limits::default()), Ok(()));
        // Use the bytes the short name "saves" in the request: the request as typed still fits a frame…
        let saved = full.image.len() - short.image.len();
        let mut tipped = short.clone();
        tipped.command[2].push_str(&"x".repeat(saved));
        let raw = serde_json::to_vec(&worst_case_lease(&tipped)).unwrap().len();
        assert_eq!(raw, MAX_FRAME_LEN as usize);
        // …but the stored, normalized job would not, so it is refused.
        assert_eq!(lease_frame_len(&tipped), MAX_FRAME_LEN as usize + saved);
        assert!(
            tipped
                .validate(&Limits::default())
                .unwrap_err()
                .contains("job", ErrorCode::TooLarge)
        );
    }

    #[test]
    fn oversized_files_are_not_decoded() {
        // 10 MiB of '#' (not base64) with a valid length: refused as too large, never decoded.
        let spec = with(|s| s.files[0].content_b64 = "#".repeat(10 * 1024 * 1024));
        let errs = spec.validate(&Limits::default()).unwrap_err();
        assert!(errs.contains("files", ErrorCode::TooLarge), "{errs}");
        assert!(
            !errs.contains("files[0].content_b64", ErrorCode::InvalidFormat),
            "{errs}"
        );
    }

    #[test]
    fn limits_are_configurable() {
        let limits = Limits {
            allowed_registries: Some(vec!["registry.example.com".into()]),
            ..Limits::default()
        };
        assert_eq!(
            with(|s| s.image = "registry.example.com/app".into()).validate(&limits),
            Ok(())
        );
        assert!(
            base()
                .validate(&limits)
                .unwrap_err()
                .contains("image", ErrorCode::NotAllowed)
        );
        let limits = Limits {
            max_files_bytes: 1,
            ..Limits::default()
        };
        assert!(
            base()
                .validate(&limits)
                .unwrap_err()
                .contains("files", ErrorCode::TooLarge)
        );
    }

    /// Review P3: over the file cap, nothing is checked per entry (one `too_many`, whatever the entries hold).
    #[test]
    fn too_many_files_skips_the_per_entry_checks() {
        let spec = with(|s| {
            s.files = (0..10_000)
                .map(|i| InputFile {
                    path: format!("bad path {i}"),
                    content_b64: "!".into(),
                })
                .collect()
        });
        let errs = spec.validate(&Limits::default()).unwrap_err();
        assert_eq!(errs.len(), 1, "{errs}");
        assert!(errs.contains("files", ErrorCode::TooMany));
    }

    #[test]
    fn path_set_issues_cases() {
        use PathSetIssue::*;
        let issues = |p: &[&str]| path_set_issues(p.iter().copied());
        assert_eq!(issues(&["/inputs/a", "/inputs/b", "/inputs/ab", "/inputs/a.b/c"]), []);
        assert_eq!(issues(&["/inputs/a", "/inputs/a"]), [Duplicate { index: 1, first: 0 }]);
        assert_eq!(issues(&["/inputs/a", "/inputs/a/b"]), [Conflict { index: 1, other: 0 }]);
        assert_eq!(
            issues(&["/inputs/a/b/c", "/inputs/a"]),
            [Conflict { index: 1, other: 0 }]
        );
        assert_eq!(
            issues(&["/inputs/a/b/c", "/inputs/x", "/inputs/a/b"]),
            [Conflict { index: 2, other: 0 }]
        );
        // Relative output paths work the same way.
        assert_eq!(
            issues(&["out", "out/x.csv", "out.csv"]),
            [Conflict { index: 1, other: 0 }]
        );
        // A refused path is not kept, so it causes no further issues.
        assert_eq!(
            issues(&["a", "a/b", "a/b/c"]),
            [Conflict { index: 1, other: 0 }, Conflict { index: 2, other: 0 }]
        );
    }

    /// The same sequential semantics as `path_set_issues`, the slow way.
    fn path_set_issues_reference(paths: &[String]) -> Vec<PathSetIssue> {
        let mut kept: Vec<(usize, &str)> = Vec::new();
        let mut out = Vec::new();
        for (i, p) in paths.iter().enumerate() {
            if let Some((j, _)) = kept.iter().find(|(_, q)| *q == p) {
                out.push(PathSetIssue::Duplicate { index: i, first: *j });
            } else if let Some((j, _)) = kept.iter().find(|(_, q)| is_dir_of(q, p) || is_dir_of(p, q)) {
                out.push(PathSetIssue::Conflict { index: i, other: *j });
            } else {
                kept.push((i, p));
            }
        }
        out
    }

    proptest::proptest! {
        #[test]
        fn path_set_issues_matches_the_quadratic_reference(
            paths in proptest::collection::vec("[ab]{1,2}(/[ab]{1,2}){0,3}", 0..40)
        ) {
            let fast = path_set_issues(paths.iter().map(String::as_str));
            let slow = path_set_issues_reference(&paths);
            proptest::prop_assert_eq!(fast.len(), slow.len());
            for (f, s) in fast.iter().zip(&slow) {
                match (f, s) {
                    (PathSetIssue::Duplicate { .. }, PathSetIssue::Duplicate { .. }) => proptest::prop_assert_eq!(f, s),
                    // A new path can be a directory of several kept paths; any of them is a correct `other`.
                    (
                        PathSetIssue::Conflict { index, other },
                        PathSetIssue::Conflict { index: slow_index, .. },
                    ) => {
                        proptest::prop_assert_eq!(index, slow_index);
                        let (p, q) = (&paths[*index], &paths[*other]);
                        proptest::prop_assert!(other < index && (is_dir_of(p, q) || is_dir_of(q, p)));
                    }
                    _ => proptest::prop_assert!(false, "{:?} vs {:?}", f, s),
                }
            }
        }
    }

    #[test]
    fn output_paths() {
        for ok in ["a", "a/b.csv", ".hidden", "a/.b/c", "x..y"] {
            assert_eq!(validate_output_path(ok), Ok(()), "{ok:?}");
        }
        let bad = [
            ("", PathError::InvalidSegment),
            ("/etc/passwd", PathError::Absolute),
            ("..", PathError::InvalidSegment),
            ("../x", PathError::InvalidSegment),
            ("a/../../x", PathError::InvalidSegment),
            ("./a", PathError::InvalidSegment),
            ("a//b", PathError::InvalidSegment),
            ("a/", PathError::InvalidSegment),
            ("a\0b", PathError::InvalidChar),
            ("..\\x", PathError::InvalidChar),
            ("a\nb", PathError::InvalidChar),
        ];
        for (path, want) in bad {
            assert_eq!(validate_output_path(path), Err(want), "{path:?}");
        }
        assert_eq!(validate_output_path(&"a/".repeat(3000)), Err(PathError::TooLong));
        assert_eq!(validate_output_path(&"a".repeat(256)), Err(PathError::InvalidSegment));
    }

    #[test]
    fn base64_helpers() {
        assert_eq!(base64_decoded_len(""), Some(0));
        assert_eq!(base64_decoded_len("aGk="), Some(2));
        assert_eq!(base64_decoded_len("aGVsbG8="), Some(5));
        assert_eq!(base64_decoded_len("aGVsbA=="), Some(4));
        assert_eq!(base64_decoded_len("aGVs"), Some(3));
        assert_eq!(base64_decoded_len("aGk"), None);
        assert_eq!(base64_decoded_len("a==="), None);
        assert_eq!(base64_decoded_len("aG=k"), None);
        assert_eq!(decode_base64_bounded("aGVsbG8=", 5), Ok(b"hello".to_vec()));
        assert_eq!(decode_base64_bounded("aGVsbG8=", 4), Err(Base64Error::TooLarge));
        assert_eq!(decode_base64_bounded("aGVsbG9=", 5), Err(Base64Error::Invalid)); // non-zero trailing bits
        assert_eq!(decode_base64_bounded("aGVs bG8", 10), Err(Base64Error::Invalid));
        assert_eq!(decode_base64_bounded("aGVs_G8=", 10), Err(Base64Error::Invalid)); // URL-safe alphabet
    }
}
