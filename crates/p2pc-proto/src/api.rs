// SPDX-License-Identifier: Apache-2.0

//! REST API types: `JobSpec`, `Job`, nodes, keys and usage (spec §7).
//!
//! JSON field names are exactly those of §7, in snake_case. Timestamps are RFC 3339 in UTC.
//!
//! Unknown fields (spec §6, "Compatibility within `p2pc/agent/1`"):
//! - **request bodies** ([`JobSpec`] and its parts, [`CreateApiKey`], [`CreateJoinToken`]) reject them, so a typo such
//!   as `"memroy_mb"` is an error instead of a silent default;
//! - **response types and protocol payloads** ([`Job`], [`Node`], [`Inventory`], [`OutputFile`], …) ignore them, so
//!   an older CLI or server keeps working when a newer peer adds a field.
//!
//! Validation rules live in [`crate::validate`]; this module only describes shapes and defaults.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::auth::{ApiKey, JoinToken};
use crate::ids::{AccountId, AuditEventId, JobId, JoinTokenId, KeyId, NodeId, ProjectId};
use crate::units::Units;

/// Default `resources.disk_mb` (§7).
pub const DEFAULT_DISK_MB: u64 = 2_048;
/// Default `timeout_s` (§7).
pub const DEFAULT_TIMEOUT_S: u32 = 3_600;
/// Default `retry.max_attempts` (§7).
pub const DEFAULT_MAX_ATTEMPTS: u32 = 2;
/// Default `outputs.max_mb` (the §7 example).
pub const DEFAULT_OUTPUTS_MAX_MB: u64 = 1_024;
/// The only placement pool in v0.1.
pub const POOL_MINE: &str = "mine";
/// Largest page size for list endpoints (§7).
pub const MAX_PAGE_LIMIT: u32 = 100;

fn default_disk_mb() -> u64 {
    DEFAULT_DISK_MB
}
fn default_timeout_s() -> u32 {
    DEFAULT_TIMEOUT_S
}
fn default_max_attempts() -> u32 {
    DEFAULT_MAX_ATTEMPTS
}
fn default_outputs_max_mb() -> u64 {
    DEFAULT_OUTPUTS_MAX_MB
}
fn default_pools() -> Vec<String> {
    vec![POOL_MINE.to_string()]
}

/// Defines the job spec types once, so the strict request types and the lenient response types cannot drift.
///
/// `$strictness` is applied to every struct: `serde(deny_unknown_fields)` for the request types, nothing for the
/// response types. `$note` is appended to every type's doc. `$File` is defined outside the macro, because the two
/// families differ there: the request carries `content_b64`, the response only `{path, size, sha256}` (§7).
macro_rules! job_spec_types {
    (
        strictness: [$(#[$strictness:meta])*],
        note: $note:literal,
        idempotency: [$($idempotency:tt)*],
        $Spec:ident, $File:ident, $Res:ident, $Egress:ident, $Out:ident, $Place:ident, $Retry:ident $(,)?
    ) => {
        #[doc = "A job specification: what to run and with which limits (§7)."]
        #[doc = ""]
        #[doc = "`Debug` never prints environment values or input file contents (§7: env values are never logged)."]
        #[doc = ""]
        #[doc = $note]
        #[derive(Clone, PartialEq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$strictness])*
        pub struct $Spec {
            /// Optional human label.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub name: Option<String>,
            /// OCI image reference, for example `docker.io/library/python:3.12-slim`.
            pub image: String,
            /// The argv to run. There is no shell unless the argv calls one.
            pub command: Vec<String>,
            /// Environment variables. Values are secret-like: never logged, and never returned by the API.
            ///
            /// Values may not contain NUL, `\n` or `\r` (§7): they go into Podman's line-based `--env-file`, where a
            /// newline would inject another variable. Encode multi-line secrets as base64, or pass them as `files`.
            #[serde(default)]
            pub env: BTreeMap<String, String>,
            /// Files written under `/inputs` before the job starts.
            #[serde(default)]
            pub files: Vec<$File>,
            /// Requested resources.
            pub resources: $Res,
            /// Wall-clock limit in seconds. Default 3 600.
            #[serde(default = "default_timeout_s")]
            pub timeout_s: u32,
            /// Network egress allowlist. Empty means no network at all.
            #[serde(default)]
            pub egress: $Egress,
            /// Limits on the files collected from `/outputs`.
            #[serde(default)]
            pub outputs: $Out,
            /// Where the job may run.
            #[serde(default)]
            pub placement: $Place,
            /// Retry policy (only node loss consumes an attempt).
            #[serde(default)]
            pub retry: $Retry,
            $($idempotency)*
        }

        #[doc = "Requested resources."]
        #[doc = ""]
        #[doc = $note]
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$strictness])*
        pub struct $Res {
            /// vCPUs, 0.25-256, fractional allowed.
            pub cpu: f64,
            /// Memory in MiB, 128-1 048 576.
            pub memory_mb: u64,
            /// Whole GPUs: 0 or 1 in v0.1.
            #[serde(default)]
            pub gpu: u32,
            /// Disk in MiB for outputs and the writable layer. Default 2 048.
            #[serde(default = "default_disk_mb")]
            pub disk_mb: u64,
        }

        #[doc = "Network egress policy."]
        #[doc = ""]
        #[doc = $note]
        #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$strictness])*
        pub struct $Egress {
            /// Allowed domains. Each one matches itself and its subdomains on whole labels.
            #[serde(default)]
            pub allow: Vec<String>,
        }

        #[doc = "Limits on collected outputs."]
        #[doc = ""]
        #[doc = $note]
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$strictness])*
        pub struct $Out {
            /// Maximum total size of the uploaded outputs, in MiB.
            #[serde(default = "default_outputs_max_mb")]
            pub max_mb: u64,
        }

        impl Default for $Out {
            fn default() -> Self {
                Self { max_mb: DEFAULT_OUTPUTS_MAX_MB }
            }
        }

        #[doc = "Placement constraints."]
        #[doc = ""]
        #[doc = $note]
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$strictness])*
        pub struct $Place {
            /// Pools the job may run in. Only `["mine"]` in v0.1.
            #[serde(default = "default_pools")]
            pub pools: Vec<String>,
            /// Pin the job to one node.
            #[serde(default)]
            pub node_id: Option<NodeId>,
            /// Node labels that must all match.
            #[serde(default)]
            pub labels: BTreeMap<String, String>,
        }

        impl Default for $Place {
            fn default() -> Self {
                Self { pools: default_pools(), node_id: None, labels: BTreeMap::new() }
            }
        }

        #[doc = "Retry policy."]
        #[doc = ""]
        #[doc = $note]
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$strictness])*
        pub struct $Retry {
            /// Attempts in total, 1-5. Default 2. Only node loss consumes an attempt.
            #[serde(default = "default_max_attempts")]
            pub max_attempts: u32,
        }

        impl Default for $Retry {
            fn default() -> Self {
                Self { max_attempts: DEFAULT_MAX_ATTEMPTS }
            }
        }
    };
}

job_spec_types!(
    strictness: [#[serde(deny_unknown_fields)]],
    note: "**Strict** (request type): the `POST /v1/jobs` body, and what the agent parses a lease's job into \
           (`LeaseJob::parse_strict`). Unknown fields are rejected, which catches typos and refuses a lease the \
           agent would not fully understand (§6). Responses use the lenient twin, [`JobSpecView`].",
    idempotency: [
        /// Client-chosen key that makes the submission idempotent (§7). Scoped to the API key that submits it. It is
        /// **never returned**: no response type has it (see [`JobSpecView`]).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub idempotency_key: Option<String>,
    ],
    JobSpec,
    InputFile,
    Resources,
    Egress,
    Outputs,
    Placement,
    Retry,
);

job_spec_types!(
    strictness: [],
    note: "**Lenient and redacted** (response type): the `spec` of a [`Job`] in API responses (§7 \"Job \
           representation in responses\"). Unknown fields are ignored, so an older CLI or SDK keeps reading jobs \
           after the server adds a field (§6). `env` values are always `\"<redacted>\"` and `files` carry \
           `{path, size, sha256}` with no content, and there is **no `idempotency_key`**: a response never carries it \
           (§7). Build it with [`JobSpecView::from_stored`].",
    // No `idempotency_key`: responses never carry it (§7). The key only means something to the key that sent it, and
    // echoing it would let another key learn it.
    idempotency: [],
    JobSpecView,
    InputFileView,
    ResourcesView,
    EgressView,
    OutputsView,
    PlacementView,
    RetryView,
);

/// Writes the `Debug` of a spec type: env values and file contents are redacted, only names, paths and sizes show.
macro_rules! spec_debug {
    ($Spec:ident $(, $extra:ident)?) => {
        impl fmt::Debug for $Spec {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Env values and file contents are redacted: only names, paths and sizes are shown.
                let env_names: Vec<&str> = self.env.keys().map(String::as_str).collect();
                let mut d = f.debug_struct(stringify!($Spec));
                d.field("name", &self.name)
                    .field("image", &self.image)
                    .field("command", &self.command)
                    .field("env_names", &env_names)
                    .field("files", &self.files)
                    .field("resources", &self.resources)
                    .field("timeout_s", &self.timeout_s)
                    .field("egress", &self.egress)
                    .field("outputs", &self.outputs)
                    .field("placement", &self.placement)
                    .field("retry", &self.retry);
                $(d.field(stringify!($extra), &self.$extra);)?
                d.finish()
            }
        }
    };
}

spec_debug!(JobSpec, idempotency_key);
spec_debug!(JobSpecView);

/// An input file in a request: written to `path` (under `/inputs`) with the base64-decoded `content_b64`.
///
/// `Debug` shows the path and the encoded length, never the content. **Strict** (request type): unknown fields are
/// rejected.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct InputFile {
    /// Absolute path under `/inputs/`.
    pub path: String,
    /// File content, standard base64 with padding.
    pub content_b64: String,
}

impl fmt::Debug for InputFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InputFile")
            .field("path", &self.path)
            .field("content_b64_len", &self.content_b64.len())
            .finish()
    }
}

/// An input file as shown in responses (§7): its path, decoded size and SHA-256, **never its content**. Lenient:
/// unknown fields are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InputFileView {
    /// Absolute path under `/inputs/`.
    pub path: String,
    /// Decoded size in bytes.
    pub size: u64,
    /// SHA-256 of the decoded content.
    pub sha256: Sha256Digest,
}

/// The value every `env` entry has in a [`JobSpecView`] (§7).
pub const REDACTED: &str = "<redacted>";

/// `From` from a strict nested type to its response twin: they have the same fields.
macro_rules! convert_twins {
    ($($A:ident => $B:ident { $($field:ident),* $(,)? })*) => {$(
        impl From<$A> for $B {
            fn from(v: $A) -> Self {
                Self { $($field: v.$field),* }
            }
        }
    )*};
}

convert_twins! {
    Resources => ResourcesView { cpu, memory_mb, gpu, disk_mb }
    Egress => EgressView { allow }
    Outputs => OutputsView { max_mb }
    Placement => PlacementView { pools, node_id, labels }
    Retry => RetryView { max_attempts }
}

/// The metadata of one input file, `{path, size, sha256}`: what responses show instead of the content (§7).
///
/// The server computes it **once**, when the job is accepted ([`FileMeta::compute_all`]), stores it next to the
/// job, and builds every response from it with [`JobSpecView::from_stored_with_meta`], so listing jobs never
/// decodes or hashes file contents again.
pub type FileMeta = InputFileView;

impl InputFileView {
    /// The metadata of one input file: its decoded size and the SHA-256 of the decoded content.
    pub fn compute(file: &InputFile) -> Result<Self, crate::validate::Base64Error> {
        let bytes = crate::validate::decode_base64_bounded(&file.content_b64, usize::MAX)?;
        Ok(Self {
            path: file.path.clone(),
            size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            sha256: Sha256Digest(Sha256::digest(&bytes).into()),
        })
    }

    /// The metadata of every input file of a spec, in order. Call it once, at submission (after validation).
    pub fn compute_all(spec: &JobSpec) -> Result<Vec<Self>, crate::validate::Base64Error> {
        spec.files.iter().map(Self::compute).collect()
    }
}

/// The file metadata given to [`JobSpecView::from_stored_with_meta`] does not describe the spec's files (another
/// count, or another path at some position).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the file metadata does not match the job's input files")]
pub struct FileMetaMismatch;

impl JobSpecView {
    /// The response view of a stored spec, from file metadata computed once at submission (§7 "Job representation
    /// in responses"):
    /// - every `env` value becomes [`REDACTED`] (names are kept);
    /// - `files` are the given `{path, size, sha256}`; the content is neither copied, decoded nor hashed.
    ///
    /// Secrets submitted by a `jobs:write` key are therefore never readable through the API. Fails if `meta` does
    /// not list exactly the spec's file paths, in order.
    pub fn from_stored_with_meta(spec: &JobSpec, meta: &[FileMeta]) -> Result<Self, FileMetaMismatch> {
        let matches = meta.len() == spec.files.len() && meta.iter().zip(&spec.files).all(|(m, f)| m.path == f.path);
        if !matches {
            return Err(FileMetaMismatch);
        }
        Ok(Self::redacted(spec, meta.to_vec()))
    }

    /// Like [`JobSpecView::from_stored_with_meta`], computing the file metadata on the spot. Convenient for tests
    /// and one-offs; the server should store [`FileMeta::compute_all`] at submission instead of calling this for
    /// every response. Fails only if a stored file is not valid base64, which validation rules out.
    pub fn from_stored(spec: &JobSpec) -> Result<Self, crate::validate::Base64Error> {
        Ok(Self::redacted(spec, FileMeta::compute_all(spec)?))
    }

    fn redacted(spec: &JobSpec, files: Vec<FileMeta>) -> Self {
        Self {
            name: spec.name.clone(),
            image: spec.image.clone(),
            command: spec.command.clone(),
            env: spec.env.keys().map(|k| (k.clone(), REDACTED.to_string())).collect(),
            files,
            resources: spec.resources.clone().into(),
            timeout_s: spec.timeout_s,
            egress: spec.egress.clone().into(),
            outputs: spec.outputs.clone().into(),
            placement: spec.placement.clone().into(),
            retry: spec.retry.clone().into(),
        }
    }
}

/// State of a job (§7).
///
/// `queued → assigned → running → {succeeded | failed | timed_out | cancelled | lost}`, with requeueing on node loss.
/// See [`transition_allowed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    /// Waiting for a node.
    Queued,
    /// Leased to a node, not started yet.
    Assigned,
    /// Running on a node.
    Running,
    /// Exited with code 0.
    Succeeded,
    /// Exited with a non-zero code, or the sandbox failed.
    Failed,
    /// Hit `timeout_s`.
    TimedOut,
    /// Cancelled by the user.
    Cancelled,
    /// Its node was lost and no attempts remained.
    Lost,
}

impl JobStatus {
    /// Every state, in declaration order.
    pub const ALL: [JobStatus; 8] = [
        JobStatus::Queued,
        JobStatus::Assigned,
        JobStatus::Running,
        JobStatus::Succeeded,
        JobStatus::Failed,
        JobStatus::TimedOut,
        JobStatus::Cancelled,
        JobStatus::Lost,
    ];

    /// Whether the state is final. Terminal states are immutable.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            JobStatus::Succeeded | JobStatus::Failed | JobStatus::TimedOut | JobStatus::Cancelled | JobStatus::Lost
        )
    }

    /// The snake_case name used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            JobStatus::Queued => "queued",
            JobStatus::Assigned => "assigned",
            JobStatus::Running => "running",
            JobStatus::Succeeded => "succeeded",
            JobStatus::Failed => "failed",
            JobStatus::TimedOut => "timed_out",
            JobStatus::Cancelled => "cancelled",
            JobStatus::Lost => "lost",
        }
    }
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The job state machine of §7: whether a job may move from `from` to `to`.
///
/// - `queued → assigned` (placement) or `cancelled`. A queued job never expires in v0.1.
/// - `assigned → running` (`JobStarted`), `queued` (node loss with attempts left, or the lease was not accepted in
///   time), `lost` (node loss, no attempts left), `failed` (the sandbox failed before the job started),
///   `timed_out` (the server watchdog's backstop for an agent that accepted the lease and hung before
///   `JobStarted`, for example during an image pull; §7, §8 "Timeouts") or `cancelled`.
/// - `running → succeeded | failed | timed_out | cancelled | lost`, or `queued` on node loss with attempts left.
/// - Terminal states never change. Staying in the same state is not a transition.
#[must_use]
pub const fn transition_allowed(from: JobStatus, to: JobStatus) -> bool {
    use JobStatus::*;
    matches!(
        (from, to),
        (Queued, Assigned | Cancelled)
            | (Assigned, Running | Queued | Lost | Failed | TimedOut | Cancelled)
            | (Running, Succeeded | Failed | TimedOut | Cancelled | Lost | Queued)
    )
}

/// A job as returned by the API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Job {
    /// Job ID.
    pub id: JobId,
    /// Project the job belongs to.
    pub project_id: ProjectId,
    /// Optional label, copied from the spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Current state.
    pub status: JobStatus,
    /// Current attempt, starting at 1 (0 while never placed).
    pub attempt: u32,
    /// The submitted spec, with the image normalized, built with [`JobSpecView::from_stored`]: `env` values are
    /// `"<redacted>"` and files carry no content (§7). Lenient: a field added by a newer server does not break
    /// older clients.
    pub spec: JobSpecView,
    /// Node of the current or last attempt.
    #[serde(default)]
    pub node_id: Option<NodeId>,
    /// Why the job is in its current state, when there is something to tell the user, for example why a queued job
    /// is not being placed (§8 "Offer cap"). User-visible; never contains secrets.
    #[serde(default)]
    pub reason: Option<String>,
    /// When a cancel was requested for a job that was already `assigned` or `running` (the scheduler delivers it to
    /// the node, and the job ends `cancelled`). `null` if none was requested, or if the job was queued and
    /// cancelled at once.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub cancel_requested_at: Option<OffsetDateTime>,
    /// Exit code, when the job exited.
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Short error code when the job failed without an exit code (for example `disk_limit`).
    #[serde(default)]
    pub error: Option<String>,
    /// Estimated units reserved by the job (resources × timeout).
    pub estimated_units: Units,
    /// When the job was created.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub created_at: OffsetDateTime,
    /// When the current attempt started running.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub started_at: Option<OffsetDateTime>,
    /// When the job reached a terminal state.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub finished_at: Option<OffsetDateTime>,
    /// The job's attempts, oldest first: only in `GET /v1/jobs/{id}`; lists of jobs leave the field out (§7). An
    /// attempt is an accepted lease: refused or unanswered offers are not listed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<Vec<JobAttempt>>,
}

impl Job {
    /// A job with nothing but its identity, state, spec, estimate and creation time: no node, reason, cancel request,
    /// result, timestamps or attempts. Set the other public fields after, so a field added here does not break other
    /// crates (CONTRIBUTING rule 7).
    #[must_use]
    pub fn new(
        id: JobId,
        project_id: ProjectId,
        status: JobStatus,
        attempt: u32,
        spec: JobSpecView,
        estimated_units: Units,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            project_id,
            name: spec.name.clone(),
            status,
            attempt,
            spec,
            node_id: None,
            reason: None,
            cancel_requested_at: None,
            exit_code: None,
            error: None,
            estimated_units,
            created_at,
            started_at: None,
            finished_at: None,
            attempts: None,
        }
    }
}

/// One attempt of a job, in `GET /v1/jobs/{id}` (§7): an accepted lease, on one node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct JobAttempt {
    /// The attempt number, from 1. Only node loss starts a new one.
    pub attempt: u32,
    /// The node it ran on.
    pub node_id: NodeId,
    /// In job-state words: `running` while the attempt is in progress (accepted, or started), then `succeeded`,
    /// `failed`, `timed_out`, `cancelled` or `lost`. An attempt replaced after node loss (fenced) is `lost`.
    pub outcome: JobStatus,
    /// The reason code of the end (for example `exited_0`, `exit_code`, `node_lost`, `absent_from_hello`,
    /// `watchdog`), or `null` while the attempt runs. Never a secret.
    #[serde(default)]
    pub reason: Option<String>,
    /// When the job process started on the node (`JobStarted`); `null` if it never did (accepted, then lost or timed
    /// out during the image pull).
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub started_at: Option<OffsetDateTime>,
    /// When the attempt ended; `null` while it runs.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub ended_at: Option<OffsetDateTime>,
}

impl JobAttempt {
    /// Attempt `attempt` on `node_id`, in progress (`running`, no reason, not started, not ended). Set the other
    /// public fields after (CONTRIBUTING rule 7).
    #[must_use]
    pub fn new(attempt: u32, node_id: NodeId) -> Self {
        Self {
            attempt,
            node_id,
            outcome: JobStatus::Running,
            reason: None,
            started_at: None,
            ended_at: None,
        }
    }
}

/// Which output stream a log line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// One line of `GET /v1/jobs/{id}/logs` (NDJSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LogLine {
    /// Sequence number within the attempt.
    pub seq: u64,
    /// Source stream.
    pub stream: LogStream,
    /// When the agent captured it.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub ts: OffsetDateTime,
    /// The text (invalid UTF-8 replaced).
    pub data: String,
}

/// A SHA-256 digest, serialized as 64 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema), schema(value_type = String))]
pub struct Sha256Digest(pub [u8; 32]);

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&data_encoding::HEXLOWER.encode(&self.0))
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({self})")
    }
}

/// The string is not 64 lowercase hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("expected a SHA-256 digest as 64 lowercase hex characters")]
pub struct InvalidDigest;

impl std::str::FromStr for Sha256Digest {
    type Err = InvalidDigest;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(InvalidDigest);
        }
        let bytes = data_encoding::HEXLOWER
            .decode(s.as_bytes())
            .map_err(|_| InvalidDigest)?;
        bytes.try_into().map(Sha256Digest).map_err(|_| InvalidDigest)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::ids::deserialize_from_str(deserializer)
    }
}

/// An output file of a job (`GET /v1/jobs/{id}/outputs`, and `JobFinished.outputs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OutputFile {
    /// Path relative to `/outputs`, for example `results/a.csv`.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256 of the content.
    pub sha256: Sha256Digest,
}

/// Most log bytes stored per attempt (§7, 64 MiB of NDJSON). Past it, one [`LOG_TRUNCATED_MESSAGE`] line on
/// `stderr`, and the rest is dropped.
pub const MAX_LOG_BYTES_PER_ATTEMPT: u64 = 64 * 1024 * 1024;

/// The `data` of the single line that marks a truncated log (§7).
pub const LOG_TRUNCATED_MESSAGE: &str =
    "[p2pc] log truncated: this attempt's log reached 64 MiB; later output was dropped";

/// Most output files one attempt may upload (§6 "Uploads").
pub const MAX_OUTPUT_FILES: u32 = 10_000;

/// The header of an output download that carries the file's SHA-256 (§7), 64 lowercase hex characters.
pub const OUTPUT_SHA256_HEADER: &str = "x-p2pc-sha256";

/// One entry of `GET /v1/jobs/{id}/outputs` (§7): a published output file. Clients that only know [`OutputFile`]
/// read it as one (unknown fields are ignored).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OutputEntry {
    /// Path relative to `/outputs`, for example `results/a.csv`.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256 of the content.
    pub sha256: Sha256Digest,
    /// The file was garbage-collected after the retention period (§12): the download answers `410 Gone`.
    #[serde(default)]
    pub expired: bool,
}

impl OutputEntry {
    /// A published, unexpired entry for `file`.
    #[must_use]
    pub fn new(file: OutputFile) -> Self {
        Self {
            path: file.path,
            size: file.size,
            sha256: file.sha256,
            expired: false,
        }
    }

    /// The entry as an [`OutputFile`].
    #[must_use]
    pub fn file(&self) -> OutputFile {
        OutputFile {
            path: self.path.clone(),
            size: self.size,
            sha256: self.sha256,
        }
    }
}

/// Connection state of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    /// Connected and heartbeating.
    Online,
    /// Not connected, or its lease TTL expired.
    Offline,
}

/// An amount of node capacity.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Capacity {
    /// vCPUs.
    pub cpu: f64,
    /// Memory in MiB.
    pub memory_mb: u64,
    /// Whole GPUs.
    pub gpu: u32,
    /// Disk for job directories, in MiB (§6 `Inventory`, §8). `None` when the agent does not report it (older than
    /// the 2026-11-07 amendment): the scheduler then places by CPU, memory and GPU only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_mb: Option<u64>,
}

/// CPU description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CpuInfo {
    /// Model name, for example `AMD Ryzen 9 7950X`.
    pub model: String,
    /// Logical cores.
    pub cores: u32,
}

/// One GPU (§6 "GPU inventory"). The `uuid` is its key: a GPU is never identified by its index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GpuInfo {
    /// Stable identifier, for example `GPU-6a3d0a2e-…` (NVML), or `MIG-…`.
    pub uuid: String,
    /// Device index as the driver enumerates it. Informational only.
    pub index: u32,
    /// Model name.
    pub name: String,
    /// Driver version.
    pub driver_version: String,
    /// CUDA version the driver supports, if known.
    #[serde(default)]
    pub cuda_driver_version: Option<String>,
    /// Compute capability, for example `8.9`, if known.
    #[serde(default)]
    pub compute_capability: Option<String>,
    /// Video memory in MiB. `None` means unknown, and then the GPU is not offerable (it is never guessed).
    #[serde(default)]
    pub vram_mb: Option<u64>,
    /// PCI bus/device/function, for example `0000:01:00.0`, if known (not on WSL2).
    #[serde(default)]
    pub pci_bdf: Option<String>,
    /// Whether MIG is enabled. A MIG card is reported but not offerable in v0.1.
    #[serde(default)]
    pub mig: bool,
}

impl GpuInfo {
    /// Whether the GPU may be offered to jobs in v0.1: MIG disabled and VRAM known (§6).
    #[must_use]
    pub fn is_offerable(&self) -> bool {
        !self.mig && self.vram_mb.is_some()
    }
}

/// The node's platform (§6, §9.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// Native Linux.
    Linux,
    /// The dedicated WSL2 distro on Windows.
    Wsl2,
}

/// Outcome of GPU detection (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GpuStatusKind {
    /// Detection worked (there may still be no GPU).
    Ok,
    /// No NVIDIA driver.
    NoDriver,
    /// NVML failed.
    NvmlError,
    /// No GPU was found.
    NotFound,
    /// The CDI spec is missing.
    CdiMissing,
    /// The CDI spec is older than the driver.
    CdiStale,
}

/// GPU detection status with an optional explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GpuStatus {
    /// The outcome.
    pub status: GpuStatusKind,
    /// Human explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Result of the once-per-boot smoke container on WSL2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SmokeResult {
    /// Whether the smoke container ran correctly.
    pub ok: bool,
    /// Short explanation when it did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The WSL2 health block (§6 "GPU inventory").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Wsl2Health {
    /// The distro's version stamp. `null` when unknown (no stamp file): never an empty string.
    #[serde(default)]
    pub distro_version: Option<String>,
    /// Podman version. `null` when unknown (Podman missing or its version unreadable): never an empty string.
    #[serde(default)]
    pub podman_version: Option<String>,
    /// Whether the CDI spec is present.
    pub cdi_present: bool,
    /// Whether the CDI spec is older than the driver.
    pub cdi_stale: bool,
    /// The once-per-boot smoke container, once it has run.
    #[serde(default)]
    pub smoke: Option<SmokeResult>,
}

/// Isolation class of a sandbox driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SandboxClass {
    /// An OCI container (rootless Podman with crun).
    Container,
    /// An OCI container under gVisor (`runsc`).
    ContainerGvisor,
}

/// A sandbox driver the node can use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SandboxCapability {
    /// Driver name, for example `podman`.
    pub driver: String,
    /// Isolation class.
    pub class: SandboxClass,
    /// OCI runtimes available, for example `["crun"]`.
    pub runtimes: Vec<String>,
    /// Whether the node meets the §9.0 requirements of its platform profile for this driver. Added in T07; an
    /// inventory without it decodes as **not** ready (fail closed).
    #[serde(default)]
    pub ready: bool,
    /// Why the driver is not ready, one entry per failed §9.0 check, each `<code>: <detail>`. Empty when ready.
    #[serde(default)]
    pub problems: Vec<String>,
}

/// What a node has (§6 `Join`/`Hello`, §7 `GET /v1/nodes`). Reported by the agent; validate it with
/// [`crate::protocol::validate_inventory`] when it comes from the network.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Inventory {
    /// The machine's hostname, as reported. The server derives the node's unique `name` from it (§5); it is never
    /// used for authentication.
    pub hostname: String,
    /// Native Linux or the WSL2 distro.
    pub platform: Platform,
    /// CPU.
    pub cpu: CpuInfo,
    /// Total RAM in MiB.
    pub memory_mb: u64,
    /// Operating system, for example `Ubuntu 24.04`.
    pub os: String,
    /// CPU architecture, for example `x86_64`.
    pub arch: String,
    /// GPUs, keyed by `uuid`.
    #[serde(default)]
    pub gpus: Vec<GpuInfo>,
    /// Outcome of GPU detection.
    pub gpu_status: GpuStatus,
    /// Whether `/dev/dxg` (the WSL2 GPU device) is present.
    #[serde(default)]
    pub dxg: bool,
    /// WSL2 health block; absent on native Linux.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wsl2: Option<Wsl2Health>,
    /// Sandbox drivers.
    #[serde(default)]
    pub sandbox: Vec<SandboxCapability>,
    /// Capacity offered to jobs: hardware × the owner's share limits (§8).
    pub offered: Capacity,
    /// Size of the filesystem that holds the job directories, in MiB, if the agent could read it. `offered.disk_mb`
    /// never exceeds it (validated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_total_mb: Option<u64>,
    /// Agent version.
    pub agent_version: String,
}

/// A node as returned by the API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Node {
    /// Node ID.
    pub id: NodeId,
    /// The node's name, **derived by the server** from the reported hostname: sanitized and unique per account
    /// (`base`, `base-1`, …, compared case-insensitively). An explicit rename that collides is refused. Never used
    /// for authentication (§5 "Names").
    pub name: String,
    /// The hostname the agent reported, as is.
    pub hostname: String,
    /// Connection state.
    pub state: NodeState,
    /// Whether the node is draining (accepts no new jobs).
    pub draining: bool,
    /// Last reported inventory.
    pub inventory: Inventory,
    /// Capacity not reserved by active leases.
    pub free: Capacity,
    /// Labels used by `placement.labels`.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Last heartbeat.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub last_seen: Option<OffsetDateTime>,
    /// When the node joined.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub created_at: OffsetDateTime,
}

impl Node {
    /// A node with nothing reserved (`free` is `inventory.offered`), not draining, no labels and never seen. Callers
    /// outside this crate set the other public fields afterwards, so a field added here does not break them
    /// (CONTRIBUTING "Shared types grow").
    #[must_use]
    pub fn new(
        id: NodeId,
        name: impl Into<String>,
        hostname: impl Into<String>,
        state: NodeState,
        inventory: Inventory,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            hostname: hostname.into(),
            state,
            draining: false,
            free: inventory.offered.clone(),
            inventory,
            labels: BTreeMap::new(),
            last_seen: None,
            created_at,
        }
    }
}

/// Response of `POST /v1/estimate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Estimate {
    /// Whether some enrolled node could ever run the job.
    pub feasible: bool,
    /// Nodes that match the request.
    pub matching_nodes: u32,
    /// Whether the job would wait in the queue right now.
    pub would_queue: bool,
    /// Units the job reserves per hour, in milli-units.
    pub units_per_hour: Units,
    /// Why the job is not feasible, or would queue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// An API key scope (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum Scope {
    /// Everything.
    #[serde(rename = "admin")]
    Admin,
    /// Create and cancel jobs.
    #[serde(rename = "jobs:write")]
    JobsWrite,
    /// Read jobs, logs, outputs, estimates and usage.
    #[serde(rename = "jobs:read")]
    JobsRead,
    /// Read nodes.
    #[serde(rename = "nodes:read")]
    NodesRead,
    /// Drain, resume and delete nodes.
    #[serde(rename = "nodes:write")]
    NodesWrite,
}

/// Body of `POST /v1/keys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CreateApiKey {
    /// Optional human label (§5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Scopes granted to the key.
    pub scopes: Vec<Scope>,
    /// Optional expiry (§5). After it, the key authenticates nothing.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub expires_at: Option<OffsetDateTime>,
    /// Daily cap in milli-units, per UTC day.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily_unit_cap: Option<Units>,
    /// Glob patterns on the normalized image reference. `None` allows every image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_images: Option<Vec<String>>,
}

/// An API key as listed by `GET /v1/keys`. Never contains the secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiKeyInfo {
    /// Public key ID.
    pub id: KeyId,
    /// Project the key acts in.
    pub project_id: ProjectId,
    /// Optional human label (§5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Granted scopes.
    pub scopes: Vec<Scope>,
    /// Daily cap in milli-units.
    #[serde(default)]
    pub daily_unit_cap: Option<Units>,
    /// Image allowlist. `None` allows every image.
    #[serde(default)]
    pub allowed_images: Option<Vec<String>>,
    /// Creation time.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub created_at: OffsetDateTime,
    /// Optional expiry (§5).
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub expires_at: Option<OffsetDateTime>,
    /// Last time the key authenticated a request (the server writes it at most once a minute).
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub last_used_at: Option<OffsetDateTime>,
    /// When the key was revoked. A revoked key's row is never deleted (§5).
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub revoked_at: Option<OffsetDateTime>,
}

/// Response of `POST /v1/keys`, **flat** (§5): every field of the key's metadata plus `key`, the full key, which is
/// shown only this once.
///
/// `Debug` redacts the secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NewApiKey {
    /// The full key, `p2pc_sk_<key_id>_<secret>`. Store it now: it cannot be shown again.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub key: ApiKey,
    /// The key's metadata, serialized at the top level.
    #[serde(flatten)]
    pub info: ApiKeyInfo,
}

/// Body of `POST /v1/nodes/join-tokens`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CreateJoinToken {
    /// Optional human label, shown when tokens are listed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Validity in seconds. Default 900 (15 minutes), maximum 86 400 (24 h).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_s: Option<u32>,
}

/// A join token as listed by `GET /v1/nodes/join-tokens` (§5 "Listing and revoking"). Never contains the token or
/// its code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct JoinTokenInfo {
    /// Row ID, used by `DELETE /v1/nodes/join-tokens/{id}`.
    pub id: JoinTokenId,
    /// Optional label.
    #[serde(default)]
    pub label: Option<String>,
    /// The key that created it.
    pub created_by_key_id: KeyId,
    /// Creation time.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub created_at: OffsetDateTime,
    /// Expiry (from the server's row, the only one that counts).
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub expires_at: OffsetDateTime,
    /// When a `Join` consumed it.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub consumed_at: Option<OffsetDateTime>,
    /// The node it enrolled.
    #[serde(default)]
    pub consumed_by_node_id: Option<NodeId>,
    /// When it was revoked unused.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub revoked_at: Option<OffsetDateTime>,
}

impl JoinTokenInfo {
    /// An unused, unrevoked token with no label. Callers outside this crate set the other public fields afterwards
    /// (CONTRIBUTING "Shared types grow").
    #[must_use]
    pub fn new(
        id: JoinTokenId,
        created_by_key_id: KeyId,
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            label: None,
            created_by_key_id,
            created_at,
            expires_at,
            consumed_at: None,
            consumed_by_node_id: None,
            revoked_at: None,
        }
    }
}

/// Response of `GET /v1/whoami`: who the presented key is, and its limits (§7). Never contains the secret.
///
/// The limit fields (`label`, `daily_unit_cap`, `allowed_images`, `expires_at`) were added after the first shape
/// (`{account_id, project_id, key_id, scopes}`); they default to `null` when an older server omits them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WhoAmI {
    /// The key's account.
    pub account_id: AccountId,
    /// The key's project.
    pub project_id: ProjectId,
    /// The key's public ID.
    pub key_id: KeyId,
    /// The key's scopes.
    pub scopes: Vec<Scope>,
    /// The key's label, if it has one.
    #[serde(default)]
    pub label: Option<String>,
    /// The key's daily cap in milli-units, per UTC day. `null` means **uncapped**: `p2pc mcp` uses this to refuse
    /// a key that could spend without limit (§7).
    #[serde(default)]
    pub daily_unit_cap: Option<Units>,
    /// The key's image allowlist (globs on the normalized image). `null` allows every image.
    #[serde(default)]
    pub allowed_images: Option<Vec<String>>,
    /// When the key expires, if it does.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub expires_at: Option<OffsetDateTime>,
}

/// Response of `GET /healthz` (§7): liveness only, with no data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Health {
    /// Always `ok`.
    pub status: String,
}

impl Health {
    /// `{"status":"ok"}`.
    #[must_use]
    pub fn ok() -> Self {
        Self { status: "ok".into() }
    }
}

/// What an audit event records (§5 "Audit"). Closed: one value per event the spec lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// An API key was created.
    KeyCreated,
    /// An API key was revoked.
    KeyRevoked,
    /// A join token was created.
    JoinTokenCreated,
    /// A `Join` consumed a join token.
    JoinTokenConsumed,
    /// An unused join token was revoked.
    JoinTokenRevoked,
    /// A node was enrolled.
    NodeEnrolled,
    /// A node was deleted.
    NodeDeleted,
    /// Failed authentications, aggregated per minute (the count is in `detail`), never one row each.
    AuthFailed,
    /// An unrestricted admin key was created offline by `p2pc-server keys recover` (§5 "Offline recovery").
    KeyRecovered,
    /// A live node joined again with a new token of its own account (§5 "Re-enrolling the same machine"): same
    /// node id, refreshed inventory, the token's project.
    NodeReenrolled,
}

/// One row of the append-only audit log, as returned by `GET /v1/audit` (§5 "Audit").
///
/// `detail` is a JSON object that **never holds a secret**: no key, token, code or env value. The server should
/// check it with [`audit_detail_has_secret`] before writing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditEvent {
    /// Event ID.
    pub id: AuditEventId,
    /// When it happened (the start of the minute, for `auth_failed`).
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub at: OffsetDateTime,
    /// What happened.
    pub kind: AuditKind,
    /// The key that acted, if any.
    #[serde(default)]
    pub actor_key_id: Option<KeyId>,
    /// The object acted on (a key, join token or node ID), as an opaque string.
    #[serde(default)]
    pub subject_id: Option<String>,
    /// Event-specific, secret-free details.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub detail: serde_json::Map<String, serde_json::Value>,
}

/// Whether an audit `detail` contains something that looks like a secret: an API key (`p2pc_sk_…`) or a join
/// token (`p2pc_join_…`), anywhere in its strings or keys, at any depth. A guard for the server, which must never
/// write such an event (§5 "No event ever contains a secret").
#[must_use]
pub fn audit_detail_has_secret(detail: &serde_json::Map<String, serde_json::Value>) -> bool {
    fn looks_secret(s: &str) -> bool {
        s.contains(crate::auth::API_KEY_PREFIX) || s.contains(crate::auth::JOIN_TOKEN_PREFIX)
    }
    fn walk(v: &serde_json::Value) -> bool {
        match v {
            serde_json::Value::String(s) => looks_secret(s),
            serde_json::Value::Array(items) => items.iter().any(walk),
            serde_json::Value::Object(map) => map.iter().any(|(k, v)| looks_secret(k) || walk(v)),
            _ => false,
        }
    }
    detail.iter().any(|(k, v)| looks_secret(k) || walk(v))
}

/// Response of `POST /v1/nodes/join-tokens`: `{id, join_token, expires_at}`, returned once. `Debug` redacts the
/// code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct JoinTokenResponse {
    /// The token's row ID, for listing and `DELETE /v1/nodes/join-tokens/{id}`.
    pub id: JoinTokenId,
    /// The token, `p2pc_join_…`. Single-use.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub join_token: JoinToken,
    /// When it expires.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub expires_at: OffsetDateTime,
}

impl JoinTokenResponse {
    /// The response for a new token: its row ID and the token, whose own expiry is the row's (the server builds the
    /// token from the row it stores).
    #[must_use]
    pub fn new(id: JoinTokenId, join_token: JoinToken) -> Self {
        Self {
            id,
            expires_at: join_token.expires_at,
            join_token,
        }
    }
}

/// Response of `GET /v1/server` (§7): how to reach this server's iroh endpoint. Nothing in it is secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ServerInfo {
    /// The server's iroh NodeId (lowercase hex).
    pub node_id: String,
    /// The relay URLs the server uses (and hands to agents in join tokens).
    pub relays: Vec<String>,
    /// The server address `p2pc_srv_…` (§10): the NodeId and the relays, for `p2pc login`.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: crate::auth::ServerAddress,
    /// The server version (semver).
    pub version: String,
}

impl ServerInfo {
    /// The info for a server `address` (its NodeId and relays come from it) and `version`.
    #[must_use]
    pub fn new(address: crate::auth::ServerAddress, version: impl Into<String>) -> Self {
        Self {
            node_id: address.server.clone(),
            relays: address.relays.iter().map(|u| u.as_str().to_string()).collect(),
            address,
            version: version.into(),
        }
    }
}

/// One row of the append-only usage ledger: one finished attempt (§11).
///
/// Build it with [`UsageRecord::new`] and set the measured fields, so a field added here does not break other crates
/// (CONTRIBUTING rule 7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UsageRecord {
    /// Job.
    pub job_id: JobId,
    /// Attempt number. Not the lease epoch: refused offers take epochs but no attempt (§6).
    pub attempt: u32,
    /// Node that ran the attempt.
    pub node_id: NodeId,
    /// Key that submitted the job.
    pub key_id: KeyId,
    /// Account.
    pub account_id: AccountId,
    /// Project.
    pub project_id: ProjectId,
    /// Start of the attempt.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub started_at: OffsetDateTime,
    /// End of the attempt.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub ended_at: OffsetDateTime,
    /// Reserved vCPU time, in vCPU-milliseconds.
    pub reserved_cpu_ms: u64,
    /// Reserved GPU time, in GPU-milliseconds.
    pub reserved_gpu_ms: u64,
    /// CPU time actually used (cgroup stats), in milliseconds.
    pub used_cpu_ms: u64,
    /// Peak resident memory in MiB.
    pub max_rss_mb: u64,
    /// Units charged, in milli-units.
    pub units: Units,
    /// `true` when the server estimated the record because the node never reported the end of the attempt (the
    /// watchdog fired, the job was cancelled on an unreachable node, or the node was lost): the reserved resources
    /// from the start (or the acceptance) to the end, with nothing measured.
    #[serde(default)]
    pub estimated: bool,
}

impl UsageRecord {
    /// A record of attempt `attempt` of `job_id` on `node_id`, for the job's key, account and project, with nothing
    /// measured yet: zero amounts, both times at the Unix epoch, not an estimate. Set the other public fields after.
    #[must_use]
    pub fn new(
        job_id: JobId,
        attempt: u32,
        node_id: NodeId,
        key_id: KeyId,
        account_id: AccountId,
        project_id: ProjectId,
    ) -> Self {
        Self {
            job_id,
            attempt,
            node_id,
            key_id,
            account_id,
            project_id,
            started_at: OffsetDateTime::UNIX_EPOCH,
            ended_at: OffsetDateTime::UNIX_EPOCH,
            reserved_cpu_ms: 0,
            reserved_gpu_ms: 0,
            used_cpu_ms: 0,
            max_rss_mb: 0,
            units: Units::ZERO,
            estimated: false,
        }
    }
}

/// How `GET /v1/usage` groups its totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum UsageGroupBy {
    /// Per job.
    Job,
    /// Per node.
    Node,
    /// Per API key.
    Key,
}

/// Totals of a set of usage records: one group of `GET /v1/usage`, or the whole range.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UsageTotals {
    /// The group: a job, node or key ID, after `group_by`. `null` for the total of the range.
    #[serde(default)]
    pub key: Option<String>,
    /// Finished attempts counted.
    pub attempts: u64,
    /// Reserved vCPU time, in vCPU-milliseconds.
    pub reserved_cpu_ms: u64,
    /// Reserved GPU time, in GPU-milliseconds.
    pub reserved_gpu_ms: u64,
    /// CPU time actually used (cgroup stats), in milliseconds.
    pub used_cpu_ms: u64,
    /// The highest peak resident memory of the attempts, in MiB.
    pub max_rss_mb: u64,
    /// Units charged, in milli-units.
    pub units: Units,
    /// How many of `attempts` are server estimates ([`UsageRecord::estimated`]).
    #[serde(default)]
    pub estimated_attempts: u64,
}

/// Response of `GET /v1/usage`: the usage ledger of the caller's project for attempts that ended in `[from, to)`,
/// grouped, with cursor pagination over the groups, and the total of the whole range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UsageReport {
    /// Start of the range (inclusive).
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub from: OffsetDateTime,
    /// End of the range (exclusive).
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub to: OffsetDateTime,
    /// How the items are grouped.
    pub group_by: UsageGroupBy,
    /// The groups of this page, ordered by `key`.
    pub items: Vec<UsageTotals>,
    /// Pass as `cursor` to get the next page. `None` on the last page.
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// The total of the whole range (every page).
    pub total: UsageTotals,
}

impl UsageReport {
    /// A report of `[from, to)` grouped by `group_by`, with no items and no next page yet. Set the other public
    /// fields after (CONTRIBUTING rule 7).
    #[must_use]
    pub fn new(from: OffsetDateTime, to: OffsetDateTime, group_by: UsageGroupBy, total: UsageTotals) -> Self {
        Self {
            from,
            to,
            group_by,
            items: Vec::new(),
            next_cursor: None,
            total,
        }
    }
}

/// A cursor-paginated list (`limit` ≤ 100).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Page<T> {
    /// The items of this page.
    pub items: Vec<T>,
    /// Pass as `cursor` to get the next page. `None` on the last page.
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Default `type` of a [`Problem`] (RFC 9457 §4.2.1).
pub const PROBLEM_TYPE_DEFAULT: &str = "about:blank";

/// An RFC 9457 `application/problem+json` error body, with a stable `code`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Problem {
    /// Problem type URI.
    #[serde(rename = "type")]
    pub type_: String,
    /// Short human summary.
    pub title: String,
    /// HTTP status code.
    pub status: u16,
    /// Human explanation of this occurrence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Stable machine-readable code, for example `unsupported_pool`.
    pub code: String,
    /// Per-field validation errors, for `422` responses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<crate::validate::FieldError>,
}

impl Problem {
    /// A problem with the default type and no detail.
    #[must_use]
    pub fn new(status: u16, code: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            type_: PROBLEM_TYPE_DEFAULT.to_string(),
            title: title.into(),
            status,
            detail: None,
            code: code.into(),
            errors: Vec::new(),
        }
    }

    /// Adds a detail message.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// The `422` for a rejected [`JobSpec`].
    ///
    /// The code is `too_large` when the job does not fit its `Lease` frame (field `job`), `unsupported_pool` when the
    /// pool is the problem (§7 names both codes), and `validation_failed` otherwise. Every field error is listed in
    /// `errors`.
    #[must_use]
    pub fn from_validation(errors: &crate::validate::ValidationErrors) -> Self {
        use crate::validate::ErrorCode;
        // §7 names two codes: `too_large` when the job does not fit its Lease frame (that check only runs when
        // every other rule passed, so it never coexists with another error), and `unsupported_pool`.
        let code = if errors.iter().any(|e| e.field == "job" && e.code == ErrorCode::TooLarge) {
            "too_large"
        } else if errors.iter().any(|e| e.code == ErrorCode::UnsupportedPool) {
            "unsupported_pool"
        } else {
            "validation_failed"
        };
        let mut p = Problem::new(422, code, "The request is invalid");
        p.errors = errors.iter().cloned().collect();
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constructors other crates use instead of struct literals (CONTRIBUTING "Shared types grow").
    #[test]
    fn join_token_response_and_server_info_constructors() {
        let token = JoinToken::generate(
            "a".repeat(64),
            vec![url::Url::parse("https://relay.example.invalid/").unwrap()],
            time::Duration::minutes(15),
            time::macros::datetime!(2026-11-05 10:00:00 UTC),
        )
        .unwrap();
        let id = JoinTokenId::generate();
        let resp = JoinTokenResponse::new(id, token.clone());
        assert_eq!((resp.id, resp.expires_at), (id, token.expires_at));
        assert_eq!(resp.join_token, token);
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["id"], json!(id.to_string()));
        assert_eq!(v["expires_at"], json!("2026-11-05T10:15:00Z"));

        let address = crate::auth::ServerAddress::new("b".repeat(64), token.relays.clone());
        let info = ServerInfo::new(address.clone(), "0.1.0");
        assert_eq!(info.node_id, "b".repeat(64));
        assert_eq!(info.relays, ["https://relay.example.invalid/"]);
        assert_eq!(info.address, address);
        assert_eq!(
            serde_json::to_value(&info).unwrap()["address"],
            json!(address.encode().unwrap())
        );
    }
    use serde_json::json;

    fn spec_json() -> serde_json::Value {
        json!({
            "name": "optional label",
            "image": "docker.io/library/python:3.12-slim",
            "command": ["python", "-c", "print(6*7)"],
            "env": {"KEY": "value"},
            "files": [{"path": "/inputs/data.csv", "content_b64": "aGk="}],
            "resources": {"cpu": 2, "memory_mb": 4096, "gpu": 0, "disk_mb": 10240},
            "timeout_s": 3600,
            "egress": {"allow": ["pypi.org", "files.pythonhosted.org"]},
            "outputs": {"max_mb": 1024},
            "placement": {"pools": ["mine"], "node_id": null, "labels": {}},
            "retry": {"max_attempts": 2},
            "idempotency_key": "optional"
        })
    }

    #[test]
    fn the_spec_example_job_spec_parses() {
        let spec: JobSpec = serde_json::from_value(spec_json()).unwrap();
        assert_eq!(spec.image, "docker.io/library/python:3.12-slim");
        assert_eq!(spec.resources.cpu, 2.0);
        assert_eq!(spec.resources.memory_mb, 4096);
        assert_eq!(spec.env["KEY"], "value");
        assert_eq!(spec.placement.pools, ["mine"]);
        assert_eq!(spec.idempotency_key.as_deref(), Some("optional"));
        // Round trip keeps every field name and value.
        let back = serde_json::to_value(&spec).unwrap();
        let keys = |v: &serde_json::Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
        assert_eq!(keys(&back), keys(&spec_json()));
        assert_eq!(serde_json::from_value::<JobSpec>(back).unwrap(), spec);
    }

    #[test]
    fn job_spec_defaults_match_the_spec() {
        let spec: JobSpec = serde_json::from_value(json!({
            "image": "python:3.12",
            "command": ["true"],
            "resources": {"cpu": 0.5, "memory_mb": 256}
        }))
        .unwrap();
        assert_eq!(spec.resources.gpu, 0);
        assert_eq!(spec.resources.disk_mb, 2_048);
        assert_eq!(DEFAULT_DISK_MB, 2_048);
        assert_eq!(spec.timeout_s, 3_600);
        assert_eq!(spec.retry.max_attempts, 2);
        assert_eq!(spec.placement.pools, ["mine"]);
        assert!(spec.egress.allow.is_empty());
        assert!(spec.env.is_empty() && spec.files.is_empty());
        assert_eq!(spec.outputs.max_mb, DEFAULT_OUTPUTS_MAX_MB);
    }

    /// The response form of the §7 example spec, as the server would send it.
    fn view_json() -> serde_json::Value {
        let spec: JobSpec = serde_json::from_value(spec_json()).unwrap();
        serde_json::to_value(JobSpecView::from_stored(&spec).unwrap()).unwrap()
    }

    /// Spec §6: the CLI and SDK ignore unknown fields in REST responses.
    #[test]
    fn rest_responses_ignore_unknown_fields() {
        let at = "2026-11-05T10:00:00Z";
        let job = json!({
            "id": "job_01ARZ3NDEKTSV4RRFFQ69G5FAV", "project_id": "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "status": "running", "attempt": 1, "spec": view_json(), "estimated_units": 2000, "created_at": at,
            "queue_position": 3
        });
        let job: Job = serde_json::from_value(job).unwrap();
        assert_eq!(job.status, JobStatus::Running);

        let inventory = json!({
            "hostname": "node-1", "platform": "linux", "gpu_status": {"status": "ok", "temp_c": 40},
            "cpu": {"model": "Example CPU", "cores": 8, "flags": []},
            "memory_mb": 1024, "os": "linux", "arch": "x86_64",
            "gpus": [{"uuid": "GPU-1", "index": 0, "name": "g", "driver_version": "1", "vram_mb": 1, "fan": 3}],
            "sandbox": [{"driver": "podman", "class": "container", "runtimes": ["crun"], "version": "5"}],
            "offered": {"cpu": 4.0, "memory_mb": 512, "gpu": 0, "disk_mb": 9},
            "agent_version": "0.2.0", "kernel": "6.1"
        });
        let node = json!({
            "id": "node_01ARZ3NDEKTSV4RRFFQ69G5FAV", "name": "node-1", "hostname": "node-1",
            "state": "online", "draining": false, "inventory": inventory,
            "free": {"cpu": 1.0, "memory_mb": 1, "gpu": 0}, "created_at": at, "region": "home"
        });
        let node: Node = serde_json::from_value(node).unwrap();
        assert_eq!(node.inventory.offered.cpu, 4.0);

        let key = json!({"id": "abcdefgh2345", "project_id": "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV", "scopes": ["admin"],
            "created_at": at, "expires_at": null});
        assert!(serde_json::from_value::<ApiKeyInfo>(key).is_ok());
        let est = json!({"feasible": true, "matching_nodes": 1, "would_queue": false, "units_per_hour": 1000,
            "eta_s": 4});
        assert!(serde_json::from_value::<Estimate>(est).is_ok());
        let p = json!({"type": "about:blank", "title": "t", "status": 404, "code": "not_found", "instance": "/x"});
        assert!(serde_json::from_value::<Problem>(p).is_ok());
        let page = json!({"items": [], "next_cursor": null, "total": 0});
        assert!(serde_json::from_value::<Page<Job>>(page).is_ok());
        let out = json!({"path": "a", "size": 1, "sha256": "00".repeat(32), "mode": 420});
        assert!(serde_json::from_value::<OutputFile>(out).is_ok());
    }

    /// Review P2: a newer server may add `JobSpec` fields; older CLIs must still read `Job` and `Page<Job>`.
    #[test]
    fn job_spec_inside_responses_tolerates_unknown_fields() {
        let mut spec = view_json();
        spec["future_field"] = json!({"x": 1});
        spec["resources"]["future_field"] = json!(2);
        spec["files"][0]["future_field"] = json!(3);
        spec["egress"]["future_field"] = json!(4);
        spec["outputs"]["future_field"] = json!(5);
        spec["placement"]["future_field"] = json!(6);
        spec["retry"]["future_field"] = json!(7);
        let job = json!({
            "id": "job_01ARZ3NDEKTSV4RRFFQ69G5FAV", "project_id": "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "status": "queued", "attempt": 0, "spec": spec, "estimated_units": 2000,
            "created_at": "2026-11-05T10:00:00Z"
        });
        let parsed: Job = serde_json::from_value(job.clone()).unwrap();
        assert_eq!(parsed.spec.image, "docker.io/library/python:3.12-slim");
        assert_eq!(parsed.spec.resources.memory_mb, 4096);
        let page: Page<Job> = serde_json::from_value(json!({"items": [job], "next_cursor": null})).unwrap();
        assert_eq!(page.items.len(), 1);
        // The request form with future fields is refused as a request body.
        let mut req = spec_json();
        req["future_field"] = json!(1);
        assert!(serde_json::from_value::<JobSpec>(req).is_err());
    }

    /// Review P3: the server computes file metadata once, at submission, and builds every response from it.
    #[test]
    fn job_view_from_precomputed_file_metadata() {
        let mut spec: JobSpec = serde_json::from_value(spec_json()).unwrap();
        spec.files.push(InputFile {
            path: "/inputs/b.bin".into(),
            content_b64: "AAEC".into(),
        });
        let meta: Vec<FileMeta> = FileMeta::compute_all(&spec).unwrap();
        assert_eq!(
            meta[0],
            FileMeta {
                path: "/inputs/data.csv".into(),
                size: 2,
                sha256: Sha256Digest(Sha256::digest(b"hi").into())
            }
        );
        assert_eq!(meta[1].size, 3);
        let view = JobSpecView::from_stored_with_meta(&spec, &meta).unwrap();
        assert_eq!(view, JobSpecView::from_stored(&spec).unwrap());
        assert_eq!(view.files, meta);
        // The precomputed path never touches the content: even unreadable stored content works if the metadata
        // was computed when the job was accepted.
        let mut stored = spec.clone();
        stored.files[1].content_b64 = "not base64 any more".into();
        assert_eq!(JobSpecView::from_stored_with_meta(&stored, &meta).unwrap(), view);
        // Metadata that does not describe the spec's files is refused.
        assert_eq!(
            JobSpecView::from_stored_with_meta(&spec, &meta[..1]),
            Err(FileMetaMismatch)
        );
        let mut swapped = meta.clone();
        swapped.swap(0, 1);
        assert_eq!(
            JobSpecView::from_stored_with_meta(&spec, &swapped),
            Err(FileMetaMismatch)
        );
    }

    /// Spec §7 "Job representation in responses": no env value and no file content ever comes out.
    #[test]
    fn job_responses_never_return_env_values_or_file_contents() {
        let secrets = [
            "hunter2-env-secret",
            "-----BEGIN KEY----- abc",
            "p2pc_sk_abcdefgh2345_zzzz",
        ];
        let contents: [&[u8]; 3] = [b"file-secret-one", b"", b"\x00\x01binary-secret\xff"];
        let mut spec: JobSpec = serde_json::from_value(spec_json()).unwrap();
        for (i, s) in secrets.iter().enumerate() {
            spec.env.insert(format!("SECRET_{i}"), (*s).to_string());
        }
        spec.files = contents
            .iter()
            .enumerate()
            .map(|(i, c)| InputFile {
                path: format!("/inputs/f{i}"),
                content_b64: data_encoding::BASE64.encode(c),
            })
            .collect();
        let view = JobSpecView::from_stored(&spec).unwrap();

        // Env names stay, every value is the marker.
        assert_eq!(view.env.len(), spec.env.len());
        assert!(view.env.values().all(|v| v == REDACTED));
        assert!(view.env.contains_key("SECRET_0") && view.env.contains_key("KEY"));
        // Files are {path, size, sha256} of the decoded content.
        for (file, content) in view.files.iter().zip(contents) {
            assert_eq!(file.size, content.len() as u64);
            assert_eq!(file.sha256, Sha256Digest(Sha256::digest(content).into()));
        }
        assert_eq!(view.files[0].path, "/inputs/f0");

        // Nothing secret anywhere: not in the JSON of a `Job`, not in `Debug`.
        let job = Job {
            id: "job_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            project_id: "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            name: None,
            status: JobStatus::Queued,
            attempt: 0,
            spec: view.clone(),
            node_id: None,
            reason: None,
            cancel_requested_at: None,
            exit_code: None,
            error: None,
            estimated_units: Units::ZERO,
            created_at: time::macros::datetime!(2026-11-05 10:00:00 UTC),
            started_at: None,
            finished_at: None,
            attempts: None,
        };
        let out = format!("{} {:?}", serde_json::to_string(&job).unwrap(), job);
        for s in secrets.iter().copied().chain(["value"]) {
            assert!(!out.contains(s), "{s:?} leaked: {out}");
        }
        for f in &spec.files {
            if !f.content_b64.is_empty() {
                assert!(!out.contains(&f.content_b64), "content leaked: {out}");
            }
        }
        assert!(!out.contains("content_b64"), "{out}");
        // A malformed stored file is an error, never invented metadata.
        spec.files[0].content_b64 = "!!!!".into();
        assert!(JobSpecView::from_stored(&spec).is_err());
    }

    /// Spec §5 (9c5b740): key metadata uses `label`, `expires_at`, `last_used_at` and `revoked_at`; the create
    /// response is flat (metadata plus `key`).
    #[test]
    fn key_shapes_follow_section_5() {
        let req: CreateApiKey = serde_json::from_value(json!({
            "label": "ci", "scopes": ["jobs:write"], "expires_at": "2027-01-01T00:00:00Z", "daily_unit_cap": 5000
        }))
        .unwrap();
        assert_eq!(req.label.as_deref(), Some("ci"));
        assert_eq!(req.expires_at, Some(time::macros::datetime!(2027-01-01 00:00:00 UTC)));
        // `name` was renamed to `label`; the request type is strict, so the old name is an error.
        assert!(serde_json::from_value::<CreateApiKey>(json!({"name": "ci", "scopes": ["admin"]})).is_err());

        let key = ApiKey::generate();
        let info = ApiKeyInfo {
            id: key.key_id(),
            project_id: "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            label: Some("ci".into()),
            scopes: vec![Scope::JobsWrite],
            daily_unit_cap: Some(Units::from_units(5)),
            allowed_images: None,
            created_at: time::macros::datetime!(2026-11-05 10:00:00 UTC),
            expires_at: Some(time::macros::datetime!(2027-01-01 00:00:00 UTC)),
            last_used_at: None,
            revoked_at: None,
        };
        let v = serde_json::to_value(&info).unwrap();
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "allowed_images",
                "created_at",
                "daily_unit_cap",
                "expires_at",
                "id",
                "label",
                "last_used_at",
                "project_id",
                "revoked_at",
                "scopes"
            ]
        );
        assert_eq!(serde_json::from_value::<ApiKeyInfo>(v).unwrap(), info);

        // Flat create response: every metadata field at the top level, plus `key`.
        let new = NewApiKey {
            key: key.clone(),
            info: info.clone(),
        };
        let v = serde_json::to_value(&new).unwrap();
        assert_eq!(v["key"], json!(key.expose()));
        assert_eq!(v["id"], json!(key.key_id().to_string()));
        assert_eq!(v["label"], json!("ci"));
        assert_eq!(v["expires_at"], json!("2027-01-01T00:00:00Z"));
        assert!(v.get("info").is_none(), "{v}");
        assert_eq!(serde_json::from_value::<NewApiKey>(v).unwrap(), new);
    }

    fn keys_of(v: &serde_json::Value) -> Vec<String> {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    }

    /// Spec §7 `GET /v1/whoami`:
    /// `{account_id, project_id, key_id, scopes, label, daily_unit_cap, allowed_images, expires_at}`.
    #[test]
    fn whoami_shape() {
        let w = WhoAmI {
            account_id: "acc_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            project_id: "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            key_id: "abcdefgh2345".parse().unwrap(),
            scopes: vec![Scope::JobsRead],
            label: Some("agent".to_string()),
            daily_unit_cap: Some(Units::from_units(5)),
            allowed_images: Some(vec!["docker.io/library/*".to_string()]),
            expires_at: Some(time::macros::datetime!(2027-01-01 00:00:00 UTC)),
        };
        let v = serde_json::to_value(&w).unwrap();
        assert_eq!(
            keys_of(&v),
            [
                "account_id",
                "allowed_images",
                "daily_unit_cap",
                "expires_at",
                "key_id",
                "label",
                "project_id",
                "scopes"
            ]
        );
        assert_eq!(v["daily_unit_cap"], 5000);
        assert_eq!(v["expires_at"], "2027-01-01T00:00:00Z");
        assert_eq!(serde_json::from_value::<WhoAmI>(v).unwrap(), w);
        // An uncapped, unrestricted key says so with explicit nulls.
        let open = WhoAmI {
            label: None,
            daily_unit_cap: None,
            allowed_images: None,
            expires_at: None,
            ..w
        };
        let v = serde_json::to_value(&open).unwrap();
        for k in ["label", "daily_unit_cap", "allowed_images", "expires_at"] {
            assert!(v[k].is_null(), "{k}: {v}");
        }
    }

    /// Additive (§6 compatibility): the first shape, with only the four original fields, still parses, and the new
    /// fields default to `null`.
    #[test]
    fn whoami_without_the_limit_fields_still_parses() {
        let old = json!({
            "account_id": "acc_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "project_id": "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "key_id": "abcdefgh2345",
            "scopes": ["jobs:read"],
        });
        let w: WhoAmI = serde_json::from_value(old).unwrap();
        assert_eq!(w.daily_unit_cap, None);
        assert_eq!(w.allowed_images, None);
        assert_eq!(w.label, None);
        assert_eq!(w.expires_at, None);
    }

    /// §7 (c47c0a5): idempotency keys are scoped to the API key that sent them, and **responses never include
    /// them**. The request type has the field; the response view does not, whatever the stored spec holds.
    #[test]
    fn a_response_never_carries_the_idempotency_key() {
        let mut spec: JobSpec = serde_json::from_value(spec_json()).unwrap();
        spec.idempotency_key = Some("k-3f9a77c1".to_string());
        let view = JobSpecView::from_stored(&spec).unwrap();
        let v = serde_json::to_value(&view).unwrap();
        assert!(v.get("idempotency_key").is_none(), "{v}");
        let job = Job {
            id: "job_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            project_id: "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            name: None,
            status: JobStatus::Queued,
            attempt: 1,
            spec: view,
            node_id: None,
            reason: None,
            cancel_requested_at: None,
            exit_code: None,
            error: None,
            estimated_units: Units::ZERO,
            created_at: time::macros::datetime!(2026-11-05 10:00:00 UTC),
            started_at: None,
            finished_at: None,
            attempts: None,
        };
        let text = serde_json::to_string(&job).unwrap();
        assert!(!text.contains("idempotency"), "{text}");
        assert!(!text.contains("k-3f9a77c1"), "{text}");
        // An older server's response that did carry it still parses (unknown fields are ignored), and the value is
        // dropped, not kept.
        let mut with_key = serde_json::to_value(&job).unwrap();
        with_key["spec"]["idempotency_key"] = json!("leaked");
        let parsed: Job = serde_json::from_value(with_key).unwrap();
        assert!(!serde_json::to_string(&parsed).unwrap().contains("leaked"));
        // The request type keeps the field, and its Debug still shows it (it is not a secret to its sender).
        assert!(format!("{spec:?}").contains("idempotency_key"));
        assert!(!format!("{:?}", job.spec).contains("idempotency"));
    }

    /// `reason` and `cancel_requested_at` are additive on `Job`: a job without them (an older server) parses.
    #[test]
    fn job_reason_and_cancel_requested_at_are_additive() {
        let spec = JobSpecView::from_stored(&serde_json::from_value::<JobSpec>(spec_json()).unwrap()).unwrap();
        let job = Job {
            id: "job_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            project_id: "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            name: None,
            status: JobStatus::Queued,
            attempt: 1,
            spec,
            node_id: None,
            reason: Some("no node has a free GPU".to_string()),
            cancel_requested_at: Some(time::macros::datetime!(2026-11-05 10:00:01 UTC)),
            exit_code: None,
            error: None,
            estimated_units: Units::ZERO,
            created_at: time::macros::datetime!(2026-11-05 10:00:00 UTC),
            started_at: None,
            finished_at: None,
            attempts: None,
        };
        let mut v = serde_json::to_value(&job).unwrap();
        assert_eq!(v["reason"], "no node has a free GPU");
        assert_eq!(v["cancel_requested_at"], "2026-11-05T10:00:01Z");
        assert_eq!(serde_json::from_value::<Job>(v.clone()).unwrap(), job);
        let obj = v.as_object_mut().unwrap();
        obj.remove("reason");
        obj.remove("cancel_requested_at");
        let old: Job = serde_json::from_value(v).unwrap();
        assert_eq!((old.reason, old.cancel_requested_at), (None, None));
    }

    /// Spec §7 `GET /healthz`: liveness only, `{"status":"ok"}`.
    #[test]
    fn health_shape() {
        let v = serde_json::to_value(Health::ok()).unwrap();
        assert_eq!(v, json!({"status": "ok"}));
        assert_eq!(serde_json::from_value::<Health>(v).unwrap(), Health::ok());
    }

    /// Spec §5 "Audit": a closed kind for each recorded event, and a detail object that never holds a secret.
    #[test]
    fn audit_event_shape_and_kinds() {
        let names = [
            (AuditKind::KeyCreated, "key_created"),
            (AuditKind::KeyRevoked, "key_revoked"),
            (AuditKind::JoinTokenCreated, "join_token_created"),
            (AuditKind::JoinTokenConsumed, "join_token_consumed"),
            (AuditKind::JoinTokenRevoked, "join_token_revoked"),
            (AuditKind::NodeEnrolled, "node_enrolled"),
            (AuditKind::NodeDeleted, "node_deleted"),
            (AuditKind::AuthFailed, "auth_failed"),
            (AuditKind::KeyRecovered, "key_recovered"),
            (AuditKind::NodeReenrolled, "node_reenrolled"),
        ];
        for (kind, name) in names {
            assert_eq!(serde_json::to_value(kind).unwrap(), json!(name));
            assert_eq!(serde_json::from_value::<AuditKind>(json!(name)).unwrap(), kind);
        }
        assert!(serde_json::from_value::<AuditKind>(json!("key_rotated")).is_err());
        let e = AuditEvent {
            id: "aud_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            at: time::macros::datetime!(2026-11-05 10:00:00 UTC),
            kind: AuditKind::AuthFailed,
            actor_key_id: None,
            subject_id: None,
            detail: json!({"count": 12, "minute": "2026-11-05T10:00:00Z"})
                .as_object()
                .unwrap()
                .clone(),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(
            keys_of(&v),
            ["actor_key_id", "at", "detail", "id", "kind", "subject_id"]
        );
        assert_eq!(serde_json::from_value::<AuditEvent>(v).unwrap(), e);
        assert!(!audit_detail_has_secret(&e.detail));
        // A detail must be an object.
        let mut bad = serde_json::to_value(&e).unwrap();
        bad["detail"] = json!("text");
        assert!(serde_json::from_value::<AuditEvent>(bad).is_err());
        // The helper the server asserts with before writing an event.
        let key = ApiKey::generate().expose();
        for leaky in [
            json!({"key": key}),
            json!({"nested": {"list": [1, {"token": "p2pc_join_abcdef"}]}}), // gitleaks:allow
            json!({"note": format!("got {key} from a header")}),
        ] {
            assert!(audit_detail_has_secret(leaky.as_object().unwrap()), "{leaky}");
        }
        assert!(!audit_detail_has_secret(
            json!({"key_id": "abcdefgh2345"}).as_object().unwrap()
        ));
    }

    /// Spec §5 "Listing and revoking": the token list never contains the code.
    #[test]
    fn join_token_info_and_create_shapes() {
        let info = JoinTokenInfo {
            id: "jtk_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            label: Some("laptop".into()),
            created_by_key_id: "abcdefgh2345".parse().unwrap(),
            created_at: time::macros::datetime!(2026-11-05 10:00:00 UTC),
            expires_at: time::macros::datetime!(2026-11-05 10:15:00 UTC),
            consumed_at: None,
            consumed_by_node_id: None,
            revoked_at: None,
        };
        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(
            keys_of(&v),
            [
                "consumed_at",
                "consumed_by_node_id",
                "created_at",
                "created_by_key_id",
                "expires_at",
                "id",
                "label",
                "revoked_at"
            ]
        );
        assert_eq!(serde_json::from_value::<JoinTokenInfo>(v).unwrap(), info);
        let req: CreateJoinToken = serde_json::from_value(json!({"label": "laptop", "ttl_s": 600})).unwrap();
        assert_eq!((req.label.as_deref(), req.ttl_s), (Some("laptop"), Some(600)));
        assert_eq!(
            serde_json::from_value::<CreateJoinToken>(json!({})).unwrap(),
            CreateJoinToken::default()
        );
        assert!(serde_json::from_value::<CreateJoinToken>(json!({"name": "x"})).is_err());
    }

    /// Spec §5 "Names": the server derives `name`; the reported `hostname` is shown too.
    #[test]
    fn node_has_name_and_hostname() {
        let node = json!({
            "id": "node_01ARZ3NDEKTSV4RRFFQ69G5FAV", "name": "desktop-1", "hostname": "DESKTOP",
            "state": "online", "draining": false,
            "inventory": serde_json::to_value(crate::protocol::tests::inventory()).unwrap(),
            "free": {"cpu": 1.0, "memory_mb": 1, "gpu": 0}, "created_at": "2026-11-05T10:00:00Z"
        });
        let parsed: Node = serde_json::from_value(node.clone()).unwrap();
        assert_eq!(
            (parsed.name.as_str(), parsed.hostname.as_str()),
            ("desktop-1", "DESKTOP")
        );
        for field in ["name", "hostname"] {
            let mut missing = node.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Node>(missing).is_err(), "{field}");
        }
    }

    /// §7: `attempts` is left out of a job unless set (lists), and an attempt uses the job-state words.
    #[test]
    fn job_attempts_are_optional_and_use_job_state_words() {
        let node: NodeId = "node_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap();
        let spec = JobSpecView::from_stored(
            &serde_json::from_value::<JobSpec>(serde_json::json!({
                "image": "docker.io/library/alpine:3", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 256}
            }))
            .unwrap(),
        )
        .unwrap();
        let t = time::macros::datetime!(2026-11-06 10:00:00 UTC);
        let mut job = Job::new(
            JobId::generate(),
            ProjectId::generate(),
            JobStatus::Running,
            1,
            spec,
            Units::ZERO,
            t,
        );
        let v = serde_json::to_value(&job).unwrap();
        assert!(v.get("attempts").is_none(), "absent unless set: {v}");
        let mut a = JobAttempt::new(1, node);
        a.started_at = Some(t);
        job.attempts = Some(vec![a.clone()]);
        let v = serde_json::to_value(&job).unwrap();
        assert_eq!(
            v["attempts"],
            serde_json::json!([{"attempt": 1, "node_id": node.to_string(), "outcome": "running", "reason": null,
                "started_at": "2026-11-06T10:00:00Z", "ended_at": null}])
        );
        assert_eq!(serde_json::from_value::<Job>(v).unwrap(), job);
        a.outcome = JobStatus::Lost;
        a.reason = Some("node_lost".into());
        assert_eq!(serde_json::to_value(&a).unwrap()["outcome"], "lost");
    }

    /// Spec §11: the ledger's time columns are milliseconds, with these exact names.
    #[test]
    fn usage_record_uses_millisecond_names() {
        let rec = UsageRecord {
            job_id: "job_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            attempt: 1,
            node_id: "node_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            key_id: "abcdefgh2345".parse().unwrap(),
            account_id: "acc_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            project_id: "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            started_at: time::macros::datetime!(2026-11-05 10:00:00 UTC),
            ended_at: time::macros::datetime!(2026-11-05 11:00:00 UTC),
            reserved_cpu_ms: 7_200_000,
            reserved_gpu_ms: 0,
            used_cpu_ms: 3_600_000,
            max_rss_mb: 512,
            units: Units::from_units(2),
            estimated: false,
        };
        let v = serde_json::to_value(&rec).unwrap();
        for field in ["reserved_cpu_ms", "reserved_gpu_ms", "used_cpu_ms"] {
            assert!(v.get(field).is_some_and(serde_json::Value::is_u64), "{field}");
        }
        assert_eq!(serde_json::from_value::<UsageRecord>(v.clone()).unwrap(), rec);
        // `estimated` is additive: a record without it is a measured one.
        let mut old = v;
        old.as_object_mut().unwrap().remove("estimated");
        assert_eq!(serde_json::from_value::<UsageRecord>(old).unwrap(), rec);
        // The constructor fills nothing but the identity.
        let new = UsageRecord::new(rec.job_id, 1, rec.node_id, rec.key_id, rec.account_id, rec.project_id);
        assert_eq!((new.units, new.estimated, new.reserved_cpu_ms), (Units::ZERO, false, 0));
    }

    /// REST request bodies keep rejecting unknown fields, which catches typos (spec §6).
    #[test]
    fn rest_requests_reject_unknown_fields() {
        assert!(serde_json::from_value::<CreateApiKey>(json!({"scopes": ["admin"]})).is_ok());
        assert!(serde_json::from_value::<CreateApiKey>(json!({"scopes": ["admin"], "scope": "admin"})).is_err());
        assert!(serde_json::from_value::<CreateJoinToken>(json!({"ttl_s": 60})).is_ok());
        assert!(serde_json::from_value::<CreateJoinToken>(json!({"ttl": 60})).is_err());
        let mut v = spec_json();
        v["retry"]["max_attempt"] = json!(3);
        assert!(serde_json::from_value::<JobSpec>(v).is_err());
        let mut v = spec_json();
        v["files"][0]["mode"] = json!(420);
        assert!(serde_json::from_value::<JobSpec>(v).is_err());
    }

    #[test]
    fn job_spec_rejects_unknown_and_missing_fields() {
        let mut v = spec_json();
        v["memroy_mb"] = json!(1);
        assert!(serde_json::from_value::<JobSpec>(v).is_err());
        let mut v = spec_json();
        v["resources"]["ram"] = json!(1);
        assert!(serde_json::from_value::<JobSpec>(v).is_err());
        for field in ["image", "command", "resources"] {
            let mut v = spec_json();
            v.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<JobSpec>(v).is_err(), "{field}");
        }
        let mut v = spec_json();
        v["resources"].as_object_mut().unwrap().remove("memory_mb");
        assert!(serde_json::from_value::<JobSpec>(v).is_err());
    }

    #[test]
    fn job_spec_debug_redacts_env_values_and_file_contents() {
        let mut spec: JobSpec = serde_json::from_value(spec_json()).unwrap();
        spec.env.insert("DB_PASSWORD".into(), "hunter2-very-secret".into());
        spec.files[0].content_b64 = "c2VjcmV0LWZpbGUtY29udGVudA==".into();
        let dbg = format!("{spec:?}");
        assert!(dbg.contains("DB_PASSWORD"));
        assert!(!dbg.contains("hunter2-very-secret"), "{dbg}");
        assert!(!dbg.contains("c2VjcmV0LWZpbGUtY29udGVudA=="), "{dbg}");
        assert!(!dbg.contains("\"value\""), "{dbg}");
        assert!(dbg.contains("/inputs/data.csv"));
    }

    #[test]
    fn terminal_states() {
        use JobStatus::*;
        let terminal: Vec<_> = JobStatus::ALL.into_iter().filter(|s| s.is_terminal()).collect();
        assert_eq!(terminal, [Succeeded, Failed, TimedOut, Cancelled, Lost]);
    }

    #[test]
    fn state_machine_exhaustive() {
        use JobStatus::*;
        // Every (from, to) pair that is allowed. Everything else must be refused.
        let allowed = [
            (Queued, Assigned),
            (Queued, Cancelled),
            (Assigned, Running),
            (Assigned, Queued),
            (Assigned, Lost),
            (Assigned, Failed),
            (Assigned, Cancelled),
            // Spec §7/§8 (75d69de): the server watchdog's backstop for an agent that hangs before `JobStarted`.
            (Assigned, TimedOut),
            (Running, Succeeded),
            (Running, Failed),
            (Running, TimedOut),
            (Running, Cancelled),
            (Running, Lost),
            (Running, Queued),
        ];
        let mut count = 0;
        for from in JobStatus::ALL {
            for to in JobStatus::ALL {
                let expected = allowed.contains(&(from, to));
                assert_eq!(transition_allowed(from, to), expected, "{from} -> {to}");
                count += 1;
            }
        }
        assert_eq!(count, 64);
    }

    #[test]
    fn terminal_states_are_immutable_and_self_loops_are_not_transitions() {
        for from in JobStatus::ALL {
            assert!(!transition_allowed(from, from), "{from}");
            if from.is_terminal() {
                for to in JobStatus::ALL {
                    assert!(!transition_allowed(from, to), "{from} -> {to}");
                }
            }
        }
    }

    #[test]
    fn every_non_terminal_state_can_be_cancelled_and_nothing_returns_to_queued_from_terminal() {
        for s in JobStatus::ALL.into_iter().filter(|s| !s.is_terminal()) {
            assert!(transition_allowed(s, JobStatus::Cancelled), "{s}");
        }
        // A queued job is never placed with an expiry, so it cannot time out or be lost.
        assert!(!transition_allowed(JobStatus::Queued, JobStatus::TimedOut));
        assert!(!transition_allowed(JobStatus::Queued, JobStatus::Lost));
        assert!(!transition_allowed(JobStatus::Queued, JobStatus::Running));
    }

    #[test]
    fn job_status_wire_names() {
        for s in JobStatus::ALL {
            assert_eq!(serde_json::to_string(&s).unwrap(), format!("\"{}\"", s.as_str()));
        }
        assert_eq!(serde_json::to_string(&JobStatus::TimedOut).unwrap(), "\"timed_out\"");
        assert!(serde_json::from_str::<JobStatus>("\"Timed_Out\"").is_err());
    }

    #[test]
    fn scopes_use_the_spec_names() {
        let v = serde_json::to_value([
            Scope::Admin,
            Scope::JobsWrite,
            Scope::JobsRead,
            Scope::NodesRead,
            Scope::NodesWrite,
        ])
        .unwrap();
        assert_eq!(
            v,
            json!(["admin", "jobs:write", "jobs:read", "nodes:read", "nodes:write"])
        );
    }

    #[test]
    fn sha256_digest_is_lowercase_hex() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let d: Sha256Digest = hex.parse().unwrap();
        assert_eq!(d.to_string(), hex);
        assert_eq!(serde_json::to_string(&d).unwrap(), format!("\"{hex}\""));
        assert!(hex.to_uppercase().parse::<Sha256Digest>().is_err());
        assert!(hex[..62].parse::<Sha256Digest>().is_err());
        assert!(format!("{hex}00").parse::<Sha256Digest>().is_err());
        assert!(format!("{}zz", &hex[..62]).parse::<Sha256Digest>().is_err());
    }

    #[test]
    fn problem_shape_is_rfc9457() {
        let p = Problem::new(404, "not_found", "Not found").with_detail("no such job");
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(
            v,
            json!({"type": "about:blank", "title": "Not found", "status": 404, "detail": "no such job", "code": "not_found"})
        );
        assert_eq!(serde_json::from_value::<Problem>(v).unwrap(), p);
    }

    #[test]
    fn page_shape() {
        let p = Page {
            items: vec![1, 2],
            next_cursor: Some("abc".into()),
        };
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            json!({"items": [1, 2], "next_cursor": "abc"})
        );
    }

    #[test]
    fn an_output_entry_reads_as_an_output_file_and_says_whether_it_expired() {
        let file = OutputFile {
            path: "results/a.csv".into(),
            size: 3,
            sha256: Sha256Digest([7; 32]),
        };
        let entry = OutputEntry::new(file.clone());
        let v = serde_json::to_value(&entry).unwrap();
        assert_eq!(v["expired"], false);
        assert_eq!(v["path"], "results/a.csv");
        // A client that only knows `OutputFile` ignores `expired`.
        assert_eq!(serde_json::from_value::<OutputFile>(v).unwrap(), file);
        assert_eq!(entry.file(), file);
        // `expired` defaults to false when absent.
        let back: OutputEntry = serde_json::from_value(serde_json::to_value(&file).unwrap()).unwrap();
        assert!(!back.expired);
        assert_eq!(MAX_LOG_BYTES_PER_ATTEMPT, 64 << 20);
        assert!(!LOG_TRUNCATED_MESSAGE.chars().any(char::is_control));
    }

    /// Runs with `--features openapi` (CI's clippy builds it with `--all-features`).
    #[cfg(feature = "openapi")]
    #[test]
    fn every_api_type_has_an_openapi_schema() {
        use utoipa::OpenApi;

        #[derive(OpenApi)]
        #[openapi(components(schemas(
            JobSpec,
            JobSpecView,
            Job,
            JobStatus,
            LogLine,
            OutputFile,
            OutputEntry,
            Node,
            Inventory,
            Estimate,
            Scope,
            CreateApiKey,
            ApiKeyInfo,
            NewApiKey,
            CreateJoinToken,
            JoinTokenResponse,
            UsageRecord,
            UsageGroupBy,
            Problem,
            Page<Job>,
            WhoAmI,
            Health,
            AuditEvent,
            AuditKind,
            JoinTokenInfo,
            ServerInfo,
        )))]
        struct Doc;

        let doc = serde_json::to_value(Doc::openapi()).unwrap();
        let schemas = &doc["components"]["schemas"];
        for name in [
            "JobSpec",
            "Job",
            "JobStatus",
            "LogLine",
            "OutputFile",
            "OutputEntry",
            "Node",
            "Inventory",
            "Estimate",
            "ApiKeyInfo",
            "NewApiKey",
            "JoinTokenResponse",
            "UsageRecord",
            "WhoAmI",
            "Health",
            "AuditEvent",
            "AuditKind",
            "JoinTokenInfo",
            "ServerInfo",
            "GpuInfo",
            "GpuStatus",
            "Wsl2Health",
            "Problem",
        ] {
            assert!(schemas.get(name).is_some(), "missing schema {name}");
        }
        for schema in ["JobSpec", "JobSpecView"] {
            let spec = &schemas[schema]["properties"];
            for field in [
                "image",
                "command",
                "env",
                "files",
                "resources",
                "timeout_s",
                "egress",
                "placement",
                "retry",
            ] {
                assert!(spec.get(field).is_some(), "{schema}.{field}");
            }
        }
        // The request type is closed, the response type is open, and `Job.spec` uses the response type.
        assert_eq!(schemas["JobSpec"]["additionalProperties"], json!(false));
        assert_ne!(schemas["JobSpecView"]["additionalProperties"], json!(false));
        assert_eq!(schemas["Resources"]["additionalProperties"], json!(false));
        assert_ne!(schemas["ResourcesView"]["additionalProperties"], json!(false));
        assert_eq!(
            schemas["Job"]["properties"]["spec"]["$ref"],
            json!("#/components/schemas/JobSpecView")
        );
        // Response files carry metadata only; request files carry the content.
        let view_file = &schemas["InputFileView"]["properties"];
        assert!(view_file.get("size").is_some() && view_file.get("sha256").is_some());
        assert!(view_file.get("content_b64").is_none());
        assert!(schemas["InputFile"]["properties"].get("content_b64").is_some());
        // The flat key-create response exposes `key` next to the metadata.
        assert!(
            serde_json::to_string(&schemas["NewApiKey"])
                .unwrap()
                .contains("\"key\"")
        );
        assert!(schemas["Problem"]["properties"].get("type").is_some());
    }
}
