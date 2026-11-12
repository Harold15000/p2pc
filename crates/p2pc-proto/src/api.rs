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
//!
//! **H2 additions** (H2 spec §5, §7, §12) are all additive: every new field of an H1 type is optional on input and
//! is left out of the output while it has its H1 value, so an H1 peer reads and writes exactly the H1 bytes (pinned
//! by the `h1_wire_fixtures_are_byte_identical` test). The H1 types keep their field types, with two exceptions that
//! the principal change needs (H2 §5.5, T2-10): `WhoAmI.key_id` and `JoinTokenInfo.created_by_key_id` are `Option`,
//! `null` when the principal is a device. For an API key they serialize exactly as in H1. `UsageRecord.key_id` changes
//! with the ledger (T2-16).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::auth::{ApiKey, JoinToken};
use crate::ids::{
    AccountId, AuditEventId, DeviceId, JobId, JoinRequestId, JoinTokenId, KeyId, NodeId, PairingTicketId, ProjectId,
};
use crate::units::Units;

/// Default `resources.disk_mb` (§7).
pub const DEFAULT_DISK_MB: u64 = 2_048;
/// Default `timeout_s` of a batch job (§7).
pub const DEFAULT_TIMEOUT_S: u32 = 3_600;
/// Default `retry.max_attempts` of a batch job (§7).
pub const DEFAULT_MAX_ATTEMPTS: u32 = 2;
/// Default, and largest, `timeout_s` of a service: 30 days (H2 §7.1).
pub const DEFAULT_SERVICE_TIMEOUT_S: u32 = 2_592_000;
/// Default `retry.max_attempts` of a service (H2 §7.1): consecutive attempts that never became healthy.
pub const DEFAULT_SERVICE_MAX_ATTEMPTS: u32 = 3;
/// Default `service.idle_timeout_s` (H2 §7.1).
pub const DEFAULT_IDLE_TIMEOUT_S: u32 = 3_600;
/// Default `service.health.interval_s` (H2 §7.1).
pub const DEFAULT_HEALTH_INTERVAL_S: u32 = 10;
/// Default `service.health.timeout_s` (H2 §7.1).
pub const DEFAULT_HEALTH_TIMEOUT_S: u32 = 3;
/// Default `service.health.start_period_s` (H2 §7.1).
pub const DEFAULT_HEALTH_START_PERIOD_S: u32 = 300;
/// Default `service.health.failure_threshold` (H2 §7.1).
pub const DEFAULT_HEALTH_FAILURE_THRESHOLD: u32 = 3;
/// Default `outputs.max_mb` (the §7 example).
pub const DEFAULT_OUTPUTS_MAX_MB: u64 = 1_024;
/// The only placement pool in v0.1.
pub const POOL_MINE: &str = "mine";
/// Largest page size for list endpoints (§7).
pub const MAX_PAGE_LIMIT: u32 = 100;

fn default_disk_mb() -> u64 {
    DEFAULT_DISK_MB
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
fn default_idle_timeout_s() -> Option<u32> {
    Some(DEFAULT_IDLE_TIMEOUT_S)
}
fn default_health_interval_s() -> u32 {
    DEFAULT_HEALTH_INTERVAL_S
}
fn default_health_timeout_s() -> u32 {
    DEFAULT_HEALTH_TIMEOUT_S
}
fn default_health_start_period_s() -> u32 {
    DEFAULT_HEALTH_START_PERIOD_S
}
fn default_health_failure_threshold() -> u32 {
    DEFAULT_HEALTH_FAILURE_THRESHOLD
}
fn is_false(b: &bool) -> bool {
    !*b
}
fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Deserializes a field that is **present**: a JSON `null` is refused, as for a plain field, and the value is wrapped
/// in `Some`. With `#[serde(default)]`, an absent field is `None`. The JobSpec wire types use it so that a field
/// whose default depends on `kind` keeps H1's rule that `null` is not a value.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// What kind of job a spec describes (H2 §7.1): a batch job runs to completion (H1), a service keeps running and
/// exposes ports. `batch` is the default, and is left out of serialized specs, so H1 peers see H1 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    /// A job that runs to completion (H1).
    #[default]
    Batch,
    /// A long-running job with ports (H2 §7.2).
    Service,
}

impl JobKind {
    /// Whether this is `batch` (used to leave the default out of serialized specs).
    #[must_use]
    pub const fn is_batch(&self) -> bool {
        matches!(self, JobKind::Batch)
    }

    /// The snake_case name used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            JobKind::Batch => "batch",
            JobKind::Service => "service",
        }
    }

    /// The default `timeout_s` of this kind: 3 600 for `batch` (H1), 2 592 000 (30 days) for `service` (H2 §7.1).
    #[must_use]
    pub const fn default_timeout_s(self) -> u32 {
        match self {
            JobKind::Batch => DEFAULT_TIMEOUT_S,
            JobKind::Service => DEFAULT_SERVICE_TIMEOUT_S,
        }
    }

    /// The default `retry.max_attempts` of this kind: 2 for `batch` (H1), 3 for `service` (H2 §7.1).
    #[must_use]
    pub const fn default_max_attempts(self) -> u32 {
        match self {
            JobKind::Batch => DEFAULT_MAX_ATTEMPTS,
            JobKind::Service => DEFAULT_SERVICE_MAX_ATTEMPTS,
        }
    }
}

impl fmt::Display for JobKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What happens to a service when its node is lost (H2 §7.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    /// The first node loss ends the job `lost`.
    Never,
    /// Requeue it, under `retry.max_attempts` and at most 5 node-loss restarts in any 24 h.
    #[default]
    OnNodeLoss,
}

/// A blob input's content address (H2 §7.1, §7.5): `sha256:<64 lowercase hex>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema), schema(value_type = String))]
pub struct BlobRef(pub Sha256Digest);

/// The prefix of a [`BlobRef`].
pub const BLOB_REF_PREFIX: &str = "sha256:";

impl fmt::Display for BlobRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{BLOB_REF_PREFIX}{}", self.0)
    }
}

impl fmt::Debug for BlobRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobRef({self})")
    }
}

/// The string is not `sha256:<64 lowercase hex>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("expected a blob reference `sha256:<64 lowercase hex>`")]
pub struct InvalidBlobRef;

impl std::str::FromStr for BlobRef {
    type Err = InvalidBlobRef;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s.strip_prefix(BLOB_REF_PREFIX).ok_or(InvalidBlobRef)?;
        hex.parse().map(BlobRef).map_err(|_| InvalidBlobRef)
    }
}

impl Serialize for BlobRef {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for BlobRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::ids::deserialize_from_str(deserializer)
    }
}

/// Defines the job spec types once, so the strict request types and the lenient response types cannot drift.
///
/// `$strictness` is applied to every struct: `serde(deny_unknown_fields)` for the request types, nothing for the
/// response types. `$note` is appended to every type's doc. `$File` is defined outside the macro, because the two
/// families differ there: the request carries `content_b64`, the response only `{path, size, sha256}` (§7).
///
/// `$Spec` deserializes through `$Wire` (`wire:` gives the `serde(from)` attribute), a private twin whose
/// `timeout_s` and `retry.max_attempts` are optional: an absent value takes the default of the spec's `kind`
/// (H2 §7.1), which a field-level `serde(default)` cannot see. Serialization is the plain derive, unchanged for H1
/// fields, and every H2 field is skipped while it has its default, so an H1 spec serializes to its H1 bytes.
macro_rules! job_spec_types {
    (
        strictness: [$(#[$strictness:meta])*],
        note: $note:literal,
        wire: [$(#[$wire:meta])*],
        idempotency: [$($idem:ident)?],
        $Spec:ident, $Wire:ident, $File:ident, $Res:ident, $Egress:ident, $Out:ident, $Place:ident, $Retry:ident,
        $RetryWire:ident, $Service:ident, $Port:ident, $Health:ident, $Volume:ident, $Input:ident, $Template:ident $(,)?
    ) => {
        #[doc = "A job specification: what to run and with which limits (§7, H2 §7.1)."]
        #[doc = ""]
        #[doc = "`Debug` never prints environment values or input file contents (§7: env values are never logged)."]
        #[doc = ""]
        #[doc = $note]
        #[derive(Clone, PartialEq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$strictness])*
        $(#[$wire])*
        pub struct $Spec {
            /// `batch` (default) or `service` (H2 §7.1). Left out when `batch`.
            #[serde(default, skip_serializing_if = "JobKind::is_batch")]
            pub kind: JobKind,
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
            /// Wall-clock limit in seconds. Every job has one (hard rule 3). Default 3 600 for `batch` (1-86 400) and
            /// 2 592 000, 30 days, for `service` (60-2 592 000). (`serde(default)` here only marks it optional in the
            /// schema: deserialization goes through the wire type, which applies the default of the `kind`.)
            #[serde(default)]
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
            /// Retry policy. For `batch`, only node loss consumes an attempt (default 2); for `service`, it counts
            /// consecutive attempts that never became healthy (default 3).
            #[serde(default)]
            pub retry: $Retry,
            /// The service block: required when `kind = "service"`, forbidden otherwise (H2 §7.1).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub service: Option<$Service>,
            /// Persistent volumes, 0-4 (H2 §7.1, §11.3): only for services and template launches.
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            pub volumes: Vec<$Volume>,
            /// Blob inputs, 0-32, delivered read-only under `/inputs` (H2 §7.1, §7.5).
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            pub inputs: Vec<$Input>,
            /// Read-only: set by a template launch (H2 §7.6). A `POST /v1/jobs` that sends it gets
            /// `422 read_only_field`.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub template: Option<$Template>,
            $(
                /// Client-chosen key that makes the submission idempotent (§7). Scoped to the principal that submits
                /// it, an API key or a device (H2 §5.6). It is **never returned**: no response type has it (see
                /// [`JobSpecView`]).
                #[serde(default, skip_serializing_if = "Option::is_none")]
                pub $idem: Option<String>,
            )?
        }

        /// The wire form of the spec: what is actually deserialized (see the macro's doc).
        #[derive(Deserialize)]
        $(#[$strictness])*
        struct $Wire {
            #[serde(default)]
            kind: JobKind,
            #[serde(default)]
            name: Option<String>,
            image: String,
            command: Vec<String>,
            #[serde(default)]
            env: BTreeMap<String, String>,
            #[serde(default)]
            files: Vec<$File>,
            resources: $Res,
            #[serde(default, deserialize_with = "present")]
            timeout_s: Option<u32>,
            #[serde(default)]
            egress: $Egress,
            #[serde(default)]
            outputs: $Out,
            #[serde(default)]
            placement: $Place,
            #[serde(default)]
            retry: $RetryWire,
            #[serde(default)]
            service: Option<$Service>,
            #[serde(default)]
            volumes: Vec<$Volume>,
            #[serde(default)]
            inputs: Vec<$Input>,
            #[serde(default)]
            template: Option<$Template>,
            $(
                #[serde(default)]
                $idem: Option<String>,
            )?
        }

        /// The wire form of `retry`: `max_attempts` is optional, and its default depends on the spec's `kind`.
        #[derive(Default, Deserialize)]
        $(#[$strictness])*
        struct $RetryWire {
            #[serde(default, deserialize_with = "present")]
            max_attempts: Option<u32>,
        }

        impl From<$Wire> for $Spec {
            fn from(w: $Wire) -> Self {
                let kind = w.kind;
                Self {
                    kind,
                    name: w.name,
                    image: w.image,
                    command: w.command,
                    env: w.env,
                    files: w.files,
                    resources: w.resources,
                    timeout_s: w.timeout_s.unwrap_or(kind.default_timeout_s()),
                    egress: w.egress,
                    outputs: w.outputs,
                    placement: w.placement,
                    retry: $Retry {
                        max_attempts: w.retry.max_attempts.unwrap_or(kind.default_max_attempts()),
                    },
                    service: w.service,
                    volumes: w.volumes,
                    inputs: w.inputs,
                    template: w.template,
                    $($idem: w.$idem,)?
                }
            }
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
            /// Attempts in total, 1-5. Default 2 for `batch` (only node loss consumes an attempt) and 3 for `service`
            /// (consecutive attempts that never became healthy, H2 §7.2).
            #[serde(default = "default_max_attempts")]
            pub max_attempts: u32,
        }

        /// The batch default (2 attempts). A spec read from JSON takes the default of its `kind` instead.
        impl Default for $Retry {
            fn default() -> Self {
                Self { max_attempts: DEFAULT_MAX_ATTEMPTS }
            }
        }

        #[doc = "The service block of a `kind = \"service\"` job (H2 §7.1)."]
        #[doc = ""]
        #[doc = $note]
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$strictness])*
        pub struct $Service {
            /// The ports the service listens on inside its container, 1-8. The shim forwards no other port.
            pub ports: Vec<$Port>,
            /// The health check. Without it, the service is `healthy` as soon as a connection to its first port
            /// succeeds through the bridge.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub health: Option<$Health>,
            /// `null` (never) or 300-604 800 seconds without an open port connection and without traffic, measured
            /// by the hub. Default 3 600 when absent.
            #[serde(default = "default_idle_timeout_s", deserialize_with = "Option::deserialize")]
            pub idle_timeout_s: Option<u32>,
            /// What a node loss does (default `on_node_loss`).
            #[serde(default)]
            pub restart: RestartPolicy,
        }

        #[doc = "One exposed port of a service (H2 §7.1)."]
        #[doc = ""]
        #[doc = $note]
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$strictness])*
        pub struct $Port {
            /// The TCP port inside the container, 1-65 535, unique.
            pub port: u32,
            /// `[a-z][a-z0-9-]{0,31}`, unique.
            pub name: String,
        }

        #[doc = "A service health check (H2 §7.1): exactly one of `http_get` or `tcp: true`."]
        #[doc = ""]
        #[doc = $note]
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$strictness])*
        pub struct $Health {
            /// An absolute path to `GET`, at most 256 bytes. Only the status line is read.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub http_get: Option<String>,
            /// A TCP connect check.
            #[serde(default, skip_serializing_if = "is_false")]
            pub tcp: bool,
            /// The port to check: one of `service.ports`.
            pub port: u32,
            /// Seconds between checks, 2-300. Default 10.
            #[serde(default = "default_health_interval_s")]
            pub interval_s: u32,
            /// Seconds before one check fails, 1-60. Default 3.
            #[serde(default = "default_health_timeout_s")]
            pub timeout_s: u32,
            /// Seconds the service may stay `starting`, 0-3 600. Default 300.
            #[serde(default = "default_health_start_period_s")]
            pub start_period_s: u32,
            /// Consecutive failed checks that make it `unhealthy`, 1-20. Default 3.
            #[serde(default = "default_health_failure_threshold")]
            pub failure_threshold: u32,
        }

        #[doc = "A persistent volume of a job (H2 §7.1, §11.3)."]
        #[doc = ""]
        #[doc = $note]
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$strictness])*
        pub struct $Volume {
            /// `[a-z0-9][a-z0-9._-]{0,62}`, or `tpl:<template id>/<name>` (template launches only). A label, never
            /// a path: the agent derives the directory from it.
            pub name: String,
            /// Where it is mounted: absolute, under `/volumes/`.
            pub mount: String,
            /// Size limit in MiB, 64-262 144.
            pub max_mb: u64,
        }

        #[doc = "A blob input (H2 §7.1): the blob, delivered read-only at `path`."]
        #[doc = ""]
        #[doc = $note]
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$strictness])*
        pub struct $Input {
            /// Absolute path under `/inputs/`, with the `files` path rules.
            pub path: String,
            /// The blob, which must exist in the caller's account when the job is created.
            pub blob: BlobRef,
        }

        #[doc = "The template a job was launched from (H2 §7.6). Read-only: only a template launch sets it."]
        #[doc = ""]
        #[doc = $note]
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        $(#[$strictness])*
        pub struct $Template {
            /// The template's id.
            pub id: String,
            /// The template's version, from 1.
            pub version: u32,
            /// The model the hub pulls at launch (the template's `pull` parameter), `null` without one.
            #[serde(default)]
            pub pull: Option<String>,
        }
    };
}

job_spec_types!(
    strictness: [#[serde(deny_unknown_fields)]],
    note: "**Strict** (request type): the `POST /v1/jobs` body, and what the agent parses a lease's job into \
           (`LeaseJob::parse_strict`). Unknown fields are rejected, which catches typos and refuses a lease the \
           agent would not fully understand (§6). Responses use the lenient twin, [`JobSpecView`].",
    wire: [#[serde(from = "JobSpecWire")]],
    idempotency: [idempotency_key],
    JobSpec,
    JobSpecWire,
    InputFile,
    Resources,
    Egress,
    Outputs,
    Placement,
    Retry,
    RetryWire,
    ServiceSpec,
    ServicePort,
    HealthCheck,
    VolumeSpec,
    BlobInput,
    TemplateRef,
);

job_spec_types!(
    strictness: [],
    note: "**Lenient and redacted** (response type): the `spec` of a [`Job`] in API responses (§7 \"Job \
           representation in responses\"). Unknown fields are ignored, so an older CLI or SDK keeps reading jobs \
           after the server adds a field (§6). `env` values are always `\"<redacted>\"` and `files` carry \
           `{path, size, sha256}` with no content, and there is **no `idempotency_key`**: a response never carries it \
           (§7). Build it with [`JobSpecView::from_stored`].",
    wire: [#[serde(from = "JobSpecViewWire")]],
    // No `idempotency_key`: responses never carry it (§7). The key only means something to the key that sent it, and
    // echoing it would let another key learn it.
    idempotency: [],
    JobSpecView,
    JobSpecViewWire,
    InputFileView,
    ResourcesView,
    EgressView,
    OutputsView,
    PlacementView,
    RetryView,
    RetryViewWire,
    ServiceSpecView,
    ServicePortView,
    HealthCheckView,
    VolumeSpecView,
    BlobInputView,
    TemplateRefView,
);

/// Writes the `Debug` of a spec type: env values and file contents are redacted, only names, paths and sizes show.
macro_rules! spec_debug {
    ($Spec:ident $(, $extra:ident)?) => {
        impl fmt::Debug for $Spec {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Env values and file contents are redacted: only names, paths and sizes are shown.
                let env_names: Vec<&str> = self.env.keys().map(String::as_str).collect();
                let mut d = f.debug_struct(stringify!($Spec));
                d.field("kind", &self.kind)
                    .field("name", &self.name)
                    .field("image", &self.image)
                    .field("command", &self.command)
                    .field("env_names", &env_names)
                    .field("files", &self.files)
                    .field("resources", &self.resources)
                    .field("timeout_s", &self.timeout_s)
                    .field("egress", &self.egress)
                    .field("outputs", &self.outputs)
                    .field("placement", &self.placement)
                    .field("retry", &self.retry)
                    .field("service", &self.service)
                    .field("volumes", &self.volumes)
                    .field("inputs", &self.inputs)
                    .field("template", &self.template);
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
    ServicePort => ServicePortView { port, name }
    HealthCheck => HealthCheckView { http_get, tcp, port, interval_s, timeout_s, start_period_s, failure_threshold }
    VolumeSpec => VolumeSpecView { name, mount, max_mb }
    BlobInput => BlobInputView { path, blob }
    TemplateRef => TemplateRefView { id, version, pull }
}

impl From<ServiceSpec> for ServiceSpecView {
    fn from(v: ServiceSpec) -> Self {
        Self {
            ports: v.ports.into_iter().map(Into::into).collect(),
            health: v.health.map(Into::into),
            idle_timeout_s: v.idle_timeout_s,
            restart: v.restart,
        }
    }
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
            kind: spec.kind,
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
            service: spec.service.clone().map(Into::into),
            volumes: spec.volumes.iter().cloned().map(Into::into).collect(),
            inputs: spec.inputs.iter().cloned().map(Into::into).collect(),
            template: spec.template.clone().map(Into::into),
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
    /// The service view of a `kind = "service"` job (H2 §7.2): health, ports, idle and cap deadlines, the hub's model
    /// pull and today's traffic. Left out for batch jobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceView>,
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
            service: None,
        }
    }
}

/// `Job.reason` of a service stopped by a principal (H2 §7.2); the job ends `cancelled`.
pub const REASON_STOPPED: &str = "stopped";
/// `Job.reason` of a service stopped after `idle_timeout_s` without connections or traffic (H2 §7.2).
pub const REASON_IDLE_TIMEOUT: &str = "idle_timeout";
/// `Job.reason` of a service stopped because its principal's daily cap was reached (H2 §7.2, §12).
pub const REASON_CAP_REACHED: &str = "cap_reached";
/// `Job.error` of a service the agent stopped because it never became healthy, or stayed unhealthy (H2 §7.2).
pub const ERROR_HEALTH_CHECK_FAILED: &str = "health_check_failed";
/// `Job.error` of a service that lost its node a sixth time within 24 h (H2 §7.2); the job ends `lost`.
pub const ERROR_RESTART_LIMIT: &str = "restart_limit";
/// Most node-loss restarts of one service in any 24 h, whatever `retry.max_attempts` says (H2 §7.2).
pub const MAX_NODE_LOSS_RESTARTS_PER_24H: u32 = 5;
/// How long an attempt must stay `healthy` to reset the count of attempts that never became healthy (H2 §7.2).
pub const HEALTHY_RESETS_ATTEMPTS_AFTER_S: u32 = 600;

/// The health of a running service (H2 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ServiceHealth {
    /// From `JobStarted` until the first passing check, at most `start_period_s`.
    Starting,
    /// The last check passed.
    Healthy,
    /// The last `failure_threshold` checks failed.
    Unhealthy,
}

/// The state of the hub's model pull for a template service (H2 §7.2, §7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SetupState {
    /// The pull is running.
    Pulling,
    /// The pull ended with a final `status: "success"` line.
    Done,
    /// Both tries failed; the hub does not pull again in this attempt.
    Failed,
}

/// Why a model pull failed (H2 §7.6 "Reading").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SetupFailure {
    /// A line with `error`.
    ErrorLine,
    /// A line longer than 4 KiB, or malformed.
    BadLine,
    /// The stream ended without the final `success` line.
    Eof,
    /// The stream broke (`node_unreachable`, an agent reconnect or a hub restart).
    StreamBroken,
    /// 2 h after the try started.
    Deadline,
}

/// The hub's model pull of a template service, `service.setup` (H2 §7.2, §7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ServiceSetup {
    /// `pulling`, `done` or `failed`.
    pub state: SetupState,
    /// MiB downloaded so far.
    #[serde(default)]
    pub completed_mb: u64,
    /// MiB to download, once the service reported it.
    #[serde(default)]
    pub total_mb: Option<u64>,
    /// Tries so far (at most 2 per attempt).
    #[serde(default)]
    pub tries: u32,
    /// Why it failed, when `state` is `failed`.
    #[serde(default)]
    pub reason: Option<SetupFailure>,
}

/// A service's traffic for one UTC day, recorded and not billed (H2 §12 `service_traffic`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ServiceTraffic {
    /// 00:00 UTC of the day the totals are for.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub day: OffsetDateTime,
    /// Bytes from clients to the service.
    #[serde(default)]
    pub bytes_in: u64,
    /// Bytes from the service to clients.
    #[serde(default)]
    pub bytes_out: u64,
    /// Port connections opened.
    #[serde(default)]
    pub connections: u64,
}

/// The `service` member of `GET /v1/jobs/{id}` for a service (H2 §7.2). Lenient, and every field defaults, so a
/// newer server may add fields and an older one may leave some out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ServiceView {
    /// The health of the running attempt; `null` while the service is not running.
    #[serde(default)]
    pub health: Option<ServiceHealth>,
    /// Since when `health` has had its value.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub health_since: Option<OffsetDateTime>,
    /// The exposed ports, from the spec.
    #[serde(default)]
    pub ports: Vec<ServicePortView>,
    /// Port connections open now.
    #[serde(default)]
    pub open_connections: u32,
    /// Last byte forwarded in either direction (updated at most every 10 s).
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub last_activity_at: Option<OffsetDateTime>,
    /// When the idle timeout stops the service; `null` while a connection is open or when `idle_timeout_s` is
    /// `null`.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub idle_deadline: Option<OffsetDateTime>,
    /// When `timeout_s` ends the current attempt.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub deadline: Option<OffsetDateTime>,
    /// When today's cap reservation runs out (H2 §12); `null` for an uncapped principal.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub cap_deadline: Option<OffsetDateTime>,
    /// Node-loss restarts in the last 24 h (at most [`MAX_NODE_LOSS_RESTARTS_PER_24H`]).
    #[serde(default)]
    pub restarts_24h: u32,
    /// The hub's model pull (H2 §7.6); `null` for a job without one.
    #[serde(default)]
    pub setup: Option<ServiceSetup>,
    /// Today's traffic totals (H2 §12).
    #[serde(default)]
    pub traffic: Option<ServiceTraffic>,
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
    /// `approved` (default, and every H1 node) or `pending_approval` (H2 §5.5): a pending node gets no lease until
    /// an `admin` approves it. Left out when `approved`.
    #[serde(default, skip_serializing_if = "NodeApproval::is_approved")]
    pub approval: NodeApproval,
    /// The principal that minted the node's join token, as the hub recorded it; `null` for H1 nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_by: Option<Principal>,
    /// The node phrase (H2 §5.5): 6 words derived from the node's iroh NodeId, shown before approving it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_phrase: Option<String>,
}

/// Whether a node may get work (H2 §5.5 "Node approval").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NodeApproval {
    /// The node is eligible for leases.
    #[default]
    Approved,
    /// Enrolled by a non-`admin` principal's token: waiting for approval on the hub PC, never offered a lease.
    PendingApproval,
}

impl NodeApproval {
    /// Whether this is `approved` (used to leave the default out of serialized nodes).
    #[must_use]
    pub const fn is_approved(&self) -> bool {
        matches!(self, NodeApproval::Approved)
    }
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
            approval: NodeApproval::Approved,
            enrolled_by: None,
            node_phrase: None,
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
    /// Open a port connection to a service (H2 §7.4).
    #[serde(rename = "services:connect")]
    ServicesConnect,
    /// Launch templates, and see the narrow template view of jobs (H2 §5.5, §7.6).
    #[serde(rename = "templates:launch")]
    TemplatesLaunch,
    /// Upload blobs, and withdraw one's own claim on them (H2 §7.5).
    #[serde(rename = "blobs:write")]
    BlobsWrite,
    /// Open a join request that an `admin` must approve (H2 §5.4).
    #[serde(rename = "nodes:invite")]
    NodesInvite,
    /// Mint join tokens valid at most 15 minutes, whose nodes start `pending_approval` (H2 §5.4).
    #[serde(rename = "nodes:join")]
    NodesJoin,
}

impl Scope {
    /// Every scope, in declaration order.
    pub const ALL: [Scope; 10] = [
        Scope::Admin,
        Scope::JobsWrite,
        Scope::JobsRead,
        Scope::NodesRead,
        Scope::NodesWrite,
        Scope::ServicesConnect,
        Scope::TemplatesLaunch,
        Scope::BlobsWrite,
        Scope::NodesInvite,
        Scope::NodesJoin,
    ];

    /// The wire name, for example `jobs:read`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Scope::Admin => "admin",
            Scope::JobsWrite => "jobs:write",
            Scope::JobsRead => "jobs:read",
            Scope::NodesRead => "nodes:read",
            Scope::NodesWrite => "nodes:write",
            Scope::ServicesConnect => "services:connect",
            Scope::TemplatesLaunch => "templates:launch",
            Scope::BlobsWrite => "blobs:write",
            Scope::NodesInvite => "nodes:invite",
            Scope::NodesJoin => "nodes:join",
        }
    }
}

/// The "Owner" profile (H2 §5.5): the desktop app on the hub PC.
pub const OWNER_PROFILE: [Scope; 1] = [Scope::Admin];

/// The default "Phone" profile (H2 §5.5): the default scopes of a pairing ticket. It cannot submit arbitrary
/// JobSpecs, read other jobs, open a non-template service or mint join tokens.
pub const PHONE_PROFILE: [Scope; 4] = [
    Scope::NodesRead,
    Scope::TemplatesLaunch,
    Scope::BlobsWrite,
    Scope::NodesInvite,
];

/// The opt-in "Developer device" profile (H2 §5.5): the phone profile plus `jobs:read`, `jobs:write`,
/// `services:connect` and `nodes:join`.
pub const DEVELOPER_DEVICE_PROFILE: [Scope; 8] = [
    Scope::NodesRead,
    Scope::TemplatesLaunch,
    Scope::BlobsWrite,
    Scope::NodesInvite,
    Scope::JobsRead,
    Scope::JobsWrite,
    Scope::ServicesConnect,
    Scope::NodesJoin,
];

/// Who authenticated a request (H2 §5.5): an API key (H1) or a paired device. JSON `{"kind": "key", "id": "…"}` or
/// `{"kind": "device", "id": "dev_…"}`, as `GET /v1/whoami`'s `principal`.
///
/// [`Display`](fmt::Display) and [`FromStr`](std::str::FromStr) use the `key:<id>` and `device:<id>` labels of
/// `GET /v1/usage?group_by=principal` (H2 §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Principal {
    /// An API key.
    Key(KeyId),
    /// A paired device.
    Device(DeviceId),
}

impl Principal {
    /// The key, if the principal is one.
    #[must_use]
    pub const fn key_id(&self) -> Option<KeyId> {
        match self {
            Principal::Key(k) => Some(*k),
            Principal::Device(_) => None,
        }
    }

    /// The device, if the principal is one.
    #[must_use]
    pub const fn device_id(&self) -> Option<DeviceId> {
        match self {
            Principal::Key(_) => None,
            Principal::Device(d) => Some(*d),
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Principal::Key(k) => write!(f, "key:{k}"),
            Principal::Device(d) => write!(f, "device:{d}"),
        }
    }
}

/// The string is not `key:<key id>` or `device:<device id>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("expected `key:<key id>` or `device:<device id>`")]
pub struct InvalidPrincipal;

impl std::str::FromStr for Principal {
    type Err = InvalidPrincipal;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(k) = s.strip_prefix("key:") {
            k.parse().map(Principal::Key).map_err(|_| InvalidPrincipal)
        } else if let Some(d) = s.strip_prefix("device:") {
            d.parse().map(Principal::Device).map_err(|_| InvalidPrincipal)
        } else {
            Err(InvalidPrincipal)
        }
    }
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
    /// Validity in seconds. Default 900 (15 minutes), maximum 86 400 (24 h); at most 900 with `pre_approved`, and
    /// for a `nodes:join` principal (H2 §7.3, where the spec calls it `expires_in_s`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_s: Option<u32>,
    /// The node it enrolls starts `approved` (H2 §5.4, §5.5). `admin` principals only (else `403`). Left out when
    /// `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub pre_approved: bool,
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
    /// The key that created it; `null` when a device did (H2 §5.6), see `created_by`.
    #[serde(default)]
    pub created_by_key_id: Option<KeyId>,
    /// The principal that created it, `{kind, id}` (H2 §5.6). Absent from an H1 server, whose tokens are always
    /// created by the `created_by_key_id` key. Left out when `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Principal>,
    /// Minted with the `admin`-only `pre_approved` option: the node it enrolls starts `approved` (H2 §5.4). Left out
    /// when `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub pre_approved: bool,
    /// The agent NodeId (64 lowercase hex) the token is bound to: the token of an approved join request enrolls no
    /// other (H2 §5.4). Left out when `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_iroh_node_id: Option<String>,
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
            created_by_key_id: Some(created_by_key_id),
            created_by: None,
            pre_approved: false,
            bound_iroh_node_id: None,
            created_at,
            expires_at,
            consumed_at: None,
            consumed_by_node_id: None,
            revoked_at: None,
        }
    }

    /// An unused, unrevoked token with no label, created by `created_by`, a key or a device (H2 §5.6):
    /// `created_by_key_id` is the key, or `None` for a device.
    #[must_use]
    pub fn by_principal(
        id: JoinTokenId,
        created_by: Principal,
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            label: None,
            created_by_key_id: created_by.key_id(),
            created_by: Some(created_by),
            pre_approved: false,
            bound_iroh_node_id: None,
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
    /// The key's public ID; `null` when the caller is a device (H2 §5.5), see `principal`.
    #[serde(default)]
    pub key_id: Option<KeyId>,
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
    /// Who the caller is, `{kind, id}` (H2 §5.5). `null` from an H1 server, whose callers are always the `key_id`
    /// key. Left out when `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<Principal>,
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
    /// A pairing ticket was created (H2 §5.2).
    PairingTicketCreated,
    /// An unused pairing ticket was revoked (H2 §5.2).
    PairingTicketRevoked,
    /// A device paired with a ticket (H2 §5.3).
    DevicePaired,
    /// A device was revoked (H2 §5.5).
    DeviceRevoked,
    /// A device was registered offline by `p2pc-server devices add` (H2 §5.3).
    DeviceAddedOffline,
    /// A device was revoked offline by `p2pc-server devices revoke` (H2 §5.3).
    DeviceRevokedOffline,
    /// A join request was opened (H2 §5.4).
    JoinRequestCreated,
    /// A join request's listener nonce matched its commitment (H2 §5.4).
    JoinRequestRevealed,
    /// A join request's listener nonce did not match its commitment (H2 §5.4).
    JoinRequestRevealFailed,
    /// An `admin` approved a join request (H2 §5.4).
    JoinRequestApproved,
    /// A join request was rejected or withdrawn (H2 §5.4).
    JoinRequestRejected,
    /// The join token of an approved request was handed to the requesting device (H2 §5.4).
    JoinRequestDelivered,
    /// An `admin` approved a `pending_approval` node (H2 §5.5).
    NodeApproved,
    /// A node left the cloud by itself (H2 §6.1 `leave`).
    NodeLeft,
    /// A template bundle became current (H2 §7.6).
    TemplateBundleLoaded,
}

impl AuditKind {
    /// Every kind, in declaration order (H1's, then H2's).
    pub const ALL: [AuditKind; 25] = [
        AuditKind::KeyCreated,
        AuditKind::KeyRevoked,
        AuditKind::JoinTokenCreated,
        AuditKind::JoinTokenConsumed,
        AuditKind::JoinTokenRevoked,
        AuditKind::NodeEnrolled,
        AuditKind::NodeDeleted,
        AuditKind::AuthFailed,
        AuditKind::KeyRecovered,
        AuditKind::NodeReenrolled,
        AuditKind::PairingTicketCreated,
        AuditKind::PairingTicketRevoked,
        AuditKind::DevicePaired,
        AuditKind::DeviceRevoked,
        AuditKind::DeviceAddedOffline,
        AuditKind::DeviceRevokedOffline,
        AuditKind::JoinRequestCreated,
        AuditKind::JoinRequestRevealed,
        AuditKind::JoinRequestRevealFailed,
        AuditKind::JoinRequestApproved,
        AuditKind::JoinRequestRejected,
        AuditKind::JoinRequestDelivered,
        AuditKind::NodeApproved,
        AuditKind::NodeLeft,
        AuditKind::TemplateBundleLoaded,
    ];
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
    /// The device that acted, if any (H2 §5.6). At most one of `actor_key_id` and `actor_device_id` is set. Left
    /// out when `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_device_id: Option<DeviceId>,
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
    /// The REST API generation (H2 §7.3): 1 for H1, [`API_VERSION_H2`] for H2. An absent value means 1, and 1 is
    /// left out, so an H1 server's response is unchanged.
    #[serde(default = "api_version_h1", skip_serializing_if = "is_api_version_h1")]
    pub api_version: u32,
    /// The oldest web app build this hub accepts (H2 §14.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_web_version: Option<String>,
    /// The hub's display name (H2 §7.3, `PATCH /v1/server`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub_name: Option<String>,
    /// The largest blob upload, in MiB (H2 §7.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_blob_mb: Option<u64>,
}

/// `ServerInfo.api_version` of an H1 server, and its value when absent.
pub const API_VERSION_H1: u32 = 1;
/// `ServerInfo.api_version` of a server that serves the H2 API (H2 §7.3).
pub const API_VERSION_H2: u32 = 2;

fn api_version_h1() -> u32 {
    API_VERSION_H1
}
fn is_api_version_h1(v: &u32) -> bool {
    *v == API_VERSION_H1
}

impl ServerInfo {
    /// The info for a server `address` (its NodeId and relays come from it) and `version`, with the H1 API
    /// generation and no H2 fields: the server sets `api_version` to [`API_VERSION_H2`] once it serves the H2 API.
    #[must_use]
    pub fn new(address: crate::auth::ServerAddress, version: impl Into<String>) -> Self {
        Self {
            node_id: address.server.clone(),
            relays: address.relays.iter().map(|u| u.as_str().to_string()).collect(),
            address,
            version: version.into(),
            api_version: API_VERSION_H1,
            min_web_version: None,
            hub_name: None,
            max_blob_mb: None,
        }
    }
}

/// Body of `PATCH /v1/server` (H2 §7.3), `admin` only. Validate with [`UpdateServer::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct UpdateServer {
    /// The hub's display name: 1-64 printable characters.
    pub hub_name: String,
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
    /// Per API key. Rows of device principals are left out of the groups (H2 §12).
    Key,
    /// Per device (H2 §12). Rows of API keys are left out of the groups.
    Device,
    /// Per principal (H2 §12): every row, in groups labelled `key:<id>` or `device:<id>`.
    Principal,
    /// Per job kind, `batch` or `service` (H2 §12).
    Kind,
    /// Per template (H2 §12). Rows of jobs that came from no template are left out of the groups.
    Template,
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
    /// How many ledger rows (slices, H2 §12) are server estimates, midnight slices of running services included.
    /// Left out when 0, and absent from H1 servers.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub estimated_slices: u64,
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

// ---------------------------------------------------------------------------------------------------------------
// H2 resources (H2 spec §5.2-§5.5, §7.3-§7.7): blobs, volumes, templates, devices, pairing tickets, join requests and
// the error codes H2 adds. Request bodies reject unknown fields; responses ignore them.
// ---------------------------------------------------------------------------------------------------------------

/// The request header of `POST /v1/blobs` with the blob's SHA-256, 64 lowercase hex (H2 §7.5). The same header name
/// as [`OUTPUT_SHA256_HEADER`].
pub const BLOB_SHA256_HEADER: &str = "x-p2pc-sha256";
/// Default largest blob upload, in MiB (H2 §7.5 `max_blob_mb`).
pub const DEFAULT_MAX_BLOB_MB: u64 = 2_048;
/// Default per-account blob quota, in MiB (H2 §7.5 `blobs_quota_mb`).
pub const DEFAULT_BLOBS_QUOTA_MB: u64 = 20_480;

/// Response of `POST /v1/blobs` (`201`, or `200` when the account already had it; H2 §7.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BlobUploaded {
    /// The blob's digest.
    pub sha256: Sha256Digest,
    /// Size in bytes.
    pub size: u64,
    /// When the account first stored it.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub created_at: OffsetDateTime,
    /// When it expires if nothing references it; `null` while a non-terminal job keeps it alive.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub expires_at: Option<OffsetDateTime>,
}

/// One blob of `GET /v1/blobs` (H2 §7.3). There is no endpoint that returns blob contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BlobInfo {
    /// The blob's digest.
    pub sha256: Sha256Digest,
    /// Size in bytes.
    pub size: u64,
    /// When the account first stored it.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub created_at: OffsetDateTime,
    /// How many jobs reference it (a count, so the response stays bounded).
    #[serde(default)]
    pub referenced_by: u64,
    /// When it expires if nothing references it; `null` while a non-terminal job keeps it alive.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub expires_at: Option<OffsetDateTime>,
}

/// Response of `GET /v1/blobs` (H2 §7.3, §12): one page of the account's blobs, plus its stored total and quota.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BlobList {
    /// The blobs of this page.
    pub items: Vec<BlobInfo>,
    /// Pass as `cursor` to get the next page. `None` on the last page.
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// Bytes the account stores in blobs (every page).
    #[serde(default)]
    pub total_bytes: u64,
    /// The account's blob quota, in MiB.
    #[serde(default)]
    pub quota_mb: u64,
}

/// One volume of `GET /v1/volumes`, from the latest `VolumeReport`s (H2 §7.3, §11.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VolumeInfo {
    /// The volume's name, as in the JobSpec (`tpl:<id>/<name>` for template volumes).
    pub name: String,
    /// The node that holds it.
    pub node_id: NodeId,
    /// Its measured size, in MiB.
    pub size_mb: u64,
    /// Its limit, in MiB.
    pub max_mb: u64,
    /// When a job last used it.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub last_used_at: Option<OffsetDateTime>,
    /// The job that holds it now, if any (a volume has at most one holder).
    #[serde(default)]
    pub in_use_by: Option<JobId>,
}

/// The UI a template gets in the web app (H2 §7.6, §9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum TemplateUi {
    /// The private chat UI.
    Chat,
    /// The transcription UI.
    Transcribe,
    /// No UI.
    None,
}

/// What a template needs from a GPU (H2 §7.6 `requirements.gpu`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GpuRequirement {
    /// Launches with `resources.gpu = 1`.
    Required,
    /// `gpu: 1` when the account has an eligible GPU node, `gpu: 0` otherwise.
    Preferred,
    /// No GPU.
    #[default]
    None,
}

/// A template's hardware requirements (H2 §7.6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TemplateRequirements {
    /// GPU need.
    #[serde(default)]
    pub gpu: GpuRequirement,
    /// Smallest GPU memory, in MiB, if it matters.
    #[serde(default)]
    pub min_vram_mb: Option<u64>,
}

/// The JobSpec field an `int` template parameter may set (H2 §7.6 `field:` targets): a closed list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ParamField {
    /// `timeout_s`.
    TimeoutS,
    /// `service.idle_timeout_s`.
    ServiceIdleTimeoutS,
}

impl ParamField {
    /// The field's path, as written after `field:`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ParamField::TimeoutS => "timeout_s",
            ParamField::ServiceIdleTimeoutS => "service.idle_timeout_s",
        }
    }

    /// The field's JobSpec range for a template of `kind` (H2 §7.1), inclusive. A template's bounds for the
    /// parameter must lie inside it. `None` when the field does not exist for that kind (`service.*` of a batch).
    #[must_use]
    pub const fn range(self, kind: JobKind) -> Option<(u32, u32)> {
        use crate::validate::{
            MAX_IDLE_TIMEOUT_S, MAX_SERVICE_TIMEOUT_S, MAX_TIMEOUT_S, MIN_IDLE_TIMEOUT_S, MIN_SERVICE_TIMEOUT_S,
        };
        match (self, kind) {
            (ParamField::TimeoutS, JobKind::Batch) => Some((1, MAX_TIMEOUT_S)),
            (ParamField::TimeoutS, JobKind::Service) => Some((MIN_SERVICE_TIMEOUT_S, MAX_SERVICE_TIMEOUT_S)),
            (ParamField::ServiceIdleTimeoutS, JobKind::Service) => Some((MIN_IDLE_TIMEOUT_S, MAX_IDLE_TIMEOUT_S)),
            (ParamField::ServiceIdleTimeoutS, JobKind::Batch) => None,
        }
    }
}

/// Where a template parameter goes (H2 §7.6 "Parameter targets"). On the wire it is a string: `env:<NAME>`,
/// `argv:<index>`, `field:timeout_s`, `field:service.idle_timeout_s`, `input:<path>` or `pull`. Parsing checks the
/// env name, the canonical decimal index and the `/inputs` path rules, so a target can never name a reserved
/// variable or a path outside `/inputs`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ParamTarget {
    /// The whole value of an env variable of the template's spec.
    Env(String),
    /// One whole argv element of the template's spec.
    Argv(u32),
    /// A listed JobSpec field (`int` parameters only).
    Field(ParamField),
    /// One `inputs` entry at this fixed path (`blob` parameters only).
    Input(String),
    /// The model the hub pulls at launch (`enum` parameters of `ui = "chat"` templates only).
    Pull,
}

impl fmt::Display for ParamTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParamTarget::Env(name) => write!(f, "env:{name}"),
            ParamTarget::Argv(i) => write!(f, "argv:{i}"),
            ParamTarget::Field(field) => write!(f, "field:{}", field.as_str()),
            ParamTarget::Input(path) => write!(f, "input:{path}"),
            ParamTarget::Pull => f.write_str("pull"),
        }
    }
}

/// The string is not a valid [`ParamTarget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "expected `env:<NAME>`, `argv:<index>`, `field:timeout_s`, `field:service.idle_timeout_s`, `input:<path under \
     /inputs/>` or `pull`"
)]
pub struct InvalidParamTarget;

impl std::str::FromStr for ParamTarget {
    type Err = InvalidParamTarget;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "pull" {
            return Ok(ParamTarget::Pull);
        }
        let (kind, rest) = s.split_once(':').ok_or(InvalidParamTarget)?;
        match kind {
            "env" if crate::validate::is_settable_env_name(rest) => Ok(ParamTarget::Env(rest.to_string())),
            "argv" => {
                // Canonical decimal only: no sign, no leading zero, no spaces.
                let canonical = !rest.is_empty()
                    && rest.bytes().all(|b| b.is_ascii_digit())
                    && (rest == "0" || !rest.starts_with('0'));
                if !canonical {
                    return Err(InvalidParamTarget);
                }
                rest.parse().map(ParamTarget::Argv).map_err(|_| InvalidParamTarget)
            }
            "field" => match rest {
                "timeout_s" => Ok(ParamTarget::Field(ParamField::TimeoutS)),
                "service.idle_timeout_s" => Ok(ParamTarget::Field(ParamField::ServiceIdleTimeoutS)),
                _ => Err(InvalidParamTarget),
            },
            "input" if crate::validate::validate_input_path(rest).is_ok() => Ok(ParamTarget::Input(rest.to_string())),
            _ => Err(InvalidParamTarget),
        }
    }
}

impl Serialize for ParamTarget {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ParamTarget {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::ids::deserialize_from_str(deserializer)
    }
}

/// The type of a template parameter (H2 §7.6): `{"type": "enum", "values": [...]}`, `{"type": "int", "min": …,
/// "max": …}`, `{"type": "bool"}` or `{"type": "blob"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ParamType {
    /// One of the template's values.
    Enum {
        /// The allowed values.
        values: Vec<String>,
    },
    /// An integer within the template's bounds, inclusive.
    Int {
        /// Smallest value.
        min: i64,
        /// Largest value.
        max: i64,
    },
    /// `true` or `false`.
    Bool,
    /// A blob digest, `sha256:<64 hex>`, of the caller's account.
    Blob,
}

/// A parameter value in a launch request (H2 §7.6): a bool, an integer, or a string (enum values and blob
/// digests).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(untagged)]
pub enum ParamValue {
    /// A `bool` parameter.
    Bool(bool),
    /// An `int` parameter.
    Int(i64),
    /// An `enum` value or a `blob` digest.
    Text(String),
}

/// A template parameter (H2 §7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TemplateParam {
    /// The parameter's name, the key of `params` in a launch.
    pub name: String,
    /// A label for the UI.
    #[serde(default)]
    pub label: Option<String>,
    /// The type and its bounds or values.
    #[serde(flatten)]
    pub ty: ParamType,
    /// The value used when a launch leaves it out; a parameter without one is required.
    #[serde(default)]
    pub default: Option<ParamValue>,
    /// Where the value goes: `env:<NAME>`, `argv:<index>`, `field:<field>`, `input:<path>` or `pull`.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub target: ParamTarget,
}

/// One HTTP request that non-`admin` principals may send to a template service (H2 §7.4, §7.6): exact method and
/// exact absolute path (a final `*` segment only where the template needs it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AllowedRoute {
    /// A port of the template's `service.ports`.
    pub port: u32,
    /// The method, for example `POST`.
    pub method: String,
    /// The exact path, for example `/api/chat`.
    pub path: String,
}

/// A template as `GET /v1/templates` lists it (H2 §7.6): what the UI needs to offer and launch it. The JobSpec and
/// the allowed routes stay on the hub ([`Template`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TemplateInfo {
    /// The template's id, `[a-z][a-z0-9-]{0,62}`.
    pub id: String,
    /// The template's version, from 1.
    pub version: u32,
    /// Title for the UI.
    pub title: String,
    /// Description for the UI.
    #[serde(default)]
    pub description: String,
    /// `batch` or `service`.
    pub kind: JobKind,
    /// The web app UI it gets.
    pub ui: TemplateUi,
    /// One shared instance per account and project (H2 §7.6).
    #[serde(default)]
    pub singleton: bool,
    /// Hardware requirements.
    #[serde(default)]
    pub requirements: TemplateRequirements,
    /// Its parameters.
    #[serde(default)]
    pub params: Vec<TemplateParam>,
    /// The image and model licenses, shown in the UI.
    #[serde(default)]
    pub licenses: Vec<String>,
    /// Estimate of the first-run download, in MiB, shown before launch.
    #[serde(default)]
    pub download_mb: u64,
}

/// A template of the signed bundle (H2 §7.6): its listing fields, the vetted JobSpec and the routes non-`admin`
/// principals may send to it. The bundle rules (pinned digest, targets, `tpl:` volumes, routes) are checked over the
/// whole bundle by the bundle test (T2-50), not by this type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Template {
    /// What `GET /v1/templates` shows.
    #[serde(flatten)]
    pub info: TemplateInfo,
    /// The vetted JobSpec the launch starts from.
    pub spec: JobSpec,
    /// For a service: the requests non-`admin` principals may send. None means closed to them.
    #[serde(default)]
    pub allowed_routes: Vec<AllowedRoute>,
}

/// Response of `GET /v1/templates` (H2 §7.3, §7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TemplateList {
    /// The served bundle's version; `null` when none can be served.
    #[serde(default)]
    pub bundle_version: Option<u64>,
    /// The templates (empty when no bundle can be served).
    #[serde(default)]
    pub templates: Vec<TemplateInfo>,
    /// Why no bundle can be served, if so.
    #[serde(default)]
    pub bundle_error: Option<String>,
}

/// Body of `POST /v1/templates/{id}/launch` (H2 §7.3, §7.6). Validate with [`LaunchTemplate::validate`]; the
/// parameters themselves are checked against the template (`422 invalid_params`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct LaunchTemplate {
    /// Parameter values by name.
    #[serde(default)]
    pub params: BTreeMap<String, ParamValue>,
    /// As for jobs: scoped to the principal, never returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Body of `POST /v1/devices/pairing-tickets` (H2 §5.2), `admin` only. Validate with
/// [`CreatePairingTicket::validate`] and check it against its creator with
/// [`check_limits_no_escalation`](crate::validate::check_limits_no_escalation).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CreatePairingTicket {
    /// Label of the device it pairs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The device's scopes. Default: the phone profile ([`PHONE_PROFILE`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<Scope>>,
    /// The device's daily cap in milli-units.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily_unit_cap: Option<Units>,
    /// The device's image allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_images: Option<Vec<String>>,
    /// The ticket's validity in seconds, 1-3 600. Default 600.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_s: Option<u32>,
    /// The device's life in seconds, counted from the ticket's creation; more than the ticket's validity. Absent:
    /// the device never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_expires_in_s: Option<u64>,
    /// The most blob bytes, in MiB, the device may hold a claim on (H2 §7.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blobs_quota_mb: Option<u64>,
}

/// Response of `POST /v1/devices/pairing-tickets` (H2 §5.2): returned once. `Debug` redacts `ticket` and `url`
/// (the URL carries the ticket in its fragment).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PairingTicketCreated {
    /// The ticket's row ID, for listing and revoking.
    pub id: PairingTicketId,
    /// The ticket, `p2pc_pair_…`. Single-use. A secret: shown once.
    pub ticket: String,
    /// `https://<web app origin>/pair#<ticket>`, for the QR code.
    pub url: String,
    /// When the ticket expires.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for PairingTicketCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingTicketCreated")
            .field("id", &self.id)
            .field("ticket", &"<redacted>")
            .field("url", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A pairing ticket as `GET /v1/devices/pairing-tickets` lists it (H2 §5.2). Never contains the ticket or its code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PairingTicketInfo {
    /// Row ID.
    pub id: PairingTicketId,
    /// Label of the device it pairs.
    #[serde(default)]
    pub label: Option<String>,
    /// The device's scopes.
    pub scopes: Vec<Scope>,
    /// The device's daily cap.
    #[serde(default)]
    pub daily_unit_cap: Option<Units>,
    /// The device's image allowlist.
    #[serde(default)]
    pub allowed_images: Option<Vec<String>>,
    /// The device's blob quota, in MiB.
    #[serde(default)]
    pub blobs_quota_mb: Option<u64>,
    /// When the device it pairs expires, if it does.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub device_expires_at: Option<OffsetDateTime>,
    /// The principal that created it.
    pub created_by: Principal,
    /// Creation time.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub created_at: OffsetDateTime,
    /// Expiry.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub expires_at: OffsetDateTime,
    /// When a `Pair` consumed it.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub consumed_at: Option<OffsetDateTime>,
    /// The device it created.
    #[serde(default)]
    pub device_id: Option<DeviceId>,
    /// When it was revoked unused.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub revoked_at: Option<OffsetDateTime>,
}

/// A paired device, as `GET /v1/devices` lists it (H2 §7.3). Never contains key material: a device is
/// authenticated by its iroh NodeId.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeviceInfo {
    /// Device ID.
    pub id: DeviceId,
    /// Its label.
    #[serde(default)]
    pub label: Option<String>,
    /// The platform hint the device sent when it paired (at most 64 bytes, free text).
    #[serde(default)]
    pub platform: String,
    /// Its scopes.
    pub scopes: Vec<Scope>,
    /// Its daily cap.
    #[serde(default)]
    pub daily_unit_cap: Option<Units>,
    /// Its image allowlist.
    #[serde(default)]
    pub allowed_images: Option<Vec<String>>,
    /// Its blob quota, in MiB.
    #[serde(default)]
    pub blobs_quota_mb: Option<u64>,
    /// When it expires, if it does.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub expires_at: Option<OffsetDateTime>,
    /// When it paired.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub created_at: OffsetDateTime,
    /// Last request (written at most once a minute).
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub last_seen_at: Option<OffsetDateTime>,
    /// When it was revoked. Revoked rows are kept.
    #[serde(default, with = "crate::timestamp::option")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime))]
    pub revoked_at: Option<OffsetDateTime>,
    /// The principal that created its pairing ticket.
    pub paired_by: Principal,
}

impl DeviceInfo {
    /// A live device with no label, limits or activity. Set the other public fields after (CONTRIBUTING rule 7).
    #[must_use]
    pub fn new(
        id: DeviceId,
        platform: impl Into<String>,
        scopes: Vec<Scope>,
        created_at: OffsetDateTime,
        paired_by: Principal,
    ) -> Self {
        Self {
            id,
            label: None,
            platform: platform.into(),
            scopes,
            daily_unit_cap: None,
            allowed_images: None,
            blobs_quota_mb: None,
            expires_at: None,
            created_at,
            last_seen_at: None,
            revoked_at: None,
            paired_by,
        }
    }

    /// Whether the device is live at `now`: not revoked and not past its `expires_at` (H2 §5.5).
    #[must_use]
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|at| at > now)
    }

    /// Whether it is an **unrestricted `admin`** device (H2 §5.5 "Last admin"): `admin`, no expiry, no cap, no
    /// image list and no blob quota. The hub refuses to revoke the last live one (`409 last_admin_device`).
    #[must_use]
    pub fn is_unrestricted_admin(&self) -> bool {
        self.scopes.contains(&Scope::Admin)
            && self.expires_at.is_none()
            && self.daily_unit_cap.is_none()
            && self.allowed_images.is_none()
            && self.blobs_quota_mb.is_none()
    }
}

/// Body of `POST /v1/nodes/join-requests` (H2 §5.4, §7.3), copied from the invite QR. NodeIds, the commitment and
/// the nonces are 32 bytes, written as 64 lowercase hex characters (as [`ServerInfo::node_id`]). Validate with
/// [`CreateJoinRequest::validate`]; the hub also checks that both NodeIds are Ed25519 points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CreateJoinRequest {
    /// The joining PC's invite listener NodeId.
    pub listener_node_id: String,
    /// The joining PC's agent NodeId: the join token will be bound to it.
    pub iroh_node_id: String,
    /// The invite's expiry, from the QR.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub invite_expires_at: OffsetDateTime,
    /// `BLAKE3("p2pc-join-commit-v1" || listener nonce)`, from the QR.
    pub listener_commitment: String,
}

/// Response of `POST /v1/nodes/join-requests` (`201`, H2 §5.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct JoinRequestCreated {
    /// The request's ID.
    pub id: JoinRequestId,
    /// 15 minutes after its creation.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub expires_at: OffsetDateTime,
    /// The hub's 32-byte nonce, 64 lowercase hex, which the phone sends in `InviteOpen`.
    pub hub_nonce: String,
}

/// Body of `POST /v1/nodes/join-requests/{id}/reveal` (H2 §5.4 step 4). `Debug` redacts the nonce.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RevealJoinRequest {
    /// The listener's 32-byte nonce, 64 lowercase hex.
    pub listener_nonce: String,
}

impl fmt::Debug for RevealJoinRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevealJoinRequest")
            .field("listener_nonce", &"<redacted>")
            .finish()
    }
}

/// The state of a join request (H2 §5.4, §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum JoinRequestState {
    /// Created; waiting for the listener nonce.
    AwaitingReveal,
    /// Revealed; waiting for an `admin`'s approval.
    Pending,
    /// Approved; the requesting device may fetch the token.
    Approved,
    /// Rejected, withdrawn, or revealed with a wrong nonce.
    Rejected,
    /// Past its 15 minutes.
    Expired,
    /// Its token was handed to the requesting device.
    Delivered,
}

/// A join request as `GET /v1/nodes/join-requests` lists it (H2 §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct JoinRequestInfo {
    /// Request ID.
    pub id: JoinRequestId,
    /// The principal that opened it.
    pub requested_by: Principal,
    /// The joining PC's invite listener NodeId (64 lowercase hex).
    pub listener_node_id: String,
    /// The joining PC's agent NodeId (64 lowercase hex).
    pub iroh_node_id: String,
    /// The 6-word approval phrase; `null` while `awaiting_reveal`.
    #[serde(default)]
    pub approval_phrase: Option<String>,
    /// Its state.
    pub state: JoinRequestState,
    /// Creation time.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub created_at: OffsetDateTime,
    /// 15 minutes after creation.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub expires_at: OffsetDateTime,
}

/// Response of `POST /v1/nodes/join-requests/{id}/token` (H2 §7.3): returned once. `Debug` redacts the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct JoinRequestToken {
    /// The join token, bound to the request's agent NodeId. Single-use.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub join_token: JoinToken,
    /// When it expires.
    #[serde(with = "crate::timestamp")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub expires_at: OffsetDateTime,
}

/// The error codes H2 adds (H2 §7.7), with their HTTP status.
///
/// `invalid_ticket` and `not_paired` are answered on the pairing and device protocols, not by a REST route, so they
/// have no HTTP status. H1's `last_admin_key` and `cap_exceeded` keep serving keys and template launches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum H2ErrorCode {
    /// `PairError`: unknown, expired, revoked or used ticket (one code for all).
    InvalidTicket,
    /// Close code of a `p2pc/device/1` connection from a NodeId that is not a live device.
    NotPaired,
    /// `400`: a device request that carries an `Authorization` header.
    UnexpectedAuthorization,
    /// `409`: revoking the last live unrestricted `admin` device.
    LastAdminDevice,
    /// `403`: a request to a template service that matches none of its `allowed_routes`.
    RouteNotAllowed,
    /// `431`: request line and headers over 8 KiB or 64 headers.
    HeadersTooLarge,
    /// `409`: the service is not running.
    ServiceNotRunning,
    /// `409`: the service is still `starting`.
    ServiceNotReady,
    /// `422`: the port is not in `service.ports`.
    PortNotExposed,
    /// `429`: a port connection limit is reached.
    TooManyConnections,
    /// `502`: the hub could not open the stream to the node, or the agent refused it.
    NodeUnreachable,
    /// `422`: a blob input that the caller's account does not hold.
    UnknownBlob,
    /// `422`: blob inputs and inline files do not fit in `resources.disk_mb` minus 64 MiB.
    InputsExceedDisk,
    /// `422`: the uploaded body does not hash to `X-P2PC-SHA256`.
    DigestMismatch,
    /// `507`: the account's or the device's blob quota would be exceeded.
    QuotaExceeded,
    /// `409`: a non-terminal job references the blob.
    BlobInUse,
    /// `409`: a job holds the volume.
    VolumeInUse,
    /// `422`: volumes on a batch job that is not a template launch.
    VolumesNotAllowed,
    /// `503`: the node is offline (a volume deletion is not queued).
    NodeOffline,
    /// `422`: a client sent a read-only field (`template`).
    ReadOnlyField,
    /// `404`: no template with that id.
    UnknownTemplate,
    /// `422`: an unknown parameter, a wrong type or a value out of the template's bounds.
    InvalidParams,
    /// `503`: no template bundle can be served.
    TemplatesUnavailable,
    /// `409`: a singleton is running with another model.
    SingletonRunning,
    /// `409`: the join request is not in a state, or not within the time, that allows the call.
    JoinRequestClosed,
    /// `422`: a join request with a bad expiry, NodeId or commitment.
    InvalidJoinRequest,
}

impl H2ErrorCode {
    /// Every code, in the order of H2 §7.7.
    pub const ALL: [H2ErrorCode; 26] = [
        H2ErrorCode::InvalidTicket,
        H2ErrorCode::NotPaired,
        H2ErrorCode::UnexpectedAuthorization,
        H2ErrorCode::LastAdminDevice,
        H2ErrorCode::RouteNotAllowed,
        H2ErrorCode::HeadersTooLarge,
        H2ErrorCode::ServiceNotRunning,
        H2ErrorCode::ServiceNotReady,
        H2ErrorCode::PortNotExposed,
        H2ErrorCode::TooManyConnections,
        H2ErrorCode::NodeUnreachable,
        H2ErrorCode::UnknownBlob,
        H2ErrorCode::InputsExceedDisk,
        H2ErrorCode::DigestMismatch,
        H2ErrorCode::QuotaExceeded,
        H2ErrorCode::BlobInUse,
        H2ErrorCode::VolumeInUse,
        H2ErrorCode::VolumesNotAllowed,
        H2ErrorCode::NodeOffline,
        H2ErrorCode::ReadOnlyField,
        H2ErrorCode::UnknownTemplate,
        H2ErrorCode::InvalidParams,
        H2ErrorCode::TemplatesUnavailable,
        H2ErrorCode::SingletonRunning,
        H2ErrorCode::JoinRequestClosed,
        H2ErrorCode::InvalidJoinRequest,
    ];

    /// The snake_case `code` of the problem.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        use H2ErrorCode::*;
        match self {
            InvalidTicket => "invalid_ticket",
            NotPaired => "not_paired",
            UnexpectedAuthorization => "unexpected_authorization",
            LastAdminDevice => "last_admin_device",
            RouteNotAllowed => "route_not_allowed",
            HeadersTooLarge => "headers_too_large",
            ServiceNotRunning => "service_not_running",
            ServiceNotReady => "service_not_ready",
            PortNotExposed => "port_not_exposed",
            TooManyConnections => "too_many_connections",
            NodeUnreachable => "node_unreachable",
            UnknownBlob => "unknown_blob",
            InputsExceedDisk => "inputs_exceed_disk",
            DigestMismatch => "digest_mismatch",
            QuotaExceeded => "quota_exceeded",
            BlobInUse => "blob_in_use",
            VolumeInUse => "volume_in_use",
            VolumesNotAllowed => "volumes_not_allowed",
            NodeOffline => "node_offline",
            ReadOnlyField => "read_only_field",
            UnknownTemplate => "unknown_template",
            InvalidParams => "invalid_params",
            TemplatesUnavailable => "templates_unavailable",
            SingletonRunning => "singleton_running",
            JoinRequestClosed => "join_request_closed",
            InvalidJoinRequest => "invalid_join_request",
        }
    }

    /// The HTTP status of the problem, or `None` for the two protocol-only codes.
    #[must_use]
    pub const fn http_status(self) -> Option<u16> {
        use H2ErrorCode::*;
        Some(match self {
            InvalidTicket | NotPaired => return None,
            UnexpectedAuthorization => 400,
            RouteNotAllowed => 403,
            UnknownTemplate => 404,
            LastAdminDevice | ServiceNotRunning | ServiceNotReady | BlobInUse | VolumeInUse | SingletonRunning
            | JoinRequestClosed => 409,
            PortNotExposed | UnknownBlob | InputsExceedDisk | DigestMismatch | VolumesNotAllowed | ReadOnlyField
            | InvalidParams | InvalidJoinRequest => 422,
            TooManyConnections => 429,
            HeadersTooLarge => 431,
            NodeUnreachable => 502,
            NodeOffline | TemplatesUnavailable => 503,
            QuotaExceeded => 507,
        })
    }

    /// The problem for this code, with `title`; `None` for the protocol-only codes.
    #[must_use]
    pub fn problem(self, title: impl Into<String>) -> Option<Problem> {
        self.http_status()
            .map(|status| Problem::new(status, self.as_str(), title))
    }
}

impl fmt::Display for H2ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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
    /// The code is, in this order of precedence:
    /// - `too_large` when the job does not fit its `Lease` frame (field `job`);
    /// - the H2 §7.1 codes `read_only_field`, `volumes_not_allowed`, `inputs_exceed_disk` and `unknown_blob`, when a
    ///   field error has that code (an H1 request never produces them);
    /// - `unsupported_pool` when the pool is the problem (§7 names it and `too_large`);
    /// - `validation_failed` otherwise.
    ///
    /// Every field error is listed in `errors`.
    #[must_use]
    pub fn from_validation(errors: &crate::validate::ValidationErrors) -> Self {
        use crate::validate::ErrorCode;
        let has = |code: ErrorCode| errors.iter().any(|e| e.code == code);
        // `too_large` on `job` comes from the Lease frame check, which only runs when every other rule passed, so it
        // never coexists with another error.
        let h2 = [
            ErrorCode::ReadOnlyField,
            ErrorCode::VolumesNotAllowed,
            ErrorCode::InputsExceedDisk,
            ErrorCode::UnknownBlob,
        ];
        let code = if errors.iter().any(|e| e.field == "job" && e.code == ErrorCode::TooLarge) {
            "too_large"
        } else if let Some(code) = h2.into_iter().find(|c| has(*c)) {
            code.as_str()
        } else if has(ErrorCode::UnsupportedPool) {
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
            service: None,
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
            key_id: Some("abcdefgh2345".parse().unwrap()),
            scopes: vec![Scope::JobsRead],
            label: Some("agent".to_string()),
            daily_unit_cap: Some(Units::from_units(5)),
            allowed_images: Some(vec!["docker.io/library/*".to_string()]),
            expires_at: Some(time::macros::datetime!(2027-01-01 00:00:00 UTC)),
            principal: None,
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
            service: None,
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
            service: None,
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
            actor_device_id: None,
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
        let mut info = JoinTokenInfo::new(
            "jtk_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            "abcdefgh2345".parse().unwrap(),
            time::macros::datetime!(2026-11-05 10:00:00 UTC),
            time::macros::datetime!(2026-11-05 10:15:00 UTC),
        );
        info.label = Some("laptop".into());
        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v["created_by_key_id"], "abcdefgh2345");
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

    // ---------------------------------------------------------------------------------------------------------------
    // H2 (T2-01): JobSpec extension, service view, principals, devices, blobs, templates and errors.
    // ---------------------------------------------------------------------------------------------------------------

    /// H1 wire fixtures, captured by serializing with the H1 types before the H2 fields existed. Each one must
    /// deserialize and serialize again to exactly these bytes: an H1 peer sees no change (architect's ruling 4).
    const H1_FIXTURES: [(&str, &str); 10] = [
        (
            "spec_full",
            r#"{"name":"optional label","image":"docker.io/library/python:3.12-slim","command":["python","-c","print(6*7)"],"env":{"KEY":"value"},"files":[{"path":"/inputs/data.csv","content_b64":"aGk="}],"resources":{"cpu":2.0,"memory_mb":4096,"gpu":0,"disk_mb":10240},"timeout_s":3600,"egress":{"allow":["pypi.org","files.pythonhosted.org"]},"outputs":{"max_mb":1024},"placement":{"pools":["mine"],"node_id":null,"labels":{}},"retry":{"max_attempts":2},"idempotency_key":"optional"}"#,
        ),
        (
            "spec_minimal",
            r#"{"image":"python:3.12","command":["true"],"env":{},"files":[],"resources":{"cpu":0.5,"memory_mb":256,"gpu":0,"disk_mb":2048},"timeout_s":3600,"egress":{"allow":[]},"outputs":{"max_mb":1024},"placement":{"pools":["mine"],"node_id":null,"labels":{}},"retry":{"max_attempts":2}}"#,
        ),
        (
            "spec_pinned",
            r#"{"image":"ghcr.io/org/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":["/bin/app","--x"],"env":{"A":"1","B_2":""},"files":[],"resources":{"cpu":1.25,"memory_mb":128,"gpu":1,"disk_mb":1},"timeout_s":86400,"egress":{"allow":[]},"outputs":{"max_mb":1024},"placement":{"pools":["mine"],"node_id":"node_01ARZ3NDEKTSV4RRFFQ69G5FAV","labels":{"gpu.vendor/model":"x"}},"retry":{"max_attempts":5}}"#,
        ),
        (
            "view",
            r#"{"name":"optional label","image":"docker.io/library/python:3.12-slim","command":["python"],"env":{"KEY":"<redacted>"},"files":[{"path":"/inputs/data.csv","size":2,"sha256":"8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"}],"resources":{"cpu":2.0,"memory_mb":4096,"gpu":0,"disk_mb":2048},"timeout_s":3600,"egress":{"allow":[]},"outputs":{"max_mb":1024},"placement":{"pools":["mine"],"node_id":null,"labels":{}},"retry":{"max_attempts":2}}"#,
        ),
        (
            "job",
            r#"{"id":"job_01ARZ3NDEKTSV4RRFFQ69G5FAV","project_id":"prj_01ARZ3NDEKTSV4RRFFQ69G5FAV","name":"optional label","status":"running","attempt":1,"spec":{"name":"optional label","image":"docker.io/library/python:3.12-slim","command":["python"],"env":{"KEY":"<redacted>"},"files":[{"path":"/inputs/data.csv","size":2,"sha256":"8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"}],"resources":{"cpu":2.0,"memory_mb":4096,"gpu":0,"disk_mb":2048},"timeout_s":3600,"egress":{"allow":[]},"outputs":{"max_mb":1024},"placement":{"pools":["mine"],"node_id":null,"labels":{}},"retry":{"max_attempts":2}},"node_id":"node_01ARZ3NDEKTSV4RRFFQ69G5FAV","reason":null,"cancel_requested_at":null,"exit_code":null,"error":null,"estimated_units":2000,"created_at":"2026-11-05T10:00:00Z","started_at":"2026-11-05T10:01:00Z","finished_at":null,"attempts":[{"attempt":1,"node_id":"node_01ARZ3NDEKTSV4RRFFQ69G5FAV","outcome":"running","reason":null,"started_at":null,"ended_at":null}]}"#,
        ),
        (
            "whoami",
            r#"{"account_id":"acc_01ARZ3NDEKTSV4RRFFQ69G5FAV","project_id":"prj_01ARZ3NDEKTSV4RRFFQ69G5FAV","key_id":"abcdefgh2345","scopes":["jobs:read","jobs:write"],"label":"ci","daily_unit_cap":5000,"allowed_images":null,"expires_at":null}"#,
        ),
        ("join_token_req", r#"{"label":"laptop","ttl_s":900}"#),
        (
            "audit",
            r#"{"id":"aud_01ARZ3NDEKTSV4RRFFQ69G5FAV","at":"2026-11-05T10:00:00Z","kind":"key_created","actor_key_id":"abcdefgh2345","subject_id":"x","detail":{"n":1}}"#,
        ),
        (
            "usage_totals",
            r#"{"key":"job_01ARZ3NDEKTSV4RRFFQ69G5FAV","attempts":2,"reserved_cpu_ms":1,"reserved_gpu_ms":0,"used_cpu_ms":1,"max_rss_mb":3,"units":7,"estimated_attempts":1}"#,
        ),
        (
            "node",
            r#"{"id":"node_01ARZ3NDEKTSV4RRFFQ69G5FAV","name":"node-1","hostname":"node-1","state":"online","draining":false,"inventory":{"hostname":"node-1","platform":"linux","cpu":{"model":"Example CPU","cores":8},"memory_mb":1024,"os":"linux","arch":"x86_64","gpus":[],"gpu_status":{"status":"ok"},"dxg":false,"sandbox":[],"offered":{"cpu":4.0,"memory_mb":512,"gpu":0},"agent_version":"0.1.0"},"free":{"cpu":1.0,"memory_mb":1,"gpu":0},"labels":{},"last_seen":null,"created_at":"2026-11-05T10:00:00Z"}"#,
        ),
    ];

    fn reserialize<T: Serialize + serde::de::DeserializeOwned>(json: &str) -> String {
        serde_json::to_string(&serde_json::from_str::<T>(json).unwrap()).unwrap()
    }

    #[test]
    fn h1_wire_fixtures_are_byte_identical() {
        for (name, json) in H1_FIXTURES {
            let again = match name {
                n if n.starts_with("spec_") => reserialize::<JobSpec>(json),
                "view" => reserialize::<JobSpecView>(json),
                "job" => reserialize::<Job>(json),
                "whoami" => reserialize::<WhoAmI>(json),
                "join_token_req" => reserialize::<CreateJoinToken>(json),
                "audit" => reserialize::<AuditEvent>(json),
                "usage_totals" => reserialize::<UsageTotals>(json),
                "node" => reserialize::<Node>(json),
                other => panic!("unknown fixture {other}"),
            };
            assert_eq!(again, json, "{name}");
        }
        // The Lease an H1 agent receives for an H1 job is unchanged too: the same object (a `LeaseJob` is a JSON map,
        // whose keys were already sorted in H1, so compare values, not bytes).
        let spec: JobSpec = serde_json::from_str(H1_FIXTURES[0].1).unwrap();
        let lease_job = crate::protocol::LeaseJob::from_spec(&spec);
        assert_eq!(
            serde_json::to_value(&lease_job).unwrap(),
            serde_json::from_str::<serde_json::Value>(H1_FIXTURES[0].1).unwrap()
        );
        // And an H1 job still parses through the agent's strict check.
        assert_eq!(lease_job.parse_strict().unwrap(), spec);
    }

    /// The H2 §7.1 "Private AI chat" example, with placeholders filled in.
    fn service_json() -> serde_json::Value {
        json!({
            "kind": "service",
            "name": "Private AI chat",
            "image": format!("docker.io/ollama/ollama@sha256:{}", "a".repeat(64)),
            "command": ["/bin/ollama", "serve"],
            "env": {"OLLAMA_HOST": "127.0.0.1:11434", "OLLAMA_MODELS": "/volumes/models"},
            "resources": {"cpu": 4, "memory_mb": 8192, "gpu": 1, "disk_mb": 2048},
            "timeout_s": 2_592_000,
            "egress": {"allow": ["registry.ollama.example", "models.example.com"]},
            "service": {
                "ports": [{"port": 11434, "name": "api"}],
                "health": {"http_get": "/api/version", "port": 11434, "interval_s": 10, "timeout_s": 3,
                           "start_period_s": 600, "failure_threshold": 3},
                "idle_timeout_s": 3600,
                "restart": "on_node_loss"
            },
            "volumes": [{"name": "tpl:private-chat/models", "mount": "/volumes/models", "max_mb": 20480}],
            "placement": {"pools": ["mine"], "node_id": null, "labels": {}},
            "retry": {"max_attempts": 3},
            "idempotency_key": "optional"
        })
    }

    #[test]
    fn the_h2_service_example_parses_and_round_trips() {
        let spec: JobSpec = serde_json::from_value(service_json()).unwrap();
        assert_eq!(spec.kind, JobKind::Service);
        let service = spec.service.as_ref().unwrap();
        assert_eq!(
            service.ports,
            [ServicePort {
                port: 11434,
                name: "api".into()
            }]
        );
        let health = service.health.as_ref().unwrap();
        assert_eq!(health.http_get.as_deref(), Some("/api/version"));
        assert!(!health.tcp);
        assert_eq!(health.start_period_s, 600);
        assert_eq!(service.idle_timeout_s, Some(3600));
        assert_eq!(service.restart, RestartPolicy::OnNodeLoss);
        assert_eq!(spec.volumes[0].name, "tpl:private-chat/models");
        let back = serde_json::to_value(&spec).unwrap();
        assert_eq!(serde_json::from_value::<JobSpec>(back.clone()).unwrap(), spec);
        assert_eq!(back["kind"], "service");
    }

    /// The H2 §7.1 "Transcribe audio" example: a batch job with a blob input.
    #[test]
    fn the_h2_batch_example_with_a_blob_input_parses() {
        let digest = "b".repeat(64);
        let spec: JobSpec = serde_json::from_value(json!({
            "kind": "batch",
            "image": format!("ghcr.io/ggml-org/whisper.cpp@sha256:{}", "c".repeat(64)),
            "command": ["/bin/sh", "/inputs/.template/transcribe.sh"],
            "env": {"LANGUAGE": "auto", "MODEL": "small"},
            "inputs": [{"path": "/inputs/audio", "blob": format!("sha256:{digest}")}],
            "volumes": [{"name": "tpl:transcribe/models", "mount": "/volumes/models", "max_mb": 5120}],
            "resources": {"cpu": 4, "memory_mb": 4096, "gpu": 1, "disk_mb": 4096},
            "timeout_s": 3600
        }))
        .unwrap();
        assert_eq!(spec.kind, JobKind::Batch);
        assert_eq!(spec.inputs[0].blob.to_string(), format!("sha256:{digest}"));
        assert_eq!(spec.retry.max_attempts, DEFAULT_MAX_ATTEMPTS);
        // `kind: batch` is the default, so it is left out again.
        assert!(serde_json::to_value(&spec).unwrap().get("kind").is_none());
    }

    #[test]
    fn absent_timeout_and_attempts_take_the_default_of_the_kind() {
        let minimal = |kind: Option<&str>| {
            let mut v = json!({"image": "python:3.12", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 256}});
            if let Some(kind) = kind {
                v["kind"] = json!(kind);
            }
            serde_json::from_value::<JobSpec>(v).unwrap()
        };
        for spec in [minimal(None), minimal(Some("batch"))] {
            assert_eq!((spec.timeout_s, spec.retry.max_attempts), (3_600, 2));
        }
        let service = minimal(Some("service"));
        assert_eq!((service.timeout_s, service.retry.max_attempts), (2_592_000, 3));
        // An empty `retry` takes the default too; explicit values are kept for both kinds.
        let mut v = serde_json::to_value(&service).unwrap();
        v["retry"] = json!({});
        v.as_object_mut().unwrap().remove("timeout_s");
        let again: JobSpec = serde_json::from_value(v.clone()).unwrap();
        assert_eq!((again.timeout_s, again.retry.max_attempts), (2_592_000, 3));
        v["timeout_s"] = json!(60);
        v["retry"] = json!({"max_attempts": 1});
        let explicit: JobSpec = serde_json::from_value(v.clone()).unwrap();
        assert_eq!((explicit.timeout_s, explicit.retry.max_attempts), (60, 1));
        // As in H1, `null` is not a value for these fields.
        for (field, null) in [("timeout_s", json!(null)), ("retry", json!({"max_attempts": null}))] {
            let mut bad = v.clone();
            bad[field] = null;
            assert!(serde_json::from_value::<JobSpec>(bad).is_err(), "{field}");
        }
        // The view applies the same defaults (an older server could omit them).
        let mut view = serde_json::to_value(JobSpecView::from_stored(&service).unwrap()).unwrap();
        view.as_object_mut().unwrap().remove("timeout_s");
        view.as_object_mut().unwrap().remove("retry");
        let view: JobSpecView = serde_json::from_value(view).unwrap();
        assert_eq!((view.timeout_s, view.retry.max_attempts), (2_592_000, 3));
    }

    #[test]
    fn service_block_defaults_and_null_idle_timeout() {
        let parse = |service: serde_json::Value| {
            let mut v = service_json();
            v["service"] = service;
            serde_json::from_value::<JobSpec>(v).map(|s| s.service.unwrap())
        };
        let s = parse(json!({"ports": [{"port": 80, "name": "http"}]})).unwrap();
        assert_eq!(s.idle_timeout_s, Some(DEFAULT_IDLE_TIMEOUT_S));
        assert_eq!(s.restart, RestartPolicy::OnNodeLoss);
        assert!(s.health.is_none());
        // `null` means never; absent means the default.
        let never = parse(json!({"ports": [{"port": 80, "name": "http"}], "idle_timeout_s": null})).unwrap();
        assert_eq!(never.idle_timeout_s, None);
        let tcp = parse(json!({"ports": [{"port": 80, "name": "http"}], "restart": "never",
            "health": {"tcp": true, "port": 80}}))
        .unwrap();
        let h = tcp.health.unwrap();
        assert_eq!(
            (h.tcp, h.interval_s, h.timeout_s, h.start_period_s, h.failure_threshold),
            (true, 10, 3, 300, 3)
        );
        assert_eq!(tcp.restart, RestartPolicy::Never);
        // Strict: unknown fields in the new request types are refused.
        assert!(parse(json!({"ports": [{"port": 80, "name": "http", "proto": "udp"}]})).is_err());
        assert!(parse(json!({"ports": [], "replicas": 2})).is_err());
        assert!(parse(json!({"ports": [], "restart": "always"})).is_err());
        let mut v = service_json();
        v["volumes"][0]["path"] = json!("/x");
        assert!(serde_json::from_value::<JobSpec>(v).is_err());
        let mut v = service_json();
        v["template"] = json!({"id": "private-chat", "version": 1, "pull": null, "extra": 1});
        assert!(serde_json::from_value::<JobSpec>(v).is_err());
        let mut v = service_json();
        v["kind"] = json!("daemon");
        assert!(serde_json::from_value::<JobSpec>(v).is_err());
    }

    #[test]
    fn the_view_of_a_service_keeps_its_h2_fields_and_tolerates_new_ones() {
        let mut spec: JobSpec = serde_json::from_value(service_json()).unwrap();
        spec.inputs.push(BlobInput {
            path: "/inputs/a".into(),
            blob: BlobRef(Sha256Digest([1; 32])),
        });
        spec.template = Some(TemplateRef {
            id: "private-chat".into(),
            version: 2,
            pull: Some("model:4b".into()),
        });
        let view = JobSpecView::from_stored(&spec).unwrap();
        assert_eq!(view.kind, JobKind::Service);
        assert_eq!(view.service.as_ref().unwrap().ports[0].port, 11434);
        assert_eq!(view.volumes[0].max_mb, 20480);
        assert_eq!(view.inputs[0].path, "/inputs/a");
        assert_eq!(view.template.as_ref().unwrap().pull.as_deref(), Some("model:4b"));
        assert!(view.env.values().all(|v| v == REDACTED));
        let mut v = serde_json::to_value(&view).unwrap();
        assert!(v.get("idempotency_key").is_none());
        for path in ["service", "volumes/0", "inputs/0", "template"] {
            let pointer = format!("/{path}");
            v.pointer_mut(&pointer).unwrap()["future_field"] = json!(1);
        }
        v["service"]["ports"][0]["future_field"] = json!(1);
        v["service"]["health"]["future_field"] = json!(1);
        assert_eq!(serde_json::from_value::<JobSpecView>(v).unwrap(), view);
    }

    #[test]
    fn a_service_job_carries_the_service_view() {
        let spec: JobSpec = serde_json::from_value(service_json()).unwrap();
        let mut job = Job::new(
            JobId::generate(),
            ProjectId::generate(),
            JobStatus::Running,
            1,
            JobSpecView::from_stored(&spec).unwrap(),
            Units::ZERO,
            time::macros::datetime!(2026-11-05 10:00:00 UTC),
        );
        assert!(serde_json::to_value(&job).unwrap().get("service").is_none());
        job.service = Some(ServiceView {
            health: Some(ServiceHealth::Healthy),
            ports: job.spec.service.as_ref().unwrap().ports.clone(),
            open_connections: 2,
            restarts_24h: 1,
            setup: Some(ServiceSetup {
                state: SetupState::Failed,
                completed_mb: 10,
                total_mb: Some(2_500),
                tries: 2,
                reason: Some(SetupFailure::StreamBroken),
            }),
            traffic: Some(ServiceTraffic {
                day: time::macros::datetime!(2026-11-05 00:00:00 UTC),
                bytes_in: 1,
                bytes_out: 2,
                connections: 3,
            }),
            ..ServiceView::default()
        });
        let v = serde_json::to_value(&job).unwrap();
        assert_eq!(v["service"]["health"], "healthy");
        assert_eq!(v["service"]["setup"]["reason"], "stream_broken");
        assert_eq!(v["service"]["traffic"]["day"], "2026-11-05T00:00:00Z");
        assert!(v["service"]["idle_deadline"].is_null());
        assert_eq!(serde_json::from_value::<Job>(v).unwrap(), job);
        // Every field of the view defaults: an older or newer server's view parses.
        assert_eq!(
            serde_json::from_value::<ServiceView>(json!({"later": true})).unwrap(),
            ServiceView::default()
        );
        for (health, name) in [
            (ServiceHealth::Starting, "starting"),
            (ServiceHealth::Unhealthy, "unhealthy"),
        ] {
            assert_eq!(serde_json::to_value(health).unwrap(), json!(name));
        }
        for (reason, name) in [
            (SetupFailure::ErrorLine, "error_line"),
            (SetupFailure::BadLine, "bad_line"),
            (SetupFailure::Eof, "eof"),
            (SetupFailure::Deadline, "deadline"),
        ] {
            assert_eq!(serde_json::to_value(reason).unwrap(), json!(name));
        }
    }

    #[test]
    fn blob_refs_are_sha256_prefixed_lowercase_hex() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let r: BlobRef = format!("sha256:{hex}").parse().unwrap();
        assert_eq!(r.0.to_string(), hex);
        assert_eq!(serde_json::to_value(r).unwrap(), json!(format!("sha256:{hex}")));
        for bad in [
            hex.to_string(),
            format!("SHA256:{hex}"),
            format!("sha256:{}", hex.to_uppercase()),
            format!("sha256:{}", &hex[..63]),
            format!("sha512:{hex}"),
            format!("sha256: {hex}"),
        ] {
            assert_eq!(bad.parse::<BlobRef>(), Err(InvalidBlobRef), "{bad}");
        }
    }

    #[test]
    fn principals_serialize_as_kind_and_id_and_label_for_usage() {
        let key: KeyId = "abcdefgh2345".parse().unwrap();
        let dev: DeviceId = "dev_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap();
        assert_eq!(
            serde_json::to_value(Principal::Key(key)).unwrap(),
            json!({"kind": "key", "id": "abcdefgh2345"})
        );
        assert_eq!(
            serde_json::to_value(Principal::Device(dev)).unwrap(),
            json!({"kind": "device", "id": "dev_01ARZ3NDEKTSV4RRFFQ69G5FAV"})
        );
        assert!(serde_json::from_value::<Principal>(json!({"kind": "device", "id": "abcdefgh2345"})).is_err());
        assert!(serde_json::from_value::<Principal>(json!({"kind": "node", "id": "x"})).is_err());
        for p in [Principal::Key(key), Principal::Device(dev)] {
            assert_eq!(p.to_string().parse::<Principal>(), Ok(p));
        }
        // Built from the key ID rather than spelled out, so no literal looks like a credential.
        assert_eq!(Principal::Key(key).to_string(), format!("key:{key}"));
        assert_eq!(
            (Principal::Key(key).key_id(), Principal::Key(key).device_id()),
            (Some(key), None)
        );
        assert_eq!(Principal::Device(dev).device_id(), Some(dev));
        let bad = [
            key.to_string(),
            "key:".into(),
            format!("device:{key}"),
            format!("Key:{key}"),
        ];
        for bad in &bad {
            assert_eq!(bad.parse::<Principal>(), Err(InvalidPrincipal), "{bad}");
        }
    }

    #[test]
    fn whoami_principal_is_additive() {
        let mut w: WhoAmI = serde_json::from_str(H1_FIXTURES[5].1).unwrap();
        assert_eq!(w.principal, None);
        let key = w.key_id.unwrap();
        w.principal = Some(Principal::Key(key));
        let v = serde_json::to_value(&w).unwrap();
        assert_eq!(v["principal"], json!({"kind": "key", "id": "abcdefgh2345"}));
        assert_eq!(v["key_id"], "abcdefgh2345");
        assert_eq!(serde_json::from_value::<WhoAmI>(v).unwrap(), w);
        // A device (H2 §5.5): `key_id` stays in the body, as `null`.
        let dev: DeviceId = "dev_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap();
        w.key_id = None;
        w.principal = Some(Principal::Device(dev));
        let v = serde_json::to_value(&w).unwrap();
        assert_eq!(v["key_id"], serde_json::Value::Null);
        assert_eq!(v["principal"], json!({"kind": "device", "id": dev.to_string()}));
        assert_eq!(serde_json::from_value::<WhoAmI>(v).unwrap(), w);
    }

    /// H2 §5.6: a token names its minter. A key's token keeps H1's `created_by_key_id`; a device's has it `null`.
    /// `pre_approved` and `bound_iroh_node_id` are left out at their H1 values.
    #[test]
    fn join_token_info_names_a_key_or_a_device() {
        // A row ID from the ULID spec's example, not a secret.
        let id: JoinTokenId = "jtk_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(); // gitleaks:allow
        let (at, until) = (
            time::macros::datetime!(2026-11-05 10:00:00 UTC),
            time::macros::datetime!(2026-11-05 10:15:00 UTC),
        );
        let key: KeyId = "abcdefgh2345".parse().unwrap();
        let by_key = JoinTokenInfo::by_principal(id, Principal::Key(key), at, until);
        let v = serde_json::to_value(&by_key).unwrap();
        assert_eq!(v["created_by_key_id"], "abcdefgh2345");
        assert_eq!(v["created_by"], json!({"kind": "key", "id": "abcdefgh2345"}));
        assert!(
            v.get("pre_approved").is_none() && v.get("bound_iroh_node_id").is_none(),
            "{v}"
        );
        assert_eq!(serde_json::from_value::<JoinTokenInfo>(v).unwrap(), by_key);
        let dev: DeviceId = "dev_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap();
        let mut by_device = JoinTokenInfo::by_principal(id, Principal::Device(dev), at, until);
        by_device.pre_approved = true;
        by_device.bound_iroh_node_id = Some("ab".repeat(32));
        let v = serde_json::to_value(&by_device).unwrap();
        assert_eq!(v["created_by_key_id"], serde_json::Value::Null);
        assert_eq!(v["created_by"], json!({"kind": "device", "id": dev.to_string()}));
        assert_eq!(v["pre_approved"], true);
        assert_eq!(v["bound_iroh_node_id"], "ab".repeat(32));
        assert_eq!(serde_json::from_value::<JoinTokenInfo>(v).unwrap(), by_device);
        // An H1 server's listing still parses: the new fields default.
        let h1 = json!({
            "id": id, "label": null, "created_by_key_id": "abcdefgh2345",
            "created_at": "2026-11-05T10:00:00Z", "expires_at": "2026-11-05T10:15:00Z",
            "consumed_at": null, "consumed_by_node_id": null, "revoked_at": null,
        });
        assert_eq!(
            serde_json::from_value::<JoinTokenInfo>(h1).unwrap(),
            JoinTokenInfo::new(id, key, at, until)
        );
    }

    #[test]
    fn h2_scopes_audit_kinds_and_profiles_use_the_spec_names() {
        let names: Vec<&str> = Scope::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            names,
            [
                "admin",
                "jobs:write",
                "jobs:read",
                "nodes:read",
                "nodes:write",
                "services:connect",
                "templates:launch",
                "blobs:write",
                "nodes:invite",
                "nodes:join"
            ]
        );
        for s in Scope::ALL {
            assert_eq!(serde_json::to_value(s).unwrap(), json!(s.as_str()));
        }
        use Scope::*;
        assert_eq!(PHONE_PROFILE, [NodesRead, TemplatesLaunch, BlobsWrite, NodesInvite]);
        // The developer profile is the phone profile plus exactly four scopes.
        assert_eq!(&DEVELOPER_DEVICE_PROFILE[..4], &PHONE_PROFILE);
        assert_eq!(
            &DEVELOPER_DEVICE_PROFILE[4..],
            &[JobsRead, JobsWrite, ServicesConnect, NodesJoin]
        );
        assert!(!PHONE_PROFILE.contains(&JobsWrite) && !PHONE_PROFILE.contains(&NodesJoin));
        assert_eq!(OWNER_PROFILE, [Admin]);

        let h2_kinds = [
            "pairing_ticket_created",
            "pairing_ticket_revoked",
            "device_paired",
            "device_revoked",
            "device_added_offline",
            "device_revoked_offline",
            "join_request_created",
            "join_request_revealed",
            "join_request_reveal_failed",
            "join_request_approved",
            "join_request_rejected",
            "join_request_delivered",
            "node_approved",
            "node_left",
            "template_bundle_loaded",
        ];
        let wire: Vec<serde_json::Value> = AuditKind::ALL
            .iter()
            .map(|k| serde_json::to_value(k).unwrap())
            .collect();
        assert_eq!(&wire[10..], h2_kinds.map(|k| json!(k)).as_slice());
        let unique: std::collections::BTreeSet<String> = wire.iter().map(ToString::to_string).collect();
        assert_eq!(unique.len(), AuditKind::ALL.len());
    }

    #[test]
    fn audit_actor_device_is_additive() {
        let mut e: AuditEvent = serde_json::from_str(H1_FIXTURES[7].1).unwrap();
        assert_eq!(e.actor_device_id, None);
        e.actor_key_id = None;
        e.actor_device_id = Some("dev_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap());
        e.kind = AuditKind::DevicePaired;
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["actor_device_id"], "dev_01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(serde_json::from_value::<AuditEvent>(v).unwrap(), e);
    }

    #[test]
    fn node_approval_fields_are_additive() {
        let mut node: Node = serde_json::from_str(H1_FIXTURES[9].1).unwrap();
        assert_eq!(
            (node.approval, node.enrolled_by, node.node_phrase.clone()),
            (NodeApproval::Approved, None, None)
        );
        node.approval = NodeApproval::PendingApproval;
        node.enrolled_by = Some(Principal::Device("dev_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()));
        node.node_phrase = Some("one two three four five six".into());
        let v = serde_json::to_value(&node).unwrap();
        assert_eq!(v["approval"], "pending_approval");
        assert_eq!(v["enrolled_by"]["kind"], "device");
        assert_eq!(serde_json::from_value::<Node>(v).unwrap(), node);
    }

    #[test]
    fn server_info_api_version_is_one_when_absent_and_two_for_h2() {
        let address = crate::auth::ServerAddress::new(
            "b".repeat(64),
            vec![url::Url::parse("https://relay.example.invalid/").unwrap()],
        );
        let h1 = ServerInfo::new(address, "0.1.0");
        assert_eq!(h1.api_version, API_VERSION_H1);
        let v = serde_json::to_value(&h1).unwrap();
        assert_eq!(keys_of(&v), ["address", "node_id", "relays", "version"]);
        assert_eq!(serde_json::from_value::<ServerInfo>(v).unwrap().api_version, 1);
        let h2 = ServerInfo {
            api_version: API_VERSION_H2,
            hub_name: Some("Home".into()),
            max_blob_mb: Some(DEFAULT_MAX_BLOB_MB),
            min_web_version: Some("0.2.0".into()),
            ..h1
        };
        let v = serde_json::to_value(&h2).unwrap();
        assert_eq!(
            (v["api_version"].clone(), v["max_blob_mb"].clone()),
            (json!(2), json!(2048))
        );
        assert_eq!(serde_json::from_value::<ServerInfo>(v).unwrap(), h2);
        let patch: UpdateServer = serde_json::from_value(json!({"hub_name": "Home"})).unwrap();
        assert_eq!(patch.hub_name, "Home");
        assert!(serde_json::from_value::<UpdateServer>(json!({"hub_name": "x", "api_version": 3})).is_err());
    }

    #[test]
    fn join_token_pre_approved_and_usage_estimated_slices_are_additive() {
        let req: CreateJoinToken = serde_json::from_value(json!({"pre_approved": true, "ttl_s": 900})).unwrap();
        assert!(req.pre_approved);
        assert_eq!(serde_json::to_value(&req).unwrap()["pre_approved"], true);
        let mut t: UsageTotals = serde_json::from_str(H1_FIXTURES[8].1).unwrap();
        assert_eq!(t.estimated_slices, 0);
        t.estimated_slices = 4;
        assert_eq!(serde_json::to_value(&t).unwrap()["estimated_slices"], 4);
    }

    #[test]
    fn h2_error_codes_are_unique_snake_case_with_the_spec_statuses() {
        let mut seen = std::collections::BTreeSet::new();
        for code in H2ErrorCode::ALL {
            let s = code.as_str();
            assert!(seen.insert(s), "{s}");
            assert_eq!(serde_json::to_value(code).unwrap(), json!(s));
            assert!(s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{s}");
            if let Some(p) = code.problem("t") {
                assert_eq!((p.code.as_str(), Some(p.status)), (s, code.http_status()));
            }
        }
        use H2ErrorCode::*;
        for (code, status) in [
            (InvalidTicket, None),
            (NotPaired, None),
            (UnexpectedAuthorization, Some(400)),
            (RouteNotAllowed, Some(403)),
            (HeadersTooLarge, Some(431)),
            (ServiceNotReady, Some(409)),
            (PortNotExposed, Some(422)),
            (TooManyConnections, Some(429)),
            (NodeUnreachable, Some(502)),
            (QuotaExceeded, Some(507)),
            (NodeOffline, Some(503)),
            (TemplatesUnavailable, Some(503)),
            (UnknownTemplate, Some(404)),
            (VolumesNotAllowed, Some(422)),
            (ReadOnlyField, Some(422)),
            (JoinRequestClosed, Some(409)),
        ] {
            assert_eq!(code.http_status(), status, "{code}");
        }
        // The validation codes with an H2 problem code use the same names.
        use crate::validate::ErrorCode as E;
        for (field_code, problem) in [
            (E::ReadOnlyField, ReadOnlyField),
            (E::VolumesNotAllowed, VolumesNotAllowed),
            (E::InputsExceedDisk, InputsExceedDisk),
            (E::UnknownBlob, UnknownBlob),
        ] {
            assert_eq!(field_code.as_str(), problem.as_str());
        }
    }

    #[test]
    fn problem_codes_for_the_h2_validation_errors() {
        use crate::validate::{ErrorCode, H2Features, Limits, SpecContext};
        let limits = Limits {
            h2: H2Features::ALL,
            ..Limits::default()
        };
        let mut spec: JobSpec = serde_json::from_value(service_json()).unwrap();
        spec.volumes.clear();
        assert_eq!(spec.validate(&limits), Ok(()));
        let code = |s: &JobSpec, ctx| Problem::from_validation(&s.validate_in(&limits, ctx).unwrap_err()).code;
        let mut with_template = spec.clone();
        with_template.template = Some(TemplateRef {
            id: "private-chat".into(),
            version: 1,
            pull: None,
        });
        assert_eq!(code(&with_template, SpecContext::Create), "read_only_field");
        let mut batch = spec.clone();
        batch.kind = JobKind::Batch;
        batch.service = None;
        batch.timeout_s = 3_600;
        batch.volumes =
            serde_json::from_value(json!([{"name": "data", "mount": "/volumes/data", "max_mb": 64}])).unwrap();
        assert_eq!(code(&batch, SpecContext::Create), "volumes_not_allowed");
        let errs = batch.check_inputs_fit_disk(0);
        assert_eq!(errs, Ok(()), "no inputs: the disk rule does not apply");
        batch.inputs.push(BlobInput {
            path: "/inputs/a".into(),
            blob: BlobRef(Sha256Digest([0; 32])),
        });
        let disk = batch.check_inputs_fit_disk(u64::MAX).unwrap_err();
        assert!(disk.contains("inputs", ErrorCode::InputsExceedDisk));
        assert_eq!(Problem::from_validation(&disk).code, "inputs_exceed_disk");
        // Out of range stays H1's `validation_failed`, with the field code `out_of_range`.
        let mut long = spec.clone();
        long.timeout_s = 2_592_001;
        assert_eq!(code(&long, SpecContext::Create), "validation_failed");
    }

    #[test]
    fn secrets_in_h2_responses_are_redacted_in_debug() {
        let created = PairingTicketCreated {
            id: "ptk_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(),
            ticket: "p2pc_pair_SECRETPAYLOAD".into(), // gitleaks:allow
            url: "https://app.example.invalid/pair#p2pc_pair_SECRETPAYLOAD".into(), // gitleaks:allow
            expires_at: time::macros::datetime!(2026-11-05 10:10:00 UTC),
        };
        let dbg = format!("{created:?}");
        assert!(!dbg.contains("SECRETPAYLOAD"), "{dbg}");
        // Serialization shows them: this response is the one time the ticket is shown.
        assert!(serde_json::to_string(&created).unwrap().contains("SECRETPAYLOAD"));
        let reveal = RevealJoinRequest {
            listener_nonce: "7".repeat(64),
        };
        assert!(!format!("{reveal:?}").contains("7777"));
    }

    #[test]
    fn device_info_liveness_and_unrestricted_admin() {
        let now = time::macros::datetime!(2026-11-05 10:00:00 UTC);
        let by = Principal::Key("abcdefgh2345".parse().unwrap());
        let mut d = DeviceInfo::new(DeviceId::generate(), "iOS Safari", vec![Scope::Admin], now, by);
        assert!(d.is_live(now) && d.is_unrestricted_admin());
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["paired_by"], json!({"kind": "key", "id": "abcdefgh2345"}));
        assert_eq!(serde_json::from_value::<DeviceInfo>(v).unwrap(), d);
        d.expires_at = Some(now);
        assert!(!d.is_live(now) && !d.is_unrestricted_admin());
        d.expires_at = Some(now + time::Duration::seconds(1));
        assert!(d.is_live(now));
        d.expires_at = None;
        d.blobs_quota_mb = Some(1);
        assert!(!d.is_unrestricted_admin());
        d.blobs_quota_mb = None;
        d.revoked_at = Some(now);
        assert!(!d.is_live(now));
        d.scopes = PHONE_PROFILE.to_vec();
        assert!(!d.is_unrestricted_admin());
    }

    #[test]
    fn param_targets_parse_only_the_spec_forms() {
        use std::str::FromStr;
        for (text, target) in [
            ("env:LANGUAGE", ParamTarget::Env("LANGUAGE".into())),
            ("argv:0", ParamTarget::Argv(0)),
            ("argv:12", ParamTarget::Argv(12)),
            ("field:timeout_s", ParamTarget::Field(ParamField::TimeoutS)),
            (
                "field:service.idle_timeout_s",
                ParamTarget::Field(ParamField::ServiceIdleTimeoutS),
            ),
            ("input:/inputs/audio", ParamTarget::Input("/inputs/audio".into())),
            ("pull", ParamTarget::Pull),
        ] {
            assert_eq!(ParamTarget::from_str(text), Ok(target.clone()), "{text}");
            assert_eq!(target.to_string(), text);
            assert_eq!(serde_json::to_value(&target).unwrap(), json!(text));
        }
        for bad in [
            "env:P2PC_TOKEN",
            "env:lower",
            "env:",
            "argv:-1",
            "argv:01",
            "argv: 1",
            "argv:99999999999",
            "field:resources.gpu",
            "field:image",
            "input:/etc/passwd",
            "input:/inputs/../x",
            "input:/inputs",
            "pull:x",
            "shell:echo",
            "",
        ] {
            assert_eq!(ParamTarget::from_str(bad), Err(InvalidParamTarget), "{bad}");
        }
        assert_eq!(ParamField::TimeoutS.range(JobKind::Batch), Some((1, 86_400)));
        assert_eq!(ParamField::TimeoutS.range(JobKind::Service), Some((60, 2_592_000)));
        assert_eq!(
            ParamField::ServiceIdleTimeoutS.range(JobKind::Service),
            Some((300, 604_800))
        );
        assert_eq!(ParamField::ServiceIdleTimeoutS.range(JobKind::Batch), None);
    }

    #[test]
    fn template_shapes() {
        let entry = json!({
            "id": "private-chat", "version": 1, "title": "Private AI chat", "description": "Chat with a model",
            "kind": "service", "ui": "chat", "singleton": true,
            "requirements": {"gpu": "preferred", "min_vram_mb": 6144},
            "params": [
                {"name": "model", "type": "enum", "values": ["m-small", "m-large"], "default": "m-small",
                 "target": "pull"},
                {"name": "idle", "type": "int", "min": 900, "max": 86400, "default": 3600,
                 "target": "field:service.idle_timeout_s"},
                {"name": "audio", "type": "blob", "target": "input:/inputs/audio"}
            ],
            "licenses": ["Ollama: MIT"], "download_mb": 2600,
            "spec": service_json(),
            "allowed_routes": [{"port": 11434, "method": "POST", "path": "/api/chat"}]
        });
        let t: Template = serde_json::from_value(entry).unwrap();
        assert_eq!(
            t.info.params[0].ty,
            ParamType::Enum {
                values: vec!["m-small".into(), "m-large".into()]
            }
        );
        assert_eq!(t.info.params[1].default, Some(ParamValue::Int(3600)));
        assert_eq!(t.info.params[2].target, ParamTarget::Input("/inputs/audio".into()));
        assert_eq!(t.info.requirements.gpu, GpuRequirement::Preferred);
        assert_eq!(t.allowed_routes[0].path, "/api/chat");
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["params"][1]["type"], "int");
        assert_eq!(serde_json::from_value::<Template>(v).unwrap(), t);
        // The listing never carries the spec or the routes.
        let list = TemplateList {
            bundle_version: Some(7),
            templates: vec![t.info.clone()],
            bundle_error: None,
        };
        let text = serde_json::to_string(&list).unwrap();
        assert!(
            !text.contains("allowed_routes") && !text.contains("OLLAMA_HOST"),
            "{text}"
        );
        let launch: LaunchTemplate =
            serde_json::from_value(json!({"params": {"model": "m-small", "idle": 900, "gpu": false}})).unwrap();
        assert_eq!(launch.params["idle"], ParamValue::Int(900));
        assert_eq!(launch.params["gpu"], ParamValue::Bool(false));
        assert!(serde_json::from_value::<LaunchTemplate>(json!({"params": {}, "template": "x"})).is_err());
    }

    #[test]
    fn h2_request_bodies_reject_unknown_fields() {
        assert!(serde_json::from_value::<CreatePairingTicket>(json!({})).is_ok());
        assert!(serde_json::from_value::<CreatePairingTicket>(json!({"scope": ["admin"]})).is_err());
        let req = json!({"listener_node_id": "a".repeat(64), "iroh_node_id": "b".repeat(64),
            "invite_expires_at": "2026-11-05T10:15:00Z", "listener_commitment": "c".repeat(64)});
        assert!(serde_json::from_value::<CreateJoinRequest>(req.clone()).is_ok());
        let mut extra = req;
        extra["code"] = json!("x");
        assert!(serde_json::from_value::<CreateJoinRequest>(extra).is_err());
        assert!(serde_json::from_value::<RevealJoinRequest>(json!({"listener_nonce": "a", "x": 1})).is_err());
    }

    proptest::proptest! {
        /// Ruling 4: an absent `timeout_s` or `retry.max_attempts` takes the default of the kind; a present one is
        /// kept; and the spec round-trips through its own serialization.
        #[test]
        fn wire_defaults_follow_the_kind(
            service in proptest::bool::ANY,
            timeout in proptest::option::of(1u32..3_000_000),
            attempts in proptest::option::of(1u32..6),
            retry_object in proptest::bool::ANY,
        ) {
            let kind = if service { JobKind::Service } else { JobKind::Batch };
            let mut v = json!({"image": "python:3.12", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 256}});
            if service {
                v["kind"] = json!("service");
                v["service"] = json!({"ports": [{"port": 80, "name": "http"}]});
            }
            if let Some(t) = timeout {
                v["timeout_s"] = json!(t);
            }
            match (attempts, retry_object) {
                (Some(a), _) => v["retry"] = json!({"max_attempts": a}),
                (None, true) => v["retry"] = json!({}),
                (None, false) => {}
            }
            let spec: JobSpec = serde_json::from_value(v).unwrap();
            proptest::prop_assert_eq!(spec.kind, kind);
            proptest::prop_assert_eq!(spec.timeout_s, timeout.unwrap_or(kind.default_timeout_s()));
            proptest::prop_assert_eq!(spec.retry.max_attempts, attempts.unwrap_or(kind.default_max_attempts()));
            let text = serde_json::to_string(&spec).unwrap();
            let back: JobSpec = serde_json::from_str(&text).unwrap();
            proptest::prop_assert_eq!(&back, &spec);
            proptest::prop_assert_eq!(serde_json::to_string(&back).unwrap(), text);
        }

        /// An H1-shaped spec (no H2 field) serializes with no H2 key, so H1 peers read it, and re-serializes to the
        /// same bytes.
        #[test]
        fn h1_shaped_specs_have_no_h2_keys_and_stable_bytes(
            name in proptest::option::of("[a-z ]{0,8}"),
            env in proptest::collection::btree_map("[A-Z]{1,4}", "[a-z0-9]{0,4}", 0..4),
            timeout in 1u32..86_401,
            attempts in 1u32..6,
            node in proptest::bool::ANY,
            idem in proptest::option::of("[a-z0-9]{1,8}"),
        ) {
            let mut spec: JobSpec = serde_json::from_value(spec_json()).unwrap();
            spec.name = name;
            spec.env = env;
            spec.timeout_s = timeout;
            spec.retry.max_attempts = attempts;
            spec.placement.node_id = node.then(|| "node_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap());
            spec.idempotency_key = idem;
            let text = serde_json::to_string(&spec).unwrap();
            for key in ["\"kind\"", "\"service\"", "\"volumes\"", "\"inputs\"", "\"template\""] {
                proptest::prop_assert!(!text.contains(key), "{} in {}", key, text);
            }
            proptest::prop_assert_eq!(reserialize::<JobSpec>(&text), text.clone());
            let view = serde_json::to_string(&JobSpecView::from_stored(&spec).unwrap()).unwrap();
            proptest::prop_assert_eq!(reserialize::<JobSpecView>(&view), view);
        }
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
            UpdateServer,
            Principal,
            ServiceView,
            BlobUploaded,
            BlobList,
            VolumeInfo,
            TemplateList,
            LaunchTemplate,
            Template,
            CreatePairingTicket,
            PairingTicketCreated,
            PairingTicketInfo,
            DeviceInfo,
            CreateJoinRequest,
            JoinRequestCreated,
            RevealJoinRequest,
            JoinRequestInfo,
            JoinRequestToken,
            H2ErrorCode,
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
        // H2: the new JobSpec fields are optional, in both families, and the new request types are closed.
        for schema in ["JobSpec", "JobSpecView"] {
            for field in ["kind", "service", "volumes", "inputs", "template"] {
                assert!(schemas[schema]["properties"].get(field).is_some(), "{schema}.{field}");
            }
            let required = schemas[schema]["required"].as_array().unwrap();
            assert_eq!(
                required,
                &[json!("image"), json!("command"), json!("resources")],
                "{schema}"
            );
        }
        for closed in [
            "ServiceSpec",
            "ServicePort",
            "HealthCheck",
            "VolumeSpec",
            "BlobInput",
            "TemplateRef",
        ] {
            assert_eq!(schemas[closed]["additionalProperties"], json!(false), "{closed}");
            assert_ne!(
                schemas[format!("{closed}View").as_str()]["additionalProperties"],
                json!(false),
                "{closed}View"
            );
        }
        assert!(schemas["Job"]["properties"].get("service").is_some());
        for name in [
            "Principal",
            "DeviceInfo",
            "TemplateList",
            "BlobList",
            "H2ErrorCode",
            "JoinRequestInfo",
        ] {
            assert!(schemas.get(name).is_some(), "missing schema {name}");
        }
    }
}
