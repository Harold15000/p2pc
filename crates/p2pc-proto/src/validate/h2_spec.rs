// SPDX-License-Identifier: Apache-2.0

//! The H2 rows of the JobSpec validation table (H2 spec §7.1): `service`, `volumes`, `inputs` and `template`.
//!
//! They run from [`JobSpec::validate_in`] after the H1 rows. A batch job with none of these fields gets no error
//! from here, so every H1 rule holds exactly for it. Messages never quote env values or file contents.

use std::collections::BTreeSet;

use super::{
    Collector, ErrorCode, H2Features, MAX_IDLE_TIMEOUT_S, MAX_PATH_LEN, MIN_IDLE_TIMEOUT_S, PathError, PathSetIssue,
    SpecContext, ValidationErrors, base64_decoded_len, check_relative, path_set_issues, validate_input_path,
};
use crate::api::{HealthCheck, JobKind, JobSpec, ServiceSpec, TemplateRef};

/// Most `service.ports`.
pub const MAX_SERVICE_PORTS: usize = 8;
/// Longest `service.health.http_get`, in bytes.
pub const MAX_HEALTH_PATH_LEN: usize = 256;
/// `service.health.interval_s` range.
pub const HEALTH_INTERVAL_S: (u32, u32) = (2, 300);
/// `service.health.timeout_s` range.
pub const HEALTH_TIMEOUT_S: (u32, u32) = (1, 60);
/// `service.health.start_period_s` range.
pub const HEALTH_START_PERIOD_S: (u32, u32) = (0, 3_600);
/// `service.health.failure_threshold` range.
pub const HEALTH_FAILURE_THRESHOLD: (u32, u32) = (1, 20);
/// Most `volumes`.
pub const MAX_VOLUMES: usize = 4;
/// Smallest `volumes[].max_mb`.
pub const MIN_VOLUME_MB: u64 = 64;
/// Largest `volumes[].max_mb` (256 GiB).
pub const MAX_VOLUME_MB: u64 = 262_144;
/// Directory that volumes are mounted under.
pub const VOLUMES_DIR: &str = "/volumes";
/// The prefix of a template volume name, `tpl:<template id>/<name>`.
pub const TEMPLATE_VOLUME_PREFIX: &str = "tpl:";
/// Most blob `inputs`.
pub const MAX_BLOB_INPUTS: usize = 32;
/// What blob inputs and inline files leave free of `resources.disk_mb`, in MiB (H2 §7.1 `inputs`).
pub const INPUTS_DISK_RESERVE_MB: u64 = 64;
/// Longest `template.pull`, in bytes.
pub const MAX_TEMPLATE_PULL_LEN: usize = 256;

/// `[a-z0-9][a-z0-9._-]{0,62}`: a plain volume name, and the `<name>` of a template volume.
fn is_volume_label(s: &str) -> bool {
    let b = s.as_bytes();
    let first = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let rest = |c: &u8| first(c) || matches!(c, b'.' | b'_' | b'-');
    (1..=63).contains(&b.len()) && b.first().is_some_and(first) && b[1..].iter().all(rest)
}

/// Whether `id` is a valid template id: `[a-z][a-z0-9-]{0,62}`. No `/`, `:` or `.`, so it can sit inside a volume
/// name `tpl:<id>/<name>` and a bundle file name without ambiguity.
#[must_use]
pub fn is_template_id(id: &str) -> bool {
    let b = id.as_bytes();
    (1..=63).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// A parsed volume name (H2 §7.1): a label, never a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VolumeName<'a> {
    /// `[a-z0-9][a-z0-9._-]{0,62}`.
    Plain(&'a str),
    /// `tpl:<template id>/<name>`: only a template launch may use it (SI-H2-9).
    Template {
        /// The template's id.
        template_id: &'a str,
        /// The volume's name within the template.
        name: &'a str,
    },
}

/// Why a volume name is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("must match [a-z0-9][a-z0-9._-]{{0,62}}, or tpl:<template id>/<name>")]
pub struct VolumeNameError;

impl<'a> VolumeName<'a> {
    /// Parses a volume name: the rule of the JobSpec, and of the `{name}` segment of
    /// `DELETE /v1/volumes/{node_id}/{name}` once decoded (H2 §7.3).
    pub fn parse(name: &'a str) -> Result<Self, VolumeNameError> {
        if let Some(rest) = name.strip_prefix(TEMPLATE_VOLUME_PREFIX) {
            let (template_id, label) = rest.split_once('/').ok_or(VolumeNameError)?;
            if is_template_id(template_id) && is_volume_label(label) {
                return Ok(VolumeName::Template {
                    template_id,
                    name: label,
                });
            }
            return Err(VolumeNameError);
        }
        if is_volume_label(name) {
            Ok(VolumeName::Plain(name))
        } else {
            Err(VolumeNameError)
        }
    }
}

/// Checks a volume mount (H2 §7.1): absolute, under `/volumes/`, naming a directory below it, with no `..`, `.` or
/// empty segments and no NUL, control characters or backslashes.
pub fn validate_volume_mount(path: &str) -> Result<(), PathError> {
    if path.len() > MAX_PATH_LEN {
        return Err(PathError::TooLong);
    }
    let rest = path
        .strip_prefix(VOLUMES_DIR)
        .and_then(|r| r.strip_prefix('/'))
        .ok_or(PathError::NotUnderVolumes)?;
    check_relative(rest)
}

/// `[a-z][a-z0-9-]{0,31}`: a service port name.
fn is_port_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// The `service.health.http_get` rule: an absolute path of at most 256 bytes, with no `..` and only printable ASCII
/// other than space (so no CR, LF, NUL or anything that could end the request line).
fn check_health_path(path: &str, c: &mut Collector) {
    const FIELD: &str = "service.health.http_get";
    if path.len() > MAX_HEALTH_PATH_LEN {
        c.push(
            FIELD,
            ErrorCode::TooLarge,
            format!("must be at most {MAX_HEALTH_PATH_LEN} bytes"),
        );
    } else if !path.starts_with('/') || path.contains("..") || !path.bytes().all(|b| b.is_ascii_graphic()) {
        c.push(
            FIELD,
            ErrorCode::InvalidFormat,
            "must be an absolute path of printable ASCII, without spaces and without `..`",
        );
    }
}

fn check_range(c: &mut Collector, field: &str, value: u32, (min, max): (u32, u32), unit: &str) {
    if !(min..=max).contains(&value) {
        c.push(field, ErrorCode::OutOfRange, format!("must be {min}-{max}{unit}"));
    }
}

impl JobSpec {
    /// The template the spec was launched from, as far as `ctx` accepts one: never in `Create`, where a client's
    /// `template` is refused and so grants nothing.
    fn launched_template(&self, ctx: SpecContext) -> Option<&TemplateRef> {
        match ctx {
            SpecContext::Create => None,
            SpecContext::Launch | SpecContext::Stored => self.template.as_ref(),
        }
    }

    /// The H2 §7.1 rows, in table order: `service`, `volumes`, `inputs`, `template`. A row whose feature is off
    /// (see [`H2Features`]) refuses its field with one `not_allowed` and checks nothing else of it.
    pub(super) fn check_h2(&self, features: H2Features, ctx: SpecContext, c: &mut Collector) {
        let off = |c: &mut Collector, field: &str| {
            c.push(
                field,
                ErrorCode::NotAllowed,
                "not supported here yet (H2 job feature not enabled)",
            );
        };
        let uses_services = self.kind == JobKind::Service || self.service.is_some();
        if uses_services && !features.services {
            off(
                c,
                if self.kind == JobKind::Service {
                    "kind"
                } else {
                    "service"
                },
            );
        } else {
            match (self.kind, &self.service) {
                (JobKind::Service, Some(service)) => check_service(service, c),
                (JobKind::Service, None) => c.push("service", ErrorCode::Required, "required when kind is \"service\""),
                (JobKind::Batch, Some(_)) => c.push(
                    "service",
                    ErrorCode::NotAllowed,
                    "only allowed when kind is \"service\"",
                ),
                (JobKind::Batch, None) => {}
            }
        }
        if !self.volumes.is_empty() && !features.volumes {
            off(c, "volumes");
        } else {
            self.check_volumes(ctx, c);
        }
        if !self.inputs.is_empty() && !features.blob_inputs {
            off(c, "inputs");
        } else {
            self.check_inputs(c);
        }
        self.check_template(ctx, c);
    }

    fn check_volumes(&self, ctx: SpecContext, c: &mut Collector) {
        if self.volumes.is_empty() {
            return;
        }
        let template = self.launched_template(ctx);
        if self.kind != JobKind::Service && template.is_none() {
            // One error, nothing per entry: the volumes are refused whatever they hold.
            c.push(
                "volumes",
                ErrorCode::VolumesNotAllowed,
                "volumes are only allowed for services and template launches",
            );
            return;
        }
        if self.volumes.len() > MAX_VOLUMES {
            c.push("volumes", ErrorCode::TooMany, format!("at most {MAX_VOLUMES} volumes"));
            return;
        }
        let mut names = BTreeSet::new();
        let mut mounts: Vec<(usize, &str)> = Vec::new();
        for (i, v) in self.volumes.iter().enumerate() {
            match VolumeName::parse(&v.name) {
                Err(e) => c.push(format!("volumes[{i}].name"), ErrorCode::InvalidFormat, e.to_string()),
                Ok(VolumeName::Template { template_id, .. }) if template.is_none_or(|t| t.id != template_id) => {
                    // SI-H2-9: a client never names a template's volume, and a template only its own.
                    c.push(
                        format!("volumes[{i}].name"),
                        ErrorCode::NotAllowed,
                        "tpl: names are reserved for the launched template's own volumes",
                    );
                }
                Ok(_) => {
                    if !names.insert(v.name.as_str()) {
                        c.push(
                            format!("volumes[{i}].name"),
                            ErrorCode::Duplicate,
                            "the same volume name appears twice",
                        );
                    }
                }
            }
            match validate_volume_mount(&v.mount) {
                Err(e) => c.push(format!("volumes[{i}].mount"), ErrorCode::InvalidFormat, e.to_string()),
                Ok(()) => mounts.push((i, v.mount.as_str())),
            }
            if !(MIN_VOLUME_MB..=MAX_VOLUME_MB).contains(&v.max_mb) {
                c.push(
                    format!("volumes[{i}].max_mb"),
                    ErrorCode::OutOfRange,
                    format!("must be {MIN_VOLUME_MB}-{MAX_VOLUME_MB} MiB"),
                );
            }
        }
        // No mount may be a prefix of another, on whole segments (`/volumes/a` and `/volumes/a/b`).
        for issue in path_set_issues(mounts.iter().map(|(_, p)| *p)) {
            match issue {
                PathSetIssue::Duplicate { index, .. } => c.push(
                    format!("volumes[{}].mount", mounts[index].0),
                    ErrorCode::Duplicate,
                    "the same mount appears twice",
                ),
                PathSetIssue::Conflict { index, other } => c.push(
                    format!("volumes[{}].mount", mounts[index].0),
                    ErrorCode::PathConflict,
                    format!(
                        "conflicts with volumes[{}].mount: one mount is a directory of the other",
                        mounts[other].0
                    ),
                ),
            }
        }
    }

    fn check_inputs(&self, c: &mut Collector) {
        if self.inputs.is_empty() {
            return;
        }
        if self.inputs.len() > MAX_BLOB_INPUTS {
            c.push(
                "inputs",
                ErrorCode::TooMany,
                format!("at most {MAX_BLOB_INPUTS} blob inputs"),
            );
            return;
        }
        // Inline files first, then the inputs: a clash between the two is reported on the input. The files' own
        // problems were reported by the `files` row, so only issues on inputs are reported here.
        let files: Vec<&str> = self
            .files
            .iter()
            .map(|f| f.path.as_str())
            .filter(|p| validate_input_path(p).is_ok())
            .collect();
        let mut inputs: Vec<(usize, &str)> = Vec::new();
        for (i, input) in self.inputs.iter().enumerate() {
            match validate_input_path(&input.path) {
                Err(e) => c.push(format!("inputs[{i}].path"), ErrorCode::InvalidFormat, e.to_string()),
                Ok(()) => inputs.push((i, input.path.as_str())),
            }
        }
        let all = files.iter().copied().chain(inputs.iter().map(|(_, p)| *p));
        let field = |index: usize| format!("inputs[{}].path", inputs[index - files.len()].0);
        let describe = |other: usize| {
            if other < files.len() {
                "a files entry".to_string()
            } else {
                format!("inputs[{}].path", inputs[other - files.len()].0)
            }
        };
        for issue in path_set_issues(all) {
            match issue {
                PathSetIssue::Duplicate { index, first } if index >= files.len() => c.push(
                    field(index),
                    ErrorCode::Duplicate,
                    format!("the same path as {}", describe(first)),
                ),
                PathSetIssue::Conflict { index, other } if index >= files.len() => c.push(
                    field(index),
                    ErrorCode::PathConflict,
                    format!(
                        "conflicts with {}: one path is a directory of the other",
                        describe(other)
                    ),
                ),
                _ => {}
            }
        }
    }

    fn check_template(&self, ctx: SpecContext, c: &mut Collector) {
        match (ctx, &self.template) {
            (SpecContext::Create, Some(_)) => c.push(
                "template",
                ErrorCode::ReadOnlyField,
                "is set by a template launch; a client may not send it",
            ),
            (SpecContext::Launch, None) => c.push("template", ErrorCode::Required, "a template launch sets it"),
            (SpecContext::Launch | SpecContext::Stored, Some(t)) => {
                if !is_template_id(&t.id) {
                    c.push(
                        "template.id",
                        ErrorCode::InvalidFormat,
                        "must match [a-z][a-z0-9-]{0,62}",
                    );
                }
                if t.version == 0 {
                    c.push("template.version", ErrorCode::OutOfRange, "must be at least 1");
                }
                if let Some(pull) = &t.pull {
                    if pull.is_empty() || pull.len() > MAX_TEMPLATE_PULL_LEN {
                        c.push(
                            "template.pull",
                            ErrorCode::OutOfRange,
                            format!("must be 1-{MAX_TEMPLATE_PULL_LEN} bytes"),
                        );
                    } else if pull.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
                        c.push(
                            "template.pull",
                            ErrorCode::InvalidFormat,
                            "must not contain control characters or spaces",
                        );
                    }
                }
            }
            (SpecContext::Create | SpecContext::Stored, None) => {}
        }
    }

    /// The H2 §7.1 disk rule for blob inputs: the blobs (`blob_bytes`, their sizes summed by the server, which
    /// knows them) plus the decoded inline `files` must fit in `resources.disk_mb` minus 64 MiB, else
    /// `422 inputs_exceed_disk` on `inputs`.
    ///
    /// It applies only to a spec with blob `inputs`, so an H1 batch job keeps H1's rules exactly. Call it after
    /// [`JobSpec::validate_in`] passed, with the sizes read in the job-creation transaction.
    pub fn check_inputs_fit_disk(&self, blob_bytes: u64) -> Result<(), ValidationErrors> {
        if self.inputs.is_empty() {
            return Ok(());
        }
        let files: u64 = self
            .files
            .iter()
            .map(|f| base64_decoded_len(&f.content_b64).map_or(u64::MAX, |n| u64::try_from(n).unwrap_or(u64::MAX)))
            .fold(0, u64::saturating_add);
        let total = blob_bytes.saturating_add(files);
        let room = self
            .resources
            .disk_mb
            .saturating_sub(INPUTS_DISK_RESERVE_MB)
            .saturating_mul(1024 * 1024);
        if total > room {
            return Err(ValidationErrors::single(
                "inputs",
                ErrorCode::InputsExceedDisk,
                "blob inputs and inline files must fit in resources.disk_mb minus 64 MiB",
            ));
        }
        Ok(())
    }
}

/// The `service` block rows.
fn check_service(s: &ServiceSpec, c: &mut Collector) {
    if s.ports.is_empty() || s.ports.len() > MAX_SERVICE_PORTS {
        c.push(
            "service.ports",
            ErrorCode::OutOfRange,
            format!("must have 1-{MAX_SERVICE_PORTS} ports"),
        );
    }
    // Over the cap, nothing is checked per entry: the work stays bounded.
    if s.ports.len() <= MAX_SERVICE_PORTS {
        let mut ports = BTreeSet::new();
        let mut names = BTreeSet::new();
        for (i, p) in s.ports.iter().enumerate() {
            if !(1..=u32::from(u16::MAX)).contains(&p.port) {
                c.push(
                    format!("service.ports[{i}].port"),
                    ErrorCode::OutOfRange,
                    "must be 1-65535",
                );
            } else if !ports.insert(p.port) {
                c.push(
                    format!("service.ports[{i}].port"),
                    ErrorCode::Duplicate,
                    "the same port appears twice",
                );
            }
            if !is_port_name(&p.name) {
                c.push(
                    format!("service.ports[{i}].name"),
                    ErrorCode::InvalidFormat,
                    "must match [a-z][a-z0-9-]{0,31}",
                );
            } else if !names.insert(p.name.as_str()) {
                c.push(
                    format!("service.ports[{i}].name"),
                    ErrorCode::Duplicate,
                    "the same name appears twice",
                );
            }
        }
    }
    if let Some(h) = &s.health {
        check_health(h, s, c);
    }
    if let Some(idle) = s.idle_timeout_s {
        check_range(
            c,
            "service.idle_timeout_s",
            idle,
            (MIN_IDLE_TIMEOUT_S, MAX_IDLE_TIMEOUT_S),
            " seconds, or null (never)",
        );
    }
}

fn check_health(h: &HealthCheck, s: &ServiceSpec, c: &mut Collector) {
    match (&h.http_get, h.tcp) {
        (Some(path), false) => check_health_path(path, c),
        (None, true) => {}
        _ => c.push(
            "service.health",
            ErrorCode::InvalidFormat,
            "must have exactly one of http_get or tcp: true",
        ),
    }
    if !s.ports.iter().any(|p| p.port == h.port) {
        c.push(
            "service.health.port",
            ErrorCode::InvalidFormat,
            "must be one of service.ports",
        );
    }
    check_range(
        c,
        "service.health.interval_s",
        h.interval_s,
        HEALTH_INTERVAL_S,
        " seconds",
    );
    check_range(c, "service.health.timeout_s", h.timeout_s, HEALTH_TIMEOUT_S, " seconds");
    check_range(
        c,
        "service.health.start_period_s",
        h.start_period_s,
        HEALTH_START_PERIOD_S,
        " seconds",
    );
    check_range(
        c,
        "service.health.failure_threshold",
        h.failure_threshold,
        HEALTH_FAILURE_THRESHOLD,
        "",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{BlobInput, BlobRef, InputFile, RestartPolicy, ServicePort, Sha256Digest, VolumeSpec};
    use crate::validate::{ErrorCode::*, FieldError, Limits};
    use serde_json::json;

    /// The limits of a component that implements every H2 job feature.
    fn h2() -> Limits {
        Limits {
            h2: H2Features::ALL,
            ..Limits::default()
        }
    }

    /// A valid service, as the H2 §7.1 example (without its template volume).
    fn service() -> JobSpec {
        serde_json::from_value(json!({
            "kind": "service",
            "image": format!("docker.io/ollama/ollama@sha256:{}", "a".repeat(64)),
            "command": ["/bin/ollama", "serve"],
            "resources": {"cpu": 4, "memory_mb": 8192, "gpu": 1, "disk_mb": 2048},
            "service": {
                "ports": [{"port": 11434, "name": "api"}, {"port": 8080, "name": "web-ui"}],
                "health": {"http_get": "/api/version", "port": 11434}
            }
        }))
        .unwrap()
    }

    fn batch() -> JobSpec {
        serde_json::from_value(json!({
            "image": "python:3.12", "command": ["true"], "resources": {"cpu": 1, "memory_mb": 256, "disk_mb": 1024},
            "files": [{"path": "/inputs/data.csv", "content_b64": "aGk="}]
        }))
        .unwrap()
    }

    fn template(id: &str) -> Option<TemplateRef> {
        Some(TemplateRef {
            id: id.into(),
            version: 1,
            pull: None,
        })
    }

    fn volume(name: &str, mount: &str) -> VolumeSpec {
        VolumeSpec {
            name: name.into(),
            mount: mount.into(),
            max_mb: 1024,
        }
    }

    fn input(path: &str) -> BlobInput {
        BlobInput {
            path: path.into(),
            blob: BlobRef(Sha256Digest([9; 32])),
        }
    }

    fn with(mut s: JobSpec, f: impl FnOnce(&mut JobSpec)) -> JobSpec {
        f(&mut s);
        s
    }

    fn svc(f: impl FnOnce(&mut ServiceSpec)) -> JobSpec {
        with(service(), |s| f(s.service.as_mut().unwrap()))
    }

    fn health(f: impl FnOnce(&mut HealthCheck)) -> JobSpec {
        svc(|s| f(s.health.as_mut().unwrap()))
    }

    #[test]
    fn valid_h2_rows() {
        use SpecContext::*;
        let cases: Vec<(&str, JobSpec, SpecContext)> = vec![
            ("service example", service(), Create),
            ("service: timeout 60", with(service(), |s| s.timeout_s = 60), Create),
            (
                "service: timeout 30 days",
                with(service(), |s| s.timeout_s = 2_592_000),
                Create,
            ),
            ("service: 1 port", svc(|s| s.ports.truncate(1)), Create),
            (
                "service: 8 ports",
                svc(|s| {
                    s.health = None;
                    s.ports = (1..=8)
                        .map(|i| ServicePort {
                            port: i,
                            name: format!("p{i}"),
                        })
                        .collect();
                }),
                Create,
            ),
            (
                "port 65535",
                svc(|s| {
                    s.health = None;
                    s.ports[1].port = 65_535;
                }),
                Create,
            ),
            (
                "port name of 32",
                svc(|s| s.ports[1].name = format!("a{}", "b-9".repeat(11).get(..31).unwrap())),
                Create,
            ),
            ("no health", svc(|s| s.health = None), Create),
            (
                "tcp health",
                health(|h| {
                    h.http_get = None;
                    h.tcp = true;
                }),
                Create,
            ),
            ("health on second port", health(|h| h.port = 8080), Create),
            (
                "health path 256",
                health(|h| h.http_get = Some(format!("/{}", "a".repeat(255)))),
                Create,
            ),
            (
                "health path with query",
                health(|h| h.http_get = Some("/health?full=1".into())),
                Create,
            ),
            (
                "health bounds low",
                health(|h| {
                    h.interval_s = 2;
                    h.timeout_s = 1;
                    h.start_period_s = 0;
                    h.failure_threshold = 1;
                }),
                Create,
            ),
            (
                "health bounds high",
                health(|h| {
                    h.interval_s = 300;
                    h.timeout_s = 60;
                    h.start_period_s = 3_600;
                    h.failure_threshold = 20;
                }),
                Create,
            ),
            ("idle never", svc(|s| s.idle_timeout_s = None), Create),
            ("idle 300", svc(|s| s.idle_timeout_s = Some(300)), Create),
            ("idle 7 days", svc(|s| s.idle_timeout_s = Some(604_800)), Create),
            ("restart never", svc(|s| s.restart = RestartPolicy::Never), Create),
            (
                "service volume",
                with(service(), |s| s.volumes = vec![volume("models", "/volumes/models")]),
                Create,
            ),
            (
                "4 volumes",
                with(service(), |s| {
                    s.volumes = (0..4)
                        .map(|i| volume(&format!("v{i}"), &format!("/volumes/v{i}")))
                        .collect()
                }),
                Create,
            ),
            (
                "volume name rule edges",
                with(service(), |s| {
                    s.volumes = vec![volume(&"a".repeat(63), "/volumes/a"), volume("0._-x", "/volumes/b/c")]
                }),
                Create,
            ),
            (
                "volume 64 MiB",
                with(service(), |s| {
                    s.volumes = vec![VolumeSpec {
                        max_mb: 64,
                        ..volume("v", "/volumes/v")
                    }]
                }),
                Create,
            ),
            (
                "volume 256 GiB",
                with(service(), |s| {
                    s.volumes = vec![VolumeSpec {
                        max_mb: 262_144,
                        ..volume("v", "/volumes/v")
                    }]
                }),
                Create,
            ),
            (
                "sibling mounts",
                with(service(), |s| {
                    s.volumes = vec![volume("a", "/volumes/a"), volume("b", "/volumes/ab")]
                }),
                Create,
            ),
            (
                "template volume on a template launch",
                with(service(), |s| {
                    s.template = template("private-chat");
                    s.volumes = vec![volume("tpl:private-chat/models", "/volumes/models")];
                }),
                Launch,
            ),
            (
                "batch template launch with volumes",
                with(batch(), |s| {
                    s.template = template("transcribe");
                    s.volumes = vec![
                        volume("tpl:transcribe/models", "/volumes/models"),
                        volume("cache", "/volumes/cache"),
                    ];
                }),
                Launch,
            ),
            (
                "stored template job",
                with(batch(), |s| {
                    s.template = template("transcribe");
                    s.volumes = vec![volume("tpl:transcribe/models", "/volumes/models")];
                }),
                Stored,
            ),
            ("stored job without template", service(), Stored),
            (
                "template with pull",
                with(service(), |s| {
                    s.template = Some(TemplateRef {
                        id: "private-chat".into(),
                        version: 3,
                        pull: Some("model:4b".into()),
                    });
                }),
                Launch,
            ),
            (
                "batch input",
                with(batch(), |s| s.inputs = vec![input("/inputs/audio")]),
                Create,
            ),
            (
                "32 inputs",
                with(batch(), |s| {
                    s.inputs = (0..32).map(|i| input(&format!("/inputs/b{i}"))).collect()
                }),
                Create,
            ),
            (
                "service input",
                with(service(), |s| s.inputs = vec![input("/inputs/x")]),
                Create,
            ),
            (
                "input beside a file with a shared prefix",
                with(batch(), |s| {
                    s.inputs = vec![input("/inputs/data.csv.gz"), input("/inputs/data")]
                }),
                Create,
            ),
        ];
        for (label, spec, ctx) in cases {
            assert_eq!(spec.validate_in(&h2(), ctx), Ok(()), "{label}");
        }
    }

    #[test]
    fn invalid_h2_rows() {
        use SpecContext::*;
        let cases: Vec<(&str, JobSpec, SpecContext, &str, crate::validate::ErrorCode)> = vec![
            (
                "service timeout 59",
                with(service(), |s| s.timeout_s = 59),
                Create,
                "timeout_s",
                OutOfRange,
            ),
            (
                "service timeout over 30 days",
                with(service(), |s| s.timeout_s = 2_592_001),
                Create,
                "timeout_s",
                OutOfRange,
            ),
            (
                "batch keeps H1's 24 h",
                with(batch(), |s| s.timeout_s = 86_401),
                Create,
                "timeout_s",
                OutOfRange,
            ),
            (
                "service missing",
                with(service(), |s| s.service = None),
                Create,
                "service",
                Required,
            ),
            (
                "service on a batch",
                with(batch(), |s| s.service = service().service),
                Create,
                "service",
                NotAllowed,
            ),
            (
                "no ports",
                svc(|s| {
                    s.ports.clear();
                    s.health = None;
                }),
                Create,
                "service.ports",
                OutOfRange,
            ),
            (
                "9 ports",
                svc(|s| {
                    s.health = None;
                    s.ports = (1..=9)
                        .map(|i| ServicePort {
                            port: i,
                            name: format!("p{i}"),
                        })
                        .collect();
                }),
                Create,
                "service.ports",
                OutOfRange,
            ),
            (
                "port 0",
                svc(|s| s.ports[1].port = 0),
                Create,
                "service.ports[1].port",
                OutOfRange,
            ),
            (
                "port 65536",
                svc(|s| s.ports[1].port = 65_536),
                Create,
                "service.ports[1].port",
                OutOfRange,
            ),
            (
                "port twice",
                svc(|s| s.ports[1].port = 11434),
                Create,
                "service.ports[1].port",
                Duplicate,
            ),
            (
                "name twice",
                svc(|s| s.ports[1].name = "api".into()),
                Create,
                "service.ports[1].name",
                Duplicate,
            ),
            (
                "name uppercase",
                svc(|s| s.ports[1].name = "Web".into()),
                Create,
                "service.ports[1].name",
                InvalidFormat,
            ),
            (
                "name digit first",
                svc(|s| s.ports[1].name = "1web".into()),
                Create,
                "service.ports[1].name",
                InvalidFormat,
            ),
            (
                "name empty",
                svc(|s| s.ports[1].name = String::new()),
                Create,
                "service.ports[1].name",
                InvalidFormat,
            ),
            (
                "name 33",
                svc(|s| s.ports[1].name = "a".repeat(33)),
                Create,
                "service.ports[1].name",
                InvalidFormat,
            ),
            (
                "both checks",
                health(|h| h.tcp = true),
                Create,
                "service.health",
                InvalidFormat,
            ),
            (
                "no check",
                health(|h| h.http_get = None),
                Create,
                "service.health",
                InvalidFormat,
            ),
            (
                "health port not exposed",
                health(|h| h.port = 9),
                Create,
                "service.health.port",
                InvalidFormat,
            ),
            (
                "relative path",
                health(|h| h.http_get = Some("api/version".into())),
                Create,
                "service.health.http_get",
                InvalidFormat,
            ),
            (
                "dotdot",
                health(|h| h.http_get = Some("/a/../b".into())),
                Create,
                "service.health.http_get",
                InvalidFormat,
            ),
            (
                "CRLF",
                health(|h| h.http_get = Some("/a\r\nHost: x".into())),
                Create,
                "service.health.http_get",
                InvalidFormat,
            ),
            (
                "NUL",
                health(|h| h.http_get = Some("/a\0".into())),
                Create,
                "service.health.http_get",
                InvalidFormat,
            ),
            (
                "space",
                health(|h| h.http_get = Some("/a b".into())),
                Create,
                "service.health.http_get",
                InvalidFormat,
            ),
            (
                "path 257",
                health(|h| h.http_get = Some(format!("/{}", "a".repeat(256)))),
                Create,
                "service.health.http_get",
                TooLarge,
            ),
            (
                "interval 1",
                health(|h| h.interval_s = 1),
                Create,
                "service.health.interval_s",
                OutOfRange,
            ),
            (
                "interval 301",
                health(|h| h.interval_s = 301),
                Create,
                "service.health.interval_s",
                OutOfRange,
            ),
            (
                "timeout 0",
                health(|h| h.timeout_s = 0),
                Create,
                "service.health.timeout_s",
                OutOfRange,
            ),
            (
                "timeout 61",
                health(|h| h.timeout_s = 61),
                Create,
                "service.health.timeout_s",
                OutOfRange,
            ),
            (
                "start 3601",
                health(|h| h.start_period_s = 3_601),
                Create,
                "service.health.start_period_s",
                OutOfRange,
            ),
            (
                "threshold 0",
                health(|h| h.failure_threshold = 0),
                Create,
                "service.health.failure_threshold",
                OutOfRange,
            ),
            (
                "threshold 21",
                health(|h| h.failure_threshold = 21),
                Create,
                "service.health.failure_threshold",
                OutOfRange,
            ),
            (
                "idle 299",
                svc(|s| s.idle_timeout_s = Some(299)),
                Create,
                "service.idle_timeout_s",
                OutOfRange,
            ),
            (
                "idle 0",
                svc(|s| s.idle_timeout_s = Some(0)),
                Create,
                "service.idle_timeout_s",
                OutOfRange,
            ),
            (
                "idle over 7 days",
                svc(|s| s.idle_timeout_s = Some(604_801)),
                Create,
                "service.idle_timeout_s",
                OutOfRange,
            ),
            (
                "volumes on a batch job",
                with(batch(), |s| s.volumes = vec![volume("data", "/volumes/data")]),
                Create,
                "volumes",
                VolumesNotAllowed,
            ),
            (
                "volumes on a stored batch job without template",
                with(batch(), |s| s.volumes = vec![volume("data", "/volumes/data")]),
                Stored,
                "volumes",
                VolumesNotAllowed,
            ),
            (
                "5 volumes",
                with(service(), |s| {
                    s.volumes = (0..5)
                        .map(|i| volume(&format!("v{i}"), &format!("/volumes/v{i}")))
                        .collect()
                }),
                Create,
                "volumes",
                TooMany,
            ),
            (
                "template volume from a client (SI-H2-9)",
                with(service(), |s| {
                    s.volumes = vec![volume("tpl:private-chat/models", "/volumes/models")]
                }),
                Create,
                "volumes[0].name",
                NotAllowed,
            ),
            (
                "another template's volume",
                with(service(), |s| {
                    s.template = template("transcribe");
                    s.volumes = vec![volume("tpl:private-chat/models", "/volumes/models")];
                }),
                Launch,
                "volumes[0].name",
                NotAllowed,
            ),
            (
                "another template's volume, stored",
                with(service(), |s| {
                    s.template = template("transcribe");
                    s.volumes = vec![volume("tpl:private-chat/models", "/volumes/models")];
                }),
                Stored,
                "volumes[0].name",
                NotAllowed,
            ),
            (
                "name uppercase",
                with(service(), |s| s.volumes = vec![volume("Models", "/volumes/m")]),
                Create,
                "volumes[0].name",
                InvalidFormat,
            ),
            (
                "name a path",
                with(service(), |s| s.volumes = vec![volume("../etc", "/volumes/m")]),
                Create,
                "volumes[0].name",
                InvalidFormat,
            ),
            (
                "name slash",
                with(service(), |s| s.volumes = vec![volume("a/b", "/volumes/m")]),
                Create,
                "volumes[0].name",
                InvalidFormat,
            ),
            (
                "name 64",
                with(service(), |s| s.volumes = vec![volume(&"a".repeat(64), "/volumes/m")]),
                Create,
                "volumes[0].name",
                InvalidFormat,
            ),
            (
                "name dot first",
                with(service(), |s| s.volumes = vec![volume(".a", "/volumes/m")]),
                Create,
                "volumes[0].name",
                InvalidFormat,
            ),
            (
                "tpl without name",
                with(service(), |s| {
                    s.template = template("private-chat");
                    s.volumes = vec![volume("tpl:private-chat", "/volumes/m")];
                }),
                Launch,
                "volumes[0].name",
                InvalidFormat,
            ),
            (
                "tpl nested",
                with(service(), |s| {
                    s.template = template("private-chat");
                    s.volumes = vec![volume("tpl:private-chat/a/b", "/volumes/m")];
                }),
                Launch,
                "volumes[0].name",
                InvalidFormat,
            ),
            (
                "same name twice",
                with(service(), |s| {
                    s.volumes = vec![volume("v", "/volumes/a"), volume("v", "/volumes/b")]
                }),
                Create,
                "volumes[1].name",
                Duplicate,
            ),
            (
                "mount outside",
                with(service(), |s| s.volumes = vec![volume("v", "/data")]),
                Create,
                "volumes[0].mount",
                InvalidFormat,
            ),
            (
                "mount is the root",
                with(service(), |s| s.volumes = vec![volume("v", "/volumes")]),
                Create,
                "volumes[0].mount",
                InvalidFormat,
            ),
            (
                "mount trailing slash",
                with(service(), |s| s.volumes = vec![volume("v", "/volumes/")]),
                Create,
                "volumes[0].mount",
                InvalidFormat,
            ),
            (
                "mount prefix trick",
                with(service(), |s| s.volumes = vec![volume("v", "/volumesx/a")]),
                Create,
                "volumes[0].mount",
                InvalidFormat,
            ),
            (
                "mount dotdot",
                with(service(), |s| s.volumes = vec![volume("v", "/volumes/../inputs")]),
                Create,
                "volumes[0].mount",
                InvalidFormat,
            ),
            (
                "mount relative",
                with(service(), |s| s.volumes = vec![volume("v", "volumes/a")]),
                Create,
                "volumes[0].mount",
                InvalidFormat,
            ),
            (
                "mount inside another",
                with(service(), |s| {
                    s.volumes = vec![volume("a", "/volumes/a"), volume("b", "/volumes/a/b")]
                }),
                Create,
                "volumes[1].mount",
                PathConflict,
            ),
            (
                "mount around another",
                with(service(), |s| {
                    s.volumes = vec![volume("a", "/volumes/a/b"), volume("b", "/volumes/a")]
                }),
                Create,
                "volumes[1].mount",
                PathConflict,
            ),
            (
                "same mount twice",
                with(service(), |s| {
                    s.volumes = vec![volume("a", "/volumes/a"), volume("b", "/volumes/a")]
                }),
                Create,
                "volumes[1].mount",
                Duplicate,
            ),
            (
                "volume 63 MiB",
                with(service(), |s| {
                    s.volumes = vec![VolumeSpec {
                        max_mb: 63,
                        ..volume("v", "/volumes/v")
                    }]
                }),
                Create,
                "volumes[0].max_mb",
                OutOfRange,
            ),
            (
                "volume over 256 GiB",
                with(service(), |s| {
                    s.volumes = vec![VolumeSpec {
                        max_mb: 262_145,
                        ..volume("v", "/volumes/v")
                    }]
                }),
                Create,
                "volumes[0].max_mb",
                OutOfRange,
            ),
            (
                "33 inputs",
                with(batch(), |s| {
                    s.inputs = (0..33).map(|i| input(&format!("/inputs/b{i}"))).collect()
                }),
                Create,
                "inputs",
                TooMany,
            ),
            (
                "input outside",
                with(batch(), |s| s.inputs = vec![input("/etc/passwd")]),
                Create,
                "inputs[0].path",
                InvalidFormat,
            ),
            (
                "input dotdot",
                with(batch(), |s| s.inputs = vec![input("/inputs/../x")]),
                Create,
                "inputs[0].path",
                InvalidFormat,
            ),
            (
                "input is the dir",
                with(batch(), |s| s.inputs = vec![input("/inputs")]),
                Create,
                "inputs[0].path",
                InvalidFormat,
            ),
            (
                "input clashes with a file",
                with(batch(), |s| s.inputs = vec![input("/inputs/data.csv")]),
                Create,
                "inputs[0].path",
                Duplicate,
            ),
            (
                "input below a file",
                with(batch(), |s| s.inputs = vec![input("/inputs/data.csv/x")]),
                Create,
                "inputs[0].path",
                PathConflict,
            ),
            (
                "input above a file",
                with(batch(), |s| {
                    s.files[0].path = "/inputs/a/b".into();
                    s.inputs = vec![input("/inputs/a")];
                }),
                Create,
                "inputs[0].path",
                PathConflict,
            ),
            (
                "input twice",
                with(batch(), |s| s.inputs = vec![input("/inputs/x"), input("/inputs/x")]),
                Create,
                "inputs[1].path",
                Duplicate,
            ),
            (
                "input inside another input",
                with(batch(), |s| s.inputs = vec![input("/inputs/x"), input("/inputs/x/y")]),
                Create,
                "inputs[1].path",
                PathConflict,
            ),
            (
                "template from a client",
                with(service(), |s| s.template = template("private-chat")),
                Create,
                "template",
                ReadOnlyField,
            ),
            ("launch without template", service(), Launch, "template", Required),
            (
                "template id uppercase",
                with(service(), |s| s.template = template("Chat")),
                Launch,
                "template.id",
                InvalidFormat,
            ),
            (
                "template id with slash",
                with(service(), |s| s.template = template("a/b")),
                Stored,
                "template.id",
                InvalidFormat,
            ),
            (
                "template version 0",
                with(service(), |s| {
                    s.template = Some(TemplateRef {
                        version: 0,
                        ..template("a").unwrap()
                    })
                }),
                Launch,
                "template.version",
                OutOfRange,
            ),
            (
                "template pull empty",
                with(service(), |s| {
                    s.template = Some(TemplateRef {
                        pull: Some(String::new()),
                        ..template("a").unwrap()
                    })
                }),
                Launch,
                "template.pull",
                OutOfRange,
            ),
            (
                "template pull long",
                with(service(), |s| {
                    s.template = Some(TemplateRef {
                        pull: Some("m".repeat(257)),
                        ..template("a").unwrap()
                    })
                }),
                Launch,
                "template.pull",
                OutOfRange,
            ),
            (
                "template pull control",
                with(service(), |s| {
                    s.template = Some(TemplateRef {
                        pull: Some("m\n".into()),
                        ..template("a").unwrap()
                    })
                }),
                Launch,
                "template.pull",
                InvalidFormat,
            ),
        ];
        for (label, spec, ctx, field, code) in cases {
            let errs = spec.validate_in(&h2(), ctx).expect_err(label);
            assert!(
                errs.contains(field, code),
                "{label}: expected {field} {code}, got {errs}"
            );
            assert_eq!(errs.len(), 1, "{label}: expected exactly one error, got {errs}");
        }
    }

    /// `JobSpec::validate` is the strictest context: a client can never set a template or a template's volume.
    #[test]
    fn validate_is_the_create_context() {
        let spec = with(service(), |s| {
            s.template = template("private-chat");
            s.volumes = vec![volume("tpl:private-chat/models", "/volumes/models")];
        });
        let errs = spec.validate(&h2()).unwrap_err();
        assert!(errs.contains("template", ReadOnlyField), "{errs}");
        assert!(errs.contains("volumes[0].name", NotAllowed), "{errs}");
        assert_eq!(spec.validate_in(&h2(), SpecContext::Launch), Ok(()));
        assert_eq!(spec.validate_in(&h2(), SpecContext::Stored), Ok(()));
        assert_eq!(SpecContext::default(), SpecContext::Create);
        // A batch job that only claims to be a template launch gets no volumes either.
        let claimed = with(batch(), |s| {
            s.template = template("transcribe");
            s.volumes = vec![volume("data", "/volumes/data")];
        });
        let errs = claimed.validate(&h2()).unwrap_err();
        assert!(
            errs.contains("volumes", VolumesNotAllowed) && errs.contains("template", ReadOnlyField),
            "{errs}"
        );
        assert_eq!(errs.len(), 2, "{errs}");
    }

    /// The H2 rows never fire for a plain H1 batch job, whatever the context.
    #[test]
    fn h1_batch_jobs_get_no_h2_error_in_any_context_but_launch() {
        for ctx in [SpecContext::Create, SpecContext::Stored] {
            assert_eq!(batch().validate_in(&h2(), ctx), Ok(()));
        }
        let errs = batch().validate_in(&h2(), SpecContext::Launch).unwrap_err();
        assert!(errs.contains("template", Required));
    }

    /// A component that does not implement an H2 feature keeps refusing its fields (as H1 did), with one
    /// `not_allowed` on the field and nothing else checked; H1 jobs are unaffected.
    #[test]
    fn h2_features_are_off_by_default() {
        assert_eq!(Limits::default().h2, H2Features::default());
        assert_eq!(Limits::agent().h2, H2Features::default());
        type Switch = fn(&mut H2Features);
        let services: Switch = |f| f.services = false;
        let volumes: Switch = |f| f.volumes = false;
        let blob_inputs: Switch = |f| f.blob_inputs = false;
        // Each case has invalid content for its field: with its feature off, only the switch is reported.
        let cases = [
            ("service", svc(|s| s.ports.clear()), "kind", services),
            (
                "service block on a batch",
                with(batch(), |s| s.service = service().service),
                "service",
                services,
            ),
            (
                "volumes",
                with(service(), |s| s.volumes = vec![volume("Bad", "/x")]),
                "volumes",
                volumes,
            ),
            (
                "inputs",
                with(batch(), |s| s.inputs = vec![input("/etc/x")]),
                "inputs",
                blob_inputs,
            ),
        ];
        let switch_message = |e: &FieldError| e.message.contains("not enabled");
        for (label, spec, field, turn_off) in cases {
            let mut features = H2Features::ALL;
            turn_off(&mut features);
            let errs = spec
                .validate(&Limits {
                    h2: features,
                    ..Limits::default()
                })
                .unwrap_err();
            assert!(errs.contains(field, NotAllowed), "{label}: {errs}");
            assert_eq!(errs.len(), 1, "{label}: only the switch is reported, got {errs}");
            // With the feature on, the field's own rules apply instead, and no switch error remains.
            let errs = spec.validate(&h2()).unwrap_err();
            assert!(!errs.iter().any(switch_message), "{label}: {errs}");
        }
        // H1 batch jobs pass with every feature off.
        assert_eq!(batch().validate(&Limits::default()), Ok(()));
        // `template` needs no switch: refused from clients, accepted in a launch.
        let launched = with(batch(), |s| s.template = template("transcribe"));
        assert!(
            launched
                .validate(&Limits::default())
                .unwrap_err()
                .contains("template", ReadOnlyField)
        );
        assert_eq!(launched.validate_in(&Limits::default(), SpecContext::Launch), Ok(()));
    }

    #[test]
    fn many_ports_or_volumes_are_refused_without_per_entry_work() {
        let spec = svc(|s| {
            s.health = None;
            s.ports = (0..10_000)
                .map(|_| ServicePort {
                    port: 0,
                    name: "Bad".into(),
                })
                .collect();
        });
        let errs = spec.validate(&h2()).unwrap_err();
        assert_eq!(errs.len(), 1, "{errs}");
        let spec = with(service(), |s| s.volumes = vec![volume("Bad", "/x"); 10_000]);
        let errs = spec.validate(&h2()).unwrap_err();
        assert_eq!(errs.len(), 1, "{errs}");
        let spec = with(batch(), |s| s.inputs = vec![input("/x"); 10_000]);
        assert_eq!(spec.validate(&h2()).unwrap_err().len(), 1);
    }

    #[test]
    fn inputs_must_fit_the_disk_minus_64_mib() {
        const MIB: u64 = 1024 * 1024;
        let spec = with(batch(), |s| s.inputs = vec![input("/inputs/audio")]);
        // disk 1024 MiB: 960 MiB of room, the inline file is 2 bytes.
        let room = (1024 - 64) * MIB;
        assert_eq!(spec.check_inputs_fit_disk(room - 2), Ok(()));
        let errs = spec.check_inputs_fit_disk(room - 1).unwrap_err();
        assert!(errs.contains("inputs", InputsExceedDisk), "{errs}");
        // Even with nothing in the blobs, a disk of 64 MiB or less leaves no room.
        let tiny = with(spec.clone(), |s| s.resources.disk_mb = 64);
        assert!(tiny.check_inputs_fit_disk(0).is_err());
        let no_files = with(tiny, |s| s.files.clear());
        assert_eq!(no_files.check_inputs_fit_disk(0), Ok(()));
        // Without blob inputs the rule does not apply (H1 batch jobs keep their rules).
        let h1 = with(batch(), |s| s.resources.disk_mb = 1);
        assert_eq!(h1.check_inputs_fit_disk(u64::MAX), Ok(()));
        // Saturating, never overflowing.
        let huge = with(spec, |s| {
            s.files = vec![InputFile {
                path: "/inputs/f".into(),
                content_b64: "!".into(),
            }];
        });
        assert!(huge.check_inputs_fit_disk(u64::MAX).is_err());
    }

    #[test]
    fn volume_names_parse() {
        assert_eq!(VolumeName::parse("models"), Ok(VolumeName::Plain("models")));
        assert_eq!(
            VolumeName::parse("tpl:private-chat/models"),
            Ok(VolumeName::Template {
                template_id: "private-chat",
                name: "models"
            })
        );
        for bad in [
            "",
            "tpl:",
            "tpl:/x",
            "tpl:x/",
            "tpl:X/y",
            "tpl:a.b/y",
            "tpl:a/b/c",
            "TPL:a/b",
            "a:b",
            "a b",
            "é",
        ] {
            assert_eq!(VolumeName::parse(bad), Err(VolumeNameError), "{bad:?}");
        }
        assert!(
            is_template_id("private-chat") && is_template_id("a") && is_template_id(&format!("a{}", "b".repeat(62)))
        );
        for bad in ["", "1a", "-a", "a_b", "a.b", "a/b", "A", &"a".repeat(64)] {
            assert!(!is_template_id(bad), "{bad:?}");
        }
        assert_eq!(validate_volume_mount("/volumes/a/b"), Ok(()));
        assert_eq!(validate_volume_mount("/inputs/a"), Err(PathError::NotUnderVolumes));
        assert_eq!(
            validate_volume_mount(&format!("/volumes/{}", "a/".repeat(3000))),
            Err(PathError::TooLong)
        );
    }

    /// Whether `dir` is a strict path-prefix of `path` on whole segments.
    fn is_dir_of(dir: &str, path: &str) -> bool {
        path.strip_prefix(dir).is_some_and(|rest| rest.starts_with('/'))
    }

    proptest::proptest! {
        /// The port rows against a direct model: each port is reported out of range, or as a repeat of an earlier
        /// in-range port, or not at all; the same for names.
        #[test]
        fn port_rules_match_a_reference(
            ports in proptest::collection::vec((0u32..5, "[a-c1A]{0,2}"), 1..9),
        ) {
            let spec = svc(|s| {
                s.health = None;
                s.ports = ports.iter().map(|(p, n)| ServicePort { port: *p, name: n.clone() }).collect();
            });
            let errs = spec.validate(&h2()).err().map(|e| e.into_vec()).unwrap_or_default();
            let mut want = Vec::new();
            let mut seen_ports = Vec::new();
            let mut seen_names = Vec::new();
            for (i, (p, n)) in ports.iter().enumerate() {
                if *p == 0 {
                    want.push((format!("service.ports[{i}].port"), OutOfRange));
                } else if seen_ports.contains(p) {
                    want.push((format!("service.ports[{i}].port"), Duplicate));
                } else {
                    seen_ports.push(*p);
                }
                let valid = n.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                    && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
                if !valid {
                    want.push((format!("service.ports[{i}].name"), InvalidFormat));
                } else if seen_names.contains(n) {
                    want.push((format!("service.ports[{i}].name"), Duplicate));
                } else {
                    seen_names.push(n.clone());
                }
            }
            let got: Vec<_> = errs.into_iter().map(|e| (e.field, e.code)).collect();
            proptest::prop_assert_eq!(got, want);
        }

        /// Mount conflicts: a spec validates iff no two mounts are equal or one is a directory of the other.
        #[test]
        fn mount_conflicts_match_a_reference(
            mounts in proptest::collection::vec("[ab]{1,2}(/[ab]{1,2}){0,2}", 1..5),
        ) {
            let spec = with(service(), |s| {
                s.volumes = mounts
                    .iter()
                    .enumerate()
                    .map(|(i, m)| volume(&format!("v{i}"), &format!("/volumes/{m}")))
                    .collect();
            });
            let clash = mounts.iter().enumerate().any(|(i, a)| {
                mounts.iter().enumerate().any(|(j, b)| i != j && (a == b || is_dir_of(a, b)))
            });
            proptest::prop_assert_eq!(spec.validate(&h2()).is_ok(), !clash);
        }

        /// A `tpl:` volume validates only in a launch or stored spec of the template it names.
        #[test]
        fn template_volumes_need_their_own_template(
            named in "[a-c]{1,2}",
            launched in proptest::option::of("[a-c]{1,2}"),
            ctx in proptest::sample::select(vec![SpecContext::Create, SpecContext::Launch, SpecContext::Stored]),
        ) {
            let spec = with(service(), |s| {
                s.template = launched.as_deref().and_then(template);
                s.volumes = vec![volume(&format!("tpl:{named}/models"), "/volumes/models")];
            });
            let ok = spec.validate_in(&h2(), ctx).is_ok();
            let expected = ctx != SpecContext::Create && launched.as_deref() == Some(named.as_str());
            proptest::prop_assert_eq!(ok, expected);
        }
    }
}
