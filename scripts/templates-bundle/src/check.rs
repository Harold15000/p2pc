// SPDX-License-Identifier: Apache-2.0

//! The rules every template MUST meet (H2 §7.6, SI-H2-13), checked over a whole bundle.
//!
//! Each rule is a [`Problem`] naming the template. The checks collect every problem instead of stopping at the
//! first, so one run tells the author everything that is wrong.
//!
//! The rules, in the order of the spec:
//!
//! - the image is pinned by `@sha256:` digest (a placeholder digest passes in development and fails a release);
//! - parameters reach the job only through their targets: whole env values, whole argv elements, a listed JobSpec
//!   field within bounds that lie inside the field's JobSpec range, an `inputs` entry at a fixed path, or the `pull`
//!   model of a chat template; enum values come from the template and are plain words;
//! - egress is a fixed list and volumes use the `tpl:<id>/` namespace (both checked by the normal JobSpec validation
//!   plus the namespace rule here);
//! - `allowed_routes` name ports of `service.ports`, one `GET` or `POST` and an exact absolute path each, never a
//!   route that pulls, creates, copies, pushes or deletes models, and a wildcard only on the reviewed list;
//! - the spec sets a finite `timeout_s` (enforced by [`crate::source`], which refuses a spec that leaves it out);
//! - every JobSpec a launch can produce passes the normal JobSpec validation: the defaults, every enum value, both
//!   bounds of every int, both values of every bool, with and without a GPU.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use p2pc_proto::api::{
    GpuRequirement, JobKind, ParamTarget, ParamType, ParamValue, Template, TemplateParam, TemplateUi,
};
use p2pc_proto::validate::{H2Features, ImageRef, Limits, SpecContext, is_template_id};

use crate::bundle::Bundle;
use crate::params::build_spec;

/// How strict the checks are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Development and CI: a placeholder image digest is allowed (the digest has not been taken from the registry
    /// yet).
    Dev,
    /// A release: a placeholder image digest is refused, so a bundle that carries one cannot be signed.
    Release,
}

/// One broken rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// The template it is about, or `None` for the bundle as a whole.
    pub template: Option<String>,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.template {
            Some(id) => write!(f, "{id}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

/// Wildcard routes (a final `*` segment, §7.4) that a reviewer accepted: `(template id, path)`. Empty in the beta
/// (§7.4: "the beta templates do not"). Adding a line here is a reviewed change, like the template that needs it.
const WILDCARD_ROUTES: &[(&str, &str)] = &[];

/// The most templates in a bundle, parameters in a template, routes in a template and values in an enum.
const MAX_TEMPLATES: usize = 32;
const MAX_PARAMS: usize = 16;
const MAX_ROUTES: usize = 16;
const MAX_ENUM_VALUES: usize = 32;
/// Longest route path, in bytes (the same bound as a health path, §7.1).
const MAX_ROUTE_PATH: usize = 256;
/// The all-zero digest that stands in for a digest nobody has taken from the registry yet.
const PLACEHOLDER_DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Env variables a parameter may not set: they change how a program loads code or where its traffic goes.
const FORBIDDEN_ENV: &[&str] = &[
    "PATH",
    "BASH_ENV",
    "ENV",
    "IFS",
    "SHELL",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "NODE_OPTIONS",
    "PERL5OPT",
    "RUBYOPT",
    "JAVA_TOOL_OPTIONS",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
];

/// Ollama's model-writing endpoints (the second segment after `/api/`).
const MODEL_WRITE_SEGMENTS: &[&str] = &["pull", "create", "copy", "push", "delete", "blobs"];

/// Shells whose `-c` argument is a script.
const SHELLS: &[&str] = &["sh", "bash", "dash", "ash", "zsh", "ksh"];

struct Ctx<'a> {
    id: &'a str,
    problems: Vec<Problem>,
}

impl Ctx<'_> {
    fn say(&mut self, message: impl Into<String>) {
        self.problems.push(Problem {
            template: Some(self.id.to_string()),
            message: message.into(),
        });
    }
}

/// Checks every template of `bundle` and the bundle's own fields.
#[must_use]
pub fn check_bundle(bundle: &Bundle, mode: Mode) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut whole = |message: &str| {
        problems.push(Problem {
            template: None,
            message: message.to_string(),
        })
    };
    if bundle.bundle_version == 0 {
        whole("bundle_version must be at least 1");
    }
    if semver::Version::parse(&bundle.min_hub_version).is_err() {
        whole("min_hub_version must be a semantic version such as 0.1.0");
    }
    if bundle.templates.is_empty() {
        whole("a bundle needs at least one template");
    }
    if bundle.templates.len() > MAX_TEMPLATES {
        whole("too many templates in the bundle");
    }
    let mut seen = BTreeSet::new();
    for t in &bundle.templates {
        if !seen.insert(t.info.id.as_str()) {
            problems.push(Problem {
                template: Some(t.info.id.clone()),
                message: "duplicate template id".to_string(),
            });
        }
    }
    for t in &bundle.templates {
        problems.extend(check_template(t, mode));
    }
    problems
}

/// Checks one template.
#[must_use]
pub fn check_template(t: &Template, mode: Mode) -> Vec<Problem> {
    let mut c = Ctx {
        id: &t.info.id,
        problems: Vec::new(),
    };
    check_identity(t, &mut c);
    check_kind_and_ui(t, &mut c);
    check_spec_shape(t, mode, &mut c);
    let params_ok = check_params(t, &mut c);
    check_routes(t, &mut c);
    if params_ok {
        check_every_launch(t, &mut c);
    }
    c.problems
}

fn plain_text(s: &str, allow_newlines: bool) -> bool {
    s.chars().all(|ch| !ch.is_control() || (allow_newlines && ch == '\n'))
}

fn check_identity(t: &Template, c: &mut Ctx<'_>) {
    let info = &t.info;
    if !is_template_id(&info.id) {
        c.say("the id must match [a-z][a-z0-9-]{0,62}");
    }
    if info.version == 0 {
        c.say("version must be at least 1");
    }
    if info.title.is_empty() || info.title.chars().count() > 80 || !plain_text(&info.title, false) {
        c.say("title must be 1-80 printable characters");
    }
    if info.description.chars().count() > 1000 || !plain_text(&info.description, true) {
        c.say("description must be at most 1000 printable characters");
    }
    if info.licenses.is_empty() {
        c.say("licenses must not be empty: the UI shows the image and model licenses");
    }
    if info.licenses.len() > 8
        || info
            .licenses
            .iter()
            .any(|l| l.is_empty() || l.chars().count() > 120 || !plain_text(l, false))
    {
        c.say("each license is 1-120 printable characters, at most 8 of them");
    }
    if info.download_mb == 0 {
        c.say("download_mb must be at least 1: the UI shows the first-run download before launch");
    } else if info.download_mb > 200_000 {
        c.say("download_mb is over 200000");
    }
    if let Some(vram) = info.requirements.min_vram_mb {
        if info.requirements.gpu == GpuRequirement::None && vram > 0 {
            c.say("min_vram_mb is set but requirements.gpu = \"none\"");
        }
        if vram > 262_144 {
            c.say("min_vram_mb is over 262144");
        }
    }
}

fn check_kind_and_ui(t: &Template, c: &mut Ctx<'_>) {
    let info = &t.info;
    if info.kind != t.spec.kind {
        c.say("kind must equal spec.kind");
    }
    if info.ui == TemplateUi::Chat && info.kind != JobKind::Service {
        c.say("ui = \"chat\" needs kind = \"service\"");
    }
    if info.ui == TemplateUi::Transcribe && info.kind != JobKind::Batch {
        c.say("ui = \"transcribe\" needs kind = \"batch\"");
    }
    if info.singleton && info.kind != JobKind::Service {
        c.say("singleton is only for a service");
    }
}

fn check_spec_shape(t: &Template, mode: Mode, c: &mut Ctx<'_>) {
    let spec = &t.spec;
    if spec.template.is_some() {
        c.say("spec.template must not be set: a launch sets it");
    }
    if spec.idempotency_key.is_some() {
        c.say("spec.idempotency_key must not be set");
    }
    if !spec.inputs.is_empty() {
        c.say("spec.inputs must be empty: blobs come from `blob` parameters");
    }

    match ImageRef::parse(&spec.image) {
        Err(e) => c.say(format!("image: {e}")),
        Ok(image) => match image.digest() {
            None => c.say("the image must be pinned by @sha256: digest"),
            Some(digest) => {
                if digest == PLACEHOLDER_DIGEST && mode == Mode::Release {
                    c.say("the image carries a placeholder digest (all zeros): take the real one from the registry before a release");
                }
            }
        },
    }

    let wanted_gpu = u32::from(t.info.requirements.gpu != GpuRequirement::None);
    if spec.resources.gpu != wanted_gpu {
        c.say(format!(
            "resources.gpu is {} but requirements.gpu = {:?} needs {wanted_gpu} (the hub lowers a preferred GPU to 0 at launch)",
            spec.resources.gpu,
            format!("{:?}", t.info.requirements.gpu).to_lowercase()
        ));
    }

    let prefix = format!("tpl:{}/", t.info.id);
    for volume in &spec.volumes {
        if !volume.name.starts_with(&prefix) {
            c.say(format!(
                "volume `{}` must be named {prefix}<name>",
                volume.name.escape_debug()
            ));
        }
    }
}

// ---- parameters ------------------------------------------------------------------------------------------------

/// `[a-z][a-z0-9_]{0,31}`
fn is_param_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// A plain word an env value or an argv element may take from an enum: `[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}`. No space,
/// quote, `$`, backtick, `;`, `|`, `&`, `<`, `>`, `\`, `*`, newline or leading `-`, so the script that reads it needs
/// no escaping and a value can never be taken for an option.
fn is_plain_word(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'+' | b'-'))
}

/// A model name for the `pull` target: `[namespace/]name[:tag]` of `[A-Za-z0-9._-]`, at most one `/` and one `:` (the
/// `:` after the `/`), no empty or dot-leading part, so it cannot name another registry or climb a path.
fn is_model_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 128 || s.matches('/').count() > 1 || s.matches(':').count() > 1 {
        return false;
    }
    if let (Some(slash), Some(colon)) = (s.find('/'), s.find(':'))
        && colon < slash
    {
        return false;
    }
    s.split(['/', ':']).all(|part| {
        let b = part.as_bytes();
        !b.is_empty()
            && b[0].is_ascii_alphanumeric()
            && !part.contains("..")
            && b.iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    })
}

fn type_name(ty: &ParamType) -> &'static str {
    match ty {
        ParamType::Enum { .. } => "enum",
        ParamType::Int { .. } => "int",
        ParamType::Bool => "bool",
        ParamType::Blob => "blob",
    }
}

/// Checks the parameters. Returns whether they are sound enough to build every launch from them.
fn check_params(t: &Template, c: &mut Ctx<'_>) -> bool {
    let params = &t.info.params;
    let before = c.problems.len();
    if params.len() > MAX_PARAMS {
        c.say("too many parameters");
    }
    let mut names = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut pulls = 0;
    for p in params {
        if !is_param_name(&p.name) {
            c.say(format!(
                "parameter name `{}` must match [a-z][a-z0-9_]{{0,31}}",
                p.name.escape_debug()
            ));
        }
        if !names.insert(p.name.as_str()) {
            c.say(format!("duplicate parameter name `{}`", p.name));
        }
        if !targets.insert(p.target.to_string()) {
            c.say(format!(
                "parameter `{}` has the same target as another parameter ({})",
                p.name, p.target
            ));
        }
        if p.target == ParamTarget::Pull {
            pulls += 1;
        }
        check_param_type(p, c);
        check_param_target(t, p, c);
    }
    if pulls > 1 {
        c.say("more than one parameter has the `pull` target");
    }
    c.problems.len() == before
}

fn check_param_type(p: &TemplateParam, c: &mut Ctx<'_>) {
    let n = &p.name;
    match (&p.ty, &p.default) {
        (ParamType::Enum { values }, default) => {
            if values.is_empty() {
                c.say(format!("enum parameter `{n}` has no values"));
            }
            if values.len() > MAX_ENUM_VALUES {
                c.say(format!("enum parameter `{n}` has more than {MAX_ENUM_VALUES} values"));
            }
            let mut seen = BTreeSet::new();
            for v in values {
                if !seen.insert(v.as_str()) {
                    c.say(format!("enum parameter `{n}` has a duplicate value"));
                }
                let ok = match p.target {
                    ParamTarget::Pull => is_model_name(v),
                    _ => is_plain_word(v),
                };
                if !ok {
                    c.say(format!(
                        "enum parameter `{n}` has the value {:?}: values must be plain words ([A-Za-z0-9._:+-], starting with a letter or digit), or model names for `pull`",
                        v.escape_debug().to_string()
                    ));
                }
            }
            match default {
                Some(ParamValue::Text(d)) if values.contains(d) => {}
                Some(ParamValue::Text(_)) => c.say(format!("the default of parameter `{n}` is not one of its values")),
                Some(_) => c.say(format!("the default of parameter `{n}` is not a string")),
                None => c.say(format!("parameter `{n}` needs a default")),
            }
        }
        (ParamType::Int { min, max }, default) => {
            if min > max {
                c.say(format!("int parameter `{n}` has min above max"));
            }
            match default {
                Some(ParamValue::Int(d)) if (*min..=*max).contains(d) => {}
                Some(ParamValue::Int(_)) => c.say(format!("the default of parameter `{n}` lies outside its bounds")),
                Some(_) => c.say(format!("the default of parameter `{n}` is not an int")),
                None => c.say(format!("parameter `{n}` needs a default")),
            }
        }
        (ParamType::Bool, default) => match default {
            Some(ParamValue::Bool(_)) => {}
            Some(_) => c.say(format!("the default of parameter `{n}` is not a bool")),
            None => c.say(format!("parameter `{n}` needs a default")),
        },
        (ParamType::Blob, default) => {
            if default.is_some() {
                c.say(format!(
                    "a blob parameter has no default (`{n}`): the caller always names the blob"
                ));
            }
        }
    }
}

fn check_param_target(t: &Template, p: &TemplateParam, c: &mut Ctx<'_>) {
    let n = &p.name;
    let spec = &t.spec;
    let is_blob = matches!(p.ty, ParamType::Blob);
    if is_blob && !matches!(p.target, ParamTarget::Input(_)) {
        c.say(format!("a blob parameter must use an `input:` target (`{n}`)"));
    }
    match &p.target {
        ParamTarget::Env(name) => {
            if !spec.env.contains_key(name) {
                c.say(format!("env target {name} is not an env variable of the template's spec: the template fixes the variable and the parameter replaces its whole value"));
            }
            if name.starts_with("LD_") || FORBIDDEN_ENV.contains(&name.as_str()) {
                c.say(format!(
                    "env target {name} is a loader, interpreter or proxy variable that no parameter may set"
                ));
            }
        }
        ParamTarget::Argv(index) => {
            let len = spec.command.len();
            let i = usize::try_from(*index).unwrap_or(usize::MAX);
            if i >= len {
                c.say(format!("argv:{index} is outside the command ({len} elements)"));
            } else if i == 0 {
                c.say("argv:0 would replace the program itself");
            } else if is_shell_script_slot(&spec.command, i) {
                c.say(format!(
                    "argv:{index} is the script of a shell `-c`: a parameter must never become shell code"
                ));
            }
        }
        ParamTarget::Field(field) => match &p.ty {
            ParamType::Int { min, max } => match field.range(t.info.kind) {
                None => c.say(format!(
                    "field {} does not exist for a {} template",
                    field.as_str(),
                    t.info.kind
                )),
                Some((lo, hi)) => {
                    if *min < i64::from(lo) || *max > i64::from(hi) {
                        c.say(format!(
                            "the bounds {min}..{max} of parameter `{n}` are outside the JobSpec range {lo}..{hi} of {}",
                            field.as_str()
                        ));
                    }
                }
            },
            _ => c.say(format!(
                "`field:` targets are only for an int parameter (`{n}` is {})",
                type_name(&p.ty)
            )),
        },
        ParamTarget::Input(_) => {
            if !is_blob {
                c.say(format!(
                    "`input:` targets are only for a blob parameter (`{n}` is {})",
                    type_name(&p.ty)
                ));
            }
        }
        ParamTarget::Pull => {
            if !matches!(p.ty, ParamType::Enum { .. }) {
                c.say(format!(
                    "`pull` is only for an enum parameter (`{n}` is {})",
                    type_name(&p.ty)
                ));
            }
            if t.info.ui != TemplateUi::Chat {
                c.say("`pull` is only for a template with ui = \"chat\"");
            }
        }
    }
    if matches!(p.ty, ParamType::Bool) && !matches!(p.target, ParamTarget::Env(_) | ParamTarget::Argv(_)) {
        c.say(format!("bool parameters go to env or argv targets only (`{n}`)"));
    }
}

/// Whether `command[i]` is the script argument of a shell invoked with `-c`.
fn is_shell_script_slot(command: &[String], i: usize) -> bool {
    let Some(program) = command.first() else { return false };
    let base = program.rsplit('/').next().unwrap_or(program);
    SHELLS.contains(&base)
        && i >= 1
        && command.get(..i).is_some_and(|before| {
            before
                .iter()
                .skip(1)
                .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'))
        })
}

// ---- routes ----------------------------------------------------------------------------------------------------

fn check_routes(t: &Template, c: &mut Ctx<'_>) {
    let routes = &t.allowed_routes;
    if routes.is_empty() {
        return;
    }
    let Some(service) = t.spec.service.as_ref().filter(|_| t.spec.kind == JobKind::Service) else {
        c.say("a batch template has no service to route to: allowed_routes must be empty");
        return;
    };
    if routes.len() > MAX_ROUTES {
        c.say("too many allowed_routes");
    }
    let mut seen = BTreeSet::new();
    for r in routes {
        let shown = format!(
            "{} {} (port {})",
            r.method.escape_debug(),
            r.path.escape_debug(),
            r.port
        );
        if !seen.insert((r.port, r.method.as_str(), r.path.as_str())) {
            c.say(format!("duplicate route {shown}"));
        }
        if !service.ports.iter().any(|p| p.port == r.port) {
            c.say(format!("route {shown}: the port is not in service.ports"));
        }
        if r.method != "GET" && r.method != "POST" {
            c.say(format!("route {shown}: the method must be exactly GET or POST"));
        }
        if let Some(why) = route_path_problem(&t.info.id, &r.path) {
            c.say(format!("route {shown}: {why}"));
        }
    }
}

/// Why `path` is not an acceptable route path, or `None`. The hub matches the request target byte for byte (§7.4),
/// so a path with a query, an escape or a dot segment could never match what the author meant.
fn route_path_problem(template_id: &str, path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return Some("the path must be absolute".to_string());
    }
    if path.len() > MAX_ROUTE_PATH {
        return Some(format!("the path is over {MAX_ROUTE_PATH} bytes"));
    }
    if !path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'/' | b'-' | b'*'))
    {
        return Some("the path may only use A-Z a-z 0-9 . _ ~ - / (no query, fragment, escape or space)".to_string());
    }
    let segments: Vec<&str> = path[1..].split('/').collect();
    if segments.iter().any(|s| s.is_empty()) {
        return Some("the path has an empty segment".to_string());
    }
    if segments.iter().any(|s| *s == "." || *s == "..") {
        return Some("the path has a dot segment".to_string());
    }
    let wildcard_ok = segments.last() == Some(&"*") && segments[..segments.len() - 1].iter().all(|s| !s.contains('*'));
    if path.contains('*') {
        if !wildcard_ok {
            return Some("a wildcard is only a whole final `*` segment".to_string());
        }
        if !WILDCARD_ROUTES.contains(&(template_id, path)) {
            return Some(
                "a wildcard route needs a reviewed entry in WILDCARD_ROUTES (the beta templates have none)".to_string(),
            );
        }
    }
    // A final `*` stands for any one segment, so test the path with each model-writing word in its place.
    let expansions: Vec<Vec<&str>> = if path.contains('*') {
        MODEL_WRITE_SEGMENTS
            .iter()
            .chain(["x"].iter())
            .map(|word| segments.iter().map(|s| if *s == "*" { *word } else { *s }).collect())
            .collect()
    } else {
        vec![segments.clone()]
    };
    if expansions.iter().any(|segs| reaches_model_write(segs)) {
        return Some(
            "the route can reach a model-writing endpoint (pull, create, copy, push, delete or blobs)".to_string(),
        );
    }
    None
}

fn reaches_model_write(segments: &[&str]) -> bool {
    segments.first().is_some_and(|s| s.eq_ignore_ascii_case("api"))
        && segments
            .get(1)
            .is_some_and(|s| MODEL_WRITE_SEGMENTS.iter().any(|w| s.eq_ignore_ascii_case(w)))
}

// ---- every launch ----------------------------------------------------------------------------------------------

/// A blob digest to stand in for the caller's blob in the checks.
const DUMMY_BLOB: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Builds the JobSpec of every launch the template can produce at its edges and validates each one with the normal
/// JobSpec validation, in the `Launch` context, with every H2 feature on.
fn check_every_launch(t: &Template, c: &mut Ctx<'_>) {
    let limits = Limits {
        h2: H2Features::ALL,
        ..Limits::default()
    };
    let mut base: BTreeMap<String, ParamValue> = BTreeMap::new();
    for p in &t.info.params {
        if matches!(p.ty, ParamType::Blob) {
            base.insert(p.name.clone(), ParamValue::Text(DUMMY_BLOB.to_string()));
        }
    }

    let mut cases: Vec<(String, BTreeMap<String, ParamValue>, bool)> = vec![
        ("the defaults, with a GPU".to_string(), base.clone(), true),
        ("the defaults, without a GPU".to_string(), base.clone(), false),
    ];
    for p in &t.info.params {
        let candidates: Vec<ParamValue> = match &p.ty {
            ParamType::Enum { values } => values.iter().cloned().map(ParamValue::Text).collect(),
            ParamType::Int { min, max } => vec![ParamValue::Int(*min), ParamValue::Int(*max)],
            ParamType::Bool => vec![ParamValue::Bool(false), ParamValue::Bool(true)],
            ParamType::Blob => Vec::new(),
        };
        for (i, value) in candidates.into_iter().enumerate() {
            let mut values = base.clone();
            values.insert(p.name.clone(), value);
            cases.push((format!("parameter `{}`, candidate {}", p.name, i + 1), values, true));
        }
    }

    for (what, values, gpu) in cases {
        match build_spec(t, &values, gpu) {
            Err(e) => c.say(format!("a launch with {what} cannot be built: {e}")),
            Ok(spec) => {
                if let Err(errors) = spec.validate_in(&limits, SpecContext::Launch) {
                    for e in &errors {
                        c.say(format!(
                            "a launch with {what} fails the JobSpec validation: {}: {} ({})",
                            e.field, e.message, e.code
                        ));
                    }
                }
            }
        }
    }
}
