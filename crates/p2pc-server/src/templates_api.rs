// SPDX-License-Identifier: AGPL-3.0-only

//! The template endpoints (H2 spec §7.3, §7.6): `GET /v1/templates` and `POST /v1/templates/{id}/launch`.
//!
//! **A launch is a job submission whose JobSpec the hub writes.** The caller chooses a template of the bundle the
//! hub serves ([`crate::templates`]) and values for its parameters; the hub builds the JobSpec through the
//! template's parameter targets and nothing else (`templates_bundle::params::build_spec`, the one implementation,
//! which the bundle rules of SI-H2-13 are checked against), sets `template: {id, version, pull}` and creates the
//! job with the caller as its principal. From there it is a job like any other: the caller's image allowlist and
//! daily cap apply, placement applies, and the template view of the job routes shows it (§5.5).
//!
//! - **Parameters.** An unknown parameter, a value of the wrong type or outside the template's bounds, an enum
//!   value the template does not list: `422 invalid_params`. The answer names the template's parameter and never
//!   repeats the value.
//! - **Singleton.** While an instance of a `singleton` template is `queued`, `assigned` or `running` in the
//!   caller's account and project, a launch returns it (`200`) and creates nothing, unless the launch names a
//!   `pull` model other than the instance's: `409 singleton_running`, with the instance and its model in `detail`.
//! - **Caps.** A principal with a `daily_unit_cap` is checked before the job exists, through T2-16's `spent(P, D)`
//!   ([`crate::units::spent_today`]) for a batch template and its daily service reservation
//!   ([`crate::units::reserve_new_service`]) for a service template. There is no cap arithmetic here. The refusal is
//!   H1's `402 cap_exceeded`, with a `detail` that names the template, the units it needs and the units left today.
//! - **No bundle.** When the hub may serve no bundle (SI-H2-14), the listing is empty with `bundle_error` and a
//!   launch gets `503 templates_unavailable`.
//!
//! **Secrets.** Nothing here logs a spec, a parameter value or a body.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use p2pc_proto::api::{
    FileMeta, GpuRequirement, H2ErrorCode, Job, JobKind, JobSpec, LaunchTemplate, ParamTarget, Problem, Scope,
    Template, TemplateList,
};
use p2pc_proto::ids::JobId;
use p2pc_proto::units::{Units, estimate_units};
use p2pc_proto::validate::{H2Features, Limits, SpecContext, image_allowed};
use templates_bundle::params::{ParamError, build_spec};

use crate::app::AppState;
use crate::auth::{AnyKey, Authorized, RequiredScope, recheck_caller};
use crate::error::ApiError;
use crate::extract::ApiJson;
use crate::spec_hash::spec_hash;
use crate::store;
use crate::store::jobs::{self, JobRow, NewJob};
use crate::units::{check_cap, gpu_hour_units, reserve_new_service, spent_today};

/// The `templates:launch` scope (or `admin`).
#[derive(Debug)]
pub struct TemplatesLaunchScope;

impl RequiredScope for TemplatesLaunchScope {
    const SCOPE: Option<Scope> = Some(Scope::TemplatesLaunch);
}

/// A principal with `templates:launch` (or `admin`).
pub type LaunchKey = Authorized<TemplatesLaunchScope>;

/// `503 templates_unavailable`: the hub may serve no bundle now (H2 §7.6 "What it serves").
fn templates_unavailable(why: &str) -> ApiError {
    ApiError::service_unavailable(
        H2ErrorCode::TemplatesUnavailable.as_str(),
        format!("No template can be launched right now: {why}."),
    )
}

/// `404 unknown_template`.
fn unknown_template() -> ApiError {
    ApiError::with_status(
        StatusCode::NOT_FOUND,
        H2ErrorCode::UnknownTemplate.as_str(),
        "The hub serves no template with this id (see GET /v1/templates).",
    )
}

/// `422 invalid_params`. [`ParamError`] names the template's own parameter and never repeats a value.
fn invalid_params(e: &ParamError) -> ApiError {
    ApiError::unprocessable(H2ErrorCode::InvalidParams.as_str(), format!("Invalid `params`: {e}."))
}

/// `402 cap_exceeded` for a launch (H2 §7.6 "Launch by a capped principal"): the template, what it needs and what
/// is left today, so a UI can say "Your daily limit does not allow <template>".
fn cap_exceeded(template: &Template, needs: Units, cap: Units, spent: Units) -> ApiError {
    let left = cap.saturating_sub(spent);
    let what = match template.info.kind {
        JobKind::Batch => "for its whole time limit",
        JobKind::Service => "for its first 15 minutes",
    };
    ApiError::with_status(
        StatusCode::PAYMENT_REQUIRED,
        "cap_exceeded",
        format!(
            "Your daily limit does not allow the template `{}`: it needs {needs} units {what}, and {left} units are \
             left today (UTC) of a daily cap of {cap} units.",
            template.info.id
        ),
    )
}

/// The served bundle (H2 §7.6): what a UI needs to offer and launch each template, with `bundle_version`. The vetted
/// JobSpec and the `allowed_routes` of a template stay on the hub.
///
/// When the hub may serve no bundle (the bundle it loaded last is gone or damaged, and it never serves an older
/// one), the list is empty and `bundle_error` says why.
#[utoipa::path(
    get,
    path = "/v1/templates",
    tag = "templates",
    responses(
        (status = 200, description = "The templates of the bundle the hub serves, with `bundle_version`; an empty list, `bundle_version: null` and `bundle_error` when it can serve none.", body = TemplateList),
        (status = 401, description = "Missing or invalid key.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "The caller has neither `jobs:read` nor `templates:launch`.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn list_templates(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: AnyKey,
) -> Result<Json<TemplateList>, ApiError> {
    if !p.has_scope(Scope::JobsRead) && !p.has_scope(Scope::TemplatesLaunch) {
        return Err(ApiError::forbidden(Scope::TemplatesLaunch));
    }
    Ok(Json(match state.bundle.served() {
        Ok(loaded) => TemplateList {
            bundle_version: Some(loaded.version()),
            templates: loaded.bundle.templates.iter().map(|t| t.info.clone()).collect(),
            bundle_error: None,
        },
        Err(why) => TemplateList {
            bundle_version: None,
            templates: Vec::new(),
            bundle_error: Some(why),
        },
    }))
}

/// The response for a job: `201` with `Location` for a new one, `200` for one that existed.
fn job_response(status: StatusCode, row: &JobRow) -> Response {
    let mut resp = (status, Json(row.to_job())).into_response();
    if status == StatusCode::CREATED
        && let Ok(location) = HeaderValue::from_str(&format!("/v1/jobs/{}", row.job_id))
    {
        resp.headers_mut().insert(header::LOCATION, location);
    }
    resp
}

/// The `pull` model a launch names itself, if the template has a `pull` parameter and the launch sets it.
fn named_pull<'a>(template: &Template, launch: &'a LaunchTemplate) -> Option<&'a p2pc_proto::api::ParamValue> {
    template
        .info
        .params
        .iter()
        .find(|p| p.target == ParamTarget::Pull)
        .and_then(|p| launch.params.get(&p.name))
}

/// The JobSpec of the launch (H2 §7.6 "Launch"): the parameters checked against the template and written to their
/// targets, the GPU from the placement hint, then the normal JobSpec validation and the image normalized.
async fn build(
    state: &AppState,
    p: &crate::auth::Principal,
    template: &Template,
    launch: &LaunchTemplate,
) -> Result<JobSpec, ApiError> {
    let to_error = |e: ParamError| match e {
        // The bundle rules build every launch a template can produce, so this is a bug, not the caller's doing.
        ParamError::Template(why) => {
            tracing::error!(template = %template.info.id, %why, "a served template cannot be launched");
            ApiError::internal()
        }
        other => invalid_params(&other),
    };
    let limits = Limits {
        allowed_registries: Some(state.config.allowed_registries.clone()),
        h2: H2Features::ALL,
        ..Limits::default()
    };
    // The spec with or without the GPU, validated as any JobSpec is, in the launch context.
    let assemble = |gpu_available: bool| -> Result<JobSpec, ApiError> {
        let mut spec = build_spec(template, &launch.params, gpu_available).map_err(to_error)?;
        spec.idempotency_key.clone_from(&launch.idempotency_key);
        spec.validate_in(&limits, SpecContext::Launch)
            .map_err(|e| ApiError::validation(&e))?;
        Ok(spec)
    };
    let spec = assemble(true)?;
    // §7.6 "Placement hints": a preferred GPU is asked for only when the account has a node that could give one.
    if template.info.requirements.gpu == GpuRequirement::Preferred
        && state.nodes.match_job(p.account_id, &spec).await.matching_nodes == 0
    {
        return assemble(false);
    }
    Ok(spec)
}

/// Launches a template: builds its JobSpec from `params` through the template's parameter targets, sets
/// `template: {id, version, pull}` and creates the job with the caller as its principal.
///
/// - **`params`**: values by parameter name; a parameter left out takes the template's default. An unknown
///   parameter, a wrong type, a value outside the template's bounds or an enum value it does not list gets
///   `422 invalid_params`. A `blob` parameter names a blob of the caller's account (`422 unknown_blob`).
/// - **Singleton templates**: while an instance is `queued`, `assigned` or `running`, the launch returns it (`200`)
///   and creates nothing; if the launch names a `pull` model other than the instance's, `409 singleton_running`
///   with the instance's id and model in `detail`.
/// - **Limits of the caller**: its `allowed_images` (`403 image_not_allowed`) and its `daily_unit_cap`
///   (`402 cap_exceeded`, naming the template, the units it needs and the units left today). A batch template needs
///   its estimate (resources × `timeout_s`); a service template needs 15 minutes of runtime from the day's
///   reservation, and is stopped when the day's cap is reached.
/// - **Idempotency**: `idempotency_key` works as for jobs, scoped to the caller: the same key with the same launch
///   returns the job (`200`), with another launch `409 idempotency_conflict`.
#[utoipa::path(
    post,
    path = "/v1/templates/{id}/launch",
    tag = "templates",
    request_body = LaunchTemplate,
    params(("id" = String, Path, description = "The template's id, as `GET /v1/templates` lists it.")),
    responses(
        (status = 201, description = "The job was created and is queued.", body = Job, headers(("Location" = String, description = "`/v1/jobs/{id}`"))),
        (status = 200, description = "The running instance of a `singleton` template, or the job this caller already launched with the idempotency key.", body = Job),
        (status = 401, description = "Missing or invalid key, or the caller was revoked or expired while the request was in flight.", content_type = "application/problem+json", body = Problem),
        (status = 402, description = "`cap_exceeded`: the caller's daily unit cap does not allow the template; `detail` names the template, the units it needs and the units left today.", content_type = "application/problem+json", body = Problem),
        (status = 403, description = "`forbidden`: the caller lacks `templates:launch`. `image_not_allowed`: its allowed images do not cover the template's image.", content_type = "application/problem+json", body = Problem),
        (status = 404, description = "`unknown_template`: the served bundle has no template with this id.", content_type = "application/problem+json", body = Problem),
        (status = 409, description = "`singleton_running`: an instance of this singleton template is live with another model; `detail` has its id and model. `idempotency_conflict`: the caller already used the idempotency key with another launch.", content_type = "application/problem+json", body = Problem),
        (status = 422, description = "`invalid_params`: an unknown parameter, a wrong type, a value outside the template's bounds or not one of its values. `unknown_blob`: a `blob` parameter the caller's account does not hold. `inputs_exceed_disk`. `invalid_body`, `validation_failed`: the body itself.", content_type = "application/problem+json", body = Problem),
        (status = 503, description = "`templates_unavailable`: the hub may serve no template bundle now.", content_type = "application/problem+json", body = Problem),
    )
)]
pub async fn launch_template(
    State(state): State<AppState>,
    Authorized { principal: p, .. }: LaunchKey,
    Path(id): Path<String>,
    ApiJson(launch): ApiJson<LaunchTemplate>,
) -> Result<Response, ApiError> {
    launch.validate().map_err(|e| ApiError::validation(&e))?;
    let loaded = state.bundle.served().map_err(|why| templates_unavailable(&why))?;
    let template = loaded.template(&id).ok_or_else(unknown_template)?;
    // Everything that costs CPU happens before the write lock is taken, as for `POST /v1/jobs`.
    let mut spec = build(&state, &p, template, &launch).await?;
    // Validation parsed the image, so this cannot fail; a failure would be a bug.
    let image = spec.normalized_image().map_err(|_| ApiError::internal())?;
    spec.image = image.to_string();
    let files_meta = FileMeta::compute_all(&spec).map_err(|_| ApiError::internal())?;
    // What makes two launches the same request: the template (and its version) and the parameters as sent. The GPU
    // hint is left out on purpose, so a retry is still the same launch after a GPU node joined.
    let request = serde_json::json!({"launch": {
        "template": template.info.id,
        "version": template.info.version,
        "params": launch.params,
    }});
    let hash = spec_hash(&request);
    let service = spec.kind == JobKind::Service;
    let gpu_hour = gpu_hour_units(&state.config);
    // H2 §12: a service reserves nothing in `units_reserved`; a capped principal's service holds a day at a time.
    let units = if service {
        Units::ZERO
    } else {
        estimate_units(&spec.resources, spec.timeout_s, gpu_hour)
    };

    // Reads (the caller, an earlier launch with the key, the singleton's instance, the day's spending), then writes:
    // IMMEDIATE. It also serializes concurrent launches, so two of them cannot both start a singleton.
    let mut tx = store::begin_immediate(&state.db).await?;
    let now = state.clock.now();
    // §5 "Re-checked at the point of use": the caller's current row decides.
    let caller = recheck_caller(&mut tx, &state, &p, now).await?;
    if let Some(patterns) = &caller.allowed_images
        && !image_allowed(patterns, &image)
    {
        return Err(ApiError::image_not_allowed(&spec.image));
    }
    // A replay is answered before anything else: the job exists and is already counted.
    if let Some(key) = &spec.idempotency_key
        && let Some(existing) = jobs::find_by_idempotency_key(&mut tx, p.account_id, p.project_id, p.id, key).await?
    {
        return if existing.spec_hash == hash {
            Ok(job_response(StatusCode::OK, &existing))
        } else {
            Err(ApiError::idempotency_conflict())
        };
    }
    // §7.6 "Launch": a live instance of a singleton is returned, never doubled.
    if template.info.singleton
        && let Some(instance) =
            store::templates::live_instance(&mut tx, p.account_id, p.project_id, &template.info.id).await?
        && let Some(row) = jobs::get(&mut tx, p.account_id, p.project_id, instance).await?
    {
        let running = row.spec_view.template.as_ref().and_then(|t| t.pull.clone());
        let wanted = spec.template.as_ref().and_then(|t| t.pull.clone());
        if named_pull(template, &launch).is_some() && wanted != running {
            return Err(ApiError::conflict(
                H2ErrorCode::SingletonRunning.as_str(),
                format!(
                    "The instance {} of `{}` is running with the model `{}`. Stop it to launch another model.",
                    row.job_id,
                    template.info.id,
                    running.as_deref().unwrap_or("none")
                ),
            ));
        }
        return Ok(job_response(StatusCode::OK, &row));
    }
    if !spec.inputs.is_empty() {
        let blob_bytes = store::blobs::resolve_inputs(&mut tx, p.account_id, &spec.inputs)
            .await?
            .map_err(|_| {
                ApiError::unprocessable(
                    H2ErrorCode::UnknownBlob.as_str(),
                    "A `blob` parameter names a blob this account does not hold (upload it with POST /v1/blobs first).",
                )
            })?;
        spec.check_inputs_fit_disk(blob_bytes)
            .map_err(|e| ApiError::validation(&e))?;
    }
    // §7.6 "Launch by a capped principal": before the job exists, through T2-16 (H2 §12).
    let mut day_hold = None;
    if let Some(cap) = caller.daily_unit_cap {
        if service {
            let held = reserve_new_service(&mut tx, p.account_id, p.id, cap, &spec, gpu_hour, now)
                .await?
                .map_err(|c| cap_exceeded(template, c.estimate, c.cap, c.reserved))?;
            day_hold = Some(held);
        } else {
            let spent = spent_today(&mut tx, p.account_id, p.id, now).await?;
            check_cap(cap, spent, units).map_err(|c| cap_exceeded(template, c.estimate, c.cap, c.reserved))?;
        }
    }
    let new = NewJob {
        job_id: JobId::generate(),
        account_id: p.account_id,
        project_id: p.project_id,
        principal: p.id,
        spec,
        files_meta,
        spec_hash: hash,
        units_reserved: units,
    };
    let row = jobs::insert(&mut tx, &new, now).await?;
    if let Some(held) = day_hold {
        crate::units::hold(&mut tx, row.job_id, held, now).await?;
    }
    tx.commit().await?;
    // The IDs only: never the spec or a parameter.
    tracing::info!(job_id = %row.job_id, principal = %p.id, template = %template.info.id, "template launched");
    state.kick.kick();
    Ok(job_response(StatusCode::CREATED, &row))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use p2pc_proto::api::{BlobRef, ParamType, ParamValue};
    use proptest::prelude::*;
    use templates_bundle::bundle::Bundle;

    use super::*;
    use crate::templates::Trust;

    /// A blob digest for the `blob` parameters that are not the one under test.
    const BLOB: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// The bundle this hub embeds and serves: the templates a launch can name.
    fn served() -> Bundle {
        serde_json::from_slice(&Trust::built_in().embedded).unwrap()
    }

    /// The words a parameter may put into an env value or an argv element: the template's own enum values, a
    /// rendered bool and a rendered integer.
    fn is_template_word(template: &Template, word: &str) -> bool {
        let listed = template.info.params.iter().any(|p| match &p.ty {
            ParamType::Enum { values } => values.iter().any(|v| v == word),
            _ => false,
        });
        listed || word == "true" || word == "false" || word.parse::<i64>().is_ok()
    }

    /// What no parameter target reaches must be the template's own, whatever the caller sent.
    fn assert_only_targets_changed(template: &Template, spec: &JobSpec) -> Result<(), TestCaseError> {
        let vetted = &template.spec;
        prop_assert_eq!(&spec.image, &vetted.image);
        prop_assert_eq!(spec.kind, vetted.kind);
        prop_assert_eq!(&spec.name, &vetted.name);
        prop_assert_eq!(&spec.files, &vetted.files);
        prop_assert_eq!(&spec.egress, &vetted.egress);
        prop_assert_eq!(&spec.volumes, &vetted.volumes);
        prop_assert_eq!(&spec.placement, &vetted.placement);
        prop_assert_eq!(&spec.retry, &vetted.retry);
        prop_assert_eq!(&spec.outputs, &vetted.outputs);
        prop_assert_eq!(spec.resources.cpu.to_bits(), vetted.resources.cpu.to_bits());
        prop_assert_eq!(spec.resources.memory_mb, vetted.resources.memory_mb);
        prop_assert_eq!(spec.resources.disk_mb, vetted.resources.disk_mb);
        prop_assert!(spec.resources.gpu <= 1);
        // Env: the template's variables, each with the template's value or one of its own words.
        prop_assert_eq!(
            spec.env.keys().collect::<Vec<_>>(),
            vetted.env.keys().collect::<Vec<_>>()
        );
        for (name, value) in &spec.env {
            prop_assert!(vetted.env.get(name) == Some(value) || is_template_word(template, value));
        }
        // Argv: the same shape, each element the template's or one of its own words.
        prop_assert_eq!(spec.command.len(), vetted.command.len());
        for (arg, vetted_arg) in spec.command.iter().zip(&vetted.command) {
            prop_assert!(arg == vetted_arg || is_template_word(template, arg));
        }
        // The service: its ports and health are the template's; only the idle timeout is a target.
        match (&spec.service, &vetted.service) {
            (Some(service), Some(vetted_service)) => {
                prop_assert_eq!(&service.ports, &vetted_service.ports);
                prop_assert_eq!(&service.health, &vetted_service.health);
                prop_assert_eq!(service.restart, vetted_service.restart);
            }
            (None, None) => {}
            _ => prop_assert!(false, "a launch added or removed the service block"),
        }
        // Inputs: only at the paths the template fixes.
        for input in &spec.inputs {
            let fixed = template
                .info
                .params
                .iter()
                .any(|p| p.target == ParamTarget::Input(input.path.clone()));
            prop_assert!(fixed, "an input at a path the template does not fix");
        }
        let launched = spec.template.as_ref();
        prop_assert_eq!(launched.map(|t| t.id.as_str()), Some(template.info.id.as_str()));
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// SI-H2-13, over the bundle the hub serves: any string as the value of any parameter is either refused
        /// (`invalid_params`) or one of the template's own values, and what no target reaches stays the
        /// template's. Shell metacharacters are just strings here: none of them is a value of a template.
        #[test]
        fn any_string_as_a_parameter_value_is_refused_or_is_the_templates_own(
            value in prop_oneof![
                ".*",
                "[;|&$`<>(){}!*?'\"\\\\ \n\t-]{1,12}",
                "(small|base|medium|auto|en|qwen3:4b-instruct|qwen3:1.7b)[;|&$` ]{0,3}.{0,6}",
            ],
            which in 0usize..16,
            gpu in any::<bool>(),
        ) {
            for template in &served().templates {
                let params = &template.info.params;
                let param = &params[which % params.len()];
                let mut values = BTreeMap::new();
                for p in params.iter().filter(|p| matches!(p.ty, ParamType::Blob)) {
                    values.insert(p.name.clone(), ParamValue::Text(BLOB.to_string()));
                }
                values.insert(param.name.clone(), ParamValue::Text(value.clone()));
                match build_spec(template, &values, gpu) {
                    // Refused: the caller's doing, never a broken template, and the answer never repeats the value.
                    Err(e) => {
                        prop_assert!(!matches!(e, ParamError::Template(_)), "{e}");
                        let said = invalid_params(&e);
                        let detail = said.problem().detail.clone().unwrap_or_default();
                        prop_assert!(value.len() < 4 || !detail.contains(&value), "{detail}");
                        prop_assert_eq!(said.problem().code.as_str(), "invalid_params");
                    }
                    Ok(spec) => {
                        match &param.ty {
                            ParamType::Enum { values: listed } => prop_assert!(listed.contains(&value)),
                            ParamType::Blob => prop_assert!(value.parse::<BlobRef>().is_ok()),
                            ParamType::Int { .. } | ParamType::Bool => {
                                prop_assert!(false, "a string was taken for an int or a bool");
                            }
                        }
                        assert_only_targets_changed(template, &spec)?;
                    }
                }
            }
        }

        /// The same for integers: inside the template's bounds or refused, never clamped.
        #[test]
        fn an_int_parameter_is_inside_the_templates_bounds_or_refused(value in any::<i64>(), near in -3i64..=3) {
            for template in &served().templates {
                for param in &template.info.params {
                    let ParamType::Int { min, max } = &param.ty else { continue };
                    for candidate in [value, min.saturating_add(near), max.saturating_add(near)] {
                        let mut values = BTreeMap::new();
                        values.insert(param.name.clone(), ParamValue::Int(candidate));
                        match build_spec(template, &values, true) {
                            Ok(spec) => {
                                prop_assert!((*min..=*max).contains(&candidate));
                                assert_only_targets_changed(template, &spec)?;
                            }
                            Err(e) => {
                                prop_assert!(!(*min..=*max).contains(&candidate), "{e}");
                                prop_assert!(!matches!(e, ParamError::Template(_)), "{e}");
                            }
                        }
                    }
                }
            }
        }
    }
}
