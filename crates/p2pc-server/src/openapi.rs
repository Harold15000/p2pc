// SPDX-License-Identifier: AGPL-3.0-only

//! The OpenAPI 3.1 document, generated from the handlers and the `p2pc-proto` types (utoipa).
//!
//! It is served at `GET /v1/openapi.json` and committed as `docs/api/openapi.json`; the `openapi` integration test
//! fails when the two drift (see `docs/dev/README.md`).

use std::sync::OnceLock;

use p2pc_proto::api::{
    ApiKeyInfo, AuditEvent, AuditKind, BlobInfo, BlobList, BlobUploaded, Capacity, CpuInfo, CreateApiKey,
    CreateJoinRequest, CreateJoinToken, CreatePairingTicket, DeviceInfo, Estimate, GpuInfo, GpuRequirement, GpuStatus,
    GpuStatusKind, Health, Inventory, Job, JobAttempt, JobSpec, JobSpecView, JobStatus, JoinRequestCreated,
    JoinRequestInfo, JoinRequestState, JoinRequestToken, JoinTokenInfo, JoinTokenResponse, LaunchTemplate, LogLine,
    LogStream, NewApiKey, Node, NodeApproval, NodeState, OutputEntry, Page, PairingTicketCreated, PairingTicketInfo,
    ParamType, ParamValue, Platform, Principal, Problem, RevealJoinRequest, SandboxCapability, SandboxClass, Scope,
    ServerInfo, SmokeResult, TemplateInfo, TemplateList, TemplateParam, TemplateRequirements, TemplateUi, UpdateServer,
    UsageGroupBy, UsageReport, UsageTotals, VolumeInfo, WhoAmI, Wsl2Health,
};
use p2pc_proto::validate::{ErrorCode, FieldError};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::{
    app, artifacts_api, blobs_api, devices_api, jobs_api, join_requests_api, nodes_api, ports_api, templates_api,
    usage_api, volumes_api,
};

/// Name of the security scheme.
pub const BEARER: &str = "bearer";

/// The API description.
#[derive(Debug, OpenApi)]
#[openapi(
    info(
        title = "P2PC API",
        description = "The P2PC control plane REST API. Errors are RFC 9457 `application/problem+json` with a \
                       stable `code`. Lists use cursor pagination (`limit` ≤ 100, `cursor`).",
        license(name = "AGPL-3.0-only", identifier = "AGPL-3.0-only"),
    ),
    paths(
        app::healthz,
        app::openapi_json,
        app::whoami,
        app::create_key,
        app::list_keys,
        app::revoke_key,
        app::list_audit,
        nodes_api::get_server,
        nodes_api::patch_server,
        nodes_api::create_join_token,
        nodes_api::list_join_tokens,
        nodes_api::revoke_join_token,
        nodes_api::list_nodes,
        nodes_api::get_node,
        nodes_api::drain_node,
        nodes_api::resume_node,
        nodes_api::delete_node,
        nodes_api::approve_node,
        join_requests_api::create_join_request,
        join_requests_api::list_join_requests,
        join_requests_api::get_join_request,
        join_requests_api::reveal_join_request,
        join_requests_api::approve_join_request,
        join_requests_api::join_request_token,
        join_requests_api::reject_join_request,
        devices_api::create_pairing_ticket,
        devices_api::list_pairing_tickets,
        devices_api::revoke_pairing_ticket,
        devices_api::list_devices,
        devices_api::get_device,
        devices_api::revoke_device,
        jobs_api::create_job,
        jobs_api::list_jobs,
        jobs_api::get_job,
        jobs_api::cancel_job,
        jobs_api::estimate,
        ports_api::connect,
        artifacts_api::get_logs,
        artifacts_api::list_outputs,
        artifacts_api::download_output,
        usage_api::get_usage,
        blobs_api::upload_blob,
        blobs_api::head_blob,
        blobs_api::list_blobs,
        blobs_api::delete_blob,
        templates_api::list_templates,
        templates_api::launch_template,
        volumes_api::list_volumes,
        volumes_api::delete_volume,
    ),
    components(schemas(
        Problem,
        FieldError,
        ErrorCode,
        Scope,
        Health,
        WhoAmI,
        CreateApiKey,
        ApiKeyInfo,
        NewApiKey,
        AuditKind,
        AuditEvent,
        Page<ApiKeyInfo>,
        Page<AuditEvent>,
        ServerInfo,
        UpdateServer,
        CreateJoinToken,
        JoinTokenResponse,
        JoinTokenInfo,
        Page<JoinTokenInfo>,
        Node,
        NodeState,
        Inventory,
        Capacity,
        CpuInfo,
        GpuInfo,
        GpuStatus,
        GpuStatusKind,
        Platform,
        SandboxCapability,
        SandboxClass,
        SmokeResult,
        Wsl2Health,
        Page<Node>,
        JobSpec,
        JobSpecView,
        JobStatus,
        Job,
        JobAttempt,
        Estimate,
        Page<Job>,
        LogLine,
        LogStream,
        OutputEntry,
        Page<OutputEntry>,
        UsageGroupBy,
        UsageTotals,
        UsageReport,
        Principal,
        NodeApproval,
        CreatePairingTicket,
        PairingTicketCreated,
        PairingTicketInfo,
        Page<PairingTicketInfo>,
        DeviceInfo,
        Page<DeviceInfo>,
        CreateJoinRequest,
        JoinRequestCreated,
        RevealJoinRequest,
        JoinRequestState,
        JoinRequestInfo,
        Page<JoinRequestInfo>,
        JoinRequestToken,
        BlobUploaded,
        BlobInfo,
        BlobList,
        TemplateList,
        TemplateInfo,
        TemplateParam,
        ParamType,
        ParamValue,
        TemplateRequirements,
        GpuRequirement,
        TemplateUi,
        LaunchTemplate,
        VolumeInfo,
        Page<VolumeInfo>,
    )),
    modifiers(&BearerAuth),
    security(("bearer" = [])),
    tags(
        (name = "meta", description = "Health and the API description."),
        (name = "auth", description = "The calling key."),
        (name = "keys", description = "API keys (admin)."),
        (name = "audit", description = "Append-only audit log (admin)."),
        (name = "server", description = "The server's iroh identity."),
        (name = "nodes", description = "Join tokens, join requests and enrolled nodes."),
        (name = "devices", description = "Pairing tickets and paired devices (H2 §5)."),
        (name = "jobs", description = "Submit, list, inspect, cancel and estimate jobs."),
        (name = "usage", description = "The usage ledger: finished attempts and the units they cost."),
        (name = "blobs", description = "Content-addressed job inputs, per account (H2 §7.5). No route returns blob contents."),
        (name = "templates", description = "The vetted one-click workloads of the bundle the hub serves, and their launch (H2 §7.6)."),
        (name = "volumes", description = "The persistent volumes the nodes hold (H2 §7.3, §11.3)."),
    )
)]
pub struct ApiDoc;

/// Adds the `bearer` scheme: `Authorization: Bearer p2pc_sk_…`.
#[derive(Debug)]
struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            BEARER,
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("p2pc_sk_<key_id>_<secret>")
                    .build(),
            ),
        );
    }
}

/// The document as pretty JSON with a trailing newline, exactly as committed.
pub fn document() -> String {
    static DOC: OnceLock<String> = OnceLock::new();
    DOC.get_or_init(|| {
        let mut text = ApiDoc::openapi()
            .to_pretty_json()
            .unwrap_or_else(|e| format!("{{\"error\": \"cannot render the OpenAPI document: {e}\"}}"));
        text.push('\n');
        text
    })
    .clone()
}
