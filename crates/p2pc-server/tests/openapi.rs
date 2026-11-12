// SPDX-License-Identifier: AGPL-3.0-only

//! The committed `docs/api/openapi.json` must match the document generated from the code.
//!
//! To regenerate it after changing the API: `P2PC_UPDATE_OPENAPI=1 cargo test -p p2pc-server --test openapi`.

use std::path::PathBuf;

fn committed_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/openapi.json")
}

#[test]
fn committed_openapi_document_matches_the_code() {
    let generated = p2pc_server::openapi::document();
    let path = committed_path();
    if std::env::var_os("P2PC_UPDATE_OPENAPI").is_some_and(|v| v == "1") {
        std::fs::write(&path, &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == generated,
        "docs/api/openapi.json is out of date. Regenerate it with \
         `P2PC_UPDATE_OPENAPI=1 cargo test -p p2pc-server --test openapi` and commit the result."
    );
}

#[test]
fn the_document_describes_every_endpoint_with_bearer_security() {
    let doc: serde_json::Value = serde_json::from_str(&p2pc_server::openapi::document()).unwrap();
    assert!(doc["openapi"].as_str().unwrap().starts_with("3.1"));
    let paths = &doc["paths"];
    for (path, method) in [
        ("/healthz", "get"),
        ("/v1/openapi.json", "get"),
        ("/v1/whoami", "get"),
        ("/v1/keys", "get"),
        ("/v1/keys", "post"),
        ("/v1/keys/{key_id}", "delete"),
        ("/v1/audit", "get"),
        ("/v1/server", "get"),
        ("/v1/nodes/join-tokens", "get"),
        ("/v1/nodes/join-tokens", "post"),
        ("/v1/nodes/join-tokens/{id}", "delete"),
        ("/v1/nodes", "get"),
        ("/v1/nodes/{id}", "get"),
        ("/v1/nodes/{id}", "delete"),
        ("/v1/nodes/{id}/drain", "post"),
        ("/v1/nodes/{id}/resume", "post"),
        ("/v1/jobs", "get"),
        ("/v1/jobs", "post"),
        ("/v1/jobs/{id}", "get"),
        ("/v1/jobs/{id}/cancel", "post"),
        ("/v1/estimate", "post"),
        ("/v1/usage", "get"),
    ] {
        assert!(paths[path][method].is_object(), "{method} {path}");
    }
    assert_eq!(doc["components"]["securitySchemes"]["bearer"]["scheme"], "bearer");
    // The scheme is required globally; only the public operations opt out.
    assert_eq!(doc["security"], serde_json::json!([{"bearer": []}]));
    for (path, method) in [("/healthz", "get"), ("/v1/openapi.json", "get")] {
        assert_eq!(paths[path][method]["security"], serde_json::json!([{}]), "{path}");
    }
    // Every authenticated operation (review P3-6: POST /v1/keys and GET /v1/audit were missing from this list).
    for (path, method) in [
        ("/v1/whoami", "get"),
        ("/v1/keys", "get"),
        ("/v1/keys", "post"),
        ("/v1/keys/{key_id}", "delete"),
        ("/v1/audit", "get"),
        ("/v1/server", "get"),
        ("/v1/nodes/join-tokens", "get"),
        ("/v1/nodes/join-tokens", "post"),
        ("/v1/nodes/join-tokens/{id}", "delete"),
        ("/v1/nodes", "get"),
        ("/v1/nodes/{id}", "get"),
        ("/v1/nodes/{id}", "delete"),
        ("/v1/nodes/{id}/drain", "post"),
        ("/v1/nodes/{id}/resume", "post"),
        ("/v1/jobs", "get"),
        ("/v1/jobs", "post"),
        ("/v1/jobs/{id}", "get"),
        ("/v1/jobs/{id}/cancel", "post"),
        ("/v1/estimate", "post"),
        ("/v1/usage", "get"),
    ] {
        assert!(
            paths[path][method].get("security").is_none(),
            "{method} {path} must not opt out"
        );
    }
    // And no operation besides the two public ones opts out.
    let mut public = Vec::new();
    for (path, item) in paths.as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            if op.get("security").is_some() {
                public.push(format!("{method} {path}"));
            }
        }
    }
    public.sort();
    assert_eq!(public, ["get /healthz", "get /v1/openapi.json"]);
    for name in [
        "Problem",
        "ApiKeyInfo",
        "NewApiKey",
        "CreateApiKey",
        "WhoAmI",
        "AuditEvent",
        "Health",
        "ServerInfo",
        "JoinTokenResponse",
        "JoinTokenInfo",
        "CreateJoinToken",
        "Node",
        "Inventory",
        "Job",
        "JobSpec",
        "JobSpecView",
        "JobStatus",
        "UsageReport",
        "UsageTotals",
        "UsageGroupBy",
        "Estimate",
        "Resources",
        "InputFile",
        "InputFileView",
    ] {
        assert!(doc["components"]["schemas"][name].is_object(), "{name}");
    }
    // `POST /v1/keys` documents the 403 for escalation as well as the missing scope.
    let post = &paths["/v1/keys"]["post"]["responses"]["403"]["description"];
    assert!(post.as_str().unwrap().contains("escalation_denied"), "{post}");
    // `DELETE /v1/nodes/join-tokens/{id}` documents the 409 for a consumed token.
    let del = &paths["/v1/nodes/join-tokens/{id}"]["delete"]["responses"]["409"]["description"];
    assert!(del.as_str().unwrap().contains("token_consumed"), "{del}");
}

/// T04: the job endpoints document their statuses and the `Idempotency-Key` header, and `Job` exposes `reason`.
#[test]
fn the_job_endpoints_document_their_contract() {
    let doc: serde_json::Value = serde_json::from_str(&p2pc_server::openapi::document()).unwrap();
    let paths = &doc["paths"];
    let statuses = |path: &str, method: &str| -> Vec<String> {
        let mut v: Vec<String> = paths[path][method]["responses"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        statuses("/v1/jobs", "post"),
        ["200", "201", "401", "402", "403", "409", "422"]
    );
    assert_eq!(statuses("/v1/jobs", "get"), ["200", "401", "403", "422"]);
    assert_eq!(statuses("/v1/jobs/{id}", "get"), ["200", "401", "403", "404"]);
    assert_eq!(statuses("/v1/jobs/{id}/cancel", "post"), ["200", "401", "403", "404"]);
    assert_eq!(statuses("/v1/estimate", "post"), ["200", "401", "403", "422"]);
    for (path, method) in [("/v1/jobs", "post"), ("/v1/estimate", "post")] {
        let params = paths[path][method]["parameters"].as_array().unwrap();
        assert!(
            params
                .iter()
                .any(|p| p["name"] == "Idempotency-Key" && p["in"] == "header"),
            "{path}"
        );
    }
    let list_params: Vec<&str> = paths["/v1/jobs"]["get"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    for name in ["limit", "cursor", "status", "node_id"] {
        assert!(list_params.contains(&name), "{name} in {list_params:?}");
    }
    // The fields T04 added to existing types.
    let job = &doc["components"]["schemas"]["Job"]["properties"];
    for field in ["reason", "cancel_requested_at", "estimated_units", "spec", "status"] {
        assert!(job[field].is_object(), "Job.{field}");
    }
    // §7 (c47c0a5): the request has an idempotency key, no response type does.
    let schemas = &doc["components"]["schemas"];
    assert!(schemas["JobSpec"]["properties"]["idempotency_key"].is_object());
    assert!(schemas["JobSpecView"]["properties"].get("idempotency_key").is_none());
    assert!(schemas["Job"]["properties"].get("idempotency_key").is_none());
    let who = &doc["components"]["schemas"]["WhoAmI"]["properties"];
    for field in ["label", "daily_unit_cap", "allowed_images", "expires_at"] {
        assert!(who[field].is_object(), "WhoAmI.{field}");
    }
}

/// T2-13 (H2 §7.3, §7.4, §7.7): the port connection documents the upgrade, every status it answers and the error
/// codes H2 adds for it, each with its HTTP status.
#[test]
fn the_port_connection_documents_its_contract() {
    let doc: serde_json::Value = serde_json::from_str(&p2pc_server::openapi::document()).unwrap();
    let op = &doc["paths"]["/v1/jobs/{id}/ports/{port}/connect"]["post"];
    assert!(op.is_object(), "the operation is documented");
    assert!(op.get("security").is_none(), "it does not opt out of authentication");
    let responses = op["responses"].as_object().unwrap();
    let mut statuses: Vec<&str> = responses.keys().map(String::as_str).collect();
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        [
            "101", "400", "401", "403", "404", "409", "413", "422", "429", "431", "502"
        ]
    );
    for (status, code) in [
        ("403", "route_not_allowed"),
        ("409", "service_not_running"),
        ("409", "service_not_ready"),
        ("422", "port_not_exposed"),
        ("429", "too_many_connections"),
        ("431", "headers_too_large"),
        ("502", "node_unreachable"),
    ] {
        let description = responses[status]["description"].as_str().unwrap();
        assert!(description.contains(code), "{status} names {code}: {description}");
    }
    let params: Vec<&str> = op["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(params, ["id", "port", "wait_ready"]);
}
