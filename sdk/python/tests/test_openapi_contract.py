# SPDX-License-Identifier: Apache-2.0
"""The SDK's wire models against ``docs/api/openapi.json``, the server's own contract.

``docs/api/openapi.json`` is generated from the server code and committed (spec §7). Every
request and response model the SDK defines is compared with its schema there: field names,
required fields and types. If the server's OpenAPI drifts from the SDK, a test here fails.

The test reads the file and makes no network calls.

Every model and every route the SDK uses is in the registries below: there is no pending list.
A model or route that is not in the document yet must wait for its server task, not be excused here.

The document is loaded by the ``openapi`` fixture, not at import: the module-level ``skipif``
below skips the tests before any fixture runs, so outside the repository (an sdist) nothing
tries to open ``docs/api/openapi.json``.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from helpers import FakeServer, job_json
from pydantic import BaseModel

import p2pc
import p2pc._common as c
import p2pc.models as m

REPO_ROOT = Path(__file__).resolve().parents[3]
OPENAPI_PATH = REPO_ROOT / "docs" / "api" / "openapi.json"

pytestmark = pytest.mark.skipif(
    not (REPO_ROOT / "Cargo.toml").exists(),
    reason="not inside the P2PC repository (for example an sdist): no docs/api/openapi.json",
)


def load_openapi() -> dict[str, Any]:
    with OPENAPI_PATH.open(encoding="utf-8") as fh:
        loaded: dict[str, Any] = json.load(fh)
    return loaded


@pytest.fixture(scope="module")
def openapi() -> dict[str, Any]:
    return load_openapi()


@pytest.fixture(scope="module")
def schemas(openapi: dict[str, Any]) -> dict[str, Any]:
    components: dict[str, Any] = openapi["components"]["schemas"]
    return components


# --- JSON-schema normalisation -------------------------------------------------------------
class Schema:
    """A JSON schema with its ``$ref``s resolved against the document it came from."""

    def __init__(self, node: Any, defs: dict[str, Any]) -> None:
        self.node = node
        self.defs = defs

    def resolve(self) -> Schema:
        node = self.node
        while isinstance(node, dict) and "$ref" in node:
            node = self.defs[node["$ref"].rsplit("/", 1)[-1]]
        return Schema(node, self.defs)

    def sub(self, node: Any) -> Schema:
        return Schema(node, self.defs)

    def normal(self) -> tuple[Schema, bool]:
        """The schema without ``null`` alternatives, and whether ``null`` was allowed."""
        schema = self.resolve()
        node = schema.node
        if not isinstance(node, dict):
            return schema, False
        for key in ("oneOf", "anyOf"):
            if key in node:
                alternatives = [self.sub(alt) for alt in node[key]]
                live = [a for a in alternatives if not a.is_null()]
                nullable = len(live) != len(alternatives)
                if len(live) == 1:
                    inner, inner_null = live[0].normal()
                    return inner, nullable or inner_null
                return schema, nullable
        if "allOf" in node:
            return schema.merged(), False
        types = node.get("type")
        if isinstance(types, list) and "null" in types:
            rest = [t for t in types if t != "null"]
            return self.sub({**node, "type": rest[0] if len(rest) == 1 else rest}), True
        return schema, False

    def is_null(self) -> bool:
        node = self.resolve().node
        return isinstance(node, dict) and node.get("type") == "null"

    def merged(self) -> Schema:
        """``allOf`` flattened into one object schema (how ``NewApiKey`` is built)."""
        node = self.resolve().node
        if not isinstance(node, dict) or "allOf" not in node:
            return self.resolve()
        props: dict[str, Any] = {}
        required: set[str] = set()
        for part in node["allOf"]:
            piece = self.sub(part).merged().node
            props |= piece.get("properties", {})
            required |= set(piece.get("required", []))
        extra = {k: v for k, v in node.items() if k not in ("allOf", "description")}
        return self.sub(
            {"type": "object", **extra, "properties": props, "required": sorted(required)}
        )

    def properties(self) -> dict[str, Schema]:
        node = self.merged().node
        return {k: self.sub(v) for k, v in node.get("properties", {}).items()}

    def required(self) -> set[str]:
        return set(self.merged().node.get("required", []))

    def forbids_extra(self) -> bool:
        return self.merged().node.get("additionalProperties") is False

    def kind(self) -> str:
        node = self.merged().node
        if "properties" in node:
            return "object"
        kind = node.get("type")
        if kind == "string" and node.get("format") == "date-time":
            return "datetime"
        if kind == "object":
            extra = node.get("additionalProperties")
            return "any-map" if extra in (None, True, {}) else "map"
        if kind is None:
            return "any"
        return str(kind)


def diff(sdk: Schema, api: Schema, path: str, *, request: bool) -> list[str]:
    """Differences between the SDK's schema and the server's, empty if they agree.

    A response model must have exactly the server's fields and required set: the SDK may not
    ask for what the server does not promise, nor drop what it sends. A request model may send a
    subset, but must send every required field (a non-nullable default counts as sent).
    """
    sdk_inner, sdk_null = sdk.normal()
    api_inner, api_null = api.normal()
    problems: list[str] = []
    if sdk_inner.kind() != api_inner.kind():
        return [f"{path}: SDK type {sdk_inner.kind()}, OpenAPI type {api_inner.kind()}"]
    kind = api_inner.kind()
    if sdk_null != api_null and not (sdk_null and not api_null and path.endswith("?")):
        problems.append(f"{path}: SDK nullable={sdk_null}, OpenAPI nullable={api_null}")
    if kind == "array":
        problems += diff(
            sdk_inner.sub(sdk_inner.merged().node["items"]),
            api_inner.sub(api_inner.merged().node["items"]),
            f"{path}[]",
            request=request,
        )
    elif kind == "map":
        problems += diff(
            sdk_inner.sub(sdk_inner.merged().node["additionalProperties"]),
            api_inner.sub(api_inner.merged().node["additionalProperties"]),
            f"{path}{{}}",
            request=request,
        )
    elif kind == "object":
        problems += diff_object(sdk_inner, api_inner, path, request=request)
    return problems


def diff_object(sdk: Schema, api: Schema, path: str, *, request: bool) -> list[str]:
    sdk_props, api_props = sdk.properties(), api.properties()
    sdk_required, api_required = sdk.required(), api.required()
    problems: list[str] = []
    problems.extend(
        f"{path}.{name}: in the SDK, not in the OpenAPI"
        for name in sorted(set(sdk_props) - set(api_props))
    )
    if request:
        for name in sorted(api_required):
            if name not in sdk_props:
                problems.append(f"{path}.{name}: required by the OpenAPI, missing in the SDK")
            elif name not in sdk_required and sdk_props[name].normal()[1]:
                problems.append(f"{path}.{name}: required by the OpenAPI, optional and null here")
        if sdk.forbids_extra() != api.forbids_extra():
            problems.append(f"{path}: additionalProperties differ (strict request types)")
    else:
        problems.extend(
            f"{path}.{name}: in the OpenAPI, not in the SDK"
            for name in sorted(set(api_props) - set(sdk_props))
        )
        if sdk_required != api_required:
            problems.append(
                f"{path}: required differ: SDK {sorted(sdk_required)}, "
                f"OpenAPI {sorted(api_required)}"
            )
    for name in sorted(set(sdk_props) & set(api_props)):
        # An optional, non-nullable member may be ``X | None = None`` in Python: absent == None.
        marker = "?" if name not in api_required else ""
        problems += diff(
            sdk_props[name], api_props[name], f"{path}.{name}{marker}", request=request
        )
    return problems


def sdk_schema(model: type[BaseModel]) -> Schema:
    schema = model.model_json_schema()
    return Schema(schema, schema.get("$defs", {}))


def api_schema(schemas: dict[str, Any], name: str) -> Schema:
    return Schema({"$ref": f"#/components/schemas/{name}"}, schemas)


def drift(
    schemas: dict[str, Any], model: type[BaseModel], schema_name: str, *, request: bool
) -> list[str]:
    return diff(sdk_schema(model), api_schema(schemas, schema_name), schema_name, request=request)


# --- registry: every model the SDK defines -------------------------------------------------
def sdk_model(name: str) -> type[BaseModel]:
    model = getattr(m, name, None)
    assert isinstance(model, type), f"p2pc.models.{name} is missing"
    return model  # type: ignore[no-any-return]


# (SDK model, OpenAPI schema). Strict request types: the body the SDK sends.
REQUESTS = [
    ("JobSpec", "JobSpec"),
    ("Resources", "Resources"),
    ("Egress", "Egress"),
    ("Placement", "Placement"),
    ("Retry", "Retry"),
    ("Outputs", "Outputs"),
    ("InputFile", "InputFile"),
    ("CreateApiKey", "CreateApiKey"),
    ("CreateJoinToken", "CreateJoinToken"),
]
# Lenient responses: what the SDK parses.
RESPONSES = [
    ("Job", "Job"),
    ("AsyncJob", "Job"),
    ("JobAttempt", "JobAttempt"),
    ("JobSpecView", "JobSpecView"),
    ("ResourcesView", "ResourcesView"),
    ("EgressView", "EgressView"),
    ("PlacementView", "PlacementView"),
    ("RetryView", "RetryView"),
    ("OutputsView", "OutputsView"),
    ("InputFileView", "InputFileView"),
    ("Estimate", "Estimate"),
    ("ApiKey", "ApiKeyInfo"),
    ("NewApiKey", "NewApiKey"),
    ("WhoAmI", "WhoAmI"),
    ("AuditEvent", "AuditEvent"),
    ("FieldError", "FieldError"),
    ("Node", "Node"),
    ("Inventory", "Inventory"),
    ("Capacity", "Capacity"),
    ("CpuInfo", "CpuInfo"),
    ("GpuInfo", "GpuInfo"),
    ("GpuStatus", "GpuStatus"),
    ("SandboxCapability", "SandboxCapability"),
    ("Wsl2Health", "Wsl2Health"),
    ("SmokeResult", "SmokeResult"),
    ("JoinToken", "JoinTokenResponse"),
    ("JoinTokenInfo", "JoinTokenInfo"),
    ("ServerInfo", "ServerInfo"),
    ("UsageReport", "UsageReport"),
    ("UsageTotals", "UsageTotals"),
    ("LogLine", "LogLine"),
    ("OutputFile", "OutputEntry"),
]
# Pagination envelope and its item type.
PAGES = [
    ("Job", "Page_Job"),
    ("ApiKey", "Page_ApiKeyInfo"),
    ("AuditEvent", "Page_AuditEvent"),
    ("Node", "Page_Node"),
    ("JoinTokenInfo", "Page_JoinTokenInfo"),
    ("OutputFile", "Page_OutputEntry"),
]
# Helper base classes that are not wire shapes.
INTERNAL = {"_Request", "_Response", "_JobFields", "Page"}


@pytest.mark.parametrize(("model", "schema"), REQUESTS, ids=[r[1] for r in REQUESTS])
def test_request_model_matches_openapi(schemas: dict[str, Any], model: str, schema: str) -> None:
    assert drift(schemas, sdk_model(model), schema, request=True) == []


@pytest.mark.parametrize(("model", "schema"), RESPONSES, ids=[r[0] for r in RESPONSES])
def test_response_model_matches_openapi(schemas: dict[str, Any], model: str, schema: str) -> None:
    assert drift(schemas, sdk_model(model), schema, request=False) == []


@pytest.mark.parametrize(("item", "schema"), PAGES, ids=[p[1] for p in PAGES])
def test_page_matches_openapi(schemas: dict[str, Any], item: str, schema: str) -> None:
    page = m.Page[sdk_model(item)]  # type: ignore[misc]
    assert drift(schemas, page, schema, request=False) == []


def test_every_sdk_model_is_covered_by_the_contract() -> None:
    covered = {r[0] for r in REQUESTS} | {r[0] for r in RESPONSES} | INTERNAL
    defined = {
        name
        for name, obj in vars(m).items()
        if isinstance(obj, type)
        and issubclass(obj, BaseModel)
        and obj.__module__ == m.__name__
        and obj.__name__ == name  # an alias such as JobResources is not a second model
    }
    assert defined - covered == set(), "add these models to the contract registry"
    assert {p[0] for p in PAGES} <= covered


# --- the checker itself: it must notice drift ----------------------------------------------
def mutated(schemas: dict[str, Any], change: Any) -> dict[str, Any]:
    changed = copy.deepcopy(schemas)
    change(changed)
    return changed


def drift_against(schemas: dict[str, Any], model: str, schema: str, *, request: bool) -> list[str]:
    return diff(
        sdk_schema(sdk_model(model)),
        Schema({"$ref": f"#/components/schemas/{schema}"}, schemas),
        schema,
        request=request,
    )


def test_checker_notices_a_new_response_field(schemas: dict[str, Any]) -> None:
    schemas = mutated(
        schemas, lambda s: s["Job"]["properties"].update(new_field={"type": "string"})
    )
    assert any("new_field" in p for p in drift_against(schemas, "Job", "Job", request=False))


def test_checker_notices_a_changed_type(schemas: dict[str, Any]) -> None:
    schemas = mutated(schemas, lambda s: s["Job"]["properties"]["attempt"].update(type="string"))
    assert any("attempt" in p for p in drift_against(schemas, "Job", "Job", request=False))


def test_checker_notices_a_changed_required_set(schemas: dict[str, Any]) -> None:
    schemas = mutated(schemas, lambda s: s["Job"]["required"].remove("spec"))
    assert any("required" in p for p in drift_against(schemas, "Job", "Job", request=False))


def test_checker_notices_a_new_required_request_field(schemas: dict[str, Any]) -> None:
    schemas = mutated(schemas, lambda s: s["Retry"].update(required=["max_attempts", "backoff"]))
    assert any("backoff" in p for p in drift_against(schemas, "Retry", "Retry", request=True))


def test_checker_notices_a_nested_change(schemas: dict[str, Any]) -> None:
    schemas = mutated(
        schemas, lambda s: s["ResourcesView"]["properties"]["cpu"].update(type="string")
    )
    assert any("spec" in p for p in drift_against(schemas, "Job", "Job", request=False))


# --- enums, paths and parameters -----------------------------------------------------------
def api_enum(schemas: dict[str, Any], name: str) -> set[str]:
    node = schemas[name]
    if "enum" in node:
        return set(node["enum"])
    return {alt["const"] if "const" in alt else alt["enum"][0] for alt in node["oneOf"]}


def test_enums_match_openapi(schemas: dict[str, Any]) -> None:
    assert set(m.KEY_SCOPES) == api_enum(schemas, "Scope")
    assert {s.value for s in m.JobStatus} == api_enum(schemas, "JobStatus")
    assert set(m.AUDIT_KINDS) == api_enum(schemas, "AuditKind")
    assert set(m.NODE_STATES) == api_enum(schemas, "NodeState")
    assert set(m.GPU_STATUS_KINDS) == api_enum(schemas, "GpuStatusKind")
    assert set(m.SANDBOX_CLASSES) == api_enum(schemas, "SandboxClass")
    assert set(m.PLATFORMS) == api_enum(schemas, "Platform")
    assert set(m.LOG_STREAMS) == api_enum(schemas, "LogStream")
    assert set(p2pc.FIELD_ERROR_CODES) == api_enum(schemas, "ErrorCode")


def test_problem_members_are_all_exposed_by_errors(schemas: dict[str, Any]) -> None:
    body: dict[str, Any] = {
        "type": "https://example.invalid/problems/validation_failed",
        "title": "Unprocessable Content",
        "status": 422,
        "detail": "see errors",
        "code": "validation_failed",
        "errors": [{"field": "resources.cpu", "code": "out_of_range", "message": "too big"}],
    }
    assert set(body) == set(schemas["Problem"]["properties"]), "Problem changed: update the SDK"
    import httpx

    from p2pc._common import error_from_response

    err = error_from_response(httpx.Response(422, json=body), None)
    for name, value in body.items():
        if name == "errors":
            assert [(e.field, e.code, e.message) for e in err.errors] == [
                ("resources.cpu", "out_of_range", "too big")
            ]
        else:
            assert getattr(err, name) == value


# The (method, path template) pairs the SDK calls; every one must be documented.
SDK_ENDPOINTS = [
    ("get", "/v1/whoami"),
    ("get", "/v1/server"),
    ("post", "/v1/jobs"),
    ("get", "/v1/jobs"),
    ("get", "/v1/jobs/{id}"),
    ("post", "/v1/jobs/{id}/cancel"),
    ("post", "/v1/estimate"),
    ("post", "/v1/keys"),
    ("get", "/v1/keys"),
    ("delete", "/v1/keys/{key_id}"),
    ("get", "/v1/audit"),
    ("get", "/v1/nodes"),
    ("get", "/v1/nodes/{id}"),
    ("post", "/v1/nodes/{id}/drain"),
    ("post", "/v1/nodes/{id}/resume"),
    ("delete", "/v1/nodes/{id}"),
    ("post", "/v1/nodes/join-tokens"),
    ("get", "/v1/nodes/join-tokens"),
    ("delete", "/v1/nodes/join-tokens/{id}"),
    ("get", "/v1/jobs/{id}/logs"),
    ("get", "/v1/jobs/{id}/outputs"),
    ("get", "/v1/jobs/{id}/outputs/{path}"),
    ("get", "/v1/usage"),
]


@pytest.mark.parametrize(
    ("method", "path"), SDK_ENDPOINTS, ids=[" ".join(e) for e in SDK_ENDPOINTS]
)
def test_sdk_endpoint_is_in_openapi(openapi: dict[str, Any], method: str, path: str) -> None:
    assert method in openapi["paths"].get(path, {}), f"{method.upper()} {path} is not documented"


def api_parameters(openapi: dict[str, Any], path: str, method: str) -> set[str]:
    return {p["name"] for p in openapi["paths"][path][method].get("parameters", [])}


def test_list_query_parameters_exist_in_openapi(
    openapi: dict[str, Any], client: p2pc.Client, server: FakeServer
) -> None:
    page = {"items": [], "next_cursor": None}
    for path in ("/v1/jobs", "/v1/keys", "/v1/audit", "/v1/nodes", "/v1/nodes/join-tokens"):
        server.on("GET", path, page)
    list(client.jobs.list(status="queued", node_id="node_1", limit=7))
    assert set(server.query()) <= api_parameters(openapi, "/v1/jobs", "get")
    client.keys.list()
    assert set(server.query()) <= api_parameters(openapi, "/v1/keys", "get")
    list(client.audit(kind="key_created", limit=7))
    assert set(server.query()) <= api_parameters(openapi, "/v1/audit", "get")
    assert server.query()["kind"] == "key_created"
    client.nodes.list(state="online")
    assert set(server.query()) <= api_parameters(openapi, "/v1/nodes", "get")
    assert server.query()["state"] == "online"
    client.join_tokens.list()
    assert set(server.query()) <= api_parameters(openapi, "/v1/nodes/join-tokens", "get")
    server.on(
        "GET",
        "/v1/usage",
        {
            "from": "2026-11-01T00:00:00Z",
            "to": "2026-11-02T00:00:00Z",
            "group_by": "key",
            "items": [],
            "next_cursor": None,
            "total": {
                "attempts": 0,
                "reserved_cpu_ms": 0,
                "reserved_gpu_ms": 0,
                "used_cpu_ms": 0,
                "max_rss_mb": 0,
                "units": 0,
            },
        },
    )
    client.usage(from_="2026-11-01T00:00:00Z", to="2026-11-02T00:00:00Z", group_by="key")
    assert set(server.query()) == {"from", "to", "group_by", "limit"}
    assert set(server.query()) <= api_parameters(openapi, "/v1/usage", "get")


def test_estimate_takes_a_job_spec_body(openapi: dict[str, Any]) -> None:
    body = openapi["paths"]["/v1/estimate"]["post"]["requestBody"]["content"]["application/json"]
    assert body["schema"]["$ref"].endswith("/JobSpec")


def test_logs_and_outputs_queries_and_the_digest_header_exist_in_openapi(
    openapi: dict[str, Any], client: p2pc.Client, server: FakeServer, tmp_path: Path
) -> None:
    from helpers import streamed

    logs, listing, download = (
        "/v1/jobs/j/logs",
        "/v1/jobs/j/outputs",
        "/v1/jobs/j/outputs/a.txt",
    )
    digest = hashlib.sha256(b"abc").hexdigest()
    server.on("GET", logs, lambda _req: streamed([]))
    server.on("GET", "/v1/jobs/j", job_json("j", "succeeded", attempt=2, exit_code=0))
    list(client.jobs.logs("j", follow=True, since_seq=3, attempt=2))
    sent = dict(next(r for r in server.requests if r.url.path == logs).url.params)
    assert sent == {"follow": "true", "since_seq": "3", "attempt": "2"}
    assert set(sent) <= api_parameters(openapi, "/v1/jobs/{id}/logs", "get")
    server.on("GET", listing, {"items": [{"path": "a.txt", "size": 3, "sha256": digest}]})
    server.on("GET", download, httpx.Response(200, content=b"abc"))
    client.jobs.download_output("j", "a.txt", tmp_path, attempt=2)
    for request in server.requests[-2:]:
        assert request.url.params["attempt"] == "2"
        assert "attempt" in api_parameters(openapi, "/v1/jobs/{id}/outputs", "get")
    assert "attempt" in api_parameters(openapi, "/v1/jobs/{id}/outputs/{path}", "get")
    ok = openapi["paths"]["/v1/jobs/{id}/outputs/{path}"]["get"]["responses"]
    assert "X-P2PC-SHA256" in ok["200"]["headers"]
    assert "410" in ok
    assert c.DIGEST_HEADER == "X-P2PC-SHA256"
