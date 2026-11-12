# SPDX-License-Identifier: Apache-2.0
"""Wire models for the Jobs API (§7 of the H1 spec).

Every JSON shape the SDK sends or receives is defined here and nowhere else, so this module
can later be replaced by code generated from the server's OpenAPI document.

Request models validate the §7 table client-side so obvious mistakes fail before the
request. The server stays authoritative: it may reject more (for example registries that are
not on its allowlist).

Security notes:

* ``hide_input_in_errors`` keeps user input (environment values, file contents) out of
  validation error messages.
* ``env`` and ``content_b64`` are excluded from ``repr``, and the full key of a new API key is
  a ``SecretStr``.
* Response models that may carry secrets ignore unknown members instead of storing them, so
  a surprise field can never end up in a ``repr``.
"""

from __future__ import annotations

import base64
import binascii
import copy
import ipaddress
import re
from collections.abc import AsyncGenerator, Awaitable, Callable, Iterator
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Generic, Literal, Self, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    SecretStr,
    field_validator,
    model_validator,
)

from p2pc.errors import ConfigurationError, FieldError, P2PCError

if TYPE_CHECKING:
    from p2pc.aclient import AsyncClient
    from p2pc.client import Client

__all__ = [
    "AUDIT_KINDS",
    "GPU_REQUIREMENTS",
    "GPU_STATUS_KINDS",
    "JOB_KINDS",
    "LOG_STREAMS",
    "NODE_APPROVALS",
    "NODE_STATES",
    "PLATFORMS",
    "RESTART_POLICIES",
    "SANDBOX_CLASSES",
    "SERVICE_HEALTHS",
    "SETUP_FAILURES",
    "SETUP_STATES",
    "TEMPLATE_PARAM_TYPES",
    "TEMPLATE_UIS",
    "ApiKey",
    "AsyncJob",
    "AuditEvent",
    "BlobInput",
    "BlobInputView",
    "Capacity",
    "CpuInfo",
    "CreateApiKey",
    "CreateJoinToken",
    "DevicePrincipal",
    "Egress",
    "EgressView",
    "Estimate",
    "FieldError",
    "GpuInfo",
    "GpuStatus",
    "HealthCheck",
    "HealthCheckView",
    "InputFile",
    "InputFileView",
    "Inventory",
    "Job",
    "JobAttempt",
    "JobResources",
    "JobSpec",
    "JobSpecView",
    "JobStatus",
    "JoinToken",
    "JoinTokenInfo",
    "KeyPrincipal",
    "LogLine",
    "NewApiKey",
    "Node",
    "OutputFile",
    "Outputs",
    "OutputsView",
    "Page",
    "Placement",
    "PlacementView",
    "Principal",
    "Resources",
    "ResourcesView",
    "Retry",
    "RetryView",
    "SandboxCapability",
    "ServerInfo",
    "ServicePort",
    "ServicePortView",
    "ServiceSetup",
    "ServiceSpec",
    "ServiceSpecView",
    "ServiceTraffic",
    "ServiceView",
    "SmokeResult",
    "TemplateInfo",
    "TemplateList",
    "TemplateParam",
    "TemplateRefView",
    "TemplateRequirements",
    "UsageReport",
    "UsageTotals",
    "VolumeSpec",
    "VolumeSpecView",
    "WhoAmI",
    "Wsl2Health",
]

# Spec §7: the files of a job are limited to 512 KiB in total, decoded. (The whole job must also
# fit one 1 MiB Lease frame; only the server can check that exactly, with 422 ``too_large``.)
MAX_FILES_BYTES = 512 * 1024
MAX_COMMAND_BYTES = 64 * 1024
MAX_ENV_BYTES = 32 * 1024
KEY_SCOPES = frozenset(
    {
        "admin",
        "jobs:write",
        "jobs:read",
        "nodes:read",
        "nodes:write",
        # H2 (spec §5.5).
        "services:connect",
        "templates:launch",
        "blobs:write",
        "nodes:invite",
        "nodes:join",
    }
)
NODE_STATES = frozenset({"online", "offline"})
LOG_STREAMS = frozenset({"stdout", "stderr"})
GPU_STATUS_KINDS = frozenset(
    {"ok", "no_driver", "nvml_error", "not_found", "cdi_missing", "cdi_stale"}
)
SANDBOX_CLASSES = frozenset({"container", "container-gvisor"})
PLATFORMS = frozenset({"linux", "wsl2"})
AUDIT_KINDS = frozenset(
    {
        "key_created",
        "key_revoked",
        "join_token_created",
        "join_token_consumed",
        "join_token_revoked",
        "node_enrolled",
        "node_reenrolled",
        "node_deleted",
        "auth_failed",
        "key_recovered",
        # H2 (spec §5.6).
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
    }
)
# H2 enums (spec §5.5, §7.1, §7.2). Response fields that carry them are plain strings, so a value a
# newer server adds still parses, as for the H1 enums above.
JOB_KINDS = frozenset({"batch", "service"})
RESTART_POLICIES = frozenset({"never", "on_node_loss"})
SERVICE_HEALTHS = frozenset({"starting", "healthy", "unhealthy"})
SETUP_STATES = frozenset({"pulling", "done", "failed"})
SETUP_FAILURES = frozenset({"error_line", "bad_line", "eof", "stream_broken", "deadline"})
NODE_APPROVALS = frozenset({"approved", "pending_approval"})
# Templates (spec §7.6): the UI a template gets, what it needs from a GPU, and its parameter types.
TEMPLATE_UIS = frozenset({"chat", "transcribe", "none"})
GPU_REQUIREMENTS = frozenset({"required", "preferred", "none"})
TEMPLATE_PARAM_TYPES = frozenset({"enum", "int", "bool", "blob"})
MAX_SERVICE_TIMEOUT_S = 2_592_000  # a service's wall-clock limit: 30 days, the maximum (spec §7.1)
MILLI = 1000  # milli-units per unit, and milli-vCPUs per vCPU (spec §11)
MIB = 1024 * 1024
MAX_OUTPUTS_MB = 10_240  # the server's largest outputs.max_mb
DEFAULT_OUTPUT_FILE_BYTES = 1024**3  # 1 GiB: a download cap when there is no job to ask
MAX_OUTPUT_FILE_BYTES = MAX_OUTPUTS_MB * MIB  # 10 GiB: no cap may go above it
MAX_IDEMPOTENCY_KEY_LEN = 255
REDACTED = "<redacted>"

_REQUEST_CONFIG = ConfigDict(extra="forbid", hide_input_in_errors=True)

# --- image reference ---------------------------------------------------------------------
_NAME_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_DOMAIN_LABEL = r"(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"
# As in Docker's reference grammar, the first component is a registry only if it has a dot or
# a port, or is "localhost"; otherwise it is a (lowercase-only) path component.
_REGISTRY = (
    rf"(?:{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})*:[0-9]+"
    rf"|{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})+"
    r"|localhost)"
)
# All three are used with `fullmatch`: `$` would also match before a trailing newline, and
# `\w` would accept non-ASCII letters and digits.
_IMAGE_RE = re.compile(
    rf"(?:{_REGISTRY}/)?{_NAME_COMPONENT}(?:/{_NAME_COMPONENT})*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?"
)
_ENV_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]*")
_ENV_VALUE_FORBIDDEN = ("\x00", "\n", "\r")
_EGRESS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class _Request(BaseModel):
    model_config = _REQUEST_CONFIG


class _Response(BaseModel):
    model_config = ConfigDict(extra="ignore")


# --- request models ----------------------------------------------------------------------
class Resources(_Request):
    """Resources reserved for the job. ``disk_mb=None`` lets the server default (2,048)."""

    cpu: float = Field(default=1, ge=0.25, le=256)
    memory_mb: int = Field(default=1024, ge=128, le=1_048_576)
    gpu: Literal[0, 1] = 0
    disk_mb: int | None = Field(default=None, ge=1)

    @field_validator("cpu")
    @classmethod
    def _check_milli_cpu(cls, value: float) -> float:
        # Units are computed from the value rounded to the nearest milli-vCPU (spec §7): the
        # server rejects anything finer, so say so before sending.
        if abs(value * MILLI - round(value * MILLI)) > 1e-6:
            raise ValueError("cpu must be a multiple of 0.001")
        return value


class Egress(_Request):
    """Domains the job may reach through the egress proxy (whole-label match)."""

    allow: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("allow")
    @classmethod
    def _check_domains(cls, value: list[str]) -> list[str]:
        for domain in value:
            _check_egress_domain(domain)
        return value


def _check_egress_domain(domain: str) -> None:
    if "*" in domain:
        raise ValueError("egress.allow: wildcards are not allowed")
    if domain != domain.lower():
        raise ValueError(f"egress.allow: {domain!r} must be lowercase")
    try:
        ipaddress.ip_address(domain.strip("[]"))
    except ValueError:
        pass
    else:
        raise ValueError("egress.allow: IP literals are not allowed")
    labels = domain.split(".")
    if len(domain) > 253 or not all(_EGRESS_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError(f"egress.allow: {domain!r} is not a valid domain name")
    if labels[-1].isdigit():
        # An all-numeric last label can only be an IPv4 literal in disguise (192.0.2.4, 127.1).
        raise ValueError("egress.allow: IP literals are not allowed")


def _default_pools() -> list[Literal["mine"]]:
    return ["mine"]


class Placement(_Request):
    """Where the job may run. Only the ``mine`` pool exists in v0.1."""

    pools: list[Literal["mine"]] = Field(default_factory=_default_pools)
    node_id: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class Retry(_Request):
    """Attempts are consumed only by node loss."""

    max_attempts: int = Field(default=2, ge=1, le=5)


class Outputs(_Request):
    """Cap on the files collected from ``/outputs``."""

    max_mb: int = Field(ge=1, le=MAX_OUTPUTS_MB)


class InputFile(_Request):
    """A file placed under ``/inputs`` before the job starts."""

    path: str
    content_b64: str = Field(repr=False)

    @classmethod
    def from_content(cls, path: str, content: bytes | str) -> Self:
        """Build an input file from raw bytes, or from a string (encoded as UTF-8)."""
        raw = content.encode() if isinstance(content, str) else content
        if len(raw) > MAX_FILES_BYTES:
            raise ValueError("input files are limited to 512 KiB in total")
        return cls(path=path, content_b64=base64.b64encode(raw).decode("ascii"))

    @field_validator("path")
    @classmethod
    def _check_path(cls, value: str) -> str:
        parts = value.split("/")
        if (
            not value.startswith("/inputs/")
            or len(value) > 4096
            or "\x00" in value
            or any(p in ("", ".", "..") for p in parts[1:])
        ):
            raise ValueError("file path must be an absolute path under /inputs, without '..'")
        return value

    @field_validator("content_b64")
    @classmethod
    def _check_b64(cls, value: str) -> str:
        try:
            base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("content_b64 is not valid base64") from None
        return value

    def decoded_size(self) -> int:
        return len(base64.b64decode(self.content_b64, validate=True))


# --- H2 request models (spec §7.1) --------------------------------------------------------
_BLOB_REF_RE = re.compile(r"sha256:[0-9a-f]{64}")
_PORT_NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_VOLUME_NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")


class ServicePort(_Request):
    """A port a service listens on inside its container. The shim forwards no other port."""

    port: int = Field(ge=1, le=65_535)
    name: str

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        if not _PORT_NAME_RE.fullmatch(value):
            raise ValueError("port name must match [a-z][a-z0-9-]{0,31}")
        return value


class HealthCheck(_Request):
    """How the agent decides a service is healthy: exactly one of ``http_get`` or ``tcp``."""

    port: int = Field(ge=1, le=65_535)
    http_get: str | None = None
    tcp: bool | None = None
    interval_s: int | None = Field(default=None, ge=2, le=300)
    timeout_s: int | None = Field(default=None, ge=1, le=60)
    start_period_s: int | None = Field(default=None, ge=0, le=3_600)
    failure_threshold: int | None = Field(default=None, ge=1, le=20)

    @model_validator(mode="after")
    def _check_one_probe(self) -> Self:
        if (self.http_get is None) == (not self.tcp):
            raise ValueError("health: give exactly one of http_get or tcp=True")
        if self.http_get is not None:
            path = self.http_get
            if (
                not path.startswith("/")
                or len(path.encode()) > 256
                or any(ch in path for ch in ("\r", "\n", "\x00"))
                or ".." in path.split("/")
            ):
                raise ValueError(
                    "health.http_get must be an absolute path of at most 256 bytes "
                    "without '..' or control characters"
                )
        return self


class ServiceSpec(_Request):
    """The ``service`` block of a ``kind="service"`` job.

    ``idle_timeout_s=None`` means *never* when it is set explicitly (``ServiceSpec(ports=[...],
    idle_timeout_s=None)``); leaving it out takes the server's default (3,600).
    """

    ports: list[ServicePort] = Field(min_length=1, max_length=8)
    health: HealthCheck | None = None
    idle_timeout_s: int | None = None
    restart: Literal["never", "on_node_loss"] | None = None

    @field_validator("idle_timeout_s")
    @classmethod
    def _check_idle(cls, value: int | None) -> int | None:
        if value is not None and not 300 <= value <= 604_800:
            raise ValueError("idle_timeout_s must be None (never) or 300-604800")
        return value

    @model_validator(mode="after")
    def _check_ports(self) -> Self:
        numbers = [p.port for p in self.ports]
        names = [p.name for p in self.ports]
        if len(set(numbers)) != len(numbers) or len(set(names)) != len(names):
            raise ValueError("service ports and their names must be unique")
        if self.health is not None and self.health.port not in numbers:
            raise ValueError("health.port must be one of the service ports")
        return self


class VolumeSpec(_Request):
    """A persistent volume (services only, spec §7.1, §11.3). ``name`` is a label, never a path."""

    name: str
    mount: str
    max_mb: int = Field(ge=64, le=262_144)

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        # `tpl:<id>/<name>` is for template launches only: the hub refuses it from a client.
        if not _VOLUME_NAME_RE.fullmatch(value):
            raise ValueError("volume name must match [a-z0-9][a-z0-9._-]{0,62}")
        return value

    @field_validator("mount")
    @classmethod
    def _check_mount(cls, value: str) -> str:
        parts = value.split("/")
        if (
            not value.startswith("/volumes/")
            or len(value) > 4096
            or "\x00" in value
            or any(p in ("", ".", "..") for p in parts[1:])
        ):
            raise ValueError("volume mount must be an absolute path under /volumes/, without '..'")
        return value


class BlobInput(_Request):
    """A blob delivered read-only at ``path`` (under ``/inputs``): ``blob`` is ``sha256:<hex>``."""

    path: str
    blob: str

    @field_validator("path")
    @classmethod
    def _check_path(cls, value: str) -> str:
        parts = value.split("/")
        if (
            not value.startswith("/inputs/")
            or len(value) > 4096
            or "\x00" in value
            or any(p in ("", ".", "..") for p in parts[1:])
        ):
            raise ValueError("input path must be an absolute path under /inputs, without '..'")
        return value

    @field_validator("blob")
    @classmethod
    def _check_blob(cls, value: str) -> str:
        if not _BLOB_REF_RE.fullmatch(value):
            raise ValueError(
                "blob must be a digest 'sha256:' and 64 lowercase hex digits, as "
                "client.blobs.put returns it"
            )
        return value


class JobSpec(_Request):
    """The body of ``POST /v1/jobs``."""

    kind: Literal["batch", "service"] | None = None
    name: str | None = None
    image: str
    command: list[str]
    env: dict[str, str] | None = Field(default=None, repr=False)
    files: list[InputFile] | None = None
    inputs: list[BlobInput] | None = Field(default=None, max_length=32)
    volumes: list[VolumeSpec] | None = Field(default=None, max_length=4)
    service: ServiceSpec | None = None
    resources: Resources = Field(default_factory=Resources)
    timeout_s: int | None = Field(default=None, ge=1, le=MAX_SERVICE_TIMEOUT_S)
    egress: Egress | None = None
    outputs: Outputs | None = None
    placement: Placement | None = None
    retry: Retry | None = None
    idempotency_key: str | None = None

    @field_validator("idempotency_key")
    @classmethod
    def _check_idempotency_key(cls, value: str | None) -> str | None:
        # Header-safe like the server's rule: ASCII graphic characters only, no spaces.
        if value is not None and (
            not 1 <= len(value) <= MAX_IDEMPOTENCY_KEY_LEN
            or not all("!" <= ch <= "~" for ch in value)
        ):
            raise ValueError(
                f"idempotency_key must be 1-{MAX_IDEMPOTENCY_KEY_LEN} printable ASCII "
                "characters without spaces"
            )
        return value

    @field_validator("image")
    @classmethod
    def _check_image(cls, value: str) -> str:
        if len(value) > 255 or not _IMAGE_RE.fullmatch(value):
            raise ValueError("image is not a valid OCI reference")
        return value

    @field_validator("command")
    @classmethod
    def _check_command(cls, value: list[str]) -> list[str]:
        if not 1 <= len(value) <= 256:
            raise ValueError("command must have 1-256 arguments")
        if sum(len(arg.encode()) for arg in value) > MAX_COMMAND_BYTES:
            raise ValueError("command is limited to 64 KiB in total")
        return value

    @field_validator("env")
    @classmethod
    def _check_env(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        if value is None:
            return value
        if len(value) > 64:
            raise ValueError("env is limited to 64 variables")
        total = 0
        for name, val in value.items():
            if not _ENV_NAME_RE.fullmatch(name):
                raise ValueError(f"env name {name!r} must match [A-Z_][A-Z0-9_]*")
            if name.startswith("P2PC_"):
                raise ValueError(f"env name {name!r} is reserved (P2PC_ prefix)")
            if any(ch in val for ch in _ENV_VALUE_FORBIDDEN):
                # Values go into a line-based env file: a newline would inject a variable.
                # The message names the variable, never its value.
                raise ValueError(
                    f"env value of {name!r} may not contain NUL, newline or carriage return; "
                    "encode multi-line values (for example base64) or pass them as files"
                )
            total += len(name.encode()) + len(val.encode())
        if total > MAX_ENV_BYTES:
            raise ValueError("env is limited to 32 KiB in total")
        return value

    @model_validator(mode="after")
    def _check_files_total(self) -> Self:
        if self.files and sum(f.decoded_size() for f in self.files) > MAX_FILES_BYTES:
            raise ValueError("input files are limited to 512 KiB in total (decoded)")
        return self

    @model_validator(mode="after")
    def _check_kind(self) -> Self:
        service = self.kind == "service"
        if service != (self.service is not None):
            raise ValueError("service is required for kind='service' and forbidden otherwise")
        if not service:
            if self.timeout_s is not None and self.timeout_s > 86_400:
                raise ValueError("timeout_s of a batch job is at most 86400")
            if self.volumes:
                raise ValueError("volumes are allowed only for kind='service' jobs")
        elif self.timeout_s is not None and self.timeout_s < 60:
            raise ValueError("timeout_s of a service is 60-2592000")
        if self.volumes:
            names = [v.name for v in self.volumes]
            if len(set(names)) != len(names):
                raise ValueError("volume names must be unique")
        if self.inputs:
            paths = [i.path for i in self.inputs]
            if len(set(paths)) != len(paths):
                raise ValueError("input paths must be unique")
        return self

    def to_wire(self) -> dict[str, Any]:
        """JSON-ready body: unset optional members are omitted so server defaults apply.

        One ``None`` is meaningful and kept: ``service.idle_timeout_s`` set explicitly to
        ``None`` means *never idle out*.
        """
        wire = self.model_dump(mode="json", exclude_none=True)
        if (
            self.service is not None
            and "idle_timeout_s" in self.service.model_fields_set
            and self.service.idle_timeout_s is None
        ):
            wire["service"]["idle_timeout_s"] = None
        return wire


# --- response models ---------------------------------------------------------------------
class JobStatus(StrEnum):
    QUEUED = "queued"
    ASSIGNED = "assigned"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    LOST = "lost"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL


_TERMINAL = frozenset(
    {
        JobStatus.SUCCEEDED,
        JobStatus.FAILED,
        JobStatus.TIMED_OUT,
        JobStatus.CANCELLED,
        JobStatus.LOST,
    }
)


class LogLine(_Response):
    """One NDJSON record of ``GET /v1/jobs/{id}/logs``: ``{seq, stream, ts, data}``.

    ``seq`` counts from 0 within one attempt. ``stream`` is one of :data:`LOG_STREAMS`;
    ``data`` is UTF-8 text (invalid bytes were replaced by the server). Past 64 MiB per attempt
    the server stores one last ``stderr`` line that also has ``truncated: true``: see
    :attr:`truncated`.
    """

    # Not closed to unknown members: `truncated` is documented in prose only, so it is read from
    # the extras (the schema lists exactly seq, stream, ts and data, as the contract test checks).
    model_config = ConfigDict(extra="allow")

    seq: int = Field(ge=0)
    stream: str
    ts: datetime
    data: str

    @property
    def truncated(self) -> bool:
        """This is the marker that the attempt's log hit the server's 64 MiB cap."""
        return bool(self.model_extra and self.model_extra.get("truncated") is True)


class OutputFile(_Response):
    """An entry of ``GET /v1/jobs/{id}/outputs``: the server publishes ``path``, ``size`` and
    ``sha256`` (64 lowercase hex characters) for every file. After the server's GC (7 days by
    default) an entry has ``expired=True`` and cannot be downloaded."""

    path: str
    size: int = Field(ge=0)
    sha256: str
    expired: bool = False


class ResourcesView(_Response):
    """Resources as the server reports them: no request bounds, so a job always parses."""

    cpu: float
    memory_mb: int
    gpu: int = 0
    disk_mb: int | None = None


JobResources = ResourcesView  # the name 0.1.0 used


class EgressView(_Response):
    allow: list[str] = Field(default_factory=list)


class PlacementView(_Response):
    pools: list[str] = Field(default_factory=list)
    node_id: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class RetryView(_Response):
    max_attempts: int | None = None


class OutputsView(_Response):
    max_mb: int | None = None


class InputFileView(_Response):
    """An input file as the API shows it: path, decoded size and SHA-256, never the content."""

    path: str
    size: int
    sha256: str


class ServicePortView(_Response):
    """One exposed port of a service (H2 spec §7.1)."""

    port: int
    name: str


class HealthCheckView(_Response):
    """A service health check: ``http_get`` (a path) or ``tcp``, on one of the service's ports."""

    port: int
    http_get: str | None = None
    tcp: bool = False
    interval_s: int = 10
    timeout_s: int = 3
    start_period_s: int = 300
    failure_threshold: int = 3


class ServiceSpecView(_Response):
    """The ``service`` block of a service job (H2 spec §7.1). ``idle_timeout_s=None`` is never.

    ``restart`` is one of :data:`RESTART_POLICIES`, kept as a string.
    """

    ports: list[ServicePortView]
    health: HealthCheckView | None = None
    idle_timeout_s: int | None = 3600
    restart: str = "on_node_loss"


class VolumeSpecView(_Response):
    """A persistent volume of a job (H2 spec §7.1): a name, never a host path."""

    name: str
    mount: str
    max_mb: int


class BlobInputView(_Response):
    """A blob input (H2 spec §7.1): the blob ``sha256:<hex>``, delivered read-only at ``path``."""

    path: str
    blob: str


class TemplateRefView(_Response):
    """The template a job was launched from (H2 spec §7.6)."""

    id: str
    version: int
    pull: str | None = None


class JobSpecView(_Response):
    """The spec of a job as returned by the API (spec §7, "Job representation in responses").

    The image is normalized, every ``env`` value is the string ``"<redacted>"`` and files carry
    no content. Idempotency keys are never returned.

    The H2 members (``kind``, ``service``, ``volumes``, ``inputs``, ``template``) default to an H1
    batch job, which is what an H1 server's jobs are. ``kind`` is one of :data:`JOB_KINDS`.
    """

    name: str | None = None
    image: str
    command: list[str]
    env: dict[str, str] = Field(default_factory=dict, repr=False)
    files: list[InputFileView] = Field(default_factory=list)
    resources: ResourcesView
    timeout_s: int | None = None
    egress: EgressView = Field(default_factory=EgressView)
    outputs: OutputsView | None = None
    placement: PlacementView = Field(default_factory=PlacementView)
    retry: RetryView | None = None
    kind: str = "batch"
    service: ServiceSpecView | None = None
    volumes: list[VolumeSpecView] = Field(default_factory=list)
    inputs: list[BlobInputView] = Field(default_factory=list)
    template: TemplateRefView | None = None


class ServiceSetup(_Response):
    """The hub's model pull of a template service (H2 spec §7.2, §7.6).

    ``state`` is one of :data:`SETUP_STATES`, ``reason`` one of :data:`SETUP_FAILURES`.
    """

    state: str
    completed_mb: int = 0
    total_mb: int | None = None
    tries: int = 0
    reason: str | None = None


class ServiceTraffic(_Response):
    """A service's traffic for one UTC day, recorded and not billed (H2 spec §12)."""

    day: datetime
    bytes_in: int = 0
    bytes_out: int = 0
    connections: int = 0


class ServiceView(_Response):
    """The ``service`` member of a service job (H2 spec §7.2). Every member is optional.

    ``health`` is one of :data:`SERVICE_HEALTHS`, or ``None`` while the service is not running.
    """

    health: str | None = None
    health_since: datetime | None = None
    ports: list[ServicePortView] = Field(default_factory=list)
    open_connections: int = 0
    last_activity_at: datetime | None = None
    idle_deadline: datetime | None = None
    deadline: datetime | None = None
    cap_deadline: datetime | None = None
    restarts_24h: int = 0
    setup: ServiceSetup | None = None
    traffic: ServiceTraffic | None = None


class JobAttempt(_Response):
    """One attempt of a job, in ``Job.attempts`` (spec §7): an accepted lease, on one node.

    ``outcome`` is in job-state words: ``running`` while the attempt is in progress, then
    ``succeeded``, ``failed``, ``timed_out``, ``cancelled`` or ``lost`` (also what an attempt
    replaced after node loss ends as). ``started_at`` is ``None`` until the job process starts, and
    stays ``None`` if it never did (lost during the image pull); ``ended_at`` and ``reason`` are
    ``None`` while the attempt runs.
    """

    attempt: int
    node_id: str
    outcome: JobStatus
    reason: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None


class _JobFields(_Response):
    id: str
    project_id: str
    status: JobStatus
    attempt: int
    spec: JobSpecView
    estimated_units: int = Field(
        description="milli-units reserved by the job (resources x timeout)"
    )
    created_at: datetime
    name: str | None = None
    node_id: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    exit_code: int | None = None
    error: str | None = None
    reason: str | None = None
    cancel_requested_at: datetime | None = None
    attempts: list[JobAttempt] | None = Field(
        default=None,
        description="oldest first; only in jobs.get (a list of jobs leaves the field out)",
    )
    service: ServiceView | None = Field(
        default=None, description="only for service jobs (H2 spec §7.2)"
    )

    # --- equality and copies --------------------------------------------------------------
    # The bound client lives in a private attribute that pydantic would compare and deep-copy.
    # It is not part of what a job *is*: two jobs with the same data are equal whichever client
    # returned them, and a copy shares the client (an HTTP client cannot be duplicated).
    def __eq__(self, other: object) -> bool:
        if type(other) is not type(self):
            return NotImplemented
        assert isinstance(other, _JobFields)  # noqa: S101 - narrowing for the type checker
        return (
            self.__dict__ == other.__dict__ and self.__pydantic_extra__ == other.__pydantic_extra__
        )

    def _clone(self, *, deep: bool, memo: dict[int, Any] | None = None) -> Self:
        clone = type(self).__new__(type(self))
        fields = copy.deepcopy(self.__dict__, memo) if deep else copy.copy(self.__dict__)
        extra = self.__pydantic_extra__
        if deep:
            extra = copy.deepcopy(extra, memo)
        private = self.__pydantic_private__
        object.__setattr__(clone, "__dict__", fields)
        object.__setattr__(clone, "__pydantic_extra__", extra)
        object.__setattr__(
            clone, "__pydantic_fields_set__", copy.copy(self.__pydantic_fields_set__)
        )
        # A new dict, the same values: the client is shared, never copied.
        object.__setattr__(
            clone, "__pydantic_private__", None if private is None else dict(private)
        )
        return clone

    def __copy__(self) -> Self:
        return self._clone(deep=False)

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        return self._clone(deep=True, memo=memo)

    @property
    def is_terminal(self) -> bool:
        return self.status.is_terminal

    @property
    def hint(self) -> str | None:
        """One line on how to fix a failed job, or ``None``. Today: a job that ended with
        ``error="disk_limit"`` wrote more than its disk limit; run it again with a larger
        ``disk_mb``."""
        if self.error != "disk_limit":
            return None
        limit = self.spec.resources.disk_mb
        shown = f" ({limit} MiB)" if limit is not None else ""
        return (
            f"the job wrote more than its disk limit{shown}: "
            "run it again with a larger `disk_mb` (Resources(disk_mb=...))"
        )

    @property
    def image(self) -> str:
        """The normalized image reference (``spec.image``)."""
        return self.spec.image

    @property
    def command(self) -> list[str]:
        return self.spec.command

    @property
    def resources(self) -> ResourcesView:
        return self.spec.resources


def _outputs_cap(spec: JobSpecView) -> int:
    """Bytes allowed for one file of this job: its own ``outputs.max_mb`` (the most it can
    collect in total), up to the server's maximum; 1 GiB when the job states no limit."""
    if spec.outputs is None or spec.outputs.max_mb is None:
        return DEFAULT_OUTPUT_FILE_BYTES
    return min(spec.outputs.max_mb * MIB, MAX_OUTPUT_FILE_BYTES)


def _unbound() -> ConfigurationError:
    return ConfigurationError("this object is not bound to a client; use client.jobs instead")


class Job(_JobFields):
    """A job, bound to the :class:`~p2pc.Client` that returned it."""

    _client: Client | None = PrivateAttr(default=None)

    def _bind(self, client: Client) -> Self:
        self._client = client
        return self

    def _require(self) -> Client:
        if self._client is None:
            raise _unbound()
        return self._client

    def wait(self, timeout: float | None = None, poll_interval: float = 2.0) -> Job:
        """Poll until a terminal state. Raises :class:`TimeoutError` after ``timeout`` s."""
        return self._require().jobs.wait(self.id, timeout=timeout, poll_interval=poll_interval)

    def logs(
        self,
        follow: bool = False,
        since_seq: int = 0,
        attempt: int | None = None,
        *,
        on_outage: Callable[[P2PCError], None] | None = None,
    ) -> Iterator[LogLine]:
        """Logs of one attempt (the latest by default); ``since_seq`` is inclusive. With
        ``follow``, ``on_outage`` is called once per outage: see ``Client.jobs.logs``."""
        return self._require().jobs.logs(
            self.id, follow=follow, since_seq=since_seq, attempt=attempt, on_outage=on_outage
        )

    def outputs(self, attempt: int | None = None) -> list[OutputFile]:
        return self._require().jobs.outputs(self.id, attempt=attempt)

    def download_output(self, path: str, dest: str | Path, attempt: int | None = None) -> Path:
        """Download one output file, capped at this job's own ``outputs.max_mb`` (up to the
        server's maximum of 10 240 MiB, even above 1 GiB); 1 GiB if the job states no limit."""
        return self._require().jobs.download_output(
            self.id,
            path,
            dest,
            max_bytes=_outputs_cap(self.spec),
            attempt=attempt,
        )

    def cancel(self) -> Job:
        return self._require().jobs.cancel(self.id)


class AsyncJob(_JobFields):
    """A job, bound to the :class:`~p2pc.AsyncClient` that returned it."""

    _client: AsyncClient | None = PrivateAttr(default=None)

    def _bind(self, client: AsyncClient) -> Self:
        self._client = client
        return self

    def _require(self) -> AsyncClient:
        if self._client is None:
            raise _unbound()
        return self._client

    async def wait(self, timeout: float | None = None, poll_interval: float = 2.0) -> AsyncJob:
        """Poll until a terminal state. Raises :class:`TimeoutError` after ``timeout`` s."""
        return await self._require().jobs.wait(
            self.id, timeout=timeout, poll_interval=poll_interval
        )

    def logs(
        self,
        follow: bool = False,
        since_seq: int = 0,
        attempt: int | None = None,
        *,
        on_outage: Callable[[P2PCError], Awaitable[None] | None] | None = None,
    ) -> AsyncGenerator[LogLine, None]:
        """Async iterator of :class:`LogLine` of one attempt (the latest by default).

        To stop early, close it: ``async with contextlib.aclosing(job.logs()) as logs: ...``.
        With ``follow``, ``on_outage`` is called once per outage: see ``AsyncClient.jobs.logs``.
        """
        return self._require().jobs.logs(
            self.id, follow=follow, since_seq=since_seq, attempt=attempt, on_outage=on_outage
        )

    async def outputs(self, attempt: int | None = None) -> list[OutputFile]:
        return await self._require().jobs.outputs(self.id, attempt=attempt)

    async def download_output(
        self, path: str, dest: str | Path, attempt: int | None = None
    ) -> Path:
        """Download one output file, capped at this job's own ``outputs.max_mb`` (up to the
        server's maximum of 10 240 MiB, even above 1 GiB); 1 GiB if the job states no limit."""
        return await self._require().jobs.download_output(
            self.id,
            path,
            dest,
            max_bytes=_outputs_cap(self.spec),
            attempt=attempt,
        )

    async def cancel(self) -> AsyncJob:
        return await self._require().jobs.cancel(self.id)


class Estimate(_Response):
    feasible: bool
    matching_nodes: int
    would_queue: bool
    units_per_hour: int = Field(description="milli-units reserved per hour")
    reason: str | None = None


class ApiKey(_Response):
    """An API key as listed by ``GET /v1/keys``. Never contains the key itself.

    ``daily_unit_cap`` is in milli-units (1 unit = 1,000).
    """

    id: str
    project_id: str
    scopes: list[str]
    created_at: datetime
    label: str | None = None
    daily_unit_cap: int | None = None
    allowed_images: list[str] | None = None
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


class NewApiKey(ApiKey):
    """The response of ``keys.create``: the key's metadata, flat, plus the full key, once."""

    key: SecretStr


class KeyPrincipal(_Response):
    """A principal that is an API key (H2 spec §5.5): ``{"kind": "key", "id": <key id>}``."""

    kind: Literal["key"]
    id: str


class DevicePrincipal(_Response):
    """A principal that is a paired device (H2 spec §5.5): ``{"kind": "device", "id": "dev_…"}``."""

    kind: Literal["device"]
    id: str


Principal = Annotated[KeyPrincipal | DevicePrincipal, Field(discriminator="kind")]
"""Who authenticated a request (H2 spec §5.5): an API key or a paired device."""


class WhoAmI(_Response):
    """``GET /v1/whoami``: the presented key and its limits. Never its secret.

    ``principal`` is ``None`` from an H1 server, whose callers are always the ``key_id`` key.
    ``key_id`` is the API key's ID; it is ``None`` only when the caller is a paired device (H2
    spec §5.5), which ``principal`` then names. A caller that uses an API key always gets its ID.
    """

    account_id: str
    project_id: str
    scopes: list[str]
    key_id: str | None = None
    label: str | None = None
    daily_unit_cap: int | None = None
    allowed_images: list[str] | None = None
    expires_at: datetime | None = None
    principal: Principal | None = None


class AuditEvent(_Response):
    """One row of the append-only audit log (``detail`` never holds a secret).

    At most one of ``actor_key_id`` and ``actor_device_id`` is set.
    """

    id: str
    at: datetime
    kind: str
    detail: dict[str, Any]
    actor_key_id: str | None = None
    actor_device_id: str | None = None
    subject_id: str | None = None


class CreateApiKey(_Request):
    """The body of ``POST /v1/keys``. ``daily_unit_cap`` is in milli-units."""

    scopes: list[str] = Field(min_length=1)
    daily_unit_cap: int | None = Field(default=None, ge=0)
    allowed_images: list[str] | None = None
    label: str | None = None
    expires_at: datetime | None = None

    @field_validator("scopes")
    @classmethod
    def _check_scopes(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - KEY_SCOPES)
        if unknown:
            raise ValueError(f"unknown scopes {unknown}; valid scopes: {sorted(KEY_SCOPES)}")
        return value

    @field_validator("expires_at")
    @classmethod
    def _whole_seconds_utc(cls, value: datetime | None) -> datetime | None:
        # The server wants a future time in whole seconds. Dropping the fraction can only
        # shorten the key's life, never extend it.
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).replace(microsecond=0)

    def to_wire(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


class JoinToken(_Response):
    """``POST /v1/nodes/join-tokens``: the token, shown once. ``id`` revokes it."""

    id: str
    join_token: SecretStr
    expires_at: datetime


class CreateJoinToken(_Request):
    """The body of ``POST /v1/nodes/join-tokens``."""

    label: str | None = None
    ttl_s: int | None = Field(default=None, ge=1, le=86_400)

    def to_wire(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


class JoinTokenInfo(_Response):
    """A join token as listed by ``GET /v1/nodes/join-tokens``. Never the token or its code.

    ``created_by`` names the principal that minted it (H2 spec §5.6); it is ``None`` from an H1
    server, whose tokens are always minted by the ``created_by_key_id`` key. ``created_by_key_id``
    is ``None`` when a paired device minted the token. ``pre_approved`` and ``bound_iroh_node_id``
    (H2 spec §5.4) keep their H1 values, ``False`` and ``None``, when the server leaves them out.
    """

    id: str
    label: str | None = None
    created_by_key_id: str | None = None
    created_by: Principal | None = None
    pre_approved: bool = False
    bound_iroh_node_id: str | None = None
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None
    consumed_by_node_id: str | None = None
    revoked_at: datetime | None = None


class Capacity(_Response):
    """An amount of node capacity: vCPUs, whole GPUs and memory in MiB.

    ``disk_mb`` is the disk for job directories in MiB, when the agent reports it (``None`` for an
    older agent, which the scheduler places by the other three).
    """

    cpu: float
    gpu: int
    memory_mb: int
    disk_mb: int | None = None


class CpuInfo(_Response):
    cores: int
    model: str


class GpuInfo(_Response):
    """One GPU. The ``uuid`` is its key; the index is informational."""

    uuid: str
    index: int
    name: str
    driver_version: str
    compute_capability: str | None = None
    cuda_driver_version: str | None = None
    mig: bool = False
    pci_bdf: str | None = None
    vram_mb: int | None = None


class GpuStatus(_Response):
    status: str
    reason: str | None = None


class SandboxCapability(_Response):
    """A sandbox driver the node can use. ``class`` is spelled ``sandbox_class`` here."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    sandbox_class: str = Field(alias="class")
    driver: str
    runtimes: list[str]
    problems: list[str] = Field(default_factory=list)
    ready: bool = False  # an inventory without it decodes as not ready: fail closed (spec)


class SmokeResult(_Response):
    ok: bool
    detail: str | None = None


class Wsl2Health(_Response):
    cdi_present: bool
    cdi_stale: bool
    distro_version: str | None = None
    podman_version: str | None = None
    smoke: SmokeResult | None = None


class Inventory(_Response):
    """What a node has, as the agent last reported it."""

    agent_version: str
    arch: str
    cpu: CpuInfo
    gpu_status: GpuStatus
    hostname: str
    memory_mb: int
    offered: Capacity
    os: str
    platform: str
    disk_total_mb: int | None = None
    dxg: bool = False
    gpus: list[GpuInfo] = Field(default_factory=list)
    # Reported only by an agent with `share_update` (H2 §6.1): the disk share for volumes, and the owner's pause.
    owner_paused: bool | None = None
    sandbox: list[SandboxCapability] = Field(default_factory=list)
    volumes_mb: int | None = None
    wsl2: Wsl2Health | None = None


class Node(_Response):
    """An enrolled node (spec §7). ``name`` is derived by the server and unique per account.

    ``approval`` is one of :data:`NODE_APPROVALS`: a ``pending_approval`` node gets no work until
    an admin approves it (H2 spec §5.5). An H1 server's nodes are ``approved``.
    """

    id: str
    name: str
    hostname: str
    state: str
    draining: bool
    created_at: datetime
    free: Capacity
    inventory: Inventory
    labels: dict[str, str] = Field(default_factory=dict)
    last_seen: datetime | None = None
    approval: str = "approved"
    enrolled_by: Principal | None = None
    node_phrase: str | None = None


class ServerInfo(_Response):
    """``GET /v1/server``: how to reach the server's iroh endpoint. Nothing in it is secret.

    ``api_version`` is 1 for an H1 server (which leaves it out) and 2 for H2 (H2 spec §7.3).
    """

    node_id: str
    relays: list[str]
    address: str
    version: str
    api_version: int = 1
    min_web_version: str | None = None
    hub_name: str | None = None
    max_blob_mb: int | None = None


class UsageTotals(_Response):
    """The totals of a set of ledger rows: one group of ``GET /v1/usage``, or the whole range.

    Times are in milliseconds, ``max_rss_mb`` in MiB and ``units`` in milli-units (spec §11).
    ``key`` is the job, node or key ID of the group, and ``None`` in :attr:`UsageReport.total`.
    ``estimated_attempts`` counts how many of ``attempts`` are server estimates (a node that
    never reported its usage); the server leaves it out when there are none.
    ``estimated_slices`` counts every estimated ledger row, midnight slices of running services
    included (H2 spec §12); also left out when 0.
    """

    attempts: int
    reserved_cpu_ms: int
    reserved_gpu_ms: int
    used_cpu_ms: int
    max_rss_mb: int
    units: int = Field(description="milli-units")
    key: str | None = None
    estimated_attempts: int = 0
    estimated_slices: int = 0


class UsageReport(_Response):
    """``GET /v1/usage``: attempts that ended in ``[from_, to)``, grouped by ``group_by``.

    ``client.usage()`` follows every page of groups, so ``items`` holds them all and
    ``next_cursor`` is ``None``; ``total`` is the total of the whole range.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    from_: datetime = Field(alias="from", description="start of the range (inclusive)")
    to: datetime = Field(description="end of the range (exclusive)")
    group_by: str
    items: list[UsageTotals]
    total: UsageTotals
    next_cursor: str | None = None


# --- templates (H2 spec §7.6) --------------------------------------------------------------
class TemplateParam(_Response):
    """A parameter of a template: ``type`` is one of :data:`TEMPLATE_PARAM_TYPES`.

    An ``enum`` has ``values``, an ``int`` has ``min`` and ``max``; a parameter without a
    ``default`` is required. ``target`` says where the hub writes the value (``env:<NAME>``,
    ``argv:<index>``, ``field:<field>``, ``input:<path>`` or ``pull``).
    """

    name: str
    label: str | None = None
    type: Literal["enum", "int", "bool", "blob"]
    values: list[str] | None = None
    min: int | None = None
    max: int | None = None
    default: bool | int | str | None = None
    target: str


class TemplateRequirements(_Response):
    """What a template needs from the hardware: ``gpu`` is one of :data:`GPU_REQUIREMENTS`."""

    gpu: str = "none"
    min_vram_mb: int | None = None


class TemplateInfo(_Response):
    """A template as ``GET /v1/templates`` lists it. ``ui`` is one of :data:`TEMPLATE_UIS`."""

    id: str
    version: int
    title: str
    description: str = ""
    kind: Literal["batch", "service"]
    ui: str
    singleton: bool = False
    requirements: TemplateRequirements = Field(default_factory=TemplateRequirements)
    params: list[TemplateParam] = Field(default_factory=list)
    licenses: list[str] = Field(default_factory=list)
    download_mb: int = 0


class TemplateList(_Response):
    """The served template bundle: empty with ``bundle_error`` when no bundle can be loaded."""

    bundle_version: int | None = None
    templates: list[TemplateInfo] = Field(default_factory=list)
    bundle_error: str | None = None

    def __iter__(self) -> Iterator[TemplateInfo]:  # type: ignore[override]
        return iter(self.templates)

    def __len__(self) -> int:
        return len(self.templates)


T = TypeVar("T")


class Page(_Response, Generic[T]):
    """One page of a cursor-paginated list."""

    items: list[T]
    next_cursor: str | None = None
