# SPDX-License-Identifier: Apache-2.0
"""Transport-independent helpers shared by the sync and async clients."""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import logging
import os
import re
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, TypeVar
from urllib.parse import quote, urlsplit

import httpx
from pydantic import BaseModel, ValidationError

from p2pc._version import __version__
from p2pc.errors import (
    AuthenticationError,
    CapExceededError,
    ChecksumMismatchError,
    ConfigurationError,
    ConflictError,
    FieldError,
    InvalidResponseError,
    NotFoundError,
    P2PCConnectionError,
    P2PCError,
    PermissionDeniedError,
    RateLimitError,
    ServerError,
    UnprocessableError,
    UnsafePathError,
)
from p2pc.models import (
    DEFAULT_OUTPUT_FILE_BYTES,
    MAX_OUTPUT_FILE_BYTES,
    CreateApiKey,
    CreateJoinToken,
    Egress,
    InputFile,
    JobSpec,
    JobStatus,
    LogLine,
    OutputFile,
    Outputs,
    Page,
    Placement,
    Resources,
    Retry,
    UsageReport,
    _JobFields,
)

DEFAULT_API_URL = "http://127.0.0.1:7477"
ENV_API_URL = "P2PC_API_URL"
ENV_API_KEY = "P2PC_API_KEY"
USER_AGENT = f"p2pc-python/{__version__}"
MAX_LOG_LINE_BYTES = 8 * 1024 * 1024
MAX_PAGE_LIMIT = 100
NDJSON = "application/x-ndjson"
MAX_ERROR_BODY = 64 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
ERROR_EXCERPT_CHARS = 200
MAX_FIELD_ERRORS = 100
LOG = logging.getLogger("p2pc")
DEFAULT_FOLLOW_IDLE_TIMEOUT = 300.0
# A followed log is read again after a beat when the read proved nothing: 1 s, doubling to 5 s.
FOLLOW_INITIAL_WAIT = 1.0
FOLLOW_MAX_WAIT = 5.0
# While the server cannot be reached (or fails) a follow waits 1 s, doubling to 30 s, and gives up
# when one outage has lasted 5 minutes from its first failure.
OUTAGE_INITIAL_WAIT = 1.0
OUTAGE_MAX_WAIT = 30.0
OUTAGE_GIVE_UP_AFTER = 300.0
# A followed stream that delivered a line, or stayed open this long (seconds), was working: when
# it breaks (the server's 60 s idle cut) that is no failure of the server.
STREAM_STABLE_AFTER = 10.0
# The most groups `usage()` loads over all its pages; more is a server (or a query) gone wrong.
MAX_USAGE_GROUPS = 10_000
# The header with a download's sha256 (64 lowercase hex characters).
DIGEST_HEADER = "X-P2PC-SHA256"
_KEY_RE = re.compile(r"p2pc_sk_[A-Za-z0-9_]{4,}")
# A join token (secret: it holds the one-time code) and a server address (not secret, but the
# CLI shows it only on purpose): `p2pc_join_` / `p2pc_srv_` plus an encoded payload.
_TOKEN_RE = re.compile(r"(p2pc_join_|p2pc_srv_)[A-Za-z0-9_]{4,}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")

M = TypeVar("M", bound=BaseModel)


# --- key masking -------------------------------------------------------------------------
def mask_key(key: str | None) -> str:
    """``p2pc_sk_abc…``: the prefix and the first characters of the (public) key id only."""
    if not key:
        return "<unset>"
    prefix = "p2pc_sk_"
    if key.startswith(prefix):
        return key[: len(prefix) + 3] + "…"
    return "…"


def redact(text: str, key: str | None) -> str:
    """Mask the configured API key, its secret part, and anything shaped like an API key, a join
    token (``p2pc_join_…``) or a server address (``p2pc_srv_…``)."""
    if key:
        text = text.replace(key, mask_key(key))
        secret = key.rsplit("_", 1)[-1]
        if len(secret) >= 16:
            text = text.replace(secret, "…")
    text = _KEY_RE.sub(lambda m: mask_key(m.group(0)), text)
    return _TOKEN_RE.sub(lambda m: f"{m.group(1)}…", text)


# --- configuration -----------------------------------------------------------------------
@dataclass(frozen=True)
class Config:
    api_url: str
    api_key: str | None = field(repr=False)
    timeout: float
    follow_idle_timeout: float = DEFAULT_FOLLOW_IDLE_TIMEOUT

    @classmethod
    def resolve(
        cls,
        api_url: str | None,
        api_key: str | None,
        timeout: float,
        follow_idle_timeout: float = DEFAULT_FOLLOW_IDLE_TIMEOUT,
    ) -> Config:
        url = api_url or os.environ.get(ENV_API_URL) or DEFAULT_API_URL
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ConfigurationError("api_url must start with http:// or https://")
        if "@" in parts.netloc:
            # httpx turns userinfo into Basic auth, which would replace our bearer header. The
            # message never repeats the URL: it may hold a password.
            raise ConfigurationError(
                "api_url must not contain credentials (user:pass@host); "
                "pass the API key as api_key or in P2PC_API_KEY"
            )
        if timeout <= 0:
            raise ConfigurationError("timeout must be positive")
        if follow_idle_timeout <= 0:
            raise ConfigurationError("follow_idle_timeout must be positive")
        key = (api_key or os.environ.get(ENV_API_KEY) or "").strip()
        return cls(url.rstrip("/"), key or None, timeout, follow_idle_timeout)

    @property
    def safe_url(self) -> str:
        """The API URL without any credentials embedded in it."""
        parts = urlsplit(self.api_url)
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        port = f":{parts.port}" if parts.port else ""
        return f"{parts.scheme}://{host}{port}{parts.path}"

    def require_key(self) -> str:
        if not self.api_key:
            raise ConfigurationError(
                f"no API key: pass api_key=... or set the {ENV_API_KEY} environment variable"
            )
        return self.api_key

    def headers(self, accept: str = "application/json") -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.require_key()}",
            "User-Agent": USER_AGENT,
            "Accept": accept,
        }

    def url(self, path: str) -> str:
        return f"{self.api_url}{path}"

    @property
    def is_cleartext_remote(self) -> bool:
        """``http://`` to a host that is not loopback: the key would travel in clear text."""
        parts = urlsplit(self.api_url)
        if parts.scheme != "http":
            return False
        host = (parts.hostname or "").lower()
        if host == "localhost":
            return False
        try:
            return not ipaddress.ip_address(host).is_loopback
        except ValueError:
            return True

    def warn_if_cleartext(self) -> None:
        """Log (once per client, from its constructor) that the key travels in clear text.

        Not an error: the spec allows plain HTTP behind your own proxy. Only the host is
        logged, never the path, query or key.
        """
        if self.is_cleartext_remote:
            host = urlsplit(self.api_url).hostname
            LOG.warning(
                "api_url uses http:// to %s: the API key is sent in clear text. "
                "Use https:// unless this is a trusted network or your own proxy.",
                host,
            )

    def client_repr(self, name: str) -> str:
        return f"{name}(api_url={self.safe_url!r}, api_key={mask_key(self.api_key)!r})"


# --- errors ------------------------------------------------------------------------------
_STATUS_CLASSES: dict[int, type[P2PCError]] = {
    401: AuthenticationError,
    402: CapExceededError,
    403: PermissionDeniedError,
    404: NotFoundError,
    409: ConflictError,
    410: NotFoundError,  # `expired`: an output the server's GC deleted
    422: UnprocessableError,
    429: RateLimitError,
}


def _str_member(body: Mapping[str, Any], name: str) -> str | None:
    value = body.get(name)
    return value if isinstance(value, str) else None


def _retry_after(headers: httpx.Headers) -> float | None:
    raw = headers.get("retry-after")
    if raw is None:
        return None
    try:
        seconds = float(raw)
    except ValueError:
        return None  # HTTP-date form: not worth parsing here
    return seconds if seconds >= 0 else None


def _field_errors(raw: Any, clean: Callable[[str | None], str | None]) -> list[FieldError]:
    """The ``errors`` members of a problem body; malformed entries are skipped, not fatal."""
    if not isinstance(raw, list):
        return []
    found: list[FieldError] = []
    for entry in raw[:MAX_FIELD_ERRORS]:
        if not isinstance(entry, dict):
            continue
        fields = {k: clean(_str_member(entry, k)) for k in ("field", "code", "message")}
        if all(v is not None for v in fields.values()):
            found.append(FieldError.model_validate(fields))
    return found


def error_from_response(
    response: httpx.Response, api_key: str | None, raw_body: bytes | None = None
) -> P2PCError:
    """Map an error response to the closest exception class, by HTTP status.

    The body is parsed as ``application/problem+json`` when possible; anything else is
    reduced to a short excerpt. At most 64 KiB of the body is looked at. Secrets are masked
    in the whole text *before* it is truncated, so a key can never survive half-cut.

    ``raw_body`` is for streamed responses whose body was read separately.
    """
    status = response.status_code
    raw = (response.content if raw_body is None else raw_body)[:MAX_ERROR_BODY]
    body: Mapping[str, Any] = {}
    excerpt: str | None = None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            body = parsed
    except ValueError:
        text = redact(raw.decode("utf-8", errors="replace"), api_key).strip()
        excerpt = text[:ERROR_EXCERPT_CHARS] or None

    def clean(value: str | None) -> str | None:
        return redact(value, api_key) if value is not None else None

    title = clean(_str_member(body, "title")) or response.reason_phrase or None
    detail = clean(_str_member(body, "detail") or excerpt)
    code = clean(_str_member(body, "code"))
    type_ = clean(_str_member(body, "type"))
    errors = _field_errors(body.get("errors"), clean)
    if status == 410 and code in (None, "expired"):
        code = "output_expired"  # the SDK's name for it, as for an expired entry of a listing

    if status >= 500:
        cls: type[P2PCError] = ServerError
    else:
        cls = _STATUS_CLASSES.get(status, P2PCError)
    kwargs: dict[str, Any] = {
        "status": status,
        "code": code,
        "title": title,
        "detail": detail,
        "type": type_,
        "errors": errors,
    }
    if cls is RateLimitError or cls is ServerError:
        kwargs["retry_after"] = _retry_after(response.headers)
    return cls(**kwargs)


class ErrorBody:
    """Accumulates at most ``MAX_ERROR_BODY`` bytes of an error response."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def add(self, chunk: bytes) -> bool:
        """Add a chunk; returns True once the cap is reached (stop reading)."""
        self._buf += chunk[: MAX_ERROR_BODY - len(self._buf)]
        return len(self._buf) >= MAX_ERROR_BODY

    def value(self) -> bytes:
        return bytes(self._buf)


class ResponseBody:
    """Accumulates a successful response body, refusing anything over the size cap."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def add(self, chunk: bytes) -> None:
        self._buf += chunk
        if len(self._buf) > MAX_RESPONSE_BYTES:
            raise InvalidResponseError("the response body exceeds the maximum accepted size")

    def value(self) -> bytes:
        return bytes(self._buf)


def parse_json(body: bytes) -> Any:
    """The decoded JSON body, or ``None`` when the body is empty."""
    if not body:
        return None
    try:
        return json.loads(body)
    except ValueError:
        raise InvalidResponseError("the server returned a body that is not valid JSON") from None


class FollowIdleTimeout(Exception):  # noqa: N818 - internal control flow, never user-facing
    """A followed log stream was silent for ``follow_idle_timeout`` seconds."""


def parse_model(model: type[M], data: Any) -> M:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise InvalidResponseError(
            f"unexpected {model.__name__} in server response ({exc.error_count()} errors)"
        ) from None


def parse_page(model: type[M], data: Any) -> Page[M]:
    """Accept ``{"items": [...], "next_cursor": ...}`` or, leniently, a bare JSON array."""
    if isinstance(data, list):
        return Page[M](items=[parse_model(model, item) for item in data])
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise InvalidResponseError("expected a page with an 'items' array")
    cursor = data.get("next_cursor")
    if cursor is not None and not isinstance(cursor, str):
        raise InvalidResponseError("'next_cursor' must be a string or null")
    return Page[M](
        items=[parse_model(model, item) for item in data["items"]], next_cursor=cursor or None
    )


def next_cursor(page: Page[Any] | UsageReport, seen: set[str]) -> str | None:
    """The cursor to follow, guarding against a server that loops."""
    cursor = page.next_cursor
    if cursor is None:
        return None
    if cursor in seen:
        raise InvalidResponseError("the server repeated a pagination cursor")
    seen.add(cursor)
    return cursor


# --- request building --------------------------------------------------------------------
def segment(value: str, what: str = "id") -> str:
    """A single URL path segment (no ``/``, no traversal)."""
    if not isinstance(value, str) or value in ("", ".", ".."):
        raise ValueError(f"{what} must be a non-empty string and not a dot segment")
    return quote(value, safe="")


def build_spec(
    image: str,
    command: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    files: Sequence[InputFile] | Mapping[str, bytes | str] | None = None,
    cpu: float = 1,
    memory_mb: int = 1024,
    gpu: int = 0,
    disk_mb: int | None = None,
    timeout_s: int | None = None,
    egress: Egress | Sequence[str] | None = None,
    outputs_max_mb: int | None = None,
    placement: Placement | Mapping[str, Any] | None = None,
    max_attempts: int | None = None,
    idempotency_key: str | None = None,
    name: str | None = None,
) -> JobSpec:
    """Validate the arguments against the §7 table and return the job spec."""
    if isinstance(command, str):
        raise TypeError("command must be a list of arguments (an argv), not a string")
    input_files: list[InputFile] | None
    if files is None:
        input_files = None
    elif isinstance(files, Mapping):
        input_files = [InputFile.from_content(p, c) for p, c in files.items()]
    else:
        input_files = list(files)
    egress_model = (
        egress if isinstance(egress, Egress) or egress is None else Egress(allow=list(egress))
    )
    placement_model = (
        Placement.model_validate(placement) if isinstance(placement, Mapping) else placement
    )
    return JobSpec(
        name=name,
        image=image,
        command=list(command),
        env=dict(env) if env is not None else None,
        files=input_files,
        resources=Resources.model_validate(
            {"cpu": cpu, "memory_mb": memory_mb, "gpu": gpu, "disk_mb": disk_mb}
        ),
        timeout_s=timeout_s,
        egress=egress_model,
        outputs=Outputs(max_mb=outputs_max_mb) if outputs_max_mb is not None else None,
        placement=placement_model,
        retry=Retry(max_attempts=max_attempts) if max_attempts is not None else None,
        idempotency_key=idempotency_key,
    )


def check_limit(limit: int) -> int:
    if not 1 <= limit <= MAX_PAGE_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_PAGE_LIMIT}")
    return limit


def format_time(value: datetime | str | None) -> str | None:
    if value is None or isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat()


def jobs_list_params(status: Any, node_id: str | None, limit: int) -> dict[str, str]:
    params = {"limit": str(check_limit(limit))}
    if status is not None:
        params["status"] = str(getattr(status, "value", status))
    if node_id is not None:
        params["node_id"] = node_id
    return params


def nodes_params(state: str | None, limit: int) -> dict[str, str]:
    params = {"limit": str(check_limit(limit))}
    if state is not None:
        params["state"] = state
    return params


def audit_params(kind: str | None, limit: int) -> dict[str, str]:
    params = {"limit": str(check_limit(limit))}
    if kind is not None:
        params["kind"] = kind
    return params


def check_attempt(attempt: int | None) -> int | None:
    """``attempt`` is 1-based; ``None`` means the latest one (the server's default)."""
    if attempt is None:
        return None
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise ValueError("attempt must be a positive integer (1 is the first attempt)")
    return attempt


def attempt_params(attempt: int | None) -> dict[str, str]:
    checked = check_attempt(attempt)
    return {} if checked is None else {"attempt": str(checked)}


def logs_params(follow: bool, since_seq: int, attempt: int | None = None) -> dict[str, str]:
    """Query of ``GET /v1/jobs/{id}/logs``.

    ``since_seq`` is inclusive (spec §7): the stream starts at the first chunk with
    ``seq >= since_seq``, so a client resumes with ``last_seq + 1``. Logs are per attempt:
    without ``attempt`` the server serves the latest one.
    """
    if since_seq < 0:
        raise ValueError("since_seq must be >= 0")
    params = {"follow": "true" if follow else "false", "since_seq": str(since_seq)}
    return params | attempt_params(attempt)


def check_max_bytes(max_bytes: int | None) -> int:
    """The per-file download cap: 1 GiB without a job to ask, or ``max_bytes``. Nothing can
    raise it above the server's largest ``outputs.max_mb`` (10 240 MiB)."""
    if max_bytes is None:
        return DEFAULT_OUTPUT_FILE_BYTES
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    return min(max_bytes, MAX_OUTPUT_FILE_BYTES)


def usage_params(
    from_: datetime | str | None, to: datetime | str | None, group_by: str
) -> dict[str, str]:
    if group_by not in ("job", "node", "key"):
        raise ValueError("group_by must be 'job', 'node' or 'key'")
    params = {"group_by": group_by}
    if (start := format_time(from_)) is not None:
        params["from"] = start
    if (end := format_time(to)) is not None:
        params["to"] = end
    return params


class UsagePager:
    """The pages of ``GET /v1/usage``, merged into one report.

    Without ``from``/``to`` the server takes "today" (UTC) on every request, so a call that
    crosses 00:00 UTC would mix two days under the first page's totals. The range the first
    page reports is therefore sent on every later page. At most :data:`MAX_USAGE_GROUPS` groups
    are loaded; more raises :class:`~p2pc.InvalidResponseError`.
    """

    def __init__(
        self, from_: datetime | str | None, to: datetime | str | None, group_by: str
    ) -> None:
        self.query = usage_params(from_, to, group_by)
        self.query["limit"] = str(MAX_PAGE_LIMIT)
        self._report: UsageReport | None = None
        self._seen: set[str] = set()

    def add(self, page: UsageReport) -> bool:
        """Take the next page; ``True`` if another one must be fetched (``query`` is ready)."""
        if self._report is None:
            self._report = page.model_copy(update={"next_cursor": None})
            for name, instant in (("from", page.from_), ("to", page.to)):
                self.query.setdefault(name, instant.isoformat())
        else:
            items = [*self._report.items, *page.items]
            self._report = self._report.model_copy(update={"items": items})
        cursor = next_cursor(page, self._seen)
        if len(self._report.items) > MAX_USAGE_GROUPS or (
            cursor is not None and len(self._report.items) >= MAX_USAGE_GROUPS
        ):
            raise InvalidResponseError(
                f"the usage report has more than {MAX_USAGE_GROUPS} groups: "
                "narrow the range, or group by something coarser"
            )
        if cursor is None:
            return False
        self.query["cursor"] = cursor
        return True

    @property
    def report(self) -> UsageReport:
        assert self._report is not None  # noqa: S101 - add() ran at least once
        return self._report


def check_wait_args(poll_interval: float, timeout: float | None) -> None:
    if poll_interval <= 0:
        raise ValueError("poll_interval must be positive")
    if timeout is not None and timeout < 0:
        raise ValueError("timeout must not be negative")


def timeout_message(job_id: str, timeout: float | None, status: object) -> str:
    return f"job {job_id} did not reach a terminal state within {timeout}s (last status: {status})"


# --- NDJSON ------------------------------------------------------------------------------
class NdjsonDecoder:
    """Incremental decoder: handles lines split across arbitrary chunk boundaries."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> list[LogLine]:
        self._buf += chunk
        lines: list[LogLine] = []
        while (idx := self._buf.find(b"\n")) != -1:
            raw = bytes(self._buf[:idx])
            del self._buf[: idx + 1]
            if (line := self._decode(raw)) is not None:
                lines.append(line)
        if len(self._buf) > MAX_LOG_LINE_BYTES:
            raise InvalidResponseError("a log line exceeds the maximum accepted size")
        return lines

    def finish(self) -> list[LogLine]:
        raw = bytes(self._buf)
        self._buf.clear()
        line = self._decode(raw)
        return [line] if line is not None else []

    @staticmethod
    def _decode(raw: bytes) -> LogLine | None:
        raw = raw.strip()
        if not raw:
            return None
        try:
            return LogLine.model_validate_json(raw)
        except ValidationError:
            raise InvalidResponseError("the log stream contained an invalid record") from None


# --- following a log -----------------------------------------------------------------------
@dataclass(frozen=True)
class LogRead:
    """One read of an attempt's log: where it starts, and whether its end is conclusive."""

    attempt: int
    since_seq: int
    #: The attempt was already over when the read began: nothing is written after it.
    conclusive: bool


@dataclass
class _Reading:
    attempt: int
    next_seq: int
    final_done: bool = False  # a conclusive read has ended: nothing more will come
    no_log: P2PCError | None = None  # the last read was a 404


def _attempt_over(job: _JobFields, attempt: int) -> bool:
    """Nothing more will be written to ``attempt``'s log: the job is final, or a later attempt
    took over."""
    return job.is_terminal or attempt < job.attempt


class LogFollower:
    """The rules for following a job's log, shared by the sync and async clients.

    Same as the Rust CLI's ``StreamFollower``. The server may end a followed stream before the
    attempt is over (at its idle limit, or on an internal error), so an end of stream proves
    nothing. **An attempt's log is finished only by a read that began after the attempt was
    known to be over** (the job is final, or a later attempt exists). Until then a ``404`` ("no
    log yet"), an empty page or a stream that ends are followed by another read, after a beat.

    The caller loops: ``job = get`` ; ``read = next_read(job)`` ; if there is one, stream it,
    feeding each line to :meth:`accept` and yielding it only if that returns true, then
    :meth:`ended` or :meth:`missing` ; ``job = get`` ; ``finished, wait = after(job)`` ; stop, or
    sleep ``wait`` and go again. A transient failure of the stream or of a ``get`` is the
    caller's business: it waits as :class:`Outage` says and tries again (the stream from the next
    ``seq``, which :meth:`next_read` knows).
    """

    def __init__(self, since_seq: int, attempt: int | None) -> None:
        self._since_seq = since_seq
        self._fixed = attempt
        self._cur: _Reading | None = None
        self._backoff = FOLLOW_INITIAL_WAIT
        self._last_state: tuple[str, int] | None = None

    def _target(self, job: _JobFields) -> int:
        if self._fixed is not None:
            return self._fixed
        cur = self._cur
        if cur is not None and cur.attempt < job.attempt and not cur.final_done:
            return cur.attempt  # the tail of the old attempt is read first
        return job.attempt

    @staticmethod
    def _readable(job: _JobFields, attempt: int) -> bool:
        """The attempt has a log to read: it started, or a later attempt shows that it did."""
        return job.attempt >= 1 and (job.status is not JobStatus.QUEUED or attempt < job.attempt)

    def next_read(self, job: _JobFields) -> LogRead | None:
        target = self._target(job)
        if not self._readable(job, target):
            return None
        if self._cur is None or self._cur.attempt != target:
            # The first attempt starts where the caller said; a later one starts again at 0.
            self._cur = _Reading(target, self._since_seq if self._cur is None else 0)
        if self._cur.final_done:
            return None
        return LogRead(target, self._cur.next_seq, _attempt_over(job, target))

    def accept(self, line: LogLine) -> bool:
        """Whether ``line`` is new, which also moves the reader past it.

        A line below the next expected ``seq`` was delivered already (or was asked to be
        skipped with ``since_seq``): the server may send it again after a reconnect, and the
        caller drops it, like the CLI does. ``seq`` is per attempt.
        """
        cur = self._cur
        if cur is None or line.seq < cur.next_seq:
            return False
        cur.next_seq = line.seq + 1
        return True

    def ended(self, read: LogRead, *, complete: bool = True) -> None:
        """The stream ended. ``complete`` is false for an idle timeout, which reached no end."""
        if self._cur is not None:
            self._cur.no_log = None
            self._cur.final_done = complete and read.conclusive

    def missing(self, read: LogRead, error: P2PCError) -> None:
        """The read was a ``404``: no log (yet), or no such attempt."""
        if self._cur is not None:
            self._cur.no_log = error
            self._cur.final_done = read.conclusive

    def after(self, job: _JobFields) -> tuple[bool, float]:
        """``(finished, wait)`` once ``job`` has been fetched after a read (or a missed one).

        ``wait`` is how long to sleep before the next round: zero when that read can already be
        the conclusive one, or is of another attempt.
        """
        state = (job.status.value, job.attempt)
        if state != self._last_state:
            self._last_state = state
            self._backoff = FOLLOW_INITIAL_WAIT
        cur = self._cur
        if cur is not None and cur.final_done:
            # Following the latest, that must be the job's own last attempt.
            finished = self._fixed is not None or cur.attempt >= job.attempt
        else:
            finished = job.is_terminal and not self._readable(job, self._target(job))
        if finished:
            if self._fixed is not None and cur is not None and cur.no_log is not None:
                raise cur.no_log  # the attempt that was asked for has no log, now it is over
            return True, 0.0
        target = self._target(job)
        if cur is None:
            immediate = self._readable(job, target)
        else:
            immediate = self._readable(job, target) and (
                target != cur.attempt or (not cur.final_done and _attempt_over(job, target))
            )
        if immediate:
            return False, 0.0
        wait = self._backoff
        self._backoff = min(self._backoff * 2, FOLLOW_MAX_WAIT)
        return False, wait


def is_transient(error: P2PCError) -> bool:
    """Whether a failed request is worth retrying while following: the network (a connection
    error, a timeout, a broken body), ``408``, ``429`` and ``5xx``. Anything else (``401``,
    ``403``, ``404``, ``422``, an answer of the wrong shape) is permanent."""
    if isinstance(error, P2PCConnectionError):
        return True
    return error.status is not None and (error.status in (408, 429) or error.status >= 500)


class Outage:
    """The waits of one route of a follow while it fails, shared by both clients.

    A follow keeps **one ``Outage`` per route**: the log stream and the job check. Each starts at
    its own first failure and ends only when the caller says so with :meth:`over`, after a
    success *on its own route*: a stream that worked (it delivered a line, or stayed open for
    ``STREAM_STABLE_AFTER`` seconds, even if it then broke) for the log route, a successful
    ``GET /v1/jobs/{id}`` for the job route. Neither route's success ends the other's outage, so
    a broken job route still gives up while logs flow, and a long healthy stream never leaves a
    stale outage of the log route behind.

    Each :meth:`failed` returns how long to wait: 1 s, doubling to 30 s, or the server's
    ``Retry-After`` if longer, but never past the 5 minutes the outage may last. Once those are
    used up it raises :class:`~p2pc.P2PCConnectionError` instead.

    An outage is a run of failures of its route (spec §7): it is timed from the **start** of its
    first failed request, it has no success on the route, and no **gap** between two of the
    route's requests. The gap is how late the next request began, after the time it was due
    (the end of the last failed one plus the wait this class asked for), so it counts only what
    the follow did meanwhile, the other route's work, never the wait. A gap longer than 30 s,
    the longest wait, means the client was busy with healthy work elsewhere: the failure that
    comes after it starts a new outage, announced again.
    """

    def __init__(
        self,
        monotonic: Callable[[], float],
        job_id: str,
        route: str,
        on_outage: Callable[[P2PCError], object] | None = None,
    ) -> None:
        self._monotonic = monotonic
        self._job_id = job_id
        self._route = route
        self._on_outage = on_outage
        self._announced: object = None
        self._started: float | None = None
        self._next_due: float | None = None
        self._retry_wait = OUTAGE_INITIAL_WAIT

    def failed(self, error: P2PCError, request_started: float) -> float:
        """A transient failure of a request that was sent at ``request_started`` (the caller's
        ``monotonic`` clock). Returns how long to wait before the next request of this route."""
        now = self._monotonic()
        if (
            self._started is not None
            and self._next_due is not None
            and request_started - self._next_due > OUTAGE_MAX_WAIT
        ):
            self.over()  # a gap: this failure starts a new outage
        if self._started is None:
            self._started = request_started
            LOG.info(
                "outage of the %s while following job %s: %s", self._route, self._job_id, error
            )
            if self._on_outage is not None:
                # What the callback returned: the async client awaits it (see ``announced``).
                self._announced = self._on_outage(error)
        left = OUTAGE_GIVE_UP_AFTER - (now - self._started)
        if left <= 0:
            raise P2PCConnectionError(
                f"gave up following job {self._job_id}: the outage of the {self._route} lasted "
                f"{OUTAGE_GIVE_UP_AFTER:.0f} s without a success on that route "
                f"(last error: {error.message})"
            ) from error
        asked = getattr(error, "retry_after", None)
        wait = max(self._retry_wait, asked if isinstance(asked, int | float) else 0.0)
        self._retry_wait = min(self._retry_wait * 2, OUTAGE_MAX_WAIT)
        wait = min(wait, left)
        self._next_due = now + wait
        return wait

    def announced(self) -> object:
        """What ``on_outage`` returned for the outage :meth:`failed` just started, once.

        ``None`` if it did not start one. The async client awaits it when it is awaitable, so
        an ``async def`` callback runs to its end.
        """
        result, self._announced = self._announced, None
        return result

    def over(self) -> None:
        """The route worked (or a gap ended the outage): the next failure starts a new outage."""
        self._started = None
        self._next_due = None
        self._retry_wait = OUTAGE_INITIAL_WAIT


# --- downloads ---------------------------------------------------------------------------
def safe_output_target(dest: str | Path, remote_path: str) -> tuple[Path, Path]:
    """Resolve ``dest / remote_path`` and refuse anything that escapes ``dest``.

    Returns ``(dest_root, target)``. Rejects absolute paths, ``..``, empty or ``.``
    components, backslashes, NUL bytes, and targets that resolve (through symlinks)
    outside ``dest``.
    """
    if (
        not remote_path
        or "\x00" in remote_path
        or "\\" in remote_path
        or remote_path.startswith("/")
        or any(p in ("", ".", "..") for p in remote_path.split("/"))
    ):
        raise UnsafePathError(
            "refusing output path that could escape the destination directory",
            code="unsafe_path",
        )
    root = Path(dest).resolve()
    target = (root / PurePosixPath(remote_path)).resolve()
    if not target.is_relative_to(root) or target == root:
        raise UnsafePathError(
            "refusing output path that resolves outside the destination directory",
            code="unsafe_path",
        )
    return root, target


def expected_digest(entry: OutputFile) -> str:
    """The listing's sha256 as 64 lowercase hex characters; downloads are never unverified."""
    raw = (entry.sha256 or "").lower().removeprefix("sha256:")
    if not _SHA256_RE.fullmatch(raw):
        raise InvalidResponseError(
            f"the listing for {entry.path!r} has no valid sha256: "
            "refusing to download a file that cannot be verified"
        )
    return raw


def expected_size(entry: OutputFile, max_bytes: int = DEFAULT_OUTPUT_FILE_BYTES) -> int:
    """The listing's size (the model guarantees it is there), a hard limit while writing.

    A file larger than ``max_bytes`` is refused before any byte is fetched.
    """
    size = entry.size
    if size > max_bytes:
        limit = (
            "the 1 GiB per-file limit"
            if max_bytes == DEFAULT_OUTPUT_FILE_BYTES
            else f"the download limit of {max_bytes} bytes"
        )
        raise InvalidResponseError(f"{entry.path!r} is {size} bytes, larger than {limit}")
    return size


def find_output(
    listing: Sequence[OutputFile], remote_path: str, max_bytes: int = DEFAULT_OUTPUT_FILE_BYTES
) -> OutputFile:
    for item in listing:
        if item.path == remote_path:
            if item.expired:
                raise NotFoundError(
                    f"output file {remote_path!r} has expired (garbage-collected on the server)",
                    status=410,
                    code="output_expired",
                )
            expected_digest(item)
            expected_size(item, max_bytes)
            return item
    raise NotFoundError(
        f"no output file {remote_path!r} in the job's listing",
        status=404,
        code="output_not_found",
    )


class DownloadWriter:
    """Writes to a temporary file next to the target, verifies it, then renames it.

    Construction does no I/O and cannot fail half-way: the filesystem is touched by
    :meth:`open`, :meth:`write` and :meth:`commit`, and :meth:`abort` is safe after any of
    them, or after none. On failure, :meth:`abort` deletes the temporary file, the target if
    this writer created it, and the directories this writer created (only if they are still
    empty), so a failed or cancelled download leaves nothing behind.

    Never call :meth:`abort` while another method is running in a worker thread.
    """

    def __init__(
        self,
        root: Path,
        target: Path,
        expected: OutputFile,
        max_bytes: int = DEFAULT_OUTPUT_FILE_BYTES,
    ) -> None:
        self._digest = expected_digest(expected)
        self._limit = expected_size(expected, max_bytes)
        self._root = root
        self._target = target
        self._expected = expected
        self._hash = hashlib.sha256()
        self._size = 0
        self._created: list[Path] = []  # deepest first
        self._tmp: Path | None = None
        self._file: Any = None
        self._target_existed = False
        self._committed = False

    def open(self) -> None:
        """Create the missing directories and the temporary file."""
        target = self._target
        self._target_existed = target.exists() or target.is_symlink()
        directory = target.parent
        while not directory.exists():
            self._created.append(directory)
            directory = directory.parent
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            # Re-check after creating directories: a symlinked parent could point elsewhere.
            if not target.parent.resolve().is_relative_to(self._root):
                raise UnsafePathError(
                    "refusing output path that resolves outside the destination directory",
                    code="unsafe_path",
                )
            fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".p2pc-", suffix=".part")
            self._tmp = Path(tmp)
            self._file = os.fdopen(fd, "wb")
        except BaseException:
            self.abort()
            raise

    def check_header(self, headers: Mapping[str, str]) -> None:
        """The server's ``X-P2PC-SHA256`` must agree with the listing, before a byte is stored.

        A response without the header is still verified against the listing, byte by byte.
        """
        announced = headers.get(DIGEST_HEADER)
        if announced is not None and announced.strip().lower() != self._digest:
            raise ChecksumMismatchError(
                f"the server announced sha256 {announced.strip()[:64]!r} for "
                f"{self._expected.path!r} in {DIGEST_HEADER}, but its listing says "
                f"{self._digest}: refusing the download",
                code="checksum_mismatch",
            )

    def write(self, chunk: bytes) -> None:
        self._size += len(chunk)
        if self._size > self._limit:
            raise self._mismatch("size", f"more than the {self._limit} bytes listed")  # hard limit
        self._hash.update(chunk)
        self._file.write(chunk)

    def commit(self) -> Path:
        self._file.close()
        if self._size != self._limit:
            raise self._mismatch("size", f"{self._size} bytes, listed {self._limit}")
        if (actual := self._hash.hexdigest()) != self._digest:
            raise self._mismatch("sha256", f"got {actual}, listed {self._digest}")
        assert self._tmp is not None  # noqa: S101 - set by open()
        os.replace(self._tmp, self._target)
        self._committed = True
        return self._target

    def abort(self) -> None:
        if self._file is not None:
            with contextlib.suppress(OSError):
                self._file.close()
        if self._tmp is not None:
            with contextlib.suppress(OSError):
                self._tmp.unlink()
        if self._committed and not self._target_existed:
            # The rename happened but the caller is being told the download failed (for
            # example it was cancelled): do not leave a file it was never given. A target
            # that existed before was replaced atomically by a verified file; that stays.
            with contextlib.suppress(OSError):
                self._target.unlink()
        for directory in self._created:
            with contextlib.suppress(OSError):
                directory.rmdir()

    def _mismatch(self, what: str, detail: str) -> ChecksumMismatchError:
        return ChecksumMismatchError(
            f"downloaded output {self._expected.path!r} does not match the listing "
            f"({what}: {detail})",
            code="checksum_mismatch",
        )


def output_url_path(job_id: str, remote_path: str) -> str:
    return f"/v1/jobs/{segment(job_id)}/outputs/{quote(remote_path, safe='/')}"


def join_token_body(ttl_s: int | None, label: str | None = None) -> dict[str, Any]:
    if ttl_s is not None and not 1 <= ttl_s <= 86_400:
        raise ValueError("ttl_s must be between 1 and 86400 seconds (24 h)")
    return CreateJoinToken(ttl_s=ttl_s, label=label).to_wire()


def key_body(
    scopes: Sequence[str],
    daily_unit_cap: int | None,
    allowed_images: Sequence[str] | None,
    label: str | None = None,
    expires_at: datetime | str | None = None,
) -> dict[str, Any]:
    if isinstance(scopes, str) or not scopes:
        raise ValueError("scopes must be a non-empty list")
    return CreateApiKey(
        scopes=list(scopes),
        daily_unit_cap=daily_unit_cap,
        allowed_images=None if allowed_images is None else list(allowed_images),
        label=label,
        expires_at=expires_at,  # type: ignore[arg-type]  # pydantic parses ISO strings
    ).to_wire()
