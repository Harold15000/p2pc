# SPDX-License-Identifier: Apache-2.0
"""Statuses, results, checks and redaction: the vocabulary of the acceptance harness.

Status rules (the only place they live):

* ``pass``    every automated step ran and held.
* ``fail``    a step ran and the product did not do what the criterion says (or the harness itself broke).
* ``blocked`` a step could not run because a piece of the product is not built yet. The reason names the task that
              unblocks it. It is never counted as a pass.
* ``skip``    the environment does not allow the step (no machine configured, a tool is not installed, a manual
              attestation is missing). It is never counted as a pass either.

A criterion with several checks takes the worst status, in the order fail > blocked > skip > pass, so a criterion is
``pass`` only when every one of its checks passed.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable

PASS = "pass"
FAIL = "fail"
SKIP = "skip"
BLOCKED = "blocked"
STATUSES = (PASS, FAIL, SKIP, BLOCKED)
# Worst first.
_SEVERITY = {FAIL: 3, BLOCKED: 2, SKIP: 1, PASS: 0}

REDACTED = "<redacted>"


class Blocked(Exception):
    """A piece of the product is missing. ``unblocked_by`` lists the tasks that bring it, from the one map (``context.OWNERS``)."""

    def __init__(self, reason: str, unblocked_by: Iterable[str] = ()):
        super().__init__(reason)
        self.reason = reason
        self.unblocked_by = list(unblocked_by)


class Skipped(Exception):
    """The environment does not allow this check."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class CheckFailed(Exception):
    """The product did not do what the criterion says."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def aggregate(statuses: Iterable[str]) -> str:
    """The worst of ``statuses``. An empty list is a failure: no evidence is never a pass."""
    worst = None
    for s in statuses:
        if s not in _SEVERITY:
            raise ValueError(f"unknown status {s!r}")
        if worst is None or _SEVERITY[s] > _SEVERITY[worst]:
            worst = s
    return FAIL if worst is None else worst


# --------------------------------------------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------------------------------------------

# API keys (p2pc_sk_<key_id>_<secret>) and join tokens (p2pc_join_<payload>). Server addresses (p2pc_srv_) are not
# secret and stay readable. The bare prefix is redacted too: over-redacting a doc string is harmless.
SECRET_RE = re.compile(r"p2pc_(?:sk|join)_[A-Za-z0-9_\-]*")
_MIN_LITERAL_SECRET = 8


class Redactor:
    """Replaces secrets with ``<redacted>``: the patterns above, plus literals registered at run time."""

    def __init__(self) -> None:
        self._literals: list[str] = []

    def add_secret(self, value: str | None) -> None:
        if value and len(value) >= _MIN_LITERAL_SECRET and value not in self._literals:
            self._literals.append(value)
            self._literals.sort(key=len, reverse=True)

    def redact(self, text: str) -> str:
        text = SECRET_RE.sub(REDACTED, text)
        for lit in self._literals:
            text = text.replace(lit, REDACTED)
        return text

    def redact_bytes(self, data: bytes) -> str:
        return self.redact(data.decode("utf-8", errors="replace"))

    def redact_object(self, obj: Any) -> Any:
        """Redacts every string (keys and values) of a JSON-like structure. Other types pass through."""
        if isinstance(obj, str):
            return self.redact(obj)
        if isinstance(obj, dict):
            return {self.redact(k) if isinstance(k, str) else k: self.redact_object(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.redact_object(v) for v in obj]
        return obj


REDACTOR = Redactor()


def redact(text: str) -> str:
    return REDACTOR.redact(text)


def redact_bytes(data: bytes) -> str:
    return REDACTOR.redact_bytes(data)


def redact_object(obj: Any) -> Any:
    return REDACTOR.redact_object(obj)


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    """Terminal colour codes make an excerpt unreadable in a report."""
    return _ANSI_RE.sub("", text)


def clean(text: str) -> str:
    """Terminal colours stripped and secrets redacted: the only form in which command output may be shortened or shown.
    Redact BEFORE cutting: a cut can drop the ``p2pc_sk_`` prefix and leave a readable half that no pattern matches."""
    return redact(strip_ansi(text))


def tail(text: str, n: int) -> str:
    """The last ``n`` characters of the cleaned text."""
    return clean(text).strip()[-n:]


def last_line(text: str) -> str:
    """The last non-empty line of the cleaned text, without the ssh client's own ``** `` warnings (OpenSSH's
    post-quantum notice is three of them, "** The server may need to be upgraded. See https://openssh.com/pq.html"
    last): they say nothing about why a command failed, and they would be taken for the reason."""
    lines = [ln for ln in clean(text).splitlines() if ln.strip() and not ln.startswith("** ")]
    return lines[-1].strip() if lines else ""


SSH_FAILED_EXIT = 255  # ssh's own failure, and wsl.exe's when it cannot run what it was asked


def failure_reason(exit_code: int | None, stderr: str) -> str:
    """The reason a command failed, from its stderr: the last line that says something. Exit 255 is also explained, since
    ssh and wsl.exe both use it and often say nothing else once the client's warnings are dropped."""
    line = last_line(stderr)
    if exit_code == SSH_FAILED_EXIT:
        return f"{line} (ssh or wsl.exe failed)" if line else "ssh or wsl.exe failed"
    return line


def excerpt(text: str, limit: int = 2000) -> str:
    """At most about ``limit`` characters: the head and the tail, with a note about what was dropped."""
    if len(text) <= limit:
        return text
    half = limit // 2
    omitted = len(text) - 2 * half
    return f"{text[:half]}\n…[{omitted} characters omitted]…\n{text[-half:]}"


# --------------------------------------------------------------------------------------------------------------
# Steps (one command that was run)
# --------------------------------------------------------------------------------------------------------------

# What the unfinished subcommands of this version print (docs/cli.md: "not implemented yet", exit 125).
STUB_MARKERS = ("not implemented yet", "not supported by this version yet", "not available in this version yet")
# What a REST route that does not exist yet answers. A 404 is ALSO what an existing route answers for an unknown id
# (a job that is not there), so these statuses alone never prove a missing piece: the context asks the server's own
# /v1/openapi.json whether the route exists (``Context.route_missing``).
MISSING_ROUTE_STATUSES = (404, 405, 501)


@dataclass
class Step:
    label: str
    role: str
    command: str
    exit_code: int | None
    duration_s: float = 0.0
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: str = ""  # the harness could not run the command at all (ssh failed to start, ...)
    retries: int = 0  # ssh connection-setup failures retried before the command ran (a blip of the network)
    retry_first_error: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.error

    def parsed_stdout(self) -> Any:
        """The stdout as JSON (``--json``), or None when it is not JSON."""
        try:
            return json.loads(self.stdout)
        except (ValueError, TypeError):
            return None

    def final_json(self) -> Any:
        """The last JSON line of stdout, or None. ``p2pc run --json`` (and ``p2pc logs --json``) print NDJSON: the log
        records as they arrive, and for ``run`` the final job as the LAST line (docs/cli.md, "JSON output")."""
        for line in reversed(self.stdout.strip().splitlines()):
            if not line.strip():
                continue
            try:
                return json.loads(line)
            except ValueError:
                return None
        return None

    def ndjson(self) -> list[Any]:
        """Every line of stdout as JSON; a line that is not JSON is skipped."""
        out = []
        for line in self.stdout.splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def error_json(self) -> dict | None:
        """The ``{"error": {...}}`` object that ``--json`` prints on stderr (docs/cli.md)."""
        for line in reversed(self.stderr.strip().splitlines()):
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and isinstance(obj.get("error"), dict):
                return obj["error"]
        return None

    def missing_piece(self) -> bool:
        """True when the command failed because it is a stub that says so (``not implemented yet``). Nothing else
        counts: in particular not an HTTP status, see ``route_status``. A step that succeeded is never a missing piece."""
        if self.ok or self.exit_code is None:
            return False
        return self.stub_marker()

    def stub_marker(self) -> bool:
        """Whether the output says the command is a stub, whatever the exit code: ``p2pc <stub> --help`` succeeds and
        its help text says "not available in this version yet"."""
        low = (self.stdout + "\n" + self.stderr).lower()
        return any(m in low for m in STUB_MARKERS)

    def route_status(self) -> int | None:
        """The 404, 405 or 501 an API call answered, or None. Only a hint: whether the ROUTE is missing is decided
        against the server's OpenAPI document, because an existing route answers 404 for an unknown id."""
        if self.ok or self.exit_code is None:
            return None
        err = self.error_json()
        if err and err.get("kind") == "api" and err.get("status") in MISSING_ROUTE_STATUSES:
            return err["status"]
        return None

    def to_dict(self, limit: int = 1500) -> dict:
        # Redact first, cut second: a cut can never leave a readable half of a secret.
        extra = {"ssh_retries": self.retries, "ssh_first_error": redact(self.retry_first_error)} if self.retries else {}
        return {
            **extra,
            "label": redact(self.label),
            "role": self.role,
            "command": redact(self.command),
            "exit_code": self.exit_code,
            "duration_s": round(self.duration_s, 3),
            "timed_out": self.timed_out,
            "error": redact(self.error),
            "stdout_excerpt": excerpt(redact(strip_ansi(self.stdout)), limit),
            "stderr_excerpt": excerpt(redact(strip_ansi(self.stderr)), limit),
        }


# --------------------------------------------------------------------------------------------------------------
# Checks and results
# --------------------------------------------------------------------------------------------------------------


@dataclass
class Check:
    name: str
    status: str
    reason: str = ""
    unblocked_by: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    timings: dict[str, float] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    steps: list[Step] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "reason": redact(self.reason),
            "unblocked_by": list(self.unblocked_by),
            "duration_s": round(self.duration_s, 3),
            "timings": {k: round(v, 3) for k, v in self.timings.items()},
            "evidence": redact_object(self.evidence),
            "steps": [s.to_dict() for s in self.steps],
        }


class CheckScope:
    """``with result.check("name") as c:`` runs a check. Leaving the block normally passes it; ``Blocked``,
    ``Skipped`` and ``CheckFailed`` (or any other exception, which is a harness or product bug) set the status."""

    def __init__(self, result: "Result", name: str):
        self._result = result
        self.name = name
        self.timings: dict[str, float] = {}
        self.evidence: dict[str, Any] = {}
        self.steps: list[Step] = []
        self._t0 = 0.0

    def __enter__(self) -> "CheckScope":
        self._t0 = time.monotonic()
        self._result._active = self
        return self

    def timing(self, name: str, seconds: float) -> None:
        self.timings[name] = seconds

    def require(self, condition: object, message: str) -> None:
        if not condition:
            raise CheckFailed(message)

    def needs(self, *names: str) -> None:
        """Declares that this check only makes sense when the named earlier checks passed. A blocked dependency
        makes this check blocked by the same tasks; a failed or skipped one makes it skipped."""
        for name in names:
            dep = next((c for c in self._result.checks if c.name == name), None)
            if dep is None:
                raise CheckFailed(f"harness bug: unknown dependency {name!r}")
            if dep.status == PASS:
                continue
            if dep.status == BLOCKED:
                raise Blocked(f"depends on '{name}', which is blocked", dep.unblocked_by)
            if dep.status == FAIL:
                raise Skipped(f"not run: '{name}' failed")
            raise Skipped(f"not run: '{name}' was skipped")

    def __exit__(self, exc_type, exc, tb) -> bool:
        status, reason, unblocked = PASS, "", []
        swallow = True
        if exc_type is None:
            pass
        elif issubclass(exc_type, Blocked):
            status, reason, unblocked = BLOCKED, exc.reason, exc.unblocked_by
        elif issubclass(exc_type, Skipped):
            status, reason = SKIP, exc.reason
        elif issubclass(exc_type, CheckFailed):
            status, reason = FAIL, exc.reason
        elif issubclass(exc_type, Exception):
            status, reason = FAIL, f"{exc_type.__name__}: {exc}"
        else:
            # KeyboardInterrupt, SystemExit: record what we know and let it propagate.
            status, reason = FAIL, f"interrupted ({exc_type.__name__})"
            swallow = False
        self._result._active = None
        self._result.checks.append(
            Check(
                name=self.name,
                status=status,
                reason=reason,
                unblocked_by=list(unblocked),
                duration_s=time.monotonic() - self._t0,
                timings=self.timings,
                evidence=self.evidence,
                steps=self.steps,
            )
        )
        return swallow


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Result:
    """The outcome of one criterion: its checks, the commands behind them and the timings."""

    def __init__(self, id: str, title: str):
        self.id = id
        self.title = title
        self.checks: list[Check] = []
        self.loose_steps: list[Step] = []  # commands run outside any check
        self.started_at = _now()
        self.finished_at = ""
        self._t0 = time.monotonic()
        self.duration_s = 0.0
        self._active: CheckScope | None = None

    def check(self, name: str) -> CheckScope:
        return CheckScope(self, name)

    def add_check(
        self, name: str, status: str, reason: str = "", unblocked_by: Iterable[str] = (), **fields: Any
    ) -> Check:
        if status not in _SEVERITY:
            raise ValueError(f"unknown status {status!r}")
        if status != PASS and not reason:
            raise ValueError(f"a {status} check needs a reason")
        chk = Check(name=name, status=status, reason=reason, unblocked_by=list(unblocked_by), **fields)
        self.checks.append(chk)
        return chk

    def record_step(self, step: Step) -> None:
        (self._active.steps if self._active is not None else self.loose_steps).append(step)

    def finish(self) -> "Result":
        self.finished_at = _now()
        self.duration_s = time.monotonic() - self._t0
        return self

    @property
    def status(self) -> str:
        return aggregate(c.status for c in self.checks)

    @property
    def reason(self) -> str:
        parts = [f"{c.name}: {c.reason}" for c in self.checks if c.status != PASS and c.reason]
        return "; ".join(parts)

    @property
    def unblocked_by(self) -> list[str]:
        seen: list[str] = []
        for c in self.checks:
            if c.status == BLOCKED:
                for t in c.unblocked_by:
                    if t not in seen:
                        seen.append(t)
        return seen

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in STATUSES}
        for c in self.checks:
            out[c.status] += 1
        return out

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "reason": redact(self.reason),
            "unblocked_by": self.unblocked_by,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(self.duration_s, 3),
            "check_counts": self.counts(),
            "checks": [c.to_dict() for c in self.checks],
            "other_steps": [s.to_dict() for s in self.loose_steps],
        }


def summarize(results: Iterable[Result]) -> dict[str, int]:
    out = {s: 0 for s in STATUSES}
    for r in results:
        out[r.status] += 1
    return out


def exit_code(results: Iterable[Result], strict: bool) -> int:
    """0 unless a criterion failed. With ``strict`` (the release gate) anything but an all-pass is 1."""
    counts = summarize(results)
    if counts[FAIL]:
        return 1
    if strict and (counts[BLOCKED] or counts[SKIP] or not counts[PASS]):
        return 1
    return 0
