# SPDX-License-Identifier: Apache-2.0
"""What has landed, read from the product itself: parsers for the three things the harness looks at.

* routes: the server's own ``/v1/openapi.json`` (or the committed copy, ``docs/api/openapi.json``, which a test of the
  server keeps equal to what the code generates);
* subcommands: ``p2pc --help`` and ``p2pc-agent --help``, where a stub says so in its description;
* tests: ``cargo test --workspace --all-features -- --list``.

Nothing here names a task. Which task owns a piece is the map in ``context.OWNERS``; whether the piece exists is what
these parsers read. So a task that lands changes what the harness does without anyone editing it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

# The words clap prints for a command that exists but does nothing yet (crates/p2pc-cli/src/cli.rs).
STUB_PHRASES = ("not available in this version yet", "not implemented yet")


def shape(path: str) -> str:
    """A path template with its parameter names erased: ``/v1/jobs/{id}/logs`` equals ``/v1/jobs/{job_id}/logs``."""
    return re.sub(r"\{[^}/]*\}", "{}", path)


# --------------------------------------------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------------------------------------------


def parse_openapi(doc: Any) -> set[tuple[str, str]] | None:
    """``{(METHOD, shaped path)}`` from an OpenAPI document, or None when it is not one (an unreadable document says
    nothing about which routes exist)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
        return None
    out = set()
    for path, ops in doc["paths"].items():
        if isinstance(ops, dict):
            out |= {(m.upper(), shape(path)) for m in ops if m.lower() in ("get", "post", "put", "patch", "delete")}
    return out


def load_openapi_file(path: Any) -> set[tuple[str, str]] | None:
    try:
        with open(path, encoding="utf-8") as f:
            return parse_openapi(json.load(f))
    except (OSError, ValueError):
        return None


def schema_has_property(doc: Any, schema: str, prop: str) -> bool | None:
    """Whether ``components.schemas.<schema>.properties`` of an OpenAPI document has ``prop``; None if the schema is
    not in the document (nothing can be said)."""
    try:
        props = doc["components"]["schemas"][schema]["properties"]
    except (KeyError, TypeError):
        return None
    return isinstance(props, dict) and prop in props


# --------------------------------------------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------------------------------------------

_COMMAND_LINE = re.compile(r"^\s{2}([a-z][a-z0-9-]*)(?:\s{2,}(.*))?$")


def parse_help_commands(text: str) -> dict[str, bool]:
    """The subcommands of a clap ``--help`` (its ``Commands:`` section) and whether each is still a stub, which clap
    shows in the command's description. ``{}`` when the text has no such section."""
    out: dict[str, bool] = {}
    inside = False
    last = None
    for line in text.splitlines():
        if line.strip() == "Commands:":
            inside = True
            continue
        if not inside:
            continue
        if not line.strip():
            break
        m = _COMMAND_LINE.match(line)
        if m:
            last = m.group(1)
            out[last] = any(p in (m.group(2) or "").lower() for p in STUB_PHRASES)
        elif last and line.startswith("      "):  # a wrapped description
            out[last] = out[last] or any(p in line.lower() for p in STUB_PHRASES)
    out.pop("help", None)
    return out


def is_stub_text(text: str) -> bool:
    low = text.lower()
    return any(p in low for p in STUB_PHRASES)


# --------------------------------------------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ListedTest:
    name: str  # the full path cargo filters on: ``module::name``
    target: str  # ``unittests src/lib.rs`` or ``tests/jobs.rs``
    ignored: bool = False

    @property
    def target_stem(self) -> str:
        """``jobs`` for ``tests/jobs.rs``; ``lib`` or ``main`` for unit tests."""
        m = re.search(r"([A-Za-z0-9_]+)\.rs$", self.target)
        stem = m.group(1) if m else self.target
        return stem if self.target.startswith("tests/") else {"lib": "lib", "main": "main"}.get(stem, stem)


_RUNNING = re.compile(r"^\s*Running (.+?) \(.+\)\s*$")
_DOC = re.compile(r"^\s*Doc-tests ")
_TEST = re.compile(r"^(.+): (test|benchmark)$")


def parse_test_list(text: str, ignored: bool = False) -> list[ListedTest]:
    """The tests of a ``cargo test --workspace -- --list`` output, each with the test binary it came from. Doc-tests
    are left out (they have no stable name to filter on). ``ignored``: the output of ``-- --list --ignored``."""
    out: list[ListedTest] = []
    target: str | None = None
    for line in text.splitlines():
        if _DOC.match(line):
            target = None
            continue
        m = _RUNNING.match(line)
        if m:
            target = m.group(1)
            continue
        t = _TEST.match(line)
        if t and target is not None and t.group(2) == "test":
            out.append(ListedTest(t.group(1), target, ignored))
    return out


def merge_lists(all_tests: list[ListedTest], ignored_tests: list[ListedTest]) -> list[ListedTest]:
    """``--list`` shows every test, ignored ones included; ``--list --ignored`` says which were ignored."""
    ignored = {(t.target, t.name) for t in ignored_tests}
    return [ListedTest(t.name, t.target, (t.target, t.name) in ignored) for t in all_tests]


# --------------------------------------------------------------------------------------------------------------
# The product, asked offline (for `--list`)
# --------------------------------------------------------------------------------------------------------------


# A piece with no marker in the running product, whose landing shows in the checkout's own documentation: docs/cli.md
# says it once the code does (T11b3's "A closed stdout detaches too"). (path, regex that must match). The single table
# for `--list` (Landed) and for the run (context.Context.feature_landed).
DOC_MARKERS: dict[str, tuple[str, str]] = {
    "run-closed-stdout": ("docs/cli.md", r"(?i)closed stdout|stdout closed"),
}


class Landed:
    """Whether a piece has landed, asked of the repository's own build: routes from the committed OpenAPI document,
    subcommands from ``p2pc --help``, the agent's connection from ``p2pc-agent status``. ``landed(key)`` takes a key of
    ``context.OWNERS`` and answers True, False, or None when the product cannot say (no binary, or a piece that has no
    marker, like the agent's lease executor)."""

    def __init__(self, repo: Any, run: Any = None, build: bool = True):
        import subprocess
        from pathlib import Path

        self.repo = Path(repo)
        self._run = run or subprocess.run
        self._build = build
        self._routes: Any = "unread"
        self._cli: Any = "unread"
        self._agent: Any = "unread"
        self._tried_build = False
        self._built = False  # the harness's own build succeeded

    def _build_once(self) -> None:
        """Builds `p2pc` and `p2pc-agent` (debug) once, when building is allowed. Even when binaries exist: they may be
        older than the sources. A failed build, or no cargo, leaves whatever is there to ``_binary``."""
        if not self._build or self._tried_build:
            return
        self._tried_build = True
        try:
            cp = self._run(["cargo", "build", "--manifest-path", str(self.repo / "Cargo.toml"), "-p", "p2pc-cli", "-p", "p2pc-agent"],
                           capture_output=True, timeout=3600, stdin=-3)
            self._built = cp.returncode == 0
        except (OSError, Exception):  # no cargo, a failed build: the product cannot say
            self._built = False

    def _binary(self, name: str) -> Any:
        """The binary to ask. The one the harness's own build just produced (`target/debug`: a no-op build leaves it as it
        is, but it is up to date with the sources, which a `target/release` from some earlier day may not be); without a
        build, the newer of `target/release` and `target/debug` (T15a review P3: release used to win whatever its age)."""
        self._build_once()
        found = [p for p in (self.repo / "target" / profile / name for profile in ("release", "debug")) if p.is_file()]
        if self._built:
            debug = self.repo / "target" / "debug" / name
            if debug in found:
                return debug
        if not found:
            return None
        return max(found, key=lambda p: p.stat().st_mtime)

    def _exec(self, name: str, *args: str) -> tuple[int, str] | None:
        binary = self._binary(name)
        if binary is None:
            return None
        try:
            cp = self._run([str(binary), *args], capture_output=True, timeout=60, stdin=-3)
        except (OSError, Exception):
            return None
        return cp.returncode, (cp.stdout or b"").decode("utf-8", "replace") + (cp.stderr or b"").decode("utf-8", "replace")

    def route(self, method: str, path: str) -> bool | None:
        if self._routes == "unread":
            self._routes = load_openapi_file(self.repo / "docs" / "api" / "openapi.json")
        return None if self._routes is None else (method.upper(), shape(path)) in self._routes

    def cli(self, sub: str) -> bool | None:
        if self._cli == "unread":
            got = self._exec("p2pc", "--help")
            self._cli = parse_help_commands(got[1]) if got and got[0] == 0 else None
        if not self._cli:
            return None
        return sub in self._cli and not self._cli[sub]

    def agent_connection(self) -> bool | None:
        if self._agent == "unread":
            got = self._exec("p2pc-agent", "status")
            self._agent = None if got is None else not is_stub_text(got[1])
        return self._agent

    def landed(self, key: str) -> bool | None:
        kind, _, rest = key.partition(" ")
        if kind == "route":
            method, _, path = rest.partition(" ")
            return self.route(method, path)
        if kind == "cli":
            return self.cli(rest)
        if kind == "feature":
            if rest == "scheduler":
                return self.route("GET", "/v1/usage")
            if rest == "agent-connection":
                return self.agent_connection()
            if rest == "installer":
                return (self.repo / "deploy" / "linux" / "install-server.sh").is_file()
            if rest in DOC_MARKERS:
                path, pattern = DOC_MARKERS[rest]
                try:
                    return re.search(pattern, (self.repo / path).read_text(encoding="utf-8")) is not None
                except OSError:
                    return None
            if rest == "node-installer":
                return (self.repo / "deploy" / "linux" / "install-node.sh").is_file()
        return None
