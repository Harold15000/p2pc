# SPDX-License-Identifier: Apache-2.0
"""The context every criterion script receives: machines, executors, recording, the ``p2pc`` CLI and polling.

A script calls ``ctx.require(...)`` for the roles it needs (which skips when a role is not configured, and fails
when a configured one is unreachable), ``ctx.deploy(...)`` for the binaries, and then ``ctx.p2pc(...)`` or
``ctx.exec(...)``. Every command is recorded, with its exit code and a redacted excerpt of its output, into the check
that is running. Time and sleeping are injectable, so the polling logic is tested without waiting.
"""

from __future__ import annotations

import json as _json
import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

import core
import executors
import machines
import product

# THE map of the harness: who owns each piece. This is the only place that names a task; every `Blocked(...)` takes its
# task from here (`owner(key)`), and a test scans the other files for a task name. Whether a piece has LANDED is never
# read from here: it is read from the product (`product.py`): routes from the server's OpenAPI, subcommands from
# `--help`, tests from `cargo test -- --list`. So when a task lands nothing has to be edited.
OWNERS: dict[str, str] = {
    "route POST /v1/jobs": "T04",
    "route GET /v1/jobs": "T04",
    "route GET /v1/jobs/{id}": "T04",
    "route POST /v1/jobs/{id}/cancel": "T04",
    "route POST /v1/estimate": "T04",
    "route GET /v1/nodes": "T05",
    "route POST /v1/nodes/join-tokens": "T05",
    "route GET /v1/nodes/join-tokens": "T05",
    "route GET /v1/server": "T05",
    "route GET /v1/jobs/{id}/logs": "T10b",
    "route GET /v1/jobs/{id}/outputs": "T10b",
    "route GET /v1/usage": "T06",
    "cli logs": "T11b2",  # spec §15 splits T11b: the tunnel (T11b1) and logs, results, usage (T11b2)
    "cli results": "T11b2",
    "cli usage": "T11b2",
    "cli proxy": "T11b1",
    "feature agent-connection": "T05b",  # `p2pc-agent join -` and `run`: a machine comes online
    "feature scheduler": "T06",  # a queued job is placed on a node; fencing, leases
    "feature executor": "T10a",  # the agent runs the lease and reports back
    "feature installer": "T14b1",  # install-server.sh
    "feature run-closed-stdout": "T11b3",  # `p2pc run … | head -1` detaches with 130 (spec §7, amended 2026-11-06)
    "feature node-installer": "T14b2",  # deploy/linux/install-node.sh: the node's agent, its unit (and install.ps1 -Join)
    "feature gateway": "T05",
    "feature server-core": "T03",  # keys, auth, the wire types: merged, but its tests are still looked up by owner
    "feature sandbox-driver": "T08",
    "feature egress-proxy": "T09",
}


def owner(key: str) -> list[str]:
    """The task that brings ``key`` (``route GET /v1/nodes``, ``cli logs``, ``feature scheduler``)."""
    try:
        return [OWNERS[key]]
    except KeyError:
        raise core.CheckFailed(f"harness bug: nothing in context.OWNERS says who brings {key!r}") from None


# What each `p2pc` subcommand calls. The route's owner is OWNERS["route <METHOD> <path>"].
CLI_ROUTES: dict[str, tuple[str, str]] = {
    "run": ("POST", "/v1/jobs"),
    "estimate": ("POST", "/v1/estimate"),
    "jobs": ("GET", "/v1/jobs"),
    "status": ("GET", "/v1/jobs/{id}"),
    "cancel": ("POST", "/v1/jobs/{id}/cancel"),
    "machines": ("GET", "/v1/nodes"),
    "join-token create": ("POST", "/v1/nodes/join-tokens"),
    "join-token list": ("GET", "/v1/nodes/join-tokens"),
    "logs": ("GET", "/v1/jobs/{id}/logs"),
    "results": ("GET", "/v1/jobs/{id}/outputs"),
    "usage": ("GET", "/v1/usage"),
}
# The installers have no marker in the running product: they are scripts of the repository, and landed means present.
INSTALLER_SCRIPTS: dict[str, tuple[str, ...]] = {
    "installer": ("deploy/linux/install-server.sh",),
    "node-installer": ("deploy/linux/install-node.sh",),  # T14b2; the Windows side (install.ps1 -Join) ships with it
}
# A piece with no marker in the running product, whose landing shows in the checkout's own documentation, is in
# product.DOC_MARKERS: the one table that `--list` (product.Landed) and the run (below) both read.
DOC_MARKERS = product.DOC_MARKERS
CLI_ROLE_NAME = "server"  # where the CLI and the REST probes run (flows.CLI_ROLE)
HARNESS = "harness"  # the pseudo role: the machine that runs the harness (cargo, gitleaks...)

BINARY_FILES = {"p2pc": "p2pc", "p2pc_server": "p2pc-server", "p2pc_agent": "p2pc-agent"}
TERMINAL = frozenset({"succeeded", "failed", "timed_out", "cancelled", "lost"})
DEFAULT_SERVER_URL = "http://127.0.0.1:7477"

HOST_PROBE = "p2pc-host-ok"  # what the PowerShell round trip to a Windows host prints
# A string full of everything that breaks quoting. Sent through a real machine before any criterion runs.
_PROBE = "it's \"q\"  a $HOME `x` $(y) ; \\ é"
# Sent on stdin and echoed back by `cat`: proves stdin crosses every layer too (put() and the secret wrapper rely on it).
_STDIN_PROBE = "stdin: it's \"q\"  $HOME `x` $(y) ;\nsecond line\n\u00e9"
_ENV_NAME = machines.ENV_NAME_RE
# A key or a join token, with its secret part: what must never be in an argv. The bare prefix in a command is fine.
_ARGV_SECRET_RE = re.compile(r"p2pc_(?:sk|join)_[A-Za-z0-9_\-]{8,}")
# Reads each secret from a line of stdin into an exported variable, then becomes the command.
_SECRET_PREAMBLE = "{reads} && exec \"$@\""


class Context:
    def __init__(
        self,
        config: machines.Machines,
        repo_root: Path,
        *,
        environ: Mapping[str, str] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        executor_factory: Callable[[machines.Role], executors.Executor] = executors.make_executor,
        redactor: core.Redactor = core.REDACTOR,
    ):
        self.machines = config
        self.repo_root = Path(repo_root)
        self.environ = dict(os.environ if environ is None else environ)
        self.clock = clock
        self.sleep = sleep
        self.state: dict[str, Any] = {}  # shared by the criteria of one run (the admin key, the joined nodes...)
        self.redactor = redactor
        self.result: core.Result | None = None
        self.artifacts_dir: Path | None = None  # set by run.py: where a criterion may keep evidence files
        self._executor_factory = executor_factory
        self._executors: dict[str, executors.Executor] = {}
        self._probed: set[str] = set()
        self._host_probed: set[str] = set()
        self._deployed: dict[tuple[str, str], str] = {}
        self._auto_workdirs: dict[str, str] = {}  # roles without `workdir`: the private directory made for the run

    # ---------------------------------------------------------------------------------------------------------
    # Recording
    # ---------------------------------------------------------------------------------------------------------

    def begin(self, id: str, title: str) -> core.Result:
        self.result = core.Result(id, title)
        return self.result

    def _record(self, step: core.Step) -> None:
        if self.result is not None:
            self.result.record_step(step)

    # ---------------------------------------------------------------------------------------------------------
    # Machines
    # ---------------------------------------------------------------------------------------------------------

    def executor(self, role: str) -> executors.Executor:
        if role not in self._executors:
            if role == HARNESS:
                spec = machines.Role(name=HARNESS, executor="local")
            else:
                spec = self.machines.roles[role]
            self._executors[role] = self._executor_factory(spec)
        return self._executors[role]

    def role(self, name: str) -> machines.Role:
        return self.machines.roles[name]

    def workdir(self, role: str) -> str:
        """The role's working directory. Without `workdir` in the machines file it is a private directory made on the
        machine with `mktemp -d` (random name, mode 0700), removed by ``close()``: never a predictable path in /tmp."""
        configured = self.machines.roles[role].workdir
        if configured:
            return configured
        if role not in self._auto_workdirs:
            step = self.exec(role, ["mktemp", "-d", "-t", "p2pc-acc.XXXXXXXXXX"], label=f"private workdir {role}", timeout=60)
            path = step.stdout.strip()
            if not step.ok or not machines.POSIX_PATH_RE.fullmatch(path) or path == "/":
                raise core.CheckFailed(
                    f"cannot make a private working directory on role '{role}': "
                    f"{step.error or core.last_line(step.stderr) or 'mktemp printed no path'}"
                )
            self._auto_workdirs[role] = path
        return self._auto_workdirs[role]

    def close(self) -> None:
        """Removes the private working directories this run made (binaries, config, logs). Never raises."""
        for role, path in list(self._auto_workdirs.items()):
            if path.startswith("/") and "p2pc-acc." in path:  # only what mktemp made for us
                self.exec(role, ["rm", "-rf", path], label=f"remove workdir {role}", timeout=60, record=False)
            del self._auto_workdirs[role]

    def bin(self, role: str, name: str) -> str:
        return f"{self.workdir(role)}/bin/{BINARY_FILES[name]}"

    def enabled_roles(self, *names: str) -> list[str]:
        return [n for n in names if n in self.machines.roles and self.machines.roles[n].enabled]

    def _check_configured(self, roles: Sequence[str]) -> None:
        for name in roles:
            spec = self.machines.roles.get(name)
            if spec is None:
                raise core.Skipped(f"role '{name}' is not in the machines file")
            if not spec.enabled:
                raise core.Skipped(f"role '{name}' is disabled (enabled = false) in the machines file")

    def require(self, *roles: str) -> None:
        """Skips when a role is not in the machines file or is disabled; fails when an enabled one is unreachable or
        mangles a command (the quoting round trip)."""
        self._check_configured(roles)
        for name in roles:
            self._preflight(name)

    def require_host(self, role: str) -> None:
        """Like ``require`` for the Windows HOST of a WSL role, not for its distro: a PowerShell round trip over ssh. The
        step that installs the distro (``install.ps1 -Tar``) runs on the host, so it must not need the distro to exist."""
        self._check_configured([role])
        if role in self._host_probed:
            return
        step = self.exec_host(role, f"Write-Output {executors.ps_quote(HOST_PROBE)}", label=f"preflight host {role}", timeout=60)
        if not step.ok or HOST_PROBE not in step.stdout:
            why = step.error or ("timed out" if step.timed_out else core.failure_reason(step.exit_code, step.stderr) or "no answer")
            raise core.CheckFailed(f"cannot reach the Windows host of role '{role}' ({self.executor(role).description}): {why}")
        self._host_probed.add(role)

    def probe_distro(self, role: str) -> core.Step:
        """Asks the Windows host of ``role`` (which must be reachable: ``require_host``) to run a command in its WSL distro:
        ``wsl.exe -d <distro> --exec true`` exits 0 when the distro exists and runs. The Step is returned whole: a non-zero
        exit may be a distro that does not exist, but a timeout (a slow boot) says nothing about that."""
        distro = self.machines.roles[role].distro or ""
        return self.exec_host(
            role, f"& wsl.exe -d {executors.ps_quote(distro)} --exec true", label=f"does the distro {distro} exist?", timeout=120
        )

    def _preflight(self, role: str) -> None:
        if role in self._probed:
            return
        step = self.exec(
            role,
            ["sh", "-c", 'printf %s "$1"; printf "\\n--stdin--\\n"; cat', "sh", _PROBE],
            label=f"preflight {role}",
            timeout=30,
            stdin=_STDIN_PROBE.encode(),
        )
        if not step.ok:
            why = step.error or ("timed out" if step.timed_out else core.failure_reason(step.exit_code, step.stderr) or "no answer")
            raise core.CheckFailed(f"cannot reach role '{role}' ({self.executor(role).description}): {why}")
        if step.stdout != f"{_PROBE}\n--stdin--\n{_STDIN_PROBE}":
            raise core.CheckFailed(
                f"quoting round trip failed on role '{role}': a command with quotes, spaces and $, or what was sent "
                "on stdin, came back changed"
            )
        work = self.workdir(role)
        made = self.exec(
            role,
            ["sh", "-c", 'mkdir -p "$1/bin" && chmod 700 "$1"', "sh", work],
            label=f"private workdir {role}",
            timeout=30,
        )
        if not made.ok:
            raise core.CheckFailed(f"cannot create {work} on role '{role}': {core.last_line(made.stderr)}")
        self._probed.add(role)

    # ---------------------------------------------------------------------------------------------------------
    # Running commands
    # ---------------------------------------------------------------------------------------------------------

    def build_argv(
        self,
        argv: Sequence[str],
        env: Mapping[str, str] | None,
        secret_env: Mapping[str, str] | None,
    ) -> list[str]:
        """The argv to execute: ``argv`` under ``env`` (plain variables, through ``env``), and with ``secret_env``
        read from stdin by a small shell wrapper, so that a secret never sits in a process list."""
        out = list(argv)
        if env:
            for name in env:
                if not _ENV_NAME.fullmatch(name):
                    raise executors.ExecError(f"bad environment variable name {name!r}")
            out = ["env", *[f"{k}={v}" for k, v in env.items()], *out]
        if secret_env:
            for name in secret_env:
                if not _ENV_NAME.fullmatch(name):
                    raise executors.ExecError(f"bad environment variable name {name!r}")
            reads = " && ".join(f"IFS= read -r {n} && export {n}" for n in secret_env)
            out = ["sh", "-c", _SECRET_PREAMBLE.format(reads=reads), "p2pc-acc", *out]
        return out

    def exec(
        self,
        role: str,
        argv: Sequence[str],
        *,
        label: str | None = None,
        timeout: float = 120.0,
        stdin: bytes | None = None,
        env: Mapping[str, str] | None = None,
        secret_env: Mapping[str, str] | None = None,
        record: bool = True,
        hold_stdin_until: Callable[[str], bool] | None = None,
        hold_deadline_s: float | None = None,
    ) -> core.Step:
        """Runs a command on a role and records it. A non-zero exit is a step to examine, not an exception.

        ``hold_stdin_until``: keep stdin open until the predicate on stdout holds, the command exits or
        ``hold_deadline_s`` passes (see ``Executor.run``)."""
        for value in (secret_env or {}).values():
            self.redactor.add_secret(value)
        self._refuse_secrets_in_argv(argv, env)
        shown = executors.sh_join(argv)
        if env:
            shown = " ".join(f"{k}={executors.sh_join([v])}" for k, v in env.items()) + " " + shown
        if secret_env:
            shown = " ".join(f"{k}=<secret>" for k in secret_env) + " " + shown
        data = stdin
        if secret_env:
            lines = "".join(f"{v}\n" for v in secret_env.values()).encode()
            data = lines + (stdin or b"")
        try:
            full = self.build_argv(argv, env, secret_env)
            held = {} if hold_stdin_until is None else {
                "hold_stdin_until": hold_stdin_until, "hold_deadline_s": hold_deadline_s}
            res = self.executor(role).run(full, timeout=timeout, stdin=data, **held)
        except executors.ExecError as e:
            res = executors.ExecResult(None, error=str(e))
        step = self._step(role, label or shown, shown, res)
        if record:
            self._record(step)
        return step

    def _refuse_secrets_in_argv(self, argv: Sequence[str], env: Mapping[str, str] | None) -> None:
        """No secret, ever, in an argument (rule of the harness): an argument shows in the machine's process list and in
        its shell history. Keys and tokens go on stdin (``secret_env``, ``stdin``) or in 0600 files. A key or a join token
        (``p2pc_sk_`` / ``p2pc_join_`` with something after the prefix), or any secret this run learned, in ``argv`` or in
        the plain ``env`` fails the check before the command is sent. The message never repeats the secret."""
        parts = [*argv, *(f"{k}={v}" for k, v in (env or {}).items())]
        for part in parts:
            if _ARGV_SECRET_RE.search(part) or any(lit in part for lit in self.redactor._literals):
                raise core.CheckFailed(
                    "harness bug: a key or a join token was about to travel in a command's argv; "
                    "secrets go on stdin (secret_env) or in a 0600 file, never in an argument. The command was not sent."
                )

    @staticmethod
    def _step(role: str, label: str, command: str, res: executors.ExecResult) -> core.Step:
        return core.Step(
            label=label,
            role=role,
            command=command,
            exit_code=res.returncode,
            duration_s=res.duration_s,
            stdout=res.stdout,
            stderr=res.stderr,
            timed_out=res.timed_out,
            error=res.error,
            retries=res.retries,
            retry_first_error=res.retry_first_error,
        )

    def exec_host(
        self,
        role: str,
        script: str,
        *,
        label: str,
        timeout: float = 120.0,
        stdin: bytes | None = None,
        record: bool = True,
    ) -> core.Step:
        """Runs a PowerShell ``script`` on the Windows host of a WSL role (where ``deploy/wsl/install.ps1`` is) and records
        it. ``stdin`` becomes the script's pipeline, never an argument. Refused, like ``exec``, if a secret is in the
        script text."""
        self._refuse_secrets_in_argv([script], None)
        try:
            res = self.executor(role).run_on_host(script, timeout=timeout, stdin=stdin)
        except executors.ExecError as e:
            res = executors.ExecResult(None, error=str(e))
        step = self._step(role, label, f"powershell: {script}", res)
        if record:
            self._record(step)
        return step

    def exec_ok(self, role: str, argv: Sequence[str], **kw: Any) -> core.Step:
        """Like ``exec`` but a command that did not succeed fails the check."""
        step = self.exec(role, argv, **kw)
        if not step.ok:
            raise core.CheckFailed(describe_failure(step))
        return step

    # ---------------------------------------------------------------------------------------------------------
    # Binaries
    # ---------------------------------------------------------------------------------------------------------

    def deploy(self, role: str, *names: str) -> dict[str, str]:
        """Copies binaries built locally into the role's workdir and verifies each copy with sha256 (spec: the
        harness copies them, with sha256 checks). Returns name -> sha256."""
        self.require(role)
        out: dict[str, str] = {}
        for name in names:
            local = self.machines.binaries.path(name)
            if local is None or not local.is_file():
                raise core.Skipped(
                    f"binary {BINARY_FILES[name]} not found"
                    + (f" at {local}" if local else " (not set in [binaries])")
                    + ": build it with `cargo build --release` and point [binaries] at it"
                )
            digest = executors.file_sha256(local)
            pin = self.machines.binaries.pinned_sha256(name)
            if pin and pin != digest:
                raise core.CheckFailed(
                    f"{BINARY_FILES[name]} does not match its pinned sha256 (built {digest[:12]}…, pinned {pin[:12]}…)"
                )
            remote = self.bin(role, name)
            if self._deployed.get((role, name)) == digest:
                out[name] = digest
                continue
            ex = self.executor(role)
            t0 = self.clock()
            put = ex.put(local, remote)
            self._record(self._step(role, f"copy {BINARY_FILES[name]}", f"put {BINARY_FILES[name]} -> {remote}", put))
            if put.returncode != 0:
                raise core.CheckFailed(
                    f"cannot copy {BINARY_FILES[name]} to role '{role}': {core.last_line(put.stderr) or put.error}"
                )
            try:
                remote_digest, hashed = ex.sha256_result(remote)
            except executors.ExecError as e:
                raise core.CheckFailed(str(e)) from None
            self._record(
                core.Step(
                    f"sha256 {BINARY_FILES[name]}",
                    role,
                    f"sha256sum {remote}",
                    0,
                    duration_s=self.clock() - t0,
                    stdout=f"{remote_digest}  {remote}",
                    retries=hashed.retries,
                    retry_first_error=hashed.retry_first_error,
                )
            )
            if remote_digest != digest:
                raise core.CheckFailed(
                    f"sha256 mismatch after copying {BINARY_FILES[name]} to role '{role}' "
                    f"(local {digest[:12]}…, remote {remote_digest[:12]}…)"
                )
            self._deployed[(role, name)] = digest
            out[name] = digest
        return out

    # ---------------------------------------------------------------------------------------------------------
    # The p2pc CLI
    # ---------------------------------------------------------------------------------------------------------

    def set_admin_key(self, key: str) -> None:
        self.state["admin_key"] = key
        self.redactor.add_secret(key)

    def admin_key(self) -> str:
        key = self.state.get("admin_key")
        if key:
            return key
        server = self.machines.roles.get("server")
        env_name = server.get("admin_key_env") if server else None
        if env_name and self.environ.get(env_name):
            self.set_admin_key(self.environ[env_name])
            return self.state["admin_key"]
        hint = f"set ${env_name} to an admin key" if env_name else "set admin_key_env in [server]"
        raise core.Skipped(f"no admin key: run AC-1 first (it installs the server and captures the key), or {hint}")

    def server_url(self) -> str:
        server = self.machines.roles.get("server")
        return (server.get("url") if server else None) or DEFAULT_SERVER_URL

    def p2pc(
        self,
        role: str,
        args: Sequence[str],
        *,
        key: str | None = "admin",
        server_url: str | None = None,
        json: bool = True,
        timeout: float = 120.0,
        stdin: bytes | None = None,
        expect_ok: bool = False,
        record: bool = True,
        hold_stdin_until: Callable[[str], bool] | None = None,
        hold_deadline_s: float | None = None,
    ) -> core.Step:
        """Runs ``p2pc`` on ``role`` against the server, with ``--json`` and the key passed through stdin.

        ``key``: ``"admin"`` (the admin key), ``None`` (no key) or a key string.

        **Every call is checked for a missing piece**, from the product and the map (``OWNERS``), so no script can
        forget it. The check is ``blocked``, naming the owner, when

        * the call failed and the subcommand is a stub in ``p2pc --help`` (read once per run, and only when a call
          fails: a stub given arguments dies in clap before it can say what it is), or
        * the call answered 404, 405 or 501 AND the REST route behind it (``CLI_ROUTES``) is absent from the server's own
          ``/v1/openapi.json``. A 404 alone never blocks: an existing route answers it for an unknown job id."""
        sub = args[0] if args else ""
        route = CLI_ROUTES.get(self._route_key(args))
        step = self._p2pc_exec(
            role, args, key=key, server_url=server_url, json=json, timeout=timeout, stdin=stdin, record=record,
            hold_stdin_until=hold_stdin_until, hold_deadline_s=hold_deadline_s,
        )
        if not step.ok and sub and f"cli {sub}" in OWNERS and self.cli_stub(role, sub):
            raise core.Blocked(f"`p2pc {sub}` is not available in this version of the CLI yet", owner(f"cli {sub}"))
        self.raise_if_missing(step, what=f"p2pc {sub}", route=route, cli=sub)
        if expect_ok and not step.ok:
            raise core.CheckFailed(describe_failure(step))
        return step

    def raise_if_missing(self, step: core.Step, *, what: str, route: tuple[str, str] | None, cli: str | None = None) -> None:
        """Raises ``Blocked`` when a failed step is explained by a piece that is not built: a stub's own words, or a
        404/405/501 on a route the server's OpenAPI does not have. The same path serves ``p2pc`` and plain REST calls."""
        detail = describe_failure(step).splitlines()[0] if (step.stdout or step.stderr or step.error) else ""
        if not step.ok and step.missing_piece():
            key = f"cli {cli}" if cli and f"cli {cli}" in OWNERS else (f"route {route[0]} {route[1]}" if route else None)
            if key:
                raise core.Blocked(f"`{what}` is not available yet ({detail})", owner(key))
        if route is not None and step.route_status() is not None and self.route_missing(*route):
            raise core.Blocked(
                f"{route[0]} {route[1]} is not in the server's OpenAPI document yet ({detail[:150]})",
                owner(f"route {route[0]} {route[1]}"),
            )

    def _p2pc_exec(
        self,
        role: str,
        args: Sequence[str],
        *,
        key: str | None,
        server_url: str | None = None,
        json: bool = True,
        timeout: float = 120.0,
        stdin: bytes | None = None,
        record: bool = True,
        hold_stdin_until: Callable[[str], bool] | None = None,
        hold_deadline_s: float | None = None,
    ) -> core.Step:
        """Runs ``p2pc`` and records it: no missing-piece checks (they are ``p2pc``'s, and reading ``--help`` must not
        trigger itself)."""
        api_key = self.admin_key() if key == "admin" else key
        env = {
            "P2PC_CONFIG_DIR": f"{self.workdir(role)}/p2pc-config",
            "P2PC_SERVER": server_url or self.server_url(),
        }
        argv = [self.bin(role, "p2pc"), *(["--json"] if json else []), *args]
        step = self.exec(
            role,
            argv,
            label="p2pc " + " ".join(args[:2]),
            timeout=timeout,
            stdin=stdin,
            env=env,
            secret_env={"P2PC_API_KEY": api_key} if api_key else None,
            record=record,
            hold_stdin_until=hold_stdin_until,
            hold_deadline_s=hold_deadline_s,
        )
        # Keep the report readable: show `p2pc <args>`, not the whole wrapper.
        step.command = "p2pc " + executors.sh_join(args)
        return step

    @staticmethod
    def _route_key(args: Sequence[str]) -> str:
        """The key into ``CLI_ROUTES``: the subcommand, or ``<sub> <verb>`` for the ones with verbs."""
        if not args:
            return ""
        if args[0] == "join-token":
            return "join-token " + (args[1] if len(args) > 1 else "")
        if args[0] == "machines":
            return "machines" if len(args) == 1 or args[1].startswith("-") else "machines " + args[1]
        return args[0]

    # ---------------------------------------------------------------------------------------------------------
    # What has landed: read from the product
    # ---------------------------------------------------------------------------------------------------------

    def openapi_routes(self) -> set[tuple[str, str]] | None:
        """``{(METHOD, shaped path)}`` from the server's ``GET /v1/openapi.json``. A successful read is cached for the
        run. A failed one is retried once and NOT cached: it may be a hiccup, and if it cannot be read no route is
        declared missing."""
        if self.state.get("openapi_routes") is not None:
            return self.state["openapi_routes"]
        for _attempt in range(2):
            try:
                step = self.rest_get(CLI_ROLE_NAME, "/v1/openapi.json", record=False)
            except (core.Skipped, executors.ExecError):
                return None
            doc = step.parsed_stdout() if step.ok else None
            routes = product.parse_openapi(doc)
            if routes is not None:
                self.state["openapi_routes"] = routes
                self.state["openapi_doc"] = doc
                return routes
        return None

    def schema_has_property(self, schema: str, prop: str) -> bool | None:
        """Whether the server's OpenAPI declares ``prop`` on the schema ``schema`` (for example ``Job.attempts``); None
        when the document cannot be read or has no such schema."""
        if self.openapi_routes() is None:
            return None
        return product.schema_has_property(self.state.get("openapi_doc"), schema, prop)

    def route_landed(self, method: str, template: str) -> bool | None:
        """Whether the server has the route; None when its OpenAPI cannot be read (then nothing is declared)."""
        routes = self.openapi_routes()
        if routes is None:
            return None
        return (method.upper(), product.shape(template)) in routes

    def route_missing(self, method: str, template: str) -> bool:
        """True only when the server's OpenAPI document was read and has no ``method`` on ``template`` (parameter names
        do not matter)."""
        return self.route_landed(method, template) is False

    def cli_commands(self, role: str) -> dict[str, bool]:
        """The subcommands of ``p2pc --help`` and whether each says it is a stub. Read once per run; ``{}`` if the help
        cannot be read (then no subcommand is declared a stub)."""
        cache = self.state.setdefault("cli_commands", {})
        if role not in cache:
            help_step = self._p2pc_exec(role, ["--help"], key=None, json=False, timeout=60)
            cache[role] = product.parse_help_commands(help_step.stdout) if help_step.ok else {}
        return cache[role]

    def cli_stub(self, role: str, sub: str) -> bool:
        """Whether ``p2pc <sub>`` is a stub, read from ``p2pc --help`` (help has no side effect, unlike a bare
        ``p2pc proxy`` that works and starts a listener)."""
        return self.cli_commands(role).get(sub) is True

    def agent_landed(self, role: str) -> bool | None:
        """Whether the agent's connection to the server exists, asked of the agent itself: ``p2pc-agent status`` is
        read-only, and a stub says so in its own words. None when there is nothing to ask."""
        cache = self.state.setdefault("agent_landed", {})
        if role not in cache:
            self.deploy(role, "p2pc_agent")
            step = self.exec(role, [self.bin(role, "p2pc_agent"), "status"], label="p2pc-agent status", timeout=60)
            cache[role] = None if (step.error or step.timed_out) else not step.stub_marker()
        return cache[role]

    def feature_landed(self, name: str) -> bool | None:
        """Whether a feature without a route of its own exists, from what the product reports: the scheduler is T06's
        ``GET /v1/usage`` in the OpenAPI; the agent's connection is its own ``status``. None: it cannot be read."""
        if name == "scheduler":
            return self.route_landed("GET", "/v1/usage")
        if name == "agent-connection":
            roles = self.enabled_roles("node_linux_gpu", "node_linux", "node_wsl2_gpu")
            return self.agent_landed(roles[0]) if roles else None
        if name in DOC_MARKERS:
            path, pattern = DOC_MARKERS[name]
            try:
                return re.search(pattern, (self.repo_root / path).read_text(encoding="utf-8")) is not None
            except OSError:
                return None
        if name in INSTALLER_SCRIPTS:  # the script being in this checkout (the same test as `run.py --list`)
            return any((self.repo_root / path).is_file() for path in INSTALLER_SCRIPTS[name])
        return None

    def rest_get(
        self, role: str, path: str, *, timeout: float = 60.0, record: bool = True,
        route: tuple[str, str] | None = None, expect_ok: bool = False,
    ) -> core.Step:
        """``GET <server>/<path>`` with the admin key, through curl (the key goes in curl's config on stdin).

        The HTTP status is captured (``-w``): a 2xx is exit 0; anything else is exit 22 with the same
        ``{"error": {"kind": "api", "status", "code"…}}`` on stderr that ``p2pc --json`` prints, so the answer goes
        through the same missing-route and error path as ``ctx.p2pc`` (``route`` names the route behind the path)."""
        if not re.fullmatch(r"/[A-Za-z0-9_./?=&%-]*", path):
            raise executors.ExecError(f"bad REST path {path!r}")
        config = f'url = "{self.server_url()}{path}"\nheader = "Authorization: Bearer {self.admin_key()}"\n'
        step = self.exec(
            role,
            ["curl", "-sS", "--max-time", str(int(timeout)), "-K", "-", "-w", "\n%{http_code}"],
            label=f"GET {path}",
            timeout=timeout + 15,
            stdin=config.encode(),
            record=record,
        )
        step.command = f"curl GET {path}"
        if step.exit_code == 0:
            body, _, code = step.stdout.rpartition("\n")
            step.stdout = body
            status = int(code) if code.strip().isdigit() else 0
            if not 200 <= status < 300:
                step.exit_code = 22
                try:
                    problem = _json.loads(body)
                except ValueError:
                    problem = {}
                problem = problem if isinstance(problem, dict) else {}
                step.stderr = _json.dumps({"error": {
                    "kind": "api", "status": status, "code": problem.get("code"), "title": problem.get("title"),
                    "detail": problem.get("detail")}})
        if route is not None or expect_ok:
            self.raise_if_missing(step, what=f"GET {path}", route=route)
        if expect_ok and not step.ok:
            raise core.CheckFailed(describe_failure(step))
        return step

    def json_of(self, step: core.Step, what: str = "output") -> Any:
        data = step.parsed_stdout()
        if data is None:
            raise core.CheckFailed(f"{what} is not JSON: {core.excerpt(core.clean(step.stdout), 120)!r}")
        return data

    def final_job(self, step: core.Step, what: str = "p2pc run --json") -> dict:
        """The final job of a ``p2pc run --json``: the last line of its NDJSON stdout, after the job's log records."""
        job = step.final_json()
        if not isinstance(job, dict) or not isinstance(job.get("id"), str) or "status" not in job:
            raise core.CheckFailed(f"{what} did not end with the job as its last line: {core.excerpt(core.clean(step.stdout), 120)!r}")
        return job

    def wait_job(
        self,
        role: str,
        job_id: str,
        *,
        timeout_s: float,
        poll_s: float = 1.0,
        until: Iterable[str] | None = None,
        key: str | None = "admin",
    ) -> tuple[dict, float]:
        """Polls ``p2pc status`` until the job reaches one of the ``until`` states (default: any terminal state).
        Returns the job and the seconds waited. Only the last poll is kept in the report."""
        goal = frozenset(until) if until is not None else TERMINAL
        start = self.clock()
        while True:
            step = self.p2pc(role, ["status", job_id], key=key, expect_ok=True, record=False)
            job = self.json_of(step, "p2pc status")
            status = job.get("status") if isinstance(job, dict) else None
            elapsed = self.clock() - start
            if status in goal:
                self._record(step)
                return job, elapsed
            if status in TERMINAL and status not in goal:
                self._record(step)
                raise core.CheckFailed(f"job {job_id} ended as '{status}' while waiting for {sorted(goal)}")
            if elapsed >= timeout_s:
                self._record(step)
                raise core.CheckFailed(f"job {job_id} was still '{status}' after {timeout_s:g} s")
            self.sleep(poll_s)

    # ---------------------------------------------------------------------------------------------------------
    # Parameters and manual evidence
    # ---------------------------------------------------------------------------------------------------------

    def param(self, name: str) -> int:
        return self.machines.params[name]

    def image(self, name: str) -> str:
        return self.machines.images[name]

    def manual_evidence(self, key: str) -> tuple[Path, str]:
        """A human-made report the machines file points to: returns its path and sha256, or skips."""
        path = self.machines.manual.get(key)
        if path is None:
            raise core.Skipped(f"manual evidence not provided: set [manual] {key} in the machines file")
        if not path.is_file():
            raise core.Skipped(f"manual evidence [manual] {key} not found: {path.name}")
        if path.stat().st_size == 0:
            raise core.Skipped(f"manual evidence [manual] {key} is empty: {path.name}")
        return path, executors.file_sha256(path)


def describe_failure(step: core.Step) -> str:
    """One readable line about why a command did not succeed: the API error code if there is one. Everything that
    comes from the machine or the server is redacted first."""
    err = step.error_json()
    if step.error:
        return core.clean(f"{step.label}: {step.error}")
    if step.timed_out:
        return f"{step.label}: timed out"
    if err:
        text = f"{step.label}: exit {step.exit_code}: {err.get('code') or err.get('kind')}: {err.get('detail') or err.get('title') or ''}"
        return core.clean(text).rstrip(": ")
    return core.clean(f"{step.label}: exit {step.exit_code}: {core.failure_reason(step.exit_code, step.stderr)}").rstrip(": ")
