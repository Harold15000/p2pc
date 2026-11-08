# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the criterion scripts: node lookup, job submission, and the pure analysis functions.

The analysis functions (cargo output, listening sockets, concurrency, the usage ledger, MCP replies, the egress probe)
take plain data and return plain data, so ``test_harness.py`` tests them without a machine.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit
from typing import Any, Iterable, Sequence

import context
import core
import product

CLI_ROLE = "server"  # the functional criteria run the CLI on the server host, against its loopback address
# A Linux node with an NVIDIA GPU, a Linux node without one, and the WSL2 node (which has one).
NODE_ROLES = ("node_linux_gpu", "node_linux", "node_wsl2_gpu")
GPU_ROLES = ("node_linux_gpu", "node_wsl2_gpu")  # the nodes AC-3 needs
PLATFORM_OF = {"node_linux_gpu": "linux", "node_linux": "linux", "node_wsl2_gpu": "wsl2"}
LABEL_OF = {"node_linux_gpu": "linux", "node_linux": "linux-cpu", "node_wsl2_gpu": "wsl2"}  # in the names of checks
ACTIVE_STATES = ("assigned", "running")


# --------------------------------------------------------------------------------------------------------------
# Environment, nodes and jobs
# --------------------------------------------------------------------------------------------------------------


def ready(ctx, c: core.CheckScope, node_roles: Sequence[str] = ()) -> None:
    """Inside a check: roles reachable, ``p2pc`` copied, the admin key works. """
    ctx.require(CLI_ROLE, *node_roles)
    ctx.deploy(CLI_ROLE, "p2pc")
    ctx.admin_key()
    who = ctx.json_of(ctx.p2pc(CLI_ROLE, ["whoami"], expect_ok=True), "p2pc whoami")
    c.require("admin" in (who.get("scopes") or []), "the key in use has no admin scope")


def list_nodes(ctx) -> list[dict]:
    step = ctx.p2pc(CLI_ROLE, ["machines"], expect_ok=True)  # a missing `GET /v1/nodes` is blocked by its owner (ctx.p2pc)
    nodes = ctx.json_of(step, "p2pc machines")
    if not isinstance(nodes, list):
        raise core.CheckFailed("p2pc machines --json is not an array")
    return nodes


# --------------------------------------------------------------------------------------------------------------
# Scopes: exactly what a key's calls need (crates/p2pc-server/src/auth.rs, the routes of jobs_api.rs, and the MCP tools
# of crates/p2pc-cli/src/mcp/tools.rs). A key the harness creates gets these and nothing more.
# --------------------------------------------------------------------------------------------------------------

CLI_SCOPE: dict[str, str | None] = {
    "whoami": None,  # any valid key
    "proxy": None,  # the tunnel makes no REST call itself: the calls made through it carry their own scopes
    "mcp": None,  # `p2pc mcp` calls whoami on start; each tool needs its own scope (MCP_SCOPE)
    "run": "jobs:write",
    "cancel": "jobs:write",
    "estimate": "jobs:read",
    "status": "jobs:read",
    "jobs": "jobs:read",
    "logs": "jobs:read",
    "results": "jobs:read",
    "usage": "jobs:read",
    "machines": "nodes:read",
    "keys": "admin",
    "join-token": "admin",
    "audit": "admin",
}
MCP_SCOPE: dict[str, str] = {
    "p2pc_estimate": "jobs:read",
    "p2pc_run": "jobs:write",
    "p2pc_status": "jobs:read",
    "p2pc_logs": "jobs:read",
    "p2pc_results": "jobs:read",
    "p2pc_cancel": "jobs:write",
    "p2pc_machines": "nodes:read",
}


def scopes_needed(cli: Iterable[str] = (), mcp: Iterable[str] = ()) -> list[str]:
    """The scopes a key needs for these ``p2pc`` subcommands and MCP tools: the least that works, sorted. A key must
    have at least one scope, so a key that only needs to be a valid key gets ``jobs:read``."""
    need = {CLI_SCOPE[c] for c in cli} | {MCP_SCOPE[t] for t in mcp}
    need.discard(None)
    return sorted(need) or ["jobs:read"]


# --------------------------------------------------------------------------------------------------------------
# The gate for every criterion that needs a job to RUN
# --------------------------------------------------------------------------------------------------------------

GATE_PLACE_S = 60  # a job must leave `queued` once the scheduler exists
GATE_START_S = 900  # ... then start running (includes the first image pull)
GATE_FINISH_S = 120  # ... then finish and be reported


def _poll_job(ctx, job_id: str, still: Sequence[str], timeout_s: float) -> dict:
    """Polls ``p2pc status`` until the job leaves the ``still`` states or ``timeout_s`` passes; returns the last job."""
    start = ctx.clock()
    while True:
        job = ctx.json_of(ctx.p2pc(CLI_ROLE, ["status", job_id], expect_ok=True, record=False), "p2pc status")
        if job.get("status") not in still or ctx.clock() - start >= timeout_s:
            return job
        ctx.sleep(2.0)


def require_jobs_run(ctx) -> None:
    """A node can actually run a job. Probed ONCE per run with a trivial job; the answer, a ``Blocked`` included, is
    remembered. Without it, a criterion that waits for a job would time out and report a ``fail`` for something that is
    only not built yet.

    What has landed is read from the product, in this order:

    1. the nodes route in the server's OpenAPI (``ctx.p2pc`` blocks on it by itself);
    2. no machine online: the agent is asked (``p2pc-agent status``); if it is still a stub the agent's connection is
       what is missing, otherwise the environment is (nobody joined a machine): a skip;
    3. the probe job is **always submitted** (one marker is not proof the scheduler is absent). If it leaves ``queued``,
       the scheduler exists and the run continues. If it stays ``queued`` and the scheduler's marker (``GET /v1/usage``
       in the OpenAPI) is absent, that is ``blocked`` by the scheduler's owner; if the marker is present it is a **fail**; if
       the OpenAPI cannot be read it is a **fail** that says the marker could not be read;
    4. past the scheduler, a timeout is a **fail**: the executor has no marker of its own to read, so a job that is
       assigned and never starts, or runs and never finishes, is reported as the failure it looks like (the message
       names who owns the executor)."""
    cached = ctx.state.get("jobs_run")
    if isinstance(cached, BaseException):
        raise cached
    if cached is True:
        return
    try:
        _probe_jobs_run(ctx)
    except (core.Blocked, core.Skipped, core.CheckFailed) as e:
        ctx.state["jobs_run"] = e
        raise
    ctx.state["jobs_run"] = True


def _probe_jobs_run(ctx) -> None:
    nodes = list_nodes(ctx)
    online = [n for n in nodes if n.get("state") == "online"]
    if not online:
        if ctx.feature_landed("agent-connection") is False:
            raise core.Blocked("no machine is online and the agent cannot connect yet", context.owner("feature agent-connection"))
        raise core.Skipped("no machine is online: join a machine (`p2pc-agent join`) and start its agent, then run again")
    job = submit(
        ctx,
        ["--image", ctx.image("cpu"), "--cpu", "0.25", "--mem", "128M", "--timeout", "2m", "--name", "acc-gate",
         "--", "true"],
    )
    executor = ", ".join(context.owner("feature executor"))
    final: dict = {}
    try:
        placed = _poll_job(ctx, job["id"], ("queued",), GATE_PLACE_S)
        if placed.get("status") == "queued":
            # One marker is not proof of absence: the job was submitted anyway, and nothing placed it.
            marker = ctx.feature_landed("scheduler")
            if marker is False:
                raise core.Blocked(
                    f"machines are online and the probe job stayed queued for {GATE_PLACE_S} s, and the server has no "
                    "scheduler marker (`GET /v1/usage` in its OpenAPI): nothing places jobs yet",
                    context.owner("feature scheduler"),
                )
            if marker is None:
                raise core.CheckFailed(
                    f"the probe job stayed queued for {GATE_PLACE_S} s on an online machine, and the scheduler's marker "
                    "(`GET /v1/usage`) could not be read from the server's OpenAPI: it cannot be told whether the "
                    "scheduler is missing (blocked) or broken (a failure)"
                )
            raise core.CheckFailed(
                f"the scheduler's marker (`GET /v1/usage`) is in the OpenAPI but the probe job stayed queued for "
                f"{GATE_PLACE_S} s on an online machine"
            )
        started = _poll_job(ctx, job["id"], ("queued", "assigned"), GATE_START_S)
        if started.get("status") in ("queued", "assigned"):
            raise core.CheckFailed(
                f"the probe job was assigned to a machine and never started within {GATE_START_S} s: the agent's lease "
                f"executor (task {executor}) is the first suspect"
            )
        final = _poll_job(ctx, job["id"], ("running",), GATE_FINISH_S)
        if final.get("status") == "running":
            raise core.CheckFailed(
                f"the probe job (`true`) was still running after {GATE_FINISH_S} s: the agent did not report "
                f"JobFinished (task {executor})"
            )
    finally:
        # Never leave the probe behind.
        ctx.p2pc(CLI_ROLE, ["cancel", job["id"]], record=False)
    if final.get("status") != "succeeded":
        raise core.CheckFailed(
            f"the probe job ended as '{final.get('status')}' ({final.get('error') or 'exit ' + str(final.get('exit_code'))}): "
            "a node exists and runs jobs, and this one failed"
        )


def ready_to_run(ctx, c: core.CheckScope, node_roles: Sequence[str] = ()) -> None:
    """``ready`` plus the gate: for a check that goes on to run jobs."""
    ready(ctx, c, node_roles)
    require_jobs_run(ctx)


def enabled_node_roles(ctx) -> list[str]:
    return ctx.enabled_roles(*NODE_ROLES)


def node_id_for(ctx, role: str, nodes: Sequence[dict]) -> str:
    """The server's id of the machine that plays ``role``: remembered from AC-1, or the node named in the machines
    file, or the only online node of the right platform that has a GPU."""
    known = ctx.state.get("node_ids", {}).get(role)
    if known and any(n.get("id") == known for n in nodes):
        return known
    name = ctx.role(role).get("node_name")
    if name:
        for n in nodes:
            if name in (n.get("name"), n.get("hostname")):
                return n["id"]
        raise core.CheckFailed(f"no machine named '{name}' in p2pc machines (role {role})")
    wants_gpu = role in GPU_ROLES  # `node_linux` is the Linux node WITHOUT a GPU
    candidates = [
        n
        for n in nodes
        if (n.get("inventory") or {}).get("platform") == PLATFORM_OF[role]
        and bool((n.get("inventory") or {}).get("gpus")) == wants_gpu
        and n.get("state") == "online"
    ]
    if len(candidates) != 1:
        raise core.CheckFailed(
            f"cannot tell which machine is role {role}: {len(candidates)} online {PLATFORM_OF[role]} nodes "
            f"{'with' if wants_gpu else 'without'} a GPU; set node_name in the machines file"
        )
    return candidates[0]["id"]


def role_of_node(ctx, node_id: str, nodes: Sequence[dict]) -> str | None:
    for role in enabled_node_roles(ctx):
        try:
            if node_id_for(ctx, role, nodes) == node_id:
                return role
        except core.CheckFailed:
            continue
    return None


def submit(ctx, args: Sequence[str], *, key: str | None = "admin") -> dict:
    """``p2pc run --detach`` and returns the job. A missing `POST /v1/jobs` is blocked by its owner (``ctx.p2pc``)."""
    step = ctx.p2pc(CLI_ROLE, ["run", "--detach", *args], expect_ok=True, key=key)
    job = ctx.json_of(step, "p2pc run --detach")
    if not isinstance(job, dict) or not isinstance(job.get("id"), str):
        raise core.CheckFailed("p2pc run --detach --json did not print a job with an id")
    return job


def parse_ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def usage_upper_bound(jobs: Iterable[dict]) -> str:
    """The ``--to`` of ``p2pc usage`` for a batch of finished jobs: an hour after the last one ended, in whole seconds
    UTC (what the CLI sends). Without it the CLI stops at the end of the current UTC day (docs/cli.md), and a batch that
    crosses midnight would lose its last attempts from the ledger. ``--to`` is exclusive, hence the margin."""
    from datetime import timedelta, timezone

    # Every end we know of, and the creation of a job that has none: the latest of them all.
    latest = max(parse_ts(j[k]) for j in jobs for k in ("finished_at", "created_at") if j.get(k))
    return (latest + timedelta(hours=1)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def seconds_between(start: str | None, end: str | None) -> float:
    if not start or not end:
        raise core.CheckFailed("the job has no timestamps for this interval")
    return (parse_ts(end) - parse_ts(start)).total_seconds()


def visible_containers(ctx, node_role: str, *, running_only: bool = False) -> list[str]:
    """The names of the sandbox containers P2PC has on a node (label ``p2pc.lease``, spec §9), as the harness's podman
    sees them. If the harness cannot run podman there at all, the answer is a skip, never an empty list: an empty list
    would make "the container is gone" true of everything.

    ``running_only``: only containers that are running. SI-13 is about a partitioned agent STOPPING its job, so AC-6
    looks only at running ones (a stopped container that has not been removed yet is not a job still running);
    AC-7's "the container is gone" is stricter and also lists the stopped ones (``ps -a``)."""
    podman = ctx.role(node_role).get("podman") or ["podman"]
    step = ctx.exec(
        node_role,
        [*podman, "ps", *([] if running_only else ["-a"]), "--filter", "label=p2pc.lease", "--format", "{{.Names}}"],
        timeout=60,
    )
    if not step.ok:
        raise core.Skipped(
            f"the harness cannot list containers on '{node_role}' "
            f"({core.last_line(step.stderr) or step.error or 'podman failed'}): set `podman` for this role in the machines file"
        )
    return [ln.strip() for ln in step.stdout.splitlines() if ln.strip()]


def new_container(ctx, node_role: str, baseline: Sequence[str], *, running_only: bool = False) -> str:
    """The container of the job that was just started on ``node_role``: the one name (``p2pc-<lease id>``, from the
    ``p2pc.lease`` label) that was not there in ``baseline``, taken before the job was submitted. The job carries no
    lease id, so this is how its own container is told from anybody else's. Without proof that it is visible, "the
    container is gone" would be vacuous, so the answer is a skip."""
    new = sorted(set(visible_containers(ctx, node_role, running_only=running_only)) - set(baseline))
    if not new:
        raise core.Skipped(
            f"no new P2PC container is visible on '{node_role}' while the job runs: the harness's podman is not the "
            "agent's (set `podman` for the role), so 'the container is gone' cannot be proved"
        )
    if len(new) > 1:
        raise core.CheckFailed(f"{len(new)} new containers appeared on '{node_role}' ({', '.join(new)}): other jobs are starting there")
    return new[0]


def wait_until(ctx, predicate, *, timeout_s: float, poll_s: float, what: str):
    """Polls ``predicate()`` (returns a truthy value when done) on the context's clock. Fails with ``what``."""
    start = ctx.clock()
    while True:
        value = predicate()
        if value:
            return value, ctx.clock() - start
        if ctx.clock() - start >= timeout_s:
            raise core.CheckFailed(f"timed out after {timeout_s:g} s waiting for {what}")
        ctx.sleep(poll_s)


# --------------------------------------------------------------------------------------------------------------
# AC-11: which tests exist, read from cargo
# --------------------------------------------------------------------------------------------------------------


def test_inventory(ctx) -> list[product.ListedTest]:
    """Every test of the workspace, from ``cargo test --workspace --all-features -- --list`` (and ``--list --ignored`` to
    tell which are ``#[ignore]``d). Read once per run. cargo prints the test binary on stderr and the names on stdout, so
    both streams go through one pipe, in order."""
    if "test_inventory" in ctx.state:
        return ctx.state["test_inventory"]
    manifest = str(ctx.repo_root / "Cargo.toml")

    def listing(*extra: str) -> core.Step:
        return ctx.exec(
            "harness",
            ["sh", "-c", 'exec cargo test --manifest-path "$0" --workspace --all-features -- --list "$@" 2>&1', manifest, *extra],
            label="cargo test -- --list " + " ".join(extra),
            timeout=3600,
        )

    first = listing()
    if first.error or first.exit_code == 127:
        raise core.Skipped("cargo is not available on the machine that runs the harness")
    if not first.ok:
        raise core.CheckFailed(f"cannot list the tests (the workspace does not build?): {core.tail(first.stdout, 300)}")
    ignored = listing("--ignored")
    c_all = product.parse_test_list(first.stdout)
    c_ign = product.parse_test_list(ignored.stdout, ignored=True) if ignored.ok else []
    ctx.state["test_inventory"] = product.merge_lists(c_all, c_ign)
    return ctx.state["test_inventory"]


# --------------------------------------------------------------------------------------------------------------
# AC-11: cargo test output
# --------------------------------------------------------------------------------------------------------------

_RESULT_RE = re.compile(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored")


def parse_cargo_test(output: str) -> tuple[int, int, int]:
    """(passed, failed, ignored) summed over every test binary in a ``cargo test`` output."""
    passed = failed = ignored = 0
    for m in _RESULT_RE.finditer(output):
        passed += int(m.group(1))
        failed += int(m.group(2))
        ignored += int(m.group(3))
    return passed, failed, ignored


# --------------------------------------------------------------------------------------------------------------
# AC-8: open ports
# --------------------------------------------------------------------------------------------------------------


def _split_local(addr: str) -> tuple[str, int] | None:
    host, sep, port = addr.rpartition(":")
    if not sep or not port.isdigit():
        return None
    return host.strip("[]").split("%")[0], int(port)


def _is_loopback(host: str) -> bool:
    return host.startswith("127.") or host in ("::1", "localhost")


def url_port(url: str) -> int:
    """The TCP port of an http(s) URL, with the scheme's default (80, 443) when the URL names none."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("not an http(s) URL with a host")
    return parts.port or (443 if parts.scheme == "https" else 80)


_CLOSED_RE = re.compile(r"(?i)connection refused|network is unreachable|host is unreachable|no route to host|timed out")


def classify_port_probe(exit_code: int | None, stderr: str) -> str:
    """What a ``timeout N bash -c 'echo > /dev/tcp/host/port'`` probe proves: ``open`` (it connected), ``closed`` (the
    connection was refused, the network is unreachable, or it timed out), ``tool-missing`` (exit 127: no bash or
    timeout), or ``unknown`` (anything else, for example a name that did not resolve): never proof of a closed port."""
    if exit_code == 0:
        return "open"
    if exit_code == 127:
        return "tool-missing"
    if exit_code == 124 or (exit_code is not None and _CLOSED_RE.search(stderr)):
        return "closed"
    return "unknown"


P2PC_PROCESSES = ("p2pc-server", "p2pc-agent")
P2PC_USERS = ("p2pc-server", "p2pc")  # the server's user and the agent's (deploy/linux/install-*.sh)
_USERS_RE = re.compile(r'users:\(\("([^"]*)"')
_UID_RE = re.compile(r"\buid:(\d+)")


@dataclass(frozen=True)
class Listener:
    """One listening socket of ``ss -H -l{t,u}npe``: its local address, and the owner when ``ss`` can tell."""

    local: str  # as ss prints it: 0.0.0.0:22, [::]:22, 127.0.0.53%lo:53
    host: str
    port: int
    process: str | None  # the name from `users:(("name",pid=...))`: only the processes the caller may see
    uid: int | None  # from `ss -e`

    def describe(self) -> str:
        who = self.process or (f"uid {self.uid}" if self.uid is not None else "unknown process")
        return f"{self.local} ({who})"


def parse_listeners(ss_output: str) -> list[Listener]:
    """The sockets in ``ss -H -ltnpe`` or ``-lunpe`` output (state, queues, local, peer, then the process and ``-e`` fields).
    A line that does not look like one is skipped."""
    out = []
    for line in ss_output.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        local = _split_local(cols[3])
        if local is None:
            continue
        proc = _USERS_RE.search(line)
        uid = _UID_RE.search(line)
        out.append(Listener(cols[3], local[0], local[1], proc.group(1) if proc else None, int(uid.group(1)) if uid else None))
    return out


def p2pc_listeners(
    listeners: Iterable[Listener], *, uids: Iterable[int] = (), names: Iterable[str] = P2PC_PROCESSES, any_process: bool = False
) -> list[Listener]:
    """The sockets that are P2PC's: the process is ``p2pc-server`` or ``p2pc-agent``, or its user is the server's or the
    agent's (``uids``, from ``ss -e``). Everything else on the machine (Docker, Tailscale, the owner's own services) is
    not P2PC's business.

    ``any_process``: for a WSL2 distro. The distros share one network namespace, so ``ss`` lists the sockets of all of
    them, but names only the processes it can see, which are this distro's: a socket with a process is the distro's."""
    names, uids = set(names), set(uids)
    if any_process:
        return [l for l in listeners if l.process is not None]
    return [l for l in listeners if l.process in names or (l.uid is not None and l.uid in uids)]


def exposed_listeners(listeners: Iterable[Listener], allowed_ports: Iterable[int]) -> list[str]:
    """The listeners that accept connections from outside the machine: any local address that is not loopback, on a port
    that is not allowed (the ssh port, for example). Give it TCP sockets: a UDP socket is not an open port to connect to."""
    allowed = set(allowed_ports)
    return [l.local for l in listeners if not _is_loopback(l.host) and l.port not in allowed]


# --------------------------------------------------------------------------------------------------------------
# AC-10: concurrency and the ledger
# --------------------------------------------------------------------------------------------------------------


def _per_node(value: int | dict[str, int] | None, node: str, default: int) -> int:
    if value is None:
        return default
    return value if isinstance(value, int) else value.get(node, default)


def analyze_concurrency(
    snapshots: Sequence[Sequence[tuple[str | None, str]]],
    *,
    limit: int | dict[str, int],
    reach: int | dict[str, int] | None = None,
    per_job_cpu: float | None = None,
    offered_cpu: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Each snapshot is the list of (node_id, status) of every job at one instant. A job in ``assigned`` or
    ``running`` holds a reservation.

    ``limit``: how many of the run's jobs a node may hold at once, ``floor(offered CPU / job CPU)`` per node (spec §8
    limits capacity, not a count), or one number for every node. More is double booking (``over_limit``), and so is
    more CPU than the node offers (``over_capacity_cpu``). ``reach``: how many each node must get to, or the test did
    not stress the scheduler (default: ``limit``); the nodes that did not are in ``not_reached`` with (peak, target)."""
    peak: dict[str, int] = {}
    nodes: set[str] = set(limit) if isinstance(limit, dict) else set()
    if isinstance(reach, dict):
        nodes |= set(reach)
    for snap in snapshots:
        counts = Counter(node for node, status in snap if node and status in ACTIVE_STATES)
        for node, n in counts.items():
            peak[node] = max(peak.get(node, 0), n)
    nodes |= set(peak)
    over_cpu: dict[str, float] = {}
    if per_job_cpu is not None and offered_cpu:
        for node, n in peak.items():
            if node in offered_cpu and n * per_job_cpu > offered_cpu[node] + 1e-9:
                over_cpu[node] = n * per_job_cpu
    over, short = {}, {}
    for node in sorted(nodes):
        lim = _per_node(limit, node, 10**9)
        target = _per_node(reach, node, lim) if reach is not None else lim
        p = peak.get(node, 0)
        if p > lim:
            over[node] = p
        if p < target:
            short[node] = (p, target)
    return {
        "peak_per_node": peak,
        "over_limit": over,
        "over_capacity_cpu": over_cpu,
        "reached_limit": sorted(n for n in nodes if n not in short),
        "not_reached": short,
    }


def final_problems(jobs: Sequence[dict], expected: int) -> list[str]:
    """What is wrong with the end state of a batch: a job missing, lost, failed, run twice."""
    problems = []
    if len(jobs) != expected:
        problems.append(f"{len(jobs)} jobs found, {expected} submitted")
    ids = [j.get("id") for j in jobs]
    if len(set(ids)) != len(ids):
        problems.append("a job id appears twice")
    bad = Counter(j.get("status") for j in jobs if j.get("status") != "succeeded")
    for status, n in sorted(bad.items(), key=lambda kv: str(kv[0])):
        problems.append(f"{n} job(s) ended as '{status}', not succeeded")
    twice = [j.get("id") for j in jobs if (j.get("attempt") or 1) > 1]
    if twice:
        problems.append(f"{len(twice)} job(s) needed a second attempt (a node was lost or double-booked)")
    return problems


def _usage_rows(data: Any) -> list[dict]:
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        data = data["items"]
    if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
        raise core.CheckFailed("p2pc usage --json is not an array of objects")
    return data


def usage_key(row: dict) -> str | None:
    for name in ("job_id", "group", "key", "id"):
        if isinstance(row.get(name), str):
            return row[name]
    return None


def reconcile_ledger(
    job_rows: Any,
    expected_job_ids: Iterable[str],
    node_rows: Any = None,
    key_rows: Any = None,
    key_id: str | None = None,
) -> list[str]:
    """The ledger totals of AC-10 (spec §11), for THIS run only. ``units`` are milli-units, ``reserved_cpu_ms``
    vCPU-milliseconds, so one vCPU-hour (3 600 000 vCPU-ms) is 1 000 milli-units: ``units == reserved_cpu_ms / 3600``
    for CPU-only work.

    The ledger belongs to the account, so it also holds jobs of earlier runs and of other keys: rows of jobs this run
    did not submit are ignored, not errors. Returns the problems: a job of the run without exactly one row, a row that
    does not match its reserved time, the run's key total (``key_rows`` row of ``key_id``) different from the per-job
    total, and node totals smaller than what the run's jobs account for (a node total may be larger: other jobs ran
    there too)."""
    problems = []
    expected = set(expected_job_ids)
    rows = [r for r in _usage_rows(job_rows) if usage_key(r) in expected]
    seen = Counter(usage_key(r) for r in rows)
    missing = sorted(expected - set(seen))
    if missing:
        problems.append(f"{len(missing)} job(s) have no ledger row (for example {missing[0]})")
    dup = sorted(k for k, n in seen.items() if n > 1 and k)
    if dup:
        problems.append(f"{len(dup)} job(s) have more than one ledger row (for example {dup[0]})")
    total = 0
    for r in rows:
        units = r.get("units")
        if not isinstance(units, int):
            problems.append(f"row {usage_key(r)} has no integer 'units'")
            continue
        total += units
        cpu_ms, gpu_ms = r.get("reserved_cpu_ms"), r.get("reserved_gpu_ms", 0) or 0
        if isinstance(cpu_ms, int) and not gpu_ms and abs(units - cpu_ms / 3600) > 1.0:
            problems.append(f"row {usage_key(r)}: {units} milli-units for {cpu_ms} vCPU-ms (expected about {cpu_ms / 3600:.0f})")
    if key_rows is not None:
        mine = [r for r in _usage_rows(key_rows) if key_id is None or usage_key(r) == key_id or r.get("key_id") == key_id]
        if key_id is not None and not mine:
            problems.append(f"the per-key view has no row for the run's key {key_id}")
        key_total = sum(r.get("units", 0) for r in mine if isinstance(r.get("units"), int))
        if mine and key_total != total:
            problems.append(f"the run key's total ({key_total}) differs from the per-job total ({total}) milli-units")
    if node_rows is not None:
        node_total = sum(r.get("units", 0) for r in _usage_rows(node_rows) if isinstance(r.get("units"), int))
        if node_total < total:
            problems.append(f"the per-node totals ({node_total}) are smaller than the run's per-job total ({total}) milli-units")
    return problems


# --------------------------------------------------------------------------------------------------------------
# AC-9: MCP over stdio (newline-delimited JSON-RPC)
# --------------------------------------------------------------------------------------------------------------

MCP_TOOLS = (
    "p2pc_estimate",
    "p2pc_run",
    "p2pc_status",
    "p2pc_logs",
    "p2pc_results",
    "p2pc_cancel",
    "p2pc_machines",
)
_JOB_ID_RE = re.compile(r"job_[0-9A-Za-z]+")


def mcp_request(id_: int | None, method: str, params: dict | None = None) -> str:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if id_ is not None:
        msg["id"] = id_
    if params is not None:
        msg["params"] = params
    return json.dumps(msg, separators=(",", ":"))


def mcp_session(calls: Sequence[tuple[int, str, dict]]) -> bytes:
    """The stdin of one MCP session: initialize, initialized, then each ``(id, tool, arguments)`` call, and tools/list."""
    lines = [
        mcp_request(1, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "p2pc-acceptance", "version": "0"}}),
        mcp_request(None, "notifications/initialized"),
        mcp_request(2, "tools/list", {}),
    ]
    for id_, tool, arguments in calls:
        lines.append(mcp_request(id_, "tools/call", {"name": tool, "arguments": arguments}))
    return ("\n".join(lines) + "\n").encode()


def parse_mcp_output(stdout: str) -> list[dict]:
    """Every JSON-RPC message the server printed. A line that is not JSON is a protocol error."""
    out = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            raise core.CheckFailed("the MCP server printed a line that is not JSON on stdout") from None
        out.append(msg)
    return out


def mcp_reply_problem(message: dict) -> str | None:
    """What is wrong with a JSON-RPC reply, or None: an ``error`` member, no ``result``, or a tool result with
    ``isError: true``. Any of the three means the call failed."""
    ident = message.get("id")
    error = message.get("error")
    if error is not None:
        code = error.get("code") if isinstance(error, dict) else None
        text = error.get("message") if isinstance(error, dict) else error
        return core.clean(f"JSON-RPC error {code} in the reply to {ident}: {text}")
    result = message.get("result")
    if result is None:
        return f"no result in the reply to {ident}"
    if isinstance(result, dict) and result.get("isError") is True:
        content = result.get("content")
        text = ""
        if isinstance(content, list) and content and isinstance(content[0], dict):
            text = str(content[0].get("text", ""))
        return core.clean(f"the tool call {ident} answered isError: true ({core.excerpt(text, 120)})")
    return None


ATTEMPT_OUTCOMES = ("running", "succeeded", "failed", "timed_out", "cancelled", "lost")  # spec §7: the job-state words
ATTEMPT_FIELDS = ("attempt", "node_id", "outcome", "reason", "started_at", "ended_at")


def attempt_shape_problems(attempts: Any) -> list[str]:
    """Spec §7: ``GET /v1/jobs/{id}`` returns ``attempts: [{attempt, node_id, outcome, reason, started_at, ended_at}]``,
    oldest first; ``outcome`` is ``running`` while the attempt runs (and only then ``ended_at`` is null); rejected offers
    are not listed; ``started_at`` is null until ``JobStarted``. The six fields must all be there; extra ones (``epoch``, say) are evidence, not a failure (see
    ``attempt_extra_fields``)."""
    if not isinstance(attempts, list) or not attempts or not all(isinstance(a, dict) for a in attempts):
        return ["the job's attempts are not a non-empty list of objects"]
    problems = []
    for i, a in enumerate(attempts):
        missing = sorted(set(ATTEMPT_FIELDS) - set(a))
        if missing:
            problems.append(f"attempts[{i}] lacks the field(s) the spec requires: {missing}")
            continue
        if not isinstance(a["attempt"], int) or isinstance(a["attempt"], bool) or a["attempt"] < 1:
            problems.append(f"attempts[{i}].attempt is not a positive integer")
        for key in ("node_id", "outcome"):
            if not isinstance(a[key], str) or not a[key]:
                problems.append(f"attempts[{i}].{key} is not a non-empty string")
        # `started_at` is null until JobStarted (spec §7, amended 2026-11-06): while the image is pulled, and for good if
        # the attempt never started.
        for key in ("reason", "started_at", "ended_at"):
            if a[key] is not None and (not isinstance(a[key], str) or not a[key]):
                problems.append(f"attempts[{i}].{key} is neither a non-empty string nor null")
        if isinstance(a["outcome"], str) and a["outcome"] not in ATTEMPT_OUTCOMES:
            problems.append(f"attempts[{i}].outcome '{a['outcome']}' is not one of {', '.join(ATTEMPT_OUTCOMES)}")
        running = a["outcome"] == "running"
        if running != (a["ended_at"] is None):
            problems.append(f"attempts[{i}]: outcome is '{a['outcome']}' but ended_at is {a['ended_at']!r} (null exactly while running)")
    numbers = [a.get("attempt") for a in attempts]
    if all(isinstance(n, int) for n in numbers) and numbers != sorted(numbers):
        problems.append(f"attempts are not oldest first: {numbers}")
    return problems


def attempt_extra_fields(attempts: Any) -> list[str]:
    """The fields of the attempts beyond the six of §7, for the evidence."""
    if not isinstance(attempts, list):
        return []
    return sorted({k for a in attempts if isinstance(a, dict) for k in a} - set(ATTEMPT_FIELDS))


def attempts_problems(attempts: Any, first_node: str, second_node: str) -> list[str]:
    """AC-6: the §7 ``attempts`` of the job (see ``attempt_shape_problems``). ``outcome`` uses the job-state words: an
    attempt replaced after node loss (fenced included) is ``lost``. Attempt 1 must have ended on the first node as
    ``lost``: if the partitioned node's late ``JobFinished`` had been accepted it would read ``succeeded`` or ``failed``.
    Attempt 2 must have ended on the other node as ``succeeded``, and there must be nothing else. ``exited`` and
    ``fenced`` are not outcomes."""
    problems = attempt_shape_problems(attempts)
    if problems:
        return problems
    if [a["attempt"] for a in attempts] != [1, 2]:
        return [f"expected exactly attempts 1 and 2, oldest first, got {[a['attempt'] for a in attempts]}"]
    first, second = attempts
    if first["node_id"] != first_node:
        problems.append("attempt 1 is not on the node that was cut")
    if first["outcome"] != "lost":
        problems.append(f"attempt 1 ended as '{first['outcome']}', not lost: a late report from the cut node may have been accepted")
    if second["node_id"] != second_node:
        problems.append("attempt 2 is not on the other node")
    if second["outcome"] != "succeeded":
        problems.append(f"attempt 2 ended as '{second['outcome']}', not succeeded")
    elif second["started_at"] is None:
        problems.append("attempt 2 succeeded but has no started_at: it can only succeed after JobStarted")
    return problems


def mcp_api_error(message: dict) -> dict | None:
    """The ``{"kind": "api", "status": ..}`` error a tool answered with, as p2pc's MCP server builds it: in the result's
    ``structuredContent`` (``{"error": {...}}``) and again, serialized, in the text. None for anything else."""
    result = message.get("result")
    if not isinstance(result, dict) or result.get("isError") is not True:
        return None
    candidates = [result.get("structuredContent")]
    for block in result.get("content") or []:
        if isinstance(block, dict) and isinstance(block.get("text"), str):
            try:
                candidates.append(json.loads(block["text"]))
            except ValueError:
                pass
    for doc in candidates:
        err = doc.get("error") if isinstance(doc, dict) else None
        if isinstance(err, dict) and err.get("kind") == "api":
            return err
    return None


def count_mcp_replies(stdout: str) -> int:
    """How many JSON-RPC replies (a message with an ``id`` and a ``result`` or an ``error``) are in the output so far.
    A half-written last line is not counted."""
    n = 0
    for line in stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if isinstance(msg, dict) and "method" not in msg and msg.get("id") is not None and ("result" in msg or "error" in msg):
            n += 1
    return n


def mcp_tool_names(messages: Sequence[dict]) -> list[str]:
    for m in messages:
        if m.get("id") == 2 and isinstance(m.get("result"), dict):
            return sorted(t.get("name", "") for t in m["result"].get("tools", []))
    return []


def mcp_job_ids(message: dict) -> list[str]:
    """The job id a tool answered with. ``p2pc_run`` and ``p2pc_cancel`` put it in ``structuredContent.job_id``
    (``job_summary`` in crates/p2pc-cli/src/mcp/tools.rs); only a reply without that member is searched for the pattern."""
    result = message.get("result")
    structured = result.get("structuredContent") if isinstance(result, dict) else None
    if isinstance(structured, dict) and isinstance(structured.get("job_id"), str) and _JOB_ID_RE.fullmatch(structured["job_id"]):
        return [structured["job_id"]]
    return _JOB_ID_RE.findall(json.dumps(result if result is not None else {}))


# --------------------------------------------------------------------------------------------------------------
# AC-4: the probe that runs INSIDE the job (stdlib Python, no pip)
# --------------------------------------------------------------------------------------------------------------

# Exit codes: 0 every destination behaved, 2 the allowed one did not work (the proxy is not usable), 3 a forbidden
# destination was not denied by the policy. The shim's proxy is at 127.0.0.1:3128 (spec §9). The proxy's answer to a
# CONNECT says who refused: 200 the tunnel opened (REACHED); 403 a policy refusal and 503 a closed gate (REFUSED); 502
# and 504 mean the policy ALLOWED it and the connection then failed, and no answer or garbage says nothing about the
# policy: both print POLICY-ALLOWED and fail, because a denial that is not the policy's proves nothing.
# P2PC_PROBE_DIRECT lists host:port that must not be reachable WITHOUT the proxy (SI-3): the default is the spec's own example.
EGRESS_PROBE = r"""
import os, socket, sys
proxy_host, _, proxy_port = os.environ.get("P2PC_PROBE_PROXY", "127.0.0.1:3128").rpartition(":")
allowed = sys.argv[1]
forbidden = sys.argv[2:]
direct = [d for d in os.environ.get("P2PC_PROBE_DIRECT", "1.1.1.1:443").split(",") if d]

def proxy_status(target):
    try:
        s = socket.create_connection((proxy_host, int(proxy_port)), timeout=15)
        s.settimeout(15)
        s.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (target, target)).encode())
        line = s.recv(256).split(b"\r\n", 1)[0].decode("latin-1", "replace")
        s.close()
        parts = line.split(" ")
        return parts[1] if line.startswith("HTTP/") and len(parts) > 1 and parts[1].isdigit() else "no-answer"
    except Exception:
        return "no-answer"

code = 0
status = proxy_status(allowed)
if status == "200":
    print("OK allowed " + allowed)
else:
    print("FAIL allowed destination did not work: %s (%s)" % (allowed, status))
    sys.exit(2)
for target in forbidden:
    status = proxy_status(target)
    if status == "200":
        print("REACHED forbidden " + target)
        code = 3
    elif status in ("403", "503"):
        print("REFUSED %s (%s)" % (target, status))
    else:
        print("POLICY-ALLOWED %s (%s)" % (target, status))
        code = 3
for target in direct:
    host, _, port = target.rpartition(":")
    try:
        socket.create_connection((host, int(port)), timeout=5).close()
        print("REACHED direct " + target)
        code = 3
    except Exception:
        print("NO-ROUTE direct " + target)
sys.exit(code)
"""
