# SPDX-License-Identifier: Apache-2.0
"""AC-10: run 100 jobs with 4 concurrent per node. No double booking, no lost jobs, and the ledger totals match (spec §8, §11).

The driver submits `job_count` jobs sized so that `jobs_per_node` fit on a node, samples the job list while they run,
and checks the end state. The analysis lives in `flows.py` (pure functions, unit-tested).

Why the jobs last long: the scheduler's choice is BEST FIT (spec §8, "Choice"): the least free capacity left after
placement. It fills the smallest node first, then the next one, and only then a big node. So a short job that ends
before the queue backs up is placed again on the same small nodes, and the big node never fills (ACC-1 round 5: 71 jobs
on one node, none on another). Only a backed-up queue reaches every node. `plan_load` therefore makes each job last
longer than it takes to submit one job for every slot of every node, and keeps `job_count` above the sum of the limits."""

from __future__ import annotations

import math
import uuid

import core
import flows

ID = "AC-10"
TITLE = "100 jobs, 4 per node: no double booking, ledger matches"
SPEC = "Run 100 jobs, with 4 concurrent per node. No double booking, no lost jobs, and the ledger totals match."
ROLES = ("server", "node_linux_gpu", "node_linux", "node_wsl2_gpu")
# What it needs, as keys of context.OWNERS: whether each has landed is read from the product (`--list`).
NEEDS: tuple[str, ...] = ("route GET /v1/nodes", "feature agent-connection", "feature scheduler", "feature executor", "cli usage")

MIN_JOB_SLEEP_S = 30
SUBMIT_BUDGET_S = 2  # per job: a CLI call, with room (a slow link) so the first jobs outlast the submission of the slots
SAMPLE_EVERY_S = 1.0


def plan_load(limits: dict[str, int], configured_count: int) -> tuple[int, int, int]:
    """(sleep seconds of each job, job count, deadline seconds) so that the queue backs up and every node fills.

    The slots are the sum of the nodes' limits. The first job must still run when the last slot is taken, so a job lasts
    at least `MIN_JOB_SLEEP_S` and `SUBMIT_BUDGET_S` per slot. The count is the configured one, but always above the
    slots (twice as many at least, so there is a second wave)."""
    slots = sum(limits.values())
    sleep_s = max(MIN_JOB_SLEEP_S, SUBMIT_BUDGET_S * slots)
    count = max(configured_count, 2 * slots)
    waves = -(-count // max(1, slots))  # ceil
    deadline_s = (waves + 1) * (sleep_s + 15) + count * SUBMIT_BUDGET_S + 900
    return sleep_s, count, deadline_s


NON_TERMINAL = ("assigned", "running", "queued")


def _list_jobs(ctx, prefix: str, *flags: str) -> list[dict]:
    step = ctx.p2pc(flows.CLI_ROLE, ["jobs", *flags, "--all"], expect_ok=True, record=False, timeout=300)
    jobs = ctx.json_of(step, "p2pc jobs")
    if not isinstance(jobs, list):
        raise core.CheckFailed("p2pc jobs --all --json is not an array")
    # The API filters by status and node only (spec §7): it has no name filter, so the name prefix cuts what the server
    # already narrowed by state. Other jobs of the account (earlier runs) are never counted.
    return [j for j in jobs if str(j.get("name", "")).startswith(prefix)]


def _snapshot(ctx, prefix: str) -> dict[str, dict]:
    """The jobs of this run that are not finished, one server-side query per state (`--status`), so a poll costs a few
    small answers however many jobs have already finished. A job can move between two queries: it is kept once, by its
    latest state, so it can never be counted on two nodes (or twice) in one snapshot."""
    seen: dict[str, dict] = {}
    for state in NON_TERMINAL:
        for job in _list_jobs(ctx, prefix, "--status", state):
            seen[job["id"]] = job
    return seen


def run(ctx) -> core.Result:
    res = ctx.begin(ID, TITLE)
    st: dict = {"snapshots": []}
    try:
        _checks(ctx, res, st)
    finally:
        if st.get("key_id"):  # the run's own key never outlives the run, whatever happened
            ctx.p2pc(flows.CLI_ROLE, ["keys", "revoke", st["key_id"]], timeout=60)
    return res


def _checks(ctx, res: core.Result, st: dict) -> None:
    configured, per_node = ctx.param("job_count"), ctx.param("jobs_per_node")
    count = configured  # raised below, once the limits of the nodes are known
    run_tag = uuid.uuid4().hex[:8]
    prefix = f"acc10-{run_tag}-"

    with res.check("environment ready: every enabled node is online") as c:
        roles = flows.enabled_node_roles(ctx)
        if not roles:
            raise core.Skipped("no node role is enabled in the machines file")
        flows.ready_to_run(ctx, c, roles)
        nodes = flows.list_nodes(ctx)
        st["ids"] = [flows.node_id_for(ctx, r, nodes) for r in roles]
        by_id = {n["id"]: n for n in nodes}
        c.require(all(by_id[i].get("state") == "online" for i in st["ids"]), "a node is not online")
        # What a node OFFERS (inventory.offered, spec §6, §8), not what is free right now: something already running on
        # it must not shrink the jobs of the test, nor hide that the node is busy.
        def offered(i: str, field: str) -> float:
            return float(((by_id[i].get("inventory") or {}).get("offered") or {}).get(field, 0))

        def free(i: str, field: str) -> float:
            return float((by_id[i].get("free") or {}).get(field, offered(i, field)))

        st["offered_cpu"] = {i: offered(i, "cpu") for i in st["ids"]}
        smallest = min(st["offered_cpu"].values())
        # Each job asks for 1/per_node of the smallest node, so `per_node` of them fit on it.
        st["cpu"] = math.floor(smallest / per_node * 1000) / 1000
        c.require(st["cpu"] >= 0.25, f"a node offers too little CPU ({smallest}) for {per_node} jobs of at least 0.25 vCPU")
        st["mem"] = max(128, min(512, int(min(offered(i, "memory_mb") for i in st["ids"])) // per_node))
        # Spec §8 limits capacity, not a count: a node bigger than the smallest holds more than `per_node` of these
        # jobs, and a smaller one fewer. The limit of each node is what its offered capacity allows.
        st["limits"] = {
            i: min(
                math.floor(offered(i, "cpu") / st["cpu"] + 1e-9),
                math.floor(offered(i, "memory_mb") / st["mem"] + 1e-9) if offered(i, "memory_mb") else 10**9,
            )
            for i in st["ids"]
        }
        # What each node must REACH, or the test did not stress the scheduler: min(per_node, limit); for a node that is
        # already busy, the part of the limit that is still free.
        st["reach"] = {
            i: min(per_node, st["limits"][i], math.floor(free(i, "cpu") / st["cpu"] + 1e-9)) for i in st["ids"]
        }
        busy = {i: round(offered(i, "cpu") - free(i, "cpu"), 3) for i in st["ids"] if free(i, "cpu") < offered(i, "cpu")}
        if not all(t >= 1 for t in st["reach"].values()):
            # The environment's, not the product's: the test needs idle nodes.
            raise core.Skipped(f"a node has no free capacity for even one job (it is busy): {st['reach']}")
        st["sleep_s"], count, st["deadline_s"] = plan_load(st["limits"], configured)
        slots = sum(st["limits"].values())
        c.evidence.update(
            job_sleep_s=st["sleep_s"], slots=slots, queue_backs_up=count > slots, configured_job_count=configured,
            jobs=count, per_node=per_node, cpu_per_job=st["cpu"], mem_mb_per_job=st["mem"], nodes=len(st["ids"]),
            limits=st["limits"], reach=st["reach"], busy_cpu_at_start=busy,
        )

    with res.check("a dedicated key for this run") as c:
        c.needs("environment ready: every enabled node is online")
        # The ledger is the account's, not the run's. Every job of the run is submitted with this key, so the per-key
        # total of the ledger is the run's own, whatever else was run on the server before.
        made = ctx.json_of(
            ctx.p2pc(flows.CLI_ROLE, ["keys", "create", "--label", f"acceptance-ac10-{run_tag}", "--expires", "1d",
                                      *[x for sc in flows.scopes_needed(cli=["run"]) for x in ("--scope", sc)]],
                     expect_ok=True),
            "p2pc keys create",
        )
        key = made.get("key")
        c.require(isinstance(key, str) and key.startswith("p2pc_sk_") and made.get("id"), "keys create returned no key")
        ctx.redactor.add_secret(key)
        st["key"], st["key_id"] = key, made["id"]
        c.evidence["key_id"] = made["id"]

    with res.check(f"submit {count} jobs") as c:
        c.needs("a dedicated key for this run")
        t0 = ctx.clock()
        for i in range(count):
            step = ctx.p2pc(
                flows.CLI_ROLE,
                ["run", "--detach", "--image", ctx.image("cpu"), "--cpu", str(st["cpu"]), "--mem", f"{st['mem']}M",
                 "--timeout", "10m", "--name", f"{prefix}{i}", "--idempotency-key", f"{prefix}{i}",
                 "--", "sh", "-c", f"echo job-{i}; sleep {st['sleep_s']}"],
                key=st["key"], record=(i == 0), timeout=120,
            )
            c.require(step.ok, f"job {i} was refused: {core.tail(step.stderr, 200)}")
        c.timing("submit_all_s", ctx.clock() - t0)

    with res.check("run to completion, sampling who runs where") as c:
        c.needs(f"submit {count} jobs")
        start = ctx.clock()
        deadline = st["deadline_s"]

        poll_s: list[float] = []  # how long each poll took: a slow poll samples a blurrier picture

        def finished():
            t0 = ctx.clock()
            active = _snapshot(ctx, prefix)
            poll_s.append(ctx.clock() - t0)
            st["snapshots"].append([(j.get("node_id"), j.get("status")) for j in active.values()])
            return not active  # everything was submitted before the first poll: nothing active means all are done

        _, waited = flows.wait_until(ctx, finished, timeout_s=deadline, poll_s=SAMPLE_EVERY_S, what=f"all {count} jobs to finish")
        c.timing("run_all_s", waited)
        c.timing("poll_max_s", max(poll_s))
        c.timing("poll_mean_s", sum(poll_s) / len(poll_s))
        c.evidence.update(snapshots=len(st["snapshots"]), poll_durations_s=[round(p, 3) for p in poll_s])
        st["jobs"] = _list_jobs(ctx, prefix)  # the end state, once

    with res.check("no double booking: never over a node's own limit, never more CPU than offered") as c:
        c.needs("run to completion, sampling who runs where")
        report = flows.analyze_concurrency(
            st["snapshots"], limit=st["limits"], reach=st["reach"], per_job_cpu=st["cpu"], offered_cpu=st["offered_cpu"]
        )
        c.evidence.update(report)
        c.require(not report["over_limit"], f"a node ran more jobs at once than its offered capacity allows: {report['over_limit']} (limits {st['limits']})")
        c.require(not report["over_capacity_cpu"], f"a node was given more CPU than it offers: {report['over_capacity_cpu']}")
        c.require(not report["not_reached"],
                  f"a node did not reach its share ((peak, needed) per node: {report['not_reached']}), so the test did not stress the scheduler")

    with res.check("no lost jobs: all succeeded, each exactly once") as c:
        c.needs("run to completion, sampling who runs where")
        problems = flows.final_problems(st["jobs"], count)
        c.require(not problems, "; ".join(problems))

    with res.check("the ledger totals match (this run's jobs and key only)") as c:
        c.needs("no lost jobs: all succeeded, each exactly once")
        # Only what happened since this run's first job was created (spec §7: GET /v1/usage ?from&to), and only this
        # run's jobs and key: an earlier run, or anything else on the server, is in the ledger too.
        since = min(j["created_at"] for j in st["jobs"] if j.get("created_at"))
        c.evidence["from"] = since

        def usage(group: str):
            # `--by`, not `--group-by` (docs/cli.md). `--to` is explicit too: by default the CLI stops at the end of
            # the current UTC day, and a run that crosses midnight would lose its last jobs from the ledger.
            step = ctx.p2pc(
                flows.CLI_ROLE,
                ["usage", "--by", group, "--from", since, "--to", flows.usage_upper_bound(st["jobs"])],
                expect_ok=True,
            )
            return ctx.json_of(step, f"p2pc usage --by {group}")

        by_job = usage("job")
        problems = flows.reconcile_ledger(
            by_job, [j["id"] for j in st["jobs"]], usage("node"), usage("key"), key_id=st["key_id"]
        )
        c.require(not problems, "; ".join(problems))
