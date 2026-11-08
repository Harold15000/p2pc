# SPDX-License-Identifier: Apache-2.0
"""AC-6: kill a node's network mid-job. The job is retried on the other node, and the first node cannot report back
for the old attempt (U6, SI-8, SI-13).

The harness cannot know how to cut the network of YOUR node without cutting its own ssh connection, so the machines file
gives `partition_command` and `heal_command` for each node role. `heal_command` always runs at the end."""

from __future__ import annotations

import context
import core
import flows

ID = "AC-6"
TITLE = "Node loss: retry elsewhere, no stale report"
SPEC = "Kill the node's network mid-job. The job is retried on the other node, and the first node cannot report back for the old attempt."
ROLES = ("server", "node_linux_gpu", "node_linux", "node_wsl2_gpu")
# What it needs, as keys of context.OWNERS: whether each has landed is read from the product (`--list`).
NEEDS: tuple[str, ...] = ("route GET /v1/nodes", "feature agent-connection", "feature scheduler", "feature executor", "cli usage")

# The job must NOT end by itself while the harness watches the first node: otherwise "its container is gone" could be
# the job's own end (the containers are `--rm`) and not the agent stopping it. The window is: the server requeues within
# `lease_ttl_s` + DETECT_MARGIN_S of the cut, then the harness looks at the node; the rest is slack.
DETECT_MARGIN_S = 90  # the wait for attempt 2 after the cut, beyond lease_ttl_s
OBSERVE_S = 120  # how long the harness may take to look at the first node (and to heal) after that
SLACK_S = 60


def long_run_s(ttl: int) -> int:
    """How long attempt 1's job runs, from the server's ``lease_ttl_s`` (the ``lease_ttl_s`` param, which must equal the
    server's own): longer than anything the harness observes."""
    return int(ttl) + DETECT_MARGIN_S + OBSERVE_S + SLACK_S


def job_timeout_s(ttl: int) -> int:
    """The job's ``--timeout``: the run length plus 600 s, so the job never times out while the harness watches it. A
    fixed value broke as soon as ``lease_ttl_s`` was raised (it can be up to 3600). Spec §7 allows up to 86 400 s."""
    return long_run_s(ttl) + 600


def run(ctx) -> core.Result:
    res = ctx.begin(ID, TITLE)
    ttl = ctx.param("lease_ttl_s")
    long_run = long_run_s(ttl)
    st: dict = {}

    with res.check("two nodes and a way to cut one of them") as c:
        roles = flows.enabled_node_roles(ctx)
        if len(roles) < 2:
            raise core.Skipped("AC-6 needs two enabled nodes (two of node_linux_gpu, node_linux and node_wsl2_gpu): the job must have another node to go to")
        flows.ready_to_run(ctx, c, roles)
        usable = [r for r in roles if ctx.role(r).get("partition_command") and ctx.role(r).get("heal_command")]
        if not usable:
            raise core.Skipped("set partition_command and heal_command on a node role to say how its network is cut")
        st["roles"] = roles
        nodes = flows.list_nodes(ctx)
        st["ids"] = {r: flows.node_id_for(ctx, r, nodes) for r in roles}
        # Before the job exists: the P2PC containers already on each node, so that the job's own can be told apart.
        st["baseline"] = {r: flows.visible_containers(ctx, r, running_only=True) for r in roles}

    try:
        with res.check("submit a job that survives one node loss") as c:
            c.needs("two nodes and a way to cut one of them")
            job = flows.submit(
                ctx,
                ["--image", ctx.image("cpu"), "--cpu", "1", "--mem", "256M", "--retries", "1", "--timeout", f"{job_timeout_s(ttl)}s",
                 "--name", "acc6", "--", "sh", "-c", f"sleep {long_run}; echo done"],
            )
            st["job"] = job["id"]
            c.evidence.update(job_id=job["id"], job_runs_s=long_run, job_timeout_s=job_timeout_s(ttl), lease_ttl_s=ttl)

        with res.check("the job starts on a node") as c:
            c.needs("submit a job that survives one node loss")
            job, waited = ctx.wait_job(flows.CLI_ROLE, st["job"], timeout_s=300, poll_s=2, until={"running"})
            st["first_node"] = job.get("node_id")
            st["first_role"] = flows.role_of_node(ctx, st["first_node"], flows.list_nodes(ctx))
            c.require(st["first_role"], "the job runs on a machine that is none of the configured roles")
            c.require(job.get("attempt") == 1, f"expected attempt 1, got {job.get('attempt')}")
            # The proof that attempt 1's container is visible, taken while it runs: without it "its old attempt is
            # gone" after the heal would be vacuously true, and the network is not cut. Running containers only (SI-13: the
            # agent STOPS its job; a stopped one that is not removed yet is not a job still running).
            st["old_container"] = flows.new_container(ctx, st["first_role"], st["baseline"][st["first_role"]], running_only=True)
            c.evidence["old_container"] = st["old_container"]
            c.evidence.update(first_node=st["first_node"], first_role=st["first_role"])

        with res.check("cut the network of that node") as c:
            c.needs("the job starts on a node")
            role = ctx.role(st["first_role"])
            command = role.get("partition_command")
            if not command:
                raise core.Skipped(f"no partition_command for role '{st['first_role']}'")
            if not role.get("heal_command"):
                raise core.Skipped(f"role '{st['first_role']}' has no heal_command: not cutting a network that cannot be restored")
            # From here on the network may be (partly) cut, whatever the command reports: it may have timed out or
            # failed half way. So the heal is owed from the moment the command STARTS, not when it succeeds.
            st["partition_started"] = True
            step = ctx.exec(st["first_role"], ["sh", "-c", command], label="partition", timeout=60)
            c.require(step.ok, context.describe_failure(step))

        with res.check("the job is retried on the other node") as c:
            c.needs("cut the network of that node")

            def retried():
                job = ctx.json_of(ctx.p2pc(flows.CLI_ROLE, ["status", st["job"]], expect_ok=True, record=False), "status")
                return job if job.get("attempt") == 2 and job.get("status") in ("assigned", "running", "succeeded") else None

            job, waited = flows.wait_until(ctx, retried, timeout_s=ttl + DETECT_MARGIN_S, poll_s=3, what="attempt 2 to start")
            c.timing("detect_and_requeue_s", waited)
            c.require(job.get("node_id") and job["node_id"] != st["first_node"], "attempt 2 did not go to another node")
            st["second_node"] = job["node_id"]
            c.evidence["second_node"] = st["second_node"]
            # Looked at the moment attempt 2 is first seen, with the network still cut (the harness's own ssh works).
            st["visible_at_requeue"] = flows.visible_containers(ctx, st["first_role"], running_only=True)

        with res.check("the cut node stopped the old attempt before the requeue (SI-13)") as c:
            c.needs("the job is retried on the other node")
            still = st["old_container"] in st["visible_at_requeue"]
            c.evidence.update(old_container=st["old_container"], visible_at_requeue=st["visible_at_requeue"])
            c.require(
                not still,
                f"the old attempt's container {st['old_container']} was still on the first node when attempt 2 appeared: "
                f"a partitioned agent must stop its job before the server requeues it (agent_lease_ttl_s + 10 <= lease_ttl_s). "
                f"The job runs {long_run} s, so it did not end by itself",
            )
    finally:
        if st.get("partition_started"):
            with res.check("restore the network of the first node") as c:
                heal = ctx.role(st["first_role"]).get("heal_command")
                c.require(bool(heal), f"role '{st['first_role']}' has a partition_command but no heal_command")
                ctx.exec_ok(st["first_role"], ["sh", "-c", heal], label="heal", timeout=120)

    with res.check("the first node cannot report back: its old attempt stays gone after the heal") as c:
        c.needs("the cut node stopped the old attempt before the requeue (SI-13)")
        c.require(
            st["old_container"] not in flows.visible_containers(ctx, st["first_role"], running_only=True),
            f"the old attempt's container {st['old_container']} is back on the first node after the heal",
        )

    with res.check("the job finishes once, on the other node") as c:
        c.needs("the job is retried on the other node")
        job, waited = ctx.wait_job(flows.CLI_ROLE, st["job"], timeout_s=long_run + 300, poll_s=5)
        c.timing("finish_after_retry_s", waited)
        c.require(job["status"] == "succeeded", f"the job ended as {job['status']} ({job.get('error')})")
        c.require(job.get("attempt") == 2, f"the job finished as attempt {job.get('attempt')}, expected 2")
        c.require(job.get("node_id") == st["second_node"], "the result was reported by a node other than the attempt-2 node")

    with res.check("each attempt has its own log: only attempt 2 printed done") as c:
        c.needs("the job finishes once, on the other node")
        # `?attempt=K` (docs/cli.md: "a job whose machine was lost is retried as a new attempt, with its own log").
        second = ctx.p2pc(flows.CLI_ROLE, ["logs", st["job"], "--attempt", "2"], json=False, expect_ok=True)
        c.require("done" in second.stdout.split(), "the log of attempt 2 does not contain `done`")
        followed = ctx.p2pc(flows.CLI_ROLE, ["logs", st["job"], "--follow", "--attempt", "2"], json=False, expect_ok=True, timeout=120)
        c.require("done" in followed.stdout.split(), "`logs --follow --attempt 2` of a finished attempt does not show `done`")
        first = ctx.p2pc(flows.CLI_ROLE, ["logs", st["job"], "--attempt", "1"], json=False, expect_ok=True)
        c.require("done" not in first.stdout.split(), "the log of attempt 1 contains `done`: it was cut off before it could finish, or it is attempt 2's")
        none = ctx.p2pc(flows.CLI_ROLE, ["logs", st["job"], "--attempt", "3"])
        c.require(none.exit_code == 125 and (none.error_json() or {}).get("status") == 404, "an attempt that does not exist did not answer 404 (exit 125)")

    with res.check("attempt 1 ends lost and a late JobFinished is ignored") as c:
        c.needs("the job finishes once, on the other node")
        final = ctx.json_of(ctx.p2pc(flows.CLI_ROLE, ["status", st["job"]], expect_ok=True), "p2pc status")
        attempts = final.get("attempts")
        if not isinstance(attempts, list):
            if ctx.schema_has_property("Job", "attempts") is True:
                raise core.CheckFailed("the server's OpenAPI declares `attempts` on a job, but this job came without them")
            raise core.Blocked(
                "the server does not report per-attempt outcomes yet (no `attempts` in its Job schema): "
                "this check needs them to see that attempt 1 ended lost and that a late JobFinished was ignored",
                context.owner("feature scheduler"),
            )
        problems = flows.attempts_problems(attempts, st["first_node"], st["second_node"])
        c.require(not problems, "; ".join(problems))
        c.evidence["attempts"] = attempts
        c.evidence["extra_attempt_fields"] = flows.attempt_extra_fields(attempts)

    # `p2pc usage --by job` gives one TOTAL per job, not one row per attempt, so this proves only that the job
    # was charged at all (the per-attempt rows of the ledger are not exposed by the API).
    with res.check("the ledger has a row for the job") as c:
        c.needs("the job finishes once, on the other node")
        rows = ctx.json_of(ctx.p2pc(flows.CLI_ROLE, ["usage", "--by", "job"], expect_ok=True), "p2pc usage")
        mine = [r for r in (rows.get("items", rows) if isinstance(rows, dict) else rows) if flows.usage_key(r) == st["job"]]
        c.require(mine, "no ledger row for the job")
    return res
