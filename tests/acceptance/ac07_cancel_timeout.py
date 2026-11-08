# SPDX-License-Identifier: Apache-2.0
"""AC-7: cancel and timeout. The job stops within 15 seconds and the container is gone (spec §9: SIGTERM, 10 s grace, SIGKILL)."""

from __future__ import annotations

import re
import uuid

import context
import core
import flows

ID = "AC-7"
TITLE = "Cancel and timeout stop the job within 15 s"
SPEC = "Cancel and timeout: the job stops within 15 s and the container is gone."
ROLES = ("server", "node_linux_gpu", "node_linux", "node_wsl2_gpu")
# What it needs, as keys of context.OWNERS: whether each has landed is read from the product (`--list`).
NEEDS: tuple[str, ...] = (
    "route GET /v1/nodes", "feature agent-connection", "feature scheduler", "feature executor", "feature run-closed-stdout",
)

BUDGET_S = 15
TIMEOUT_JOB_S = 20
# `p2pc run` writes the job's stdout to its own stdout. Its reader here, `head -n 1`, goes away after the first line; the
# job then keeps writing every 2 s, so a write into the closed pipe (spec §7: exit 130, `run` detached, the job keeps
# running) always comes within seconds, even if `run` batched the first lines. The exit code of `p2pc run` is written
# to a file because a pipeline reports its last command's.
CLOSED_STDOUT_SCRIPT = (
    '{ "$0" run --image "$3" --cpu 1 --mem 256M --timeout 30m --name acc7-closed-stdout -- '
    "sh -c 'echo first; while :; do sleep 2; echo tick; done' 2>\"$1\"; echo \"$?\" >\"$2\"; } | head -n 1"
)


def _stopped_and_gone(ctx, job_id: str, role: str, container: str, since: float) -> float:
    """Seconds from ``since`` until the job is terminal AND ITS OWN container (seen running before) is gone."""
    def done():
        job = ctx.json_of(ctx.p2pc(flows.CLI_ROLE, ["status", job_id], expect_ok=True, record=False), "status")
        stopped = job["status"] not in ("queued", "assigned", "running")
        return job if stopped and container not in flows.visible_containers(ctx, role) else None

    flows.wait_until(ctx, done, timeout_s=BUDGET_S + 10, poll_s=0.5, what=f"the job to stop and container {container} to be removed")
    return ctx.clock() - since


def run(ctx) -> core.Result:
    res = ctx.begin(ID, TITLE)
    st: dict = {}

    with res.check("environment ready") as c:
        roles = flows.enabled_node_roles(ctx)
        if not roles:
            raise core.Skipped("no node role is enabled in the machines file")
        flows.ready_to_run(ctx, c, roles)
        st["roles"] = roles

    def baselines():
        # Before the job exists: what P2PC containers are already there, so that the job's own can be told apart.
        return {r: flows.visible_containers(ctx, r) for r in st["roles"]}

    with res.check("cancel: a running job stops within 15 s and its container is gone") as c:
        c.needs("environment ready")
        before = baselines()
        job = flows.submit(
            ctx, ["--image", ctx.image("cpu"), "--cpu", "1", "--mem", "256M", "--timeout", "30m", "--name", "acc7-cancel",
                  "--", "sleep", "600"])
        job, _ = ctx.wait_job(flows.CLI_ROLE, job["id"], timeout_s=900, poll_s=2, until={"running"})
        role = flows.role_of_node(ctx, job["node_id"], flows.list_nodes(ctx))
        c.require(role, "the job runs on a machine that is none of the configured roles")
        container = flows.new_container(ctx, role, before[role])  # proof that THIS job's container is visible
        c.evidence["container"] = container
        t0 = ctx.clock()
        ctx.p2pc(flows.CLI_ROLE, ["cancel", job["id"]], expect_ok=True)
        elapsed = _stopped_and_gone(ctx, job["id"], role, container, t0)
        c.timing("cancel_to_gone_s", elapsed)
        c.require(elapsed <= BUDGET_S, f"cancel took {elapsed:.1f} s, over {BUDGET_S} s")
        final = ctx.json_of(ctx.p2pc(flows.CLI_ROLE, ["status", job["id"]], expect_ok=True), "status")
        c.require(final["status"] == "cancelled", f"the job is '{final['status']}', not cancelled")
        c.evidence["job_id"] = job["id"]

    with res.check("timeout: the job ends as timed_out within 15 s of its limit and its container is gone") as c:
        c.needs("environment ready")
        before = baselines()
        job = flows.submit(
            ctx, ["--image", ctx.image("cpu"), "--cpu", "1", "--mem", "256M", "--timeout", f"{TIMEOUT_JOB_S}s",
                  "--name", "acc7-timeout", "--", "sleep", "600"])
        job, _ = ctx.wait_job(flows.CLI_ROLE, job["id"], timeout_s=900, poll_s=2, until={"running"})
        role = flows.role_of_node(ctx, job["node_id"], flows.list_nodes(ctx))
        c.require(role, "the job runs on a machine that is none of the configured roles")
        container = flows.new_container(ctx, role, before[role])
        c.evidence["container"] = container
        job, _ = ctx.wait_job(flows.CLI_ROLE, job["id"], timeout_s=TIMEOUT_JOB_S + BUDGET_S + 60, poll_s=2)
        c.require(job["status"] == "timed_out", f"the job ended as {job['status']}")
        ran = flows.seconds_between(job.get("started_at"), job.get("finished_at"))
        c.timing("ran_for_s", ran)
        c.require(ran <= TIMEOUT_JOB_S + BUDGET_S, f"the job ran {ran:.1f} s, over its {TIMEOUT_JOB_S} s limit plus {BUDGET_S} s")
        flows.wait_until(ctx, lambda: container not in flows.visible_containers(ctx, role), timeout_s=BUDGET_S, poll_s=1,
                         what=f"container {container} to be removed after the timeout")
        c.evidence["job_id"] = job["id"]

    with res.check("timeout: p2pc run exits with 124") as c:
        c.needs("environment ready")
        step = ctx.p2pc(
            flows.CLI_ROLE,
            ["run", "--image", ctx.image("cpu"), "--cpu", "1", "--mem", "256M", "--timeout", f"{TIMEOUT_JOB_S}s",
             "--name", "acc7-exit124", "--", "sleep", "600"],
            timeout=TIMEOUT_JOB_S + 300,
        )
        c.require(step.exit_code == 124, f"p2pc run exited {step.exit_code}, expected 124 (spec §7)")
        c.require(ctx.final_job(step).get("status") == "timed_out", "the job did not end as timed_out")
    with res.check("cancel: `p2pc run` of a cancelled job exits 130") as c:
        c.needs("environment ready")
        # No concurrency needed: the same job and the same idempotency key return the job that exists (docs/cli.md,
        # "Retries"), and `run` follows it to its end. A cancelled job ends `run` with 130 (spec §7).
        args = ["--image", ctx.image("cpu"), "--cpu", "1", "--mem", "256M", "--timeout", "30m", "--name", "acc7-run-130",
                "--idempotency-key", f"acc7-{uuid.uuid4().hex[:12]}", "--", "sleep", "600"]
        job = flows.submit(ctx, args)
        job, _ = ctx.wait_job(flows.CLI_ROLE, job["id"], timeout_s=900, poll_s=2, until={"running"})
        ctx.p2pc(flows.CLI_ROLE, ["cancel", job["id"]], expect_ok=True)
        job, _ = ctx.wait_job(flows.CLI_ROLE, job["id"], timeout_s=BUDGET_S + 10, poll_s=1)
        c.require(job["status"] == "cancelled", f"the job is '{job['status']}', not cancelled")
        step = ctx.p2pc(flows.CLI_ROLE, ["run", *args], timeout=120)
        c.require(step.exit_code == 130, f"p2pc run of a cancelled job exited {step.exit_code}, expected 130 (spec §7)")
        final = ctx.final_job(step)
        c.require(final["id"] == job["id"], "the same idempotency key did not return the same job")
        c.require(final["status"] == "cancelled", f"`p2pc run --json` ended with status {final['status']}")
        c.evidence["job_id"] = job["id"]

    with res.check("run detaches with 130 when its stdout closes while the job runs, and the job keeps running") as c:
        # After the check above, so that a server without the jobs route is `blocked` once, there, with its owner: this
        # one runs `p2pc run` through a shell pipeline, which `ctx.p2pc` cannot wrap.
        c.needs("cancel: `p2pc run` of a cancelled job exits 130")
        work = ctx.workdir(flows.CLI_ROLE)
        stderr_file, exit_file = f"{work}/acc7-closed.err", f"{work}/acc7-closed.exit"
        job_id = None
        try:
            ctx.exec(
                flows.CLI_ROLE,
                ["sh", "-c", CLOSED_STDOUT_SCRIPT, ctx.bin(flows.CLI_ROLE, "p2pc"), stderr_file, exit_file, ctx.image("cpu")],
                env={"P2PC_CONFIG_DIR": f"{work}/p2pc-config", "P2PC_SERVER": ctx.server_url()},
                secret_env={"P2PC_API_KEY": ctx.admin_key()},
                label="p2pc run | head -n 1",
                timeout=900,
            )
            code = ctx.exec(flows.CLI_ROLE, ["cat", exit_file], timeout=30).stdout.strip()
            err = ctx.exec(flows.CLI_ROLE, ["cat", stderr_file], timeout=30).stdout
            found = re.search(r"job_[0-9A-Za-z]+", err)
            job_id = found.group(0) if found else None
            c.require(job_id, "p2pc run printed no job id on stderr")
            if code == "0" and "detached" not in err and ctx.feature_landed("run-closed-stdout") is False:
                # What the code does before that rule lands: a write into the closed pipe ends `run` quietly with 0, no hint. The rule is in
                # the spec (§7, amended 2026-11-06) and not in this checkout's code or docs yet: not a failure of what exists.
                raise core.Blocked(
                    "`p2pc run` exited 0 with no detach hint after its stdout closed: the detach on a closed stdout (spec §7) "
                    "is not in this checkout yet (docs/cli.md does not mention it)",
                    context.owner("feature run-closed-stdout"),
                )
            c.require(code == "130", f"p2pc run exited {code or 'with no code'} after its stdout closed, expected 130 (spec §7, amended 2026-11-06)")
            c.require("detached" in err and f"p2pc cancel {job_id}" in err, "p2pc run did not say how to follow or stop the job it detached from")
            job = ctx.json_of(ctx.p2pc(flows.CLI_ROLE, ["status", job_id], expect_ok=True), "p2pc status")
            c.require(job["status"] in ("queued", "assigned", "running"), f"the job is '{job['status']}': detaching must not stop it")
            c.evidence["job_id"] = job_id
        finally:
            if job_id:
                ctx.p2pc(flows.CLI_ROLE, ["cancel", job_id], record=False)
            ctx.exec(flows.CLI_ROLE, ["rm", "-f", stderr_file, exit_file], record=False, timeout=30)
    return res
