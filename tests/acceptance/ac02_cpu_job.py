# SPDX-License-Identifier: Apache-2.0
"""AC-2: a CPU job round trip (`print(6*7)`): logs, exit 0, `succeeded`; submit to start in 5 s or less with the image cached.

U3, and the exit-code table of spec §7."""

from __future__ import annotations

import core
import flows

ID = "AC-2"
TITLE = "CPU job round trip"
SPEC = "CPU job round trip (`print(6*7)`): logs, exit 0, `succeeded`. Overhead from submit to start <= 5 s when the image is cached."
ROLES = ("server", "node_linux_gpu", "node_linux", "node_wsl2_gpu")
# What it needs, as keys of context.OWNERS: whether each has landed is read from the product (`--list`).
NEEDS: tuple[str, ...] = ("route GET /v1/nodes", "feature agent-connection", "feature scheduler", "feature executor", "cli logs", "route GET /v1/jobs/{id}/logs")

PULL_TIMEOUT_S = 900


def _flags(ctx):
    return ["--image", ctx.image("cpu"), "--cpu", "1", "--mem", "512M", "--timeout", "5m"]


def run(ctx) -> core.Result:
    res = ctx.begin(ID, TITLE)
    job_id = None

    with res.check("environment ready") as c:
        roles = flows.enabled_node_roles(ctx)
        if not roles:
            raise core.Skipped("no node role is enabled in the machines file")
        flows.ready_to_run(ctx, c, roles)

    with res.check("warm the image cache") as c:
        c.needs("environment ready")
        job = flows.submit(ctx, [*_flags(ctx), "--name", "acc2-warm", "--", "python", "-c", "print(6*7)"])
        job, waited = ctx.wait_job(flows.CLI_ROLE, job["id"], timeout_s=PULL_TIMEOUT_S, poll_s=2)
        c.timing("first_job_s", waited)
        c.require(job["status"] == "succeeded", f"the warm-up job ended as {job['status']} ({job.get('error')})")

    with res.check("round trip: exit 0 and succeeded") as c:
        c.needs("warm the image cache")
        step = ctx.p2pc(flows.CLI_ROLE, ["run", *_flags(ctx), "--name", "acc2", "--", "python", "-c", "print(6*7)"], timeout=300)
        c.require(step.exit_code == 0, f"p2pc run exited {step.exit_code}, not 0 (spec §7)")
        job = ctx.final_job(step)
        c.require(job.get("status") == "succeeded", f"the job ended as {job.get('status')}")
        c.require(job.get("exit_code") == 0, f"the job's exit_code is {job.get('exit_code')}")
        job_id = job["id"]
        c.evidence["job_id"] = job_id
        # `--json` followed the job live: its stdout line arrived as a log record (`{seq, stream, ts, data}`) before the job.
        live = [r for r in step.ndjson() if isinstance(r, dict) and "seq" in r and "stream" in r]
        c.require(any(r.get("stream") == "stdout" and "42" in str(r.get("data")).split() for r in live),
                  "the live log that p2pc run followed did not carry the job's 42")

    with res.check("overhead from submit to start is within the budget") as c:
        c.needs("round trip: exit 0 and succeeded")
        job = ctx.json_of(ctx.p2pc(flows.CLI_ROLE, ["status", job_id], expect_ok=True), "p2pc status")
        overhead = flows.seconds_between(job.get("created_at"), job.get("started_at"))
        c.timing("submit_to_start_s", overhead)
        budget = ctx.param("overhead_budget_s")
        c.require(overhead <= budget, f"submit to start took {overhead:.2f} s, over {budget} s")

    with res.check("the logs show 42") as c:
        c.needs("round trip: exit 0 and succeeded")
        step = ctx.p2pc(flows.CLI_ROLE, ["logs", job_id], json=False, expect_ok=True)  # a stub or a missing route is blocked by its owner
        c.require("42" in step.stdout.split(), "the job's logs do not contain 42")

    with res.check("logs --follow and --attempt show the same output and return 0 when the log ends") as c:
        c.needs("round trip: exit 0 and succeeded")
        # `logs` returns 0 whatever the job's outcome (docs/cli.md: the command worked), and `--follow` ends when the log does.
        for extra in (["--follow"], ["--attempt", "1"], ["--follow", "--attempt", "1"]):
            step = ctx.p2pc(flows.CLI_ROLE, ["logs", job_id, *extra], json=False, expect_ok=True, timeout=120)
            c.require("42" in step.stdout.split(), f"`p2pc logs {' '.join(extra)}` does not show 42")
        step = ctx.p2pc(flows.CLI_ROLE, ["logs", job_id, "--since-seq", "0"], expect_ok=True)
        records = [r for r in step.ndjson() if isinstance(r, dict)]
        c.require(records, "`p2pc logs --json` printed no record")
        for r in records:
            c.require(set(r) >= {"seq", "stream", "ts", "data"}, f"a log record lacks seq, stream, ts or data: {sorted(r)}")
        c.require(records[0]["seq"] == 0, f"the first record of the log has seq {records[0]['seq']}, not 0")

    with res.check("a failing job returns its own exit code") as c:
        c.needs("warm the image cache")
        step = ctx.p2pc(flows.CLI_ROLE, ["run", *_flags(ctx), "--", "sh", "-c", "exit 3"], timeout=300)
        c.require(step.exit_code == 3, f"p2pc run exited {step.exit_code}, expected the job's own 3 (spec §7)")
        job = ctx.final_job(step)
        c.require(job.get("status") == "failed" and job.get("exit_code") == 3, f"unexpected final job: {job.get('status')}/{job.get('exit_code')}")

    with res.check("a job p2pc refuses exits 125 and creates nothing") as c:
        c.needs("warm the image cache")  # the jobs API is there and a node runs jobs
        def newest():  # jobs are listed newest first
            return [j.get("id") for j in ctx.json_of(ctx.p2pc(flows.CLI_ROLE, ["jobs", "--limit", "1"], expect_ok=True), "p2pc jobs")]

        before = newest()
        # 1000 vCPUs is out of range (0.25-256): p2pc validates with the server's own rules and sends nothing.
        step = ctx.p2pc(flows.CLI_ROLE, ["run", "--image", ctx.image("cpu"), "--cpu", "1000", "--", "true"])
        c.require(step.exit_code == 125, f"p2pc run with --cpu 1000 exited {step.exit_code}, expected 125 (spec §7)")
        err = step.error_json() or {}
        c.require(err.get("kind") == "validation", f"expected a validation error, got {err.get('kind')} {err.get('code')}")
        c.require(newest() == before, "a refused job was created anyway")
    return res
