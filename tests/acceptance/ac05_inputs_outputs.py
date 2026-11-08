# SPDX-License-Identifier: Apache-2.0
"""AC-5: `/inputs` (inline, up to 512 KiB) and `/outputs` (up to 1 GiB) round trip with sha256 verification."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import core
import executors
import flows

ID = "AC-5"
TITLE = "Inputs and outputs round trip"
SPEC = "`/inputs` (inline, up to 512 KiB) and `/outputs` (up to 1 GiB) round trip with sha256 verification."
ROLES = ("server", "node_linux_gpu", "node_linux", "node_wsl2_gpu")
# What it needs, as keys of context.OWNERS: whether each has landed is read from the product (`--list`).
NEEDS: tuple[str, ...] = ("route GET /v1/nodes", "feature agent-connection", "feature scheduler", "feature executor", "cli results", "route GET /v1/jobs/{id}/outputs")

JOB_TIMEOUT_S = 1800


def run(ctx) -> core.Result:
    res = ctx.begin(ID, TITLE)
    work = ""  # set in "environment ready", once the role is known to be enabled and reachable
    size = ctx.param("input_kib") * 1024
    big_mb = ctx.param("big_output_mb")
    state: dict = {}

    with res.check("environment ready") as c:
        roles = flows.enabled_node_roles(ctx)
        if not roles:
            raise core.Skipped("no node role is enabled in the machines file")
        flows.ready_to_run(ctx, c, roles)
        work = ctx.workdir(flows.CLI_ROLE)
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "in.bin"
            local.write_bytes(os.urandom(size))
            state["input_sha256"] = executors.file_sha256(local)
            put = ctx.executor(flows.CLI_ROLE).put(local, f"{work}/in.bin", mode="644")
            c.require(put.returncode == 0, f"cannot copy the input file: {put.stderr.strip() or put.error}")
        c.evidence.update(input_bytes=size, input_sha256=state["input_sha256"])

    with res.check("the job reads the input and writes the outputs") as c:
        c.needs("environment ready")
        script = (
            "set -e; sha256sum /inputs/in.bin > /outputs/in.sha256; "
            f"dd if=/dev/urandom of=/outputs/big.bin bs=1M count={big_mb} 2>/dev/null; "
            "sha256sum /outputs/big.bin > /outputs/big.sha256"
        )
        job = flows.submit(
            ctx,
            ["--image", ctx.image("cpu"), "--cpu", "1", "--mem", "512M", "--disk", "4G", "--timeout", "30m",
             "--file", f"{work}/in.bin:/inputs/in.bin", "--name", "acc5", "--", "sh", "-c", script],
        )
        job, waited = ctx.wait_job(flows.CLI_ROLE, job["id"], timeout_s=JOB_TIMEOUT_S, poll_s=3)
        c.timing("job_s", waited)
        c.require(job["status"] == "succeeded", f"the job ended as {job['status']} exit {job.get('exit_code')} ({job.get('error')})")
        state["job_id"] = job["id"]
        c.evidence["job_id"] = job["id"]

    with res.check("results download with sha256 verification") as c:
        c.needs("the job reads the input and writes the outputs")
        out = f"{work}/results-{state['job_id']}"
        # `--json` prints {"job_id", "directory", "files": [{"path", "size", "sha256", "saved_to"}], "bytes"} (docs/cli.md).
        # The CLI itself verifies each file against the size and sha256 the job listed, in a temporary file, and exits 125
        # when one fails: a zero exit is the CLI's verification. The checks below are the harness's own.
        step = ctx.p2pc(flows.CLI_ROLE, ["results", state["job_id"], "--out", out], expect_ok=True, timeout=1200)
        report = ctx.json_of(step, "p2pc results")
        files = {f.get("path"): f for f in report.get("files", []) if isinstance(f, dict)} if isinstance(report, dict) else {}
        c.require(set(files) >= {"in.sha256", "big.bin", "big.sha256"}, f"p2pc results saved {sorted(files)}, expected in.sha256, big.bin and big.sha256")
        c.require(files["big.bin"].get("size") == big_mb * 1024 * 1024, f"big.bin is {files['big.bin'].get('size')} bytes, expected {big_mb} MiB")
        c.require(report.get("bytes") == sum(f.get("size", 0) for f in files.values()), "the report's byte total is not the sum of its files")
        state["out"] = out
        state["files"] = files

    with res.check("results refuses to overwrite without --force, and --force replaces") as c:
        c.needs("results download with sha256 verification")
        again = ctx.p2pc(flows.CLI_ROLE, ["results", state["job_id"], "--out", state["out"]])
        c.require(again.exit_code == 125, f"a second `p2pc results` into the same directory exited {again.exit_code}, expected 125 (nothing is overwritten without --force)")
        forced = ctx.p2pc(flows.CLI_ROLE, ["results", state["job_id"], "--out", state["out"], "--file", "in.sha256", "--force"], expect_ok=True, timeout=300)
        c.require(ctx.json_of(forced, "p2pc results --force").get("files", [{}])[0].get("path") == "in.sha256", "--file in.sha256 --force did not save in.sha256")

    with res.check("the input arrived intact (its sha256 as the job saw it)") as c:
        c.needs("results download with sha256 verification")
        step = ctx.exec_ok(flows.CLI_ROLE, ["cat", f"{state['out']}/in.sha256"], timeout=60)
        seen = step.stdout.split()[0] if step.stdout.split() else ""
        c.require(seen == state["input_sha256"], "the sha256 the job computed for /inputs/in.bin differs from the one sent")

    with res.check("the big output arrived intact (sha256 of the downloaded file)") as c:
        c.needs("results download with sha256 verification")
        claimed = ctx.exec_ok(flows.CLI_ROLE, ["cat", f"{state['out']}/big.sha256"], timeout=60).stdout.split()
        actual = ctx.exec_ok(flows.CLI_ROLE, ["sha256sum", f"{state['out']}/big.bin"], timeout=600).stdout.split()
        c.require(claimed and actual and claimed[0] == actual[0], "the downloaded big.bin does not match the sha256 the job computed")
        # The server's own list (GET /v1/jobs/{id}/outputs, a page: {"items": [{path, size, sha256}], "next_cursor"}).
        listing = ctx.json_of(
            ctx.rest_get(flows.CLI_ROLE, f"/v1/jobs/{state['job_id']}/outputs", route=("GET", "/v1/jobs/{id}/outputs"), expect_ok=True),
            "GET outputs",
        )
        items = listing.get("items", listing) if isinstance(listing, (dict, list)) else []
        by_path = {i.get("path", "").lstrip("/").split("/")[-1]: i.get("sha256") for i in items if isinstance(i, dict)}
        c.require(state["files"]["big.bin"].get("sha256") == actual[0], "the sha256 p2pc results printed for big.bin differs from the downloaded file's")
        c.require(by_path.get("big.bin") == actual[0], "the server's output list has another sha256 for big.bin")
        c.evidence.update(big_mb=big_mb, big_sha256=actual[0])
    return res
