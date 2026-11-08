# SPDX-License-Identifier: Apache-2.0
"""AC-3: a GPU job (`nvidia-smi`, and a PyTorch matmul on `cuda`) succeeds on both Linux and WSL2. U4."""

from __future__ import annotations

import core
import flows

ID = "AC-3"
TITLE = "GPU job on Linux and WSL2"
SPEC = "GPU job (`nvidia-smi`, and a PyTorch matmul on `cuda`) succeeds on both Linux and WSL2."
ROLES = ("server", "node_linux_gpu", "node_wsl2_gpu")  # the GPU nodes only
# What it needs, as keys of context.OWNERS: whether each has landed is read from the product (`--list`).
NEEDS: tuple[str, ...] = ("route GET /v1/nodes", "feature agent-connection", "feature scheduler", "feature executor", "cli logs", "route GET /v1/jobs/{id}/logs")

PULL_TIMEOUT_S = 1800

# Exits 0 only if CUDA is there and a matmul on the GPU gives a finite result. The exit code carries the verdict, so
# this part of the criterion does not wait for `p2pc logs`.
MATMUL = (
    "import sys, torch; "
    "ok = torch.cuda.is_available(); "
    "a = torch.randn(2048, 2048, device='cuda') if ok else None; "
    "b = (a @ a) if ok else None; "
    "torch.cuda.synchronize() if ok else None; "
    "fin = bool(ok and torch.isfinite(b).all().item()); "
    "print('cuda', ok, 'matmul-finite', fin, torch.cuda.get_device_name(0) if ok else '-'); "
    "sys.exit(0 if fin else 3)"
)


def run(ctx) -> core.Result:
    res = ctx.begin(ID, TITLE)
    roles = flows.enabled_node_roles(ctx)

    with res.check("environment ready") as c:
        if not roles:
            raise core.Skipped("no node role is enabled in the machines file")
        flows.ready_to_run(ctx, c, roles)

    for role in flows.GPU_ROLES:
        platform = flows.LABEL_OF[role]
        with res.check(f"{platform}: nvidia-smi succeeds") as c:
            c.needs("environment ready")
            if role not in roles:
                raise core.Skipped(f"role '{role}' is not enabled")
            node_id = flows.node_id_for(ctx, role, flows.list_nodes(ctx))
            job = flows.submit(
                ctx,
                ["--image", ctx.image("gpu_smi"), "--gpu", "1", "--cpu", "1", "--mem", "1G", "--node", node_id,
                 "--timeout", "10m", "--name", f"acc3-smi-{platform}", "--", "nvidia-smi"],
            )
            job, waited = ctx.wait_job(flows.CLI_ROLE, job["id"], timeout_s=PULL_TIMEOUT_S, poll_s=3)
            c.timing("job_s", waited)
            c.require(job["status"] == "succeeded", f"nvidia-smi ended as {job['status']} ({job.get('error')})")
            c.require(job.get("node_id") == node_id, "the job did not run on the requested machine")
            c.evidence["job_id"] = job["id"]
            ctx.state[f"acc3_smi_{role}"] = job["id"]

        with res.check(f"{platform}: nvidia-smi prints the GPU table in the logs") as c:
            c.needs(f"{platform}: nvidia-smi succeeds")
            step = ctx.p2pc(flows.CLI_ROLE, ["logs", ctx.state[f"acc3_smi_{role}"]], json=False, expect_ok=True)
            c.require("NVIDIA-SMI" in step.stdout, "the logs do not contain the nvidia-smi table")

        with res.check(f"{platform}: PyTorch matmul on cuda succeeds") as c:
            c.needs(f"{platform}: nvidia-smi succeeds")
            node_id = flows.node_id_for(ctx, role, flows.list_nodes(ctx))
            job = flows.submit(
                ctx,
                ["--image", ctx.image("gpu_torch"), "--gpu", "1", "--cpu", "2", "--mem", "4G", "--node", node_id,
                 "--timeout", "20m", "--name", f"acc3-torch-{platform}", "--", "python", "-c", MATMUL],
            )
            job, waited = ctx.wait_job(flows.CLI_ROLE, job["id"], timeout_s=PULL_TIMEOUT_S, poll_s=5)
            c.timing("job_s", waited)
            c.require(job["status"] == "succeeded" and job.get("exit_code") == 0,
                      f"the matmul job ended as {job['status']} exit {job.get('exit_code')} ({job.get('error')})")
            c.evidence["job_id"] = job["id"]
    return res
