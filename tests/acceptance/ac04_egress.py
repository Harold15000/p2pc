# SPDX-License-Identifier: Apache-2.0
"""AC-4: egress. `pip install requests` works with the PyPI allowlist; the LAN gateway, the host, `100.64.0.1` and any
other domain are refused. U5, SI-3, SI-4 and SI-5, on the real machine."""

from __future__ import annotations

import core
import flows

ID = "AC-4"
TITLE = "Egress allowlist and denied destinations"
SPEC = "Egress: `pip install requests` works with the PyPI allowlist. A connection to the LAN gateway, the host, `100.64.0.1` or another domain fails."
ROLES = ("server", "node_linux_gpu", "node_linux", "node_wsl2_gpu")
# What it needs, as keys of context.OWNERS: whether each has landed is read from the product (`--list`).
NEEDS: tuple[str, ...] = ("route GET /v1/nodes", "feature agent-connection", "feature scheduler", "feature executor")

ALLOW = "pypi.org,files.pythonhosted.org"
PULL_TIMEOUT_S = 900
# Not an allowlisted domain, not in any private range.
OTHER_DOMAIN = "example.com:443"
CGNAT = "100.64.0.1:80"


def run(ctx) -> core.Result:
    res = ctx.begin(ID, TITLE)
    roles = flows.enabled_node_roles(ctx)

    with res.check("environment ready") as c:
        if not roles:
            raise core.Skipped("no node role is enabled in the machines file")
        flows.ready_to_run(ctx, c, roles)

    for role in flows.NODE_ROLES:
        platform = flows.LABEL_OF[role]
        with res.check(f"{platform}: pip install requests through the PyPI allowlist") as c:
            c.needs("environment ready")
            if role not in roles:
                raise core.Skipped(f"role '{role}' is not enabled")
            node_id = flows.node_id_for(ctx, role, flows.list_nodes(ctx))
            job = flows.submit(
                ctx,
                ["--image", ctx.image("cpu"), "--cpu", "1", "--mem", "1G", "--node", node_id, "--egress", ALLOW,
                 "--timeout", "10m", "--name", f"acc4-pip-{platform}", "--",
                 "sh", "-c", "pip install --no-cache-dir --target /tmp/pkgs requests"],
            )
            job, _ = ctx.wait_job(flows.CLI_ROLE, job["id"], timeout_s=PULL_TIMEOUT_S, poll_s=3)
            c.require(job["status"] == "succeeded", f"pip install ended as {job['status']} exit {job.get('exit_code')} ({job.get('error')})")
            c.evidence["job_id"] = job["id"]

        with res.check(f"{platform}: the LAN gateway, the host, 100.64.0.1 and another domain are refused") as c:
            c.needs(f"{platform}: pip install requests through the PyPI allowlist")
            node = ctx.role(role)
            gateway, host = node.get("lan_gateway"), node.get("lan_host")
            if not gateway or not host:
                raise core.Skipped(f"set lan_gateway and lan_host for role '{role}' in the machines file")
            node_id = flows.node_id_for(ctx, role, flows.list_nodes(ctx))
            targets = [f"{gateway}:80", f"{host}:80", f"{host}:443", CGNAT, OTHER_DOMAIN]
            job = flows.submit(
                ctx,
                ["--image", ctx.image("cpu"), "--cpu", "1", "--mem", "512M", "--node", node_id, "--egress", ALLOW,
                 "--timeout", "5m", "--name", f"acc4-deny-{platform}", "--",
                 "python", "-c", flows.EGRESS_PROBE, "pypi.org:443", *targets],
            )
            job, _ = ctx.wait_job(flows.CLI_ROLE, job["id"], timeout_s=300, poll_s=2)
            code = job.get("exit_code")
            # The probe's exit code is the verdict: 0 all good, 2 the allowed domain failed, 3 something forbidden was not
            # denied by the policy: reached (200), or allowed and then failed to connect (502/504, no answer), or a direct connection.
            c.require(code != 3, "a forbidden destination was reachable or was not denied by the policy (REACHED, POLICY-ALLOWED "
                      "502/504/no answer, or a direct connection): see the probe's output in the job log")
            c.require(code != 2, "the allowed domain did not work through the proxy, so the denials prove nothing")
            c.require(job["status"] == "succeeded" and code == 0, f"the probe job ended as {job['status']} exit {code} ({job.get('error')})")
            c.evidence.update(job_id=job["id"], targets=len(targets))
    return res
