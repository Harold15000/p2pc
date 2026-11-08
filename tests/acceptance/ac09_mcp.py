# SPDX-License-Identifier: Apache-2.0
"""AC-9: the MCP server works from Claude Code with a capped key. The cap and the image allowlist are enforced (U7).

The harness drives `p2pc mcp` over stdio with raw JSON-RPC, as a client would. The last step, using it from Claude Code
itself, is manual: point `[manual] claude_code_session` at your notes."""

from __future__ import annotations

import uuid

import context
import core
import executors
import flows

ID = "AC-9"
TITLE = "MCP server with a capped key"
SPEC = "The MCP server works from Claude Code with a capped key. The cap and the image allowlist are enforced."
ROLES = ("server", "node_linux_gpu", "node_linux", "node_wsl2_gpu")
# What it needs, as keys of context.OWNERS: whether each has landed is read from the product (`--list`).
NEEDS: tuple[str, ...] = ("route GET /v1/nodes",)

# The JSON-RPC ids of the tool calls in the session below, and the CLI subcommand each tool is the twin of: the REST
# route behind a tool is the route behind that subcommand (context.CLI_ROUTES), and the owner comes from context.OWNERS.
TOOL_OF_ID = {3: "p2pc_estimate", 4: "p2pc_run", 5: "p2pc_machines", 6: "p2pc_run"}
SUB_OF_TOOL = {"p2pc_estimate": "estimate", "p2pc_run": "run", "p2pc_machines": "machines"}
# What the capped key is used for, so that it gets exactly the scopes that needs (flows.scopes_needed).
SESSION_TOOLS = ("p2pc_estimate", "p2pc_run", "p2pc_machines")
KEY_CLI_CALLS = ("whoami", "run")  # `p2pc whoami`, and `p2pc run --detach` for the cap and the allowlist
EXPECTED_REPLIES = 6  # initialize, tools/list, estimate, run (id 4), machines, run again (id 6, the retry)
# `wait_s` of both p2pc_run calls. The session only checks that the retry (a new request id, the same idempotency_key) returns the same job, so neither
# call waits for it: a job that cannot start (a node stopped by a registry's pull limit, ACC-1) must not use up the session
# and hide the answer to the second call.
RUN_WAIT_S = 0
# How long stdin of `p2pc mcp` is held open for the replies (90 s plus the waits of both runs, in case a wait is ever set),
# and how long the whole call may take: that, the time `p2pc mcp` gets to exit once stdin is closed, and a margin.
REPLY_DEADLINE_S = 90 + 2 * RUN_WAIT_S
SESSION_TIMEOUT_S = REPLY_DEADLINE_S + int(executors.HOLD_EXIT_GRACE_S) + 60
CAP_UNITS = "1"
ALLOWED_PATTERN = "docker.io/library/python:*"


def _scope_flags(scopes: list[str]) -> list[str]:
    return [x for scope in scopes for x in ("--scope", scope)]


def _create_key(ctx, c, label: str, *flags: str) -> dict:
    step = ctx.p2pc(flows.CLI_ROLE, ["keys", "create", "--label", label, *flags], expect_ok=True)
    made = ctx.json_of(step, "p2pc keys create")
    key = made.get("key")
    c.require(isinstance(key, str) and key.startswith("p2pc_sk_"), "keys create returned no key")
    ctx.redactor.add_secret(key)
    made["key"] = key
    return made


def run(ctx) -> core.Result:
    res = ctx.begin(ID, TITLE)
    created: list[str] = []
    st: dict = {}

    try:
        with res.check("create a capped key with an image allowlist") as c:
            flows.ready(ctx, c)
            made = _create_key(
                ctx, c, "acceptance-mcp", *_scope_flags(flows.scopes_needed(cli=KEY_CLI_CALLS, mcp=SESSION_TOOLS)),
                "--cap", CAP_UNITS, "--image", ALLOWED_PATTERN, "--expires", "1d",
            )
            created.append(made["id"] if "id" in made else made.get("key_id", ""))
            st["key"] = made["key"]
            c.require(made.get("daily_unit_cap") is not None, "the new key has no daily_unit_cap")
            c.require(made.get("allowed_images") == [ALLOWED_PATTERN], "the new key's allowed_images is not what was asked")
            who = ctx.json_of(ctx.p2pc(flows.CLI_ROLE, ["whoami"], key=st["key"], expect_ok=True), "whoami with the capped key")
            c.require("admin" not in (who.get("scopes") or []), "the capped key has the admin scope")

        with res.check("p2pc mcp refuses an admin key and an uncapped key") as c:
            c.needs("create a capped key with an image allowlist")
            # This key is only ever used to START `p2pc mcp` (which calls whoami and refuses): it needs no scope at all
            # beyond the one every key must have.
            uncapped = _create_key(ctx, c, "acceptance-uncapped", *_scope_flags(flows.scopes_needed()), "--expires", "1d")
            created.append(uncapped.get("id", ""))
            for name, key in (("an admin key", ctx.admin_key()), ("an uncapped key", uncapped["key"])):
                step = ctx.p2pc(flows.CLI_ROLE, ["mcp"], key=key, json=False, stdin=b"", timeout=60)
                c.require(not step.ok, f"p2pc mcp started with {name}: it must refuse (spec §7, U7)")
                text = (step.stderr + step.stdout).lower()
                c.require("cap" in text or "admin" in text, f"p2pc mcp refused {name} without saying why")

        with res.check("an MCP session with the capped key: tools, estimate, run, machines") as c:
            c.needs("p2pc mcp refuses an admin key and an uncapped key")
            # A compliant client never repeats a request id (MCP, Basic protocol): the retry has its own id (6) and the same
            # `idempotency_key`, which is fresh for every run so that a job from an earlier run is never returned.
            run_args = {
                "image": ctx.image("cpu"), "command": ["python", "-c", "print(6*7)"], "cpu": 0.25, "memory_mb": 256,
                "timeout_s": 120, "wait_s": RUN_WAIT_S, "idempotency_key": f"acc9-{uuid.uuid4().hex}",
            }
            session = flows.mcp_session([
                (3, "p2pc_estimate", {"image": ctx.image("cpu"), "command": ["true"], "cpu": 0.25, "memory_mb": 256, "timeout_s": 60}),
                (4, "p2pc_run", dict(run_args)),
                (5, "p2pc_machines", {}),
                (6, "p2pc_run", dict(run_args)),
            ])
            # stdin stays OPEN until every reply has arrived (or the deadline): a server that treats end-of-input as "shut
            # down" drops the answers still in flight if it is closed right after the requests are written.
            step = ctx.p2pc(
                flows.CLI_ROLE, ["mcp"], key=st["key"], json=False, stdin=session, timeout=SESSION_TIMEOUT_S,
                hold_stdin_until=lambda out: flows.count_mcp_replies(out) >= EXPECTED_REPLIES, hold_deadline_s=REPLY_DEADLINE_S,
            )
            msgs = flows.parse_mcp_output(step.stdout)
            c.require(msgs, "the MCP server printed nothing on stdout")
            c.require(step.stderr.strip() == "" or "warn" in step.stderr.lower() or step.ok, "the MCP server failed")
            # A tool that answered with an API error for a route the server does not have yet is not a failure of the
            # product that exists: it is blocked by the task that brings the route.
            for ident, tool in TOOL_OF_ID.items():
                method, path = context.CLI_ROUTES[SUB_OF_TOOL[tool]]
                for m in (r for r in msgs if r.get("id") == ident):
                    err = flows.mcp_api_error(m)
                    if err and err.get("status") in core.MISSING_ROUTE_STATUSES and ctx.route_missing(method, path):
                        raise core.Blocked(
                            f"{tool} answered {err.get('status')} for {method} {path}, which is not in the server's "
                            "OpenAPI document yet",
                            context.owner(f"route {method} {path}"),
                        )
            # A JSON-RPC error, a reply without a result, or isError: true is a failed call, whatever else is in the reply.
            for m in msgs:
                if "method" in m or m.get("id") is None:
                    continue  # a notification or a request from the server, not a reply to ours
                problem = flows.mcp_reply_problem(m)
                c.require(problem is None, f"MCP call failed: {problem}")
            tools = flows.mcp_tool_names(msgs)
            c.require(set(flows.MCP_TOOLS) <= set(tools), f"tools/list lacks: {sorted(set(flows.MCP_TOOLS) - set(tools))}")
            replies = {}
            for m in msgs:
                replies.setdefault(m.get("id"), []).append(m)
            for ident, what in ((1, "initialize"), (3, "p2pc_estimate"), (5, "p2pc_machines"), (4, "p2pc_run"), (6, "the retried p2pc_run")):
                c.require(ident in replies, f"no reply to {what} (request id {ident})")
            runs = replies.get(4, []) + replies.get(6, [])
            c.require(len(replies.get(4, [])) == 1 and len(replies.get(6, [])) == 1, "expected one reply to each of the two p2pc_run calls (ids 4 and 6)")
            ids = [flows.mcp_job_ids(r) for r in runs]
            c.require(ids[0] and ids[0] == ids[1], "a retried p2pc_run call (new request id, same idempotency_key) created a second job: it must return the same one")
            st["mcp_job"] = ids[0][0]
            c.evidence["job_id"] = st["mcp_job"]

        with res.check("the daily cap is enforced") as c:
            c.needs("create a capped key with an image allowlist")
            step = ctx.p2pc(
                flows.CLI_ROLE,
                ["run", "--detach", "--image", ctx.image("cpu"), "--cpu", "4", "--mem", "512M", "--timeout", "2h", "--", "true"],
                key=st["key"],
            )
            err = step.error_json() or {}
            c.require(not step.ok, "a job whose estimate exceeds the cap was accepted")
            c.require(err.get("status") == 402 and err.get("code") == "cap_exceeded", f"expected 402 cap_exceeded, got {err.get('status')} {err.get('code')}")

        with res.check("the image allowlist is enforced") as c:
            c.needs("create a capped key with an image allowlist")
            step = ctx.p2pc(
                flows.CLI_ROLE,
                ["run", "--detach", "--image", ctx.image("denied_image"), "--cpu", "0.25", "--mem", "256M", "--timeout", "1m", "--", "true"],
                key=st["key"],
            )
            err = step.error_json() or {}
            c.require(not step.ok, "a job with an image outside the key's allowlist was accepted")
            c.require(
                err.get("code") != "forbidden",
                "the job was refused because the key lacks a scope (`forbidden`), not because of its image allowlist",
            )
            c.require(
                (err.get("status"), err.get("code")) == (403, "image_not_allowed"),
                f"expected 403 image_not_allowed, got {err.get('status')} {err.get('code')}",
            )
            c.evidence["refusal"] = {"status": err.get("status"), "code": err.get("code")}
    finally:
        if st.get("mcp_job"):  # the job the session created: do not leave it queued, spending the account
            ctx.p2pc(flows.CLI_ROLE, ["cancel", st["mcp_job"]], record=False)
        for key_id in created:
            if key_id:
                ctx.p2pc(flows.CLI_ROLE, ["keys", "revoke", key_id], record=True)

    with res.check("the MCP server used from Claude Code (manual)") as c:
        path, digest = ctx.manual_evidence("claude_code_session")
        c.evidence.update(report=path.name, sha256=digest)
    return res
