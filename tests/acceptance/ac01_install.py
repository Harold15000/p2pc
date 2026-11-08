# SPDX-License-Identifier: Apache-2.0
"""AC-1: server install to admin key in 10 minutes or less, with one command; join a node in 2 minutes or less, with one.

U1 (install, admin key shown once) and U2 (enroll a machine, see it in `p2pc machines` with its inventory)."""

from __future__ import annotations

import re

import context
import core
import flows

ID = "AC-1"
TITLE = "Install the server and join a node"
SPEC = "Server install to admin key: <= 10 min, one command. Join a node: <= 2 min, one command."
ROLES = ("server", "node_linux_gpu", "node_linux", "node_wsl2_gpu")
# What it needs, as keys of context.OWNERS: whether each has landed is read from the product (`--list`).
NEEDS: tuple[str, ...] = (
    "feature installer", "feature node-installer", "route GET /v1/nodes", "route POST /v1/nodes/join-tokens", "feature agent-connection",
)

INSTALL_BUDGET_S = 600
JOIN_BUDGET_S = 120
ONLINE_WAIT_S = 90
_KEY_RE = re.compile(r"p2pc_sk_[A-Za-z0-9_]+")
# What `GET /v1/nodes` returns of a node's `inventory` (docs/api/openapi.json, schema Inventory; `wsl2` only on WSL2).
INVENTORY_FIELDS = ("hostname", "platform", "cpu", "memory_mb", "os", "arch", "gpus", "gpu_status", "sandbox", "offered", "agent_version")
ALREADY_ENROLLED = 3  # `p2pc-agent join` exit code (crates/p2pc-agent/src/connection/exit.rs)
# The exit codes of deploy/wsl/install.ps1 (its header), for the message when the Windows installer fails. The Linux
# installer exits 0 done, 1 failed or refused, 2 usage error; its log is /var/log/p2pc-node-install.log, and the
# agent's is `journalctl _UID=$(id -u p2pc) _SYSTEMD_USER_UNIT=p2pc-agent.service`.
WINDOWS_INSTALLER_EXIT = {
    2: "bad usage", 10: "Windows build too old", 11: "WSL not installed", 12: "WSL too old", 13: "WSL default version is not 2",
    14: "virtualization disabled in the firmware", 15: "not enough disk space", 16: "the p2pc-node distro already exists (use -Upgrade)",
    17: "the tar or its .sha256 is missing", 18: "SHA-256 mismatch", 20: "wsl --import failed", 21: "verification of the new distro failed",
    31: "p2pc-node is not installed", 32: "the image has no agent or no p2pc-shim, or is older than 0.2.2",
    33: "the enrollment failed (the token was refused or expired, or the agent could not reach the server)",
    34: "the node is already enrolled with another identity (use -Force)", 35: "the Scheduled Task could not be registered or started",
}
DISTRO_EXISTS = 16  # install.ps1 -Tar: "the p2pc-node distro already exists (use -Upgrade)"
NODE_RUN_STATUS = "/var/lib/p2pc/node-run.status"  # in the Windows node's distro (deploy/wsl/p2pc-node-run)
# What the installers print when they find the node enrolled and were not told to enroll it again (install-node.sh:
# "already enrolled … (rerun with --force …)"; install.ps1: "… .\\install.ps1 -Join -Force").
ALREADY_ENROLLED_LINE = re.compile(r"(?i)already enrolled.*(rerun with --force|-Join -Force)")
ALREADY_ENROLLED_HINT = (
    "an installer that finds the machine already enrolled skips the join and leaves the token unused: add --force "
    "(Linux) or -Force (Windows) to install_command to enroll the same node again, or remove the node with "
    "`p2pc machines rm NAME --yes` first"
)
TOKEN_EXPIRES = "15m"  # `p2pc join-token create --expires` (the default; passed explicitly, so the flag is exercised)


def run(ctx) -> core.Result:
    res = ctx.begin(ID, TITLE)

    with res.check("server install: one command, within 10 minutes") as c:
        ctx.require("server")
        command = ctx.role("server").get("install_command")
        if not command:
            if ctx.feature_landed("installer") is False:
                raise core.Blocked("there is no server installer in this checkout yet", context.owner("feature installer"))
            # The installer exists (deploy/linux/install-server.sh); the machines file just does not say how to run it. That
            # is the environment's, not the product's: the install is not exercised, so AC-1 cannot be `pass`.
            raise core.Skipped(
                "install_command is not set in [server]: the installer (deploy/linux/install-server.sh) is not run, so the "
                "10-minute install is not measured. Set it, or export the admin key of an installed server"
            )
        step = ctx.exec("server", ["sh", "-c", command], label="server install", timeout=INSTALL_BUDGET_S + 30)
        c.timing("install_s", step.duration_s)
        c.require(step.ok, f"the install command exited {step.exit_code}")
        c.require(step.duration_s <= INSTALL_BUDGET_S, f"install took {step.duration_s:.0f} s, over {INSTALL_BUDGET_S} s")
        found = _KEY_RE.search(step.stdout + "\n" + step.stderr)
        c.require(found is not None, "the installer did not print an admin API key (U1: shown once)")
        ctx.set_admin_key(found.group(0))
        health = ctx.exec("server", ["curl", "-fsS", "--max-time", "20", f"{ctx.server_url()}/healthz"], timeout=40)
        c.require(health.ok, f"GET /healthz failed after the install: {health.stderr.strip()}")

    with res.check("the admin key works (login, whoami)") as c:
        ctx.require("server")
        ctx.deploy("server", "p2pc")
        key = ctx.admin_key()
        ctx.p2pc("server", ["login", "--server", ctx.server_url(), "--key-stdin"], key=None, stdin=(key + "\n").encode(), expect_ok=True)
        who = ctx.json_of(ctx.p2pc("server", ["whoami"], expect_ok=True), "p2pc whoami")
        c.require("admin" in (who.get("scopes") or []), "the installer's key has no admin scope")

    ctx.state.setdefault("node_ids", {})
    ctx.state.setdefault("joined_by_installer", {})
    for role in flows.NODE_ROLES:
        _node(ctx, res, role)
    return res


def _is_windows(ctx, role: str) -> bool:
    spec = ctx.machines.roles.get(role)  # a role that is not in the machines file is skipped by `ctx.require` in its checks
    return spec is not None and spec.executor == "wsl_over_ssh"


def _new_token(ctx, c, role: str) -> tuple[str, str]:
    """A single-use join token (`join-token create --expires 15m`): (token, row id). The token is a secret: it only ever
    goes on stdin (spec §7)."""
    tok = ctx.json_of(
        ctx.p2pc("server", ["join-token", "create", "--label", f"acceptance-{role}", "--expires", TOKEN_EXPIRES], expect_ok=True),
        "p2pc join-token create",
    )
    token = tok.get("join_token")
    c.require(isinstance(token, str) and token.startswith("p2pc_join_"), "join-token create returned no join_token")
    ctx.redactor.add_secret(token)
    c.require(isinstance(tok.get("id"), str), "join-token create returned no id")
    c.require(isinstance(tok.get("expires_at"), str), "join-token create returned no expires_at")
    c.evidence["token_expires_at"] = tok["expires_at"]
    return token, tok["id"]


def _node(ctx, res, role: str) -> None:
    windows = _is_windows(ctx, role)
    install_name = f"{role}: the node installer, one command"
    if windows:
        with res.check(f"{role}: the node image (install.ps1 -Tar)") as c:
            # The Windows HOST, not the distro: this step is what creates the distro, so it cannot need it. The distro is
            # checked by the steps after this one (`ctx.require(role)`).
            ctx.require("server")
            ctx.require_host(role)
            command = ctx.role(role).get("image_install_command")
            if not command:
                distro = ctx.role(role).distro
                probe = ctx.probe_distro(role)
                c.require(
                    not (probe.timed_out or probe.error),
                    f"could not tell whether the distro {distro} exists: {probe.error or 'the probe timed out'}"
                    + (" (it may be slow to boot; run it again)" if probe.timed_out else ""),
                )
                c.require(
                    probe.ok,
                    f"the distro {distro} does not exist: set image_install_command, or install it (deploy/wsl/install.ps1 -Tar) "
                    f"(wsl.exe exit {probe.exit_code}: {core.failure_reason(probe.exit_code, probe.stderr) or 'no message'})",
                )
                raise core.Skipped(
                    f"image_install_command is not set for role '{role}': the {distro} distro exists and is used as it is "
                    "(install.ps1 -Tar is not run)"
                )
            step = ctx.exec_host(role, command, label="install.ps1 -Tar", timeout=INSTALL_BUDGET_S + 30)
            c.timing("image_install_s", step.duration_s)
            if step.exit_code == DISTRO_EXISTS:
                raise core.Skipped(
                    "distro already installed (install.ps1 -Tar exits 16 when p2pc-node exists): the image step runs once; "
                    "the node is used as it is. To install a newer image, use -Upgrade yourself"
                )
            c.require(step.ok, _installer_failure(step, windows))

    with res.check(install_name) as c:
        ctx.require("server", role)
        command = ctx.role(role).get("install_command")
        if not command:
            if ctx.feature_landed("node-installer") is False:
                raise core.Blocked(
                    "there is no node installer in this checkout yet (deploy/linux/install-node.sh, deploy/wsl/install.ps1 -Join)",
                    context.owner("feature node-installer"),
                )
            raise core.Skipped(
                f"install_command is not set for role '{role}': the node installer is not run (the join below uses the "
                "p2pc-agent the harness copied, which is not what a user gets)"
            )
        ctx.deploy("server", "p2pc")
        token, token_id = _new_token(ctx, c, role)
        # The installer enrolls the node and starts its agent (Linux: the systemd user unit; Windows: the "P2PC node"
        # task). The token reaches `p2pc-agent join -` on stdin only: here it is the stdin of the installer, or the
        # pipeline of install.ps1.
        stdin = (token + "\n").encode()
        if windows:
            step = ctx.exec_host(role, command, label="install.ps1 -Join", stdin=stdin, timeout=JOIN_BUDGET_S + 60)
        else:
            step = ctx.exec(role, ["sh", "-c", command], label=f"node install {role}", stdin=stdin, timeout=JOIN_BUDGET_S + 60)
        c.timing("join_s", step.duration_s)
        c.require(step.ok, _installer_failure(step, windows))
        refused = next((ln.strip() for ln in step.stdout.splitlines() if ALREADY_ENROLLED_LINE.search(ln)), None)
        # Without --force an enrolled node is not enrolled again: the installer says so, still prints `Joined:` and exits 0,
        # and the token stays unused. Fail here, not after the wait for a token nobody consumes.
        c.require(refused is None, f"the node is already enrolled and the installer skipped the join ({refused}): {ALREADY_ENROLLED_HINT}")
        joined = next((ln.strip() for ln in step.stdout.splitlines() if ln.strip().startswith("Joined:")), None)
        c.require(joined, "the installer exited 0 but did not print `Joined: <node> on <server>`")
        c.evidence["installer_said"] = joined
        c.require(step.duration_s <= JOIN_BUDGET_S, f"install and join took {step.duration_s:.0f} s, over {JOIN_BUDGET_S} s")
        ctx.state["joined_by_installer"][role] = token_id

    with res.check(f"{role}: join with one command, within 2 minutes") as c:
        ctx.require("server", role)
        if ctx.role(role).get("install_command"):
            c.needs(install_name)  # the installer joined the node; what follows only looks at the result
        token_id = ctx.state["joined_by_installer"].get(role)
        if token_id is None:
            token_id = _harness_join(ctx, c, role)
        node = _joined_node(ctx, c, role, token_id)
        inv = node.get("inventory") or {}
        absent = [f for f in INVENTORY_FIELDS if f not in inv]
        c.require(not absent, f"the machine's inventory lacks: {', '.join(absent)}")
        expected_gpu = role in flows.GPU_ROLES
        c.require(bool(inv.get("gpus")) == expected_gpu, f"role '{role}' {'has' if expected_gpu else 'has no'} GPU in the machines file, but the inventory lists {len(inv.get('gpus') or [])}")
        ctx.state["node_ids"][role] = node["id"]
        c.evidence.update(
            node_id=node["id"], platform=inv.get("platform"), gpus=len(inv.get("gpus") or []),
            sandbox_ready=[bool(d.get("ready")) for d in inv.get("sandbox") or []],
        )
        if windows and token_id in ctx.state["joined_by_installer"].values():
            # The supervisor the "P2PC node" task runs writes why it is where it is (deploy/wsl/p2pc-node-run).
            status = ctx.exec(role, ["cat", NODE_RUN_STATUS], timeout=30)
            state = next((ln.split("=", 1)[1] for ln in status.stdout.splitlines() if ln.startswith("state=")), None)
            c.evidence["node_run_state"] = state
            c.require(state == "running", f"{NODE_RUN_STATUS} says state={state}, expected running ({core.last_line(status.stderr) or 'see reason= in that file'})")


def _installer_failure(step, windows: bool) -> str:
    code = step.exit_code
    if step.error or step.timed_out:
        return context.describe_failure(step)
    if windows:
        why = WINDOWS_INSTALLER_EXIT.get(code, "see %LOCALAPPDATA%\\P2PC\\logs\\install-<time>.log on the Windows machine")
    else:
        why = {1: "failed or refused: see /var/log/p2pc-node-install.log on the node", 2: "usage error"}.get(code, "see /var/log/p2pc-node-install.log")
    return f"the node installer exited {code}: {why}"


def _harness_join(ctx, c, role: str) -> str:
    """Without an installer command: the harness joins with the p2pc-agent it copied, and starts it itself. Returns the id
    of the token it used."""
    ctx.deploy(role, "p2pc_agent")
    ctx.deploy("server", "p2pc")
    token, token_id = _new_token(ctx, c, role)
    # The token goes on stdin (`join -`), never in the argument list: it would show in `ps` and in shell history
    # (spec §7, CLI conventions).
    join = ctx.exec(
        role,
        [ctx.bin(role, "p2pc_agent"), "join", "-"],
        label="p2pc-agent join",
        stdin=(token + "\n").encode(),
        timeout=JOIN_BUDGET_S + 30,
    )
    if join.missing_piece():
        raise core.Blocked("`p2pc-agent join` is not implemented yet", context.owner("feature agent-connection"))
    if join.exit_code == ALREADY_ENROLLED:
        raise core.Skipped(
            f"role '{role}' is already enrolled (p2pc-agent join exit {ALREADY_ENROLLED}): AC-1 needs a fresh machine. "
            "To start over: `p2pc machines rm NAME --yes` on the server, then `p2pc-agent join --force` or delete "
            "the agent's data directory on the node"
        )
    c.timing("join_s", join.duration_s)
    c.require(join.ok, f"p2pc-agent join exited {join.exit_code}")
    c.require(join.duration_s <= JOIN_BUDGET_S, f"join took {join.duration_s:.0f} s, over {JOIN_BUDGET_S} s")
    start = ctx.role(role).get("agent_start_command") or ('nohup "$0" run > "$1" 2>&1 < /dev/null &')
    ctx.exec(
        role,
        ["sh", "-c", start, ctx.bin(role, "p2pc_agent"), f"{ctx.workdir(role)}/agent.log"],
        label="start the agent",
        timeout=30,
    )
    return token_id


def _joined_node(ctx, c, role: str, token_id: str) -> dict:
    """The node that consumed the token, online. Found by the token, not by being new: a re-enrollment (`--force`) keeps the
    node's id (spec §5). Single use: the server's own list says which node used it."""

    def consumer():
        listed = ctx.json_of(ctx.p2pc("server", ["join-token", "list"], expect_ok=True), "p2pc join-token list")
        row = next((t for t in listed if isinstance(t, dict) and t.get("id") == token_id), None) if isinstance(listed, list) else None
        c.require(row is not None, "the new join token is not in `p2pc join-token list`")
        return row.get("consumed_by_node_id")

    node_id, _ = flows.wait_until(
        ctx, consumer, timeout_s=ONLINE_WAIT_S, poll_s=3,
        what=f"the join token to be consumed by a node ({ALREADY_ENROLLED_HINT})",
    )

    def online():
        return next((n for n in flows.list_nodes(ctx) if n.get("id") == node_id and n.get("state") == "online"), None)

    node, waited = flows.wait_until(ctx, online, timeout_s=ONLINE_WAIT_S, poll_s=3, what="the machine to be online")
    c.timing("online_after_join_s", waited)
    return node
