# SPDX-License-Identifier: Apache-2.0
"""AC-8: a client on another network (4G) uses `p2pc proxy`. Neither the server nor the nodes have open ports (spec §10)."""

from __future__ import annotations

import context
import core
import flows

ID = "AC-8"
TITLE = "Remote client through p2pc proxy; no open ports"
SPEC = "A client on another network (4G) uses `p2pc proxy`. Neither the server nor the nodes have open ports."
ROLES = ("server", "client_remote", "node_linux_gpu", "node_linux", "node_wsl2_gpu")
# What it needs, as keys of context.OWNERS: whether each has landed is read from the product (`--list`).
NEEDS: tuple[str, ...] = ("route GET /v1/server", "route GET /v1/nodes", "cli proxy", "feature agent-connection", "feature scheduler", "feature executor")

PROXY_LISTEN = "127.0.0.1:7477"
PROCESS = {"server": "p2pc-server", "node_linux_gpu": "p2pc-agent", "node_linux": "p2pc-agent", "node_wsl2_gpu": "p2pc-agent"}


def _p2pc_uids(ctx, role: str) -> set[int]:
    """The uids of the server's and the agent's users, for the roles whose `ss` cannot name every process."""
    uids = set()
    for user in flows.P2PC_USERS:
        step = ctx.exec(role, ["id", "-u", user], timeout=30, record=False)
        if step.ok and step.stdout.strip().isdigit():
            uids.add(int(step.stdout.strip()))
    return uids


NON_QUIC_UDP_PORTS = {5353: "mDNS", 1900: "SSDP", 137: "NetBIOS", 5355: "LLMNR"}


def _p2pc_sockets(ctx, role: str, proto: str, uids: set[int], wsl: bool) -> tuple[list, int]:
    """The listening sockets of P2PC (``proto``: ``t`` or ``u``) and how many others were left out. `sudo -n ss` when the
    role has passwordless sudo (it names every process), else plain `ss -e` (the uids of the owners); a WSL2 distro runs
    as root, so it needs no sudo."""
    ss = ["ss", "-H", f"-l{proto}npe"]
    step = None if wsl else ctx.exec(role, ["sudo", "-n", *ss], timeout=30, record=False)
    if step is None or not step.ok:
        step = ctx.exec_ok(role, ss, timeout=30)
    everything = flows.parse_listeners(step.stdout)
    mine = flows.p2pc_listeners(everything, uids=uids, any_process=wsl)
    return mine, len(everything) - len(mine)


def run(ctx) -> core.Result:
    res = ctx.begin(ID, TITLE)
    st: dict = {}

    try:
        with res.check("the server's address") as c:
            ctx.require("server", "client_remote")
            ctx.deploy("server", "p2pc")
            ctx.deploy("client_remote", "p2pc")
            ctx.admin_key()
            # Same path as every `p2pc` call: a 404 on a route the server's OpenAPI lacks is blocked by its owner.
            info = ctx.json_of(
                ctx.rest_get("server", "/v1/server", route=("GET", "/v1/server"), expect_ok=True), "GET /v1/server"
            )
            address = info.get("address") if isinstance(info, dict) else None
            c.require(isinstance(address, str) and address.startswith("p2pc_srv_"), "GET /v1/server returned no p2pc_srv_ address")
            st["address"] = address

        with res.check("p2pc proxy listens on the client") as c:
            c.needs("the server's address")
            # Probe with `--help` first (never a bare call: a `p2pc proxy` that works would start a listener). A stub
            # given `--listen …` would die in clap ("unexpected argument") before it could say what it is, and the log
            # would then look like a product failure.
            if ctx.cli_stub("client_remote", "proxy"):
                raise core.Blocked("`p2pc proxy` is not available in this version of the CLI yet", context.owner("cli proxy"))
            log = f"{ctx.workdir('client_remote')}/proxy.log"
            pidfile = f"{ctx.workdir('client_remote')}/proxy.pid"
            start = 'nohup "$0" proxy --listen "$1" > "$2" 2>&1 < /dev/null & echo $! > "$3"'
            ctx.exec(
                "client_remote",
                ["sh", "-c", start, ctx.bin("client_remote", "p2pc"), PROXY_LISTEN, log, pidfile],
                env={"P2PC_SERVER": st["address"], "P2PC_CONFIG_DIR": f"{ctx.workdir('client_remote')}/p2pc-config"},
                label="start p2pc proxy",
                timeout=30,
            )
            st["pidfile"] = pidfile

            def listening():
                alive = ctx.exec("client_remote", ["sh", "-c", 'kill -0 "$(cat "$1")" 2>/dev/null', "sh", pidfile], record=False, timeout=20)
                out = ctx.exec("client_remote", ["cat", log], record=False, timeout=20)
                if not alive.ok:
                    if "not implemented yet" in out.stdout.lower():
                        raise core.Blocked("`p2pc proxy` is not implemented yet", context.owner("cli proxy"))
                    raise core.CheckFailed(f"p2pc proxy exited: {core.tail(out.stdout, 200)}")
                port = PROXY_LISTEN.rsplit(":", 1)[1]
                ss = ctx.exec("client_remote", ["ss", "-H", "-ltn"], record=False, timeout=20)
                return f"127.0.0.1:{port}" in ss.stdout

            _, waited = flows.wait_until(ctx, listening, timeout_s=30, poll_s=1, what="p2pc proxy to listen")
            c.timing("proxy_ready_s", waited)

        with res.check("the remote client runs a job through the tunnel") as c:
            c.needs("p2pc proxy listens on the client")
            url = f"http://{PROXY_LISTEN}"
            who = ctx.json_of(ctx.p2pc("client_remote", ["whoami"], server_url=url, expect_ok=True), "whoami through the proxy")
            c.require(who.get("key_id"), "whoami through the proxy returned no key")
            flows.require_jobs_run(ctx)  # the tunnel works; whether a node can run the job is the gate's question
            step = ctx.p2pc(
                "client_remote",
                ["run", "--image", ctx.image("cpu"), "--cpu", "1", "--mem", "256M", "--timeout", "5m", "--", "python", "-c", "print(6*7)"],
                server_url=url, timeout=900,
            )
            c.require(step.exit_code == 0, f"p2pc run through the proxy exited {step.exit_code}")

        with res.check("a profile with the p2pc_srv_ address reaches the API without a separate proxy") as c:
            c.needs("the server's address")
            step = ctx.p2pc("client_remote", ["whoami"], server_url=st["address"], expect_ok=True)
            c.require(ctx.json_of(step, "whoami").get("key_id"), "whoami through the address returned no key")
    finally:
        if st.get("pidfile"):
            ctx.exec("client_remote", ["sh", "-c", 'kill "$(cat "$1")" 2>/dev/null; rm -f "$1"', "sh", st["pidfile"]], label="stop p2pc proxy", timeout=20)

    for role in ("server", "node_linux_gpu", "node_linux", "node_wsl2_gpu"):
        with res.check(f"{role}: no listening port reachable from outside") as c:
            ctx.require(role)
            process = PROCESS[role]
            running = ctx.exec(role, ["pgrep", "-x", process], timeout=30)
            if not running.ok:
                raise core.Skipped(f"{process} is not running on '{role}': install and start it (AC-1), then run AC-8 again")
            allowed = ctx.role(role).get("allowed_listen_ports") or [22]
            # Only P2PC's own sockets count: on the owner's machine other services always listen (Docker, Tailscale, and, in
            # a WSL2 distro, the sockets of the owner's other distros, which share the network namespace).
            wsl = ctx.role(role).executor == "wsl_over_ssh"
            uids = set() if wsl else _p2pc_uids(ctx, role)
            tcp, ignored_tcp = _p2pc_sockets(ctx, role, "t", uids, wsl)
            udp, ignored_udp = _p2pc_sockets(ctx, role, "u", uids, wsl)
            exposed = flows.exposed_listeners(tcp, allowed)
            # Spec §10: a node's iroh endpoint uses UDP (QUIC), outbound-initiated but bound to a local port: allowed, and
            # named here so the report shows exactly which sockets those are.
            c.evidence.update(
                allowed_ports=allowed,
                p2pc_tcp_listeners=[l.describe() for l in tcp],
                p2pc_udp_sockets=[l.describe() for l in udp],
                ignored_non_p2pc_sockets=ignored_tcp + ignored_udp,
            )
            c.require(not exposed, "TCP listeners of P2PC reachable from outside: " + ", ".join(exposed))
            # The evidence is what the owner reads to confirm only iroh's UDP is open: a P2PC socket on a well-known
            # non-QUIC port (mDNS local discovery, for one) is not iroh's outbound QUIC and is not passed in silence.
            # Not in a WSL2 distro: there every socket with a visible process counts, including the distro's own
            # systemd-resolved/avahi, so a well-known port there cannot be pinned on P2PC.
            odd = [f"{l.describe()} ({NON_QUIC_UDP_PORTS[l.port]})" for l in udp if l.port in NON_QUIC_UDP_PORTS and not wsl]
            c.require(not odd, "UDP sockets of P2PC on a port that is not iroh's QUIC: " + ", ".join(odd))

    with res.check("from the remote network, the server's REST port is closed") as c:
        ctx.require("server", "client_remote")
        host = ctx.role("server").get("public_host")
        if not host:
            raise core.Skipped("set public_host in [server] to probe the server from the client's network")
        try:
            port = str(flows.url_port(ctx.server_url()))
        except ValueError as e:
            raise core.CheckFailed(f"the server url in the machines file is not usable: {e}") from None
        probe = ctx.exec("client_remote", ["sh", "-c", 'timeout 8 bash -c "echo > /dev/tcp/$0/$1"', host, port], timeout=30)
        verdict = flows.classify_port_probe(probe.exit_code, probe.stderr + probe.error)
        c.evidence.update(host_port=f"{host}:{port}", verdict=verdict)
        if verdict == "tool-missing":
            raise core.Skipped(f"the probe needs bash and timeout on 'client_remote': {core.last_line(probe.stderr)}")
        c.require(verdict != "open", f"{host}:{port} accepted a TCP connection from the client's network")
        c.require(
            verdict == "closed",
            f"could not tell whether {host}:{port} is closed: exit {probe.exit_code}, {core.last_line(probe.stderr) or probe.error or 'no message'}",
        )
    return res
