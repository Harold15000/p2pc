# P2PC acceptance harness

One command runs the v0.1 acceptance criteria (spec §14, AC-1 to AC-12) against **real machines** and writes an
evidence report. Since T15b the harness matches the product that is on `main` (the gateway, the scheduler, the agent's
executor, the log, result and usage endpoints and the CLI that drives them): a failure in a run is a failure of the
product, and `blocked` is left for what is genuinely not built: on `main` that is one rule, the detach of `p2pc run` when
its stdout closes (T11b3, AC-7; the node installers of T14b2 are merged). A step whose piece is missing is still reported as `blocked`, with the task that unblocks it, so the harness
keeps working on a checkout that lacks one. **It never fakes a pass.**

Python 3.12 or newer, standard library only. No network access is needed to run the harness's own tests.

**Tools on the PATH.** AC-12 runs `gitleaks`, `cargo-deny` and `cargo-cyclonedx` on the machine that runs the harness, so
all three must be on the PATH **of the shell that starts it** (a `brew`-installed `gitleaks` is not there unless linuxbrew
is in that shell's PATH). A missing one makes its AC-12 check a `skip`; `run.py --list` names the ones it cannot find.

- [Quick start](#quick-start)
- [The machines file](#the-machines-file)
- [How a run works](#how-a-run-works)
- [The criteria](#the-criteria)
- [The report](#the-report)
- [When a task lands](#when-a-task-lands)
- [Tests of the harness](#tests-of-the-harness)
- [Assumptions re-checked against `main`](#assumptions-re-checked-against-main-t15b)

## Quick start

```sh
cargo build --release                         # p2pc, p2pc-server and p2pc-agent, in target/release
cp tests/acceptance/machines.example.toml tests/acceptance/machines.toml   # git-ignored; fill in your machines
export P2PC_ACC_ADMIN_KEY=...                 # only to test a server that is already installed (see AC-1)

tests/acceptance/run.py --machines tests/acceptance/machines.toml                  # every criterion
tests/acceptance/run.py --machines tests/acceptance/machines.toml --only AC-2,AC-5
tests/acceptance/run.py --only AC-12 --machines tests/acceptance/machines.example.toml   # runs today, locally
tests/acceptance/run.py --list                                                    # the table below
```

| Option | Meaning |
|---|---|
| `--machines FILE` | The machines file. Required, except with `--list`. |
| `--only AC-2,AC-5` | Run only these criteria (`ac5` and `AC5` also work). |
| `--report-dir DIR` | Where reports go. Default: `tests/acceptance/reports/`. |
| `--strict` | The release gate: exit 1 unless **every** selected criterion is `pass`. |
| `--list` | Print the criteria and what each one waits for. |
| `--repo DIR` | The repository AC-11 and AC-12 inspect. Default: this checkout. |

**Exit code:** 0 when no criterion failed (`blocked` and `skip` are reported, not failures); 1 when one failed or, with
`--strict`, when any is not `pass`; 2 for a usage or machines-file error; 130 when interrupted (the partial report is
still written).

## The machines file

`machines.example.toml` documents every key. All names in it are placeholders (`example.invalid`) and every role is
`enabled = false`, so the example is valid and only the local criteria (AC-11, AC-12) run from it.

| Role | Machine |
|---|---|
| `server` | The always-on machine that runs `p2pc-server`. The functional criteria also run the `p2pc` CLI **on it**, against its loopback address. |
| `node_linux_gpu` | A Linux node with an NVIDIA GPU. |
| `node_linux` | A Linux node **without** a GPU. It runs every criterion a CPU node can (AC-1, AC-2, AC-4 to AC-8, AC-10); AC-3 needs the GPU roles. |
| `node_wsl2_gpu` | A Windows machine with an NVIDIA GPU, whose WSL2 distro `p2pc-node` is the node. |
| `client_remote` | A machine on another network, for AC-8. |

`machines.example.toml` describes the lab of the first real run: `server` and `node_linux` over `ssh`, and `node_wsl2_gpu`
through `ssh` → `wsl.exe -d p2pc-node -u root …`. That lab has no Linux GPU, so AC-3 is `skip` for Linux there, and the
criterion cannot be `pass` until a `node_linux_gpu` is added; AC-8 likewise needs a `client_remote`.

A role you do not have is left out, or `enabled = false`: the criteria that need it are `skip`. A role that is enabled
but unreachable is a `fail`, never a skip.

**Executors** (how commands reach a machine):

| `executor` | Runs |
|---|---|
| `local` | The command, directly, on the machine that runs the harness. |
| `ssh` | `ssh <host> <command>`. `host` is an alias of your `~/.ssh/config`. |
| `wsl_over_ssh` | `host` is an ssh alias of a **Windows** machine and `distro` is the WSL distro. The harness runs `wsl.exe -d <distro> -u root --exec sh -c …` through PowerShell. The node installer (`install.ps1`) is a Windows script, so a WSL role's `image_install_command` and `install_command` are PowerShell run **on the Windows host** over the same ssh connection (`Executor.run_on_host`), not in the distro. |

All the quoting is in one module, `executors.py`. For `wsl_over_ssh` the command never travels as text through the
three Windows layers (the Windows command line, PowerShell, `wsl.exe`): it is sent base64-encoded, written to a
file in a private (`mktemp -d`, mode 0700) directory inside the distro and run there, so quotes, spaces and `$` arrive unchanged, and no double quote ever
reaches `wsl.exe` (Windows PowerShell 5.1 mangles them). The unit tests decode what the executor builds and run it
with a real shell, and also through one extra shell pass. The one thing they cannot cover is Windows' own argument
parsing, so **before every run the harness sends a probe through each machine**, with quotes, spaces and `$` in the
command and a multi-line text on stdin, and compares what comes back.

**Why `--exec` and not the spec's `--`.** The harness runs `wsl.exe -d <distro> -u root --exec sh -c …`, as
`deploy/wsl/install.ps1` does. With `--`, wsl.exe first hands the command line to the distro's default shell, which
expands `$` and splits arguments again before our `sh -c` sees them; with `--exec` it starts `sh` directly, so the only
shell that reads the script is the one the harness chose. The spec's `--` is the form for typing a command by hand.

**Binaries.** `[binaries]` points at the three binaries you built locally. The harness copies each one into the
machine's `workdir/bin` (name the `workdir`, as the example does, and you know where they are) and runs `sha256sum` on the copy: a mismatch fails the run. Add `p2pc_sha256 = "…"` (and the
same for the others) to pin the exact build you mean to test. The copy streams the file through stdin (for WSL, through
PowerShell), so the sha256 check is what proves it arrived byte for byte. `workdir` is a POSIX path, inside the distro for WSL. Leave it out and the harness makes a private
directory with `mktemp -d` (random name, mode 0700) on each machine and removes it at the end: there is no predictable
path in `/tmp`. The same goes for the temporary script of the WSL executor.

**Secrets.** API keys and join tokens travel on the **stdin** of a small wrapper (or in a 0600 file), never in an
argument, so they do not show up in a process list or in a shell history. This is enforced: `Context.exec` refuses,
before anything is sent, a command whose argv (or plain `env`) holds a `p2pc_sk_…` or `p2pc_join_…` string or any secret
the run learned, and the check fails; and every test that runs a script against scripted machines fails if such a string
reached a machine's argv. Any such string, and any key the run learned, becomes `<redacted>` before anything is written
to a report.

**Manual evidence.** Three things need a human: the internal pentest (AC-11), using the MCP server from Claude Code
(AC-9) and a stranger following the docs (AC-12). Write a report, point `[manual]` at it, and the harness records its
sha256. Without it that check is `skip`, so the criterion cannot be `pass`.

## How a run works

Each criterion is a script, `acNN_<name>.py`, with a `run(ctx)` that returns a result made of **checks**. Each check
records the commands it ran, their exit codes, their timings and short, redacted excerpts of their output.

| Status | Meaning |
|---|---|
| `pass` | Every step ran and held. |
| `fail` | A step ran and the product did not do what the criterion says (or the harness broke). |
| `blocked` | A step could not run because a piece of the product is not built yet. The reason names the task that unblocks it. |
| `skip` | The environment does not allow it: a role is not configured, a tool is not installed, manual evidence is missing. |

A criterion takes the **worst** of its checks, in the order `fail` > `blocked` > `skip` > `pass`. So a criterion is
`pass` only when every one of its checks passed, `blocked` is never counted as `pass`, and the report's verdict is
"accepted" only when every selected criterion is `pass`.

**The rule: `blocked`, naming the owning task, for every piece that has not landed; `fail` only for a product that
exists and is wrong.** And **the harness never says what has landed: it asks the product**, so it needs no edit when a
task lands. There are two separate things:

- *Who owns a piece* is one map, `OWNERS` in `context.py`: `route GET /v1/nodes`, `cli logs`, `feature scheduler`… →
  the task that brings it. It is the only place in the harness that names a task, and every `Blocked(...)` takes its
  tasks from it (`context.owner(key)`). A test scans every other file for a task name, and every `Blocked(` for an
  `owner(` call.
- *Whether a piece has landed* is read from the product:

| What | Read from |
|---|---|
| a REST route | the server's own `/v1/openapi.json` (for `--list`: the committed `docs/api/openapi.json`, which a test of the server keeps equal to the code) |
| a CLI subcommand | `p2pc --help`: a stub says "(not available in this version yet)" in its description |
| the agent's connection | `p2pc-agent status`, which a stub answers with "not implemented yet" |
| the scheduler | `GET /v1/usage` (T06's marker) in the OpenAPI |
| which negative tests exist | `cargo test --workspace --all-features -- --list` (and `--list --ignored`) |
| the agent's lease executor | nothing: it has no marker, so the gate's timeout decides (see below) |

Every `ctx.p2pc(...)` call is checked against that: the call failed and the subcommand is a stub in `p2pc --help`
(read once per run, only when a call fails: a stub given arguments dies in clap before it can say what it is), **or** it
answered 404, 405 or 501 **and** its route (`CLI_ROUTES`) is absent from the server's OpenAPI (read once; one retry; a
failed read is not remembered and declares nothing missing). A 404 alone never blocks: an existing route answers it for
an unknown job id. `ctx.rest_get` goes through the same path: it keeps the HTTP status and turns a non-2xx into the
same `{"error": …}` that `p2pc --json` prints. A check that depends on a blocked one is blocked by the same tasks;
after a failure, the checks that depend on it are skipped.

**Can a node run jobs?** Every criterion that waits for a job first passes one gate, `flows.require_jobs_run`, once per
run, with the answer (a block included) remembered: no `GET /v1/nodes` is blocked by its owner; no machine online asks
the agent (`status`): a stub is the agent's connection, anything else is a `skip` (nobody joined a machine); machines
online: the probe job is **always submitted**, because one marker is not proof that the scheduler is absent. If it leaves
`queued` the scheduler exists and the run goes on. If it stays `queued` and `GET /v1/usage` is absent from the OpenAPI,
that is `blocked` by the scheduler's owner; with the marker present it is a **`fail`**, and if the OpenAPI cannot be read it is a
`fail` whose message says the marker could not be read. Past the scheduler, a job that is
`assigned` and never starts, or runs and never finishes, is a **`fail`**, because the executor has no marker of its own
to read: the message names its owner. The probe is cancelled afterwards.

**Keys have exactly the scopes their calls need.** `flows.scopes_needed` maps each subcommand and MCP tool to its scope
(from `crates/p2pc-server/src/auth.rs` and the tools of `crates/p2pc-cli/src/mcp/tools.rs`) and every key the harness
creates is made from it: AC-9's capped key has `jobs:read` (estimate), `jobs:write` (run) and `nodes:read`
(`p2pc_machines`); AC-10's key has `jobs:write` and nothing else; AC-9's uncapped key, which only ever starts `p2pc mcp`,
has the one scope every key must have. The tests' fakes enforce scopes with the real `403 forbidden` reply, and a test
reads the scopes the harness asked for.

A test runs **every criterion against the product at each stage of its construction** (only the jobs API; nodes but no
agent; an agent but no scheduler; scheduled but never started; started but never reported) with the real reply shapes,
and fails if any check is a `fail`, or if a `blocked` names anything but an owning task. Another reads the scripts'
source: every `p2pc` subcommand they call must be in the tables, no script names a blocker by hand, and no key gets a
literal list of scopes.

**Jobs carry their own verdict.** Where possible a job's exit code says whether the behaviour held (the egress probe
in AC-4, the matmul in AC-3), so those steps do not wait for `p2pc logs`.

## The criteria

Generated by `./run.py --list`, which asks the product (the committed OpenAPI, `p2pc --help`, `p2pc-agent status`; it
builds `p2pc` and `p2pc-agent` if they are not built, unless `--no-build`). A script declares only what it **needs**
(`NEEDS`, keys of the owner map); "Waiting for" names the owners of those that have not landed and "Runs today" says
whether none, some or all have. `T10a*` (the owner of the executor) means the executor, which landed but which the product cannot report offline (no
marker: `p2pc-agent status` only shows its leases once a machine is enrolled), so the column keeps naming it; on a run,
a node that does not execute is a `fail` of the gate that names its owner, never a `blocked`. `?` means the product could
not be asked (no binary). `--list` builds `p2pc` and `p2pc-agent` (debug) first, unless `--no-build`, and asks the binary
that build produced, or the newer of `target/release` and `target/debug` when it does not build. Nothing in a script or in this table is edited when a task lands: run `--list` again. A test
checks the first three columns and the shape of the other two.

<!-- status-table:start -->
| ID | Criterion | Machines | Runs today | Waiting for |
|---|---|---|---|---|
| AC-1 | Install the server and join a node | `server`, `node_linux_gpu`, `node_linux`, `node_wsl2_gpu` | yes | nothing |
| AC-2 | CPU job round trip | `server`, `node_linux_gpu`, `node_linux`, `node_wsl2_gpu` | partly | T10a* |
| AC-3 | GPU job on Linux and WSL2 | `server`, `node_linux_gpu`, `node_wsl2_gpu` | partly | T10a* |
| AC-4 | Egress allowlist and denied destinations | `server`, `node_linux_gpu`, `node_linux`, `node_wsl2_gpu` | partly | T10a* |
| AC-5 | Inputs and outputs round trip | `server`, `node_linux_gpu`, `node_linux`, `node_wsl2_gpu` | partly | T10a* |
| AC-6 | Node loss: retry elsewhere, no stale report | `server`, `node_linux_gpu`, `node_linux`, `node_wsl2_gpu` | partly | T10a* |
| AC-7 | Cancel and timeout stop the job within 15 s | `server`, `node_linux_gpu`, `node_linux`, `node_wsl2_gpu` | partly | T10a*, T11b3 |
| AC-8 | Remote client through p2pc proxy; no open ports | `server`, `client_remote`, `node_linux_gpu`, `node_linux`, `node_wsl2_gpu` | partly | T10a* |
| AC-9 | MCP server with a capped key | `server`, `node_linux_gpu`, `node_linux`, `node_wsl2_gpu` | yes | nothing |
| AC-10 | 100 jobs, 4 per node: no double booking, ledger matches | `server`, `node_linux_gpu`, `node_linux`, `node_wsl2_gpu` | partly | T10a* |
| AC-11 | Security invariants SI-1 to SI-12 and pentest | none (local) | yes | nothing |
| AC-12 | Supply chain, SECURITY.md and docs | none (local) | yes | nothing |
<!-- status-table:end -->

What each one checks (all through the real CLI, with `--json` and the exit codes of spec §7):

- **AC-1 · `ac01_install.py`.** Runs `install_command` of `[server]` (one command, `install-server.sh`) and times it
  against 10 minutes; captures the admin key it prints; `p2pc login --key-stdin` and `whoami`. Then, for each node role,
  with the merged installers of T14b2:
  - *Linux* (`install-node.sh --from DIR`, run with sudo): the role's `install_command` is run with the join token on its
    **stdin** (the installer hands it to `p2pc-agent join -`; never an argument), timed against 2 minutes; it must exit 0
    and print `Joined: <node> on <server>`. The installer also starts the agent (the systemd user unit of `p2pc`), so the
    harness neither copies nor starts one. Exit 1 is reported with its log, `/var/log/p2pc-node-install.log`.
  - *Windows* (`install.ps1`, on the **host**): a WSL role may give `image_install_command` (`-Tar …`, not timed; run it **once**; this step checks the Windows
    **host** over ssh (`powershell`), never the distro, which may not exist yet: the distro is checked by the steps after it.
    Without the command it is a `skip` when the distro exists, and a failure when it does not ("the distro p2pc-node does not
    exist: set image_install_command, or install it"). With it, the step is a `skip` ("distro already installed") when
    `install.ps1` exits 16 because `p2pc-node` exists; any other exit is a failure) and `install_command` (`-Join`), which gets the token as its
    **pipeline** (`$input | …`, how `install.ps1` takes it) and so **must be a single command**: no `;`, `&&`, `||` or
    newline (the machines file is refused otherwise), since PowerShell hands the pipeline to the first statement only; run
    `Unblock-File` on the host yourself, once, is timed against 2 minutes and must print `Joined:`. Then
    `/var/lib/p2pc/node-run.status` in the distro (written by `p2pc-node-run`) must say `state=running`. Its exit codes
    (31 to 35, …) are explained in the failure.
  - The node is found by the token: `p2pc join-token create --expires 15m` gives a token id, and `p2pc join-token list`
    must show it consumed by a node, which must come online with every field of the `Inventory` schema (and a GPU exactly
    when the role has one). Not "the new node": `--force` / `-Force` enrolls the **same** node again (spec §5), so a rerun
    keeps its id. Without `--force` / `-Force` an enrolled node is not enrolled again: the installer says "already enrolled
    … rerun with --force", still prints `Joined:` and exits 0, and the token stays unused. The install step fails **at
    once** on that line, with the hint to add `--force` or run `p2pc machines rm NAME --yes` (a token nobody consumed
    fails the join step the same way after a wait).
  - Without `install_command` for a node: `blocked` by T14b2 while `deploy/linux/install-node.sh` is not in the checkout,
    `skip` once it is; the join then uses the `p2pc-agent` the harness copied (`join -` with the token on stdin, started
    with `agent_start_command` or `nohup`), which is not what a user gets, and a machine that is already enrolled (exit 3)
    is a `skip` with the way out.
  - Without `install_command` in `[server]` the server step is `skip` (the installer exists, it is just not run), or
    `blocked` by T14b1 in a checkout with no installer. To test an installed server instead, export its admin key in the
    variable named by `admin_key_env`.
  `--uninstall [--purge]`, `-Stop`, `-Start`, `-Upgrade` and `-Uninstall` take the node away or offline, so no criterion runs
  them; `-Status` only shows what the harness already reads (`node-run.status`, the server's view of the node).
- **AC-2 · `ac02_cpu_job.py`.** Warms the image, then `p2pc run --json … print(6*7)`: exit 0, and the final job is the
  **last line** of its NDJSON stdout (`run --json` prints the log records first); the live log carried `42`; `succeeded`,
  `exit_code` 0; submit-to-start (`created_at` to `started_at`) within `overhead_budget_s` (5 s); `p2pc logs` shows `42`, and
  so do `logs --follow`, `--attempt 1` and `--follow --attempt 1`, each returning 0 (the command worked), while
  `logs --json` prints `{seq, stream, ts, data}` records from `seq` 0; a job that `exit 3` makes `p2pc run` exit 3; a job
  `p2pc` refuses locally (`--cpu 1000`) exits 125 with a `validation` error and creates nothing.
- **AC-3 · `ac03_gpu_job.py`.** On each GPU node, pinned with `--node`: `nvidia-smi` succeeds (and its table is in the
  logs), and a PyTorch matmul on `cuda` exits 0.
- **AC-4 · `ac04_egress.py`.** `pip install requests` with `--egress pypi.org,files.pythonhosted.org` works. A probe job
  then checks that the proxy accepts the allowed domain and refuses the LAN gateway, the node's own LAN address,
  `100.64.0.1` and another domain, and that a direct connection to `1.1.1.1:443` has no route (SI-3). It needs
  `lan_gateway` and `lan_host` in the machines file. The probe (`flows.EGRESS_PROBE`) is unit-tested against a fake
  proxy.
- **AC-5 · `ac05_inputs_outputs.py`.** A 512 KiB random input (`--file`), a ~1 GiB output (`big_output_mb`), sha256 of
  both computed inside the job and again after `p2pc results --out DIR --json` (whose zero exit is the CLI's own
  verification of every file against the size and sha256 the job listed; the report's files, sizes and byte total are
  checked too), and compared with the server's output list. A second `results` into the same directory must exit 125
  (nothing is overwritten without `--force`), and `--file in.sha256 --force` replaces that one file.
- **AC-6 · `ac06_node_loss.py`.** Needs two nodes and a `partition_command` that cuts one node's network without
  cutting the harness's own ssh (and a `heal_command`, which always runs at the end). A job with `--retries 1` starts
  on node A and runs `lease_ttl_s + 90 + 120 + 60` seconds (the `lease_ttl_s` param, which must equal the server's), so it
  cannot end by itself while the harness watches (its container is `--rm`); its `--timeout` is that run length plus 600 s,
  derived, never a fixed value (`lease_ttl_s` can be up to 3600, and spec §7 allows up to 86 400 s). A is cut; the job must
  be retried on node B (attempt 2) within `lease_ttl_s + 90`; **at the moment attempt 2 first appears, and with the
  network still cut, the old attempt's container must already be gone from A** (SI-13: a partitioned agent stops its job
  before the server requeues it; the harness's own ssh still works because the cut only drops the agent user's packets).
  SI-13 looks only at **running** containers (`podman ps`, not `ps -a`): a stopped container that is not removed yet is
  not a job still running. A is healed and the container must not come back; the job finishes once, on B. Each attempt
  has its own log (`p2pc logs --attempt 2` shows `done`, attempt 1's does not, attempt 3 answers 404). A last check,
  "attempt 1 ends lost and a late `JobFinished` is ignored", reads exactly the §7 fields of `GET /v1/jobs/{id}`:
  `attempts: [{attempt, node_id, outcome, reason, started_at, ended_at}]`, oldest first, no field missing; `outcome`
  `running` only while `ended_at` is null; `outcome` is one of `running`, `succeeded`, `failed`, `timed_out`, `cancelled`,
  `lost` (an attempt replaced after node loss, fenced included, is `lost`; `exited` and `fenced` are not accepted);
  `reason` is a string or null; `started_at` is a string or null (null until `JobStarted`, spec §7 as amended 2026-11-06;
  attempt 2, which succeeded, has one); fields beyond the six (`epoch`, say) are listed in the evidence, not a failure;
  attempt 1 on the cut node ended `lost`, attempt 2 on the other node `succeeded`. That check is `blocked` (by the
  scheduler's owner) only against a server whose `Job` schema does not declare `attempts`; the server on `main` does.
  **WSL2 distros share one network namespace**: cutting a WSL2 node cuts every distro of that Windows user, and iptables
  must never be used for it.
- **AC-7 · `ac07_cancel_timeout.py`.** Cancel a running job: `cancelled` and **its own** container gone within 15 s.
  A job with `--timeout 20s`: `timed_out`, stopped within 15 s of its limit and its container gone; and, separately,
  `p2pc run` exits 124. The exit codes of spec §7 that depend on a stop: `p2pc run` of a cancelled job exits 130 (the same
  job and idempotency key return the job that exists, so no concurrency is needed), and `p2pc run … | head -n 1`, whose
  stdout closes while the job runs, exits 130, says how to follow or stop the job, and leaves the job running (spec §7 as
  amended 2026-11-06; the harness cancels it afterwards). **That rule is in the spec but not on `main` yet** (T11b3): there
  `run` ends 0 with no hint when the pipe closes. So while the checkout's `docs/cli.md` does not describe it ("a closed
  stdout detaches"), exit 0 with no `detached:` line is `blocked` by T11b3, not a failure; once the docs say it, the same
  result is a `fail`, and the check passes as soon as the code is there, with no edit. Exit 75 (lost) is not asserted anywhere: it needs a job whose
  last attempt is lost, which would end AC-6's retry. "The container is gone" is only claimed with proof: the harness lists the P2PC containers
  (label `p2pc.lease`, with the role's `podman` command) before the job exists, and after it runs the one new name
  must be visible (the job carries no lease id, so the name is how its container is told from anybody else's). If it
  cannot see it (podman not usable, or not the agent's), the check is `skip` with the reason, never `pass`; AC-6 does
  the same before it cuts any network.
- **AC-8 · `ac08_remote_client.py`.** Reads the server's `p2pc_srv_` address (`GET /v1/server`); starts
  `p2pc proxy --listen 127.0.0.1:7477` on `client_remote`; runs `whoami` and a job through it; uses a `p2pc_srv_`
  profile directly. On the server and on every node: no TCP listener **of P2PC** on a non-loopback address besides the
  allowed ports (default 22; `allowed_listen_ports` is for the owner's own exceptions). Only P2PC's sockets are looked at,
  because on the owner's machine other services always listen (Docker, Tailscale, the other WSL2 distros, which share the
  network namespace): on Linux, `ss -H -ltnpe` and `ss -H -lunpe` (with `sudo -n` when the role has it), keeping the sockets
  whose process is `p2pc-server` or `p2pc-agent` or whose uid is the user `p2pc-server` or `p2pc` (from `ss -e`, when sudo
  does not work); in the WSL2 distro, the sockets that have a process of that distro. A P2PC UDP socket is the iroh
  endpoint (spec §10) and is allowed; the report names them (`p2pc_udp_sockets`; a P2PC UDP socket on a well-known non-QUIC port such as 5353 fails; other services' sockets are only counted, as `ignored_non_p2pc_sockets`). From the client's network, the server's REST port at `public_host` must refuse a connection.
  Whether the client really is on another network is for you to arrange: the harness cannot know.
- **AC-9 · `ac09_mcp.py`.** Creates a key with a cap and an image allowlist (this part works today); `p2pc mcp` must
  refuse an admin key and an uncapped key; a raw JSON-RPC session over stdio lists the seven tools and runs
  `p2pc_estimate`, `p2pc_run` (called twice, with request ids 4 and 6 and the same fresh `idempotency_key`: one job; a request id is never repeated) and `p2pc_machines`; a job over the cap
  gets `402 cap_exceeded`; an image outside the allowlist is refused. The keys it creates are revoked at the end. A tool that answers
  `isError` with an API error 404, 405 or 501 for its route (`p2pc_estimate` is `POST /v1/estimate`, `p2pc_run`
  `POST /v1/jobs`, `p2pc_machines` `GET /v1/nodes`) while the route is absent from the server's OpenAPI document is
  `blocked` by the owner of that route in the map, not failed; any other error reply is a failure (a `403 forbidden`, a key short of a scope,
  included). Both `p2pc_run` calls say `wait_s: 0` (the session only checks that the retry returns the same job, so a job that cannot
  start, say a node stopped by a registry's pull limit, cannot hide the answer), and the timeout of the `p2pc mcp` call is the
  wait for the replies plus both `wait_s` plus a margin. stdin of `p2pc mcp` stays open until all six replies have arrived or 90 s have passed: a server that treats
  end-of-input as "shut down" drops the answers still in flight if it is closed right after the requests.
- **AC-10 · `ac10_scale.py`.** Submits `job_count` (100) jobs sized so that `jobs_per_node` (4) fit on the smallest
  node, and samples every second with three small server-side queries (`p2pc jobs --status assigned|running|queued --all`),
  so a poll does not grow with the number of finished jobs. The API filters by status and node only (spec §7), so the
  name prefix of the run is applied to what the server already narrowed; a job seen by two queries is kept once. The
  duration of each poll is recorded (`poll_max_s`, `poll_mean_s`, `poll_durations_s`), because a slow poll samples a
  blurrier picture. The end state is read once, with one full listing. Spec §8 limits capacity, not a count, so each
  node's limit is `floor(offered CPU / job CPU)` with **offered** taken from the inventory (`inventory.offered`), not
  from what is free: something already running on a node does not shrink the jobs, and is shown as `busy_cpu_at_start`.
  Checks: no node ever holds more than its own limit or more CPU than it offers (no double booking); every node reaches
  `min(jobs_per_node, its limit)` (for a busy node, what is still free of it), or the test did not stress the
  scheduler; all jobs `succeeded` exactly once (no lost jobs), and the
  ledger (`p2pc usage --by job|node|key`, whose `--json` is the report `{from, to, group_by, items: [{key, attempts, units, …}], total}`) has one row per job **of this run** whose units match the reserved time, and the run's key total
  equals the per-job total (node totals are at least that, other jobs ran there too). The ledger belongs to the
  account, so the run is isolated in three ways: the jobs are submitted with a **dedicated key** created for the run
  (revoked at the end, whatever happens), usage is read with `--from` the creation of the run's first job and `--to` an hour after the last one ended (spec §7,
  `GET /v1/usage ?from&to`; the CLI's own default stops at the end of the UTC day, which a run that crosses midnight would
  not survive), and rows of jobs the run did not submit are ignored. The analysis functions are
  unit-tested, including a ledger with an unrelated job in it.
- **AC-11 · `ac11_security_invariants.py`.** Which negative tests exist is read from `cargo test --workspace
  --all-features -- --list` (and `--list --ignored`). Each invariant has expected test **name patterns** (and test
  files): a test that exists is run, once, by its full name, and cargo must run as many as were listed; a test that is
  `#[ignore]`d is run with `-- --include-ignored` on a node role that sets `repo_dir` (a checkout there), and is a
  `skip` ("exists, ignored") otherwise, never missing (SI-3 needs real Podman). On a native Linux node set `test_prefix` (a command prefix, like `podman`) to run them as the node user in a systemd user service, and `test_env` (`P2PC_SHIM`…, only when the musl shim is not at its default path under `target/`; build it with `cargo build -p p2pc-shim --release --target x86_64-unknown-linux-musl`) for their environment: the evidence names the node and the prefix's first word, and a native node with `repo_dir` but no `test_prefix` gets a hint when they fail. See `machines.example.toml`. Only a pattern with no match at all is
  missing, and then: if the piece it tests has landed its test is overdue and that is a `fail` naming the missing pattern;
  otherwise the check is `blocked` by the owner in the map. A route owner has landed when the route is in the committed
  OpenAPI; a `feature` owner (server core, gateway, sandbox driver, egress proxy…) has landed when **any** other expected
  test of the same owner exists in the `--list`, so a deleted or renamed SI-4 test is a `fail`, not "waiting". The agent's
  connection is asked of the agent (`p2pc-agent status`, offline, as `--list` does), so a missing SI-12 runtime test is a
  `fail` once the agent connects. A renamed test is therefore a missing test, never a
  silent pass. Anything whose function name starts with `si<N>_` is part of invariant N with no change here (cargo's
  filters match the function's path, not the file). The expected patterns include the ones of the node gateway now on `main`
  (`another_accounts_nodes_and_tokens_are_invisible`,
  `unknown_messages_keep_the_connection_and_malformed_frames_close_it`, the join-token tests of `gateway.rs`,
  `no_secrets_in_gateway_logs`). The pentest is manual evidence.
- **AC-12 · `ac12_supply_chain.py`.** Runs **today, locally**: `cargo deny check`; `gitleaks git` over the whole
  history (`skip`, with the install hint, if gitleaks is not installed); the SBOM with `cargo cyclonedx`, generated in a
  temporary copy of the files git tracks and never in the operator's tree (`skip` if it
  is not installed; the documents are kept in the report's `artifacts/`); `SECURITY.md` present and non-empty;
  `scripts/check-spdx.sh`. The stranger's walkthrough of AC-1 to AC-3 is manual evidence.

## The report

Each run writes a new directory `reports/<UTC timestamp>/` with:

- `report.json`: for each criterion the status, the reason, the tasks that block it, the timings, and for each check
  the commands run with their exit codes, durations and short output excerpts. The schema number is in `schema`.
- `report.md`: the same for people, starting with a table and a verdict.
- `artifacts/`: files a criterion keeps as evidence (the SBOM, the gitleaks findings).

`reports/` and `machines.toml` are git-ignored. A report holds your real ssh aliases, command lines and job output:
read it before you share it. Secrets are redacted, but the harness cannot know what else is private to you.

## When a task lands

Nothing in the harness is edited. Run the criteria it unblocks (`./run.py --machines machines.toml --only AC-2`): a
route that now exists in the OpenAPI, a subcommand that is no longer a stub, an agent whose `status` answers, and tests
that now show up in `cargo test -- --list` are all seen by the next run, and what was `blocked` is run. A step that
now fails is a real result: fix the product, or, if the harness assumed something wrong, the script. `./run.py --list`
refreshes the table above. The only edits are the ones that add knowledge: a new piece goes into `OWNERS` (and into a
script's `NEEDS` if the script depends on it), and a new negative test is picked up when its function name starts with
`si<N>_`, or is added to the patterns of its invariant in `ac11_security_invariants.py`.

## Tests of the harness

```sh
python3 -m unittest discover tests/acceptance
```

They cover the machines-file schema and its errors, the executor quoting (a command with quotes and spaces through
`wsl_over_ssh`, decoded and run with a real shell), redaction, report rendering, the status rules (`blocked` is never a
`pass`), the runner, the analysis functions, and each script against scripted machines. No network and no real machine.

## Assumptions re-checked against `main` (T15b)

The scripts were written from the spec and `docs/cli.md` before most pieces existed. T15b read every assumption and every
CLI call and JSON field the scripts use against the code on `main` (`crates/p2pc-cli`, `docs/cli.md`,
`docs/api/openapi.json`, `crates/p2pc-cli/src/mcp/tools.rs`, `p2pc-agent --help`). What did not hold was fixed in the
scripts; what held is not listed again.

**What was wrong, and what changed**

| Assumed | On `main` | Change |
|---|---|---|
| `p2pc usage --group-by job\|node\|key` | the flag is `--by` (`--group-by` is a clap error) | AC-6 and AC-10 use `--by`; AC-10 also passes `--to` (the CLI's default stops at the end of the UTC day) |
| `p2pc usage --json` is an array of ledger rows (`job_id`, `units`, `reserved_cpu_ms`) | it is the report `{from, to, group_by, items: [{key, attempts, units, reserved_cpu_ms, …}], total}`: rows are per group, named `key` | the analysis already read `items` and `key`; the scripted machines now return the real report |
| `p2pc run --json` prints the job | it prints NDJSON: the log records, then the final job as the **last line** | `ctx.final_job` / `Step.final_json`; AC-2 and AC-7 read the last line, and AC-2 also checks the live log record |
| an attempt's `started_at` is always a string | it is `null` until `JobStarted` (spec §7, amended 2026-11-06) | `started_at` may be null; a succeeded attempt must have one |
| `join-token create` output has `join_token` | it does, and also `id` and `expires_at` | AC-1 passes `--expires 15m`, and `join-token list` must show the token consumed by the node |
| an image outside the key's allowlist is 403 or 422 | `403 image_not_allowed` | AC-9 already asked for exactly that; this note was stale |
| `p2pc run … \| head -1` detaches with 130 and the hint while the job runs (spec §7, amended 2026-11-06) | **not on `main`**: `run` ends 0, silently (`run.rs` → `app.rs`); the code is T11b3 (PR #27) | **a disagreement between the spec and the product, written down, not papered over.** The check is `blocked` by T11b3 until `docs/cli.md` of the checkout mentions the rule; `MainWorld` answers what `main` does |
| the nodes are a Linux GPU node and a WSL2 GPU node | the first real lab has a Linux node **without** a GPU | new role `node_linux` |
| the harness copies `p2pc-agent`, runs `join -`, and starts it with `nohup` | `install-node.sh` installs the agent and the shim, enrolls it as user `p2pc` and starts the systemd user unit; `install.ps1 -Join` enrolls it and registers the "P2PC node" task | AC-1 runs the installers; the harness's own join stays only for a node with no `install_command` |
| a joining node is the one that was not in `p2pc machines` before | `--force` / `-Force` re-enrolls **the same node** (same id) | the node is the one that consumed the token (`join-token list`) |
| the Windows installer can be run in the distro | `install.ps1` is a Windows script (`-Tar`, `-Join`, `-Status`, …) that drives `wsl.exe` itself; the token is its pipeline. The default PowerShell policy of a Windows client (`Restricted`) refuses any `.ps1` | `run_on_host` / `image_install_command` / `install_command` of a WSL role run on the host with `-ExecutionPolicy Bypass` (this process only); a script downloaded from the internet may still need `Unblock-File .\install.ps1` |
| Podman on a Linux node is `sudo -u p2pc -H podman` | the agent runs as `p2pc` (home `/var/lib/p2pc`) under its user unit, which has the runtime directory | the example sets `XDG_RUNTIME_DIR` for it, and starts with `cd /`: `sudo -u p2pc` keeps the ssh user's home as the current directory, which `p2pc` cannot read (0700 on Arch, 0750 on Ubuntu since 21.04), and podman ends with "cannot chdir". The command is `["sudo", "-u", "p2pc", "-H", "sh", "-c", "cd / && XDG_RUNTIME_DIR=/run/user/$(id -u) exec podman \"$@\"", "podman"]` |

**Checked and held** (no change needed): how a log follow ends (spec §7, amended 2026-11-06: the body ends cleanly only when the attempt is over; the CLI reopens from `next_seq` after any earlier end, with outages tracked per route and at most 5 minutes each), which the harness meets only through `p2pc run` and `logs --follow` of jobs that end, with generous timeouts; the installers' contracts: the token is only ever on stdin or in the pipeline, an
argument that holds one is refused (exit 2); `install-node.sh` exits 0, 1 or 2, logs to `/var/log/p2pc-node-install.log`, ends
with `Joined: <node> on <server>`, and `--uninstall [--purge]` keeps or deletes the enrollment; `install.ps1 -Join` ends with
the same line, `-Join -Force` re-enrolls the same node, `-Stop`/`-Start` take the task offline/online, its exit codes are those
of its header, and `/var/lib/p2pc/node-run.status` is `state=running|restarting|stopped` (plus `exit_code=`, `reason=`); `results JOB --out DIR` (each file verified against size and sha256 by the CLI,
exit 125 on a mismatch or an existing file without `--force`); `logs JOB [--follow] [--attempt K]` (returns 0 when the log
ends, 125 and a 404 for an attempt that does not exist; `?attempt=K` is the REST form); `--file LOCAL:/inputs/PATH` and
the 512 KiB limit; `--timeout` as a duration; `machines rm NAME --yes` (no script runs it, since removing a node would end
the run: AC-1 only quotes it as the way to start over); `GET /v1/server` returns `address` and `p2pc proxy` reads the
server from `P2PC_SERVER`; the MCP tools take `image`, `command`, `cpu`, `memory_mb`, `timeout_s` (and `deny_unknown_fields`
refuses any other), answer with `job_id`, speak newline-delimited JSON-RPC, and the same `idempotency_key` gets the same job, whatever the request id
(`crates/p2pc-cli/tests/mcp.rs`); `p2pc mcp` refuses an admin or an uncapped key with exit 125 and says why;
`p2pc-agent join -` reads the token from stdin and exits 3 when the machine is already enrolled; the exit codes of spec §7
(0, the job's own, 75, 124, 125, 130, with the amended 130 rule for a closed stdout) are those of
`crates/p2pc-cli/src/outcome.rs`.

**Still assumed, because only a real run can tell**

- The agent the harness starts with `nohup p2pc-agent run` uses the config that `p2pc-agent join` wrote (the same user,
  the same default path). Give `agent_start_command` when the agent runs as another user.
- `podman` as given in the machines file sees the containers of the agent (AC-6 and AC-7 are `skip`, never `pass`, when it
  does not).
- A cut network (`partition_command`) is detected by the server within `lease_ttl_s + 90` s, and `lease_ttl_s` in the
  machines file equals the server's.
