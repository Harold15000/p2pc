# deploy/: server install, node images and host setup

How the P2PC server is installed and how P2PC nodes are prepared. Spec references are to `docs/specs/H1-personal-cloud.md`; "E1" and "E8" are the
experiments behind spec §9.0.

| Path | What it is |
|---|---|
| `wsl/build-rootfs.sh` | Builds the `p2pc-node` WSL2 distro image (Ubuntu 24.04 rootfs + Podman + skopeo + NVIDIA toolkit). |
| `wsl/packages.lock` | The exact package versions that go into the image. |
| `wsl/p2pc-boot` | Runs at every distro start: refreshes the NVIDIA CDI spec, writes a status file. |
| `wsl/install.ps1` | Windows installer: checks, install, join (`-Join`), status, upgrade, uninstall. |
| `wsl/p2pc-node-run` | Runs in the distro (from the "P2PC node" Scheduled Task): keeps `p2pc-agent run` running, with a backoff and a rotated log. |
| `wsl/nvidia.sh` | The one definition of "is there an NVIDIA GPU behind `/dev/dxg`?", installed as `/usr/local/lib/p2pc/nvidia.sh` and sourced by `p2pc-boot` and `test-distro.sh`. |
| `wsl/boot-status.sh` | The one definition of "is the boot status from this start of the distro?", installed as `/usr/local/lib/p2pc/boot-status.sh` and sourced by `p2pc-boot`, `test-distro.sh` and `p2pc-node-run`. |
| `wsl/test-distro.sh` | Checks the §9.0 profile end to end, inside the imported distro. |
| `linux/install-server.sh` | Installs the server (`p2pc-server`) as a hardened systemd service, in one command. |
| `linux/p2pc-server.service` | The server's systemd unit. |
| `linux/install-node.sh` | Joins a Linux machine as a node, in one command: host setup, agent, enrollment, service. |
| `linux/p2pc-agent.service` | The agent's systemd **user** unit (user `p2pc`, rootless Podman). |
| `../scripts/release.sh` | Builds the static, checksummed release artifacts into `dist/<version>/`. |
| `linux/setup-host.sh` | Prepares a native Linux node (rootless Podman as user `p2pc`); `install-node.sh` runs it. |
| `check.sh`, `tests/` | Static checks and unit tests for all of the above (CI runs `deploy/check.sh`). |

## Join a machine (spec §14 AC-1: one command plus the token)

On a machine with an admin key, create a single-use token. It is printed once, on a line of its own; no command it
suggests contains it:

```bash
p2pc join-token create --label spare-pc
```

The token is a secret until it is used. Never put it on a command line (`ps`, the shell history and the Windows
command line of a process show it to others): every installer below asks for it with hidden input, or reads it from
stdin or the pipeline, and hands it to `p2pc-agent join -` on its stdin only.

### Join a Linux machine

With the release directory on the machine (`dist/<version>/` of `scripts/release.sh`, copied over, or an `https://` URL
with the same files):

```bash
sudo sh 0.1.0/install-node.sh --from 0.1.0          # paste the token when asked
```

Any Linux with systemd works, on x86_64 or aarch64. **Supported by the installers:** Ubuntu 22.04, 24.04 and 26.04,
Debian 12 and 13, and Arch Linux (and distributions based on it), covered by the installers' tests (`deploy/tests/`,
with fake system commands). For a Linux node the distribution must also ship Podman ≥ 4.9 (Ubuntu 24.04+, Debian 13,
Arch); on Ubuntu 22.04 and Debian 12 only the server works without a newer Podman. **Tested end to end on real machines:** Ubuntu 24.04 and an Arch-based distribution. On any
other distribution the installer prints one warning line ("not a tested platform") and goes on. It stops only when a
requirement is missing (root, a running systemd, `systemctl`, `runuser`, `useradd`, `sha256sum`, `tar`, `bash`, `curl`
or `wget`), and it names that one; `setup-host.sh` then checks Podman, crun and cgroup delegation.

Every `p2pc-agent` command the installer runs, the final `doctor` included, starts in `/`, so a directory the user
`p2pc` cannot enter (your 0700 home) never causes a false "cannot chdir". If that last `doctor` still says NOT READY, the
installer prints doctor's text and a warning next to the `Joined:` line, with the fix hint, and still exits 0: the join
worked, but the node will not run jobs until the listed items are fixed. Check again with
`sudo runuser -u p2pc -- sh -c 'cd / && exec p2pc-agent doctor'` (from `/`: run from your own 0700 directory it
fails with a false "cannot chdir").

Or, without a terminal: `sudo sh 0.1.0/install-node.sh --from 0.1.0 < token.txt` (see "Scripted or CI install" below
for how to get `token.txt`). An argument that holds a token
(`p2pc_join_…`) is refused with exit 2 before anything runs or is logged, and is never echoed; an unknown option is
never echoed either. The user `p2pc` must have the home `/var/lib/p2pc` in the passwd database (where the unit's agent
looks for its enrollment): any other home is refused, for the install and for `--purge`. Each step is checked
(`install-node.sh` reruns are idempotent; `--version V` picks a version when `SHA256SUMS` lists several):

1. every file it uses is checked against `SHA256SUMS`: the agent and `p2pc-shim` tarballs, `setup-host.sh`,
   `p2pc-agent.service`. A release without `p2pc-shim` is refused: the agent takes no lease without it;
2. it runs that `setup-host.sh` (the user `p2pc`, subuid/subgid, linger, the cgroup delegation check, Podman ≥ 4.9 and
   crun, CDI with an NVIDIA GPU; see "Native Linux" below). **A host that is not ready stops here**, with
   `setup-host.sh`'s fixes printed, before anything of the agent is installed or enrolled;
3. it installs `/usr/local/bin/p2pc-agent`, `/usr/local/bin/p2pc-shim` (next to the agent, where its executor looks for
   it) and the user unit `/etc/systemd/user/p2pc-agent.service`;
4. it enrolls, as `p2pc`, from `/`:
   `runuser -u p2pc -- sh -c 'cd / && exec "$@"' sh env -i ... p2pc-agent join -`. The script moves its own stdin to
   another descriptor (fd 3) first and gives it only to that command, as its stdin. Every other command it runs gets fd 3
   closed, and fd 3 is closed for good right after the join, so nothing else can read the token; on a terminal the agent
   asks for it (hidden input). An enrolled machine is not enrolled again unless you pass `--force`, which re-enrolls
   this machine as **the same node** (spec §5; the unit is stopped during the join, and started again if it fails).
   To retire a machine instead, remove it on the server with `p2pc machines rm`;
5. `systemctl --user -M p2pc@ enable p2pc-agent` (works without `systemd-container`, measured), then start (restart
   when a binary, the unit or the enrollment changed), and waits up to 60 s for `Connection: connected`. If the agent
   stops right away it says why from its exit status: 7 (removed from the server: rerun with `--force` and a new
   token), 6 (too old: a newer release);
6. it prints `p2pc-agent doctor`, the status line and `Joined: <node> on <server>`.

The agent then runs from boot (linger), as `p2pc`, with rootless Podman. The unit restarts it on failure, except on
the agent's terminal exit codes (6 agent too old, 7 removed from the server, 8 never joined). It carries the hardening a
user unit can take without breaking rootless Podman (`UMask=0077`, `LimitCORE=0`, `KeyringMode=private`) and, on
purpose, **no** `NoNewPrivileges=yes`: rootless Podman needs the setuid `newuidmap`/`newgidmap`; the unit's header
explains each setting it leaves out. Exit codes of the installer: 0 done, 1 failed or refused, 2 usage error. Its log:
`/var/log/p2pc-node-install.log` (0600; never the token).

### Join a Windows machine

With the `p2pc-node` distro installed (section "Windows (WSL2)" below; the image must be built with the agent and
`p2pc-shim`, `--agent-from`), from PowerShell, as yourself:

```powershell
.\install.ps1 -Join                                   # paste the token when asked (hidden)
Get-Content .\token.txt | .\install.ps1 -Join         # or from the pipeline
```

`-Join` refuses a token given as an argument (exit 2, and it echoes nothing). It writes the token to the stdin of
`wsl.exe -d p2pc-node -u root --exec /usr/bin/env P2PC_AGENT_CONFIG=/var/lib/p2pc/agent.toml /usr/local/bin/p2pc-agent join -`,
then registers and starts the per-user Scheduled Task **"P2PC node"**, running
`conhost.exe --headless cmd.exe /d /s /c ""%LOCALAPPDATA%\P2PC\node-task.cmd""` (no window): a small wrapper the
installer writes and owns, which runs `wsl.exe -d p2pc-node -u root --exec /usr/local/sbin/p2pc-node-run` (see "When
the node stops for good" below). The task runs as you, never elevated (`RunLevel Limited`, `LogonType Interactive`): no
time limit, restarted on failure, allowed on battery, `IgnoreNew`, `StartWhenAvailable`. That attached `wsl.exe` keeps
the distro running; `.wslconfig` is never changed (`instanceIdleTimeout` would affect every distro). It waits up to 60 s
for the agent to connect and ends with `Joined: <node> on <server>`. A rerun re-registers the task (and rewrites the
wrapper); `-Join -Force` re-enrolls this machine with a new token, as **the same node** (spec §5: a join from a NodeId
the server knows keeps that node and its id). To retire a machine instead, remove it on the server with
`p2pc machines rm`. Whenever the installer starts or restarts the task (`-Join` after an enrollment or on a
stopped task, `-Start`, `-Upgrade`), only a connection made **since that start** counts: the agent's state file can still
say "connected" from before (measured: `-Join` after `-Stop` showed a connection 11 minutes old). A task that already
runs keeps its agent, and its current connection is taken as it is.

**The task's triggers (spec §9.0).**
- **Every 5 minutes, with no end:** a watchdog. With `IgnoreNew` it does nothing while the node runs; when the task has
  ended, for example after `wsl --terminate p2pc-node` (the task then ends with `0x0` and Windows does not restart it),
  it starts the node again within 5 minutes. It is always registered.
- **At your sign-in, for your user only** (`New-ScheduledTaskTrigger -AtLogOn -User <you>`): always, elevated or not. A
  normal user may register it (measured with a Limited, medium-integrity token); Windows refuses only a logon trigger
  for *any* user (`-AtLogOn` without `-User`, or `schtasks /SC ONLOGON`), which P2PC never asks for.
- If Windows refuses the registration anyway (access denied), `-Join` registers the 5-minute trigger alone and says:
  the node starts within 5 minutes of signing in. If even that is refused, it stops with exit 35; it never falls back
  to another way of starting the agent.

**Stopping the node.** Stopping the task alone does **not** stop the node: `Stop-ScheduledTask` kills `conhost`, but
its `wsl.exe`, `p2pc-node-run` and the agent keep running (measured), and the task then shows `Ready`. Use:

```powershell
.\install.ps1 -Stop      # disable the task, stop it, then wsl --terminate p2pc-node: offline until -Start
.\install.ps1 -Start     # enable the task and start it
```

`-Stop` keeps the task disabled, so neither your sign-in nor the 5-minute trigger starts the node again, and neither
does `-Upgrade`: a node stopped with `-Stop` stays stopped after an upgrade, until `-Start`.

**When the node stops for good** (spec §9.0, "Terminal exits stop the node for good, watchdog included"). The agent's
terminal exits are 6 (the server refuses this agent version), 7 (the server removed this node) and 8 (not joined).
Retrying cannot help, and the 5-minute trigger would otherwise start such a node again within 5 minutes, forever:
booting the WSL VM on the PC and dialing the server with a revoked identity. So:
- `p2pc-node-run` records why in `/var/lib/p2pc/node-run.status` and exits **64**;
- the wrapper then **disables the task** (`schtasks /Change /TN "\P2PC node" /DISABLE`) and writes
  `%LOCALAPPDATA%\P2PC\stopped-by-node` next to itself, with the code, the time, the reason and whether the disable
  worked. Last, it runs `wsl --terminate p2pc-node`, best effort: nothing runs in the distro any more, and an idle
  distro left Running keeps the WSL VM and its memory up (measured: still Running 6 minutes after the stop). Its result
  changes neither the record nor the wrapper's exit code. The PC then runs nothing of P2PC until you act;
- `.\install.ps1 -Status` shows it ("STOPPED FOR GOOD", the code and the time) and what to run:
  - after 7 or 8: a new token from `p2pc join-token create`, then `.\install.ps1 -Join -Force` (`-Join` without
    `-Force` refuses, since the old enrollment no longer works);
  - after 6: a newer image, `.\install.ps1 -Upgrade -Tar <newer image>`, which enables the task again by itself;
  - when the record has no code (the wrapper reads it from the distro, and under load `wsl.exe` can fail with
    `Wsl/Service/0x8007274c`), the installer reads it again from `node-run.status`, through the same retry. If it is
    still unknown, `-Status` says so and points at the agent log, and `-Join` and `-Upgrade` say "unknown: see
    `-Status`" instead of guessing the advice;
- `-Join`, `-Start` and (after 6 only) `-Upgrade` forget the record and enable the task again. An
  `-Upgrade` after 7, 8 or an unknown code leaves it off (even when the wrapper's disable failed and the task is
  still Ready: the stop record decides), and a node stopped with `-Stop` stays stopped.
- An ordinary end (the agent asked to stop, `wsl --terminate`, a WSL update) leaves the task enabled: the watchdog
  brings the node back.

The rights: after registering the task, the installer gives full control of it to SYSTEM, Administrators and **you**
(`D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<your SID>)`), through the Task Scheduler COM API
(`Schedule.Service` → `GetTask("P2PC node").SetSecurityDescriptor(<sddl>, 0)`). Without it, a task registered from an
elevated PowerShell gives you only read access (`FR`), and your own non-elevated wrapper is denied the `/DISABLE`
(measured on Windows 11, build 26200; after the call it succeeds). A non-elevated registration already gives you full
control, and the call does no harm there. If Windows refuses the call, the task stays registered with its default
rights, with a warning. As a fallback in either case, `p2pc-node-run` keeps a stamp of a terminal stop (the SHA-256 of
`agent.toml` and of the agent binary). At its next start it exits 64 at once, without running the agent, while that
stamp still matches. A new enrollment or a newer agent changes the stamp.

`.\install.ps1 -Status` shows the task's state, then `p2pc-agent status` and `p2pc-node-run`'s status from the distro,
and reports an **orphan** (the agent runs but the task does not, so nothing supervises it) with what to run:
`.\install.ps1 -Stop`, then `.\install.ps1 -Start`. It also warns when the task does not run the wrapper (a task
registered by an older `install.ps1`, which would never stop the node for good), and says to run `.\install.ps1 -Join`
(which registers it again, and starts the node).

**A busy WSL.** Under load `wsl.exe` can fail with `Wsl/Service/0x8007274c` (a WSL service timeout) before anything runs
in the distro. The installer retries a `wsl.exe` call on that error only, up to 3 times, 5 s apart (for `-Join` the
token stays in memory, and the agent never got it). If a `-Join -Force` still fails, the task that ran before is
enabled and started again, on the previous enrollment.

Inside the distro, `/usr/local/sbin/p2pc-node-run`:
- runs one at a time (a lock in `/run`). A second one, started while the first still runs (for example after the task
  was stopped, which leaves the first one alive), **waits** for the lock and takes over when the first one ends, so its
  own `wsl.exe` stays attached;
- waits up to 60 s for the boot status of this start of the distro (see "The boot status can arrive late" below), then
  starts the agent anyway;
- runs `p2pc-agent run` with a clean environment (nothing from Windows: no `WSL_INTEROP`, no `WSLENV`), without the
  lock's descriptor (an agent that outlives its runner never keeps the next one out) and with SIGHUP ignored (on
  SIGTERM, SIGINT or SIGHUP the runner stops the agent with TERM, so it stops its jobs cleanly);
- restarts it after an unexpected exit, after 1 s, doubling up to 60 s, and back to 1 s once a run lasted 60 s;
- stops on exit 0 (asked to stop) and exits 0; stops for good on the terminal codes 6, 7 and 8 and exits 64, so that
  the wrapper disables the task (above). Why it stopped is in `/var/lib/p2pc/node-run.status` (`state=`, `exit_code=`,
  `reason=`, `time=`, and for a terminal stop `stamp=`).

### Scripted or CI install (no terminal)

With no terminal (a script, CI, an agent) the admin key must not go to whatever reads the installer's output. Give
`install-server.sh` a path, and the key is written there instead, created new with mode 0600 and printed nowhere else.
It refuses a path that already exists. The whole chain, on the server host:

```bash
sudo sh 0.1.0/install-server.sh --from 0.1.0 --admin-key-file K     # K: a new path in a private dir
p2pc login --server http://127.0.0.1:7477 --key-stdin < K
shred -u K                                                          # rm -f K where shred is missing
```

Run through `sudo`, the installer gives K to the user who ran `sudo` (`SUDO_USER`), mode 0600, and says so, so the next
two commands work without sudo. Run as root with no `SUDO_USER`, K stays root's: use the root form,
`p2pc login --server http://127.0.0.1:7477 --key-stdin < K` and `shred -u K` as root. K is created through a temporary
file linked into place, so an existing path (a FIFO or a symlink too) is refused, as is a directory that group or others
can write to without the sticky bit.

`--admin-key-file` only writes a key on a first install; on a server that already exists it writes nothing and says so.
Keep K in a directory only you can read, and delete it as soon as the login works. For the join token, save only the
token (no other text around it) and feed it to the node installer:

```bash
(umask 077; p2pc join-token create --token-only > token.txt)       # mode 0600: the token and a newline, nothing else
sudo sh 0.1.0/install-node.sh --from 0.1.0 < token.txt             # on the node
shred -u token.txt                                                  # rm -f token.txt where shred is missing
```

If you create the token on another machine, copy `token.txt` to the node over a private channel
(`scp`, keeping mode 0600), or run `p2pc join-token create --token-only` on the node itself when it has `p2pc` logged
in. The token is single use and expires in 15 minutes, but it is still a secret until then: never commit the file or
leave it behind on either machine (`shred -u`, or `rm -f` where `shred` is missing).

### Where the logs are

| Machine | What | Where |
|---|---|---|
| Linux node | The agent | `sudo journalctl _UID=$(id -u p2pc) _SYSTEMD_USER_UNIT=p2pc-agent.service` (`-f` to follow): p2pc's user journal. Not `journalctl --user -M p2pc@`: that needs `systemd-container`, which `apt install podman` does not bring (measured on Ubuntu 24.04) |
| Linux node | The installer | `/var/log/p2pc-node-install.log` |
| Windows node | The agent and `p2pc-node-run` | inside the distro, `/var/log/p2pc/agent.log`, rotated by size: `agent.log`, `.1`, `.2`, 10 MiB each (the distro has no journald): `wsl -d p2pc-node -u root --exec /usr/bin/tail -f /var/log/p2pc/agent.log` |
| Windows node | Why the agent stopped for good | `wsl -d p2pc-node -u root --exec /bin/cat /var/lib/p2pc/node-run.status`, or `.\install.ps1 -Status` |
| Windows node | The installer | `%LOCALAPPDATA%\P2PC\logs\install-<time>.log` (never the token) |
| Server | The control plane | `journalctl -u p2pc-server`; installer: `/var/log/p2pc-server-install.log` |

### Troubleshooting a Linux node

**`cgroup_not_delegated: cgroup controllers not delegated to this user: cpu …`** (in `p2pc-agent doctor`, and as the
sandbox's problem in `p2pc machines`). The node joined, but its sandbox is not ready, so no job is placed on it.

What it means: rootless Podman enforces the CPU, memory and PID limits of a job through cgroup controllers, and systemd
only hands those to a user when it **delegates** them to that user's manager, `user@<uid>.service`. The agent reads
what that unit delegates (the same place `setup-host.sh` reads it), not what its own cgroup has turned on: systemd
turns a controller on in `app.slice` and in the agent's unit only when some unit there asks for it, while the
containers get their own scopes, for which `user@` delegates the controller on demand. The message names the file it
read, and which controllers are missing.

How to check it (as any user; `p2pc` is the node's user):

```bash
uid=$(id -u p2pc)
cat /sys/fs/cgroup/user.slice/user-$uid.slice/user@$uid.service/cgroup.controllers   # must list cpu memory pids
systemctl show user@$uid.service --property=DelegateControllers --value             # what the unit is configured to give
```

If `user@` lists `cpu memory pids`, the agent's own cgroup is not the problem (the unit sets `CPUWeight=100` so that
systemd turns `cpu` on there too, and `podman info` agrees). If it lacks one, delegate them, as root:

```bash
mkdir -p /etc/systemd/system/user@.service.d
printf '[Service]\nDelegate=cpu cpuset io memory pids\n' > /etc/systemd/system/user@.service.d/p2pc-delegate.conf
systemctl daemon-reload && systemctl restart user@$(id -u p2pc).service   # or reboot
```

Then **restart the agent** (`sudo systemctl --user -M p2pc@ restart p2pc-agent`). It builds its sandbox driver once, when
it starts, so a node that becomes ready later stays not ready until the agent restarts; the problem line in the
inventory is re-checked every 10 minutes, but it does not make the driver ready. On a unit installed before
`CPUWeight=100` was added, re-run `install-node.sh` (or copy the new unit and run `systemctl --user -M p2pc@
daemon-reload`) so that `podman info` agrees too.

### How to remove it

Linux:

```bash
sudo sh install-node.sh --uninstall           # stop and disable the unit, remove it, /usr/local/bin/p2pc-agent and
                                              # /usr/local/bin/p2pc-shim;
                                              # the identity and the enrollment stay (a rerun of the install resumes)
sudo sh install-node.sh --uninstall --purge   # also delete the agent's config and identity (asks you to type "purge";
                                              # --yes skips it): /var/lib/p2pc/.config/p2pc-agent and
                                              # /var/lib/p2pc/.local/share/p2pc-agent, and nothing else
```

A purge deletes nothing while the agent runs (the unit, or a `p2pc-agent` of `p2pc` outside it), and it deletes as
`p2pc`, so a symlink in that home cannot point it anywhere else. A `data_dir` moved elsewhere in `agent.toml` is named,
never deleted. A second `--uninstall` (or `--purge` after `--uninstall`) does not touch the unit that is already gone.
What stays, and how to remove it too: the install log `/var/log/p2pc-node-install.log` (`sudo rm` it), the user `p2pc`
with its home, Podman's images and containers
(`sudo userdel -r p2pc`), linger (`sudo loginctl disable-linger p2pc`, before `userdel`), the sub-id ranges in
`/etc/subuid` and `/etc/subgid`, `/etc/cdi/nvidia.yaml`, and any `/etc/systemd/system/user@.service.d/p2pc-delegate.conf`
you added. Remove the node on the server too: `p2pc machines rm <name>`.

Windows: `.\install.ps1 -Uninstall` stops and removes the "P2PC node" task first, then unregisters the distro (section
5 below has the details and the backups); when the distro is already gone it still removes the task. `.\install.ps1
-Upgrade` disables and stops the task, upgrades, registers the task again (so a node installed by an older
`install.ps1` gets the wrapper and the rights above), and enables and starts it again. The new registration is made
disabled: a task that was disabled before the upgrade (`-Stop`, or a terminal stop after 7, 8 or an unknown code, even
if the wrapper's disable failed) stays Disabled. If the
new registration fails, the task keeps its previous definition, with a warning.

## Windows (WSL2)

The node is a **dedicated distro named `p2pc-node`**. It is an appliance: the agent is its only tenant, it has no
Windows drives, no Windows interop and no systemd. The installer only ever creates, replaces or removes this one distro.
It never touches your other distros, `.wslconfig` or Windows features; when one of those is the problem it prints the
command for you to run.

### 1. Build the image (on a Linux build host or inside an Ubuntu WSL distro, as root)

```bash
sudo deploy/wsl/build-rootfs.sh --dry-run --agent-from dist/0.1.0               # print the plan; no root, no network
sudo deploy/wsl/build-rootfs.sh --out ./out --agent-from dist/0.1.0 [--version 0.2.2]
```

Outputs: `p2pc-node-<version>.tar.gz`, `p2pc-node-<version>.tar.gz.sha256`, `manifest.txt` (every package and version).
The image version is 0.2.2 by default (0.2.0 added the agent, `p2pc-node-run`, `boot-status.sh` and `/var/log/p2pc`;
0.2.1 adds `p2pc-shim` and the `p2pc-node-run` that waits for the lock; 0.2.2 moves the agent's config into
`/var/lib/p2pc/agent.toml`, see below).

**All mutable node state lives in `/var/lib/p2pc`**, the one directory `-Upgrade` carries over. Inside the distro the
agent runs as root, and as root it would read `/etc/p2pc/agent.toml`, which an upgrade replaces with the image's: up to
0.2.1 that is where `join` wrote `[server]`, so an upgrade kept the identity key but lost the enrollment, and the agent
stopped with "not joined" (exit 8). From 0.2.2 the config is `/var/lib/p2pc/agent.toml` (mode 0600): the image ships it
with no setting (the built-in defaults; the image never had an `/etc/p2pc/agent.toml` either), `p2pc-node-run` and every
agent call of `install.ps1` name it with `P2PC_AGENT_CONFIG`, and `join` writes `[server]` into it. To run the agent by
hand inside the distro, name it too:
`wsl -d p2pc-node -u root --exec /usr/bin/env P2PC_AGENT_CONFIG=/var/lib/p2pc/agent.toml /usr/local/bin/p2pc-agent status`.
`-Join` refuses an image up to 0.2.1 (exit 32): upgrade it first.

**The agent comes from the release.** `--agent-from <dist dir>` takes `p2pc-agent-<v>-x86_64-unknown-linux-musl.tar.gz`
from the `dist/<version>/` that `scripts/release.sh` wrote, after checking it against that directory's `SHA256SUMS`
(already in the dry run; a mismatch, a missing file or several versions without `--agent-version V` stop the build),
copies it into the build's work directory, checks it again there, and installs its `p2pc-agent` as
`/usr/local/bin/p2pc-agent`. It does the same with `p2pc-shim-<v>-x86_64-unknown-linux-musl.tar.gz` (the same version),
installed as `/usr/local/bin/p2pc-shim`, next to the agent: the agent's executor takes no lease without it, so a dist
without it is refused. `manifest.txt` records both tarballs and their SHA-256. `--agent <path>` (a developer build,
checked against nothing, with `--shim <path>` for the shim) still exists; it cannot be combined with `--agent-from`. An
image without the agent or the shim builds fine, but `install.ps1 -Join` refuses it (exit 32).

What the builder does, and why:

- Downloads the pinned Ubuntu 24.04.5 WSL image and **verifies its SHA-256** before unpacking (nothing unverified is used).
- Points apt at the **Ubuntu snapshot archive** named by `snapshot=` in `packages.lock`
  (`https://snapshot.ubuntu.com/ubuntu/<timestamp>`: noble, noble-updates, noble-security), runs `apt-get -y upgrade`
  against it (the image gets every security fix up to the snapshot, and the same snapshot always gives the same
  packages), then installs the packages of `packages.lock` with `--no-install-recommends`. The stock Ubuntu sources are
  put back before the image is packed. NVIDIA's apt key is downloaded (the key behind `nvidia.github.io/libnvidia-container/gpgkey`, "NVIDIA CORPORATION (Open Source Projects)", fingerprint `C95B321B61E88C1809C4F759DDCAE044F796ECB0`; not the CUDA repository key), and its
  **fingerprint is pinned and checked** (exactly one primary key, equal to the pin) before apt is told to trust it.
- Deletes `/etc/wsl-distribution.conf` (the Ubuntu `.wsl` base ships it with an OOBE `command=/usr/lib/wsl/wsl-setup` and
  `defaultUid=1000`, which would make the first launch ask for a user name and create a login user): the distro is a
  root-only appliance and the agent is its only tenant.
- Writes the configuration of the table below, creates `/var/lib/p2pc` (mode 0700) and `/etc/p2pc-distro-version`.
- Cleans apt lists and caches, empties `/etc/machine-id`, removes ssh host keys, logs and shell history.
- Unpacks the base image and packs the result with `--xattrs --xattrs-include=security.capability`, so file capabilities
  (`setcap`, for example `cap_net_raw` on `/usr/bin/ping`) survive; the tar is PAX, the only format that can carry them,
  with fixed extended-header names so it stays reproducible. `p2pc-test-distro` checks `getcap /usr/bin/ping`.
- Packs a deterministic tar: `--sort=name --mtime=@$SOURCE_DATE_EPOCH --numeric-owner --format=pax`, `gzip -n`. The same rootfs gives
  the same bytes. `SOURCE_DATE_EPOCH` defaults to the **commit time of the checkout** (`git log -1 --format=%ct`), so the
  same commit gives the same timestamps; without git it falls back to the current time **with a warning** (set
  `SOURCE_DATE_EPOCH` yourself to override). Ubuntu packages come from the pinned snapshot, NVIDIA's four packages are
  pinned exactly (NVIDIA's repository is not snapshotted), and `manifest.txt` records the full closure. Package
  maintainer scripts and the build itself are not guaranteed bit-for-bit, so compare `manifest.txt`, not the tar hash.
- Mounts `/proc`, `/sys`, `/dev` into the chroot and **unmounts them on any exit** (`trap`). It will not delete its
  temporary directory, or pack the tar, while anything is still mounted under it. It unmounts from its own list in
  reverse order *and* from `/proc/self/mountinfo` (decoding the kernel's `\040`-style escapes), canonicalises the work
  directory (a `TMPDIR` with a trailing slash or a symlink is fine) and refuses one with whitespace or a backslash; the
  final `rm -rf` uses `--one-file-system`. It writes nothing outside that directory and `--out`.
- With `--agent-from <dist>` (or `--agent <path>` and `--shim <path>`) the binaries are installed as
  `/usr/local/bin/p2pc-agent` and `/usr/local/bin/p2pc-shim` (see above).
- The image also carries `p2pc-boot`, the test script (`/usr/local/sbin/p2pc-test-distro`), `p2pc-node-run`
  (`/usr/local/sbin`), their shared `/usr/local/lib/p2pc/nvidia.sh` and `/usr/local/lib/p2pc/boot-status.sh`, and
  `/var/log/p2pc` (mode 0700), because the distro cannot see Windows files (`automount` is off), so they have to be
  inside.

**`packages.lock`.** One `name=version` per line, fully pinned (resolved by the first real build, 2026-11-05; the four
NVIDIA packages are all at `1.20.1-1`, as NVIDIA's install guide does), plus one `snapshot=<UTC timestamp,
YYYYMMDDTHHMMSSZ>` line. A bare `name` is unpinned and a normal build refuses it.

**Updating the base packages** (security fixes): on a trusted build host run

```bash
sudo deploy/wsl/build-rootfs.sh --update-lock --out ./out    # moves snapshot= to now, installs the newest Ubuntu
                                                             # versions in it, rewrites packages.lock; NVIDIA pins stay
git diff deploy/wsl/packages.lock                            # review the new snapshot and versions, commit
sudo deploy/wsl/build-rootfs.sh --version <next> --out ./out # rebuild from the committed lock
diff <old manifest.txt> out/manifest.txt                     # every package that changed, with versions
```

Bump `--version` (it ends up in `/etc/p2pc-distro-version` and the file names). A pin that no longer exists in the
snapshot (apt: "Version ... not found") means the lock and the snapshot do not match: run `--update-lock`.

**When the snapshot service is down.** `snapshot.ubuntu.com` sometimes answers 5xx. Inside the build, apt retries each
failed download 5 times, with 30 s timeouts (a build-only `99p2pc-retries` file that the image does not keep). If an
archive still fails, `apt-get update --error-on=any` **stops the build** with a message that names the archive URL (it no
longer limps on to a confusing "Unable to locate package"). Nothing is built and nothing falls back by itself:
`--archive live` is never chosen automatically. You have two choices:

1. Wait and retry (the lock is unchanged; the timestamps are permanent once the service is back).
2. Build knowingly from the live mirrors: `sudo deploy/wsl/build-rootfs.sh --archive live --version <v> --out ./out`.
   apt then uses `archive.ubuntu.com` (noble, noble-updates) and `security.ubuntu.com` (noble-security). The script
   prints a loud warning that the build is **not reproducible**.
   - Live mode installs the **newest** Ubuntu versions in the live archive and ignores the Ubuntu pins of
     `packages.lock` (the live archive keeps only the newest version of each package, so those pins stop resolving
     within days). NVIDIA's pins still apply, because NVIDIA's repository keeps old versions.
   - The versions that were resolved are in `manifest.txt`, next to `# archive=live` and `# archive_build_time=...`.
     `/etc/p2pc-distro-version` records `archive=live` and `archive_build_time=...`. A snapshot build records
     `archive=snapshot@<timestamp>`.
   - `packages.lock` is never rewritten in live mode, and `--update-lock` cannot be combined with `--archive live`.

Rebuild from the snapshot as soon as it is back, and diff the two `manifest.txt` files.

### 2. Install

From PowerShell 5.1 or newer, as yourself, with the three build outputs side by side. Windows blocks
scripts by default (execution policy), and blocks a downloaded one even more. For a file you trust, allow local scripts
in this window only, then remove the download mark from the script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned    # this PowerShell window only
Unblock-File .\install.ps1
```

The image has its own version (0.2.2 by default, `build-rootfs.sh`), apart from the release version; `-Join` refuses an
image older than 0.2.2 (exit 32).

```powershell
.\install.ps1 -CheckOnly                                  # run only the pre-install checks
.\install.ps1 -Tar .\p2pc-node-0.2.2.tar.gz               # verify SHA-256, then wsl --import ... --version 2
```

Then join it to your server: `.\install.ps1 -Join` ("Join a Windows machine" above).

Default location: `%LOCALAPPDATA%\P2PC\wsl\p2pc-node` (`-InstallDir` to change). The checks each have their own message
and exit code (listed at the top of `install.ps1`); the log path is printed at the end.

| Check | Exit | Why |
|---|---|---|
| Windows build ≥ 19044 | 10 | The Store version of WSL needs it. |
| `wsl --version` works, ≥ 2.0.0 | 11 / 12 | Installed and recent enough to import with `--version 2`. |
| WSL default version is 2 | 13 | We import with `--version 2` anyway; a default of 1 usually means a half-configured WSL. |
| Virtualization on in the firmware | 14 | WSL2 is a VM. A running hypervisor counts as proof. |
| ≥ 20 GB free (`-MinFreeGB`) | 15 | Image, container images, job data. |
| `p2pc-node` not yet installed | 16 | Install never overwrites. Points to `-Upgrade`. |
| SHA-256 of the tar matches its `.sha256` | 17 / 18 | Spec §9.0: the rootfs is pinned and hash-verified. |

### 3. Test

```powershell
wsl -d p2pc-node -u root --exec /usr/local/sbin/p2pc-test-distro
wsl -d p2pc-node -u root --exec /usr/local/sbin/p2pc-test-distro --json
```

It prints `PASS` / `FAIL` / `SKIP` / `INFO` per check and exits non-zero on any `FAIL` (`INFO` is a fact that cannot be
asserted and never changes the exit code). It checks:
skopeo is installed and `skopeo inspect --raw docker://docker.io/library/busybox:1.36.1` returns a manifest (`INFO` when the
node has no network; the agent uses skopeo to check the image size cap before pulling, because Podman 4.9 cannot inspect a
single-image OCI manifest, spec §9 "Images"); file capabilities survive the image (`getcap /usr/bin/ping` shows `cap_net_raw`); the appliance stays root-only (no `/etc/wsl-distribution.conf`, no login user with uid ≥ 1000); isolation (no `/mnt/c`, no 9p/drvfs mounts except WSL's own read-only GPU driver store, no `WSL_INTEROP`, no Windows `PATH`; the WSLInterop `binfmt_misc` entry is shown as `INFO`, because `binfmt_misc` is
shared by every distro in the WSL VM and other distros keep interop on, so it cannot be removed per distro); the
`wsl.conf`, `/etc/subuid`, `/etc/subgid` and Podman configuration (`cgroupfs`, cgroup v2, `crun`, ≥ 4.9); a hardened
`podman run` with the §9 flags and `--userns=auto` (CapEff 0, CapBnd 0, NoNewPrivs 1, seccomp filter, remapped
`uid_map`); no network (TCP to `1.1.1.1:443`, the default gateway and `100.100.100.100:53` must each be
**unreachable**: the probe (busybox `wget` in the alpine image, the one applet that names them: "Connection refused", "Network
(is) unreachable" / "No route to host" / "Host is unreachable", "Connection|Operation timed out" / "download timed
out"; both glibc and musl wordings are accepted) tells "refused" (a RST: something answered), "unreachable" (no route: what an empty network
namespace gives) and "timed out" (packets dropped) apart, and a `--network=none` container must see "unreachable"; two
controls, a loopback connect that works and an unused loopback port that is refused, so that "blocked" cannot mean "the
probe is broken"); the memory limit and the PID limit, **measured from the host
side** in the job's own cgroup (`--cgroup-parent=/p2pc-test-<check>-<pid>`, removed afterwards): `memory.events`
`oom_kill > 0` after a 200 MB allocation under `--memory=64m`, and `pids.events` `max > 0` plus
`HostConfig.PidsLimit == 64` after a bounded loop of 200 forks under `--pids-limit=64`. Podman's own `OOMKilled` flag is
only printed as `INFO` (spec §9 "Memory" makes `memory.events` `oom_kill` the primary signal, not `OOMKilled` or exit 137
alone): on WSL2, Podman 4.9.3 with conmon 2.1.10 and cgroupfs never sets it (the kernel kills the job,
exit 137, and Podman records nothing), and a trap inside a job that is at its PID limit cannot fork to report anything; and, only with an NVIDIA GPU (`/dev/dxg` is not enough: WSL exposes it for every GPU-PV driver, Intel and AMD integrated GPUs
included, so the test also needs `libcuda.so*` under `/usr/lib/wsl/lib` and a working `nvidia-smi -L`; otherwise the GPU
checks are `SKIP` with "no NVIDIA GPU"; with `libcuda` but a failing or hanging `nvidia-smi -L` a GPU is expected and broken, which is a `FAIL`, as is `p2pc-boot` reporting `nvidia_smi_failed`), CDI `nvidia.com/gpu=all` and `nvidia-smi -L` inside a CUDA image.

The test pulls two small images (needs internet, cached afterwards) and does one `skopeo inspect --raw` against the
registry (`INFO`, not a failure, when the node has no network). The images are **pinned by digest**: the digests are the
constants at the top of `test-distro.sh` (`ALPINE_DIGEST`, `CUDA_DIGEST`, resolved on 2026-11-05), so a plain run needs no
arguments. To try other images, pass them with `--alpine-image` / `--cuda-image`. To bump the constants, resolve the new
digests on a trusted machine, review them and commit them:

```powershell
wsl -d p2pc-node -u root --exec /usr/local/sbin/p2pc-test-distro --resolve-images
wsl -d p2pc-node -u root --exec /usr/local/sbin/p2pc-test-distro --alpine-image <repo@sha256:...> --cuda-image <repo@sha256:...>   # optional override
```

### 4. Upgrade

```powershell
.\install.ps1 -Upgrade -Tar .\p2pc-node-0.2.2.tar.gz        # asks for confirmation; -Force skips it
```

Without a terminal (an SSH session, a pipe) a confirmation can never be answered, so `-Upgrade` and `-Uninstall`
without `-Force` stop at once with exit 30 and say to rerun with `-Force`; they never wait.

The agent's identity key, its config with the enrollment (`agent.toml`, `[server]`) and its state live **inside** the
distro, in `/var/lib/p2pc` (§9.0). **From an image up to 0.2.1**, which kept the config in `/etc/p2pc/agent.toml`, the
upgrade first copies that file to `/var/lib/p2pc/agent.toml` in the old distro (or creates an empty one when the node
never joined), so the archive carries the enrollment: a node joined on 0.2.1 comes back online on 0.2.2 with no new
token. After the restore it checks that a node that was enrolled still holds `[server]`, and after the task is started
again that the agent did not stop with exit 8 (no enrollment) or 7 (removed by the server); either one ends the upgrade
with **exit 38** and says what to run (`.\install.ps1 -Join -Force` with a new token), never with exit 0 and a warning.
Re-importing a distro without saving `/var/lib/p2pc` would force the node to re-enrol, so the upgrade: (0) checks, before anything else is touched, that the old distro's directory holds nothing but the files WSL itself keeps there (`ext4.vhdx`, and `shortcut.ico`, which WSL 2.7.8 creates at import; one list, `$WslOwnedFiles` in `install.ps1`, compared case-insensitively) (`wsl --unregister`
removes only WSL's own files, so any other file would make the import into the same directory fail, exit 19, after the old
distro is already gone; the upgrade stops with exit 19 up front instead); (1) stops the distro and archives `/var/lib/p2pc` **inside
it**, into `/var/tmp/p2pc-state-<timestamp>.tar` (mode 0600; `find` lists what to keep, without sockets, FIFOs, `tmp/` and the boot status files, and hands the list to `tar`), computes its SHA-256 there, copies it out with
`cmd.exe`'s own redirection (`cmd.exe /d /s /c ""wsl.exe" ... --exec /bin/cat <file> > "<windows path>""`, byte-exact) into
`%LOCALAPPDATA%\P2PC\backups\` (not `%TEMP%`, where Windows Storage Sense deletes old files; the `\\wsl.localhost` share does not
exist in non-interactive sessions such as SSH), and compares `Get-FileHash` of the copy with the hash computed inside; the
temporary file in the distro is removed on every path. **Binary data never goes through PowerShell**: Windows PowerShell 5.1
re-encodes the stdout of a native command that is piped, captured or redirected, which corrupts a tar (a first version of
the upgrade did that and stopped safely at the hash check with exit 23); `deploy/tests/test-install-lint.sh` flags any such
pattern in `install.ps1`; "does `/var/lib/p2pc` exist?" is asked with a probe that must answer exactly `P2PC_STATE=present` or
`P2PC_STATE=absent` with exit 0: anything else (the distro would not start, garbled output) stops the upgrade with exit
23 before anything is touched. If it is positively absent (an older or hand-made image) the upgrade refuses unless
`-Force` is given, because the node will then have to re-enrol; with `-Force` it logs that and goes on without
restoring anything; (2) unregisters the old distro and imports the new image; (3) copies
the archive into a mode-0600 file in the new distro (raw .NET streams, never a PowerShell pipe), checks its hash there and
extracts it, and always deletes that copy afterwards, on success and on every failure (same modes and numeric owners); (4) verifies that the listing of `/var/lib/p2pc`
(names, modes, owners; `boot-status.json` and `tmp/`, which `p2pc-boot` rewrites at every start, are left out, and so are
sockets and FIFOs: they are not identity, a socket cannot be archived, and one of them would otherwise make every upgrade
fail the comparison with exit 26) is identical to before and that the new distro passes its sanity checks. The archive is renamed
to `p2pc-state-<timestamp>.ok.tar` only after step 4, and only the newest 3 of those are kept (older ones are deleted at the end
of a successful upgrade). The backup of an upgrade that did not finish keeps its plain `p2pc-state-<timestamp>.tar` name, is
never deleted by the upgrade, and `-Uninstall` keeps it too unless you pass `-DeleteFailedBackups` (section 5); its path is printed at the end of the run. A backup holds the agent's identity key:
treat it as a secret (it sits in your user profile) and delete the ones you no longer need. Running jobs are lost and retried elsewhere (§9, "no checkpointing").

*Recovering from a failed upgrade.* If the new image cannot be imported after the old distro was unregistered, the state
archive is in `%LOCALAPPDATA%\P2PC\backups\p2pc-state-<timestamp>.tar` (the path is printed when the run ends). Fix the cause, run `.\install.ps1 -Tar <image>`, then copy the
archive into the distro and extract it. From **cmd.exe** (PowerShell has no `<` redirection):
`wsl.exe -d p2pc-node -u root --exec /bin/tar --numeric-owner -C /var/lib -xpf - < "%LOCALAPPDATA%\P2PC\backups\p2pc-state-<timestamp>.tar"`.
When the node is back, delete that file (it is never pruned: it did not come from a finished upgrade).

On the PC that hosts the hub (H2: `/var/lib/p2pc-server/hub.enabled` exists) the same archive also holds
`/var/lib/p2pc-server`: the cloud's database, the hub's keys, its blobs and `hub.enabled`. The command above restores
both directories, because the archive's names are relative to `/var/lib` (`p2pc/...`, `p2pc-server/...`). Before you
start the node again, check that the hub came back whole:
`wsl.exe -d p2pc-node -u root --exec /usr/bin/stat -c "%a %U %n" /var/lib/p2pc-server /var/lib/p2pc-server/hub.enabled`
must show `700 root` for the directory, and
`wsl.exe -d p2pc-node -u root --exec /usr/bin/env P2PC_DATA_DIR=/var/lib/p2pc-server /usr/local/bin/p2pc-server info`
must print the hub's NodeId as before (your phone and your other PCs know the hub by it). Then `.\install.ps1 -Start`.
Treat this archive like the cloud itself: anyone with it holds your hub's keys and database.

*Backing up and restoring the hub's data by hand.* `-Upgrade` stops with exit 23, and touches nothing, when
`/var/lib/p2pc-server` exists without `/var/lib/p2pc`, or when the drives have no room for the archive. Before you
repair such a distro, or before anything else that may lose it, copy the hub's data out of it yourself. From
**cmd.exe**, with the node stopped (`.\install.ps1 -Stop`, so that the hub's database is not being written):

1. Make the archive inside the distro, mode 0600, and note its hash:
   `wsl.exe -d p2pc-node -u root --exec /bin/sh -c "umask 077; tar --numeric-owner -C /var/lib -cpf /var/tmp/p2pc-server-backup.tar p2pc-server; sha256sum /var/tmp/p2pc-server-backup.tar"`
2. Copy it out byte for byte (cmd.exe redirection, never a PowerShell pipe, which re-encodes binary data):
   `wsl.exe -d p2pc-node -u root --exec /bin/cat /var/tmp/p2pc-server-backup.tar > "%LOCALAPPDATA%\P2PC\backups\p2pc-server-<timestamp>.tar"`
3. Check that `certutil -hashfile "%LOCALAPPDATA%\P2PC\backups\p2pc-server-<timestamp>.tar" SHA256` prints the hash of
   step 1, then delete the copy in the distro:
   `wsl.exe -d p2pc-node -u root --exec /bin/rm -f /var/tmp/p2pc-server-backup.tar`

To restore it, into a distro whose node is stopped and that has no `/var/lib/p2pc-server` of its own (move an existing
one aside first; tar would mix the two):
`wsl.exe -d p2pc-node -u root --exec /bin/tar --numeric-owner -C /var/lib -xpf - < "%LOCALAPPDATA%\P2PC\backups\p2pc-server-<timestamp>.tar"`,
then run the two checks above (`700 root`, the same NodeId) and `.\install.ps1 -Start`. `p2pc-run` starts the hub within
about 5 s if `hub.enabled` came back. These `p2pc-server-*.tar` files are yours: neither `-Upgrade` nor `-Uninstall`
prunes or deletes them.

### 5. Uninstall

```powershell
.\install.ps1 -Uninstall                          # confirmation prompt; -Force skips it
.\install.ps1 -Uninstall -KeepBackups             # leave every upgrade state backup where it is
.\install.ps1 -Uninstall -DeleteFailedBackups     # also delete the backup of an upgrade that failed
```

First it stops and removes the Scheduled Task "P2PC node" (if it cannot, it stops with exit 37 and the distro is not
touched), and deletes its wrapper `%LOCALAPPDATA%\P2PC\node-task.cmd` and any `stopped-by-node` record; then it runs
`wsl --unregister p2pc-node`. This **deletes the agent identity and every container image in the distro**. The
identity also sits in the upgrade state backups under `%LOCALAPPDATA%\P2PC\backups\`, which come in two kinds:

- `p2pc-state-<timestamp>.ok.tar`: the backup of an upgrade that finished and was verified. By default `-Uninstall`
  **deletes these** (after the confirmation, with or without `-Force`, and only after the unregister succeeded), and then
  the `backups` folder if it is empty.
- `p2pc-state-<timestamp>.tar`: the backup of an upgrade that did not finish. It can be the **only copy** of that node's
  identity, so `-Uninstall` **never deletes it by default**, `-Force` or not. The prompt and the final message list each
  one by its full path. It holds the agent identity key. Delete it by hand, or with '.\install.ps1 -Uninstall -DeleteFailedBackups' (which also uninstalls the node), when you no longer need it.

`-KeepBackups` keeps every backup of both kinds, and the prompt and the final message say so and name the folder.
`-DeleteFailedBackups` deletes both kinds (it cannot be combined with `-KeepBackups`). Nothing else in that folder is
touched. The same warning, word for word, is printed at the end of an upgrade that failed.

### Why each setting is what it is

| Setting | Where | Why |
|---|---|---|
| `[boot] systemd=false` | `/etc/wsl.conf` | All WSL2 distros share one cgroup v2 root; a second systemd would fight over it (§9.0). |
| `[boot] command=/usr/local/sbin/p2pc-boot` | `/etc/wsl.conf` | Regenerates the CDI spec when the Windows driver libraries changed (§9.0, E8: "CDI at boot"). |
| `[automount] enabled=false`, `mountFsTab=false` | `/etc/wsl.conf` | The distro must not see the Windows filesystem (hard rule 8): jobs can never reach `C:`. |
| `[interop] enabled=false`, `appendWindowsPath=false` | `/etc/wsl.conf` | No launching Windows executables from the distro, no Windows `PATH` (hard rule 8). |
| `[network] generateHosts/generateResolvConf=true` | `/etc/wsl.conf` | Values from E1; the host side of the node (the agent) needs working DNS. |
| `[user] default=root` | `/etc/wsl.conf` | On WSL2 Podman runs as root inside the appliance; the isolation comes from `--userns=auto`, not from the login user (§9.0). |
| `cgroup_manager = "cgroupfs"`, `events_logger = "file"`, `cgroupns = "private"` | `/etc/containers/containers.conf.d/p2pc.conf` | With no systemd, Podman must manage cgroups itself; `file` events need no journald; a private cgroup namespace hides the shared root from jobs (E1). |
| `containers:2147483647:2147483648` | `/etc/subuid`, `/etc/subgid` | The range `--userns=auto` allocates from. Container root becomes an unprivileged high uid (§9.0). |
| `--network=none` (in every job) | agent / tests | All WSL2 distros of a Windows user share **one network namespace**: E1 saw the other distros' interfaces, Docker bridges and Tailscale. Never filter with iptables, since that would affect every distro. |
| `/var/lib/p2pc` mode 0700 | image | Holds the agent identity key and its config with the enrollment, `agent.toml` (§9.0). |
| Pinned base SHA-256, NVIDIA key fingerprint, `packages.lock` | builder | The rootfs ships pre-built and verified; nothing is installed with apt at first launch (§9.0). |
| No driver inside the distro | image | The GPU comes from the Windows driver through `/dev/dxg` and `/usr/lib/wsl`; `nvidia-ctk cdi generate --mode=wsl` describes it (§9.0, E1). |

**The boot status can arrive late.** `p2pc-boot` is the distro's `[boot] command`, which WSL runs asynchronously, and it runs
`nvidia-smi -L` (up to about 10 s) at every start. So `/var/lib/p2pc/boot-status.json` can appear a few seconds after the
distro is up, and the file of the previous start can still be there. "Fresh" is decided **by identity, not by time**:
`p2pc-boot` records `init_starttime`, the raw start ticks of the distro's init (field 22 of `/proc/1/stat`), and a status
is fresh when that number **equals** field 22 of `/proc/1/stat` read now. Every start of the distro has its own init.
(The rule used to compare the status `time` with `btime` plus the init's start: that had 1-2 s of slack, and the clock
can step after the host sleeps.) `boot-status.sh` is the rule in bash, `Get-ProcStarttime`/`Test-BootStatusFresh` in
`install.ps1`. `install.ps1` waits up to 30 s for a fresh status after `-Install` and `-Upgrade` and prints the CDI state
(a warning, never an error, if it does not come; `nvidia_smi_failed` and any `errors` are printed as warnings);
`p2pc-test-distro` polls every second for up to 30 s before it fails `cfg.boot_status`; `p2pc-node-run` waits up to 60 s
before it starts the agent. **The agent (T05b inventory, T10a) must treat a missing or older file as "not ready yet",
not as "no GPU"**; it still decides "older" by time today, and should compare `init_starttime` too (a follow-up in
`crates/p2pc-agent`, outside T14b2). A status without `init_starttime` (an image older than 0.2.0) is never fresh for the
scripts.

`p2pc-boot` details: it regenerates `/etc/cdi/nvidia.yaml` when it is missing or older than the newest file in
`/usr/lib/wsl/lib` **or when a path the spec refers to (a `hostPath:` of a mount, the `path:` of a hook or device node)
no longer exists** (a driver update that removed a library), does nothing without `/dev/dxg`, **nor when no NVIDIA GPU is behind it** (it needs a `libcuda.so*` under `/usr/lib/wsl/lib` and `nvidia-smi -L` listing a GPU; an Intel or AMD GPU-PV driver has `/dev/dxg` too: the status says `"cdi":"no_nvidia_gpu"`, with no error, and no CDI spec is generated; **with `libcuda` but a failing, missing or hanging `nvidia-smi -L`** a GPU is expected and does not work: the status says `"cdi":"nvidia_smi_failed"`, the reason goes to `errors` (saying whether the existing CDI spec was kept, which it always is) and nothing is regenerated; `nvidia-smi` is looked up like the agent does, on `PATH` first, then in `/usr/lib/wsl/lib`; and when there is no NVIDIA GPU any more but `/etc/cdi/nvidia.yaml` is left over from when there was one, it is renamed to `nvidia.yaml.stale-<time>` (podman loads only `*.yaml` and `*.json`, so it stops listing devices that no longer exist) and the status says so in `notes`, which is not an error; with `nvidia_smi_failed` the spec is left alone), runs `nvidia-ctk` under a 20 s timeout, writes the new spec to a
temporary file **outside `/etc/cdi`** (`/var/lib/p2pc/tmp/*.yaml`; podman loads every `*.yaml` in `/etc/cdi`, and
`nvidia-ctk` appends `.yaml` to an `--output` that has no extension) and renames it in place only on success, deletes
stray `.nvidia-cdi.*` files left by older versions, writes `/var/lib/p2pc/boot-status.json` (one line:
`time`, `cdi`, `cdi_regenerated`, `errors`, `notes`), and **always exits 0**, so it can never block or fail a distro start.

## Server on Linux

The control plane, `p2pc-server`, runs as a hardened systemd system service on one always-on machine: any Linux with
systemd, on x86_64 (or aarch64 when a release for it was built). **Supported by the installers:** Ubuntu 22.04, 24.04
and 26.04, Debian 12 and 13, and Arch Linux (and distributions based on it), covered by the installers' tests.
**Tested end to end on real machines:** Ubuntu 24.04 and an Arch-based distribution. Any other distribution gets one
warning line ("not a tested platform") and the install goes on.
The installer checks what it needs, one requirement at a time (root, a running systemd, `systemctl`, `runuser`,
`useradd`, `sha256sum`, `tar`, and `curl` or `wget`) and names the one that is missing. Spec §2 U1 and §14 AC-1: one
command, from the release files to a running server and the admin key.

### 1. Build the release (on a build machine)

```bash
scripts/release.sh --check-reproducible        # writes dist/<version>/, builds twice and compares SHA256SUMS
cd dist/0.1.0 && sha256sum -c SHA256SUMS      # check a copy anywhere
```

Needs the Rust toolchain of `rust-toolchain.toml` with the `x86_64-unknown-linux-musl` target
(`rustup target add x86_64-unknown-linux-musl`) and a musl C compiler for the C code in SQLite and ring: `musl-gcc`
(`apt-get install musl-tools`) or `cargo-zigbuild` with zig (`RELEASE_BUILDER=zigbuild` forces it). The script never
installs anything. aarch64 is built only when its Rust target and `cargo-zigbuild` (or `aarch64-linux-musl-gcc`) are
there, and is skipped with a note otherwise; an SBOM is written only when `cargo-cyclonedx` is installed (and the
release fails if it then writes none). `python3` (standard library only) writes `THIRD-PARTY-LICENSES`.

`dist/<version>/` holds, per target, `p2pc-server-…`, `p2pc-…`, `p2pc-agent-…` and `p2pc-shim-<version>-<target>.tar.gz`
(each with the static binary, its `LICENSE`, `THIRD-PARTY-LICENSES` and a `README`), plus the deploy files
`install-server.sh`, `p2pc-server.service`, `install-node.sh`, `setup-host.sh` and `p2pc-agent.service` (`DEPLOY_FILES`
in the script, fixed modes), `sbom/` (optional) and `SHA256SUMS`, which lists every one of them. The tarballs are deterministic (sorted names, owner 0:0, fixed modes, mtime from the
HEAD commit, `gzip -n`) and the binaries are built with remapped paths, so the same commit gives the same bytes.
Nothing is uploaded: publishing is a separate decision.

`THIRD-PARTY-LICENSES` starts with what every static binary contains besides the crates: the Rust standard library
(Rust's own notice, `share/doc/rust/COPYRIGHT-library.html` of the pinned toolchain, as text) and, on musl targets,
LLVM's libunwind and compiler-rt (`LICENSES/third-party/llvm-project-LICENSE.TXT`) and musl libc 1.2.5
(`LICENSES/third-party/musl-1.2.5-COPYRIGHT`). Both vendored texts are pinned by SHA-256 in the script. Then it lists
every crate the binary links (the normal dependencies that `cargo metadata` resolves for the target; not dev- or
build-dependencies) with its version, its license expression and the full texts of the `LICENSE*`, `COPYING*` and
`NOTICE*` files it ships. `scripts/third-party-licenses.py` writes it, and fails the
release with a list when a crate ships no license file, except for a short reviewed allowlist in that script of
dual-licensed crates that get the plain Apache-2.0 text from `LICENSES/`.

### 2. Install (one command, on the server)

Copy `dist/<version>/` to the server (for example `scp -r dist/0.1.0 server.example.invalid:`), then:

```bash
sudo sh 0.1.0/install-server.sh --from 0.1.0
```

`--from` takes that directory or an `https://` URL with the same files. Every file is checked against `SHA256SUMS`
before anything is installed; a mismatch, a file missing from `SHA256SUMS`, an unsupported architecture, no root,
no systemd or a missing tool all stop it with a message and change nothing. Options: `--version X` (when `SHA256SUMS`
lists several), `--listen IP:PORT` (default `127.0.0.1:7477`, first install only), `--admin-key-file PATH` (no terminal:
see "Scripted or CI install" below). It also installs `p2pc` in `/usr/local/bin`, so on the server host you can log in
with `p2pc login --server http://127.0.0.1:7477` (the http URL; a laptop or a node uses the `p2pc_srv_…` address).

It prints the admin key **once**, between two lines of dashes, with the server address (`p2pc_srv_…`), waits for
`GET /healthz` (30 s at most) and ends with a one-screen summary and the next steps:

```bash
p2pc login --server http://127.0.0.1:7477      # asks for the admin key
p2pc join-token create                          # prints a token; see "Join a machine" above
```

The key comes from `p2pc-server init`, run as `p2pc-server` and outside systemd, with its output going straight to
your terminal: it never reaches the journal, the install log, a command line or an environment variable. Only its
SHA-256 is stored. Lost every admin key? On the server:
`sudo runuser -u p2pc-server -- env P2PC_DATA_DIR=/var/lib/p2pc-server p2pc-server keys recover`.

### What it creates

| Path | Owner | Mode | What |
|---|---|---|---|
| `/usr/local/bin/p2pc-server`, `/usr/local/bin/p2pc` | root | 0755 | The server and the CLI (static binaries). |
| `/etc/systemd/system/p2pc-server.service` | root | 0644 | The unit, enabled at boot. |
| `/etc/systemd/system/p2pc-server.service.d/10-container.conf` | root | 0644 | Only on hosts without user namespaces (see below): `PrivateUsers=no`. |
| user and group `p2pc-server` | | | A system user: no login shell, home `/var/lib/p2pc-server`. |
| `/var/lib/p2pc-server/` | p2pc-server | 0700 | The data dir (`P2PC_DATA_DIR`, spec §12). |
| `…/server.toml` | p2pc-server | 0600 | The config: `bind`, relays, limits. |
| `…/p2pc.db` (and `-wal`, `-shm`) | p2pc-server | 0600 | SQLite: accounts, key digests, jobs, nodes, audit. |
| `…/server.key` | p2pc-server | 0600 | The server's iroh identity: its NodeId and address. |
| `…/logs/`, `…/artifacts/` | p2pc-server | 0700 | Job logs and outputs. |
| `/var/log/p2pc-server-install.log` | root | 0600 | The installer's steps (never the key). |

The service runs with no capabilities, a read-only file system except its data dir, private `/tmp` and devices, its
own user namespace, `@system-service` system calls only and no write-and-execute memory. It may open `AF_INET` and
`AF_INET6` (the REST API and iroh's outbound QUIC), `AF_UNIX` and `AF_NETLINK` (iroh's `netwatch` reads interfaces
and routes, for the address hygiene of spec §10). Logs: `journalctl -u p2pc-server`.

**Containers.** Some hosts cannot give a service its own user namespace: an unprivileged LXC container (as on
Proxmox), or a Podman or Docker container running systemd. There `PrivateUsers=yes` stops the unit from starting
(`217/USER`), often only together with the rest of the unit's sandbox. So before starting the service, the installer
tests the unit itself: it writes a temporary oneshot unit `/run/systemd/system/p2pc-server-probe.service` made of the
installed unit's own `[Service]` settings (user, sandbox and all; without `Exec*`, `Restart*`, `Type`,
`StateDirectory*`), which runs `p2pc-server --version` with `TimeoutStartSec=30`, and starts it with `systemctl` (as
root, over systemd's private socket: no D-Bus needed). Probe A is the unit as installed; probe B adds
`PrivateUsers=no`. Then it removes the probe unit again.
- A passes: no drop-in, and a rerun removes an old one.
- A fails with the user-namespace status (`217/USER` or `226/NAMESPACE`, read with `systemctl show -p ExecMainStatus`
  before the probe is cleaned up), B passes: it adds the drop-in `10-container.conf` with `PrivateUsers=no` and says
  so in its output, its summary and its log ("this host cannot give the service its own user namespace (container?):
  PrivateUsers is off"). Everything else in the hardening stays.
- A fails with any other status (a slow `daemon-reload`, the 30 s timeout on a loaded host, an OOM): A is retried once.
  If it still fails for another reason, it warns and keeps `PrivateUsers=yes` (and an existing drop-in): one failed
  probe never turns the hardening off.
- A (with the user-namespace status) and B both fail: `PrivateUsers` is not the cause. It says so, changes nothing, and
  the health wait reports the real error.

A rerun also clears a unit left in `start-limit-hit` by an earlier failed start (`systemctl reset-failed`). A service
that fails with `226/NAMESPACE` (an unprivileged LXC container without nesting) gets a hint: turn on `nesting=1`; one
that fails with `217/USER` gets a hint too.

The REST API listens on loopback by default. To change it later, edit `bind` in `/var/lib/p2pc-server/server.toml`
and `sudo systemctl restart p2pc-server`; anything beyond loopback must sit behind a TLS reverse proxy (spec §10,
option A). Agents never need it: they dial the server over iroh.

### Back up

Stop the service for a consistent copy of the SQLite database, archive the data dir, start it again. The archive is
created private (`umask 077`: mode 0600, owned by root):

```bash
sudo systemctl stop p2pc-server
(umask 077 && sudo tar -C /var/lib -czf "p2pc-server-$(date +%F).tar.gz" p2pc-server)
sudo systemctl start p2pc-server
```

The archive holds `server.key` (whoever has it can impersonate the server to your agents) and every key digest: keep
it mode 0600 wherever you copy it. To restore: install the same version first, then

```bash
sudo systemctl stop p2pc-server
sudo rm -rf /var/lib/p2pc-server && sudo tar -C /var/lib -xzf p2pc-server-2026-11-05.tar.gz
sudo chown -R p2pc-server:p2pc-server /var/lib/p2pc-server    # the uid may differ from the old machine's
sudo systemctl start p2pc-server
```

The admin keys of the backup work again; the one printed by that fresh install does not.

### Upgrade

Back up, then rerun the installer of the new release:

```bash
sudo sh 0.1.1/install-server.sh --from 0.1.1 --version 0.1.1
```

It replaces the binaries and the unit, restarts the service and waits for `/healthz`. It never runs `init` again and
never touches the data dir; rerunning it with the same release changes nothing.

### Uninstall

```bash
sudo sh install-server.sh --uninstall                  # stop, disable, remove the unit, its drop-ins and the binaries; keep the data and the user
sudo sh install-server.sh --uninstall --purge          # also delete /var/lib/p2pc-server and the user (asks you to type "purge")
sudo sh install-server.sh --uninstall --purge --yes    # the same, without asking
```

A purge first runs `systemctl stop`, then checks the service, whether or not the unit file is still there: it deletes
something only when `ActiveState` is `inactive`, `failed` or empty and `MainPID` is 0. Otherwise it deletes nothing:
stop it yourself, then rerun. A plain `--uninstall` only warns.

## Native Linux

`install-node.sh` runs `setup-host.sh` for you ("Join a Linux machine" above). On its own:

```bash
sudo deploy/linux/setup-host.sh --check-only    # report, change nothing (no root needed)
sudo deploy/linux/setup-host.sh                 # apply
```

Idempotent. It: creates the system user `p2pc` (home `/var/lib/p2pc`, mode 0700); adds subuid/subgid ranges for it
(rootless containers map container root into them: the rootless column of §9.0); runs `loginctl enable-linger p2pc`
(a systemd user session at boot, which rootless Podman and cgroup delegation need); checks cgroup v2 and that `cpu`,
`memory` and `pids` are delegated to user sessions (the §9 limits need them), **printing the fix instead of applying
it**; checks Podman ≥ 4.9 and `crun`; and, with an NVIDIA GPU and `nvidia-ctk` present, runs
`nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml`. It **never installs** the NVIDIA toolkit or any package: it
prints how. Every command that changes something is checked afterwards: `[done]` only when it worked and the result
is really in place, a `[TODO]` with a hint when it did not (a missing `p2pc` user in apply mode is a TODO, and so is a
sub-id range that would not fit in the 32-bit id space). `--check-only` prints what is missing as `[plan]`. Exit code
0 = the host is **really** ready (nothing is left to do), 1 = something is not in place, 3 = needs root.

Upgrade: re-run the script. Uninstall: see "How to remove it" above (`install-node.sh --uninstall --purge`, then
`userdel -r p2pc`, which also deletes Podman's storage).

## Checks and tests (no root, no Windows needed)

```bash
deploy/check.sh
```

Runs `bash -n` and `shellcheck` on every script (`deploy/` and `scripts/`), the SPDX header check, an
ASCII/PowerShell-7-syntax lint and (when `pwsh` is installed) a PowerShell parse of `install.ps1`, then
`deploy/tests/run.sh`. For the server: the unit's directives (and `systemd-analyze verify` and `security` where
`systemd-analyze` can run; CI sets `CHECK_REQUIRE_SYSTEMD_ANALYZE=1`), `install-server.sh` end to end under `sh` with
fake system commands (fresh install, rerun, upgrade, checksum mismatch, supported and other platforms, each missing
tool, uninstall and purge, and that the admin key reaches stdout only), and the deterministic tarballs and the dry run
of `release.sh`. For the node installers: `install-node.sh` end to end under `sh` with fakes (fresh, rerun, upgrade,
`--force`, a refused token, a host that is not ready, checksum and version refusals, uninstall and purge; the token is
asserted absent from every argv, the log, the output and every file written), the user unit (and `systemd-analyze --user
verify` where it can run), `p2pc-node-run` (backoff, terminal codes, the boot-status wait, the single-runner lock, log
rotation) with a fake agent and a fake clock, `build-rootfs.sh --agent-from`, the `-Join`/`-Status`/task flows of
`install.ps1` with stubs (with `pwsh`), and a child `pwsh` that puts a token on the command line and must be refused
without echoing it. For the nodes: unit tests of the pure helpers (lock parsing, SHA-256 and key-fingerprint checks,
mount safety, deterministic tar flags, the CDI staleness rule, the status JSON, the `/proc` parsers of the node test,
sub-id ranges, version comparison) and `build-rootfs.sh --dry-run`.
What cannot run without root, WSL or a container runtime (the build itself, the import, `test-distro.sh`) runs on a
test node as described above.
