#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests for deploy/wsl/p2pc-run, the supervisor the "P2PC node" Scheduled Task runs inside the p2pc-node distro (H2 spec
# §8.5; it replaces p2pc-node-run). It supervises two children, each with its own lock, backoff and rotated log:
#   - the agent, always, with H1's rules: the wait for a fresh boot status, the restart backoff (1 s, doubling, now at most
#     30 s, back to 1 s after a run of 60 s), the terminal exit codes that stop it for good (and why, in node-run.status);
#   - the hub (`p2pc-server serve`, P2PC_DATA_DIR=/var/lib/p2pc-server), only while /var/lib/p2pc-server/hub.enabled
#     exists, and only with a loopback REST bind and its data in that directory.
# It exits 64 (the task wrapper then disables the task) only when the agent stopped for good AND the hub is disabled.
# Everything runs with fakes: a fake p2pc-agent and p2pc-server that exit with scripted codes, `sleep`/`date` stubs on a
# fake clock, and the runner's hub poll driven by the test through FIFOs, so nothing ever really waits.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
runner="$here/../wsl/p2pc-run"
# shellcheck source=deploy/wsl/p2pc-run
source "$runner"
make_scratch

# The runner's hub poll interval in these tests: a value no backoff ever takes (1 2 4 8 16 30), so the fake sleep can tell
# the poll from a backoff. CHECK_S: the hub supervisor's listener check interval in these tests (another such value).
TICK_S=7
CHECK_S=11

# --- pure helpers ---------------------------------------------------------------------------------------------------
assert_eq "2" "$(next_delay 1)" "1 s doubles to 2 s"
assert_eq "16" "$(next_delay 8)" "8 s doubles to 16 s"
assert_eq "30" "$(next_delay 16)" "16 s doubles, capped at 30 s (H2 §8.5: 1 s doubling to 30 s)"
assert_eq "30" "$(next_delay 30)" "and stays there"
exit_rs="$here/../../crates/p2pc-agent/src/connection/exit.rs"
for name in AGENT_TOO_OLD NOT_ENROLLED NOT_JOINED; do
  code="$(sed -n "s/^pub const $name: u8 = \([0-9]*\);/\1/p" "$exit_rs")"
  assert_true "$name ($code, from exit.rs) is terminal" is_terminal "$code"
  assert_true "$name ($code) has a reason" test -n "$(terminal_reason "$code")"
done
for code in 1 2 3 4 5 9 124 137 143 255; do
  assert_false "exit $code is not terminal: restart" is_terminal "$code"
done
assert_contains "$(terminal_reason 7)" "-Join" "not enrolled: join again"
assert_contains "$(terminal_reason 8)" "-Join" "never joined: join"
assert_contains "$(terminal_reason 6)" "-Upgrade" "too old: upgrade"

# --- the hub's server.toml: started only with a loopback REST bind and its data in the hub directory ----------------
# toml_root_string <file> <key>: a top-level string value; 3 when absent, 4 when given twice, 5 when unreadable.
toml() { printf '%b' "$1" >"$SCRATCH/server.toml"; }
toml 'data_dir = "/var/lib/p2pc-server"\nbind = "127.0.0.1:7477"\n\n[iroh]\nbind = "0.0.0.0:1"\n'
assert_eq "127.0.0.1:7477" "$(toml_root_string "$SCRATCH/server.toml" bind)" "a top-level string"
assert_eq "/var/lib/p2pc-server" "$(toml_root_string "$SCRATCH/server.toml" data_dir)" "another one"
toml '# a comment\n\n  bind="[::1]:7477"   # loopback\ndata_dir = '"'"'/x'"'"'\n'
assert_eq "[::1]:7477" "$(toml_root_string "$SCRATCH/server.toml" bind)" "no spaces around =, a trailing comment"
assert_eq "/x" "$(toml_root_string "$SCRATCH/server.toml" data_dir)" "a literal string"
toml '[http]\nbind = "0.0.0.0:7477"\n'
toml_root_string "$SCRATCH/server.toml" bind >/dev/null
assert_eq "3" "$?" "a key inside a table is not the top-level one: absent"
toml 'bind = "127.0.0.1:1"\nbind = "0.0.0.0:1"\n'
toml_root_string "$SCRATCH/server.toml" bind >/dev/null
assert_eq "4" "$?" "a key given twice"
for bad in 'bind = 7477' 'bind = """127.0.0.1:7477"""' 'bind = "127.0.0.1:7477" x' 'bind = "a\\"b"'; do
  toml "$bad\n"
  toml_root_string "$SCRATCH/server.toml" bind >/dev/null
  assert_eq "5" "$?" "unreadable value: $bad"
done
toml '"bind" = "0.0.0.0:7477"\n'
assert_eq "0.0.0.0:7477" "$(toml_root_string "$SCRATCH/server.toml" bind)" "a quoted key is the same key (never ignored)"
# A multi-line string at the root could hide a key line from a line-based reader (or fake one): any root-level line with
# """ or ''' makes the whole file unreadable (5), whichever key is asked for. So does a byte order mark.
for ml in 'note = """\nbind = "127.0.0.1:1"\n"""\nbind = "0.0.0.0:7477"\n' "note = '''\nx\n'''\nbind = \"127.0.0.1:7477\"\n" \
  'bind = "127.0.0.1:7477"\nnote = """one line"""\n'; do
  toml "$ml"
  toml_root_string "$SCRATCH/server.toml" bind >/dev/null
  assert_eq "5" "$?" "a root-level multi-line string marker makes the file unreadable: $ml"
  toml_root_string "$SCRATCH/server.toml" data_dir >/dev/null
  assert_eq "5" "$?" "for every key: $ml"
done
toml 'bind = "127.0.0.1:7477"\n[iroh]\nnote = """\nx\n"""\n'
assert_eq "127.0.0.1:7477" "$(toml_root_string "$SCRATCH/server.toml" bind)" "a multi-line string inside a table is not at the root"
printf '\xef\xbb\xbfbind = "127.0.0.1:7477"\n' >"$SCRATCH/server.toml"
toml_root_string "$SCRATCH/server.toml" bind >/dev/null
assert_eq "5" "$?" "a file that starts with a byte order mark is unreadable"

for addr in 127.0.0.1:7477 127.0.0.2:9000 '[::1]:7477'; do
  assert_true "$addr is a loopback bind" is_loopback_bind "$addr"
done
for addr in 0.0.0.0:7477 192.0.2.1:7477 '[::]:7477' '[::ffff:127.0.0.1]:7477' '[2001:db8::1]:7477' 127.0.0.1 \
  localhost:7477 127.0.0.1:7477x 1127.0.0.1:7477 ' 127.0.0.1:7477' '[0:0:0:0:0:0:0:1]:7477'; do
  assert_false "$addr is refused (fail closed)" is_loopback_bind "$addr"
done

hub="$SCRATCH/hubdir"
mkdir -p "$hub"
cfgcheck() { # cfgcheck <toml text>: the refusal reason, empty when the hub may start
  printf '%b' "$1" >"$hub/server.toml"
  hub_config_problem "$hub/server.toml" "$hub"
}
assert_true "the default bind (none written) is loopback" cfgcheck "data_dir = \"$hub\"\n"
assert_true "an explicit loopback bind" cfgcheck "data_dir = \"$hub\"\nbind = \"127.0.0.1:7477\"\n"
assert_false "a LAN bind is refused" cfgcheck "data_dir = \"$hub\"\nbind = \"0.0.0.0:7477\"\n"
assert_contains "$(cfgcheck "data_dir = \"$hub\"\nbind = \"0.0.0.0:7477\"\n")" "0.0.0.0:7477" "and the reason names it"
assert_false "a bind given twice is refused" cfgcheck "data_dir = \"$hub\"\nbind = \"127.0.0.1:1\"\nbind = \"127.0.0.1:2\"\n"
assert_false "an unreadable bind is refused" cfgcheck "data_dir = \"$hub\"\nbind = 7477\n"
assert_false "data outside the hub directory is refused (the upgrade would not carry it)" cfgcheck "data_dir = \"/srv/p2pc\"\n"
assert_contains "$(cfgcheck "data_dir = \"/srv/p2pc\"\n")" "/srv/p2pc" "and the reason names it"
assert_false "no data_dir is refused" cfgcheck "bind = \"127.0.0.1:7477\"\n"
assert_false "a root-level multi-line string is refused" cfgcheck "data_dir = \"$hub\"\nnote = \"\"\"\nbind = \"127.0.0.1:1\"\n\"\"\"\n"
printf '\xef\xbb\xbfdata_dir = "%s"\n' "$hub" >"$hub/server.toml"
assert_false "a byte order mark is refused" hub_config_problem "$hub/server.toml" "$hub"
assert_contains "$(hub_config_problem "$hub/server.toml" "$hub")" "cannot read" "and the reason says it cannot be read"

# --- pid_exposed_tcp_listeners (listeners.sh): the hub's own non-loopback TCP listeners, from /proc -------------------------
fp="$SCRATCH/fakeproc-unit"
mkdir -p "$fp/net" "$fp/42/fd" "$fp/43/fd"
{
  printf '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n'
  printf '   0: 0100007F:1D35 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 501 1 0 100 0 0 10 0\n'
  printf '   1: 00000000:1D35 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 502 1 0 100 0 0 10 0\n'
  printf '   2: 0A0200C0:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 503 1 0 100 0 0 10 0\n'
} >"$fp/net/tcp"
ln -s 'socket:[501]' "$fp/42/fd/3"
ln -s 'socket:[503]' "$fp/43/fd/3"
assert_eq "" "$(pid_exposed_tcp_listeners "$fp" 42)" "a process with a loopback listener only: nothing"
assert_eq "192.0.2.10:80" "$(pid_exposed_tcp_listeners "$fp" 43)" "a process on a host address: named"
assert_eq "" "$(pid_exposed_tcp_listeners "$fp" 44)" "a process that is gone: nothing"
ln -s 'socket:[502]' "$fp/42/fd/4"
assert_eq "0.0.0.0:7477" "$(pid_exposed_tcp_listeners "$fp" 42)" "the wildcard is exposed (0.0.0.0 is not held by another pid here)"
rm -f "$hub/server.toml"
assert_false "no server.toml (the hub was never initialised) is refused" hub_config_problem "$hub/server.toml" "$hub"
assert_contains "$(hub_config_problem "$hub/server.toml" "$hub")" "init" "and the reason says to initialise it"

# --- the end-to-end runs ------------------------------------------------------------------------------------------------
fakebin="$SCRATCH/fakebin"
mkdir -p "$fakebin"
# sleep N: the runner's hub poll ($NR_TICK_S) is driven by the test when tick.fifo exists (it says "tick", then waits for
# a line on go.fifo), and otherwise idles until the runner kills it; it is never recorded. Any other sleep is a backoff or
# the boot-status poll: it advances the fake clock by N and records it; it never waits.
cat >"$fakebin/sleep" <<'FAKE'
#!/bin/sh
if [ "$1" = "$NR_TICK_S" ]; then
  if [ -p "$NR_STATE/tick.fifo" ]; then
    exec 3<>"$NR_STATE/go.fifo"
    echo tick >"$NR_STATE/tick.fifo"
    read -r _ <&3
    exit 0
  fi
  exec /bin/sleep 1000
fi
# The hub supervisor's listener check ($NR_CHECK_S): the same, on check.fifo and checkgo.fifo.
if [ "$1" = "$NR_CHECK_S" ]; then
  if [ -p "$NR_STATE/check.fifo" ]; then
    exec 3<>"$NR_STATE/checkgo.fifo"
    echo check >"$NR_STATE/check.fifo"
    read -r _ <&3
    exit 0
  fi
  exec /bin/sleep 1000
fi
echo "$1" >>"$NR_STATE/sleeps"
# What the sleep inherited (fd number and target): it must not hold a lock (9) or a log pipe (1, 2).
for fd in /proc/$$/fd/*; do echo "${fd##*/} $(readlink "$fd")"; done >>"$NR_STATE/sleep-fds"
# A held sleep (the backoff tests): say so on a FIFO, then really sleep, so the test can act while the runner waits.
if [ -e "$NR_STATE/hold-sleep" ]; then
  echo sleeping >"$NR_STATE/sleeping.fifo"
  exec /bin/sleep 10
fi
now="$(cat "$NR_STATE/clock" 2>/dev/null || echo 1000)"
echo $((now + $1)) >"$NR_STATE/clock"
FAKE
cat >"$fakebin/date" <<'FAKE'
#!/bin/sh
if [ "$*" = "+%s" ]; then cat "$NR_STATE/clock" 2>/dev/null || echo 1000; else exec /bin/date "$@"; fi
FAKE
# flock: the real one, but a BLOCKING call (no -n) first says so on $NR_FLOCK_FIFO when the test set one, so the test
# knows the runner is waiting for a lock without polling or sleeping.
real_flock="$(command -v flock)"
cat >"$fakebin/flock" <<FAKE
#!/bin/sh
if [ "\$1" != "-n" ] && [ -n "\${NR_FLOCK_FIFO:-}" ]; then echo blocked >"\$NR_FLOCK_FIFO"; fi
exec "$real_flock" "\$@"
FAKE
chmod 0755 "$fakebin"/*

proc1="1 (init) S 0 1 1 0 -1 4194560 1 2 3 4 5 6 7 8 20 0 1 0 5555 2265088 300 1"
# The fake agent of one run (the runner starts it with a clean environment, so the state dir is baked in): it pops its
# exit code from codes (one per line), runs for `runtime` seconds of fake time, prints `lines` lines of log, and records
# its argv and environment.
write_fake_agent() {
  cat >"$NR_STATE/p2pc-agent" <<FAKE
#!/bin/bash
state="$NR_STATE"
FAKE
  cat >>"$NR_STATE/p2pc-agent" <<'FAKE'
echo "agent $*" >>"$state/agent-argv"
env >"$state/agent-env"
# What it inherited: the runner's locks (fd 9) must not reach it, and SIGHUP must be ignored (SigIgn bit 0).
if [ -e "/proc/$$/fd/9" ]; then echo open >"$state/agent-fd9"; else echo closed >"$state/agent-fd9"; fi
sed -n 's/^SigIgn:[[:space:]]*//p' "/proc/$$/status" >"$state/agent-sigign"
if [ -e "$state/long" ]; then
  # A long run: say it started (through a FIFO the test reads), then idle until a signal ends it.
  trap 'echo TERM >>"$state/agent-signals"; kill "$idle" 2>/dev/null; exit 0' TERM
  sleep 1000 >/dev/null 2>&1 &
  idle=$!
  echo started >"$state/started.fifo"
  wait "$idle"
  exit 0
fi
code="$(head -n 1 "$state/codes" 2>/dev/null)"
sed -i '1d' "$state/codes" 2>/dev/null
n="$(cat "$state/lines" 2>/dev/null || echo 1)"
for ((i = 0; i < n; i++)); do echo "agent line $i: 0123456789abcdefghijklmnopqrstuvwxyz"; done
echo "agent stderr" >&2
rt="$(cat "$state/runtime" 2>/dev/null || echo 0)"
now="$(cat "$state/clock" 2>/dev/null || echo 1000)"
echo $((now + rt)) >"$state/clock"
exit "${code:-7}"
FAKE
  chmod 0755 "$NR_STATE/p2pc-agent"
}
# The fake hub (p2pc-server): it pops its exit code from hub-codes; with none left it runs until a signal ends it (and
# says "started" on hub-started.fifo when the test made one, and "stopped" on hub-stopped.fifo when it is stopped).
write_fake_server() {
  cat >"$NR_STATE/p2pc-server" <<FAKE
#!/bin/bash
state="$NR_STATE"
FAKE
  cat >>"$NR_STATE/p2pc-server" <<'FAKE'
echo "server $*" >>"$state/hub-argv"
env >"$state/hub-env"
if [ -e "/proc/$$/fd/9" ]; then echo open >"$state/hub-fd9"; else echo closed >"$state/hub-fd9"; fi
sed -n 's/^SigIgn:[[:space:]]*//p' "/proc/$$/status" >"$state/hub-sigign"
echo "hub line: listening" # the hub's own output goes to hub.log
code="$(head -n 1 "$state/hub-codes" 2>/dev/null)"
sed -i '1d' "$state/hub-codes" 2>/dev/null
# hub-listen holds a /proc/net/tcp address ("0100007F:1D35"): the fake hub "listens" there, in the fake /proc the runner
# reads (P2PC_RUN_PROC): a listening socket in net/tcp, and a descriptor of this process ($$, the runner's child) on it.
if [ -s "$state/hub-listen" ]; then
  mkdir -p "$state/fakeproc/net" "$state/fakeproc/$$/fd"
  printf '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: %s 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 4242 1 0 100 0 0 10 0\n' \
    "$(cat "$state/hub-listen")" >"$state/fakeproc/net/tcp"
  ln -sfn 'socket:[4242]' "$state/fakeproc/$$/fd/3"
fi
if [ -z "$code" ]; then
  trap 'echo TERM >>"$state/hub-signals"; kill "$idle" 2>/dev/null; [ -p "$state/hub-stopped.fifo" ] && echo stopped >"$state/hub-stopped.fifo"; exit 0' TERM
  sleep 1000 >/dev/null 2>&1 &
  idle=$!
  [ -p "$state/hub-started.fifo" ] && echo started >"$state/hub-started.fifo"
  wait "$idle"
  exit 0
fi
rt="$(cat "$state/hub-runtime" 2>/dev/null || echo 0)"
now="$(cat "$state/clock" 2>/dev/null || echo 1000)"
echo $((now + rt)) >"$state/clock"
exit "$code"
FAKE
  chmod 0755 "$NR_STATE/p2pc-server"
}
new_run() {
  NR_STATE="$(mktemp -d "$SCRATCH/run.XXXXXX")"
  write_fake_agent
  write_fake_server
  mkdir -p "$NR_STATE/proc/1" "$NR_STATE/lib" "$NR_STATE/log" "$NR_STATE/hub"
  chmod 0700 "$NR_STATE/hub"
  printf '%s\n' "$proc1" >"$NR_STATE/proc/1/stat"
  printf '{"time":"2026-11-06T10:00:00Z","init_starttime":5555,"cdi":"skipped","cdi_regenerated":false,"errors":[],"notes":[]}\n' \
    >"$NR_STATE/lib/boot-status.json"
  printf 'data_dir = "%s"\nbind = "127.0.0.1:7477"\n' "$NR_STATE/hub" >"$NR_STATE/hub/server.toml"
}
enable_hub() { touch "$NR_STATE/hub/hub.enabled"; }
disable_hub() { rm -f "$NR_STATE/hub/hub.enabled"; }
# runner_exec: replaces the current (sub)shell with the runner and its fakes. `runner_exec &` therefore gives the
# runner's own PID in $!, so signals reach it.
runner_exec() {
  exec env -i PATH="$fakebin:/usr/bin:/bin" NR_STATE="$NR_STATE" NR_TICK_S="$TICK_S" NR_CHECK_S="$CHECK_S" \
    P2PC_PROC="$NR_STATE/proc" P2PC_RUN_PROC="$NR_STATE/fakeproc" \
    P2PC_RUN_AGENT="$NR_STATE/p2pc-agent" P2PC_RUN_SERVER="$NR_STATE/p2pc-server" P2PC_RUN_STATE_DIR="$NR_STATE/lib" \
    P2PC_RUN_HUB_DIR="$NR_STATE/hub" P2PC_RUN_LOG_DIR="$NR_STATE/log" P2PC_RUN_AGENT_LOCK="$NR_STATE/agent.lock" \
    P2PC_RUN_HUB_LOCK="$NR_STATE/hub.lock" P2PC_RUN_HUB_POLL_S="$TICK_S" P2PC_RUN_LISTEN_CHECK_S="$CHECK_S" \
    P2PC_RUN_LOG_MAX_BYTES="${LOG_MAX:-10485760}" WSL_INTEROP=/run/WSL/1_interop WSLENV=SECRETISH \
    NR_FLOCK_FIFO="${NR_FLOCK_FIFO:-}" \
    bash "$runner" >"$NR_STATE/stdout" 2>&1
}
# run_runner: the runner in the foreground; status in $STATUS.
run_runner() {
  (runner_exec)
  STATUS=$?
}
# read_fifo <fifo>: one line from it. Opened read-write so the open never blocks; the 30 s limit only turns a broken
# runner into a failed assertion instead of a hung test (it is not used to wait for anything).
read_fifo() {
  local fd line=""
  exec {fd}<>"$1"
  read -r -t 30 -u "$fd" line
  exec {fd}<&-
  printf '%s' "$line"
}
# write_fifo <fifo> <line>: opened read-write too, so it never blocks, even when nobody reads any more.
write_fifo() {
  local fd
  exec {fd}<>"$1"
  printf '%s\n' "$2" >&"$fd"
  exec {fd}>&-
}
# with_ticks: the test drives the runner's hub poll. next_tick: the runner is in its poll (returns "tick"), and lets it end.
with_ticks() { mkfifo "$NR_STATE/tick.fifo" "$NR_STATE/go.fifo"; }
await_tick() { read_fifo "$NR_STATE/tick.fifo"; }
release_tick() { write_fifo "$NR_STATE/go.fifo" go; }
sleeps() { paste -sd' ' "$NR_STATE/sleeps" 2>/dev/null; }
status_of() { cat "$NR_STATE/lib/node-run.status" 2>/dev/null; }
agent_runs() {
  local n
  n="$(grep -c '^agent run$' "$NR_STATE/agent-argv" 2>/dev/null)"
  echo "${n:-0}"
}
hub_runs() {
  local n
  n="$(grep -c '^server serve$' "$NR_STATE/hub-argv" 2>/dev/null)"
  echo "${n:-0}"
}
hub_log() { cat "$NR_STATE/log/hub.log" 2>/dev/null; }

# A crash loop: 1 then 2, 4, 8, ... up to 30 s, then a terminal code ends it.
new_run
printf '1\n1\n1\n1\n1\n1\n1\n1\n1\n7\n' >"$NR_STATE/codes"
run_runner
assert_eq "64" "$STATUS" "a terminal code with the hub disabled ends the runner with 64: the task wrapper then disables the task"
assert_eq "10" "$(agent_runs)" "the agent ran ten times"
assert_eq "1 2 4 8 16 30 30 30 30" "$(sleeps)" "backoff: 1 s, doubling, at most 30 s (H2 §8.5)"
assert_eq "0" "$(hub_runs)" "without hub.enabled the hub is never started"
assert_false "and no hub.log is written" test -e "$NR_STATE/log/hub.log"
# A signal between `sleep &` and `SLEEP_PID=$!` leaves the sleep orphaned (T14b3 review P3 3): it must hold neither a
# single-runner lock (fd 9) nor the log pipe (fd 1, 2), so the next runner and the log writer are not kept waiting.
assert_false "the backoff sleep does not inherit the lock (fd 9)" grep -q '^9 ' "$NR_STATE/sleep-fds"
assert_false "the backoff sleep does not hold the log pipe" grep -qE '^[12] pipe:' "$NR_STATE/sleep-fds"
assert_contains "$(status_of)" "state=stopped" "the status says stopped"
assert_contains "$(status_of)" "exit_code=7" "with the exit code"
assert_contains "$(status_of)" "reason=$(terminal_reason 7)" "and why"
assert_eq "600" "$(stat -c %a "$NR_STATE/lib/node-run.status")" "node-run.status is 0600"
assert_contains "$(cat "$NR_STATE/log/agent.log")" "agent line 0" "the agent's stdout is in the log"
assert_contains "$(cat "$NR_STATE/log/agent.log")" "agent stderr" "and its stderr"
assert_contains "$(cat "$NR_STATE/log/agent.log")" "exited with 1; restarting in 4 s" "the runner logs each restart"
assert_contains "$(cat "$NR_STATE/log/agent.log")" "stopped for good" "and the stop"
assert_eq "agent run" "$(sort -u "$NR_STATE/agent-argv")" "it always runs exactly 'p2pc-agent run'"
# The agent gets a clean environment: nothing from Windows (spec §9.0: no WSL_INTEROP), only PATH, HOME and LANG.
assert_false "no WSL_INTEROP in the agent's environment" grep -q '^WSL_INTEROP=' "$NR_STATE/agent-env"
assert_false "no WSLENV in the agent's environment" grep -q '^WSLENV=' "$NR_STATE/agent-env"
assert_true "HOME=/root" grep -qx 'HOME=/root' "$NR_STATE/agent-env"
assert_false "the agent does not get the hub's data dir" grep -q '^P2PC_DATA_DIR=' "$NR_STATE/agent-env"
# The agent's config is in /var/lib/p2pc (the state dir), the one directory -Upgrade carries (T14b2 review P2).
assert_true "P2PC_AGENT_CONFIG names the config in the state dir" grep -qx "P2PC_AGENT_CONFIG=$NR_STATE/lib/agent.toml" "$NR_STATE/agent-env"
assert_true "a missing config is created" test -e "$NR_STATE/lib/agent.toml"
assert_eq "600" "$(stat -c %a "$NR_STATE/lib/agent.toml")" "created 0600"
new_run
printf '[server]\nnode_id = "testonly"\n' >"$NR_STATE/lib/agent.toml"
printf '7\n' >"$NR_STATE/codes"
run_runner
assert_true "an existing config is never touched" grep -q '^\[server\]' "$NR_STATE/lib/agent.toml"

# Every terminal code stops at once, with its own reason; nothing is restarted.
for code in 6 7 8; do
  new_run
  printf '%s\n' "$code" >"$NR_STATE/codes"
  run_runner
  assert_eq "64" "$STATUS" "exit $code: the runner ends with 64"
  assert_eq "1" "$(agent_runs)" "exit $code: no restart"
  assert_eq "" "$(sleeps)" "exit $code: no backoff"
  assert_contains "$(status_of)" "exit_code=$code" "exit $code: recorded"
done
# Exit 0 is a requested stop (SIGTERM to the agent): no restart either.
new_run
printf '0\n' >"$NR_STATE/codes"
run_runner
assert_eq "1" "$(agent_runs)" "exit 0: the agent was asked to stop; no restart"
assert_contains "$(status_of)" "state=stopped" "exit 0: stopped"
assert_eq "0" "$STATUS" "exit 0 stays 0: an ordinary end, the watchdog may start the node again"
assert_false "exit 0 records no stamp (nothing to refuse later)" grep -q '^stamp=' "$NR_STATE/lib/node-run.status"

# --- the fallback: a terminal stop is not retried while nothing changed (if the wrapper could not disable the task) ---
# The status of a terminal stop carries a stamp: the SHA-256 of agent.toml and of the agent binary. At start, a terminal
# record whose stamp still matches makes the runner exit 64 at once, without running the agent (no dial with a revoked
# identity every 5 minutes). A new enrollment (agent.toml) or a new agent (an -Upgrade) changes the stamp.
new_run
printf '[server]\nnode_id = "removed"\n' >"$NR_STATE/lib/agent.toml"
printf '7\n' >"$NR_STATE/codes"
run_runner
assert_eq "64" "$STATUS" "removed node: 64"
assert_true "the terminal stop records a stamp" grep -qE '^stamp=[0-9a-f]{64}$' "$NR_STATE/lib/node-run.status"
: >"$NR_STATE/agent-argv"
printf '7\n' >"$NR_STATE/codes"
run_runner
assert_eq "64" "$STATUS" "started again with nothing changed: 64 at once"
assert_eq "0" "$(agent_runs)" "and the agent is not run at all"
assert_contains "$(cat "$NR_STATE/log/agent.log")" "nothing changed since" "the log says why"
assert_contains "$(status_of)" "exit_code=7" "the record of the stop is kept"
# a new enrollment: agent.toml changes, so the agent runs again
printf '[server]\nnode_id = "reenrolled"\n' >"$NR_STATE/lib/agent.toml"
: >"$NR_STATE/agent-argv"
printf '0\n' >"$NR_STATE/codes"
run_runner
assert_eq "1" "$(agent_runs)" "after a new enrollment the agent runs again"
# a new agent binary (an upgrade, for exit 6): the stamp changes too
new_run
printf '6\n' >"$NR_STATE/codes"
run_runner
printf '\n# a newer agent\n' >>"$NR_STATE/p2pc-agent"
: >"$NR_STATE/agent-argv"
printf '0\n' >"$NR_STATE/codes"
run_runner
assert_eq "1" "$(agent_runs)" "after a new agent binary the agent runs again"
# a stamp that does not match (or none): the agent runs
new_run
printf 'state=stopped\nexit_code=7\nstamp=%064d\n' 0 >"$NR_STATE/lib/node-run.status"
printf '0\n' >"$NR_STATE/codes"
run_runner
assert_eq "1" "$(agent_runs)" "a terminal record with another stamp does not stop the agent"

# A long run resets the backoff: after a run of 60 s or more (here 300 s) the next restart waits 1 s again.
new_run
printf '1\n1\n1\n1\n7\n' >"$NR_STATE/codes"
printf '0\n' >"$NR_STATE/runtime"
run_runner
assert_eq "1 2 4 8" "$(sleeps)" "short runs: the backoff grows"
new_run
printf '1\n1\n1\n7\n' >"$NR_STATE/codes"
printf '300\n' >"$NR_STATE/runtime"
run_runner
assert_eq "1 1 1" "$(sleeps)" "a run of 300 s resets the backoff to 1 s"

# --- the boot status wait -------------------------------------------------------------------------------------------------
# A fresh status is there: no wait at all.
new_run
printf '7\n' >"$NR_STATE/codes"
run_runner
assert_eq "" "$(sleeps)" "fresh boot status: the agent starts at once"
assert_contains "$(cat "$NR_STATE/log/agent.log")" "boot status: fresh" "and the log says so"
# The previous start's status (another init): it waits, polling once a second, up to 60 s, then starts anyway.
new_run
sed -i 's/"init_starttime":5555/"init_starttime":4444/' "$NR_STATE/lib/boot-status.json"
printf '7\n' >"$NR_STATE/codes"
run_runner
assert_eq "60" "$(grep -c '^1$' "$NR_STATE/sleeps")" "a stale status: it polls once a second for 60 s"
assert_eq "1" "$(agent_runs)" "then starts the agent anyway (it treats GPUs as not ready by itself)"
assert_contains "$(cat "$NR_STATE/log/agent.log")" "no fresh boot status" "and logs that it did not come"
# No status at all: the same.
new_run
rm -f "$NR_STATE/lib/boot-status.json"
printf '7\n' >"$NR_STATE/codes"
run_runner
assert_eq "60" "$(grep -c '^1$' "$NR_STATE/sleeps")" "no status: it waits 60 s at most"

# --- what the agent inherits: never the lock, and SIGHUP ignored ----------------------------------------------------------------
new_run
printf '7\n' >"$NR_STATE/codes"
run_runner
assert_eq "closed" "$(cat "$NR_STATE/agent-fd9")" "the agent does not inherit the runner's lock (fd 9)"
assert_eq "1" "$(( 0x$(cat "$NR_STATE/agent-sigign") & 1 ))" "the agent ignores SIGHUP (the runner forwards a stop as TERM)"

# --- a second runner WAITS for the lock and takes over (the task stays attached), it never exits at once ------------------
# The real run: Stop-ScheduledTask killed conhost but not the wsl.exe children, so the first runner lived on; a later start
# found the lock held and exited 0, leaving the old runner unsupervised by the task. Now the new one waits for it.
new_run
printf '7\n' >"$NR_STATE/codes"
mkfifo "$NR_STATE/flock.fifo"
exec 8>"$NR_STATE/agent.lock"
flock -n 8
# 8>&-: the runner must not inherit the test's own locked descriptor, or the lock could never be released.
NR_FLOCK_FIFO="$NR_STATE/flock.fifo" runner_exec 8>&- &
second=$!
blocked="$(read_fifo "$NR_STATE/flock.fifo")"
assert_eq "blocked" "$blocked" "the second runner blocks on the agent lock"
assert_eq "0" "$(agent_runs)" "and starts no agent while the lock is held"
assert_contains "$(cat "$NR_STATE/log/agent.log")" "waiting" "it logs that it waits to take over"
exec 8>&- # the first runner ends
wait "$second"
assert_eq "1" "$(agent_runs)" "once the lock is free, the waiting runner takes over and starts the agent"
assert_contains "$(status_of)" "exit_code=7" "and supervises it to the end"

# --- SIGTERM to the runner: the agent gets TERM, and node-run.status ends as stopped ----------------------------------------
new_run
touch "$NR_STATE/long"
mkfifo "$NR_STATE/started.fifo"
runner_exec &
runner_pid=$!
started="$(read_fifo "$NR_STATE/started.fifo")"
assert_eq "started" "$started" "the long-running agent started"
assert_contains "$(status_of)" "state=running" "the status says running while it runs"
kill -TERM "$runner_pid"
wait "$runner_pid"
assert_eq "0" "$?" "a stopped runner exits 0"
assert_eq "TERM" "$(cat "$NR_STATE/agent-signals" 2>/dev/null)" "the agent got TERM from the runner"
assert_contains "$(status_of)" "state=stopped" "node-run.status ends as stopped"
assert_contains "$(cat "$NR_STATE/log/agent.log")" "stopping on a signal" "and the log says why"

# --- a stop signal during the backoff is acted on at once (T14b3): the delay is `sleep & wait`, not a foreground sleep --------
new_run
printf '1\n' >"$NR_STATE/codes"
touch "$NR_STATE/hold-sleep"
mkfifo "$NR_STATE/sleeping.fifo"
runner_exec &
runner_pid=$!
slept="$(read_fifo "$NR_STATE/sleeping.fifo")"
assert_eq "sleeping" "$slept" "the runner is in its backoff after the agent exited with 1"
assert_contains "$(status_of)" "state=restarting" "the status says restarting"
SECONDS=0
kill -TERM "$runner_pid"
wait "$runner_pid"
assert_true "TERM during the backoff ends the runner within a second (took ${SECONDS} s; the held sleep lasts 10 s)" test "$SECONDS" -lt 2
assert_contains "$(status_of)" "state=stopped" "node-run.status ends as stopped"
assert_contains "$(cat "$NR_STATE/log/agent.log")" "stopping on a signal" "and the log says why"
assert_eq "1" "$(agent_runs)" "and the agent was not started again"
# (INT is not tried (TERM and HUP are): a background job of a non-interactive shell starts with SIGINT ignored, and bash cannot trap it.)
for sig in TERM HUP; do
  new_run
  printf '1\n' >"$NR_STATE/codes"
  touch "$NR_STATE/hold-sleep"
  mkfifo "$NR_STATE/sleeping.fifo"
  runner_exec &
  runner_pid=$!
  read_fifo "$NR_STATE/sleeping.fifo" >/dev/null
  SECONDS=0
  kill -"$sig" "$runner_pid"
  wait "$runner_pid"
  assert_true "$sig during the backoff ends the runner within a second (took ${SECONDS} s)" test "$SECONDS" -lt 2
  assert_eq "1" "$(agent_runs)" "$sig: the agent was not started again"
done

# --- log rotation: 3 files of at most LOG_MAX bytes ----------------------------------------------------------------------------
new_run
printf '1\n1\n1\n1\n1\n1\n7\n' >"$NR_STATE/codes"
printf '40\n' >"$NR_STATE/lines"
LOG_MAX=2000 run_runner
log="$NR_STATE/log"
assert_true "agent.log exists" test -f "$log/agent.log"
assert_true "agent.log.1 exists" test -f "$log/agent.log.1"
assert_true "agent.log.2 exists" test -f "$log/agent.log.2"
assert_false "no agent.log.3: three files at most" test -e "$log/agent.log.3"
for f in agent.log agent.log.1 agent.log.2; do
  assert_true "$f is at most 2000 bytes ($(stat -c %s "$log/$f"))" test "$(stat -c %s "$log/$f")" -le 2000
done
assert_contains "$(tail -n 1 "$log/agent.log")" "nothing left to supervise" "the newest line (the runner's last) is in agent.log"
assert_contains "$(cat "$log/agent.log.1" "$log/agent.log")" "stopped for good" "and the agent's stop just before it"
assert_eq "700" "$(stat -c %a "$log")" "the log directory is 0700"
# A log already over the limit at start is rotated before the first line.
new_run
head -c 5000 /dev/zero | tr '\0' 'x' >"$NR_STATE/log/agent.log"
printf '7\n' >"$NR_STATE/codes"
LOG_MAX=2000 run_runner
assert_true "an oversized log is rotated at start" test "$(stat -c %s "$NR_STATE/log/agent.log")" -le 2000

# --- the hub: started with its own clean environment, its own log and its own backoff --------------------------------------
# A crash loop of the hub (1 s doubling to 30 s), then it stays up; the agent runs beside it, untouched.
new_run
enable_hub
touch "$NR_STATE/long"
mkfifo "$NR_STATE/started.fifo" "$NR_STATE/hub-started.fifo"
printf '1\n1\n1\n1\n1\n1\n1\n' >"$NR_STATE/hub-codes"
runner_exec &
runner_pid=$!
assert_eq "started" "$(read_fifo "$NR_STATE/started.fifo")" "the agent runs"
assert_eq "started" "$(read_fifo "$NR_STATE/hub-started.fifo")" "and the hub, once hub.enabled exists"
assert_eq "8" "$(hub_runs)" "the hub was started eight times (seven failures, then it stayed up)"
assert_eq "1 2 4 8 16 30 30" "$(sleeps)" "the hub's backoff: 1 s, doubling, at most 30 s"
assert_eq "server serve" "$(sort -u "$NR_STATE/hub-argv")" "it always runs exactly 'p2pc-server serve'"
assert_true "P2PC_DATA_DIR is the hub directory (the one the upgrade carries)" grep -qx "P2PC_DATA_DIR=$NR_STATE/hub" "$NR_STATE/hub-env"
assert_false "no WSL_INTEROP in the hub's environment" grep -q '^WSL_INTEROP=' "$NR_STATE/hub-env"
assert_false "no WSLENV in the hub's environment" grep -q '^WSLENV=' "$NR_STATE/hub-env"
assert_true "HOME=/root for the hub" grep -qx 'HOME=/root' "$NR_STATE/hub-env"
assert_false "the hub does not get the agent's config" grep -q '^P2PC_AGENT_CONFIG=' "$NR_STATE/hub-env"
assert_eq "closed" "$(cat "$NR_STATE/hub-fd9")" "the hub does not inherit a runner lock (fd 9)"
assert_eq "1" "$(( 0x$(cat "$NR_STATE/hub-sigign") & 1 ))" "the hub ignores SIGHUP (the runner forwards a stop as TERM)"
assert_eq "1" "$(agent_runs)" "the agent was started once, whatever the hub did"
kill -TERM "$runner_pid"
wait "$runner_pid"
assert_eq "0" "$?" "TERM: the runner exits 0"
assert_eq "TERM" "$(cat "$NR_STATE/hub-signals" 2>/dev/null)" "the hub got TERM"
assert_eq "TERM" "$(cat "$NR_STATE/agent-signals" 2>/dev/null)" "and the agent too"
# The logs are complete once the runner has ended (each log writer drains before its supervisor exits).
assert_contains "$(hub_log)" "hub line: listening" "the hub's output goes to hub.log"
assert_contains "$(hub_log)" "p2pc-server exited with 1; restarting in 4 s" "the hub's restarts are in hub.log"
assert_false "and not in agent.log" grep -q 'p2pc-server exited' "$NR_STATE/log/agent.log"
assert_false "the agent's lines are not in hub.log" grep -qE 'agent line|agent stderr|boot status' "$NR_STATE/log/hub.log"
assert_contains "$(hub_log)" "stopping on a signal" "hub.log says why"
assert_eq "700" "$(stat -c %a "$NR_STATE/log")" "the log directory is 0700"

# A long hub run resets its backoff, as the agent's does.
new_run
enable_hub
touch "$NR_STATE/long"
mkfifo "$NR_STATE/started.fifo" "$NR_STATE/hub-started.fifo"
printf '1\n1\n1\n' >"$NR_STATE/hub-codes"
printf '300\n' >"$NR_STATE/hub-runtime"
runner_exec &
runner_pid=$!
read_fifo "$NR_STATE/started.fifo" >/dev/null
assert_eq "started" "$(read_fifo "$NR_STATE/hub-started.fifo")" "the hub is up"
assert_eq "1 1 1" "$(sleeps)" "hub runs of 300 s reset its backoff to 1 s"
kill -TERM "$runner_pid"
wait "$runner_pid"

# The hub is never started with a REST bind that is not loopback (hard rule 4, H2 §8.5): the runner refuses, says why in
# hub.log, and tries again after its backoff (the config may be fixed).
new_run
enable_hub
touch "$NR_STATE/long" "$NR_STATE/hold-sleep"
mkfifo "$NR_STATE/started.fifo" "$NR_STATE/sleeping.fifo"
printf 'data_dir = "%s"\nbind = "0.0.0.0:7477"\n' "$NR_STATE/hub" >"$NR_STATE/hub/server.toml"
runner_exec &
runner_pid=$!
read_fifo "$NR_STATE/started.fifo" >/dev/null
assert_eq "sleeping" "$(read_fifo "$NR_STATE/sleeping.fifo")" "a hub with a LAN bind: the runner backs off"
assert_eq "0" "$(hub_runs)" "and never started p2pc-server"
kill -TERM "$runner_pid"
wait "$runner_pid"
assert_eq "0" "$?" "TERM: the runner exits 0"
assert_eq "TERM" "$(cat "$NR_STATE/agent-signals" 2>/dev/null)" "the agent ran beside it all along"
assert_contains "$(hub_log)" "refusing to start the hub" "hub.log says it refused"
assert_contains "$(hub_log)" "0.0.0.0:7477" "and names the bind"
# A missing p2pc-server (an image without the hub): the same, it never crash-loops faster than its backoff.
new_run
enable_hub
touch "$NR_STATE/long" "$NR_STATE/hold-sleep"
mkfifo "$NR_STATE/started.fifo" "$NR_STATE/sleeping.fifo"
rm -f "$NR_STATE/p2pc-server"
runner_exec &
runner_pid=$!
read_fifo "$NR_STATE/started.fifo" >/dev/null
assert_eq "sleeping" "$(read_fifo "$NR_STATE/sleeping.fifo")" "no p2pc-server: the runner backs off"
kill -TERM "$runner_pid"
wait "$runner_pid"
assert_contains "$(hub_log)" "is missing" "hub.log says the binary is missing"

# After the hub started, the runner checks its listeners in /proc every LISTEN_CHECK_S: a TCP listener of the hub that is
# not loopback stops it (TERM), whatever server.toml said; then the backoff, as after any exit.
new_run
enable_hub
touch "$NR_STATE/long" "$NR_STATE/hold-sleep"
mkfifo "$NR_STATE/started.fifo" "$NR_STATE/hub-started.fifo" "$NR_STATE/sleeping.fifo" "$NR_STATE/check.fifo" "$NR_STATE/checkgo.fifo"
printf '00000000:1D35\n' >"$NR_STATE/hub-listen"
runner_exec &
runner_pid=$!
read_fifo "$NR_STATE/started.fifo" >/dev/null
assert_eq "started" "$(read_fifo "$NR_STATE/hub-started.fifo")" "the hub started (and listens on 0.0.0.0:7477)"
assert_eq "check" "$(read_fifo "$NR_STATE/check.fifo")" "the runner waits for its listener check"
write_fifo "$NR_STATE/checkgo.fifo" go
assert_eq "sleeping" "$(read_fifo "$NR_STATE/sleeping.fifo")" "the check found a LAN listener: the hub was stopped and the runner backs off"
assert_eq "TERM" "$(cat "$NR_STATE/hub-signals" 2>/dev/null)" "the hub got TERM"
assert_eq "1" "$(hub_runs)" "it ran once"
kill -TERM "$runner_pid"
wait "$runner_pid"
assert_contains "$(hub_log)" "not loopback" "hub.log says why"
assert_contains "$(hub_log)" "0.0.0.0:7477" "and names the address"
assert_eq "1" "$(agent_runs)" "the agent ran beside it, once"
# The same check with a loopback listener: the hub stays up, check after check.
new_run
enable_hub
touch "$NR_STATE/long"
mkfifo "$NR_STATE/started.fifo" "$NR_STATE/hub-started.fifo" "$NR_STATE/check.fifo" "$NR_STATE/checkgo.fifo"
printf '0100007F:1D35\n' >"$NR_STATE/hub-listen"
runner_exec &
runner_pid=$!
read_fifo "$NR_STATE/started.fifo" >/dev/null
read_fifo "$NR_STATE/hub-started.fifo" >/dev/null
assert_eq "check" "$(read_fifo "$NR_STATE/check.fifo")" "the first listener check"
write_fifo "$NR_STATE/checkgo.fifo" go
assert_eq "check" "$(read_fifo "$NR_STATE/check.fifo")" "a loopback listener passes: the runner checks again later"
assert_false "and the hub was not stopped" test -e "$NR_STATE/hub-signals"
kill -TERM "$runner_pid"
wait "$runner_pid"
assert_eq "1" "$(hub_runs)" "the hub ran once"
assert_false "hub.log reports no LAN listener" grep -q 'not loopback' "$NR_STATE/log/hub.log"

# The hub has its own lock: while another runner's hub holds it, this one waits for it, and the agent is not held up.
new_run
enable_hub
touch "$NR_STATE/long"
mkfifo "$NR_STATE/started.fifo" "$NR_STATE/hub-started.fifo" "$NR_STATE/flock.fifo"
exec 8>"$NR_STATE/hub.lock"
flock -n 8
NR_FLOCK_FIFO="$NR_STATE/flock.fifo" runner_exec 8>&- &
runner_pid=$!
assert_eq "blocked" "$(read_fifo "$NR_STATE/flock.fifo")" "the hub supervisor blocks on the hub lock"
assert_eq "started" "$(read_fifo "$NR_STATE/started.fifo")" "while the agent starts (its lock is another one)"
assert_eq "0" "$(hub_runs)" "no hub while the hub lock is held"
exec 8>&-
assert_eq "started" "$(read_fifo "$NR_STATE/hub-started.fifo")" "once the hub lock is free, the hub starts"
assert_contains "$(hub_log)" "waiting" "hub.log says it waited"
kill -TERM "$runner_pid"
wait "$runner_pid"

# --- hub.enabled appears and goes away while the runner runs (the poll): the hub follows it, the agent does not -------------
new_run
touch "$NR_STATE/long"
mkfifo "$NR_STATE/started.fifo" "$NR_STATE/hub-started.fifo" "$NR_STATE/hub-stopped.fifo"
with_ticks
runner_exec &
runner_pid=$!
read_fifo "$NR_STATE/started.fifo" >/dev/null
assert_eq "tick" "$(await_tick)" "the runner polls for hub.enabled"
assert_eq "0" "$(hub_runs)" "no hub.enabled: no hub"
enable_hub
release_tick
assert_eq "started" "$(read_fifo "$NR_STATE/hub-started.fifo")" "hub.enabled appeared: the next poll starts the hub"
assert_eq "tick" "$(await_tick)" "the runner polls on"
disable_hub
release_tick
assert_eq "stopped" "$(read_fifo "$NR_STATE/hub-stopped.fifo")" "hub.enabled went away: the next poll stops the hub"
assert_eq "TERM" "$(cat "$NR_STATE/hub-signals" 2>/dev/null)" "with TERM"
assert_eq "tick" "$(await_tick)" "the runner goes on: the agent still runs"
assert_false "and the agent was not stopped" test -e "$NR_STATE/agent-signals"
kill -TERM "$runner_pid"
wait "$runner_pid"
assert_eq "0" "$?" "TERM: the runner exits 0"
assert_contains "$(hub_log)" "hub.enabled was removed" "hub.log says why the hub was stopped"
assert_eq "1" "$(hub_runs)" "the hub ran once"
assert_eq "1" "$(agent_runs)" "the agent ran once"

# --- terminal stops (H2 §8.5): the agent's terminal code stops only the agent; the hub keeps running after its own node was
# removed, and the runner exits 64 only when no child is left: the agent terminal AND the hub disabled.
new_run
enable_hub
printf '7\n' >"$NR_STATE/codes"
mkfifo "$NR_STATE/hub-started.fifo"
with_ticks
runner_exec &
runner_pid=$!
assert_eq "started" "$(read_fifo "$NR_STATE/hub-started.fifo")" "the hub runs"
# Taking the agent lock proves the agent's supervisor has ended (it holds the lock until it is gone).
flock "$NR_STATE/agent.lock" true
assert_contains "$(status_of)" "exit_code=7" "the agent stopped for good (the node was removed)"
await_tick >/dev/null
release_tick
assert_eq "tick" "$(await_tick)" "the runner keeps polling: it did not exit 64 with the hub enabled"
release_tick
assert_eq "tick" "$(await_tick)" "still running after another poll"
assert_false "the hub was not stopped" test -e "$NR_STATE/hub-signals"
disable_hub
release_tick
wait "$runner_pid"
assert_eq "64" "$?" "hub.enabled removed with the agent stopped for good: nothing is left, the runner exits 64"
assert_eq "TERM" "$(cat "$NR_STATE/hub-signals" 2>/dev/null)" "after stopping the hub"
assert_eq "1" "$(agent_runs)" "the agent was never restarted"
assert_contains "$(cat "$NR_STATE/log/agent.log")" "nothing left to supervise" "agent.log says why the runner ended"

# An agent that stops for good while hub.enabled exists from the start of the next run: the stamp fallback stops only the
# agent; the hub still runs.
new_run
enable_hub
printf '[server]\nnode_id = "removed"\n' >"$NR_STATE/lib/agent.toml"
printf 'state=stopped\nexit_code=7\nstamp=%s\n' "$(cat "$NR_STATE/lib/agent.toml" "$NR_STATE/p2pc-agent" | sha256sum | cut -d' ' -f1)" >"$NR_STATE/lib/node-run.status"
mkfifo "$NR_STATE/hub-started.fifo"
with_ticks
runner_exec &
runner_pid=$!
assert_eq "started" "$(read_fifo "$NR_STATE/hub-started.fifo")" "the hub starts although the agent stays stopped"
flock "$NR_STATE/agent.lock" true
assert_eq "0" "$(agent_runs)" "the agent is not run (nothing changed since its terminal stop)"
await_tick >/dev/null
release_tick
assert_eq "tick" "$(await_tick)" "the runner keeps running for the hub"
kill -TERM "$runner_pid"
wait "$runner_pid"
assert_eq "0" "$?" "TERM: 0"
assert_eq "TERM" "$(cat "$NR_STATE/hub-signals" 2>/dev/null)" "the hub got TERM"

# An agent asked to stop (exit 0) with the hub enabled: the hub keeps running too.
new_run
enable_hub
printf '0\n' >"$NR_STATE/codes"
mkfifo "$NR_STATE/hub-started.fifo"
with_ticks
runner_exec &
runner_pid=$!
read_fifo "$NR_STATE/hub-started.fifo" >/dev/null
flock "$NR_STATE/agent.lock" true
await_tick >/dev/null
release_tick
assert_eq "tick" "$(await_tick)" "agent exit 0 with the hub enabled: the runner keeps running"
disable_hub
release_tick
wait "$runner_pid"
assert_eq "0" "$?" "then hub.enabled removed: nothing left, exit 0 (an ordinary end)"

# --- the runner never logs the environment or a token: it has none to log ----------------------------------------------------
assert_false "p2pc-run never reads a token" grep -qi 'token' "$runner"

finish_tests "test-run"
