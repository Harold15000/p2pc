#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests for deploy/wsl/p2pc-node-run, the supervisor the "P2PC node" Scheduled Task runs inside the p2pc-node distro:
# the wait for a fresh boot status, the restart backoff (1 s, doubling, at most 60 s, back to 1 s after a long run), the
# terminal exit codes that stop it for good (and why, in node-run.status), and the size-rotated log. Everything runs
# with fakes: a fake p2pc-agent that exits with scripted codes, and `sleep`/`date` stubs on a fake clock, so nothing
# ever really waits.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
runner="$here/../wsl/p2pc-node-run"
# shellcheck source=deploy/wsl/p2pc-node-run
source "$runner"
make_scratch

# --- pure helpers ---------------------------------------------------------------------------------------------------
assert_eq "2" "$(next_delay 1)" "1 s doubles to 2 s"
assert_eq "32" "$(next_delay 16)" "16 s doubles to 32 s"
assert_eq "60" "$(next_delay 32)" "the delay is capped at 60 s"
assert_eq "60" "$(next_delay 60)" "and stays there"
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

# --- the end-to-end runs ------------------------------------------------------------------------------------------------
fakebin="$SCRATCH/fakebin"
mkdir -p "$fakebin"
# sleep N: advances the fake clock by N and records it; never waits.
cat >"$fakebin/sleep" <<'FAKE'
#!/bin/sh
echo "$1" >>"$NR_STATE/sleeps"
# What the sleep inherited (fd number and target): it must not hold the lock (9) or the log pipe (1, 2).
for fd in /proc/$$/fd/*; do echo "${fd##*/} $(readlink "$fd")"; done >>"$NR_STATE/sleep-fds"
# A held sleep (the backoff test): say so on a FIFO, then really sleep, so the test can signal the runner mid-backoff.
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
# knows the runner is waiting for the lock without polling or sleeping.
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
# What it inherited: the runner's lock (fd 9) must not reach it, and SIGHUP must be ignored (SigIgn bit 0).
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
new_run() {
  NR_STATE="$(mktemp -d "$SCRATCH/run.XXXXXX")"
  write_fake_agent
  mkdir -p "$NR_STATE/proc/1" "$NR_STATE/lib" "$NR_STATE/log"
  printf '%s\n' "$proc1" >"$NR_STATE/proc/1/stat"
  printf '{"time":"2026-11-06T10:00:00Z","init_starttime":5555,"cdi":"skipped","cdi_regenerated":false,"errors":[],"notes":[]}\n' \
    >"$NR_STATE/lib/boot-status.json"
}
# runner_exec: replaces the current (sub)shell with the runner and its fakes. `runner_exec &` therefore gives the
# runner's own PID in $!, so signals reach it.
runner_exec() {
  exec env -i PATH="$fakebin:/usr/bin:/bin" NR_STATE="$NR_STATE" P2PC_PROC="$NR_STATE/proc" \
    P2PC_NODE_RUN_AGENT="$NR_STATE/p2pc-agent" P2PC_NODE_RUN_STATE_DIR="$NR_STATE/lib" \
    P2PC_NODE_RUN_LOG_DIR="$NR_STATE/log" P2PC_NODE_RUN_LOCK="$NR_STATE/lock" \
    P2PC_NODE_RUN_LOG_MAX_BYTES="${LOG_MAX:-10485760}" WSL_INTEROP=/run/WSL/1_interop WSLENV=SECRETISH \
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
sleeps() { paste -sd' ' "$NR_STATE/sleeps" 2>/dev/null; }
status_of() { cat "$NR_STATE/lib/node-run.status" 2>/dev/null; }
agent_runs() {
  local n
  n="$(grep -c '^agent run$' "$NR_STATE/agent-argv" 2>/dev/null)"
  echo "${n:-0}"
}

# A crash loop: 1 then 2, 4, 8, ... up to 60 s, then a terminal code ends it.
new_run
printf '1\n1\n1\n1\n1\n1\n1\n1\n1\n7\n' >"$NR_STATE/codes"
run_runner
assert_eq "64" "$STATUS" "a terminal code ends the runner with 64: the task wrapper then disables the task (spec 9.0)"
assert_eq "10" "$(agent_runs)" "the agent ran ten times"
assert_eq "1 2 4 8 16 32 60 60 60" "$(sleeps)" "backoff: 1 s, doubling, at most 60 s"
# A signal between `sleep &` and `SLEEP_PID=$!` leaves the sleep orphaned (T14b3 review P3 3): it must hold neither the
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
exec 8>"$NR_STATE/lock"
flock -n 8
# 8>&-: the runner must not inherit the test's own locked descriptor, or the lock could never be released.
NR_FLOCK_FIFO="$NR_STATE/flock.fifo" runner_exec 8>&- &
second=$!
blocked="$(read_fifo "$NR_STATE/flock.fifo")"
assert_eq "blocked" "$blocked" "the second runner blocks on the lock"
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
assert_contains "$(cat "$log/agent.log")" "stopped for good" "the newest lines are in agent.log"
assert_eq "700" "$(stat -c %a "$log")" "the log directory is 0700"
# A log already over the limit at start is rotated before the first line.
new_run
head -c 5000 /dev/zero | tr '\0' 'x' >"$NR_STATE/log/agent.log"
printf '7\n' >"$NR_STATE/codes"
LOG_MAX=2000 run_runner
assert_true "an oversized log is rotated at start" test "$(stat -c %s "$NR_STATE/log/agent.log")" -le 2000

# --- the runner never logs the environment or a token: it has none to log ----------------------------------------------------
assert_false "p2pc-node-run never reads a token" grep -qi 'token' "$runner"

finish_tests "test-node-run"
