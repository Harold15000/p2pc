#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Unit tests for the pure helpers of deploy/linux/setup-host.sh, plus smoke tests of its argument handling.
# (The real setup needs root and systemd; it is exercised on a node, see deploy/README.md.)
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
# shellcheck source=deploy/linux/setup-host.sh
source "$here/../linux/setup-host.sh"
make_scratch

# --- podman_version_from / version_ge ---------------------------------------------------------------------------------
assert_eq "4.9.3" "$(podman_version_from 'podman version 4.9.3')" "plain version"
assert_eq "5.2.0" "$(podman_version_from 'podman version 5.2.0-dev')" "pre-release suffix dropped"
assert_eq "" "$(podman_version_from 'garbage')" "no version"
assert_true "4.9.3 ok" version_ge 4.9.3 4.9
assert_true "5.0 ok" version_ge 5.0.0 4.9
assert_false "4.3.1 too old" version_ge 4.3.1 4.9
assert_false "3.4.4 too old (Ubuntu 22.04)" version_ge 3.4.4 4.9

# --- missing_controllers ----------------------------------------------------------------------------------------------
assert_eq "" "$(missing_controllers 'cpuset cpu io memory pids')" "all delegated"
assert_eq "cpu pids" "$(missing_controllers 'cpuset io memory')" "cpu and pids missing"
assert_eq "cpu memory pids" "$(missing_controllers '')" "nothing delegated"
assert_eq "cpu" "$(missing_controllers 'cpus memory pids')" "cpuset-like names do not count as cpu"

# --- sub-id ranges -----------------------------------------------------------------------------------------------
cat >"$SCRATCH/subuid" <<'S'
alice:100000:65536
bob:165536:65536
S
assert_eq "231072" "$(sub_next_start "$SCRATCH/subuid")" "next range follows the highest end"
printf '' >"$SCRATCH/empty"
assert_eq "100000" "$(sub_next_start "$SCRATCH/empty")" "empty file starts at 100000"
assert_eq "100000" "$(sub_next_start "$SCRATCH/does-not-exist")" "missing file starts at 100000"
printf 'weird:1000:10\n' >"$SCRATCH/low"
assert_eq "100000" "$(sub_next_start "$SCRATCH/low")" "never starts below 100000"
# A range that ends at the very top of the 32-bit id space leaves no room for another one: rejected, never a bogus start.
printf 'containers:2147483647:2147483648\n' >"$SCRATCH/big"
assert_false "no start after a range that ends at 2^32-1" sub_next_start "$SCRATCH/big"
assert_eq "" "$(sub_next_start "$SCRATCH/big" 2>/dev/null)" "and nothing is printed for it"
# The last start that still fits: start + 65535 == 4294967294.
printf 'edge:4294836223:65536\n' >"$SCRATCH/edge"
assert_eq "4294901759" "$(sub_next_start "$SCRATCH/edge")" "the highest start that still fits is accepted"
printf 'edge:4294836224:65536\n' >"$SCRATCH/edge2"
assert_false "one id more and it no longer fits" sub_next_start "$SCRATCH/edge2"
assert_true "has entry" has_sub_entry "$SCRATCH/subuid" alice
assert_false "no entry for a prefix of a name" has_sub_entry "$SCRATCH/subuid" ali
assert_false "no entry" has_sub_entry "$SCRATCH/subuid" p2pc

# --- steps with fake system commands: every change is verified, a failure is a TODO, never "ready" ----------------------
fake_state="$SCRATCH/fake"
fakebin="$SCRATCH/fakebin"
mkdir -p "$fake_state" "$fakebin" "$SCRATCH/home"
cat >"$fakebin/id" <<'FAKE'
#!/usr/bin/env bash
[[ -e "$FAKE_STATE/user" ]] || exit 1
[[ "$*" == "-u p2pc" ]] && echo 1234
exit 0
FAKE
cat >"$fakebin/useradd" <<'FAKE'
#!/usr/bin/env bash
[[ -e "$FAKE_STATE/useradd-fail" ]] && exit 9
[[ -e "$FAKE_STATE/useradd-noop" ]] && exit 0
touch "$FAKE_STATE/user"
FAKE
cat >"$fakebin/usermod" <<'FAKE'
#!/usr/bin/env bash
[[ -e "$FAKE_STATE/usermod-fail" ]] && exit 9
[[ -e "$FAKE_STATE/usermod-noop" ]] && exit 0
range="$2"
first="${range%-*}"
last="${range#*-}"
case "$1" in
  --add-subuids) printf 'p2pc:%s:%s\n' "$first" "$((last - first + 1))" >>"$FAKE_SUBUID" ;;
  --add-subgids) printf 'p2pc:%s:%s\n' "$first" "$((last - first + 1))" >>"$FAKE_SUBGID" ;;
esac
FAKE
cat >"$fakebin/loginctl" <<'FAKE'
#!/usr/bin/env bash
[[ -e "$FAKE_STATE/loginctl-fail" ]] && exit 9
[[ -e "$FAKE_STATE/loginctl-noop" ]] && exit 0
touch "$FAKE_LINGER/p2pc"
FAKE
cat >"$fakebin/chown" <<'FAKE'
#!/usr/bin/env bash
[[ -e "$FAKE_STATE/chown-fail" ]] && exit 9
exit 0
FAKE
cat >"$fakebin/stat" <<'FAKE'
#!/usr/bin/env bash
# The owner is whatever the scenario says; everything else is the real stat.
if [[ "$*" == "-c %U "* && -e "$FAKE_STATE/owner-ok" ]]; then echo p2pc; exit 0; fi
exec /usr/bin/stat "$@"
FAKE
printf '#!/bin/sh\nexit 0\n' >"$fakebin/newuidmap"
cp "$fakebin/newuidmap" "$fakebin/newgidmap"
chmod +x "$fakebin"/*
export FAKE_STATE="$fake_state" FAKE_SUBUID="$SCRATCH/f-subuid" FAKE_SUBGID="$SCRATCH/f-subgid" FAKE_LINGER="$SCRATCH/linger"
mkdir -p "$FAKE_LINGER"
SUBUID_FILE="$FAKE_SUBUID"
SUBGID_FILE="$FAKE_SUBGID"
LINGER_DIR="$FAKE_LINGER"
P2PC_HOME="$SCRATCH/home"
chmod 0700 "$P2PC_HOME"
orig_path="$PATH"

# scenario <name> [flags that exist as files in the fake state]...: resets everything, then sets the flags
scenario() {
  rm -rf "$fake_state" "$FAKE_LINGER"
  mkdir -p "$fake_state" "$FAKE_LINGER"
  : >"$FAKE_SUBUID"
  : >"$FAKE_SUBGID"
  TODO_COUNT=0
  PLAN_COUNT=0
  CHECK_ONLY=0
  local f
  for f in "$@"; do : >"$fake_state/$f"; done
  PATH="$fakebin:$orig_path"
}
# run_steps <step>...: runs the steps in this shell (so TODO_COUNT is visible); output goes to $SCRATCH/out
run_steps() {
  local st
  : >"$SCRATCH/out"
  for st in "$@"; do "$st" >>"$SCRATCH/out" 2>&1; done
  OUT="$(cat "$SCRATCH/out")"
}

# The install hints are not apt-only (T14c review): each names apt, dnf and pacman.
scenario owner-ok
PATH="$(path_without "$fakebin" podman crun newuidmap newgidmap)"
run_steps step_subids step_podman
for hint in "apt-get install uidmap" "dnf install shadow-utils" "pacman -S shadow" \
  "apt-get install podman" "dnf install podman" "pacman -S podman" \
  "apt-get install crun" "dnf install crun" "pacman -S crun"; do
  assert_contains "$OUT" "$hint" "the hint names: $hint"
done

scenario owner-ok
run_steps step_user
assert_eq "0" "$TODO_COUNT" "apply mode, user missing, useradd works: no TODO"
assert_contains "$OUT" "[done] created system user p2pc" "the creation is reported as done"

scenario useradd-fail
run_steps step_user
assert_eq "1" "$TODO_COUNT" "useradd fails: one TODO"
assert_contains "$OUT" "useradd failed" "useradd fails: the message says so"
assert_false "useradd fails: nothing is reported as done" grep -q '\[done\]' <<<"$OUT"

scenario useradd-noop
run_steps step_user
assert_eq "1" "$TODO_COUNT" "useradd claims success but no user: one TODO"
assert_contains "$OUT" "still does not exist" "useradd noop: the message says so"

scenario useradd-fail
run_steps step_user step_subids step_linger
assert_true "apply mode, user missing: later steps add TODOs, not 'would'" test "$TODO_COUNT" -ge 4
assert_contains "$OUT" "user p2pc does not exist" "later steps explain why"

scenario user owner-ok
run_steps step_user step_subids step_linger
assert_eq "0" "$TODO_COUNT" "fresh user, everything applies cleanly: no TODO"
assert_contains "$OUT" "[done] added $SUBUID_FILE range 100000-165535" "subuid range added and verified"
assert_contains "$OUT" "loginctl enable-linger p2pc" "linger enabled and verified"
assert_false "no TODO and no plan lines" grep -qE '\[(TODO|plan)\]' <<<"$OUT"

scenario user owner-ok
printf 'p2pc:100000:65536\n' >"$FAKE_SUBUID"
printf 'p2pc:100000:65536\n' >"$FAKE_SUBGID"
: >"$FAKE_LINGER/p2pc"
run_steps step_user step_subids step_linger
assert_eq "0" "$TODO_COUNT" "everything already in place: no TODO"
assert_false "nothing is changed when everything is in place" grep -q '\[done\]' <<<"$OUT"

scenario user owner-ok usermod-fail
run_steps step_subids
assert_eq "2" "$TODO_COUNT" "usermod fails: a TODO for subuid and one for subgid"
assert_contains "$OUT" "usermod --add-subuids 100000-165535 p2pc failed" "usermod failure names the command"

scenario user owner-ok usermod-noop
run_steps step_subids
assert_eq "2" "$TODO_COUNT" "usermod claims success but the range is missing: TODOs"
assert_contains "$OUT" "still has no range" "usermod noop is caught by the re-check"

scenario user owner-ok
printf 'containers:2147483647:2147483648\n' >"$FAKE_SUBUID"
run_steps step_subids
assert_eq "1" "$TODO_COUNT" "no room for another sub-id range: one TODO (subuid), subgid is still added"
assert_contains "$OUT" "32-bit id space" "the TODO says why"

scenario user loginctl-fail
run_steps step_linger
assert_eq "1" "$TODO_COUNT" "loginctl fails: TODO"
scenario user loginctl-noop
run_steps step_linger
assert_eq "1" "$TODO_COUNT" "loginctl claims success but linger is off: TODO"

scenario user owner-ok
CHECK_ONLY=1
run_steps step_linger
assert_eq "1" "$PLAN_COUNT" "--check-only with linger off is one [plan] step (it used to report ready)"
assert_eq "0" "$TODO_COUNT" "a [plan] step is not a [TODO]: install-node.sh does it itself"
assert_contains "$OUT" "[plan]" "--check-only prints a plan line"

# T14g item 8: the closing line and exit code. Only [TODO]s make the host "not ready".
TODO_COUNT=0 PLAN_COUNT=4
out="$(print_result)"
rc=$?
assert_eq "0" "$rc" "only [plan] steps left: exit 0"
assert_contains "$out" "Ready: install-node.sh will do the 4 [plan] step(s) above" "only [plan] steps left: says so"
assert_false "only [plan] steps left: not 'NOT ready'" grep -q 'NOT ready' <<<"$out"
TODO_COUNT=2 PLAN_COUNT=4
out="$(print_result)"
rc=$?
assert_eq "1" "$rc" "a [TODO] is open: exit 1"
assert_contains "$out" "NOT ready: 2 item(s)" "a [TODO] is open: NOT ready, counting the TODOs only"
TODO_COUNT=0 PLAN_COUNT=0
out="$(print_result)"
assert_eq "Result: ready." "$out" "nothing left: ready"
TODO_COUNT=0 PLAN_COUNT=0

# T14g item 6: --check-only and the real run agree on the NVIDIA CDI spec. A current spec is kept, not regenerated.
cat >"$fakebin/nvidia-smi" <<'FAKE'
#!/usr/bin/env bash
echo "GPU 0: Fake GPU (UUID: GPU-example)"
FAKE
cat >"$fakebin/nvidia-ctk" <<'FAKE'
#!/usr/bin/env bash
echo "nvidia-ctk $*" >>"$FAKE_STATE/ctk-calls"
case "$*" in "cdi generate --output="*) echo "kind: nvidia.com/gpu" >"${3#--output=}" ;; esac
FAKE
chmod +x "$fakebin"/nvidia-smi "$fakebin"/nvidia-ctk
CDI_SPEC="$SCRATCH/cdi/nvidia.yaml"
NVIDIA_VERSION_FILE="$SCRATCH/driver-version"
mkdir -p "$SCRATCH/cdi"
: >"$NVIDIA_VERSION_FILE"
touch -d '2026-01-01' "$NVIDIA_VERSION_FILE"
echo "kind: nvidia.com/gpu" >"$CDI_SPEC"
touch -d '2026-06-01' "$CDI_SPEC"
scenario
CHECK_ONLY=1
run_steps step_gpu
assert_eq "0" "$((TODO_COUNT + PLAN_COUNT))" "check-only: a current CDI spec needs nothing"
scenario
run_steps step_gpu
assert_false "apply: a current CDI spec is not regenerated" test -e "$fake_state/ctk-calls"
assert_contains "$OUT" "present and current" "apply: it says it kept the spec"
touch -d '2025-01-01' "$CDI_SPEC"
scenario
CHECK_ONLY=1
run_steps step_gpu
assert_eq "1" "$PLAN_COUNT" "check-only: a spec older than the driver is planned for regeneration"
scenario
run_steps step_gpu
assert_true "apply: a spec older than the driver is regenerated" grep -q 'cdi generate' "$fake_state/ctk-calls"
rm -f "$CDI_SPEC"
scenario
CHECK_ONLY=1
run_steps step_gpu
assert_eq "1" "$PLAN_COUNT" "check-only: a missing spec is planned"
scenario
run_steps step_gpu
assert_true "apply: a missing spec is generated" test -s "$CDI_SPEC"

scenario user
run_steps step_user
assert_eq "0" "$TODO_COUNT" "home owned by someone else, chown works: fixed and done"
assert_contains "$OUT" "chown p2pc:p2pc" "the chown is reported"
scenario user chown-fail
run_steps step_user
assert_eq "1" "$TODO_COUNT" "home owned by someone else, chown fails: TODO"

PATH="$orig_path"
TODO_COUNT=0

# --- argument handling -------------------------------------------------------------------------------------------
script="$here/../linux/setup-host.sh"
bash "$script" --bogus >/dev/null 2>&1
assert_eq "2" "$?" "unknown flag: exit 2"
bash "$script" --help >/dev/null 2>&1
assert_eq "0" "$?" "--help: exit 0"
if [[ $EUID -ne 0 ]]; then
  bash "$script" >/dev/null 2>&1
  assert_eq "3" "$?" "changing the system as non-root: exit 3"
fi
out="$(bash "$script" --check-only 2>&1)"
rc=$?
if [[ $rc -ne 0 && $rc -ne 1 ]]; then _fail "--check-only exit code was $rc (output: $out)"; fi
assert_contains "$out" "check-only" "--check-only says so"
assert_contains "$out" "cgroup" "--check-only reports cgroups"
assert_contains "$out" "podman" "--check-only reports podman"

finish_tests "test-setup-host"
