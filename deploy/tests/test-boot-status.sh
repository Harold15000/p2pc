#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests for deploy/wsl/boot-status.sh: "fresh" means the status records the start ticks of this distro's init, compared
# for equality (T14a2 review carry-over: by identity, not by time).
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
# shellcheck source=deploy/wsl/boot-status.sh
source "$here/../wsl/boot-status.sh"
make_scratch

# A real-looking /proc/1/stat: field 22 is 4242. The command name may hold spaces and parentheses.
stat_plain='1 (init) S 0 1 1 0 -1 4194560 1 2 3 4 5 6 7 8 20 0 1 0 4242 2265088 300 18446744073709551615'
stat_odd='1 (my (odd) init) S 0 1 1 0 -1 4194560 1 2 3 4 5 6 7 8 20 0 1 0 4242 2265088 300 1'
assert_eq "4242" "$(proc_starttime "$stat_plain")" "field 22 of /proc/1/stat"
assert_eq "4242" "$(proc_starttime "$stat_odd")" "a command name with spaces and parentheses"
assert_false "no parenthesis: unreadable" proc_starttime '1 init S 0'
assert_false "too few fields: unreadable" proc_starttime '1 (init) S 0 1 1'
assert_false "not a number: unreadable" proc_starttime '1 (init) S 0 1 1 0 -1 4194560 1 2 3 4 5 6 7 8 20 0 1 0 x 2265088'
assert_false "empty: unreadable" proc_starttime ''

mkdir -p "$SCRATCH/proc/1"
printf '%s\n' "$stat_plain" >"$SCRATCH/proc/1/stat"
assert_eq "4242" "$(P2PC_PROC="$SCRATCH/proc" current_init_starttime)" "reads \$P2PC_PROC/1/stat"
assert_false "no /proc/1/stat: fails" env P2PC_PROC="$SCRATCH/none" bash -c "source '$here/../wsl/boot-status.sh'; current_init_starttime"

fresh='{"time":"2026-11-06T10:00:00Z","init_starttime":4242,"cdi":"fresh","cdi_regenerated":false,"errors":[],"notes":[]}'
old='{"time":"2026-11-06T10:00:00Z","init_starttime":4241,"cdi":"fresh","cdi_regenerated":false,"errors":[],"notes":[]}'
none='{"time":"2026-11-06T10:00:00Z","init_starttime":null,"cdi":"fresh","cdi_regenerated":false,"errors":[],"notes":[]}'
legacy='{"time":"2026-11-06T10:00:00Z","cdi":"fresh","cdi_regenerated":false,"errors":[],"notes":[]}'
assert_eq "4242" "$(status_init_starttime "$fresh")" "the recorded starttime"
assert_false "null: none recorded" status_init_starttime "$none"
assert_false "an older p2pc-boot recorded none" status_init_starttime "$legacy"
assert_true "same init: fresh" boot_status_fresh "$fresh" 4242
assert_false "another init (the previous start): not fresh" boot_status_fresh "$old" 4242
assert_false "a LATER number is not fresh either: equality, not order" boot_status_fresh "$fresh" 4241
assert_false "no identity in the status: not fresh" boot_status_fresh "$legacy" 4242
assert_false "null identity: not fresh" boot_status_fresh "$none" 4242
assert_false "unknown current init: not fresh" boot_status_fresh "$fresh" ""
assert_false "a prefix is not equal" boot_status_fresh '{"init_starttime":42420,"cdi":"x"}' 4242
# The time no longer matters at all: a status whose time is far in the "future" or "past" is judged by identity only.
assert_true "time is ignored" boot_status_fresh '{"time":"1999-01-01T00:00:00Z","init_starttime":4242}' 4242

finish_tests "test-boot-status"
