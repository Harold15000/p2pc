#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests for deploy/linux/p2pc-server.service: the directives T14b1 and spec §12 require are present with the exact
# values, and, when systemd-analyze is installed, the unit verifies and its exposure score stays low.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
make_scratch
unit="$here/../linux/p2pc-server.service"

# value_of <key>: every value of `key=` in the unit, space-joined (a key may repeat).
value_of() {
  sed -n "s/^$1=//p" "$unit" | paste -sd' ' -
}

assert_true "unit exists" test -f "$unit"
assert_true "SPDX header" grep -q '^# SPDX-License-Identifier: Apache-2.0' "$unit"

# --- identity, data dir and process -------------------------------------------------------------------------------
assert_eq "p2pc-server" "$(value_of User)" "User"
assert_eq "p2pc-server" "$(value_of Group)" "Group"
assert_eq "p2pc-server" "$(value_of StateDirectory)" "StateDirectory"
assert_eq "0700" "$(value_of StateDirectoryMode)" "StateDirectoryMode"
assert_eq "P2PC_DATA_DIR=/var/lib/p2pc-server" "$(value_of Environment)" "the data dir of spec §12"
assert_eq "/usr/local/bin/p2pc-server serve" "$(value_of ExecStart)" "ExecStart"
assert_eq "on-failure" "$(value_of Restart)" "Restart"
assert_eq "5s" "$(value_of RestartSec)" "RestartSec"
assert_eq "0077" "$(value_of UMask)" "UMask"
assert_eq "multi-user.target" "$(value_of WantedBy)" "WantedBy"
# No secret is ever passed through the unit.
assert_false "no EnvironmentFile" grep -q '^EnvironmentFile=' "$unit"
assert_false "no key material in the unit" grep -qiE 'p2pc_sk_|api.?key' "$unit"

# --- hardening (the list of the T14b1 task) ------------------------------------------------------------------------
for key in NoNewPrivileges PrivateTmp PrivateDevices ProtectHome ProtectKernelTunables ProtectKernelModules \
  ProtectKernelLogs ProtectControlGroups ProtectClock ProtectHostname RestrictNamespaces RestrictRealtime \
  RestrictSUIDSGID LockPersonality MemoryDenyWriteExecute; do
  assert_eq "yes" "$(value_of "$key")" "$key"
done
assert_eq "strict" "$(value_of ProtectSystem)" "ProtectSystem"
assert_eq "native" "$(value_of SystemCallArchitectures)" "SystemCallArchitectures"
assert_eq "@system-service ~@privileged @resources" "$(value_of SystemCallFilter)" "SystemCallFilter"
assert_true "CapabilityBoundingSet is empty" grep -qx 'CapabilityBoundingSet=' "$unit"
assert_eq "" "$(value_of CapabilityBoundingSet)" "no capability"
assert_eq "AF_INET AF_INET6 AF_UNIX AF_NETLINK" "$(value_of RestrictAddressFamilies)" "RestrictAddressFamilies"
assert_true "AF_NETLINK is justified in a comment" grep -qE '^# .*AF_NETLINK.*netwatch' "$unit"
# Nothing that would weaken the sandbox.
assert_false "no AmbientCapabilities granted" grep -qE '^AmbientCapabilities=.+' "$unit"
assert_false "no ReadWritePaths beyond the StateDirectory" grep -q '^ReadWritePaths=' "$unit"

# --- systemd-analyze, when available --------------------------------------------------------------------------------
# Measured on a real host (the architect's run of 2026-11-06, Ubuntu 24.04, systemd 255): exposure 1.1, "OK".
readonly MAX_EXPOSURE=2.0
# Some build sandboxes give systemd-analyze no writable /run, and then it cannot even start. Locally that is "cannot
# check here", never "the unit is wrong": the check is skipped with a NOTE, and never passes silently. With
# CHECK_REQUIRE_SYSTEMD_ANALYZE=1 (CI), it is a failure: CI must really check the unit.
require_analyze="${CHECK_REQUIRE_SYSTEMD_ANALYZE:-0}"
# skip_or_fail <what> <output>: a NOTE locally, a failed assertion when systemd-analyze is required.
skip_or_fail() {
  if [[ "$require_analyze" == 1 ]]; then
    assert_true "systemd-analyze $1 can run (CHECK_REQUIRE_SYSTEMD_ANALYZE=1): $(first_line "$2")" false
  else
    echo "   NOTE: SKIPPED systemd-analyze $1: it cannot initialise here ($(first_line "$2"))"
  fi
}
cannot_init() {
  [[ "$1" == *"Failed to initialize unit search paths"* || "$1" == *"Failed to setup working directory"* ]]
}
assert_true "classifies the unit-search-path error" cannot_init "Failed to initialize unit search paths: Read-only file system"
assert_true "classifies the working-directory error" cannot_init "Failed to setup working directory: Read-only file system"
assert_false "a real verify error is not a skip" cannot_init "p2pc-server.service:12: Unknown key name 'Bogus'"
first_line() { printf '%s\n' "$1" | head -n 1; }

if ! command -v systemd-analyze >/dev/null 2>&1; then
  if [[ "$require_analyze" == 1 ]]; then
    assert_true "systemd-analyze is installed (CHECK_REQUIRE_SYSTEMD_ANALYZE=1)" false
  else
    echo "   NOTE: systemd-analyze is not installed; the unit was checked statically only"
  fi
else
  # `verify` checks that ExecStart exists: point a copy at a stand-in binary. Everything else is the real unit.
  fake_bin="$SCRATCH/p2pc-server"
  printf '#!/bin/sh\nexit 0\n' >"$fake_bin"
  chmod 0755 "$fake_bin"
  sed "s|^ExecStart=/usr/local/bin/p2pc-server|ExecStart=$fake_bin|" "$unit" >"$SCRATCH/p2pc-server.service"
  verify_out="$(systemd-analyze verify --man=no "$SCRATCH/p2pc-server.service" 2>&1)"
  verify_status=$?
  if cannot_init "$verify_out"; then
    skip_or_fail verify "$verify_out"
  else
    # Lines about other units on the build machine are not ours.
    own="$(printf '%s\n' "$verify_out" | grep 'p2pc-server.service' || true)"
    assert_eq "0" "$verify_status" "systemd-analyze verify exit status (output: $verify_out)"
    assert_eq "" "$own" "systemd-analyze verify reports nothing about the unit"
  fi

  security_out="$(systemd-analyze security --offline=true "$unit" 2>&1)"
  score="$(printf '%s\n' "$security_out" | sed -n 's/.*Overall exposure level for p2pc-server.service: \([0-9.]*\).*/\1/p')"
  if cannot_init "$security_out"; then
    skip_or_fail security "$security_out"
  elif [[ -z "$score" ]] && [[ "$security_out" == *"--offline"* || "$security_out" == *"unrecognized option"* ]]; then
    # `--offline` exists since systemd 250 (Ubuntu 22.04 has 249).
    echo "   NOTE: SKIPPED systemd-analyze security: this version has no --offline"
  else
    echo "   systemd-analyze security: exposure ${score:-?} (at most $MAX_EXPOSURE)"
    assert_true "exposure score '${score:-none}' is at most $MAX_EXPOSURE (output: $security_out)" \
      awk -v s="${score:-99}" -v max="$MAX_EXPOSURE" 'BEGIN { exit !(s + 0 <= max + 0) }'
  fi
fi

finish_tests "test-server-unit"
