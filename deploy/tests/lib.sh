#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tiny assertion helpers for the deploy/ unit tests (plain bash, no framework).
# Each test file sources this, then the script under test (which only defines functions when sourced).
# shellcheck disable=SC2034  # the counters are read by finish_tests

TESTS_RUN=0
TESTS_FAILED=0

_fail() {
  TESTS_FAILED=$((TESTS_FAILED + 1))
  printf 'FAIL: %s\n' "$*" >&2
}

# assert_eq <expected> <actual> <description>
assert_eq() {
  TESTS_RUN=$((TESTS_RUN + 1))
  if [[ "$1" != "$2" ]]; then
    _fail "$3: expected [$1], got [$2]"
  fi
}

# assert_true <description> <command...>: the command must succeed.
assert_true() {
  TESTS_RUN=$((TESTS_RUN + 1))
  local desc="$1"
  shift
  if ! "$@" >/dev/null 2>&1; then
    _fail "$desc: command failed: $*"
  fi
}

# assert_false <description> <command...>: the command must fail.
assert_false() {
  TESTS_RUN=$((TESTS_RUN + 1))
  local desc="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    _fail "$desc: command unexpectedly succeeded: $*"
  fi
}

# assert_contains <haystack> <needle> <description>
assert_contains() {
  TESTS_RUN=$((TESTS_RUN + 1))
  if [[ "$1" != *"$2"* ]]; then
    _fail "$3: [$2] not found in [$1]"
  fi
}

finish_tests() {
  local name="${1:-tests}"
  if ((TESTS_FAILED > 0)); then
    printf '%s: %d of %d assertions FAILED\n' "$name" "$TESTS_FAILED" "$TESTS_RUN" >&2
    exit 1
  fi
  printf '%s: %d assertions passed\n' "$name" "$TESTS_RUN"
}

# A private scratch directory, removed on exit.
make_scratch() {
  SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/p2pc-deploy-test.XXXXXX")"
  # shellcheck disable=SC2064  # expand now: SCRATCH is fixed for the life of the test
  trap "rm -rf '$SCRATCH'" EXIT
}

# path_without <fakebin> <tool>...: prints a new directory to use as the WHOLE of PATH. It holds a symlink to every
# command the real PATH offers, with the fakes in <fakebin> taking the place of the real ones, minus the named tools.
# That is how a test makes a command "not installed", even one that lives in /usr/bin next to everything else.
path_without() {
  local fake="$1" dir d i tool
  local -a dirs
  shift
  dir="$(mktemp -d "$SCRATCH/path.XXXXXX")"
  IFS=: read -ra dirs <<<"$PATH"
  # Last PATH entry first, so that an earlier entry (and then the fakes) replaces a later one of the same name.
  for ((i = ${#dirs[@]} - 1; i >= 0; i--)); do
    d="${dirs[i]}"
    if [[ -d "$d" ]]; then ln -sf -t "$dir" "$d"/* 2>/dev/null || true; fi
  done
  ln -sf -t "$dir" "$fake"/*
  for tool in "$@"; do rm -f "$dir/$tool"; done
  printf '%s\n' "$dir"
}
