#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# boot-status.sh: the one definition of "is /var/lib/p2pc/boot-status.json from THIS start of the distro?", shared by
# p2pc-boot (which writes the identity), p2pc-test-distro and p2pc-run (which compare it). The image installs it
# as /usr/local/lib/p2pc/boot-status.sh; the scripts source it from there, from the directory they sit in (a
# checkout, deploy/wsl/), or from $P2PC_BOOT_STATUS_LIB. Sourcing only defines functions.
#
# Why not a time: "fresh" used to mean "the status time is not earlier than btime + the init's start". That has one to
# two seconds of slack (whole seconds, and btime itself is rounded), and the clock can step after the host sleeps, so a
# stale file could pass or a fresh one fail. The start of the distro's init is identified exactly by the raw start
# ticks of its PID 1 (field 22 of /proc/1/stat, clock ticks since the VM booted): every start of the distro has its
# own init with its own value, and it never changes while that init lives. p2pc-boot writes that number into the
# status as "init_starttime", and a reader compares it with its own /proc/1/stat for EQUALITY.

# proc_starttime <text of /proc/PID/stat>: field 22 (starttime), the raw clock ticks; fails if it cannot be read. The
# command name (field 2) sits in parentheses and may hold spaces and parentheses, so fields count from the LAST ")".
proc_starttime() {
  local rest fields
  [[ "$1" == *")"* ]] || return 1
  rest="${1##*)}"
  read -ra fields <<<"$rest"
  # fields[0] is the state (field 3), so field 22 is fields[19].
  [[ "${fields[19]:-}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${fields[19]}"
}

# current_init_starttime: the starttime of this distro's init ($P2PC_PROC, for the tests, replaces /proc).
current_init_starttime() {
  proc_starttime "$(cat "${P2PC_PROC:-/proc}/1/stat" 2>/dev/null)"
}

# status_init_starttime <boot-status.json text>: the "init_starttime" it records; fails when there is none (an older
# p2pc-boot, or one that could not read /proc/1/stat and wrote null).
status_init_starttime() {
  [[ "$1" =~ \"init_starttime\":([0-9]+)[,}] ]] || return 1
  printf '%s\n' "${BASH_REMATCH[1]}"
}

# boot_status_fresh <boot-status.json text> <starttime of this distro's init>: written by p2pc-boot in this start.
boot_status_fresh() {
  local recorded
  recorded="$(status_init_starttime "$1")" || return 1
  [[ "$2" =~ ^[0-9]+$ ]] || return 1
  [[ "$recorded" == "$2" ]]
}
