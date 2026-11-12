#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# listeners.sh: the one reading of "which TCP sockets listen, on which address, and who holds them", from /proc (hard rule
# 4; H2 spec §8.5 and §10.5: beyond the hub's own iroh endpoint, UDP, nothing of the distro listens except the loopback
# REST listener). Shared by p2pc-run (which stops a hub that listens on anything else) and p2pc-test-distro (which checks
# the running distro). The image installs it as /usr/local/lib/p2pc/listeners.sh; the scripts source it from there, from
# the directory they sit in (a checkout, deploy/wsl/), or from $P2PC_LISTENERS_LIB. Sourcing only defines functions.
#
# /proc/net/tcp and tcp6 show the sockets of the reader's network namespace. All WSL2 distros share the VM's namespace
# (H1 §9.0, E1), so a socket that no process of this distro holds belongs to another distro; job containers run with
# --network=none and have namespaces of their own.

# tcp_endpoint <hex address:hex port of /proc/net/tcp or tcp6>: prints "<loopback|exposed> <address:port>". The kernel
# writes an IPv4 address as one 32-bit word and an IPv6 address as four, each in host (little-endian) byte order.
# Loopback is 127.0.0.0/8, ::1 and the IPv4-mapped ::ffff:127.0.0.0/104; everything else, the wildcards included, is
# exposed. Fails on anything it cannot read.
tcp_endpoint() {
  local hex="${1%:*}" port="${1##*:}" w i b=() groups=() scope=exposed
  [[ "$1" == *:* && "$port" =~ ^[0-9A-Fa-f]{4}$ ]] || return 1
  port=$((16#$port))
  if [[ "$hex" =~ ^[0-9A-Fa-f]{8}$ ]]; then
    b=("${hex:6:2}" "${hex:4:2}" "${hex:2:2}" "${hex:0:2}")
    [[ "${b[0],,}" == 7f ]] && scope=loopback
    printf '%s %d.%d.%d.%d:%d\n' "$scope" "$((16#${b[0]}))" "$((16#${b[1]}))" "$((16#${b[2]}))" "$((16#${b[3]}))" "$port"
    return 0
  fi
  [[ "$hex" =~ ^[0-9A-Fa-f]{32}$ ]] || return 1
  for ((w = 0; w < 4; w++)); do
    i="${hex:w*8:8}"
    b+=("${i:6:2}" "${i:4:2}" "${i:2:2}" "${i:0:2}")
  done
  local flat="${b[*]}"
  flat="${flat// /}"
  flat="${flat,,}"
  if [[ "$flat" == 00000000000000000000000000000001 || "$flat" == 00000000000000000000ffff7f* ]]; then
    scope=loopback
  fi
  for ((i = 0; i < 16; i += 2)); do
    groups+=("$(printf '%x' "$((16#${b[i]}${b[i + 1]}))")")
  done
  local IFS=:
  printf '%s [%s]:%d\n' "$scope" "${groups[*]}" "$port"
}

# tcp_listeners <proc root>: one line per listening TCP socket (state 0A) of this network namespace, from net/tcp and
# net/tcp6: "<inode> <loopback|exposed> <address:port>".
tcp_listeners() {
  local f local_addr state inode ep
  for f in "$1/net/tcp" "$1/net/tcp6"; do
    [[ -r "$f" ]] || continue
    while read -r _ local_addr _ state _ _ _ _ _ inode _; do
      [[ "$state" == 0A && "$inode" =~ ^[0-9]+$ ]] || continue
      ep="$(tcp_endpoint "$local_addr")" || continue
      printf '%s %s\n' "$inode" "$ep"
    done < <(tail -n +2 "$f")
  done
}

# socket_inode_owners <proc root>: "<inode> <pid> <command name>" for every socket descriptor of every process this
# distro can see (/proc/<pid>/fd/<n> -> socket:[<inode>]).
socket_inode_owners() {
  local d pid fd target comm
  for d in "$1"/[0-9]*; do
    pid="${d##*/}"
    [[ "$pid" =~ ^[0-9]+$ && -d "$d/fd" ]] || continue
    comm="$(head -n 1 "$d/comm" 2>/dev/null)"
    for fd in "$d"/fd/*; do
      target="$(readlink "$fd" 2>/dev/null)" || continue
      [[ "$target" =~ ^socket:\[([0-9]+)\]$ ]] || continue
      printf '%s %s %s\n' "${BASH_REMATCH[1]}" "$pid" "${comm:-?}"
    done
  done
}

# tcp_listener_report <proc root>: "<loopback|exposed> <address:port> <owners>" per listening TCP socket, where owners is
# "comm[pid]" for every process of this distro that holds it (comma separated), or "-" for none.
tcp_listener_report() {
  local listeners owners inode scope addr who
  listeners="$(tcp_listeners "$1")"
  owners="$(socket_inode_owners "$1")"
  while read -r inode scope addr; do
    [[ -n "$inode" ]] || continue
    who="$(awk -v i="$inode" '$1 == i { printf "%s%s[%s]", (n++ ? "," : ""), $3, $2 }' <<<"$owners")"
    printf '%s %s %s\n' "$scope" "$addr" "${who:--}"
  done <<<"$listeners"
}

# pid_exposed_tcp_listeners <proc root> <pid>: the addresses of the listening TCP sockets that process <pid> holds and
# that are not loopback, one per line (nothing when there are none, or when the process is gone).
pid_exposed_tcp_listeners() {
  local proc="$1" pid="$2" fd target inodes=" " inode scope addr
  for fd in "$proc/$pid"/fd/*; do
    target="$(readlink "$fd" 2>/dev/null)" || continue
    [[ "$target" =~ ^socket:\[([0-9]+)\]$ ]] && inodes+="${BASH_REMATCH[1]} "
  done
  [[ "$inodes" == " " ]] && return 0
  while read -r inode scope addr; do
    [[ -n "$inode" && "$scope" == exposed && "$inodes" == *" $inode "* ]] && printf '%s\n' "$addr"
  done < <(tcp_listeners "$proc")
  return 0
}
