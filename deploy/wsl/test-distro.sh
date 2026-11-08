#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# test-distro.sh: end-to-end check of the p2pc-node WSL2 profile of spec 9.0 (experiment E1), run INSIDE the imported
# distro as root. The image installs it as /usr/local/sbin/p2pc-test-distro:
#
#   wsl -d p2pc-node -u root --exec /usr/local/sbin/p2pc-test-distro [--json]
#
# It prints PASS / FAIL / SKIP / INFO per check and exits 1 if any check FAILed (2 on a usage error). INFO is a
# fact worth showing that cannot be asserted (it never changes the exit code).
#   - isolation: no /mnt/c, no 9p/drvfs mounts, no Windows interop
#   - configuration: wsl.conf values, no OOBE config and no login user (uid >= 1000), /etc/subuid, /etc/subgid, Podman (cgroupfs, crun, cgroup v2)
#   - file capabilities survive the image: getcap /usr/bin/ping shows cap_net_raw (the xattr is kept on unpack and pack)
#   - skopeo is installed and `skopeo inspect --raw docker://docker.io/library/busybox:1.36.1` returns a manifest (INFO
#     when the node has no network): the agent uses it to check the image size cap before pulling
#   - a hardened `podman run` with the spec 9 flags: no capabilities, no-new-privileges, seccomp, remapped userns
#   - no network: TCP to 1.1.1.1:443, the default gateway and 100.100.100.100:53 must be UNREACHABLE (not refused, not
#     timed out: classify_connect tells the three apart), with a positive control (loopback connects) and a refused
#     control (an unused loopback port is refused), so that "blocked" cannot mean "nc is broken"
#   - limits: the memory limit kills a 200 MB allocation and the PID limit refuses forks in a bounded loop. Both are
#     measured from the HOST side, in the job's cgroup (memory.events oom_kill, pids.events max): on WSL2 Podman 4.9.3
#     with conmon 2.1.10 and cgroupfs never sets OOMKilled (the kernel kills the job, exit 137, and nothing records it
#     in Podman), and a trap inside a job that is at its PID limit cannot fork to report anything
#   - GPU (only with an NVIDIA GPU: /dev/dxg plus libcuda; Intel/AMD GPU-PV, no libcuda, is SKIP; libcuda with a
#     failing nvidia-smi -L is a FAIL): CDI lists nvidia.com/gpu=all and nvidia-smi -L inside a CUDA image lists one GPU
#
# It needs the internet ONLY to pull two small images (cached afterwards) and for one skopeo registry lookup (INFO
# when there is no network). Images are pinned by digest: the digests are the constants below, which already hold the
# values resolved on 2026-11-05, so a plain run needs no arguments. To override them (a newer image, a mirror) pass
# --alpine-image and --cuda-image (or the P2PC_TEST_ALPINE_IMAGE / P2PC_TEST_CUDA_IMAGE variables); to bump the constants,
# run --resolve-images on a trusted machine and commit the new digests after reviewing them.
#
# Sourcing this file only defines functions (deploy/tests/ unit-tests them).

ALPINE_TAG_REF="docker.io/library/alpine:3.20"
# Digest that ALPINE_TAG_REF resolved to on 2026-11-05 (`p2pc-test-distro --resolve-images`, real Windows run).
ALPINE_DIGEST="sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
CUDA_TAG_REF="docker.io/nvidia/cuda:12.8.1-base-ubuntu24.04"
# Digest that CUDA_TAG_REF resolved to on 2026-11-05 (same run). To bump: re-run --resolve-images and review.
CUDA_DIGEST="sha256:133c78a0575303be34164d0b90137a042172bdf60696af01a3c424ab402d86e2"

# Targets that must be unreachable from a --network=none container (spec 13 SI-3, spec 9.0).
readonly NET_TARGET_INTERNET="1.1.1.1:443"
readonly NET_TARGET_TAILNET_DNS="100.100.100.100:53"

# Where WSL puts the Windows driver's libraries (and nvidia-smi); overridable only for the unit tests.
WSL_LIB="${P2PC_TEST_WSL_LIB:-/usr/lib/wsl/lib}"

# The shared "is there an NVIDIA GPU?" check (nvidia_gpu_check, also used by p2pc-boot): $P2PC_NVIDIA_LIB, else next
# to this script (a checkout), else where the image installs it.
for _nv in "${P2PC_NVIDIA_LIB:-}" "$(dirname "${BASH_SOURCE[0]}")/nvidia.sh" /usr/local/lib/p2pc/nvidia.sh; do
  if [[ -n "$_nv" && -r "$_nv" ]]; then
    # shellcheck source=deploy/wsl/nvidia.sh
    source "$_nv"
    break
  fi
done
unset _nv
# The boot-status identity rule (boot_status_fresh, current_init_starttime): the same search as nvidia.sh.
for _bs in "${P2PC_BOOT_STATUS_LIB:-}" "$(dirname "${BASH_SOURCE[0]}")/boot-status.sh" /usr/local/lib/p2pc/boot-status.sh; do
  if [[ -n "$_bs" && -r "$_bs" ]]; then
    # shellcheck source=deploy/wsl/boot-status.sh
    source "$_bs"
    break
  fi
done
unset _bs

# Where the cgroup v2 hierarchy is mounted (overridable only for the unit tests).
CGROUP_ROOT="${P2PC_TEST_CGROUP_ROOT:-/sys/fs/cgroup}"

JSON=0
RESULTS=()

# ---------------------------------------------------------------------------------------------------------------
# Pure helpers (unit-tested in deploy/tests/test-test-distro.sh)
# ---------------------------------------------------------------------------------------------------------------

# version_ge <a> <b>: a >= b, comparing dotted versions.
version_ge() {
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]
}

# json_escape <string>: contents of a JSON string literal.
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  printf '%s' "$s"
}

# ini_get <file> <section> <key>: the value of key in [section] of an INI file (as wsl.conf); fails if absent.
ini_get() {
  awk -v sec="$2" -v key="$3" '
    /^[[:space:]]*[#;]/ { next }
    /^[[:space:]]*\[/ { s = $0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", s); cur = s; next }
    cur == sec {
      i = index($0, "="); if (i == 0) next
      k = substr($0, 1, i - 1); v = substr($0, i + 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", k); gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      if (k == key) { print v; found = 1; exit }
    }
    END { exit found ? 0 : 1 }
  ' "$1"
}

# status_field <text> <Field>: value of a "Field:<tab>value" line of /proc/<pid>/status.
status_field() {
  local line
  while IFS= read -r line; do
    if [[ "$line" == "$2:"* ]]; then
      line="${line#"$2:"}"
      line="${line#"${line%%[![:space:]]*}"}"
      printf '%s' "${line%"${line##*[![:space:]]}"}"
      return 0
    fi
  done <<<"$1"
  return 0
}

# caps_are_zero <hex>: a capability mask that is all zeros (and not empty).
caps_are_zero() {
  [[ "$1" =~ ^0+$ ]]
}

# uid_map_remapped <text of /proc/self/uid_map>: true if container uid 0 maps to a non-zero host uid.
uid_map_remapped() {
  local inside outside count
  while read -r inside outside count; do
    [[ -n "${count:-}" && "$inside" == 0 ]] && [[ "$outside" != 0 ]] && return 0
    [[ "$inside" == 0 ]] && return 1
  done <<<"$1"
  return 1
}

# default_gateway_from_route <file in /proc/net/route format>: the default gateway as a dotted quad.
default_gateway_from_route() {
  local dest gw flags
  while read -r _ dest gw flags _; do
    [[ "$dest" == "00000000" && "$gw" =~ ^[0-9A-Fa-f]{8}$ ]] || continue
    ((0x$flags & 2)) || continue # RTF_GATEWAY
    printf '%d.%d.%d.%d\n' "0x${gw:6:2}" "0x${gw:4:2}" "0x${gw:2:2}" "0x${gw:0:2}"
    return 0
  done <"$1"
  return 1
}

# is_digest_ref <ref>: repo@sha256:<64 hex>
is_digest_ref() {
  [[ "$1" =~ ^[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]]
}

# pinned_ref <tag-ref> <digest>: repo@digest (the tag is dropped); fails on a malformed digest.
pinned_ref() {
  local ref="$1" digest="$2"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  [[ "${ref##*/}" == *:* ]] && ref="${ref%:*}"
  printf '%s@%s\n' "$ref" "$digest"
}

# kv_get <text> <key>: value of the first "key=value" line.
kv_get() {
  local line
  while IFS= read -r line; do
    if [[ "$line" == "$2="* ]]; then
      printf '%s' "${line#"$2="}"
      return 0
    fi
  done <<<"$1"
  return 0
}

# events_value <text of a cgroup *.events file> <key>: the number after the key (0 if the key is absent).
events_value() {
  local v
  v="$(awk -v k="$2" '$1 == k { print $2; exit }' <<<"$1")"
  printf '%s' "${v:-0}"
}

# cgroup_events_max <cgroup-dir> <events-file-name> <key>: the largest value of <key> over <dir>/<file> and the same
# file in every cgroup below it. The container's own cgroup is a child of the cgroup we named with --cgroup-parent,
# and whether the parent's file includes its children depends on the kernel, so look at all of them.
cgroup_events_max() {
  local dir="$1" file="$2" key="$3" f v best=0
  [[ -d "$dir" ]] || {
    printf '0'
    return 0
  }
  while IFS= read -r -d '' f; do
    v="$(events_value "$(cat -- "$f" 2>/dev/null)" "$key")"
    [[ "$v" =~ ^[0-9]+$ ]] && ((v > best)) && best="$v"
  done < <(find "$dir" -name "$file" -type f -print0 2>/dev/null)
  printf '%d' "$best"
}

# test_cgroup_name <check> <pid>: the cgroup (one level below the root, as in the measured case) a check's jobs go in.
test_cgroup_name() {
  printf 'p2pc-test-%s-%s' "$1" "$2"
}

# remove_test_cgroup <name>: removes a cgroup made by test_cgroup_name (deepest first). Refuses any other name, so a
# bug can never rmdir a real cgroup.
remove_test_cgroup() {
  [[ "$1" =~ ^p2pc-test-[a-z]+-[0-9]+$ ]] || return 1
  [[ -d "$CGROUP_ROOT/$1" ]] || return 0
  find "$CGROUP_ROOT/$1" -depth -type d -exec rmdir {} + 2>/dev/null || true
  [[ ! -d "$CGROUP_ROOT/$1" ]]
}

# login_users <passwd-file>: users with uid >= 1000 whose shell can log in (not nologin, not false, not empty). The
# appliance has none: it only ever runs as root, with the agent as its only tenant.
login_users() {
  awk -F: '
    $3 ~ /^[0-9]+$/ && $3 + 0 >= 1000 {
      sh = $7
      if (sh == "" || sh ~ /\/(nologin|false)$/) next
      print $1
    }
  ' "$1"
}

# windows_mounts <mounts-file>: mount points of 9p/drvfs filesystems, except the read-only GPU driver store that WSL
# itself mounts at /usr/lib/wsl/drivers when a GPU is passed through. Prints offenders, one per line.
windows_mounts() {
  local mp type opts
  while read -r _ mp type opts _; do
    [[ "$type" == 9p || "$type" == drvfs ]] || continue
    if [[ "$mp" == /usr/lib/wsl/drivers && ",$opts," == *,ro,* ]]; then continue; fi
    printf '%s\n' "$mp"
  done <"$1"
}

# classify_connect <raw>: what a TCP connect attempt told us, from the raw probe result the container prints,
# "rc:<exit code>;secs:<whole seconds it took>;msg:<what busybox wget said>". The probe is busybox `wget` because it is
# the only busybox applet that names the failures (measured in real `podman run --network=none` containers; busybox
# `nc` prints nothing, or nothing useful for a refusal, and exits 1 for every case).
#
# The probe runs in the ALPINE image (ALPINE_TAG_REF, musl libc). Most of wget's text is the C library's strerror(),
# and glibc and musl word some errors differently (glibc busybox:1.36.1 says "Network is unreachable", musl alpine says
# "Network unreachable"), so both are accepted: the classifier must not depend on which base image the probe ends up in.
#   refused      "wget: can't connect to remote host (127.0.0.1): Connection refused" (same in both): something
#                answered with a RST
#   unreachable  "...(100.100.100.100): Network is unreachable" (glibc) / "Network unreachable" (musl), and for a host
#                "No route to host" (glibc) / "Host is unreachable" (musl): the kernel has no route, which is what an
#                empty network namespace gives
#   timeout      "...: Connection timed out" (glibc) / "...: Operation timed out" (musl), and wget's own
#                "wget: download timed out": nothing came back until the probe gave up (packets dropped)
#   connected    exit 0, or an HTTP-level message ("server returned error", "error getting response"), which only a
#                completed TCP connection can produce
#   error        anything else (a missing tool, a garbled result, a message not listed here): never a verdict about
#                the network. The strerror() messages only count after wget's "can't connect to remote host (...): "
#                prefix, so another tool's text does not.
NET_PROBE_TIMEOUT=3
classify_connect() {
  local raw="$1" re='^rc:([0-9]+);secs:([0-9]+);msg:(.*)$' rc msg
  local cant_connect="wget: can't connect to remote host \\([^)]*\\): "
  local refused_re="${cant_connect}Connection refused"
  local unreachable_re="${cant_connect}(Network (is )?unreachable|No route to host|Host is unreachable)"
  local timeout_re="${cant_connect}(Connection|Operation) timed out"
  if [[ ! "$raw" =~ $re ]]; then
    echo error
    return 0
  fi
  rc="${BASH_REMATCH[1]}" msg="${BASH_REMATCH[3]}"
  if ((rc == 0)) || [[ "$msg" == *"server returned error"* || "$msg" == *"error getting response"* ]]; then
    echo connected
  elif [[ "$msg" =~ $refused_re ]]; then
    echo refused
  elif [[ "$msg" =~ $unreachable_re ]]; then
    echo unreachable
  elif [[ "$msg" =~ $timeout_re || "$msg" == *"wget: download timed out"* ]]; then
    echo timeout
  else
    echo error
  fi
}

# net_kind_ok <expected> <got>: each check requires the kind it expects, not just "not connected".
net_kind_ok() {
  [[ "$1" == "$2" ]]
}

# net_kind_hint <kind>: why a kind other than the expected one matters (empty for "unreachable").
net_kind_hint() {
  case "$1" in
    unreachable) ;;
    connected) echo "it is reachable from a --network=none container" ;;
    refused) echo "something answered with a RST: the container sees a network it should not have" ;;
    timeout) echo "the packets were dropped, not refused by the kernel: the container has an interface or route it should not have" ;;
    *) echo "the probe gave no usable answer" ;;
  esac
}

# --- the boot status race: p2pc-boot is the distro's [boot] command, which WSL runs asynchronously, and it runs
# `nvidia-smi -L` (up to about 10 s) at every start, so boot-status.json can appear a few seconds AFTER the distro is up,
# and the file of the previous start can still be there. "Fresh" = written in THIS start of the distro, decided by
# identity: the status records the start ticks of the distro's init and they must EQUAL field 22 of /proc/1/stat now
# (boot_status_fresh and current_init_starttime, from boot-status.sh). A time comparison had 1-2 s of slack and broke
# when the clock stepped after the host slept (T14a2 review).

# poll_sleep <seconds>: the one place the wait sleeps (the unit tests replace it, so they never really wait).
poll_sleep() {
  sleep "$1"
}

BOOT_STATUS_WAIT_S=30
# wait_boot_status <file>: polls once a second, up to $BOOT_STATUS_WAIT_S, for a non-empty status file that is fresh. When
# the init's start ticks cannot be read the file merely has to exist. Sets BOOT_STATUS_TEXT to the last text read
# and BOOT_STATUS_WHY to what was wrong. Returns 0 when a (fresh) status is there.
wait_boot_status() {
  local file="$1" init i
  BOOT_STATUS_TEXT=""
  BOOT_STATUS_WHY="$file is missing"
  init="$(current_init_starttime)" || init=""
  for ((i = 0; i <= BOOT_STATUS_WAIT_S; i++)); do
    if [[ -s "$file" ]]; then
      BOOT_STATUS_TEXT="$(cat "$file")"
      if [[ -z "$init" ]] || boot_status_fresh "$BOOT_STATUS_TEXT" "$init"; then
        return 0
      fi
      BOOT_STATUS_WHY="$file is not from this start of the distro (it records init_starttime $(status_init_starttime "$BOOT_STATUS_TEXT" || echo 'none'), this init started at $init): that is the file of the previous start"
    fi
    ((i < BOOT_STATUS_WAIT_S)) && poll_sleep 1
  done
  return 1
}

# boot_status_ok <boot-status.json text> <nvidia_gpu_check exit code>: whether p2pc-boot's status is acceptable. Where
# no NVIDIA GPU is expected (code 1: no libcuda) the status must say exactly that, "no_nvidia_gpu", with no error: an
# error there means a CDI spec left from an old GPU could not be moved aside, and podman would keep loading devices
# that do not exist. Where one is expected (code 0, or 2 = libcuda but nvidia-smi broken) the status must carry no
# error, and "nvidia_smi_failed" is a failure.
boot_status_ok() {
  [[ "$1" == *'"errors":[]'* ]] || return 1
  if [[ "$2" == 1 ]]; then
    [[ "$1" == *'"cdi":"no_nvidia_gpu"'* ]]
  else
    [[ "$1" != *'"cdi":"nvidia_smi_failed"'* ]]
  fi
}

# getcap_has <getcap output> <capability>: true if the output lists the capability (both libcap output formats).
getcap_has() {
  [[ "$1" =~ (^|[[:space:],=])"$2"([[:space:],=+]|$) ]]
}

# skopeo_manifest_ok <text>: `skopeo inspect --raw` output that is a manifest: JSON with a schemaVersion and either
# layers (a single image) or manifests (a manifest list / OCI index).
skopeo_manifest_ok() {
  [[ "$1" == *'"schemaVersion"'* && ( "$1" == *'"layers"'* || "$1" == *'"manifests"'* ) ]]
}

# skopeo_failure_is_network <error text>: the failure looks like "this node cannot reach the registry" (no DNS, no
# route, timeout), as opposed to a broken skopeo (a missing policy.json, a bad reference).
skopeo_failure_is_network() {
  local t="${1,,}"
  [[ "$t" == *"no such host"* || "$t" == *"i/o timeout"* || "$t" == *"network is unreachable"* ||
    "$t" == *"connection refused"* || "$t" == *"context deadline exceeded"* || "$t" == *"temporary failure in name resolution"* ||
    "$t" == *"tls handshake timeout"* || "$t" == *"no route to host"* ]]
}

# --- result bookkeeping ---------------------------------------------------------------------------------------------
# record <PASS|FAIL|SKIP|INFO> <name> [detail]
record() {
  local status="$1" name="$2" detail="${3:-}"
  RESULTS+=("$status"$'\t'"$name"$'\t'"$detail")
  ((JSON)) && return 0
  if [[ -n "$detail" ]]; then
    printf '%-4s %s: %s\n' "$status" "$name" "$detail"
  else
    printf '%-4s %s\n' "$status" "$name"
  fi
}

count_status() {
  local r n=0
  for r in "${RESULTS[@]}"; do
    [[ "${r%%$'\t'*}" == "$1" ]] && n=$((n + 1))
  done
  printf '%d' "$n"
}

render_json() {
  local r status name detail first=1
  printf '{"checks":['
  for r in "${RESULTS[@]}"; do
    IFS=$'\t' read -r status name detail <<<"$r"
    ((first)) || printf ','
    first=0
    printf '{"name":"%s","status":"%s","detail":"%s"}' "$(json_escape "$name")" "$status" "$(json_escape "$detail")"
  done
  printf '],"pass":%d,"fail":%d,"skip":%d,"info":%d}\n' "$(count_status PASS)" "$(count_status FAIL)" "$(count_status SKIP)" "$(count_status INFO)"
}

# one_line <text>: collapse to a single, length-limited line for a detail field.
one_line() {
  local s="${1//$'\n'/ | }"
  printf '%s' "${s:0:400}"
}

# --- container helpers ----------------------------------------------------------------------------------------------
# The security-relevant subset of the fixed `podman run` argument list of spec 9 (the agent builds the full list).
# --http-proxy=false: Podman would otherwise copy the host's HTTP(S)_PROXY into the container (WSL's autoProxy can set
# them), and the network probe would then talk to a proxy instead of the target (T14a2 review).
JOB_FLAGS=(--network=none --http-proxy=false --cap-drop=all --security-opt=no-new-privileges --pids-limit=2048 --userns=auto)

# run_job <timeout-s> <podman-run args...>: runs podman with a hard timeout; sets OUT and RC.
run_job() {
  local t="$1"
  shift
  OUT="$(timeout --kill-after=5 "$t" podman run "$@" 2>&1)"
  RC=$?
}

# shellcheck disable=SC2016  # these run in the container's shell, not here
NET_SCRIPT='
echo "IFACES=$(ls /sys/class/net | tr "\n" " ")"
echo "DEFAULT_ROUTES=$(awk "\$2==\"00000000\"" /proc/net/route | wc -l)"
probe() { # probe <host> <port> <timeout-s>: one raw result line, parsed by classify_connect on the host
  s=$(date +%s)
  m=$(wget -Y off -T "$3" -q -O /dev/null "http://$1:$2/" 2>&1)
  rc=$?
  e=$(date +%s)
  echo "rc:$rc;secs:$((e-s));msg:$(echo $m)"
}
nc -l -p 18080 >/dev/null 2>&1 &
i=0
until echo | nc -w 1 127.0.0.1 18080 >/dev/null 2>&1; do
  i=$((i+1))
  if [ "$i" -ge 25 ]; then echo CONTROL=fail; exit 3; fi
  sleep 0.2
done
echo CONTROL=ok
echo "CONTROL_REFUSED=$(probe 127.0.0.1 18081 2)"
for t in "$@"; do
  h=${t%:*}; p=${t##*:}
  echo "TARGET $t=$(probe "$h" "$p" '"$NET_PROBE_TIMEOUT"')"
done
'

# shellcheck disable=SC2016  # these run in the container's shell, not here
MEM_SCRIPT='x=$(head -c 209715200 /dev/zero | tr "\000" a); echo ALLOCATED=${#x}'

# A bounded loop (200 forks), not a bomb. The job itself only forks; what happened is read from the host side.
# shellcheck disable=SC2016  # these run in the container's shell, not here
PIDS_SCRIPT='
i=0
while [ "$i" -lt 200 ]; do
  sleep 30 &
  i=$((i+1))
done
echo FORKED=$i
'

HARDENED_SCRIPT='cat /proc/self/status; echo ---UIDMAP---; cat /proc/self/uid_map'

# ---------------------------------------------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------------------------------------------
check_isolation() {
  local bad
  if [[ -e /mnt/c ]]; then record FAIL iso.no_mnt_c "/mnt/c exists"; else record PASS iso.no_mnt_c; fi
  bad="$(windows_mounts /proc/mounts | paste -sd' ' -)"
  if [[ -n "$bad" ]]; then record FAIL iso.no_9p_drvfs "9p/drvfs mounts: $bad"; else record PASS iso.no_9p_drvfs; fi
  if [[ -n "${WSL_INTEROP:-}" ]]; then record FAIL iso.no_wsl_interop "WSL_INTEROP is set"; else record PASS iso.no_wsl_interop; fi
  # binfmt_misc is shared by every distro in the WSL VM, and other distros keep interop on, so the WSLInterop entry is
  # visible here and cannot be removed per distro. It is information, not a verdict; the checks around it (no
  # WSL_INTEROP, no Windows PATH, no drives, interop=false in wsl.conf) are the real protections.
  if [[ -e /proc/sys/fs/binfmt_misc/WSLInterop || -e /proc/sys/fs/binfmt_misc/WSLInterop-late ]]; then
    record INFO iso.binfmt_interop "the WSLInterop binfmt entry is visible, because binfmt_misc is shared by all distros of the WSL VM and other distros keep interop on; it cannot be removed per distro. This distro is protected by interop=false (wsl.conf), no WSL_INTEROP, and no Windows PATH."
  else
    record INFO iso.binfmt_interop "no WSLInterop binfmt entry is visible"
  fi
  if [[ ":${PATH}:" == *:/mnt/*:* ]]; then record FAIL iso.no_windows_path "PATH has /mnt entries: $PATH"; else record PASS iso.no_windows_path; fi
}

check_wsl_conf() {
  local bad="" spec section key want got
  for spec in "boot systemd false" "boot command /usr/local/sbin/p2pc-boot" "automount enabled false" \
    "automount mountFsTab false" "interop enabled false" "interop appendWindowsPath false" \
    "network generateHosts true" "network generateResolvConf true" "user default root"; do
    read -r section key want <<<"$spec"
    got="$(ini_get /etc/wsl.conf "$section" "$key" 2>/dev/null || true)"
    [[ "$got" == "$want" ]] || bad+="[$section] $key=${got:-<missing>} (want $want); "
  done
  if [[ -z "$bad" ]]; then record PASS cfg.wsl_conf; else record FAIL cfg.wsl_conf "$bad"; fi
}

# The Ubuntu .wsl base ships /etc/wsl-distribution.conf (an OOBE command and defaultUid=1000), which would make the first
# launch create a login user. The builder deletes it; the appliance stays root-only.
check_no_oobe_user() {
  local users
  if [[ -e /etc/wsl-distribution.conf ]]; then
    record FAIL cfg.no_oobe "/etc/wsl-distribution.conf exists: the first launch would run its OOBE and create a login user"
  else
    record PASS cfg.no_oobe
  fi
  users="$(login_users /etc/passwd | paste -sd' ' -)"
  if [[ -n "$users" ]]; then
    record FAIL cfg.no_login_users "login users with uid >= 1000: $users (the appliance is root-only, the agent is its only tenant)"
  else
    record PASS cfg.no_login_users
  fi
}

check_subids() {
  local f
  for f in subuid subgid; do
    if grep -qxF 'containers:2147483647:2147483648' "/etc/$f" 2>/dev/null; then
      record PASS "cfg.$f"
    else
      record FAIL "cfg.$f" "/etc/$f lacks containers:2147483647:2147483648 (needed by --userns=auto)"
    fi
  done
}

check_podman_config() {
  local v cg ver rt ev
  if ! command -v podman >/dev/null 2>&1; then
    record FAIL cfg.podman_installed "podman is not installed"
    return 1
  fi
  ver="$(podman version --format '{{.Client.Version}}' 2>/dev/null || true)"
  if [[ -n "$ver" ]] && version_ge "$ver" 4.9; then record PASS cfg.podman_version "$ver"; else record FAIL cfg.podman_version "got '${ver}', need >= 4.9"; fi
  cg="$(podman info --format '{{.Host.CgroupManager}}' 2>&1 || true)"
  if [[ "$cg" == cgroupfs ]]; then record PASS cfg.cgroup_manager; else record FAIL cfg.cgroup_manager "got '$(one_line "$cg")', want cgroupfs"; fi
  v="$(podman info --format '{{.Host.CgroupsVersion}}' 2>&1 || true)"
  if [[ "$v" == v2 ]]; then record PASS cfg.cgroup_v2; else record FAIL cfg.cgroup_v2 "got '$(one_line "$v")', want v2"; fi
  rt="$(podman info --format '{{.Host.OCIRuntime.Name}}' 2>&1 || true)"
  if [[ "$rt" == crun ]]; then record PASS cfg.oci_runtime; else record FAIL cfg.oci_runtime "got '$(one_line "$rt")', want crun"; fi
  ev="$(podman info --format '{{.Host.EventLogger}}' 2>&1 || true)"
  if [[ "$ev" == file ]]; then record PASS cfg.events_logger; else record FAIL cfg.events_logger "got '$(one_line "$ev")', want file"; fi
}

check_state_files() {
  local mode gpu_rc
  if [[ -x /usr/local/sbin/p2pc-boot ]]; then record PASS cfg.boot_script; else record FAIL cfg.boot_script "/usr/local/sbin/p2pc-boot missing or not executable"; fi
  mode="$(stat -c %a /var/lib/p2pc 2>/dev/null || true)"
  if [[ "$mode" == 700 ]]; then record PASS cfg.state_dir_mode; else record FAIL cfg.state_dir_mode "/var/lib/p2pc mode is '${mode:-missing}', want 700"; fi
  if grep -q '^image_version=' /etc/p2pc-distro-version 2>/dev/null; then
    record PASS cfg.distro_version "$(grep '^image_version=' /etc/p2pc-distro-version)"
  else
    record FAIL cfg.distro_version "/etc/p2pc-distro-version missing or malformed"
  fi
  # p2pc-boot runs asynchronously at distro start and can take ~10 s (nvidia-smi): wait for a status written after this start.
  if ! wait_boot_status /var/lib/p2pc/boot-status.json; then
    record FAIL cfg.boot_status "no fresh /var/lib/p2pc/boot-status.json within ${BOOT_STATUS_WAIT_S} s: ${BOOT_STATUS_WHY}. Did p2pc-boot run at distro start?"
  elif [[ -e /dev/dxg ]]; then
    nvidia_gpu_check "$WSL_LIB" "" >/dev/null
    gpu_rc=$?
    if boot_status_ok "$(cat /var/lib/p2pc/boot-status.json)" "$gpu_rc"; then
      record PASS cfg.boot_status "$(one_line "$(cat /var/lib/p2pc/boot-status.json)")"
    else
      record FAIL cfg.boot_status "p2pc-boot reported errors on a node where an NVIDIA GPU is expected: $(one_line "$(cat /var/lib/p2pc/boot-status.json)")"
    fi
  else
    record PASS cfg.boot_status "$(one_line "$(cat /var/lib/p2pc/boot-status.json)")"
  fi
}

# File capabilities live in the security.capability xattr, which a tar without --xattrs silently drops: ping would then
# work only for root. /usr/bin/ping is the canary (Ubuntu gives it cap_net_raw through setcap in the package).
check_file_caps() {
  local target=/usr/bin/ping out
  if [[ ! -e "$target" ]]; then
    record FAIL cfg.file_caps "$target is missing from the image"
  elif ! command -v getcap >/dev/null 2>&1; then
    record FAIL cfg.file_caps "getcap is not installed (libcap2-bin), so the file capabilities cannot be checked"
  else
    out="$(getcap "$target" 2>&1)"
    if getcap_has "$out" cap_net_raw; then
      record PASS cfg.file_caps "$(one_line "$out")"
    else
      record FAIL cfg.file_caps "$target has no cap_net_raw file capability (getcap said: '$(one_line "$out")'): the security.capability xattrs were lost when the image was unpacked or packed"
    fi
  fi
}

# The agent checks the image size cap with `skopeo inspect --raw` before pulling (spec 9, "Images"), so the image must
# ship skopeo. The registry lookup needs the internet: with no network it is INFO, not a FAIL (a broken skopeo is).
SKOPEO_PROBE_REF="docker://docker.io/library/busybox:1.36.1"
check_skopeo() {
  local ver out
  if ! command -v skopeo >/dev/null 2>&1; then
    record FAIL image.skopeo "skopeo is not installed (the agent needs it for the image size cap, spec 9 Images)"
    return 1
  fi
  ver="$(skopeo --version 2>&1 | head -n1)"
  record PASS image.skopeo "$(one_line "$ver")"
  if out="$(timeout --kill-after=5 60 skopeo inspect --raw "$SKOPEO_PROBE_REF" 2>&1)"; then
    if skopeo_manifest_ok "$out"; then
      record PASS image.skopeo_inspect_raw "skopeo inspect --raw $SKOPEO_PROBE_REF returned a manifest"
    else
      record FAIL image.skopeo_inspect_raw "skopeo inspect --raw $SKOPEO_PROBE_REF succeeded but the output is not a manifest: $(one_line "$out")"
    fi
  elif skopeo_failure_is_network "$out"; then
    record INFO image.skopeo_inspect_raw "no network to the registry, so skopeo inspect --raw $SKOPEO_PROBE_REF could not be tried: $(one_line "$out")"
  else
    record FAIL image.skopeo_inspect_raw "skopeo inspect --raw $SKOPEO_PROBE_REF failed: $(one_line "$out")"
  fi
}

pull_image() { # pull_image <ref> <check-name>
  local out
  if out="$(timeout 600 podman pull --quiet "$1" 2>&1)"; then
    record PASS "$2" "$1"
    return 0
  fi
  record FAIL "$2" "cannot pull $1: $(one_line "$out")"
  return 1
}

check_hardened_run() {
  local status_text map
  run_job 120 --rm "${JOB_FLAGS[@]}" --memory=128m --memory-swap=128m --cpus=1 "$ALPINE_IMAGE" sh -c "$HARDENED_SCRIPT"
  if ((RC != 0)); then
    record FAIL run.hardened "podman run failed (exit $RC): $(one_line "$OUT")"
    return 1
  fi
  record PASS run.hardened "podman run with the spec 9 flags and --userns=auto works"
  status_text="${OUT%%---UIDMAP---*}"
  map="${OUT#*---UIDMAP---}"
  local eff bnd nnp sec
  eff="$(status_field "$status_text" CapEff)"
  bnd="$(status_field "$status_text" CapBnd)"
  nnp="$(status_field "$status_text" NoNewPrivs)"
  sec="$(status_field "$status_text" Seccomp)"
  if caps_are_zero "$eff"; then record PASS sec.cap_eff "CapEff=$eff"; else record FAIL sec.cap_eff "CapEff='$eff', want 0"; fi
  if caps_are_zero "$bnd"; then record PASS sec.cap_bnd "CapBnd=$bnd"; else record FAIL sec.cap_bnd "CapBnd='$bnd', want 0"; fi
  if [[ "$nnp" == 1 ]]; then record PASS sec.no_new_privs; else record FAIL sec.no_new_privs "NoNewPrivs='$nnp', want 1"; fi
  if [[ "$sec" == 2 ]]; then record PASS sec.seccomp "filter mode"; else record FAIL sec.seccomp "Seccomp='$sec', want 2 (filter)"; fi
  if uid_map_remapped "$map"; then
    record PASS sec.userns_remapped "$(one_line "$(tr -s ' ' <<<"$map")")"
  else
    record FAIL sec.userns_remapped "uid_map is the identity or unreadable: $(one_line "$(tr -s ' ' <<<"$map")")"
  fi
}

check_no_network() {
  local gw targets=("$NET_TARGET_INTERNET") t name kind
  gw="$(default_gateway_from_route /proc/net/route 2>/dev/null || true)"
  [[ -n "$gw" ]] && targets+=("$gw:80")
  targets+=("$NET_TARGET_TAILNET_DNS")
  run_job 120 --rm "${JOB_FLAGS[@]}" "$ALPINE_IMAGE" sh -c "$NET_SCRIPT" sh "${targets[@]}"
  if [[ "$(kv_get "$OUT" CONTROL)" != ok ]]; then
    record FAIL net.probe_control "the probe could not even connect to a loopback listener, so the results below mean nothing: $(one_line "$OUT")"
    return 1
  fi
  record PASS net.probe_control "loopback connect works inside the container"
  local ifaces routes
  ifaces="$(kv_get "$OUT" IFACES)"
  ifaces="${ifaces%"${ifaces##*[![:space:]]}"}"
  if [[ "$ifaces" == lo ]]; then record PASS net.only_loopback; else record FAIL net.only_loopback "interfaces seen in the container: '$ifaces'"; fi
  routes="$(kv_get "$OUT" DEFAULT_ROUTES)"
  if [[ "$routes" == 0 ]]; then record PASS net.no_default_route; else record FAIL net.no_default_route "default routes: '$routes'"; fi
  # A refused connect to a loopback port with no listener proves the probe can tell "refused" from "unreachable".
  kind="$(classify_connect "$(kv_get "$OUT" CONTROL_REFUSED)")"
  if net_kind_ok refused "$kind"; then
    record PASS net.probe_refused_control "an unused loopback port is classified as refused, so refused and unreachable can be told apart"
  else
    record FAIL net.probe_refused_control "an unused loopback port was classified as '$kind' (want refused): $(one_line "$(kv_get "$OUT" CONTROL_REFUSED)")"
  fi
  # Inside --network=none there is only `lo` and no route: every external target must be UNREACHABLE (the kernel has
  # nowhere to send the packet). A refusal (someone answered), a timeout (packets went somewhere and were dropped) or
  # a connection are all different failures, and none of them is the isolation we promise.
  for t in "${targets[@]}"; do
    case "$t" in
      "$NET_TARGET_INTERNET") name=net.internet_blocked ;;
      "$NET_TARGET_TAILNET_DNS") name=net.tailnet_blocked ;;
      *) name=net.gateway_blocked ;;
    esac
    kind="$(classify_connect "$(kv_get "$OUT" "TARGET $t")")"
    if net_kind_ok unreachable "$kind"; then
      record PASS "$name" "$t: unreachable"
    else
      record FAIL "$name" "$t: expected unreachable, got $kind ($(net_kind_hint "$kind")): $(one_line "$(kv_get "$OUT" "TARGET $t")")"
    fi
  done
  if [[ -z "$gw" ]]; then record SKIP net.gateway_blocked "the distro has no default gateway to probe"; fi
}

# run_in_test_cgroup <check> <timeout-s> <podman-run args...>: like run_job, but the container is NOT removed on exit
# (its cgroup must survive until we have read it) and lives under its own --cgroup-parent. Sets OUT, RC, CT_NAME, CG_NAME.
run_in_test_cgroup() {
  local check="$1" t="$2"
  shift 2
  CG_NAME="$(test_cgroup_name "$check" "$$")"
  CT_NAME="p2pc-test-$check-$$"
  CLEAN_NAMES+=("$CT_NAME")
  CLEAN_CGROUPS+=("$CG_NAME")
  run_job "$t" --name "$CT_NAME" --cgroup-parent="/$CG_NAME" "$@"
}

# The kernel's OOM killer is the primary signal (spec 9, "Memory"): memory.events oom_kill > 0. Podman's own
# OOMKilled flag is shown for information only; it is not set on WSL2 with Podman 4.9.3 / conmon 2.1.10 / cgroupfs.
check_memory_limit() {
  local oom kills
  run_in_test_cgroup mem 180 "${JOB_FLAGS[@]}" --memory=64m --memory-swap=64m "$ALPINE_IMAGE" sh -c "$MEM_SCRIPT"
  oom="$(podman inspect --format '{{.State.OOMKilled}}' "$CT_NAME" 2>/dev/null || true)"
  kills="$(cgroup_events_max "$CGROUP_ROOT/$CG_NAME" memory.events oom_kill)"
  if ((kills > 0)) && ((RC != 0)); then
    record PASS limit.memory "200 MB allocation under --memory=64m: exit $RC, memory.events oom_kill=$kills"
  else
    record FAIL limit.memory "exit $RC, memory.events oom_kill=$kills (want a non-zero exit and oom_kill > 0) in $CGROUP_ROOT/$CG_NAME: $(one_line "$OUT")"
  fi
  record INFO limit.memory_podman_flag "podman reports OOMKilled='${oom:-?}' (informational: Podman 4.9.3 on WSL2 never sets it; the agent must use memory.events)"
  podman rm -f "$CT_NAME" >/dev/null 2>&1 || true
  remove_test_cgroup "$CG_NAME" || record INFO limit.cleanup "could not remove the test cgroup $CG_NAME"
}

check_pids_limit() {
  local limit hits
  run_in_test_cgroup pids 180 "${JOB_FLAGS[@]}" --pids-limit=64 "$ALPINE_IMAGE" sh -c "$PIDS_SCRIPT"
  limit="$(podman inspect --format '{{.HostConfig.PidsLimit}}' "$CT_NAME" 2>/dev/null || true)"
  hits="$(cgroup_events_max "$CGROUP_ROOT/$CG_NAME" pids.events max)"
  if [[ "$limit" == 64 ]] && ((hits > 0)); then
    record PASS limit.pids "200 forks under --pids-limit=64: HostConfig.PidsLimit=64, pids.events max=$hits (forks refused)"
  else
    record FAIL limit.pids "HostConfig.PidsLimit='$limit' (want 64), pids.events max=$hits (want > 0) in $CGROUP_ROOT/$CG_NAME: $(one_line "$OUT")"
  fi
  podman rm -f "$CT_NAME" >/dev/null 2>&1 || true
  remove_test_cgroup "$CG_NAME" || record INFO limit.cleanup "could not remove the test cgroup $CG_NAME"
}

check_gpu() {
  local list out n reason
  if [[ ! -e /dev/dxg ]]; then
    record SKIP gpu.cdi "no /dev/dxg: no GPU passthrough on this machine"
    record SKIP gpu.nvidia_smi "no /dev/dxg"
    return 0
  fi
  # /dev/dxg exists for any GPU-PV driver (Intel and AMD integrated GPUs too): only an NVIDIA GPU gets a CDI spec.
  # rc 1 = no libcuda = no NVIDIA GPU (SKIP). rc 2 = libcuda is there but nvidia-smi -L does not work: a GPU is
  # expected on this node and it is broken, which is a FAIL, not a skip.
  reason="$(nvidia_gpu_check "$WSL_LIB" "")"
  case $? in
    0) ;;
    1)
      record SKIP gpu.cdi "no NVIDIA GPU ($reason): /dev/dxg is exposed for every GPU-PV driver"
      record SKIP gpu.nvidia_smi "no NVIDIA GPU"
      return 0
      ;;
    *)
      record FAIL gpu.cdi "an NVIDIA driver is present (libcuda) but the GPU does not work: $reason"
      record FAIL gpu.nvidia_smi "nvidia-smi -L failed on the host side: $reason"
      return 1
      ;;
  esac
  if ! command -v nvidia-ctk >/dev/null 2>&1; then
    record FAIL gpu.cdi "nvidia-ctk is not installed"
    return 1
  fi
  list="$(nvidia-ctk cdi list 2>&1 || true)"
  if grep -qxF 'nvidia.com/gpu=all' <<<"$list"; then
    record PASS gpu.cdi "nvidia.com/gpu=all is listed"
  else
    record FAIL gpu.cdi "nvidia.com/gpu=all not in the CDI list: $(one_line "$list")"
    return 1
  fi
  if [[ -z "$CUDA_IMAGE" ]]; then
    record FAIL gpu.nvidia_smi "no digest-pinned CUDA image (run --resolve-images, then pass --cuda-image)"
    return 1
  fi
  pull_image "$CUDA_IMAGE" image.pull_cuda || return 1
  run_job 300 --rm "${JOB_FLAGS[@]}" --device nvidia.com/gpu=all "$CUDA_IMAGE" nvidia-smi -L
  out="$OUT"
  n="$(grep -c '^GPU [0-9]*: ' <<<"$out" || true)"
  if ((RC == 0)) && ((n == 1)); then
    record PASS gpu.nvidia_smi "$(one_line "$out")"
  else
    record FAIL gpu.nvidia_smi "exit $RC, $n GPU line(s) (want exactly 1): $(one_line "$out")"
  fi
}

resolve_images() {
  local a c
  command -v podman >/dev/null 2>&1 || {
    echo "podman not found" >&2
    return 1
  }
  podman pull --quiet "$ALPINE_TAG_REF" >/dev/null || return 1
  podman pull --quiet "$CUDA_TAG_REF" >/dev/null || return 1
  a="$(podman image inspect --format '{{.Digest}}' "$ALPINE_TAG_REF")"
  c="$(podman image inspect --format '{{.Digest}}' "$CUDA_TAG_REF")"
  printf 'ALPINE_DIGEST=%s\nCUDA_DIGEST=%s\n' "$a" "$c"
  printf 'Run the tests with:\n  p2pc-test-distro --alpine-image %s --cuda-image %s\n' \
    "$(pinned_ref "$ALPINE_TAG_REF" "$a")" "$(pinned_ref "$CUDA_TAG_REF" "$c")"
}

usage() {
  cat <<'USAGE'
Usage: test-distro.sh [--json] [--alpine-image REF@sha256:...] [--cuda-image REF@sha256:...]
       test-distro.sh --resolve-images
Run as root inside the p2pc-node distro. Exit 0 = no FAIL, 1 = at least one FAIL, 2 = usage error.
  --json            machine-readable output (one JSON object on stdout)
  --alpine-image    small image for the sandbox checks, pinned by digest (or P2PC_TEST_ALPINE_IMAGE)
  --cuda-image      CUDA base image for the GPU check, pinned by digest (or P2PC_TEST_CUDA_IMAGE)
  --resolve-images  pull the tag references and print their digests (run once, on a trusted machine)
USAGE
}

cleanup() {
  local n
  for n in "${CLEAN_NAMES[@]}"; do
    podman rm -f "$n" >/dev/null 2>&1 || true
  done
  for n in "${CLEAN_CGROUPS[@]}"; do
    remove_test_cgroup "$n" || true
  done
}

main() {
  set -uo pipefail
  CLEAN_NAMES=()
  CLEAN_CGROUPS=()
  ALPINE_IMAGE="${P2PC_TEST_ALPINE_IMAGE:-$(pinned_ref "$ALPINE_TAG_REF" "$ALPINE_DIGEST" 2>/dev/null || true)}"
  CUDA_IMAGE="${P2PC_TEST_CUDA_IMAGE:-$(pinned_ref "$CUDA_TAG_REF" "$CUDA_DIGEST" 2>/dev/null || true)}"
  local resolve=0
  while (($# > 0)); do
    case "$1" in
      --json) JSON=1 ;;
      --resolve-images) resolve=1 ;;
      --alpine-image | --cuda-image)
        (($# >= 2)) || {
          usage >&2
          return 2
        }
        if [[ "$1" == --alpine-image ]]; then ALPINE_IMAGE="$2"; else CUDA_IMAGE="$2"; fi
        shift
        ;;
      -h | --help)
        usage
        return 0
        ;;
      *)
        usage >&2
        return 2
        ;;
    esac
    shift
  done
  local img
  for img in "$ALPINE_IMAGE" "$CUDA_IMAGE"; do
    if [[ -n "$img" ]] && ! is_digest_ref "$img"; then
      echo "image '$img' is not pinned by digest (repo@sha256:<64 hex>)" >&2
      return 2
    fi
  done
  [[ $EUID -eq 0 ]] || {
    echo "run as root inside the p2pc-node distro" >&2
    return 2
  }
  if ((resolve)); then
    resolve_images
    return $?
  fi
  trap cleanup EXIT

  check_isolation
  check_wsl_conf
  check_no_oobe_user
  check_subids
  check_state_files
  check_file_caps
  check_skopeo
  if check_podman_config; then
    if [[ -z "$ALPINE_IMAGE" ]]; then
      record FAIL image.alpine_pinned "no digest-pinned alpine image: run --resolve-images, then pass --alpine-image"
    elif pull_image "$ALPINE_IMAGE" image.pull_alpine; then
      check_hardened_run
      check_no_network
      check_memory_limit
      check_pids_limit
    fi
    check_gpu
  fi

  if ((JSON)); then
    render_json
  else
    printf 'Summary: %d passed, %d failed, %d skipped, %d info\n' "$(count_status PASS)" "$(count_status FAIL)" "$(count_status SKIP)" "$(count_status INFO)"
  fi
  ((EUID == 0)) && (($(count_status FAIL) == 0))
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
  exit $?
fi
