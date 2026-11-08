#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# setup-host.sh: prepares a native Linux machine to be a P2PC node (spec 9.0, "Linux host" column).
# Run as root; the agent then runs as the unprivileged system user `p2pc`, with ROOTLESS Podman.
#
#   sudo deploy/linux/setup-host.sh [--check-only]
#
# What it does (idempotent):
#   1. creates the system user `p2pc` (home /var/lib/p2pc, mode 0700, no login shell)
#   2. gives it subuid/subgid ranges (rootless containers map container root into this range)
#   3. loginctl enable-linger p2pc  (a systemd user session at boot, without a login: needed for rootless Podman)
#   4. checks cgroup v2 and that cpu, memory and pids are delegated to user sessions
#      (the limits of spec 9 need them) and PRINTS the fix when they are not; it never applies it
#   5. checks Podman >= 4.9 and crun
#   6. with an NVIDIA GPU and nvidia-ctk installed, generates the CDI spec; otherwise prints how to install the
#      toolkit. It never installs the toolkit or any package itself.
#
# --check-only reports everything and changes nothing (no root needed).
# Exit codes: 0 = host ready (with --check-only also when only [plan] steps are left: install-node.sh does them),
# 1 = a [TODO] is open, 2 = usage error, 3 = needs root.
# Every command that changes the system is checked: success is reported as [done], failure as a [TODO] with a hint,
# and exit 0 means the host really is ready, never just "nothing failed loudly".
#
# Sourcing this file only defines functions (deploy/tests/ unit-tests them).

readonly P2PC_USER="p2pc"
readonly MIN_PODMAN="4.9"
readonly REQUIRED_CONTROLLERS="cpu memory pids"
readonly SUBID_COUNT=65536
readonly SUBID_FLOOR=100000
# The highest valid uid/gid is 2^32-2 (2^32-1 is the "no id" value). A range must end at or below it.
readonly SUBID_LAST_VALID=4294967294

# Plain variables, not readonly: the tests point them at a scratch directory.
P2PC_HOME="/var/lib/p2pc"
SUBUID_FILE="/etc/subuid"
SUBGID_FILE="/etc/subgid"
LINGER_DIR="/var/lib/systemd/linger"
CDI_SPEC="/etc/cdi/nvidia.yaml"
# The loaded driver's version file: a CDI spec older than it was generated for an earlier driver.
NVIDIA_VERSION_FILE="/proc/driver/nvidia/version"

# ---------------------------------------------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------------------------------------------

# version_ge <a> <b>: a >= b, comparing dotted versions.
version_ge() {
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]
}

# podman_version_from <`podman --version` output>: "4.9.3" from "podman version 4.9.3" (suffixes like -dev dropped).
podman_version_from() {
  local v
  v="$(grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' <<<"$1" | head -n1)"
  printf '%s' "$v"
}

# missing_controllers <space separated list of delegated controllers>: those of REQUIRED_CONTROLLERS not in the list.
missing_controllers() {
  local c missing=()
  for c in $REQUIRED_CONTROLLERS; do
    [[ " $1 " == *" $c "* ]] || missing+=("$c")
  done
  printf '%s' "${missing[*]:-}"
}

# sub_next_start <subuid-or-subgid file>: first id after every existing range, never below SUBID_FLOOR. Fails (prints
# nothing) when a whole range of SUBID_COUNT ids starting there would not fit in the 32-bit id space, e.g. after a
# range like "containers:2147483647:2147483648": it is then up to the administrator to free or choose a range.
sub_next_start() {
  local file="$1" start
  if [[ -r "$file" ]]; then
    start="$(awk -F: -v floor="$SUBID_FLOOR" '
      NF >= 3 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ { e = $2 + $3; if (e > max) max = e }
      END { printf "%.0f\n", (max > floor ? max : floor) }
    ' "$file")"
  else
    start="$SUBID_FLOOR"
  fi
  [[ "$start" =~ ^[0-9]+$ ]] || return 1
  # awk printed a decimal integer; bash arithmetic is 64-bit, so this cannot overflow.
  ((start + SUBID_COUNT - 1 <= SUBID_LAST_VALID)) || return 1
  printf '%s\n' "$start"
}

# has_sub_entry <file> <user>
has_sub_entry() {
  [[ -r "$1" ]] && awk -F: -v u="$2" '$1 == u { f = 1 } END { exit !f }' "$1"
}

# ---------------------------------------------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------------------------------------------
TODO_COUNT=0
PLAN_COUNT=0
CHECK_ONLY=0

ok() { printf '  [ ok ] %s\n' "$*"; }
changed() { printf '  [done] %s\n' "$*"; }
# [plan]: something --check-only found that is not in place yet and that this script (so install-node.sh) does by itself.
# It is not a [TODO]: the user has nothing to do for it.
would() {
  PLAN_COUNT=$((PLAN_COUNT + 1))
  printf '  [plan] %s\n' "$*"
}
warn() { printf '  [warn] %s\n' "$*"; }
todo() {
  TODO_COUNT=$((TODO_COUNT + 1))
  printf '  [TODO] %s\n' "$1"
  shift
  local l
  for l in "$@"; do printf '         %s\n' "$l"; done
}

# ---------------------------------------------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------------------------------------------
step_user() {
  local mode owner
  echo "User and home"
  if id -u "$P2PC_USER" >/dev/null 2>&1; then
    ok "user $P2PC_USER exists (uid $(id -u "$P2PC_USER"))"
  elif ((CHECK_ONLY)); then
    would "create system user $P2PC_USER with home $P2PC_HOME"
    return 0
  elif ! useradd --system --user-group --create-home --home-dir "$P2PC_HOME" --shell /usr/sbin/nologin "$P2PC_USER"; then
    todo "useradd failed: the system user $P2PC_USER was not created" "Run it by hand to see why:  useradd --system --user-group --create-home --home-dir $P2PC_HOME --shell /usr/sbin/nologin $P2PC_USER"
    return 0
  elif ! id -u "$P2PC_USER" >/dev/null 2>&1; then
    todo "useradd reported success but user $P2PC_USER still does not exist" "Check /etc/passwd and the system logs."
    return 0
  else
    changed "created system user $P2PC_USER with home $P2PC_HOME"
  fi
  owner="$(stat -c %U "$P2PC_HOME" 2>/dev/null || true)"
  if [[ -z "$owner" ]]; then
    todo "the home directory $P2PC_HOME does not exist" "Create it:  install -d -o $P2PC_USER -g $P2PC_USER -m 0700 $P2PC_HOME"
    return 0
  elif [[ "$owner" == "$P2PC_USER" ]]; then
    ok "$P2PC_HOME is owned by $P2PC_USER"
  elif ((CHECK_ONLY)); then
    would "chown $P2PC_USER:$P2PC_USER $P2PC_HOME (owned by '$owner' now)"
  elif chown "$P2PC_USER:$P2PC_USER" "$P2PC_HOME"; then
    changed "chown $P2PC_USER:$P2PC_USER $P2PC_HOME (it belonged to '$owner')"
  else
    todo "could not chown $P2PC_HOME to $P2PC_USER (owned by '$owner')" "Run:  chown $P2PC_USER:$P2PC_USER $P2PC_HOME"
  fi
  mode="$(stat -c %a "$P2PC_HOME" 2>/dev/null || true)"
  if [[ "$mode" == 700 ]]; then
    ok "$P2PC_HOME has mode 0700"
  elif ((CHECK_ONLY)); then
    would "chmod 0700 $P2PC_HOME (now '${mode:-missing}')"
  elif chmod 0700 "$P2PC_HOME"; then
    changed "chmod 0700 $P2PC_HOME"
  else
    todo "could not chmod 0700 $P2PC_HOME" "Run:  chmod 0700 $P2PC_HOME"
  fi
}

step_subids() {
  local kind file start end flag
  echo "Subordinate uid/gid ranges (rootless user namespaces)"
  for kind in uid gid; do
    file="$SUBUID_FILE"
    [[ "$kind" == gid ]] && file="$SUBGID_FILE"
    if has_sub_entry "$file" "$P2PC_USER"; then
      ok "$file has a range for $P2PC_USER"
    elif ((CHECK_ONLY)); then
      would "add a $file range of $SUBID_COUNT ids for $P2PC_USER"
    elif ! id -u "$P2PC_USER" >/dev/null 2>&1; then
      todo "cannot add a $file range: user $P2PC_USER does not exist (see above)"
    elif ! start="$(sub_next_start "$file")"; then
      todo "no free $SUBID_COUNT-id range after the ones in $file (the next one would not fit in the 32-bit id space)" \
        "Free or shrink a range in $file, or add one for $P2PC_USER by hand:  usermod --add-sub${kind}s <first>-<last> $P2PC_USER"
    else
      end=$((start + SUBID_COUNT - 1))
      flag="--add-sub${kind}s"
      if ! usermod "$flag" "$start-$end" "$P2PC_USER"; then
        todo "usermod $flag $start-$end $P2PC_USER failed" "Run it by hand to see the error."
      elif ! has_sub_entry "$file" "$P2PC_USER"; then
        todo "usermod reported success but $file still has no range for $P2PC_USER" "Check the file, and that /etc/login.defs allows sub ids."
      else
        changed "added $file range $start-$end for $P2PC_USER"
      fi
    fi
  done
  if command -v newuidmap >/dev/null 2>&1 && command -v newgidmap >/dev/null 2>&1; then
    ok "newuidmap/newgidmap present"
  else
    todo "newuidmap/newgidmap are missing (rootless Podman needs them)" "Install it with your package manager, e.g.: apt-get install uidmap   |   dnf install shadow-utils   |   pacman -S shadow"
  fi
}

step_linger() {
  echo "systemd user session"
  if ! command -v loginctl >/dev/null 2>&1; then
    todo "loginctl not found: rootless Podman as a service needs systemd-logind" "Native Linux nodes need a systemd-based distribution."
    return 0
  fi
  if [[ -e "$LINGER_DIR/$P2PC_USER" ]]; then
    ok "linger is enabled for $P2PC_USER"
  elif ((CHECK_ONLY)); then
    would "loginctl enable-linger $P2PC_USER"
  elif ! id -u "$P2PC_USER" >/dev/null 2>&1; then
    todo "cannot enable linger: user $P2PC_USER does not exist (see above)"
  elif ! loginctl enable-linger "$P2PC_USER"; then
    todo "loginctl enable-linger $P2PC_USER failed" "Run it by hand to see the error (is systemd-logind running?)."
  elif [[ ! -e "$LINGER_DIR/$P2PC_USER" ]]; then
    todo "loginctl enable-linger reported success but linger is not enabled for $P2PC_USER" "Check:  loginctl show-user $P2PC_USER --property=Linger"
  else
    changed "loginctl enable-linger $P2PC_USER"
  fi
}

# delegated_controllers <uid>: what systemd delegates to user@<uid>.service, from the running cgroup if there is one,
# otherwise from the unit's configuration.
delegated_controllers() {
  local uid="$1" f
  f="/sys/fs/cgroup/user.slice/user-${uid}.slice/user@${uid}.service/cgroup.controllers"
  if [[ -r "$f" ]]; then
    cat "$f"
  elif command -v systemctl >/dev/null 2>&1; then
    systemctl show "user@${uid}.service" --property=DelegateControllers --value 2>/dev/null || true
  fi
}

step_cgroups() {
  local uid missing delegated
  echo "cgroups"
  if [[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null || true)" == cgroup2fs ]]; then
    ok "cgroup v2 (unified hierarchy)"
  else
    todo "cgroup v2 is not the active hierarchy" \
      "Boot with systemd.unified_cgroup_hierarchy=1 on the kernel command line (most current distributions already do)."
  fi
  if ! uid="$(id -u "$P2PC_USER" 2>/dev/null)"; then
    warn "cgroup delegation cannot be checked until user $P2PC_USER exists"
    return 0
  fi
  delegated="$(delegated_controllers "$uid")"
  missing="$(missing_controllers "$delegated")"
  if [[ -z "$missing" ]]; then
    ok "cpu, memory and pids are delegated to user sessions (delegated: ${delegated:-unknown})"
  else
    todo "controllers not delegated to user sessions: $missing (delegated: ${delegated:-none})" \
      "Without them rootless Podman cannot enforce CPU/memory/PID limits. To fix, run as root:" \
      "  mkdir -p /etc/systemd/system/user@.service.d" \
      "  printf '[Service]\\nDelegate=cpu cpuset io memory pids\\n' > /etc/systemd/system/user@.service.d/p2pc-delegate.conf" \
      "  systemctl daemon-reload && systemctl restart user@${uid}.service   # or reboot"
  fi
}

step_podman() {
  local out ver
  echo "Podman"
  if ! command -v podman >/dev/null 2>&1; then
    todo "podman is not installed (need >= $MIN_PODMAN)" "Install it with your package manager, e.g.: apt-get install podman   |   dnf install podman   |   pacman -S podman   (Ubuntu 24.04 ships 4.9.3)"
  else
    out="$(podman --version 2>&1 || true)"
    ver="$(podman_version_from "$out")"
    if [[ -n "$ver" ]] && version_ge "$ver" "$MIN_PODMAN"; then
      ok "podman $ver (>= $MIN_PODMAN)"
    else
      todo "podman '${ver:-unknown}' is older than $MIN_PODMAN" "Upgrade it; Ubuntu 22.04's 3.4 is too old."
    fi
  fi
  if command -v crun >/dev/null 2>&1; then
    ok "crun present"
  else
    todo "crun is not installed" "Install it with your package manager, e.g.: apt-get install crun   |   dnf install crun   |   pacman -S crun"
  fi
}

# cdi_spec_current: the CDI spec exists, is not empty, and is not older than the loaded driver (when that is known).
# Both --check-only and the real run use it, so they agree on whether the spec is regenerated.
cdi_spec_current() {
  [[ -s "$CDI_SPEC" ]] || return 1
  [[ ! -e "$NVIDIA_VERSION_FILE" || ! "$CDI_SPEC" -ot "$NVIDIA_VERSION_FILE" ]]
}

nvidia_gpu_present() {
  [[ -e /dev/nvidiactl ]] && return 0
  command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L 2>/dev/null | grep -q '^GPU '
}

step_gpu() {
  echo "NVIDIA GPU (CDI)"
  if ! nvidia_gpu_present; then
    ok "no NVIDIA GPU detected: CPU-only node, CDI skipped"
    return 0
  fi
  if ! command -v nvidia-ctk >/dev/null 2>&1; then
    todo "an NVIDIA GPU is present but the NVIDIA Container Toolkit (nvidia-ctk) is not installed" \
      "This script does not install it. Follow NVIDIA's install guide:" \
      "  https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html" \
      "(verify the repository's signing-key fingerprint against NVIDIA's documentation), then re-run this script." \
      "The toolkit version measured for P2PC is 1.20.1 (spec 9.0)."
    return 0
  fi
  if ((CHECK_ONLY)); then
    if cdi_spec_current; then ok "CDI spec present and current: $CDI_SPEC"; else would "nvidia-ctk cdi generate --output=$CDI_SPEC"; fi
    return 0
  fi
  if cdi_spec_current; then
    ok "CDI spec present and current: $CDI_SPEC (kept; delete it to regenerate)"
  elif ! install -d -m 0755 "$(dirname "$CDI_SPEC")"; then
    todo "cannot create $(dirname "$CDI_SPEC")" "Create it by hand, then re-run this script."
  elif ! nvidia-ctk cdi generate --output="$CDI_SPEC" >/dev/null 2>&1; then
    todo "nvidia-ctk cdi generate failed" "Run it by hand to see the error: nvidia-ctk cdi generate --output=$CDI_SPEC"
  elif [[ ! -s "$CDI_SPEC" ]]; then
    todo "nvidia-ctk cdi generate reported success but $CDI_SPEC is missing or empty" "Run it by hand and look at its output."
  else
    changed "generated $CDI_SPEC ($(nvidia-ctk cdi list 2>/dev/null | grep -c '^nvidia.com/gpu=' || true) CDI names)"
    echo "         Re-run this script after a driver update to refresh it."
  fi
}

# print_result: the closing line, and the exit code for it: 1 only for [TODO]s. [plan] steps are what install-node.sh does
# itself, so they do not make the host "not ready".
print_result() {
  if ((TODO_COUNT > 0)); then
    echo "Result: NOT ready: $TODO_COUNT item(s) need attention (see [TODO] above)."
    return 1
  fi
  if ((PLAN_COUNT > 0)); then
    echo "Result: Ready: install-node.sh will do the $PLAN_COUNT [plan] step(s) above."
    return 0
  fi
  echo "Result: ready."
}

usage() {
  cat <<'USAGE'
Usage: setup-host.sh [--check-only]
  --check-only   report what is and is not in place; change nothing (no root needed)
  -h, --help     this text
Exit codes: 0 ready (--check-only: also when only [plan] steps are left), 1 a [TODO] is open, 2 usage error,
3 needs root.
USAGE
}

main() {
  set -uo pipefail
  while (($# > 0)); do
    case "$1" in
      --check-only) CHECK_ONLY=1 ;;
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
  if ((!CHECK_ONLY)) && [[ $EUID -ne 0 ]]; then
    echo "setup-host.sh must run as root (use --check-only to just look)" >&2
    return 3
  fi
  if ((CHECK_ONLY)); then
    echo "p2pc host setup (check-only: nothing will be changed)"
  else
    echo "p2pc host setup"
  fi
  step_user
  step_subids
  step_linger
  step_cgroups
  step_podman
  step_gpu
  echo
  print_result
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
  exit $?
fi
