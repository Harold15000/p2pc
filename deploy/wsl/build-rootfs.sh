#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds the `p2pc-node` WSL2 distro image (spec 9.0, experiment E1): an Ubuntu 24.04 rootfs with Podman, crun and
# the NVIDIA Container Toolkit, configured as an appliance (no automount, no Windows interop, no systemd, cgroupfs).
#
# Run as root on a Linux build host or inside a build distro (an existing Ubuntu WSL distro works). Everything
# happens inside one temporary directory; nothing else on the host is touched, and every mount is undone on exit.
#
#   sudo deploy/wsl/build-rootfs.sh [--dry-run] [--out DIR] [--version V]
#                                   [--agent-from DIST [--agent-version V] | --agent PATH [--shim PATH] [--server PATH]]
#                                   [--base-image FILE] [--update-lock] [--archive snapshot|live]
#
# Reproducibility: SOURCE_DATE_EPOCH defaults to the commit time of the checkout (set it yourself to override), and the
# base packages come from a pinned Ubuntu snapshot (packages.lock: snapshot=...), so the same commit builds the same
# package set.
#
# Outputs (in --out, default deploy/wsl/out):
#   p2pc-node-<version>.tar.gz          the rootfs, importable with `wsl --import`
#   p2pc-node-<version>.tar.gz.sha256   `sha256sum -c` compatible
#   manifest.txt                        every installed package and its version
#
# Sourcing this file only defines functions (deploy/tests/ unit-tests them).

# ---------------------------------------------------------------------------------------------------------------
# Pinned inputs. Changing any of these is a reviewed, deliberate act.
# ---------------------------------------------------------------------------------------------------------------
# 0.2.0 (T14b2): the agent from the release dist (--agent-from), p2pc-node-run and boot-status.sh, /var/log/p2pc.
# 0.2.1 (T14b2 real run): p2pc-shim next to the agent, and the p2pc-node-run that waits for the lock.
# 0.2.2 (T14b2 review): the agent's config is /var/lib/p2pc/agent.toml (P2PC_AGENT_CONFIG), so -Upgrade carries the
# enrollment; up to 0.2.1 it was /etc/p2pc/agent.toml and an upgrade lost [server].
# 0.3.0 (H2 T2-41): the hub in the distro: p2pc-server (from the same dist as the agent) and p2pc-run, which runs the
# agent and, while /var/lib/p2pc-server/hub.enabled exists, the hub; p2pc-node-run is a symlink to it for one release.
readonly DEFAULT_IMAGE_VERSION="0.3.0"
readonly BASE_URL="https://releases.ubuntu.com/24.04.5/ubuntu-24.04.5-wsl-amd64.wsl"
readonly BASE_SHA256="bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e"
readonly NVIDIA_KEY_URL="https://nvidia.github.io/libnvidia-container/gpgkey"
# Primary-key fingerprint of the key served at NVIDIA_KEY_URL: "NVIDIA CORPORATION (Open Source Projects)
# <cudatools@nvidia.com>", the signing key of the libnvidia-container / NVIDIA Container Toolkit apt repository.
# Source: fetched from NVIDIA_KEY_URL on 2026-11-05 and fingerprinted independently by the architect, and seen by this
# builder in the first real run. NOTE: this is NOT the key of NVIDIA's CUDA repository (EB693B35...3BF863CC), which
# is a different key. If NVIDIA rotates the key the build fails closed and prints the fingerprint it saw; verify that
# against NVIDIA's install guide before changing this value.
readonly NVIDIA_KEY_FPR="C95B321B61E88C1809C4F759DDCAE044F796ECB0"  # gitleaks:allow
readonly NVIDIA_APT_URL="https://nvidia.github.io/libnvidia-container/stable/deb/amd64"
# Ubuntu's snapshot archive: every Ubuntu package (and every security update up to the snapshot time) comes from
# <SNAPSHOT_BASE>/<timestamp> where the timestamp is the `snapshot=` line of packages.lock. NVIDIA's repository is not
# snapshotted, which is why its four packages keep exact pins.
readonly SNAPSHOT_BASE="https://snapshot.ubuntu.com/ubuntu"
readonly UBUNTU_SUITES="noble noble-updates noble-security"
# --archive live: the regular mirrors, for when the snapshot service is down. NOT reproducible; never chosen automatically.
readonly LIVE_ARCHIVE_URL="http://archive.ubuntu.com/ubuntu"
readonly LIVE_SECURITY_URL="http://security.ubuntu.com/ubuntu"
readonly NVIDIA_KEYRING="/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg"
readonly SUBID_LINE="containers:2147483647:2147483648"

MOUNTED=()
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly LOCK_FILE="$SCRIPT_DIR/packages.lock"

log() { printf '[build-rootfs] %s\n' "$*" >&2; }
die() {
  printf '[build-rootfs] ERROR: %s\n' "$*" >&2
  exit 1
}

# ---------------------------------------------------------------------------------------------------------------
# Pure helpers (unit-tested in deploy/tests/test-build-rootfs.sh)
# ---------------------------------------------------------------------------------------------------------------

# is_valid_version <v>: MAJOR.MINOR.PATCH with an optional -/+ suffix. It ends up in file names, so no slashes.
is_valid_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]
}

# iso8601_utc <epoch>
iso8601_utc() {
  date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ
}

# lock_parse <file>: prints "name<TAB>version" per entry (version empty when unpinned). Fails on a malformed line.
lock_parse() {
  local file="$1" line name version n=0
  local -A seen=()
  [[ -r "$file" ]] || {
    printf 'cannot read %s\n' "$file" >&2
    return 1
  }
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    line="${line%"${line##*[![:space:]]}"}" # trim trailing whitespace
    line="${line#"${line%%[![:space:]]*}"}" # trim leading whitespace
    [[ -z "$line" || "$line" == \#* ]] && continue
    if [[ "$line" == snapshot=* ]]; then
      # A directive, not a package: validated here, read by lock_snapshot.
      if [[ ! "${line#snapshot=}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
        printf '%s:%d: bad snapshot timestamp in "%s" (want YYYYMMDDTHHMMSSZ, UTC)\n' "$file" "$n" "$line" >&2
        return 1
      fi
      if [[ -n "${seen[snapshot=]:-}" ]]; then
        printf '%s:%d: duplicate snapshot line\n' "$file" "$n" >&2
        return 1
      fi
      seen[snapshot=]=1
      continue
    fi
    if [[ "$line" == *=* ]]; then
      name="${line%%=*}"
      version="${line#*=}"
      if [[ -z "$version" || ! "$version" =~ ^[A-Za-z0-9][A-Za-z0-9.+~:-]*$ ]]; then
        printf '%s:%d: bad version in "%s"\n' "$file" "$n" "$line" >&2
        return 1
      fi
    else
      name="$line"
      version=""
    fi
    if [[ ! "$name" =~ ^[a-z0-9][a-z0-9+.-]*$ ]]; then
      printf '%s:%d: bad package name in "%s"\n' "$file" "$n" "$line" >&2
      return 1
    fi
    if [[ -n "${seen[$name]:-}" ]]; then
      printf '%s:%d: duplicate package "%s"\n' "$file" "$n" "$name" >&2
      return 1
    fi
    seen[$name]=1
    printf '%s\t%s\n' "$name" "$version"
  done <"$file"
}

# lock_snapshot <file>: the UTC timestamp of the `snapshot=` line (YYYYMMDDTHHMMSSZ); fails if there is not exactly
# one valid line.
lock_snapshot() {
  local ts
  lock_parse "$1" >/dev/null || return 1
  ts="$(grep -E '^[[:space:]]*snapshot=' "$1" | sed -E 's/^[[:space:]]*snapshot=//; s/[[:space:]]+$//')"
  [[ "$ts" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
    printf '%s: no snapshot=YYYYMMDDTHHMMSSZ line\n' "$1" >&2
    return 1
  }
  printf '%s\n' "$ts"
}

# snapshot_sources_content <timestamp>: the apt (deb822) sources that point noble, noble-updates and noble-security at
# the Ubuntu snapshot archive.
snapshot_sources_content() {
  printf 'Types: deb\nURIs: %s/%s\nSuites: %s\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n' \
    "$SNAPSHOT_BASE" "$1" "$UBUNTU_SUITES"
}

# live_sources_content: the apt (deb822) sources for --archive live: noble and noble-updates from archive.ubuntu.com,
# noble-security from security.ubuntu.com.
live_sources_content() {
  printf 'Types: deb\nURIs: %s\nSuites: noble noble-updates\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\nTypes: deb\nURIs: %s\nSuites: noble-security\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n' \
    "$LIVE_ARCHIVE_URL" "$LIVE_SECURITY_URL"
}

# parse_archive_mode <value>: prints snapshot or live; fails on anything else (there is no "auto" and no fallback).
parse_archive_mode() {
  case "$1" in
    snapshot | live) printf '%s\n' "$1" ;;
    *) return 1 ;;
  esac
}

# archive_sources_content <snapshot|live> <timestamp>
archive_sources_content() {
  if [[ "$1" == live ]]; then live_sources_content; else snapshot_sources_content "$2"; fi
}

# archive_urls <snapshot|live> <timestamp>: the archive URLs apt will contact, space separated (for error messages).
archive_urls() {
  if [[ "$1" == live ]]; then
    printf '%s %s\n' "$LIVE_ARCHIVE_URL" "$LIVE_SECURITY_URL"
  else
    printf '%s/%s\n' "$SNAPSHOT_BASE" "$2"
  fi
}

# archive_record <snapshot|live> <timestamp>: the value recorded in manifest.txt and /etc/p2pc-distro-version.
archive_record() {
  if [[ "$1" == live ]]; then printf 'live\n'; else printf 'snapshot@%s\n' "$2"; fi
}

# archive_build_time_line: for --archive live, "\narchive_build_time=<real UTC time>" (the build is not reproducible, so
# when it ran matters); nothing for a snapshot.
archive_build_time_line() {
  if [[ "$ARCHIVE" == live ]]; then printf '\narchive_build_time=%s' "$ARCHIVE_BUILD_TIME"; fi
}

# lock_is_nvidia <name>: packages that come from NVIDIA's repository rather than Ubuntu's.
lock_is_nvidia() {
  [[ "$1" == nvidia-container-toolkit* || "$1" == libnvidia-container* ]]
}

# lock_apt_args <ubuntu|nvidia>  (stdin: lock_parse output): one apt argument per line, `name=version` or bare name.
lock_apt_args() {
  local want="$1" name version
  while IFS=$'\t' read -r name version; do
    [[ -z "$name" ]] && continue
    if lock_is_nvidia "$name"; then
      [[ "$want" == nvidia ]] || continue
    else
      [[ "$want" == ubuntu ]] || continue
    fi
    if [[ -n "$version" ]]; then printf '%s=%s\n' "$name" "$version"; else printf '%s\n' "$name"; fi
  done
}

# ubuntu_install_args  (stdin: lock_parse output): the Ubuntu package arguments for apt-get install, by mode.
# snapshot: the exact pins of packages.lock. --update-lock or --archive live: bare names, i.e. the newest version the
# archive has (the live archive keeps only the newest of each package in -updates/-security, so pins stop resolving within
# days). NVIDIA's packages are not affected: lock_apt_args nvidia always keeps their pins.
ubuntu_install_args() {
  if [[ "$ARCHIVE" == live ]] || ((UPDATE_LOCK)); then lock_apt_names ubuntu; else lock_apt_args ubuntu; fi
}

# lock_unpinned  (stdin: lock_parse output): names without a version.
lock_unpinned() {
  local name version
  while IFS=$'\t' read -r name version; do
    [[ -n "$name" && -z "$version" ]] && printf '%s\n' "$name"
  done
}

# lock_apt_names <ubuntu|nvidia>  (stdin: lock_parse output): bare package names, one per line (used by --update-lock,
# which installs the newest version available in the new snapshot instead of the pinned one).
lock_apt_names() {
  local want="$1" name version
  while IFS=$'\t' read -r name version; do
    [[ -z "$name" ]] && continue
    if lock_is_nvidia "$name"; then
      [[ "$want" == nvidia ]] || continue
    else
      [[ "$want" == ubuntu ]] || continue
    fi
    printf '%s\n' "$name"
  done
}

# lock_pin_versions <lockfile> <resolved.tsv> [<snapshot>]: prints the lock with every package listed in resolved.tsv
# (name<TAB>version) pinned to that version, whether it was bare or already pinned, and, when given, the snapshot line
# replaced by <snapshot> (added if missing). Comments, blank lines and packages not in resolved.tsv (the NVIDIA ones)
# are kept as they are.
lock_pin_versions() {
  local lockfile="$1" resolved="$2" snap="${3:-}" line name ver done_snap=0
  local -A res=()
  while IFS=$'\t' read -r name ver; do
    [[ -n "$name" ]] && res[$name]="$ver"
  done <"$resolved"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == snapshot=* && -n "$snap" ]]; then
      printf 'snapshot=%s\n' "$snap"
      done_snap=1
      continue
    fi
    if [[ -z "$line" || "$line" == \#* || "$line" == snapshot=* ]]; then
      printf '%s\n' "$line"
      continue
    fi
    name="${line%%=*}"
    if [[ -n "${res[$name]:-}" ]]; then
      printf '%s=%s\n' "$name" "${res[$name]}"
    else
      printf '%s\n' "$line"
    fi
  done <"$lockfile"
  if [[ -n "$snap" && $done_snap -eq 0 ]]; then
    printf 'snapshot=%s\n' "$snap"
  fi
}

# sha256_of <file>
sha256_of() {
  sha256sum -- "$1" | cut -d' ' -f1
}

# verify_sha256 <file> <expected-hex>
verify_sha256() {
  local want="${2,,}" got
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || return 1
  got="$(sha256_of "$1")"
  [[ "$got" == "$want" ]]
}

# The release's agent (T14b2): the musl build for the image's architecture, from a dist/<version>/ that
# scripts/release.sh wrote, checked against its SHA256SUMS before anything else reads it.
readonly AGENT_TARGET="x86_64-unknown-linux-musl"

# dist_agent_tarball <SHA256SUMS> <version or empty>: the p2pc-agent tarball name SHA256SUMS lists for that version, or
# for the only version it lists. Fails when there is none, several (and no version), or a malformed version.
dist_agent_tarball() {
  local sums="$1" want="$2" versions n
  versions="$(awk '{ n = $2; sub(/^\*/, "", n); print n }' "$sums" 2>/dev/null |
    sed -n "s/^p2pc-agent-\(.*\)-$AGENT_TARGET\.tar\.gz\$/\1/p" | LC_ALL=C sort -u)"
  if [[ -n "$want" ]]; then
    grep -qxF -- "$want" <<<"$versions" || return 1
  else
    n="$(grep -c . <<<"$versions" || true)"
    ((n == 1)) || return 1
    want="$versions"
  fi
  [[ "$want" =~ ^[0-9A-Za-z.+-]+$ ]] || return 1
  printf 'p2pc-agent-%s-%s.tar.gz\n' "$want" "$AGENT_TARGET"
}

# dist_shim_tarball <agent tarball name>: the p2pc-shim tarball of the same version and target. The agent's executor
# takes no lease unless p2pc-shim sits next to it (T14b2 real run), so --agent-from installs both.
dist_shim_tarball() {
  [[ "$1" == p2pc-agent-*.tar.gz ]] || return 1
  printf 'p2pc-shim-%s\n' "${1#p2pc-agent-}"
}

# dist_server_tarball <agent tarball name>: the p2pc-server tarball of the same version and target. The image carries the
# hub (H2 §8.5), so --agent-from installs it too.
dist_server_tarball() {
  [[ "$1" == p2pc-agent-*.tar.gz ]] || return 1
  printf 'p2pc-server-%s\n' "${1#p2pc-agent-}"
}

# dist_sum <SHA256SUMS> <name>: the SHA-256 listed for exactly that name.
dist_sum() {
  awk -v f="$2" '{ n = $2; sub(/^\*/, "", n) } n == f && $1 ~ /^[0-9a-f]+$/ && length($1) == 64 { print $1; exit }' "$1"
}

# verified_dist_sum <dist dir> <name>: the SHA-256 that SHA256SUMS lists for the file, printed only when the file
# matches it. That listed hash, never a new hash of the dist file, is what the work-dir copy is checked against later.
verified_dist_sum() {
  local want
  want="$(dist_sum "$1/SHA256SUMS" "$2")"
  [[ -n "$want" && -f "$1/$2" ]] && verify_sha256 "$1/$2" "$want" || return 1
  printf '%s\n' "$want"
}

# dist_verify <dist dir> <name>: the file exists and matches its line in SHA256SUMS.
dist_verify() {
  verified_dist_sum "$1" "$2" >/dev/null
}

# gpg_primary_fprs  (stdin: `gpg --with-colons` output): the fingerprints of primary keys only (not subkeys).
gpg_primary_fprs() {
  awk -F: '
    $1 == "pub" { want = 1; next }
    $1 == "sub" || $1 == "sec" || $1 == "ssb" { want = 0; next }
    $1 == "fpr" && want { print $10; want = 0 }
  '
}

# fingerprint_matches <pinned-fpr>  (stdin: gpg colon output): true only if the input holds exactly one primary key
# and it is the pinned one. A second key would otherwise be trusted by apt without being pinned.
fingerprint_matches() {
  local pin="${1^^}" f
  local -a fprs=()
  while IFS= read -r f; do fprs+=("${f^^}"); done < <(gpg_primary_fprs)
  [[ ${#fprs[@]} -eq 1 && "${fprs[0]}" == "$pin" ]]
}

# path_within <root> <path>: true if <path>, after resolving symlinks and "..", is <root> or below it.
path_within() {
  local root path
  root="$(realpath -m -- "$1")"
  path="$(realpath -m -- "$2")"
  [[ "$path" == "$root" || "$path" == "$root"/* ]]
}

# mounts_under <dir> [mountinfo-file]: mount points at or below <dir>, in mount order. <dir> is normalised first (no
# trailing or doubled slashes, no "..", symlinks resolved), because /proc/self/mountinfo shows canonical paths; and the
# mount points in mountinfo are decoded, because the kernel writes space, tab, newline and backslash as octal escapes
# (\040 \011 \012 \134). Comparing the raw text would miss a mount under a path that has one of those.
mounts_under() {
  local d
  d="$(realpath -m -- "$1")"
  P2PC_MU_DIR="$d" awk '
    function unesc(s,   out, c) {
      out = ""
      while (match(s, /\\[0-7][0-7][0-7]/)) {
        c = substr(s, RSTART + 1, 3)
        out = out substr(s, 1, RSTART - 1) sprintf("%c", substr(c, 1, 1) * 64 + substr(c, 2, 1) * 8 + substr(c, 3, 1))
        s = substr(s, RSTART + RLENGTH)
      }
      return out s
    }
    BEGIN { d = ENVIRON["P2PC_MU_DIR"] }
    { m = unesc($5); if (m == d || index(m, d "/") == 1) print m }
  ' "${2:-/proc/self/mountinfo}"
}

# deepest_first  (stdin: one path per line): deepest paths first, so children are unmounted before their parents.
deepest_first() {
  awk '{ print length($0) "\t" $0 }' | sort -t$'\t' -k1,1nr -s | cut -f2-
}

# live_mounts <work-dir>: everything that is mounted at or below <work-dir>: what mountinfo shows, plus a direct
# mountpoint(1) check of the places we mount on. Two independent views, so a parsing gap in one cannot hide a mount.
live_mounts() {
  local d="$1" m
  {
    mounts_under "$d"
    for m in "$d" "$d/rootfs" "$d/rootfs/proc" "$d/rootfs/sys" "$d/rootfs/dev" "$d/rootfs/dev/pts"; do
      if mountpoint -q -- "$m" 2>/dev/null; then printf '%s\n' "$m"; fi
    done
  } | LC_ALL=C sort -u
}

# valid_work_path <path>: absolute, with no whitespace and no backslash (they are escaped in mountinfo, and a build
# directory name that needs escaping is not worth the risk).
valid_work_path() {
  [[ "$1" == /* && "$1" != *[[:space:]]* && "$1" != *\\* ]]
}

# default_source_date_epoch <dir>: the commit time of the checkout that <dir> belongs to, so that the same commit gives
# the same tar timestamps; the current time (with a warning on stderr) when git or the repository is not available.
# `safe.directory=*` only for this one read-only `git log`: the script runs as root under sudo, on a checkout owned by
# someone else, and git would otherwise refuse ("dubious ownership"); the checkout is already trusted, since root is
# executing a script from it.
default_source_date_epoch() {
  local ct=""
  if command -v git >/dev/null 2>&1; then
    ct="$(git -c safe.directory='*' -C "$1" log -1 --format=%ct 2>/dev/null || true)"
  fi
  if [[ "$ct" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$ct"
    return 0
  fi
  log "WARNING: cannot read the commit time (no git, or not a git checkout): using the current time. The tar will NOT be reproducible; set SOURCE_DATE_EPOCH to fix it."
  date +%s
}

# File capabilities (setcap) live in the security.capability xattr. They must survive unpack and pack: without them
# /usr/bin/ping and the like stop working for non-root users, and the image silently differs from the packages' intent.
# Only this xattr is carried (no SELinux labels, ACLs or user.* data from the build host). Overridable only for the
# unit tests, which cannot set security.* xattrs without root.
XATTR_INCLUDE="security.capability"

# tar_extract_args: one tar argument per line, for unpacking the base image (add -xpzf and -C yourself).
tar_extract_args() {
  printf '%s\n' "--numeric-owner" "--xattrs" "--xattrs-include=$XATTR_INCLUDE"
}

# tar_deterministic_args <epoch>: one tar argument per line. Same tree + same epoch = same tar stream.
# PAX format, because the GNU format has nowhere to put xattrs. The pax extended-header names are fixed
# (GNU tar's default contains the process id, which would make every pack different), and atime/ctime, which GNU tar
# only adds on request, are deleted explicitly. `wsl --import` reads pax tarballs.
tar_deterministic_args() {
  printf '%s\n' "--sort=name" "--mtime=@$1" "--numeric-owner" "--format=pax" \
    "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime" \
    "--xattrs" "--xattrs-include=$XATTR_INCLUDE"
}

# is_elf <file>
is_elf() {
  [[ "$(head -c 4 -- "$1" | od -An -tx1 | tr -d ' \n')" == "7f454c46" ]]
}

# ---------------------------------------------------------------------------------------------------------------
# Configuration file contents (the values come from experiment E1 and spec 9.0; they are printed by --dry-run)
# ---------------------------------------------------------------------------------------------------------------
wsl_conf_content() {
  cat <<'CONF'
[boot]
systemd=false
command=/usr/local/sbin/p2pc-boot
[automount]
enabled=false
mountFsTab=false
[interop]
enabled=false
appendWindowsPath=false
[network]
generateHosts=true
generateResolvConf=true
[user]
default=root
CONF
}

agent_config_content() {
  cat <<'CONF'
# p2pc-agent config of the p2pc-node distro (P2PC_AGENT_CONFIG points here). No settings: the built-in defaults.
# `p2pc-agent join` adds the [server] section. install.ps1 -Upgrade carries this file over with /var/lib/p2pc.
CONF
}

containers_conf_content() {
  cat <<'CONF'
[engine]
cgroup_manager = "cgroupfs"
events_logger = "file"

[containers]
cgroupns = "private"
CONF
}

nvidia_apt_list_content() {
  printf 'deb [arch=amd64 signed-by=%s] %s /\n' "$NVIDIA_KEYRING" "$NVIDIA_APT_URL"
}

# ---------------------------------------------------------------------------------------------------------------
# Plan (--dry-run)
# ---------------------------------------------------------------------------------------------------------------
# plan_entry <name> <version>: one package line of the plan.
plan_entry() {
  if [[ -n "$2" ]]; then printf '       %s=%s\n' "$1" "$2"; else printf '       %s  (UNPINNED)\n' "$1"; fi
}

print_plan() {
  local name version src
  cat <<PLAN
p2pc-node image build plan (nothing is executed, downloaded or written)

Inputs
  image version     : $IMAGE_VERSION
  base image        : ${BASE_IMAGE_FILE:-$BASE_URL}
  base sha256       : $BASE_SHA256   (build aborts on mismatch)
  SOURCE_DATE_EPOCH : $SOURCE_DATE_EPOCH ($(iso8601_utc "$SOURCE_DATE_EPOCH"))   (default: the commit time of this checkout)
  Ubuntu archive    : $(archive_record "$ARCHIVE" "$SNAPSHOT_TS"): $(archive_urls "$ARCHIVE" "$SNAPSHOT_TS")   (--archive $ARCHIVE; suites: $UBUNTU_SUITES)
  agent binary      : $(agent_plan_line)
  job shim          : $(shim_plan_line)
  hub server        : $(server_plan_line)
  lock file         : $LOCK_FILE

Steps (as root, in a private temporary directory under \${TMPDIR:-/var/tmp})
  1. download the base image and verify its SHA-256, then unpack it into <tmp>/rootfs
  2. mount /proc, /sys, /dev and /dev/pts into <tmp>/rootfs; copy the build host's resolv.conf in
  3. point apt at the Ubuntu archive above, run apt-get update --error-on=any (a failing archive stops the build, naming
     its URL) and apt-get -y upgrade (every security fix up to the snapshot, reproducibly; with --archive live, up to
     the build time, NOT reproducibly), then install with apt-get install --no-install-recommends:
PLAN
  while IFS=$'\t' read -r name version; do
    lock_is_nvidia "$name" && continue
    if [[ "$ARCHIVE" == live ]] || ((UPDATE_LOCK)); then
      # the same test as ubuntu_install_args: the newest version, not the lock's pin
      [[ "$ARCHIVE" == live ]] && src='live archive' || src='new snapshot'
      if [[ -n "$version" ]]; then
        printf '       %s  (newest in the %s; lock pin %s ignored)\n' "$name" "$src" "$version"
      else
        printf '       %s  (newest in the %s)\n' "$name" "$src"
      fi
    else
      plan_entry "$name" "$version"
    fi
  done <<<"$LOCK_ENTRIES"
  cat <<PLAN
  4. add NVIDIA's apt repository: key from $NVIDIA_KEY_URL, required primary-key fingerprint
       $NVIDIA_KEY_FPR
     ($NVIDIA_APT_URL), then install:
PLAN
  while IFS=$'\t' read -r name version; do
    lock_is_nvidia "$name" || continue
    plan_entry "$name" "$version"
  done <<<"$LOCK_ENTRIES"
  cat <<PLAN
  5. write the configuration files:
     /etc/wsl.conf
$(wsl_conf_content | sed 's/^/         /')
     /etc/containers/containers.conf.d/p2pc.conf
$(containers_conf_content | sed 's/^/         /')
     /etc/subuid and /etc/subgid
         $SUBID_LINE
     /usr/local/sbin/p2pc-boot        (from deploy/wsl/p2pc-boot, mode 0755)
     /usr/local/sbin/p2pc-test-distro (from deploy/wsl/test-distro.sh, mode 0755)
     /usr/local/lib/p2pc/nvidia.sh    (from deploy/wsl/nvidia.sh, mode 0644; sourced by both scripts above)
     /usr/local/lib/p2pc/boot-status.sh (from deploy/wsl/boot-status.sh, mode 0644; "is the boot status of this start?")
     /usr/local/sbin/p2pc-run         (from deploy/wsl/p2pc-run, mode 0755; the Scheduled Task runs it: the agent, and
                                       the hub while /var/lib/p2pc-server/hub.enabled exists)
     /usr/local/sbin/p2pc-node-run -> p2pc-run   (the old path, kept as a symlink for one release)
     /usr/local/bin/p2pc-agent        (only with --agent-from or --agent)
     /usr/local/bin/p2pc-shim         (with --agent-from, or --agent with --shim; the agent takes no lease without it)
     /usr/local/bin/p2pc-server       (the hub: with --agent-from, or --agent with --server; p2pc-run starts it only while
                                       /var/lib/p2pc-server/hub.enabled exists)
     /usr/local/share/doc/p2pc-server/LICENSE and README   (with --agent-from: p2pc-server is AGPL-3.0-only)
     /etc/wsl-distribution.conf       (DELETED: the base image's first-launch OOBE would create a login user)
  6. create /var/lib/p2pc with mode 0700 (the agent's identity lives here), /var/lib/p2pc/agent.toml (mode 0600, the
     agent's config, no settings: the built-in defaults; join writes [server] into it) and /var/log/p2pc with mode 0700
     (p2pc-run's rotated agent.log and hub.log: the distro has no journald). /var/lib/p2pc-server, the hub's data, is
     NOT created: \`p2pc-server init\` creates it (0700) on the PC that becomes the hub
     write /etc/p2pc-distro-version  (image version $IMAGE_VERSION, build date, base sha256, apt snapshot)
  7. write manifest.txt from dpkg-query, then restore the stock apt sources, clean: apt lists and caches, /etc/machine-id (emptied), ssh host keys,
     logs, shell history, /tmp, /etc/resolv.conf
  8. unmount everything (from the mount list we kept, in reverse order, and from /proc/self/mountinfo; also on error,
     via trap), and refuse to tar or to delete the temp directory while anything is still mounted under it
  9. tar the rootfs deterministically and gzip it:
       tar -C <tmp>/rootfs $(tar_deterministic_args "$SOURCE_DATE_EPOCH" | tr '\n' ' ')-cf - . | gzip -n -9

Outputs in $OUT_DIR
  p2pc-node-$IMAGE_VERSION.tar.gz
  p2pc-node-$IMAGE_VERSION.tar.gz.sha256
  manifest.txt
PLAN
  if [[ "$ARCHIVE" == live ]]; then
    printf '\n%s\n' "$(live_warning)"
  fi
  if [[ -n "$(lock_unpinned <<<"$LOCK_ENTRIES")" ]]; then
    printf '\nWARNING: packages.lock has unpinned entries (%s).\n' "$(lock_unpinned <<<"$LOCK_ENTRIES" | paste -sd, -)"
    printf 'A real build refuses them; run with --update-lock on a trusted host and commit the result.\n'
  fi
}

usage() {
  cat <<'USAGE'
Usage: build-rootfs.sh [options]
  --dry-run          print the plan and exit (no root, no network, no writes)
  --out DIR          output directory (default: <script dir>/out)
  --version V        image version, MAJOR.MINOR.PATCH (default: 0.3.0)
  --agent-from DIST  install the release's agent: p2pc-agent-<v>-x86_64-unknown-linux-musl.tar.gz from DIST (the
                     dist/<version>/ of scripts/release.sh), checked against DIST/SHA256SUMS first (the documented build)
  --agent-version V  with --agent-from: which version, when SHA256SUMS lists several
                     It also installs p2pc-shim and p2pc-server (the hub, with its LICENSE) from
                     p2pc-{shim,server}-<v>-x86_64-unknown-linux-musl.tar.gz, checked the same way.
  --agent PATH       install this p2pc-agent binary as is (a developer build; not checked against anything)
  --shim PATH        with --agent: install this p2pc-shim binary as is
  --server PATH      with --agent: install this p2pc-server binary as is (the hub)
  --base-image FILE  use an already downloaded base image (it is still verified against the pinned SHA-256)
  --archive MODE     snapshot (default): Ubuntu packages from the pinned snapshot, reproducible.
                     live: from archive.ubuntu.com / security.ubuntu.com, NOT reproducible; for when the snapshot
                     service is down. Installs the newest Ubuntu versions (the pins of packages.lock are ignored,
                     NVIDIA's are kept), records them in manifest.txt, never rewrites packages.lock. The script
                     never switches by itself.
  --update-lock      move the snapshot to now, install the newest Ubuntu versions in it, then rewrite packages.lock
                     with the new snapshot timestamp and the resolved versions (NVIDIA's pins are kept)
  -h, --help         this text
USAGE
}

# ---------------------------------------------------------------------------------------------------------------
# Build steps (globals: WORK, ROOTFS, MOUNTED)
# ---------------------------------------------------------------------------------------------------------------
require_tools() {
  local t missing=()
  for t in curl tar gzip sha256sum gpg chroot mount umount realpath install od; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  ((${#missing[@]} == 0)) || die "missing tools on the build host: ${missing[*]} (apt-get install curl tar gzip coreutils gnupg util-linux)"
  [[ "$(uname -m)" == x86_64 ]] || die "this builder targets amd64 (x86_64) only; this host is $(uname -m)"
}

chroot_run() {
  chroot "$ROOTFS" /usr/bin/env -i HOME=/root LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin "$@"
}

# write_rootfs_file <mode> <absolute-path-inside-rootfs> <content>
write_rootfs_file() {
  local mode="$1" path="$2" content="$3" dest="$ROOTFS$2"
  path_within "$ROOTFS" "$(dirname "$dest")" || die "refusing to write outside the rootfs: $path"
  mkdir -p -- "$(dirname "$dest")"
  rm -f -- "$dest"
  (
    umask 077
    printf '%s\n' "$content" >"$dest"
  )
  chmod "$mode" -- "$dest"
}

mount_chroot() {
  mount -t proc proc "$ROOTFS/proc"
  MOUNTED+=("$ROOTFS/proc")
  mount -t sysfs sysfs "$ROOTFS/sys"
  MOUNTED+=("$ROOTFS/sys")
  mount --bind /dev "$ROOTFS/dev"
  mount --make-rslave "$ROOTFS/dev"
  MOUNTED+=("$ROOTFS/dev")
  mount --bind /dev/pts "$ROOTFS/dev/pts"
  mount --make-rslave "$ROOTFS/dev/pts"
  MOUNTED+=("$ROOTFS/dev/pts")
}

unmount_chroot() {
  local m i
  [[ -n "${ROOTFS:-}" && -d "$ROOTFS" ]] || return 0
  # 1. What we mounted, in reverse order.
  for ((i = ${#MOUNTED[@]} - 1; i >= 0; i--)); do
    m="${MOUNTED[i]}"
    if mountpoint -q -- "$m" 2>/dev/null; then
      umount -- "$m" 2>/dev/null || umount -l -- "$m" 2>/dev/null || log "WARNING: could not unmount $m"
    fi
  done
  # 2. Anything else mountinfo shows below the rootfs, deepest first (this catches what our own list missed).
  while IFS= read -r m; do
    [[ -n "$m" ]] || continue
    umount -- "$m" 2>/dev/null || umount -l -- "$m" 2>/dev/null || log "WARNING: could not unmount $m"
  done < <(mounts_under "$ROOTFS" | deepest_first)
  MOUNTED=()
}

# assert_unmounted <what>: dies if anything is still mounted at or below WORK.
assert_unmounted() {
  local left
  left="$(live_mounts "$WORK")"
  if [[ -n "$left" ]]; then
    log "mounts are still present under $WORK:"
    printf '%s\n' "$left" >&2
    die "refusing to $1 while something is still mounted under the work directory"
  fi
}

cleanup() {
  local rc=$?
  trap - EXIT
  unmount_chroot || true
  if [[ -n "${WORK:-}" && -d "$WORK" ]]; then
    # A recursive delete through a live bind mount of /dev or /sys would be a disaster: check first, and even then
    # never cross a filesystem boundary (--one-file-system).
    if [[ -n "$(live_mounts "$WORK")" ]]; then
      log "ERROR: mounts are still present under $WORK; NOT deleting it. Unmount them, then remove it by hand:"
      live_mounts "$WORK" >&2
      [[ $rc -eq 0 ]] && rc=1
    else
      rm -rf --one-file-system -- "$WORK"
    fi
  fi
  exit "$rc"
}

fetch_base_image() {
  BASE_FILE="$WORK/base.wsl"
  if [[ -n "$BASE_IMAGE_FILE" ]]; then
    [[ -f "$BASE_IMAGE_FILE" ]] || die "--base-image not found: $BASE_IMAGE_FILE"
    BASE_FILE="$BASE_IMAGE_FILE"
  else
    log "downloading $BASE_URL"
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 \
      --output "$BASE_FILE" "$BASE_URL"
  fi
  verify_sha256 "$BASE_FILE" "$BASE_SHA256" || die "base image SHA-256 mismatch (expected $BASE_SHA256, got $(sha256_of "$BASE_FILE"))"
  log "base image verified"
}

unpack_base() {
  mkdir -p -- "$ROOTFS"
  chmod 755 "$ROOTFS"
  local -a xargs=()
  mapfile -t xargs < <(tar_extract_args)
  tar "${xargs[@]}" -xpzf "$BASE_FILE" -C "$ROOTFS"
  [[ -x "$ROOTFS/usr/bin/apt-get" && -d "$ROOTFS/etc" ]] || die "the unpacked base image does not look like an Ubuntu rootfs"
}

prepare_chroot() {
  local host_resolv=/etc/resolv.conf
  [[ -s "$host_resolv" ]] || die "$host_resolv is missing or empty on the build host (the chroot needs DNS)"
  path_within "$ROOTFS" "$ROOTFS/etc" || die "rootfs /etc escapes the rootfs"
  rm -f -- "$ROOTFS/etc/resolv.conf" # it may be a symlink; never write through it
  cp -- "$host_resolv" "$ROOTFS/etc/resolv.conf"
  # Packages must not start services while the chroot builds.
  write_rootfs_file 0755 /usr/sbin/policy-rc.d $'#!/bin/sh\nexit 101'
}

# live_warning: the loud notice printed whenever --archive live is used.
live_warning() {
  printf '%s\n' \
    "################################################################################" \
    "# WARNING: --archive live" \
    "# Ubuntu packages come from the live mirrors, so this build is NOT reproducible:" \
    "# the same commit can give different packages tomorrow. archive=live and the" \
    "# build time are recorded in manifest.txt and /etc/p2pc-distro-version." \
    "# Use the snapshot (the default) when its service works." \
    "################################################################################"
}

# apt_retries_content: apt settings for the build only (removed again by restore_apt_sources, never in the image). The
# snapshot service answered 5xx for hours on 2026-11-06; apt 2.3+ waits longer between retries.
apt_retries_content() {
  printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";'
}

# configure_apt_archive: apt reads only the chosen Ubuntu archive. The stock sources are moved to $WORK/apt-orig and
# put back by restore_apt_sources, so the shipped image has the standard Ubuntu sources.
# Check-Valid-Until is off for a snapshot because it is, by definition, a past state of the archive.
configure_apt_archive() {
  local f
  mkdir -p -- "$WORK/apt-orig"
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources; do
    if [[ -e "$ROOTFS$f" ]]; then
      path_within "$ROOTFS" "$(dirname "$ROOTFS$f")" || die "refusing to touch $f: it escapes the rootfs"
      mv -- "$ROOTFS$f" "$WORK/apt-orig/$(basename "$f")"
    fi
  done
  write_rootfs_file 0644 /etc/apt/sources.list.d/p2pc-archive.sources "$(archive_sources_content "$ARCHIVE" "$SNAPSHOT_TS")"
  if [[ "$ARCHIVE" == snapshot ]]; then
    write_rootfs_file 0644 /etc/apt/apt.conf.d/99p2pc-snapshot 'Acquire::Check-Valid-Until "false";'
  fi
  write_rootfs_file 0644 /etc/apt/apt.conf.d/99p2pc-retries "$(apt_retries_content)"
  log "apt points at $(archive_urls "$ARCHIVE" "$SNAPSHOT_TS") ($(archive_record "$ARCHIVE" "$SNAPSHOT_TS"))"
}

restore_apt_sources() {
  rm -f -- "$ROOTFS/etc/apt/sources.list.d/p2pc-archive.sources" "$ROOTFS/etc/apt/apt.conf.d/99p2pc-snapshot" "$ROOTFS/etc/apt/apt.conf.d/99p2pc-retries"
  [[ -e "$WORK/apt-orig/sources.list" ]] && cp -p -- "$WORK/apt-orig/sources.list" "$ROOTFS/etc/apt/sources.list"
  [[ -e "$WORK/apt-orig/ubuntu.sources" ]] && cp -p -- "$WORK/apt-orig/ubuntu.sources" "$ROOTFS/etc/apt/sources.list.d/ubuntu.sources"
  return 0
}

# apt_update <what>: apt-get update that STOPS the build on any fetch error. Without --error-on=any apt only warns when an
# archive answers 5xx, and the build would fail later with a confusing "Unable to locate package".
apt_update() {
  if ! chroot_run apt-get update --error-on=any; then
    die "apt-get update failed for $1. A source could not be fetched (see the apt lines above; Ubuntu archive: $(archive_urls "$ARCHIVE" "$SNAPSHOT_TS")). Nothing was built. If the Ubuntu snapshot service is down, retry later. The build can use --archive live (not reproducible); it is never chosen automatically."
  fi
}

install_ubuntu_packages() {
  local -a args=()
  # --update-lock: the newest version in the new snapshot (the pins are rewritten from what gets installed).
  # --archive live: the newest in the live archive; packages.lock is never rewritten. See ubuntu_install_args.
  mapfile -t args < <(ubuntu_install_args <<<"$LOCK_ENTRIES")
  ((${#args[@]} > 0)) || die "packages.lock has no Ubuntu packages"
  configure_apt_archive
  log "apt-get update + upgrade from $(archive_record "$ARCHIVE" "$SNAPSHOT_TS"), then install (Ubuntu): ${args[*]}"
  apt_update "the Ubuntu archive"
  chroot_run apt-get -y upgrade
  chroot_run apt-get install -y --no-install-recommends "${args[@]}"
}

install_nvidia_packages() {
  local -a args=()
  local keyfile="$WORK/nvidia.gpgkey" gnupg="$WORK/gnupg"
  mapfile -t args < <(lock_apt_args nvidia <<<"$LOCK_ENTRIES")
  ((${#args[@]} > 0)) || die "packages.lock has no NVIDIA packages"
  log "fetching NVIDIA apt signing key"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 --output "$keyfile" "$NVIDIA_KEY_URL"
  mkdir -m 700 -- "$gnupg"
  export GNUPGHOME="$gnupg"
  gpg --batch --with-colons --show-keys "$keyfile" | fingerprint_matches "$NVIDIA_KEY_FPR" ||
    die "NVIDIA signing key does not match the pinned fingerprint $NVIDIA_KEY_FPR (saw: $(gpg --batch --with-colons --show-keys "$keyfile" | gpg_primary_fprs | paste -sd, -))"
  install -d -m 0755 "$ROOTFS/usr/share/keyrings"
  gpg --batch --yes --dearmor --output "$ROOTFS$NVIDIA_KEYRING" "$keyfile"
  chmod 0644 "$ROOTFS$NVIDIA_KEYRING"
  # What apt will actually trust is the dearmored keyring: verify that too.
  gpg --batch --with-colons --show-keys "$ROOTFS$NVIDIA_KEYRING" | fingerprint_matches "$NVIDIA_KEY_FPR" ||
    die "the installed NVIDIA keyring does not match the pinned fingerprint"
  unset GNUPGHOME
  write_rootfs_file 0644 /etc/apt/sources.list.d/nvidia-container-toolkit.list "$(nvidia_apt_list_content)"
  log "apt-get install (NVIDIA): ${args[*]}"
  apt_update "the Ubuntu archive or NVIDIA's repository ($NVIDIA_APT_URL)"
  chroot_run apt-get install -y --no-install-recommends "${args[@]}"
}

# remove_rootfs_file <absolute-path-inside-rootfs>: deletes one file of the image (a symlink is removed, never followed);
# refuses a path whose directory resolves outside the rootfs.
remove_rootfs_file() {
  local dest="$ROOTFS$1"
  path_within "$ROOTFS" "$(dirname "$dest")" || die "refusing to remove outside the rootfs: $1"
  rm -f -- "$dest"
}

write_configuration() {
  # The Ubuntu .wsl base ships /etc/wsl-distribution.conf with an OOBE `command=/usr/lib/wsl/wsl-setup` and
  # `defaultUid=1000`: the first launch would ask for a user name and create a login user. This distro is an appliance
  # that only ever runs as root with the agent as its only tenant, so the file goes (test-distro.sh checks it is gone).
  remove_rootfs_file /etc/wsl-distribution.conf
  write_rootfs_file 0644 /etc/wsl.conf "$(wsl_conf_content)"
  write_rootfs_file 0644 /etc/containers/containers.conf.d/p2pc.conf "$(containers_conf_content)"
  write_rootfs_file 0644 /etc/subuid "$SUBID_LINE"
  write_rootfs_file 0644 /etc/subgid "$SUBID_LINE"
  install -D -m 0755 -o 0 -g 0 "$SCRIPT_DIR/p2pc-boot" "$ROOTFS/usr/local/sbin/p2pc-boot"
  install -D -m 0755 -o 0 -g 0 "$SCRIPT_DIR/test-distro.sh" "$ROOTFS/usr/local/sbin/p2pc-test-distro"
  # The one definition of "is there an NVIDIA GPU?", sourced by p2pc-boot and p2pc-test-distro.
  install -D -m 0644 -o 0 -g 0 "$SCRIPT_DIR/nvidia.sh" "$ROOTFS/usr/local/lib/p2pc/nvidia.sh"
  # The one definition of "is this boot status from this start of the distro?", sourced by p2pc-boot,
  # p2pc-test-distro and p2pc-run.
  install -D -m 0644 -o 0 -g 0 "$SCRIPT_DIR/boot-status.sh" "$ROOTFS/usr/local/lib/p2pc/boot-status.sh"
  # What the "P2PC node" Scheduled Task runs (install.ps1 -Join): it keeps the agent running, and the hub while it is
  # enabled (H2 §8.5).
  install -D -m 0755 -o 0 -g 0 "$SCRIPT_DIR/p2pc-run" "$ROOTFS/usr/local/sbin/p2pc-run"
  # The old name, kept for one release: tasks registered by an older install.ps1 (and p2pc-wsl's task XML) run it.
  # Relative, so it points inside the image whatever the rootfs path is at build time.
  remove_rootfs_file /usr/local/sbin/p2pc-node-run
  ln -s p2pc-run "$ROOTFS/usr/local/sbin/p2pc-node-run"
  # The agent's identity and state live here (spec 9.0); only root may enter. /var/lib/p2pc-server, the hub's data, is
  # not created here: `p2pc-server init` creates it (0700) on the PC that becomes the hub, and an upgrade compares the
  # listings of both directories before and after, so an empty one in the image would break that comparison.
  install -d -m 0700 -o 0 -g 0 "$ROOTFS/var/lib/p2pc"
  # The agent's config, next to its identity: everything mutable in /var/lib/p2pc, the one directory install.ps1
  # -Upgrade carries over. p2pc-run and install.ps1 name it with P2PC_AGENT_CONFIG. No setting: the built-in
  # defaults (the image never had an /etc/p2pc/agent.toml either); `p2pc-agent join` writes [server] into it.
  write_rootfs_file 0600 /var/lib/p2pc/agent.toml "$(agent_config_content)"
  # p2pc-run's rotated agent.log and hub.log (no journald in the distro).
  install -d -m 0700 -o 0 -g 0 "$ROOTFS/var/log/p2pc"
  write_rootfs_file 0644 /etc/p2pc-distro-version \
    "$(printf 'image_version=%s\nbuild_date=%s\nbase_sha256=%s\narchive=%s%s' "$IMAGE_VERSION" "$(iso8601_utc "$SOURCE_DATE_EPOCH")" "$BASE_SHA256" "$(archive_record "$ARCHIVE" "$SNAPSHOT_TS")" "$(archive_build_time_line)")"
  if [[ -n "$AGENT_PATH" ]]; then
    install -D -m 0755 -o 0 -g 0 "$AGENT_PATH" "$ROOTFS/usr/local/bin/p2pc-agent"
    log "installed the agent (sha256 $(sha256_of "$AGENT_PATH"))"
  fi
  if [[ -n "$SHIM_PATH" ]]; then
    # Next to the agent: that is where its executor looks for it.
    install -D -m 0755 -o 0 -g 0 "$SHIM_PATH" "$ROOTFS/usr/local/bin/p2pc-shim"
    log "installed p2pc-shim (sha256 $(sha256_of "$SHIM_PATH"))"
  fi
  if [[ -n "$SERVER_PATH" ]]; then
    # The hub (H2 §8.5). p2pc-run starts it only while /var/lib/p2pc-server/hub.enabled exists.
    install -D -m 0755 -o 0 -g 0 "$SERVER_PATH" "$ROOTFS/usr/local/bin/p2pc-server"
    log "installed p2pc-server (sha256 $(sha256_of "$SERVER_PATH"))"
  fi
  if [[ -n "$SERVER_DOC_DIR" ]]; then
    # p2pc-server is AGPL-3.0-only: its license, and the README that says where its source is, go with the binary.
    install -D -m 0644 -o 0 -g 0 "$SERVER_DOC_DIR/LICENSE" "$ROOTFS/usr/local/share/doc/p2pc-server/LICENSE"
    install -D -m 0644 -o 0 -g 0 "$SERVER_DOC_DIR/README" "$ROOTFS/usr/local/share/doc/p2pc-server/README"
  fi
}

# write_manifest <path>: every installed package and its version, sorted, tab separated.
write_manifest() {
  {
    printf '# p2pc-node image %s, built %s\n' "$IMAGE_VERSION" "$(iso8601_utc "$SOURCE_DATE_EPOCH")"
    printf '# base image sha256 %s\n' "$BASE_SHA256"
    printf '# archive=%s\n' "$(archive_record "$ARCHIVE" "$SNAPSHOT_TS")"
    if [[ "$ARCHIVE" == live ]]; then
      printf '# archive_build_time=%s (live archive: not reproducible; the versions below are what was resolved)\n' "$ARCHIVE_BUILD_TIME"
    fi
    if [[ -n "$AGENT_PATH" ]]; then
      printf '# p2pc-agent sha256 %s\n' "$(sha256_of "$AGENT_PATH")"
      [[ -z "$AGENT_FROM" ]] || printf '# p2pc-agent from %s (sha256 %s, verified against SHA256SUMS)\n' "$AGENT_TARBALL" "$AGENT_TARBALL_SHA"
      if [[ -n "$SHIM_PATH" ]]; then
        printf '# p2pc-shim sha256 %s\n' "$(sha256_of "$SHIM_PATH")"
        [[ -z "$AGENT_FROM" ]] || printf '# p2pc-shim from %s (sha256 %s, verified against SHA256SUMS)\n' "$SHIM_TARBALL" "$SHIM_TARBALL_SHA"
      else
        printf '# p2pc-shim not included: this agent takes no lease\n'
      fi
    else
      printf '# p2pc-agent not included\n'
    fi
    if [[ -n "$SERVER_PATH" ]]; then
      printf '# p2pc-server sha256 %s\n' "$(sha256_of "$SERVER_PATH")"
      [[ -z "$AGENT_FROM" ]] || printf '# p2pc-server from %s (sha256 %s, verified against SHA256SUMS)\n' "$SERVER_TARBALL" "$SERVER_TARBALL_SHA"
    else
      printf '# p2pc-server not included: this image cannot be a hub\n'
    fi
    printf '# package<TAB>version\n'
    # shellcheck disable=SC2016  # dpkg-query expands ${Package}/${Version} itself
    chroot_run dpkg-query -W -f='${Package}\t${Version}\n' | LC_ALL=C sort
  } >"$1"
}

# update_lock: pin every bare entry of packages.lock to the version that got installed.
update_lock() {
  local resolved="$WORK/resolved.tsv" name version
  : >"$resolved"
  # Every Ubuntu package was installed bare (newest in the new snapshot); NVIDIA's are re-pinned only if they were bare.
  while IFS=$'\t' read -r name version; do
    [[ -n "$name" ]] || continue
    if lock_is_nvidia "$name" && [[ -n "$version" ]]; then continue; fi
    # shellcheck disable=SC2016  # dpkg-query expands ${Version} itself
    printf '%s\t%s\n' "$name" "$(chroot_run dpkg-query -W -f='${Version}' "$name")" >>"$resolved"
  done <<<"$LOCK_ENTRIES"
  lock_pin_versions "$LOCK_FILE" "$resolved" "$SNAPSHOT_TS" >"$WORK/packages.lock.new"
  lock_parse "$WORK/packages.lock.new" >/dev/null || die "internal error: the regenerated lock file is invalid"
  [[ "$(lock_snapshot "$WORK/packages.lock.new")" == "$SNAPSHOT_TS" ]] || die "internal error: the snapshot line was not updated"
  cat "$WORK/packages.lock.new" >"$LOCK_FILE"
  log "rewrote $LOCK_FILE (snapshot $SNAPSHOT_TS); review and commit it"
}

# The cleanup runs inside the chroot, so symlinks in the image can never point a delete at the build host.
clean_rootfs() {
  restore_apt_sources
  chroot_run /bin/sh -eu -c '
    rm -f /usr/sbin/policy-rc.d /etc/resolv.conf
    find /var/lib/apt/lists /var/cache/apt /var/cache/debconf -mindepth 1 -type f -delete 2>/dev/null || true
    rm -f /var/lib/dpkg/*-old /var/cache/ldconfig/aux-cache /var/lib/systemd/random-seed
    : > /etc/machine-id
    [ -L /var/lib/dbus/machine-id ] || rm -f /var/lib/dbus/machine-id
    rm -f /etc/ssh/ssh_host_*
    find /var/log -type f -delete
    find /tmp /var/tmp -mindepth 1 -delete
    rm -rf /root/.cache
    rm -f /root/.bash_history /root/.lesshst /root/.viminfo /root/.python_history
    find /home -maxdepth 2 \( -name .bash_history -o -name .lesshst -o -name .viminfo \) -delete 2>/dev/null || true
  '
}

pack() {
  local name="p2pc-node-$IMAGE_VERSION" tarball hash
  local -a targs=()
  mapfile -t targs < <(tar_deterministic_args "$SOURCE_DATE_EPOCH")
  assert_unmounted "tar"
  tarball="$WORK/$name.tar.gz"
  tar -C "$ROOTFS" "${targs[@]}" -cf - . | gzip -n -9 >"$tarball"
  hash="$(sha256_of "$tarball")"
  printf '%s  %s.tar.gz\n' "$hash" "$name" >"$WORK/$name.tar.gz.sha256"
  mkdir -p -- "$OUT_DIR"
  install -m 0644 "$tarball" "$OUT_DIR/$name.tar.gz"
  install -m 0644 "$WORK/$name.tar.gz.sha256" "$OUT_DIR/$name.tar.gz.sha256"
  install -m 0644 "$WORK/manifest.txt" "$OUT_DIR/manifest.txt"
  log "wrote $OUT_DIR/$name.tar.gz (sha256 $hash)"
}

# agent_plan_line: the "agent binary" line of the plan.
agent_plan_line() {
  if [[ -n "$AGENT_FROM" ]]; then
    printf '%s/%s (sha256 %s, verified against %s/SHA256SUMS)' "$AGENT_FROM" "$AGENT_TARBALL" "$AGENT_TARBALL_SHA" "$AGENT_FROM"
  elif [[ -n "$AGENT_PATH" ]]; then
    printf '%s (--agent: a developer build, not checked against a release)' "$AGENT_PATH"
  else
    printf 'none (the image builds without it; the documented build passes --agent-from)'
  fi
}

# shim_plan_line: the "job shim" line of the plan.
shim_plan_line() {
  if [[ -n "$AGENT_FROM" ]]; then
    printf '%s/%s (sha256 %s, verified against %s/SHA256SUMS) -> /usr/local/bin/p2pc-shim' "$AGENT_FROM" "$SHIM_TARBALL" "$SHIM_TARBALL_SHA" "$AGENT_FROM"
  elif [[ -n "$SHIM_PATH" ]]; then
    printf '%s (--shim: a developer build) -> /usr/local/bin/p2pc-shim' "$SHIM_PATH"
  else
    printf 'none (without p2pc-shim next to it the agent takes no lease)'
  fi
}

# server_plan_line: the "hub server" line of the plan.
server_plan_line() {
  if [[ -n "$AGENT_FROM" ]]; then
    printf '%s/%s (sha256 %s, verified against %s/SHA256SUMS) -> /usr/local/bin/p2pc-server' "$AGENT_FROM" "$SERVER_TARBALL" "$SERVER_TARBALL_SHA" "$AGENT_FROM"
  elif [[ -n "$SERVER_PATH" ]]; then
    printf '%s (--server: a developer build) -> /usr/local/bin/p2pc-server' "$SERVER_PATH"
  else
    printf 'none (this image cannot be a hub)'
  fi
}

# extract_from_dist <tarball> <sha256> <binary>: copies one verified tarball into the work dir, checks it again there
# (nothing can swap it between the check and the read), and prints the path of the binary taken out of it.
extract_from_dist() {
  local tarball="$1" sha="$2" bin="$3" stem="${1%.tar.gz}" copy="$WORK/agent/$1" path
  mkdir -p "$WORK/agent/x"
  cp -- "$AGENT_FROM/$tarball" "$copy"
  verify_sha256 "$copy" "$sha" || die "$tarball changed while it was being copied"
  tar -xzf "$copy" -C "$WORK/agent/x" "$stem/$bin" || die "$tarball has no $stem/$bin"
  path="$WORK/agent/x/$stem/$bin"
  [[ -f "$path" && ! -L "$path" ]] || die "$stem/$bin in $tarball is not a regular file"
  is_elf "$path" || die "$stem/$bin in $tarball is not an ELF executable"
  log "$bin comes from $AGENT_FROM/$tarball (sha256 $sha, verified against SHA256SUMS)"
  printf '%s\n' "$path"
}

# extract_server_doc <server tarball>: LICENSE and README of p2pc-server, from the work-dir copy that extract_from_dist
# already checked; prints the directory that holds them.
extract_server_doc() {
  local stem="${1%.tar.gz}" dir="$WORK/agent/doc" f
  mkdir -p "$dir"
  tar -xzf "$WORK/agent/$1" -C "$dir" "$stem/LICENSE" "$stem/README" || die "$1 has no $stem/LICENSE or $stem/README"
  for f in LICENSE README; do
    [[ -f "$dir/$stem/$f" && ! -L "$dir/$stem/$f" ]] || die "$stem/$f in $1 is not a regular file"
  done
  printf '%s\n' "$dir/$stem"
}

# extract_dist_agent: the agent (AGENT_PATH) and, when their tarballs are known, p2pc-shim (SHIM_PATH) and p2pc-server
# (SERVER_PATH, with its license in SERVER_DOC_DIR) from the dist.
extract_dist_agent() {
  AGENT_PATH="$(extract_from_dist "$AGENT_TARBALL" "$AGENT_TARBALL_SHA" p2pc-agent)" || exit 1
  if [[ -n "${SHIM_TARBALL:-}" ]]; then
    SHIM_PATH="$(extract_from_dist "$SHIM_TARBALL" "$SHIM_TARBALL_SHA" p2pc-shim)" || exit 1
  fi
  if [[ -n "${SERVER_TARBALL:-}" ]]; then
    SERVER_PATH="$(extract_from_dist "$SERVER_TARBALL" "$SERVER_TARBALL_SHA" p2pc-server)" || exit 1
    SERVER_DOC_DIR="$(extract_server_doc "$SERVER_TARBALL")" || exit 1
  fi
}

# ---------------------------------------------------------------------------------------------------------------
main() {
  set -euo pipefail
  IMAGE_VERSION="$DEFAULT_IMAGE_VERSION"
  OUT_DIR="$SCRIPT_DIR/out"
  AGENT_PATH=""
  AGENT_FROM=""
  AGENT_VERSION=""
  AGENT_TARBALL=""
  AGENT_TARBALL_SHA=""
  SHIM_PATH=""
  SHIM_TARBALL=""
  SHIM_TARBALL_SHA=""
  SERVER_PATH=""
  SERVER_TARBALL=""
  SERVER_TARBALL_SHA=""
  SERVER_DOC_DIR=""
  BASE_IMAGE_FILE=""
  local dry_run=0
  UPDATE_LOCK=0
  ARCHIVE=snapshot
  ARCHIVE_BUILD_TIME=""
  while (($# > 0)); do
    case "$1" in
      --dry-run) dry_run=1 ;;
      --update-lock) UPDATE_LOCK=1 ;;
      --archive)
        (($# >= 2)) || {
          usage >&2
          die "--archive needs a value (snapshot or live)"
        }
        ARCHIVE="$(parse_archive_mode "$2")" || die "invalid --archive '$2' (expected snapshot or live; there is no automatic fallback)"
        shift
        ;;
      --out | --version | --agent | --shim | --server | --agent-from | --agent-version | --base-image)
        (($# >= 2)) || {
          usage >&2
          die "$1 needs a value"
        }
        case "$1" in
          --out) OUT_DIR="$2" ;;
          --version) IMAGE_VERSION="$2" ;;
          --agent) AGENT_PATH="$2" ;;
          --shim) SHIM_PATH="$2" ;;
          --server) SERVER_PATH="$2" ;;
          --agent-from) AGENT_FROM="$2" ;;
          --agent-version) AGENT_VERSION="$2" ;;
          --base-image) BASE_IMAGE_FILE="$2" ;;
        esac
        shift
        ;;
      -h | --help)
        usage
        return 0
        ;;
      *)
        usage >&2
        die "unknown option: $1"
        ;;
    esac
    shift
  done

  is_valid_version "$IMAGE_VERSION" || die "invalid --version '$IMAGE_VERSION' (expected MAJOR.MINOR.PATCH)"
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(default_source_date_epoch "$SCRIPT_DIR")}"
  [[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be an integer"
  LOCK_ENTRIES="$(lock_parse "$LOCK_FILE")" || die "invalid $LOCK_FILE"
  SNAPSHOT_TS="$(lock_snapshot "$LOCK_FILE")" || die "invalid $LOCK_FILE"
  # --update-lock moves the snapshot to now; the lock file is rewritten with it at the end of the build.
  if [[ "$ARCHIVE" == live ]] && ((UPDATE_LOCK)); then
    die "--update-lock moves the snapshot, so it cannot be combined with --archive live"
  fi
  if [[ "$ARCHIVE" == live ]]; then ARCHIVE_BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; fi
  if ((UPDATE_LOCK)); then SNAPSHOT_TS="$(date -u +%Y%m%dT%H%M%SZ)"; fi
  if [[ -n "$AGENT_PATH" && -n "$AGENT_FROM" ]]; then
    die "--agent and --agent-from cannot be combined"
  fi
  if [[ -n "$AGENT_VERSION" && -z "$AGENT_FROM" ]]; then
    die "--agent-version only goes with --agent-from"
  fi
  if [[ -n "$SHIM_PATH" && -z "$AGENT_PATH" ]]; then
    die "--shim only goes with --agent (--agent-from takes p2pc-shim from the dist)"
  fi
  if [[ -n "$SERVER_PATH" && -z "$AGENT_PATH" ]]; then
    die "--server only goes with --agent (--agent-from takes p2pc-server from the dist)"
  fi
  if [[ -n "$AGENT_PATH" ]]; then
    [[ -f "$AGENT_PATH" ]] || die "--agent: no such file: $AGENT_PATH"
    is_elf "$AGENT_PATH" || die "--agent: $AGENT_PATH is not an ELF executable"
  fi
  if [[ -n "$SHIM_PATH" ]]; then
    [[ -f "$SHIM_PATH" ]] || die "--shim: no such file: $SHIM_PATH"
    is_elf "$SHIM_PATH" || die "--shim: $SHIM_PATH is not an ELF executable"
  fi
  if [[ -n "$SERVER_PATH" ]]; then
    [[ -f "$SERVER_PATH" ]] || die "--server: no such file: $SERVER_PATH"
    is_elf "$SERVER_PATH" || die "--server: $SERVER_PATH is not an ELF executable"
  fi
  if [[ -n "$AGENT_FROM" ]]; then
    # Checked now, before the plan or the build: reading only, so a dry run does it too.
    [[ -f "$AGENT_FROM/SHA256SUMS" ]] || die "--agent-from: $AGENT_FROM/SHA256SUMS does not exist (pass the dist/<version>/ that scripts/release.sh wrote)"
    AGENT_TARBALL="$(dist_agent_tarball "$AGENT_FROM/SHA256SUMS" "$AGENT_VERSION")" ||
      die "--agent-from: $AGENT_FROM/SHA256SUMS lists no single p2pc-agent for $AGENT_TARGET${AGENT_VERSION:+ at version $AGENT_VERSION} (pass --agent-version when it lists several)"
    AGENT_TARBALL_SHA="$(verified_dist_sum "$AGENT_FROM" "$AGENT_TARBALL")" ||
      die "--agent-from: SHA-256 mismatch (or a missing file) for $AGENT_FROM/$AGENT_TARBALL against SHA256SUMS: refusing to use it"
    SHIM_TARBALL="$(dist_shim_tarball "$AGENT_TARBALL")" || die "internal error: no shim tarball name for $AGENT_TARBALL"
    [[ -n "$(dist_sum "$AGENT_FROM/SHA256SUMS" "$SHIM_TARBALL")" ]] ||
      die "--agent-from: $AGENT_FROM/SHA256SUMS lists no $SHIM_TARBALL: the agent takes no lease without p2pc-shim, so the image would be useless"
    SHIM_TARBALL_SHA="$(verified_dist_sum "$AGENT_FROM" "$SHIM_TARBALL")" ||
      die "--agent-from: SHA-256 mismatch (or a missing file) for $AGENT_FROM/$SHIM_TARBALL against SHA256SUMS: refusing to use it"
    SERVER_TARBALL="$(dist_server_tarball "$AGENT_TARBALL")" || die "internal error: no server tarball name for $AGENT_TARBALL"
    [[ -n "$(dist_sum "$AGENT_FROM/SHA256SUMS" "$SERVER_TARBALL")" ]] ||
      die "--agent-from: $AGENT_FROM/SHA256SUMS lists no $SERVER_TARBALL: the image carries the hub (H2 spec 8.5), so it needs p2pc-server"
    SERVER_TARBALL_SHA="$(verified_dist_sum "$AGENT_FROM" "$SERVER_TARBALL")" ||
      die "--agent-from: SHA-256 mismatch (or a missing file) for $AGENT_FROM/$SERVER_TARBALL against SHA256SUMS: refusing to use it"
  fi

  if ((dry_run)); then
    print_plan
    return 0
  fi
  if [[ "$ARCHIVE" == live ]]; then live_warning >&2; fi

  [[ $EUID -eq 0 ]] || die "run as root (it needs chroot and mount); use --dry-run to see the plan without root"
  if [[ -n "$(lock_unpinned <<<"$LOCK_ENTRIES")" ]] && ((!UPDATE_LOCK)); then
    die "packages.lock has unpinned entries ($(lock_unpinned <<<"$LOCK_ENTRIES" | paste -sd, -)); run once with --update-lock and commit the result"
  fi
  require_tools

  MOUNTED=()
  local tmpbase
  tmpbase="$(realpath -e -- "${TMPDIR:-/var/tmp}")" || die "TMPDIR (${TMPDIR:-/var/tmp}) does not exist"
  valid_work_path "$tmpbase" || die "TMPDIR ($tmpbase) must be an absolute path without whitespace or backslashes"
  WORK="$(mktemp -d "$tmpbase/p2pc-rootfs.XXXXXX")"
  trap cleanup EXIT
  # The canonical path, because that is what /proc/self/mountinfo shows (a trailing slash or a symlink in TMPDIR
  # would otherwise make the mount checks compare different strings).
  WORK="$(realpath -e -- "$WORK")"
  valid_work_path "$WORK" || die "work directory $WORK must not contain whitespace or backslashes"
  ROOTFS="$WORK/rootfs"
  trap 'exit 130' INT TERM
  log "work directory: $WORK"
  if [[ -n "$AGENT_FROM" ]]; then
    extract_dist_agent
  fi

  fetch_base_image
  unpack_base
  mount_chroot
  prepare_chroot
  install_ubuntu_packages
  install_nvidia_packages
  write_configuration
  write_manifest "$WORK/manifest.txt"
  ((!UPDATE_LOCK)) || update_lock
  clean_rootfs
  unmount_chroot
  pack
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
