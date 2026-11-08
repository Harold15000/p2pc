#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# install-server.sh: installs the P2PC control plane (p2pc-server) as a hardened systemd service, in one command
# (spec §2 U1 and §14 AC-1). Any Linux with systemd, on x86_64 or aarch64 (spec §9.0 "Which Linux"). Tested on
# Ubuntu 22.04, 24.04 and 26.04, Debian 12 and 13, and Arch Linux; any other distribution gets one warning, never a
# refusal.
#
#   sudo sh install-server.sh --from <dir|https-url> [--version X] [--listen 127.0.0.1:7477]
#                         [--admin-key-file PATH]
#   sudo sh install-server.sh --uninstall [--purge [--yes]]
#
# --from is a release directory (the dist/<version>/ that scripts/release.sh writes) or an https URL with the same
# files: SHA256SUMS, p2pc-server-<version>-<target>.tar.gz, p2pc-<version>-<target>.tar.gz and p2pc-server.service.
# Every file is checked against SHA256SUMS before anything is installed.
#
# What it does (idempotent: rerun it to upgrade, with --version):
#   1. checks what it needs, one requirement at a time (root, a running systemd, systemctl, runuser, useradd,
#      sha256sum, tar, curl or wget, and the architecture) and names the one that is missing. The distribution's name
#      is not a requirement: an untested one only gets a warning;
#   2. installs p2pc-server and p2pc to /usr/local/bin (0755, root);
#   3. creates the system user p2pc-server (no login shell);
#   4. installs /etc/systemd/system/p2pc-server.service and runs daemon-reload. Before starting it, it checks that
#      this host can run the service with its own user namespace (PrivateUsers=yes): many containers cannot (an
#      unprivileged LXC, a Podman or Docker container with systemd), often only in combination with the rest of the
#      unit's sandbox. So the check is the installed unit itself: a temporary oneshot unit in /run/systemd/system made
#      of the unit's own [Service] settings, running `p2pc-server --version`, started through systemctl (as root it
#      needs no D-Bus). Probe A is the unit as installed; probe B is the same plus PrivateUsers=no.
#        A passes: no drop-in (an old one is removed).
#        A fails with 217/USER or 226/NAMESPACE (read with systemctl show before the probe is cleaned up), B passes:
#          the drop-in p2pc-server.service.d/10-container.conf with PrivateUsers=no, and a note.
#        A fails with another status (a slow daemon-reload, the timeout, an OOM): A is retried once; still failing for
#          another reason, PrivateUsers=yes stays, with a warning. One failed probe never turns the hardening off.
#        A and B both fail: PrivateUsers is not the cause; nothing changes, and the health wait reports the real error;
#   5. only if /var/lib/p2pc-server holds no server yet: runs `p2pc-server init` as p2pc-server, outside systemd.
#      The admin key it prints goes straight to this script's stdout (your terminal) and nowhere else: not to the
#      journal, not to the install log, not to argv or the environment of another process;
#   6. systemctl reset-failed (a rerun after a crash loop must recover), systemctl enable --now p2pc-server, then
#      waits (at most 30 s) for GET /healthz;
#   7. prints a summary.
# --uninstall stops and disables the service and removes the unit, its drop-ins and the binaries. It keeps the data
# dir and the user unless --purge is given, which asks for a typed confirmation (or takes --yes). A purge deletes
# nothing while the service is still active after `systemctl stop`, whether or not its unit file is still there.
#
# Exit codes: 0 done, 1 failed or refused, 2 usage error.
# P2PC_INSTALL_ROOT (tests only) prefixes every path the script touches, so the tests can run it without root.

set -eu
umask 077

# Where releases will be published. A placeholder until publishing is decided: until then, pass --from.
DEFAULT_RELEASES_URL="https://example.invalid/p2pc/releases"

ROOT="${P2PC_INSTALL_ROOT:-}"
SERVICE="p2pc-server"
SERVICE_USER="p2pc-server"
DATA_DIR_SYSTEM="/var/lib/p2pc-server"
DATA_DIR="$ROOT$DATA_DIR_SYSTEM"
BIN_DIR="$ROOT/usr/local/bin"
UNIT_DIR="$ROOT/etc/systemd/system"
UNIT_FILE="$UNIT_DIR/$SERVICE.service"
DROPIN_DIR="$UNIT_FILE.d"
CONTAINER_DROPIN="$DROPIN_DIR/10-container.conf"
LOG_FILE="$ROOT/var/log/p2pc-server-install.log"
# os-release(5): /etc/os-release, else /usr/lib/os-release (a minimal image can have only the second).
OS_RELEASE="$ROOT/etc/os-release"
[ -r "$OS_RELEASE" ] || OS_RELEASE="$ROOT/usr/lib/os-release"
SYSTEMD_RUNTIME="$ROOT/run/systemd/system"
PROBE_UNIT_NAME="p2pc-server-probe.service"
PROBE_UNIT="$SYSTEMD_RUNTIME/$PROBE_UNIT_NAME"
DEFAULT_LISTEN="127.0.0.1:7477"
HEALTH_TIMEOUT_S=30
BINARIES="p2pc-server p2pc"

FROM=""
VERSION=""
LISTEN=""
KEY_FILE=""
KEY_FILE_SET=0
UNINSTALL=0
PURGE=0
ASSUME_YES=0
WORKDIR=""
KEY_TMP=""
CHANGED=0
LOG_READY=0
PROBE_ACTIVE=0
PRIVATE_USERS_OFF=0
NO_USERNS_NOTE="this host cannot give the service its own user namespace (container?): PrivateUsers is off"

# ---------------------------------------------------------------------------------------------------------------
# Output. The log never receives the output of `p2pc-server init`: only these lines.
# ---------------------------------------------------------------------------------------------------------------
log_line() {
  # Only once open_log has checked the path, and never through a symlink swapped in since.
  if [ "$LOG_READY" = 1 ] && [ -f "$LOG_FILE" ] && [ ! -L "$LOG_FILE" ]; then
    { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$LOG_FILE"; } 2>/dev/null || true
  fi
}

# open_log: the install log is a regular 0600 file. When the path is anything else, a new log is created with mktemp
# in the same directory, made 0600, and renamed into place: the rename replaces a symlink without following it (-T:
# never into the directory a symlink points to), so nothing can be redirected between a check and the open. A real
# directory at that path is refused.
open_log() {
  log_dir="$(dirname "$LOG_FILE")"
  [ -d "$log_dir" ] || return 0
  if [ -f "$LOG_FILE" ] && [ ! -L "$LOG_FILE" ]; then
    chmod 0600 "$LOG_FILE"
  else
    if [ -d "$LOG_FILE" ] && [ ! -L "$LOG_FILE" ]; then
      die "$LOG_FILE exists and is not a regular file: move it away and rerun"
    fi
    if [ -L "$LOG_FILE" ] || [ -e "$LOG_FILE" ]; then
      warn "$LOG_FILE was not a regular file (a symlink?): replaced by a new log"
    fi
    new_log="$(mktemp "$log_dir/.p2pc-server-install.log.XXXXXX")" || die "cannot create a log in $log_dir"
    if ! { chmod 0600 "$new_log" && mv -fT "$new_log" "$LOG_FILE"; }; then
      rm -f "$new_log"
      die "cannot put the install log in place at $LOG_FILE"
    fi
  fi
  LOG_READY=1
}
say() {
  printf '%s\n' "$*"
  log_line "$*"
}
step() { say "==> $*"; }
warn() {
  printf 'warning: %s\n' "$*" >&2
  log_line "warning: $*"
}
die() {
  printf 'error: %s\n' "$*" >&2
  log_line "error: $*"
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  sudo sh install-server.sh --from <dir|https-url> [--version X] [--listen ADDR]
                           [--admin-key-file PATH]
  sudo sh install-server.sh --uninstall [--purge [--yes]]

  --from DIR|URL   a release directory (dist/<version>/ from scripts/release.sh) or an https URL with the same files
  --version X      the version to install (default: the only one listed in SHA256SUMS); rerun with a newer one to
                   upgrade
  --listen ADDR    REST listen address, IP:PORT or [IPv6]:PORT (default 127.0.0.1:7477). Used by the first install
                   only; later, edit bind in /var/lib/p2pc-server/server.toml
  --admin-key-file PATH
                   for a scripted install with no terminal: write the admin key to PATH (created new, mode 0600; refused
                   if PATH exists) and print it nowhere else. First install only
  --uninstall      stop and remove the service, the unit and the binaries; keep the data and the user
  --purge          with --uninstall: also delete /var/lib/p2pc-server (database, keys, artifacts) and the user
  --yes            with --purge: do not ask for confirmation
  -h, --help       this text
USAGE
}

cleanup() {
  if [ "$PROBE_ACTIVE" = 1 ]; then
    probe_cleanup
  fi
  if [ -n "$WORKDIR" ]; then
    rm -rf "$WORKDIR"
  fi
  # A signal while the temporary admin key file exists must not leave the key on disk.
  if [ -n "$KEY_TMP" ]; then
    rm -f "$KEY_TMP"
  fi
}

# ---------------------------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------------------------

# os_field <KEY>: the value of KEY in os-release, without quotes. The file is read, never sourced.
os_field() {
  sed -n "s/^$1=//p" "$OS_RELEASE" | head -n 1 | tr -d '"'"'"
}

# target_for_arch <uname -m>: the Rust target of the release tarballs.
target_for_arch() {
  case "$1" in
    x86_64 | amd64) echo "x86_64-unknown-linux-musl" ;;
    aarch64 | arm64) echo "aarch64-unknown-linux-musl" ;;
    *) return 1 ;;
  esac
}

# valid_listen <addr>: IPv4:port or [IPv6]:port, digits only in the port. The server parses it again.
valid_listen() {
  printf '%s\n' "$1" | grep -Eqx '([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}|\[[0-9A-Fa-f:.]+\]:[0-9]{1,5}'
}

# probe_url <bind>: the /healthz URL for a bind address. A wildcard bind is probed on loopback.
probe_url() {
  host="${1%:*}"
  port="${1##*:}"
  case "$host" in
    0.0.0.0) host="127.0.0.1" ;;
    "[::]") host="[::1]" ;;
  esac
  echo "http://$host:$port/healthz"
}

is_loopback() {
  case "${1%:*}" in
    127.* | "[::1]") return 0 ;;
    *) return 1 ;;
  esac
}

# http_ok <url>: one probe, 2 s at most, never through a proxy.
http_ok() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --noproxy '*' --max-time 2 -o /dev/null "$1" >/dev/null 2>&1
  else
    wget -q --no-proxy -T 2 -t 1 -O /dev/null "$1" >/dev/null 2>&1
  fi
}

# fetch <name> <dest>: copy or download one release file.
fetch() {
  case "$FROM" in
    https://*)
      url="${FROM%/}/$1"
      if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto =https --proto-redir =https --tlsv1.2 --retry 3 --connect-timeout 10 --max-time 600 \
          -o "$2" "$url" || die "cannot download $url"
      else
        wget -q --https-only --max-redirect=0 -T 30 -t 3 -O "$2" "$url" || die "cannot download $url"
      fi
      ;;
    *)
      [ -f "$FROM/$1" ] || die "$FROM/$1 does not exist"
      cp "$FROM/$1" "$2"
      ;;
  esac
}

# expected_sum <name>: the SHA-256 that SHA256SUMS lists for a file name (an exact match, never a prefix).
expected_sum() {
  awk -v f="$1" '{ n = $2; sub(/^\*/, "", n) } n == f && $1 ~ /^[0-9a-f]+$/ && length($1) == 64 { print $1; exit }' \
    "$WORKDIR/SHA256SUMS"
}

# fetch_verified <name>: fetch a file into the work dir and check it against SHA256SUMS.
fetch_verified() {
  want="$(expected_sum "$1")"
  [ -n "$want" ] || die "$1 is not listed in SHA256SUMS: refusing to install it"
  fetch "$1" "$WORKDIR/$1"
  got="$(sha256sum "$WORKDIR/$1" | cut -d ' ' -f 1)"
  [ "$got" = "$want" ] || die "checksum mismatch for $1 (expected $want, got $got): refusing to install"
}

# pick_version: --version, or the only p2pc-server version that SHA256SUMS lists for this target.
pick_version() {
  if [ -n "$VERSION" ]; then
    return 0
  fi
  versions="$(awk '{ n = $2; sub(/^\*/, "", n); print n }' "$WORKDIR/SHA256SUMS" |
    sed -n "s/^p2pc-server-\(.*\)-$TARGET\.tar\.gz\$/\1/p" | sort -u)"
  count="$(printf '%s' "$versions" | grep -c . || true)"
  [ "$count" -ge 1 ] || die "SHA256SUMS lists no p2pc-server for $TARGET"
  [ "$count" -eq 1 ] || die "SHA256SUMS lists several versions ($(echo "$versions" | tr '\n' ' ')): pass --version"
  VERSION="$versions"
  # The same check as on --version: the version ends up in file names and paths.
  printf '%s\n' "$VERSION" | grep -Eqx '[0-9A-Za-z.+-]+' ||
    die "the version in SHA256SUMS does not look like a version: $VERSION"
}

# install_file <src> <dest> <mode>: atomic replace, owned by root. Returns 0 and sets CHANGED when the content
# changed, 1 when it was already in place. Callers use it in `if`, where `set -e` does not apply: every step is
# checked here.
install_file() {
  if [ -f "$2" ] && cmp -s "$1" "$2"; then
    chmod "$3" "$2" || die "cannot chmod $3 $2"
    chown root:root "$2" || die "cannot chown root:root $2"
    return 1
  fi
  tmp="$(dirname "$2")/.$(basename "$2").new.$$"
  if ! { cp "$1" "$tmp" && chmod "$3" "$tmp" && chown root:root "$tmp" && mv -f "$tmp" "$2"; }; then
    rm -f "$tmp"
    die "cannot install $2"
  fi
  CHANGED=1
  return 0
}

# as_service_user <args...>: run p2pc-server as the service user, with a clean environment. Nothing secret is ever
# passed in argv or the environment: the admin key only comes OUT of `init`, on its stdout.
as_service_user() {
  runuser -u "$SERVICE_USER" -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$DATA_DIR" \
    P2PC_DATA_DIR="$DATA_DIR" "$BIN_DIR/p2pc-server" "$@"
}

# configured_bind: the `bind` in server.toml, read as root.
configured_bind() {
  sed -n 's/^bind = "\(.*\)"$/\1/p' "$DATA_DIR/server.toml" 2>/dev/null | head -n 1
}

# ---------------------------------------------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------------------------------------------
check_root_and_systemd() {
  [ "$(id -u)" = 0 ] || die "run this as root: sudo sh $0 ..."
  [ -d "$SYSTEMD_RUNTIME" ] ||
    die "systemd is not running on this machine (no $SYSTEMD_RUNTIME): the server is installed as a systemd service"
  command -v systemctl >/dev/null 2>&1 ||
    die "systemctl is missing: install systemd with your package manager (the server is a systemd service)"
}

# The platforms the installers are tested on (spec §9.0 "Which Linux"). Any other Linux that meets every requirement
# gets one warning and the install goes on. The same text is in install-node.sh: keep the two in step.
TESTED_PLATFORMS="Ubuntu 22.04, 24.04, 26.04; Debian 12, 13; Arch Linux"

# tested_platform <id> <version_id> <id_like>: succeeds for a tested platform. Arch Linux is any ID=arch, or a
# distribution whose ID_LIKE lists arch (Omarchy, Manjaro, EndeavourOS...), at any version: it is rolling.
tested_platform() {
  case "$1 $2" in
    "ubuntu 22.04" | "ubuntu 24.04" | "ubuntu 26.04" | "debian 12" | "debian 13" | "arch "*) return 0 ;;
  esac
  case " $3 " in
    *" arch "*) return 0 ;;
  esac
  return 1
}

# warn_if_untested: after every requirement is met, one warning line for a platform that is not a tested one, on stderr
# and in the log. Never a refusal. Sets OS_NAME.
warn_if_untested() {
  id_=""
  ver=""
  id_like=""
  if [ -r "$OS_RELEASE" ]; then
    id_="$(os_field ID)"
    ver="$(os_field VERSION_ID)"
    id_like="$(os_field ID_LIKE)"
  fi
  if [ -z "$id_" ] && [ -z "$ver" ]; then
    OS_NAME="unknown"
  else
    OS_NAME="${id_:-unknown} ${ver:-unknown}"
  fi
  if ! tested_platform "$id_" "$ver" "$id_like"; then
    warn "$OS_NAME is not a tested platform (tested: $TESTED_PLATFORMS); every requirement is met, so the install goes on"
  fi
}

# require_tool <name> <package that provides it>: one requirement at a time, and the error names the one that is missing.
require_tool() {
  command -v "$1" >/dev/null 2>&1 ||
    die "$1 is missing: install it with your package manager (it comes with $2)"
}

check_platform() {
  arch="$(uname -m)"
  TARGET="$(target_for_arch "$arch")" || die "unsupported architecture: $arch (supported: x86_64, aarch64)"
  require_tool runuser util-linux
  require_tool useradd "shadow, or passwd on Debian and Ubuntu"
  require_tool sha256sum coreutils
  require_tool tar tar
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    die "neither curl nor wget is installed: install one with your package manager (for example \`apt-get install curl\`, \`dnf install curl\` or \`pacman -S curl\`)"
  fi
  warn_if_untested
}

fetch_release() {
  step "Release: $FROM"
  fetch SHA256SUMS "$WORKDIR/SHA256SUMS"
  pick_version
  for bin in $BINARIES; do
    tarball="$bin-$VERSION-$TARGET.tar.gz"
    [ -n "$(expected_sum "$tarball")" ] ||
      die "$tarball is not in SHA256SUMS: no $bin $VERSION for $TARGET in $FROM"
  done
  for bin in $BINARIES; do
    fetch_verified "$bin-$VERSION-$TARGET.tar.gz"
  done
  fetch_verified "$SERVICE.service"
  say "    verified against SHA256SUMS: $BINARIES and $SERVICE.service ($VERSION, $TARGET)"
  for bin in $BINARIES; do
    stem="$bin-$VERSION-$TARGET"
    mkdir "$WORKDIR/x-$bin"
    tar -xzf "$WORKDIR/$stem.tar.gz" -C "$WORKDIR/x-$bin" "$stem/$bin" || die "$stem.tar.gz has no $stem/$bin"
    if [ -L "$WORKDIR/x-$bin/$stem/$bin" ] || [ ! -f "$WORKDIR/x-$bin/$stem/$bin" ]; then
      die "$stem/$bin in $stem.tar.gz is not a regular file"
    fi
  done
}

install_binaries() {
  step "Binaries in ${BIN_DIR:-/usr/local/bin}"
  (umask 022 && mkdir -p "$BIN_DIR")
  for bin in $BINARIES; do
    if install_file "$WORKDIR/x-$bin/$bin-$VERSION-$TARGET/$bin" "$BIN_DIR/$bin" 0755; then
      say "    installed $bin $VERSION"
    else
      say "    $bin $VERSION already installed"
    fi
  done
}

create_user() {
  step "System user $SERVICE_USER"
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    say "    exists"
  else
    useradd --system --user-group --home-dir "$DATA_DIR_SYSTEM" --no-create-home --shell /usr/sbin/nologin \
      --comment "P2PC control plane" "$SERVICE_USER" || die "useradd $SERVICE_USER failed"
    say "    created (no login shell)"
  fi
}

# probe_cleanup: remove the temporary probe unit and every trace of it. Also run from the EXIT trap.
probe_cleanup() {
  rm -f "$PROBE_UNIT"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed "$PROBE_UNIT_NAME" >/dev/null 2>&1 || true
  PROBE_ACTIVE=0
}

# unit_service_settings: the [Service] settings of the installed unit, in order, without comments and without the
# keys that make it a long-running service (Exec*, Restart*, Type, StateDirectory*, start timeouts). Everything that
# sandboxes it (User, PrivateUsers, Protect*, SystemCallFilter, ...) is kept: that is what the probe must test.
unit_service_settings() {
  awk '
    /^[[:space:]]*\[/ { in_service = ($0 ~ /^[[:space:]]*\[Service\][[:space:]]*$/); next }
    !in_service || /^[[:space:]]*([#;]|$)/ { next }
    {
      key = $0
      sub(/^[[:space:]]+/, "", key)
      sub(/[[:space:]]*=.*$/, "", key)
      if (key ~ /^(Exec[A-Za-z]*|Restart|RestartSec|Type|StateDirectory|StateDirectoryMode|TimeoutStartSec|TimeoutSec)$/) next
      print
    }
  ' "$UNIT_FILE"
}

# PROBE_STATUS: the ExecMainStatus systemd recorded for the last probe that failed (read before the probe unit is reset),
# empty when it passed. 217 (USER) and 226 (NAMESPACE) are what a refused user namespace gives.
PROBE_STATUS=""

# probe_run [extra setting]: start a temporary oneshot unit made of the installed unit's own [Service] settings
# (plus the extra one, e.g. PrivateUsers=no, which overrides the unit's), running the installed binary's --version,
# and succeed if it ran. TimeoutStartSec bounds it inside systemd too. Through systemctl only: as root it talks to
# systemd over its private socket, so hosts without D-Bus (minimal hosts, containers) answer correctly.
probe_run() {
  {
    echo "# Written and removed by install-server.sh: a one-time check, never enabled."
    echo "[Unit]"
    echo "Description=p2pc-server install check"
    echo "[Service]"
    unit_service_settings
    echo "Type=oneshot"
    echo "TimeoutStartSec=30"
    echo "ExecStart=$BIN_DIR/p2pc-server --version"
    if [ -n "${1:-}" ]; then
      echo "$1"
    fi
  } >"$WORKDIR/probe.service" || die "cannot build the probe unit from $UNIT_FILE"
  PROBE_ACTIVE=1
  (umask 022 && mkdir -p "$SYSTEMD_RUNTIME" && cp "$WORKDIR/probe.service" "$PROBE_UNIT") ||
    die "cannot write $PROBE_UNIT"
  probe_rc=0
  PROBE_STATUS=""
  systemctl daemon-reload || probe_rc=1
  if [ "$probe_rc" = 0 ]; then
    timeout 60 systemctl start "$PROBE_UNIT_NAME" >/dev/null 2>&1 || probe_rc=1
  fi
  if [ "$probe_rc" != 0 ]; then
    # Before the cleanup: its reset-failed clears what systemd recorded.
    PROBE_STATUS="$(systemctl show -p ExecMainStatus --value "$PROBE_UNIT_NAME" 2>/dev/null || true)"
  fi
  probe_cleanup
  return "$probe_rc"
}

# userns_status <ExecMainStatus>: the probe was refused its user namespace (217/USER or 226/NAMESPACE).
userns_status() {
  case "$1" in
    217 | 226) return 0 ;;
    *) return 1 ;;
  esac
}

# check_private_users: decide whether this host needs the PrivateUsers=no drop-in (see the header, step 4). One failed
# probe A must not switch the hardening off on a host that supports it (a slow daemon-reload, the 30 s timeout on a
# loaded host, an OOM): B is only tried when A failed with the user-namespace status (217/USER or 226/NAMESPACE).
# Otherwise A is retried once; if it still fails for another reason, PrivateUsers=yes stays, with a warning.
check_private_users() {
  # Probe A: the unit as installed (without our drop-in, which lives in another file).
  a_ok=0
  if probe_run; then
    a_ok=1
  elif ! userns_status "$PROBE_STATUS"; then
    first_status="$PROBE_STATUS"
    if probe_run; then
      a_ok=1
    elif ! userns_status "$PROBE_STATUS"; then
      kept="PrivateUsers=yes"
      if [ -e "$CONTAINER_DROPIN" ]; then
        kept="the existing PrivateUsers=no drop-in"
      fi
      warn "the install check of the service failed twice, with status ${first_status:-?} then ${PROBE_STATUS:-?}: not the user-namespace status (217/USER or 226/NAMESPACE), so it says nothing about PrivateUsers: keeping $kept; if the service does not start, see  journalctl -u $SERVICE -n 50"
      return 0
    fi
  fi
  if [ "$a_ok" = 1 ]; then
    if [ -e "$CONTAINER_DROPIN" ]; then
      rm -f "$CONTAINER_DROPIN"
      rmdir "$DROPIN_DIR" 2>/dev/null || true
      CHANGED=1
      say "    this host can give the service its own user namespace: removed the old PrivateUsers=no drop-in"
    fi
    return 0
  fi
  # Probe B: the same, with PrivateUsers=no.
  if ! probe_run "PrivateUsers=no"; then
    if [ -e "$CONTAINER_DROPIN" ]; then
      warn "on this host the service's sandbox fails even with PrivateUsers=no, so PrivateUsers is not the cause: keeping the existing PrivateUsers=no drop-in; if the service does not start, see  journalctl -u $SERVICE -n 50"
    else
      warn "on this host the service's sandbox fails even with PrivateUsers=no, so PrivateUsers is not the cause: keeping PrivateUsers=yes; if the service does not start, see  journalctl -u $SERVICE -n 50"
    fi
    return 0
  fi
  warn "$NO_USERNS_NOTE"
  {
    echo "# Written by install-server.sh: $NO_USERNS_NOTE."
    echo "# Rerun install-server.sh on a host that can, and it removes this file."
    echo "[Service]"
    echo "PrivateUsers=no"
  } >"$WORKDIR/10-container.conf"
  (umask 022 && mkdir -p "$DROPIN_DIR")
  if install_file "$WORKDIR/10-container.conf" "$CONTAINER_DROPIN" 0644; then
    say "    installed the drop-in $CONTAINER_DROPIN"
  fi
}

# failure_hint: a hint for the exit status systemd recorded for the service, if it is a known one.
failure_hint() {
  case "$(systemctl show -p ExecMainStatus --value "$SERVICE" 2>/dev/null || true)" in
    226) echo " (status 226/NAMESPACE: this host refused the service's mount namespace; in an unprivileged LXC container, turn on nesting, e.g. on Proxmox: the container > Options > Features > nesting=1)" ;;
    217) echo " (status 217/USER: this host cannot run the service as $SERVICE_USER or in its own user namespace)" ;;
    *) echo "" ;;
  esac
}

install_unit() {
  step "Service unit $UNIT_FILE"
  (umask 022 && mkdir -p "$UNIT_DIR")
  if install_file "$WORKDIR/$SERVICE.service" "$UNIT_FILE" 0644; then
    say "    installed"
  else
    say "    unchanged"
  fi
  check_private_users
  if [ -e "$CONTAINER_DROPIN" ]; then
    PRIVATE_USERS_OFF=1
  fi
  systemctl daemon-reload
}

# init_to_key_file: `p2pc-server init` with its stdout kept off this script's output: the admin key line goes only to
# KEY_FILE (new, 0600); the rest of init's stdout (the server address) is shown. init's output is held in a shell
# variable, never in a file, so the only place the key reaches disk is the 0600 temp file next to KEY_FILE that is linked
# into place. stderr (no secret) goes to the terminal as usual.
init_to_key_file() {
  log_line "running p2pc-server init (the admin key goes to $KEY_FILE only)"
  initout="$(as_service_user init --bind "${LISTEN:-$DEFAULT_LISTEN}")" ||
    die "p2pc-server init failed (see the message above)"
  key="$(printf '%s\n' "$initout" | sed -n 's/^ADMIN API KEY (shown once): //p' | head -n 1)"
  if [ -z "$key" ]; then
    initout=""
    die "p2pc-server init printed no admin key: recover one with sudo runuser -u $SERVICE_USER -- env P2PC_DATA_DIR=$DATA_DIR_SYSTEM p2pc-server keys recover"
  fi
  # Written to a fresh mktemp file next to KEY_FILE, then hard-linked into place: ln fails if KEY_FILE exists (a FIFO or a
  # symlink planted there included) and never follows a symlink, so the key is never written through the path itself.
  key_tmp="$(mktemp "$(dirname "$KEY_FILE")/.p2pc-admin-key.XXXXXX")" || key_tmp=""
  KEY_TMP="$key_tmp"
  if [ -z "$key_tmp" ] ||
    ! { chmod 0600 "$key_tmp" && printf '%s\n' "$key" >"$key_tmp" &&
      { [ -z "${SUDO_USER:-}" ] || chown "$SUDO_USER": "$key_tmp"; } && ln "$key_tmp" "$KEY_FILE"; }; then
    [ -z "$key_tmp" ] || rm -f "$key_tmp"
    KEY_TMP=""
    initout=""
    die "cannot create $KEY_FILE (does it exist now?): the server is initialised, so recover a key with sudo runuser -u $SERVICE_USER -- env P2PC_DATA_DIR=$DATA_DIR_SYSTEM p2pc-server keys recover"
  fi
  rm -f "$key_tmp"
  KEY_TMP=""
  key=""
  printf '%s\n' "$initout" | sed '/^ADMIN API KEY/d'
  initout=""
  say ""
  key_url="$(probe_url "${LISTEN:-$DEFAULT_LISTEN}")"
  key_url="${key_url%/healthz}"
  if [ -n "${SUDO_USER:-}" ]; then
    say "The admin key was written to $KEY_FILE (mode 0600, owned by $SUDO_USER). Use it once, then delete it:"
  else
    say "The admin key was written to $KEY_FILE (mode 0600, owned by root). Use it once, then delete it:"
  fi
  say "    p2pc login --server $key_url --key-stdin < $KEY_FILE ; shred -u $KEY_FILE   (rm -f if shred is missing)"
  log_line "p2pc-server init done (key written to $KEY_FILE)"
}

init_server() {
  step "Data dir $DATA_DIR"
  mkdir -p "$DATA_DIR"
  chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
  chmod 0700 "$DATA_DIR"
  if [ -e "$DATA_DIR/server.toml" ] || [ -e "$DATA_DIR/p2pc.db" ]; then
    INITIALISED_NOW=0
    say "    already initialised: the existing server, its data and its keys are kept"
    if [ -n "$KEY_FILE" ]; then
      say "    no admin key was written to $KEY_FILE: the server already exists"
    fi
    say "    (lost every admin key? sudo runuser -u $SERVICE_USER -- env P2PC_DATA_DIR=$DATA_DIR_SYSTEM p2pc-server keys recover)"
    if [ -n "$LISTEN" ] && [ "$LISTEN" != "$(configured_bind)" ]; then
      warn "--listen $LISTEN is ignored on an existing server: the listen address is bind in $DATA_DIR_SYSTEM/server.toml (edit it, then systemctl restart $SERVICE)"
    fi
    return 0
  fi
  INITIALISED_NOW=1
  if [ -n "$KEY_FILE" ]; then
    init_to_key_file
    return 0
  fi
  if [ ! -t 1 ]; then
    warn "stdout is not a terminal: the admin key is written to whatever reads this script's output"
  fi
  log_line "running p2pc-server init (its output goes to the terminal only, never to this log)"
  say ""
  say "The ADMIN API KEY below is shown ONCE. Copy it now into a password manager."
  say "--------------------------------------------------------------------------------"
  # stdout and stderr of init go to the terminal directly, never through say/log_line or a pipe.
  as_service_user init --bind "${LISTEN:-$DEFAULT_LISTEN}" || die "p2pc-server init failed (see the message above)"
  printf '%s\n' "--------------------------------------------------------------------------------"
  log_line "p2pc-server init done"
}

start_service() {
  step "Service $SERVICE"
  # A first install that crash-looped leaves the unit in start-limit-hit, and every start fails until this.
  systemctl reset-failed "$SERVICE" 2>/dev/null || true
  systemctl enable --now "$SERVICE" ||
    die "systemctl enable --now $SERVICE failed$(failure_hint): see  journalctl -u $SERVICE -n 50  and  systemctl status $SERVICE"
  if [ "$CHANGED" = 1 ] && [ "$INITIALISED_NOW" = 0 ]; then
    # New binary or unit on an existing install: run the new one.
    systemctl restart "$SERVICE" || die "systemctl restart $SERVICE failed$(failure_hint): see  journalctl -u $SERVICE -n 50"
    say "    restarted on the new version"
  fi
  BIND="$(configured_bind)"
  if [ -z "$BIND" ]; then
    BIND="${LISTEN:-$DEFAULT_LISTEN}"
    warn "cannot read bind from $DATA_DIR_SYSTEM/server.toml; probing $BIND"
  fi
  url="$(probe_url "$BIND")"
  # A real deadline: a probe that hangs for its whole 2 s counts against the 30 s.
  deadline=$(($(date +%s) + HEALTH_TIMEOUT_S))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if http_ok "$url"; then
      say "    healthy: $url"
      return 0
    fi
    sleep 1
  done
  die "$SERVICE did not answer $url within ${HEALTH_TIMEOUT_S}s$(failure_hint): see  journalctl -u p2pc-server -n 50  and  systemctl status $SERVICE"
}

summary() {
  address="$(as_service_user info 2>/dev/null | sed -n 's/^SERVER ADDRESS: //p' | head -n 1)" || address=""
  say ""
  say "P2PC server $VERSION is running ($OS_NAME, $TARGET)."
  say "  REST API:        http://$BIND  (bind in $DATA_DIR_SYSTEM/server.toml)"
  say "  SERVER ADDRESS: ${address:-unknown (run: sudo runuser -u $SERVICE_USER -- env P2PC_DATA_DIR=$DATA_DIR_SYSTEM p2pc-server info)}"
  say "  Data dir:        $DATA_DIR_SYSTEM (0700, $SERVICE_USER)   Unit: /etc/systemd/system/$SERVICE.service"
  say "  Logs:            journalctl -u $SERVICE     Install log: /var/log/p2pc-server-install.log"
  if [ "$PRIVATE_USERS_OFF" = 1 ]; then
    say "  Note:            $NO_USERNS_NOTE"
  fi
  say ""
  say "Next steps:"
  if [ "$INITIALISED_NOW" = 1 ] && [ -n "$KEY_FILE" ]; then
    say "  1. Log in with the admin key in $KEY_FILE, then delete the file: it is never shown again."
  elif [ "$INITIALISED_NOW" = 1 ]; then
    say "  1. Keep the admin key printed above: it is never shown again."
  else
    say "  1. Use your existing admin key (or create a new one with p2pc-server keys recover, see above)."
  fi
  step_no=2
  if [ "$INITIALISED_NOW" = 1 ] && [ -n "$KEY_FILE" ]; then
    # Step 1 already logs in with the key file: no second, interactive, login step.
    say "     p2pc login --server http://$BIND --key-stdin < $KEY_FILE"
  else
    say "  2. Log in on this machine (it asks for the key):  p2pc login --server http://$BIND"
    step_no=3
  fi
  say "  $step_no. Enroll a machine:  p2pc join-token create, then on that machine run install-node.sh (Linux) or"
  say "     .\\install.ps1 -Join (Windows) and paste the token when asked (see deploy/README.md)"
  say "  Agents and remote clients reach this server through its SERVER ADDRESS, over iroh: no port is opened."
  if ! is_loopback "$BIND"; then
    say ""
    warn "the REST API listens on $BIND, beyond loopback: put a TLS reverse proxy in front of it (spec §10, option A)"
  fi
}

uninstall() {
  if [ "$PURGE" = 1 ] && [ "$ASSUME_YES" = 0 ]; then
    printf 'This deletes %s (the database, every key, all logs and artifacts) and the user %s.\n' \
      "$DATA_DIR_SYSTEM" "$SERVICE_USER"
    printf 'Type "purge" to confirm: '
    answer=""
    read -r answer || true
    [ "$answer" = "purge" ] || die "not confirmed: nothing was changed"
  fi
  step "Uninstall $SERVICE"
  # Stop first, whatever the unit file says (it may have been deleted by hand while the service runs), then check:
  # stopped means ActiveState inactive, failed or empty (unknown unit) AND no main process.
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  state="$(systemctl show -p ActiveState --value "$SERVICE" 2>/dev/null || true)"
  main_pid="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || true)"
  case "$state" in
    inactive | failed | "") stopped=1 ;;
    *) stopped=0 ;;
  esac
  [ "$main_pid" = 0 ] || stopped=0
  if [ "$stopped" = 0 ]; then
    # Never delete the data of a server that may still be running.
    [ "$PURGE" = 0 ] ||
      die "$SERVICE is still active after systemctl stop (ActiveState=${state:-?}, MainPID=${main_pid:-?}): nothing was deleted (stop it, then rerun)"
    warn "$SERVICE is still active after systemctl stop (ActiveState=${state:-?}, MainPID=${main_pid:-?})"
  fi
  if [ -e "$UNIT_FILE" ]; then
    systemctl disable "$SERVICE" || warn "systemctl disable $SERVICE failed"
    rm -f "$UNIT_FILE"
    rm -rf "$DROPIN_DIR"
    systemctl daemon-reload
    systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
    say "    service stopped, disabled and removed"
  else
    rm -rf "$DROPIN_DIR"
    say "    no unit installed"
  fi
  for bin in $BINARIES; do
    rm -f "$BIN_DIR/$bin"
  done
  say "    removed $BINARIES from /usr/local/bin"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$DATA_DIR"
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
      userdel "$SERVICE_USER" || warn "userdel $SERVICE_USER failed"
    fi
    say "    deleted $DATA_DIR_SYSTEM and the user $SERVICE_USER"
  else
    say "    kept $DATA_DIR_SYSTEM and the user $SERVICE_USER (rerun with --uninstall --purge to delete them)"
  fi
}

main() {
  args="$*"
  while [ $# -gt 0 ]; do
    case "$1" in
      --from)
        [ $# -ge 2 ] || { usage >&2; exit 2; }
        FROM="$2"
        shift
        ;;
      --version)
        [ $# -ge 2 ] || { usage >&2; exit 2; }
        VERSION="$2"
        shift
        ;;
      --listen)
        [ $# -ge 2 ] || { usage >&2; exit 2; }
        LISTEN="$2"
        shift
        ;;
      --admin-key-file)
        [ $# -ge 2 ] || { usage >&2; exit 2; }
        KEY_FILE="$2"
        KEY_FILE_SET=1
        shift
        ;;
      --uninstall) UNINSTALL=1 ;;
      --purge) PURGE=1 ;;
      --yes) ASSUME_YES=1 ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        usage >&2
        exit 2
        ;;
    esac
    shift
  done
  if [ "$PURGE" = 1 ] && [ "$UNINSTALL" = 0 ]; then
    die "--purge only goes with --uninstall"
  fi
  if [ "$KEY_FILE_SET" = 1 ]; then
    [ -n "$KEY_FILE" ] || die "--admin-key-file needs a path"
    [ "$UNINSTALL" = 0 ] || die "--admin-key-file does not go with --uninstall"
    # Refused before anything is changed. -e is false for a dangling symlink, so -L is checked too (never followed).
    if [ -e "$KEY_FILE" ] || [ -L "$KEY_FILE" ]; then
      die "$KEY_FILE already exists: --admin-key-file never overwrites. Choose a new path, or remove the file"
    fi
    key_dir="$(dirname "$KEY_FILE")"
    [ -d "$key_dir" ] || die "the directory of $KEY_FILE does not exist"
    # A directory others can write to (without the sticky bit) lets them swap the path between the checks and the write.
    if [ -n "$(find "$key_dir" -maxdepth 0 -perm /022 ! -perm -1000 2>/dev/null)" ]; then
      die "the directory of $KEY_FILE ($key_dir) is writable by group or others without the sticky bit: use a private directory"
    fi
    # The key file is given to SUDO_USER after init has run, when a failure would lose the key: check it now.
    if [ -n "${SUDO_USER:-}" ] && ! id -u "$SUDO_USER" >/dev/null 2>&1; then
      die "SUDO_USER is '$SUDO_USER', which is not a local user, so the key file could not be given to it: run the installer from a login of a real user, or as root with SUDO_USER unset"
    fi
  fi
  if [ -n "$LISTEN" ] && ! valid_listen "$LISTEN"; then
    die "--listen must be IP:PORT or [IPv6]:PORT, got: $LISTEN"
  fi
  if [ -n "$VERSION" ] && ! printf '%s\n' "$VERSION" | grep -Eqx '[0-9A-Za-z.+-]+'; then
    die "--version must look like 0.1.0, got: $VERSION"
  fi

  check_root_and_systemd
  open_log
  log_line "install-server.sh $args"
  if [ "$UNINSTALL" = 1 ]; then
    uninstall
    return 0
  fi

  if [ -z "$FROM" ]; then
    [ -n "$VERSION" ] ||
      die "no release is published yet: pass --from <dist/<version> directory or https URL> (see deploy/README.md)"
    FROM="$DEFAULT_RELEASES_URL/$VERSION"
  fi
  case "$FROM" in
    https://*) ;;
    *://*) die "--from must be a local directory or an https:// URL, got: $FROM" ;;
    *) [ -d "$FROM" ] || die "--from $FROM is not a directory" ;;
  esac
  check_platform

  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/p2pc-install.XXXXXX")"
  trap cleanup EXIT
  trap 'exit 130' INT TERM HUP

  fetch_release
  install_binaries
  create_user
  install_unit
  init_server
  start_service
  summary
}

main "$@"
