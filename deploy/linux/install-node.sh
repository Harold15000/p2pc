#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# install-node.sh: joins a native Linux machine to a P2PC server as a node, in one command (spec §9.0 "Linux host",
# §14 AC-1: "Join a node: <= 2 min, one command"). The agent runs as the unprivileged user p2pc, with rootless Podman,
# as a systemd USER unit that starts at boot (linger) and survives reboots.
#
#   sudo sh install-node.sh --from <dir|https-url> [--version V] [--force]     then paste the join token when asked
#   sudo sh install-node.sh --from <dir> < token-file                          the token on stdin instead
#   sudo sh install-node.sh --uninstall [--purge [--yes]]
#
# --from is a release directory (the dist/<version>/ that scripts/release.sh writes) or an https URL with the same
# files: SHA256SUMS, p2pc-agent-<version>-<target>.tar.gz, setup-host.sh and p2pc-agent.service. Every file is checked
# against SHA256SUMS before anything is used.
#
# THE JOIN TOKEN never passes through this script: it is never read into a variable, never put in an argv, a log or a
# file. `p2pc-agent join -` reads it itself, from this script's stdin: with a hidden prompt on a terminal, or to the
# end of a pipe or a file. The script moves its stdin to fd 3 first and runs everything else with stdin from
# /dev/null, so nothing else can consume it.
#
# What it does (idempotent: rerun it to upgrade, with --version):
#   1. checks what it needs, one requirement at a time (root, a running systemd, systemctl, runuser, useradd,
#      sha256sum, tar, bash, curl or wget, and the architecture) and names the one that is missing. The distribution's
#      name is not a requirement: an untested one only gets a warning (spec §9.0 "Which Linux"). Then it verifies the
#      release;
#   2. runs the release's setup-host.sh (the p2pc user, subuid/subgid, linger, the cgroup delegation check, Podman
#      >= 4.9 and crun, CDI with an NVIDIA GPU). If the host is not ready it stops here, with setup-host.sh's fixes
#      printed above, before anything of the agent is installed or enrolled;
#   3. installs p2pc-agent and p2pc-shim (the job helper the agent needs next to it) into /usr/local/bin (0755, root),
#      and the user unit /etc/systemd/user/p2pc-agent.service;
#   4. unless the node is already enrolled (then only with --force): runs, as p2pc,
#        runuser -u p2pc -- sh -c 'cd / && exec "$@"' sh env -i ... p2pc-agent join -   (join --force - with --force)
#   5. enables the unit for p2pc (systemctl --user -M p2pc@ enable p2pc-agent) and starts it, or restarts it when the
#      binary, the unit or the enrollment changed; then waits (at most 60 s) for the agent to connect;
#   6. prints doctor's summary, the status line and "Joined: <node> on <server>". A doctor that says NOT READY is a
#      warning next to it (the join worked: the exit code stays 0). Every p2pc-agent command runs from /.
# --uninstall stops and disables the unit and removes it and the binary; the identity and the enrollment are kept.
# --purge (with --uninstall) also deletes the agent's own config and identity, and nothing else: the user p2pc, its
# Podman storage and what setup-host.sh did stay (see deploy/README.md). It deletes nothing while the agent runs.
#
# Logs: the agent logs to p2pc's user journal:  sudo journalctl _UID=$(id -u p2pc) _SYSTEMD_USER_UNIT=p2pc-agent.service
# Exit codes: 0 done, 1 failed or refused, 2 usage error.
# P2PC_INSTALL_ROOT (tests only) prefixes every path the script touches, so the tests can run it without root.

set -eu
umask 077

# Where releases will be published. A placeholder until publishing is decided: until then, pass --from.
DEFAULT_RELEASES_URL="https://example.invalid/p2pc/releases"

ROOT="${P2PC_INSTALL_ROOT:-}"
AGENT_USER="p2pc"
UNIT="p2pc-agent"
HOME_SYSTEM="/var/lib/p2pc"
AGENT_HOME="$ROOT$HOME_SYSTEM"
# The agent's own paths for a non-root user (crates/p2pc-agent/src/config.rs: ~/.config/p2pc-agent/agent.toml and the
# data dir ~/.local/share/p2pc-agent, which holds the identity key). --purge deletes these two and nothing else.
AGENT_CONFIG_DIR="$AGENT_HOME/.config/p2pc-agent"
AGENT_DATA_DIR="$AGENT_HOME/.local/share/p2pc-agent"
BIN_DIR="$ROOT/usr/local/bin"
USER_UNIT_DIR="$ROOT/etc/systemd/user"
UNIT_FILE="$USER_UNIT_DIR/$UNIT.service"
LOG_FILE="$ROOT/var/log/p2pc-node-install.log"
# os-release(5): /etc/os-release, else /usr/lib/os-release (a minimal image can have only the second).
OS_RELEASE="$ROOT/etc/os-release"
[ -r "$OS_RELEASE" ] || OS_RELEASE="$ROOT/usr/lib/os-release"
SYSTEMD_RUNTIME="$ROOT/run/systemd/system"
CONNECT_TIMEOUT_S=60
# The agent's log, from p2pc's user journal. Not `journalctl --user -M p2pc@`: that needs systemd-machined, which a plain
# Ubuntu 24.04 with Podman does not have ("org.freedesktop.machine1 was not provided": T14b2 real run). Set once the
# uid of p2pc is known (journal_cmd).
JOURNAL_CMD="journalctl _UID=<uid of p2pc> _SYSTEMD_USER_UNIT=$UNIT.service"

FROM=""
VERSION=""
FORCE=0
UNINSTALL=0
PURGE=0
ASSUME_YES=0
WORKDIR=""
CHANGED=0
JOINED_NOW=0
LOG_READY=0
AGENT_UID=""
# 1 while join --force has stopped a running unit and nothing has started it again yet: a signal then starts it first.
stopped_for_join=0

# ---------------------------------------------------------------------------------------------------------------
# Output (the same style as install-server.sh). The log gets only these lines, never the agent's own output.
# ---------------------------------------------------------------------------------------------------------------
# The installer's own stdin waits on fd 3 for `p2pc-agent join` (see main). The helpers that run commands close it
# for them (the `3<&-` after a function body), so no command but the join can ever read it (review 4 P3-3).
log_line() {
  if [ "$LOG_READY" = 1 ] && [ -f "$LOG_FILE" ] && [ ! -L "$LOG_FILE" ]; then
    { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$LOG_FILE"; } 2>/dev/null || true
  fi
} 3<&-

# open_log: a regular 0600 file; anything else at that path is replaced by a new log renamed into place (never
# followed through a symlink). A real directory there is refused.
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
    new_log="$(mktemp "$log_dir/.p2pc-node-install.log.XXXXXX")" || die "cannot create a log in $log_dir"
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
usage_error() {
  printf 'error: %s\n' "$*" >&2
  usage >&2
  exit 2
}

usage() {
  cat <<'USAGE'
Usage:
  sudo sh install-node.sh --from <dir|https-url> [--version V] [--force]
  sudo sh install-node.sh --uninstall [--purge [--yes]]

  --from DIR|URL   a release directory (dist/<version>/ from scripts/release.sh) or an https URL with the same files
  --version V      the version to install (default: the only one listed in SHA256SUMS); rerun with a newer one to
                   upgrade
  --force          enroll again even if this machine is already enrolled: re-enrolls this machine, as the same
                   node (spec 5). To retire a machine instead, remove it on the server with p2pc machines rm
  --uninstall      stop and remove the agent's unit and binary; keep its identity and enrollment
  --purge          with --uninstall: also delete the agent's config and identity (it must join again)
  --yes            with --purge: do not ask for confirmation
  -h, --help       this text

The join token is never an argument: paste it when the agent asks (hidden input), or give it on stdin:
  sudo sh install-node.sh --from DIR < token-file
USAGE
}

cleanup() {
  if [ -n "$WORKDIR" ]; then
    rm -rf "$WORKDIR"
  fi
} 3<&-

# on_signal: INT, TERM or HUP (Ctrl-C at the token prompt, a closed terminal). If join --force stopped the running unit
# and nothing has started it yet, start it again on the previous enrollment before leaving: the node must not be left
# offline (T14b2 review 5 P3). The trap is set in main; user_ctl closes fd 3 for itself.
on_signal() {
  if [ "$stopped_for_join" = 1 ]; then
    stopped_for_join=0
    if user_ctl start "$UNIT" >/dev/null 2>&1; then
      warn "interrupted: $UNIT was started again on the previous enrollment"
    else
      warn "interrupted, and $UNIT could not be started again: see  $JOURNAL_CMD -n 50"
    fi
  fi
  exit 130
}

# ---------------------------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------------------------
target_for_arch() {
  case "$1" in
    x86_64 | amd64) echo "x86_64-unknown-linux-musl" ;;
    aarch64 | arm64) echo "aarch64-unknown-linux-musl" ;;
    *) return 1 ;;
  esac
}

# valid_version <v>: what a version may look like in a file name; the same rule for --version and SHA256SUMS.
valid_version() {
  printf '%s\n' "$1" | grep -Eqx '[0-9A-Za-z.+-]+'
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
} 3<&-

# expected_sum <name>: the SHA-256 that SHA256SUMS lists for a file name (an exact match, never a prefix).
expected_sum() {
  awk -v f="$1" '{ n = $2; sub(/^\*/, "", n) } n == f && $1 ~ /^[0-9a-f]+$/ && length($1) == 64 { print $1; exit }' \
    "$WORKDIR/SHA256SUMS"
}

fetch_verified() {
  want="$(expected_sum "$1")"
  [ -n "$want" ] || die "$1 is not listed in SHA256SUMS: refusing to use it"
  fetch "$1" "$WORKDIR/$1"
  got="$(sha256sum "$WORKDIR/$1" | cut -d ' ' -f 1)"
  [ "$got" = "$want" ] || die "checksum mismatch for $1 (expected $want, got $got): refusing to install"
}

# pick_version: --version, or the only p2pc-agent version SHA256SUMS lists for this target, checked like --version.
pick_version() {
  if [ -z "$VERSION" ]; then
    versions="$(awk '{ n = $2; sub(/^\*/, "", n); print n }' "$WORKDIR/SHA256SUMS" |
      sed -n "s/^p2pc-agent-\(.*\)-$TARGET\.tar\.gz\$/\1/p" | sort -u)"
    count="$(printf '%s' "$versions" | grep -c . || true)"
    [ "$count" -ge 1 ] || die "SHA256SUMS lists no p2pc-agent for $TARGET"
    [ "$count" -eq 1 ] || die "SHA256SUMS lists several versions ($(echo "$versions" | tr '\n' ' ')): pass --version"
    VERSION="$versions"
  fi
  valid_version "$VERSION" || die "the version in SHA256SUMS does not look like a version: $VERSION"
}

# install_file <src> <dest> <mode>: atomic replace, owned by root. 0 (and CHANGED=1) when the content changed, 1
# when it was already in place. Every step is checked here: callers use it in `if`, where set -e does not apply.
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

# as_agent <args...>: p2pc-agent as p2pc, with a clean environment (HOME decides where its config and identity are;
# XDG_RUNTIME_DIR is what rootless Podman needs). Its stdin is /dev/null (see main) unless the caller says otherwise:
# only `join` is given the real one, as its stdin (`as_agent join - <&3`). fd 3 itself is always closed for it.
# P2PC_AGENT_SUPERVISED=1 (T10e): this installer starts the agent, so `join` ends with "The installer starts the agent."
# instead of telling the owner to run `p2pc-agent run`. The other subcommands ignore it.
# It always starts in / (T14f): runuser keeps the caller's working directory, and when p2pc cannot enter it (the
# caller's 0700 home) rootless Podman fails with "cannot chdir" and doctor reports a false NOT READY.
as_agent() {
  runuser -u "$AGENT_USER" -- sh -c 'cd / && exec "$@"' sh \
    env -i PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME="$AGENT_HOME" \
    XDG_RUNTIME_DIR="/run/user/$AGENT_UID" LANG=C.UTF-8 P2PC_AGENT_SUPERVISED=1 "$BIN_DIR/p2pc-agent" "$@"
} 3<&-

# user_ctl <args...>: p2pc's own service manager (it runs from boot thanks to linger).
user_ctl() {
  systemctl --user -M "$AGENT_USER@" "$@"
} 3<&-

# agent_status: `p2pc-agent status` (local files only, no network); empty when it cannot run.
agent_status() {
  as_agent status 2>/dev/null || true
}

# passwd_home: p2pc's home directory, from the passwd database.
passwd_home() {
  getent passwd "$AGENT_USER" 2>/dev/null | cut -d: -f6
}

# check_agent_home: the agent under the unit runs with p2pc's home from the passwd database, so the enrollment (and a
# purge) must use that same directory. This installer and setup-host.sh use /var/lib/p2pc; any other home is refused
# rather than guessed (review P3-2).
check_agent_home() {
  home="$(passwd_home)"
  [ "$home" = "$HOME_SYSTEM" ] ||
    die "the user $AGENT_USER has the home ${home:-(none)}, not $HOME_SYSTEM: the agent under the unit would look for its enrollment there. Set its home to $HOME_SYSTEM, then rerun"
}

# journal_cmd: JOURNAL_CMD with p2pc's uid, once it is known.
journal_cmd() {
  JOURNAL_CMD="journalctl _UID=$AGENT_UID _SYSTEMD_USER_UNIT=$UNIT.service"
}

# status_field <status text> <label>: the value after "<label>:" on its line.
status_field() {
  printf '%s\n' "$1" | sed -n "s/^$2:[[:space:]]*//p" | head -n 1
}

# ---------------------------------------------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------------------------------------------
check_root_and_systemd() {
  [ "$(id -u)" = 0 ] || die "run this as root: sudo sh $0 ..."
  [ -d "$SYSTEMD_RUNTIME" ] ||
    die "systemd is not running on this machine (no $SYSTEMD_RUNTIME): the agent runs as a systemd user service"
  command -v systemctl >/dev/null 2>&1 ||
    die "systemctl is missing: install systemd with your package manager (the agent is a systemd user service)"
}

# os_field <KEY>: the value of KEY in os-release, without quotes. The file is read, never sourced.
os_field() {
  sed -n "s/^$1=//p" "$OS_RELEASE" | head -n 1 | tr -d '"'"'"
}

# The platforms the installers are tested on (spec §9.0 "Which Linux"). Any other Linux that meets every requirement
# gets one warning and the install goes on. The same text is in install-server.sh: keep the two in step.
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
# and in the log. Never a refusal.
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
    os_name="unknown"
  else
    os_name="${id_:-unknown} ${ver:-unknown}"
  fi
  if ! tested_platform "$id_" "$ver" "$id_like"; then
    warn "$os_name is not a tested platform (tested: $TESTED_PLATFORMS); every requirement is met, so the install goes on"
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
  require_tool bash bash
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    die "neither curl nor wget is installed: install one with your package manager (for example \`apt-get install curl\`, \`dnf install curl\` or \`pacman -S curl\`)"
  fi
  warn_if_untested
}

fetch_release() {
  step "Release: $FROM"
  fetch SHA256SUMS "$WORKDIR/SHA256SUMS"
  pick_version
  # The agent and p2pc-shim, the helper that runs inside every job: the agent's executor takes no lease unless
  # p2pc-shim sits next to it, so a release without it is refused.
  for bin in p2pc-agent p2pc-shim; do
    tarball="$bin-$VERSION-$TARGET.tar.gz"
    [ -n "$(expected_sum "$tarball")" ] || die "$tarball is not in SHA256SUMS: no $bin $VERSION for $TARGET in $FROM"
  done
  for f in "p2pc-agent-$VERSION-$TARGET.tar.gz" "p2pc-shim-$VERSION-$TARGET.tar.gz" setup-host.sh "$UNIT.service"; do
    fetch_verified "$f"
  done
  say "    verified against SHA256SUMS: p2pc-agent, p2pc-shim, setup-host.sh and $UNIT.service ($VERSION, $TARGET)"
  mkdir "$WORKDIR/x"
  for bin in p2pc-agent p2pc-shim; do
    stem="$bin-$VERSION-$TARGET"
    tar -xzf "$WORKDIR/$stem.tar.gz" -C "$WORKDIR/x" "$stem/$bin" || die "$stem.tar.gz has no $stem/$bin"
    if [ -L "$WORKDIR/x/$stem/$bin" ] || [ ! -f "$WORKDIR/x/$stem/$bin" ]; then
      die "$stem/$bin in $stem.tar.gz is not a regular file"
    fi
  done
  AGENT_BIN="$WORKDIR/x/p2pc-agent-$VERSION-$TARGET/p2pc-agent"
  SHIM_BIN="$WORKDIR/x/p2pc-shim-$VERSION-$TARGET/p2pc-shim"
}

# setup_host: the release's own setup-host.sh (verified above), run as root. Its report goes straight to the
# terminal; its exit code decides. Nothing of the agent is installed on a host that is not ready.
setup_host() {
  step "Host setup (setup-host.sh)"
  rc=0
  bash "$WORKDIR/setup-host.sh" 3<&- || rc=$?
  case "$rc" in
    0) say "    the host is ready" ;;
    *) die "this host is not ready for a node (setup-host.sh exit $rc): fix the [TODO] items above, then rerun this command. Nothing was enrolled." ;;
  esac
  AGENT_UID="$(id -u "$AGENT_USER" 2>/dev/null)" || die "setup-host.sh reported ready but the user $AGENT_USER does not exist"
  check_agent_home
  journal_cmd
}

install_agent() {
  step "Agent in ${BIN_DIR:-/usr/local/bin} and the user unit $UNIT_FILE"
  (umask 022 && mkdir -p "$BIN_DIR" "$USER_UNIT_DIR")
  # p2pc-shim next to the agent: that is where the agent's executor looks for it.
  for pair in "$AGENT_BIN:p2pc-agent" "$SHIM_BIN:p2pc-shim"; do
    if install_file "${pair%:*}" "$BIN_DIR/${pair##*:}" 0755; then
      say "    installed ${pair##*:} $VERSION"
    else
      say "    ${pair##*:} $VERSION already installed"
    fi
  done
  if install_file "$WORKDIR/$UNIT.service" "$UNIT_FILE" 0644; then
    say "    installed $UNIT.service"
  else
    say "    $UNIT.service unchanged"
  fi
  # p2pc's user manager runs because of linger; start it in case linger was enabled just now.
  systemctl start "user@$AGENT_UID.service" || die "cannot start the user manager of $AGENT_USER (user@$AGENT_UID.service): is linger enabled? see setup-host.sh"
  user_ctl daemon-reload || die "systemctl --user -M $AGENT_USER@ daemon-reload failed: is the user manager of $AGENT_USER running? (loginctl show-user $AGENT_USER)"
}

# join: the only step that runs with fd 3 open (see main), and only the agent's join gets it, as its stdin. Everything
# else in it runs inside `{ ...; } 3<&-`.
join() {
  NEED_JOIN=1
  {
    step "Enrollment"
    status="$(agent_status)"
    if [ "$(status_field "$status" Enrolled | cut -c1-3)" = "yes" ]; then
      if [ "$FORCE" = 0 ]; then
        say "    already enrolled $(status_field "$status" Enrolled | sed 's/^yes //') (rerun with --force to re-enroll this machine, the same node)"
        NEED_JOIN=0
      else
        say "    already enrolled; --force: re-enrolling this machine (the same node)"
      fi
    fi
    # A running agent must not keep the old enrollment while the new one is written (review 4 P3-2, as on Windows): it
    # is stopped first, and started again on the old one if the join fails.
    if [ "$NEED_JOIN" = 1 ] && [ "$FORCE" = 1 ] && [ -e "$UNIT_FILE" ] && user_ctl is-active --quiet "$UNIT"; then
      # The flag goes up before the stop: the stop can take a minute while the agent drains, and a Ctrl-C then kills
      # only the systemctl client, while systemd still finishes the stop (T14b3 review P3 1).
      stopped_for_join=1
      user_ctl stop "$UNIT" || {
        stopped_for_join=0
        die "systemctl --user -M $AGENT_USER@ stop $UNIT failed: nothing was enrolled"
      }
    fi
  } 3<&-
  [ "$NEED_JOIN" = 1 ] || return 0
  if [ -t 3 ]; then
    say "    paste the join token from \`p2pc join-token create\` (the input is hidden)" 3<&-
  fi
  log_line "running p2pc-agent join as $AGENT_USER (the token goes from stdin to the agent only)"
  rc=0
  # The one command that gets this script's stdin (fd 3, see main): the agent reads the token from it, prompting on a
  # terminal. fd 3 itself is closed for it, so it sees the token once, on stdin only.
  if [ "$FORCE" = 1 ]; then
    as_agent join --force - <&3 3<&- || rc=$?
  else
    as_agent join - <&3 3<&- || rc=$?
  fi
  {
    if [ "$rc" != 0 ] && [ "$stopped_for_join" = 1 ]; then
      stopped_for_join=0
      if user_ctl start "$UNIT"; then
        warn "the enrollment failed: $UNIT was started again on the previous enrollment"
      else
        warn "the enrollment failed, and $UNIT could not be started again: see  $JOURNAL_CMD -n 50"
      fi
    fi
    case "$rc" in
      0) ;;
      3) die "the agent says this machine is already enrolled: rerun with --force to re-enroll it (the same node)" ;;
      4) die "the server refused the token, or it is not a join token (exit 4): create a new one with p2pc join-token create and paste it when asked (or give it on stdin)" ;;
      5) die "the join token has expired (exit 5): create a new one with p2pc join-token create" ;;
      6) die "the server refuses this agent version (exit 6): install a newer release" ;;
      *) die "p2pc-agent join failed (exit $rc, see the message above). With no terminal, give the token on stdin; on a terminal, paste it when asked" ;;
    esac
  } 3<&-
  JOINED_NOW=1
  log_line "p2pc-agent join done"
}

start_agent() {
  step "Service $UNIT (user $AGENT_USER)"
  user_ctl enable "$UNIT" || die "systemctl --user -M $AGENT_USER@ enable $UNIT failed"
  # A unit that stopped on a terminal code, or crash-looped into start-limit-hit, must be able to start again.
  user_ctl reset-failed "$UNIT" 2>/dev/null || true
  # Only a connection made since this (re)start counts (review P3-1): the agent's state file can still say "connected"
  # from before. A unit that already runs and is not restarted keeps its agent, and its connection is current.
  NOT_BEFORE=""
  if [ "$CHANGED" = 1 ] || [ "$JOINED_NOW" = 1 ] || ! user_ctl is-active --quiet "$UNIT"; then
    NOT_BEFORE="$(date +%s)"
  fi
  if [ "$CHANGED" = 1 ] || [ "$JOINED_NOW" = 1 ]; then
    user_ctl restart "$UNIT" || die "systemctl --user -M $AGENT_USER@ restart $UNIT failed: see  $JOURNAL_CMD -n 50"
    stopped_for_join=0
    say "    restart requested"
  else
    user_ctl start "$UNIT" || die "systemctl --user -M $AGENT_USER@ start $UNIT failed: see  $JOURNAL_CMD -n 50"
    stopped_for_join=0
    say "    start requested"
  fi
}

# die_not_running: the unit stopped after the start; say why, from the agent's exit status (review P3-8).
die_not_running() {
  code="$(user_ctl show -p ExecMainStatus --value "$UNIT" 2>/dev/null || true)"
  case "$code" in
    7) hint=": the server says this machine is not enrolled any more (it was removed). Enroll it again with a new token from p2pc join-token create:  sudo sh install-node.sh --from <dist dir> --force" ;;
    6) hint=": the server refuses this agent version. Install a newer release:  sudo sh install-node.sh --from <newer dist dir>" ;;
    8) hint=": this machine is not enrolled. Rerun the install and paste a token" ;;
    *) hint="" ;;
  esac
  die "$UNIT is not running (it exited after the start, exit ${code:-?})$hint. See  $JOURNAL_CMD -n 50"
}

# connected_since_ok <Connection field>: "connected (since T)", and T not before NOT_BEFORE (when set). Same clock: the
# agent writes T on this machine.
connected_since_ok() {
  case "$1" in
    connected*) ;;
    *) return 1 ;;
  esac
  [ -n "$NOT_BEFORE" ] || return 0
  since="$(printf '%s\n' "$1" | sed -n 's/^connected (since \([^)]*\)).*/\1/p')"
  [ -n "$since" ] || return 1
  since_s="$(date -u -d "$since" +%s 2>/dev/null)" || return 1
  [ "$since_s" -ge "$NOT_BEFORE" ]
}

# wait_connected: the agent must stay up; it should connect within CONNECT_TIMEOUT_S. Still connecting after that is
# a warning: the agent keeps trying by itself (the server or the relay may be briefly unreachable).
wait_connected() {
  deadline=$(($(date +%s) + CONNECT_TIMEOUT_S))
  while :; do
    user_ctl is-active --quiet "$UNIT" || die_not_running
    STATUS_TEXT="$(agent_status)"
    if connected_since_ok "$(status_field "$STATUS_TEXT" Connection)"; then
      # The state the unit ends in, said only now that it is known (a start that is followed by an exit is not "running").
      say "    running, connected"
      return 0
    fi
    [ "$(date +%s)" -lt "$deadline" ] || break
    sleep 2
  done
  say "    running, not connected yet"
  warn "the agent is running but not connected since the start, after ${CONNECT_TIMEOUT_S}s ($(status_field "$STATUS_TEXT" Connection)); it keeps trying by itself. Follow it with:  $JOURNAL_CMD -f"
}

summary() {
  say ""
  say "P2PC node agent $VERSION runs as $AGENT_USER (rootless Podman), from boot."
  doctor_rc=0
  doctor="$(as_agent doctor 2>&1)" || doctor_rc=$?
  printf '%s\n' "$doctor" | sed '/^[[:space:]]*$/d; s/^/  /'
  say "  Connection:    $(status_field "$STATUS_TEXT" Connection)"
  say "  Logs:          $JOURNAL_CMD     Install log: /var/log/p2pc-node-install.log"
  say "  Remove:        sudo sh install-node.sh --uninstall   (keeps the identity; --purge deletes it)"
  node="$(status_field "$STATUS_TEXT" Enrolled | sed -n 's/^yes (node \([^,)]*\).*/\1/p')"
  server="$(status_field "$STATUS_TEXT" 'Server NodeId')"
  if [ "$doctor_rc" != 0 ]; then
    # The join itself worked (the exit code stays 0): only the sandbox check is not satisfied.
    warn "this node is enrolled but the sandbox is NOT READY (doctor exit $doctor_rc, see above). It will not run jobs until it is fixed: apply the fixes doctor lists, then check with  sudo runuser -u $AGENT_USER -- sh -c 'cd / && exec p2pc-agent doctor'"
  fi
  say "Joined: ${node:-?} on ${server:-?}"
}

# agent_stopped: the unit is stopped (ActiveState inactive, failed or empty, and no main process) and no p2pc-agent
# of p2pc runs outside it either (someone may have started `p2pc-agent run` by hand).
agent_stopped() {
  if [ -n "$AGENT_UID" ]; then
    state="$(user_ctl show -p ActiveState --value "$UNIT" 2>/dev/null || true)"
    main_pid="$(user_ctl show -p MainPID --value "$UNIT" 2>/dev/null || true)"
    case "$state" in
      inactive | failed | "") ;;
      *) return 1 ;;
    esac
    case "$main_pid" in
      0 | "") ;;
      *) return 1 ;;
    esac
    if command -v pgrep >/dev/null 2>&1 && pgrep -u "$AGENT_USER" -x p2pc-agent >/dev/null 2>&1; then
      state="a p2pc-agent process of $AGENT_USER outside the unit"
      return 1
    fi
  fi
  return 0
}

# configured_data_dir: the data_dir agent.toml sets, when it is not the default (purge never deletes it). The file is
# read as p2pc (it is p2pc's file), and without the agent binary, which an earlier --uninstall has removed.
configured_data_dir() {
  d="$(runuser -u "$AGENT_USER" -- sed -n 's/^[[:space:]]*data_dir[[:space:]]*=[[:space:]]*"\(.*\)"[[:space:]]*$/\1/p' \
    "$AGENT_CONFIG_DIR/agent.toml" 2>/dev/null | head -n 1)" || d=""
  if [ -n "$d" ] && [ "$d" != "$AGENT_DATA_DIR" ]; then
    echo "$d"
  fi
}

# confirm_purge: --purge asks first (a shell read from fd 3, the installer's stdin; no command runs meanwhile).
confirm_purge() {
  if [ "$PURGE" = 1 ] && [ "$ASSUME_YES" = 0 ]; then
    printf 'This deletes the agent identity and enrollment (%s and %s): the machine must join again.\n' \
      "$HOME_SYSTEM/.config/p2pc-agent" "$HOME_SYSTEM/.local/share/p2pc-agent"
    printf 'Type "purge" to confirm: '
    answer=""
    read -r answer <&3 || true
    [ "$answer" = "purge" ] || die "not confirmed: nothing was changed"
  fi
}

uninstall() {
  step "Uninstall $UNIT"
  AGENT_UID="$(id -u "$AGENT_USER" 2>/dev/null)" || AGENT_UID=""
  if [ "$PURGE" = 1 ] && [ -n "$AGENT_UID" ]; then
    # Purge deletes paths in p2pc's home: only the home the agent really uses (review P3-2).
    check_agent_home
  fi
  # Only while the unit is installed: after an earlier --uninstall there is nothing to disable, and the call would only
  # warn (T14b2 real run: --purge right after --uninstall).
  if [ -n "$AGENT_UID" ] && [ -e "$UNIT_FILE" ]; then
    user_ctl disable --now "$UNIT" >/dev/null 2>&1 || warn "systemctl --user -M $AGENT_USER@ disable --now $UNIT failed (is the user manager running?)"
  fi
  state=""
  if ! agent_stopped; then
    [ "$PURGE" = 0 ] ||
      die "the agent is still running (${state:-?}): nothing was deleted (stop it, then rerun)"
    warn "the agent is still running (${state:-?})"
  fi
  # Report only what this run removes: a second --uninstall (or --purge after it) finds them gone.
  removed=""
  for pair in "$UNIT_FILE:/etc/systemd/user/$UNIT.service" "$BIN_DIR/p2pc-agent:/usr/local/bin/p2pc-agent" \
    "$BIN_DIR/p2pc-shim:/usr/local/bin/p2pc-shim"; do
    if [ -e "${pair%%:*}" ] || [ -L "${pair%%:*}" ]; then
      rm -f "${pair%%:*}"
      removed="$removed${removed:+, }${pair#*:}"
    fi
  done
  if [ -n "$AGENT_UID" ]; then
    user_ctl daemon-reload >/dev/null 2>&1 || true
    user_ctl reset-failed "$UNIT" >/dev/null 2>&1 || true
  fi
  if [ -n "$removed" ]; then
    # "a, b, c" reads "a, b and c".
    last="${removed##*, }"
    case "$removed" in
      *", "*) removed="${removed%, *} and $last" ;;
    esac
    say "    removed $removed"
  else
    say "    nothing to remove: the unit and the binaries were already gone"
  fi
  if [ "$PURGE" = 0 ]; then
    say "    kept the identity and enrollment in $HOME_SYSTEM (rerun with --uninstall --purge to delete them)"
    return 0
  fi
  if [ -z "$AGENT_UID" ]; then
    say "    there is no user $AGENT_USER: $HOME_SYSTEM was not touched"
    return 0
  fi
  other="$(configured_data_dir)"
  # As p2pc, never as root: a symlink inside p2pc's home cannot point the deletion anywhere p2pc cannot write.
  runuser -u "$AGENT_USER" -- rm -rf --one-file-system -- "$AGENT_CONFIG_DIR" "$AGENT_DATA_DIR" ||
    die "could not delete $AGENT_CONFIG_DIR and $AGENT_DATA_DIR"
  if [ -n "$other" ]; then
    warn "agent.toml set data_dir = $other: that directory was NOT deleted (it is not one of the agent's default paths); delete it yourself if it holds nothing else"
  fi
  say "    deleted $HOME_SYSTEM/.config/p2pc-agent and $HOME_SYSTEM/.local/share/p2pc-agent (the identity)"
  say "    kept the user $AGENT_USER, its Podman storage and the host setup; to remove them too:  userdel -r $AGENT_USER  (see deploy/README.md)"
}

main() {
  # A join token is never an argument (it would sit in argv, `ps` and the shell history). One that was given anyway is
  # refused before anything else, before the log is opened, and never echoed (review P3-1).
  for arg in "$@"; do
    case "$arg" in
      *p2pc_join_*)
        printf 'error: an argument holds a join token (not shown, and nothing was written). Never put it on the command line: run this without it and paste the token when asked, or give it on stdin.\n' >&2
        exit 2
        ;;
    esac
  done
  args="$*"
  while [ $# -gt 0 ]; do
    case "$1" in
      --from)
        [ $# -ge 2 ] || usage_error "--from needs a value"
        FROM="$2"
        shift
        ;;
      --version)
        [ $# -ge 2 ] || usage_error "--version needs a value"
        VERSION="$2"
        shift
        ;;
      --force) FORCE=1 ;;
      --uninstall) UNINSTALL=1 ;;
      --purge) PURGE=1 ;;
      --yes) ASSUME_YES=1 ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) usage_error "unknown option (not shown: it could be a secret); see --help" ;;
    esac
    shift
  done
  if [ "$PURGE" = 1 ] && [ "$UNINSTALL" = 0 ]; then
    usage_error "--purge only goes with --uninstall"
  fi
  if [ "$UNINSTALL" = 1 ] && { [ -n "$FROM" ] || [ -n "$VERSION" ] || [ "$FORCE" = 1 ]; }; then
    usage_error "--uninstall takes no --from, --version or --force"
  fi
  if [ -n "$VERSION" ] && ! valid_version "$VERSION"; then
    die "--version must look like 0.1.0, got: $VERSION"
  fi
  # The caller's stdin (a terminal, or the piped token) moves to fd 3, and stdin becomes /dev/null for the whole run:
  # no command can consume the token by accident. Only `p2pc-agent join` (and the purge confirmation, a shell read)
  # read fd 3. Every other step runs with fd 3 closed (`{ ...; } 3<&-`), and it is closed for good right after the join
  # (review 4 P3-3): no child of this script but the join ever inherits it.
  exec 3<&0 </dev/null

  {
    check_root_and_systemd
    open_log
    log_line "install-node.sh $args"
  } 3<&-
  if [ "$UNINSTALL" = 1 ]; then
    confirm_purge
    exec 3<&-
    uninstall
    return 0
  fi

  {
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

    WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/p2pc-node-install.XXXXXX")"
    trap cleanup EXIT
    trap on_signal INT TERM HUP

    fetch_release
    setup_host
    install_agent
  } 3<&-
  join
  exec 3<&-
  start_agent
  wait_connected
  summary
}

main "$@"
