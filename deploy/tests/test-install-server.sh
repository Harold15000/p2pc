#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end tests of deploy/linux/install-server.sh with fakes: a PATH of stub system commands (systemctl, useradd,
# userdel, id, runuser, chown, curl, sleep, uname), a scratch root (P2PC_INSTALL_ROOT) and a fake p2pc-server that
# prints a fake admin key. The script runs under `sh` (dash on Debian and Ubuntu), exactly as the docs say.
# The real install needs root and systemd: see "Server on Linux" in deploy/README.md for the run on a real machine.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
make_scratch
installer="$here/../linux/install-server.sh"
unit_src="$here/../linux/p2pc-server.service"
target="x86_64-unknown-linux-musl"

FAKE_KEY="p2pc_sk_fakefakefake_testonlynotarealkeytestonlynotarealkeytestonly" # gitleaks:allow
FAKE_ADDRESS="p2pc_srv_testonlyfakeaddress"

# --- fake system commands ----------------------------------------------------------------------------------------------
fakebin="$SCRATCH/fakebin"
mkdir -p "$fakebin"
cat >"$fakebin/id" <<'FAKE'
#!/bin/sh
# Not recorded in calls: reading ids changes nothing.
if [ "$*" = "-u" ]; then echo "${FAKE_UID:-0}"; exit 0; fi
if [ "$*" = "-u p2pc-server" ] && [ -e "$FAKE_STATE/user" ]; then echo 990; exit 0; fi
if [ "$*" = "-u alice" ]; then echo 1000; exit 0; fi
exit 1
FAKE
cat >"$fakebin/useradd" <<'FAKE'
#!/bin/sh
echo "useradd $*" >>"$FAKE_STATE/calls"
touch "$FAKE_STATE/user"
FAKE
cat >"$fakebin/userdel" <<'FAKE'
#!/bin/sh
echo "userdel $*" >>"$FAKE_STATE/calls"
rm -f "$FAKE_STATE/user"
FAKE
cat >"$fakebin/chown" <<'FAKE'
#!/bin/sh
echo "chown $*" >>"$FAKE_STATE/calls"
# chown-term: the installer gets SIGTERM while it holds the temporary key file (T14g item 3).
case "$*" in *p2pc-admin-key*) [ ! -e "$FAKE_STATE/chown-term" ] || kill -TERM "$PPID" ;; esac
[ ! -e "$FAKE_STATE/chown-fails" ]
FAKE
# A fake clock: `date +%s` reads $FAKE_STATE/clock, and `sleep N` advances it by N without waiting. Any other `date`
# (the log timestamps) is the real one.
cat >"$fakebin/sleep" <<'FAKE'
#!/bin/sh
echo "sleep $*" >>"$FAKE_STATE/calls"
now="$(cat "$FAKE_STATE/clock" 2>/dev/null || echo 1000)"
echo $((now + $1)) >"$FAKE_STATE/clock"
FAKE
cat >"$fakebin/date" <<'FAKE'
#!/bin/sh
if [ "$*" = "+%s" ]; then cat "$FAKE_STATE/clock" 2>/dev/null || echo 1000; else exec /bin/date "$@"; fi
FAKE
cat >"$fakebin/uname" <<'FAKE'
#!/bin/sh
if [ "$*" = "-m" ]; then echo "${FAKE_ARCH:-x86_64}"; else /bin/uname "$@"; fi
FAKE
# systemctl (systemd through its private socket: no D-Bus involved).
#   $FAKE_STATE/start-limit-hit   every start of the service fails until `reset-failed`, as after a crash loop;
#   $FAKE_STATE/stop-fails        `stop` fails and the service stays active;
#   $FAKE_STATE/start-fails       every start or restart of the service fails, even after reset-failed;
#   $FAKE_STATE/restart-fails     only `restart` fails;
#   $FAKE_STATE/no-userns         like the unprivileged container of the architect's rerun: a probe unit fails when
#                                 PrivateUsers=yes is in effect (the LAST PrivateUsers= line) TOGETHER with the
#                                 service's own sandbox (ProtectKernelTunables=yes). A minimal unit with only User= and
#                                 PrivateUsers=yes passes there, which is why the probe must be the real unit;
#   $FAKE_STATE/probe-fails       every probe unit fails, whatever its settings, with the status in
#                                 $FAKE_STATE/probe-fail-status (default 1: not a user-namespace failure);
#   $FAKE_STATE/probe-flaky       holds a count: that many probe starts fail first (status 1: a slow daemon-reload, a
#                                 timeout, an OOM), then the probe behaves normally;
#   $FAKE_STATE/exec-status       what `systemctl show -p ExecMainStatus --value` prints for the service;
#   a failed probe records its ExecMainStatus in $FAKE_STATE/probe-status (217/USER when PrivateUsers=yes is refused),
#   which `show -p ExecMainStatus --value p2pc-server-probe.service` prints until `reset-failed` clears it;
#   $FAKE_STATE/active-state      overrides what `show -p ActiveState` prints (e.g. "deactivating");
#   $FAKE_STATE/main-pid          overrides what `show -p MainPID` prints.
# Each probe unit that is started is appended to $FAKE_STATE/probe-units, followed by a "---" line.
cat >"$fakebin/systemctl" <<'FAKE'
#!/bin/sh
echo "systemctl $*" >>"$FAKE_STATE/calls"
probe="$P2PC_INSTALL_ROOT/run/systemd/system/p2pc-server-probe.service"
case "$*" in
  "enable --now p2pc-server" | "start p2pc-server" | "restart p2pc-server")
    [ -e "$FAKE_STATE/start-fails" ] && exit 1
    [ "$*" = "restart p2pc-server" ] && [ -e "$FAKE_STATE/restart-fails" ] && exit 1
    if [ -e "$FAKE_STATE/start-limit-hit" ]; then
      echo "Job for p2pc-server.service failed (start-limit-hit)." >&2
      exit 1
    fi
    touch "$FAKE_STATE/running" ;;
  "stop p2pc-server")
    [ -e "$FAKE_STATE/stop-fails" ] && exit 1
    rm -f "$FAKE_STATE/running" ;;
  "is-active --quiet p2pc-server") [ -e "$FAKE_STATE/running" ] || exit 3 ;;
  "show -p ActiveState --value p2pc-server")
    if [ -e "$FAKE_STATE/active-state" ]; then cat "$FAKE_STATE/active-state"
    elif [ -e "$FAKE_STATE/running" ]; then echo active
    else echo inactive; fi ;;
  "show -p MainPID --value p2pc-server")
    if [ -e "$FAKE_STATE/main-pid" ]; then cat "$FAKE_STATE/main-pid"
    elif [ -e "$FAKE_STATE/running" ]; then echo 4242
    else echo 0; fi ;;
  "show -p ExecMainStatus --value p2pc-server") cat "$FAKE_STATE/exec-status" 2>/dev/null || echo 0 ;;
  "reset-failed p2pc-server") rm -f "$FAKE_STATE/start-limit-hit" ;;
  "show -p ExecMainStatus --value p2pc-server-probe.service") cat "$FAKE_STATE/probe-status" 2>/dev/null || echo 0 ;;
  "reset-failed p2pc-server-probe.service") rm -f "$FAKE_STATE/probe-status" ;;
  "start p2pc-server-probe.service")
    [ -f "$probe" ] || exit 5
    { cat "$probe"; echo "---"; } >>"$FAKE_STATE/probe-units"
    if [ -e "$FAKE_STATE/probe-fails" ]; then
      cat "$FAKE_STATE/probe-fail-status" 2>/dev/null >"$FAKE_STATE/probe-status" || echo 1 >"$FAKE_STATE/probe-status"
      [ -s "$FAKE_STATE/probe-status" ] || echo 1 >"$FAKE_STATE/probe-status"
      exit 1
    fi
    flaky="$(cat "$FAKE_STATE/probe-flaky" 2>/dev/null || echo 0)"
    if [ "$flaky" -gt 0 ]; then
      echo $((flaky - 1)) >"$FAKE_STATE/probe-flaky"
      echo 1 >"$FAKE_STATE/probe-status"
      exit 1
    fi
    private_users="$(sed -n 's/^PrivateUsers=//p' "$probe" | tail -n 1)"
    if [ -e "$FAKE_STATE/no-userns" ] && [ "$private_users" = yes ] && grep -qx 'ProtectKernelTunables=yes' "$probe"; then
      echo 217 >"$FAKE_STATE/probe-status"
      exit 1
    fi ;;
esac
exit 0
FAKE
# runuser -u <user> -- <command...>: records the user and runs the command as the test user.
cat >"$fakebin/runuser" <<'FAKE'
#!/bin/sh
echo "runuser $*" >>"$FAKE_STATE/calls"
[ "$1" = "-u" ] || exit 99
shift 2
[ "$1" = "--" ] || exit 98
shift
exec "$@"
FAKE
# wget: only the health probe (what the installer needs from it when curl is absent); it is never preferred over curl.
cat >"$fakebin/wget" <<'FAKE'
#!/bin/sh
echo "wget $*" >>"$FAKE_STATE/calls"
[ -e "$FAKE_STATE/running" ] && [ ! -e "$FAKE_STATE/unhealthy" ] && exit 0
exit 4
FAKE
# curl: the health probe answers when the service "runs"; https downloads come from $FAKE_MIRROR.
cat >"$fakebin/curl" <<'FAKE'
#!/bin/sh
echo "curl $*" >>"$FAKE_STATE/calls"
out=""
url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    http://* | https://*) url="$1" ;;
  esac
  shift
done
case "$url" in
  */healthz)
    # A probe that times out costs time too ($FAKE_PROBE_COST seconds on the fake clock).
    if [ -n "${FAKE_PROBE_COST:-}" ]; then
      now="$(cat "$FAKE_STATE/clock" 2>/dev/null || echo 1000)"
      echo $((now + FAKE_PROBE_COST)) >"$FAKE_STATE/clock"
    fi
    [ -e "$FAKE_STATE/running" ] && [ ! -e "$FAKE_STATE/unhealthy" ] && exit 0
    exit 7 ;;
  https://example.invalid/p2pc/*)
    src="$FAKE_MIRROR/${url#https://example.invalid/p2pc/}"
    [ -f "$src" ] || exit 22
    cp "$src" "$out" ;;
  *) exit 6 ;;
esac
FAKE
chmod 0755 "$fakebin"/*

# --- fake release directories -----------------------------------------------------------------------------------------
# make_release <dir> <version> [marker]: tarballs with fake binaries, the real unit file and SHA256SUMS.
make_release() {
  local dir="$1" version="$2" marker="${3:-v1}" stage name
  mkdir -p "$dir"
  stage="$(mktemp -d "$SCRATCH/stage.XXXXXX")"
  name="p2pc-server-$version-$target"
  mkdir -p "$stage/$name"
  cat >"$stage/$name/p2pc-server" <<FAKE
#!/bin/sh
# fake p2pc-server ($marker)
case "\$1" in
  init)
    bind="127.0.0.1:7477"
    if [ "\${2:-}" = "--bind" ]; then bind="\$3"; fi
    echo "init \$*" >>"\$P2PC_DATA_DIR/../init-calls"
    [ -e "\$P2PC_DATA_DIR/server.toml" ] && { echo "error: already initialised" >&2; exit 1; }
    printf 'bind = "%s"\ndata_dir = "%s"\n' "\$bind" "\$P2PC_DATA_DIR" >"\$P2PC_DATA_DIR/server.toml"
    echo "Initialised \$P2PC_DATA_DIR" >&2
    echo "ADMIN API KEY (shown once): $FAKE_KEY"
    echo "SERVER ADDRESS: $FAKE_ADDRESS"
    ;;
  info)
    echo "NODE ID: testonlyfakenodeid"
    echo "SERVER ADDRESS: $FAKE_ADDRESS"
    ;;
  *) exit 2 ;;
esac
FAKE
  chmod 0755 "$stage/$name/p2pc-server"
  echo "license" >"$stage/$name/LICENSE"
  tar -C "$stage" -czf "$dir/$name.tar.gz" "$name"
  name="p2pc-$version-$target"
  mkdir -p "$stage/$name"
  printf '#!/bin/sh\necho "p2pc %s (%s)"\n' "$version" "$marker" >"$stage/$name/p2pc"
  chmod 0755 "$stage/$name/p2pc"
  echo "license" >"$stage/$name/LICENSE"
  tar -C "$stage" -czf "$dir/$name.tar.gz" "$name"
  cp "$unit_src" "$dir/p2pc-server.service"
  (cd "$dir" && sha256sum -- *.tar.gz p2pc-server.service >SHA256SUMS)
  rm -rf "$stage"
}

# new_root: a fresh scratch root with systemd and a supported OS, and fresh fake state.
new_root() {
  ROOT="$(mktemp -d "$SCRATCH/root.XXXXXX")"
  FAKE_STATE="$ROOT.state"
  mkdir -p "$ROOT/etc" "$ROOT/run/systemd/system" "$ROOT/usr/local/bin" "$ROOT/var/lib" "$ROOT/var/log" "$FAKE_STATE"
  printf 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n' >"$ROOT/etc/os-release"
}

# run_installer <args...>: runs the installer under sh; stdout in $OUT, stderr in $ERR, status in $STATUS.
run_installer() {
  local stdin="${STDIN:-/dev/null}"
  env PATH="${TEST_PATH:-$fakebin:$PATH}" P2PC_INSTALL_ROOT="$ROOT" FAKE_STATE="$FAKE_STATE" FAKE_MIRROR="$SCRATCH/mirror" \
    FAKE_UID="${FAKE_UID:-0}" FAKE_ARCH="${FAKE_ARCH:-x86_64}" FAKE_PROBE_COST="${FAKE_PROBE_COST:-}" \
    sh "$installer" "$@" <"$stdin" >"$SCRATCH/out" 2>"$SCRATCH/err"
  STATUS=$?
  OUT="$(cat "$SCRATCH/out")"
  ERR="$(cat "$SCRATCH/err")"
}

dropin_rel="etc/systemd/system/p2pc-server.service.d/10-container.conf"
count_lines() { grep -c -- "$1" "$2" 2>/dev/null || true; }
calls() { cat "$FAKE_STATE/calls" 2>/dev/null || true; }
mode_of() { stat -c %a "$1" 2>/dev/null || echo missing; }

rel1="$SCRATCH/dist/0.1.0"
rel2="$SCRATCH/dist/0.1.1"
make_release "$rel1" 0.1.0 v1
make_release "$rel2" 0.1.1 v2
mkdir -p "$SCRATCH/mirror"
make_release "$SCRATCH/mirror/0.1.0" 0.1.0 v1

assert_true "installer exists" test -f "$installer"
assert_true "SPDX header" grep -q 'SPDX-License-Identifier: Apache-2.0' "$installer"
assert_true "set -eu" grep -qx 'set -eu' "$installer"
assert_true "umask 077" grep -qx 'umask 077' "$installer"

# --- a fresh install ------------------------------------------------------------------------------------------------------
new_root
run_installer --from "$rel1"
assert_eq "0" "$STATUS" "fresh install succeeds (stderr: $ERR)"
assert_eq "1" "$(count_lines "$FAKE_KEY" "$SCRATCH/out")" "the admin key is printed exactly once, on stdout"
assert_false "the admin key is not on stderr" grep -qF "$FAKE_KEY" "$SCRATCH/err"
log="$ROOT/var/log/p2pc-server-install.log"
assert_true "the installer keeps a log" test -s "$log"
assert_eq "600" "$(mode_of "$log")" "the install log is 0600"
assert_false "the admin key is not in the install log" grep -qF "$FAKE_KEY" "$log"
# Every file the install wrote, except the fake binary itself (whose source holds the fake key).
assert_eq "" "$(grep -rlF "$FAKE_KEY" "$ROOT/var" "$ROOT/etc" "$ROOT/run" "$FAKE_STATE" 2>/dev/null)" \
  "the admin key is in no file at all"
assert_false "the admin key never reaches an argv" grep -qF "$FAKE_KEY" "$FAKE_STATE/calls"
assert_contains "$OUT" "SERVER ADDRESS: $FAKE_ADDRESS" "the server address is printed"
assert_contains "$OUT" "p2pc login" "the next steps are printed"
assert_true "p2pc-server installed" cmp -s "$ROOT/usr/local/bin/p2pc-server" <(tar -xzOf "$rel1/p2pc-server-0.1.0-$target.tar.gz" "p2pc-server-0.1.0-$target/p2pc-server")
assert_true "p2pc installed" test -x "$ROOT/usr/local/bin/p2pc"
assert_eq "755" "$(mode_of "$ROOT/usr/local/bin/p2pc-server")" "p2pc-server is 0755"
assert_eq "755" "$(mode_of "$ROOT/usr/local/bin/p2pc")" "p2pc is 0755"
assert_contains "$(calls)" "chown root:root $ROOT/usr/local/bin/" "binaries are owned by root"
assert_true "unit installed verbatim" cmp -s "$ROOT/etc/systemd/system/p2pc-server.service" "$unit_src"
assert_eq "644" "$(mode_of "$ROOT/etc/systemd/system/p2pc-server.service")" "the unit is 0644"
assert_contains "$(calls)" "useradd --system --user-group --home-dir /var/lib/p2pc-server --no-create-home --shell /usr/sbin/nologin" "system user with no login"
assert_eq "700" "$(mode_of "$ROOT/var/lib/p2pc-server")" "data dir 0700"
assert_contains "$(calls)" "chown p2pc-server:p2pc-server $ROOT/var/lib/p2pc-server" "data dir owned by p2pc-server"
assert_contains "$(calls)" "runuser -u p2pc-server -- env -i" "init runs as p2pc-server with a clean environment"
assert_contains "$(calls)" "P2PC_DATA_DIR=$ROOT/var/lib/p2pc-server" "init gets the system data dir"
assert_eq "1" "$(count_lines '^init' "$ROOT/var/lib/init-calls")" "init ran once"
assert_contains "$(cat "$ROOT/var/lib/init-calls")" "init --bind 127.0.0.1:7477" "default listen address"
assert_contains "$(calls)" "systemctl daemon-reload" "daemon-reload"
assert_contains "$(calls)" "systemctl enable --now p2pc-server" "enabled and started"
assert_contains "$(calls)" "http://127.0.0.1:7477/healthz" "waits for /healthz on the listen address"
assert_true "unit installed before the service is started" awk '/daemon-reload/ { r = NR } /enable --now/ { e = NR } END { exit !(r && e && r < e) }' "$FAKE_STATE/calls"
assert_true "init ran before the service started" awk '/runuser .* init/ { i = NR } /enable --now/ { e = NR } END { exit !(i && e && i < e) }' "$FAKE_STATE/calls"
assert_false "systemd-run is not used (it needs D-Bus)" grep -q 'systemd-run' "$installer"
assert_eq "1" "$(count_lines '^systemctl start p2pc-server-probe.service$' "$FAKE_STATE/calls")" "probe A passed: one probe run"
probe_a="$(sed '/^---$/,$d' "$FAKE_STATE/probe-units")"
# Probe A is the installed unit's own [Service] settings, minus the lifecycle keys, plus a oneshot --version.
expected_service="$(awk '/^\[/ { s = ($0 == "[Service]"); next } s && !/^[[:space:]]*(#|$)/' "$unit_src" |
  grep -Ev '^(Exec[A-Za-z]*|Restart|RestartSec|Type|StateDirectory|StateDirectoryMode|TimeoutStartSec|TimeoutSec)=')"
probe_settings="$(awk '/^\[/ { s = ($0 == "[Service]"); next } s && !/^[[:space:]]*(#|$)/' <<<"$probe_a" |
  grep -Ev '^(Type=oneshot|TimeoutStartSec=30|ExecStart=.*)$')"
assert_eq "$expected_service" "$probe_settings" "probe A holds exactly the installed unit's [Service] settings, in order"
for key in User=p2pc-server PrivateUsers=yes ProtectProc=invisible PrivateDevices=yes ProtectKernelTunables=yes \
  ProtectHostname=yes SystemCallFilter=@system-service CapabilityBoundingSet=; do
  assert_true "probe A carries $key from the unit" grep -qx -- "$key" <<<"$probe_a"
done
assert_contains "$probe_a" "Type=oneshot" "the probe is a oneshot unit"
assert_contains "$probe_a" "TimeoutStartSec=30" "bounded by systemd itself (TimeoutStartSec=30)"
assert_contains "$probe_a" "ExecStart=$ROOT/usr/local/bin/p2pc-server --version" "running the installed binary's --version"
assert_eq "1" "$(grep -c '^ExecStart=' <<<"$probe_a")" "and no other ExecStart"
for key in Restart RestartSec StateDirectory StateDirectoryMode; do
  assert_false "probe A has no $key" grep -q "^$key=" <<<"$probe_a"
done
assert_eq "1" "$(grep -c '^Type=' <<<"$probe_a")" "a single Type= (oneshot), not the unit's own"
assert_false "the probe unit is removed" test -e "$ROOT/run/systemd/system/p2pc-server-probe.service"
assert_eq "1" "$(count_lines '^systemctl reset-failed p2pc-server-probe.service$' "$FAKE_STATE/calls")" "and reset-failed after the run"
assert_true "the probe runs before the service starts" awk '/start p2pc-server-probe/ { p = NR } /enable --now/ { e = NR } END { exit !(p && e && p < e) }' "$FAKE_STATE/calls"
assert_true "daemon-reload after the last probe cleanup, before the service starts" awk '/start p2pc-server-probe/ { p = NR } /daemon-reload/ && p { r = NR } /enable --now/ { e = NR } END { exit !(p && r && e && p < r && r < e) }' "$FAKE_STATE/calls"
assert_false "the probe passed: no container drop-in" test -e "$ROOT/$dropin_rel"
assert_false "and no PrivateUsers note" grep -q 'PrivateUsers is off' "$SCRATCH/out"
assert_true "reset-failed runs before enable --now" awk '/reset-failed p2pc-server/ { r = NR } /enable --now/ { e = NR } END { exit !(r && e && r < e) }' "$FAKE_STATE/calls"
assert_contains "$(cat "$log")" "install-server.sh --from $rel1" "the log records the real arguments"

# --- --admin-key-file PATH: the key goes to a new 0600 file and nowhere else (T14f) --------------------------------------
new_root
keyfile="$SCRATCH/admin.key"
rm -f "$keyfile"
run_installer --from "$rel1" --admin-key-file "$keyfile"
assert_eq "0" "$STATUS" "--admin-key-file: a fresh install succeeds (stderr: $ERR)"
assert_eq "600" "$(mode_of "$keyfile")" "--admin-key-file: the file is 0600"
assert_eq "$FAKE_KEY" "$(cat "$keyfile" 2>/dev/null)" "--admin-key-file: the file holds exactly the key"
assert_false "--admin-key-file: no key on stdout" grep -qF "$FAKE_KEY" "$SCRATCH/out"
assert_false "--admin-key-file: no key on stderr" grep -qF "$FAKE_KEY" "$SCRATCH/err"
assert_false "--admin-key-file: no 'ADMIN API KEY' banner on stdout" grep -qF "ADMIN API KEY" "$SCRATCH/out"
assert_false "--admin-key-file: the key is not in the install log" grep -qF "$FAKE_KEY" "$log"
assert_false "--admin-key-file: the key never reaches an argv" grep -qF "$FAKE_KEY" "$FAKE_STATE/calls"
assert_eq "" "$(grep -rlF "$FAKE_KEY" "$ROOT/var" "$ROOT/etc" "$ROOT/run" "$FAKE_STATE" 2>/dev/null)" \
  "--admin-key-file: the key is on disk nowhere but in the file"
assert_contains "$OUT" "$keyfile" "--admin-key-file: it says where the key is"
assert_contains "$OUT" "SERVER ADDRESS: $FAKE_ADDRESS" "--admin-key-file: the server address is still printed"
assert_false "--admin-key-file: no tty warning (nothing secret goes to stdout)" grep -q 'stdout is not a terminal' "$SCRATCH/out" "$SCRATCH/err"

# An existing PATH is refused before anything is changed, and left as it was.
new_root
printf 'precious\n' >"$keyfile"
run_installer --from "$rel1" --admin-key-file "$keyfile"
assert_eq "1" "$STATUS" "--admin-key-file: an existing file is refused"
assert_eq "precious" "$(cat "$keyfile")" "--admin-key-file: the existing file is untouched"
assert_contains "$ERR" "already exists" "--admin-key-file: the refusal says why"
assert_false "--admin-key-file: nothing was initialised" test -e "$ROOT/var/lib/init-calls"
# A dangling symlink at PATH is an existing path too (it must not be followed).
new_root
rm -f "$keyfile"
ln -s "$SCRATCH/elsewhere" "$keyfile"
run_installer --from "$rel1" --admin-key-file "$keyfile"
assert_eq "1" "$STATUS" "--admin-key-file: a symlink at PATH is refused"
assert_false "--admin-key-file: the symlink target was not created" test -e "$SCRATCH/elsewhere"
rm -f "$keyfile"
# A missing parent directory is refused up front.
new_root
run_installer --from "$rel1" --admin-key-file "$SCRATCH/no-such-dir/k"
assert_eq "1" "$STATUS" "--admin-key-file: a missing directory is refused"
# On a rerun (already initialised) there is no key to write: say so and leave PATH absent.
new_root
run_installer --from "$rel1"
rm -f "$keyfile"
run_installer --from "$rel1" --admin-key-file "$keyfile"
assert_eq "0" "$STATUS" "--admin-key-file: a rerun succeeds (stderr: $ERR)"
assert_false "--admin-key-file: a rerun writes no file" test -e "$keyfile"
assert_contains "$OUT" "no admin key was written" "--admin-key-file: a rerun says no key was written"
# The interactive path is unchanged: the key still goes to stdout (checked above) with no key file option.

# --- T14f review round: owner, FIFO, empty path, writable directory, real URL in the hint --------------------------------
new_root
rm -f "$keyfile"
run_installer --from "$rel1" --admin-key-file "$keyfile" --listen 127.0.0.1:7999
assert_eq "0" "$STATUS" "--admin-key-file without SUDO_USER succeeds (stderr: $ERR)"
assert_eq "600" "$(mode_of "$keyfile")" "without SUDO_USER: 0600"
assert_eq "$(id -u)" "$(stat -c %u "$keyfile")" "without SUDO_USER: the file stays with the installing user (root in real life)"
assert_false "without SUDO_USER: no chown of a key file" grep -q 'chown .*p2pc-admin-key' "$FAKE_STATE/calls"
assert_contains "$OUT" "owned by root" "without SUDO_USER: it says the file is root's"
assert_contains "$OUT" "p2pc login --server http://127.0.0.1:7999 --key-stdin" "the hint has the real URL of this install"
assert_false "the hint never says <server>" grep -q '<server>' "$SCRATCH/out"
assert_eq "" "$(ls -A "$(dirname "$keyfile")" | grep '^\.p2pc-admin-key' || true)" "no temp key file is left behind"
new_root
rm -f "$keyfile"
SUDO_USER=alice run_installer --from "$rel1" --admin-key-file "$keyfile"
assert_eq "0" "$STATUS" "--admin-key-file with SUDO_USER succeeds (stderr: $ERR)"
assert_eq "600" "$(mode_of "$keyfile")" "with SUDO_USER: still 0600"
assert_true "with SUDO_USER: the key file is given to that user" grep -qE '^chown alice: .*p2pc-admin-key' "$FAKE_STATE/calls"
assert_contains "$OUT" "owned by alice" "with SUDO_USER: the output says so"
assert_contains "$OUT" "p2pc login --server http://127.0.0.1:7477 --key-stdin" "default URL in the hint"
rm -f "$keyfile"
# T14g item 7: in key-file mode the next steps show only the key-file form, not the interactive "it asks for the key".
new_root
rm -f "$keyfile"
run_installer --from "$rel1" --admin-key-file "$keyfile"
assert_false "key-file mode: no step that asks for the key" grep -q 'it asks for the key' "$SCRATCH/out"
assert_contains "$OUT" "2. Enroll a machine" "key-file mode: the steps are renumbered"
assert_contains "$OUT" "--key-stdin < $keyfile" "key-file mode: the login is the --key-stdin form"
rm -f "$keyfile"
new_root
run_installer --from "$rel1"
assert_contains "$OUT" "it asks for the key" "interactive mode keeps the login step"
assert_contains "$OUT" "3. Enroll a machine" "interactive mode keeps its numbering"
rm -f "$keyfile"
# T14g item 3: a signal while the temporary key file exists must not leave the key on disk.
new_root
rm -f "$keyfile"
touch "$FAKE_STATE/chown-term"
SUDO_USER=alice run_installer --from "$rel1" --admin-key-file "$keyfile"
assert_eq "130" "$STATUS" "a SIGTERM between mktemp and the link ends the install with 130 (stderr: $ERR)"
assert_eq "" "$(ls -A "$(dirname "$keyfile")" | grep '^\.p2pc-admin-key' || true)" "a signal leaves no temporary key file behind"
assert_false "a signal leaves no key file at PATH" test -e "$keyfile"
# T14g item 4: a SUDO_USER that is no local user is refused before init runs, so no key is lost.
new_root
rm -f "$keyfile"
SUDO_USER=ghost run_installer --from "$rel1" --admin-key-file "$keyfile"
assert_eq "1" "$STATUS" "--admin-key-file with an unknown SUDO_USER is refused"
assert_contains "$ERR" "SUDO_USER" "the refusal names SUDO_USER"
assert_false "nothing was initialised" test -e "$ROOT/var/lib/init-calls"
assert_false "nothing was installed" test -e "$ROOT/usr/local/bin/p2pc-server"
rm -f "$keyfile"
# A FIFO at PATH is refused and never opened for writing (a writer would block forever on it).
new_root
mkfifo "$keyfile"
timeout 20 env PATH="$fakebin:$PATH" P2PC_INSTALL_ROOT="$ROOT" FAKE_STATE="$FAKE_STATE" FAKE_MIRROR="$SCRATCH/mirror" FAKE_UID=0 \
  FAKE_ARCH=x86_64 sh "$installer" --from "$rel1" --admin-key-file "$keyfile" </dev/null >"$SCRATCH/out" 2>"$SCRATCH/err"
assert_eq "1" "$?" "a FIFO at PATH is refused (not blocked)"
assert_true "the FIFO is still a FIFO" test -p "$keyfile"
rm -f "$keyfile"
new_root
run_installer --from "$rel1" --admin-key-file ""
assert_eq "1" "$STATUS" "--admin-key-file '' is refused"
assert_contains "$ERR" "--admin-key-file needs a path" "and says it needs a path"
# A directory writable by others without the sticky bit is refused.
new_root
wdir="$SCRATCH/wdir"
mkdir -p "$wdir" && chmod 0777 "$wdir"
run_installer --from "$rel1" --admin-key-file "$wdir/k"
assert_eq "1" "$STATUS" "a world-writable directory without the sticky bit is refused"
assert_contains "$ERR" "sticky bit" "and says why"
chmod 1777 "$wdir"
run_installer --from "$rel1" --admin-key-file "$wdir/k"
assert_eq "0" "$STATUS" "a sticky world-writable directory (like /tmp) is accepted (stderr: $ERR)"
rm -rf "$wdir"

assert_eq "0" "$(grep -v '^[[:space:]]*#' "$installer" | grep -c 'init\.out\|>"\$initout"')" "init's output (and the key in it) is held in memory, never in a scratch file"
# --- a rerun is idempotent: no second init, the key is not printed again -------------------------------------------------
: >"$FAKE_STATE/calls"
run_installer --from "$rel1"
assert_eq "0" "$STATUS" "rerun succeeds (stderr: $ERR)"
assert_false "no key on a rerun" grep -qF "ADMIN API KEY" "$SCRATCH/out"
assert_eq "1" "$(count_lines '^init' "$ROOT/var/lib/init-calls")" "init did not run again"
assert_false "no second useradd" grep -q '^useradd' "$FAKE_STATE/calls"
assert_contains "$OUT" "already initialised" "the rerun says the server exists"
assert_contains "$OUT" "keys recover" "and how to get a new admin key"
assert_contains "$OUT" "SERVER ADDRESS: $FAKE_ADDRESS" "the address is shown again (it is not secret)"
assert_false "nothing changed, so no restart" grep -q 'systemctl restart' "$FAKE_STATE/calls"

# --- --listen on a rerun does not rewrite the config; the probe follows server.toml ---------------------------------------
: >"$FAKE_STATE/calls"
run_installer --from "$rel1" --listen 127.0.0.1:9999
assert_eq "0" "$STATUS" "rerun with another --listen succeeds"
assert_contains "$OUT$ERR" "server.toml" "it says where the listen address really comes from"
assert_contains "$(calls)" "http://127.0.0.1:7477/healthz" "the probe uses the configured bind"

# --- upgrade: a new version replaces the binaries and restarts ----------------------------------------------------------
: >"$FAKE_STATE/calls"
run_installer --from "$rel2" --version 0.1.1
assert_eq "0" "$STATUS" "upgrade succeeds (stderr: $ERR)"
assert_true "new p2pc-server" grep -q 'fake p2pc-server (v2)' "$ROOT/usr/local/bin/p2pc-server"
assert_contains "$(calls)" "systemctl restart p2pc-server" "the service is restarted on the new binary"
assert_eq "1" "$(count_lines '^init' "$ROOT/var/lib/init-calls")" "an upgrade never runs init"
assert_true "data kept" test -f "$ROOT/var/lib/p2pc-server/server.toml"

# --- --version that is not in SHA256SUMS ---------------------------------------------------------------------------------
run_installer --from "$rel1" --version 9.9.9
assert_false "an unknown version is refused" test "$STATUS" = 0
assert_contains "$ERR" "9.9.9" "the error names the version"

# --- a checksum mismatch refuses before anything is installed --------------------------------------------------------------
bad="$SCRATCH/dist/bad"
make_release "$bad" 0.1.0 v1
printf 'tampered' >>"$bad/p2pc-server-0.1.0-$target.tar.gz"
new_root
run_installer --from "$bad"
assert_false "a tampered tarball is refused" test "$STATUS" = 0
assert_contains "$ERR" "checksum" "the error says checksum"
assert_false "nothing installed" test -e "$ROOT/usr/local/bin/p2pc-server"
assert_false "no user created" grep -q '^useradd' "$FAKE_STATE/calls"
assert_false "systemd untouched" grep -q '^systemctl' "$FAKE_STATE/calls"
# A tampered unit is refused too.
bad2="$SCRATCH/dist/bad2"
make_release "$bad2" 0.1.0 v1
echo "ExecStartPre=/bin/evil" >>"$bad2/p2pc-server.service"
new_root
run_installer --from "$bad2"
assert_false "a tampered unit is refused" test "$STATUS" = 0
assert_false "nothing installed (unit)" test -e "$ROOT/usr/local/bin/p2pc-server"
# A file missing from SHA256SUMS is refused.
bad3="$SCRATCH/dist/bad3"
make_release "$bad3" 0.1.0 v1
grep -v 'p2pc-0.1.0' "$bad3/SHA256SUMS" >"$bad3/S" && mv "$bad3/S" "$bad3/SHA256SUMS"
new_root
run_installer --from "$bad3" --version 0.1.0
assert_false "a file missing from SHA256SUMS is refused" test "$STATUS" = 0
assert_false "nothing installed (missing sum)" test -e "$ROOT/usr/local/bin/p2pc-server"

# --- which Linux: the requirements decide, not the name (spec §9.0 "Which Linux") -------------------------------------------
tested_tail="is not a tested platform (tested: Ubuntu 22.04, 24.04, 26.04; Debian 12, 13; Arch Linux); every requirement is met, so the install goes on"
# The platform warnings in a file (stderr, or the install log, whose lines start with a timestamp).
platform_warnings() { grep -o 'warning: .* is not a tested platform.*' "$1" 2>/dev/null || true; }
warnings_in() { platform_warnings "$1" | grep -c . || true; }

# Tested platforms install with no warning at all.
for os in 'ID=ubuntu\nVERSION_ID="22.04"' 'ID=ubuntu\nVERSION_ID="24.04"' 'ID=ubuntu\nVERSION_ID="26.04"' \
  'ID=debian\nVERSION_ID="12"' 'ID=debian\nVERSION_ID="13"' 'ID=arch\nBUILD_ID=rolling' \
  'NAME=Omarchy\nID=omarchy\nID_LIKE=arch\nVERSION_ID=4.0.6' 'ID=manjaro\nID_LIKE="arch archlinux"'; do
  new_root
  printf '%b\n' "$os" >"$ROOT/etc/os-release"
  run_installer --from "$rel1"
  assert_eq "0" "$STATUS" "tested platform [$os] installs (stderr: $ERR)"
  assert_eq "0" "$(warnings_in "$SCRATCH/err")" "tested platform [$os]: no platform warning on stderr"
  assert_eq "0" "$(warnings_in "$ROOT/var/log/p2pc-server-install.log")" "tested platform [$os]: no warning in the log"
done

# Any other Linux goes on, with exactly one warning line that names it, on stderr and in the log.
for os in 'ID=fedora\nVERSION_ID="41"|fedora 41' 'ID=ubuntu\nVERSION_ID="20.04"|ubuntu 20.04' \
  'ID=void|void unknown' 'ID=opensuse-tumbleweed\nID_LIKE="opensuse suse"\nVERSION_ID="20261105"|opensuse-tumbleweed 20261105'; do
  new_root
  printf '%b\n' "${os%%|*}" >"$ROOT/etc/os-release"
  run_installer --from "$rel1"
  assert_eq "0" "$STATUS" "other platform [${os##*|}] installs (stderr: $ERR)"
  assert_eq "warning: ${os##*|} $tested_tail" "$(platform_warnings "$SCRATCH/err")" "[${os##*|}]: exactly one warning line, and it names the platform"
  assert_eq "1" "$(warnings_in "$ROOT/var/log/p2pc-server-install.log")" "[${os##*|}]: the warning is in the install log too"
  assert_true "[${os##*|}]: the service is installed" test -x "$ROOT/usr/local/bin/p2pc-server"
done
# No /etc/os-release at all: the same warning, with `unknown`.
new_root
rm -f "$ROOT/etc/os-release"
run_installer --from "$rel1"
assert_eq "0" "$STATUS" "no os-release installs (stderr: $ERR)"
assert_eq "warning: unknown $tested_tail" "$(platform_warnings "$SCRATCH/err")" "no os-release: one warning, naming unknown"
# Only /usr/lib/os-release (os-release(5)): it is read when /etc/os-release is absent, so a tested platform has no warning.
new_root
rm -f "$ROOT/etc/os-release"
mkdir -p "$ROOT/usr/lib"
printf 'ID=debian\nVERSION_ID="12"\n' >"$ROOT/usr/lib/os-release"
run_installer --from "$rel1"
assert_eq "0" "$STATUS" "only /usr/lib/os-release installs (stderr: $ERR)"
assert_eq "0" "$(warnings_in "$SCRATCH/err")" "only /usr/lib/os-release: a tested platform, no warning"
new_root
printf 'ID=fedora\nVERSION_ID="41"\n' >"$ROOT/etc/os-release"
mkdir -p "$ROOT/usr/lib"
printf 'ID=debian\nVERSION_ID="12"\n' >"$ROOT/usr/lib/os-release"
run_installer --from "$rel1"
assert_eq "warning: fedora 41 $tested_tail" "$(platform_warnings "$SCRATCH/err")" "/etc/os-release wins over /usr/lib/os-release"
# The warning only comes once every requirement is met: a missing one stops the install without it.
new_root
printf 'ID=fedora\nVERSION_ID="41"\n' >"$ROOT/etc/os-release"
TEST_PATH="$(path_without "$fakebin" tar)" run_installer --from "$rel1"
assert_eq "1" "$STATUS" "fedora without tar fails"
assert_eq "0" "$(warnings_in "$SCRATCH/err")" "no 'every requirement is met' warning when one is not"

# Each requirement is checked by itself, and the error names it. Nothing is done before the check.
for missing in runuser useradd sha256sum tar systemctl; do
  new_root
  TEST_PATH="$(path_without "$fakebin" "$missing")" run_installer --from "$rel1"
  assert_eq "1" "$STATUS" "without $missing the install fails"
  assert_contains "$ERR" "$missing is missing" "the error says $missing is missing"
  assert_false "without $missing: nothing was installed" test -e "$ROOT/usr/local/bin/p2pc-server"
  assert_false "without $missing: no hint assumes apt for a core tool" grep -q 'standard Ubuntu or Debian' "$SCRATCH/err"
done
new_root
TEST_PATH="$(path_without "$fakebin" curl wget)" run_installer --from "$rel1"
assert_eq "1" "$STATUS" "without curl and wget the install fails"
assert_contains "$ERR" "curl" "the error names curl"
assert_contains "$ERR" "wget" "the error names wget"
assert_contains "$ERR" "package manager" "the hint speaks of the package manager"
assert_contains "$ERR" "dnf install curl" "the hint is not only apt"
assert_contains "$ERR" "pacman -S curl" "the hint names pacman too"
assert_false "without curl and wget: nothing installed" test -e "$ROOT/usr/local/bin/p2pc-server"
# Only one of the two is enough.
new_root
TEST_PATH="$(path_without "$fakebin" wget)" run_installer --from "$rel1"
assert_eq "0" "$STATUS" "curl alone is enough (stderr: $ERR)"
new_root
TEST_PATH="$(path_without "$fakebin" curl)" run_installer --from "$rel1"
assert_eq "0" "$STATUS" "wget alone is enough (stderr: $ERR)"

new_root
FAKE_UID=1000 run_installer --from "$rel1"
assert_false "non-root refused" test "$STATUS" = 0
assert_contains "$ERR" "root" "the error says root"
new_root
rmdir "$ROOT/run/systemd/system"
run_installer --from "$rel1"
assert_false "no systemd refused" test "$STATUS" = 0
assert_contains "$ERR" "systemd" "the error says systemd"
new_root
FAKE_ARCH=riscv64 run_installer --from "$rel1"
assert_false "riscv64 refused" test "$STATUS" = 0
assert_contains "$ERR" "riscv64" "the error names the architecture"
new_root
FAKE_ARCH=aarch64 run_installer --from "$rel1"
assert_false "aarch64 without an aarch64 tarball refused" test "$STATUS" = 0
assert_contains "$ERR" "aarch64-unknown-linux-musl" "the error names the missing target"

# --- argument validation ------------------------------------------------------------------------------------------------------
new_root
run_installer --from "$rel1" --listen 'localhost;rm -rf /'
assert_false "a bad --listen is refused" test "$STATUS" = 0
assert_false "nothing done for a bad --listen" test -s "$FAKE_STATE/calls"
run_installer --purge
assert_false "--purge alone is refused" test "$STATUS" = 0
run_installer --bogus
assert_eq "2" "$STATUS" "an unknown option is a usage error"
run_installer --help
assert_eq "0" "$STATUS" "--help"
assert_contains "$OUT" "--uninstall" "--help lists --uninstall"
run_installer
assert_false "no --from and no published releases yet" test "$STATUS" = 0
assert_contains "$ERR" "--from" "the error points at --from"

# --- --listen on a fresh install ---------------------------------------------------------------------------------------------
new_root
run_installer --from "$rel1" --listen 0.0.0.0:7480
assert_eq "0" "$STATUS" "fresh install with --listen (stderr: $ERR)"
assert_contains "$(cat "$ROOT/var/lib/init-calls")" "init --bind 0.0.0.0:7480" "--listen reaches init"
assert_contains "$(calls)" "http://127.0.0.1:7480/healthz" "a wildcard bind is probed on loopback"
assert_contains "$OUT$ERR" "reverse proxy" "a non-loopback bind gets the TLS warning"
new_root
run_installer --from "$rel1" --listen '[::1]:7481'
assert_eq "0" "$STATUS" "IPv6 --listen (stderr: $ERR)"
assert_contains "$(calls)" "http://[::1]:7481/healthz" "IPv6 probe"

# --- download from a URL ----------------------------------------------------------------------------------------------------
new_root
run_installer --from https://example.invalid/p2pc/0.1.0
assert_eq "0" "$STATUS" "install from a URL (stderr: $ERR)"
assert_true "installed from the URL" test -x "$ROOT/usr/local/bin/p2pc-server"
assert_contains "$(calls)" "--proto =https" "downloads are https only"
assert_contains "$(calls)" "--proto-redir =https" "redirects are https only too"
assert_contains "$(calls)" "--connect-timeout 10" "downloads have a connect timeout"
assert_contains "$(calls)" "--max-time 600" "and a total timeout"
new_root
run_installer --from http://example.invalid/p2pc/0.1.0
assert_false "plain http is refused" test "$STATUS" = 0
assert_false "nothing fetched over http" grep -q '^curl' "$FAKE_STATE/calls"

# --- the service never becomes healthy ----------------------------------------------------------------------------------------
new_root
touch "$FAKE_STATE/unhealthy"
run_installer --from "$rel1"
assert_false "an unhealthy service fails the install" test "$STATUS" = 0
assert_contains "$ERR" "journalctl -u p2pc-server" "the error says where to look"
assert_eq "30" "$(count_lines '/healthz' "$FAKE_STATE/calls")" "it polls for at most 30 s (one probe a second)"
# The deadline is real time, not a count of probes: probes that each take 2 s leave room for 10 of them.
new_root
touch "$FAKE_STATE/unhealthy"
FAKE_PROBE_COST=2 run_installer --from "$rel1"
assert_false "slow probes: still a failure" test "$STATUS" = 0
assert_eq "10" "$(count_lines '/healthz' "$FAKE_STATE/calls")" "slow probes stop at the 30 s deadline"

# --- a failing install step stops the install (install_file runs inside `if`, where set -e does not apply) -------------
new_root
touch "$FAKE_STATE/chown-fails"
run_installer --from "$rel1"
assert_false "a failed chown stops the install" test "$STATUS" = 0
assert_contains "$ERR" "cannot install" "and says what failed"
assert_false "no half-installed binary" test -e "$ROOT/usr/local/bin/p2pc-server"
assert_eq "" "$(find "$ROOT/usr/local/bin" -name '.*.new.*')" "no temporary file left behind"
assert_false "nothing started" grep -q '^systemctl enable' "$FAKE_STATE/calls"

# --- container hosts: no user namespace for the service, so PrivateUsers is turned off by a drop-in -------------------
new_root
touch "$FAKE_STATE/no-userns"
run_installer --from "$rel1"
assert_eq "0" "$STATUS" "a host without user namespaces still gets a running server (stderr: $ERR)"
dropin="$ROOT/$dropin_rel"
assert_true "the drop-in is written" test -f "$dropin"
assert_eq "[Service]
PrivateUsers=no" "$(grep -v '^#' "$dropin")" "it only turns PrivateUsers off"
assert_eq "644" "$(mode_of "$dropin")" "the drop-in is 0644"
assert_eq "755" "$(mode_of "$(dirname "$dropin")")" "its directory is 0755"
note="this host cannot give the service its own user namespace (container?): PrivateUsers is off"
assert_eq "1" "$(count_lines "$note" "$SCRATCH/err")" "said once while installing"
# shellcheck disable=SC2016  # awk code, with the note passed by -v
assert_true "and once in the summary" awk -v n="$note" 'index($0, "P2PC server") { s = 1 } s && index($0, n) { f = 1 } END { exit !f }' "$SCRATCH/out"
assert_true "and logged" grep -qF "$note" "$ROOT/var/log/p2pc-server-install.log"
assert_true "the drop-in is in place before the service starts" awk '/start p2pc-server-probe/ { p = NR } /daemon-reload/ && p { r = NR } /enable --now/ { e = NR } END { exit !(p && r && e && p < r && r < e) }' "$FAKE_STATE/calls"
assert_false "the probe unit is removed (container)" test -e "$ROOT/run/systemd/system/p2pc-server-probe.service"
assert_eq "2" "$(count_lines '^systemctl start p2pc-server-probe.service$' "$FAKE_STATE/calls")" "A failed, so B ran"
probe_b="$(sed '1,/^---$/d; /^---$/,$d' "$FAKE_STATE/probe-units")"
assert_eq "PrivateUsers=no" "$(sed -n 's/^PrivateUsers=/PrivateUsers=/p' <<<"$probe_b" | tail -n 1)" "probe B ends with PrivateUsers=no"
assert_eq "$(grep -v '^PrivateUsers=no$' <<<"$probe_b")" "$(sed '/^---$/,$d' "$FAKE_STATE/probe-units")" "and is otherwise probe A"
# A rerun on the same host keeps it, and changes nothing.
: >"$FAKE_STATE/calls"
run_installer --from "$rel1"
assert_eq "0" "$STATUS" "rerun on a container host"
assert_true "the drop-in stays" test -f "$dropin"
assert_false "nothing changed, so no restart (container)" grep -q 'systemctl restart' "$FAKE_STATE/calls"
# The host gains user namespaces (or the server moves to a VM): the old drop-in is removed and the service restarted.
rm -f "$FAKE_STATE/no-userns"
: >"$FAKE_STATE/calls"
run_installer --from "$rel1"
assert_eq "0" "$STATUS" "rerun once the probe passes"
assert_false "the old drop-in is removed" test -e "$dropin"
assert_false "and its empty directory" test -e "$(dirname "$dropin")"
assert_contains "$(calls)" "systemctl restart p2pc-server" "the service is restarted with PrivateUsers back on"
assert_false "no PrivateUsers note once it is on" grep -q 'PrivateUsers is off' "$SCRATCH/out"
# --uninstall removes the drop-in directory.
touch "$FAKE_STATE/no-userns"
run_installer --from "$rel1"
assert_true "drop-in back" test -f "$dropin"
echo "# an admin's own override" >"$(dirname "$dropin")/20-local.conf"
run_installer --uninstall
assert_eq "0" "$STATUS" "uninstall on a container host"
assert_false "--uninstall removes the drop-in directory" test -e "$(dirname "$dropin")"

# --- both probes fail: PrivateUsers is not the cause, so nothing changes and the health wait reports the real error ------
new_root
touch "$FAKE_STATE/probe-fails" "$FAKE_STATE/unhealthy"
echo 217 >"$FAKE_STATE/probe-fail-status"
run_installer --from "$rel1"
assert_false "both probes fail and the service does not start: the install fails" test "$STATUS" = 0
assert_false "no drop-in when both probes fail" test -e "$ROOT/$dropin_rel"
assert_contains "$ERR" "fails even with PrivateUsers=no" "the message says PrivateUsers is not the cause"
assert_contains "$ERR" "keeping PrivateUsers=yes" "and that PrivateUsers stays on"
assert_contains "$ERR" "did not answer" "then the health wait reports the real error"
assert_eq "2" "$(count_lines '^systemctl start p2pc-server-probe.service$' "$FAKE_STATE/calls")" "both probes ran"
assert_false "the probe unit is removed after two failures" test -e "$ROOT/run/systemd/system/p2pc-server-probe.service"
assert_eq "2" "$(count_lines '^systemctl reset-failed p2pc-server-probe.service$' "$FAKE_STATE/calls")" "and reset after each"
# An old drop-in is kept when the probe proves nothing.
new_root
touch "$FAKE_STATE/no-userns"
run_installer --from "$rel1"
touch "$FAKE_STATE/probe-fails"
echo 217 >"$FAKE_STATE/probe-fail-status"
run_installer --from "$rel1"
assert_eq "0" "$STATUS" "rerun with both probes failing and an old drop-in"
assert_true "the old drop-in stays when the probe proves nothing" test -f "$ROOT/$dropin_rel"
assert_contains "$ERR" "keeping the existing PrivateUsers=no drop-in" "and the message says the drop-in is kept"
assert_false "it does not claim PrivateUsers=yes then" grep -q 'keeping PrivateUsers=yes' "$SCRATCH/err"
# --- T14b1 review: ONE failed probe A must not switch PrivateUsers off (a slow daemon-reload, the 30 s timeout, an OOM) -----
# A failed once, not with the user-namespace status: A is retried, passes, and nothing changes.
new_root
echo 1 >"$FAKE_STATE/probe-flaky"
run_installer --from "$rel1"
assert_eq "0" "$STATUS" "a flaky probe A: the install succeeds (stderr: $ERR)"
assert_false "a flaky probe A writes no drop-in" test -e "$ROOT/$dropin_rel"
assert_eq "2" "$(count_lines '^systemctl start p2pc-server-probe.service$' "$FAKE_STATE/calls")" "A ran twice (the retry), B never"
assert_false "B never ran: no probe unit with PrivateUsers=no" grep -qx 'PrivateUsers=no' "$FAKE_STATE/probe-units"
assert_contains "$(calls)" "systemctl show -p ExecMainStatus --value p2pc-server-probe.service" "the status of the failed probe is read"
assert_true "the status is read before the probe unit is reset" awk '/show -p ExecMainStatus --value p2pc-server-probe/ { s = NR } /reset-failed p2pc-server-probe/ && s && !r { r = NR } END { exit !(s && r && s < r) }' "$FAKE_STATE/calls"
# A fails twice for another reason: warn, keep PrivateUsers=yes, never try B.
new_root
touch "$FAKE_STATE/probe-fails"
run_installer --from "$rel1"
assert_false "A failing for another reason writes no drop-in" test -e "$ROOT/$dropin_rel"
assert_eq "2" "$(count_lines '^systemctl start p2pc-server-probe.service$' "$FAKE_STATE/calls")" "A and its retry; no B"
assert_false "no probe with PrivateUsers=no" grep -qx 'PrivateUsers=no' "$FAKE_STATE/probe-units"
assert_contains "$ERR" "keeping PrivateUsers=yes" "it warns and keeps PrivateUsers=yes"
assert_contains "$ERR" "not the user-namespace status" "and says why"
# An old drop-in is kept when A fails for another reason too (the probe proved nothing).
new_root
touch "$FAKE_STATE/no-userns"
run_installer --from "$rel1"
touch "$FAKE_STATE/probe-fails"
run_installer --from "$rel1"
assert_true "an old drop-in stays when A fails for another reason" test -f "$ROOT/$dropin_rel"
# 226/NAMESPACE (an unprivileged LXC without nesting) is a user-namespace status too: B runs.
new_root
touch "$FAKE_STATE/probe-fails"
echo 226 >"$FAKE_STATE/probe-fail-status"
run_installer --from "$rel1"
assert_eq "2" "$(count_lines '^systemctl start p2pc-server-probe.service$' "$FAKE_STATE/calls")" "226: A then B (no retry)"
assert_true "226: B ran with PrivateUsers=no" grep -qx 'PrivateUsers=no' "$FAKE_STATE/probe-units"

# --- T14b1 review: a VERSION taken from SHA256SUMS is checked like --version ------------------------------------------------
weird="$SCRATCH/dist/weird"
make_release "$weird" 0.1.0 v1
for b in p2pc-server p2pc; do
  mv "$weird/$b-0.1.0-$target.tar.gz" "$weird/$b-0.1.0;id-$target.tar.gz"
done
(cd "$weird" && sha256sum -- *.tar.gz p2pc-server.service >SHA256SUMS)
new_root
run_installer --from "$weird"
assert_false "a malformed version in SHA256SUMS is refused" test "$STATUS" = 0
assert_contains "$ERR" "does not look like a version" "and the error says why"
assert_false "nothing installed with a malformed version" test -e "$ROOT/usr/local/bin/p2pc-server"

# The probe reads the unit AS INSTALLED: a changed unit in the release changes the probe.
new_root
sed 's/^ProtectHostname=yes$/ProtectHostname=yes\nLockPersonality=yes\n# a comment line\nRestrictRealtime=yes/' "$unit_src" >"$SCRATCH/unit-variant"
variant="$SCRATCH/dist/variant"
make_release "$variant" 0.1.0 v1
cp "$SCRATCH/unit-variant" "$variant/p2pc-server.service"
(cd "$variant" && sha256sum -- *.tar.gz p2pc-server.service >SHA256SUMS)
run_installer --from "$variant"
assert_eq "0" "$STATUS" "install with a variant unit (stderr: $ERR)"
assert_eq "2" "$(sed '/^---$/,$d' "$FAKE_STATE/probe-units" | grep -c '^LockPersonality=yes$')" "the probe follows the installed unit, line for line"
assert_false "comments are not copied" grep -q '^# a comment line' "$FAKE_STATE/probe-units"
# If the installer dies mid-probe (a timeout), the trap still removes the probe unit.
new_root
cat >"$fakebin/timeout" <<'FAKE'
#!/bin/sh
case "$*" in *p2pc-server-probe*) [ -e "$FAKE_STATE/probe-hangs" ] && kill -TERM "$PPID" && exit 124 ;; esac
shift
exec "$@"
FAKE
chmod 0755 "$fakebin/timeout"
touch "$FAKE_STATE/probe-hangs"
run_installer --from "$rel1"
assert_false "an interrupted install fails" test "$STATUS" = 0
assert_false "the probe unit is removed even then" test -e "$ROOT/run/systemd/system/p2pc-server-probe.service"
rm -f "$fakebin/timeout"

# --- a service that fails with 226/NAMESPACE gets the LXC nesting hint ----------------------------------------------------
new_root
touch "$FAKE_STATE/unhealthy"
echo 226 >"$FAKE_STATE/exec-status"
run_installer --from "$rel1"
assert_false "226: the install fails" test "$STATUS" = 0
assert_contains "$ERR" "226/NAMESPACE" "the hint names the status"
assert_contains "$ERR" "nesting=1" "and the LXC nesting feature"
new_root
touch "$FAKE_STATE/unhealthy"
run_installer --from "$rel1"
assert_false "no 226 hint for another failure" grep -q 'NAMESPACE' "$SCRATCH/err"
new_root
touch "$FAKE_STATE/unhealthy"
echo 217 >"$FAKE_STATE/exec-status"
run_installer --from "$rel1"
assert_contains "$ERR" "217/USER" "the 217/USER hint"
assert_contains "$ERR" "cannot run the service as p2pc-server" "names the user"
# The hint is on a failed enable --now too, and on a failed restart.
new_root
touch "$FAKE_STATE/start-fails"
echo 226 >"$FAKE_STATE/exec-status"
run_installer --from "$rel1"
assert_false "a failed enable --now fails the install" test "$STATUS" = 0
assert_contains "$ERR" "systemctl enable --now p2pc-server failed (status 226/NAMESPACE" "the enable --now error carries the hint"
new_root
run_installer --from "$rel1"
touch "$FAKE_STATE/restart-fails"
echo 217 >"$FAKE_STATE/exec-status"
run_installer --from "$rel2" --version 0.1.1
assert_false "a failed restart on upgrade fails the install" test "$STATUS" = 0
assert_contains "$ERR" "systemctl restart p2pc-server failed (status 217/USER" "the restart error carries the hint"

# --- a rerun after a crash-looping first install recovers (start-limit-hit) ------------------------------------------------
new_root
run_installer --from "$rel1"
touch "$FAKE_STATE/start-limit-hit"
rm -f "$FAKE_STATE/running"
: >"$FAKE_STATE/calls"
run_installer --from "$rel1"
assert_eq "0" "$STATUS" "a rerun after start-limit-hit succeeds (stderr: $ERR)"
assert_contains "$OUT" "healthy:" "and the service is healthy again"
assert_true "reset-failed before enable --now on the rerun" awk '/reset-failed p2pc-server/ { r = NR } /enable --now/ { e = NR } END { exit !(r && e && r < e) }' "$FAKE_STATE/calls"

# --- the install log is never followed through a symlink --------------------------------------------------------------------
new_root
echo "precious" >"$SCRATCH/elsewhere"
ln -s "$SCRATCH/elsewhere" "$ROOT/var/log/p2pc-server-install.log"
run_installer --from "$rel1"
assert_eq "0" "$STATUS" "install with a symlinked log (stderr: $ERR)"
assert_eq "precious" "$(cat "$SCRATCH/elsewhere")" "the symlink target is untouched"
assert_false "the log is no longer a symlink" test -L "$ROOT/var/log/p2pc-server-install.log"
assert_true "it is a regular file again" test -f "$ROOT/var/log/p2pc-server-install.log"
assert_eq "600" "$(mode_of "$ROOT/var/log/p2pc-server-install.log")" "recreated 0600"
# A symlink to a directory: the log must replace the link, never land inside the directory.
new_root
mkdir "$SCRATCH/somedir"
ln -s "$SCRATCH/somedir" "$ROOT/var/log/p2pc-server-install.log"
run_installer --from "$rel1"
assert_eq "0" "$STATUS" "install with a log symlinked to a directory (stderr: $ERR)"
assert_eq "" "$(ls -A "$SCRATCH/somedir")" "nothing was written into the directory"
assert_true "the log is a regular file" test -f "$ROOT/var/log/p2pc-server-install.log"
assert_false "and not a symlink" test -L "$ROOT/var/log/p2pc-server-install.log"
assert_eq "" "$(find "$ROOT/var/log" -name '.p2pc-server-install.log.*')" "no temporary log left behind"
assert_true "the installer creates the log with mktemp and renames it into place" grep -q 'mv -fT' "$installer"
new_root
mkdir "$ROOT/var/log/p2pc-server-install.log"
run_installer --from "$rel1"
assert_false "a log path that is a directory is refused" test "$STATUS" = 0
assert_contains "$ERR" "not a regular file" "and says why"
assert_false "nothing installed with a bad log path" test -e "$ROOT/usr/local/bin/p2pc-server"

# --- uninstall keeps the data; purge asks first ---------------------------------------------------------------------------------
new_root
run_installer --from "$rel1"
: >"$FAKE_STATE/calls"
run_installer --uninstall
assert_eq "0" "$STATUS" "uninstall succeeds (stderr: $ERR)"
assert_contains "$(calls)" "systemctl stop p2pc-server" "stopped"
assert_contains "$(calls)" "systemctl disable p2pc-server" "and disabled"
assert_false "unit removed" test -e "$ROOT/etc/systemd/system/p2pc-server.service"
assert_false "p2pc-server removed" test -e "$ROOT/usr/local/bin/p2pc-server"
assert_false "p2pc removed" test -e "$ROOT/usr/local/bin/p2pc"
assert_true "data kept" test -f "$ROOT/var/lib/p2pc-server/server.toml"
assert_false "user kept" grep -q '^userdel' "$FAKE_STATE/calls"
assert_contains "$OUT" "--purge" "it says how to delete the data too"
# A second uninstall is harmless.
run_installer --uninstall
assert_eq "0" "$STATUS" "uninstall twice"
# A plain --uninstall while the service cannot be stopped warns and goes on; it never deletes data anyway.
new_root
run_installer --from "$rel1"
touch "$FAKE_STATE/stop-fails"
run_installer --uninstall
assert_eq "0" "$STATUS" "plain --uninstall while active: rc 0 (stderr: $ERR)"
assert_contains "$ERR" "still active" "it warns that the service is still active"
assert_false "the unit is removed anyway" test -e "$ROOT/etc/systemd/system/p2pc-server.service"
assert_false "and the binaries" test -e "$ROOT/usr/local/bin/p2pc-server"
assert_true "data kept" test -f "$ROOT/var/lib/p2pc-server/server.toml"
rm -f "$FAKE_STATE/stop-fails"
new_root
run_installer --from "$rel1"
run_installer --uninstall

printf 'no\n' >"$SCRATCH/no"
STDIN="$SCRATCH/no" run_installer --uninstall --purge
assert_false "purge not confirmed is refused" test "$STATUS" = 0
assert_true "data kept without confirmation" test -f "$ROOT/var/lib/p2pc-server/server.toml"
STDIN=/dev/null run_installer --uninstall --purge
assert_false "purge with no answer at all is refused" test "$STATUS" = 0
assert_true "data still kept" test -f "$ROOT/var/lib/p2pc-server/server.toml"
printf 'purge\n' >"$SCRATCH/yes"
STDIN="$SCRATCH/yes" run_installer --uninstall --purge
assert_eq "0" "$STATUS" "typed confirmation purges (stderr: $ERR)"
assert_false "data deleted" test -e "$ROOT/var/lib/p2pc-server"
assert_contains "$(calls)" "userdel p2pc-server" "user deleted"

new_root
run_installer --from "$rel1"
touch "$FAKE_STATE/stop-fails"
run_installer --uninstall --purge --yes
assert_false "purge stops when the service cannot be stopped" test "$STATUS" = 0
assert_contains "$ERR" "nothing was deleted" "and says nothing was deleted"
assert_true "data kept when the stop failed" test -f "$ROOT/var/lib/p2pc-server/server.toml"
assert_true "binaries kept when the stop failed" test -e "$ROOT/usr/local/bin/p2pc-server"
assert_false "user kept when the stop failed" grep -q '^userdel' "$FAKE_STATE/calls"
# The unit file is gone (deleted by hand) but the service still runs: the purge still refuses.
rm -f "$ROOT/etc/systemd/system/p2pc-server.service"
run_installer --uninstall --purge --yes
assert_false "purge refuses while active, even without the unit file" test "$STATUS" = 0
assert_contains "$ERR" "still active" "and says it is still active"
assert_true "data kept without the unit file" test -f "$ROOT/var/lib/p2pc-server/server.toml"
assert_contains "$(calls)" "systemctl show -p ActiveState --value p2pc-server" "the check reads ActiveState"
assert_contains "$(calls)" "systemctl show -p MainPID --value p2pc-server" "and MainPID"
rm -f "$FAKE_STATE/stop-fails"
# Stopped as far as ActiveState goes, but a main process is still there: refuse.
rm -f "$FAKE_STATE/running"
echo 4242 >"$FAKE_STATE/main-pid"
run_installer --uninstall --purge --yes
assert_false "purge refuses while MainPID is not 0" test "$STATUS" = 0
assert_contains "$ERR" "nothing was deleted" "MainPID: nothing was deleted"
assert_true "data kept while MainPID is set" test -f "$ROOT/var/lib/p2pc-server/server.toml"
rm -f "$FAKE_STATE/main-pid"
# A state other than inactive, failed or empty: refuse.
echo deactivating >"$FAKE_STATE/active-state"
run_installer --uninstall --purge --yes
assert_false "purge refuses while deactivating" test "$STATUS" = 0
assert_contains "$ERR" "deactivating" "and names the state"
assert_true "data kept while deactivating" test -f "$ROOT/var/lib/p2pc-server/server.toml"
# failed (and MainPID 0) is fine.
echo failed >"$FAKE_STATE/active-state"
run_installer --uninstall --purge --yes
assert_eq "0" "$STATUS" "purge goes ahead when the service is failed (stderr: $ERR)"
assert_false "data deleted when failed" test -e "$ROOT/var/lib/p2pc-server"
rm -f "$FAKE_STATE/active-state"
new_root
run_installer --from "$rel1"
run_installer --uninstall --purge --yes
assert_eq "0" "$STATUS" "--yes purges without asking"
assert_false "data deleted with --yes" test -e "$ROOT/var/lib/p2pc-server"
assert_false "unit removed with --purge" test -e "$ROOT/etc/systemd/system/p2pc-server.service"

finish_tests "test-install-server"
