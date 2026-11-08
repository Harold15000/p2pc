#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end tests of deploy/linux/install-node.sh with fakes, in the style of test-install-server.sh: a PATH of stub
# system commands (systemctl, runuser, id, chown, pgrep, curl, sleep, date, uname), a scratch root (P2PC_INSTALL_ROOT),
# a fake setup-host.sh and a fake p2pc-agent inside fake release directories. The script runs under `sh`.
# What is checked above all: the join token goes from the installer's stdin to the agent's stdin and nowhere else (no
# argv, no log, no file, no output), the host check stops a host that is not ready before anything is enrolled, and
# every rerun is idempotent. The real install needs root, systemd and Podman: see PR.md / deploy/README.md.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
make_scratch
installer="$here/../linux/install-node.sh"
unit_src="$here/../linux/p2pc-agent.service"
target="x86_64-unknown-linux-musl"

FAKE_TOKEN="p2pc_join_testonlyfaketokentestonlyfaketokentestonly" # gitleaks:allow
FAKE_NODE="nod_testonlyfakenode"
FAKE_SERVER="testonlyfakeservernodeid"

# --- fake system commands ----------------------------------------------------------------------------------------------
fakebin="$SCRATCH/fakebin"
mkdir -p "$fakebin"
cat >"$fakebin/id" <<'FAKE'
#!/bin/sh
if [ "$*" = "-u" ]; then echo "${FAKE_UID:-0}"; exit 0; fi
if [ "$*" = "-u p2pc" ] && [ -e "$FAKE_STATE/user" ]; then echo 991; exit 0; fi
exit 1
FAKE
# getent passwd p2pc: once setup-host.sh created the user; its home is $FAKE_STATE/home (default /var/lib/p2pc).
cat >"$fakebin/getent" <<'FAKE'
#!/bin/sh
[ "$1" = passwd ] && [ "$2" = p2pc ] && [ -e "$FAKE_STATE/user" ] || exit 2
echo "p2pc:x:991:991:P2PC node agent:$(cat "$FAKE_STATE/home" 2>/dev/null || echo /var/lib/p2pc):/usr/sbin/nologin"
FAKE
# useradd: the installer only checks that it exists (setup-host.sh, faked here, is what creates the user).
cat >"$fakebin/useradd" <<'FAKE'
#!/bin/sh
exit 0
FAKE
cat >"$fakebin/chown" <<'FAKE'
#!/bin/sh
echo "chown $*" >>"$FAKE_STATE/calls"
FAKE
cat >"$fakebin/pgrep" <<'FAKE'
#!/bin/sh
echo "pgrep $*" >>"$FAKE_STATE/calls"
[ -e "$FAKE_STATE/agent-outside-systemd" ]
FAKE
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
# systemctl: the system manager (only `start user@991.service`) and p2pc's user manager (--user -M p2pc@ ...).
#   $FAKE_STATE/stop-fails      `stop`/`disable --now` leave the agent running;
#   $FAKE_STATE/agent-dies      the agent exits right after every start (is-active fails), with the status in
#                               $FAKE_STATE/exec-status (what `show -p ExecMainStatus` prints; default 1);
#   $FAKE_STATE/no-user-manager every --user call fails, as when p2pc's user manager is not running.
cat >"$fakebin/systemctl" <<'FAKE'
#!/bin/sh
echo "systemctl $*" >>"$FAKE_STATE/calls"
case "$*" in
  "--user -M p2pc@ "*) [ -e "$FAKE_STATE/no-user-manager" ] && { echo "Failed to connect to bus" >&2; exit 1; } ;;
esac
case "$*" in
  "--user -M p2pc@ start p2pc-agent" | "--user -M p2pc@ restart p2pc-agent")
    [ -e "$FAKE_STATE/agent-dies" ] || touch "$FAKE_STATE/running" ;;
  "--user -M p2pc@ stop p2pc-agent" | "--user -M p2pc@ disable --now p2pc-agent")
    [ -e "$FAKE_STATE/stop-fails" ] || rm -f "$FAKE_STATE/running"
    # A Ctrl-C while the stop is under way: systemd still finishes the stop, but the client dies of the signal.
    if [ -e "$FAKE_STATE/stop-interrupt" ]; then
      kill -"$(cat "$FAKE_STATE/stop-interrupt")" "$PPID"
      exit 130
    fi ;;
  "--user -M p2pc@ is-active --quiet p2pc-agent") [ -e "$FAKE_STATE/running" ] || exit 3 ;;
  "--user -M p2pc@ show -p ActiveState --value p2pc-agent")
    if [ -e "$FAKE_STATE/running" ]; then echo active; else echo inactive; fi ;;
  "--user -M p2pc@ show -p MainPID --value p2pc-agent")
    if [ -e "$FAKE_STATE/running" ]; then echo 4242; else echo 0; fi ;;
  "--user -M p2pc@ show -p ExecMainStatus --value p2pc-agent") cat "$FAKE_STATE/exec-status" 2>/dev/null || echo 1 ;;
esac
exit 0
FAKE
# runuser -u <user> -- <command...>: records its argv, then runs the command as the test user.
cat >"$fakebin/runuser" <<'FAKE'
#!/bin/sh
echo "runuser $*" >>"$FAKE_STATE/calls"
[ "$1" = "-u" ] || exit 99
shift 2
[ "$1" = "--" ] || exit 98
shift
exec "$@"
FAKE
cat >"$fakebin/curl" <<'FAKE'
#!/bin/sh
echo "curl $*" >>"$FAKE_STATE/calls"
out=""
url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    https://*) url="$1" ;;
  esac
  shift
done
case "$url" in
  https://example.invalid/p2pc/*)
    src="$FAKE_MIRROR/${url#https://example.invalid/p2pc/}"
    [ -f "$src" ] || exit 22
    cp "$src" "$out" ;;
  *) exit 6 ;;
esac
FAKE
chmod 0755 "$fakebin"/*
# Every fake records it when it inherited fd 3: the installer keeps its own stdin there, and with it the token. Only
# `p2pc-agent join` may get the token, and on its stdin only, so no child at all may see fd 3 (review 4 P3-3).
# shellcheck disable=SC2016  # expanded by each fake when it runs, not here
FD3_CHECK='[ -e /proc/self/fd/3 ] && echo "${0##*/} $*" >>"$FAKE_STATE/fd3-open"'
for f in "$fakebin"/*; do
  sed -i "1a $FD3_CHECK" "$f"
done
# fd3_clean <description>: no child of the last run saw fd 3.
fd3_clean() {
  assert_eq "" "$(cat "$FAKE_STATE/fd3-open" 2>/dev/null)" "$1: no child of the installer inherited fd 3 (its saved stdin)"
  rm -f "$FAKE_STATE/fd3-open"
}

# --- fake release directories -----------------------------------------------------------------------------------------
# The fake agent finds the test state from its HOME (the installer runs it with a clean environment): HOME is
# <root>/var/lib/p2pc and the state is <root>.state. It records its own argv, and only a HASH of what it read on stdin.
# make_release <dir> <version> [marker]
make_release() {
  local dir="$1" version="$2" marker="${3:-v1}" stage name
  mkdir -p "$dir"
  stage="$(mktemp -d "$SCRATCH/stage.XXXXXX")"
  name="p2pc-agent-$version-$target"
  mkdir -p "$stage/$name"
  cat >"$stage/$name/p2pc-agent" <<FAKE
#!/bin/sh
# fake p2pc-agent ($marker)
state="\${HOME%/var/lib/p2pc}.state"
echo "agent \$*" >>"\$state/agent-argv"
conf="\$HOME/.config/p2pc-agent/agent.toml"
data="\$HOME/.local/share/p2pc-agent"
# T14f: rootless Podman cannot start from a directory p2pc may not enter (the caller's 0700 home): the fake fails the
# same way for every subcommand when it is not run from /.
echo "\$(pwd)" >>"\$state/agent-cwd"
if [ "\$(pwd)" != / ]; then echo "Sandbox: NOT READY - podman info failed: cannot chdir to \$(pwd)" >&2; exit 125; fi
case "\$1" in
  join)
    if [ -e "\$conf" ] && [ "\${2:-}" != "--force" ]; then echo "error: already enrolled" >&2; exit 3; fi
    # A join that is cut short (Ctrl-C at the token prompt): the file holds the signal to send to the installer, the
    # agent's parent, and the agent dies of it as well.
    if [ -e "\$state/join-interrupt" ]; then
      kill -"\$(cat "\$state/join-interrupt")" "\$PPID"
      exit 130
    fi
    echo "\${P2PC_AGENT_SUPERVISED:-unset}" >"\$state/join-supervised"
    token="\$(cat)"
    printf '%s' "\$token" | sha256sum | cut -d ' ' -f 1 >"\$state/token-sha"
    if [ "\$token" != "$FAKE_TOKEN" ]; then echo "error: the server refused the token" >&2; exit 4; fi
    mkdir -p "\$(dirname "\$conf")" "\$data"
    printf '[server]\nnode_id = "%s"\nagent_node_id = "%s"\n' "$FAKE_SERVER" "$FAKE_NODE" >"\$conf"
    echo "fake identity key" >"\$data/identity.key"
    echo "Enrolled: node $FAKE_NODE (hostname test)."
    ;;
  status)
    if [ -e "\$conf" ]; then
      echo "Enrolled:      yes (node $FAKE_NODE, account acc_testonly)"
      echo "Server NodeId: $FAKE_SERVER"
      echo "Connection:    \$(cat "\$state/connection" 2>/dev/null || echo 'connected (since 2026-11-06T10:00:00Z)')"
    else
      echo "Enrolled:      no (run \\\`p2pc-agent join\\\` with a join token)"
      echo "Connection:    not enrolled"
    fi
    ;;
  doctor)
    echo "p2pc-agent doctor $version"
    echo ""
    if [ -e "\$state/doctor-not-ready" ]; then
      echo "Sandbox (podman, runtime crun): NOT READY"
      echo "  [x] rootless Podman cannot start: fake problem"
      echo ""
      echo "Result: NOT READY (1 problem). Nothing was changed: apply the fixes above, then run \\\`p2pc-agent doctor\\\` again."
      exit 1
    fi
    echo "Sandbox (podman, runtime crun): ready"
    echo "GPU: none"
    ;;
  *) exit 2 ;;
esac
FAKE
  chmod 0755 "$stage/$name/p2pc-agent"
  echo "license" >"$stage/$name/LICENSE"
  tar -C "$stage" -czf "$dir/$name.tar.gz" "$name"
  # The job shim (T10a's executor takes no lease without it next to the agent).
  name="p2pc-shim-$version-$target"
  mkdir -p "$stage/$name"
  printf '#!/bin/sh\n# fake p2pc-shim (%s)\necho "p2pc-shim %s"\n' "$marker" "$version" >"$stage/$name/p2pc-shim"
  chmod 0755 "$stage/$name/p2pc-shim"
  echo "license" >"$stage/$name/LICENSE"
  tar -C "$stage" -czf "$dir/$name.tar.gz" "$name"
  # The fake host setup: records that it ran and what it got on stdin, creates the user, and is "ready" unless told.
  cat >"$dir/setup-host.sh" <<'FAKE'
#!/usr/bin/env bash
# fake setup-host.sh
state="${P2PC_INSTALL_ROOT}.state"
[ -e /proc/self/fd/3 ] && echo "setup-host.sh $*" >>"$state/fd3-open"
echo "setup-host $*" >>"$state/calls"
cat >"$state/setup-stdin"
touch "$state/user"
mkdir -p "$P2PC_INSTALL_ROOT/var/lib/p2pc"
if [ -e "$state/host-not-ready" ]; then
  echo "  [TODO] podman is not installed (need >= 4.9)"
  echo "         Install it with your package manager, e.g.: apt-get install podman"
  echo "Result: NOT ready: 1 item(s) need attention (see [TODO] and [plan] above)."
  exit 1
fi
echo "Result: ready."
FAKE
  chmod 0755 "$dir/setup-host.sh"
  cp "$unit_src" "$dir/p2pc-agent.service"
  (cd "$dir" && sha256sum -- *.tar.gz setup-host.sh p2pc-agent.service >SHA256SUMS)
  rm -rf "$stage"
}

new_root() {
  ROOT="$(mktemp -d "$SCRATCH/root.XXXXXX")"
  FAKE_STATE="$ROOT.state"
  mkdir -p "$ROOT/etc" "$ROOT/run/systemd/system" "$ROOT/usr/local/bin" "$ROOT/var/lib" "$ROOT/var/log" "$FAKE_STATE"
  printf 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n' >"$ROOT/etc/os-release"
}

# run_installer <args...>: under sh, with $STDIN on stdin (default /dev/null); stdout in $OUT, stderr in $ERR.
run_installer() {
  local stdin="${STDIN:-/dev/null}"
  env PATH="${TEST_PATH:-$fakebin:$PATH}" P2PC_INSTALL_ROOT="$ROOT" FAKE_STATE="$FAKE_STATE" FAKE_MIRROR="$SCRATCH/mirror" \
    FAKE_UID="${FAKE_UID:-0}" FAKE_ARCH="${FAKE_ARCH:-x86_64}" \
    sh "$installer" "$@" <"$stdin" >"$SCRATCH/out" 2>"$SCRATCH/err"
  STATUS=$?
  OUT="$(cat "$SCRATCH/out")"
  ERR="$(cat "$SCRATCH/err")"
}

count_lines() { grep -c -- "$1" "$2" 2>/dev/null || true; }
calls() { cat "$FAKE_STATE/calls" 2>/dev/null || true; }
mode_of() { stat -c %a "$1" 2>/dev/null || echo missing; }
# before <first regex> <second regex>: both appear in the calls, the first one earlier.
before() {
  awk -v a="$1" -v b="$2" '$0 ~ a && !x { x = NR } $0 ~ b && !y { y = NR } END { exit !(x && y && x < y) }' "$FAKE_STATE/calls"
}
# no_token_anywhere <description>: the token is in no argv, no output, no log and no file the run wrote.
no_token_anywhere() {
  assert_false "$1: not in any argv (installer's calls)" grep -qF "$FAKE_TOKEN" "$FAKE_STATE/calls"
  assert_false "$1: not in the agent's argv" grep -qF "$FAKE_TOKEN" "$FAKE_STATE/agent-argv"
  assert_false "$1: not on stdout" grep -qF "$FAKE_TOKEN" "$SCRATCH/out"
  assert_false "$1: not on stderr" grep -qF "$FAKE_TOKEN" "$SCRATCH/err"
  assert_eq "" "$(grep -rlF "$FAKE_TOKEN" "$ROOT" "$FAKE_STATE" 2>/dev/null | grep -v '/p2pc-agent$')" \
    "$1: in no file at all (except the fake agent binary, which holds it to compare)"
}

token_file="$SCRATCH/token"
printf '%s\n' "$FAKE_TOKEN" >"$token_file"
# The fake agent hashes "$(cat)", which drops the trailing newline.
token_sha="$(printf '%s' "$FAKE_TOKEN" | sha256sum | cut -d ' ' -f 1)"
printf 'p2pc_join_testonlywrongtoken\n' >"$SCRATCH/wrong-token" # gitleaks:allow

rel1="$SCRATCH/dist/0.1.0"
rel2="$SCRATCH/dist/0.1.1"
make_release "$rel1" 0.1.0 v1
make_release "$rel2" 0.1.1 v2
mkdir -p "$SCRATCH/mirror"
make_release "$SCRATCH/mirror/0.1.0" 0.1.0 v1
home_rel="var/lib/p2pc"

# --- static properties of the installer ---------------------------------------------------------------------------------
assert_true "installer exists" test -f "$installer"
assert_true "SPDX header" grep -q 'SPDX-License-Identifier: Apache-2.0' "$installer"
assert_true "set -eu" grep -qx 'set -eu' "$installer"
assert_true "umask 077" grep -qx 'umask 077' "$installer"
# The installer itself never reads the token: its only `read` is the typed confirmation of --purge.
assert_eq "1" "$(grep -v '^[[:space:]]*#' "$installer" | grep -cE '(^|[^A-Za-z_])read ')" "the installer has exactly one read (the purge confirmation)"
assert_false "no variable named like a token" grep -qiE '\$\{?(TOKEN|JOIN_TOKEN)' "$installer"
assert_true "setup-host.sh is reused, not copied (no subuid logic in the installer)" bash -c "! grep -q 'usermod' '$installer'"

# --- a fresh install, token piped on stdin ----------------------------------------------------------------------------------
new_root
STDIN="$token_file" run_installer --from "$rel1"
assert_eq "0" "$STATUS" "fresh install succeeds (stderr: $ERR)"
assert_eq "$token_sha" "$(cat "$FAKE_STATE/token-sha" 2>/dev/null)" "the agent read exactly the piped token on its stdin"
assert_eq "" "$(cat "$FAKE_STATE/setup-stdin" 2>/dev/null)" "setup-host.sh got nothing on stdin (it cannot eat the token)"
no_token_anywhere "fresh install"
fd3_clean "fresh install"
assert_true "p2pc-agent installed" cmp -s "$ROOT/usr/local/bin/p2pc-agent" <(tar -xzOf "$rel1/p2pc-agent-0.1.0-$target.tar.gz" "p2pc-agent-0.1.0-$target/p2pc-agent")
assert_true "p2pc-shim installed next to the agent" cmp -s "$ROOT/usr/local/bin/p2pc-shim" <(tar -xzOf "$rel1/p2pc-shim-0.1.0-$target.tar.gz" "p2pc-shim-0.1.0-$target/p2pc-shim")
assert_eq "755" "$(mode_of "$ROOT/usr/local/bin/p2pc-shim")" "p2pc-shim is 0755"
assert_eq "755" "$(mode_of "$ROOT/usr/local/bin/p2pc-agent")" "p2pc-agent is 0755"
assert_contains "$(calls)" "chown root:root $ROOT/usr/local/bin/" "the binary is owned by root"
unit="$ROOT/etc/systemd/user/p2pc-agent.service"
assert_true "the user unit is installed verbatim" cmp -s "$unit" "$unit_src"
assert_eq "644" "$(mode_of "$unit")" "the unit is 0644"
assert_contains "$(calls)" "setup-host" "setup-host.sh ran"
assert_contains "$(calls)" "runuser -u p2pc -- sh -c cd / && exec \"\$@\" sh env -i" "join runs as p2pc, from /, with a clean environment"
assert_contains "$(calls)" "HOME=$ROOT/$home_rel" "with p2pc's home"
assert_true "join reads the token from stdin (join -)" grep -qE '^agent join -$' "$FAKE_STATE/agent-argv"
assert_eq "1" "$(cat "$FAKE_STATE/join-supervised" 2>/dev/null)" "join runs with P2PC_AGENT_SUPERVISED=1 (T10e: it says the installer starts the agent)"
assert_contains "$(calls)" "systemctl start user@991.service" "p2pc's user manager is started"
assert_contains "$(calls)" "systemctl --user -M p2pc@ daemon-reload" "the user manager reloads the unit"
assert_contains "$(calls)" "systemctl --user -M p2pc@ enable p2pc-agent" "the unit is enabled for p2pc"
assert_true "setup-host before join" before '^setup-host' 'runuser .* join'
assert_true "unit installed (daemon-reload) before join" before 'daemon-reload' 'runuser .* join'
assert_true "join before the service starts" before 'runuser .* join' 'p2pc@ (re)?start p2pc-agent'
assert_true "reset-failed before the start" before 'reset-failed p2pc-agent' 'p2pc@ (re)?start p2pc-agent'
assert_contains "$OUT" "Sandbox (podman, runtime crun): ready" "doctor's summary is printed"
assert_contains "$OUT" "Connection:    connected" "the status line is printed"
assert_eq "Joined: $FAKE_NODE on $FAKE_SERVER" "$(tail -n 1 "$SCRATCH/out")" "it ends with Joined: <node> on <server>"
# T14f: every p2pc-agent command runs from /, so a caller directory p2pc cannot enter never matters.
assert_true "the agent was run at least once" test -s "$FAKE_STATE/agent-cwd"
assert_eq "" "$(grep -vx / "$FAKE_STATE/agent-cwd")" "every p2pc-agent command ran from /"
assert_false "no 'cannot chdir' in the installer's output" grep -q 'cannot chdir' "$SCRATCH/out" "$SCRATCH/err"
assert_false "no NOT READY in a ready node's output" grep -q 'NOT READY' "$SCRATCH/out" "$SCRATCH/err"
assert_contains "$OUT" "journalctl _UID=991 _SYSTEMD_USER_UNIT=p2pc-agent.service" "it says where the logs are, with a command that needs no systemd-container"
assert_false "no journalctl --user -M (it needs systemd-container: real run)" grep -q 'journalctl --user -M' "$SCRATCH/out" "$SCRATCH/err"
assert_eq "0" "$(grep -v '^[[:space:]]*#' "$installer" | grep -c 'journalctl --user -M')" "the installer never prints journalctl --user -M"
log="$ROOT/var/log/p2pc-node-install.log"
assert_true "the installer keeps a log" test -s "$log"
assert_eq "600" "$(mode_of "$log")" "the install log is 0600"
assert_contains "$(cat "$log")" "install-node.sh --from $rel1" "the log records the arguments"
assert_contains "$OUT" "    running, connected" "the service line says the state the unit ends in"
assert_true "identity created by the agent" test -f "$ROOT/$home_rel/.local/share/p2pc-agent/identity.key"

# --- a rerun is idempotent: no second join, no restart --------------------------------------------------------------------
: >"$FAKE_STATE/calls"
: >"$FAKE_STATE/agent-argv"
STDIN="$token_file" run_installer --from "$rel1"
assert_eq "0" "$STATUS" "rerun succeeds (stderr: $ERR)"
assert_false "no join on a rerun" grep -q '^agent join' "$FAKE_STATE/agent-argv"
assert_contains "$OUT" "already enrolled" "the rerun says the node is enrolled"
assert_contains "$OUT" "already enrolled (node $FAKE_NODE" "worded already enrolled (node ...), no colon"
assert_false "no colon after enrolled" grep -q 'already enrolled:' "$SCRATCH/out"
assert_contains "$OUT" "--force" "and how to enroll it again"
assert_false "nothing changed, so no restart" grep -q 'restart p2pc-agent' "$FAKE_STATE/calls"
assert_contains "$(calls)" "systemctl --user -M p2pc@ start p2pc-agent" "the service is started (a no-op when it runs)"
assert_eq "Joined: $FAKE_NODE on $FAKE_SERVER" "$(tail -n 1 "$SCRATCH/out")" "a rerun ends with the Joined line too"
no_token_anywhere "rerun"

# --- T14f: a doctor that says NOT READY is a warning next to "Joined", and the exit code stays 0 ---------------------------
touch "$FAKE_STATE/doctor-not-ready"
run_installer --from "$rel1"
assert_eq "0" "$STATUS" "doctor NOT READY: the join worked, so the exit code is 0 (stderr: $ERR)"
assert_contains "$OUT" "NOT READY" "doctor NOT READY: doctor's own text is printed"
assert_contains "$ERR" "warning" "doctor NOT READY: a clear warning"
assert_contains "$ERR" "this node is enrolled but the sandbox is NOT READY" "doctor NOT READY: the warning says what it means"
assert_contains "$ERR" "sudo runuser -u p2pc -- sh -c 'cd / && exec p2pc-agent doctor'" "doctor NOT READY: the hint runs doctor from /"
assert_eq "Joined: $FAKE_NODE on $FAKE_SERVER" "$(tail -n 1 "$SCRATCH/out")" "doctor NOT READY: it still ends with Joined"
rm -f "$FAKE_STATE/doctor-not-ready"

# --- upgrade: a new agent replaces the binary and restarts it; the enrollment is kept --------------------------------------
: >"$FAKE_STATE/calls"
: >"$FAKE_STATE/agent-argv"
run_installer --from "$rel2" --version 0.1.1
assert_eq "0" "$STATUS" "upgrade succeeds (stderr: $ERR)"
assert_true "new agent" grep -q 'fake p2pc-agent (v2)' "$ROOT/usr/local/bin/p2pc-agent"
assert_contains "$(calls)" "systemctl --user -M p2pc@ restart p2pc-agent" "restarted on the new binary"
assert_false "no join on an upgrade" grep -q '^agent join' "$FAKE_STATE/agent-argv"

# --- --force enrolls again ---------------------------------------------------------------------------------------------------
: >"$FAKE_STATE/calls"
: >"$FAKE_STATE/agent-argv"
rm -f "$FAKE_STATE/token-sha"
STDIN="$token_file" run_installer --from "$rel2" --version 0.1.1 --force
assert_eq "0" "$STATUS" "--force succeeds (stderr: $ERR)"
assert_true "join --force -" grep -qE '^agent join --force -$' "$FAKE_STATE/agent-argv"
assert_eq "$token_sha" "$(cat "$FAKE_STATE/token-sha" 2>/dev/null)" "--force: the token came on stdin"
assert_contains "$(calls)" "systemctl --user -M p2pc@ restart p2pc-agent" "--force restarts the agent on the new enrollment"
no_token_anywhere "--force"
# The running agent is stopped before join --force (review 4 P3-2, as on Windows): it must not keep the old enrollment
# while the new one is written.
assert_true "--force: the unit is stopped before the join" before 'p2pc@ stop p2pc-agent' 'runuser .* join'
assert_contains "$OUT" "re-enrolling this machine (the same node)" "--force re-enrolls the same node (spec 5)"
assert_false "no more talk of a new node" grep -q 'new node' "$SCRATCH/out"
fd3_clean "--force"
# --force with a refused token: the unit is started again, on the old enrollment
: >"$FAKE_STATE/calls"
STDIN="$SCRATCH/wrong-token" run_installer --from "$rel2" --version 0.1.1 --force
assert_eq "1" "$STATUS" "--force with a refused token fails"
assert_true "--force refused: stopped before the join" before 'p2pc@ stop p2pc-agent' 'runuser .* join'
assert_true "--force refused: started again after it" before 'runuser .* join' 'p2pc@ start p2pc-agent'
assert_contains "$ERR" "started again on the previous enrollment" "and it says so"
assert_true "--force refused: the unit runs again" test -e "$FAKE_STATE/running"
fd3_clean "--force refused"

# --force abandoned at the token prompt (T14b3): the unit was stopped for the join, and an INT, TERM or HUP must start it
# again before the installer exits (it used to leave the node offline).
for sig in INT TERM HUP; do
  : >"$FAKE_STATE/calls"
  touch "$FAKE_STATE/running"
  echo "$sig" >"$FAKE_STATE/join-interrupt"
  STDIN="$token_file" run_installer --from "$rel2" --version 0.1.1 --force
  rm -f "$FAKE_STATE/join-interrupt"
  assert_eq "130" "$STATUS" "--force cut short by $sig: exit 130"
  assert_true "--force $sig: stopped before the join" before 'p2pc@ stop p2pc-agent' 'runuser .* join'
  assert_true "--force $sig: started again after the join was cut" before 'runuser .* join' 'p2pc@ start p2pc-agent'
  assert_true "--force $sig: the unit runs again" test -e "$FAKE_STATE/running"
  assert_eq "1" "$(count_lines 'p2pc@ start p2pc-agent' "$FAKE_STATE/calls")" "--force $sig: started exactly once"
  fd3_clean "--force $sig"
done
# The signal arrives during the stop itself (T14b3 review P3 1): systemd still finishes the stop, so the unit must be
# started again all the same.
: >"$FAKE_STATE/calls"
touch "$FAKE_STATE/running"
echo INT >"$FAKE_STATE/stop-interrupt"
STDIN="$token_file" run_installer --from "$rel2" --version 0.1.1 --force
rm -f "$FAKE_STATE/stop-interrupt"
assert_eq "130" "$STATUS" "--force interrupted during the stop: exit 130"
assert_true "--force interrupted during the stop: started again" test -e "$FAKE_STATE/running"
assert_eq "1" "$(count_lines 'p2pc@ start p2pc-agent' "$FAKE_STATE/calls")" "--force interrupted during the stop: started once"
# Without --force nothing was stopped, so an interrupted join starts nothing.
: >"$FAKE_STATE/calls"
echo TERM >"$FAKE_STATE/join-interrupt"
rm -f "$ROOT/$home_rel/.config/p2pc-agent/agent.toml"
STDIN="$token_file" run_installer --from "$rel2" --version 0.1.1
rm -f "$FAKE_STATE/join-interrupt"
assert_eq "130" "$STATUS" "a first join cut short: exit 130"
assert_false "and the unit was never stopped, so it is not started" grep -q 'p2pc@ start p2pc-agent' "$FAKE_STATE/calls"

# --- a refused token: nothing is started ----------------------------------------------------------------------------------
new_root
STDIN="$SCRATCH/wrong-token" run_installer --from "$rel1"
assert_eq "1" "$STATUS" "a refused token fails the install"
assert_contains "$ERR" "refused the token" "and says why (exit 4)"
assert_false "the service is not enabled" grep -q 'enable p2pc-agent' "$FAKE_STATE/calls"
assert_false "nor started" grep -qE 'p2pc@ (re)?start p2pc-agent' "$FAKE_STATE/calls"
# No token at all (stdin is /dev/null, not a terminal).
new_root
run_installer --from "$rel1"
assert_eq "1" "$STATUS" "no token fails the install"
assert_contains "$ERR" "paste" "and says how to give the token"

# --- a host that is not ready stops before anything is enrolled --------------------------------------------------------------
new_root
touch "$FAKE_STATE/host-not-ready"
STDIN="$token_file" run_installer --from "$rel1"
assert_eq "1" "$STATUS" "a host that is not ready fails the install"
assert_contains "$OUT" "[TODO] podman is not installed" "setup-host.sh's fixes are shown"
assert_contains "$ERR" "not ready" "the error says the host is not ready"
assert_false "nothing enrolled" test -e "$FAKE_STATE/token-sha"
assert_false "no join" grep -q 'join' "$FAKE_STATE/agent-argv" 2>/dev/null
assert_false "the agent is not installed" test -e "$ROOT/usr/local/bin/p2pc-agent"
assert_false "no unit installed" test -e "$ROOT/etc/systemd/user/p2pc-agent.service"
assert_false "the user manager is untouched" grep -q -- '--user' "$FAKE_STATE/calls"

# --- the agent dies right after the start: the install fails with the journal hint --------------------------------------
new_root
touch "$FAKE_STATE/agent-dies"
STDIN="$token_file" run_installer --from "$rel1"
assert_eq "1" "$STATUS" "an agent that does not stay up fails the install"
assert_contains "$ERR" "journalctl _UID=991 _SYSTEMD_USER_UNIT=p2pc-agent.service" "the error says where to look"
assert_contains "$ERR" "exit 1" "and the agent's exit status"
# Exit 7: the server removed the node: the hint is --force with a new token (review P3-8).
new_root
touch "$FAKE_STATE/agent-dies"
echo 7 >"$FAKE_STATE/exec-status"
STDIN="$token_file" run_installer --from "$rel1"
assert_eq "1" "$STATUS" "exit 7: the install fails"
assert_false "exit 7: the service line never claimed running (real run 2)" grep -qE '^    running' "$SCRATCH/out"
assert_contains "$ERR" "--force" "exit 7: points at --force"
assert_contains "$ERR" "join-token create" "exit 7: and at a new token"
# Exit 6: the agent is too old for the server.
new_root
touch "$FAKE_STATE/agent-dies"
echo 6 >"$FAKE_STATE/exec-status"
STDIN="$token_file" run_installer --from "$rel1"
assert_contains "$ERR" "newer release" "exit 6: points at a newer release"
# The agent runs but never connects: a warning after 60 s (fake clock), not a failure; the agent keeps trying.
new_root
echo "connecting (since 2026-11-06T10:00:00Z)" >"$FAKE_STATE/connection"
STDIN="$token_file" run_installer --from "$rel1"
assert_eq "0" "$STATUS" "an agent that is still connecting is not a failure (stderr: $ERR)"
assert_contains "$ERR" "not connected" "but it warns"
assert_true "it waited 60 s at most" test "$(cat "$FAKE_STATE/clock")" -le 1061
assert_true "it polled the status more than once" test "$(grep -c '^agent status' "$FAKE_STATE/agent-argv")" -gt 2

# --- only a connection made since the (re)start counts (review P3-1, as on Windows) ----------------------------------------
# The fake clock is set to 2026-11-06T11:00:00Z; the agent state file says connected since 10:00 (from before).
epoch_11h="$(date -u -d 2026-11-06T11:00:00Z +%s)"
new_root
echo "$epoch_11h" >"$FAKE_STATE/clock"
echo "connected (since 2026-11-06T10:00:00Z)" >"$FAKE_STATE/connection"
STDIN="$token_file" run_installer --from "$rel1"
assert_eq "0" "$STATUS" "a stale connection after the start: not a failure (stderr: $ERR)"
assert_contains "$ERR" "not connected since the start" "but it is not taken as connected: it waits, then warns"
assert_true "it waited (polled more than once)" test "$(grep -c '^agent status' "$FAKE_STATE/agent-argv")" -gt 2
new_root
echo "$epoch_11h" >"$FAKE_STATE/clock"
echo "connected (since 2026-11-06T11:00:03Z)" >"$FAKE_STATE/connection"
STDIN="$token_file" run_installer --from "$rel1"
assert_eq "0" "$STATUS" "a connection since the start (stderr: $ERR)"
assert_false "is taken at once: no warning" grep -q 'not connected' "$SCRATCH/err"
assert_contains "$OUT" "running, connected" "and the service line says so"
# A unit that already ran (a rerun that changes nothing) keeps its agent: its connection from before counts.
echo "connected (since 2026-11-06T10:00:00Z)" >"$FAKE_STATE/connection"
: >"$FAKE_STATE/agent-argv"
STDIN="$token_file" run_installer --from "$rel1"
assert_eq "0" "$STATUS" "rerun, unit already running (stderr: $ERR)"
assert_false "rerun: its current connection is taken, no warning" grep -q 'not connected' "$SCRATCH/err"

# --- checksums: a tampered file is refused before anything is touched ------------------------------------------------------
for f in "p2pc-agent-0.1.0-$target.tar.gz" "p2pc-shim-0.1.0-$target.tar.gz" setup-host.sh p2pc-agent.service; do
  bad="$SCRATCH/dist/bad-$f"
  make_release "$bad" 0.1.0 v1
  printf '\n# tampered\n' >>"$bad/$f"
  new_root
  STDIN="$token_file" run_installer --from "$bad"
  assert_eq "1" "$STATUS" "a tampered $f is refused"
  assert_contains "$ERR" "checksum mismatch for $f" "the error names $f"
  assert_false "setup-host did not run ($f)" grep -q '^setup-host' "$FAKE_STATE/calls"
  assert_false "no agent installed ($f)" test -e "$ROOT/usr/local/bin/p2pc-agent"
  assert_false "no shim installed ($f)" test -e "$ROOT/usr/local/bin/p2pc-shim"
done
bad="$SCRATCH/dist/no-shim"
make_release "$bad" 0.1.0 v1
rm -f "$bad/p2pc-shim-0.1.0-$target.tar.gz"
(cd "$bad" && sha256sum -- *.tar.gz setup-host.sh p2pc-agent.service >SHA256SUMS)
new_root
run_installer --from "$bad"
assert_eq "1" "$STATUS" "a release without p2pc-shim is refused"
assert_contains "$ERR" "p2pc-shim" "and the error names it"
assert_false "nothing installed without the shim" test -e "$ROOT/usr/local/bin/p2pc-agent"
bad="$SCRATCH/dist/unlisted"
make_release "$bad" 0.1.0 v1
grep -v 'setup-host.sh' "$bad/SHA256SUMS" >"$bad/S" && mv "$bad/S" "$bad/SHA256SUMS"
new_root
run_installer --from "$bad"
assert_eq "1" "$STATUS" "a file missing from SHA256SUMS is refused"
assert_contains "$ERR" "setup-host.sh is not listed in SHA256SUMS" "and named"

# --- versions -----------------------------------------------------------------------------------------------------------------
new_root
run_installer --from "$rel1" --version 9.9.9
assert_eq "1" "$STATUS" "an unknown version is refused"
assert_contains "$ERR" "9.9.9" "and named"
run_installer --from "$rel1" --version '0.1.0;id'
assert_eq "1" "$STATUS" "a malformed --version is refused"
# A version taken from SHA256SUMS goes through the same check as --version.
weird="$SCRATCH/dist/weird"
make_release "$weird" 0.1.0 v1
mv "$weird/p2pc-agent-0.1.0-$target.tar.gz" "$weird/p2pc-agent-0.1.0;id-$target.tar.gz"
(cd "$weird" && sha256sum -- *.tar.gz setup-host.sh p2pc-agent.service >SHA256SUMS)
new_root
run_installer --from "$weird"
assert_eq "1" "$STATUS" "a malformed version in SHA256SUMS is refused"
assert_contains "$ERR" "the version in SHA256SUMS does not look like a version" "and the error says why"
both="$SCRATCH/dist/both"
make_release "$both" 0.1.0 v1
make_release "$SCRATCH/dist/both-b" 0.1.1 v2
cp "$SCRATCH/dist/both-b/p2pc-agent-0.1.1-$target.tar.gz" "$both/"
(cd "$both" && sha256sum -- *.tar.gz setup-host.sh p2pc-agent.service >SHA256SUMS)
new_root
run_installer --from "$both"
assert_eq "1" "$STATUS" "two versions without --version are refused"
assert_contains "$ERR" "--version" "and the error asks for --version"

# --- preflight refusals --------------------------------------------------------------------------------------------------------
new_root
FAKE_UID=1000 run_installer --from "$rel1"
assert_eq "1" "$STATUS" "non-root refused"
assert_contains "$ERR" "root" "the error says root"
new_root
rmdir "$ROOT/run/systemd/system"
run_installer --from "$rel1"
assert_eq "1" "$STATUS" "no systemd refused"
assert_contains "$ERR" "systemd" "the error says systemd"
new_root
FAKE_ARCH=riscv64 run_installer --from "$rel1"
assert_eq "1" "$STATUS" "riscv64 refused"
assert_contains "$ERR" "riscv64" "the error names the architecture"
# --- which Linux: the requirements decide, not the name (spec §9.0 "Which Linux") -------------------------------------------
tested_tail="is not a tested platform (tested: Ubuntu 22.04, 24.04, 26.04; Debian 12, 13; Arch Linux); every requirement is met, so the install goes on"
# The platform warnings in a file (stderr, or the install log, whose lines start with a timestamp).
platform_warnings() { grep -o 'warning: .* is not a tested platform.*' "$1" 2>/dev/null || true; }
warnings_in() { platform_warnings "$1" | grep -c . || true; }

for os in 'ID=ubuntu\nVERSION_ID="22.04"' 'ID=ubuntu\nVERSION_ID="24.04"' 'ID=ubuntu\nVERSION_ID="26.04"' \
  'ID=debian\nVERSION_ID="12"' 'ID=debian\nVERSION_ID="13"' 'ID=arch\nBUILD_ID=rolling' \
  'NAME=Omarchy\nID=omarchy\nID_LIKE=arch\nVERSION_ID=4.0.6' 'ID=manjaro\nID_LIKE="arch archlinux"'; do
  new_root
  printf '%b\n' "$os" >"$ROOT/etc/os-release"
  STDIN="$token_file" run_installer --from "$rel1"
  assert_eq "0" "$STATUS" "tested platform [$os] installs (stderr: $ERR)"
  assert_eq "0" "$(warnings_in "$SCRATCH/err")" "tested platform [$os]: no platform warning on stderr"
  assert_eq "0" "$(warnings_in "$ROOT/var/log/p2pc-node-install.log")" "tested platform [$os]: no warning in the log"
done
for os in 'ID=fedora\nVERSION_ID="41"|fedora 41' 'ID=ubuntu\nVERSION_ID="20.04"|ubuntu 20.04'; do
  new_root
  printf '%b\n' "${os%%|*}" >"$ROOT/etc/os-release"
  STDIN="$token_file" run_installer --from "$rel1"
  assert_eq "0" "$STATUS" "other platform [${os##*|}] installs (stderr: $ERR)"
  assert_eq "warning: ${os##*|} $tested_tail" "$(platform_warnings "$SCRATCH/err")" "[${os##*|}]: exactly one warning line, and it names the platform"
  assert_eq "1" "$(warnings_in "$ROOT/var/log/p2pc-node-install.log")" "[${os##*|}]: the warning is in the install log too"
done
new_root
rm -f "$ROOT/etc/os-release"
STDIN="$token_file" run_installer --from "$rel1"
assert_eq "0" "$STATUS" "no os-release installs (stderr: $ERR)"
assert_eq "warning: unknown $tested_tail" "$(platform_warnings "$SCRATCH/err")" "no os-release: one warning, naming unknown"
# Only /usr/lib/os-release (os-release(5)): it is read when /etc/os-release is absent, so a tested platform has no warning.
new_root
rm -f "$ROOT/etc/os-release"
mkdir -p "$ROOT/usr/lib"
printf 'ID=debian\nVERSION_ID="12"\n' >"$ROOT/usr/lib/os-release"
STDIN="$token_file" run_installer --from "$rel1"
assert_eq "0" "$STATUS" "only /usr/lib/os-release installs (stderr: $ERR)"
assert_eq "0" "$(warnings_in "$SCRATCH/err")" "only /usr/lib/os-release: a tested platform, no warning"
new_root
printf 'ID=fedora\nVERSION_ID="41"\n' >"$ROOT/etc/os-release"
mkdir -p "$ROOT/usr/lib"
printf 'ID=debian\nVERSION_ID="12"\n' >"$ROOT/usr/lib/os-release"
STDIN="$token_file" run_installer --from "$rel1"
assert_eq "warning: fedora 41 $tested_tail" "$(platform_warnings "$SCRATCH/err")" "/etc/os-release wins over /usr/lib/os-release"

# Each requirement is checked by itself, and the error names it. Nothing is enrolled or installed before the check.
for missing in runuser useradd sha256sum tar bash systemctl; do
  new_root
  printf 'ID=fedora\nVERSION_ID="41"\n' >"$ROOT/etc/os-release"
  TEST_PATH="$(path_without "$fakebin" "$missing")" STDIN="$token_file" run_installer --from "$rel1"
  assert_eq "1" "$STATUS" "without $missing the install fails"
  assert_contains "$ERR" "$missing is missing" "the error says $missing is missing"
  assert_eq "0" "$(warnings_in "$SCRATCH/err")" "without $missing: no 'every requirement is met' warning"
  assert_false "without $missing: nothing was installed" test -e "$ROOT/usr/local/bin/p2pc-agent"
done
new_root
TEST_PATH="$(path_without "$fakebin" curl wget)" STDIN="$token_file" run_installer --from "$rel1"
assert_eq "1" "$STATUS" "without curl and wget the install fails"
assert_contains "$ERR" "curl" "the error names curl"
assert_contains "$ERR" "wget" "the error names wget"
assert_contains "$ERR" "package manager" "the hint speaks of the package manager"
assert_contains "$ERR" "dnf install curl" "the hint is not only apt"
assert_contains "$ERR" "pacman -S curl" "the hint names pacman too"
new_root
TEST_PATH="$(path_without "$fakebin" wget)" STDIN="$token_file" run_installer --from "$rel1"
assert_eq "0" "$STATUS" "curl alone is enough (stderr: $ERR)"
new_root
TEST_PATH="$(path_without "$fakebin" curl)" STDIN="$token_file" run_installer --from "$rel1"
assert_eq "0" "$STATUS" "wget alone is enough (stderr: $ERR)"

run_installer --bogus
assert_eq "2" "$STATUS" "an unknown option is a usage error"
run_installer --help
assert_eq "0" "$STATUS" "--help"
assert_contains "$OUT" "--purge" "--help lists --purge"
run_installer --purge
assert_eq "2" "$STATUS" "--purge alone is a usage error"
run_installer --from "$rel1" --uninstall
assert_eq "2" "$STATUS" "--uninstall with --from is a usage error"
new_root
run_installer
assert_eq "1" "$STATUS" "no --from and no published releases yet"
assert_contains "$ERR" "--from" "the error points at --from"
new_root
run_installer --from http://example.invalid/p2pc/0.1.0
assert_eq "1" "$STATUS" "plain http is refused"

# --- download from an https URL ------------------------------------------------------------------------------------------------
new_root
STDIN="$token_file" run_installer --from https://example.invalid/p2pc/0.1.0
assert_eq "0" "$STATUS" "install from a URL (stderr: $ERR)"
assert_contains "$(calls)" "--proto =https" "downloads are https only"
no_token_anywhere "URL install"
fd3_clean "URL install (curl)"

# --- uninstall keeps the identity; purge deletes only the agent's own paths ------------------------------------------------------
new_root
STDIN="$token_file" run_installer --from "$rel1"
mkdir -p "$ROOT/$home_rel/.local/share/containers/storage"
echo "an image layer" >"$ROOT/$home_rel/.local/share/containers/storage/layer"
: >"$FAKE_STATE/calls"
run_installer --uninstall
assert_eq "0" "$STATUS" "uninstall succeeds (stderr: $ERR)"
assert_contains "$(calls)" "systemctl --user -M p2pc@ disable --now p2pc-agent" "stopped and disabled"
assert_false "the unit is removed" test -e "$ROOT/etc/systemd/user/p2pc-agent.service"
assert_false "the binary is removed" test -e "$ROOT/usr/local/bin/p2pc-agent"
assert_false "and the shim" test -e "$ROOT/usr/local/bin/p2pc-shim"
assert_true "the identity is kept" test -f "$ROOT/$home_rel/.local/share/p2pc-agent/identity.key"
assert_true "the config (enrollment) is kept" test -f "$ROOT/$home_rel/.config/p2pc-agent/agent.toml"
assert_contains "$OUT" "--purge" "it says how to delete the identity too"
assert_contains "$OUT" "removed /etc/systemd/user/p2pc-agent.service, /usr/local/bin/p2pc-agent and /usr/local/bin/p2pc-shim" "it lists what it removed"
: >"$FAKE_STATE/calls"
run_installer --uninstall
assert_eq "0" "$STATUS" "uninstall twice is harmless"
assert_false "the second uninstall does not disable a unit that is gone" grep -q 'disable --now' "$FAKE_STATE/calls"
assert_false "the second uninstall does not claim to remove what is gone" grep -q 'removed /etc/systemd' "$SCRATCH/out"
assert_contains "$OUT" "nothing to remove" "it says there was nothing left to remove"
assert_eq "" "$ERR" "and warns about nothing (real run: --purge after --uninstall warned)"
# The purge asks first.
printf 'no\n' >"$SCRATCH/no"
STDIN="$SCRATCH/no" run_installer --uninstall --purge
assert_eq "1" "$STATUS" "purge not confirmed is refused"
assert_true "identity kept without confirmation" test -f "$ROOT/$home_rel/.local/share/p2pc-agent/identity.key"
printf 'purge\n' >"$SCRATCH/yes"
STDIN="$SCRATCH/yes" run_installer --uninstall --purge
assert_eq "0" "$STATUS" "typed confirmation purges (stderr: $ERR)"
assert_false "--purge after --uninstall: no disable warning" grep -q 'disable --now' "$SCRATCH/err"
assert_false "the identity is deleted" test -e "$ROOT/$home_rel/.local/share/p2pc-agent"
assert_false "the agent config is deleted" test -e "$ROOT/$home_rel/.config/p2pc-agent"
assert_true "Podman's storage is not the agent's: kept" test -f "$ROOT/$home_rel/.local/share/containers/storage/layer"
assert_true "the home is kept" test -d "$ROOT/$home_rel"
assert_contains "$(calls)" "runuser -u p2pc -- rm -rf --one-file-system --" "the deletion runs as p2pc (no symlink in its home can point root elsewhere)"
assert_contains "$OUT" "userdel" "it says how to remove the rest (the user, Podman's storage)"
fd3_clean "uninstall and the typed purge"
# A purge refuses while the agent runs.
new_root
STDIN="$token_file" run_installer --from "$rel1"
touch "$FAKE_STATE/stop-fails"
run_installer --uninstall --purge --yes
assert_eq "1" "$STATUS" "purge refuses while the agent is still active"
assert_contains "$ERR" "nothing was deleted" "and says nothing was deleted"
assert_true "identity kept while active" test -f "$ROOT/$home_rel/.local/share/p2pc-agent/identity.key"
rm -f "$FAKE_STATE/stop-fails" "$FAKE_STATE/running"
# ... and while a p2pc-agent of p2pc runs outside systemd.
touch "$FAKE_STATE/agent-outside-systemd"
run_installer --uninstall --purge --yes
assert_eq "1" "$STATUS" "purge refuses while p2pc-agent runs outside the unit"
assert_contains "$(calls)" "pgrep -u p2pc -x p2pc-agent" "it looks for the process"
assert_true "identity kept while a process runs" test -f "$ROOT/$home_rel/.local/share/p2pc-agent/identity.key"
rm -f "$FAKE_STATE/agent-outside-systemd"
# A data_dir moved elsewhere in agent.toml is named, never deleted.
sed -i '1i data_dir = "/srv/elsewhere"' "$ROOT/$home_rel/.config/p2pc-agent/agent.toml"
run_installer --uninstall --purge --yes
assert_eq "0" "$STATUS" "--yes purges without asking (stderr: $ERR)"
assert_contains "$ERR" "/srv/elsewhere" "a data_dir outside the defaults is named"
assert_false "the default identity dir is gone" test -e "$ROOT/$home_rel/.local/share/p2pc-agent"
# Without a p2pc user at all, an uninstall still removes our files.
new_root
STDIN="$token_file" run_installer --from "$rel1"
rm -f "$FAKE_STATE/user"
run_installer --uninstall
assert_eq "0" "$STATUS" "uninstall without the p2pc user (stderr: $ERR)"
assert_false "the unit is removed (no user)" test -e "$ROOT/etc/systemd/user/p2pc-agent.service"

# --- p2pc's home comes from the passwd database: the enrollment must land where the unit's agent looks (review P3-2) -----
new_root
echo /home/p2pc >"$FAKE_STATE/home"
STDIN="$token_file" run_installer --from "$rel1"
assert_eq "1" "$STATUS" "a p2pc whose home is not /var/lib/p2pc is refused"
assert_contains "$ERR" "/home/p2pc" "the error names the home it found"
assert_contains "$ERR" "/var/lib/p2pc" "and the one it needs"
assert_false "nothing is enrolled there" grep -q '^agent join' "$FAKE_STATE/agent-argv"
assert_false "the agent is not installed" test -e "$ROOT/usr/local/bin/p2pc-agent"
new_root
STDIN="$token_file" run_installer --from "$rel1"
echo /home/p2pc >"$FAKE_STATE/home"
STDIN="$SCRATCH/yes" run_installer --uninstall --purge --yes
assert_eq "1" "$STATUS" "a purge refuses when p2pc's home moved"
assert_true "and deletes nothing" test -f "$ROOT/$home_rel/.local/share/p2pc-agent/identity.key"
rm -f "$FAKE_STATE/home"

# --- a token-shaped argument is refused before anything, and nothing is echoed (review P3-1) ----------------------------
for args in "--from p2pc_join_testonlyargtoken" "--version p2pc_join_testonlyargtoken" "p2pc_join_testonlyargtoken" \
  "--from $rel1 --p2pc_join_testonlyargtoken"; do
  new_root
  # shellcheck disable=SC2086  # split on purpose: each case is a list of arguments
  run_installer $args
  assert_eq "2" "$STATUS" "a token-shaped argument ($args) is a usage error"
  assert_false "it is not echoed on stderr ($args)" grep -qF 'p2pc_join_testonlyargtoken' "$SCRATCH/err"
  assert_false "nor on stdout ($args)" grep -qF 'p2pc_join_testonlyargtoken' "$SCRATCH/out"
  assert_false "no log is opened ($args)" test -e "$ROOT/var/log/p2pc-node-install.log"
  assert_eq "" "$(calls)" "nothing ran ($args)"
done
new_root
run_installer --from "$rel1" --some-secret-looking-option
assert_eq "2" "$STATUS" "an unknown option is a usage error"
assert_false "an unknown option is never echoed (it could be a secret)" grep -qF 'some-secret-looking-option' "$SCRATCH/err"

# --- the unit ---------------------------------------------------------------------------------------------------------------------
value_of() { sed -n "s/^$1=//p" "$unit_src" | paste -sd' ' -; }
assert_eq "p2pc" "$(value_of ConditionUser)" "ConditionUser"
assert_eq "/usr/local/bin/p2pc-agent run" "$(value_of ExecStart)" "ExecStart"
assert_eq "on-failure" "$(value_of Restart)" "Restart"
assert_eq "6 7 8" "$(value_of RestartPreventExitStatus)" "RestartPreventExitStatus: the agent's terminal exit codes"
assert_eq "default.target" "$(value_of WantedBy)" "WantedBy"
assert_eq "0077" "$(value_of UMask)" "UMask"
assert_false "NoNewPrivileges is not set (newuidmap is setuid)" grep -qE '^NoNewPrivileges=' "$unit_src"
assert_true "and the unit says why" grep -qE '^#.*NoNewPrivileges=yes.*newuidmap' "$unit_src"
for key in SystemCallFilter PrivateUsers ProtectSystem ProtectHome PrivateTmp RestrictNamespaces CapabilityBoundingSet \
  LockPersonality MemoryDenyWriteExecute; do
  assert_false "no $key in a rootless Podman user unit" grep -qE "^$key=" "$unit_src"
done
exit_rs="$here/../../crates/p2pc-agent/src/connection/exit.rs"
for name in AGENT_TOO_OLD NOT_ENROLLED NOT_JOINED; do
  code="$(sed -n "s/^pub const $name: u8 = \([0-9]*\);/\1/p" "$exit_rs")"
  assert_contains " $(value_of RestartPreventExitStatus) " " $code " "RestartPreventExitStatus has $name ($code) from exit.rs"
done
if command -v systemd-analyze >/dev/null 2>&1; then
  printf '#!/bin/sh\nexit 0\n' >"$SCRATCH/p2pc-agent"
  chmod 0755 "$SCRATCH/p2pc-agent"
  sed "s|^ExecStart=/usr/local/bin/p2pc-agent|ExecStart=$SCRATCH/p2pc-agent|" "$unit_src" >"$SCRATCH/p2pc-agent.service"
  verify_out="$(systemd-analyze --user verify --man=no "$SCRATCH/p2pc-agent.service" 2>&1)"
  if [[ "$verify_out" == *"Failed to initialize"* || "$verify_out" == *"Failed to setup"* || "$verify_out" == *"Failed to connect"* || "$verify_out" == *"XDG_RUNTIME_DIR"* ]]; then
    echo "   NOTE: SKIPPED systemd-analyze --user verify: it cannot initialise here ($(head -n 1 <<<"$verify_out"))"
  else
    assert_eq "" "$(grep 'p2pc-agent.service' <<<"$verify_out" || true)" "systemd-analyze --user verify reports nothing about the unit"
  fi
fi

finish_tests "test-install-node"
