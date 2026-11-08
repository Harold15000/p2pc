#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs the shell script that install.ps1 uses to archive /var/lib/p2pc (the agent identity) against a scratch tree that
# holds the awkward things: a socket, a FIFO, the boot step's own files. It needs no PowerShell and no WSL: the script is
# taken out of install.ps1 verbatim, with /var/lib pointed at the scratch directory.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
make_scratch
ps1="$here/../wsl/install.ps1"

# shellcheck disable=SC2016  # the pattern is for grep: the $ is a literal PowerShell variable sigil
line="$(grep -E '^\$StateArchiveScript = "' "$ps1")"
# shellcheck disable=SC2016  # same
assert_eq "1" "$(grep -cE '^\$StateArchiveScript = "' "$ps1")" "install.ps1 defines the archive script exactly once, on one line"
script="${line#\$StateArchiveScript = \"}"
script="${script%\"}"
assert_contains "$script" "/var/lib" "the script archives /var/lib/p2pc"
assert_false "the PowerShell string has no characters PowerShell would expand" grep -q '[$`]' <<<"$script"
assert_false "the script has no double quote (it is one PowerShell string)" grep -q '"' <<<"$script"
assert_false "the script has no && (the installer lint keeps PowerShell 5.1 syntax)" grep -q '&&' <<<"$script"
assert_contains "$script" "-cpf @OUT@; sha256sum @OUT@" "the archive goes to a file and is hashed where it is made (stdout carries no binary data)"
assert_false "the script never writes the archive to stdout" grep -q -- '-cpf -' <<<"$script"
script="${script//\/var\/lib/$SCRATCH/lib}"
out="$SCRATCH/out/p2pc-state-test.tar"
mkdir -p "$SCRATCH/out"
script="${script//@OUT@/$out}"

state="$SCRATCH/lib/p2pc"
mkdir -p "$state/jobs/j1" "$state/tmp" "$state/images"
printf 'secret' >"$state/identity.key"
chmod 600 "$state/identity.key"
printf 'cfg' >"$state/jobs/j1/config.json"
printf 'x' >"$state/tmp/nvidia-cdi.abc.yaml"
printf '{}' >"$state/boot-status.json"
printf 'x' >"$state/.boot-status.AbC123"
printf 'with space and "quote"' >"$state/jobs/odd name's \"file\""
ln -s identity.key "$state/link"
mkfifo "$state/jobs/ctl.fifo"
mkfifo "$state/top.fifo"
# A socket file is made with mknod(2), which any user may call with S_IFSOCK: no listening process, no path-length limit.
make_socket() { # make_socket <path>
  python3 -c "import os, stat, sys; os.mknod(sys.argv[1], stat.S_IFSOCK | 0o600)" "$1"
}
if make_socket "$state/agent.sock" 2>/dev/null && make_socket "$state/jobs/j1/run.sock" 2>/dev/null; then
  have_sockets=1
else
  have_sockets=0
  echo "test-install-archive: SKIPPED the socket part (python3 cannot create a socket node here)"
fi
assert_true "the scratch tree really has a FIFO" test -p "$state/top.fifo"
((have_sockets)) && assert_true "the scratch tree really has a socket" test -S "$state/agent.sock"

bash -c "$script" >"$SCRATCH/stdout" 2>"$SCRATCH/err"
assert_eq "0" "$?" "the archive script exits 0 (a socket does not make tar fail or warn)"
assert_eq "" "$(cat "$SCRATCH/err")" "nothing on stderr (no 'socket ignored' warnings)"
assert_eq "$(sha256sum <"$out" | cut -d' ' -f1)  $out" "$(cat "$SCRATCH/stdout")" "stdout is only the SHA-256 line of the archive file, computed where it was made"
assert_eq "600" "$(stat -c %a "$out")" "the archive is created mode 0600 (umask 077): it holds the identity key"
cp "$out" "$SCRATCH/state.tar"
listing="$(tar -tf "$SCRATCH/state.tar" | LC_ALL=C sort)"
assert_contains "$listing" "p2pc/identity.key" "the identity key is archived"
assert_contains "$listing" "p2pc/jobs/j1/config.json" "nested files are archived"
assert_contains "$listing" "p2pc/link" "symlinks are archived"
assert_contains "$listing" 'p2pc/jobs/odd name'"'"'s "file"' "odd file names survive (find -print0 / tar --null)"
for gone in tmp boot-status.json .boot-status.AbC123 top.fifo jobs/ctl.fifo agent.sock jobs/j1/run.sock; do
  assert_false "$gone is not archived" grep -qx -- "p2pc/$gone" <<<"$listing"
done
assert_false "nothing under tmp/ is archived" grep -q '^p2pc/tmp/' <<<"$listing"
assert_eq "p2pc/" "$(grep -x 'p2pc/' <<<"$listing")" "the state directory itself is archived (its mode and owner are restored)"

# Restore into a fresh tree and compare what the installer compares: mode, uid, gid, type and path, minus the ignored
# entries (here: sockets, FIFOs, tmp, boot-status.json, .boot-status.*).
mkdir -p "$SCRATCH/restore/p2pc-parent"
tar --numeric-owner -C "$SCRATCH/restore/p2pc-parent" -xpf "$SCRATCH/state.tar"
list_state() {
  find "$1" ! -type s ! -type p -printf '%m:%U:%G:%y:%P\n' | LC_ALL=C sort | grep -Ev ':(tmp|tmp/.*|boot-status\.json|\.boot-status\..*)$'
}
before="$(list_state "$state")"
after="$(list_state "$SCRATCH/restore/p2pc-parent/p2pc")"
assert_eq "$before" "$after" "the listing before and after the restore is identical (no upgrade fails with exit 26 over a socket or FIFO)"
assert_eq "secret" "$(cat "$SCRATCH/restore/p2pc-parent/p2pc/identity.key")" "the identity key content is restored"
assert_eq "600" "$(stat -c %a "$SCRATCH/restore/p2pc-parent/p2pc/identity.key")" "the identity key mode is restored"

# A failing tar must fail the script (set -o pipefail), so the installer never trusts a partial archive.
failing="${script//--numeric-owner/--no-such-tar-option}"
assert_false "a failing tar fails the script" bash -c "$failing"

# The old command, for contrast: with a socket in the tree the listing and the archive disagree.
if ((have_sockets)); then
  all_before="$(find "$state" -printf '%y:%P\n' | LC_ALL=C sort | grep -c '^s:')"
  assert_eq "2" "$all_before" "(control) a plain find lists both sockets, which no archive could restore"
fi

# The installer must also keep sockets and FIFOs out of its before/after listing.
assert_true "install.ps1 lists the state without sockets and FIFOs" grep -qF "'!', '-type', 's', '!', '-type', 'p'" "$ps1"

# --- the config migration of -Upgrade ($ConfigMigrationScript): an image up to 0.2.1 kept [server] in
# /etc/p2pc/agent.toml, which an upgrade replaces; before the archive is made it is copied into /var/lib/p2pc, so the
# enrollment comes along (T14b2 review P2). Run against scratch trees, with /etc and /var/lib pointed there.
# shellcheck disable=SC2016  # the pattern is for grep: the $ is a literal PowerShell variable sigil
mline="$(grep -E '^\$ConfigMigrationScript = "' "$ps1")"
# shellcheck disable=SC2016  # same
assert_eq "1" "$(grep -cE '^\$ConfigMigrationScript = "' "$ps1")" "install.ps1 defines the migration script exactly once, on one line"
mscript="${mline#\$ConfigMigrationScript = \"}"
mscript="${mscript%\"}"
assert_false "migration: no characters PowerShell would expand" grep -q '[$`]' <<<"$mscript"
assert_false "migration: no double quote" grep -q '"' <<<"$mscript"
assert_false "migration: no &&" grep -q '&&' <<<"$mscript"
assert_false "migration: no || (the PowerShell 7 syntax lint)" grep -q '||' <<<"$mscript"
# run_migration <root>: the script with /etc and /var/lib under <root> (and no chown: the tests do not run as root).
run_migration() {
  local s="$mscript"
  s="${s//\/var\/lib\//$1/var/lib/}"
  s="${s//\/etc\/p2pc\//$1/etc/p2pc/}"
  s="${s//-o 0 -g 0 /}"
  sh -c "$s"
}
m="$SCRATCH/mig-joined"
mkdir -p "$m/var/lib/p2pc" "$m/etc/p2pc"
printf '[server]\nnode_id = "testonly"\n' >"$m/etc/p2pc/agent.toml"
assert_eq "P2PC_CONFIG=moved" "$(run_migration "$m")" "0.2.1, joined: the config is copied"
assert_true "0.2.1, joined: [server] is now in /var/lib/p2pc/agent.toml" grep -q '^\[server\]' "$m/var/lib/p2pc/agent.toml"
assert_eq "600" "$(stat -c %a "$m/var/lib/p2pc/agent.toml")" "and the copy is 0600"
assert_true "the old file stays (the old distro is unchanged if the upgrade stops)" test -s "$m/etc/p2pc/agent.toml"
assert_eq "P2PC_CONFIG=present" "$(run_migration "$m")" "a second run changes nothing"
m="$SCRATCH/mig-new"
mkdir -p "$m/var/lib/p2pc" "$m/etc/p2pc"
printf '[server]\nnode_id = "new"\n' >"$m/var/lib/p2pc/agent.toml"
printf '[server]\nnode_id = "stale"\n' >"$m/etc/p2pc/agent.toml"
assert_eq "P2PC_CONFIG=present" "$(run_migration "$m")" "0.2.2 layout: present"
assert_true "0.2.2 layout: the file in /var/lib/p2pc is never overwritten" grep -q '"new"' "$m/var/lib/p2pc/agent.toml"
m="$SCRATCH/mig-unjoined"
mkdir -p "$m/var/lib/p2pc"
assert_eq "P2PC_CONFIG=created" "$(run_migration "$m")" "0.2.1, never joined: an empty file is created"
assert_true "an empty, 0600 file" test -e "$m/var/lib/p2pc/agent.toml"
assert_eq "600" "$(stat -c %a "$m/var/lib/p2pc/agent.toml")" "and it is 0600"
assert_false "and it holds no [server]" grep -q server "$m/var/lib/p2pc/agent.toml"

finish_tests "test-install-archive"
