#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Unit tests for the pure helpers of deploy/wsl/build-rootfs.sh, plus a --dry-run smoke test.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
# shellcheck source=deploy/wsl/build-rootfs.sh
source "$here/../wsl/build-rootfs.sh"
make_scratch

# --- is_valid_version -------------------------------------------------------------------------------------------
assert_true "version 0.1.0" is_valid_version "0.1.0"
assert_true "version with suffix" is_valid_version "1.2.3-rc.1"
assert_false "version empty" is_valid_version ""
assert_false "version path traversal" is_valid_version "../0.1.0"
assert_false "version with space" is_valid_version "0.1 0"
assert_false "version two parts" is_valid_version "0.1"

# --- lock_parse -------------------------------------------------------------------------------------------------
cat >"$SCRATCH/good.lock" <<'LOCK'
# comment

podman=4.9.3+ds1-1ubuntu0.2
crun
nvidia-container-toolkit=1.20.1-1
LOCK
got="$(lock_parse "$SCRATCH/good.lock")"
assert_eq $'podman\t4.9.3+ds1-1ubuntu0.2\ncrun\t\nnvidia-container-toolkit\t1.20.1-1' "$got" "lock_parse good file"

printf 'pod man=1\n' >"$SCRATCH/bad1.lock"
assert_false "lock with space in name" lock_parse "$SCRATCH/bad1.lock"
printf -- '-oHostile=1\n' >"$SCRATCH/bad2.lock"
assert_false "lock name starting with dash" lock_parse "$SCRATCH/bad2.lock"
printf 'podman=1\npodman=2\n' >"$SCRATCH/bad3.lock"
assert_false "lock duplicate name" lock_parse "$SCRATCH/bad3.lock"
printf 'podman=\n' >"$SCRATCH/bad4.lock"
assert_false "lock empty version after =" lock_parse "$SCRATCH/bad4.lock"
printf 'podman=1 2\n' >"$SCRATCH/bad5.lock"
assert_false "lock version with space" lock_parse "$SCRATCH/bad5.lock"

# --- lock_group / lock_apt_args / lock_unpinned ---------------------------------------------------------------
parsed="$(lock_parse "$SCRATCH/good.lock")"
assert_eq $'nvidia-container-toolkit=1.20.1-1' "$(lock_apt_args nvidia <<<"$parsed")" "nvidia group args"
assert_eq $'podman=4.9.3+ds1-1ubuntu0.2\ncrun' "$(lock_apt_args ubuntu <<<"$parsed")" "ubuntu group args (unpinned = bare name)"
assert_eq "crun" "$(lock_unpinned <<<"$parsed")" "unpinned names"
assert_true "toolkit-base is nvidia" lock_is_nvidia "nvidia-container-toolkit-base"
assert_true "libnvidia-container1 is nvidia" lock_is_nvidia "libnvidia-container1"
assert_false "podman is not nvidia" lock_is_nvidia "podman"

# --- lock_pin_versions: re-pins every resolved package, keeps comments and unresolved (NVIDIA) lines -------------------
printf 'crun\t1.14.1-1\npodman\t9.9.9\n' >"$SCRATCH/resolved.tsv"
lock_pin_versions "$SCRATCH/good.lock" "$SCRATCH/resolved.tsv" >"$SCRATCH/new.lock"
assert_eq $'# comment\n\npodman=9.9.9\ncrun=1.14.1-1\nnvidia-container-toolkit=1.20.1-1' "$(cat "$SCRATCH/new.lock")" \
  "lock_pin_versions re-pins resolved packages (bare or pinned), keeps comments and the NVIDIA pin"
assert_eq $'podman\ncrun' "$(lock_apt_names ubuntu <<<"$parsed")" "lock_apt_names: bare names of the ubuntu group"
assert_eq "nvidia-container-toolkit" "$(lock_apt_names nvidia <<<"$parsed")" "lock_apt_names: nvidia group"

# --- snapshot= directive ----------------------------------------------------------------------------------------
cat >"$SCRATCH/snap.lock" <<'LOCK'
# header
snapshot=20261105T000000Z
podman=4.9.3
nvidia-container-toolkit=1.20.1-1
LOCK
assert_eq $'podman\t4.9.3\nnvidia-container-toolkit\t1.20.1-1' "$(lock_parse "$SCRATCH/snap.lock")" "the snapshot line is not a package"
assert_eq "20261105T000000Z" "$(lock_snapshot "$SCRATCH/snap.lock")" "lock_snapshot"
assert_false "a lock without a snapshot line is refused by lock_snapshot" lock_snapshot "$SCRATCH/good.lock"
printf 'snapshot=2026-11-05\npodman=1\n' >"$SCRATCH/snapbad.lock"
assert_false "a malformed snapshot timestamp is refused" lock_parse "$SCRATCH/snapbad.lock"
printf 'snapshot=20261105T000000Z\nsnapshot=20261106T000000Z\n' >"$SCRATCH/snapdup.lock"
assert_false "two snapshot lines are refused" lock_parse "$SCRATCH/snapdup.lock"
printf 'snapshot=20261105T000000\n' >"$SCRATCH/snapnoz.lock"
assert_false "a snapshot without the Z is refused" lock_snapshot "$SCRATCH/snapnoz.lock"
assert_eq "20261105T000000Z" "$(lock_snapshot "$here/../wsl/packages.lock")" "the committed lock has a snapshot"
lock_pin_versions "$SCRATCH/snap.lock" "$SCRATCH/resolved.tsv" 20270101T120000Z >"$SCRATCH/snap-new.lock"
assert_eq "20270101T120000Z" "$(lock_snapshot "$SCRATCH/snap-new.lock")" "lock_pin_versions moves the snapshot"
assert_eq $'# header\nsnapshot=20270101T120000Z\npodman=9.9.9\nnvidia-container-toolkit=1.20.1-1' "$(cat "$SCRATCH/snap-new.lock")" "snapshot replaced in place, others re-pinned"
printf 'podman=1\n' >"$SCRATCH/nosnap.lock"
lock_pin_versions "$SCRATCH/nosnap.lock" "$SCRATCH/resolved.tsv" 20270101T120000Z >"$SCRATCH/nosnap-new.lock"
assert_eq "20270101T120000Z" "$(lock_snapshot "$SCRATCH/nosnap-new.lock")" "a missing snapshot line is added"
src="$(snapshot_sources_content 20261105T000000Z)"
assert_contains "$src" "URIs: https://snapshot.ubuntu.com/ubuntu/20261105T000000Z" "snapshot sources URI"
assert_contains "$src" "Suites: noble noble-updates noble-security" "snapshot sources suites"
assert_contains "$src" "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg" "snapshot sources are signed"

# --- sha256 -----------------------------------------------------------------------------------------------------
printf 'hello\n' >"$SCRATCH/f"
good="5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
assert_eq "$good" "$(sha256_of "$SCRATCH/f")" "sha256_of"
assert_true "verify_sha256 ok" verify_sha256 "$SCRATCH/f" "$good"
assert_true "verify_sha256 is case-insensitive" verify_sha256 "$SCRATCH/f" "${good^^}"
assert_false "verify_sha256 mismatch" verify_sha256 "$SCRATCH/f" "$(printf '0%.0s' {1..64})"
assert_false "verify_sha256 garbage" verify_sha256 "$SCRATCH/f" "nothex"

# --- gpg fingerprints: exactly one primary key, equal to the pin ---------------------------------------------------
colon_ok=$'tru::1:1700000000:0:3:1:5\npub:-:4096:1:DDCAE044F796ECB0:1400000000:::-:::scESC::::::23::0:\nfpr:::::::::C95B321B61E88C1809C4F759DDCAE044F796ECB0:\nuid:-::::1400000000::AAAA::NVIDIA::::::::::0:\nsub:-:4096:1:1111111111111111:1400000000::::::e::::::23:\nfpr:::::::::0123456789012345678901234567890123456789:'
assert_eq "C95B321B61E88C1809C4F759DDCAE044F796ECB0" "$(gpg_primary_fprs <<<"$colon_ok")" "primary fingerprint only (subkey ignored)"
assert_true "fingerprint pin matches" fingerprint_matches "C95B321B61E88C1809C4F759DDCAE044F796ECB0" <<<"$colon_ok"
assert_false "fingerprint pin mismatch" fingerprint_matches "0000000000000000000000000000000000000000" <<<"$colon_ok"
colon_two="$colon_ok"$'\npub:-:4096:1:BBBBBBBBBBBBBBBB:1400000000:::-:::scESC::::::23::0:\nfpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:'
assert_false "a second, unpinned primary key is refused" fingerprint_matches "C95B321B61E88C1809C4F759DDCAE044F796ECB0" <<<"$colon_two"
assert_false "no key at all is refused" fingerprint_matches "C95B321B61E88C1809C4F759DDCAE044F796ECB0" <<<""

# --- path_within ------------------------------------------------------------------------------------------------
mkdir -p "$SCRATCH/root/etc" "$SCRATCH/outside"
ln -s "$SCRATCH/outside" "$SCRATCH/root/escape"
assert_true "path inside root" path_within "$SCRATCH/root" "$SCRATCH/root/etc/wsl.conf"
assert_false "dotdot escapes" path_within "$SCRATCH/root" "$SCRATCH/root/../outside/x"
assert_false "absolute symlink escapes" path_within "$SCRATCH/root" "$SCRATCH/root/escape/x"
assert_false "sibling with same prefix" path_within "$SCRATCH/root" "$SCRATCH/root2/x"

# --- mounts_under (never rm -rf a tree that still has mounts) ------------------------------------------------------
cat >"$SCRATCH/mountinfo" <<'MI'
22 28 0:21 / /proc rw,nosuid shared:14 - proc proc rw
60 28 0:50 / /var/tmp/p2pc-rootfs.abc/rootfs/proc rw - proc proc rw
61 28 0:6 / /var/tmp/p2pc-rootfs.abc/rootfs/dev rw - devtmpfs udev rw
62 28 0:7 / /var/tmp/p2pc-rootfs.abcd/rootfs rw - ext4 /dev/sda rw
MI
assert_eq $'/var/tmp/p2pc-rootfs.abc/rootfs/proc\n/var/tmp/p2pc-rootfs.abc/rootfs/dev' \
  "$(mounts_under /var/tmp/p2pc-rootfs.abc "$SCRATCH/mountinfo")" "mounts_under matches whole path components only"
assert_eq "" "$(mounts_under /var/tmp/none "$SCRATCH/mountinfo")" "mounts_under with none"
# A TMPDIR with a trailing slash, or doubled slashes, gives a non-canonical WORK; mountinfo shows canonical paths.
assert_eq $'/var/tmp/p2pc-rootfs.abc/rootfs/proc\n/var/tmp/p2pc-rootfs.abc/rootfs/dev' \
  "$(mounts_under /var/tmp//p2pc-rootfs.abc/ "$SCRATCH/mountinfo")" "mounts_under copes with a trailing and a doubled slash"
# The kernel writes space, tab, newline and backslash in mount points as octal escapes.
cat >"$SCRATCH/mountinfo-esc" <<'MI'
60 28 0:50 / /var/tmp/p2pc-rootfs.abc/rootfs/my\040dir rw - tmpfs t rw
61 28 0:51 / /var/tmp/p2pc-rootfs.abc/rootfs/tab\011dir rw - tmpfs t rw
62 28 0:52 / /var/tmp/p2pc-rootfs.abc\040x/rootfs rw - tmpfs t rw
63 28 0:53 / /var/tmp/other\134dir rw - tmpfs t rw
MI
assert_eq $'/var/tmp/p2pc-rootfs.abc/rootfs/my dir\n/var/tmp/p2pc-rootfs.abc/rootfs/tab\tdir' \
  "$(mounts_under /var/tmp/p2pc-rootfs.abc "$SCRATCH/mountinfo-esc")" "octal-escaped mount points are decoded; a sibling named 'abc x' is not under 'abc'"
assert_eq "/var/tmp/p2pc-rootfs.abc x/rootfs" "$(mounts_under "/var/tmp/p2pc-rootfs.abc x" "$SCRATCH/mountinfo-esc")" "a directory with a space is found through its \\040"
assert_eq '/var/tmp/other\dir' "$(mounts_under '/var/tmp/other\dir' "$SCRATCH/mountinfo-esc")" "\\134 decodes to a backslash"
assert_eq $'/a/b/c/d\n/a/b/c\n/a/b\n/a' "$(printf '/a\n/a/b\n/a/b/c/d\n/a/b/c\n' | deepest_first)" "deepest_first"
assert_true "valid_work_path: plain" valid_work_path /var/tmp/p2pc-rootfs.abc
assert_false "valid_work_path: space" valid_work_path "/var/tmp/p2pc rootfs"
assert_false "valid_work_path: tab" valid_work_path $'/var/tmp/p2pc\trootfs'
assert_false "valid_work_path: backslash" valid_work_path '/var/tmp/p2pc\rootfs'
assert_false "valid_work_path: relative" valid_work_path var/tmp/x
assert_eq "" "$(live_mounts "$SCRATCH")" "live_mounts: nothing is mounted under a plain scratch dir"
assert_true "live_mounts sees the real /proc mount" test -n "$(live_mounts /proc)"

# --- tar_args: determinism flags ----------------------------------------------------------------------------------
tar_flag_text="$(tar_deterministic_args 1700000000 | tr '\n' ' ')"
assert_contains "$tar_flag_text" "--sort=name" "tar sorts by name"
assert_contains "$tar_flag_text" "--mtime=@1700000000" "tar uses SOURCE_DATE_EPOCH"
assert_contains "$tar_flag_text" "--numeric-owner" "tar uses numeric owners"
assert_contains "$tar_flag_text" "--format=pax" "tar format: pax, the only one that can carry xattrs"
assert_false "no gnu format any more (it drops xattrs)" grep -q -- '--format=gnu' <<<"$tar_flag_text"
assert_contains "$tar_flag_text" "--pax-option=exthdr.name=%d/PaxHeaders/%f" "pax header names do not contain the pid (determinism)"
assert_contains "$tar_flag_text" "--xattrs " "tar packs xattrs"
assert_contains "$tar_flag_text" "--xattrs-include=security.capability " "tar packs only file capabilities"
extract_flag_text="$(tar_extract_args | tr '\n' ' ')"
assert_contains "$extract_flag_text" "--numeric-owner" "unpack keeps numeric owners"
assert_contains "$extract_flag_text" "--xattrs " "unpack restores xattrs"
assert_contains "$extract_flag_text" "--xattrs-include=security.capability " "unpack restores file capabilities"
# Behaviour, not just flags: an xattr survives unpack -> pack -> unpack, the pack is byte-for-byte reproducible, and an
# xattr outside the include pattern is not carried. (Real file capabilities need root; a user.* xattr on the scratch
# filesystem stands in for them by overriding the include pattern, as security.capability is the default.)
xt="$SCRATCH/xattr"
mkdir -p "$xt/src/usr/bin"
printf 'x' >"$xt/src/usr/bin/ping"
printf 'y' >"$xt/src/usr/bin/other"
if python3 -c "import os,sys; os.setxattr(sys.argv[1], 'user.p2pc.cap', b'v1'); os.setxattr(sys.argv[2], 'user.unlisted', b'v2')" \
  "$xt/src/usr/bin/ping" "$xt/src/usr/bin/other" 2>/dev/null; then
  XATTR_INCLUDE='user.p2pc.*'
  mapfile -t pack_args < <(tar_deterministic_args 1700000000)
  tar -C "$xt/src" "${pack_args[@]}" -cf "$xt/a.tar" .
  tar -C "$xt/src" "${pack_args[@]}" -cf "$xt/b.tar" .
  assert_eq "$(sha256_of "$xt/a.tar")" "$(sha256_of "$xt/b.tar")" "pack with xattrs is reproducible (no pid in the headers)"
  mkdir -p "$xt/dst"
  mapfile -t unpack_args < <(tar_extract_args)
  tar "${unpack_args[@]}" -xpf "$xt/a.tar" -C "$xt/dst"
  assert_eq "v1" "$(python3 -c "import os,sys; print(os.getxattr(sys.argv[1], 'user.p2pc.cap').decode())" "$xt/dst/usr/bin/ping")" "the xattr survives pack and unpack"
  assert_false "an xattr outside the include pattern is not carried" python3 -c "import os,sys; os.getxattr(sys.argv[1], 'user.unlisted')" "$xt/dst/usr/bin/other"
  mapfile -t plain_args < <(printf '%s\n' --sort=name --numeric-owner)
  mkdir -p "$xt/lost"
  tar -C "$xt/src" "${plain_args[@]}" -cf "$xt/plain.tar" .
  tar --numeric-owner -xpf "$xt/plain.tar" -C "$xt/lost"
  assert_false "(control) a tar without --xattrs loses the xattr, which is the bug this fixes" python3 -c "import os,sys; os.getxattr(sys.argv[1], 'user.p2pc.cap')" "$xt/lost/usr/bin/ping"
  XATTR_INCLUDE=security.capability
else
  echo "test-build-rootfs: SKIPPED the xattr round trip (this filesystem refuses user.* xattrs or python3 is missing)"
fi
assert_eq "2023-11-14T22:13:20Z" "$(iso8601_utc 1700000000)" "iso8601_utc"

# --- default_source_date_epoch ---------------------------------------------------------------------------------
repo_root="$(cd "$here/../.." && pwd)"
want_ct="$(git -C "$repo_root" log -1 --format=%ct 2>/dev/null || true)"
if [[ "$want_ct" =~ ^[0-9]+$ ]]; then
  assert_eq "$want_ct" "$(default_source_date_epoch "$repo_root" 2>/dev/null)" "the epoch defaults to the commit time"
  assert_eq "$want_ct" "$(default_source_date_epoch "$repo_root/deploy/wsl" 2>/dev/null)" "also from a subdirectory"
fi
mkdir -p "$SCRATCH/not-a-repo"
fallback="$(default_source_date_epoch "$SCRATCH/not-a-repo" 2>"$SCRATCH/epoch.err")"
assert_true "no git checkout: falls back to a number" test "$fallback" -gt 1700000000
assert_contains "$(cat "$SCRATCH/epoch.err")" "WARNING" "the fallback warns that the tar is not reproducible"
assert_eq "1234" "$(SOURCE_DATE_EPOCH=1234 bash "$here/../wsl/build-rootfs.sh" --dry-run 2>&1 | sed -n 's/^  SOURCE_DATE_EPOCH : \([0-9]*\) .*/\1/p')" "an explicit SOURCE_DATE_EPOCH wins"

# --- --archive: snapshot or live, never automatic ---------------------------------------------------------------
assert_eq "snapshot" "$(parse_archive_mode snapshot)" "parse_archive_mode snapshot"
assert_eq "live" "$(parse_archive_mode live)" "parse_archive_mode live"
assert_false "parse_archive_mode rejects auto" parse_archive_mode auto
assert_false "parse_archive_mode rejects empty" parse_archive_mode ""
assert_false "parse_archive_mode is case sensitive" parse_archive_mode Live
live_src="$(archive_sources_content live 20261105T000000Z)"
assert_contains "$live_src" $'URIs: http://archive.ubuntu.com/ubuntu\nSuites: noble noble-updates\n' "live: archive.ubuntu.com for noble and noble-updates"
assert_contains "$live_src" $'URIs: http://security.ubuntu.com/ubuntu\nSuites: noble-security\n' "live: security.ubuntu.com for noble-security"
assert_false "live sources never mention the snapshot service" grep -q snapshot.ubuntu.com <<<"$live_src"
assert_eq "2" "$(grep -c '^Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' <<<"$live_src")" "live: both stanzas are signed"
snap_src="$(archive_sources_content snapshot 20261105T000000Z)"
assert_eq "$(snapshot_sources_content 20261105T000000Z)" "$snap_src" "snapshot mode gives the snapshot sources"
assert_false "snapshot sources never mention the live mirrors" grep -qE 'archive.ubuntu.com|security.ubuntu.com' <<<"$snap_src"
assert_eq "snapshot@20261105T000000Z" "$(archive_record snapshot 20261105T000000Z)" "archive record for a snapshot"
assert_eq "live" "$(archive_record live 20261105T000000Z)" "archive record for live"
assert_contains "$(archive_urls snapshot 20261105T000000Z)" "https://snapshot.ubuntu.com/ubuntu/20261105T000000Z" "archive_urls snapshot"
assert_contains "$(archive_urls live x)" "http://security.ubuntu.com/ubuntu" "archive_urls live"
assert_eq "" "$(ARCHIVE=snapshot archive_build_time_line)" "no build time line for a snapshot"
assert_eq $'\narchive_build_time=2026-01-02T03:04:05Z' "$(ARCHIVE=live ARCHIVE_BUILD_TIME=2026-01-02T03:04:05Z archive_build_time_line)" "build time line for live"
assert_contains "$(live_warning)" "NOT reproducible" "the live warning is explicit"
script="$here/../wsl/build-rootfs.sh"
live_plan="$(bash "$script" --dry-run --archive live 2>&1)"
assert_eq "0" "$?" "--dry-run --archive live exits 0"
assert_contains "$live_plan" "--archive live" "the plan shows the mode"
assert_contains "$live_plan" "http://archive.ubuntu.com/ubuntu" "the plan shows the live URLs"
assert_contains "$live_plan" "NOT reproducible" "the plan carries the warning"
assert_contains "$live_plan" "--error-on=any" "the plan says update stops on fetch errors"
assert_false "the live plan has no pinned Ubuntu package lines" grep -qE '^       (podman|crun|ca-certificates)=' <<<"$live_plan"
assert_contains "$live_plan" "podman  (newest in the live archive; lock pin " "the live plan says the lock pin is ignored"
assert_contains "$live_plan" "nvidia-container-toolkit=1.20.1-1" "the live plan keeps the NVIDIA pin"
update_plan="$(bash "$script" --dry-run --update-lock 2>&1)"
assert_eq "0" "$?" "--dry-run --update-lock exits 0"
assert_contains "$update_plan" "(newest in the new snapshot; lock pin " "the --update-lock plan says the lock pin is ignored"
assert_false "the --update-lock plan has no pinned Ubuntu package lines" grep -qE '^       (podman|crun|ca-certificates)=' <<<"$update_plan"
assert_contains "$update_plan" "nvidia-container-toolkit=1.20.1-1" "the --update-lock plan keeps the NVIDIA pin"
default_plan="$(bash "$script" --dry-run 2>&1)"
assert_contains "$default_plan" "podman=" "the snapshot plan keeps the Ubuntu pins"
assert_contains "$default_plan" "snapshot@20261105T000000Z" "the default is the snapshot"
assert_false "the default plan has no live warning" grep -q 'WARNING: --archive live' <<<"$default_plan"
assert_false "--archive auto is refused" bash "$script" --dry-run --archive auto
assert_false "--archive without a value is refused" bash "$script" --dry-run --archive
assert_false "--update-lock with --archive live is refused" bash "$script" --dry-run --archive live --update-lock

# --- apt_update stops the build on a fetch error and names the URL -----------------------------------------------
# The real functions are kept and put back after each fake: `unset -f` would delete them for the tests that follow.
orig_chroot_run="$(declare -f chroot_run)"
orig_configure_apt_archive="$(declare -f configure_apt_archive)"
chroot_run() { printf '%s\n' "$*" >>"$SCRATCH/chroot.log"; return "${FAKE_APT_RC:-0}"; }
ARCHIVE=snapshot SNAPSHOT_TS=20261105T000000Z
: >"$SCRATCH/chroot.log"
FAKE_APT_RC=0 apt_update "test"
assert_eq "apt-get update --error-on=any" "$(cat "$SCRATCH/chroot.log")" "apt-get update runs with --error-on=any"
apt_msg="$(FAKE_APT_RC=100 apt_update "the Ubuntu archive" 2>&1)"
assert_contains "$apt_msg" "https://snapshot.ubuntu.com/ubuntu/20261105T000000Z" "the error names the snapshot URL"
assert_contains "$apt_msg" "--archive live" "the error mentions the explicit way out"
ARCHIVE=live
apt_msg="$(FAKE_APT_RC=100 apt_update "x" 2>&1)"
assert_contains "$apt_msg" "http://archive.ubuntu.com/ubuntu" "the error names the live URL"
# shellcheck disable=SC2016  # the single-quoted script runs in the child shell
assert_false "apt_update exits non-zero on failure" bash -c 'source "$1"; chroot_run() { echo FAKE-CALLED >&2; return 100; }; ARCHIVE=live SNAPSHOT_TS=x apt_update x 2>&1 | grep -q FAKE-CALLED; exit "${PIPESTATUS[0]}"' _ "$here/../wsl/build-rootfs.sh"
unset -f chroot_run; eval "$orig_chroot_run"
eval "$orig_chroot_run"

# --- T14d: apt retries for the build only, and live mode without Ubuntu pins ----------------------------------------
assert_contains "$(apt_retries_content)" 'Acquire::Retries "5";' "the build's apt configuration has the retries"
assert_contains "$(apt_retries_content)" 'Acquire::http::Timeout "30";' "the build's apt configuration has a timeout"
ROOTFS="$SCRATCH/rootfs-apt" WORK="$SCRATCH/work-apt" ARCHIVE=snapshot SNAPSHOT_TS=20261105T000000Z
mkdir -p "$ROOTFS/etc/apt/sources.list.d"
: >"$ROOTFS/etc/apt/sources.list.d/ubuntu.sources"
configure_apt_archive >/dev/null 2>&1
assert_true "during the build the retries file is in apt.conf.d" test -f "$ROOTFS/etc/apt/apt.conf.d/99p2pc-retries"
assert_contains "$(cat "$ROOTFS/etc/apt/apt.conf.d/99p2pc-retries")" 'Acquire::Retries "5"' "the file carries the retries"
restore_apt_sources
assert_false "the final rootfs has no retries file" test -e "$ROOTFS/etc/apt/apt.conf.d/99p2pc-retries"
assert_false "the final rootfs has no snapshot apt file" test -e "$ROOTFS/etc/apt/apt.conf.d/99p2pc-snapshot"
ARCHIVE=live
configure_apt_archive >/dev/null 2>&1
assert_true "live mode also has the retries file" test -f "$ROOTFS/etc/apt/apt.conf.d/99p2pc-retries"
restore_apt_sources
assert_false "live: the final rootfs has no retries file" test -e "$ROOTFS/etc/apt/apt.conf.d/99p2pc-retries"

pins_lock="$(printf 'podman=4.9.3+ds1-1ubuntu0.2\nca-certificates=20260816ubuntu0.24.04.1\nnvidia-container-toolkit=1.20.1-1\n')"
pins_parsed="$(lock_parse <(printf 'snapshot=20261105T000000Z\n%s\n' "$pins_lock"))"
UPDATE_LOCK=0
ARCHIVE=snapshot
assert_eq $'podman=4.9.3+ds1-1ubuntu0.2\nca-certificates=20260816ubuntu0.24.04.1' "$(ubuntu_install_args <<<"$pins_parsed")" "snapshot: Ubuntu args carry their pins"
assert_eq "nvidia-container-toolkit=1.20.1-1" "$(lock_apt_args nvidia <<<"$pins_parsed")" "snapshot: NVIDIA args carry their pin"
UPDATE_LOCK=1 ARCHIVE=snapshot
assert_eq $'podman\nca-certificates' "$(ubuntu_install_args <<<"$pins_parsed")" "--update-lock: Ubuntu args are bare names, the pins are ignored"
assert_eq "nvidia-container-toolkit=1.20.1-1" "$(lock_apt_args nvidia <<<"$pins_parsed")" "--update-lock: NVIDIA args keep their pin"
UPDATE_LOCK=0
ARCHIVE=live
assert_eq $'podman\nca-certificates' "$(ubuntu_install_args <<<"$pins_parsed")" "live: Ubuntu args carry no =version"
assert_eq "nvidia-container-toolkit=1.20.1-1" "$(lock_apt_args nvidia <<<"$pins_parsed")" "live: NVIDIA args keep their pin"
ARCHIVE=snapshot

# The wiring: what install_ubuntu_packages / install_nvidia_packages really hand to `apt-get install`.
LOCK_ENTRIES="$pins_parsed"
chroot_run() { printf '%s\n' "$*" >>"$SCRATCH/wire.log"; }
configure_apt_archive() { :; }
# shellcheck disable=SC2317  # called by install_nvidia_packages
curl() {
  local prev="" last=""
  for last in "$@"; do
    [[ "$prev" == --output ]] && : >"$last"
    prev="$last"
  done
}
# shellcheck disable=SC2317  # called by install_nvidia_packages
gpg() {
  local prev="" a
  for a in "$@"; do
    [[ "$prev" == --output ]] && : >"$a"
    prev="$a"
  done
  printf 'pub:-:255:22:%s:1:::::\nfpr:::::::::%s:\n' "${NVIDIA_KEY_FPR: -16}" "$NVIDIA_KEY_FPR"
}
for mode in snapshot live; do
  ARCHIVE=$mode UPDATE_LOCK=0 ROOTFS="$SCRATCH/rootfs-wire-$mode" WORK="$SCRATCH/work-wire-$mode"
  mkdir -p "$ROOTFS" "$WORK"
  : >"$SCRATCH/wire.log"
  install_ubuntu_packages >/dev/null 2>&1
  install_nvidia_packages >/dev/null 2>&1
  ubuntu_line="$(grep '^apt-get install' "$SCRATCH/wire.log" | sed -n 1p)"
  nvidia_line="$(grep '^apt-get install' "$SCRATCH/wire.log" | sed -n 2p)"
  assert_contains "$nvidia_line" "nvidia-container-toolkit=1.20.1-1" "$mode: the NVIDIA install line keeps its pin"
  if [[ "$mode" == live ]]; then
    assert_eq "apt-get install -y --no-install-recommends podman ca-certificates" "$ubuntu_line" "live: the Ubuntu install line has bare names"
  else
    assert_eq "apt-get install -y --no-install-recommends podman=4.9.3+ds1-1ubuntu0.2 ca-certificates=20260816ubuntu0.24.04.1" "$ubuntu_line" "snapshot: the Ubuntu install line has the pins"
  fi
done
unset -f curl gpg
eval "$orig_chroot_run"
eval "$orig_configure_apt_archive"
ARCHIVE=snapshot

# A live build's manifest: archive=live and the versions that were resolved.
chroot_run() { printf 'podman\t5.0.0-live\nca-certificates\t20261101\n'; }
ARCHIVE=live ARCHIVE_BUILD_TIME=2026-01-02T03:04:05Z AGENT_PATH="" AGENT_FROM="" SHIM_PATH="" IMAGE_VERSION=9.9.9 SOURCE_DATE_EPOCH=1700000000
write_manifest "$SCRATCH/live-manifest.txt"
unset -f chroot_run; eval "$orig_chroot_run"
live_manifest="$(cat "$SCRATCH/live-manifest.txt")"
assert_contains "$live_manifest" "# archive=live" "the live manifest records archive=live"
assert_contains "$live_manifest" $'podman\t5.0.0-live' "the live manifest records the resolved versions"
assert_contains "$live_manifest" "archive_build_time=2026-01-02T03:04:05Z" "the live manifest records the build time"
ARCHIVE=snapshot

help_text="$(bash "$script" --help 2>&1)"
assert_contains "$help_text" "--archive MODE" "--help documents --archive"
assert_contains "$help_text" "never rewrites packages.lock" "--help says live never rewrites the lock"
ARCHIVE=snapshot
chroot_run() { return 100; }
assert_contains "$(apt_update x 2>&1)" "--archive live" "the apt_update error names --archive live"
assert_contains "$(apt_update x 2>&1)" "never chosen automatically" "the error says it is never automatic"
unset -f chroot_run; eval "$orig_chroot_run"

# --- remove_rootfs_file: the OOBE config of the Ubuntu base must go ----------------------------------------------
ROOTFS="$SCRATCH/rootfs-rm"
mkdir -p "$ROOTFS/etc" "$SCRATCH/outside-rm"
printf '[oobe]\ncommand=/usr/lib/wsl/wsl-setup\ndefaultUid=1000\n' >"$ROOTFS/etc/wsl-distribution.conf"
printf 'keep\n' >"$ROOTFS/etc/wsl.conf"
remove_rootfs_file /etc/wsl-distribution.conf
assert_false "wsl-distribution.conf is removed" test -e "$ROOTFS/etc/wsl-distribution.conf"
assert_true "other files are left alone" test -e "$ROOTFS/etc/wsl.conf"
remove_rootfs_file /etc/wsl-distribution.conf
assert_true "removing a file that is already gone is fine" true
# a symlink is removed, not followed
printf 'precious\n' >"$SCRATCH/outside-rm/target"
ln -s "$SCRATCH/outside-rm/target" "$ROOTFS/etc/wsl-distribution.conf"
remove_rootfs_file /etc/wsl-distribution.conf
assert_false "a symlink at that path is removed" test -L "$ROOTFS/etc/wsl-distribution.conf"
assert_true "and its target is untouched" test -e "$SCRATCH/outside-rm/target"
# an /etc that is a symlink out of the rootfs is refused
rm -rf "${ROOTFS:?}/etc"
ln -s "$SCRATCH/outside-rm" "$ROOTFS/etc"
printf 'x\n' >"$SCRATCH/outside-rm/wsl-distribution.conf"
# shellcheck disable=SC2016  # the single-quoted script runs in the child shell
assert_false "an /etc that escapes the rootfs is refused" bash -c 'source "$1"; ROOTFS="$2"; remove_rootfs_file /etc/wsl-distribution.conf' _ "$here/../wsl/build-rootfs.sh" "$ROOTFS"
assert_true "and nothing outside was deleted" test -e "$SCRATCH/outside-rm/wsl-distribution.conf"
unset ROOTFS

# --- is_elf ---------------------------------------------------------------------------------------------------
assert_true "bash is an ELF file" is_elf "$(command -v bash)"
assert_false "a text file is not ELF" is_elf "$SCRATCH/f"

# --- --dry-run: full plan, no root, no network, no side effects ------------------------------------------------
plan="$(bash "$repo_root/deploy/wsl/build-rootfs.sh" --dry-run --version 9.9.9 --out "$SCRATCH/out" 2>&1)"
rc=$?
assert_eq "0" "$rc" "dry-run exit code"
for needle in "bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e" "ubuntu-24.04.5-wsl-amd64.wsl" \
  "p2pc-node-9.9.9.tar.gz" "manifest.txt" "/etc/wsl.conf" "/etc/containers/containers.conf.d/p2pc.conf" \
  "containers:2147483647:2147483648" "/usr/local/sbin/p2pc-boot" "/etc/p2pc-distro-version" "nvidia-container-toolkit" \
  "--sort=name" "mode 0700" "C95B321B61E88C1809C4F759DDCAE044F796ECB0"; do
  assert_contains "$plan" "$needle" "dry-run plan mentions $needle"
done
assert_contains "$plan" "/usr/local/lib/p2pc/nvidia.sh" "dry-run installs the shared NVIDIA check"
assert_true "the builder installs nvidia.sh into the image" grep -qF '/usr/local/lib/p2pc/nvidia.sh"' "$repo_root/deploy/wsl/build-rootfs.sh"
assert_contains "$plan" $'       nvidia-container-toolkit=1.20.1-1\n' "dry-run prints a pinned entry once, as name=version"
assert_contains "$plan" $'       libnvidia-container1=1.20.1-1\n' "dry-run lists every pinned NVIDIA package"
assert_contains "$plan" $'       podman=4.9.3+ds1-1ubuntu0.2\n' "dry-run lists the pinned Ubuntu packages"
assert_eq $'       crun  (UNPINNED)' "$(plan_entry crun "")" "plan_entry flags an unpinned entry"
assert_eq $'       crun=1.2' "$(plan_entry crun 1.2)" "plan_entry prints name=version"
# The committed lock must be fully pinned: a normal build refuses bare names.
assert_eq "" "$(lock_parse "$here/../wsl/packages.lock" | lock_unpinned)" "packages.lock has no unpinned entries"
# skopeo: the agent reads the remote manifest with `skopeo inspect --raw` before pulling (spec 9, "Images"), because
# Podman 4.9 cannot inspect a single-image OCI manifest. It must be in the image, pinned.
assert_true "packages.lock pins skopeo to an exact version" grep -Eq '^skopeo=[^[:space:]]+$' "$here/../wsl/packages.lock"
assert_contains "$plan" "       skopeo=" "dry-run lists the pinned skopeo"
assert_contains "$plan" "nvidia-container-toolkit-base=1.20.1-1" "toolkit-base pinned"
assert_contains "$plan" "libnvidia-container-tools=1.20.1-1" "libnvidia-container-tools pinned"
assert_contains "$plan" "https://snapshot.ubuntu.com/ubuntu/20261105T000000Z" "dry-run shows the Ubuntu snapshot"
assert_contains "$plan" "apt-get -y upgrade" "dry-run shows the upgrade against the snapshot"
assert_false "dry-run does not warn about unpinned entries" grep -q WARNING <<<"$plan"
assert_false "dry-run creates nothing" test -e "$SCRATCH/out"
assert_false "bad --version is refused" bash "$repo_root/deploy/wsl/build-rootfs.sh" --dry-run --version "../x"
assert_false "unknown flag is refused" bash "$repo_root/deploy/wsl/build-rootfs.sh" --dry-run --nope
# shellcheck disable=SC2016  # the single-quoted script is meant to expand in the child shell
assert_false "non-root real build is refused" bash -c '[[ $EUID -ne 0 ]] && exec bash "$1" --out "$2"; exit 1' _ "$repo_root/deploy/wsl/build-rootfs.sh" "$SCRATCH/out2"

# --- T14b2: what the image carries for the agent ------------------------------------------------------------------
assert_eq "0.2.2" "$DEFAULT_IMAGE_VERSION" "the image version was bumped (0.2.2: the agent config in /var/lib/p2pc)"
default_plan="$(bash "$script" --dry-run 2>&1)"
assert_contains "$default_plan" "p2pc-node-0.2.2.tar.gz" "the default image version is 0.2.2"
assert_contains "$default_plan" "/var/lib/p2pc/agent.toml" "the plan names the agent config in /var/lib/p2pc"
# shellcheck disable=SC2016  # the literal text of the builder's line
assert_true "the builder writes it 0600" grep -qF 'write_rootfs_file 0600 /var/lib/p2pc/agent.toml' "$script"
assert_eq "" "$(agent_config_content | grep -v '^#')" "it holds no setting (the built-in defaults), only comments"
assert_eq "0" "$(grep -c '/etc/p2pc/agent.toml' <<<"$(sed -n '/^write_configuration()/,/^}/p' "$script" | grep -v '^[[:space:]]*#')")" "the image writes no /etc/p2pc/agent.toml"
for needle in "/usr/local/sbin/p2pc-run" "/usr/local/lib/p2pc/boot-status.sh" "/var/log/p2pc"; do
  assert_contains "$plan" "$needle" "dry-run plan installs $needle"
done
for src in p2pc-run boot-status.sh; do
  assert_true "the builder installs $src into the image" grep -qF "\"\$SCRIPT_DIR/$src\"" "$script"
done
# H2 §8.5: p2pc-run replaces p2pc-node-run, whose path stays as a symlink for one release (an existing task, and
# p2pc-wsl's task XML, still run /usr/local/sbin/p2pc-node-run).
assert_false "the old runner is no longer a file of the checkout" test -e "$repo_root/deploy/wsl/p2pc-node-run"
assert_contains "$plan" "/usr/local/sbin/p2pc-node-run -> p2pc-run" "the plan keeps the old path as a symlink to p2pc-run"
# shellcheck disable=SC2016  # the literal text of the builder's line
assert_true "the builder makes that symlink (relative, inside the rootfs)" grep -qF 'ln -s p2pc-run "$ROOTFS/usr/local/sbin/p2pc-node-run"' "$script"
assert_false "the image does not create /var/lib/p2pc-server (p2pc-server init does, 0700; an upgrade compares listings)" \
  grep -q 'var/lib/p2pc-server' <<<"$(sed -n '/^write_configuration()/,/^}/p' "$script" | grep -v '^[[:space:]]*#')"

# --- --agent-from: the agent comes from the release dist, checked against SHA256SUMS --------------------------------
target="x86_64-unknown-linux-musl"
# make_dist <dir> <version...>: a release dir with a p2pc-agent tarball per version (the binary is a copy of an ELF).
make_dist() {
  local dir="$1" v stem
  shift
  mkdir -p "$dir"
  for v in "$@"; do
    for bin in p2pc-agent p2pc-shim; do
      stem="$bin-$v-$target"
      mkdir -p "$SCRATCH/stage/$stem"
      # Two different ELF files, so the tests can tell which one landed where.
      if [[ "$bin" == p2pc-agent ]]; then cp "$(type -P true)" "$SCRATCH/stage/$stem/$bin"; else cp "$(type -P false)" "$SCRATCH/stage/$stem/$bin"; fi
      tar -C "$SCRATCH/stage" -czf "$dir/$stem.tar.gz" "$stem"
    done
  done
  (cd "$dir" && sha256sum -- p2pc-agent-*.tar.gz p2pc-shim-*.tar.gz >SHA256SUMS)
}
make_dist "$SCRATCH/dist1" 0.1.0
assert_eq "p2pc-agent-0.1.0-$target.tar.gz" "$(dist_agent_tarball "$SCRATCH/dist1/SHA256SUMS" "")" "the only agent in SHA256SUMS"
assert_eq "p2pc-agent-0.1.0-$target.tar.gz" "$(dist_agent_tarball "$SCRATCH/dist1/SHA256SUMS" 0.1.0)" "the agent of --agent-version"
assert_false "an agent version that is not listed" dist_agent_tarball "$SCRATCH/dist1/SHA256SUMS" 0.9.9
assert_true "a listed tarball with the right hash verifies" dist_verify "$SCRATCH/dist1" "p2pc-agent-0.1.0-$target.tar.gz"
make_dist "$SCRATCH/dist2" 0.1.0 0.1.1
assert_false "two versions and no --agent-version: refused" dist_agent_tarball "$SCRATCH/dist2/SHA256SUMS" ""
assert_eq "p2pc-agent-0.1.1-$target.tar.gz" "$(dist_agent_tarball "$SCRATCH/dist2/SHA256SUMS" 0.1.1)" "two versions: --agent-version picks one"
assert_false "a malformed version in SHA256SUMS is refused" dist_agent_tarball <(echo "$(printf '0%.0s' {1..64})  p2pc-agent-0.1.0;x-$target.tar.gz") ""
agent_plan="$(bash "$script" --dry-run --agent-from "$SCRATCH/dist1" 2>&1)"
assert_eq "0" "$?" "--dry-run --agent-from exits 0"
assert_contains "$agent_plan" "p2pc-agent-0.1.0-$target.tar.gz" "the plan names the tarball"
assert_contains "$agent_plan" "verified against $SCRATCH/dist1/SHA256SUMS" "the plan says it was verified"
assert_contains "$agent_plan" "$(sha256_of "$SCRATCH/dist1/p2pc-agent-0.1.0-$target.tar.gz")" "and shows its SHA-256"
assert_contains "$agent_plan" "p2pc-shim-0.1.0-$target.tar.gz" "the plan names the shim tarball of the same version"
assert_contains "$agent_plan" "$(sha256_of "$SCRATCH/dist1/p2pc-shim-0.1.0-$target.tar.gz")" "and its SHA-256"
assert_contains "$agent_plan" "/usr/local/bin/p2pc-shim" "the plan installs p2pc-shim next to the agent"
assert_eq "p2pc-shim-0.1.0-$target.tar.gz" "$(dist_shim_tarball "p2pc-agent-0.1.0-$target.tar.gz")" "the shim tarball has the agent version"
cp -r "$SCRATCH/dist1" "$SCRATCH/dist-badshim"
printf 'x' >>"$SCRATCH/dist-badshim/p2pc-shim-0.1.0-$target.tar.gz"
assert_false "a tampered shim tarball is refused, even in a dry run" bash "$script" --dry-run --agent-from "$SCRATCH/dist-badshim"
cp -r "$SCRATCH/dist1" "$SCRATCH/dist-noshim"
rm "$SCRATCH/dist-noshim/p2pc-shim-0.1.0-$target.tar.gz"
(cd "$SCRATCH/dist-noshim" && grep -v p2pc-shim SHA256SUMS >S && mv S SHA256SUMS)
noshim_plan="$(bash "$script" --dry-run --agent-from "$SCRATCH/dist-noshim" 2>&1)"
assert_eq "1" "$?" "a dist without p2pc-shim is refused (the agent would take no lease)"
assert_contains "$noshim_plan" "p2pc-shim" "and the error names it"
cp -r "$SCRATCH/dist1" "$SCRATCH/dist-bad"
printf 'x' >>"$SCRATCH/dist-bad/p2pc-agent-0.1.0-$target.tar.gz"
bad_plan="$(bash "$script" --dry-run --agent-from "$SCRATCH/dist-bad" 2>&1)"
assert_eq "1" "$?" "a tampered agent tarball is refused, even in a dry run"
assert_contains "$bad_plan" "SHA-256 mismatch" "and says why"
assert_false "--agent-from a dir without SHA256SUMS is refused" bash "$script" --dry-run --agent-from "$SCRATCH"
assert_false "--agent and --agent-from together are refused" bash "$script" --dry-run --agent "$(type -P true)" --agent-from "$SCRATCH/dist1"
assert_false "--agent-version without --agent-from is refused" bash "$script" --dry-run --agent-version 0.1.0
assert_false "--agent-from with two versions and no --agent-version is refused" bash "$script" --dry-run --agent-from "$SCRATCH/dist2"
assert_true "--agent-from with two versions and --agent-version" bash "$script" --dry-run --agent-from "$SCRATCH/dist2" --agent-version 0.1.1
assert_false "the plan of a build without the agent says so" grep -q 'verified against' <<<"$default_plan"
assert_false "dry-run with --agent-from creates nothing" test -e "$SCRATCH/out"
# The hash the work-dir copy is checked against is the one in SHA256SUMS, never a new hash of the dist file (review
# P3-4): a file swapped after the first check could otherwise vouch for itself.
listed="$(dist_sum "$SCRATCH/dist1/SHA256SUMS" "p2pc-agent-0.1.0-$target.tar.gz")"
assert_eq "$listed" "$(verified_dist_sum "$SCRATCH/dist1" "p2pc-agent-0.1.0-$target.tar.gz")" "verified_dist_sum gives the SHA256SUMS hash"
assert_false "verified_dist_sum refuses a tampered file" verified_dist_sum "$SCRATCH/dist-bad" "p2pc-agent-0.1.0-$target.tar.gz"
assert_false "verified_dist_sum refuses a file SHA256SUMS does not list" verified_dist_sum "$SCRATCH/dist-noshim" "p2pc-shim-0.1.0-$target.tar.gz"
# shellcheck disable=SC2016  # the literal text the builder must not contain
assert_eq "0" "$(grep -c 'sha256_of "$AGENT_FROM/' "$script")" "the builder never re-hashes a dist file to get the expected hash"
# The real build: the verified tarball is copied into the work dir, checked again, and the binary taken out of it.
extracted="$(
  WORK="$SCRATCH/work-x" AGENT_FROM="$SCRATCH/dist1" AGENT_TARBALL="p2pc-agent-0.1.0-$target.tar.gz"
  AGENT_TARBALL_SHA="$(sha256_of "$SCRATCH/dist1/$AGENT_TARBALL")"
  extract_dist_agent 2>/dev/null && printf '%s' "$AGENT_PATH"
)"
assert_eq "$SCRATCH/work-x/agent/x/p2pc-agent-0.1.0-$target/p2pc-agent" "$extracted" "the agent is extracted into the work dir"
assert_true "and it is the binary of the tarball" cmp -s "$extracted" "$(type -P true)"
extracted_shim="$(
  WORK="$SCRATCH/work-s" AGENT_FROM="$SCRATCH/dist1" AGENT_TARBALL="p2pc-agent-0.1.0-$target.tar.gz"
  AGENT_TARBALL_SHA="$(sha256_of "$SCRATCH/dist1/$AGENT_TARBALL")"
  SHIM_TARBALL="p2pc-shim-0.1.0-$target.tar.gz" SHIM_TARBALL_SHA="$(sha256_of "$SCRATCH/dist1/p2pc-shim-0.1.0-$target.tar.gz")"
  extract_dist_agent 2>/dev/null && printf '%s' "$SHIM_PATH"
)"
assert_true "the shim is extracted too, and it is the shim of the tarball" cmp -s "$extracted_shim" "$(type -P false)"
# shellcheck disable=SC2016  # the literal text of the builder's install line
assert_true "the builder installs the shim next to the agent" grep -qF '"$ROOTFS/usr/local/bin/p2pc-shim"' "$script"
assert_false "a tarball that changed after the check is refused" bash -c "
  source '$script'; WORK='$SCRATCH/work-y' AGENT_FROM='$SCRATCH/dist1' AGENT_TARBALL='p2pc-agent-0.1.0-$target.tar.gz'
  AGENT_TARBALL_SHA=$(printf '0%.0s' {1..64}); extract_dist_agent"

finish_tests "test-build-rootfs"
