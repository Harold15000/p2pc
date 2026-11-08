#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Unit tests for the pure helpers of deploy/wsl/test-distro.sh (parsers and verdict logic). The real checks need a
# distro with Podman; those run on a node (see deploy/README.md).
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
# shellcheck source=deploy/wsl/test-distro.sh
source "$here/../wsl/test-distro.sh"
make_scratch

# --- ini_get ----------------------------------------------------------------------------------------------------
cat >"$SCRATCH/wsl.conf" <<'INI'
# comment
[boot]
systemd=false
command = /usr/local/sbin/p2pc-boot
[automount]
enabled=false
; another comment
[interop]
enabled=false
INI
assert_eq "false" "$(ini_get "$SCRATCH/wsl.conf" boot systemd)" "ini_get simple"
assert_eq "/usr/local/sbin/p2pc-boot" "$(ini_get "$SCRATCH/wsl.conf" boot command)" "ini_get trims spaces around ="
assert_eq "false" "$(ini_get "$SCRATCH/wsl.conf" interop enabled)" "ini_get uses the right section"
assert_false "ini_get missing key" ini_get "$SCRATCH/wsl.conf" boot nope
assert_false "ini_get key in the wrong section" ini_get "$SCRATCH/wsl.conf" boot enabled

# --- status_field / caps -------------------------------------------------------------------------------------------
status=$'Name:\tsh\nCapInh:\t0000000000000000\nCapBnd:\t0000000000000000\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n'
assert_eq "0000000000000000" "$(status_field "$status" CapEff)" "status_field CapEff"
assert_eq "1" "$(status_field "$status" NoNewPrivs)" "status_field NoNewPrivs"
assert_eq "2" "$(status_field "$status" Seccomp)" "status_field Seccomp"
assert_eq "" "$(status_field "$status" Nope)" "status_field missing"
assert_true "all-zero caps" caps_are_zero "0000000000000000"
assert_false "non-zero caps" caps_are_zero "00000000a80425fb"
assert_false "empty caps" caps_are_zero ""

# --- uid_map_remapped ---------------------------------------------------------------------------------------------
assert_true "subuid range" uid_map_remapped $'         0     100000      65536\n'
assert_true "userns=auto style range" uid_map_remapped $'         0 2147483647      1024\n'
assert_false "identity map (host root)" uid_map_remapped $'         0          0 4294967295\n'
assert_false "identity for uid 0 even if split" uid_map_remapped $'         0          0          1\n         1     100000      65535\n'
assert_false "empty map" uid_map_remapped ""

# --- default_gateway_from_route ------------------------------------------------------------------------------------
cat >"$SCRATCH/route" <<'ROUTE'
Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	016433C6	0003	0	0	0	00000000	0	0	0
eth0	006433C6	00000000	0001	0	0	0	00FFFFFF	0	0	0
ROUTE
assert_eq "198.51.100.1" "$(default_gateway_from_route "$SCRATCH/route")" "gateway decoded (little-endian hex)"
printf 'Iface\tDestination\tGateway\tFlags\n' >"$SCRATCH/route-none"
assert_false "no default route" default_gateway_from_route "$SCRATCH/route-none"

# --- pinned image refs --------------------------------------------------------------------------------------------
digest="sha256:$(printf 'ab%.0s' {1..32})"
assert_eq "docker.io/library/alpine@$digest" "$(pinned_ref docker.io/library/alpine:3.20 "$digest")" "pinned_ref drops the tag"
assert_false "empty digest is refused" pinned_ref docker.io/library/alpine:3.20 ""
assert_false "short digest is refused" pinned_ref docker.io/library/alpine:3.20 "sha256:abc"
assert_true "digest-pinned ref accepted" is_digest_ref "docker.io/library/alpine@$digest"
assert_false "tag-only ref rejected" is_digest_ref "docker.io/library/alpine:3.20"

# --- container output parsers --------------------------------------------------------------------------------------
net=$'IFACES=lo \nDEFAULT_ROUTES=0\nCONTROL=ok\nTARGET 192.0.2.1:443=rc:1;secs:0;msg:nc: Network is unreachable\nTARGET 192.0.2.53:53=rc:0;secs:0;msg:\n'
assert_eq "ok" "$(kv_get "$net" CONTROL)" "kv_get"
assert_eq "rc:1;secs:0;msg:nc: Network is unreachable" "$(kv_get "$net" "TARGET 192.0.2.1:443")" "kv_get with spaces in the key"
assert_eq "rc:0;secs:0;msg:" "$(kv_get "$net" "TARGET 192.0.2.53:53")" "kv_get raw probe result"
assert_eq "" "$(kv_get "$net" NOPE)" "kv_get missing"

# --- classify_connect: refused (RST), unreachable and timed out are three different facts ---------------------------
# Fixtures are the real busybox wget messages, measured in `podman run --network=none docker.io/library/busybox:1.36.1`
# (the timeout one on a bridge network) on the Windows node.
refused_raw="rc:1;secs:0;msg:wget: can't connect to remote host (127.0.0.1): Connection refused"
unreach_raw="rc:1;secs:0;msg:wget: can't connect to remote host (192.0.2.53): Network is unreachable"
timeout_raw="rc:1;secs:2;msg:wget: download timed out"
assert_eq "refused" "$(classify_connect "$refused_raw")" "wget refused"
assert_eq "unreachable" "$(classify_connect "$unreach_raw")" "wget unreachable"
assert_eq "unreachable" "$(classify_connect "rc:1;secs:0;msg:wget: can't connect to remote host (198.51.100.1): Network is unreachable")" "wget unreachable, internet target"
assert_eq "timeout" "$(classify_connect "$timeout_raw")" "wget timed out"
# musl (the alpine image the probe runs in) words strerror() differently from glibc: real strings from the Windows node
musl_unreach="rc:1;secs:0;msg:wget: can't connect to remote host (198.51.100.1): Network unreachable"
assert_eq "unreachable" "$(classify_connect "$musl_unreach")" "musl: Network unreachable (internet target)"
assert_eq "unreachable" "$(classify_connect "rc:1;secs:0;msg:wget: can't connect to remote host (192.0.2.1): Network unreachable")" "musl: Network unreachable (gateway)"
assert_eq "unreachable" "$(classify_connect "rc:1;secs:0;msg:wget: can't connect to remote host (192.0.2.53): Network unreachable")" "musl: Network unreachable (tailnet DNS)"
assert_eq "refused" "$(classify_connect "rc:1;secs:0;msg:wget: can't connect to remote host (127.0.0.1): Connection refused")" "refused reads the same in musl"
assert_eq "unreachable" "$(classify_connect "rc:1;secs:0;msg:wget: can't connect to remote host (192.0.2.1): No route to host")" "glibc: No route to host"
assert_eq "unreachable" "$(classify_connect "rc:1;secs:0;msg:wget: can't connect to remote host (192.0.2.1): Host is unreachable")" "musl: Host is unreachable"
assert_eq "timeout" "$(classify_connect "rc:1;secs:3;msg:wget: can't connect to remote host (192.0.2.1): Connection timed out")" "glibc: Connection timed out"
assert_eq "timeout" "$(classify_connect "rc:1;secs:3;msg:wget: can't connect to remote host (192.0.2.1): Operation timed out")" "musl: Operation timed out"
assert_eq "error" "$(classify_connect "rc:1;secs:0;msg:nc: Network unreachable")" "musl text without wget's prefix is not a verdict"
assert_eq "error" "$(classify_connect "rc:1;secs:0;msg:wget: can't connect to remote host (198.51.100.1): Permission denied")" "another strerror() text is an error"
assert_eq "error" "$(classify_connect "rc:1;secs:0;msg:wget: bad address 'unreachable'")" "the word alone, outside the prefix, is an error"
assert_eq "connected" "$(classify_connect 'rc:0;secs:0;msg:')" "exit 0 is a connection"
assert_eq "connected" "$(classify_connect 'rc:1;secs:0;msg:wget: server returned error: HTTP/1.1 404 Not Found')" "an HTTP error needs a TCP connection"
assert_eq "connected" "$(classify_connect 'rc:1;secs:0;msg:wget: error getting response')" "a peer that closes after connecting is connected"
assert_eq "error" "$(classify_connect 'rc:1;secs:0;msg:')" "busybox nc style silence is not a verdict"
assert_eq "error" "$(classify_connect 'rc:1;secs:3;msg:')" "a silent failure is not a timeout either"
assert_eq "error" "$(classify_connect 'rc:127;secs:0;msg:sh: wget: not found')" "a missing tool is an error, never 'blocked'"
assert_eq "error" "$(classify_connect 'rc:1;secs:0;msg:wget: bad address '"'"'x'"'"'')" "an unknown message is an error"
assert_eq "error" "$(classify_connect 'rc:1;secs:0;msg:nc: Network is unreachable')" "only wget's messages count"
assert_eq "error" "$(classify_connect '')" "an empty result is an error"
assert_eq "error" "$(classify_connect 'garbage')" "an unparsable result is an error"
assert_eq "error" "$(classify_connect 'rc:x;secs:y;msg:z')" "non-numeric fields are an error"
assert_true "an expected kind that matches" net_kind_ok unreachable unreachable
assert_false "refused is not unreachable" net_kind_ok unreachable refused
assert_false "timeout is not unreachable" net_kind_ok unreachable timeout
assert_false "connected is not unreachable" net_kind_ok unreachable connected
assert_false "error is not unreachable" net_kind_ok unreachable error
assert_eq "" "$(net_kind_hint unreachable)" "no hint for the expected kind"
assert_contains "$(net_kind_hint connected)" "reachable" "connected hint"
assert_contains "$(net_kind_hint refused)" "RST" "refused hint"
assert_contains "$(net_kind_hint timeout)" "dropped" "timeout hint"

# --- version_ge ---------------------------------------------------------------------------------------------------
assert_true "4.9.3 >= 4.9" version_ge 4.9.3 4.9
assert_true "5.0.0 >= 4.9" version_ge 5.0.0 4.9
assert_false "4.8.9 >= 4.9" version_ge 4.8.9 4.9
assert_true "10.0 >= 9.9" version_ge 10.0 9.9

# --- windows_mounts -------------------------------------------------------------------------------------------------
cat >"$SCRATCH/mounts-clean" <<'M'
/dev/sdc / ext4 rw,relatime 0 0
none /usr/lib/wsl/drivers 9p ro,nosuid,nodev,noatime,aname=drivers;fmask=222 0 0
tmpfs /run tmpfs rw,nosuid 0 0
M
assert_eq "" "$(windows_mounts "$SCRATCH/mounts-clean")" "only the read-only GPU driver store is tolerated"
cat >"$SCRATCH/mounts-dirty" <<'M'
/dev/sdc / ext4 rw,relatime 0 0
C:\134 /mnt/c 9p rw,noatime,aname=drvfs;path=C:\134 0 0
none /usr/lib/wsl/drivers 9p rw,nosuid 0 0
M
assert_eq $'/mnt/c\n/usr/lib/wsl/drivers' "$(windows_mounts "$SCRATCH/mounts-dirty")" "drvfs C: and a read-write driver store are offenders"

# --- cgroup event helpers (measured from the host side; spec 9 \"Memory\") --------------------------------------------------
assert_eq "1" "$(events_value $'low 0\nhigh 0\nmax 0\noom 1\noom_kill 1\noom_group_kill 0' oom_kill)" "events_value reads oom_kill"
assert_eq "0" "$(events_value $'max 0\n' oom_kill)" "events_value: absent key is 0"
assert_eq "7" "$(events_value $'max 7\n' max)" "events_value pids max"
CGROUP_ROOT="$SCRATCH/cgroup"
cg="$(test_cgroup_name mem 4242)"
assert_eq "p2pc-test-mem-4242" "$cg" "test_cgroup_name"
mkdir -p "$CGROUP_ROOT/$cg/libpod-abc" "$CGROUP_ROOT/other"
printf 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n' >"$CGROUP_ROOT/$cg/memory.events"
printf 'low 0\nhigh 0\nmax 0\noom 1\noom_kill 1\n' >"$CGROUP_ROOT/$cg/libpod-abc/memory.events"
printf 'max 0\n' >"$CGROUP_ROOT/$cg/pids.events"
printf 'max 12\n' >"$CGROUP_ROOT/$cg/libpod-abc/pids.events"
printf 'oom_kill 99\n' >"$CGROUP_ROOT/other/memory.events"
assert_eq "1" "$(cgroup_events_max "$CGROUP_ROOT/$cg" memory.events oom_kill)" "oom_kill is found in the container's child cgroup"
assert_eq "12" "$(cgroup_events_max "$CGROUP_ROOT/$cg" pids.events max)" "pids.events max is found in the child cgroup"
assert_eq "0" "$(cgroup_events_max "$CGROUP_ROOT/$cg" memory.events nope)" "unknown key is 0"
assert_eq "0" "$(cgroup_events_max "$CGROUP_ROOT/missing" memory.events oom_kill)" "missing cgroup is 0 (never a false pass)"
assert_false "remove_test_cgroup refuses a foreign name" remove_test_cgroup "other"
assert_false "remove_test_cgroup refuses a path" remove_test_cgroup "../other"
assert_true "a foreign cgroup is untouched" test -f "$CGROUP_ROOT/other/memory.events"
# a real cgroup dir holds only pseudo-files that rmdir drops with the dir; in the scratch tree remove the files first
rm -f "$CGROUP_ROOT/$cg"/*.events "$CGROUP_ROOT/$cg"/libpod-abc/*.events
assert_true "remove_test_cgroup removes the tree (children first)" remove_test_cgroup "$cg"
assert_false "the test cgroup is gone" test -e "$CGROUP_ROOT/$cg"
assert_true "removing a cgroup that is already gone is fine" remove_test_cgroup "$cg"

# --- login_users: the appliance has no login user -----------------------------------------------------------------
cat >"$SCRATCH/passwd-clean" <<'P'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
svc:x:1000:1000::/var/lib/svc:/bin/false
empty:x:1001:1001::/home/empty:
P
assert_eq "" "$(login_users "$SCRATCH/passwd-clean")" "root, system accounts, nobody and nologin/false users are not login users"
cat >"$SCRATCH/passwd-user" <<'P'
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
alice:x:1234:1234::/home/alice:/bin/sh
sys999:x:999:999::/x:/bin/bash
P
assert_eq $'ubuntu\nalice' "$(login_users "$SCRATCH/passwd-user")" "uid >= 1000 with a login shell is reported; uid 999 is not"
printf 'broken line\nweird:x:abc:1::/x:/bin/bash\n' >"$SCRATCH/passwd-bad"
assert_eq "" "$(login_users "$SCRATCH/passwd-bad")" "malformed lines are ignored"

# --- getcap_has: file capabilities survive the image (tar must keep the security.capability xattr) -------------------
assert_true "libcap >= 2.4x format" getcap_has '/usr/bin/ping cap_net_raw=ep' cap_net_raw
assert_true "old libcap format" getcap_has '/usr/bin/ping = cap_net_raw+ep' cap_net_raw
assert_true "among several capabilities" getcap_has '/usr/bin/x cap_net_admin,cap_net_raw=eip' cap_net_raw
assert_false "empty output: the xattr was lost" getcap_has '' cap_net_raw
assert_false "another capability only" getcap_has '/usr/bin/ping cap_net_admin=ep' cap_net_raw
assert_false "a similar name is not the capability" getcap_has '/usr/bin/ping cap_net_raw_x=ep' cap_net_raw

# --- skopeo checks: the agent reads image manifests with `skopeo inspect --raw` before pulling (spec 9, "Images") ---------
assert_true "a manifest list is a manifest" skopeo_manifest_ok '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"digest":"sha256:00"}]}'
assert_true "a single-image manifest is a manifest" skopeo_manifest_ok $'{\n  "schemaVersion": 2,\n  "layers": [ {"size": 1} ]\n}'
assert_false "empty output is not a manifest" skopeo_manifest_ok ''
assert_false "an error message is not a manifest" skopeo_manifest_ok 'FATA[0000] Error parsing image name'
assert_false "JSON without layers or manifests is not a manifest" skopeo_manifest_ok '{"schemaVersion":2}'
assert_true "no such host is a network problem" skopeo_failure_is_network 'FATA[0000] Error parsing image name: pinging container registry registry-1.docker.io: Get "https://registry-1.docker.io/v2/": dial tcp: lookup registry-1.docker.io: no such host'
assert_true "i/o timeout is a network problem" skopeo_failure_is_network 'dial tcp 192.0.2.1:443: i/o timeout'
assert_true "network unreachable is a network problem" skopeo_failure_is_network 'dial tcp 192.0.2.1:443: connect: network is unreachable'
assert_true "connection refused is a network problem" skopeo_failure_is_network 'dial tcp 192.0.2.1:443: connect: connection refused'
assert_true "a context deadline is a network problem" skopeo_failure_is_network 'context deadline exceeded'
assert_true "a temporary failure in name resolution is a network problem" skopeo_failure_is_network 'Temporary failure in name resolution'
assert_false "a missing policy file is not a network problem" skopeo_failure_is_network 'open /etc/containers/policy.json: no such file or directory'
assert_false "an unknown tag is not a network problem" skopeo_failure_is_network 'manifest unknown: manifest unknown'
assert_false "empty output is not a network problem" skopeo_failure_is_network ''

# --- the boot status race: wait for the status of THIS start of the distro (by identity: boot-status.sh) ----------------
# p2pc-boot records the start ticks of the distro's init; the status is fresh when they EQUAL field 22 of /proc/1/stat.
proc1_stat="1 (init) S 0 1 1 0 -1 4194560 100 0 0 0 5 6 0 0 20 0 1 0 12345 4096 100 18446744073709551615"
fresh_json='{"time":"2026-11-05T21:45:13Z","init_starttime":12345,"cdi":"fresh","cdi_regenerated":false,"errors":[],"notes":[]}'
# The previous start's file: another init. Its time is LATER than the fresh one on purpose (the clock stepped after the
# host slept): time no longer decides anything.
old_json='{"time":"2026-11-05T23:59:59Z","init_starttime":12001,"cdi":"fresh","cdi_regenerated":false,"errors":[],"notes":[]}'
legacy_json='{"time":"2026-11-05T21:45:13Z","cdi":"fresh","cdi_regenerated":false,"errors":[],"notes":[]}'
assert_true "the same init: fresh" boot_status_fresh "$fresh_json" 12345
assert_false "another init, even with a later time: not fresh" boot_status_fresh "$old_json" 12345
assert_false "no identity recorded (an older p2pc-boot): not fresh" boot_status_fresh "$legacy_json" 12345
assert_false "the time-based helpers are gone" declare -F proc_start_epoch
# wait_boot_status against a /proc fixture and a scripted poll_sleep (the test never really sleeps)
mkdir -p "$SCRATCH/proc/1"
printf '%s' "$proc1_stat" >"$SCRATCH/proc/1/stat"
export P2PC_PROC="$SCRATCH/proc"
status_file="$SCRATCH/boot-status.json"
SLEEPS=0
poll_sleep() {
  SLEEPS=$((SLEEPS + 1))
  [[ -z "${ON_SLEEP:-}" ]] || "$ON_SLEEP"
  return 0
}
late_status() { # the old file shows up on the 2nd sleep, the new one on the 4th
  if ((SLEEPS == 2)); then printf '%s\n' "$old_json" >"$status_file"; elif ((SLEEPS == 4)); then printf '%s\n' "$fresh_json" >"$status_file"; fi
}
ON_SLEEP=""
printf '%s\n' "$fresh_json" >"$status_file"
SLEEPS=0
assert_true "a fresh status is accepted at once" wait_boot_status "$status_file"
wait_boot_status "$status_file"
assert_eq "0" "$SLEEPS" "no sleep when the status is already fresh"
# missing at first, then the OLD file, then the new one, written on the 4th sleep
rm -f "$status_file"
SLEEPS=0
ON_SLEEP=late_status
wait_boot_status "$status_file"
rc=$?
assert_eq "0" "$rc" "the status that appears late is accepted"
assert_eq "4" "$SLEEPS" "it polled once a second and ignored the stale file in between"
assert_contains "$BOOT_STATUS_TEXT" '"init_starttime":12345' "the accepted text is the new one"
# only ever the old file: gives up after the limit, saying why
printf '%s\n' "$old_json" >"$status_file"
SLEEPS=0
ON_SLEEP=""
wait_boot_status "$status_file"
assert_eq "1" "$?" "a status that never gets fresh is a failure"
assert_eq "$BOOT_STATUS_WAIT_S" "$SLEEPS" "it slept once per second for the whole limit"
assert_eq "30" "$BOOT_STATUS_WAIT_S" "the limit is 30 s"
assert_contains "$BOOT_STATUS_WHY" "previous start" "the failure says the file is from the previous start"
assert_contains "$BOOT_STATUS_WHY" "12001" "and names the recorded init"
assert_contains "$BOOT_STATUS_WHY" "12345" "and this one"
rm -f "$status_file"
SLEEPS=0
wait_boot_status "$status_file"
assert_eq "1" "$?" "no file at all is a failure"
assert_contains "$BOOT_STATUS_WHY" "missing" "the failure says it is missing"
# the init cannot be read (no /proc fixture): the file only has to exist
mkdir -p "$SCRATCH/proc-empty"
printf '%s\n' "$old_json" >"$status_file"
P2PC_PROC="$SCRATCH/proc-empty" wait_boot_status "$status_file"
assert_eq "0" "$?" "without the init's identity an existing status is accepted"
unset P2PC_PROC
poll_sleep() { sleep "$1"; }

# --- boot_status_ok: what each GPU situation requires of p2pc-boot's status ----------------------------------------------
ok_json='{"time":"T","cdi":"fresh","cdi_regenerated":false,"errors":[]}'
smi_json='{"time":"T","cdi":"nvidia_smi_failed","cdi_regenerated":false,"errors":["nvidia-smi -L failed or timed out; the existing CDI spec /etc/cdi/nvidia.yaml was kept as it is"]}'
none_json='{"time":"T","cdi":"no_nvidia_gpu","cdi_regenerated":false,"errors":[],"notes":[]}'
err_json='{"time":"T","cdi":"failed","cdi_regenerated":false,"errors":["nvidia-ctk cdi generate failed (exit 1)"]}'
# retire_stale_cdi could not move the old spec aside: no GPU, and podman still loads devices that do not exist.
retire_failed_json='{"time":"T","cdi":"no_nvidia_gpu","cdi_regenerated":false,"errors":["no NVIDIA GPU, but the old CDI spec /etc/cdi/nvidia.yaml could not be renamed out of the way"],"notes":[]}'
assert_true "GPU expected, clean status" boot_status_ok "$ok_json" 0
assert_false "GPU expected, nvidia_smi_failed" boot_status_ok "$smi_json" 0
assert_false "libcuda but broken nvidia-smi (code 2), nvidia_smi_failed" boot_status_ok "$smi_json" 2
assert_false "GPU expected, errors" boot_status_ok "$err_json" 0
assert_true "no NVIDIA GPU (code 1), no_nvidia_gpu without errors" boot_status_ok "$none_json" 1
assert_false "no NVIDIA GPU (code 1), but the stale spec could not be retired" boot_status_ok "$retire_failed_json" 1
assert_false "no NVIDIA GPU (code 1), but the status claims another CDI state" boot_status_ok "$err_json" 1
assert_false "no NVIDIA GPU (code 1), but the status says fresh" boot_status_ok "$ok_json" 1

# --- the network probe never goes through a proxy -----------------------------------------------------------------------
# Podman copies HTTP(S)_PROXY into the container unless --http-proxy=false (and WSL's autoProxy can set them), and busybox
# wget would then "connect" to the proxy: a blocked network could look reachable, or the other way round.
assert_contains " ${JOB_FLAGS[*]} " " --http-proxy=false " "every test container runs with --http-proxy=false (spec 9)"
assert_contains "$NET_SCRIPT" "wget -Y off" "the probe's wget never uses a proxy"

# --- json output ----------------------------------------------------------------------------------------------------
assert_eq 'say \"hi\"\n' "$(json_escape $'say "hi"\n')" "json_escape"
JSON=1
RESULTS=()
record PASS iso.one "fine" >/dev/null
record FAIL iso.two 'bad "thing"' >/dev/null
record SKIP gpu.x "no gpu" >/dev/null
record INFO iso.binfmt_interop "shared binfmt_misc" >/dev/null
out="$(render_json)"
assert_contains "$out" '"name":"iso.one","status":"PASS"' "json has the pass"
assert_contains "$out" '"status":"FAIL","detail":"bad \"thing\""' "json escapes details"
assert_contains "$out" '"pass":1,"fail":1,"skip":1,"info":1' "json totals"
assert_eq "1" "$(count_status FAIL)" "count_status"
assert_eq "1" "$(count_status INFO)" "an INFO result is counted separately from FAIL"
assert_contains "$out" '"name":"iso.binfmt_interop","status":"INFO"' "json has the info"

# --- the whole script: arguments and refusal paths that need no Podman ------------------------------------------------
assert_false "unknown flag exits non-zero" bash "$here/../wsl/test-distro.sh" --bogus
assert_false "a tag-only --alpine-image is refused" bash "$here/../wsl/test-distro.sh" --alpine-image docker.io/library/alpine:3.20

finish_tests "test-test-distro"
