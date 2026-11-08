#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests for deploy/wsl/p2pc-boot: the CDI staleness rule, the status JSON, and the "never blocks, always exits 0"
# contract, driven through a fake nvidia-ctk.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
boot="$here/../wsl/p2pc-boot"
# shellcheck source=deploy/wsl/p2pc-boot
source "$boot"
make_scratch

# --- cdi_needs_regen --------------------------------------------------------------------------------------------
lib="$SCRATCH/wsl-lib"
mkdir -p "$lib"
touch -d '2026-01-01 00:00:00' "$lib/libcuda.so.1.1" "$lib/libdxcore.so"
assert_true "missing spec is stale" cdi_needs_regen "$SCRATCH/nvidia.yaml" "$lib"
: >"$SCRATCH/nvidia.yaml"
assert_true "an empty spec is stale" cdi_needs_regen "$SCRATCH/nvidia.yaml" "$lib"
echo 'cdiVersion: 0.5.0' >"$SCRATCH/nvidia.yaml"
touch -d '2026-06-01 00:00:00' "$SCRATCH/nvidia.yaml"
assert_false "spec newer than every driver library is fresh" cdi_needs_regen "$SCRATCH/nvidia.yaml" "$lib"
touch -d '2026-09-01 00:00:00' "$lib/libcuda.so.1.1"
assert_true "a newer driver library makes the spec stale" cdi_needs_regen "$SCRATCH/nvidia.yaml" "$lib"
ln -s "$lib/libcuda.so.1.1" "$lib/libcuda.so.1"
touch -d '2026-12-01 00:00:00' -h "$lib/libcuda.so.1" # the link itself is newer, the target is not
touch -d '2026-12-01 00:00:00' "$SCRATCH/nvidia.yaml"
assert_false "compares link targets, not the links" cdi_needs_regen "$SCRATCH/nvidia.yaml" "$lib"
assert_false "no driver dir and a spec present: fresh" cdi_needs_regen "$SCRATCH/nvidia.yaml" "$SCRATCH/does-not-exist"

# --- spec paths that no longer exist ----------------------------------------------------------------------------
refdir="$SCRATCH/refs"
mkdir -p "$refdir"
: >"$refdir/libcuda.so.1.1"
: >"$refdir/nvidia-smi"
cat >"$SCRATCH/ref-spec.yaml" <<SPEC
cdiVersion: 0.5.0
kind: nvidia.com/gpu
devices:
  - name: all
    containerEdits:
      deviceNodes:
        - path: $refdir/libcuda.so.1.1
containerEdits:
  hooks:
    - hookName: createContainer
      path: $refdir/nvidia-smi
      args:
        - nvidia-cdi-hook
  mounts:
    - hostPath: "$refdir/libcuda.so.1.1"
      containerPath: /usr/lib/wsl/lib/this-does-not-exist-in-the-distro
      options:
        - ro
    - hostPath: '$refdir/nvidia-smi'
      containerPath: /usr/bin/nvidia-smi
SPEC
touch -d '2027-03-01' "$SCRATCH/ref-spec.yaml"
assert_eq "" "$(cdi_missing_paths "$SCRATCH/ref-spec.yaml")" "every referenced host path exists: nothing missing (containerPath is not checked)"
assert_false "a spec whose paths all exist is fresh" cdi_needs_regen "$SCRATCH/ref-spec.yaml" "$lib"
rm -f "$refdir/libcuda.so.1.1"
assert_eq "$refdir/libcuda.so.1.1" "$(cdi_missing_paths "$SCRATCH/ref-spec.yaml" | sort -u)" "a removed driver library is reported (quoted hostPath, device node path)"
assert_true "a spec that points at a removed library is stale" cdi_needs_regen "$SCRATCH/ref-spec.yaml" "$lib"
: >"$refdir/libcuda.so.1.1"
rm -f "$refdir/nvidia-smi"
assert_true "a removed hook binary (path: of a hook, single-quoted hostPath) makes it stale" cdi_needs_regen "$SCRATCH/ref-spec.yaml" "$lib"
assert_eq "" "$(cdi_missing_paths "$SCRATCH/no-such-spec.yaml")" "an unreadable spec reports nothing (cdi_needs_regen handles 'missing')"

# --- GPU fixtures (the check itself is tested in test-nvidia.sh) -------------------------------------------------
gpu="$SCRATCH/gpu"
mkdir -p "$gpu/amdlib" "$gpu/smi"
: >"$gpu/amdlib/libdxcore.so" # what an Intel or AMD GPU-PV driver ships: no libcuda
cat >"$gpu/smi/smi-ok" <<'FAKE'
#!/usr/bin/env bash
[[ "$1" == -L ]] || exit 64
echo "GPU 0: NVIDIA GeForce RTX 0000 (UUID: GPU-00000000-0000-0000-0000-000000000000)"
FAKE
cat >"$gpu/smi/smi-fail" <<'FAKE'
#!/usr/bin/env bash
echo "NVIDIA-SMI has failed because it could not communicate with the NVIDIA driver." >&2
exit 9
FAKE
cat >"$gpu/smi/smi-hang" <<'FAKE'
#!/usr/bin/env bash
exec sleep 60
FAKE
chmod +x "$gpu"/smi/*

# --- json helpers -----------------------------------------------------------------------------------------------
assert_eq 'a\"b\\c' "$(json_escape 'a"b\c')" "json_escape quotes and backslashes"
assert_eq 'x\ty' "$(json_escape $'x\ty')" "json_escape tab"
NOTES=()
INIT_STARTTIME=4242
assert_eq '{"time":"T","init_starttime":4242,"cdi":"fresh","cdi_regenerated":false,"errors":[],"notes":[]}' "$(status_json T fresh false)" "status_json without errors"
assert_eq '{"time":"T","init_starttime":4242,"cdi":"failed","cdi_regenerated":false,"errors":["boom","two \"q\""],"notes":[]}' \
  "$(status_json T failed false boom 'two "q"')" "status_json with errors"
NOTES=("moved \"x\"" "y")
assert_eq '{"time":"T","init_starttime":4242,"cdi":"no_nvidia_gpu","cdi_regenerated":false,"errors":[],"notes":["moved \"x\"","y"]}' "$(status_json T no_nvidia_gpu false)" "status_json with notes"
NOTES=()
INIT_STARTTIME=""
assert_eq '{"time":"T","init_starttime":null,"cdi":"fresh","cdi_regenerated":false,"errors":[],"notes":[]}' "$(status_json T fresh false)" "an unreadable /proc/1/stat is null, never a guess"
INIT_STARTTIME="12; rm"
assert_contains "$(status_json T fresh false)" '"init_starttime":null' "anything but digits is null"

# --- end to end with a fake nvidia-ctk ----------------------------------------------------------------------------
bin="$SCRATCH/bin"
state="$SCRATCH/state"
etc_cdi="$SCRATCH/cdi"
mkdir -p "$bin"
cat >"$bin/nvidia-ctk-ok" <<'FAKE'
#!/usr/bin/env bash
for a in "$@"; do case "$a" in --output=*) out="${a#--output=}" ;; esac; done
[[ "$*" == *"cdi generate"* && "$*" == *"--mode=wsl"* ]] || exit 64
# Like the real nvidia-ctk: an --output without a .yaml/.json extension gets ".yaml" appended.
case "$out" in *.yaml | *.yml | *.json) ;; *) out="$out.yaml" ;; esac
printf 'cdiVersion: 0.5.0\nkind: nvidia.com/gpu\n' >"$out"
FAKE
cat >"$bin/nvidia-ctk-fail" <<'FAKE'
#!/usr/bin/env bash
for a in "$@"; do case "$a" in --output=*) out="${a#--output=}" ;; esac; done
printf 'partial' >"$out"
printf 'partial' >"$out.yaml"
echo "no GPU" >&2
exit 1
FAKE
cat >"$bin/nvidia-ctk-hang" <<'FAKE'
#!/usr/bin/env bash
exec sleep 60
FAKE
chmod +x "$bin"/*
: >"$SCRATCH/dxg"
mkdir -p "$SCRATCH/proc/1"
echo '1 (init) S 0 1 1 0 -1 4194560 1 2 3 4 5 6 7 8 20 0 1 0 98765 2265088 300 1' >"$SCRATCH/proc/1/stat"

run_boot() { # run_boot <ctk> [extra env...]
  local ctk="$1"
  shift
  env P2PC_BOOT_DXG="$SCRATCH/dxg" P2PC_BOOT_WSL_LIB="$lib" P2PC_BOOT_CDI_SPEC="$etc_cdi/nvidia.yaml" P2PC_PROC="$SCRATCH/proc" \
    P2PC_BOOT_STATE_DIR="$state" P2PC_BOOT_CTK="$ctk" P2PC_BOOT_CTK_TIMEOUT=2 P2PC_BOOT_SMI="$gpu/smi/smi-ok" "$@" bash "$boot"
}

# no /dev/dxg: quiet skip
run_boot "$bin/nvidia-ctk-ok" P2PC_BOOT_DXG="$SCRATCH/no-such-device"
assert_eq "0" "$?" "no GPU: exit 0"
assert_contains "$(cat "$state/boot-status.json")" '"cdi":"skipped"' "no GPU: skipped"
assert_contains "$(cat "$state/boot-status.json")" '"init_starttime":98765,' "the status records the start ticks of this init"
run_boot "$bin/nvidia-ctk-ok" P2PC_BOOT_DXG="$SCRATCH/no-such-device" P2PC_PROC="$SCRATCH/no-proc"
assert_eq "0" "$?" "no /proc/1/stat: still exit 0"
assert_contains "$(cat "$state/boot-status.json")" '"init_starttime":null,' "no /proc/1/stat: null"
assert_false "no GPU: nothing generated" test -e "$etc_cdi/nvidia.yaml"

# /dev/dxg but no libcuda (Intel/AMD GPU-PV): reported cleanly, nothing generated, no error
run_boot "$bin/nvidia-ctk-ok" P2PC_BOOT_WSL_LIB="$gpu/amdlib"
assert_eq "0" "$?" "dxg without libcuda: exit 0"
assert_contains "$(cat "$state/boot-status.json")" '"cdi":"no_nvidia_gpu"' "dxg without libcuda: reported as no NVIDIA GPU"
assert_contains "$(cat "$state/boot-status.json")" '"errors":[]' "dxg without libcuda: not an error"
assert_false "dxg without libcuda: no CDI spec generated" test -e "$etc_cdi/nvidia.yaml"

# A CDI spec left over from when there was an NVIDIA GPU: no libcuda now, so it is moved aside (podman loads only *.yaml)
mkdir -p "$etc_cdi"
printf 'cdiVersion: 0.5.0\nkind: nvidia.com/gpu\n' >"$etc_cdi/nvidia.yaml"
run_boot "$bin/nvidia-ctk-ok" P2PC_BOOT_WSL_LIB="$gpu/amdlib"
assert_eq "0" "$?" "stale spec, no NVIDIA GPU: exit 0"
assert_false "stale spec, no NVIDIA GPU: nvidia.yaml is gone" test -e "$etc_cdi/nvidia.yaml"
assert_eq "1" "$(find "$etc_cdi" -name 'nvidia.yaml.stale-*' | wc -l)" "stale spec, no NVIDIA GPU: renamed to nvidia.yaml.stale-<time>"
assert_eq "0" "$(find "$etc_cdi" -name '*.yaml' -o -name '*.json' | wc -l)" "stale spec, no NVIDIA GPU: podman would load nothing from the CDI dir"
assert_contains "$(cat "$state/boot-status.json")" '"cdi":"no_nvidia_gpu"' "stale spec, no NVIDIA GPU: reported as no NVIDIA GPU"
assert_contains "$(cat "$state/boot-status.json")" '"errors":[]' "stale spec, no NVIDIA GPU: not an error"
assert_contains "$(cat "$state/boot-status.json")" 'renamed to' "stale spec, no NVIDIA GPU: the status notes it"
assert_contains "$(cat "$state/boot-status.json")" 'nvidia.yaml.stale-' "stale spec, no NVIDIA GPU: the note names the new file"
run_boot "$bin/nvidia-ctk-ok" P2PC_BOOT_WSL_LIB="$gpu/amdlib"
assert_contains "$(cat "$state/boot-status.json")" '"notes":[]' "second boot, no spec left: nothing to note"
assert_eq "1" "$(find "$etc_cdi" -name 'nvidia.yaml.stale-*' | wc -l)" "second boot: no second stale file"
rm -f "$etc_cdi"/nvidia.yaml.stale-*
# with libcuda but a broken nvidia-smi the spec is NOT moved (the GPU is expected back)
printf 'cdiVersion: 0.5.0\n' >"$etc_cdi/nvidia.yaml"
run_boot "$bin/nvidia-ctk-ok" P2PC_BOOT_SMI="$gpu/smi/smi-fail"
assert_true "nvidia_smi_failed: the spec stays" test -s "$etc_cdi/nvidia.yaml"
assert_eq "0" "$(find "$etc_cdi" -name 'nvidia.yaml.stale-*' | wc -l)" "nvidia_smi_failed: nothing renamed"
rm -f "$etc_cdi/nvidia.yaml"

# libcuda but nvidia-smi -L fails or hangs: a GPU is expected and it does not work: an error, and nothing is generated
for variant in failing hanging; do
  case "$variant" in
    failing) run_boot "$bin/nvidia-ctk-ok" P2PC_BOOT_SMI="$gpu/smi/smi-fail" ;;
    hanging) run_boot "$bin/nvidia-ctk-ok" P2PC_BOOT_SMI="$gpu/smi/smi-hang" P2PC_SMI_TIMEOUT=1 ;;
  esac
  assert_eq "0" "$?" "$variant nvidia-smi: still exit 0"
  assert_contains "$(cat "$state/boot-status.json")" '"cdi":"nvidia_smi_failed"' "$variant nvidia-smi: reported as nvidia_smi_failed"
  assert_false "$variant nvidia-smi: the error is recorded" grep -q '"errors":\[\]' "$state/boot-status.json"
  assert_contains "$(cat "$state/boot-status.json")" "no CDI spec yet" "$variant nvidia-smi: says no spec exists"
  assert_false "$variant nvidia-smi: no CDI spec generated" test -e "$etc_cdi/nvidia.yaml"
done

# GPU, spec missing: regenerated
run_boot "$bin/nvidia-ctk-ok"
assert_eq "0" "$?" "regen: exit 0"
assert_contains "$(cat "$state/boot-status.json")" '"cdi_regenerated":true' "regen: status says regenerated"
assert_true "regen: spec written" test -s "$etc_cdi/nvidia.yaml"
assert_contains "$(cat "$etc_cdi/nvidia.yaml")" 'cdiVersion' "regen: spec has the generated content"
assert_eq "1" "$(find "$etc_cdi" -type f | wc -l)" "regen: nothing but nvidia.yaml in the CDI dir"
assert_eq "0" "$(find "$state/tmp" -type f | wc -l)" "regen: no temporary file left in the state dir"
assert_eq "0" "$(find "$etc_cdi" -name '.*' | wc -l)" "regen: no hidden file in the CDI dir"
assert_eq "1" "$(wc -l <"$state/boot-status.json")" "status is one line"
assert_eq "700" "$(stat -c %a "$state")" "state dir is 0700"
assert_eq "600" "$(stat -c %a "$state/boot-status.json")" "status file is 0600"

# GPU, spec present, nvidia-smi fails: the existing spec is kept, and the reason says so
cp "$etc_cdi/nvidia.yaml" "$SCRATCH/nvidia.before"
touch -d '2027-06-01' "$lib/libcuda.so.1.1" # a stale spec, which would otherwise be regenerated
run_boot "$bin/nvidia-ctk-ok" P2PC_BOOT_SMI="$gpu/smi/smi-fail"
assert_contains "$(cat "$state/boot-status.json")" '"cdi":"nvidia_smi_failed"' "failing nvidia-smi with a spec: nvidia_smi_failed"
assert_contains "$(cat "$state/boot-status.json")" "existing CDI spec" "failing nvidia-smi with a spec: the reason says it was kept"
assert_eq "$(cat "$SCRATCH/nvidia.before")" "$(cat "$etc_cdi/nvidia.yaml")" "failing nvidia-smi with a spec: the spec is untouched"
touch -d '2026-01-01' "$lib/libcuda.so.1.1"

# GPU, spec fresh: left alone
touch -d '2027-01-01' "$etc_cdi/nvidia.yaml"
run_boot "$bin/nvidia-ctk-fail"
assert_eq "0" "$?" "fresh: exit 0"
assert_contains "$(cat "$state/boot-status.json")" '"cdi":"fresh"' "fresh: not regenerated"
assert_contains "$(cat "$etc_cdi/nvidia.yaml")" 'cdiVersion' "fresh: spec untouched"

# generator fails: exit 0, error recorded, the old spec is kept, no partial file left behind
touch -d '2027-06-01' "$lib/libcuda.so.1.1"
run_boot "$bin/nvidia-ctk-fail"
assert_eq "0" "$?" "failing generator: exit 0"
assert_contains "$(cat "$state/boot-status.json")" '"cdi":"failed"' "failing generator: status"
assert_contains "$(cat "$state/boot-status.json")" 'nvidia-ctk' "failing generator: error mentions nvidia-ctk"
assert_contains "$(cat "$etc_cdi/nvidia.yaml")" 'cdiVersion' "failing generator: previous spec kept"
assert_eq "1" "$(find "$etc_cdi" -type f | wc -l)" "failing generator: nothing added to the CDI dir"
assert_eq "0" "$(find "$state/tmp" -type f | wc -l)" "failing generator: neither \$tmp nor \$tmp.yaml left behind"

# stale temporary specs from older versions are removed (podman would load them as real specs)
printf 'x' >"$etc_cdi/.nvidia-cdi.M9Ivjf.yaml"
printf 'x' >"$etc_cdi/.nvidia-cdi.abc123"
run_boot "$bin/nvidia-ctk-fail"
assert_eq "0" "$?" "stale cleanup: exit 0"
assert_eq "0" "$(find "$etc_cdi" -name '.nvidia-cdi.*' | wc -l)" "stale .nvidia-cdi.* files are deleted"
assert_true "stale cleanup keeps the real spec" test -s "$etc_cdi/nvidia.yaml"

# generator hangs: killed by the timeout, still exit 0
run_boot "$bin/nvidia-ctk-hang" P2PC_BOOT_CTK_TIMEOUT=1
assert_eq "0" "$?" "hanging generator: exit 0"
assert_contains "$(cat "$state/boot-status.json")" 'timed out' "hanging generator: timeout recorded"

# missing nvidia-ctk: exit 0 with an error
run_boot "$SCRATCH/bin/nope"
assert_eq "0" "$?" "missing nvidia-ctk: exit 0"
assert_contains "$(cat "$state/boot-status.json")" 'not found' "missing nvidia-ctk: error recorded"

# unwritable state dir: still exit 0
run_boot "$bin/nvidia-ctk-ok" P2PC_BOOT_STATE_DIR=/proc/p2pc-no-such-dir/x
assert_eq "0" "$?" "unwritable state dir: exit 0"

finish_tests "test-boot"
