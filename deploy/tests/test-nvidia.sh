#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests for deploy/wsl/nvidia.sh, the shared "is there an NVIDIA GPU behind /dev/dxg?" check used by p2pc-boot and
# test-distro.sh, with fixtures: WSL exposes /dev/dxg for every GPU-PV driver, so the device alone proves nothing.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
# shellcheck source=deploy/wsl/nvidia.sh
source "$here/../wsl/nvidia.sh"
make_scratch

# The fakes run bash by its absolute path, so they work under the minimal PATH below.
bash_bin="$(command -v bash)"
gpu="$SCRATCH/gpu"
mkdir -p "$gpu/nvlib" "$gpu/amdlib" "$gpu/emptylib" "$gpu/smi" "$gpu/pathbin"
: >"$gpu/nvlib/libcuda.so.1.1"
ln -s libcuda.so.1.1 "$gpu/nvlib/libcuda.so.1"
ln -s libcuda.so.1 "$gpu/nvlib/libcuda.so"
: >"$gpu/amdlib/libdxcore.so"                 # what an Intel or AMD GPU-PV driver ships: no libcuda
ln -s nowhere.so "$gpu/emptylib/libcuda.so.1" # a dangling link is not a library
cat >"$gpu/smi/smi-ok" <<FAKE
#!$bash_bin
[[ "\$1" == -L ]] || exit 64
echo "GPU 0: NVIDIA GeForce RTX 0000 (UUID: GPU-00000000-0000-0000-0000-000000000000)"
FAKE
cat >"$gpu/smi/smi-fail" <<FAKE
#!$bash_bin
echo "NVIDIA-SMI has failed because it could not communicate with the NVIDIA driver." >&2
exit 9
FAKE
cat >"$gpu/smi/smi-none" <<FAKE # exit 0 but no GPU line
#!$bash_bin
echo "No devices were found"
FAKE
cat >"$gpu/smi/smi-hang" <<'FAKE'
#!/usr/bin/env bash
exec sleep 60
FAKE
chmod +x "$gpu"/smi/*

check() { # check <libdir> [smi]: prints "<rc>:<reason>"
  local out rc
  out="$(nvidia_gpu_check "$@")"
  rc=$?
  printf '%s:%s' "$rc" "$out"
}

assert_eq "0:" "$(check "$gpu/nvlib" "$gpu/smi/smi-ok")" "libcuda and a working nvidia-smi: an NVIDIA GPU (0)"
# 1 = no NVIDIA GPU
assert_contains "$(check "$gpu/amdlib" "$gpu/smi/smi-ok")" "1:no libcuda" "Intel/AMD GPU-PV (no libcuda): 1, and the reason says so"
assert_contains "$(check "$gpu/emptylib" "$gpu/smi/smi-ok")" "1:no libcuda" "a dangling libcuda link is not a library: 1"
assert_contains "$(check "$gpu/does-not-exist" "$gpu/smi/smi-ok")" "1:no libcuda" "no driver directory: 1"
# 2 = libcuda is there but nvidia-smi does not work
assert_contains "$(check "$gpu/nvlib" "$gpu/smi/smi-fail")" "2:nvidia-smi -L failed" "libcuda but nvidia-smi -L fails: 2"
assert_contains "$(check "$gpu/nvlib" "$gpu/smi/smi-none")" "2:nvidia-smi -L lists no GPU" "nvidia-smi -L exits 0 but lists no GPU: 2"
assert_contains "$(check "$gpu/nvlib" "$gpu/smi/nope")" "2:nvidia-smi not found" "nvidia-smi missing: 2"
res="$(P2PC_SMI_TIMEOUT=1 check "$gpu/nvlib" "$gpu/smi/smi-hang")"
assert_contains "$res" "2:nvidia-smi -L failed or timed out" "a hanging nvidia-smi is killed by the timeout: 2"

# lookup order, like the agent's: nvidia-smi on PATH first, then the driver directory
cp "$gpu/smi/smi-ok" "$gpu/nvlib/nvidia-smi" # WSL ships nvidia-smi next to the libraries
cp "$gpu/smi/smi-fail" "$gpu/pathbin/nvidia-smi"
res="$(PATH="$gpu/pathbin:$PATH" check "$gpu/nvlib")"
assert_contains "$res" "2:nvidia-smi -L failed" "nvidia-smi on PATH wins over the one in the driver directory (here the PATH one fails)"
cp "$gpu/smi/smi-ok" "$gpu/pathbin/nvidia-smi"
assert_eq "0:" "$(PATH="$gpu/pathbin:$PATH" check "$gpu/nvlib")" "nvidia-smi on PATH is used when it works"
# "No nvidia-smi on PATH" must really mean none: a PATH made only of a scratch bin dir with the three tools the check
# needs (find, timeout, grep), so a real nvidia-smi on the test machine (/usr/bin/nvidia-smi on a GPU host) cannot
# change the result (T14a2 review).
minbin="$SCRATCH/minbin"
mkdir -p "$minbin"
for tool in find timeout grep; do
  ln -s "$(command -v "$tool")" "$minbin/$tool"
done
assert_eq "find grep timeout" "$(find "$minbin" -mindepth 1 -printf '%f\n' | LC_ALL=C sort | paste -sd' ' -)" "the minimal PATH holds exactly find, timeout and grep"
assert_eq "0:" "$(PATH="$minbin" check "$gpu/nvlib")" "with no nvidia-smi on PATH the driver directory's is used"
rm -f "$gpu/nvlib/nvidia-smi"
assert_contains "$(PATH="$minbin" check "$gpu/nvlib")" "2:nvidia-smi not found" "neither on PATH nor in the driver directory: 2"
assert_eq "0:" "$(PATH="$gpu/pathbin:$PATH" check "$gpu/nvlib" "$gpu/smi/smi-ok")" "an explicit nvidia-smi argument is used as given"

# One definition: both scripts source this file and define no copy of their own.
for f in "$here/../wsl/p2pc-boot" "$here/../wsl/test-distro.sh"; do
  assert_false "$(basename "$f") has no copy of nvidia_gpu_check" grep -q '^nvidia_gpu_check()' "$f"
  assert_true "$(basename "$f") sources nvidia.sh" grep -q 'nvidia.sh' "$f"
done

finish_tests "test-nvidia"
