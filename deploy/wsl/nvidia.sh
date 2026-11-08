#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# nvidia.sh: the one definition of "is there an NVIDIA GPU behind /dev/dxg?", shared by p2pc-boot and test-distro.sh.
# The image installs it as /usr/local/lib/p2pc/nvidia.sh (build-rootfs.sh); both scripts source it from there, or from
# the directory they sit in when run from a checkout (deploy/wsl/), or from $P2PC_NVIDIA_LIB. Sourcing only defines
# functions.

# nvidia_gpu_check <libdir> [nvidia-smi]: classifies the GPU WSL passes through. WSL exposes /dev/dxg for every GPU-PV
# driver (Intel and AMD integrated GPUs included), so the device alone proves nothing. It prints the reason on stdout
# when the answer is not 0, and returns:
#   0  an NVIDIA GPU: a libcuda.so* under <libdir> (the Windows driver's CUDA library, which Intel and AMD do not ship)
#      AND `nvidia-smi -L` exits 0 listing at least one "GPU n:" line
#   1  no NVIDIA GPU: there is no libcuda.so* under <libdir>
#   2  an NVIDIA driver is there (libcuda is) but nvidia-smi is missing, fails, hangs (killed after
#      $P2PC_SMI_TIMEOUT seconds, default 10) or lists no GPU: a GPU is expected here and it does not work
# nvidia-smi is looked up like the agent does: the [nvidia-smi] argument if given, else `nvidia-smi` on PATH, else
# <libdir>/nvidia-smi.
nvidia_gpu_check() {
  local libdir="$1" smi="${2:-}" out
  if [[ -z "$(find -L "$libdir" -maxdepth 1 -name 'libcuda.so*' -type f -print -quit 2>/dev/null)" ]]; then
    echo "no libcuda.so* in $libdir"
    return 1
  fi
  if [[ -z "$smi" ]]; then
    if command -v nvidia-smi >/dev/null 2>&1; then
      smi=nvidia-smi
    else
      smi="$libdir/nvidia-smi"
    fi
  fi
  if [[ "$smi" == */* ]]; then
    [[ -x "$smi" ]] || {
      echo "nvidia-smi not found at $smi"
      return 2
    }
  else
    command -v "$smi" >/dev/null 2>&1 || {
      echo "nvidia-smi not found in PATH"
      return 2
    }
  fi
  out="$(timeout --kill-after=2 "${P2PC_SMI_TIMEOUT:-10}" "$smi" -L 2>/dev/null)" || {
    echo "nvidia-smi -L failed or timed out"
    return 2
  }
  grep -q '^GPU [0-9]' <<<"$out" || {
    echo "nvidia-smi -L lists no GPU"
    return 2
  }
  return 0
}
