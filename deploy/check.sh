#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Static checks and unit tests for everything under deploy/. CI runs this; run it before pushing a change to deploy/.
#   deploy/check.sh
# Environment:
#   CHECK_REQUIRE_PWSH=1   fail (instead of skipping) when PowerShell is not installed; CI sets it.
#   CHECK_REQUIRE_SYSTEMD_ANALYZE=1   fail (instead of skipping with a NOTE) when systemd-analyze is not installed
#                                     or cannot initialise (no writable /run) for the server unit; CI sets it.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
status=0
fail() {
  echo "FAIL: $*" >&2
  status=1
}

# scripts/ too: the release script (scripts/release.sh) is tested from deploy/tests/.
mapfile -t shell_files < <(find deploy scripts templates -type f \( -name '*.sh' -o -name 'p2pc-boot' -o -name 'p2pc-run' \) | LC_ALL=C sort)
mapfile -t ps_files < <(find deploy -type f -name '*.ps1' | LC_ALL=C sort)
all_files=("${shell_files[@]}" "${ps_files[@]}")

echo "== files"
printf '   %s\n' "${all_files[@]}"

echo "== bash -n"
for f in "${shell_files[@]}"; do
  bash -n "$f" || fail "bash -n $f"
done

echo "== shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck_cmd=(shellcheck)
elif command -v uvx >/dev/null 2>&1; then
  shellcheck_cmd=(uvx --from shellcheck-py shellcheck)
else
  shellcheck_cmd=()
  fail "neither shellcheck nor uvx is installed"
fi
if ((${#shellcheck_cmd[@]} > 0)); then
  "${shellcheck_cmd[@]}" -x "${shell_files[@]}" || fail "shellcheck reported problems"
fi

echo "== SPDX headers and executable bits"
for f in "${all_files[@]}"; do
  head -n 3 "$f" | grep -q 'SPDX-License-Identifier: Apache-2.0' || fail "missing SPDX header: $f"
done
for f in "${shell_files[@]}"; do
  [[ -x "$f" ]] || fail "not executable: $f"
done
scripts/check-spdx.sh >/dev/null || fail "scripts/check-spdx.sh"

echo "== PowerShell"
for f in "${ps_files[@]}"; do
  # Windows PowerShell 5.1 reads a BOM-less file as the ANSI code page: keep the installer pure ASCII.
  if LC_ALL=C grep -nP '[^\x00-\x7F]' "$f" >/dev/null; then
    fail "$f contains non-ASCII characters (PowerShell 5.1 would misread them)"
  fi
  # Syntax that exists only in PowerShell 7 must not creep in: the target is Windows PowerShell 5.1.
  ps7_only="$(grep -nE '^[^#]*([[:space:]]&&[[:space:]]|[[:space:]]\|\|[[:space:]]|\?\?|\?\.|-AsHashtable|-Parallel)' "$f" || true)"
  if [[ -n "$ps7_only" ]]; then
    printf '%s\n' "$ps7_only" >&2
    fail "$f uses PowerShell 7-only syntax"
  fi
done
if ((${#ps_files[@]} > 0)); then
  if command -v pwsh >/dev/null 2>&1; then
    for f in "${ps_files[@]}"; do
      # shellcheck disable=SC2016  # PowerShell code: nothing here is meant to expand in bash
      P2PC_PS1="$root/$f" pwsh -NoProfile -NonInteractive -Command '
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($env:P2PC_PS1, [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error ("{0}:{1} {2}" -f $env:P2PC_PS1, $_.Extent.StartLineNumber, $_.Message) }; exit 1 }
      ' || fail "PowerShell parse errors in $f"
    done
    # shellcheck disable=SC2016  # PowerShell code
    echo "   parsed with $(pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')"
  elif [[ "${CHECK_REQUIRE_PWSH:-0}" == 1 ]]; then
    fail "pwsh is not installed but CHECK_REQUIRE_PWSH=1"
  else
    echo "   SKIPPED the PowerShell parse check: pwsh is not installed (set CHECK_REQUIRE_PWSH=1 to make this an error)"
  fi
fi

echo "== unit tests"
deploy/tests/run.sh || fail "deploy/tests"

if ((status == 0)); then
  echo "deploy/check.sh: OK"
fi
exit "$status"
