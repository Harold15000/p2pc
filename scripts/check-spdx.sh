#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fails if a source file lacks an SPDX header, or carries the wrong license for its crate.
# Usage: scripts/check-spdx.sh   (run from anywhere; it works on the repository root)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
status=0

# All Rust sources and shell scripts, excluding build output and vendored trees.
while IFS= read -r -d '' file; do
  rel="${file#"$root"/}"
  header="$(head -n 3 "$file" | grep -m1 -o 'SPDX-License-Identifier: [A-Za-z0-9.+-]*' || true)"
  if [[ -z "$header" ]]; then
    echo "missing SPDX header: $rel" >&2
    status=1
    continue
  fi
  expected="Apache-2.0"
  if [[ "$rel" == crates/p2pc-server/* ]]; then
    expected="AGPL-3.0-only"
  fi
  found="${header#SPDX-License-Identifier: }"
  if [[ "$found" != "$expected" ]]; then
    echo "wrong SPDX license ($found, expected $expected): $rel" >&2
    status=1
  fi
done < <(find "$root" \
  \( -path "$root/target" -o -path "$root/.git" -o -path "$root/.claude" -o -path "$root/sdk/python/.venv" \) -prune -o \
  -type f \( -name '*.rs' -o -name '*.sh' \) -print0)

if [[ $status -eq 0 ]]; then
  echo "SPDX headers OK"
fi
exit $status
