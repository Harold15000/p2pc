#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs every deploy/tests/test-*.sh in its own bash process. Exits non-zero if any fails.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
status=0
for t in "$here"/test-*.sh; do
  if ! bash "$t"; then
    status=1
  fi
done
exit "$status"
