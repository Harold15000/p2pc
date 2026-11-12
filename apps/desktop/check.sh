#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Gates of the desktop app crate (apps/desktop/src-tauri, crate `p2pc-desktop`). The crate is its own workspace,
# excluded from the root one, because its Tauri glue (feature `app`) needs a webview toolkit (WebKitGTK on Linux,
# WebView2 on Windows). Not run by CI (H2 T2-42); run it by hand before a change to apps/desktop is merged.
#
# Usage:
#   apps/desktop/check.sh          fmt, clippy, tests and cargo-deny without the Tauri glue (any machine)
#   apps/desktop/check.sh --app    also clippy and build with the `app` feature (needs WebKitGTK or WebView2)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
manifest="$here/src-tauri/Cargo.toml"
# Under the repository's ignored target/ (scripts/check-spdx.sh skips it), not under src-tauri/.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target/desktop}"

with_app=0
case "${1:-}" in
  "") ;;
  --app) with_app=1 ;;
  *)
    echo "usage: $0 [--app]" >&2
    exit 2
    ;;
esac

cargo fmt --manifest-path "$manifest" --check
cargo clippy --locked --manifest-path "$manifest" --all-targets -- -D warnings
cargo test --locked --manifest-path "$manifest"
# The root policy. Its graph has `all-features = true`, so Tauri's tree is checked too. Licenses, bans and sources on
# every target of deny.toml; advisories on the shipped target, Windows: on Linux, Tauri's GTK and D-Bus stack pulls
# crates with "unmaintained" notices (RUSTSEC-2024-0370 proc-macro-error, RUSTSEC-2026-0370/0371/0372 zvariant,
# zbus_names, zvariant_derive; no known vulnerability) that deny.toml does not ignore. See apps/desktop/README.md.
deny=(cargo deny --manifest-path "$manifest" --config "$root/deny.toml")
"${deny[@]}" check licenses bans sources
"${deny[@]}" --target x86_64-pc-windows-msvc check advisories

if [[ $with_app -eq 1 ]]; then
  cargo clippy --locked --manifest-path "$manifest" --all-targets --features app -- -D warnings
  cargo test --locked --manifest-path "$manifest" --features app
  cargo build --locked --manifest-path "$manifest" --features app
fi

echo "apps/desktop: OK"
