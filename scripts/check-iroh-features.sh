#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Spec §10 address hygiene: iroh is built WITHOUT its `portmapper` feature, so nothing in P2PC ever asks the owner's
# router to open a port (UPnP, NAT-PMP, PCP). The builders also disable it at run time (p2pc-net), but the feature
# must stay off at compile time too. This fails if any workspace crate, with any feature combination, turns it on.
set -euo pipefail

cd "$(dirname "$0")/.."
tree="$(cargo tree --locked --workspace --all-features --edges features --invert iroh)"
if ! grep -q 'iroh feature' <<<"$tree"; then
    echo "check-iroh-features: cargo tree printed no iroh features; the check would be vacuous" >&2
    exit 1
fi
if grep -q 'iroh feature "portmapper"' <<<"$tree"; then
    echo "check-iroh-features: iroh's \"portmapper\" feature is enabled; it must stay off (spec §10)" >&2
    grep -n 'portmapper' <<<"$tree" >&2
    exit 1
fi
echo "check-iroh-features: iroh is built without portmapper"
