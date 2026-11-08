#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests for scripts/release.sh that run in CI time: the tarballs are deterministic (listing, owners, modes, mtimes,
# gzip header), the licenses are the right ones, SHA256SUMS is well formed, the builder is chosen as documented and
# a dry run builds nothing. The real build (and its reproducibility check) runs with:
#   scripts/release.sh --check-reproducible
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/tests/lib.sh
source "$here/lib.sh"
# shellcheck source=scripts/release.sh
source "$here/../../scripts/release.sh"
make_scratch
release="$here/../../scripts/release.sh"
target="x86_64-unknown-linux-musl"
epoch=1793919889

# --- package_binary is deterministic -------------------------------------------------------------------------------------
printf '\177ELF fake server binary\n' >"$SCRATCH/p2pc-server"
printf '\177ELF fake cli binary\n' >"$SCRATCH/p2pc"
printf 'THIRD-PARTY LICENSES (fake)\n' >"$SCRATCH/tpl"
mkdir -p "$SCRATCH/a" "$SCRATCH/b"
assert_true "package the server" package_binary "$SCRATCH/p2pc-server" p2pc-server 0.1.0 "$target" "$epoch" "$SCRATCH/a" "$SCRATCH/tpl"
assert_true "package the CLI" package_binary "$SCRATCH/p2pc" p2pc 0.1.0 "$target" "$epoch" "$SCRATCH/a" "$SCRATCH/tpl"
# Same inputs, but another umask, other mtimes and another mode on the input: the bytes must not change.
touch -d '2001-02-03 04:05:06' "$SCRATCH/p2pc-server"
chmod 0600 "$SCRATCH/p2pc-server"
(umask 077 && package_binary "$SCRATCH/p2pc-server" p2pc-server 0.1.0 "$target" "$epoch" "$SCRATCH/b" "$SCRATCH/tpl")
(umask 002 && LC_ALL=C.UTF-8 package_binary "$SCRATCH/p2pc" p2pc 0.1.0 "$target" "$epoch" "$SCRATCH/b" "$SCRATCH/tpl")
tarball="p2pc-server-0.1.0-$target.tar.gz"
assert_eq "$(sha256sum <"$SCRATCH/a/$tarball")" "$(sha256sum <"$SCRATCH/b/$tarball")" "the server tarball is byte-identical"
assert_eq "$(sha256sum <"$SCRATCH/a/p2pc-0.1.0-$target.tar.gz")" "$(sha256sum <"$SCRATCH/b/p2pc-0.1.0-$target.tar.gz")" \
  "the CLI tarball is byte-identical"

listing="$(TZ=UTC tar --numeric-owner --full-time -tvzf "$SCRATCH/a/$tarball" | awk '{ print $1, $2, $4, $5, $6 }')"
stamp="$(TZ=UTC date -u -d "@$epoch" '+%Y-%m-%d %H:%M:%S')"
stem="p2pc-server-0.1.0-$target"
expected="drwxr-xr-x 0/0 $stamp $stem/
-rw-r--r-- 0/0 $stamp $stem/LICENSE
-rw-r--r-- 0/0 $stamp $stem/README
-rw-r--r-- 0/0 $stamp $stem/THIRD-PARTY-LICENSES
-rwxr-xr-x 0/0 $stamp $stem/p2pc-server"
assert_eq "$expected" "$listing" "sorted names, owner 0/0, fixed modes, mtime = SOURCE_DATE_EPOCH"
# gzip header (RFC 1952): no file name (FLG.FNAME, bit 3) and MTIME = 0, so `gzip -n` really was used.
read -r -a header < <(od -An -tu1 -N8 "$SCRATCH/a/$tarball")
assert_eq "0" "$((header[3] & 8))" "no file name in the gzip header"
assert_eq "0 0 0 0" "${header[4]} ${header[5]} ${header[6]} ${header[7]}" "no mtime in the gzip header"

# --- contents: binary, its license and a README line --------------------------------------------------------------------
mkdir -p "$SCRATCH/x"
tar -xzf "$SCRATCH/a/$tarball" -C "$SCRATCH/x"
tar -xzf "$SCRATCH/a/p2pc-0.1.0-$target.tar.gz" -C "$SCRATCH/x"
assert_true "the binary is intact" cmp -s "$SCRATCH/p2pc-server" "$SCRATCH/x/$stem/p2pc-server"
assert_true "THIRD-PARTY-LICENSES is shipped as given" cmp -s "$SCRATCH/tpl" "$SCRATCH/x/$stem/THIRD-PARTY-LICENSES"
assert_false "a missing THIRD-PARTY-LICENSES is an error" package_binary "$SCRATCH/p2pc" p2pc 0.1.0 "$target" "$epoch" "$SCRATCH/b" "$SCRATCH/nope"
assert_true "the server is AGPL-3.0" grep -q 'GNU AFFERO GENERAL PUBLIC LICENSE' "$SCRATCH/x/$stem/LICENSE"
assert_true "the CLI is Apache-2.0" grep -q 'Apache License' "$SCRATCH/x/p2pc-0.1.0-$target/LICENSE"
assert_false "and not AGPL" grep -q 'AFFERO' "$SCRATCH/x/p2pc-0.1.0-$target/LICENSE"
assert_eq "1" "$(wc -l <"$SCRATCH/x/$stem/README")" "the README is one line"
assert_contains "$(cat "$SCRATCH/x/$stem/README")" "p2pc-server 0.1.0 ($target)" "the README names the binary"
assert_contains "$(cat "$SCRATCH/x/$stem/README")" "AGPL-3.0-only" "the README names the license"
assert_eq "Apache-2.0" "$(license_id p2pc-agent)" "the agent is Apache-2.0"
assert_eq "Apache-2.0" "$(license_id p2pc-shim)" "the shim is Apache-2.0"

# --- THIRD-PARTY-LICENSES from cargo metadata and the crates' own license files ------------------------------------------
# A fixture of `cargo metadata --filter-platform` output: app -> alpha, beta, ws-lib (a workspace member) -> gamma, and
# beta -> delta -> netwatch. app also has a dev-dependency and a build-dependency, which are not in the binary.
gen="$here/../../scripts/third-party-licenses.py"
reg="$SCRATCH/registry"
crate() { mkdir -p "$reg/$1"; printf '[package]\nname = "%s"\n' "$1" >"$reg/$1/Cargo.toml"; }
crate alpha && printf 'MIT License\nCopyright (c) Alpha Authors\n' >"$reg/alpha/LICENSE-MIT" && printf 'Alpha NOTICE\n' >"$reg/alpha/NOTICE"
crate beta && printf 'Apache text of beta\r\n' >"$reg/beta/LICENSE-APACHE" && printf 'MIT text of beta\n' >"$reg/beta/license-mit"
crate gamma && mkdir -p "$reg/gamma/docs" && printf 'Gamma license via license-file\n' >"$reg/gamma/docs/LIC.txt"
crate delta && mkdir -p "$reg/delta/LICENSES" && printf 'Delta REUSE text\n' >"$reg/delta/LICENSES/MIT.txt"
crate netwatch
crate nolicense && printf 'not a license\n' >"$reg/nolicense/README.md"
crate devonly && printf 'dev\n' >"$reg/devonly/LICENSE"
crate builder && printf 'build\n' >"$reg/builder/LICENSE"
mkdir -p "$reg/app" "$reg/ws-lib" "$SCRATCH/licenses"
printf 'PLAIN APACHE-2.0 TEXT\n' >"$SCRATCH/licenses/Apache-2.0.txt"
src='"registry+https://github.com/rust-lang/crates.io-index"'
pkg() { # id name version license source manifest [license_file]
  local lf=null
  [[ -n "${7:-}" ]] && lf="\"$7\""
  printf '{"id":"%s","name":"%s","version":"%s","license":%s,"license_file":%s,"source":%s,"manifest_path":"%s/Cargo.toml"}' \
    "$1" "$2" "$3" "$4" "$lf" "$5" "$6"
}
dep() { printf '{"pkg":"%s","dep_kinds":[{"kind":%s,"target":null}]}' "$1" "$2"; }
node() { local id="$1"; shift; local IFS=,; printf '{"id":"%s","deps":[%s]}' "$id" "$*"; }
write_meta() { # <file> <with nolicense: 0|1> <netwatch license>
  local extra="" extra_node="" extra_dep=""
  if [[ "$2" == 1 ]]; then
    extra=",$(pkg nl nolicense 0.1.0 '"MIT"' "$src" "$reg/nolicense")"
    extra_node=",$(node nl)"
    extra_dep="$(dep nl null)"
  fi
  cat >"$1" <<JSON
{"workspace_members":["app","wsl"],"packages":[
$(pkg gamma gamma 0.3.0 '"Apache-2.0"' "$src" "$reg/gamma" docs/LIC.txt),
$(pkg app app 0.1.0 '"Apache-2.0"' null "$reg/app"),
$(pkg beta beta 2.0.0 '"MIT OR Apache-2.0"' "$src" "$reg/beta"),
$(pkg alpha alpha 1.0.0 '"MIT"' "$src" "$reg/alpha"),
$(pkg wsl ws-lib 0.1.0 '"Apache-2.0"' null "$reg/ws-lib"),
$(pkg delta delta 0.1.0 '"MIT"' "$src" "$reg/delta"),
$(pkg nw netwatch 0.19.3 "\"$3\"" "$src" "$reg/netwatch"),
$(pkg dev devonly 1.0.0 '"MIT"' "$src" "$reg/devonly"),
$(pkg bld builder 1.0.0 '"MIT"' "$src" "$reg/builder")$extra
],"resolve":{"root":null,"nodes":[
$(node app "$(dep alpha null)" "$(dep beta null)" "$(dep wsl null)" "$(dep dev '"dev"')" "$(dep bld '"build"')" ${extra_dep:+"$extra_dep"}),
$(node wsl "$(dep gamma null)"),
$(node beta "$(dep delta null)"),
$(node delta "$(dep nw null)"),
$(node alpha), $(node gamma), $(node nw), $(node dev), $(node bld)$extra_node
]}}
JSON
}
# A fake toolchain sysroot with Rust's library notice, and the real vendored LLVM and musl texts (they are pinned by
# SHA-256 in the generator, so fakes would be refused).
sysroot="$SCRATCH/sysroot-fake"
mkdir -p "$sysroot/share/doc/rust" "$SCRATCH/licenses/third-party"
printf '<html><body><h1>Copyright notices for The Rust Standard Library</h1><p>The Rust   Standard\nLibrary is dual-licensed.</p><pre>  RUST-STD MIT TEXT\n    indented &amp; kept</pre></body></html>\n' \
  >"$sysroot/share/doc/rust/COPYRIGHT-library.html"
cp "$here/../../LICENSES/third-party/llvm-project-LICENSE.TXT" "$here/../../LICENSES/third-party/musl-1.2.5-COPYRIGHT" \
  "$SCRATCH/licenses/third-party/"
run_gen() { # <metadata> [package] [target]: stdout in $GEN_OUT, stderr in $GEN_ERR, status in $GEN_STATUS
  python3 -I "$gen" --metadata "$1" --package "${2:-app}" --binary app --version 0.1.0 --target "${3:-$target}" \
    --license-dir "$SCRATCH/licenses" --rust-sysroot "$sysroot" >"$SCRATCH/gen.out" 2>"$SCRATCH/gen.err"
  GEN_STATUS=$?
  GEN_OUT="$(cat "$SCRATCH/gen.out")"
  GEN_ERR="$(cat "$SCRATCH/gen.err")"
}
write_meta "$SCRATCH/meta-missing.json" 1 "MIT OR Apache-2.0"
run_gen "$SCRATCH/meta-missing.json"
assert_eq "1" "$GEN_STATUS" "a crate with no license file fails the generation"
assert_contains "$GEN_ERR" "nolicense 0.1.0 (MIT)" "and is listed by name, version and license"
write_meta "$SCRATCH/meta-bad-allow.json" 0 "GPL-3.0-only"
run_gen "$SCRATCH/meta-bad-allow.json"
assert_eq "1" "$GEN_STATUS" "an allowlisted crate whose license expression changed is not excused"
assert_contains "$GEN_ERR" "netwatch 0.19.3 (GPL-3.0-only)" "and is listed"

write_meta "$SCRATCH/meta.json" 0 "MIT OR Apache-2.0"
run_gen "$SCRATCH/meta.json"
assert_eq "0" "$GEN_STATUS" "generation succeeds (stderr: $GEN_ERR)"
assert_contains "$GEN_OUT" "app 0.1.0 ($target)" "the header names the binary"
headers="$(grep -E '^Package: ' "$SCRATCH/gen.out" | paste -sd' ' -)"
assert_eq "Package: alpha 1.0.0 Package: beta 2.0.0 Package: delta 0.1.0 Package: gamma 0.3.0 Package: netwatch 0.19.3" \
  "$headers" "exactly the non-workspace normal dependencies, transitively through a workspace member, sorted"
assert_contains "$GEN_OUT" "License: MIT OR Apache-2.0" "each package has its license expression"
assert_contains "$GEN_OUT" "Copyright (c) Alpha Authors" "the full texts are included"
assert_contains "$GEN_OUT" "Alpha NOTICE" "NOTICE files too"
assert_contains "$GEN_OUT" "--- beta 2.0.0: LICENSE-APACHE ---" "each text names its file"
assert_contains "$GEN_OUT" "MIT text of beta" "license files match case-insensitively"
assert_false "CRLF is normalised" grep -q $'\r' "$SCRATCH/gen.out"
assert_contains "$GEN_OUT" "Gamma license via license-file" "the license-file field is honoured"
assert_contains "$GEN_OUT" "Delta REUSE text" "a LICENSES/ directory is read"
assert_contains "$GEN_OUT" "PLAIN APACHE-2.0 TEXT" "an allowlisted crate gets the plain SPDX text"
assert_contains "$GEN_OUT" "ships no license file" "and says why"
assert_false "no dev-dependency" grep -q 'devonly' "$SCRATCH/gen.out"
assert_false "no build-dependency" grep -q 'builder' "$SCRATCH/gen.out"
assert_false "no workspace member" grep -qE '^Package: (app|ws-lib) ' "$SCRATCH/gen.out"
assert_false "no local path leaks into the file" grep -qF "$SCRATCH" "$SCRATCH/gen.out"
assert_false "no timestamp" grep -qE '[0-9]{4}-[0-9]{2}-[0-9]{2}' "$SCRATCH/gen.out"
first="$(sha256sum <"$SCRATCH/gen.out")"
# The same graph with packages and nodes in another order gives the same bytes.
python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1])); m["packages"].reverse(); m["resolve"]["nodes"].reverse(); json.dump(m, open(sys.argv[2], "w"))' \
  "$SCRATCH/meta.json" "$SCRATCH/meta-rev.json"
run_gen "$SCRATCH/meta-rev.json"
assert_eq "$first" "$(sha256sum <"$SCRATCH/gen.out")" "the output does not depend on the input order"
run_gen "$SCRATCH/meta.json" no-such-package
assert_eq "2" "$GEN_STATUS" "an unknown package is a usage error"

# --- the toolchain sections: Rust's standard library, LLVM's libunwind and compiler-rt, musl libc --------------------------
run_gen "$SCRATCH/meta.json"
assert_contains "$GEN_OUT" "It is a static binary, which contains, each under its own license:" "the new header wording"
assert_true "the header lists the standard library, LLVM, musl and the crates" grep -qE '^  - the 5 third-party Rust packages below\.$' "$SCRATCH/gen.out"
assert_contains "$GEN_OUT" "Component: The Rust standard library (std, core, alloc, compiler_builtins" "a Rust standard library section"
assert_contains "$GEN_OUT" "The Rust Standard Library is dual-licensed." "its notice is converted to text (spaces collapsed)"
assert_contains "$GEN_OUT" "  RUST-STD MIT TEXT
    indented & kept" "and <pre> texts are kept verbatim, entities decoded"
assert_false "no HTML tags left" grep -qE '</?(pre|p|h1|body)>' "$SCRATCH/gen.out"
assert_contains "$GEN_OUT" "Component: LLVM: libunwind (the self-contained libunwind.a) and the compiler-rt parts of compiler_builtins" \
  "an LLVM section on musl"
assert_contains "$GEN_OUT" "License: Apache-2.0 WITH LLVM-exception" "with its license expression"
assert_contains "$GEN_OUT" "The LLVM Project is under the Apache License v2.0 with LLVM Exceptions" "and the full LLVM text"
assert_contains "$GEN_OUT" "Component: musl libc 1.2.5" "a musl section on musl"
assert_contains "$GEN_OUT" "musl as a whole is licensed under the following standard MIT license" "with musl's full COPYRIGHT"
assert_contains "$GEN_OUT" "Rich Felker" "including its copyright line"
assert_true "toolchain sections come before the crates" awk '/^Component: musl/ { m = NR } /^Package: alpha/ { a = NR } END { exit !(m && a && m < a) }' "$SCRATCH/gen.out"
run_gen "$SCRATCH/meta.json" app x86_64-unknown-linux-gnu
assert_eq "0" "$GEN_STATUS" "a glibc target works too"
assert_false "no musl section off musl" grep -q '^Component: musl' "$SCRATCH/gen.out"
assert_false "no libunwind section off musl" grep -q '^Component: LLVM' "$SCRATCH/gen.out"
assert_true "the standard library section is always there" grep -q '^Component: The Rust standard library' "$SCRATCH/gen.out"
printf 'edited\n' >>"$SCRATCH/licenses/third-party/musl-1.2.5-COPYRIGHT"
run_gen "$SCRATCH/meta.json"
assert_eq "1" "$GEN_STATUS" "an edited vendored text is refused"
assert_contains "$GEN_ERR" "does not match its pinned SHA-256" "and says why"
cp "$here/../../LICENSES/third-party/musl-1.2.5-COPYRIGHT" "$SCRATCH/licenses/third-party/"
mv "$sysroot/share/doc/rust/COPYRIGHT-library.html" "$sysroot/notice.html"
run_gen "$SCRATCH/meta.json"
assert_eq "1" "$GEN_STATUS" "a toolchain without its library notice is refused"
assert_contains "$GEN_ERR" "COPYRIGHT-library.html is missing" "and says which file"
mv "$sysroot/notice.html" "$sysroot/share/doc/rust/COPYRIGHT-library.html"
# The real toolchain's notice converts, and holds what the review asked about.
real_notice="$(rustc --print sysroot 2>/dev/null)/share/doc/rust/COPYRIGHT-library.html"
if [[ -f "$real_notice" ]]; then
  python3 -I "$gen" --metadata "$SCRATCH/meta.json" --package app --binary app --version 0.1.0 --target "$target" \
    --license-dir "$here/../../LICENSES" --rust-sysroot "$(rustc --print sysroot)" >"$SCRATCH/real.out" 2>/dev/null
  assert_eq "0" "$?" "the real toolchain notice and the real vendored texts work"
  assert_true "the real notice names hashbrown" grep -q 'hashbrown' "$SCRATCH/real.out"
else
  echo "   NOTE: no Rust toolchain notice here ($real_notice); the real-notice check was skipped"
fi

# --- SBOM: a cargo cyclonedx that writes nothing is an error, never a silent release without an SBOM ---------------------
sbin="$SCRATCH/sbombin"
mkdir -p "$sbin" "$SCRATCH/ws/crates/demo"
printf '#!/bin/sh\nexit 0\n' >"$sbin/cargo-cyclonedx"
# The fake `cargo cyclonedx` writes demo.cdx.json only when $SBOM_WRITES is set.
# shellcheck disable=SC2016  # the script's own code: it expands when the fake runs
printf '#!/bin/sh\n[ -n "${SBOM_WRITES:-}" ] && echo "{}" >crates/demo/demo.cdx.json\nexit 0\n' >"$sbin/cargo"
chmod 0755 "$sbin/cargo-cyclonedx" "$sbin/cargo"
sbom_err="$( (ROOT_DIR="$SCRATCH/ws" PATH="$sbin:$PATH" sbom "$SCRATCH/sbom-none") 2>&1)"
assert_eq "1" "$?" "no *.cdx.json produced: the release fails"
assert_contains "$sbom_err" "wrote no *.cdx.json" "with a clear message"
(ROOT_DIR="$SCRATCH/ws" PATH="$sbin:$PATH" SBOM_WRITES=1 sbom "$SCRATCH/sbom-ok") 2>/dev/null
assert_eq "0" "$?" "an SBOM produced: fine"
assert_true "it is moved into the release" test -f "$SCRATCH/sbom-ok/sbom/demo.cdx.json"
assert_false "and not left next to the crate" test -e "$SCRATCH/ws/crates/demo/demo.cdx.json"

# --- SHA256SUMS ------------------------------------------------------------------------------------------------------------
mkdir -p "$SCRATCH/a/sbom"
echo '{}' >"$SCRATCH/a/sbom/p2pc-server.cdx.json"
assert_true "write_sums" write_sums "$SCRATCH/a"
sums="$(cat "$SCRATCH/a/SHA256SUMS")"
names="$(awk '{ print $2 }' <<<"$sums")"
assert_eq "$(LC_ALL=C sort <<<"$names")" "$names" "SHA256SUMS is sorted by name"
assert_eq "3" "$(grep -cE '^[0-9a-f]{64}  [^ ]+$' <<<"$sums")" "three well-formed lines (two tarballs and the SBOM)"
assert_true "subdirectories are listed by relative path" grep -q '  sbom/p2pc-server.cdx.json$' "$SCRATCH/a/SHA256SUMS"
assert_false "SHA256SUMS does not list itself" grep -q 'SHA256SUMS' "$SCRATCH/a/SHA256SUMS"
assert_true "sha256sum -c accepts it" bash -c "cd '$SCRATCH/a' && sha256sum -c --quiet SHA256SUMS"

# --- builder selection ---------------------------------------------------------------------------------------------------
fake="$SCRATCH/fakebin"
mkdir -p "$fake" "$SCRATCH/sysroot/lib/rustlib/aarch64-unknown-linux-musl/lib"
printf '#!/bin/sh\necho %s\n' "$SCRATCH/sysroot" >"$fake/rustc"
chmod 0755 "$fake/rustc"
# Only the fakes and the basic tools: no musl-gcc, no cargo-zigbuild.
basic="$SCRATCH/basic"
mkdir -p "$basic"
for t in sh bash dirname; do ln -s "$(command -v "$t")" "$basic/$t"; done
out="$(PATH="$fake:$basic" builder_for "$target")"
assert_eq "1" "$(PATH="$fake:$basic" builder_for "$target" >/dev/null; echo $?)" "no musl C compiler: x86_64 cannot build"
assert_contains "$out" "musl-tools" "and the message says what to install"
assert_eq "skip:no cross toolchain for aarch64-unknown-linux-musl (cargo-zigbuild, or aarch64-linux-musl-gcc)" \
  "$(PATH="$fake:$basic" builder_for aarch64-unknown-linux-musl)" "aarch64 without a cross toolchain is skipped"
printf '#!/bin/sh\nexit 0\n' >"$fake/musl-gcc"
printf '#!/bin/sh\nexit 0\n' >"$fake/cargo-zigbuild"
chmod 0755 "$fake/musl-gcc" "$fake/cargo-zigbuild"
assert_eq "cargo:musl-gcc" "$(PATH="$fake:$basic" builder_for "$target")" "musl-gcc is preferred"
assert_eq "zigbuild" "$(RELEASE_BUILDER=zigbuild PATH="$fake:$basic" builder_for "$target")" "RELEASE_BUILDER=zigbuild"
assert_eq "zigbuild" "$(PATH="$fake:$basic" builder_for aarch64-unknown-linux-musl)" "aarch64 with cargo-zigbuild"
rm -rf "$SCRATCH/sysroot/lib/rustlib/aarch64-unknown-linux-musl"
assert_contains "$(PATH="$fake:$basic" builder_for aarch64-unknown-linux-musl)" "skip:the Rust target" \
  "aarch64 without its Rust target is skipped"

# --- build command and path remapping -------------------------------------------------------------------------------------
assert_eq "cargo build --locked --release --target $target -p p2pc-server -p p2pc-cli -p p2pc-agent -p p2pc-shim" \
  "$(build_command "$target" cargo:musl-gcc | paste -sd' ' -)" "the cargo command"
assert_eq "cargo zigbuild --locked --release --target $target -p p2pc-server -p p2pc-cli -p p2pc-agent -p p2pc-shim" \
  "$(build_command "$target" zigbuild | paste -sd' ' -)" "the zigbuild command"
flags="$(HOME=/home/someone CARGO_HOME=/home/someone/.cargo remap_flags /work/target)"
assert_contains "$flags" "--remap-path-prefix=/home/someone=/home/build" "HOME is remapped"
assert_contains "$flags" "--remap-path-prefix=$ROOT_DIR=/build/p2pc" "the workspace is remapped"
# rustc applies the last matching prefix: the target dir (the most specific) comes last.
assert_eq "--remap-path-prefix=/work/target=/build/target" "$(tr ' ' '\n' <<<"$flags" | grep . | tail -n 1)" \
  "the most specific remap comes last"

# --- dry run: prints the plan, builds and writes nothing -------------------------------------------------------------------
dry="$(bash "$release" --dry-run --out "$SCRATCH/dist" 2>&1)"
assert_eq "0" "$?" "the dry run succeeds"
assert_contains "$dry" "$target" "the plan names the x86_64 target"
assert_contains "$dry" "aarch64-unknown-linux-musl" "and the aarch64 one"
assert_contains "$dry" "SOURCE_DATE_EPOCH=$(git -C "$here" log -1 --format=%ct)" "SOURCE_DATE_EPOCH is the commit time"
assert_contains "$dry" "nothing built" "it says nothing was built"
assert_false "no output directory" test -e "$SCRATCH/dist"
assert_eq "2" "$(bash "$release" --bogus >/dev/null 2>&1; echo $?)" "an unknown option is a usage error"

# --- the deploy files of the dist: the server's and the node's installers, units and host setup (T14b1, T14b2) -----------
assert_eq "install-node.sh:0755 install-server.sh:0755 p2pc-agent.service:0644 p2pc-server.service:0644 setup-host.sh:0755" \
  "$(for e in "${DEPLOY_FILES[@]}"; do f="${e%:*}"; printf '%s:%s\n' "${f##*/}" "${e##*:}"; done | LC_ALL=C sort | paste -sd' ' -)" \
  "the dist ships both installers, both units and setup-host.sh, with fixed modes"
mkdir -p "$SCRATCH/deploy-out"
copy_deploy_files "$SCRATCH/deploy-out"
for e in "${DEPLOY_FILES[@]}"; do
  f="${e%:*}"
  name="${f##*/}"
  assert_true "$name is copied verbatim" cmp -s "$ROOT_DIR/$f" "$SCRATCH/deploy-out/$name"
  assert_eq "${e##*:}" "0$(stat -c %a "$SCRATCH/deploy-out/$name")" "$name has mode ${e##*:}"
done
write_sums "$SCRATCH/deploy-out"
for name in install-node.sh setup-host.sh p2pc-agent.service; do
  assert_true "SHA256SUMS lists $name" grep -qE "  $name\$" "$SCRATCH/deploy-out/SHA256SUMS"
done
assert_true "the node files verify with sha256sum -c" bash -c "cd '$SCRATCH/deploy-out' && sha256sum -c --quiet SHA256SUMS"
assert_contains "$dry" "install-node.sh" "the plan lists the node installer"
assert_contains "$dry" "p2pc-agent.service" "and the agent unit"

finish_tests "test-release"
