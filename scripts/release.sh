#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# release.sh: builds the release artifacts of P2PC, reproducibly, into dist/<version>/. Nothing is uploaded:
# publishing is a separate decision.
#
#   scripts/release.sh [--version X] [--out DIR] [--force] [--check-reproducible] [--dry-run]
#
# For each target it builds p2pc-server, p2pc, p2pc-agent and p2pc-shim, static (musl), with --locked, in release mode
# (the workspace profile strips them), with --remap-path-prefix for $HOME, $CARGO_HOME, the workspace and the target
# dir, and SOURCE_DATE_EPOCH taken from the time of the HEAD commit. Then it writes:
#   <bin>-<version>-<target>.tar.gz   one per binary and target: the binary, its LICENSE (AGPL-3.0-only for
#                                     p2pc-server, Apache-2.0 for the others), THIRD-PARTY-LICENSES (every crate it
#                                     links, with its license texts: scripts/third-party-licenses.py, from
#                                     `cargo metadata`; plus the Rust standard library, and on musl LLVM's
#                                     libunwind and musl libc) and a README. Deterministic: sorted names, owner 0:0, fixed
#                                     modes, mtime = SOURCE_DATE_EPOCH, `gzip -n`.
#   install-server.sh, p2pc-server.service   the server installer and its unit (deploy/linux/).
#   install-node.sh, setup-host.sh, p2pc-agent.service   the node installer, the host setup it runs and the
#                                     agent's systemd user unit (deploy/linux/). DEPLOY_FILES is the list.
#   sbom/<crate>.cdx.json             CycloneDX SBOMs, only if `cargo cyclonedx` is installed.
#   SHA256SUMS                        of every file above.
#
# Targets:
#   x86_64-unknown-linux-musl   always. The C code (SQLite, ring) needs a musl C compiler: `musl-gcc`
#                               (apt-get install musl-tools) or cargo-zigbuild (with zig). Neither is installed by
#                               this script.
#   aarch64-unknown-linux-musl  only if its Rust target is installed and cargo-zigbuild is present (or
#                               aarch64-linux-musl-gcc); otherwise it is skipped with a note.
#
# --check-reproducible builds everything a second time, from a clean second target dir into a scratch dir, and
# compares the two SHA256SUMS (SBOMs excluded: they carry a timestamp and a random serial number).
# --dry-run prints the plan and builds nothing.
#
# Sourcing this file only defines functions (deploy/tests/test-release.sh unit-tests them).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The binaries, as `<cargo package>:<binary>`.
RELEASE_BINARIES=(p2pc-server:p2pc-server p2pc-cli:p2pc p2pc-agent:p2pc-agent p2pc-shim:p2pc-shim)
RELEASE_TARGETS=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)

note() { printf 'release: %s\n' "$*" >&2; }
die() {
  printf 'release: error: %s\n' "$*" >&2
  exit 1
}

# workspace_version: `version` of [workspace.package] in Cargo.toml.
workspace_version() {
  sed -n '/^\[workspace\.package\]/,/^\[/ s/^version = "\(.*\)"$/\1/p' "$ROOT_DIR/Cargo.toml" | head -n 1
}

# commit_epoch: the committer time of HEAD, in seconds since the epoch.
commit_epoch() {
  git -C "$ROOT_DIR" log -1 --format=%ct
}

# license_file <binary>: the LICENSE that goes into that binary's tarball.
license_file() {
  if [[ "$1" == p2pc-server ]]; then
    echo "$ROOT_DIR/crates/p2pc-server/LICENSE"
  else
    echo "$ROOT_DIR/LICENSE"
  fi
}

license_id() {
  if [[ "$1" == p2pc-server ]]; then echo "AGPL-3.0-only"; else echo "Apache-2.0"; fi
}

# package_binary <binary path> <binary name> <version> <target> <epoch> <out dir> <third-party licenses file>: writes
# <out dir>/<name>-<version>-<target>.tar.gz. The result depends only on the file contents and the arguments: not on
# the umask, the owner, the mtimes or the locale of the build machine. Callers use it with `||`, where `set -e` does
# not apply: every step is checked.
package_binary() {
  local src="$1" name="$2" version="$3" target="$4" epoch="$5" out="$6" third_party="$7"
  local stem="$name-$version-$target" stage
  [[ -f "$src" && -f "$third_party" ]] || return 1
  stage="$(mktemp -d "${TMPDIR:-/tmp}/p2pc-release.XXXXXX")" || return 1
  if ! { mkdir "$stage/$stem" &&
    cp "$src" "$stage/$stem/$name" &&
    cp "$(license_file "$name")" "$stage/$stem/LICENSE" &&
    cp "$third_party" "$stage/$stem/THIRD-PARTY-LICENSES" &&
    printf '%s %s (%s): part of P2PC, a self-hostable personal compute cloud. License: %s (see LICENSE; third-party licenses in THIRD-PARTY-LICENSES). Install and use: deploy/README.md in the P2PC source repository.\n' \
      "$name" "$version" "$target" "$(license_id "$name")" >"$stage/$stem/README" &&
    chmod 0755 "$stage/$stem" "$stage/$stem/$name" &&
    chmod 0644 "$stage/$stem/LICENSE" "$stage/$stem/THIRD-PARTY-LICENSES" "$stage/$stem/README"; }; then
    rm -rf "$stage"
    return 1
  fi
  LC_ALL=C tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
    -C "$stage" -cf - "$stem" | gzip -n -9 >"$out/$stem.tar.gz"
  local status=("${PIPESTATUS[@]}")
  rm -rf "$stage"
  [[ "${status[0]}" == 0 && "${status[1]}" == 0 ]]
}

# copy_static <src> <dest> <mode>: a fixed-mode copy (deploy files shipped next to the tarballs).
copy_static() {
  cp "$1" "$2"
  chmod "$3" "$2"
}

# The deploy files shipped next to the tarballs, as <path from the repo root>:<mode>. Each lands in the dist under its
# own name, and SHA256SUMS lists it, so the installers can check every file they use.
DEPLOY_FILES=(
  deploy/linux/install-server.sh:0755
  deploy/linux/p2pc-server.service:0644
  deploy/linux/install-node.sh:0755
  deploy/linux/setup-host.sh:0755
  deploy/linux/p2pc-agent.service:0644
)

# copy_deploy_files <out>: every DEPLOY_FILES entry into <out>, with its fixed mode.
copy_deploy_files() {
  local e f
  for e in "${DEPLOY_FILES[@]}"; do
    f="${e%:*}"
    copy_static "$ROOT_DIR/$f" "$1/${f##*/}" "${e##*:}" || return 1
  done
}

# write_sums <dir>: SHA256SUMS of every file under <dir> (but itself), sorted by name, `sha256sum -c` format.
write_sums() {
  (
    cd "$1" || exit 1
    local sums
    sums="$(find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | while IFS= read -r f; do
      sha256sum -- "$f"
    done)" || exit 1
    printf '%s\n' "$sums" >SHA256SUMS
    chmod 0644 SHA256SUMS
  )
}

# rust_target_installed <target>: the Rust standard library for that target is installed.
rust_target_installed() {
  [[ -d "$(rustc --print sysroot)/lib/rustlib/$1/lib" ]]
}

# builder_for <target>: prints `cargo:<cc>` or `zigbuild`, or `skip:<reason>` (exit 0), or fails with the reason.
builder_for() {
  local target="$1" cc=""
  case "$target" in
    x86_64-unknown-linux-musl)
      for c in x86_64-linux-musl-gcc musl-gcc; do
        if command -v "$c" >/dev/null 2>&1; then
          cc="$c"
          break
        fi
      done
      if [[ "${RELEASE_BUILDER:-}" != zigbuild && -n "$cc" ]]; then
        echo "cargo:$cc"
      elif command -v cargo-zigbuild >/dev/null 2>&1; then
        echo "zigbuild"
      else
        echo "no musl C compiler for $target: install musl-tools (apt-get install musl-tools) or cargo-zigbuild and zig"
        return 1
      fi
      ;;
    aarch64-unknown-linux-musl)
      if ! rust_target_installed "$target"; then
        echo "skip:the Rust target $target is not installed (rustup target add $target)"
      elif command -v cargo-zigbuild >/dev/null 2>&1; then
        echo "zigbuild"
      elif command -v aarch64-linux-musl-gcc >/dev/null 2>&1; then
        echo "cargo:aarch64-linux-musl-gcc"
      else
        echo "skip:no cross toolchain for $target (cargo-zigbuild, or aarch64-linux-musl-gcc)"
      fi
      ;;
    *)
      echo "unknown target $target"
      return 1
      ;;
  esac
}

# build_command <target> <builder>: the cargo argv for one target (one line per word, for the dry run and the build).
build_command() {
  local target="$1" builder="$2" sub="build"
  [[ "$builder" == zigbuild ]] && sub="zigbuild"
  printf '%s\n' cargo "$sub" --locked --release --target "$target"
  local entry
  for entry in "${RELEASE_BINARIES[@]}"; do
    printf '%s\n' -p "${entry%%:*}"
  done
}

# remap_flags <target dir>: the path remapping for rustc. rustc applies the LAST matching prefix, so the most specific
# paths come last.
remap_flags() {
  local target_dir="$1" cargo_home="${CARGO_HOME:-$HOME/.cargo}"
  printf '%s ' "--remap-path-prefix=$HOME=/home/build" \
    "--remap-path-prefix=$cargo_home=/cargo" \
    "--remap-path-prefix=$ROOT_DIR=/build/p2pc" \
    "--remap-path-prefix=$target_dir=/build/target"
}

# cflags_remap <target dir>: the same remapping for the C compiler (SQLite, ring).
cflags_remap() {
  local target_dir="$1" cargo_home="${CARGO_HOME:-$HOME/.cargo}"
  printf '%s ' "-ffile-prefix-map=$HOME=/home/build" \
    "-ffile-prefix-map=$cargo_home=/cargo" \
    "-ffile-prefix-map=$ROOT_DIR=/build/p2pc" \
    "-ffile-prefix-map=$target_dir=/build/target"
}

# build_target <target> <builder> <target dir> <epoch>
build_target() {
  local target="$1" builder="$2" target_dir="$3" epoch="$4" cmd var
  mapfile -t cmd < <(build_command "$target" "$builder")
  var="${target//-/_}"
  local -a envs=(
    "SOURCE_DATE_EPOCH=$epoch"
    "CARGO_TARGET_DIR=$target_dir"
    "CARGO_INCREMENTAL=0"
    "RUSTFLAGS=$(remap_flags "$target_dir")"
    "CFLAGS_$var=$(cflags_remap "$target_dir")"
  )
  if [[ "$builder" == cargo:* ]]; then
    envs+=("CC_$var=${builder#cargo:}")
    # The linker of a cross target must be the matching gcc too.
    if [[ "$target" == aarch64-* ]]; then
      envs+=("CARGO_TARGET_${var^^}_LINKER=${builder#cargo:}")
    fi
  fi
  note "building $target with ${builder%%:*} into $target_dir"
  (cd "$ROOT_DIR" && env "${envs[@]}" "${cmd[@]}") || die "the build for $target failed"
}

# sbom <out dir>: CycloneDX SBOMs, if `cargo cyclonedx` is installed.
sbom() {
  local out="$1"
  if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
    note "SBOM skipped: cargo-cyclonedx is not installed (cargo install cargo-cyclonedx)"
    return 0
  fi
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/p2pc-sbom.XXXXXX")"
  # It writes <crate>.cdx.json next to each crate's Cargo.toml: move them into the release.
  (cd "$ROOT_DIR" && cargo cyclonedx --format json) >"$tmp/log" 2>&1 || {
    cat "$tmp/log" >&2
    rm -rf "$tmp"
    die "cargo cyclonedx failed"
  }
  mkdir -p "$out/sbom"
  local f
  while IFS= read -r f; do
    mv "$f" "$out/sbom/$(basename "$f")"
  done < <(find "$ROOT_DIR/crates" -maxdepth 2 -name '*.cdx.json')
  if ! compgen -G "$out/sbom/*.cdx.json" >/dev/null; then
    cat "$tmp/log" >&2
    rm -rf "$tmp"
    die "cargo cyclonedx succeeded but wrote no *.cdx.json next to the crates' Cargo.toml (has its output layout changed? its log is above)"
  fi
  chmod 0644 "$out/sbom"/*.cdx.json
  rm -rf "$tmp"
}

# third_party_licenses <target> <version> <dir>: writes <dir>/<binary>.THIRD-PARTY-LICENSES for every release binary,
# from the dependency graph that `cargo metadata` resolves for <target>.
third_party_licenses() {
  local target="$1" version="$2" dir="$3" entry sysroot
  sysroot="$(cd "$ROOT_DIR" && rustc --print sysroot)" || die "rustc --print sysroot failed"
  (cd "$ROOT_DIR" && cargo metadata --format-version 1 --locked --filter-platform "$target") >"$dir/metadata.json" ||
    die "cargo metadata failed for $target"
  for entry in "${RELEASE_BINARIES[@]}"; do
    python3 -I "$ROOT_DIR/scripts/third-party-licenses.py" --metadata "$dir/metadata.json" --package "${entry%%:*}" \
      --binary "${entry#*:}" --version "$version" --target "$target" --license-dir "$ROOT_DIR/LICENSES" \
      --rust-sysroot "$sysroot" \
      >"$dir/${entry#*:}.THIRD-PARTY-LICENSES" ||
      die "cannot write THIRD-PARTY-LICENSES for ${entry#*:} ($target): see above"
  done
}

# release_into <out dir> <target dir> <version> <epoch>: builds and packages every available target.
release_into() {
  local out="$1" target_dir="$2" version="$3" epoch="$4" target builder entry bin licenses
  mkdir -p "$out"
  for target in "${RELEASE_TARGETS[@]}"; do
    builder="$(builder_for "$target")" || die "$builder"
    if [[ "$builder" == skip:* ]]; then
      note "SKIPPED $target: ${builder#skip:}"
      continue
    fi
    build_target "$target" "$builder" "$target_dir" "$epoch"
    licenses="$(mktemp -d "${TMPDIR:-/tmp}/p2pc-licenses.XXXXXX")"
    third_party_licenses "$target" "$version" "$licenses"
    for entry in "${RELEASE_BINARIES[@]}"; do
      bin="${entry#*:}"
      package_binary "$target_dir/$target/release/$bin" "$bin" "$version" "$target" "$epoch" "$out" \
        "$licenses/$bin.THIRD-PARTY-LICENSES" || die "packaging $bin for $target failed"
      if command -v file >/dev/null 2>&1 &&
        ! file "$target_dir/$target/release/$bin" | grep -Eq 'statically linked|static-pie linked'; then
        note "warning: $bin for $target does not look statically linked"
      fi
    done
    rm -rf "$licenses"
  done
  copy_deploy_files "$out" || die "copying the deploy files failed"
  sbom "$out"
  write_sums "$out"
}

usage() {
  cat <<'USAGE'
Usage: scripts/release.sh [--version X] [--out DIR] [--force] [--check-reproducible] [--dry-run]
  --version X            version in the file names (default: [workspace.package] version in Cargo.toml)
  --out DIR              output directory (default: dist/<version>)
  --force                replace DIR if it exists
  --check-reproducible   build a second time in a clean target dir and compare SHA256SUMS
  --dry-run              print the plan; build nothing
Environment: RELEASE_BUILDER=zigbuild uses cargo-zigbuild even when musl-gcc is installed.
USAGE
}

main() {
  set -euo pipefail
  local version="" out="" force=0 repro=0 dry=0
  while (($# > 0)); do
    case "$1" in
      --version)
        version="${2:?--version needs a value}"
        shift
        ;;
      --out)
        out="${2:?--out needs a value}"
        shift
        ;;
      --force) force=1 ;;
      --check-reproducible) repro=1 ;;
      --dry-run) dry=1 ;;
      -h | --help)
        usage
        return 0
        ;;
      *)
        usage >&2
        return 2
        ;;
    esac
    shift
  done
  [[ -n "$version" ]] || version="$(workspace_version)"
  [[ "$version" =~ ^[0-9A-Za-z.+-]+$ ]] || die "bad version: $version"
  [[ -n "$out" ]] || out="$ROOT_DIR/dist/$version"
  local epoch
  epoch="$(commit_epoch)"
  [[ "$epoch" =~ ^[0-9]+$ ]] || die "cannot read the time of the HEAD commit"
  if [[ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=no)" ]]; then
    note "warning: the work tree has uncommitted changes: this build is not the HEAD commit"
  fi

  echo "P2PC release $version  SOURCE_DATE_EPOCH=$epoch ($(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ))  out=$out"
  local target builder
  for target in "${RELEASE_TARGETS[@]}"; do
    if builder="$(builder_for "$target")"; then
      if [[ "$builder" == skip:* ]]; then
        echo "  $target: SKIPPED (${builder#skip:})"
      else
        echo "  $target: $builder: $(build_command "$target" "$builder" | paste -sd' ' -)"
      fi
    else
      echo "  $target: CANNOT BUILD ($builder)"
      ((dry)) || die "$builder"
    fi
  done
  # THIRD-PARTY-LICENSES is written by a stdlib-only python3 script (standard on Ubuntu and Debian).
  if ! command -v python3 >/dev/null 2>&1; then
    echo "  CANNOT WRITE THIRD-PARTY-LICENSES: python3 is not installed"
    ((dry)) || die "python3 is needed for THIRD-PARTY-LICENSES"
  fi
  local e f
  for e in "${DEPLOY_FILES[@]}"; do
    f="${e%:*}"
    echo "  $f -> ${f##*/} (mode ${e##*:})"
  done
  if ((dry)); then
    echo "  dry run: nothing built"
    return 0
  fi

  if [[ -e "$out" ]]; then
    ((force)) || die "$out exists: remove it or pass --force"
    rm -rf "$out"
  fi
  release_into "$out" "$ROOT_DIR/target/release-a" "$version" "$epoch"
  echo "== $out"
  cat "$out/SHA256SUMS"

  if ((repro)); then
    local second
    second="$(mktemp -d "${TMPDIR:-/tmp}/p2pc-release-b.XXXXXX")"
    # A clean second target dir: nothing is reused from the first build.
    rm -rf "$ROOT_DIR/target/release-b"
    release_into "$second/out" "$ROOT_DIR/target/release-b" "$version" "$epoch"
    if diff <(grep -v '\.cdx\.json$' "$out/SHA256SUMS") <(grep -v '\.cdx\.json$' "$second/out/SHA256SUMS"); then
      echo "REPRODUCIBLE: two builds gave identical SHA256SUMS"
      rm -rf "$second"
    else
      echo "NOT REPRODUCIBLE: the second build is in $second/out" >&2
      return 1
    fi
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
  exit $?
fi
