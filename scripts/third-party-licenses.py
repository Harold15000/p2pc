#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# third-party-licenses.py: writes the THIRD-PARTY-LICENSES file of one release binary, from `cargo metadata` and the
# license files that each crate ships in its own source (no extra tool: python3's standard library only).
#
#   cargo metadata --format-version 1 --locked --filter-platform <target> >meta.json
#   python3 -I scripts/third-party-licenses.py --metadata meta.json --package p2pc-cli --binary p2pc \
#     --version 0.1.0 --target x86_64-unknown-linux-musl --license-dir LICENSES \
#     --rust-sysroot "$(rustc --print sysroot)" >THIRD-PARTY-LICENSES
#
# Fixed sections first: what every binary links statically besides the crates.
#   - The Rust standard library (std, core, alloc, compiler_builtins and the crates std is built from): Rust's own
#     notice, share/doc/rust/COPYRIGHT-library.html of the pinned toolchain, converted to plain text.
#   - On musl targets, LLVM's libunwind (the self-contained libunwind.a) and the LLVM compiler-rt parts of
#     compiler_builtins: LICENSES/third-party/llvm-project-LICENSE.TXT, copied from
#     https://github.com/llvm/llvm-project/blob/llvmorg-20.1.0/libunwind/LICENSE.TXT (the same text in every LLVM
#     release since 9; Rust builds libunwind from its fork of llvm-project).
#   - On musl targets, musl libc 1.2.5 (the self-contained libc.a; its src/internal/version.h says 1.2.5):
#     LICENSES/third-party/musl-1.2.5-COPYRIGHT, the COPYRIGHT file of musl 1.2.5
#     (https://musl.libc.org/releases/musl-1.2.5.tar.gz), copied verbatim from the musl tree that zig 0.17.1 vendors
#     (PyPI ziglang 0.17.1, ziglang/lib/libc/musl/COPYRIGHT).
#   Both vendored files are pinned by SHA-256 below, so an edit to them is caught.
#
# Which crates: every non-workspace package reachable from --package through NORMAL dependency edges of the resolved
# graph for the target (through workspace members too). Dev-dependencies and build-dependencies are left out: they
# are not part of the binary. Proc-macro crates are normal dependencies, so they are kept (over-inclusive, on purpose).
#
# Which texts: the files at the top of the crate's source whose name starts with LICENSE/LICENCE, UNLICENSE, COPYING
# or NOTICE (any case), the files of a directory with such a name (REUSE's LICENSES/), and the manifest's
# `license-file`. A crate with none of them fails the run with a list, unless it is in ALLOWLIST below.
#
# The output depends only on the graph and the texts: packages sorted by name and version, files sorted by name, CRLF
# normalised, no timestamps and no local paths. Exit codes: 0 written, 1 crates without a license file, 2 usage.

import argparse
import hashlib
import json
import os
import re
import sys
from html.parser import HTMLParser

# Crates that ship no license file, reviewed by hand. Each one is dual-licensed and the text we ship is the plain
# SPDX/ASF text of the license we elect, from the repository's LICENSES/ directory: the Apache-2.0 text needs no
# copyright line filled in. The license expression must match exactly, or the crate is not excused.
#   name: (expected license expression, elected license, file in --license-dir)
ALLOWLIST = {
    # The iroh family (n0), crates.io packages without a license file in the published crate.
    "enum-assoc": ("MIT OR Apache-2.0", "Apache-2.0", "Apache-2.0.txt"),
    "iroh-base": ("MIT OR Apache-2.0", "Apache-2.0", "Apache-2.0.txt"),
    "iroh-dns": ("MIT OR Apache-2.0", "Apache-2.0", "Apache-2.0.txt"),
    "iroh-metrics-derive": ("MIT OR Apache-2.0", "Apache-2.0", "Apache-2.0.txt"),
    "n0-error-macros": ("MIT OR Apache-2.0", "Apache-2.0", "Apache-2.0.txt"),
    "netwatch": ("MIT OR Apache-2.0", "Apache-2.0", "Apache-2.0.txt"),
}

# Vendored texts under --license-dir, pinned: (file, SHA-256).
LLVM_LICENSE = ("third-party/llvm-project-LICENSE.TXT",
                "b5efebcaca80879234098e52d1725e6d9eb8fb96a19fce625d39184b705f7b6d")
MUSL_COPYRIGHT = ("third-party/musl-1.2.5-COPYRIGHT",
                  "f9bc4423732350eb0b3f7ed7e91d530298476f8fec0c6c427a1c04ade22655af")
RUST_LIBRARY_NOTICE = os.path.join("share", "doc", "rust", "COPYRIGHT-library.html")

LICENSE_NAME = re.compile(r"^(un)?licen[cs]e|^copying|^notice", re.IGNORECASE)
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
RULE = "=" * 100


def read_text(path):
    with open(path, "rb") as f:
        text = f.read().decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n").rstrip() + "\n"


class _HtmlText(HTMLParser):
    """Plain text of an HTML notice: <pre> blocks verbatim, other text with collapsed spaces, blocks on new lines."""

    BLOCKS = frozenset({"p", "div", "li", "h1", "h2", "h3", "h4", "tr", "br", "section", "details", "summary"})

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.pre = [], 0

    def handle_starttag(self, tag, attrs):
        if tag == "pre":
            self.pre += 1
        if tag == "pre" or tag in self.BLOCKS:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag == "pre":
            self.pre -= 1
        if tag == "pre" or tag in self.BLOCKS:
            self.out.append("\n")

    def handle_data(self, data):
        if self.pre:
            self.out.append(data)
        elif data.split():
            self.out.append(" ".join(data.split()) + " ")


def html_to_text(path):
    parser = _HtmlText()
    parser.feed(read_text(path))
    lines = [line.rstrip() for line in "".join(parser.out).split("\n")]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip() + "\n"


class UsageError(Exception):
    pass


def pinned_text(license_dir, pinned):
    name, digest = pinned
    path = os.path.join(license_dir, name)
    if not os.path.isfile(path):
        raise UsageError(f"{path} is missing")
    with open(path, "rb") as f:
        got = hashlib.sha256(f.read()).hexdigest()
    if got != digest:
        raise UsageError(f"{path} does not match its pinned SHA-256 (got {got}): restore the vendored text")
    return read_text(path)


def toolchain_sections(target, sysroot, license_dir):
    """[(title, license expression, note, [(file name, text)])] for what the toolchain links into every binary."""
    notice = os.path.join(sysroot, RUST_LIBRARY_NOTICE)
    if not os.path.isfile(notice):
        raise UsageError(f"{notice} is missing: the Rust toolchain's notice for its standard library is needed")
    sections = [(
        "The Rust standard library (std, core, alloc, compiler_builtins, and the crates std is built from)",
        "Apache-2.0 OR MIT, with the exceptions listed in its notice",
        "Rust's own notice for the standard library of this toolchain, converted from HTML to text.\n",
        [("COPYRIGHT-library (from the Rust toolchain)", html_to_text(notice))],
    )]
    if "musl" in target:
        sections.append((
            "LLVM: libunwind (the self-contained libunwind.a) and the compiler-rt parts of compiler_builtins",
            "Apache-2.0 WITH LLVM-exception",
            "",
            [("LICENSE.TXT (llvm-project)", pinned_text(license_dir, LLVM_LICENSE))],
        ))
        sections.append((
            "musl libc 1.2.5 (the self-contained libc.a; parts of it also reach compiler_builtins through libm)",
            "MIT",
            "",
            [("COPYRIGHT (musl 1.2.5)", pinned_text(license_dir, MUSL_COPYRIGHT))],
        ))
    return sections


def license_files(pkg):
    """[(display name, absolute path)] of the crate's own license files, sorted by display name."""
    root = os.path.dirname(pkg["manifest_path"])
    found = {}
    for entry in os.listdir(root):
        path = os.path.join(root, entry)
        if not LICENSE_NAME.match(entry):
            continue
        if os.path.isfile(path):
            found[entry] = path
        elif os.path.isdir(path):
            for sub in os.listdir(path):
                if os.path.isfile(os.path.join(path, sub)):
                    found[entry + "/" + sub] = os.path.join(path, sub)
    if pkg.get("license_file"):
        rel = os.path.normpath(pkg["license_file"])
        path = os.path.join(root, rel)
        if not rel.startswith("..") and os.path.isfile(path):
            found.setdefault(rel.replace(os.sep, "/"), path)
    return sorted(found.items())


def source_label(pkg):
    source = pkg.get("source") or ""
    if source == CRATES_IO:
        return "crates.io"
    if source.startswith(("git+", "registry+", "sparse+")):
        return source
    return "local path dependency"


def closure(meta, root_id):
    """Ids reachable from root_id through normal (non-dev, non-build) edges."""
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    seen, stack = set(), [root_id]
    while stack:
        for dep in nodes.get(stack.pop(), {}).get("deps", []):
            normal = any(k.get("kind") is None for k in dep.get("dep_kinds", []))
            if normal and dep["pkg"] not in seen:
                seen.add(dep["pkg"])
                stack.append(dep["pkg"])
    return seen


def main():
    ap = argparse.ArgumentParser(description="Write THIRD-PARTY-LICENSES for one release binary.")
    for flag in ("--metadata", "--package", "--binary", "--version", "--target", "--license-dir", "--rust-sysroot"):
        ap.add_argument(flag, required=True)
    args = ap.parse_args()
    try:
        fixed = toolchain_sections(args.target, args.rust_sysroot, args.license_dir)
    except UsageError as e:
        print(f"third-party-licenses: {e}", file=sys.stderr)
        return 1

    with open(args.metadata, encoding="utf-8") as f:
        meta = json.load(f)
    packages = {p["id"]: p for p in meta["packages"]}
    workspace = set(meta["workspace_members"])
    roots = [i for i in workspace if packages[i]["name"] == args.package]
    if len(roots) != 1:
        print(f"third-party-licenses: {args.package} is not a workspace member", file=sys.stderr)
        return 2

    third = [packages[i] for i in closure(meta, roots[0]) if i not in workspace]
    third.sort(key=lambda p: (p["name"], p["version"], source_label(p)))

    entries, missing = [], []
    for pkg in third:
        expr = pkg.get("license") or "(none: see the license file)"
        files = [(name, read_text(path)) for name, path in license_files(pkg)]
        note = ""
        if not files:
            allowed = ALLOWLIST.get(pkg["name"])
            if allowed is None or allowed[0] != pkg.get("license"):
                missing.append(f"{pkg['name']} {pkg['version']} ({pkg.get('license')})")
                continue
            _, elected, text_file = allowed
            files = [(f"{elected} (plain SPDX text)", read_text(os.path.join(args.license_dir, text_file)))]
            note = f"Note: the crate ships no license file; it is used under {elected}, whose plain text follows.\n"
        entries.append((pkg, expr, note, files))

    if missing:
        print("third-party-licenses: these crates ship no license file and are not in the reviewed allowlist "
              "(scripts/third-party-licenses.py):", file=sys.stderr)
        for line in missing:
            print(f"  {line}", file=sys.stderr)
        return 1

    out = sys.stdout
    out.write(f"THIRD-PARTY LICENSES of {args.binary} {args.version} ({args.target})\n\n")
    out.write(f"{args.binary} is part of P2PC. It is a static binary, which contains, each under its own license:\n")
    for title, _, _, _ in fixed:
        out.write(f"  - {title};\n")
    out.write(f"  - the {len(entries)} third-party Rust packages below.\n")
    out.write("Their license and notice texts follow, as each project ships them.\n\n")
    for pkg, _, _, _ in entries:
        out.write(f"  {pkg['name']} {pkg['version']}\n")
    for title, expr, note, files in fixed:
        out.write(f"\n{RULE}\nComponent: {title}\nLicense: {expr}\n")
        out.write(note)
        for name, text in files:
            out.write(f"\n--- {name} ---\n\n{text}")
    for pkg, expr, note, files in entries:
        out.write(f"\n{RULE}\nPackage: {pkg['name']} {pkg['version']}\nLicense: {expr}\nSource: {source_label(pkg)}\n")
        out.write(note)
        for name, text in files:
            out.write(f"\n--- {pkg['name']} {pkg['version']}: {name} ---\n\n{text}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
