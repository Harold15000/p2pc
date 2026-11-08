# SPDX-License-Identifier: Apache-2.0
"""AC-12: `cargo deny check`, the secret scan, the SBOM and SECURITY.md are in place; the docs let a stranger do AC-1 to AC-3.

Runs today, on the machine that runs the harness, against this checkout."""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path

import core
import executors

ID = "AC-12"
TITLE = "Supply chain, SECURITY.md and docs"
SPEC = "`cargo deny check`, the secret scan, the SBOM and `SECURITY.md` are in place, and the docs let a stranger do AC-1 to AC-3."
ROLES: tuple[str, ...] = ()
# What it needs, as keys of context.OWNERS: whether each has landed is read from the product (`--list`).
NEEDS: tuple[str, ...] = ()

# `gitleaks --exit-code N` is what it exits with when it FINDS leaks; its own errors always exit 1, so any other
# number tells the two apart.
GITLEAKS_LEAKS_EXIT = 3
GITLEAKS_HINT = "install gitleaks (https://github.com/gitleaks/gitleaks#installing, for example `brew install gitleaks`)"
CYCLONEDX_HINT = "install the SBOM tool with `cargo install --locked cargo-cyclonedx`"
DENY_HINT = "install cargo-deny with `cargo install --locked cargo-deny`"


def _tool_missing(step: core.Step) -> bool:
    """A tool is missing only when the shell says so (exit 127), the program does not exist, or cargo says there is no
    such subcommand. Any other failure, whatever its text, is the tool running and finding a problem."""
    if step.exit_code == 127:
        return True
    if step.error and "No such file or directory" in step.error:
        return True
    return bool(re.search(r"no such (sub)?command", step.stderr, re.IGNORECASE))


def _tail(step: core.Step, lines: int = 3) -> str:
    text = [ln for ln in core.clean(step.stderr + "\n" + step.stdout).splitlines() if ln.strip()]
    return " | ".join(text[-lines:])


def _read_findings(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [f for f in data if isinstance(f, dict)] if isinstance(data, list) else []


def run(ctx) -> core.Result:
    res = ctx.begin(ID, TITLE)
    repo = ctx.repo_root
    manifest = str(repo / "Cargo.toml")

    with res.check("cargo deny check") as c:
        step = ctx.exec("harness", ["cargo", "deny", "--manifest-path", manifest, "check"], timeout=1800)
        if _tool_missing(step):
            raise core.Skipped(f"cargo-deny is not available: {DENY_HINT}")
        c.require(step.ok, f"cargo deny check exited {step.exit_code}: {_tail(step)}")

    with res.check("secret scan (gitleaks, full git history)") as c:
        probe = ctx.exec("harness", ["gitleaks", "version"], timeout=30)
        if _tool_missing(probe):
            raise core.Skipped(f"gitleaks is not installed: {GITLEAKS_HINT}")
        c.require(probe.ok, f"`gitleaks version` failed: {_tail(probe)}")
        c.evidence["gitleaks"] = probe.stdout.strip()
        with tempfile.TemporaryDirectory() as tmp:
            findings_file = Path(tmp) / "gitleaks.json"
            step = ctx.exec(
                "harness",
                # .gitleaksignore and .gitleaks.toml belong to the repo root, so name it: the harness's own working
                # directory is wherever the operator happens to be.
                ["gitleaks", "git", "--no-banner", "--no-color", "--redact", "--exit-code", str(GITLEAKS_LEAKS_EXIT),
                 "--gitleaks-ignore-path", str(repo), "--report-format", "json", "--report-path", str(findings_file),
                 str(repo)],
                timeout=1800,
            )
            findings = _read_findings(findings_file)
            if findings and ctx.artifacts_dir is not None:
                ctx.artifacts_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(findings_file, ctx.artifacts_dir / "gitleaks.json")  # secrets are redacted in it
        c.evidence["findings"] = len(findings)
        # Exit codes: 0 clean, GITLEAKS_LEAKS_EXIT leaks found; anything else (gitleaks' own 1, a signal, a timeout) is
        # the tool failing, which says nothing about leaks: report its own output, not "found leaks".
        if step.exit_code not in (0, GITLEAKS_LEAKS_EXIT) and not findings:
            raise core.CheckFailed(
                f"gitleaks itself failed (exit {step.exit_code}{', timed out' if step.timed_out else ''}): "
                f"{step.error or _tail(step) or 'no output'}"
            )
        if step.exit_code == GITLEAKS_LEAKS_EXIT or findings:
            where = ", ".join(f"{f.get('RuleID')} {f.get('File')}:{f.get('StartLine')}" for f in findings[:6])
            raise core.CheckFailed(
                f"gitleaks reports {len(findings)} potential secret(s) in the git history ({where}"
                f"{', ...' if len(findings) > 6 else ''}); mark fake secrets with `gitleaks:allow`, or ask a maintainer to triage"
            )

    with res.check("SBOM (cargo cyclonedx)") as c:
        probe = ctx.exec("harness", ["cargo", "cyclonedx", "--version"], timeout=60)
        if _tool_missing(probe):
            raise core.Skipped(f"cargo-cyclonedx is not installed: {CYCLONEDX_HINT}")
        c.require(probe.ok, f"`cargo cyclonedx --version` failed: {_tail(probe)}")
        # `cargo cyclonedx` writes its documents next to every Cargo.toml (and cargo writes target/): never in the
        # operator's tree. It runs in a temporary copy of the files git tracks, that is the committed state of the
        # checkout plus any tracked change, and the copy is removed afterwards.
        listing = ctx.exec("harness", ["git", "-C", str(repo), "ls-files", "-z"], timeout=60)
        c.require(listing.ok, f"cannot list the repository's files: {_tail(listing)}")
        with tempfile.TemporaryDirectory(prefix="p2pc-sbom-") as tmp:
            copy = Path(tmp) / "repo"
            copied = 0
            for rel in (r for r in listing.stdout.split("\0") if r):
                src = repo / rel
                if src.is_file():
                    (copy / rel).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, copy / rel)
                    copied += 1
            c.require(copied, "git lists no file to copy")
            step = ctx.exec(
                "harness", ["cargo", "cyclonedx", "--manifest-path", str(copy / "Cargo.toml"), "--format", "json"],
                timeout=900,
            )
            made = sorted(p for p in copy.rglob("*.cdx.json") if "target" not in p.relative_to(copy).parts)
            c.require(step.ok, f"cargo cyclonedx exited {step.exit_code}: {_tail(step)}")
            c.require(made, "cargo cyclonedx wrote no *.cdx.json file")
            components = 0
            for path in made:
                bom = json.loads(path.read_text(encoding="utf-8"))
                c.require(bom.get("bomFormat") == "CycloneDX", f"{path.name} is not a CycloneDX document")
                components += len(bom.get("components") or [])
                if ctx.artifacts_dir is not None:
                    ctx.artifacts_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, ctx.artifacts_dir / path.name)
            c.require(components > 0, "the SBOM lists no components")
            c.evidence.update(documents=[p.name for p in made], components=components, files_copied=copied)

    with res.check("SECURITY.md present and non-empty") as c:
        path = repo / "SECURITY.md"
        c.require(path.is_file(), "SECURITY.md is missing")
        text = path.read_text(encoding="utf-8")
        c.require(len(text.strip()) >= 200, "SECURITY.md is (nearly) empty")
        c.require("vulnerab" in text.lower(), "SECURITY.md does not say how to report a vulnerability")
        c.evidence.update(bytes=len(text.encode()), sha256=executors.file_sha256(path))

    with res.check("SPDX headers (scripts/check-spdx.sh)") as c:
        step = ctx.exec("harness", ["bash", str(repo / "scripts" / "check-spdx.sh")], timeout=120)
        c.require(step.ok, f"check-spdx.sh exited {step.exit_code}: {_tail(step)}")

    with res.check("the docs let a stranger do AC-1 to AC-3 (manual)") as c:
        path, digest = ctx.manual_evidence("stranger_walkthrough")
        c.evidence.update(report=path.name, sha256=digest)
    return res
