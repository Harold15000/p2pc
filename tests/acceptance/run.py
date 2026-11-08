#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Runs the P2PC v0.1 acceptance criteria (spec §14) against real machines and writes an evidence report.

    ./run.py --machines machines.toml [--only AC-2,AC-5] [--report-dir reports/] [--strict]
    ./run.py --list                      # the criteria and what each one still waits for

Exit code: 0 when no criterion failed (``blocked`` and ``skip`` are reported, not failures); 1 when one failed, or,
with ``--strict`` (the release gate), when any criterion is not ``pass``; 2 for a usage or machines-file error;
130 when interrupted. Python 3.12+, standard library only.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

if sys.version_info < (3, 12):  # pragma: no cover
    sys.exit("run.py needs Python 3.12 or newer")

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import context  # noqa: E402
import core  # noqa: E402
import criteria  # noqa: E402
import machines  # noqa: E402
import product  # noqa: E402
import report  # noqa: E402

DEFAULT_REPORT_DIR = HERE / "reports"
REPO_ROOT = HERE.parents[1]


def _git_describe(repo: Path) -> str:
    try:
        cp = subprocess.run(
            ["git", "-C", str(repo), "describe", "--always", "--dirty", "--abbrev=12"],
            capture_output=True,
            text=True,
            timeout=10,
            stdin=subprocess.DEVNULL,
        )
        return cp.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run.py",
        description="Run the P2PC v0.1 acceptance criteria against real machines and write an evidence report.",
    )
    p.add_argument("--machines", type=Path, help="the machines file (see machines.example.toml)")
    p.add_argument("--only", help="comma-separated criteria to run, for example AC-2,AC-5 (default: all)")
    p.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR, help="where reports go (default: reports/)")
    p.add_argument("--list", action="store_true", help="print the criteria and what each waits for, then exit")
    p.add_argument("--strict", action="store_true", help="release gate: exit 1 unless every criterion is pass")
    p.add_argument("--no-build", action="store_true", help="--list: do not build p2pc and p2pc-agent to read what has landed")
    p.add_argument("--repo", type=Path, default=REPO_ROOT, help="the p2pc repository (default: this checkout)")
    return p


def _failure_result(mod, partial: core.Result | None, reason: str) -> core.Result:
    res = partial if partial is not None and partial.id == mod.ID else core.Result(mod.ID, mod.TITLE)
    res.add_check("script", core.FAIL, reason)
    return res


def _run_all(ctx, selected: list, results: list[core.Result]) -> bool:
    """Runs each criterion in turn, appending to ``results``. Returns True when interrupted by Ctrl-C."""
    for mod in selected:
        ctx.result = None
        try:
            res = mod.run(ctx)
            if not isinstance(res, core.Result):
                res = _failure_result(mod, ctx.result, f"harness bug: run() returned {type(res).__name__}, not a Result")
        except KeyboardInterrupt:
            print(f"{mod.ID:6} interrupted", file=sys.stderr)
            if ctx.result is not None and ctx.result.id == mod.ID:
                # What the criterion had recorded before Ctrl-C (its commands, its finished checks, the interrupted
                # one as a failure) is evidence: keep it in the report.
                results.append(ctx.result.finish())
            return True
        except Exception as e:  # a script bug must not stop the other criteria
            res = _failure_result(mod, ctx.result, f"{type(e).__name__}: {core.clean(str(e))}")
        results.append(res.finish())
        print(_progress(res), file=sys.stderr)
    return False


def _progress(res: core.Result) -> str:
    counts = res.counts()
    detail = ", ".join(f"{counts[s]} {s}" for s in core.STATUSES if counts[s])
    line = f"{res.id:6} {res.status.upper():8} {res.title} ({detail})"
    if res.status != core.PASS and res.reason:
        line += "\n         " + core.redact(res.reason)[:300]
    return line


def main(argv: list[str] | None = None, *, loader: Callable[[], list] = criteria.load_all) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)

    mods = loader()
    if args.list:
        landed = product.Landed(args.repo, build=not args.no_build)
        print(criteria.status_table(mods, landed, context.OWNERS))
        absent = criteria.missing_tools()
        if absent:
            print(f"\nTools not on the PATH of this shell (the AC-12 check that needs each is a skip): {', '.join(absent)}")
        return 0
    if args.machines is None:
        print("error: --machines is required (or use --list)", file=sys.stderr)
        return 2
    try:
        config = machines.load_machines(args.machines)
    except machines.MachinesError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    ids = [m.ID for m in mods]
    selected = mods
    if args.only is not None:
        try:
            wanted = criteria.parse_only(args.only, ids)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        selected = [m for m in mods if m.ID in wanted]

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = report.new_run_dir(args.report_dir, run_id)
    ctx = context.Context(config, repo_root=args.repo)
    ctx.artifacts_dir = run_dir / "artifacts"  # evidence files a criterion keeps (the SBOM...)
    started = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    results: list[core.Result] = []
    interrupted = False
    try:
        interrupted = _run_all(ctx, selected, results)
    finally:
        ctx.close()

    finished = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    rep = report.build_report(
        results,
        run_id=run_dir.name,
        started_at=started,
        finished_at=finished,
        machines_name=config.source_name,
        git_commit=_git_describe(args.repo),
        strict=args.strict,
        interrupted=interrupted,
    )
    out = report.write_into(run_dir, rep)
    counts = rep["summary"]["counts"]
    print(f"summary: {', '.join(f'{counts[s]} {s}' for s in core.STATUSES)}", file=sys.stderr)
    print(f"report: {out}")
    if interrupted:
        return 130
    return core.exit_code(results, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
