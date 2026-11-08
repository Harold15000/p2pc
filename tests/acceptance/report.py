# SPDX-License-Identifier: Apache-2.0
"""Builds and writes the evidence report of a run: ``report.json`` (for machines) and ``report.md`` (for people).

Everything is redacted before it is built and checked again before it is written: a ``p2pc_sk_`` or ``p2pc_join_``
string never reaches a file.
"""

from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any, Iterable

import core

SCHEMA = 1


def _number(criterion: dict) -> int:
    try:
        return int(str(criterion["id"]).rsplit("-", 1)[1])
    except (IndexError, ValueError):
        return 10_000


def build_report(
    results: Iterable[core.Result],
    *,
    run_id: str,
    started_at: str,
    finished_at: str,
    machines_name: str,
    git_commit: str,
    strict: bool,
    interrupted: bool = False,
) -> dict:
    results = list(results)
    criteria = sorted((r.to_dict() for r in results), key=_number)
    counts = core.summarize(results)
    report = {
        "schema": SCHEMA,
        "run": {
            "id": run_id,
            "started_at": started_at,
            "finished_at": finished_at,
            "machines_file": machines_name,
            "git_commit": git_commit,
            "strict": strict,
            "interrupted": interrupted,
            "python": platform.python_version(),
        },
        "summary": {
            "counts": counts,
            "criteria_run": len(results),
            # Only an all-pass run is acceptance evidence: blocked and skip never count as pass.
            "accepted": bool(results) and counts[core.PASS] == len(results) and not interrupted,
        },
        "criteria": criteria,
    }
    return core.redact_object(report)


def _cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def _fence(text: str) -> str:
    """A fenced block that survives backticks inside the text."""
    longest = max((len(run) for run in _backtick_runs(text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{text}\n{fence}"


def _backtick_runs(text: str) -> list[str]:
    runs, cur = [], ""
    for ch in text:
        if ch == "`":
            cur += ch
        elif cur:
            runs.append(cur)
            cur = ""
    if cur:
        runs.append(cur)
    return runs


def _status_text(status: str, unblocked_by: list[str]) -> str:
    return f"{status} ({', '.join(unblocked_by)})" if status == core.BLOCKED and unblocked_by else status


def _counts_line(counts: dict[str, int]) -> str:
    return ", ".join(f"{counts[s]} {s}" for s in core.STATUSES)


def render_markdown(report: dict) -> str:
    run = report["run"]
    summary = report["summary"]
    out: list[str] = ["# P2PC v0.1 acceptance report", ""]
    out += [
        f"- Run: `{run['id']}` ({run['started_at']} to {run['finished_at']})",
        f"- Commit: `{run['git_commit']}`; machines file: `{run['machines_file']}`; Python {run['python']}",
        f"- Result: **{_counts_line(summary['counts'])}**"
        + (" (interrupted)" if run.get("interrupted") else ""),
        "- Verdict: " + ("**all criteria passed**" if summary["accepted"] else "**not accepted** (blocked, skipped or failed criteria remain; only `pass` counts)"),
        "",
        "| ID | Criterion | Status | Detail |",
        "|---|---|---|---|",
    ]
    for c in report["criteria"]:
        detail = c["reason"] or "all checks passed"
        if c["unblocked_by"]:
            detail += f" (blocked until {', '.join(c['unblocked_by'])})"
        out.append(f"| {c['id']} | {_cell(c['title'])} | {c['status']} | {_cell(detail)} |")
    for c in report["criteria"]:
        out += ["", f"## {c['id']} · {c['title']}: {c['status']}", ""]
        if c["unblocked_by"]:
            out.append(f"Blocked until: {', '.join(c['unblocked_by'])}.")
            out.append("")
        out += [f"Duration {c['duration_s']} s.", "", "| Check | Status | Time (s) | Detail |", "|---|---|---|---|"]
        for chk in c["checks"]:
            out.append(
                f"| {_cell(chk['name'])} | {_status_text(chk['status'], chk['unblocked_by'])} | {chk['duration_s']} | "
                f"{_cell(chk['reason'])} |"
            )
        for chk in c["checks"]:
            if not (chk["steps"] or chk["timings"] or chk["evidence"]):
                continue
            out += ["", f"### {chk['name']}", ""]
            if chk["timings"]:
                out.append("Timings: " + ", ".join(f"{k} = {v} s" for k, v in chk["timings"].items()))
            if chk["evidence"]:
                out.append("Evidence: " + _cell(json.dumps(chk["evidence"], sort_keys=True)))
            for step in chk["steps"]:
                if out[-1] != "":
                    out.append("")
                out.append(f"- `{_cell(step['command'])}` on {step['role']}: {_exit_text(step)} ({step['duration_s']} s)")
                for name in ("stdout_excerpt", "stderr_excerpt"):
                    text = step[name].strip()
                    if text:
                        out += ["", f"  {name.split('_')[0]}:", "", _fence(_short(text))]
        if c["other_steps"]:
            out += ["", "Other commands:"]
            for step in c["other_steps"]:
                out.append(f"- `{_cell(step['command'])}` on {step['role']}: {_exit_text(step)}")
    text = "\n".join(out) + "\n"
    return core.redact(text)


def _short(text: str, limit: int = 600) -> str:
    return core.excerpt(text, limit)


def _exit_text(step: dict) -> str:
    if step.get("error"):
        text = f"did not run ({step['error']})"
    elif step.get("timed_out"):
        text = "timed out"
    else:
        text = f"exit {step['exit_code']}"
    if step.get("ssh_retries"):
        text += f"; ssh retried {step['ssh_retries']}x after a connection failure ({step.get('ssh_first_error', '')})"
    return text


def new_run_dir(base_dir: Path, run_id: str) -> Path:
    """Creates ``<base_dir>/<run_id>`` (or ``<run_id>-2``... when it exists): one directory per run, never reused."""
    base_dir = Path(base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    out = base_dir / run_id
    n = 1
    while True:
        try:
            out.mkdir()
            return out
        except FileExistsError:
            n += 1
            out = base_dir / f"{run_id}-{n}"


def _render_files(report: dict, redact: bool) -> tuple[str, str]:
    if redact:
        report = core.redact_object(report)
    json_text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if core.SECRET_RE.search(json_text):
        raise RuntimeError("refusing to write a report that still contains a secret")
    md_text = render_markdown(report)
    if core.SECRET_RE.search(md_text):
        raise RuntimeError("refusing to write a report that still contains a secret")
    return json_text, md_text


def write_into(run_dir: Path, report: dict, *, redact: bool = True) -> Path:
    """Writes ``report.json`` and ``report.md`` into an existing run directory."""
    json_text, md_text = _render_files(report, redact)
    (run_dir / "report.json").write_text(json_text, encoding="utf-8")
    (run_dir / "report.md").write_text(md_text, encoding="utf-8")
    return run_dir


def write_report(base_dir: Path, report: dict, *, redact: bool = True) -> Path:
    """A new run directory under ``base_dir`` with both files. Nothing is created if the report holds a secret."""
    _render_files(report, redact)  # fail before touching the disk
    run_dir = new_run_dir(base_dir, str(report.get("run", {}).get("id", "run")))
    return write_into(run_dir, report, redact=redact)
