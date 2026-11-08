# SPDX-License-Identifier: Apache-2.0
"""The registry of criteria: one script per acceptance criterion of spec §14.

Each script is a module ``acNN_<name>.py`` with these attributes:

    ID           "AC-2"
    TITLE        a short name
    SPEC         the criterion as the spec words it
    ROLES        the machine roles it needs (empty: it runs on the machine that runs the harness)
    NEEDS        what it needs, as keys of context.OWNERS ("route GET /v1/nodes", "cli logs", "feature scheduler"):
                 `./run.py --list` asks the product which have landed and names the owner of the rest
    run(ctx)     runs the criterion and returns a ``core.Result``
"""

from __future__ import annotations

import importlib
import re
import shutil
from types import ModuleType
from typing import Iterable

MODULES = (
    "ac01_install",
    "ac02_cpu_job",
    "ac03_gpu_job",
    "ac04_egress",
    "ac05_inputs_outputs",
    "ac06_node_loss",
    "ac07_cancel_timeout",
    "ac08_remote_client",
    "ac09_mcp",
    "ac10_scale",
    "ac11_security_invariants",
    "ac12_supply_chain",
)


# What AC-12 runs on the machine that runs the harness: `gitleaks`, `cargo deny` (the program `cargo-deny`) and
# `cargo cyclonedx` (`cargo-cyclonedx`). Each must be on the PATH of the shell that starts the harness.
REQUIRED_TOOLS = ("gitleaks", "cargo-deny", "cargo-cyclonedx")


def missing_tools(which=shutil.which) -> list[str]:
    """The tools of ``REQUIRED_TOOLS`` that ``which`` cannot find on the PATH."""
    return [tool for tool in REQUIRED_TOOLS if not which(tool)]


def load_all() -> list[ModuleType]:
    return [importlib.import_module(name) for name in MODULES]


def _cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def waiting_for(keys, landed, owners) -> tuple[list[str], str]:
    """The tasks a criterion still waits for and how much of it runs: each key of ``NEEDS`` is asked of the product
    (``landed``); a piece that has not landed names its owner (``owners``); one the product cannot answer for is marked
    ``?``, and one that has no marker at all (the agent's lease executor) ``*``: the run's gate decides that one."""
    waiting: list[str] = []
    landed_count = 0
    for key in keys:
        state = landed.landed(key)
        if state is True:
            landed_count += 1
            continue
        task = owners.get(key, "?")
        mark = "*" if key == "feature executor" else ("?" if state is None else "")
        if task + mark not in waiting:
            waiting.append(task + mark)
    if not waiting:
        runs = "yes"
    elif landed_count == 0:
        runs = "no"
    else:
        runs = "partly"
    return sorted(waiting), runs


def status_table(modules: Iterable[ModuleType], landed=None, owners=None) -> str:
    """The Markdown table of what each criterion needs and what it waits for. The README embeds it. The last two
    columns are READ FROM THE PRODUCT when ``landed`` is given (``./run.py --list``); without it they show ``-``."""
    rows = [
        "| ID | Criterion | Machines | Runs today | Waiting for |",
        "|---|---|---|---|---|",
    ]
    for m in modules:
        roles = ", ".join(f"`{r}`" for r in m.ROLES) or "none (local)"
        if landed is None:
            runs, waiting = "-", "-"
        else:
            tasks, runs = waiting_for(getattr(m, "NEEDS", ()), landed, owners or {})
            waiting = ", ".join(tasks) or "nothing"
        rows.append(f"| {m.ID} | {_cell(m.TITLE)} | {roles} | {runs} | {waiting} |")
    return "\n".join(rows)


_ID_RE = re.compile(r"(?i)ac-?(\d{1,2})")


def parse_only(spec: str, known_ids: list[str]) -> list[str]:
    """``"AC-2,ac5,AC12"`` -> ``["AC-2", "AC-5", "AC-12"]``, in numeric order and without repeats."""
    wanted: set[str] = set()
    for token in spec.split(","):
        m = _ID_RE.fullmatch(token.strip()) if token.strip() == token.strip().replace(" ", "") else None
        ident = f"AC-{int(m.group(1))}" if m else None
        if ident not in known_ids:
            raise ValueError(f"unknown criterion {token.strip()!r} in --only (known: {known_ids[0]} to {known_ids[-1]})")
        wanted.add(ident)
    return sorted(wanted, key=lambda i: int(i.split("-")[1]))
