# SPDX-License-Identifier: Apache-2.0
"""The machines file: which machines play which role, how to reach them, and where the binaries are.

The schema is documented, with every key, in ``machines.example.toml``. Validation reports every problem at once, as
``[table] key: message`` lines, and never echoes a value that could be a secret.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import core

ROLES = ("server", "node_linux_gpu", "node_linux", "node_wsl2_gpu", "client_remote")
EXECUTORS = ("local", "ssh", "wsl_over_ssh")
BINARIES = ("p2pc", "p2pc_server", "p2pc_agent")

HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]*")  # an ssh alias: never starts with "-" (option injection)
DISTRO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
POSIX_PATH_RE = re.compile(r"/[A-Za-z0-9_./-]*")
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ADDRESS_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]*")
CHAINED_RE = re.compile(r";|&&|\|\||[\r\n]")  # more than one statement (see executors.refuse_chained)
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")

DEFAULT_PARAMS: dict[str, int] = {
    "job_count": 100,  # AC-10
    "jobs_per_node": 4,  # AC-10
    "big_output_mb": 1000,  # AC-5 (the cap is 1 GiB = 1024 MiB, spec §7 outputs.max_mb)
    "input_kib": 512,  # AC-5 (spec §7: at most 512 KiB of inline files)
    "lease_ttl_s": 60,  # AC-6 (spec §6)
    "overhead_budget_s": 5,  # AC-2
}
PARAM_RANGES: dict[str, tuple[int, int]] = {
    "job_count": (1, 1000),
    "jobs_per_node": (1, 64),
    "big_output_mb": (1, 1024),
    "input_kib": (1, 512),
    "lease_ttl_s": (10, 3600),
    "overhead_budget_s": (1, 600),
}

DEFAULT_IMAGES: dict[str, str] = {
    "cpu": "docker.io/library/python:3.12-slim",
    "gpu_smi": "nvcr.io/nvidia/cuda:12.4.1-base-ubuntu22.04",
    "gpu_torch": "docker.io/pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime",
    "denied_image": "docker.io/library/alpine:3.20",  # outside the AC-9 key's allowlist
}

MANUAL_KEYS = ("pentest_report", "claude_code_session", "stranger_walkthrough")


class MachinesError(ValueError):
    """The machines file is not valid. ``problems`` has one line per problem."""

    def __init__(self, problems: list[str]):
        self.problems = [core.redact(p) for p in problems]
        super().__init__("invalid machines file:\n  " + "\n  ".join(self.problems))


# --------------------------------------------------------------------------------------------------------------
# Field validators: each returns the clean value or raises ValueError(message)
# --------------------------------------------------------------------------------------------------------------


def _string(v: Any) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ValueError("must be a non-empty string")
    return v


def _bool(v: Any) -> bool:
    if not isinstance(v, bool):
        raise ValueError("must be true or false")
    return v


def _url(v: Any) -> str:
    if not isinstance(v, str) or not v.startswith(("http://", "https://")) or " " in v:
        raise ValueError("must start with http:// or https:// and have no spaces")
    return v.rstrip("/")


def _workdir(v: Any) -> str:
    if not isinstance(v, str) or not POSIX_PATH_RE.fullmatch(v) or v == "/" or ".." in v.split("/"):
        raise ValueError("must be an absolute POSIX path of letters, digits and _ . / - (not /, no ..)")
    return v.rstrip("/")


def _env_name(v: Any) -> str:
    if not isinstance(v, str) or not ENV_NAME_RE.fullmatch(v):
        raise ValueError("must be an environment variable name")
    return v


def _ports(v: Any) -> list[int]:
    ok = isinstance(v, list) and all(isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535 for p in v)
    if not ok:
        raise ValueError("must be a list of ports (1-65535)")
    return list(v)


def _string_list(v: Any) -> list[str]:
    if not isinstance(v, list) or not v or not all(isinstance(x, str) and x for x in v):
        raise ValueError("must be a non-empty list of strings")
    return list(v)


_SECRET_NAME_RE = re.compile(r"KEY|TOKEN|SECRET|PASSW|CREDENTIAL|AUTH", re.IGNORECASE)


def _test_env(v: Any) -> dict[str, str]:
    """``test_env``: variables for the ignored cargo tests, passed as ``env VAR=value`` (visible in the process list and
    the report's command line), so a secret does not belong here."""
    if not isinstance(v, dict) or not v:
        raise ValueError("must be a non-empty table of VAR = \"value\" strings")
    for name, value in v.items():
        if not isinstance(name, str) or not ENV_NAME_RE.fullmatch(name):
            raise ValueError(f"{name!r} must be an environment variable name")
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a string")
        if _SECRET_NAME_RE.search(name):
            raise ValueError(f"{name} looks like a secret: test_env is passed on a command line, never put a secret in it")
    return dict(v)


def _ssh_options(v: Any) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise ValueError("must be a list of strings (extra arguments for ssh, for example [\"-J\", \"jump\"])")
    return list(v)


def _address(v: Any) -> str:
    # A literal IP or a host name; it ends up inside a job's command line, so keep it boring.
    if not isinstance(v, str) or not ADDRESS_RE.fullmatch(v):
        raise ValueError("must be an IP address or a host name")
    return v


_COMMON = {"executor", "enabled", "host", "distro", "workdir", "ssh_options"}
_NODE = {"node_name", "image_install_command", "install_command", "agent_start_command", "repo_dir", "test_prefix", "test_env", "podman", "partition_command", "heal_command", "lan_gateway", "lan_host", "allowed_listen_ports"}
ROLE_KEYS: dict[str, set[str]] = {
    "server": _COMMON | {"url", "admin_key_env", "install_command", "public_host", "allowed_listen_ports"},
    "node_linux_gpu": _COMMON | _NODE,
    "node_linux": _COMMON | _NODE,
    "node_wsl2_gpu": _COMMON | _NODE,
    "client_remote": _COMMON | {"public_host"},
}
_VALIDATORS: dict[str, Callable[[Any], Any]] = {
    "enabled": _bool,
    "workdir": _workdir,
    "ssh_options": _ssh_options,
    "url": _url,
    "admin_key_env": _env_name,
    "install_command": _string,
    "image_install_command": _string,
    "public_host": _address,
    "allowed_listen_ports": _ports,
    "node_name": _string,
    "repo_dir": _workdir,
    "agent_start_command": _string,
    "podman": _string_list,
    "test_prefix": _string_list,
    "test_env": _test_env,
    "partition_command": _string,
    "heal_command": _string,
    "lan_gateway": _address,
    "lan_host": _address,
}


@dataclass
class Role:
    name: str
    executor: str
    enabled: bool = True
    host: str | None = None
    distro: str | None = None
    workdir: str | None = None  # None: a private directory (mktemp -d, mode 0700) made on the machine at first use
    ssh_options: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.extra.get(key, default)


class Binaries:
    def __init__(self, paths: dict[str, Path], pins: dict[str, str]):
        self._paths = paths
        self._pins = pins

    def path(self, name: str) -> Path | None:
        return self._paths.get(name)

    get = path

    def pinned_sha256(self, name: str) -> str | None:
        return self._pins.get(name)


@dataclass
class Machines:
    source_name: str
    roles: dict[str, Role]
    binaries: Binaries
    params: dict[str, int]
    images: dict[str, str]
    manual: dict[str, Path]


def _parse_role(name: str, table: dict, problems: list[str]) -> Role | None:
    tag = f"[{name}]"
    before = len(problems)
    allowed = ROLE_KEYS[name]
    for key in table:
        if key not in allowed:
            problems.append(f"{tag} {key}: unknown key (allowed: {', '.join(sorted(allowed))})")

    executor = table.get("executor")
    if executor is None:
        problems.append(f"{tag} executor: required (one of {', '.join(EXECUTORS)})")
    elif executor not in EXECUTORS:
        problems.append(f'{tag} executor: "{executor}" is not one of {", ".join(EXECUTORS)}')
        executor = None

    host, distro = table.get("host"), table.get("distro")
    if executor == "local":
        if "host" in table:
            problems.append(f'{tag} host: not allowed for executor "local"')
        if "distro" in table:
            problems.append(f'{tag} distro: only for executor "wsl_over_ssh"')
    elif executor in ("ssh", "wsl_over_ssh"):
        if host is None:
            problems.append(f'{tag} host: required for executor "{executor}" (an ssh host alias)')
        elif not isinstance(host, str) or not HOST_RE.fullmatch(host):
            problems.append(f"{tag} host: must be an ssh host alias (letters, digits, . _ @ -; not starting with -)")
        if executor == "ssh" and "distro" in table:
            problems.append(f'{tag} distro: only for executor "wsl_over_ssh"')
        if executor == "wsl_over_ssh":
            if distro is None:
                problems.append(f'{tag} distro: required for executor "wsl_over_ssh" (the WSL distro name)')
            elif not isinstance(distro, str) or not DISTRO_RE.fullmatch(distro):
                problems.append(f"{tag} distro: must be a distro name (letters, digits, . _ -; not starting with -)")

    values: dict[str, Any] = {}
    for key, check in _VALIDATORS.items():
        if key in table and key in allowed:
            try:
                values[key] = check(table[key])
            except ValueError as e:
                problems.append(f"{tag} {key}: {e}")

    command = values.get("install_command")
    # Only a node's install_command is a PowerShell pipeline that gets the join token; the server's runs through `sh -c`.
    if executor == "wsl_over_ssh" and name != "server" and command is not None and CHAINED_RE.search(command):
        problems.append(
            f"{tag} install_command: must be a single command (no `;`, `&&`, `||` or newline): the harness pipes the join "
            "token into it, and PowerShell gives a pipeline to the first statement only. Use `& '<path>\\install.ps1' -Join "
            "[-Force]`"
        )

    for key in ("test_prefix", "test_env"):
        # Without repo_dir the role is never picked to run the ignored tests, and the key would be ignored in silence.
        if key in values and "repo_dir" not in table:
            problems.append(f"{tag} {key}: needs repo_dir (a p2pc checkout on the node): without it the key is never used")

    if len(problems) > before:
        return None
    extra = {k: v for k, v in values.items() if k not in ("enabled", "workdir", "ssh_options")}
    return Role(
        name=name,
        executor=executor,
        enabled=values.get("enabled", True),
        host=host,
        distro=distro,
        workdir=values.get("workdir"),
        ssh_options=values.get("ssh_options", []),
        extra=extra,
    )


def _closed_table(
    doc: dict, name: str, allowed: set[str], problems: list[str], check: Callable[[str, Any], Any]
) -> dict[str, Any]:
    table = doc.get(name, {})
    out: dict[str, Any] = {}
    if not isinstance(table, dict):
        problems.append(f"[{name}]: must be a table")
        return out
    for key, value in table.items():
        if key not in allowed:
            problems.append(f"[{name}] {key}: unknown key (allowed: {', '.join(sorted(allowed))})")
            continue
        try:
            out[key] = check(key, value)
        except ValueError as e:
            problems.append(f"[{name}] {key}: {e}")
    return out


def parse_machines(text: str, base_dir: Path, source_name: str = "machines.toml") -> Machines:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise MachinesError([f"invalid TOML: {e}"]) from None

    problems: list[str] = []
    known = set(ROLES) | {"binaries", "params", "images", "manual"}
    for key, value in doc.items():
        if key not in known:
            kind = "table" if isinstance(value, dict) else "key"
            problems.append(f"unknown {kind} [{key}] (expected: {', '.join(sorted(known))})")

    roles: dict[str, Role] = {}
    for name in ROLES:
        if name not in doc:
            continue
        if not isinstance(doc[name], dict):
            problems.append(f"[{name}]: must be a table")
            continue
        role = _parse_role(name, doc[name], problems)
        if role is not None:
            roles[name] = role
    if not any(n in doc for n in ROLES):
        problems.append(f"no machine roles: define at least one of {', '.join('[' + r + ']' for r in ROLES)}")

    def param(key: str, value: Any) -> int:
        lo, hi = PARAM_RANGES[key]
        if not isinstance(value, int) or isinstance(value, bool) or not lo <= value <= hi:
            raise ValueError(f"must be an integer between {lo} and {hi}")
        return value

    params = dict(DEFAULT_PARAMS)
    params.update(_closed_table(doc, "params", set(DEFAULT_PARAMS), problems, param))

    def image(_key: str, value: Any) -> str:
        if not isinstance(value, str) or not value or re.search(r"\s", value):
            raise ValueError("must be a non-empty image reference without spaces")
        return value

    images = dict(DEFAULT_IMAGES)
    images.update(_closed_table(doc, "images", set(DEFAULT_IMAGES), problems, image))

    bin_keys = set(BINARIES) | {f"{b}_sha256" for b in BINARIES}

    def binary(key: str, value: Any) -> Any:
        if key.endswith("_sha256"):
            if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
                raise ValueError("must be 64 hex characters")
            return value.lower()
        if not isinstance(value, str) or not value:
            raise ValueError("must be a path (a non-empty string)")
        return value

    raw_bin = _closed_table(doc, "binaries", bin_keys, problems, binary)
    paths = {
        k: (Path(v) if Path(v).is_absolute() else Path(base_dir) / v) for k, v in raw_bin.items() if k in BINARIES
    }
    pins = {k[: -len("_sha256")]: v for k, v in raw_bin.items() if k.endswith("_sha256")}

    def manual(_key: str, value: Any) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError("must be a path (a non-empty string)")
        return value

    raw_manual = _closed_table(doc, "manual", set(MANUAL_KEYS), problems, manual)
    manual_paths = {k: (Path(v) if Path(v).is_absolute() else Path(base_dir) / v) for k, v in raw_manual.items()}

    if problems:
        raise MachinesError(problems)
    return Machines(
        source_name=source_name,
        roles=roles,
        binaries=Binaries(paths, pins),
        params=params,
        images=images,
        manual=manual_paths,
    )


def load_machines(path: Path | str) -> Machines:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise MachinesError([f"cannot read {path.name}: {e.strerror or e}"]) from None
    return parse_machines(text, base_dir=path.resolve().parent, source_name=path.name)
