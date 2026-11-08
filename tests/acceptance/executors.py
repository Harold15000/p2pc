# SPDX-License-Identifier: Apache-2.0
"""How the harness runs a command on a machine. ALL shell quoting of the harness lives in this module.

Three executors:

* ``LocalExecutor``      runs the argv directly, on the machine that runs the harness.
* ``SshExecutor``        ``ssh <host> <command>``. The command is one string for the remote POSIX shell, built with
                         ``sh_join``.
* ``WslOverSshExecutor`` ssh to a Windows host, then ``wsl.exe -d <distro> -u root --exec sh -c ...`` through PowerShell.
                         Windows adds three layers of quoting (the Windows command line, PowerShell, wsl.exe) and
                         Windows PowerShell 5.1 mangles embedded double quotes when it calls a native program. So the
                         command never travels as text through those layers: it is base64, written to a file in a
                         private (mktemp -d, mode 0700) directory inside the distro and run there. Everything that crosses a layer is made of
                         ``[A-Za-z0-9+/=]`` or sits in a PowerShell single-quoted string with no double quote.

The tests decode what these functions build and run the result with a real shell, so a regression in the quoting shows
up without Windows. The one thing they cannot cover is Windows' own argument parsing: ``preflight`` in context.py
sends a round-trip probe through the real machine before any criterion runs.
"""

from __future__ import annotations

import base64
import hashlib
import re
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

import machines

SSH_DEFAULT_OPTIONS = (
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=4",
)

# cmd.exe, which is OpenSSH-for-Windows's default shell, limits a command line to 8191 characters.
MAX_WINDOWS_COMMAND_CHARS = 7500

_MODE_RE = re.compile(r"[0-7]{3,4}")
# Copies stdin to a path, creating the parent directory. The path and the mode are positional arguments, so they are
# never parsed as shell text.
_PUT_SCRIPT = 'mkdir -p "$(dirname "$1")" && cat > "$1" && chmod "$2" "$1"'

# Failures of ssh that happen BEFORE the session starts, so the command cannot have run: only these are retried.
_SSH_SETUP_FAILURE_RE = re.compile(
    # Anchored to the start of a line: these are OpenSSH's own line prefixes, so a remote command that prints the same
    # words (and exits 255) is never run a second time.
    r"(?m)^(?:ssh: connect to host \S+ port \d+: (?:Connection timed out|Connection refused|No route to host|Network is unreachable)"
    r"|ssh: Could not resolve hostname"
    r"|kex_exchange_identification)"
)
SSH_RETRY_DELAYS_S = (5.0, 15.0)


def is_ssh_setup_failure(res: "ExecResult") -> bool:
    """ssh exited 255 and said it never got a session going. Anything else (a drop mid-session, a plain 255) may mean the
    command ran, and is never retried."""
    return res.returncode == 255 and _SSH_SETUP_FAILURE_RE.search(res.stderr) is not None


# PowerShell treats these as quote characters, besides the ASCII one.
_PS_QUOTES = "'‘’‚‛"


class ExecError(Exception):
    """The harness could not run something (a bad host name, a command too long, a missing hash...)."""


@dataclass
class ExecResult:
    returncode: int | None  # None: the command did not run to the end (timeout, could not start)
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    timed_out: bool = False
    error: str = ""
    retries: int = 0  # ssh connection-setup failures that were retried before this result
    retry_first_error: str = ""  # the first of them (last stderr line), so a report shows the network blinked


# --------------------------------------------------------------------------------------------------------------
# Quoting (the one place)
# --------------------------------------------------------------------------------------------------------------


def sh_join(argv: Sequence[str]) -> str:
    """An argv as one string for a POSIX shell: running it gives back exactly these arguments."""
    return shlex.join(list(argv))


def ps_quote(text: str) -> str:
    """A PowerShell single-quoted string. Inside it nothing is special except the quote characters, which are doubled."""
    return "'" + "".join(c * 2 if c in _PS_QUOTES else c for c in text) + "'"


def encode_powershell(script: str) -> str:
    """The form `powershell -EncodedCommand` takes: base64 of the UTF-16LE script."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def wsl_remote_command(distro: str, argv: Sequence[str]) -> str:
    """The command string that ssh sends to the Windows host, to run ``argv`` as root in the WSL ``distro``.

    ``--exec`` (as ``deploy/wsl/install.ps1`` does), not the spec's ``--``: with ``--`` wsl.exe hands the line to the
    distro's default shell first, which expands ``$`` and re-splits the arguments before our ``sh -c`` ever sees them.
    ``--exec`` starts ``sh`` directly, so the one shell that reads the script is the one we chose."""
    payload = base64.b64encode(sh_join(argv).encode("utf-8")).decode("ascii")
    # No double quote anywhere. The script goes in a directory that `mktemp -d` makes (mode 0700, a random name), so
    # no other user can read it or plant a file at a predictable path, and parallel commands never share one. The
    # user's command reads the real stdin because the script is a file, not the pipe. If mktemp gives nothing that
    # starts with a slash, nothing runs.
    inner = (
        "d=$(mktemp -d); case $d in /*) ;; *) exit 70;; esac; "
        f"echo {payload} | base64 -d > $d/cmd.sh; sh $d/cmd.sh; rc=$?; rm -rf $d; exit $rc"
    )
    script = (
        "$ProgressPreference = 'SilentlyContinue'; "
        f"& wsl.exe -d {ps_quote(distro)} -u root --exec sh -c {ps_quote(inner)}; "
        "exit $LASTEXITCODE"
    )
    command = "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + encode_powershell(script)
    if len(command) > MAX_WINDOWS_COMMAND_CHARS:
        raise ExecError(
            f"the command is too long for a Windows command line ({len(command)} characters, the limit is "
            f"{MAX_WINDOWS_COMMAND_CHARS}); send data with put() and keep the command short"
        )
    return command


def refuse_chained(script: str) -> None:
    """The token is the stdin of the ssh call, and PowerShell gives it to the FIRST pipeline of the script only. A script
    of several statements (``;``, a newline, ``&&``, ``||``) would give it to the first and nothing to the rest, so an
    ``install_command`` that gets a token must be a single command (``& 'C:\\\\p2pc-dist\\\\install.ps1' -Join [-Force]``)."""
    if machines.CHAINED_RE.search(script):
        raise ExecError(
            "a command that gets the join token on its stdin must be a single command, with no `;`, `&&`, `||` or newline: "
            "PowerShell gives the pipeline only to the first statement (use `& '<path>\\install.ps1' -Join [-Force]`; "
            "run Unblock-File yourself, once)"
        )


def windows_host_command(script: str, *, pipe_stdin: bool = False) -> str:
    """The command string that ssh sends to the Windows host to run ``script`` in PowerShell. With ``pipe_stdin`` the stdin
    of the ssh call becomes the pipeline of the script (``$input | <script>``): the join token reaches ``install.ps1 -Join``
    that way, as its documentation says, and never as an argument. The exit code is the script's own."""
    if pipe_stdin:
        refuse_chained(script)
    body = f"$input | {script}" if pipe_stdin else script
    full = f"$ProgressPreference = 'SilentlyContinue'; {body}; exit $LASTEXITCODE"
    # `-ExecutionPolicy Bypass`: the default policy of a Windows client is Restricted, which refuses to run any .ps1 (so
    # `install.ps1` would fail before it starts). It applies to this process only. A downloaded script may also carry the
    # "from the internet" mark: `Unblock-File` on it (see the README).
    command = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encode_powershell(full)
    if len(command) > MAX_WINDOWS_COMMAND_CHARS:
        raise ExecError(
            f"the script is too long for a Windows command line ({len(command)} characters, the limit is "
            f"{MAX_WINDOWS_COMMAND_CHARS}): put it in a .ps1 file on the host and run that"
        )
    return command


def file_sha256(path: Path | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------------------------------------------
# Executors
# --------------------------------------------------------------------------------------------------------------

Runner = Callable[..., "subprocess.CompletedProcess[bytes]"]


# How long a command that was held open gets to exit after its stdin is closed, before it is killed.
HOLD_EXIT_GRACE_S = 10.0


class Executor:
    description = "?"

    def __init__(self, runner: Runner = subprocess.run, popen: Callable[..., Any] = subprocess.Popen):
        self._runner = runner
        self._popen = popen

    def _local_argv(self, argv: Sequence[str]) -> list[str]:  # pragma: no cover - abstract
        raise NotImplementedError

    retry_delays_s: Sequence[float] = ()
    _sleep: Callable[[float], None] = staticmethod(time.sleep)

    def run(self, argv: Sequence[str], **kwargs: Any) -> ExecResult:
        """Runs ``argv`` (see ``_run_once``). Where ``retry_delays_s`` is set (ssh), a connection-setup failure is retried
        after each delay, and the result says how many retries there were and the first error."""
        first_error = ""
        retries = 0
        t0 = time.monotonic()
        for delay in self.retry_delays_s:
            res = self._run_once(argv, **kwargs)
            if not is_ssh_setup_failure(res):
                break
            if not first_error:
                first_error = res.stderr.strip().splitlines()[-1] if res.stderr.strip() else "ssh exited 255"
            retries += 1
            self._sleep(delay)
        else:
            res = self._run_once(argv, **kwargs)
        if retries:
            # The whole call: the timed-out connects and the waits too, not only the last attempt.
            res.retries, res.retry_first_error = retries, first_error
            res.duration_s = max(res.duration_s, time.monotonic() - t0)
        return res

    def _run_once(
        self,
        argv: Sequence[str],
        *,
        timeout: float = 120.0,
        stdin: bytes | None = None,
        stdin_file: Path | None = None,
        hold_stdin_until: Callable[[str], bool] | None = None,
        hold_deadline_s: float | None = None,
    ) -> ExecResult:
        """Runs ``argv`` on the machine. A non-zero exit, a timeout and a program that cannot start are results, not
        exceptions: the criteria decide what they mean.

        ``hold_stdin_until``: write ``stdin`` but keep the pipe OPEN until ``hold_stdin_until(stdout so far)`` is true,
        the command exits, or ``hold_deadline_s`` passes; only then close it. A server that treats end-of-input as
        "shut down" (an MCP server over stdio) drops the answers still in flight if stdin is closed right after the
        requests are written."""
        local = self._local_argv(argv)
        if hold_stdin_until is not None:
            return self._run_held(local, stdin or b"", hold_stdin_until, hold_deadline_s, timeout)
        kwargs: dict = {"capture_output": True, "timeout": timeout}
        fh = None
        t0 = time.monotonic()
        try:
            if stdin_file is not None:
                fh = open(stdin_file, "rb")
                kwargs["stdin"] = fh
            elif stdin is not None:
                kwargs["input"] = stdin
            else:
                kwargs["stdin"] = subprocess.DEVNULL  # never let a child eat the harness's own stdin
            cp = self._runner(local, **kwargs)
        except subprocess.TimeoutExpired as e:
            return ExecResult(
                None,
                stdout=(e.stdout or b"").decode("utf-8", "replace"),
                stderr=(e.stderr or b"").decode("utf-8", "replace"),
                duration_s=time.monotonic() - t0,
                timed_out=True,
            )
        except OSError as e:
            return ExecResult(
                None, duration_s=time.monotonic() - t0, error=f"cannot start {local[0]}: {e.strerror or e}"
            )
        finally:
            if fh is not None:
                fh.close()
        return ExecResult(
            cp.returncode,
            stdout=(cp.stdout or b"").decode("utf-8", "replace"),
            stderr=(cp.stderr or b"").decode("utf-8", "replace"),
            duration_s=time.monotonic() - t0,
        )

    def _run_held(
        self,
        local: list[str],
        data: bytes,
        until: Callable[[str], bool],
        deadline_s: float | None,
        timeout: float,
    ) -> ExecResult:
        t0 = time.monotonic()
        try:
            proc = self._popen(local, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            return ExecResult(None, duration_s=time.monotonic() - t0, error=f"cannot start {local[0]}: {e.strerror or e}")
        out: list[bytes] = []
        err: list[bytes] = []
        lock = threading.Lock()
        satisfied = threading.Event()
        eof = threading.Event()

        def read_out() -> None:
            for chunk in iter(lambda: proc.stdout.read1(65536), b""):
                with lock:
                    out.append(chunk)
                    text = b"".join(out).decode("utf-8", "replace")
                if until(text):
                    satisfied.set()
            eof.set()

        def read_err() -> None:
            for chunk in iter(lambda: proc.stderr.read1(65536), b""):
                with lock:
                    err.append(chunk)

        threads = [threading.Thread(target=read_out, daemon=True), threading.Thread(target=read_err, daemon=True)]
        for t in threads:
            t.start()
        try:
            proc.stdin.write(data)
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass  # the command already exited: its output says why
        hold = min(deadline_s if deadline_s is not None else timeout, timeout)
        timed_out = False
        # Wait for the answers (or the command's own end, or the deadline); then, and only then, close stdin.
        waiter_done = threading.Event()

        def wait_exit() -> None:
            proc.wait()
            waiter_done.set()

        threading.Thread(target=wait_exit, daemon=True).start()
        end = time.monotonic() + hold
        while not waiter_done.is_set():
            remaining = end - time.monotonic()
            if remaining <= 0 or satisfied.wait(timeout=min(0.05, remaining)):
                break
        try:
            proc.stdin.close()
        except OSError:
            pass
        grace = max(0.0, min(HOLD_EXIT_GRACE_S, timeout - (time.monotonic() - t0)))
        if not waiter_done.wait(timeout=grace):
            timed_out = True
            proc.kill()
            waiter_done.wait(timeout=5)
        # After a kill, a grandchild may still hold the pipes open: do not wait for it.
        eof.wait(timeout=0.5 if timed_out else 5)
        for t in threads:
            t.join(timeout=0.5 if timed_out else 5)
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        with lock:
            stdout = b"".join(out).decode("utf-8", "replace")
            stderr = b"".join(err).decode("utf-8", "replace")
        return ExecResult(
            None if timed_out else proc.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_s=time.monotonic() - t0,
            timed_out=timed_out,
        )

    def run_on_host(self, script: str, *, timeout: float = 120.0, stdin: bytes | None = None) -> ExecResult:
        """Runs a PowerShell ``script`` on the Windows host of a WSL role (where ``deploy/wsl/install.ps1`` runs). Only
        ``wsl_over_ssh`` machines have one."""
        raise ExecError(f"{self.description} is not a Windows host: there is no PowerShell to run a script in")

    def put(self, local: Path | str, remote: str, mode: str = "755", timeout: float = 600.0) -> ExecResult:
        """Copies a local file to ``remote`` (an absolute path on the machine) by streaming it through stdin."""
        if not _MODE_RE.fullmatch(mode):
            raise ExecError(f"bad file mode {mode!r}")
        return self.run(["sh", "-c", _PUT_SCRIPT, "sh", remote, mode], stdin_file=Path(local), timeout=timeout)

    def sha256(self, remote: str) -> str:
        return self.sha256_result(remote)[0]

    def sha256_result(self, remote: str) -> tuple[str, ExecResult]:
        """The hash and the run that made it (so a report can show its duration and its ssh retries)."""
        res = self.run(["sha256sum", remote], timeout=120)
        first = res.stdout.split()[0] if res.stdout.split() else ""
        if res.returncode != 0 or not re.fullmatch(r"[0-9a-f]{64}", first):
            raise ExecError(f"cannot hash {remote} on {self.description}: {res.stderr.strip() or res.error or 'no output'}")
        return first, res


class LocalExecutor(Executor):
    description = "local"

    def _local_argv(self, argv: Sequence[str]) -> list[str]:
        return list(argv)

    def sha256_result(self, remote: str) -> tuple[str, ExecResult]:
        t0 = time.monotonic()
        try:
            return file_sha256(remote), ExecResult(0, duration_s=time.monotonic() - t0)
        except OSError as e:
            raise ExecError(f"cannot hash {remote}: {e.strerror or e}") from None


def _check_host(host: str) -> str:
    if not machines.HOST_RE.fullmatch(host):
        raise ExecError("bad ssh host alias (letters, digits, . _ @ -; not starting with -)")
    return host


class SshExecutor(Executor):
    def __init__(
        self,
        host: str,
        options: Sequence[str] = (),
        ssh_bin: str = "ssh",
        runner: Runner = subprocess.run,
        popen: Callable[..., Any] = subprocess.Popen,
        sleep: Callable[[float], None] = time.sleep,
    ):
        super().__init__(runner, popen)
        self._sleep = sleep
        self.retry_delays_s = SSH_RETRY_DELAYS_S
        self.host = _check_host(host)
        self.options = list(options)
        self.ssh_bin = ssh_bin
        self.description = f"ssh {host}"

    def _prefix(self) -> list[str]:
        return [self.ssh_bin, *SSH_DEFAULT_OPTIONS, *self.options, self.host]

    def _local_argv(self, argv: Sequence[str]) -> list[str]:
        return [*self._prefix(), sh_join(argv)]


class WslOverSshExecutor(SshExecutor):
    def __init__(
        self,
        host: str,
        distro: str,
        options: Sequence[str] = (),
        ssh_bin: str = "ssh",
        runner: Runner = subprocess.run,
        popen: Callable[..., Any] = subprocess.Popen,
        sleep: Callable[[float], None] = time.sleep,
    ):
        super().__init__(host, options=options, ssh_bin=ssh_bin, runner=runner, popen=popen, sleep=sleep)
        if not machines.DISTRO_RE.fullmatch(distro):
            raise ExecError("bad WSL distro name (letters, digits, . _ -; not starting with -)")
        self.distro = distro
        self.description = f"wsl {distro} over ssh {host}"

    def _local_argv(self, argv: Sequence[str]) -> list[str]:
        return [*self._prefix(), wsl_remote_command(self.distro, argv)]

    def run_on_host(self, script: str, *, timeout: float = 120.0, stdin: bytes | None = None) -> ExecResult:
        command = windows_host_command(script, pipe_stdin=stdin is not None)
        return _HostPowerShell(self, command).run(["powershell"], timeout=timeout, stdin=stdin)


class _HostPowerShell(SshExecutor):
    """The same ssh connection as a ``WslOverSshExecutor``, with a PowerShell command in place of the distro's."""

    def __init__(self, parent: "WslOverSshExecutor", command: str):
        super().__init__(parent.host, options=parent.options, ssh_bin=parent.ssh_bin, runner=parent._runner, popen=parent._popen, sleep=parent._sleep)
        self._command = command
        self.description = f"powershell on {parent.host}"

    def _local_argv(self, argv: Sequence[str]) -> list[str]:
        return [*self._prefix(), self._command]


def make_executor(role: machines.Role, *, ssh_bin: str = "ssh", runner: Runner = subprocess.run) -> Executor:
    if role.executor == "local":
        return LocalExecutor(runner)
    if role.executor == "ssh":
        return SshExecutor(role.host or "", options=role.ssh_options, ssh_bin=ssh_bin, runner=runner)
    if role.executor == "wsl_over_ssh":
        return WslOverSshExecutor(
            role.host or "", role.distro or "", options=role.ssh_options, ssh_bin=ssh_bin, runner=runner
        )
    raise ExecError(f"unknown executor {role.executor!r}")
