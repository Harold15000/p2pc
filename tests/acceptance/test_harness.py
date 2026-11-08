# SPDX-License-Identifier: Apache-2.0
"""Tests of the acceptance harness itself (stdlib only; no network, no real machines).

Run with:  python3 -m unittest discover tests/acceptance
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import context  # noqa: E402
import criteria  # noqa: E402
import core  # noqa: E402
import executors  # noqa: E402
import flows  # noqa: E402
import machines  # noqa: E402
import product  # noqa: E402
import report  # noqa: E402
import run as runner  # noqa: E402

# Fake secrets, built at runtime so that no secret-looking literal sits in the repo.
FAKE_KEY = "p2pc_sk_" + "abcdefghijkl" + "_" + "q" * 52
FAKE_JOIN = "p2pc_join_" + "MFRGGZDFMZTWQ2LK" * 4


class StatusRules(unittest.TestCase):
    def test_blocked_is_never_a_pass(self):
        self.assertEqual(core.aggregate([core.PASS, core.BLOCKED]), core.BLOCKED)
        self.assertEqual(core.aggregate([core.BLOCKED]), core.BLOCKED)
        self.assertNotEqual(core.aggregate([core.PASS, core.PASS, core.BLOCKED]), core.PASS)

    def test_skip_is_never_a_pass_either(self):
        self.assertEqual(core.aggregate([core.PASS, core.SKIP]), core.SKIP)

    def test_precedence_is_fail_then_blocked_then_skip_then_pass(self):
        self.assertEqual(core.aggregate([core.PASS, core.SKIP, core.BLOCKED, core.FAIL]), core.FAIL)
        self.assertEqual(core.aggregate([core.PASS, core.SKIP, core.BLOCKED]), core.BLOCKED)
        self.assertEqual(core.aggregate([core.PASS, core.SKIP]), core.SKIP)
        self.assertEqual(core.aggregate([core.PASS, core.PASS]), core.PASS)

    def test_no_evidence_is_not_a_pass(self):
        self.assertEqual(core.aggregate([]), core.FAIL)

    def test_unknown_status_is_refused(self):
        with self.assertRaises(ValueError):
            core.aggregate(["passed"])

    def test_summary_counts_blocked_apart_from_pass(self):
        results = []
        for status in (core.PASS, core.BLOCKED, core.BLOCKED, core.SKIP, core.FAIL):
            r = core.Result("AC-X", "t")
            r.add_check("c", status, reason="r")
            results.append(r)
        counts = core.summarize(results)
        self.assertEqual(counts, {"pass": 1, "fail": 1, "skip": 1, "blocked": 2})

    def test_overall_exit_code(self):
        def res(*statuses):
            r = core.Result("AC-X", "t")
            for i, s in enumerate(statuses):
                r.add_check(f"c{i}", s, reason="r")
            return r

        self.assertEqual(core.exit_code([res(core.PASS), res(core.BLOCKED)], strict=False), 0)
        self.assertEqual(core.exit_code([res(core.PASS), res(core.FAIL)], strict=False), 1)
        # --strict is the release gate: only all-pass is acceptable.
        self.assertEqual(core.exit_code([res(core.PASS), res(core.BLOCKED)], strict=True), 1)
        self.assertEqual(core.exit_code([res(core.PASS), res(core.SKIP)], strict=True), 1)
        self.assertEqual(core.exit_code([res(core.PASS)], strict=True), 0)


class ResultAndChecks(unittest.TestCase):
    def test_a_check_that_raises_nothing_passes(self):
        r = core.Result("AC-X", "t")
        with r.check("ok"):
            pass
        self.assertEqual(r.checks[0].status, core.PASS)
        self.assertEqual(r.status, core.PASS)

    def test_blocked_skip_and_failure_exceptions_set_the_status(self):
        r = core.Result("AC-X", "t")
        with r.check("b"):
            raise core.Blocked("p2pc results does not exist yet", ["T10", "T11b"])
        with r.check("s"):
            raise core.Skipped("no gitleaks")
        with r.check("f"):
            raise core.CheckFailed("exit 3")
        with r.check("boom"):
            raise RuntimeError("unexpected")
        statuses = [c.status for c in r.checks]
        self.assertEqual(statuses, [core.BLOCKED, core.SKIP, core.FAIL, core.FAIL])
        self.assertEqual(r.checks[0].unblocked_by, ["T10", "T11b"])
        self.assertIn("RuntimeError", r.checks[3].reason)
        self.assertEqual(r.status, core.FAIL)
        self.assertEqual(r.unblocked_by, ["T10", "T11b"])

    def test_require_raises_a_failure_with_the_message(self):
        r = core.Result("AC-X", "t")
        with r.check("c") as c:
            c.require(1 == 2, "one is not two")
        self.assertEqual(r.checks[0].status, core.FAIL)
        self.assertEqual(r.checks[0].reason, "one is not two")

    def test_a_dependent_check_inherits_blocked_and_skips_after_a_failure(self):
        r = core.Result("AC-X", "t")
        with r.check("first"):
            raise core.Blocked("missing", ["T04"])
        with r.check("second") as c:
            c.needs("first")
            raise AssertionError("must not run")  # pragma: no cover
        with r.check("third"):
            raise core.CheckFailed("bad")
        with r.check("fourth") as c:
            c.needs("third")
            raise AssertionError("must not run")  # pragma: no cover
        by_name = {c.name: c for c in r.checks}
        self.assertEqual(by_name["second"].status, core.BLOCKED)
        self.assertEqual(by_name["second"].unblocked_by, ["T04"])
        self.assertEqual(by_name["fourth"].status, core.SKIP)
        self.assertIn("third", by_name["fourth"].reason)

    def test_keyboard_interrupt_is_not_swallowed(self):
        r = core.Result("AC-X", "t")
        with self.assertRaises(KeyboardInterrupt):
            with r.check("c"):
                raise KeyboardInterrupt

    def test_timings_and_evidence_are_kept(self):
        r = core.Result("AC-X", "t")
        with r.check("c") as c:
            c.timing("submit_to_start_s", 1.5)
            c.evidence["sha256"] = "ab" * 32
        self.assertEqual(r.checks[0].timings, {"submit_to_start_s": 1.5})
        self.assertEqual(r.checks[0].evidence["sha256"], "ab" * 32)

    def test_a_result_without_checks_fails(self):
        self.assertEqual(core.Result("AC-X", "t").status, core.FAIL)

    def test_steps_recorded_during_a_check_belong_to_that_check(self):
        r = core.Result("AC-X", "t")
        with r.check("c"):
            r.record_step(core.Step(label="x", role="server", command="p2pc whoami", exit_code=0))
        self.assertEqual(len(r.checks[0].steps), 1)
        self.assertEqual(r.checks[0].steps[0].command, "p2pc whoami")


class Redaction(unittest.TestCase):
    def test_keys_and_join_tokens_are_redacted(self):
        text = f"key={FAKE_KEY} and token {FAKE_JOIN}."
        out = core.redact(text)
        self.assertNotIn(FAKE_KEY, out)
        self.assertNotIn(FAKE_JOIN, out)
        self.assertNotIn("p2pc_sk_", out)
        self.assertNotIn("p2pc_join_", out)
        self.assertEqual(out.count("<redacted>"), 2)

    def test_redaction_stops_at_the_end_of_the_secret(self):
        self.assertEqual(core.redact(f'"{FAKE_KEY}",'), '"<redacted>",')
        self.assertEqual(core.redact(f"export K={FAKE_KEY}\nnext line"), "export K=<redacted>\nnext line")

    def test_a_server_address_is_not_a_secret(self):
        self.assertEqual(core.redact("p2pc_srv_MFRGGZDF"), "p2pc_srv_MFRGGZDF")

    def test_extra_literal_secrets_are_redacted_too(self):
        red = core.Redactor()
        red.add_secret("hunter2-hunter2")
        self.assertEqual(red.redact("pw=hunter2-hunter2"), "pw=<redacted>")
        # Too short to be worth redacting everywhere (it would shred ordinary words).
        red.add_secret("abc")
        self.assertEqual(red.redact("abc"), "abc")

    def test_redact_object_walks_keys_and_values_but_keeps_types(self):
        obj = {"a": [FAKE_KEY, {"b": FAKE_JOIN, "n": 3, "ok": True, "none": None}], FAKE_KEY: "x"}
        out = core.redact_object(obj)
        dumped = json.dumps(out)
        self.assertNotIn("p2pc_sk_", dumped)
        self.assertNotIn("p2pc_join_", dumped)
        self.assertEqual(out["a"][1]["n"], 3)
        self.assertIs(out["a"][1]["ok"], True)
        self.assertIsNone(out["a"][1]["none"])

    def test_bytes_with_invalid_utf8_are_handled(self):
        self.assertEqual(core.redact_bytes(b"\xff" + FAKE_KEY.encode()), "�<redacted>")

    def test_a_step_never_stores_a_secret(self):
        step = core.Step(
            label="login",
            role="server",
            command=f"p2pc login --token {FAKE_JOIN}",
            exit_code=1,
            stdout=f"your key is {FAKE_KEY}",
            stderr=f"bad {FAKE_KEY}",
        )
        dumped = json.dumps(step.to_dict())
        self.assertNotIn("p2pc_sk_", dumped)
        self.assertNotIn("p2pc_join_", dumped)

    def test_excerpts_are_short_and_keep_head_and_tail(self):
        text = "H" * 100 + "M" * 5000 + "T" * 100
        out = core.excerpt(text, limit=300)
        self.assertLessEqual(len(out), 400)
        self.assertTrue(out.startswith("H" * 50))
        self.assertTrue(out.endswith("T" * 50))
        self.assertIn("omitted", out)
        self.assertEqual(core.excerpt("short", limit=300), "short")

    def test_terminal_colours_are_stripped_from_excerpts(self):
        step = core.Step(label="l", role="r", command="c", exit_code=0, stderr="\x1b[90m4:29PM\x1b[0m \x1b[33mWRN\x1b[0m leaks")
        self.assertEqual(step.to_dict()["stderr_excerpt"], "4:29PM WRN leaks")

    def test_the_excerpt_cannot_cut_a_secret_in_half_and_leak_the_rest(self):
        # The secret is redacted BEFORE the excerpt is cut, so a cut can never leave a readable half.
        text = "x" * 5000 + FAKE_KEY + "y" * 5000
        step = core.Step(label="l", role="r", command="c", exit_code=0, stdout=text)
        dumped = json.dumps(step.to_dict())
        self.assertNotIn("qqqqq", dumped)


def parse(text: str) -> "machines.Machines":
    return machines.parse_machines(textwrap.dedent(text), base_dir=Path("/base"))


def problems(text: str) -> list[str]:
    try:
        parse(text)
    except machines.MachinesError as e:
        return e.problems
    raise AssertionError("expected a MachinesError")


class MachinesSchema(unittest.TestCase):
    def test_the_shipped_example_is_valid(self):
        m = machines.load_machines(HERE / "machines.example.toml")
        self.assertEqual(set(m.roles), set(machines.ROLES))
        # Everything is disabled in the example, so `--only AC-12` is the only thing that runs from it.
        self.assertTrue(all(not r.enabled for r in m.roles.values()))
        self.assertEqual({r.executor for r in m.roles.values()}, {"ssh", "wsl_over_ssh"})

    def test_a_minimal_file_with_the_three_executors(self):
        m = parse(
            """
            [server]
            executor = "local"

            [node_linux_gpu]
            executor = "ssh"
            host = "node-linux"

            [node_wsl2_gpu]
            executor = "wsl_over_ssh"
            host = "win-box"
            distro = "p2pc-node"
            """
        )
        self.assertEqual(m.roles["server"].executor, "local")
        self.assertEqual(m.roles["node_linux_gpu"].host, "node-linux")
        wsl = m.roles["node_wsl2_gpu"]
        self.assertEqual((wsl.host, wsl.distro), ("win-box", "p2pc-node"))
        self.assertTrue(wsl.enabled)  # the default
        self.assertIsNone(wsl.workdir)  # no predictable default: a private directory is made at run time

    def test_defaults_for_params_images_and_binaries(self):
        m = parse('[server]\nexecutor = "local"\n')
        self.assertEqual(m.params["job_count"], 100)
        self.assertEqual(m.params["jobs_per_node"], 4)
        self.assertEqual(m.params["overhead_budget_s"], 5)
        self.assertIn("python", m.images["cpu"])
        self.assertIsNone(m.binaries.get("p2pc"))

    def test_binary_paths_are_relative_to_the_machines_file(self):
        m = parse(
            """
            [server]
            executor = "local"
            [binaries]
            p2pc = "../../target/release/p2pc"
            p2pc_agent = "/abs/p2pc-agent"
            p2pc_sha256 = "%s"
            """
            % ("ab" * 32)
        )
        self.assertEqual(m.binaries.path("p2pc"), Path("/base/../../target/release/p2pc"))
        self.assertEqual(m.binaries.path("p2pc_agent"), Path("/abs/p2pc-agent"))
        self.assertEqual(m.binaries.pinned_sha256("p2pc"), "ab" * 32)
        self.assertIsNone(m.binaries.pinned_sha256("p2pc_agent"))

    def test_invalid_toml_is_a_machines_error(self):
        p = problems("[server\nexecutor = ")
        self.assertTrue(p[0].startswith("invalid TOML"))

    def test_unknown_top_level_table_and_unknown_role(self):
        p = problems('[server]\nexecutor = "local"\n[nodes]\nexecutor = "local"\n')
        self.assertTrue(any("unknown table [nodes]" in x for x in p), p)

    def test_an_empty_file_has_no_roles(self):
        self.assertTrue(any("no machine roles" in x for x in problems("# nothing\n")))

    def test_the_executor_is_required_and_checked(self):
        self.assertTrue(any("[server] executor: required" in x for x in problems("[server]\n")))
        p = problems('[server]\nexecutor = "rsh"\n')
        self.assertTrue(any('[server] executor: "rsh" is not one of' in x for x in p), p)

    def test_ssh_needs_a_host_and_wsl_needs_a_distro_too(self):
        p = problems('[node_linux_gpu]\nexecutor = "ssh"\n')
        self.assertTrue(any("[node_linux_gpu] host: required" in x for x in p), p)
        p = problems('[node_wsl2_gpu]\nexecutor = "wsl_over_ssh"\nhost = "h"\n')
        self.assertTrue(any("[node_wsl2_gpu] distro: required" in x for x in p), p)

    def test_local_must_not_name_a_host_or_a_distro(self):
        p = problems('[server]\nexecutor = "local"\nhost = "x"\n')
        self.assertTrue(any("[server] host: not allowed" in x for x in p), p)
        p = problems('[server]\nexecutor = "ssh"\nhost = "x"\ndistro = "d"\n')
        self.assertTrue(any("[server] distro: only for executor" in x for x in p), p)

    def test_hosts_and_distros_cannot_smuggle_options_or_shell(self):
        for bad in ("-oProxyCommand=x", "a b", "a;b", "h\\nx", ""):
            p = problems(f'[server]\nexecutor = "ssh"\nhost = {json.dumps(bad)}\n')
            self.assertTrue(any("[server] host:" in x for x in p), (bad, p))
        for bad in ("my distro", "d'x", "d;x", "-d"):
            p = problems(f'[node_wsl2_gpu]\nexecutor = "wsl_over_ssh"\nhost = "h"\ndistro = {json.dumps(bad)}\n')
            self.assertTrue(any("[node_wsl2_gpu] distro:" in x for x in p), (bad, p))

    def test_types_are_checked_and_every_problem_is_reported_at_once(self):
        p = problems(
            """
            [server]
            executor = "local"
            enabled = "yes"
            url = "ftp://x"
            workdir = "relative/dir"
            allowed_listen_ports = [22, "ssh", 70000]
            [client_remote]
            executor = "ssh"
            """
        )
        joined = "\n".join(p)
        self.assertIn("[server] enabled: must be true or false", joined)
        self.assertIn("[server] url: must start with http:// or https://", joined)
        self.assertIn("[server] workdir: must be an absolute POSIX path", joined)
        self.assertIn("[server] allowed_listen_ports:", joined)
        self.assertIn("[client_remote] host: required", joined)
        self.assertGreaterEqual(len(p), 5)

    def test_unknown_keys_are_rejected_to_catch_typos(self):
        p = problems('[server]\nexecutor = "local"\nurll = "http://x"\n')
        self.assertTrue(any("[server] urll: unknown key" in x for x in p), p)
        # A key that exists for another role is not valid here.
        p = problems('[client_remote]\nexecutor = "local"\npartition_command = "x"\n')
        self.assertTrue(any("[client_remote] partition_command: unknown key" in x for x in p), p)

    def test_params_images_binaries_and_manual_are_validated(self):
        p = problems(
            """
            [server]
            executor = "local"
            [params]
            job_count = 0
            jobs_per_node = "four"
            nope = 1
            [images]
            cpu = "has space"
            [binaries]
            p2pc_sha256 = "xyz"
            wat = "x"
            [manual]
            pentest_report = 3
            """
        )
        joined = "\n".join(p)
        self.assertIn("[params] job_count: must be an integer between 1 and 1000", joined)
        self.assertIn("[params] jobs_per_node:", joined)
        self.assertIn("[params] nope: unknown key", joined)
        self.assertIn("[images] cpu:", joined)
        self.assertIn("[binaries] p2pc_sha256: must be 64 hex characters", joined)
        self.assertIn("[binaries] wat: unknown key", joined)
        self.assertIn("[manual] pentest_report: must be a path", joined)

    def test_the_error_message_lists_the_problems_and_never_a_value_that_looks_like_a_secret(self):
        try:
            parse(f'[server]\nexecutor = "local"\nurl = "{FAKE_KEY}"\n')
        except machines.MachinesError as e:
            self.assertNotIn("p2pc_sk_", str(e))
            self.assertNotIn("p2pc_sk_", "".join(e.problems))
        else:  # pragma: no cover
            self.fail("expected an error")


NASTY_ARGV = [
    "printf",
    "%s|%s|%s|%s",
    "it's a \"quoted\"  string",
    "two  spaces; $HOME `id` $(echo x) && rm -rf /",
    "\u00fcn\u00ef c\u00f6d\u00e9 \u2018curly\u2019",
    "",
]


def direct_output(argv: list[str]) -> str:
    return subprocess.run(argv, capture_output=True, text=True, check=True).stdout


LEDGER = "the ledger totals match (this run's jobs and key only)"


PS_QUOTES = "'\u2018\u2019\u201a\u201b"


def ps_tokens(segment: str) -> list[str]:
    """A minimal PowerShell tokenizer for the one statement the harness builds: bare words and single-quoted strings
    (with ``''`` as the escape), up to the first unquoted ``;``. It is the test's own parser, so it checks the
    harness's quoting independently of the code that produced it."""
    tokens, i = [], 0
    while i < len(segment):
        ch = segment[i]
        if ch.isspace():
            i += 1
        elif ch == ";":
            break
        else:
            buf, quoted = "", False
            while i < len(segment):
                ch = segment[i]
                if ch in PS_QUOTES:
                    quoted = True
                    i += 1
                    while True:
                        if segment[i] in PS_QUOTES:
                            if i + 1 < len(segment) and segment[i + 1] in PS_QUOTES:
                                buf += segment[i]  # a doubled quote character is one literal character
                                i += 2
                                continue
                            i += 1
                            break
                        buf += segment[i]
                        i += 1
                    continue
                if ch.isspace() or ch == ";":
                    break
                buf += ch
                i += 1
            tokens.append(buf)
            assert quoted or buf
    return tokens


def decode_ssh_argv(local_argv: list[str]) -> tuple[str, list[str], str]:
    """(ssh host, wsl.exe arguments, the PowerShell script) from the argv the executor handed to ssh."""
    host, remote = local_argv[-2], local_argv[-1]
    prefix = "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
    assert remote.startswith(prefix), remote
    encoded = remote[len(prefix) :]
    assert re.fullmatch(r"[A-Za-z0-9+/=]+", encoded)
    script = base64.b64decode(encoded).decode("utf-16-le")
    start = script.index("& wsl.exe")
    return host, ps_tokens(script[start + 2 :]), script


class FakeRunner:
    """Stands in for subprocess.run and records the local argv and what was sent to stdin."""

    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.calls: list[tuple[list[str], dict]] = []
        self._result = (returncode, stdout, stderr)

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        rc, out, err = self._result
        return subprocess.CompletedProcess(argv, rc, out, err)


class Quoting(unittest.TestCase):
    def test_sh_join_round_trips_through_a_real_shell(self):
        for argv in (NASTY_ARGV, ["printf", "%s", "a'b"], ["printf", "%s", "\\n$'x'"]):
            out = subprocess.run(["sh", "-c", executors.sh_join(argv)], capture_output=True, text=True, check=True).stdout
            self.assertEqual(out, direct_output(argv))

    def test_ps_quote(self):
        self.assertEqual(executors.ps_quote("abc"), "'abc'")
        self.assertEqual(executors.ps_quote("it's"), "'it''s'")
        # PowerShell treats the typographic quotes as quotes too.
        for q in "\u2018\u2019\u201a\u201b":
            self.assertEqual(ps_tokens(executors.ps_quote("a" + q + "b")), ["a" + q + "b"])
        self.assertEqual(ps_tokens(executors.ps_quote("it's \"x\" $y `z`")), ["it's \"x\" $y `z`"])

    def test_encode_powershell_is_base64_of_utf16le(self):
        enc = executors.encode_powershell("Write-Output 'h\u00e9'")
        self.assertEqual(base64.b64decode(enc).decode("utf-16-le"), "Write-Output 'h\u00e9'")


class WslOverSsh(unittest.TestCase):
    def make(self, runner=None, distro="p2pc-node"):
        runner = runner or FakeRunner()
        return executors.WslOverSshExecutor("win-box", distro, runner=runner), runner

    def test_the_command_has_the_documented_shape(self):
        ex, runner = self.make()
        ex.run(["echo", "hi"])
        local_argv, _ = runner.calls[0]
        self.assertEqual(local_argv[0], "ssh")
        self.assertIn("BatchMode=yes", local_argv)
        host, wsl_args, script = decode_ssh_argv(local_argv)
        self.assertEqual(host, "win-box")
        # --exec (as deploy/wsl/install.ps1 does), never `--`: no pass through the distro's default shell.
        self.assertEqual(wsl_args[:8], ["wsl.exe", "-d", "p2pc-node", "-u", "root", "--exec", "sh", "-c"])
        self.assertNotIn("--", wsl_args)
        self.assertEqual(len(wsl_args), 9)
        self.assertTrue(script.rstrip().endswith("exit $LASTEXITCODE"))

    def test_a_command_with_quotes_and_spaces_survives_every_layer(self):
        ex, runner = self.make()
        ex.run(NASTY_ARGV)
        _, wsl_args, _ = decode_ssh_argv(runner.calls[0][0])
        inner = wsl_args[8]
        # What wsl.exe hands to the distro: `sh -c <inner>`. Run exactly that, with a real shell.
        out = subprocess.run(["sh", "-c", inner], capture_output=True, text=True, check=True).stdout
        self.assertEqual(out, direct_output(NASTY_ARGV))

    def test_an_extra_shell_pass_does_not_expand_anything_early(self):
        """What --exec avoids: some layer that runs `sh -c <inner>` through one more shell, as wsl.exe does without
        --exec. When that layer quotes properly (as here), the inner script must still run unchanged: nothing may be
        expanded by the outer shell, and the temporary directory must be made by the inner one."""
        ex, runner = self.make()
        ex.run(NASTY_ARGV)
        inner = decode_ssh_argv(runner.calls[0][0])[1][8]
        with tempfile.TemporaryDirectory() as base:
            env = dict(os.environ, TMPDIR=base, HOME=base)
            outer = "bash -c " + shlex.quote("sh -c " + shlex.quote(inner))  # bash -c 'sh -c "<inner>"'
            done = subprocess.run(["sh", "-c", outer], env=env, capture_output=True, text=True)
            self.assertEqual(done.stdout, direct_output(NASTY_ARGV))
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(list(Path(base).iterdir()), [])
        # The unquoted form is what the distro's default shell would do without --exec: `$d` is expanded by the
        # outer shell (to nothing) and the script never runs. That is why the argv must say --exec.
        with tempfile.TemporaryDirectory() as base:
            env = dict(os.environ, TMPDIR=base)
            naive = subprocess.run(["bash", "-c", f'sh -c "{inner}"'], env=env, capture_output=True, text=True)
            self.assertNotEqual(naive.stdout, direct_output(NASTY_ARGV))

    def test_no_double_quote_ever_reaches_wsl_exe(self):
        # Windows PowerShell 5.1 mangles embedded double quotes when it passes arguments to a native program.
        ex, runner = self.make()
        ex.run(NASTY_ARGV)
        _, wsl_args, script = decode_ssh_argv(runner.calls[0][0])
        self.assertNotIn('"', wsl_args[8])
        self.assertNotIn('"', script)

    def test_the_command_text_is_not_visible_in_the_ssh_argv(self):
        ex, runner = self.make()
        secret_arg = "very-private-argument-value"
        ex.run(["echo", secret_arg])
        self.assertNotIn(secret_arg, " ".join(runner.calls[0][0]))

    def test_stdin_and_the_exit_code_survive(self):
        ex, runner = self.make()
        ex.run(["sh", "-c", "cat; exit 7"], stdin=b"payload")
        self.assertEqual(runner.calls[0][1]["input"], b"payload")
        _, wsl_args, _ = decode_ssh_argv(runner.calls[0][0])
        done = subprocess.run(["sh", "-c", wsl_args[8]], input=b"payload", capture_output=True)
        self.assertEqual(done.stdout, b"payload")
        self.assertEqual(done.returncode, 7)

    def test_the_script_lives_in_a_private_random_directory_never_a_predictable_path(self):
        ex, runner = self.make()
        ex.run(["true"])
        _, wsl_args, script = decode_ssh_argv(runner.calls[0][0])
        inner = wsl_args[8]
        self.assertIn("mktemp -d", inner)  # random name, mode 0700
        self.assertNotIn("/tmp/", inner)
        self.assertNotIn("$$", inner)
        self.assertNotIn("/tmp/", script)

    def test_the_directory_is_removed_after_the_command_and_nothing_runs_without_one(self):
        ex, runner = self.make()
        ex.run(["sh", "-c", "echo hi; exit 4"])
        inner = decode_ssh_argv(runner.calls[0][0])[1][8]
        with tempfile.TemporaryDirectory() as base:
            env = dict(os.environ, TMPDIR=base)
            done = subprocess.run(["sh", "-c", inner], env=env, capture_output=True, text=True)
            self.assertEqual((done.stdout.strip(), done.returncode), ("hi", 4))
            self.assertEqual(list(Path(base).iterdir()), [])  # cleaned up
            # mktemp that fails (a TMPDIR that does not exist): the user's command must not run at all.
            env = dict(os.environ, TMPDIR=str(Path(base) / "missing"))
            done = subprocess.run(["sh", "-c", inner], env=env, capture_output=True, text=True)
            self.assertEqual(done.returncode, 70)
            self.assertEqual(done.stdout, "")

    def test_a_bad_distro_is_refused_before_anything_runs(self):
        for bad in ("p2pc node", "x'; calc; '", "-d", "", "a\nb"):
            with self.assertRaises(executors.ExecError, msg=bad):
                executors.WslOverSshExecutor("win-box", bad, runner=FakeRunner())

    def test_a_bad_host_is_refused(self):
        for bad in ("-oProxyCommand=x", "a b", ""):
            with self.assertRaises(executors.ExecError, msg=bad):
                executors.WslOverSshExecutor(bad, "p2pc-node", runner=FakeRunner())

    def test_an_oversized_command_is_refused_with_a_hint(self):
        ex, _ = self.make()
        with self.assertRaises(executors.ExecError) as cm:
            ex.run(["echo", "x" * 20000])
        self.assertIn("put()", str(cm.exception))


class SingleCommandInstall(unittest.TestCase):
    """T15b review P3: the token is the stdin of the ssh call, which PowerShell hands to the FIRST pipeline of the script
    only. `Unblock-File x; & install.ps1 -Join` would give the token to Unblock-File and nothing to -Join."""

    def test_the_commands_that_would_swallow_the_token_are_refused_everywhere(self):
        for bad in ("Unblock-File x.ps1; & 'x.ps1' -Join", "& 'x.ps1' -Join && echo", "& 'x.ps1' -Join || exit 1",
                    "Unblock-File x.ps1\n& 'x.ps1' -Join", "Unblock-File x.ps1\r\n& 'x.ps1' -Join"):
            with self.assertRaises(executors.ExecError, msg=bad) as cm:
                executors.windows_host_command(bad, pipe_stdin=True)
            self.assertIn("single command", str(cm.exception))
            toml = f'[node_wsl2_gpu]\nexecutor = "wsl_over_ssh"\nhost = "win"\ndistro = "p2pc-node"\ninstall_command = {json.dumps(bad)}\n'
            self.assertTrue(any("install_command" in x and "single command" in x for x in problems(toml)), bad)

    def test_a_chained_server_install_command_is_accepted(self):
        # The server's install_command runs through `sh -c` inside the distro, not as a PowerShell pipeline
        # (T15b review P3 2): `;`, `&&` and newlines are fine there.
        for chained in ("cd /opt/p2pc && ./install-server.sh", "./a.sh; ./b.sh", "./a.sh\n./b.sh"):
            toml = ('[server]\nexecutor = "wsl_over_ssh"\nhost = "win"\ndistro = "p2pc-node"\n'
                    f"install_command = {json.dumps(chained)}\n")
            self.assertEqual(parse(toml).roles["server"].get("install_command"), chained)

    def test_a_single_command_is_accepted_and_the_image_command_may_have_several(self):
        one = "& 'C:\\\\p2pc-dist\\\\install.ps1' -Join -Force"
        self.assertIn("-EncodedCommand", executors.windows_host_command(one, pipe_stdin=True))
        toml = ('[node_wsl2_gpu]\nexecutor = "wsl_over_ssh"\nhost = "win"\ndistro = "p2pc-node"\n'
                f'install_command = {json.dumps(one)}\nimage_install_command = "Unblock-File x.ps1; & x.ps1 -Tar y"\n')
        parse(toml)  # valid: no MachinesError
        # without a token on stdin, a script of several statements is fine
        executors.windows_host_command("Unblock-File x.ps1; & x.ps1 -Status")

    def test_a_linux_install_command_may_chain_since_sh_c_gives_the_whole_script_the_stdin(self):
        toml = '[node_linux]\nexecutor = "ssh"\nhost = "n"\ninstall_command = "sudo true; sudo sh install-node.sh --from d"\n'
        parse(toml)


class WindowsHostCommands(unittest.TestCase):
    """deploy/wsl/install.ps1 runs on the Windows host, not in the distro: `run_on_host` sends a PowerShell script over ssh
    and pipes the stdin of the call into the command (the join token goes in the pipeline, as the installer says)."""

    def make(self):
        runner = FakeRunner()
        return executors.WslOverSshExecutor("win-box", "p2pc-node", runner=runner), runner

    @staticmethod
    def script_of(local_argv):
        remote = local_argv[-1]
        prefix = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
        assert remote.startswith(prefix), remote
        return base64.b64decode(remote[len(prefix):]).decode("utf-16-le")

    def test_the_command_runs_in_powershell_on_the_host_and_its_exit_code_is_the_scripts(self):
        ex, runner = self.make()
        ex.run_on_host("& 'C:\\p2pc\\install.ps1' -Status")
        argv, _ = runner.calls[0]
        self.assertEqual(argv[-2], "win-box")
        script = self.script_of(argv)
        self.assertIn("& 'C:\\p2pc\\install.ps1' -Status", script)
        self.assertNotIn("wsl.exe", script)  # on the host, not in the distro
        self.assertTrue(script.rstrip().endswith("exit $LASTEXITCODE"))
        self.assertNotIn("$input", script)  # no stdin: nothing is piped

    def test_stdin_is_piped_into_the_command_never_put_in_the_script(self):
        ex, runner = self.make()
        ex.run_on_host("& 'C:\\p2pc\\install.ps1' -Join", stdin=b"p2pc_join_" + b"X" * 20 + b"\n")
        argv, kwargs = runner.calls[0]
        script = self.script_of(argv)
        self.assertIn("$input | & 'C:\\p2pc\\install.ps1' -Join", script)
        self.assertEqual(kwargs["input"], b"p2pc_join_" + b"X" * 20 + b"\n")
        self.assertNotIn("p2pc_join_", script)
        self.assertNotIn("p2pc_join_", " ".join(argv))

    def test_the_execution_policy_is_bypassed_for_this_process_or_install_ps1_would_not_start(self):
        # T15b review P3: the default policy of a Windows client is Restricted, which refuses every .ps1.
        ex, runner = self.make()
        ex.run_on_host("& 'C:\\p2pc\\install.ps1' -Status")
        self.assertIn("-ExecutionPolicy Bypass", runner.calls[0][0][-1])
        self.assertLess(runner.calls[0][0][-1].index("-ExecutionPolicy"), runner.calls[0][0][-1].index("-EncodedCommand"))

    def test_an_oversized_script_is_refused(self):
        ex, _ = self.make()
        with self.assertRaises(executors.ExecError):
            ex.run_on_host("& x " + "a" * 20000)

    def test_a_machine_that_is_not_a_windows_host_says_so(self):
        with self.assertRaises(executors.ExecError):
            executors.SshExecutor("node-linux", runner=FakeRunner()).run_on_host("x")


class ScriptedRunner:
    """Answers each call with the next (returncode, stderr) of the script; the last one repeats."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = 0

    def __call__(self, argv, **kwargs):
        rc, err = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        return subprocess.CompletedProcess(argv, rc, b"out" if rc == 0 else b"", err.encode())


class SshRetriesConnectionSetup(unittest.TestCase):
    TIMEOUT = "ssh: connect to host 192.0.2.7 port 22: Connection timed out\n"

    def make(self, *answers, wsl=False):
        runner = ScriptedRunner(*answers)
        sleeps: list[float] = []
        if wsl:
            ex = executors.WslOverSshExecutor("win-box", "p2pc-node", runner=runner, sleep=sleeps.append)
        else:
            ex = executors.SshExecutor("node-linux", runner=runner, sleep=sleeps.append)
        return ex, runner, sleeps

    def test_a_connect_timeout_then_success_is_one_retry_and_the_success(self):
        for wsl in (False, True):
            ex, runner, sleeps = self.make((255, self.TIMEOUT), (0, ""), wsl=wsl)
            res = ex.run(["true"])
            self.assertEqual((res.returncode, res.stdout), (0, "out"))
            self.assertEqual((runner.calls, sleeps, res.retries), (2, [5.0], 1))
            self.assertIn("Connection timed out", res.retry_first_error)

    def test_three_connect_timeouts_are_the_failure_after_waiting_5_then_15_seconds(self):
        ex, runner, sleeps = self.make((255, self.TIMEOUT))
        res = ex.run(["true"])
        self.assertEqual(res.returncode, 255)
        self.assertEqual((runner.calls, sleeps, res.retries), (3, [5.0, 15.0], 2))

    def test_the_other_setup_failures_are_retried(self):
        for err in ("ssh: connect to host h port 22: Connection refused", "ssh: connect to host h port 22: No route to host",
                    "ssh: connect to host h port 22: Network is unreachable",
                    "ssh: Could not resolve hostname h: Name or service not known",
                    "kex_exchange_identification: read: Connection reset by peer"):
            ex, runner, _ = self.make((255, err + "\n"), (0, ""))
            self.assertEqual(ex.run(["true"]).returncode, 0, err)
            self.assertEqual(runner.calls, 2, err)

    def test_a_setup_message_in_the_middle_of_the_command_output_is_never_retried(self):
        # T15g P3: OpenSSH's own messages start a line; the remote command's output can say the same words anywhere.
        for err in ("remote tool: Could not resolve hostname x\n", "x ssh: connect to host h port 22: Connection timed out\n",
                    "log: kex_exchange_identification\n"):
            ex, runner, sleeps = self.make((255, err), (0, ""))
            res = ex.run(["true"])
            self.assertEqual((res.returncode, runner.calls, sleeps), (255, 1, []), err)

    def test_the_duration_of_a_retried_run_covers_every_attempt_and_the_waits(self):
        import time

        ex, _, _ = self.make((255, self.TIMEOUT), (255, self.TIMEOUT), (0, ""))
        ex._sleep = lambda _delay: time.sleep(0.05)  # a short real wait stands in for the 5 s and 15 s
        res = ex.run(["true"])
        self.assertEqual(res.retries, 2)
        self.assertGreaterEqual(res.duration_s, 0.1)  # the two waits are in it, not only the last attempt

    def test_a_drop_after_the_session_started_is_never_retried(self):
        for rc, err in ((255, "Connection closed by remote host\n"), (255, ""), (255, "Permission denied (publickey).\n"),
                        (1, self.TIMEOUT)):
            ex, runner, sleeps = self.make((rc, err), (0, ""))
            res = ex.run(["true"])
            self.assertEqual((res.returncode, runner.calls, sleeps, res.retries), (rc, 1, [], 0), err)

    def test_the_local_executor_never_retries(self):
        runner = ScriptedRunner((255, self.TIMEOUT))
        executors.LocalExecutor(runner).run(["true"])
        self.assertEqual(runner.calls, 1)

    def test_the_retries_reach_the_step_and_the_report(self):
        ex, _, _ = self.make((255, self.TIMEOUT), (0, ""))
        res = ex.run(["true"])
        step = context.Context._step("node", "label", "true", res)
        d = step.to_dict()
        self.assertEqual(d["ssh_retries"], 1)
        self.assertIn("Connection timed out", d["ssh_first_error"])
        self.assertIn("ssh retried 1x", report._exit_text(d))
        plain = context.Context._step("node", "label", "true", executors.ExecResult(0)).to_dict()
        self.assertNotIn("ssh_retries", plain)


class SshAndLocal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        # A fake ssh: it ignores its options and the host, and runs the remote command string with a shell, as a
        # real sshd would for a POSIX login shell.
        self.fake_ssh = self.dir / "ssh"
        self.fake_ssh.write_text('#!/bin/sh\nfor last; do :; done\nexec sh -c "$last"\n')
        self.fake_ssh.chmod(0o755)

    def test_ssh_argv_shape_and_host_before_command(self):
        runner = FakeRunner()
        ex = executors.SshExecutor("node-linux", options=["-J", "jump"], runner=runner)
        ex.run(["echo", "a b"])
        argv, _ = runner.calls[0]
        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertEqual(argv[-2:], ["node-linux", "echo 'a b'"])
        self.assertEqual(argv[argv.index("-J") + 1], "jump")

    def test_ssh_round_trips_a_nasty_command_through_the_remote_shell(self):
        ex = executors.SshExecutor("node-linux", ssh_bin=str(self.fake_ssh))
        res = ex.run(NASTY_ARGV)
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout, direct_output(NASTY_ARGV))

    def test_local_runs_stdin_exit_code_and_stderr(self):
        res = executors.LocalExecutor().run(["sh", "-c", "cat; echo err >&2; exit 3"], stdin=b"in")
        self.assertEqual((res.returncode, res.stdout, res.stderr.strip()), (3, "in", "err"))
        self.assertFalse(res.timed_out)

    def test_a_timeout_is_reported_not_raised(self):
        res = executors.LocalExecutor().run(["sleep", "5"], timeout=0.2)
        self.assertTrue(res.timed_out)
        self.assertIsNone(res.returncode)

    def test_a_missing_program_is_an_error_result(self):
        res = executors.LocalExecutor().run(["/nonexistent/program-xyz"])
        self.assertIsNone(res.returncode)
        self.assertIn("cannot start", res.error)

    def test_put_copies_with_the_mode_and_sha256_agrees(self):
        src = self.dir / "bin-src"
        src.write_bytes(bytes(range(256)) * 10)
        dest = self.dir / "deep" / "dir" / "p2pc"
        for ex in (executors.LocalExecutor(), executors.SshExecutor("h", ssh_bin=str(self.fake_ssh))):
            if dest.exists():
                dest.unlink()
            res = ex.put(src, str(dest), mode="755")
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(dest.read_bytes(), src.read_bytes())
            self.assertTrue(os.access(dest, os.X_OK))
            self.assertEqual(ex.sha256(str(dest)), executors.file_sha256(src))

    def test_put_survives_odd_remote_paths(self):
        src = self.dir / "s"
        src.write_bytes(b"x")
        weird = self.dir / "a b" / "it's"
        res = executors.LocalExecutor().put(src, str(weird), mode="644")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(weird.exists())

    def test_sha256_of_a_missing_file_raises(self):
        with self.assertRaises(executors.ExecError):
            executors.LocalExecutor().sha256(str(self.dir / "nope"))

    def test_make_executor_builds_the_right_class(self):
        ml = machines.parse_machines(
            textwrap.dedent(
                """
                [server]
                executor = "local"
                [node_linux_gpu]
                executor = "ssh"
                host = "h1"
                ssh_options = ["-J", "j"]
                [node_wsl2_gpu]
                executor = "wsl_over_ssh"
                host = "h2"
                distro = "d"
                """
            ),
            base_dir=self.dir,
        )
        kinds = {n: type(executors.make_executor(r)).__name__ for n, r in ml.roles.items()}
        self.assertEqual(
            kinds,
            {"server": "LocalExecutor", "node_linux_gpu": "SshExecutor", "node_wsl2_gpu": "WslOverSshExecutor"},
        )


# A key or a join token with something after the prefix: what must never be an argument of a command (it would show in
# `ps` and in shell history on the machine). Mentioning the bare prefix is fine.
ARGV_SECRET_RE = re.compile(r"p2pc_(?:sk|join)_[A-Za-z0-9_\-]{8,}")


class FakeExecutor(executors.Executor):
    """A scripted machine. ``handler(argv, stdin)`` returns an ExecResult, or a (returncode, stdout, stderr) tuple."""

    description = "fake"

    def __init__(self, handler=None):
        super().__init__()
        self.handler = handler or (lambda argv, stdin: (0, "", ""))
        self.calls: list[tuple[list[str], bytes | None]] = []
        self.files: dict[str, bytes] = {}
        self.corrupt_puts = False
        self.violations: list[str] = []  # roles that were disabled when something asked for their executor
        self.holds: list = []  # (argv, predicate, deadline) of the commands run with stdin held open
        self.host_calls: list[tuple[str, bytes | None]] = []  # (script, stdin) run on a Windows host
        self.secrets_in_argv: list[list[str]] = []  # commands that reached the machine with a key or token in their argv

    def run(self, argv, *, timeout=120.0, stdin=None, stdin_file=None, hold_stdin_until=None, hold_deadline_s=None):
        if stdin_file is not None:
            stdin = Path(stdin_file).read_bytes()
        if hold_stdin_until is not None:
            self.holds.append((list(argv), hold_stdin_until, hold_deadline_s))
        self.calls.append((list(argv), stdin))
        if any(ARGV_SECRET_RE.search(a) for a in argv):
            self.secrets_in_argv.append(list(argv))
        out = self.handler(list(argv), stdin)
        if isinstance(out, tuple):
            out = executors.ExecResult(out[0], out[1], out[2])
        if argv[:1] == ["curl"] and "-w" in argv and out.returncode == 0 and not re.search(r"\n\d{3}$", out.stdout):
            # The fake plays curl: `-w "\n%{http_code}"` appends the status. A problem+json body carries its own status.
            status = 200
            try:
                body = json.loads(out.stdout)
                if isinstance(body, dict) and isinstance(body.get("status"), int) and body["status"] >= 400 and "code" in body:
                    status = body["status"]
            except ValueError:
                pass
            out = executors.ExecResult(0, f"{out.stdout}\n{status}", out.stderr)
        return out

    def run_on_host(self, script, *, timeout=120.0, stdin=None):
        """The Windows host of a WSL role: the script reaches the handler as ``["<powershell>", script]``."""
        self.host_calls.append((script, stdin))
        if script and ARGV_SECRET_RE.search(script):
            self.secrets_in_argv.append([script])
        out = self.handler(["<powershell>", script], stdin)
        return executors.ExecResult(out[0], out[1], out[2]) if isinstance(out, tuple) else out

    def put(self, local, remote, mode="755", timeout=600.0):
        data = Path(local).read_bytes()
        self.files[remote] = data + (b"x" if self.corrupt_puts else b"")
        return executors.ExecResult(0)

    def sha256(self, remote):
        return self.sha256_result(remote)[0]

    sha256_retries = 0

    def sha256_result(self, remote):
        import hashlib

        return hashlib.sha256(self.files[remote]).hexdigest(), executors.ExecResult(0, retries=self.sha256_retries)


ROLES_TOML = """
[server]
executor = "local"
url = "http://127.0.0.1:7477"
admin_key_env = "TEST_ADMIN_KEY"
workdir = "/work/server"

[node_linux_gpu]
executor = "ssh"
host = "node-linux"

[node_wsl2_gpu]
executor = "wsl_over_ssh"
host = "win-box"
distro = "p2pc-node"
enabled = false
"""


class DisabledRoleUsed(BaseException):
    """A command was sent to a role that is not enabled. A BaseException so that no check can swallow it as a
    failure: it propagates and fails the test loudly."""


def refusing_factory(fake):
    """Every executor of the scripted machines refuses to exist for a disabled role: a script that touches a machine it
    was told not to use (or has not checked is enabled) is caught, whatever it was doing."""

    def factory(role):
        if not role.enabled:
            fake.violations.append(role.name)
            raise DisabledRoleUsed(f"a command was sent to the disabled role '{role.name}'")
        return fake

    return factory


def make_ctx(handler=None, toml=ROLES_TOML, environ=None, base=None, **kw):
    ml = machines.parse_machines(toml, base_dir=base or Path("/base"))
    fake = FakeExecutor(handler)
    clock = FakeClock()
    ctx = context.Context(
        ml,
        repo_root=HERE.parents[1],
        environ=environ or {},
        clock=clock.now,
        sleep=clock.sleep,
        executor_factory=refusing_factory(fake),
        **kw,
    )
    ctx.clock_fake = clock
    return ctx, fake


class FakeClock:
    def __init__(self):
        self.t = 1000.0
        self.slept: list[float] = []

    def now(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


def preflight_ok(argv, stdin):
    """Answers the harness's own probes (the quoting round trip) the way a healthy machine does."""
    if argv[:2] == ["sh", "-c"] and "printf" in argv[2]:
        return (0, argv[-1] + "\n--stdin--\n" + (stdin or b"").decode(), "")
    if argv[:2] == ["mktemp", "-d"]:
        return (0, "/tmp/p2pc-acc.TESTONLY0\n", "")
    return (0, "", "")


def full_inventory(platform, gpus=1, cpu=4.0):
    """An `Inventory` as `GET /v1/nodes` returns it (docs/api/openapi.json): every field the schema requires."""
    return {"hostname": "h", "platform": platform, "cpu": {"model": "x", "logical": 8, "physical": 4}, "memory_mb": 16384,
            "os": "Ubuntu 24.04", "arch": "x86_64", "gpus": [{"uuid": f"GPU-{i}", "name": "RTX", "vram_mb": 8192} for i in range(gpus)],
            "gpu_status": {"kind": "ok"}, "dxg": platform == "wsl2",
            "sandbox": [{"driver": "podman", "class": "container", "runtimes": ["crun"], "ready": True}],
            "offered": {"cpu": cpu, "memory_mb": 8192, "gpu": gpus}, "agent_version": "0.1.0"}


class ContextRecording(unittest.TestCase):
    def test_exec_records_a_redacted_step_into_the_active_check(self):
        ctx, fake = make_ctx(lambda argv, stdin: (3, f"out {FAKE_KEY}", "err"))
        res = ctx.begin("AC-X", "t")
        with res.check("c"):
            step = ctx.exec("server", ["echo", "x"], label="say")  # the machine's OUTPUT carries a key; argv never does
        self.assertEqual(step.exit_code, 3)
        self.assertFalse(step.ok)
        recorded = res.checks[0].steps[0]
        self.assertNotIn("p2pc_sk_", json.dumps(recorded.to_dict()))
        self.assertEqual(recorded.label, "say")

    def test_a_secret_env_travels_on_stdin_never_in_the_argv(self):
        ctx, fake = make_ctx()
        res = ctx.begin("AC-X", "t")
        with res.check("c"):
            ctx.exec("server", ["p2pc", "whoami"], secret_env={"P2PC_API_KEY": FAKE_KEY}, env={"P2PC_SERVER": "http://x"})
        argv, stdin = fake.calls[0]
        self.assertNotIn(FAKE_KEY, " ".join(argv))
        self.assertEqual(stdin, FAKE_KEY.encode() + b"\n")
        self.assertIn("read -r P2PC_API_KEY", argv[2])
        # The logical command is what the report shows: the key's name, never its value.
        shown = res.checks[0].steps[0].command
        self.assertIn("P2PC_API_KEY=<secret>", shown)
        self.assertNotIn(FAKE_KEY, shown)

    def test_the_secret_wrapper_really_exports_the_variable(self):
        ctx, fake = make_ctx()
        argv = ctx.build_argv(["sh", "-c", 'printf %s "$P2PC_API_KEY"'], env=None, secret_env={"P2PC_API_KEY": "s3cr3t-value"})
        out = subprocess.run(argv, input=b"s3cr3t-value\n", capture_output=True)
        self.assertEqual(out.stdout, b"s3cr3t-value")

    SECRET_KEY = "p2pc_sk_" + "abcdefghijkl" + "_" + "s" * 40  # gitleaks:allow
    SECRET_TOKEN = "p2pc_join_" + "MFRGGZDFMZTWQ2LK" * 2  # gitleaks:allow

    def test_a_key_or_a_join_token_in_an_argument_is_refused_before_anything_runs(self):
        for secret in (self.SECRET_KEY, self.SECRET_TOKEN):
            ctx, fake = make_ctx()
            ctx.begin("AC-X", "t")
            for argv, env in ((["echo", secret], None), (["sh", "-c", f"curl -H 'Authorization: Bearer {secret}' x"], None),
                              (["echo", "hi"], {"WHATEVER": secret})):
                with self.assertRaises(core.CheckFailed) as cm:
                    ctx.exec("server", argv, env=env)
                self.assertIn("argv", str(cm.exception))
                self.assertNotIn(secret, str(cm.exception))  # the refusal does not print the secret either
            self.assertEqual(fake.calls, [], "the command must not reach the machine")

    def test_a_secret_the_run_learned_is_refused_in_an_argument_whatever_it_looks_like(self):
        ctx, fake = make_ctx()
        ctx.begin("AC-X", "t")
        ctx.redactor.add_secret("hunter2-hunter2")
        with self.assertRaises(core.CheckFailed):
            ctx.exec("server", ["echo", "hunter2-hunter2"])
        self.assertEqual(fake.calls, [])

    def test_a_secret_on_stdin_or_the_bare_prefix_in_an_argument_is_fine(self):
        ctx, fake = make_ctx()
        ctx.begin("AC-X", "t")
        ctx.exec("server", ["cat"], stdin=self.SECRET_KEY.encode())
        ctx.exec("server", ["echo"], secret_env={"P2PC_API_KEY": self.SECRET_KEY})
        ctx.exec("server", ["grep", "-c", "p2pc_sk_", "/dev/null"])
        self.assertEqual(len(fake.calls), 3)
        for argv, _ in fake.calls:
            self.assertNotIn(self.SECRET_KEY, " ".join(argv))
        self.assertEqual(fake.secrets_in_argv, [])

    def test_env_names_are_validated(self):
        ctx, _ = make_ctx()
        with self.assertRaises(executors.ExecError):
            ctx.build_argv(["x"], env={"BAD NAME": "1"}, secret_env=None)
        with self.assertRaises(executors.ExecError):
            ctx.build_argv(["x"], env=None, secret_env={"a;b": "1"})

    def test_an_executor_error_becomes_a_step_with_an_error(self):
        def boom(argv, stdin):
            raise executors.ExecError("command too long")

        ctx, _ = make_ctx(boom)
        step = ctx.exec("server", ["x"])
        self.assertIsNone(step.exit_code)
        self.assertIn("too long", step.error)


class Roles(unittest.TestCase):
    def test_missing_and_disabled_roles_are_skipped(self):
        ctx, _ = make_ctx(preflight_ok)
        with self.assertRaises(core.Skipped) as cm:
            ctx.require("client_remote")
        self.assertIn("not in the machines file", cm.exception.reason)
        with self.assertRaises(core.Skipped) as cm:
            ctx.require("node_wsl2_gpu")
        self.assertIn("disabled", cm.exception.reason)

    def test_an_enabled_reachable_role_passes_and_is_probed_once(self):
        ctx, fake = make_ctx(preflight_ok)
        ctx.require("node_linux_gpu")
        n = len(fake.calls)
        ctx.require("node_linux_gpu")
        self.assertEqual(len(fake.calls), n)

    def test_an_unreachable_role_is_a_failure_not_a_skip(self):
        ctx, _ = make_ctx(lambda argv, stdin: executors.ExecResult(255, stderr="ssh: Could not resolve hostname"))
        with self.assertRaises(core.CheckFailed) as cm:
            ctx.require("node_linux_gpu")
        self.assertIn("cannot reach", cm.exception.reason)

    def test_the_probe_sends_stdin_and_compares_the_echo(self):
        ctx, fake = make_ctx(preflight_ok)
        ctx.require("node_linux_gpu")
        probe = next((argv, stdin) for argv, stdin in fake.calls if argv[:2] == ["sh", "-c"] and "printf" in argv[2])
        self.assertIn("second line", probe[1].decode())  # multi-line, with shell metacharacters
        # Stdin that gets lost or changed on the way (a layer that eats it, a CRLF conversion) is a failure.
        for mangle in (lambda s: "", lambda s: s.replace("\n", "\r\n"), lambda s: s[:-1]):
            def handler(argv, stdin, m=mangle):
                if argv[:2] == ["sh", "-c"] and "printf" in argv[2]:
                    return (0, argv[-1] + "\n--stdin--\n" + m((stdin or b"").decode()), "")
                return (0, "", "")

            ctx, _ = make_ctx(handler)
            with self.assertRaises(core.CheckFailed) as cm:
                ctx.require("node_linux_gpu")
            self.assertIn("stdin", cm.exception.reason)

    def test_a_quoting_round_trip_mismatch_is_a_failure(self):
        ctx, _ = make_ctx(lambda argv, stdin: (0, "mangled", ""))
        with self.assertRaises(core.CheckFailed) as cm:
            ctx.require("node_linux_gpu")
        self.assertIn("round trip", cm.exception.reason)


class Deploy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        (self.dir / "p2pc").write_bytes(b"\x7fELF fake binary")

    def toml(self, extra=""):
        return ROLES_TOML + f'\n[binaries]\np2pc = "p2pc"\n{extra}\n'

    def test_copy_then_verify_the_sha256(self):
        ctx, fake = make_ctx(preflight_ok, toml=self.toml(), base=self.dir)
        evidence = ctx.deploy("node_linux_gpu", "p2pc")
        self.assertEqual(evidence["p2pc"], executors.file_sha256(self.dir / "p2pc"))
        self.assertIn("/tmp/p2pc-acc.TESTONLY0/bin/p2pc", fake.files)

    def test_a_retry_inside_the_hash_shows_in_the_sha256_step(self):
        ctx, fake = make_ctx(preflight_ok, toml=self.toml(), base=self.dir)
        fake.sha256_retries = 2
        res = ctx.begin("T", "t")
        with res.check("deploy") as c:
            ctx.deploy("node_linux_gpu", "p2pc")
        step = next(s for s in res.checks[0].steps if s.label == "sha256 p2pc")
        self.assertEqual(step.retries, 2)

    def test_a_copy_that_differs_is_a_failure(self):
        ctx, fake = make_ctx(preflight_ok, toml=self.toml(), base=self.dir)
        fake.corrupt_puts = True
        with self.assertRaises(core.CheckFailed) as cm:
            ctx.deploy("node_linux_gpu", "p2pc")
        self.assertIn("sha256 mismatch", cm.exception.reason)

    def test_a_pinned_hash_that_does_not_match_the_build_is_a_failure(self):
        ctx, _ = make_ctx(preflight_ok, toml=self.toml(f'p2pc_sha256 = "{"0" * 64}"'), base=self.dir)
        with self.assertRaises(core.CheckFailed) as cm:
            ctx.deploy("node_linux_gpu", "p2pc")
        self.assertIn("pinned", cm.exception.reason)

    def test_a_missing_binary_is_a_skip_with_the_build_hint(self):
        ctx, _ = make_ctx(preflight_ok, toml=self.toml(), base=self.dir)
        with self.assertRaises(core.Skipped) as cm:
            ctx.deploy("node_linux_gpu", "p2pc_agent")
        self.assertIn("cargo build --release", cm.exception.reason)



# `p2pc --help` of today's binary (logs, results, usage and proxy are stubs and say so).
TODAY_P2PC_HELP = """The p2pc command-line client.

Usage: p2pc [OPTIONS] <COMMAND>

Commands:
  login       Check an API key against the server and store it in the profile
  whoami      Show who the API key is: account, project, key ID and scopes
  run         Submit a job and follow it until it ends
  jobs        List jobs
  status      Show a job
  machines    List machines, or show, drain, resume and remove one
  join-token  Create, list and revoke join tokens for new machines
  keys        Create, list and revoke API keys
  logs        Show a job's logs (not available in this version yet)
  results     Download a job's outputs (not available in this version yet)
  usage       Show reserved and used compute (not available in this version yet)
  proxy       Tunnel the REST API over iroh (not available in this version yet)
  mcp         Serve the MCP protocol over stdio, so that an AI agent can run jobs with its own capped key
  help        Print this message or the help of the given subcommand(s)

Options:
      --json  Print the API's JSON instead of tables and text. Lists are JSON arrays
  -h, --help  Print help
"""

class P2pcCalls(unittest.TestCase):
    def test_the_environment_and_the_json_flag(self):
        ctx, fake = make_ctx(lambda argv, stdin: (0, "{}", ""), environ={"TEST_ADMIN_KEY": FAKE_KEY})
        ctx.begin("AC-X", "t")
        ctx.p2pc("server", ["whoami"])
        argv, stdin = fake.calls[0]
        text = " ".join(argv)
        self.assertIn("P2PC_CONFIG_DIR=/work/server/p2pc-config", text)
        self.assertIn("P2PC_SERVER=http://127.0.0.1:7477", text)
        self.assertIn("/work/server/bin/p2pc --json whoami", text)
        self.assertEqual(stdin, FAKE_KEY.encode() + b"\n")
        self.assertNotIn(FAKE_KEY, text)

    def test_the_json_flag_goes_before_the_subcommand_so_a_job_command_keeps_its_arguments(self):
        ctx, fake = make_ctx(lambda argv, stdin: (0, "{}", ""), environ={"TEST_ADMIN_KEY": FAKE_KEY})
        ctx.begin("AC-X", "t")
        ctx.p2pc("server", ["run", "--image", "i", "--", "echo", "hi"])
        argv = fake.calls[0][0]
        self.assertEqual(argv[argv.index("--json") + 1], "run")
        self.assertEqual(argv[-2:], ["echo", "hi"])

    def openapi_answer(self, *routes):
        paths = {}
        for method, path in routes:
            paths.setdefault(path, {})[method.lower()] = {}
        return json.dumps({"paths": paths})

    def world(self, p2pc, openapi=(7, "", "curl: (7) no")):
        """The CLI answers ``p2pc(tail)``; ``p2pc --help`` is today's real help; the server's /v1/openapi.json answers
        ``openapi`` (a (code, text) pair, by default unreadable)."""
        calls = []

        def handler(argv, stdin):
            if argv[:1] == ["curl"]:
                calls.append("curl")
                return (openapi[0], openapi[1], "")
            if any(a.endswith("/p2pc") for a in argv):
                tail = [a for a in argv[next(i for i, a in enumerate(argv) if a.endswith("/p2pc")) + 1:] if a != "--json"]
                calls.append(tail)
                if tail == ["--help"]:
                    return (0, TODAY_P2PC_HELP, "")
                return p2pc(tail)
            return preflight_ok(argv, stdin)

        ctx, fake = make_ctx(handler, environ={"TEST_ADMIN_KEY": FAKE_KEY})
        ctx.begin("AC-X", "t")
        return ctx, calls

    API404 = (125, "", json.dumps({"error": {"kind": "api", "status": 404, "code": "not_found"}}))
    API405 = (125, "", json.dumps({"error": {"kind": "api", "status": 405, "code": "method_not_allowed"}}))

    def test_a_stub_is_read_from_p2pc_help_and_blocked_by_the_owner_in_the_map(self):
        clap = lambda sub: (125, "", f"error: unexpected argument 'x' found\n\nUsage: p2pc {sub}\n")  # noqa: E731
        for sub in ("logs", "results", "usage", "proxy"):
            ctx, calls = self.world(lambda tail, s=sub: clap(s))
            with self.assertRaises(core.Blocked, msg=sub) as cm:
                ctx.p2pc("server", [sub, "job_1"])
            self.assertEqual(cm.exception.unblocked_by, [context.OWNERS[f"cli {sub}"]], sub)
            with self.assertRaises(core.Blocked):
                ctx.p2pc("server", [sub, "job_1"])
            self.assertEqual(calls.count(["--help"]), 1, "p2pc --help is read once per run")

    def test_a_404_blocks_only_when_the_route_is_absent_from_the_servers_openapi(self):
        absent = (0, self.openapi_answer(("GET", "/v1/keys")))
        ctx, _ = self.world(lambda tail: self.API404, absent)
        with self.assertRaises(core.Blocked) as cm:
            ctx.p2pc("server", ["jobs"])
        self.assertEqual(cm.exception.unblocked_by, [context.OWNERS["route GET /v1/jobs"]])
        # The route exists, so the 404 is about something else: a real result to examine, never a block.
        present = (0, self.openapi_answer(("GET", "/v1/jobs"), ("POST", "/v1/jobs")))
        ctx, _ = self.world(lambda tail: self.API404, present)
        step = ctx.p2pc("server", ["jobs"])
        self.assertEqual(step.route_status(), 404)
        with self.assertRaises(core.CheckFailed):
            ctx.p2pc("server", ["jobs"], expect_ok=True)
        # The method matters: the path is there but POST is not.
        get_only = (0, self.openapi_answer(("GET", "/v1/jobs")))
        ctx, _ = self.world(lambda tail: self.API405, get_only)
        with self.assertRaises(core.Blocked) as cm:
            ctx.p2pc("server", ["run", "--image", "i"])
        self.assertEqual(cm.exception.unblocked_by, [context.OWNERS["route POST /v1/jobs"]])

    def test_a_404_for_an_unknown_job_never_reads_as_blocked(self):
        present = (0, self.openapi_answer(("GET", "/v1/jobs/{id}")))  # the server's own document has the route
        ctx, _ = self.world(lambda tail: self.API404, present)
        step = ctx.p2pc("server", ["status", "job_missing"])
        self.assertEqual(step.exit_code, 125)
        with self.assertRaises(core.CheckFailed) as cm:
            ctx.p2pc("server", ["status", "job_missing"], expect_ok=True)
        self.assertIn("not_found", cm.exception.reason)

    def test_an_unreadable_openapi_document_never_declares_a_route_missing(self):
        for openapi in ((1, ""), (0, "not json"), (0, json.dumps({"no": "paths"})), (0, json.dumps({"paths": []}))):
            ctx, _ = self.world(lambda tail: self.API404, openapi)
            step = ctx.p2pc("server", ["jobs"])
            self.assertEqual(step.exit_code, 125, openapi)

    def test_the_openapi_document_is_fetched_once(self):
        ctx, calls = self.world(lambda tail: self.API404, (0, self.openapi_answer(("GET", "/v1/jobs"))))
        for _ in range(3):
            ctx.p2pc("server", ["jobs"])
        self.assertEqual(calls.count("curl"), 1)

    def test_other_api_errors_are_not_blocked(self):
        err = (125, "", json.dumps({"error": {"kind": "api", "status": 402, "code": "cap_exceeded"}}))
        ctx, _ = self.world(lambda tail: err, (0, self.openapi_answer()))
        step = ctx.p2pc("server", ["jobs"])
        self.assertEqual(step.error_json()["status"], 402)

    def test_a_stub_that_says_so_when_called_is_blocked_even_if_help_cannot_be_read(self):
        for text in ("not implemented yet\n", "error: `p2pc logs` is not implemented yet in this version"):
            ctx, fake = make_ctx(lambda argv, stdin, t=text: (125, "", t), environ={"TEST_ADMIN_KEY": FAKE_KEY})
            ctx.begin("AC-X", "t")
            with self.assertRaises(core.Blocked) as cm:
                ctx.p2pc("server", ["logs"])
            self.assertEqual(cm.exception.unblocked_by, [context.OWNERS["cli logs"]])

    def test_the_gap_between_what_is_called_and_who_owns_it_is_an_error_not_a_pass(self):
        with self.assertRaises(core.CheckFailed):
            context.owner("route GET /v1/not-in-the-map")

    def test_a_missing_piece_is_never_reported_for_a_command_that_worked(self):
        step = core.Step("l", "r", "c", exit_code=0, stdout="not implemented yet")
        self.assertFalse(step.missing_piece())

    def test_expect_ok_raises_a_failure_with_the_api_error(self):
        err = json.dumps({"error": {"kind": "api", "status": 402, "code": "cap_exceeded"}})
        ctx, _ = make_ctx(lambda argv, stdin: (125, "", err), environ={"TEST_ADMIN_KEY": FAKE_KEY})
        ctx.begin("AC-X", "t")
        with self.assertRaises(core.CheckFailed) as cm:
            ctx.p2pc("server", ["run"], expect_ok=True)
        self.assertIn("cap_exceeded", cm.exception.reason)
        self.assertIn("125", cm.exception.reason)

    def test_no_admin_key_is_a_skip(self):
        ctx, _ = make_ctx(lambda argv, stdin: (0, "{}", ""))
        ctx.begin("AC-X", "t")
        with self.assertRaises(core.Skipped) as cm:
            ctx.p2pc("server", ["whoami"])
        self.assertIn("TEST_ADMIN_KEY", cm.exception.reason)

    def test_a_key_from_an_earlier_criterion_is_used_and_registered_for_redaction(self):
        ctx, fake = make_ctx(lambda argv, stdin: (0, "{}", ""))
        ctx.set_admin_key("weird-format-admin-key-123")
        ctx.begin("AC-X", "t")
        ctx.p2pc("server", ["whoami"])
        self.assertEqual(fake.calls[0][1], b"weird-format-admin-key-123\n")
        self.assertEqual(core.redact("x weird-format-admin-key-123 y"), "x <redacted> y")


class WaitForJob(unittest.TestCase):
    def test_polls_until_terminal_with_the_injected_clock(self):
        states = iter(["queued", "assigned", "running", "succeeded"])
        ctx, fake = make_ctx(
            lambda argv, stdin: (0, json.dumps({"id": "job_1", "status": next(states)}), ""),
            environ={"TEST_ADMIN_KEY": FAKE_KEY},
        )
        res = ctx.begin("AC-X", "t")
        with res.check("c"):
            job, elapsed = ctx.wait_job("server", "job_1", timeout_s=60, poll_s=2)
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(elapsed, 6)  # three sleeps of 2 s on the fake clock: no real waiting
        # Only the last poll is kept as evidence; the others would drown the report.
        self.assertEqual(len(res.checks[0].steps), 1)

    def test_a_job_that_never_ends_is_a_failure_after_the_timeout(self):
        ctx, _ = make_ctx(
            lambda argv, stdin: (0, json.dumps({"id": "job_1", "status": "queued"}), ""), environ={"TEST_ADMIN_KEY": FAKE_KEY}
        )
        ctx.begin("AC-X", "t")
        with self.assertRaises(core.CheckFailed) as cm:
            ctx.wait_job("server", "job_1", timeout_s=10, poll_s=3)
        self.assertIn("queued", cm.exception.reason)

    def test_until_can_wait_for_running(self):
        states = iter(["queued", "running"])
        ctx, _ = make_ctx(
            lambda argv, stdin: (0, json.dumps({"id": "j", "status": next(states)}), ""), environ={"TEST_ADMIN_KEY": FAKE_KEY}
        )
        ctx.begin("AC-X", "t")
        job, _ = ctx.wait_job("server", "j", timeout_s=30, until={"running"})
        self.assertEqual(job["status"], "running")


class ManualEvidence(unittest.TestCase):
    def test_missing_is_a_skip_and_present_records_the_hash(self):
        with tempfile.TemporaryDirectory() as d:
            doc = Path(d) / "pentest.md"
            doc.write_text("no critical findings\n")
            ctx, _ = make_ctx(toml=ROLES_TOML + '\n[manual]\npentest_report = "pentest.md"\n', base=Path(d))
            path, digest = ctx.manual_evidence("pentest_report")
            self.assertEqual(path, doc)
            self.assertEqual(digest, executors.file_sha256(doc))
            with self.assertRaises(core.Skipped):
                ctx.manual_evidence("claude_code_session")
            doc.write_text("")
            with self.assertRaises(core.Skipped) as cm:
                ctx.manual_evidence("pentest_report")
            self.assertIn("empty", cm.exception.reason)


def sample_results() -> list[core.Result]:
    ok = core.Result("AC-12", "Supply chain")
    with ok.check("cargo deny"):
        ok.record_step(
            core.Step("cargo deny check", "harness", "cargo deny check", 0, 12.3, stdout="advisories ok", stderr="")
        )
    blocked = core.Result("AC-3", "GPU job")
    with blocked.check("nvidia-smi logs"):
        raise core.Blocked("p2pc logs is not available yet", ["T10", "T11b"])
    failed = core.Result("AC-2", "CPU job")
    with failed.check("run") as c:
        failed.record_step(core.Step("p2pc run", "server", "p2pc run --detach", 125, 0.4, stderr="boom"))
        c.timing("submit_to_start_s", 7.25)
        raise core.CheckFailed("exit 125")
    skipped = core.Result("AC-8", "Remote client")
    with skipped.check("client"):
        raise core.Skipped("role 'client_remote' is disabled")
    return [r.finish() for r in (failed, blocked, skipped, ok)]


def build(results=None, **kw):
    results = sample_results() if results is None else results
    return report.build_report(
        results,
        run_id="20261105T120000Z",
        started_at="2026-11-05T12:00:00Z",
        finished_at="2026-11-05T12:01:00Z",
        machines_name="machines.example.toml",
        git_commit="abc1234",
        strict=False,
        **kw,
    )


class ReportRendering(unittest.TestCase):
    def test_json_has_status_reason_timings_commands_and_exit_codes(self):
        rep = build()
        self.assertEqual(rep["schema"], 1)
        by_id = {c["id"]: c for c in rep["criteria"]}
        self.assertEqual(by_id["AC-2"]["status"], "fail")
        self.assertEqual(by_id["AC-3"]["status"], "blocked")
        self.assertEqual(by_id["AC-3"]["unblocked_by"], ["T10", "T11b"])
        self.assertEqual(by_id["AC-8"]["status"], "skip")
        self.assertEqual(by_id["AC-12"]["status"], "pass")
        step = by_id["AC-2"]["checks"][0]["steps"][0]
        self.assertEqual((step["command"], step["exit_code"]), ("p2pc run --detach", 125))
        self.assertEqual(step["stderr_excerpt"], "boom")
        self.assertEqual(by_id["AC-2"]["checks"][0]["timings"], {"submit_to_start_s": 7.25})
        self.assertEqual(rep["summary"]["counts"], {"pass": 1, "fail": 1, "skip": 1, "blocked": 1})

    def test_criteria_are_ordered_by_number(self):
        ids = [c["id"] for c in build()["criteria"]]
        self.assertEqual(ids, ["AC-2", "AC-3", "AC-8", "AC-12"])

    def test_blocked_is_not_counted_as_pass_in_the_summary_and_verdict(self):
        rep = build([r for r in sample_results() if r.id in ("AC-12", "AC-3")])
        self.assertEqual(rep["summary"]["counts"]["pass"], 1)
        self.assertEqual(rep["summary"]["counts"]["blocked"], 1)
        self.assertFalse(rep["summary"]["accepted"])  # 1 of 2 passed: nothing is "accepted" with a blocked criterion

    def test_accepted_only_when_every_selected_criterion_passed(self):
        only_ok = [r for r in sample_results() if r.id == "AC-12"]
        self.assertTrue(build(only_ok)["summary"]["accepted"])

    def test_markdown_shows_the_table_blockers_and_commands(self):
        md = report.render_markdown(build())
        self.assertIn("| AC-2 | CPU job | fail |", md)
        self.assertIn("| AC-3 | GPU job | blocked |", md)
        self.assertIn("T10", md)
        self.assertIn("T11b", md)
        self.assertIn("p2pc run --detach", md)
        self.assertIn("exit 125", md)
        self.assertIn("submit_to_start_s", md)
        self.assertIn("1 pass, 1 fail, 1 skip, 1 blocked", md)
        # Never an unqualified "pass" for something that did not pass.
        row = next(line for line in md.splitlines() if line.startswith("| AC-3"))
        self.assertNotIn("pass", row)

    def test_markdown_fences_survive_output_that_contains_backticks(self):
        res = core.Result("AC-2", "t")
        with res.check("c"):
            res.record_step(core.Step("l", "r", "cmd", 0, stdout="``` inside ```"))
        md = report.render_markdown(build([res.finish()]))
        self.assertIn("````", md)

    def test_secrets_never_reach_the_json_or_the_markdown(self):
        res = core.Result("AC-1", f"title with {FAKE_KEY}")
        with res.check(f"check {FAKE_JOIN}") as c:
            c.evidence["key"] = FAKE_KEY
            res.record_step(
                core.Step(f"login {FAKE_KEY}", "server", f"p2pc login {FAKE_JOIN}", 0, stdout=FAKE_KEY, stderr=FAKE_JOIN)
            )
            raise core.CheckFailed(f"saw {FAKE_KEY}")
        rep = build([res.finish()])
        text = json.dumps(rep) + report.render_markdown(rep)
        self.assertNotIn("p2pc_sk_", text)
        self.assertNotIn("p2pc_join_", text)
        self.assertNotIn("qqqq", text)
        self.assertIn("<redacted>", text)

    def test_write_report_creates_one_directory_per_run_with_both_files_and_no_secrets(self):
        res = core.Result("AC-1", "t")
        with res.check("c") as c:
            c.evidence["k"] = FAKE_KEY
        with tempfile.TemporaryDirectory() as d:
            out = report.write_report(Path(d), build([res.finish()]))
            self.assertEqual(out.parent, Path(d))
            self.assertTrue((out / "report.json").is_file())
            self.assertTrue((out / "report.md").is_file())
            for name in ("report.json", "report.md"):
                self.assertNotIn("p2pc_sk_", (out / name).read_text())
            data = json.loads((out / "report.json").read_text())
            self.assertEqual(data["criteria"][0]["id"], "AC-1")
            # A second run with the same id never overwrites the first.
            again = report.write_report(Path(d), build([res.finish()]))
            self.assertNotEqual(again, out)

    def test_the_writer_refuses_to_write_a_secret_that_got_past_redaction(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError):
                report.write_report(Path(d), {"run_id": "x", "criteria": [], "oops": FAKE_KEY}, redact=False)
            self.assertEqual(list(Path(d).iterdir()), [])


class CriteriaRegistry(unittest.TestCase):
    def test_there_is_one_script_per_criterion_with_its_metadata(self):
        mods = criteria.load_all()
        self.assertEqual([m.ID for m in mods], [f"AC-{n}" for n in range(1, 13)])
        for n, m in enumerate(mods, start=1):
            with self.subTest(m.ID):
                self.assertTrue(callable(m.run))
                self.assertTrue(m.__name__.startswith(f"ac{n:02d}_"))
                self.assertTrue(m.TITLE)
                self.assertTrue(set(m.ROLES) <= set(machines.ROLES))
                # What a criterion needs is keys of the one owner map; no task name, no claim about what is built.
                self.assertTrue(set(m.NEEDS) <= set(context.OWNERS), set(m.NEEDS) - set(context.OWNERS))
                self.assertFalse(hasattr(m, "WAITING_FOR") or hasattr(m, "RUNS_TODAY"), m.ID)

    def test_every_script_starts_with_an_spdx_header(self):
        for path in HERE.glob("*.py"):
            head = "\n".join(path.read_text().splitlines()[:3])
            self.assertIn("SPDX-License-Identifier: Apache-2.0", head, path.name)

    def test_the_table_lists_all_twelve_in_order(self):
        table = criteria.status_table(criteria.load_all())
        rows = [ln for ln in table.splitlines() if ln.startswith("| AC-")]
        self.assertEqual(len(rows), 12)
        self.assertTrue(rows[0].startswith("| AC-1 "))
        self.assertTrue(rows[11].startswith("| AC-12 "))

    def test_ac12_needs_nothing_and_ac10_needs_the_scheduler(self):
        mods = {m.ID: m for m in criteria.load_all()}
        self.assertEqual((mods["AC-12"].NEEDS, mods["AC-12"].ROLES), ((), ()))
        self.assertIn("feature scheduler", mods["AC-10"].NEEDS)

    class FakeLanded:
        """A product at some stage: ``states`` maps keys of the owner map to True, False or None (cannot say)."""

        def __init__(self, states):
            self.states = states

        def landed(self, key):
            return self.states.get(key)

    def test_the_waiting_column_is_read_from_the_product_not_from_a_list(self):
        keys = ("route GET /v1/nodes", "feature scheduler", "feature executor", "cli logs", "route GET /v1/jobs/{id}/logs")
        none = self.FakeLanded({k: False for k in keys})
        waiting, runs = criteria.waiting_for(keys, none, context.OWNERS)
        self.assertEqual((waiting, runs), (["T05", "T06", "T10a*", "T10b", "T11b2"], "no"))
        # T05 and T06 land: the same criteria, no edit, and the column follows.
        some = self.FakeLanded({"route GET /v1/nodes": True, "feature scheduler": True})
        waiting, runs = criteria.waiting_for(keys, some, context.OWNERS)
        self.assertEqual(runs, "partly")
        self.assertEqual(waiting, ["T10a*", "T10b?", "T11b2?"])  # unreadable (None) pieces are marked, never assumed landed
        self.assertNotIn("T05", waiting)
        self.assertNotIn("T06", waiting)
        everything = self.FakeLanded({k: True for k in keys if k != "feature executor"})
        waiting, runs = criteria.waiting_for(keys, everything, context.OWNERS)
        self.assertEqual((waiting, runs), (["T10a*"], "partly"))  # the executor has no marker: the run's gate decides
        allof = criteria.waiting_for((), everything, context.OWNERS)
        self.assertEqual(allof, ([], "yes"))

    def test_a_piece_the_product_cannot_answer_for_is_marked_with_a_question_mark(self):
        waiting, _ = criteria.waiting_for(("cli logs",), self.FakeLanded({}), context.OWNERS)
        self.assertEqual(waiting, ["T11b2?"])

    def test_parse_only(self):
        ids = [m.ID for m in criteria.load_all()]
        self.assertEqual(criteria.parse_only("AC-2,ac5, AC12", ids), ["AC-2", "AC-5", "AC-12"])
        self.assertEqual(criteria.parse_only("AC-5,AC-2,AC-5", ids), ["AC-2", "AC-5"])
        for bad in ("AC-13", "AC-0", "x", "", "AC-2,,AC-3 AC-4"):
            with self.assertRaises(ValueError, msg=bad):
                criteria.parse_only(bad, ids)


def fake_module(id, run, title="t", roles=()):
    import types

    return types.SimpleNamespace(
        ID=id, TITLE=title, ROLES=roles, RUNS_TODAY="yes", WAITING_FOR=(), SPEC="", __name__=f"ac_{id}", run=run
    )


class RunnerMain(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.machines = self.dir / "machines.toml"
        self.machines.write_text('[server]\nexecutor = "local"\nenabled = false\n')

    def invoke(self, args, modules, stdout=None):
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = runner.main(args, loader=lambda: modules)
        return code, out.getvalue(), err.getvalue()

    def reports(self):
        return sorted((self.dir / "reports").iterdir())

    def passing(self, ctx):
        res = ctx.begin("AC-1", "t")
        with res.check("c"):
            pass
        return res

    def test_runs_the_selected_criteria_and_writes_a_report(self):
        calls = []

        def run1(ctx):
            calls.append("1")
            return self.passing(ctx)

        def run2(ctx):
            calls.append("2")
            res = ctx.begin("AC-2", "t")
            with res.check("c"):
                raise core.Blocked("needs T04", ["T04"])
            return res

        mods = [fake_module("AC-1", run1), fake_module("AC-2", run2)]
        code, _, err = self.invoke(["--machines", str(self.machines), "--report-dir", str(self.dir / "reports"), "--only", "AC-2"], mods)
        self.assertEqual(calls, ["2"])
        self.assertEqual(code, 0)  # blocked is not a failure by default...
        run_dir = self.reports()[0]
        data = json.loads((run_dir / "report.json").read_text())
        self.assertEqual([c["id"] for c in data["criteria"]], ["AC-2"])
        self.assertEqual(data["criteria"][0]["status"], "blocked")
        self.assertIn("AC-2", err)

    def test_strict_turns_blocked_and_skip_into_a_failing_exit_code(self):
        def run2(ctx):
            res = ctx.begin("AC-2", "t")
            with res.check("c"):
                raise core.Blocked("needs T04", ["T04"])
            return res

        args = ["--machines", str(self.machines), "--report-dir", str(self.dir / "reports")]
        self.assertEqual(self.invoke(args, [fake_module("AC-2", run2)])[0], 0)
        self.assertEqual(self.invoke(args + ["--strict"], [fake_module("AC-2", run2)])[0], 1)

    def test_a_failing_criterion_exits_1(self):
        def run1(ctx):
            res = ctx.begin("AC-1", "t")
            with res.check("c"):
                raise core.CheckFailed("nope")
            return res

        code, _, _ = self.invoke(["--machines", str(self.machines), "--report-dir", str(self.dir / "r")], [fake_module("AC-1", run1)])
        self.assertEqual(code, 1)

    def test_a_crashing_script_is_a_failure_and_the_others_still_run(self):
        def boom(ctx):
            raise RuntimeError("script bug")

        mods = [fake_module("AC-1", boom), fake_module("AC-2", lambda ctx: self.ok(ctx, "AC-2"))]
        code, _, _ = self.invoke(["--machines", str(self.machines), "--report-dir", str(self.dir / "r")], mods)
        self.assertEqual(code, 1)
        data = json.loads((sorted((self.dir / "r").iterdir())[0] / "report.json").read_text())
        statuses = {c["id"]: c["status"] for c in data["criteria"]}
        self.assertEqual(statuses, {"AC-1": "fail", "AC-2": "pass"})
        self.assertIn("RuntimeError", data["criteria"][0]["reason"])

    def ok(self, ctx, id):
        res = ctx.begin(id, "t")
        with res.check("c"):
            pass
        return res

    def test_a_script_that_returns_the_wrong_thing_fails(self):
        mods = [fake_module("AC-1", lambda ctx: "pass")]
        code, _, _ = self.invoke(["--machines", str(self.machines), "--report-dir", str(self.dir / "r")], mods)
        self.assertEqual(code, 1)

    def test_a_bad_machines_file_is_a_usage_error_that_lists_every_problem(self):
        bad = self.dir / "bad.toml"
        bad.write_text('[server]\nexecutor = "rsh"\n[nodes]\nx = 1\n')
        code, _, err = self.invoke(["--machines", str(bad)], [])
        self.assertEqual(code, 2)
        self.assertIn("executor", err)
        self.assertIn("[nodes]", err)

    def test_a_bad_only_is_a_usage_error(self):
        code, _, err = self.invoke(["--machines", str(self.machines), "--only", "AC-99"], [fake_module("AC-1", lambda c: None)])
        self.assertEqual(code, 2)
        self.assertIn("AC-99", err)

    def test_machines_is_required_unless_listing(self):
        code, _, err = self.invoke([], [fake_module("AC-1", lambda c: None)])
        self.assertEqual(code, 2)
        self.assertIn("--machines", err)

    def test_list_prints_the_status_table_and_runs_nothing(self):
        ran = []
        mods = [fake_module("AC-1", lambda ctx: ran.append(1), title="Install")]
        code, out, _ = self.invoke(["--list"], mods)
        self.assertEqual(code, 0)
        self.assertEqual(ran, [])
        self.assertIn("| AC-1 | Install |", out)

    def test_ctrl_c_still_writes_the_partial_report(self):
        def interrupted(ctx):
            raise KeyboardInterrupt

        mods = [fake_module("AC-1", lambda ctx: self.ok(ctx, "AC-1")), fake_module("AC-2", interrupted)]
        code, _, _ = self.invoke(["--machines", str(self.machines), "--report-dir", str(self.dir / "r")], mods)
        self.assertEqual(code, 130)
        data = json.loads((sorted((self.dir / "r").iterdir())[0] / "report.json").read_text())
        self.assertEqual([c["id"] for c in data["criteria"]], ["AC-1"])
        self.assertTrue(data["run"]["interrupted"])

    def test_an_interrupted_criterion_stays_in_the_report_with_what_it_recorded(self):
        def interrupted(ctx):
            res = ctx.begin("AC-2", "t")
            with res.check("first") as c:
                c.evidence["done"] = True
            with res.check("second"):
                res.record_step(core.Step("p2pc run", "server", "p2pc run", None, error="interrupted"))
                raise KeyboardInterrupt
            return res

        mods = [fake_module("AC-1", lambda ctx: self.ok(ctx, "AC-1")), fake_module("AC-2", interrupted)]
        code, _, _ = self.invoke(["--machines", str(self.machines), "--report-dir", str(self.dir / "r")], mods)
        self.assertEqual(code, 130)
        data = json.loads((sorted((self.dir / "r").iterdir())[0] / "report.json").read_text())
        self.assertEqual([c["id"] for c in data["criteria"]], ["AC-1", "AC-2"])
        ac2 = data["criteria"][1]
        self.assertEqual([(c["name"], c["status"]) for c in ac2["checks"]], [("first", "pass"), ("second", "fail")])
        self.assertIn("interrupted", ac2["checks"][1]["reason"])
        self.assertEqual(ac2["checks"][1]["steps"][0]["command"], "p2pc run")
        self.assertEqual(ac2["status"], "fail")
        self.assertTrue(data["run"]["interrupted"])
        self.assertFalse(data["summary"]["accepted"])

    def test_a_secret_in_a_script_result_never_reaches_the_report_directory(self):
        def leaky(ctx):
            res = ctx.begin("AC-1", "t")
            with res.check("c") as c:
                c.evidence["admin_key"] = FAKE_KEY
                raise core.CheckFailed(f"got {FAKE_KEY}")
            return res

        self.invoke(["--machines", str(self.machines), "--report-dir", str(self.dir / "r")], [fake_module("AC-1", leaky)])
        for path in (sorted((self.dir / "r").iterdir())[0]).iterdir():
            self.assertNotIn("p2pc_sk_", path.read_text())


class FlowAnalysis(unittest.TestCase):
    def test_parse_cargo_test_sums_every_binary_and_sees_zero_matches(self):
        out = (
            "running 2 tests\ntest result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 5 filtered out; finished in 0.01s\n"
            "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s\n"
            "test result: FAILED. 1 passed; 3 failed; 0 ignored\n"
        )
        self.assertEqual(flows.parse_cargo_test(out), (3, 3, 1))
        self.assertEqual(flows.parse_cargo_test("error: could not compile"), (0, 0, 0))

    def test_exposed_listeners_flags_only_what_a_remote_machine_could_reach(self):
        ss = textwrap.dedent(
            """\
            LISTEN 0 4096 127.0.0.1:7477 0.0.0.0:*
            LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
            LISTEN 0 128 [::]:22 [::]:*
            LISTEN 0 4096 *:8080 *:*
            LISTEN 0 4096 [::1]:631 [::]:*
            LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*
            LISTEN 0 100 192.0.2.5:3000 0.0.0.0:*
            garbage
            """
        )
        listeners = flows.parse_listeners(ss)
        self.assertEqual(flows.exposed_listeners(listeners, [22]), ["*:8080", "192.0.2.5:3000"])
        self.assertEqual(flows.exposed_listeners(listeners, [22, 8080, 3000]), [])
        self.assertEqual(flows.exposed_listeners(flows.parse_listeners(""), [22]), [])

    def snap(self, **per_node):
        return [(n, st) for n, statuses in per_node.items() for st in statuses]

    def test_concurrency_within_the_limit_and_the_limit_reached(self):
        snaps = [
            self.snap(a=["running"] * 4, b=["assigned"] * 4, c=[]) + [(None, "queued")] * 5,
            self.snap(a=["running"] * 2, b=["running"] * 3),
        ]
        out = flows.analyze_concurrency(snaps, limit=4, per_job_cpu=1.0, offered_cpu={"a": 4.0, "b": 4.0})
        self.assertEqual(out["peak_per_node"], {"a": 4, "b": 4})
        self.assertEqual(out["over_limit"], {})
        self.assertEqual(out["over_capacity_cpu"], {})
        self.assertEqual(out["reached_limit"], ["a", "b"])

    def test_a_fifth_job_on_a_node_is_double_booking(self):
        snaps = [self.snap(a=["running"] * 4 + ["assigned"])]
        out = flows.analyze_concurrency(snaps, limit=4)
        self.assertEqual(out["over_limit"], {"a": 5})

    def test_more_cpu_than_offered_is_double_booking_even_below_the_job_limit(self):
        out = flows.analyze_concurrency([self.snap(a=["running"] * 3)], limit=4, per_job_cpu=2.0, offered_cpu={"a": 4.0})
        self.assertEqual(out["over_capacity_cpu"], {"a": 6.0})

    def test_finished_and_queued_jobs_hold_no_reservation(self):
        out = flows.analyze_concurrency([self.snap(a=["succeeded"] * 50 + ["queued"] * 9)], limit=4)
        self.assertEqual(out["peak_per_node"], {})
        self.assertEqual(out["reached_limit"], [])

    def jobs(self, n=3, override=None):
        override = override or {}
        return [{"id": f"job_{i}", "status": "succeeded", "attempt": 1} | override.get(i, {}) for i in range(n)]

    def test_final_state_of_a_clean_batch(self):
        self.assertEqual(flows.final_problems(self.jobs(), 3), [])

    def test_a_lost_failed_missing_or_retried_job_is_reported(self):
        jobs = self.jobs(4, {1: {"status": "lost"}, 2: {"status": "failed"}, 3: {"attempt": 2}})
        text = " ".join(flows.final_problems(jobs, 5))
        self.assertIn("4 jobs found, 5 submitted", text)
        self.assertIn("'lost'", text)
        self.assertIn("'failed'", text)
        self.assertIn("second attempt", text)
        self.assertIn("appears twice", " ".join(flows.final_problems([{"id": "x", "status": "succeeded"}] * 2, 2)))

    def rows(self, n=3, cpu_ms=7200, override=None):
        override = override or {}
        return [{"job_id": f"job_{i}", "units": cpu_ms // 3600, "reserved_cpu_ms": cpu_ms} | override.get(i, {}) for i in range(n)]

    def test_the_ledger_reconciles(self):
        ids = [f"job_{i}" for i in range(3)]
        rows = self.rows()
        node_rows = [{"node_id": "a", "units": 4}, {"node_id": "b", "units": 2}]
        key_rows = [{"key_id": "k", "units": 6}]
        self.assertEqual(flows.reconcile_ledger(rows, ids, node_rows, key_rows), [])
        self.assertEqual(flows.reconcile_ledger({"items": rows}, ids), [])

    def test_ledger_problems_are_each_reported(self):
        ids = [f"job_{i}" for i in range(4)]
        rows = self.rows(3, override={1: {"units": 99}}) + [dict(self.rows(1)[0])]  # job_1 mischarged, job_0 twice, job_3 absent
        text = " | ".join(flows.reconcile_ledger(rows, ids, [{"units": 1}], [{"key_id": "k", "units": 1}], key_id="k"))
        self.assertIn("job_3", text)
        self.assertIn("more than one ledger row", text)
        self.assertIn("99 milli-units for 7200 vCPU-ms", text)
        self.assertIn("per-node totals", text)
        self.assertIn("run key's total", text)

    def test_the_ledger_of_the_account_is_not_the_ledger_of_the_run(self):
        ids = ["job_0", "job_1"]
        rows = self.rows(2) + [{"job_id": "job_from_an_earlier_run", "units": 9000, "reserved_cpu_ms": 32_400_000}]
        node_rows = [{"node_id": "a", "units": 4 + 9000}, {"node_id": "b", "units": 0}]  # a node also ran the older job
        key_rows = [{"key_id": "run_key", "units": 4}, {"key_id": "somebody_else", "units": 9000}]
        self.assertEqual(flows.reconcile_ledger(rows, ids, node_rows, key_rows, key_id="run_key"), [])
        # Without filtering by the run's job ids and key the same ledger would not add up: that is the bug.
        self.assertNotEqual(flows.reconcile_ledger(rows, ids, node_rows, [{"key_id": "somebody_else", "units": 9000}], key_id="run_key"), [])

    def test_a_missing_key_row_and_a_wrong_key_total_are_problems(self):
        ids = ["job_0"]
        rows = self.rows(1)
        self.assertIn("no row for the run's key", " ".join(flows.reconcile_ledger(rows, ids, None, [{"key_id": "other", "units": 2}], key_id="k")))
        self.assertIn("run key's total", " ".join(flows.reconcile_ledger(rows, ids, None, [{"key_id": "k", "units": 3}], key_id="k")))
        self.assertEqual(flows.reconcile_ledger(rows, ids, None, [{"key_id": "k", "units": 2}], key_id="k"), [])

    def test_one_vcpu_hour_is_a_thousand_milli_units(self):
        row = {"job_id": "j", "units": 1000, "reserved_cpu_ms": 3_600_000}
        self.assertEqual(flows.reconcile_ledger([row], ["j"]), [])

    def test_a_gpu_row_is_not_checked_against_cpu_time_alone(self):
        row = {"job_id": "j", "units": 10_000, "reserved_cpu_ms": 3_600_000, "reserved_gpu_ms": 3_600_000}
        self.assertEqual(flows.reconcile_ledger([row], ["j"]), [])

    def test_timestamps(self):
        self.assertEqual(flows.seconds_between("2026-11-05T12:00:00Z", "2026-11-05T12:00:03.5Z"), 3.5)
        with self.assertRaises(core.CheckFailed):
            flows.seconds_between("2026-11-05T12:00:00Z", None)

    def test_mcp_session_is_json_rpc_and_the_initialized_notification_has_no_id(self):
        data = flows.mcp_session([(4, "p2pc_run", {"image": "i"})]).decode()
        msgs = [json.loads(line) for line in data.splitlines()]
        self.assertEqual([m.get("method") for m in msgs], ["initialize", "notifications/initialized", "tools/list", "tools/call"])
        self.assertNotIn("id", msgs[1])
        self.assertEqual(msgs[3]["params"], {"name": "p2pc_run", "arguments": {"image": "i"}})
        self.assertTrue(all("\n" not in line for line in data.rstrip("\n").splitlines()))

    def test_mcp_output_parsing(self):
        out = '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"b"},{"name":"a"}]}}\n\n{"id":4,"result":{"content":[{"text":"{\\"id\\":\\"job_01ABC\\"}"}]}}\n'
        msgs = flows.parse_mcp_output(out)
        self.assertEqual(flows.mcp_tool_names(msgs), ["a", "b"])
        self.assertEqual(flows.mcp_job_ids(msgs[1]), ["job_01ABC"])
        with self.assertRaises(core.CheckFailed):
            flows.parse_mcp_output("p2pc mcp: starting\n")


class UsageRange(unittest.TestCase):
    def test_the_upper_bound_is_an_hour_after_the_last_job_ended_in_whole_seconds_utc(self):
        jobs = [{"created_at": "2026-11-05T23:00:00Z", "finished_at": "2026-11-05T23:59:30.250Z"},
                {"created_at": "2026-11-05T23:10:00Z", "finished_at": "2026-11-05T23:40:00Z"}]
        self.assertEqual(flows.usage_upper_bound(jobs), "2026-11-06T00:59:30Z")  # past midnight: the CLI's own default would cut it

    def test_a_job_without_an_end_falls_back_to_its_creation(self):
        self.assertEqual(flows.usage_upper_bound([{"created_at": "2026-11-05T12:00:00Z"}]), "2026-11-05T13:00:00Z")

    def test_a_non_utc_offset_is_converted(self):
        self.assertEqual(flows.usage_upper_bound([{"finished_at": "2026-11-05T12:00:00+02:00"}]), "2026-11-05T11:00:00Z")


class EgressProbe(unittest.TestCase):
    """The probe that runs inside the AC-4 job, tested against a fake proxy on loopback (no real network)."""

    def run_probe(self, answer, args, direct=""):
        import socketserver
        import threading

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                line = self.request.recv(1024).split(b"\r\n", 1)[0].decode()
                target = line.split(" ")[1]
                code = answer(target)
                if code is None:  # closes the socket without a word
                    return
                self.request.sendall(f"HTTP/1.1 {code} X\r\n\r\n".encode())

        with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                env = dict(os.environ, P2PC_PROBE_PROXY=f"127.0.0.1:{server.server_address[1]}", P2PC_PROBE_DIRECT=direct)
                done = subprocess.run([sys.executable, "-c", flows.EGRESS_PROBE, *args], env=env, capture_output=True, text=True, timeout=60)
            finally:
                server.shutdown()
        return done

    ARGS = ["pypi.org:443", "192.0.2.1:80", "100.64.0.1:80", "example.com:443"]

    def test_a_proxy_that_allows_only_the_allowlist_passes(self):
        done = self.run_probe(lambda t: 200 if t == "pypi.org:443" else 403, self.ARGS)
        self.assertEqual(done.returncode, 0, done.stdout)
        self.assertIn("OK allowed pypi.org:443", done.stdout)
        self.assertEqual(done.stdout.count("REFUSED"), 3)

    def test_a_proxy_that_lets_the_lan_through_fails_with_3(self):
        done = self.run_probe(lambda t: 403 if t.startswith("example") else 200, self.ARGS)
        self.assertEqual(done.returncode, 3)
        self.assertIn("REACHED forbidden 192.0.2.1:80", done.stdout)
        self.assertIn("REACHED forbidden 100.64.0.1:80", done.stdout)
        self.assertIn("REFUSED example.com:443", done.stdout)

    def test_a_proxy_that_refuses_the_allowed_domain_fails_with_2_so_denials_prove_nothing(self):
        done = self.run_probe(lambda t: 403, self.ARGS)
        self.assertEqual(done.returncode, 2)
        self.assertIn("FAIL allowed", done.stdout)

    def test_the_status_line_decides_200_reached_403_and_503_refused_502_and_504_policy_allowed(self):
        codes = {"192.0.2.1:80": 200, "192.0.2.2:80": 403, "192.0.2.3:80": 503, "192.0.2.4:80": 502, "192.0.2.5:80": 504}
        done = self.run_probe(lambda t: codes.get(t, 200), ["pypi.org:443", *codes])
        self.assertEqual(done.returncode, 3, done.stdout)
        lines = done.stdout.splitlines()
        self.assertIn("REACHED forbidden 192.0.2.1:80", lines)
        self.assertIn("REFUSED 192.0.2.2:80 (403)", lines)
        self.assertIn("REFUSED 192.0.2.3:80 (503)", lines)
        self.assertIn("POLICY-ALLOWED 192.0.2.4:80 (502)", lines)
        self.assertIn("POLICY-ALLOWED 192.0.2.5:80 (504)", lines)

    def test_only_refusals_pass_even_when_one_is_a_closed_gate(self):
        done = self.run_probe(lambda t: 200 if t == "pypi.org:443" else 503, self.ARGS)
        self.assertEqual(done.returncode, 0, done.stdout)

    def test_a_502_alone_fails_with_3_because_the_policy_did_not_deny_it(self):
        done = self.run_probe(lambda t: 200 if t == "pypi.org:443" else 502, self.ARGS[:2])
        self.assertEqual(done.returncode, 3)
        self.assertIn("POLICY-ALLOWED 192.0.2.1:80 (502)", done.stdout)

    def test_garbage_and_no_answer_are_not_a_denial(self):
        done = self.run_probe(lambda t: 200 if t == "pypi.org:443" else "garbage", self.ARGS[:2])
        self.assertEqual(done.returncode, 3)
        self.assertIn("POLICY-ALLOWED 192.0.2.1:80 (no-answer)", done.stdout)

    def test_a_proxy_that_closes_without_a_reply_is_no_denial(self):
        done = self.run_probe(lambda t: 200 if t == "pypi.org:443" else None, self.ARGS[:2])
        self.assertEqual(done.returncode, 3, done.stdout)
        self.assertIn("POLICY-ALLOWED 192.0.2.1:80 (no-answer)", done.stdout)

    def test_the_allowed_domain_failing_with_a_502_is_still_exit_2(self):
        done = self.run_probe(lambda t: 502, self.ARGS)
        self.assertEqual(done.returncode, 2)
        self.assertIn("FAIL allowed destination did not work: pypi.org:443 (502)", done.stdout)

    def test_a_direct_connection_that_succeeds_is_a_violation(self):
        import socket

        with socket.socket() as listener:  # a loopback port that accepts: stands in for "the internet"
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            done = self.run_probe(lambda t: 200 if t == "pypi.org:443" else 403, self.ARGS[:1], direct=f"127.0.0.1:{port}")
        self.assertEqual(done.returncode, 3)
        self.assertIn("REACHED direct", done.stdout)


def script_ctx(test, handler, toml, binaries=(), environ=None, gate=True):
    """A context for running a real criterion script against scripted machines. ``gate=True`` says a node can run jobs
    (the probe of ``flows.require_jobs_run`` is not what the test is about); ``gate=False`` leaves it to be probed."""
    tmp = tempfile.TemporaryDirectory()
    base = Path(tmp.name)
    for name in binaries:
        (base / name).write_bytes(b"binary " + name.encode())
    ctx, fake = make_ctx(handler, toml=toml + "\n[binaries]\n" + "".join(f'{n} = "{n}"\n' for n in binaries), environ=environ or {}, base=base)
    test.addCleanup(tmp.cleanup)
    # Every test that runs a script against scripted machines also checks this: no key and no join token, ever, in the
    # argv of a command sent to a machine (they travel on stdin, or in 0600 files).
    test.addCleanup(lambda: test.assertEqual(fake.secrets_in_argv, [], "a secret reached a machine in an argv"))
    if gate:
        ctx.state["jobs_run"] = True
    return ctx, fake


def p2pc_subcommand(argv: list[str]) -> str | None:
    return argv[argv.index("--json") + 1] if "--json" in argv else None


class ScriptsAgainstScriptedMachines(unittest.TestCase):
    NODES = """
    [server]
    executor = "local"
    admin_key_env = "TEST_ADMIN_KEY"
    [node_linux_gpu]
    executor = "local"
    """

    def test_ac2_stops_at_the_missing_jobs_api_and_never_reports_a_pass(self):
        import ac02_cpu_job

        missing_route = json.dumps({"error": {"kind": "api", "status": 404, "code": "not_found"}})

        def handler(argv, stdin):
            sub = p2pc_subcommand(argv)
            if sub == "whoami":
                return (0, json.dumps({"key_id": "k", "scopes": ["admin"]}), "")
            if sub == "machines":
                return (0, json.dumps([{"id": "node_1", "state": "online"}]), "")
            if sub == "run":
                return (125, "", missing_route)
            if argv[:1] == ["curl"]:  # the server's OpenAPI document: it has machines but no jobs yet
                return (0, json.dumps({"paths": {"/v1/nodes": {"get": {}}, "/v1/whoami": {"get": {}}}}), "")
            return preflight_ok(argv, stdin)

        ctx, _ = script_ctx(self, handler, self.NODES, binaries=["p2pc"], environ={"TEST_ADMIN_KEY": FAKE_KEY})
        res = ac02_cpu_job.run(ctx)
        by_name = {c.name: c for c in res.checks}
        self.assertEqual(by_name["environment ready"].status, core.PASS)
        self.assertEqual(by_name["warm the image cache"].status, core.BLOCKED)
        self.assertEqual(by_name["warm the image cache"].unblocked_by, ["T04"])
        # Everything that depends on it is blocked by the same task, not skipped and not passed.
        self.assertEqual(by_name["round trip: exit 0 and succeeded"].status, core.BLOCKED)
        self.assertEqual(by_name["the logs show 42"].status, core.BLOCKED)
        self.assertEqual(res.status, core.BLOCKED)
        self.assertIn("T04", res.unblocked_by)
        self.assertNotIn(core.PASS, [c.status for c in res.checks if c.name != "environment ready"])

    def test_ac2_is_skipped_without_machines(self):
        import ac02_cpu_job

        ctx, _ = script_ctx(self, preflight_ok, '[server]\nexecutor = "local"\n')
        res = ac02_cpu_job.run(ctx)
        self.assertEqual(res.checks[0].status, core.SKIP)
        self.assertEqual(res.status, core.SKIP)

    def test_ac1_is_blocked_on_the_installer_only_while_it_is_not_in_the_checkout(self):
        import ac01_install

        ctx, _ = script_ctx(self, preflight_ok, '[server]\nexecutor = "local"\n')
        with tempfile.TemporaryDirectory() as bare:
            ctx.repo_root = Path(bare)  # no deploy/linux/install-server.sh
            first = ac01_install.run(ctx).checks[0]
        self.assertEqual((first.status, first.unblocked_by), (core.BLOCKED, ["T14b1"]))

    def test_ac1_with_the_installer_in_the_checkout_but_no_command_is_a_skip_never_blocked(self):
        import ac01_install

        ctx, _ = script_ctx(self, preflight_ok, '[server]\nexecutor = "local"\n')  # this checkout has install-server.sh
        first = ac01_install.run(ctx).checks[0]
        self.assertEqual((first.status, first.unblocked_by), (core.SKIP, []))
        self.assertIn("install_command", first.reason)

    def test_ac1_captures_the_key_from_the_installer_and_times_it(self):
        import ac01_install

        def handler(argv, stdin):
            if argv[:2] == ["sh", "-c"] and "install-it" in argv[2]:
                return (0, f"Installed.\nADMIN API KEY (shown once): {FAKE_KEY}\n", "")
            if argv[:1] == ["curl"]:
                return (0, "ok", "")
            return preflight_ok(argv, stdin)

        toml = '[server]\nexecutor = "local"\ninstall_command = "install-it --yes"\n'
        ctx, _ = script_ctx(self, handler, toml)
        res = ac01_install.run(ctx)
        self.assertEqual(res.checks[0].status, core.PASS, res.checks[0].reason)
        self.assertIn("install_s", res.checks[0].timings)
        self.assertEqual(ctx.state["admin_key"], FAKE_KEY)
        self.assertNotIn("p2pc_sk_", json.dumps(res.to_dict()))

    def test_ac1_fails_an_installer_that_does_not_print_the_key(self):
        import ac01_install

        def handler(argv, stdin):
            if argv[:2] == ["sh", "-c"] and "install-it" in argv[2]:
                return (0, "Installed.\n", "")
            return preflight_ok(argv, stdin)

        ctx, _ = script_ctx(self, handler, '[server]\nexecutor = "local"\ninstall_command = "install-it"\n')
        res = ac01_install.run(ctx)
        self.assertEqual(res.checks[0].status, core.FAIL)
        self.assertIn("admin API key", res.checks[0].reason)

    def test_ac12_skips_a_missing_tool_with_its_install_hint(self):
        import ac12_supply_chain as ac12

        def handler(argv, stdin):
            if argv[:2] == ["cargo", "deny"]:
                return (101, "", "error: no such command: `deny`")
            if argv[0] == "gitleaks":
                return executors.ExecResult(None, error="cannot start gitleaks: No such file or directory")
            if argv[:2] == ["cargo", "cyclonedx"]:
                return (101, "", "error: no such command: `cyclonedx`")
            return (0, "", "")

        ctx, _ = script_ctx(self, handler, '[server]\nexecutor = "local"\n')
        res = ac12.run(ctx)
        by = {c.name: c for c in res.checks}
        self.assertEqual(by["cargo deny check"].status, core.SKIP)
        self.assertIn("cargo install --locked cargo-deny", by["cargo deny check"].reason)
        self.assertEqual(by["secret scan (gitleaks, full git history)"].status, core.SKIP)
        self.assertIn("gitleaks", by["secret scan (gitleaks, full git history)"].reason)
        self.assertIn("cargo-cyclonedx", by["SBOM (cargo cyclonedx)"].reason)
        self.assertEqual(by["SECURITY.md present and non-empty"].status, core.PASS)
        self.assertEqual(res.status, core.SKIP)  # a skipped tool is never a pass

    def test_ac12_a_failing_deny_is_a_failure(self):
        import ac12_supply_chain as ac12

        ctx, _ = script_ctx(self, lambda argv, stdin: (1, "", "error[license-not-encountered]") if argv[:2] == ["cargo", "deny"] else (0, "", ""), '[server]\nexecutor = "local"\n')
        res = ac12.run(ctx)
        self.assertEqual(res.checks[0].status, core.FAIL)
        self.assertEqual(res.status, core.FAIL)

    def test_ac12_gitleaks_findings_fail_the_check_and_name_where(self):
        import ac12_supply_chain as ac12

        def handler(argv, stdin):
            if argv[:2] == ["gitleaks", "git"]:
                path = argv[argv.index("--report-path") + 1]
                Path(path).write_text(json.dumps([{"RuleID": "generic-api-key", "File": "a/b.rs", "StartLine": 7}]))
                return (3, "", "leaks found: 1")
            return (0, "0", "")

        ctx, _ = script_ctx(self, handler, '[server]\nexecutor = "local"\n')
        res = ac12.run(ctx)
        scan = next(c for c in res.checks if c.name.startswith("secret scan"))
        self.assertEqual(scan.status, core.FAIL)
        self.assertIn("generic-api-key a/b.rs:7", scan.reason)
        self.assertEqual(scan.evidence["findings"], 1)

    def run_gitleaks(self, answer):
        import ac12_supply_chain as ac12

        seen = []

        def handler(argv, stdin):
            if argv[:2] == ["gitleaks", "git"]:
                seen.append(argv)
                return answer
            return (0, "0", "")

        ctx, _ = script_ctx(self, handler, '[server]\nexecutor = "local"\n')
        res = ac12.run(ctx)
        return next(c for c in res.checks if c.name.startswith("secret scan")), seen

    def test_gitleaks_is_told_to_exit_3_for_leaks_so_its_own_errors_can_be_told_apart(self):
        scan, seen = self.run_gitleaks((0, "", ""))
        self.assertEqual(scan.status, core.PASS)
        argv = seen[0]
        self.assertEqual(argv[argv.index("--exit-code") + 1], "3")

    def test_a_gitleaks_error_without_findings_reports_the_tools_own_output(self):
        scan, _ = self.run_gitleaks((1, "", "ERR failed to open the repo: not a git repository"))
        self.assertEqual(scan.status, core.FAIL)
        self.assertIn("gitleaks itself failed (exit 1)", scan.reason)
        self.assertIn("not a git repository", scan.reason)
        self.assertNotIn("potential secret", scan.reason)
        timed_out = self.run_gitleaks(executors.ExecResult(None, timed_out=True))[0]
        self.assertEqual(timed_out.status, core.FAIL)
        self.assertIn("timed out", timed_out.reason)

    def test_exit_3_without_a_readable_report_is_still_leaks(self):
        scan, _ = self.run_gitleaks((3, "", "leaks found"))
        self.assertEqual(scan.status, core.FAIL)
        self.assertIn("potential secret", scan.reason)

    def test_ac10_waits_for_the_jobs_api(self):
        import ac10_scale

        ctx, _ = script_ctx(self, preflight_ok, '[server]\nexecutor = "local"\n')
        self.assertEqual(ac10_scale.run(ctx).checks[0].status, core.SKIP)

    def test_ac8_ac9_ac3_ac4_ac5_ac6_ac7_skip_cleanly_when_no_machine_is_configured(self):
        import ac03_gpu_job, ac04_egress, ac05_inputs_outputs, ac06_node_loss, ac07_cancel_timeout, ac08_remote_client, ac09_mcp

        for mod in (ac03_gpu_job, ac04_egress, ac05_inputs_outputs, ac06_node_loss, ac07_cancel_timeout, ac08_remote_client, ac09_mcp):
            with self.subTest(mod.ID):
                ctx, _ = script_ctx(self, preflight_ok, '[server]\nexecutor = "local"\nenabled = false\n')
                res = mod.run(ctx)
                self.assertEqual(res.status, core.SKIP, [(c.name, c.status, c.reason) for c in res.checks])
                self.assertNotEqual(res.status, core.PASS)


class Readme(unittest.TestCase):
    def test_the_status_table_is_the_one_run_py_list_prints(self):
        text = (HERE / "README.md").read_text(encoding="utf-8")
        block = text.split("<!-- status-table:start -->\n", 1)[1].split("\n<!-- status-table:end -->", 1)[0]
        # The first three columns are the scripts' own and must match. The last two ("Runs today", "Waiting for") are READ
        # FROM THE PRODUCT by `./run.py --list`, so they are as of the last time that was run, and are checked for shape:
        # a task that lands changes them without this test, or any script, being edited.
        want = criteria.status_table(criteria.load_all()).splitlines()
        got = block.splitlines()
        self.assertEqual(len(got), len(want))
        self.assertEqual([r.split("|")[:4] for r in got], [r.split("|")[:4] for r in want], "refresh the table with ./run.py --list")
        for row in got[2:]:
            runs, waiting = [c.strip() for c in row.split("|")[4:6]]
            self.assertIn(runs, ("yes", "partly", "no"), row)
            self.assertRegex(waiting, r"^(nothing|T\d+[a-z]?\d?[*?]?(, T\d+[a-z]?\d?[*?]?)*)$", row)

    def test_the_readme_has_no_real_hostnames_or_addresses(self):
        for name in ("README.md", "machines.example.toml"):
            text = (HERE / name).read_text(encoding="utf-8")
            for match in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text):
                ok = match.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "127.", "100.64.", "1.1.1.1", "0.0.0.0"))
                self.assertTrue(ok, f"{name}: {match} is not a documentation address")

    def test_the_example_documents_every_machine_key(self):
        text = (HERE / "machines.example.toml").read_text(encoding="utf-8")
        for role, keys in machines.ROLE_KEYS.items():
            for key in keys:
                self.assertRegex(text, rf"(?m)^#?\s*{key}\s*=|^#\s+{key}\b", f"{key} (role {role}) is not in the example")


class MachinesNodeKeys(unittest.TestCase):
    def test_the_agent_start_command_and_podman_are_accepted_on_nodes_only(self):
        m = parse(
            """
            [node_linux_gpu]
            executor = "local"
            agent_start_command = "nohup $0 run > $1 &"
            podman = ["sudo", "-u", "p2pc", "podman"]
            lan_gateway = "192.0.2.1"
            """
        )
        self.assertEqual(m.roles["node_linux_gpu"].get("podman"), ["sudo", "-u", "p2pc", "podman"])
        self.assertTrue(any("agent_start_command: unknown key" in x for x in problems('[server]\nexecutor = "local"\nagent_start_command = "x"\n')))
        self.assertTrue(any("lan_gateway:" in x for x in problems('[node_linux_gpu]\nexecutor = "local"\nlan_gateway = "192.0.2.4; rm"\n')))


class TestPrefixAndEnvKeys(unittest.TestCase):
    NODE = '[node_linux]\nexecutor = "local"\nrepo_dir = "/srv/p2pc"\n'

    def test_an_invalid_repo_dir_gets_its_own_error_and_not_a_false_needs_repo_dir(self):
        # T15f P3: repo_dir is set but fails validation, so it is missing from the validated values only.
        found = problems('[node_linux]\nexecutor = "local"\nrepo_dir = 5\ntest_prefix = ["sudo"]\n')
        self.assertTrue(any("repo_dir" in x for x in found), found)
        self.assertFalse(any("needs repo_dir" in x for x in found), found)

    def test_they_need_repo_dir_or_they_would_be_ignored_in_silence(self):
        # T15e review P3 5: without repo_dir the role is never picked to run the ignored tests, so the keys do nothing.
        bare = '[node_linux]\nexecutor = "local"\n'
        self.assertTrue(any("test_prefix" in x and "repo_dir" in x for x in problems(bare + 'test_prefix = ["sudo"]\n')))
        self.assertTrue(any("test_env" in x and "repo_dir" in x for x in problems(bare + 'test_env = { A = "1" }\n')))

    def test_they_are_accepted_on_nodes(self):
        m = parse(self.NODE + 'test_prefix = ["sudo", "-u", "p2pc"]\ntest_env = { P2PC_SHIM = "/opt/shim" }\n')
        self.assertEqual(m.roles["node_linux"].get("test_prefix"), ["sudo", "-u", "p2pc"])
        self.assertEqual(m.roles["node_linux"].get("test_env"), {"P2PC_SHIM": "/opt/shim"})

    def test_a_non_list_or_empty_prefix_is_refused(self):
        for bad in ('"sudo"', "[]", "[1]", '[""]'):
            with self.subTest(bad):
                self.assertTrue(any("test_prefix:" in x for x in problems(self.NODE + f"test_prefix = {bad}\n")))

    def test_a_bad_env_is_refused(self):
        for bad in ('["A=1"]', "{}", '{ "1A" = "x" }', "{ A = 1 }", '{ API_TOKEN = "x" }'):
            with self.subTest(bad):
                self.assertTrue(any("test_env:" in x for x in problems(self.NODE + f"test_env = {bad}\n")))

    def test_they_are_not_accepted_on_the_server(self):
        self.assertTrue(any("test_prefix: unknown key" in x for x in problems('[server]\nexecutor = "local"\ntest_prefix = ["a"]\n')))


class TheLabExample(unittest.TestCase):
    """T15b: machines.example.toml describes the lab of the first real run, with placeholders only."""

    def setUp(self):
        self.m = machines.load_machines(HERE / "machines.example.toml")

    def test_the_server_is_a_linux_host_over_ssh_with_a_directory_named_for_the_binaries(self):
        server = self.m.roles["server"]
        self.assertEqual(server.executor, "ssh")
        self.assertTrue(server.workdir and server.workdir.startswith("/"), "the example names the directory of the binaries")

    def test_the_windows_node_is_wsl_over_ssh_into_the_p2pc_node_distro(self):
        win = self.m.roles["node_wsl2_gpu"]
        self.assertEqual((win.executor, win.distro), ("wsl_over_ssh", "p2pc-node"))
        self.assertEqual(win.get("podman"), ["podman"])

    def test_the_linux_node_has_no_gpu_role_and_the_gpu_linux_one_is_left_disabled(self):
        self.assertEqual(self.m.roles["node_linux"].executor, "ssh")
        self.assertFalse(self.m.roles["node_linux_gpu"].enabled)  # not in the lab
        self.assertFalse(self.m.roles["client_remote"].enabled)

    def test_every_role_is_disabled_so_that_the_example_is_valid_as_it_is_and_nothing_names_a_real_machine(self):
        self.assertFalse(any(r.enabled for r in self.m.roles.values()))
        for role in self.m.roles.values():
            if role.host:
                self.assertTrue(role.host.startswith("lab-"), role.host)  # an alias of the user's ssh config, never a name of ours
        text = (HERE / "machines.example.toml").read_text(encoding="utf-8")
        self.assertNotRegex(text, r"(?i)ssh-(rsa|ed25519)|BEGIN [A-Z ]*PRIVATE|p2pc_(sk|join)_[A-Za-z0-9]{8}")

    def test_the_example_drives_the_merged_node_installers(self):
        # T14b2: install-node.sh on Linux (sudo, from a release directory), install.ps1 on the Windows HOST (-Tar, -Join).
        self.assertIn("install-node.sh --from", self.m.roles["node_linux"].get("install_command"))
        win = self.m.roles["node_wsl2_gpu"]
        self.assertIn("install.ps1' -Join", win.get("install_command"))
        # `-Tar` is run once, so it is commented out in the example (a second run exits 16), but it is shown there.
        self.assertIsNone(win.get("image_install_command"))
        text = (HERE / "machines.example.toml").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^# image_install_command = .*install\.ps1.* -Tar ")
        self.assertIn("ONCE", text)
        for command in (self.m.roles["node_linux"].get("install_command"), win.get("install_command")):
            self.assertNotRegex(command, r"p2pc_join_")  # the token is never in a command

    def test_the_node_roles_accept_an_installer_command(self):
        for role in ("node_linux", "node_linux_gpu", "node_wsl2_gpu"):
            self.assertIn("install_command", machines.ROLE_KEYS[role])
        self.assertNotIn("install_command", machines.ROLE_KEYS["client_remote"])


class Ac10LoadPlan(unittest.TestCase):
    """Best fit packs the jobs (spec §8): only a queue that backs up reaches every node (ACC-1 round 5)."""

    LIMITS = {"small": 4, "big": 22, "mid": 20}

    def test_the_queue_backs_up_with_nodes_of_4_22_and_20(self):
        import ac10_scale

        sleep_s, count, deadline_s = ac10_scale.plan_load(self.LIMITS, 100)
        self.assertGreater(count, sum(self.LIMITS.values()))  # more than 46 jobs
        self.assertGreaterEqual(sleep_s, 30)
        # The first job must still run when the last slot is taken: the submissions (about a second each) of one
        # full round of slots take less than a job lasts.
        self.assertGreater(sleep_s, sum(self.LIMITS.values()))
        self.assertGreater(deadline_s, sleep_s)

    def test_the_old_values_do_not_make_the_queue_back_up(self):
        import ac10_scale

        # Round 5: jobs of 4 s. Submitting one job per slot (46 of them) takes longer than that, so the first jobs end
        # before the last slot is taken and best fit never reaches the big node.
        old_sleep_s = 4
        slots = sum(self.LIMITS.values())
        self.assertLess(old_sleep_s, ac10_scale.SUBMIT_BUDGET_S * slots)
        self.assertGreaterEqual(ac10_scale.plan_load(self.LIMITS, 100)[0], ac10_scale.SUBMIT_BUDGET_S * slots)

    def test_a_larger_sum_of_limits_means_longer_jobs_and_more_of_them(self):
        import ac10_scale

        s1, c1, d1 = ac10_scale.plan_load({"a": 4, "b": 4}, 8)
        s2, c2, d2 = ac10_scale.plan_load({"a": 40, "b": 40, "c": 40}, 100)
        self.assertEqual(s1, 30)  # the floor
        self.assertGreater(s2, s1)
        self.assertGreater(c2, 120)  # the configured 100 is not enough for 120 slots
        self.assertGreater(d2, d1)

    def test_the_configured_count_is_kept_when_it_is_enough(self):
        import ac10_scale

        self.assertEqual(ac10_scale.plan_load({"a": 2, "b": 2}, 8)[1], 8)
        self.assertEqual(ac10_scale.plan_load(self.LIMITS, 200)[1], 200)


class Ac10Driver(unittest.TestCase):
    """The AC-10 driver, end to end, against a simulated server: 8 jobs, 2 nodes, 2 per node."""

    TOML = """
    [server]
    executor = "local"
    admin_key_env = "TEST_ADMIN_KEY"
    [node_linux_gpu]
    executor = "local"
    [node_wsl2_gpu]
    executor = "local"
    [params]
    job_count = 8
    jobs_per_node = 2
    """

    RUN_KEY = "p2pc_sk_" + "acc10runkey1" + "_" + "r" * 52
    CLAP_USAGE = "error: unexpected argument '--group-by' found\n\n  tip: a similar argument exists: '--by'\n\nUsage: p2pc usage [OPTIONS]\n\nFor more information, try '--help'.\n"

    def simulate(self, tick0_extra_on_n1=False, lose_job=None, usage_units=2, run_stderr=None, usage_stub=False,
                 unrelated_in_ledger=True, offered_cpu=None, free_cpu=None, wave_size=4, node_of=None):
        offered_cpu = offered_cpu or {"n1": 4.0, "n2": 4.0}
        free_cpu = free_cpu or dict(offered_cpu)
        sim = {"tick": 0, "names": [], "cpu": None, "queries": [], "revoked": [], "usage": [], "submit_keys": [],
               "created": 0, "created_scopes": []}
        nodes = [
            {"id": "n1", "name": "n1", "state": "online", "free": {"cpu": free_cpu["n1"], "memory_mb": 8192, "gpu": 1},
             "inventory": {"platform": "linux", "gpus": [{"uuid": "g"}], "hostname": "n1", "cpu": {}, "memory_mb": 1, "os": "x", "sandbox": [],
                           "offered": {"cpu": offered_cpu["n1"], "memory_mb": 8192, "gpu": 1}}},
            {"id": "n2", "name": "n2", "state": "online", "free": {"cpu": free_cpu["n2"], "memory_mb": 8192, "gpu": 1},
             "inventory": {"platform": "wsl2", "gpus": [{"uuid": "g"}], "hostname": "n2", "cpu": {}, "memory_mb": 1, "os": "x", "sandbox": [],
                           "offered": {"cpu": offered_cpu["n2"], "memory_mb": 8192, "gpu": 1}}},
        ]

        def jobs_now():
            names = sim["names"]
            out = []
            for i, name in enumerate(names):
                node = node_of(i) if node_of else ("n1" if i % 2 == 0 else "n2")
                wave = i // wave_size
                status = "queued" if sim["tick"] < wave else ("running" if sim["tick"] == wave else "succeeded")
                if lose_job == i and status == "succeeded":
                    status = "lost"
                out.append({"id": f"job_{i}", "name": name, "status": status, "node_id": None if status == "queued" else node,
                            "attempt": 1, "created_at": f"2026-11-05T12:00:{i:02d}Z"})
            if tick0_extra_on_n1 and sim["tick"] == 0:
                for j in (8, 9):  # a third and fourth job booked on n1 at once (more than 2)
                    out.append({"id": f"job_x{j}", "name": f"{names[0].rsplit('-', 1)[0]}-{j}", "status": "running", "node_id": "n1", "attempt": 1})
            return out

        def handler(argv, stdin):
            sub = p2pc_subcommand(argv)
            if sub == "whoami":
                return (0, json.dumps({"key_id": "k", "scopes": ["admin"]}), "")
            if sub == "machines":
                return (0, json.dumps(nodes), "")
            if "keys" in argv and "create" in argv:
                sim["created"] += 1
                sim["created_scopes"].append([argv[i + 1] for i, a in enumerate(argv) if a == "--scope"])
                return (0, json.dumps({"id": "kid_run", "key": self.RUN_KEY, "scopes": ["jobs:write"]}), "")
            if "keys" in argv and "revoke" in argv:
                sim["revoked"].append(argv[-1])
                return (0, "{}", "")
            if argv[-1] == "--help" and argv[-2].endswith("/p2pc"):  # `p2pc --help`: is `usage` still a stub?
                real = TODAY_P2PC_HELP.replace("Show reserved and used compute (not available in this version yet)", "Show reserved and used compute")
                return (0, TODAY_P2PC_HELP if usage_stub else real, "")
            if sub == "run" and run_stderr is not None:
                return (125, "", run_stderr)
            if sub == "run":
                sim["submit_keys"].append((stdin or b"").split(b"\n", 1)[0].decode())
                sim["names"].append(argv[argv.index("--name") + 1])
                sim["cpu"] = argv[argv.index("--cpu") + 1]
                return (0, json.dumps({"id": f"job_{len(sim['names']) - 1}", "status": "queued"}), "")
            if sub == "jobs":
                data = jobs_now()
                sim["queries"].append([a for a in argv if a.startswith("--") or a in ("assigned", "running", "queued")])
                if "--status" in argv:
                    wanted = argv[argv.index("--status") + 1]
                    data = [j for j in data if j["status"] == wanted]
                    if wanted == "queued":
                        sim["tick"] += 1  # one poll = three queries (assigned, running, queued); time moves once per poll
                else:
                    data = data + [{"id": "job_other", "name": "somebody-else", "status": "running", "node_id": "n1", "attempt": 1}]
                return (0, json.dumps(data + [{"id": "job_old", "name": "acc9-old", "status": "running", "node_id": "n1"}] if "--status" in argv else data), "")
            if sub == "usage":
                if usage_stub:  # an old CLI: clap refuses the arguments before the stub can speak
                    return (125, "", self.CLAP_USAGE)
                if "--group-by" in argv:  # the real flag is --by (docs/cli.md, crates/p2pc-cli/src/cli.rs)
                    return (125, "", self.CLAP_USAGE)
                group = argv[argv.index("--by") + 1]
                sim["usage"].append(argv)
                ms = 7200

                def totals(key, units, reserved_cpu_ms=0):
                    return {"key": key, "attempts": 1, "units": units, "reserved_cpu_ms": reserved_cpu_ms,
                            "reserved_gpu_ms": 0, "used_cpu_ms": 0, "max_rss_mb": 0, "estimated_attempts": 0}

                if group == "job":
                    items = [totals(f"job_{i}", usage_units, ms) for i in range(8)]
                    if unrelated_in_ledger:  # an earlier run's job is in the ledger too
                        items.append(totals("job_from_an_earlier_run", 5000, 18_000_000))
                elif group == "node":
                    items = [totals("n1", usage_units * 4 + (5000 if unrelated_in_ledger else 0)), totals("n2", usage_units * 4)]
                else:
                    items = [totals("kid_run", usage_units * 8)]
                    if unrelated_in_ledger:
                        items.append(totals("key_of_somebody_else", 5000))
                # The real report (UsageReport): the range, how it is grouped, the items and the total of the range.
                total = totals(None, sum(i["units"] for i in items))
                return (0, json.dumps({"from": "2026-11-05T12:00:00Z", "to": "2026-11-06T00:00:00Z", "group_by": group,
                                       "items": items, "total": total, "next_cursor": None}), "")
            return preflight_ok(argv, stdin)

        ctx, _ = script_ctx(self, handler, self.TOML, binaries=["p2pc"], environ={"TEST_ADMIN_KEY": FAKE_KEY})
        return ctx, sim

    def test_a_refusal_with_a_key_cut_from_its_end_leaks_nothing(self):
        import ac10_scale

        ctx, _ = self.simulate(run_stderr="e" * 300 + FAKE_KEY)
        res = ac10_scale.run(ctx)
        submit = next(c for c in res.checks if c.name.startswith("submit"))
        self.assertEqual(submit.status, core.FAIL)
        self.assertNotIn("qqqq", submit.reason)
        self.assertNotIn("qqqq", json.dumps(res.to_dict()))

    def test_a_poll_is_three_server_side_queries_and_other_jobs_are_never_counted(self):
        import ac10_scale

        ctx, sim = self.simulate()
        res = ac10_scale.run(ctx)
        self.assertEqual(res.status, core.PASS)
        states = [q[q.index("--status") + 1] for q in sim["queries"] if "--status" in q]
        self.assertEqual(set(states), {"assigned", "running", "queued"})
        self.assertEqual(states[:3], ["assigned", "running", "queued"])
        # Exactly one unfiltered listing, at the end, for the end state: terminal jobs are not re-read on every poll.
        self.assertEqual(len([q for q in sim["queries"] if "--status" not in q]), 1)
        self.assertNotIn("--status", sim["queries"][-1])  # the last query is that unfiltered listing
        # Somebody else's running job (job_other, acc9-old) never shows up in the concurrency picture.
        by = next(c for c in res.checks if c.name.startswith("no double booking"))
        self.assertEqual(by.status, core.PASS)

    def test_the_duration_of_each_poll_is_recorded(self):
        import ac10_scale

        ctx, _ = self.simulate()
        res = ac10_scale.run(ctx)
        chk = next(c for c in res.checks if c.name.startswith("run to completion"))
        self.assertIn("poll_max_s", chk.timings)
        self.assertIn("poll_mean_s", chk.timings)
        self.assertEqual(len(chk.evidence["poll_durations_s"]), chk.evidence["snapshots"])

    def test_a_job_that_moves_between_two_queries_is_never_counted_twice(self):
        import ac10_scale

        def handler(argv, stdin):
            if p2pc_subcommand(argv) == "jobs":
                state = argv[argv.index("--status") + 1]
                # job_1 starts between the assigned and the running query, so both answer it; job_2 is only queued.
                rows = {"assigned": ["job_1"], "running": ["job_1"], "queued": ["job_2"]}[state]
                node = None if state == "queued" else "n1"
                return (0, json.dumps([{"id": r, "name": "acc10-x-1", "status": state, "node_id": node} for r in rows]), "")
            return preflight_ok(argv, stdin)

        ctx, _ = script_ctx(self, handler, '[server]\nexecutor = "local"\nadmin_key_env = "K"\n', binaries=["p2pc"], environ={"K": FAKE_KEY})
        ctx.begin("AC-10", "t")
        snap = ac10_scale._snapshot(ctx, "acc10-x-")
        self.assertEqual(sorted(snap), ["job_1", "job_2"])
        self.assertEqual(snap["job_1"]["status"], "running")  # the latest state wins: one entry, on one node
        self.assertEqual(snap["job_2"]["status"], "queued")

    DOUBLE = "no double booking: never over a node's own limit, never more CPU than offered"

    def test_unequal_nodes_each_get_what_their_own_capacity_allows(self):
        import ac10_scale

        # n1 offers 4 vCPU, n2 offers 8: the jobs are sized by the smaller (2 vCPU, so 2 per node), but n2 may hold 4.
        ctx, sim = self.simulate(offered_cpu={"n1": 4.0, "n2": 8.0}, wave_size=6, node_of=lambda i: "n2" if i % 3 else "n1")
        res = ac10_scale.run(ctx)
        by = {c.name: c for c in res.checks}
        self.assertEqual(by[self.DOUBLE].status, core.PASS, by[self.DOUBLE].reason)
        env = next(c for c in res.checks if c.name.startswith("environment ready"))
        self.assertEqual(env.evidence["limits"], {"n1": 2, "n2": 4})
        self.assertEqual(env.evidence["reach"], {"n1": 2, "n2": 2})  # min(per_node, limit)
        self.assertEqual(sim["cpu"], "2.0")

    def test_a_bigger_node_over_its_own_limit_is_double_booking(self):
        import ac10_scale

        # n2 holds 5 jobs at once but offers only 8 vCPU for 2-vCPU jobs: 4 at most.
        ctx, _ = self.simulate(offered_cpu={"n1": 4.0, "n2": 8.0}, wave_size=6, node_of=lambda i: "n2" if i < 5 else "n1")
        by = {c.name: c for c in ac10_scale.run(ctx).checks}
        self.assertEqual(by[self.DOUBLE].status, core.FAIL)
        self.assertIn("n2", by[self.DOUBLE].reason)

    def test_the_old_flat_limit_would_have_flagged_the_bigger_node(self):
        snaps = [[("n1", "running")] * 2 + [("n2", "running")] * 4]
        old = flows.analyze_concurrency(snaps, limit=2)
        self.assertEqual(old["over_limit"], {"n2": 4})  # a count of 2 for everyone: what was wrong
        new = flows.analyze_concurrency(snaps, limit={"n1": 2, "n2": 4}, reach={"n1": 2, "n2": 2})
        self.assertEqual((new["over_limit"], new["not_reached"]), ({}, {}))

    def test_a_node_that_never_reaches_its_share_did_not_stress_the_scheduler(self):
        import ac10_scale

        ctx, _ = self.simulate(wave_size=2)  # one job per node at a time: never 2
        by = {c.name: c for c in ac10_scale.run(ctx).checks}
        self.assertEqual(by[self.DOUBLE].status, core.FAIL)
        self.assertIn("did not reach its share", by[self.DOUBLE].reason)

    def test_something_already_running_neither_shrinks_the_jobs_nor_hides_that_the_node_is_busy(self):
        import ac10_scale

        # n1 offers 4 vCPU but 2 are in use. The jobs are sized from what is OFFERED (2 vCPU), not from what is free
        # (which would give 1 vCPU jobs), and n1 only has to reach what is still free (1 job).
        ctx, sim = self.simulate(free_cpu={"n1": 2.0, "n2": 4.0}, wave_size=3, node_of=lambda i: "n1" if i % 3 == 0 else "n2")
        res = ac10_scale.run(ctx)
        env = next(c for c in res.checks if c.name.startswith("environment ready"))
        self.assertEqual(sim["cpu"], "2.0")
        self.assertEqual(env.evidence["busy_cpu_at_start"], {"n1": 2.0})
        self.assertEqual(env.evidence["reach"], {"n1": 1, "n2": 2})
        by = {c.name: c for c in res.checks}
        self.assertEqual(by[self.DOUBLE].status, core.PASS, by[self.DOUBLE].reason)

    def test_a_node_with_no_free_capacity_for_one_job_cannot_run_the_test(self):
        import ac10_scale

        ctx, _ = self.simulate(free_cpu={"n1": 1.0, "n2": 4.0})
        env = next(c for c in ac10_scale.run(ctx).checks if c.name.startswith("environment ready"))
        self.assertEqual(env.status, core.SKIP)  # the environment is busy: not the product's fault
        self.assertIn("no free capacity", env.reason)

    def test_a_correct_scheduler_passes_every_check(self):
        import ac10_scale

        ctx, sim = self.simulate()
        res = ac10_scale.run(ctx)
        self.assertEqual([(c.name, c.status, c.reason) for c in res.checks if c.status != core.PASS], [])
        self.assertEqual(res.status, core.PASS)
        self.assertEqual(len(sim["names"]), 8)
        self.assertEqual(sim["cpu"], "2.0")  # 4 vCPU offered / 2 jobs per node
        self.assertTrue(all(n.startswith("acc10-") for n in sim["names"]))

    def test_a_node_booked_beyond_its_limit_fails_the_double_booking_check(self):
        import ac10_scale

        ctx, _ = self.simulate(tick0_extra_on_n1=True)
        res = ac10_scale.run(ctx)
        by = {c.name: c for c in res.checks}
        self.assertEqual(by["no double booking: never over a node's own limit, never more CPU than offered"].status, core.FAIL)
        self.assertEqual(res.status, core.FAIL)

    def test_a_lost_job_fails_the_no_lost_jobs_check(self):
        import ac10_scale

        ctx, _ = self.simulate(lose_job=5)
        res = ac10_scale.run(ctx)
        by = {c.name: c for c in res.checks}
        self.assertEqual(by["no lost jobs: all succeeded, each exactly once"].status, core.FAIL)
        self.assertIn("lost", by["no lost jobs: all succeeded, each exactly once"].reason)
        self.assertEqual(by[LEDGER].status, core.SKIP)  # not evaluated after a failure

    def test_a_ledger_that_does_not_add_up_fails_only_the_ledger_check(self):
        import ac10_scale

        ctx, _ = self.simulate(usage_units=7)  # 7 milli-units for 7200 vCPU-ms: should be 2
        res = ac10_scale.run(ctx)
        by = {c.name: c for c in res.checks}
        self.assertEqual(by[LEDGER].status, core.FAIL)
        self.assertEqual(by["no lost jobs: all succeeded, each exactly once"].status, core.PASS)

    def test_the_ledger_is_blocked_until_p2pc_usage_exists(self):
        import ac10_scale

        # The real CLI today: `p2pc usage` says it is not implemented; `p2pc usage --group-by job` never gets that far,
        # clap refuses the argument first.
        ctx, sim = self.simulate(usage_stub=True)
        res = ac10_scale.run(ctx)
        by = {c.name: c for c in res.checks}
        ledger = by[LEDGER]
        self.assertEqual((ledger.status, ledger.unblocked_by), (core.BLOCKED, ["T11b2"]))
        self.assertNotEqual(res.status, core.PASS)

    def test_the_ledger_covers_only_this_run(self):
        import ac10_scale

        ctx, sim = self.simulate(unrelated_in_ledger=True)
        res = ac10_scale.run(ctx)
        self.assertEqual([(c.name, c.status, c.reason) for c in res.checks if c.status != core.PASS], [])
        # --from is the creation of the run's first job, as the server recorded it (spec §7: GET /v1/usage ?from&to).
        self.assertEqual(len(sim["usage"]), 3)
        for argv in sim["usage"]:
            self.assertEqual(argv[argv.index("--from") + 1], "2026-11-05T12:00:00Z")
            self.assertIn("--to", argv)  # explicit: the CLI's default stops at the end of the UTC day
            self.assertNotIn("--group-by", argv)
        self.assertEqual({a[a.index("--by") + 1] for a in sim["usage"]}, {"job", "node", "key"})
        # An unrelated job (and key, and node load) is in the ledger and does not matter.
        ledger = next(c for c in res.checks if c.name == LEDGER)
        self.assertEqual(ledger.evidence["from"], "2026-11-05T12:00:00Z")

    def test_the_jobs_are_submitted_with_a_dedicated_key_that_is_revoked_at_the_end(self):
        import ac10_scale

        ctx, sim = self.simulate()
        res = ac10_scale.run(ctx)
        self.assertEqual(sim["created"], 1)
        self.assertEqual(set(sim["submit_keys"]), {self.RUN_KEY})  # not the admin key
        self.assertNotEqual(self.RUN_KEY, FAKE_KEY)
        self.assertEqual(sim["revoked"], ["kid_run"])
        self.assertNotIn("p2pc_sk_", json.dumps(res.to_dict()))

    def test_the_run_key_is_revoked_even_when_a_check_blows_up(self):
        import ac10_scale

        ctx, sim = self.simulate(run_stderr="refused")
        ac10_scale.run(ctx)
        self.assertEqual(sim["revoked"], ["kid_run"])
        # ... and also when the run is interrupted.
        ctx, sim = self.simulate()
        original = ctx.executor("server").handler

        def interrupt(argv, stdin):
            if p2pc_subcommand(argv) == "jobs":
                raise KeyboardInterrupt
            return original(argv, stdin)

        ctx.executor("server").handler = interrupt
        with self.assertRaises(KeyboardInterrupt):
            ac10_scale.run(ctx)
        self.assertEqual(sim["revoked"], ["kid_run"])


class ContextWorkdir(unittest.TestCase):
    def test_without_workdir_a_private_directory_is_made_once_with_mktemp(self):
        ctx, fake = make_ctx(preflight_ok)
        self.assertEqual(ctx.workdir("node_linux_gpu"), "/tmp/p2pc-acc.TESTONLY0")
        self.assertEqual(ctx.workdir("node_linux_gpu"), "/tmp/p2pc-acc.TESTONLY0")
        made = [argv for argv, _ in fake.calls if argv[:2] == ["mktemp", "-d"]]
        self.assertEqual(len(made), 1)
        self.assertNotIn("/tmp/p2pc-acceptance", json.dumps(fake.calls))

    def test_a_path_that_is_not_absolute_or_a_failing_mktemp_is_a_failure(self):
        for answer in ((0, "relative/dir\n", ""), (0, "", ""), (0, "/\n", ""), (1, "", "mktemp: failed")):
            ctx, _ = make_ctx(lambda argv, stdin, a=answer: a)
            with self.assertRaises(core.CheckFailed, msg=answer):
                ctx.workdir("node_linux_gpu")

    def test_the_preflight_makes_the_directory_private(self):
        ctx, fake = make_ctx(preflight_ok)
        ctx.require("node_linux_gpu")
        calls = [argv for argv, _ in fake.calls]
        self.assertTrue(any(a[:2] == ["sh", "-c"] and "chmod 700" in a[2] for a in calls), calls)

    def test_close_removes_only_the_directories_the_run_made(self):
        ctx, fake = make_ctx(preflight_ok)
        ctx.workdir("node_linux_gpu")
        ctx.workdir("server")  # explicit /work/server: not ours to delete
        ctx.close()
        removed = [argv for argv, _ in fake.calls if argv[:2] == ["rm", "-rf"]]
        self.assertEqual(removed, [["rm", "-rf", "/tmp/p2pc-acc.TESTONLY0"]])
        ctx.close()  # idempotent
        self.assertEqual(len([1 for argv, _ in fake.calls if argv[:2] == ["rm", "-rf"]]), 1)


class RedactBeforeCutting(unittest.TestCase):
    def test_a_key_cut_at_its_prefix_leaves_nothing_readable(self):
        text = "x" * 50 + FAKE_KEY
        # Cutting first would keep only the tail of the secret, which has no p2pc_sk_ prefix for a pattern to match.
        self.assertIn("qqqq", text[-30:])
        self.assertNotIn("qqqq", core.tail(text, 30))
        self.assertNotIn("qqqq", core.last_line("first\n" + text))
        self.assertNotIn("qqqq", core.excerpt(core.clean(text), 40))

    def test_tail_strips_colours_and_whitespace(self):
        self.assertEqual(core.tail("\x1b[31mred\x1b[0m  \n", 10), "red")
        self.assertEqual(core.last_line("a\n\nb  \n\n"), "b")
        self.assertEqual(core.last_line(""), "")

    def test_failure_descriptions_are_redacted_before_they_are_shortened(self):
        long_stderr = "e" * 400 + FAKE_KEY
        step = core.Step("p2pc run", "server", "c", 125, stderr=long_stderr)
        self.assertNotIn("qqqq", context.describe_failure(step))
        err = json.dumps({"error": {"kind": "api", "status": 500, "code": "x", "detail": FAKE_KEY}})
        self.assertNotIn("p2pc_sk_", context.describe_failure(core.Step("p2pc run", "server", "c", 125, stderr=err)))

    def test_a_non_json_answer_is_quoted_redacted_and_short(self):
        ctx, _ = make_ctx()
        with self.assertRaises(core.CheckFailed) as cm:
            ctx.json_of(core.Step("l", "r", "c", 0, stdout="z" * 100 + FAKE_KEY), "p2pc whoami")
        self.assertNotIn("qqqq", cm.exception.reason)
        self.assertNotIn("p2pc_sk_", cm.exception.reason)


class FlowsPorts(unittest.TestCase):
    def test_url_port_uses_the_schemes_default(self):
        self.assertEqual(flows.url_port("http://127.0.0.1:7477"), 7477)
        self.assertEqual(flows.url_port("https://p2pc.example.invalid"), 443)
        self.assertEqual(flows.url_port("http://p2pc.example.invalid/"), 80)
        self.assertEqual(flows.url_port("http://[2001:db8::1]:99/x"), 99)
        for bad in ("ftp://x", "p2pc.example.invalid", "http://"):
            with self.assertRaises(ValueError, msg=bad):
                flows.url_port(bad)

    def test_only_a_refusal_unreachable_or_a_timeout_counts_as_closed(self):
        c = flows.classify_port_probe
        self.assertEqual(c(0, ""), "open")
        self.assertEqual(c(1, "bash: connect: Connection refused\nbash: /dev/tcp/h/1: Connection refused"), "closed")
        self.assertEqual(c(1, "bash: connect: Network is unreachable"), "closed")
        self.assertEqual(c(1, "bash: connect: No route to host"), "closed")
        self.assertEqual(c(124, ""), "closed")  # timeout(1)
        self.assertEqual(c(127, "sh: 1: timeout: not found"), "tool-missing")
        # Not evidence of a closed port: the name did not resolve, or something else went wrong.
        self.assertEqual(c(1, "bash: h: Name or service not known"), "unknown")
        self.assertEqual(c(2, ""), "unknown")
        self.assertEqual(c(1, "bash: connect: Permission denied"), "unknown")


class Ac8RestPort(unittest.TestCase):
    TOML = """
    [server]
    executor = "local"
    url = "%s"
    public_host = "198.51.100.10"
    [client_remote]
    executor = "local"
    """

    def run_check(self, probe, url="http://127.0.0.1:7477"):
        import ac08_remote_client

        seen = []

        def handler(argv, stdin):
            if argv[:2] == ["sh", "-c"] and "/dev/tcp" in argv[2]:
                seen.append(argv)
                return probe
            return preflight_ok(argv, stdin)

        ctx, _ = script_ctx(self, handler, self.TOML % url)
        res = ac08_remote_client.run(ctx)
        check = next(c for c in res.checks if c.name.startswith("from the remote network"))
        return check, seen

    def test_a_refused_connection_is_closed_and_the_port_comes_from_the_url(self):
        check, seen = self.run_check((1, "", "bash: connect: Connection refused"))
        self.assertEqual(check.status, core.PASS, check.reason)
        self.assertEqual(seen[0][-2:], ["198.51.100.10", "7477"])

    def test_the_default_port_of_the_scheme_is_used_when_the_url_has_none(self):
        _, seen = self.run_check((124, "", ""), url="https://p2pc.example.invalid")
        self.assertEqual(seen[0][-1], "443")

    def test_an_accepted_connection_fails(self):
        check, _ = self.run_check((0, "", ""))
        self.assertEqual(check.status, core.FAIL)
        self.assertIn("accepted", check.reason)

    def test_a_missing_tool_is_a_skip_with_a_reason_never_a_pass(self):
        check, _ = self.run_check((127, "", "sh: 1: timeout: not found"))
        self.assertEqual(check.status, core.SKIP)
        self.assertIn("not found", check.reason)

    def test_an_unexplained_failure_is_not_proof_of_a_closed_port(self):
        check, _ = self.run_check((1, "", "bash: h: Name or service not known"))
        self.assertEqual(check.status, core.FAIL)
        self.assertIn("could not tell", check.reason)

    def test_a_proxy_that_died_with_a_key_in_its_log_leaks_nothing(self):
        import ac08_remote_client

        def handler(argv, stdin):
            sub = p2pc_subcommand(argv)
            if argv[:1] == ["curl"]:
                return (0, json.dumps({"address": "p2pc_srv_ABC"}), "")
            if argv[:2] == ["sh", "-c"] and "kill -0" in argv[2]:
                return (1, "", "")
            if argv[:1] == ["cat"]:
                return (0, "e" * 400 + FAKE_KEY, "")
            return preflight_ok(argv, stdin) if sub is None else (0, "{}", "")

        ctx, _ = script_ctx(self, handler, self.TOML % "http://127.0.0.1:7477", binaries=["p2pc"], environ={})
        ctx.set_admin_key("admin-key-for-the-test-1234")
        res = ac08_remote_client.run(ctx)
        proxy = next(c for c in res.checks if c.name == "p2pc proxy listens on the client")
        self.assertEqual(proxy.status, core.FAIL)
        self.assertNotIn("qqqq", proxy.reason)
        self.assertNotIn("p2pc_sk_", proxy.reason)


class Ac12MissingVersusFailing(unittest.TestCase):
    def run_deny(self, result):
        import ac12_supply_chain as ac12

        ctx, _ = script_ctx(self, lambda argv, stdin: result if argv[:2] == ["cargo", "deny"] else (0, "", ""), '[server]\nexecutor = "local"\n')
        return ac12.run(ctx).checks[0]

    def test_a_real_deny_failure_is_a_fail_even_if_the_output_says_not_found(self):
        check = self.run_deny((1, "", "error[unmaintained]: package not found in the lockfile"))
        self.assertEqual(check.status, core.FAIL)

    def test_exit_127_or_a_clear_no_such_subcommand_is_a_missing_tool(self):
        self.assertEqual(self.run_deny((127, "", "sh: cargo-deny: not found")).status, core.SKIP)
        self.assertEqual(self.run_deny((101, "", "error: no such command: `deny`")).status, core.SKIP)
        self.assertEqual(self.run_deny((101, "", "error: no such subcommand: deny")).status, core.SKIP)

    def test_a_program_that_cannot_start_is_missing_only_when_it_does_not_exist(self):
        import ac12_supply_chain as ac12

        gone = core.Step("l", "harness", "c", None, error="cannot start gitleaks: No such file or directory")
        denied = core.Step("l", "harness", "c", None, error="cannot start gitleaks: Permission denied")
        self.assertTrue(ac12._tool_missing(gone))
        self.assertFalse(ac12._tool_missing(denied))
        self.assertFalse(ac12._tool_missing(core.Step("l", "harness", "c", 2, stderr="error: file not found: Cargo.lock")))

    def test_gitleaks_runs_with_the_repo_root_ignore_file(self):
        import ac12_supply_chain as ac12

        seen = []

        def handler(argv, stdin):
            if argv[:2] == ["gitleaks", "git"]:
                seen.append(argv)
                Path(argv[argv.index("--report-path") + 1]).write_text("[]")
            return (0, "0", "")

        ctx, _ = script_ctx(self, handler, '[server]\nexecutor = "local"\n')
        ac12.run(ctx)
        argv = seen[0]
        repo = str(ctx.repo_root)
        # .gitleaksignore and .gitleaks.toml are read from the repo root, whatever the harness's working directory is.
        self.assertEqual(argv[argv.index("--gitleaks-ignore-path") + 1], repo)
        self.assertEqual(argv[-1], repo)


class McpReplies(unittest.TestCase):
    def test_a_good_reply_has_no_problem(self):
        ok = {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "{}"}], "isError": False}}
        self.assertIsNone(flows.mcp_reply_problem(ok))
        self.assertIsNone(flows.mcp_reply_problem({"id": 1, "result": {"serverInfo": {}}}))  # isError absent

    def test_an_error_reply_a_missing_result_and_iserror_true_are_all_problems(self):
        err = {"jsonrpc": "2.0", "id": 3, "error": {"code": -32602, "message": "bad params"}}
        self.assertIn("JSON-RPC error", flows.mcp_reply_problem(err))
        self.assertIn("-32602", flows.mcp_reply_problem(err))
        self.assertIn("no result", flows.mcp_reply_problem({"jsonrpc": "2.0", "id": 3}))
        self.assertIn("no result", flows.mcp_reply_problem({"id": 3, "result": None}))
        tool_err = {"id": 3, "result": {"isError": True, "content": [{"type": "text", "text": "cap exceeded"}]}}
        self.assertIn("isError", flows.mcp_reply_problem(tool_err))
        self.assertIn("cap exceeded", flows.mcp_reply_problem(tool_err))

    def test_the_job_id_of_p2pc_run_is_the_job_id_member_of_the_structured_result(self):
        # crates/p2pc-cli/src/mcp/tools.rs `job_summary`: {"job_id", "status", "finished", "attempt", ...}. The id of an
        # untrusted log line that merely looks like one (job_...) in the text must not be taken for it.
        reply = {"id": 4, "result": {"isError": False, "structuredContent": {"job_id": "job_01REAL", "status": "queued"},
                                     "content": [{"type": "text", "text": "{\"job_id\": \"job_01REAL\"} job_01SPOOF"}]}}
        self.assertEqual(flows.mcp_job_ids(reply), ["job_01REAL"])
        # A server that sends only the text content is still read, by the pattern.
        self.assertEqual(flows.mcp_job_ids({"id": 4, "result": {"content": [{"type": "text", "text": "job_01ABC queued"}]}}), ["job_01ABC"])

    def test_the_problem_text_is_redacted(self):
        err = {"id": 3, "error": {"code": 1, "message": FAKE_KEY}}
        self.assertNotIn("p2pc_sk_", flows.mcp_reply_problem(err))


class Ac6HealAlwaysRuns(unittest.TestCase):
    TOML = """
    [server]
    executor = "local"
    admin_key_env = "TEST_ADMIN_KEY"
    [node_linux_gpu]
    executor = "local"
    partition_command = "PARTITION"
    heal_command = "HEAL"
    [node_wsl2_gpu]
    executor = "local"
    partition_command = "PARTITION"
    heal_command = "HEAL"
    [params]
    lease_ttl_s = 10
    """

    def simulate(self, partition=(0, "", ""), final_attempts=None, container_visible=True, podman_answer=None,
                 agent_stops=True, requeue_after_s=15, stopped_remains=False):
        """A world with a clock. ``agent_stops``: the cut agent stops its job when it is partitioned (SI-13), so the
        container is gone before the requeue; False: the container stays until the job ends BY ITSELF, ``sleep N`` seconds
        after it started (the containers are --rm). The server requeues ``requeue_after_s`` after the cut."""
        st = {"partitioned": False, "healed": False, "heals": 0, "running": False, "calls": [], "ps_argv": [],
              "started_at": None, "cut_at": None, "sleep_s": None}
        nodes = [
            {"id": "n1", "name": "n1", "state": "online", "inventory": {"platform": "linux", "gpus": [{"u": 1}]}},
            {"id": "n2", "name": "n2", "state": "online", "inventory": {"platform": "wsl2", "gpus": [{"u": 1}]}},
        ]

        def handler(argv, stdin):
            sub = p2pc_subcommand(argv)
            if argv[:3] == ["sh", "-c", "PARTITION"]:
                st["partitioned"] = True
                st["cut_at"] = st["ctx"].clock()
                return partition
            if argv[:3] == ["sh", "-c", "HEAL"]:
                st["healed"] = True
                st["heals"] += 1
                return (0, "", "")
            if argv[:2] == ["podman", "ps"]:
                if podman_answer is not None:
                    return podman_answer
                # The first node's container for attempt 1 exists while the job runs. It ends when the agent stops it (at
                # the cut, if the agent does what SI-13 says) or when the job ends by itself.
                ends_by_itself = st["started_at"] is not None and st["ctx"].clock() >= st["started_at"] + (st["sleep_s"] or 0)
                shown = container_visible and st["running"] and not ends_by_itself and not (agent_stops and st["partitioned"])
                # A container that was stopped but not removed is still listed by `ps -a`, and never by `ps`.
                leftover = stopped_remains and container_visible and st["running"] and agent_stops and st["partitioned"] and "-a" in argv
                st["ps_argv"].append(list(argv))
                return (0, "p2pc-lease-attempt1\n" if (shown or leftover) else "", "")
            if sub == "whoami":
                return (0, json.dumps({"key_id": "k", "scopes": ["admin"]}), "")
            if sub == "machines":
                return (0, json.dumps(nodes), "")
            if sub == "run":
                m = re.search(r"sleep (\d+);", " ".join(argv))
                st["sleep_s"] = int(m.group(1)) if m else None
                st["timeout"] = argv[argv.index("--timeout") + 1] if "--timeout" in argv else None
                return (0, json.dumps({"id": "job_1", "status": "queued"}), "")
            if sub == "status":
                if not st["partitioned"] or (not st["healed"] and st["ctx"].clock() - st["cut_at"] < requeue_after_s):
                    if not st["running"]:
                        st["running"], st["started_at"] = True, st["ctx"].clock()
                    job = {"id": "job_1", "status": "running", "node_id": "n1", "attempt": 1}
                elif not st["healed"]:
                    job = {"id": "job_1", "status": "running", "node_id": "n2", "attempt": 2}
                else:
                    job = {"id": "job_1", "status": "succeeded", "node_id": "n2", "attempt": 2}
                    if final_attempts is not None:
                        job["attempts"] = final_attempts
                return (0, json.dumps(job), "")
            if sub == "usage":
                return (125, "", "not implemented yet\n")
            return preflight_ok(argv, stdin)

        ctx, fake = script_ctx(self, handler, self.TOML, binaries=["p2pc"], environ={"TEST_ADMIN_KEY": FAKE_KEY})
        st["fake"] = fake
        st["ctx"] = ctx
        return ctx, st

    def test_a_container_the_harness_cannot_see_means_skip_and_the_network_is_never_cut(self):
        ctx, st = self.simulate(container_visible=False)
        res, by = self.checks(ctx)
        starts = by["the job starts on a node"]
        self.assertEqual(starts.status, core.SKIP)
        self.assertIn("cannot be proved", starts.reason)
        self.assertFalse(st["partitioned"], "the network must not be cut when 'the container is gone' cannot be proved")
        self.assertEqual(st["heals"], 0)
        self.assertNotEqual(res.status, core.PASS)
        self.assertNotIn(core.FAIL, [c.status for c in res.checks])

    def test_podman_that_cannot_be_run_is_a_skip_with_the_reason_never_an_empty_list(self):
        ctx, st = self.simulate(podman_answer=(125, "", "Error: permission denied: cannot connect to podman socket"))
        res, by = self.checks(ctx)
        first = by["two nodes and a way to cut one of them"]
        self.assertEqual(first.status, core.SKIP)
        self.assertIn("cannot list containers", first.reason)
        self.assertIn("permission denied", first.reason)
        self.assertEqual(res.status, core.SKIP)
        self.assertFalse(st["partitioned"])

    OLD = "the cut node stopped the old attempt before the requeue (SI-13)"

    def test_the_old_attempt_is_proved_by_its_own_container_name_and_that_name_must_go_before_the_requeue(self):
        ctx, st = self.simulate()
        res, by = self.checks(ctx)
        self.assertEqual(by["the job starts on a node"].evidence["old_container"], "p2pc-lease-attempt1")
        self.assertEqual(by[self.OLD].status, core.PASS, by[self.OLD].reason)
        self.assertEqual(by["the first node cannot report back: its old attempt stays gone after the heal"].status, core.PASS)

    def test_the_job_runs_longer_than_everything_the_harness_observes(self):
        import ac06_node_loss as ac6

        self.assertEqual(ac6.long_run_s(60), 60 + 90 + 120 + 60)
        ctx, st = self.simulate()
        self.checks(ctx)
        self.assertEqual(st["sleep_s"], ac6.long_run_s(10))  # the TOML says lease_ttl_s = 10
        self.assertGreater(st["sleep_s"], 10 + ac6.DETECT_MARGIN_S + ac6.OBSERVE_S)

    def test_si13_looks_only_at_running_containers_a_stopped_one_that_lingers_is_not_a_running_job(self):
        # T15a review P3: `podman ps -a` also lists stopped containers, so an agent that stopped its job (SI-13 holds) but
        # whose container had not been removed yet was reported as failing.
        ctx, st = self.simulate(stopped_remains=True)
        _, by = self.checks(ctx)
        self.assertEqual(by[self.OLD].status, core.PASS, by[self.OLD].reason)
        self.assertEqual(by["the first node cannot report back: its old attempt stays gone after the heal"].status, core.PASS)
        self.assertTrue(st["ps_argv"])
        self.assertTrue(all("-a" not in argv for argv in st["ps_argv"]), "AC-6 asked for stopped containers too")
        self.assertIn("p2pc.lease", " ".join(st["ps_argv"][0]))

    def test_the_job_timeout_follows_the_run_length_never_a_fixed_30_minutes(self):
        # T15a review P3: `--timeout 30m` with a run of lease_ttl_s + 270 s timed the job out whenever lease_ttl_s > ~1500.
        import ac06_node_loss as ac6

        for ttl in (10, 60, 1500, 3600):
            run = ac6.long_run_s(ttl)
            self.assertEqual(ac6.job_timeout_s(ttl), run + 600)
            self.assertLessEqual(ac6.job_timeout_s(ttl), 86_400)  # spec §7: timeout_s 1-86,400
        ctx, st = self.simulate()
        self.checks(ctx)
        self.assertEqual(st["timeout"], f"{ac6.job_timeout_s(10)}s")
        self.assertGreater(int(st["timeout"][:-1]), st["sleep_s"])

    def test_an_old_container_that_survives_until_the_requeue_is_a_failure(self):
        # The agent never stops its job: the container stays until the job ends by itself, which must be later than
        # anything observed (before this was fixed, `sleep 150` ended inside the window and the check passed anyway).
        ctx, st = self.simulate(agent_stops=False)
        res, by = self.checks(ctx)
        self.assertEqual(by[self.OLD].status, core.FAIL)
        self.assertIn("p2pc-lease-attempt1", by[self.OLD].reason)
        self.assertIn("before the server requeues it", by[self.OLD].reason)
        self.assertEqual(res.status, core.FAIL)
        self.assertEqual(st["heals"], 1)

    def test_the_slowest_allowed_requeue_still_finds_the_job_running_by_itself(self):
        # The server requeues at the very end of the wait (lease_ttl_s + 90): the unstopped container must still be there.
        import ac06_node_loss as ac6

        ctx, st = self.simulate(agent_stops=False, requeue_after_s=10 + ac6.DETECT_MARGIN_S - 3)
        _, by = self.checks(ctx)
        self.assertEqual(by[self.OLD].status, core.FAIL)

    def test_an_old_container_that_is_back_after_the_heal_is_a_failure(self):
        ctx, st = self.simulate()
        original = ctx.executor("server").handler

        def back(argv, stdin):
            if argv[:2] == ["podman", "ps"] and st["healed"]:
                return (0, "p2pc-lease-attempt1\n", "")
            return original(argv, stdin)

        ctx.executor("server").handler = back
        _, by = self.checks(ctx)
        self.assertEqual(by[self.OLD].status, core.PASS)
        late = by["the first node cannot report back: its old attempt stays gone after the heal"]
        self.assertEqual(late.status, core.FAIL)
        self.assertIn("p2pc-lease-attempt1", late.reason)

    def checks(self, ctx):
        import ac06_node_loss

        res = ac06_node_loss.run(ctx)
        return res, {c.name: c for c in res.checks}

    def test_the_happy_path_heals_once_and_never_passes_the_blocked_checks(self):
        ctx, st = self.simulate()
        res, by = self.checks(ctx)
        self.assertEqual(st["heals"], 1)
        self.assertEqual(by["cut the network of that node"].status, core.PASS)
        self.assertEqual(by["restore the network of the first node"].status, core.PASS)
        self.assertEqual(by["the job finishes once, on the other node"].status, core.PASS)
        self.assertNotEqual(res.status, core.PASS)  # the ledger and the attempt checks wait for T06 and T10

    def test_a_partition_command_that_times_out_still_gets_healed(self):
        ctx, st = self.simulate(partition=executors.ExecResult(None, timed_out=True))
        res, by = self.checks(ctx)
        self.assertEqual(by["cut the network of that node"].status, core.FAIL)
        self.assertTrue(st["healed"], "heal_command must run after a partition command that timed out")
        self.assertEqual(by["restore the network of the first node"].status, core.PASS)
        self.assertEqual(res.status, core.FAIL)

    def test_a_partition_command_that_half_failed_still_gets_healed(self):
        ctx, st = self.simulate(partition=(1, "", "nft: table created, rule failed"))
        _, by = self.checks(ctx)
        self.assertEqual(by["cut the network of that node"].status, core.FAIL)
        self.assertEqual(st["heals"], 1)

    def test_a_failing_heal_is_reported_loudly(self):
        ctx, st = self.simulate()
        original = ctx.executor("server").handler

        def bad_heal(argv, stdin):
            if argv[:3] == ["sh", "-c", "HEAL"]:
                return (1, "", "nft: no such table")
            return original(argv, stdin)

        ctx.executor("server").handler = bad_heal
        res, by = self.checks(ctx)
        self.assertEqual(by["restore the network of the first node"].status, core.FAIL)
        self.assertEqual(res.status, core.FAIL)

    def test_heal_runs_even_when_the_run_is_interrupted_after_the_partition(self):
        import ac06_node_loss

        ctx, st = self.simulate()
        original = ctx.executor("server").handler

        def interrupt(argv, stdin):
            if p2pc_subcommand(argv) == "status" and st["partitioned"]:
                raise KeyboardInterrupt
            return original(argv, stdin)

        ctx.executor("server").handler = interrupt
        with self.assertRaises(KeyboardInterrupt):
            ac06_node_loss.run(ctx)
        self.assertEqual(st["heals"], 1)

    def attempts_check(self, final_attempts):
        ctx, _ = self.simulate(final_attempts=final_attempts)
        _, by = self.checks(ctx)
        return by["attempt 1 ends lost and a late JobFinished is ignored"]

    def test_the_stale_report_check_is_blocked_until_the_server_reports_attempts(self):
        chk = self.attempts_check(None)
        self.assertEqual((chk.status, chk.unblocked_by), (core.BLOCKED, ["T06"]))

    @staticmethod
    def att(n, node, outcome, reason=None, started="2026-11-06T10:00:00Z", ended="2026-11-06T10:01:00Z"):
        return {"attempt": n, "node_id": node, "outcome": outcome, "reason": reason, "started_at": started, "ended_at": ended}

    def test_the_stale_report_check_becomes_real_when_attempts_are_reported(self):
        good = [self.att(1, "n1", "lost", "node_lost"), self.att(2, "n2", "succeeded")]
        self.assertEqual(self.attempts_check(good).status, core.PASS)
        late_report_accepted = [dict(good[0], outcome="succeeded"), good[1]]
        chk = self.attempts_check(late_report_accepted)
        self.assertEqual(chk.status, core.FAIL)
        self.assertIn("attempt 1", chk.reason)

    def test_the_attempts_of_the_spec_are_checked_field_by_field(self):
        f = flows.attempts_problems
        good = [self.att(1, "a", "lost", "node_lost"), self.att(2, "b", "succeeded")]
        self.assertEqual(f(good, "a", "b"), [])
        self.assertEqual(flows.ATTEMPT_FIELDS, ("attempt", "node_id", "outcome", "reason", "started_at", "ended_at"))
        # reason: a string or null, nothing more is asserted about it
        self.assertEqual(f([dict(good[0], reason=None), dict(good[1], reason="whatever_code")], "a", "b"), [])
        self.assertTrue(f([dict(good[0], reason=7), good[1]], "a", "b"))
        # a field missing, a field the spec does not have, a wrong type
        self.assertTrue(f([{k: v for k, v in good[0].items() if k != "reason"}, good[1]], "a", "b"))
        # a field beyond the six is evidence, not a failure
        self.assertEqual(f([dict(good[0], epoch=3), good[1]], "a", "b"), [])
        self.assertEqual(flows.attempt_extra_fields([dict(good[0], epoch=3), dict(good[1], lease="x")]), ["epoch", "lease"])
        self.assertEqual(flows.attempt_extra_fields(good), [])
        self.assertTrue(f([dict(good[0], started_at=5), good[1]], "a", "b"))
        self.assertTrue(f([dict(good[0], attempt="1"), good[1]], "a", "b"))
        # `running` has no end, anything else has one
        running = self.att(2, "b", "running", ended=None)
        self.assertEqual(flows.attempt_shape_problems([good[0], running]), [])
        self.assertTrue(flows.attempt_shape_problems([good[0], dict(running, ended_at="2026-11-06T10:02:00Z")]))
        self.assertTrue(flows.attempt_shape_problems([good[0], dict(good[1], ended_at=None)]))
        # oldest first
        self.assertTrue(f(good[::-1], "a", "b"))

    def test_started_at_is_null_until_jobstarted_spec_7_amended_2026_11_06(self):
        # An attempt accepted and then lost during the image pull never started: started_at is null, and that is valid.
        pulling = self.att(1, "a", "lost", "node_lost", started=None)
        self.assertEqual(flows.attempt_shape_problems([pulling]), [])
        self.assertEqual(flows.attempt_shape_problems([self.att(2, "b", "running", started=None, ended=None)]), [])
        self.assertEqual(flows.attempts_problems([pulling, self.att(2, "b", "succeeded")], "a", "b"), [])
        # ... but a string that is not a timestamp is not, and an attempt that succeeded must have started.
        self.assertTrue(flows.attempt_shape_problems([self.att(1, "a", "lost", started="")]))
        problems = flows.attempts_problems([pulling, self.att(2, "b", "succeeded", started=None)], "a", "b")
        self.assertTrue(any("started_at" in p for p in problems), problems)

    def test_the_outcomes_are_the_job_state_words_of_the_spec(self):
        self.assertEqual(flows.ATTEMPT_OUTCOMES, ("running", "succeeded", "failed", "timed_out", "cancelled", "lost"))
        for word in ("running", "succeeded", "failed", "timed_out", "cancelled", "lost"):
            ended = None if word == "running" else "2026-11-06T10:01:00Z"
            self.assertEqual(flows.attempt_shape_problems([self.att(1, "a", word, ended=ended)]), [], word)
        for word in ("exited", "fenced", "error", ""):
            self.assertTrue(flows.attempt_shape_problems([self.att(1, "a", word)]), word)

    def test_attempts_problems(self):
        f = flows.attempts_problems
        good = [self.att(1, "a", "lost"), self.att(2, "b", "succeeded")]
        self.assertEqual(f(good, "a", "b"), [])
        self.assertTrue(f(good[:1], "a", "b"))  # attempt 2 missing
        self.assertTrue(f(good + [self.att(3, "a", "succeeded")], "a", "b"))  # a third row
        self.assertTrue(f([dict(good[0], node_id="b"), good[1]], "a", "b"))  # attempt 1 on the wrong node
        self.assertTrue(f([dict(good[0], outcome="succeeded"), good[1]], "a", "b"))  # the cut node's late report was accepted
        self.assertTrue(f([dict(good[0], outcome="failed"), good[1]], "a", "b"))
        self.assertTrue(f([dict(good[0], outcome="cancelled"), good[1]], "a", "b"))  # only `lost` is attempt 1's end
        self.assertTrue(f([dict(good[0], outcome="fenced"), good[1]], "a", "b"))  # not a spec word
        self.assertTrue(f([good[0], dict(good[1], outcome="lost")], "a", "b"))  # attempt 2 did not finish
        self.assertTrue(f([good[0], dict(good[1], outcome="exited")], "a", "b"))  # not a spec word
        self.assertTrue(f([good[0], dict(good[1], outcome="failed")], "a", "b"))
        self.assertTrue(f("nope", "a", "b"))
        self.assertTrue(f([], "a", "b"))


def harness_handler(argv, stdin):
    """The local machine (cargo, gitleaks, ...), scripted: every explicit test filter matches something, the si<N>_
    convention ones match nothing, the optional SBOM tool is not installed."""
    if argv[:2] == ["sh", "-c"] and "--list" in argv[2]:
        today = Ac11FromTheTestList("test_the_real_listing_format_is_parsed")
        return (0, "" if "--ignored" in argv else Ac11FromTheTestList.listing(today.today()), "")
    if argv[:2] == ["cargo", "test"]:
        names = [n for n in argv[argv.index("--exact") + 1:] if not n.startswith("--")] if "--exact" in argv else []
        return (0, f"test result: ok. {len(names)} passed; 0 failed; 0 ignored\n", "")
    if argv[:2] == ["cargo", "cyclonedx"]:
        return (127, "", "sh: cargo-cyclonedx: not found")
    if argv[:2] == ["gitleaks", "git"]:
        Path(argv[argv.index("--report-path") + 1]).write_text("[]")
    return (0, "0", "")


class EveryCriterionAgainstTheExample(unittest.TestCase):
    """machines.example.toml has every role disabled: no criterion may reach a machine, and the run must not fail."""

    def setUp(self):
        self.config = machines.load_machines(HERE / "machines.example.toml")
        self.assertTrue(all(not r.enabled for r in self.config.roles.values()))

    def scripted(self):
        fake = FakeExecutor(harness_handler)
        clock = FakeClock()
        ctx = context.Context(
            self.config, repo_root=HERE.parents[1], environ={}, clock=clock.now, sleep=clock.sleep,
            executor_factory=refusing_factory(fake),
        )
        return ctx, fake

    def test_no_criterion_reaches_a_disabled_machine_and_none_fails(self):
        results = []
        for mod in criteria.load_all():
            ctx, fake = self.scripted()
            res = mod.run(ctx)  # a DisabledRoleUsed (BaseException) would propagate and fail this test
            self.assertEqual(fake.violations, [], mod.ID)
            machine_calls = [c for c in fake.calls if c[0][:1] != ["cargo"] and c[0][:1] != ["gitleaks"]]
            if mod.ROLES:
                self.assertEqual(machine_calls, [], f"{mod.ID} sent commands although every role is disabled")
            self.assertNotEqual(res.status, core.FAIL, (mod.ID, [(c.name, c.status, c.reason) for c in res.checks]))
            self.assertIn(res.status, (core.BLOCKED, core.SKIP), mod.ID)  # nothing can PASS from the example
            results.append(res)
        self.assertEqual(core.exit_code(results, strict=False), 0)
        self.assertEqual(core.exit_code(results, strict=True), 1)

    def test_the_runner_exits_0_and_writes_a_report_without_touching_a_machine(self):
        import contextlib
        import functools
        import io
        from unittest import mock

        fake = FakeExecutor(harness_handler)
        patched = functools.partial(context.Context, executor_factory=refusing_factory(fake))
        mods = [m for m in criteria.load_all()]
        with tempfile.TemporaryDirectory() as d, mock.patch.object(runner.context, "Context", patched):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = runner.main(["--machines", str(HERE / "machines.example.toml"), "--report-dir", d], loader=lambda: mods)
            self.assertEqual(code, 0, err.getvalue())
            data = json.loads((next(Path(d).iterdir()) / "report.json").read_text())
        self.assertEqual(len(data["criteria"]), 12)
        self.assertEqual(fake.violations, [])
        self.assertEqual({c["status"] for c in data["criteria"]} - {"blocked", "skip"}, set())
        self.assertFalse(data["summary"]["accepted"])

    def test_the_scripted_machines_refuse_a_disabled_role(self):
        ctx, fake = make_ctx(preflight_ok)
        with self.assertRaises(DisabledRoleUsed):
            ctx.exec("node_wsl2_gpu", ["true"])  # ROLES_TOML has this role disabled
        self.assertEqual(fake.violations, ["node_wsl2_gpu"])

    def test_ac5_makes_its_working_directory_only_after_the_role_check(self):
        import ac05_inputs_outputs

        ctx, fake = make_ctx(preflight_ok, toml='[server]\nexecutor = "local"\nenabled = false\n')
        res = ac05_inputs_outputs.run(ctx)
        self.assertEqual(res.checks[0].status, core.SKIP)
        self.assertEqual((fake.violations, fake.calls), ([], []))


class Ac8ServerRoute(unittest.TestCase):
    TOML = """
    [server]
    executor = "local"
    [client_remote]
    executor = "local"
    """

    def first_check(self, openapi_paths):
        import ac08_remote_client

        def handler(argv, stdin):
            if argv[:1] == ["curl"]:
                if b"/v1/openapi.json" in (stdin or b""):
                    return (0, json.dumps({"paths": {p: {"get": {}} for p in openapi_paths}}), "")
                return (0, json.dumps({"type": "about:blank", "status": 404, "code": "not_found"}), "")
            return preflight_ok(argv, stdin)

        ctx, _ = script_ctx(self, handler, self.TOML, binaries=["p2pc"])
        ctx.set_admin_key("admin-key-for-the-test-1234")
        return ac08_remote_client.run(ctx).checks[0]

    def test_a_404_with_the_route_absent_from_openapi_is_blocked_by_its_owner(self):
        chk = self.first_check(["/v1/jobs"])
        self.assertEqual((chk.status, chk.unblocked_by), (core.BLOCKED, [context.OWNERS["route GET /v1/server"]]))

    def test_a_404_although_the_route_exists_is_a_failure(self):
        chk = self.first_check(["/v1/jobs", "/v1/server"])
        self.assertEqual(chk.status, core.FAIL)
        self.assertIn("not_found", chk.reason)  # the same error path as every p2pc call: code and status, no special case


class Ac1JoinToken(unittest.TestCase):
    TOKEN = "p2pc_join_" + "MFRGGZDFMZTWQ2LK" * 3
    TOML = """
    [server]
    executor = "local"
    admin_key_env = "TEST_ADMIN_KEY"
    [node_linux_gpu]
    executor = "local"
    """

    def simulate(self, join_answer=(0, "joined", "")):
        st = {"joined": False}

        def handler(argv, stdin):
            sub = p2pc_subcommand(argv)
            if sub == "whoami":
                return (0, json.dumps({"key_id": "k", "scopes": ["admin"]}), "")
            if sub == "login":
                return (0, "{}", "")
            if sub == "join-token" and "list" in argv:
                consumed = "node_1" if st["joined"] else None
                return (0, json.dumps([{"id": "jtk_1", "created_by_key_id": "k", "created_at": "2026-11-05T12:00:00Z",
                                        "expires_at": "2026-11-05T12:15:00Z", "consumed_by_node_id": consumed}]), "")
            if sub == "join-token":
                st["token_args"] = list(argv)
                return (0, json.dumps({"id": "jtk_1", "join_token": self.TOKEN, "expires_at": "2026-11-05T12:15:00Z"}), "")
            if sub == "machines":
                nodes = []
                if st["joined"]:
                    nodes = [{"id": "node_1", "state": "online", "inventory": full_inventory("linux", gpus=1)}]
                return (0, json.dumps(nodes), "")
            if argv[-2:-1] == ["join"] or "join" in argv[-3:]:
                st["joined"] = True
                return join_answer
            return preflight_ok(argv, stdin)

        ctx, fake = script_ctx(self, handler, self.TOML, binaries=["p2pc", "p2pc_agent"], environ={"TEST_ADMIN_KEY": FAKE_KEY})
        fake.st = st
        return ctx, fake

    def test_the_token_goes_to_the_agent_on_stdin_and_never_in_an_argument(self):
        import ac01_install

        ctx, fake = self.simulate()
        res = ac01_install.run(ctx)
        join_checks = [c for c in res.checks if c.name == "node_linux_gpu: join with one command, within 2 minutes"]
        self.assertEqual(join_checks[0].status, core.PASS, join_checks[0].reason)
        self.assertEqual(join_checks[0].evidence["token_expires_at"], "2026-11-05T12:15:00Z")
        # `--expires` is passed, and the server's list says the node consumed the token (single use).
        self.assertEqual(fake.st["token_args"][fake.st["token_args"].index("--expires") + 1], "15m")
        joins = [(a, s) for a, s in fake.calls if a[-2:] == ["join", "-"]]
        self.assertEqual(len(joins), 1)
        self.assertEqual(joins[0][0][-3:], [ctx.bin("node_linux_gpu", "p2pc_agent"), "join", "-"])
        self.assertEqual(joins[0][1], (self.TOKEN + "\n").encode())
        for argv, _stdin in fake.calls:
            self.assertNotIn(self.TOKEN, " ".join(argv))
        self.assertNotIn("p2pc_join_", json.dumps(res.to_dict()))  # and never in the report

    def test_an_agent_that_does_not_know_the_stdin_form_yet_does_not_pass(self):
        import ac01_install

        ctx, _ = self.simulate(join_answer=(2, "", "error: invalid join token"))
        res = ac01_install.run(ctx)
        chk = next(c for c in res.checks if c.name == "node_linux_gpu: join with one command, within 2 minutes")
        self.assertEqual(chk.status, core.FAIL)
        self.assertNotEqual(res.status, core.PASS)

    def test_a_machine_that_is_already_enrolled_is_a_skip_that_says_how_to_start_over(self):
        import ac01_install

        ctx, _ = self.simulate(join_answer=(3, "", "error: this machine is already enrolled"))
        chk = next(c for c in ac01_install.run(ctx).checks if c.name == "node_linux_gpu: join with one command, within 2 minutes")
        self.assertEqual(chk.status, core.SKIP)
        self.assertIn("machines rm NAME --yes", chk.reason)

    def test_the_node_installer_is_blocked_by_t14b2_until_it_is_in_the_checkout_then_a_skip_without_a_command(self):
        import ac01_install

        name = "node_linux_gpu: the node installer, one command"
        ctx, _ = self.simulate()
        with tempfile.TemporaryDirectory() as bare:  # a checkout with no installers at all
            ctx.repo_root = Path(bare)
            chk = next(c for c in ac01_install.run(ctx).checks if c.name == name)
        self.assertEqual((chk.status, chk.unblocked_by), (core.BLOCKED, ["T14b2"]))
        with tempfile.TemporaryDirectory() as repo:
            (Path(repo) / "deploy" / "linux").mkdir(parents=True)
            (Path(repo) / "deploy" / "linux" / "install-node.sh").write_text("#!/bin/sh\n")
            ctx, _ = self.simulate()
            ctx.repo_root = Path(repo)
            chk = next(c for c in ac01_install.run(ctx).checks if c.name == name)
        self.assertEqual((chk.status, chk.unblocked_by), (core.SKIP, []))
        self.assertIn("install_command", chk.reason)

    def test_a_node_without_a_gpu_is_the_role_node_linux_and_is_told_apart_by_its_inventory(self):
        nodes = [{"id": "gpu", "state": "online", "inventory": full_inventory("linux", gpus=1)},
                 {"id": "cpu", "state": "online", "inventory": full_inventory("linux", gpus=0)},
                 {"id": "win", "state": "online", "inventory": full_inventory("wsl2", gpus=1)}]
        toml = Ac1JoinToken.TOML + '[node_linux]\nexecutor = "local"\n[node_wsl2_gpu]\nexecutor = "local"\n'
        ctx, _ = script_ctx(self, preflight_ok, toml, binaries=[], environ={"TEST_ADMIN_KEY": FAKE_KEY})
        self.assertEqual(flows.node_id_for(ctx, "node_linux_gpu", nodes), "gpu")
        self.assertEqual(flows.node_id_for(ctx, "node_linux", nodes), "cpu")
        self.assertEqual(flows.node_id_for(ctx, "node_wsl2_gpu", nodes), "win")


class Ac1Installers(unittest.TestCase):
    """T14b2 landed: AC-1 runs the node installers of deploy/ (`install-node.sh` on Linux, `install.ps1` on the Windows host)
    with the join token on stdin, and finds the node by the token it consumed."""

    TOKEN = Ac1JoinToken.TOKEN
    TOML = """
    [server]
    executor = "local"
    admin_key_env = "TEST_ADMIN_KEY"
    [node_linux]
    executor = "local"
    install_command = "sudo sh /dist/install-node.sh --from /dist"
    [node_wsl2_gpu]
    executor = "wsl_over_ssh"
    host = "win-box"
    distro = "p2pc-node"
    image_install_command = "& 'C:\\\\dist\\\\install.ps1' -Tar 'C:\\\\dist\\\\p2pc-node.tar.gz'"
    install_command = "& 'C:\\\\dist\\\\install.ps1' -Join"
    """

    def simulate(self, linux=(0, "Joined: n-linux on srv\n", ""), windows=(0, "Joined: n-win on srv\n", ""), consumes=True,
                 run_state="running", existing=()):
        st = {"consumed": {}, "tokens": 0, "agent_calls": []}
        roles = {}  # token id -> (node id, platform, gpus)

        def installed(token_id, node, platform, gpus):
            if consumes:
                st["consumed"][token_id] = node
                roles[node] = (platform, gpus)

        def handler(argv, stdin):
            sub = p2pc_subcommand(argv)
            if argv[:2] == ["<powershell>"] or argv[:1] == ["<powershell>"]:
                script = argv[1]
                if "p2pc-host-ok" in script:  # the preflight of the Windows host
                    return (0, "p2pc-host-ok\n", "")
                if "wsl.exe" in script and "--exec" in script:  # does the distro exist?
                    return (0, "", "")
                st.setdefault("host_scripts", []).append((script, stdin))
                if "-Join" in script:
                    if windows[0] == 0:
                        installed(f"jtk_{st['tokens']}", "node_win", "wsl2", 1)
                    return windows
                return (0, "imported\n", "")
            if argv[:2] == ["sh", "-c"] and "install-node.sh" in argv[2]:
                st["linux_stdin"] = stdin
                if linux[0] == 0:
                    installed(f"jtk_{st['tokens']}", "node_linux", "linux", 0)
                return linux
            if argv[:1] == ["cat"] and argv[-1] == "/var/lib/p2pc/node-run.status":
                return (0, f"state={run_state}\ntime=2026-11-06T10:00:00Z\n", "")
            if any(a.endswith("/p2pc-agent") for a in argv):
                st["agent_calls"].append(argv)
                return (0, "", "")
            if sub == "whoami":
                return (0, json.dumps({"key_id": "k", "scopes": ["admin"]}), "")
            if sub == "join-token" and "list" in argv:
                rows = [{"id": f"jtk_{i}", "created_by_key_id": "k", "created_at": "2026-11-05T12:00:00Z",
                         "expires_at": "2026-11-05T12:15:00Z", "consumed_by_node_id": st["consumed"].get(f"jtk_{i}")}
                        for i in range(1, st["tokens"] + 1)]
                return (0, json.dumps(rows), "")
            if sub == "join-token":
                st["tokens"] += 1
                st["token_args"] = list(argv)
                return (0, json.dumps({"id": f"jtk_{st['tokens']}", "join_token": self.TOKEN, "expires_at": "2026-11-05T12:15:00Z"}), "")
            if sub == "machines":
                nodes = [{"id": n, "state": "online", "inventory": full_inventory(plat, gpus=g)} for n, (plat, g) in roles.items()]
                nodes += [{"id": n, "state": "online", "inventory": full_inventory("linux", gpus=0)} for n in existing]
                return (0, json.dumps(nodes), "")
            return preflight_ok(argv, stdin)

        ctx, fake = script_ctx(self, handler, self.TOML, binaries=["p2pc", "p2pc_agent"], environ={"TEST_ADMIN_KEY": FAKE_KEY})
        fake.st = st
        return ctx, fake

    def run_ac1(self, **kw):
        import ac01_install

        ctx, fake = self.simulate(**kw)
        res = ac01_install.run(ctx)
        return {c.name: c for c in res.checks}, fake, ctx

    LINUX_INSTALL = "node_linux: the node installer, one command"
    LINUX_JOIN = "node_linux: join with one command, within 2 minutes"
    WIN_IMAGE = "node_wsl2_gpu: the node image (install.ps1 -Tar)"
    WIN_INSTALL = "node_wsl2_gpu: the node installer, one command"
    WIN_JOIN = "node_wsl2_gpu: join with one command, within 2 minutes"

    def test_linux_the_installer_gets_the_token_on_stdin_and_the_node_is_found_by_the_token_it_consumed(self):
        by, fake, ctx = self.run_ac1()
        self.assertEqual(by[self.LINUX_INSTALL].status, core.PASS, by[self.LINUX_INSTALL].reason)
        self.assertEqual(by[self.LINUX_JOIN].status, core.PASS, by[self.LINUX_JOIN].reason)
        self.assertEqual(fake.st["linux_stdin"], (self.TOKEN + "\n").encode())
        self.assertEqual(by[self.LINUX_INSTALL].evidence["installer_said"], "Joined: n-linux on srv")
        self.assertEqual(ctx.state["node_ids"]["node_linux"], "node_linux")
        self.assertIn("join_s", by[self.LINUX_INSTALL].timings)
        # The installer started the agent (the unit): the harness neither copied an agent nor ran one.
        self.assertEqual(fake.st["agent_calls"], [])
        for argv, _ in fake.calls:
            self.assertNotIn(self.TOKEN, " ".join(argv))

    def test_windows_install_ps1_runs_on_the_host_with_the_token_in_the_pipeline_and_node_run_says_running(self):
        by, fake, ctx = self.run_ac1()
        self.assertEqual(by[self.WIN_IMAGE].status, core.PASS, by[self.WIN_IMAGE].reason)
        self.assertEqual(by[self.WIN_INSTALL].status, core.PASS, by[self.WIN_INSTALL].reason)
        self.assertEqual(by[self.WIN_JOIN].status, core.PASS, by[self.WIN_JOIN].reason)
        self.assertEqual(by[self.WIN_JOIN].evidence["node_run_state"], "running")
        (image, image_stdin), (join, join_stdin) = fake.st["host_scripts"]
        self.assertIn("-Tar", image)
        self.assertIsNone(image_stdin)  # no token for the image
        self.assertIn("-Join", join)
        self.assertEqual(join_stdin, (self.TOKEN + "\n").encode())
        self.assertNotIn(self.TOKEN, join)  # never in the script text (the host's command line)
        self.assertEqual(ctx.state["node_ids"]["node_wsl2_gpu"], "node_win")

    def test_a_node_the_supervisor_says_is_not_running_fails_the_windows_join(self):
        by, _, _ = self.run_ac1(run_state="stopped")
        self.assertEqual(by[self.WIN_JOIN].status, core.FAIL)
        self.assertIn("state=stopped", by[self.WIN_JOIN].reason)

    def test_the_distro_that_already_exists_is_a_skip_not_a_failure_of_the_run(self):
        # `install.ps1 -Tar` exits 16 on a second run: "the p2pc-node distro already exists (use -Upgrade)".
        import ac01_install

        ctx, fake = self.simulate()
        original = fake.handler
        fake.handler = lambda argv, stdin: (16, "", "the p2pc-node distro already exists\n") if argv[0] == "<powershell>" and "-Tar" in argv[1] else original(argv, stdin)
        by = {c.name: c for c in ac01_install.run(ctx).checks}
        self.assertEqual(by[self.WIN_IMAGE].status, core.SKIP)
        self.assertIn("distro already installed", by[self.WIN_IMAGE].reason)
        self.assertEqual(by[self.WIN_JOIN].status, core.PASS, by[self.WIN_JOIN].reason)  # the rest of the node goes on
        ctx, fake = self.simulate()
        original = fake.handler
        fake.handler = lambda argv, stdin: (18, "", "mismatch\n") if argv[0] == "<powershell>" and "-Tar" in argv[1] else original(argv, stdin)
        by = {c.name: c for c in ac01_install.run(ctx).checks}
        self.assertEqual(by[self.WIN_IMAGE].status, core.FAIL)  # any other exit stays a failure
        self.assertIn("SHA-256 mismatch", by[self.WIN_IMAGE].reason)

    def test_the_image_install_is_a_skip_without_its_command(self):
        import ac01_install

        ctx, fake = self.simulate()
        ctx.machines.roles["node_wsl2_gpu"].extra.pop("image_install_command")
        by = {c.name: c for c in ac01_install.run(ctx).checks}
        self.assertEqual(by[self.WIN_IMAGE].status, core.SKIP)
        self.assertIn("image_install_command", by[self.WIN_IMAGE].reason)

    def test_a_reenrollment_keeps_the_node_id_so_the_node_is_found_by_its_token_not_by_being_new(self):
        # `--force` / `-Force` enrolls the same node again (spec 5): the node is already in `p2pc machines` before the join.
        by, _, ctx = self.run_ac1(existing=("node_linux",))
        self.assertEqual(by[self.LINUX_JOIN].status, core.PASS, by[self.LINUX_JOIN].reason)

    def test_an_installer_that_exits_non_zero_fails_with_where_to_look_and_no_fallback_join_hides_it(self):
        by, fake, _ = self.run_ac1(linux=(1, "", "error: cannot install\n"))
        self.assertEqual(by[self.LINUX_INSTALL].status, core.FAIL)
        self.assertIn("/var/log/p2pc-node-install.log", by[self.LINUX_INSTALL].reason)
        self.assertEqual(by[self.LINUX_JOIN].status, core.SKIP)  # depends on the installer; the harness does not join instead
        self.assertEqual(fake.st["agent_calls"], [])

    def test_the_windows_exit_codes_of_install_ps1_are_explained(self):
        by, _, _ = self.run_ac1(windows=(34, "", "already enrolled\n"))
        self.assertEqual(by[self.WIN_INSTALL].status, core.FAIL)
        self.assertIn("exited 34", by[self.WIN_INSTALL].reason)
        self.assertIn("-Force", by[self.WIN_INSTALL].reason)

    def test_an_already_enrolled_node_without_force_fails_the_install_step_at_once(self):
        # install-node.sh without --force on an enrolled node says so, still prints `Joined:` and exits 0; the token stays unused.
        said = ("    already enrolled yes (node n1) (rerun with --force to re-enroll this machine, the same node)\n"
                "Joined: n1 on srv\n")
        by, fake, _ = self.run_ac1(linux=(0, said, ""), consumes=False)
        self.assertEqual(by[self.LINUX_INSTALL].status, core.FAIL)
        self.assertIn("already enrolled", by[self.LINUX_INSTALL].reason)
        self.assertIn("--force", by[self.LINUX_INSTALL].reason)
        self.assertIn("machines rm", by[self.LINUX_INSTALL].reason)
        self.assertEqual(by[self.LINUX_JOIN].status, core.SKIP)  # not after a 90 s wait for a token nobody uses
        windows = ("The node is already enrolled yes (node n2). To re-enroll this machine (the same node):   "
                   ".\\install.ps1 -Join -Force\nJoined: n2 on srv\n")
        by, _, _ = self.run_ac1(windows=(0, windows, ""), consumes=False)
        self.assertEqual(by[self.WIN_INSTALL].status, core.FAIL)
        self.assertIn("-Force", by[self.WIN_INSTALL].reason)

    def test_a_forced_reenrollment_that_says_it_is_re_enrolling_is_not_refused(self):
        said = "    already enrolled; --force: re-enrolling this machine (the same node)\nJoined: n1 on srv\n"
        by, _, _ = self.run_ac1(linux=(0, said, ""))
        self.assertEqual(by[self.LINUX_INSTALL].status, core.PASS, by[self.LINUX_INSTALL].reason)

    def test_an_installer_that_exits_zero_without_saying_joined_does_not_pass(self):
        by, _, _ = self.run_ac1(linux=(0, "done\n", ""))
        self.assertEqual(by[self.LINUX_INSTALL].status, core.FAIL)
        self.assertIn("Joined:", by[self.LINUX_INSTALL].reason)

    def test_a_token_nobody_consumed_says_the_machine_may_be_enrolled_and_how_to_force_it(self):
        by, _, _ = self.run_ac1(consumes=False)
        self.assertEqual(by[self.LINUX_JOIN].status, core.FAIL)
        self.assertIn("--force", by[self.LINUX_JOIN].reason)
        self.assertIn("machines rm", by[self.LINUX_JOIN].reason)

    def test_an_installer_slower_than_two_minutes_fails(self):
        import ac01_install

        ctx, fake = self.simulate()
        fake_run = fake.run

        def run(argv, **kw):
            out = fake_run(argv, **kw)
            if argv[:2] == ["sh", "-c"] and "install-node.sh" in argv[2]:
                out.duration_s = ac01_install.JOIN_BUDGET_S + 5
            return out

        fake.run = run
        by = {c.name: c for c in ac01_install.run(ctx).checks}
        self.assertEqual(by[self.LINUX_INSTALL].status, core.FAIL)
        self.assertIn("over 120 s", by[self.LINUX_INSTALL].reason)


class Ac7ContainerProof(unittest.TestCase):
    TOML = """
    [server]
    executor = "local"
    admin_key_env = "TEST_ADMIN_KEY"
    [node_linux_gpu]
    executor = "local"
    """

    def simulate(self, container_visible=True, removed_on_cancel=True, podman_answer=None, timeout_job=True):
        st = {"phase": "idle", "cancelled": False, "listed": 0, "exit124": False}
        node = {"id": "n1", "name": "n1", "state": "online", "inventory": {"platform": "linux", "gpus": [{"u": 1}]}}

        def handler(argv, stdin):
            sub = p2pc_subcommand(argv)
            if argv[:2] == ["podman", "ps"]:
                st["listed"] += 1
                if podman_answer is not None:
                    return podman_answer
                alive = container_visible and st["phase"] == "running" or (not removed_on_cancel and st["phase"] == "ended")
                return (0, "p2pc-lease-7\n" if alive else "", "")
            if sub == "whoami":
                return (0, json.dumps({"key_id": "k", "scopes": ["admin"]}), "")
            if sub == "machines":
                return (0, json.dumps([node]), "")
            if argv[:1] == ["cat"]:
                return (0, {"exit": "130\n", "err": "job_9\n\ndetached: job job_9 keeps running. To follow it again or to stop it:\n  p2pc logs --follow job_9\n  p2pc cancel job_9\n"}[argv[-1].rsplit(".", 1)[1]], "")
            if sub == "run" and "acc7-run-130" in argv:  # the exit-code checks of spec §7 (their own job, not job_7)
                job = {"id": "job_130", "status": "cancelled"}
                if "--detach" in argv:
                    return (0, json.dumps(job | {"status": "queued"}), "")
                return (130, json.dumps(job) + "\n", "")
            if sub == "cancel" and argv[-1] in ("job_130", "job_9"):
                st["cancelled_130"] = st.get("cancelled_130") or argv[-1] == "job_130"
                st.setdefault("also_cancelled", []).append(argv[-1])
                return (0, "{}", "")
            if sub == "status" and argv[-1] in ("job_130", "job_9"):
                if argv[-1] == "job_9":
                    return (0, json.dumps({"id": "job_9", "status": "running", "node_id": "n1"}), "")
                return (0, json.dumps({"id": "job_130", "status": "cancelled" if st.get("cancelled_130") else "running", "node_id": "n1"}), "")
            if sub == "run" and "--detach" in argv:
                st["phase"] = "submitted"
                st["cancelled"] = False
                return (0, json.dumps({"id": "job_7", "status": "queued"}), "")
            if sub == "run":  # foreground: the exit code is the job's
                return (124, json.dumps({"id": "job_8", "status": "timed_out"}), "")
            if sub == "cancel":
                st["cancelled"] = True
                st["phase"] = "ended"
                return (0, "{}", "")
            if sub == "status":
                if st["phase"] == "submitted":
                    st["phase"] = "running"
                    return (0, json.dumps({"id": "job_7", "status": "running", "node_id": "n1"}), "")
                if st["phase"] == "running" and not st["cancelled"]:
                    # the timeout flow: the job ends by itself on the next look
                    st["phase"] = "ended"
                    return (0, json.dumps({"id": "job_7", "status": "timed_out", "node_id": "n1",
                                           "started_at": "2026-11-05T12:00:00Z", "finished_at": "2026-11-05T12:00:21Z"}), "")
                done = "cancelled" if st["cancelled"] else "timed_out"
                return (0, json.dumps({"id": "job_7", "status": done, "node_id": "n1",
                                       "started_at": "2026-11-05T12:00:00Z", "finished_at": "2026-11-05T12:00:21Z"}), "")
            return preflight_ok(argv, stdin)

        ctx, _ = script_ctx(self, handler, self.TOML, binaries=["p2pc"], environ={"TEST_ADMIN_KEY": FAKE_KEY})
        return ctx, st

    def run_ac7(self, **kw):
        import ac07_cancel_timeout

        ctx, st = self.simulate(**kw)
        res = ac07_cancel_timeout.run(ctx)
        return res, {c.name: c for c in res.checks}, st

    CANCEL = "cancel: a running job stops within 15 s and its container is gone"
    TIMEOUT = "timeout: the job ends as timed_out within 15 s of its limit and its container is gone"

    def test_cancel_proves_its_own_container_before_and_after(self):
        res, by, st = self.run_ac7()
        self.assertEqual(by[self.CANCEL].status, core.PASS, by[self.CANCEL].reason)
        self.assertEqual(by[self.CANCEL].evidence["container"], "p2pc-lease-7")

    def test_a_container_the_harness_cannot_see_makes_cancel_and_timeout_skip_never_pass(self):
        res, by, st = self.run_ac7(container_visible=False)
        self.assertEqual(by[self.CANCEL].status, core.SKIP)
        self.assertIn("cannot be proved", by[self.CANCEL].reason)
        self.assertEqual(by[self.TIMEOUT].status, core.SKIP)
        self.assertNotEqual(res.status, core.PASS)
        self.assertFalse(st["cancelled"], "nothing is cancelled when the proof of the container is missing")

    def test_podman_that_fails_is_a_skip_with_the_reason(self):
        res, by, _ = self.run_ac7(podman_answer=(125, "", "Error: cannot connect to Podman socket"))
        self.assertEqual(by["environment ready"].status, core.PASS)
        self.assertEqual(by[self.CANCEL].status, core.SKIP)
        self.assertIn("cannot connect to Podman socket", by[self.CANCEL].reason)

    def test_a_container_that_is_still_there_after_the_cancel_is_a_failure(self):
        res, by, _ = self.run_ac7(removed_on_cancel=False)
        self.assertEqual(by[self.CANCEL].status, core.FAIL)
        self.assertEqual(res.status, core.FAIL)

    RUN130 = "cancel: `p2pc run` of a cancelled job exits 130"
    CLOSED = "run detaches with 130 when its stdout closes while the job runs, and the job keeps running"

    def test_spec_7_exit_130_a_cancelled_job_and_a_closed_stdout_while_the_job_runs(self):
        res, by, st = self.run_ac7()
        self.assertEqual(by[self.RUN130].status, core.PASS, by[self.RUN130].reason)
        self.assertEqual(by[self.CLOSED].status, core.PASS, by[self.CLOSED].reason)
        self.assertEqual(by[self.CLOSED].evidence["job_id"], "job_9")
        self.assertIn("job_9", st["also_cancelled"])  # the detached job is never left running

    def test_the_closed_stdout_check_runs_the_real_pipeline_with_the_key_on_stdin(self):
        ctx, st = self.simulate()
        import ac07_cancel_timeout

        ac07_cancel_timeout.run(ctx)
        argv, stdin = next((a, i) for a, i in ctx.executor("server").calls if any("acc7-closed-stdout" in x for x in a))
        self.assertNotIn(FAKE_KEY, " ".join(argv))  # the key never travels in argv
        self.assertTrue((stdin or b"").startswith(FAKE_KEY.encode()))
        script = next(x for x in argv if "acc7-closed-stdout" in x)
        self.assertIn("| head -n 1", script)
        # The job keeps writing after the first line, so a write into the closed pipe always comes within seconds
        # (T15b review P3 1): one `echo second` after one sleep could be batched into the first read.
        self.assertIn("while :; do sleep 2; echo tick; done", script)
        self.assertNotIn("echo second", script)

    def test_a_run_that_exits_other_than_130_after_its_stdout_closed_is_a_failure(self):
        ctx, st = self.simulate()
        original = ctx.executor("server").handler

        def handler(argv, stdin):
            if argv[:1] == ["cat"] and argv[-1].endswith(".exit"):
                return (0, "0\n", "")
            return original(argv, stdin)

        ctx.executor("server").handler = handler
        import ac07_cancel_timeout

        by = {c.name: c for c in ac07_cancel_timeout.run(ctx).checks}
        self.assertEqual(by[self.CLOSED].status, core.FAIL)
        self.assertIn("expected 130", by[self.CLOSED].reason)

    def test_a_cancelled_job_whose_run_exits_0_is_a_failure(self):
        ctx, st = self.simulate()
        original = ctx.executor("server").handler

        def handler(argv, stdin):
            if p2pc_subcommand(argv) == "run" and "acc7-run-130" in argv and "--detach" not in argv:
                return (0, json.dumps({"id": "job_130", "status": "cancelled"}) + "\n", "")
            return original(argv, stdin)

        ctx.executor("server").handler = handler
        import ac07_cancel_timeout

        by = {c.name: c for c in ac07_cancel_timeout.run(ctx).checks}
        self.assertEqual(by[self.RUN130].status, core.FAIL)
        self.assertIn("expected 130", by[self.RUN130].reason)

    def test_the_timeout_flow_and_the_exit_code_124_are_separate_checks(self):
        res, by, _ = self.run_ac7()
        self.assertEqual(by[self.TIMEOUT].status, core.PASS, by[self.TIMEOUT].reason)
        self.assertEqual(by["timeout: p2pc run exits with 124"].status, core.PASS)


class StubProbes:
    """Today's p2pc: `logs`, `results`, `usage` and `proxy` are stubs. In `p2pc --help` their description says "(not
    available in this version yet)"; with NO arguments they print "not implemented yet" (exit 125); given any other
    argument, clap refuses it first. These are the real shapes of the replies (constants only)."""

    CLAP = "error: unexpected argument '{arg}' found\n\nUsage: p2pc {sub}\n\nFor more information, try '--help'.\n"
    STUB = "error: `p2pc {sub}` is not implemented yet in this version\n"
    HELP = "Show something (not available in this version yet).\n\nUsage: p2pc {sub}\n\nOptions:\n  -h, --help  Print help\n"
    REAL_HELP = "Show a job's logs.\n\nUsage: p2pc logs [OPTIONS] <JOB_ID>\n\nOptions:\n  -h, --help  Print help\n"

    def handler(self, calls, implemented=()):
        def handler(argv, stdin):
            if not any(a.endswith("/p2pc") for a in argv):
                return preflight_ok(argv, stdin)
            tail = argv[argv.index(next(a for a in argv if a.endswith("/p2pc"))) + 1:]
            tail = [a for a in tail if a != "--json"]
            calls.append(tail)
            sub, rest = (tail[0], tail[1:]) if tail else ("", [])
            if sub in implemented:
                if rest == ["--help"]:
                    return (0, self.REAL_HELP, "")
                if not rest:
                    return (125, "", "error: the following required arguments were not provided: <JOB_ID>\n")
                return (125, "", json.dumps({"error": {"kind": "api", "status": 404, "code": "not_found"}}))
            if sub in ("logs", "results", "usage", "proxy"):
                if rest == ["--help"]:
                    return (0, self.HELP.format(sub=sub), "")
                if rest:
                    return (125, "", self.CLAP.format(arg=rest[0], sub=sub))
                return (125, "", self.STUB.format(sub=sub))
            return (0, "{}", "")

        return handler


class StubsInScripts(unittest.TestCase):
    """The scripts against today's replies: a stub is `blocked` by T11b, never `fail`."""

    TOML = """
    [server]
    executor = "local"
    admin_key_env = "TEST_ADMIN_KEY"
    [node_linux_gpu]
    executor = "local"
    """

    def job(self, **kw):
        base = {"id": "job_1", "status": "succeeded", "exit_code": 0, "node_id": "n1",
                "created_at": "2026-11-05T12:00:00Z", "started_at": "2026-11-05T12:00:02Z"}
        return base | kw

    def handler(self):
        clap = StubProbes.CLAP
        stub = StubProbes.STUB

        def handler(argv, stdin):
            tail_i = next((i for i, a in enumerate(argv) if a.endswith("/p2pc")), None)
            if tail_i is None:
                return preflight_ok(argv, stdin)
            tail = [a for a in argv[tail_i + 1:] if a != "--json"]
            sub, rest = (tail[0], tail[1:]) if tail else ("", [])
            if tail == ["--help"]:
                return (0, TODAY_P2PC_HELP, "")
            if sub in ("logs", "results", "usage", "proxy"):
                if rest == ["--help"]:
                    return (0, StubProbes.HELP.format(sub=sub), "")
                return (125, "", clap.format(arg=rest[0], sub=sub) if rest else stub.format(sub=sub))
            if sub == "whoami":
                return (0, json.dumps({"key_id": "k", "scopes": ["admin"]}), "")
            if sub == "machines":
                return (0, json.dumps([{"id": "n1", "state": "online", "inventory": {"platform": "linux", "gpus": [{"u": 1}]}}]), "")
            ndjson = lambda job, *logs: "".join(json.dumps(x) + "\n" for x in (*logs, job))  # noqa: E731
            if sub == "run" and "1000" in argv:  # --cpu 1000: refused locally, with the server's own rules
                return (125, "", json.dumps({"error": {"kind": "validation", "code": "validation_failed", "errors": [{"field": "resources.cpu"}]}}))
            if sub == "jobs":
                return (0, json.dumps([self.job()]), "")
            if sub == "run" and "exit 3" in argv:
                return (3, ndjson(self.job(status="failed", exit_code=3)), "")
            if sub == "run" and "--detach" not in rest:
                return (0, ndjson(self.job(), {"seq": 0, "stream": "stdout", "ts": "2026-11-05T12:00:03Z", "data": "42\n"}), "")
            if sub == "run":
                return (0, json.dumps(self.job()), "")
            if sub == "status":
                return (0, json.dumps(self.job()), "")
            return (0, "{}", "")

        return handler

    def test_ac2_logs_are_blocked_by_t11b_not_failed(self):
        import ac02_cpu_job

        ctx, _ = script_ctx(self, self.handler(), self.TOML, binaries=["p2pc"], environ={"TEST_ADMIN_KEY": FAKE_KEY})
        res = ac02_cpu_job.run(ctx)
        logs = next(c for c in res.checks if c.name == "the logs show 42")
        self.assertEqual((logs.status, logs.unblocked_by), (core.BLOCKED, ["T11b2"]))
        self.assertNotEqual(res.status, core.FAIL, [(c.name, c.reason) for c in res.checks if c.status == core.FAIL])

    def test_ac5_results_are_blocked_by_t11b_not_failed(self):
        import ac05_inputs_outputs

        ctx, _ = script_ctx(self, self.handler(), self.TOML, binaries=["p2pc"], environ={"TEST_ADMIN_KEY": FAKE_KEY})
        res = ac05_inputs_outputs.run(ctx)
        by = {c.name: c for c in res.checks}
        self.assertEqual(by["results download with sha256 verification"].unblocked_by, ["T11b2"])
        self.assertNotIn(core.FAIL, [c.status for c in res.checks], [(c.name, c.reason) for c in res.checks])

    def test_ac3_logs_are_blocked_by_t11b_not_failed(self):
        import ac03_gpu_job

        ctx, _ = script_ctx(self, self.handler(), self.TOML, binaries=["p2pc"], environ={"TEST_ADMIN_KEY": FAKE_KEY})
        res = ac03_gpu_job.run(ctx)
        logs = next(c for c in res.checks if "GPU table in the logs" in c.name)
        self.assertEqual((logs.status, logs.unblocked_by), (core.BLOCKED, ["T11b2"]))
        self.assertNotIn(core.FAIL, [c.status for c in res.checks], [(c.name, c.reason) for c in res.checks])


class Ac8ProxyStub(unittest.TestCase):
    TOML = Ac8RestPort.TOML % "http://127.0.0.1:7477"

    def test_the_proxy_stub_is_blocked_by_t11b_and_never_started_with_its_arguments(self):
        import ac08_remote_client

        started = []

        def handler(argv, stdin):
            if argv[:1] == ["curl"]:
                return (0, json.dumps({"address": "p2pc_srv_ABC"}), "")
            joined = " ".join(argv)
            if "--listen" in joined:
                started.append(argv)  # what the real binary answers to this is a clap error, and the log would say so
                return (0, "", "")
            if argv[-1] == "--help" and argv[-2].endswith("/p2pc"):
                return (0, TODAY_P2PC_HELP, "")
            if argv[-1] == "proxy":  # a bare call would start a listener once it exists: the harness must not make it
                started.append(argv)
                return (125, "", "error: `p2pc proxy` is not implemented yet in this version\n")
            return preflight_ok(argv, stdin)

        ctx, _ = script_ctx(self, handler, self.TOML, binaries=["p2pc"])
        ctx.set_admin_key("admin-key-for-the-test-1234")
        res = ac08_remote_client.run(ctx)
        proxy = next(c for c in res.checks if c.name == "p2pc proxy listens on the client")
        self.assertEqual((proxy.status, proxy.unblocked_by), (core.BLOCKED, ["T11b1"]))
        self.assertEqual(started, [])
        dependent = next(c for c in res.checks if c.name.startswith("the remote client runs a job"))
        self.assertEqual((dependent.status, dependent.unblocked_by), (core.BLOCKED, ["T11b1"]))


# What each call needs, written here from crates/p2pc-server/src/auth.rs and crates/p2pc-cli/src/mcp/tools.rs, NOT taken
# from the harness's own table: the fakes enforce it, so a key with too few scopes fails the way the real server fails.
REAL_CLI_SCOPE = {"run": "jobs:write", "cancel": "jobs:write", "estimate": "jobs:read", "status": "jobs:read",
                  "jobs": "jobs:read", "machines": "nodes:read", "keys": "admin"}
REAL_MCP_SCOPE = {"p2pc_estimate": "jobs:read", "p2pc_run": "jobs:write", "p2pc_machines": "nodes:read",
                  "p2pc_status": "jobs:read", "p2pc_logs": "jobs:read", "p2pc_results": "jobs:read", "p2pc_cancel": "jobs:write"}
REAL_MCP_TOOL_ROUTE = {"p2pc_estimate": ("POST", "/v1/estimate"), "p2pc_run": ("POST", "/v1/jobs"),
                       "p2pc_machines": ("GET", "/v1/nodes")}


def forbidden_error(scope):
    """The real shape: ApiError::forbidden(scope) in crates/p2pc-server/src/error.rs."""
    return {"kind": "api", "status": 403, "code": "forbidden", "title": "Forbidden",
            "detail": f"This API key lacks the `{scope}` scope."}


class ScopedWorld:
    """The server as far as AC-9 sees it: keys with the scopes they were CREATED with (read from the `--scope` flags the
    harness sent), the routes that exist, and `p2pc mcp` answering each request line as the real one does."""

    ADMIN = "p2pc_sk_" + "adminkeyid01" + "_" + "a" * 52

    def __init__(self, routes=("/v1/estimate", "/v1/jobs", "/v1/nodes"), mutate=None):
        self.routes = set(routes)
        self.keys = {self.ADMIN: {"admin"}}
        self.created: list[dict] = []
        self.revoked: list[str] = []
        self.cancelled: list[str] = []
        self.mutate = mutate
        self.n = 0
        self.jobs_by_key: dict[str, str] = {}
        self.keyless_runs = 0

    def has(self, key, scope):
        scopes = self.keys.get(key, set())
        return "admin" in scopes or scope in scopes

    def openapi(self):
        return {"paths": {p: {"get": {}, "post": {}} for p in self.routes | {"/v1/whoami", "/v1/keys"}}}

    @staticmethod
    def api_error(status, code="not_found", **extra):
        return {"kind": "api", "status": status, "code": code, "title": code, **extra}

    def cli(self, argv, stdin):
        key = (stdin or b"").split(b"\n", 1)[0].decode()
        sub = argv[argv.index("--json") + 1] if "--json" in argv else None
        if "keys" in argv and "create" in argv:
            self.n += 1
            scopes = {argv[i + 1] for i, a in enumerate(argv) if a == "--scope"}
            capped = "--cap" in argv
            new = "p2pc_sk_" + f"key{self.n:09d}" + "_" + str(self.n) * 52
            self.keys[new] = scopes
            made = {"id": f"kid_{self.n}", "key": new, "scopes": sorted(scopes),
                    "daily_unit_cap": 1000 if capped else None,
                    "allowed_images": [argv[argv.index("--image") + 1]] if "--image" in argv else []}
            self.created.append(made)
            return (0, json.dumps(made), "")
        if "keys" in argv and "revoke" in argv:
            self.revoked.append(argv[-1])
            return (0, "{}", "")
        if sub == "whoami":
            return (0, json.dumps({"key_id": "k", "scopes": sorted(self.keys.get(key, set()))}), "")
        if sub == "cancel":
            self.cancelled.append(argv[-1])
            return (0, "{}", "")
        if argv[-1] == "mcp":
            return self.mcp(key, stdin)
        if sub in REAL_CLI_SCOPE:
            need = REAL_CLI_SCOPE[sub]
            if not self.has(key, need):
                return (125, "", json.dumps({"error": forbidden_error(need)}))
            if sub == "run":
                if "4" in argv:
                    return (125, "", json.dumps({"error": self.api_error(402, "cap_exceeded")}))
                if any("alpine" in a for a in argv):
                    return (125, "", json.dumps({"error": self.api_error(403, "image_not_allowed")}))
                return (0, json.dumps({"id": "job_cli", "status": "queued"}), "")
        return (0, "{}", "")

    def mcp(self, key, stdin):
        if not (self.has(key, "jobs:write") or self.has(key, "jobs:read")) and "admin" in self.keys.get(key, ()):
            return (125, "", "refusing to run: the key is admin")
        if key not in self.keys or "admin" in self.keys[key] or not any(m["key"] == key and m["daily_unit_cap"] for m in self.created):
            return (125, "", "refusing to run: the key is admin or has no daily cap")
        replies = []
        for line in (stdin or b"").split(b"\n")[1:]:
            if not line.strip():
                continue
            msg = json.loads(line)
            if "id" not in msg:
                continue
            ident, method = msg["id"], msg["method"]
            if method == "initialize":
                replies.append({"jsonrpc": "2.0", "id": ident, "result": {"serverInfo": {"name": "p2pc"}}})
            elif method == "tools/list":
                replies.append({"jsonrpc": "2.0", "id": ident, "result": {"tools": [{"name": n} for n in flows.MCP_TOOLS]}})
            else:
                tool = msg["params"]["name"]
                err = None
                if not self.has(key, REAL_MCP_SCOPE[tool]):
                    err = forbidden_error(REAL_MCP_SCOPE[tool])
                elif REAL_MCP_TOOL_ROUTE[tool][1] not in self.routes:
                    err = self.api_error(404)
                if err:
                    doc = {"error": err}
                    replies.append({"jsonrpc": "2.0", "id": ident, "result": {
                        "isError": True, "structuredContent": doc, "content": [{"type": "text", "text": json.dumps(doc)}]}})
                else:
                    if tool == "p2pc_run":
                        # Like the product: the same idempotency_key gives the same job, and no key gives a new one.
                        k = msg["params"]["arguments"].get("idempotency_key")
                        if k is None:
                            self.keyless_runs += 1
                        body = {"job_id": self.jobs_by_key.setdefault(k, "job_01ABC" if not self.jobs_by_key else f"job_01ABD{len(self.jobs_by_key)}") if k else f"job_01NOKEY{self.keyless_runs}"}
                    else:
                        body = {"ok": True}
                    replies.append({"jsonrpc": "2.0", "id": ident, "result": {
                        "isError": False, "structuredContent": body, "content": [{"type": "text", "text": json.dumps(body)}]}})
        if self.mutate:
            self.mutate(replies)
        return (0, "".join(json.dumps(r) + "\n" for r in replies), "")

    def handler(self, argv, stdin):
        if argv[:1] == ["curl"]:
            return (0, json.dumps(self.openapi()), "")
        if any(a.endswith("/p2pc") for a in argv):
            return self.cli(argv, stdin)
        return preflight_ok(argv, stdin)


class Ac9WithScopes(unittest.TestCase):
    TOML = """
    [server]
    executor = "local"
    admin_key_env = "TEST_ADMIN_KEY"
    """

    def run_ac9(self, world=None, patch=None):
        import ac09_mcp
        from unittest import mock

        world = world or ScopedWorld()
        ctx, fake = script_ctx(self, world.handler, self.TOML, binaries=["p2pc"], environ={"TEST_ADMIN_KEY": world.ADMIN}, gate=False)
        if patch:
            with mock.patch.object(flows, "scopes_needed", patch):
                res = ac09_mcp.run(ctx)
        else:
            res = ac09_mcp.run(ctx)
        return res, {c.name: c for c in res.checks}, world, fake

    SESSION = "an MCP session with the capped key: tools, estimate, run, machines"

    def test_a_clean_session_passes_with_exactly_the_scopes_it_needs(self):
        res, by, world, _ = self.run_ac9()
        self.assertEqual(by[self.SESSION].status, core.PASS, by[self.SESSION].reason)
        capped, uncapped = world.created
        self.assertEqual(capped["scopes"], ["jobs:read", "jobs:write", "nodes:read"])  # machines needs nodes:read
        self.assertEqual(uncapped["scopes"], ["jobs:read"])  # it only ever starts `p2pc mcp`
        self.assertEqual(sorted(world.revoked), ["kid_1", "kid_2"])
        self.assertEqual(world.cancelled, ["job_01ABC"])  # the job the session created is not left queued

    def test_the_capped_key_has_the_scopes_every_tool_it_calls_requires_per_auth_rs_and_tools_rs(self):
        import ac09_mcp

        needed = {REAL_MCP_SCOPE[t] for t in ac09_mcp.SESSION_TOOLS} | {REAL_CLI_SCOPE[c] for c in ac09_mcp.KEY_CLI_CALLS if c in REAL_CLI_SCOPE}
        self.assertEqual(set(flows.scopes_needed(cli=ac09_mcp.KEY_CLI_CALLS, mcp=ac09_mcp.SESSION_TOOLS)), needed)

    def test_a_key_without_nodes_read_makes_p2pc_machines_fail_with_403_and_the_check_fails(self):
        without = lambda cli=(), mcp=(): ["jobs:read", "jobs:write"]  # noqa: E731  (the bug the review found)
        res, by, world, _ = self.run_ac9(patch=without)
        chk = by[self.SESSION]
        self.assertEqual(chk.status, core.FAIL)  # a forbidden is a failure, never a block
        self.assertIn("nodes:read", chk.reason)
        self.assertEqual(res.status, core.FAIL)

    def test_a_key_without_jobs_write_cannot_run_and_the_fake_enforces_it_on_the_cli_too(self):
        res, by, world, _ = self.run_ac9(patch=lambda cli=(), mcp=(): ["jobs:read", "nodes:read"])
        self.assertEqual(by[self.SESSION].status, core.FAIL)
        self.assertIn("jobs:write", by[self.SESSION].reason)
        # The cap and allowlist checks must not mistake "no scope" for "refused by the cap or the allowlist".
        self.assertEqual(by["the image allowlist is enforced"].status, core.FAIL)
        self.assertIn("lacks a scope", by["the image allowlist is enforced"].reason)
        self.assertEqual(by["the daily cap is enforced"].status, core.FAIL)

    def test_stdin_is_held_open_until_all_six_replies_have_arrived(self):
        res, by, world, fake = self.run_ac9()
        (argv, until, deadline), = fake.holds
        self.assertEqual(deadline, 90)
        one = '{"jsonrpc":"2.0","id":1,"result":{}}\n'
        self.assertFalse(until(one * 5))
        self.assertTrue(until(one * 6))
        self.assertFalse(until(one * 5 + '{"jsonrpc":"2.0","id":9,"res'))  # a half-written line is not a reply
        self.assertFalse(until('{"jsonrpc":"2.0","method":"notifications/message","params":{}}\n' * 6))  # nor are notifications

    def _session_calls(self):
        _, by, _, fake = self.run_ac9()
        (argv, _, _), = fake.holds
        stdin = next(stdin for a, stdin in fake.calls if a == argv and b"tools/call" in (stdin or b""))
        return [json.loads(line) for line in stdin.decode().splitlines()[1:] if line.strip()]  # line 0 is the key

    def test_neither_p2pc_run_call_waits_for_the_job_it_only_checks_that_the_retry_returns_the_same_one(self):
        # ACC-1: a first p2pc_run that waits for a job which cannot start (the node hit a registry's pull limit) used up the
        # session before the repeated call was answered. Both calls say wait_s = 0, explicitly, whatever the tool's default.
        calls = self._session_calls()
        runs = [m["params"]["arguments"] for m in calls if m.get("method") == "tools/call" and m["params"]["name"] == "p2pc_run"]
        self.assertEqual(len(runs), 2)
        self.assertEqual([r.get("wait_s") for r in runs], [0, 0])

    def test_the_retry_has_its_own_request_id_and_the_same_fresh_valid_idempotency_key(self):
        import re

        calls = [m for m in self._session_calls() if "id" in m]
        ids = [m["id"] for m in calls]
        self.assertEqual(len(ids), len(set(ids)), "a request id was repeated (MCP forbids it)")
        runs = [m for m in calls if m["method"] == "tools/call" and m["params"]["name"] == "p2pc_run"]
        self.assertEqual([m["id"] for m in runs], [4, 6])
        keys = [m["params"]["arguments"]["idempotency_key"] for m in runs]
        self.assertEqual(keys[0], keys[1])
        self.assertRegex(keys[0], r"^[A-Za-z0-9._:-]{1,128}$")
        self.assertEqual(runs[0]["params"]["arguments"], runs[1]["params"]["arguments"])
        again = [m["params"]["arguments"]["idempotency_key"] for m in self._session_calls() if m.get("method") == "tools/call" and m["params"]["name"] == "p2pc_run"]
        self.assertNotEqual(keys[0], again[0], "the key must be fresh for every run")
        self.assertIsNone(re.search(r"\s", keys[0]))

    def test_a_retry_that_creates_a_second_job_fails_the_session(self):
        def second_job(replies):
            body = {"job_id": "job_01OTHER"}
            replies[5] = {"jsonrpc": "2.0", "id": 6, "result": {"isError": False, "structuredContent": body,
                                                                 "content": [{"type": "text", "text": json.dumps(body)}]}}

        res, by, _, _ = self.run_ac9(ScopedWorld(mutate=second_job))
        self.assertEqual(by[self.SESSION].status, core.FAIL)
        self.assertIn("second job", by[self.SESSION].reason)

    def test_a_missing_reply_to_the_retry_fails_the_session(self):
        res, by, _, _ = self.run_ac9(ScopedWorld(mutate=lambda replies: replies.pop(5)))
        self.assertEqual(by[self.SESSION].status, core.FAIL)
        self.assertIn("request id 6", by[self.SESSION].reason)

    def test_the_session_timeout_covers_the_wait_for_the_replies_the_waits_of_both_runs_and_a_margin(self):
        import ac09_mcp

        seen = []
        world = ScopedWorld()
        ctx, fake = script_ctx(self, world.handler, self.TOML, binaries=["p2pc"], environ={"TEST_ADMIN_KEY": world.ADMIN}, gate=False)
        original = fake.run

        def run(argv, **kw):
            if argv[-1] == "mcp" and kw.get("hold_stdin_until"):
                seen.append((kw["timeout"], kw["hold_deadline_s"]))
            return original(argv, **kw)

        fake.run = run
        ac09_mcp.run(ctx)
        (timeout, deadline), = seen
        self.assertEqual(deadline, 90 + 2 * ac09_mcp.RUN_WAIT_S)
        self.assertGreaterEqual(timeout, deadline + executors.HOLD_EXIT_GRACE_S + 30)
        self.assertGreaterEqual(timeout, 90 + 2 * ac09_mcp.RUN_WAIT_S + executors.HOLD_EXIT_GRACE_S + 30)

    def test_a_json_rpc_error_a_missing_result_and_iserror_still_fail_the_session(self):
        def err(replies):
            replies[2] = {"jsonrpc": "2.0", "id": 3, "error": {"code": -32603, "message": "estimate exploded"}}

        def noresult(replies):
            replies[4] = {"jsonrpc": "2.0", "id": 5}

        def iserror(replies):
            replies[3] = {"jsonrpc": "2.0", "id": 4, "result": {"isError": True, "content": [{"type": "text", "text": "cap_exceeded job_01ABC"}]}}

        for mutate, word in ((err, "estimate exploded"), (noresult, "no result"), (iserror, "isError")):
            res, by, _, _ = self.run_ac9(ScopedWorld(mutate=mutate))
            self.assertEqual(by[self.SESSION].status, core.FAIL, word)
            self.assertIn(word, by[self.SESSION].reason)

    def test_a_tool_whose_route_is_missing_is_blocked_by_the_task_that_brings_it(self):
        for absent, task in (("/v1/estimate", "T04"), ("/v1/jobs", "T04"), ("/v1/nodes", "T05")):
            world = ScopedWorld(routes={"/v1/estimate", "/v1/jobs", "/v1/nodes"} - {absent})
            res, by, _, _ = self.run_ac9(world)
            chk = by[self.SESSION]
            self.assertEqual((chk.status, chk.unblocked_by), (core.BLOCKED, [task]), absent)
            self.assertIn(absent, chk.reason)

    def test_the_same_404_for_a_route_that_exists_is_a_failure(self):
        world = ScopedWorld()
        original = world.mcp

        def always_404(key, stdin):
            code, out, err = original(key, stdin)
            if code != 0:  # a refusal (admin or uncapped key): nothing to rewrite
                return (code, out, err)
            replies = [json.loads(line) for line in out.splitlines()]
            doc = {"error": world.api_error(404)}
            replies[3] = {"jsonrpc": "2.0", "id": 4, "result": {"isError": True, "structuredContent": doc,
                                                                 "content": [{"type": "text", "text": json.dumps(doc)}]}}
            return (code, "".join(json.dumps(r) + "\n" for r in replies), err)

        world.mcp = always_404
        res, by, _, _ = self.run_ac9(world)
        self.assertEqual(by[self.SESSION].status, core.FAIL)
        self.assertIn("isError", by[self.SESSION].reason)


class TodayWorld(ScopedWorld):
    """The product at a given stage, in the real reply shapes: which REST routes exist, whether a node is online, and what
    a job does (``queued`` forever: no scheduler; ``assigned``: no agent executor; ``running``: no JobFinished; ``done``).
    The CLI stubs (`logs`, `results`, `usage`, `proxy`) and the agent's `join -` stay stubs, as they are today."""

    JOBS = {"/v1/jobs", "/v1/jobs/{id}", "/v1/jobs/{id}/cancel", "/v1/estimate"}  # T04 is merged
    NODES = {"/v1/nodes", "/v1/nodes/join-tokens", "/v1/server"}  # T05
    SCHEDULER = {"/v1/usage"}  # the marker of the scheduler (T06): `GET /v1/usage` is in the OpenAPI

    def __init__(self, routes, nodes_online=False, job="queued", agent=None):
        super().__init__(routes=routes)
        self.nodes_online = nodes_online
        self.agent = nodes_online if agent is None else agent  # the agent's `status` answers (its connection exists)
        self.job = job
        self.submitted = 0
        self.joined = 0
        self.calls = []

    def openapi(self):
        return {"paths": {p: {"get": {}, "post": {}, "delete": {}} for p in self.routes | {"/v1/whoami", "/v1/keys"}}}

    def missing(self, path):
        return path not in self.routes

    def job_json(self, ident="job_1", **kw):
        st = self.job
        base = {"id": ident, "status": {"done": "succeeded"}.get(st, st), "attempt": 1,
                "created_at": "2026-11-05T12:00:00Z", "name": "x"}
        if st != "queued":
            base["node_id"] = "n1"
        if st in ("running", "done"):
            base["started_at"] = "2026-11-05T12:00:02Z"
        if st == "done":
            base.update(exit_code=0, finished_at="2026-11-05T12:00:09Z")
        if st == "failed":
            base.update(started_at="2026-11-05T12:00:02Z", exit_code=None, error="start_failed",
                        finished_at="2026-11-05T12:00:03Z")
        return base | kw

    def node_json(self, ident, platform):
        return {"id": ident, "name": ident, "state": "online",
                "inventory": full_inventory(platform) | {"hostname": ident},
                "free": {"cpu": 4.0, "memory_mb": 8192, "gpu": 1}}

    def cli(self, argv, stdin):
        i = next(k for k, a in enumerate(argv) if a.endswith("/p2pc"))
        tail = [a for a in argv[i + 1:] if a != "--json"]
        self.calls.append(tail)
        sub, rest = (tail[0], tail[1:]) if tail else ("", [])
        if tail == ["--help"]:
            return (0, TODAY_P2PC_HELP, "")
        problem = lambda status: (125, "", json.dumps({"error": self.api_error(status)}))  # noqa: E731
        if sub in ("logs", "results", "usage", "proxy"):
            if rest == ["--help"]:
                return (0, StubProbes.HELP.format(sub=sub), "")
            return (125, "", StubProbes.CLAP.format(arg=rest[0], sub=sub) if rest else StubProbes.STUB.format(sub=sub))
        if sub == "machines" and not rest:
            if self.missing("/v1/nodes"):
                return problem(404)
            nodes = [self.node_json("n1", "linux"), self.node_json("n2", "wsl2")] if self.nodes_online else []
            nodes += [self.node_json(f"joined_{k}", "linux") for k in range(self.joined)]
            return (0, json.dumps(nodes), "")
        if sub == "join-token":
            if self.missing("/v1/nodes/join-tokens"):
                return problem(404)
            if "list" in rest:  # the k-th token enrolled the k-th joined machine
                rows = [{"id": f"jtk_{k + 1}", "created_by_key_id": "k", "created_at": "2026-11-05T12:00:00Z",
                         "expires_at": "2026-11-05T12:15:00Z", "consumed_by_node_id": f"joined_{k}"} for k in range(self.joined)]
                return (0, json.dumps(rows), "")
            self.tokens = getattr(self, "tokens", 0) + 1
            return (0, json.dumps({"id": f"jtk_{self.tokens}", "join_token": "p2pc_join_" + "MFRGGZDF" * 8,
                                   "expires_at": "2026-11-05T12:15:00Z"}), "")
        if sub == "run":
            if self.missing("/v1/jobs"):
                return problem(404)
            if "1000" in rest:  # --cpu 1000: refused locally, before anything is sent
                return (125, "", json.dumps({"error": {"kind": "validation", "code": "validation_failed"}}))
            refused = super().cli(argv, stdin)  # the key's scope, cap and image allowlist (all enforced since T04)
            if refused[0] != 0:
                return refused
            self.submitted += 1
            if "--detach" in rest:
                return (0, json.dumps(self.job_json(f"job_{self.submitted}", status="queued")), "")
            code = {"done": 0}.get(self.job, 125)
            # `p2pc run --json` is NDJSON: the log records as they arrive, then the final job as the last line.
            log = {"seq": 0, "stream": "stdout", "ts": "2026-11-05T12:00:03Z", "data": "42\n"}
            return (code, json.dumps(log) + "\n" + json.dumps(self.job_json(f"job_{self.submitted}")) + "\n", "")
        if sub == "status":
            if self.missing("/v1/jobs/{id}"):
                return problem(404)
            return (0, json.dumps(self.job_json(rest[-1])), "")
        if sub == "jobs":
            return (0, "[]", "") if not self.missing("/v1/jobs") else problem(404)
        return super().cli(argv, stdin)

    def handler(self, argv, stdin):
        if argv[:1] == ["curl"]:
            url = (stdin or b"").decode()
            if "/v1/openapi.json" in url:
                return (0, json.dumps(self.openapi()), "")
            if "/v1/server" in url:
                if self.missing("/v1/server"):
                    return (0, json.dumps({"type": "about:blank", "status": 404, "code": "not_found"}), "")
                return (0, json.dumps({"address": "p2pc_srv_ABC"}), "")
            return (0, "ok", "")
        if argv[:2] == ["sh", "-c"] and "install-it" in argv[2]:
            return (0, f"ADMIN API KEY (shown once): {self.ADMIN}\n", "")
        if any(a.endswith("/p2pc-agent") for a in argv):
            if self.agent:  # the agent's connection exists: `status` answers, `join -` works
                if "join" in argv:
                    self.joined += 1  # a new machine appears in `p2pc machines`
                return (0, "connected\n", "")
            return (2, "", "not implemented yet\n")
        if any(a.endswith("/p2pc") for a in argv):
            return self.cli(argv, stdin)
        if argv[:1] == ["pgrep"]:
            return (1, "", "")  # nothing runs on the machines yet
        if argv[:2] == ["sh", "-c"] and "/dev/tcp" in argv[2]:
            return (1, "", "bash: connect: Connection refused")  # nobody listens: the REST port is closed from outside
        return preflight_ok(argv, stdin)


ALL_ROLES_TOML = """
[server]
executor = "local"
admin_key_env = "TEST_ADMIN_KEY"
public_host = "198.51.100.10"
install_command = "install-it --yes"
[node_linux_gpu]
executor = "local"
partition_command = "PARTITION"
heal_command = "HEAL"
lan_gateway = "192.0.2.1"
lan_host = "192.0.2.50"
[node_wsl2_gpu]
executor = "local"
partition_command = "PARTITION"
heal_command = "HEAL"
lan_gateway = "192.0.2.1"
lan_host = "192.0.2.51"
[client_remote]
executor = "local"
[params]
job_count = 4
jobs_per_node = 2
"""

# The tasks a check may be blocked by: the product's own, never a made-up one.
OWNING_TASKS = set(context.OWNERS.values())

CRITERIA_RUNNING_PRODUCT = ("AC-1", "AC-2", "AC-3", "AC-4", "AC-5", "AC-6", "AC-7", "AC-8", "AC-9", "AC-10")


class EveryCheckAgainstTheProductAsItIs(unittest.TestCase):
    """The audit, as a test. Every AC from 1 to 10 runs, with every role enabled, against the product at each stage of
    its construction. Rule (a): while a route, subcommand or feature is missing a check is `blocked` naming its owning
    task, or `skip`; it is a `fail` only for a product that exists and is wrong. No stage may produce a `fail`."""

    STAGES = {
        "T04 only (jobs API merged; no nodes, no tunnel)": dict(routes=TodayWorld.JOBS),
        "+ T05 routes, no agent online": dict(routes=TodayWorld.JOBS | TodayWorld.NODES),
        "+ an agent online, no scheduler": dict(routes=TodayWorld.JOBS | TodayWorld.NODES, nodes_online=True, job="queued"),
        # From here the scheduler's marker (GET /v1/usage) is in the OpenAPI. The agent's executor has no marker of its
        # own, so a job that never starts or never finishes is the gate's one `fail` (and what depends on it is skipped).
        "+ scheduler, no agent executor": dict(routes=TodayWorld.JOBS | TodayWorld.NODES | TodayWorld.SCHEDULER, nodes_online=True, job="assigned"),
        "+ executor starts jobs, never reports": dict(routes=TodayWorld.JOBS | TodayWorld.NODES | TodayWorld.SCHEDULER, nodes_online=True, job="running"),
    }
    GATE_FAILS_IN = ("+ scheduler, no agent executor", "+ executor starts jobs, never reports")

    def run_stage(self, **world_kwargs):
        import criteria as registry

        world = TodayWorld(**world_kwargs)
        ctx, fake = script_ctx(self, world.handler, ALL_ROLES_TOML, binaries=["p2pc", "p2pc_agent"],
                               environ={"TEST_ADMIN_KEY": world.ADMIN}, gate=False)
        fake.violations.clear()
        results = {}
        for mod in registry.load_all():
            if mod.ID in CRITERIA_RUNNING_PRODUCT:
                results[mod.ID] = mod.run(ctx)
        return results, world

    def test_no_check_fails_at_any_stage_and_every_block_names_an_owning_task(self):
        for stage, kwargs in self.STAGES.items():
            results, _ = self.run_stage(**kwargs)
            for ident, res in results.items():
                for chk in res.checks:
                    where = f"[{stage}] {ident} / {chk.name}: {chk.status} {chk.reason}"
                    if chk.status == core.FAIL:
                        # The one failure allowed: the gate, once the scheduler exists, when the job never starts or
                        # finishes and the agent's executor has no marker of its own to read.
                        self.assertIn(stage, self.GATE_FAILS_IN, where)
                        self.assertRegex(chk.reason, r"executor|JobFinished", where)
                    if chk.status == core.BLOCKED:
                        self.assertTrue(chk.unblocked_by, where)
                        self.assertTrue(set(chk.unblocked_by) <= OWNING_TASKS, where)
                        self.assertTrue(chk.reason, where)
                    if chk.status != core.PASS:
                        self.assertTrue(chk.reason, where)
                # AC-1 needs no scheduler: once the agent's connection exists it can pass. Nothing else can.
                if ident == "AC-1" and stage not in list(self.STAGES)[:2]:
                    continue
                self.assertNotEqual(res.status, core.PASS, f"[{stage}] {ident} cannot pass: part of the product is missing")

    def test_the_task_named_for_each_gap_is_the_owner_of_that_gap(self):
        def checks(stage, ac):
            results, _ = self.run_stage(**self.STAGES[stage])
            return {c.name: c for c in results[ac].checks}

        owners = context.OWNERS
        # Nothing about nodes exists: the check that lists them is the nodes route's.
        by = checks("T04 only (jobs API merged; no nodes, no tunnel)", "AC-7")
        self.assertEqual(by["environment ready"].unblocked_by, [owners["route GET /v1/nodes"]])
        # Nodes exist but no agent is online and the agent says it is a stub: the agent's connection.
        by = checks("+ T05 routes, no agent online", "AC-2")
        self.assertEqual(by["environment ready"].unblocked_by, [owners["feature agent-connection"]])
        # An agent is online but the server has no scheduler marker: the scheduler, without waiting or submitting.
        by = checks("+ an agent online, no scheduler", "AC-6")
        self.assertEqual(by["two nodes and a way to cut one of them"].unblocked_by, [owners["feature scheduler"]])
        # The scheduler exists: a job that never starts is now a fail that names the executor's owner.
        by = checks("+ scheduler, no agent executor", "AC-10")
        gate = by["environment ready: every enabled node is online"]
        self.assertEqual(gate.status, core.FAIL)
        self.assertIn(owners["feature executor"], gate.reason)
        self.assertEqual(by["a dedicated key for this run"].status, core.SKIP)  # what depends on it is not run
        by = checks("+ executor starts jobs, never reports", "AC-3")
        self.assertEqual(by["environment ready"].status, core.FAIL)
        self.assertIn("JobFinished", by["environment ready"].reason)

    def test_the_stubs_of_the_cli_are_t11b_and_their_routes_are_t10b_or_t06(self):
        import ac02_cpu_job

        world = TodayWorld(routes=TodayWorld.JOBS | TodayWorld.NODES | TodayWorld.SCHEDULER, nodes_online=True, job="done")
        ctx, _ = script_ctx(self, world.handler, ALL_ROLES_TOML, binaries=["p2pc", "p2pc_agent"], environ={"TEST_ADMIN_KEY": world.ADMIN}, gate=False)
        by = {c.name: c for c in ac02_cpu_job.run(ctx).checks}
        self.assertEqual(
            (by["the logs show 42"].status, by["the logs show 42"].unblocked_by),
            (core.BLOCKED, [context.OWNERS["cli logs"]]),
        )
        for check in ("environment ready", "warm the image cache", "round trip: exit 0 and succeeded"):
            self.assertEqual(by[check].status, core.PASS, (check, by[check].reason))

    def test_the_machines_are_never_touched_for_a_disabled_role(self):
        # TodayWorld uses the refusing factory through script_ctx: a command to a disabled role would have raised.
        results, _ = self.run_stage(routes=TodayWorld.JOBS)
        self.assertEqual(len(results), 10)


# `p2pc --help` of the binary on main: every command is real (docs/cli.md); nothing says "not available".
MAIN_P2PC_HELP = """The p2pc command-line client.

Usage: p2pc [OPTIONS] <COMMAND>

Commands:
  login       Check an API key against the server and store it in the profile
  logout      Remove the profile's API key
  whoami      Show who the API key is: account, project, key ID and scopes
  run         Submit a job and follow it until it ends
  estimate    Ask whether a job could run, without submitting it
  jobs        List jobs
  status      Show a job
  cancel      Cancel a job
  machines    List machines, or show, drain, resume and remove one
  join-token  Create, list and revoke join tokens for new machines
  keys        Create, list and revoke API keys
  audit       Show the audit log
  logs        Show a job's logs
  results     Download a job's outputs
  usage       Show reserved and used compute
  proxy       Serve the REST API of a server address on a local port
  mcp         Serve the MCP protocol over stdio, so that an AI agent can run jobs with its own capped key
  completion  Print a shell completion script
  help        Print this message or the help of the given subcommand(s)

Options:
      --json  Print the API's JSON instead of tables and text. Lists are JSON arrays
  -h, --help  Print help
"""

MAIN_TOML = ALL_ROLES_TOML.replace(
    "[node_wsl2_gpu]", '[node_linux]\nexecutor = "local"\npartition_command = "PARTITION"\nheal_command = "HEAL"\n'
    'lan_gateway = "192.0.2.1"\nlan_host = "192.0.2.52"\n[node_wsl2_gpu]', 1,
).replace("job_count = 4", "job_count = 4\nbig_output_mb = 1")


class MainWorld(TodayWorld):
    """The product as it is on `main`: the server's real OpenAPI document (docs/api/openapi.json), a `p2pc` with no stub,
    an agent that joins, and jobs that run to the end. The replies have the real shapes of docs/cli.md (NDJSON for
    `run --json` and `logs --json`, the report of `usage`, the files of `results`)."""

    DOC = json.loads((HERE.parents[1] / "docs" / "api" / "openapi.json").read_text(encoding="utf-8"))
    JOINED = (("linux", 1), ("linux", 0), ("wsl2", 1))  # the roles join in the order of flows.NODE_ROLES

    def __init__(self, detaches_on_closed_stdout=False, **kw):
        super().__init__(routes=set(self.DOC["paths"]), nodes_online=False, job="done", agent=True, **kw)
        # What `p2pc run … | head -1` does: on `main` it ends 0 with no hint; with the detach rule of spec §7 it exits 130.
        self.detaches = detaches_on_closed_stdout
        self.lifecycle: dict[str, dict] = {}  # AC-7's jobs, which really run: {"phase", "polls", "name"}
        self.jobs: dict[str, dict] = {}
        self.results_calls: list[list[str]] = []
        self.fake = None  # the scripted machine, set by the test: AC-5's input file is in its `files`

    def openapi(self):
        return self.DOC

    def machine(self, k):
        platform, gpus = self.JOINED[k % len(self.JOINED)]
        return {"id": f"joined_{k}", "name": f"joined-{k}", "state": "online", "inventory": full_inventory(platform, gpus=gpus) | {"hostname": f"joined-{k}"},
                "free": {"cpu": 4.0, "memory_mb": 8192, "gpu": gpus}}

    def register(self, rest, ident):
        name = rest[rest.index("--name") + 1] if "--name" in rest else ""
        node = rest[rest.index("--node") + 1] if "--node" in rest else "joined_0"
        self.jobs[ident] = {"name": name, "node": node}

    def job_json(self, ident="job_1", **kw):
        info = self.jobs.get(ident, {})
        return super().job_json(ident, name=info.get("name", "x"), node_id=info.get("node", "joined_0"), **kw)

    def logs_text(self, ident):
        name = self.jobs.get(ident, {}).get("name", "")
        return "NVIDIA-SMI 555.00\n" if "smi" in name else "42\n"

    def new_lifecycle_job(self, name, rest=()):
        self.submitted += 1
        ident = f"job_{self.submitted}"
        self.register(["--name", name, *([a for a in rest if a != "--name"])], ident)
        self.jobs[ident]["name"] = name
        self.lifecycle[ident] = {"phase": "queued", "polls": 0, "name": name}
        return ident

    def life_json(self, ident):
        life = self.lifecycle[ident]
        phase = life["phase"]
        base = {"id": ident, "status": phase, "attempt": 1, "name": life["name"], "created_at": "2026-11-05T12:00:00Z", "node_id": "joined_0"}
        if phase != "queued":
            base["started_at"] = "2026-11-05T12:00:02Z"
        if phase in ("cancelled", "timed_out"):
            base["finished_at"] = "2026-11-05T12:00:23Z" if phase == "timed_out" else "2026-11-05T12:00:10Z"
        return base

    def acc7(self, sub, rest):
        """AC-7's jobs run for real in the scripted product: they go queued -> running, and end when cancelled or timed out."""
        name = rest[rest.index("--name") + 1] if "--name" in rest else ""
        if sub == "run" and name.startswith("acc7-"):
            if name == "acc7-run-130" and "--detach" not in rest:
                ident = next(i for i, l in self.lifecycle.items() if l["name"] == name)
                return (130, json.dumps(self.life_json(ident)) + "\n", "")
            existing = next((i for i, l in self.lifecycle.items() if l["name"] == name and name == "acc7-run-130"), None)
            ident = existing or self.new_lifecycle_job(name, rest)
            if "--detach" in rest:
                return (0, json.dumps(self.life_json(ident)), "")
            self.lifecycle[ident]["phase"] = "timed_out"  # `run` of a job with a 20 s timeout follows it to its end
            return (124, json.dumps(self.life_json(ident)) + "\n", "")
        if sub in ("status", "cancel") and rest and rest[-1] in self.lifecycle:
            ident = rest[-1]
            life = self.lifecycle[ident]
            if sub == "cancel":
                if life["phase"] in ("queued", "running"):
                    life["phase"] = "cancelled"
                return (0, json.dumps(self.life_json(ident)), "")
            life["polls"] += 1
            if life["phase"] == "queued":
                life["phase"] = "running"
            elif life["phase"] == "running" and life["name"] == "acc7-timeout" and life["polls"] >= 3:
                life["phase"] = "timed_out"
            return (0, json.dumps(self.life_json(ident)), "")
        return None

    def running_containers(self):
        return [f"p2pc-lease-{i}" for i, l in self.lifecycle.items() if l["phase"] == "running"]

    def cli(self, argv, stdin):
        i = next(k for k, a in enumerate(argv) if a.endswith("/p2pc"))
        as_json = "--json" in argv
        tail = [a for a in argv[i + 1:] if a != "--json"]
        sub, rest = (tail[0], tail[1:]) if tail else ("", [])
        if tail == ["--help"]:
            return (0, MAIN_P2PC_HELP, "")
        if sub == "machines" and not rest:
            return (0, json.dumps([self.machine(k) for k in range(self.joined)]), "")
        reply = self.acc7(sub, rest)
        if reply is not None:
            return reply
        if sub == "run" and "exit 3" in rest and "--detach" not in rest:
            failed = self.job_json("job_exit3", status="failed", exit_code=3)
            return (3, json.dumps(failed) + "\n", "")
        if sub == "run" and "1000" not in rest:
            code, out, err = super().cli(argv, stdin)
            for line in out.splitlines():
                doc = json.loads(line) if line.startswith("{") else {}
                if doc.get("id", "").startswith("job_") and "name" in doc:
                    self.register(rest, doc["id"])
            return (code, out, err)
        if sub == "logs":
            ident = next(a for a in rest if a.startswith("job_"))
            if "--attempt" in rest and rest[rest.index("--attempt") + 1] == "3":
                return (125, "", json.dumps({"error": self.api_error(404)}))
            text = self.logs_text(ident)
            if as_json:
                return (0, json.dumps({"seq": 0, "stream": "stdout", "ts": "2026-11-05T12:00:03Z", "data": text}) + "\n", "")
            return (0, text, "")
        if sub == "results":
            self.results_calls.append(rest)
            ident = rest[0]
            out_dir = rest[rest.index("--out") + 1]
            if "--force" not in rest and len(self.results_calls) > 1:
                return (125, "", json.dumps({"error": {"kind": "error", "message": "files exist"}}))
            size = 1024 * 1024  # big_output_mb = 1 in MAIN_TOML
            files = [("in.sha256", 90, "a" * 64), ("big.bin", size, "b" * 64), ("big.sha256", 90, "c" * 64)]
            if "--file" in rest:
                files = [f for f in files if f[0] == rest[rest.index("--file") + 1]]
            doc = {"job_id": ident, "directory": out_dir, "bytes": sum(f[1] for f in files),
                   "files": [{"path": p, "size": n, "sha256": h, "saved_to": f"{out_dir}/{p}"} for p, n, h in files]}
            return (0, json.dumps(doc), "")
        if sub == "usage":
            return (0, json.dumps({"from": "2026-11-05T12:00:00Z", "to": "2026-11-06T00:00:00Z", "group_by": rest[rest.index("--by") + 1],
                                   "items": [], "total": {"key": None, "attempts": 0, "units": 0}}), "")
        return super().cli(argv, stdin)

    def handler(self, argv, stdin):
        if argv[:2] == ["podman", "ps"]:
            return (0, "".join(n + "\n" for n in self.running_containers()), "")
        if any("acc7-closed-stdout" in a for a in argv):  # `p2pc run … | head -n 1`, the script of AC-7
            ident = self.new_lifecycle_job("acc7-closed-stdout")
            self.lifecycle[ident]["phase"] = "running"
            self.closed_job = ident
            return (0, "first\n", "")
        if argv[:1] == ["cat"] and argv[-1].endswith("acc7-closed.exit"):
            return (0, "130\n" if self.detaches else "0\n", "")
        if argv[:1] == ["cat"] and argv[-1].endswith("acc7-closed.err"):
            job = self.closed_job
            hint = f"\ndetached: job {job} keeps running. To follow it again or to stop it:\n  p2pc logs --follow {job}\n  p2pc cancel {job}\n"
            return (0, f"{job}\n" + (hint if self.detaches else ""), "")
        if argv[:1] == ["curl"] and "/outputs" in (stdin or b"").decode():
            return (0, json.dumps({"items": [{"path": "in.sha256", "size": 90, "sha256": "a" * 64},
                                             {"path": "big.bin", "size": 1048576, "sha256": "b" * 64},
                                             {"path": "big.sha256", "size": 90, "sha256": "c" * 64}], "next_cursor": None}), "")
        if argv[:1] == ["cat"] and argv[-1].endswith("/in.sha256"):  # what the job's sha256sum printed of /inputs/in.bin
            import hashlib

            sent = next(v for k, v in self.fake.files.items() if k.endswith("/in.bin"))
            return (0, hashlib.sha256(sent).hexdigest() + "  /inputs/in.bin\n", "")
        if argv[:1] == ["cat"] and argv[-1].endswith("big.sha256"):
            return (0, "b" * 64 + "  /outputs/big.bin\n", "")
        if argv[:1] == ["sha256sum"]:
            return (0, "b" * 64 + f"  {argv[-1]}\n", "")
        return super().handler(argv, stdin)


class TheProductOnMain(unittest.TestCase):
    """T15b: with only the pieces that are on `main`, no criterion says `blocked`, except what is T14b2's (the node
    installer). The scripted machines have the product's real shapes (see MainWorld)."""

    MARKER = "**A closed stdout detaches too.** In `p2pc run | head -1`, once the reader has gone, ...\n"  # what PR #27 adds

    def checkout(self, node_installer=True, t11b3=False):
        """A scripted checkout holding exactly the files the harness reads from it, so that no test depends on what the
        live repository contains on the day it runs: the two installers (`deploy/linux/install-server.sh`, and
        `install-node.sh` unless ``node_installer`` is False) and a `docs/cli.md` that has, or has not, the line that
        T11b3 adds (the marker of the detach on a closed stdout)."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "docs").mkdir()
        (root / "docs" / "cli.md").write_text(("# p2pc\n" + (self.MARKER if t11b3 else "") + "Ctrl-C detaches and does not cancel.\n"))
        (root / "deploy" / "linux").mkdir(parents=True)
        (root / "deploy" / "linux" / "install-server.sh").write_text("#!/bin/sh\n")
        if node_installer:
            (root / "deploy" / "linux" / "install-node.sh").write_text("#!/bin/sh\n")
        return root

    def run_all(self, world=None, repo_root=None, **checkout):
        """AC-1 to AC-10 against ``world`` and a scripted checkout (``checkout`` says which: see ``checkout``)."""
        import criteria as registry

        world = world or MainWorld()
        ctx, fake = script_ctx(self, world.handler, MAIN_TOML, binaries=["p2pc", "p2pc_agent"],
                               environ={"TEST_ADMIN_KEY": world.ADMIN}, gate=False)  # the gate is probed for real
        world.fake = fake
        ctx.repo_root = repo_root if repo_root is not None else self.checkout(**checkout)
        results = {}
        for mod in registry.load_all():
            if mod.ID in CRITERIA_RUNNING_PRODUCT:
                results[mod.ID] = mod.run(ctx)
        return results, world, ctx

    CLOSED = "run detaches with 130 when its stdout closes while the job runs, and the job keeps running"

    @staticmethod
    def blocked_of(results):
        return [(ident, c.name, c.unblocked_by, c.reason) for ident, res in results.items() for c in res.checks if c.status == core.BLOCKED]

    def test_with_the_node_installers_but_without_t11b3_only_the_detach_on_a_closed_stdout_is_blocked_and_it_names_t11b3(self):
        # The state of `main` on the day this was written: T14b2 merged, T11b3 (PR #27) not. `p2pc run … | head -1` ends 0 with
        # no hint and spec §7 says 130: reported as blocked by its owner, not as a failure of what exists.
        results, _, _ = self.run_all(world=MainWorld(detaches_on_closed_stdout=False), node_installer=True, t11b3=False)
        self.assertEqual([b[:3] for b in self.blocked_of(results)], [("AC-7", self.CLOSED, ["T11b3"])])

    def test_without_install_node_sh_the_installer_steps_are_blocked_by_t14b2_too(self):
        # The path stays covered: a scripted checkout that has no node installer yet.
        results, _, _ = self.run_all(node_installer=False, t11b3=False)
        blocked = self.blocked_of(results)
        installers = [b for b in blocked if b[0] == "AC-1"]
        self.assertEqual(len(installers), len(flows.NODE_ROLES))
        for ident, name, owners, reason in installers:
            self.assertEqual((owners, name.split(": ", 1)[-1]), (["T14b2"], "the node installer, one command"), reason)
        self.assertEqual([b[:3] for b in blocked if b[0] != "AC-1"], [("AC-7", self.CLOSED, ["T11b3"])])

    def test_when_t11b3_lands_the_same_check_passes_with_no_edit(self):
        # Docs with the marker, and a product that detaches: nothing is blocked any more, in any criterion.
        results, _, _ = self.run_all(world=MainWorld(detaches_on_closed_stdout=True), node_installer=True, t11b3=True)
        check = next(c for c in results["AC-7"].checks if c.name == self.CLOSED)
        self.assertEqual(check.status, core.PASS, check.reason)
        self.assertEqual(self.blocked_of(results), [])
        self.assertEqual(self.fails_of(results), [])

    def test_once_t11b3_has_landed_exit_0_with_no_hint_is_a_failure_not_a_block(self):
        results, _, _ = self.run_all(world=MainWorld(detaches_on_closed_stdout=False), node_installer=True, t11b3=True)
        check = next(c for c in results["AC-7"].checks if c.name == self.CLOSED)
        self.assertEqual(check.status, core.FAIL)
        self.assertIn("expected 130", check.reason)

    def test_ac7_really_runs_in_the_scripted_product_and_everything_but_the_unlanded_rule_passes(self):
        results, _, _ = self.run_all(t11b3=False)
        by = {c.name: c for c in results["AC-7"].checks}
        for name, c in by.items():
            if name != self.CLOSED:
                self.assertEqual(c.status, core.PASS, (name, c.reason))
        self.assertEqual(by[self.CLOSED].status, core.BLOCKED)

    def test_list_and_the_run_read_the_same_doc_marker_table(self):
        # T15b review P3 3: one table (product.DOC_MARKERS) decides whether T11b3 has landed, for `--list` (product.Landed)
        # and for the run (ctx.feature_landed). Changing the pattern there changes both, so they cannot disagree.
        root = self.checkout(t11b3=False)
        world = MainWorld()
        ctx, _ = script_ctx(self, world.handler, MAIN_TOML, binaries=["p2pc", "p2pc_agent"],
                            environ={"TEST_ADMIN_KEY": world.ADMIN}, gate=False)
        ctx.repo_root = root
        self.assertIs(product.Landed(root, build=False).landed("feature run-closed-stdout"), False)
        self.assertIs(ctx.feature_landed("run-closed-stdout"), False)
        marker = {"run-closed-stdout": ("docs/cli.md", r"Ctrl-C detaches")}
        with unittest.mock.patch.dict(product.DOC_MARKERS, marker):
            self.assertIs(product.Landed(root, build=False).landed("feature run-closed-stdout"), True)
            self.assertIs(ctx.feature_landed("run-closed-stdout"), True)

    def test_no_test_here_reads_the_live_checkout(self):
        # What the review found: with the live docs/cli.md, T11b3's merge would turn three of these red. Every run uses a
        # scripted checkout (a temporary directory), whatever the live one holds.
        _, _, ctx = self.run_all()
        self.assertNotEqual(ctx.repo_root.resolve(), HERE.parents[1].resolve())
        self.assertIn(tempfile.gettempdir(), str(ctx.repo_root.resolve()).replace("/private", ""))

    def test_with_the_installer_but_no_command_the_installer_steps_are_skips_that_say_what_to_set(self):
        results, _, _ = self.run_all(node_installer=True)
        steps = [c for c in results["AC-1"].checks if c.name.endswith("the node installer, one command")]
        self.assertEqual(len(steps), len(flows.NODE_ROLES))
        for c in steps:
            self.assertEqual(c.status, core.SKIP)
            self.assertIn("install_command", c.reason)

    @staticmethod
    def fails_of(results):
        return [(ident, c.name, c.reason) for ident, res in results.items() for c in res.checks
                if c.status == core.FAIL and ident in ("AC-1", "AC-2", "AC-3", "AC-4", "AC-5", "AC-7", "AC-9")]

    def test_the_criteria_that_the_scripted_product_satisfies_pass(self):
        results, _, _ = self.run_all(t11b3=False)
        for ident in ("AC-2", "AC-3", "AC-4", "AC-5", "AC-9"):
            res = results[ident]
            where = [(c.name, c.status, c.reason) for c in res.checks if c.status not in (core.PASS, core.SKIP)]
            self.assertEqual(where, [], ident)

    def test_no_check_fails_on_the_product_as_it_is(self):
        results, _, _ = self.run_all(world=MainWorld(detaches_on_closed_stdout=False), t11b3=False)
        self.assertEqual(self.fails_of(results), [])


class TheGate(unittest.TestCase):
    """flows.require_jobs_run: a node can actually run a job, probed once per run, every fact read from the product."""

    JOBS_NODES = TodayWorld.JOBS | TodayWorld.NODES
    WITH_SCHEDULER = JOBS_NODES | TodayWorld.SCHEDULER

    def gate(self, routes=None, **kw):
        world = TodayWorld(routes=self.WITH_SCHEDULER if routes is None else routes, **kw)
        ctx, _ = script_ctx(self, world.handler, ALL_ROLES_TOML, binaries=["p2pc", "p2pc_agent"],
                            environ={"TEST_ADMIN_KEY": world.ADMIN}, gate=False)
        ctx.begin("AC-X", "t")
        return ctx, world

    def blocked_by(self, ctx):
        with self.assertRaises(core.Blocked) as cm:
            flows.require_jobs_run(ctx)
        return cm.exception

    def test_a_missing_piece_is_blocked_by_the_owner_the_map_names(self):
        owners = context.OWNERS
        # No machine online and the agent says it is a stub: the agent's connection.
        ctx, world = self.gate(routes=self.JOBS_NODES, nodes_online=False)
        self.assertEqual(self.blocked_by(ctx).unblocked_by, [owners["feature agent-connection"]])
        # Machines online, no scheduler marker (GET /v1/usage) in the OpenAPI AND the probe job stays queued: the scheduler.
        ctx, world = self.gate(routes=self.JOBS_NODES, nodes_online=True)
        err = self.blocked_by(ctx)
        self.assertEqual(err.unblocked_by, [owners["feature scheduler"]])
        self.assertIn("scheduler", err.reason)
        self.assertEqual(world.submitted, 1)  # the probe is always submitted: one marker is not proof

    def test_a_queued_probe_with_an_unreadable_openapi_says_the_marker_could_not_be_read(self):
        ctx, _ = self.gate(nodes_online=True, job="queued")
        original = ctx.feature_landed
        ctx.feature_landed = lambda name: None if name == "scheduler" else original(name)
        with self.assertRaises(core.CheckFailed) as cm:
            flows.require_jobs_run(ctx)
        reason = cm.exception.reason
        self.assertIn("could not be read", reason)
        self.assertNotIn("scheduler exists", reason)
        self.assertNotIn("is in the OpenAPI", reason)
        # ... and with the marker really there the message says so.
        ctx, _ = self.gate(nodes_online=True, job="queued")
        with self.assertRaises(core.CheckFailed) as cm:
            flows.require_jobs_run(ctx)
        self.assertIn("is in the OpenAPI", cm.exception.reason)

    def test_a_missing_scheduler_marker_does_not_stop_a_scheduler_that_works(self):
        # The OpenAPI has no GET /v1/usage but the probe job leaves `queued`: the scheduler exists, so the run goes on.
        ctx, world = self.gate(routes=self.JOBS_NODES, nodes_online=True, job="done")
        flows.require_jobs_run(ctx)
        self.assertEqual(world.submitted, 1)
        # ... and a job that is assigned but never starts is then the executor's, as with the marker.
        ctx, _ = self.gate(routes=self.JOBS_NODES, nodes_online=True, job="assigned")
        with self.assertRaises(core.CheckFailed) as cm:
            flows.require_jobs_run(ctx)
        self.assertIn("never started", cm.exception.reason)

    def test_missing_routes_are_blocked_by_the_owner_of_the_route(self):
        owners = context.OWNERS
        ctx, _ = self.gate(routes=TodayWorld.JOBS, nodes_online=True)  # no /v1/nodes
        self.assertEqual(self.blocked_by(ctx).unblocked_by, [owners["route GET /v1/nodes"]])
        ctx, _ = self.gate(routes=TodayWorld.NODES | TodayWorld.SCHEDULER, nodes_online=True)  # no /v1/jobs
        self.assertEqual(self.blocked_by(ctx).unblocked_by, [owners["route POST /v1/jobs"]])

    def test_an_agent_that_exists_with_nobody_online_is_a_skip_not_a_block(self):
        ctx, _ = self.gate(routes=self.JOBS_NODES, nodes_online=False, agent=True)
        with self.assertRaises(core.Skipped) as cm:
            flows.require_jobs_run(ctx)
        self.assertIn("no machine is online", cm.exception.reason)

    def test_once_the_scheduler_exists_a_job_that_does_not_progress_is_a_fail_naming_the_executors_owner(self):
        owner = context.OWNERS["feature executor"]
        for job, word in (("queued", "stayed queued"), ("assigned", "never started"), ("running", "JobFinished")):
            ctx, _ = self.gate(nodes_online=True, job=job)
            with self.assertRaises(core.CheckFailed, msg=job) as cm:
                flows.require_jobs_run(ctx)
            self.assertIn(word, cm.exception.reason)
            if job != "queued":
                self.assertIn(owner, cm.exception.reason)

    def test_a_working_node_passes_and_the_probe_runs_once_per_run_and_is_cancelled(self):
        ctx, world = self.gate(nodes_online=True, job="done")
        for _ in range(3):
            flows.require_jobs_run(ctx)
        self.assertEqual(world.submitted, 1)
        self.assertIs(ctx.state["jobs_run"], True)
        self.assertEqual(world.cancelled, ["job_1"])  # nothing is left behind

    def test_every_answer_is_remembered_so_nothing_waits_twice(self):
        ctx, world = self.gate(routes=self.JOBS_NODES, nodes_online=True)
        first, second = self.blocked_by(ctx), self.blocked_by(ctx)
        self.assertEqual(first.unblocked_by, second.unblocked_by)
        ctx, world = self.gate(nodes_online=True, job="assigned")
        for _ in range(2):
            with self.assertRaises(core.CheckFailed):
                flows.require_jobs_run(ctx)
        self.assertEqual(world.submitted, 1)
        self.assertEqual(world.cancelled, ["job_1"])

    def test_a_probe_job_that_fails_on_a_node_that_exists_is_a_real_failure(self):
        ctx, _ = self.gate(nodes_online=True, job="failed")
        with self.assertRaises(core.CheckFailed) as cm:
            flows.require_jobs_run(ctx)
        self.assertIn("start_failed", cm.exception.reason)

    def test_waiting_uses_the_injected_clock_never_a_real_sleep(self):
        ctx, _ = self.gate(nodes_online=True, job="queued")
        with self.assertRaises(core.CheckFailed):
            flows.require_jobs_run(ctx)
        self.assertGreaterEqual(sum(ctx.clock_fake.slept), flows.GATE_PLACE_S)


class Ac7WhenPiecesAreMissing(unittest.TestCase):
    """No AC-7 check may fail because a piece of the product is missing: the jobs route, a machine, the scheduler."""

    def run_ac7(self, world, gate):
        import ac07_cancel_timeout

        ctx, _ = script_ctx(self, world.handler, ALL_ROLES_TOML, binaries=["p2pc", "p2pc_agent"],
                            environ={"TEST_ADMIN_KEY": world.ADMIN}, gate=gate)
        res = ac07_cancel_timeout.run(ctx)
        return res, {c.name: c for c in res.checks}

    def assert_no_fail(self, res):
        self.assertEqual([(c.name, c.reason) for c in res.checks if c.status == core.FAIL], [])
        self.assertNotEqual(res.status, core.PASS)

    def test_the_jobs_route_is_missing(self):
        world = TodayWorld(routes=TodayWorld.NODES | TodayWorld.SCHEDULER, nodes_online=True)
        res, by = self.run_ac7(world, gate=False)
        self.assert_no_fail(res)
        self.assertEqual(by["environment ready"].unblocked_by, [context.OWNERS["route POST /v1/jobs"]])

    def test_the_jobs_route_is_missing_even_when_the_gate_was_taken_for_granted(self):
        # The foreground `p2pc run` of the exit-code check takes the same blocked path, on its own.
        world = TodayWorld(routes=TodayWorld.NODES | TodayWorld.SCHEDULER, nodes_online=True)
        res, by = self.run_ac7(world, gate=True)
        self.assert_no_fail(res)
        for name in ("cancel: a running job stops within 15 s and its container is gone",
                     "timeout: the job ends as timed_out within 15 s of its limit and its container is gone",
                     "timeout: p2pc run exits with 124"):
            self.assertEqual((by[name].status, by[name].unblocked_by), (core.BLOCKED, [context.OWNERS["route POST /v1/jobs"]]), name)

    def test_no_node_can_run_jobs(self):
        owners = context.OWNERS
        for routes, nodes_online, owner in (
            (TodayWorld.JOBS | TodayWorld.NODES, False, "feature agent-connection"),  # nobody, and the agent is a stub
            (TodayWorld.JOBS | TodayWorld.NODES, True, "feature scheduler"),  # machines, no scheduler marker
        ):
            world = TodayWorld(routes=routes, nodes_online=nodes_online)
            res, by = self.run_ac7(world, gate=False)
            self.assert_no_fail(res)
            self.assertEqual(by["environment ready"].unblocked_by, [owners[owner]], owner)
            self.assertEqual(by["timeout: p2pc run exits with 124"].status, core.BLOCKED)

    def test_with_a_scheduler_a_job_that_never_progresses_is_reported_by_the_gate_alone(self):
        for job in ("assigned", "running"):
            world = TodayWorld(routes=TodayWorld.JOBS | TodayWorld.NODES | TodayWorld.SCHEDULER, nodes_online=True, job=job)
            res, by = self.run_ac7(world, gate=False)
            self.assertEqual([c.name for c in res.checks if c.status == core.FAIL], ["environment ready"], job)
            self.assertEqual(by["timeout: p2pc run exits with 124"].status, core.SKIP, job)  # not run after a failed gate


class TheClassOfProblem(unittest.TestCase):
    """Rules (a) and (b), enforced on the scripts' own source so a new check cannot slip past them."""

    SOURCES = {p.name: p.read_text(encoding="utf-8") for p in HERE.glob("ac*.py")}
    # Subcommands that exist and need no route of the unfinished tasks.
    EXISTING = {"whoami", "login", "keys", "mcp", "audit", "completion"}

    def used_subcommands(self):
        used = {}
        for name, text in self.SOURCES.items():
            for m in re.finditer(r"ctx\.p2pc\([^\[]{0,200}?\[\s*\"([a-z-]+)\"", text):
                used.setdefault(m.group(1), set()).add(name)
            if "flows.submit(" in text:
                used.setdefault("run", set()).add(name)
        return used

    def test_every_p2pc_subcommand_a_script_calls_is_covered_by_a_route_or_a_cli_owner_or_exists(self):
        for sub, files in self.used_subcommands().items():
            self.assertTrue(
                sub in context.CLI_ROUTES or f"cli {sub}" in context.OWNERS or sub in self.EXISTING or f"{sub} create" in context.CLI_ROUTES,
                f"{sorted(files)} call `p2pc {sub}`, which the map does not know: its missing route would be a fail",
            )

    def test_every_route_of_the_table_has_an_owner_in_the_one_map(self):
        for sub, (method, path) in context.CLI_ROUTES.items():
            self.assertIn(f"route {method} {path}", context.OWNERS, sub)
        for key, task in context.OWNERS.items():
            self.assertRegex(task, r"^T\d+[a-z]?\d?$", key)

    def test_split_task_ids_like_t11b1_are_accepted_by_every_task_id_pattern(self):
        import re

        owner_re = r"^T\d+[a-z]?\d?$"
        waiting_re = r"^(nothing|T\d+[a-z]?\d?[*?]?(, T\d+[a-z]?\d?[*?]?)*)$"
        for task in ("T04", "T10a", "T11b1", "T11b2", "T14b1"):
            self.assertRegex(task, owner_re)
            self.assertRegex(task, waiting_re)
        self.assertRegex("T11b1*, T11b2?", waiting_re)
        self.assertIsNone(re.match(owner_re, "T11bb1"))
        # and the harness's own scan for a stray task id sees the split ids
        self.assertTrue(re.search(r"\bT\d{2}[a-z]?\d?\b", "waits for T11b1"))

    def test_the_owners_are_the_ones_the_architect_gave(self):
        o = context.OWNERS
        self.assertEqual(o["route GET /v1/usage"], "T06")  # GET /v1/usage is the scheduler's (ledger)
        self.assertEqual((o["route GET /v1/jobs/{id}/logs"], o["route GET /v1/jobs/{id}/outputs"]), ("T10b", "T10b"))
        self.assertEqual((o["route GET /v1/nodes"], o["route POST /v1/nodes/join-tokens"]), ("T05", "T05"))
        self.assertEqual(o["route POST /v1/jobs"], "T04")
        self.assertEqual({o[f"cli {s}"] for s in ("logs", "results", "usage", "proxy")}, {"T11b1", "T11b2"})
        self.assertEqual((o["feature agent-connection"], o["feature scheduler"], o["feature executor"], o["feature installer"]),
                         ("T05b", "T06", "T10a", "T14b1"))

    FILES = ("flows.py", "criteria.py", "run.py", "report.py", "core.py", "executors.py", "machines.py")

    def test_no_task_is_named_outside_the_one_map(self):
        """The map in context.py is the only place that names a task. A script that names one by hand goes stale the day
        the task lands; so does a docstring that says what is not built yet."""
        for name in [n for n in self.SOURCES] + list(self.FILES):
            text = self.SOURCES.get(name) or (HERE / name).read_text(encoding="utf-8")
            self.assertNotRegex(text, r"\bT\d{2}[a-z]?\d?\b", f"{name} names a task: use context.owner(key)")

    def test_every_blocked_in_the_scripts_takes_its_tasks_from_the_map(self):
        for name, text in list(self.SOURCES.items()) + [("flows.py", (HERE / "flows.py").read_text(encoding="utf-8"))]:
            for m in re.finditer(r"core\.Blocked\(", text):
                depth, k = 1, m.end()
                while depth and k < len(text):
                    depth += {"(": 1, ")": -1}.get(text[k], 0)
                    k += 1
                call = text[m.start():k]
                self.assertIn("owner(", call, f"{name}: a Blocked without an owner from the map: {call[:120]!r}")

    def test_every_script_that_waits_for_a_job_passes_the_gate_first(self):
        # AC-9 submits through MCP and the CLI only to see the cap and the allowlist refuse: it never waits for a job.
        for name, text in self.SOURCES.items():
            if name in ("ac09_mcp.py",):
                continue
            runs_jobs = "flows.submit(" in text or re.search(r"ctx\.p2pc\([^\[]{0,200}?\[\s*\"run\"", text)
            if runs_jobs:
                self.assertRegex(text, r"ready_to_run\(|require_jobs_run\(", f"{name} runs jobs without the gate")

    def test_no_script_names_a_blocker_by_hand_the_table_does_it(self):
        for name, text in self.SOURCES.items():
            self.assertNotRegex(text, r"blocker=|route_blocker=", name)

    def test_every_key_a_script_creates_gets_scopes_from_scopes_needed_never_a_literal_list(self):
        for name, text in self.SOURCES.items():
            self.assertNotRegex(text, r"\"--scope\"\s*,\s*\"(jobs|nodes|admin)", name)

    def test_the_scope_tables_cover_every_subcommand_and_tool_and_match_the_real_ones(self):
        subs = {k.split()[0] for k in context.CLI_ROUTES} | {k.split()[1] for k in context.OWNERS if k.startswith("cli ")}
        for base in subs:
            self.assertIn(base, flows.CLI_SCOPE, base)
            self.assertEqual(flows.CLI_SCOPE[base], REAL_CLI_SCOPE.get(base, flows.CLI_SCOPE[base]), base)
        for tool, scope in REAL_MCP_SCOPE.items():
            self.assertEqual(flows.MCP_SCOPE[tool], scope, tool)
        self.assertEqual(set(flows.MCP_SCOPE), set(flows.MCP_TOOLS))

    def test_scopes_needed_is_the_least_that_works(self):
        self.assertEqual(flows.scopes_needed(cli=["run"]), ["jobs:write"])
        self.assertEqual(flows.scopes_needed(cli=["whoami"]), ["jobs:read"])  # a key needs at least one scope
        self.assertEqual(flows.scopes_needed(), ["jobs:read"])
        self.assertEqual(flows.scopes_needed(mcp=["p2pc_machines"]), ["nodes:read"])
        self.assertEqual(flows.scopes_needed(cli=["run", "whoami"], mcp=["p2pc_estimate", "p2pc_run", "p2pc_machines"]),
                         ["jobs:read", "jobs:write", "nodes:read"])

    def test_the_ac10_key_can_submit_and_nothing_else(self):
        import ac10_scale

        ctx, sim = Ac10Driver("test_a_correct_scheduler_passes_every_check").simulate()
        # (the Ac10Driver fake records the scopes it was asked for through the `keys create` flags)
        ac10_scale.run(ctx)
        self.assertEqual(sim["created_scopes"], [["jobs:write"]])


class OpenApiRead(unittest.TestCase):
    def ctx_with(self, answers):
        calls = []

        def handler(argv, stdin):
            if argv[:1] == ["curl"]:
                calls.append(1)
                return answers[min(len(calls), len(answers)) - 1]
            return preflight_ok(argv, stdin)

        ctx, _ = make_ctx(handler, environ={"TEST_ADMIN_KEY": FAKE_KEY})
        ctx.begin("AC-X", "t")
        return ctx, calls

    GOOD = (0, json.dumps({"paths": {"/v1/jobs": {"get": {}}}}), "")

    def test_a_failed_read_is_retried_once(self):
        ctx, calls = self.ctx_with([(7, "", "curl: (7) Failed to connect"), self.GOOD])
        self.assertEqual(ctx.openapi_routes(), {("GET", "/v1/jobs")})
        self.assertEqual(len(calls), 2)

    def test_a_failed_read_is_not_cached_and_declares_no_route_missing(self):
        ctx, calls = self.ctx_with([(7, "", "x")] * 4 + [self.GOOD])
        self.assertIsNone(ctx.openapi_routes())  # two attempts
        self.assertFalse(ctx.route_missing("GET", "/v1/nodes"))  # unreadable: nothing is declared missing
        self.assertEqual(len(calls), 4)  # ... and each question tried again: the failure was not remembered
        self.assertTrue(ctx.route_missing("GET", "/v1/nodes"))  # now it reads, and the route is absent
        self.assertEqual(len(calls), 5)

    def test_a_good_read_is_cached_for_the_run(self):
        ctx, calls = self.ctx_with([self.GOOD])
        for _ in range(4):
            ctx.openapi_routes()
        self.assertEqual(len(calls), 1)

    def test_a_document_without_paths_is_a_failed_read(self):
        ctx, calls = self.ctx_with([(0, json.dumps({"openapi": "3.1.0"}), "")] * 2 + [self.GOOD])
        self.assertIsNone(ctx.openapi_routes())
        self.assertEqual(len(calls), 2)


class SbomInATemporaryCopy(unittest.TestCase):
    def run_sbom(self, write=True):
        import ac12_supply_chain as ac12

        seen = {}

        def handler(argv, stdin):
            if argv[:2] == ["cargo", "cyclonedx"] and "--version" in argv:
                return (0, "cargo-cyclonedx 0.5.7", "")
            if argv[:2] == ["cargo", "cyclonedx"]:
                manifest = Path(argv[argv.index("--manifest-path") + 1])
                seen["manifest"] = manifest
                seen["existed_during"] = manifest.is_file()
                if write:
                    (manifest.parent / "p2pc.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "x"}]}))
                return (0, "", "")
            if argv[:2] == ["git", "-C"] and "ls-files" in argv:
                return (0, "Cargo.toml\0README.md\0does-not-exist-anymore\0", "")
            return (0, "", "")

        ctx, _ = script_ctx(self, handler, '[server]\nexecutor = "local"\n')
        ctx.artifacts_dir = Path(tempfile.mkdtemp(prefix="p2pc-test-art-"))
        self.addCleanup(__import__("shutil").rmtree, ctx.artifacts_dir, True)
        before = sorted(p.name for p in ctx.repo_root.rglob("*.cdx.json") if "target" not in p.parts)
        res = ac12.run(ctx)
        after = sorted(p.name for p in ctx.repo_root.rglob("*.cdx.json") if "target" not in p.parts)
        return next(c for c in res.checks if c.name.startswith("SBOM")), seen, before, after, ctx

    def test_the_sbom_is_generated_in_a_temporary_copy_never_in_the_operators_tree(self):
        chk, seen, before, after, ctx = self.run_sbom()
        self.assertEqual(chk.status, core.PASS, chk.reason)
        self.assertNotIn(ctx.repo_root, seen["manifest"].parents)  # not under the checkout
        self.assertTrue(seen["existed_during"])
        self.assertEqual(before, after)  # no *.cdx.json appeared in the operator's tree
        self.assertFalse(seen["manifest"].exists(), "the temporary copy is removed afterwards")
        self.assertEqual(chk.evidence["files_copied"], 2)  # the file git lists but that is gone is skipped
        self.assertTrue((ctx.artifacts_dir / "p2pc.cdx.json").is_file())  # the evidence is kept in the report

    def test_no_document_is_a_failure(self):
        chk, _, before, after, _ = self.run_sbom(write=False)
        self.assertEqual(chk.status, core.FAIL)
        self.assertEqual(before, after)


class Ac6RenamedCheck(unittest.TestCase):
    def test_the_ledger_check_says_what_it_proves(self):
        text = (HERE / "ac06_node_loss.py").read_text(encoding="utf-8")
        self.assertIn('"the ledger has a row for the job"', text)
        self.assertNotIn('"the ledger has one row per attempt"', text)  # the old name of the check
        self.assertNotIn("has one row per attempt", (HERE / "README.md").read_text(encoding="utf-8"))


class Ac11FromTheTestList(unittest.TestCase):
    """AC-11 reads which tests exist from `cargo test --workspace --all-features -- --list`; nothing is kept here."""

    NODE_TOML = """
    [server]
    executor = "local"
    [node_linux_gpu]
    executor = "local"
    repo_dir = "/srv/p2pc"
    """
    PLAIN = '[server]\nexecutor = "local"\n'

    @staticmethod
    def listing(names_by_target):
        """The merged output of `cargo test -- --list`: a Running header per test binary, then `path: test` lines."""
        out = []
        for target, names in names_by_target.items():
            header = "unittests src/lib.rs" if target == "lib" else f"tests/{target}.rs"
            out.append(f"     Running {header} (target/debug/deps/{target}-0123456789abcdef)")
            out += [f"{n}: test" for n in names]
            out += ["", f"{len(names)} tests, 0 benchmarks"]
        return "\n".join(out) + "\n"

    @staticmethod
    def names_for(pattern):
        """A test name that matches an expected pattern (plain names only; regexes with anchors are the 'future' ones)."""
        return pattern.name if re.fullmatch(r"[A-Za-z0-9_]+", pattern.name or "") else None

    def today(self, drop=(), extra=()):
        """The tests of the product as it is: every expected plain name and target exists, except those in ``drop``."""
        import ac11_security_invariants as ac11

        lib, files = [], {}
        for inv in ac11.INVARIANTS:
            for pat in inv.pats:
                if pat.name in drop or pat.target in drop:
                    continue
                if pat.target:
                    files.setdefault(pat.target, []).append(f"tests::{pat.target}_one")
                elif self.names_for(pat):
                    lib.append(f"module::tests::{pat.name}")
        lib += list(extra)
        return {"lib": lib, **files}

    def handler(self, names_by_target, ignored=(), cargo=None, node_calls=None):
        def handler(argv, stdin):
            if argv[:2] == ["sh", "-c"] and "--list" in argv[2]:
                if "--ignored" in argv:
                    ign = {t: [n for n in ns if n.rsplit("::", 1)[-1] in ignored] for t, ns in names_by_target.items()}
                    return (0, self.listing({t: ns for t, ns in ign.items() if ns}), "")
                return (0, self.listing(names_by_target), "")
            if "cargo" in argv[:-1] and argv[argv.index("cargo") + 1] == "test":
                if cargo:
                    return cargo(argv)
                names = argv[argv.index("--exact") + 1:] if "--exact" in argv else []
                names = [n for n in names if not n.startswith("--")]
                if node_calls is not None and "--include-ignored" in argv:
                    node_calls.append(argv)
                return (0, f"test result: ok. {len(names)} passed; 0 failed; 0 ignored\n", "")
            return preflight_ok(argv, stdin)

        return handler

    class AgentSays:
        """What ``product.Landed(...).agent_connection()`` answers (``p2pc-agent status``): True, False or None."""

        def __init__(self, landed):
            self.landed = landed

        def agent_connection(self):
            return self.landed

    def run_ac11(self, listing, toml=None, routes=(), agent=False, product_landed=None, **kw):
        import ac11_security_invariants as ac11

        ctx, fake = script_ctx(self, self.handler(listing, **kw), toml or self.PLAIN)
        ctx.state["committed_routes"] = set(routes)  # what the committed OpenAPI says has landed
        ctx.state["product_landed"] = product_landed or self.AgentSays(agent)
        res = ac11.run(ctx)
        return res, {c.name.split(":")[0] if c.name.startswith("SI-") else c.name: c for c in res.checks}, fake

    GAPS = ()  # SI-8's `si8_stale_epoch_is_fenced` landed with T06, SI-9's `si9_downloads_refuse_…` with T10b
    SI12_RUNTIME = "si12_runtime_the_running_agent_opens_only_its_iroh_udp_sockets"  # T05b
    SI1_NOT_OWNER = "si1_not_owner_is_refused_before_anything"  # T05b: the owner check is in the agent's connection
    AGENT_CONNECTION_TESTS = (SI12_RUNTIME, SI1_NOT_OWNER)

    def test_what_exists_is_run_and_the_gaps_are_named_with_their_owner(self):
        res, by, _ = self.run_ac11(self.today(), routes={("GET", "/v1/nodes")})
        for si in ("SI-1", "SI-2", "SI-4", "SI-5", "SI-6", "SI-7", "SI-8", "SI-9", "SI-10", "SI-11", "SI-12"):
            self.assertEqual(by[si].status, core.PASS, (si, by[si].reason))
        summary = by["negative tests that do not exist yet"]
        self.assertEqual(summary.status, core.BLOCKED if self.GAPS else core.PASS, summary.reason)
        self.assertEqual(sorted({m.split(":")[0] for m in summary.evidence["missing"]}), sorted(self.GAPS))
        self.assertNotEqual(res.status, core.PASS)

    def test_a_test_that_lands_later_is_picked_up_with_no_edit_when_it_is_named_si_n(self):
        extra = ["fencing::tests::si8_stale_epoch_is_fenced", "gateway::si12_runtime_sockets_of_the_agent"]
        res, by, fake = self.run_ac11(self.today(extra=extra))
        self.assertEqual(by["SI-8"].status, core.PASS, by["SI-8"].reason)
        self.assertEqual(by["SI-12"].status, core.PASS, by["SI-12"].reason)
        ran = [a for a, _ in fake.calls if a[:2] == ["cargo", "test"]]
        self.assertTrue(any("fencing::tests::si8_stale_epoch_is_fenced" in a for a in ran))

    def test_a_naming_convention_match_never_marks_an_owner_landed(self):
        # PR #18: a new `si1_` test (the convention of SI-1) must not make the scheduler "landed", so the missing `si8_`
        # test stays blocked by T06 and never becomes "overdue". Nor does a test that matches SI-8's own convention
        # pattern for another invariant's sake make any sibling overdue. (T06 has landed its SI-8 test since, and T10b
        # its SI-9 server-download test; the product here is one before both, with those tests dropped and the outputs
        # route not in its OpenAPI, so the rule is still exercised: a `si9_` test that is not the expected one leaves
        # SI-9 blocked by its owner, never passing and never overdue.)
        before = ("si8_stale_epoch_is_fenced", "si9_downloads_refuse_traversal_and_planted_links")
        for extra in (["sandbox::driver::tests::si1_another_not_owner_case"],
                      ["sandbox::driver::tests::si1_another_not_owner_case", "x::tests::si9_server_download_traversal"]):
            with self.subTest(extra):
                res, by, _ = self.run_ac11(self.today(drop=before, extra=extra))
                self.assertEqual(by["SI-1"].status, core.PASS, by["SI-1"].reason)
                self.assertEqual((by["SI-8"].status, by["SI-8"].unblocked_by),
                                 (core.BLOCKED, [context.OWNERS["feature scheduler"]]), by["SI-8"].reason)
                self.assertEqual((by["SI-9"].status, by["SI-9"].unblocked_by),
                                 (core.BLOCKED, [context.OWNERS["route GET /v1/jobs/{id}/outputs"]]), by["SI-9"].reason)
                self.assertNotEqual(res.status, core.FAIL, [(c.name, c.status, c.reason) for c in res.checks])
        import ac11_security_invariants as ac11
        from unittest import mock

        # The rule itself: an owner with a convention pattern that matches and an explicit test that does not exist is
        # still only blocked. Counting the convention match would call the missing test overdue.
        si8 = ac11.Invariant("SI-8", "fenced", (ac11.Pat("feature scheduler", name=r"(^|::)si8_"),
                                                ac11.Pat("feature scheduler", name=r"si8_lease_report_after_requeue_is_cancelled")))
        invariants = tuple(si8 if inv.id == "SI-8" else inv for inv in ac11.INVARIANTS)
        listing = self.today(extra=["fencing::tests::si8_stale_epoch_is_fenced"])  # the product: no si8_lease_… test
        with mock.patch.object(ac11, "INVARIANTS", invariants):
            res, by, _ = self.run_ac11(listing)
        self.assertEqual((by["SI-8"].status, by["SI-8"].unblocked_by),
                         (core.BLOCKED, [context.OWNERS["feature scheduler"]]), by["SI-8"].reason)
        self.assertTrue(ac11.Pat("feature scheduler", name=r"(^|::)si8_").is_convention)
        self.assertFalse(ac11.Pat("feature agent-connection", name=r"si1_not_owner_is_refused_before_anything").is_convention)
        self.assertFalse(ac11.Pat("feature gateway", target="no_secrets_in_gateway_logs").is_convention)

    def test_each_test_that_exists_is_run_once_by_its_full_name(self):
        _, _, fake = self.run_ac11(self.today())
        for argv, _stdin in fake.calls:
            if argv[:2] == ["cargo", "test"] and "--exact" in argv:
                names = argv[argv.index("--exact") + 1:]
                self.assertEqual(len(names), len(set(names)))
                self.assertTrue(all("::" in n for n in names if n != "--exact"), names)

    def test_a_missing_test_whose_piece_has_landed_is_a_failure_not_a_gap(self):
        # The nodes route is in the OpenAPI, so the test of the cross-account nodes view is overdue.
        res, by, _ = self.run_ac11(self.today(drop=("another_accounts_nodes_and_tokens_are_invisible",)), routes={("GET", "/v1/nodes")})
        self.assertEqual(by["SI-7"].status, core.FAIL)
        self.assertIn("another_accounts_nodes_and_tokens_are_invisible", by["SI-7"].reason)
        self.assertIn("has landed", by["SI-7"].reason)
        # ... and the same missing test, before the route has landed, is only blocked by the route's owner.
        res, by, _ = self.run_ac11(self.today(drop=("another_accounts_nodes_and_tokens_are_invisible",)), routes=set())
        self.assertEqual((by["SI-7"].status, by["SI-7"].unblocked_by), (core.BLOCKED, [context.OWNERS["route GET /v1/nodes"]]))

    def test_a_renamed_test_is_a_missing_test_never_a_silent_pass(self):
        listing = self.today(drop=("every_deny_range_is_refused_through_the_proxy",))
        listing["lib"].append("egress::tests::every_deny_range_is_refused_somehow_else")
        res, by, _ = self.run_ac11(listing)
        # The egress proxy has landed (its other SI-4/SI-5 tests exist), so a vanished sibling is overdue, not "waiting".
        self.assertEqual(by["SI-4"].status, core.FAIL)
        self.assertIn("every_deny_range_is_refused_through_the_proxy", by["SI-4"].reason)
        self.assertIn("has landed", by["SI-4"].reason)

    def test_the_agents_connection_has_landed_when_the_agent_says_so(self):
        # SI-12's runtime test and SI-1's not_owner test are the agent connection's. When neither is in the --list,
        # nothing of that owner is, so the agent is asked.
        listing = self.today(drop=self.AGENT_CONNECTION_TESTS)
        res, by, _ = self.run_ac11(listing, agent=True)
        self.assertEqual(by["SI-12"].status, core.FAIL, by["SI-12"].reason)
        self.assertIn("has landed", by["SI-12"].reason)
        self.assertIn("si12_runtime", by["SI-12"].reason)
        res, by, _ = self.run_ac11(listing, agent=False)
        self.assertEqual((by["SI-12"].status, by["SI-12"].unblocked_by), (core.BLOCKED, context.owner("feature agent-connection")))
        res, by, _ = self.run_ac11(listing, agent=None)  # the agent cannot be asked: not landed, not failed
        self.assertEqual(by["SI-12"].status, core.BLOCKED)

    def test_si1_belongs_to_the_agent_connection_whose_sibling_test_proves_it_landed(self):
        import ac11_security_invariants as ac11

        si1 = next(inv for inv in ac11.INVARIANTS if inv.id == "SI-1")
        self.assertEqual({p.owner for p in si1.pats}, {"feature agent-connection"})
        # SI-12's runtime test gone, SI-1's still there: the connection has landed without asking the agent, so the
        # missing sibling is overdue.
        res, by, _ = self.run_ac11(self.today(drop=(self.SI12_RUNTIME,)), agent=None)
        self.assertEqual(by["SI-1"].status, core.PASS, by["SI-1"].reason)
        self.assertEqual(by["SI-12"].status, core.FAIL, by["SI-12"].reason)
        self.assertIn("has landed", by["SI-12"].reason)

    def test_the_agent_is_asked_with_status_offline_by_product_landed(self):
        import product

        calls = []

        def run(argv, **kw):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, b"p2pc-agent: connected to the server\n", b"")

        with tempfile.TemporaryDirectory() as d:
            binary = Path(d) / "target" / "debug" / "p2pc-agent"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"x")
            landed = product.Landed(d, run=run, build=False)
            res, by, _ = self.run_ac11(self.today(drop=self.AGENT_CONNECTION_TESTS), product_landed=landed)
        self.assertEqual(calls, [[str(binary), "status"]])
        self.assertEqual(by["SI-12"].status, core.FAIL)

    def test_a_feature_owner_has_landed_when_any_of_its_tests_exists(self):
        # SI-6 (gateway logs) and SI-10 (gateway frames) belong to a `feature` owner: no route says it landed, but a sibling
        # test of the same owner in the --list does.
        for dropped, si in (("no_secrets_in_gateway_logs", "SI-6"),
                            ("unknown_messages_keep_the_connection_and_malformed_frames_close_it", "SI-10")):
            with self.subTest(dropped):
                res, by, _ = self.run_ac11(self.today(drop=(dropped,)))
                self.assertEqual(by[si].status, core.FAIL, by[si].reason)
                self.assertIn(dropped, by[si].reason)
                self.assertIn("has landed", by[si].reason)

    def test_a_feature_owner_with_none_of_its_tests_is_still_only_blocked(self):
        import ac11_security_invariants as ac11

        every = tuple(p.name for inv in ac11.INVARIANTS for p in inv.pats if p.owner == "feature egress-proxy")
        res, by, _ = self.run_ac11(self.today(drop=every))
        for si in ("SI-4", "SI-5"):
            self.assertEqual((by[si].status, by[si].unblocked_by), (core.BLOCKED, context.owner("feature egress-proxy")), si)

    def test_a_test_that_fails_when_run_is_a_failure(self):
        def cargo(argv):
            if any("only_allowlisted_domains_pass_on_whole_labels" in a for a in argv):
                return (101, "test result: FAILED. 0 passed; 1 failed; 0 ignored\n", "")
            names = [n for n in argv[argv.index("--exact") + 1:]]
            return (0, f"test result: ok. {len(names)} passed; 0 failed; 0 ignored\n", "")

        res, by, _ = self.run_ac11(self.today(), cargo=cargo)
        self.assertEqual(by["SI-5"].status, core.FAIL)
        self.assertEqual(res.status, core.FAIL)

    def test_cargo_running_fewer_tests_than_were_listed_is_a_failure(self):
        res, by, _ = self.run_ac11(self.today(), cargo=lambda argv: (0, "test result: ok. 1 passed; 0 failed; 0 ignored\n", ""))
        self.assertEqual(by["SI-6"].status, core.FAIL)
        self.assertIn("ran 1 of the", by["SI-6"].reason)

    def test_an_ignored_test_is_skipped_where_it_cannot_run_and_never_reported_missing(self):
        res, by, _ = self.run_ac11(self.today(), ignored=("si3_network_none_blocks_the_internet",))
        self.assertEqual(by["SI-3"].status, core.SKIP)
        self.assertIn("#[ignore]", by["SI-3"].reason)
        self.assertNotIn("SI-3", " ".join(by["negative tests that do not exist yet"].evidence["missing"]))

    def test_an_ignored_test_runs_with_include_ignored_on_a_node_with_a_checkout(self):
        calls = []
        res, by, _ = self.run_ac11(self.today(), toml=self.NODE_TOML, ignored=("si3_network_none_blocks_the_internet",), node_calls=calls)
        self.assertEqual(by["SI-3"].status, core.PASS, by["SI-3"].reason)
        self.assertEqual(len(calls), 1)
        self.assertIn("/srv/p2pc/Cargo.toml", calls[0])
        self.assertIn("--test-threads=1", calls[0])
        self.assertIn("module::tests::si3_network_none_blocks_the_internet", calls[0])

    PREFIX_TOML = """
    [server]
    executor = "local"
    [node_linux]
    executor = "local"
    repo_dir = "/srv/p2pc"
    test_prefix = ["sudo", "-u", "p2pc", "-H", "sh", "-c", "cd / && exec \\"$@\\"", "p2pc-test"]
    test_env = { P2PC_SHIM = "/srv/p2pc/shim", P2PC_TEST_IMAGE = "example.invalid/img:1" }
    """

    def test_test_prefix_and_test_env_wrap_the_cargo_command_in_that_order(self):
        calls = []
        res, by, _ = self.run_ac11(self.today(), toml=self.PREFIX_TOML, ignored=("si3_network_none_blocks_the_internet",), node_calls=calls)
        self.assertEqual(by["SI-3"].status, core.PASS, by["SI-3"].reason)
        argv = calls[0]
        self.assertEqual(argv[:6], ["sudo", "-u", "p2pc", "-H", "sh", "-c"])
        i = argv.index("env")
        self.assertEqual(argv[i:i + 4], ["env", "P2PC_SHIM=/srv/p2pc/shim", "P2PC_TEST_IMAGE=example.invalid/img:1", "cargo"])
        ev = by["SI-3"].evidence
        self.assertEqual(ev["test_node"], "node_linux")
        self.assertEqual(ev["test_prefix"], "sudo")

    def test_the_prefixed_command_is_prefix_then_env_then_cargo(self):
        import ac11_security_invariants as ac11

        argv = ac11.node_test_argv(["sudo", "x"], {"A": "1", "B": "2"}, ["cargo", "test"])
        self.assertEqual(argv, ["sudo", "x", "env", "A=1", "B=2", "cargo", "test"])
        self.assertEqual(ac11.node_test_argv(["sudo"], {}, ["cargo", "test"]), ["sudo", "cargo", "test"])
        self.assertEqual(ac11.node_test_argv(None, None, ["cargo", "test"]), ["cargo", "test"])
        self.assertEqual(ac11.node_test_argv(None, {"A": "1"}, ["cargo"]), ["env", "A=1", "cargo"])

    def test_a_role_without_the_keys_runs_cargo_exactly_as_before(self):
        calls = []
        res, by, _ = self.run_ac11(self.today(), toml=self.NODE_TOML, ignored=("si3_network_none_blocks_the_internet",), node_calls=calls)
        # T15e review P3 4: the whole argv, as before the keys existed, not just its first two words.
        self.assertEqual(calls[0], [
            "cargo", "test", "--manifest-path", "/srv/p2pc/Cargo.toml", "--workspace", "--all-features", "--",
            "--include-ignored", "--exact", "--test-threads=1", "module::tests::si3_network_none_blocks_the_internet"])
        self.assertNotIn("test_prefix", by["SI-3"].evidence)

    def failing_cargo(self, argv):
        if "--include-ignored" in argv:
            return (101, "test result: FAILED. 0 passed; 1 failed; 0 ignored\n", "")
        return (0, "test result: ok. 1 passed; 0 failed; 0 ignored\n", "")

    def test_a_native_linux_node_with_repo_dir_and_no_prefix_gets_a_hint_on_failure(self):
        toml = self.NODE_TOML.replace("node_linux_gpu", "node_linux")
        res, by, _ = self.run_ac11(self.today(), toml=toml, ignored=("si3_network_none_blocks_the_internet",), cargo=self.failing_cargo)
        self.assertEqual(by["SI-3"].status, core.FAIL)
        self.assertIn("test_prefix", by["SI-3"].reason)

    def test_no_hint_for_a_wsl_role_or_for_a_node_that_has_a_prefix(self):
        for name, toml in (
            ("wsl", self.NODE_TOML.replace("node_linux_gpu", "node_wsl2_gpu")),
            ("prefix", self.PREFIX_TOML),
        ):
            with self.subTest(name):
                res, by, _ = self.run_ac11(self.today(), toml=toml, ignored=("si3_network_none_blocks_the_internet",), cargo=self.failing_cargo)
                self.assertEqual(by["SI-3"].status, core.FAIL)
                self.assertNotIn("hint", by["SI-3"].reason)

    def test_the_failure_names_the_ignored_tests_that_were_run(self):
        # T15e review P3 1: when the node run fails is when the operator most needs to know what ran.
        res, by, _ = self.run_ac11(self.today(), toml=self.NODE_TOML, ignored=("si3_network_none_blocks_the_internet",), cargo=self.failing_cargo)
        self.assertEqual(by["SI-3"].status, core.FAIL)
        self.assertEqual(by["SI-3"].evidence["test_node"], "node_linux_gpu")
        self.assertEqual(by["SI-3"].evidence["ignored_tests"], ["module::tests::si3_network_none_blocks_the_internet"])

    def test_the_skip_for_a_node_without_repo_dir_is_unchanged(self):
        res, by, _ = self.run_ac11(self.today(), ignored=("si3_network_none_blocks_the_internet",))
        self.assertEqual(by["SI-3"].status, core.SKIP)
        self.assertIn("set repo_dir on an enabled node role (a p2pc checkout there) to run them with --include-ignored", by["SI-3"].reason)

    def test_an_ignored_test_that_fails_or_runs_nothing_on_the_node_is_a_failure(self):
        def cargo(passed, failed, rc):
            def run(argv):
                if "--include-ignored" in argv:
                    return (rc, f"test result: {'ok' if rc == 0 else 'FAILED'}. {passed} passed; {failed} failed; 0 ignored\n", "")
                names = argv[argv.index("--exact") + 1:]
                return (0, f"test result: ok. {len(names)} passed; 0 failed; 0 ignored\n", "")
            return run

        for passed, failed, rc, word in ((0, 1, 101, "failed"), (0, 0, 0, "only 0 of 1")):
            res, by, _ = self.run_ac11(self.today(), toml=self.NODE_TOML, ignored=("si3_network_none_blocks_the_internet",),
                                       cargo=cargo(passed, failed, rc))
            self.assertEqual(by["SI-3"].status, core.FAIL, word)
            self.assertIn(word, by["SI-3"].reason)

    def test_the_t05_tests_now_on_main_are_expected(self):
        import ac11_security_invariants as ac11

        wanted = {p.name for inv in ac11.INVARIANTS for p in inv.pats} | {p.target for inv in ac11.INVARIANTS for p in inv.pats}
        for name in (
            "another_accounts_nodes_and_tokens_are_invisible",
            "unknown_messages_keep_the_connection_and_malformed_frames_close_it",
            "an_expired_token_is_refused_even_with_a_forged_later_expiry",
            "revoked_and_wrong_code_tokens_are_refused",
            "a_retry_by_the_same_node_id_is_idempotent_and_others_are_refused",
            "two_concurrent_joins_with_one_token_create_exactly_one_node",
            "no_secrets_in_gateway_logs",
            "secret_hash_stored_format",
            "api_key_hash_and_constant_time_verify",
        ):
            self.assertIn(name, wanted)

    def test_a_listing_that_fails_to_build_is_a_failure_and_a_missing_cargo_a_skip(self):
        import ac11_security_invariants as ac11

        ctx, _ = script_ctx(self, lambda argv, stdin: (101, "error: could not compile `p2pc-agent`\n", "") if argv[:2] == ["sh", "-c"] else preflight_ok(argv, stdin), self.PLAIN)
        first = ac11.run(ctx).checks[0]
        self.assertEqual(first.status, core.FAIL)
        self.assertIn("could not compile", first.reason)
        ctx, _ = script_ctx(self, lambda argv, stdin: (127, "", "sh: cargo: not found") if argv[:2] == ["sh", "-c"] else preflight_ok(argv, stdin), self.PLAIN)
        self.assertEqual(ac11.run(ctx).checks[0].status, core.SKIP)

    def test_the_real_listing_format_is_parsed(self):
        sample = (
            "     Running unittests src/lib.rs (target/debug/deps/p2pc_agent-80c7208a8c0d516a)\n"
            "egress::tests::every_deny_range_is_refused_through_the_proxy: test\n"
            "sandbox::argv::tests::si2_golden_argv_linux: test\n\n2 tests, 0 benchmarks\n"
            "     Running unittests src/main.rs (target/debug/deps/p2pc_agent-93579be83a34d6fe)\n\n0 tests, 0 benchmarks\n"
            "     Running tests/podman_real.rs (target/debug/deps/podman_real-3caa363da8051c83)\n"
            "si3_network_none_blocks_the_internet: test\n\n1 test, 0 benchmarks\n"
            "   Doc-tests p2pc_agent\n\n0 tests, 0 benchmarks\n"
        )
        tests = product.parse_test_list(sample)
        self.assertEqual([(t.name, t.target_stem) for t in tests], [
            ("egress::tests::every_deny_range_is_refused_through_the_proxy", "lib"),
            ("sandbox::argv::tests::si2_golden_argv_linux", "lib"),
            ("si3_network_none_blocks_the_internet", "podman_real"),
        ])
        ignored = product.parse_test_list("     Running tests/podman_real.rs (x)\nsi3_network_none_blocks_the_internet: test\n", ignored=True)
        merged = product.merge_lists(tests, ignored)
        self.assertEqual([t.ignored for t in merged], [False, False, True])


class RestGetKeepsTheStatus(unittest.TestCase):
    def get(self, body, status=200, route=None, expect_ok=False, openapi=None):
        def handler(argv, stdin):
            if argv[:1] == ["curl"]:
                url = (stdin or b"").decode()
                if "/v1/openapi.json" in url:
                    return (0, json.dumps({"paths": openapi or {}}), "")
                # a real curl with -w "\n%{http_code}": the body, a newline and the status
                return (0, f"{body}\n{status}", "")
            return preflight_ok(argv, stdin)

        ctx, fake = make_ctx(handler, environ={"TEST_ADMIN_KEY": FAKE_KEY})
        ctx.begin("AC-X", "t")
        return ctx, ctx.rest_get("server", "/v1/server", route=route, expect_ok=expect_ok)

    def test_a_2xx_is_exit_0_with_the_body_alone(self):
        ctx, step = self.get('{"address": "p2pc_srv_X"}')
        self.assertEqual((step.exit_code, step.parsed_stdout()), (0, {"address": "p2pc_srv_X"}))

    def test_any_other_status_is_exit_22_with_the_error_in_the_shape_p2pc_prints(self):
        problem = json.dumps({"type": "about:blank", "title": "Not Found", "status": 404, "code": "not_found", "detail": "x"})
        ctx, step = self.get(problem, 404)
        self.assertEqual(step.exit_code, 22)
        err = step.error_json()
        self.assertEqual((err["kind"], err["status"], err["code"]), ("api", 404, "not_found"))
        self.assertEqual(step.route_status(), 404)

    def test_a_404_for_a_route_the_openapi_lacks_is_blocked_by_its_owner_like_any_p2pc_call(self):
        problem = json.dumps({"title": "Not Found", "status": 404, "code": "not_found"})
        with self.assertRaises(core.Blocked) as cm:
            ctx, step = self.get(problem, 404, route=("GET", "/v1/server"), openapi={"/v1/jobs": {"get": {}}})
        self.assertEqual(cm.exception.unblocked_by, [context.OWNERS["route GET /v1/server"]])

    def test_the_same_404_when_the_route_exists_is_a_failure_with_the_code(self):
        problem = json.dumps({"title": "Not Found", "status": 404, "code": "not_found"})
        with self.assertRaises(core.CheckFailed) as cm:
            self.get(problem, 404, route=("GET", "/v1/server"), expect_ok=True, openapi={"/v1/server": {"get": {}}})
        self.assertIn("not_found", cm.exception.reason)

    def test_a_500_with_a_plain_body_is_still_an_error_step(self):
        ctx, step = self.get("oops", 500)
        self.assertEqual((step.exit_code, step.error_json()["status"]), (22, 500))


class LandedOffline(unittest.TestCase):
    """`./run.py --list`: what has landed, asked of the repository's own build."""

    def repo(self, routes=(), with_binaries=True):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root = Path(d.name)
        (root / "docs" / "api").mkdir(parents=True)
        paths = {}
        for method, path in routes:
            paths.setdefault(path, {})[method.lower()] = {}
        (root / "docs" / "api" / "openapi.json").write_text(json.dumps({"paths": paths}))
        if with_binaries:
            (root / "target" / "debug").mkdir(parents=True)
            for name in ("p2pc", "p2pc-agent"):
                (root / "target" / "debug" / name).write_text("")
        return root

    @staticmethod
    def runner(agent_status=b"not implemented yet\n", agent_code=2, logs_stub=True):
        calls = []

        def run(argv, **kw):
            calls.append(argv)
            name = Path(argv[0]).name
            if name == "p2pc":
                help_text = TODAY_P2PC_HELP if logs_stub else TODAY_P2PC_HELP.replace(" (not available in this version yet)", "")
                return subprocess.CompletedProcess(argv, 0, help_text.encode(), b"")
            if name == "p2pc-agent":
                return subprocess.CompletedProcess(argv, agent_code, b"", agent_status)
            raise AssertionError(argv)

        run.calls = calls
        return run

    def test_routes_come_from_the_committed_openapi_and_subcommands_from_help(self):
        root = self.repo(routes=[("GET", "/v1/nodes"), ("GET", "/v1/jobs/{job_id}/logs")])
        landed = product.Landed(root, run=self.runner(), build=False)
        self.assertIs(landed.landed("route GET /v1/nodes"), True)
        self.assertIs(landed.landed("route GET /v1/jobs/{id}/logs"), True)  # parameter names do not matter
        self.assertIs(landed.landed("route GET /v1/usage"), False)
        self.assertIs(landed.landed("feature scheduler"), False)  # its marker is GET /v1/usage
        self.assertIs(landed.landed("cli whoami"), True)
        self.assertIs(landed.landed("cli logs"), False)  # a stub says so in its description
        self.assertIs(landed.landed("cli proxy"), False)

    def test_when_a_task_lands_the_answer_changes_with_no_edit(self):
        before = product.Landed(self.repo(), run=self.runner(), build=False)
        self.assertEqual((before.landed("feature scheduler"), before.landed("cli logs"), before.landed("feature agent-connection")),
                         (False, False, False))
        after = product.Landed(
            self.repo(routes=[("GET", "/v1/usage")]),
            run=self.runner(agent_status=b"", agent_code=0, logs_stub=False),
            build=False,
        )
        self.assertEqual((after.landed("feature scheduler"), after.landed("cli logs"), after.landed("feature agent-connection")),
                         (True, True, True))

    def test_what_has_no_marker_or_cannot_be_asked_is_none(self):
        landed = product.Landed(self.repo(with_binaries=False), run=self.runner(), build=False)
        self.assertIsNone(landed.landed("cli logs"))  # no binary to ask
        self.assertIsNone(landed.landed("feature agent-connection"))
        self.assertIsNone(landed.landed("feature executor"))  # nothing in the product says so
        self.assertIsNone(landed.landed("feature gateway"))

    def test_with_no_build_the_newer_of_release_and_debug_is_asked_never_a_stale_release(self):
        # T15a review P3: `target/release` was preferred over `target/debug` whatever their age.
        import os

        root = self.repo()
        (root / "target" / "release").mkdir(parents=True)
        for name in ("p2pc", "p2pc-agent"):
            os.utime(root / "target" / "debug" / name, (2_000_000_000, 2_000_000_000))
            (root / "target" / "release" / name).write_text("")
            os.utime(root / "target" / "release" / name, (1_000_000_000, 1_000_000_000))
        run = self.runner()
        product.Landed(root, run=run, build=False).landed("cli logs")
        self.assertEqual([Path(c[0]).parent.name for c in run.calls], ["debug"])
        for name in ("p2pc", "p2pc-agent"):
            os.utime(root / "target" / "release" / name, (3_000_000_000, 3_000_000_000))
        run = self.runner()
        product.Landed(root, run=run, build=False).landed("cli logs")
        self.assertEqual([Path(c[0]).parent.name for c in run.calls], ["release"])

    def test_when_the_harness_builds_it_asks_the_binary_that_build_produced(self):
        import os

        root = self.repo()
        (root / "target" / "release").mkdir(parents=True)
        for name in ("p2pc", "p2pc-agent"):
            (root / "target" / "release" / name).write_text("")
            os.utime(root / "target" / "release" / name, (3_000_000_000, 3_000_000_000))  # newer, and stale for the sources
            os.utime(root / "target" / "debug" / name, (1_000_000_000, 1_000_000_000))  # a no-op build leaves it as it is
        base = self.runner()

        def run(argv, **kw):
            if argv[0] == "cargo":
                run.calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            return base(argv, **kw)

        run.calls = []
        product.Landed(root, run=run, build=True).landed("cli logs")
        self.assertEqual(run.calls[0][:2], ["cargo", "build"])
        self.assertNotIn("--release", run.calls[0])
        self.assertEqual([Path(c[0]).parent.name for c in base.calls], ["debug"])  # the build's own, not the stale release
        # A build that fails falls back to whatever is there, the newer of the two.
        base2 = self.runner()

        def failing(argv, **kw):
            if argv[0] == "cargo":
                return subprocess.CompletedProcess(argv, 101, b"", b"error")
            return base2(argv, **kw)

        product.Landed(root, run=failing, build=True).landed("cli logs")
        self.assertEqual([Path(c[0]).parent.name for c in base2.calls], ["release"])

    def test_the_installer_is_the_script_being_there(self):
        root = self.repo()
        landed = product.Landed(root, run=self.runner(), build=False)
        self.assertIs(landed.landed("feature installer"), False)
        (root / "deploy" / "linux").mkdir(parents=True)
        (root / "deploy" / "linux" / "install-server.sh").write_text("#!/bin/sh\n")
        self.assertIs(product.Landed(root, run=self.runner(), build=False).landed("feature installer"), True)

    def test_list_prints_the_table_read_from_the_product(self):
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = runner.main(["--list", "--no-build"])
        self.assertEqual(code, 0)
        rows = [ln for ln in buf.getvalue().splitlines() if ln.startswith("| AC-")]
        self.assertEqual(len(rows), 12)
        self.assertIn("nothing", rows[11])  # AC-12 needs nothing


class HelpParsing(unittest.TestCase):
    def test_the_commands_section_of_the_real_help(self):
        got = product.parse_help_commands(TODAY_P2PC_HELP)
        self.assertEqual(got["logs"], True)
        self.assertEqual(got["run"], False)
        self.assertEqual(got["join-token"], False)
        self.assertNotIn("help", got)
        self.assertEqual(product.parse_help_commands("no commands here"), {})

    def test_the_agent_help_has_no_stub_phrases_so_the_agent_is_asked_with_status(self):
        agent = "Usage: p2pc-agent\n\nCommands:\n  run   Run the agent daemon\n  join  Enroll this machine\n  status  Show the agent's state\n\nOptions:\n"
        self.assertEqual(product.parse_help_commands(agent), {"run": False, "join": False, "status": False})


class Ac1WslStepsAreInOrder(unittest.TestCase):
    """ACC-1: the step that installs the WSL2 distro ran its preflight INSIDE the distro, which does not exist yet, so the
    step that would create it never ran. The image step now checks the Windows host; the distro comes after."""

    TOKEN = Ac1JoinToken.TOKEN
    TOML = Ac1Installers.TOML
    simulate = Ac1Installers.simulate
    WIN_IMAGE = Ac1Installers.WIN_IMAGE
    WIN_INSTALL = Ac1Installers.WIN_INSTALL
    WIN_JOIN = Ac1Installers.WIN_JOIN

    def machine(self, *, distro_exists, host_ok=True, probe_times_out=False, probe_error=False):
        """The Windows role gets its own scripted machine: commands in the distro fail (exit 255, wsl.exe) until the
        distro exists, and `install.ps1 -Tar` is what makes it exist."""
        ctx, fake = self.simulate()
        shared = fake.handler
        state = {"distro": distro_exists}
        order: list[tuple[str, str]] = []
        win = FakeExecutor()

        def handler(argv, stdin):
            if argv[0] == "<powershell>":
                script = argv[1]
                order.append(("host", script))
                if not host_ok:
                    return (255, "", "ssh: connect to host win-box port 22: Connection refused\n")
                if "-Tar" in script:
                    state["distro"] = True
                if "wsl.exe" in script and "--exec" in script:
                    if probe_error:
                        return executors.ExecResult(None, error="cannot start ssh: No such file or directory")
                    if probe_times_out:
                        return executors.ExecResult(None, timed_out=True)
                    return (0, "", "") if state["distro"] else (255, "", "")
                return shared(argv, stdin)
            order.append(("distro", argv[0]))
            if not state["distro"]:
                return (255, "", "** The server may need to be upgraded. See https://openssh.com/pq.html\n")
            return shared(argv, stdin)

        win.handler = handler
        ctx._executor_factory = lambda role: win if role.name == "node_wsl2_gpu" else fake
        return ctx, order

    def checks(self, ctx):
        import ac01_install

        return {c.name: c for c in ac01_install.run(ctx).checks}

    def test_no_distro_and_an_image_command_the_image_step_runs_first_then_the_distro_is_used_and_join_runs(self):
        ctx, order = self.machine(distro_exists=False)
        by = self.checks(ctx)
        self.assertEqual(by[self.WIN_IMAGE].status, core.PASS, by[self.WIN_IMAGE].reason)
        self.assertEqual(by[self.WIN_INSTALL].status, core.PASS, by[self.WIN_INSTALL].reason)
        self.assertEqual(by[self.WIN_JOIN].status, core.PASS, by[self.WIN_JOIN].reason)
        host = [i for i, (kind, _) in enumerate(order) if kind == "host"]
        first_distro = next(i for i, (kind, _) in enumerate(order) if kind == "distro")
        tar = next(i for i in host if "-Tar" in order[i][1])
        join = next(i for i in host if "-Join" in order[i][1])
        self.assertLess(host[0], tar)  # the Windows host is checked first...
        self.assertNotIn("-Tar", order[host[0]][1])
        self.assertLess(tar, first_distro)  # ...nothing runs in the distro before the image is installed...
        self.assertLess(first_distro, join)  # ...and the distro is checked before -Join

    def test_no_distro_and_no_image_command_says_what_to_do(self):
        ctx, _ = self.machine(distro_exists=False)
        ctx.machines.roles["node_wsl2_gpu"].extra.pop("image_install_command")
        by = self.checks(ctx)
        self.assertEqual(by[self.WIN_IMAGE].status, core.FAIL)
        self.assertIn("the distro p2pc-node does not exist: set image_install_command, or install it", by[self.WIN_IMAGE].reason)

    def test_a_probe_that_times_out_does_not_say_the_distro_is_missing(self):
        # T15d review P3 2: a distro that is slow to boot is not a distro that does not exist.
        ctx, _ = self.machine(distro_exists=True, probe_times_out=True)
        ctx.machines.roles["node_wsl2_gpu"].extra.pop("image_install_command")
        by = self.checks(ctx)
        self.assertEqual(by[self.WIN_IMAGE].status, core.FAIL)
        self.assertIn("timed out", by[self.WIN_IMAGE].reason)
        self.assertNotIn("does not exist", by[self.WIN_IMAGE].reason)

    def test_the_boot_hint_is_only_for_a_timeout_not_for_a_probe_that_could_not_run(self):
        # T15f P3: ssh that does not start is not a slow boot.
        for kw, hint in (({"probe_times_out": True}, True), ({"probe_error": True}, False)):
            ctx, _ = self.machine(distro_exists=True, **kw)
            ctx.machines.roles["node_wsl2_gpu"].extra.pop("image_install_command")
            reason = self.checks(ctx)[self.WIN_IMAGE].reason
            self.assertIn("could not tell", reason)
            self.assertEqual("slow to boot" in reason, hint, reason)

    def test_a_missing_distro_reports_the_exit_code_of_the_probe(self):
        ctx, _ = self.machine(distro_exists=False)
        ctx.machines.roles["node_wsl2_gpu"].extra.pop("image_install_command")
        by = self.checks(ctx)
        self.assertIn("exit 255", by[self.WIN_IMAGE].reason)

    def test_an_existing_distro_and_no_image_command_is_still_a_skip(self):
        ctx, _ = self.machine(distro_exists=True)
        ctx.machines.roles["node_wsl2_gpu"].extra.pop("image_install_command")
        by = self.checks(ctx)
        self.assertEqual(by[self.WIN_IMAGE].status, core.SKIP)
        self.assertEqual(by[self.WIN_JOIN].status, core.PASS, by[self.WIN_JOIN].reason)

    def test_an_unreachable_windows_host_is_reported_as_the_host_with_the_real_ssh_error(self):
        ctx, order = self.machine(distro_exists=False, host_ok=False)
        by = self.checks(ctx)
        self.assertEqual(by[self.WIN_IMAGE].status, core.FAIL)
        self.assertIn("Windows host", by[self.WIN_IMAGE].reason)
        self.assertIn("Connection refused", by[self.WIN_IMAGE].reason)
        self.assertEqual(order[0][0], "host")  # the image step looked at the host, and only the host, first


class SshFailureReasons(unittest.TestCase):
    """ACC-1: the reason for a failed ssh call was OpenSSH's post-quantum warning, which hid the real error."""

    WARNING = (
        "** WARNING: connection is not using a post-quantum key exchange algorithm.\n"
        "** This session may be vulnerable to \"store now, decrypt later\" attacks.\n"
        "** The server may need to be upgraded. See https://openssh.com/pq.html\n"
    )

    def test_the_clients_warning_lines_are_dropped_and_the_real_error_is_the_reason(self):
        for stderr in (self.WARNING + "ssh: connect to host win-box port 22: Connection refused\n",
                       "ssh: connect to host win-box port 22: Connection refused\n" + self.WARNING):
            self.assertEqual(core.last_line(stderr), "ssh: connect to host win-box port 22: Connection refused")

    def test_a_line_that_merely_contains_stars_is_kept(self):
        self.assertEqual(core.last_line("error: a ** b\n"), "error: a ** b")

    def test_only_warnings_leave_no_reason_and_exit_255_is_explained(self):
        ctx, _ = make_ctx(lambda argv, stdin: (255, "", self.WARNING), toml=ROLES_TOML)
        with self.assertRaises(core.CheckFailed) as caught:
            ctx.require("node_linux_gpu")
        message = str(caught.exception)
        self.assertIn("ssh or wsl.exe failed", message)
        self.assertNotIn("openssh.com/pq", message)

    def test_exit_255_with_a_real_error_shows_both(self):
        ctx, _ = make_ctx(lambda argv, stdin: (255, "", self.WARNING + "Permission denied (publickey).\n"), toml=ROLES_TOML)
        with self.assertRaises(core.CheckFailed) as caught:
            ctx.require("node_linux_gpu")
        self.assertIn("Permission denied (publickey).", str(caught.exception))
        self.assertIn("ssh or wsl.exe failed", str(caught.exception))


SS_MIXED = """\
LISTEN 0 4096 127.0.0.1:7477 0.0.0.0:* users:(("p2pc-server",pid=812,fd=9)) uid:996 ino:1 sk:a
LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3)) uid:0 ino:2 sk:b
LISTEN 0 4096 172.17.0.1:53 0.0.0.0:* users:(("dockerd",pid=5,fd=3)) uid:0 ino:3 sk:c
LISTEN 0 4096 100.64.0.7:44434 0.0.0.0:* users:(("tailscaled",pid=6,fd=3)) uid:0 ino:4 sk:d
LISTEN 0 4096 [fd7a:115c:a1e0::1]:54558 [::]:* users:(("tailscaled",pid=6,fd=4)) uid:0 ino:5 sk:e
LISTEN 0 128 192.0.2.5:3000 0.0.0.0:* users:(("node",pid=9,fd=3)) uid:1000 ino:6 sk:f
LISTEN 0 128 127.0.0.1:9100 0.0.0.0:* users:(("conmon",pid=40,fd=3)) uid:995 ino:7 sk:g
LISTEN 0 128 0.0.0.0:9000 0.0.0.0:* uid:995 ino:8 sk:h
LISTEN 0 128 0.0.0.0:631 0.0.0.0:* ino:9 sk:i
garbage
"""


class ListeningSockets(unittest.TestCase):
    """ACC-1: AC-8 counted every socket on the machine (Docker, Tailscale, the other WSL2 distros). Only P2PC's count."""

    def test_the_parser_reads_address_port_process_and_uid(self):
        got = {(l.host, l.port): (l.process, l.uid) for l in flows.parse_listeners(SS_MIXED)}
        self.assertEqual(got[("127.0.0.1", 7477)], ("p2pc-server", 996))
        self.assertEqual(got[("fd7a:115c:a1e0::1", 54558)], ("tailscaled", 0))
        self.assertEqual(got[("0.0.0.0", 9000)], (None, 995))  # `ss -e` without root: the uid, no process name
        self.assertEqual(got[("0.0.0.0", 631)], (None, None))
        self.assertEqual(len(got), 9)  # `garbage` is skipped

    def test_only_p2pcs_own_processes_and_users_are_kept(self):
        mine = flows.p2pc_listeners(flows.parse_listeners(SS_MIXED), uids={995, 996})
        self.assertEqual([(l.host, l.port) for l in mine],
                         [("127.0.0.1", 7477), ("127.0.0.1", 9100), ("0.0.0.0", 9000)])

    def test_the_process_name_alone_is_enough_without_the_uids(self):
        mine = flows.p2pc_listeners(flows.parse_listeners(SS_MIXED), uids=set())
        self.assertEqual([(l.host, l.port) for l in mine], [("127.0.0.1", 7477)])

    def test_in_a_wsl2_distro_the_sockets_with_a_process_of_the_distro_are_kept(self):
        # The distros share one network namespace, but `ss -p` names only the processes it can see: this distro's.
        mine = flows.p2pc_listeners(flows.parse_listeners(SS_MIXED), uids=set(), any_process=True)
        self.assertNotIn(("0.0.0.0", 631), [(l.host, l.port) for l in mine])
        self.assertNotIn(("0.0.0.0", 9000), [(l.host, l.port) for l in mine])  # no process: another distro's
        self.assertIn(("172.17.0.1", 53), [(l.host, l.port) for l in mine])

    def test_exposed_means_tcp_on_a_non_loopback_address_outside_the_allowed_ports(self):
        mine = flows.p2pc_listeners(flows.parse_listeners(SS_MIXED), uids={995, 996})
        self.assertEqual(flows.exposed_listeners(mine, [22]), ["0.0.0.0:9000"])
        self.assertEqual(flows.exposed_listeners(mine, [22, 9000]), [])
        self.assertEqual(flows.exposed_listeners([], [22]), [])

    def test_a_port_the_owner_allows_is_not_exposed(self):
        listeners = flows.parse_listeners("LISTEN 0 128 192.0.2.5:3000 0.0.0.0:* users:((\"p2pc-agent\",pid=1,fd=3)) uid:995\n")
        self.assertEqual(flows.exposed_listeners(listeners, [22]), ["192.0.2.5:3000"])
        self.assertEqual(flows.exposed_listeners(listeners, [22, 3000]), [])


class Ac8ListeningCheck(unittest.TestCase):
    TOML = """
    [server]
    executor = "local"
    admin_key_env = "TEST_ADMIN_KEY"
    [node_linux]
    executor = "local"
    [node_wsl2_gpu]
    executor = "wsl_over_ssh"
    host = "win-box"
    distro = "p2pc-node"
    """
    TCP_OK = (
        'LISTEN 0 4096 127.0.0.1:7477 0.0.0.0:* users:(("p2pc-server",pid=812,fd=9)) uid:996 ino:1\n'
        'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3)) uid:0 ino:2\n'
        'LISTEN 0 4096 172.17.0.1:53 0.0.0.0:* uid:0 ino:3\n'
        'LISTEN 0 4096 100.64.0.7:44434 0.0.0.0:* uid:0 ino:4\n'
        'LISTEN 0 4096 [fd7a:115c:a1e0::1]:54558 [::]:* uid:0 ino:5\n'
    )
    UDP = (
        'UNCONN 0 0 0.0.0.0:41234 0.0.0.0:* users:(("p2pc-agent",pid=77,fd=6)) uid:995 ino:11\n'
        'UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("avahi-daemon",pid=3,fd=12)) uid:0 ino:12\n'
        'UNCONN 0 0 0.0.0.0:41641 0.0.0.0:* uid:0 ino:13\n'
    )

    def run_check(self, role, tcp, udp=None, sudo=False, uids=True, toml=None, plain=None):
        import ac08_remote_client

        calls = []

        def handler(argv, stdin):
            if argv[:1] == ["pgrep"]:
                return (0, "77\n", "")
            if argv[:2] == ["id", "-u"]:
                return (0, {"p2pc": "995\n", "p2pc-server": "996\n"}[argv[2]], "") if uids else (1, "", "id: 'x': no such user")
            ss = argv[1:] if argv[:1] == ["sudo"] else argv
            if ss[:1] == ["ss"] or argv[:2] == ["sudo", "-n"]:
                calls.append(argv)
                if argv[:1] == ["sudo"] and not sudo:
                    return (1, "", "sudo: a password is required\n")
                out = tcp if "-ltnpe" in " ".join(ss) or "-lt" in " ".join(ss) else (self.UDP if udp is None else udp)
                if plain is not None and argv[:1] == ["ss"] and "-ltnpe" in " ".join(ss):
                    out = plain  # what the plain (no sudo) ss says, when it must differ from the sudo one
                return (0, out, "")
            return preflight_ok(argv, stdin)

        ctx, _ = script_ctx(self, handler, toml or self.TOML, environ={"TEST_ADMIN_KEY": FAKE_KEY})
        res = ac08_remote_client.run(ctx)
        check = next(c for c in res.checks if c.name == f"{role}: no listening port reachable from outside")
        return check, calls

    def test_sockets_that_are_not_p2pcs_do_not_count(self):
        check, _ = self.run_check("server", self.TCP_OK)
        self.assertEqual(check.status, core.PASS, check.reason)

    def test_the_iroh_udp_sockets_are_allowed_and_named_in_the_evidence(self):
        check, _ = self.run_check("node_linux", self.TCP_OK)
        self.assertEqual(check.status, core.PASS, check.reason)
        self.assertEqual(check.evidence["p2pc_udp_sockets"], ["0.0.0.0:41234 (p2pc-agent)"])
        self.assertEqual(check.evidence["ignored_non_p2pc_sockets"], 6)  # a count: the sockets of other services

    def test_a_p2pc_tcp_listener_on_a_non_loopback_address_fails_even_among_the_noise(self):
        tcp = self.TCP_OK + 'LISTEN 0 128 0.0.0.0:9000 0.0.0.0:* users:(("p2pc-agent",pid=77,fd=5)) uid:995 ino:8\n'
        check, _ = self.run_check("node_linux", tcp)
        self.assertEqual(check.status, core.FAIL)
        self.assertIn("0.0.0.0:9000", check.reason)
        self.assertNotIn("172.17.0.1", check.reason)
        self.assertNotIn("100.64.0.7", check.reason)

    def test_the_owners_allowed_ports_are_kept(self):
        tcp = 'LISTEN 0 128 0.0.0.0:9000 0.0.0.0:* users:(("p2pc-agent",pid=77,fd=5)) uid:995 ino:8\n'
        check, _ = self.run_check("node_linux", tcp, toml=self.TOML.replace(
            '[node_linux]\n    executor = "local"', '[node_linux]\n    executor = "local"\n    allowed_listen_ports = [22, 9000]'))
        self.assertEqual(check.status, core.PASS, check.reason)

    def test_sudo_is_used_when_it_works_and_the_uids_from_ss_e_when_it_does_not(self):
        # T15d review P3 3: the two paths answer DIFFERENTLY, so the result shows which one was used.
        exposed = 'LISTEN 0 128 0.0.0.0:9000 0.0.0.0:* uid:995 ino:8\n'
        check, calls = self.run_check("server", self.TCP_OK, sudo=True, plain=self.TCP_OK + exposed)
        self.assertEqual(check.status, core.PASS, check.reason)  # the sudo output (clean) was the one used
        self.assertIn(["sudo", "-n", "ss", "-H", "-ltnpe"], calls)
        # Without sudo the p2pc user's sockets are found by their uid, whatever `ss` can say of the process.
        check, calls = self.run_check("node_linux", self.TCP_OK + exposed, sudo=False)
        self.assertEqual(check.status, core.FAIL)
        self.assertIn("0.0.0.0:9000", check.reason)
        self.assertIn(["sudo", "-n", "ss", "-H", "-ltnpe"], calls)  # tried first
        self.assertIn(["ss", "-H", "-ltnpe"], calls)  # then the plain one

    def test_a_p2pc_udp_socket_on_a_well_known_non_quic_port_fails(self):
        # T15d review P3 1: P2PC on UDP 5353 (mDNS) is not iroh's outbound QUIC and must not be labelled as such.
        udp = self.UDP + 'UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("p2pc-agent",pid=77,fd=7)) uid:995 ino:14\n'
        check, _ = self.run_check("node_linux", self.TCP_OK, udp=udp)
        self.assertEqual(check.status, core.FAIL)
        self.assertIn("5353", check.reason)

    def test_in_the_wsl2_distro_there_is_no_sudo_and_other_distros_sockets_are_ignored(self):
        tcp = (
            'LISTEN 0 4096 127.0.0.1:7478 0.0.0.0:* users:(("p2pc-agent",pid=77,fd=9)) uid:0 ino:1\n'
            'LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* ino:2\n'  # another distro: no process visible here
        )
        only_wsl = '[node_wsl2_gpu]\nexecutor = "wsl_over_ssh"\nhost = "win-box"\ndistro = "p2pc-node"\n'
        check, calls = self.run_check("node_wsl2_gpu", tcp, toml=only_wsl)
        self.assertEqual(check.status, core.PASS, check.reason)
        self.assertTrue(calls)
        self.assertFalse(any(c[:1] == ["sudo"] for c in calls))


class ExampleLinuxPodman(unittest.TestCase):
    """ACC-1: `sudo -u p2pc -H sh -c ...` starts in the ssh user's home, which p2pc cannot read (0700 on Arch, 0750 on
    Ubuntu): podman then ends with "cannot chdir"."""

    def test_the_example_command_changes_to_the_root_directory_first(self):
        podman = machines.load_machines(HERE / "machines.example.toml").roles["node_linux"].get("podman")
        self.assertEqual(podman[:6], ["sudo", "-u", "p2pc", "-H", "sh", "-c"])
        script = podman[6]
        self.assertTrue(script.startswith("cd / && "), script)
        self.assertIn("XDG_RUNTIME_DIR=/run/user/$(id -u) exec podman", script)

    def test_the_readme_says_the_same(self):
        text = (HERE / "README.md").read_text(encoding="utf-8")
        self.assertIn("cd / && XDG_RUNTIME_DIR", text)


class ToolsOnThePath(unittest.TestCase):
    def test_the_missing_tools_are_the_ones_which_cannot_find(self):
        have = {"gitleaks": "/usr/bin/gitleaks", "cargo-deny": None, "cargo-cyclonedx": None}
        self.assertEqual(criteria.missing_tools(have.get), ["cargo-deny", "cargo-cyclonedx"])
        self.assertEqual(criteria.missing_tools(lambda name: "/bin/" + name), [])

    def test_list_names_the_missing_tools_and_the_criterion_that_needs_them(self):
        import contextlib
        import io
        from unittest import mock

        buf = io.StringIO()
        with mock.patch.object(criteria, "missing_tools", lambda which=None: ["gitleaks"]), contextlib.redirect_stdout(buf):
            self.assertEqual(runner.main(["--list", "--no-build"]), 0)
        self.assertRegex(buf.getvalue(), r"(?i)not on the PATH.*gitleaks")
        self.assertIn("AC-12", buf.getvalue().split("not on the PATH", 1)[1])

    def test_list_says_nothing_when_all_are_there(self):
        import contextlib
        import io
        from unittest import mock

        buf = io.StringIO()
        with mock.patch.object(criteria, "missing_tools", lambda which=None: []), contextlib.redirect_stdout(buf):
            runner.main(["--list", "--no-build"])
        self.assertNotIn("not on the PATH", buf.getvalue())

    def test_the_readme_lists_the_three_tools(self):
        text = (HERE / "README.md").read_text(encoding="utf-8")
        for tool in ("gitleaks", "cargo-deny", "cargo-cyclonedx"):
            self.assertRegex(text, rf"(?s)on the PATH.{{0,300}}{tool}|{tool}.{{0,300}}on the PATH")


if __name__ == "__main__":
    unittest.main()
