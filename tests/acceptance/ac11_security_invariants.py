# SPDX-License-Identifier: Apache-2.0
"""AC-11: negative tests for SI-1 to SI-12 pass; an internal pentest from a separate machine finds no critical issue.

The negative tests of spec §13 are `cargo test` tests. Which of them exist is read from `cargo test --workspace
--all-features -- --list`, not from a list kept here: each invariant has expected test NAME PATTERNS, and

* a pattern that matches is run (those that exist are run, exactly once each, by their full name);
* a matching test that is `#[ignore]`d is run with `-- --include-ignored` on a node role that sets `repo_dir` (a p2pc
  checkout there), and is a `skip` ("exists, ignored") where there is none: it is never reported missing;
* only a pattern with no match at all is missing. If the piece it tests has landed (read from the committed OpenAPI
  document), its test is overdue and that is a `fail`; otherwise the check is `blocked` by the owner in
  `context.OWNERS`.

Convention for tests that land later: the test **function name must start with `si<N>_`**, for example
`si8_stale_epoch_is_fenced`, because cargo's filters match the function's path (module path and name) and not the file
it lives in. Every such test is run without any change here; the required patterns below name what each invariant
needs at least."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import context
import core
import flows
import product

ID = "AC-11"
TITLE = "Security invariants SI-1 to SI-12 and pentest"
SPEC = "Negative tests for SI-1 to SI-12 pass. An internal pentest from a separate machine finds no critical issue."
ROLES: tuple[str, ...] = ()
# What this criterion needs, as keys of context.OWNERS: the table of the README shows the owners of those not landed yet.
NEEDS = (
    "route GET /v1/nodes",
    "feature scheduler",
    "feature agent-connection",
    "route GET /v1/jobs/{id}/outputs",
)


@dataclass(frozen=True)
class Pat:
    """An expected negative test: a regex searched in the test's full path (``module::name``) and/or the stem of the
    test file it lives in, and who brings it if it does not exist (a key of ``context.OWNERS``)."""

    owner: str
    name: str = ""
    target: str = ""

    def matches(self, test: product.ListedTest) -> bool:
        if self.target and test.target_stem != self.target:
            return False
        return bool(re.search(self.name, test.name)) if self.name else bool(self.target)

    @property
    def is_convention(self) -> bool:
        """Whether this is a naming-convention pattern (``(^|::)si<N>_…``) rather than an explicit test name or file.
        A convention match is evidence that the invariant has a test, never that its owner has landed: any later
        test named ``si<N>_`` would otherwise mark that owner landed and make its other tests "overdue"."""
        return self.name.startswith("(^|::)si")

    def label(self) -> str:
        return " ".join(x for x in (f"in tests/{self.target}.rs" if self.target else "", self.name and f"/{self.name}/") if x)


@dataclass(frozen=True)
class Invariant:
    id: str
    summary: str
    pats: tuple[Pat, ...]

    @property
    def convention(self) -> Pat:
        n = self.id[3:]
        return Pat(owner="feature scheduler", name=rf"(^|::)si{n}_")


def _names(owner: str, *names: str) -> tuple[Pat, ...]:
    return tuple(Pat(owner, name=n) for n in names)


INVARIANTS: tuple[Invariant, ...] = (
    # The owner check lives in the agent's connection: `not_owner` is answered before any lease handler, the lease
    # executor included, sees the lease. The executor's own second check is named `si1_…` too (the convention).
    Invariant("SI-1", "the agent rejects a lease for another account (not_owner)",
              _names("feature agent-connection", r"si1_not_owner_is_refused_before_anything")),
    Invariant("SI-2", "the podman argv is exactly the fixed one; job input cannot inject arguments",
              _names("feature sandbox-driver", r"si2_golden_argv", r"hostile_values_cannot_inject_flags",
                     r"env_file_lines_and_injection")),
    Invariant("SI-3", "no egress list: a TCP connect to 1.1.1.1:443 fails (real Podman; #[ignore]d off a test node)",
              _names("feature sandbox-driver", r"si3_network_none_blocks_the_internet")),
    Invariant("SI-4", "the egress proxy refuses every deny range, DNS rebinding and IPv4-mapped IPv6",
              _names("feature egress-proxy", r"every_deny_range_is_refused_through_the_proxy",
                     r"deny_ranges_have_exact_boundaries", r"dns_rebinding_connects_only_to_the_checked_ip")),
    Invariant("SI-5", "only allowlisted domains pass, on whole labels",
              _names("feature egress-proxy", r"only_allowlisted_domains_pass_on_whole_labels")),
    Invariant(
        "SI-6", "keys and join codes are stored hashed and never appear in logs, Debug output or errors",
        (
            Pat("feature server-core", target="no_secrets_in_logs"),
            Pat("route POST /v1/jobs", target="jobs_no_env_in_logs"),
            Pat("feature gateway", target="no_secrets_in_gateway_logs"),
        ) + _names("feature server-core", r"secret_hash_stored_format", r"api_key_hash_and_constant_time_verify",
                   r"api_key_is_redacted_everywhere_but_expose_and_serialize", r"new_api_key_debug_is_redacted",
                   r"join_token_debug_never_shows_the_code_or_the_token", r"debug_of_join_and_lease_hides_secrets",
                   r"job_spec_debug_redacts_env_values_and_file_contents", r"debug_output_never_contains_the_key"),
    ),
    Invariant(
        "SI-7", "every object read and write is filtered by account and project (cross-account negative cases)",
        _names("feature server-core", r"accounts_cannot_see_or_revoke_each_others_keys")
        + _names("route POST /v1/jobs", r"get_returns_the_job_and_never_another_accounts",
                 r"an_idempotency_key_means_nothing_to_another_account")
        + _names("route GET /v1/nodes", r"another_accounts_nodes_and_tokens_are_invisible"),
    ),
    Invariant("SI-8", "a stale epoch is fenced: the message is rejected and the server answers Cancel",
              (Pat("feature scheduler", name=r"si8_stale_epoch_is_fenced"),)),
    Invariant(
        "SI-9", "output paths cannot escape the job directory (agent and server download)",
        _names("feature sandbox-driver", r"si9_hostile_entries_are_skipped_with_a_reason")
        + (Pat("route GET /v1/jobs/{id}/outputs", name=r"si9_downloads_refuse_traversal_and_planted_links"),),
    ),
    Invariant(
        "SI-10", "oversized frames and malformed JSON close the connection without panicking; unknown types decode to Unknown",
        _names("feature server-core", r"oversize_frames_are_rejected_before_reading_the_body",
               r"unknown_message_types_decode_to_unknown", r"mutated_valid_frames_never_panic")
        + _names("feature gateway", r"unknown_messages_keep_the_connection_and_malformed_frames_close_it"),
    ),
    Invariant(
        "SI-11", "join tokens are single-use and expire against the server's row; consuming is atomic",
        _names("feature gateway", r"an_expired_token_is_refused_even_with_a_forged_later_expiry",
               r"revoked_and_wrong_code_tokens_are_refused",
               r"a_retry_by_the_same_node_id_is_idempotent_and_others_are_refused",
               r"two_concurrent_joins_with_one_token_create_exactly_one_node"),
    ),
    Invariant(
        "SI-12", "the agent opens no listening socket reachable from outside",
        (Pat("feature server-core", target="si12_no_listening_sockets"),
         Pat("feature agent-connection", name=r"si12_runtime_the_running_agent_opens_only_its_iroh_udp_sockets")),
    ),
)


def _landed(ctx, key: str, matched_owners: frozenset[str] = frozenset()) -> bool | None:
    """Whether the piece behind ``key`` exists, read from the product without a server:

    * a route, and the scheduler's marker: the committed OpenAPI document (checked against the server's code by a test of
      the server);
    * any other ``feature`` (the server core, the gateway, the sandbox driver, the egress proxy…): it has landed when
      **some other expected test of the same owner exists** in the ``--list`` inventory (``matched_owners``). Its code
      is there, so a sibling test that is gone was deleted or renamed, which is overdue, not "waiting";
    * the agent's connection: asked of the agent itself (``p2pc-agent status``, offline), as ``--list`` does;
    * None when it cannot be told, and then the owner is simply named."""
    if key in matched_owners:
        return True
    if key == "feature agent-connection":
        return ctx.state.setdefault("product_landed", product.Landed(ctx.repo_root)).agent_connection()
    if key.startswith("route "):
        _, method, path = key.split(" ", 2)
        routes = ctx.state.get("committed_routes")
        if routes is None:
            routes = ctx.state["committed_routes"] = product.load_openapi_file(Path(ctx.repo_root) / "docs" / "api" / "openapi.json")
        return None if routes is None else (method, product.shape(path)) in routes
    if key == "feature scheduler":
        return _landed(ctx, "route GET /v1/usage")
    return None


def node_test_argv(prefix: list[str] | None, env: dict[str, str] | None, cargo: list[str]) -> list[str]:
    """The command run on a node for the ignored tests: ``<test_prefix> env VAR=value... <cargo ...>``. Without the
    keys it is ``cargo`` exactly as it was."""
    return [*(prefix or []), *(["env", *(f"{k}={v}" for k, v in env.items())] if env else []), *cargo]


def run(ctx) -> core.Result:
    res = ctx.begin(ID, TITLE)
    manifest = str(ctx.repo_root / "Cargo.toml")
    missing_report: list[str] = []
    gaps: dict[str, list[str]] = {}  # owner task -> what is missing

    tests: list[product.ListedTest] = []
    with res.check("the tests that exist (cargo test --list)") as c:
        tests = flows.test_inventory(ctx)
        c.evidence.update(tests=len(tests), ignored=sum(1 for t in tests if t.ignored))
        c.require(tests, "cargo lists no test")
    # An owner has landed when ANY of its expected tests exists: the others, if missing, are then overdue. Only explicit
    # patterns count: a match of a naming convention proves the invariant has a test, not that an owner has landed.
    matched_owners = frozenset(
        p.owner for inv in INVARIANTS for p in inv.pats if not p.is_convention and any(p.matches(t) for t in tests)
    )

    for inv in INVARIANTS:
        with res.check(f"{inv.id}: {inv.summary}") as c:
            c.needs("the tests that exist (cargo test --list)")
            matched: list[product.ListedTest] = []
            missing: list[Pat] = []
            for pat in inv.pats:
                hit = [t for t in tests if pat.matches(t)]
                matched += hit
                if not hit:
                    missing.append(pat)
            conv = inv.convention
            matched += [t for t in tests if conv.matches(t)]  # anything named si<N>_ is part of the invariant too
            unique = {(t.target, t.name): t for t in matched}
            runnable = sorted({t.name for t in unique.values() if not t.ignored})
            ignored = sorted({t.name for t in unique.values() if t.ignored})
            ran = 0
            if runnable:
                expected = sum(1 for t in unique.values() if not t.ignored)
                step = ctx.exec(
                    "harness",
                    ["cargo", "test", "--manifest-path", manifest, "--workspace", "--all-features", "--", "--exact", *runnable],
                    label=f"cargo test {inv.id} ({len(runnable)} tests)",
                    timeout=3600,
                )
                passed, failed, _ign = flows.parse_cargo_test(step.stdout + "\n" + step.stderr)
                c.require(not step.error and not step.timed_out, f"cargo test did not run: {step.error or 'timed out'}")
                c.require(step.ok and failed == 0, f"{inv.id}: {failed} failed, exit {step.exit_code}")
                c.require(passed >= expected, f"{inv.id}: cargo ran {passed} of the {expected} tests listed: {core.last_line(step.stderr)}")
                ran = passed
            skipped = ""
            if ignored:
                node = next((r for r in ctx.enabled_roles(*flows.NODE_ROLES) if ctx.role(r).get("repo_dir")), None)
                if node is None:
                    skipped = (
                        f"{len(ignored)} test(s) exist but are #[ignore]d ({', '.join(n.rsplit('::', 1)[-1] for n in ignored)}): "
                        "set repo_dir on an enabled node role (a p2pc checkout there) to run them with --include-ignored"
                    )
                else:
                    ctx.require(node)
                    role = ctx.role(node)
                    prefix, test_env = role.get("test_prefix"), role.get("test_env")
                    hint = ""
                    if not prefix and node in ("node_linux", "node_linux_gpu"):
                        hint = (" (hint: a native Linux node has no systemd user session in an ssh login, which the real-Podman "
                                "tests need: set test_prefix to run them as the node user in a user service, see machines.example.toml)")
                    # Before the run, so a failing run still says which tests it was running and where.
                    c.evidence.update(test_node=node, ignored_tests=ignored)
                    if prefix:
                        c.evidence.update(test_prefix=prefix[0])  # the first word only, never the whole command
                    step = ctx.exec(
                        node,
                        node_test_argv(prefix, test_env, [
                            "cargo", "test", "--manifest-path", f"{role.get('repo_dir')}/Cargo.toml", "--workspace",
                            "--all-features", "--", "--include-ignored", "--exact", "--test-threads=1", *ignored]),
                        label=f"cargo test {inv.id} --include-ignored (on {node})",
                        timeout=3600,
                    )
                    passed, failed, _ign = flows.parse_cargo_test(step.stdout + "\n" + step.stderr)
                    c.require(not step.error and not step.timed_out, f"on {node}: {step.error or 'timed out'}{hint}")
                    c.require(step.ok and failed == 0, f"on {node}: {failed} failed, exit {step.exit_code}{hint}")
                    c.require(passed >= len(ignored), f"on {node}: only {passed} of {len(ignored)} ignored tests ran{hint}")
                    ran += passed
            c.evidence.update(tests_run=ran, matched=sorted({t.name for t in unique.values()}),
                              missing=[p.label() for p in missing])
            # Missing patterns: overdue (a fail) when the piece they test has landed, otherwise the owner's to bring.
            overdue = [p for p in missing if _landed(ctx, p.owner, matched_owners) is True]
            c.require(
                not overdue,
                f"{inv.id}: its piece has landed but its negative test is missing: " + "; ".join(p.label() for p in overdue),
            )
            if missing:
                for p in missing:
                    missing_report.append(f"{inv.id}: no test matches {p.label()} ({', '.join(context.owner(p.owner))})")
                    gaps.setdefault(p.owner, []).append(f"{inv.id} {p.label()}")
                raise core.Blocked(
                    f"{inv.id}: {len(missing)} expected test(s) do not exist yet: " + "; ".join(p.label() for p in missing),
                    sorted({t for p in missing for t in context.owner(p.owner)}),
                )
            if skipped:
                raise core.Skipped(skipped)

    with res.check("negative tests that do not exist yet") as c:
        c.evidence["missing"] = missing_report
        if missing_report:
            raise core.Blocked(
                f"{len(missing_report)} gap(s) in the SI negative tests: " + "; ".join(missing_report),
                sorted({t for key in gaps for t in context.owner(key)}),
            )

    with res.check("internal pentest from a separate machine (manual)") as c:
        path, digest = ctx.manual_evidence("pentest_report")
        c.evidence.update(report=path.name, sha256=digest)
    return res
