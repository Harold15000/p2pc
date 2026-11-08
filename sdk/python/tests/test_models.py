# SPDX-License-Identifier: Apache-2.0
"""Client-side validation of the §7 JobSpec table and the wire models."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

import pytest
from helpers import job_json, key_json, node_json
from pydantic import ValidationError

from p2pc import (
    ApiKey,
    Egress,
    Estimate,
    InputFile,
    Job,
    JobAttempt,
    JobSpec,
    JobSpecView,
    JobStatus,
    JoinToken,
    LogLine,
    NewApiKey,
    Node,
    OutputFile,
    Outputs,
    Page,
    Placement,
    Resources,
    Retry,
    UsageReport,
    UsageTotals,
)

IMAGE = "docker.io/library/python:3.12-slim"
JOIN_TOKEN = "p2pc_join_ABCDEF"  # gitleaks:allow


def spec(**overrides: Any) -> JobSpec:
    base: dict[str, Any] = {"image": IMAGE, "command": ["python", "-c", "print(6*7)"]}
    base.update(overrides)
    return JobSpec(**base)


def test_minimal_spec_wire_format_omits_unset_fields() -> None:
    wire = spec().to_wire()
    assert wire == {
        "image": IMAGE,
        "command": ["python", "-c", "print(6*7)"],
        "resources": {"cpu": 1, "memory_mb": 1024, "gpu": 0},
    }


def test_full_spec_wire_format_matches_section_7() -> None:
    wire = spec(
        name="demo",
        env={"KEY": "value"},
        files=[InputFile.from_content("/inputs/data.csv", "a,b\n1,2\n")],
        resources=Resources(cpu=2, memory_mb=4096, gpu=0, disk_mb=10240),
        timeout_s=3600,
        egress=Egress(allow=["pypi.org", "files.pythonhosted.org"]),
        outputs={"max_mb": 1024},
        placement=Placement(pools=["mine"], node_id=None),
        retry=Retry(max_attempts=2),
        idempotency_key="k1",
    ).to_wire()
    assert wire["name"] == "demo"
    assert wire["env"] == {"KEY": "value"}
    assert wire["files"] == [
        {"path": "/inputs/data.csv", "content_b64": base64.b64encode(b"a,b\n1,2\n").decode()}
    ]
    assert wire["resources"] == {"cpu": 2, "memory_mb": 4096, "gpu": 0, "disk_mb": 10240}
    assert wire["timeout_s"] == 3600
    assert wire["egress"] == {"allow": ["pypi.org", "files.pythonhosted.org"]}
    assert wire["outputs"] == {"max_mb": 1024}
    assert wire["placement"] == {"pools": ["mine"], "labels": {}}
    assert wire["retry"] == {"max_attempts": 2}
    assert wire["idempotency_key"] == "k1"


@pytest.mark.parametrize(
    "image",
    [
        "python",
        "python:3.12-slim",
        "docker.io/library/python:3.12-slim",
        "ghcr.io/owner/repo/img:v1",
        "registry.example.invalid:5000/team/img:1.0",
        "docker.io/library/python@sha256:" + "a" * 64,
        "quay.io/org/img:tag@sha256:" + "0" * 64,
    ],
)
def test_valid_image_references(image: str) -> None:
    assert spec(image=image).image == image


@pytest.mark.parametrize(
    "image",
    [
        "",
        "UPPER/case:tag",
        "has space:latest",
        "img:",
        "img@sha256:abc",
        "img@md5:" + "a" * 32,
        "-bad/img",
        "img:tag:again",
        "docker.io//img",
    ],
)
def test_invalid_image_references(image: str) -> None:
    with pytest.raises(ValidationError):
        spec(image=image)


def test_command_bounds() -> None:
    with pytest.raises(ValidationError):
        spec(command=[])
    with pytest.raises(ValidationError):
        spec(command=["x"] * 257)
    assert len(spec(command=["x"] * 256).command) == 256
    # 64 KiB total
    with pytest.raises(ValidationError):
        spec(command=["a" * 40_000, "b" * 30_000])
    spec(command=["a" * 32_768, "b" * 32_768])


def test_command_must_be_an_argv_not_a_string() -> None:
    with pytest.raises(ValidationError):
        spec(command="python -c 'print(1)'")


def test_env_rules() -> None:
    assert spec(env={"A_1": "x", "_UNDER": "y"}).env == {"A_1": "x", "_UNDER": "y"}
    for bad in ("lower", "1ABC", "A-B", "", "A B"):
        with pytest.raises(ValidationError):
            spec(env={bad: "v"})
    with pytest.raises(ValidationError):
        spec(env={"P2PC_TOKEN": "v"})
    with pytest.raises(ValidationError):
        spec(env={f"V{i}": "x" for i in range(65)})
    assert len(spec(env={f"V{i}": "x" for i in range(64)}).env or {}) == 64
    with pytest.raises(ValidationError):
        spec(env={"BIG": "x" * 33_000})


def test_env_values_never_appear_in_repr_or_validation_errors() -> None:
    secret = "hunter2-super-secret-value"
    assert secret not in repr(spec(env={"TOKEN": secret}))
    assert secret not in str(spec(env={"TOKEN": secret}))
    with pytest.raises(ValidationError) as err:
        spec(env={"P2PC_BAD": secret})
    assert secret not in str(err.value)


def test_input_file_from_bytes_and_str() -> None:
    assert InputFile.from_content("/inputs/a.bin", b"\x00\x01").content_b64 == "AAE="
    assert (
        InputFile.from_content("/inputs/a.txt", "héllo").content_b64
        == base64.b64encode("héllo".encode()).decode()
    )


@pytest.mark.parametrize(
    "path",
    [
        "inputs/a.txt",
        "/etc/passwd",
        "/inputs",
        "/inputs/../etc/passwd",
        "/inputs/a/../../b",
        "/inputs//a",
        "/inputsx/a",
        "/inputs/",
    ],
)
def test_input_file_paths_must_be_under_inputs(path: str) -> None:
    with pytest.raises(ValidationError):
        InputFile(path=path, content_b64="AA==")


def test_input_file_rejects_invalid_base64() -> None:
    with pytest.raises(ValidationError):
        InputFile(path="/inputs/a", content_b64="not base64!!")


def test_files_total_decoded_size_capped_at_512_kib() -> None:
    cap = 512 * 1024  # spec §7
    spec(files=[InputFile.from_content("/inputs/a", b"x" * cap)])
    spec(
        files=[
            InputFile.from_content("/inputs/a", b"x" * (cap // 2)),
            InputFile.from_content("/inputs/b", b"x" * (cap // 2)),
        ]
    )
    with pytest.raises(ValidationError, match="512 KiB"):
        spec(
            files=[
                InputFile.from_content("/inputs/a", b"x" * (cap // 2 + 1)),
                InputFile.from_content("/inputs/b", b"x" * (cap // 2)),
            ]
        )
    with pytest.raises(ValueError, match="512 KiB"):
        InputFile.from_content("/inputs/huge", b"x" * (cap + 1))


def test_the_files_cap_counts_decoded_bytes_not_base64_length() -> None:
    cap = 512 * 1024
    # Base64 of `cap` bytes is longer than `cap` characters, and must still be accepted.
    file = InputFile.from_content("/inputs/a", b"\x00" * cap)
    assert len(file.content_b64) > cap
    spec(files=[file])


@pytest.mark.parametrize("value", ["a\nb", "a\rb", "a\x00b", "\n", "line1\r\nline2"])
def test_env_values_with_nul_or_line_breaks_are_rejected(value: str) -> None:
    with pytest.raises(ValidationError, match="NUL, newline or carriage return") as err:
        spec(env={"TOKEN": value})
    assert "TOKEN" in str(err.value)  # the variable is named...
    assert repr(value) not in str(err.value)  # ...its value never is


def test_env_values_may_contain_other_control_and_unicode_characters() -> None:
    assert spec(env={"A": "tab\there", "B": "héllo ☃", "C": ""}).env == {
        "A": "tab\there",
        "B": "héllo ☃",
        "C": "",
    }


@pytest.mark.parametrize("cpu", [0.2501, 1.0005, 0.3333, 2.0001])
def test_cpu_must_be_a_multiple_of_a_milli_vcpu(cpu: float) -> None:
    with pytest.raises(ValidationError, match=r"multiple of 0\.001"):
        Resources(cpu=cpu)


@pytest.mark.parametrize("cpu", [0.25, 0.251, 1, 1.001, 2.5, 0.1 + 0.2 + 0.05, 255.999, 256])
def test_cpu_multiples_of_a_milli_vcpu_are_accepted_despite_float_error(cpu: float) -> None:
    assert Resources(cpu=cpu).cpu == cpu


@pytest.mark.parametrize("cpu", [0.24, 0, -1, 256.5])
def test_cpu_bounds_rejected(cpu: float) -> None:
    with pytest.raises(ValidationError):
        Resources(cpu=cpu)


@pytest.mark.parametrize("cpu", [0.25, 1, 2.5, 256])
def test_cpu_bounds_accepted(cpu: float) -> None:
    assert Resources(cpu=cpu).cpu == cpu


def test_resources_other_bounds() -> None:
    for mem in (127, 1_048_577):
        with pytest.raises(ValidationError):
            Resources(memory_mb=mem)
    Resources(memory_mb=128)
    Resources(memory_mb=1_048_576)
    for gpu in (-1, 2):
        with pytest.raises(ValidationError):
            Resources(gpu=gpu)
    assert Resources(gpu=1).gpu == 1
    with pytest.raises(ValidationError):
        Resources(disk_mb=0)


@pytest.mark.parametrize("timeout", [0, -5, 86_401])
def test_timeout_bounds_rejected(timeout: int) -> None:
    with pytest.raises(ValidationError):
        spec(timeout_s=timeout)


def test_timeout_bounds_accepted() -> None:
    assert spec(timeout_s=1).timeout_s == 1
    assert spec(timeout_s=86_400).timeout_s == 86_400


@pytest.mark.parametrize(
    "domain",
    [
        "*.pypi.org",
        "PyPI.org",
        "192.0.2.4",
        "127.1",
        "::1",
        "[::1]",
        "a b.com",
        "pypi.org.",
        "",
        ".x.com",
    ],
)
def test_egress_rejects_bad_entries(domain: str) -> None:
    with pytest.raises(ValidationError):
        Egress(allow=[domain])


def test_egress_accepts_domains_and_caps_at_32() -> None:
    assert Egress(allow=["pypi.org", "files.pythonhosted.org", "localhost"]).allow
    Egress(allow=[f"d{i}.example.com" for i in range(32)])
    with pytest.raises(ValidationError):
        Egress(allow=[f"d{i}.example.com" for i in range(33)])


def test_placement_only_mine_pool() -> None:
    assert Placement().pools == ["mine"]
    with pytest.raises(ValidationError):
        Placement(pools=["public"])


def test_retry_bounds() -> None:
    assert Retry().max_attempts == 2
    for bad in (0, 6):
        with pytest.raises(ValidationError):
            Retry(max_attempts=bad)
    assert Retry(max_attempts=5).max_attempts == 5


def test_job_status_terminal() -> None:
    terminal = {"succeeded", "failed", "timed_out", "cancelled", "lost"}
    for st in JobStatus:
        assert st.is_terminal == (st.value in terminal)
    assert {s.value for s in JobStatus} == terminal | {"queued", "assigned", "running"}


def test_job_parses_and_is_terminal() -> None:
    job = Job.model_validate(job_json("job_1", "succeeded", exit_code=0, future=1))
    assert job.is_terminal
    assert job.exit_code == 0
    assert not Job.model_validate(job_json("j", "running")).is_terminal


def test_a_disk_limit_failure_has_a_hint_that_names_disk_mb() -> None:
    job = Job.model_validate(job_json(status="failed", error="disk_limit"))
    assert job.hint is not None
    assert "wrote more than its disk limit (10240 MiB)" in job.hint
    assert "disk_mb" in job.hint
    # Any other job has none.
    assert Job.model_validate(job_json(status="failed", error="image_pull_failed")).hint is None
    assert Job.model_validate(job_json(status="succeeded")).hint is None


def test_job_nests_a_redacted_spec_with_file_digests() -> None:
    job = Job.model_validate(
        job_json(
            spec={
                "name": "demo",
                "image": IMAGE,
                "command": ["run"],
                "env": {"TOKEN": "<redacted>"},
                "files": [{"path": "/inputs/a.csv", "size": 8, "sha256": "ab" * 32}],
                "resources": {"cpu": 2.0, "memory_mb": 4096, "gpu": 0, "disk_mb": 10240},
                "timeout_s": 3600,
                "egress": {"allow": ["pypi.org"]},
                "outputs": {"max_mb": 1024},
                "placement": {"pools": ["mine"], "node_id": None, "labels": {}},
                "retry": {"max_attempts": 2},
            },
            estimated_units=2000,
            reason="no node has a free GPU",
            cancel_requested_at="2026-11-05T10:05:00Z",
            node_id="node_1",
        )
    )
    assert job.spec.env == {"TOKEN": "<redacted>"}
    assert [(f.path, f.size, f.sha256) for f in job.spec.files] == [("/inputs/a.csv", 8, "ab" * 32)]
    assert job.spec.egress.allow == ["pypi.org"]
    assert job.estimated_units == 2000  # milli-units: 2 vCPU x 1 h
    assert job.reason == "no node has a free GPU"
    assert job.cancel_requested_at is not None
    # Conveniences read through the spec.
    assert (job.image, job.command, job.resources.cpu) == (IMAGE, ["run"], 2.0)
    assert "TOKEN" not in repr(job)


def test_job_never_carries_an_idempotency_key() -> None:
    # Spec §7: scoped to the API key and never returned. Even if a server did send one, the
    # SDK does not store it (so it can never be printed or logged from a Job).
    assert "idempotency_key" not in Job.model_fields
    assert "idempotency_key" not in JobSpecView.model_fields
    leaky = job_json(idempotency_key="nightly-1")
    leaky["spec"]["idempotency_key"] = "nightly-1"
    job = Job.model_validate(leaky)
    assert "idempotency_key" not in job.model_dump()
    assert "nightly-1" not in repr(job)
    assert not hasattr(job, "idempotency_key")
    # It stays a request-side field: the SDK sends it, and the server never gives it back.
    assert "idempotency_key" in JobSpec.model_fields


@pytest.mark.parametrize(
    "missing", ["id", "project_id", "status", "attempt", "spec", "estimated_units", "created_at"]
)
def test_job_requires_what_the_server_always_sends(missing: str) -> None:
    body = job_json()
    del body[missing]
    with pytest.raises(ValidationError):
        Job.model_validate(body)


def test_response_models_parse() -> None:
    assert (
        LogLine.model_validate(
            {"seq": 3, "stream": "stderr", "ts": "2026-01-01T00:00:00Z", "data": "x"}
        ).seq
        == 3
    )
    assert OutputFile.model_validate({"path": "a/b.txt", "size": 3, "sha256": "ab" * 32}).size == 3
    est = Estimate.model_validate(
        {"feasible": True, "matching_nodes": 2, "would_queue": False, "units_per_hour": 1500}
    )
    assert est.units_per_hour == 1500  # milli-units: 1.5 units an hour
    assert est.reason is None
    assert Node.model_validate(node_json("n1")).id == "n1"
    totals = UsageTotals.model_validate(
        {
            "key": "job_1",
            "attempts": 1,
            "reserved_cpu_ms": 3_600_000,
            "reserved_gpu_ms": 0,
            "used_cpu_ms": 1_000,
            "max_rss_mb": 64,
            "units": 1500,
        }
    )
    assert totals.units == 1500  # milli-units
    assert totals.estimated_attempts == 0  # the server leaves it out when there are none


def test_page_model() -> None:
    page = Page[OutputFile].model_validate(
        {"items": [{"path": "a", "size": 1, "sha256": "00" * 32}], "next_cursor": "c2"}
    )
    assert page.next_cursor == "c2"
    assert page.items[0].path == "a"
    assert Page[OutputFile](items=[]).next_cursor is None


def test_secrets_are_masked_in_models() -> None:
    secret = "p2pc_sk_abcdefghijkl_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
    key = NewApiKey.model_validate(key_json(key=secret))
    assert key.key.get_secret_value() == secret
    assert secret not in repr(key)
    assert secret not in str(key)
    assert secret not in str(key.model_dump())
    assert secret not in key.model_dump_json()
    assert "ZZZZZZZZ" not in repr(key)
    # A listed key never has one; and a stray `key` member is ignored, not stored.
    listed = ApiKey.model_validate(key_json(key=secret))
    assert not hasattr(listed, "key")
    assert secret not in repr(listed)
    assert secret not in listed.model_dump_json()
    tok = JoinToken.model_validate(
        {"id": "jt_1", "join_token": JOIN_TOKEN, "expires_at": "2026-01-01T00:00:00Z"}
    )
    assert JOIN_TOKEN not in repr(tok)
    assert tok.join_token.get_secret_value() == JOIN_TOKEN


def test_validators_do_not_accept_a_trailing_newline() -> None:
    with pytest.raises(ValidationError):
        spec(env={"NAME\n": "v"})
    with pytest.raises(ValidationError):
        spec(image="python\n")
    with pytest.raises(ValidationError):
        spec(image="python:3.12\n")
    with pytest.raises(ValidationError):
        Egress(allow=["192.0.2.4\n"])
    with pytest.raises(ValidationError):
        Egress(allow=["pypi.org\n"])


def test_image_tags_are_ascii_only() -> None:
    with pytest.raises(ValidationError):
        spec(image="python:vé")  # \w would have accepted the accented letter
    with pytest.raises(ValidationError):
        spec(image="python:١٢")  # Arabic-Indic digits
    assert spec(image="python:V1_2-rc.3").image == "python:V1_2-rc.3"


def test_job_resources_parse_without_request_bounds() -> None:
    job = Job.model_validate(
        job_json(
            spec={
                "image": IMAGE,
                "command": ["x"],
                "resources": {"cpu": 0.1, "memory_mb": 64, "gpu": 4, "disk_mb": 0, "extra": 1},
            }
        )
    )
    assert (job.resources.cpu, job.resources.memory_mb, job.resources.gpu) == (0.1, 64, 4)


# --- idempotency key and outputs.max_mb: what the server rejects (validate/mod.rs) -----------
@pytest.mark.parametrize("key", ["a", "nightly-2026-11-05", "x" * 255, "!~", "a.b_c:d/e=f+g"])
def test_valid_idempotency_keys(key: str) -> None:
    assert spec(idempotency_key=key).idempotency_key == key


@pytest.mark.parametrize(
    "key",
    [
        "",
        "x" * 256,
        "has space",
        " lead",
        "trail ",
        "tab\there",
        "new\nline",
        "é",
        "naïve",
        "a\x7f",
        "a\x00",
    ],
)
def test_invalid_idempotency_keys_fail_before_sending(key: str) -> None:
    with pytest.raises(ValidationError, match="idempotency_key") as err:
        spec(idempotency_key=key)
    assert "1-255 printable ASCII characters without spaces" in str(err.value)


def test_idempotency_key_is_still_optional_and_never_part_of_the_job_view() -> None:
    assert spec().idempotency_key is None
    assert "idempotency_key" not in spec().to_wire()


def test_outputs_max_mb_is_bounded_like_the_server() -> None:
    assert Outputs(max_mb=1).max_mb == 1
    assert Outputs(max_mb=10_240).max_mb == 10_240
    for bad in (0, -1, 10_241):
        with pytest.raises(ValidationError):
            Outputs(max_mb=bad)
    assert spec(outputs={"max_mb": 10_240}).outputs == Outputs(max_mb=10_240)
    with pytest.raises(ValidationError):
        spec(outputs={"max_mb": 10_241})


# --- attempts and usage (T06) ----------------------------------------------------------------
def test_job_attempts_parse_with_the_real_shape() -> None:
    job = Job.model_validate(
        job_json(
            "job_1",
            "running",
            attempt=2,
            attempts=[
                {
                    "attempt": 1,
                    "node_id": "node_1",
                    "outcome": "lost",
                    "reason": "node_lost",
                    "started_at": None,  # accepted, then lost during the image pull
                    "ended_at": "2026-11-05T10:05:00Z",
                },
                {
                    "attempt": 2,
                    "node_id": "node_2",
                    "outcome": "running",
                    "reason": None,
                    "started_at": "2026-11-05T10:06:00Z",
                    "ended_at": None,
                },
            ],
        )
    )
    assert job.attempts is not None
    first, second = job.attempts
    assert all(isinstance(a, JobAttempt) for a in job.attempts)
    assert (first.attempt, first.node_id, first.outcome, first.reason) == (
        1,
        "node_1",
        JobStatus.LOST,
        "node_lost",
    )
    assert first.started_at is None
    assert first.ended_at == datetime(2026, 11, 5, 10, 5, tzinfo=UTC)
    assert second.outcome is JobStatus.RUNNING
    assert second.reason is None
    assert second.ended_at is None
    assert second.started_at == datetime(2026, 11, 5, 10, 6, tzinfo=UTC)


def test_job_attempts_are_none_when_the_server_leaves_them_out() -> None:
    # Only GET /v1/jobs/{id} has them: a list of jobs omits the field (and null is accepted).
    assert Job.model_validate(job_json()).attempts is None
    assert Job.model_validate(job_json(attempts=None)).attempts is None
    assert Job.model_validate(job_json(attempts=[])).attempts == []


def test_an_attempt_needs_the_fields_the_server_always_sends() -> None:
    with pytest.raises(ValidationError):
        JobAttempt.model_validate({"attempt": 1, "node_id": "node_1"})  # no outcome


def test_usage_report_uses_the_real_shape_and_the_from_alias() -> None:
    totals = {
        "attempts": 3,
        "estimated_attempts": 1,
        "reserved_cpu_ms": 1,
        "reserved_gpu_ms": 2,
        "used_cpu_ms": 3,
        "max_rss_mb": 4,
        "units": 5,
    }
    report = UsageReport.model_validate(
        {
            "from": "2026-11-01T00:00:00Z",
            "to": "2026-11-02T00:00:00Z",
            "group_by": "node",
            "items": [{**totals, "key": "node_1"}],
            "next_cursor": None,
            "total": {**totals, "key": None},
        }
    )
    assert report.from_ == datetime(2026, 11, 1, tzinfo=UTC)
    assert report.group_by == "node"
    assert report.items[0].key == "node_1"
    assert report.items[0].estimated_attempts == 1
    assert report.total.key is None
    assert report.total.units == 5


# --- logs and outputs: the real shapes (T13d) ---------------------------------------------
LOG_RECORD = {"seq": 3, "stream": "stderr", "ts": "2026-11-05T10:00:01Z", "data": "oops\n"}
OUTPUT_ENTRY = {"path": "results/a.csv", "size": 12, "sha256": "ab" * 32}


def test_a_log_line_has_seq_stream_ts_and_data() -> None:
    line = LogLine.model_validate(LOG_RECORD)
    assert (line.seq, line.stream, line.data) == (3, "stderr", "oops\n")
    assert line.ts == datetime(2026, 11, 5, 10, 0, 1, tzinfo=UTC)
    assert line.truncated is False


@pytest.mark.parametrize("missing", ["seq", "stream", "ts", "data"])
def test_a_log_line_without_a_member_the_server_always_sends_is_refused(missing: str) -> None:
    record = {k: v for k, v in LOG_RECORD.items() if k != missing}
    with pytest.raises(ValidationError):
        LogLine.model_validate(record)


def test_a_log_line_refuses_a_negative_seq() -> None:
    with pytest.raises(ValidationError):
        LogLine.model_validate({**LOG_RECORD, "seq": -1})


def test_the_truncation_marker_is_told_apart_and_other_members_are_ignored() -> None:
    marker = LogLine.model_validate({**LOG_RECORD, "truncated": True, "future": 1})
    assert marker.truncated is True
    # Only the literal `true` marks it: no job output can produce a member of that name.
    for other in ("true", 1, None, False):
        assert LogLine.model_validate({**LOG_RECORD, "truncated": other}).truncated is False


def test_an_output_file_has_path_size_and_sha256() -> None:
    entry = OutputFile.model_validate(OUTPUT_ENTRY)
    assert (entry.path, entry.size, entry.sha256, entry.expired) == (
        "results/a.csv",
        12,
        "ab" * 32,
        False,
    )
    assert OutputFile.model_validate({**OUTPUT_ENTRY, "expired": True}).expired is True


@pytest.mark.parametrize("missing", ["path", "size", "sha256"])
def test_an_output_file_without_a_member_the_server_always_sends_is_refused(missing: str) -> None:
    entry = {k: v for k, v in OUTPUT_ENTRY.items() if k != missing}
    with pytest.raises(ValidationError):
        OutputFile.model_validate(entry)


def test_an_output_file_refuses_a_negative_size() -> None:
    with pytest.raises(ValidationError):
        OutputFile.model_validate({**OUTPUT_ENTRY, "size": -1})
