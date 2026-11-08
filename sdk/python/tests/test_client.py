# SPDX-License-Identifier: Apache-2.0
"""The synchronous client against a fake server: method, path, query, body and parsing."""

from __future__ import annotations

import hashlib
import json
import logging
import tomllib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from helpers import (
    API_URL,
    KEY,
    KEY_SECRET,
    FakeClock,
    FakeServer,
    job_json,
    join_token_info_json,
    json_response,
    key_json,
    node_json,
    problem,
    streamed,
)
from pydantic import ValidationError

import p2pc
from p2pc import (
    ApiKey,
    AuditEvent,
    AuthenticationError,
    CapExceededError,
    ChecksumMismatchError,
    Client,
    ConfigurationError,
    ConflictError,
    Egress,
    Estimate,
    InputFile,
    InvalidResponseError,
    Job,
    JobStatus,
    JoinToken,
    JoinTokenInfo,
    LogLine,
    NewApiKey,
    Node,
    NotFoundError,
    OutputFile,
    P2PCConnectionError,
    P2PCError,
    ServerError,
    ServerInfo,
    UnprocessableError,
    UnsafePathError,
    UsageReport,
    UsageTotals,
    WhoAmI,
)

SRV_ADDRESS = "p2pc_srv_EXAMPLE"  # gitleaks:allow
JOIN_TOKEN = "p2pc_join_ABCDEF"  # gitleaks:allow
NEW_KEY = f"p2pc_sk_zzzzzzzzzzzz_{KEY_SECRET}"  # gitleaks:allow

Factory = Callable[..., Client]

IMAGE = "docker.io/library/python:3.12-slim"
CMD = ["python", "-c", "print(6*7)"]


# --- configuration, headers, secrecy -----------------------------------------------------
def test_version_matches_pyproject() -> None:
    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    assert tomllib.loads(pyproject.read_text())["project"]["version"] == p2pc.__version__


def test_sends_bearer_and_user_agent(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/jobs/job_1", job_json())
    client.jobs.get("job_1")
    req = server.requests[0]
    assert req.headers["authorization"] == f"Bearer {KEY}"
    assert req.headers["user-agent"] == f"p2pc-python/{p2pc.__version__}"
    assert str(req.url).startswith(f"{API_URL}/v1/jobs/job_1")


def test_defaults_come_from_environment(
    monkeypatch: pytest.MonkeyPatch, server: FakeServer
) -> None:
    monkeypatch.setenv("P2PC_API_URL", "http://env.example.invalid:9000/")
    monkeypatch.setenv("P2PC_API_KEY", KEY)
    server.on("GET", "/v1/jobs/j", job_json("j"))
    c = Client(http_client=httpx.Client(transport=httpx.MockTransport(server)))
    c.jobs.get("j")
    assert str(server.requests[0].url) == "http://env.example.invalid:9000/v1/jobs/j"
    assert server.requests[0].headers["authorization"] == f"Bearer {KEY}"


def test_default_api_url_is_local(monkeypatch: pytest.MonkeyPatch, server: FakeServer) -> None:
    server.on("GET", "/v1/jobs/j", job_json("j"))
    c = Client(api_key=KEY, http_client=httpx.Client(transport=httpx.MockTransport(server)))
    c.jobs.get("j")
    assert str(server.requests[0].url).startswith("http://127.0.0.1:7477/v1/jobs/j")


def test_missing_key_fails_at_first_call_not_at_construction(server: FakeServer) -> None:
    c = Client(http_client=httpx.Client(transport=httpx.MockTransport(server)))  # no error
    with pytest.raises(ConfigurationError, match="P2PC_API_KEY"):
        c.jobs.get("j")
    assert server.requests == []  # nothing was sent


def test_bad_api_url_is_rejected_at_construction() -> None:
    with pytest.raises(ConfigurationError, match="http"):
        Client(api_url="ftp://example.invalid", api_key=KEY)


def test_repr_masks_the_key(client: Client) -> None:
    for text in (repr(client), str(client), f"{client}", f"{client!r}"):
        assert KEY not in text
        assert KEY_SECRET not in text
        assert "p2pc_sk_abc…" in text
    assert "Client" in repr(client)


def test_internal_config_repr_masks_the_key(client: Client) -> None:
    assert KEY not in repr(client._config)
    assert KEY_SECRET not in repr(client._config)


def test_credentials_in_the_api_url_are_rejected_without_echoing_them() -> None:
    # httpx would turn userinfo into Basic auth and replace the bearer header (see test_config).
    with pytest.raises(ConfigurationError, match="credentials") as err:
        Client(api_url="http://user:pw-hunter2@p2pc.example.invalid:7477", api_key=KEY)
    assert "hunter2" not in str(err.value) + repr(err.value)


def test_key_never_appears_in_logs(
    client: Client, server: FakeServer, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    server.on("GET", "/v1/jobs/j", job_json("j"))
    server.on("POST", "/v1/jobs", problem(401, "unauthorized", f"bad key {KEY}"))
    client.jobs.get("j")
    with pytest.raises(AuthenticationError):
        client.jobs.create(IMAGE, CMD)
    assert any(r.name == "p2pc" for r in caplog.records), "the SDK logs requests at DEBUG"
    assert KEY not in caplog.text
    assert KEY_SECRET not in caplog.text


def test_key_never_appears_in_exceptions(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/jobs/echo", problem(401, "unauthorized", f"you sent {KEY}"))
    with pytest.raises(AuthenticationError) as err:
        client.jobs.get("echo")
    assert KEY not in str(err.value) + repr(err.value)
    assert KEY_SECRET not in str(err.value) + repr(err.value)

    def boom(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect, token {KEY}")

    server.on("GET", "/v1/jobs/conn", boom)
    with pytest.raises(P2PCConnectionError) as conn:
        client.jobs.get("conn")
    assert KEY not in str(conn.value) + repr(conn.value)
    assert KEY_SECRET not in str(conn.value) + repr(conn.value)


def test_transport_failure_is_p2pc_connection_error(client: Client, server: FakeServer) -> None:
    def boom(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    server.on("GET", "/v1/jobs/x", boom)
    with pytest.raises(P2PCConnectionError):
        client.jobs.get("x")


def test_context_manager_closes_only_owned_http_client(
    server: FakeServer, make_client: Factory
) -> None:
    injected = httpx.Client(transport=httpx.MockTransport(server))
    with make_client(http_client=injected):
        pass
    assert not injected.is_closed
    with Client(api_key=KEY) as owned:
        inner = owned._http
    assert inner.is_closed


def test_ids_cannot_inject_path_segments(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/jobs/../nodes", job_json("x"))
    client.jobs.get("../nodes")
    assert server.requests[0].url.raw_path.startswith(b"/v1/jobs/..%2Fnodes")
    for bad in ("", ".", ".."):
        with pytest.raises(ValueError, match="id"):
            client.jobs.get(bad)


# --- jobs --------------------------------------------------------------------------------
def test_create_posts_the_spec_and_returns_a_bound_job(client: Client, server: FakeServer) -> None:
    server.on("POST", "/v1/jobs", json_response(job_json("job_9"), 201))
    job = client.jobs.create(
        IMAGE,
        CMD,
        env={"KEY": "value"},
        files={"/inputs/a.txt": "hello"},
        cpu=2,
        memory_mb=4096,
        gpu=1,
        disk_mb=2048,
        timeout_s=600,
        egress=["pypi.org"],
        outputs_max_mb=5,
        placement={"pools": ["mine"], "labels": {"zone": "a"}},
        max_attempts=3,
        idempotency_key="idem-1",
        name="demo",
    )
    assert isinstance(job, Job)
    assert job.id == "job_9"
    assert job.status is JobStatus.QUEUED
    req = server.requests[0]
    assert (req.method, req.url.path) == ("POST", "/v1/jobs")
    assert req.headers["content-type"] == "application/json"
    assert server.body() == {
        "name": "demo",
        "image": IMAGE,
        "command": CMD,
        "env": {"KEY": "value"},
        "files": [{"path": "/inputs/a.txt", "content_b64": "aGVsbG8="}],
        "resources": {"cpu": 2, "memory_mb": 4096, "gpu": 1, "disk_mb": 2048},
        "timeout_s": 600,
        "egress": {"allow": ["pypi.org"]},
        "outputs": {"max_mb": 5},
        "placement": {"pools": ["mine"], "labels": {"zone": "a"}},
        "retry": {"max_attempts": 3},
        "idempotency_key": "idem-1",
    }


def test_create_minimal_body_uses_defaults(client: Client, server: FakeServer) -> None:
    server.on("POST", "/v1/jobs", json_response(job_json(), 201))
    client.jobs.create(IMAGE, CMD)
    assert server.body() == {
        "image": IMAGE,
        "command": CMD,
        "resources": {"cpu": 1, "memory_mb": 1024, "gpu": 0},
    }


def test_create_accepts_model_arguments(client: Client, server: FakeServer) -> None:
    server.on("POST", "/v1/jobs", json_response(job_json(), 201))
    client.jobs.create(
        IMAGE,
        CMD,
        files=[InputFile.from_content("/inputs/b.bin", b"\x00\x01")],
        egress=Egress(allow=["example.com"]),
    )
    assert server.body()["files"] == [{"path": "/inputs/b.bin", "content_b64": "AAE="}]
    assert server.body()["egress"] == {"allow": ["example.com"]}


def test_idempotent_replay_returns_existing_job_on_200(client: Client, server: FakeServer) -> None:
    server.on("POST", "/v1/jobs", json_response(job_json("job_1", "running"), 200))
    assert client.jobs.create(IMAGE, CMD, idempotency_key="k").status is JobStatus.RUNNING


def test_run_is_an_alias_of_create(client: Client, server: FakeServer) -> None:
    server.on("POST", "/v1/jobs", json_response(job_json("job_r"), 201))
    assert client.jobs.run(IMAGE, CMD, cpu=0.5).id == "job_r"
    assert server.body()["resources"]["cpu"] == 0.5


@pytest.mark.parametrize(
    "kwargs",
    [
        {"image": "BAD IMAGE", "command": CMD},
        {"image": IMAGE, "command": []},
        {"image": IMAGE, "command": CMD, "cpu": 0.1},
        {"image": IMAGE, "command": CMD, "memory_mb": 64},
        {"image": IMAGE, "command": CMD, "gpu": 2},
        {"image": IMAGE, "command": CMD, "timeout_s": 0},
        {"image": IMAGE, "command": CMD, "env": {"P2PC_X": "1"}},
        {"image": IMAGE, "command": CMD, "files": {"/etc/passwd": "x"}},
        {"image": IMAGE, "command": CMD, "egress": ["*.example.com"]},
        {"image": IMAGE, "command": CMD, "placement": {"pools": ["public"]}},
        {"image": IMAGE, "command": CMD, "max_attempts": 9},
    ],
)
def test_obvious_mistakes_fail_before_any_request(
    client: Client, server: FakeServer, kwargs: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        client.jobs.create(**kwargs)
    assert server.requests == []


def test_command_string_is_refused_not_split_into_characters(
    client: Client, server: FakeServer
) -> None:
    with pytest.raises(TypeError, match="argv"):
        client.jobs.create(IMAGE, "echo hi")  # type: ignore[arg-type]
    assert server.requests == []


def test_create_error_mapping(client: Client, server: FakeServer) -> None:
    server.on("POST", "/v1/jobs", problem(402, "cap_exceeded", "daily cap of 10 units reached"))
    with pytest.raises(CapExceededError) as err:
        client.jobs.create(IMAGE, CMD)
    assert err.value.status == 402
    assert err.value.code == "cap_exceeded"
    assert "daily cap" in str(err.value)
    server.on("POST", "/v1/jobs", problem(409, "idempotency_conflict"))
    with pytest.raises(ConflictError):
        client.jobs.create(IMAGE, CMD, idempotency_key="k")
    server.on("POST", "/v1/jobs", problem(422, "unsupported_pool"))
    with pytest.raises(UnprocessableError) as unp:
        client.jobs.create(IMAGE, CMD)
    assert unp.value.code == "unsupported_pool"


def test_get(client: Client, server: FakeServer) -> None:
    server.on(
        "GET",
        "/v1/jobs/job_1",
        job_json(
            "job_1",
            "succeeded",
            exit_code=0,
            node_id="node_a",
            created_at="2026-11-05T10:00:00Z",
            finished_at="2026-11-05T10:00:05Z",
        ),
    )
    job = client.jobs.get("job_1")
    assert (server.requests[0].method, server.requests[0].url.path) == ("GET", "/v1/jobs/job_1")
    assert job.is_terminal
    assert job.exit_code == 0
    assert job.node_id == "node_a"
    assert job.created_at == datetime(2026, 11, 5, 10, 0, tzinfo=UTC)


def test_get_returns_the_attempts_and_a_list_leaves_them_out(
    client: Client, server: FakeServer
) -> None:
    attempt = {
        "attempt": 1,
        "node_id": "node_a",
        "outcome": "succeeded",
        "reason": "exited_0",
        "started_at": "2026-11-05T10:00:01Z",
        "ended_at": "2026-11-05T10:00:05Z",
    }
    server.on("GET", "/v1/jobs/job_1", job_json("job_1", "succeeded", attempts=[attempt]))
    job = client.jobs.get("job_1")
    assert job.attempts is not None
    assert [(a.attempt, a.node_id, a.outcome, a.reason) for a in job.attempts] == [
        (1, "node_a", JobStatus.SUCCEEDED, "exited_0")
    ]
    server.on("GET", "/v1/jobs", {"items": [job_json("job_1", "succeeded")], "next_cursor": None})
    assert [j.attempts for j in client.jobs.list()] == [None]


def test_get_not_found(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/jobs/nope", problem(404, "not_found"))
    with pytest.raises(NotFoundError):
        client.jobs.get("nope")


def test_unexpected_response_shape(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/jobs/bad", {"id": "x", "status": "exploded"})
    with pytest.raises(InvalidResponseError):
        client.jobs.get("bad")
    server.on("GET", "/v1/jobs/html", httpx.Response(200, content=b"<html>"))
    with pytest.raises(InvalidResponseError):
        client.jobs.get("html")


def _page(ids: list[str], cursor: str | None) -> dict[str, Any]:
    return {"items": [job_json(i) for i in ids], "next_cursor": cursor}


def test_list_paginates_across_three_pages(client: Client, server: FakeServer) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        cursor = req.url.params.get("cursor")
        pages = {
            None: _page(["a", "b"], "c2"),
            "c2": _page(["c", "d"], "c3"),
            "c3": _page(["e"], None),
        }
        return json_response(pages[cursor])

    server.on("GET", "/v1/jobs", handler)
    jobs = list(client.jobs.list(status="running", node_id="node_a", limit=2))
    assert [j.id for j in jobs] == ["a", "b", "c", "d", "e"]
    assert all(isinstance(j, Job) for j in jobs)
    assert [r.url.params.get("cursor") for r in server.requests] == [None, "c2", "c3"]
    for req in server.requests:
        assert req.url.params["status"] == "running"
        assert req.url.params["node_id"] == "node_a"
        assert req.url.params["limit"] == "2"


def test_list_is_lazy(client: Client, server: FakeServer) -> None:
    server.on(
        "GET",
        "/v1/jobs",
        json_response(_page(["a"], "c2")),
        json_response(_page(["b"], None)),
    )
    it = iter(client.jobs.list())
    assert server.requests == []  # nothing fetched until iteration starts
    assert next(it).id == "a"
    assert len(server.requests) == 1
    assert next(it).id == "b"
    assert len(server.requests) == 2
    with pytest.raises(StopIteration):
        next(it)


def test_list_defaults_and_status_enum(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/jobs", _page([], None))
    assert list(client.jobs.list(status=JobStatus.QUEUED)) == []
    assert server.query() == {"limit": "50", "status": "queued"}


def test_list_validates_limit_and_detects_cursor_loops(client: Client, server: FakeServer) -> None:
    for bad in (0, 101):
        with pytest.raises(ValueError, match="limit"):
            list(client.jobs.list(limit=bad))
    server.on("GET", "/v1/jobs", _page(["a"], "same"))
    with pytest.raises(InvalidResponseError, match="cursor"):
        list(client.jobs.list())


def test_cancel(client: Client, server: FakeServer) -> None:
    server.on("POST", "/v1/jobs/job_1/cancel", job_json("job_1", "cancelled"))
    job = client.jobs.cancel("job_1")
    assert server.requests[0].method == "POST"
    assert job.status is JobStatus.CANCELLED


def output(path: str, **extra: Any) -> dict[str, Any]:
    """An entry of ``GET /v1/jobs/{id}/outputs`` as the server sends it."""
    return {"path": path, "size": 3, "sha256": "ab" * 32, **extra}


def test_outputs_listing(client: Client, server: FakeServer) -> None:
    server.on(
        "GET",
        "/v1/jobs/job_1/outputs",
        {"items": [{"path": "result.txt", "size": 3, "sha256": "ab" * 32}], "next_cursor": None},
    )
    assert client.jobs.outputs("job_1") == [OutputFile(path="result.txt", size=3, sha256="ab" * 32)]


def test_outputs_follows_pages_and_accepts_bare_arrays(client: Client, server: FakeServer) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.params.get("cursor") == "n":
            return json_response({"items": [output("b")], "next_cursor": None})
        return json_response({"items": [output("a")], "next_cursor": "n"})

    server.on("GET", "/v1/jobs/j/outputs", handler)
    assert [o.path for o in client.jobs.outputs("j")] == ["a", "b"]
    server.on("GET", "/v1/jobs/k/outputs", [output("only")])
    assert [o.path for o in client.jobs.outputs("k")] == ["only"]


# --- logs --------------------------------------------------------------------------------
TS = "2026-11-05T10:00:00Z"


def _ndjson(*records: dict[str, Any]) -> bytes:
    return b"".join(json.dumps(r).encode() + b"\n" for r in records)


def test_logs_query_and_parsing(client: Client, server: FakeServer) -> None:
    body = _ndjson(
        {"seq": 1, "stream": "stdout", "ts": "2026-11-05T10:00:00Z", "data": "hello\n"},
        {"seq": 2, "stream": "stderr", "ts": "2026-11-05T10:00:01Z", "data": "oops\n"},
    )
    server.on("GET", "/v1/jobs/job_1/logs", streamed([body]))
    lines = list(client.jobs.logs("job_1", since_seq=5, attempt=2))
    assert server.query() == {"follow": "false", "since_seq": "5", "attempt": "2"}
    assert server.requests[0].headers["accept"] == "application/x-ndjson"
    assert lines == [
        LogLine(
            seq=1, stream="stdout", ts=datetime(2026, 11, 5, 10, 0, tzinfo=UTC), data="hello\n"
        ),
        LogLine(
            seq=2, stream="stderr", ts=datetime(2026, 11, 5, 10, 0, 1, tzinfo=UTC), data="oops\n"
        ),
    ]


def test_logs_defaults(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/jobs/j/logs", streamed([]))
    assert list(client.jobs.logs("j")) == []
    assert server.query() == {"follow": "false", "since_seq": "0"}


def test_logs_lines_split_across_chunks(client: Client, server: FakeServer) -> None:
    full = _ndjson(
        {"seq": 1, "stream": "stdout", "ts": TS, "data": "héllo wörld\n"},
        {"seq": 2, "stream": "stdout", "ts": TS, "data": "second"},
        {"seq": 3, "stream": "stderr", "ts": TS, "data": "third"},
    )
    # One byte at a time is the worst case: splits inside JSON tokens and inside the
    # multi-byte UTF-8 characters.
    server.on("GET", "/v1/jobs/j/logs", streamed([full[i : i + 1] for i in range(len(full))]))
    lines = list(client.jobs.logs("j"))
    assert [(x.seq, x.data) for x in lines] == [(1, "héllo wörld\n"), (2, "second"), (3, "third")]


def test_logs_blank_lines_and_missing_final_newline(client: Client, server: FakeServer) -> None:
    head = b'{"stream": "stdout", "ts": "' + TS.encode() + b'", '
    chunks = [head + b'"seq": 1, "data": "a"}\n\n', b"\r\n" + head + b'"seq": 2, "da', b'ta": "b"}']
    server.on("GET", "/v1/jobs/j/logs", streamed(chunks))
    assert [x.seq for x in client.jobs.logs("j")] == [1, 2]


def test_logs_invalid_record_and_oversized_line(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/jobs/bad/logs", streamed([b"not json\n"]))
    with pytest.raises(InvalidResponseError):
        list(client.jobs.logs("bad"))
    server.on("GET", "/v1/jobs/big/logs", streamed([b"x" * (1024 * 1024)] * 9))
    with pytest.raises(InvalidResponseError, match="size"):
        list(client.jobs.logs("big"))


def test_logs_is_lazy_and_errors_are_mapped(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/jobs/missing/logs", problem(404, "not_found"))
    it = client.jobs.logs("missing")
    assert server.requests == []
    with pytest.raises(NotFoundError):
        next(it)


def test_logs_validates_arguments_eagerly(client: Client) -> None:
    with pytest.raises(ValueError, match="since_seq"):
        client.jobs.logs("j", since_seq=-1)


# --- wait --------------------------------------------------------------------------------
def test_wait_polls_until_terminal(client: Client, server: FakeServer, clock: FakeClock) -> None:
    server.on(
        "GET",
        "/v1/jobs/j",
        job_json("j", "queued"),
        job_json("j", "running"),
        job_json("j", "succeeded", exit_code=0),
    )
    job = client.jobs.wait("j", poll_interval=0.5)
    assert job.status is JobStatus.SUCCEEDED
    assert server.count("GET", "/v1/jobs/j") == 3
    assert clock.sleeps == [0.5, 0.5]


def test_wait_returns_immediately_when_already_terminal(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    server.on("GET", "/v1/jobs/j", job_json("j", "failed", exit_code=1))
    assert client.jobs.wait("j").status is JobStatus.FAILED
    assert clock.sleeps == []


@pytest.mark.parametrize("status", ["succeeded", "failed", "timed_out", "cancelled", "lost"])
def test_wait_stops_on_every_terminal_state(
    client: Client, server: FakeServer, status: str
) -> None:
    server.on("GET", "/v1/jobs/j", job_json("j", status))
    assert client.jobs.wait("j").status.value == status


def test_wait_times_out(client: Client, server: FakeServer, clock: FakeClock) -> None:
    server.on("GET", "/v1/jobs/j", job_json("j", "running"))
    with pytest.raises(TimeoutError, match="running"):
        client.jobs.wait("j", timeout=5, poll_interval=2)
    # polls at t=0, 2, 4 and a final one at the deadline (t=5); never sleeps past it
    assert clock.sleeps == [2, 2, 1]
    assert server.count("GET", "/v1/jobs/j") == 4


def test_wait_zero_timeout_checks_once(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    server.on("GET", "/v1/jobs/j", job_json("j", "queued"))
    with pytest.raises(TimeoutError):
        client.jobs.wait("j", timeout=0)
    assert server.count("GET", "/v1/jobs/j") == 1
    assert clock.sleeps == []


def test_wait_validates_arguments(client: Client) -> None:
    with pytest.raises(ValueError, match="poll_interval"):
        client.jobs.wait("j", poll_interval=0)
    with pytest.raises(ValueError, match="timeout"):
        client.jobs.wait("j", timeout=-1)


# --- Job convenience methods -------------------------------------------------------------
def test_job_convenience_methods_use_the_creating_client(
    client: Client, server: FakeServer
) -> None:
    server.on("POST", "/v1/jobs", json_response(job_json("j", "queued"), 201))
    server.on("GET", "/v1/jobs/j", job_json("j", "succeeded", exit_code=0))
    server.on(
        "GET",
        "/v1/jobs/j/logs",
        streamed([_ndjson({"seq": 1, "stream": "stdout", "ts": TS, "data": "x"})]),
    )
    server.on("GET", "/v1/jobs/j/outputs", [{"path": "o.txt", "size": 1, "sha256": "00" * 32}])
    server.on("POST", "/v1/jobs/j/cancel", job_json("j", "cancelled"))

    job = client.jobs.run(IMAGE, CMD)
    done = job.wait()
    assert done.status is JobStatus.SUCCEEDED
    assert done.is_terminal
    assert [x.data for x in done.logs()] == ["x"]
    assert [o.path for o in done.outputs()] == ["o.txt"]
    assert done.cancel().status is JobStatus.CANCELLED


def test_u10_one_liner(client: Client, server: FakeServer) -> None:
    server.on("POST", "/v1/jobs", json_response(job_json("j"), 201))
    server.on("GET", "/v1/jobs/j", job_json("j", "succeeded", exit_code=0))
    assert client.jobs.run(image=IMAGE, command=CMD).wait().status is JobStatus.SUCCEEDED


def test_unbound_job_methods_raise() -> None:
    job = Job.model_validate(job_json())
    with pytest.raises(ConfigurationError, match="not bound"):
        job.wait()


# --- download_output ---------------------------------------------------------------------
def _serve_output(server: FakeServer, remote: str, data: bytes, sha: str | None = None) -> None:
    listing = {
        "items": [
            {"path": remote, "size": len(data), "sha256": sha or hashlib.sha256(data).hexdigest()}
        ],
        "next_cursor": None,
    }
    server.on("GET", "/v1/jobs/j/outputs", listing)
    server.on(
        "GET",
        f"/v1/jobs/j/outputs/{remote}",
        httpx.Response(200, content=data),
    )


def test_download_streams_to_disk_and_verifies(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    data = b"hello world" * 10_000
    _serve_output(server, "results/out.bin", data)
    target = client.jobs.download_output("j", "results/out.bin", tmp_path / "dl")
    assert target == (tmp_path / "dl" / "results" / "out.bin").resolve()
    assert target.read_bytes() == data
    assert sorted(p.name for p in target.parent.iterdir()) == ["out.bin"]  # no .part left behind
    assert server.requests[1].url.path == "/v1/jobs/j/outputs/results/out.bin"


def test_download_quotes_the_path(client: Client, server: FakeServer, tmp_path: Path) -> None:
    sha = hashlib.sha256(b"x").hexdigest()
    server.on("GET", "/v1/jobs/j/outputs", [{"path": "my file#1.txt", "size": 1, "sha256": sha}])
    server.on("GET", "/v1/jobs/j/outputs/my file#1.txt", httpx.Response(200, content=b"x"))
    client.jobs.download_output("j", "my file#1.txt", tmp_path)
    assert server.requests[1].url.raw_path == b"/v1/jobs/j/outputs/my%20file%231.txt"
    assert (tmp_path / "my file#1.txt").read_bytes() == b"x"


def test_download_sha256_mismatch_raises_and_leaves_nothing(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    _serve_output(server, "out.bin", b"tampered!", sha="00" * 32)
    with pytest.raises(ChecksumMismatchError):
        client.jobs.download_output("j", "out.bin", tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_download_size_mismatch_raises(client: Client, server: FakeServer, tmp_path: Path) -> None:
    server.on("GET", "/v1/jobs/j/outputs", [{"path": "a", "size": 2, "sha256": "00" * 32}])
    server.on("GET", "/v1/jobs/j/outputs/a", httpx.Response(200, content=b"way too long"))
    with pytest.raises(ChecksumMismatchError, match="size"):
        client.jobs.download_output("j", "a", tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_download_does_not_overwrite_an_existing_file_on_failure(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    (tmp_path / "out.bin").write_bytes(b"precious")
    _serve_output(server, "out.bin", b"tampered!", sha="00" * 32)
    with pytest.raises(ChecksumMismatchError):
        client.jobs.download_output("j", "out.bin", tmp_path)
    assert (tmp_path / "out.bin").read_bytes() == b"precious"


@pytest.mark.parametrize(
    "remote",
    ["../evil.txt", "a/../../evil.txt", "/etc/passwd", "", ".", "a//b", "a\\..\\b", "a\x00b"],
)
def test_download_refuses_paths_that_escape_the_destination(
    client: Client, server: FakeServer, tmp_path: Path, remote: str
) -> None:
    dest = tmp_path / "dest"
    with pytest.raises(UnsafePathError):
        client.jobs.download_output("j", remote, dest)
    assert server.requests == []  # refused before any request
    assert not (tmp_path / "evil.txt").exists()


def test_download_refuses_symlink_escape(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    outside = tmp_path / "outside"
    dest.mkdir()
    outside.mkdir()
    (dest / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(UnsafePathError):
        client.jobs.download_output("j", "link/x.txt", dest)
    assert list(outside.iterdir()) == []


def test_download_unknown_output(client: Client, server: FakeServer, tmp_path: Path) -> None:
    server.on("GET", "/v1/jobs/j/outputs", [output("other")])
    with pytest.raises(NotFoundError, match="missing"):
        client.jobs.download_output("j", "missing", tmp_path)


def test_download_server_error_leaves_nothing(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    server.on("GET", "/v1/jobs/j/outputs", [{"path": "a", "size": 1, "sha256": "00" * 32}])
    server.on("GET", "/v1/jobs/j/outputs/a", problem(500, "boom"))
    with pytest.raises(ServerError):
        client.jobs.download_output("j", "a", tmp_path)
    assert list(tmp_path.iterdir()) == []


# --- estimate, nodes, join tokens, keys, usage -------------------------------------------
def test_estimate(client: Client, server: FakeServer) -> None:
    server.on(
        "POST",
        "/v1/estimate",
        {"feasible": True, "matching_nodes": 1, "would_queue": False, "units_per_hour": 2000},
    )
    est = client.estimate(IMAGE, CMD, cpu=2, timeout_s=3600)
    assert isinstance(est, Estimate)
    assert est.feasible
    assert est.units_per_hour == 2000  # milli-units: 2 units an hour
    assert server.body()["resources"]["cpu"] == 2
    assert server.body()["timeout_s"] == 3600
    assert "idempotency_key" not in server.body()


def test_estimate_infeasible_has_reason(client: Client, server: FakeServer) -> None:
    server.on(
        "POST",
        "/v1/estimate",
        {
            "feasible": False,
            "matching_nodes": 0,
            "would_queue": False,
            "units_per_hour": 0,
            "reason": "no node has a gpu",
        },
    )
    assert client.estimate(IMAGE, CMD, gpu=1).reason == "no node has a gpu"


def test_nodes(client: Client, server: FakeServer) -> None:
    server.on(
        "GET",
        "/v1/nodes",
        json_response({"items": [node_json("node_1")], "next_cursor": "p2"}),
        json_response({"items": [node_json("node_2", draining=True)], "next_cursor": None}),
    )
    nodes = client.nodes.list()
    assert [n.id for n in nodes] == ["node_1", "node_2"]
    assert all(isinstance(n, Node) for n in nodes)
    assert [n.draining for n in nodes] == [False, True]
    assert server.requests[1].url.params["cursor"] == "p2"
    assert "state" not in server.requests[0].url.params

    server.on("GET", "/v1/nodes/node_1", node_json("node_1"))
    node = client.nodes.get("node_1")
    assert node.last_seen == datetime(2026, 11, 5, 10, 0, tzinfo=UTC)
    assert (node.name, node.hostname, node.state) == (
        "workstation",
        "workstation.example.invalid",
        "online",
    )
    assert node.free.gpu == 1
    assert node.free.disk_mb == 30720
    assert (node.inventory.offered.disk_mb, node.inventory.disk_total_mb) == (51200, 512000)
    assert node.inventory.offered.cpu == 8.0
    assert node.inventory.gpus[0].vram_mb == 24564
    assert node.inventory.sandbox[0].sandbox_class == "container"  # the wire name is "class"
    assert node.inventory.sandbox[0].ready is True
    assert node.labels == {"zone": "lab"}

    server.on("POST", "/v1/nodes/node_1/drain", node_json("node_1", draining=True))
    assert client.nodes.drain("node_1").draining is True
    assert server.requests[-1].method == "POST"

    server.on("POST", "/v1/nodes/node_1/resume", node_json("node_1", draining=False))
    assert client.nodes.resume("node_1").draining is False
    assert server.requests[-1].url.path == "/v1/nodes/node_1/resume"

    server.on("DELETE", "/v1/nodes/node_1", httpx.Response(204))
    assert client.nodes.delete("node_1") is None
    assert server.requests[-1].method == "DELETE"


def test_nodes_list_filters_by_state(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/nodes", {"items": [], "next_cursor": None})
    client.nodes.list(state="offline")
    assert server.query()["state"] == "offline"
    server.on("GET", "/v1/nodes", problem(400, "invalid_query", "unknown state"))
    with pytest.raises(P2PCError) as err:
        client.nodes.list(state="sleeping")
    assert err.value.status == 400


def test_node_actions_need_a_node_in_the_answer(client: Client, server: FakeServer) -> None:
    server.on("POST", "/v1/nodes/node_1/drain", httpx.Response(200))
    with pytest.raises(InvalidResponseError):
        client.nodes.drain("node_1")


def test_a_node_without_its_required_members_is_an_invalid_response(
    client: Client, server: FakeServer
) -> None:
    body = node_json()
    del body["inventory"]
    server.on("GET", "/v1/nodes/node_1", body)
    with pytest.raises(InvalidResponseError):
        client.nodes.get("node_1")


def test_node_inventory_tolerates_a_gpuless_wsl2_node_and_unknown_members(
    client: Client, server: FakeServer
) -> None:
    body = node_json()
    inv = body["inventory"]
    inv.update(
        platform="wsl2",
        gpus=[],
        gpu_status={"status": "cdi_missing", "reason": "no CDI spec"},
        wsl2={"cdi_present": False, "cdi_stale": False, "smoke": {"ok": True}},
        a_future_member={"x": 1},
    )
    inv["sandbox"][0].pop("ready")  # an inventory without it decodes as not ready (fail closed)
    server.on("GET", "/v1/nodes/node_1", body)
    node = client.nodes.get("node_1")
    assert node.inventory.platform == "wsl2"
    assert node.inventory.gpu_status.reason == "no CDI spec"
    assert node.inventory.wsl2 is not None
    assert node.inventory.wsl2.smoke is not None
    assert node.inventory.wsl2.smoke.ok
    assert node.inventory.wsl2.podman_version is None
    assert node.inventory.sandbox[0].ready is False
    assert not hasattr(node.inventory, "a_future_member")


def test_server_info(client: Client, server: FakeServer) -> None:
    server.on(
        "GET",
        "/v1/server",
        {
            "node_id": "ab" * 32,
            "relays": ["https://relay.example.invalid"],
            "address": SRV_ADDRESS,
            "version": "0.1.0",
        },
    )
    info = client.server()
    assert isinstance(info, ServerInfo)
    assert (info.node_id, info.relays, info.address, info.version) == (
        "ab" * 32,
        ["https://relay.example.invalid"],
        SRV_ADDRESS,
        "0.1.0",
    )
    assert server.requests[-1].url.path == "/v1/server"


def test_join_tokens(client: Client, server: FakeServer) -> None:
    server.on(
        "POST",
        "/v1/nodes/join-tokens",
        json_response(
            {"id": "jtk_1", "join_token": JOIN_TOKEN, "expires_at": "2026-11-05T10:15:00Z"},
            201,
        ),
    )
    tok = client.join_tokens.create(ttl_s=900)
    assert isinstance(tok, JoinToken)
    assert tok.id == "jtk_1"
    assert tok.join_token.get_secret_value() == JOIN_TOKEN
    assert JOIN_TOKEN not in repr(tok)
    assert server.body() == {"ttl_s": 900}
    client.join_tokens.create()
    assert server.body() == {}
    for bad in (0, 86_401):
        with pytest.raises(ValueError, match="ttl_s"):
            client.join_tokens.create(ttl_s=bad)


def test_keys_create_returns_the_flat_response_with_the_key(
    client: Client, server: FakeServer
) -> None:
    created = key_json(
        "zzzzzzzzzzzz",
        scopes=["jobs:read", "jobs:write"],
        daily_unit_cap=10_000,
        allowed_images=["docker.io/library/*"],
        label="ci",
        expires_at="2027-01-01T00:00:00Z",
        key=NEW_KEY,
    )
    server.on("POST", "/v1/keys", json_response(created, 201))
    key = client.keys.create(
        ["jobs:read", "jobs:write"],
        daily_unit_cap=10_000,
        allowed_images=["docker.io/library/*"],
        label="ci",
        expires_at=datetime(2027, 1, 1, tzinfo=UTC),
    )
    assert isinstance(key, NewApiKey)
    assert key.key.get_secret_value() == NEW_KEY
    assert (key.id, key.label, key.daily_unit_cap) == ("zzzzzzzzzzzz", "ci", 10_000)
    assert key.expires_at == datetime(2027, 1, 1, tzinfo=UTC)
    assert key.revoked_at is None
    assert KEY_SECRET not in repr(key)
    assert server.body() == {
        "scopes": ["jobs:read", "jobs:write"],
        "daily_unit_cap": 10_000,
        "allowed_images": ["docker.io/library/*"],
        "label": "ci",
        "expires_at": "2027-01-01T00:00:00Z",
    }

    client.keys.create(["admin"])
    assert server.body() == {"scopes": ["admin"]}
    for bad in ([], ["root"]):
        with pytest.raises(ValueError, match="scopes"):
            client.keys.create(bad)


def test_key_expiry_is_sent_in_whole_seconds_utc(client: Client, server: FakeServer) -> None:
    server.on("POST", "/v1/keys", json_response(key_json(key=NEW_KEY), 201))
    plus_two = timezone(timedelta(hours=2))
    client.keys.create(["admin"], expires_at=datetime(2027, 1, 1, 2, 0, 0, 999_999, plus_two))
    # The fraction is dropped (a shorter life, never a longer one) and the zone normalised.
    assert server.body()["expires_at"] == "2027-01-01T00:00:00Z"
    client.keys.create(["admin"], expires_at="2027-01-01T00:00:00Z")
    assert server.body()["expires_at"] == "2027-01-01T00:00:00Z"
    # A string with a fraction and a zone is normalised the same way; a naive time is UTC.
    client.keys.create(["admin"], expires_at="2027-01-01T05:30:00.75+05:30")
    assert server.body()["expires_at"] == "2027-01-01T00:00:00Z"
    client.keys.create(["admin"], expires_at=datetime(2027, 1, 1, 0, 0, 0, 1))
    assert server.body()["expires_at"] == "2027-01-01T00:00:00Z"
    # Whatever the form, no fractional part reaches the wire (the server answers 422 to one).
    minus_five = timezone(timedelta(hours=-5))
    client.keys.create(["admin"], expires_at=datetime(2026, 12, 31, 19, 0, 0, 123_456, minus_five))
    assert "." not in server.body()["expires_at"]
    with pytest.raises(ValueError, match="expires_at"):
        client.keys.create(["admin"], expires_at="soon")


def test_keys_list_shows_lifecycle_and_never_a_secret(client: Client, server: FakeServer) -> None:
    server.on(
        "GET",
        "/v1/keys",
        {
            "items": [
                key_json("k1", scopes=["admin"], last_used_at="2026-11-05T11:00:00Z"),
                key_json("k2", revoked_at="2026-11-05T12:00:00Z", label="old"),
            ],
            "next_cursor": None,
        },
    )
    live, revoked = client.keys.list()
    assert isinstance(live, ApiKey)
    assert not live.is_revoked
    assert live.last_used_at == datetime(2026, 11, 5, 11, 0, tzinfo=UTC)
    assert revoked.is_revoked
    assert revoked.label == "old"


def test_keys_revoke_sends_delete_and_delete_is_an_alias(
    client: Client, server: FakeServer
) -> None:
    server.on("DELETE", "/v1/keys/k1", httpx.Response(204))
    assert client.keys.revoke("k1") is None
    assert (server.requests[-1].method, server.requests[-1].url.path) == ("DELETE", "/v1/keys/k1")
    assert client.keys.delete("k1") is None
    assert server.count("DELETE", "/v1/keys/k1") == 2


def test_revoking_the_last_admin_key_is_a_conflict_with_its_code(
    client: Client, server: FakeServer
) -> None:
    server.on("DELETE", "/v1/keys/k1", problem(409, "last_admin_key"))
    with pytest.raises(ConflictError) as err:
        client.keys.revoke("k1")
    assert err.value.code == "last_admin_key"


def test_whoami_returns_the_keys_limits(client: Client, server: FakeServer) -> None:
    server.on(
        "GET",
        "/v1/whoami",
        {
            "account_id": "acc_1",
            "project_id": "prj_1",
            "key_id": "abcdefghijkl",
            "scopes": ["jobs:read"],
            "label": "laptop",
            "daily_unit_cap": 5_000,
            "allowed_images": ["docker.io/library/*"],
            "expires_at": "2027-01-01T00:00:00Z",
        },
    )
    me = client.whoami()
    assert isinstance(me, WhoAmI)
    assert (me.account_id, me.key_id, me.scopes) == ("acc_1", "abcdefghijkl", ["jobs:read"])
    assert me.daily_unit_cap == 5_000  # milli-units
    assert me.allowed_images == ["docker.io/library/*"]
    assert me.expires_at == datetime(2027, 1, 1, tzinfo=UTC)
    assert KEY_SECRET not in repr(me)


def test_whoami_of_an_unrestricted_key_has_null_limits(client: Client, server: FakeServer) -> None:
    server.on(
        "GET",
        "/v1/whoami",
        {"account_id": "a", "project_id": "p", "key_id": "k", "scopes": ["admin"]},
    )
    me = client.whoami()
    assert (me.label, me.daily_unit_cap, me.allowed_images, me.expires_at) == (None,) * 4


def test_whoami_with_a_bad_key_is_an_authentication_error(
    client: Client, server: FakeServer
) -> None:
    server.on("GET", "/v1/whoami", problem(401, "unauthenticated"))
    with pytest.raises(AuthenticationError) as err:
        client.whoami()
    assert err.value.code == "unauthenticated"


def test_audit_iterates_pages_and_filters_by_kind(client: Client, server: FakeServer) -> None:
    def event(n: int, kind: str = "key_created") -> dict[str, Any]:
        return {
            "id": f"aud_{n}",
            "at": "2026-11-05T10:00:00Z",
            "kind": kind,
            "detail": {"scopes": ["admin"]},
            "actor_key_id": "abcdefghijkl",
            "subject_id": "zzzzzzzzzzzz",
        }

    server.on(
        "GET",
        "/v1/audit",
        json_response({"items": [event(2)], "next_cursor": "c2"}),
        json_response(
            {"items": [{**event(1), "actor_key_id": None, "subject_id": None}], "next_cursor": None}
        ),
    )
    events = list(client.audit(kind="key_created", limit=1))
    assert [e.id for e in events] == ["aud_2", "aud_1"]
    assert isinstance(events[0], AuditEvent)
    assert events[0].detail == {"scopes": ["admin"]}
    assert events[1].actor_key_id is None
    assert server.requests[0].url.params["kind"] == "key_created"
    assert server.requests[0].url.params["limit"] == "1"
    assert server.requests[1].url.params["cursor"] == "c2"
    with pytest.raises(ValueError, match="limit"):
        client.audit(limit=0)


def test_audit_without_a_filter_sends_no_kind(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/audit", {"items": [], "next_cursor": None})
    assert list(client.audit()) == []
    assert "kind" not in server.query()


def test_join_token_list_and_revoke(client: Client, server: FakeServer) -> None:
    server.on(
        "GET",
        "/v1/nodes/join-tokens",
        {
            "items": [
                join_token_info_json(
                    "jtk_1",
                    label="laptop",
                    consumed_at="2026-11-05T10:05:00Z",
                    consumed_by_node_id="node_1",
                )
            ],
            "next_cursor": None,
        },
    )
    (info,) = client.join_tokens.list()
    assert isinstance(info, JoinTokenInfo)
    assert (info.id, info.consumed_by_node_id, info.revoked_at) == ("jtk_1", "node_1", None)
    server.on("DELETE", "/v1/nodes/join-tokens/jtk_1", httpx.Response(204))
    assert client.join_tokens.revoke("jtk_1") is None
    assert server.requests[-1].method == "DELETE"
    with pytest.raises(ValueError, match="id"):
        client.join_tokens.revoke("..")


def test_revoking_a_consumed_join_token_is_a_conflict_with_its_code(
    client: Client, server: FakeServer
) -> None:
    server.on("DELETE", "/v1/nodes/join-tokens/jtk_1", problem(409, "token_consumed"))
    with pytest.raises(ConflictError) as err:
        client.join_tokens.revoke("jtk_1")
    assert err.value.code == "token_consumed"


def test_join_token_create_can_carry_a_label(client: Client, server: FakeServer) -> None:
    server.on(
        "POST",
        "/v1/nodes/join-tokens",
        json_response(
            {"id": "jtk_1", "join_token": JOIN_TOKEN, "expires_at": "2026-11-05T10:15:00Z"}, 201
        ),
    )
    tok = client.join_tokens.create(ttl_s=60, label="laptop")
    assert server.body() == {"ttl_s": 60, "label": "laptop"}
    assert tok.id == "jtk_1"


def test_invalid_specs_fail_before_any_request(client: Client, server: FakeServer) -> None:
    for kwargs in (
        {"env": {"TOKEN": "a\nb"}},
        {"env": {"TOKEN": "a\x00b"}},
        {"files": {"/inputs/big": b"x" * (512 * 1024 + 1)}},
        {"cpu": 1.0005},
    ):
        with pytest.raises(ValueError):  # noqa: PT011 - pydantic's ValidationError is one
            client.jobs.create(IMAGE, CMD, **kwargs)  # type: ignore[arg-type]
        with pytest.raises(ValueError):  # noqa: PT011
            client.estimate(IMAGE, CMD, **kwargs)  # type: ignore[arg-type]
    assert server.requests == []


def usage_totals(key: str | None, **extra: Any) -> dict[str, Any]:
    """One ``UsageTotals`` as ``GET /v1/usage`` returns it (milli-units, milliseconds, MiB)."""
    return {
        "key": key,
        "attempts": 2,
        "reserved_cpu_ms": 7_200_000,
        "reserved_gpu_ms": 0,
        "used_cpu_ms": 5_000_000,
        "max_rss_mb": 512,
        "units": 2000,
        **extra,
    }


def usage_page(
    items: list[dict[str, Any]], cursor: str | None, total: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "from": "2026-11-01T00:00:00Z",
        "to": "2026-11-05T00:00:00Z",
        "group_by": "job",
        "items": items,
        "next_cursor": cursor,
        "total": total or usage_totals(None, attempts=3, units=2250),
    }


def test_usage_returns_the_grouped_report_with_its_total(
    client: Client, server: FakeServer
) -> None:
    server.on(
        "GET",
        "/v1/usage",
        json_response(usage_page([usage_totals("job_1", estimated_attempts=1)], "u2")),
        json_response(usage_page([usage_totals("job_2", attempts=1, units=250)], None)),
    )
    report = client.usage(
        from_=datetime(2026, 11, 1, tzinfo=UTC), to="2026-11-05T00:00:00Z", group_by="job"
    )
    assert isinstance(report, UsageReport)
    assert (report.from_, report.to, report.group_by) == (
        datetime(2026, 11, 1, tzinfo=UTC),
        datetime(2026, 11, 5, tzinfo=UTC),
        "job",
    )
    # Every page of groups is followed; the total is the server's, for the whole range.
    assert [(g.key, g.attempts, g.estimated_attempts, g.units) for g in report.items] == [
        ("job_1", 2, 1, 2000),
        ("job_2", 1, 0, 250),
    ]
    assert all(isinstance(g, UsageTotals) for g in report.items)
    assert report.next_cursor is None
    assert report.total.key is None
    assert (report.total.attempts, report.total.units) == (3, 2250)
    assert (report.items[0].used_cpu_ms, report.items[0].max_rss_mb) == (5_000_000, 512)
    assert server.requests[0].url.params["from"] == "2026-11-01T00:00:00+00:00"
    assert server.requests[0].url.params["to"] == "2026-11-05T00:00:00Z"
    assert server.requests[0].url.params["group_by"] == "job"
    assert server.requests[0].url.params["limit"] == "100"
    assert server.requests[1].url.params["cursor"] == "u2"


def test_usage_defaults_and_validation(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/usage", usage_page([], None))
    assert client.usage(group_by="node").items == []
    assert server.query() == {"group_by": "node", "limit": "100"}
    with pytest.raises(ValueError, match="group_by"):
        client.usage(group_by="user")


def test_usage_sends_fractions_of_a_second_unchanged(client: Client, server: FakeServer) -> None:
    # GET /v1/usage takes any RFC 3339 instant (only key expiry must be whole seconds), and
    # truncating `to`, which is exclusive, would drop the attempts that ended in that second.
    server.on("GET", "/v1/usage", usage_page([], None))
    plus_two = timezone(timedelta(hours=2))
    client.usage(
        from_=datetime(2026, 11, 1, 2, 0, 0, 250_000, plus_two),
        to=datetime(2026, 11, 2, 0, 0, 0, 500_000),  # naive: taken as UTC
    )
    assert server.query()["from"] == "2026-11-01T02:00:00.250000+02:00"
    assert server.query()["to"] == "2026-11-02T00:00:00.500000+00:00"


def day_page(day: int, items: list[dict[str, Any]], cursor: str | None) -> httpx.Response:
    """A usage page for the UTC day ``day`` of November 2026 (what "today" is for the server)."""
    page = usage_page(items, cursor)
    page["from"], page["to"] = f"2026-11-{day:02d}T00:00:00Z", f"2026-11-{day + 1:02d}T00:00:00Z"
    return json_response(page)


def test_usage_without_a_range_pins_the_first_pages_range_on_every_page(
    client: Client, server: FakeServer
) -> None:
    # The first page is served on 5 November; midnight UTC passes; the server would now answer
    # the second page for the 6th. Sending page 1's range keeps the whole report on one day.
    seen: list[dict[str, str]] = []

    def second(req: httpx.Request) -> httpx.Response:
        seen.append(dict(req.url.params))
        day = 5 if req.url.params.get("from") else 6  # "today" when it is not pinned
        return day_page(day, [usage_totals("job_2")], None)

    server.on("GET", "/v1/usage", day_page(5, [usage_totals("job_1")], "u2"), second)
    report = client.usage()
    assert [g.key for g in report.items] == ["job_1", "job_2"]
    assert report.from_ == datetime(2026, 11, 5, tzinfo=UTC)
    first = dict(server.requests[0].url.params)
    assert "from" not in first
    assert "to" not in first
    assert seen == [
        {
            "group_by": "job",
            "limit": "100",
            "cursor": "u2",
            "from": "2026-11-05T00:00:00+00:00",
            "to": "2026-11-06T00:00:00+00:00",
        }
    ]


def test_usage_keeps_a_range_the_caller_gave(client: Client, server: FakeServer) -> None:
    server.on(
        "GET",
        "/v1/usage",
        day_page(1, [usage_totals("job_1")], "u2"),
        day_page(1, [usage_totals("job_2")], None),
    )
    client.usage(from_="2026-11-01T00:00:00Z", to="2026-11-02T00:00:00Z")
    for request in server.requests:
        assert request.url.params["from"] == "2026-11-01T00:00:00Z"
        assert request.url.params["to"] == "2026-11-02T00:00:00Z"


def test_usage_pins_only_the_bound_the_caller_left_out(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/usage", day_page(1, [], "u2"), day_page(1, [], None))
    client.usage(from_="2026-11-01T00:00:00Z")
    assert server.requests[1].url.params["from"] == "2026-11-01T00:00:00Z"
    assert server.requests[1].url.params["to"] == "2026-11-02T00:00:00+00:00"


def many_groups(first: int, count: int) -> list[dict[str, Any]]:
    return [usage_totals(f"job_{n:05d}") for n in range(first, first + count)]


def test_usage_stops_at_10000_groups_and_names_the_limit(
    client: Client, server: FakeServer
) -> None:
    # 100 groups per page: the 101st page would be the 10 001st group and beyond.
    pages = [json_response(usage_page(many_groups(n * 100, 100), f"u{n + 1}")) for n in range(120)]
    server.on("GET", "/v1/usage", *pages)
    with pytest.raises(InvalidResponseError, match="10000"):
        client.usage()
    assert server.count("GET", "/v1/usage") == 100  # it did not go on to fetch more


def test_usage_accepts_exactly_10000_groups(client: Client, server: FakeServer) -> None:
    pages = [
        json_response(usage_page(many_groups(n * 100, 100), None if n == 99 else f"u{n + 1}"))
        for n in range(100)
    ]
    server.on("GET", "/v1/usage", *pages)
    assert len(client.usage().items) == 10_000


def test_usage_refuses_a_server_that_repeats_a_cursor(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/usage", usage_page([usage_totals("job_1")], "same"))
    with pytest.raises(InvalidResponseError, match="cursor"):
        client.usage()


def test_idempotency_key_and_outputs_limit_are_checked_before_any_request(
    client: Client, server: FakeServer
) -> None:
    for bad_key in ("", "has space", "x" * 256, "naïve"):
        with pytest.raises(ValidationError, match="idempotency_key"):
            client.jobs.create(IMAGE, CMD, idempotency_key=bad_key)
    with pytest.raises(ValidationError):
        client.jobs.create(IMAGE, CMD, outputs_max_mb=10_241)
    with pytest.raises(ValidationError):
        client.estimate(IMAGE, CMD, outputs_max_mb=0)
    assert server.requests == []
    server.on("POST", "/v1/jobs", json_response(job_json(), 201))
    client.jobs.create(IMAGE, CMD, idempotency_key="nightly-1", outputs_max_mb=10_240)
    assert server.body()["idempotency_key"] == "nightly-1"
    assert server.body()["outputs"] == {"max_mb": 10_240}


def test_a_node_from_an_agent_without_disk_still_parses(client: Client, server: FakeServer) -> None:
    """Spec §6 (amended 2026-11-07): ``disk_mb`` is optional, an older agent does not report it."""
    body = node_json("node_1")
    del body["free"]["disk_mb"]
    del body["inventory"]["offered"]["disk_mb"]
    del body["inventory"]["disk_total_mb"]
    server.on("GET", "/v1/nodes/node_1", body)
    node = client.nodes.get("node_1")
    assert node.free.disk_mb is None
    assert node.inventory.offered.disk_mb is None
    assert node.inventory.disk_total_mb is None
