# SPDX-License-Identifier: Apache-2.0
"""Async parity with the sync client: create, get, wait, logs, and the rest of the surface."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from helpers import (
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

from p2pc import (
    AsyncClient,
    AsyncJob,
    CapExceededError,
    ChecksumMismatchError,
    ConfigurationError,
    InvalidResponseError,
    JobStatus,
    LogLine,
    NotFoundError,
    P2PCConnectionError,
    UnsafePathError,
)

pytestmark = pytest.mark.asyncio

SRV_ADDRESS = "p2pc_srv_EXAMPLE"  # gitleaks:allow
JOIN_TOKEN = "p2pc_join_EXAMPLE"  # gitleaks:allow

Factory = Callable[..., AsyncClient]
IMAGE = "docker.io/library/python:3.12-slim"
CMD = ["python", "-c", "print(6*7)"]


@pytest.fixture
def aclient(make_aclient: Factory) -> AsyncClient:
    return make_aclient()


async def test_create_and_get(aclient: AsyncClient, server: FakeServer) -> None:
    server.on("POST", "/v1/jobs", json_response(job_json("job_1"), 201))
    server.on("GET", "/v1/jobs/job_1", job_json("job_1", "running"))
    job = await aclient.jobs.create(IMAGE, CMD, cpu=2, env={"A": "1"}, idempotency_key="k")
    assert isinstance(job, AsyncJob)
    assert server.requests[0].headers["authorization"] == f"Bearer {KEY}"
    assert server.requests[0].headers["user-agent"].startswith("p2pc-python/")
    assert server.body()["resources"]["cpu"] == 2
    assert server.body()["idempotency_key"] == "k"
    assert (await aclient.jobs.get("job_1")).status is JobStatus.RUNNING
    assert (await aclient.jobs.run(IMAGE, CMD)).id == "job_1"


async def test_client_side_validation_and_errors(aclient: AsyncClient, server: FakeServer) -> None:
    with pytest.raises(ValidationError):
        await aclient.jobs.create(IMAGE, [])
    with pytest.raises(TypeError, match="argv"):
        await aclient.jobs.create(IMAGE, "echo hi")  # type: ignore[arg-type]
    assert server.requests == []
    server.on("POST", "/v1/jobs", problem(402, "cap_exceeded"))
    with pytest.raises(CapExceededError):
        await aclient.jobs.create(IMAGE, CMD)
    server.on("GET", "/v1/jobs/x", problem(404, "not_found"))
    with pytest.raises(NotFoundError):
        await aclient.jobs.get("x")


async def test_missing_key_fails_at_first_call(server: FakeServer) -> None:
    c = AsyncClient(http_client=httpx.AsyncClient(transport=httpx.MockTransport(server)))
    with pytest.raises(ConfigurationError, match="P2PC_API_KEY"):
        await c.jobs.get("j")
    assert server.requests == []


async def test_transport_error(aclient: AsyncClient, server: FakeServer) -> None:
    def boom(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"refused {KEY}")

    server.on("GET", "/v1/jobs/j", boom)
    with pytest.raises(P2PCConnectionError) as err:
        await aclient.jobs.get("j")
    assert KEY not in str(err.value)
    assert KEY_SECRET not in str(err.value)


async def test_key_masked_in_repr_and_logs(
    aclient: AsyncClient, server: FakeServer, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    assert KEY not in repr(aclient)
    assert KEY not in str(aclient)
    assert "p2pc_sk_abc…" in repr(aclient)
    server.on("GET", "/v1/jobs/j", job_json("j"))
    await aclient.jobs.get("j")
    assert any(r.name == "p2pc" for r in caplog.records)
    assert KEY not in caplog.text


async def test_wait_polls_until_terminal(
    aclient: AsyncClient, server: FakeServer, clock: FakeClock
) -> None:
    server.on(
        "GET",
        "/v1/jobs/j",
        job_json("j", "queued"),
        job_json("j", "running"),
        job_json("j", "succeeded", exit_code=0),
    )
    job = await aclient.jobs.wait("j", poll_interval=0.5)
    assert job.status is JobStatus.SUCCEEDED
    assert clock.sleeps == [0.5, 0.5]


async def test_wait_times_out(aclient: AsyncClient, server: FakeServer, clock: FakeClock) -> None:
    server.on("GET", "/v1/jobs/j", job_json("j", "running"))
    with pytest.raises(TimeoutError):
        await aclient.jobs.wait("j", timeout=5, poll_interval=2)
    assert clock.sleeps == [2, 2, 1]
    with pytest.raises(ValueError, match="poll_interval"):
        await aclient.jobs.wait("j", poll_interval=0)


async def test_logs_split_across_chunks(aclient: AsyncClient, server: FakeServer) -> None:
    full = b"".join(
        json.dumps(
            {"seq": i, "stream": "stdout", "ts": "2026-11-05T10:00:00Z", "data": f"líne {i}\n"}
        ).encode()
        + b"\n"
        for i in range(1, 4)
    )
    server.on("GET", "/v1/jobs/j/logs", streamed([full[i : i + 3] for i in range(0, len(full), 3)]))
    lines = [x async for x in aclient.jobs.logs("j", since_seq=2)]
    assert [x.seq for x in lines] == [1, 2, 3]
    assert lines[0] == LogLine(
        seq=1, stream="stdout", ts=datetime(2026, 11, 5, 10, 0, tzinfo=UTC), data="líne 1\n"
    )
    assert server.query() == {"follow": "false", "since_seq": "2"}


async def test_logs_error_mapping_and_validation(aclient: AsyncClient, server: FakeServer) -> None:
    server.on("GET", "/v1/jobs/missing/logs", problem(404, "not_found"))
    with pytest.raises(NotFoundError):
        [x async for x in aclient.jobs.logs("missing")]
    with pytest.raises(ValueError, match="since_seq"):
        aclient.jobs.logs("j", since_seq=-1)


async def test_list_paginates(aclient: AsyncClient, server: FakeServer) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        cursor = req.url.params.get("cursor")
        pages: dict[str | None, dict[str, Any]] = {
            None: {"items": [job_json("a")], "next_cursor": "c2"},
            "c2": {"items": [job_json("b")], "next_cursor": "c3"},
            "c3": {"items": [job_json("c")], "next_cursor": None},
        }
        return json_response(pages[cursor])

    server.on("GET", "/v1/jobs", handler)
    jobs = [j async for j in aclient.jobs.list(status="queued", limit=1)]
    assert [j.id for j in jobs] == ["a", "b", "c"]
    assert all(isinstance(j, AsyncJob) for j in jobs)
    assert [r.url.params.get("cursor") for r in server.requests] == [None, "c2", "c3"]


async def test_cancel_outputs_and_job_convenience(aclient: AsyncClient, server: FakeServer) -> None:
    server.on("POST", "/v1/jobs", json_response(job_json("j"), 201))
    server.on("GET", "/v1/jobs/j", job_json("j", "succeeded", exit_code=0))
    server.on(
        "GET",
        "/v1/jobs/j/logs",
        streamed([b'{"seq": 1, "stream": "stdout", "ts": "2026-11-05T10:00:00Z", "data": "x"}\n']),
    )
    server.on("GET", "/v1/jobs/j/outputs", [{"path": "o.txt", "size": 1, "sha256": "00" * 32}])
    server.on("POST", "/v1/jobs/j/cancel", job_json("j", "cancelled"))
    job = await aclient.jobs.run(IMAGE, CMD)
    done = await job.wait()
    assert done.is_terminal
    assert [x.data async for x in done.logs()] == ["x"]
    assert [o.path for o in await done.outputs()] == ["o.txt"]
    assert (await done.cancel()).status is JobStatus.CANCELLED


async def test_download_output(aclient: AsyncClient, server: FakeServer, tmp_path: Path) -> None:
    data = b"payload" * 5000
    server.on(
        "GET",
        "/v1/jobs/j/outputs",
        [{"path": "d/out.bin", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}],
    )
    server.on("GET", "/v1/jobs/j/outputs/d/out.bin", httpx.Response(200, content=data))
    target = await aclient.jobs.download_output("j", "d/out.bin", tmp_path)
    assert target.read_bytes() == data


async def test_download_mismatch_and_traversal(
    aclient: AsyncClient, server: FakeServer, tmp_path: Path
) -> None:
    server.on("GET", "/v1/jobs/j/outputs", [{"path": "a", "size": 3, "sha256": "00" * 32}])
    server.on("GET", "/v1/jobs/j/outputs/a", httpx.Response(200, content=b"abc"))
    with pytest.raises(ChecksumMismatchError):
        await aclient.jobs.download_output("j", "a", tmp_path)
    assert list(tmp_path.iterdir()) == []
    n = len(server.requests)
    with pytest.raises(UnsafePathError):
        await aclient.jobs.download_output("j", "../x", tmp_path)
    assert len(server.requests) == n


async def test_remaining_surface(aclient: AsyncClient, server: FakeServer) -> None:
    server.on(
        "POST",
        "/v1/estimate",
        {"feasible": True, "matching_nodes": 1, "would_queue": False, "units_per_hour": 1000},
    )
    assert (await aclient.estimate(IMAGE, CMD)).feasible

    server.on(
        "GET",
        "/v1/nodes",
        json_response({"items": [node_json("n1")], "next_cursor": "p"}),
        json_response({"items": [node_json("n2")], "next_cursor": None}),
    )
    assert [n.id for n in await aclient.nodes.list(state="online")] == ["n1", "n2"]
    node_pages = [r for r in server.requests if r.url.path == "/v1/nodes"]
    assert [r.url.params["state"] for r in node_pages] == ["online", "online"]
    server.on("GET", "/v1/nodes/n1", node_json("n1"))
    assert (await aclient.nodes.get("n1")).id == "n1"
    server.on("POST", "/v1/nodes/n1/drain", node_json("n1", draining=True))
    assert (await aclient.nodes.drain("n1")).draining
    server.on("POST", "/v1/nodes/n1/resume", node_json("n1"))
    assert not (await aclient.nodes.resume("n1")).draining
    server.on("DELETE", "/v1/nodes/n1", httpx.Response(204))
    await aclient.nodes.delete("n1")
    server.on(
        "GET",
        "/v1/server",
        {"node_id": "ab" * 32, "relays": [], "address": SRV_ADDRESS, "version": "0.1.0"},
    )
    assert (await aclient.server()).address == SRV_ADDRESS

    server.on(
        "POST",
        "/v1/nodes/join-tokens",
        {"id": "jtk_1", "join_token": JOIN_TOKEN, "expires_at": "2026-11-05T10:15:00Z"},
    )
    tok = await aclient.join_tokens.create(ttl_s=60)
    assert tok.join_token.get_secret_value() == JOIN_TOKEN
    assert server.body() == {"ttl_s": 60}

    server.on("POST", "/v1/keys", {**key_json("k", scopes=["admin"]), "key": "s3cret"})
    key = await aclient.keys.create(["admin"], daily_unit_cap=5, label="ci")
    assert key.key.get_secret_value() == "s3cret"
    assert "s3cret" not in repr(key)
    assert server.body() == {"scopes": ["admin"], "daily_unit_cap": 5, "label": "ci"}
    server.on("GET", "/v1/keys", {"items": [key_json("k", scopes=[])], "next_cursor": None})
    assert [k.id for k in await aclient.keys.list()] == ["k"]
    server.on("DELETE", "/v1/keys/k", httpx.Response(204))
    await aclient.keys.revoke("k")
    await aclient.keys.delete("k")

    server.on(
        "GET",
        "/v1/whoami",
        {"account_id": "a", "project_id": "p", "key_id": "k", "scopes": ["admin"]},
    )
    assert (await aclient.whoami()).key_id == "k"
    server.on(
        "GET",
        "/v1/audit",
        {
            "items": [
                {"id": "aud_1", "at": "2026-11-05T10:00:00Z", "kind": "key_revoked", "detail": {}}
            ],
            "next_cursor": None,
        },
    )
    assert [e.id async for e in aclient.audit(kind="key_revoked")] == ["aud_1"]
    assert server.query()["kind"] == "key_revoked"

    server.on(
        "GET",
        "/v1/nodes/join-tokens",
        {
            "items": [join_token_info_json("jtk_1")],
            "next_cursor": None,
        },
    )
    assert [t.id for t in await aclient.join_tokens.list()] == ["jtk_1"]
    server.on("DELETE", "/v1/nodes/join-tokens/jtk_1", httpx.Response(204))
    await aclient.join_tokens.revoke("jtk_1")

    totals = {
        "attempts": 1,
        "reserved_cpu_ms": 1,
        "reserved_gpu_ms": 0,
        "used_cpu_ms": 1,
        "max_rss_mb": 1,
        "units": 1,
    }
    server.on(
        "GET",
        "/v1/usage",
        {
            "from": "2026-11-01T00:00:00Z",
            "to": "2026-11-02T00:00:00Z",
            "group_by": "job",
            "items": [{**totals, "key": "job_1", "estimated_attempts": 1}],
            "next_cursor": "u2",
            "total": {**totals, "attempts": 2, "key": None},
        },
        {
            "from": "2026-11-01T00:00:00Z",
            "to": "2026-11-02T00:00:00Z",
            "group_by": "job",
            "items": [{**totals, "key": "job_2"}],
            "next_cursor": None,
            "total": {**totals, "attempts": 2, "key": None},
        },
    )
    report = await aclient.usage(group_by="job")
    assert [(g.key, g.estimated_attempts) for g in report.items] == [("job_1", 1), ("job_2", 0)]
    assert (report.total.attempts, report.next_cursor) == (2, None)
    assert server.requests[-2].url.params["group_by"] == "job"
    assert server.requests[-1].url.params["cursor"] == "u2"
    with pytest.raises(ValueError, match="group_by"):
        await aclient.usage(group_by="user")


async def test_context_manager_closes_only_owned_http_client(
    server: FakeServer, make_aclient: Factory
) -> None:
    injected = httpx.AsyncClient(transport=httpx.MockTransport(server))
    async with make_aclient(http_client=injected):
        pass
    assert not injected.is_closed
    await injected.aclose()
    async with AsyncClient(api_key=KEY) as owned:
        inner = owned._http
    assert inner.is_closed


async def test_usage_pins_the_range_and_stops_at_10000_groups(
    aclient: AsyncClient, server: FakeServer
) -> None:
    def totals(key: str) -> dict[str, Any]:
        return {
            "key": key,
            "attempts": 1,
            "reserved_cpu_ms": 1,
            "reserved_gpu_ms": 0,
            "used_cpu_ms": 1,
            "max_rss_mb": 1,
            "units": 1,
        }

    def page(n: int, cursor: str | None, day: int = 5) -> dict[str, Any]:
        return {
            "from": f"2026-11-{day:02d}T00:00:00Z",
            "to": f"2026-11-{day + 1:02d}T00:00:00Z",
            "group_by": "job",
            "items": [totals(f"job_{n}_{i}") for i in range(100)],
            "next_cursor": cursor,
            "total": totals("x") | {"key": None},
        }

    server.on("GET", "/v1/usage", page(0, "u1"), page(1, None, day=6))  # midnight passed
    report = await aclient.usage()
    assert len(report.items) == 200
    assert report.from_ == datetime(2026, 11, 5, tzinfo=UTC)
    assert "from" not in server.requests[0].url.params
    assert server.requests[1].url.params["from"] == "2026-11-05T00:00:00+00:00"
    assert server.requests[1].url.params["to"] == "2026-11-06T00:00:00+00:00"

    server.requests.clear()
    server.on("GET", "/v1/usage", *[page(n, f"u{n + 1}") for n in range(120)])
    with pytest.raises(InvalidResponseError, match="10000"):
        await aclient.usage()
    assert server.count("GET", "/v1/usage") == 100
