# SPDX-License-Identifier: Apache-2.0
"""Review fixes: mandatory download digests, error-body redaction and caps, log reconnects."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from contextlib import aclosing
from pathlib import Path

import httpx
import pytest
from helpers import (
    KEY,
    KEY_SECRET,
    CountingStream,
    FakeServer,
    idle_then,
    job_json,
    streamed,
)

from p2pc import (
    AsyncClient,
    ChecksumMismatchError,
    Client,
    ConfigurationError,
    InvalidResponseError,
    P2PCConnectionError,
    ServerError,
)

Factory = Callable[..., Client]
AFactory = Callable[..., AsyncClient]


def _line(seq: int) -> bytes:
    record = {"seq": seq, "stream": "stdout", "ts": "2026-11-05T10:00:00Z", "data": f"l{seq}\n"}
    return json.dumps(record).encode() + b"\n"


# --- download_output: the digest is mandatory ----------------------------------------------
@pytest.mark.parametrize(
    "entry",
    [
        {"path": "a", "size": 1, "sha256": ""},
        {"path": "a", "size": 1, "sha256": "zz" * 32},
        {"path": "a", "size": 1, "sha256": "ab" * 31},
        {"path": "a", "size": 1, "sha256": "ab" * 33},
        {"path": "a", "size": 1, "sha256": "ab" * 32 + "\n"},
    ],
)
def test_download_refuses_a_listing_without_a_valid_sha256(
    client: Client, server: FakeServer, tmp_path: Path, entry: dict[str, object]
) -> None:
    server.on("GET", "/v1/jobs/j/outputs", [entry])
    server.on("GET", "/v1/jobs/j/outputs/a", httpx.Response(200, content=b"x"))
    with pytest.raises(InvalidResponseError, match="sha256"):
        client.jobs.download_output("j", "a", tmp_path)
    assert server.count("GET", "/v1/jobs/j/outputs/a") == 0  # never even fetched
    assert list(tmp_path.iterdir()) == []


def test_download_accepts_prefixed_and_uppercase_digests(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    sha = "sha256:" + hashlib.sha256(b"x").hexdigest().upper()
    server.on("GET", "/v1/jobs/j/outputs", [{"path": "a", "size": 1, "sha256": sha}])
    server.on("GET", "/v1/jobs/j/outputs/a", httpx.Response(200, content=b"x"))
    assert client.jobs.download_output("j", "a", tmp_path).read_bytes() == b"x"


def test_download_size_is_a_hard_limit_while_writing(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    body = CountingStream(b"x" * 65_536, 1000)
    server.on("GET", "/v1/jobs/j/outputs", [{"path": "a", "size": 10, "sha256": "00" * 32}])
    server.on("GET", "/v1/jobs/j/outputs/a", httpx.Response(200, stream=body))
    with pytest.raises(ChecksumMismatchError, match="size"):
        client.jobs.download_output("j", "a", tmp_path)
    assert body.pulled == 1  # stopped at the first oversized chunk, not after 64 MB
    assert list(tmp_path.iterdir()) == []


def test_failed_download_removes_the_directories_it_created(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    (tmp_path / "keep").mkdir()
    server.on(
        "GET", "/v1/jobs/j/outputs", [{"path": "keep/new/deep/f", "size": 1, "sha256": "00" * 32}]
    )
    server.on("GET", "/v1/jobs/j/outputs/keep/new/deep/f", httpx.Response(200, content=b"x"))
    with pytest.raises(ChecksumMismatchError):
        client.jobs.download_output("j", "keep/new/deep/f", tmp_path)
    assert [p.name for p in tmp_path.iterdir()] == ["keep"]  # pre-existing dir is untouched
    assert list((tmp_path / "keep").iterdir()) == []


@pytest.mark.asyncio
async def test_async_download_refuses_missing_sha256(
    make_aclient: AFactory, server: FakeServer, tmp_path: Path
) -> None:
    aclient = make_aclient()
    server.on("GET", "/v1/jobs/j/outputs", [{"path": "a", "size": 1}])
    with pytest.raises(InvalidResponseError, match="OutputFile"):  # the model requires it
        await aclient.jobs.download_output("j", "a", tmp_path)
    assert server.count("GET", "/v1/jobs/j/outputs/a") == 0


@pytest.mark.asyncio
async def test_async_failed_download_removes_created_directories(
    make_aclient: AFactory, server: FakeServer, tmp_path: Path
) -> None:
    aclient = make_aclient()
    server.on("GET", "/v1/jobs/j/outputs", [{"path": "d/e/f", "size": 1, "sha256": "00" * 32}])
    server.on("GET", "/v1/jobs/j/outputs/d/e/f", httpx.Response(200, content=b"x"))
    with pytest.raises(ChecksumMismatchError):
        await aclient.jobs.download_output("j", "d/e/f", tmp_path)
    assert list(tmp_path.iterdir()) == []


# --- error bodies: redaction before truncation, and a read cap ----------------------------
def test_key_straddling_byte_200_of_a_non_json_body_is_fully_redacted(
    client: Client, server: FakeServer
) -> None:
    body = b"x" * 188 + KEY.encode() + b" and some trailing text"
    server.on(
        "GET",
        "/v1/jobs/j",
        httpx.Response(502, headers={"content-type": "text/html"}, content=body),
    )
    with pytest.raises(ServerError) as err:
        client.jobs.get("j")
    text = str(err.value) + repr(err.value) + (err.value.detail or "")
    assert "p2pc_sk_abcd" not in text  # the old code kept the first 12 characters of the key
    assert KEY_SECRET[:8] not in text
    assert "p2pc_sk_abc…" in text


def test_other_keys_in_error_bodies_are_redacted_too(client: Client, server: FakeServer) -> None:
    other = "p2pc_sk_zzzzzzzzzzzz_ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKL"
    server.on(
        "GET",
        "/v1/jobs/j",
        httpx.Response(
            500,
            headers={"content-type": "application/problem+json"},
            json={"title": f"t {other}", "detail": f"d {other}", "code": "c"},
        ),
    )
    with pytest.raises(ServerError) as err:
        client.jobs.get("j")
    text = str(err.value) + repr(err.value) + (err.value.detail or "") + (err.value.title or "")
    assert "ABCDEFGHIJKL" not in text
    assert "p2pc_sk_zzz…" in text


def test_error_body_is_read_at_most_64_kib(client: Client, server: FakeServer) -> None:
    body = CountingStream(b"e" * 16_384, 10_000)
    server.on("GET", "/v1/jobs/j", httpx.Response(500, stream=body))
    with pytest.raises(ServerError):
        client.jobs.get("j")
    assert body.pulled <= 5  # 64 KiB = 4 chunks, not 160 MB


@pytest.mark.asyncio
async def test_async_error_body_is_read_at_most_64_kib(
    make_aclient: AFactory, server: FakeServer
) -> None:
    aclient = make_aclient()
    body = CountingStream(b"e" * 16_384, 10_000)
    server.on("GET", "/v1/jobs/j", httpx.Response(500, stream=body))
    with pytest.raises(ServerError):
        await aclient.jobs.get("j")
    assert body.pulled <= 5


def test_oversized_success_body_is_refused(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/jobs/j", httpx.Response(200, stream=CountingStream(b"x" * 1_048_576, 40)))
    with pytest.raises(InvalidResponseError, match="size"):
        client.jobs.get("j")


# --- followed logs: the idle timeout (reopening and stopping are in test_logs_follow.py) ----
def test_follow_uses_the_idle_timeout_for_reads_and_the_normal_one_otherwise(
    make_client: Factory, server: FakeServer
) -> None:
    client = make_client(follow_idle_timeout=7.5, timeout=12.0)
    # a fresh response per call: a streamed body can only be consumed once
    server.on("GET", "/v1/jobs/j/logs", lambda _req: streamed([]))
    server.on("GET", "/v1/jobs/j", job_json("j", "succeeded", exit_code=0))
    list(client.jobs.logs("j", follow=True))
    list(client.jobs.logs("j", follow=False))
    logs = [r for r in server.requests if r.url.path.endswith("/logs")]
    assert logs[0].extensions["timeout"]["read"] == 7.5
    assert logs[-1].extensions["timeout"]["read"] == 12.0


def test_non_follow_read_timeout_is_a_connection_error(client: Client, server: FakeServer) -> None:
    server.on("GET", "/v1/jobs/j/logs", idle_then([_line(1)]))
    it = client.jobs.logs("j")
    assert next(it).seq == 1
    with pytest.raises(P2PCConnectionError):
        next(it)


def test_follow_idle_timeout_must_be_positive() -> None:
    with pytest.raises(ConfigurationError, match="follow_idle_timeout"):
        Client(api_key=KEY, follow_idle_timeout=0)
    with pytest.raises(ConfigurationError, match="follow_idle_timeout"):
        AsyncClient(api_key=KEY, follow_idle_timeout=-1)


@pytest.mark.asyncio
async def test_async_logs_can_be_closed_early_with_aclosing(
    make_aclient: AFactory, server: FakeServer
) -> None:
    aclient = make_aclient()
    server.on("GET", "/v1/jobs/j/logs", streamed([_line(1), _line(2), _line(3)]))
    async with aclosing(aclient.jobs.logs("j")) as logs:
        first = await anext(logs)
    assert first.seq == 1
