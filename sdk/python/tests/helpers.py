# SPDX-License-Identifier: Apache-2.0
"""Test doubles: a recording fake server over ``httpx.MockTransport`` and a fake clock."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable, Iterable, Iterator
from typing import Any

import httpx

API_URL = "http://p2pc.example.invalid:7477"
KEY_ID = "abcdefghijkl"
KEY_SECRET = "QRSTUVWXYZ234567QRSTUVWXYZ234567QRSTUVWXYZ23"  # gitleaks:allow
KEY = f"p2pc_sk_{KEY_ID}_{KEY_SECRET}"  # synthetic: not a real credential

Handler = Callable[[httpx.Request], httpx.Response]


def json_response(data: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=data)


def problem(
    status: int, code: str, detail: str = "went wrong", title: str = "Problem"
) -> httpx.Response:
    return httpx.Response(
        status,
        headers={"content-type": "application/problem+json"},
        json={
            "type": f"https://example.invalid/problems/{code}",
            "title": title,
            "status": status,
            "detail": detail,
            "code": code,
        },
    )


def job_json(job_id: str = "job_1", status: str = "queued", **extra: Any) -> dict[str, Any]:
    """A job as ``GET /v1/jobs/{id}`` returns it: nested redacted ``spec``, milli-units."""
    return {
        "id": job_id,
        "project_id": "prj_1",
        "status": status,
        "attempt": 1,
        "estimated_units": 1000,
        "created_at": "2026-11-05T10:00:00Z",
        "spec": {
            "image": "docker.io/library/python:3.12-slim",
            "command": ["python", "-c", "print(6*7)"],
            "resources": {"cpu": 1.0, "memory_mb": 1024, "gpu": 0, "disk_mb": 10240},
        },
        **extra,
    }


def node_json(node_id: str = "node_1", **extra: Any) -> dict[str, Any]:
    """A node as ``GET /v1/nodes/{id}`` returns it (192.0.2.0/24 and example.invalid only)."""
    return {
        "id": node_id,
        "name": "workstation",
        "hostname": "workstation.example.invalid",
        "state": "online",
        "draining": False,
        "created_at": "2026-11-05T09:00:00Z",
        "last_seen": "2026-11-05T10:00:00Z",
        "labels": {"zone": "lab"},
        "free": {"cpu": 6.0, "gpu": 1, "memory_mb": 24576, "disk_mb": 30720},
        "inventory": {
            "agent_version": "0.1.0",
            "arch": "x86_64",
            "os": "Ubuntu 24.04",
            "platform": "linux",
            "hostname": "workstation.example.invalid",
            "memory_mb": 32768,
            "cpu": {"cores": 16, "model": "Example CPU"},
            "offered": {"cpu": 8.0, "gpu": 1, "memory_mb": 24576, "disk_mb": 51200},
            "disk_total_mb": 512000,
            "gpu_status": {"status": "ok"},
            "gpus": [
                {
                    "uuid": "GPU-00000000-0000-0000-0000-000000000000",
                    "index": 0,
                    "name": "Example GPU",
                    "driver_version": "555.0",
                    "vram_mb": 24564,
                }
            ],
            "sandbox": [
                {
                    "class": "container",
                    "driver": "podman",
                    "runtimes": ["crun"],
                    "ready": True,
                    "problems": [],
                }
            ],
        },
        **extra,
    }


def join_token_info_json(row_id: str = "jtk_1", **extra: Any) -> dict[str, Any]:
    """A join token as ``GET /v1/nodes/join-tokens`` lists it: never the token itself."""
    return {
        "id": row_id,
        "created_by_key_id": "abcdefghijkl",
        "created_at": "2026-11-05T10:00:00Z",
        "expires_at": "2026-11-05T10:15:00Z",
        **extra,
    }


def key_json(key_id: str = "abcdefghijkl", **extra: Any) -> dict[str, Any]:
    """An API key as ``GET /v1/keys`` lists it: metadata only."""
    return {
        "id": key_id,
        "project_id": "prj_1",
        "scopes": ["jobs:read"],
        "created_at": "2026-11-05T10:00:00Z",
        **extra,
    }


class ChunkStream(httpx.SyncByteStream, httpx.AsyncByteStream):
    """A response body delivered in exactly the given chunks (sync and async)."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._chunks = list(chunks)

    def __iter__(self) -> Iterator[bytes]:
        yield from self._chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


class FailingStream(httpx.SyncByteStream, httpx.AsyncByteStream):
    """Delivers the chunks, then raises ``exc`` (for example an idle ``ReadTimeout``)."""

    def __init__(self, chunks: Iterable[bytes], exc: Exception) -> None:
        self._chunks = list(chunks)
        self._exc = exc

    def __iter__(self) -> Iterator[bytes]:
        yield from self._chunks
        raise self._exc

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk
        raise self._exc


class CountingStream(httpx.SyncByteStream, httpx.AsyncByteStream):
    """Many equal chunks; records how many were actually pulled by the client."""

    def __init__(self, chunk: bytes, count: int) -> None:
        self._chunk = chunk
        self._count = count
        self.pulled = 0

    def __iter__(self) -> Iterator[bytes]:
        for _ in range(self._count):
            self.pulled += 1
            yield self._chunk

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for _ in range(self._count):
            self.pulled += 1
            yield self._chunk


class WatchedStream(httpx.SyncByteStream, httpx.AsyncByteStream):
    """Delivers the chunks, and records whether the client released the stream (``closed``)."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._chunks = list(chunks)
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        yield from self._chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk

    def close(self) -> None:
        self.closed = True

    async def aclose(self) -> None:
        self.closed = True


def idle_then(chunks: Iterable[bytes]) -> httpx.Response:
    """A followed log stream that goes silent: the read timeout fires after ``chunks``."""
    return httpx.Response(
        200,
        headers={"content-type": "application/x-ndjson"},
        stream=FailingStream(chunks, httpx.ReadTimeout("idle")),
    )


def streamed(chunks: Iterable[bytes], status: int = 200) -> httpx.Response:
    return httpx.Response(
        status, headers={"content-type": "application/x-ndjson"}, stream=ChunkStream(chunks)
    )


class FakeServer:
    """Routes ``(method, path)`` to handlers and records every request."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self._routes: dict[tuple[str, str], list[Handler]] = {}

    def on(self, method: str, path: str, *handlers: Handler | httpx.Response | Any) -> FakeServer:
        """Register one handler per expected call (the last one repeats)."""
        wrapped: list[Handler] = []
        for h in handlers:
            if isinstance(h, httpx.Response):
                wrapped.append(lambda _req, resp=h: resp)
            elif callable(h):
                wrapped.append(h)
            else:
                wrapped.append(lambda _req, data=h: json_response(data))
        self._routes[(method, path)] = wrapped
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        handlers = self._routes.get((request.method, request.url.path))
        if not handlers:
            return problem(599, "unrouted", f"no route for {request.method} {request.url.path}")
        index = min(self.count(request.method, request.url.path) - 1, len(handlers) - 1)
        return handlers[index](request)

    def count(self, method: str, path: str) -> int:
        return sum(1 for r in self.requests if r.method == method and r.url.path == path)

    def body(self, index: int = -1) -> Any:
        return json.loads(self.requests[index].content)

    def query(self, index: int = -1) -> dict[str, str]:
        return dict(self.requests[index].url.params)


class FakeClock:
    """Deterministic ``sleep`` and ``monotonic``: sleeping just advances time."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    async def asleep(self, seconds: float) -> None:
        self.sleep(seconds)


def broken_then(chunks: Iterable[bytes]) -> httpx.Response:
    """A followed log stream the server breaks mid-body (no clean end) after ``chunks``."""
    return httpx.Response(
        200,
        headers={"content-type": "application/x-ndjson"},
        stream=FailingStream(
            chunks, httpx.RemoteProtocolError("peer closed connection without a complete body")
        ),
    )


class SlowBreakStream(httpx.SyncByteStream, httpx.AsyncByteStream):
    """Delivers the chunks, lets ``seconds`` pass on the fake clock, then breaks the body."""

    def __init__(self, clock: FakeClock, seconds: float, chunks: Iterable[bytes]) -> None:
        self._clock = clock
        self._seconds = seconds
        self._chunks = list(chunks)

    def _break(self) -> None:
        self._clock.now += self._seconds  # the time the stream stayed open, not a sleep
        raise httpx.RemoteProtocolError("peer closed connection without a complete body")

    def __iter__(self) -> Iterator[bytes]:
        yield from self._chunks
        self._break()

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk
        self._break()


def cut_after(clock: FakeClock, seconds: float, chunks: Iterable[bytes] = ()) -> httpx.Response:
    """A followed stream the server cuts after ``seconds`` of being open (its idle cut)."""
    return httpx.Response(
        200,
        headers={"content-type": "application/x-ndjson"},
        stream=SlowBreakStream(clock, seconds, chunks),
    )
