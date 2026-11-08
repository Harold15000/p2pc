# SPDX-License-Identifier: Apache-2.0
"""Output downloads: size and digest are mandatory, the size is capped, ``attempt`` is
passed on, and an async download that is cancelled leaves nothing behind (T13 review P3-1,
P3-2 and P3-5)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from helpers import CountingStream, FakeServer, job_json, problem

from p2pc import (
    AsyncClient,
    AsyncJob,
    ChecksumMismatchError,
    Client,
    InvalidResponseError,
    Job,
    NotFoundError,
)
from p2pc import _common as c

GIB = 1024**3
DATA = b"hello outputs"
SHA = hashlib.sha256(DATA).hexdigest()
LISTING = "/v1/jobs/j/outputs"


def entry(path: str = "a", **extra: Any) -> dict[str, Any]:
    return {"path": path, "size": len(DATA), "sha256": SHA, **extra}


# --- P3-2: the listing must announce the size, and it is capped ------------------------------
@pytest.mark.parametrize(
    ("bad", "message"),
    [
        # The server always announces the size: a listing without a valid one does not parse.
        ({"size": None}, "OutputFile"),
        ({"size": -1}, "OutputFile"),
        ({"size": "lots"}, "OutputFile"),
    ],
)
def test_download_refuses_a_listing_without_a_valid_size(
    client: Client, server: FakeServer, tmp_path: Path, bad: dict[str, Any], message: str
) -> None:
    server.on("GET", LISTING, [{**entry(), **bad}])
    server.on("GET", f"{LISTING}/a", httpx.Response(200, content=DATA))
    with pytest.raises(InvalidResponseError, match=message):
        client.jobs.download_output("j", "a", tmp_path)
    assert server.count("GET", f"{LISTING}/a") == 0  # never fetched
    assert list(tmp_path.iterdir()) == []


def test_download_refuses_a_listing_that_omits_the_size_key(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    server.on("GET", LISTING, [{"path": "a", "sha256": SHA}])
    with pytest.raises(InvalidResponseError, match="OutputFile"):
        client.jobs.download_output("j", "a", tmp_path)


def test_a_file_over_1_gib_is_refused_before_any_download(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    server.on("GET", LISTING, [entry(size=GIB + 1)])
    with pytest.raises(InvalidResponseError, match="1 GiB"):
        client.jobs.download_output("j", "a", tmp_path)
    assert server.count("GET", f"{LISTING}/a") == 0
    assert list(tmp_path.iterdir()) == []


def test_the_default_cap_is_exactly_1_gib() -> None:
    # No explicit cap anywhere: this is the cap a download has when there is no job to ask.
    assert c.expected_size(c.OutputFile(path="a", size=GIB, sha256=SHA)) == GIB
    with pytest.raises(InvalidResponseError, match="1 GiB"):
        c.expected_size(c.OutputFile(path="a", size=GIB + 1, sha256=SHA))


def test_a_file_of_exactly_1_gib_is_not_refused_by_the_default_cap(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    # 1 GiB announced, a few bytes delivered: the cap check passed (no "1 GiB" refusal) and the
    # download failed later, on the size mismatch.
    server.on("GET", LISTING, [entry(size=GIB)])
    server.on("GET", f"{LISTING}/a", httpx.Response(200, content=DATA))
    with pytest.raises(ChecksumMismatchError, match="size"):
        client.jobs.download_output("j", "a", tmp_path)
    assert server.count("GET", f"{LISTING}/a") == 1


def test_max_bytes_lowers_the_cap(client: Client, server: FakeServer, tmp_path: Path) -> None:
    server.on("GET", LISTING, [entry()])
    server.on("GET", f"{LISTING}/a", httpx.Response(200, content=DATA))
    with pytest.raises(InvalidResponseError, match="limit"):
        client.jobs.download_output("j", "a", tmp_path, max_bytes=len(DATA) - 1)
    assert server.count("GET", f"{LISTING}/a") == 0
    assert client.jobs.download_output("j", "a", tmp_path, max_bytes=len(DATA)).read_bytes() == DATA


def test_max_bytes_can_raise_the_default_cap_up_to_the_servers_maximum(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    # 2 GiB announced, a few bytes delivered: the cap check passed (no InvalidResponseError)
    # and the download failed later, on the size mismatch.
    server.on("GET", LISTING, [entry(size=2 * GIB)])
    server.on("GET", f"{LISTING}/a", httpx.Response(200, content=DATA))
    with pytest.raises(ChecksumMismatchError, match="size"):
        client.jobs.download_output("j", "a", tmp_path, max_bytes=2 * GIB)
    assert server.count("GET", f"{LISTING}/a") == 1


def test_max_bytes_can_never_exceed_the_servers_maximum_of_10240_mib(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    ten_gib = 10 * GIB  # outputs.max_mb is at most 10 240
    assert c.check_max_bytes(100 * GIB) == ten_gib
    server.on("GET", LISTING, [entry(size=ten_gib + 1)])
    with pytest.raises(InvalidResponseError, match="limit"):
        client.jobs.download_output("j", "a", tmp_path, max_bytes=100 * GIB)
    assert server.count("GET", f"{LISTING}/a") == 0


def test_the_default_cap_without_max_bytes_is_still_1_gib() -> None:
    assert c.check_max_bytes(None) == GIB


@pytest.mark.parametrize("bad", [-1, 1.5, True])
def test_max_bytes_must_be_a_non_negative_integer(client: Client, tmp_path: Path, bad: Any) -> None:
    with pytest.raises(ValueError, match="max_bytes"):
        client.jobs.download_output("j", "a", tmp_path, max_bytes=bad)


def test_the_job_passes_its_outputs_max_mb_as_the_cap(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    spec = {**job_json()["spec"], "outputs": {"max_mb": 1}}
    job = Job.model_validate(job_json("j", spec=spec))._bind(client)
    server.on("GET", LISTING, [entry(size=1024 * 1024 + 1)])
    with pytest.raises(InvalidResponseError, match="limit"):
        job.download_output("a", tmp_path)
    server.on("GET", LISTING, [entry()])
    server.on("GET", f"{LISTING}/a", httpx.Response(200, content=DATA))
    assert job.download_output("a", tmp_path).read_bytes() == DATA


@pytest.mark.parametrize("max_mb", [2048, 10_240])
def test_the_jobs_own_outputs_limit_is_the_cap_even_above_1_gib(
    client: Client, server: FakeServer, tmp_path: Path, max_mb: int
) -> None:
    spec = {**job_json()["spec"], "outputs": {"max_mb": max_mb}}
    job = Job.model_validate(job_json("j", spec=spec))._bind(client)
    cap = max_mb * 1024 * 1024
    server.on("GET", LISTING, [entry(size=cap + 1)])
    with pytest.raises(InvalidResponseError, match=f"limit of {cap} bytes"):
        job.download_output("a", tmp_path)
    assert server.count("GET", f"{LISTING}/a") == 0
    # Exactly at the job's limit (over 1 GiB) is accepted by the cap check: only the short body
    # then fails, on the size mismatch.
    server.on("GET", LISTING, [entry(size=cap)])
    server.on("GET", f"{LISTING}/a", httpx.Response(200, content=DATA))
    with pytest.raises(ChecksumMismatchError, match="size"):
        job.download_output("a", tmp_path)


def test_a_jobs_outputs_limit_above_the_servers_maximum_is_capped_at_it(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    spec = {**job_json()["spec"], "outputs": {"max_mb": 50_000}}  # a view is lenient
    job = Job.model_validate(job_json("j", spec=spec))._bind(client)
    server.on("GET", LISTING, [entry(size=10 * GIB + 1)])
    with pytest.raises(InvalidResponseError, match="limit"):
        job.download_output("a", tmp_path)


def test_a_job_without_an_outputs_limit_uses_the_1_gib_cap(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    job = Job.model_validate(job_json("j"))._bind(client)
    server.on("GET", LISTING, [entry(size=GIB + 1)])
    with pytest.raises(InvalidResponseError, match="1 GiB"):
        job.download_output("a", tmp_path)


def test_more_bytes_than_announced_stops_at_the_first_oversized_chunk(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    body = CountingStream(b"x" * 65_536, 100_000)  # ~6 GB if it were all read
    server.on("GET", LISTING, [entry(size=10)])
    server.on("GET", f"{LISTING}/a", httpx.Response(200, stream=body))
    with pytest.raises(ChecksumMismatchError, match="size"):
        client.jobs.download_output("j", "a", tmp_path)
    assert body.pulled == 1
    assert list(tmp_path.iterdir()) == []


def test_fewer_bytes_than_announced_is_a_size_mismatch(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    server.on("GET", LISTING, [entry(size=len(DATA) + 5)])
    server.on("GET", f"{LISTING}/a", httpx.Response(200, content=DATA))
    with pytest.raises(ChecksumMismatchError, match="size"):
        client.jobs.download_output("j", "a", tmp_path)
    assert list(tmp_path.iterdir()) == []


# --- P3-5: logs and outputs are per attempt; expired entries --------------------------------
def test_outputs_listing_takes_an_attempt(client: Client, server: FakeServer) -> None:
    server.on("GET", LISTING, [entry()])
    client.jobs.outputs("j")
    assert "attempt" not in server.query()  # the latest by default
    client.jobs.outputs("j", attempt=2)
    assert server.query()["attempt"] == "2"


def test_download_passes_the_attempt_to_the_listing_and_the_file(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    server.on("GET", LISTING, [entry()])
    server.on("GET", f"{LISTING}/a", httpx.Response(200, content=DATA))
    client.jobs.download_output("j", "a", tmp_path, attempt=3)
    assert [r.url.params.get("attempt") for r in server.requests] == ["3", "3"]


@pytest.mark.parametrize("bad", [0, -1, 1.5, "1", True])
def test_attempt_must_be_a_positive_integer(client: Client, tmp_path: Path, bad: Any) -> None:
    with pytest.raises(ValueError, match="attempt"):
        client.jobs.outputs("j", attempt=bad)
    with pytest.raises(ValueError, match="attempt"):
        client.jobs.logs("j", attempt=bad)
    with pytest.raises(ValueError, match="attempt"):
        client.jobs.download_output("j", "a", tmp_path, attempt=bad)


def test_an_expired_output_is_reported_as_gone_not_as_a_bad_listing(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    server.on("GET", LISTING, [entry(expired=True)])
    with pytest.raises(NotFoundError, match="expired") as err:
        client.jobs.download_output("j", "a", tmp_path)
    assert err.value.code == "output_expired"
    assert server.count("GET", f"{LISTING}/a") == 0
    assert client.jobs.outputs("j")[0].expired is True
    server.on("GET", LISTING, [entry()])
    assert client.jobs.outputs("j")[0].expired is False


def test_logs_take_an_attempt_and_keep_it_on_every_reconnect(
    client: Client, server: FakeServer
) -> None:
    from helpers import idle_then, job_json, streamed

    def line(seq: int) -> bytes:
        record = {"seq": seq, "stream": "stdout", "ts": "2026-11-05T10:00:00Z", "data": "x"}
        return json.dumps(record).encode() + b"\n"

    server.on(
        "GET",
        "/v1/jobs/j/logs",
        lambda _req: idle_then([line(4)]),
        lambda _req: streamed([line(5)]),
        lambda _req: streamed([]),
    )
    server.on(
        "GET",
        "/v1/jobs/j",
        job_json("j", "running", attempt=2),
        job_json("j", "running", attempt=2),
        job_json("j", "succeeded", attempt=2, exit_code=0),
    )
    seqs = [entry.seq for entry in client.jobs.logs("j", follow=True, attempt=2)]
    assert seqs == [4, 5]
    reads = [r.url.params for r in server.requests if r.url.path.endswith("/logs")]
    # since_seq is inclusive (spec §7): a client resumes at last_seq + 1, here 4 + 1, then 5 + 1.
    assert [(p["attempt"], p["since_seq"]) for p in reads] == [("2", "0"), ("2", "5"), ("2", "6")]


def test_logs_without_an_attempt_do_not_send_one(client: Client, server: FakeServer) -> None:
    from helpers import streamed

    server.on("GET", "/v1/jobs/j/logs", streamed([]))
    list(client.jobs.logs("j"))
    assert "attempt" not in server.query()


@pytest.mark.asyncio
async def test_async_attempt_for_logs_and_outputs(aclient: AsyncClient, server: FakeServer) -> None:
    from helpers import streamed

    server.on("GET", LISTING, [entry()])
    await aclient.jobs.outputs("j", attempt=2)
    assert server.query()["attempt"] == "2"
    server.on("GET", "/v1/jobs/j/logs", streamed([]))
    assert [line async for line in aclient.jobs.logs("j", attempt=3)] == []
    assert server.query()["attempt"] == "3"
    with pytest.raises(ValueError, match="attempt"):
        aclient.jobs.logs("j", attempt=0)


@pytest.mark.asyncio
async def test_async_job_download_follows_its_outputs_limit_above_1_gib(
    aclient: AsyncClient, server: FakeServer, tmp_path: Path
) -> None:
    spec = {**job_json()["spec"], "outputs": {"max_mb": 2048}}
    job = AsyncJob.model_validate(job_json("j", spec=spec))._bind(aclient)
    server.on("GET", LISTING, [entry(size=2 * GIB)])
    server.on("GET", f"{LISTING}/a", httpx.Response(200, content=DATA))
    with pytest.raises(ChecksumMismatchError, match="size"):  # past the cap check
        await job.download_output("a", tmp_path)
    server.on("GET", LISTING, [entry(size=2 * GIB + 1)])
    with pytest.raises(InvalidResponseError, match="limit"):
        await job.download_output("a", tmp_path)


@pytest.mark.asyncio
async def test_async_job_download_uses_its_outputs_limit(
    aclient: AsyncClient, server: FakeServer, tmp_path: Path
) -> None:
    spec = {**job_json()["spec"], "outputs": {"max_mb": 1}}
    job = AsyncJob.model_validate(job_json("j", spec=spec))._bind(aclient)
    server.on("GET", LISTING, [entry(size=1024 * 1024 + 1)])
    with pytest.raises(InvalidResponseError, match="limit"):
        await job.download_output("a", tmp_path)
    server.on("GET", LISTING, [entry()])
    server.on("GET", f"{LISTING}/a", httpx.Response(200, content=DATA))
    assert (await job.download_output("a", tmp_path)).read_bytes() == DATA


# --- P3-1: cancelling an async download ------------------------------------------------------
class Gate:
    """Holds a worker-thread step until the test releases it: no sleeps, no races.

    ``entered`` is set (on the loop) when the step starts; the step then waits for ``release``.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.entered = asyncio.Event()
        self.release = threading.Event()

    def wrap(self, original: Callable[..., Any], only_first: bool = False) -> Callable[..., Any]:
        calls = 0

        def wrapper(writer: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            if not only_first or calls == 1:
                self.loop.call_soon_threadsafe(self.entered.set)
                assert self.release.wait(timeout=30), "the test never released the step"
            return original(writer, *args, **kwargs)

        return wrapper


class BlockedBody(httpx.AsyncByteStream):
    """A response body that has not delivered anything until the test says so."""

    def __init__(self, gate: asyncio.Event) -> None:
        self._gate = gate

    async def __aiter__(self) -> AsyncIterator[bytes]:
        await self._gate.wait()
        yield DATA


@pytest.fixture
def served(server: FakeServer) -> FakeServer:
    server.on("GET", LISTING, [entry("d/e/out.bin")])
    server.on("GET", f"{LISTING}/d/e/out.bin", httpx.Response(200, content=DATA))
    return server


def tree(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


async def cancel_at(
    aclient: AsyncClient, tmp_path: Path, gate: Gate
) -> asyncio.CancelledError | None:
    task = asyncio.ensure_future(aclient.jobs.download_output("j", "d/e/out.bin", tmp_path))
    await gate.entered.wait()  # the worker thread is inside the step
    task.cancel()  # for example asyncio.timeout expiring
    gate.release.set()  # let the in-flight thread finish: abort must not race it
    with pytest.raises(asyncio.CancelledError):
        await task
    return None


@pytest.mark.parametrize("step", ["open", "write", "commit"])
@pytest.mark.asyncio
async def test_cancelling_during_each_step_leaves_no_part_file_and_no_directories(
    step: str,
    aclient: AsyncClient,
    served: FakeServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = Gate(asyncio.get_running_loop())
    monkeypatch.setattr(c.DownloadWriter, step, gate.wrap(getattr(c.DownloadWriter, step)))
    await cancel_at(aclient, tmp_path, gate)
    assert tree(tmp_path) == []  # no .p2pc-*.part, no d/ or d/e/, no out.bin


@pytest.mark.asyncio
async def test_cancelling_after_the_commit_removes_the_file_it_created(
    aclient: AsyncClient, served: FakeServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The cancel lands while the thread renames the file: the download finished, but the caller
    # was told it was cancelled, so nothing new may be left on disk.
    gate = Gate(asyncio.get_running_loop())
    monkeypatch.setattr(c.DownloadWriter, "commit", gate.wrap(c.DownloadWriter.commit))
    await cancel_at(aclient, tmp_path, gate)
    assert not (tmp_path / "d").exists()


@pytest.mark.asyncio
async def test_cancelling_during_commit_keeps_a_pre_existing_target_and_directories(
    aclient: AsyncClient, served: FakeServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "d" / "e").mkdir(parents=True)
    (tmp_path / "d" / "e" / "out.bin").write_bytes(b"old")
    gate = Gate(asyncio.get_running_loop())
    monkeypatch.setattr(c.DownloadWriter, "commit", gate.wrap(c.DownloadWriter.commit))
    await cancel_at(aclient, tmp_path, gate)
    # Pre-existing paths are not ours to delete; no temporary file is left next to it.
    assert tree(tmp_path) == ["d", "d/e", "d/e/out.bin"]


@pytest.mark.asyncio
async def test_cancelling_the_second_chunk_leaves_nothing(
    aclient: AsyncClient, server: FakeServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.on("GET", LISTING, [entry("d/e/out.bin", size=2 * len(DATA))])
    server.on(
        "GET",
        f"{LISTING}/d/e/out.bin",
        httpx.Response(200, stream=_Chunks([DATA, DATA])),
    )
    gate = Gate(asyncio.get_running_loop())
    original = c.DownloadWriter.write
    calls = 0

    def second_only(writer: Any, chunk: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            gate.loop.call_soon_threadsafe(gate.entered.set)
            assert gate.release.wait(timeout=30)
        original(writer, chunk)

    monkeypatch.setattr(c.DownloadWriter, "write", second_only)
    await cancel_at(aclient, tmp_path, gate)
    assert tree(tmp_path) == []


class _Chunks(httpx.AsyncByteStream, httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk

    def __iter__(self) -> Iterator[bytes]:
        yield from self._chunks


@pytest.mark.asyncio
async def test_cancelling_while_waiting_for_the_first_byte_leaves_nothing(
    aclient: AsyncClient, server: FakeServer, tmp_path: Path
) -> None:
    loop = asyncio.get_running_loop()
    requested = asyncio.Event()

    def handler(_req: httpx.Request) -> httpx.Response:
        loop.call_soon_threadsafe(requested.set)
        return httpx.Response(200, stream=BlockedBody(asyncio.Event()))  # never delivers

    server.on("GET", LISTING, [entry("d/e/out.bin")])
    server.on("GET", f"{LISTING}/d/e/out.bin", handler)
    task = asyncio.ensure_future(aclient.jobs.download_output("j", "d/e/out.bin", tmp_path))
    await requested.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert tree(tmp_path) == []


@pytest.mark.asyncio
async def test_asyncio_timeout_cancels_cleanly(
    aclient: AsyncClient, server: FakeServer, tmp_path: Path
) -> None:
    loop = asyncio.get_running_loop()
    requested = asyncio.Event()

    def handler(_req: httpx.Request) -> httpx.Response:
        loop.call_soon_threadsafe(requested.set)
        return httpx.Response(200, stream=BlockedBody(asyncio.Event()))  # never delivers

    server.on("GET", LISTING, [entry("d/e/out.bin")])
    server.on("GET", f"{LISTING}/d/e/out.bin", handler)

    async def download_with_a_deadline() -> None:
        async with asyncio.timeout(None) as deadline:  # armed by hand: no wall-clock wait
            task = asyncio.ensure_future(aclient.jobs.download_output("j", "d/e/out.bin", tmp_path))
            await requested.wait()  # the writer is open and the body is pending
            deadline.reschedule(loop.time())
            await task

    with pytest.raises(TimeoutError):
        await download_with_a_deadline()
    assert tree(tmp_path) == []


@pytest.mark.asyncio
async def test_a_second_cancel_while_draining_still_cleans_up(
    aclient: AsyncClient, served: FakeServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = Gate(asyncio.get_running_loop())
    monkeypatch.setattr(c.DownloadWriter, "write", gate.wrap(c.DownloadWriter.write))
    task = asyncio.ensure_future(aclient.jobs.download_output("j", "d/e/out.bin", tmp_path))
    await gate.entered.wait()
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()  # impatient caller
    gate.release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert tree(tmp_path) == []


@pytest.mark.asyncio
async def test_a_normal_async_download_is_unchanged(
    aclient: AsyncClient, served: FakeServer, tmp_path: Path
) -> None:
    target = await aclient.jobs.download_output("j", "d/e/out.bin", tmp_path)
    assert target.read_bytes() == DATA
    assert tree(tmp_path) == ["d", "d/e", "d/e/out.bin"]  # and no .part file


@pytest.fixture
def aclient(make_aclient: Callable[..., AsyncClient]) -> AsyncClient:
    return make_aclient()


# --- X-P2PC-SHA256 and 410 Gone (T13d) --------------------------------------------------------
def body_with(data: bytes = DATA, digest: str | None = SHA, status: int = 200) -> httpx.Response:
    headers = {} if digest is None else {c.DIGEST_HEADER: digest}
    return httpx.Response(status, content=data, headers=headers)


def test_the_digest_header_is_checked_against_the_listing(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    server.on("GET", LISTING, [entry()])
    server.on("GET", f"{LISTING}/a", body_with(digest=SHA.upper()))  # case is not significant
    assert client.jobs.download_output("j", "a", tmp_path).read_bytes() == DATA


def test_a_digest_header_that_disagrees_with_the_listing_is_refused_before_any_byte(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    other = hashlib.sha256(b"other").hexdigest()
    body = CountingStream(b"x" * 1024, 10)
    server.on("GET", LISTING, [entry()])
    server.on(
        "GET", f"{LISTING}/a", httpx.Response(200, headers={c.DIGEST_HEADER: other}, stream=body)
    )
    with pytest.raises(ChecksumMismatchError, match=c.DIGEST_HEADER) as err:
        client.jobs.download_output("j", "a", tmp_path)
    assert other in str(err.value)
    assert SHA in str(err.value)
    assert err.value.code == "checksum_mismatch"
    assert body.pulled == 0
    assert list(tmp_path.iterdir()) == []


def test_a_response_without_the_header_is_still_verified_against_the_listing(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    server.on("GET", LISTING, [entry()])
    server.on("GET", f"{LISTING}/a", body_with(digest=None))
    assert client.jobs.download_output("j", "a", tmp_path).read_bytes() == DATA
    server.on("GET", f"{LISTING}/a", body_with(b"x" * len(DATA), digest=None))
    with pytest.raises(ChecksumMismatchError, match="sha256") as err:
        client.jobs.download_output("j", "a", tmp_path / "other")
    assert hashlib.sha256(b"x" * len(DATA)).hexdigest() in str(err.value)  # says what arrived


def test_a_body_that_does_not_match_its_own_header_is_refused(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    # Header and listing agree, the bytes do not: tampered in transit, or a broken server.
    server.on("GET", LISTING, [entry()])
    server.on("GET", f"{LISTING}/a", body_with(b"x" * len(DATA)))
    with pytest.raises(ChecksumMismatchError, match="sha256"):
        client.jobs.download_output("j", "a", tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_a_410_from_the_download_is_output_expired(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    # The listing was fetched just before the GC ran: the entry is not marked yet.
    server.on("GET", LISTING, [entry()])
    server.on("GET", f"{LISTING}/a", problem(410, "expired", "deleted after retention"))
    with pytest.raises(NotFoundError) as err:
        client.jobs.download_output("j", "a", tmp_path)
    assert (err.value.status, err.value.code) == (410, "output_expired")
    assert list(tmp_path.iterdir()) == []


def test_a_410_without_a_problem_body_is_output_expired_too(
    client: Client, server: FakeServer, tmp_path: Path
) -> None:
    server.on("GET", LISTING, [entry()])
    server.on("GET", f"{LISTING}/a", httpx.Response(410))
    with pytest.raises(NotFoundError) as err:
        client.jobs.download_output("j", "a", tmp_path)
    assert err.value.code == "output_expired"


@pytest.mark.asyncio
async def test_async_digest_header_and_410(
    aclient: AsyncClient, server: FakeServer, tmp_path: Path
) -> None:
    server.on("GET", LISTING, [entry()])
    server.on("GET", f"{LISTING}/a", body_with(digest=hashlib.sha256(b"other").hexdigest()))
    with pytest.raises(ChecksumMismatchError, match=c.DIGEST_HEADER):
        await aclient.jobs.download_output("j", "a", tmp_path)
    server.on("GET", f"{LISTING}/a", problem(410, "expired"))
    with pytest.raises(NotFoundError) as err:
        await aclient.jobs.download_output("j", "a", tmp_path)
    assert err.value.code == "output_expired"
    server.on("GET", f"{LISTING}/a", body_with())
    assert (await aclient.jobs.download_output("j", "a", tmp_path)).read_bytes() == DATA
    assert list(tmp_path.iterdir()) == [tmp_path / "a"]
