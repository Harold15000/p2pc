# SPDX-License-Identifier: Apache-2.0
"""Following logs (T13d): the same rules as the Rust CLI's ``StreamFollower``.

The server may end a followed stream cleanly before the attempt is over (at its 60 s idle limit,
or on an internal error), so a stream that ends proves nothing. An attempt's log is finished
only by a read that *began* after the attempt was known to be over: the job is final, or a later
attempt exists. A ``404`` or an empty page before that proves nothing either.

Every test runs on the fake clock (``FakeClock``): waiting only advances it. The records have the
real shape of ``GET /v1/jobs/{id}/logs``: ``{seq, stream, ts, data}``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from contextlib import aclosing
from typing import Any

import httpx
import pytest
from helpers import FakeClock, FakeServer, WatchedStream, idle_then, job_json, problem, streamed

from p2pc import AsyncClient, Client, NotFoundError, UnprocessableError

Factory = Callable[..., Client]
AFactory = Callable[..., AsyncClient]
LOGS = "/v1/jobs/j/logs"
JOB = "/v1/jobs/j"


def rec(seq: int, stream: str = "stdout", **extra: Any) -> dict[str, Any]:
    return {
        "seq": seq,
        "stream": stream,
        "ts": "2026-11-05T10:00:00Z",
        "data": f"line {seq}\n",
        **extra,
    }


def ndjson(*seqs: int) -> bytes:
    return b"".join(json.dumps(rec(s)).encode() + b"\n" for s in seqs)


def ends(*seqs: int) -> Callable[[httpx.Request], httpx.Response]:
    """A stream that delivers these lines and ends cleanly (a fresh response per call)."""
    return lambda _req: streamed([ndjson(*seqs)] if seqs else [])


def job(status: str, attempt: int = 1) -> dict[str, Any]:
    extra: dict[str, Any] = {"attempt": attempt}
    if status in ("succeeded", "failed"):
        extra["exit_code"] = 0 if status == "succeeded" else 1
    return job_json("j", status, **extra)


def reads(server: FakeServer) -> list[tuple[str | None, str]]:
    """``(attempt, since_seq)`` of every log request, in order."""
    return [
        (r.url.params.get("attempt"), r.url.params["since_seq"])
        for r in server.requests
        if r.url.path == LOGS
    ]


# --- a page is one read --------------------------------------------------------------------
def test_a_page_is_one_read_and_never_looks_at_the_job(client: Client, server: FakeServer) -> None:
    server.on("GET", LOGS, ends(4, 5))
    assert [x.seq for x in client.jobs.logs("j", since_seq=4)] == [4, 5]
    assert server.query() == {"follow": "false", "since_seq": "4"}
    assert server.count("GET", JOB) == 0


# --- a stream that ends while the job runs is reopened -------------------------------------
def test_a_stream_that_ends_cleanly_while_the_job_runs_is_reopened_until_it_is_over(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # The server closed the stream at its idle limit with the job still running; later the job
    # writes line 2 and ends. Nothing may be lost or repeated, and the follow must not give up.
    server.on("GET", LOGS, ends(0, 1), ends(), ends(2), ends())
    server.on(
        "GET",
        JOB,
        job("running"),  # before the first read
        job("running"),  # after it: not over
        job("running"),  # after the empty read: not over
        job("succeeded"),  # after the read of line 2: over now
        job("succeeded"),  # after the conclusive read
    )
    assert [x.seq for x in client.jobs.logs("j", follow=True)] == [0, 1, 2]
    # The attempt is always pinned. The read of line 2 began while the job still ran, so
    # one more read, which began after it was over, decides.
    assert reads(server) == [("1", "0"), ("1", "2"), ("1", "2"), ("1", "3")]
    assert {r.url.params["follow"] for r in server.requests if r.url.path == LOGS} == {"true"}
    assert clock.sleeps == [1.0, 2.0]  # a beat between reads that prove nothing, growing


def test_the_wait_between_reads_that_prove_nothing_is_capped(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    server.on("GET", LOGS, ends())
    server.on("GET", JOB, *[job("running")] * 7, job("succeeded"))
    assert list(client.jobs.logs("j", follow=True)) == []
    assert clock.sleeps == [1.0, 2.0, 4.0, 5.0, 5.0, 5.0]


def test_a_silent_stream_is_reopened_from_the_next_seq_after_the_idle_timeout(
    client: Client, server: FakeServer
) -> None:
    server.on("GET", LOGS, lambda _r: idle_then([ndjson(0, 1)]), ends(2), ends())
    server.on("GET", JOB, job("running"), job("running"), job("succeeded"), job("succeeded"))
    assert [x.seq for x in client.jobs.logs("j", follow=True)] == [0, 1, 2]
    assert reads(server) == [("1", "0"), ("1", "2"), ("1", "3")]


def test_an_idle_timeout_proves_nothing_even_when_the_attempt_is_over(
    client: Client, server: FakeServer
) -> None:
    # A read that timed out did not reach the end of the log, whatever the job says.
    server.on("GET", LOGS, lambda _r: idle_then([]), ends(0))
    server.on("GET", JOB, job("succeeded"))
    assert [x.seq for x in client.jobs.logs("j", follow=True)] == [0]
    assert reads(server) == [("1", "0"), ("1", "0")]


def test_a_404_or_an_empty_page_before_the_attempt_is_over_proves_nothing(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    server.on(
        "GET",
        LOGS,
        lambda _r: problem(404, "not_found"),  # no log yet
        ends(),  # an empty 200
        ends(0, 1),
        ends(),
    )
    server.on("GET", JOB, *[job("running")] * 3, *[job("succeeded")] * 2)
    assert [x.seq for x in client.jobs.logs("j", follow=True)] == [0, 1]
    assert reads(server) == [("1", "0"), ("1", "0"), ("1", "0"), ("1", "2")]
    assert clock.sleeps == [1.0, 2.0]


def test_a_404_that_began_after_the_attempt_was_over_means_it_has_no_log(
    client: Client, server: FakeServer
) -> None:
    server.on("GET", LOGS, lambda _r: problem(404, "not_found"))
    server.on("GET", JOB, job("succeeded"))
    assert list(client.jobs.logs("j", follow=True)) == []  # following the latest: no error
    assert reads(server) == [("1", "0")]


def test_a_fixed_attempt_without_a_log_reports_it_once_it_is_over(
    client: Client, server: FakeServer
) -> None:
    server.on("GET", LOGS, lambda _r: problem(404, "not_found"))
    server.on("GET", JOB, job("succeeded"))
    with pytest.raises(NotFoundError):
        list(client.jobs.logs("j", follow=True, attempt=1))


def test_permanent_errors_end_the_follow(client: Client, server: FakeServer) -> None:
    # A 5xx is transient and retried (test_logs_follow_retry.py); a 422 never gets better.
    server.on("GET", LOGS, lambda _r: problem(422, "validation_failed"))
    server.on("GET", JOB, job("running"))
    with pytest.raises(UnprocessableError):
        list(client.jobs.logs("j", follow=True))


# --- before the job runs, and when it never does --------------------------------------------
def test_nothing_is_read_while_the_job_is_queued(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    server.on("GET", LOGS, ends(0), ends())
    server.on("GET", JOB, job("queued"), job("queued"), job("running"), *[job("succeeded")] * 3)
    assert [x.seq for x in client.jobs.logs("j", follow=True)] == [0]
    assert clock.sleeps == [1.0]
    assert server.requests[0].url.path == JOB  # the job is looked at before any read
    assert reads(server)[0] == ("1", "0")


def test_a_final_job_that_never_started_has_no_log_to_read(
    client: Client, server: FakeServer
) -> None:
    server.on("GET", JOB, job_json("j", "cancelled", attempt=0))
    assert list(client.jobs.logs("j", follow=True)) == []
    assert reads(server) == []


def test_a_missing_job_is_an_error(client: Client, server: FakeServer) -> None:
    server.on("GET", JOB, problem(404, "not_found"))
    with pytest.raises(NotFoundError):
        list(client.jobs.logs("j", follow=True))


# --- retries: one log per attempt ------------------------------------------------------------
def test_a_requeued_job_is_followed_through_its_next_attempt(
    client: Client, server: FakeServer
) -> None:
    # The node was lost: attempt 2 took over before the tail of attempt 1 was read. That tail is
    # read first, from where the reader was; the next attempt starts again at seq 0.
    server.on(
        "GET",
        LOGS,
        lambda r: streamed([ndjson(0, 1)]) if r.url.params["attempt"] == "1" else streamed([]),
        lambda r: streamed([ndjson(2)]) if r.url.params["attempt"] == "1" else streamed([]),
        lambda r: streamed([ndjson(0, 1)]),
        ends(),
    )
    server.on(
        "GET",
        JOB,
        job("running", 1),  # first read
        job("running", 2),  # a later attempt exists now
        job("running", 2),
        job("succeeded", 2),
        job("succeeded", 2),
    )
    seen = [(x.seq, x.data) for x in client.jobs.logs("j", follow=True)]
    assert seen == [
        (0, "line 0\n"),
        (1, "line 1\n"),
        (2, "line 2\n"),
        (0, "line 0\n"),
        (1, "line 1\n"),
    ]
    assert reads(server) == [("1", "0"), ("1", "2"), ("2", "0"), ("2", "2")]


def test_a_fixed_attempt_ends_with_that_attempt_not_with_the_job(
    client: Client, server: FakeServer
) -> None:
    server.on("GET", LOGS, ends(0, 1))
    server.on("GET", JOB, job("running", 2))  # attempt 1 is over: attempt 2 exists
    assert [x.seq for x in client.jobs.logs("j", follow=True, attempt=1, since_seq=0)] == [0, 1]
    assert reads(server) == [("1", "0")]


def test_since_seq_is_inclusive_and_applies_to_the_first_read_only(
    client: Client, server: FakeServer
) -> None:
    server.on("GET", LOGS, ends(7, 8), ends())
    server.on("GET", JOB, job("running"), job("succeeded"), job("succeeded"))
    assert [x.seq for x in client.jobs.logs("j", follow=True, since_seq=7)] == [7, 8]
    assert reads(server) == [("1", "7"), ("1", "9")]


def test_the_truncation_marker_is_read_as_a_log_line(client: Client, server: FakeServer) -> None:
    marker = rec(9, "stderr", truncated=True)
    server.on(
        "GET",
        LOGS,
        lambda _r: streamed([json.dumps(rec(8)).encode() + b"\n", json.dumps(marker).encode()]),
    )
    lines = list(client.jobs.logs("j"))
    assert [x.truncated for x in lines] == [False, True]
    assert lines[1].stream == "stderr"


# --- async: the same rules -------------------------------------------------------------------
@pytest.mark.asyncio
async def test_async_a_stream_that_ends_cleanly_while_the_job_runs_is_reopened(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    server.on("GET", LOGS, ends(0, 1), ends(), ends(2), ends())
    server.on(
        "GET",
        JOB,
        job("running"),
        job("running"),
        job("running"),
        job("succeeded"),
        job("succeeded"),
    )
    seen = [x.seq async for x in aclient.jobs.logs("j", follow=True)]
    assert seen == [0, 1, 2]
    assert reads(server) == [("1", "0"), ("1", "2"), ("1", "2"), ("1", "3")]
    assert clock.sleeps == [1.0, 2.0]


@pytest.mark.asyncio
async def test_async_a_404_before_the_attempt_is_over_proves_nothing(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    server.on("GET", LOGS, lambda _r: problem(404, "not_found"), ends(0), ends())
    server.on("GET", JOB, *[job("running")] * 2, *[job("succeeded")] * 3)
    assert [x.seq async for x in aclient.jobs.logs("j", follow=True)] == [0]
    assert clock.sleeps == [1.0]


@pytest.mark.asyncio
async def test_async_a_requeued_job_is_followed_through_its_next_attempt(
    make_aclient: AFactory, server: FakeServer
) -> None:
    aclient = make_aclient()
    server.on("GET", LOGS, ends(0), ends(), ends(0), ends())
    server.on(
        "GET",
        JOB,
        job("running", 1),
        job("running", 2),
        job("running", 2),
        job("succeeded", 2),
        job("succeeded", 2),
    )
    assert [x.seq async for x in aclient.jobs.logs("j", follow=True)] == [0, 0]
    assert reads(server) == [("1", "0"), ("1", "1"), ("2", "0"), ("2", "1")]


@pytest.mark.asyncio
async def test_async_a_fixed_attempt_without_a_log_reports_it(
    make_aclient: AFactory, server: FakeServer
) -> None:
    aclient = make_aclient()
    server.on("GET", LOGS, lambda _r: problem(404, "not_found"))
    server.on("GET", JOB, job("succeeded", 2))
    with pytest.raises(NotFoundError):
        _ = [x async for x in aclient.jobs.logs("j", follow=True, attempt=3)]


@pytest.mark.asyncio
async def test_async_logs_can_still_be_closed_early(
    make_aclient: AFactory, server: FakeServer
) -> None:
    aclient = make_aclient()
    server.on("GET", LOGS, ends(0, 1, 2))
    server.on("GET", JOB, job("running"))
    async with aclosing(aclient.jobs.logs("j", follow=True)) as logs:
        assert (await anext(logs)).seq == 0


# --- closing a follow early releases the stream at once ---------------------------------------
def test_closing_a_follow_early_releases_the_stream_before_close_returns(
    client: Client, server: FakeServer
) -> None:
    stream = WatchedStream([ndjson(0), ndjson(1), ndjson(2)])
    server.on(
        "GET",
        LOGS,
        lambda _r: httpx.Response(
            200, headers={"content-type": "application/x-ndjson"}, stream=stream
        ),
    )
    server.on("GET", JOB, job("running"))
    logs = client.jobs.logs("j", follow=True)
    assert next(logs).seq == 0
    assert not stream.closed
    logs.close()  # type: ignore[attr-defined]
    assert stream.closed


@pytest.mark.asyncio
async def test_async_closing_a_follow_early_releases_the_stream_before_aclose_returns(
    make_aclient: AFactory, server: FakeServer
) -> None:
    aclient = make_aclient()
    stream = WatchedStream([ndjson(0), ndjson(1), ndjson(2)])
    server.on(
        "GET",
        LOGS,
        lambda _r: httpx.Response(
            200, headers={"content-type": "application/x-ndjson"}, stream=stream
        ),
    )
    server.on("GET", JOB, job("running"))
    logs = aclient.jobs.logs("j", follow=True)
    assert (await anext(logs)).seq == 0
    assert not stream.closed
    await logs.aclose()
    assert stream.closed


# --- a line the server sends twice is delivered once ------------------------------------------
def test_lines_the_server_resends_after_a_reconnect_are_dropped(
    client: Client, server: FakeServer
) -> None:
    # The second read starts at 3, but the server sends 1..4 again: only 3 and 4 are new.
    server.on("GET", LOGS, ends(0, 1, 2), ends(1, 2, 3, 4), ends())
    server.on("GET", JOB, job("running"), job("running"), job("succeeded"), job("succeeded"))
    assert [x.seq for x in client.jobs.logs("j", follow=True)] == [0, 1, 2, 3, 4]
    assert reads(server) == [("1", "0"), ("1", "3"), ("1", "5")]


def test_a_line_repeated_inside_one_stream_is_dropped(client: Client, server: FakeServer) -> None:
    server.on("GET", LOGS, ends(0, 1, 1, 0, 2), ends())
    server.on("GET", JOB, job("running"), job("succeeded"), job("succeeded"))
    assert [x.seq for x in client.jobs.logs("j", follow=True)] == [0, 1, 2]


def test_lines_below_since_seq_are_dropped_and_a_new_attempt_starts_again_at_0(
    client: Client, server: FakeServer
) -> None:
    def by_attempt(first: bytes, second: bytes) -> Callable[[httpx.Request], httpx.Response]:
        return lambda r: streamed([first if r.url.params["attempt"] == "1" else second])

    server.on("GET", LOGS, by_attempt(ndjson(3, 4, 5), b""), by_attempt(b"", ndjson(0, 1)))
    server.on("GET", JOB, job("running", 1), job("running", 2), job("succeeded", 2))
    seen = [x.seq for x in client.jobs.logs("j", follow=True, since_seq=5)]
    assert seen == [5, 0, 1]  # 3 and 4 are below 5; attempt 2 is not held to attempt 1's seqs


@pytest.mark.asyncio
async def test_async_lines_the_server_resends_after_a_reconnect_are_dropped(
    make_aclient: AFactory, server: FakeServer
) -> None:
    aclient = make_aclient()
    server.on("GET", LOGS, ends(0, 1, 2), ends(1, 2, 3, 4), ends())
    server.on("GET", JOB, job("running"), job("running"), job("succeeded"), job("succeeded"))
    assert [x.seq async for x in aclient.jobs.logs("j", follow=True)] == [0, 1, 2, 3, 4]
    assert reads(server) == [("1", "0"), ("1", "3"), ("1", "5")]


@pytest.mark.asyncio
async def test_async_a_line_repeated_inside_one_stream_is_dropped(
    make_aclient: AFactory, server: FakeServer
) -> None:
    aclient = make_aclient()
    server.on("GET", LOGS, ends(0, 1, 1, 0, 2), ends())
    server.on("GET", JOB, job("running"), job("succeeded"), job("succeeded"))
    assert [x.seq async for x in aclient.jobs.logs("j", follow=True)] == [0, 1, 2]
