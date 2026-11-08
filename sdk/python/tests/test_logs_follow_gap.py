# SPDX-License-Identifier: Apache-2.0
"""The outage rules of a follow (T13h): the gap, the start of an outage, and the sync callback.

An outage of a route is a run of failures of that route. It is timed from the **start** of its
first failed request, has no success on that route, and has no gap longer than 30 s (the longest
wait) between the time its next request was due and the time it began. A longer gap means the
client was busy with healthy work on the other route: the next failure starts a **new** outage.
The gap does not count the wait the SDK scheduled itself. One outage lasts at most 5 minutes.

Time is the fake clock: waiting, and a request that takes time, only advance it.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from helpers import FakeClock, FakeServer, cut_after, problem, streamed
from test_logs_follow import JOB, LOGS, ends, job, ndjson
from test_logs_follow_retry import AFactory, down, hangs

from p2pc import Client, P2PCConnectionError, P2PCError

SIX_MINUTES = 360.0


def slow_reads(clock: FakeClock, seconds: float) -> Callable[[httpx.Request], httpx.Response]:
    """Every read takes ``seconds`` and delivers one new line."""

    def answer(request: httpx.Request) -> httpx.Response:
        clock.now += seconds
        return streamed([ndjson(int(request.url.params["since_seq"]))])

    return answer


def after_the_long_stream(server: FakeServer, clock: FakeClock) -> None:
    """A failed job check, a healthy stream of six minutes, one more failed job check."""
    server.on("GET", LOGS, ends(0), lambda _r: cut_after(clock, SIX_MINUTES, [ndjson(1)]), ends())
    server.on("GET", JOB, job("running"), down(503), down(503), job("succeeded"))


# --- the gap rule ---------------------------------------------------------------------------
def test_a_failed_check_before_and_after_a_long_stream_are_two_outages(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    after_the_long_stream(server, clock)
    seen: list[P2PCError] = []
    started = clock.now
    assert [x.seq for x in client.jobs.logs("j", follow=True, on_outage=seen.append)] == [0, 1]
    assert clock.now - started > SIX_MINUTES
    assert len(seen) == 2  # one announcement for each outage
    assert clock.sleeps == [1.0, 1.0]  # and the second starts again at 1 s


@pytest.mark.asyncio
async def test_async_a_failed_check_before_and_after_a_long_stream_are_two_outages(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    after_the_long_stream(server, clock)
    seen: list[P2PCError] = []
    lines = make_aclient().jobs.logs("j", follow=True, on_outage=seen.append)
    assert [x.seq async for x in lines] == [0, 1]
    assert len(seen) == 2
    assert clock.sleeps == [1.0, 1.0]


def test_a_job_route_that_keeps_failing_gives_up_five_minutes_after_its_first_failure(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # Every log read takes 2 s, so from one failed check to the next it is the wait plus 2 s: with
    # waits of 30 s that is 32 s. The scheduled wait is no gap; only the 2 s of work in between
    # counts, so this is one outage and it ends 5 minutes after its first failure.
    server.on("GET", LOGS, slow_reads(clock, 2))
    server.on("GET", JOB, job("running"), down(503))
    announced: list[float] = []
    with pytest.raises(P2PCConnectionError, match="job check"):
        list(client.jobs.logs("j", follow=True, on_outage=lambda _e: announced.append(clock.now)))
    assert len(announced) == 1
    assert 300 <= clock.now - announced[0] < 305


@pytest.mark.asyncio
async def test_async_a_job_route_that_keeps_failing_gives_up_five_minutes_after_its_first_failure(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    server.on("GET", LOGS, slow_reads(clock, 2))
    server.on("GET", JOB, job("running"), down(503))
    announced: list[float] = []
    lines = make_aclient().jobs.logs(
        "j", follow=True, on_outage=lambda _e: announced.append(clock.now)
    )
    with pytest.raises(P2PCConnectionError, match="job check"):
        _ = [x async for x in lines]
    assert len(announced) == 1
    assert 300 <= clock.now - announced[0] < 305


def test_a_log_route_that_is_really_down_gives_up_after_five_minutes(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    server.on("GET", LOGS, down(503))
    server.on("GET", JOB, job("running"))
    seen: list[P2PCError] = []
    started = clock.now
    with pytest.raises(P2PCConnectionError, match="log stream"):
        list(client.jobs.logs("j", follow=True, on_outage=seen.append))
    assert clock.now - started == 300.0
    assert len(seen) == 1


def test_a_retry_after_longer_than_the_longest_wait_is_no_gap(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # The server asks for 120 s; the SDK waits that long. The next request is due after the wait
    # it scheduled, so this is still the same outage.
    server.on("GET", LOGS, ends(0), ends())
    server.on("GET", JOB, job("running"), down(503, **{"Retry-After": "120"}))
    seen: list[P2PCError] = []
    with pytest.raises(P2PCConnectionError, match="job check"):
        list(client.jobs.logs("j", follow=True, on_outage=seen.append))
    assert len(seen) == 1
    assert 120.0 in clock.sleeps
    assert sum(clock.sleeps) == 300.0


# --- an outage is timed from the start of its first failed request ------------------------------
def test_a_log_route_that_hangs_with_the_default_timeout_gives_up_after_five_minutes(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # `follow_idle_timeout` is 300 s by default: the first request hangs for all of the outage's
    # 5 minutes, and the outage began when it was sent, not when it gave up.
    server.on("GET", LOGS, hangs(clock, 300))
    server.on("GET", JOB, job("running"))
    started = clock.now
    seen: list[P2PCError] = []
    with pytest.raises(P2PCConnectionError, match="log stream"):
        list(client.jobs.logs("j", follow=True, on_outage=seen.append))
    assert clock.now - started == 300.0
    assert len(seen) == 1
    assert clock.sleeps == []


@pytest.mark.asyncio
async def test_async_a_log_route_that_hangs_with_the_default_timeout_gives_up_after_five_minutes(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    server.on("GET", LOGS, hangs(clock, 300))
    server.on("GET", JOB, job("running"))
    started = clock.now
    with pytest.raises(P2PCConnectionError, match="log stream"):
        _ = [x async for x in make_aclient().jobs.logs("j", follow=True)]
    assert clock.now - started == 300.0


def test_a_slow_failed_job_check_is_timed_from_when_it_was_sent(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # A job check that times out after 200 s: the outage began 200 s before it failed, so there
    # are 100 s left, not 300.
    def slow_failure(_r: httpx.Request) -> httpx.Response:
        clock.now += 200
        return problem(503, "unavailable")

    server.on("GET", LOGS, ends(0), ends())
    server.on("GET", JOB, job("running"), slow_failure, down(503))
    started = clock.now
    with pytest.raises(P2PCConnectionError, match="job check"):
        list(client.jobs.logs("j", follow=True))
    # The budget is exactly 300 s: 200 s in the slow check and the 100 s left, slept. Giving up
    # right after the 200 s failure would pass the upper bound alone.
    assert 300 <= clock.now - started < 305
    assert sum(clock.sleeps) == pytest.approx(100, abs=5)


# --- a sync client does not take an async callback ---------------------------------------------
def test_a_sync_client_rejects_an_async_on_outage(client: Client, server: FakeServer) -> None:
    async def on_outage(_error: P2PCError) -> None:
        raise AssertionError("never awaited")

    with pytest.raises(TypeError, match="AsyncClient"):
        client.jobs.logs("j", follow=True, on_outage=on_outage)  # type: ignore[arg-type]
    assert server.requests == []  # refused before anything is sent


def test_a_sync_client_still_takes_a_plain_callback(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    server.on("GET", LOGS, down(503), ends(0), ends())
    server.on("GET", JOB, job("running"), job("succeeded"))
    seen: list[P2PCError] = []
    assert [x.seq for x in client.jobs.logs("j", follow=True, on_outage=seen.append)] == [0]
    assert len(seen) == 1


def test_a_job_object_rejects_an_async_on_outage_too(client: Client, server: FakeServer) -> None:
    async def on_outage(_error: P2PCError) -> None:
        raise AssertionError("never awaited")

    server.on("GET", JOB, job("running"))
    handle = client.jobs.get("j")
    with pytest.raises(TypeError, match="AsyncClient"):
        handle.logs(follow=True, on_outage=on_outage)  # type: ignore[arg-type]
