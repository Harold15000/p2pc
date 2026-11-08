# SPDX-License-Identifier: Apache-2.0
"""Following across outages (T13f): the same retry rules as the Rust CLI's ``StreamFollower``.

The server breaks a followed body (instead of ending it) at its idle cut and on internal errors.
A broken stream, a connection error, a timeout, ``429`` and ``5xx`` are transient, on the stream
and on the ``GET /v1/jobs/{id}`` checks: the follow waits (1 s, doubling, at most 30 s, or the
server's ``Retry-After``) and reopens from the next ``seq``. Outages are tracked per route, the
log stream and the job check; each lasts at most 5 minutes from its first failure and ends only
with a success on its own route (a stream that worked, a job check that answered, or a ``404``
from the log route, which is an answer). A failed job check records its failure, waits and goes
back to reading the logs, so lines keep flowing while the job route is down. ``401``, ``403``,
``404`` on the job and ``422`` end the follow at once.

Time is the fake clock: waiting only advances it.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable

import httpx
import pytest
from helpers import FakeClock, FakeServer, broken_then, cut_after, idle_then, problem, streamed
from test_logs_follow import JOB, LOGS, ends, job, ndjson, reads

from p2pc import (
    AsyncClient,
    AuthenticationError,
    Client,
    NotFoundError,
    P2PCConnectionError,
    P2PCError,
    PermissionDeniedError,
    UnprocessableError,
)
from p2pc.models import LogLine

Factory = Callable[..., Client]
AFactory = Callable[..., AsyncClient]


def broken(*seqs: int) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _req: broken_then([ndjson(*seqs)] if seqs else [])


def down(status: int = 503, **headers: str) -> Callable[[httpx.Request], httpx.Response]:
    def answer(_req: httpx.Request) -> httpx.Response:
        response = problem(status, "unavailable")
        response.headers.update(headers)
        return response

    return answer


def assert_gave_up(clock: FakeClock) -> None:
    """The waits were 1 s doubling to 30 s, and they add up to exactly the 5-minute budget."""
    assert clock.sleeps[:6] == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0]
    assert max(clock.sleeps) <= 30.0
    assert sum(clock.sleeps) == 300.0


# --- a broken stream is reopened from the next seq --------------------------------------------
def test_a_stream_that_delivered_lines_and_breaks_is_reopened_from_the_next_seq(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # It was working (it delivered lines): the break is not an outage but an incomplete end, and
    # the job is checked before the stream is reopened.
    server.on("GET", LOGS, broken(0, 1), ends(2), ends())
    server.on("GET", JOB, job("running"), job("succeeded"), job("succeeded"))
    seen: list[P2PCError] = []
    assert [x.seq for x in client.jobs.logs("j", follow=True, on_outage=seen.append)] == [0, 1, 2]
    # The job was over when the second read began, so that read, from seq 2, is the one that ends.
    assert reads(server) == [("1", "0"), ("1", "2")]
    assert clock.sleeps == []
    assert seen == []


def test_a_stream_that_breaks_at_once_is_an_outage_and_is_reopened_after_a_wait(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    seen: list[P2PCError] = []
    server.on("GET", LOGS, broken(), broken(), ends(0), ends())
    server.on("GET", JOB, job("running"), job("succeeded"), job("succeeded"))
    assert [x.seq for x in client.jobs.logs("j", follow=True, on_outage=seen.append)] == [0]
    assert reads(server) == [("1", "0"), ("1", "0"), ("1", "0"), ("1", "1")]
    assert clock.sleeps == [1.0, 2.0]
    assert len(seen) == 1


def test_a_job_that_is_silent_across_two_idle_cuts_is_followed_to_its_end(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # The server cuts a quiet stream after 60 s, twice (it breaks the body), then the job writes.
    seen: list[P2PCError] = []
    server.on(
        "GET",
        LOGS,
        lambda _r: cut_after(clock, 60),
        lambda _r: cut_after(clock, 60),
        ends(0),
        ends(),
    )
    server.on("GET", JOB, *[job("running")] * 3, job("succeeded"))
    assert [x.seq for x in client.jobs.logs("j", follow=True, on_outage=seen.append)] == [0]
    assert reads(server) == [("1", "0"), ("1", "0"), ("1", "0"), ("1", "1")]
    assert clock.sleeps == [1.0, 2.0]  # only the beat between reads that prove nothing
    assert seen == []


def test_a_quiet_job_is_followed_across_many_idle_cuts(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # Under the server's 60 s idle cut a quiet job is cut every minute: 15 cuts are over 15
    # minutes, three times the outage budget, and the server is healthy all the time.
    seen: list[P2PCError] = []
    server.on("GET", LOGS, *[lambda _r: cut_after(clock, 60)] * 15, ends())
    server.on("GET", JOB, *[job("running")] * 16, job("succeeded"))
    started = clock.now
    assert list(client.jobs.logs("j", follow=True, on_outage=seen.append)) == []
    assert clock.now - started > 15 * 60
    assert len(reads(server)) == 17  # 15 cuts, a clean end, and the read that decides
    assert seen == []
    assert max(clock.sleeps) <= 5.0  # beats between reads, never the outage waits


def test_a_stream_that_delivers_a_line_every_50_seconds_and_breaks_is_followed(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    def quiet_job(request: httpx.Request) -> httpx.Response:
        seq = int(request.url.params["since_seq"])
        return cut_after(clock, 50, [ndjson(seq)]) if seq < 20 else httpx.Response(200)

    seen: list[P2PCError] = []
    server.on("GET", LOGS, quiet_job)
    server.on("GET", JOB, *[job("running")] * 21, job("succeeded"))
    started = clock.now
    assert [x.seq for x in client.jobs.logs("j", follow=True, on_outage=seen.append)] == list(
        range(20)
    )
    assert clock.now - started >= 20 * 50
    assert seen == []


def test_a_5xx_or_429_on_the_stream_is_retried(client: Client, server: FakeServer) -> None:
    server.on("GET", LOGS, down(500), down(429), down(502), ends(0), ends())
    server.on("GET", JOB, job("running"), job("succeeded"), job("succeeded"))
    assert [x.seq for x in client.jobs.logs("j", follow=True)] == [0]


# --- outages are tracked per route --------------------------------------------------------------
@pytest.mark.parametrize("lines", [(0,), ()], ids=["a line", "silent for the hour"])
def test_an_old_log_outage_does_not_count_against_a_later_job_check_failure(
    client: Client, server: FakeServer, clock: FakeClock, lines: tuple[int, ...]
) -> None:
    # The log route fails (outage from T0), recovers, and a healthy stream runs for an hour. That
    # working stream ended the log route's outage. When the stream breaks, one job check fails:
    # it is a new, young outage of the *job* route, not the hour-old one of the logs.
    seen: list[P2PCError] = []
    server.on(
        "GET",
        LOGS,
        down(503),
        down(503),
        down(503),
        lambda _r: cut_after(clock, 3600, [ndjson(*lines)] if lines else []),
        ends(),
    )
    server.on("GET", JOB, job("running"), down(503), job("succeeded"))
    started = clock.now
    assert [x.seq for x in client.jobs.logs("j", follow=True, on_outage=seen.append)] == list(lines)
    assert clock.now - started > 3600
    assert clock.sleeps == [1.0, 2.0, 4.0, 1.0]  # three log retries, then one job-check retry
    assert len(seen) == 2  # one outage on each route


def test_a_log_route_that_stays_down_after_a_job_check_succeeds_still_gives_up(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # A good job check does not end the *log* route's outage: only a stream that worked does.
    server.on("GET", LOGS, down(503))
    server.on("GET", JOB, job("running"))
    with pytest.raises(P2PCConnectionError, match="log stream"):
        list(client.jobs.logs("j", follow=True))
    assert_gave_up(clock)


# --- transient job checks ---------------------------------------------------------------------
def test_transient_failures_of_the_job_check_are_retried_and_the_outage_resets(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # Two outages, each of its own: the wait starts again at 1 s after a successful job check.
    server.on("GET", LOGS, ends(0), ends(), ends())
    server.on(
        "GET",
        JOB,
        down(503),  # before the first read: the very first check is retried too
        down(504),
        job("running"),
        down(500),  # after the first read
        job("succeeded"),
        job("succeeded"),
    )
    seen: list[P2PCError] = []
    assert [x.seq for x in client.jobs.logs("j", follow=True, on_outage=seen.append)] == [0]
    assert clock.sleeps == [1.0, 2.0, 1.0]
    assert len(seen) == 2


def test_a_connection_error_on_the_job_check_is_retried(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    def refuse(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    server.on("GET", LOGS, ends(0), ends())
    server.on("GET", JOB, refuse, refuse, job("succeeded"))
    assert [x.seq for x in client.jobs.logs("j", follow=True)] == [0]
    assert clock.sleeps == [1.0, 2.0]


def test_the_wait_honours_retry_after_but_never_goes_past_the_budget(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    server.on("GET", LOGS, ends(0), ends())
    server.on(
        "GET",
        JOB,
        down(429, **{"retry-after": "7"}),
        down(503, **{"retry-after": "5000"}),
        job("succeeded"),
    )
    assert [x.seq for x in client.jobs.logs("j", follow=True)] == [0]
    assert clock.sleeps == [7.0, 293.0]  # 5 minutes in all, however long the server asks


# --- giving up --------------------------------------------------------------------------------
def test_an_outage_longer_than_five_minutes_ends_the_follow(
    client: Client, server: FakeServer, clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    # The log endpoint is down: its streams fail to open (5xx) or break at once.
    server.on("GET", LOGS, down(503), broken())
    server.on("GET", JOB, job("running"))
    seen: list[P2PCError] = []
    with (
        caplog.at_level(logging.INFO, logger="p2pc"),
        pytest.raises(P2PCConnectionError, match="300 s") as info,
    ):
        list(client.jobs.logs("j", follow=True, on_outage=seen.append))
    assert "outage" in str(info.value)
    assert_gave_up(clock)
    assert len(seen) == 1
    assert [r.name for r in caplog.records if "outage" in r.getMessage()] == ["p2pc"]


def test_job_checks_that_keep_failing_end_the_follow_even_while_logs_work(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # The logs work, so they are read between the failed checks, but that does not end the *job*
    # route's outage: only a successful check does.
    server.on("GET", LOGS, ends(0), ends())
    server.on("GET", JOB, job("running"), down(503))
    with pytest.raises(P2PCConnectionError, match="outage"):
        list(client.jobs.logs("j", follow=True))
    assert_gave_up(clock)


def test_an_outage_ended_by_a_job_check_starts_afresh_the_next_time(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # A job check fails, one works (outage over), then they fail again: a new outage, from zero
    # (the wait starts again at 1 s).
    server.on("GET", LOGS, ends(0), ends(), ends())
    server.on("GET", JOB, job("running"), down(503), job("running"), down(503))
    with pytest.raises(P2PCConnectionError):
        list(client.jobs.logs("j", follow=True))
    assert clock.sleeps[:3] == [1.0, 1.0, 1.0]  # the wait starts again at 1 s: new outage
    assert sum(clock.sleeps) > 300.0


# --- the logs are read while the job route is down (T13g) ---------------------------------------
def job_down_for(
    clock: FakeClock, seconds: float, then: dict[str, object]
) -> Callable[[httpx.Request], httpx.Response]:
    """The first job check answers (running); then they fail for ``seconds`` of fake time."""
    started = clock.now
    calls = {"n": 0}

    def answer(_req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json=job("running"))
        if clock.now - started < seconds:
            return problem(503, "unavailable")
        return httpx.Response(200, json=then)

    return answer


def one_line_per_read(_req: httpx.Request) -> httpx.Response:
    seq = int(_req.url.params["since_seq"])
    return streamed([ndjson(seq)])


def test_logs_are_read_while_the_job_checks_fail(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # The job route is down for 2 minutes and the log route is healthy: the follow goes back to the
    # logs after each failed check (as the CLI does) instead of retrying the check in place.
    server.on("GET", LOGS, one_line_per_read)
    server.on("GET", JOB, job_down_for(clock, 120, job("succeeded")))
    started = clock.now
    arrivals: list[tuple[float, int]] = []
    seen: list[P2PCError] = []
    lines = client.jobs.logs("j", follow=True, on_outage=seen.append)
    arrivals.extend((clock.now - started, line.seq) for line in lines)
    assert [seq for _, seq in arrivals] == list(range(len(arrivals)))  # none lost or repeated
    assert len([t for t, _ in arrivals if 0 < t < 120]) >= 5  # lines arrived during the outage
    assert clock.now - started >= 120
    assert len(seen) == 1  # one outage, of the job route


def test_a_job_route_that_stays_down_gives_up_while_logs_flow(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    server.on("GET", LOGS, one_line_per_read)
    server.on("GET", JOB, job_down_for(clock, 10_000, job("succeeded")))
    got: list[int] = []
    with pytest.raises(P2PCConnectionError, match="job check"):
        got.extend(line.seq for line in client.jobs.logs("j", follow=True))
    assert got == list(range(len(got)))
    assert len(got) >= 6  # logs kept coming for the whole 5 minutes
    assert_gave_up(clock)


# --- a 404 from the log route ends a log outage (T13g) --------------------------------------
def not_started_then_blip(
    clock: FakeClock, started: float, blip: list[bool]
) -> Callable[[httpx.Request], httpx.Response]:
    """503, then 404s for 310 s of fake time (attempt 2 has not started), a 503, then lines."""
    calls = {"n": 0}

    def logs(_req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return problem(503, "unavailable")
        if clock.now - started < 310:
            return problem(404, "not_found")
        if not blip:
            blip.append(True)
            return problem(503, "unavailable")
        return streamed([ndjson(0)])

    return logs


def test_a_404_ends_a_log_outage(client: Client, server: FakeServer, clock: FakeClock) -> None:
    # attempt=2 gets 404s while it has not started. A 503 before them starts a log outage; the
    # 404s are answers of a working route and end it, so a blip after 5 minutes of them is a new
    # outage and not the end of the old one.
    started = clock.now
    blip: list[bool] = []
    server.on("GET", LOGS, not_started_then_blip(clock, started, blip))
    server.on(
        "GET", JOB, lambda _r: httpx.Response(200, json=job("succeeded" if blip else "running"))
    )
    seen: list[P2PCError] = []
    lines = client.jobs.logs("j", follow=True, attempt=1, on_outage=seen.append)
    assert [x.seq for x in lines] == [0]
    assert clock.now - started > 310
    assert len(seen) == 2  # the 503 before the 404s, and the one after them: two outages


# --- a log route that hangs before the headers gives up (T13g) -------------------------------
def hangs(clock: FakeClock, seconds: float) -> Callable[[httpx.Request], httpx.Response]:
    calls = {"n": 0}

    def hang(_req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] > 200:
            raise AssertionError("the follow never gave up")
        clock.now += seconds  # the time the request waited for headers that never came
        raise httpx.ReadTimeout("no headers")

    return hang


def test_a_log_route_that_hangs_before_the_headers_gives_up(
    make_client: Factory, server: FakeServer, clock: FakeClock
) -> None:
    client = make_client(follow_idle_timeout=10.0)
    server.on("GET", LOGS, hangs(clock, 10))
    server.on("GET", JOB, job("running"))
    started = clock.now
    seen: list[P2PCError] = []
    with pytest.raises(P2PCConnectionError, match="log stream"):
        list(client.jobs.logs("j", follow=True, on_outage=seen.append))
    assert 300 <= clock.now - started < 400
    assert len(seen) == 1


def test_a_timeout_after_the_headers_of_a_working_body_is_not_a_failure(
    client: Client, server: FakeServer, clock: FakeClock
) -> None:
    # Many idle timeouts of a body that delivered a line: never an outage, however long it takes.
    server.on("GET", LOGS, *[lambda _r: idle_then([ndjson(0)])] * 60, ends())
    server.on("GET", JOB, *[job("running")] * 61, job("succeeded"))
    seen: list[P2PCError] = []
    assert [x.seq for x in client.jobs.logs("j", follow=True, on_outage=seen.append)] == [0]
    assert seen == []


async def collect(lines: AsyncIterator[LogLine], into: list[int]) -> None:
    """Keep the ``seq`` of every line delivered, even if the follow then raises."""
    async for line in lines:
        into.append(line.seq)  # noqa: PERF401 - a comprehension would lose them on a raise


@pytest.mark.asyncio
async def test_async_logs_are_read_while_the_job_checks_fail(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    server.on("GET", LOGS, one_line_per_read)
    server.on("GET", JOB, job_down_for(clock, 120, job("succeeded")))
    started = clock.now
    arrivals: list[tuple[float, int]] = []
    arrivals.extend(
        [(clock.now - started, line.seq) async for line in aclient.jobs.logs("j", follow=True)]
    )
    assert [seq for _, seq in arrivals] == list(range(len(arrivals)))
    assert len([t for t, _ in arrivals if 0 < t < 120]) >= 5
    assert clock.now - started >= 120


@pytest.mark.asyncio
async def test_async_a_job_route_that_stays_down_gives_up_while_logs_flow(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    server.on("GET", LOGS, one_line_per_read)
    server.on("GET", JOB, job_down_for(clock, 10_000, job("succeeded")))
    got: list[int] = []
    with pytest.raises(P2PCConnectionError, match="job check"):
        await collect(aclient.jobs.logs("j", follow=True), got)
    assert len(got) >= 6
    assert_gave_up(clock)


@pytest.mark.asyncio
async def test_async_a_404_ends_a_log_outage(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    started = clock.now
    blip: list[bool] = []
    server.on("GET", LOGS, not_started_then_blip(clock, started, blip))
    server.on(
        "GET", JOB, lambda _r: httpx.Response(200, json=job("succeeded" if blip else "running"))
    )
    seen: list[P2PCError] = []
    lines = aclient.jobs.logs("j", follow=True, attempt=1, on_outage=seen.append)
    assert [x.seq async for x in lines] == [0]
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_async_a_log_route_that_hangs_before_the_headers_gives_up(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient(follow_idle_timeout=10.0)
    server.on("GET", LOGS, hangs(clock, 10))
    server.on("GET", JOB, job("running"))
    started = clock.now
    with pytest.raises(P2PCConnectionError, match="log stream"):
        _ = [x async for x in aclient.jobs.logs("j", follow=True)]
    assert 300 <= clock.now - started < 400


# --- an async on_outage is awaited (T13g) ---------------------------------------------------
@pytest.mark.asyncio
async def test_async_an_async_on_outage_is_awaited_once_per_outage(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    seen: list[P2PCError] = []

    async def on_outage(error: P2PCError) -> None:
        seen.append(error)

    server.on("GET", LOGS, down(503), down(503), ends(0), ends())
    server.on("GET", JOB, job("running"), down(503), job("succeeded"), job("succeeded"))
    lines = aclient.jobs.logs("j", follow=True, on_outage=on_outage)
    assert [x.seq async for x in lines] == [0]
    assert len(seen) == 2  # one outage on each route, each announced and awaited once


@pytest.mark.asyncio
async def test_async_a_plain_on_outage_still_works(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    seen: list[P2PCError] = []
    server.on("GET", LOGS, down(503), ends(0), ends())
    server.on("GET", JOB, job("running"), job("succeeded"), job("succeeded"))
    lines = aclient.jobs.logs("j", follow=True, on_outage=seen.append)
    assert [x.seq async for x in lines] == [0]
    assert len(seen) == 1


# --- permanent errors end it at once ----------------------------------------------------------
@pytest.mark.parametrize(
    ("where", "answer", "error"),
    [
        (LOGS, 401, AuthenticationError),
        (LOGS, 403, PermissionDeniedError),
        (LOGS, 422, UnprocessableError),
        (JOB, 401, AuthenticationError),
        (JOB, 403, PermissionDeniedError),
        (JOB, 404, NotFoundError),
        (JOB, 422, UnprocessableError),
    ],
)
def test_permanent_errors_end_the_follow_at_once(
    client: Client,
    server: FakeServer,
    clock: FakeClock,
    where: str,
    answer: int,
    error: type[P2PCError],
) -> None:
    server.on("GET", LOGS, ends(0))
    server.on("GET", JOB, job("running"))
    server.on("GET", where, down(answer))
    on_outage: list[P2PCError] = []
    with pytest.raises(error):
        list(client.jobs.logs("j", follow=True, on_outage=on_outage.append))
    assert clock.sleeps == []
    assert on_outage == []


# --- async: the same rules --------------------------------------------------------------------
@pytest.mark.asyncio
async def test_async_a_stream_that_delivered_lines_and_breaks_is_reopened_from_the_next_seq(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    seen: list[P2PCError] = []
    server.on("GET", LOGS, broken(0, 1), ends(2), ends())
    server.on("GET", JOB, job("running"), job("succeeded"), job("succeeded"))
    lines = aclient.jobs.logs("j", follow=True, on_outage=seen.append)
    assert [x.seq async for x in lines] == [0, 1, 2]
    # The job was over when the second read began, so that read, from seq 2, is the one that ends.
    assert reads(server) == [("1", "0"), ("1", "2")]
    assert clock.sleeps == []
    assert seen == []


@pytest.mark.asyncio
async def test_async_a_stream_that_breaks_at_once_is_an_outage(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    seen: list[P2PCError] = []
    server.on("GET", LOGS, broken(), broken(), ends(0), ends())
    server.on("GET", JOB, job("running"), job("succeeded"), job("succeeded"))
    lines = aclient.jobs.logs("j", follow=True, on_outage=seen.append)
    assert [x.seq async for x in lines] == [0]
    assert clock.sleeps == [1.0, 2.0]
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_async_a_quiet_job_is_followed_across_many_idle_cuts(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    seen: list[P2PCError] = []
    server.on("GET", LOGS, *[lambda _r: cut_after(clock, 60)] * 15, ends())
    server.on("GET", JOB, *[job("running")] * 16, job("succeeded"))
    started = clock.now
    lines = aclient.jobs.logs("j", follow=True, on_outage=seen.append)
    assert [x async for x in lines] == []
    assert clock.now - started > 15 * 60
    assert len(reads(server)) == 17
    assert seen == []


@pytest.mark.asyncio
async def test_async_a_stream_that_delivers_a_line_every_50_seconds_and_breaks_is_followed(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()

    def quiet_job(request: httpx.Request) -> httpx.Response:
        seq = int(request.url.params["since_seq"])
        return cut_after(clock, 50, [ndjson(seq)]) if seq < 20 else httpx.Response(200)

    seen: list[P2PCError] = []
    server.on("GET", LOGS, quiet_job)
    server.on("GET", JOB, *[job("running")] * 21, job("succeeded"))
    lines = aclient.jobs.logs("j", follow=True, on_outage=seen.append)
    assert [x.seq async for x in lines] == list(range(20))
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize("lines", [(0,), ()], ids=["a line", "silent for the hour"])
async def test_async_an_old_log_outage_does_not_count_against_a_later_job_check_failure(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock, lines: tuple[int, ...]
) -> None:
    aclient = make_aclient()
    seen: list[P2PCError] = []
    server.on(
        "GET",
        LOGS,
        down(503),
        down(503),
        down(503),
        lambda _r: cut_after(clock, 3600, [ndjson(*lines)] if lines else []),
        ends(),
    )
    server.on("GET", JOB, job("running"), down(503), job("succeeded"))
    started = clock.now
    stream = aclient.jobs.logs("j", follow=True, on_outage=seen.append)
    assert [x.seq async for x in stream] == list(lines)
    assert clock.now - started > 3600
    assert clock.sleeps == [1.0, 2.0, 4.0, 1.0]
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_async_a_log_route_that_stays_down_after_a_job_check_succeeds_still_gives_up(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    server.on("GET", LOGS, down(503))
    server.on("GET", JOB, job("running"))
    with pytest.raises(P2PCConnectionError, match="log stream"):
        _ = [x async for x in aclient.jobs.logs("j", follow=True)]
    assert_gave_up(clock)


@pytest.mark.asyncio
async def test_async_transient_job_checks_are_retried_and_honour_retry_after(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    server.on("GET", LOGS, ends(0), ends())
    server.on("GET", JOB, down(429, **{"retry-after": "7"}), down(503), job("succeeded"))
    assert [x.seq async for x in aclient.jobs.logs("j", follow=True)] == [0]
    assert clock.sleeps == [7.0, 2.0]


@pytest.mark.asyncio
async def test_async_an_outage_longer_than_five_minutes_ends_the_follow(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    server.on("GET", LOGS, down(503), broken())
    server.on("GET", JOB, job("running"))
    with pytest.raises(P2PCConnectionError, match="outage"):
        _ = [x async for x in aclient.jobs.logs("j", follow=True)]
    assert_gave_up(clock)


@pytest.mark.asyncio
async def test_async_job_checks_that_keep_failing_end_the_follow_even_while_logs_work(
    make_aclient: AFactory, server: FakeServer, clock: FakeClock
) -> None:
    aclient = make_aclient()
    # The logs keep being read between the failed checks, which does not end the job outage.
    server.on("GET", LOGS, ends(0), ends())
    server.on("GET", JOB, job("running"), down(503))
    with pytest.raises(P2PCConnectionError, match="outage"):
        _ = [x async for x in aclient.jobs.logs("j", follow=True)]
    assert_gave_up(clock)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("where", "answer", "error"),
    [
        (LOGS, 401, AuthenticationError),
        (JOB, 401, AuthenticationError),
        (JOB, 404, NotFoundError),
        (LOGS, 422, UnprocessableError),
    ],
)
async def test_async_permanent_errors_end_the_follow_at_once(
    make_aclient: AFactory,
    server: FakeServer,
    clock: FakeClock,
    where: str,
    answer: int,
    error: type[P2PCError],
) -> None:
    aclient = make_aclient()
    server.on("GET", LOGS, ends(0))
    server.on("GET", JOB, job("running"))
    server.on("GET", where, down(answer))
    with pytest.raises(error):
        _ = [x async for x in aclient.jobs.logs("j", follow=True)]
    assert clock.sleeps == []
