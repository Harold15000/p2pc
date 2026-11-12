# SPDX-License-Identifier: Apache-2.0
"""Asynchronous client: the same surface as :class:`p2pc.Client`, with ``await``."""

from __future__ import annotations

import asyncio
import builtins
import inspect
import logging
import os
import time
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import aclosing, asynccontextmanager
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Self, TypeVar

import httpx
from pydantic import BaseModel

from p2pc import _common as c
from p2pc import h2
from p2pc._ports import AsyncPortForwarder
from p2pc.errors import InvalidResponseError, NotFoundError, P2PCConnectionError, P2PCError
from p2pc.h2 import Blob, TemplateList
from p2pc.models import (
    ApiKey,
    AsyncJob,
    AuditEvent,
    BlobInput,
    Egress,
    Estimate,
    InputFile,
    JobStatus,
    JoinToken,
    JoinTokenInfo,
    LogLine,
    NewApiKey,
    Node,
    OutputFile,
    Page,
    Placement,
    ServerInfo,
    ServicePort,
    UsageReport,
    VolumeSpec,
    WhoAmI,
)

__all__ = ["AsyncClient"]

LOG = logging.getLogger("p2pc")
M = TypeVar("M", bound=BaseModel)
R = TypeVar("R")


async def _in_thread(fn: Callable[..., R], *args: Any) -> R:
    """Run blocking file I/O in a worker thread, so that a cancel never races it.

    A thread cannot be interrupted. If the awaiting task is cancelled (for example by
    ``asyncio.timeout``) while ``fn`` runs, the cancellation is held until the thread has
    returned, and only then re-raised: the caller's cleanup (``DownloadWriter.abort``) therefore
    never runs while the thread is still touching the same files. A second cancel while
    waiting is deferred the same way; the thread calls are short, single file operations.
    """
    work = asyncio.ensure_future(asyncio.to_thread(fn, *args))
    cancelled: asyncio.CancelledError | None = None
    while True:
        try:
            result = await asyncio.shield(work)
        except asyncio.CancelledError as exc:
            if work.cancelled():
                raise
            cancelled = exc
            continue
        except BaseException:
            if cancelled is not None:
                raise cancelled from None
            raise
        break
    if cancelled is not None:
        raise cancelled
    return result


class AsyncClient:
    """Async client for the P2PC Jobs API. See :class:`p2pc.Client` for the parameters."""

    def __init__(
        self,
        api_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 30.0,
        http_client: httpx.AsyncClient | None = None,
        *,
        follow_idle_timeout: float = c.DEFAULT_FOLLOW_IDLE_TIMEOUT,
    ) -> None:
        self._config = c.Config.resolve(api_url, api_key, timeout, follow_idle_timeout)
        self._config.warn_if_cleartext()
        self._owns_http = http_client is None
        self._http = http_client if http_client is not None else httpx.AsyncClient()
        # Injectable for tests: no real sleeping is needed to exercise `wait`.
        self._sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
        self._monotonic: Callable[[], float] = time.monotonic
        self.jobs = AsyncJobsResource(self)
        self.nodes = AsyncNodesResource(self)
        self.join_tokens = AsyncJoinTokensResource(self)
        self.keys = AsyncKeysResource(self)
        self.blobs = AsyncBlobsResource(self)
        self.services = AsyncServicesResource(self)
        self.templates = AsyncTemplatesResource(self)

    def __repr__(self) -> str:
        return self._config.client_repr("AsyncClient")

    __str__ = __repr__

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # --- transport ---------------------------------------------------------------------
    def _connection_error(self, exc: httpx.TransportError) -> P2PCConnectionError:
        detail = c.redact(f"{type(exc).__name__}: {exc}", self._config.api_key)
        return P2PCConnectionError(f"could not reach {self._config.safe_url}: {detail}")

    async def _raise_for_status(self, response: httpx.Response) -> None:
        """Raise the mapped error for a non-2xx response, reading at most 64 KiB of its body."""
        LOG.debug("response status=%d", response.status_code)
        if response.status_code >= 300:
            body = c.ErrorBody()
            async for chunk in response.aiter_bytes():
                if body.add(chunk):
                    break
            raise c.error_from_response(response, self._config.api_key, body.value())

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        json: Any = None,
        content: Any = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> Any:
        headers = {**self._config.headers(), **(extra_headers or {})}
        LOG.debug("request %s %s", method, path)
        body = c.ResponseBody()
        try:
            async with self._http.stream(
                method,
                self._config.url(path),
                params=params,
                json=json,
                content=content,
                headers=headers,
                timeout=self._config.timeout,
            ) as response:
                await self._raise_for_status(response)
                async for chunk in response.aiter_bytes():
                    body.add(chunk)
        except httpx.TransportError as exc:
            raise self._connection_error(exc) from None
        return c.parse_json(body.value())

    @asynccontextmanager
    async def _stream(
        self,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        accept: str = "application/octet-stream",
        follow: bool = False,
    ) -> AsyncIterator[httpx.Response]:
        headers = self._config.headers(accept)
        # A followed log stream may be silent for a while: it gets its own, longer read timeout.
        read = self._config.follow_idle_timeout if follow else self._config.timeout
        timeout = httpx.Timeout(self._config.timeout, read=read)
        LOG.debug("stream GET %s", path)
        try:
            async with self._http.stream(
                "GET", self._config.url(path), params=params, headers=headers, timeout=timeout
            ) as response:
                await self._raise_for_status(response)
                yield response
        except httpx.TransportError as exc:
            if follow and isinstance(exc, httpx.ReadTimeout):
                raise c.FollowIdleTimeout from None
            raise self._connection_error(exc) from None

    async def _pages(
        self, path: str, model: type[M], params: Mapping[str, str]
    ) -> AsyncIterator[Page[M]]:
        query = dict(params)
        seen: set[str] = set()
        while True:
            page = c.parse_page(model, await self._request("GET", path, params=query))
            yield page
            cursor = c.next_cursor(page, seen)
            if cursor is None:
                return
            query["cursor"] = cursor

    async def _all(
        self, path: str, model: type[M], extra: Mapping[str, str] | None = None
    ) -> builtins.list[M]:
        params = {"limit": str(c.MAX_PAGE_LIMIT), **(extra or {})}
        return [item async for page in self._pages(path, model, params) for item in page.items]

    async def _blob_exists(self, digest: str) -> bool:
        """``HEAD /v1/blobs/{sha256}``: whether the hub has the blob (a refusal counts as "not
        known": the upload that follows gets the hub's own answer)."""
        headers = self._config.headers()
        try:
            async with self._http.stream(
                "HEAD",
                self._config.url(f"/v1/blobs/{digest}"),
                headers=headers,
                timeout=self._config.timeout,
            ) as response:
                if 400 <= response.status_code < 500:
                    return False
                await self._raise_for_status(response)
                if "content-length" not in response.headers:
                    raise InvalidResponseError("the answer to HEAD /v1/blobs has no Content-Length")
                return True
        except httpx.TransportError as exc:
            raise self._connection_error(exc) from None

    # --- top-level calls -----------------------------------------------------------------
    async def whoami(self) -> WhoAmI:
        """``GET /v1/whoami``: the presented key and its limits (never its secret)."""
        return c.parse_model(WhoAmI, await self._request("GET", "/v1/whoami"))

    async def server(self) -> ServerInfo:
        """``GET /v1/server``: the server's iroh NodeId, relays, address and version."""
        return c.parse_model(ServerInfo, await self._request("GET", "/v1/server"))

    def audit(self, kind: str | None = None, limit: int = 50) -> AsyncGenerator[AuditEvent, None]:
        """``GET /v1/audit`` (admin): lazily iterate the audit log, newest first."""
        return self._audit(c.audit_params(kind, limit))

    async def _audit(self, params: Mapping[str, str]) -> AsyncGenerator[AuditEvent, None]:
        async for page in self._pages("/v1/audit", AuditEvent, params):
            for event in page.items:
                yield event

    async def estimate(
        self,
        image: str,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        files: Sequence[InputFile] | Mapping[str, bytes | str] | None = None,
        cpu: float = 1,
        memory_mb: int = 1024,
        gpu: int = 0,
        disk_mb: int | None = None,
        timeout_s: int | None = None,
        egress: Egress | Sequence[str] | None = None,
        outputs_max_mb: int | None = None,
        placement: Placement | Mapping[str, Any] | None = None,
        max_attempts: int | None = None,
        name: str | None = None,
        inputs: Mapping[str, Blob | str] | Sequence[BlobInput] | None = None,
    ) -> Estimate:
        """``POST /v1/estimate``: would this job fit, and what would it cost in units?"""
        spec = c.build_spec(
            image,
            command,
            env=env,
            files=files,
            cpu=cpu,
            memory_mb=memory_mb,
            gpu=gpu,
            disk_mb=disk_mb,
            timeout_s=timeout_s,
            egress=egress,
            outputs_max_mb=outputs_max_mb,
            placement=placement,
            max_attempts=max_attempts,
            name=name,
            inputs=inputs,
        )
        data = await self._request("POST", "/v1/estimate", json=spec.to_wire())
        return c.parse_model(Estimate, data)

    async def usage(
        self,
        from_: datetime | str | None = None,
        to: datetime | str | None = None,
        group_by: str = "job",
    ) -> UsageReport:
        """``GET /v1/usage``: attempts that ended in ``[from_, to)``, grouped by ``job``, ``node``
        or ``key``, with the total of the range. Every page of groups is followed.

        The server defaults to the current UTC day. Instants are sent as given (a ``datetime``
        without a zone is UTC); the endpoint accepts fractions of a second. Without a range, the
        one the first page reports is sent on every later page, so a call that crosses 00:00 UTC
        still reports a single day. More than 10 000 groups raise
        :class:`~p2pc.InvalidResponseError`: narrow the range or group by something coarser.
        """
        pager = c.UsagePager(from_, to, group_by)
        while True:
            data = await self._request("GET", "/v1/usage", params=pager.query)
            if not pager.add(c.parse_model(UsageReport, data)):
                return pager.report


class AsyncJobsResource:
    def __init__(self, client: AsyncClient) -> None:
        self._c = client

    async def create(
        self,
        image: str,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        files: Sequence[InputFile] | Mapping[str, bytes | str] | None = None,
        cpu: float = 1,
        memory_mb: int = 1024,
        gpu: int = 0,
        disk_mb: int | None = None,
        timeout_s: int | None = None,
        egress: Egress | Sequence[str] | None = None,
        outputs_max_mb: int | None = None,
        placement: Placement | Mapping[str, Any] | None = None,
        max_attempts: int | None = None,
        idempotency_key: str | None = None,
        name: str | None = None,
        inputs: Mapping[str, Blob | str] | Sequence[BlobInput] | None = None,
    ) -> AsyncJob:
        """``POST /v1/jobs``. The arguments are validated against the §7 table first.

        ``inputs`` maps a path under ``/inputs`` to a blob, read-only in the job: a
        :class:`~p2pc.Blob` from ``client.blobs.put`` or a ``"sha256:<hex>"`` string.
        """
        spec = c.build_spec(
            image,
            command,
            env=env,
            files=files,
            cpu=cpu,
            memory_mb=memory_mb,
            gpu=gpu,
            disk_mb=disk_mb,
            timeout_s=timeout_s,
            egress=egress,
            outputs_max_mb=outputs_max_mb,
            placement=placement,
            max_attempts=max_attempts,
            idempotency_key=idempotency_key,
            name=name,
            inputs=inputs,
        )
        return self._job(await self._c._request("POST", "/v1/jobs", json=spec.to_wire()))

    run = create

    async def get(self, id: str) -> AsyncJob:
        return self._job(await self._c._request("GET", f"/v1/jobs/{c.segment(id)}"))

    def list(
        self,
        status: JobStatus | str | None = None,
        node_id: str | None = None,
        limit: int = 50,
    ) -> AsyncGenerator[AsyncJob, None]:
        """Iterate jobs, fetching cursor pages lazily. ``limit`` is the page size (≤ 100)."""
        return self._list(c.jobs_list_params(status, node_id, limit))

    async def _list(self, params: Mapping[str, str]) -> AsyncGenerator[AsyncJob, None]:
        async for page in self._c._pages("/v1/jobs", AsyncJob, params):
            for job in page.items:
                yield job._bind(self._c)

    async def cancel(self, id: str) -> AsyncJob:
        return self._job(await self._c._request("POST", f"/v1/jobs/{c.segment(id)}/cancel"))

    def logs(
        self,
        id: str,
        follow: bool = False,
        since_seq: int = 0,
        attempt: int | None = None,
        *,
        on_outage: Callable[[P2PCError], Awaitable[None] | None] | None = None,
    ) -> AsyncGenerator[LogLine, None]:
        """Iterate the NDJSON log: a page, or with ``follow=True`` the whole log until it ends.

        Logs are per attempt: ``attempt`` is 1-based and defaults to the latest one. ``since_seq``
        is **inclusive** (``seq >= since_seq``): a client resumes with ``last_seq + 1``.

        With ``follow`` the SDK follows the job like the CLI does: a stream the server ends early
        is reopened from ``last_seq + 1`` until the attempt is over, which only a read that
        *began* after the job was final (or a later attempt exists) can tell; a ``404`` or an
        empty page before that is retried after a beat. See
        :meth:`p2pc.client.JobsResource.logs` for the details.

        Transient failures (a broken stream, a connection error, a timeout, ``429``, ``5xx``) are
        retried as there. Outages are tracked per route, the log stream and the job check, and each
        ends only with a success on its own route (for the stream: a line delivered, or 10 s
        open, even if it then breaks); each lasts at most 5 minutes, then
        :class:`~p2pc.P2PCConnectionError` is raised. ``on_outage(error)`` is called once per
        outage, whichever route it is on; it may be a plain function or an ``async def``, which is
        awaited. A working stream that the server cuts is not a failure: the job is checked and
        the stream reopened.

        An outage is timed from the start of its first failed request, and a gap of more than
        30 s between the time a route's next request was due and the time it began (the follow was
        busy with healthy work on the other route) starts a new outage; the wait the SDK
        scheduled is not part of the gap. See :meth:`p2pc.client.JobsResource.logs`.

        To stop early, close the iterator so the connection is released promptly::

            async with contextlib.aclosing(client.jobs.logs(job_id, follow=True)) as logs:
                async for line in logs:
                    ...
        """
        path = f"/v1/jobs/{c.segment(id)}/logs"
        c.logs_params(follow, since_seq, attempt)  # validate eagerly
        if not follow:
            return self._page(path, since_seq, attempt)
        return self._follow(id, path, since_seq, attempt, on_outage)

    async def _page(
        self, path: str, since_seq: int, attempt: int | None
    ) -> AsyncGenerator[LogLine, None]:
        decoder = c.NdjsonDecoder()
        params = c.logs_params(False, since_seq, attempt)
        async with self._c._stream(path, params=params, accept=c.NDJSON) as response:
            async for chunk in response.aiter_bytes():
                for line in decoder.feed(chunk):
                    yield line
        for line in decoder.finish():
            yield line

    async def _follow(
        self,
        id: str,
        path: str,
        since_seq: int,
        attempt: int | None,
        on_outage: Callable[[P2PCError], Awaitable[None] | None] | None,
    ) -> AsyncGenerator[LogLine, None]:
        follower = c.LogFollower(since_seq, attempt)
        # Outages are tracked per route, each ending only with a success on its own route.
        logs_outage = c.Outage(self._c._monotonic, id, "log stream", on_outage)
        job_outage = c.Outage(self._c._monotonic, id, "job check", on_outage)
        job = await self._first_check(id, job_outage)
        while True:
            read = follower.next_read(job)
            if read is not None:
                read_started = self._c._monotonic()
                try:
                    # `async for` does not pass `aclose()` on: close the read here, so a caller
                    # that stops early releases the HTTP stream at once, not when the finalizer
                    # runs.
                    async with aclosing(self._read(path, read, follower, logs_outage)) as lines:
                        async for line in lines:
                            yield line
                except P2PCError as exc:
                    if not c.is_transient(exc):
                        raise
                    # Reopen from the next seq (the follower knows it) once the wait is over.
                    await self._wait_out(logs_outage, exc, read_started)
                    continue
            check_started = self._c._monotonic()
            try:
                job = await self.get(id)
            except P2PCError as exc:
                if not c.is_transient(exc):
                    raise
                # Back to the top, as the CLI does: the logs are read while the job route is down.
                await self._wait_out(job_outage, exc, check_started)
                continue
            job_outage.over()
            finished, wait = follower.after(job)
            if finished:
                return
            if wait:
                await self._c._sleep(wait)

    async def _wait_out(self, outage: c.Outage, error: P2PCError, request_started: float) -> None:
        """Record a transient failure of a request sent at ``request_started`` on its route and
        sleep as long as its outage says. An ``async def`` ``on_outage`` is awaited here, once
        per outage."""
        wait = outage.failed(error, request_started)
        announced = outage.announced()
        if inspect.isawaitable(announced):
            await announced
        await self._c._sleep(wait)

    async def _first_check(self, id: str, outage: c.Outage) -> AsyncJob:
        """The first ``get``, retried in place while it fails transiently: until the job is
        known there is nothing to read."""
        while True:
            started = self._c._monotonic()
            try:
                job = await self.get(id)
            except P2PCError as exc:
                if not c.is_transient(exc):
                    raise
                await self._wait_out(outage, exc, started)
                continue
            outage.over()
            return job

    async def _read(
        self, path: str, read: c.LogRead, follower: c.LogFollower, outage: c.Outage
    ) -> AsyncGenerator[LogLine, None]:
        """One followed read: its lines go to the caller, and how it ended to ``follower``.

        A stream that was working (it delivered a line, or stayed open for ``STREAM_STABLE_AFTER``
        seconds) is a success of the log route, even if it then breaks: ``outage`` (the log
        route's) ends, and the break is an incomplete end, like an idle timeout: the server cut
        it and the job decides what next. Only a stream that fails to open, or breaks straight
        away, raises, and is counted as a failure of the log route by the caller.
        """
        decoder = c.NdjsonDecoder()
        params = c.logs_params(True, read.since_seq, read.attempt)
        opened_at: float | None = None
        delivered = False

        def working() -> bool:
            if delivered:
                return True
            return opened_at is not None and (
                self._c._monotonic() - opened_at >= c.STREAM_STABLE_AFTER
            )

        try:
            async with self._c._stream(
                path, params=params, accept=c.NDJSON, follow=True
            ) as response:
                opened_at = self._c._monotonic()
                async for chunk in response.aiter_bytes():
                    for line in decoder.feed(chunk):
                        if follower.accept(line):
                            delivered = True
                            outage.over()
                            yield line
        except c.FollowIdleTimeout:
            if opened_at is None:
                # No headers within ``follow_idle_timeout``: a log route that hangs. Counted as a
                # failure, or a hung endpoint would be retried for ever.
                raise P2PCConnectionError(
                    "the log stream sent no response within the follow idle timeout"
                ) from None
            if working():
                outage.over()
            follower.ended(read, complete=False)
            return
        except P2PCConnectionError:
            if not working():
                raise
            outage.over()
            follower.ended(read, complete=False)
            return
        except NotFoundError as exc:
            if exc.status != 404:
                raise
            outage.over()  # an answer from a working log route, whatever it says about the log
            follower.missing(read, exc)
            return
        outage.over()  # the server ended the body: the route worked
        for line in decoder.finish():
            if follower.accept(line):
                yield line
        follower.ended(read)

    async def wait(
        self,
        id: str,
        timeout: float | None = None,
        poll_interval: float = 2.0,
    ) -> AsyncJob:
        """Poll until the job is terminal. Raises :class:`TimeoutError` after ``timeout`` s."""
        c.check_wait_args(poll_interval, timeout)
        deadline = None if timeout is None else self._c._monotonic() + timeout
        while True:
            job = await self.get(id)
            if job.is_terminal:
                return job
            if deadline is None:
                await self._c._sleep(poll_interval)
                continue
            remaining = deadline - self._c._monotonic()
            if remaining <= 0:
                raise TimeoutError(c.timeout_message(id, timeout, job.status.value))
            await self._c._sleep(min(poll_interval, remaining))

    async def outputs(self, id: str, attempt: int | None = None) -> builtins.list[OutputFile]:
        """The output files of the latest attempt, or of ``attempt``."""
        return await self._c._all(
            f"/v1/jobs/{c.segment(id)}/outputs", OutputFile, c.attempt_params(attempt)
        )

    async def download_output(
        self,
        id: str,
        path: str,
        dest: str | Path,
        *,
        max_bytes: int | None = None,
        attempt: int | None = None,
    ) -> Path:
        """Stream ``path`` into the directory ``dest`` and verify it against the listing.

        Same guarantees as :meth:`p2pc.client.JobsResource.download_output`: the listing must
        announce a valid sha256 and size, a file over the cap (``max_bytes``, 1 GiB by default, at
        most 10 240 MiB) is refused,
        and a failed download leaves nothing behind (including the directories it created, if
        still empty). File I/O runs in worker threads so the event loop is never blocked.

        Cancelling it (for example with ``asyncio.timeout``) is safe at every step: the
        cancellation is delivered once the worker thread that is running has finished, and then
        the temporary file, the new directories and, if the rename had already happened, the
        new file are removed. A file that existed before the download is never deleted.
        """
        cap = c.check_max_bytes(max_bytes)
        params = c.attempt_params(attempt)
        root, target = await asyncio.to_thread(c.safe_output_target, dest, path)
        expected = c.find_output(await self.outputs(id, attempt), path, cap)
        writer = c.DownloadWriter(root, target, expected, cap)  # no I/O: cannot half-succeed
        try:
            await _in_thread(writer.open)
            async with self._c._stream(c.output_url_path(id, path), params=params) as response:
                writer.check_header(response.headers)
                async for chunk in response.aiter_bytes():
                    await _in_thread(writer.write, chunk)
            return await _in_thread(writer.commit)
        except BaseException:
            writer.abort()
            raise

    def _job(self, data: Any) -> AsyncJob:
        if data is None:
            raise InvalidResponseError("the server returned an empty body, expected a job")
        return c.parse_model(AsyncJob, data)._bind(self._c)


class AsyncNodesResource:
    def __init__(self, client: AsyncClient) -> None:
        self._c = client

    async def list(self, state: str | None = None) -> builtins.list[Node]:
        """``GET /v1/nodes`` (nodes:read). ``state`` is ``online`` (draining nodes included) or
        ``offline``; the server answers ``400`` for anything else."""
        return await self._c._all("/v1/nodes", Node, c.nodes_params(state, c.MAX_PAGE_LIMIT))

    async def get(self, id: str) -> Node:
        return c.parse_model(Node, await self._c._request("GET", f"/v1/nodes/{c.segment(id)}"))

    async def drain(self, id: str) -> Node:
        """Stop giving the node new leases (nodes:write). Idempotent; returns the node."""
        return await self._action(f"/v1/nodes/{c.segment(id)}/drain")

    async def resume(self, id: str) -> Node:
        """Let a draining node take leases again (nodes:write). Returns the node."""
        return await self._action(f"/v1/nodes/{c.segment(id)}/resume")

    async def delete(self, id: str) -> None:
        await self._c._request("DELETE", f"/v1/nodes/{c.segment(id)}")

    async def _action(self, path: str) -> Node:
        data = await self._c._request("POST", path)
        if data is None:
            raise InvalidResponseError("the server returned an empty body, expected a node")
        return c.parse_model(Node, data)


class AsyncJoinTokensResource:
    def __init__(self, client: AsyncClient) -> None:
        self._c = client

    async def create(self, ttl_s: int | None = None, *, label: str | None = None) -> JoinToken:
        """``POST /v1/nodes/join-tokens`` (admin). The token is single-use."""
        body = c.join_token_body(ttl_s, label)
        data = await self._c._request("POST", "/v1/nodes/join-tokens", json=body)
        return c.parse_model(JoinToken, data)

    async def list(self) -> builtins.list[JoinTokenInfo]:
        """``GET /v1/nodes/join-tokens`` (admin): metadata only, never the tokens."""
        return await self._c._all("/v1/nodes/join-tokens", JoinTokenInfo)

    async def revoke(self, id: str) -> None:
        """``DELETE /v1/nodes/join-tokens/{id}`` (admin): revoke an unused token. Idempotent.

        A token that a node already used is ``409 token_consumed`` (:class:`~p2pc.ConflictError`):
        delete the node instead.
        """
        await self._c._request("DELETE", f"/v1/nodes/join-tokens/{c.segment(id)}")


class AsyncKeysResource:
    def __init__(self, client: AsyncClient) -> None:
        self._c = client

    async def create(
        self,
        scopes: Sequence[str],
        daily_unit_cap: int | None = None,
        allowed_images: Sequence[str] | None = None,
        *,
        label: str | None = None,
        expires_at: datetime | str | None = None,
    ) -> NewApiKey:
        """``POST /v1/keys`` (admin). ``key`` is returned once: store it now.

        ``daily_unit_cap`` is in milli-units (1 unit = 1,000). A key cannot be given more power
        than the key that creates it (``403 escalation_denied``).
        """
        body = c.key_body(scopes, daily_unit_cap, allowed_images, label, expires_at)
        return c.parse_model(NewApiKey, await self._c._request("POST", "/v1/keys", json=body))

    async def list(self) -> builtins.list[ApiKey]:
        return await self._c._all("/v1/keys", ApiKey)

    async def revoke(self, id: str) -> None:
        """``DELETE /v1/keys/{id}`` (admin): sets ``revoked_at``; the row is never deleted.

        Idempotent. The account's last unrestricted admin key cannot be revoked (``409``).
        """
        await self._c._request("DELETE", f"/v1/keys/{c.segment(id)}")

    delete = revoke


class AsyncBlobsResource:
    def __init__(self, client: AsyncClient) -> None:
        self._c = client

    async def put(self, path: str | os.PathLike[str]) -> Blob:
        """Upload the file at ``path`` as a blob; see :meth:`p2pc.Client.blobs`.

        The file must be a regular file and is opened once: the SHA-256 and the upload read the
        same descriptor. A blob the hub already has is not sent again (``uploaded=False``).
        """
        measured = await _in_thread(h2.measure_file, path)
        try:
            if await self._c._blob_exists(measured.digest):
                return Blob(sha256=measured.digest, size=measured.size, uploaded=False)
            data = await self._c._request(
                "POST",
                "/v1/blobs",
                content=h2.aupload_chunks(measured.handle, measured.size),
                extra_headers={
                    "Content-Length": str(measured.size),
                    "Content-Type": "application/octet-stream",
                    "X-P2PC-SHA256": measured.digest,
                },
            )
        finally:
            await _in_thread(measured.close)
        blob = c.parse_model(Blob, data)
        if blob.sha256 != measured.digest:
            raise InvalidResponseError("the hub stored a blob with another digest than the file's")
        return blob.model_copy(update={"uploaded": True})


class AsyncServicesResource:
    def __init__(self, client: AsyncClient) -> None:
        self._c = client

    async def run(
        self,
        image: str,
        command: Sequence[str],
        *,
        ports: Sequence[int | tuple[int, str] | ServicePort],
        health_http: str | None = None,
        health_tcp: bool = False,
        idle_timeout_s: int | c._Unset | None = c.UNSET,
        restart: str | None = None,
        volumes: Sequence[VolumeSpec | Mapping[str, Any]] | None = None,
        env: Mapping[str, str] | None = None,
        files: Sequence[InputFile] | Mapping[str, bytes | str] | None = None,
        inputs: Mapping[str, Blob | str] | Sequence[BlobInput] | None = None,
        cpu: float = 1,
        memory_mb: int = 1024,
        gpu: int = 0,
        disk_mb: int | None = None,
        timeout_s: int | None = None,
        egress: Egress | Sequence[str] | None = None,
        placement: Placement | Mapping[str, Any] | None = None,
        max_attempts: int | None = None,
        idempotency_key: str | None = None,
        name: str | None = None,
    ) -> AsyncJob:
        """Start a long-lived service (``kind="service"``); see :meth:`p2pc.Client.services`."""
        spec = c.build_spec(
            image,
            command,
            env=env,
            files=files,
            cpu=cpu,
            memory_mb=memory_mb,
            gpu=gpu,
            disk_mb=disk_mb,
            timeout_s=timeout_s,
            egress=egress,
            placement=placement,
            max_attempts=max_attempts,
            idempotency_key=idempotency_key,
            name=name,
            inputs=inputs,
            kind="service",
            service=c.build_service(
                ports,
                health_http=health_http,
                health_tcp=health_tcp,
                idle_timeout_s=idle_timeout_s,
                restart=restart,
            ),
            volumes=[VolumeSpec.model_validate(v) if isinstance(v, Mapping) else v for v in volumes]
            if volumes is not None
            else None,
        )
        return self._c.jobs._job(await self._c._request("POST", "/v1/jobs", json=spec.to_wire()))

    def connect(
        self, job: AsyncJob | str, port: int, *, wait_ready: bool = True
    ) -> AsyncPortForwarder:
        """A local loopback port that forwards to ``port`` of the service ``job``.

        ``async with client.services.connect(job, 11434) as local_port:``; see
        :meth:`p2pc.Client.services` for the rules (loopback only, at most 16 connections).
        """
        job_id = job if isinstance(job, str) else job.id
        c.segment(job_id, "job id")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise ValueError("port must be an integer between 1 and 65535")
        return AsyncPortForwarder(self._c._config, job_id, port, wait_ready=wait_ready)


class AsyncTemplatesResource:
    def __init__(self, client: AsyncClient) -> None:
        self._c = client

    async def list(self) -> TemplateList:
        """``GET /v1/templates``: the served template bundle (iterate it for the templates)."""
        return c.parse_model(TemplateList, await self._c._request("GET", "/v1/templates"))

    async def launch(
        self,
        id: str,
        params: Mapping[str, bool | int | str] | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> AsyncJob:
        """``POST /v1/templates/{id}/launch``: start a template with ``params``."""
        body = c.launch_body(params, idempotency_key)
        return self._c.jobs._job(
            await self._c._request(
                "POST", f"/v1/templates/{c.segment(id, 'template id')}/launch", json=body
            )
        )
