# SPDX-License-Identifier: Apache-2.0
"""Synchronous client."""

from __future__ import annotations

import builtins
import inspect
import logging
import os
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Self, TypeVar

import httpx
from pydantic import BaseModel

from p2pc import _common as c
from p2pc import h2
from p2pc._ports import PortForwarder
from p2pc.errors import InvalidResponseError, NotFoundError, P2PCConnectionError, P2PCError
from p2pc.h2 import Blob, TemplateList
from p2pc.models import (
    ApiKey,
    AuditEvent,
    BlobInput,
    Egress,
    Estimate,
    InputFile,
    Job,
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

__all__ = ["Client"]

LOG = logging.getLogger("p2pc")
M = TypeVar("M", bound=BaseModel)


class Client:
    """Client for the P2PC Jobs API.

    ``api_url`` defaults to ``$P2PC_API_URL`` or ``http://127.0.0.1:7477``. ``api_key``
    defaults to ``$P2PC_API_KEY``; a missing key is reported at the first call, not here.
    Pass ``http_client`` to control transport details (proxies, TLS, mock transports); it is
    never closed by the SDK. ``follow_idle_timeout`` bounds how long a followed log stream may
    stay silent before the SDK reconnects (``timeout`` applies to everything else).
    """

    def __init__(
        self,
        api_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 30.0,
        http_client: httpx.Client | None = None,
        *,
        follow_idle_timeout: float = c.DEFAULT_FOLLOW_IDLE_TIMEOUT,
    ) -> None:
        self._config = c.Config.resolve(api_url, api_key, timeout, follow_idle_timeout)
        self._config.warn_if_cleartext()
        self._owns_http = http_client is None
        self._http = http_client if http_client is not None else httpx.Client()
        # Injectable for tests: no real sleeping is needed to exercise `wait`.
        self._sleep: Callable[[float], None] = time.sleep
        self._monotonic: Callable[[], float] = time.monotonic
        self.jobs = JobsResource(self)
        self.nodes = NodesResource(self)
        self.join_tokens = JoinTokensResource(self)
        self.keys = KeysResource(self)
        self.blobs = BlobsResource(self)
        self.services = ServicesResource(self)
        self.templates = TemplatesResource(self)

    def __repr__(self) -> str:
        return self._config.client_repr("Client")

    __str__ = __repr__

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # --- transport ---------------------------------------------------------------------
    def _connection_error(self, exc: httpx.TransportError) -> P2PCConnectionError:
        detail = c.redact(f"{type(exc).__name__}: {exc}", self._config.api_key)
        return P2PCConnectionError(f"could not reach {self._config.safe_url}: {detail}")

    def _raise_for_status(self, response: httpx.Response) -> None:
        """Raise the mapped error for a non-2xx response, reading at most 64 KiB of its body."""
        LOG.debug("response status=%d", response.status_code)
        if response.status_code >= 300:
            body = c.ErrorBody()
            for chunk in response.iter_bytes():
                if body.add(chunk):
                    break
            raise c.error_from_response(response, self._config.api_key, body.value())

    def _request(
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
            with self._http.stream(
                method,
                self._config.url(path),
                params=params,
                json=json,
                content=content,
                headers=headers,
                timeout=self._config.timeout,
            ) as response:
                self._raise_for_status(response)
                for chunk in response.iter_bytes():
                    body.add(chunk)
        except httpx.TransportError as exc:
            raise self._connection_error(exc) from None
        return c.parse_json(body.value())

    @contextmanager
    def _stream(
        self,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        accept: str = "application/octet-stream",
        follow: bool = False,
    ) -> Iterator[httpx.Response]:
        headers = self._config.headers(accept)
        # A followed log stream may be silent for a while: it gets its own, longer read timeout.
        read = self._config.follow_idle_timeout if follow else self._config.timeout
        timeout = httpx.Timeout(self._config.timeout, read=read)
        LOG.debug("stream GET %s", path)
        try:
            with self._http.stream(
                "GET", self._config.url(path), params=params, headers=headers, timeout=timeout
            ) as response:
                self._raise_for_status(response)
                yield response
        except httpx.TransportError as exc:
            if follow and isinstance(exc, httpx.ReadTimeout):
                raise c.FollowIdleTimeout from None
            raise self._connection_error(exc) from None

    def _pages(self, path: str, model: type[M], params: Mapping[str, str]) -> Iterator[Page[M]]:
        query = dict(params)
        seen: set[str] = set()
        while True:
            page = c.parse_page(model, self._request("GET", path, params=query))
            yield page
            cursor = c.next_cursor(page, seen)
            if cursor is None:
                return
            query["cursor"] = cursor

    def _all(
        self, path: str, model: type[M], extra: Mapping[str, str] | None = None
    ) -> builtins.list[M]:
        params = {"limit": str(c.MAX_PAGE_LIMIT), **(extra or {})}
        return [item for page in self._pages(path, model, params) for item in page.items]

    def _blob_exists(self, digest: str) -> bool:
        """``HEAD /v1/blobs/{sha256}``: whether the hub has the blob.

        A ``HEAD`` answer has no body, so a refusal there (``401``, ``403``) carries no reason:
        it counts as "not known" and the upload that follows gets the hub's own answer.
        """
        headers = self._config.headers()
        try:
            with self._http.stream(
                "HEAD",
                self._config.url(f"/v1/blobs/{digest}"),
                headers=headers,
                timeout=self._config.timeout,
            ) as response:
                if 400 <= response.status_code < 500:
                    return False
                self._raise_for_status(response)
                if "content-length" not in response.headers:
                    raise InvalidResponseError("the answer to HEAD /v1/blobs has no Content-Length")
                return True
        except httpx.TransportError as exc:
            raise self._connection_error(exc) from None

    # --- top-level calls -----------------------------------------------------------------
    def whoami(self) -> WhoAmI:
        """``GET /v1/whoami``: the presented key and its limits (never its secret)."""
        return c.parse_model(WhoAmI, self._request("GET", "/v1/whoami"))

    def server(self) -> ServerInfo:
        """``GET /v1/server``: the server's iroh NodeId, relays, address and version."""
        return c.parse_model(ServerInfo, self._request("GET", "/v1/server"))

    def audit(self, kind: str | None = None, limit: int = 50) -> Iterator[AuditEvent]:
        """``GET /v1/audit`` (admin): lazily iterate the audit log, newest first."""
        params = c.audit_params(kind, limit)
        return (e for page in self._pages("/v1/audit", AuditEvent, params) for e in page.items)

    def estimate(
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
        return c.parse_model(Estimate, self._request("POST", "/v1/estimate", json=spec.to_wire()))

    def usage(
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
            page = c.parse_model(UsageReport, self._request("GET", "/v1/usage", params=pager.query))
            if not pager.add(page):
                return pager.report


class JobsResource:
    def __init__(self, client: Client) -> None:
        self._c = client

    def create(
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
    ) -> Job:
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
        return self._job(self._c._request("POST", "/v1/jobs", json=spec.to_wire()))

    run = create

    def get(self, id: str) -> Job:
        return self._job(self._c._request("GET", f"/v1/jobs/{c.segment(id)}"))

    def list(
        self,
        status: JobStatus | str | None = None,
        node_id: str | None = None,
        limit: int = 50,
    ) -> Iterator[Job]:
        """Iterate jobs, fetching cursor pages lazily. ``limit`` is the page size (≤ 100)."""
        params = c.jobs_list_params(status, node_id, limit)
        return (
            job._bind(self._c)
            for page in self._c._pages("/v1/jobs", Job, params)
            for job in page.items
        )

    def cancel(self, id: str) -> Job:
        return self._job(self._c._request("POST", f"/v1/jobs/{c.segment(id)}/cancel"))

    def logs(
        self,
        id: str,
        follow: bool = False,
        since_seq: int = 0,
        attempt: int | None = None,
        *,
        on_outage: Callable[[P2PCError], None] | None = None,
    ) -> Iterator[LogLine]:
        """Iterate the NDJSON log: a page, or with ``follow=True`` the whole log until it ends.

        Logs are per attempt: ``attempt`` is 1-based and defaults to the latest one. ``since_seq``
        is **inclusive**: the stream starts at the first chunk with ``seq >= since_seq``, so a
        client resumes with ``last_seq + 1``, which is what a reconnect does here.

        Without ``follow`` it is one read of what is stored now. With it the SDK follows the job
        like the CLI does: a stream the server ends early (it does so after 60 s without a new
        line, or on an internal error) is reopened from ``last_seq + 1`` until the attempt is
        over, which only a read that *began* after the job was final (or a later attempt exists)
        can tell. A ``404`` or an empty page before that is retried after a beat. Without
        ``attempt`` it goes on to the next attempt when the job is requeued (``seq`` starts
        again at 0); with it, only that attempt is followed, and a missing log is a
        :class:`~p2pc.NotFoundError` once it is over.

        A transient failure does not end a follow, on the stream or on the job checks: a broken
        stream, a connection error, a timeout, ``429`` and ``5xx``. The SDK waits (1 s, doubling
        to 30 s, or the ``Retry-After`` the server sends) and reopens from the next ``seq``.

        Outages are tracked **per route**, the log stream and the job check, and each ends only
        with a success on its own route: a stream that delivered a line or stayed open for 10 s
        (even if it then breaks, as at the server's 60 s idle cut) for the log route, a
        successful ``GET /v1/jobs/{id}`` for the job route. A stream that fails to open or breaks
        at once is a failure. Each outage may last 5 minutes from its first failure; then
        :class:`~p2pc.P2PCConnectionError` is raised. So a job route that keeps failing gives up
        while logs flow, and a long healthy stream leaves no stale outage behind. A working
        stream that is cut is not a failure: the job is checked and the stream reopened, however
        many times that happens. A ``404`` from the log route is an answer, so it ends the log
        route's outage; a timeout before the response headers is a failure of it, one after the
        headers of a working body is not. A failed job check is recorded and the logs are read
        again before the next check, so lines flow while the job route is down. ``401``,
        ``403``, ``404`` on the job and ``422`` end the follow at once.
        ``on_outage(error)``, if given, is called once per outage, whichever route it is on,
        with its first error (the SDK never prints; it also logs it to ``p2pc`` at INFO). It must
        be a plain function: an ``async def`` would only make a coroutine that nobody awaits, so
        it raises :class:`TypeError` (use :class:`~p2pc.AsyncClient` for an async callback).

        An outage is a run of failures of one route: it is timed from the **start** of its first
        failed request, has no success on that route, and no gap longer than 30 s (the longest
        wait) between the time one of its requests was due and the time it began. A longer gap
        means the follow was busy with healthy work on the other route (a long stream): the next
        failure starts a **new** outage, announced again. The wait the SDK scheduled is not part
        of a gap. So one failed job check before a 6-minute stream and one after it are two short
        outages, not one that gave up.
        """
        if on_outage is not None and inspect.iscoroutinefunction(on_outage):
            raise TypeError(
                "on_outage is an async function, which the sync Client would never await: "
                "pass a plain function, or use AsyncClient"
            )
        path = f"/v1/jobs/{c.segment(id)}/logs"
        c.logs_params(follow, since_seq, attempt)  # validate eagerly
        if not follow:
            return self._page(path, since_seq, attempt)
        return self._follow(id, path, since_seq, attempt, on_outage)

    def _page(self, path: str, since_seq: int, attempt: int | None) -> Iterator[LogLine]:
        decoder = c.NdjsonDecoder()
        params = c.logs_params(False, since_seq, attempt)
        with self._c._stream(path, params=params, accept=c.NDJSON) as response:
            for chunk in response.iter_bytes():
                yield from decoder.feed(chunk)
        yield from decoder.finish()

    def _follow(
        self,
        id: str,
        path: str,
        since_seq: int,
        attempt: int | None,
        on_outage: Callable[[P2PCError], None] | None,
    ) -> Iterator[LogLine]:
        follower = c.LogFollower(since_seq, attempt)
        # Outages are tracked per route, each ending only with a success on its own route.
        logs_outage = c.Outage(self._c._monotonic, id, "log stream", on_outage)
        job_outage = c.Outage(self._c._monotonic, id, "job check", on_outage)
        job = self._first_check(id, job_outage)
        while True:
            read = follower.next_read(job)
            if read is not None:
                read_started = self._c._monotonic()
                try:
                    yield from self._read(path, read, follower, logs_outage)
                except P2PCError as exc:
                    if not c.is_transient(exc):
                        raise
                    # Reopen from the next seq (the follower knows it) once the wait is over.
                    self._c._sleep(logs_outage.failed(exc, read_started))
                    continue
            check_started = self._c._monotonic()
            try:
                job = self.get(id)
            except P2PCError as exc:
                if not c.is_transient(exc):
                    raise
                # Back to the top, as the CLI does: the logs are read while the job route is down.
                self._c._sleep(job_outage.failed(exc, check_started))
                continue
            job_outage.over()
            finished, wait = follower.after(job)
            if finished:
                return
            if wait:
                self._c._sleep(wait)

    def _first_check(self, id: str, outage: c.Outage) -> Job:
        """The first ``get``, retried in place while it fails transiently: until the job is
        known there is nothing to read."""
        while True:
            started = self._c._monotonic()
            try:
                job = self.get(id)
            except P2PCError as exc:
                if not c.is_transient(exc):
                    raise
                self._c._sleep(outage.failed(exc, started))
                continue
            outage.over()
            return job

    def _read(
        self, path: str, read: c.LogRead, follower: c.LogFollower, outage: c.Outage
    ) -> Iterator[LogLine]:
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
            with self._c._stream(path, params=params, accept=c.NDJSON, follow=True) as response:
                opened_at = self._c._monotonic()
                for chunk in response.iter_bytes():
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

    def wait(
        self,
        id: str,
        timeout: float | None = None,
        poll_interval: float = 2.0,
    ) -> Job:
        """Poll until the job is terminal. Raises :class:`TimeoutError` after ``timeout`` s."""
        c.check_wait_args(poll_interval, timeout)
        deadline = None if timeout is None else self._c._monotonic() + timeout
        while True:
            job = self.get(id)
            if job.is_terminal:
                return job
            if deadline is None:
                self._c._sleep(poll_interval)
                continue
            remaining = deadline - self._c._monotonic()
            if remaining <= 0:
                raise TimeoutError(c.timeout_message(id, timeout, job.status.value))
            self._c._sleep(min(poll_interval, remaining))

    def outputs(self, id: str, attempt: int | None = None) -> builtins.list[OutputFile]:
        """The output files of the latest attempt, or of ``attempt``. Entries have ``expired``
        set after the server's retention period."""
        return self._c._all(
            f"/v1/jobs/{c.segment(id)}/outputs", OutputFile, c.attempt_params(attempt)
        )

    def download_output(
        self,
        id: str,
        path: str,
        dest: str | Path,
        *,
        max_bytes: int | None = None,
        attempt: int | None = None,
    ) -> Path:
        """Stream ``path`` into the directory ``dest`` and verify it against the listing.

        The listing must announce both ``size`` and ``sha256``. A file larger than the cap is
        refused before any byte is fetched, and a download that delivers more bytes than
        announced stops at the first excess chunk. The cap is ``max_bytes`` if you pass it (at
        most 10 240 MiB, the server's largest ``outputs.max_mb``) and 1 GiB otherwise;
        ``Job.download_output`` passes the job's own ``outputs.max_mb`` instead, even above 1 GiB.

        The file is written to ``dest/path`` through a temporary file, so a failed or
        tampered download never leaves a partial result, and a failed download also removes
        the directories it created (if still empty). Paths that would escape ``dest`` raise
        :class:`~p2pc.UnsafePathError` before any request is made. A listing without a valid
        sha256 or size raises :class:`~p2pc.InvalidResponseError`; an entry the server has
        garbage-collected (``expired``) raises :class:`~p2pc.NotFoundError` with the code
        ``output_expired``. ``attempt`` selects the attempt of the listing and the file.
        """
        cap = c.check_max_bytes(max_bytes)
        params = c.attempt_params(attempt)
        root, target = c.safe_output_target(dest, path)
        expected = c.find_output(self.outputs(id, attempt), path, cap)
        writer = c.DownloadWriter(root, target, expected, cap)
        try:
            writer.open()
            with self._c._stream(c.output_url_path(id, path), params=params) as response:
                writer.check_header(response.headers)
                for chunk in response.iter_bytes():
                    writer.write(chunk)
            return writer.commit()
        except BaseException:
            writer.abort()
            raise

    def _job(self, data: Any) -> Job:
        if data is None:
            raise InvalidResponseError("the server returned an empty body, expected a job")
        return c.parse_model(Job, data)._bind(self._c)


class NodesResource:
    def __init__(self, client: Client) -> None:
        self._c = client

    def list(self, state: str | None = None) -> builtins.list[Node]:
        """``GET /v1/nodes`` (nodes:read). ``state`` is ``online`` (draining nodes included) or
        ``offline``; the server answers ``400`` for anything else."""
        return self._c._all("/v1/nodes", Node, c.nodes_params(state, c.MAX_PAGE_LIMIT))

    def get(self, id: str) -> Node:
        return c.parse_model(Node, self._c._request("GET", f"/v1/nodes/{c.segment(id)}"))

    def drain(self, id: str) -> Node:
        """Stop giving the node new leases (nodes:write). Idempotent; returns the node."""
        return self._action(f"/v1/nodes/{c.segment(id)}/drain")

    def resume(self, id: str) -> Node:
        """Let a draining node take leases again (nodes:write). Returns the node."""
        return self._action(f"/v1/nodes/{c.segment(id)}/resume")

    def delete(self, id: str) -> None:
        """Delete the node and close its connection (nodes:write). It must join again."""
        self._c._request("DELETE", f"/v1/nodes/{c.segment(id)}")

    def _action(self, path: str) -> Node:
        data = self._c._request("POST", path)
        if data is None:
            raise InvalidResponseError("the server returned an empty body, expected a node")
        return c.parse_model(Node, data)


class JoinTokensResource:
    def __init__(self, client: Client) -> None:
        self._c = client

    def create(self, ttl_s: int | None = None, *, label: str | None = None) -> JoinToken:
        """``POST /v1/nodes/join-tokens`` (admin). The token is single-use."""
        body = c.join_token_body(ttl_s, label)
        return c.parse_model(
            JoinToken, self._c._request("POST", "/v1/nodes/join-tokens", json=body)
        )

    def list(self) -> builtins.list[JoinTokenInfo]:
        """``GET /v1/nodes/join-tokens`` (admin): metadata only, never the tokens."""
        return self._c._all("/v1/nodes/join-tokens", JoinTokenInfo)

    def revoke(self, id: str) -> None:
        """``DELETE /v1/nodes/join-tokens/{id}`` (admin): revoke an unused token. Idempotent.

        A token that a node already used is ``409 token_consumed`` (:class:`~p2pc.ConflictError`):
        delete the node instead.
        """
        self._c._request("DELETE", f"/v1/nodes/join-tokens/{c.segment(id)}")


class KeysResource:
    def __init__(self, client: Client) -> None:
        self._c = client

    def create(
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
        return c.parse_model(NewApiKey, self._c._request("POST", "/v1/keys", json=body))

    def list(self) -> builtins.list[ApiKey]:
        return self._c._all("/v1/keys", ApiKey)

    def revoke(self, id: str) -> None:
        """``DELETE /v1/keys/{id}`` (admin): sets ``revoked_at``; the row is never deleted.

        Idempotent. The account's last unrestricted admin key cannot be revoked (``409``).
        """
        self._c._request("DELETE", f"/v1/keys/{c.segment(id)}")

    delete = revoke


class BlobsResource:
    def __init__(self, client: Client) -> None:
        self._c = client

    def put(self, path: str | os.PathLike[str]) -> Blob:
        """Upload the file at ``path`` as a blob (spec §7.5) and return it.

        The file must be a regular file. It is opened once: the SHA-256 and the upload read the
        same descriptor, so a file that changes meanwhile fails instead of uploading other bytes.
        The hub is asked first (``HEAD``): a blob it already has is not sent again
        (``uploaded=False``). Use ``jobs.run(..., inputs={"/inputs/x": blob})`` to give it to a job.
        The hub keeps a blob for 24 hours after its last use.
        """
        measured = h2.measure_file(path)
        try:
            if self._c._blob_exists(measured.digest):
                return Blob(sha256=measured.digest, size=measured.size, uploaded=False)
            data = self._c._request(
                "POST",
                "/v1/blobs",
                content=h2.upload_chunks(measured.handle, measured.size),
                extra_headers={
                    "Content-Length": str(measured.size),
                    "Content-Type": "application/octet-stream",
                    "X-P2PC-SHA256": measured.digest,
                },
            )
        finally:
            measured.close()
        blob = c.parse_model(Blob, data)
        if blob.sha256 != measured.digest:
            raise InvalidResponseError("the hub stored a blob with another digest than the file's")
        return blob.model_copy(update={"uploaded": True})


class ServicesResource:
    def __init__(self, client: Client) -> None:
        self._c = client

    def run(
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
    ) -> Job:
        """``POST /v1/jobs`` with ``kind="service"`` (spec §7.1, §7.2): start a long-lived service.

        ``ports`` lists the ports it listens on (a number, a ``(number, name)`` pair or a
        :class:`~p2pc.ServicePort`). ``health_http`` (a path) or ``health_tcp`` checks the first
        port. ``idle_timeout_s`` is 300-604800 seconds, ``None`` for never (leave it out for the
        server's default, 3600). ``restart`` is ``"never"`` or ``"on_node_loss"`` (the default).
        ``timeout_s`` is 60-2592000 and defaults to the 30-day maximum. Reach it with
        :meth:`connect`; stop it with ``jobs.cancel(job.id)``.
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
        return self._c.jobs._job(self._c._request("POST", "/v1/jobs", json=spec.to_wire()))

    def connect(self, job: Job | str, port: int, *, wait_ready: bool = True) -> PortForwarder:
        """A local port that forwards to ``port`` of the service ``job`` (spec §7.4).

        Use it as a context manager: ``with client.services.connect(job, 11434) as local_port:``.
        It listens on ``127.0.0.1:<local_port>`` (loopback only) and opens one upgraded
        connection to the hub per local connection; at most 16 are open at once. With
        ``wait_ready`` (the default) the hub waits up to 30 s for a service that is still
        ``starting``. When an upgrade is refused (``service_not_running``, ``port_not_exposed``
        …) that local connection is closed and the error is kept in ``.last_error`` of the
        returned object. The block ends the listener and every open connection.
        """
        job_id = job if isinstance(job, str) else job.id
        c.segment(job_id, "job id")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise ValueError("port must be an integer between 1 and 65535")
        return PortForwarder(self._c._config, job_id, port, wait_ready=wait_ready)


class TemplatesResource:
    def __init__(self, client: Client) -> None:
        self._c = client

    def list(self) -> TemplateList:
        """``GET /v1/templates`` (spec §7.6): the served template bundle.

        Iterate it for the templates; ``bundle_error`` says why it is empty when no bundle can be
        loaded.
        """
        return c.parse_model(TemplateList, self._c._request("GET", "/v1/templates"))

    def launch(
        self,
        id: str,
        params: Mapping[str, bool | int | str] | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> Job:
        """``POST /v1/templates/{id}/launch`` (spec §7.6): start a template with ``params``.

        Returns the job. For a ``singleton`` template that is already running, it is the running
        instance. ``params`` are checked by the hub (``422 invalid_params``); a ``blob``
        parameter takes a :class:`~p2pc.Blob` or its ``"sha256:<hex>"`` string.
        """
        body = c.launch_body(params, idempotency_key)
        return self._c.jobs._job(
            self._c._request(
                "POST", f"/v1/templates/{c.segment(id, 'template id')}/launch", json=body
            )
        )
