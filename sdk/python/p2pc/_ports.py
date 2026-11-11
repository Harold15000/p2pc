# SPDX-License-Identifier: Apache-2.0
"""``client.services.connect``: a local loopback port that forwards to a service port (spec §7.4).

``POST /v1/jobs/{id}/ports/{port}/connect`` is an HTTP/1.1 upgrade to ``p2pc-port/1``; after the
``101`` the connection is a raw byte stream into the service. ``httpx`` cannot hand back an
upgraded connection, so the handshake is written here on a plain (or TLS) socket; it is short,
bounded and never reads more than ``MAX_HEAD`` bytes before the ``101``.

The listener binds ``127.0.0.1`` only, on an ephemeral port: the SDK never exposes a service to
the network. Each accepted connection opens one upgraded connection to the hub. At most
``MAX_CONNECTIONS`` are open at once (the hub allows 16 per principal and service); the next ones
wait in the listen backlog. The key is sent only to the hub and is masked in every message.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import selectors
import socket
import ssl
import threading
from collections.abc import Callable
from types import TracebackType
from urllib.parse import urlsplit

import httpx

from p2pc import _common as c
from p2pc.errors import InvalidResponseError, P2PCConnectionError, P2PCError

LOG = logging.getLogger("p2pc")

PORT_UPGRADE_PROTOCOL = "p2pc-port/1"
MAX_CONNECTIONS = 16
MAX_HEAD = 64 * 1024
#: The hub waits up to 30 s for a ``starting`` service when asked to (``?wait_ready=true``).
WAIT_READY_S = 35.0
_PUMP_CHUNK = 64 * 1024


def _target(
    config: c.Config, job_id: str, port: int, wait_ready: bool
) -> tuple[str, int, bool, str]:
    """(host, port, tls, request target) of the connect endpoint."""
    parts = urlsplit(config.api_url)
    tls = parts.scheme == "https"
    host = parts.hostname or ""
    number = parts.port or (443 if tls else 80)
    path = f"{parts.path.rstrip('/')}/v1/jobs/{c.segment(job_id, 'job id')}/ports/{port}/connect"
    if wait_ready:
        path += "?wait_ready=true"
    return host, number, tls, path


def request_head(config: c.Config, job_id: str, port: int, wait_ready: bool) -> bytes:
    """The bytes of the upgrade request (no body)."""
    host, number, tls, target = _target(config, job_id, port, wait_ready)
    default = 443 if tls else 80
    host_header = f"[{host}]" if ":" in host else host
    if number != default:
        host_header += f":{number}"
    headers = {
        "Host": host_header,
        "Authorization": f"Bearer {config.require_key()}",
        "User-Agent": c.USER_AGENT,
        "Connection": "Upgrade",
        "Upgrade": PORT_UPGRADE_PROTOCOL,
        "Content-Length": "0",
    }
    lines = [f"POST {target} HTTP/1.1", *(f"{k}: {v}" for k, v in headers.items()), "", ""]
    return "\r\n".join(lines).encode("ascii")


def parse_head(raw: bytes) -> tuple[int, str, dict[str, str]]:
    """Status, reason and (lowercase) headers of a response head."""
    try:
        text = raw.decode("iso-8859-1")
        status_line, *header_lines = text.split("\r\n")
        _, code, *reason = status_line.split(" ", 2)
        status = int(code)
    except ValueError:
        raise InvalidResponseError("the server's answer is not an HTTP response") from None
    headers: dict[str, str] = {}
    for line in header_lines:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return status, (reason[0] if reason else ""), headers


def refusal(
    status: int, reason: str, headers: dict[str, str], body: bytes, key: str | None
) -> P2PCError:
    """The mapped error for a non-``101`` answer to the upgrade request."""
    response = httpx.Response(
        status,
        headers={"content-type": headers.get("content-type", "application/octet-stream")},
        content=b"",
        extensions={"reason_phrase": reason.encode("ascii", "replace")},
    )
    return c.error_from_response(response, key, body)


def _no_upgrade(status: int) -> P2PCError:
    return InvalidResponseError(
        f"the server answered {status} instead of switching protocols; "
        "it is not a P2PC hub that serves service ports"
    )


# --- sync ------------------------------------------------------------------------------------
def open_port(
    config: c.Config,
    job_id: str,
    port: int,
    wait_ready: bool,
    *,
    context: ssl.SSLContext | None = None,
) -> tuple[socket.socket, bytes]:
    """Open an upgraded connection to ``port`` of the service ``job_id``.

    Returns the socket and any bytes the hub sent right after its ``101``. Raises the mapped
    :class:`~p2pc.P2PCError` for an answer before the upgrade (``409 service_not_running``,
    ``409 service_not_ready``, ``422 port_not_exposed``, ``429``, ``502 node_unreachable`` …).
    """
    host, number, tls, _ = _target(config, job_id, port, wait_ready)
    timeout = config.timeout + (WAIT_READY_S if wait_ready else 0.0)
    head = request_head(config, job_id, port, wait_ready)
    try:
        raw = socket.create_connection((host, number), timeout=config.timeout)
    except OSError as exc:
        detail = c.redact(f"{type(exc).__name__}: {exc}", config.api_key)
        raise P2PCConnectionError(f"could not reach {config.safe_url}: {detail}") from None
    sock: socket.socket = raw
    try:
        if tls:
            sock = (context or ssl.create_default_context()).wrap_socket(raw, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(head)
        buffer = bytearray()
        while b"\r\n\r\n" not in buffer:
            chunk = sock.recv(8192)
            if not chunk:
                raise P2PCConnectionError("the server closed the connection before it answered")
            buffer += chunk
            if len(buffer) > MAX_HEAD:
                raise InvalidResponseError("the server's answer head is too large")
        raw_head, _, rest = bytes(buffer).partition(b"\r\n\r\n")
        status, reason, headers = parse_head(raw_head)
        if status == 101:
            sock.settimeout(None)
            return sock, rest
        # An error answer: its (short) body is the problem document.
        body = bytearray(rest)
        want = min(int(headers.get("content-length", "0") or 0), c.MAX_ERROR_BODY)
        while len(body) < want:
            chunk = sock.recv(8192)
            if not chunk:
                break
            body += chunk
        if status < 300:
            raise _no_upgrade(status)
        raise refusal(status, reason, headers, bytes(body), config.api_key)
    except (OSError, ssl.SSLError) as exc:
        sock.close()
        detail = c.redact(f"{type(exc).__name__}: {exc}", config.api_key)
        raise P2PCConnectionError(f"could not reach {config.safe_url}: {detail}") from None
    except BaseException:
        sock.close()
        raise


def _pump(a: socket.socket, b: socket.socket, leftover: bytes) -> None:
    """Copy bytes both ways until both directions have ended, then close both sockets."""
    if leftover:
        a.sendall(leftover)  # `a` is the local side: what the hub sent after the 101
    selector = selectors.DefaultSelector()
    open_ends = {a: b, b: a}
    for sock in open_ends:
        sock.setblocking(False)
        selector.register(sock, selectors.EVENT_READ)
    try:
        while open_ends:
            for key, _ in selector.select():
                src: socket.socket = key.fileobj  # type: ignore[assignment]
                dst = open_ends.get(src)
                if dst is None:
                    continue
                try:
                    data = src.recv(_PUMP_CHUNK)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    data = b""
                if data:
                    dst.setblocking(True)
                    try:
                        dst.sendall(data)
                    except OSError:
                        data = b""
                    finally:
                        with contextlib.suppress(OSError):
                            dst.setblocking(False)
                if not data:
                    selector.unregister(src)
                    del open_ends[src]
                    with contextlib.suppress(OSError):
                        dst.shutdown(socket.SHUT_WR)
    finally:
        selector.close()
        for sock in (a, b):
            with contextlib.suppress(OSError):
                sock.close()


class PortForwarder:
    """A loopback listener whose every connection is forwarded to the service port.

    Use through ``with client.services.connect(job, port) as local_port``: it listens on
    ``127.0.0.1:<local_port>`` until the block ends, when it closes the listener and every open
    connection. A failed upgrade closes that local connection and is kept in ``last_error``
    (and logged without the key).
    """

    def __init__(
        self,
        config: c.Config,
        job_id: str,
        port: int,
        *,
        wait_ready: bool = True,
        opener: Callable[..., tuple[socket.socket, bytes]] = open_port,
        context: ssl.SSLContext | None = None,
    ) -> None:
        self._config = config
        self._job_id = job_id
        self._port = port
        self._wait_ready = wait_ready
        self._opener = opener
        self._context = context
        self._listener: socket.socket | None = None
        self._wake_r, self._wake_w = socket.socketpair()
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._lock = threading.Lock()
        self._live: set[socket.socket] = set()
        self._threads: list[threading.Thread] = []
        self._stopped = threading.Event()
        self.last_error: P2PCError | None = None
        self.local_port = 0

    def start(self) -> int:
        listener = socket.create_server(("127.0.0.1", 0), backlog=64)
        self._listener = listener
        self.local_port = int(listener.getsockname()[1])
        thread = threading.Thread(target=self._accept_loop, name="p2pc-port-accept", daemon=True)
        self._threads.append(thread)
        thread.start()
        return self.local_port

    def _accept_loop(self) -> None:
        listener = self._listener
        assert listener is not None  # noqa: S101 - set by start()
        selector = selectors.DefaultSelector()
        selector.register(listener, selectors.EVENT_READ)
        selector.register(self._wake_r, selectors.EVENT_READ)
        try:
            while not self._stopped.is_set():
                # A free slot first, so that the 17th connection waits in the listen backlog.
                if not self._slots.acquire(blocking=False):
                    if self._stopped.wait(0.05):
                        break
                    continue
                accepted = False
                try:
                    for key, _ in selector.select():
                        if key.fileobj is listener:
                            client, _addr = listener.accept()
                            accepted = True
                            worker = threading.Thread(
                                target=self._serve,
                                args=(client,),
                                name="p2pc-port-conn",
                                daemon=True,
                            )
                            with self._lock:
                                self._threads.append(worker)
                            worker.start()
                        else:
                            return
                except OSError:
                    return
                finally:
                    if not accepted:
                        self._slots.release()
        finally:
            selector.close()

    def _serve(self, client: socket.socket) -> None:
        try:
            try:
                upstream, leftover = self._opener(
                    self._config, self._job_id, self._port, self._wait_ready, context=self._context
                )
            except P2PCError as exc:
                self.last_error = exc
                LOG.warning("service connection to port %d refused: %s", self._port, exc)
                client.close()
                return
            with self._lock:
                self._live.update((client, upstream))
            try:
                _pump(client, upstream, leftover)
            finally:
                with self._lock:
                    self._live.difference_update((client, upstream))
        finally:
            self._slots.release()

    def close(self) -> None:
        if self._stopped.is_set():
            return
        self._stopped.set()
        with contextlib.suppress(OSError):
            self._wake_w.send(b"x")
        if self._listener is not None:
            self._listener.close()
        with self._lock:
            live = list(self._live)
            threads = list(self._threads)
        for sock in live:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
        for thread in threads:
            thread.join(timeout=5)
        self._wake_r.close()
        self._wake_w.close()

    def __enter__(self) -> int:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


# --- async -----------------------------------------------------------------------------------
async def aopen_port(
    config: c.Config,
    job_id: str,
    port: int,
    wait_ready: bool,
    *,
    context: ssl.SSLContext | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Async twin of :func:`open_port`: the reader and writer of the upgraded connection."""
    host, number, tls, _ = _target(config, job_id, port, wait_ready)
    timeout = config.timeout + (WAIT_READY_S if wait_ready else 0.0)
    head = request_head(config, job_id, port, wait_ready)
    try:
        ssl_arg = (context or ssl.create_default_context()) if tls else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, number, ssl=ssl_arg, limit=MAX_HEAD),
            timeout=config.timeout,
        )
    except (OSError, TimeoutError) as exc:
        detail = c.redact(f"{type(exc).__name__}: {exc}", config.api_key)
        raise P2PCConnectionError(f"could not reach {config.safe_url}: {detail}") from None
    try:
        writer.write(head)
        await writer.drain()
        raw_head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
        status, reason, headers = parse_head(raw_head[:-4])
        if status == 101:
            return reader, writer
        want = min(int(headers.get("content-length", "0") or 0), c.MAX_ERROR_BODY)
        body = await asyncio.wait_for(reader.read(want), timeout=config.timeout) if want else b""
        if status < 300:
            raise _no_upgrade(status)
        raise refusal(status, reason, headers, body, config.api_key)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        writer.close()
        raise InvalidResponseError("the server's answer is incomplete or too large") from None
    except (OSError, TimeoutError) as exc:
        writer.close()
        detail = c.redact(f"{type(exc).__name__}: {exc}", config.api_key)
        raise P2PCConnectionError(f"could not reach {config.safe_url}: {detail}") from None
    except BaseException:
        writer.close()
        raise


async def _copy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(_PUMP_CHUNK):
            writer.write(data)
            await writer.drain()
    except (OSError, asyncio.CancelledError):
        pass
    finally:
        with contextlib.suppress(OSError, RuntimeError):
            if writer.can_write_eof():
                writer.write_eof()


class AsyncPortForwarder:
    """:class:`PortForwarder` for ``asyncio``: ``async with client.services.connect(...)``."""

    def __init__(
        self,
        config: c.Config,
        job_id: str,
        port: int,
        *,
        wait_ready: bool = True,
        opener: Callable[..., object] = aopen_port,
        context: ssl.SSLContext | None = None,
    ) -> None:
        self._config = config
        self._job_id = job_id
        self._port = port
        self._wait_ready = wait_ready
        self._opener = opener
        self._context = context
        self._server: asyncio.Server | None = None
        self._slots = asyncio.Semaphore(MAX_CONNECTIONS)
        self._tasks: set[asyncio.Task[None]] = set()
        self.last_error: P2PCError | None = None
        self.local_port = 0

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0, backlog=64)
        self.local_port = int(self._server.sockets[0].getsockname()[1])
        return self.local_port

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        try:
            async with self._slots:
                try:
                    up_reader, up_writer = await self._opener(  # type: ignore[misc]
                        self._config,
                        self._job_id,
                        self._port,
                        self._wait_ready,
                        context=self._context,
                    )
                except P2PCError as exc:
                    self.last_error = exc
                    LOG.warning("service connection to port %d refused: %s", self._port, exc)
                    return
                try:
                    await asyncio.gather(_copy(reader, up_writer), _copy(up_reader, writer))
                finally:
                    with contextlib.suppress(OSError, RuntimeError):
                        up_writer.close()
        finally:
            with contextlib.suppress(OSError, RuntimeError):
                writer.close()
            if task is not None:
                self._tasks.discard(task)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            for task in list(self._tasks):
                task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> int:
        return await self.start()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()


__all__ = [
    "AsyncPortForwarder",
    "PortForwarder",
    "aopen_port",
    "open_port",
]
