# SPDX-License-Identifier: Apache-2.0
"""The H2 additions of the SDK (spec §7.8): blobs, blob inputs, services and templates.

Blob and template calls run against ``httpx.MockTransport`` (``FakeServer``). ``services.connect``
needs an HTTP upgrade, which a mock transport cannot do, so it talks to a fake hub that listens on
``127.0.0.1:0`` in a thread (loopback only, no real network).
"""

# Style rules relaxed for this file only: the one-line asserts and nested ``with`` blocks mirror
# what a socket test reads like, and ``pytest.raises(ValueError)`` is also pydantic's error.
# ruff: noqa: PT011, PT018, SIM117

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import os
import socket
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from helpers import KEY, KEY_SECRET, FakeServer, job_json, json_response, problem
from pydantic import ValidationError

import p2pc
from p2pc import AsyncClient, Client, ServicePort, VolumeSpec
from p2pc import h2 as h2mod

DIGEST = hashlib.sha256(b"hello world").hexdigest()
REF = f"sha256:{DIGEST}"
STORED = {"sha256": DIGEST, "size": 11, "created_at": "2026-11-05T10:00:00Z", "expires_at": None}


def client_for(server: FakeServer) -> Client:
    return Client(
        api_url="http://p2pc.example.invalid:7477",
        api_key=KEY,
        http_client=httpx.Client(transport=httpx.MockTransport(server)),
    )


def aclient_for(server: FakeServer) -> AsyncClient:
    return AsyncClient(
        api_url="http://p2pc.example.invalid:7477",
        api_key=KEY,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(server)),
    )


@pytest.fixture
def blob_file(tmp_path: Path) -> Path:
    path = tmp_path / "data.bin"
    path.write_bytes(b"hello world")
    return path


# --- blobs.put -----------------------------------------------------------------------------
def test_put_asks_first_then_uploads_the_file_with_its_digest_and_length(blob_file: Path) -> None:
    server = (
        FakeServer()
        .on("HEAD", f"/v1/blobs/{DIGEST}", httpx.Response(404))
        .on("POST", "/v1/blobs", json_response(STORED, 201))
    )
    blob = client_for(server).blobs.put(blob_file)
    assert [r.method for r in server.requests] == ["HEAD", "POST"]
    upload = server.requests[1]
    assert upload.content == b"hello world"
    assert upload.headers["content-length"] == "11"
    assert "transfer-encoding" not in upload.headers  # the hub answers 411 to a chunked upload
    assert upload.headers["x-p2pc-sha256"] == DIGEST
    assert upload.headers["authorization"] == f"Bearer {KEY}"
    assert (blob.sha256, blob.size, blob.uploaded) == (DIGEST, 11, True)
    assert blob.ref == REF == str(blob)


def test_put_does_not_upload_a_blob_the_hub_already_has(blob_file: Path) -> None:
    server = FakeServer().on(
        "HEAD", f"/v1/blobs/{DIGEST}", httpx.Response(200, headers={"content-length": "11"})
    )
    blob = client_for(server).blobs.put(str(blob_file))
    assert [r.method for r in server.requests] == ["HEAD"]
    assert (blob.ref, blob.size, blob.uploaded) == (REF, 11, False)


def test_a_refused_head_is_not_an_answer_the_upload_says_why(blob_file: Path) -> None:
    server = (
        FakeServer()
        .on("HEAD", f"/v1/blobs/{DIGEST}", httpx.Response(403))
        .on("POST", "/v1/blobs", problem(403, "forbidden", "needs blobs:write"))
    )
    with pytest.raises(p2pc.PermissionDeniedError) as err:
        client_for(server).blobs.put(blob_file)
    assert "blobs:write" in str(err.value)
    assert [r.method for r in server.requests] == ["HEAD", "POST"]


def test_put_refuses_what_is_not_a_regular_file_before_any_request(tmp_path: Path) -> None:
    server = FakeServer()
    client = client_for(server)
    with pytest.raises(h2mod.BlobFileError):
        client.blobs.put(tmp_path)  # a directory
    with pytest.raises(FileNotFoundError):
        client.blobs.put(tmp_path / "missing")
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)
        # Nobody writes to it: a blocking `open` would hang here. It is refused instead.
        with pytest.raises(h2mod.BlobFileError):
            client.blobs.put(fifo)
    assert server.requests == []


def test_put_checks_the_digest_the_hub_stored(blob_file: Path) -> None:
    wrong = {**STORED, "sha256": "0" * 64}
    server = (
        FakeServer()
        .on("HEAD", f"/v1/blobs/{DIGEST}", httpx.Response(404))
        .on("POST", "/v1/blobs", json_response(wrong, 201))
    )
    with pytest.raises(p2pc.InvalidResponseError):
        client_for(server).blobs.put(blob_file)


def test_the_measure_and_the_upload_read_one_descriptor_and_stop_at_the_size(
    tmp_path: Path,
) -> None:
    path = tmp_path / "f"
    path.write_bytes(b"hello world")
    measured = h2mod.measure_file(path)
    try:
        assert (measured.size, measured.digest) == (11, DIGEST)
        assert measured.handle.tell() == 0  # rewound for the upload
        # A file that grew since it was measured: the extra bytes are never read.
        path.write_bytes(b"hello world and more")
        assert b"".join(h2mod.upload_chunks(measured.handle, measured.size)) == b"hello worl" + b"d"
    finally:
        measured.close()


class Growing(io.RawIOBase):
    """A file that keeps yielding bytes after the size it had when it was measured."""

    def __init__(self, total: int) -> None:
        self.left = total

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        n = min(len(buffer), self.left)
        buffer[:n] = b"x" * n
        self.left -= n
        return n


def test_a_file_that_shrank_or_grew_while_hashed_is_refused() -> None:
    assert h2mod.hash_handle(io.BytesIO(b"hello world"), 11) == DIGEST
    with pytest.raises(h2mod.BlobFileError, match="shorter"):
        h2mod.hash_handle(io.BytesIO(b"hello"), 11)
    with pytest.raises(h2mod.BlobFileError, match="longer"):
        h2mod.hash_handle(io.BytesIO(b"hello world!"), 11)
    growing = Growing(11 + 5_000_000)
    with pytest.raises(h2mod.BlobFileError, match="longer"):
        h2mod.hash_handle(io.BufferedReader(growing), 11)
    assert growing.left > 4_000_000  # it stopped near the size: it never read the whole growth
    # The upload iterator refuses a file that got shorter, and never reads more than its size.
    with pytest.raises(h2mod.BlobFileError):
        list(h2mod.upload_chunks(io.BytesIO(b"short"), 11))


def test_async_put_uploads_and_skips_like_the_sync_one(blob_file: Path) -> None:
    async def scenario() -> None:
        server = (
            FakeServer()
            .on("HEAD", f"/v1/blobs/{DIGEST}", httpx.Response(404))
            .on("POST", "/v1/blobs", json_response(STORED, 201))
        )
        async with aclient_for(server) as client:
            blob = await client.blobs.put(blob_file)
        assert [r.method for r in server.requests] == ["HEAD", "POST"]
        assert server.requests[1].content == b"hello world"
        assert server.requests[1].headers["content-length"] == "11"
        assert (blob.ref, blob.uploaded) == (REF, True)

        have = FakeServer().on(
            "HEAD", f"/v1/blobs/{DIGEST}", httpx.Response(200, headers={"content-length": "11"})
        )
        async with aclient_for(have) as client:
            assert (await client.blobs.put(blob_file)).uploaded is False
        assert [r.method for r in have.requests] == ["HEAD"]

    asyncio.run(scenario())


# --- jobs.run(inputs=...) --------------------------------------------------------------------
def test_run_sends_blob_inputs_from_blobs_and_digest_strings() -> None:
    server = FakeServer().on("POST", "/v1/jobs", json_response(job_json(), 201))
    blob = h2mod.Blob(sha256=DIGEST, size=11)
    other = "sha256:" + "ab" * 32
    client_for(server).jobs.run(
        "python:3.12-slim",
        ["python", "/inputs/main.py"],
        inputs={"/inputs/a": blob, "/inputs/b": other},
    )
    assert server.body()["inputs"] == [
        {"path": "/inputs/a", "blob": REF},
        {"path": "/inputs/b", "blob": other},
    ]
    assert "kind" not in server.body()  # a batch job: the H1 body is unchanged


@pytest.mark.parametrize(
    "bad",
    ["/etc/passwd", "../x", "file:///etc/passwd", "sha256:xyz", "", "sha256:" + "A" * 64],
)
def test_run_never_takes_a_local_path_as_an_input(bad: str) -> None:
    server = FakeServer()
    with pytest.raises(ValueError):
        client_for(server).jobs.run("python:3.12-slim", ["true"], inputs={"/inputs/a": bad})
    assert server.requests == []


def test_input_paths_follow_the_files_rules() -> None:
    server = FakeServer()
    for path in ("/etc/x", "/inputs/../x", "/inputs//x", "inputs/x"):
        with pytest.raises(ValidationError):
            client_for(server).jobs.run("python:3.12-slim", ["true"], inputs={path: REF})
    assert server.requests == []


def test_estimate_takes_inputs_too() -> None:
    server = FakeServer().on(
        "POST",
        "/v1/estimate",
        {"feasible": True, "matching_nodes": 1, "would_queue": False, "units_per_hour": 1000},
    )
    client_for(server).estimate("python:3.12-slim", ["true"], inputs={"/inputs/a": REF})
    assert server.body()["inputs"] == [{"path": "/inputs/a", "blob": REF}]


# --- services.run ---------------------------------------------------------------------------
def service_job() -> dict[str, Any]:
    return job_json(
        "job_svc",
        "running",
        service={
            "health": "healthy",
            "ports": [{"port": 11434, "name": "api"}],
            "open_connections": 0,
            "restarts_24h": 0,
        },
    )


def test_services_run_builds_a_service_job() -> None:
    server = FakeServer().on("POST", "/v1/jobs", json_response(service_job(), 201))
    job = client_for(server).services.run(
        "docker.io/ollama/ollama:latest",
        ["/bin/ollama", "serve"],
        ports=[(11434, "api"), 8080],
        health_http="/api/version",
        restart="never",
        volumes=[{"name": "models", "mount": "/volumes/models", "max_mb": 20480}],
        env={"OLLAMA_HOST": "127.0.0.1:11434"},
    )
    body = server.body()
    assert body["kind"] == "service"
    assert body["service"] == {
        "ports": [{"port": 11434, "name": "api"}, {"port": 8080, "name": "port-8080"}],
        "health": {"port": 11434, "http_get": "/api/version"},
        "restart": "never",
    }  # idle_timeout_s left out: the server's default (3,600)
    assert body["volumes"] == [{"name": "models", "mount": "/volumes/models", "max_mb": 20480}]
    assert job.id == "job_svc"


def test_services_run_keeps_an_explicit_never_idle_and_a_tcp_health_check() -> None:
    server = FakeServer().on("POST", "/v1/jobs", json_response(service_job(), 201))
    client_for(server).services.run(
        "python:3.12-slim",
        ["python", "-m", "http.server"],
        ports=[8000],
        idle_timeout_s=None,
        health_tcp=True,
        timeout_s=3600,
    )
    service = server.body()["service"]
    assert service["idle_timeout_s"] is None  # `None` is "never", not "unset"
    assert service["health"] == {"port": 8000, "tcp": True}
    assert server.body()["timeout_s"] == 3600


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ports": []},
        {"ports": [0]},
        {"ports": [70000]},
        {"ports": [80, 80]},
        {"ports": [(80, "Bad Name")]},
        {"ports": [80], "health_http": "api"},
        {"ports": [80], "health_http": "/a/../b"},
        {"ports": [80], "health_http": "/x", "health_tcp": True},
        {"ports": [80], "idle_timeout_s": 10},
        {"ports": [80], "restart": "always"},
        {"ports": [80], "timeout_s": 30},
        {"ports": [80], "timeout_s": 2_592_001},
        {"ports": [80], "volumes": [{"name": "TPL:x/y", "mount": "/volumes/a", "max_mb": 64}]},
        {
            "ports": [80],
            "volumes": [{"name": "tpl:chat/models", "mount": "/volumes/a", "max_mb": 64}],
        },
        {"ports": [80], "volumes": [{"name": "a", "mount": "/etc", "max_mb": 64}]},
        {"ports": [80], "volumes": [{"name": "a", "mount": "/volumes/../x", "max_mb": 64}]},
        {"ports": [80], "volumes": [{"name": "a", "mount": "/volumes/a", "max_mb": 1}]},
    ],
)
def test_services_run_validates_before_any_request(kwargs: dict[str, Any]) -> None:
    server = FakeServer()
    with pytest.raises((ValidationError, ValueError, TypeError)):
        client_for(server).services.run("python:3.12-slim", ["true"], **kwargs)
    assert server.requests == []


def test_a_batch_job_cannot_carry_a_service_or_volumes() -> None:
    with pytest.raises(ValidationError):
        p2pc.JobSpec(
            image="python:3.12-slim",
            command=["true"],
            service=p2pc.ServiceSpec(ports=[ServicePort(port=80, name="a")]),
        )
    with pytest.raises(ValidationError):
        p2pc.JobSpec(
            image="python:3.12-slim",
            command=["true"],
            volumes=[VolumeSpec(name="a", mount="/volumes/a", max_mb=64)],
        )
    with pytest.raises(ValidationError):
        p2pc.JobSpec(image="python:3.12-slim", command=["true"], kind="service")
    with pytest.raises(ValidationError):
        p2pc.JobSpec(image="python:3.12-slim", command=["true"], timeout_s=86_401)


def test_async_services_run_and_templates() -> None:
    async def scenario() -> None:
        server = (
            FakeServer()
            .on("POST", "/v1/jobs", json_response(service_job(), 201))
            .on("POST", "/v1/templates/private-chat/launch", json_response(job_json("job_t"), 201))
            .on(
                "GET",
                "/v1/templates",
                {"bundle_version": 3, "templates": [], "bundle_error": None},
            )
        )
        async with aclient_for(server) as client:
            job = await client.services.run("python:3.12-slim", ["true"], ports=[8000])
            assert server.body(0)["kind"] == "service" and job.id == "job_svc"
            listing = await client.templates.list()
            assert listing.bundle_version == 3 and len(listing) == 0
            launched = await client.templates.launch("private-chat", {"model": "small"})
            assert launched.id == "job_t"
            assert server.body(2) == {"params": {"model": "small"}}

    asyncio.run(scenario())


# --- templates ------------------------------------------------------------------------------
TEMPLATES = {
    "bundle_version": 7,
    "templates": [
        {
            "id": "transcribe",
            "version": 2,
            "title": "Transcribe audio",
            "description": "whisper",
            "kind": "batch",
            "ui": "transcribe",
            "singleton": False,
            "requirements": {"gpu": "preferred", "min_vram_mb": 2048},
            "params": [
                {"name": "audio", "type": "blob", "target": "input:/inputs/audio"},
                {
                    "name": "model",
                    "label": "Model",
                    "type": "enum",
                    "values": ["base", "small"],
                    "default": "small",
                    "target": "env:MODEL",
                },
                {"name": "n", "type": "int", "min": 1, "max": 5, "default": 2, "target": "argv:1"},
            ],
            "licenses": ["MIT"],
            "download_mb": 1500,
            "a_future_field": True,
        }
    ],
    "bundle_error": None,
}


def test_templates_list_parses_the_bundle_and_ignores_new_fields() -> None:
    server = FakeServer().on("GET", "/v1/templates", TEMPLATES)
    listing = client_for(server).templates.list()
    assert listing.bundle_version == 7
    (template,) = list(listing)
    assert (template.id, template.kind, template.download_mb) == ("transcribe", "batch", 1500)
    assert [p.type for p in template.params] == ["blob", "enum", "int"]
    assert template.params[1].values == ["base", "small"]


def test_templates_list_with_no_bundle_is_empty_with_the_reason() -> None:
    body = {"bundle_version": None, "templates": [], "bundle_error": "no bundle"}
    listing = client_for(FakeServer().on("GET", "/v1/templates", body)).templates.list()
    assert len(listing) == 0 and listing.bundle_error == "no bundle"


def test_templates_launch_sends_params_and_a_blob_as_its_digest() -> None:
    server = FakeServer().on(
        "POST", "/v1/templates/transcribe/launch", json_response(job_json(), 201)
    )
    client_for(server).templates.launch(
        "transcribe",
        {"audio": h2mod.Blob(sha256=DIGEST, size=11), "model": "small", "n": 3, "fast": True},  # type: ignore[dict-item]
        idempotency_key="launch-1",
    )
    assert server.body() == {
        "params": {"audio": REF, "model": "small", "n": 3, "fast": True},
        "idempotency_key": "launch-1",
    }


def test_a_singleton_that_is_running_comes_back_as_its_job() -> None:
    server = FakeServer().on(
        "POST", "/v1/templates/private-chat/launch", json_response(job_json("job_running"), 200)
    )
    assert client_for(server).templates.launch("private-chat").id == "job_running"
    assert server.body() == {"params": {}}


def test_a_template_id_is_one_path_segment_and_params_are_typed() -> None:
    server = FakeServer()
    client = client_for(server)
    with pytest.raises(ValueError):
        client.templates.launch("..")
    with pytest.raises(TypeError):
        client.templates.launch("a", {"x": [1]})  # type: ignore[dict-item]
    with pytest.raises(ValueError):
        client.templates.launch("a", idempotency_key="has space")
    assert server.requests == []
    # A hub that answers 422 invalid_params surfaces as the SDK's error.
    server.on("POST", "/v1/templates/a%2Fb/launch", problem(422, "invalid_params", "bad model"))
    server.on("POST", "/v1/templates/a/launch", problem(422, "invalid_params", "bad model"))
    with pytest.raises(p2pc.UnprocessableError) as err:
        client.templates.launch("a")
    assert err.value.code == "invalid_params"


# --- services.connect: a fake hub on loopback ------------------------------------------------
class FakeHub:
    """Answers ``POST …/connect`` with a ``101`` and an upper-casing echo, or with a refusal."""

    def __init__(self, status: int = 101, body: bytes = b"") -> None:
        self.status = status
        self.body = body
        self.heads: list[str] = []
        self._lock = threading.Lock()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._conns: list[socket.socket] = []
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._listener.close()
        with self._lock:
            conns = list(self._conns)
        for conn in conns:
            conn.close()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            with self._lock:
                self._conns.append(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            self.heads.append(head.decode())
            if self.status != 101:
                conn.sendall(
                    f"HTTP/1.1 {self.status} Error\r\ncontent-type: application/problem+json\r\n"
                    f"content-length: {len(self.body)}\r\nconnection: close\r\n\r\n".encode()
                    + self.body
                )
                return
            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                b"Upgrade: p2pc-port/1\r\n\r\nWELCOME "
            )
            if rest:
                conn.sendall(rest.upper())
            while chunk := conn.recv(4096):
                conn.sendall(chunk.upper())
        except OSError:
            pass
        finally:
            conn.close()


@pytest.fixture
def hub() -> Iterator[FakeHub]:
    fake = FakeHub()
    yield fake
    fake.close()


def hub_client(hub_: FakeHub) -> Client:
    return Client(api_url=f"http://127.0.0.1:{hub_.port}", api_key=KEY)


def read_some(sock: socket.socket, at_least: int) -> bytes:
    data = b""
    while len(data) < at_least:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def test_connect_forwards_a_local_loopback_port_to_the_service(hub: FakeHub) -> None:
    client = hub_client(hub)
    forwarder = client.services.connect("job_svc", 11434)
    with forwarder as local_port:
        assert forwarder._listener is not None
        assert forwarder._listener.getsockname()[0] == "127.0.0.1"  # never the network
        with socket.create_connection(("127.0.0.1", local_port), timeout=10) as conn:
            conn.settimeout(10)
            conn.sendall(b"ping")
            assert read_some(conn, len(b"WELCOME PING")) == b"WELCOME PING"
    (head,) = hub.heads
    lines = head.split("\r\n")
    assert lines[0] == "POST /v1/jobs/job_svc/ports/11434/connect?wait_ready=true HTTP/1.1"
    headers = {line.split(":", 1)[0].lower(): line.split(":", 1)[1].strip() for line in lines[1:]}
    assert headers["upgrade"] == "p2pc-port/1"
    assert headers["connection"] == "Upgrade"
    assert headers["authorization"] == f"Bearer {KEY}"


def test_connect_takes_a_job_object_and_can_skip_wait_ready(hub: FakeHub) -> None:
    server = FakeServer().on("POST", "/v1/jobs", json_response(service_job(), 201))
    created = client_for(server).services.run("python:3.12-slim", ["true"], ports=[8000])
    with hub_client(hub).services.connect(created, 8000, wait_ready=False) as port:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
            conn.settimeout(10)
            conn.sendall(b"x")
            assert read_some(conn, 9) == b"WELCOME X"
    assert hub.heads[0].split("\r\n")[0] == "POST /v1/jobs/job_svc/ports/8000/connect HTTP/1.1"


def test_a_refused_upgrade_closes_the_local_connection_and_keeps_the_error() -> None:
    body = (
        b'{"type":"x","title":"Conflict","status":409,"code":"service_not_running",'
        b'"detail":"the service is not running"}'
    )
    refusing = FakeHub(409, body)
    try:
        forwarder = hub_client(refusing).services.connect("job_svc", 8000)
        with forwarder as port:
            with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
                conn.settimeout(10)
                assert conn.recv(10) == b""  # closed, with the error kept for the caller
        assert isinstance(forwarder.last_error, p2pc.ConflictError)
        assert forwarder.last_error.code == "service_not_running"
        assert KEY not in str(forwarder.last_error) and KEY_SECRET not in repr(forwarder.last_error)
    finally:
        refusing.close()


def test_the_key_is_not_in_the_log_of_a_refused_upgrade(caplog: pytest.LogCaptureFixture) -> None:
    refusing = FakeHub(
        401, b'{"title":"Unauthorized","status":401,"detail":"bad key ' + KEY.encode() + b'"}'
    )
    try:
        forwarder = hub_client(refusing).services.connect("job_svc", 8000)
        with caplog.at_level(logging.DEBUG, logger="p2pc"), forwarder as port:
            with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
                conn.settimeout(10)
                conn.recv(10)
        assert isinstance(forwarder.last_error, p2pc.AuthenticationError)
        assert KEY_SECRET not in caplog.text and KEY_SECRET not in str(forwarder.last_error)
    finally:
        refusing.close()


def test_connect_validates_its_arguments_before_listening() -> None:
    client = Client(api_url="http://127.0.0.1:1", api_key=KEY)
    for port in (0, 70000, True, "80"):
        with pytest.raises(ValueError):
            client.services.connect("job_svc", port)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        client.services.connect("..", 80)


def test_an_unreachable_hub_is_a_connection_error_without_the_key() -> None:
    with socket.create_server(("127.0.0.1", 0)) as probe:
        free_port = probe.getsockname()[1]
    forwarder = Client(api_url=f"http://127.0.0.1:{free_port}", api_key=KEY).services.connect(
        "job_svc", 80
    )
    with forwarder as port:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
            conn.settimeout(10)
            assert conn.recv(10) == b""
    assert isinstance(forwarder.last_error, p2pc.P2PCConnectionError)
    assert KEY_SECRET not in str(forwarder.last_error)


def test_closing_ends_the_listener_and_every_open_connection(hub: FakeHub) -> None:
    forwarder = hub_client(hub).services.connect("job_svc", 8000)
    with forwarder as port:
        conn = socket.create_connection(("127.0.0.1", port), timeout=10)
        conn.settimeout(10)
        conn.sendall(b"a")
        assert read_some(conn, 9) == b"WELCOME A"
    # The block ended: the open connection is closed and the port no longer accepts.
    assert conn.recv(10) == b""
    conn.close()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2)


def test_async_connect_forwards_and_reports_a_refusal(hub: FakeHub) -> None:
    async def scenario() -> None:
        async with AsyncClient(api_url=f"http://127.0.0.1:{hub.port}", api_key=KEY) as client:
            forwarder = client.services.connect("job_svc", 8000)
            async with forwarder as port:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"ping")
                await writer.drain()
                got = await asyncio.wait_for(reader.readexactly(len(b"WELCOME PING")), 10)
                assert got == b"WELCOME PING"
                writer.close()
            assert forwarder.local_port == port
        refusing = FakeHub(
            422, b'{"title":"x","status":422,"code":"port_not_exposed","detail":"port not exposed"}'
        )
        try:
            async with AsyncClient(
                api_url=f"http://127.0.0.1:{refusing.port}", api_key=KEY
            ) as client:
                forwarder = client.services.connect("job_svc", 9)
                async with forwarder as port:
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    assert await asyncio.wait_for(reader.read(10), 10) == b""
                    writer.close()
                assert isinstance(forwarder.last_error, p2pc.UnprocessableError)
                assert forwarder.last_error.code == "port_not_exposed"
        finally:
            refusing.close()

    asyncio.run(scenario())
