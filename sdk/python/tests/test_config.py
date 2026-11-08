# SPDX-License-Identifier: Apache-2.0
"""``api_url`` handling: no credentials in the URL, and a warning for cleartext HTTP."""

from __future__ import annotations

import logging

import httpx
import pytest
from helpers import KEY, KEY_SECRET, FakeServer, job_json

from p2pc import AsyncClient, Client, ConfigurationError

REMOTE_HTTP = "http://p2pc.example.invalid:7477"  # a non-loopback host over cleartext HTTP


@pytest.mark.parametrize(
    "url",
    [
        "http://user:pw-hunter2@p2pc.example.invalid:7477",
        "https://user:pw-hunter2@p2pc.example.invalid",
        "http://only-a-user@p2pc.example.invalid",
        "http://:only-a-password-hunter2@p2pc.example.invalid",
        "http://user:pw-hunter2@[2001:db8::1]:7477",
    ],
)
def test_userinfo_in_api_url_is_rejected(url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ConfigurationError, match="credentials") as err:
        Client(api_url=url, api_key=KEY)
    assert "hunter2" not in str(err.value) + repr(err.value)
    # The same applies when the URL comes from the environment.
    monkeypatch.setenv("P2PC_API_URL", url)
    with pytest.raises(ConfigurationError, match="credentials"):
        Client(api_key=KEY)
    with pytest.raises(ConfigurationError, match="credentials"):
        AsyncClient(api_key=KEY)


def test_the_bearer_header_is_what_is_sent_and_never_basic_auth(server: FakeServer) -> None:
    server.on("GET", "/v1/jobs/j", job_json("j"))
    c = Client(
        api_url=REMOTE_HTTP,
        api_key=KEY,
        http_client=httpx.Client(transport=httpx.MockTransport(server)),
    )
    c.jobs.get("j")
    assert server.requests[0].headers["authorization"] == f"Bearer {KEY}"


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:7477",
        "http://127.1.2.3:7477",
        "http://localhost:7477",
        "http://LOCALHOST",
        "http://[::1]:7477",
        "https://p2pc.example.invalid",
        "https://192.0.2.4:7477",
    ],
)
def test_no_warning_for_loopback_or_https(url: str, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    Client(api_url=url, api_key=KEY)
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


@pytest.mark.parametrize(
    "url",
    [
        REMOTE_HTTP,
        "http://192.0.2.4:7477",
        "http://[2001:db8::1]:7477",
        "http://localhost.example.invalid",
    ],
)
def test_cleartext_http_to_a_remote_host_warns_once_per_client(
    url: str, caplog: pytest.LogCaptureFixture, server: FakeServer
) -> None:
    caplog.set_level(logging.DEBUG)
    server.on("GET", "/v1/jobs/j", job_json("j"))
    c = Client(
        api_url=url,
        api_key=KEY,
        http_client=httpx.Client(transport=httpx.MockTransport(server)),
    )
    c.jobs.get("j")
    c.jobs.get("j")
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].name == "p2pc"
    message = warnings[0].getMessage()
    assert "clear text" in message
    assert KEY not in message
    assert KEY_SECRET not in message
    # It is a warning, not a refusal: the request went through.
    assert server.count("GET", "/v1/jobs/j") == 2
    # A second client warns again ("once per client").
    Client(api_url=url, api_key=KEY)
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 2


def test_the_async_client_warns_too(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    AsyncClient(api_url=REMOTE_HTTP, api_key=KEY)
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1


def test_the_warning_does_not_contain_url_path_or_query(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    Client(api_url=f"{REMOTE_HTTP}/prefix?token=abc", api_key=KEY)
    (warning,) = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert "token=abc" not in warning.getMessage()
    assert "p2pc.example.invalid" in warning.getMessage()
