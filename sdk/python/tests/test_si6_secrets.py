# SPDX-License-Identifier: Apache-2.0
"""SI-6: an API key never appears in ``repr()``, exceptions or logs, on any path the 0.1.1
surface adds (``keys.create``, ``whoami``, ``audit``, join tokens)."""

from __future__ import annotations

import logging
from typing import Any

import httpx
import pytest
from helpers import KEY, KEY_SECRET, FakeServer, job_json, json_response, key_json, problem

from p2pc import (
    Client,
    InvalidResponseError,
    JoinToken,
    NewApiKey,
    P2PCConnectionError,
    P2PCError,
)

NEW_KEY = "p2pc_sk_zzzzzzzzzzzz_ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKL"  # gitleaks:allow
JOIN_TOKEN = "p2pc_join_SECRETCODE"  # gitleaks:allow
NEW_SECRET = NEW_KEY.rsplit("_", 1)[-1]


def assert_no_secret(text: str) -> None:
    for secret in (KEY, KEY_SECRET, NEW_KEY, NEW_SECRET):
        assert secret not in text


def test_new_key_never_shows_in_repr_str_dump_or_json() -> None:
    new = NewApiKey.model_validate(key_json("zzzzzzzzzzzz", key=NEW_KEY))
    for text in (repr(new), str(new), str(new.model_dump()), new.model_dump_json()):
        assert_no_secret(text)
    assert new.key.get_secret_value() == NEW_KEY  # only an explicit call reveals it


def test_join_token_never_shows_in_repr_or_dump() -> None:
    tok = JoinToken.model_validate(
        {"id": "jtk_1", "join_token": JOIN_TOKEN, "expires_at": "2026-11-05T10:15:00Z"}
    )
    for text in (repr(tok), str(tok), str(tok.model_dump()), tok.model_dump_json()):
        assert "SECRETCODE" not in text


def test_keys_create_does_not_log_the_new_key(
    client: Client, server: FakeServer, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    server.on("POST", "/v1/keys", json_response(key_json("zzzzzzzzzzzz", key=NEW_KEY), 201))
    created = client.keys.create(["jobs:read"], label="ci")
    assert any(r.name == "p2pc" for r in caplog.records), "the SDK logs requests at DEBUG"
    assert_no_secret(caplog.text)
    assert_no_secret(repr(created) + repr(client))


def test_a_malformed_key_response_is_an_error_that_does_not_quote_the_key(
    client: Client, server: FakeServer
) -> None:
    # `created_at` missing: the response is invalid, and the message must not echo the body.
    bad = {"id": "zzzzzzzzzzzz", "scopes": ["admin"], "key": NEW_KEY}
    server.on("POST", "/v1/keys", json_response(bad, 201))
    with pytest.raises(InvalidResponseError) as err:
        client.keys.create(["admin"])
    assert_no_secret(str(err.value) + repr(err.value) + repr(err.value.__cause__))
    assert err.value.__suppress_context__


@pytest.mark.parametrize(
    ("method", "path", "call"),
    [
        ("GET", "/v1/whoami", lambda c: c.whoami()),
        ("GET", "/v1/audit", lambda c: list(c.audit())),
        ("GET", "/v1/keys", lambda c: c.keys.list()),
        ("POST", "/v1/keys", lambda c: c.keys.create(["admin"])),
        ("DELETE", "/v1/keys/k", lambda c: c.keys.revoke("k")),
        ("GET", "/v1/nodes/join-tokens", lambda c: c.join_tokens.list()),
        ("DELETE", "/v1/nodes/join-tokens/t", lambda c: c.join_tokens.revoke("t")),
    ],
)
def test_server_errors_that_echo_the_key_are_masked_on_every_new_call(
    client: Client, server: FakeServer, method: str, path: str, call: Any
) -> None:
    server.on(method, path, problem(403, "forbidden", f"{KEY} lacks admin; also {NEW_KEY}"))
    with pytest.raises(P2PCError) as err:
        call(client)
    text = str(err.value) + repr(err.value) + str(getattr(err.value, "detail", ""))
    assert_no_secret(text)


def test_connection_errors_on_new_calls_do_not_leak_the_key(
    client: Client, server: FakeServer
) -> None:
    def boom(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect with {KEY}")

    server.on("GET", "/v1/whoami", boom)
    with pytest.raises(P2PCConnectionError) as err:
        client.whoami()
    assert_no_secret(str(err.value) + repr(err.value))


def test_job_repr_and_logs_never_contain_env_values_or_the_key(
    client: Client, server: FakeServer, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    leaked_value = "hunter2-very-secret"
    body = job_json()
    body["spec"]["env"] = {"TOKEN": "<redacted>"}
    server.on("POST", "/v1/jobs", json_response(body, 201))
    job = client.jobs.create(
        "docker.io/library/python:3.12-slim", ["true"], env={"TOKEN": leaked_value}
    )
    assert leaked_value not in repr(job) + caplog.text + job.model_dump_json()
    assert_no_secret(caplog.text + repr(job))


# --- join tokens and server addresses in error text -------------------------------------------
SRV_ADDRESS = "p2pc_srv_mfrggzdfmztwq2lknbuxg5dsmvzxi"  # gitleaks:allow
JOIN_TOKEN_LONG = "p2pc_join_mfrggzdfmztwq2lknbuxg5dsmvzxi23abcdefg"  # gitleaks:allow


def test_redact_masks_join_tokens_and_server_addresses() -> None:
    from p2pc._common import redact

    # A join token carries the one-time code, so it is secret. A server address is not, but the
    # CLI prints it only on purpose (`p2pc-server init`, GET /v1/server): an error message that
    # happens to carry one hides it the same way, and so never helps map a deployment.
    text = redact(f"bad {JOIN_TOKEN_LONG}, then {SRV_ADDRESS}; also {JOIN_TOKEN}.", KEY)
    assert text == "bad p2pc_join_…, then p2pc_srv_…; also p2pc_join_…."
    assert "mfrggzdf" not in text
    assert "SECRETCODE" not in text


def test_redact_masks_every_occurrence_and_leaves_other_text_alone() -> None:
    from p2pc._common import redact

    assert redact(f"{SRV_ADDRESS} {SRV_ADDRESS}", None) == "p2pc_srv_… p2pc_srv_…"
    assert redact("p2pc_join_ is a prefix, p2pc_srv_ too", None) == (
        "p2pc_join_ is a prefix, p2pc_srv_ too"
    )
    assert redact("see http://192.0.2.1:7477/v1/jobs", None) == "see http://192.0.2.1:7477/v1/jobs"
    # The API key is still masked in the same pass.
    assert redact(f"{KEY} and {JOIN_TOKEN}", KEY) == f"{KEY[:11]}… and p2pc_join_…"


def test_server_error_that_echoes_a_join_token_or_address_is_masked(
    client: Client, server: FakeServer
) -> None:
    server.on(
        "POST",
        "/v1/nodes/join-tokens",
        problem(409, "token_consumed", f"{JOIN_TOKEN_LONG} was used; server {SRV_ADDRESS}"),
    )
    with pytest.raises(P2PCError) as err:
        client.join_tokens.create()
    text = str(err.value) + repr(err.value) + str(getattr(err.value, "detail", ""))
    assert "mfrggzdf" not in text
    assert "p2pc_join_…" in text
