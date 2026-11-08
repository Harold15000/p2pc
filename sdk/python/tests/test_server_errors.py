# SPDX-License-Identifier: Apache-2.0
"""The problem+json codes the real server sends (``crates/p2pc-server/src/error.rs``), and the
per-field ``errors`` of a 422."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from p2pc import (
    AuthenticationError,
    CapExceededError,
    Client,
    ConflictError,
    FieldError,
    NotFoundError,
    P2PCError,
    PermissionDeniedError,
    UnprocessableError,
)
from p2pc._common import error_from_response
from p2pc.errors import FIELD_ERROR_CODES

KEY = "p2pc_sk_abcdefghijkl_QRSTUVWXYZ234567QRSTUVWXYZ234567QRSTUVWXYZ23"  # gitleaks:allow


def problem(status: int, code: str, **extra: Any) -> httpx.Response:
    body = {
        "type": f"https://example.invalid/problems/{code}",
        "title": "A title",
        "status": status,
        "detail": "Something specific",
        "code": code,
        **extra,
    }
    return httpx.Response(
        status, headers={"content-type": "application/problem+json"}, content=json.dumps(body)
    )


# (status, code): the codes and statuses of the server's ApiError constructors and of §5/§7.
SERVER_CODES: list[tuple[int, str, type[P2PCError]]] = [
    (401, "unauthenticated", AuthenticationError),
    (403, "forbidden", PermissionDeniedError),
    (403, "escalation_denied", PermissionDeniedError),
    (403, "image_not_allowed", PermissionDeniedError),
    (402, "cap_exceeded", CapExceededError),
    (409, "idempotency_conflict", ConflictError),
    (409, "last_admin_key", ConflictError),
    (404, "not_found", NotFoundError),
    (422, "validation_failed", UnprocessableError),
    (422, "unsupported_pool", UnprocessableError),
    (422, "too_large", UnprocessableError),
    (422, "invalid_body", UnprocessableError),
    (400, "invalid_json", P2PCError),
    (405, "method_not_allowed", P2PCError),
    (408, "request_timeout", P2PCError),
    (413, "payload_too_large", P2PCError),
    (415, "unsupported_media_type", P2PCError),
]


@pytest.mark.parametrize(("status", "code", "cls"), SERVER_CODES, ids=[c[1] for c in SERVER_CODES])
def test_every_server_code_maps_to_its_class_and_keeps_its_code(
    status: int, code: str, cls: type[P2PCError]
) -> None:
    err = error_from_response(problem(status, code), KEY)
    assert type(err) is cls
    assert (err.status, err.code) == (status, code)
    assert f"[{code}]" in str(err)


def test_internal_errors_are_server_errors_with_the_internal_code() -> None:
    from p2pc import ServerError

    err = error_from_response(problem(500, "internal"), KEY)
    assert isinstance(err, ServerError)
    assert err.code == "internal"


def test_field_errors_of_a_422_are_exposed() -> None:
    err = error_from_response(
        problem(
            422,
            "validation_failed",
            errors=[
                {"field": "resources.cpu", "code": "out_of_range", "message": "must be 0.25-256"},
                {"field": "files[0].path", "code": "invalid_format", "message": "not in /inputs"},
            ],
        ),
        KEY,
    )
    assert err.errors == (
        FieldError(field="resources.cpu", code="out_of_range", message="must be 0.25-256"),
        FieldError(field="files[0].path", code="invalid_format", message="not in /inputs"),
    )
    assert {e.code for e in err.errors} <= FIELD_ERROR_CODES


def test_unsupported_pool_and_too_large_name_their_field() -> None:
    err = error_from_response(
        problem(
            422,
            "unsupported_pool",
            errors=[{"field": "placement.pools", "code": "unsupported_pool", "message": "x"}],
        ),
        KEY,
    )
    assert isinstance(err, UnprocessableError)
    assert err.errors[0].field == "placement.pools"
    too_large = error_from_response(
        problem(422, "too_large", errors=[{"field": "job", "code": "too_large", "message": "x"}]),
        KEY,
    )
    assert too_large.errors[0].field == "job"


def test_escalation_denied_lists_the_fields_that_exceed_the_creating_key() -> None:
    err = error_from_response(
        problem(
            403,
            "escalation_denied",
            errors=[{"field": "scopes", "code": "not_allowed", "message": "exceeds"}],
        ),
        KEY,
    )
    assert isinstance(err, PermissionDeniedError)
    assert [(e.field, e.code) for e in err.errors] == [("scopes", "not_allowed")]


def test_unknown_field_error_codes_and_malformed_entries_do_not_break_the_error() -> None:
    err = error_from_response(
        problem(
            422,
            "validation_failed",
            errors=[
                {"field": "a", "code": "a_code_from_the_future", "message": "m", "extra": 1},
                {"field": "b"},  # incomplete: skipped
                "nonsense",
                {"field": 1, "code": 2, "message": 3},
            ],
        ),
        KEY,
    )
    assert [(e.field, e.code) for e in err.errors] == [("a", "a_code_from_the_future")]
    assert error_from_response(problem(422, "validation_failed", errors="x"), KEY).errors == ()
    assert error_from_response(problem(404, "not_found"), KEY).errors == ()


def test_field_error_messages_are_redacted_and_their_number_bounded() -> None:
    echoed = problem(
        422,
        "validation_failed",
        errors=[{"field": "env.X", "code": "reserved", "message": f"bad {KEY}"}],
    )
    err = error_from_response(echoed, KEY)
    assert KEY not in repr(err.errors) + str(err.errors[0].message)
    many = problem(
        422,
        "validation_failed",
        errors=[{"field": f"f{i}", "code": "reserved", "message": "m"} for i in range(1000)],
    )
    assert len(error_from_response(many, KEY).errors) == 100


def test_a_422_from_the_api_reaches_the_caller_with_its_fields(client: Client, server: Any) -> None:
    server.on(
        "POST",
        "/v1/jobs",
        problem(
            422,
            "validation_failed",
            errors=[{"field": "timeout_s", "code": "out_of_range", "message": "1-86400"}],
        ),
    )
    with pytest.raises(UnprocessableError) as err:
        client.jobs.create("docker.io/library/python:3.12-slim", ["true"])
    assert err.value.errors[0].field == "timeout_s"
