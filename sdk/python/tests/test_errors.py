# SPDX-License-Identifier: Apache-2.0
"""problem+json → exception mapping, and key masking."""

from __future__ import annotations

import json

import httpx
import pytest

from p2pc import (
    AuthenticationError,
    CapExceededError,
    ConflictError,
    NotFoundError,
    P2PCError,
    PermissionDeniedError,
    RateLimitError,
    ServerError,
    UnprocessableError,
)
from p2pc._common import error_from_response, mask_key, redact

KEY = "p2pc_sk_abcdefghijkl_QRSTUVWXYZ234567QRSTUVWXYZ234567QRSTUVWXYZ23"  # gitleaks:allow


def problem(status: int, code: str | None = "some_code", **extra: object) -> httpx.Response:
    body: dict[str, object] = {
        "type": "https://example.invalid/problems/x",
        "title": "A title",
        "status": status,
        "detail": "Something specific",
    }
    if code is not None:
        body["code"] = code
    body.update(extra)
    return httpx.Response(
        status,
        headers={"content-type": "application/problem+json"},
        content=json.dumps(body).encode(),
    )


@pytest.mark.parametrize(
    ("status", "cls"),
    [
        (401, AuthenticationError),
        (403, PermissionDeniedError),
        (404, NotFoundError),
        (409, ConflictError),
        (402, CapExceededError),
        (422, UnprocessableError),
        (429, RateLimitError),
        (500, ServerError),
        (502, ServerError),
        (503, ServerError),
        (599, ServerError),
    ],
)
def test_status_maps_to_class(status: int, cls: type[P2PCError]) -> None:
    err = error_from_response(problem(status, code="brand_new_unknown_code"), KEY)
    assert type(err) is cls
    assert isinstance(err, P2PCError)
    assert err.status == status
    assert err.code == "brand_new_unknown_code"
    assert err.title == "A title"
    assert err.detail == "Something specific"
    assert err.type == "https://example.invalid/problems/x"
    assert "Something specific" in str(err)


def test_unmapped_4xx_is_base_error() -> None:
    err = error_from_response(problem(400, "bad_request"), KEY)
    assert type(err) is P2PCError
    assert err.status == 400


def test_known_codes() -> None:
    assert error_from_response(problem(402, "cap_exceeded"), KEY).code == "cap_exceeded"
    assert error_from_response(problem(422, "unsupported_pool"), KEY).code == "unsupported_pool"


def test_non_problem_body_falls_back_to_status() -> None:
    resp = httpx.Response(
        502, headers={"content-type": "text/html"}, content=b"<html>bad gateway</html>"
    )
    err = error_from_response(resp, KEY)
    assert isinstance(err, ServerError)
    assert err.status == 502
    assert err.code is None
    assert err.detail is not None
    assert "bad gateway" in err.detail


def test_malformed_json_body_does_not_crash() -> None:
    resp = httpx.Response(
        500, headers={"content-type": "application/problem+json"}, content=b"{not json"
    )
    assert isinstance(error_from_response(resp, KEY), ServerError)
    resp = httpx.Response(
        404, headers={"content-type": "application/problem+json"}, content=b"[1, 2]"
    )
    assert isinstance(error_from_response(resp, KEY), NotFoundError)


def test_non_string_members_are_ignored() -> None:
    err = error_from_response(problem(404, code=None, title=5, detail=["x"], type={"a": 1}), KEY)
    assert err.title is not None  # falls back to the HTTP reason phrase
    assert err.detail is None
    assert err.type is None


def test_retry_after_on_429() -> None:
    resp = problem(429)
    resp.headers["retry-after"] = "7"
    err = error_from_response(resp, KEY)
    assert isinstance(err, RateLimitError)
    assert err.retry_after == 7.0
    resp.headers["retry-after"] = "Wed, 21 Oct 2015 07:28:00 GMT"
    err2 = error_from_response(resp, KEY)
    assert isinstance(err2, RateLimitError)
    assert err2.retry_after is None


def test_error_never_contains_the_key_even_if_the_server_echoes_it() -> None:
    err = error_from_response(problem(401, detail=f"bad credentials {KEY}"), KEY)
    assert KEY not in str(err)
    assert KEY not in repr(err)
    assert err.detail is not None
    assert KEY not in err.detail
    assert KEY.split("_")[-1] not in str(err)


def test_mask_key() -> None:
    assert mask_key(KEY) == "p2pc_sk_abc…"
    assert mask_key(None) == "<unset>"
    assert mask_key("") == "<unset>"
    assert mask_key("some-other-token") == "…"


def test_redact() -> None:
    assert redact(f"x {KEY} y", KEY) == "x p2pc_sk_abc… y"
    assert redact("nothing here", KEY) == "nothing here"
    assert redact("anything", None) == "anything"


def test_redact_masks_any_key_shaped_token_even_if_not_configured() -> None:
    other = "p2pc_sk_zzzzzzzzzzzz_ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    assert redact(f"a {other} b", None) == "a p2pc_sk_zzz… b"
    assert redact(f"a {other} b", KEY) == "a p2pc_sk_zzz… b"
    assert redact(f"{KEY} {other}", KEY) == "p2pc_sk_abc… p2pc_sk_zzz…"
