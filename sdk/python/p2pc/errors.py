# SPDX-License-Identifier: Apache-2.0
"""Exception hierarchy.

Server errors are RFC 9457 ``application/problem+json`` documents. They are mapped to a
class by HTTP status, so an unknown ``code`` still lands on the closest class.

Exception messages never contain the API key: the key is masked before a message is built.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

# The ``code`` of a field error in a 422 (the server's ``ErrorCode``). The ``code`` of the problem
# itself is open: ``unauthenticated``, ``forbidden``, ``escalation_denied``, ``image_not_allowed``,
# ``cap_exceeded``, ``idempotency_conflict``, ``last_admin_key``, ``not_found``,
# ``validation_failed``, ``unsupported_pool``, ``too_large``, ``invalid_body``... and any the SDK
# does not know yet: the exception class is chosen by HTTP status.
FIELD_ERROR_CODES = frozenset(
    {
        "out_of_range",
        "invalid_format",
        "too_large",
        "too_many",
        "reserved",
        "unsupported_pool",
        "not_allowed",
        "duplicate",
        "path_conflict",
        # H2 (spec §7.1, §7.7).
        "required",
        "read_only_field",
        "volumes_not_allowed",
        "inputs_exceed_disk",
        "unknown_blob",
    }
)


class FieldError(BaseModel):
    """One validation problem of a ``422``: ``field`` is a path such as ``files[0].path``.

    ``message`` never contains env values or file contents.
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    field: str
    code: str
    message: str


class P2PCError(Exception):
    """Base class for every error raised by the SDK.

    ``status``, ``code``, ``title``, ``detail`` and ``type`` mirror the members of the
    ``application/problem+json`` body, and ``errors`` lists its per-field problems (empty for
    anything but a ``422`` or an ``escalation_denied``). They are ``None`` (``errors`` empty) for
    client-side errors.
    """

    def __init__(
        self,
        message: str | None = None,
        *,
        status: int | None = None,
        code: str | None = None,
        title: str | None = None,
        detail: str | None = None,
        type: str | None = None,
        errors: Sequence[FieldError] = (),
    ) -> None:
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.type = type
        self.errors: tuple[FieldError, ...] = tuple(errors)
        if message is None:
            head = " ".join(str(p) for p in (status, title) if p is not None) or "P2PC error"
            message = f"{head}: {detail}" if detail else head
            if code:
                message = f"{message} [{code}]"
        self.message = message
        super().__init__(message)


class ConfigurationError(P2PCError):
    """The client is misconfigured, for example no API key was provided."""


class InvalidResponseError(P2PCError):
    """The server answered with something the SDK cannot understand."""


class AuthenticationError(P2PCError):
    """401: the API key is missing, malformed, unknown or revoked."""


class PermissionDeniedError(P2PCError):
    """403: ``forbidden`` (missing scope), ``image_not_allowed`` or ``escalation_denied``."""


class NotFoundError(P2PCError):
    """404: the job, node, key or output does not exist."""


class ConflictError(P2PCError):
    """409: ``idempotency_conflict`` (a key reused with a different body), ``last_admin_key`` (the
    last unrestricted admin key cannot be revoked) or ``token_consumed`` (a join token that a
    node already used cannot be revoked: delete the node)."""


class CapExceededError(P2PCError):
    """402 ``cap_exceeded``: the key's daily unit cap would be exceeded."""


class UnprocessableError(P2PCError):
    """422: the server rejected the request body (``validation_failed``, ``unsupported_pool``,
    ``too_large``...). ``errors`` says which fields."""


class RateLimitError(P2PCError):
    """429: too many requests. ``retry_after`` is in seconds, when the server says."""

    def __init__(
        self,
        message: str | None = None,
        *,
        status: int | None = None,
        code: str | None = None,
        title: str | None = None,
        detail: str | None = None,
        type: str | None = None,
        errors: Sequence[FieldError] = (),
        retry_after: float | None = None,
    ) -> None:
        super().__init__(
            message, status=status, code=code, title=title, detail=detail, type=type, errors=errors
        )
        self.retry_after = retry_after


class ServerError(P2PCError):
    """5xx: the control plane failed. ``retry_after`` is in seconds, when the server says."""

    def __init__(
        self,
        message: str | None = None,
        *,
        status: int | None = None,
        code: str | None = None,
        title: str | None = None,
        detail: str | None = None,
        type: str | None = None,
        errors: Sequence[FieldError] = (),
        retry_after: float | None = None,
    ) -> None:
        super().__init__(
            message, status=status, code=code, title=title, detail=detail, type=type, errors=errors
        )
        self.retry_after = retry_after


class P2PCConnectionError(P2PCError):
    """The request never produced a response (DNS, connect, TLS, timeout, reset...)."""


class UnsafePathError(P2PCError):
    """A path would escape the destination directory."""


class ChecksumMismatchError(P2PCError):
    """A downloaded output does not match the sha256 (or size) in the listing."""
