# SPDX-License-Identifier: Apache-2.0
"""H2 additions: blobs and templates (spec §7.5, §7.6, §7.8).

These models are **not** in :mod:`p2pc.models` on purpose. ``tests/test_openapi_contract.py``
holds every model of that module against ``docs/api/openapi.json``, and the document does not
have the blob and template routes yet (they wait for their server task). The contract test has a
guard that fails the day the document gains them, as a reminder to move these models into
:mod:`p2pc.models` and its registry.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import stat
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import IO, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from p2pc.errors import P2PCError

__all__ = ["Blob", "TemplateInfo", "TemplateList", "TemplateParam", "blob_ref"]

_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_REF_RE = re.compile(r"sha256:[0-9a-f]{64}")
READ_CHUNK = 256 * 1024


class _Response(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Blob(_Response):
    """A blob of the hub: content-addressed, kept 24 hours after its last use (spec §7.5).

    ``sha256`` is the bare hex digest, as the API writes it; ``ref`` is the form a job's
    ``inputs`` use (``sha256:<hex>``). ``uploaded`` is set by ``client.blobs.put``: ``False``
    when the hub already had the blob and nothing was sent (then ``created_at`` and
    ``expires_at`` are unknown, ``None``).
    """

    sha256: str = Field(pattern=_DIGEST_RE.pattern)
    size: int = Field(ge=0)
    created_at: datetime | None = None
    expires_at: datetime | None = None
    uploaded: bool = False

    @property
    def ref(self) -> str:
        """``sha256:<hex>``, the value of an ``inputs`` entry."""
        return f"sha256:{self.sha256}"

    def __str__(self) -> str:
        return self.ref


def blob_ref(blob: Blob | str) -> str:
    """``sha256:<hex>`` of a :class:`Blob` or of a string that already is one."""
    if isinstance(blob, Blob):
        return blob.ref
    if isinstance(blob, str) and _REF_RE.fullmatch(blob):
        return blob
    raise ValueError(
        "an input blob is a Blob (from client.blobs.put) or a digest string 'sha256:<64 hex>'; "
        "a local path is never accepted"
    )


class TemplateParam(_Response):
    """A parameter of a template: ``type`` is ``enum``, ``int``, ``bool`` or ``blob``."""

    name: str
    label: str | None = None
    type: Literal["enum", "int", "bool", "blob"]
    values: list[str] | None = None
    min: int | None = None
    max: int | None = None
    default: bool | int | str | None = None
    target: str


class TemplateInfo(_Response):
    """A template as ``GET /v1/templates`` lists it."""

    id: str
    version: int
    title: str
    description: str = ""
    kind: Literal["batch", "service"]
    ui: str
    singleton: bool = False
    requirements: dict[str, Any] = Field(default_factory=dict)
    params: list[TemplateParam] = Field(default_factory=list)
    licenses: list[str] = Field(default_factory=list)
    download_mb: int = 0


class TemplateList(_Response):
    """The served template bundle: empty with ``bundle_error`` when no bundle can be loaded."""

    bundle_version: int | None = None
    templates: list[TemplateInfo] = Field(default_factory=list)
    bundle_error: str | None = None

    def __iter__(self) -> Iterator[TemplateInfo]:  # type: ignore[override]
        return iter(self.templates)

    def __len__(self) -> int:
        return len(self.templates)


class BlobFileError(P2PCError):
    """The file cannot be uploaded as a blob (not a regular file, or it changed while read)."""


@dataclass
class MeasuredFile:
    """A regular file, open, with its size and SHA-256. Read the handle, never the path again."""

    handle: IO[bytes]
    size: int
    digest: str

    def close(self) -> None:
        self.handle.close()


def hash_handle(handle: IO[bytes], size: int) -> str:
    """The SHA-256 of exactly ``size`` bytes of ``handle``.

    Raises :class:`BlobFileError` if the file yields fewer bytes, or one byte more, than ``size``:
    it changed while it was read.
    """
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = handle.read(min(READ_CHUNK, remaining))
        if not chunk:
            raise BlobFileError("the file got shorter while it was read")
        digest.update(chunk)
        remaining -= len(chunk)
    if handle.read(1):
        raise BlobFileError("the file got longer while it was read")
    return digest.hexdigest()


def measure_file(path: str | os.PathLike[str]) -> MeasuredFile:
    """Open ``path`` once, require a regular file, and hash exactly the bytes ``fstat`` sized.

    The file is opened without blocking, so a FIFO is refused instead of waiting for a writer.
    The returned handle is rewound to the start: the hash and the upload read the same
    descriptor, so what is uploaded is what was hashed or the upload fails. A file that grows or
    shrinks while it is hashed raises :class:`BlobFileError`.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise BlobFileError(f"{os.fspath(path)!r} is not a regular file")
    except BaseException:
        os.close(fd)
        raise
    handle = os.fdopen(fd, "rb")
    try:
        digest = hash_handle(handle, info.st_size)
        handle.seek(0)
        return MeasuredFile(handle, info.st_size, digest)
    except BaseException:
        handle.close()
        raise


def upload_chunks(handle: IO[bytes], size: int) -> Iterator[bytes]:
    """The body of an upload: exactly ``size`` bytes of ``handle``, never more.

    The request announces ``Content-Length: size``. If the file got shorter since it was
    measured the iterator raises, so a truncated blob is never completed; if it grew, the extra
    bytes are not read (and the hub, which hashes the body, refuses a changed file with
    ``422 digest_mismatch``).
    """
    remaining = size
    while remaining:
        chunk = handle.read(min(READ_CHUNK, remaining))
        if not chunk:
            raise BlobFileError("the file got shorter than it was when it was measured")
        remaining -= len(chunk)
        yield chunk


async def aupload_chunks(handle: IO[bytes], size: int) -> AsyncIterator[bytes]:
    """:func:`upload_chunks` for ``asyncio``: each read runs in a worker thread."""
    remaining = size
    while remaining:
        chunk = await asyncio.to_thread(handle.read, min(READ_CHUNK, remaining))
        if not chunk:
            raise BlobFileError("the file got shorter than it was when it was measured")
        remaining -= len(chunk)
        yield chunk
