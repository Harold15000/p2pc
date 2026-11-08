# SPDX-License-Identifier: Apache-2.0
"""A ``Job`` holds the client that returned it in a private attribute. It must not take part
in equality, and copies must share it (never clone an HTTP client)."""

from __future__ import annotations

import copy
import threading
from collections.abc import Callable

import httpx
import pytest
from helpers import FakeServer, job_json

from p2pc import AsyncClient, AsyncJob, Client, Job

SYNTHETIC_KEY = "p2pc_sk_abcdefghijkl_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"  # gitleaks:allow


def other_client(server: FakeServer) -> Client:
    return Client(
        api_url="https://p2pc.example.invalid",
        api_key=SYNTHETIC_KEY,
        http_client=httpx.Client(transport=httpx.MockTransport(server)),
    )


def test_equality_ignores_the_bound_client(client: Client, server: FakeServer) -> None:
    a = Job.model_validate(job_json("j"))._bind(client)
    b = Job.model_validate(job_json("j"))._bind(other_client(server))
    unbound = Job.model_validate(job_json("j"))
    assert a == b
    assert a == unbound
    assert unbound == b


def test_equality_still_compares_every_field(client: Client) -> None:
    a = Job.model_validate(job_json("j"))._bind(client)
    assert a != Job.model_validate(job_json("j", "running"))._bind(client)
    assert a != Job.model_validate(job_json("other"))._bind(client)
    changed = job_json("j")
    changed["spec"]["command"] = ["different"]
    assert a != Job.model_validate(changed)._bind(client)  # nested spec counts too
    assert a != "not a job"
    assert a != object()


def test_a_job_and_an_async_job_are_not_equal() -> None:
    assert Job.model_validate(job_json("j")) != AsyncJob.model_validate(job_json("j"))


def test_async_jobs_ignore_the_client_too(aclient: AsyncClient) -> None:
    a = AsyncJob.model_validate(job_json("j"))._bind(aclient)
    assert a == AsyncJob.model_validate(job_json("j"))
    assert a != AsyncJob.model_validate(job_json("j", "failed"))


def test_equal_jobs_are_not_hashable_by_accident() -> None:
    # Mutable models are unhashable; defining __eq__ must not silently change that.
    with pytest.raises(TypeError):
        hash(Job.model_validate(job_json("j")))


def test_shallow_copy_shares_the_client_and_the_spec(client: Client) -> None:
    job = Job.model_validate(job_json("j"))._bind(client)
    clone = copy.copy(job)
    assert clone is not job
    assert clone == job
    assert clone._client is client
    assert clone.spec is job.spec


def test_deep_copy_shares_the_client_but_copies_the_data(client: Client) -> None:
    job = Job.model_validate(job_json("j"))._bind(client)
    clone = copy.deepcopy(job)
    assert clone == job
    assert clone._client is client  # the same object, not a copy
    assert clone.spec is not job.spec
    assert clone.spec.command is not job.spec.command
    clone.spec.command.append("x")
    assert job.spec.command == ["python", "-c", "print(6*7)"]  # the original is untouched


def test_model_copy_and_deep_model_copy_share_the_client(client: Client) -> None:
    job = Job.model_validate(job_json("j"))._bind(client)
    assert job.model_copy()._client is client
    deep = job.model_copy(deep=True)
    assert deep._client is client
    assert deep.spec is not job.spec


def test_deep_copy_works_even_if_the_client_cannot_be_copied(server: FakeServer) -> None:
    # A real httpx client holds locks and sockets: deep-copying it would fail or duplicate it.
    c = Client(api_url="https://p2pc.example.invalid", api_key=SYNTHETIC_KEY)
    c._lock = threading.Lock()  # type: ignore[attr-defined]
    job = Job.model_validate(job_json("j"))._bind(c)
    assert copy.deepcopy(job)._client is c
    assert copy.deepcopy([job, job])[0]._client is c


def test_deep_copy_preserves_sharing_within_one_memo(client: Client) -> None:
    job = Job.model_validate(job_json("j"))._bind(client)
    first, second = copy.deepcopy([job, job])
    assert first is second  # the memo still maps one object to one copy


def test_unbound_jobs_copy_fine() -> None:
    job = Job.model_validate(job_json("j"))
    assert copy.deepcopy(job)._client is None
    assert copy.copy(job)._client is None


def test_a_copy_can_still_drive_the_client(client: Client, server: FakeServer) -> None:
    server.on("POST", "/v1/jobs/j/cancel", job_json("j", "cancelled"))
    job = Job.model_validate(job_json("j"))._bind(client)
    assert copy.deepcopy(job).cancel().status.value == "cancelled"


def test_async_job_copies_share_the_client(aclient: AsyncClient) -> None:
    job = AsyncJob.model_validate(job_json("j"))._bind(aclient)
    assert copy.copy(job)._client is aclient
    assert copy.deepcopy(job)._client is aclient
    assert copy.deepcopy(job) == job


@pytest.fixture
def aclient(make_aclient: Callable[..., AsyncClient]) -> AsyncClient:
    return make_aclient()
