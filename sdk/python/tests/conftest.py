# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from helpers import API_URL, KEY, FakeClock, FakeServer

from p2pc import AsyncClient, Client


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never depend on the developer's real configuration."""
    monkeypatch.delenv("P2PC_API_URL", raising=False)
    monkeypatch.delenv("P2PC_API_KEY", raising=False)


@pytest.fixture
def server() -> FakeServer:
    return FakeServer()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def make_client(server: FakeServer, clock: FakeClock) -> Callable[..., Client]:
    def factory(**kwargs: object) -> Client:
        kwargs.setdefault("api_url", API_URL)
        kwargs.setdefault("api_key", KEY)
        kwargs.setdefault("http_client", httpx.Client(transport=httpx.MockTransport(server)))
        client = Client(**kwargs)  # type: ignore[arg-type]
        client._sleep = clock.sleep
        client._monotonic = clock.monotonic
        return client

    return factory


@pytest.fixture
def client(make_client: Callable[..., Client]) -> Client:
    return make_client()


@pytest.fixture
def make_aclient(server: FakeServer, clock: FakeClock) -> Callable[..., AsyncClient]:
    def factory(**kwargs: object) -> AsyncClient:
        kwargs.setdefault("api_url", API_URL)
        kwargs.setdefault("api_key", KEY)
        kwargs.setdefault("http_client", httpx.AsyncClient(transport=httpx.MockTransport(server)))
        client = AsyncClient(**kwargs)  # type: ignore[arg-type]
        client._sleep = clock.asleep
        client._monotonic = clock.monotonic
        return client

    return factory
