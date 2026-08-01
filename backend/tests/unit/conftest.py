"""Shared unit-test fixtures for connectors that speak HTTP.

The provider adapters build their own ``httpx.AsyncClient`` inside the
request path (deliberately — see the module docstrings in
``app/connectors/``), so there is no transport seam to inject. These
fixtures give the tests one: ``http_stub`` swaps the ``httpx.AsyncClient``
constructor for one bound to an ``httpx.MockTransport``, and records every
request the adapter actually put on the wire.

That matters for coverage honesty. Asserting on the recorded request is an
assertion about the provider contract — which URL, which auth header, which
body shape — not about which lines ran. ``fast_sleep`` removes real backoff
delay while still executing the adapters' ``_backoff`` code and recording
the delays it asked for, so retry policy stays observable.

No fixture here writes a credential anywhere but an in-process env var that
pytest removes at teardown, and none of them log request bodies.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

import httpx
import pytest


@dataclass
class HttpStub:
    """Records what an adapter sent and replays a scripted response."""

    requests: list[httpx.Request] = field(default_factory=list)

    @property
    def call_count(self) -> int:
        return len(self.requests)

    @property
    def last_request(self) -> httpx.Request:
        if not self.requests:
            raise AssertionError("adapter made no HTTP request")
        return self.requests[-1]


@pytest.fixture
def http_stub(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., HttpStub]]:
    """Return an installer: ``install(handler)`` or ``install(responses=[...])``.

    ``responses`` is a scripted sequence; the last entry repeats once the
    script is exhausted, so "fails twice then succeeds" reads literally.
    Each entry is an ``httpx.Response`` or an exception instance to raise.
    """
    real_client = httpx.AsyncClient

    def install(
        handler: Callable[[httpx.Request], httpx.Response] | None = None,
        *,
        responses: list[object] | None = None,
    ) -> HttpStub:
        stub = HttpStub()

        if handler is None:
            if not responses:
                raise ValueError("pass either handler or a non-empty responses list")
            script = list(responses)

            def handler(request: httpx.Request) -> httpx.Response:
                entry = script[min(len(stub.requests) - 1, len(script) - 1)]
                if isinstance(entry, Exception):
                    raise entry
                assert isinstance(entry, httpx.Response)
                # A Response may be replayed; hand back a fresh one so httpx
                # never reads a consumed stream.
                return httpx.Response(
                    status_code=entry.status_code,
                    headers=entry.headers,
                    content=entry.content,
                )

        assert handler is not None
        inner = handler

        def recording(request: httpx.Request) -> httpx.Response:
            stub.requests.append(request)
            return inner(request)

        def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
            kwargs.pop("transport", None)
            return real_client(*args, transport=httpx.MockTransport(recording), **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", factory)
        return stub

    yield install


@pytest.fixture
def fast_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Run backoff for real but without the wall-clock cost.

    Returns the list of delays the code under test asked to sleep for, so a
    test can assert that retry policy actually backed off rather than only
    that it looped.
    """
    delays: list[float] = []
    real_sleep = asyncio.sleep

    async def instant(delay: float, *args: object, **kwargs: object) -> object:
        delays.append(delay)
        return await real_sleep(0, *args, **kwargs)

    monkeypatch.setattr(asyncio, "sleep", instant)
    return delays
