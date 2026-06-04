"""Tests for SOAR incident sinks: factory + open() success/failure (A2)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.soar import incidents as soar
from app.soar.incidents import (
    Incident,
    OpsgenieSink,
    PagerDutySink,
    WebhookSink,
    build_adapters,
    open_in_all,
)

pytestmark = pytest.mark.unit


def _incident(**over):
    base = dict(
        org_id="org-1",
        title="Critical: propagation chain",
        severity="critical",
        description="multi-agent injection",
        source="epa_fleet",
        asset_id="asset-1",
        correlation_id="flow-1",
        detected_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        detail={"agents": ["A", "B"]},
    )
    base.update(over)
    return Incident(**base)


class _FakeResp:
    def __init__(self, status: int) -> None:
        self.status_code = status
        self.text = "ok"


class _FakeClient:
    status = 202
    raise_exc = False

    def __init__(self, *a, **k) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, *a, **k):
        if _FakeClient.raise_exc:
            raise RuntimeError("down")
        return _FakeResp(_FakeClient.status)


@pytest.fixture
def fake_httpx(monkeypatch):
    _FakeClient.status = 202
    _FakeClient.raise_exc = False
    monkeypatch.setattr(soar.httpx, "AsyncClient", _FakeClient)
    return _FakeClient


class TestBuildAdapters:
    def test_builds_each_type(self):
        configs = [
            {"type": "pagerduty", "name": "pd", "config": {"routing_key": "k"}},
            {"type": "opsgenie", "name": "og", "config": {"api_key": "k"}},
            {"type": "webhook", "name": "wh", "config": {"url": "http://x"}},
        ]
        assert len(build_adapters(configs)) == 3

    def test_unknown_and_invalid_skipped(self):
        assert build_adapters([{"type": "nope"}]) == []
        assert build_adapters([{"type": "pagerduty", "config": {}}]) == []  # missing routing_key
        assert build_adapters(["x"]) == []  # type: ignore[list-item]


class TestOpen:
    async def test_pagerduty_open_success(self, fake_httpx):
        assert await PagerDutySink(name="pd", routing_key="k").open(_incident()) is True

    async def test_opsgenie_open_success(self, fake_httpx):
        assert await OpsgenieSink(name="og", api_key="k").open(_incident()) is True

    async def test_webhook_open_success(self, fake_httpx):
        assert await WebhookSink(name="wh", url="http://x").open(_incident()) is True

    async def test_non_2xx_is_false(self, fake_httpx):
        _FakeClient.status = 500
        assert await WebhookSink(name="wh", url="http://x").open(_incident()) is False

    async def test_network_error_is_false(self, fake_httpx):
        _FakeClient.raise_exc = True
        assert await WebhookSink(name="wh", url="http://x").open(_incident()) is False

    async def test_open_in_all_isolates_failures(self, fake_httpx):
        sinks = [WebhookSink(name="a", url="http://x"), WebhookSink(name="b", url="http://y")]
        out = await open_in_all(sinks, _incident())
        assert out == {"a": True, "b": True}
