"""Unit tests for SOAR incident sinks (PagerDuty / Opsgenie / Webhook)."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

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


def _incident() -> Incident:
    return Incident(
        org_id="00000000-0000-0000-0000-000000000001",
        title="High-severity finding detected",
        severity="high",
        description="Prompt injection succeeded on production asset.",
        source="evaluation",
        asset_id="00000000-0000-0000-0000-0000000000aa",
        correlation_id="corr-1",
        detected_at=datetime(2026, 5, 13, 12, 0, tzinfo=timezone.utc),
        detail={"category": "prompt_injection"},
    )


class _RecordingClient:
    instances: list["_RecordingClient"] = []

    def __init__(self, *a: Any, **kw: Any) -> None:
        self.posts: list[dict[str, Any]] = []
        _RecordingClient.instances.append(self)

    async def __aenter__(self) -> "_RecordingClient":
        return self

    async def __aexit__(self, *a: Any) -> None:
        return None

    async def post(self, url: str, *, content: Any = None, headers: dict | None = None) -> Any:
        self.posts.append({"url": url, "content": content, "headers": headers or {}})

        class R:
            status_code = 202
            text = "{}"

        return R()


@pytest.fixture(autouse=True)
def _patch_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    _RecordingClient.instances = []
    monkeypatch.setattr(soar.httpx, "AsyncClient", _RecordingClient)


def test_pagerduty_uses_events_api_and_maps_severity() -> None:
    sink = PagerDutySink(name="prod", routing_key="R-KEY")
    asyncio.run(sink.open(_incident()))
    post = _RecordingClient.instances[0].posts[0]
    assert post["url"].endswith("/v2/enqueue")
    body = json.loads(post["content"])
    assert body["routing_key"] == "R-KEY"
    assert body["payload"]["severity"] == "error"  # high → error
    assert body["payload"]["component"].endswith("00aa")


def test_opsgenie_priority_mapping_and_team() -> None:
    sink = OpsgenieSink(name="og", api_key="K", team="oncall", region="us")
    asyncio.run(sink.open(_incident()))
    post = _RecordingClient.instances[0].posts[0]
    assert post["url"] == "https://api.opsgenie.com/v2/alerts"
    body = json.loads(post["content"])
    assert body["priority"] == "P2"
    assert body["responders"] == [{"type": "team", "name": "oncall"}]


def test_webhook_passes_through_custom_headers() -> None:
    sink = WebhookSink(
        name="hook", url="https://example/hook", headers={"X-Sig": "abc"}
    )
    asyncio.run(sink.open(_incident()))
    post = _RecordingClient.instances[0].posts[0]
    assert post["headers"]["X-Sig"] == "abc"
    assert post["headers"]["Content-Type"] == "application/json"


def test_build_adapters_skips_invalid_entries() -> None:
    out = build_adapters(
        [
            {"type": "pagerduty", "name": "p", "config": {"routing_key": "k"}},
            {"type": "unknown", "name": "x", "config": {}},
            {"type": "pagerduty", "name": "missing", "config": {}},  # invalid
        ]
    )
    assert [a.name for a in out] == ["p"]


def test_open_in_all_returns_per_sink_status() -> None:
    sinks = [
        WebhookSink(name="a", url="https://example/a"),
        WebhookSink(name="b", url="https://example/b"),
    ]
    result = asyncio.run(open_in_all(sinks, _incident()))
    assert result == {"a": True, "b": True}


def test_sink_swallows_network_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Crashing:
        def __init__(self, *a: Any, **kw: Any) -> None: ...
        async def __aenter__(self) -> "_Crashing": return self
        async def __aexit__(self, *a: Any) -> None: return None
        async def post(self, *a: Any, **kw: Any) -> Any:
            raise RuntimeError("down")

    monkeypatch.setattr(soar.httpx, "AsyncClient", _Crashing)
    sink = WebhookSink(name="w", url="https://example")
    assert asyncio.run(sink.open(_incident())) is False
