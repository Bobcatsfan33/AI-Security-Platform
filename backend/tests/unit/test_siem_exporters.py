"""Unit tests for SIEM exporters.

We don't hit real SIEM endpoints — every test replaces ``httpx.AsyncClient``
with a fake that records the outgoing requests. This exercises the
shape of each adapter (headers, URL, body schema) without network IO.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import pytest

from app.siem import exporters
from app.siem.exporters import (
    ChronicleExporter,
    DatadogExporter,
    ElasticExporter,
    SentinelExporter,
    SiemEvent,
    SplunkHECExporter,
    WebhookExporter,
    build_exporters,
    export_to_all,
)


# ─────────────────────────────────────── fixtures


def _event() -> SiemEvent:
    return SiemEvent(
        timestamp=datetime(2026, 5, 13, 12, 0, 0, tzinfo=timezone.utc),
        org_id="00000000-0000-0000-0000-000000000001",
        event_type="finding",
        severity="high",
        source="evaluation",
        title="Prompt injection succeeded",
        detail={"category": "prompt_injection", "risk_score": 0.85},
        asset_id="00000000-0000-0000-0000-0000000000aa",
        correlation_id="11111111-1111-1111-1111-111111111111",
    )


class _FakeResponse:
    def __init__(self, status_code: int = 200, body: dict[str, Any] | None = None):
        self.status_code = status_code
        self.text = json.dumps(body or {})

    def json(self) -> dict[str, Any]:
        return json.loads(self.text)


class _RecordingClient:
    """Replacement for httpx.AsyncClient that captures the POST."""

    instances: list["_RecordingClient"] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.posts: list[dict[str, Any]] = []
        self.timeout = kwargs.get("timeout")
        _RecordingClient.instances.append(self)

    async def __aenter__(self) -> "_RecordingClient":
        return self

    async def __aexit__(self, *a: Any) -> None:
        return None

    async def post(
        self,
        url: str,
        *,
        content: Any = None,
        headers: dict[str, str] | None = None,
        auth: Any = None,
    ) -> _FakeResponse:
        self.posts.append(
            {
                "url": url,
                "content": content if isinstance(content, str) else (
                    content.decode() if isinstance(content, bytes) else content
                ),
                "headers": headers or {},
                "auth": auth,
            }
        )
        # Elastic bulk requires a parsable JSON response with .errors=false
        if "/_bulk" in url:
            return _FakeResponse(200, {"errors": False, "items": []})
        return _FakeResponse(200)


@pytest.fixture(autouse=True)
def _patch_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    _RecordingClient.instances = []
    monkeypatch.setattr(exporters.httpx, "AsyncClient", _RecordingClient)


# ─────────────────────────────────────── per-backend tests


def test_splunk_hec_exporter_shape() -> None:
    ex = SplunkHECExporter(
        name="prod", url="https://splunk.example", token="HEC-TOKEN", index="ai"
    )
    n = asyncio.run(ex.export([_event(), _event()]))
    assert n == 2
    assert len(_RecordingClient.instances) == 1
    post = _RecordingClient.instances[0].posts[0]
    assert post["url"].endswith("/services/collector/event")
    assert post["headers"]["Authorization"] == "Splunk HEC-TOKEN"
    # Splunk HEC accepts concatenated JSON objects; split them with raw_decode.
    decoder = json.JSONDecoder()
    body = post["content"]
    decoded: list[dict[str, Any]] = []
    idx = 0
    while idx < len(body):
        obj, end = decoder.raw_decode(body, idx)
        decoded.append(obj)
        idx = end
    assert len(decoded) == 2
    assert all(d["index"] == "ai" for d in decoded)
    assert all(d["event"]["event_type"] == "finding" for d in decoded)


def test_elastic_exporter_bulk_format() -> None:
    ex = ElasticExporter(
        name="siem",
        url="https://es.example",
        index="ai-security",
        api_key="ABC",
    )
    n = asyncio.run(ex.export([_event()]))
    assert n == 1
    post = _RecordingClient.instances[0].posts[0]
    assert post["url"].endswith("/_bulk")
    assert post["headers"]["Authorization"] == "ApiKey ABC"
    lines = [line for line in post["content"].split("\n") if line]
    assert len(lines) == 2
    action = json.loads(lines[0])
    doc = json.loads(lines[1])
    assert action == {"index": {"_index": "ai-security"}}
    assert doc["@timestamp"].startswith("2026-05-13")
    assert doc["event"]["severity"] == "high"


def test_sentinel_signature_present() -> None:
    ex = SentinelExporter(
        name="ws",
        workspace_id="dead-beef",
        shared_key="dGVzdC1rZXk=",  # base64("test-key")
    )
    asyncio.run(ex.export([_event()]))
    headers = _RecordingClient.instances[0].posts[0]["headers"]
    assert headers["Log-Type"] == "AiSecurity"
    assert headers["Authorization"].startswith("SharedKey dead-beef:")
    assert "x-ms-date" in headers


def test_datadog_logs_payload() -> None:
    ex = DatadogExporter(name="dd", api_key="DD-KEY")
    asyncio.run(ex.export([_event()]))
    post = _RecordingClient.instances[0].posts[0]
    assert post["headers"]["DD-API-KEY"] == "DD-KEY"
    arr = json.loads(post["content"])
    assert isinstance(arr, list)
    assert arr[0]["ddtags"].startswith("event_type:finding")
    assert arr[0]["attributes"]["asset_id"].endswith("00aa")


def test_chronicle_udm_payload() -> None:
    ex = ChronicleExporter(
        name="chr",
        customer_id="cust-1",
        bearer_token="BEARER",
    )
    asyncio.run(ex.export([_event()]))
    post = _RecordingClient.instances[0].posts[0]
    assert post["headers"]["Authorization"] == "Bearer BEARER"
    body = json.loads(post["content"])
    assert "events" in body
    assert body["events"][0]["security_result"][0]["severity"] == "HIGH"


def test_webhook_generic_payload() -> None:
    ex = WebhookExporter(
        name="hook",
        url="https://example/incoming",
        headers={"X-Custom": "1"},
    )
    asyncio.run(ex.export([_event()]))
    post = _RecordingClient.instances[0].posts[0]
    assert post["headers"]["X-Custom"] == "1"
    assert post["headers"]["Content-Type"] == "application/json"
    body = json.loads(post["content"])
    assert body["events"][0]["event_type"] == "finding"


def test_export_to_all_aggregates_counts() -> None:
    exs = [
        WebhookExporter(name="hook-1", url="https://a.example"),
        WebhookExporter(name="hook-2", url="https://b.example"),
    ]
    result = asyncio.run(export_to_all(exs, [_event(), _event(), _event()]))
    assert result == {"hook-1": 3, "hook-2": 3}


def test_exporter_swallows_network_errors() -> None:
    class _Boom(_RecordingClient):
        async def post(self, *a: Any, **kw: Any) -> _FakeResponse:  # type: ignore[override]
            raise RuntimeError("network down")

    exporters.httpx.AsyncClient = _Boom  # type: ignore[assignment]
    try:
        ex = WebhookExporter(name="hook", url="https://example")
        # Must not raise even though the network call errors out.
        n = asyncio.run(ex.export([_event()]))
        assert n == 0
    finally:
        exporters.httpx.AsyncClient = _RecordingClient  # type: ignore[assignment]


def test_build_exporters_skips_unknown_types() -> None:
    out = build_exporters(
        [
            {"type": "splunk_hec", "name": "s", "config": {"url": "u", "token": "t"}},
            {"type": "unknown", "name": "x", "config": {}},
            {"type": "datadog", "name": "d", "config": {"api_key": "k"}},
        ]
    )
    names = [ex.name for ex in out]
    assert names == ["s", "d"]


def test_build_exporters_skips_invalid_config() -> None:
    out = build_exporters(
        [
            # Missing required field "token" — TypeError is caught
            {"type": "splunk_hec", "name": "s", "config": {"url": "u"}},
        ]
    )
    assert out == []
