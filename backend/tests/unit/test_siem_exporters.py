"""Contract tests for the six SIEM exporters (A2 coverage).

Covers each exporter's payload formatter (the wire shape the target SIEM
expects), the Sentinel HMAC signature, the config→exporter factory, and the
export() success/failure paths via a fake httpx client.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.siem import exporters as ex
from app.siem.exporters import (
    ChronicleExporter,
    DatadogExporter,
    ElasticExporter,
    SentinelExporter,
    SiemEvent,
    SplunkHECExporter,
    WebhookExporter,
    _sentinel_signature,
    _to_cim_lite,
    _to_ecs,
    _to_generic,
    _to_sentinel,
    _to_udm,
    build_exporters,
)

pytestmark = pytest.mark.unit


def _event(**over):
    base = dict(
        timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc),
        org_id="org-1",
        event_type="finding",
        severity="high",
        source="evaluation",
        title="Prompt injection detected",
        detail={"rule": "pi-1", "score": 0.9},
        asset_id="asset-1",
        correlation_id="corr-1",
    )
    base.update(over)
    return SiemEvent(**base)


# ── fake httpx ────────────────────────────────────────────────────────────
class _FakeResp:
    def __init__(self, status: int) -> None:
        self.status_code = status
        self.text = "ok"

    def json(self) -> dict:
        return {"errors": False}


class _FakeClient:
    status = 200
    raise_exc = False

    def __init__(self, *a, **k) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, *a, **k):
        if _FakeClient.raise_exc:
            raise RuntimeError("network down")
        return _FakeResp(_FakeClient.status)


@pytest.fixture
def fake_httpx(monkeypatch):
    _FakeClient.status = 200
    _FakeClient.raise_exc = False
    monkeypatch.setattr(ex.httpx, "AsyncClient", _FakeClient)
    return _FakeClient


# ── formatters ──────────────────────────────────────────────────────────
class TestFormatters:
    def test_cim_lite_carries_core_fields_and_detail(self):
        d = _to_cim_lite(_event())
        assert d["severity"] == "high"
        assert d["src_user_id"] == "org-1"
        assert d["object"] == "asset-1"
        assert d["rule"] == "pi-1"  # detail merged

    def test_ecs_shape(self):
        d = _to_ecs(_event())
        assert d["event"]["severity"] == "high"
        assert d["organization"]["id"] == "org-1"
        assert d["message"] == "Prompt injection detected"

    def test_sentinel_serialises_detail_as_json_string(self):
        d = _to_sentinel(_event())
        assert d["OrgId"] == "org-1"
        assert isinstance(d["Detail"], str) and "pi-1" in d["Detail"]

    def test_udm_uppercases_severity(self):
        d = _to_udm(_event())
        assert d["security_result"][0]["severity"] == "HIGH"
        assert d["principal"]["user"]["userid"] == "org-1"

    def test_generic_roundtrips_detail(self):
        d = _to_generic(_event())
        assert d["detail"] == {"rule": "pi-1", "score": 0.9}
        assert d["correlation_id"] == "corr-1"


class TestSentinelSignature:
    def test_signature_is_deterministic_and_prefixed(self):
        import base64

        key = base64.b64encode(b"secret-key-32-bytes-padding-xxxxx").decode()
        sig1 = _sentinel_signature(
            workspace_id="ws", shared_key=key, date_str="Mon, 01 Jun 2026", content_length=10
        )
        sig2 = _sentinel_signature(
            workspace_id="ws", shared_key=key, date_str="Mon, 01 Jun 2026", content_length=10
        )
        assert sig1 == sig2
        assert sig1.startswith("SharedKey ws:")


# ── factory ─────────────────────────────────────────────────────────────
class TestBuildExporters:
    def test_builds_each_type(self):
        configs = [
            {"type": "splunk_hec", "name": "s", "config": {"url": "http://x", "token": "t"}},
            {"type": "elastic", "name": "e", "config": {"url": "http://x", "index": "i"}},
            {"type": "sentinel", "name": "se", "config": {"workspace_id": "w", "shared_key": "k"}},
            {"type": "datadog", "name": "d", "config": {"api_key": "k"}},
            {"type": "chronicle", "name": "c", "config": {"customer_id": "c", "bearer_token": "k"}},
            {"type": "webhook", "name": "w", "config": {"url": "http://x"}},
        ]
        built = build_exporters(configs)
        assert len(built) == 6

    def test_unknown_type_skipped(self):
        assert build_exporters([{"type": "nope", "config": {}}]) == []

    def test_invalid_config_skipped(self):
        # missing required kwargs → TypeError → skipped, not raised
        assert build_exporters([{"type": "splunk_hec", "config": {}}]) == []

    def test_non_dict_entry_skipped(self):
        assert build_exporters(["garbage"]) == []  # type: ignore[list-item]


# ── export() paths ──────────────────────────────────────────────────────
class TestExport:
    async def test_each_exporter_reports_success(self, fake_httpx):
        evs = [_event()]
        assert await SplunkHECExporter(name="s", url="http://x", token="t").export(evs) == 1
        assert await ElasticExporter(name="e", url="http://x", index="i").export(evs) == 1
        assert await DatadogExporter(name="d", api_key="k").export(evs) == 1
        assert await WebhookExporter(name="w", url="http://x").export(evs) == 1

    async def test_empty_events_is_noop(self, fake_httpx):
        assert await WebhookExporter(name="w", url="http://x").export([]) == 0

    async def test_non_2xx_returns_zero(self, fake_httpx):
        _FakeClient.status = 500
        assert await WebhookExporter(name="w", url="http://x").export([_event()]) == 0

    async def test_network_error_returns_zero(self, fake_httpx):
        _FakeClient.raise_exc = True
        assert await WebhookExporter(name="w", url="http://x").export([_event()]) == 0
