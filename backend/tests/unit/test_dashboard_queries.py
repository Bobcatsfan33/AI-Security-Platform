"""Tests for dashboard ClickHouse queries.

We don't run a real ClickHouse. The fake client records the SQL it sees
and returns canned rows so we can assert on shape + parameter handling.
"""

from __future__ import annotations

import uuid

import pytest

from app.telemetry import clickhouse_writer, dashboard_queries


class _FakeResult:
    def __init__(self, columns: list[str], rows: list[tuple]) -> None:
        self.column_names = columns
        self.result_rows = rows


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        # Map a substring of the query to canned (columns, rows).
        self.responses: dict[str, tuple[list[str], list[tuple]]] = {}

    def query(self, query: str, parameters: dict | None = None) -> _FakeResult:
        self.calls.append((query, parameters or {}))
        for needle, payload in self.responses.items():
            if needle in query:
                return _FakeResult(*payload)
        return _FakeResult(["count"], [(0,)])


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr(dashboard_queries, "_get_client", lambda: client)
    return client


def test_runtime_overview_parses_summary(fake_client: _FakeClient) -> None:
    fake_client.responses["count() AS total"] = (
        ["total", "blocked", "avg_latency", "p50", "p95", "p99"],
        [(1000, 50, 142.5, 100, 250, 800)],
    )
    fake_client.responses["GROUP BY event_type"] = (
        ["event_type", "count"],
        [("request", 600), ("response", 400)],
    )
    fake_client.responses["GROUP BY pipeline_exit_stage"] = (
        ["pipeline_exit_stage", "count"],
        [("no_match", 950), ("stage1_regex", 50)],
    )
    fake_client.responses["GROUP BY bucket"] = (
        ["bucket", "count", "blocked"],
        [("2026-05-13T10:00:00", 500, 25), ("2026-05-13T11:00:00", 500, 25)],
    )

    org_id = uuid.uuid4()
    result = dashboard_queries.runtime_overview(org_id=org_id, time_range="24h")

    assert result.total_events == 1000
    assert result.blocked_events == 50
    assert result.block_rate_pct == 5.0
    assert result.p95_latency_ms == 250.0
    assert result.by_event_type == [
        {"event_type": "request", "count": 600},
        {"event_type": "response", "count": 400},
    ]
    assert len(result.timeline) == 2

    # Every query must be parameterised by org_id
    for query, params in fake_client.calls:
        assert "org_id" in params
        assert params["org_id"] == org_id


def test_runtime_overview_handles_no_data(fake_client: _FakeClient) -> None:
    # No responses configured — every call returns count=0
    result = dashboard_queries.runtime_overview(
        org_id=uuid.uuid4(), time_range="1h"
    )
    assert result.total_events == 0
    assert result.block_rate_pct == 0.0
    assert result.by_event_type == [{"count": 0}]  # default fallback


def test_traffic_by_asset_query_includes_limit(fake_client: _FakeClient) -> None:
    fake_client.responses["GROUP BY asset_id"] = (
        ["asset_id", "total_events", "inbound", "outbound", "blocked",
         "avg_latency_ms", "estimated_cost_usd", "token_input", "token_output"],
        [
            (
                "11111111-1111-1111-1111-111111111111",
                100, 50, 50, 5, 120.0, 0.42, 5000, 8000,
            ),
        ],
    )
    org_id = uuid.uuid4()
    result = dashboard_queries.traffic_by_asset(
        org_id=org_id, time_range="7d", limit=25
    )
    assert len(result.rows) == 1
    assert result.rows[0]["total_events"] == 100
    # limit must be passed as a parameter
    call = fake_client.calls[0]
    assert call[1]["limit"] == 25


def test_policy_effectiveness_aggregates_stages(fake_client: _FakeClient) -> None:
    fake_client.responses["countIf(pipeline_exit_stage = 'stage1_regex')"] = (
        ["s1", "s2", "s3", "nm", "s1_avg", "s2_avg", "s3_avg"],
        [(120, 30, 5, 845, 50.0, 1200.0, 145.0)],
    )
    fake_client.responses["GROUP BY block_reason"] = (
        ["block_reason", "count"],
        [("prompt_injection", 25), ("pii_leak", 10)],
    )
    org_id = uuid.uuid4()
    result = dashboard_queries.policy_effectiveness(
        org_id=org_id, time_range="24h"
    )
    assert result.stage1_hits == 120
    assert result.stage2_hits == 30
    assert result.stage3_hits == 5
    assert result.no_match == 845
    assert result.stage1_avg_us == 50.0
    assert result.top_block_reasons[0]["block_reason"] == "prompt_injection"


def test_query_swallows_clickhouse_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom:
        def query(self, *a, **kw):
            raise RuntimeError("ch down")

    monkeypatch.setattr(dashboard_queries, "_get_client", lambda: _Boom())
    result = dashboard_queries.runtime_overview(
        org_id=uuid.uuid4(), time_range="1h"
    )
    # Must degrade to zero-state, not raise
    assert result.total_events == 0


def test_query_returns_empty_when_clickhouse_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dashboard_queries, "_get_client", lambda: None)
    result = dashboard_queries.traffic_by_asset(org_id=uuid.uuid4())
    assert result.rows == []


def test_time_range_maps_to_correct_interval() -> None:
    # exercise every supported range
    for tr in ("1h", "6h", "24h", "7d", "30d"):
        interval = dashboard_queries._range_interval(tr)  # type: ignore[arg-type]
        assert "INTERVAL" in interval
