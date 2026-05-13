"""Dashboard queries against the ClickHouse ``runtime_events`` table.

This module owns the read-side aggregations the dashboard pages need:

  - runtime overview  : event volume + block rate + p50/p95 latency
  - traffic           : per-asset breakdown by event_type / direction
  - policy effectiveness : Stage 1 vs Stage 2 vs Stage 3 hit rates

Queries are parameterised to prevent SQL injection — ClickHouse-connect's
``parameters=`` arg handles binding. All queries are scoped by org_id.
If ClickHouse is unavailable the functions return an empty-but-typed
shape so the dashboard renders gracefully.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any, Literal

from app.telemetry.clickhouse_writer import CLICKHOUSE_TABLE, _get_client

logger = logging.getLogger("platform.dashboards")

TimeRange = Literal["1h", "6h", "24h", "7d", "30d"]


@dataclass(frozen=True)
class RuntimeOverview:
    time_range: TimeRange
    total_events: int
    blocked_events: int
    block_rate_pct: float
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    by_event_type: list[dict[str, Any]]
    by_pipeline_exit_stage: list[dict[str, Any]]
    timeline: list[dict[str, Any]]  # per-bucket event counts


@dataclass(frozen=True)
class TrafficByAsset:
    time_range: TimeRange
    rows: list[dict[str, Any]]  # one per asset


@dataclass(frozen=True)
class PolicyEffectiveness:
    time_range: TimeRange
    stage1_hits: int
    stage2_hits: int
    stage3_hits: int
    no_match: int
    stage1_avg_us: float
    stage2_avg_us: float
    stage3_avg_ms: float
    top_block_reasons: list[dict[str, Any]]


def _range_interval(time_range: TimeRange) -> str:
    return {
        "1h": "INTERVAL 1 HOUR",
        "6h": "INTERVAL 6 HOUR",
        "24h": "INTERVAL 24 HOUR",
        "7d": "INTERVAL 7 DAY",
        "30d": "INTERVAL 30 DAY",
    }[time_range]


def _bucket_function(time_range: TimeRange) -> str:
    """Pick a granularity matching the time range."""
    return {
        "1h": "toStartOfMinute",
        "6h": "toStartOfFiveMinute",
        "24h": "toStartOfFifteenMinutes",
        "7d": "toStartOfHour",
        "30d": "toStartOfHour",
    }[time_range]


def _safe_query(query: str, parameters: dict[str, Any]) -> list[dict[str, Any]]:
    """Issue a parameterised query, return list-of-dicts. Fail-soft."""
    client = _get_client()
    if client is None:
        return []
    try:
        result = client.query(query, parameters=parameters)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "clickhouse_query_failed",
            extra={"error": str(exc), "query_prefix": query[:80]},
        )
        return []
    columns = list(result.column_names)
    return [dict(zip(columns, row)) for row in result.result_rows]


# ──────────────────────────────────────────────── runtime overview


def runtime_overview(
    *, org_id: uuid.UUID, time_range: TimeRange = "24h"
) -> RuntimeOverview:
    interval = _range_interval(time_range)
    bucket = _bucket_function(time_range)

    summary_rows = _safe_query(
        f"""
        SELECT
            count() AS total,
            countIf(event_type IN ('block', 'kill_switch')) AS blocked,
            avg(latency_ms) AS avg_latency,
            quantile(0.50)(latency_ms) AS p50,
            quantile(0.95)(latency_ms) AS p95,
            quantile(0.99)(latency_ms) AS p99
        FROM {CLICKHOUSE_TABLE}
        WHERE org_id = {{org_id:UUID}}
          AND timestamp >= now() - {interval}
        """,
        {"org_id": org_id},
    )
    summary = summary_rows[0] if summary_rows else {}
    total = int(summary.get("total", 0) or 0)
    blocked = int(summary.get("blocked", 0) or 0)

    by_type = _safe_query(
        f"""
        SELECT event_type, count() AS count
        FROM {CLICKHOUSE_TABLE}
        WHERE org_id = {{org_id:UUID}}
          AND timestamp >= now() - {interval}
        GROUP BY event_type
        ORDER BY count DESC
        """,
        {"org_id": org_id},
    )

    by_stage = _safe_query(
        f"""
        SELECT pipeline_exit_stage, count() AS count
        FROM {CLICKHOUSE_TABLE}
        WHERE org_id = {{org_id:UUID}}
          AND timestamp >= now() - {interval}
        GROUP BY pipeline_exit_stage
        ORDER BY count DESC
        """,
        {"org_id": org_id},
    )

    timeline = _safe_query(
        f"""
        SELECT
            {bucket}(timestamp) AS bucket,
            count() AS count,
            countIf(event_type IN ('block', 'kill_switch')) AS blocked
        FROM {CLICKHOUSE_TABLE}
        WHERE org_id = {{org_id:UUID}}
          AND timestamp >= now() - {interval}
        GROUP BY bucket
        ORDER BY bucket
        """,
        {"org_id": org_id},
    )

    block_rate = (100.0 * blocked / total) if total else 0.0
    return RuntimeOverview(
        time_range=time_range,
        total_events=total,
        blocked_events=blocked,
        block_rate_pct=round(block_rate, 2),
        avg_latency_ms=float(summary.get("avg_latency") or 0.0),
        p50_latency_ms=float(summary.get("p50") or 0.0),
        p95_latency_ms=float(summary.get("p95") or 0.0),
        p99_latency_ms=float(summary.get("p99") or 0.0),
        by_event_type=by_type,
        by_pipeline_exit_stage=by_stage,
        timeline=timeline,
    )


# ──────────────────────────────────────────────── traffic by asset


def traffic_by_asset(
    *, org_id: uuid.UUID, time_range: TimeRange = "24h", limit: int = 50
) -> TrafficByAsset:
    interval = _range_interval(time_range)
    rows = _safe_query(
        f"""
        SELECT
            asset_id,
            count() AS total_events,
            countIf(direction = 'inbound') AS inbound,
            countIf(direction = 'outbound') AS outbound,
            countIf(event_type IN ('block', 'kill_switch')) AS blocked,
            avg(latency_ms) AS avg_latency_ms,
            sum(estimated_cost_usd) AS estimated_cost_usd,
            sum(token_count_input) AS token_input,
            sum(token_count_output) AS token_output
        FROM {CLICKHOUSE_TABLE}
        WHERE org_id = {{org_id:UUID}}
          AND timestamp >= now() - {interval}
        GROUP BY asset_id
        ORDER BY total_events DESC
        LIMIT {{limit:UInt32}}
        """,
        {"org_id": org_id, "limit": limit},
    )
    return TrafficByAsset(time_range=time_range, rows=rows)


# ──────────────────────────────────────────────── policy effectiveness


def policy_effectiveness(
    *, org_id: uuid.UUID, time_range: TimeRange = "24h"
) -> PolicyEffectiveness:
    interval = _range_interval(time_range)

    stage_rows = _safe_query(
        f"""
        SELECT
            countIf(pipeline_exit_stage = 'stage1_regex') AS s1,
            countIf(pipeline_exit_stage = 'stage2_ml') AS s2,
            countIf(pipeline_exit_stage = 'stage3_judge') AS s3,
            countIf(pipeline_exit_stage = 'no_match') AS nm,
            avg(stage1_latency_us) AS s1_avg,
            avg(stage2_latency_us) AS s2_avg,
            avg(stage3_latency_ms) AS s3_avg
        FROM {CLICKHOUSE_TABLE}
        WHERE org_id = {{org_id:UUID}}
          AND timestamp >= now() - {interval}
        """,
        {"org_id": org_id},
    )
    row = stage_rows[0] if stage_rows else {}

    reasons = _safe_query(
        f"""
        SELECT block_reason, count() AS count
        FROM {CLICKHOUSE_TABLE}
        WHERE org_id = {{org_id:UUID}}
          AND timestamp >= now() - {interval}
          AND block_reason != ''
        GROUP BY block_reason
        ORDER BY count DESC
        LIMIT 10
        """,
        {"org_id": org_id},
    )

    return PolicyEffectiveness(
        time_range=time_range,
        stage1_hits=int(row.get("s1", 0) or 0),
        stage2_hits=int(row.get("s2", 0) or 0),
        stage3_hits=int(row.get("s3", 0) or 0),
        no_match=int(row.get("nm", 0) or 0),
        stage1_avg_us=float(row.get("s1_avg") or 0.0),
        stage2_avg_us=float(row.get("s2_avg") or 0.0),
        stage3_avg_ms=float(row.get("s3_avg") or 0.0),
        top_block_reasons=reasons,
    )
