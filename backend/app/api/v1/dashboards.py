"""Dashboard query routes — read-only aggregations over ClickHouse.

All endpoints require the ``analyst`` role at minimum and are scoped to
the authenticated org_id. Time-range is the only knob exposed in v1.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.auth.dependencies import require_role
from app.identity.types import IdentityContext
from app.telemetry import dashboard_queries as q

router = APIRouter(tags=["dashboards"])

TimeRange = Literal["1h", "6h", "24h", "7d", "30d"]


class RuntimeOverviewResponse(BaseModel):
    time_range: TimeRange
    total_events: int
    blocked_events: int
    block_rate_pct: float
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    by_event_type: list[dict[str, Any]] = Field(default_factory=list)
    by_pipeline_exit_stage: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)


class TrafficByAssetResponse(BaseModel):
    time_range: TimeRange
    rows: list[dict[str, Any]]


class PolicyEffectivenessResponse(BaseModel):
    time_range: TimeRange
    stage1_hits: int
    stage2_hits: int
    stage3_hits: int
    no_match: int
    stage1_avg_us: float
    stage2_avg_us: float
    stage3_avg_ms: float
    top_block_reasons: list[dict[str, Any]] = Field(default_factory=list)


@router.get("/runtime", response_model=RuntimeOverviewResponse)
async def runtime_overview(
    time_range: TimeRange = Query("24h"),
    identity: IdentityContext = Depends(require_role("analyst")),
) -> RuntimeOverviewResponse:
    summary = q.runtime_overview(org_id=identity.org_id, time_range=time_range)
    return RuntimeOverviewResponse(
        time_range=summary.time_range,
        total_events=summary.total_events,
        blocked_events=summary.blocked_events,
        block_rate_pct=summary.block_rate_pct,
        avg_latency_ms=summary.avg_latency_ms,
        p50_latency_ms=summary.p50_latency_ms,
        p95_latency_ms=summary.p95_latency_ms,
        p99_latency_ms=summary.p99_latency_ms,
        by_event_type=summary.by_event_type,
        by_pipeline_exit_stage=summary.by_pipeline_exit_stage,
        timeline=summary.timeline,
    )


@router.get("/traffic", response_model=TrafficByAssetResponse)
async def traffic_by_asset(
    time_range: TimeRange = Query("24h"),
    limit: int = Query(50, ge=1, le=200),
    identity: IdentityContext = Depends(require_role("analyst")),
) -> TrafficByAssetResponse:
    result = q.traffic_by_asset(
        org_id=identity.org_id, time_range=time_range, limit=limit
    )
    return TrafficByAssetResponse(time_range=result.time_range, rows=result.rows)


@router.get("/policy-effectiveness", response_model=PolicyEffectivenessResponse)
async def policy_effectiveness(
    time_range: TimeRange = Query("24h"),
    identity: IdentityContext = Depends(require_role("analyst")),
) -> PolicyEffectivenessResponse:
    result = q.policy_effectiveness(
        org_id=identity.org_id, time_range=time_range
    )
    return PolicyEffectivenessResponse(
        time_range=result.time_range,
        stage1_hits=result.stage1_hits,
        stage2_hits=result.stage2_hits,
        stage3_hits=result.stage3_hits,
        no_match=result.no_match,
        stage1_avg_us=result.stage1_avg_us,
        stage2_avg_us=result.stage2_avg_us,
        stage3_avg_ms=result.stage3_avg_ms,
        top_block_reasons=result.top_block_reasons,
    )
