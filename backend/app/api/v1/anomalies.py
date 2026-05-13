"""Attack graph + anomaly detection routes."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.anomaly.attack_graph import build_attack_graph
from app.anomaly.detector import Anomaly, detect_for_asset
from app.auth.dependencies import require_role
from app.identity.types import IdentityContext

router = APIRouter(tags=["anomalies"])


Window = Literal["1h", "6h", "24h", "7d"]


class AttackGraphResponse(BaseModel):
    org_id: str
    asset_id: str
    window: str
    total_events: int
    session_count: int
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)


class AnomalyResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    asset_id: uuid.UUID
    detected_at: datetime
    kind: Literal["volume_spike", "novel_transition", "risk_inflation"]
    severity: Literal["info", "low", "medium", "high", "critical"]
    title: str
    detail: dict[str, Any]


def _serialise(a: Anomaly) -> AnomalyResponse:
    return AnomalyResponse(
        id=a.id,
        org_id=a.org_id,
        asset_id=a.asset_id,
        detected_at=a.detected_at,
        kind=a.kind,
        severity=a.severity,
        title=a.title,
        detail=a.detail,
    )


@router.get("/graph", response_model=AttackGraphResponse)
async def get_attack_graph(
    asset_id: uuid.UUID = Query(...),
    window: Window = Query("24h"),
    identity: IdentityContext = Depends(require_role("analyst")),
) -> AttackGraphResponse:
    graph = build_attack_graph(
        org_id=identity.org_id, asset_id=asset_id, window=window
    )
    return AttackGraphResponse(**graph.to_dict())


@router.get("", response_model=list[AnomalyResponse])
async def detect(
    asset_id: uuid.UUID = Query(...),
    current_window: Window = Query("1h"),
    baseline_window: Window = Query("7d"),
    identity: IdentityContext = Depends(require_role("analyst")),
) -> list[AnomalyResponse]:
    anomalies = detect_for_asset(
        org_id=identity.org_id,
        asset_id=asset_id,
        current_window=current_window,
        baseline_window=baseline_window,
    )
    return [_serialise(a) for a in anomalies]
