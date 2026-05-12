"""AI-BOM routes — graph, supply-chain risk, drift.

Each endpoint is org-scoped via the asset's ``org_id``; an asset from
one org cannot be inspected by another.

Drift uses the asset's ``change_log`` JSONB field to find the previous
snapshot — operators who want explicit comparison points can pass a
``baseline_change_log_index`` query param. Without a baseline, every
tracked field shows up as "newly set" relative to a null baseline.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.aibom.builder import AIBom, build_bom
from app.aibom.drift import DriftReport, compute_drift
from app.aibom.risk import SupplyChainRisk, score_supply_chain
from app.auth.dependencies import require_role
from app.db.models.ai_asset import AIAsset
from app.db.session import get_db
from app.identity.types import IdentityContext

router = APIRouter(tags=["aibom"])


class BomResponse(BaseModel):
    asset_id: str
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]


class RiskResponse(BaseModel):
    asset_id: str
    score: float
    components: list[dict[str, Any]]
    factors: dict[str, Any]


class DriftResponse(BaseModel):
    asset_id: str
    changed: bool
    changes: list[dict[str, Any]]
    max_severity: str
    summary: str


async def _load_asset(
    db: AsyncSession, asset_id: uuid.UUID, org_id: uuid.UUID
) -> AIAsset:
    row = (
        await db.execute(
            select(AIAsset).where(
                AIAsset.id == asset_id, AIAsset.org_id == org_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
    return row


def _asset_to_dict(row: AIAsset) -> dict[str, Any]:
    """Convert the SQLAlchemy row to a dict the AI-BOM functions accept."""
    return {
        "id": str(row.id),
        "name": row.name,
        "provider": row.provider,
        "model_name": row.model_name,
        "model_version": row.model_version,
        "hosting": row.hosting,
        "system_prompt": row.system_prompt,
        "temperature": row.temperature,
        "max_tokens": row.max_tokens,
        "top_p": row.top_p,
        "tools": row.tools or [],
        "mcp_servers": row.mcp_servers or [],
        "rag_sources": row.rag_sources or [],
        "plugins": row.plugins or [],
        "fine_tuning": row.fine_tuning or {},
        "environment": row.environment,
        "exposure": row.exposure,
        "data_classification": row.data_classification,
        "regulatory_scope": row.regulatory_scope or [],
        "dependencies": row.dependencies or [],
        "data_lineage": row.data_lineage or [],
        "upstream_services": row.upstream_services or [],
        "downstream_consumers": row.downstream_consumers or [],
        "is_agentic": row.is_agentic,
        "agent_framework": row.agent_framework,
        "max_tool_calls_per_session": row.max_tool_calls_per_session,
        "human_in_loop_required": row.human_in_loop_required,
        "allowed_external_actions": row.allowed_external_actions or [],
        "blast_radius_score": row.blast_radius_score,
        "change_log": row.change_log or [],
    }


@router.get("/{asset_id}", response_model=BomResponse)
async def get_bom(
    asset_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> BomResponse:
    row = await _load_asset(db, asset_id, identity.org_id)
    bom = build_bom(_asset_to_dict(row))
    return BomResponse(
        asset_id=bom.asset_id,
        nodes=[asdict(n) for n in bom.nodes],
        edges=[asdict(e) for e in bom.edges],
    )


@router.get("/{asset_id}/risk", response_model=RiskResponse)
async def get_risk(
    asset_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> RiskResponse:
    row = await _load_asset(db, asset_id, identity.org_id)
    risk = score_supply_chain(_asset_to_dict(row))
    return RiskResponse(
        asset_id=risk.asset_id,
        score=risk.score,
        components=[asdict(c) for c in risk.components],
        factors=risk.factors,
    )


@router.get("/{asset_id}/drift", response_model=DriftResponse)
async def get_drift(
    asset_id: uuid.UUID,
    baseline_change_log_index: int | None = Query(
        None,
        description=(
            "Optional index into the asset's change_log to use as the "
            "baseline snapshot. Default: compare against the most recent "
            "change_log entry (or empty baseline if no history)."
        ),
    ),
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> DriftResponse:
    row = await _load_asset(db, asset_id, identity.org_id)
    current = _asset_to_dict(row)

    # change_log entries are expected to be {timestamp, field, old_value,
    # new_value, changed_by} but the test/real-world distribution will
    # be partial. We construct a baseline dict by replaying the change log
    # up to baseline_change_log_index.
    change_log = current.get("change_log") or []
    if baseline_change_log_index is None:
        # Default: most recent prior snapshot. If the log is empty,
        # baseline is None → every set field shows as new.
        baseline_change_log_index = max(0, len(change_log) - 1)

    baseline = (
        _reconstruct_baseline(current, change_log, baseline_change_log_index)
        if change_log
        else None
    )

    report = compute_drift(current=current, baseline=baseline)
    return DriftResponse(
        asset_id=report.asset_id,
        changed=report.changed,
        changes=[asdict(c) for c in report.changes],
        max_severity=report.max_severity,
        summary=report.summary,
    )


def _reconstruct_baseline(
    current: dict[str, Any],
    change_log: list[dict[str, Any]],
    up_to_index: int,
) -> dict[str, Any]:
    """Walk the change_log forwards up to up_to_index, replaying changes
    onto a copy of the current snapshot in REVERSE — i.e. for each
    logged change, restore the old_value into the baseline copy.

    The asset row IS the latest snapshot. To get the state-at-time-T, we
    start from the latest and undo the changes that happened AFTER time-T.
    """
    baseline = dict(current)
    # Apply log entries from the latest backwards down to (up_to_index + 1)
    for entry in reversed(change_log[up_to_index + 1 :]):
        field = entry.get("field")
        if not field:
            continue
        baseline[field] = entry.get("old_value")
    return baseline
