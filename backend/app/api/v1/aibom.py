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
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.aibom.blast_radius import compute_blast_radius
from app.aibom.builder import build_bom
from app.aibom.coerce import as_dict_list
from app.aibom.drift import compute_drift
from app.aibom.risk import score_supply_chain
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


class BlastRadiusResponse(BaseModel):
    asset_id: str
    # The bound is a contract, not a comment: the schema rejects an out-of-range
    # score, so a computation bug cannot ship a 137 to a design partner.
    score: float = Field(ge=0, le=100)
    severity: str
    reach: dict[str, Any]
    # Each factor: {name, score, weight, detail}. `detail` is the basis a
    # reviewer reads to decide whether to trust the number.
    factors: list[dict[str, Any]]
    containment: list[str]
    basis: dict[str, Any]


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
    """Build the dict the AI-BOM functions consume, from the CURRENT model.

    The agentic/reachability config (``tools``, ``downstream_consumers``,
    ``is_agentic``, ``exposure``, ``change_log``, …) lives in the asset's
    ``metadata_json`` JSONB bag — the v2.0 pivot replaced the typed columns the
    original router read, so reading them off the row raised ``AttributeError``
    on the first request. That is why aibom was never mounted despite being
    audited as "3 endpoints": reachability was graded, not function.

    Permissive-when-missing is the load-bearing property: the bag is passed
    through VERBATIM, with NO defaults. A key that is absent stays absent — the
    domain functions then read it as empty/zero and report the absence — so a
    sparse asset yields the honest-empty decomposition, never a fabricated one.
    The authoritative columns (``id``/``name``/``provider``) override any
    same-named metadata key.
    """
    meta = row.metadata_json if isinstance(row.metadata_json, dict) else {}
    return {
        **meta,
        "id": str(row.id),
        "name": row.name,
        "provider": row.provider,
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
    # new_value, changed_by} but the value is operator-shaped JSONB. Coerce to a
    # list of DICTS: a non-list log, or a non-dict entry, must not
    # AttributeError on .get and 500 — malformed operator data is not a server
    # error. Non-dict entries are dropped.
    change_log = as_dict_list(current.get("change_log"))
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


@router.get("/{asset_id}/blast-radius", response_model=BlastRadiusResponse)
async def get_blast_radius(
    asset_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> BlastRadiusResponse:
    """Computed blast radius — the reachable impact if this asset is compromised.

    The score is DERIVED from the asset's reachability (see
    ``app/aibom/blast_radius.py``), not the stored ``blast_radius_score`` scalar,
    and every point of it traces to a factor with a stated basis. An asset with
    no agentic metadata returns a low radius whose factors say why.
    """
    row = await _load_asset(db, asset_id, identity.org_id)
    br = compute_blast_radius(_asset_to_dict(row))
    return BlastRadiusResponse(
        asset_id=br.asset_id,
        score=br.score,
        severity=br.severity,
        reach=br.reach,
        factors=[asdict(f) for f in br.factors],
        containment=list(br.containment),
        basis=br.basis,
    )
