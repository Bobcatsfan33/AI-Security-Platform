"""Findings routes — list, view, update remediation status.

A finding is one vulnerability discovered by an evaluation. The
remediation workflow is the only mutation operators normally perform:

  open → in_progress → remediated → verified
  open → accepted_risk
  open → false_positive

Each transition emits an audit event so compliance reviewers can trace
who closed what when.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.db.models.finding import Finding
from app.db.session import get_db
from app.identity.types import IdentityContext
from app.security.audit_log import AuditEventType, AuditOutcome, log_event

router = APIRouter(tags=["findings"])


Severity = Literal["info", "low", "medium", "high", "critical"]
RemediationStatus = Literal[
    "open", "in_progress", "remediated", "verified", "accepted_risk", "false_positive"
]


class FindingResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    evaluation_id: uuid.UUID
    asset_id: uuid.UUID
    test_case_id: uuid.UUID
    title: str
    category: str
    sub_category: str | None
    severity: str
    risk_score: float
    confidence: float
    attack_succeeded: bool
    control_mappings: list[str]
    prompt_sent: str | None
    response_received: str | None
    system_prompt_used: str | None
    judge_reasoning: str | None
    recommendation: str | None
    remediation_status: str
    remediation_notes: str | None
    remediation_owner: uuid.UUID | None
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    resolved_at: datetime | None = Field(default=None)
    created_at: datetime


class RemediationUpdate(BaseModel):
    remediation_status: RemediationStatus
    remediation_notes: str | None = None
    remediation_owner: uuid.UUID | None = None


def _to_response(row: Finding) -> FindingResponse:
    return FindingResponse(
        id=row.id,
        org_id=row.org_id,
        evaluation_id=row.evaluation_id,
        asset_id=row.asset_id,
        test_case_id=row.test_case_id,
        title=row.title,
        category=row.category,
        sub_category=row.sub_category,
        severity=row.severity,
        risk_score=row.risk_score,
        confidence=row.confidence,
        attack_succeeded=row.attack_succeeded,
        control_mappings=list(row.control_mappings or []),
        prompt_sent=row.prompt_sent,
        response_received=row.response_received,
        system_prompt_used=row.system_prompt_used,
        judge_reasoning=row.judge_reasoning,
        recommendation=row.recommendation,
        remediation_status=row.remediation_status,
        remediation_notes=row.remediation_notes,
        remediation_owner=row.remediation_owner,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        occurrence_count=row.occurrence_count,
        resolved_at=row.verified_at,
        created_at=row.created_at,
    )


# ─────────────────────────────────────────────── routes


@router.get("", response_model=list[FindingResponse])
async def list_findings(
    asset_id: uuid.UUID | None = Query(None),
    evaluation_id: uuid.UUID | None = Query(None),
    severity: Severity | None = Query(None),
    remediation_status: RemediationStatus | None = Query(None),
    category: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[FindingResponse]:
    stmt = select(Finding).where(Finding.org_id == identity.org_id)
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if evaluation_id:
        stmt = stmt.where(Finding.evaluation_id == evaluation_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if remediation_status:
        stmt = stmt.where(Finding.remediation_status == remediation_status)
    if category:
        stmt = stmt.where(Finding.category == category)
    stmt = stmt.order_by(
        Finding.severity.desc(), Finding.created_at.desc()
    ).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_response(r) for r in rows]


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    row = await _load_owned(db, finding_id, identity.org_id)
    return _to_response(row)


@router.patch("/{finding_id}/remediation", response_model=FindingResponse)
async def update_remediation(
    finding_id: uuid.UUID,
    payload: RemediationUpdate,
    identity: IdentityContext = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    row = await _load_owned(db, finding_id, identity.org_id)
    old_status = row.remediation_status
    row.remediation_status = payload.remediation_status
    if payload.remediation_notes is not None:
        row.remediation_notes = payload.remediation_notes
    if payload.remediation_owner is not None:
        row.remediation_owner = payload.remediation_owner
    if payload.remediation_status in ("remediated", "verified", "accepted_risk", "false_positive"):
        row.verified_at = datetime.now(timezone.utc)
    row.updated_by = identity.user_id
    await db.commit()
    await db.refresh(row)
    log_event(
        AuditEventType.CONFIG_CHANGED,
        AuditOutcome.SUCCESS,
        tenant_id=str(identity.org_id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"finding:{row.id}",
        detail={
            "action": "remediation_status_changed",
            "from": old_status,
            "to": row.remediation_status,
        },
    )
    return _to_response(row)


async def _load_owned(
    db: AsyncSession, finding_id: uuid.UUID, org_id: uuid.UUID
) -> Finding:
    row = (
        await db.execute(
            select(Finding).where(
                Finding.id == finding_id, Finding.org_id == org_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
    return row
