"""Evaluation routes — kick off, monitor, summarize evaluation runs."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.db.models.evaluation import Evaluation
from app.db.session import get_db
from app.evaluation.runner import EvaluationRunner
from app.identity.types import IdentityContext

router = APIRouter(tags=["evaluations"])


EvalType = Literal["full", "regression_only", "targeted", "red_team_campaign"]
EvalStatus = Literal["created", "running", "completed", "failed", "cancelled"]


class EvaluationCreate(BaseModel):
    asset_id: uuid.UUID
    eval_type: EvalType = "full"
    triggered_by: Literal[
        "manual", "scheduled", "ci_cd", "drift_detection", "webhook"
    ] = "manual"
    trigger_context: dict[str, Any] = Field(default_factory=dict)
    connector_id: uuid.UUID | None = None
    test_case_ids: list[uuid.UUID] = Field(default_factory=list)
    max_test_cases: int | None = Field(default=None, ge=1, le=500)
    timeout_seconds: int = Field(default=600, ge=60, le=3600)
    parallel_workers: int = Field(default=4, ge=1, le=20)


class EvaluationResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    asset_id: uuid.UUID
    triggered_by: str
    status: str
    eval_type: str
    connector_id: uuid.UUID | None
    test_case_ids: list[uuid.UUID]
    score: float
    risk_label: str | None
    tests_run: int
    tests_passed: int
    tests_failed: int
    findings_count: int
    critical_findings: int
    summary: dict[str, Any]
    model_cost_usd: float
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: int | None
    created_at: datetime


def _to_response(row: Evaluation) -> EvaluationResponse:
    raw_ids = row.test_case_ids or []
    parsed_ids: list[uuid.UUID] = []
    for v in raw_ids:
        if isinstance(v, str):
            try:
                parsed_ids.append(uuid.UUID(v))
            except ValueError:
                continue
        elif isinstance(v, uuid.UUID):
            parsed_ids.append(v)
    return EvaluationResponse(
        id=row.id,
        org_id=row.org_id,
        asset_id=row.asset_id,
        triggered_by=row.triggered_by,
        status=row.status,
        eval_type=row.eval_type,
        connector_id=row.connector_id,
        test_case_ids=parsed_ids,
        score=row.score,
        risk_label=row.risk_label,
        tests_run=row.tests_run,
        tests_passed=row.tests_passed,
        tests_failed=row.tests_failed,
        findings_count=row.findings_count,
        critical_findings=row.critical_findings,
        summary=row.summary or {},
        model_cost_usd=row.model_cost_usd,
        started_at=row.started_at,
        completed_at=row.completed_at,
        duration_seconds=row.duration_seconds,
        created_at=row.created_at,
    )


# ─────────────────────────────────────────────── helpers


async def _run_in_background(evaluation_id: uuid.UUID) -> None:
    runner = EvaluationRunner()
    await runner.run(evaluation_id)


# ─────────────────────────────────────────────── routes


@router.get("", response_model=list[EvaluationResponse])
async def list_evaluations(
    asset_id: uuid.UUID | None = Query(None),
    status_filter: EvalStatus | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[EvaluationResponse]:
    stmt = select(Evaluation).where(Evaluation.org_id == identity.org_id)
    if asset_id:
        stmt = stmt.where(Evaluation.asset_id == asset_id)
    if status_filter:
        stmt = stmt.where(Evaluation.status == status_filter)
    stmt = stmt.order_by(Evaluation.created_at.desc()).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_response(r) for r in rows]


@router.post(
    "", response_model=EvaluationResponse, status_code=status.HTTP_201_CREATED
)
async def create_evaluation(
    payload: EvaluationCreate,
    background_tasks: BackgroundTasks,
    identity: IdentityContext = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> EvaluationResponse:
    row = Evaluation(
        id=uuid.uuid4(),
        org_id=identity.org_id,
        asset_id=payload.asset_id,
        triggered_by=payload.triggered_by,
        trigger_context=payload.trigger_context,
        status="created",
        eval_type=payload.eval_type,
        connector_id=payload.connector_id,
        test_case_ids=[str(i) for i in payload.test_case_ids],
        max_test_cases=payload.max_test_cases,
        timeout_seconds=payload.timeout_seconds,
        parallel_workers=payload.parallel_workers,
        initiated_by=identity.user_id,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    background_tasks.add_task(_run_in_background, row.id)
    return _to_response(row)


@router.get("/{evaluation_id}", response_model=EvaluationResponse)
async def get_evaluation(
    evaluation_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> EvaluationResponse:
    row = (
        await db.execute(
            select(Evaluation).where(
                Evaluation.id == evaluation_id,
                Evaluation.org_id == identity.org_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
    return _to_response(row)


@router.post("/{evaluation_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_evaluation(
    evaluation_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Mark an evaluation as cancelled. The background runner will see
    the status change on its next checkpoint and exit. Sprint 1 follow-
    on: actually interrupt the running task — currently a flag-only
    cancellation."""
    row = (
        await db.execute(
            select(Evaluation).where(
                Evaluation.id == evaluation_id,
                Evaluation.org_id == identity.org_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
    if row.status in ("completed", "failed", "cancelled"):
        return
    row.status = "cancelled"
    await db.commit()
