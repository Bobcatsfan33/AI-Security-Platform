"""Policy CRUD — every write publishes invalidation to Redis pub/sub.

Sprint 1 wires the storage + distribution mechanism. The actual three-stage
enforcement engine ships in Sprint 2 (Stage 1) and Sprint 3 (Stage 2). The
runtime agent that consumes these policies ships in Sprint 7.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.db.models.policy import Policy
from app.db.session import get_db
from app.identity.types import IdentityContext
from app.services.policy_pubsub import publish_policy_change

router = APIRouter(tags=["policies"])

EnforcementLevel = Literal["fast", "balanced", "comprehensive"]
FailBehavior = Literal["open", "closed"]
JudgeFallback = Literal["block", "flag", "allow"]


# --------------------------------------------------------------------------- DTOs


class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    enforcement_level: EnforcementLevel = "fast"
    fail_behavior: FailBehavior = "open"
    ml_confidence_threshold_high: float = Field(0.7, ge=0.0, le=1.0)
    ml_confidence_threshold_low: float = Field(0.3, ge=0.0, le=1.0)
    judge_model_endpoint: str | None = None

    rules: list[dict[str, Any]] = Field(default_factory=list)
    tool_allowlist: list[str] = Field(default_factory=list)
    tool_denylist: list[str] = Field(default_factory=list)
    tool_approval_required: list[str] = Field(default_factory=list)
    rate_limits: dict[str, Any] = Field(default_factory=dict)
    content_filters: dict[str, Any] = Field(default_factory=dict)

    classifiers: list[dict[str, Any]] = Field(default_factory=list)
    judge_enabled: bool = False
    judge_system_prompt: str | None = None
    judge_categories: list[str] = Field(default_factory=list)
    judge_timeout_ms: int = Field(3000, ge=100, le=30_000)
    judge_fallback_action: JudgeFallback = "flag"

    assigned_assets: list[uuid.UUID] = Field(default_factory=list)


class PolicyUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: Literal["draft", "active", "archived"] | None = None
    enforcement_level: EnforcementLevel | None = None
    fail_behavior: FailBehavior | None = None
    ml_confidence_threshold_high: float | None = None
    ml_confidence_threshold_low: float | None = None
    rules: list[dict[str, Any]] | None = None
    tool_allowlist: list[str] | None = None
    tool_denylist: list[str] | None = None
    tool_approval_required: list[str] | None = None
    rate_limits: dict[str, Any] | None = None
    content_filters: dict[str, Any] | None = None
    classifiers: list[dict[str, Any]] | None = None
    judge_enabled: bool | None = None
    judge_system_prompt: str | None = None
    judge_categories: list[str] | None = None
    judge_timeout_ms: int | None = None
    judge_fallback_action: JudgeFallback | None = None
    assigned_assets: list[uuid.UUID] | None = None


class PolicyResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    description: str | None
    version: int
    status: str
    enforcement_level: str
    fail_behavior: str
    ml_confidence_threshold_high: float
    ml_confidence_threshold_low: float
    rules: list[dict[str, Any]]
    tool_allowlist: list[str]
    tool_denylist: list[str]
    tool_approval_required: list[str]
    rate_limits: dict[str, Any]
    content_filters: dict[str, Any]
    classifiers: list[dict[str, Any]]
    judge_enabled: bool
    judge_categories: list[str]
    judge_timeout_ms: int
    judge_fallback_action: str
    assigned_assets: list[uuid.UUID]
    created_at: datetime
    updated_at: datetime


def _to_response(row: Policy) -> PolicyResponse:
    return PolicyResponse(
        id=row.id,
        org_id=row.org_id,
        name=row.name,
        description=row.description,
        version=row.version,
        status=row.status,
        enforcement_level=row.enforcement_level,
        fail_behavior=row.fail_behavior,
        ml_confidence_threshold_high=row.ml_confidence_threshold_high,
        ml_confidence_threshold_low=row.ml_confidence_threshold_low,
        rules=row.rules or [],
        tool_allowlist=row.tool_allowlist or [],
        tool_denylist=row.tool_denylist or [],
        tool_approval_required=row.tool_approval_required or [],
        rate_limits=row.rate_limits or {},
        content_filters=row.content_filters or {},
        classifiers=row.classifiers or [],
        judge_enabled=row.judge_enabled,
        judge_categories=row.judge_categories or [],
        judge_timeout_ms=row.judge_timeout_ms,
        judge_fallback_action=row.judge_fallback_action,
        assigned_assets=[uuid.UUID(s) for s in row.assigned_assets or []],
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


# ----------------------------------------------------------------------- routes


@router.get("", response_model=list[PolicyResponse])
async def list_policies(
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[PolicyResponse]:
    rows = (
        await db.execute(select(Policy).where(Policy.org_id == identity.org_id))
    ).scalars().all()
    return [_to_response(r) for r in rows]


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: PolicyCreate,
    identity: IdentityContext = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> PolicyResponse:
    row = Policy(
        id=uuid.uuid4(),
        org_id=identity.org_id,
        name=payload.name,
        description=payload.description,
        version=1,
        status="draft",
        enforcement_level=payload.enforcement_level,
        fail_behavior=payload.fail_behavior,
        ml_confidence_threshold_high=payload.ml_confidence_threshold_high,
        ml_confidence_threshold_low=payload.ml_confidence_threshold_low,
        judge_model_endpoint=payload.judge_model_endpoint,
        rules=payload.rules,
        tool_allowlist=payload.tool_allowlist,
        tool_denylist=payload.tool_denylist,
        tool_approval_required=payload.tool_approval_required,
        rate_limits=payload.rate_limits,
        content_filters=payload.content_filters,
        classifiers=payload.classifiers,
        judge_enabled=payload.judge_enabled,
        judge_system_prompt=payload.judge_system_prompt,
        judge_categories=payload.judge_categories,
        judge_timeout_ms=payload.judge_timeout_ms,
        judge_fallback_action=payload.judge_fallback_action,
        assigned_assets=[str(u) for u in payload.assigned_assets],
        created_by=identity.user_id,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    await publish_policy_change(
        org_id=row.org_id, policy_id=row.id, version=row.version, event="create"
    )
    return _to_response(row)


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> PolicyResponse:
    row = await _load_owned(db, policy_id, identity.org_id)
    return _to_response(row)


@router.patch("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: uuid.UUID,
    payload: PolicyUpdate,
    identity: IdentityContext = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> PolicyResponse:
    row = await _load_owned(db, policy_id, identity.org_id)

    update_dict = payload.model_dump(exclude_unset=True)
    if "assigned_assets" in update_dict:
        update_dict["assigned_assets"] = [str(u) for u in update_dict["assigned_assets"]]

    for field, value in update_dict.items():
        setattr(row, field, value)

    row.version += 1
    await db.commit()
    await db.refresh(row)

    await publish_policy_change(
        org_id=row.org_id, policy_id=row.id, version=row.version, event="update"
    )
    return _to_response(row)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> None:
    row = await _load_owned(db, policy_id, identity.org_id)
    org_id = row.org_id
    pid = row.id
    version = row.version
    await db.delete(row)
    await db.commit()
    await publish_policy_change(
        org_id=org_id, policy_id=pid, version=version, event="delete"
    )


async def _load_owned(
    db: AsyncSession, policy_id: uuid.UUID, org_id: uuid.UUID
) -> Policy:
    row = (
        await db.execute(
            select(Policy).where(Policy.id == policy_id, Policy.org_id == org_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
    return row
