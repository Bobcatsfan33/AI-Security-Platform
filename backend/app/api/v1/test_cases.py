"""Test case CRUD + global library access.

The TestCase table is org-scoped OR global (org_id IS NULL). Operators
see the union of their own cases plus the global library. New custom
cases are written with the calling org's ID.

The global library is seeded by ``backend/scripts/seed_test_cases.py``
or via POST /v1/test-cases/seed-defaults (admin-only) the first time
an org wants the baseline coverage.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.db.models.test_case import TestCase
from app.db.session import get_db
from app.identity.types import IdentityContext
from app.testcases.library import DEFAULT_LIBRARY

router = APIRouter(tags=["test_cases"])


Severity = Literal["info", "low", "medium", "high", "critical"]
AttackType = Literal[
    "single_turn", "multi_turn", "indirect", "tool_based", "rag_based", "encoded"
]


class TestCaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    category: str = Field(min_length=1, max_length=64)
    sub_category: str | None = None
    severity: Severity = "medium"
    attack_type: AttackType = "single_turn"
    prompts: list[dict[str, Any]] = Field(default_factory=list)
    system_prompt_override: str | None = None
    injected_context: str | None = None
    expected_behavior: str
    success_criteria: dict[str, Any] = Field(default_factory=dict)
    failure_indicators: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    control_mappings: list[str] = Field(default_factory=list)
    mitre_atlas_id: str | None = None
    source: str = "manual"


class TestCaseResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID | None
    name: str
    description: str | None
    category: str
    sub_category: str | None
    severity: str
    attack_type: str
    prompts: list[dict[str, Any]]
    expected_behavior: str
    success_criteria: dict[str, Any]
    failure_indicators: list[str]
    tags: list[str]
    control_mappings: list[str]
    mitre_atlas_id: str | None
    source: str
    is_global: bool
    effectiveness_score: float
    is_regression: bool
    created_at: datetime


def _to_response(row: TestCase) -> TestCaseResponse:
    return TestCaseResponse(
        id=row.id,
        org_id=row.org_id,
        name=row.name,
        description=row.description,
        category=row.category,
        sub_category=row.sub_category,
        severity=row.severity,
        attack_type=row.attack_type,
        prompts=row.prompts or [],
        expected_behavior=row.expected_behavior,
        success_criteria=row.success_criteria or {},
        failure_indicators=row.failure_indicators or [],
        tags=row.tags or [],
        control_mappings=row.control_mappings or [],
        mitre_atlas_id=row.mitre_atlas_id,
        source=row.source,
        is_global=row.org_id is None,
        effectiveness_score=row.effectiveness_score,
        is_regression=row.is_regression,
        created_at=row.created_at,
    )


# ─────────────────────────────────────────────── routes


@router.get("", response_model=list[TestCaseResponse])
async def list_test_cases(
    category: str | None = Query(None),
    severity: Severity | None = Query(None),
    include_global: bool = Query(True),
    limit: int = Query(200, ge=1, le=1000),
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[TestCaseResponse]:
    """Return org-specific + (optionally) global library entries."""
    org_filter = TestCase.org_id == identity.org_id
    if include_global:
        org_filter = or_(TestCase.org_id == identity.org_id, TestCase.org_id.is_(None))

    stmt = select(TestCase).where(org_filter)
    if category:
        stmt = stmt.where(TestCase.category == category)
    if severity:
        stmt = stmt.where(TestCase.severity == severity)
    stmt = stmt.order_by(TestCase.created_at.desc()).limit(limit)

    rows = (await db.execute(stmt)).scalars().all()
    return [_to_response(r) for r in rows]


@router.post(
    "", response_model=TestCaseResponse, status_code=status.HTTP_201_CREATED
)
async def create_test_case(
    payload: TestCaseCreate,
    identity: IdentityContext = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> TestCaseResponse:
    row = TestCase(
        id=uuid.uuid4(),
        org_id=identity.org_id,
        **payload.model_dump(mode="json"),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.get("/{test_case_id}", response_model=TestCaseResponse)
async def get_test_case(
    test_case_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> TestCaseResponse:
    row = (
        await db.execute(
            select(TestCase).where(
                TestCase.id == test_case_id,
                or_(TestCase.org_id == identity.org_id, TestCase.org_id.is_(None)),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
    return _to_response(row)


@router.delete("/{test_case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_test_case(
    test_case_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete only org-owned cases; global library cases are immutable."""
    row = (
        await db.execute(
            select(TestCase).where(
                TestCase.id == test_case_id,
                TestCase.org_id == identity.org_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="not_found_or_immutable_global",
        )
    await db.delete(row)
    await db.commit()


@router.post("/seed-defaults", response_model=dict[str, int])
async def seed_default_library(
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, int]:
    """Idempotently seed the default test case library into the global
    (org_id=NULL) bucket. Safe to call multiple times — existing entries
    are skipped by name.

    Returns ``{"inserted": N, "skipped": M}``.
    """
    inserted = 0
    skipped = 0
    for spec in DEFAULT_LIBRARY:
        existing = (
            await db.execute(
                select(TestCase).where(
                    TestCase.org_id.is_(None), TestCase.name == spec["name"]
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            skipped += 1
            continue
        row = TestCase(
            id=uuid.uuid4(),
            org_id=None,
            source="community",
            **spec,
        )
        db.add(row)
        inserted += 1
    await db.commit()
    return {"inserted": inserted, "skipped": skipped}
