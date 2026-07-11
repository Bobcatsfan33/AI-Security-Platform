"""Finding model — a vulnerability discovered by an evaluation.

Part of the v2 governance revival (see :mod:`app.db.models.evaluation`).
Columns mirror the v1 DDL from ``20260507_0001_initial_schema``; the model
is :class:`TenantScoped` so it is covered by the Wall-1 ORM guard and the
Wall-2 RLS policy added in migration ``20260704_0008``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import (
    Base,
    JsonbList,
    TimestampUtc,
    TimestampUtcUpdated,
    UUIDFk,
    UUIDPk,
)
from app.db.tenancy import TenantScoped

_DateTimeTz = DateTime(timezone=True)


class Finding(Base, TenantScoped):
    __tablename__ = "findings"

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    evaluation_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("evaluations.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("ai_assets.id", ondelete="CASCADE"), nullable=False
    )
    test_case_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("test_cases.id", ondelete="RESTRICT"), nullable=False
    )

    # --- Classification ---
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sub_category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    attack_succeeded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    control_mappings: Mapped[JsonbList]

    # --- Evidence ---
    prompt_sent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response_received: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    system_prompt_used: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    context_injected: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tool_calls_made: Mapped[JsonbList]
    judge_reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    policy_results: Mapped[JsonbList]
    evidence_artifacts: Mapped[JsonbList]

    # --- Remediation ---
    recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="open"
    )  # open | in_progress | remediated | verified | accepted_risk | false_positive
    remediation_owner: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    remediation_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verified_by_evaluation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    verified_at: Mapped[Optional[datetime]] = mapped_column(_DateTimeTz, nullable=True)
    regression_test_case_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    # --- Metadata ---
    first_seen_at: Mapped[TimestampUtc]
    last_seen_at: Mapped[TimestampUtc]
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]
    updated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
