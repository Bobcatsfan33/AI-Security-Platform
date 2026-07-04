"""Evaluation model — a run of test cases against an AI asset.

The v2.0 pivot dropped the v1 governance schema (``evaluations`` /
``findings`` / ``test_cases`` / ``connector_configs``). This revives the
``evaluations`` table exactly as the quarantine manifest in
``tests/unit/test_no_broken_imports.py`` prescribes: reintroduce the model,
repoint nothing (the evaluation runner and its routers never changed), drop
the quarantine entries. Columns mirror the v1 DDL from
``20260507_0001_initial_schema``.

Unlike the v1 model (plain ``Base``), this revival is :class:`TenantScoped`
so it is covered by the Wall-1 ORM guard and the Wall-2 RLS policy added in
migration ``20260704_0008`` — the same shape the policy revival (0007) used.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import (
    Base,
    JsonbDict,
    JsonbList,
    TimestampUtc,
    UUIDFk,
    UUIDPk,
)
from app.db.tenancy import TenantScoped

_DateTimeTz = DateTime(timezone=True)


class Evaluation(Base, TenantScoped):
    __tablename__ = "evaluations"

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("ai_assets.id", ondelete="CASCADE"), nullable=False
    )

    triggered_by: Mapped[str] = mapped_column(
        String(32), nullable=False, default="manual"
    )  # manual | scheduled | ci_cd | drift_detection | webhook
    trigger_context: Mapped[JsonbDict]
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="created", index=True
    )  # created | running | completed | failed | cancelled
    eval_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="full"
    )  # full | regression_only | targeted | red_team_campaign

    # --- Configuration ---
    test_case_ids: Mapped[JsonbList]
    connector_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    max_test_cases: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=600, nullable=False)
    parallel_workers: Mapped[int] = mapped_column(Integer, default=4, nullable=False)

    # --- Results ---
    score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_label: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )  # good | needs_hardening | high_risk | critical
    tests_run: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tests_passed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tests_failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    summary: Mapped[JsonbDict]
    model_cost_usd: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # --- CI/CD gate ---
    gate_result: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )  # pass | fail | warn | not_applicable
    gate_policy: Mapped[JsonbDict]
    gate_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # --- Metadata ---
    started_at: Mapped[Optional[datetime]] = mapped_column(_DateTimeTz, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(_DateTimeTz, nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    initiated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    previous_evaluation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    created_at: Mapped[TimestampUtc]
