"""Evaluation model — a run of test cases against an AI asset."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import (
    Base,
    JsonbDict,
    JsonbList,
    TimestampUtc,
    UUIDFk,
    UUIDPk,
)

if TYPE_CHECKING:
    pass


class Evaluation(Base):
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
    connector_id: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)
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
    started_at: Mapped[Optional[TimestampUtc]] = mapped_column(nullable=True)
    completed_at: Mapped[Optional[TimestampUtc]] = mapped_column(nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    initiated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    previous_evaluation_id: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)

    created_at: Mapped[TimestampUtc]
