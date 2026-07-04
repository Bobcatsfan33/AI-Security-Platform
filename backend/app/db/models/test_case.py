"""Test Case model — adversarial test definitions for evaluations.

Part of the v2 governance revival (see :mod:`app.db.models.evaluation`).
Columns mirror the v1 DDL from ``20260507_0001_initial_schema``.

``org_id`` is nullable: NULL test cases are part of the global/shared library
that all organizations can run (the evaluation runner unions
``org_id == <org>`` with ``org_id IS NULL`` — see
``app/evaluation/runner.py``). The model is still :class:`TenantScoped` so the
tenancy marker test passes and the Wall-2 RLS policy applies, but it restates
``org_id`` as nullable (overriding the mixin's non-null default) and the RLS
policy in migration ``20260704_0008`` deliberately admits ``org_id IS NULL``
rows so the global library stays visible to every tenant.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import Boolean, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import (
    Base,
    JsonbDict,
    JsonbList,
    TimestampUtc,
    TimestampUtcUpdated,
    UUIDPk,
)
from app.db.tenancy import TenantScoped


class TestCase(Base, TenantScoped):
    __tablename__ = "test_cases"

    id: Mapped[UUIDPk]
    # Restated as nullable: the shared/global library carries org_id IS NULL.
    # This overrides the TenantScoped mixin's non-null org_id.
    org_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sub_category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium"
    )  # info | low | medium | high | critical
    attack_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="single_turn"
    )  # single_turn | multi_turn | indirect | tool_based | rag_based | encoded

    # --- Test content ---
    # prompts: ordered list for multi-turn — [{"role": "user", "content": "...", "delay_ms": 0}]
    prompts: Mapped[JsonbList]
    system_prompt_override: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    injected_context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expected_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    success_criteria: Mapped[JsonbDict]
    failure_indicators: Mapped[JsonbList]

    # --- Metadata ---
    tags: Mapped[JsonbList]
    control_mappings: Mapped[JsonbList]  # OWASP LLM01-10, NIST AI RMF, ISO 42001, custom
    mitre_atlas_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    source: Mapped[str] = mapped_column(
        String(32), nullable=False, default="manual"
    )  # manual | generated | community | imported
    generated_from: Mapped[JsonbDict]
    effectiveness_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    is_regression: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]
