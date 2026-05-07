"""Test Case model — adversarial test definitions for evaluations.

org_id is nullable: NULL test cases are part of the global/shared library
that all organizations can run.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import (
    Base,
    JsonbDict,
    JsonbList,
    TimestampUtc,
    TimestampUtcUpdated,
    UUIDPk,
)

if TYPE_CHECKING:
    pass


class TestCase(Base):
    __tablename__ = "test_cases"

    id: Mapped[UUIDPk]
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
    is_regression: Mapped[bool] = mapped_column(default=False, nullable=False)

    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]
