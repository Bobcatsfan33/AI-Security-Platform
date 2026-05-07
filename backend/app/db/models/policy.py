"""Policy model — three-stage pipeline configuration with enforcement levels.

The runtime agent (Sprint 7) reads this from a Redis-cached snapshot and
enforces. Sprint 1 only creates the schema and the pub/sub plumbing — actual
enforcement comes later.

Enforcement levels (binding decision):
    fast          → Stage 1 only (regex + deterministic). Sub-1ms latency.
    balanced      → Stage 1 + Stage 2 (ML/ONNX). 5–10ms latency.
    comprehensive → Stage 1 + Stage 2 + Stage 3 (LLM judge). 500ms–3s latency.

Fail behavior:
    open   → allow on cache miss / Redis unreachable
    closed → block on cache miss / Redis unreachable
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import (
    CheckConstraint,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import (
    Base,
    JsonbDict,
    JsonbList,
    TimestampUtc,
    TimestampUtcUpdated,
    UUIDFk,
    UUIDPk,
)


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (
        CheckConstraint(
            "enforcement_level IN ('fast', 'balanced', 'comprehensive')",
            name="enforcement_level_valid",
        ),
        CheckConstraint(
            "fail_behavior IN ('open', 'closed')",
            name="fail_behavior_valid",
        ),
    )

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="draft"
    )  # draft | active | archived

    # --- Enforcement configuration ---
    enforcement_level: Mapped[str] = mapped_column(
        String(16), nullable=False, default="fast"
    )
    fail_behavior: Mapped[str] = mapped_column(
        String(8), nullable=False, default="open"
    )
    ml_confidence_threshold_high: Mapped[float] = mapped_column(
        Float, default=0.7, nullable=False
    )
    ml_confidence_threshold_low: Mapped[float] = mapped_column(
        Float, default=0.3, nullable=False
    )
    judge_model_endpoint: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    # --- Stage 1 rules (regex + deterministic) ---
    rules: Mapped[JsonbList]
    tool_allowlist: Mapped[JsonbList]
    tool_denylist: Mapped[JsonbList]
    tool_approval_required: Mapped[JsonbList]
    rate_limits: Mapped[JsonbDict]
    content_filters: Mapped[JsonbDict]

    # --- Stage 2 ML classifiers (referenced by ID; ONNX in object storage) ---
    classifiers: Mapped[JsonbList]
    classifier_sync_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # --- Stage 3 LLM judge ---
    judge_enabled: Mapped[bool] = mapped_column(default=False, nullable=False)
    judge_system_prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    judge_categories: Mapped[JsonbList]
    judge_timeout_ms: Mapped[int] = mapped_column(Integer, default=3000, nullable=False)
    judge_fallback_action: Mapped[str] = mapped_column(
        String(16), nullable=False, default="flag"
    )  # block | flag | allow

    # --- Distribution ---
    assigned_assets: Mapped[JsonbList]
    sync_status: Mapped[JsonbDict]
    last_distributed_at: Mapped[Optional[TimestampUtc]] = mapped_column(nullable=True)

    # --- Metadata ---
    created_by: Mapped[Optional[UUIDFk]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]
    change_log: Mapped[JsonbList]
