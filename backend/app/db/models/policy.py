"""Policy v2 model — runtime enforcement policy of record.

The v2.0 pivot dropped the v1 ``policies`` table together with the rest of
the governance schema, but Track 2 (Runtime Monitoring) was meant to stay
intact — and the runtime agent's only way to enforce anything is
``GET /v1/policies/{id}`` (runtime-agent/policy/cache.go). This revives the
policy store exactly as the quarantine manifest in
``tests/unit/test_no_broken_imports.py`` prescribes: reintroduce the model,
repoint nothing (the router and cache never changed), drop the quarantine
entries. Columns mirror the v1 DDL from ``20260507_0001_initial_schema``.
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
    JsonbDict,
    JsonbList,
    TimestampUtc,
    TimestampUtcUpdated,
    UUIDFk,
    UUIDPk,
)
from app.db.tenancy import TenantScoped

_DateTimeTz = DateTime(timezone=True)


class Policy(Base, TenantScoped):
    __tablename__ = "policies"

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    enforcement_level: Mapped[str] = mapped_column(String(16), nullable=False, default="fast")
    fail_behavior: Mapped[str] = mapped_column(String(8), nullable=False, default="open")
    ml_confidence_threshold_high: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.7
    )
    ml_confidence_threshold_low: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    judge_model_endpoint: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    rules: Mapped[JsonbList]
    tool_allowlist: Mapped[JsonbList]
    tool_denylist: Mapped[JsonbList]
    tool_approval_required: Mapped[JsonbList]
    rate_limits: Mapped[JsonbDict]
    content_filters: Mapped[JsonbDict]
    classifiers: Mapped[JsonbList]
    classifier_sync_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    judge_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    judge_system_prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    judge_categories: Mapped[JsonbList]
    judge_timeout_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=3000)
    judge_fallback_action: Mapped[str] = mapped_column(String(16), nullable=False, default="flag")
    assigned_assets: Mapped[JsonbList]
    sync_status: Mapped[JsonbDict]
    last_distributed_at: Mapped[Optional[datetime]] = mapped_column(_DateTimeTz, nullable=True)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]
    change_log: Mapped[JsonbList]
