"""Red Team v2 models — campaign-of-record + per-attack findings.

The v2.0 pivot dropped the v1 ``evaluations`` / ``findings`` / ``test_cases``
tables that the v1 red-team router rode on. Rather than resurrect that whole
governance schema, Red Teaming gets its own lean, self-contained pair of
tables: a :class:`RedTeamCampaign` (the run-of-record + aggregates) and the
:class:`RedTeamFinding` rows (one per successful attack). Successful findings
can later bridge into the live ThreatNarrative / promotion flywheel without
either side owning the other's schema.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, Text
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

_DateTimeTz = DateTime(timezone=True)


class RedTeamCampaign(Base):
    __tablename__ = "red_team_campaigns"

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # The asset under test, if the campaign targets a catalogued asset. No FK —
    # a campaign can target an ad-hoc system prompt with no asset row.
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, default="created", index=True)
    strategy_ids: Mapped[JsonbList]
    total_attacks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    successful_attacks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    target_errors: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_label: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    total_cost_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    summary: Mapped[JsonbDict]
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(_DateTimeTz, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(_DateTimeTz, nullable=True)

    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]


class RedTeamFinding(Base):
    __tablename__ = "red_team_findings"

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("red_team_campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    strategy_id: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    response: Mapped[str] = mapped_column(Text, nullable=False, default="")
    classification: Mapped[str] = mapped_column(Text, nullable=False, default="")
    compliance_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False, default="")

    created_at: Mapped[TimestampUtc]
