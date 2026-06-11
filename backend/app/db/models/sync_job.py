"""SyncJob — one execution of a connector's discover/sync run."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

from sqlalchemy import DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import ENUM
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDPk
from app.db.tenancy import TenantScoped

SYNC_STATUS_ENUM = ENUM(
    "pending",
    "running",
    "completed",
    "failed",
    name="sync_status_enum",
    create_type=False,
)


class SyncJob(Base, TenantScoped):
    __tablename__ = "sync_jobs"

    id: Mapped[UUIDPk]
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    connector_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("connectors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        SYNC_STATUS_ENUM, nullable=False, default="pending"
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow,
        index=True,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    assets_discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    assets_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    assets_removed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
