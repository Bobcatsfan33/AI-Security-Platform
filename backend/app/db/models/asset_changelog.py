"""AssetChangelog — append-only audit trail for asset mutations."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

from sqlalchemy import DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import ENUM, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDPk

CHANGE_TYPE_ENUM = ENUM(
    "created",
    "updated",
    "removed",
    "owner_changed",
    name="change_type_enum",
    create_type=False,
)


class AssetChangelog(Base):
    __tablename__ = "asset_changelog"

    id: Mapped[UUIDPk]
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ai_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    change_type: Mapped[str] = mapped_column(CHANGE_TYPE_ENUM, nullable=False)
    previous_value: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONB, nullable=True
    )
    new_value: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        index=True,
    )
