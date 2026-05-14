"""AssetTag — flexible key/value tags hung off an AI asset."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDPk


class AssetTag(Base):
    __tablename__ = "asset_tags"
    __table_args__ = (
        UniqueConstraint("asset_id", "key", name="uq_asset_tags_asset_key"),
    )

    id: Mapped[UUIDPk]
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ai_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
