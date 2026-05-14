"""Deployment — one instance of an AI asset running somewhere."""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampUtc, TimestampUtcUpdated, UUIDPk


class Deployment(Base):
    __tablename__ = "deployments"

    id: Mapped[UUIDPk]
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ai_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    environment: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    endpoint_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    region: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    replicas: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="active")
    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]
