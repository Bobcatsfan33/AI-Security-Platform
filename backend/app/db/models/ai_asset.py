"""AI asset — the v2 node in the asset graph.

An asset is anything we discovered via a connector: a model, an
endpoint, a dataset, a pipeline, an agent, or a tool. Identity in the
source system is preserved as ``external_id`` and unique within a
connector. Semantic search runs over ``embedding`` via pgvector.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ENUM
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import (
    Base,
    JsonbDict,
    TimestampUtc,
    TimestampUtcUpdated,
    UUIDPk,
)

ASSET_TYPE_ENUM = ENUM(
    "model",
    "endpoint",
    "dataset",
    "pipeline",
    "agent",
    "tool",
    name="asset_type_enum",
    create_type=False,
)

ASSET_STATUS_ENUM = ENUM(
    "active",
    "inactive",
    "deprecated",
    "unknown",
    name="asset_status_enum",
    create_type=False,
)


class AIAsset(Base):
    __tablename__ = "ai_assets"
    __table_args__ = (
        UniqueConstraint(
            "connector_id", "external_id", name="uq_ai_assets_connector_external"
        ),
        CheckConstraint(
            "risk_score BETWEEN 0 AND 100", name="ck_ai_assets_risk_score_range"
        ),
    )

    id: Mapped[UUIDPk]
    name: Mapped[str] = mapped_column(Text, nullable=False)
    asset_type: Mapped[str] = mapped_column(ASSET_TYPE_ENUM, nullable=False, index=True)
    asset_status: Mapped[str] = mapped_column(
        ASSET_STATUS_ENUM, nullable=False, default="active"
    )
    provider: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    version: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    external_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    connector_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("connectors.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    risk_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, index=True
    )
    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("owners.id", ondelete="SET NULL"), nullable=True, index=True
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[JsonbDict]

    # pgvector. Nullable — we backfill embeddings lazily.
    embedding: Mapped[Optional[Any]] = mapped_column(Vector(1536), nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow,
        index=True,
    )
    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]

    connector: Mapped["Connector"] = relationship(  # noqa: F821
        "Connector", lazy="joined"
    )
    owner: Mapped[Optional["Owner"]] = relationship(  # noqa: F821
        "Owner", lazy="joined"
    )
    deployments: Mapped[list["Deployment"]] = relationship(  # noqa: F821
        "Deployment", cascade="all, delete-orphan"
    )
    tags: Mapped[list["AssetTag"]] = relationship(  # noqa: F821
        "AssetTag", cascade="all, delete-orphan"
    )
