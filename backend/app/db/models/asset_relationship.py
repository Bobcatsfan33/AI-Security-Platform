"""AssetRelationship — directed edge between two AI assets in the graph.

``relationship_type`` is free-form so connectors can introduce new edge
shapes without a migration. Common values: ``deployed_at``,
``trained_on``, ``uses``, ``produces``.
"""

from __future__ import annotations

import uuid

from sqlalchemy import CheckConstraint, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampUtc, UUIDPk
from app.db.tenancy import TenantScoped


class AssetRelationship(Base, TenantScoped):
    __tablename__ = "asset_relationships"
    __table_args__ = (
        UniqueConstraint(
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            name="uq_asset_relationships_triple",
        ),
        CheckConstraint(
            "source_asset_id <> target_asset_id",
            name="ck_asset_relationships_no_self_loop",
        ),
    )

    id: Mapped[UUIDPk]
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ai_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ai_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relationship_type: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[TimestampUtc]
