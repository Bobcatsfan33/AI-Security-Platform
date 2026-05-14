"""Connector — registered external system that we sync AI assets from.

Replaces the v1 ``connector_configs`` table. v2 connectors are the
*ingest* point: each connector knows how to talk to one external system
(AWS SageMaker, OpenAI, Azure ML, etc.) and produces a stream of
:class:`DiscoveredAsset` records that the sync service folds into the
``ai_assets`` graph.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, JsonbDict, TimestampUtc, TimestampUtcUpdated, UUIDPk


class Connector(Base):
    __tablename__ = "connectors"

    id: Mapped[UUIDPk]
    name: Mapped[str] = mapped_column(Text, nullable=False)
    connector_type: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    # Credentials live as an encrypted JSON blob. The service layer uses
    # :mod:`app.security.field_crypto` to round-trip; the column itself
    # stores cipher bytes, not plaintext.
    config_encrypted: Mapped[JsonbDict]
    schedule: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, index=True
    )
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_sync_status: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]
