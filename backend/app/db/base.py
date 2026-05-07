"""SQLAlchemy 2.0 declarative base and shared column types."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from sqlalchemy import DateTime, MetaData
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, mapped_column

# Naming convention for constraints — keeps Alembic autogenerate diffs stable
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Common column types as Annotated aliases — used across all models.
UUIDPk = Annotated[
    uuid.UUID,
    mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
]
UUIDFk = Annotated[uuid.UUID, mapped_column(UUID(as_uuid=True), index=True)]
TimestampUtc = Annotated[
    datetime,
    mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False),
]
TimestampUtcUpdated = Annotated[
    datetime,
    mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False),
]
JsonbDict = Annotated[dict[str, Any], mapped_column(JSONB, default=dict, nullable=False)]
JsonbList = Annotated[list[Any], mapped_column(JSONB, default=list, nullable=False)]
