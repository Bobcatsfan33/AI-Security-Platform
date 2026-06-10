"""Owner — the team/email/department that owns one or more AI assets."""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampUtc, UUIDPk


class Owner(Base):
    __tablename__ = "owners"

    id: Mapped[UUIDPk]
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    team: Mapped[str] = mapped_column(Text, nullable=False)
    email: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    department: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[TimestampUtc]
