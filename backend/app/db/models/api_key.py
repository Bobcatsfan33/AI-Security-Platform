"""API Key model — bcrypt-hashed credentials for machine-to-machine auth."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JsonbList, TimestampUtc, UUIDFk, UUIDPk
from app.db.tenancy import TenantScoped

if TYPE_CHECKING:
    from app.db.models.organization import Organization


class ApiKey(Base, TenantScoped):
    __tablename__ = "api_keys"

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    # Bcrypt hash of the API key. The plaintext key is shown to the user once at creation
    # and never stored. We also persist a short prefix (first 8 chars) for display in the UI
    # — this is unauthenticated metadata, not a credential.
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(8), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scopes: Mapped[JsonbList]  # ["assets:read", "evaluations:write", ...]

    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    expires_at: Mapped[Optional[TimestampUtc]] = mapped_column(nullable=True)
    last_used_at: Mapped[Optional[TimestampUtc]] = mapped_column(nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    created_at: Mapped[TimestampUtc]

    organization: Mapped["Organization"] = relationship(back_populates="api_keys")
