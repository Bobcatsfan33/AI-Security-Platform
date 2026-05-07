"""User model.

Users always belong to exactly one organization. Identity (idp_subject_id) is
unique per IDP — a user provisioned by Org A's Okta cannot collide with a
user provisioned by Org B's Okta.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import (
    Base,
    JsonbList,
    TimestampUtc,
    TimestampUtcUpdated,
    UUIDFk,
    UUIDPk,
)

if TYPE_CHECKING:
    from app.db.models.idp_config import IdpConfig
    from app.db.models.organization import Organization


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("org_id", "email", name="uq_users_org_id_email"),
        UniqueConstraint(
            "idp_config_id",
            "idp_subject_id",
            name="uq_users_idp_config_id_idp_subject_id",
        ),
    )

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(32), nullable=False, default="viewer"
    )  # owner | admin | analyst | viewer | api_only

    # Identity provider linkage (NULL for legacy/local users — not supported in Sprint 1)
    idp_config_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("idp_configs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    idp_subject_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    idp_groups: Mapped[JsonbList]

    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    last_login_at: Mapped[Optional[TimestampUtc]] = mapped_column(nullable=True)
    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]

    organization: Mapped["Organization"] = relationship(back_populates="users")
    idp_config: Mapped[Optional["IdpConfig"]] = relationship()
