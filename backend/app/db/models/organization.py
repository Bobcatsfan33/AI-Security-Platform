"""Organization (tenant) model.

Every other resource in the platform is scoped by org_id. Tenant isolation
is enforced at the repository layer — see app/db/repositories/base.py.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JsonbDict, TimestampUtc, TimestampUtcUpdated, UUIDPk

if TYPE_CHECKING:
    from app.db.models.api_key import ApiKey
    from app.db.models.idp_config import IdpConfig
    from app.db.models.user import User


class Organization(Base):
    __tablename__ = "organizations"
    __table_args__ = (UniqueConstraint("slug", name="uq_organizations_slug"),)

    id: Mapped[UUIDPk]
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    plan_tier: Mapped[str] = mapped_column(
        String(32), nullable=False, default="assessment"
    )  # assessment | continuous | runtime | intelligence
    settings: Mapped[JsonbDict]

    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]

    users: Mapped[list["User"]] = relationship(back_populates="organization")
    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="organization")
    idp_configs: Mapped[list["IdpConfig"]] = relationship(back_populates="organization")
