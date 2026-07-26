"""MCP persistence models — tool profiles, call history, violation records.

Part of the governance revival (WS3). The v2.0 pivot (migration 0003) dropped
the MCP tables together with the rest of the governance schema; this revives
:class:`McpToolProfile`, :class:`McpCall` and :class:`McpViolation` against the
authoritative DDL in ``20260509_0002_connector_configs_and_mcp`` and repoints
``app.mcp.service`` / ``app.api.v1.mcp`` at them. Schema is (re)created by
migration ``20260708_0009_revive_mcp``.

Unlike the v1 originals (plain ``Base``), these are :class:`TenantScoped` so
they are covered by the Wall-1 ORM guard and the Wall-2 RLS policy — matching
the rest of the governance revival (0007/0008).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import (
    Base,
    JsonbDict,
    JsonbList,
    TimestampUtc,
    TimestampUtcUpdated,
    UUIDFk,
    UUIDPk,
)
from app.db.tenancy import TenantScoped

_DateTimeTz = DateTime(timezone=True)


class McpToolProfile(Base, TenantScoped):
    """Operator-defined MCP tool profile, scoped to one org."""

    __tablename__ = "mcp_tool_profiles"
    __table_args__ = (
        UniqueConstraint("org_id", "tool_name", name="uq_mcp_tool_profiles_org_tool"),
        CheckConstraint(
            "access_mode IN ('read','write','execute','admin','exfil')",
            name="ck_mcp_tool_profiles_access_mode_valid",
        ),
    )

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    access_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    allowed_params: Mapped[JsonbList]
    forbidden_params: Mapped[JsonbList]
    param_constraints: Mapped[JsonbDict]

    # Attribution on a security surface: a profile always has a creator (the
    # API enforces it via the provisioned-subject 403), so NOT NULL. RESTRICT,
    # not SET NULL — deprovisioning deactivates (SCIM), it does not delete, so a
    # user carrying live attribution must not be hard-deleted out from under it.
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]


class McpCall(Base, TenantScoped):
    """One inspected MCP call. Append-only history."""

    __tablename__ = "mcp_calls"

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    session_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    access_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    params: Mapped[JsonbDict]
    recommendation: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    violations: Mapped[JsonbList]
    chain_matches: Mapped[JsonbList]
    called_at: Mapped[TimestampUtc]


class McpViolation(Base, TenantScoped):
    """Materialized non-allow recommendations.

    The dashboard reads from here rather than scanning mcp_calls.
    """

    __tablename__ = "mcp_violations"
    __table_args__ = (
        # A violation is 'open' IFF it has no resolver. This makes the audit
        # hole — "resolved (or acknowledged / false_positive) with no resolver" —
        # unrepresentable at the schema level, not merely unwritten by the API.
        CheckConstraint(
            "(resolution_status = 'open') = (resolved_by IS NULL)",
            name="ck_mcp_violations_resolver_matches_status",
        ),
    )

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    call_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("mcp_calls.id", ondelete="CASCADE"), nullable=False
    )
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    recommendation: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    violations: Mapped[JsonbList]
    chain_matches: Mapped[JsonbList]
    resolution_status: Mapped[str] = mapped_column(
        String(32), default="open", nullable=False
    )  # open | acknowledged | resolved | false_positive
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Stays nullable — NULL is the legitimate "unresolved" state. RESTRICT (not
    # SET NULL) so a resolver's stamp is never anonymized by deleting the user.
    # The CHECK below ties the stamp to the state: a violation is 'open' IFF it
    # has no resolver, so "acted-on with no resolver" is unrepresentable.
    resolved_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(_DateTimeTz, nullable=True)
    created_at: Mapped[TimestampUtc]
