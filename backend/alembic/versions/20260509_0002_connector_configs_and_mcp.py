"""connector_configs + MCP tables

Revision ID: 0002_connector_mcp
Revises: 0001_initial
Create Date: 2026-05-09
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_connector_mcp"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


JSONB = postgresql.JSONB(astext_type=sa.Text())
UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    # ─────────────────────────────────────────── connector_configs
    op.create_table(
        "connector_configs",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("api_key_ref", sa.String(512), nullable=False, server_default=""),
        sa.Column("config", JSONB, nullable=False, server_default="{}"),
        sa.Column("verification_status", JSONB, nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_connector_configs_org_id", "connector_configs", ["org_id"])
    op.create_index(
        "ix_connector_configs_org_id_provider",
        "connector_configs",
        ["org_id", "provider"],
    )

    # ─────────────────────────────────────────── mcp_tool_profiles
    # Per-org tool registry. Built-in profiles are loaded into memory only
    # (see app/mcp/inspector.py DEFAULT_TOOL_PROFILES); rows here are
    # operator-defined customizations on top of the defaults.
    op.create_table(
        "mcp_tool_profiles",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("access_mode", sa.String(16), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("allowed_params", JSONB, nullable=False, server_default="[]"),
        sa.Column("forbidden_params", JSONB, nullable=False, server_default="[]"),
        sa.Column("param_constraints", JSONB, nullable=False, server_default="{}"),
        sa.Column("created_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("org_id", "tool_name", name="uq_mcp_tool_profiles_org_tool"),
        sa.CheckConstraint(
            "access_mode IN ('read','write','execute','admin','exfil')",
            name="ck_mcp_tool_profiles_access_mode_valid",
        ),
    )
    op.create_index("ix_mcp_tool_profiles_org_id", "mcp_tool_profiles", ["org_id"])

    # ─────────────────────────────────────────── mcp_calls
    # Append-only history of every inspected MCP call. Used to reconstruct
    # the chain context for chain-pattern matching on subsequent calls.
    op.create_table(
        "mcp_calls",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("session_id", sa.String(128), nullable=False),
        sa.Column("agent_id", sa.String(128), nullable=False, server_default=""),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("access_mode", sa.String(16), nullable=False),
        sa.Column("params", JSONB, nullable=False, server_default="{}"),
        sa.Column("recommendation", sa.String(16), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("violations", JSONB, nullable=False, server_default="[]"),
        sa.Column("chain_matches", JSONB, nullable=False, server_default="[]"),
        sa.Column("called_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_mcp_calls_org_id", "mcp_calls", ["org_id"])
    op.create_index("ix_mcp_calls_session_id", "mcp_calls", ["session_id"])
    op.create_index(
        "ix_mcp_calls_org_session_time",
        "mcp_calls",
        ["org_id", "session_id", "called_at"],
    )

    # ─────────────────────────────────────────── mcp_violations
    # Materialized list of every non-allow recommendation. Lets operators
    # query "show me everything flagged or blocked" without scanning the
    # full mcp_calls history.
    op.create_table(
        "mcp_violations",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("call_id", UUID, sa.ForeignKey("mcp_calls.id", ondelete="CASCADE"), nullable=False),
        sa.Column("session_id", sa.String(128), nullable=False),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("recommendation", sa.String(16), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("violations", JSONB, nullable=False, server_default="[]"),
        sa.Column("chain_matches", JSONB, nullable=False, server_default="[]"),
        sa.Column("resolution_status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.Column("resolved_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_mcp_violations_org_id", "mcp_violations", ["org_id"])
    op.create_index("ix_mcp_violations_call_id", "mcp_violations", ["call_id"])
    op.create_index(
        "ix_mcp_violations_org_status", "mcp_violations", ["org_id", "resolution_status"]
    )


def downgrade() -> None:
    op.drop_table("mcp_violations")
    op.drop_table("mcp_calls")
    op.drop_table("mcp_tool_profiles")
    op.drop_table("connector_configs")
