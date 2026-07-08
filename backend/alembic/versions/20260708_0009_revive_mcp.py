"""Revive MCP schema — mcp_tool_profiles, mcp_calls, mcp_violations

Revision ID: 0009_revive_mcp
Revises: 0008_revive_governance
Create Date: 2026-07-08

WS3 of the governance revival. The v2 pivot (0003) dropped the MCP tables with
the rest of the governance schema; 0008 revived evaluations/findings/test_cases/
connector_configs, and this revives the last three — the MCP inspection tables
the MCP page (``app.api.v1.mcp``) and its service ride on. DDL is hand-copied
from the authoritative source ``20260509_0002_connector_configs_and_mcp`` — NOT
alembic autogenerate.

RLS mirrors 0006/0007/0008: ENABLE + FORCE row level security and a per-table
``<table>_tenant_isolation`` policy keyed on the ``app.current_org`` GUC. All
three tables have a NOT NULL ``org_id`` so they use the standard policy.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0009_revive_mcp"
down_revision: str | None = "0008_revive_governance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


JSONB = postgresql.JSONB(astext_type=sa.Text())
UUID = postgresql.UUID(as_uuid=True)

_RLS_TABLES = ("mcp_tool_profiles", "mcp_calls", "mcp_violations")


def upgrade() -> None:
    # ─────────────────────────────────────────── mcp_tool_profiles (from 0002)
    op.create_table(
        "mcp_tool_profiles",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "org_id",
            UUID,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("access_mode", sa.String(16), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("allowed_params", JSONB, nullable=False, server_default="[]"),
        sa.Column("forbidden_params", JSONB, nullable=False, server_default="[]"),
        sa.Column("param_constraints", JSONB, nullable=False, server_default="{}"),
        sa.Column(
            "created_by",
            UUID,
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
        sa.UniqueConstraint("org_id", "tool_name", name="uq_mcp_tool_profiles_org_tool"),
        sa.CheckConstraint(
            "access_mode IN ('read','write','execute','admin','exfil')",
            name="ck_mcp_tool_profiles_access_mode_valid",
        ),
    )
    op.create_index("ix_mcp_tool_profiles_org_id", "mcp_tool_profiles", ["org_id"])

    # ─────────────────────────────────────────── mcp_calls (from 0002)
    op.create_table(
        "mcp_calls",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "org_id",
            UUID,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("session_id", sa.String(128), nullable=False),
        sa.Column("agent_id", sa.String(128), nullable=False, server_default=""),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("access_mode", sa.String(16), nullable=False),
        sa.Column("params", JSONB, nullable=False, server_default="{}"),
        sa.Column("recommendation", sa.String(16), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("violations", JSONB, nullable=False, server_default="[]"),
        sa.Column("chain_matches", JSONB, nullable=False, server_default="[]"),
        sa.Column(
            "called_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
    )
    op.create_index("ix_mcp_calls_org_id", "mcp_calls", ["org_id"])
    op.create_index("ix_mcp_calls_session_id", "mcp_calls", ["session_id"])
    op.create_index(
        "ix_mcp_calls_org_session_time",
        "mcp_calls",
        ["org_id", "session_id", "called_at"],
    )

    # ─────────────────────────────────────────── mcp_violations (from 0002)
    op.create_table(
        "mcp_violations",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "org_id",
            UUID,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "call_id",
            UUID,
            sa.ForeignKey("mcp_calls.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("session_id", sa.String(128), nullable=False),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("recommendation", sa.String(16), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("violations", JSONB, nullable=False, server_default="[]"),
        sa.Column("chain_matches", JSONB, nullable=False, server_default="[]"),
        sa.Column("resolution_status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.Column(
            "resolved_by",
            UUID,
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
    )
    op.create_index("ix_mcp_violations_org_id", "mcp_violations", ["org_id"])
    op.create_index("ix_mcp_violations_call_id", "mcp_violations", ["call_id"])
    op.create_index(
        "ix_mcp_violations_org_status", "mcp_violations", ["org_id", "resolution_status"]
    )

    # ─────────────────────────────────────────── Wall 2 — RLS
    for t in _RLS_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {t}_tenant_isolation ON {t} "
            "USING (org_id = current_setting('app.current_org', true)::uuid) "
            "WITH CHECK (org_id = current_setting('app.current_org', true)::uuid)"
        )


def downgrade() -> None:
    # Drop RLS policies before the tables (mirrors 0007/0008). FK order: drop
    # mcp_violations (FKs mcp_calls) before mcp_calls.
    for t in _RLS_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {t}_tenant_isolation ON {t}")

    op.drop_table("mcp_violations")
    op.drop_table("mcp_calls")
    op.drop_table("mcp_tool_profiles")
