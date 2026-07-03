"""Revive policies table — runtime agent policy distribution (v2)

Revision ID: 0007_revive_policies
Revises: 0006_enable_rls
Create Date: 2026-07-03

The v2 pivot (0003) dropped the v1 ``policies`` table with the governance
schema, but Track 2 (Runtime Monitoring) still distributes enforcement
policies to the runtime agent via ``GET /v1/policies/{id}``. Recreates the
table with the v1 DDL (from 0001) and enables RLS in the same shape 0006
applied to every tenant table.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0007_revive_policies"
down_revision: str | None = "0006_enable_rls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


JSONB = postgresql.JSONB(astext_type=sa.Text())
UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "policies",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "org_id",
            UUID,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(32), nullable=False, server_default="draft"),
        sa.Column("enforcement_level", sa.String(16), nullable=False, server_default="fast"),
        sa.Column("fail_behavior", sa.String(8), nullable=False, server_default="open"),
        sa.Column(
            "ml_confidence_threshold_high", sa.Float(), nullable=False, server_default="0.7"
        ),
        sa.Column(
            "ml_confidence_threshold_low", sa.Float(), nullable=False, server_default="0.3"
        ),
        sa.Column("judge_model_endpoint", sa.String(512), nullable=True),
        sa.Column("rules", JSONB, nullable=False, server_default="[]"),
        sa.Column("tool_allowlist", JSONB, nullable=False, server_default="[]"),
        sa.Column("tool_denylist", JSONB, nullable=False, server_default="[]"),
        sa.Column("tool_approval_required", JSONB, nullable=False, server_default="[]"),
        sa.Column("rate_limits", JSONB, nullable=False, server_default="{}"),
        sa.Column("content_filters", JSONB, nullable=False, server_default="{}"),
        sa.Column("classifiers", JSONB, nullable=False, server_default="[]"),
        sa.Column("classifier_sync_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("judge_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("judge_system_prompt", sa.Text(), nullable=True),
        sa.Column("judge_categories", JSONB, nullable=False, server_default="[]"),
        sa.Column("judge_timeout_ms", sa.Integer(), nullable=False, server_default="3000"),
        sa.Column("judge_fallback_action", sa.String(16), nullable=False, server_default="flag"),
        sa.Column("assigned_assets", JSONB, nullable=False, server_default="[]"),
        sa.Column("sync_status", JSONB, nullable=False, server_default="{}"),
        sa.Column("last_distributed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_by",
            UUID,
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("change_log", JSONB, nullable=False, server_default="[]"),
        sa.CheckConstraint(
            "enforcement_level IN ('fast', 'balanced', 'comprehensive')",
            name="ck_policies_enforcement_level_valid",
        ),
        sa.CheckConstraint(
            "fail_behavior IN ('open', 'closed')",
            name="ck_policies_fail_behavior_valid",
        ),
    )
    op.create_index("ix_policies_org_id", "policies", ["org_id"])

    # Wall 2 — same RLS shape 0006 applied to every tenant table.
    op.execute("ALTER TABLE policies ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE policies FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY policies_tenant_isolation ON policies "
        "USING (org_id = current_setting('app.current_org', true)::uuid) "
        "WITH CHECK (org_id = current_setting('app.current_org', true)::uuid)"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS policies_tenant_isolation ON policies")
    op.drop_index("ix_policies_org_id", table_name="policies")
    op.drop_table("policies")
