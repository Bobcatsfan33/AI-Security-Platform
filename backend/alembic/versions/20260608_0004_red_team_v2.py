"""Red Team v2 — campaign-of-record + per-attack findings

Revision ID: 0004_red_team_v2
Revises: 0003_asset_graph_v2
Create Date: 2026-06-08

Reintroduces a lean, self-contained pair of tables for the revived v2 Red
Teaming feature (the v1 evaluations/findings tables it used were dropped in
the v2 pivot): ``red_team_campaigns`` (run-of-record + aggregates) and
``red_team_findings`` (one row per successful attack, FK to the campaign).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0004_red_team_v2"
down_revision: str | None = "0003_asset_graph_v2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


JSONB = postgresql.JSONB(astext_type=sa.Text())
UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "red_team_campaigns",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "org_id",
            UUID,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("asset_id", UUID, nullable=True, index=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="created", index=True),
        sa.Column("strategy_ids", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("total_attacks", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("successful_attacks", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("target_errors", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("success_rate", sa.Float(), nullable=False, server_default="0"),
        sa.Column("score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("risk_label", sa.Text(), nullable=True),
        sa.Column("total_cost_usd", sa.Float(), nullable=False, server_default="0"),
        sa.Column("summary", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
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
    )
    op.create_table(
        "red_team_findings",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "org_id",
            UUID,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "campaign_id",
            UUID,
            sa.ForeignKey("red_team_campaigns.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("asset_id", UUID, nullable=True, index=True),
        sa.Column("strategy_id", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False, index=True),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("prompt", sa.Text(), nullable=False),
        sa.Column("response", sa.Text(), nullable=False, server_default=""),
        sa.Column("classification", sa.Text(), nullable=False, server_default=""),
        sa.Column("compliance_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("recommendation", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )


def downgrade() -> None:
    op.drop_table("red_team_findings")
    op.drop_table("red_team_campaigns")
