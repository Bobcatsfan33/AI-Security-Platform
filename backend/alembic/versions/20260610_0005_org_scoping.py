"""Multi-tenant org scoping for the asset graph

Revision ID: 0005_org_scoping
Revises: 0004_red_team_v2
Create Date: 2026-06-10

The v2 pivot rebuilt the asset graph without tenant scoping. This adds
``org_id`` (FK organizations, indexed) to every tenant-owned asset-graph table
so reads/writes can be isolated per org — matching the already-org-scoped
RAPIDE detection layer. NOT NULL is safe: these tables carry no rows before
GA (every environment provisions the schema fresh).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0005_org_scoping"
down_revision: str | None = "0004_red_team_v2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)

_TABLES = (
    "connectors",
    "ai_assets",
    "deployments",
    "owners",
    "sync_jobs",
    "asset_tags",
    "asset_relationships",
    "asset_changelog",
)


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(
            table,
            sa.Column(
                "org_id",
                UUID,
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
        )
        op.create_index(f"ix_{table}_org_id", table, ["org_id"])


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.drop_index(f"ix_{table}_org_id", table_name=table)
        op.drop_column(table, "org_id")
