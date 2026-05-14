"""v2 pivot — drop governance schema, introduce asset graph

Revision ID: 0003_asset_graph_v2
Revises: 0002_connector_mcp
Create Date: 2026-05-13

The v2.0 product pivot focuses the platform on two wedges:
  Track 1 — Asset Inventory + Connectors (this migration's scope)
  Track 2 — Runtime Monitoring (untouched)

Governance tables (evaluations, findings, test_cases, policies, mcp_*,
the v1 ai_assets, connector_configs) are dropped. The new schema is
built around a connector → ai_asset graph with embedding-based search,
ownership, deployments, tags, relationships, and a changelog.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_asset_graph_v2"
down_revision: Union[str, None] = "0002_connector_mcp"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


JSONB = postgresql.JSONB(astext_type=sa.Text())
UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    # ─────────────────────────────────────────── drop v1 governance tables
    # Order matters: drop dependent tables before referenced tables.
    for table_name in (
        "mcp_violations",
        "mcp_calls",
        "mcp_tool_profiles",
        "findings",
        "evaluations",
        "test_cases",
        "policies",
        "ai_assets",
        "connector_configs",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table_name} CASCADE")

    # ─────────────────────────────────────────── enum types
    op.execute(
        "CREATE TYPE asset_type_enum AS ENUM "
        "('model', 'endpoint', 'dataset', 'pipeline', 'agent', 'tool')"
    )
    op.execute(
        "CREATE TYPE asset_status_enum AS ENUM "
        "('active', 'inactive', 'deprecated', 'unknown')"
    )
    op.execute(
        "CREATE TYPE sync_status_enum AS ENUM "
        "('pending', 'running', 'completed', 'failed')"
    )
    op.execute(
        "CREATE TYPE change_type_enum AS ENUM "
        "('created', 'updated', 'removed', 'owner_changed')"
    )

    # ─────────────────────────────────────────── owners
    op.create_table(
        "owners",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("team", sa.Text, nullable=False),
        sa.Column("email", sa.Text, nullable=False),
        sa.Column("department", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_owners_email", "owners", ["email"])

    # ─────────────────────────────────────────── connectors
    op.create_table(
        "connectors",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("connector_type", sa.Text, nullable=False),
        sa.Column("config_encrypted", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("schedule", sa.Text, nullable=True),
        sa.Column("is_enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_status", sa.Text, nullable=True),
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
    op.create_index("ix_connectors_connector_type", "connectors", ["connector_type"])
    op.create_index("ix_connectors_is_enabled", "connectors", ["is_enabled"])

    # ─────────────────────────────────────────── ai_assets (v2)
    op.create_table(
        "ai_assets",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column(
            "asset_type",
            postgresql.ENUM(name="asset_type_enum", create_type=False),
            nullable=False,
        ),
        sa.Column(
            "asset_status",
            postgresql.ENUM(name="asset_status_enum", create_type=False),
            nullable=False,
            server_default="active",
        ),
        sa.Column("provider", sa.Text, nullable=False),
        sa.Column("version", sa.Text, nullable=True),
        sa.Column("external_id", sa.Text, nullable=False),
        sa.Column(
            "connector_id",
            UUID,
            sa.ForeignKey("connectors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("risk_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "owner_id",
            UUID,
            sa.ForeignKey("owners.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("metadata_json", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        # pgvector — emitted as a raw type since SQLAlchemy doesn't know vector(n)
        sa.Column(
            "embedding",
            sa.dialects.postgresql.ARRAY(sa.Float),
            nullable=True,
        ),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
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
        sa.UniqueConstraint(
            "connector_id", "external_id", name="uq_ai_assets_connector_external"
        ),
        sa.CheckConstraint(
            "risk_score BETWEEN 0 AND 100", name="ck_ai_assets_risk_score_range"
        ),
    )
    # Replace the ARRAY column with a real pgvector vector(1536) column.
    op.execute("ALTER TABLE ai_assets DROP COLUMN embedding")
    op.execute("ALTER TABLE ai_assets ADD COLUMN embedding vector(1536)")

    op.create_index("ix_ai_assets_connector_id", "ai_assets", ["connector_id"])
    op.create_index("ix_ai_assets_asset_type", "ai_assets", ["asset_type"])
    op.create_index("ix_ai_assets_provider", "ai_assets", ["provider"])
    op.create_index("ix_ai_assets_risk_score", "ai_assets", ["risk_score"])
    op.create_index("ix_ai_assets_last_seen_at", "ai_assets", ["last_seen_at"])
    op.create_index("ix_ai_assets_owner_id", "ai_assets", ["owner_id"])
    op.create_index("ix_ai_assets_external_id", "ai_assets", ["external_id"])
    # IVFFlat index for cosine similarity — built lazily once enough rows exist.
    # Creating it empty is fine; tune `lists` later via REINDEX.
    op.execute(
        "CREATE INDEX ix_ai_assets_embedding "
        "ON ai_assets USING ivfflat (embedding vector_cosine_ops) "
        "WITH (lists = 100)"
    )

    # ─────────────────────────────────────────── deployments
    op.create_table(
        "deployments",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "asset_id",
            UUID,
            sa.ForeignKey("ai_assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("environment", sa.Text, nullable=False),
        sa.Column("endpoint_url", sa.Text, nullable=True),
        sa.Column("region", sa.Text, nullable=True),
        sa.Column("replicas", sa.Integer, nullable=True),
        sa.Column("status", sa.Text, nullable=False, server_default="active"),
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
    op.create_index("ix_deployments_asset_id", "deployments", ["asset_id"])
    op.create_index("ix_deployments_environment", "deployments", ["environment"])

    # ─────────────────────────────────────────── sync_jobs
    op.create_table(
        "sync_jobs",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "connector_id",
            UUID,
            sa.ForeignKey("connectors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "status",
            postgresql.ENUM(name="sync_status_enum", create_type=False),
            nullable=False,
            server_default="pending",
        ),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assets_discovered", sa.Integer, nullable=False, server_default="0"),
        sa.Column("assets_updated", sa.Integer, nullable=False, server_default="0"),
        sa.Column("assets_removed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text, nullable=True),
    )
    op.create_index("ix_sync_jobs_connector_id", "sync_jobs", ["connector_id"])
    op.create_index("ix_sync_jobs_started_at", "sync_jobs", ["started_at"])

    # ─────────────────────────────────────────── asset_tags
    op.create_table(
        "asset_tags",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "asset_id",
            UUID,
            sa.ForeignKey("ai_assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key", sa.Text, nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.UniqueConstraint("asset_id", "key", name="uq_asset_tags_asset_key"),
    )
    op.create_index("ix_asset_tags_asset_id", "asset_tags", ["asset_id"])
    op.create_index("ix_asset_tags_key", "asset_tags", ["key"])

    # ─────────────────────────────────────────── asset_relationships
    op.create_table(
        "asset_relationships",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "source_asset_id",
            UUID,
            sa.ForeignKey("ai_assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "target_asset_id",
            UUID,
            sa.ForeignKey("ai_assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relationship_type", sa.Text, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            name="uq_asset_relationships_triple",
        ),
        sa.CheckConstraint(
            "source_asset_id <> target_asset_id",
            name="ck_asset_relationships_no_self_loop",
        ),
    )
    op.create_index(
        "ix_asset_relationships_source", "asset_relationships", ["source_asset_id"]
    )
    op.create_index(
        "ix_asset_relationships_target", "asset_relationships", ["target_asset_id"]
    )

    # ─────────────────────────────────────────── asset_changelog
    op.create_table(
        "asset_changelog",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "asset_id",
            UUID,
            sa.ForeignKey("ai_assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "change_type",
            postgresql.ENUM(name="change_type_enum", create_type=False),
            nullable=False,
        ),
        sa.Column("previous_value", JSONB, nullable=True),
        sa.Column("new_value", JSONB, nullable=True),
        sa.Column(
            "changed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_asset_changelog_asset_id", "asset_changelog", ["asset_id"])
    op.create_index("ix_asset_changelog_changed_at", "asset_changelog", ["changed_at"])


def downgrade() -> None:
    # v2 is a one-way pivot — downgrade restores only an empty governance
    # surface. The v1 data is not recoverable from the v2 schema.
    for table_name in (
        "asset_changelog",
        "asset_relationships",
        "asset_tags",
        "sync_jobs",
        "deployments",
        "ai_assets",
        "connectors",
        "owners",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table_name} CASCADE")
    for enum in (
        "change_type_enum",
        "sync_status_enum",
        "asset_status_enum",
        "asset_type_enum",
    ):
        op.execute(f"DROP TYPE IF EXISTS {enum}")
