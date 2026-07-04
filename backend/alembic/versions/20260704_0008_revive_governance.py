"""Revive governance schema — evaluations, findings, test_cases, connector_configs

Revision ID: 0008_revive_governance
Revises: 0007_revive_policies
Create Date: 2026-07-04

The v2 pivot (0003) dropped the v1 governance schema together with its models.
0007 revived ``policies``; this revives the remaining four tables the
governance pages (Evaluations, Findings, Test Cases) and the evaluation runner
ride on. DDL is hand-copied from the authoritative sources — ``evaluations`` /
``findings`` / ``test_cases`` from ``20260507_0001_initial_schema`` and
``connector_configs`` from ``20260509_0002_connector_configs_and_mcp`` — NOT
alembic autogenerate.

RLS mirrors the shape 0006/0007 applied to every tenant table: ENABLE + FORCE
row level security and a per-table ``<table>_tenant_isolation`` policy keyed on
the ``app.current_org`` GUC.

test_cases exception: ``org_id`` is nullable by design — NULL rows are the
global/shared test-case library every org can run (see
``app/db/models/test_case.py`` and the ``org_id IS NULL`` union in
``app/evaluation/runner.py``). Its RLS policy therefore admits ``org_id IS NULL``
rows in addition to the tenant's own, so the shared library stays visible; a
blanket ``org_id = current_setting(...)`` (NULL is never equal) would hide it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0008_revive_governance"
down_revision: str | None = "0007_revive_policies"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


JSONB = postgresql.JSONB(astext_type=sa.Text())
UUID = postgresql.UUID(as_uuid=True)

# Standard tenant tables (org_id NOT NULL) — same RLS shape as 0006/0007.
_STD_RLS_TABLES = ("evaluations", "findings", "connector_configs")


def upgrade() -> None:
    # ─────────────────────────────────────────── test_cases (from 0001)
    # org_id is nullable: NULL == global/shared library.
    op.create_table(
        "test_cases",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "org_id",
            UUID,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("sub_category", sa.String(64), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("attack_type", sa.String(32), nullable=False, server_default="single_turn"),
        sa.Column("prompts", JSONB, nullable=False, server_default="[]"),
        sa.Column("system_prompt_override", sa.Text(), nullable=True),
        sa.Column("injected_context", sa.Text(), nullable=True),
        sa.Column("expected_behavior", sa.Text(), nullable=False),
        sa.Column("success_criteria", JSONB, nullable=False, server_default="{}"),
        sa.Column("failure_indicators", JSONB, nullable=False, server_default="[]"),
        sa.Column("tags", JSONB, nullable=False, server_default="[]"),
        sa.Column("control_mappings", JSONB, nullable=False, server_default="[]"),
        sa.Column("mitre_atlas_id", sa.String(32), nullable=True),
        sa.Column("source", sa.String(32), nullable=False, server_default="manual"),
        sa.Column("generated_from", JSONB, nullable=False, server_default="{}"),
        sa.Column("effectiveness_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("is_regression", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
    )
    op.create_index("ix_test_cases_org_id", "test_cases", ["org_id"])
    op.create_index("ix_test_cases_category", "test_cases", ["category"])

    # ─────────────────────────────────────────── connector_configs (from 0002)
    op.create_table(
        "connector_configs",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "org_id",
            UUID,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("api_key_ref", sa.String(512), nullable=False, server_default=""),
        sa.Column("config", JSONB, nullable=False, server_default="{}"),
        sa.Column("verification_status", JSONB, nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("notes", sa.Text(), nullable=True),
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
    )
    op.create_index("ix_connector_configs_org_id", "connector_configs", ["org_id"])
    op.create_index(
        "ix_connector_configs_org_id_provider",
        "connector_configs",
        ["org_id", "provider"],
    )

    # ─────────────────────────────────────────── evaluations (from 0001)
    op.create_table(
        "evaluations",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "org_id",
            UUID,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            UUID,
            sa.ForeignKey("ai_assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("triggered_by", sa.String(32), nullable=False, server_default="manual"),
        sa.Column("trigger_context", JSONB, nullable=False, server_default="{}"),
        sa.Column("status", sa.String(32), nullable=False, server_default="created"),
        sa.Column("eval_type", sa.String(32), nullable=False, server_default="full"),
        sa.Column("test_case_ids", JSONB, nullable=False, server_default="[]"),
        sa.Column("connector_id", UUID, nullable=True),
        sa.Column("max_test_cases", sa.Integer(), nullable=True),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="600"),
        sa.Column("parallel_workers", sa.Integer(), nullable=False, server_default="4"),
        sa.Column("score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("risk_label", sa.String(32), nullable=True),
        sa.Column("tests_run", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tests_passed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tests_failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary", JSONB, nullable=False, server_default="{}"),
        sa.Column("model_cost_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("gate_result", sa.String(32), nullable=True),
        sa.Column("gate_policy", JSONB, nullable=False, server_default="{}"),
        sa.Column("gate_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "initiated_by",
            UUID,
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("previous_evaluation_id", UUID, nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
    )
    op.create_index("ix_evaluations_org_id", "evaluations", ["org_id"])
    op.create_index("ix_evaluations_asset_id", "evaluations", ["asset_id"])
    op.create_index("ix_evaluations_status", "evaluations", ["status"])

    # ─────────────────────────────────────────── findings (from 0001)
    op.create_table(
        "findings",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "org_id",
            UUID,
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "evaluation_id",
            UUID,
            sa.ForeignKey("evaluations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            UUID,
            sa.ForeignKey("ai_assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "test_case_id",
            UUID,
            sa.ForeignKey("test_cases.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("sub_category", sa.String(64), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("attack_succeeded", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("control_mappings", JSONB, nullable=False, server_default="[]"),
        sa.Column("prompt_sent", sa.Text(), nullable=True),
        sa.Column("response_received", sa.Text(), nullable=True),
        sa.Column("system_prompt_used", sa.Text(), nullable=True),
        sa.Column("context_injected", sa.Text(), nullable=True),
        sa.Column("tool_calls_made", JSONB, nullable=False, server_default="[]"),
        sa.Column("judge_reasoning", sa.Text(), nullable=True),
        sa.Column("policy_results", JSONB, nullable=False, server_default="[]"),
        sa.Column("evidence_artifacts", JSONB, nullable=False, server_default="[]"),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("remediation_status", sa.String(32), nullable=False, server_default="open"),
        sa.Column(
            "remediation_owner",
            UUID,
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("remediation_notes", sa.Text(), nullable=True),
        sa.Column("verified_by_evaluation_id", UUID, nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("regression_test_case_id", UUID, nullable=True),
        sa.Column(
            "first_seen_at",
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
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column(
            "updated_by",
            UUID,
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_findings_org_id", "findings", ["org_id"])
    op.create_index("ix_findings_evaluation_id", "findings", ["evaluation_id"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_category", "findings", ["category"])

    # ─────────────────────────────────────────── Wall 2 — RLS
    # Standard tenant tables: same shape 0006/0007 applied everywhere.
    for t in _STD_RLS_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {t}_tenant_isolation ON {t} "
            "USING (org_id = current_setting('app.current_org', true)::uuid) "
            "WITH CHECK (org_id = current_setting('app.current_org', true)::uuid)"
        )

    # test_cases: admit the global/shared library (org_id IS NULL) alongside the
    # tenant's own rows, both for reads (USING) and writes (WITH CHECK — global
    # library seeding sets org_id NULL). Global test cases carry no tenant data.
    op.execute("ALTER TABLE test_cases ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE test_cases FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY test_cases_tenant_isolation ON test_cases "
        "USING (org_id IS NULL OR org_id = current_setting('app.current_org', true)::uuid) "
        "WITH CHECK (org_id IS NULL OR org_id = current_setting('app.current_org', true)::uuid)"
    )


def downgrade() -> None:
    # Drop RLS policies before the tables (mirrors 0007). FK order: drop findings
    # (FKs evaluations + test_cases) before its parents.
    op.execute("DROP POLICY IF EXISTS test_cases_tenant_isolation ON test_cases")
    for t in _STD_RLS_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {t}_tenant_isolation ON {t}")

    op.drop_table("findings")
    op.drop_table("evaluations")
    op.drop_table("connector_configs")
    op.drop_table("test_cases")
