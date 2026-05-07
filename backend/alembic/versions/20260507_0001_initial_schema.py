"""initial schema — Sprint 1 (organizations, users, idp_configs, api_keys,
ai_assets, test_cases, evaluations, findings, policies)

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-07
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


JSONB = postgresql.JSONB(astext_type=sa.Text())
UUID = postgresql.UUID(as_uuid=True)


def _ts(default: bool = True, *, on_update: bool = False, nullable: bool = False) -> sa.Column:
    kwargs = {"nullable": nullable}
    if default:
        kwargs["server_default"] = sa.text("now() at time zone 'utc'")
    return sa.Column(
        "placeholder",
        sa.DateTime(timezone=True),
        **kwargs,
    )


def upgrade() -> None:
    # Required extensions. pgvector is needed in Sprint 2 for similarity search;
    # creating it now keeps later migrations clean.
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    # ---------------------------------------------------------------- organizations
    op.create_table(
        "organizations",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("plan_tier", sa.String(32), nullable=False, server_default="assessment"),
        sa.Column("settings", JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("slug", name="uq_organizations_slug"),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"])

    # ---------------------------------------------------------------- idp_configs
    op.create_table(
        "idp_configs",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider_type", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending_verification"),
        sa.Column("saml_config", JSONB, nullable=False, server_default="{}"),
        sa.Column("oidc_config", JSONB, nullable=False, server_default="{}"),
        sa.Column("scim_config", JSONB, nullable=False, server_default="{}"),
        sa.Column("directory_sync", JSONB, nullable=False, server_default="{}"),
        sa.Column("verification_status", JSONB, nullable=False, server_default="{}"),
        sa.Column("created_by", UUID, nullable=True),  # FK added after users table created
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_idp_configs_org_id", "idp_configs", ["org_id"])

    # ---------------------------------------------------------------- users
    op.create_table(
        "users",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False, server_default="viewer"),
        sa.Column("idp_config_id", UUID, sa.ForeignKey("idp_configs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("idp_subject_id", sa.String(255), nullable=True),
        sa.Column("idp_groups", JSONB, nullable=False, server_default="[]"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("org_id", "email", name="uq_users_org_id_email"),
        sa.UniqueConstraint("idp_config_id", "idp_subject_id", name="uq_users_idp_config_id_idp_subject_id"),
    )
    op.create_index("ix_users_org_id", "users", ["org_id"])
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_idp_config_id", "users", ["idp_config_id"])

    # Now we can backfill the FK on idp_configs.created_by
    op.create_foreign_key(
        "fk_idp_configs_created_by_users",
        "idp_configs",
        "users",
        ["created_by"],
        ["id"],
        ondelete="SET NULL",
    )

    # ---------------------------------------------------------------- api_keys
    op.create_table(
        "api_keys",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key_hash", sa.String(128), nullable=False),
        sa.Column("key_prefix", sa.String(8), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scopes", JSONB, nullable=False, server_default="[]"),
        sa.Column("created_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_api_keys_org_id", "api_keys", ["org_id"])
    op.create_index("ix_api_keys_key_prefix", "api_keys", ["key_prefix"])

    # ---------------------------------------------------------------- ai_assets
    op.create_table(
        "ai_assets",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        # Model identity
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model_name", sa.String(128), nullable=False),
        sa.Column("model_version", sa.String(128), nullable=True),
        sa.Column("hosting", sa.String(32), nullable=False, server_default="saas_api"),
        sa.Column("endpoint_url", sa.String(512), nullable=True),
        sa.Column("connector_config", JSONB, nullable=False, server_default="{}"),
        # System config
        sa.Column("system_prompt", sa.Text(), nullable=True),
        sa.Column("temperature", sa.Float(), nullable=True),
        sa.Column("max_tokens", sa.Integer(), nullable=True),
        sa.Column("top_p", sa.Float(), nullable=True),
        sa.Column("tools", JSONB, nullable=False, server_default="[]"),
        sa.Column("mcp_servers", JSONB, nullable=False, server_default="[]"),
        sa.Column("rag_sources", JSONB, nullable=False, server_default="[]"),
        sa.Column("plugins", JSONB, nullable=False, server_default="[]"),
        sa.Column("fine_tuning", JSONB, nullable=False, server_default="{}"),
        # Exposure
        sa.Column("environment", sa.String(32), nullable=False, server_default="dev"),
        sa.Column("exposure", sa.String(32), nullable=False, server_default="internal_only"),
        sa.Column("data_classification", sa.String(32), nullable=False, server_default="internal"),
        sa.Column("user_base_size", sa.Integer(), nullable=True),
        sa.Column("interactions_per_day", sa.Integer(), nullable=True),
        sa.Column("regulatory_scope", JSONB, nullable=False, server_default="[]"),
        # Supply chain
        sa.Column("dependencies", JSONB, nullable=False, server_default="[]"),
        sa.Column("data_lineage", JSONB, nullable=False, server_default="[]"),
        sa.Column("upstream_services", JSONB, nullable=False, server_default="[]"),
        sa.Column("downstream_consumers", JSONB, nullable=False, server_default="[]"),
        sa.Column("supply_chain_risk_score", sa.Float(), nullable=True),
        # Agent
        sa.Column("is_agentic", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("agent_framework", sa.String(64), nullable=True),
        sa.Column("max_tool_calls_per_session", sa.Integer(), nullable=True),
        sa.Column("human_in_loop_required", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("allowed_external_actions", JSONB, nullable=False, server_default="[]"),
        sa.Column("blast_radius_score", sa.Float(), nullable=True),
        # Security posture
        sa.Column("last_evaluation_id", UUID, nullable=True),
        sa.Column("last_evaluation_score", sa.Float(), nullable=True),
        sa.Column("last_evaluation_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("open_findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("runtime_agent_connected", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("runtime_agent_version", sa.String(32), nullable=True),
        sa.Column("runtime_policy_id", UUID, nullable=True),
        # Metadata
        sa.Column("owner_id", UUID, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("team", sa.String(128), nullable=True),
        sa.Column("tags", JSONB, nullable=False, server_default="[]"),
        sa.Column("change_log", JSONB, nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_ai_assets_org_id", "ai_assets", ["org_id"])
    op.create_index("ix_ai_assets_provider", "ai_assets", ["provider"])
    op.create_index("ix_ai_assets_environment", "ai_assets", ["environment"])

    # ---------------------------------------------------------------- test_cases
    op.create_table(
        "test_cases",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True),
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
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_test_cases_org_id", "test_cases", ["org_id"])
    op.create_index("ix_test_cases_category", "test_cases", ["category"])

    # ---------------------------------------------------------------- evaluations
    op.create_table(
        "evaluations",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", UUID, sa.ForeignKey("ai_assets.id", ondelete="CASCADE"), nullable=False),
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
        sa.Column("initiated_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("previous_evaluation_id", UUID, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_evaluations_org_id", "evaluations", ["org_id"])
    op.create_index("ix_evaluations_asset_id", "evaluations", ["asset_id"])
    op.create_index("ix_evaluations_status", "evaluations", ["status"])

    # ---------------------------------------------------------------- findings
    op.create_table(
        "findings",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("evaluation_id", UUID, sa.ForeignKey("evaluations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", UUID, sa.ForeignKey("ai_assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("test_case_id", UUID, sa.ForeignKey("test_cases.id", ondelete="RESTRICT"), nullable=False),
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
        sa.Column("remediation_owner", UUID, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("remediation_notes", sa.Text(), nullable=True),
        sa.Column("verified_by_evaluation_id", UUID, nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("regression_test_case_id", UUID, nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_findings_org_id", "findings", ["org_id"])
    op.create_index("ix_findings_evaluation_id", "findings", ["evaluation_id"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_category", "findings", ["category"])

    # ---------------------------------------------------------------- policies
    op.create_table(
        "policies",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(32), nullable=False, server_default="draft"),
        sa.Column("enforcement_level", sa.String(16), nullable=False, server_default="fast"),
        sa.Column("fail_behavior", sa.String(8), nullable=False, server_default="open"),
        sa.Column("ml_confidence_threshold_high", sa.Float(), nullable=False, server_default="0.7"),
        sa.Column("ml_confidence_threshold_low", sa.Float(), nullable=False, server_default="0.3"),
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
        sa.Column("created_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
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


def downgrade() -> None:
    op.drop_table("policies")
    op.drop_table("findings")
    op.drop_table("evaluations")
    op.drop_table("test_cases")
    op.drop_table("ai_assets")
    op.drop_table("api_keys")
    op.drop_constraint("fk_idp_configs_created_by_users", "idp_configs", type_="foreignkey")
    op.drop_table("users")
    op.drop_table("idp_configs")
    op.drop_table("organizations")
