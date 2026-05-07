"""AI Asset model — full Sprint 1 schema per blueprint.

An AI asset represents a deployed model / agent / RAG system / copilot that
the platform monitors and protects. Most fields are JSONB blobs for things
that don't need indexed querying (system_prompt, tools, mcp_servers, etc.).
The flat fields are those we filter or aggregate on (provider, environment,
exposure, owner, status).
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import (
    Base,
    JsonbDict,
    JsonbList,
    TimestampUtc,
    TimestampUtcUpdated,
    UUIDFk,
    UUIDPk,
)

if TYPE_CHECKING:
    from app.db.models.organization import Organization


class AIAsset(Base):
    __tablename__ = "ai_assets"

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="active"
    )  # active | inactive | decommissioned | under_review

    # --- Model identity ---
    provider: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # openai | anthropic | google | azure_openai | bedrock | ollama | vllm | custom
    model_name: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    hosting: Mapped[str] = mapped_column(
        String(32), nullable=False, default="saas_api"
    )  # saas_api | self_hosted | private_cloud | on_prem
    endpoint_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    connector_config: Mapped[JsonbDict]

    # --- System configuration ---
    system_prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    temperature: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    max_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    top_p: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    tools: Mapped[JsonbList]
    mcp_servers: Mapped[JsonbList]
    rag_sources: Mapped[JsonbList]
    plugins: Mapped[JsonbList]
    fine_tuning: Mapped[JsonbDict]

    # --- Exposure & classification ---
    environment: Mapped[str] = mapped_column(
        String(32), nullable=False, default="dev", index=True
    )  # dev | staging | production
    exposure: Mapped[str] = mapped_column(
        String(32), nullable=False, default="internal_only"
    )  # internal_only | customer_facing | public | api_only
    data_classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default="internal"
    )  # public | internal | confidential | restricted | regulated
    user_base_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    interactions_per_day: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    regulatory_scope: Mapped[JsonbList]

    # --- Supply chain (AI-BOM) — populated by Sprint 6 ---
    dependencies: Mapped[JsonbList]
    data_lineage: Mapped[JsonbList]
    upstream_services: Mapped[JsonbList]
    downstream_consumers: Mapped[JsonbList]
    supply_chain_risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # --- Agent configuration (for agentic systems) ---
    is_agentic: Mapped[bool] = mapped_column(default=False, nullable=False)
    agent_framework: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    max_tool_calls_per_session: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    human_in_loop_required: Mapped[bool] = mapped_column(default=False, nullable=False)
    allowed_external_actions: Mapped[JsonbList]
    blast_radius_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # --- Security posture (cached, refreshed by evaluation runner) ---
    last_evaluation_id: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)
    last_evaluation_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    last_evaluation_date: Mapped[Optional[TimestampUtc]] = mapped_column(nullable=True)
    open_findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    runtime_agent_connected: Mapped[bool] = mapped_column(default=False, nullable=False)
    runtime_agent_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    runtime_policy_id: Mapped[Optional[uuid.UUID]] = mapped_column(nullable=True)

    # --- Metadata ---
    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    team: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    tags: Mapped[JsonbList]
    change_log: Mapped[JsonbList]

    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]

    organization: Mapped["Organization"] = relationship()
