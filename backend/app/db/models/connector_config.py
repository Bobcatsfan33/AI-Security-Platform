"""ConnectorConfig model — per-org registered AI model providers.

Part of the v2 governance revival (see :mod:`app.db.models.evaluation`).
Columns mirror the v1 DDL from ``20260509_0002_connector_configs_and_mcp``.

Distinct from :class:`app.db.models.connector.Connector` (table
``connectors``), which is the v2 *asset-ingest* connector. This
``connector_configs`` table is the registry of *model provider*
credentials the evaluation runner drives a target model through
(``app/evaluation/runner.py`` → ``app/connectors/registry.build_connector``).

Each row is one registered provider: provider type, model identity,
credential reference (env: / awssm: / vault: / enc:), and provider-specific
config (Azure endpoint, Ollama base URL, etc.). Credentials are NEVER stored
in plaintext — the connector resolves the reference at use time. The model is
:class:`TenantScoped`, covered by the Wall-1 ORM guard and the Wall-2 RLS
policy added in migration ``20260704_0008``.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import (
    Base,
    JsonbDict,
    TimestampUtc,
    TimestampUtcUpdated,
    UUIDFk,
    UUIDPk,
)
from app.db.tenancy import TenantScoped


class ConnectorConfig(Base, TenantScoped):
    """Registered model provider credentials for one org."""

    __tablename__ = "connector_configs"

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    provider: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # openai | anthropic | ollama | azure_openai | bedrock | custom
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)

    # Reference, never plaintext. Empty allowed for providers without auth
    # (ollama). The verifier explicitly tolerates empty refs for those.
    api_key_ref: Mapped[str] = mapped_column(String(512), nullable=False, default="")

    # Provider-specific bag — base_url for Ollama, endpoint + deployment_name
    # for Azure, region/profile for Bedrock, etc.
    config: Mapped[JsonbDict]

    # Most-recent health_check outcome:
    #   {"ok": bool, "tested_at": iso, "error": str | null,
    #    "latency_ms": int | null}
    verification_status: Mapped[JsonbDict]

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]
