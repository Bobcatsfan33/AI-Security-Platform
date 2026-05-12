"""ConnectorConfig model — per-org registered AI model providers.

Each row represents one registered connector: provider type, model
identity, credential reference (env: / awssm: / vault: / enc:), and
provider-specific config (Azure endpoint, Ollama base URL, etc.).

Credentials are NEVER stored in plaintext. The connector resolves the
reference through :mod:`app.security.secrets` at use time. Admins who
paste a plaintext key in the UI get auto-encryption via the same
``enc-pending:`` flow already used for OIDC client secrets in
:mod:`app.api.v1.idp_admin`.

Verification status records the most recent ``health_check`` outcome so
the dashboard can show which connectors are currently usable without
re-testing on every render.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import (
    Base,
    JsonbDict,
    TimestampUtc,
    TimestampUtcUpdated,
    UUIDFk,
    UUIDPk,
)

if TYPE_CHECKING:
    from app.db.models.organization import Organization


class ConnectorConfig(Base):
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

    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_by: Mapped[Optional[UUIDFk]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]

    organization: Mapped["Organization"] = relationship()
