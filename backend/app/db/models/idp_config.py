"""Identity Provider configuration — per-organization SAML / OIDC / SCIM settings.

Provider-specific configuration is stored as JSONB rather than separate tables
because (a) only one of the three blocks is used per row, (b) the shape of each
block is well-defined by the protocol, (c) JSONB lets us evolve fields without
migrations as we add new IDPs.

Secrets (OIDC client_secret, SCIM bearer token) are stored as REFERENCES to a
secret store, never plaintext. In dev mode the resolver reads env vars; in
production this should point at AWS Secrets Manager / HashiCorp Vault / etc.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import (
    Base,
    JsonbDict,
    TimestampUtc,
    TimestampUtcUpdated,
    UUIDFk,
    UUIDPk,
)
from app.db.tenancy import TenantScoped

if TYPE_CHECKING:
    from app.db.models.organization import Organization


class IdpConfig(Base, TenantScoped):
    __tablename__ = "idp_configs"

    id: Mapped[UUIDPk]
    org_id: Mapped[UUIDFk] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    provider_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # saml | oidc | scim | ldap | custom_webhook
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="pending_verification"
    )  # active | disabled | pending_verification

    # Exactly one of these three is populated based on provider_type.
    # SAML config schema (see blueprint Decision 4):
    #   {entity_id, sso_url, slo_url, certificate, name_id_format, attribute_mappings}
    saml_config: Mapped[JsonbDict]
    # OIDC config schema:
    #   {issuer_url, client_id, client_secret_ref, scopes, audience, claim_mappings}
    oidc_config: Mapped[JsonbDict]
    # SCIM config schema:
    #   {endpoint_url, bearer_token_hash, sync_groups, auto_provision}
    scim_config: Mapped[JsonbDict]

    # Directory sync schedule + group→role mapping
    #   {enabled, frequency_minutes, last_synced_at, group_to_role_mapping, default_role}
    directory_sync: Mapped[JsonbDict]

    # Verification status: {tested_at, test_result, test_user}
    verification_status: Mapped[JsonbDict]

    created_by: Mapped[Optional[UUIDFk]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[TimestampUtc]
    updated_at: Mapped[TimestampUtcUpdated]

    organization: Mapped["Organization"] = relationship(back_populates="idp_configs")
