"""Pin every organization to one data-residency region.

Revision ID: 0012_tenant_data_region
Revises: 0011_active_scim_integrity
Create Date: 2026-07-30

Existing tenants receive ``local`` and therefore cannot be served by a
production deployment until an operator assigns their approved region. This
is intentionally fail closed: a migration cannot infer a customer's legal
residency commitment.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0012_tenant_data_region"
down_revision: str | None = "0011_active_scim_integrity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column(
            "data_region",
            sa.String(length=32),
            nullable=False,
            server_default="local",
        ),
    )
    op.create_index("ix_organizations_data_region", "organizations", ["data_region"])
    # API-key authentication resolves a public key prefix before the tenant is
    # known. Keep FORCE RLS active and expose only rows matching the
    # transaction-local prefix supplied by verify_api_key; writes remain
    # governed exclusively by the tenant policy.
    op.execute(
        "CREATE POLICY api_keys_prefix_resolution ON api_keys FOR SELECT "
        "USING (key_prefix = NULLIF("
        "current_setting('app.api_key_prefix', true), ''))"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS api_keys_prefix_resolution ON api_keys")
    op.drop_index("ix_organizations_data_region", table_name="organizations")
    op.drop_column("organizations", "data_region")
