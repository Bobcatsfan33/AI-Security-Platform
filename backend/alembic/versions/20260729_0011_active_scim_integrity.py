"""Enforce one active SCIM provider per organization.

Revision ID: 0011_active_scim_integrity
Revises: 0010_mcp_attribution_integrity
Create Date: 2026-07-29

Inbound SCIM authentication resolves the active provider for an organization.
More than one active provider makes that identity ambiguous, so the database
must reject the state even when concurrent admin requests race past the API
preflight.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0011_active_scim_integrity"
down_revision: str | None = "0010_mcp_attribution_integrity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INDEX = "uq_idp_configs_active_scim_per_org"


def upgrade() -> None:
    op.execute(
        f"""
        CREATE UNIQUE INDEX {_INDEX}
        ON idp_configs (org_id)
        WHERE provider_type = 'scim' AND status = 'active'
        """
    )


def downgrade() -> None:
    op.drop_index(_INDEX, table_name="idp_configs")
