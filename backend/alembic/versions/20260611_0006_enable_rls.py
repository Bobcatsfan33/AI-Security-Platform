"""Enable Row-Level Security on all tenant-scoped tables (Wall 2)

Revision ID: 0006_enable_rls
Revises: 0005_org_scoping
Create Date: 2026-06-11

Wall 2 of tenant isolation. Every tenant-owned table gets an RLS policy keyed on
the ``app.current_org`` GUC, which ``auth/dependencies.py`` (and SCIM auth) set
per transaction from the authenticated identity. Raw SQL, future ORM bypasses,
and bugs in the Wall-1 ORM guard all stop here.

``FORCE ROW LEVEL SECURITY`` binds the table owner too (belt and braces for any
path still using the owner DSN). The application connects as ``asp_app``
(NOBYPASSRLS — see ``deploy/db/roles.sql``); Alembic keeps running as the owner.

current_setting(..., true) returns NULL when the GUC is unset; ``org_id = NULL``
is never true, so a query with no org context returns zero rows — fail closed.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0006_enable_rls"
down_revision: str | None = "0005_org_scoping"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Mirrors the models marked TenantScoped in app/db/tenancy.py. Keep in sync: a
# new tenant table must be added here AND marked TenantScoped (the unit test
# test_every_tenant_model_is_marked guards the marker side).
TENANT_TABLES = (
    "ai_assets",
    "api_keys",
    "asset_changelog",
    "asset_relationships",
    "asset_tags",
    "connectors",
    "deployments",
    "idp_configs",
    "owners",
    "red_team_campaigns",
    "red_team_findings",
    "sync_jobs",
    "users",
)


def upgrade() -> None:
    for t in TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {t}_tenant_isolation ON {t} "
            "USING (org_id = current_setting('app.current_org', true)::uuid) "
            "WITH CHECK (org_id = current_setting('app.current_org', true)::uuid)"
        )


def downgrade() -> None:
    for t in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {t}_tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
