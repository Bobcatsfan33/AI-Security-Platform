"""MCP attribution integrity — NOT NULL creator, RESTRICT deletes, state-tied resolver

Revision ID: 0010_mcp_attribution_integrity
Revises: 0009_revive_mcp
Create Date: 2026-07-25

Closes the attribution hole 0009 shipped: ``created_by`` / ``resolved_by`` were
``nullable`` with ``ondelete=SET NULL``, so deleting a user silently anonymized
their historical stamps — an audit trail with a hole on a security surface.

The tightening, per-column (they are not symmetric):

* ``mcp_tool_profiles.created_by`` → **NOT NULL** + **ON DELETE RESTRICT**. A
  profile always has a creator; the API now guarantees it (the provisioned-
  subject 403), and the schema enforces it.
* ``mcp_violations.resolved_by`` → stays **nullable** (NULL is the legitimate
  "unresolved" state) but gains **ON DELETE RESTRICT**, plus a CHECK that ties
  the stamp to the state: ``(resolution_status = 'open') = (resolved_by IS
  NULL)``. The real hole was never "nullable" — it was "acted-on with no
  resolver". The CHECK makes that state *unrepresentable*, not merely unwritten.

RESTRICT (not CASCADE/SET NULL) because deprovisioning is DEACTIVATION, not
deletion (``app/scim/users.py`` sets ``is_active = False``). A user carrying
live attribution can no longer be hard-deleted out from under the audit trail.

Backfill (a no-op on a fresh DB — these tables are empty until real traffic):
existing NULL/degraded stamps are attributed to a per-org sentinel "system"
user (``system@platform.internal``, inactive, api_only), created only for orgs
that actually need it. Documented here because a sentinel that isn't documented
is indistinguishable from a real actor later.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0010_mcp_attribution_integrity"
down_revision: str | None = "0009_revive_mcp"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FK_CREATED_BY = "fk_mcp_tool_profiles_created_by_users"
_FK_RESOLVED_BY = "fk_mcp_violations_resolved_by_users"
_CK_RESOLVER_STATE = "ck_mcp_violations_resolver_matches_status"
_SENTINEL_EMAIL = "system@platform.internal"


def upgrade() -> None:
    # ── Backfill (no-op on an empty DB) ──────────────────────────────────────
    # 1. A per-org sentinel user for every org that has a stamp we must repair:
    #    a NULL creator, OR a non-open violation with no resolver. ON CONFLICT
    #    keeps it idempotent against the (org_id, email) unique constraint.
    op.execute(
        f"""
        INSERT INTO users (id, org_id, email, name, role, is_active, idp_groups,
                           created_at, updated_at)
        SELECT gen_random_uuid(), o.org_id, '{_SENTINEL_EMAIL}',
               'System (migration backfill)', 'api_only', false, '[]'::jsonb,
               now(), now()
        FROM (
            SELECT DISTINCT org_id FROM mcp_tool_profiles WHERE created_by IS NULL
            UNION
            SELECT DISTINCT org_id FROM mcp_violations
              WHERE resolution_status <> 'open' AND resolved_by IS NULL
        ) o
        ON CONFLICT (org_id, email) DO NOTHING
        """
    )
    # 2. Attribute NULL creators to their org's sentinel.
    op.execute(
        f"""
        UPDATE mcp_tool_profiles p
        SET created_by = u.id
        FROM users u
        WHERE p.created_by IS NULL
          AND u.org_id = p.org_id AND u.email = '{_SENTINEL_EMAIL}'
        """
    )
    # 3. Close the "acted-on with no resolver" hole: attribute to the sentinel.
    op.execute(
        f"""
        UPDATE mcp_violations v
        SET resolved_by = u.id, resolved_at = COALESCE(v.resolved_at, now())
        FROM users u
        WHERE v.resolution_status <> 'open' AND v.resolved_by IS NULL
          AND u.org_id = v.org_id AND u.email = '{_SENTINEL_EMAIL}'
        """
    )
    # 4. Its inverse: an open violation must not carry a resolver stamp (no path
    #    creates this today, but the CHECK below would reject it — repair first).
    op.execute(
        "UPDATE mcp_violations SET resolved_by = NULL, resolved_at = NULL "
        "WHERE resolution_status = 'open' AND resolved_by IS NOT NULL"
    )

    # ── mcp_tool_profiles.created_by: NOT NULL + RESTRICT ────────────────────
    op.drop_constraint(_FK_CREATED_BY, "mcp_tool_profiles", type_="foreignkey")
    op.alter_column("mcp_tool_profiles", "created_by", nullable=False)
    op.create_foreign_key(
        _FK_CREATED_BY,
        "mcp_tool_profiles",
        "users",
        ["created_by"],
        ["id"],
        ondelete="RESTRICT",
    )

    # ── mcp_violations.resolved_by: RESTRICT (stays nullable) + state CHECK ───
    op.drop_constraint(_FK_RESOLVED_BY, "mcp_violations", type_="foreignkey")
    op.create_foreign_key(
        _FK_RESOLVED_BY,
        "mcp_violations",
        "users",
        ["resolved_by"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        _CK_RESOLVER_STATE,
        "mcp_violations",
        "(resolution_status = 'open') = (resolved_by IS NULL)",
    )


def downgrade() -> None:
    # Reverse in the opposite order. The sentinel users are left in place: they
    # may now own attribution rows, and deleting them would reintroduce the very
    # NULLs this migration removed.
    op.drop_constraint(_CK_RESOLVER_STATE, "mcp_violations", type_="check")
    op.drop_constraint(_FK_RESOLVED_BY, "mcp_violations", type_="foreignkey")
    op.create_foreign_key(
        _FK_RESOLVED_BY,
        "mcp_violations",
        "users",
        ["resolved_by"],
        ["id"],
        ondelete="SET NULL",
    )

    op.drop_constraint(_FK_CREATED_BY, "mcp_tool_profiles", type_="foreignkey")
    op.alter_column("mcp_tool_profiles", "created_by", nullable=True)
    op.create_foreign_key(
        _FK_CREATED_BY,
        "mcp_tool_profiles",
        "users",
        ["created_by"],
        ["id"],
        ondelete="SET NULL",
    )
