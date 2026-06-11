"""SCIM bearer-token authentication.

The IdP authenticates inbound SCIM requests with
``Authorization: Bearer <token>``. The token's bcrypt hash lives in the
``scim_config.bearer_token_hash`` field on a SCIM-type IdP config row.
The plaintext is shown to the admin exactly once when minted (see
:func:`mint_scim_token` in ``app/api/v1/idp_admin.py``).

This dependency:
1. Resolves the org by URL slug
2. Loads the org's SCIM IdP config (must be active)
3. bcrypt-verifies the bearer token against the stored hash
4. Returns the IdP config row so the route can use its
   directory_sync.group_to_role_mapping
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator

from fastapi import Depends, Header, HTTPException, status
from passlib.hash import bcrypt
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.idp_config import IdpConfig
from app.db.models.organization import Organization
from app.db.session import get_db
from app.db.tenancy import current_org_id
from app.security.audit_log import AuditEventType, log_event


async def scim_authenticated_idp(
    org_slug: str,
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> AsyncIterator[tuple[Organization, IdpConfig]]:
    """Resolve the org + active SCIM IdP, verify the bearer token, and arm
    tenant isolation for the rest of the request.

    A yield dependency: SCIM does not go through ``current_identity``, so it
    must arm Wall 1 (the ``current_org_id`` ContextVar) and Wall 2 (the
    ``app.current_org`` GUC) itself once the org is known, and reset on exit.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing_bearer_token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1].strip()

    # Organization is the tenant root (not TenantScoped) — resolvable without org
    # context.
    org = (
        await db.execute(select(Organization).where(Organization.slug == org_slug))
    ).scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="org_not_found")

    # Sanctioned tenant-guard bypass #2: IdpConfig is tenant-scoped, but this
    # lookup resolves which IdP the inbound token belongs to and runs before org
    # context is armed. Audited so every bypass is observable. (grep:
    # bypass_tenant_guard)
    log_event(
        AuditEventType.TENANT_GUARD_BYPASS,
        tenant_id=str(org.id),
        resource="idp_configs",
        detail={"reason": "scim_idp_resolution"},
    )
    idp = (
        await db.execute(
            select(IdpConfig).where(
                IdpConfig.org_id == org.id,
                IdpConfig.provider_type == "scim",
                IdpConfig.status == "active",
            ),
            execution_options={"bypass_tenant_guard": True},
        )
    ).scalar_one_or_none()
    if idp is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no_active_scim_config_for_org",
        )

    stored_hash = (idp.scim_config or {}).get("bearer_token_hash") or ""
    if not stored_hash or not _verify_token(token, stored_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_bearer_token",
        )

    # Token verified — arm both isolation walls for the provisioning queries that
    # follow (all of which filter by this org explicitly; the walls make that a
    # guarantee, not a convention).
    ctx_token = current_org_id.set(org.id)
    await db.execute(
        text("SELECT set_config('app.current_org', :org, true)"),
        {"org": str(org.id)},
    )
    try:
        yield org, idp
    finally:
        current_org_id.reset(ctx_token)


def _verify_token(plaintext: str, hashed: str) -> bool:
    try:
        return bcrypt.verify(plaintext, hashed)
    except (ValueError, TypeError):
        return False


# ─────────────────────────────────────────────── token minting


def generate_scim_token() -> tuple[str, str]:
    """Return ``(plaintext, bcrypt_hash)``. The plaintext is shown to the
    admin exactly once at creation time and never persisted."""
    plaintext = "scim_" + secrets.token_urlsafe(40)
    return plaintext, bcrypt.hash(plaintext)
