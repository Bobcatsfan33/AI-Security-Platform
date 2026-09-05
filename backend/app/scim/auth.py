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

from fastapi import Depends, Header, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.password_hashing import hash_secret, verify_secret
from app.db.models.idp_config import IdpConfig
from app.db.models.organization import Organization
from app.db.session import get_db
from app.db.tenancy import tenant_scope
from app.scim.types import SCIMError
from app.security.residency import TenantRegionMismatchError, enforce_organization_region


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
        raise SCIMError(
            status=status.HTTP_401_UNAUTHORIZED,
            detail="missing_bearer_token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1].strip()

    # Organization is the tenant root (not TenantScoped) — resolvable without org
    # context.
    org = (
        await db.execute(select(Organization).where(Organization.slug == org_slug))
    ).scalar_one_or_none()
    try:
        enforce_organization_region(org, surface=f"/v1/scim/v2/{org_slug}")
    except TenantRegionMismatchError as exc:
        raise SCIMError(
            status=status.HTTP_421_MISDIRECTED_REQUEST,
            detail="tenant_region_unavailable",
        ) from exc

    # The URL slug identifies a region-validated tenant root, so both isolation
    # walls can safely constrain the IdP lookup before the bearer secret is
    # checked. No ORM or RLS bypass is needed.
    async with tenant_scope(db, org.id):
        idp = (
            await db.execute(
                select(IdpConfig).where(
                    IdpConfig.org_id == org.id,
                    IdpConfig.provider_type == "scim",
                    IdpConfig.status == "active",
                )
            )
        ).scalar_one_or_none()
        if idp is None:
            raise SCIMError(
                status=status.HTTP_404_NOT_FOUND,
                detail="no_active_scim_config_for_org",
            )

        stored_hash = (idp.scim_config or {}).get("bearer_token_hash") or ""
        if not stored_hash or not verify_secret(token, stored_hash):
            raise SCIMError(
                status=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_bearer_token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Keep both walls armed for all provisioning queries in the route.
        yield org, idp


# ───────────────────────────────────────────── token minting


def generate_scim_token() -> tuple[str, str]:
    """Return ``(plaintext, bcrypt_hash)``. The plaintext is shown to the
    admin exactly once at creation time and never persisted."""
    plaintext = "scim_" + secrets.token_urlsafe(40)
    return plaintext, hash_secret(plaintext)
