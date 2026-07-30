"""FastAPI auth dependencies.

current_identity:
    Resolves an IdentityContext from either a Bearer JWT or an X-API-Key header.
    Raises 401 if neither is provided / valid.

require_role / require_any_role:
    Dependency factories that wrap current_identity with an RBAC check.

Tenant isolation:
    Every authenticated request carries `org_id`. ``current_identity`` arms both
    isolation walls for the request — it sets the ``current_org_id`` ContextVar
    (Wall 1, the ORM guard) and the ``app.current_org`` Postgres GUC (Wall 2,
    RLS) — and resets the ContextVar when the request ends. Repositories no
    longer need to remember to filter; see ``app/db/tenancy.py``.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterable
from dataclasses import replace

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.api_key_service import verify_api_key
from app.auth.jwt_service import TokenError, verify_access_token
from app.auth.rbac import has_role_at_least, is_in
from app.db.models.organization import Organization
from app.db.session import get_db
from app.db.tenancy import tenant_scope
from app.identity.types import IdentityContext
from app.security.residency import TenantRegionMismatchError, enforce_organization_region


async def current_identity(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> AsyncIterator[IdentityContext]:
    """Resolve the request principal and arm tenant isolation.

    Prefers JWT over API key when both are sent. A yield dependency so the org
    context is always reset, even on error. FastAPI resolves yield dependencies
    transparently, so existing call sites are unchanged.
    """
    identity: IdentityContext

    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            claims = await verify_access_token(token)
        except TokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"invalid_token: {e}",
                headers={"WWW-Authenticate": "Bearer"},
            ) from e
        identity = IdentityContext(
            org_id=uuid.UUID(claims["org"]),
            user_id=uuid.UUID(claims["sub"]),
            role=str(claims.get("role", "viewer")),
            auth_method=str(claims.get("auth", "oidc")),
            scopes=tuple(claims.get("scopes") or ()),
            idp_subject_id=claims.get("idp_sub"),
            jwt_id=claims.get("jti"),
        )
    elif x_api_key:
        record = await verify_api_key(db, x_api_key)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_api_key",
            )
        identity = IdentityContext(
            org_id=record.org_id,
            user_id=None,
            role="api_only",
            auth_method="api_key",
            scopes=tuple(record.scopes or ()),
            api_key_id=record.id,
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="not_authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Residency wall: validate the tenant root before arming ORM/RLS context.
    # Organization is intentionally not TenantScoped, so this lookup can occur
    # before current_org_id/app.current_org are set.
    org = (
        await db.execute(select(Organization).where(Organization.id == identity.org_id))
    ).scalar_one_or_none()
    try:
        resident_org = enforce_organization_region(org, surface=request.url.path)
    except TenantRegionMismatchError as exc:
        raise HTTPException(
            status_code=status.HTTP_421_MISDIRECTED_REQUEST,
            detail="tenant_region_unavailable",
        ) from exc
    identity = replace(identity, data_region=resident_org.data_region)

    request.state.identity = identity
    async with tenant_scope(db, identity.org_id):
        yield identity


def require_role(minimum: str):
    """Dependency factory: requires the principal's role to be at least `minimum`."""

    async def dep(identity: IdentityContext = Depends(current_identity)) -> IdentityContext:
        if not has_role_at_least(identity.role, minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"insufficient_role: requires {minimum} or above",
            )
        return identity

    return dep


def require_any_role(roles: Iterable[str]):
    """Dependency factory: principal's role must be one of `roles`."""
    allowed = tuple(roles)

    async def dep(identity: IdentityContext = Depends(current_identity)) -> IdentityContext:
        if not is_in(identity.role, allowed):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"insufficient_role: requires one of {allowed}",
            )
        return identity

    return dep


def require_scope(scope: str):
    """For API-key-authenticated calls, require a specific scope. JWT users bypass."""

    async def dep(identity: IdentityContext = Depends(current_identity)) -> IdentityContext:
        if identity.auth_method == "api_key" and scope not in identity.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing_scope: {scope}",
            )
        return identity

    return dep
