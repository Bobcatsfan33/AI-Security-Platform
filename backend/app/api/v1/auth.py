"""Auth routes — OIDC login flow, refresh, logout."""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import current_identity
from app.auth.jwt_service import (
    consume_refresh_token,
    issue_token_pair,
    revoke_jti,
)
from app.auth.user_provisioning import upsert_user_from_claims
from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.models.idp_config import IdpConfig
from app.db.models.organization import Organization
from app.db.session import get_db
from app.identity.adapter import IdentityAuthError
from app.identity.registry import build_adapter
from app.identity.types import IdentityContext
from app.services.redis_client import get_redis

router = APIRouter(tags=["auth"])
log = get_logger("auth")

OIDC_STATE_PREFIX = "auth:oidc_state:"
OIDC_STATE_TTL_SECONDS = 600  # 10 min — covers the time between redirect and callback


# --------------------------------------------------------------------------- DTOs

class TokenPairResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    access_expires_at: datetime
    refresh_token: str
    refresh_expires_at: datetime
    user: dict[str, Any]


class RefreshRequest(BaseModel):
    refresh_token: str


# ---------------------------------------------------------------------- helpers

async def _get_org_idp(
    db: AsyncSession, org_slug: str
) -> tuple[Organization, IdpConfig]:
    org = (
        await db.execute(select(Organization).where(Organization.slug == org_slug))
    ).scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="org_not_found")

    idp = (
        await db.execute(
            select(IdpConfig).where(
                IdpConfig.org_id == org.id,
                IdpConfig.provider_type == "oidc",
                IdpConfig.status == "active",
            )
        )
    ).scalar_one_or_none()
    if idp is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no_active_oidc_config_for_org",
        )
    return org, idp


def _redirect_uri_for(request: Request, org_slug: str) -> str:
    base = str(request.base_url).rstrip("/")
    return f"{base}{get_settings().api_v1_prefix}/auth/oidc/{org_slug}/callback"


# ----------------------------------------------------------------------- routes

@router.get("/oidc/{org_slug}/login")
async def oidc_login(
    org_slug: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    _, idp = await _get_org_idp(db, org_slug)
    adapter = build_adapter(idp)

    state = secrets.token_urlsafe(24)
    redirect_uri = _redirect_uri_for(request, org_slug)

    # Persist state so we can validate on callback
    redis = await get_redis()
    await redis.set(
        OIDC_STATE_PREFIX + state,
        f"{idp.id}|{redirect_uri}",
        ex=OIDC_STATE_TTL_SECONDS,
    )

    try:
        url = await adapter.begin_login(redirect_uri=redirect_uri, state=state)
    except IdentityAuthError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        ) from e
    return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)


@router.get("/oidc/{org_slug}/callback", response_model=TokenPairResponse)
async def oidc_callback(
    org_slug: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenPairResponse:
    params = dict(request.query_params)
    state = params.get("state")
    if not state:
        raise HTTPException(status_code=400, detail="missing_state")

    redis = await get_redis()
    stored = await redis.get(OIDC_STATE_PREFIX + state)
    if stored is None:
        raise HTTPException(status_code=400, detail="state_expired_or_unknown")
    await redis.delete(OIDC_STATE_PREFIX + state)

    expected_idp_id_str, redirect_uri = stored.split("|", 1)
    expected_idp_id = uuid.UUID(expected_idp_id_str)

    org, idp = await _get_org_idp(db, org_slug)
    if idp.id != expected_idp_id:
        raise HTTPException(status_code=400, detail="state_idp_mismatch")

    adapter = build_adapter(idp)
    callback_params = {**params, "_redirect_uri": redirect_uri}
    try:
        claims = await adapter.complete_login(
            callback_params=callback_params, expected_state=state
        )
    except IdentityAuthError as e:
        log.warning("oidc_login_failed", reason=str(e), org_slug=org_slug)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)
        ) from e

    user = await upsert_user_from_claims(db, idp=idp, claims=claims)
    await db.commit()

    pair = await issue_token_pair(
        org_id=org.id,
        user_id=user.id,
        role=user.role,
        auth_method="oidc",
        idp_subject_id=claims.subject_id,
    )

    log.info(
        "oidc_login_success",
        org_id=str(org.id),
        user_id=str(user.id),
        role=user.role,
    )

    return TokenPairResponse(
        access_token=pair.access_token,
        access_expires_at=pair.access_expires_at,
        refresh_token=pair.refresh_token,
        refresh_expires_at=pair.refresh_expires_at,
        user={
            "id": str(user.id),
            "email": user.email,
            "name": user.name,
            "role": user.role,
            "org_id": str(org.id),
        },
    )


@router.post("/refresh", response_model=TokenPairResponse)
async def refresh(req: RefreshRequest) -> TokenPairResponse:
    payload = await consume_refresh_token(req.refresh_token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_refresh_token"
        )

    pair = await issue_token_pair(
        org_id=uuid.UUID(payload["org_id"]),
        user_id=uuid.UUID(payload["user_id"]),
        role=payload["role"],
        auth_method="refresh",
    )
    return TokenPairResponse(
        access_token=pair.access_token,
        access_expires_at=pair.access_expires_at,
        refresh_token=pair.refresh_token,
        refresh_expires_at=pair.refresh_expires_at,
        user={
            "id": payload["user_id"],
            "org_id": payload["org_id"],
            "role": payload["role"],
        },
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(identity: IdentityContext = Depends(current_identity)) -> None:
    if identity.jwt_id:
        # Revoke the access token. The refresh token is single-use already
        # (rotated on /refresh) so this is sufficient.
        settings = get_settings()
        await revoke_jti(identity.jwt_id, ttl_seconds=settings.jwt_access_ttl_seconds)


@router.get("/me")
async def me(identity: IdentityContext = Depends(current_identity)) -> dict[str, Any]:
    return {
        "org_id": str(identity.org_id),
        "user_id": str(identity.user_id) if identity.user_id else None,
        "role": identity.role,
        "auth_method": identity.auth_method,
        "scopes": list(identity.scopes),
    }


@router.get("/_internal/now")
async def server_time() -> dict[str, str]:
    """Trivial unauthenticated diagnostic — useful for smoke tests."""
    return {"now": datetime.now(timezone.utc).isoformat()}
