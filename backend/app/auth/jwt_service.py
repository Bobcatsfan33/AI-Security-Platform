"""JWT issuance, verification, and revocation.

Design (Sprint 1):
    - Access token: 15 minutes, HS256-signed JWT, carries org/user/role/scopes
    - Refresh token: 7 days, opaque random token, hashed in Redis
    - Revocation: per-JTI flag in Redis with TTL = remaining lifetime
    - Rotation: on /auth/refresh the old refresh token is invalidated and a
      new pair is issued. This limits blast radius if a refresh token leaks.

The JWT secret is loaded from settings. For production we'd switch to RS256
with a JWKS endpoint so the runtime agent can verify access tokens without
sharing a symmetric secret — that's a Sprint 7 concern.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from jwt import PyJWTError

from app.core.config import get_settings
from app.services.redis_client import get_redis

REVOKED_PREFIX = "auth:revoked:"
REFRESH_PREFIX = "auth:refresh:"


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    access_expires_at: datetime
    refresh_token: str
    refresh_expires_at: datetime
    jti: str


def _now() -> datetime:
    return datetime.now(UTC)


def _make_jti() -> str:
    return str(uuid.uuid4())


async def issue_token_pair(
    *,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    role: str,
    auth_method: str,
    scopes: tuple[str, ...] = (),
    idp_subject_id: str | None = None,
) -> TokenPair:
    settings = get_settings()
    now = _now()
    jti = _make_jti()
    access_expires = now + timedelta(seconds=settings.jwt_access_ttl_seconds)
    refresh_expires = now + timedelta(seconds=settings.jwt_refresh_ttl_seconds)

    access_claims: dict[str, Any] = {
        "iss": "ai-security-platform",
        "sub": str(user_id),
        "org": str(org_id),
        "role": role,
        "auth": auth_method,
        "scopes": list(scopes),
        "idp_sub": idp_subject_id,
        "iat": int(now.timestamp()),
        "exp": int(access_expires.timestamp()),
        "jti": jti,
    }
    access_token = jwt.encode(access_claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)

    refresh_token = secrets.token_urlsafe(48)
    refresh_payload = {
        "user_id": str(user_id),
        "org_id": str(org_id),
        "role": role,
        "jti": jti,
        "issued_at": now.isoformat(),
    }

    redis = await get_redis()
    await redis.hset(REFRESH_PREFIX + refresh_token, mapping=refresh_payload)
    await redis.expire(REFRESH_PREFIX + refresh_token, settings.jwt_refresh_ttl_seconds)

    return TokenPair(
        access_token=access_token,
        access_expires_at=access_expires,
        refresh_token=refresh_token,
        refresh_expires_at=refresh_expires,
        jti=jti,
    )


class TokenError(Exception):
    """Raised when access-token validation fails."""


async def verify_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "sub", "org", "jti"]},
        )
    except PyJWTError as e:
        raise TokenError(f"invalid_token: {e}") from e

    jti = claims.get("jti")
    if not jti:
        raise TokenError("missing_jti")

    redis = await get_redis()
    if await redis.exists(REVOKED_PREFIX + jti):
        raise TokenError("token_revoked")

    return claims


async def revoke_jti(jti: str, *, ttl_seconds: int) -> None:
    """Mark a JTI as revoked. TTL should be the remaining lifetime so the entry
    auto-expires when the token would have expired anyway."""
    redis = await get_redis()
    await redis.set(REVOKED_PREFIX + jti, "1", ex=max(ttl_seconds, 1))


async def consume_refresh_token(refresh_token: str) -> dict[str, Any] | None:
    """Atomically pop the refresh token (rotation). Returns the payload if valid,
    None if missing/expired/already-used."""
    redis = await get_redis()
    key = REFRESH_PREFIX + refresh_token
    payload = await redis.hgetall(key)
    if not payload:
        return None
    deleted = await redis.delete(key)
    if not deleted:
        # Lost a race — another consumer popped it first. Treat as invalid.
        return None
    return payload
