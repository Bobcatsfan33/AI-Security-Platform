"""JWT issuance, verification, and revocation.

Design (Sprint 1):
    - Access token: 15 minutes, HS256-signed JWT, carries org/user/role/scopes
    - Refresh token: 7 days, opaque random token, hashed in Redis
    - Revocation: per-JTI flag in Redis with TTL = remaining lifetime
    - Rotation: on /auth/refresh the old refresh token is invalidated and a
      new pair is issued. This limits blast radius if a refresh token leaks.

Signing (Phase 3A): RS256 when ``jwt_private_key`` is configured — access
tokens are stamped with a ``kid`` and verifiers fetch the public key from
``/v1/auth/.well-known/jwks.json``, so no party needs the symmetric secret.
Falls back to HS256 (``jwt_secret``) for dev/test.

Key-rotation runbook:
  1. Generate a new RSA keypair.
  2. Move the CURRENT public key into ``jwt_additional_public_keys`` keyed by
     its current ``jwt_key_id`` (so in-flight tokens still verify).
  3. Set ``jwt_private_key`` to the new private key and ``jwt_key_id`` to a new
     kid; redeploy. New tokens sign under the new kid; old ones verify against
     the retained public key until they expire.
  4. After the old access-token TTL elapses, drop the old entry from
     ``jwt_additional_public_keys``.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from jwt import PyJWTError

from app.core.config import get_settings
from app.services.redis_client import get_redis


@dataclass(frozen=True)
class _SigningContext:
    """How tokens are signed + verified, derived from settings.

    RS256 when a private key is configured (verifiers use the public key via
    JWKS — no shared secret); HS256 otherwise. ``verify_keys`` maps kid →
    public key for RS256 (active + rotated-out), or ``{None: secret}`` for
    HS256 (kid-less)."""

    algorithm: str
    sign_key: Any
    kid: str | None
    verify_keys: dict[str | None, Any]


@lru_cache(maxsize=8)
def _build_context(
    private_pem: str | None,
    kid: str,
    additional_items: tuple[tuple[str, str], ...],
    secret: str,
) -> _SigningContext:
    if private_pem:
        private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
        verify_keys: dict[str | None, Any] = {kid: private_key.public_key()}
        for extra_kid, pem in additional_items:
            verify_keys[extra_kid] = serialization.load_pem_public_key(pem.encode())
        return _SigningContext("RS256", private_key, kid, verify_keys)
    return _SigningContext("HS256", secret, None, {None: secret})


def signing_context() -> _SigningContext:
    """The current signing context (cached per unique key configuration)."""
    s = get_settings()
    return _build_context(
        s.jwt_private_key,
        s.jwt_key_id,
        tuple(sorted(s.jwt_additional_public_keys.items())),
        s.jwt_secret,
    )


def reset_signing_context_cache() -> None:
    """Drop the cached contexts — call after a key rotation or in tests."""
    _build_context.cache_clear()


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
    ctx = signing_context()
    headers = {"kid": ctx.kid} if ctx.kid else None
    access_token = jwt.encode(access_claims, ctx.sign_key, algorithm=ctx.algorithm, headers=headers)

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
    ctx = signing_context()
    try:
        if ctx.algorithm == "HS256":
            key: Any = ctx.verify_keys[None]
        else:
            # RS256: select the public key by the token's kid.
            kid = jwt.get_unverified_header(token).get("kid")
            key = ctx.verify_keys.get(kid)
            if key is None:
                raise TokenError(f"unknown_kid: {kid}")
        claims = jwt.decode(
            token,
            key,
            algorithms=[ctx.algorithm],
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
