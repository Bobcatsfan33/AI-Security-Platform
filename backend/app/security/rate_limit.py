"""Redis-backed rate limiting (Phase 0.2).

Fixed-window counters in Redis (INCR + first-hit EXPIRE) exposed as FastAPI
dependencies, so a route opts in with ``dependencies=[Depends(...)]`` and never
changes its own signature.

Two scopes, per the threat model:
* **per-IP** — blunts credential stuffing on login/token and ingest-flood DoS
  from a single source. Pre-auth routes can only key on IP.
* **per-principal** — bounds an authenticated caller (org + user/api-key)
  independently of source IP, for authenticated routes like telemetry ingest.

Fail-OPEN: if Redis is unavailable the request is allowed (a limiter outage
must never take down auth or ingest). Throttle decisions return HTTP 429 with a
``Retry-After`` header.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from fastapi import Depends, HTTPException, Request, status

from app.auth.dependencies import current_identity
from app.identity.types import IdentityContext
from app.services.redis_client import get_redis

logger = logging.getLogger("platform.security.rate_limit")

_PREFIX = "ratelimit:"


def client_ip(request: Request) -> str:
    """Best-effort client IP. Honors the first X-Forwarded-For hop (set by a
    trusted proxy) and falls back to the socket peer."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


async def _hit(key: str, *, limit: int, window_seconds: int) -> tuple[bool, int]:
    """Register one hit against a fixed window. Returns (allowed, retry_after).

    Fail-open: any Redis error counts as allowed.
    """
    try:
        redis = await get_redis()
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, window_seconds)
        if count > limit:
            ttl = await redis.ttl(key)
            return False, ttl if ttl and ttl > 0 else window_seconds
        return True, 0
    except Exception as exc:
        logger.warning("rate_limit_unavailable", extra={"error": str(exc)})
        return True, 0


def _too_many(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="rate_limit_exceeded",
        headers={"Retry-After": str(retry_after)},
    )


def rate_limit_ip(
    *, bucket: str, limit: int, window_seconds: int
) -> Callable[[Request], Awaitable[None]]:
    """Per-IP limiter dependency for the given bucket."""

    async def _dep(request: Request) -> None:
        key = f"{_PREFIX}{bucket}:ip:{client_ip(request)}"
        allowed, retry_after = await _hit(key, limit=limit, window_seconds=window_seconds)
        if not allowed:
            raise _too_many(retry_after)

    return _dep


def rate_limit_principal(
    *, bucket: str, limit: int, window_seconds: int
) -> Callable[[IdentityContext], Awaitable[None]]:
    """Per-principal limiter dependency (org + user/api-key). Resolves the
    caller via ``current_identity`` (deduped with the route's own auth)."""

    async def _dep(identity: IdentityContext = Depends(current_identity)) -> None:
        principal = identity.api_key_id or identity.user_id or "anon"
        key = f"{_PREFIX}{bucket}:principal:{identity.org_id}:{principal}"
        allowed, retry_after = await _hit(key, limit=limit, window_seconds=window_seconds)
        if not allowed:
            raise _too_many(retry_after)

    return _dep


# ─────────────────────────────────────────────── default limits
# Tunable defaults; conservative enough to stop abuse without tripping normal
# use. Window is seconds.

LOGIN = {"limit": 10, "window_seconds": 60}  # SSO initiation / callback per IP
TOKEN = {"limit": 30, "window_seconds": 60}  # /auth/refresh per IP
INGEST_IP = {"limit": 2000, "window_seconds": 60}  # telemetry flood guard per IP
INGEST_PRINCIPAL = {"limit": 10000, "window_seconds": 60}  # per authenticated principal
