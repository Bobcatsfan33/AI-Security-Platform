"""Async Redis client — single shared connection pool for the whole process.

Used for:
  - Policy invalidation pub/sub (Sprint 1 plumbing, Sprint 7 enforcement)
  - JWT revocation list
  - Rate limiting (later)
"""

from __future__ import annotations

import redis.asyncio as redis_asyncio

from app.core.config import get_settings

_client: redis_asyncio.Redis | None = None


async def get_redis() -> redis_asyncio.Redis:
    global _client
    if _client is None:
        _client = redis_asyncio.from_url(
            get_settings().redis_url,
            decode_responses=True,
            encoding="utf-8",
            max_connections=20,
        )
    return _client


async def close_redis() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
