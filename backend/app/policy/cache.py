"""In-process compiled-policy cache + Redis pub/sub hot reload.

The runtime agent (Sprint 7) will run this cache in-process as a Go
goroutine. The Python implementation here serves two purposes:

1. The control-plane evaluation engine (Sprint 4+) and the policy
   simulation endpoint need a way to look up the active CompiledPolicy
   for an org without re-querying Postgres on every request.

2. It's the reference implementation that the Go agent's cache
   contract is modelled after — so wire-level behavior (invalidation
   message format, cache miss handling, stale-cache grace period) is
   exercised here first.

The cache holds frozen :class:`CompiledPolicy` snapshots keyed by
policy_id. The subscriber listens on
``policy:invalidation:{org_id}`` channels and rebuilds entries on each
``create``/``update``/``delete`` message. The atomic swap is a single
dict assignment, so readers never observe a half-built policy.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.policy import Policy
from app.db.session import SessionLocal
from app.policy.compiled import CompiledPolicy, compile_policy
from app.services.policy_pubsub import channel_name
from app.services.redis_client import get_redis

logger = logging.getLogger("platform.policy.cache")


class CompiledPolicyCache:
    """Per-process cache. Construct one at app startup; share across requests.

    Thread/coroutine safety: dict operations on CPython are atomic; we
    never hold a reference across an ``await`` between read and use so
    interleaved invalidation can't tear a request mid-evaluation.
    """

    def __init__(self) -> None:
        self._by_id: dict[uuid.UUID, CompiledPolicy] = {}
        self._tasks: dict[uuid.UUID, asyncio.Task] = {}

    # ─────────────────────────────────────────── public lookup

    def get(self, policy_id: uuid.UUID) -> CompiledPolicy | None:
        """Synchronous lookup. Returns the active snapshot or None if not
        loaded yet (caller's responsibility to handle — typically by
        falling back to fail_behavior on the parent policy)."""
        return self._by_id.get(policy_id)

    async def load(self, *, policy_id: uuid.UUID) -> CompiledPolicy | None:
        """Force-load a policy from the database. Replaces any cached copy."""
        async with SessionLocal() as db:
            row = await self._fetch(db, policy_id)
        if row is None:
            self._by_id.pop(policy_id, None)
            return None
        compiled = compile_policy(policy_row=row)
        self._by_id[policy_id] = compiled
        return compiled

    async def warm_org(self, *, org_id: uuid.UUID) -> int:
        """Pre-load every active policy for one org. Returns count loaded."""
        async with SessionLocal() as db:
            rows = (
                await db.execute(
                    select(Policy).where(
                        Policy.org_id == org_id, Policy.status == "active"
                    )
                )
            ).scalars().all()
        count = 0
        for row in rows:
            self._by_id[row.id] = compile_policy(policy_row=_row_to_dict(row))
            count += 1
        return count

    def evict(self, policy_id: uuid.UUID) -> bool:
        """Remove a policy from the cache. Returns True if it was present."""
        return self._by_id.pop(policy_id, None) is not None

    # ─────────────────────────────────────────── subscriber lifecycle

    async def subscribe(self, *, org_id: uuid.UUID) -> None:
        """Start a background task that listens on the org's invalidation
        channel and refreshes the cache on every message.

        Idempotent: calling twice for the same org is a no-op.
        """
        if org_id in self._tasks and not self._tasks[org_id].done():
            return
        self._tasks[org_id] = asyncio.create_task(
            self._subscribe_loop(org_id), name=f"policy_subscriber:{org_id}"
        )

    async def unsubscribe(self, *, org_id: uuid.UUID) -> None:
        task = self._tasks.pop(org_id, None)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    async def stop_all(self) -> None:
        """Cancel every active subscriber. Called from app shutdown."""
        org_ids = list(self._tasks.keys())
        for org_id in org_ids:
            await self.unsubscribe(org_id=org_id)

    # ─────────────────────────────────────────── internals

    async def _subscribe_loop(self, org_id: uuid.UUID) -> None:
        """Long-running consumer for one org's invalidation channel."""
        redis = await get_redis()
        pubsub = redis.pubsub()
        chan = channel_name(org_id)
        await pubsub.subscribe(chan)
        logger.info(
            "policy_cache_subscriber_started",
            extra={"org_id": str(org_id), "channel": chan},
        )

        try:
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                try:
                    payload = json.loads(message["data"])
                except (json.JSONDecodeError, TypeError):
                    logger.warning(
                        "policy_cache_bad_invalidation_payload",
                        extra={"raw": str(message)[:200]},
                    )
                    continue
                await self._apply_invalidation(payload)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("policy_cache_subscriber_crashed")
            raise
        finally:
            try:
                await pubsub.unsubscribe(chan)
                await pubsub.aclose()
            except Exception:  # noqa: BLE001
                pass

    async def _apply_invalidation(self, payload: dict[str, Any]) -> None:
        """Process one invalidation message.

        Payload shape (matches :func:`app.services.policy_pubsub.publish_policy_change`):
            {"policy_id": "<uuid>", "version": <int>, "event": "create|update|delete"}
        """
        try:
            policy_id = uuid.UUID(payload["policy_id"])
        except (KeyError, ValueError):
            logger.warning("policy_cache_invalid_payload", extra={"payload": payload})
            return

        event = payload.get("event")
        if event == "delete":
            evicted = self.evict(policy_id)
            logger.info(
                "policy_cache_evicted",
                extra={"policy_id": str(policy_id), "was_present": evicted},
            )
            return

        # create or update — reload from DB
        compiled = await self.load(policy_id=policy_id)
        logger.info(
            "policy_cache_refreshed",
            extra={
                "policy_id": str(policy_id),
                "event": event,
                "loaded": compiled is not None,
                "version": payload.get("version"),
            },
        )

    @staticmethod
    async def _fetch(
        db: AsyncSession, policy_id: uuid.UUID
    ) -> dict[str, Any] | None:
        row = (
            await db.execute(select(Policy).where(Policy.id == policy_id))
        ).scalar_one_or_none()
        if row is None:
            return None
        return _row_to_dict(row)


def _row_to_dict(row: Policy) -> dict[str, Any]:
    """Hand-rolled SQLAlchemy → dict so :func:`compile_policy` (which is
    DB-agnostic) can consume it."""
    return {
        "id": str(row.id),
        "org_id": str(row.org_id),
        "version": row.version,
        "enforcement_level": row.enforcement_level,
        "fail_behavior": row.fail_behavior,
        "ml_confidence_threshold_high": row.ml_confidence_threshold_high,
        "ml_confidence_threshold_low": row.ml_confidence_threshold_low,
        "rules": row.rules or [],
        "tool_allowlist": row.tool_allowlist or [],
        "tool_denylist": row.tool_denylist or [],
        "tool_approval_required": row.tool_approval_required or [],
        "rate_limits": row.rate_limits or {},
        "content_filters": row.content_filters or {},
    }


# ─────────────────────────────────────────── Module singleton

_cache: CompiledPolicyCache | None = None


def get_cache() -> CompiledPolicyCache:
    global _cache
    if _cache is None:
        _cache = CompiledPolicyCache()
    return _cache


def reset_cache_for_tests() -> None:
    """Test helper — drop the singleton."""
    global _cache
    _cache = None
