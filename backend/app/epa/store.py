"""EnvelopeStore — persistence for per-agent behavioral envelopes.

The fleet loads an envelope before processing an event and saves it after, so
EPA state survives restarts and rebalances. Two backends: an in-memory store
for dev/tests and a Redis-backed store for production (Redis 7 is already a
platform dependency).
"""

from __future__ import annotations

import json
from typing import Optional, Protocol, runtime_checkable

from app.epa.envelope import BehavioralEnvelope

_REDIS_PREFIX = "epa:envelope:"


@runtime_checkable
class EnvelopeStore(Protocol):
    async def load(self, agent_instance_id: str) -> Optional[BehavioralEnvelope]: ...

    async def save(self, envelope: BehavioralEnvelope) -> None: ...


class InMemoryEnvelopeStore:
    """Process-local store for dev/tests."""

    def __init__(self) -> None:
        self._data: dict[str, dict] = {}

    async def load(self, agent_instance_id: str) -> Optional[BehavioralEnvelope]:
        raw = self._data.get(agent_instance_id)
        return BehavioralEnvelope.from_dict(raw) if raw else None

    async def save(self, envelope: BehavioralEnvelope) -> None:
        self._data[envelope.agent_instance_id] = envelope.to_dict()


class RedisEnvelopeStore:
    """Redis-backed store. Envelopes are JSON blobs keyed by instance id."""

    def __init__(self, redis, *, ttl_seconds: int = 7 * 24 * 3600) -> None:
        self._redis = redis
        self._ttl = ttl_seconds

    async def load(self, agent_instance_id: str) -> Optional[BehavioralEnvelope]:
        raw = await self._redis.get(_REDIS_PREFIX + agent_instance_id)
        if not raw:
            return None
        return BehavioralEnvelope.from_dict(json.loads(raw))

    async def save(self, envelope: BehavioralEnvelope) -> None:
        await self._redis.set(
            _REDIS_PREFIX + envelope.agent_instance_id,
            json.dumps(envelope.to_dict()),
            ex=self._ttl,
        )
