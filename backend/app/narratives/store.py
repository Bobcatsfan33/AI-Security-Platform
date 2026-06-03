"""NarrativeStore — persistence + triage for Tier-3 narratives.

The EPA fleet (via NarrativeBuilder) writes narratives here; the analyst
workbench reads and dispositions them. In-memory backend for dev/tests; Redis
for production (cross-process: the fleet runs in a consumer, the API in the web
process). Dispositioning is immutable — it produces a new narrative record —
and is recorded to the hash-chained audit log by the API layer.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from typing import Optional, Protocol, runtime_checkable

from app.narratives.narrative import DispositionStatus, ThreatNarrative

_REDIS_PREFIX = "narrative:"
_REDIS_INDEX = "narrative:index:"  # per-org sorted set of ids


@runtime_checkable
class NarrativeStore(Protocol):
    async def save(self, narrative: ThreatNarrative) -> None: ...

    async def get(self, org_id: str, narrative_id: str) -> Optional[ThreatNarrative]: ...

    async def list(
        self, org_id: str, *, status: Optional[str] = None, severity: Optional[str] = None
    ) -> list[ThreatNarrative]: ...


def apply_disposition(
    narrative: ThreatNarrative,
    *,
    status: DispositionStatus,
    rationale: str,
    assignee: str,
) -> ThreatNarrative:
    """Return a new narrative with the disposition applied (immutable update)."""
    return dataclasses.replace(
        narrative,
        status=status,
        rationale=rationale,
        assignee=assignee,
        disposition_at=datetime.now(timezone.utc),
    )


class InMemoryNarrativeStore:
    def __init__(self) -> None:
        self._data: dict[str, dict[str, dict]] = {}  # org -> id -> dict

    async def save(self, narrative: ThreatNarrative) -> None:
        self._data.setdefault(narrative.org_id, {})[str(narrative.id)] = narrative.to_dict()

    async def get(self, org_id: str, narrative_id: str) -> Optional[ThreatNarrative]:
        raw = self._data.get(org_id, {}).get(narrative_id)
        return ThreatNarrative.from_dict(raw) if raw else None

    async def list(
        self, org_id: str, *, status: Optional[str] = None, severity: Optional[str] = None
    ) -> list[ThreatNarrative]:
        items = [ThreatNarrative.from_dict(d) for d in self._data.get(org_id, {}).values()]
        items = _filter(items, status=status, severity=severity)
        # newest first
        return sorted(items, key=lambda n: n.created_at, reverse=True)


class RedisNarrativeStore:
    def __init__(self, redis, *, ttl_seconds: int = 30 * 24 * 3600) -> None:
        self._redis = redis
        self._ttl = ttl_seconds

    def _key(self, org_id: str, nid: str) -> str:
        return f"{_REDIS_PREFIX}{org_id}:{nid}"

    async def save(self, narrative: ThreatNarrative) -> None:
        nid = str(narrative.id)
        await self._redis.set(
            self._key(narrative.org_id, nid), json.dumps(narrative.to_dict()), ex=self._ttl
        )
        await self._redis.sadd(f"{_REDIS_INDEX}{narrative.org_id}", nid)

    async def get(self, org_id: str, narrative_id: str) -> Optional[ThreatNarrative]:
        raw = await self._redis.get(self._key(org_id, narrative_id))
        return ThreatNarrative.from_dict(json.loads(raw)) if raw else None

    async def list(
        self, org_id: str, *, status: Optional[str] = None, severity: Optional[str] = None
    ) -> list[ThreatNarrative]:
        ids = await self._redis.smembers(f"{_REDIS_INDEX}{org_id}")
        out: list[ThreatNarrative] = []
        for nid in ids:
            nid = nid.decode() if isinstance(nid, bytes) else nid
            n = await self.get(org_id, nid)
            if n is not None:
                out.append(n)
        out = _filter(out, status=status, severity=severity)
        return sorted(out, key=lambda n: n.created_at, reverse=True)


def _filter(
    items: list[ThreatNarrative], *, status: Optional[str], severity: Optional[str]
) -> list[ThreatNarrative]:
    if status:
        items = [n for n in items if n.status == status]
    if severity:
        items = [n for n in items if n.severity == severity]
    return items
