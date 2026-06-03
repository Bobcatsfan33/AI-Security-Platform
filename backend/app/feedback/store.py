"""SuppressionStore — persistence for suppression rules (in-memory + Redis)."""

from __future__ import annotations

import json
from typing import Optional, Protocol, runtime_checkable

from app.feedback.suppression import SuppressionRule

_REDIS_PREFIX = "suppression:"
_REDIS_INDEX = "suppression:index:"


@runtime_checkable
class SuppressionStore(Protocol):
    async def save(self, rule: SuppressionRule) -> None: ...

    async def get(self, org_id: str, rule_id: str) -> Optional[SuppressionRule]: ...

    async def list(self, org_id: str, *, status: Optional[str] = None) -> list[SuppressionRule]: ...


class InMemorySuppressionStore:
    def __init__(self) -> None:
        self._data: dict[str, dict[str, dict]] = {}

    async def save(self, rule: SuppressionRule) -> None:
        self._data.setdefault(rule.org_id, {})[str(rule.id)] = rule.to_dict()

    async def get(self, org_id: str, rule_id: str) -> Optional[SuppressionRule]:
        raw = self._data.get(org_id, {}).get(rule_id)
        return SuppressionRule.from_dict(raw) if raw else None

    async def list(self, org_id: str, *, status: Optional[str] = None) -> list[SuppressionRule]:
        items = [SuppressionRule.from_dict(d) for d in self._data.get(org_id, {}).values()]
        if status:
            items = [r for r in items if r.status == status]
        return sorted(items, key=lambda r: r.created_at, reverse=True)


class RedisSuppressionStore:
    def __init__(self, redis) -> None:
        self._redis = redis

    def _key(self, org_id: str, rid: str) -> str:
        return f"{_REDIS_PREFIX}{org_id}:{rid}"

    async def save(self, rule: SuppressionRule) -> None:
        rid = str(rule.id)
        await self._redis.set(self._key(rule.org_id, rid), json.dumps(rule.to_dict()))
        await self._redis.sadd(f"{_REDIS_INDEX}{rule.org_id}", rid)

    async def get(self, org_id: str, rule_id: str) -> Optional[SuppressionRule]:
        raw = await self._redis.get(self._key(org_id, rule_id))
        return SuppressionRule.from_dict(json.loads(raw)) if raw else None

    async def list(self, org_id: str, *, status: Optional[str] = None) -> list[SuppressionRule]:
        ids = await self._redis.smembers(f"{_REDIS_INDEX}{org_id}")
        out: list[SuppressionRule] = []
        for rid in ids:
            rid = rid.decode() if isinstance(rid, bytes) else rid
            r = await self.get(org_id, rid)
            if r is not None and (status is None or r.status == status):
                out.append(r)
        return sorted(out, key=lambda r: r.created_at, reverse=True)
