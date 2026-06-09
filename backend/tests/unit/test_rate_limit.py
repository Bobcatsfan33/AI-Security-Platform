"""Rate limiting (Phase 0.2) — throttle engages per IP and per principal, and
fails open when Redis is unavailable.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from app.identity.types import IdentityContext
from app.security import rate_limit
from app.security.rate_limit import (
    _hit,
    client_ip,
    rate_limit_ip,
    rate_limit_principal,
)

pytestmark = pytest.mark.unit


class _FakeRedis:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.ttls: dict[str, int] = {}

    async def incr(self, key: str) -> int:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def expire(self, key: str, ttl: int) -> bool:
        self.ttls[key] = ttl
        return True

    async def ttl(self, key: str) -> int:
        return self.ttls.get(key, -1)


class _BoomRedis:
    async def incr(self, key: str) -> int:
        raise RuntimeError("redis down")


@pytest.fixture
def fake_redis(monkeypatch: pytest.MonkeyPatch) -> _FakeRedis:
    fake = _FakeRedis()

    async def _get_redis() -> _FakeRedis:
        return fake

    monkeypatch.setattr(rate_limit, "get_redis", _get_redis)
    return fake


class _Req:
    """Minimal Request stand-in with headers + client."""

    def __init__(self, ip: str = "1.2.3.4", xff: str | None = None) -> None:
        self.headers = {"x-forwarded-for": xff} if xff else {}

        class _C:
            host = ip

        self.client = _C()


class TestClientIp:
    def test_prefers_first_forwarded_hop(self):
        assert client_ip(_Req(ip="10.0.0.1", xff="9.9.9.9, 10.0.0.1")) == "9.9.9.9"

    def test_falls_back_to_socket_peer(self):
        assert client_ip(_Req(ip="10.0.0.1")) == "10.0.0.1"


class TestHit:
    async def test_allows_up_to_limit_then_blocks(self, fake_redis: _FakeRedis):
        results = [await _hit("k", limit=3, window_seconds=60) for _ in range(5)]
        allowed = [r[0] for r in results]
        assert allowed == [True, True, True, False, False]
        # blocked hits report a positive Retry-After
        assert results[-1][1] > 0

    async def test_fails_open_on_redis_error(self, monkeypatch: pytest.MonkeyPatch):
        async def _boom() -> _BoomRedis:
            return _BoomRedis()

        monkeypatch.setattr(rate_limit, "get_redis", _boom)
        allowed, retry = await _hit("k", limit=1, window_seconds=60)
        assert allowed is True and retry == 0


class TestIpDependency:
    async def test_throttle_engages_after_limit(self, fake_redis: _FakeRedis):
        dep = rate_limit_ip(bucket="login", limit=2, window_seconds=60)
        req = _Req(ip="5.5.5.5")
        await dep(req)  # 1
        await dep(req)  # 2
        with pytest.raises(HTTPException) as ei:
            await dep(req)  # 3 → blocked
        assert ei.value.status_code == 429
        assert "Retry-After" in ei.value.headers

    async def test_separate_ips_have_separate_budgets(self, fake_redis: _FakeRedis):
        dep = rate_limit_ip(bucket="login", limit=1, window_seconds=60)
        await dep(_Req(ip="1.1.1.1"))
        await dep(_Req(ip="2.2.2.2"))  # different IP — not throttled


class TestPrincipalDependency:
    async def test_throttle_by_principal(self, fake_redis: _FakeRedis):
        dep = rate_limit_principal(bucket="ingest", limit=2, window_seconds=60)
        ident = IdentityContext(
            org_id=uuid.uuid4(),
            user_id=None,
            role="api_only",
            auth_method="api_key",
            api_key_id=uuid.uuid4(),
        )
        await dep(ident)
        await dep(ident)
        with pytest.raises(HTTPException) as ei:
            await dep(ident)
        assert ei.value.status_code == 429
