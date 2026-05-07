"""JWT service unit tests — covers issuance, verification, and revocation.

Uses fakeredis-style stubbing of the redis client so these tests do not
require a running Redis. We monkey-patch app.services.redis_client.get_redis
to return an in-memory async fake.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.auth import jwt_service
from app.core.config import get_settings


class _FakeRedis:
    """Minimal in-memory async stand-in covering the surface jwt_service uses."""

    def __init__(self) -> None:
        self.store: dict[str, Any] = {}
        self.ttls: dict[str, int] = {}

    async def hset(self, key: str, mapping: dict[str, Any]) -> int:
        self.store[key] = dict(mapping)
        return len(mapping)

    async def hgetall(self, key: str) -> dict[str, Any]:
        v = self.store.get(key)
        if v is None:
            return {}
        return dict(v)

    async def expire(self, key: str, ttl: int) -> bool:
        self.ttls[key] = ttl
        return key in self.store

    async def set(self, key: str, value: str, *, ex: int | None = None) -> bool:
        self.store[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    async def exists(self, key: str) -> int:
        return 1 if key in self.store else 0

    async def delete(self, key: str) -> int:
        return 1 if self.store.pop(key, None) is not None else 0


@pytest.fixture
def fake_redis(monkeypatch: pytest.MonkeyPatch) -> _FakeRedis:
    fake = _FakeRedis()

    async def _get_redis() -> _FakeRedis:
        return fake

    monkeypatch.setattr(jwt_service, "get_redis", _get_redis)
    return fake


@pytest.mark.unit
class TestJwtService:
    async def test_issue_and_verify_round_trip(self, fake_redis: _FakeRedis) -> None:
        org_id = uuid.uuid4()
        user_id = uuid.uuid4()
        pair = await jwt_service.issue_token_pair(
            org_id=org_id,
            user_id=user_id,
            role="analyst",
            auth_method="oidc",
            scopes=("assets:read",),
            idp_subject_id="okta|abc123",
        )
        claims = await jwt_service.verify_access_token(pair.access_token)
        assert claims["org"] == str(org_id)
        assert claims["sub"] == str(user_id)
        assert claims["role"] == "analyst"
        assert claims["scopes"] == ["assets:read"]
        assert claims["idp_sub"] == "okta|abc123"

    async def test_revoked_token_rejected(self, fake_redis: _FakeRedis) -> None:
        pair = await jwt_service.issue_token_pair(
            org_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            role="viewer",
            auth_method="oidc",
        )
        await jwt_service.revoke_jti(pair.jti, ttl_seconds=60)

        with pytest.raises(jwt_service.TokenError, match="token_revoked"):
            await jwt_service.verify_access_token(pair.access_token)

    async def test_tampered_token_rejected(self, fake_redis: _FakeRedis) -> None:
        pair = await jwt_service.issue_token_pair(
            org_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            role="viewer",
            auth_method="oidc",
        )
        # Flip one char in the signature segment
        head, payload, sig = pair.access_token.split(".")
        tampered_sig = "A" + sig[1:] if sig[0] != "A" else "B" + sig[1:]
        tampered = f"{head}.{payload}.{tampered_sig}"

        with pytest.raises(jwt_service.TokenError):
            await jwt_service.verify_access_token(tampered)

    async def test_refresh_token_rotation_invalidates_old(
        self, fake_redis: _FakeRedis
    ) -> None:
        pair = await jwt_service.issue_token_pair(
            org_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            role="viewer",
            auth_method="oidc",
        )

        first_consume = await jwt_service.consume_refresh_token(pair.refresh_token)
        assert first_consume is not None
        assert first_consume["role"] == "viewer"

        second_consume = await jwt_service.consume_refresh_token(pair.refresh_token)
        assert second_consume is None  # already consumed → no replay

    async def test_settings_jwt_secret_meets_min_length(self) -> None:
        # Guard against accidentally weakening the JWT_SECRET min_length validator.
        s = get_settings()
        assert len(s.jwt_secret) >= 32
