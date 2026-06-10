"""RS256 / JWKS signing (Phase 3A) — asymmetric tokens so verifiers use the
public key (no shared symmetric secret), with kid-based rotation.

HS256 fallback stays covered by test_jwt_service.py; here we exercise the
RS256 path by pointing get_settings at an ephemeral keypair.
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.auth import jwt_service

pytestmark = pytest.mark.unit


def _keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return priv, pub


# Generate once — RSA keygen is the slow part.
_PRIV_A, _PUB_A = _keypair()
_PRIV_B, _PUB_B = _keypair()
_SECRET = "x" * 40


def _settings(*, private_pem, kid="key-a", additional=None):
    return SimpleNamespace(
        jwt_private_key=private_pem,
        jwt_key_id=kid,
        jwt_additional_public_keys=additional or {},
        jwt_secret=_SECRET,
        jwt_access_ttl_seconds=900,
        jwt_refresh_ttl_seconds=604800,
    )


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, Any] = {}

    async def hset(self, key, mapping):
        self.store[key] = dict(mapping)
        return 1

    async def expire(self, key, ttl):
        return True

    async def exists(self, key):
        return 1 if key in self.store else 0


@pytest.fixture
def rs256(monkeypatch: pytest.MonkeyPatch):
    """Configure RS256 with key-a active. Returns a setter to reconfigure."""
    fake = _FakeRedis()

    async def _get_redis():
        return fake

    monkeypatch.setattr(jwt_service, "get_redis", _get_redis)

    def configure(settings) -> None:
        monkeypatch.setattr(jwt_service, "get_settings", lambda: settings)
        jwt_service.reset_signing_context_cache()

    configure(_settings(private_pem=_PRIV_A))
    return configure


async def _issue(role="analyst") -> str:
    pair = await jwt_service.issue_token_pair(
        org_id=uuid.uuid4(), user_id=uuid.uuid4(), role=role, auth_method="oidc"
    )
    return pair.access_token


class TestRs256:
    async def test_token_is_rs256_with_kid(self, rs256):
        token = await _issue()
        header = jwt_service.jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        assert header["kid"] == "key-a"

    async def test_issue_verify_round_trip(self, rs256):
        token = await _issue(role="admin")
        claims = await jwt_service.verify_access_token(token)
        assert claims["role"] == "admin"

    async def test_tampered_token_rejected(self, rs256):
        token = await _issue()
        head, payload, sig = token.split(".")
        tampered = f"{head}.{payload}.{'A' if sig[0] != 'A' else 'B'}{sig[1:]}"
        with pytest.raises(jwt_service.TokenError):
            await jwt_service.verify_access_token(tampered)

    async def test_unknown_kid_rejected(self, rs256):
        token = await _issue()  # signed with key-a
        # Reconfigure so only key-b is known — key-a's kid is now unknown.
        rs256(_settings(private_pem=_PRIV_B, kid="key-b"))
        with pytest.raises(jwt_service.TokenError, match="unknown_kid"):
            await jwt_service.verify_access_token(token)

    async def test_rotation_old_tokens_still_verify(self, rs256):
        # Token issued under key-a...
        old_token = await _issue()
        # ...then rotate: key-b becomes active, key-a kept as a verify-only key.
        rs256(
            _settings(
                private_pem=_PRIV_B,
                kid="key-b",
                additional={"key-a": _PUB_A},
            )
        )
        # New tokens use key-b; old key-a tokens still validate during rotation.
        new_token = await _issue()
        assert jwt_service.jwt.get_unverified_header(new_token)["kid"] == "key-b"
        assert (await jwt_service.verify_access_token(old_token))["org"]
        assert (await jwt_service.verify_access_token(new_token))["org"]


class TestJwksRendering:
    def test_public_keys_render_as_valid_jwk(self, rs256):
        ctx = jwt_service.signing_context()
        assert ctx.algorithm == "RS256"
        keys = []
        for kid, pub in ctx.verify_keys.items():
            jwk = json.loads(RSAAlgorithm.to_jwk(pub))
            jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
            keys.append(jwk)
        assert len(keys) == 1
        assert keys[0]["kty"] == "RSA"
        assert keys[0]["kid"] == "key-a"
        assert "n" in keys[0] and "e" in keys[0]


class TestHs256Fallback:
    def test_no_private_key_uses_hs256(self):
        ctx = jwt_service._build_context(None, "default", (), _SECRET)
        assert ctx.algorithm == "HS256"
        assert ctx.kid is None
        assert ctx.verify_keys == {None: _SECRET}
