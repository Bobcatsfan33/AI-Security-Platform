"""Connector registry CRUD + /test integration tests."""

from __future__ import annotations

import uuid

import httpx
import pytest

from app.auth.jwt_service import issue_token_pair
from app.db.models.organization import Organization
from app.db.models.user import User
from app.db.session import SessionLocal

pytestmark = pytest.mark.integration


async def _admin_user(org: Organization, role: str = "admin") -> User:
    user = User(
        id=uuid.uuid4(),
        org_id=org.id,
        email=f"adm-{uuid.uuid4().hex[:6]}@example.com",
        name="Admin",
        role=role,
        idp_groups=[],
    )
    async with SessionLocal() as db:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    return user


@pytest.mark.asyncio
async def test_create_and_list_connector(
    fresh_org: Organization, app_client
) -> None:
    user = await _admin_user(fresh_org)
    pair = await issue_token_pair(
        org_id=fresh_org.id, user_id=user.id, role="admin", auth_method="oidc"
    )
    headers = {"Authorization": f"Bearer {pair.access_token}"}

    async with app_client as client:
        r = await client.post(
            "/v1/connectors",
            json={
                "provider": "openai",
                "display_name": "OpenAI prod",
                "model": "gpt-4o-mini",
                "api_key_ref": "env:OPENAI_API_KEY",
                "config": {},
            },
            headers=headers,
        )
        assert r.status_code == 201, r.text
        body = r.json()
        # Reference itself is never returned
        assert "api_key_ref" not in body
        assert body["api_key_ref_present"] is True

        r = await client.get("/v1/connectors", headers=headers)
        assert r.status_code == 200
        ids = [c["id"] for c in r.json()]
        assert body["id"] in ids


@pytest.mark.asyncio
async def test_provider_requires_key(fresh_org: Organization, app_client) -> None:
    user = await _admin_user(fresh_org)
    pair = await issue_token_pair(
        org_id=fresh_org.id, user_id=user.id, role="admin", auth_method="oidc"
    )
    headers = {"Authorization": f"Bearer {pair.access_token}"}

    async with app_client as client:
        # openai without api_key_ref → 400
        r = await client.post(
            "/v1/connectors",
            json={
                "provider": "openai",
                "display_name": "x",
                "model": "gpt-4o-mini",
                "api_key_ref": "",
            },
            headers=headers,
        )
        assert r.status_code == 400

        # ollama without api_key_ref → 201
        r = await client.post(
            "/v1/connectors",
            json={
                "provider": "ollama",
                "display_name": "local llama",
                "model": "llama3.2",
                "api_key_ref": "",
                "config": {"base_url": "http://localhost:11434"},
            },
            headers=headers,
        )
        assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_enc_pending_key_auto_encrypted_at_storage(
    fresh_org: Organization,
    app_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plaintext keys prefixed with ``enc-pending:`` should be encrypted
    via field_crypto before persistence."""
    # Wire a deterministic field_crypto engine
    from cryptography.fernet import Fernet

    from app.security import field_crypto

    key = Fernet.generate_key().decode()
    monkeypatch.setenv("FIELD_CRYPTO_KEY", key)
    monkeypatch.setenv("FIELD_CRYPTO_KEY_REF", "env:FIELD_CRYPTO_KEY")
    monkeypatch.delenv("FIELD_CRYPTO_KEYRING_REF", raising=False)
    field_crypto.reset_engine_for_tests()

    user = await _admin_user(fresh_org)
    pair = await issue_token_pair(
        org_id=fresh_org.id, user_id=user.id, role="admin", auth_method="oidc"
    )
    headers = {"Authorization": f"Bearer {pair.access_token}"}

    async with app_client as client:
        r = await client.post(
            "/v1/connectors",
            json={
                "provider": "anthropic",
                "display_name": "Claude prod",
                "model": "claude-sonnet-4",
                "api_key_ref": "enc-pending:sk-ant-secretvalue",
                "config": {},
            },
            headers=headers,
        )
        assert r.status_code == 201, r.text

    # Inspect the DB row directly — api_key_ref should now be `enc:v1:...`
    from app.db.models.connector_config import ConnectorConfig
    from sqlalchemy import select

    async with SessionLocal() as db:
        row = (
            await db.execute(
                select(ConnectorConfig).where(
                    ConnectorConfig.org_id == fresh_org.id
                )
            )
        ).scalar_one()
        assert row.api_key_ref.startswith("enc:")
        # And the encrypted ref round-trips back to the original plaintext
        # via the EncryptedInlineResolver
        from app.security.secrets import get_resolver

        assert get_resolver().resolve(row.api_key_ref) == "sk-ant-secretvalue"


@pytest.mark.asyncio
async def test_test_endpoint_records_verification_status(
    fresh_org: Organization,
    app_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The /test endpoint should run health_check, persist outcome to
    verification_status, and return the result."""
    # Patch httpx so the health_check sees a successful response
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = httpx.MockTransport(
            lambda _: httpx.Response(200, json={"data": []})
        )
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

    # Static secret resolver
    from app.security import secrets as secrets_mod

    class StaticResolver:
        prefix = "test:"

        def resolve(self, reference: str) -> str:
            return "sk-test-key"

    original = secrets_mod.get_resolver()
    secrets_mod.set_resolver(StaticResolver())

    try:
        user = await _admin_user(fresh_org)
        pair = await issue_token_pair(
            org_id=fresh_org.id, user_id=user.id, role="admin", auth_method="oidc"
        )
        headers = {"Authorization": f"Bearer {pair.access_token}"}

        async with app_client as client:
            r = await client.post(
                "/v1/connectors",
                json={
                    "provider": "openai",
                    "display_name": "test",
                    "model": "gpt-4o-mini",
                    "api_key_ref": "test:k",
                },
                headers=headers,
            )
            assert r.status_code == 201
            connector_id = r.json()["id"]

            r = await client.post(
                f"/v1/connectors/{connector_id}/test", headers=headers
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["ok"] is True
            assert body["error"] is None

            # And verification_status persisted
            r = await client.get(
                f"/v1/connectors/{connector_id}", headers=headers
            )
            assert r.json()["verification_status"]["ok"] is True
    finally:
        secrets_mod.set_resolver(original)


@pytest.mark.asyncio
async def test_cross_org_isolation(fresh_org: Organization, app_client) -> None:
    """A connector created in org A must not be readable from org B."""
    user_a = await _admin_user(fresh_org)
    pair_a = await issue_token_pair(
        org_id=fresh_org.id, user_id=user_a.id, role="admin", auth_method="oidc"
    )

    other = Organization(
        id=uuid.uuid4(), name="Other", slug=f"other-{uuid.uuid4().hex[:6]}"
    )
    async with SessionLocal() as db:
        db.add(other)
        await db.commit()

    try:
        user_b = await _admin_user(other)
        pair_b = await issue_token_pair(
            org_id=other.id, user_id=user_b.id, role="admin", auth_method="oidc"
        )

        async with app_client as client:
            r = await client.post(
                "/v1/connectors",
                json={
                    "provider": "ollama",
                    "display_name": "A-only",
                    "model": "llama3.2",
                    "api_key_ref": "",
                },
                headers={"Authorization": f"Bearer {pair_a.access_token}"},
            )
            connector_id = r.json()["id"]

            # Org B cannot read by ID
            r = await client.get(
                f"/v1/connectors/{connector_id}",
                headers={"Authorization": f"Bearer {pair_b.access_token}"},
            )
            assert r.status_code == 404
    finally:
        from sqlalchemy import text

        async with SessionLocal() as db:
            await db.execute(
                text("DELETE FROM organizations WHERE id = :id"), {"id": other.id}
            )
            await db.commit()
