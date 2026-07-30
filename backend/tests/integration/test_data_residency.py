"""Region-cell enforcement across every enterprise identity entry point."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
import pytest_asyncio
from sqlalchemy import text

from app.api.v1.auth import _get_org_idp
from app.auth.api_key_service import create_api_key, verify_api_key
from app.auth.jwt_service import REFRESH_PREFIX, consume_refresh_token, issue_token_pair
from app.core.config import get_settings
from app.db.models.idp_config import IdpConfig
from app.db.models.organization import Organization
from app.db.session import SessionLocal
from app.db.tenancy import current_org_id
from app.scim.auth import generate_scim_token
from app.services.redis_client import get_redis

pytestmark = pytest.mark.integration


def _token(org_id: uuid.UUID) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": "ai-security-platform",
            "sub": str(uuid.uuid4()),
            "org": str(org_id),
            "role": "admin",
            "auth": "test",
            "scopes": [],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=10)).timestamp()),
            "jti": str(uuid.uuid4()),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )


@pytest_asyncio.fixture
async def nonresident_org() -> tuple[Organization, str]:
    org = Organization(
        id=uuid.uuid4(),
        name="EU tenant",
        slug=f"eu-{uuid.uuid4().hex[:8]}",
        data_region="eu-west-1",
    )
    async with SessionLocal() as db:
        db.add(org)
        created = await create_api_key(
            db,
            org_id=org.id,
            name="residency-test",
            scopes=["runtime:ingest"],
            created_by=None,
        )
        await db.commit()

    async with SessionLocal() as db:
        assert await verify_api_key(db, created.plaintext) is not None

    yield org, created.plaintext

    async with SessionLocal() as db:
        await db.execute(text("DELETE FROM organizations WHERE id = :id"), {"id": org.id})
        await db.commit()


@pytest_asyncio.fixture
async def resident_identity_org() -> tuple[Organization, str]:
    org = Organization(
        id=uuid.uuid4(),
        name="Local identity tenant",
        slug=f"local-{uuid.uuid4().hex[:8]}",
        data_region=get_settings().deployment_region,
    )
    scim_token, scim_hash = generate_scim_token()
    async with SessionLocal() as db:
        db.add(org)
        db.add_all(
            [
                IdpConfig(
                    org_id=org.id,
                    provider_type="oidc",
                    display_name="Local OIDC",
                    status="active",
                    oidc_config={
                        "issuer_url": "https://idp.example.com",
                        "client_id": "residency-test",
                        "client_secret_ref": "env://OIDC_CLIENT_SECRET",
                    },
                    saml_config={},
                    scim_config={},
                    directory_sync={},
                    verification_status={},
                ),
                IdpConfig(
                    org_id=org.id,
                    provider_type="scim",
                    display_name="Local SCIM",
                    status="active",
                    oidc_config={},
                    saml_config={},
                    scim_config={"bearer_token_hash": scim_hash},
                    directory_sync={},
                    verification_status={},
                ),
            ]
        )
        await db.commit()

    yield org, scim_token

    async with SessionLocal() as db:
        await db.execute(text("DELETE FROM organizations WHERE id = :id"), {"id": org.id})
        await db.commit()


async def test_jwt_and_api_key_are_rejected_before_tenant_context(
    app_client, nonresident_org
) -> None:
    org, api_key = nonresident_org
    async with app_client as client:
        jwt_response = await client.get(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {_token(org.id)}"},
        )
        key_response = await client.get("/v1/auth/me", headers={"X-API-Key": api_key})

    assert jwt_response.status_code == 421
    assert jwt_response.json()["detail"] == "tenant_region_unavailable"
    assert key_response.status_code == 421


async def test_sso_metadata_and_scim_are_rejected_in_wrong_cell(
    app_client, nonresident_org
) -> None:
    org, _ = nonresident_org
    async with app_client as client:
        oidc = await client.get(f"/v1/auth/oidc/{org.slug}/login")
        metadata = await client.get(f"/v1/auth/saml/{org.slug}/metadata")
        scim = await client.get(
            f"/v1/scim/v2/{org.slug}/ServiceProviderConfig",
            headers={"Authorization": "Bearer invalid"},
        )

    assert oidc.status_code == 421
    assert metadata.status_code == 421
    assert scim.status_code == 421
    assert scim.json()["detail"] == "tenant_region_unavailable"


async def test_resident_sso_and_scim_lookup_use_both_isolation_walls(
    app_client, resident_identity_org
) -> None:
    org, scim_token = resident_identity_org
    async with SessionLocal() as db:
        resolved_org, idp = await _get_org_idp(db, org.slug)

    assert resolved_org.id == org.id
    assert idp.provider_type == "oidc"
    assert current_org_id.get() is None

    async with app_client as client:
        response = await client.get(
            f"/v1/scim/v2/{org.slug}/ServiceProviderConfig",
            headers={"Authorization": f"Bearer {scim_token}"},
        )

    assert response.status_code == 200
    assert current_org_id.get() is None


async def test_wrong_cell_does_not_consume_single_use_refresh_token(
    app_client, nonresident_org
) -> None:
    org, _ = nonresident_org
    user_id = uuid.uuid4()
    pair = await issue_token_pair(
        org_id=org.id,
        user_id=user_id,
        role="admin",
        auth_method="test",
    )

    async with app_client as client:
        response = await client.post(
            "/v1/auth/refresh",
            json={"refresh_token": pair.refresh_token},
        )

    assert response.status_code == 421
    payload = await consume_refresh_token(pair.refresh_token)
    assert payload is not None
    assert payload["org_id"] == str(org.id)


async def test_malformed_refresh_record_is_consumed_and_rejected(app_client) -> None:
    refresh_token = f"malformed-{uuid.uuid4()}"
    redis = await get_redis()
    key = REFRESH_PREFIX + refresh_token
    await redis.hset(
        key,
        mapping={
            "org_id": "not-a-uuid",
            "user_id": str(uuid.uuid4()),
            "role": "admin",
        },
    )
    await redis.expire(key, 60)

    async with app_client as client:
        response = await client.post(
            "/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_refresh_token"
    assert await redis.exists(key) == 0
