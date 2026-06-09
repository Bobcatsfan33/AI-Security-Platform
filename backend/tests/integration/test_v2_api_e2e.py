"""HTTP-layer end-to-end test: register connector → sync → query assets.

Drives the FastAPI app in-process via httpx ASGI transport. Mints a
JWT directly so we don't depend on the OIDC/SAML round-trip.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.db.session import SessionLocal

pytestmark = pytest.mark.integration


def _issue_admin_token() -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    claims = {
        "iss": "ai-security-platform",
        "sub": str(uuid.uuid4()),
        "org": str(uuid.uuid4()),
        "role": "admin",
        "auth": "test",
        "scopes": [],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(
        claims, settings.jwt_secret, algorithm=settings.jwt_algorithm
    )


@pytest.fixture
def _auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_issue_admin_token()}"}


@pytest.fixture
async def _cleanup_connector_ids():
    created: list[str] = []
    yield created
    if not created:
        return
    async with SessionLocal() as db:
        for cid in created:
            await db.execute(
                text("DELETE FROM connectors WHERE id = :id"), {"id": cid}
            )
        await db.commit()


async def test_full_pipeline_register_sync_list(
    app_client, _auth_headers, _cleanup_connector_ids
) -> None:
    async with app_client as client:
        # 1. The catalog includes the mock connector
        resp = await client.get(
            "/v1/connectors/available", headers=_auth_headers
        )
        assert resp.status_code == 200
        catalog_names = [m["name"] for m in resp.json()]
        assert "Mock" in catalog_names

        # 2. Register a mock connector
        resp = await client.post(
            "/v1/connectors",
            headers=_auth_headers,
            json={
                "name": "integration-mock",
                "connector_type": "mock",
                "config": {"stable": True},
            },
        )
        assert resp.status_code == 201, resp.text
        connector_id = resp.json()["id"]
        _cleanup_connector_ids.append(connector_id)

        # 3. Test connection succeeds
        resp = await client.post(
            f"/v1/connectors/{connector_id}/test", headers=_auth_headers
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["connected"] is True

        # 4. Sync — should discover the 10 mock assets
        resp = await client.post(
            f"/v1/connectors/{connector_id}/sync", headers=_auth_headers
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "completed"
        assert body["assets_discovered"] == 10

        # 5. Assets visible via the list route
        resp = await client.get(
            f"/v1/assets?connector_id={connector_id}", headers=_auth_headers
        )
        assert resp.status_code == 200
        assets = resp.json()
        assert len(assets) == 10
        types = {a["asset_type"] for a in assets}
        assert types == {"model", "endpoint", "dataset", "pipeline", "agent", "tool"}

        # 6. Asset detail returns deployments/tags lists (even if empty)
        sample = assets[0]
        resp = await client.get(
            f"/v1/assets/{sample['id']}", headers=_auth_headers
        )
        assert resp.status_code == 200
        detail = resp.json()
        assert detail["id"] == sample["id"]
        assert detail["deployments"] == []
        assert detail["tags"] == []

        # 7. Changelog shows a `created` entry from the sync
        resp = await client.get(
            f"/v1/assets/{sample['id']}/history", headers=_auth_headers
        )
        assert resp.status_code == 200
        history = resp.json()
        assert len(history) >= 1
        assert any(h["change_type"] == "created" for h in history)

        # 8. Discovery overview lists the connector and totals correctly
        resp = await client.get(
            "/v1/discovery/status", headers=_auth_headers
        )
        assert resp.status_code == 200
        status = resp.json()
        assert status["total_connectors"] >= 1
        assert any(c["id"] == connector_id for c in status["connectors"])

        # 9. Dashboard summary returns counts >= what we just added
        resp = await client.get(
            "/v1/dashboard/summary", headers=_auth_headers
        )
        assert resp.status_code == 200
        summary = resp.json()
        assert summary["total_assets"] >= 10
        assert summary["unowned_count"] >= 10


async def test_search_finds_assets_by_name(
    app_client, _auth_headers, _cleanup_connector_ids
) -> None:
    async with app_client as client:
        resp = await client.post(
            "/v1/connectors",
            headers=_auth_headers,
            json={
                "name": "search-mock",
                "connector_type": "mock",
                "config": {"stable": True},
            },
        )
        assert resp.status_code == 201
        connector_id = resp.json()["id"]
        _cleanup_connector_ids.append(connector_id)

        await client.post(
            f"/v1/connectors/{connector_id}/sync", headers=_auth_headers
        )

        # Mock fixture includes "GPT-4o" in its name
        resp = await client.get(
            "/v1/assets/search?q=GPT", headers=_auth_headers
        )
        assert resp.status_code == 200
        hits = resp.json()
        assert any("GPT" in h["name"] for h in hits)


async def test_unknown_connector_type_rejected(app_client, _auth_headers) -> None:
    async with app_client as client:
        resp = await client.post(
            "/v1/connectors",
            headers=_auth_headers,
            json={
                "name": "bad",
                "connector_type": "nonexistent_type",
                "config": {},
            },
        )
        assert resp.status_code == 400
        assert "unknown connector_type" in resp.json()["detail"]
