"""Cross-tenant isolation (Phase 3B) — proof, not assertion.

Org A creates and syncs a connector; org B's token must get **404** (never
200/403) for every direct access to A's resources, and must never see A's
data in any list or aggregate view. 404-not-403 so existence isn't disclosed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
import pytest_asyncio
from sqlalchemy import text

from app.core.config import get_settings
from app.db.models.organization import Organization
from app.db.session import SessionLocal

pytestmark = pytest.mark.integration


def _token(org_id: uuid.UUID) -> str:
    s = get_settings()
    now = datetime.now(UTC)
    claims = {
        "iss": "ai-security-platform",
        "sub": str(uuid.uuid4()),
        "org": str(org_id),
        "role": "admin",
        "auth": "test",
        "scopes": [],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, s.jwt_secret, algorithm=s.jwt_algorithm)


@pytest_asyncio.fixture
async def two_orgs():
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    async with SessionLocal() as db:
        for oid, label in ((org_a, "a"), (org_b, "b")):
            db.add(
                Organization(
                    id=oid, name=f"iso-{label}", slug=f"iso-{label}-{uuid.uuid4().hex[:8]}"
                )
            )
        await db.commit()
    yield org_a, org_b
    # CASCADE cleans up any connectors/assets created under either org.
    async with SessionLocal() as db:
        await db.execute(
            text("DELETE FROM organizations WHERE id IN (:a, :b)"),
            {"a": org_a, "b": org_b},
        )
        await db.commit()


async def test_cross_tenant_isolation(app_client, two_orgs) -> None:
    org_a, org_b = two_orgs
    a = {"Authorization": f"Bearer {_token(org_a)}"}
    b = {"Authorization": f"Bearer {_token(org_b)}"}

    async with app_client as client:
        # Org A creates a connector and syncs it (→ 10 mock assets in org A).
        resp = await client.post(
            "/v1/connectors",
            headers=a,
            json={"name": "a-conn", "connector_type": "mock", "config": {"stable": True}},
        )
        assert resp.status_code == 201, resp.text
        cid = resp.json()["id"]
        await client.post(f"/v1/connectors/{cid}/sync", headers=a)

        a_assets = (await client.get("/v1/assets", headers=a)).json()
        assert a_assets, "org A should see its synced assets"
        aid = a_assets[0]["id"]

        # ── Org B: every direct access to A's resources → 404 (not 403/200) ──
        assert (await client.get(f"/v1/connectors/{cid}", headers=b)).status_code == 404
        assert (await client.post(f"/v1/connectors/{cid}/test", headers=b)).status_code == 404
        assert (await client.post(f"/v1/connectors/{cid}/sync", headers=b)).status_code == 404
        assert (await client.delete(f"/v1/connectors/{cid}", headers=b)).status_code == 404
        assert (await client.get(f"/v1/assets/{aid}", headers=b)).status_code == 404
        assert (await client.get(f"/v1/assets/{aid}/history", headers=b)).status_code == 404

        # ── Org B: list / aggregate views must not leak A's data ─────────────
        assert (await client.get("/v1/connectors", headers=b)).json() == []
        assert (await client.get("/v1/assets", headers=b)).json() == []
        assert (await client.get("/v1/assets/unowned", headers=b)).json() == []
        summary_b = (await client.get("/v1/dashboard/summary", headers=b)).json()
        assert summary_b["total_assets"] == 0
        disc_b = (await client.get("/v1/discovery/status", headers=b)).json()
        assert disc_b["total_assets"] == 0
        assert all(c["id"] != cid for c in disc_b["connectors"])

        # ── Org A still owns and sees everything ─────────────────────────────
        assert (await client.get(f"/v1/connectors/{cid}", headers=a)).status_code == 200
        assert (await client.get(f"/v1/assets/{aid}", headers=a)).status_code == 200
        assert (await client.get("/v1/dashboard/summary", headers=a)).json()["total_assets"] >= 10
