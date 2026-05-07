"""Tenant isolation smoke test — Org A cannot read Org B's policies.

Marked `integration` because it requires a running Postgres + Redis. Run with:

    docker compose up -d postgres redis
    cd backend && alembic upgrade head
    pytest -m integration

The test exercises the policy CRUD path end-to-end through FastAPI's
TestClient, using two distinct identities backed by two different orgs.
"""

from __future__ import annotations

import os
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt_service import issue_token_pair
from app.db.models.organization import Organization
from app.db.models.user import User
from app.db.session import SessionLocal
from app.main import app

pytestmark = pytest.mark.integration


async def _seed_org_and_user(db: AsyncSession, slug: str, role: str = "admin") -> tuple[Organization, User]:
    org = Organization(id=uuid.uuid4(), name=slug.title(), slug=slug)
    db.add(org)
    await db.flush()
    user = User(
        id=uuid.uuid4(),
        org_id=org.id,
        email=f"admin@{slug}.test",
        name=f"Admin {slug}",
        role=role,
        idp_groups=[],
    )
    db.add(user)
    await db.commit()
    return org, user


@pytest.mark.asyncio
async def test_org_a_cannot_read_org_b_policy() -> None:
    if "ENVIRONMENT" not in os.environ or os.environ["ENVIRONMENT"] != "test":
        pytest.skip("integration test requires ENVIRONMENT=test")

    async with SessionLocal() as db:
        org_a, user_a = await _seed_org_and_user(db, slug=f"org-a-{uuid.uuid4().hex[:6]}")
        org_b, user_b = await _seed_org_and_user(db, slug=f"org-b-{uuid.uuid4().hex[:6]}")

    pair_a = await issue_token_pair(
        org_id=org_a.id, user_id=user_a.id, role="admin", auth_method="oidc"
    )
    pair_b = await issue_token_pair(
        org_id=org_b.id, user_id=user_b.id, role="admin", auth_method="oidc"
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Org A creates a policy
        resp = await client.post(
            "/v1/policies",
            json={"name": "org-a-policy", "enforcement_level": "fast"},
            headers={"Authorization": f"Bearer {pair_a.access_token}"},
        )
        assert resp.status_code == 201, resp.text
        policy_id = resp.json()["id"]

        # Org A can read it
        resp = await client.get(
            f"/v1/policies/{policy_id}",
            headers={"Authorization": f"Bearer {pair_a.access_token}"},
        )
        assert resp.status_code == 200

        # Org B cannot read it via direct ID lookup
        resp = await client.get(
            f"/v1/policies/{policy_id}",
            headers={"Authorization": f"Bearer {pair_b.access_token}"},
        )
        assert resp.status_code == 404

        # Org B cannot see it in their list either
        resp = await client.get(
            "/v1/policies",
            headers={"Authorization": f"Bearer {pair_b.access_token}"},
        )
        assert resp.status_code == 200
        ids = [p["id"] for p in resp.json()]
        assert policy_id not in ids
