"""Policy Redis pub/sub propagation — end-to-end against live Redis.

Verifies:
  - Subscribing to ``policy:invalidation:{org_id}`` and receiving the JSON
    invalidation message after a policy CRUD operation
  - Message payload shape: {policy_id, version, event}
  - Each operation (create/update/delete) emits the right event type
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import pytest

from app.auth.jwt_service import issue_token_pair
from app.db.models.organization import Organization
from app.db.models.user import User
from app.db.session import SessionLocal
from app.services.policy_pubsub import channel_name
from app.services.redis_client import get_redis

pytestmark = pytest.mark.integration


async def _admin_user(org: Organization) -> User:
    user = User(
        id=uuid.uuid4(),
        org_id=org.id,
        email=f"admin-{uuid.uuid4().hex[:6]}@example.com",
        name="Admin",
        role="admin",
        idp_groups=[],
    )
    async with SessionLocal() as db:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    return user


async def _drain_one(pubsub, *, timeout: float = 3.0) -> dict[str, Any] | None:
    """Read messages until we get a real 'message' event or time out."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        msg = await pubsub.get_message(timeout=0.5, ignore_subscribe_messages=True)
        if msg is not None and msg.get("type") == "message":
            return msg
        await asyncio.sleep(0.05)
    return None


@pytest.mark.asyncio
async def test_policy_create_publishes_invalidation(
    fresh_org: Organization, app_client
) -> None:
    user = await _admin_user(fresh_org)
    pair = await issue_token_pair(
        org_id=fresh_org.id, user_id=user.id, role="admin", auth_method="oidc"
    )
    headers = {"Authorization": f"Bearer {pair.access_token}"}

    redis = await get_redis()
    pubsub = redis.pubsub()
    await pubsub.subscribe(channel_name(fresh_org.id))

    try:
        # Drain the SUBSCRIBE confirmation
        await pubsub.get_message(timeout=0.5)

        async with app_client as client:
            resp = await client.post(
                "/v1/policies",
                json={"name": "test-policy", "enforcement_level": "fast"},
                headers=headers,
            )
            assert resp.status_code == 201, resp.text
            policy_id = resp.json()["id"]
            policy_version = resp.json()["version"]

        msg = await _drain_one(pubsub)
        assert msg is not None, "no invalidation message received"

        payload = json.loads(msg["data"])
        assert payload["event"] == "create"
        assert payload["policy_id"] == policy_id
        assert payload["version"] == policy_version
    finally:
        await pubsub.unsubscribe()
        await pubsub.aclose()


@pytest.mark.asyncio
async def test_policy_update_publishes_invalidation_with_new_version(
    fresh_org: Organization, app_client
) -> None:
    user = await _admin_user(fresh_org)
    pair = await issue_token_pair(
        org_id=fresh_org.id, user_id=user.id, role="admin", auth_method="oidc"
    )
    headers = {"Authorization": f"Bearer {pair.access_token}"}

    async with app_client as client:
        r = await client.post(
            "/v1/policies",
            json={"name": "v-test", "enforcement_level": "fast"},
            headers=headers,
        )
        policy_id = r.json()["id"]
        v1 = r.json()["version"]

        redis = await get_redis()
        pubsub = redis.pubsub()
        await pubsub.subscribe(channel_name(fresh_org.id))
        try:
            await pubsub.get_message(timeout=0.5)  # drain subscribe

            r = await client.patch(
                f"/v1/policies/{policy_id}",
                json={"enforcement_level": "balanced"},
                headers=headers,
            )
            assert r.status_code == 200
            assert r.json()["version"] == v1 + 1

            msg = await _drain_one(pubsub)
            assert msg is not None
            payload = json.loads(msg["data"])
            assert payload["event"] == "update"
            assert payload["policy_id"] == policy_id
            assert payload["version"] == v1 + 1
        finally:
            await pubsub.unsubscribe()
            await pubsub.aclose()


@pytest.mark.asyncio
async def test_policy_delete_publishes_invalidation(
    fresh_org: Organization, app_client
) -> None:
    user = await _admin_user(fresh_org)
    pair = await issue_token_pair(
        org_id=fresh_org.id, user_id=user.id, role="admin", auth_method="oidc"
    )
    headers = {"Authorization": f"Bearer {pair.access_token}"}

    async with app_client as client:
        r = await client.post(
            "/v1/policies",
            json={"name": "d-test", "enforcement_level": "fast"},
            headers=headers,
        )
        policy_id = r.json()["id"]

        redis = await get_redis()
        pubsub = redis.pubsub()
        await pubsub.subscribe(channel_name(fresh_org.id))
        try:
            await pubsub.get_message(timeout=0.5)

            r = await client.delete(
                f"/v1/policies/{policy_id}",
                headers=headers,
            )
            assert r.status_code == 204

            msg = await _drain_one(pubsub)
            assert msg is not None
            payload = json.loads(msg["data"])
            assert payload["event"] == "delete"
            assert payload["policy_id"] == policy_id
        finally:
            await pubsub.unsubscribe()
            await pubsub.aclose()


@pytest.mark.asyncio
async def test_pubsub_channel_isolated_per_org(
    fresh_org: Organization, app_client
) -> None:
    """Two distinct orgs should never see each other's policy invalidations."""
    other = Organization(
        id=uuid.uuid4(), name="Other", slug=f"other-{uuid.uuid4().hex[:6]}"
    )
    async with SessionLocal() as db:
        db.add(other)
        await db.commit()

    try:
        user = await _admin_user(fresh_org)
        pair = await issue_token_pair(
            org_id=fresh_org.id, user_id=user.id, role="admin", auth_method="oidc"
        )
        headers = {"Authorization": f"Bearer {pair.access_token}"}

        redis = await get_redis()
        pubsub = redis.pubsub()
        # Subscribe to OTHER's channel — fresh_org's policy writes must NOT
        # appear here
        await pubsub.subscribe(channel_name(other.id))
        try:
            await pubsub.get_message(timeout=0.5)
            async with app_client as client:
                r = await client.post(
                    "/v1/policies",
                    json={"name": "cross-org-leak-test", "enforcement_level": "fast"},
                    headers=headers,
                )
                assert r.status_code == 201

            # Should time out — no message on the other org's channel
            msg = await _drain_one(pubsub, timeout=1.0)
            assert msg is None
        finally:
            await pubsub.unsubscribe()
            await pubsub.aclose()
    finally:
        from sqlalchemy import text

        async with SessionLocal() as db:
            await db.execute(
                text("DELETE FROM organizations WHERE id = :id"), {"id": other.id}
            )
            await db.commit()
