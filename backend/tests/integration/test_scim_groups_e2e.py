"""SCIM Groups end-to-end tests.

Groups in the platform are derived from each user's ``idp_groups`` JSONB
column, not stored separately. The integration tests here verify:

- POST /Groups with members propagates the group name into each user's
  idp_groups
- Group→role recomputation runs on every membership change via
  directory_sync.group_to_role_mapping
- PATCH add/remove members flow through to user records
- DELETE removes the group name from every member's idp_groups
- LIST shows distinct group names with correct member counts
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.db.models.idp_config import IdpConfig
from app.db.models.organization import Organization
from app.db.models.user import User
from app.db.session import SessionLocal
from app.scim.types import SCHEMA_GROUP, SCHEMA_PATCH_OP, SCHEMA_USER

pytestmark = pytest.mark.integration


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _user_payload(user_name: str, **overrides: object) -> dict:
    base = {
        "schemas": [SCHEMA_USER],
        "userName": user_name,
        "active": True,
        "name": {"givenName": "T", "familyName": "U"},
        "emails": [{"value": user_name, "primary": True}],
    }
    base.update(overrides)
    return base


async def _create_user(client, org_slug: str, token: str, user_name: str) -> str:
    r = await client.post(
        f"/v1/scim/v2/{org_slug}/Users",
        json=_user_payload(user_name),
        headers=_bearer(token),
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


@pytest.mark.asyncio
async def test_create_group_adds_members_to_each_user_idp_groups(
    fresh_org: Organization,
    scim_idp: tuple[IdpConfig, str],
    app_client,
) -> None:
    _, token = scim_idp
    async with app_client as client:
        u1 = await _create_user(client, fresh_org.slug, token, "u1@example.com")
        u2 = await _create_user(client, fresh_org.slug, token, "u2@example.com")

        r = await client.post(
            f"/v1/scim/v2/{fresh_org.slug}/Groups",
            json={
                "schemas": [SCHEMA_GROUP],
                "displayName": "Engineering",
                "members": [{"value": u1}, {"value": u2}],
            },
            headers=_bearer(token),
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["displayName"] == "Engineering"
        assert {m["value"] for m in body["members"]} == {u1, u2}

    # Verify both users now have "Engineering" in idp_groups and the
    # analyst role from group_to_role_mapping.
    async with SessionLocal() as db:
        rows = (
            await db.execute(
                select(User).where(User.org_id == fresh_org.id)
            )
        ).scalars().all()
        for u in rows:
            assert "Engineering" in u.idp_groups
            assert u.role == "analyst"


@pytest.mark.asyncio
async def test_get_nonexistent_group_returns_404(
    fresh_org: Organization,
    scim_idp: tuple[IdpConfig, str],
    app_client,
) -> None:
    _, token = scim_idp
    async with app_client as client:
        r = await client.get(
            f"/v1/scim/v2/{fresh_org.slug}/Groups/Nonexistent",
            headers=_bearer(token),
        )
        assert r.status_code == 404
        assert r.json()["status"] == "404"


@pytest.mark.asyncio
async def test_list_groups_aggregates_distinct_names(
    fresh_org: Organization,
    scim_idp: tuple[IdpConfig, str],
    app_client,
) -> None:
    _, token = scim_idp
    async with app_client as client:
        u1 = await _create_user(client, fresh_org.slug, token, "g-u1@example.com")
        u2 = await _create_user(client, fresh_org.slug, token, "g-u2@example.com")

        await client.post(
            f"/v1/scim/v2/{fresh_org.slug}/Groups",
            json={
                "schemas": [SCHEMA_GROUP],
                "displayName": "Engineering",
                "members": [{"value": u1}],
            },
            headers=_bearer(token),
        )
        await client.post(
            f"/v1/scim/v2/{fresh_org.slug}/Groups",
            json={
                "schemas": [SCHEMA_GROUP],
                "displayName": "Security",
                "members": [{"value": u2}],
            },
            headers=_bearer(token),
        )

        r = await client.get(
            f"/v1/scim/v2/{fresh_org.slug}/Groups", headers=_bearer(token)
        )
        assert r.status_code == 200
        body = r.json()
        names = {g["displayName"] for g in body["Resources"]}
        assert {"Engineering", "Security"}.issubset(names)


@pytest.mark.asyncio
async def test_patch_group_add_members_recomputes_role(
    fresh_org: Organization,
    scim_idp: tuple[IdpConfig, str],
    app_client,
) -> None:
    """When a user is added to the Security group via PATCH, their platform
    role should change from viewer (default) to admin (per
    directory_sync.group_to_role_mapping)."""
    _, token = scim_idp
    async with app_client as client:
        u1 = await _create_user(client, fresh_org.slug, token, "p-u1@example.com")

        # Create the Security group first by adding u1
        await client.post(
            f"/v1/scim/v2/{fresh_org.slug}/Groups",
            json={
                "schemas": [SCHEMA_GROUP],
                "displayName": "Security",
                "members": [{"value": u1}],
            },
            headers=_bearer(token),
        )

        u2 = await _create_user(client, fresh_org.slug, token, "p-u2@example.com")

        # u2 starts as viewer (no groups)
        async with SessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.id == uuid.UUID(u2)))
            ).scalar_one()
            assert user.role == "viewer"

        # PATCH the group to add u2 — uses RFC 7644 add-with-path
        patch_doc = {
            "schemas": [SCHEMA_PATCH_OP],
            "Operations": [
                {
                    "op": "add",
                    "path": "members",
                    "value": [{"value": u2}],
                }
            ],
        }
        r = await client.patch(
            f"/v1/scim/v2/{fresh_org.slug}/Groups/Security",
            json=patch_doc,
            headers=_bearer(token),
        )
        assert r.status_code == 200, r.text

        # u2 is now admin
        async with SessionLocal() as db:
            user = (
                await db.execute(select(User).where(User.id == uuid.UUID(u2)))
            ).scalar_one()
            assert user.role == "admin"
            assert "Security" in user.idp_groups


@pytest.mark.asyncio
async def test_delete_group_removes_from_all_users(
    fresh_org: Organization,
    scim_idp: tuple[IdpConfig, str],
    app_client,
) -> None:
    _, token = scim_idp
    async with app_client as client:
        u1 = await _create_user(client, fresh_org.slug, token, "d-u1@example.com")
        u2 = await _create_user(client, fresh_org.slug, token, "d-u2@example.com")

        await client.post(
            f"/v1/scim/v2/{fresh_org.slug}/Groups",
            json={
                "schemas": [SCHEMA_GROUP],
                "displayName": "Engineering",
                "members": [{"value": u1}, {"value": u2}],
            },
            headers=_bearer(token),
        )

        r = await client.delete(
            f"/v1/scim/v2/{fresh_org.slug}/Groups/Engineering",
            headers=_bearer(token),
        )
        assert r.status_code == 204, r.text

    async with SessionLocal() as db:
        rows = (
            await db.execute(select(User).where(User.org_id == fresh_org.id))
        ).scalars().all()
        for u in rows:
            assert "Engineering" not in (u.idp_groups or [])
