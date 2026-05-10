"""SCIM Users CRUD round-trip against a live Postgres.

Exercises the route handlers, the bearer-token auth, the user_service /
serializer wiring, and the org-isolation invariants — none of which are
covered by the unit tests because they need a real DB.
"""

from __future__ import annotations

import json

import pytest

from app.db.models.idp_config import IdpConfig
from app.db.models.organization import Organization
from app.scim.types import SCHEMA_USER, SCHEMA_PATCH_OP

pytestmark = pytest.mark.integration


def _user_payload(user_name: str, **overrides: object) -> dict:
    base = {
        "schemas": [SCHEMA_USER],
        "userName": user_name,
        "active": True,
        "name": {"givenName": "Test", "familyName": "User"},
        "emails": [{"value": user_name, "primary": True, "type": "work"}],
    }
    base.update(overrides)
    return base


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_create_then_read_user(
    fresh_org: Organization,
    scim_idp: tuple[IdpConfig, str],
    app_client,
) -> None:
    _, token = scim_idp
    async with app_client as client:
        resp = await client.post(
            f"/v1/scim/v2/{fresh_org.slug}/Users",
            json=_user_payload("alice@example.com"),
            headers=_bearer(token),
        )
        assert resp.status_code == 201, resp.text
        created = resp.json()
        assert created["userName"] == "alice@example.com"
        user_id = created["id"]

        resp = await client.get(
            f"/v1/scim/v2/{fresh_org.slug}/Users/{user_id}",
            headers=_bearer(token),
        )
        assert resp.status_code == 200
        assert resp.json()["userName"] == "alice@example.com"


@pytest.mark.asyncio
async def test_create_user_assigns_role_from_groups(
    fresh_org: Organization,
    scim_idp: tuple[IdpConfig, str],
    app_client,
) -> None:
    """Creating a user via SCIM with idp_groups should map to the correct role
    via directory_sync.group_to_role_mapping."""
    _, token = scim_idp
    payload = _user_payload(
        "bob@example.com",
        groups=[{"value": "Security", "display": "Security"}],
    )
    async with app_client as client:
        resp = await client.post(
            f"/v1/scim/v2/{fresh_org.slug}/Users",
            json=payload,
            headers=_bearer(token),
        )
        assert resp.status_code == 201, resp.text

    # Verify in the DB that the user got the admin role from the Security group
    from sqlalchemy import select

    from app.db.models.user import User
    from app.db.session import SessionLocal

    async with SessionLocal() as db:
        rows = (
            await db.execute(
                select(User).where(
                    User.org_id == fresh_org.id, User.email == "bob@example.com"
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].role == "admin"
        assert "Security" in rows[0].idp_groups


@pytest.mark.asyncio
async def test_list_users_with_filter(
    fresh_org: Organization,
    scim_idp: tuple[IdpConfig, str],
    app_client,
) -> None:
    _, token = scim_idp
    async with app_client as client:
        for name in ("alice@example.com", "bob@example.com", "cathy@example.com"):
            r = await client.post(
                f"/v1/scim/v2/{fresh_org.slug}/Users",
                json=_user_payload(name),
                headers=_bearer(token),
            )
            assert r.status_code == 201

        # Without filter — all 3
        r = await client.get(
            f"/v1/scim/v2/{fresh_org.slug}/Users",
            headers=_bearer(token),
        )
        assert r.status_code == 200
        assert r.json()["totalResults"] >= 3

        # eq filter
        r = await client.get(
            f"/v1/scim/v2/{fresh_org.slug}/Users",
            params={"filter": 'userName eq "alice@example.com"'},
            headers=_bearer(token),
        )
        assert r.status_code == 200
        body = r.json()
        assert body["totalResults"] == 1
        assert body["Resources"][0]["userName"] == "alice@example.com"

        # sw filter
        r = await client.get(
            f"/v1/scim/v2/{fresh_org.slug}/Users",
            params={"filter": 'userName sw "bo"'},
            headers=_bearer(token),
        )
        assert r.status_code == 200
        assert r.json()["totalResults"] == 1
        assert r.json()["Resources"][0]["userName"] == "bob@example.com"


@pytest.mark.asyncio
async def test_patch_replace_active_flag(
    fresh_org: Organization,
    scim_idp: tuple[IdpConfig, str],
    app_client,
) -> None:
    _, token = scim_idp
    async with app_client as client:
        r = await client.post(
            f"/v1/scim/v2/{fresh_org.slug}/Users",
            json=_user_payload("dave@example.com"),
            headers=_bearer(token),
        )
        user_id = r.json()["id"]

        patch_doc = {
            "schemas": [SCHEMA_PATCH_OP],
            "Operations": [
                {"op": "replace", "path": "active", "value": False}
            ],
        }
        r = await client.patch(
            f"/v1/scim/v2/{fresh_org.slug}/Users/{user_id}",
            json=patch_doc,
            headers=_bearer(token),
        )
        assert r.status_code == 200, r.text
        assert r.json()["active"] is False


@pytest.mark.asyncio
async def test_delete_deactivates_user(
    fresh_org: Organization,
    scim_idp: tuple[IdpConfig, str],
    app_client,
) -> None:
    """SCIM DELETE on a User deactivates rather than hard-deletes — so audit
    trails remain. Verify the row still exists with is_active=False."""
    _, token = scim_idp
    async with app_client as client:
        r = await client.post(
            f"/v1/scim/v2/{fresh_org.slug}/Users",
            json=_user_payload("eve@example.com"),
            headers=_bearer(token),
        )
        user_id = r.json()["id"]

        r = await client.delete(
            f"/v1/scim/v2/{fresh_org.slug}/Users/{user_id}",
            headers=_bearer(token),
        )
        assert r.status_code == 204

        # Read still succeeds — user record persists
        r = await client.get(
            f"/v1/scim/v2/{fresh_org.slug}/Users/{user_id}",
            headers=_bearer(token),
        )
        assert r.status_code == 200
        assert r.json()["active"] is False


@pytest.mark.asyncio
async def test_unauthenticated_request_rejected(
    fresh_org: Organization,
    scim_idp: tuple[IdpConfig, str],
    app_client,
) -> None:
    async with app_client as client:
        r = await client.get(f"/v1/scim/v2/{fresh_org.slug}/Users")
        assert r.status_code == 401

        r = await client.get(
            f"/v1/scim/v2/{fresh_org.slug}/Users",
            headers={"Authorization": "Bearer scim_definitely-wrong"},
        )
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_token_from_other_org_rejected(
    fresh_org: Organization,
    scim_idp: tuple[IdpConfig, str],
    app_client,
) -> None:
    """A SCIM token issued for org A must not authenticate against org B's slug.
    The route resolver looks up the SCIM IdP by org_slug, then verifies the
    bearer against THAT IdP's hash."""
    import uuid as _uuid

    from app.db.session import SessionLocal

    _, token_for_a = scim_idp

    other = Organization(
        id=_uuid.uuid4(),
        name="Other Org",
        slug=f"other-{_uuid.uuid4().hex[:8]}",
    )
    async with SessionLocal() as db:
        db.add(other)
        await db.commit()

    try:
        async with app_client as client:
            r = await client.get(
                f"/v1/scim/v2/{other.slug}/Users",
                headers=_bearer(token_for_a),
            )
            # Either 401 (no SCIM IdP for that org) or 404 — both are correct
            # rejections. The wrong outcome would be a 200 reading the other
            # org's users.
            assert r.status_code in (401, 404)
    finally:
        from sqlalchemy import text

        async with SessionLocal() as db:
            await db.execute(
                text("DELETE FROM organizations WHERE id = :id"), {"id": other.id}
            )
            await db.commit()


@pytest.mark.asyncio
async def test_service_provider_config_returns_scim_compliant_body(
    fresh_org: Organization,
    scim_idp: tuple[IdpConfig, str],
    app_client,
) -> None:
    _, token = scim_idp
    async with app_client as client:
        r = await client.get(
            f"/v1/scim/v2/{fresh_org.slug}/ServiceProviderConfig",
            headers=_bearer(token),
        )
        assert r.status_code == 200
        body = json.loads(r.content)
        assert body["patch"]["supported"] is True
        assert body["filter"]["supported"] is True
        assert body["bulk"]["supported"] is False
