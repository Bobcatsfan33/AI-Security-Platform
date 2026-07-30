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
from sqlalchemy import select, text

from app.core.config import get_settings
from app.db.models.idp_config import IdpConfig
from app.db.models.mcp import McpToolProfile
from app.db.models.organization import Organization
from app.db.models.user import User
from app.db.session import SessionLocal

pytestmark = pytest.mark.integration


def _token(
    org_id: uuid.UUID,
    *,
    subject: uuid.UUID | None = None,
    role: str = "admin",
) -> str:
    s = get_settings()
    now = datetime.now(UTC)
    claims = {
        "iss": "ai-security-platform",
        "sub": str(subject or uuid.uuid4()),
        "org": str(org_id),
        "role": role,
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


async def test_siem_exporter_config_is_org_scoped(app_client, two_orgs, monkeypatch) -> None:
    """SIEM exporter config lives in Organization.settings, addressed by name
    within the caller's org — so isolation is structural: org B's token can only
    ever load org B's row. This proves it end to end (GAP-001).

    404-not-403 on B's probes for A's exporter, so existence is not disclosed.
    """
    org_a, org_b = two_orgs
    a = {"Authorization": f"Bearer {_token(org_a)}"}
    b = {"Authorization": f"Bearer {_token(org_b)}"}
    # The create path resolves the secret ref, so the referenced var must exist.
    monkeypatch.setenv("A_TOKEN", "org-a-splunk-token")
    splunk = {
        "type": "splunk_hec",
        "name": "a-splunk",
        "config": {"url": "https://splunk.a", "token": "env:A_TOKEN"},
    }

    async with app_client as client:
        # Org A creates an exporter.
        resp = await client.post("/v1/siem/exporters", headers=a, json=splunk)
        assert resp.status_code == 201, resp.text

        # ── Org B must not see it in the list ────────────────────────────────
        assert (await client.get("/v1/siem/exporters", headers=b)).json() == []

        # ── Org B must not be able to mutate it by name (404, not 403) ───────
        assert (
            await client.put("/v1/siem/exporters/a-splunk", headers=b, json=splunk)
        ).status_code == 404
        assert (await client.delete("/v1/siem/exporters/a-splunk", headers=b)).status_code == 404

        # ── Org A still owns it ──────────────────────────────────────────────
        a_list = (await client.get("/v1/siem/exporters", headers=a)).json()
        assert [e["name"] for e in a_list] == ["a-splunk"]


async def test_enterprise_identity_provisioning_is_org_scoped(
    app_client,
    two_orgs,
    monkeypatch,
) -> None:
    """Mounted IdP admin + SCIM remain admin-only and tenant-bound end to end."""
    from app.scim import groups as scim_group_service
    from app.scim import users as scim_user_service
    from app.scim.types import SCHEMA_GROUP, SCHEMA_PATCH_OP, SCHEMA_USER

    audit_events: list[str] = []

    def capture_audit(event_type, *args, **kwargs) -> None:
        audit_events.append(getattr(event_type, "value", str(event_type)))

    monkeypatch.setattr(scim_user_service, "log_event", capture_audit)
    monkeypatch.setattr(scim_group_service, "log_event", capture_audit)

    org_a, org_b = two_orgs
    admin_a, admin_b = uuid.uuid4(), uuid.uuid4()
    async with SessionLocal() as db:
        db.add_all(
            [
                User(
                    id=admin_a,
                    org_id=org_a,
                    email=f"identity-admin-a-{admin_a.hex[:8]}@x.io",
                    name="Identity Admin A",
                    role="admin",
                    idp_groups=[],
                ),
                User(
                    id=admin_b,
                    org_id=org_b,
                    email=f"identity-admin-b-{admin_b.hex[:8]}@x.io",
                    name="Identity Admin B",
                    role="admin",
                    idp_groups=[],
                ),
            ]
        )
        await db.commit()
        slugs = dict(
            (
                await db.execute(
                    select(Organization.id, Organization.slug).where(
                        Organization.id.in_((org_a, org_b))
                    )
                )
            ).all()
        )

    a = {"Authorization": f"Bearer {_token(org_a, subject=admin_a)}"}
    b = {"Authorization": f"Bearer {_token(org_b, subject=admin_b)}"}
    viewer_a = {"Authorization": f"Bearer {_token(org_a, subject=admin_a, role='viewer')}"}

    async with app_client as client:
        # The administration surface requires admin and never reveals another
        # organization's configuration or object existence.
        assert (await client.get("/v1/idp", headers=viewer_a)).status_code == 403
        create_a = await client.post(
            "/v1/idp",
            headers=a,
            json={"provider_type": "scim", "display_name": "SCIM A"},
        )
        create_b = await client.post(
            "/v1/idp",
            headers=b,
            json={"provider_type": "scim", "display_name": "SCIM B"},
        )
        assert create_a.status_code == create_b.status_code == 201
        idp_a, idp_b = create_a.json()["id"], create_b.json()["id"]
        assert [row["id"] for row in (await client.get("/v1/idp", headers=a)).json()] == [idp_a]
        assert [row["id"] for row in (await client.get("/v1/idp", headers=b)).json()] == [idp_b]
        assert (
            await client.patch(
                f"/v1/idp/{idp_a}",
                headers=b,
                json={"display_name": "cross-tenant overwrite"},
            )
        ).status_code == 404
        assert (await client.post(f"/v1/idp/{idp_a}/scim-token", headers=b)).status_code == 404
        assert (await client.delete(f"/v1/idp/{idp_a}", headers=b)).status_code == 404

        token_a_response = await client.post(f"/v1/idp/{idp_a}/scim-token", headers=a)
        token_b_response = await client.post(f"/v1/idp/{idp_b}/scim-token", headers=b)
        assert token_a_response.status_code == token_b_response.status_code == 200
        scim_a = {"Authorization": f"Bearer {token_a_response.json()['token']}"}
        scim_b = {"Authorization": f"Bearer {token_b_response.json()['token']}"}
        assert (
            await client.patch(f"/v1/idp/{idp_a}", headers=a, json={"status": "active"})
        ).status_code == 200
        assert (
            await client.patch(f"/v1/idp/{idp_b}", headers=b, json={"status": "active"})
        ).status_code == 200

        # The SCIM provider may manage only users attributed to this IdP, not
        # local/OIDC/SAML identities that happen to share its organization.
        assert (
            await client.get(f"/v1/scim/v2/{slugs[org_a]}/Users/{admin_a}", headers=scim_a)
        ).status_code == 404
        assert (
            await client.delete(
                f"/v1/scim/v2/{slugs[org_a]}/Users/{admin_a}",
                headers=scim_a,
            )
        ).status_code == 404
        before = await client.get(f"/v1/scim/v2/{slugs[org_a]}/Users", headers=scim_a)
        assert before.status_code == 200
        assert before.json()["Resources"] == []

        # A second active SCIM provider is rejected deterministically instead
        # of making inbound authentication ambiguous.
        second = await client.post(
            "/v1/idp",
            headers=a,
            json={"provider_type": "scim", "display_name": "SCIM A duplicate"},
        )
        assert second.status_code == 201
        second_id = second.json()["id"]
        assert (
            await client.patch(
                f"/v1/idp/{second_id}",
                headers=a,
                json={"status": "active"},
            )
        ).json()["detail"] == "scim_token_required_before_activation"
        assert (await client.post(f"/v1/idp/{second_id}/scim-token", headers=a)).status_code == 200
        conflict = await client.patch(
            f"/v1/idp/{second_id}",
            headers=a,
            json={"status": "active"},
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"] == "active_scim_idp_already_exists"

        # A token is valid only for its URL tenant. Auth failures retain the
        # SCIM error contract so enterprise IdPs can parse them.
        cross = await client.get(f"/v1/scim/v2/{slugs[org_a]}/Users", headers=scim_b)
        assert cross.status_code == 401
        assert cross.headers["content-type"].startswith("application/scim+json")
        assert cross.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]

        created = await client.post(
            f"/v1/scim/v2/{slugs[org_a]}/Users",
            headers=scim_a,
            json={
                "schemas": [SCHEMA_USER],
                "userName": "provisioned-a@example.com",
                "name": {"formatted": "Provisioned A"},
                "active": True,
            },
        )
        assert created.status_code == 201, created.text
        provisioned_id = created.json()["id"]
        group = await client.post(
            f"/v1/scim/v2/{slugs[org_a]}/Groups",
            headers=scim_a,
            json={
                "schemas": [SCHEMA_GROUP],
                "displayName": "Security",
                "members": [
                    {"value": provisioned_id},
                    {"value": str(admin_a)},
                ],
            },
        )
        assert group.status_code == 201, group.text
        assert {member["value"] for member in group.json()["members"]} == {provisioned_id}
        a_users = await client.get(f"/v1/scim/v2/{slugs[org_a]}/Users", headers=scim_a)
        assert [row["userName"] for row in a_users.json()["Resources"]] == [
            "provisioned-a@example.com"
        ]
        user_path = f"/v1/scim/v2/{slugs[org_a]}/Users/{provisioned_id}"
        assert (await client.get(user_path, headers=scim_a)).status_code == 200
        patched_user = await client.patch(
            user_path,
            headers=scim_a,
            json={
                "schemas": [SCHEMA_PATCH_OP],
                "Operations": [{"op": "replace", "path": "active", "value": False}],
            },
        )
        assert patched_user.status_code == 200
        assert patched_user.json()["active"] is False
        replaced_user = await client.put(
            user_path,
            headers=scim_a,
            json={
                "schemas": [SCHEMA_USER],
                "userName": "provisioned-a@example.com",
                "name": {"formatted": "Provisioned A Updated"},
                "active": True,
            },
        )
        assert replaced_user.status_code == 200
        assert replaced_user.json()["active"] is True
        assert replaced_user.json()["name"]["formatted"] == "Provisioned A Updated"

        group_path = f"/v1/scim/v2/{slugs[org_a]}/Groups/Security"
        assert (await client.get(group_path, headers=scim_a)).status_code == 200
        groups = await client.get(f"/v1/scim/v2/{slugs[org_a]}/Groups", headers=scim_a)
        assert [row["displayName"] for row in groups.json()["Resources"]] == ["Security"]
        patched_group = await client.patch(
            group_path,
            headers=scim_a,
            json={
                "schemas": [SCHEMA_PATCH_OP],
                "Operations": [
                    {
                        "op": "replace",
                        "path": "members",
                        "value": [{"value": provisioned_id}],
                    }
                ],
            },
        )
        assert patched_group.status_code == 200
        assert {member["value"] for member in patched_group.json()["members"]} == {provisioned_id}
        assert (await client.delete(group_path, headers=scim_a)).status_code == 204
        assert (await client.get(group_path, headers=scim_a)).status_code == 404

        service_config = await client.get(
            f"/v1/scim/v2/{slugs[org_a]}/ServiceProviderConfig",
            headers=scim_a,
        )
        resource_types = await client.get(
            f"/v1/scim/v2/{slugs[org_a]}/ResourceTypes",
            headers=scim_a,
        )
        assert service_config.status_code == resource_types.status_code == 200
        assert service_config.headers["content-type"].startswith("application/scim+json")
        assert resource_types.json()["totalResults"] == 2

        # B's valid token and endpoint still cannot resolve A's user id, while
        # B's list contains none of A's identity data.
        assert (
            await client.get(
                f"/v1/scim/v2/{slugs[org_b]}/Users/{provisioned_id}",
                headers=scim_b,
            )
        ).status_code == 404
        b_users = await client.get(f"/v1/scim/v2/{slugs[org_b]}/Users", headers=scim_b)
        assert b_users.status_code == 200
        assert "provisioned-a@example.com" not in {
            row["userName"] for row in b_users.json()["Resources"]
        }

        assert (await client.delete(user_path, headers=scim_a)).status_code == 204
        deactivated = await client.get(user_path, headers=scim_a)
        assert deactivated.status_code == 200
        assert deactivated.json()["active"] is False

        malformed = await client.post(
            f"/v1/scim/v2/{slugs[org_a]}/Users",
            headers={
                **scim_a,
                "Content-Type": "application/scim+json",
            },
            content="{",
        )
        assert malformed.status_code == 400
        assert malformed.headers["content-type"].startswith("application/scim+json")
        assert malformed.json()["scimType"] == "invalidSyntax"

    async with SessionLocal() as db:
        endpoint = (
            await db.execute(select(IdpConfig.scim_config).where(IdpConfig.id == uuid.UUID(idp_a)))
        ).scalar_one()
        local_admin = (await db.execute(select(User).where(User.id == admin_a))).scalar_one()
    assert endpoint["endpoint_url"] == f"/v1/scim/v2/{slugs[org_a]}"
    assert local_admin.is_active is True
    assert local_admin.idp_groups == []
    assert {
        "user.provisioned",
        "user.updated",
        "user.deprovisioned",
        "group.membership.updated",
    }.issubset(audit_events)


async def test_aibom_is_org_scoped(app_client, two_orgs) -> None:
    """aibom endpoints load the asset by (id, org_id), so org B cannot inspect
    org A's asset through any of them — 404, not 403 (GAP-001 part 2, Tier A)."""
    import uuid as _uuid

    from app.db.models.ai_asset import AIAsset
    from app.db.models.connector import Connector

    org_a, org_b = two_orgs
    a = {"Authorization": f"Bearer {_token(org_a)}"}
    b = {"Authorization": f"Bearer {_token(org_b)}"}

    connector_id, asset_id = _uuid.uuid4(), _uuid.uuid4()
    async with SessionLocal() as db:
        db.add(
            Connector(
                id=connector_id,
                org_id=org_a,
                name="a-conn",
                connector_type="mock",
                config_encrypted={},
                is_enabled=True,
            )
        )
        db.add(
            AIAsset(
                id=asset_id,
                org_id=org_a,
                name="a-asset",
                asset_type="agent",
                provider="openai",
                external_id=f"ext-{asset_id.hex[:8]}",
                connector_id=connector_id,
                metadata_json={"is_agentic": True, "tools": ["x"]},
            )
        )
        await db.commit()

    async with app_client as client:
        # Org A sees every aibom view of its asset.
        for suffix in ("", "/risk", "/drift", "/blast-radius"):
            assert (await client.get(f"/v1/aibom/{asset_id}{suffix}", headers=a)).status_code == 200

        # Org B is 404 on every one — existence not disclosed.
        for suffix in ("", "/risk", "/drift", "/blast-radius"):
            assert (await client.get(f"/v1/aibom/{asset_id}{suffix}", headers=b)).status_code == 404


async def test_mcp_is_org_scoped(app_client, two_orgs) -> None:
    """MCP surface (Tier A) is org-scoped across all three tables: a custom tool
    profile, an inspected call, and its violation, all created in org A, are
    invisible to org B — B sees only built-in profiles, empty violations/chain,
    and 404 (not 403) on A's profile by id."""
    org_a, org_b = two_orgs
    a = {"Authorization": f"Bearer {_token(org_a)}"}
    b = {"Authorization": f"Bearer {_token(org_b)}"}

    # Seed A's custom profile (created_by a real A user — NOT NULL FK).
    creator, pid = uuid.uuid4(), uuid.uuid4()
    async with SessionLocal() as db:
        db.add(
            User(
                id=creator,
                org_id=org_a,
                email=f"a-{creator.hex[:8]}@x.io",
                name="A",
                role="admin",
                idp_groups=[],
            )
        )
        await db.flush()
        db.add(
            McpToolProfile(
                id=pid,
                org_id=org_a,
                tool_name="secret_tool",
                access_mode="read",
                description="",
                allowed_params=["q"],
                forbidden_params=["DROP"],
                param_constraints={},
                created_by=creator,
            )
        )
        await db.commit()

    async with app_client as client:
        # A inspects a malicious call — materializes a call + violation in A.
        await client.post(
            "/v1/mcp/inspect",
            headers=a,
            json={
                "session_id": "a-sess",
                "agent_id": "ag",
                "tool_name": "secret_tool",
                "params": {"query": "DROP TABLE t"},
            },
        )

        # A sees its own data (positive control).
        a_tools = (await client.get("/v1/mcp/tools", headers=a)).json()
        assert any(t["tool_name"] == "secret_tool" for t in a_tools)
        assert (await client.get("/v1/mcp/violations", headers=a)).json()
        assert len((await client.get("/v1/mcp/chain/a-sess", headers=a)).json()) == 1

        # B sees NONE of A's data.
        b_tools = (await client.get("/v1/mcp/tools", headers=b)).json()
        assert not any(t["tool_name"] == "secret_tool" for t in b_tools)
        assert (await client.get("/v1/mcp/violations", headers=b)).json() == []
        assert (await client.get("/v1/mcp/chain/a-sess", headers=b)).json() == []

        # B cannot touch A's profile by id — 404, not 403 (existence not disclosed).
        assert (
            await client.patch(f"/v1/mcp/tools/{pid}", headers=b, json={"description": "x"})
        ).status_code == 404
        assert (await client.delete(f"/v1/mcp/tools/{pid}", headers=b)).status_code == 404
