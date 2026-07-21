"""SIEM exporter admin API — HTTP contract through the MOUNTED app (GAP-001).

These drive the router as ``create_app`` mounts it: tier registry, middleware,
auth dependencies, and the RLS-wired DB session all in the path. That is the
point — the 12 validator unit tests in ``test_siem_write_path_gating`` prove the
gate's fine-grained logic, but only a request through the mounted app proves the
gate fires with auth, org-scoping and the real ``Organization.settings`` column
behind it. "The thing we test is the thing we ship" applies to mounting too.

Postgres-backed (org rows are real), so these run in CI and skip locally without
a database — same as the other integration tests.
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


def _token(org_id: uuid.UUID, role: str = "admin") -> str:
    s = get_settings()
    now = datetime.now(UTC)
    claims = {
        "iss": "ai-security-platform",
        "sub": str(uuid.uuid4()),
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
async def org():
    org_id = uuid.uuid4()
    async with SessionLocal() as db:
        db.add(Organization(id=org_id, name="siem-org", slug=f"siem-{uuid.uuid4().hex[:8]}"))
        await db.commit()
    yield org_id
    async with SessionLocal() as db:
        await db.execute(text("DELETE FROM organizations WHERE id = :id"), {"id": org_id})
        await db.commit()


def _splunk(name: str = "prod") -> dict:
    return {
        "type": "splunk_hec",
        "name": name,
        "config": {"url": "https://splunk.example.com", "token": "env:SPLUNK_TOKEN"},
    }


# ─────────────────────────────────────────── the happy path, end to end


async def test_create_list_update_delete(app_client, org, monkeypatch) -> None:
    # The create path RESOLVES the secret ref (it must actually exist), so the
    # env var the ref points at has to be set — a real behaviour worth knowing.
    monkeypatch.setenv("SPLUNK_TOKEN", "test-splunk-token")
    admin = {"Authorization": f"Bearer {_token(org)}"}

    async with app_client as client:
        # create
        resp = await client.post("/v1/siem/exporters", headers=admin, json=_splunk())
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["type"] == "splunk_hec"
        assert body["enabled"] is True
        assert body["config_redacted"]["token"] == "***", "the secret ref must be redacted on read"

        # list
        listed = (await client.get("/v1/siem/exporters", headers=admin)).json()
        assert [e["name"] for e in listed] == ["prod"]

        # update: disable it (the always-allowed write) and confirm it sticks
        resp = await client.put(
            "/v1/siem/exporters/prod", headers=admin, json={**_splunk(), "enabled": False}
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["enabled"] is False

        # delete
        resp = await client.delete("/v1/siem/exporters/prod", headers=admin)
        assert resp.status_code == 204, resp.text
        assert (await client.get("/v1/siem/exporters", headers=admin)).json() == []


# ─────────────────────────────────────────── the tier gate, through HTTP


async def test_gated_type_rejected_on_create(app_client, org) -> None:
    """The write-path gate, fired through the mounted router rather than the
    validator in isolation. Sentinel is Tier C; without the flag it is a 400."""
    admin = {"Authorization": f"Bearer {_token(org)}"}
    sentinel = {
        "type": "sentinel",
        "name": "sec",
        "config": {"workspace_id": "w", "shared_key": "env:SENTINEL_KEY"},
    }

    async with app_client as client:
        resp = await client.post("/v1/siem/exporters", headers=admin, json=sentinel)

    assert resp.status_code == 400, resp.text
    assert "PLATFORM_ENABLE_SIEM_EXTENDED" in resp.json()["detail"]


async def test_gated_type_rejected_on_create_even_when_disabled(app_client, org) -> None:
    """No create carve-out: enabled=false is not a way to stage a gated exporter
    on a flag-off deployment. This is the exact hole #65's review closed, now
    proven at the HTTP boundary."""
    admin = {"Authorization": f"Bearer {_token(org)}"}
    sentinel = {
        "type": "sentinel",
        "name": "sec",
        "enabled": False,
        "config": {"workspace_id": "w", "shared_key": "env:SENTINEL_KEY"},
    }

    async with app_client as client:
        resp = await client.post("/v1/siem/exporters", headers=admin, json=sentinel)

    assert resp.status_code == 400, resp.text


async def test_unknown_type_is_422_at_the_boundary(app_client, org) -> None:
    """ExporterType is a Literal, so pydantic rejects an unknown type with 422
    BEFORE the tier validator runs. Documented in siem.py; asserted here so the
    'unknown-type 400 is unreachable via HTTP' claim stays true."""
    admin = {"Authorization": f"Bearer {_token(org)}"}

    async with app_client as client:
        resp = await client.post(
            "/v1/siem/exporters",
            headers=admin,
            json={"type": "splunk_hecc", "name": "typo", "config": {}},
        )

    assert resp.status_code == 422, resp.text


async def test_raw_secret_rejected(app_client, org) -> None:
    """Secret-bearing fields must be references, never raw values in the JSONB."""
    admin = {"Authorization": f"Bearer {_token(org)}"}
    raw = {
        "type": "splunk_hec",
        "name": "leak",
        "config": {"url": "https://x", "token": "s3cr3t-literal"},
    }

    async with app_client as client:
        resp = await client.post("/v1/siem/exporters", headers=admin, json=raw)

    assert resp.status_code == 400, resp.text


# ─────────────────────────────────────────── auth negative paths


async def test_unauthenticated_is_401(app_client, org) -> None:
    async with app_client as client:
        resp = await client.get("/v1/siem/exporters")
    assert resp.status_code == 401, resp.text


async def test_viewer_role_is_forbidden(app_client, org) -> None:
    """Exporter config is admin-only; a viewer token must be 403, not 200."""
    viewer = {"Authorization": f"Bearer {_token(org, role='viewer')}"}
    async with app_client as client:
        resp = await client.get("/v1/siem/exporters", headers=viewer)
    assert resp.status_code == 403, resp.text
