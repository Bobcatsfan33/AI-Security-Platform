"""aibom HTTP contract through the MOUNTED app (Tier A, GAP-001 part 2).

The function is proven separately in test_aibom_function.py; this proves the
endpoints deliver it through create_app — tier registry, auth, RLS-wired
session in the path. Tier A means the higher bar: the blast-radius endpoint is a
headline claim, so the tests assert on the REASONS it returns, not just that it
returns 200.

Postgres-backed; runs in CI, skips locally without a database.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import jwt
import pytest
import pytest_asyncio
from sqlalchemy import text

from app.core.config import get_settings
from app.db.models.ai_asset import AIAsset
from app.db.models.connector import Connector
from app.db.models.organization import Organization
from app.db.session import SessionLocal

pytestmark = pytest.mark.integration


def _token(org_id: uuid.UUID, role: str = "viewer") -> str:
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
async def org_with_asset() -> AsyncIterator[tuple[uuid.UUID, uuid.UUID]]:
    """A real org + connector + one rich agentic asset. Yields (org_id, asset_id)."""
    org_id, connector_id, asset_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    async with SessionLocal() as db:
        db.add(Organization(id=org_id, name="aibom-api", slug=f"ab-{uuid.uuid4().hex[:8]}"))
        await db.flush()
        db.add(
            Connector(
                id=connector_id,
                org_id=org_id,
                name="c",
                connector_type="mock",
                config_encrypted={},
                is_enabled=True,
            )
        )
        db.add(
            AIAsset(
                id=asset_id,
                org_id=org_id,
                name="rich-agent",
                asset_type="agent",
                provider="openai",
                external_id=f"ext-{asset_id.hex[:8]}",
                connector_id=connector_id,
                metadata_json={
                    "is_agentic": True,
                    "human_in_loop_required": False,
                    "max_tool_calls_per_session": 500,
                    "tools": ["shell", "http"],
                    "mcp_servers": ["fs"],
                    "allowed_external_actions": ["send_email", "wire_transfer"],
                    "downstream_consumers": ["billing", "crm"],
                    "exposure": "public",
                    "data_classification": "restricted",
                },
            )
        )
        await db.commit()
    yield org_id, asset_id
    async with SessionLocal() as db:
        await db.execute(text("DELETE FROM organizations WHERE id = :id"), {"id": org_id})
        await db.commit()


@pytest_asyncio.fixture
async def org_with_bare_asset() -> AsyncIterator[tuple[uuid.UUID, uuid.UUID]]:
    """An asset with empty metadata_json — the honest-empty path."""
    org_id, connector_id, asset_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    async with SessionLocal() as db:
        db.add(Organization(id=org_id, name="aibom-bare", slug=f"ab-{uuid.uuid4().hex[:8]}"))
        await db.flush()
        db.add(
            Connector(
                id=connector_id, org_id=org_id, name="c", connector_type="mock",
                config_encrypted={}, is_enabled=True,
            )
        )
        db.add(
            AIAsset(
                id=asset_id, org_id=org_id, name="bare", asset_type="model",
                provider="openai", external_id=f"ext-{asset_id.hex[:8]}",
                connector_id=connector_id, metadata_json={},
            )
        )
        await db.commit()
    yield org_id, asset_id
    async with SessionLocal() as db:
        await db.execute(text("DELETE FROM organizations WHERE id = :id"), {"id": org_id})
        await db.commit()


# ─────────────────────────────────────────── every endpoint answers


async def test_all_four_endpoints_answer(app_client, org_with_asset) -> None:
    org_id, asset_id = org_with_asset
    h = {"Authorization": f"Bearer {_token(org_id)}"}

    async with app_client as client:
        for suffix in ("", "/risk", "/drift", "/blast-radius"):
            resp = await client.get(f"/v1/aibom/{asset_id}{suffix}", headers=h)
            assert resp.status_code == 200, f"{suffix}: {resp.text}"
            assert resp.json()["asset_id"] == str(asset_id)


async def test_blast_radius_returns_a_reasoned_decomposition(app_client, org_with_asset) -> None:
    """Tier A bar: the endpoint returns the basis, not just a number."""
    org_id, asset_id = org_with_asset
    h = {"Authorization": f"Bearer {_token(org_id)}"}

    async with app_client as client:
        body = (await client.get(f"/v1/aibom/{asset_id}/blast-radius", headers=h)).json()

    assert body["severity"] in ("high", "critical")
    assert 0.0 <= body["score"] <= 100.0
    names = {f["name"] for f in body["factors"]}
    assert {"tool_reach", "external_action_surface", "downstream_fanout", "autonomy"} <= names
    for f in body["factors"]:
        assert f["detail"], "every factor must carry the basis it was computed from"
    assert body["reach"]["downstream_consumers"] == ["billing", "crm"]


async def test_blast_radius_is_honest_on_an_empty_asset(app_client, org_with_bare_asset) -> None:
    """The Tier A honest-empty claim, over HTTP: a low radius whose factors state
    the absence — never a fabricated number."""
    org_id, asset_id = org_with_bare_asset
    h = {"Authorization": f"Bearer {_token(org_id)}"}

    async with app_client as client:
        body = (await client.get(f"/v1/aibom/{asset_id}/blast-radius", headers=h)).json()

    assert body["severity"] == "low"
    reasons = {f["name"]: f["detail"] for f in body["factors"]}
    assert reasons["tool_reach"] == "no tool grants recorded"
    assert reasons["downstream_fanout"] == "no downstream connections known"
    assert body["reach"]["downstream_consumers"] == []


async def test_blast_radius_is_deterministic_over_http(app_client, org_with_asset) -> None:
    org_id, asset_id = org_with_asset
    h = {"Authorization": f"Bearer {_token(org_id)}"}

    async with app_client as client:
        a = (await client.get(f"/v1/aibom/{asset_id}/blast-radius", headers=h)).json()
        b = (await client.get(f"/v1/aibom/{asset_id}/blast-radius", headers=h)).json()

    assert a == b, "same asset, two calls — the number a design partner reruns must not move"


# ─────────────────────────────────────────── negative paths


async def test_unknown_asset_is_404(app_client, org_with_asset) -> None:
    org_id, _ = org_with_asset
    h = {"Authorization": f"Bearer {_token(org_id)}"}
    async with app_client as client:
        resp = await client.get(f"/v1/aibom/{uuid.uuid4()}/blast-radius", headers=h)
    assert resp.status_code == 404, resp.text


async def test_unauthenticated_is_401(app_client, org_with_asset) -> None:
    _, asset_id = org_with_asset
    async with app_client as client:
        resp = await client.get(f"/v1/aibom/{asset_id}/blast-radius")
    assert resp.status_code == 401, resp.text


@pytest_asyncio.fixture
async def org_with_malformed_asset() -> AsyncIterator[tuple[uuid.UUID, uuid.UUID]]:
    """An asset whose metadata_json is operator-shaped garbage: string-where-list,
    bool-where-int, non-dict-in-list, non-numeric scalar. None of it must 500."""
    org_id, connector_id, asset_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    async with SessionLocal() as db:
        db.add(Organization(id=org_id, name="aibom-bad", slug=f"ab-{uuid.uuid4().hex[:8]}"))
        await db.flush()
        db.add(
            Connector(
                id=connector_id, org_id=org_id, name="c", connector_type="mock",
                config_encrypted={}, is_enabled=True,
            )
        )
        db.add(
            AIAsset(
                id=asset_id, org_id=org_id, name="bad", asset_type="agent",
                provider="openai", external_id=f"ext-{asset_id.hex[:8]}",
                connector_id=connector_id,
                metadata_json={
                    "is_agentic": "false",  # truthy string
                    "human_in_loop_required": "false",
                    "max_tool_calls_per_session": True,  # bool where int
                    "tools": "shell",  # string where list
                    "mcp_servers": "fs",
                    "regulatory_scope": "gdpr",  # string where list
                    "downstream_consumers": ["ok", 123, {"nested": "x"}],  # mixed
                    "blast_radius_score": "not-a-number",  # non-numeric scalar
                    "exposure": "dmz",  # present but unmapped
                    "rag_sources": "single",
                    "data_lineage": {"not": "a list"},
                    "change_log": "totally-not-a-list",  # non-list log
                },
            )
        )
        await db.commit()
    yield org_id, asset_id
    async with SessionLocal() as db:
        await db.execute(text("DELETE FROM organizations WHERE id = :id"), {"id": org_id})
        await db.commit()


async def test_no_endpoint_500s_on_malformed_metadata(app_client, org_with_malformed_asset) -> None:
    """Malformed operator data is a client-data condition, not a server error.
    Every aibom endpoint must answer 200 — the pre-hardening bugs (float() on a
    string, .get on a non-dict change_log entry) were 500s."""
    org_id, asset_id = org_with_malformed_asset
    h = {"Authorization": f"Bearer {_token(org_id)}"}

    async with app_client as client:
        for suffix in ("", "/risk", "/drift", "/blast-radius"):
            resp = await client.get(f"/v1/aibom/{asset_id}{suffix}", headers=h)
            assert resp.status_code == 200, f"{suffix} 500'd on malformed data: {resp.text}"


async def test_malformed_blast_radius_fabricates_nothing(app_client, org_with_malformed_asset) -> None:
    """The Tier A honesty claim under garbage input: nothing is invented. The
    truthy-string is_agentic does not score agentic; 'shell' is not 5 tools; the
    bool budget is not a budget; the unmapped exposure says unrecognised."""
    org_id, asset_id = org_with_malformed_asset
    h = {"Authorization": f"Bearer {_token(org_id)}"}

    async with app_client as client:
        body = (await client.get(f"/v1/aibom/{asset_id}/blast-radius", headers=h)).json()

    assert body["reach"]["autonomy"]["is_agentic"] is False
    assert body["reach"]["tool_reach"]["tools"] == 0
    assert body["reach"]["autonomy"]["max_tool_calls_per_session"] is None
    assert body["containment"] == [] or "human-in-the-loop" not in " ".join(body["containment"])
    reasons = {f["name"]: f["detail"] for f in body["factors"]}
    assert "not a boolean" in reasons["autonomy"]
    assert "not a recognised level" in reasons["exposure"]
