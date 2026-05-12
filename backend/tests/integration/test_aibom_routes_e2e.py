"""AI-BOM routes integration tests against live PG."""

from __future__ import annotations

import uuid

import pytest

from app.auth.jwt_service import issue_token_pair
from app.db.models.ai_asset import AIAsset
from app.db.models.organization import Organization
from app.db.models.user import User
from app.db.session import SessionLocal

pytestmark = pytest.mark.integration


async def _admin_headers(org: Organization) -> dict[str, str]:
    user = User(
        id=uuid.uuid4(),
        org_id=org.id,
        email=f"u-{uuid.uuid4().hex[:6]}@example.com",
        name="Admin",
        role="admin",
        idp_groups=[],
    )
    async with SessionLocal() as db:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    pair = await issue_token_pair(
        org_id=org.id, user_id=user.id, role="admin", auth_method="oidc"
    )
    return {"Authorization": f"Bearer {pair.access_token}"}


async def _make_asset(org_id: uuid.UUID, **overrides) -> AIAsset:
    base = {
        "id": uuid.uuid4(),
        "org_id": org_id,
        "name": "Test AI",
        "provider": "openai",
        "model_name": "gpt-4o",
        "environment": "production",
        "exposure": "customer_facing",
        "data_classification": "confidential",
        "tools": [{"name": "lookup_user"}, {"name": "send_email"}],
        "rag_sources": [{"name": "internal-docs", "data_classification": "internal"}],
        "mcp_servers": [],
        "plugins": [],
        "fine_tuning": {},
        "regulatory_scope": [],
        "dependencies": [],
        "data_lineage": [],
        "upstream_services": [],
        "downstream_consumers": [],
        "allowed_external_actions": [],
        "tags": [],
        "change_log": [],
        "connector_config": {},
    }
    base.update(overrides)
    asset = AIAsset(**base)
    async with SessionLocal() as db:
        db.add(asset)
        await db.commit()
        await db.refresh(asset)
    return asset


@pytest.mark.asyncio
async def test_get_bom(fresh_org: Organization, app_client) -> None:
    asset = await _make_asset(fresh_org.id)
    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        r = await client.get(f"/v1/aibom/{asset.id}", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["asset_id"] == str(asset.id)
        node_types = {n["type"] for n in body["nodes"]}
        assert "asset" in node_types
        assert "provider" in node_types
        assert "model" in node_types
        assert "tool" in node_types
        assert "rag_source" in node_types


@pytest.mark.asyncio
async def test_get_risk(fresh_org: Organization, app_client) -> None:
    asset = await _make_asset(
        fresh_org.id,
        data_classification="regulated",
        exposure="public",
        is_agentic=True,
        blast_radius_score=70.0,
    )
    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        r = await client.get(f"/v1/aibom/{asset.id}/risk", headers=headers)
        assert r.status_code == 200
        body = r.json()
        assert 0 <= body["score"] <= 100
        # Specific high-risk config should produce a high score
        assert body["score"] > 30
        # Every component returns with a non-empty name
        names = {c["name"] for c in body["components"]}
        assert "provider_trust" in names
        assert "exposure" in names
        assert "agentic_blast_radius" in names


@pytest.mark.asyncio
async def test_drift_no_history_treats_as_first_snapshot(
    fresh_org: Organization, app_client
) -> None:
    """An asset with an empty change_log → baseline is None → drift report
    shows all set fields as new."""
    asset = await _make_asset(fresh_org.id, change_log=[])
    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        r = await client.get(f"/v1/aibom/{asset.id}/drift", headers=headers)
        assert r.status_code == 200
        body = r.json()
        # First-snapshot — every set field is "added"
        assert body["changed"] is True
        # No high+ severity changes unless we set high-severity fields;
        # we did set system_prompt=None and tools=[...] in defaults, so
        # at least 'tools' should show up
        change_fields = {c["field"] for c in body["changes"]}
        assert "model_name" in change_fields


@pytest.mark.asyncio
async def test_drift_with_change_log_baseline(
    fresh_org: Organization, app_client
) -> None:
    """The change_log records old values. compute_drift reconstructs the
    baseline by undoing the log entries."""
    asset = await _make_asset(
        fresh_org.id,
        system_prompt="You are helpful.",
        model_name="gpt-4o",
        change_log=[
            {
                "timestamp": "2026-04-01T00:00:00Z",
                "field": "system_prompt",
                "old_value": "Original prompt",
                "new_value": "You are helpful.",
                "changed_by": "admin",
            },
            {
                "timestamp": "2026-05-01T00:00:00Z",
                "field": "model_name",
                "old_value": "gpt-3.5-turbo",
                "new_value": "gpt-4o",
                "changed_by": "admin",
            },
        ],
    )
    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        # Without a baseline_change_log_index, the default is the most-
        # recent entry (index 1) — meaning the baseline is "the snapshot
        # AFTER both changes were applied" → no drift detected for the
        # last logged change. Let's compare against index 0 instead so
        # we see the model_name change.
        r = await client.get(
            f"/v1/aibom/{asset.id}/drift?baseline_change_log_index=0",
            headers=headers,
        )
        assert r.status_code == 200
        body = r.json()
        change_fields = {c["field"] for c in body["changes"]}
        assert "model_name" in change_fields


@pytest.mark.asyncio
async def test_cross_org_isolation(fresh_org: Organization, app_client) -> None:
    """An asset from org A is invisible to org B."""
    asset = await _make_asset(fresh_org.id)

    other = Organization(
        id=uuid.uuid4(), name="Other", slug=f"other-{uuid.uuid4().hex[:6]}"
    )
    async with SessionLocal() as db:
        db.add(other)
        await db.commit()

    try:
        headers_b = await _admin_headers(other)
        async with app_client as client:
            r = await client.get(f"/v1/aibom/{asset.id}", headers=headers_b)
            assert r.status_code == 404
    finally:
        from sqlalchemy import text

        async with SessionLocal() as db:
            await db.execute(
                text("DELETE FROM organizations WHERE id = :id"), {"id": other.id}
            )
            await db.commit()
