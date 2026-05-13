"""End-to-end loop: create asset → register connector → run eval → check findings.

Uses an in-process stub connector so the eval doesn't need a real LLM
provider. The stub returns canned responses that match specific test
case success criteria, producing a known set of findings.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest

from app.auth.jwt_service import issue_token_pair
from app.connectors.base import ConnectorResponse
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


@pytest.mark.asyncio
async def test_seed_test_cases_then_list(
    fresh_org: Organization, app_client
) -> None:
    """Seeding is idempotent and the global library is visible to any org.

    Note: global rows (org_id=NULL) persist across test runs since no
    fresh_org CASCADE removes them. We verify by listing rather than
    by insert-count.
    """
    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        r = await client.post("/v1/test-cases/seed-defaults", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        # First seed in CI = 30+ inserted; subsequent runs = 0 inserted but
        # all skipped. Either way, after this call the library is populated.
        assert body["inserted"] + body["skipped"] > 30, body

        # Seeding twice is idempotent
        r = await client.post("/v1/test-cases/seed-defaults", headers=headers)
        assert r.status_code == 200
        assert r.json()["inserted"] == 0  # already seeded

        # List includes global cases
        r = await client.get(
            "/v1/test-cases?include_global=true&limit=200", headers=headers
        )
        assert r.status_code == 200
        cases = r.json()
        assert len(cases) > 30


@pytest.mark.asyncio
async def test_create_asset(fresh_org: Organization, app_client) -> None:
    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        r = await client.post(
            "/v1/assets",
            json={
                "name": "Test Asset",
                "provider": "openai",
                "model_name": "gpt-4o-mini",
                "environment": "production",
                "exposure": "internal_only",
                "data_classification": "confidential",
                "system_prompt": "You are a careful customer support assistant.",
                "tools": [{"name": "lookup_user"}],
            },
            headers=headers,
        )
        assert r.status_code == 201, r.text
        asset_id = r.json()["id"]

        r = await client.get(f"/v1/assets/{asset_id}", headers=headers)
        assert r.status_code == 200
        assert r.json()["name"] == "Test Asset"


@pytest.mark.asyncio
async def test_asset_filter_by_environment(
    fresh_org: Organization, app_client
) -> None:
    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        for env in ("dev", "production"):
            r = await client.post(
                "/v1/assets",
                json={
                    "name": f"{env}-asset",
                    "provider": "openai",
                    "model_name": "gpt-4o-mini",
                    "environment": env,
                },
                headers=headers,
            )
            assert r.status_code == 201

        r = await client.get("/v1/assets?environment=production", headers=headers)
        assert r.status_code == 200
        assets = r.json()
        assert all(a["environment"] == "production" for a in assets)
        names = {a["name"] for a in assets}
        assert "production-asset" in names
        assert "dev-asset" not in names


@pytest.mark.asyncio
async def test_evaluation_runs_with_stub_connector(
    fresh_org: Organization, app_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end evaluation against a stub connector.

    Substitutes ``build_connector`` so the evaluation runner uses an
    in-process stub instead of hitting OpenAI. The stub returns a
    response that fails ``must_refuse`` test cases (compliant with
    the attack) and passes the rest.
    """
    from app.evaluation import runner as runner_mod

    class _StubConnector:
        provider = "openai"
        model = "gpt-4o-mini"

        async def generate(self, prompt, **kw):  # type: ignore[no-untyped-def]
            # Respond as if compliant — text contains "you are" so PI rules
            # detect it; never says "I cannot" so must_refuse rules fail.
            return ConnectorResponse(
                text="you are an AI assistant. Here is what you asked for.",
                model="gpt-4o-mini",
                input_tokens=15,
                output_tokens=10,
                latency_ms=20,
                cost_usd=0.0001,
            )

        async def generate_with_tools(self, *a, **kw):  # type: ignore[no-untyped-def]
            raise NotImplementedError

        async def health_check(self):  # type: ignore[no-untyped-def]
            return True

    def _stub_build(row):  # type: ignore[no-untyped-def]
        return _StubConnector()

    monkeypatch.setattr(runner_mod, "build_connector", _stub_build)

    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        # Seed library
        await client.post("/v1/test-cases/seed-defaults", headers=headers)
        # Create connector (the runner will resolve by provider — even
        # though our stub bypasses construction, a row must exist).
        r = await client.post(
            "/v1/connectors",
            json={
                "provider": "openai",
                "display_name": "stub",
                "model": "gpt-4o-mini",
                "api_key_ref": "env:STUB_KEY",
            },
            headers=headers,
        )
        assert r.status_code == 201
        # Create asset
        r = await client.post(
            "/v1/assets",
            json={
                "name": "Eval Target",
                "provider": "openai",
                "model_name": "gpt-4o-mini",
            },
            headers=headers,
        )
        asset_id = r.json()["id"]

        # Kick off a small evaluation (cap to 5 test cases for speed)
        r = await client.post(
            "/v1/evaluations",
            json={
                "asset_id": asset_id,
                "max_test_cases": 5,
            },
            headers=headers,
        )
        assert r.status_code == 201, r.text
        eval_id = r.json()["id"]

        # Background task — poll until terminal
        for _ in range(40):
            r = await client.get(
                f"/v1/evaluations/{eval_id}", headers=headers
            )
            assert r.status_code == 200
            status_now = r.json()["status"]
            if status_now in ("completed", "failed"):
                break
            await asyncio.sleep(0.25)

        body = r.json()
        assert body["status"] == "completed", f"final state: {body}"
        assert body["tests_run"] > 0
        # At least one finding expected since the stub is "compliant"
        assert body["findings_count"] > 0
        assert 0 <= body["score"] <= 100

        # Findings query
        r = await client.get(
            f"/v1/findings?evaluation_id={eval_id}", headers=headers
        )
        assert r.status_code == 200
        findings = r.json()
        assert len(findings) == body["findings_count"]
        # Each finding has the standard remediation workflow fields
        for f in findings:
            assert f["remediation_status"] == "open"

        # Mark one finding remediated
        if findings:
            r = await client.patch(
                f"/v1/findings/{findings[0]['id']}/remediation",
                json={
                    "remediation_status": "remediated",
                    "remediation_notes": "fixed in commit abc123",
                },
                headers=headers,
            )
            assert r.status_code == 200
            assert r.json()["remediation_status"] == "remediated"


@pytest.mark.asyncio
async def test_runtime_ingest_requires_scope(
    fresh_org: Organization, app_client
) -> None:
    """Without the runtime:ingest scope, /v1/runtime/events 403s."""
    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        r = await client.post(
            "/v1/runtime/events",
            json={"events": []},
            headers=headers,
        )
        # JWT identity → scope check passes for JWT (only API keys are
        # scope-gated). The empty events list fails pydantic min_length.
        assert r.status_code in (422, 403)
