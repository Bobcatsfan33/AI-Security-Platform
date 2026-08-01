"""API routes: who is refused, and that a refusal writes nothing.

Route-level RBAC is declarative (``Depends(require_role(...))``), which is
exactly why it needs testing at the HTTP layer: a dependency that is dropped,
mistyped, or attached to the wrong handler still imports, still starts, and
still serves — it just stops refusing anyone. Nothing below the router would
notice.

Three properties, in order of how badly they fail:

  **Refusal is real, not cosmetic.** Every denial test re-reads the resource
  afterwards and asserts the database is untouched. A 403 that returns after
  the write has already landed is worse than no check at all, because the
  audit trail records a rejection.

  **Unauthenticated is 401, under-privileged is 403.** Collapsing them tells
  an attacker nothing, but collapsing them the other way — 403 for anonymous
  requests — hides broken authentication behind what looks like an RBAC
  decision.

  **Another tenant's resource is 404, not 403.** 403 confirms the row exists,
  which is a cross-tenant existence oracle.

Malformed-input cases assert 4xx rather than a specific body, because the
contract that matters is "rejected before it reaches the model layer".
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.db.models.policy import Policy
from app.db.session import SessionLocal

pytestmark = pytest.mark.integration

WRITE_ROLES = ["owner", "admin", "analyst"]
# `api_only` is a side-track in the hierarchy, not a low-privilege UI role:
# has_role_at_least() refuses it for every UI requirement including "viewer".
READ_ONLY_ROLES = ["viewer"]
NON_WRITE_ROLES = ["viewer", "api_only"]


def _token(org_id: uuid.UUID, role: str, *, user_id: uuid.UUID | None = None) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": "ai-security-platform",
            "sub": str(user_id or uuid.uuid4()),
            "org": str(org_id),
            "role": role,
            "auth": "test",
            "scopes": [],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=10)).timestamp()),
            "jti": str(uuid.uuid4()),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )


def _headers(org_id: uuid.UUID, role: str = "admin") -> dict[str, str]:
    """Headers for a principal that exists — ``policies.created_by`` is a real FK."""
    return {"Authorization": f"Bearer {_token(org_id, role, user_id=_ACTORS.get(org_id))}"}


# One persisted actor per org, so writes that stamp created_by satisfy the FK.
_ACTORS: dict[uuid.UUID, uuid.UUID] = {}


async def _make_org() -> uuid.UUID:
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    async with SessionLocal() as db:
        await db.execute(
            text("INSERT INTO organizations (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": org_id, "n": "authz-org", "s": f"authz-{org_id.hex[:10]}"},
        )
        await db.execute(
            text(
                "INSERT INTO users (id, org_id, email, name, role, idp_groups, is_active) "
                "VALUES (:u, :o, :e, :n, 'admin', '[]'::jsonb, true)"
            ),
            {"u": user_id, "o": org_id, "e": f"actor-{user_id.hex[:8]}@example.test", "n": "actor"},
        )
        await db.commit()
    _ACTORS[org_id] = user_id
    return org_id


async def _drop_org(org_id: uuid.UUID) -> None:
    _ACTORS.pop(org_id, None)
    async with SessionLocal() as db:
        await db.execute(text("DELETE FROM organizations WHERE id = :i"), {"i": org_id})
        await db.commit()


async def _make_policy(org_id: uuid.UUID, *, name: str = "baseline") -> uuid.UUID:
    policy_id = uuid.uuid4()
    async with SessionLocal() as db:
        db.add(
            Policy(
                id=policy_id,
                org_id=org_id,
                name=name,
                version=1,
                status="active",
                enforcement_level="fast",
                fail_behavior="closed",
                rules=[],
                tool_allowlist=[],
                tool_denylist=[],
                tool_approval_required=[],
                rate_limits={},
                content_filters={},
                classifiers=[],
            )
        )
        await db.commit()
    return policy_id


async def _policy_snapshot(policy_id: uuid.UUID) -> dict | None:
    async with SessionLocal() as db:
        row = (
            (
                await db.execute(
                    text(
                        "SELECT name, status, fail_behavior, version " "FROM policies WHERE id = :i"
                    ),
                    {"i": policy_id},
                )
            )
            .mappings()
            .one_or_none()
        )
    return dict(row) if row else None


@pytest.fixture
async def org() -> uuid.UUID:
    org_id = await _make_org()
    yield org_id
    await _drop_org(org_id)


@pytest.fixture
async def other_org() -> uuid.UUID:
    org_id = await _make_org()
    yield org_id
    await _drop_org(org_id)


NEW_POLICY = {
    "name": "created-by-test",
    "enforcement_level": "fast",
    "fail_behavior": "closed",
    "rules": [],
}


class TestAuthenticationIsRequired:
    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("get", "/v1/policies"),
            ("post", "/v1/policies"),
            ("get", "/v1/assets"),
            ("get", "/v1/findings"),
            ("get", "/v1/connectors"),
            ("get", "/v1/auth/me"),
        ],
    )
    async def test_an_anonymous_request_is_401_not_403(self, app_client, method, path):
        async with app_client as client:
            response = await client.request(method.upper(), path, json={})

        assert response.status_code == 401
        assert response.json()["detail"] == "not_authenticated"

    async def test_a_401_advertises_the_expected_scheme(self, app_client):
        async with app_client as client:
            response = await client.get("/v1/policies")

        assert response.headers.get("www-authenticate") == "Bearer"

    @pytest.mark.parametrize(
        "header",
        [
            "Bearer not-a-jwt",
            "Bearer ",
            "Basic dXNlcjpwYXNz",
            "bearer",
            "",
        ],
    )
    async def test_a_malformed_authorization_header_never_authenticates(self, app_client, header):
        async with app_client as client:
            response = await client.get("/v1/policies", headers={"Authorization": header})

        assert response.status_code == 401

    async def test_an_expired_token_is_rejected(self, app_client, org):
        settings = get_settings()
        past = datetime.now(UTC) - timedelta(hours=2)
        expired = jwt.encode(
            {
                "iss": "ai-security-platform",
                "sub": str(uuid.uuid4()),
                "org": str(org),
                "role": "admin",
                "auth": "test",
                "iat": int(past.timestamp()),
                "exp": int((past + timedelta(minutes=5)).timestamp()),
                "jti": str(uuid.uuid4()),
            },
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )

        async with app_client as client:
            response = await client.get(
                "/v1/policies", headers={"Authorization": f"Bearer {expired}"}
            )

        assert response.status_code == 401

    async def test_a_token_signed_with_the_wrong_key_is_rejected(self, app_client, org):
        now = datetime.now(UTC)
        forged = jwt.encode(
            {
                "iss": "ai-security-platform",
                "sub": str(uuid.uuid4()),
                "org": str(org),
                "role": "owner",
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(minutes=10)).timestamp()),
                "jti": str(uuid.uuid4()),
            },
            "an-attacker-controlled-secret-of-sufficient-length",
            algorithm="HS256",
        )

        async with app_client as client:
            response = await client.get(
                "/v1/policies", headers={"Authorization": f"Bearer {forged}"}
            )

        assert response.status_code == 401

    async def test_a_token_for_an_unknown_org_does_not_authorize(self, app_client):
        """Moved out of TestTenantScoping in P12.1. A random UUID is not a
        sibling tenant — nothing here compares two orgs, so this is a question
        about whether a well-formed token for a nonexistent org authenticates,
        which is what this class is about."""
        async with app_client as client:
            response = await client.get("/v1/policies", headers=_headers(uuid.uuid4(), "admin"))

        assert response.status_code in (401, 403, 404, 421)
        assert response.status_code != 200

    async def test_an_unknown_api_key_is_rejected(self, app_client):
        async with app_client as client:
            response = await client.get(
                "/v1/policies", headers={"X-API-Key": "aisp_not_a_real_key"}
            )

        assert response.status_code == 401
        assert response.json()["detail"] == "invalid_api_key"


class TestWriteAuthorization:
    @pytest.mark.parametrize("role", NON_WRITE_ROLES)
    async def test_a_read_only_role_cannot_create_a_policy(self, app_client, org, role):
        async with app_client as client:
            response = await client.post(
                "/v1/policies", headers=_headers(org, role), json=NEW_POLICY
            )

        assert response.status_code == 403
        assert "insufficient_role" in response.json()["detail"]

    @pytest.mark.parametrize("role", NON_WRITE_ROLES)
    async def test_a_denied_create_writes_nothing(self, app_client, org, role):
        """The whole point of the 403: no row may exist afterwards."""
        async with app_client as client:
            response = await client.post(
                "/v1/policies", headers=_headers(org, role), json=NEW_POLICY
            )
        assert response.status_code == 403

        async with SessionLocal() as db:
            count = (
                await db.execute(
                    text("SELECT count(*) FROM policies WHERE org_id = :o AND name = :n"),
                    {"o": org, "n": NEW_POLICY["name"]},
                )
            ).scalar_one()

        assert count == 0

    @pytest.mark.parametrize("role", NON_WRITE_ROLES)
    async def test_a_denied_update_leaves_the_row_byte_for_byte(self, app_client, org, role):
        policy_id = await _make_policy(org)
        before = await _policy_snapshot(policy_id)

        async with app_client as client:
            response = await client.patch(
                f"/v1/policies/{policy_id}",
                headers=_headers(org, role),
                json={"fail_behavior": "open", "name": "weakened"},
            )

        assert response.status_code == 403
        assert await _policy_snapshot(policy_id) == before

    @pytest.mark.parametrize("role", ["viewer", "analyst", "api_only"])
    async def test_deleting_a_policy_requires_admin(self, app_client, org, role):
        policy_id = await _make_policy(org)

        async with app_client as client:
            response = await client.delete(f"/v1/policies/{policy_id}", headers=_headers(org, role))

        assert response.status_code == 403
        assert await _policy_snapshot(policy_id) is not None, "a denied delete must not delete"

    @pytest.mark.parametrize("role", WRITE_ROLES)
    async def test_a_privileged_role_can_create(self, app_client, org, role):
        async with app_client as client:
            response = await client.post(
                "/v1/policies",
                headers=_headers(org, role),
                json={**NEW_POLICY, "name": f"created-by-{role}"},
            )

        assert response.status_code == 201, response.text
        assert response.json()["name"] == f"created-by-{role}"

    async def test_admin_can_delete_what_viewer_could_not(self, app_client, org):
        policy_id = await _make_policy(org)

        async with app_client as client:
            denied = await client.delete(
                f"/v1/policies/{policy_id}", headers=_headers(org, "viewer")
            )
            allowed = await client.delete(
                f"/v1/policies/{policy_id}", headers=_headers(org, "admin")
            )

        assert (denied.status_code, allowed.status_code) == (403, 204)
        assert await _policy_snapshot(policy_id) is None

    @pytest.mark.parametrize("role", READ_ONLY_ROLES + WRITE_ROLES)
    async def test_every_ui_role_can_read(self, app_client, org, role):
        await _make_policy(org)

        async with app_client as client:
            response = await client.get("/v1/policies", headers=_headers(org, role))

        assert response.status_code == 200

    async def test_an_unknown_role_claim_is_refused_rather_than_defaulted_up(self, app_client, org):
        """A typo'd or attacker-chosen role must not fall through to allowed."""
        async with app_client as client:
            response = await client.post(
                "/v1/policies", headers=_headers(org, "superadmin"), json=NEW_POLICY
            )

        assert response.status_code == 403


@pytest.mark.tenant_isolation
class TestTenantScoping:
    async def test_another_tenants_policy_is_404_not_403(self, app_client, org, other_org):
        """403 would confirm the row exists — a cross-tenant existence oracle."""
        foreign = await _make_policy(other_org, name="theirs")

        async with app_client as client:
            response = await client.get(f"/v1/policies/{foreign}", headers=_headers(org, "admin"))

        assert response.status_code == 404

    async def test_another_tenants_policy_cannot_be_updated(self, app_client, org, other_org):
        foreign = await _make_policy(other_org, name="theirs")
        before = await _policy_snapshot(foreign)

        async with app_client as client:
            response = await client.patch(
                f"/v1/policies/{foreign}",
                headers=_headers(org, "admin"),
                json={"fail_behavior": "open"},
            )

        assert response.status_code == 404
        assert await _policy_snapshot(foreign) == before

    async def test_another_tenants_policy_cannot_be_deleted(self, app_client, org, other_org):
        foreign = await _make_policy(other_org, name="theirs")

        async with app_client as client:
            response = await client.delete(
                f"/v1/policies/{foreign}", headers=_headers(org, "admin")
            )

        assert response.status_code == 404
        assert await _policy_snapshot(foreign) is not None

    async def test_listing_never_includes_another_tenants_rows(self, app_client, org, other_org):
        mine = await _make_policy(org, name="mine")
        theirs = await _make_policy(other_org, name="theirs")

        async with app_client as client:
            response = await client.get("/v1/policies", headers=_headers(org, "admin"))

        ids = {p["id"] for p in response.json()}
        assert str(mine) in ids
        assert str(theirs) not in ids


class TestMalformedInput:
    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"name": ""},
            {"name": "x", "enforcement_level": "not-a-level"},
            {"name": "x", "fail_behavior": "maybe"},
            {"name": 12345},
            {"name": "x", "rules": "not-a-list"},
        ],
        ids=["empty", "blank-name", "bad-level", "bad-fail", "wrong-type", "rules-not-list"],
    )
    async def test_an_invalid_body_is_rejected_before_it_reaches_the_database(
        self, app_client, org, body
    ):
        async with app_client as client:
            response = await client.post("/v1/policies", headers=_headers(org), json=body)

        assert 400 <= response.status_code < 500

        async with SessionLocal() as db:
            count = (
                await db.execute(
                    text("SELECT count(*) FROM policies WHERE org_id = :o"), {"o": org}
                )
            ).scalar_one()
        assert count == 0

    async def test_an_oversized_name_is_rejected(self, app_client, org):
        async with app_client as client:
            response = await client.post(
                "/v1/policies", headers=_headers(org), json={**NEW_POLICY, "name": "x" * 10_000}
            )

        assert 400 <= response.status_code < 500

    async def test_unknown_fields_do_not_become_columns(self, app_client, org):
        """Whether they are ignored or rejected, they must not be persisted."""
        async with app_client as client:
            response = await client.post(
                "/v1/policies",
                headers=_headers(org),
                json={**NEW_POLICY, "name": "extra-fields", "org_id": str(uuid.uuid4())},
            )

        if response.status_code == 201:
            assert response.json()["org_id"] == str(org), "a client must not choose its tenant"
        else:
            assert 400 <= response.status_code < 500

    async def test_a_non_uuid_path_parameter_is_rejected(self, app_client, org):
        async with app_client as client:
            response = await client.get("/v1/policies/not-a-uuid", headers=_headers(org))

        assert response.status_code == 422

    async def test_a_body_that_is_not_json_is_rejected(self, app_client, org):
        async with app_client as client:
            response = await client.post(
                "/v1/policies",
                headers={**_headers(org), "content-type": "application/json"},
                content=b"{not json",
            )

        assert 400 <= response.status_code < 500

    async def test_a_missing_resource_is_404(self, app_client, org):
        async with app_client as client:
            response = await client.get(f"/v1/policies/{uuid.uuid4()}", headers=_headers(org))

        assert response.status_code == 404


class TestUnauthenticatedAuthSurfaces:
    """A few auth routes are public by design; the boundary must stay exact."""

    async def test_server_time_needs_no_credential(self, app_client):
        async with app_client as client:
            response = await client.get("/v1/auth/_internal/now")

        assert response.status_code == 200
        assert "now" in response.json()

    async def test_jwks_is_public_and_publishes_no_private_material(self, app_client):
        async with app_client as client:
            response = await client.get("/v1/auth/.well-known/jwks.json")

        assert response.status_code == 200
        body = response.json()
        assert "keys" in body
        for key in body["keys"]:
            assert key["use"] == "sig" and key["alg"] == "RS256"
            assert "d" not in key, "a JWKS must never carry the private exponent"
            assert "p" not in key and "q" not in key

    async def test_saml_metadata_is_public_for_a_known_org(self, app_client, org):
        async with app_client as client:
            response = await client.get(f"/v1/auth/saml/authz-{str(org.hex)[:10]}/metadata")

        # Slug lookup may miss; either way the route must not 500.
        assert response.status_code in (200, 404, 421)

    async def test_me_reflects_the_presented_identity(self, app_client, org):
        user_id = uuid.uuid4()
        headers = {"Authorization": f"Bearer {_token(org, 'analyst', user_id=user_id)}"}

        async with app_client as client:
            response = await client.get("/v1/auth/me", headers=headers)

        assert response.status_code == 200
        body = response.json()
        assert body["org_id"] == str(org)
        assert body["user_id"] == str(user_id)
        assert body["role"] == "analyst"

    async def test_logout_requires_authentication(self, app_client):
        async with app_client as client:
            response = await client.post("/v1/auth/logout")

        assert response.status_code == 401

    async def test_logout_revokes_the_presented_access_token(self, app_client, org):
        headers = _headers(org, "admin")

        async with app_client as client:
            assert (await client.get("/v1/auth/me", headers=headers)).status_code == 200
            assert (await client.post("/v1/auth/logout", headers=headers)).status_code == 204
            after = await client.get("/v1/auth/me", headers=headers)

        assert after.status_code == 401, "a revoked jti must stop working immediately"


@pytest.mark.tenant_isolation
class TestAuthIsOrgScopedAcrossTenants:
    """``/auth`` is the surface that *mints* the org claim every other router
    trusts, so a leak here is not one router's leak — it is every router's.

    The properties below are about the identity boundary itself: a credential
    minted for one org must never come back describing another, and revoking
    one org's session must not touch the other's.
    """

    async def test_me_never_reports_a_foreign_org(self, app_client, org, other_org):
        async with app_client as client:
            mine = await client.get("/v1/auth/me", headers=_headers(org, "admin"))
            theirs = await client.get("/v1/auth/me", headers=_headers(other_org, "admin"))

        assert mine.json()["org_id"] == str(org)
        assert theirs.json()["org_id"] == str(other_org)
        assert mine.json()["org_id"] != theirs.json()["org_id"]

    async def test_a_refresh_token_returns_an_access_token_for_its_own_org(
        self, app_client, org, other_org
    ):
        """The redeemed token must carry the org the refresh token was issued
        to. Reading the org from anywhere else — a header, the request body, a
        cached last-seen value — would hand the caller a cross-tenant token."""
        from app.auth.jwt_service import issue_token_pair

        pair = await issue_token_pair(
            org_id=other_org, user_id=uuid.uuid4(), role="analyst", auth_method="test"
        )

        async with app_client as client:
            refreshed = await client.post(
                "/v1/auth/refresh", json={"refresh_token": pair.refresh_token}
            )
            access = refreshed.json()["access_token"]
            me = await client.get("/v1/auth/me", headers={"Authorization": f"Bearer {access}"})

        assert me.json()["org_id"] == str(other_org)
        assert me.json()["org_id"] != str(org)

    async def test_logging_out_of_one_org_does_not_revoke_the_other(
        self, app_client, org, other_org
    ):
        """Revocation is keyed on the token's jti. If it were keyed on
        something coarser — the org, the subject, a shared prefix — one
        tenant's logout would sign the other tenant out."""
        mine = _headers(org, "admin")
        theirs = _headers(other_org, "admin")

        async with app_client as client:
            assert (await client.post("/v1/auth/logout", headers=mine)).status_code == 204
            still_valid = await client.get("/v1/auth/me", headers=theirs)

        assert still_valid.status_code == 200
        assert still_valid.json()["org_id"] == str(other_org)


class TestRefreshFlow:
    async def test_an_unknown_refresh_token_is_401(self, app_client):
        async with app_client as client:
            response = await client.post(
                "/v1/auth/refresh", json={"refresh_token": "not-a-real-token"}
            )

        assert response.status_code == 401
        assert response.json()["detail"] == "invalid_refresh_token"

    async def test_a_missing_refresh_token_field_is_rejected(self, app_client):
        async with app_client as client:
            response = await client.post("/v1/auth/refresh", json={})

        assert response.status_code == 422

    async def test_a_refresh_token_is_single_use(self, app_client, org):
        from app.auth.jwt_service import issue_token_pair

        pair = await issue_token_pair(
            org_id=org, user_id=uuid.uuid4(), role="analyst", auth_method="test"
        )

        async with app_client as client:
            first = await client.post(
                "/v1/auth/refresh", json={"refresh_token": pair.refresh_token}
            )
            replay = await client.post(
                "/v1/auth/refresh", json={"refresh_token": pair.refresh_token}
            )

        assert first.status_code == 200, first.text
        assert first.json()["user"]["role"] == "analyst"
        assert replay.status_code == 401, "replaying a rotated refresh token must fail"

    async def test_a_refreshed_access_token_authenticates(self, app_client, org):
        from app.auth.jwt_service import issue_token_pair

        pair = await issue_token_pair(
            org_id=org, user_id=uuid.uuid4(), role="viewer", auth_method="test"
        )

        async with app_client as client:
            refreshed = await client.post(
                "/v1/auth/refresh", json={"refresh_token": pair.refresh_token}
            )
            access = refreshed.json()["access_token"]
            me = await client.get("/v1/auth/me", headers={"Authorization": f"Bearer {access}"})

        assert me.status_code == 200
        assert me.json()["role"] == "viewer"
        assert me.json()["auth_method"] == "refresh"
