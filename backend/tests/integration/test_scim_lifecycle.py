"""SCIM provisioning lifecycle against a live database.

SCIM is how the customer's IdP tells the platform who works there. The
lifecycle it drives — provision, promote, demote, deprovision — is the
platform's only automatic path for *removing* access, so the failure that
matters is the quiet one: an operation that returns 200 and changes nothing.

What these tests hold:

  * **Deprovisioning deactivates and never hard-deletes.** SCIM DELETE means
    "this person left"; dropping the row would take the audit trail and the
    historical findings with it. The user must remain, inactive.
  * **Role follows group membership, in both directions.** A promotion that
    lands but a demotion that does not is a privilege ratchet — the case is
    asserted explicitly, not just the promotion.
  * **The IdP boundary is the tenancy boundary.** Every read and write is
    scoped by both ``org_id`` *and* ``idp_config_id``. A second IdP in the
    same org must not see or mutate the first one's users, or a customer with
    two directories has a cross-directory takeover.
  * **Malformed input is refused with the right SCIM status.** 400 for
    invalid, 409 for uniqueness, 404 for absent, 501 for syntax we do not
    implement. An IdP retries on some of these and gives up on others, so
    collapsing them changes what the customer's directory does.

Emails here are ``@example.test`` literals; nothing logs a token or a body.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, text

from app.db.models.idp_config import IdpConfig
from app.db.models.user import User
from app.db.session import SessionLocal
from app.scim import groups as scim_groups
from app.scim import users as scim_users
from app.scim.types import SCHEMA_GROUP, SCHEMA_PATCH_OP, SCHEMA_USER, SCIMError

pytestmark = pytest.mark.integration

GROUP_TO_ROLE = {
    "platform-admins": "admin",
    "security-analysts": "analyst",
}


def _user_payload(email: str, **overrides):
    payload = {
        "schemas": [SCHEMA_USER],
        "userName": email,
        "name": {"givenName": "Ada", "familyName": "Lovelace"},
        "emails": [{"value": email, "primary": True}],
        "active": True,
    }
    payload.update(overrides)
    return payload


def _patch(*operations):
    return {"schemas": [SCHEMA_PATCH_OP], "Operations": list(operations)}


async def _new_idp(
    org_id: uuid.UUID, *, name: str = "primary", status: str = "active"
) -> IdpConfig:
    idp = IdpConfig(
        id=uuid.uuid4(),
        org_id=org_id,
        provider_type="scim",
        display_name=name,
        status=status,
        saml_config={},
        oidc_config={},
        scim_config={"auto_provision": True, "sync_groups": True},
        directory_sync={"group_to_role_mapping": GROUP_TO_ROLE, "default_role": "viewer"},
        verification_status={},
    )
    async with SessionLocal() as db:
        db.add(idp)
        await db.commit()
        await db.refresh(idp)
    return idp


@pytest.fixture
async def idp(test_org: uuid.UUID) -> IdpConfig:
    return await _new_idp(test_org)


@pytest.fixture
async def second_idp(test_org: uuid.UUID) -> IdpConfig:
    """A second directory mid-migration.

    Migration 0011 enforces at most one *active* SCIM provider per org (see
    ``TestActiveScimIntegrity``), so the incoming directory is staged as
    ``pending_verification`` — which is exactly the window in which a
    cross-directory mistake would do damage.
    """
    return await _new_idp(test_org, name="secondary", status="pending_verification")


async def _load_user(user_id: uuid.UUID) -> User | None:
    async with SessionLocal() as db:
        return (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()


async def _count_users(org_id: uuid.UUID) -> int:
    async with SessionLocal() as db:
        return (
            await db.execute(text("SELECT count(*) FROM users WHERE org_id = :o"), {"o": org_id})
        ).scalar_one()


class TestProvisioning:
    async def test_create_persists_a_user_scoped_to_the_org_and_idp(self, test_org, idp):
        async with SessionLocal() as db:
            created = await scim_users.create_user(
                db, _user_payload("ada@example.test"), org_id=test_org, idp=idp
            )

        assert created["userName"] == "ada@example.test"
        assert created["active"] is True
        assert created["name"]["formatted"] == "Ada Lovelace"

        row = await _load_user(uuid.UUID(created["id"]))
        assert row is not None
        assert row.org_id == test_org
        assert row.idp_config_id == idp.id

    async def test_the_default_role_is_applied_when_no_group_maps(self, test_org, idp):
        async with SessionLocal() as db:
            created = await scim_users.create_user(
                db, _user_payload("plain@example.test"), org_id=test_org, idp=idp
            )

        assert (await _load_user(uuid.UUID(created["id"]))).role == "viewer"

    async def test_group_membership_at_creation_sets_the_role(self, test_org, idp):
        payload = _user_payload(
            "boss@example.test",
            groups=[{"value": "platform-admins", "display": "platform-admins"}],
        )

        async with SessionLocal() as db:
            created = await scim_users.create_user(db, payload, org_id=test_org, idp=idp)

        assert (await _load_user(uuid.UUID(created["id"]))).role == "admin"

    async def test_a_missing_user_schema_is_rejected(self, test_org, idp):
        payload = _user_payload("x@example.test")
        payload["schemas"] = []

        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_users.create_user(db, payload, org_id=test_org, idp=idp)

        assert excinfo.value.status == 400
        assert excinfo.value.scimType == "invalidValue"
        assert await _count_users(test_org) == 0

    async def test_a_missing_username_is_rejected(self, test_org, idp):
        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_users.create_user(
                    db, {"schemas": [SCHEMA_USER], "active": True}, org_id=test_org, idp=idp
                )

        assert excinfo.value.status == 400
        assert await _count_users(test_org) == 0

    @pytest.mark.parametrize(
        "username", ["", "   ", "x" * 321], ids=["empty", "whitespace", "too-long"]
    )
    async def test_an_out_of_bounds_username_is_rejected_and_writes_nothing(
        self, test_org, idp, username
    ):
        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_users.create_user(db, _user_payload(username), org_id=test_org, idp=idp)

        assert excinfo.value.status == 400
        assert await _count_users(test_org) == 0

    async def test_an_oversized_display_name_is_rejected(self, test_org, idp):
        payload = _user_payload(
            "long@example.test", displayName="N" * 300, name={"formatted": "N" * 300}
        )

        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_users.create_user(db, payload, org_id=test_org, idp=idp)

        assert excinfo.value.status == 400
        assert await _count_users(test_org) == 0

    async def test_a_duplicate_username_in_the_same_org_is_a_conflict(self, test_org, idp):
        """409 with scimType=uniqueness is what tells the IdP to stop retrying."""
        async with SessionLocal() as db:
            await scim_users.create_user(
                db, _user_payload("dupe@example.test"), org_id=test_org, idp=idp
            )

        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_users.create_user(
                    db, _user_payload("dupe@example.test"), org_id=test_org, idp=idp
                )

        assert excinfo.value.status == 409
        assert excinfo.value.scimType == "uniqueness"
        assert await _count_users(test_org) == 1

    async def test_unknown_fields_are_ignored_rather_than_rejected(self, test_org, idp):
        """IdPs push extensions we do not model; refusing them breaks provisioning."""
        payload = _user_payload(
            "extra@example.test",
            **{
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                    "department": "Security"
                },
                "nickName": "Ada",
                "unmodelled": {"deeply": {"nested": True}},
            },
        )

        async with SessionLocal() as db:
            created = await scim_users.create_user(db, payload, org_id=test_org, idp=idp)

        assert created["userName"] == "extra@example.test"

    async def test_a_client_supplied_id_does_not_choose_the_primary_key(self, test_org, idp):
        forged = uuid.uuid4()
        payload = _user_payload("forge@example.test", id=str(forged))

        async with SessionLocal() as db:
            created = await scim_users.create_user(db, payload, org_id=test_org, idp=idp)

        assert created["id"] != str(forged)


class TestDeprovisioning:
    async def test_delete_deactivates_and_keeps_the_row(self, test_org, idp):
        """A hard delete would take the audit trail and historical findings."""
        async with SessionLocal() as db:
            created = await scim_users.create_user(
                db, _user_payload("leaver@example.test"), org_id=test_org, idp=idp
            )
        user_id = uuid.UUID(created["id"])

        async with SessionLocal() as db:
            await scim_users.delete_user(db, user_id, org_id=test_org, idp=idp)

        row = await _load_user(user_id)
        assert row is not None, "SCIM DELETE must not destroy the record"
        assert row.is_active is False

    async def test_patch_active_false_deactivates(self, test_org, idp):
        async with SessionLocal() as db:
            created = await scim_users.create_user(
                db, _user_payload("offboard@example.test"), org_id=test_org, idp=idp
            )
        user_id = uuid.UUID(created["id"])

        async with SessionLocal() as db:
            patched = await scim_users.patch_user(
                db,
                user_id,
                _patch({"op": "replace", "path": "active", "value": False}),
                org_id=test_org,
                idp=idp,
            )

        assert patched["active"] is False
        assert (await _load_user(user_id)).is_active is False

    async def test_azure_style_pathless_replace_also_deactivates(self, test_org, idp):
        async with SessionLocal() as db:
            created = await scim_users.create_user(
                db, _user_payload("azure@example.test"), org_id=test_org, idp=idp
            )
        user_id = uuid.UUID(created["id"])

        async with SessionLocal() as db:
            await scim_users.patch_user(
                db,
                user_id,
                _patch({"op": "replace", "value": {"active": False}}),
                org_id=test_org,
                idp=idp,
            )

        assert (await _load_user(user_id)).is_active is False

    async def test_reactivation_is_possible(self, test_org, idp):
        async with SessionLocal() as db:
            created = await scim_users.create_user(
                db, _user_payload("rehire@example.test"), org_id=test_org, idp=idp
            )
        user_id = uuid.UUID(created["id"])

        async with SessionLocal() as db:
            await scim_users.delete_user(db, user_id, org_id=test_org, idp=idp)
        async with SessionLocal() as db:
            await scim_users.patch_user(
                db,
                user_id,
                _patch({"op": "replace", "path": "active", "value": True}),
                org_id=test_org,
                idp=idp,
            )

        assert (await _load_user(user_id)).is_active is True

    async def test_deleting_an_unknown_user_is_404(self, test_org, idp):
        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_users.delete_user(db, uuid.uuid4(), org_id=test_org, idp=idp)

        assert excinfo.value.status == 404


class TestRoleFollowsGroups:
    async def test_adding_a_mapped_group_promotes(self, test_org, idp):
        async with SessionLocal() as db:
            created = await scim_users.create_user(
                db, _user_payload("promote@example.test"), org_id=test_org, idp=idp
            )
        user_id = uuid.UUID(created["id"])
        assert (await _load_user(user_id)).role == "viewer"

        async with SessionLocal() as db:
            await scim_users.patch_user(
                db,
                user_id,
                _patch(
                    {
                        "op": "replace",
                        "path": "groups",
                        "value": [{"value": "platform-admins"}],
                    }
                ),
                org_id=test_org,
                idp=idp,
            )

        assert (await _load_user(user_id)).role == "admin"

    async def test_removing_the_group_demotes_again(self, test_org, idp):
        """A promotion that sticks after the group is gone is a privilege ratchet."""
        payload = _user_payload("demote@example.test", groups=[{"value": "platform-admins"}])
        async with SessionLocal() as db:
            created = await scim_users.create_user(db, payload, org_id=test_org, idp=idp)
        user_id = uuid.UUID(created["id"])
        assert (await _load_user(user_id)).role == "admin"

        async with SessionLocal() as db:
            await scim_users.patch_user(
                db,
                user_id,
                _patch({"op": "replace", "path": "groups", "value": []}),
                org_id=test_org,
                idp=idp,
            )

        assert (await _load_user(user_id)).role == "viewer"

    async def test_an_unmapped_group_does_not_grant_anything(self, test_org, idp):
        payload = _user_payload("nobody@example.test", groups=[{"value": "everyone"}])

        async with SessionLocal() as db:
            created = await scim_users.create_user(db, payload, org_id=test_org, idp=idp)

        assert (await _load_user(uuid.UUID(created["id"]))).role == "viewer"

    async def test_replace_recomputes_the_role_from_the_new_groups(self, test_org, idp):
        async with SessionLocal() as db:
            created = await scim_users.create_user(
                db, _user_payload("swap@example.test"), org_id=test_org, idp=idp
            )
        user_id = uuid.UUID(created["id"])

        async with SessionLocal() as db:
            replaced = await scim_users.replace_user(
                db,
                user_id,
                _user_payload("swap@example.test", groups=[{"value": "security-analysts"}]),
                org_id=test_org,
                idp=idp,
            )

        assert replaced["userName"] == "swap@example.test"
        assert (await _load_user(user_id)).role == "analyst"


class TestPatchFailureModes:
    @pytest.fixture
    async def provisioned(self, test_org, idp):
        async with SessionLocal() as db:
            created = await scim_users.create_user(
                db, _user_payload("subject@example.test"), org_id=test_org, idp=idp
            )
        return uuid.UUID(created["id"])

    async def test_a_value_filtered_path_is_501_not_a_silent_broad_write(
        self, test_org, idp, provisioned
    ):
        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_users.patch_user(
                    db,
                    provisioned,
                    _patch(
                        {
                            "op": "replace",
                            "path": 'emails[type eq "work"].value',
                            "value": "new@example.test",
                        }
                    ),
                    org_id=test_org,
                    idp=idp,
                )

        assert excinfo.value.status == 501
        assert excinfo.value.scimType == "invalidPath"

    @pytest.mark.parametrize(
        "patch_doc",
        [
            {"Operations": [{"op": "replace", "path": "active", "value": False}]},
            {"schemas": [SCHEMA_PATCH_OP], "Operations": []},
            {"schemas": [SCHEMA_PATCH_OP], "Operations": [{"op": "move", "path": "active"}]},
            {"schemas": [SCHEMA_PATCH_OP], "Operations": [{"op": "remove"}]},
        ],
        ids=["no-schema", "no-operations", "unsupported-op", "remove-without-path"],
    )
    async def test_a_malformed_patch_is_400_and_changes_nothing(
        self, test_org, idp, provisioned, patch_doc
    ):
        before = await _load_user(provisioned)

        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_users.patch_user(db, provisioned, patch_doc, org_id=test_org, idp=idp)

        assert excinfo.value.status == 400
        after = await _load_user(provisioned)
        assert (after.is_active, after.role, after.email) == (
            before.is_active,
            before.role,
            before.email,
        )

    async def test_blanking_username_alone_cannot_orphan_the_account(
        self, test_org, idp, provisioned
    ):
        """The primary ``emails`` entry outranks ``userName``.

        An account whose email went blank could never be matched again by the
        directory on the next sync, and could never be deprovisioned. The
        surviving emails array is what prevents that here.
        """
        async with SessionLocal() as db:
            patched = await scim_users.patch_user(
                db,
                provisioned,
                _patch({"op": "replace", "path": "userName", "value": ""}),
                org_id=test_org,
                idp=idp,
            )

        assert patched["userName"] == "subject@example.test"
        assert (await _load_user(provisioned)).email == "subject@example.test"

    async def test_blanking_both_username_and_emails_is_rejected(self, test_org, idp, provisioned):
        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_users.patch_user(
                    db,
                    provisioned,
                    _patch(
                        {"op": "replace", "path": "userName", "value": ""},
                        {"op": "replace", "path": "emails", "value": []},
                    ),
                    org_id=test_org,
                    idp=idp,
                )

        assert excinfo.value.status == 400
        assert (await _load_user(provisioned)).email == "subject@example.test"

    async def test_patching_an_unknown_user_is_404(self, test_org, idp):
        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_users.patch_user(
                    db,
                    uuid.uuid4(),
                    _patch({"op": "replace", "path": "active", "value": False}),
                    org_id=test_org,
                    idp=idp,
                )

        assert excinfo.value.status == 404


class TestActiveScimIntegrity:
    async def test_an_org_cannot_have_two_active_scim_providers(self, test_org, idp):
        """Two active directories would race each other's deprovisioning.

        Migration 0011 enforces this in the database rather than the service
        layer, so it also holds for writes that bypass the API.
        """
        from sqlalchemy.exc import IntegrityError

        with pytest.raises(IntegrityError):
            await _new_idp(test_org, name="rival", status="active")

    async def test_a_staged_provider_is_allowed_alongside_the_active_one(self, test_org, idp):
        staged = await _new_idp(test_org, name="incoming", status="pending_verification")
        assert staged.id != idp.id


class TestIdpAndTenantScoping:
    async def test_a_second_idp_cannot_read_the_first_ones_user(self, test_org, idp, second_idp):
        async with SessionLocal() as db:
            created = await scim_users.create_user(
                db, _user_payload("theirs@example.test"), org_id=test_org, idp=idp
            )
        user_id = uuid.UUID(created["id"])

        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_users.get_user(db, user_id, org_id=test_org, idp=second_idp)

        assert excinfo.value.status == 404

    async def test_a_second_idp_cannot_deprovision_the_first_ones_user(
        self, test_org, idp, second_idp
    ):
        """Two directories in one org must not be able to offboard each other."""
        async with SessionLocal() as db:
            created = await scim_users.create_user(
                db, _user_payload("protected@example.test"), org_id=test_org, idp=idp
            )
        user_id = uuid.UUID(created["id"])

        with pytest.raises(SCIMError):
            async with SessionLocal() as db:
                await scim_users.delete_user(db, user_id, org_id=test_org, idp=second_idp)

        assert (await _load_user(user_id)).is_active is True

    async def test_listing_is_scoped_to_the_authenticated_idp(self, test_org, idp, second_idp):
        async with SessionLocal() as db:
            await scim_users.create_user(
                db, _user_payload("first@example.test"), org_id=test_org, idp=idp
            )
            await scim_users.create_user(
                db, _user_payload("second@example.test"), org_id=test_org, idp=second_idp
            )

        async with SessionLocal() as db:
            listing = await scim_users.list_users(db, org_id=test_org, idp=idp)

        assert listing["totalResults"] == 1
        assert listing["Resources"][0]["userName"] == "first@example.test"

    async def test_a_foreign_org_cannot_read_the_user(self, test_org, idp):
        other_org = uuid.uuid4()
        async with SessionLocal() as db:
            await db.execute(
                text("INSERT INTO organizations (id, name, slug) VALUES (:i, :n, :s)"),
                {"i": other_org, "n": "other", "s": f"scim-other-{other_org.hex[:8]}"},
            )
            await db.commit()
        try:
            async with SessionLocal() as db:
                created = await scim_users.create_user(
                    db, _user_payload("mine@example.test"), org_id=test_org, idp=idp
                )

            with pytest.raises(SCIMError) as excinfo:
                async with SessionLocal() as db:
                    await scim_users.get_user(
                        db, uuid.UUID(created["id"]), org_id=other_org, idp=idp
                    )

            assert excinfo.value.status == 404
        finally:
            async with SessionLocal() as db:
                await db.execute(text("DELETE FROM organizations WHERE id = :i"), {"i": other_org})
                await db.commit()


class TestListing:
    @pytest.fixture
    async def population(self, test_org, idp):
        async with SessionLocal() as db:
            for i in range(3):
                await scim_users.create_user(
                    db, _user_payload(f"u{i}@example.test"), org_id=test_org, idp=idp
                )
        return idp

    async def test_pagination_reports_total_and_page_size_separately(self, test_org, population):
        async with SessionLocal() as db:
            page = await scim_users.list_users(
                db, org_id=test_org, idp=population, start_index=1, count=2
            )

        assert page["totalResults"] == 3, "totalResults is the match count, not the page"
        assert page["itemsPerPage"] == 2
        assert len(page["Resources"]) == 2

    async def test_a_start_index_past_the_end_yields_an_empty_page(self, test_org, population):
        async with SessionLocal() as db:
            page = await scim_users.list_users(
                db, org_id=test_org, idp=population, start_index=99, count=10
            )

        assert page["Resources"] == []
        assert page["totalResults"] == 3

    @pytest.mark.parametrize(
        ("start_index", "count"),
        [(0, 10), (-1, 10), (1, -1)],
        ids=["zero", "negative", "neg-count"],
    )
    async def test_invalid_pagination_is_rejected(self, test_org, population, start_index, count):
        """SCIM startIndex is 1-based; accepting 0 would silently skip a user."""
        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_users.list_users(
                    db, org_id=test_org, idp=population, start_index=start_index, count=count
                )

        assert excinfo.value.status == 400

    async def test_a_filter_narrows_the_result_set(self, test_org, population):
        async with SessionLocal() as db:
            page = await scim_users.list_users(
                db,
                org_id=test_org,
                idp=population,
                filter_expr='userName eq "u1@example.test"',
            )

        assert page["totalResults"] == 1
        assert page["Resources"][0]["userName"] == "u1@example.test"

    async def test_an_invalid_filter_is_400(self, test_org, population):
        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_users.list_users(
                    db, org_id=test_org, idp=population, filter_expr="userName eq"
                )

        assert excinfo.value.status == 400
        assert excinfo.value.scimType == "invalidFilter"


class TestGroups:
    async def test_creating_a_group_adds_the_name_to_each_listed_member(self, test_org, idp):
        async with SessionLocal() as db:
            member = await scim_users.create_user(
                db, _user_payload("member@example.test"), org_id=test_org, idp=idp
            )

        async with SessionLocal() as db:
            group = await scim_groups.create_group(
                db,
                {
                    "schemas": [SCHEMA_GROUP],
                    "displayName": "platform-admins",
                    "members": [{"value": member["id"]}],
                },
                org_id=test_org,
                idp=idp,
            )

        assert group["displayName"] == "platform-admins"
        row = await _load_user(uuid.UUID(member["id"]))
        assert "platform-admins" in row.idp_groups
        assert row.role == "admin", "group membership must recompute the role"

    async def test_a_missing_group_schema_is_rejected(self, test_org, idp):
        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_groups.create_group(db, {"displayName": "x"}, org_id=test_org, idp=idp)

        assert excinfo.value.status == 400

    @pytest.mark.parametrize("display_name", ["", None, 42, "N" * 256])
    async def test_an_invalid_display_name_is_rejected(self, test_org, idp, display_name):
        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_groups.create_group(
                    db,
                    {"schemas": [SCHEMA_GROUP], "displayName": display_name},
                    org_id=test_org,
                    idp=idp,
                )

        assert excinfo.value.status == 400

    async def test_members_must_be_a_list(self, test_org, idp):
        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_groups.create_group(
                    db,
                    {"schemas": [SCHEMA_GROUP], "displayName": "g", "members": "not-a-list"},
                    org_id=test_org,
                    idp=idp,
                )

        assert excinfo.value.status == 400

    @pytest.mark.parametrize(
        "member", [{"value": "not-a-uuid"}, {"value": ""}, {}, "a string", 42, None]
    )
    async def test_a_malformed_member_entry_is_skipped_not_fatal(self, test_org, idp, member):
        """One bad row from an IdP must not fail the whole group push."""
        async with SessionLocal() as db:
            group = await scim_groups.create_group(
                db,
                {
                    "schemas": [SCHEMA_GROUP],
                    "displayName": "resilient-group",
                    "members": [member],
                },
                org_id=test_org,
                idp=idp,
            )

        assert group["displayName"] == "resilient-group"

    async def test_a_member_from_another_idp_is_not_added(self, test_org, idp, second_idp):
        async with SessionLocal() as db:
            foreign = await scim_users.create_user(
                db, _user_payload("foreign@example.test"), org_id=test_org, idp=second_idp
            )

        async with SessionLocal() as db:
            await scim_groups.create_group(
                db,
                {
                    "schemas": [SCHEMA_GROUP],
                    "displayName": "platform-admins",
                    "members": [{"value": foreign["id"]}],
                },
                org_id=test_org,
                idp=idp,
            )

        row = await _load_user(uuid.UUID(foreign["id"]))
        assert row.idp_groups == []
        assert row.role == "viewer", "a foreign IdP must not be able to grant admin"

    async def test_get_group_lists_its_members(self, test_org, idp):
        async with SessionLocal() as db:
            member = await scim_users.create_user(
                db,
                _user_payload("in@example.test", groups=[{"value": "security-analysts"}]),
                org_id=test_org,
                idp=idp,
            )
            await scim_users.create_user(
                db, _user_payload("out@example.test"), org_id=test_org, idp=idp
            )

        async with SessionLocal() as db:
            group = await scim_groups.get_group(db, "security-analysts", org_id=test_org, idp=idp)

        assert [m["value"] for m in group["members"]] == [member["id"]]

    async def test_an_empty_group_is_404(self, test_org, idp):
        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_groups.get_group(db, "nobody-is-here", org_id=test_org, idp=idp)

        assert excinfo.value.status == 404

    async def test_listing_groups_enumerates_distinct_names(self, test_org, idp):
        async with SessionLocal() as db:
            await scim_users.create_user(
                db,
                _user_payload("a@example.test", groups=[{"value": "platform-admins"}]),
                org_id=test_org,
                idp=idp,
            )
            await scim_users.create_user(
                db,
                _user_payload(
                    "b@example.test",
                    groups=[{"value": "platform-admins"}, {"value": "security-analysts"}],
                ),
                org_id=test_org,
                idp=idp,
            )

        async with SessionLocal() as db:
            listing = await scim_groups.list_groups(db, org_id=test_org, idp=idp)

        names = {g["displayName"] for g in listing["Resources"]}
        assert names == {"platform-admins", "security-analysts"}
        assert listing["totalResults"] == 2

    async def test_patching_a_group_adds_and_removes_members(self, test_org, idp):
        async with SessionLocal() as db:
            staying = await scim_users.create_user(
                db,
                _user_payload("stay@example.test", groups=[{"value": "platform-admins"}]),
                org_id=test_org,
                idp=idp,
            )
            leaving = await scim_users.create_user(
                db,
                _user_payload("leave@example.test", groups=[{"value": "platform-admins"}]),
                org_id=test_org,
                idp=idp,
            )
            joining = await scim_users.create_user(
                db, _user_payload("join@example.test"), org_id=test_org, idp=idp
            )

        async with SessionLocal() as db:
            await scim_groups.patch_group(
                db,
                "platform-admins",
                _patch(
                    {
                        "op": "replace",
                        "path": "members",
                        "value": [{"value": staying["id"]}, {"value": joining["id"]}],
                    }
                ),
                org_id=test_org,
                idp=idp,
            )

        assert (await _load_user(uuid.UUID(joining["id"]))).role == "admin"
        left = await _load_user(uuid.UUID(leaving["id"]))
        assert "platform-admins" not in left.idp_groups
        assert left.role == "viewer", "removal from an admin group must demote"
        assert (await _load_user(uuid.UUID(staying["id"]))).role == "admin"

    async def test_a_group_patch_with_a_filtered_path_is_501(self, test_org, idp):
        async with SessionLocal() as db:
            await scim_users.create_user(
                db,
                _user_payload("g@example.test", groups=[{"value": "platform-admins"}]),
                org_id=test_org,
                idp=idp,
            )

        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_groups.patch_group(
                    db,
                    "platform-admins",
                    _patch({"op": "remove", "path": 'members[value eq "x"]'}),
                    org_id=test_org,
                    idp=idp,
                )

        assert excinfo.value.status == 501

    async def test_deleting_a_group_removes_it_everywhere_and_demotes(self, test_org, idp):
        async with SessionLocal() as db:
            created = await scim_users.create_user(
                db,
                _user_payload("gone@example.test", groups=[{"value": "platform-admins"}]),
                org_id=test_org,
                idp=idp,
            )
        user_id = uuid.UUID(created["id"])

        async with SessionLocal() as db:
            await scim_groups.delete_group(db, "platform-admins", org_id=test_org, idp=idp)

        row = await _load_user(user_id)
        assert row.idp_groups == []
        assert row.role == "viewer"
        assert row.is_active is True, "deleting a group must not deactivate its members"

    async def test_deleting_an_unknown_group_is_404(self, test_org, idp):
        with pytest.raises(SCIMError) as excinfo:
            async with SessionLocal() as db:
                await scim_groups.delete_group(db, "never-existed", org_id=test_org, idp=idp)

        assert excinfo.value.status == 404
