"""SCIM serializer tests — User <-> SCIM dict translation."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from app.scim.serializers import (
    _split_name,
    group_to_scim,
    scim_to_user_fields,
    user_to_scim,
)
from app.scim.types import SCHEMA_GROUP, SCHEMA_USER


def _user(**overrides: Any) -> SimpleNamespace:
    """Build a User-shaped namespace for serializer tests without hitting the DB."""
    now = datetime.now(timezone.utc)
    base = {
        "id": uuid.uuid4(),
        "email": "alice@example.com",
        "name": "Alice Liddell",
        "is_active": True,
        "idp_groups": ["Engineering", "Security"],
        "created_at": now,
        "updated_at": now,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.mark.unit
class TestUserToScim:
    def test_includes_user_schema(self) -> None:
        out = user_to_scim(_user())
        assert SCHEMA_USER in out["schemas"]

    def test_username_is_email(self) -> None:
        u = _user(email="bob@example.com")
        assert user_to_scim(u)["userName"] == "bob@example.com"

    def test_active_flag_propagates(self) -> None:
        assert user_to_scim(_user(is_active=False))["active"] is False
        assert user_to_scim(_user(is_active=True))["active"] is True

    def test_name_is_split_into_given_family(self) -> None:
        out = user_to_scim(_user(name="Alice Liddell"))
        assert out["name"]["givenName"] == "Alice"
        assert out["name"]["familyName"] == "Liddell"
        assert out["name"]["formatted"] == "Alice Liddell"

    def test_emails_array_marks_primary(self) -> None:
        emails = user_to_scim(_user(email="a@b.com"))["emails"]
        assert emails[0]["value"] == "a@b.com"
        assert emails[0]["primary"] is True

    def test_groups_projected(self) -> None:
        out = user_to_scim(_user(idp_groups=["Engineering", "Admins"]))
        names = [g["display"] for g in out["groups"]]
        assert names == ["Engineering", "Admins"]

    def test_meta_present(self) -> None:
        out = user_to_scim(_user())
        assert out["meta"]["resourceType"] == "User"
        assert out["meta"]["location"].endswith(out["id"])


@pytest.mark.unit
class TestScimToUserFields:
    def test_extracts_known_fields(self) -> None:
        fields = scim_to_user_fields(
            {
                "schemas": [SCHEMA_USER],
                "userName": "alice@example.com",
                "active": True,
                "name": {"givenName": "Alice", "familyName": "Liddell"},
                "emails": [{"value": "alice@example.com", "primary": True}],
                "groups": [{"value": "Engineering"}],
            }
        )
        assert fields["email"] == "alice@example.com"
        assert fields["name"] == "Alice Liddell"
        assert fields["is_active"] is True
        assert fields["idp_groups"] == ["Engineering"]

    def test_primary_email_overrides_username(self) -> None:
        fields = scim_to_user_fields(
            {
                "userName": "ignored",
                "emails": [{"value": "primary@x.com", "primary": True}],
            }
        )
        assert fields["email"] == "primary@x.com"

    def test_first_email_wins_when_no_primary(self) -> None:
        fields = scim_to_user_fields(
            {
                "userName": "fallback@x.com",
                "emails": [{"value": "first@x.com"}, {"value": "second@x.com"}],
            }
        )
        assert fields["email"] == "first@x.com"

    def test_formatted_name_preferred_over_given_family(self) -> None:
        fields = scim_to_user_fields(
            {
                "name": {
                    "givenName": "Alice",
                    "familyName": "Liddell",
                    "formatted": "Dr. Alice Liddell, PhD",
                }
            }
        )
        assert fields["name"] == "Dr. Alice Liddell, PhD"

    def test_unknown_fields_ignored(self) -> None:
        fields = scim_to_user_fields(
            {"userName": "x@y.com", "weirdField": "ignored"}
        )
        assert fields == {"email": "x@y.com"}

    def test_groups_with_display_preferred_over_value(self) -> None:
        fields = scim_to_user_fields(
            {
                "groups": [
                    {"value": "00g123", "display": "Engineering"},
                    {"value": "Admins"},  # no display → value used
                ]
            }
        )
        assert fields["idp_groups"] == ["Engineering", "Admins"]


@pytest.mark.unit
class TestSplitName:
    def test_single_word(self) -> None:
        assert _split_name("Alice") == ("Alice", "")

    def test_two_words(self) -> None:
        assert _split_name("Alice Liddell") == ("Alice", "Liddell")

    def test_three_words_collapses_into_family(self) -> None:
        assert _split_name("Mary Anne Smith") == ("Mary", "Anne Smith")

    def test_empty_returns_empty_pair(self) -> None:
        assert _split_name("") == ("", "")


@pytest.mark.unit
class TestGroupToScim:
    def test_includes_group_schema(self) -> None:
        result = group_to_scim(group_name="Engineering", member_users=[])
        assert SCHEMA_GROUP in result["schemas"]

    def test_id_and_displayname_use_group_name(self) -> None:
        result = group_to_scim(group_name="Engineering", member_users=[])
        assert result["id"] == "Engineering"
        assert result["displayName"] == "Engineering"

    def test_members_serialized(self) -> None:
        u1 = _user(name="Alice")
        u2 = _user(name="Bob")
        result = group_to_scim(group_name="Eng", member_users=[u1, u2])
        assert len(result["members"]) == 2
        assert result["members"][0]["display"] == "Alice"
        assert result["members"][1]["display"] == "Bob"
