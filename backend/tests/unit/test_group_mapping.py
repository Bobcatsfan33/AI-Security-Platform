"""Test IDP group → platform role mapping."""

from __future__ import annotations

import pytest

from app.identity.registry import map_groups_to_role


@pytest.mark.unit
class TestGroupMapping:
    def test_first_matching_group_wins(self) -> None:
        directory_sync = {
            "group_to_role_mapping": {
                "Engineering": "analyst",
                "Security": "admin",
            },
            "default_role": "viewer",
        }
        # Order in idp_groups determines precedence
        assert map_groups_to_role(["Security", "Engineering"], directory_sync) == "admin"
        assert map_groups_to_role(["Engineering", "Security"], directory_sync) == "analyst"

    def test_no_match_uses_default(self) -> None:
        directory_sync = {
            "group_to_role_mapping": {"Admins": "owner"},
            "default_role": "viewer",
        }
        assert map_groups_to_role(["Marketing"], directory_sync) == "viewer"

    def test_empty_groups_uses_default(self) -> None:
        directory_sync = {"group_to_role_mapping": {}, "default_role": "analyst"}
        assert map_groups_to_role([], directory_sync) == "analyst"

    def test_default_default_is_viewer(self) -> None:
        # When directory_sync doesn't specify default_role, fall back to viewer
        # (least privilege).
        assert map_groups_to_role([], {}) == "viewer"
        assert map_groups_to_role(["Unknown"], {"group_to_role_mapping": {}}) == "viewer"
