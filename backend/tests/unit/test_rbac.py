"""Unit tests for the RBAC matrix."""

from __future__ import annotations

import pytest

from app.auth.rbac import has_role_at_least, is_in, is_valid_role


@pytest.mark.unit
class TestRoleHierarchy:
    def test_owner_satisfies_every_ui_role(self) -> None:
        for required in ("owner", "admin", "analyst", "viewer"):
            assert has_role_at_least("owner", required)

    def test_admin_does_not_satisfy_owner(self) -> None:
        assert not has_role_at_least("admin", "owner")

    def test_viewer_only_satisfies_viewer(self) -> None:
        assert has_role_at_least("viewer", "viewer")
        assert not has_role_at_least("viewer", "analyst")
        assert not has_role_at_least("viewer", "admin")

    def test_api_only_is_orthogonal_to_ui_roles(self) -> None:
        assert not has_role_at_least("api_only", "viewer")
        assert not has_role_at_least("api_only", "analyst")
        assert has_role_at_least("api_only", "api_only")

    def test_unknown_role_never_satisfies(self) -> None:
        assert not has_role_at_least("hacker", "viewer")
        assert not has_role_at_least("admin", "wizard")

    def test_is_in_explicit_set(self) -> None:
        assert is_in("analyst", {"analyst", "admin"})
        assert not is_in("viewer", {"analyst", "admin"})

    def test_is_valid_role(self) -> None:
        assert is_valid_role("owner")
        assert is_valid_role("api_only")
        assert not is_valid_role("superuser")
