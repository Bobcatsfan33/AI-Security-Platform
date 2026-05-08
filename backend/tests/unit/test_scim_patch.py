"""SCIM PATCH tests — RFC 7644 §3.5.2 subset."""

from __future__ import annotations

from typing import Any

import pytest

from app.scim.patch import (
    PatchError,
    UnsupportedPatch,
    apply_patch,
)
from app.scim.types import SCHEMA_PATCH_OP


def _patch_doc(*operations: dict[str, Any]) -> dict[str, Any]:
    return {"schemas": [SCHEMA_PATCH_OP], "Operations": list(operations)}


@pytest.mark.unit
class TestPatchValidation:
    def test_missing_schemas_raises(self) -> None:
        with pytest.raises(PatchError, match="schema"):
            apply_patch({"x": 1}, {"Operations": [{"op": "add", "value": {"y": 2}}]})

    def test_empty_operations_raises(self) -> None:
        with pytest.raises(PatchError, match="non-empty"):
            apply_patch({}, {"schemas": [SCHEMA_PATCH_OP], "Operations": []})

    def test_invalid_op_raises(self) -> None:
        with pytest.raises(PatchError, match="unsupported op"):
            apply_patch({}, _patch_doc({"op": "purge", "path": "x", "value": 1}))


@pytest.mark.unit
class TestSimpleAdd:
    def test_add_top_level(self) -> None:
        result = apply_patch(
            {"userName": "alice"},
            _patch_doc({"op": "add", "path": "displayName", "value": "Alice"}),
        )
        assert result["displayName"] == "Alice"
        assert result["userName"] == "alice"

    def test_add_creates_intermediate(self) -> None:
        result = apply_patch(
            {},
            _patch_doc({"op": "add", "path": "name.givenName", "value": "Alice"}),
        )
        assert result["name"]["givenName"] == "Alice"

    def test_add_to_list_appends(self) -> None:
        result = apply_patch(
            {"emails": [{"value": "a@x.com"}]},
            _patch_doc(
                {"op": "add", "path": "emails", "value": [{"value": "b@x.com"}]}
            ),
        )
        assert len(result["emails"]) == 2

    def test_add_scalar_replaces(self) -> None:
        # Per RFC §3.5.2.1: add on scalar acts like replace
        result = apply_patch(
            {"displayName": "old"},
            _patch_doc({"op": "add", "path": "displayName", "value": "new"}),
        )
        assert result["displayName"] == "new"


@pytest.mark.unit
class TestReplace:
    def test_replace_top_level(self) -> None:
        result = apply_patch(
            {"active": True},
            _patch_doc({"op": "replace", "path": "active", "value": False}),
        )
        assert result["active"] is False

    def test_replace_nested(self) -> None:
        result = apply_patch(
            {"name": {"givenName": "old"}},
            _patch_doc({"op": "replace", "path": "name.givenName", "value": "new"}),
        )
        assert result["name"]["givenName"] == "new"

    def test_replace_without_path_merges_dict(self) -> None:
        result = apply_patch(
            {"active": True, "displayName": "Alice"},
            _patch_doc(
                {"op": "replace", "value": {"active": False, "userName": "a"}}
            ),
        )
        assert result["active"] is False
        assert result["displayName"] == "Alice"
        assert result["userName"] == "a"

    def test_replace_without_path_requires_dict(self) -> None:
        with pytest.raises(PatchError):
            apply_patch(
                {},
                _patch_doc({"op": "replace", "value": "not-a-dict"}),
            )


@pytest.mark.unit
class TestRemove:
    def test_remove_top_level(self) -> None:
        result = apply_patch(
            {"userName": "alice", "displayName": "Alice"},
            _patch_doc({"op": "remove", "path": "displayName"}),
        )
        assert "displayName" not in result
        assert result["userName"] == "alice"

    def test_remove_nested(self) -> None:
        result = apply_patch(
            {"name": {"givenName": "Alice", "familyName": "Smith"}},
            _patch_doc({"op": "remove", "path": "name.givenName"}),
        )
        assert "givenName" not in result["name"]
        assert result["name"]["familyName"] == "Smith"

    def test_remove_missing_path_is_idempotent(self) -> None:
        result = apply_patch(
            {"userName": "alice"},
            _patch_doc({"op": "remove", "path": "displayName"}),
        )
        assert result["userName"] == "alice"

    def test_remove_without_path_raises(self) -> None:
        with pytest.raises(PatchError, match="path"):
            apply_patch({"x": 1}, _patch_doc({"op": "remove"}))


@pytest.mark.unit
class TestUnsupportedPaths:
    def test_value_filtered_path_raises_unsupported(self) -> None:
        with pytest.raises(UnsupportedPatch):
            apply_patch(
                {},
                _patch_doc(
                    {
                        "op": "replace",
                        "path": 'emails[type eq "work"].value',
                        "value": "x",
                    }
                ),
            )


@pytest.mark.unit
class TestImmutability:
    def test_input_resource_not_mutated(self) -> None:
        original = {"userName": "alice", "active": True}
        result = apply_patch(
            original,
            _patch_doc({"op": "replace", "path": "active", "value": False}),
        )
        assert original["active"] is True  # original untouched
        assert result["active"] is False


@pytest.mark.unit
class TestMultipleOperations:
    def test_operations_apply_in_order(self) -> None:
        result = apply_patch(
            {"x": 1},
            _patch_doc(
                {"op": "add", "path": "y", "value": 2},
                {"op": "replace", "path": "x", "value": 99},
                {"op": "remove", "path": "y"},
            ),
        )
        assert result["x"] == 99
        assert "y" not in result
