"""SCIM PATCH semantics (RFC 7644 §3.5.2) — the deprovisioning path.

``PATCH {"active": false}`` is how every major IdP deprovisions a user. It is
the single most security-relevant message the platform receives from an
identity provider, and this module is the only thing that interprets it. Two
properties therefore matter more than SCIM conformance in the abstract:

  **Deactivation must land.** If a malformed or partially-understood
  operation silently no-ops, an offboarded employee keeps their access and
  the audit log shows a successful PATCH. Every rejection path below is
  asserted to *raise*, never to return an unchanged resource.

  **Unsupported must not mean "guessed".** Value-filtered paths
  (``emails[type eq "work"].value``) are deliberately unimplemented. Silently
  ignoring the filter and writing the whole attribute would corrupt the
  record; the module raises ``UnsupportedPatch``, which the SCIM routes turn
  into a 501 the IdP can act on.

The immutability check is not stylistic either: ``patch_user`` patches a
serialized copy and then writes the result back to the ORM object. An
``apply_patch`` that mutated its input would make a failed patch partially
applied.
"""

from __future__ import annotations

import copy

import pytest

from app.scim.patch import PatchError, UnsupportedPatch, apply_patch
from app.scim.types import SCHEMA_PATCH_OP

pytestmark = pytest.mark.unit


def _patch(*operations):
    return {"schemas": [SCHEMA_PATCH_OP], "Operations": list(operations)}


USER = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "id": "u-1",
    "userName": "ada@example.com",
    "active": True,
    "name": {"givenName": "Ada", "familyName": "Lovelace"},
    "emails": [{"value": "ada@example.com", "primary": True}],
}


class TestDeprovisioning:
    def test_setting_active_false_deactivates(self):
        result = apply_patch(USER, _patch({"op": "replace", "path": "active", "value": False}))
        assert result["active"] is False

    def test_okta_style_capitalized_op_is_accepted(self):
        """Real IdPs send "Replace"; RFC 7644 treats op as case-insensitive."""
        result = apply_patch(USER, _patch({"op": "Replace", "path": "active", "value": False}))
        assert result["active"] is False

    def test_azure_style_whole_resource_replace_deactivates(self):
        result = apply_patch(USER, _patch({"op": "replace", "value": {"active": False}}))
        assert result["active"] is False

    def test_removing_active_drops_the_attribute_rather_than_leaving_it_true(self):
        result = apply_patch(USER, _patch({"op": "remove", "path": "active"}))
        assert "active" not in result

    def test_operations_apply_in_order_so_the_last_write_wins(self):
        result = apply_patch(
            USER,
            _patch(
                {"op": "replace", "path": "active", "value": False},
                {"op": "replace", "path": "active", "value": True},
            ),
        )
        assert result["active"] is True

    def test_a_later_failing_operation_aborts_the_whole_patch(self):
        """Partial application would leave a half-deprovisioned account."""
        with pytest.raises(PatchError):
            apply_patch(
                USER,
                _patch(
                    {"op": "replace", "path": "active", "value": False},
                    {"op": "explode", "path": "active", "value": True},
                ),
            )


class TestImmutability:
    def test_the_input_resource_is_never_mutated(self):
        before = copy.deepcopy(USER)

        apply_patch(USER, _patch({"op": "replace", "path": "active", "value": False}))

        assert before == USER

    def test_nested_structures_are_deep_copied_not_shared(self):
        result = apply_patch(USER, _patch({"op": "replace", "path": "active", "value": False}))

        result["name"]["givenName"] = "MUTATED"
        result["emails"].append({"value": "x@example.com"})

        assert USER["name"]["givenName"] == "Ada"
        assert len(USER["emails"]) == 1

    def test_a_failed_patch_leaves_no_trace_on_the_input(self):
        before = copy.deepcopy(USER)

        with pytest.raises(PatchError):
            apply_patch(USER, _patch({"op": "remove"}))

        assert before == USER


class TestPathSemantics:
    def test_a_dotted_path_updates_the_nested_attribute_only(self):
        result = apply_patch(
            USER, _patch({"op": "replace", "path": "name.givenName", "value": "Grace"})
        )

        assert result["name"] == {"givenName": "Grace", "familyName": "Lovelace"}

    def test_a_dotted_path_creates_missing_intermediate_objects(self):
        result = apply_patch(
            {"id": "u"}, _patch({"op": "add", "path": "name.givenName", "value": "Grace"})
        )

        assert result["name"] == {"givenName": "Grace"}

    def test_descending_through_a_scalar_is_rejected(self):
        with pytest.raises(PatchError, match="cannot descend"):
            apply_patch(
                {"id": "u", "name": "flat string"},
                _patch({"op": "replace", "path": "name.givenName", "value": "Grace"}),
            )

    def test_removing_a_nested_attribute_leaves_its_siblings(self):
        result = apply_patch(USER, _patch({"op": "remove", "path": "name.givenName"}))

        assert result["name"] == {"familyName": "Lovelace"}

    def test_removing_an_absent_attribute_is_a_no_op_not_an_error(self):
        result = apply_patch(USER, _patch({"op": "remove", "path": "nickName"}))
        assert result["userName"] == "ada@example.com"

    @pytest.mark.parametrize("path", ["", ".", "..."])
    def test_an_effectively_empty_path_is_rejected(self, path):
        """A blank path used to mean "the whole resource" would be catastrophic."""
        with pytest.raises(PatchError):
            apply_patch(USER, _patch({"op": "remove", "path": path}))

    def test_a_dotted_path_with_empty_segments_still_addresses_the_leaf(self):
        result = apply_patch(
            USER, _patch({"op": "replace", "path": "name..givenName", "value": "G"})
        )
        assert result["name"]["givenName"] == "G"


class TestAddSemantics:
    def test_add_appends_when_both_sides_are_lists(self):
        result = apply_patch(
            USER,
            _patch({"op": "add", "path": "emails", "value": [{"value": "ada@work.example"}]}),
        )

        assert [e["value"] for e in result["emails"]] == ["ada@example.com", "ada@work.example"]

    def test_add_appends_a_scalar_onto_an_existing_list(self):
        result = apply_patch(
            USER, _patch({"op": "add", "path": "emails", "value": {"value": "b@example.com"}})
        )

        assert len(result["emails"]) == 2

    def test_add_on_a_missing_attribute_creates_it(self):
        result = apply_patch(USER, _patch({"op": "add", "path": "nickName", "value": "Ada L"}))
        assert result["nickName"] == "Ada L"

    def test_add_on_an_existing_scalar_behaves_like_replace(self):
        result = apply_patch(USER, _patch({"op": "add", "path": "active", "value": False}))
        assert result["active"] is False

    def test_add_without_path_merges_new_keys_and_concatenates_lists(self):
        result = apply_patch(
            USER,
            _patch(
                {
                    "op": "add",
                    "value": {
                        "nickName": "Ada L",
                        "emails": [{"value": "second@example.com"}],
                    },
                }
            ),
        )

        assert result["nickName"] == "Ada L"
        assert len(result["emails"]) == 2

    def test_add_without_path_overwrites_a_conflicting_scalar(self):
        result = apply_patch(USER, _patch({"op": "add", "value": {"active": False}}))
        assert result["active"] is False

    def test_add_without_path_overwrites_when_types_disagree(self):
        result = apply_patch(USER, _patch({"op": "add", "value": {"emails": "not-a-list"}}))
        assert result["emails"] == "not-a-list"


class TestReplaceSemantics:
    def test_replace_without_path_merges_the_supplied_keys_only(self):
        result = apply_patch(
            USER, _patch({"op": "replace", "value": {"active": False, "nickName": "A"}})
        )

        assert result["active"] is False
        assert result["nickName"] == "A"
        assert result["userName"] == "ada@example.com", "unlisted attributes must survive"

    def test_replace_overwrites_a_list_wholesale(self):
        result = apply_patch(
            USER, _patch({"op": "replace", "path": "emails", "value": [{"value": "only@x.com"}]})
        )

        assert len(result["emails"]) == 1

    def test_replace_can_set_an_attribute_to_null(self):
        result = apply_patch(USER, _patch({"op": "replace", "path": "nickName", "value": None}))
        assert result["nickName"] is None


class TestRejectedInput:
    def test_a_missing_patchop_schema_is_rejected(self):
        with pytest.raises(PatchError, match="PatchOp schema missing"):
            apply_patch(USER, {"Operations": [{"op": "replace", "path": "active", "value": False}]})

    def test_a_wrong_schema_uri_is_rejected(self):
        with pytest.raises(PatchError, match="PatchOp schema missing"):
            apply_patch(
                USER,
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "Operations": [{"op": "replace", "path": "active", "value": False}],
                },
            )

    @pytest.mark.parametrize(
        "operations",
        [None, [], {}, "replace active", 42],
        ids=["null", "empty", "object", "string", "number"],
    )
    def test_operations_must_be_a_non_empty_list(self, operations):
        with pytest.raises(PatchError, match="Operations"):
            apply_patch(USER, {"schemas": [SCHEMA_PATCH_OP], "Operations": operations})

    @pytest.mark.parametrize("operation", ["replace", 1, None, ["op"]])
    def test_each_operation_must_be_an_object(self, operation):
        with pytest.raises(PatchError, match="must be an object"):
            apply_patch(USER, _patch(operation))

    @pytest.mark.parametrize("op", ["move", "copy", "test", "", None, "REMOVE_ALL"])
    def test_an_unknown_op_is_rejected_rather_than_ignored(self, op):
        with pytest.raises(PatchError, match="unsupported op"):
            apply_patch(USER, _patch({"op": op, "path": "active", "value": False}))

    def test_remove_without_a_path_is_rejected(self):
        """Otherwise "remove" with no path could be read as "remove everything"."""
        with pytest.raises(PatchError, match="remove requires path"):
            apply_patch(USER, _patch({"op": "remove"}))

    @pytest.mark.parametrize("value", ["a string", 42, ["a", "list"], None])
    def test_pathless_replace_requires_an_object_value(self, value):
        with pytest.raises(PatchError, match="replace without path requires an object"):
            apply_patch(USER, _patch({"op": "replace", "value": value}))

    @pytest.mark.parametrize("value", ["a string", 42, ["a", "list"], None])
    def test_pathless_add_requires_an_object_value(self, value):
        with pytest.raises(PatchError, match="add without path requires an object"):
            apply_patch(USER, _patch({"op": "add", "value": value}))


class TestUnsupportedSyntax:
    @pytest.mark.parametrize(
        "path",
        [
            'emails[type eq "work"].value',
            'members[value eq "u-1"]',
            "emails[0]",
            "name.givenName]",
            "[",
        ],
    )
    def test_value_filtered_paths_are_refused_not_silently_broadened(self, path):
        """Dropping the filter would write the whole multi-valued attribute."""
        with pytest.raises(UnsupportedPatch, match="value-filtered"):
            apply_patch(USER, _patch({"op": "replace", "path": path, "value": "x"}))

    def test_unsupported_is_distinguishable_from_invalid(self):
        """The routes map these to 501 and 400 respectively; conflating them
        would tell an IdP to fix a request that is actually correct."""
        assert issubclass(UnsupportedPatch, PatchError)

        with pytest.raises(UnsupportedPatch):
            apply_patch(USER, _patch({"op": "remove", "path": 'emails[type eq "work"]'}))

        with pytest.raises(PatchError) as excinfo:
            apply_patch(USER, _patch({"op": "remove"}))
        assert not isinstance(excinfo.value, UnsupportedPatch)

    def test_a_filtered_path_is_rejected_before_earlier_operations_take_effect(self):
        before = copy.deepcopy(USER)

        with pytest.raises(UnsupportedPatch):
            apply_patch(
                USER,
                _patch(
                    {"op": "replace", "path": "active", "value": False},
                    {"op": "replace", "path": 'emails[type eq "work"].value', "value": "x"},
                ),
            )

        assert before == USER


class TestOversizedInput:
    def test_a_very_large_value_is_carried_through_without_truncation(self):
        """Length limits belong to the service layer; PATCH must not silently trim."""
        big = "x" * 100_000

        result = apply_patch(USER, _patch({"op": "replace", "path": "nickName", "value": big}))

        assert result["nickName"] == big

    def test_many_operations_are_all_applied(self):
        operations = [{"op": "add", "path": f"attr{i}", "value": i} for i in range(500)]

        result = apply_patch(USER, _patch(*operations))

        assert result["attr0"] == 0 and result["attr499"] == 499

    def test_a_deeply_nested_path_does_not_recurse_unboundedly(self):
        path = ".".join(f"level{i}" for i in range(200))

        result = apply_patch({"id": "u"}, _patch({"op": "add", "path": path, "value": "deep"}))

        node = result
        for i in range(200):
            node = node[f"level{i}"]
        assert node == "deep"
