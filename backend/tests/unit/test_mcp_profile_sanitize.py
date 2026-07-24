"""Unit tests for stored-profile sanitization (GAP-019).

The integration battery in ``tests/integration/test_mcp_api.py`` proves the
behaviour end-to-end through the mounted app; these pin the pure coercion logic
directly, fast and DB-free, so the edge cases are cheap to enumerate.

The rule under test: a profile read from storage is untrusted JSONB. Every
field is coerced strictly — anything unparseable is dropped from enforcement AND
named in ``integrity_issues`` — and the inspector turns a non-empty
``integrity_issues`` into a ``malformed_profile`` violation that flags the call
(deny-by-default), because on the enforcement path an unreadable profile must
never inspect as "no constraints".
"""

from __future__ import annotations

import pytest

from app.mcp.inspector import inspect_call, sanitize_stored_profile

pytestmark = pytest.mark.unit


def _san(**overrides):
    base = {
        "tool_name": "t",
        "access_mode": "read",
        "description": "d",
        "allowed_params": ["a", "b"],
        "forbidden_params": ["DROP"],
        "param_constraints": {"q": {"type": "string", "max_length": 10}},
    }
    base.update(overrides)
    return sanitize_stored_profile(**base)


def test_wellformed_profile_has_no_integrity_issues() -> None:
    p = _san()
    assert p.integrity_issues == ()
    assert p.allowed_params == ("a", "b")
    assert p.forbidden_params == ("DROP",)
    assert p.param_constraints == {"q": {"type": "string", "max_length": 10}}


def test_string_allowed_params_does_not_fabricate() -> None:
    p = _san(allowed_params="shell")
    assert p.allowed_params == ()  # NOT ('s','h','e','l','l')
    assert any("allowed_params" in i for i in p.integrity_issues)


def test_nonstring_items_are_dropped_and_flagged() -> None:
    p = _san(forbidden_params=["DROP", 123, {"x": 1}])
    assert p.forbidden_params == ("DROP",)
    assert any("forbidden_params" in i for i in p.integrity_issues)


def test_param_constraints_not_a_dict_is_flagged() -> None:
    p = _san(param_constraints="nope")
    assert p.param_constraints == {}
    assert any("param_constraints is not an object" in i for i in p.integrity_issues)


def test_non_dict_rule_is_dropped_and_flagged() -> None:
    p = _san(param_constraints={"q": "not-a-dict"})
    assert p.param_constraints == {}
    assert any("constraint 'q' is not an object" in i for i in p.integrity_issues)


def test_bad_rule_field_dropped_rest_kept() -> None:
    p = _san(param_constraints={"q": {"type": "string", "max_length": "lots"}})
    # The garbage max_length is dropped; the valid type survives.
    assert p.param_constraints == {"q": {"type": "string"}}
    assert any("max_length" in i for i in p.integrity_issues)


def test_invalid_regex_pattern_is_flagged() -> None:
    p = _san(param_constraints={"q": {"type": "string", "pattern": "([unclosed"}})
    assert "pattern" not in p.param_constraints["q"]
    assert any("pattern is not a valid regex" in i for i in p.integrity_issues)


def test_valid_numeric_and_enum_rules_survive() -> None:
    p = _san(
        param_constraints={
            "timeout": {"type": "number", "max": 300},
            "method": {"type": "enum", "values": ["GET", "POST"]},
        }
    )
    assert p.integrity_issues == ()
    assert p.param_constraints["timeout"]["max"] == 300
    assert p.param_constraints["method"]["values"] == ["GET", "POST"]


def test_bool_is_not_a_positive_int_for_max_length() -> None:
    # Strictness inherited from coerce.as_positive_int: True is not 1.
    p = _san(param_constraints={"q": {"type": "string", "max_length": True}})
    assert "max_length" not in p.param_constraints["q"]
    assert any("max_length" in i for i in p.integrity_issues)


def test_malformed_profile_inspects_as_flag_not_allow() -> None:
    p = _san(param_constraints={"q": "not-a-dict"})
    result = inspect_call(tool_name="t", params={"q": "x"}, profile=p, recent_modes=["read"])
    assert result.recommendation == "flag"
    assert result.allowed is False
    assert any(v.type == "malformed_profile" for v in result.violations)


def test_wellformed_profile_inspects_clean() -> None:
    p = _san(param_constraints={"q": {"type": "string", "max_length": 100}})
    result = inspect_call(tool_name="t", params={"q": "short"}, profile=p, recent_modes=["read"])
    assert result.recommendation == "allow"
    assert not any(v.type == "malformed_profile" for v in result.violations)
