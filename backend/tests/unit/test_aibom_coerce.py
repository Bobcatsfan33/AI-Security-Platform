"""Strict coercion helpers for operator-shaped JSONB."""

from __future__ import annotations

import pytest

from app.aibom.coerce import (
    as_bool,
    as_dict_list,
    as_list,
    as_number,
    as_positive_int,
    as_str,
)

pytestmark = pytest.mark.unit


def test_as_list_only_accepts_lists() -> None:
    assert as_list(["a", "b"]) == ["a", "b"]
    assert as_list("shell") == []  # a string is not a list — would miscount via len
    assert as_list(None) == []
    assert as_list({"a": 1}) == []
    assert as_list(5) == []


def test_as_bool_is_strict() -> None:
    assert as_bool(True) is True
    assert as_bool(False) is False
    assert as_bool("false") is None  # the bool("false") is True trap
    assert as_bool("true") is None
    assert as_bool(1) is None
    assert as_bool(None) is None


def test_as_positive_int_rejects_bool_zero_negative() -> None:
    assert as_positive_int(5) == 5
    assert as_positive_int(True) is None  # bool is not a budget
    assert as_positive_int(0) is None
    assert as_positive_int(-3) is None
    assert as_positive_int(3.5) is None
    assert as_positive_int("5") is None


def test_as_number_rejects_bool_and_non_numeric() -> None:
    assert as_number(3) == 3.0
    assert as_number(3.5) == 3.5
    assert as_number(True) is None
    assert as_number("abc") is None  # the float("abc") -> 500 trap
    assert as_number(None) is None
    assert as_number(float("inf")) is None  # not finite


def test_as_dict_list_drops_non_dicts() -> None:
    assert as_dict_list([{"a": 1}, "x", 5, {"b": 2}]) == [{"a": 1}, {"b": 2}]
    assert as_dict_list("not-a-list") == []
    assert as_dict_list(None) == []


def test_as_str_distinguishes_absent_from_non_string() -> None:
    assert as_str("DMZ") == "dmz"
    assert as_str(None) is None
    assert as_str(5) is None
    assert as_str(["x"]) is None
