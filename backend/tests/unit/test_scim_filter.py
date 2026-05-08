"""SCIM filter parser tests — RFC 7644 §3.4.2.2 subset."""

from __future__ import annotations

from typing import Any

import pytest

from app.scim.filter import (
    FilterError,
    UnsupportedFilter,
    apply,
    parse,
)


def _resource(**fields: Any) -> dict[str, Any]:
    return {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], **fields}


@pytest.mark.unit
class TestEqualityOperators:
    def test_eq_string_match(self) -> None:
        f = parse('userName eq "alice@example.com"')
        assert f(_resource(userName="alice@example.com")) is True
        assert f(_resource(userName="bob@example.com")) is False

    def test_eq_case_insensitive(self) -> None:
        f = parse('userName eq "ALICE@example.com"')
        assert f(_resource(userName="alice@example.com")) is True

    def test_eq_bool(self) -> None:
        f = parse("active eq true")
        assert f(_resource(active=True)) is True
        assert f(_resource(active=False)) is False

    def test_ne(self) -> None:
        f = parse('userName ne "alice@example.com"')
        assert f(_resource(userName="bob@example.com")) is True
        assert f(_resource(userName="alice@example.com")) is False


@pytest.mark.unit
class TestStringOperators:
    def test_sw_starts_with(self) -> None:
        f = parse('userName sw "ali"')
        assert f(_resource(userName="alice@example.com")) is True
        assert f(_resource(userName="bob@example.com")) is False

    def test_ew_ends_with(self) -> None:
        f = parse('userName ew "@example.com"')
        assert f(_resource(userName="alice@example.com")) is True
        assert f(_resource(userName="alice@other.com")) is False

    def test_co_contains(self) -> None:
        f = parse('userName co "lice"')
        assert f(_resource(userName="alice@example.com")) is True
        assert f(_resource(userName="bob@example.com")) is False


@pytest.mark.unit
class TestPresent:
    def test_pr_returns_true_for_set_attribute(self) -> None:
        f = parse("userName pr")
        assert f(_resource(userName="alice@example.com")) is True

    def test_pr_returns_false_for_missing(self) -> None:
        f = parse("middleName pr")
        assert f(_resource(userName="alice@example.com")) is False

    def test_pr_returns_false_for_empty_string(self) -> None:
        f = parse("displayName pr")
        assert f(_resource(displayName="")) is False

    def test_pr_returns_false_for_empty_list(self) -> None:
        f = parse("emails pr")
        assert f(_resource(emails=[])) is False
        assert f(_resource(emails=[{"value": "a@b.com"}])) is True


@pytest.mark.unit
class TestOrderingOperators:
    def test_gt_lt_ge_le_on_numbers(self) -> None:
        for op, expected in (("gt", False), ("ge", True), ("lt", False), ("le", True)):
            f = parse(f"score {op} 5")
            assert f({"score": 5}) is expected, f"{op} on equal value"


@pytest.mark.unit
class TestLogical:
    def test_and(self) -> None:
        f = parse('userName eq "alice@example.com" and active eq true')
        assert f(_resource(userName="alice@example.com", active=True)) is True
        assert f(_resource(userName="alice@example.com", active=False)) is False
        assert f(_resource(userName="bob@example.com", active=True)) is False

    def test_or(self) -> None:
        f = parse('userName eq "alice" or userName eq "bob"')
        assert f(_resource(userName="alice")) is True
        assert f(_resource(userName="bob")) is True
        assert f(_resource(userName="cathy")) is False

    def test_not(self) -> None:
        f = parse("not (active eq true)")
        assert f(_resource(active=True)) is False
        assert f(_resource(active=False)) is True

    def test_grouping(self) -> None:
        f = parse('(userName eq "a" or userName eq "b") and active eq true')
        assert f(_resource(userName="a", active=True)) is True
        assert f(_resource(userName="b", active=True)) is True
        assert f(_resource(userName="a", active=False)) is False
        assert f(_resource(userName="c", active=True)) is False


@pytest.mark.unit
class TestDottedPaths:
    def test_dotted_attribute_access(self) -> None:
        f = parse('name.givenName eq "Alice"')
        assert f({"name": {"givenName": "Alice"}}) is True
        assert f({"name": {"givenName": "Bob"}}) is False

    def test_dotted_returns_false_when_intermediate_missing(self) -> None:
        f = parse('name.givenName eq "Alice"')
        assert f({"userName": "alice"}) is False


@pytest.mark.unit
class TestErrorHandling:
    def test_empty_expression_raises(self) -> None:
        with pytest.raises(FilterError, match="empty"):
            parse("")
        with pytest.raises(FilterError, match="empty"):
            parse("   ")

    def test_unrecognized_operator_raises(self) -> None:
        with pytest.raises(FilterError):
            parse("userName foo \"x\"")

    def test_missing_value_raises(self) -> None:
        with pytest.raises(FilterError):
            parse("userName eq")

    def test_unclosed_paren_raises(self) -> None:
        with pytest.raises(FilterError):
            parse('(userName eq "a"')

    def test_multivalued_attribute_filter_unsupported(self) -> None:
        with pytest.raises(UnsupportedFilter):
            parse('emails[type eq "work"].value eq "x"')

    def test_filter_too_long_raises(self) -> None:
        with pytest.raises(FilterError, match="maximum length"):
            parse("a" * 5000)

    def test_trailing_tokens_raise(self) -> None:
        with pytest.raises(FilterError, match="trailing tokens"):
            parse('userName eq "a" "b"')


@pytest.mark.unit
class TestApplyHelper:
    def test_apply_filters_a_list(self) -> None:
        resources = [
            _resource(userName="alice@example.com"),
            _resource(userName="bob@example.com"),
            _resource(userName="cathy@example.com"),
        ]
        result = apply('userName sw "a"', resources)
        assert len(result) == 1
        assert result[0]["userName"] == "alice@example.com"
