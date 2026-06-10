"""SCIM filter parser (RFC 7644 §3.4.2.2 subset) — Phase 3E coverage.

Operator-critical: every IdP SCIM query hits this parser. Table-driven across
all supported operators, logical composition, precedence, dotted paths, and
the documented error/unsupported cases.
"""

from __future__ import annotations

import pytest

from app.scim.filter import FilterError, UnsupportedFilter, apply, parse

pytestmark = pytest.mark.unit

_USER = {
    "userName": "Alice.Smith@ACME.com",
    "active": True,
    "name": {"familyName": "Smith", "givenName": "Alice"},
    "title": "",
    "loginCount": 42,
}


@pytest.mark.parametrize(
    "expr,expected",
    [
        # eq / ne — case-insensitive on strings
        ('userName eq "alice.smith@acme.com"', True),
        ('userName eq "bob@acme.com"', False),
        ('userName ne "bob@acme.com"', True),
        ("active eq true", True),
        ("active eq false", False),
        # sw / ew / co
        ('userName sw "alice"', True),
        ('userName sw "bob"', False),
        ('userName ew "acme.com"', True),
        ('userName co "smith"', True),
        ('userName co "nope"', False),
        # pr (present) — empty string is NOT present
        ("userName pr", True),
        ("title pr", False),
        ("missing pr", False),
        # gt / lt / ge / le — numeric coercion
        ("loginCount gt 10", True),
        ("loginCount gt 100", False),
        ("loginCount ge 42", True),
        ("loginCount lt 100", True),
        ("loginCount le 42", True),
        # dotted attribute path, case-insensitive top-level key
        ('name.familyName eq "smith"', True),
        ('NAME.givenName eq "alice"', True),
        ('name.familyName eq "jones"', False),
        # logical composition + precedence + grouping + not
        ('userName sw "alice" and active eq true', True),
        ('userName sw "bob" or active eq true', True),
        ('userName sw "bob" and active eq true', False),
        ('not (userName sw "bob")', True),
        ('(userName sw "alice" or userName sw "bob") and active eq true', True),
        # a non-string compared with co/sw is False, not an error
        ("active co true", False),
    ],
)
def test_operator_matrix(expr: str, expected: bool):
    assert parse(expr)(_USER) is expected


def test_apply_filters_a_list():
    users = [
        {"userName": "alice", "active": True},
        {"userName": "bob", "active": False},
        {"userName": "carol", "active": True},
    ]
    out = apply("active eq true", users)
    assert [u["userName"] for u in out] == ["alice", "carol"]


def test_missing_attribute_never_matches():
    assert parse('nope eq "x"')(_USER) is False
    assert parse("nope gt 5")(_USER) is False


class TestErrors:
    @pytest.mark.parametrize(
        "expr",
        [
            "",
            "   ",
            "userName eq",  # missing value
            'eq "x"',  # missing attribute
            '(userName eq "x"',  # missing closing paren
            'userName eq "x" extra',  # trailing tokens
            "userName",  # attribute with no operator
        ],
    )
    def test_filter_error(self, expr: str):
        with pytest.raises(FilterError):
            parse(expr)

    def test_unsupported_bracket_filter(self):
        with pytest.raises(UnsupportedFilter):
            parse('emails[type eq "work"]')

    def test_overlong_expression_rejected(self):
        with pytest.raises(FilterError):
            parse('userName eq "' + "x" * 5000 + '"')
