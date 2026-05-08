"""SCIM filter parser (RFC 7644 §3.4.2.2 subset).

Origin: ported verbatim from TokenDNA ``modules/auth/scim_filter.py`` —
this module has no DB or framework dependencies, so it transfers cleanly.

Supports the operators most IdPs send:

  attribute operators:  eq, ne, sw, ew, co, gt, lt, ge, le, pr (present)
  logical operators:    and, or, not
  grouping:             ( ... )

Out of scope (raises :class:`UnsupportedFilter`):

  multi-valued attribute filters with brackets:
      emails[type eq "work"]
  These are common in PATCH paths but rare in queries; we will add
  them after observing real customer traffic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

Filter = Callable[[dict[str, Any]], bool]


class FilterError(ValueError):
    """Raised when a filter expression is malformed."""


class UnsupportedFilter(FilterError):
    """Raised when a filter uses syntax we deliberately do not implement."""


# Whitespace consumed in its own pass so the token regex is a flat
# alternation of mutually exclusive concrete patterns. Folding `\s+` into
# the token regex would risk polynomial-redos on adversarial input.
_WS_RE = re.compile(r"\s+")
_TOKEN_RE = re.compile(
    r"""
    (?P<lparen>\()                   |
    (?P<rparen>\))                   |
    (?P<lbracket>\[)                 |
    (?P<rbracket>\])                 |
    (?P<string>"(?:\\.|[^"\\])*")    |
    (?P<bool>(?<![\w.])(?:true|false)(?![\w.]))   |
    (?P<number>-?\d+(?:\.\d+)?)      |
    (?P<word>[A-Za-z_][\w.]*)
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Defense-in-depth caps. Most production IdPs send filters under 1 KB.
_MAX_FILTER_LEN = 4096
_MAX_TOKENS = 1024


@dataclass
class _Token:
    kind: str
    value: str


_LOGICAL = {"and", "or", "not"}
_OPS = {"eq", "ne", "sw", "ew", "co", "gt", "lt", "ge", "le", "pr"}


def _tokenize(expr: str) -> list[_Token]:
    out: list[_Token] = []
    i = 0
    n = len(expr)
    while i < n:
        ws = _WS_RE.match(expr, i)
        if ws:
            i = ws.end()
            if i >= n:
                break
        m = _TOKEN_RE.match(expr, i)
        if not m:
            raise FilterError(
                f"unrecognized character at offset {i}: {expr[i:i+10]!r}"
            )
        i = m.end()
        if len(out) >= _MAX_TOKENS:
            raise FilterError(f"filter exceeds maximum token count ({_MAX_TOKENS})")
        if m.group("lparen"):
            out.append(_Token("lparen", "("))
        elif m.group("rparen"):
            out.append(_Token("rparen", ")"))
        elif m.group("lbracket") or m.group("rbracket"):
            raise UnsupportedFilter(
                "multi-valued attribute filters with [...] are not supported"
            )
        elif m.group("string"):
            raw = m.group("string")[1:-1]
            out.append(_Token("string", raw.encode("utf-8").decode("unicode_escape")))
        elif m.group("bool"):
            out.append(_Token("bool", m.group("bool").lower()))
        elif m.group("number"):
            out.append(_Token("number", m.group("number")))
        elif m.group("word"):
            w = m.group("word").lower()
            if w in _LOGICAL:
                out.append(_Token("logical", w))
            elif w in _OPS:
                out.append(_Token("op", w))
            else:
                out.append(_Token("attr", m.group("word")))
    return out


# ── Recursive-descent parser ─────────────────────────────────────────────────


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self._t = tokens
        self._i = 0

    def _peek(self) -> _Token | None:
        return self._t[self._i] if self._i < len(self._t) else None

    def _eat(self) -> _Token:
        tok = self._t[self._i]
        self._i += 1
        return tok

    def parse(self) -> Filter:
        f = self._parse_or()
        if self._peek() is not None:
            raise FilterError(f"trailing tokens at offset {self._i}")
        return f

    def _parse_or(self) -> Filter:
        left = self._parse_and()
        while True:
            tok = self._peek()
            if tok and tok.kind == "logical" and tok.value == "or":
                self._eat()
                right = self._parse_and()
                left = _make_or(left, right)
            else:
                return left

    def _parse_and(self) -> Filter:
        left = self._parse_not()
        while True:
            tok = self._peek()
            if tok and tok.kind == "logical" and tok.value == "and":
                self._eat()
                right = self._parse_not()
                left = _make_and(left, right)
            else:
                return left

    def _parse_not(self) -> Filter:
        tok = self._peek()
        if tok and tok.kind == "logical" and tok.value == "not":
            self._eat()
            inner = self._parse_atom()
            return _make_not(inner)
        return self._parse_atom()

    def _parse_atom(self) -> Filter:
        tok = self._peek()
        if tok is None:
            raise FilterError("unexpected end of expression")
        if tok.kind == "lparen":
            self._eat()
            inner = self._parse_or()
            close = self._peek()
            if close is None or close.kind != "rparen":
                raise FilterError("missing closing paren")
            self._eat()
            return inner
        if tok.kind != "attr":
            raise FilterError(f"expected attribute, got {tok.kind} {tok.value!r}")
        attr = self._eat().value
        op_tok = self._peek()
        if op_tok is None or op_tok.kind != "op":
            raise FilterError(f"expected operator after {attr!r}")
        op = self._eat().value
        if op == "pr":
            return _make_pr(attr)
        val_tok = self._peek()
        if val_tok is None:
            raise FilterError(f"expected value after {attr} {op}")
        self._eat()
        if val_tok.kind == "string":
            value: Any = val_tok.value
        elif val_tok.kind == "bool":
            value = val_tok.value == "true"
        elif val_tok.kind == "number":
            value = (
                float(val_tok.value) if "." in val_tok.value else int(val_tok.value)
            )
        else:
            raise FilterError(f"expected literal after {attr} {op}, got {val_tok.kind}")
        return _make_compare(attr, op, value)


# ── Operator implementations ─────────────────────────────────────────────────


def _resolve(resource: dict[str, Any], path: str) -> Any:
    """Walk dotted attribute path. Case-insensitive on top-level keys."""
    parts = path.split(".")
    node: Any = resource
    for part in parts:
        if isinstance(node, dict):
            for key in node.keys():
                if key.lower() == part.lower():
                    node = node[key]
                    break
            else:
                return None
        else:
            return None
    return node


def _make_pr(attr: str) -> Filter:
    def f(resource: dict[str, Any]) -> bool:
        v = _resolve(resource, attr)
        if v is None:
            return False
        if isinstance(v, (str, list, dict)) and len(v) == 0:
            return False
        return True

    return f


def _make_and(a: Filter, b: Filter) -> Filter:
    return lambda r: a(r) and b(r)


def _make_or(a: Filter, b: Filter) -> Filter:
    return lambda r: a(r) or b(r)


def _make_not(a: Filter) -> Filter:
    return lambda r: not a(r)


def _coerce_pair(left: Any, right: Any) -> tuple[Any, Any]:
    if isinstance(left, str) and isinstance(right, (int, float)):
        try:
            return float(left), float(right)
        except ValueError:
            return left, str(right)
    if isinstance(right, str) and isinstance(left, (int, float)):
        try:
            return float(left), float(right)
        except ValueError:
            return str(left), right
    return left, right


def _make_compare(attr: str, op: str, expected: Any) -> Filter:
    def f(resource: dict[str, Any]) -> bool:
        actual = _resolve(resource, attr)
        if actual is None:
            return False
        a = actual.lower() if isinstance(actual, str) else actual
        e = expected.lower() if isinstance(expected, str) else expected
        if op == "eq":
            return a == e
        if op == "ne":
            return a != e
        if op == "sw":
            return isinstance(a, str) and isinstance(e, str) and a.startswith(e)
        if op == "ew":
            return isinstance(a, str) and isinstance(e, str) and a.endswith(e)
        if op == "co":
            return isinstance(a, str) and isinstance(e, str) and e in a
        if op in ("gt", "lt", "ge", "le"):
            la, le_v = _coerce_pair(actual, expected)
            try:
                if op == "gt":
                    return la > le_v
                if op == "lt":
                    return la < le_v
                if op == "ge":
                    return la >= le_v
                if op == "le":
                    return la <= le_v
            except TypeError:
                return False
        return False

    return f


# ── Public entry point ────────────────────────────────────────────────────────


def parse(expr: str) -> Filter:
    """Parse a SCIM filter expression and return an evaluator callable."""
    if not expr or not expr.strip():
        raise FilterError("empty filter expression")
    if len(expr) > _MAX_FILTER_LEN:
        raise FilterError(
            f"filter expression exceeds maximum length ({_MAX_FILTER_LEN} chars)"
        )
    tokens = _tokenize(expr)
    if not tokens:
        raise FilterError("empty filter expression")
    return _Parser(tokens).parse()


def apply(expr: str, resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    f = parse(expr)
    return [r for r in resources if f(r)]
