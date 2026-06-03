"""Complex Event Pattern DSL — spec → compiled form.

A pattern is a multi-condition rule over a *flow* of events (one
correlation_key), expressing the kind of causal/temporal/absence logic flat
SIEM rules can't (brief §3.3). Example — the brief's four-condition pattern:

    name: cross-workspace-read-then-egress
    severity: critical
    all_of:
      - event: memory_access
        where: {workspace: {ne: {$ctx: home_workspace}}}   # cross-workspace
      - absent: {event: task_assignment}                    # no active task
      - event: external_api_call
        within: 60                                          # ...within 60s
        causally_after: memory_access                       # ...caused by the read
        where: {endpoint: {not_in: {$ctx: tool_manifest}}}  # unapproved endpoint

Specs compile ONCE (predicates resolved, structure validated) into a
CompiledPattern the evaluator runs per flow — mirroring how CompiledPolicy
pre-compiles regex so the hot path stays cheap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

Severity = str
# A compiled predicate: (event_field_value, context) -> bool.
PredicateFn = Callable[[Any, dict[str, Any]], bool]


class PatternValidationError(ValueError):
    """Raised when a pattern spec is structurally invalid."""


# ── predicate operators ───────────────────────────────────────────────────
def _resolve(operand: Any, ctx: dict[str, Any]) -> Any:
    """Resolve a literal or a {$ctx: key} reference against the context."""
    if isinstance(operand, dict) and "$ctx" in operand:
        return ctx.get(operand["$ctx"])
    return operand


_OPS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "in": lambda a, b: b is not None and a in b,
    "not_in": lambda a, b: b is not None and a not in b,
    "gte": lambda a, b: a is not None and b is not None and a >= b,
    "lte": lambda a, b: a is not None and b is not None and a <= b,
    "contains": lambda a, b: b is not None and b in (a or ""),
}


def _compile_predicate(field_name: str, spec: dict[str, Any]) -> PredicateFn:
    if not isinstance(spec, dict) or len(spec) != 1:
        raise PatternValidationError(
            f"predicate for {field_name!r} must be a single-op object, got {spec!r}"
        )
    ((op, operand),) = spec.items()
    if op == "exists":
        want = bool(operand)
        return lambda value, ctx: (value is not None and value != "") is want
    if op not in _OPS:
        raise PatternValidationError(f"unknown predicate op {op!r} on {field_name!r}")
    fn = _OPS[op]

    def predicate(value: Any, ctx: dict[str, Any]) -> bool:
        return fn(value, _resolve(operand, ctx))

    return predicate


@dataclass(frozen=True)
class CompiledCondition:
    event_type: str
    absent: bool = False
    within_s: float | None = None
    causally_after: str | None = None
    # field name → predicate
    where: tuple[tuple[str, PredicateFn], ...] = field(default_factory=tuple)

    def matches_event(self, event: dict[str, Any], ctx: dict[str, Any]) -> bool:
        if (event.get("event_type") or "") != self.event_type:
            return False
        for fname, pred in self.where:
            if not pred(event.get(fname), ctx):
                return False
        return True


@dataclass(frozen=True)
class CompiledPattern:
    name: str
    severity: Severity
    signal_kind: str
    conditions: tuple[CompiledCondition, ...]
    # Library/content metadata. atlas_techniques maps the pattern to MITRE
    # ATLAS (the AI-native analog to OWASP/NIST); version + references make
    # patterns shippable, citable content.
    version: int = 1
    description: str = ""
    atlas_techniques: tuple[str, ...] = field(default_factory=tuple)
    references: tuple[str, ...] = field(default_factory=tuple)
    category: str = ""


def compile_pattern(spec: dict[str, Any]) -> CompiledPattern:
    """Validate + compile a pattern spec. Raises PatternValidationError."""
    name = str(spec.get("name") or "").strip()
    if not name:
        raise PatternValidationError("pattern requires a non-empty name")
    all_of = spec.get("all_of")
    if not isinstance(all_of, list) or not all_of:
        raise PatternValidationError("pattern requires a non-empty all_of list")

    conditions: list[CompiledCondition] = []
    positive_types: set[str] = set()
    for raw in all_of:
        if not isinstance(raw, dict):
            raise PatternValidationError(f"condition must be an object, got {raw!r}")
        if "absent" in raw:
            inner = raw["absent"]
            if not isinstance(inner, dict) or "event" not in inner:
                raise PatternValidationError("absent must wrap an {event: ...} object")
            conditions.append(
                CompiledCondition(
                    event_type=str(inner["event"]),
                    absent=True,
                    where=_compile_where(inner.get("where")),
                )
            )
            continue
        if "event" not in raw:
            raise PatternValidationError(f"condition needs 'event' or 'absent': {raw!r}")
        ca = raw.get("causally_after")
        if ca is not None and ca not in positive_types:
            raise PatternValidationError(
                f"causally_after {ca!r} must reference an earlier event condition"
            )
        within = raw.get("within")
        cond = CompiledCondition(
            event_type=str(raw["event"]),
            within_s=float(within) if within is not None else None,
            causally_after=ca,
            where=_compile_where(raw.get("where")),
        )
        conditions.append(cond)
        positive_types.add(cond.event_type)

    return CompiledPattern(
        name=name,
        severity=str(spec.get("severity") or "medium"),
        signal_kind=str(spec.get("signal_kind") or "pattern_match"),
        conditions=tuple(conditions),
        version=int(spec.get("version", 1)),
        description=str(spec.get("description") or ""),
        atlas_techniques=tuple(spec.get("atlas_techniques") or ()),
        references=tuple(spec.get("references") or ()),
        category=str(spec.get("category") or ""),
    )


def _compile_where(where: Any) -> tuple[tuple[str, PredicateFn], ...]:
    if where is None:
        return ()
    if not isinstance(where, dict):
        raise PatternValidationError(f"where must be an object, got {where!r}")
    return tuple((fname, _compile_predicate(fname, pspec)) for fname, pspec in where.items())
