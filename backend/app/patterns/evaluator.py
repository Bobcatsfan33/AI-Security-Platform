"""Pattern evaluator — runs a CompiledPattern over one flow's events.

Events are the wire dicts of a single correlation_key (a flow), assumed
time-ordered. The evaluator binds each positive condition to an event,
enforcing ``causally_after`` (causal-depth ordering) and ``within`` (temporal
window), and verifies ``absent`` conditions (the negative/absence detection
flat rules can't express). Returns a PatternMatch when every condition holds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from app.patterns.compiled import CompiledPattern


@dataclass(frozen=True)
class PatternMatch:
    pattern_name: str
    severity: str
    signal_kind: str
    correlation_key: str
    matched_event_ids: tuple[str, ...]
    agents: tuple[str, ...] = field(default_factory=tuple)


def _epoch(event: dict[str, Any]) -> float:
    raw = event.get("timestamp")
    if not raw:
        return 0.0
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return 0.0


def _depth(event: dict[str, Any]) -> int:
    try:
        return int(event.get("causal_depth") or 0)
    except (TypeError, ValueError):
        return 0


def evaluate(
    pattern: CompiledPattern,
    events: list[dict[str, Any]],
    *,
    context: Optional[dict[str, Any]] = None,
) -> Optional[PatternMatch]:
    """Return a PatternMatch if ``pattern`` holds over ``events``, else None."""
    ctx = context or {}
    ordered = sorted(events, key=_epoch)

    # Absence conditions first — any matching event fails the pattern.
    for cond in pattern.conditions:
        if cond.absent and any(cond.matches_event(e, ctx) for e in ordered):
            return None

    bindings: dict[str, dict[str, Any]] = {}  # event_type -> bound event
    last_bound: dict[str, Any] | None = None

    for cond in pattern.conditions:
        if cond.absent:
            continue
        candidates = [e for e in ordered if cond.matches_event(e, ctx)]

        ref = bindings.get(cond.causally_after) if cond.causally_after else last_bound
        if cond.causally_after and ref is None:
            return None  # the referenced condition never bound

        if cond.causally_after and ref is not None:
            ref_depth = _depth(ref)
            candidates = [e for e in candidates if _depth(e) > ref_depth]

        if cond.within_s is not None and ref is not None:
            ref_ts = _epoch(ref)
            candidates = [e for e in candidates if 0.0 <= (_epoch(e) - ref_ts) <= cond.within_s]

        if not candidates:
            return None
        chosen = candidates[0]  # earliest by timestamp
        bindings[cond.event_type] = chosen
        last_bound = chosen

    matched = tuple(e.get("event_id", "") for e in bindings.values())
    agents = tuple(
        sorted(
            {
                str(e.get("agent_instance_id", ""))
                for e in bindings.values()
                if e.get("agent_instance_id")
            }
        )
    )
    correlation_key = ""
    if bindings:
        correlation_key = str(next(iter(bindings.values())).get("correlation_key", ""))
    return PatternMatch(
        pattern_name=pattern.name,
        severity=pattern.severity,
        signal_kind=pattern.signal_kind,
        correlation_key=correlation_key,
        matched_event_ids=matched,
        agents=agents,
    )
