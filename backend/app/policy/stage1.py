"""Stage 1 policy enforcement — regex / keyword / PII / tool firewall.

The fast path. Sub-1ms p99 latency budget. No I/O, no allocations in
the hot loop, no external library calls. Every rule is pre-compiled
into a :class:`CompiledRule`; this module just walks the rule list and
runs match() against the input text.

Behavior summary:
- Walk all enabled rules in order. Stop at the first MATCH whose action
  is "block" — that's the most aggressive verdict and short-circuits.
- For non-blocking matches (flag / log_only), accumulate them but keep
  walking so we can find a more severe one if present.
- If no rule matches, return ``matched=False`` so the orchestrator can
  pass to Stage 2 (or just allow, in fast-mode).
- Tool firewall is checked separately when the input context includes
  a tool call.
"""

from __future__ import annotations

import re
import time
from typing import Any

from app.policy.compiled import CompiledPolicy, CompiledRule, luhn_check
from app.policy.types import (
    Direction,
    PolicyInput,
    Severity,
    StageResult,
)

# ─────────────────────────────────────────────── Engine


class Stage1RegexEngine:
    """Stage 1 deterministic engine. Stateless — safe to share across goroutines.

    Implementations of higher-level cache management (compiled policy
    lookup, environment filtering) live above this layer in the
    pipeline orchestrator.
    """

    async def evaluate(
        self,
        *,
        input_: PolicyInput,
        policy: CompiledPolicy,
        environment: str | None = None,
    ) -> StageResult:
        start = time.perf_counter_ns()

        # 1. Tool firewall — applies only when the input describes a tool call
        tool_call = input_.context.get("tool_call") if input_.context else None
        if tool_call:
            tool_result = self._check_tool_firewall(
                tool_name=str(tool_call.get("name", "")),
                policy=policy,
            )
            if tool_result is not None:
                return self._stamp_latency(tool_result, start)

        # 2. Walk enabled rules. Track the most severe match so we never miss
        #    a critical one because a low-severity rule fired first.
        accumulated: list[StageResult] = []
        for rule in policy.rules:
            if not rule.enabled:
                continue
            if environment and rule.environments and environment not in rule.environments:
                continue

            match = self._match_rule(rule=rule, text=input_.text)
            if match is None:
                continue

            # Block actions short-circuit immediately
            if rule.action == "block":
                return self._stamp_latency(match, start)
            accumulated.append(match)

        if accumulated:
            # Pick highest severity
            chosen = max(accumulated, key=lambda r: _SEVERITY_RANK[r.severity])
            return self._stamp_latency(chosen, start)

        # 3. No match
        return self._stamp_latency(
            StageResult(stage="stage1_regex", matched=False, action="allowed"),
            start,
        )

    # ─────────────────────────────────────────── helpers

    def _match_rule(self, *, rule: CompiledRule, text: str) -> StageResult | None:
        """Return a StageResult if the rule matches, else None."""
        if rule.type == "regex":
            for pattern in rule.regex_patterns:
                m = pattern.search(text)
                if m is not None:
                    return _result_for(rule=rule, evidence={"matched_text": _redact_match(m)})

        elif rule.type == "keyword":
            lowered = text.lower()
            for kw in rule.keywords:
                if kw and kw in lowered:
                    return _result_for(rule=rule, evidence={"keyword": kw})

        elif rule.type == "pii_pattern":
            for pattern in rule.regex_patterns:
                m = pattern.search(text)
                if m is None:
                    continue
                # Credit card regex over-fires; require Luhn
                if pattern.pattern.startswith(r"\b(?:\d[- ]?){12,18}"):
                    digits = re.sub(r"\D", "", m.group(0))
                    if not luhn_check(digits):
                        continue
                return _result_for(rule=rule, evidence={"pii_detected": True})

        # rate_limit and custom rule types are scaffolded but not implemented
        # in Sprint 2 — they require state (per-session counters) which
        # belongs in the orchestrator, not the stage engine. Skip.
        return None

    def _check_tool_firewall(self, *, tool_name: str, policy: CompiledPolicy) -> StageResult | None:
        if not tool_name:
            return None
        if tool_name in policy.tool_denylist:
            return StageResult(
                stage="stage1_regex",
                matched=True,
                action="blocked",
                severity="critical",
                category="unsafe_tool_use",
                rule_id="tool_firewall:denylist",
                confidence=1.0,
                reason=f"tool {tool_name!r} is on the denylist",
                evidence={"tool_name": tool_name},
            )
        if tool_name in policy.tool_approval_required:
            return StageResult(
                stage="stage1_regex",
                matched=True,
                action="escalated",
                severity="high",
                category="unsafe_tool_use",
                rule_id="tool_firewall:approval_required",
                confidence=1.0,
                reason=f"tool {tool_name!r} requires approval",
                evidence={"tool_name": tool_name},
            )
        # Allowlist enforcement: if an allowlist is configured and this tool
        # isn't on it, block. An empty allowlist is interpreted as "no
        # allowlist enforcement" rather than "block everything".
        if policy.tool_allowlist and tool_name not in policy.tool_allowlist:
            return StageResult(
                stage="stage1_regex",
                matched=True,
                action="blocked",
                severity="high",
                category="unsafe_tool_use",
                rule_id="tool_firewall:not_allowlisted",
                confidence=1.0,
                reason=f"tool {tool_name!r} is not on the allowlist",
                evidence={"tool_name": tool_name},
            )
        return None

    @staticmethod
    def _stamp_latency(result: StageResult, start_ns: int) -> StageResult:
        latency_us = (time.perf_counter_ns() - start_ns) // 1000
        # Single chokepoint for every Stage 1 result — stamp the honest mode.
        return StageResult(
            stage=result.stage,
            matched=result.matched,
            action=result.action,
            severity=result.severity,
            category=result.category,
            rule_id=result.rule_id,
            confidence=result.confidence,
            reason=result.reason,
            latency_us=int(latency_us),
            evidence=result.evidence,
            mode="stage1_regex",
        )


# ─────────────────────────────────────────────── helpers


_SEVERITY_RANK: dict[Severity, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _result_for(*, rule: CompiledRule, evidence: dict[str, Any]) -> StageResult:
    """Build a StageResult from a matched rule. Confidence is always 1.0
    on Stage 1 matches because the rule was deterministic."""
    return StageResult(
        stage="stage1_regex",
        matched=True,
        action=_action_to_taken(rule.action),
        severity=rule.severity,
        category=rule.category,
        rule_id=rule.id or rule.name,
        confidence=1.0,
        reason=f"matched {rule.type} rule {rule.name!r}",
        evidence=evidence,
    )


_ACTION_MAP: dict[str, str] = {
    "block": "blocked",
    "flag": "flagged",
    "modify": "modified",
    "escalate": "escalated",
    "log_only": "allowed",
}


def _action_to_taken(action: str) -> Any:
    return _ACTION_MAP.get(action, "flagged")


def _redact_match(match: re.Match[str]) -> str:
    """Return a length-preserving redaction so audit logs don't echo PII."""
    raw = match.group(0)
    if len(raw) <= 4:
        return "*" * len(raw)
    # Keep the first and last 2 chars so an investigator can sanity-check
    # the regex was right, but never log the full sensitive value.
    return raw[:2] + "*" * (len(raw) - 4) + raw[-2:]


# ─────────────────────────────────────────────── Module-level convenience


_engine = Stage1RegexEngine()


async def evaluate(
    *,
    text: str,
    direction: Direction,
    policy: CompiledPolicy,
    asset_id: str | None = None,
    session_id: str | None = None,
    context: dict[str, Any] | None = None,
    environment: str | None = None,
) -> StageResult:
    """Top-level Stage 1 entrypoint.

    Constructs a PolicyInput from the loose arguments and invokes the
    shared engine. Convenience wrapper for callers that aren't going
    through the full pipeline orchestrator yet.
    """
    return await _engine.evaluate(
        input_=PolicyInput(
            text=text,
            direction=direction,
            asset_id=asset_id,
            session_id=session_id,
            context=context or {},
        ),
        policy=policy,
        environment=environment,
    )
