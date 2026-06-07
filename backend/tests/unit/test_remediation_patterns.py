"""Tests for the Phase-1 merge bonus: remediation also emits Pattern-DSL rules
that compile and fire (probe-to-rails feeds the behavioural-flow engine too)."""

from __future__ import annotations

import pytest

from app.patterns import compile_pattern, evaluate
from app.redteam.remediation import generate_plan

pytestmark = pytest.mark.unit


def test_plan_emits_pattern_rules_for_exploited_categories():
    plan = generate_plan(
        successful_categories={"prompt_injection": 0.8, "data_exfiltration": 0.5},
    )
    names = {p["name"] for p in plan.pattern_rules}
    assert "remediation-injection-then-tool" in names
    assert "remediation-staged-exfil" in names


def test_emitted_pattern_rules_all_compile():
    plan = generate_plan(
        successful_categories={
            "prompt_injection": 0.9,
            "data_exfiltration": 0.6,
            "credential_leakage": 0.4,
            "unsafe_tool_use": 0.3,
        },
    )
    assert len(plan.pattern_rules) == 4
    for spec in plan.pattern_rules:
        compile_pattern(spec)  # must not raise


def test_emitted_injection_pattern_actually_fires():
    plan = generate_plan(successful_categories={"prompt_injection": 0.8})
    spec = next(p for p in plan.pattern_rules if p["category"] == "prompt_injection")
    pattern = compile_pattern(spec)
    events = [
        {
            "event_id": "p1",
            "event_type": "policy_violation",
            "causal_depth": 0,
            "timestamp": "2026-06-01T00:00:01+00:00",
            "correlation_key": "f1",
        },
        {
            "event_id": "t1",
            "event_type": "tool_call",
            "causal_depth": 1,
            "timestamp": "2026-06-01T00:00:05+00:00",
            "correlation_key": "f1",
        },
    ]
    assert evaluate(pattern, events) is not None  # the rail fires on the flow


def test_no_successes_no_pattern_rules():
    plan = generate_plan(successful_categories={"prompt_injection": 0.0})
    assert plan.pattern_rules == []
