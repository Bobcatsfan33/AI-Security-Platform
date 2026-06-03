"""Tests for the Complex Event Pattern DSL (Sprint 9).

Includes the brief's exact four-condition example (cross-workspace read with no
active task, followed by unapproved egress within 60s) — the pattern that is
impossible to express in flat SIEM rule syntax (brief §3.3).
"""

from __future__ import annotations

import pytest

from app.patterns.compiled import PatternValidationError, compile_pattern
from app.patterns.evaluator import evaluate
from app.patterns.registry import PatternRegistry

pytestmark = pytest.mark.unit


def _ev(event_type, *, eid, ts, depth=0, instance="A", flow="flow-1", **fields):
    e = {
        "event_id": eid,
        "event_type": event_type,
        "timestamp": f"2026-06-01T00:00:{ts:02d}+00:00",
        "causal_depth": depth,
        "agent_instance_id": instance,
        "correlation_key": flow,
    }
    e.update(fields)
    return e


# The brief's §3.3 pattern.
BRIEF_PATTERN = {
    "name": "cross-workspace-read-then-egress",
    "severity": "critical",
    "signal_kind": "pattern_match",
    "all_of": [
        {"event": "memory_access", "where": {"workspace": {"ne": {"$ctx": "home_workspace"}}}},
        {"absent": {"event": "task_assignment"}},
        {
            "event": "external_api_call",
            "within": 60,
            "causally_after": "memory_access",
            "where": {"endpoint": {"not_in": {"$ctx": "tool_manifest"}}},
        },
    ],
}

CTX = {"home_workspace": "agentA-home", "tool_manifest": ["approved.api.com"]}


class TestCompile:
    def test_brief_pattern_compiles(self):
        p = compile_pattern(BRIEF_PATTERN)
        assert p.name == "cross-workspace-read-then-egress"
        assert p.severity == "critical"
        assert len(p.conditions) == 3
        assert any(c.absent for c in p.conditions)

    def test_missing_name_rejected(self):
        with pytest.raises(PatternValidationError):
            compile_pattern({"all_of": [{"event": "x"}]})

    def test_empty_all_of_rejected(self):
        with pytest.raises(PatternValidationError):
            compile_pattern({"name": "p", "all_of": []})

    def test_unknown_op_rejected(self):
        with pytest.raises(PatternValidationError):
            compile_pattern({"name": "p", "all_of": [{"event": "x", "where": {"f": {"bogus": 1}}}]})

    def test_causally_after_must_reference_earlier_condition(self):
        with pytest.raises(PatternValidationError):
            compile_pattern(
                {
                    "name": "p",
                    "all_of": [{"event": "a", "causally_after": "nonexistent"}],
                }
            )


class TestBriefPatternEvaluation:
    def test_full_attack_matches(self):
        p = compile_pattern(BRIEF_PATTERN)
        events = [
            _ev("memory_access", eid="m1", ts=1, depth=1, workspace="other-home"),
            _ev("external_api_call", eid="x1", ts=30, depth=2, endpoint="evil.com"),
        ]
        m = evaluate(p, events, context=CTX)
        assert m is not None
        assert m.pattern_name == "cross-workspace-read-then-egress"
        assert set(m.matched_event_ids) == {"m1", "x1"}

    def test_same_workspace_read_does_not_match(self):
        p = compile_pattern(BRIEF_PATTERN)
        events = [
            _ev("memory_access", eid="m1", ts=1, depth=1, workspace="agentA-home"),
            _ev("external_api_call", eid="x1", ts=30, depth=2, endpoint="evil.com"),
        ]
        assert evaluate(p, events, context=CTX) is None

    def test_active_task_suppresses_match(self):
        # The 'absent' condition: an active task_assignment means this is
        # legitimate cross-agent context → no alert.
        p = compile_pattern(BRIEF_PATTERN)
        events = [
            _ev("memory_access", eid="m1", ts=1, depth=1, workspace="other-home"),
            _ev("task_assignment", eid="t1", ts=2, depth=1),
            _ev("external_api_call", eid="x1", ts=30, depth=2, endpoint="evil.com"),
        ]
        assert evaluate(p, events, context=CTX) is None

    def test_approved_endpoint_does_not_match(self):
        p = compile_pattern(BRIEF_PATTERN)
        events = [
            _ev("memory_access", eid="m1", ts=1, depth=1, workspace="other-home"),
            _ev("external_api_call", eid="x1", ts=30, depth=2, endpoint="approved.api.com"),
        ]
        assert evaluate(p, events, context=CTX) is None

    def test_picks_in_window_candidate_ignoring_before_read(self):
        # x2 precedes the read (negative gap → outside the causal window); x1 is
        # 29s after (within 60s). The evaluator must skip x2 and bind x1.
        p = compile_pattern(BRIEF_PATTERN)
        events = [
            _ev("memory_access", eid="m1", ts=1, depth=1, workspace="other-home"),
            _ev("external_api_call", eid="x1", ts=30, depth=2, endpoint="evil.com"),
            _ev("external_api_call", eid="x2", ts=0, depth=2, endpoint="evil.com"),
        ]
        m = evaluate(p, events, context=CTX)
        assert m is not None and "x1" in m.matched_event_ids
        assert "x2" not in m.matched_event_ids

    def test_egress_not_causally_after_read_does_not_match(self):
        p = compile_pattern(BRIEF_PATTERN)
        # external_api_call at depth 1 (not downstream of the depth-1 read).
        events = [
            _ev("memory_access", eid="m1", ts=1, depth=2, workspace="other-home"),
            _ev("external_api_call", eid="x1", ts=30, depth=1, endpoint="evil.com"),
        ]
        assert evaluate(p, events, context=CTX) is None


class TestRegistry:
    def test_apply_specs_swaps_atomically(self):
        reg = PatternRegistry()
        loaded, errors = reg.apply_specs([BRIEF_PATTERN])
        assert loaded == 1 and errors == []
        assert reg.patterns[0].name == "cross-workspace-read-then-egress"

    def test_bad_spec_skipped_not_fatal(self):
        reg = PatternRegistry()
        loaded, errors = reg.apply_specs([BRIEF_PATTERN, {"name": "broken", "all_of": []}])
        assert loaded == 1
        assert len(errors) == 1 and "broken" in errors[0]

    def test_reload_replaces_previous_set(self):
        reg = PatternRegistry()
        reg.apply_specs([BRIEF_PATTERN])
        reg.apply_specs([{"name": "other", "all_of": [{"event": "request"}]}])
        assert len(reg.patterns) == 1
        assert reg.patterns[0].name == "other"
