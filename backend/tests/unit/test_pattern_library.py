"""Tests for the ATLAS-mapped pattern library (Sprint 10): every shipped
pattern compiles + is mapped, representative patterns fire on synthetic attack
flows, and confirmed matches promote to regression test cases."""

from __future__ import annotations

import re

import pytest

from app.patterns.evaluator import evaluate
from app.patterns.library import library_by_name, library_specs, load_library
from app.patterns.promotion import pattern_match_to_testcase

pytestmark = pytest.mark.unit

_ATLAS_RE = re.compile(r"^AML\.T\d{4}$")


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


class TestLibraryIntegrity:
    def test_library_is_nonempty_and_all_compile(self):
        patterns = load_library()
        assert len(patterns) >= 10

    def test_every_pattern_has_valid_atlas_mapping(self):
        for p in load_library():
            assert p.atlas_techniques, f"{p.name} has no ATLAS mapping"
            for t in p.atlas_techniques:
                assert _ATLAS_RE.match(t), f"{p.name}: bad ATLAS id {t!r}"

    def test_every_pattern_has_version_and_category(self):
        for p in load_library():
            assert p.version >= 1
            assert p.category, f"{p.name} missing category"

    def test_names_are_unique(self):
        names = [s["name"] for s in library_specs()]
        assert len(names) == len(set(names))


class TestRepresentativePatternsFire:
    def test_unapproved_tool_invocation(self):
        p = library_by_name()["unapproved-tool-invocation"]
        ctx = {"tool_manifest": ["search", "summarize"]}
        events = [_ev("tool_call", eid="t1", ts=1, tool_name="shell_exec")]
        assert evaluate(p, events, context=ctx) is not None
        # An approved tool does not fire.
        ok = [_ev("tool_call", eid="t2", ts=1, tool_name="search")]
        assert evaluate(p, ok, context=ctx) is None

    def test_credential_access_then_egress(self):
        p = library_by_name()["credential-access-then-egress"]
        events = [
            _ev("file_access", eid="f1", ts=1, depth=1, resource="/var/secrets/db.key"),
            _ev("external_api_call", eid="x1", ts=20, depth=2),
        ]
        assert evaluate(p, events) is not None

    def test_jailbreak_then_unsafe_tool(self):
        p = library_by_name()["jailbreak-then-unsafe-tool"]
        events = [
            _ev("alert", eid="a1", ts=1, depth=1, category="jailbreak"),
            _ev("tool_call", eid="t1", ts=10, depth=2, tool_name="code_exec"),
        ]
        assert evaluate(p, events) is not None
        # A safe tool after the alert does not fire.
        safe = [
            _ev("alert", eid="a1", ts=1, depth=1, category="jailbreak"),
            _ev("tool_call", eid="t1", ts=10, depth=2, tool_name="search"),
        ]
        assert evaluate(p, safe) is None

    def test_multi_hop_propagation_chain(self):
        p = library_by_name()["multi-hop-instruction-propagation"]
        events = [
            _ev("policy_violation", eid="p1", ts=1, depth=1),
            _ev("tool_call", eid="t1", ts=2, depth=2),
            _ev("external_api_call", eid="x1", ts=3, depth=3),
        ]
        m = evaluate(p, events)
        assert m is not None
        assert set(m.matched_event_ids) == {"p1", "t1", "x1"}


class TestPromotion:
    def test_confirmed_match_promotes_to_testcase(self):
        p = library_by_name()["jailbreak-then-unsafe-tool"]
        events = [
            _ev("alert", eid="a1", ts=1, depth=1, category="jailbreak"),
            _ev("tool_call", eid="t1", ts=10, depth=2, tool_name="code_exec"),
        ]
        match = evaluate(p, events)
        tc = pattern_match_to_testcase(p, match)
        assert tc["category"] == "jailbreak"
        assert tc["mitre_atlas_id"] == "AML.T0054"
        assert tc["success_criteria"] == {"type": "pattern_fires", "pattern": p.name}
        assert tc["metadata"]["matched_event_ids"] == list(match.matched_event_ids)
        assert "regression" in tc["tags"]
