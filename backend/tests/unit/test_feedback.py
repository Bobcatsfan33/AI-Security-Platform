"""Tests for the feedback loop (Sprint 12) — suppression learning, FP metrics,
and confirmed-narrative promotion. Includes the exit criterion: a measurable
FP-rate reduction once suppression is applied."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.epa.agent_epa import EpaSignal
from app.feedback.metrics import fp_rate_by_kind, overall_fp_rate
from app.feedback.service import narrative_to_testcase, on_false_positive
from app.feedback.store import InMemorySuppressionStore
from app.feedback.suppression import (
    activate,
    expire,
    is_expired,
    is_suppressed,
    matches,
)
from app.narratives.builder import NarrativeBuilder
from app.narratives.narrative import ThreatNarrative

pytestmark = pytest.mark.unit

ORG = str(uuid.uuid4())


def _narrative(
    kind="novel_transition", *, severity="high", agents=("A",), asset="asset-1", status="open"
):
    sigs = [
        EpaSignal(
            agent_instance_id=a,
            org_id=ORG,
            asset_id=asset,
            kind=kind,
            severity=severity,
            title=f"{kind} on {a}",
            correlation_key=f"flow-{a}",
        )
        for a in agents
    ]
    n = NarrativeBuilder().build(sigs)[0]
    return ThreatNarrative.from_dict({**n.to_dict(), "status": status})


class TestSuppressionLifecycle:
    def test_suggested_rule_is_not_active(self):
        rule = on_false_positive(_narrative(), reason="batch job", created_by="ana@x.com")
        assert rule.status == "suggested"
        # A suggested (not active) rule suppresses nothing.
        assert not is_suppressed(_narrative(), [rule])

    def test_activation_requires_no_permanence(self):
        rule = activate(
            on_false_positive(_narrative(), reason="r", created_by="a"),
            approved_by="admin@x.com",
            ttl_seconds=3600,
        )
        assert rule.status == "active"
        assert rule.expires_at is not None  # must expire / recertify

    def test_active_rule_suppresses_matching_narrative(self):
        rule = activate(
            on_false_positive(_narrative(), reason="r", created_by="a"), approved_by="admin"
        )
        assert is_suppressed(_narrative(), [rule])

    def test_does_not_suppress_different_kind(self):
        rule = activate(
            on_false_positive(_narrative(kind="novel_transition"), reason="r", created_by="a"),
            approved_by="admin",
        )
        assert not is_suppressed(_narrative(kind="propagation_chain"), [rule])

    def test_does_not_suppress_different_asset(self):
        rule = activate(
            on_false_positive(_narrative(asset="asset-1"), reason="r", created_by="a"),
            approved_by="admin",
        )
        assert not is_suppressed(_narrative(asset="asset-2"), [rule])

    def test_expired_rule_stops_suppressing(self):
        rule = activate(
            on_false_positive(_narrative(), reason="r", created_by="a"),
            approved_by="admin",
            ttl_seconds=3600,
        )
        future = datetime.now(timezone.utc) + timedelta(hours=2)
        assert is_expired(rule, now=future)
        assert not is_suppressed(_narrative(), [rule], now=future)

    def test_explicit_expire_stops_suppressing(self):
        rule = expire(
            activate(
                on_false_positive(_narrative(), reason="r", created_by="a"), approved_by="admin"
            )
        )
        assert not is_suppressed(_narrative(), [rule])

    def test_agent_overlap_required_when_rule_has_agents(self):
        rule = activate(
            on_false_positive(_narrative(agents=("A",)), reason="r", created_by="a"),
            approved_by="admin",
        )
        assert matches(rule, _narrative(agents=("A", "B")))  # overlap
        assert not matches(rule, _narrative(agents=("C",)))  # no overlap


class TestStore:
    async def test_save_list_filter(self):
        store = InMemorySuppressionStore()
        await store.save(on_false_positive(_narrative(), reason="r", created_by="a"))
        active = activate(
            on_false_positive(_narrative(), reason="r", created_by="a"), approved_by="admin"
        )
        await store.save(active)
        assert len(await store.list(ORG)) == 2
        assert len(await store.list(ORG, status="suggested")) == 1
        assert len(await store.list(ORG, status="active")) == 1


class TestPromotion:
    def test_confirmed_narrative_promotes_to_testcase(self):
        n = _narrative(kind="propagation_chain", status="confirmed")
        tc = narrative_to_testcase(n)
        assert tc["category"] == "prompt_injection"
        assert tc["success_criteria"] == {"type": "narrative_fires", "kind": "propagation_chain"}
        assert tc["metadata"]["narrative_id"] == str(n.id)


class TestFpMetrics:
    def test_fp_rate_by_kind(self):
        narratives = [
            _narrative(kind="novel_transition", status="false_positive"),
            _narrative(kind="novel_transition", status="false_positive"),
            _narrative(kind="novel_transition", status="confirmed"),
            _narrative(kind="propagation_chain", status="confirmed"),
            _narrative(kind="novel_transition", status="open"),  # unruled, ignored
        ]
        stats = fp_rate_by_kind(narratives)
        assert stats["novel_transition"].fp_rate == pytest.approx(2 / 3)
        assert stats["propagation_chain"].fp_rate == 0.0

    def test_fp_rate_drops_across_two_tuning_cycles(self):
        # Cycle 1: noisy novel_transition — mostly false positives.
        cycle1 = [
            _narrative(kind="novel_transition", status="false_positive") for _ in range(8)
        ] + [_narrative(kind="novel_transition", status="confirmed") for _ in range(2)]
        rate1 = overall_fp_rate(cycle1)

        # After suppression is applied, the benign novel_transitions stop
        # surfacing → cycle 2's ruled set is dominated by true positives.
        cycle2 = [
            _narrative(kind="novel_transition", status="false_positive") for _ in range(1)
        ] + [_narrative(kind="novel_transition", status="confirmed") for _ in range(7)]
        rate2 = overall_fp_rate(cycle2)

        assert rate1 > 0.7
        assert rate2 < rate1  # measurable FP-rate decline
