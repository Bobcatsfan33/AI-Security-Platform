"""Tests for Tier-3 threat narratives (Sprint 8) — the T2→T3 collapse and the
SOAR mapping that carries the causal flow to analysts."""

from __future__ import annotations

import pytest

from app.epa.agent_epa import EpaSignal
from app.narratives.builder import NarrativeBuilder
from app.narratives.narrative import narrative_to_incident

pytestmark = pytest.mark.unit


def _sig(kind, severity, *, conf=0.6, agent="agent-1", flow="flow-1", title=None):
    return EpaSignal(
        agent_instance_id=agent,
        org_id="org-1",
        asset_id="asset-1",
        kind=kind,
        severity=severity,
        title=title or f"{kind} on {agent}",
        confidence=conf,
        correlation_key=flow,
    )


class TestGrouping:
    def test_signals_of_one_flow_collapse_to_one_narrative(self):
        sigs = [
            _sig("novel_transition", "high", agent="A"),
            _sig("volume_spike", "medium", agent="A"),
            _sig("propagation_chain", "critical", agent="flow:flow-1"),
        ]
        narratives = NarrativeBuilder().build(sigs)
        assert len(narratives) == 1
        n = narratives[0]
        assert n.signal_count == 3
        assert n.correlation_id == "flow-1"

    def test_different_flows_make_separate_narratives(self):
        sigs = [
            _sig("novel_transition", "high", flow="flow-1"),
            _sig("novel_transition", "high", flow="flow-2"),
        ]
        assert len(NarrativeBuilder().build(sigs)) == 2

    def test_signals_without_flow_group_by_agent(self):
        sigs = [
            _sig("volume_spike", "medium", agent="X", flow=""),
            _sig("risk_inflation", "high", agent="X", flow=""),
            _sig("volume_spike", "medium", agent="Y", flow=""),
        ]
        narratives = NarrativeBuilder().build(sigs)
        assert len(narratives) == 2
        by_agents = {n.agents for n in narratives}
        assert ("X",) in by_agents and ("Y",) in by_agents


class TestSeverityAndLead:
    def test_severity_is_max_of_contributors(self):
        sigs = [_sig("volume_spike", "low"), _sig("propagation_chain", "critical")]
        n = NarrativeBuilder().build(sigs)[0]
        assert n.severity == "critical"

    def test_lead_kind_titles_the_narrative(self):
        sigs = [
            _sig("volume_spike", "high", title="vol"),
            _sig("propagation_chain", "high", title="PROP"),
        ]
        n = NarrativeBuilder().build(sigs)[0]
        # Same severity → kind priority breaks the tie (propagation_chain wins).
        assert n.kind == "propagation_chain"
        assert n.title == "PROP"

    def test_confidence_is_max(self):
        sigs = [
            _sig("volume_spike", "medium", conf=0.4),
            _sig("novel_transition", "medium", conf=0.8),
        ]
        assert NarrativeBuilder().build(sigs)[0].confidence == 0.8

    def test_cross_agent_flow_agents_excluded_from_agent_list(self):
        sigs = [
            _sig("novel_transition", "high", agent="A"),
            _sig("propagation_chain", "critical", agent="flow:flow-1"),
        ]
        n = NarrativeBuilder().build(sigs)[0]
        assert n.agents == ("A",)  # the synthetic flow: id is not a real agent


class TestTimeline:
    def test_timeline_fetcher_is_invoked(self):
        captured = {}

        def fetcher(org, asset, root):
            captured["args"] = (org, asset, root)
            return [{"event_id": "e1"}, {"event_id": "e2"}]

        n = NarrativeBuilder(timeline_fetcher=fetcher).build([_sig("novel_transition", "high")])[0]
        assert len(n.causal_timeline) == 2
        assert captured["args"] == ("org-1", "asset-1", "flow-1")

    def test_timeline_failure_is_swallowed(self):
        def boom(org, asset, root):
            raise RuntimeError("clickhouse down")

        n = NarrativeBuilder(timeline_fetcher=boom).build([_sig("novel_transition", "high")])[0]
        assert n.causal_timeline == ()  # best-effort; narrative still built


class TestSoarMapping:
    def test_narrative_to_incident_carries_flow_and_timeline(self):
        def fetcher(org, asset, root):
            return [{"event_id": "e1", "event_type": "request"}]

        n = NarrativeBuilder(timeline_fetcher=fetcher).build(
            [_sig("propagation_chain", "critical", agent="flow:flow-1")]
        )[0]
        inc = narrative_to_incident(n)
        assert inc.correlation_id == "flow-1"
        assert inc.severity == "critical"
        assert inc.source == "epa_fleet"
        assert inc.detail["causal_timeline"] == [{"event_id": "e1", "event_type": "request"}]
        assert inc.detail["narrative_id"] == str(n.id)
