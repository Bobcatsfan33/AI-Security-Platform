"""Tests for the EPA fleet (Sprint 5) — stateful streaming detection.

Covers the behavioral envelope (maturity, risk stats, serde), the four
streaming evaluators (novel transition, volume spike, risk inflation,
behavioral drift), cold-start safety, and the fleet supervisor routing events
to per-instance EPAs off the in-memory streaming bus.
"""

from __future__ import annotations

import uuid

import pytest

from app.epa.agent_epa import AgentEPA
from app.epa.envelope import MATURITY_MIN, BehavioralEnvelope
from app.epa.fleet import EpaFleet
from app.epa.store import InMemoryEnvelopeStore
from app.streaming.memory_backend import InMemoryEventBus

pytestmark = pytest.mark.unit

ORG = str(uuid.uuid4())
ASSET = str(uuid.uuid4())


def _ev(
    event_type, *, tool=None, parent=None, event_id=None, risk=0.0, session="s1", instance="agent-1"
):
    return {
        "org_id": ORG,
        "asset_id": ASSET,
        "agent_instance_id": instance,
        "session_id": session,
        "event_id": event_id or str(uuid.uuid4()),
        "parent_event_id": parent,
        "event_type": event_type,
        "tool_name": tool,
        "action_taken": "allowed",
        "risk_score": risk,
    }


def _warm(epa, n=MATURITY_MIN, *, tool="search", risk=0.0):
    """Feed n benign events establishing a stable request→tool baseline."""
    for _ in range(n):
        req = _ev("request", risk=risk)
        epa.process(req)
        epa.process(_ev("tool_call", tool=tool, parent=req["event_id"], risk=risk))


# ─────────────────────────────────────────────── Envelope


class TestEnvelope:
    def test_immature_until_threshold(self):
        env = BehavioralEnvelope(agent_instance_id="a")
        for _ in range(MATURITY_MIN - 1):
            env.event_count += 1
        assert not env.mature
        env.event_count += 1
        assert env.mature

    def test_risk_welford_mean(self):
        env = BehavioralEnvelope(agent_instance_id="a")
        for r in (0.2, 0.4, 0.6):
            env.record_risk(r)
        assert env.risk_mean == pytest.approx(0.4, abs=1e-9)

    def test_serialization_round_trip(self):
        env = BehavioralEnvelope(agent_instance_id="a", org_id=ORG)
        env.record_node("tool:x")
        env.record_risk(0.5)
        env.record_edge(("request:request", "tool:x"), novel=True)
        env.remember_event("e1", "tool:x")
        restored = BehavioralEnvelope.from_dict(env.to_dict())
        assert restored.node_counts == env.node_counts
        assert restored.seen_edges == env.seen_edges
        assert restored.risk_ewma == env.risk_ewma
        assert restored.resolve_parent_node("e1") == "tool:x"


# ─────────────────────────────────────────────── Evaluators


class TestColdStart:
    def test_no_signals_before_maturity(self):
        epa = AgentEPA(BehavioralEnvelope(agent_instance_id="a"))
        signals = []
        # Wildly anomalous behaviour, but immature → silence. Single events so
        # event_count stays below MATURITY_MIN for the whole loop.
        for i in range(MATURITY_MIN - 1):
            signals += epa.process(_ev("tool_call", tool=f"shell{i}", risk=0.99))
        assert not epa.env.mature
        assert signals == []


class TestNovelTransition:
    def test_new_edge_after_maturity_flags(self):
        epa = AgentEPA(BehavioralEnvelope(agent_instance_id="a"))
        _warm(epa)
        req = _ev("request")
        epa.process(req)
        # A transition to a never-seen tool node.
        sigs = epa.process(_ev("tool_call", tool="shell_exec", parent=req["event_id"]))
        kinds = {s.kind for s in sigs}
        assert "novel_transition" in kinds
        nt = next(s for s in sigs if s.kind == "novel_transition")
        assert "shell_exec" in nt.title

    def test_known_edge_does_not_flag(self):
        epa = AgentEPA(BehavioralEnvelope(agent_instance_id="a"))
        _warm(epa)
        req = _ev("request")
        epa.process(req)
        sigs = epa.process(_ev("tool_call", tool="search", parent=req["event_id"]))
        assert all(s.kind != "novel_transition" for s in sigs)


class TestRiskInflation:
    def test_risk_climb_after_baseline_flags(self):
        epa = AgentEPA(BehavioralEnvelope(agent_instance_id="a"))
        _warm(epa, risk=0.0)  # baseline risk ~0
        all_sigs = []
        for _ in range(6):  # EWMA climbs fast on sustained high risk
            req = _ev("request", risk=0.95)
            all_sigs += epa.process(req)
            all_sigs += epa.process(
                _ev("tool_call", tool="search", parent=req["event_id"], risk=0.95)
            )
        assert any(s.kind == "risk_inflation" for s in all_sigs)

    def test_stable_low_risk_does_not_flag(self):
        epa = AgentEPA(BehavioralEnvelope(agent_instance_id="a"))
        _warm(epa, risk=0.0)
        sigs = []
        for _ in range(6):
            req = _ev("request", risk=0.05)
            sigs += epa.process(req)
            sigs += epa.process(_ev("tool_call", tool="search", parent=req["event_id"], risk=0.05))
        assert all(s.kind != "risk_inflation" for s in sigs)


class TestVolumeSpike:
    def test_hammering_one_node_spikes(self):
        epa = AgentEPA(BehavioralEnvelope(agent_instance_id="a"))
        # Build a multi-node baseline so the node-count distribution has spread.
        for i in range(MATURITY_MIN):
            epa.process(_ev("tool_call", tool=f"t{i % 8}"))
        all_sigs = []
        # Hammer one tool far above the mean count.
        for _ in range(60):
            all_sigs += epa.process(_ev("tool_call", tool="hot"))
        assert any(s.kind == "volume_spike" for s in all_sigs)


class TestBehavioralDrift:
    def test_burst_of_novel_edges_flags_abrupt_drift(self):
        epa = AgentEPA(BehavioralEnvelope(agent_instance_id="a"))
        _warm(epa)  # stable: low lifetime novelty rate, baseline frozen
        all_sigs = []
        # A burst of distinct new transitions → recent novelty rate spikes.
        for i in range(40):
            req = _ev("request")
            epa.process(req)
            all_sigs += epa.process(_ev("tool_call", tool=f"newtool{i}", parent=req["event_id"]))
        assert any(s.kind == "behavioral_drift" for s in all_sigs)


# ─────────────────────────────────────────────── Fleet


class TestFleet:
    async def test_routes_events_to_per_instance_epas(self):
        store = InMemoryEnvelopeStore()
        fleet = EpaFleet(store=store)
        # Two instances; events for each must accumulate in separate envelopes.
        for _ in range(5):
            await fleet.handle_event(_ev("request", instance="agent-A"))
            await fleet.handle_event(_ev("request", instance="agent-B"))
        env_a = await store.load("agent-A")
        env_b = await store.load("agent-B")
        assert env_a.event_count == 5
        assert env_b.event_count == 5
        assert fleet.events_processed == 10

    async def test_envelope_persists_across_handler_calls(self):
        store = InMemoryEnvelopeStore()
        fleet = EpaFleet(store=store)
        await fleet.handle_event(_ev("request", instance="agent-X"))
        await fleet.handle_event(_ev("tool_call", tool="search", instance="agent-X"))
        env = await store.load("agent-X")
        assert env.event_count == 2

    async def test_signals_reach_sink(self):
        store = InMemoryEnvelopeStore()
        received = []

        async def sink(sig):
            received.append(sig)

        fleet = EpaFleet(store=store, sink=sink)
        # Warm one instance to maturity through the fleet, then a novel edge.
        for _ in range(MATURITY_MIN):
            req = _ev("request", instance="agent-Z")
            await fleet.handle_event(req)
            await fleet.handle_event(
                _ev("tool_call", tool="search", parent=req["event_id"], instance="agent-Z")
            )
        req = _ev("request", instance="agent-Z")
        await fleet.handle_event(req)
        await fleet.handle_event(
            _ev("tool_call", tool="exfil", parent=req["event_id"], instance="agent-Z")
        )
        assert any(s.kind == "novel_transition" for s in received)

    async def test_run_drains_in_memory_bus(self):
        bus = InMemoryEventBus()
        await bus.start()
        store = InMemoryEnvelopeStore()
        fleet = EpaFleet(store=store)
        # Publish a few events, then stop the bus so run() terminates.
        from app.telemetry.runtime_event import RuntimeEvent

        for _ in range(3):
            await bus.publish(
                RuntimeEvent(
                    org_id=uuid.UUID(ORG),
                    asset_id=uuid.UUID(ASSET),
                    agent_instance_id="agent-run",
                    session_id="s1",
                    event_type="request",
                    direction="inbound",
                    enforcement_level="fast",
                    pipeline_exit_stage="no_match",
                    action_taken="allowed",
                )
            )
        await bus.stop()  # consume() drains remaining items then terminates
        await fleet.run(bus)  # runs to completion over the drained bus
        assert fleet.events_processed == 3
