"""Tests for the cross-agent correlation EPA (Sprint 7).

These exercise the two headline multi-agent threats that per-agent EPAs and
flat correlation structurally cannot catch: prompt-injection propagation
across agents, and coordinated low-and-slow exfiltration distributed across
agents in one flow.
"""

from __future__ import annotations

import uuid

import pytest

from app.epa.cross_agent import (
    EXFIL_DATA_MIN,
    CrossAgentEPA,
    InMemoryCorrelationStore,
)
from app.epa.fleet import EpaFleet
from app.epa.store import InMemoryEnvelopeStore

pytestmark = pytest.mark.unit

ORG = str(uuid.uuid4())
FLOW = "task-flow-1"


def _ev(event_type, *, instance, flow=FLOW, depth=0, risk=0.0, action="allowed", asset="asset-1"):
    return {
        "org_id": ORG,
        "asset_id": asset,
        "agent_instance_id": instance,
        "session_id": "s1",
        "event_id": str(uuid.uuid4()),
        "correlation_key": flow,
        "causal_depth": depth,
        "event_type": event_type,
        "action_taken": action,
        "risk_score": risk,
    }


async def _run(epa, events):
    out = []
    for e in events:
        out += await epa.process(e)
    return out


class TestPropagationChain:
    async def test_multi_agent_injection_propagation_flags(self):
        epa = CrossAgentEPA(InMemoryCorrelationStore())
        # Agent A is hit (flagged), passes downstream to B which makes an
        # anomalous outbound call — a connected chain across 2 agents, ≥2 hops.
        events = [
            _ev("request", instance="A", depth=0, action="flagged", risk=0.8),
            _ev("tool_call", instance="A", depth=1),
            _ev("request", instance="B", depth=2),
            _ev("external_api_call", instance="B", depth=3),
        ]
        sigs = await _run(epa, events)
        kinds = {s.kind for s in sigs}
        assert "propagation_chain" in kinds
        chain = next(s for s in sigs if s.kind == "propagation_chain")
        assert set(chain.detail["agents"]) == {"A", "B"}
        assert chain.severity == "critical"

    async def test_single_agent_flow_does_not_flag(self):
        epa = CrossAgentEPA(InMemoryCorrelationStore())
        events = [
            _ev("request", instance="A", depth=0, action="flagged", risk=0.9),
            _ev("tool_call", instance="A", depth=1),
            _ev("external_api_call", instance="A", depth=2),
        ]
        sigs = await _run(epa, events)
        assert all(s.kind != "propagation_chain" for s in sigs)

    async def test_benign_cross_agent_flow_does_not_flag(self):
        # Two agents, but no behavioural shift and no exfil → no signal.
        epa = CrossAgentEPA(InMemoryCorrelationStore())
        events = [
            _ev("request", instance="A", depth=0),
            _ev("tool_call", instance="B", depth=1),
        ]
        sigs = await _run(epa, events)
        assert sigs == []

    async def test_fires_once_per_flow(self):
        epa = CrossAgentEPA(InMemoryCorrelationStore())
        events = [
            _ev("request", instance="A", depth=0, action="flagged", risk=0.8),
            _ev("request", instance="B", depth=2),
            _ev("external_api_call", instance="B", depth=3),
            _ev("external_api_call", instance="B", depth=4),  # would re-trigger
        ]
        sigs = await _run(epa, events)
        assert sum(1 for s in sigs if s.kind == "propagation_chain") == 1


class TestCoordinatedExfiltration:
    async def test_low_and_slow_across_agents_flags(self):
        epa = CrossAgentEPA(InMemoryCorrelationStore())
        events = []
        # Spread data access across 3 agents, each small, aggregate over the
        # threshold — none individually suspicious.
        for i in range(EXFIL_DATA_MIN + 2):
            events.append(_ev("memory_access", instance=f"agent{i % 3}", depth=i))
        events.append(_ev("external_api_call", instance="agent0", depth=99))
        sigs = await _run(epa, events)
        assert any(s.kind == "coordinated_exfiltration" for s in sigs)

    async def test_data_access_without_exfil_does_not_flag(self):
        epa = CrossAgentEPA(InMemoryCorrelationStore())
        events = [_ev("memory_access", instance=f"agent{i % 3}") for i in range(EXFIL_DATA_MIN + 5)]
        sigs = await _run(epa, events)
        assert all(s.kind != "coordinated_exfiltration" for s in sigs)

    async def test_no_correlation_key_is_ignored(self):
        epa = CrossAgentEPA(InMemoryCorrelationStore())
        e = _ev("memory_access", instance="A")
        e["correlation_key"] = ""
        assert await epa.process(e) == []


class TestFleetIntegration:
    async def test_fleet_drives_both_layers(self):
        received = []

        async def sink(s):
            received.append(s)

        fleet = EpaFleet(
            store=InMemoryEnvelopeStore(),
            sink=sink,
            cross_agent=CrossAgentEPA(InMemoryCorrelationStore()),
        )
        events = [
            _ev("request", instance="A", depth=0, action="flagged", risk=0.85),
            _ev("request", instance="B", depth=2),
            _ev("external_api_call", instance="B", depth=3),
        ]
        for e in events:
            await fleet.handle_event(e)
        assert any(s.kind == "propagation_chain" for s in received)
