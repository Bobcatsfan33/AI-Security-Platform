"""Tests for the narrative pipeline + EPA consumer service (Sprint 15).

The integration test is the payoff of the whole RAPIDE build: synthetic attack
events published to a stream are consumed by the fleet, correlated, and land as
a persisted Tier-3 narrative in the store the workbench reads — end to end.
"""

from __future__ import annotations

import uuid

import pytest

from app.epa.cross_agent import CrossAgentEPA, InMemoryCorrelationStore
from app.epa.fleet import EpaFleet
from app.epa.service import EpaConsumerService
from app.epa.store import InMemoryEnvelopeStore
from app.feedback.store import InMemorySuppressionStore
from app.feedback.suppression import activate, suggest_from_narrative
from app.narratives.narrative import ThreatNarrative
from app.narratives.pipeline import NarrativePipeline, stable_narrative_id
from app.narratives.store import InMemoryNarrativeStore
from app.streaming.memory_backend import InMemoryEventBus
from app.epa.agent_epa import EpaSignal
from app.validation.scenarios import scenario_propagation_chain

pytestmark = pytest.mark.unit

ORG = str(uuid.uuid4())


def _sig(
    kind="propagation_chain", *, severity="critical", agent="A", flow="flow-1", asset="asset-1"
):
    return EpaSignal(
        agent_instance_id=agent,
        org_id=ORG,
        asset_id=asset,
        kind=kind,
        severity=severity,
        title=f"{kind}",
        correlation_key=flow,
    )


class TestPipeline:
    async def test_signals_persist_as_narrative(self):
        store = InMemoryNarrativeStore()
        pipe = NarrativePipeline(narrative_store=store)
        out = await pipe.ingest([_sig()])
        assert len(out) == 1
        nid = stable_narrative_id(ORG, "flow-1")
        got = await store.get(ORG, str(nid))
        assert got is not None and got.kind == "propagation_chain"

    async def test_same_flow_merges_into_one_incident(self):
        store = InMemoryNarrativeStore()
        pipe = NarrativePipeline(narrative_store=store)
        await pipe.ingest([_sig(kind="novel_transition", severity="high")])
        await pipe.ingest([_sig(kind="propagation_chain", severity="critical")])
        items = await store.list(ORG)
        assert len(items) == 1  # one incident for the flow
        n = items[0]
        assert n.signal_count == 2
        assert n.severity == "critical"  # max
        assert n.kind == "propagation_chain"  # lead

    async def test_active_suppression_marks_suppressed(self):
        nstore = InMemoryNarrativeStore()
        sstore = InMemorySuppressionStore()
        # Approve a suppression for this kind+asset.
        seed = ThreatNarrative.from_dict(
            {**_narrative_dict(kind="novel_transition"), "status": "false_positive"}
        )
        rule = activate(
            suggest_from_narrative(seed, reason="benign", created_by="a"), approved_by="admin"
        )
        await sstore.save(rule)

        pipe = NarrativePipeline(narrative_store=nstore, suppression_store=sstore)
        out = await pipe.ingest([_sig(kind="novel_transition", severity="high")])
        assert out[0].status == "suppressed"

    async def test_disposition_not_overridden_by_suppression(self):
        nstore = InMemoryNarrativeStore()
        sstore = InMemorySuppressionStore()
        nid = stable_narrative_id(ORG, "flow-1")
        # Pre-existing confirmed incident for this flow.
        confirmed = ThreatNarrative.from_dict(
            {**_narrative_dict(kind="novel_transition"), "id": str(nid), "status": "confirmed"}
        )
        await nstore.save(confirmed)
        # A matching active suppression exists.
        rule = activate(
            suggest_from_narrative(confirmed, reason="x", created_by="a"), approved_by="admin"
        )
        await sstore.save(rule)

        pipe = NarrativePipeline(narrative_store=nstore, suppression_store=sstore)
        out = await pipe.ingest([_sig(kind="novel_transition", severity="high")])
        assert out[0].status == "confirmed"  # analyst ruling preserved


class TestService:
    async def test_propagation_attack_lands_as_persisted_narrative(self):
        nstore = InMemoryNarrativeStore()
        fleet = EpaFleet(
            store=InMemoryEnvelopeStore(),
            cross_agent=CrossAgentEPA(InMemoryCorrelationStore()),
        )
        pipe = NarrativePipeline(narrative_store=nstore)
        bus = InMemoryEventBus()
        await bus.start()
        service = EpaConsumerService(consumer=bus, fleet=fleet, pipeline=pipe)

        scenario = scenario_propagation_chain()
        org = scenario.events[0]["org_id"]
        for ev in scenario.events:
            await service.process_one(ev)

        narratives = await nstore.list(org)
        kinds = {n.kind for n in narratives}
        assert "propagation_chain" in kinds, kinds
        assert service.narratives_written >= 1

    async def test_run_drains_bus_to_narratives(self):
        import asyncio

        nstore = InMemoryNarrativeStore()
        fleet = EpaFleet(
            store=InMemoryEnvelopeStore(),
            cross_agent=CrossAgentEPA(InMemoryCorrelationStore()),
        )
        pipe = NarrativePipeline(narrative_store=nstore)
        bus = InMemoryEventBus()
        service = EpaConsumerService(consumer=bus, fleet=fleet, pipeline=pipe)

        scenario = scenario_propagation_chain()
        for ev in scenario.events:
            await bus._queue.put(ev)  # enqueue raw wire dicts

        # run() starts the bus then consumes; stop it once it's draining so the
        # consume loop terminates after the queue empties.
        task = asyncio.create_task(service.run())
        await asyncio.sleep(0.05)
        await bus.stop()
        await asyncio.wait_for(task, timeout=2.0)

        assert service.events_processed == len(scenario.events)
        org = scenario.events[0]["org_id"]
        assert any(n.kind == "propagation_chain" for n in await nstore.list(org))


def _narrative_dict(*, kind: str) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "org_id": ORG,
        "correlation_id": "flow-1",
        "title": kind,
        "severity": "high",
        "kind": kind,
        "confidence": 0.7,
        "agents": ["A"],
        "asset_id": "asset-1",
        "signal_count": 1,
        "contributing": [],
        "causal_timeline": [],
        "created_at": "2026-06-01T00:00:00+00:00",
        "status": "open",
    }
