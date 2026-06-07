"""Phase 2.5 bridge into the running system: an AI Guard verdict published
through the NarrativePipeline lands as a Tier-3 narrative in the workbench
store, and joins the behavioural flow that shares its correlation_key.

The bridge conversion itself is covered in test_aiguard_rapide_merge.py; this
file covers the *publishing* glue (app.aiguard.publish).
"""

from __future__ import annotations

import uuid

import pytest

from app.aiguard.publish import (
    NarrativeSignalPublisher,
    get_publisher,
    maybe_publish_inspection,
    reset_for_tests,
    set_publisher,
)
from app.aiguard.response import AIGuardResponse, DetectorOutcome
from app.epa.agent_epa import EpaSignal
from app.narratives.pipeline import NarrativePipeline, stable_narrative_id
from app.narratives.store import InMemoryNarrativeStore

pytestmark = pytest.mark.unit

ORG = str(uuid.uuid4())


def _resp(action="block"):
    return AIGuardResponse(
        action=action,
        direction="inbound",
        triggered=("prompt_injection",) if action != "allow" else (),
        detectors=(
            DetectorOutcome(
                name="prompt_injection",
                category="prompt_injection",
                confidence=0.92,
                threshold=0.6,
                triggered=action != "allow",
                action=action,
                severity="high",
            ),
        ),
        latency_ms=1.0,
    )


def _publisher() -> tuple[NarrativeSignalPublisher, InMemoryNarrativeStore]:
    store = InMemoryNarrativeStore()
    return NarrativeSignalPublisher(NarrativePipeline(narrative_store=store)), store


class TestNarrativeSignalPublisher:
    async def test_publish_lands_a_narrative(self):
        pub, store = _publisher()
        signal = EpaSignal(
            agent_instance_id="planner",
            org_id=ORG,
            asset_id="asset-1",
            kind="content_violation",
            severity="high",
            title="AI Guard block: prompt_injection (inbound)",
            confidence=0.92,
            correlation_key="flow-1",
        )
        narratives = await pub.publish(signal)
        assert len(narratives) == 1

        stored = await store.get(ORG, str(stable_narrative_id(ORG, "flow-1")))
        assert stored is not None
        assert stored.kind == "content_violation"

    async def test_content_signal_joins_behavioural_flow(self):
        """A content_violation sharing a flow's correlation_key merges into the
        same incident as a prior behavioural signal — not a duplicate."""
        pub, store = _publisher()
        # A behavioural signal lands first for flow-7.
        behavioural = EpaSignal(
            agent_instance_id="planner",
            org_id=ORG,
            asset_id="asset-1",
            kind="novel_transition",
            severity="medium",
            title="Novel transition",
            correlation_key="flow-7",
        )
        await pub.publish(behavioural)
        # Then a content violation on the same flow.
        content = EpaSignal(
            agent_instance_id="planner",
            org_id=ORG,
            asset_id="asset-1",
            kind="content_violation",
            severity="high",
            title="AI Guard block: prompt_injection (inbound)",
            correlation_key="flow-7",
        )
        await pub.publish(content)

        nid = stable_narrative_id(ORG, "flow-7")
        stored = await store.get(ORG, str(nid))
        assert stored is not None
        # One unified incident, severity escalated to the content finding's high.
        assert stored.severity == "high"
        assert stored.signal_count == 2


class TestMaybePublishInspection:
    async def test_allow_publishes_nothing(self):
        pub, _ = _publisher()
        out = await maybe_publish_inspection(
            _resp("allow"),
            pub,
            org_id=ORG,
            asset_id="a",
            agent_instance_id="ag",
            correlation_key="flow-1",
        )
        assert out == []

    async def test_block_publishes_narrative(self):
        pub, _ = _publisher()
        out = await maybe_publish_inspection(
            _resp("block"),
            pub,
            org_id=ORG,
            asset_id="a",
            agent_instance_id="ag",
            correlation_key="flow-2",
        )
        assert len(out) == 1
        assert out[0].kind == "content_violation"

    async def test_no_publisher_is_a_noop(self):
        out = await maybe_publish_inspection(
            _resp("block"), None, org_id=ORG, asset_id="a", agent_instance_id="ag"
        )
        assert out == []

    async def test_publish_failure_is_swallowed(self):
        class _Boom:
            async def publish(self, signal: object) -> list:
                raise RuntimeError("redis down")

        out = await maybe_publish_inspection(
            _resp("block"), _Boom(), org_id=ORG, asset_id="a", agent_instance_id="ag"
        )
        assert out == []  # best-effort: never raises


class TestProcessWidePublisher:
    def test_set_get_reset(self):
        reset_for_tests()
        assert get_publisher() is None
        pub, _ = _publisher()
        set_publisher(pub)
        assert get_publisher() is pub
        reset_for_tests()
        assert get_publisher() is None
