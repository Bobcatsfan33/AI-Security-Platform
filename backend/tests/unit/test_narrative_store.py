"""Tests for the narrative store + disposition (Sprint 11 workbench backend)."""

from __future__ import annotations

import uuid

import pytest

from app.epa.agent_epa import EpaSignal
from app.narratives.builder import NarrativeBuilder
from app.narratives.narrative import ThreatNarrative
from app.narratives.store import InMemoryNarrativeStore, apply_disposition

pytestmark = pytest.mark.unit

ORG = str(uuid.uuid4())


def _narrative(severity="high", status="open", org=ORG):
    sig = EpaSignal(
        agent_instance_id="A",
        org_id=org,
        asset_id="asset-1",
        kind="propagation_chain",
        severity=severity,
        title="t",
        correlation_key="flow-1",
    )
    n = NarrativeBuilder().build([sig])[0]
    return ThreatNarrative.from_dict({**n.to_dict(), "status": status})


class TestSerialization:
    def test_round_trip(self):
        n = _narrative()
        restored = ThreatNarrative.from_dict(n.to_dict())
        assert restored.id == n.id
        assert restored.severity == n.severity
        assert restored.correlation_id == n.correlation_id


class TestDisposition:
    def test_apply_disposition_is_immutable_update(self):
        n = _narrative()
        updated = apply_disposition(
            n, status="false_positive", rationale="benign batch job", assignee="ana@x.com"
        )
        assert n.status == "open"  # original unchanged
        assert updated.status == "false_positive"
        assert updated.rationale == "benign batch job"
        assert updated.assignee == "ana@x.com"
        assert updated.disposition_at is not None
        assert updated.id == n.id  # same incident


class TestStore:
    async def test_save_and_get(self):
        store = InMemoryNarrativeStore()
        n = _narrative()
        await store.save(n)
        got = await store.get(ORG, str(n.id))
        assert got is not None and got.id == n.id

    async def test_get_other_org_returns_none(self):
        store = InMemoryNarrativeStore()
        n = _narrative()
        await store.save(n)
        assert await store.get("other-org", str(n.id)) is None

    async def test_list_filters_by_status_and_severity(self):
        store = InMemoryNarrativeStore()
        await store.save(_narrative(severity="critical", status="open"))
        await store.save(_narrative(severity="high", status="confirmed"))
        await store.save(_narrative(severity="critical", status="confirmed"))

        assert len(await store.list(ORG)) == 3
        assert len(await store.list(ORG, status="confirmed")) == 2
        assert len(await store.list(ORG, severity="critical")) == 2
        both = await store.list(ORG, status="confirmed", severity="critical")
        assert len(both) == 1

    async def test_disposition_persists_through_store(self):
        store = InMemoryNarrativeStore()
        n = _narrative()
        await store.save(n)
        await store.save(apply_disposition(n, status="suppressed", rationale="r", assignee="a"))
        got = await store.get(ORG, str(n.id))
        assert got.status == "suppressed"
