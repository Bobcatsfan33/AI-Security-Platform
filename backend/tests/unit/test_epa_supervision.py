"""Tests for EPA supervision (Sprint 6) — absence detection, resource
acceleration, and the fleet sweep / health stats."""

from __future__ import annotations

import uuid

import pytest

from app.epa.agent_epa import AgentEPA, absence_signal
from app.epa.envelope import ACCEL_WINDOW, MATURITY_MIN, BehavioralEnvelope
from app.epa.fleet import EpaFleet
from app.epa.store import InMemoryEnvelopeStore

pytestmark = pytest.mark.unit

ORG = str(uuid.uuid4())
ASSET = str(uuid.uuid4())


def _ev(event_type="request", *, tool=None, risk=0.0, instance="agent-1", tokens=0):
    return {
        "org_id": ORG,
        "asset_id": ASSET,
        "agent_instance_id": instance,
        "session_id": "s1",
        "event_id": str(uuid.uuid4()),
        "parent_event_id": None,
        "event_type": event_type,
        "tool_name": tool,
        "action_taken": "allowed",
        "risk_score": risk,
        "token_count_input": tokens,
        "token_count_output": 0,
    }


def _mature_epa(interval=10.0):
    """A mature EPA fed at a steady ``interval`` so mean_interval is stable."""
    epa = AgentEPA(BehavioralEnvelope(agent_instance_id="agent-1"))
    t = 1000.0
    for _ in range(MATURITY_MIN + 5):
        epa.process(_ev(tool="search"), now=t)
        t += interval
    return epa, t


# ─────────────────────────────────────────────── Timing / envelope


class TestTiming:
    def test_mean_interval_tracks_steady_cadence(self):
        epa, _ = _mature_epa(interval=10.0)
        assert epa.env.mean_interval == pytest.approx(10.0, abs=0.5)

    def test_timing_survives_serialization(self):
        epa, t = _mature_epa(interval=5.0)
        restored = BehavioralEnvelope.from_dict(epa.env.to_dict())
        assert restored.mean_interval == pytest.approx(epa.env.mean_interval)
        assert restored.last_event_ts == epa.env.last_event_ts


# ─────────────────────────────────────────────── Acceleration


class TestAcceleration:
    def test_shrinking_intervals_flag_acceleration(self):
        epa, t = _mature_epa(interval=10.0)
        all_sigs = []
        # Strictly shrinking gaps → ramping rate (resource exhaustion curve).
        for dt in [8, 6, 4, 2, 1, 0.5, 0.25]:
            t += dt
            all_sigs += epa.process(_ev(tool="search", tokens=100), now=t)
        assert any(s.kind == "resource_acceleration" for s in all_sigs)

    def test_steady_rate_does_not_flag(self):
        epa, t = _mature_epa(interval=10.0)
        sigs = []
        for _ in range(ACCEL_WINDOW + 2):
            t += 10.0
            sigs += epa.process(_ev(tool="search"), now=t)
        assert all(s.kind != "resource_acceleration" for s in sigs)

    def test_tokens_accumulate(self):
        epa, t = _mature_epa(interval=10.0)
        before = epa.env.tokens_total
        t += 10.0
        epa.process(_ev(tool="search", tokens=500), now=t)
        assert epa.env.tokens_total == before + 500


# ─────────────────────────────────────────────── Absence


class TestAbsence:
    def test_silent_mature_agent_flagged(self):
        epa, t = _mature_epa(interval=10.0)
        # 4× the normal interval of silence → absence.
        sig = absence_signal(epa.env, now=t + 50.0, factor=4.0)
        assert sig is not None and sig.kind == "agent_silent"
        assert sig.detail["silent_seconds"] >= 40

    def test_recently_active_agent_not_flagged(self):
        epa, t = _mature_epa(interval=10.0)
        assert absence_signal(epa.env, now=t + 5.0, factor=4.0) is None

    def test_immature_agent_never_flagged(self):
        epa = AgentEPA(BehavioralEnvelope(agent_instance_id="a"))
        epa.process(_ev(), now=1000.0)
        assert absence_signal(epa.env, now=1_000_000.0, factor=4.0) is None


# ─────────────────────────────────────────────── Fleet supervision


class TestFleetSupervision:
    async def test_sweep_absences_emits_for_silent_agents(self):
        store = InMemoryEnvelopeStore()
        received = []

        async def sink(s):
            received.append(s)

        fleet = EpaFleet(store=store, sink=sink)
        t = 1000.0
        for _ in range(MATURITY_MIN + 2):
            await fleet.handle_event(_ev(tool="search", instance="agent-quiet"))
            t += 10.0
        # Force the envelope's timing by processing with explicit now via the
        # cached EPA, then sweep far in the future.
        epa = fleet._cache["agent-quiet"]
        base = 2000.0
        for _ in range(MATURITY_MIN + 2):
            epa.process(_ev(tool="search", instance="agent-quiet"), now=base)
            base += 10.0
        emitted = await fleet.sweep_absences(now=base + 500.0, factor=4.0)
        assert any(s.kind == "agent_silent" for s in emitted)
        assert any(s.kind == "agent_silent" for s in received)

    def test_stats_reports_health(self):
        store = InMemoryEnvelopeStore()
        fleet = EpaFleet(store=store)
        s = fleet.stats()
        assert set(s) >= {
            "events_processed",
            "signals_emitted",
            "agents_cached",
            "agents_mature",
        }
