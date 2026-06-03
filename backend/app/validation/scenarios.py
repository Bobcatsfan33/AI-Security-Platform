"""Multi-agent attack scenario generators (RAPIDE Sprint 13).

Each generator emits a synthetic event flow (wire dicts with full poset lineage)
for one of the brief's headline scenarios, plus the detection it must produce.
These drive the validation harness — purple-team replay through the real EPA
stack — and double as integration tests across the detection pipeline.

Scenarios:
  §4.1 prompt-injection propagation     -> propagation_chain (cross-agent)
  §4.2 coordinated low-and-slow exfil   -> coordinated_exfiltration (cross-agent)
  §4.3 behavioral drift / gradual hijack-> behavioral_drift (per-agent)
  §4.4 token/resource exhaustion        -> resource_acceleration (per-agent)
  benign control                        -> no detection
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.epa.envelope import MATURITY_MIN


@dataclass
class ValidationScenario:
    name: str
    brief_section: str
    description: str
    events: list[dict[str, Any]]
    expected_kinds: set[str]  # signal kinds that MUST fire (empty for benign)
    is_attack: bool = True


@dataclass
class _Builder:
    """Builds a flow of events with monotonic timestamps + a shared org/asset."""

    org_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    _t: float = 1_780_000_000.0  # fixed base epoch (deterministic)

    def ev(
        self,
        event_type: str,
        *,
        instance: str,
        flow: str,
        depth: int = 0,
        parent: str | None = None,
        risk: float = 0.0,
        action: str = "allowed",
        tool: str | None = None,
        dt: float = 1.0,
        **fields: Any,
    ) -> dict[str, Any]:
        self._t += dt
        eid = str(uuid.uuid4())
        e = {
            "org_id": self.org_id,
            "asset_id": self.asset_id,
            "agent_instance_id": instance,
            "session_id": f"sess-{instance}",
            "event_id": eid,
            "parent_event_id": parent,
            "correlation_key": flow,
            "causal_depth": depth,
            "event_type": event_type,
            "action_taken": action,
            "risk_score": risk,
            "tool_name": tool,
            "timestamp": datetime.fromtimestamp(self._t, tz=timezone.utc).isoformat(),
        }
        e.update(fields)
        return e


def scenario_propagation_chain() -> ValidationScenario:
    b = _Builder()
    flow = "attack-propagation"
    a1 = b.ev(
        "policy_violation", instance="planner", flow=flow, depth=0, risk=0.85, action="flagged"
    )
    a2 = b.ev(
        "tool_call", instance="planner", flow=flow, depth=1, parent=a1["event_id"], tool="message"
    )
    a3 = b.ev("request", instance="worker", flow=flow, depth=2, parent=a2["event_id"])
    a4 = b.ev("external_api_call", instance="worker", flow=flow, depth=3, parent=a3["event_id"])
    return ValidationScenario(
        name="multi-agent-prompt-injection-propagation",
        brief_section="§4.1",
        description="Injection hits the planner, propagates to the worker, which exfiltrates.",
        events=[a1, a2, a3, a4],
        expected_kinds={"propagation_chain"},
    )


def scenario_coordinated_exfiltration() -> ValidationScenario:
    b = _Builder()
    flow = "attack-exfil"
    events = []
    # Spread small data accesses across 3 agents — each innocuous, aggregate over
    # the threshold — then a single outbound call.
    for i in range(18):
        events.append(b.ev("memory_access", instance=f"agent{i % 3}", flow=flow, depth=i))
    events.append(b.ev("external_api_call", instance="agent0", flow=flow, depth=99))
    return ValidationScenario(
        name="coordinated-low-and-slow-exfiltration",
        brief_section="§4.2",
        description="Data access distributed across 3 agents, under each individual threshold.",
        events=events,
        expected_kinds={"coordinated_exfiltration"},
    )


def scenario_gradual_hijack() -> ValidationScenario:
    b = _Builder()
    flow = "agent-hijack"
    events = []
    # Warm the per-agent EPA to maturity on a stable request->tool:search edge.
    for _ in range(MATURITY_MIN):
        req = b.ev("request", instance="assistant", flow=flow)
        events.append(req)
        events.append(
            b.ev(
                "tool_call", instance="assistant", flow=flow, parent=req["event_id"], tool="search"
            )
        )
    # Then a burst of never-seen transitions — abrupt behavioural drift.
    for i in range(40):
        req = b.ev("request", instance="assistant", flow=flow)
        events.append(req)
        events.append(
            b.ev(
                "tool_call",
                instance="assistant",
                flow=flow,
                parent=req["event_id"],
                tool=f"newtool{i}",
            )
        )
    return ValidationScenario(
        name="behavioral-drift-gradual-hijack",
        brief_section="§4.3",
        description="A matured agent abruptly shifts to many never-seen tools (hijack).",
        events=events,
        expected_kinds={"behavioral_drift"},
    )


def scenario_resource_exhaustion() -> ValidationScenario:
    b = _Builder()
    flow = "resource-exhaustion"
    events = []
    # Mature at a steady 10s cadence.
    for _ in range(MATURITY_MIN):
        events.append(b.ev("tool_call", instance="runner", flow=flow, tool="search", dt=10.0))
    # Then strictly-shrinking intervals — the acceleration curve toward exhaustion.
    for dt in [8.0, 6.0, 4.0, 2.0, 1.0, 0.5, 0.25]:
        events.append(
            b.ev(
                "external_api_call",
                instance="runner",
                flow=flow,
                tool="api",
                dt=dt,
                token_count_input=500,
            )
        )
    return ValidationScenario(
        name="token-resource-exhaustion-acceleration",
        brief_section="§4.4",
        description="A matured agent's request rate accelerates toward resource exhaustion.",
        events=events,
        expected_kinds={"resource_acceleration"},
    )


def scenario_benign_control() -> ValidationScenario:
    b = _Builder()
    flow = "benign"
    events = []
    for _ in range(MATURITY_MIN + 10):
        req = b.ev("request", instance="assistant", flow=flow, dt=10.0)
        events.append(req)
        events.append(
            b.ev(
                "tool_call",
                instance="assistant",
                flow=flow,
                parent=req["event_id"],
                tool="search",
                dt=2.0,
            )
        )
    return ValidationScenario(
        name="benign-steady-operation",
        brief_section="control",
        description="A matured agent operating normally — must produce no detections.",
        events=events,
        expected_kinds=set(),
        is_attack=False,
    )


def all_scenarios() -> list[ValidationScenario]:
    return [
        scenario_propagation_chain(),
        scenario_coordinated_exfiltration(),
        scenario_gradual_hijack(),
        scenario_resource_exhaustion(),
        scenario_benign_control(),
    ]
