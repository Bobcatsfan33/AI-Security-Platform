"""Cross-agent correlation EPA (RAPIDE Sprint 7).

Per-agent EPAs each see one agent in isolation — they cannot detect an attack
that *spans* agents. This EPA subscribes to the same stream but keys state by
``correlation_key`` (the poset-spine field that threads a flow across agent
instances), accumulating a per-flow picture so it can surface the two headline
multi-agent threats the brief calls out:

  - **propagation_chain** (§4.1): a single flow that crosses ≥2 agents, shows a
    behavioural shift (flagged / high-risk events), spans ≥2 causal hops, and
    terminates in an anomalous outbound/tool action. The five events look
    innocuous one-by-one and to per-agent EPAs; the connected flow does not.

  - **coordinated_exfiltration** (§4.2): low-and-slow data egress distributed
    across agents in one flow. Each agent stays under its individual
    thresholds, but the *aggregate* data access + outbound across the flow
    crosses the line. Per-flow accumulation makes the aggregate visible.

This is intentionally accumulation-over-a-flow, not per-event — exactly the
kind of pattern flat correlation misses. State is keyed by correlation_key and
persisted via a CorrelationStore (in-memory for tests, Redis in prod). Each
signal kind fires once per flow (deduped) so a long flow doesn't spam.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable

from app.anomaly.attack_graph import _norm
from app.epa.agent_epa import EpaSignal

# Thresholds.
CROSS_MIN_AGENTS = 2  # a "cross-agent" flow involves at least two instances
PROPAGATION_MIN_DEPTH = 2  # multi-hop: the chain is ≥2 causal hops deep
PROPAGATION_RISK = 0.7  # a flagged event or this risk = "behavioural shift"
EXFIL_DATA_MIN = 15  # cumulative data-access events across the flow

_DATA_ACCESS = {"memory_access", "file_access", "rag_retrieval"}
_EXFIL = {"external_api_call"}
_FLAGGED_TYPES = {"policy_violation", "alert", "block"}
_REDIS_PREFIX = "epa:correlation:"


@dataclass
class CorrelationState:
    correlation_key: str
    org_id: str = ""
    agents: set[str] = field(default_factory=set)
    asset_ids: set[str] = field(default_factory=set)
    event_count: int = 0
    risk_max: float = 0.0
    flagged_count: int = 0
    data_access_count: int = 0
    exfil_count: int = 0
    max_depth: int = 0
    alerted: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlation_key": self.correlation_key,
            "org_id": self.org_id,
            "agents": sorted(self.agents),
            "asset_ids": sorted(self.asset_ids),
            "event_count": self.event_count,
            "risk_max": self.risk_max,
            "flagged_count": self.flagged_count,
            "data_access_count": self.data_access_count,
            "exfil_count": self.exfil_count,
            "max_depth": self.max_depth,
            "alerted": sorted(self.alerted),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CorrelationState":
        s = cls(correlation_key=d["correlation_key"])
        s.org_id = d.get("org_id", "")
        s.agents = set(d.get("agents", []))
        s.asset_ids = set(d.get("asset_ids", []))
        s.event_count = d.get("event_count", 0)
        s.risk_max = d.get("risk_max", 0.0)
        s.flagged_count = d.get("flagged_count", 0)
        s.data_access_count = d.get("data_access_count", 0)
        s.exfil_count = d.get("exfil_count", 0)
        s.max_depth = d.get("max_depth", 0)
        s.alerted = set(d.get("alerted", []))
        return s

    @property
    def shifted(self) -> bool:
        """A behavioural shift occurred somewhere in the flow."""
        return self.flagged_count > 0 or self.risk_max >= PROPAGATION_RISK


@runtime_checkable
class CorrelationStore(Protocol):
    async def load(self, correlation_key: str) -> Optional[CorrelationState]: ...

    async def save(self, state: CorrelationState) -> None: ...


class InMemoryCorrelationStore:
    def __init__(self) -> None:
        self._data: dict[str, dict] = {}

    async def load(self, correlation_key: str) -> Optional[CorrelationState]:
        raw = self._data.get(correlation_key)
        return CorrelationState.from_dict(raw) if raw else None

    async def save(self, state: CorrelationState) -> None:
        self._data[state.correlation_key] = state.to_dict()


class RedisCorrelationStore:
    def __init__(self, redis, *, ttl_seconds: int = 24 * 3600) -> None:
        self._redis = redis
        self._ttl = ttl_seconds

    async def load(self, correlation_key: str) -> Optional[CorrelationState]:
        raw = await self._redis.get(_REDIS_PREFIX + correlation_key)
        return CorrelationState.from_dict(json.loads(raw)) if raw else None

    async def save(self, state: CorrelationState) -> None:
        await self._redis.set(
            _REDIS_PREFIX + state.correlation_key,
            json.dumps(state.to_dict()),
            ex=self._ttl,
        )


class CrossAgentEPA:
    """Accumulates per-flow state and emits cross-agent signals."""

    def __init__(self, store: CorrelationStore) -> None:
        self._store = store

    async def process(self, event: dict[str, Any]) -> list[EpaSignal]:
        key = _norm(event.get("correlation_key"))
        if not key:
            return []  # no cross-agent context to correlate

        state = await self._store.load(key) or CorrelationState(correlation_key=key)
        instance = _norm(event.get("agent_instance_id"))
        if not state.org_id:
            state.org_id = _norm(event.get("org_id"))

        # ── accumulate ───────────────────────────────────────────────
        state.event_count += 1
        if instance:
            state.agents.add(instance)
        asset = _norm(event.get("asset_id"))
        if asset:
            state.asset_ids.add(asset)
        state.risk_max = max(state.risk_max, float(event.get("risk_score") or 0.0))
        et = event.get("event_type") or ""
        if event.get("action_taken") == "flagged" or et in _FLAGGED_TYPES:
            state.flagged_count += 1
        if et in _DATA_ACCESS:
            state.data_access_count += 1
        if et in _EXFIL:
            state.exfil_count += 1
        try:
            state.max_depth = max(state.max_depth, int(event.get("causal_depth") or 0))
        except (TypeError, ValueError):
            pass

        signals = self._evaluate(state)
        await self._store.save(state)
        return signals

    def _evaluate(self, state: CorrelationState) -> list[EpaSignal]:
        signals: list[EpaSignal] = []
        cross_agent = len(state.agents) >= CROSS_MIN_AGENTS
        if not cross_agent:
            return signals

        # ── propagation chain ────────────────────────────────────────
        if (
            "propagation_chain" not in state.alerted
            and state.shifted
            and state.max_depth >= PROPAGATION_MIN_DEPTH
            and state.exfil_count >= 1
        ):
            state.alerted.add("propagation_chain")
            signals.append(
                self._signal(
                    state,
                    kind="propagation_chain",
                    severity="critical",
                    title=(
                        f"Multi-agent propagation across {len(state.agents)} agents "
                        f"(flow {state.correlation_key[:8]})"
                    ),
                    confidence=0.75,
                    detail={
                        "agents": sorted(state.agents),
                        "max_causal_depth": state.max_depth,
                        "flagged_count": state.flagged_count,
                        "risk_max": round(state.risk_max, 3),
                        "exfil_count": state.exfil_count,
                    },
                )
            )

        # ── coordinated low-and-slow exfiltration ─────────────────────
        if (
            "coordinated_exfiltration" not in state.alerted
            and state.data_access_count >= EXFIL_DATA_MIN
            and state.exfil_count >= 1
        ):
            state.alerted.add("coordinated_exfiltration")
            signals.append(
                self._signal(
                    state,
                    kind="coordinated_exfiltration",
                    severity="high",
                    title=(
                        f"Coordinated exfiltration across {len(state.agents)} agents "
                        f"({state.data_access_count} accesses, flow {state.correlation_key[:8]})"
                    ),
                    confidence=0.7,
                    detail={
                        "agents": sorted(state.agents),
                        "data_access_count": state.data_access_count,
                        "exfil_count": state.exfil_count,
                    },
                )
            )
        return signals

    def _signal(
        self, state: CorrelationState, *, kind, severity, title, confidence, detail
    ) -> EpaSignal:
        return EpaSignal(
            agent_instance_id=f"flow:{state.correlation_key}",
            org_id=state.org_id,
            asset_id=next(iter(state.asset_ids), ""),
            kind=kind,
            severity=severity,
            title=title,
            confidence=confidence,
            detail=detail,
        )
