"""NarrativeBuilder — the Tier-2 → Tier-3 map.

Groups the EpaSignals of one flow (or, lacking a flow key, one agent) into a
single ThreatNarrative: the narrative's severity is the max of its signals, its
kind/title come from the most significant signal, and it optionally carries the
causal timeline reconstructed from the poset (Phase A's causal_subtree). This
is where alert volume collapses — N Tier-2 signals become 1 Tier-3 incident.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable, Iterable, Optional

from app.epa.agent_epa import EpaSignal
from app.narratives.narrative import (
    _KIND_PRIORITY,
    ThreatNarrative,
    severity_rank,
)

# Optional injectable timeline fetcher: (org_id, asset_id, root_event_id) →
# list of event dicts. In production this is app.anomaly.attack_graph
# .fetch_causal_subtree; tests pass a stub or omit it.
TimelineFetcher = Callable[[str, str, str], list[dict[str, Any]]]


class NarrativeBuilder:
    def __init__(self, *, timeline_fetcher: Optional[TimelineFetcher] = None) -> None:
        self._timeline = timeline_fetcher

    def _group_key(self, sig: EpaSignal) -> str:
        return sig.correlation_key or f"agent:{sig.agent_instance_id}"

    def _kind_priority(self, kind: str) -> int:
        try:
            return len(_KIND_PRIORITY) - _KIND_PRIORITY.index(kind)
        except ValueError:
            return 0

    def build(self, signals: Iterable[EpaSignal]) -> list[ThreatNarrative]:
        """Collapse a batch of signals into one narrative per flow/agent."""
        groups: dict[str, list[EpaSignal]] = {}
        for sig in signals:
            groups.setdefault(self._group_key(sig), []).append(sig)
        return [self._build_one(key, sigs) for key, sigs in groups.items()]

    def _build_one(self, key: str, sigs: list[EpaSignal]) -> ThreatNarrative:
        # The "lead" signal — highest severity, then highest kind priority,
        # then highest confidence — titles the narrative.
        lead = max(
            sigs,
            key=lambda s: (
                severity_rank(s.severity),
                self._kind_priority(s.kind),
                s.confidence,
            ),
        )
        agents = tuple(
            sorted(
                {s.agent_instance_id for s in sigs if not s.agent_instance_id.startswith("flow:")}
            )
        )
        correlation_id = sigs[0].correlation_key or key.removeprefix("agent:")
        org_id = next((s.org_id for s in sigs if s.org_id), "")
        asset_id = next((s.asset_id for s in sigs if s.asset_id), "")

        timeline: tuple[dict[str, Any], ...] = ()
        if self._timeline is not None and sigs[0].correlation_key:
            try:
                events = self._timeline(org_id, asset_id, sigs[0].correlation_key)
                timeline = tuple(events)
            except Exception:  # noqa: BLE001 - timeline is best-effort context
                timeline = ()

        return ThreatNarrative(
            id=uuid.uuid4(),
            org_id=org_id,
            correlation_id=correlation_id,
            title=lead.title,
            severity=lead.severity,
            kind=lead.kind,
            confidence=round(max(s.confidence for s in sigs), 3),
            agents=agents,
            asset_id=asset_id,
            signal_count=len(sigs),
            contributing=tuple(
                {"kind": s.kind, "severity": s.severity, "title": s.title} for s in sigs
            ),
            causal_timeline=timeline,
        )
