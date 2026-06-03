"""NarrativePipeline — Tier-2 signals → persisted, suppression-aware Tier-3.

The glue between the EPA fleet and the analyst workbench. Per batch of signals
(the signals one event produced), it:

  1. groups them into narratives (NarrativeBuilder, the T2→T3 map),
  2. merges each into the existing narrative for that flow — a flow has a
     STABLE id (uuid5 of org+correlation), so a long-running attack accumulates
     into one incident rather than spawning duplicates,
  3. applies active suppression rules (an analyst-approved FP guard) — a
     suppressed narrative is persisted with status="suppressed" (auditable),
     not silently dropped,
  4. preserves any analyst disposition already on the incident,
  5. persists to the NarrativeStore the workbench reads.
"""

from __future__ import annotations

import dataclasses
import uuid
from typing import Optional

from app.epa.agent_epa import EpaSignal
from app.feedback.suppression import is_suppressed
from app.narratives.builder import NarrativeBuilder, TimelineFetcher
from app.narratives.narrative import ThreatNarrative, severity_rank
from app.narratives.store import NarrativeStore

_DISPOSITIONED = {"confirmed", "false_positive", "resolved"}
_NS = uuid.UUID("a15ec000-0000-4000-8000-000000000000")  # stable namespace


def stable_narrative_id(org_id: str, correlation_id: str) -> uuid.UUID:
    return uuid.uuid5(_NS, f"aisp:{org_id}:{correlation_id}")


class NarrativePipeline:
    def __init__(
        self,
        *,
        narrative_store: NarrativeStore,
        suppression_store: object | None = None,
        timeline_fetcher: Optional[TimelineFetcher] = None,
    ) -> None:
        self._store = narrative_store
        self._suppression_store = suppression_store
        self._builder = NarrativeBuilder(timeline_fetcher=timeline_fetcher)

    async def ingest(self, signals: list[EpaSignal]) -> list[ThreatNarrative]:
        if not signals:
            return []
        persisted: list[ThreatNarrative] = []
        for fresh in self._builder.build(signals):
            stable_id = stable_narrative_id(fresh.org_id, fresh.correlation_id)
            existing = await self._store.get(fresh.org_id, str(stable_id))
            merged = _merge(existing, fresh, stable_id)
            merged = await self._apply_suppression(merged)
            await self._store.save(merged)
            persisted.append(merged)
        return persisted

    async def _apply_suppression(self, narrative: ThreatNarrative) -> ThreatNarrative:
        # Never override an analyst's explicit disposition.
        if narrative.status in _DISPOSITIONED:
            return narrative
        if self._suppression_store is None:
            return narrative
        rules = await self._suppression_store.list(narrative.org_id, status="active")
        if is_suppressed(narrative, rules):
            return dataclasses.replace(narrative, status="suppressed")
        return narrative


def _merge(
    existing: Optional[ThreatNarrative], fresh: ThreatNarrative, stable_id: uuid.UUID
) -> ThreatNarrative:
    if existing is None:
        return dataclasses.replace(fresh, id=stable_id)

    # Lead by severity → keep the most severe title/kind/severity.
    lead = fresh if severity_rank(fresh.severity) > severity_rank(existing.severity) else existing
    agents = tuple(sorted(set(existing.agents) | set(fresh.agents)))
    contributing = (existing.contributing + fresh.contributing)[-50:]  # bound growth
    timeline = fresh.causal_timeline or existing.causal_timeline
    return dataclasses.replace(
        existing,
        id=stable_id,
        title=lead.title,
        kind=lead.kind,
        severity=lead.severity,
        confidence=max(existing.confidence, fresh.confidence),
        agents=agents,
        signal_count=existing.signal_count + fresh.signal_count,
        contributing=contributing,
        causal_timeline=timeline,
        # status, assignee, rationale, created_at preserved from `existing`.
    )
