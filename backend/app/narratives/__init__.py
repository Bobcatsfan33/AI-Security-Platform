"""Tier-3 threat narratives — the human-actionable top of the abstraction.

RAPIDE's three tiers: Tier-1 raw telemetry (runtime_events) → Tier-2 behavioral
primitives (EpaSignals from the fleet) → Tier-3 threat narratives. Only Tier-3
reaches a human. The NarrativeBuilder is the T2→T3 map: it groups the EpaSignals
of one flow/agent into a single narrative carrying the full causal context, so
analysts see one actionable incident instead of N scattered alerts — the core
alert-fatigue payoff (brief §3.2, §6).
"""

from app.narratives.builder import NarrativeBuilder
from app.narratives.narrative import ThreatNarrative, narrative_to_incident

__all__ = ["NarrativeBuilder", "ThreatNarrative", "narrative_to_incident"]
