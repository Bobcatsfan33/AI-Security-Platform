"""ThreatNarrative — the Tier-3, human-actionable unit, and its SOAR mapping."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Headline kinds, most→least severe, used to title the narrative after its
# most significant contributing signal.
_KIND_PRIORITY = (
    "propagation_chain",
    "coordinated_exfiltration",
    "behavioral_drift",
    "risk_inflation",
    "resource_acceleration",
    "novel_transition",
    "volume_spike",
    "agent_silent",
)


@dataclass(frozen=True)
class ThreatNarrative:
    """One actionable incident assembled from the Tier-2 signals of a flow."""

    id: uuid.UUID
    org_id: str
    correlation_id: str  # the poset flow / root — the analyst's pivot key
    title: str
    severity: Severity
    kind: str
    confidence: float
    agents: tuple[str, ...]
    asset_id: str = ""
    signal_count: int = 0
    contributing: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    causal_timeline: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: Literal["open", "confirmed", "false_positive", "suppressed", "resolved"] = "open"


def severity_rank(sev: str) -> int:
    return _SEVERITY_RANK.get(sev, 0)


def narrative_to_incident(narrative: ThreatNarrative) -> "Any":
    """Map a Tier-3 narrative to a SOAR Incident, carrying the causal flow id
    as correlation_id and the timeline/contributing signals in detail — so the
    analyst gets the pre-built causal chain, not a bare alert (brief §6)."""
    from app.soar.incidents import Incident

    return Incident(
        org_id=narrative.org_id,
        title=narrative.title,
        severity=narrative.severity,
        description=(
            f"{narrative.kind} across {len(narrative.agents)} agent(s); "
            f"{narrative.signal_count} correlated signal(s). "
            f"Flow {narrative.correlation_id}."
        ),
        source="epa_fleet",
        asset_id=narrative.asset_id,
        correlation_id=narrative.correlation_id,
        detected_at=narrative.created_at,
        detail={
            "narrative_id": str(narrative.id),
            "kind": narrative.kind,
            "confidence": narrative.confidence,
            "agents": list(narrative.agents),
            "contributing": list(narrative.contributing),
            "causal_timeline": list(narrative.causal_timeline),
        },
    )
