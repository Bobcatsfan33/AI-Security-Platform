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
    status: "DispositionStatus" = "open"
    # Triage (Phase E). Set when an analyst dispositions the narrative.
    assignee: str = ""
    rationale: str = ""
    disposition_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "org_id": self.org_id,
            "correlation_id": self.correlation_id,
            "title": self.title,
            "severity": self.severity,
            "kind": self.kind,
            "confidence": self.confidence,
            "agents": list(self.agents),
            "asset_id": self.asset_id,
            "signal_count": self.signal_count,
            "contributing": list(self.contributing),
            "causal_timeline": list(self.causal_timeline),
            "created_at": self.created_at.isoformat(),
            "status": self.status,
            "assignee": self.assignee,
            "rationale": self.rationale,
            "disposition_at": self.disposition_at.isoformat() if self.disposition_at else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ThreatNarrative":
        return cls(
            id=uuid.UUID(d["id"]),
            org_id=d.get("org_id", ""),
            correlation_id=d.get("correlation_id", ""),
            title=d.get("title", ""),
            severity=d.get("severity", "medium"),
            kind=d.get("kind", ""),
            confidence=d.get("confidence", 0.0),
            agents=tuple(d.get("agents", [])),
            asset_id=d.get("asset_id", ""),
            signal_count=d.get("signal_count", 0),
            contributing=tuple(d.get("contributing", [])),
            causal_timeline=tuple(d.get("causal_timeline", [])),
            created_at=_parse_dt(d.get("created_at")) or datetime.now(timezone.utc),
            status=d.get("status", "open"),
            assignee=d.get("assignee", ""),
            rationale=d.get("rationale", ""),
            disposition_at=_parse_dt(d.get("disposition_at")),
        )


DispositionStatus = Literal["open", "confirmed", "false_positive", "suppressed", "resolved"]


def _parse_dt(raw: Any) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw))
    except (ValueError, TypeError):
        return None


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
