"""AI Guard ↔ RAPIDE bridge — the best-of-both-worlds merge glue.

The Zscaler-style AI Guard suite (Phase 0) inspects ONE message for content
violations. The RAPIDE stack (Sprints 5–8) correlates agent BEHAVIOUR over
time into Tier-3 narratives. Neither base joins them — this bridge does:
an AI Guard ``block``/``detect`` verdict becomes an ``EpaSignal`` that flows
through the same NarrativePipeline as behavioural signals, so a content
finding and the causal flow it belongs to surface as ONE incident.
"""

from __future__ import annotations

from app.aiguard.response import AIGuardResponse
from app.epa.agent_epa import EpaSignal
from app.narratives.narrative import severity_rank

_ACTION_SEVERITY = {"block": "high", "detect": "medium", "allow": "info"}


def aiguard_response_to_signal(
    resp: AIGuardResponse,
    *,
    org_id: str,
    asset_id: str,
    agent_instance_id: str,
    correlation_key: str = "",
) -> EpaSignal | None:
    """Convert an AI Guard verdict into an EpaSignal, or None when it allowed.

    Severity is the max of the triggered detectors' severities, floored by the
    verdict action (block ≥ high, detect ≥ medium). The detail carries the
    triggered detector names so the analyst sees exactly what fired.
    """
    if resp.action == "allow" or not resp.triggered:
        return None

    triggered = [d for d in resp.detectors if d.triggered]
    det_sev = max((d.severity for d in triggered), key=severity_rank, default="low")
    action_sev = _ACTION_SEVERITY.get(resp.action, "medium")
    severity = det_sev if severity_rank(det_sev) >= severity_rank(action_sev) else action_sev

    confidence = max((d.confidence for d in triggered), default=0.5)
    top = sorted(triggered, key=lambda d: d.confidence, reverse=True)[0]

    return EpaSignal(
        agent_instance_id=agent_instance_id,
        org_id=org_id,
        asset_id=asset_id,
        kind="content_violation",
        severity=severity,  # type: ignore[arg-type]
        title=f"AI Guard {resp.action}: {top.category} ({resp.direction})",
        confidence=round(confidence, 4),
        detail={
            "aiguard_action": resp.action,
            "direction": resp.direction,
            "triggered": list(resp.triggered),
            "categories": sorted({d.category for d in triggered}),
        },
        correlation_key=correlation_key,
    )
