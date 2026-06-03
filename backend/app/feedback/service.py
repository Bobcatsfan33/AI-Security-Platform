"""Disposition → feedback actions.

Bridges an analyst disposition to the two learning paths:
  - false_positive → a SUGGESTED suppression rule (human approves before it
    takes effect)
  - confirmed      → a regression TestCase so the detection is never silently
    lost (the red-team promotion flywheel)
"""

from __future__ import annotations

from typing import Any

from app.feedback.suppression import SuppressionRule, suggest_from_narrative
from app.narratives.narrative import ThreatNarrative


def on_false_positive(
    narrative: ThreatNarrative, *, reason: str, created_by: str
) -> SuppressionRule:
    return suggest_from_narrative(narrative, reason=reason, created_by=created_by)


def narrative_to_testcase(narrative: ThreatNarrative) -> dict[str, Any]:
    """Map a confirmed narrative into a TestCase-shaped dict for the regression
    suite (mirrors app/testcases/library.py + patterns.promotion)."""
    return {
        "name": f"[regression] {narrative.kind} — {narrative.title}"[:200],
        "description": (
            f"Auto-promoted from a confirmed narrative across "
            f"{len(narrative.agents)} agent(s), flow {narrative.correlation_id}."
        ),
        "category": _category_for(narrative.kind),
        "sub_category": "narrative_regression",
        "severity": narrative.severity,
        "attack_type": "multi_turn",
        "source": "narrative_promotion",
        "expected_behavior": f"The {narrative.kind} detection must fire on this flow.",
        "success_criteria": {"type": "narrative_fires", "kind": narrative.kind},
        "tags": ["narrative", "regression", narrative.kind],
        "metadata": {
            "narrative_id": str(narrative.id),
            "correlation_id": narrative.correlation_id,
            "agents": list(narrative.agents),
            "signal_count": narrative.signal_count,
        },
    }


_KIND_CATEGORY = {
    "propagation_chain": "prompt_injection",
    "coordinated_exfiltration": "data_exfiltration",
    "novel_transition": "unsafe_tool_use",
    "risk_inflation": "jailbreak",
    "volume_spike": "model_denial_of_service",
    "resource_acceleration": "model_denial_of_service",
    "agent_silent": "availability",
    "behavioral_drift": "prompt_injection",
}


def _category_for(kind: str) -> str:
    return _KIND_CATEGORY.get(kind, "prompt_injection")
