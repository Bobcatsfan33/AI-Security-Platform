"""Detection → red-team promotion.

When a pattern fires and is confirmed, it should become a regression test so
the platform never silently loses that coverage. This maps a confirmed
PatternMatch + its CompiledPattern into a TestCase-shaped dict compatible with
the existing red-team / regression library (app/testcases/library.py), closing
the detection → validation flywheel (Phase D).
"""

from __future__ import annotations

from typing import Any

from app.patterns.compiled import CompiledPattern
from app.patterns.evaluator import PatternMatch


def pattern_match_to_testcase(pattern: CompiledPattern, match: PatternMatch) -> dict[str, Any]:
    """Build a TestCase row dict from a confirmed pattern match.

    The shape mirrors app/testcases/library.py entries so it can be promoted
    straight into the regression suite. ATLAS techniques map to
    ``mitre_atlas_id`` (first) + ``control_mappings`` (all)."""
    atlas = list(pattern.atlas_techniques)
    return {
        "name": f"[regression] {pattern.name}",
        "description": (
            pattern.description or f"Auto-promoted from a confirmed {pattern.name} detection."
        ),
        "category": pattern.category or "prompt_injection",
        "sub_category": "pattern_regression",
        "severity": pattern.severity,
        "attack_type": "multi_turn",
        "source": "pattern_promotion",
        "expected_behavior": (
            f"The {pattern.name} pattern must fire on this flow "
            f"(correlation {match.correlation_key})."
        ),
        "success_criteria": {"type": "pattern_fires", "pattern": pattern.name},
        "tags": ["pattern", "regression", pattern.category or "detection"],
        "control_mappings": atlas,
        "mitre_atlas_id": atlas[0] if atlas else None,
        "metadata": {
            "pattern_name": pattern.name,
            "pattern_version": pattern.version,
            "matched_event_ids": list(match.matched_event_ids),
            "agents": list(match.agents),
            "correlation_key": match.correlation_key,
        },
    }
