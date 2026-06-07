"""Stage 2 adapter that runs the AI Guard detector suite.

Implements the :class:`app.policy.types.Stage2Engine` protocol so the
detector breadth can be dropped straight into the existing three-stage
pipeline (alongside, or instead of, :class:`HeuristicStage2`). It maps the
suite's strongest detector hit onto a single :class:`StageResult` with a
confidence the pipeline's confidence-band routing already understands.

The per-detector thresholds/actions are read from
``policy.content_filters["detectors"]`` so an operator's "sliding threshold
meter" settings flow through unchanged.
"""

from __future__ import annotations

import time
from typing import Any

from app.aiguard.service import AIGuardService
from app.detectors.base import DetectorContext, Direction
from app.policy.compiled import CompiledPolicy
from app.policy.types import PolicyInput, StageResult


def _ctx_from_policy(policy: CompiledPolicy, direction: Direction) -> DetectorContext:
    cf: dict[str, Any] = getattr(policy, "content_filters", {}) or {}
    return DetectorContext(
        direction=direction,
        allowed_topics=tuple(cf.get("allowed_topics", ())),
        competitor_terms=tuple(cf.get("competitor_terms", ())),
        brand_terms=tuple(cf.get("brand_terms", ())),
        allowed_languages=tuple(cf.get("allowed_languages", ())),
        extra=cf.get("detector_extra", {}) or {},
    )


class DetectorSuiteStage2:
    """Detector-suite Stage 2 engine."""

    def __init__(self, service: AIGuardService | None = None) -> None:
        self._svc = service or AIGuardService()

    async def classify(self, *, input_: PolicyInput, policy: CompiledPolicy) -> StageResult:
        start = time.perf_counter_ns()
        direction = (
            Direction.OUTBOUND
            if getattr(input_.direction, "value", input_.direction) == "outbound"
            else Direction.INBOUND
        )
        cf: dict[str, Any] = getattr(policy, "content_filters", {}) or {}
        config = cf.get("detectors", {})
        resp = self._svc.inspect(
            text=input_.text,
            direction=direction,
            config=config,
            context=_ctx_from_policy(policy, direction),
        )
        latency_us = (time.perf_counter_ns() - start) // 1000

        if resp.action == "allow":
            return StageResult(
                stage="stage2_ml", matched=False, action="allowed", latency_us=int(latency_us)
            )

        # Pick the highest-confidence triggered detector to characterize the hit.
        trig = [d for d in resp.detectors if d.triggered]
        top = max(trig, key=lambda d: d.confidence)
        action = "blocked" if resp.action == "block" else "flagged"
        return StageResult(
            stage="stage2_ml",
            matched=True,
            action=action,
            severity=top.severity,  # type: ignore[arg-type]
            category=top.category,
            rule_id=f"detector:{top.name}",
            confidence=top.confidence,
            reason=resp.reason,
            latency_us=int(latency_us),
            evidence={"triggered": list(resp.triggered), "detectors": [d.name for d in trig]},
        )
