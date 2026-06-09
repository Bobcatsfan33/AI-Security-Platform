"""AI Guard service — runs the detector suite with per-detector sliding
thresholds and produces an Allow | Block | Detect decision.

Per-detector configuration (the "sliding threshold meter" + action):

    {
      "toxicity":        {"threshold": 0.6, "action": "block"},
      "off_topic":       {"threshold": 0.7, "action": "detect"},
      "financial_advice":{"action": "off"},
      ...
    }

* ``threshold`` (0-1) — detector triggers when confidence >= threshold.
* ``action`` — what a *triggered* detector contributes to the verdict:
  ``block`` (hard stop), ``detect`` (alert/log, allow through), or ``off``
  (disabled). Defaults: enabled, default per-detector threshold, action
  ``block`` for high/critical severity detectors else ``detect``.
"""

from __future__ import annotations

import time
from typing import Any

from app.aiguard.response import AIGuardResponse, DetectorOutcome
from app.detectors import ALL_DETECTORS
from app.detectors.base import Detector, DetectorContext, DetectorResult, Direction, applies
from app.detectors.normalize import decode_and_normalize

_DEFAULT_BLOCK_SEVERITIES = {"high", "critical"}


def _default_action(det: Detector) -> str:
    return "block" if det.severity in _DEFAULT_BLOCK_SEVERITIES else "detect"


def _best_over_candidates(
    det: Detector, candidates: list[tuple[str, str]], ctx: DetectorContext
) -> DetectorResult:
    """Run ``det`` against every candidate form (raw + normalized + decoded) and
    return the highest-confidence verdict, so an attack hidden in base64 / a
    homoglyph blob is caught. The winning non-raw form is recorded in evidence
    as ``matched_form`` for analyst transparency."""
    best: DetectorResult | None = None
    best_label = "raw"
    for label, cand in candidates:
        res = det.detect(cand, ctx).clamp()
        if best is None or res.confidence > best.confidence:
            best, best_label = res, label
    assert best is not None  # candidates always includes ("raw", text)
    if best_label != "raw" and best.confidence > 0.0:
        return DetectorResult(
            best.name,
            best.category,
            best.confidence,
            best.severity,
            {**best.evidence, "matched_form": best_label},
        )
    return best


class AIGuardService:
    def __init__(self, detectors: tuple[Detector, ...] = ALL_DETECTORS) -> None:
        self._detectors = detectors

    def inspect(
        self,
        *,
        text: str,
        direction: Direction = Direction.INBOUND,
        config: dict[str, dict[str, Any]] | None = None,
        context: DetectorContext | None = None,
    ) -> AIGuardResponse:
        config = config or {}
        ctx = context or DetectorContext(direction=direction)
        # keep ctx.direction in sync with the requested direction
        if ctx.direction != direction:
            ctx = DetectorContext(
                direction=direction,
                allowed_topics=ctx.allowed_topics,
                competitor_terms=ctx.competitor_terms,
                brand_terms=ctx.brand_terms,
                allowed_languages=ctx.allowed_languages,
                extra=ctx.extra,
            )

        start = time.perf_counter()
        outcomes: list[DetectorOutcome] = []
        triggered: list[str] = []
        worst_block: DetectorOutcome | None = None

        # Decode + normalize pre-pass: run every detector against the raw text
        # plus its normalized + decoded variants (defeats the encoding-bypass
        # class). Computed once per request, shared across all detectors.
        candidates = decode_and_normalize(text).candidates()

        for det in self._detectors:
            cfg = config.get(det.name, {})
            if cfg.get("action") == "off" or not cfg.get("enabled", True):
                continue
            if not applies(det, direction):
                continue
            threshold = float(cfg.get("threshold", det.default_threshold))
            action = cfg.get("action", _default_action(det))
            res = _best_over_candidates(det, candidates, ctx)
            is_trig = res.confidence >= threshold and res.confidence > 0.0
            outcome = DetectorOutcome(
                name=res.name,
                category=res.category,
                confidence=res.confidence,
                threshold=threshold,
                triggered=is_trig,
                action=action,
                severity=res.severity,
                evidence=res.evidence,
            )
            outcomes.append(outcome)
            if is_trig:
                triggered.append(res.name)
                if action == "block" and (
                    worst_block is None or outcome.confidence > worst_block.confidence
                ):
                    worst_block = outcome

        if worst_block is not None:
            action, reason = (
                "block",
                f"{worst_block.name} ({worst_block.confidence:.2f}) >= {worst_block.threshold:.2f}",
            )
        elif triggered:
            action, reason = (
                "detect",
                f"{len(triggered)} detector(s) flagged: {', '.join(triggered)}",
            )
        else:
            action, reason = "allow", "no detectors triggered"

        latency_ms = (time.perf_counter() - start) * 1000
        return AIGuardResponse(
            action=action,
            direction=direction.value,
            triggered=tuple(triggered),
            detectors=tuple(outcomes),
            latency_ms=latency_ms,
            reason=reason,
        )


_default_service: AIGuardService | None = None


def get_service() -> AIGuardService:
    global _default_service
    if _default_service is None:
        _default_service = AIGuardService()
    return _default_service
