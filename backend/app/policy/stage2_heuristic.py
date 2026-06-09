"""Stage 2 — zero-config heuristic classifier.

The ONNX engine (:mod:`app.policy.stage2_onnx`) is the high-fidelity Stage 2,
but it needs model artifacts provisioned per deployment. Until an operator
drops in a trained model, the pipeline still needs a *functional* Stage 2 so
"balanced" / "comprehensive" enforcement actually does ML-ish detection out
of the box rather than silently passing everything through (the old
``_NoopStage2`` behaviour).

This is a deterministic, dependency-free lexical/structural classifier for
prompt-injection and jailbreak attempts. It is intentionally *not* presented
as a trained model — confidences are calibrated from signal strength, and the
ONNX engine supersedes it when configured. It exists so the three-stage
pipeline is real end-to-end with no external dependencies, and so the
confidence-routing path (Stage 2 -> Stage 3 escalation) is exercised.

Signals (each contributes weighted evidence toward a 0-1 confidence):
  - Instruction-override phrases ("ignore previous instructions", …)
  - Role / persona hijack ("you are now", "DAN", "developer mode", …)
  - System-prompt exfiltration ("repeat the text above", "system prompt")
  - Encoded-payload smell (long base64/hex blobs that hide instructions)
"""

from __future__ import annotations

import re
import time

from app.policy.compiled import CompiledPolicy
from app.policy.types import PolicyInput, StageResult

# Each pattern carries (weight, category). Weights sum (capped at 1.0) into
# the confidence. Tuned so a single strong phrase lands in the "high" band
# (≥0.7) and a single weak/structural signal lands in the "uncertain" band
# (0.3-0.7) so Stage 3 escalation gets exercised.
_SIGNALS: tuple[tuple[re.Pattern[str], float, str], ...] = (
    (
        re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b", re.I),
        0.75,
        "prompt_injection",
    ),
    (
        re.compile(r"\bdisregard\s+(?:all\s+)?(?:previous|prior|the\s+above)\b", re.I),
        0.7,
        "prompt_injection",
    ),
    (re.compile(r"\byou\s+are\s+now\b", re.I), 0.45, "jailbreak"),
    (re.compile(r"\b(?:DAN|do\s+anything\s+now)\b", re.I), 0.7, "jailbreak"),
    (re.compile(r"\bdeveloper\s+mode\b", re.I), 0.55, "jailbreak"),
    (re.compile(r"\b(?:system|initial)\s+prompt\b", re.I), 0.5, "prompt_injection"),
    (
        re.compile(r"\brepeat\s+(?:the\s+)?(?:text|words|everything)\s+above\b", re.I),
        0.6,
        "prompt_injection",
    ),
    (re.compile(r"\bpretend\s+(?:to\s+be|you\s+are)\b", re.I), 0.4, "jailbreak"),
    (
        re.compile(r"\boverride\s+(?:your\s+)?(?:safety|guidelines|rules)\b", re.I),
        0.65,
        "jailbreak",
    ),
    # Structural: a long contiguous base64/hex blob often hides a payload.
    (re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"), 0.35, "prompt_injection"),
)


class HeuristicStage2:
    """Stage 2 engine implementing the Stage2Engine protocol with no ML deps.

    Returns ``matched=True`` with ``action="flagged"`` and a calibrated
    confidence; the orchestrator handles routing (high -> act, uncertain ->
    Stage 3). Returns ``matched=False`` when no signal fires.
    """

    async def classify(self, *, input_: PolicyInput, policy: CompiledPolicy) -> StageResult:
        start_ns = time.perf_counter_ns()
        text = input_.text or ""

        confidence = 0.0
        hits: list[str] = []
        # Track per-category contribution so we can report the dominant one.
        by_category: dict[str, float] = {}
        for pattern, weight, category in _SIGNALS:
            if pattern.search(text):
                confidence += weight
                hits.append(pattern.pattern)
                by_category[category] = by_category.get(category, 0.0) + weight

        confidence = min(confidence, 1.0)
        latency_us = (time.perf_counter_ns() - start_ns) // 1000

        if not hits:
            return StageResult(
                stage="stage2_ml",
                mode="stage2_heuristic",
                matched=False,
                action="allowed",
                latency_us=int(latency_us),
            )

        category = max(by_category, key=lambda k: by_category[k])
        severity = "high" if confidence >= 0.7 else "medium"
        return StageResult(
            stage="stage2_ml",
            mode="stage2_heuristic",
            matched=True,
            action="flagged",
            severity=severity,
            category=category,
            rule_id="heuristic-stage2",
            confidence=round(confidence, 4),
            reason=f"heuristic Stage 2 matched {category!r} ({len(hits)} signal(s))",
            latency_us=int(latency_us),
            evidence={"signals": hits[:8], "confidence": round(confidence, 4)},
        )
