"""AI Guard detector framework — base types.

This package implements the breadth of inline content detectors that
"AI Guard" exposes (toxicity, prompt injection, malicious URL, invisible
text, off-topic, gibberish, legal/financial advice, language & code
detection, LLM refusal, brand/competition, context-aware PII, secrets).

Design goals
------------
* **Deterministic & dependency-free.** Every detector is pure-Python,
  no network, no heavyweight ML import. That keeps the hot path fast,
  testable offline, and portable to the Go runtime agent. Where a real
  deployment would swap in an ONNX/transformer model, the detector
  documents that the lexical/structural implementation is the floor.
* **Per-detector "sliding threshold."** Each detector emits a calibrated
  confidence in ``[0, 1]``. The operator tunes a per-detector threshold
  (the "sliding threshold meter" in the product) and the engine compares
  confidence against it to decide whether the detector *triggers*.
* **Direction aware.** Some detectors only make sense inbound
  (prompt → model), some outbound (model → user, e.g. LLM refusal).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

Severity = str  # "info" | "low" | "medium" | "high" | "critical"


class Direction(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BOTH = "both"


@dataclass(frozen=True)
class DetectorContext:
    """Optional signals a detector may consult.

    Mirrors the policy ``content_filters`` config bag. Everything is
    optional so a bare ``DetectorContext()`` is always valid.
    """

    direction: Direction = Direction.INBOUND
    allowed_topics: tuple[str, ...] = ()  # off-topic detector
    competitor_terms: tuple[str, ...] = ()  # competition detector
    brand_terms: tuple[str, ...] = ()  # brand & reputation detector
    allowed_languages: tuple[str, ...] = ()  # language detector ("en","es",…)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectorResult:
    """One detector's verdict on one piece of text."""

    name: str
    category: str
    confidence: float  # calibrated [0,1]
    severity: Severity = "low"
    evidence: dict[str, Any] = field(default_factory=dict)

    def clamp(self) -> "DetectorResult":
        c = 0.0 if self.confidence < 0 else 1.0 if self.confidence > 1 else self.confidence
        return DetectorResult(self.name, self.category, round(c, 4), self.severity, self.evidence)


@runtime_checkable
class Detector(Protocol):
    """Detector interface. Implementations are stateless and reusable."""

    name: str
    category: str
    default_threshold: float
    severity: Severity
    directions: tuple[Direction, ...]

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult: ...


def applies(detector: Detector, direction: Direction) -> bool:
    """Whether ``detector`` should run for the given traffic direction."""
    if Direction.BOTH in detector.directions:
        return True
    return direction in detector.directions
