"""AI Guard response object — the simple ``Allow | Block | Detect`` body.

The product's key UX/integration win (per the competitive battlecards) is a
flat, predictable response body: a single top-level ``action`` the calling
code branches on, plus per-detector detail. No per-detector response-shape
variance."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Action = Literal["allow", "block", "detect"]


@dataclass(frozen=True)
class DetectorOutcome:
    name: str
    category: str
    confidence: float
    threshold: float
    triggered: bool
    action: str  # configured action for this detector
    severity: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AIGuardResponse:
    action: Action
    direction: str
    triggered: tuple[str, ...]
    detectors: tuple[DetectorOutcome, ...]
    latency_ms: float
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "direction": self.direction,
            "reason": self.reason,
            "triggered": list(self.triggered),
            "latency_ms": round(self.latency_ms, 3),
            "detectors": [asdict(d) for d in self.detectors],
        }
