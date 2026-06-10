"""Detection scorecard — run the corpus through the real detection path and
measure per-class detection rate, benign false-positive rate, and inline
latency percentiles.

A case is "detected" when AI Guard returns a non-``allow`` action (it flagged
or blocked). For benign traffic, a detection is a false positive.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.benchmark.corpus import DETECTION_CORPUS, CorpusCase

# A detector callable: text -> "allow" | "detect" | "block".
ActionFn = Callable[[str], str]

# Content-policy *category* detectors (is this text about finance / legal / code
# / off-topic, etc.) — opt-in business filters, NOT security threat detection.
# The scorecard measures SECURITY efficacy, so these are disabled so a benign
# "should I buy Tesla stock?" isn't scored as a false positive.
CONTENT_POLICY_DETECTORS = (
    "financial_advice",
    "legal_advice",
    "source_code",
    "programming_language",
    "language",
    "off_topic",
    "competition",
    "brand_reputation",
)


def _security_config() -> dict[str, dict[str, str]]:
    return {name: {"action": "off"} for name in CONTENT_POLICY_DETECTORS}


def _default_action_fn() -> ActionFn:
    from app.aiguard.service import get_service

    service = get_service()
    config = _security_config()

    def _inspect(text: str) -> str:
        return service.inspect(text=text, config=config).action

    return _inspect


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (pct / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


@dataclass(frozen=True)
class ClassScore:
    attack_class: str
    total: int
    detected: int

    @property
    def detection_rate(self) -> float:
        return self.detected / self.total if self.total else 0.0


@dataclass(frozen=True)
class Scorecard:
    by_class: tuple[ClassScore, ...]
    benign_total: int
    false_positives: int
    latencies_ms: tuple[float, ...] = field(default_factory=tuple)

    @property
    def attack_total(self) -> int:
        return sum(c.total for c in self.by_class)

    @property
    def attack_detected(self) -> int:
        return sum(c.detected for c in self.by_class)

    @property
    def overall_detection_rate(self) -> float:
        return self.attack_detected / self.attack_total if self.attack_total else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.false_positives / self.benign_total if self.benign_total else 0.0

    @property
    def p50_latency_ms(self) -> float:
        return _percentile(list(self.latencies_ms), 50)

    @property
    def p99_latency_ms(self) -> float:
        return _percentile(list(self.latencies_ms), 99)

    def class_rate(self, attack_class: str) -> float:
        for c in self.by_class:
            if c.attack_class == attack_class:
                return c.detection_rate
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_detection_rate": round(self.overall_detection_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "attack_total": self.attack_total,
            "attack_detected": self.attack_detected,
            "benign_total": self.benign_total,
            "false_positives": self.false_positives,
            "latency_p50_ms": round(self.p50_latency_ms, 3),
            "latency_p99_ms": round(self.p99_latency_ms, 3),
            "by_class": {
                c.attack_class: {
                    "total": c.total,
                    "detected": c.detected,
                    "detection_rate": round(c.detection_rate, 4),
                }
                for c in self.by_class
            },
        }


def run_detection_benchmark(
    corpus: tuple[CorpusCase, ...] = DETECTION_CORPUS,
    *,
    action_fn: ActionFn | None = None,
) -> Scorecard:
    """Run every corpus case through the detection path and tally the scorecard.

    ``action_fn`` maps text → the AI Guard action; defaults to the live
    service. Injectable so tests can drive a deterministic stub.
    """
    act = action_fn or _default_action_fn()

    per_class_total: dict[str, int] = {}
    per_class_detected: dict[str, int] = {}
    benign_total = 0
    false_positives = 0
    latencies: list[float] = []

    for case in corpus:
        start = time.perf_counter()
        action = act(case.text)
        latencies.append((time.perf_counter() - start) * 1000.0)
        detected = action != "allow"

        if case.label == "attack":
            per_class_total[case.attack_class] = per_class_total.get(case.attack_class, 0) + 1
            if detected:
                per_class_detected[case.attack_class] = (
                    per_class_detected.get(case.attack_class, 0) + 1
                )
        else:
            benign_total += 1
            if detected:
                false_positives += 1

    by_class = tuple(
        ClassScore(
            attack_class=cls,
            total=per_class_total[cls],
            detected=per_class_detected.get(cls, 0),
        )
        for cls in sorted(per_class_total)
    )
    return Scorecard(
        by_class=by_class,
        benign_total=benign_total,
        false_positives=false_positives,
        latencies_ms=tuple(latencies),
    )


def render_scorecard_markdown(scorecard: Scorecard) -> str:
    """Render the scorecard as a Markdown efficacy report."""
    d = scorecard.to_dict()
    lines = [
        "# AI Guard Detection Scorecard",
        "",
        f"- **Overall detection rate:** {d['overall_detection_rate'] * 100:.1f}% "
        f"({d['attack_detected']}/{d['attack_total']} attacks)",
        f"- **False-positive rate (benign):** {d['false_positive_rate'] * 100:.1f}% "
        f"({d['false_positives']}/{d['benign_total']})",
        f"- **Inline latency:** p50 {d['latency_p50_ms']:.2f} ms · "
        f"p99 {d['latency_p99_ms']:.2f} ms",
        "",
        "## Detection rate by attack class",
        "",
        "| Class | Detected | Total | Rate |",
        "| --- | --- | --- | --- |",
    ]
    for cls, s in d["by_class"].items():
        lines.append(
            f"| {cls} | {s['detected']} | {s['total']} | {s['detection_rate'] * 100:.1f}% |"
        )
    lines.append("")
    lines.append(
        "_Synthetic, in-repo corpus — measures the AI Guard suite + decode/normalize "
        "pre-pass (Stages 1-2). Not a substitute for live-traffic evaluation._"
    )
    return "\n".join(lines)
