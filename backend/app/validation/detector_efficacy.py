"""Per-detector efficacy — precision/recall/F1/FPR over the labeled eval set.

Runs each AI Guard detector at its default threshold across EVAL_SET and reports
the confusion matrix + derived metrics. This is the harness the battlecard's
"F1 ≥ 0.9, low FPR" claim is measured against; the numbers reported here are the
DETERMINISTIC floor (a trained ONNX model raises them).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.detectors import ALL_DETECTORS
from app.detectors.base import Detector, DetectorContext, Direction, applies
from app.validation.detector_eval_set import EVAL_SET, EvalSample


@dataclass(frozen=True)
class DetectorMetrics:
    name: str
    category: str
    threshold: float
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "threshold": self.threshold,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
            "fpr": round(self.fpr, 3),
        }


def _ctx(sample_ctx: dict[str, Any]) -> tuple[DetectorContext, Direction]:
    direction = Direction(sample_ctx.get("direction", "inbound"))
    ctx = DetectorContext(
        direction=direction,
        allowed_topics=tuple(sample_ctx.get("allowed_topics", ())),
        competitor_terms=tuple(sample_ctx.get("competitor_terms", ())),
        brand_terms=tuple(sample_ctx.get("brand_terms", ())),
        allowed_languages=tuple(sample_ctx.get("allowed_languages", ())),
    )
    return ctx, direction


def _score_detector(det: Detector, eval_set: list[EvalSample]) -> DetectorMetrics:
    tp = fp = fn = tn = 0
    for text, cats, sample_ctx in eval_set:
        ctx, direction = _ctx(sample_ctx)
        if not applies(det, direction):
            continue  # detector not applicable to this sample's direction
        expected = det.category in cats
        result = det.detect(text, ctx).clamp()
        triggered = result.confidence >= det.default_threshold
        if expected and triggered:
            tp += 1
        elif expected and not triggered:
            fn += 1
        elif not expected and triggered:
            fp += 1
        else:
            tn += 1
    return DetectorMetrics(det.name, det.category, det.default_threshold, tp, fp, fn, tn)


def evaluate_detectors(eval_set: list[EvalSample] | None = None) -> dict[str, Any]:
    """Run every detector over the eval set; return per-detector metrics +
    macro-averaged F1/FPR + the count of detectors meeting the F1 ≥ 0.9 bar."""
    es = eval_set if eval_set is not None else EVAL_SET
    metrics = [_score_detector(d, es) for d in ALL_DETECTORS]
    # Macro-average over detectors that had at least one positive sample.
    scored = [m for m in metrics if (m.tp + m.fn) > 0]
    macro_f1 = sum(m.f1 for m in scored) / len(scored) if scored else 0.0
    macro_fpr = sum(m.fpr for m in metrics) / len(metrics) if metrics else 0.0
    meeting_bar = sum(1 for m in scored if m.f1 >= 0.9)
    return {
        "samples": len(es),
        "detectors_scored": len(scored),
        "macro_f1": round(macro_f1, 3),
        "macro_fpr": round(macro_fpr, 3),
        "detectors_meeting_f1_0.9": meeting_bar,
        "note": (
            "Deterministic floor metrics. Trained ONNX models behind "
            "STAGE2_ONNX_ENDPOINT raise F1 toward the 0.9 target."
        ),
        "per_detector": [m.to_dict() for m in metrics],
    }
