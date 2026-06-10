"""Detection scorecard (Phase 2) — the reproducible CI efficacy gate.

Two layers:
1. Harness unit tests over a deterministic stub (the math is correct).
2. The live scorecard gate: run the real detection path over the corpus and
   assert floors (detection rate per class + overall), a benign false-positive
   ceiling, and an inline-latency budget (the Phase-2.4 latency gate). The
   rendered scorecard is printed so every CI run publishes the numbers.

Floors are a RATCHET pinned below current measured efficacy — raise them as
detection improves (e.g. when the Phase-1 ONNX model lands), never lower.
"""

from __future__ import annotations

import pytest

from app.benchmark import run_detection_benchmark
from app.benchmark.corpus import DETECTION_CORPUS, CorpusCase
from app.benchmark.scorecard import Scorecard, render_scorecard_markdown

pytestmark = pytest.mark.unit


# ─────────────────────────────────────────────── harness math (deterministic)


def _stub(detected_texts: set[str]):
    return lambda text: "block" if text in detected_texts else "allow"


class TestHarness:
    def test_perfect_detector_scores_100_and_zero_fp(self):
        corpus = (
            CorpusCase("atk1", "attack", "prompt_injection"),
            CorpusCase("atk2", "attack", "jailbreak"),
            CorpusCase("ok1", "benign"),
        )
        sc = run_detection_benchmark(corpus, action_fn=_stub({"atk1", "atk2"}))
        assert sc.overall_detection_rate == 1.0
        assert sc.false_positive_rate == 0.0
        assert sc.class_rate("prompt_injection") == 1.0

    def test_misses_and_false_positives_are_counted(self):
        corpus = (
            CorpusCase("atk1", "attack", "jailbreak"),
            CorpusCase("atk2", "attack", "jailbreak"),
            CorpusCase("ok1", "benign"),
            CorpusCase("ok2", "benign"),
        )
        # detect one of two attacks; wrongly flag one benign
        sc = run_detection_benchmark(corpus, action_fn=_stub({"atk1", "ok1"}))
        assert sc.class_rate("jailbreak") == 0.5
        assert sc.false_positive_rate == 0.5

    def test_to_dict_and_markdown_render(self):
        sc = run_detection_benchmark(
            (CorpusCase("a", "attack", "pii"), CorpusCase("b", "benign")),
            action_fn=_stub({"a"}),
        )
        d = sc.to_dict()
        assert d["by_class"]["pii"]["detection_rate"] == 1.0
        assert "Detection Scorecard" in render_scorecard_markdown(sc)


# ─────────────────────────────────────────────── live scorecard gate

# Ratchet floors — pinned below current measured efficacy. Raise as detection
# improves; never lower. (Measured at authoring: overall 72%, FP 0%, p99<1ms.)
_OVERALL_DETECTION_FLOOR = 0.65
_FALSE_POSITIVE_CEILING = 0.05
_ENCODING_BYPASS_FLOOR = 0.90  # guards the decode/normalize pre-pass (Phase 0.1)
_P99_LATENCY_BUDGET_MS = 50.0


@pytest.fixture(scope="module")
def scorecard() -> Scorecard:
    return run_detection_benchmark(DETECTION_CORPUS)


def test_publish_scorecard(scorecard: Scorecard) -> None:
    # Printed so every CI run records the reproducible scorecard.
    print("\n" + render_scorecard_markdown(scorecard))


def test_overall_detection_rate_meets_floor(scorecard: Scorecard) -> None:
    assert scorecard.overall_detection_rate >= _OVERALL_DETECTION_FLOOR, (
        f"overall detection {scorecard.overall_detection_rate:.3f} "
        f"< floor {_OVERALL_DETECTION_FLOOR}"
    )


def test_false_positive_rate_under_ceiling(scorecard: Scorecard) -> None:
    assert (
        scorecard.false_positive_rate <= _FALSE_POSITIVE_CEILING
    ), f"benign FP rate {scorecard.false_positive_rate:.3f} > ceiling {_FALSE_POSITIVE_CEILING}"


def test_encoding_bypass_class_floor(scorecard: Scorecard) -> None:
    # The decode/normalize pre-pass must keep this class near-fully covered.
    assert scorecard.class_rate("encoding_bypass") >= _ENCODING_BYPASS_FLOOR


def test_every_attack_class_detects_something(scorecard: Scorecard) -> None:
    # A class dropping to 0% detection is a regression, however noisy the class.
    zero = [c.attack_class for c in scorecard.by_class if c.detected == 0]
    assert not zero, f"classes with 0% detection: {zero}"


def test_inline_latency_under_budget(scorecard: Scorecard) -> None:
    assert (
        scorecard.p99_latency_ms < _P99_LATENCY_BUDGET_MS
    ), f"inline p99 {scorecard.p99_latency_ms:.2f} ms exceeds budget {_P99_LATENCY_BUDGET_MS} ms"
