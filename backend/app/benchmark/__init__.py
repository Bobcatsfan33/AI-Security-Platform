"""Detection benchmark (Phase 2) — a reproducible efficacy scorecard.

Runs a labeled corpus of attacks (by class) plus benign traffic through the
real detection path (AI Guard suite + the decode/normalize pre-pass) and
measures per-class detection rate, false-positive rate on benign traffic, and
inline latency percentiles. This is the evidence layer: you cannot put an
inline proxy on production traffic without knowing its blast radius.
"""

from app.benchmark.corpus import DETECTION_CORPUS, CorpusCase
from app.benchmark.scorecard import (
    ClassScore,
    Scorecard,
    render_scorecard_markdown,
    run_detection_benchmark,
)

__all__ = [
    "DETECTION_CORPUS",
    "ClassScore",
    "CorpusCase",
    "Scorecard",
    "render_scorecard_markdown",
    "run_detection_benchmark",
]
