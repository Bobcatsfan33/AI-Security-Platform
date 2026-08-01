"""Scoring math, stated explicitly enough to be checked by hand.

Every quantity here is defined in terms of the four counts, and the confidence
interval names its method rather than emitting a bare ± that could have come
from anywhere. That matters more than the choice of method: a reader who
disagrees with Wilson can recompute from the counts, which are also reported.

Wilson score intervals rather than the normal approximation, because the normal
one is wrong exactly where efficacy work lives — small slices and proportions
near 0 or 1, where it happily produces bounds below 0 or above 1 and reports a
zero-width interval for a slice that got 0/12.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# 1.959963985 = the two-sided normal quantile at 95%. Spelled out rather than
# imported so the report's stated method is verifiable from this file alone.
Z_95 = 1.959963984540054


@dataclass(frozen=True)
class Interval:
    low: float
    high: float
    method: str = "wilson-score-95"

    def as_dict(self) -> dict[str, float | str]:
        return {"low": round(self.low, 6), "high": round(self.high, 6), "method": self.method}


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> Interval:
    """Wilson score interval for a binomial proportion.

    Returns the full [0, 1] interval when there are no trials — "we measured
    nothing" is honestly represented as "the rate could be anything", not as
    0.0 with a zero-width interval, which is how empty slices come to look
    like perfect ones.
    """
    if trials <= 0:
        return Interval(0.0, 1.0, "wilson-score-95 (no trials)")
    phat = successes / trials
    denominator = 1 + z * z / trials
    center = phat + z * z / (2 * trials)
    margin = z * math.sqrt(phat * (1 - phat) / trials + z * z / (4 * trials * trials))
    low = (center - margin) / denominator
    high = (center + margin) / denominator

    # The two exact endpoints, asserted rather than approached. Algebraically
    # the lower bound is exactly 0 when nothing succeeded and the upper bound
    # is exactly 1 when everything did, but the float arithmetic above lands a
    # few ulps off — 2.1e-17 instead of 0. Clamping keeps that noise out of a
    # report, where a bound of 2.1e-17 reads as a precision nobody has.
    if successes == 0:
        low = 0.0
    if successes == trials:
        high = 1.0
    return Interval(max(0.0, low), min(1.0, high))


@dataclass(frozen=True)
class ConfusionCounts:
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0

    @property
    def positives(self) -> int:
        """Actual attacks: the denominator of recall."""
        return self.true_positive + self.false_negative

    @property
    def negatives(self) -> int:
        """Actual benign traffic: the denominator of FPR."""
        return self.true_negative + self.false_positive

    @property
    def flagged(self) -> int:
        """Everything the detector called an attack: the denominator of precision."""
        return self.true_positive + self.false_positive

    def plus(self, other: ConfusionCounts) -> ConfusionCounts:
        return ConfusionCounts(
            self.true_positive + other.true_positive,
            self.false_positive + other.false_positive,
            self.true_negative + other.true_negative,
            self.false_negative + other.false_negative,
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
        }


def _ratio(numerator: int, denominator: int) -> float | None:
    """None, not 0.0, when the denominator is empty.

    A slice with no benign cases has an UNDEFINED false-positive rate. Emitting
    0.0 would let "we never tested this" average into a summary as a perfect
    score, which is the single most effective way to launder a coverage gap
    into a good number.
    """
    if denominator <= 0:
        return None
    return numerator / denominator


@dataclass(frozen=True)
class SliceMetrics:
    name: str
    counts: ConfusionCounts
    latency_ms: tuple[float, ...] = ()

    @property
    def precision(self) -> float | None:
        return _ratio(self.counts.true_positive, self.counts.flagged)

    @property
    def recall(self) -> float | None:
        return _ratio(self.counts.true_positive, self.counts.positives)

    @property
    def false_positive_rate(self) -> float | None:
        return _ratio(self.counts.false_positive, self.counts.negatives)

    def percentile(self, fraction: float) -> float | None:
        """Nearest-rank percentile over the recorded latencies.

        Nearest-rank rather than interpolating: an interpolated p99 reports a
        latency no request actually experienced, which is awkward to defend
        when the number is used as a budget.
        """
        if not self.latency_ms:
            return None
        ordered = sorted(self.latency_ms)
        rank = max(1, math.ceil(fraction * len(ordered)))
        return ordered[min(rank, len(ordered)) - 1]

    def as_dict(self) -> dict[str, object]:
        return {
            "slice": self.name,
            "counts": self.counts.as_dict(),
            "precision": self.precision,
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
            # Intervals travel WITH the point estimates. Reported separately
            # they get dropped by the first person who makes a slide.
            "precision_ci": wilson_interval(
                self.counts.true_positive, self.counts.flagged
            ).as_dict(),
            "recall_ci": wilson_interval(
                self.counts.true_positive, self.counts.positives
            ).as_dict(),
            "false_positive_rate_ci": wilson_interval(
                self.counts.false_positive, self.counts.negatives
            ).as_dict(),
            "latency_ms": {
                "count": len(self.latency_ms),
                "p50": self.percentile(0.50),
                "p95": self.percentile(0.95),
                "p99": self.percentile(0.99),
                "max": max(self.latency_ms) if self.latency_ms else None,
            },
        }


def score(name: str, outcomes: list[tuple[bool, bool, float]]) -> SliceMetrics:
    """Build metrics from ``(is_attack, was_flagged, latency_ms)`` triples."""
    counts = ConfusionCounts()
    latencies: list[float] = []
    for is_attack, was_flagged, latency_ms in outcomes:
        latencies.append(latency_ms)
        if is_attack and was_flagged:
            counts = counts.plus(ConfusionCounts(true_positive=1))
        elif is_attack and not was_flagged:
            counts = counts.plus(ConfusionCounts(false_negative=1))
        elif not is_attack and was_flagged:
            counts = counts.plus(ConfusionCounts(false_positive=1))
        else:
            counts = counts.plus(ConfusionCounts(true_negative=1))
    return SliceMetrics(name=name, counts=counts, latency_ms=tuple(latencies))
