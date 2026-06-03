"""False-positive metrics — the number that proves the loop works.

Computes FP rate per narrative kind from dispositioned narratives. The exit
criterion for the feedback loop is a measurable FP-rate decline across tuning
cycles; this is what produces that number (instead of the brief's unverified
85–95% claim — we measure actuals).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from app.narratives.narrative import ThreatNarrative

# A disposition counts toward the FP rate only once an analyst has ruled.
_RULED = {"confirmed", "false_positive"}


@dataclass(frozen=True)
class FpStat:
    kind: str
    confirmed: int
    false_positive: int

    @property
    def total(self) -> int:
        return self.confirmed + self.false_positive

    @property
    def fp_rate(self) -> float:
        return self.false_positive / self.total if self.total else 0.0


def fp_rate_by_kind(narratives: Iterable[ThreatNarrative]) -> dict[str, FpStat]:
    """FP stats per kind over the ruled narratives."""
    confirmed: dict[str, int] = {}
    fp: dict[str, int] = {}
    for n in narratives:
        if n.status not in _RULED:
            continue
        if n.status == "confirmed":
            confirmed[n.kind] = confirmed.get(n.kind, 0) + 1
        else:
            fp[n.kind] = fp.get(n.kind, 0) + 1
    kinds = set(confirmed) | set(fp)
    return {
        k: FpStat(kind=k, confirmed=confirmed.get(k, 0), false_positive=fp.get(k, 0)) for k in kinds
    }


def overall_fp_rate(narratives: Iterable[ThreatNarrative]) -> float:
    ruled = [n for n in narratives if n.status in _RULED]
    if not ruled:
        return 0.0
    fps = sum(1 for n in ruled if n.status == "false_positive")
    return fps / len(ruled)
