"""Aggregate AI Risk Index for an asset.

Blends supply-chain risk (:mod:`app.aibom.risk`), IAM over-privilege
(:mod:`app.spm.iam`), runtime detector exposure (share of recent traffic that
triggered AI Guard), and red-team exposure (share of attacks that succeeded)
into a single 0-100 index + letter grade. Backs the product's "AI App Risk
Index"."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

WEIGHTS = {
    "supply_chain": 0.30,
    "iam": 0.25,
    "runtime_exposure": 0.25,
    "redteam_exposure": 0.20,
}

# Grade bands as (grade, inclusive lower bound), ordered high->low. The index is
# 0-100 where higher = riskier, so an F is the worst.
GRADE_BANDS: list[dict[str, object]] = [
    {"grade": "F", "min": 80},
    {"grade": "D", "min": 60},
    {"grade": "C", "min": 40},
    {"grade": "B", "min": 20},
    {"grade": "A", "min": 0},
]


def _grade(score: float) -> str:
    for band in GRADE_BANDS:
        if score >= float(band["min"]):  # type: ignore[arg-type]
            return str(band["grade"])
    return "A"


@dataclass(frozen=True)
class RiskIndex:
    asset_id: str
    score: float  # 0..100 (higher = riskier)
    grade: str
    components: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_risk_index(
    *,
    asset_id: str,
    supply_chain_score: float = 0.0,  # 0..1
    iam_over_privilege: float = 0.0,  # 0..1
    runtime_block_rate: float = 0.0,  # 0..1 fraction of traffic blocked/flagged
    redteam_success_rate: float = 0.0,  # 0..1
) -> RiskIndex:
    comps = {
        "supply_chain": _clamp(supply_chain_score),
        "iam": _clamp(iam_over_privilege),
        "runtime_exposure": _clamp(runtime_block_rate),
        "redteam_exposure": _clamp(redteam_success_rate),
    }
    weighted = sum(comps[k] * WEIGHTS[k] for k in comps) * 100
    score = round(weighted, 2)
    return RiskIndex(
        asset_id=asset_id,
        score=score,
        grade=_grade(score),
        components={k: round(v, 4) for k, v in comps.items()},
    )


def _clamp(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else float(x)
