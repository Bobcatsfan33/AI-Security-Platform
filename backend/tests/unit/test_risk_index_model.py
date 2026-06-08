"""Risk-index scoring model — the public WEIGHTS + GRADE_BANDS that back
GET /v1/risk-index/model, and that the grade derivation stays consistent.
"""

from __future__ import annotations

import pytest

from app.spm.risk_index import GRADE_BANDS, WEIGHTS, compute_risk_index

pytestmark = pytest.mark.unit


def test_weights_sum_to_one():
    assert sum(WEIGHTS.values()) == pytest.approx(1.0)


def test_grade_bands_cover_full_range_descending():
    mins = [int(b["min"]) for b in GRADE_BANDS]
    assert mins == sorted(mins, reverse=True)
    assert mins[-1] == 0  # an A floor at 0 so every score grades


def test_grade_matches_bands():
    # All weight on one maxed component → score 100 → worst grade.
    worst = compute_risk_index(
        asset_id="a",
        supply_chain_score=1.0,
        iam_over_privilege=1.0,
        runtime_block_rate=1.0,
        redteam_success_rate=1.0,
    )
    assert worst.score == 100.0
    assert worst.grade == "F"
    # Zero exposure → A.
    best = compute_risk_index(asset_id="a")
    assert best.score == 0.0
    assert best.grade == "A"
