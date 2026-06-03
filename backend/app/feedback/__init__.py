"""Feedback loop — the alert-fatigue cure.

False-positive dispositions learn into suppression rules (human-approved,
expiring); confirmed dispositions promote into regression test cases; FP-rate
metrics prove the loop works. This is what makes the brief's alert-reduction
thesis a measured outcome rather than a claim.
"""

from app.feedback.metrics import FpStat, fp_rate_by_kind, overall_fp_rate
from app.feedback.service import narrative_to_testcase, on_false_positive
from app.feedback.store import (
    InMemorySuppressionStore,
    RedisSuppressionStore,
    SuppressionStore,
)
from app.feedback.suppression import (
    SuppressionRule,
    activate,
    expire,
    is_expired,
    is_suppressed,
    matches,
    suggest_from_narrative,
)

__all__ = [
    "FpStat",
    "fp_rate_by_kind",
    "overall_fp_rate",
    "narrative_to_testcase",
    "on_false_positive",
    "SuppressionStore",
    "InMemorySuppressionStore",
    "RedisSuppressionStore",
    "SuppressionRule",
    "activate",
    "expire",
    "is_expired",
    "is_suppressed",
    "matches",
    "suggest_from_narrative",
]
