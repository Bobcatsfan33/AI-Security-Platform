"""Domain-advice detectors: legal advice and financial advice.

These flag prompts that solicit regulated professional advice (or
responses that purport to give it) — a common enterprise guardrail to
keep an assistant from creating liability."""

from __future__ import annotations

import re

from app.detectors.base import DetectorContext, DetectorResult, Direction
from app.detectors import util

_LEGAL = (
    (re.compile(r"\b(?:is|would)\s+(?:it|this|that)\s+(?:be\s+)?(?:il)?legal\b", re.I), 0.7),
    (re.compile(r"\bcan\s+i\s+(?:sue|be\s+sued|press\s+charges)\b", re.I), 0.8),
    (re.compile(r"\blegal\s+advice\b", re.I), 0.75),
    (re.compile(r"\b(?:should|do)\s+i\s+(?:plead|settle|sign)\b", re.I), 0.6),
    (
        re.compile(
            r"\b(?:lawsuit|liability|breach\s+of\s+contract|custody|alimony|defamation)\b", re.I
        ),
        0.45,
    ),
    (re.compile(r"\bwhat\s+are\s+my\s+(?:legal\s+)?rights\b", re.I), 0.55),
    (
        re.compile(
            r"\b(?:draft|write)\s+(?:me\s+)?(?:a\s+)?(?:contract|will|nda|cease\s+and\s+desist)\b",
            re.I,
        ),
        0.55,
    ),
)
_FINANCIAL = (
    (re.compile(r"\bshould\s+i\s+(?:buy|sell|invest\s+in|short)\b", re.I), 0.75),
    (re.compile(r"\bfinancial\s+advice\b", re.I), 0.75),
    (
        re.compile(
            r"\b(?:which|what)\s+(?:stocks?|crypto|coins?|funds?)\s+(?:should|to)\s+(?:i\s+)?(?:buy|invest)\b",
            re.I,
        ),
        0.8,
    ),
    (
        re.compile(
            r"\b(?:investment|retirement|portfolio)\s+(?:advice|recommendation|strategy)\b", re.I
        ),
        0.65,
    ),
    (re.compile(r"\bhow\s+(?:much|should)\s+i\s+invest\b", re.I), 0.6),
    (re.compile(r"\b(?:tax|tax-?saving)\s+advice\b", re.I), 0.55),
    (re.compile(r"\bwill\s+\w+\s+(?:stock|price)\s+go\s+(?:up|down)\b", re.I), 0.55),
)


def _scan(text: str, table) -> tuple[float, int]:
    score = 0.0
    hits = 0
    for pat, w in table:
        if pat.search(text):
            hits += 1
            score = max(score, w)
            score += w * 0.1
    return min(score, 1.0), hits


class LegalAdviceDetector:
    name = "legal_advice"
    category = "legal_advice"
    default_threshold = 0.5
    severity = "medium"
    directions = (Direction.BOTH,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        score, hits = _scan(text, _LEGAL)
        return DetectorResult(
            self.name, self.category, score, "medium", {"signals": hits, "band": util.band(score)}
        ).clamp()


class FinancialAdviceDetector:
    name = "financial_advice"
    category = "financial_advice"
    default_threshold = 0.5
    severity = "medium"
    directions = (Direction.BOTH,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        score, hits = _scan(text, _FINANCIAL)
        return DetectorResult(
            self.name, self.category, score, "medium", {"signals": hits, "band": util.band(score)}
        ).clamp()
