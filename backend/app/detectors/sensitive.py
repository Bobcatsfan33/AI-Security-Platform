"""Sensitive-data detectors: context-aware PII, secrets/credentials,
brand & reputation, competition."""

from __future__ import annotations

import re

from app.detectors.base import DetectorContext, DetectorResult, Direction
from app.detectors import util
from app.policy.compiled import PII_PATTERNS, luhn_check

# Additional regulated identifiers beyond the Stage-1 PII_PATTERNS set.
_EXT_PII: dict[str, re.Pattern[str]] = {
    "passport": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "us_bank_routing": re.compile(r"\b(?:0[1-9]|1[0-2]|2[1-9]|3[0-2])\d{7}\b"),
    "mrn": re.compile(r"\bMRN[:#]?\s*\d{5,10}\b", re.I),
    "dob": re.compile(r"\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b"),
}
# Context words that, when near an identifier, raise confidence ("context-aware").
_PII_CONTEXT = re.compile(
    r"\b(?:patient|diagnos|medical|ssn|social\s+security|passport|salary|account|"
    r"routing|date\s+of\s+birth|dob|home\s+address|customer|employee)\b",
    re.I,
)


class ContextAwarePIIDetector:
    """Pattern PII + extended identifiers, with a context multiplier. A bare
    9-digit number is weak; the same number next to "SSN:" or "patient" is
    strong."""

    name = "context_aware_pii"
    category = "pii"
    default_threshold = 0.5
    severity = "high"
    directions = (Direction.BOTH,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        found: dict[str, int] = {}
        for label, pat in PII_PATTERNS.items():
            for m in pat.findall(text):
                if label == "credit_card" and not luhn_check(
                    m if isinstance(m, str) else "".join(m)
                ):
                    continue
                found[label] = found.get(label, 0) + 1
        for label, pat in _EXT_PII.items():
            n = len(pat.findall(text))
            if n:
                found[label] = found.get(label, 0) + n
        if not found:
            return DetectorResult(self.name, self.category, 0.0, "info", {})
        has_context = bool(_PII_CONTEXT.search(text))
        base = min(0.45 + 0.12 * (len(found) - 1) + 0.06 * (sum(found.values()) - 1), 0.85)
        score = min(base + (0.2 if has_context else 0.0), 0.99)
        sev = "critical" if {"ssn", "credit_card", "passport", "iban"} & set(found) else "high"
        return DetectorResult(
            self.name,
            self.category,
            score,
            sev,
            {"types": sorted(found), "counts": found, "context_boost": has_context},
        ).clamp()


_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws_secret": re.compile(r"\b(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])\b"),
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "github_pat": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "google_api": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "bearer": re.compile(r"\b[Bb]earer\s+[A-Za-z0-9._-]{20,}\b"),
    "password_assign": re.compile(
        r"\b(?:password|passwd|pwd|secret|api[_-]?key)\s*[=:]\s*\S{6,}", re.I
    ),
}


class SecretsDetector:
    name = "credentials_secrets"
    category = "credentials"
    default_threshold = 0.5
    severity = "critical"
    directions = (Direction.BOTH,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        hits: list[str] = []
        for label, pat in _SECRET_PATTERNS.items():
            m = pat.search(text)
            if not m:
                continue
            # entropy gate for the generic 40-char AWS-secret shape to cut FPs
            if label == "aws_secret" and util.shannon_entropy(m.group(0)) < 4.0:
                continue
            hits.append(label)
        if not hits:
            return DetectorResult(self.name, self.category, 0.0, "info", {})
        score = min(0.7 + 0.1 * (len(hits) - 1), 0.99)
        return DetectorResult(
            self.name, self.category, score, "critical", {"secret_types": hits}
        ).clamp()


class BrandReputationDetector:
    """Flags content mentioning protected brand/reputation terms, optionally
    co-occurring with negative sentiment (reputational risk)."""

    name = "brand_reputation"
    category = "brand_reputation"
    default_threshold = 0.5
    severity = "low"
    directions = (Direction.OUTBOUND,)

    _NEG = re.compile(
        r"\b(?:terrible|awful|scam|fraud|lawsuit|hate|worst|broken|garbage|sucks|disaster)\b", re.I
    )

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        if not ctx.brand_terms:
            return DetectorResult(
                self.name, self.category, 0.0, "info", {"reason": "no brand_terms configured"}
            )
        low = text.lower()
        mentioned = [b for b in ctx.brand_terms if b.lower() in low]
        if not mentioned:
            return DetectorResult(self.name, self.category, 0.0, "info", {})
        negative = bool(self._NEG.search(text))
        score = 0.7 if negative else 0.4
        return DetectorResult(
            self.name,
            self.category,
            score,
            "medium" if negative else "low",
            {"brands": mentioned, "negative_sentiment": negative},
        ).clamp()


class CompetitionDetector:
    """Flags mentions of configured competitor names (e.g. to stop an
    assistant recommending or disparaging competitors)."""

    name = "competition"
    category = "competition"
    default_threshold = 0.5
    severity = "low"
    directions = (Direction.BOTH,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        if not ctx.competitor_terms:
            return DetectorResult(
                self.name, self.category, 0.0, "info", {"reason": "no competitor_terms configured"}
            )
        low = text.lower()
        mentioned = [c for c in ctx.competitor_terms if c.lower() in low]
        if not mentioned:
            return DetectorResult(self.name, self.category, 0.0, "info", {})
        score = min(0.55 + 0.15 * (len(mentioned) - 1), 0.95)
        return DetectorResult(
            self.name, self.category, score, "low", {"competitors": mentioned}
        ).clamp()
