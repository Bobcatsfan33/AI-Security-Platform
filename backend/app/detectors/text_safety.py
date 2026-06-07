"""Content-moderation / safety detectors: toxicity, gibberish, LLM refusal,
off-topic."""

from __future__ import annotations

import re

from app.detectors.base import Detector, DetectorContext, DetectorResult, Direction
from app.detectors import util

# ─────────────────────────────────────────────── Toxicity

# Weighted lexicon. Weight ~ how strongly the term implies a toxic/abusive
# or hateful payload. Slurs / threats weigh highest.
_TOX_TERMS: tuple[tuple[str, float], ...] = (
    ("kill yourself", 1.0),
    ("kys", 0.9),
    ("i will kill you", 1.0),
    ("i'll kill you", 1.0),
    ("go die", 0.85),
    ("you should die", 0.95),
    ("retard", 0.7),
    ("idiot", 0.4),
    ("moron", 0.4),
    ("stupid", 0.3),
    ("hate you", 0.5),
    ("worthless", 0.5),
    ("piece of shit", 0.8),
    ("shut up", 0.35),
    ("bastard", 0.6),
    ("bitch", 0.6),
    ("asshole", 0.6),
    ("fuck you", 0.8),
    ("fuck", 0.45),
    ("shit", 0.3),
    ("dumbass", 0.55),
    ("nazi", 0.7),
    ("rape", 0.9),
    ("slur", 0.5),
)


class ToxicityDetector:
    name = "toxicity"
    category = "toxicity"
    default_threshold = 0.5
    severity = "high"
    directions = (Direction.BOTH,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        norm = util.collapse_obfuscation(text)
        hits: list[str] = []
        score = 0.0
        for term, weight in _TOX_TERMS:
            key = term.replace(" ", "")
            if term in norm or key in norm:
                hits.append(term)
                score = max(score, weight)
                score += weight * 0.15  # multiple hits compound a little
        sev = "critical" if score >= 0.9 else "high" if score >= 0.6 else "medium"
        return DetectorResult(
            self.name,
            self.category,
            min(score, 1.0),
            sev,
            {"matched_terms": hits[:8], "band": util.band(min(score, 1.0))},
        ).clamp()


# ─────────────────────────────────────────────── Gibberish


class GibberishDetector:
    name = "gibberish"
    category = "gibberish"
    default_threshold = 0.6
    severity = "low"
    directions = (Direction.BOTH,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        stripped = text.strip()
        if len(stripped) < 8:
            return DetectorResult(self.name, self.category, 0.0, "info", {"reason": "too short"})
        ws = util.words(stripped)
        if not ws:
            # all symbols/digits — likely gibberish for a natural-language channel
            return DetectorResult(self.name, self.category, 0.8, "low", {"reason": "no word chars"})
        avg_vowel = sum(util.vowel_ratio(w) for w in ws) / len(ws)
        ent = util.shannon_entropy(re.sub(r"\s+", "", stripped.lower()))
        en_ratio = util.english_word_ratio(stripped)
        long_consonant = sum(1 for w in ws if re.search(r"[bcdfghjklmnpqrstvwxz]{5,}", w.lower()))
        score = 0.0
        if avg_vowel < 0.18:
            score += 0.4
        if en_ratio < 0.15:
            score += 0.35
        if ent > 4.2 and en_ratio < 0.2:
            score += 0.2
        if long_consonant / max(len(ws), 1) > 0.3:
            score += 0.25
        return DetectorResult(
            self.name,
            self.category,
            min(score, 1.0),
            "low",
            {
                "avg_vowel_ratio": round(avg_vowel, 3),
                "english_word_ratio": round(en_ratio, 3),
                "entropy": round(ent, 3),
            },
        ).clamp()


# ─────────────────────────────────────────────── LLM refusal (outbound)

_REFUSAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bi(?:'m| am)\s+sorry,?\s+but\s+i\s+(?:can'?t|cannot|won'?t)\b", re.I),
    re.compile(r"\bi\s+can'?t\s+(?:help|assist|comply|provide|do)\b", re.I),
    re.compile(r"\bi\s+cannot\s+(?:help|assist|comply|provide|fulf[il]+)\b", re.I),
    re.compile(r"\bas\s+an?\s+(?:ai|language model|assistant)\b", re.I),
    re.compile(r"\bi'?m\s+(?:not\s+able|unable)\s+to\b", re.I),
    re.compile(r"\b(?:that|this)\s+(?:request|content)\s+(?:violates|goes against)\b", re.I),
    re.compile(r"\bi\s+(?:must|have to)\s+decline\b", re.I),
)


class LLMRefusalDetector:
    name = "llm_refusal"
    category = "llm_refusal"
    default_threshold = 0.5
    severity = "info"
    directions = (Direction.OUTBOUND,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        hits = [p.pattern for p in _REFUSAL_PATTERNS if p.search(text)]
        # Confidence scales with number of distinct refusal cues, capped.
        score = min(0.55 + 0.2 * (len(hits) - 1), 0.98) if hits else 0.0
        return DetectorResult(
            self.name,
            self.category,
            score,
            "info",
            {"cues": len(hits), "band": util.band(score)},
        ).clamp()


# ─────────────────────────────────────────────── Off-topic


class OffTopicDetector:
    """Flags prompts that fall outside the org's allowed topic set.

    ``ctx.allowed_topics`` carries operator-defined topic keywords (e.g.
    ["insurance","claims","policy"] for an insurance assistant). When the
    prompt shares no meaningful vocabulary with the allowed topics it is
    considered off-topic. With no allowed_topics configured the detector
    is a no-op (confidence 0)."""

    name = "off_topic"
    category = "off_topic"
    default_threshold = 0.6
    severity = "low"
    directions = (Direction.INBOUND,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        if not ctx.allowed_topics:
            return DetectorResult(
                self.name, self.category, 0.0, "info", {"reason": "no allowed_topics configured"}
            )
        toks = set(util.tokens(text)) - util.COMMON_EN
        topic_toks: set[str] = set()
        for t in ctx.allowed_topics:
            topic_toks |= set(util.tokens(t))
        if not toks:
            return DetectorResult(
                self.name, self.category, 0.0, "info", {"reason": "no content tokens"}
            )
        overlap = toks & topic_toks
        coverage = len(overlap) / len(topic_toks) if topic_toks else 0.0
        on_topic_hits = len(overlap)
        # Off-topic confidence is inverse to overlap.
        if on_topic_hits == 0:
            score = 0.85
        elif coverage < 0.15:
            score = 0.55
        else:
            score = max(0.0, 0.4 - coverage)
        return DetectorResult(
            self.name,
            self.category,
            score,
            "low",
            {"on_topic_overlap": sorted(overlap)[:6], "coverage": round(coverage, 3)},
        ).clamp()
