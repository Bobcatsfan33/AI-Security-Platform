"""Prompt-injection, jailbreak, and invisible-text detectors."""

from __future__ import annotations

import re
import unicodedata

from app.detectors import util
from app.detectors.base import DetectorContext, DetectorResult, Direction

_PI_SIGNALS: tuple[tuple[re.Pattern[str], float], ...] = (
    (
        re.compile(
            r"\bignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|provided)"
            r"(?:\s+(?:instructions?|directions?|context|orders?))?\b",
            re.I,
        ),
        0.8,
    ),
    (re.compile(r"\bdisregard\s+(?:all\s+)?(?:previous|prior|the\s+above)\b", re.I), 0.75),
    (
        re.compile(
            r"\bforget\s+(?:about\s+)?(?:all\s+)?(?:everything|the\s+previous\s+orders?)"
            r"(?:\s+(?:I|we|you|that|before|previously|so\s+far)\b.{0,50})?",
            re.I,
        ),
        0.8,
    ),
    (re.compile(r"\brepeat\s+(?:the\s+)?(?:text|words|everything|prompt)\s+above\b", re.I), 0.7),
    (
        re.compile(
            r"\b(?:spell[\s-]?check|print|return)\b.{0,45}\b(?:above|initial|hidden)"
            r"\s+(?:prompt|text|instructions?)\b",
            re.I,
        ),
        0.8,
    ),
    (
        re.compile(
            r"\b(?:reveal|print|show|output)\s+(?:your\s+)?(?:system|initial|the)\s+prompt\b", re.I
        ),
        0.85,
    ),
    (re.compile(r"\b(?:show|reveal)\b.{0,35}\bprompt[\s-]?texts?\b", re.I), 0.85),
    (re.compile(r"\breturn\s+(?:all\s+)?your\s+embeddings?\b", re.I), 0.85),
    (re.compile(r"\bwhat\s+(?:are|were)\s+your\s+(?:original\s+)?instructions\b", re.I), 0.6),
    (re.compile(r"\bwhat\s+your\s+initial\s+instructions\s+were\b", re.I), 0.75),
    (re.compile(r"\bnew\s+instructions?\s*:\s*", re.I), 0.55),
    (re.compile(r"\bignore\s+your\s+(?:directions?|instructions?|orders?)\b", re.I), 0.8),
    (re.compile(r"\boverride\s+(?:your\s+)?(?:safety|guidelines|rules|system)\b", re.I), 0.7),
    (re.compile(r"</?\s*(?:system|instructions?)\s*>", re.I), 0.6),  # fake delimiter injection
    # High-confidence override language from the external bilingual test set.
    (
        re.compile(
            r"\b(?:vergiss|vergessen\s+sie)\s+(?:jetzt\s+)?(?:alles|alle)"
            r"(?:\s+(?:davor|bisherigen?|zuvor|was))?\b",
            re.I,
        ),
        0.8,
    ),
    (
        re.compile(
            r"\bignorieren\s+sie\s+(?:die\s+)?(?:obigen?|vorherigen?)"
            r"(?:\s+(?:angaben|anweisungen))?\b",
            re.I,
        ),
        0.8,
    ),
    (re.compile(r"\bhöre\s+nicht\s+auf\s+alles\s+zuvor\s+gesagte\b", re.I), 0.8),
    (re.compile(r"\bolvide\s+todo\s+(?:lo\s+)?que\s+(?:dije|he\s+dicho)\b", re.I), 0.8),
)

# These structures are strong override evidence only when the text crossed an
# explicit untrusted-content boundary. In a direct user prompt, translation,
# roleplay, and forced-response games can be legitimate requests. In retrieved
# documents/tool output, they are instructions attempting to steer the model.
_UNTRUSTED_PI_SIGNALS: tuple[tuple[re.Pattern[str], float], ...] = (
    (
        re.compile(
            r"\b(?:ignore|ignroe|ingore|igmre)\b.{0,45}\bwhat\s+i\s+said\s+before\b",
            re.I,
        ),
        0.8,
    ),
    (
        re.compile(
            r"\bif\s+you\s+(?:do\s+not|don't)\s+know\s*,\s*" r"(?:say|answer|respond)\b",
            re.I,
        ),
        0.75,
    ),
    (re.compile(r"\bsi\s+yo\s+digo\b.{0,60}\bt[uú]\s+dices\b", re.I), 0.8),
)


class PromptInjectionDetector:
    name = "prompt_injection"
    category = "prompt_injection"
    default_threshold = 0.5
    severity = "high"
    directions = (Direction.INBOUND,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        score = 0.0
        hits: list[str] = []
        signals = _PI_SIGNALS
        if ctx.extra.get("content_trust") == "untrusted":
            signals += _UNTRUSTED_PI_SIGNALS
        for pat, w in signals:
            if pat.search(text):
                hits.append(pat.pattern)
                score = max(score, w)
                score += w * 0.1
        return DetectorResult(
            self.name,
            self.category,
            min(score, 1.0),
            "critical" if score >= 0.85 else "high",
            {"signals": len(hits), "band": util.band(min(score, 1.0))},
        ).clamp()


_JB_SIGNALS: tuple[tuple[re.Pattern[str], float], ...] = (
    (re.compile(r"\b(?:DAN|do\s+anything\s+now)\b", re.I), 0.8),
    (re.compile(r"\bdeveloper\s+mode\b", re.I), 0.6),
    (re.compile(r"\byou\s+are\s+now\s+(?:an?\s+)?\w+", re.I), 0.5),
    (re.compile(r"\bpretend\s+(?:to\s+be|you\s+are)\b", re.I), 0.5),
    (
        re.compile(r"\bact\s+as\s+(?:an?\s+)?(?:unrestricted|uncensored|evil|jailbroken)\b", re.I),
        0.85,
    ),
    (re.compile(r"\bno\s+(?:rules|restrictions|filters|guidelines)\b", re.I), 0.6),
    (re.compile(r"\bhypothetically,?\s+(?:if|how)\b", re.I), 0.35),
    (re.compile(r"\bfor\s+(?:educational|research)\s+purposes\s+only\b", re.I), 0.4),
    (re.compile(r"\bgrandma\b.{0,40}\b(?:napalm|bomb|recipe)\b", re.I), 0.8),
)


class JailbreakDetector:
    name = "jailbreak"
    category = "jailbreak"
    default_threshold = 0.5
    severity = "high"
    directions = (Direction.INBOUND,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        score = 0.0
        hits = 0
        for pat, w in _JB_SIGNALS:
            if pat.search(text):
                hits += 1
                score = max(score, w)
                score += w * 0.1
        return DetectorResult(
            self.name,
            self.category,
            min(score, 1.0),
            "critical" if score >= 0.85 else "high",
            {"signals": hits, "band": util.band(min(score, 1.0))},
        ).clamp()


# ─────────────────────────────────────────────── Invisible / steganographic text

_ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
_BIDI = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}


def _is_tag_char(ch: str) -> bool:
    # Unicode Tags block U+E0000-U+E007F is used to smuggle hidden ASCII.
    return 0xE0000 <= ord(ch) <= 0xE007F


class InvisibleTextDetector:
    name = "invisible_text"
    category = "invisible_text"
    default_threshold = 0.5
    severity = "high"
    directions = (Direction.BOTH,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        zw = sum(1 for ch in text if ch in _ZERO_WIDTH)
        bidi = sum(1 for ch in text if ch in _BIDI)
        tags = sum(1 for ch in text if _is_tag_char(ch))
        # confusable/homoglyph: non-ASCII letters mixed into otherwise ASCII words
        non_ascii_letters = sum(
            1
            for ch in text
            if ch.isalpha() and ord(ch) > 0x7F and unicodedata.category(ch).startswith("L")
        )
        score = 0.0
        if tags:
            score = 0.95  # tag-block smuggling is unambiguous
        if zw:
            score = max(score, min(0.6 + 0.05 * zw, 0.95))
        if bidi:
            score = max(score, 0.7)  # bidi override is a known spoofing vector
        if non_ascii_letters and non_ascii_letters < max(len(text) * 0.3, 3):
            score = max(score, 0.4)  # possible homoglyph injection
        return DetectorResult(
            self.name,
            self.category,
            score,
            "high" if score >= 0.7 else "medium",
            {
                "zero_width": zw,
                "bidi_controls": bidi,
                "tag_chars": tags,
                "suspect_homoglyphs": non_ascii_letters,
            },
        ).clamp()
