"""Prompt-injection, jailbreak, and invisible-text detectors."""

from __future__ import annotations

import re
import unicodedata

from app.detectors.base import DetectorContext, DetectorResult, Direction
from app.detectors import util

_PI_SIGNALS: tuple[tuple[re.Pattern[str], float], ...] = (
    (
        re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above|the)\s+instructions?\b", re.I),
        0.8,
    ),
    (re.compile(r"\bdisregard\s+(?:all\s+)?(?:previous|prior|the\s+above)\b", re.I), 0.75),
    (re.compile(r"\brepeat\s+(?:the\s+)?(?:text|words|everything|prompt)\s+above\b", re.I), 0.7),
    (
        re.compile(
            r"\b(?:reveal|print|show|output)\s+(?:your\s+)?(?:system|initial|the)\s+prompt\b", re.I
        ),
        0.85,
    ),
    (re.compile(r"\bwhat\s+(?:are|were)\s+your\s+(?:original\s+)?instructions\b", re.I), 0.6),
    (re.compile(r"\bnew\s+instructions?\s*:\s*", re.I), 0.55),
    (re.compile(r"\boverride\s+(?:your\s+)?(?:safety|guidelines|rules|system)\b", re.I), 0.7),
    (re.compile(r"</?\s*(?:system|instructions?)\s*>", re.I), 0.6),  # fake delimiter injection
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
        for pat, w in _PI_SIGNALS:
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

_ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿"}
_BIDI = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩"}


def _is_tag_char(ch: str) -> bool:
    # Unicode Tags block U+E0000–U+E007F is used to smuggle hidden ASCII.
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
