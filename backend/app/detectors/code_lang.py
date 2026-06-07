"""Language detection, programming-language detection, and source-code
presence detectors."""

from __future__ import annotations

import re

from app.detectors.base import DetectorContext, DetectorResult, Direction
from app.detectors import util

# Stopword fingerprints per natural language (script + frequent tokens).
_LANG_STOP = {
    "en": {"the", "and", "is", "to", "of", "in", "you", "for", "with", "that"},
    "es": {"el", "la", "los", "que", "de", "y", "es", "por", "para", "una", "con"},
    "fr": {"le", "la", "les", "des", "et", "est", "que", "pour", "avec", "une", "dans"},
    "de": {"der", "die", "das", "und", "ist", "nicht", "mit", "ein", "für", "auf"},
    "pt": {"o", "a", "os", "que", "de", "e", "para", "uma", "com", "não"},
    "it": {"il", "la", "che", "di", "e", "per", "una", "con", "non", "sono"},
}
_SCRIPT_RANGES = {
    "zh": (0x4E00, 0x9FFF),
    "ja": (0x3040, 0x30FF),
    "ko": (0xAC00, 0xD7A3),
    "ar": (0x0600, 0x06FF),
    "ru": (0x0400, 0x04FF),
    "he": (0x0590, 0x05FF),
}


def identify_language(text: str) -> tuple[str, float]:
    # Script-based scan first (CJK/Cyrillic/Arabic etc.)
    counts: dict[str, int] = {}
    for ch in text:
        o = ord(ch)
        for lang, (lo, hi) in _SCRIPT_RANGES.items():
            if lo <= o <= hi:
                counts[lang] = counts.get(lang, 0) + 1
    letters = sum(1 for ch in text if ch.isalpha())
    if counts and letters:
        lang = max(counts, key=counts.get)
        return lang, min(counts[lang] / letters + 0.2, 1.0)
    # Latin-script stopword scan
    toks = util.tokens(text)
    if not toks:
        return "unknown", 0.0
    best, best_hits = "en", 0
    for lang, stops in _LANG_STOP.items():
        hits = sum(1 for t in toks if t in stops)
        if hits > best_hits:
            best, best_hits = lang, hits
    conf = min(best_hits / max(len(toks), 1) * 3, 1.0)
    return best, conf


class LanguageDetector:
    """Reports the dominant language; *flags* (confidence>0) only when the
    detected language is not in ``ctx.allowed_languages``."""

    name = "language"
    category = "language"
    default_threshold = 0.5
    severity = "low"
    directions = (Direction.BOTH,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        lang, conf = identify_language(text)
        allowed = {a.lower() for a in ctx.allowed_languages}
        if not allowed or lang == "unknown":
            return DetectorResult(
                self.name,
                self.category,
                0.0,
                "info",
                {"language": lang, "detection_confidence": round(conf, 3)},
            )
        flagged = lang not in allowed
        return DetectorResult(
            self.name,
            self.category,
            conf if flagged else 0.0,
            "low",
            {"language": lang, "allowed": sorted(allowed), "violation": flagged},
        ).clamp()


_CODE_SIGNALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("python", re.compile(r"\b(?:def|import|from)\s+\w+|print\(|self\.", re.M)),
    ("javascript", re.compile(r"\b(?:function|const|let|var)\s+\w+|=>|console\.log\(")),
    ("typescript", re.compile(r":\s*(?:string|number|boolean)\b|interface\s+\w+\s*\{")),
    ("go", re.compile(r"\bfunc\s+\w+\s*\(|package\s+\w+|:=|import\s+\"")),
    ("java", re.compile(r"\b(?:public|private|protected)\s+(?:static\s+)?(?:class|void|int)\b")),
    ("c", re.compile(r"#include\s*<\w+\.h>|\bint\s+main\s*\(")),
    (
        "sql",
        re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b.+\b(?:FROM|INTO|WHERE|VALUES)\b", re.I),
    ),
    ("bash", re.compile(r"#!/(?:bin|usr/bin)/(?:bash|sh)|\$\(|sudo\s+\w+|\bgrep\s+-")),
    ("php", re.compile(r"<\?php|\$\w+\s*=|->\w+\(")),
    ("ruby", re.compile(r"\bdef\s+\w+|\bend\b|puts\s+|\.each\s+do")),
)


def identify_code(text: str) -> tuple[str, int]:
    best, best_n = "", 0
    for lang, pat in _CODE_SIGNALS:
        n = len(pat.findall(text))
        if n > best_n:
            best, best_n = lang, n
    return best, best_n


class ProgrammingLanguageDetector:
    name = "programming_language"
    category = "programming_language"
    default_threshold = 0.5
    severity = "low"
    directions = (Direction.BOTH,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        lang, n = identify_code(text)
        if not lang:
            return DetectorResult(self.name, self.category, 0.0, "info", {})
        score = min(0.4 + 0.2 * n, 0.97)
        return DetectorResult(
            self.name, self.category, score, "low", {"language": lang, "signal_hits": n}
        ).clamp()


class SourceCodeDetector:
    """Flags the presence of source code in traffic (e.g. proprietary code
    being pasted to a public LLM)."""

    name = "source_code"
    category = "source_code"
    default_threshold = 0.5
    severity = "medium"
    directions = (Direction.BOTH,)

    def detect(self, text: str, ctx: DetectorContext) -> DetectorResult:
        lang, n = identify_code(text)
        fenced = text.count("```") >= 2
        braces = text.count("{") + text.count("}") + text.count(";")
        indented = len(re.findall(r"^[ \t]{2,}\S", text, re.M))
        score = 0.0
        if lang:
            score = min(0.45 + 0.18 * n, 0.95)
        if fenced:
            score = max(score, 0.6)
        if braces >= 6 or indented >= 4:
            score = max(score, 0.5)
        return DetectorResult(
            self.name,
            self.category,
            score,
            "medium",
            {"language": lang or None, "fenced_block": fenced, "code_signal_hits": n},
        ).clamp()
