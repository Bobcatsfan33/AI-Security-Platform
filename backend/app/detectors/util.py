"""Shared, dependency-free helpers for detectors."""

from __future__ import annotations

import math
import re
from collections import Counter

_WORD_RE = re.compile(r"[A-Za-z']+")
_TOKEN_RE = re.compile(r"\w+", re.UNICODE)

# A small but high-signal English lexicon. Real deployments load a full
# dictionary; this is enough to separate prose from gibberish/code/other
# languages deterministically in tests.
COMMON_EN = frozenset("""the be to of and a in that have i it for not on with he as you do at this
    but his by from they we say her she or an will my one all would there their
    what so up out if about who get which go me when make can like time no just
    him know take people into year your good some could them see other than then
    now look only come its over think also back after use two how our work first
    well way even new want because any these give day most us is are was were been
    has had please help write code data model security policy prompt response user
    system company report should how what why where need use using able""".split())


def words(text: str) -> list[str]:
    return _WORD_RE.findall(text)


def tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def vowel_ratio(word: str) -> float:
    if not word:
        return 0.0
    v = sum(1 for ch in word.lower() if ch in "aeiou")
    return v / len(word)


def english_word_ratio(text: str) -> float:
    ws = [w.lower() for w in words(text)]
    if not ws:
        return 0.0
    hits = sum(1 for w in ws if w in COMMON_EN)
    return hits / len(ws)


def collapse_obfuscation(text: str) -> str:
    """Strip common leetspeak / spacing obfuscation so lexicon matching
    survives ``f.u.c.k`` / ``f u c k`` / ``fvck`` style evasions."""
    lowered = text.lower()
    lowered = lowered.translate(
        str.maketrans(
            {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
        )
    )
    # remove single separators between letters: f.u.c.k -> fuck
    lowered = re.sub(r"(?<=\w)[\.\-_\*\s](?=\w)", "", lowered)
    return lowered


def band(confidence: float) -> str:
    if confidence >= 0.7:
        return "high"
    if confidence >= 0.3:
        return "uncertain"
    return "low"
