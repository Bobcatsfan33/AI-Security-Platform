"""Decode + normalize pre-pass — closes the encoding-bypass class.

An attacker can hide an injection so the literal bytes never match a detector:

* **Unicode tricks** — zero-width / bidi / tag chars spliced into words, or
  homoglyph / full-width look-alikes that read the same but aren't ASCII.
* **Encodings** — the payload wrapped in base64, hex, percent-encoding, or
  rot13 so ``ignore all instructions`` arrives as ``aWdub3Jl…``.

This module produces a small set of **candidate** strings — the raw text plus a
normalized form and any plausible decodings — so every detector runs against
each form an attacker might have used, not just the bytes on the wire.

It is intentionally dependency-free and bounded (a capped number of variants)
so the pre-pass stays cheap on the inline hot path.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

from app.detectors.util import COMMON_EN, tokens

# Invisible characters used to splice/obfuscate. Mirrors the set the injection
# detector flags; here we *strip* them so the underlying text is inspectable.
_ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿"}
_BIDI = {
    "‪",
    "‫",
    "‬",
    "‭",
    "‮",
    "⁦",
    "⁧",
    "⁨",
    "⁩",
}

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9A-Fa-f]{2}\s*){8,}")
_MAX_VARIANTS = 8
_MIN_DECODE_LEN = 8


def _is_tag_char(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def strip_invisibles(text: str) -> str:
    """Remove zero-width, bidi-control, and Unicode-tag characters."""
    return "".join(
        ch for ch in text if ch not in _ZERO_WIDTH and ch not in _BIDI and not _is_tag_char(ch)
    )


def normalize_text(text: str) -> str:
    """NFKC-fold (collapses full-width / many homoglyphs to their ASCII
    canonical form) after stripping invisible characters."""
    return unicodedata.normalize("NFKC", strip_invisibles(text))


def _looks_like_text(s: str) -> bool:
    """A decoded blob is worth inspecting only if it reads like text: mostly
    printable, and containing letters (so we don't feed binary noise to
    detectors)."""
    if len(s) < _MIN_DECODE_LEN:
        return False
    printable = sum(1 for ch in s if ch.isprintable() or ch in "\n\r\t")
    letters = sum(1 for ch in s if ch.isalpha())
    return printable / len(s) >= 0.85 and letters >= max(3, len(s) // 10)


def _try_base64(s: str) -> str | None:
    s = s.strip()
    if len(s) < _MIN_DECODE_LEN:
        return None
    padded = s + "=" * (-len(s) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True).decode("utf-8", "strict")
    except (binascii.Error, ValueError):
        return None
    return decoded if _looks_like_text(decoded) else None


def _try_hex(s: str) -> str | None:
    compact = re.sub(r"\s+", "", s)
    if len(compact) < _MIN_DECODE_LEN or len(compact) % 2 != 0:
        return None
    try:
        decoded = bytes.fromhex(compact).decode("utf-8", "strict")
    except ValueError:
        return None
    return decoded if _looks_like_text(decoded) else None


def _try_url(text: str) -> str | None:
    if "%" not in text:
        return None
    decoded = urllib.parse.unquote(text)
    return decoded if decoded != text and _looks_like_text(decoded) else None


def _english_ratio(s: str) -> float:
    """Fraction of tokens that are common English words. Cheap, lexicon-based —
    enough to tell rot13 ciphertext (≈0) from real prose."""
    toks = tokens(s)
    if not toks:
        return 0.0
    return sum(1 for t in toks if t in COMMON_EN) / len(toks)


def _try_rot13(text: str) -> str | None:
    """Decode rot13 ONLY when it reveals substantially more English than the
    input. rot13 has no structural signature (it's just letters), so unguarded
    it would turn benign prose into gibberish and trip the gibberish detector —
    a false-positive. Gating on an English-ratio jump means we only surface a
    rot13 variant when the *input* was the ciphertext."""
    if not any(c.isalpha() for c in text):
        return None
    decoded = text.translate(_ROT13)
    if decoded == text or not _looks_like_text(decoded):
        return None
    if _english_ratio(decoded) >= 0.30 and _english_ratio(decoded) > _english_ratio(text) + 0.15:
        return decoded
    return None


_ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


@dataclass(frozen=True)
class Normalized:
    """The raw text plus the inspectable variants derived from it."""

    raw: str
    normalized: str
    variants: dict[str, str] = field(default_factory=dict)

    def candidates(self) -> list[tuple[str, str]]:
        """``(form_label, text)`` pairs to run detection over — raw first, then
        the normalized form, then decoded variants. Deduplicated by text."""
        out: list[tuple[str, str]] = [("raw", self.raw)]
        seen = {self.raw}
        if self.normalized not in seen:
            out.append(("normalized", self.normalized))
            seen.add(self.normalized)
        for label, value in self.variants.items():
            if value not in seen:
                out.append((label, value))
                seen.add(value)
        return out


def decode_and_normalize(text: str) -> Normalized:
    """Build the candidate set for ``text``: normalized form + bounded decodings
    (whole-string and per-substring base64/hex, plus URL/rot13 of the whole
    string). Decodings of the normalized text are included so a homoglyph-
    wrapped base64 blob is still reached."""
    normalized = normalize_text(text)
    variants: dict[str, str] = {}

    def _add(label: str, value: str | None) -> None:
        if value and value not in variants.values() and len(variants) < _MAX_VARIANTS:
            variants[label] = value

    for source, prefix in ((text, ""), (normalized, "norm_")):
        _add(f"{prefix}base64", _try_base64(source))
        _add(f"{prefix}hex", _try_hex(source))
        _add(f"{prefix}url", _try_url(source))
        _add(f"{prefix}rot13", _try_rot13(source))
        for m in _B64_RE.findall(source):
            _add(f"{prefix}base64_span", _try_base64(m))
        for m in _HEX_RE.findall(source):
            _add(f"{prefix}hex_span", _try_hex(m))

    return Normalized(raw=text, normalized=normalized, variants=variants)
