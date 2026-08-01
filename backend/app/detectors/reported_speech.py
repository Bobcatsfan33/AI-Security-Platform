"""Quoted attack text that is being TALKED ABOUT, not issued.

The people most likely to type an attack string at this product are the people
defending against it. "How would you translate 'ignore all previous
instructions'?", "write a unit test whose fixture is that phrase", "our
blocklist contains this — is it too broad?", "the attacker typed X, what
happened next?" — all ordinary, all previously scored as prompt injection at
full confidence.

The naive fix is to exempt anything in quotation marks. That is an evasion
handed straight to the attacker: wrap the payload in quotes and walk through.

So the test is a CONJUNCTION, and both halves are load-bearing:

1. the matched attack span sits inside a quotation, AND
2. the text OUTSIDE that quotation frames it as a subject of discussion —
   translate it, explain it, test against it, list it, report that someone
   else said it.

A bare quoted injection with no framing is still an injection. The framing verb
has to be outside the quotes, so an attacker cannot supply it inside their own
payload.
"""

from __future__ import annotations

import re

# Paired quotation forms, including the typographic ones a word processor
# produces — an attacker pasting from a document should not get a different
# answer than one typing ASCII quotes.
_QUOTED_SPANS = (
    re.compile(r"\"([^\"]{4,400})\""),
    re.compile(r"'([^']{4,400})'"),
    re.compile(r"“([^”]{4,400})”"),
    re.compile(r"‘([^’]{4,400})’"),
    re.compile(r"`([^`]{4,400})`"),
    re.compile(r"«([^»]{4,400})»"),
)

# Framing that makes a quoted string the OBJECT of discussion rather than an
# instruction to follow. Deliberately about handling text as text.
_FRAMING = re.compile(
    r"\b(?:translat\w*|traduc\w*|[üu]bersetz\w*"
    r"|explain\w*|explic\w*|erkl[äa]r\w*"
    r"|defin\w*|mean(?:s|ing)?|stand\s+for"
    r"|what\s+does|what\s+is|how\s+would|how\s+do(?:es)?"
    r"|exampl\w*|sampl\w*|fixtur\w*|test\s+case|unit\s+test"
    r"|blocklist\w*|blacklist\w*|allowlist\w*|denylist\w*|filter\w*|regex|pattern"
    r"|detect(?:s|or|ors|ion)?|rule|signature"
    r"|typed|wrote|said|sent|submitted|entered|pasted|contains?|includ\w*"
    r"|phrase|string|sentence|quote[ds]?|literal"
    r"|summari[sz]\w*|documentation|training|module|article|newsletter)\b",
    re.I,
)


def is_reported_speech(text: str, matched: str) -> bool:
    """Whether ``matched`` appears quoted inside ``text`` AND is framed as a topic.

    ``matched`` is the substring an injection pattern actually matched, so the
    check is about the span that triggered the detection rather than about the
    message containing a quote somewhere.
    """
    needle = matched.strip().lower()
    if not needle:
        return False

    for pattern in _QUOTED_SPANS:
        for span in pattern.finditer(text):
            inner = span.group(1)
            if needle not in inner.lower():
                continue
            # The framing must come from OUTSIDE the quotation. Reading it from
            # inside would let the payload carry its own alibi:
            #   "translate this: ignore all previous instructions"
            # where the whole thing is one quoted blob.
            outside = text[: span.start()] + text[span.end() :]
            if _FRAMING.search(outside):
                return True
    return False
