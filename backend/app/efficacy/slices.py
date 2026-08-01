"""Slice axes — the dimensions efficacy is reported along, not a tag soup.

An aggregate detection rate hides exactly the failures that matter. A model can
score 95% overall while missing every non-English attack, every indirect
injection, and every encoded payload, because those are a small share of a
corpus that is mostly easy direct-English cases. Reporting per slice is what
makes that visible, so the slices are declared here as a closed set rather than
being whatever strings a corpus author happened to type.

Closed on purpose: an unknown slice name in a manifest is a typo that would
otherwise create a silent, empty, always-passing dimension.
"""

from __future__ import annotations

from dataclasses import dataclass


class NoAuthorizedCorpusError(RuntimeError):
    """Raised when a slice requires authorized data that does not exist.

    A distinct exception type rather than a generic error because the caller
    must not be able to confuse it with "the corpus failed to load". The whole
    point is that this condition is un-substitutable.
    """


@dataclass(frozen=True)
class SliceAxis:
    name: str
    description: str
    # When True, the harness refuses to evaluate this slice from synthetic
    # data. See CUSTOMER_DISTRIBUTION.
    requires_authorized_corpus: bool = False


MULTILINGUAL = SliceAxis(
    "multilingual",
    "Attacks and benign traffic in languages other than English. Detection "
    "trained on English text degrades here in ways an aggregate score hides.",
)
MULTI_TURN = SliceAxis(
    "multi_turn",
    "Attacks assembled across several conversation turns, where no single "
    "turn is individually detectable.",
)
INDIRECT_INJECTION = SliceAxis(
    "indirect_injection",
    "Instructions arriving through retrieved documents, tool output, or other "
    "untrusted content rather than from the user directly.",
)
TOOL_CALL_ABUSE = SliceAxis(
    "tool_call_abuse",
    "Abuse of tool and MCP invocation: unauthorized tools, argument tampering, "
    "and chained calls that individually look ordinary.",
)
ENCODED_OBFUSCATED = SliceAxis(
    "encoded_obfuscated",
    "Payloads hidden by encoding or homoglyph/zero-width obfuscation, which "
    "the normalize pre-pass exists to defeat.",
)
BENIGN_HARD_NEGATIVE = SliceAxis(
    "benign_hard_negative",
    "Benign traffic that closely resembles an attack. The slice that decides "
    "whether a detector is usable in production rather than merely sensitive.",
)

# The slot that must never be quietly filled in.
#
# "Efficacy on customer-like traffic" is the number a buyer actually cares
# about, and it is the easiest one to fake: point the slice at synthetic data,
# report a high score, and nothing in the output says the distribution was
# invented. So this axis refuses. Running it without an authorized corpus
# raises NoAuthorizedCorpusError; there is no fallback path, because a
# fallback is how substitution happens.
CUSTOMER_DISTRIBUTION = SliceAxis(
    "customer_distribution",
    "Traffic sampled from real authorized customer deployments. Cannot be "
    "satisfied by synthetic data under any circumstances.",
    requires_authorized_corpus=True,
)

ALL_SLICES: tuple[SliceAxis, ...] = (
    MULTILINGUAL,
    MULTI_TURN,
    INDIRECT_INJECTION,
    TOOL_CALL_ABUSE,
    ENCODED_OBFUSCATED,
    BENIGN_HARD_NEGATIVE,
    CUSTOMER_DISTRIBUTION,
)

SLICES_BY_NAME: dict[str, SliceAxis] = {axis.name: axis for axis in ALL_SLICES}


def resolve(name: str) -> SliceAxis:
    """Look up a slice, refusing unknown names.

    Unknown names are rejected rather than tolerated: a misspelled slice would
    otherwise produce a dimension with zero cases, which reports as "no
    failures" and reads as coverage.
    """
    try:
        return SLICES_BY_NAME[name]
    except KeyError:
        raise ValueError(
            f"unknown slice axis {name!r}; known axes are "
            f"{sorted(SLICES_BY_NAME)}. Add it to app/efficacy/slices.py "
            "deliberately rather than inventing it in a manifest."
        ) from None
