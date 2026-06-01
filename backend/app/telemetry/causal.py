"""Causal context propagation for the poset spine.

When an AI agent's response triggers a downstream call (a tool invocation
that becomes another agent's request, an inter-agent message, a chained
RAG step), the lineage must survive the network hop so the control plane
can reconstruct the partially-ordered set of events ACROSS processes and
agents — not just within one session.

We carry lineage two ways, redundantly and on purpose:

1. **W3C ``traceparent``** — for interop with existing distributed-tracing
   infrastructure (OTel collectors, APM). The 128-bit trace-id is the
   poset ``root_event_id``. This means a customer's existing tracing tools
   light up for free, and our spine aligns with theirs.

2. **Native ``x-aisp-*`` headers** — ``traceparent``'s span-id is only
   64 bits, too small to round-trip a full 128-bit event UUID. The native
   headers carry the full ``parent_event_id``, ``root_event_id``,
   ``correlation_key``, and ``causal_depth`` with no loss of fidelity.

The Go runtime agent mirrors this exactly (see
``runtime-agent/proxy/causal.go``) so propagation is wire-compatible
regardless of which side originates the hop.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Mapping, Optional

# ── Header names (lower-case; HTTP headers are case-insensitive) ──────────
HEADER_TRACEPARENT = "traceparent"
HEADER_ROOT = "x-aisp-root-event"
HEADER_PARENT = "x-aisp-parent-event"
HEADER_CORRELATION = "x-aisp-correlation-key"
HEADER_DEPTH = "x-aisp-causal-depth"

_TRACEPARENT_VERSION = "00"
_TRACEPARENT_FLAGS = "01"  # sampled


@dataclass(frozen=True)
class CausalContext:
    """The lineage threaded between two causally-linked events."""

    root_event_id: uuid.UUID
    parent_event_id: uuid.UUID
    correlation_key: str
    causal_depth: int

    def traceparent(self) -> str:
        """Render as a W3C ``traceparent`` header value.

        trace-id ← root_event_id (128-bit). span-id ← low 64 bits of the
        parent event id (lossy by spec — the native header carries the
        full value).
        """
        trace_id = self.root_event_id.hex
        span_id = f"{self.parent_event_id.int & 0xFFFFFFFFFFFFFFFF:016x}"
        return f"{_TRACEPARENT_VERSION}-{trace_id}-{span_id}-{_TRACEPARENT_FLAGS}"

    def to_headers(self) -> dict[str, str]:
        """Serialize to the full set of propagation headers."""
        return {
            HEADER_TRACEPARENT: self.traceparent(),
            HEADER_ROOT: str(self.root_event_id),
            HEADER_PARENT: str(self.parent_event_id),
            HEADER_CORRELATION: self.correlation_key,
            HEADER_DEPTH: str(self.causal_depth),
        }


def _lower_get(headers: Mapping[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup that tolerates either casing."""
    if name in headers:
        return headers[name]
    for k, v in headers.items():
        if k.lower() == name:
            return v
    return None


def parse_traceparent(value: str) -> Optional[uuid.UUID]:
    """Extract the root_event_id (trace-id) from a ``traceparent`` value.

    Returns None if the header is malformed. We validate structurally but
    never raise — propagation is best-effort; a bad header degrades to a
    fresh root, it must not break the request.
    """
    parts = value.strip().split("-")
    if len(parts) != 4:
        return None
    _version, trace_id, _span, _flags = parts
    if len(trace_id) != 32:
        return None
    try:
        return uuid.UUID(hex=trace_id)
    except ValueError:
        return None


def from_headers(headers: Mapping[str, str]) -> Optional[CausalContext]:
    """Reconstruct a :class:`CausalContext` from inbound request headers.

    Prefers the high-fidelity native headers; falls back to ``traceparent``
    for the root id when native headers are absent (e.g. a hop that passed
    through a non-AISP tracing proxy). Returns None when there is no usable
    lineage at all — the caller then treats the event as a fresh root.
    """
    raw_root = _lower_get(headers, HEADER_ROOT)
    raw_parent = _lower_get(headers, HEADER_PARENT)
    raw_corr = _lower_get(headers, HEADER_CORRELATION)
    raw_depth = _lower_get(headers, HEADER_DEPTH)
    raw_tp = _lower_get(headers, HEADER_TRACEPARENT)

    root: Optional[uuid.UUID] = None
    if raw_root:
        try:
            root = uuid.UUID(raw_root)
        except ValueError:
            root = None
    if root is None and raw_tp:
        root = parse_traceparent(raw_tp)
    if root is None:
        return None

    parent: Optional[uuid.UUID] = None
    if raw_parent:
        try:
            parent = uuid.UUID(raw_parent)
        except ValueError:
            parent = None
    # Without a usable parent there is no causal edge to draw.
    if parent is None:
        return None

    try:
        depth = int(raw_depth) if raw_depth else 0
    except ValueError:
        depth = 0

    correlation = raw_corr or str(root)
    return CausalContext(
        root_event_id=root,
        parent_event_id=parent,
        correlation_key=correlation,
        causal_depth=depth,
    )
