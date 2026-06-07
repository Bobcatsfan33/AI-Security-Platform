"""Signal publishing — route a pre-formed EpaSignal into the running detection
pipeline.

The Phase 2.5 bridge (:mod:`app.aiguard.bridge`) turns an AI Guard
``block``/``detect`` verdict into an :class:`EpaSignal`. That conversion alone
does not put the finding in front of an analyst, though — something has to feed
the signal into the same :class:`NarrativePipeline` the running EPA consumer
drives, so the content finding lands as a Tier-3 narrative in the store the
workbench reads.

This module is that glue. A content_violation signal carrying the same
``correlation_key`` as the behavioural flow merges into the *one* incident for
that flow (narratives have a stable id = uuid5 of org+correlation), so a
content finding and the causal flow it belongs to surface together — the whole
point of the merge.

Publishing is best-effort by design: a content inspection is a synchronous
gateway call on the request hot-path, and a narrative-store hiccup must never
turn an ``allow`` into a 500 or block legitimate traffic.
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from app.aiguard.bridge import aiguard_response_to_signal
from app.aiguard.response import AIGuardResponse
from app.epa.agent_epa import EpaSignal
from app.narratives.narrative import ThreatNarrative
from app.narratives.pipeline import NarrativePipeline

logger = logging.getLogger("platform.aiguard.publish")


@runtime_checkable
class SignalPublisher(Protocol):
    """Routes a pre-formed signal into the detection pipeline, returning the
    narratives it produced (empty when nothing was created)."""

    async def publish(self, signal: EpaSignal) -> list[ThreatNarrative]: ...


class NarrativeSignalPublisher:
    """Feeds a signal straight into a :class:`NarrativePipeline`.

    AI Guard findings are already at the *signal* tier — they do not need to
    pass through the EPA fleet (which derives behavioural signals from raw
    events). So they enter the pipeline directly, sharing the store/suppression
    /timeline wiring the consumer uses.
    """

    def __init__(self, pipeline: NarrativePipeline) -> None:
        self._pipeline = pipeline

    async def publish(self, signal: EpaSignal) -> list[ThreatNarrative]:
        return await self._pipeline.ingest([signal])


async def maybe_publish_inspection(
    resp: AIGuardResponse,
    publisher: SignalPublisher | None,
    *,
    org_id: str,
    asset_id: str,
    agent_instance_id: str,
    correlation_key: str = "",
) -> list[ThreatNarrative]:
    """Convert an AI Guard verdict to a signal and publish it, best-effort.

    Returns the narratives produced. Returns ``[]`` — never raises — when the
    verdict allowed (no signal), no publisher is installed, or publishing
    failed; a publish failure is logged but must not break the inspect path.
    """
    signal = aiguard_response_to_signal(
        resp,
        org_id=org_id,
        asset_id=asset_id,
        agent_instance_id=agent_instance_id,
        correlation_key=correlation_key,
    )
    if signal is None or publisher is None:
        return []
    try:
        return await publisher.publish(signal)
    except Exception as exc:
        logger.warning("aiguard_signal_publish_failed", extra={"error": str(exc)})
        return []


async def build_default_publisher() -> NarrativeSignalPublisher:
    """Wire the production publisher: the same Redis-backed NarrativePipeline
    the EPA consumer uses, so content findings land in the store the workbench
    reads and merge with behavioural narratives on shared correlation."""
    from app.epa.service import _timeline_fetcher
    from app.feedback.store import RedisSuppressionStore
    from app.narratives.store import RedisNarrativeStore
    from app.services.redis_client import get_redis

    redis = await get_redis()
    pipeline = NarrativePipeline(
        narrative_store=RedisNarrativeStore(redis),
        suppression_store=RedisSuppressionStore(redis),
        timeline_fetcher=_timeline_fetcher(),
    )
    return NarrativeSignalPublisher(pipeline)


# ─────────────────────────────────────────────── process-wide publisher
# Mirrors app.streaming.events.{get,set}_producer: lifespan installs the
# default publisher; tests inject an in-memory one.

_publisher: SignalPublisher | None = None


def set_publisher(publisher: SignalPublisher | None) -> None:
    global _publisher
    _publisher = publisher


def get_publisher() -> SignalPublisher | None:
    return _publisher


def reset_for_tests() -> None:
    global _publisher
    _publisher = None
