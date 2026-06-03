"""EpaConsumerService — the running detection service.

Consumes the runtime-event stream, drives the EPA fleet (per-agent EPAs +
cross-agent correlation), and feeds emitted signals through the
NarrativePipeline so Tier-3 narratives land in the store the analyst workbench
reads. This is the long-running process that ties Sprints 2–14 together:

    Redpanda → EpaFleet + CrossAgentEPA → signals → NarrativePipeline → store

Injectable (consumer / fleet / pipeline) so tests run it over the in-memory bus
+ in-memory stores; ``build_default`` wires the production Kafka + Redis stack.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from app.epa.cross_agent import CrossAgentEPA, RedisCorrelationStore
from app.epa.fleet import EpaFleet
from app.epa.store import RedisEnvelopeStore
from app.narratives.pipeline import NarrativePipeline
from app.narratives.store import RedisNarrativeStore

logger = logging.getLogger("platform.epa.service")


class EpaConsumerService:
    def __init__(self, *, consumer: Any, fleet: EpaFleet, pipeline: NarrativePipeline) -> None:
        self._consumer = consumer
        self._fleet = fleet
        self._pipeline = pipeline
        self.events_processed = 0
        self.narratives_written = 0

    async def process_one(self, event: dict[str, Any]) -> list[Any]:
        """Process a single event end-to-end. Unit-testable."""
        signals = await self._fleet.handle_event(event)
        self.events_processed += 1
        narratives = await self._pipeline.ingest(signals)
        self.narratives_written += len(narratives)
        return narratives

    async def run(self) -> None:
        """Drain the consumer until it stops. Each event flows through the fleet
        then the narrative pipeline."""
        await self._consumer.start()
        try:
            async for event in self._consumer.consume():
                try:
                    await self.process_one(event)
                except Exception as exc:  # noqa: BLE001 - one bad event must not kill the loop
                    logger.warning("epa_service_event_failed", extra={"error": str(exc)})
        finally:
            await self._consumer.stop()


def _timeline_fetcher() -> Any:
    """Wrap fetch_causal_subtree as a (org, asset, root) -> events fetcher.
    Best-effort: returns [] when ids aren't UUIDs or ClickHouse is down."""
    from app.anomaly.attack_graph import fetch_causal_subtree

    def fetch(org_id: str, asset_id: str, root_event_id: str) -> list[dict[str, Any]]:
        try:
            return fetch_causal_subtree(
                org_id=uuid.UUID(org_id),
                asset_id=uuid.UUID(asset_id),
                root_event_id=root_event_id,
            )
        except Exception:  # noqa: BLE001
            return []

    return fetch


async def build_default() -> EpaConsumerService:
    """Wire the production service: Kafka consumer + Redis-backed stores."""
    from app.core.config import get_settings
    from app.feedback.store import RedisSuppressionStore
    from app.services.redis_client import get_redis
    from app.streaming.kafka_backend import build_consumer

    settings = get_settings()
    redis = await get_redis()

    consumer = build_consumer(
        brokers=settings.redpanda_brokers,
        topic=settings.runtime_events_topic,
        group_id="epa-fleet",
    )
    fleet = EpaFleet(
        store=RedisEnvelopeStore(redis),
        cross_agent=CrossAgentEPA(RedisCorrelationStore(redis)),
    )
    pipeline = NarrativePipeline(
        narrative_store=RedisNarrativeStore(redis),
        suppression_store=RedisSuppressionStore(redis),
        timeline_fetcher=_timeline_fetcher(),
    )
    return EpaConsumerService(consumer=consumer, fleet=fleet, pipeline=pipeline)
