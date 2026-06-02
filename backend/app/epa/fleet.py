"""EpaFleet — the supervisor that drives per-agent EPAs off the event stream.

Consumes the streaming spine (any EventConsumer), routes each event to the
EPA for its ``agent_instance_id`` (loading/saving the envelope via an
EnvelopeStore), and hands emitted signals to a sink callback. A live EPA cache
avoids reloading the envelope from the store on every event for hot agents.

This is deliberately backend-agnostic: in tests it runs against the
InMemoryEventBus + InMemoryEnvelopeStore; in production against
KafkaEventConsumer + RedisEnvelopeStore.
"""

from __future__ import annotations

import logging
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

from app.epa.agent_epa import AgentEPA, EpaSignal
from app.epa.envelope import BehavioralEnvelope
from app.epa.store import EnvelopeStore
from app.anomaly.attack_graph import _norm

logger = logging.getLogger("platform.epa.fleet")

SignalSink = Callable[[EpaSignal], Awaitable[None]]


class EpaFleet:
    def __init__(
        self,
        *,
        store: EnvelopeStore,
        sink: Optional[SignalSink] = None,
        cache_size: int = 1024,
    ) -> None:
        self._store = store
        self._sink = sink
        self._cache: dict[str, AgentEPA] = {}
        self._cache_size = cache_size
        self.events_processed = 0
        self.signals_emitted = 0

    async def _get_epa(self, instance_id: str) -> AgentEPA:
        epa = self._cache.get(instance_id)
        if epa is not None:
            return epa
        env = await self._store.load(instance_id)
        if env is None:
            env = BehavioralEnvelope(agent_instance_id=instance_id)
        epa = AgentEPA(env)
        if len(self._cache) >= self._cache_size:
            self._cache.pop(next(iter(self._cache)))  # simple FIFO eviction
        self._cache[instance_id] = epa
        return epa

    async def handle_event(self, event: dict[str, Any]) -> list[EpaSignal]:
        """Process one event end-to-end: route → evaluate → persist → sink."""
        instance_id = _norm(event.get("agent_instance_id")) or "_unknown_"
        epa = await self._get_epa(instance_id)
        signals = epa.process(event)
        await self._store.save(epa.env)
        self.events_processed += 1
        for sig in signals:
            self.signals_emitted += 1
            if self._sink is not None:
                await self._sink(sig)
        return signals

    async def run(self, consumer: "AsyncIterator[dict] | Any") -> None:
        """Drain a consumer until it stops. Accepts either an EventConsumer
        (has .consume()) or a raw async iterator of wire dicts."""
        stream = consumer.consume() if hasattr(consumer, "consume") else consumer
        async for event in stream:
            try:
                await self.handle_event(event)
            except Exception as exc:  # noqa: BLE001
                logger.warning("epa_event_failed", extra={"error": str(exc)})
