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

from app.epa.agent_epa import AgentEPA, EpaSignal, absence_signal
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
        cross_agent: "Optional[Any]" = None,
    ) -> None:
        self._store = store
        self._sink = sink
        self._cache: dict[str, AgentEPA] = {}
        self._cache_size = cache_size
        # Optional CrossAgentEPA — the per-flow correlation layer. When set,
        # every event is fed to it after per-agent processing, so one stream
        # drives both the per-agent and cross-agent detection layers.
        self._cross_agent = cross_agent
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
        if self._cross_agent is not None:
            signals = signals + await self._cross_agent.process(event)
        self.events_processed += 1
        await self._emit(signals)
        return signals

    async def _emit(self, signals: list[EpaSignal]) -> None:
        for sig in signals:
            self.signals_emitted += 1
            if self._sink is not None:
                await self._sink(sig)

    async def sweep_absences(self, *, now: float, factor: float = 4.0) -> list[EpaSignal]:
        """Supervisory sweep: emit agent_silent signals for cached mature
        agents that have gone quiet past ``factor`` × their normal interval.
        Absence is the LACK of an event, so it can't be event-driven — the
        fleet runs this on a timer.

        Note: sweeps the live EPA cache. A full sweep over all persisted
        envelopes (Redis SCAN) is a production follow-on for cold agents not
        currently cached."""
        emitted: list[EpaSignal] = []
        for epa in list(self._cache.values()):
            sig = absence_signal(epa.env, now=now, factor=factor)
            if sig is not None:
                emitted.append(sig)
        await self._emit(emitted)
        return emitted

    def stats(self) -> dict[str, Any]:
        """Health snapshot for the supervisor / metrics endpoint."""
        cached = list(self._cache.values())
        return {
            "events_processed": self.events_processed,
            "signals_emitted": self.signals_emitted,
            "agents_cached": len(cached),
            "agents_mature": sum(1 for e in cached if e.env.mature),
        }

    async def run(self, consumer: "AsyncIterator[dict] | Any") -> None:
        """Drain a consumer until it stops. Accepts either an EventConsumer
        (has .consume()) or a raw async iterator of wire dicts."""
        stream = consumer.consume() if hasattr(consumer, "consume") else consumer
        async for event in stream:
            try:
                await self.handle_event(event)
            except Exception as exc:  # noqa: BLE001
                logger.warning("epa_event_failed", extra={"error": str(exc)})
