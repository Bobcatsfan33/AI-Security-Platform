"""Producer / consumer protocols + the process-wide producer singleton.

The concrete backend is chosen at startup: aiokafka against Redpanda in
production, or the in-memory bus for single-process dev / tests. Callers
depend on the Protocols, never the concrete class.
"""

from __future__ import annotations

from typing import AsyncIterator, Optional, Protocol, runtime_checkable

from app.telemetry.runtime_event import RuntimeEvent

# Default topic; the configured value (settings.runtime_events_topic) wins at
# wiring time. Re-exported here so importers have one obvious name.
RUNTIME_EVENTS_TOPIC = "runtime.events"


@runtime_checkable
class EventProducer(Protocol):
    """Publishes runtime events to the streaming spine. Best-effort: a
    publish failure must never break the ingest path (ClickHouse is the
    durable store)."""

    async def publish(self, event: RuntimeEvent) -> bool: ...

    async def start(self) -> None: ...

    async def stop(self) -> None: ...


@runtime_checkable
class EventConsumer(Protocol):
    """Yields wire dicts (column → value) from the spine. The EPA fleet
    (Sprint 5) drives this."""

    def consume(self) -> AsyncIterator[dict]: ...

    async def start(self) -> None: ...

    async def stop(self) -> None: ...


# ─────────────────────────────────────────────── process-wide producer

_producer: Optional[EventProducer] = None


def set_producer(producer: Optional[EventProducer]) -> None:
    """Install the process producer (called from app lifespan, or by tests
    to inject the in-memory bus)."""
    global _producer
    _producer = producer


def get_producer() -> Optional[EventProducer]:
    """Return the installed producer, or None when streaming is disabled."""
    return _producer


def reset_for_tests() -> None:
    global _producer
    _producer = None
