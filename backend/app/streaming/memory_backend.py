"""In-memory event bus — single-process dev + tests.

Implements both EventProducer and EventConsumer over an asyncio.Queue, so a
publish is immediately consumable in the same process. No broker required.
This is also what the EPA fleet runs against in unit tests.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator

from app.streaming.serde import event_to_wire
from app.telemetry.runtime_event import RuntimeEvent


class InMemoryEventBus:
    """A shared in-process bus. Construct once and use as both producer and
    consumer. ``maxsize`` bounds memory; publishes beyond it drop (best-effort
    telemetry semantics) and count toward ``dropped``."""

    def __init__(self, *, maxsize: int = 10000) -> None:
        self._queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=maxsize)
        self.published = 0
        self.dropped = 0
        self._closed = False

    async def start(self) -> None:  # symmetry with the kafka backend
        self._closed = False

    async def stop(self) -> None:
        self._closed = True

    async def publish(self, event: RuntimeEvent) -> bool:
        if self._closed:
            return False
        try:
            self._queue.put_nowait(event_to_wire(event))
            self.published += 1
            return True
        except asyncio.QueueFull:
            self.dropped += 1
            return False

    async def consume(self) -> AsyncIterator[dict]:
        while not self._closed:
            yield await self._queue.get()

    def qsize(self) -> int:
        return self._queue.qsize()
