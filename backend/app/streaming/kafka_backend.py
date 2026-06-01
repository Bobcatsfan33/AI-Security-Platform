"""aiokafka-backed producer / consumer against Redpanda (Kafka wire protocol).

Production backend. ``aiokafka`` is imported lazily so the package imports
fine in environments without the broker (dev/CI), and so a missing optional
dependency degrades gracefully rather than crashing import.
"""

from __future__ import annotations

import logging
from typing import Any, AsyncIterator, Optional

from app.streaming.serde import decode, encode, partition_key
from app.telemetry.runtime_event import RuntimeEvent

logger = logging.getLogger("platform.streaming.kafka")


class KafkaEventProducer:
    """Publishes events to a Redpanda topic. Best-effort: start/publish errors
    log and return falsy rather than propagating into the ingest path."""

    def __init__(self, *, brokers: str, topic: str) -> None:
        self._brokers = brokers
        self._topic = topic
        self._producer: Any = None

    async def start(self) -> None:
        try:
            from aiokafka import AIOKafkaProducer  # type: ignore[import-untyped]
        except ImportError:  # pragma: no cover - optional dep
            logger.warning("aiokafka_unavailable_streaming_disabled")
            return
        try:
            self._producer = AIOKafkaProducer(bootstrap_servers=self._brokers)
            await self._producer.start()
            logger.info("kafka_producer_started", extra={"brokers": self._brokers})
        except Exception as exc:  # noqa: BLE001
            logger.warning("kafka_producer_start_failed", extra={"error": str(exc)})
            self._producer = None

    async def stop(self) -> None:
        if self._producer is not None:
            try:
                await self._producer.stop()
            finally:
                self._producer = None

    async def publish(self, event: RuntimeEvent) -> bool:
        if self._producer is None:
            return False
        try:
            await self._producer.send_and_wait(
                self._topic, value=encode(event), key=partition_key(event)
            )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("kafka_publish_failed", extra={"error": str(exc)})
            return False


class KafkaEventConsumer:
    """Consumes a Redpanda topic, yielding decoded wire dicts. Drives the EPA
    fleet in production. Malformed payloads are skipped (logged), never fatal."""

    def __init__(self, *, brokers: str, topic: str, group_id: str) -> None:
        self._brokers = brokers
        self._topic = topic
        self._group_id = group_id
        self._consumer: Any = None

    async def start(self) -> None:
        from aiokafka import AIOKafkaConsumer  # type: ignore[import-untyped]

        self._consumer = AIOKafkaConsumer(
            self._topic,
            bootstrap_servers=self._brokers,
            group_id=self._group_id,
            enable_auto_commit=True,
            auto_offset_reset="latest",
        )
        await self._consumer.start()
        logger.info("kafka_consumer_started", extra={"group": self._group_id})

    async def stop(self) -> None:
        if self._consumer is not None:
            try:
                await self._consumer.stop()
            finally:
                self._consumer = None

    async def consume(self) -> AsyncIterator[dict]:
        if self._consumer is None:
            return
        async for msg in self._consumer:
            try:
                yield decode(msg.value)
            except ValueError as exc:
                logger.warning("kafka_decode_skipped", extra={"error": str(exc)})
                continue


def build_producer(*, brokers: str, topic: str) -> KafkaEventProducer:
    return KafkaEventProducer(brokers=brokers, topic=topic)


def build_consumer(*, brokers: str, topic: str, group_id: str) -> KafkaEventConsumer:
    return KafkaEventConsumer(brokers=brokers, topic=topic, group_id=group_id)
