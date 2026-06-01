"""Event streaming spine — the Redpanda (Kafka-compatible) telemetry bus.

ClickHouse remains the durable audit/replay store; this bus is the *live*
spine the EPA fleet (Sprint 5) consumes. Producers publish RuntimeEvents to
the ``runtime.events`` topic; consumers yield wire dicts (same shape as
ClickHouse rows, so the poset graph builder consumes them unchanged).
"""

from app.streaming.events import (
    RUNTIME_EVENTS_TOPIC,
    EventConsumer,
    EventProducer,
    get_producer,
    reset_for_tests,
)

__all__ = [
    "RUNTIME_EVENTS_TOPIC",
    "EventConsumer",
    "EventProducer",
    "get_producer",
    "reset_for_tests",
]
