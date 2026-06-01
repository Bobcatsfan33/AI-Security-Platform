"""Tests for the event streaming spine (Sprint 2).

Covers wire serde, the in-memory bus (publish→consume round-trip used by the
EPA fleet in tests), partition keying, and the Kafka producer's best-effort
fail-safe contract. The live aiokafka↔Redpanda path is exercised against
docker-compose locally, not in CI (no broker service in CI).
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from app.streaming.events import get_producer, reset_for_tests, set_producer
from app.streaming.kafka_backend import KafkaEventProducer
from app.streaming.memory_backend import InMemoryEventBus
from app.streaming.serde import decode, encode, event_to_wire, partition_key
from app.telemetry.runtime_event import RuntimeEvent

pytestmark = pytest.mark.unit


def _event(**over) -> RuntimeEvent:
    base = dict(
        org_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        agent_instance_id="agent-1",
        session_id="sess-1",
        event_type="tool_call",
        direction="internal",
        enforcement_level="balanced",
        pipeline_exit_stage="stage2_ml",
        action_taken="flagged",
        correlation_key="task-9",
        tool_name="shell",
    )
    base.update(over)
    return RuntimeEvent(**base)  # type: ignore[arg-type]


class TestSerde:
    def test_round_trip_is_json_safe_dict(self):
        e = _event()
        wire = decode(encode(e))
        assert wire["tool_name"] == "shell"
        assert wire["event_type"] == "tool_call"
        # UUIDs and datetimes are stringified.
        assert wire["org_id"] == str(e.org_id)
        assert isinstance(wire["timestamp"], str)

    def test_event_to_wire_matches_decode(self):
        e = _event()
        assert event_to_wire(e) == decode(encode(e))

    def test_decode_rejects_garbage(self):
        with pytest.raises(ValueError):
            decode(b"not json")
        with pytest.raises(ValueError):
            decode(b"[1,2,3]")  # not an object

    def test_partition_key_prefers_correlation_key(self):
        e = _event(correlation_key="flow-42")
        assert partition_key(e) == b"flow-42"

    def test_empty_correlation_key_is_filled_to_root_by_post_init(self):
        # RuntimeEvent.__post_init__ backfills correlation_key from the root
        # id, so a real event always partitions by its causal flow.
        e = _event(correlation_key="")
        assert e.correlation_key == str(e.root_event_id)
        assert partition_key(e) == str(e.root_event_id).encode()


class TestInMemoryBus:
    async def test_publish_then_consume_round_trip(self):
        bus = InMemoryEventBus()
        await bus.start()
        e = _event(tool_name="search")
        assert await bus.publish(e) is True

        agen = bus.consume()
        wire = await asyncio.wait_for(agen.__anext__(), timeout=1.0)
        assert wire["tool_name"] == "search"
        assert bus.published == 1

    async def test_overflow_drops_and_counts(self):
        bus = InMemoryEventBus(maxsize=1)
        await bus.start()
        assert await bus.publish(_event()) is True
        assert await bus.publish(_event()) is False  # full
        assert bus.dropped == 1

    async def test_publish_after_stop_returns_false(self):
        bus = InMemoryEventBus()
        await bus.start()
        await bus.stop()
        assert await bus.publish(_event()) is False


class TestProducerSingleton:
    def test_default_is_none(self):
        reset_for_tests()
        assert get_producer() is None

    def test_set_and_get(self):
        reset_for_tests()
        bus = InMemoryEventBus()
        set_producer(bus)
        assert get_producer() is bus
        reset_for_tests()
        assert get_producer() is None


class TestKafkaProducerFailSafe:
    async def test_publish_without_start_returns_false(self):
        # No broker, never started → publish must not raise, returns False.
        p = KafkaEventProducer(brokers="localhost:9092", topic="runtime.events")
        assert await p.publish(_event()) is False

    async def test_stop_is_safe_when_never_started(self):
        p = KafkaEventProducer(brokers="localhost:9092", topic="runtime.events")
        await p.stop()  # must not raise
