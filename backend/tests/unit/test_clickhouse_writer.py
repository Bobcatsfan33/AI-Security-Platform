"""Tests for the async batched ClickHouse writer.

We don't run a real ClickHouse — instead we monkey-patch the module's
``_get_client`` to return a fake that records the inserts. This exercises
the queue, batching, flush triggers, and graceful shutdown without any
live infrastructure.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest

from app.telemetry import clickhouse_writer
from app.telemetry.clickhouse_writer import (
    flush_now,
    record_runtime_event,
    reset_for_tests,
    start_writer,
    stop_writer,
)
from app.telemetry.runtime_event import (
    RUNTIME_EVENTS_COLUMNS,
    RuntimeEvent,
)


class _FakeClient:
    """Captures every insert call so tests can assert on what was written."""

    def __init__(self) -> None:
        self.inserts: list[tuple[str, list[tuple], list[str]]] = []

    def insert(
        self, table: str, rows: list[tuple], column_names: list[str]
    ) -> None:
        self.inserts.append((table, list(rows), list(column_names)))

    @property
    def total_rows(self) -> int:
        return sum(len(rows) for _, rows, _ in self.inserts)


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    fake = _FakeClient()
    monkeypatch.setattr(clickhouse_writer, "_get_client", lambda: fake)
    reset_for_tests()
    return fake


def _event(**overrides: Any) -> RuntimeEvent:
    base = {
        "org_id": uuid.uuid4(),
        "asset_id": uuid.uuid4(),
        "agent_instance_id": "agent-1",
        "session_id": "session-1",
        "event_type": "request",
        "direction": "inbound",
        "enforcement_level": "fast",
        "pipeline_exit_stage": "no_match",
        "action_taken": "allowed",
    }
    base.update(overrides)
    return RuntimeEvent(**base)  # type: ignore[arg-type]


@pytest.mark.unit
class TestRuntimeEvent:
    def test_to_row_column_count_matches_schema(self) -> None:
        row = _event().to_row()
        assert len(row) == len(RUNTIME_EVENTS_COLUMNS), (
            "to_row() length must equal RUNTIME_EVENTS_COLUMNS — these are "
            "kept in lockstep with the SQL schema"
        )

    def test_to_row_first_column_is_event_id(self) -> None:
        e = _event()
        assert e.to_row()[0] == e.event_id

    def test_event_id_is_unique(self) -> None:
        ids = {_event().event_id for _ in range(50)}
        assert len(ids) == 50


@pytest.mark.unit
@pytest.mark.asyncio
class TestRecordRuntimeEvent:
    async def test_returns_false_when_writer_not_started(self) -> None:
        reset_for_tests()
        result = await record_runtime_event(_event())
        assert result is False

    async def test_returns_true_when_enqueued(self, fake_client: _FakeClient) -> None:
        await start_writer()
        try:
            assert await record_runtime_event(_event()) is True
        finally:
            await stop_writer()

    async def test_drain_on_shutdown_inserts_all_pending(
        self, fake_client: _FakeClient
    ) -> None:
        await start_writer()
        for _ in range(7):
            await record_runtime_event(_event())
        await stop_writer()
        assert fake_client.total_rows == 7

    async def test_batch_threshold_triggers_flush(
        self, fake_client: _FakeClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Lower the batch threshold so the test doesn't depend on the
        # default 100 events.
        monkeypatch.setattr(clickhouse_writer, "CLICKHOUSE_BATCH_SIZE", 3)
        await start_writer()
        try:
            for _ in range(3):
                await record_runtime_event(_event())
            # Give the flusher a moment to drain
            for _ in range(20):
                if fake_client.total_rows == 3:
                    break
                await asyncio.sleep(0.01)
            assert fake_client.total_rows == 3
        finally:
            await stop_writer()

    async def test_full_queue_returns_false(
        self, fake_client: _FakeClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(clickhouse_writer, "CLICKHOUSE_QUEUE_MAX", 2)
        # Don't start the flusher — let the queue fill
        from app.telemetry.clickhouse_writer import _STOP  # noqa: F401

        clickhouse_writer._queue = asyncio.Queue(  # type: ignore[attr-defined]
            maxsize=2
        )
        try:
            assert await record_runtime_event(_event()) is True
            assert await record_runtime_event(_event()) is True
            assert await record_runtime_event(_event()) is False
        finally:
            reset_for_tests()


@pytest.mark.unit
@pytest.mark.asyncio
class TestFlushNow:
    async def test_flush_now_drains_queue(self, fake_client: _FakeClient) -> None:
        await start_writer()
        try:
            for _ in range(4):
                await record_runtime_event(_event())
            count = await flush_now()
            # flush_now drains; the loop may have already drained some
            assert count + fake_client.total_rows >= 4
        finally:
            await stop_writer()


@pytest.mark.unit
@pytest.mark.asyncio
class TestResilience:
    async def test_insert_failure_does_not_break_writer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class BoomClient:
            def insert(self, *args: Any, **kwargs: Any) -> None:
                raise RuntimeError("simulated CH outage")

        monkeypatch.setattr(clickhouse_writer, "_get_client", lambda: BoomClient())
        monkeypatch.setattr(clickhouse_writer, "CLICKHOUSE_BATCH_SIZE", 2)
        reset_for_tests()
        await start_writer()
        try:
            # Two events trigger a flush which raises internally and is logged.
            # The writer must not propagate the exception.
            assert await record_runtime_event(_event()) is True
            assert await record_runtime_event(_event()) is True
            await asyncio.sleep(0.1)
            # Writer is still alive — we can keep enqueueing
            assert await record_runtime_event(_event()) is True
        finally:
            await stop_writer()

    async def test_no_client_does_not_break_writer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(clickhouse_writer, "_get_client", lambda: None)
        reset_for_tests()
        await start_writer()
        try:
            assert await record_runtime_event(_event()) is True
            await asyncio.sleep(0.05)  # let the loop tick
        finally:
            await stop_writer()
