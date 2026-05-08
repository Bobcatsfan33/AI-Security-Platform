"""Async batched ClickHouse writer for runtime telemetry events.

Boundary policy (binding): ClickHouse is **never** read in the policy
enforcement hot path. This writer is for ingestion only. Reads happen
in dashboard/analytics services (Sprint 8+).

Design
------
``clickhouse-connect`` is sync. The platform is async. To avoid pulling in
an experimental async fork, we wrap sync inserts in ``asyncio.to_thread``.
Sync inserts are batched: a bounded asyncio.Queue collects events, and a
single background task drains the queue every ``CLICKHOUSE_FLUSH_INTERVAL_S``
seconds OR when ``CLICKHOUSE_BATCH_SIZE`` events have accumulated.

Public surface
--------------
``record_runtime_event(event)``
    Enqueue a RuntimeEvent. Never blocks for more than the queue lock.
    Caller is await-able; the actual ClickHouse write happens in the
    background flusher.

``start_writer()`` / ``stop_writer()``
    Lifecycle hooks called from the FastAPI app's lifespan. ``stop_writer``
    drains any pending events before returning so we don't lose data on
    graceful shutdown.

``flush_now()``
    Force a flush. Used by tests and by an admin endpoint that wants
    synchronous-looking ingestion (rare).
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Optional

import structlog

from app.core.config import get_settings
from app.telemetry.runtime_event import RUNTIME_EVENTS_COLUMNS, RuntimeEvent

logger = structlog.get_logger("platform.telemetry")

# ─────────────────────────────────────────────── Configuration

CLICKHOUSE_BATCH_SIZE: int = int(os.getenv("CLICKHOUSE_BATCH_SIZE", "100"))
CLICKHOUSE_FLUSH_INTERVAL_S: float = float(
    os.getenv("CLICKHOUSE_FLUSH_INTERVAL_S", "5.0")
)
CLICKHOUSE_QUEUE_MAX: int = int(os.getenv("CLICKHOUSE_QUEUE_MAX", "10000"))
CLICKHOUSE_TABLE: str = "runtime_events"

# Sentinel so the flusher can be told to stop cleanly.
_STOP = object()


# ─────────────────────────────────────────────── State

_queue: Optional["asyncio.Queue[Any]"] = None
_flush_task: Optional[asyncio.Task] = None
_client: Any = None  # clickhouse_connect.Client; held lazily


def _get_client() -> Any:
    """Return a singleton clickhouse-connect client. Creates on first call.

    Errors during client construction are logged but not raised — telemetry
    failures must never propagate into application code paths that emit
    events.
    """
    global _client
    if _client is not None:
        return _client
    settings = get_settings()
    try:
        import clickhouse_connect  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("clickhouse_connect_unavailable_skipping_writes")
        return None

    # CLICKHOUSE_URL is in the form "http://host:port"
    url = settings.clickhouse_url
    try:
        _client = clickhouse_connect.get_client(
            interface=url.split("://", 1)[0] if "://" in url else "http",
            host=url.split("://", 1)[-1].split(":", 1)[0],
            port=int(url.rsplit(":", 1)[-1]) if ":" in url.split("://", 1)[-1] else 8123,
            database=settings.clickhouse_database,
            connect_timeout=5,
            send_receive_timeout=10,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("clickhouse_client_init_failed", error=str(exc))
        _client = None
    return _client


# ─────────────────────────────────────────────── Public API


async def record_runtime_event(event: RuntimeEvent) -> bool:
    """Enqueue a runtime event for async batched insertion.

    Returns True if enqueued, False if the queue is full or the writer
    isn't started. The caller's choice whether to retry / drop / surface.
    """
    if _queue is None:
        # Writer hasn't started — caller's responsibility to detect during dev.
        logger.debug("runtime_event_dropped_writer_not_started")
        return False
    try:
        _queue.put_nowait(event)
        return True
    except asyncio.QueueFull:
        logger.warning(
            "runtime_event_dropped_queue_full",
            queue_max=CLICKHOUSE_QUEUE_MAX,
        )
        return False


async def start_writer() -> None:
    """Start the background flush task. Idempotent."""
    global _queue, _flush_task
    if _flush_task is not None:
        return
    _queue = asyncio.Queue(maxsize=CLICKHOUSE_QUEUE_MAX)
    _flush_task = asyncio.create_task(_flush_loop(), name="clickhouse_flusher")
    logger.info(
        "clickhouse_writer_started",
        batch_size=CLICKHOUSE_BATCH_SIZE,
        flush_interval_s=CLICKHOUSE_FLUSH_INTERVAL_S,
    )


async def stop_writer() -> None:
    """Drain pending events and stop the flush task. Idempotent."""
    global _queue, _flush_task, _client
    if _flush_task is None:
        return
    if _queue is not None:
        await _queue.put(_STOP)
    try:
        await asyncio.wait_for(_flush_task, timeout=10.0)
    except asyncio.TimeoutError:
        logger.warning("clickhouse_writer_stop_timeout")
        _flush_task.cancel()
    finally:
        _flush_task = None
        _queue = None
        _client = None
    logger.info("clickhouse_writer_stopped")


async def flush_now() -> int:
    """Drain everything currently in the queue, return number flushed.

    Provided for tests and for admin tooling. Production code paths emit
    events and let the background task batch them.
    """
    if _queue is None:
        return 0
    batch: list[RuntimeEvent] = []
    while not _queue.empty():
        item = _queue.get_nowait()
        if item is _STOP:
            await _queue.put(_STOP)
            break
        batch.append(item)
    if batch:
        await _insert_batch(batch)
    return len(batch)


# ─────────────────────────────────────────────── Internal flush loop


async def _flush_loop() -> None:
    """Drain ``_queue`` to ClickHouse on an interval or batch threshold."""
    assert _queue is not None
    batch: list[RuntimeEvent] = []
    deadline = asyncio.get_event_loop().time() + CLICKHOUSE_FLUSH_INTERVAL_S

    while True:
        timeout = max(0.0, deadline - asyncio.get_event_loop().time())
        try:
            item = await asyncio.wait_for(_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            item = None  # interval elapsed → flush whatever we have

        if item is _STOP:
            if batch:
                await _insert_batch(batch)
            return

        if item is not None:
            batch.append(item)

        should_flush = (
            len(batch) >= CLICKHOUSE_BATCH_SIZE
            or asyncio.get_event_loop().time() >= deadline
        )
        if should_flush and batch:
            await _insert_batch(batch)
            batch = []
            deadline = asyncio.get_event_loop().time() + CLICKHOUSE_FLUSH_INTERVAL_S


async def _insert_batch(batch: list[RuntimeEvent]) -> None:
    """Bulk-insert a batch into ClickHouse. Logs errors; never raises.

    Failed batches are dropped — runtime_events is best-effort telemetry,
    not the audit log. The audit log lives elsewhere (see app/security/
    audit_log.py) and has its own durability guarantees.
    """
    client = _get_client()
    if client is None:
        logger.warning(
            "clickhouse_batch_dropped_no_client", batch_size=len(batch)
        )
        return

    rows = [event.to_row() for event in batch]
    try:
        await asyncio.to_thread(
            client.insert,
            CLICKHOUSE_TABLE,
            rows,
            column_names=list(RUNTIME_EVENTS_COLUMNS),
        )
        logger.debug("clickhouse_batch_inserted", count=len(batch))
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "clickhouse_batch_insert_failed",
            batch_size=len(batch),
            error=str(exc),
        )


# ─────────────────────────────────────────────── Test helpers


def reset_for_tests() -> None:
    """Reset module-level state. Tests only."""
    global _queue, _flush_task, _client
    _queue = None
    _flush_task = None
    _client = None
