"""SIEM forwarder service — fan out platform events to org-configured
SIEMs in the background.

The forwarder runs as a singleton per process and is initialised on
FastAPI startup. Callers push :class:`SiemEvent` objects via
:meth:`SiemForwarder.submit` — they are batched and dispatched to every
configured backend without blocking the caller.

Design notes
------------
- Per-org config lives in ``Organization.settings["siem_exporters"]``.
- Exporter instances are cached and refreshed every 60s — config writes
  through the admin route invalidate the cache for the affected org.
- A bounded in-memory queue (default 10_000) prevents unbounded growth
  when a SIEM is down; oldest events are dropped first.
- Forwarding never raises and never blocks platform operations.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.organization import Organization
from app.db.session import SessionLocal
from app.siem.exporters import (
    SiemEvent,
    SiemExporter,
    build_exporters,
    export_to_all,
)

logger = logging.getLogger("platform.siem.forwarder")


@dataclass
class _OrgCacheEntry:
    exporters: list[SiemExporter]
    loaded_at: float


class SiemForwarder:
    """Singleton service. Owns the dispatch loop and exporter cache.

    The forwarder is intentionally tolerant — every failure path logs
    and continues. The contract with callers is: ``submit`` accepts
    events, the rest is best-effort delivery.
    """

    def __init__(
        self,
        *,
        max_queue: int = 10_000,
        batch_size: int = 50,
        flush_interval_s: float = 2.0,
        cache_ttl_s: float = 60.0,
    ) -> None:
        self._queue: dict[str, deque[SiemEvent]] = defaultdict(deque)
        self._max_queue = max_queue
        self._batch_size = batch_size
        self._flush_interval_s = flush_interval_s
        self._cache_ttl_s = cache_ttl_s
        self._cache: dict[str, _OrgCacheEntry] = {}
        self._cache_lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._task: Optional[asyncio.Task[None]] = None
        self._stopped = asyncio.Event()

    # ──────────────────────────────────────── lifecycle

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopped.clear()
        self._task = asyncio.create_task(self._run(), name="siem-forwarder")
        logger.info("siem_forwarder_started")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stopped.set()
        self._wake.set()
        try:
            await asyncio.wait_for(self._task, timeout=5.0)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None
        logger.info("siem_forwarder_stopped")

    # ──────────────────────────────────────── public API

    def submit(self, event: SiemEvent) -> None:
        """Non-blocking; safe to call from request handlers."""
        q = self._queue[event.org_id]
        if len(q) >= self._max_queue:
            q.popleft()  # drop oldest
            logger.warning(
                "siem_queue_overflow",
                extra={"org_id": event.org_id, "max": self._max_queue},
            )
        q.append(event)
        self._wake.set()

    async def invalidate_org(self, org_id: str) -> None:
        async with self._cache_lock:
            self._cache.pop(org_id, None)

    # ──────────────────────────────────────── internals

    async def _run(self) -> None:
        while not self._stopped.is_set():
            try:
                await asyncio.wait_for(
                    self._wake.wait(), timeout=self._flush_interval_s
                )
            except asyncio.TimeoutError:
                pass
            self._wake.clear()
            await self._flush_all()

    async def _flush_all(self) -> None:
        for org_id in list(self._queue.keys()):
            batch: list[SiemEvent] = []
            q = self._queue[org_id]
            while q and len(batch) < self._batch_size:
                batch.append(q.popleft())
            if not batch:
                continue
            exporters = await self._exporters_for(org_id)
            if not exporters:
                continue
            results = await export_to_all(exporters, batch)
            for name, count in results.items():
                logger.debug(
                    "siem_batch_dispatched",
                    extra={"org_id": org_id, "exporter": name, "count": count},
                )

    async def _exporters_for(self, org_id: str) -> list[SiemExporter]:
        now = time.monotonic()
        async with self._cache_lock:
            entry = self._cache.get(org_id)
            if entry and (now - entry.loaded_at) < self._cache_ttl_s:
                return entry.exporters
        exporters = await self._load_exporters(org_id)
        async with self._cache_lock:
            self._cache[org_id] = _OrgCacheEntry(
                exporters=exporters, loaded_at=now
            )
        return exporters

    async def _load_exporters(self, org_id: str) -> list[SiemExporter]:
        try:
            async with SessionLocal() as db:
                return await _load_from_db(db, org_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "siem_config_load_failed",
                extra={"org_id": org_id, "error": str(exc)},
            )
            return []


async def _load_from_db(db: AsyncSession, org_id: str) -> list[SiemExporter]:
    try:
        org_uuid = uuid.UUID(org_id)
    except (TypeError, ValueError):
        return []
    row = (
        await db.execute(
            select(Organization).where(Organization.id == org_uuid)
        )
    ).scalar_one_or_none()
    if row is None:
        return []
    raw = (row.settings or {}).get("siem_exporters", [])
    if not isinstance(raw, list):
        return []
    return build_exporters(raw)


# ─────────────────────────────────────────── module-level singleton

_forwarder: SiemForwarder | None = None


def get_forwarder() -> SiemForwarder:
    """Return the process-wide forwarder, instantiating on first call."""
    global _forwarder
    if _forwarder is None:
        _forwarder = SiemForwarder()
    return _forwarder
