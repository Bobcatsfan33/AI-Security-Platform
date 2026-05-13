"""Unit tests for the SIEM forwarder service.

The forwarder is the in-process queue + dispatch loop that ships events
to org-configured SIEM backends. These tests use a recording exporter
to verify batching, queue cap, cache invalidation, and isolation
between orgs.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import pytest

from app.siem import forwarder as fwd_module
from app.siem.exporters import SiemEvent, SiemExporter
from app.siem.forwarder import SiemForwarder


class _RecordingExporter:
    exporter_type = "webhook"

    def __init__(self, name: str) -> None:
        self.name = name
        self.batches: list[list[SiemEvent]] = []

    async def export(self, events: list[SiemEvent]) -> int:
        # Copy so later mutation of the list doesn't affect assertions
        self.batches.append(list(events))
        return len(events)


def _ev(org: str) -> SiemEvent:
    return SiemEvent(
        timestamp=datetime.now(timezone.utc),
        org_id=org,
        event_type="finding",
        severity="high",
        source="evaluation",
        title="t",
        detail={},
    )


@pytest.mark.asyncio
async def test_forwarder_dispatches_to_configured_exporters(monkeypatch: pytest.MonkeyPatch) -> None:
    ex = _RecordingExporter("a")

    async def _load(org_id: str) -> list[SiemExporter]:
        return [ex]

    f = SiemForwarder(
        max_queue=100, batch_size=10, flush_interval_s=0.05, cache_ttl_s=60.0
    )
    monkeypatch.setattr(f, "_load_exporters", _load)
    await f.start()
    try:
        for _ in range(5):
            f.submit(_ev("org-1"))
        # Wait a couple of flush intervals
        await asyncio.sleep(0.3)
    finally:
        await f.stop()

    flat = [e for batch in ex.batches for e in batch]
    assert len(flat) == 5
    assert all(e.org_id == "org-1" for e in flat)


@pytest.mark.asyncio
async def test_forwarder_isolates_orgs(monkeypatch: pytest.MonkeyPatch) -> None:
    a = _RecordingExporter("a")
    b = _RecordingExporter("b")

    async def _load(org_id: str) -> list[SiemExporter]:
        return [a] if org_id == "org-a" else [b]

    f = SiemForwarder(
        max_queue=100, batch_size=10, flush_interval_s=0.05, cache_ttl_s=60.0
    )
    monkeypatch.setattr(f, "_load_exporters", _load)
    await f.start()
    try:
        f.submit(_ev("org-a"))
        f.submit(_ev("org-a"))
        f.submit(_ev("org-b"))
        await asyncio.sleep(0.3)
    finally:
        await f.stop()

    assert sum(len(batch) for batch in a.batches) == 2
    assert sum(len(batch) for batch in b.batches) == 1


@pytest.mark.asyncio
async def test_forwarder_drops_oldest_on_overflow() -> None:
    f = SiemForwarder(max_queue=3, batch_size=10, flush_interval_s=10.0)
    for i in range(5):
        ev = _ev("org-1")
        ev.detail["seq"] = i  # type: ignore[index]
        f.submit(ev)
    q = f._queue["org-1"]  # type: ignore[attr-defined]
    assert len(q) == 3
    # Oldest events (0, 1) should have been dropped — only 2, 3, 4 remain.
    seqs = [e.detail["seq"] for e in q]
    assert seqs == [2, 3, 4]


@pytest.mark.asyncio
async def test_forwarder_cache_invalidates(monkeypatch: pytest.MonkeyPatch) -> None:
    load_calls: list[str] = []

    async def _load(org_id: str) -> list[SiemExporter]:
        load_calls.append(org_id)
        return []

    f = SiemForwarder(cache_ttl_s=60.0)
    monkeypatch.setattr(f, "_load_exporters", _load)
    await f._exporters_for("org-x")
    await f._exporters_for("org-x")  # cached
    assert load_calls == ["org-x"]
    await f.invalidate_org("org-x")
    await f._exporters_for("org-x")  # re-load
    assert load_calls == ["org-x", "org-x"]


@pytest.mark.asyncio
async def test_forwarder_swallows_exporter_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Crashing:
        name = "boom"
        exporter_type = "webhook"

        async def export(self, events: list[SiemEvent]) -> int:
            raise RuntimeError("kaboom")

    async def _load(org_id: str) -> list[SiemExporter]:
        return [_Crashing()]  # type: ignore[list-item]

    f = SiemForwarder(flush_interval_s=0.05)
    monkeypatch.setattr(f, "_load_exporters", _load)
    await f.start()
    try:
        f.submit(_ev("org-1"))
        await asyncio.sleep(0.2)
    finally:
        await f.stop()  # if the crash escaped, this would hang


def test_module_singleton_is_stable() -> None:
    a = fwd_module.get_forwarder()
    b = fwd_module.get_forwarder()
    assert a is b
