"""SIEM forwarder (Phase 3E coverage) — queue / overflow / batching / cache /
dispatch / lifecycle, without a database (DB load is monkeypatched).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.siem import forwarder as fwd_mod
from app.siem.exporters import SiemEvent
from app.siem.forwarder import SiemForwarder, get_forwarder

pytestmark = pytest.mark.unit


def _event(org_id: str = "org-1", title: str = "e") -> SiemEvent:
    return SiemEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        org_id=org_id,
        event_type="runtime_event",
        severity="high",
        source="runtime_agent",
        title=title,
        detail={},
    )


class TestSubmit:
    def test_submit_enqueues_per_org(self):
        f = SiemForwarder()
        f.submit(_event("a"))
        f.submit(_event("a"))
        f.submit(_event("b"))
        assert len(f._queue["a"]) == 2
        assert len(f._queue["b"]) == 1

    def test_overflow_drops_oldest(self):
        f = SiemForwarder(max_queue=2)
        f.submit(_event("a", "first"))
        f.submit(_event("a", "second"))
        f.submit(_event("a", "third"))
        titles = [e.title for e in f._queue["a"]]
        assert titles == ["second", "third"]  # oldest ("first") dropped


class TestCache:
    async def test_exporters_cached_within_ttl(self, monkeypatch):
        f = SiemForwarder(cache_ttl_s=60.0)
        calls = {"n": 0}

        async def _load(org_id):
            calls["n"] += 1
            return ["exporter-sentinel"]

        monkeypatch.setattr(f, "_load_exporters", _load)
        assert await f._exporters_for("a") == ["exporter-sentinel"]
        assert await f._exporters_for("a") == ["exporter-sentinel"]
        assert calls["n"] == 1  # second call served from cache

    async def test_invalidate_forces_reload(self, monkeypatch):
        f = SiemForwarder(cache_ttl_s=60.0)
        calls = {"n": 0}

        async def _load(org_id):
            calls["n"] += 1
            return []

        monkeypatch.setattr(f, "_load_exporters", _load)
        await f._exporters_for("a")
        await f.invalidate_org("a")
        await f._exporters_for("a")
        assert calls["n"] == 2


class TestFlush:
    async def test_flush_batches_and_dispatches(self, monkeypatch):
        f = SiemForwarder(batch_size=2)
        for i in range(3):
            f.submit(_event("a", f"e{i}"))

        async def _exporters_for(org_id):
            return ["exp"]

        dispatched: list[int] = []

        async def _fake_export_to_all(exporters, batch):
            dispatched.append(len(batch))
            return {"exp": len(batch)}

        monkeypatch.setattr(f, "_exporters_for", _exporters_for)
        monkeypatch.setattr(fwd_mod, "export_to_all", _fake_export_to_all)

        await f._flush_all()  # batch_size=2 → first batch of 2
        await f._flush_all()  # remaining 1
        assert dispatched == [2, 1]
        assert not f._queue["a"]  # fully drained

    async def test_flush_with_no_exporters_drains_without_dispatch(self, monkeypatch):
        f = SiemForwarder()
        f.submit(_event("a"))

        async def _none(org_id):
            return []

        called = {"n": 0}

        async def _fake_export_to_all(exporters, batch):
            called["n"] += 1
            return {}

        monkeypatch.setattr(f, "_exporters_for", _none)
        monkeypatch.setattr(fwd_mod, "export_to_all", _fake_export_to_all)
        await f._flush_all()
        assert called["n"] == 0


class TestLoadFromDb:
    async def test_bad_uuid_returns_empty(self):
        # _load_from_db short-circuits on a non-UUID org_id without touching DB.
        assert await fwd_mod._load_from_db(None, "not-a-uuid") == []


class TestLifecycleAndSingleton:
    async def test_start_then_stop(self):
        f = SiemForwarder()
        await f.start()
        assert f._task is not None
        await f.stop()
        assert f._task is None

    def test_get_forwarder_is_singleton(self):
        assert get_forwarder() is get_forwarder()
