"""Tier gating for SIEM exporter types.

Splunk and Elastic are Tier B (ship, preview-labelled). Sentinel, Datadog,
Chronicle and the generic webhook are Tier C — frozen behind
``PLATFORM_ENABLE_SIEM_EXTENDED``.

The gate lives at :func:`app.siem.exporters._build_one` rather than only on the
admin route, because the two paths fail differently: a write-path check gives
an operator a clear error, but only a build-path check stops a config that was
written *before* the flag landed from continuing to forward. The exporter list
is org config in a JSONB column, not code — it outlives the deploy that gated
it.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from app.core.config import get_settings
from app.siem.exporters import (
    TIER_B_EXPORTER_TYPES,
    TIER_C_EXPORTER_TYPES,
    build_exporters,
    exporter_type_allowed,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def extended_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PLATFORM_ENABLE_SIEM_EXTENDED", "true")
    get_settings.cache_clear()


def _config(etype: str) -> dict:
    configs = {
        "splunk_hec": {"url": "https://splunk.example.com", "token": "env:SPLUNK_TOKEN"},
        "elastic": {"url": "https://elastic.example.com", "index": "aisp"},
        "sentinel": {
            "workspace_id": "w",
            "shared_key": "env:SENTINEL_KEY",
        },
        "datadog": {"api_key": "env:DD_KEY"},
        "chronicle": {"customer_id": "c", "bearer_token": "env:CHR_TOKEN"},
        "webhook": {"url": "https://hook.example.com"},
    }
    return {"type": etype, "name": f"{etype}-1", "config": configs[etype]}


# ─────────────────────────────────────────── the type split


def test_tier_split_covers_every_exporter_type() -> None:
    """No type may be untiered — an unclassified type would fall through the
    deny-by-default branch and be silently dark with no doc explaining why."""
    from typing import get_args

    from app.siem.exporters import ExporterType

    assert set(get_args(ExporterType)) == TIER_B_EXPORTER_TYPES | TIER_C_EXPORTER_TYPES
    assert not TIER_B_EXPORTER_TYPES & TIER_C_EXPORTER_TYPES


@pytest.mark.parametrize("etype", sorted(TIER_B_EXPORTER_TYPES))
def test_tier_b_types_are_allowed_by_default(etype: str) -> None:
    assert exporter_type_allowed(etype) is True


@pytest.mark.parametrize("etype", sorted(TIER_C_EXPORTER_TYPES))
def test_tier_c_types_are_denied_by_default(etype: str) -> None:
    assert exporter_type_allowed(etype) is False


@pytest.mark.parametrize("etype", sorted(TIER_C_EXPORTER_TYPES))
def test_tier_c_types_allowed_once_pulled_forward(etype: str, extended_enabled: None) -> None:
    assert exporter_type_allowed(etype) is True


def test_unknown_type_is_denied() -> None:
    assert exporter_type_allowed("splunk_but_evil") is False


def test_unknown_type_stays_denied_even_with_flag_on(extended_enabled: None) -> None:
    """The flag pulls Tier C forward; it is not an escape hatch for anything."""
    assert exporter_type_allowed("splunk_but_evil") is False


# ─────────────────────────────────────────── the forward path


@pytest.mark.parametrize("etype", sorted(TIER_C_EXPORTER_TYPES))
def test_dark_type_builds_no_exporter(etype: str) -> None:
    """This is the test that matters: a stored config for a dark type must not
    produce a live exporter, so there is nothing to forward through."""
    assert build_exporters([_config(etype)]) == []


def test_preexisting_dark_config_cannot_keep_forwarding() -> None:
    """An org configured Sentinel before the flag existed. After the flag lands
    (default off), only the Tier B exporters survive the rebuild."""
    configs = [_config("splunk_hec"), _config("sentinel"), _config("datadog")]

    exporters = build_exporters(configs)

    assert [e.name for e in exporters] == ["splunk_hec-1"]


def test_mixed_config_builds_only_tier_b_by_default() -> None:
    exporters = build_exporters([_config(t) for t in sorted(TIER_B_EXPORTER_TYPES)])
    assert len(exporters) == len(TIER_B_EXPORTER_TYPES)


def test_extended_flag_revives_the_full_set(extended_enabled: None) -> None:
    configs = [_config(t) for t in sorted(TIER_B_EXPORTER_TYPES | TIER_C_EXPORTER_TYPES)]

    exporters = build_exporters(configs)

    assert len(exporters) == len(configs), "flag on must build every configured exporter"


def test_gate_is_read_at_call_time_not_import_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """The module is imported once per process; the flag must still be
    observable after a settings reload, or tests pass while prod is stale."""
    assert exporter_type_allowed("datadog") is False

    monkeypatch.setenv("PLATFORM_ENABLE_SIEM_EXTENDED", "true")
    get_settings.cache_clear()

    assert exporter_type_allowed("datadog") is True
