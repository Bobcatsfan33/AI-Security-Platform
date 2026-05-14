"""Unit tests for the v2 discovery connector framework + mock connector."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from app.connectors.discovery import (
    BaseConnector,
    ConnectorMetadata,
    DiscoveredAsset,
    MockConnector,
    UnknownConnectorTypeError,
)
from app.connectors.discovery.registry import (
    get,
    list_available,
    register,
    reset_for_tests,
)


def test_mock_connector_metadata_well_formed() -> None:
    meta = MockConnector.get_metadata()
    assert isinstance(meta, ConnectorMetadata)
    assert meta.name == "Mock"
    assert "model" in meta.supported_asset_types
    assert meta.config_schema["type"] == "object"


def test_mock_connector_discover_returns_ten_assets() -> None:
    connector = MockConnector(config={"stable": True})
    assets = asyncio.run(connector.discover())
    assert len(assets) == 10
    # Covers every supported asset_type
    types = {a.asset_type for a in assets}
    assert types == {"model", "endpoint", "dataset", "pipeline", "agent", "tool"}
    # External IDs are deterministic in stable mode
    again = asyncio.run(connector.discover())
    assert {a.external_id for a in again} == {a.external_id for a in assets}


def test_mock_connector_sync_returns_subset_of_discover() -> None:
    connector = MockConnector(config={"stable": True})
    all_assets = asyncio.run(connector.discover())
    incremental = asyncio.run(
        connector.sync(since=datetime.now(timezone.utc))
    )
    assert 0 < len(incremental) < len(all_assets)
    # Every incremental asset must come from the discover set
    incremental_ids = {a.external_id for a in incremental}
    discover_ids = {a.external_id for a in all_assets}
    assert incremental_ids.issubset(discover_ids)


def test_mock_connector_unstable_mode_appends_uuid() -> None:
    connector = MockConnector(config={"stable": False})
    a = asyncio.run(connector.discover())
    b = asyncio.run(connector.discover())
    # Two consecutive discovers return different IDs in unstable mode.
    assert {x.external_id for x in a} != {x.external_id for x in b}


def test_mock_connector_test_connection_succeeds() -> None:
    connector = MockConnector(config={})
    status = asyncio.run(connector.test_connection())
    assert status.connected is True
    assert status.latency_ms is not None and status.latency_ms >= 0


def test_discovered_asset_validation_rejects_blank_external_id() -> None:
    with pytest.raises(ValueError):
        DiscoveredAsset(
            external_id="",
            name="x",
            asset_type="model",
            provider="openai",
        )


def test_registry_get_unknown_raises() -> None:
    with pytest.raises(UnknownConnectorTypeError):
        get("not-a-real-connector")


def test_registry_lists_registered() -> None:
    names = [m.name for m in list_available()]
    # MockConnector is registered at module import
    assert "Mock" in names


def test_registry_register_validates_subclass() -> None:
    class _NotAConnector:
        pass

    with pytest.raises(TypeError):
        register("bad", _NotAConnector)  # type: ignore[arg-type]


def test_registry_reset_clears_then_reregister() -> None:
    reset_for_tests()
    assert list_available() == []
    register("mock", MockConnector)
    assert get("mock") is MockConnector


def test_base_connector_cannot_be_instantiated() -> None:
    with pytest.raises(TypeError):
        BaseConnector(config={})  # abstract methods unimplemented
