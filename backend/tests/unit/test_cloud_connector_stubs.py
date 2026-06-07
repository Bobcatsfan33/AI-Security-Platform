"""Cloud discovery connector stubs — real registration interface + metadata,
honest about the not-yet-implemented live crawl.

The stubs let the platform register the major managed-AI clouds and render
their config forms today; discovery itself raises until the Phase-5 cloud-SDK
transport lands. These tests pin both halves of that contract.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.connectors.discovery import (
    CLOUD_STUB_CONNECTORS,
    ConnectorMetadata,
    ConnectorNotImplementedError,
)
from app.connectors.discovery.cloud_stubs import CloudStubConnector
from app.connectors.discovery.registry import get, list_available, register, reset_for_tests

pytestmark = pytest.mark.unit

EXPECTED_TYPES = {"aws_sagemaker", "aws_bedrock", "azure_ml", "gcp_vertex", "huggingface"}


def _complete_config(cls: type[CloudStubConnector]) -> dict[str, str]:
    """A config with every required field populated."""
    return dict.fromkeys(cls.required_fields, "x")


class TestMetadata:
    def test_all_stubs_present(self) -> None:
        assert set(CLOUD_STUB_CONNECTORS) == EXPECTED_TYPES

    @pytest.mark.parametrize("cls", list(CLOUD_STUB_CONNECTORS.values()))
    def test_metadata_well_formed(self, cls: type[CloudStubConnector]) -> None:
        meta = cls.get_metadata()
        assert isinstance(meta, ConnectorMetadata)
        assert meta.name and meta.description and meta.icon
        assert meta.supported_asset_types  # non-empty
        schema = meta.config_schema
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        # Every required field is a declared property.
        props = set(schema["properties"])
        assert set(schema["required"]) <= props
        assert props  # has at least one configurable field

    def test_secret_fields_marked_password(self) -> None:
        # Hugging Face token is a secret → schema marks it format=password.
        schema = CLOUD_STUB_CONNECTORS["huggingface"].get_metadata().config_schema
        assert schema["properties"]["token"]["format"] == "password"


class TestTestConnection:
    async def test_missing_config_reports_missing_fields(self) -> None:
        cls = CLOUD_STUB_CONNECTORS["azure_ml"]
        status = await cls(config={}).test_connection()
        assert status.connected is False
        assert "Missing required configuration" in status.message
        # Names the actual missing fields.
        assert "subscription_id" in status.message

    async def test_complete_config_reports_not_implemented(self) -> None:
        cls = CLOUD_STUB_CONNECTORS["aws_bedrock"]
        status = await cls(config=_complete_config(cls)).test_connection()
        assert status.connected is False
        assert "not yet implemented" in status.message

    async def test_test_connection_never_raises(self) -> None:
        for cls in CLOUD_STUB_CONNECTORS.values():
            status = await cls(config={}).test_connection()
            assert status.connected is False


class TestCrawlIsHonestlyUnimplemented:
    @pytest.mark.parametrize("cls", list(CLOUD_STUB_CONNECTORS.values()))
    async def test_discover_raises(self, cls: type[CloudStubConnector]) -> None:
        with pytest.raises(ConnectorNotImplementedError):
            await cls(config=_complete_config(cls)).discover()

    @pytest.mark.parametrize("cls", list(CLOUD_STUB_CONNECTORS.values()))
    async def test_sync_raises(self, cls: type[CloudStubConnector]) -> None:
        with pytest.raises(ConnectorNotImplementedError):
            await cls(config=_complete_config(cls)).sync(datetime.now(UTC))


class TestRegistration:
    """Self-contained: register the stubs and assert resolution, independent of
    whatever the global registry's state is when this runs."""

    def test_stubs_register_and_resolve(self) -> None:
        reset_for_tests()
        try:
            for ctype, cls in CLOUD_STUB_CONNECTORS.items():
                register(ctype, cls)
            for ctype, cls in CLOUD_STUB_CONNECTORS.items():
                assert get(ctype) is cls
            catalog_names = {m.name for m in list_available()}
            assert "AWS SageMaker" in catalog_names
            assert "Hugging Face" in catalog_names
        finally:
            # Restore the full bundled registry for any later test in the run.
            reset_for_tests()
            from app.connectors.discovery import MockConnector

            register("mock", MockConnector)
            for ctype, cls in CLOUD_STUB_CONNECTORS.items():
                register(ctype, cls)
