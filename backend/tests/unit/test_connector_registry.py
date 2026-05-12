"""Connector registry / factory tests — pure logic, no DB."""

from __future__ import annotations

from typing import Any
from types import SimpleNamespace

import pytest

from app.connectors.anthropic_connector import AnthropicConnector
from app.connectors.azure_openai_connector import AzureOpenAIConnector
from app.connectors.base import ConnectorConfigError
from app.connectors.bedrock_connector import BedrockConnector
from app.connectors.generic_openai_connector import GenericOpenAIConnector
from app.connectors.ollama_connector import OllamaConnector
from app.connectors.openai_connector import OpenAIConnector
from app.connectors.registry import SUPPORTED_PROVIDERS, build_connector


def _row(provider: str, **overrides: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "provider": provider,
        "api_key_ref": "env:KEY",
        "model": "test-model",
        "config": {},
    }
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.mark.unit
class TestBuildConnector:
    def test_openai(self) -> None:
        connector = build_connector(_row("openai"))
        assert isinstance(connector, OpenAIConnector)
        assert connector.provider == "openai"

    def test_anthropic(self) -> None:
        connector = build_connector(_row("anthropic"))
        assert isinstance(connector, AnthropicConnector)

    def test_ollama_does_not_require_key(self) -> None:
        connector = build_connector(
            _row("ollama", api_key_ref="", config={"base_url": "http://localhost:11434"})
        )
        assert isinstance(connector, OllamaConnector)

    def test_azure_openai_with_endpoint(self) -> None:
        connector = build_connector(
            _row(
                "azure_openai",
                config={
                    "endpoint": "https://r.openai.azure.com",
                    "deployment_name": "gpt-4o-prod",
                    "api_version": "2024-08-01-preview",
                },
            )
        )
        assert isinstance(connector, AzureOpenAIConnector)
        assert connector.deployment_name == "gpt-4o-prod"

    def test_azure_openai_missing_endpoint_rejected(self) -> None:
        with pytest.raises(ConnectorConfigError, match="endpoint"):
            build_connector(_row("azure_openai", config={}))

    def test_bedrock_default_region(self) -> None:
        connector = build_connector(
            _row("bedrock", model="anthropic.claude-sonnet-4", api_key_ref="")
        )
        assert isinstance(connector, BedrockConnector)
        assert connector.region == "us-east-1"

    def test_bedrock_custom_region(self) -> None:
        connector = build_connector(
            _row(
                "bedrock",
                model="anthropic.claude-sonnet-4",
                config={"region": "eu-west-1"},
            )
        )
        assert connector.region == "eu-west-1"

    def test_custom_requires_base_url(self) -> None:
        with pytest.raises(ConnectorConfigError, match="base_url"):
            build_connector(_row("custom", config={}))

    def test_custom_with_base_url(self) -> None:
        connector = build_connector(
            _row(
                "custom",
                api_key_ref="",
                config={"base_url": "http://localhost:8000/v1"},
            )
        )
        assert isinstance(connector, GenericOpenAIConnector)

    def test_custom_with_pricing_overrides(self) -> None:
        connector = build_connector(
            _row(
                "custom",
                api_key_ref="env:KEY",
                config={
                    "base_url": "https://proxy/v1",
                    "cost_input_per_million": 2.0,
                    "cost_output_per_million": 4.0,
                },
            )
        )
        assert isinstance(connector, GenericOpenAIConnector)
        # Pricing override surfaced on the instance
        assert connector._fixed_rate.input_per_million == 2.0
        assert connector._fixed_rate.output_per_million == 4.0

    def test_unknown_provider_rejected(self) -> None:
        with pytest.raises(ConnectorConfigError, match="unsupported provider"):
            build_connector(_row("acme_llm"))

    def test_case_insensitive_provider(self) -> None:
        connector = build_connector(_row("OpenAI"))
        assert isinstance(connector, OpenAIConnector)


@pytest.mark.unit
class TestSupportedProviders:
    def test_includes_all_six(self) -> None:
        assert set(SUPPORTED_PROVIDERS) == {
            "openai",
            "anthropic",
            "ollama",
            "azure_openai",
            "bedrock",
            "custom",
        }
