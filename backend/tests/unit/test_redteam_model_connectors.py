"""v2 model-connector factory — the replacement for the dropped v1
build_connector. Verifies provider dispatch + required-extra validation
without touching the network (adapters don't call out at construction)."""

from __future__ import annotations

import pytest

from app.connectors.anthropic_connector import AnthropicConnector
from app.connectors.base import ConnectorConfigError
from app.connectors.bedrock_connector import BedrockConnector
from app.connectors.generic_openai_connector import GenericOpenAIConnector
from app.connectors.ollama_connector import OllamaConnector
from app.connectors.openai_connector import OpenAIConnector
from app.redteam.model_connectors import (
    SUPPORTED_PROVIDERS,
    ConnectorSpec,
    build_model_connector,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "provider,expected",
    [
        ("openai", OpenAIConnector),
        ("anthropic", AnthropicConnector),
        ("ollama", OllamaConnector),
        ("bedrock", BedrockConnector),
    ],
)
def test_dispatches_to_concrete_adapter(provider, expected):
    conn = build_model_connector(ConnectorSpec(provider=provider, model="m", api_key_ref="env:KEY"))
    assert isinstance(conn, expected)


def test_provider_is_case_insensitive():
    assert isinstance(
        build_model_connector(
            ConnectorSpec(provider="OpenAI", model="gpt-4o", api_key_ref="env:K")
        ),
        OpenAIConnector,
    )


def test_azure_requires_endpoint():
    with pytest.raises(ConnectorConfigError):
        build_model_connector(ConnectorSpec(provider="azure_openai", model="m"))


def test_azure_builds_with_endpoint():
    from app.connectors.azure_openai_connector import AzureOpenAIConnector

    conn = build_model_connector(
        ConnectorSpec(
            provider="azure_openai",
            model="dep",
            api_key_ref="env:K",
            config={"endpoint": "https://x.openai.azure.com"},
        )
    )
    assert isinstance(conn, AzureOpenAIConnector)


def test_custom_requires_base_url():
    with pytest.raises(ConnectorConfigError):
        build_model_connector(ConnectorSpec(provider="custom", model="m"))


def test_custom_builds_with_base_url():
    conn = build_model_connector(
        ConnectorSpec(provider="custom", model="m", config={"base_url": "https://api.x"})
    )
    assert isinstance(conn, GenericOpenAIConnector)


def test_unsupported_provider_raises():
    with pytest.raises(ConnectorConfigError):
        build_model_connector(ConnectorSpec(provider="cohere", model="m"))


def test_supported_providers_all_build():
    # every advertised provider builds (with its required extras supplied)
    extras = {
        "azure_openai": {"endpoint": "https://x.openai.azure.com"},
        "custom": {"base_url": "https://api.x"},
    }
    for provider in SUPPORTED_PROVIDERS:
        build_model_connector(
            ConnectorSpec(
                provider=provider,
                model="m",
                api_key_ref="env:K",
                config=extras.get(provider, {}),
            )
        )
