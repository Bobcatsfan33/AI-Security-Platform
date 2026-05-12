"""Connector registry — load and instantiate :class:`ModelConnector`s
from persisted :class:`ConnectorConfig` rows.

The registry is a thin factory layer. It does NOT cache connectors
across requests because the secret backend's resolution is itself cached
(see :mod:`app.security.secrets`); rebuilding the connector object is
cheap. Caching connectors would complicate rotation: when an admin
updates the api_key_ref, the cached connector instance would still hold
the old plaintext.
"""

from __future__ import annotations

from typing import Any

from app.connectors.anthropic_connector import AnthropicConnector
from app.connectors.azure_openai_connector import AzureOpenAIConnector
from app.connectors.base import ConnectorConfigError, ModelConnector
from app.connectors.bedrock_connector import BedrockConnector
from app.connectors.generic_openai_connector import GenericOpenAIConnector
from app.connectors.ollama_connector import OllamaConnector
from app.connectors.openai_connector import OpenAIConnector
from app.db.models.connector_config import ConnectorConfig


def build_connector(row: ConnectorConfig) -> ModelConnector:
    """Build a concrete connector for one persisted config row.

    The row's ``config`` JSONB carries provider-specific extras (base_url,
    endpoint, deployment_name, api_version). Each adapter knows which
    keys it cares about; everything else is ignored.
    """
    provider = (row.provider or "").lower()
    config: dict[str, Any] = dict(row.config or {})

    if provider == "openai":
        return OpenAIConnector(
            api_key_ref=row.api_key_ref,
            model=row.model,
            base_url=config.get("base_url"),
            organization=config.get("organization"),
            timeout_s=float(config.get("timeout_s", 60.0)),
            max_retries=int(config.get("max_retries", 3)),
        )

    if provider == "anthropic":
        return AnthropicConnector(
            api_key_ref=row.api_key_ref,
            model=row.model,
            base_url=config.get("base_url"),
            api_version=config.get("api_version", "2023-06-01"),
            timeout_s=float(config.get("timeout_s", 60.0)),
            max_retries=int(config.get("max_retries", 3)),
        )

    if provider == "ollama":
        return OllamaConnector(
            model=row.model,
            base_url=config.get("base_url"),
            timeout_s=float(config.get("timeout_s", 120.0)),
            max_retries=int(config.get("max_retries", 1)),
        )

    if provider == "azure_openai":
        endpoint = config.get("endpoint")
        deployment_name = config.get("deployment_name") or row.model
        if not endpoint:
            raise ConnectorConfigError("azure_openai requires config.endpoint")
        return AzureOpenAIConnector(
            endpoint=endpoint,
            deployment_name=deployment_name,
            api_key_ref=row.api_key_ref,
            api_version=config.get("api_version", "2024-08-01-preview"),
            model_for_pricing=config.get("model_for_pricing"),
            timeout_s=float(config.get("timeout_s", 60.0)),
            max_retries=int(config.get("max_retries", 3)),
        )

    if provider == "bedrock":
        return BedrockConnector(
            model=row.model,
            region=config.get("region", "us-east-1"),
            api_key_ref=row.api_key_ref,
            timeout_s=float(config.get("timeout_s", 60.0)),
            max_retries=int(config.get("max_retries", 3)),
        )

    if provider == "custom":
        base_url = config.get("base_url")
        if not base_url:
            raise ConnectorConfigError("custom provider requires config.base_url")
        return GenericOpenAIConnector(
            api_key_ref=row.api_key_ref,
            model=row.model,
            base_url=base_url,
            cost_input_per_million=float(
                config.get("cost_input_per_million", 0.0)
            ),
            cost_output_per_million=float(
                config.get("cost_output_per_million", 0.0)
            ),
            timeout_s=float(config.get("timeout_s", 60.0)),
            max_retries=int(config.get("max_retries", 3)),
        )

    raise ConnectorConfigError(
        f"unsupported provider {provider!r} — supported: "
        "openai, anthropic, ollama, azure_openai, bedrock, custom"
    )


SUPPORTED_PROVIDERS: tuple[str, ...] = (
    "openai",
    "anthropic",
    "ollama",
    "azure_openai",
    "bedrock",
    "custom",
)
