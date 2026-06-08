"""Build a :class:`ModelConnector` from an inline spec — the v2 replacement
for the dropped ``app.connectors.registry.build_connector``.

The v1 registry took a persisted ``ConnectorConfig`` ORM row (a table the v2
pivot dropped). Red Teaming doesn't need that table back: a campaign request
carries the target/generator/judge model spec inline (provider + model +
api_key_ref + provider extras), and this factory builds the concrete adapter.
The adapters themselves (OpenAI/Anthropic/Ollama/Azure/Bedrock/custom) are
unchanged and import-clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.connectors.anthropic_connector import AnthropicConnector
from app.connectors.azure_openai_connector import AzureOpenAIConnector
from app.connectors.base import ConnectorConfigError, ModelConnector
from app.connectors.bedrock_connector import BedrockConnector
from app.connectors.generic_openai_connector import GenericOpenAIConnector
from app.connectors.ollama_connector import OllamaConnector
from app.connectors.openai_connector import OpenAIConnector

SUPPORTED_PROVIDERS: tuple[str, ...] = (
    "openai",
    "anthropic",
    "ollama",
    "azure_openai",
    "bedrock",
    "custom",
)


@dataclass(frozen=True)
class ConnectorSpec:
    """Inline description of a model to drive. ``api_key_ref`` is a reference
    (``env:NAME`` / ``vault:path``), never a raw secret; ``config`` carries
    provider extras (base_url, endpoint, deployment_name, region, …)."""

    provider: str
    model: str
    api_key_ref: str = ""
    config: dict[str, Any] = field(default_factory=dict)


def build_model_connector(spec: ConnectorSpec) -> ModelConnector:
    """Build a concrete :class:`ModelConnector` from an inline spec.

    Raises :class:`ConnectorConfigError` for an unsupported provider or a
    provider that's missing a required extra (e.g. azure_openai needs
    ``config.endpoint``).
    """
    provider = (spec.provider or "").lower()
    config = dict(spec.config or {})

    if provider == "openai":
        return OpenAIConnector(
            api_key_ref=spec.api_key_ref,
            model=spec.model,
            base_url=config.get("base_url"),
            organization=config.get("organization"),
            timeout_s=float(config.get("timeout_s", 60.0)),
            max_retries=int(config.get("max_retries", 3)),
        )
    if provider == "anthropic":
        return AnthropicConnector(
            api_key_ref=spec.api_key_ref,
            model=spec.model,
            base_url=config.get("base_url"),
            api_version=config.get("api_version", "2023-06-01"),
            timeout_s=float(config.get("timeout_s", 60.0)),
            max_retries=int(config.get("max_retries", 3)),
        )
    if provider == "ollama":
        return OllamaConnector(
            model=spec.model,
            base_url=config.get("base_url"),
            timeout_s=float(config.get("timeout_s", 120.0)),
            max_retries=int(config.get("max_retries", 1)),
        )
    if provider == "azure_openai":
        endpoint = config.get("endpoint")
        if not endpoint:
            raise ConnectorConfigError("azure_openai requires config.endpoint")
        return AzureOpenAIConnector(
            endpoint=endpoint,
            deployment_name=config.get("deployment_name") or spec.model,
            api_key_ref=spec.api_key_ref,
            api_version=config.get("api_version", "2024-08-01-preview"),
            model_for_pricing=config.get("model_for_pricing"),
            timeout_s=float(config.get("timeout_s", 60.0)),
            max_retries=int(config.get("max_retries", 3)),
        )
    if provider == "bedrock":
        return BedrockConnector(
            model=spec.model,
            region=config.get("region", "us-east-1"),
            api_key_ref=spec.api_key_ref,
            timeout_s=float(config.get("timeout_s", 60.0)),
            max_retries=int(config.get("max_retries", 3)),
        )
    if provider == "custom":
        base_url = config.get("base_url")
        if not base_url:
            raise ConnectorConfigError("custom provider requires config.base_url")
        return GenericOpenAIConnector(
            api_key_ref=spec.api_key_ref,
            model=spec.model,
            base_url=base_url,
            cost_input_per_million=float(config.get("cost_input_per_million", 0.0)),
            cost_output_per_million=float(config.get("cost_output_per_million", 0.0)),
            timeout_s=float(config.get("timeout_s", 60.0)),
            max_retries=int(config.get("max_retries", 3)),
        )

    raise ConnectorConfigError(
        f"unsupported provider {provider!r} — supported: {', '.join(SUPPORTED_PROVIDERS)}"
    )
