"""Generic OpenAI-compatible connector.

Many self-hosted inference servers (vLLM, LM Studio, TGI, Together's
proxy, Fireworks proxy, OpenRouter, LiteLLM proxy) expose the OpenAI
``/v1/chat/completions`` API at a custom base URL with a custom API key.
This connector is a tiny subclass of OpenAIConnector — everything is
identical except the base URL and (for some hosts) the absence of a
real model-pricing entry.

Cost: defaults to zero unless ``cost_input_per_million`` and
``cost_output_per_million`` are explicitly configured. Self-hosted
inference is genuinely free at the API surface (you're paying for
hardware separately); SaaS proxies (OpenRouter, Together) carry per-
model rates that vary by route. Operators who care about cost tracking
on a proxy should set the rates in ``ConnectorConfig.config``.
"""

from __future__ import annotations

from typing import Any

from app.connectors.base import (
    ConnectorConfigError,
    ConnectorResponse,
    CostRate,
)
from app.connectors.openai_connector import OpenAIConnector


class GenericOpenAIConnector(OpenAIConnector):
    """OpenAI-wire-compatible adapter for any custom endpoint.

    Required config:
      base_url:   the OpenAI-compatible endpoint (e.g.
                  ``https://api.openrouter.ai/api/v1`` or
                  ``http://localhost:8000/v1`` for vLLM)
      model:      model identifier the endpoint understands

    Optional config:
      api_key_ref:                may be empty for unauthenticated local
                                  servers; required for proxies
      cost_input_per_million:     override pricing
      cost_output_per_million:    override pricing
    """

    provider = "custom"

    def __init__(
        self,
        *,
        api_key_ref: str,
        model: str,
        base_url: str,
        cost_input_per_million: float = 0.0,
        cost_output_per_million: float = 0.0,
        timeout_s: float = 60.0,
        max_retries: int = 3,
    ) -> None:
        if not base_url:
            raise ConnectorConfigError("base_url is required")
        # OpenAIConnector requires a non-empty api_key_ref; pass a sentinel
        # for unauthenticated endpoints (the resolver will return "").
        super().__init__(
            api_key_ref=api_key_ref or "env:_GENERIC_NO_AUTH_SENTINEL",
            model=model,
            base_url=base_url,
            timeout_s=timeout_s,
            max_retries=max_retries,
        )
        self._fixed_rate = CostRate(
            input_per_million=cost_input_per_million,
            output_per_million=cost_output_per_million,
        )

    async def _resolved_api_key(self) -> str:
        """Allow empty API keys for unauthenticated local endpoints."""
        if self._api_key_ref == "env:_GENERIC_NO_AUTH_SENTINEL":
            return ""
        return await super()._resolved_api_key()

    def _build_headers(self, api_key: str) -> dict[str, str]:
        """Skip the Authorization header when there's no real key."""
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        return headers

    def _parse_response(
        self, data: dict[str, Any], *, latency_ms: int
    ) -> ConnectorResponse:
        """Override cost calculation to use the per-config fixed rate."""
        from app.connectors.base import calculate_cost

        # Reuse parent's text + tool-call extraction by delegating then
        # rewriting the cost. Cheaper than duplicating the whole parse.
        base = super()._parse_response(data, latency_ms=latency_ms)
        cost = calculate_cost(
            input_tokens=base.input_tokens,
            output_tokens=base.output_tokens,
            rate=self._fixed_rate,
        )
        return ConnectorResponse(
            text=base.text,
            model=base.model,
            input_tokens=base.input_tokens,
            output_tokens=base.output_tokens,
            latency_ms=base.latency_ms,
            cost_usd=cost,
            tool_calls=base.tool_calls,
            raw_response=base.raw_response,
        )
