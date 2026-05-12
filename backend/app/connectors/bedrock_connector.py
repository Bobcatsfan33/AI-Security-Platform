"""Amazon Bedrock connector — InvokeModel via boto3.

Bedrock wraps multiple model families behind one API. The wire shape
varies by family:

  - Anthropic Claude on Bedrock: same body as Anthropic native, served
    at ``anthropic.claude-*`` model IDs
  - Meta Llama: ``{"prompt", "max_gen_len", "temperature", "top_p"}``
  - Amazon Titan: ``{"inputText", "textGenerationConfig": {...}}``
  - Mistral: ``{"prompt", "max_tokens", "temperature"}``
  - Cohere: ``{"message", ...}``

Sprint 4-relevant subset: Anthropic Claude (overwhelmingly dominant on
Bedrock for evaluation work) and Meta Llama. Other families are
deferred to a follow-on chunk — the dispatch shape here is designed to
accept new families by adding a single ``_format_*`` /
``_parse_*_response`` pair.

Auth: boto3 picks up credentials via the standard chain (env vars,
shared credentials, IAM role). The connector accepts an optional
``api_key_ref`` that resolves to either:
  - ``AWS_ACCESS_KEY_ID:SECRET:SESSION_TOKEN`` (rare in production)
  - an empty value (boto3 uses default chain; most common)

Cost: Bedrock publishes per-model rates that differ from native
provider rates. We track AWS-specific rates here rather than reusing
the OpenAI/Anthropic tables.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.connectors.base import (
    ConnectorAuthError,
    ConnectorConfigError,
    ConnectorError,
    ConnectorRateLimitError,
    ConnectorResponse,
    ConnectorTransientError,
    CostRate,
    LatencyTimer,
    ToolCall,
    calculate_cost,
)
from app.security.secrets import SecretResolutionError, get_resolver

logger = logging.getLogger("platform.connectors.bedrock")

DEFAULT_REGION = "us-east-1"
DEFAULT_TIMEOUT_S = 60.0


# Bedrock-specific cost rates (USD per million tokens, as of 2026-04).
BEDROCK_COST_RATES: dict[str, CostRate] = {
    "anthropic.claude-opus-4": CostRate(15.00, 75.00),
    "anthropic.claude-sonnet-4": CostRate(3.00, 15.00),
    "anthropic.claude-haiku-4": CostRate(0.80, 4.00),
    "anthropic.claude-3-5-sonnet": CostRate(3.00, 15.00),
    "anthropic.claude-3-5-haiku": CostRate(1.00, 5.00),
    "anthropic.claude-3-opus": CostRate(15.00, 75.00),
    "anthropic.claude-3-sonnet": CostRate(3.00, 15.00),
    "anthropic.claude-3-haiku": CostRate(0.25, 1.25),
    "meta.llama3-70b": CostRate(2.65, 3.50),
    "meta.llama3-8b": CostRate(0.30, 0.60),
    "meta.llama3-1-70b": CostRate(2.65, 3.50),
    "meta.llama3-1-8b": CostRate(0.22, 0.22),
}


def _resolve_rate(model_id: str) -> CostRate:
    if model_id in BEDROCK_COST_RATES:
        return BEDROCK_COST_RATES[model_id]
    # Bedrock IDs commonly carry a version suffix like
    # "anthropic.claude-sonnet-4-20251001-v2:0" — strip the version
    # and try the longest-prefix match
    for key in sorted(BEDROCK_COST_RATES.keys(), key=len, reverse=True):
        if model_id.startswith(key):
            return BEDROCK_COST_RATES[key]
    logger.warning("bedrock_unknown_model_pricing", extra={"model": model_id})
    return CostRate(0.0, 0.0)


def _family_of(model_id: str) -> str:
    """Return the wire-shape family for a Bedrock model ID."""
    if model_id.startswith("anthropic."):
        return "anthropic"
    if model_id.startswith("meta."):
        return "meta"
    if model_id.startswith("amazon.titan"):
        return "titan"
    if model_id.startswith("mistral."):
        return "mistral"
    if model_id.startswith("cohere."):
        return "cohere"
    return "unknown"


class BedrockConnector:
    """Bedrock InvokeModel adapter.

    Config fields (passed through ConnectorConfig.config JSONB):
      region:         AWS region (default us-east-1)
      max_tokens:     default max_tokens for generate()
      temperature:    default temperature for generate()
    """

    provider = "bedrock"

    def __init__(
        self,
        *,
        model: str,
        region: str = DEFAULT_REGION,
        api_key_ref: str = "",
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_retries: int = 3,
    ) -> None:
        if not model:
            raise ConnectorConfigError("model is required")
        self.model = model
        self.region = region
        self._api_key_ref = api_key_ref
        self._timeout_s = timeout_s
        self._max_retries = max(0, max_retries)
        self._client: Any = None
        self._family = _family_of(model)

    # ─────────────────────────────────────────── public API

    async def generate(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> ConnectorResponse:
        body = self._format_body(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            messages=None,
        )
        return await self._invoke(body)

    async def generate_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        system_prompt: str | None = None,
    ) -> ConnectorResponse:
        if self._family != "anthropic":
            raise ConnectorError(
                f"tool calling on Bedrock is only supported via Anthropic "
                f"family models; got family {self._family!r}"
            )
        # Reuse the anthropic body shape with tools
        body: dict[str, Any] = {
            "anthropic_version": "bedrock-2023-05-31",
            "messages": list(messages),
            "max_tokens": 1024,
        }
        if system_prompt:
            body["system"] = system_prompt
        if tools:
            body["tools"] = [self._translate_anthropic_tool(t) for t in tools]
        return await self._invoke(body)

    async def health_check(self) -> bool:
        """List foundation models in the region. Cheap; doesn't burn an
        InvokeModel call."""
        import asyncio

        client = await self._get_client(service="bedrock")
        try:
            await asyncio.to_thread(client.list_foundation_models)
        except Exception as exc:  # noqa: BLE001
            if "credentials" in str(exc).lower() or "AccessDenied" in str(exc):
                raise ConnectorAuthError(f"bedrock_unauthorized: {exc}") from exc
            raise ConnectorError(f"bedrock_health_check_failed: {exc}") from exc
        return True

    # ─────────────────────────────────────────── internals

    async def _get_client(self, *, service: str = "bedrock-runtime") -> Any:
        """Lazy boto3 client. Resolved on first use so import-time failures
        don't break the registry."""
        import asyncio

        try:
            import boto3  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ConnectorConfigError("boto3 required for BedrockConnector") from exc

        kwargs: dict[str, Any] = {"region_name": self.region}
        # If the operator stuffed credentials in the secrets ref, parse them.
        # Format: "access_key:secret:session_token" (session_token optional).
        if self._api_key_ref:
            try:
                resolved = get_resolver().resolve(self._api_key_ref)
                parts = resolved.split(":")
                if len(parts) >= 2:
                    kwargs["aws_access_key_id"] = parts[0]
                    kwargs["aws_secret_access_key"] = parts[1]
                    if len(parts) >= 3:
                        kwargs["aws_session_token"] = parts[2]
            except SecretResolutionError as exc:
                raise ConnectorConfigError(
                    f"could not resolve api_key_ref={self._api_key_ref!r}: {exc}"
                ) from exc

        return await asyncio.to_thread(boto3.client, service, **kwargs)

    def _format_body(
        self,
        *,
        prompt: str,
        system_prompt: str | None,
        temperature: float,
        max_tokens: int,
        messages: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        if self._family == "anthropic":
            body: dict[str, Any] = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": (
                    messages
                    if messages is not None
                    else [{"role": "user", "content": prompt}]
                ),
            }
            if system_prompt:
                body["system"] = system_prompt
            return body

        if self._family == "meta":
            # Llama family on Bedrock uses a simple completion shape
            full_prompt = prompt
            if system_prompt:
                full_prompt = f"<|system|>{system_prompt}\n<|user|>{prompt}"
            return {
                "prompt": full_prompt,
                "max_gen_len": max_tokens,
                "temperature": temperature,
                "top_p": 0.9,
            }

        raise ConnectorError(
            f"unsupported Bedrock model family {self._family!r} "
            f"(supported: anthropic, meta)"
        )

    async def _invoke(self, body: dict[str, Any]) -> ConnectorResponse:
        import asyncio

        client = await self._get_client()
        with LatencyTimer() as timer:
            try:
                response = await asyncio.to_thread(
                    client.invoke_model,
                    modelId=self.model,
                    body=json.dumps(body),
                    contentType="application/json",
                    accept="application/json",
                )
            except Exception as exc:  # noqa: BLE001
                msg = str(exc)
                if "Throttling" in msg or "TooManyRequests" in msg:
                    raise ConnectorRateLimitError(f"bedrock_rate_limited: {exc}") from exc
                if "AccessDenied" in msg or "UnauthorizedOperation" in msg:
                    raise ConnectorAuthError(f"bedrock_unauthorized: {exc}") from exc
                if "ServiceUnavailable" in msg or "InternalServer" in msg:
                    raise ConnectorTransientError(f"bedrock_transient: {exc}") from exc
                raise ConnectorError(f"bedrock_invoke_failed: {exc}") from exc

        raw_bytes = response["body"].read()
        data = json.loads(raw_bytes)
        return self._parse_response(data, latency_ms=timer.elapsed_ms)

    def _parse_response(
        self, data: dict[str, Any], *, latency_ms: int
    ) -> ConnectorResponse:
        if self._family == "anthropic":
            return self._parse_anthropic(data, latency_ms=latency_ms)
        if self._family == "meta":
            return self._parse_meta(data, latency_ms=latency_ms)
        raise ConnectorError(f"unsupported response family {self._family!r}")

    def _parse_anthropic(
        self, data: dict[str, Any], *, latency_ms: int
    ) -> ConnectorResponse:
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in data.get("content") or []:
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block.get("id", ""),
                        name=block.get("name", ""),
                        arguments=block.get("input") or {},
                    )
                )
        usage = data.get("usage") or {}
        in_tokens = int(usage.get("input_tokens", 0))
        out_tokens = int(usage.get("output_tokens", 0))
        cost = calculate_cost(
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            rate=_resolve_rate(self.model),
        )
        return ConnectorResponse(
            text="".join(text_parts),
            model=self.model,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            latency_ms=latency_ms,
            cost_usd=cost,
            tool_calls=tuple(tool_calls),
            raw_response=data,
        )

    def _parse_meta(
        self, data: dict[str, Any], *, latency_ms: int
    ) -> ConnectorResponse:
        text = str(data.get("generation") or "")
        # Llama on Bedrock returns prompt_token_count + generation_token_count
        in_tokens = int(data.get("prompt_token_count", 0))
        out_tokens = int(data.get("generation_token_count", 0))
        cost = calculate_cost(
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            rate=_resolve_rate(self.model),
        )
        return ConnectorResponse(
            text=text,
            model=self.model,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            latency_ms=latency_ms,
            cost_usd=cost,
            tool_calls=(),
            raw_response=data,
        )

    @staticmethod
    def _translate_anthropic_tool(tool: dict[str, Any]) -> dict[str, Any]:
        """Accept either OpenAI-shaped or Anthropic-shaped tools."""
        if "input_schema" in tool:
            return dict(tool)
        fn = tool.get("function") or {}
        return {
            "name": fn.get("name") or tool.get("name", ""),
            "description": fn.get("description") or tool.get("description", ""),
            "input_schema": fn.get("parameters") or tool.get("input_schema") or {
                "type": "object",
                "properties": {},
            },
        }
