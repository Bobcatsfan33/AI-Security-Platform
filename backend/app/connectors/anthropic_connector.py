"""Anthropic connector — Messages API + tool use + cost tracking.

Wire shape differs from OpenAI in three meaningful ways:
1. ``system`` is a top-level field, not a role in messages
2. Message content is structured: ``[{"type": "text", "text": "..."}]`` or
   ``[{"type": "tool_use", "id": ..., "name": ..., "input": {...}}]``
3. Tool use responses come back as ``tool_use`` content blocks alongside
   text; the model can request multiple tools per turn

Cost rates from https://docs.anthropic.com/en/docs/about-claude/pricing
last refreshed 2026-04. Updated alongside OPENAI_COST_RATES.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from typing import Any

import httpx

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

logger = logging.getLogger("platform.connectors.anthropic")

DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
DEFAULT_API_VERSION = "2023-06-01"
DEFAULT_TIMEOUT_S = 60.0
DEFAULT_MAX_RETRIES = 3


ANTHROPIC_COST_RATES: dict[str, CostRate] = {
    "claude-opus-4": CostRate(input_per_million=15.00, output_per_million=75.00),
    "claude-sonnet-4": CostRate(input_per_million=3.00, output_per_million=15.00),
    "claude-haiku-4": CostRate(input_per_million=0.80, output_per_million=4.00),
    # Legacy 3.x family — kept for evaluation runs against older models
    "claude-3-5-sonnet": CostRate(input_per_million=3.00, output_per_million=15.00),
    "claude-3-5-haiku": CostRate(input_per_million=1.00, output_per_million=5.00),
    "claude-3-opus": CostRate(input_per_million=15.00, output_per_million=75.00),
    "claude-3-sonnet": CostRate(input_per_million=3.00, output_per_million=15.00),
    "claude-3-haiku": CostRate(input_per_million=0.25, output_per_million=1.25),
}


def _resolve_rate(model: str) -> CostRate:
    if model in ANTHROPIC_COST_RATES:
        return ANTHROPIC_COST_RATES[model]
    for key in sorted(ANTHROPIC_COST_RATES.keys(), key=len, reverse=True):
        if model.startswith(key):
            return ANTHROPIC_COST_RATES[key]
    logger.warning("anthropic_unknown_model_pricing", extra={"model": model})
    return CostRate(input_per_million=0.0, output_per_million=0.0)


class AnthropicConnector:
    """Concrete adapter for Anthropic Messages API."""

    provider = "anthropic"

    def __init__(
        self,
        *,
        api_key_ref: str,
        model: str,
        base_url: str | None = None,
        api_version: str = DEFAULT_API_VERSION,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        if not api_key_ref:
            raise ConnectorConfigError("api_key_ref is required")
        if not model:
            raise ConnectorConfigError("model is required")
        self._api_key_ref = api_key_ref
        self.model = model
        self._base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self._api_version = api_version
        self._timeout_s = timeout_s
        self._max_retries = max(0, max_retries)
        self._api_key: str | None = None

    # ─────────────────────────────────────────── public API

    async def generate(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> ConnectorResponse:
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            body["system"] = system_prompt
        return await self._messages_call(body)

    async def generate_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        system_prompt: str | None = None,
    ) -> ConnectorResponse:
        # Anthropic's tool schema is {"name", "description", "input_schema"}.
        # Most callers will already be in OpenAI shape ({"type": "function",
        # "function": {"name", "parameters"}}). Translate.
        anthropic_tools = [
            self._translate_tool(t) for t in tools
        ]
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": list(messages),
            "tools": anthropic_tools,
        }
        if system_prompt:
            body["system"] = system_prompt
        return await self._messages_call(body)

    async def health_check(self) -> bool:
        """Make a tiny single-token completion to verify credentials.
        Anthropic doesn't expose a list-models endpoint; this is the
        cheapest reliable round-trip."""
        api_key = await self._resolved_api_key()
        body = {
            "model": self.model,
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "x"}],
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{self._base_url}/messages",
                headers=self._build_headers(api_key),
                content=json.dumps(body),
            )
        if resp.status_code == 200:
            return True
        if resp.status_code == 401:
            raise ConnectorAuthError("anthropic_health_check_unauthorized")
        raise ConnectorError(
            f"anthropic_health_check_failed: status={resp.status_code}"
        )

    # ─────────────────────────────────────────── internals

    async def _resolved_api_key(self) -> str:
        if self._api_key is None:
            try:
                self._api_key = get_resolver().resolve(self._api_key_ref)
            except SecretResolutionError as exc:
                raise ConnectorConfigError(
                    f"could not resolve api_key_ref={self._api_key_ref!r}: {exc}"
                ) from exc
        return self._api_key

    def _build_headers(self, api_key: str) -> dict[str, str]:
        return {
            "x-api-key": api_key,
            "anthropic-version": self._api_version,
            "content-type": "application/json",
        }

    @staticmethod
    def _translate_tool(tool: dict[str, Any]) -> dict[str, Any]:
        """Accept either OpenAI-shaped or Anthropic-shaped tools and return
        an Anthropic-shaped one."""
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

    async def _messages_call(self, body: dict[str, Any]) -> ConnectorResponse:
        api_key = await self._resolved_api_key()
        url = f"{self._base_url}/messages"
        attempt = 0

        while True:
            attempt += 1
            with LatencyTimer() as timer:
                try:
                    async with httpx.AsyncClient(timeout=self._timeout_s) as client:
                        resp = await client.post(
                            url,
                            headers=self._build_headers(api_key),
                            content=json.dumps(body),
                        )
                except httpx.TimeoutException as exc:
                    if attempt > self._max_retries:
                        raise ConnectorTransientError(
                            f"anthropic_timeout after {attempt} attempts"
                        ) from exc
                    await self._backoff(attempt)
                    continue
                except httpx.RequestError as exc:
                    if attempt > self._max_retries:
                        raise ConnectorTransientError(
                            f"anthropic_request_error: {exc}"
                        ) from exc
                    await self._backoff(attempt)
                    continue

            if resp.status_code == 200:
                return self._parse_response(resp.json(), latency_ms=timer.elapsed_ms)

            if resp.status_code == 401:
                raise ConnectorAuthError("anthropic_unauthorized")
            if resp.status_code == 429:
                if attempt > self._max_retries:
                    raise ConnectorRateLimitError(
                        "anthropic_rate_limited",
                        retry_after_s=self._parse_retry_after(resp),
                    )
                await self._backoff(attempt, retry_after=self._parse_retry_after(resp))
                continue
            if 500 <= resp.status_code < 600:
                if attempt > self._max_retries:
                    raise ConnectorTransientError(
                        f"anthropic_server_error status={resp.status_code}"
                    )
                await self._backoff(attempt)
                continue

            raise ConnectorError(
                f"anthropic_request_failed status={resp.status_code} "
                f"body={resp.text[:500]}"
            )

    @staticmethod
    def _parse_retry_after(resp: httpx.Response) -> float | None:
        ra = resp.headers.get("retry-after")
        if not ra:
            return None
        try:
            return float(ra)
        except ValueError:
            return None

    async def _backoff(
        self, attempt: int, *, retry_after: float | None = None
    ) -> None:
        if retry_after is not None:
            delay = retry_after
        else:
            base = min(2 ** (attempt - 1), 30.0)
            delay = base + random.uniform(0, base * 0.25)
        logger.info(
            "anthropic_retry_backoff",
            extra={"attempt": attempt, "delay_s": round(delay, 2)},
        )
        await asyncio.sleep(delay)

    def _parse_response(
        self, data: dict[str, Any], *, latency_ms: int
    ) -> ConnectorResponse:
        # content is an array of typed blocks. Concatenate text blocks; tool_use
        # blocks become ToolCalls.
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in data.get("content") or []:
            btype = block.get("type")
            if btype == "text":
                text_parts.append(block.get("text", ""))
            elif btype == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block.get("id", ""),
                        name=block.get("name", ""),
                        arguments=block.get("input") or {},
                    )
                )

        usage = data.get("usage") or {}
        input_tokens = int(usage.get("input_tokens", 0))
        output_tokens = int(usage.get("output_tokens", 0))
        model = data.get("model", self.model)
        cost = calculate_cost(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            rate=_resolve_rate(model),
        )

        return ConnectorResponse(
            text="".join(text_parts),
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            cost_usd=cost,
            tool_calls=tuple(tool_calls),
            raw_response=data,
        )
