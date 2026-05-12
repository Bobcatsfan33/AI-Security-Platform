"""Azure OpenAI connector.

Azure's flavor of the OpenAI API uses a different URL shape and a
different auth header but the request/response bodies are identical to
the OpenAI Chat Completions API. Rather than duplicate all of
:mod:`app.connectors.openai_connector`, we subclass and override the
URL construction + auth header.

URL format:
    {endpoint}/openai/deployments/{deployment_name}/chat/completions
    ?api-version={api_version}

Cost tracking: Azure publishes its own pricing (often slightly different
from OpenAI's published rates) but most customers pay-as-you-go at the
same per-token rates. We default to the OpenAI cost table; operators
who negotiate enterprise rates can override at the connector_config
level (Sprint 11 — UI for cost-rate overrides).
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
    LatencyTimer,
    ToolCall,
    calculate_cost,
)
from app.connectors.openai_connector import _resolve_rate, _safe_json_loads
from app.security.secrets import SecretResolutionError, get_resolver

logger = logging.getLogger("platform.connectors.azure_openai")

DEFAULT_API_VERSION = "2024-08-01-preview"
DEFAULT_TIMEOUT_S = 60.0
DEFAULT_MAX_RETRIES = 3


class AzureOpenAIConnector:
    """Azure OpenAI Service adapter.

    Required config:
        endpoint          — https://<resource>.openai.azure.com
        deployment_name   — the Azure deployment alias (not the model name)
        api_key_ref       — secrets reference (env: / awssm: / vault: / enc:)

    Optional:
        api_version       — Azure REST API version (default
                            ``2024-08-01-preview``)
        model_for_pricing — OpenAI model name used to look up cost rates
                            (e.g. ``gpt-4o``). Defaults to ``deployment_name``;
                            override when your deployment alias doesn't
                            match a known model.
    """

    provider = "azure_openai"

    def __init__(
        self,
        *,
        endpoint: str,
        deployment_name: str,
        api_key_ref: str,
        api_version: str = DEFAULT_API_VERSION,
        model_for_pricing: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        if not endpoint:
            raise ConnectorConfigError("endpoint is required")
        if not deployment_name:
            raise ConnectorConfigError("deployment_name is required")
        if not api_key_ref:
            raise ConnectorConfigError("api_key_ref is required")
        self._endpoint = endpoint.rstrip("/")
        self.deployment_name = deployment_name
        self.model = deployment_name  # for the ConnectorResponse.model field
        self._api_key_ref = api_key_ref
        self._api_version = api_version
        self._model_for_pricing = model_for_pricing or deployment_name
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
        messages: list[dict[str, Any]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        body = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        return await self._chat_completion(body)

    async def generate_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        system_prompt: str | None = None,
    ) -> ConnectorResponse:
        all_messages = list(messages)
        if system_prompt and not any(m.get("role") == "system" for m in all_messages):
            all_messages.insert(0, {"role": "system", "content": system_prompt})
        body: dict[str, Any] = {"messages": all_messages}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        return await self._chat_completion(body)

    async def health_check(self) -> bool:
        """Trivial 1-token completion. Azure has no /models equivalent
        scoped to deployments, so we round-trip the chat endpoint."""
        api_key = await self._resolved_api_key()
        url = self._chat_url()
        body = {
            "messages": [{"role": "user", "content": "x"}],
            "max_tokens": 1,
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                headers=self._build_headers(api_key),
                content=json.dumps(body),
            )
        if resp.status_code == 200:
            return True
        if resp.status_code == 401:
            raise ConnectorAuthError("azure_openai_health_check_unauthorized")
        raise ConnectorError(
            f"azure_openai_health_check_failed: status={resp.status_code}"
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
            "api-key": api_key,
            "content-type": "application/json",
        }

    def _chat_url(self) -> str:
        return (
            f"{self._endpoint}/openai/deployments/{self.deployment_name}"
            f"/chat/completions?api-version={self._api_version}"
        )

    async def _chat_completion(self, body: dict[str, Any]) -> ConnectorResponse:
        api_key = await self._resolved_api_key()
        url = self._chat_url()
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
                            f"azure_openai_timeout after {attempt} attempts"
                        ) from exc
                    await self._backoff(attempt)
                    continue
                except httpx.RequestError as exc:
                    if attempt > self._max_retries:
                        raise ConnectorTransientError(
                            f"azure_openai_request_error: {exc}"
                        ) from exc
                    await self._backoff(attempt)
                    continue

            if resp.status_code == 200:
                return self._parse_response(resp.json(), latency_ms=timer.elapsed_ms)
            if resp.status_code == 401:
                raise ConnectorAuthError("azure_openai_unauthorized")
            if resp.status_code == 429:
                if attempt > self._max_retries:
                    raise ConnectorRateLimitError(
                        "azure_openai_rate_limited",
                        retry_after_s=self._parse_retry_after(resp),
                    )
                await self._backoff(attempt, retry_after=self._parse_retry_after(resp))
                continue
            if 500 <= resp.status_code < 600:
                if attempt > self._max_retries:
                    raise ConnectorTransientError(
                        f"azure_openai_server_error status={resp.status_code}"
                    )
                await self._backoff(attempt)
                continue
            raise ConnectorError(
                f"azure_openai_request_failed status={resp.status_code} "
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
            "azure_openai_retry_backoff",
            extra={"attempt": attempt, "delay_s": round(delay, 2)},
        )
        await asyncio.sleep(delay)

    def _parse_response(
        self, data: dict[str, Any], *, latency_ms: int
    ) -> ConnectorResponse:
        choices = data.get("choices") or []
        if not choices:
            raise ConnectorError("azure_openai_response_missing_choices")
        message = choices[0].get("message") or {}
        text = message.get("content") or ""
        tool_calls_raw = message.get("tool_calls") or []
        tool_calls = tuple(
            ToolCall(
                id=tc.get("id", ""),
                name=(tc.get("function") or {}).get("name", ""),
                arguments=_safe_json_loads(
                    (tc.get("function") or {}).get("arguments", "{}")
                ),
            )
            for tc in tool_calls_raw
        )
        usage = data.get("usage") or {}
        input_tokens = int(usage.get("prompt_tokens", 0))
        output_tokens = int(usage.get("completion_tokens", 0))
        cost = calculate_cost(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            rate=_resolve_rate(self._model_for_pricing),
        )
        return ConnectorResponse(
            text=text,
            model=self.deployment_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            cost_usd=cost,
            tool_calls=tool_calls,
            raw_response=data,
        )
