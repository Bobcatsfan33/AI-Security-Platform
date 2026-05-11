"""OpenAI connector — chat completions + tool calling + cost tracking.

Implements the :class:`ModelConnector` Protocol. Talks directly to
``https://api.openai.com/v1`` via httpx rather than going through the
official SDK because:

1. We need fine control over retries and timeouts in policy hot paths.
2. The platform's data path is async-first; the official SDK works
   asynchronously but pulls a large dependency surface.
3. The wire shape is stable and well-documented; speaking it directly
   keeps the adapter small and auditable.

Credentials are resolved through the platform's secrets module — the
config holds a reference (``env:OPENAI_API_KEY``) not the plaintext.

Cost tracking
-------------
``OPENAI_COST_RATES`` is the per-model price table in USD per million
tokens. Models not in the table get a zero estimate and a warning log;
this guards against silent under-billing if a customer runs a model we
haven't priced yet. The table should be refreshed against
https://openai.com/api/pricing/ on a regular cadence (Sprint 12).
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

logger = logging.getLogger("platform.connectors.openai")

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_TIMEOUT_S = 60.0
DEFAULT_MAX_RETRIES = 3


# Per-model pricing (USD per million tokens). Last refreshed: 2026-04.
# Snapshot rather than live fetch — the table is small, prices change
# infrequently, and a hardcoded table is auditable.
OPENAI_COST_RATES: dict[str, CostRate] = {
    "gpt-4o": CostRate(input_per_million=2.50, output_per_million=10.00),
    "gpt-4o-mini": CostRate(input_per_million=0.15, output_per_million=0.60),
    "gpt-4-turbo": CostRate(input_per_million=10.00, output_per_million=30.00),
    "gpt-4": CostRate(input_per_million=30.00, output_per_million=60.00),
    "gpt-3.5-turbo": CostRate(input_per_million=0.50, output_per_million=1.50),
    "o1": CostRate(input_per_million=15.00, output_per_million=60.00),
    "o1-mini": CostRate(input_per_million=3.00, output_per_million=12.00),
    "o3": CostRate(input_per_million=10.00, output_per_million=40.00),
}


def _resolve_rate(model: str) -> CostRate:
    """Look up a cost rate, falling back to the closest prefix match.

    Real model IDs include date suffixes (``gpt-4o-2024-08-06``); a
    prefix match against the table base names handles those without
    requiring the table to enumerate every dated snapshot.
    """
    if model in OPENAI_COST_RATES:
        return OPENAI_COST_RATES[model]
    # Sort longer keys first so "gpt-4o-mini" wins over "gpt-4o"
    for key in sorted(OPENAI_COST_RATES.keys(), key=len, reverse=True):
        if model.startswith(key):
            return OPENAI_COST_RATES[key]
    logger.warning("openai_unknown_model_pricing", extra={"model": model})
    return CostRate(input_per_million=0.0, output_per_million=0.0)


# ─────────────────────────────────────────────── Connector


class OpenAIConnector:
    """Concrete adapter for OpenAI's chat-completions API."""

    provider = "openai"

    def __init__(
        self,
        *,
        api_key_ref: str,
        model: str,
        base_url: str | None = None,
        organization: str | None = None,
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
        self._organization = organization
        self._timeout_s = timeout_s
        self._max_retries = max(0, max_retries)
        self._api_key: str | None = None  # resolved lazily

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
            "model": self.model,
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
        # Prepend system prompt if provided AND not already present
        all_messages = list(messages)
        if system_prompt and not any(m.get("role") == "system" for m in all_messages):
            all_messages.insert(0, {"role": "system", "content": system_prompt})

        body: dict[str, Any] = {
            "model": self.model,
            "messages": all_messages,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        return await self._chat_completion(body)

    async def health_check(self) -> bool:
        """Hit /models with the configured key. Returns True on 200, raises
        on auth failure (so the registration endpoint can surface a clear
        error)."""
        api_key = await self._resolved_api_key()
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{self._base_url}/models",
                headers=self._build_headers(api_key),
            )
        if resp.status_code == 200:
            return True
        if resp.status_code == 401:
            raise ConnectorAuthError("openai_health_check_unauthorized")
        raise ConnectorError(
            f"openai_health_check_failed: status={resp.status_code}"
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
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        if self._organization:
            headers["OpenAI-Organization"] = self._organization
        return headers

    async def _chat_completion(self, body: dict[str, Any]) -> ConnectorResponse:
        api_key = await self._resolved_api_key()
        url = f"{self._base_url}/chat/completions"
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
                            f"openai_timeout after {attempt} attempts"
                        ) from exc
                    await self._backoff(attempt)
                    continue
                except httpx.RequestError as exc:
                    if attempt > self._max_retries:
                        raise ConnectorTransientError(
                            f"openai_request_error: {exc}"
                        ) from exc
                    await self._backoff(attempt)
                    continue

            # Status-based error handling
            if resp.status_code == 200:
                return self._parse_response(resp.json(), latency_ms=timer.elapsed_ms)

            if resp.status_code == 401:
                raise ConnectorAuthError("openai_unauthorized")
            if resp.status_code == 429:
                if attempt > self._max_retries:
                    retry_after = self._parse_retry_after(resp)
                    raise ConnectorRateLimitError(
                        "openai_rate_limited", retry_after_s=retry_after
                    )
                await self._backoff(attempt, retry_after=self._parse_retry_after(resp))
                continue
            if 500 <= resp.status_code < 600:
                if attempt > self._max_retries:
                    raise ConnectorTransientError(
                        f"openai_server_error status={resp.status_code} body={resp.text[:200]}"
                    )
                await self._backoff(attempt)
                continue

            # 4xx other than 401/429 — non-retryable
            raise ConnectorError(
                f"openai_request_failed status={resp.status_code} body={resp.text[:500]}"
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
            "openai_retry_backoff",
            extra={"attempt": attempt, "delay_s": round(delay, 2)},
        )
        await asyncio.sleep(delay)

    def _parse_response(
        self, data: dict[str, Any], *, latency_ms: int
    ) -> ConnectorResponse:
        choices = data.get("choices") or []
        if not choices:
            raise ConnectorError("openai_response_missing_choices")
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
        model = data.get("model", self.model)
        cost = calculate_cost(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            rate=_resolve_rate(model),
        )

        return ConnectorResponse(
            text=text,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            cost_usd=cost,
            tool_calls=tool_calls,
            raw_response=data,
        )


def _safe_json_loads(s: str) -> dict[str, Any]:
    try:
        result = json.loads(s)
        return result if isinstance(result, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}
