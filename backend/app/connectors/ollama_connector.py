"""Ollama connector — local HTTP API to ollama serve.

Ollama is unauthenticated by design (it's meant to bind to localhost or
a trusted internal network). No API key, no cost — the customer is
running the model on their own hardware. Latency depends entirely on
the local model, so retry logic is conservative: timeouts grow, network
errors retry once.

The platform uses Ollama for two flows:
  - Customer evaluations against self-hosted models
  - The runtime agent's Stage 3 LLM judge when configured for local
    inference (Sprint 7)
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from typing import Any

import httpx

from app.connectors.base import (
    ConnectorConfigError,
    ConnectorError,
    ConnectorResponse,
    ConnectorTransientError,
    LatencyTimer,
)

logger = logging.getLogger("platform.connectors.ollama")

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_TIMEOUT_S = 120.0  # local inference can be slow on CPU
DEFAULT_MAX_RETRIES = 1   # network problems on localhost are rare; don't mask them


class OllamaConnector:
    """Adapter for Ollama's /api/chat endpoint.

    Ollama doesn't bill — cost_usd is always 0.0. Tool calling support
    depends on the model (llama3.1+, qwen2.5+, mistral-nemo+); the
    connector forwards tools when provided and parses tool_calls when
    they come back.
    """

    provider = "ollama"

    def __init__(
        self,
        *,
        model: str,
        base_url: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        if not model:
            raise ConnectorConfigError("model is required")
        self.model = model
        self._base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self._timeout_s = timeout_s
        self._max_retries = max(0, max_retries)

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
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        return await self._chat_call(body)

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
        body: dict[str, Any] = {
            "model": self.model,
            "messages": all_messages,
            "stream": False,
        }
        if tools:
            body["tools"] = tools
        return await self._chat_call(body)

    async def health_check(self) -> bool:
        """Hit /api/tags to verify the daemon is responding. Doesn't
        check whether ``self.model`` is loaded — that would require a
        pull which is slow and surprising for a health check."""
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                resp = await client.get(f"{self._base_url}/api/tags")
            except httpx.RequestError as exc:
                raise ConnectorError(f"ollama_unreachable: {exc}") from exc
        if resp.status_code == 200:
            return True
        raise ConnectorError(
            f"ollama_health_check_failed: status={resp.status_code}"
        )

    # ─────────────────────────────────────────── internals

    async def _chat_call(self, body: dict[str, Any]) -> ConnectorResponse:
        url = f"{self._base_url}/api/chat"
        attempt = 0
        while True:
            attempt += 1
            with LatencyTimer() as timer:
                try:
                    async with httpx.AsyncClient(timeout=self._timeout_s) as client:
                        resp = await client.post(
                            url,
                            content=json.dumps(body),
                            headers={"content-type": "application/json"},
                        )
                except (httpx.TimeoutException, httpx.RequestError) as exc:
                    if attempt > self._max_retries:
                        raise ConnectorTransientError(
                            f"ollama_request_error: {exc}"
                        ) from exc
                    await self._backoff(attempt)
                    continue

            if resp.status_code == 200:
                return self._parse_response(resp.json(), latency_ms=timer.elapsed_ms)
            if 500 <= resp.status_code < 600:
                if attempt > self._max_retries:
                    raise ConnectorTransientError(
                        f"ollama_server_error status={resp.status_code}"
                    )
                await self._backoff(attempt)
                continue
            raise ConnectorError(
                f"ollama_request_failed status={resp.status_code} "
                f"body={resp.text[:500]}"
            )

    async def _backoff(self, attempt: int) -> None:
        base = min(2 ** (attempt - 1), 10.0)
        await asyncio.sleep(base + random.uniform(0, base * 0.25))

    def _parse_response(
        self, data: dict[str, Any], *, latency_ms: int
    ) -> ConnectorResponse:
        message = data.get("message") or {}
        text = message.get("content") or ""

        # Token counts from Ollama's eval_count / prompt_eval_count
        input_tokens = int(data.get("prompt_eval_count", 0))
        output_tokens = int(data.get("eval_count", 0))

        # Tool calls — Ollama 0.3+ returns these in message.tool_calls
        from app.connectors.base import ToolCall

        raw_tools = message.get("tool_calls") or []
        tool_calls = tuple(
            ToolCall(
                id=str(tc.get("id", "")),
                name=(tc.get("function") or {}).get("name", ""),
                arguments=(tc.get("function") or {}).get("arguments") or {},
            )
            for tc in raw_tools
        )

        return ConnectorResponse(
            text=text,
            model=data.get("model", self.model),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            cost_usd=0.0,
            tool_calls=tool_calls,
            raw_response=data,
        )
