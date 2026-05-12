"""Ollama connector tests — local HTTP, no auth, no cost."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.connectors.base import (
    ConnectorConfigError,
    ConnectorError,
    ConnectorTransientError,
)
from app.connectors.ollama_connector import OllamaConnector


def _patch(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    transport = httpx.MockTransport(handler)
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


def _success(*, text: str = "hi", model: str = "llama3.2") -> dict[str, Any]:
    return {
        "model": model,
        "created_at": "2026-05-09T00:00:00Z",
        "message": {"role": "assistant", "content": text},
        "done": True,
        "prompt_eval_count": 4,
        "eval_count": 8,
    }


@pytest.mark.unit
class TestConstruction:
    def test_minimal_config(self) -> None:
        c = OllamaConnector(model="llama3.2")
        assert c.provider == "ollama"

    def test_missing_model_rejected(self) -> None:
        with pytest.raises(ConnectorConfigError, match="model"):
            OllamaConnector(model="")


@pytest.mark.unit
@pytest.mark.asyncio
class TestGenerate:
    async def test_no_cost_charged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = OllamaConnector(model="llama3.2")
        result = await c.generate("hi")
        assert result.text == "hi"
        assert result.cost_usd == 0.0
        assert result.input_tokens == 4
        assert result.output_tokens == 8

    async def test_no_auth_header_sent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(request.headers)
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = OllamaConnector(model="llama3.2")
        await c.generate("hi")
        # No api-key / authorization headers
        assert "authorization" not in captured["headers"]
        assert "x-api-key" not in captured["headers"]
        assert "api-key" not in captured["headers"]

    async def test_system_prompt_first_message(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = OllamaConnector(model="llama3.2")
        await c.generate("hi", system_prompt="you are helpful")
        assert captured["body"]["messages"][0] == {
            "role": "system",
            "content": "you are helpful",
        }


@pytest.mark.unit
@pytest.mark.asyncio
class TestErrorMapping:
    async def test_500_after_retry_raises_transient(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        _patch(monkeypatch, handler)
        c = OllamaConnector(model="llama3.2", max_retries=0)
        with pytest.raises(ConnectorTransientError):
            await c.generate("hi")

    async def test_400_non_retryable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(400, json={"error": "model not found"})

        _patch(monkeypatch, handler)
        c = OllamaConnector(model="missing-model", max_retries=3)
        with pytest.raises(ConnectorError):
            await c.generate("hi")


@pytest.mark.unit
@pytest.mark.asyncio
class TestHealthCheck:
    async def test_returns_true_when_daemon_responds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"models": []})

        _patch(monkeypatch, handler)
        c = OllamaConnector(model="llama3.2")
        assert await c.health_check() is True

    async def test_unreachable_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        _patch(monkeypatch, handler)
        c = OllamaConnector(model="llama3.2")
        with pytest.raises(ConnectorError, match="ollama_unreachable"):
            await c.health_check()
