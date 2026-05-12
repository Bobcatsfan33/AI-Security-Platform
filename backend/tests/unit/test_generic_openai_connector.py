"""GenericOpenAIConnector tests — vLLM / LM Studio / OpenRouter shape."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.connectors.base import ConnectorConfigError
from app.connectors.generic_openai_connector import GenericOpenAIConnector
from app.security.secrets import set_resolver


class _StaticResolver:
    prefix = "test:"

    def __init__(self, value: str = "bearer-test") -> None:
        self.value = value

    def resolve(self, reference: str) -> str:
        return self.value


@pytest.fixture(autouse=True)
def _isolate_resolver() -> None:
    from app.security import secrets as secrets_mod

    original = secrets_mod.get_resolver()
    set_resolver(_StaticResolver())
    yield
    set_resolver(original)


def _patch(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    transport = httpx.MockTransport(handler)
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


def _success(text: str = "ok") -> dict[str, Any]:
    return {
        "id": "x",
        "model": "vllm-llama",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


@pytest.mark.unit
class TestConstruction:
    def test_minimal(self) -> None:
        c = GenericOpenAIConnector(
            api_key_ref="",
            model="llama3.1-70b",
            base_url="http://localhost:8000/v1",
        )
        assert c.provider == "custom"
        assert c.model == "llama3.1-70b"

    def test_missing_base_url_rejected(self) -> None:
        with pytest.raises(ConnectorConfigError, match="base_url"):
            GenericOpenAIConnector(api_key_ref="x", model="m", base_url="")


@pytest.mark.unit
@pytest.mark.asyncio
class TestGenerate:
    async def test_no_auth_header_when_unauthenticated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(request.headers)
            captured["url"] = str(request.url)
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = GenericOpenAIConnector(
            api_key_ref="",
            model="llama3.1",
            base_url="http://vllm:8000/v1",
        )
        await c.generate("hi")
        # No Authorization header for unauthenticated endpoint
        assert "authorization" not in captured["headers"]
        # Cost is zero by default
        # (verified in next test against full response)

    async def test_with_api_key_sends_bearer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(request.headers)
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = GenericOpenAIConnector(
            api_key_ref="test:proxy-key",
            model="m",
            base_url="https://openrouter.ai/api/v1",
        )
        await c.generate("hi")
        assert captured["headers"]["authorization"] == "Bearer bearer-test"

    async def test_zero_cost_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = GenericOpenAIConnector(
            api_key_ref="",
            model="llama3.1",
            base_url="http://localhost:8000/v1",
        )
        result = await c.generate("hi")
        assert result.cost_usd == 0.0

    async def test_configured_cost_rates_applied(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = GenericOpenAIConnector(
            api_key_ref="",
            model="m",
            base_url="https://proxy.example.com/v1",
            cost_input_per_million=1.0,
            cost_output_per_million=2.0,
        )
        result = await c.generate("hi")
        # 10 input * 1.0 / 1_000_000 + 5 output * 2.0 / 1_000_000
        expected = 10 / 1_000_000 + 5 * 2 / 1_000_000
        assert abs(result.cost_usd - expected) < 1e-9

    async def test_uses_configured_base_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = GenericOpenAIConnector(
            api_key_ref="",
            model="m",
            base_url="https://together.ai/api/v1",
        )
        await c.generate("hi")
        assert captured["url"].startswith("https://together.ai/api/v1")
        assert "/chat/completions" in captured["url"]
