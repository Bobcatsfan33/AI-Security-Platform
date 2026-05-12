"""Anthropic connector unit tests with mocked httpx."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.connectors.anthropic_connector import (
    ANTHROPIC_COST_RATES,
    AnthropicConnector,
    _resolve_rate,
)
from app.connectors.base import (
    ConnectorAuthError,
    ConnectorConfigError,
    ConnectorError,
    ConnectorRateLimitError,
    ConnectorTransientError,
    ToolCall,
)
from app.security.secrets import set_resolver


class _StaticResolver:
    prefix = "test:"

    def resolve(self, reference: str) -> str:
        return "sk-ant-test-fake-key"


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


def _success(
    *,
    text: str = "hi",
    model: str = "claude-sonnet-4-20251001",
    in_t: int = 10,
    out_t: int = 5,
) -> dict[str, Any]:
    return {
        "id": "msg-1",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": in_t, "output_tokens": out_t},
    }


def _tool_use_response() -> dict[str, Any]:
    return {
        "id": "msg-2",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4",
        "content": [
            {"type": "text", "text": "calling lookup"},
            {
                "type": "tool_use",
                "id": "toolu_abc",
                "name": "lookup_user",
                "input": {"user_id": "u-1"},
            },
        ],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 30, "output_tokens": 10},
    }


# ─────────────────────────────────────────────── Construction


@pytest.mark.unit
class TestConstruction:
    def test_minimal_config(self) -> None:
        c = AnthropicConnector(api_key_ref="test:x", model="claude-sonnet-4")
        assert c.provider == "anthropic"

    def test_missing_api_key_rejected(self) -> None:
        with pytest.raises(ConnectorConfigError, match="api_key_ref"):
            AnthropicConnector(api_key_ref="", model="x")

    def test_missing_model_rejected(self) -> None:
        with pytest.raises(ConnectorConfigError, match="model"):
            AnthropicConnector(api_key_ref="test:x", model="")


# ─────────────────────────────────────────────── Cost rates


@pytest.mark.unit
class TestCostRates:
    def test_known_model(self) -> None:
        assert _resolve_rate("claude-sonnet-4") == ANTHROPIC_COST_RATES["claude-sonnet-4"]

    def test_dated_snapshot_falls_back(self) -> None:
        assert _resolve_rate("claude-sonnet-4-20251001") == ANTHROPIC_COST_RATES["claude-sonnet-4"]

    def test_unknown_zero(self) -> None:
        rate = _resolve_rate("acme-llm-1")
        assert rate.input_per_million == 0.0


# ─────────────────────────────────────────────── Success path


@pytest.mark.unit
@pytest.mark.asyncio
class TestGenerate:
    async def test_returns_normalized_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["headers"] = dict(request.headers)
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json=_success(text="hello"))

        _patch(monkeypatch, handler)
        c = AnthropicConnector(api_key_ref="test:x", model="claude-sonnet-4")
        result = await c.generate("hi", max_tokens=64)
        assert result.text == "hello"
        assert result.input_tokens == 10
        assert result.output_tokens == 5
        assert result.cost_usd > 0
        # Anthropic-specific header shape
        assert captured["headers"]["x-api-key"] == "sk-ant-test-fake-key"
        assert "anthropic-version" in captured["headers"]
        # System prompt absent → no top-level system field
        assert "system" not in captured["body"]

    async def test_system_prompt_in_top_level_field(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = AnthropicConnector(api_key_ref="test:x", model="claude-sonnet-4")
        await c.generate("hi", system_prompt="You are helpful.")
        assert captured["body"]["system"] == "You are helpful."
        # System should NOT appear as a role in messages
        assert all(m["role"] != "system" for m in captured["body"]["messages"])


@pytest.mark.unit
@pytest.mark.asyncio
class TestToolUse:
    async def test_tool_blocks_become_tool_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_tool_use_response())

        _patch(monkeypatch, handler)
        c = AnthropicConnector(api_key_ref="test:x", model="claude-sonnet-4")
        result = await c.generate_with_tools(
            messages=[{"role": "user", "content": "look up u-1"}],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "lookup_user",
                        "description": "find a user",
                        "parameters": {
                            "type": "object",
                            "properties": {"user_id": {"type": "string"}},
                        },
                    },
                }
            ],
        )
        assert len(result.tool_calls) == 1
        tc = result.tool_calls[0]
        assert isinstance(tc, ToolCall)
        assert tc.id == "toolu_abc"
        assert tc.name == "lookup_user"
        assert tc.arguments == {"user_id": "u-1"}
        # Text blocks before the tool_use are still captured
        assert "calling lookup" in result.text

    async def test_openai_shaped_tools_translated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = AnthropicConnector(api_key_ref="test:x", model="claude-sonnet-4")
        await c.generate_with_tools(
            messages=[{"role": "user", "content": "x"}],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "f",
                        "description": "desc",
                        "parameters": {"type": "object", "properties": {}},
                    },
                }
            ],
        )
        sent_tool = captured["body"]["tools"][0]
        # Translated to Anthropic shape
        assert sent_tool["name"] == "f"
        assert sent_tool["description"] == "desc"
        assert sent_tool["input_schema"] == {"type": "object", "properties": {}}


@pytest.mark.unit
@pytest.mark.asyncio
class TestErrorMapping:
    async def test_401_auth_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(401)

        _patch(monkeypatch, handler)
        c = AnthropicConnector(api_key_ref="test:x", model="claude-sonnet-4")
        with pytest.raises(ConnectorAuthError):
            await c.generate("hi")

    async def test_429_rate_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(429, headers={"retry-after": "0"})

        _patch(monkeypatch, handler)
        c = AnthropicConnector(api_key_ref="test:x", model="claude-sonnet-4", max_retries=1)
        with pytest.raises(ConnectorRateLimitError):
            await c.generate("hi")

    async def test_500_transient(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        _patch(monkeypatch, handler)
        c = AnthropicConnector(api_key_ref="test:x", model="claude-sonnet-4", max_retries=1)

        async def _no_sleep(*a, **k):  # type: ignore[no-untyped-def]
            return None

        monkeypatch.setattr(
            "app.connectors.anthropic_connector.asyncio.sleep", _no_sleep
        )
        with pytest.raises(ConnectorTransientError):
            await c.generate("hi")

    async def test_4xx_other_non_retryable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = {"n": 0}

        def handler(_: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(400, json={"error": "bad"})

        _patch(monkeypatch, handler)
        c = AnthropicConnector(api_key_ref="test:x", model="claude-sonnet-4", max_retries=5)
        with pytest.raises(ConnectorError):
            await c.generate("hi")
        assert calls["n"] == 1


@pytest.mark.unit
@pytest.mark.asyncio
class TestHealth:
    async def test_health_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = AnthropicConnector(api_key_ref="test:x", model="claude-sonnet-4")
        assert await c.health_check() is True

    async def test_health_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(401)

        _patch(monkeypatch, handler)
        c = AnthropicConnector(api_key_ref="test:x", model="claude-sonnet-4")
        with pytest.raises(ConnectorAuthError):
            await c.health_check()
