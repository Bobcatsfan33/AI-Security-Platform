"""OpenAI connector unit tests with mocked httpx.

Covers cost calculation, the success path, error mapping (auth / rate
limit / 5xx / timeout / non-retryable 4xx), retry behavior, and tool-call
parsing.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.connectors.base import (
    ConnectorAuthError,
    ConnectorConfigError,
    ConnectorError,
    ConnectorRateLimitError,
    ConnectorTransientError,
    ToolCall,
)
from app.connectors.openai_connector import (
    OPENAI_COST_RATES,
    OpenAIConnector,
    _resolve_rate,
)
from app.security.secrets import set_resolver


class _StaticResolver:
    """Returns a fixed plaintext for any reference. Used to inject a fake
    API key without touching env vars."""

    prefix = "test:"

    def __init__(self, value: str = "sk-test-fake-key") -> None:
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


def _success_response(
    *, text: str = "hello", model: str = "gpt-4o-mini", input_tokens: int = 10, output_tokens: int = 5
) -> dict[str, Any]:
    return {
        "id": "cmpl-test",
        "model": model,
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}
        ],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        },
    }


def _tool_call_response() -> dict[str, Any]:
    return {
        "id": "cmpl-test",
        "model": "gpt-4o",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_abc",
                            "type": "function",
                            "function": {
                                "name": "lookup_user",
                                "arguments": '{"user_id":"u-123"}',
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 30, "completion_tokens": 10, "total_tokens": 40},
    }


def _mock_transport(handler) -> httpx.MockTransport:
    """Wrap a request handler in an httpx MockTransport."""
    return httpx.MockTransport(handler)


def _patch_async_client(monkeypatch: pytest.MonkeyPatch, transport: httpx.MockTransport) -> None:
    """Force every AsyncClient created during the test to use our mock transport."""
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


# ─────────────────────────────────────────────── Construction


@pytest.mark.unit
class TestConstruction:
    def test_minimal_config_succeeds(self) -> None:
        c = OpenAIConnector(api_key_ref="test:fake", model="gpt-4o-mini")
        assert c.provider == "openai"
        assert c.model == "gpt-4o-mini"

    def test_missing_api_key_ref_rejected(self) -> None:
        with pytest.raises(ConnectorConfigError, match="api_key_ref"):
            OpenAIConnector(api_key_ref="", model="gpt-4o-mini")

    def test_missing_model_rejected(self) -> None:
        with pytest.raises(ConnectorConfigError, match="model"):
            OpenAIConnector(api_key_ref="test:fake", model="")


# ─────────────────────────────────────────────── Cost rates


@pytest.mark.unit
class TestCostRates:
    def test_known_model_resolves(self) -> None:
        rate = _resolve_rate("gpt-4o-mini")
        assert rate == OPENAI_COST_RATES["gpt-4o-mini"]

    def test_dated_snapshot_falls_back_to_prefix(self) -> None:
        rate = _resolve_rate("gpt-4o-2024-08-06")
        # Should match "gpt-4o", not "gpt-4o-mini" (the longer key wins
        # only when it's actually a longer prefix match)
        assert rate == OPENAI_COST_RATES["gpt-4o"]

    def test_mini_specifically_beats_4o_for_mini_dated_models(self) -> None:
        rate = _resolve_rate("gpt-4o-mini-2024-07-18")
        assert rate == OPENAI_COST_RATES["gpt-4o-mini"]

    def test_unknown_model_returns_zero(self) -> None:
        rate = _resolve_rate("acme-llama-9001")
        assert rate.input_per_million == 0.0
        assert rate.output_per_million == 0.0


# ─────────────────────────────────────────────── Success path


@pytest.mark.unit
@pytest.mark.asyncio
class TestGenerateSuccess:
    async def test_returns_normalized_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["headers"] = dict(request.headers)
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json=_success_response(text="echo"))

        _patch_async_client(monkeypatch, _mock_transport(handler))

        connector = OpenAIConnector(api_key_ref="test:fake", model="gpt-4o-mini")
        result = await connector.generate("hello world", max_tokens=128)

        assert result.text == "echo"
        assert result.model == "gpt-4o-mini"
        assert result.input_tokens == 10
        assert result.output_tokens == 5
        assert result.cost_usd > 0
        assert result.latency_ms >= 0
        # Verify request shape
        assert captured["url"].endswith("/chat/completions")
        assert captured["headers"]["authorization"] == "Bearer sk-test-fake-key"
        assert captured["body"]["model"] == "gpt-4o-mini"
        assert captured["body"]["messages"][-1] == {
            "role": "user",
            "content": "hello world",
        }
        assert captured["body"]["max_tokens"] == 128

    async def test_system_prompt_inserted_first(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json=_success_response())

        _patch_async_client(monkeypatch, _mock_transport(handler))

        connector = OpenAIConnector(api_key_ref="test:fake", model="gpt-4o")
        await connector.generate("hi", system_prompt="You are helpful.")

        messages = captured["body"]["messages"]
        assert messages[0] == {"role": "system", "content": "You are helpful."}
        assert messages[1] == {"role": "user", "content": "hi"}


@pytest.mark.unit
@pytest.mark.asyncio
class TestGenerateWithTools:
    async def test_tool_calls_parsed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_tool_call_response())

        _patch_async_client(monkeypatch, _mock_transport(handler))

        connector = OpenAIConnector(api_key_ref="test:fake", model="gpt-4o")
        result = await connector.generate_with_tools(
            messages=[{"role": "user", "content": "find me u-123"}],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "lookup_user",
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
        assert tc.id == "call_abc"
        assert tc.name == "lookup_user"
        assert tc.arguments == {"user_id": "u-123"}

    async def test_invalid_tool_args_yield_empty_dict_not_crash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bad = _tool_call_response()
        bad["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = (
            "not-valid-json"
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=bad)

        _patch_async_client(monkeypatch, _mock_transport(handler))

        connector = OpenAIConnector(api_key_ref="test:fake", model="gpt-4o")
        result = await connector.generate_with_tools(
            messages=[{"role": "user", "content": "x"}],
            tools=[],
        )
        assert result.tool_calls[0].arguments == {}

    async def test_system_prompt_only_inserted_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json=_success_response())

        _patch_async_client(monkeypatch, _mock_transport(handler))

        connector = OpenAIConnector(api_key_ref="test:fake", model="gpt-4o")
        await connector.generate_with_tools(
            messages=[
                {"role": "system", "content": "explicit-system"},
                {"role": "user", "content": "x"},
            ],
            tools=[],
            system_prompt="should-not-be-inserted",
        )
        roles = [m["role"] for m in captured["body"]["messages"]]
        assert roles == ["system", "user"]
        assert captured["body"]["messages"][0]["content"] == "explicit-system"


# ─────────────────────────────────────────────── Error paths


@pytest.mark.unit
@pytest.mark.asyncio
class TestErrorMapping:
    async def test_401_raises_auth_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401, json={"error": {"message": "Invalid API key"}}
            )

        _patch_async_client(monkeypatch, _mock_transport(handler))
        connector = OpenAIConnector(api_key_ref="test:fake", model="gpt-4o-mini")

        with pytest.raises(ConnectorAuthError):
            await connector.generate("hi")

    async def test_429_after_retries_raises_rate_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(429, headers={"retry-after": "0"})

        _patch_async_client(monkeypatch, _mock_transport(handler))
        connector = OpenAIConnector(
            api_key_ref="test:fake", model="gpt-4o-mini", max_retries=1
        )
        with pytest.raises(ConnectorRateLimitError):
            await connector.generate("hi")

    async def test_500_after_retries_raises_transient(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        _patch_async_client(monkeypatch, _mock_transport(handler))
        connector = OpenAIConnector(
            api_key_ref="test:fake", model="gpt-4o-mini", max_retries=1
        )
        # Backoff includes random jitter even at attempt 1; force zero delay
        # by patching the random sleep base.
        async def _no_sleep(*args, **kwargs):  # type: ignore[no-untyped-def]
            return None

        monkeypatch.setattr(
            "app.connectors.openai_connector.asyncio.sleep", _no_sleep
        )

        with pytest.raises(ConnectorTransientError):
            await connector.generate("hi")

    async def test_400_is_non_retryable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = {"n": 0}

        def handler(_: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(400, json={"error": {"message": "bad request"}})

        _patch_async_client(monkeypatch, _mock_transport(handler))
        connector = OpenAIConnector(
            api_key_ref="test:fake", model="gpt-4o-mini", max_retries=5
        )
        with pytest.raises(ConnectorError):
            await connector.generate("hi")
        # Single attempt — no retries on 4xx other than 401/429
        assert calls["n"] == 1

    async def test_secret_resolution_failure_raises_config_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.security.secrets import SecretResolutionError, set_resolver

        class FailingResolver:
            prefix = "test:"

            def resolve(self, reference: str) -> str:
                raise SecretResolutionError("missing secret in test backend")

        set_resolver(FailingResolver())
        connector = OpenAIConnector(api_key_ref="test:missing", model="gpt-4o-mini")
        with pytest.raises(ConnectorConfigError, match="api_key_ref"):
            await connector.generate("hi")


# ─────────────────────────────────────────────── Health check


@pytest.mark.unit
@pytest.mark.asyncio
class TestHealthCheck:
    async def test_returns_true_on_200(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": []})

        _patch_async_client(monkeypatch, _mock_transport(handler))
        connector = OpenAIConnector(api_key_ref="test:fake", model="gpt-4o-mini")
        assert await connector.health_check() is True

    async def test_401_raises_auth_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(401)

        _patch_async_client(monkeypatch, _mock_transport(handler))
        connector = OpenAIConnector(api_key_ref="test:fake", model="gpt-4o-mini")
        with pytest.raises(ConnectorAuthError):
            await connector.health_check()
