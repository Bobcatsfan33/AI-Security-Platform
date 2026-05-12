"""Bedrock connector tests — mocked boto3 client.

Real Bedrock round-trips require AWS credentials and a non-zero spend
budget. We test the dispatch and parsing logic against a stubbed
``invoke_model`` response.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.connectors.base import (
    ConnectorAuthError,
    ConnectorConfigError,
    ConnectorError,
    ConnectorRateLimitError,
)
from app.connectors.bedrock_connector import (
    BEDROCK_COST_RATES,
    BedrockConnector,
    _family_of,
    _resolve_rate,
)


class _StubBodyStream:
    """Mimics the streaming Body object boto3 returns from invoke_model."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self._bytes = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._bytes


def _bedrock_anthropic_response(text: str = "ok") -> dict[str, Any]:
    return {
        "id": "msg-bedrock-1",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 8, "output_tokens": 4},
    }


def _bedrock_meta_response(text: str = "ok") -> dict[str, Any]:
    return {
        "generation": text,
        "prompt_token_count": 7,
        "generation_token_count": 5,
        "stop_reason": "stop",
    }


def _patch_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    payload: dict[str, Any] | None = None,
    raise_exc: Exception | None = None,
) -> dict[str, Any]:
    """Patch BedrockConnector._get_client to return a stub client.

    Captures the kwargs passed to invoke_model so tests can assert.
    """
    captured: dict[str, Any] = {}

    class _StubClient:
        def invoke_model(self, **kwargs):  # type: ignore[no-untyped-def]
            captured.update(kwargs)
            if raise_exc is not None:
                raise raise_exc
            return {"body": _StubBodyStream(payload or _bedrock_anthropic_response())}

        def list_foundation_models(self):  # for health_check
            if raise_exc is not None:
                raise raise_exc
            return {"modelSummaries": []}

    async def _stub_get_client(self, *, service: str = "bedrock-runtime"):  # type: ignore[no-untyped-def]
        return _StubClient()

    monkeypatch.setattr(BedrockConnector, "_get_client", _stub_get_client)
    return captured


# ─────────────────────────────────────────────── Construction


@pytest.mark.unit
class TestConstruction:
    def test_anthropic_family_detected(self) -> None:
        c = BedrockConnector(model="anthropic.claude-sonnet-4-20251001-v2:0")
        assert c._family == "anthropic"

    def test_meta_family_detected(self) -> None:
        c = BedrockConnector(model="meta.llama3-1-70b-instruct-v1:0")
        assert c._family == "meta"

    def test_unknown_family(self) -> None:
        c = BedrockConnector(model="acme.weird")
        assert c._family == "unknown"

    def test_missing_model_rejected(self) -> None:
        with pytest.raises(ConnectorConfigError, match="model"):
            BedrockConnector(model="")


@pytest.mark.unit
class TestCostRates:
    def test_known_anthropic_model(self) -> None:
        rate = _resolve_rate("anthropic.claude-sonnet-4")
        assert rate == BEDROCK_COST_RATES["anthropic.claude-sonnet-4"]

    def test_versioned_model_falls_back_via_prefix(self) -> None:
        rate = _resolve_rate("anthropic.claude-sonnet-4-20251001-v2:0")
        assert rate == BEDROCK_COST_RATES["anthropic.claude-sonnet-4"]

    def test_unknown_model_zero(self) -> None:
        rate = _resolve_rate("amazon.titan-x")
        assert rate.input_per_million == 0.0


# ─────────────────────────────────────────────── Family dispatch


@pytest.mark.unit
@pytest.mark.asyncio
class TestGenerate:
    async def test_anthropic_round_trip(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = _patch_client(
            monkeypatch, payload=_bedrock_anthropic_response(text="hello")
        )
        c = BedrockConnector(model="anthropic.claude-sonnet-4")
        result = await c.generate("hi", system_prompt="be brief")
        assert result.text == "hello"
        assert result.input_tokens == 8
        assert result.output_tokens == 4
        assert result.cost_usd > 0
        # The body sent must match Anthropic-on-Bedrock shape
        body = json.loads(captured["body"])
        assert body["anthropic_version"] == "bedrock-2023-05-31"
        assert body["system"] == "be brief"
        assert body["messages"] == [{"role": "user", "content": "hi"}]

    async def test_meta_round_trip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured = _patch_client(
            monkeypatch, payload=_bedrock_meta_response(text="llama-said")
        )
        c = BedrockConnector(model="meta.llama3-1-70b")
        result = await c.generate("hello")
        assert result.text == "llama-said"
        assert result.input_tokens == 7
        assert result.output_tokens == 5
        body = json.loads(captured["body"])
        assert "prompt" in body
        assert "max_gen_len" in body

    async def test_unknown_family_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch)
        c = BedrockConnector(model="cohere.command-r")
        with pytest.raises(ConnectorError, match="unsupported"):
            await c.generate("hi")


@pytest.mark.unit
@pytest.mark.asyncio
class TestToolUse:
    async def test_anthropic_tools_translated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = _patch_client(monkeypatch)
        c = BedrockConnector(model="anthropic.claude-sonnet-4")
        await c.generate_with_tools(
            messages=[{"role": "user", "content": "x"}],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "parameters": {"type": "object", "properties": {}},
                    },
                }
            ],
        )
        body = json.loads(captured["body"])
        assert body["tools"][0]["name"] == "lookup"
        assert "input_schema" in body["tools"][0]

    async def test_meta_tool_use_unsupported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch)
        c = BedrockConnector(model="meta.llama3-1-70b")
        with pytest.raises(ConnectorError, match="tool calling"):
            await c.generate_with_tools(messages=[], tools=[{"name": "x"}])


@pytest.mark.unit
@pytest.mark.asyncio
class TestErrors:
    async def test_throttling_maps_to_rate_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch, raise_exc=Exception("ThrottlingException: slow down"))
        c = BedrockConnector(model="anthropic.claude-sonnet-4")
        with pytest.raises(ConnectorRateLimitError):
            await c.generate("hi")

    async def test_access_denied_maps_to_auth(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch, raise_exc=Exception("AccessDeniedException"))
        c = BedrockConnector(model="anthropic.claude-sonnet-4")
        with pytest.raises(ConnectorAuthError):
            await c.generate("hi")


@pytest.mark.unit
@pytest.mark.asyncio
class TestHealth:
    async def test_health_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_client(monkeypatch)
        c = BedrockConnector(model="anthropic.claude-sonnet-4")
        assert await c.health_check() is True

    async def test_health_403_maps_to_auth(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_client(monkeypatch, raise_exc=Exception("AccessDenied: nope"))
        c = BedrockConnector(model="anthropic.claude-sonnet-4")
        with pytest.raises(ConnectorAuthError):
            await c.health_check()


@pytest.mark.unit
class TestFamilyHelper:
    @pytest.mark.parametrize(
        "model,expected_family",
        [
            ("anthropic.claude-sonnet-4-20251001-v2:0", "anthropic"),
            ("meta.llama3-1-70b-instruct-v1:0", "meta"),
            ("amazon.titan-text-express-v1", "titan"),
            ("mistral.mistral-large-2402-v1:0", "mistral"),
            ("cohere.command-r-v1:0", "cohere"),
            ("acme.weird", "unknown"),
        ],
    )
    def test_family_of(self, model: str, expected_family: str) -> None:
        assert _family_of(model) == expected_family
