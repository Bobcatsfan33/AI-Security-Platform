"""Azure OpenAI connector tests."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.connectors.azure_openai_connector import AzureOpenAIConnector
from app.connectors.base import (
    ConnectorAuthError,
    ConnectorConfigError,
)
from app.security.secrets import set_resolver


class _StaticResolver:
    prefix = "test:"

    def resolve(self, reference: str) -> str:
        return "azure-test-key"


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


def _success(model: str = "gpt-4o-deployment") -> dict[str, Any]:
    return {
        "id": "cmpl-1",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    }


# ─────────────────────────────────────────────── Construction


@pytest.mark.unit
class TestConstruction:
    def test_minimal_config(self) -> None:
        c = AzureOpenAIConnector(
            endpoint="https://r.openai.azure.com",
            deployment_name="gpt-4o-prod",
            api_key_ref="test:k",
        )
        assert c.provider == "azure_openai"
        assert c.deployment_name == "gpt-4o-prod"

    def test_missing_endpoint_rejected(self) -> None:
        with pytest.raises(ConnectorConfigError, match="endpoint"):
            AzureOpenAIConnector(
                endpoint="", deployment_name="d", api_key_ref="test:k"
            )

    def test_missing_deployment_rejected(self) -> None:
        with pytest.raises(ConnectorConfigError, match="deployment_name"):
            AzureOpenAIConnector(
                endpoint="https://x", deployment_name="", api_key_ref="test:k"
            )

    def test_missing_api_key_rejected(self) -> None:
        with pytest.raises(ConnectorConfigError, match="api_key_ref"):
            AzureOpenAIConnector(
                endpoint="https://x", deployment_name="d", api_key_ref=""
            )


# ─────────────────────────────────────────────── URL + auth shape


@pytest.mark.unit
@pytest.mark.asyncio
class TestUrlAndAuth:
    async def test_url_includes_deployment_and_api_version(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = AzureOpenAIConnector(
            endpoint="https://my-resource.openai.azure.com",
            deployment_name="gpt-4o-prod",
            api_key_ref="test:k",
            api_version="2024-08-01-preview",
        )
        await c.generate("hi")
        assert (
            "openai/deployments/gpt-4o-prod/chat/completions"
            in captured["url"]
        )
        assert "api-version=2024-08-01-preview" in captured["url"]

    async def test_uses_api_key_header_not_bearer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(request.headers)
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = AzureOpenAIConnector(
            endpoint="https://x.openai.azure.com",
            deployment_name="d",
            api_key_ref="test:k",
        )
        await c.generate("hi")
        # Azure uses `api-key` header, not Authorization Bearer
        assert captured["headers"].get("api-key") == "azure-test-key"
        assert "authorization" not in captured["headers"]


# ─────────────────────────────────────────────── Cost / response parsing


@pytest.mark.unit
@pytest.mark.asyncio
class TestCostTracking:
    async def test_cost_resolved_via_model_for_pricing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = AzureOpenAIConnector(
            endpoint="https://x.openai.azure.com",
            deployment_name="my-custom-alias",
            api_key_ref="test:k",
            model_for_pricing="gpt-4o-mini",
        )
        result = await c.generate("hi")
        # gpt-4o-mini rates are nonzero
        assert result.cost_usd > 0

    async def test_unknown_pricing_alias_zero_cost(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = AzureOpenAIConnector(
            endpoint="https://x.openai.azure.com",
            deployment_name="weird-name",
            api_key_ref="test:k",
        )  # no model_for_pricing → falls back to deployment_name → no rate
        result = await c.generate("hi")
        assert result.cost_usd == 0.0


@pytest.mark.unit
@pytest.mark.asyncio
class TestHealth:
    async def test_health_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_success())

        _patch(monkeypatch, handler)
        c = AzureOpenAIConnector(
            endpoint="https://x.openai.azure.com",
            deployment_name="d",
            api_key_ref="test:k",
        )
        assert await c.health_check() is True

    async def test_health_401_auth_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(401)

        _patch(monkeypatch, handler)
        c = AzureOpenAIConnector(
            endpoint="https://x.openai.azure.com",
            deployment_name="d",
            api_key_ref="test:k",
        )
        with pytest.raises(ConnectorAuthError):
            await c.health_check()
