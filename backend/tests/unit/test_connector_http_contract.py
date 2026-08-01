"""Provider-adapter contract: what goes on the wire, and what comes back.

Every connector is the platform's only writer of a provider's request and
its only reader of that provider's response. A regression here is invisible
to every other suite: the evaluation runner and the Stage 3 judge both take
whatever ``ConnectorResponse`` they are handed. So these tests pin the
contract at both ends —

  request  — URL, auth header, and body shape per provider
  response — text, token counts, cost, and tool calls
  failure  — which provider status maps to which platform exception, which
             ones retry, and which ones must NOT retry

The failure half is the point of the exercise. ``ConnectorAuthError`` on a
401 that silently retried three times would burn a rate-limit budget and
delay the operator's real error by a minute; a 4xx that retried would do the
same for a permanently malformed request. Both are asserted by request count,
not by exception type alone.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.connectors.anthropic_connector import AnthropicConnector
from app.connectors.azure_openai_connector import AzureOpenAIConnector
from app.connectors.base import (
    ConnectorAuthError,
    ConnectorConfigError,
    ConnectorError,
    ConnectorRateLimitError,
    ConnectorTransientError,
)
from app.connectors.ollama_connector import OllamaConnector
from app.connectors.openai_connector import OpenAIConnector
from app.security.secrets import SecretResolutionError, get_resolver, set_resolver

pytestmark = pytest.mark.unit

API_KEY_ENV = "TEST_CONNECTOR_API_KEY"
API_KEY_REF = f"env:{API_KEY_ENV}"
FAKE_KEY = "unit-test-key-not-a-real-credential"


@pytest.fixture(autouse=True)
def _fake_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    """A resolvable reference. Value is a literal, never a real credential."""
    monkeypatch.setenv(API_KEY_ENV, FAKE_KEY)


def _json_response(payload: dict[str, object], status: int = 200, **headers: str) -> httpx.Response:
    return httpx.Response(status, json=payload, headers=headers)


OPENAI_OK: dict[str, object] = {
    "model": "gpt-4o-2026-04-01",
    "choices": [{"message": {"content": "hello"}}],
    "usage": {"prompt_tokens": 1_000_000, "completion_tokens": 1_000_000},
}


# ───────────────────────────────────────────────────────── OpenAI


class TestOpenAIRequestContract:
    async def test_generate_sends_system_then_user_and_sampling_controls(self, http_stub):
        stub = http_stub(responses=[_json_response(OPENAI_OK)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o")

        await connector.generate("classify this", system_prompt="be terse", max_tokens=64)

        request = stub.last_request
        assert str(request.url) == "https://api.openai.com/v1/chat/completions"
        assert request.headers["authorization"] == f"Bearer {FAKE_KEY}"
        body = json.loads(request.content)
        assert body["messages"] == [
            {"role": "system", "content": "be terse"},
            {"role": "user", "content": "classify this"},
        ]
        assert body["model"] == "gpt-4o"
        assert body["max_tokens"] == 64
        assert body["temperature"] == 0.0

    async def test_generate_without_system_prompt_sends_user_turn_only(self, http_stub):
        stub = http_stub(responses=[_json_response(OPENAI_OK)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o")

        await connector.generate("just this")

        assert json.loads(stub.last_request.content)["messages"] == [
            {"role": "user", "content": "just this"}
        ]

    async def test_organization_header_only_present_when_configured(self, http_stub):
        stub = http_stub(responses=[_json_response(OPENAI_OK)])
        await OpenAIConnector(
            api_key_ref=API_KEY_REF, model="gpt-4o", organization="org-tenant-a"
        ).generate("x")
        assert stub.last_request.headers["openai-organization"] == "org-tenant-a"

        stub2 = http_stub(responses=[_json_response(OPENAI_OK)])
        await OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o").generate("x")
        assert "openai-organization" not in stub2.last_request.headers

    async def test_base_url_override_is_honored_without_double_slash(self, http_stub):
        stub = http_stub(responses=[_json_response(OPENAI_OK)])
        connector = OpenAIConnector(
            api_key_ref=API_KEY_REF, model="gpt-4o", base_url="https://proxy.internal/v1/"
        )

        await connector.generate("x")

        assert str(stub.last_request.url) == "https://proxy.internal/v1/chat/completions"

    async def test_generate_with_tools_forwards_tools_and_enables_auto_choice(self, http_stub):
        stub = http_stub(responses=[_json_response(OPENAI_OK)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o")
        tools = [{"type": "function", "function": {"name": "search", "parameters": {}}}]

        await connector.generate_with_tools([{"role": "user", "content": "go"}], tools)

        body = json.loads(stub.last_request.content)
        assert body["tools"] == tools
        assert body["tool_choice"] == "auto"

    async def test_generate_with_tools_omits_tool_choice_when_no_tools(self, http_stub):
        stub = http_stub(responses=[_json_response(OPENAI_OK)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o")

        await connector.generate_with_tools([{"role": "user", "content": "go"}], [])

        body = json.loads(stub.last_request.content)
        assert "tools" not in body and "tool_choice" not in body

    async def test_caller_supplied_system_turn_is_not_duplicated(self, http_stub):
        stub = http_stub(responses=[_json_response(OPENAI_OK)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o")
        messages = [
            {"role": "system", "content": "caller wins"},
            {"role": "user", "content": "go"},
        ]

        await connector.generate_with_tools(messages, [], system_prompt="adapter default")

        sent = json.loads(stub.last_request.content)["messages"]
        assert [m["role"] for m in sent].count("system") == 1
        assert sent[0]["content"] == "caller wins"

    async def test_system_prompt_is_prepended_when_caller_omitted_one(self, http_stub):
        stub = http_stub(responses=[_json_response(OPENAI_OK)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o")

        await connector.generate_with_tools(
            [{"role": "user", "content": "go"}], [], system_prompt="adapter default"
        )

        sent = json.loads(stub.last_request.content)["messages"]
        assert sent[0] == {"role": "system", "content": "adapter default"}

    async def test_caller_message_list_is_not_mutated(self, http_stub):
        http_stub(responses=[_json_response(OPENAI_OK)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o")
        messages = [{"role": "user", "content": "go"}]

        await connector.generate_with_tools(messages, [], system_prompt="adapter default")

        assert messages == [{"role": "user", "content": "go"}]


class TestOpenAIResponseContract:
    async def test_usage_and_prefix_matched_rate_produce_cost(self, http_stub):
        http_stub(responses=[_json_response(OPENAI_OK)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o")

        response = await connector.generate("x")

        assert response.text == "hello"
        assert response.model == "gpt-4o-2026-04-01"
        assert response.input_tokens == 1_000_000
        assert response.output_tokens == 1_000_000
        # gpt-4o: $2.50 in + $10.00 out per million.
        assert response.cost_usd == pytest.approx(12.50)
        assert response.latency_ms >= 0

    async def test_longest_prefix_wins_so_mini_is_not_billed_as_full_model(self, http_stub):
        payload = dict(OPENAI_OK, model="gpt-4o-mini-2026-04-01")
        http_stub(responses=[_json_response(payload)])

        response = await OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o-mini").generate("x")

        # gpt-4o-mini: $0.15 in + $0.60 out. Billing at gpt-4o would be 12.50.
        assert response.cost_usd == pytest.approx(0.75)

    async def test_unpriced_model_reports_zero_rather_than_guessing(self, http_stub):
        payload = dict(OPENAI_OK, model="some-model-we-have-never-priced")
        http_stub(responses=[_json_response(payload)])

        response = await OpenAIConnector(api_key_ref=API_KEY_REF, model="whatever").generate("x")

        assert response.cost_usd == 0.0

    async def test_tool_calls_are_normalized_and_arguments_parsed(self, http_stub):
        payload = {
            "model": "gpt-4o",
            "choices": [
                {
                    "message": {
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "function": {"name": "search", "arguments": '{"q": "ai"}'},
                            }
                        ],
                    }
                }
            ],
            "usage": {},
        }
        http_stub(responses=[_json_response(payload)])

        response = await OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o").generate("x")

        assert response.text == ""
        assert len(response.tool_calls) == 1
        call = response.tool_calls[0]
        assert (call.id, call.name, call.arguments) == ("call_1", "search", {"q": "ai"})

    @pytest.mark.parametrize("arguments", ["not json at all", "[1, 2, 3]", '"a string"'])
    async def test_unparseable_tool_arguments_degrade_to_empty_dict(self, http_stub, arguments):
        """A provider that returns junk arguments must not crash the run."""
        payload = {
            "model": "gpt-4o",
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {"id": "c", "function": {"name": "f", "arguments": arguments}}
                        ]
                    }
                }
            ],
            "usage": {},
        }
        http_stub(responses=[_json_response(payload)])

        response = await OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o").generate("x")

        assert response.tool_calls[0].arguments == {}

    async def test_tool_call_missing_function_object_still_yields_a_call(self, http_stub):
        payload = {
            "model": "gpt-4o",
            "choices": [{"message": {"tool_calls": [{"id": "c"}]}}],
            "usage": {},
        }
        http_stub(responses=[_json_response(payload)])

        response = await OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o").generate("x")

        assert response.tool_calls[0].name == ""
        assert response.tool_calls[0].arguments == {}

    async def test_response_with_no_choices_is_an_error_not_empty_text(self, http_stub):
        http_stub(responses=[_json_response({"model": "gpt-4o", "choices": []})])

        with pytest.raises(ConnectorError, match="missing_choices"):
            await OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o").generate("x")


class TestOpenAIFailureContract:
    async def test_401_raises_auth_error_without_retrying(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({"error": "nope"}, 401)])

        with pytest.raises(ConnectorAuthError):
            await OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o").generate("x")

        assert stub.call_count == 1, "bad credentials are permanent; retrying wastes quota"
        assert fast_sleep == []

    @pytest.mark.parametrize("status", [400, 404, 422])
    async def test_non_retryable_4xx_fails_on_first_attempt(self, http_stub, fast_sleep, status):
        stub = http_stub(responses=[_json_response({"error": "bad"}, status)])

        with pytest.raises(ConnectorError) as excinfo:
            await OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o").generate("x")

        assert stub.call_count == 1
        assert not isinstance(excinfo.value, ConnectorTransientError)
        assert str(status) in str(excinfo.value)

    async def test_429_retries_to_the_limit_then_surfaces_retry_after(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 429, **{"retry-after": "2.5"})])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o", max_retries=2)

        with pytest.raises(ConnectorRateLimitError) as excinfo:
            await connector.generate("x")

        assert stub.call_count == 3, "initial attempt plus max_retries"
        assert excinfo.value.retry_after_s == 2.5
        assert fast_sleep == [2.5, 2.5], "provider's retry-after must override our backoff"

    async def test_unparseable_retry_after_falls_back_to_computed_backoff(
        self, http_stub, fast_sleep
    ):
        stub = http_stub(responses=[_json_response({}, 429, **{"retry-after": "Wed, 21 Oct"})])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o", max_retries=1)

        with pytest.raises(ConnectorRateLimitError) as excinfo:
            await connector.generate("x")

        assert stub.call_count == 2
        assert excinfo.value.retry_after_s is None
        assert fast_sleep and fast_sleep[0] >= 1.0

    async def test_missing_retry_after_header_yields_none(self, http_stub, fast_sleep):
        http_stub(responses=[_json_response({}, 429)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o", max_retries=0)

        with pytest.raises(ConnectorRateLimitError) as excinfo:
            await connector.generate("x")

        assert excinfo.value.retry_after_s is None

    async def test_5xx_retries_then_raises_transient(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 503)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o", max_retries=2)

        with pytest.raises(ConnectorTransientError, match="503"):
            await connector.generate("x")

        assert stub.call_count == 3
        assert fast_sleep == pytest.approx([1.0, 2.0], rel=0.3), "backoff must grow"

    async def test_transient_5xx_then_success_returns_the_success(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 500), _json_response(OPENAI_OK)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o", max_retries=3)

        response = await connector.generate("x")

        assert response.text == "hello"
        assert stub.call_count == 2

    async def test_timeout_retries_then_raises_transient(self, http_stub, fast_sleep):
        stub = http_stub(responses=[httpx.TimeoutException("timed out")])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o", max_retries=1)

        with pytest.raises(ConnectorTransientError, match="timeout"):
            await connector.generate("x")

        assert stub.call_count == 2

    async def test_connection_error_retries_then_raises_transient(self, http_stub, fast_sleep):
        stub = http_stub(responses=[httpx.ConnectError("refused")])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o", max_retries=1)

        with pytest.raises(ConnectorTransientError, match="request_error"):
            await connector.generate("x")

        assert stub.call_count == 2

    async def test_zero_retries_means_exactly_one_attempt(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 500)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o", max_retries=0)

        with pytest.raises(ConnectorTransientError):
            await connector.generate("x")

        assert stub.call_count == 1
        assert fast_sleep == []

    async def test_negative_retry_count_is_clamped_not_infinite(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 500)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o", max_retries=-5)

        with pytest.raises(ConnectorTransientError):
            await connector.generate("x")

        assert stub.call_count == 1

    async def test_error_body_is_truncated_so_a_provider_cannot_flood_our_logs(self, http_stub):
        stub = http_stub(responses=[httpx.Response(400, content=b"E" * 10_000)])

        with pytest.raises(ConnectorError) as excinfo:
            await OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o").generate("x")

        assert stub.call_count == 1
        assert len(str(excinfo.value)) < 700


class TestOpenAIConfigContract:
    @pytest.mark.parametrize(
        ("kwargs", "expected"),
        [
            ({"api_key_ref": "", "model": "gpt-4o"}, "api_key_ref"),
            ({"api_key_ref": API_KEY_REF, "model": ""}, "model"),
        ],
    )
    def test_missing_required_config_fails_at_construction(self, kwargs, expected):
        with pytest.raises(ConnectorConfigError, match=expected):
            OpenAIConnector(**kwargs)

    async def test_unresolvable_secret_reference_is_a_config_error_not_an_auth_error(
        self, http_stub
    ):
        """An operator typo must not look like a rejected credential."""
        http_stub(responses=[_json_response(OPENAI_OK)])
        connector = OpenAIConnector(api_key_ref="env:NO_SUCH_VAR_FOR_TESTS", model="gpt-4o")

        with pytest.raises(ConnectorConfigError, match="NO_SUCH_VAR_FOR_TESTS"):
            await connector.generate("x")

    async def test_resolved_key_is_cached_across_calls(self, http_stub, monkeypatch):
        http_stub(responses=[_json_response(OPENAI_OK)])
        connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o")
        await connector.generate("first")

        # The reference stops resolving; the already-resolved key must hold.
        monkeypatch.delenv(API_KEY_ENV)
        await connector.generate("second")

    async def test_config_error_message_does_not_leak_the_resolved_secret(self, http_stub):
        class LeakyResolver:
            prefix = "env:"

            def resolve(self, reference: str) -> str:
                raise SecretResolutionError("backend unavailable")

        previous = get_resolver()
        set_resolver(LeakyResolver())
        try:
            connector = OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o")
            with pytest.raises(ConnectorConfigError) as excinfo:
                await connector.generate("x")
            assert FAKE_KEY not in str(excinfo.value)
        finally:
            set_resolver(previous)


class TestOpenAIHealthCheck:
    async def test_health_check_hits_models_and_returns_true(self, http_stub):
        stub = http_stub(responses=[_json_response({"data": []})])

        assert await OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o").health_check() is True
        assert str(stub.last_request.url).endswith("/models")
        assert stub.last_request.method == "GET"

    async def test_health_check_401_is_an_auth_error(self, http_stub):
        http_stub(responses=[_json_response({}, 401)])
        with pytest.raises(ConnectorAuthError):
            await OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o").health_check()

    async def test_health_check_other_failure_is_a_generic_error(self, http_stub):
        http_stub(responses=[_json_response({}, 500)])
        with pytest.raises(ConnectorError, match="health_check_failed"):
            await OpenAIConnector(api_key_ref=API_KEY_REF, model="gpt-4o").health_check()


# ───────────────────────────────────────────────────────── Anthropic


ANTHROPIC_OK: dict[str, object] = {
    "model": "claude-sonnet-4-20260101",
    "content": [{"type": "text", "text": "hi"}],
    "usage": {"input_tokens": 1_000_000, "output_tokens": 1_000_000},
}


class TestAnthropicRequestContract:
    async def test_system_prompt_is_a_top_level_field_not_a_message_role(self, http_stub):
        stub = http_stub(responses=[_json_response(ANTHROPIC_OK)])
        connector = AnthropicConnector(api_key_ref=API_KEY_REF, model="claude-sonnet-4")

        await connector.generate("hello", system_prompt="be terse", max_tokens=32)

        body = json.loads(stub.last_request.content)
        assert body["system"] == "be terse"
        assert body["messages"] == [{"role": "user", "content": "hello"}]
        assert body["max_tokens"] == 32

    async def test_system_field_absent_when_no_system_prompt(self, http_stub):
        stub = http_stub(responses=[_json_response(ANTHROPIC_OK)])
        await AnthropicConnector(api_key_ref=API_KEY_REF, model="claude-sonnet-4").generate("hi")
        assert "system" not in json.loads(stub.last_request.content)

    async def test_auth_uses_x_api_key_and_a_pinned_api_version(self, http_stub):
        stub = http_stub(responses=[_json_response(ANTHROPIC_OK)])
        connector = AnthropicConnector(
            api_key_ref=API_KEY_REF, model="claude-sonnet-4", api_version="2026-01-01"
        )

        await connector.generate("hi")

        assert stub.last_request.headers["x-api-key"] == FAKE_KEY
        assert stub.last_request.headers["anthropic-version"] == "2026-01-01"
        assert "authorization" not in stub.last_request.headers
        assert str(stub.last_request.url).endswith("/messages")

    async def test_openai_shaped_tools_are_translated_to_input_schema(self, http_stub):
        stub = http_stub(responses=[_json_response(ANTHROPIC_OK)])
        connector = AnthropicConnector(api_key_ref=API_KEY_REF, model="claude-sonnet-4")
        schema = {"type": "object", "properties": {"q": {"type": "string"}}}

        await connector.generate_with_tools(
            [{"role": "user", "content": "go"}],
            [
                {
                    "type": "function",
                    "function": {"name": "search", "description": "d", "parameters": schema},
                }
            ],
            system_prompt="sys",
        )

        body = json.loads(stub.last_request.content)
        assert body["tools"] == [{"name": "search", "description": "d", "input_schema": schema}]
        assert body["system"] == "sys"

    async def test_already_anthropic_shaped_tools_pass_through_unchanged(self, http_stub):
        stub = http_stub(responses=[_json_response(ANTHROPIC_OK)])
        native = {"name": "run", "description": "d", "input_schema": {"type": "object"}}

        await AnthropicConnector(
            api_key_ref=API_KEY_REF, model="claude-sonnet-4"
        ).generate_with_tools([{"role": "user", "content": "go"}], [native])

        assert json.loads(stub.last_request.content)["tools"] == [native]

    async def test_tool_without_schema_gets_an_empty_object_schema(self, http_stub):
        stub = http_stub(responses=[_json_response(ANTHROPIC_OK)])

        await AnthropicConnector(
            api_key_ref=API_KEY_REF, model="claude-sonnet-4"
        ).generate_with_tools([{"role": "user", "content": "go"}], [{"name": "bare"}])

        assert json.loads(stub.last_request.content)["tools"] == [
            {
                "name": "bare",
                "description": "",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]


class TestAnthropicResponseContract:
    async def test_text_blocks_concatenate_and_cost_uses_the_prefix_rate(self, http_stub):
        payload = dict(
            ANTHROPIC_OK,
            content=[{"type": "text", "text": "a"}, {"type": "text", "text": "b"}],
        )
        http_stub(responses=[_json_response(payload)])

        response = await AnthropicConnector(
            api_key_ref=API_KEY_REF, model="claude-sonnet-4"
        ).generate("x")

        assert response.text == "ab"
        # claude-sonnet-4: $3 in + $15 out per million.
        assert response.cost_usd == pytest.approx(18.0)

    async def test_tool_use_blocks_become_tool_calls_and_unknown_blocks_are_ignored(
        self, http_stub
    ):
        payload = dict(
            ANTHROPIC_OK,
            content=[
                {"type": "text", "text": "thinking"},
                {"type": "tool_use", "id": "tu_1", "name": "search", "input": {"q": "ai"}},
                {"type": "some_future_block_type", "value": 1},
            ],
        )
        http_stub(responses=[_json_response(payload)])

        response = await AnthropicConnector(
            api_key_ref=API_KEY_REF, model="claude-sonnet-4"
        ).generate("x")

        assert response.text == "thinking"
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].name == "search"
        assert response.tool_calls[0].arguments == {"q": "ai"}

    async def test_empty_content_array_yields_empty_text_not_an_error(self, http_stub):
        http_stub(responses=[_json_response(dict(ANTHROPIC_OK, content=[]))])

        response = await AnthropicConnector(
            api_key_ref=API_KEY_REF, model="claude-sonnet-4"
        ).generate("x")

        assert response.text == ""
        assert response.tool_calls == ()

    async def test_unpriced_model_reports_zero_cost(self, http_stub):
        http_stub(responses=[_json_response(dict(ANTHROPIC_OK, model="claude-future-9"))])

        response = await AnthropicConnector(
            api_key_ref=API_KEY_REF, model="claude-future-9"
        ).generate("x")

        assert response.cost_usd == 0.0


class TestAnthropicFailureContract:
    async def test_401_raises_auth_error_without_retrying(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 401)])

        with pytest.raises(ConnectorAuthError):
            await AnthropicConnector(api_key_ref=API_KEY_REF, model="claude-sonnet-4").generate("x")

        assert stub.call_count == 1

    async def test_429_retries_then_surfaces_retry_after(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 429, **{"retry-after": "7"})])
        connector = AnthropicConnector(
            api_key_ref=API_KEY_REF, model="claude-sonnet-4", max_retries=1
        )

        with pytest.raises(ConnectorRateLimitError) as excinfo:
            await connector.generate("x")

        assert stub.call_count == 2
        assert excinfo.value.retry_after_s == 7.0

    async def test_429_with_unparseable_retry_after_reports_none(self, http_stub, fast_sleep):
        http_stub(responses=[_json_response({}, 429, **{"retry-after": "soon"})])
        connector = AnthropicConnector(
            api_key_ref=API_KEY_REF, model="claude-sonnet-4", max_retries=0
        )

        with pytest.raises(ConnectorRateLimitError) as excinfo:
            await connector.generate("x")

        assert excinfo.value.retry_after_s is None

    async def test_5xx_retries_then_raises_transient(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 529)])
        connector = AnthropicConnector(
            api_key_ref=API_KEY_REF, model="claude-sonnet-4", max_retries=2
        )

        with pytest.raises(ConnectorTransientError, match="529"):
            await connector.generate("x")

        assert stub.call_count == 3

    async def test_5xx_then_success_returns_the_success(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 500), _json_response(ANTHROPIC_OK)])

        response = await AnthropicConnector(
            api_key_ref=API_KEY_REF, model="claude-sonnet-4", max_retries=2
        ).generate("x")

        assert response.text == "hi"
        assert stub.call_count == 2

    async def test_timeout_and_request_errors_are_transient(self, http_stub, fast_sleep):
        http_stub(responses=[httpx.TimeoutException("slow")])
        with pytest.raises(ConnectorTransientError, match="timeout"):
            await AnthropicConnector(
                api_key_ref=API_KEY_REF, model="claude-sonnet-4", max_retries=0
            ).generate("x")

        http_stub(responses=[httpx.ConnectError("refused")])
        with pytest.raises(ConnectorTransientError, match="request_error"):
            await AnthropicConnector(
                api_key_ref=API_KEY_REF, model="claude-sonnet-4", max_retries=0
            ).generate("x")

    async def test_other_4xx_is_terminal(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({"error": "bad request"}, 400)])

        with pytest.raises(ConnectorError, match="400"):
            await AnthropicConnector(api_key_ref=API_KEY_REF, model="claude-sonnet-4").generate("x")

        assert stub.call_count == 1

    @pytest.mark.parametrize(
        ("kwargs", "expected"),
        [
            ({"api_key_ref": "", "model": "claude-sonnet-4"}, "api_key_ref"),
            ({"api_key_ref": API_KEY_REF, "model": ""}, "model"),
        ],
    )
    def test_missing_required_config_fails_at_construction(self, kwargs, expected):
        with pytest.raises(ConnectorConfigError, match=expected):
            AnthropicConnector(**kwargs)

    async def test_unresolvable_reference_is_a_config_error(self, http_stub):
        http_stub(responses=[_json_response(ANTHROPIC_OK)])
        connector = AnthropicConnector(api_key_ref="env:NOPE_NOT_SET", model="claude-sonnet-4")

        with pytest.raises(ConnectorConfigError):
            await connector.generate("x")


class TestAnthropicHealthCheck:
    async def test_health_check_is_a_single_token_round_trip(self, http_stub):
        stub = http_stub(responses=[_json_response(ANTHROPIC_OK)])

        assert (
            await AnthropicConnector(
                api_key_ref=API_KEY_REF, model="claude-sonnet-4"
            ).health_check()
            is True
        )
        body = json.loads(stub.last_request.content)
        assert body["max_tokens"] == 1, "a health check must not be able to burn real budget"

    async def test_health_check_401_is_an_auth_error(self, http_stub):
        http_stub(responses=[_json_response({}, 401)])
        with pytest.raises(ConnectorAuthError):
            await AnthropicConnector(
                api_key_ref=API_KEY_REF, model="claude-sonnet-4"
            ).health_check()

    async def test_health_check_other_status_is_a_generic_error(self, http_stub):
        http_stub(responses=[_json_response({}, 503)])
        with pytest.raises(ConnectorError, match="health_check_failed"):
            await AnthropicConnector(
                api_key_ref=API_KEY_REF, model="claude-sonnet-4"
            ).health_check()


# ───────────────────────────────────────────────────────── Azure OpenAI


AZURE_OK: dict[str, object] = {
    "choices": [{"message": {"content": "azure hello"}}],
    "usage": {"prompt_tokens": 1_000_000, "completion_tokens": 0},
}


def _azure(**overrides: object) -> AzureOpenAIConnector:
    kwargs: dict[str, object] = {
        "endpoint": "https://contoso.openai.azure.com/",
        "deployment_name": "prod-gpt4o",
        "api_key_ref": API_KEY_REF,
    }
    kwargs.update(overrides)
    return AzureOpenAIConnector(**kwargs)  # type: ignore[arg-type]


class TestAzureOpenAIContract:
    async def test_url_carries_the_deployment_and_api_version(self, http_stub):
        stub = http_stub(responses=[_json_response(AZURE_OK)])

        await _azure(api_version="2026-01-01").generate("x")

        assert str(stub.last_request.url) == (
            "https://contoso.openai.azure.com/openai/deployments/prod-gpt4o"
            "/chat/completions?api-version=2026-01-01"
        )

    async def test_auth_uses_api_key_header_not_bearer(self, http_stub):
        stub = http_stub(responses=[_json_response(AZURE_OK)])

        await _azure().generate("x")

        assert stub.last_request.headers["api-key"] == FAKE_KEY
        assert "authorization" not in stub.last_request.headers

    async def test_body_omits_model_because_the_deployment_selects_it(self, http_stub):
        stub = http_stub(responses=[_json_response(AZURE_OK)])

        await _azure().generate("hi", system_prompt="sys", max_tokens=8)

        body = json.loads(stub.last_request.content)
        assert "model" not in body
        assert body["messages"][0] == {"role": "system", "content": "sys"}
        assert body["max_tokens"] == 8

    async def test_response_model_is_the_deployment_alias(self, http_stub):
        http_stub(responses=[_json_response(AZURE_OK)])

        response = await _azure().generate("x")

        assert response.model == "prod-gpt4o"
        assert response.text == "azure hello"

    async def test_pricing_falls_back_to_the_deployment_name(self, http_stub):
        """An alias nobody priced must cost 0, not be billed as some other model."""
        http_stub(responses=[_json_response(AZURE_OK)])

        response = await _azure().generate("x")

        assert response.cost_usd == 0.0

    async def test_model_for_pricing_override_selects_the_real_rate(self, http_stub):
        http_stub(responses=[_json_response(AZURE_OK)])

        response = await _azure(model_for_pricing="gpt-4o").generate("x")

        assert response.cost_usd == pytest.approx(2.50)

    async def test_tools_are_forwarded_with_auto_choice(self, http_stub):
        stub = http_stub(responses=[_json_response(AZURE_OK)])
        tools = [{"type": "function", "function": {"name": "f", "parameters": {}}}]

        await _azure().generate_with_tools([{"role": "user", "content": "go"}], tools)

        body = json.loads(stub.last_request.content)
        assert body["tools"] == tools and body["tool_choice"] == "auto"

    async def test_generate_with_tools_without_tools_sends_messages_only(self, http_stub):
        stub = http_stub(responses=[_json_response(AZURE_OK)])

        await _azure().generate_with_tools(
            [{"role": "user", "content": "go"}], [], system_prompt="sys"
        )

        body = json.loads(stub.last_request.content)
        assert "tools" not in body
        assert body["messages"][0]["role"] == "system"

    async def test_tool_calls_are_parsed_with_the_openai_shape(self, http_stub):
        payload = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {"id": "c1", "function": {"name": "f", "arguments": '{"a": 1}'}}
                        ]
                    }
                }
            ],
            "usage": {},
        }
        http_stub(responses=[_json_response(payload)])

        response = await _azure().generate("x")

        assert response.tool_calls[0].arguments == {"a": 1}

    async def test_missing_choices_is_an_error(self, http_stub):
        http_stub(responses=[_json_response({"choices": []})])
        with pytest.raises(ConnectorError, match="missing_choices"):
            await _azure().generate("x")

    @pytest.mark.parametrize(
        ("overrides", "expected"),
        [
            ({"endpoint": ""}, "endpoint"),
            ({"deployment_name": ""}, "deployment_name"),
            ({"api_key_ref": ""}, "api_key_ref"),
        ],
    )
    def test_missing_required_config_fails_at_construction(self, overrides, expected):
        with pytest.raises(ConnectorConfigError, match=expected):
            _azure(**overrides)

    async def test_401_does_not_retry(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 401)])
        with pytest.raises(ConnectorAuthError):
            await _azure().generate("x")
        assert stub.call_count == 1

    async def test_429_retries_then_reports_retry_after(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 429, **{"retry-after": "3"})])

        with pytest.raises(ConnectorRateLimitError) as excinfo:
            await _azure(max_retries=1).generate("x")

        assert stub.call_count == 2
        assert excinfo.value.retry_after_s == 3.0

    async def test_429_without_header_reports_no_retry_after(self, http_stub, fast_sleep):
        http_stub(responses=[_json_response({}, 429)])
        with pytest.raises(ConnectorRateLimitError) as excinfo:
            await _azure(max_retries=0).generate("x")
        assert excinfo.value.retry_after_s is None

    async def test_5xx_retries_then_transient_and_recovery_succeeds(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 500)])
        with pytest.raises(ConnectorTransientError, match="500"):
            await _azure(max_retries=1).generate("x")
        assert stub.call_count == 2

        stub2 = http_stub(responses=[_json_response({}, 502), _json_response(AZURE_OK)])
        assert (await _azure(max_retries=2).generate("x")).text == "azure hello"
        assert stub2.call_count == 2

    async def test_timeout_and_connect_errors_are_transient(self, http_stub, fast_sleep):
        http_stub(responses=[httpx.TimeoutException("slow")])
        with pytest.raises(ConnectorTransientError, match="timeout"):
            await _azure(max_retries=0).generate("x")

        http_stub(responses=[httpx.ConnectError("refused")])
        with pytest.raises(ConnectorTransientError, match="request_error"):
            await _azure(max_retries=0).generate("x")

    async def test_other_4xx_is_terminal(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 403)])
        with pytest.raises(ConnectorError, match="403"):
            await _azure().generate("x")
        assert stub.call_count == 1

    async def test_unresolvable_reference_is_a_config_error(self, http_stub):
        http_stub(responses=[_json_response(AZURE_OK)])
        with pytest.raises(ConnectorConfigError):
            await _azure(api_key_ref="env:AZURE_REF_NOT_SET").generate("x")

    async def test_health_check_true_401_and_other(self, http_stub):
        stub = http_stub(responses=[_json_response(AZURE_OK)])
        assert await _azure().health_check() is True
        assert json.loads(stub.last_request.content)["max_tokens"] == 1

        http_stub(responses=[_json_response({}, 401)])
        with pytest.raises(ConnectorAuthError):
            await _azure().health_check()

        http_stub(responses=[_json_response({}, 500)])
        with pytest.raises(ConnectorError, match="health_check_failed"):
            await _azure().health_check()


# ───────────────────────────────────────────────────────── Ollama


OLLAMA_OK: dict[str, object] = {
    "model": "llama3.1",
    "message": {"content": "local hello"},
    "prompt_eval_count": 12,
    "eval_count": 34,
}


class TestOllamaContract:
    async def test_self_hosted_inference_is_never_billed(self, http_stub):
        """Cost is the customer's hardware, not ours. Zero is a contract."""
        http_stub(responses=[_json_response(OLLAMA_OK)])

        response = await OllamaConnector(model="llama3.1").generate("x")

        assert response.cost_usd == 0.0
        assert response.input_tokens == 12
        assert response.output_tokens == 34
        assert response.text == "local hello"

    async def test_no_credential_is_sent_to_a_local_daemon(self, http_stub):
        stub = http_stub(responses=[_json_response(OLLAMA_OK)])

        await OllamaConnector(model="llama3.1").generate("x")

        assert "authorization" not in stub.last_request.headers
        assert "x-api-key" not in stub.last_request.headers

    async def test_request_disables_streaming_and_carries_sampling_options(self, http_stub):
        stub = http_stub(responses=[_json_response(OLLAMA_OK)])

        await OllamaConnector(model="llama3.1").generate(
            "hi", system_prompt="sys", temperature=0.7, max_tokens=99
        )

        body = json.loads(stub.last_request.content)
        assert str(stub.last_request.url) == "http://localhost:11434/api/chat"
        assert body["stream"] is False
        assert body["options"] == {"temperature": 0.7, "num_predict": 99}
        assert body["messages"][0] == {"role": "system", "content": "sys"}

    async def test_base_url_override_strips_trailing_slash(self, http_stub):
        stub = http_stub(responses=[_json_response(OLLAMA_OK)])

        await OllamaConnector(model="llama3.1", base_url="http://gpu-box:11434/").generate("x")

        assert str(stub.last_request.url) == "http://gpu-box:11434/api/chat"

    async def test_tool_calls_use_the_nested_function_shape(self, http_stub):
        payload = dict(
            OLLAMA_OK,
            message={
                "content": "",
                "tool_calls": [{"id": 7, "function": {"name": "search", "arguments": {"q": "ai"}}}],
            },
        )
        http_stub(responses=[_json_response(payload)])

        response = await OllamaConnector(model="llama3.1").generate("x")

        assert response.tool_calls[0].id == "7"
        assert response.tool_calls[0].name == "search"
        assert response.tool_calls[0].arguments == {"q": "ai"}

    async def test_generate_with_tools_forwards_tools_and_respects_caller_system_turn(
        self, http_stub
    ):
        stub = http_stub(responses=[_json_response(OLLAMA_OK)])
        tools = [{"type": "function", "function": {"name": "f"}}]

        await OllamaConnector(model="llama3.1").generate_with_tools(
            [{"role": "system", "content": "caller"}, {"role": "user", "content": "go"}],
            tools,
            system_prompt="adapter",
        )

        body = json.loads(stub.last_request.content)
        assert body["tools"] == tools
        assert [m["role"] for m in body["messages"]].count("system") == 1
        assert body["messages"][0]["content"] == "caller"

    async def test_generate_with_tools_omits_tools_when_none_given(self, http_stub):
        stub = http_stub(responses=[_json_response(OLLAMA_OK)])

        await OllamaConnector(model="llama3.1").generate_with_tools(
            [{"role": "user", "content": "go"}], [], system_prompt="adapter"
        )

        body = json.loads(stub.last_request.content)
        assert "tools" not in body
        assert body["messages"][0]["role"] == "system"

    async def test_5xx_retries_then_raises_transient(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 500)])

        with pytest.raises(ConnectorTransientError, match="500"):
            await OllamaConnector(model="llama3.1", max_retries=1).generate("x")

        assert stub.call_count == 2

    async def test_5xx_then_success_recovers(self, http_stub, fast_sleep):
        stub = http_stub(responses=[_json_response({}, 503), _json_response(OLLAMA_OK)])

        response = await OllamaConnector(model="llama3.1", max_retries=1).generate("x")

        assert response.text == "local hello"
        assert stub.call_count == 2

    async def test_connection_refused_retries_then_raises_transient(self, http_stub, fast_sleep):
        stub = http_stub(responses=[httpx.ConnectError("daemon down")])

        with pytest.raises(ConnectorTransientError, match="request_error"):
            await OllamaConnector(model="llama3.1", max_retries=1).generate("x")

        assert stub.call_count == 2
        assert fast_sleep, "a local daemon restart deserves at least one backoff"

    async def test_4xx_is_terminal(self, http_stub, fast_sleep):
        stub = http_stub(responses=[httpx.Response(404, content=b"model not found")])

        with pytest.raises(ConnectorError, match="404"):
            await OllamaConnector(model="llama3.1").generate("x")

        assert stub.call_count == 1

    def test_model_is_required(self):
        with pytest.raises(ConnectorConfigError, match="model"):
            OllamaConnector(model="")

    async def test_health_check_probes_tags_without_pulling_a_model(self, http_stub):
        stub = http_stub(responses=[_json_response({"models": []})])

        assert await OllamaConnector(model="llama3.1").health_check() is True
        assert str(stub.last_request.url).endswith("/api/tags")
        assert stub.last_request.method == "GET"

    async def test_health_check_reports_an_unreachable_daemon(self, http_stub):
        http_stub(responses=[httpx.ConnectError("no daemon")])

        with pytest.raises(ConnectorError, match="unreachable"):
            await OllamaConnector(model="llama3.1").health_check()

    async def test_health_check_reports_a_failing_daemon(self, http_stub):
        http_stub(responses=[_json_response({}, 500)])

        with pytest.raises(ConnectorError, match="health_check_failed"):
            await OllamaConnector(model="llama3.1").health_check()
