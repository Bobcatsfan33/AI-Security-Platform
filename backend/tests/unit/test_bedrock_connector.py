"""Bedrock adapter: family dispatch, cost, and error classification.

Bedrock is the odd connector out. It has no HTTP seam of its own — boto3
owns the wire — and one API fronts several incompatible model families, so
the adapter has to pick a request shape and a response parser from the model
ID alone. Two things follow that nothing else in the suite checks:

1. **Family dispatch is a correctness boundary.** Sending a Llama body to a
   Claude model (or parsing a Llama response as Claude) does not raise — it
   silently produces empty text and zero tokens, which the evaluation runner
   would record as a passing, free run.
2. **Error classification is string matching over botocore exceptions.**
   Bedrock reports throttling, authorization, and outage through exception
   text, and the adapter's job is to turn that into the platform's retryable
   vs terminal distinction. If ``Throttling`` stopped mapping to
   ``ConnectorRateLimitError`` the caller would give up instead of backing
   off, and vice versa a permanent ``AccessDenied`` would be retried forever.

The fake client below is deliberately dumb: it records the exact kwargs the
adapter passed to ``invoke_model`` so the request shape is asserted from
what would really have gone to AWS.
"""

from __future__ import annotations

import io
import json
import sys
from typing import Any

import pytest

from app.connectors.base import (
    ConnectorAuthError,
    ConnectorConfigError,
    ConnectorError,
    ConnectorRateLimitError,
    ConnectorTransientError,
)
from app.connectors.bedrock_connector import BedrockConnector, _family_of
from app.security.secrets import SecretResolutionError, get_resolver, set_resolver

pytestmark = pytest.mark.unit


class FakeBedrockClient:
    """Stands in for a boto3 bedrock-runtime client."""

    def __init__(self, *, payload: dict[str, Any] | None = None, error: Exception | None = None):
        self._payload = payload if payload is not None else {}
        self._error = error
        self.invocations: list[dict[str, Any]] = []
        self.list_models_called = 0

    def invoke_model(self, **kwargs: Any) -> dict[str, Any]:
        self.invocations.append(kwargs)
        if self._error is not None:
            raise self._error
        return {"body": io.BytesIO(json.dumps(self._payload).encode())}

    def list_foundation_models(self) -> dict[str, Any]:
        self.list_models_called += 1
        if self._error is not None:
            raise self._error
        return {"modelSummaries": []}


@pytest.fixture
def fake_boto3(monkeypatch: pytest.MonkeyPatch):
    """Install a fake ``boto3.client`` and record how it was constructed."""
    import boto3

    calls: list[tuple[str, dict[str, Any]]] = []
    holder: dict[str, FakeBedrockClient] = {}

    def install(**client_kwargs: Any) -> FakeBedrockClient:
        client = FakeBedrockClient(**client_kwargs)
        holder["client"] = client

        def fake_client(service: str, **kwargs: Any) -> FakeBedrockClient:
            calls.append((service, kwargs))
            return client

        monkeypatch.setattr(boto3, "client", fake_client)
        return client

    install.calls = calls  # type: ignore[attr-defined]
    return install


ANTHROPIC_PAYLOAD: dict[str, Any] = {
    "content": [{"type": "text", "text": "claude on bedrock"}],
    "usage": {"input_tokens": 1_000_000, "output_tokens": 1_000_000},
}
META_PAYLOAD: dict[str, Any] = {
    "generation": "llama on bedrock",
    "prompt_token_count": 1_000_000,
    "generation_token_count": 1_000_000,
}


class TestFamilyDispatch:
    @pytest.mark.parametrize(
        ("model_id", "family"),
        [
            ("anthropic.claude-sonnet-4-v1:0", "anthropic"),
            ("meta.llama3-70b-instruct-v1:0", "meta"),
            ("amazon.titan-text-express-v1", "titan"),
            ("mistral.mistral-large-2402-v1:0", "mistral"),
            ("cohere.command-r-plus-v1:0", "cohere"),
            ("some.new-vendor-model", "unknown"),
        ],
    )
    def test_family_is_derived_from_the_model_id_prefix(self, model_id, family):
        assert _family_of(model_id) == family

    async def test_anthropic_family_sends_the_messages_body(self, fake_boto3):
        client = fake_boto3(payload=ANTHROPIC_PAYLOAD)
        connector = BedrockConnector(model="anthropic.claude-sonnet-4-v1:0")

        await connector.generate("hello", system_prompt="sys", max_tokens=64, temperature=0.3)

        sent = client.invocations[0]
        assert sent["modelId"] == "anthropic.claude-sonnet-4-v1:0"
        assert sent["contentType"] == "application/json"
        body = json.loads(sent["body"])
        assert body["anthropic_version"] == "bedrock-2023-05-31"
        assert body["messages"] == [{"role": "user", "content": "hello"}]
        assert body["system"] == "sys"
        assert body["max_tokens"] == 64 and body["temperature"] == 0.3

    async def test_anthropic_body_omits_system_when_not_supplied(self, fake_boto3):
        client = fake_boto3(payload=ANTHROPIC_PAYLOAD)

        await BedrockConnector(model="anthropic.claude-haiku-4-v1:0").generate("hi")

        assert "system" not in json.loads(client.invocations[0]["body"])

    async def test_meta_family_sends_the_completion_body_with_a_folded_system_prompt(
        self, fake_boto3
    ):
        client = fake_boto3(payload=META_PAYLOAD)
        connector = BedrockConnector(model="meta.llama3-70b-instruct-v1:0")

        await connector.generate("hello", system_prompt="sys", max_tokens=32)

        body = json.loads(client.invocations[0]["body"])
        assert body["prompt"] == "<|system|>sys\n<|user|>hello"
        assert body["max_gen_len"] == 32
        assert "messages" not in body

    async def test_meta_family_without_system_prompt_sends_the_prompt_verbatim(self, fake_boto3):
        client = fake_boto3(payload=META_PAYLOAD)

        await BedrockConnector(model="meta.llama3-1-8b-instruct-v1:0").generate("just this")

        assert json.loads(client.invocations[0]["body"])["prompt"] == "just this"

    @pytest.mark.parametrize(
        "model_id",
        ["amazon.titan-text-express-v1", "mistral.mistral-large-2402-v1:0", "unknown.model"],
    )
    async def test_unsupported_family_refuses_rather_than_sending_a_wrong_body(
        self, fake_boto3, model_id
    ):
        client = fake_boto3(payload={})

        with pytest.raises(ConnectorError, match="unsupported Bedrock model family"):
            await BedrockConnector(model=model_id).generate("x")

        assert client.invocations == [], "no request may reach AWS in an unknown shape"


class TestResponseParsing:
    async def test_anthropic_response_yields_text_tokens_and_bedrock_rate_cost(self, fake_boto3):
        fake_boto3(payload=ANTHROPIC_PAYLOAD)

        response = await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").generate("x")

        assert response.text == "claude on bedrock"
        assert response.model == "anthropic.claude-sonnet-4-v1:0"
        assert response.input_tokens == 1_000_000
        assert response.output_tokens == 1_000_000
        # Bedrock claude-sonnet-4: $3 in + $15 out per million.
        assert response.cost_usd == pytest.approx(18.0)

    async def test_anthropic_tool_use_blocks_become_tool_calls(self, fake_boto3):
        payload = dict(
            ANTHROPIC_PAYLOAD,
            content=[
                {"type": "text", "text": "using a tool"},
                {"type": "tool_use", "id": "tu_1", "name": "search", "input": {"q": "ai"}},
                {"type": "unrecognized", "x": 1},
            ],
        )
        fake_boto3(payload=payload)

        response = await BedrockConnector(model="anthropic.claude-opus-4-v1:0").generate("x")

        assert response.text == "using a tool"
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].arguments == {"q": "ai"}

    async def test_meta_response_uses_the_llama_token_counters(self, fake_boto3):
        fake_boto3(payload=META_PAYLOAD)

        response = await BedrockConnector(model="meta.llama3-70b-instruct-v1:0").generate("x")

        assert response.text == "llama on bedrock"
        assert response.input_tokens == 1_000_000
        assert response.output_tokens == 1_000_000
        assert response.tool_calls == ()
        # meta.llama3-70b: $2.65 in + $3.50 out per million.
        assert response.cost_usd == pytest.approx(6.15)

    async def test_meta_response_missing_generation_is_empty_text_not_none(self, fake_boto3):
        fake_boto3(payload={})

        response = await BedrockConnector(model="meta.llama3-8b-instruct-v1:0").generate("x")

        assert response.text == ""
        assert response.input_tokens == 0 and response.output_tokens == 0

    async def test_empty_anthropic_content_is_empty_text(self, fake_boto3):
        fake_boto3(payload={"content": [], "usage": {}})

        response = await BedrockConnector(model="anthropic.claude-3-haiku-v1:0").generate("x")

        assert response.text == "" and response.cost_usd == 0.0

    async def test_versioned_model_id_matches_the_longest_priced_prefix(self, fake_boto3):
        """`anthropic.claude-3-5-haiku-...` must not be billed as `claude-3-haiku`."""
        fake_boto3(payload=ANTHROPIC_PAYLOAD)

        response = await BedrockConnector(
            model="anthropic.claude-3-5-haiku-20241022-v1:0"
        ).generate("x")

        # claude-3-5-haiku: $1.00 + $5.00. claude-3-haiku would give 1.50.
        assert response.cost_usd == pytest.approx(6.0)

    async def test_unpriced_model_reports_zero_cost(self, fake_boto3):
        fake_boto3(payload=META_PAYLOAD)

        response = await BedrockConnector(model="meta.llama9-experimental").generate("x")

        assert response.cost_usd == 0.0


class TestToolCalling:
    async def test_tools_are_translated_and_sent_for_the_anthropic_family(self, fake_boto3):
        client = fake_boto3(payload=ANTHROPIC_PAYLOAD)
        connector = BedrockConnector(model="anthropic.claude-sonnet-4-v1:0")
        schema = {"type": "object", "properties": {"q": {"type": "string"}}}

        await connector.generate_with_tools(
            [{"role": "user", "content": "go"}],
            [{"function": {"name": "search", "description": "d", "parameters": schema}}],
            system_prompt="sys",
        )

        body = json.loads(client.invocations[0]["body"])
        assert body["tools"] == [{"name": "search", "description": "d", "input_schema": schema}]
        assert body["system"] == "sys"

    async def test_native_anthropic_tool_shape_passes_through(self, fake_boto3):
        client = fake_boto3(payload=ANTHROPIC_PAYLOAD)
        native = {"name": "run", "description": "d", "input_schema": {"type": "object"}}

        await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").generate_with_tools(
            [{"role": "user", "content": "go"}], [native]
        )

        assert json.loads(client.invocations[0]["body"])["tools"] == [native]

    async def test_tool_without_a_schema_gets_an_empty_object_schema(self, fake_boto3):
        client = fake_boto3(payload=ANTHROPIC_PAYLOAD)

        await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").generate_with_tools(
            [{"role": "user", "content": "go"}], [{"name": "bare"}]
        )

        assert json.loads(client.invocations[0]["body"])["tools"] == [
            {
                "name": "bare",
                "description": "",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]

    async def test_empty_tool_list_sends_no_tools_key(self, fake_boto3):
        client = fake_boto3(payload=ANTHROPIC_PAYLOAD)

        await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").generate_with_tools(
            [{"role": "user", "content": "go"}], []
        )

        body = json.loads(client.invocations[0]["body"])
        assert "tools" not in body and "system" not in body

    async def test_tool_calling_is_refused_for_non_anthropic_families(self, fake_boto3):
        client = fake_boto3(payload=META_PAYLOAD)

        with pytest.raises(ConnectorError, match="only supported via Anthropic"):
            await BedrockConnector(model="meta.llama3-70b-instruct-v1:0").generate_with_tools(
                [{"role": "user", "content": "go"}], [{"name": "f"}]
            )

        assert client.invocations == []


class TestErrorClassification:
    @pytest.mark.parametrize(
        ("message", "expected"),
        [
            ("ThrottlingException: rate exceeded", ConnectorRateLimitError),
            ("TooManyRequestsException", ConnectorRateLimitError),
            ("AccessDeniedException: not authorized", ConnectorAuthError),
            ("UnauthorizedOperation", ConnectorAuthError),
            ("ServiceUnavailableException", ConnectorTransientError),
            ("InternalServerException", ConnectorTransientError),
        ],
    )
    async def test_aws_error_text_maps_to_the_platform_taxonomy(
        self, fake_boto3, message, expected
    ):
        fake_boto3(error=RuntimeError(message))

        with pytest.raises(expected):
            await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").generate("x")

    async def test_an_unclassified_failure_is_a_plain_connector_error(self, fake_boto3):
        fake_boto3(error=RuntimeError("ValidationException: bad body"))

        with pytest.raises(ConnectorError) as excinfo:
            await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").generate("x")

        assert type(excinfo.value) is ConnectorError, "must not be silently retryable"
        assert "bedrock_invoke_failed" in str(excinfo.value)

    async def test_throttling_is_retryable_and_access_denied_is_not(self, fake_boto3):
        """The two classes the caller branches on must not collapse into one."""
        fake_boto3(error=RuntimeError("ThrottlingException"))
        with pytest.raises(ConnectorRateLimitError) as throttled:
            await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").generate("x")

        fake_boto3(error=RuntimeError("AccessDeniedException"))
        with pytest.raises(ConnectorAuthError) as denied:
            await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").generate("x")

        assert not isinstance(denied.value, ConnectorRateLimitError)
        assert not isinstance(throttled.value, ConnectorAuthError)


class TestClientConstruction:
    def test_model_is_required(self):
        with pytest.raises(ConnectorConfigError, match="model"):
            BedrockConnector(model="")

    async def test_region_is_passed_to_boto3_and_defaults_to_us_east_1(self, fake_boto3):
        fake_boto3(payload=ANTHROPIC_PAYLOAD)
        await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").generate("x")
        assert fake_boto3.calls[-1] == ("bedrock-runtime", {"region_name": "us-east-1"})

        fake_boto3(payload=ANTHROPIC_PAYLOAD)
        await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0", region="eu-west-1").generate(
            "x"
        )
        assert fake_boto3.calls[-1][1]["region_name"] == "eu-west-1"

    async def test_no_api_key_ref_leaves_boto3_on_its_default_credential_chain(self, fake_boto3):
        fake_boto3(payload=ANTHROPIC_PAYLOAD)

        await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").generate("x")

        _, kwargs = fake_boto3.calls[-1]
        assert set(kwargs) == {"region_name"}, "an IAM role must not be overridden by empty keys"

    async def test_static_credentials_reference_is_split_into_boto3_kwargs(
        self, fake_boto3, monkeypatch
    ):
        monkeypatch.setenv("TEST_BEDROCK_CREDS", "AKIAFAKE:secretpart:sessionpart")
        fake_boto3(payload=ANTHROPIC_PAYLOAD)

        await BedrockConnector(
            model="anthropic.claude-sonnet-4-v1:0", api_key_ref="env:TEST_BEDROCK_CREDS"
        ).generate("x")

        _, kwargs = fake_boto3.calls[-1]
        assert kwargs["aws_access_key_id"] == "AKIAFAKE"
        assert kwargs["aws_secret_access_key"] == "secretpart"
        assert kwargs["aws_session_token"] == "sessionpart"

    async def test_credentials_without_a_session_token_omit_it(self, fake_boto3, monkeypatch):
        monkeypatch.setenv("TEST_BEDROCK_CREDS", "AKIAFAKE:secretpart")
        fake_boto3(payload=ANTHROPIC_PAYLOAD)

        await BedrockConnector(
            model="anthropic.claude-sonnet-4-v1:0", api_key_ref="env:TEST_BEDROCK_CREDS"
        ).generate("x")

        assert "aws_session_token" not in fake_boto3.calls[-1][1]

    async def test_malformed_credentials_reference_is_ignored_rather_than_half_applied(
        self, fake_boto3, monkeypatch
    ):
        """A ref with no ':' cannot form a key pair; boto3 must keep its chain."""
        monkeypatch.setenv("TEST_BEDROCK_CREDS", "just-one-value")
        fake_boto3(payload=ANTHROPIC_PAYLOAD)

        await BedrockConnector(
            model="anthropic.claude-sonnet-4-v1:0", api_key_ref="env:TEST_BEDROCK_CREDS"
        ).generate("x")

        _, kwargs = fake_boto3.calls[-1]
        assert "aws_access_key_id" not in kwargs and "aws_secret_access_key" not in kwargs

    async def test_unresolvable_credentials_reference_is_a_config_error(self, fake_boto3):
        fake_boto3(payload=ANTHROPIC_PAYLOAD)

        with pytest.raises(ConnectorConfigError, match="could not resolve"):
            await BedrockConnector(
                model="anthropic.claude-sonnet-4-v1:0", api_key_ref="env:NOT_SET_ANYWHERE"
            ).generate("x")

    async def test_config_error_does_not_echo_the_resolved_credential(self, fake_boto3):
        class FailingResolver:
            prefix = "env:"

            def resolve(self, reference: str) -> str:
                raise SecretResolutionError("vault sealed")

        fake_boto3(payload=ANTHROPIC_PAYLOAD)
        previous = get_resolver()
        set_resolver(FailingResolver())
        try:
            with pytest.raises(ConnectorConfigError) as excinfo:
                await BedrockConnector(
                    model="anthropic.claude-sonnet-4-v1:0", api_key_ref="env:ANY"
                ).generate("x")
            assert "vault sealed" in str(excinfo.value)
        finally:
            set_resolver(previous)

    async def test_missing_boto3_is_reported_as_a_configuration_problem(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """Deployments that trim boto3 must get an actionable error, not ImportError."""
        monkeypatch.setitem(sys.modules, "boto3", None)

        with pytest.raises(ConnectorConfigError, match="boto3 required"):
            await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").generate("x")


class TestHealthCheck:
    async def test_health_check_lists_models_instead_of_burning_an_invocation(self, fake_boto3):
        client = fake_boto3(payload=ANTHROPIC_PAYLOAD)

        assert await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").health_check() is True
        assert client.list_models_called == 1
        assert client.invocations == []
        assert fake_boto3.calls[-1][0] == "bedrock", "control-plane API, not bedrock-runtime"

    @pytest.mark.parametrize("message", ["Unable to locate credentials", "AccessDeniedException"])
    async def test_credential_failures_surface_as_auth_errors(self, fake_boto3, message):
        fake_boto3(error=RuntimeError(message))

        with pytest.raises(ConnectorAuthError, match="unauthorized"):
            await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").health_check()

    async def test_other_failures_surface_as_generic_errors(self, fake_boto3):
        fake_boto3(error=RuntimeError("EndpointConnectionError"))

        with pytest.raises(ConnectorError, match="health_check_failed"):
            await BedrockConnector(model="anthropic.claude-sonnet-4-v1:0").health_check()
