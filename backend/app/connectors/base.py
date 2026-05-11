"""Model connector abstraction.

Every supported AI provider (OpenAI, Anthropic, Ollama, Azure OpenAI,
Bedrock, generic OpenAI-compatible) implements the
:class:`ModelConnector` Protocol. The evaluation engine (Sprint 4+) and
the policy pipeline's Stage 3 LLM judge (Sprint 7) call connectors
through this interface; provider-specific authentication, request
formatting, response parsing, and cost calculation are isolated to the
concrete adapter.

ConnectorResponse normalizes the response shape across providers so
downstream code never branches on provider. Cost is tracked at the
connector level — every adapter implements ``estimate_cost`` against
its provider's published pricing table.

Credentials are resolved through :mod:`app.security.secrets`. Connector
configs reference secrets by reference (``env:OPENAI_API_KEY``,
``awssm:openai-prod-key``, ``vault:secret/openai``) rather than holding
plaintext.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


# ─────────────────────────────────────────────── Errors


class ConnectorError(Exception):
    """Base for all connector failures."""


class ConnectorConfigError(ConnectorError):
    """Raised when connector configuration is invalid (missing API key,
    bad endpoint URL, etc.)."""


class ConnectorAuthError(ConnectorError):
    """Raised when the provider rejects our credentials."""


class ConnectorRateLimitError(ConnectorError):
    """Raised when the provider returns 429 / quota exhausted."""

    def __init__(self, detail: str, *, retry_after_s: float | None = None) -> None:
        super().__init__(detail)
        self.retry_after_s = retry_after_s


class ConnectorTransientError(ConnectorError):
    """Raised on retryable errors (5xx, network timeout, etc.)."""


# ─────────────────────────────────────────────── Response


@dataclass(frozen=True)
class ToolCall:
    """One tool/function invocation requested by the model."""

    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ConnectorResponse:
    """Normalized response from any model connector.

    Fields are intentionally provider-agnostic. Provider-specific extras
    (e.g. Anthropic's stop_reason, OpenAI's logprobs) live in
    ``raw_response`` for callers that need them.
    """

    text: str
    model: str
    input_tokens: int
    output_tokens: int
    latency_ms: int
    cost_usd: float
    tool_calls: tuple[ToolCall, ...] = field(default_factory=tuple)
    raw_response: dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────── Protocol


@runtime_checkable
class ModelConnector(Protocol):
    """Implemented by every concrete provider adapter.

    Connectors are instantiated by the connector registry on demand.
    A connector's lifecycle is short — typically created for one
    evaluation run, used for many calls, then discarded. Adapters MAY
    cache an httpx client internally for the duration of their lifetime.
    """

    provider: str

    async def generate(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> ConnectorResponse:
        """Single-turn chat completion.

        Raises:
            ConnectorAuthError: bad credentials.
            ConnectorRateLimitError: 429 / quota.
            ConnectorTransientError: 5xx / network.
            ConnectorError: anything else.
        """
        ...

    async def generate_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        system_prompt: str | None = None,
    ) -> ConnectorResponse:
        """Multi-turn conversation with tool/function calling.

        ``messages`` follows the OpenAI chat-completions shape:
            [{"role": "user|assistant|tool", "content": str | None,
              "tool_calls": [...], "tool_call_id": str | None}]

        Adapters translate to provider-specific shapes internally.
        """
        ...

    async def health_check(self) -> bool:
        """Cheap reachability + auth check. Used by the registry's
        ``/v1/connectors/{id}/test`` endpoint to validate credentials
        at registration time."""
        ...


# ─────────────────────────────────────────────── Cost helpers


@dataclass(frozen=True)
class CostRate:
    """Per-million-token rates for one model. Both are USD."""

    input_per_million: float
    output_per_million: float


def calculate_cost(
    *, input_tokens: int, output_tokens: int, rate: CostRate
) -> float:
    return (
        (input_tokens / 1_000_000.0) * rate.input_per_million
        + (output_tokens / 1_000_000.0) * rate.output_per_million
    )


# ─────────────────────────────────────────────── Latency helper


class LatencyTimer:
    """Context manager that measures wall time in milliseconds.

    Usage:
        with LatencyTimer() as t:
            ... do work ...
        latency_ms = t.elapsed_ms
    """

    def __init__(self) -> None:
        self._start: float = 0.0
        self._elapsed_ms: int = 0

    @property
    def elapsed_ms(self) -> int:
        return self._elapsed_ms

    def __enter__(self) -> "LatencyTimer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_: Any) -> None:
        self._elapsed_ms = int((time.perf_counter() - self._start) * 1000)
