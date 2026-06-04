"""Tests for connector base primitives: cost, latency, response shape (A2)."""

from __future__ import annotations

import time

import pytest

from app.connectors.base import (
    ConnectorAuthError,
    ConnectorError,
    ConnectorRateLimitError,
    ConnectorResponse,
    CostRate,
    LatencyTimer,
    ToolCall,
    calculate_cost,
)

pytestmark = pytest.mark.unit


class TestCost:
    def test_calculate_cost(self):
        rate = CostRate(input_per_million=3.0, output_per_million=15.0)
        cost = calculate_cost(input_tokens=1_000_000, output_tokens=1_000_000, rate=rate)
        assert cost == pytest.approx(18.0)

    def test_zero_tokens_zero_cost(self):
        rate = CostRate(input_per_million=3.0, output_per_million=15.0)
        assert calculate_cost(input_tokens=0, output_tokens=0, rate=rate) == 0.0


class TestLatencyTimer:
    def test_measures_elapsed(self):
        with LatencyTimer() as t:
            time.sleep(0.01)
        assert t.elapsed_ms >= 5

    def test_zero_before_use(self):
        t = LatencyTimer()
        assert t.elapsed_ms == 0


class TestResponseTypes:
    def test_response_holds_fields(self):
        r = ConnectorResponse(
            text="hi",
            model="gpt-4",
            input_tokens=10,
            output_tokens=5,
            latency_ms=100,
            cost_usd=0.01,
        )
        assert r.text == "hi" and r.tool_calls == ()

    def test_tool_call(self):
        tc = ToolCall(id="1", name="search", arguments={"q": "x"})
        assert tc.name == "search" and tc.arguments["q"] == "x"

    def test_error_hierarchy(self):
        assert issubclass(ConnectorAuthError, ConnectorError)
        assert issubclass(ConnectorRateLimitError, ConnectorError)

    def test_rate_limit_carries_retry_after(self):
        err = ConnectorRateLimitError("429", retry_after_s=2.5)
        assert err.retry_after_s == 2.5
