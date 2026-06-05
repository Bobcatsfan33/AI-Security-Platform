"""Tests for platform self-observability (A4): metrics, middleware, tracing."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from app.observability import metrics as m
from app.observability.metrics import (
    EPA_EVENTS,
    record_narrative,
    record_signal,
    render,
)
from app.observability.middleware import MetricsMiddleware
from app.observability.tracing import setup_tracing, tracing_enabled

pytestmark = pytest.mark.unit


def _tiny_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(MetricsMiddleware)

    @app.get("/ping")
    def ping():
        return {"ok": True}

    @app.get("/boom")
    def boom():
        raise ValueError("kaboom")

    @app.get("/metrics", include_in_schema=False)
    def metrics_ep():
        body, ct = render()
        from starlette.responses import Response

        return Response(content=body, media_type=ct)

    return app


class TestMetricsRender:
    def test_render_returns_exposition(self):
        body, content_type = render()
        assert b"aisp_http_requests_total" in body or b"aisp_epa_events" in body
        assert "text/plain" in content_type

    def test_domain_counters_increment(self):
        before = EPA_EVENTS._value.get()
        EPA_EVENTS.inc()
        assert EPA_EVENTS._value.get() == before + 1
        record_signal("propagation_chain")
        record_narrative("critical")
        body, _ = render()
        assert b'aisp_epa_signals_emitted_total{kind="propagation_chain"}' in body
        assert b'aisp_narratives_written_total{severity="critical"}' in body


class TestMiddleware:
    def test_request_metrics_recorded(self):
        client = TestClient(_tiny_app())
        assert client.get("/ping").status_code == 200
        body = client.get("/metrics").content
        # The /ping request was counted with a 2xx status class.
        assert b'aisp_http_requests_total{method="GET",route="/ping",status="2xx"}' in body
        assert b"aisp_http_request_duration_seconds" in body

    def test_error_counted_as_5xx(self):
        client = TestClient(_tiny_app(), raise_server_exceptions=False)
        client.get("/boom")
        body = client.get("/metrics").content
        assert b'status="5xx"' in body


class TestTracing:
    def test_tracing_disabled_without_endpoint(self, monkeypatch):
        monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
        assert tracing_enabled() is False
        assert setup_tracing(FastAPI()) is False  # no-op, no crash

    def test_setup_tracing_never_raises_when_packages_missing(self, monkeypatch):
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
        # OTel packages aren't installed → returns False, doesn't raise.
        assert setup_tracing(FastAPI()) is False
