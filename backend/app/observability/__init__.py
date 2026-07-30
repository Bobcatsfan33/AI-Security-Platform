"""Platform self-observability — Prometheus metrics + optional OTel tracing."""

from app.observability.metrics import (
    record_narrative,
    record_signal,
    render,
)
from app.observability.middleware import MetricsMiddleware
from app.observability.tracing import setup_tracing, tracing_enabled

__all__ = [
    "MetricsMiddleware",
    "record_narrative",
    "record_signal",
    "render",
    "setup_tracing",
    "tracing_enabled",
]
