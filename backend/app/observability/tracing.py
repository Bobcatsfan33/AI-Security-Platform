"""Optional OpenTelemetry tracing bootstrap.

Distributed tracing across SDK → agent → control plane → EPA consumers. The
agent already propagates W3C ``traceparent`` + ``x-aisp-*`` causal headers
(Sprint 3), so spans stitch into the same trace.

OTel packages are NOT a hard dependency — they pull a heavy tree and most
deployments scrape Prometheus instead. ``setup_tracing`` is a no-op unless both
(a) ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set and (b) the OTel + FastAPI
instrumentation packages are installed. Install with:

    pip install opentelemetry-sdk opentelemetry-exporter-otlp \
        opentelemetry-instrumentation-fastapi
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("platform.observability.tracing")


def tracing_enabled() -> bool:
    return bool(os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))


def setup_tracing(app: Any, *, service_name: str = "ai-security-platform") -> bool:
    """Instrument the FastAPI app for OTLP tracing if configured + available.
    Returns True when tracing was wired, False otherwise. Never raises — a
    missing optional dep degrades to no tracing, not a crash."""
    if not tracing_enabled():
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logger.warning("otel_packages_missing_tracing_disabled")
        return False

    try:
        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app)
        logger.info("otel_tracing_enabled", extra={"service": service_name})
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("otel_tracing_setup_failed", extra={"error": str(exc)})
        return False
