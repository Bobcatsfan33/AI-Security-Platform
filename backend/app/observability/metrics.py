"""Prometheus metrics for the control plane (A4 observability).

Golden-signal HTTP metrics plus domain metrics for the detection pipeline (EPA
events, signals, narratives). Exposed at /metrics; scraped by the ServiceMonitor
the Helm chart ships. Keep label cardinality bounded — route TEMPLATES, not raw
paths; metric KINDS, not per-flow ids.
"""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

# ── HTTP golden signals ───────────────────────────────────────────────────
HTTP_REQUESTS = Counter(
    "aisp_http_requests_total",
    "HTTP requests by method, route template, and status class.",
    ["method", "route", "status"],
)
HTTP_LATENCY = Histogram(
    "aisp_http_request_duration_seconds",
    "HTTP request latency by route template.",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
HTTP_IN_PROGRESS = Gauge(
    "aisp_http_requests_in_progress",
    "In-flight HTTP requests.",
    ["method", "route"],
)

# ── detection pipeline ────────────────────────────────────────────────────
EPA_EVENTS = Counter(
    "aisp_epa_events_processed_total",
    "Runtime events processed by the EPA consumer fleet.",
)
EPA_SIGNALS = Counter(
    "aisp_epa_signals_emitted_total",
    "EPA signals emitted, by kind.",
    ["kind"],
)
NARRATIVES_WRITTEN = Counter(
    "aisp_narratives_written_total",
    "Tier-3 narratives persisted, by severity.",
    ["severity"],
)
RUNTIME_EVENTS_INGESTED = Counter(
    "aisp_runtime_events_ingested_total",
    "Runtime telemetry events accepted at the ingest endpoint.",
)


def record_signal(kind: str) -> None:
    EPA_SIGNALS.labels(kind=kind).inc()


def record_narrative(severity: str) -> None:
    NARRATIVES_WRITTEN.labels(severity=severity).inc()


def render() -> tuple[bytes, str]:
    """Return (exposition bytes, content type) for the /metrics endpoint."""
    return generate_latest(), CONTENT_TYPE_LATEST
