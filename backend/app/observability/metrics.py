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

# ── security and continuity conditions (P16a) ─────────────────────────────
#
# One metric per alertable condition in docs/OBSERVABILITY.md. Every label
# below has a CLOSED value set, enumerated in this module and enforced by
# _bounded(). That is not tidiness: a label whose values come from request data
# is an unbounded cardinality explosion, and the first unbounded label is
# usually a tenant id — which also puts tenant identity into a metrics store
# that is not access-controlled like the application is.

# Fail-open is the condition where traffic was served WITHOUT the controls that
# were supposed to apply. Counted by which stage gave up, never by who was
# affected.
FAIL_OPEN = Counter(
    "aisp_fail_open_total",
    "Requests served without their full intended controls, by stage.",
    ["stage"],
)
FAIL_OPEN_STAGES = frozenset({"stage1_policy", "stage2_classifier", "stage3_judge", "unknown"})

# A request that found no policy to enforce. Distinct from a policy that
# allowed the request: "there was nothing to check" and "it was checked and
# permitted" are the same HTTP result and completely different security events.
POLICY_ABSENT = Counter(
    "aisp_policy_absent_total",
    "Enforcement points that found no applicable policy, by decision taken.",
    ["decision"],
)
POLICY_ABSENT_DECISIONS = frozenset({"failed_closed", "failed_open"})

# The P9 residency control firing: a tenant's traffic reached the wrong cell.
# By ENTRY POINT, not by tenant — the operator needs to know which door is
# being knocked on, and the tenant id would be both unbounded and sensitive.
REGION_REJECTIONS = Counter(
    "aisp_tenant_region_rejections_total",
    "Requests refused because the tenant's region does not match this cell.",
    ["entry_point"],
)
REGION_ENTRY_POINTS = frozenset({"jwt", "api_key", "sso", "saml", "refresh", "scim", "unknown"})

# Authentication anomalies, by REASON CLASS. The reason set is closed, so a new
# failure mode has to be added here deliberately rather than arriving as an
# arbitrary string from a parser.
AUTH_ANOMALIES = Counter(
    "aisp_auth_anomalies_total",
    "Authentication failures and anomalies, by reason class.",
    ["reason"],
)
AUTH_REASONS = frozenset(
    {
        "invalid_signature",
        "expired",
        "unknown_key_id",
        "revoked",
        "unknown_org",
        "malformed",
        "unknown_api_key",
        "replayed_refresh",
        "other",
    }
)

# The audit log is hash-chained; a verification failure means the chain is
# broken, which is a tamper indication and not a health blip.
AUDIT_CHAIN_FAILURES = Counter(
    "aisp_audit_chain_verification_failures_total",
    "Audit-chain verification failures, by check.",
    ["check"],
)
AUDIT_CHECKS = frozenset({"hash_mismatch", "sequence_gap", "signature", "unknown"})

# Backlog and staleness are GAUGES: the question is "how far behind is it right
# now", which a counter cannot answer.
PIPELINE_BACKLOG = Gauge(
    "aisp_pipeline_backlog_events",
    "Events waiting to be consumed, by pipeline stage.",
    ["stage"],
)
PIPELINE_STAGES = frozenset({"ingest", "epa_consumer", "narrative", "siem_export"})

# Seconds since the EPA consumer last recorded progress. Pairs with the P13
# heartbeat liveness probe: the probe restarts a wedged pod, this alerts when
# the fleet as a whole is not turning over.
EPA_HEARTBEAT_AGE = Gauge(
    "aisp_epa_heartbeat_age_seconds",
    "Age of the newest EPA consumer heartbeat, in seconds.",
)

# Canary result as a fixed-cardinality gauge: 1 pass, 0 fail. Deliberately not
# a per-run counter with a run id — a canary that adds a series per execution
# is a metric that eventually takes down the metrics store it was monitoring.
CANARY_RESULT = Gauge(
    "aisp_canary_result",
    "Last synthetic canary result by scenario: 1 pass, 0 fail.",
    ["scenario"],
)
CANARY_LATENCY = Gauge(
    "aisp_canary_duration_seconds",
    "Duration of the last synthetic canary run, by scenario.",
    ["scenario"],
)
CANARY_SCENARIOS = frozenset({"prompt_injection_detected", "benign_allowed", "policy_enforced"})


def _bounded(value: str, allowed: frozenset[str], fallback: str) -> str:
    """Collapse an unexpected label value into a known bucket.

    Fails SAFE for cardinality rather than for fidelity. An unrecognised value
    is recorded under ``fallback`` instead of being passed through, because a
    caller that starts emitting a request-derived string would otherwise create
    a new time series per request — and the resulting outage looks like a
    metrics-infrastructure problem, not like the labelling bug it is.
    """
    return value if value in allowed else fallback


def record_signal(kind: str) -> None:
    EPA_SIGNALS.labels(kind=kind).inc()


def record_narrative(severity: str) -> None:
    NARRATIVES_WRITTEN.labels(severity=severity).inc()


def record_fail_open(stage: str) -> None:
    FAIL_OPEN.labels(stage=_bounded(stage, FAIL_OPEN_STAGES, "unknown")).inc()


def record_policy_absent(*, failed_closed: bool) -> None:
    decision = "failed_closed" if failed_closed else "failed_open"
    POLICY_ABSENT.labels(decision=decision).inc()


def record_region_rejection(entry_point: str) -> None:
    REGION_REJECTIONS.labels(
        entry_point=_bounded(entry_point, REGION_ENTRY_POINTS, "unknown")
    ).inc()


def record_auth_anomaly(reason: str) -> None:
    AUTH_ANOMALIES.labels(reason=_bounded(reason, AUTH_REASONS, "other")).inc()


def record_audit_chain_failure(check: str) -> None:
    AUDIT_CHAIN_FAILURES.labels(check=_bounded(check, AUDIT_CHECKS, "unknown")).inc()


def set_pipeline_backlog(stage: str, depth: int) -> None:
    PIPELINE_BACKLOG.labels(stage=_bounded(stage, PIPELINE_STAGES, "ingest")).set(depth)


def set_epa_heartbeat_age(seconds: float) -> None:
    EPA_HEARTBEAT_AGE.set(seconds)


def record_canary(scenario: str, *, passed: bool, duration_seconds: float) -> None:
    bounded = _bounded(scenario, CANARY_SCENARIOS, "prompt_injection_detected")
    CANARY_RESULT.labels(scenario=bounded).set(1 if passed else 0)
    CANARY_LATENCY.labels(scenario=bounded).set(duration_seconds)


def render() -> tuple[bytes, str]:
    """Return (exposition bytes, content type) for the /metrics endpoint."""
    return generate_latest(), CONTENT_TYPE_LATEST
