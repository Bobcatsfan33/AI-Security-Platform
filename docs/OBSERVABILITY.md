# Observability instrumentation (P16a)

> **This is the instrumentation, not the operation.** Dashboards, alert rules,
> and canaries are engineering and are shipped here as code with tests.
> **EXT-OPERATIONS remains open and blocking**: it needs business-approved SLOs,
> a staffed on-call rotation, and an exercised incident. A rule that fires
> correctly into nobody's pager is not operations.

## What ships

| Artifact | Path |
|---|---|
| Dashboard as code | `deploy/observability/dashboards/control-plane.json` |
| Alert rules as code | `deploy/observability/rules/control-plane.rules.yml` |
| Rule unit tests | `deploy/observability/rules/control-plane.rules_test.yml` |
| Canary (deployable) | `deploy/observability/canary/canary-cronjob.yaml` |
| Canary (runnable) | `python -m app.observability.canary` |
| Metrics | `backend/app/observability/metrics.py` |

## Alert rules, each with a test that fires it

14 rules across security, detection continuity, and availability. **Every one is
exercised by `promtool test rules`** — and, where the distinction matters, by a
negative case proving it does *not* fire on healthy traffic. An alert that also
fires on healthy traffic gets silenced within a week, and a silenced alert is
worse than none because the dashboard still shows it as configured.

| Condition | Alert | Fires |
|---|---|---|
| Agent/stage fail-open | `AispFailOpen` | immediately, on one occurrence |
| Policy absence (allowed) | `AispPolicyAbsentFailedOpen` | immediately |
| Policy absence (denying) | `AispPolicyAbsentFailedClosed` | sustained, 5m |
| Regional mismatch | `AispRegionalMismatchSpike` | sustained, 10m |
| Auth anomalies | `AispAuthAnomalySpike` | rate-based, 5m |
| Forgery/replay indicators | `AispAuthForgerySuspected` | immediately |
| Audit-chain failure | `AispAuditChainVerificationFailed` | immediately |
| Pipeline backlog | `AispPipelineBacklogGrowing` | 10m |
| EPA heartbeat staleness | `AispEpaHeartbeatStale` | 5m |
| Ingest stopped | `AispIngestStopped` | 15m |
| Canary failing / not reporting | `AispCanaryFailing`, `AispCanaryNotReporting` | 10m / 15m |
| Error rate, p95 latency | `AispHighErrorRate`, `AispHighLatencyP95` | 5m / 10m |

`for: 0m` is used only where a single occurrence *is* the incident — a fail-open
already served real traffic without controls, and a hash-chained audit log does
not break transiently. Everything else waits, so a scrape blip or a rolling
restart does not page anyone.

Two pairs are deliberately kept separate rather than merged:

- **Policy absence failing open vs failing closed.** The first is an active
  exposure, the second is a self-inflicted outage. One alert would hide whichever
  it was not tuned for.
- **Canary failing vs not reporting.** A canary that stops emitting looks like
  nothing at all on a dashboard; only `absent()` can see it.

Run them:

```sh
promtool check rules deploy/observability/rules/control-plane.rules.yml
promtool test  rules deploy/observability/rules/control-plane.rules_test.yml
```

## The canary

Component health answers "is the process up". The canary answers **"would a real
attack be detected right now?"** — which come apart constantly: every pod Ready,
every probe green, and the detector returning `allow` for a textbook injection
because a model failed to provision or a policy shipped empty.

Two scenarios, and the second is the one people forget:

- `prompt_injection_detected` — a known attack must not be allowed.
- `benign_allowed` — ordinary traffic must still get through. A detector that
  blocks everything passes the attack probe perfectly while being unusable.

An exception is reported as a **failure**, not an error: propagating it would
leave the gauge stale at its last good value, which reads as healthy.

Probes are hard-coded strings and the module touches no tenant data, so it is
safe to run continuously in production.

## Cardinality discipline

Every label has a **closed value set** enumerated in `metrics.py` and enforced by
`_bounded()`, which collapses an unrecognised value into a known bucket rather
than passing it through.

This is not tidiness. A label whose values come from request data creates a time
series per distinct value, and the first unbounded label is almost always a
tenant id — which is simultaneously an outage risk and a data-exposure one, since
metrics stores are rarely access-controlled the way the application is.

`test_observability_instrumentation.py` asserts that **no metric carries any of**
`org`, `org_id`, `tenant`, `tenant_id`, `user`, `user_id`, `email`, `session_id`,
`correlation_key`, `agent_instance_id`, `asset_id`, `event_id`, `trace_id`,
`path`, `ip`, `api_key`, `token` — and feeds a hostile
`org-2f8c1e-user-4471-xxxx…` value to every recorder to prove it is collapsed.

The canary gauge is fixed-cardinality by construction: one series per scenario,
forever. A canary that adds a series per run eventually takes down the metrics
store it was installed to protect.

## Proposed SLOs — **not approved**

> Mirroring the RPO/RTO convention in [HA-DR-RUNBOOK.md](HA-DR-RUNBOOK.md):
> these are an engineering **proposal**. They have not been agreed with the
> business, are not committed to any customer, and no error budget is being
> enforced against them. Confirm before quoting.

| Objective | Proposed target | Window | Measured by |
|---|---|---|---|
| Control-plane availability | 99.9% of requests non-5xx | 30d rolling | `aisp_http_requests_total` |
| Control-plane latency | p95 < 500ms, p99 < 1s | 30d rolling | `aisp_http_request_duration_seconds` |
| Detection continuity | canary passing 99.5% of runs | 30d rolling | `aisp_canary_result` |
| Detection freshness | EPA heartbeat < 120s, 99% of samples | 30d rolling | `aisp_epa_heartbeat_age_seconds` |
| Ingestion lag | backlog < 10k events, 99% of samples | 30d rolling | `aisp_pipeline_backlog_events` |

Proposed error budget at 99.9% availability: **~43 minutes per 30 days**. The
budget policy — what happens when it is exhausted, who decides, what freezes —
is an operations decision and is **not** proposed here.

## What this does not claim

Rule-level tests prove an expression fires on its condition. They do **not**
prove anyone is paged: that needs an Alertmanager route, a staffed rotation, and
an incident someone actually ran. Those are EXT-OPERATIONS, and they remain open.
