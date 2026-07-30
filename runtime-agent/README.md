# AI Security Platform — Runtime Agent

The customer-deployed LLM reverse proxy. Sits in front of OpenAI /
Anthropic / Azure / Bedrock API calls, runs the three-stage policy
pipeline, and streams telemetry back to the control plane.

> Status: **Sprint 7 starter.** Scaffold + reverse proxy + Stage 1
> enforcement + telemetry queue + policy cache subscriber. Stages 2
> (Rust+CGo ONNX) and 3 (LLM judge), WebSocket kill switch, streaming
> response interception, Helm chart, and SDK wrappers are deferred to
> the Sprint 7 follow-on.

## Binding architectural decisions

- Go 1.22+ (the blueprint forbids Python here — Python's GIL is
  incompatible with the intended hot-path concurrency).
- **Latency: MEASURED, and it beats the sub-15ms target by ~460×.** On the
  reference environment (Apple M2, go1.26.3), `Pipeline.Evaluate` adds a **p99
  of 32.4 µs in `balanced` mode** (Stage 1 + in-process heuristic Stage 2) and
  **27.2 µs in `fast` mode** — full distribution, methodology and reproduction in
  [`docs/BENCHMARKS.md`](../docs/BENCHMARKS.md), harness in `runtime-agent/bench/`.
  This is *pipeline-added* latency (the product claim); end-to-end proxy overhead
  under sustained load is measured separately by the locust profile (Phase 2
  increment 3). The `comprehensive` sidecar figure measures the agent's
  transport overhead for a Stage-2/3 hop and is **not** an ONNX inference-time
  claim. GAP-002 closed for the pipeline-latency claim; see it for the remaining
  CI-gate and load-test increments.
- The Rust+CGo bridge for ONNX inference lives in `classifier/` (also
  deferred to follow-on). For now, Stage 2 is wired into the pipeline
  but returns `no-match` — the Python control plane runs Stage 2 for
  evaluation use cases (see `backend/app/policy/stage2_onnx.py`).
- Policy cache is in-memory with a configurable stale-cache grace
  period (default 5 min). Cache invalidation flows via Redis pub/sub
  on the `policy:invalidation:{org_id}` channel — the SAME channel the
  Python control plane publishes to. Wire-level interop.
- Telemetry buffers in-memory with a bounded queue; on overflow, falls
  back to disk-backed spill (follow-on). Flushes via HTTP POST to the
  control plane's `/v1/runtime/events` ingest endpoint (Sprint 7
  follow-on — for now the writer goes to stdout in development).

## Layout

```
runtime-agent/
├── cmd/agent/         entry point + config loading
├── proxy/             reverse proxy + provider format detection
├── policy/            Stage 1 enforcement + cache + invalidation listener
├── telemetry/         in-memory queue + uploader
├── management/        diagnostic endpoints (/healthz, /readyz, /metrics)
└── go.mod
```

## Running

```bash
cd runtime-agent
go build -o bin/agent ./cmd/agent
PLATFORM_URL=http://localhost:8000 \
  AGENT_ORG_ID=00000000-0000-0000-0000-000000000000 \
  AGENT_BIND=:8400 \
  ./bin/agent
```

## Sprint 7 Definition of Done — scaffold scope

| Item | Status |
|---|---|
| `net/http/httputil.ReverseProxy` base | ✅ |
| OpenAI / Anthropic / Azure provider format detection | ✅ |
| Bedrock format detection | ⏸️ follow-on |
| Streaming SSE response interception | ⏸️ follow-on |
| Stage 1 regex + PII enforcement | ✅ port from Python |
| Stage 1 tool-call firewall | ✅ |
| Stage 2 ML classifier (CGo Rust) | ⏸️ follow-on |
| Stage 3 LLM judge | ⏸️ follow-on |
| Redis pub/sub policy cache + stale grace | ✅ |
| Fail-open vs fail-closed per policy | ✅ Stages 2 and 3; cold start via `AGENT_NO_POLICY_BEHAVIOR` — see below |
| Telemetry buffer + HTTP upload | ✅ (HTTP upload stubbed to stdout) |
| Kill switch via WebSocket | ⏸️ follow-on |
| Heartbeat to control plane | ⏸️ follow-on |
| `/healthz` / `/readyz` / `/metrics` | ✅ |
| Helm chart / K8s manifests | ⏸️ follow-on |
| Python + Node SDK wrappers | ⏸️ follow-on |

### Fail behaviour

A blanket ✅ was too generous before Phase 1 (it was true of Stage 3 only), so
the surface is spelled out per stage rather than left to the reader:

| Stage | Honours `fail_behavior`? | Behaviour when its backend cannot answer |
|---|---|---|
| Stage 1 | n/a | Cannot fail — no I/O; always produces a verdict. |
| Stage 2 | ✅ Yes | `closed` → blocks; `open` (or a nil policy) → allows. Either way the result carries `Mode=stage2_unavailable`, so a degraded classifier is never mistaken for a clean verdict. |
| Stage 3 | ✅ Yes | `closed` → blocks with `judge unavailable; fail-closed`; `open` → allows. |
| No policy cached at all | via `AGENT_NO_POLICY_BEHAVIOR` | There is no policy to read a `fail_behavior` from, so this has its own setting (below). |

`fail_behavior` covers *failure*, not verdicts: a reachable backend's answer is
the answer under either setting.

### Cold start — `AGENT_NO_POLICY_BEHAVIOR`

What the proxy does when it has **no policy at all**: control plane unreachable,
cache empty. Mirrors the SDKs' fail-closed convention
(`sdks/python/platform_sdk/_routing.py`, `sdks/node/src/routing.ts`) so the
platform has one shape to learn, not two:

| `AGENT_NO_POLICY_BEHAVIOR` | `AGENT_ENVIRONMENT` | Result |
|---|---|---|
| `closed` | *(any)* | Refuse with 451 |
| `open` | *(any)* | Forward uninspected |
| *(unset)* | `production` / `prod` / *unset* | **Refuse** — deny by default |
| *(unset)* | `development` / `staging` / `test` / … | Forward uninspected |

Explicit always wins. Unset resolves by environment, and an *unspecified*
environment resolves closed — absence of information is not evidence of a dev
box. An unrecognised value is a **startup error**, not a fallback: the agent
refuses to start rather than guess at a security setting (the same posture as
its partial-mTLS check).

Both branches are loud — a log line and a telemetry event on every request that
takes them (`proxy_no_policy_fail_closed` / `proxy_no_policy_fail_open`;
`ActionTaken` of `blocked_no_policy` / `passthrough_no_policy`). A fail-closed
cold start is an outage and must be diagnosable in seconds; a fail-open one must
never look identical to a protected request.

**Operational consequence:** `closed` is the default in production, so a
control-plane outage is a traffic outage — but deploy ordering is now forgiving.
The warm load retries with bounded, jittered exponential backoff
(`LoadWithRetry`), so a briefly-late control plane is absorbed; a permanently-
absent one fails closed (safe), never hangs startup — **backoff-then-proceed, not
backoff-forever**. The full contract, and the Redis subscriber reconnect it
shares a primitive with, are documented in
[`docs/AGENT-FAILURE-MODES.md`](../docs/AGENT-FAILURE-MODES.md) with the
fault-injection tests that verify them.

See [`docs/GAPS.md`](../docs/GAPS.md) for the gaps this closed (GAP-003,
GAP-004).

### Security metrics and alerts

`/metrics` exports Prometheus metadata and bounded operational signals:
decision counters by action, fail-open counters by reason, stage-unavailability
counters by open/closed behavior, request and per-stage duration histograms,
telemetry delivery statistics, stale-policy state, and identifier-free
kill-switch gauges. Unknown action and reason values collapse to `other`;
tenant, policy, asset, tool, and user identifiers are intentionally excluded
from labels.

For Kubernetes, set `metrics.enabled=true` plus
`metrics.serviceMonitor.enabled=true` to render the scrape target. Set
`metrics.prometheusRule.enabled=true` to install the starter security alerts.
Alert meaning, triage, and PromQL investigation queries are maintained in the
[`operator runbook`](../docs/OPERATOR-RUNBOOK.md#runtime-agent-security-alerts).

## Wire compatibility with the Python control plane

- Policy invalidation channel: `policy:invalidation:{org_id}` (same as
  `backend/app/services/policy_pubsub.py`)
- Policy refresh endpoint: `GET /v1/policies/{policy_id}` (control plane)
- Telemetry ingest: `POST /v1/runtime/events` (control plane endpoint
  is a Sprint 7 follow-on; agent currently logs to stdout)
