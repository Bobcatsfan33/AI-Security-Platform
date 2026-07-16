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
- **Latency: sub-15ms added latency for `balanced` mode is a TARGET, and is
  currently UNMEASURED.** Nothing in this repo benchmarks it: there is no
  `Benchmark*` function and no load test against the proxy path. Per-stage
  `LatencyUS` is stamped at runtime and shipped as telemetry, but no test
  asserts a bound. Phase 2 lands `runtime-agent/bench/` with p50/p99 per stage
  against a mock upstream and a CI regression gate; until those numbers are
  published in `docs/BENCHMARKS.md`, treat this as an intention, not a
  property. Tracked in [`docs/GAPS.md`](../docs/GAPS.md) as GAP-002.
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
| Fail-open vs fail-closed per policy | ⚠️ **Stage 3 only** — see below |
| Telemetry buffer + HTTP upload | ✅ (HTTP upload stubbed to stdout) |
| Kill switch via WebSocket | ⏸️ follow-on |
| Heartbeat to control plane | ⏸️ follow-on |
| `/healthz` / `/readyz` / `/metrics` | ✅ |
| Helm chart / K8s manifests | ⏸️ follow-on |
| Python + Node SDK wrappers | ⏸️ follow-on |

### Fail-behavior: what is actually true today

The table above claimed a blanket ✅. It is narrower than that, and the
difference is load-bearing, so it is spelled out rather than left to the
reader:

| Stage | Honours `fail_behavior`? | Actual behaviour when it cannot reach its backend |
|---|---|---|
| Stage 1 | n/a | Cannot fail — no I/O; always produces a verdict. |
| Stage 2 | ❌ **No** | **Always fail-open**, regardless of policy. The policy argument is discarded (`stage2_http.go`). A down ONNX sidecar is indistinguishable from a clean verdict — both yield `Matched:false` — so `comprehensive` silently degrades to Stage-1-only. Tracked as **GAP-004**; fix queued for Phase 1. |
| Stage 3 | ✅ Yes | `fail_behavior: "closed"` blocks with `judge unavailable; fail-closed`; `"open"` allows. |
| No policy cached at all | ❌ **No** | **Always fail-open** — every request passes uninspected. There is no setting to change this today. Tracked as **GAP-003**; `AGENT_NO_POLICY_BEHAVIOR` lands in Phase 1. |

See [`docs/GAPS.md`](../docs/GAPS.md). Do not rely on `fail_behavior: "closed"`
as a deny-by-default guarantee until GAP-003 and GAP-004 are closed — today it
covers one stage of three.

## Wire compatibility with the Python control plane

- Policy invalidation channel: `policy:invalidation:{org_id}` (same as
  `backend/app/services/policy_pubsub.py`)
- Policy refresh endpoint: `GET /v1/policies/{policy_id}` (control plane)
- Telemetry ingest: `POST /v1/runtime/events` (control plane endpoint
  is a Sprint 7 follow-on; agent currently logs to stdout)
