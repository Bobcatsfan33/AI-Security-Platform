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

- Go 1.22+ (the blueprint forbids Python here — hot path latency budget
  is sub-15ms for `balanced` mode; Python's GIL is incompatible).
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
| Fail-open vs fail-closed per policy | ✅ |
| Telemetry buffer + HTTP upload | ✅ (HTTP upload stubbed to stdout) |
| Kill switch via WebSocket | ⏸️ follow-on |
| Heartbeat to control plane | ⏸️ follow-on |
| `/healthz` / `/readyz` / `/metrics` | ✅ |
| Helm chart / K8s manifests | ⏸️ follow-on |
| Python + Node SDK wrappers | ⏸️ follow-on |

## Wire compatibility with the Python control plane

- Policy invalidation channel: `policy:invalidation:{org_id}` (same as
  `backend/app/services/policy_pubsub.py`)
- Policy refresh endpoint: `GET /v1/policies/{policy_id}` (control plane)
- Telemetry ingest: `POST /v1/runtime/events` (control plane endpoint
  is a Sprint 7 follow-on; agent currently logs to stdout)
