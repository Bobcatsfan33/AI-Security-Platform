# AI Security Platform

A control plane for enterprise AI security — evaluation, runtime protection,
governance, and threat intelligence. Hybrid SaaS + on-prem product: this
repository holds the multi-tenant control plane (Python / FastAPI), the
customer-deployed runtime agent (Go), pluggable ONNX classifiers, a Next.js
admin UI, and supporting SDKs for OpenAI / Anthropic.

> **Status:** Tier 1 → Tier 3 engineering complete; Tier 4 (legal / marketing
> / sales artefacts) and a production hardening pass remain. This is an
> early-stage, single-maintainer project: it has **not** had an independent
> security audit or penetration test, and has no production deployments or
> reference customers yet. Compliance outputs are audit-supporting evidence,
> not third-party certification. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for
> the sprint sequence and [`docs/OPERATOR-RUNBOOK.md`](docs/OPERATOR-RUNBOOK.md)
> for day-2 ops.

---

## Capabilities (what ships today)

| Surface | What it does |
| --- | --- |
| **Evaluations** | 50-case OWASP LLM Top 10 library + per-org cases; six model connectors (OpenAI, Anthropic, Ollama, Azure OpenAI, Bedrock, OpenAI-compat); LLM-judge + pattern verdicts |
| **Findings** | Hash-chained audit trail through the open → in_progress → remediated → verified pipeline |
| **Red team** | Generative campaigns with strategy library + judge; auto-promotion of successful attacks into the regression suite |
| **AI-BOM** | Asset bill of materials, supply-chain risk scoring, model drift detection |
| **Runtime agent** (Go) | Inline reverse proxy running all three policy stages live: Stage 1 regex/PII, Stage 2 ML (zero-config heuristic inline; ONNX inference sidecar via `STAGE2_ONNX_ENDPOINT`), Stage 3 LLM judge (deterministic default; configured judge via `STAGE3_JUDGE_ENDPOINT`, fail-open/closed per policy). Confidence-band routing, kill switch, telemetry to ClickHouse |
| **SDKs** | Python + Node OpenAI/Anthropic wrappers that route through the local agent |
| **Reports** | Markdown + PDF rendering of six templates (exec summary, technical detail, OWASP LLM Top 10, NIST AI RMF, SOC 2 AI, EU AI Act) |
| **CI/CD gate** | Composite GitHub Action that triggers an evaluation, blocks the build on threshold breach, comments on PR |
| **SIEM forwarders** | Splunk HEC, Elastic bulk, Sentinel HTTP Data Collector, Datadog Logs, Chronicle UDM, generic webhook |
| **Dashboards** | `/v1/dashboards/{runtime,traffic,policy-effectiveness}` aggregations + Next.js executive view |
| **Anomaly detection** | Per-asset attack graph + statistical detector (volume spike / novel transition / risk inflation) |
| **Threat intel** | Opt-in cross-tenant clustering; STIX 2.1 export |
| **SOAR** | PagerDuty / Opsgenie / generic-webhook incident sinks |
| **Compliance** | Evidence-pack ZIP scaffolding to support SOC 2 / ISO 27001 / FedRAMP Moderate audits — supporting evidence, not certification |

---

## Architecture (binding decisions)

| Concern | Decision |
| --- | --- |
| Operational data | PostgreSQL 16 + pgvector |
| Telemetry | ClickHouse (append-only) |
| Cache + pub/sub | Redis 7 |
| Event streaming | Redpanda (Kafka-compatible) |
| Control plane API | FastAPI (Python 3.12+) |
| Identity federation | IDP-agnostic adapter; OIDC via `authlib` + `joserfc`, SAML via `python3-saml`, SCIM 2.0 |
| Runtime agent | Go 1.26 reverse proxy with `httputil` |
| ML classifier | ONNX models; Go-side runtime selected per-deployment |
| Policy enforcement | Three-stage pipeline (regex / ML / LLM judge) per policy + per-org enforcement level |
| Frontend | Next.js 16.2 App Router + Tailwind 4 + TypeScript |

---

## Running locally

```bash
# Generate a JWT secret
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(64))")

# Bring up the stack
docker compose up -d postgres redis clickhouse redpanda
docker compose up app
```

API: <http://localhost:8000/v1/docs>. Frontend (in `frontend/`): `npm run dev`.

### Apply migrations

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env  # then edit JWT_SECRET
alembic upgrade head
```

### Run tests

```bash
cd backend
pytest                              # full unit suite
pytest -m integration               # postgres + redis must be up
pytest --cov=app --cov-report=term-missing
```

The unit suite runs on every push and PR — see the `backend` job in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the count and result
on the current `main`. (A hand-maintained number here drifted from reality once
already; CI is the only count that stays true.)

### Load test

```bash
pip install locust
locust -f backend/loadtest/locustfile.py --host http://localhost:8000 \
       -u 50 -r 5 --run-time 2m --csv loadtest_results
```

---

## Repository layout

```
ai-security-platform/
├── backend/
│   ├── app/
│   │   ├── anomaly/              # Attack graph + detector
│   │   ├── api/v1/               # FastAPI routers
│   │   ├── auth/                 # JWT, API keys, RBAC
│   │   ├── compliance/           # Evidence-pack builder
│   │   ├── connectors/           # OpenAI/Anthropic/Bedrock/...
│   │   ├── db/                   # Models + Alembic
│   │   ├── evaluation/           # Runner
│   │   ├── identity/             # OIDC/SAML adapters
│   │   ├── policy/               # Three-stage pipeline
│   │   ├── redteam/              # Generative campaign engine
│   │   ├── reports/              # Markdown/PDF templates
│   │   ├── siem/                 # 6 export backends + forwarder
│   │   ├── soar/                 # 3 incident sinks
│   │   ├── telemetry/            # ClickHouse writer + dashboard queries
│   │   ├── threat_intel/         # Clustering + STIX export
│   │   └── main.py
│   ├── alembic/
│   ├── loadtest/locustfile.py
│   └── tests/{unit,integration}/
├── runtime-agent/                # Go 1.26 agent
├── frontend/                     # Next.js 16.2
├── sdks/{python,node}/           # Drop-in OpenAI/Anthropic wrappers
├── deploy/
│   ├── helm/ai-security-agent/
│   ├── k8s/agent.yaml
│   └── siem/{splunk,elastic,sentinel}/
├── actions/ai-security-gate/     # Composite GitHub Action
├── .github/workflows/ci.yml
└── docs/
```

---

## License

**BUSL-1.1** — Business Source License 1.1. Source-available; production
use is permitted unless you are offering the work to third parties on a
hosted or embedded basis to compete with the Licensor. Converts to
Apache 2.0 four years after each version's publish date.

For alternative licensing, contact ryanwallac33@gmail.com.
