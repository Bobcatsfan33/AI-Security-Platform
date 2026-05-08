# AI Security Platform — Revised Roadmap (TokenDNA-Aware)

> Generated 2026-05-07 after surveying TokenDNA. The original blueprint at
> `~/.openclaw/agents/sapor/memory/AI-SECURITY-PLATFORM-BLUEPRINT.md` was
> written assuming greenfield. TokenDNA already implements the majority of
> the capabilities the blueprint specifies, in production-grade Python.
> This document supersedes the blueprint's sprint sequence.

## Strategic frame

- **Two parallel products.** TokenDNA continues on its own roadmap (BUSL-1.1).
  The AI Security Platform is the architecturally-aligned successor with
  blueprint-binding decisions enforced from day one. Both repos live; the
  AI Security Platform selectively adopts modules from TokenDNA.
- **License: BUSL-1.1** (matching TokenDNA backend). The Sprint 1 scaffold
  was originally MIT and has been re-licensed.
- **The Sprint 1 scaffold is the target architecture.** TokenDNA modules are
  ported *into* this scaffold's structure (`backend/app/...`), not the other
  way round. Where TokenDNA's structure conflicts with the blueprint, the
  blueprint wins (e.g., strict PG/CH boundary, IDP-agnostic adapter
  interface, three-stage pipeline with enforcement levels).

## What's genuinely new vs. ported

The blueprint specified 12 sprints. After the survey, only **a small
fraction is genuinely new build**. Most of the work is **port + refactor**.

| Category | Sprints | Effort estimate |
|---|---|---|
| **New build (genuine engineering work)** | Go runtime agent, ONNX Stage 2 classifier, Redpanda streaming layer, generative red team if absent, dashboard rebuild on Next.js | 4–6 sprints |
| **Port + refactor from TokenDNA** | SAML, SCIM, audit log, RBAC variants, multi-tenancy variants, AI-BOM, MCP scanner, drift detection, blast radius, trust graph, behavioral DNA, threat intel, compliance evidence, SDK | 5–7 sprints |
| **Already done in scaffold (Sprint 1 c9042e0)** | OIDC adapter via authlib, JWT/refresh/revocation, API keys (bcrypt), 5-role RBAC, IDP config CRUD, policy CRUD with Redis pub/sub, multi-tenant isolation, base schemas, docker-compose, Alembic | 1 sprint |

---

## Sprint sequence (revised)

### Sprint 1 — Core infrastructure & identity federation

| Item | Source | Status |
|---|---|---|
| Postgres schemas, Alembic, multi-tenant Org model | scaffold (c9042e0) | ✅ done |
| OIDC adapter (authlib) | scaffold (c9042e0) | ✅ done |
| JWT + refresh + revocation | scaffold (c9042e0) | ✅ done |
| API key auth (bcrypt) | scaffold (c9042e0) | ✅ done |
| 5-role RBAC + IDP group→role mapping | scaffold (c9042e0) | ✅ done |
| Policy CRUD + Redis pub/sub | scaffold (c9042e0) | ✅ done |
| docker-compose stack (PG/Redis/CH/Redpanda/app) | scaffold (c9042e0) | ✅ done |
| **SAML adapter** | port `tokendna/modules/auth/saml.py` (206 lines) | **Sprint 1 follow-on** |
| **SCIM 2.0 endpoint** | port `tokendna/modules/auth/{scim,scim_filter,scim_patch}.py` (815 lines) | **Sprint 1 follow-on** |
| **Immutable audit log (hash-chained)** | port `tokendna/modules/security/audit_log.py` (333 lines) | **Sprint 1 follow-on** |
| **Production secrets resolver** | port `tokendna/modules/security/{secrets,secret_gate}.py` (308 lines) | **Sprint 1 follow-on** |
| **ClickHouse Python writer** | port `tokendna/modules/identity/clickhouse_client.py` | **Sprint 1 follow-on** |
| **Field-level encryption** | port `tokendna/modules/security/field_crypto.py` (210 lines) | **Sprint 1 follow-on** |
| **Security headers / mTLS** | port `tokendna/modules/security/{headers,mtls}.py` (358 lines) | **Sprint 1 follow-on** |
| **FIPS controls** (optional) | port `tokendna/modules/security/fips.py` (458 lines) | **Sprint 1 follow-on** |

**Sprint 1 follow-on becomes a discrete sprint of porting work** — call it
**Sprint 1B**.

### Sprint 1B — TokenDNA port wave 1 (security foundation)

Order matters: lower in the dependency graph first.

1. `secrets.py` + `secret_gate.py` → upgrade scaffold's `EnvVarResolver`
   with the production-grade backend (Vault / AWS SM hooks)
2. `audit_log.py` → wire AuditEvent emission into JWT issue/revoke,
   policy create/update/delete, IDP config changes (NIST 800-53 AU-2/3/9/12)
3. `field_crypto.py` → encrypt OIDC `client_secret` at rest before storing,
   decrypt on use via the secrets resolver
4. `headers.py` → CSP, HSTS, X-Frame-Options, X-Content-Type-Options
   middleware
5. `clickhouse_client.py` → wire telemetry writes to the
   `telemetry.runtime_events` table; schema is already initialized
6. `saml.py` → swap the deferred stub for the real adapter (pin
   `python3-saml`)
7. `scim*.py` → `/scim/v2/{org_slug}/Users` + `/Groups`, bearer-token auth,
   group-membership → role mapping reusing existing
   `directory_sync.group_to_role_mapping`

Estimated 1 sprint. Each port is a discrete commit with focused tests.

### Sprint 2 — Real model connectors + Stage 1 policy pipeline

Per blueprint. **No TokenDNA equivalent for the model connector pool.**
Mostly new work.

- OpenAI / Anthropic / Ollama / Azure / Bedrock / generic OpenAI-compat
- ConnectorResponse type + cost tracking
- **Refactor `policy_guard` (TokenDNA) into the three-stage pipeline
  interface.** Stage 1 logic (regex/keyword/PII/tool-firewall) ports
  cleanly. Confidence scoring output format added.

### Sprint 3 — ML-Enhanced Policy Engine (Stage 2)

Per blueprint. **Genuine new work.** TokenDNA does not have an ONNX
classifier in its policy pipeline.

- Train / fine-tune `protectai/deberta-v3-base-prompt-injection-v2`
- Build Rust ONNX library with C ABI exports
- CGo bridge in the Go runtime agent (Sprint 7)
- Confidence routing (high → action, low → pass, uncertain → Stage 3 if
  comprehensive, else flag)

### Sprint 4 — Generative red team engine

Per blueprint. **Possibly new work** — TokenDNA has
`tests/test_adversarial_harness.py` but I haven't confirmed if it's a full
red team agent or a test fixture. Audit before estimating.

### Sprint 5 — CI/CD + Regression suite + SCIM directory sync

- CI/CD integration: GitHub Actions, GitLab, webhooks (mostly new)
- Regression suite manager (mostly new)
- **SCIM directory sync** — done in Sprint 1B already

### Sprint 6 — AI Bill of Materials & Supply Chain

Almost entirely **port**.

- AI-BOM constructor → port `agent_discovery.py` + `agent_dna.py`
- Drift detection → port `permission_drift.py` (760 lines) +
  `attestation_drift.py`
- MCP scanner → port `mcp_inspector.py` (1140 lines) + `mcp_gateway.py` +
  `mcp_attestation.py`
- Shadow AI discovery → may be new (TokenDNA has `agent_discovery.py`,
  unclear if it covers IDP-OAuth-grant + cloud-billing inspection)

### Sprint 7 — Runtime Protection Agent (Go LLM Proxy) ⚠️ GENUINE NEW WORK

The blueprint's binding decision: **Go reverse proxy** in front of
LLM API calls. TokenDNA's runtime enforcement is the Cloudflare Worker
(`edge/index.js`) + Python `policy_guard`. **The Go agent is the largest
single piece of new engineering** in the platform.

Reusable from TokenDNA:
- Policy schemas / cache invalidation pattern (already in scaffold)
- The decision logic to port into Stage 1 (from `policy_guard.py`)
- The edge enforcement patterns in `edge/index.js` (DPoP, JWKS, ML risk
  pre-check) — informative reference, not direct port (different language)

### Sprint 8 — Agent Attack Graph & Anomaly Detection

Almost entirely **port**.

- Trust graph → port `trust_graph.py` (1498 lines)
- Blast radius → port `blast_radius.py` (506 lines)
- Intent correlation / chain detection → port `intent_correlation.py`
  (940 lines)
- Behavioral DNA → port `behavioral_dna.py` (649 lines)
- Session graph → port `session_graph.py`

### Sprint 9 — Threat Intelligence

Almost entirely **port**.

- `threat_intel.py`, `threat_sharing.py`, `threat_sharing_flywheel.py`
  from TokenDNA's `modules/identity/` and `modules/product/`

### Sprint 10 — SIEM/SOAR + Compliance

Mostly **port**.

- SIEM TAXII → port `modules/integrations/siem_taxii.py`
- Compliance → port `modules/identity/{compliance,compliance_engine,
  compliance_posture}.py`
- Splunk / Elastic / Sentinel / Datadog / Chronicle adapters: new

### Sprint 11 — Dashboard, Reporting & Productization

- Commercial tiers / metering / shadow mode / staged rollout → port
  `modules/product/*.py`
- Next.js dashboard: **new** (TokenDNA's `dashboard/index.html` is
  minimal)

### Sprint 12 — Hardening & Launch

Per blueprint.

---

## What lives where (boundary policy)

To prevent code drift between repos:

- **Pure security primitives** (audit log, field crypto, secrets, SAML,
  SCIM, RBAC) — port once into `backend/app/security/` here, deprecate
  the duplicate in TokenDNA *only when* TokenDNA is ready to depend on
  this repo. Until then both copies coexist; AI Security Platform repo
  is the canonical version going forward.
- **Domain modules** (trust graph, blast radius, MCP inspector, etc.) —
  port into `backend/app/domain/` (new directory) preserving function
  signatures so future cross-repo dependency is feasible.
- **AI Security Platform-only** (Go runtime agent, ONNX Stage 2,
  three-stage pipeline, Redpanda telemetry, dashboard) — never go
  back to TokenDNA.
- **TokenDNA-only** (Cloudflare Worker edge, current API surface in
  `api.py`, current commercial tiers) — never come into this repo.

If a divergence emerges between a ported module and its TokenDNA
original, the AI Security Platform version is canonical.

## License posture per area

| Area | License |
|---|---|
| Backend core (this repo) | BUSL-1.1 |
| SDK (when added) | Apache-2.0 (matching TokenDNA SDK) |
| Edge / runtime agent client libraries | MIT (matching TokenDNA edge) |
| Documentation, example configs | Apache-2.0 |

## Concrete next moves (in priority order)

1. **Sprint 1B — TokenDNA port wave 1 (security foundation)** as defined
   above. Roughly 7 modules totaling ~3,000 lines of port + adaptation.
2. **Sprint 2 — model connectors + Stage 1 pipeline refactor.** Unblocked
   by Sprint 1B (especially audit log + secrets, since connector configs
   contain real API keys).
3. **Sprint 6 — AI-BOM + MCP scanner port.** Can run in parallel with
   Sprint 2 because it depends only on Sprint 1 (done). Highest-leverage
   port — `mcp_inspector` alone is 1140 lines of differentiation.

## Risks / open questions

- **`api.py` is 6,931 lines / 304 endpoints.** Porting individual modules
  is straightforward; rebuilding the API surface in `/v1` style takes
  more thought. Don't try to port `api.py` wholesale.
- **Test corpus is 93 files.** Many will need adaptation to the new
  package structure (`backend/app/...`) — budget real time for this.
- **TokenDNA's `aegisai-foundation/` artifact.** The original blueprint
  referenced a "foundation" codebase; we located it as a Claude session
  artifact. It's now superseded by the TokenDNA port plan above. Ignore
  the foundation pointer in the blueprint going forward.
- **TokenDNA's roadmap is in motion** (HANDOFF doc at top level lists
  six in-flight slices). Coordinate before deprecating any TokenDNA
  module to avoid clobbering active work.
