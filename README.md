# AI Security Platform

The control plane for enterprise AI security — evaluation, runtime protection,
governance, and threat intelligence. Per the engineering blueprint, this is a
hybrid SaaS + on-prem product: this repository will hold the multi-tenant
control plane (Python / FastAPI), the customer-deployed runtime agent
(Go, Sprint 7), the ML classifier (Sprint 3), and the dashboard (Next.js,
Sprint 11).

> Status: **Sprint 1 — Core Infrastructure & Identity Federation, scaffold + core path.**
> See "What's in this commit" and "What's deferred" below.

---

## Architecture (binding decisions)

| Concern | Decision | Sprint |
|---|---|---|
| Operational data | PostgreSQL 16 + pgvector | 1 |
| Telemetry | ClickHouse (append-only, never on hot path) | 1 schema, follow-on for client |
| Cache + pub/sub | Redis 7 | 1 |
| Event streaming | Redpanda (Kafka-compatible) | 7 |
| Control plane API | FastAPI (Python 3.12) | 1 |
| Identity federation | IDP-agnostic adapter interface; OIDC via `authlib`, SAML via `python3-saml` | 1 (OIDC), follow-on (SAML), 5 (SCIM) |
| Runtime agent | Go 1.22+ reverse proxy | 7 |
| ML classifier | Rust ONNX library called via CGo | 3 |
| Policy enforcement | Three-stage pipeline (regex → ML → LLM judge), per-policy enforcement level | 2 / 3 / 7 |

The full blueprint lives at `~/.openclaw/agents/sapor/memory/AI-SECURITY-PLATFORM-BLUEPRINT.md`.

---

## What's in this commit (Sprint 1)

- **PostgreSQL schema** for the full Sprint 1 surface: `organizations`, `users`,
  `api_keys`, `idp_configs`, `ai_assets`, `test_cases`, `evaluations`,
  `findings`, `policies`. Single Alembic migration.
- **FastAPI app** with `/v1` versioning, structured logging (structlog JSON),
  request correlation IDs, CORS, OpenAPI docs at `/v1/docs`.
- **Identity federation layer** — pluggable adapter interface, OIDC adapter
  built on `authlib` (auth-code-with-PKCE, JWKS validation, configurable claim
  mapping). SAML adapter is a stub deferred to follow-on.
- **JWT session management** — 15-min access tokens, 7-day refresh tokens with
  rotation, revocation list in Redis.
- **API key auth** — bcrypt-hashed, prefix-indexed, scope-checked.
- **RBAC** — five roles (`owner`, `admin`, `analyst`, `viewer`, `api_only`)
  with hierarchy enforcement, IDP group → role mapping driven by per-org
  `directory_sync.group_to_role_mapping`.
- **Multi-tenant isolation** — every authenticated request resolves to an
  `IdentityContext` with `org_id`; repositories filter by org. Integration
  test (`tests/integration/test_tenant_isolation.py`) verifies Org A cannot
  read Org B's policies.
- **Policy CRUD with Redis pub/sub** — every write publishes a JSON
  invalidation message on `policy:invalidation:{org_id}`. A subscriber stub
  (`scripts/policy_subscriber.py`) demonstrates end-to-end wiring; the real
  consumer is the Go runtime agent in Sprint 7.
- **IDP config admin API** — admins can register OIDC providers; create-time
  OIDC discovery validation via `.well-known/openid-configuration` so a
  misconfigured IDP fails fast.
- **`docker-compose.yml`** for the full local stack: postgres+pgvector,
  redis, clickhouse, redpanda, app.
- **ClickHouse schema** for `telemetry.runtime_events`, partitioned by month,
  90-day TTL.
- **Tests** — pytest unit tests for RBAC, JWT, OIDC claim mapping, group
  mapping, secret resolver, API key format, pub/sub channel naming. One
  integration test for tenant isolation.

## What's deferred (per the agreed Sprint 1 scope)

- **SAML adapter implementation** — schema and stub are in; wire `python3-saml`
  in a follow-on session.
- **ClickHouse Python client** — schema is initialized via `clickhouse/init/`,
  but the Python writer service is wired in a follow-on session.
- **SCIM 2.0 endpoint** — Sprint 5.
- **Frontend** — Sprint 11.
- **Runtime agent (Go)** — Sprint 7.
- **Evaluation engine, model connectors, policy enforcement** — Sprint 2+.

---

## Running locally

### Prerequisites

- Docker + Docker Compose
- Python 3.12 (for running tests / Alembic outside the container)

### Start the stack

```bash
# Generate a JWT secret and put it in your shell env (or .env)
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(64))")

# Bring everything up
docker compose up -d postgres redis clickhouse redpanda
docker compose up app
```

The API is now at <http://localhost:8000/v1/docs>.

### Apply database migrations

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
pytest -m unit                    # no infrastructure required
pytest -m integration             # requires postgres + redis up
pytest --cov=app --cov-report=term-missing
```

### Verify policy pub/sub

In one terminal:
```bash
python -m scripts.policy_subscriber <your-org-id>
```

Create or update a policy via the API in another terminal — you'll see the
invalidation message logged immediately.

---

## Environment variables

See `backend/.env.example` for the full list. The most important:

| Var | Purpose |
|---|---|
| `JWT_SECRET` | HMAC key for access tokens. Min 32 chars. **Required.** |
| `DATABASE_URL` | `postgresql+asyncpg://...` |
| `REDIS_URL` | Used for cache, pub/sub, JWT revocation |
| `CLICKHOUSE_URL` | Telemetry DB (writer wired in follow-on) |
| `REDPANDA_BROKERS` | Streaming brokers (consumer wired in Sprint 7) |
| `JWT_ACCESS_TTL_SECONDS` / `JWT_REFRESH_TTL_SECONDS` | Token lifetimes |

---

## Repository layout

```
ai-security-platform/
├── backend/
│   ├── app/
│   │   ├── api/                  # FastAPI routers
│   │   │   ├── middleware.py     # correlation IDs
│   │   │   └── v1/               # /v1 routes (auth, idp_admin, policies, health)
│   │   ├── auth/                 # JWT, API keys, RBAC, dependencies, provisioning
│   │   ├── core/                 # config, logging
│   │   ├── db/
│   │   │   ├── base.py           # Declarative Base + shared column types
│   │   │   ├── session.py        # async engine + session factory
│   │   │   └── models/           # one file per model
│   │   ├── identity/             # IDP adapters (OIDC live, SAML stub)
│   │   ├── services/             # Redis client, pub/sub publisher
│   │   └── main.py               # FastAPI app factory
│   ├── alembic/                  # migrations
│   ├── scripts/policy_subscriber.py
│   ├── tests/
│   │   ├── unit/                 # no live infra
│   │   └── integration/          # postgres + redis required
│   ├── pyproject.toml
│   ├── alembic.ini
│   └── Dockerfile
├── clickhouse/init/              # bootstrap schema
├── docker-compose.yml
├── LICENSE                       # MIT
└── README.md
```

---

## Sprint 1 Definition of Done — status

| DoD item | Status |
|---|---|
| All existing endpoints work with PostgreSQL instead of SQLite | ✅ Greenfield on PG |
| Multi-tenant isolation: Org A cannot see Org B's resources | ✅ enforced + integration-tested |
| OIDC login flow works end-to-end | ✅ implemented; needs a real IDP to verify in your env |
| SAML login flow works end-to-end | ⏸️ deferred (stub returns clear error) |
| API key auth works for machine-to-machine access | ✅ |
| RBAC prevents viewer from creating/modifying resources | ✅ via `require_role` |
| IDP group-to-role mapping correctly assigns roles on login | ✅ unit-tested |
| ClickHouse accepts and stores test events | ⏸️ schema only; client wired in follow-on |
| Redis pub/sub channel created; policy writes publish invalidation | ✅ |
| Docker Compose brings up full stack with one command | ✅ |
| Alembic migrations run cleanly on fresh database | ✅ (run `alembic upgrade head`) |

---

## License

MIT — see `LICENSE`.
