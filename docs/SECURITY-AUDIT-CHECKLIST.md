# Self-audit checklist

Run through this before every release. Each item is either green
(passing) or has a tracked exception with an owner and due date.

## Authentication & session
- [ ] JWT signing key is sourced from a secret resolver (not env literal) in production
- [ ] Refresh token rotation enabled; reuse triggers session revocation
- [ ] OIDC ID-token verification uses joserfc with explicit algorithm allowlist
- [ ] SAML signature + audience validation enforced
- [ ] Session timeout enforced (default 8h)

## Authorization
- [ ] Every `/v1/*` route uses an `auth.dependencies.require_*` dependency
- [ ] No route accepts an org_id from the request body — always from the identity context
- [ ] Admin routes require `admin`; analyst routes require `analyst`; viewers can read only
- [ ] Test cases exist that confirm cross-tenant access returns 404 (not 403, never 200)

## Input validation
- [ ] Every public endpoint has a Pydantic model on request body + query params
- [ ] Free-text fields capped to a reasonable max length (default 8192 chars)
- [ ] File uploads (where applicable) validate magic bytes, not extension
- [ ] Telemetry ingest rejects events with `org_id` not matching the caller's identity

## SQL / ORM
- [ ] No raw f-strings inside SQL; ClickHouse queries use `parameters=`
- [ ] All SQLAlchemy queries scope by `org_id` filter
- [ ] Migrations reviewed for accidental ALTER on production-only columns

## Secret management
- [ ] No hardcoded credentials anywhere — `secret_gate.assert_production_secrets()` runs on startup
- [ ] `siem_exporters` and `soar_adapters` configs reject raw secrets at admin route validation
- [ ] Field-level encryption uses versioned Fernet (rotation supported)
- [ ] Audit log HMAC key is configured (not falling back to plain SHA-256)

## Transport security
- [ ] TLS terminated at ingress; HSTS header set (`SecurityHeadersMiddleware`)
- [ ] Internal service-to-service calls (Redis, ClickHouse, Postgres) use TLS or mTLS where supported
- [ ] CORS origin allowlist is explicit per environment

## Rate limiting & DoS
- [ ] Login endpoints are rate-limited (per IP + per username)
- [ ] Telemetry ingest enforces a per-agent QPS cap
- [ ] Bulk endpoints (SCIM, evidence-pack) require admin and have request-size limits

## Audit & logging
- [ ] `log_event` called for every privileged operation
- [ ] Audit log integrity verified nightly (`verify_log_integrity`)
- [ ] No PII or secrets in structured log fields; redaction applied to inbound prompts

## Dependencies
- [ ] `pip-audit`/`safety` runs in CI; no high-severity vulns merged
- [ ] `gosec` runs in CI for the Go agent
- [ ] `npm audit` runs in CI for the frontend; high-severity vulns block merge

## Network & deploy
- [ ] Runtime agent container runs as non-root with `readOnlyRootFilesystem`
- [ ] Helm chart drops all capabilities by default
- [ ] Network policies (k8s NetworkPolicy or equivalent) restrict the agent's egress

## Crypto & data
- [ ] No usage of MD5/SHA-1 outside of HMAC-friendly contexts
- [ ] PRNGs are `secrets.token_*` for security-critical paths
- [ ] At-rest encryption confirmed for Postgres + ClickHouse volumes

## Operations
- [ ] Backup + restore tested in the last 30 days
- [ ] Incident response runbook exists and lists the on-call rotation
- [ ] Kill-switch tested end-to-end in staging
