# Operator runbook

The minimum a new operator needs to keep the platform healthy.

## Components

| Component        | Where                              | Owns                              |
| ---------------- | ---------------------------------- | --------------------------------- |
| Control plane    | `backend/app` (FastAPI)            | Auth, evaluations, findings, API  |
| Runtime agent    | `runtime-agent/cmd/agent` (Go)     | Inline policy + telemetry         |
| ClickHouse       | `runtime_events` table             | Event storage + dashboard queries |
| Postgres         | All other state                    | Tenants / assets / policies       |
| Redis            | `policy:invalidation:*` pub/sub    | Policy push to agents             |
| Frontend         | `frontend/src/app` (Next.js)       | Admin UI                          |

## First-thirty-minutes checklist

When you take over an oncall shift:

1. `kubectl get pods -n platform` — every pod `Running`
2. `curl https://<host>/v1/healthz` — `{"status": "ok"}`
3. `curl https://<host>/v1/readyz` — `{"status": "ok"}` (validates DB + Redis)
4. Open the dashboard at `/dashboard` — KPIs render, last-built timestamps within 5 min
5. Look at the SIEM forwarder logs (`platform.siem.forwarder`) — no `siem_*_failed` floods
6. Verify the audit log fsync isn't backing up (`AUDIT_LOG_PATH` size growing steadily)

## Common alerts

### `evaluation_runner_exited` / `evaluation_runner_failed`
Cause: the runner crashed inside a background task. The evaluation row
is marked `failed`; no data was committed.

Action:
- Check the structured log for the originating exception
- Look at `/v1/evaluations/{id}` for `summary.error`
- Re-run via the UI (Evaluations → asset → Re-run)

### `clickhouse_query_failed` (dashboard query)
Cause: ClickHouse is unreachable or overloaded.

Action:
- The dashboard already degrades to zero-state; users see no error
- Check `clickhouse-client --query "SELECT 1"` on the box
- If the writer queue is full, inspect `record_runtime_event` warnings —
  raise `CLICKHOUSE_QUEUE_MAX` if needed

### `agent_offline` (no heartbeat in 5 min)
Cause: a runtime agent stopped or lost network.

Action:
- Check `kubectl logs -l app.kubernetes.io/name=ai-security-agent`
- Verify it can resolve the control plane (`getent hosts api.platform.svc`)
- If many agents go offline simultaneously, suspect the control plane
  or Redis — see the **policy distribution outage** section below

### Kill switch fired unexpectedly
Cause: an operator pushed `runtime:control:{agent_id}` with the wrong scope.

Action:
- `DEL` the Redis key to clear the kill switch
- The next long-poll round trip will pick up `ok`
- File a postmortem; the kill switch must NEVER fire without an audit
  entry — verify `system.config_changed` for the operator who pushed it

## Routine maintenance

### Rotating the audit HMAC key
1. Set `AUDIT_HMAC_KEY_REF` to the new secret reference
2. Roll the control plane (the cache is module-level, so a restart is mandatory)
3. The chain breaks at the rotation point — record the cutover timestamp
4. Verify integrity from the new genesis with `python -m app.security.audit_log verify`

### Rolling the JWT signing key
1. Add the new key under `JWT_SECRET` alongside the existing one
2. Issue new tokens with the new key; accept tokens signed by both during
   the transition window (configurable via `JWT_SECRET_LEGACY`)
3. After all sessions expire (≤ 8h), drop the legacy secret

### Re-seeding the test case library
```
curl -X POST https://<host>/v1/test-cases/seed-defaults \
     -H "Authorization: Bearer $ADMIN_TOKEN"
```
Idempotent; only inserts cases not already present.

## Outages

### Policy distribution outage
Symptoms: all agents stuck on a stale policy version.

Root cause is almost always Redis pub/sub. The agent's policy cache has
a 5-min stale grace period — beyond that, it falls back to its last
loaded policy and emits `policy_stale` warnings.

Action:
1. `redis-cli ping`
2. `redis-cli pubsub channels` should list `policy:invalidation:*`
3. Restart the agent fleet only as a last resort; the cache survives
   long Redis outages

### Database failover
Postgres goes down → control plane returns 503 on most routes; runtime
ingest still works because it writes to ClickHouse + Redis.

Action:
- Verify the replica took over (`pg_is_in_recovery()` returns `f`)
- Re-run alembic migrations if the replica was lagging
- No state is lost; in-flight evaluations are marked failed and can be
  re-run manually
