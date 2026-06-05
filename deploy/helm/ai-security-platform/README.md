# ai-security-platform Helm chart (control plane)

Deploys the multi-tenant **control-plane API**, the **EPA detection consumer
fleet**, and an optional **background worker** — HA-ready, with secrets via a
managed or external Secret.

```bash
helm install aisp deploy/helm/ai-security-platform \
  --namespace ai-security --create-namespace \
  --set image.repository=ghcr.io/you/ai-security-platform \
  --set secrets.existingSecret=aisp-secrets \
  --set config.databaseUrl="postgresql+asyncpg://USER:PASS@pg-host:5432/platform" \
  --set config.redisUrl="redis://redis-host:6379/0" \
  --set config.clickhouseUrl="http://ch-host:8123" \
  --set config.redpandaBrokers="redpanda-host:9092"
```

## What it creates

| Component | Workload | HA |
| --- | --- | --- |
| API (`uvicorn app.main:app`) | Deployment + Service (+ optional Ingress/TLS) | HPA (2–10) + PDB + anti-affinity |
| EPA consumer (`scripts.epa_consumer`) | Deployment | replicas (≤ partition count) + PDB |
| Worker (optional) | Deployment | — |
| Config / secret | ConfigMap + Secret (or external) | — |
| Metrics | ServiceMonitor (opt-in) | — |

## Production checklist

- **Stateful deps are NOT in this chart.** Point `config.*` at managed
  Postgres+pgvector, ClickHouse (replicated), Redis (cluster/sentinel), and
  Redpanda (RF≥3). See `docs/HA-DR-RUNBOOK.md`.
- **Secrets:** set `secrets.existingSecret` to a Secret backed by Vault / AWS
  Secrets Manager / KMS (key `jwt-secret`); never ship the literal. The API
  fails closed at startup if `JWT_SECRET` is unset (`security/secret_gate.py`).
- **TLS:** terminate at the Ingress (`api.ingress.tls`) and on the SDK ↔ agent
  ↔ control-plane path.
- **Migrations:** run `alembic upgrade head` (one-off Job or `kubectl exec`)
  before first traffic — see `NOTES.txt`.
- **EPA consumer scaling:** each replica joins the `epa-fleet` consumer group;
  scale up to (not beyond) the `runtime.events` partition count.

## Validate before applying

```bash
helm lint deploy/helm/ai-security-platform --set secrets.jwtSecret=dev-32-chars-xxxxxxxxxxxxxxxxxx
helm template aisp deploy/helm/ai-security-platform --set secrets.jwtSecret=dev-32-chars-xxxxxxxxxxxxxxxxxx | kubectl apply --dry-run=server -f -
```
