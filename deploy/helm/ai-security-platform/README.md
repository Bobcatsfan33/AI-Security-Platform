# ai-security-platform Helm chart (control plane)

Deploys the multi-tenant **control-plane API**, **operator dashboard**, the
**EPA detection consumer fleet**, and an optional **background worker** —
HA-ready, with secrets via a managed or external Secret.

```bash
helm install aisp deploy/helm/ai-security-platform \
  --namespace ai-security --create-namespace \
  --set image.repository=ghcr.io/you/ai-security-platform \
  --set image.digest=sha256:REPLACE_WITH_APPROVED_RELEASE_DIGEST \
  --set frontend.image.repository=ghcr.io/you/asp-frontend \
  --set frontend.image.digest=sha256:REPLACE_WITH_APPROVED_FRONTEND_DIGEST \
  --set secrets.existingSecret=aisp-secrets
```

## What it creates

| Component | Workload | HA |
| --- | --- | --- |
| API (`uvicorn app.main:app`) | Deployment + Service (+ optional Ingress/TLS) | HPA (2–10) + PDB + anti-affinity |
| Operator dashboard (Next.js) | Deployment + Service (+ same-origin Ingress/TLS) | HPA (2–6) + PDB + anti-affinity |
| EPA consumer (`scripts.epa_consumer`) | Deployment | replicas (≤ partition count) + PDB |
| Worker (optional) | Deployment | — |
| Config / secret | ConfigMap + Secret (or external) | — |
| Metrics | ServiceMonitor (opt-in) | — |

## Production checklist

- **Release identity:** use the backend and frontend digests from their
  approved release receipts and verify each signature, SPDX attestation, and
  provenance as described in `docs/RELEASE-ASSURANCE.md`. Production rendering
  rejects tags for both enabled images.
- **Same-origin browser routing:** enable `frontend.ingress` (or configure an
  equivalent enterprise gateway) so `/v1` routes to the API Service and `/`
  routes to the frontend Service. This avoids environment-specific rebuilds
  and keeps browser API calls and OIDC redirects on one TLS origin.
- **Stateful deps are NOT in this chart.** Point `config.*` at managed
  Postgres+pgvector, ClickHouse (replicated), Redis (cluster/sentinel), and
  Redpanda (RF≥3). See `docs/HA-DR-RUNBOOK.md`.
- **Secrets:** set `secrets.existingSecret` to a Secret backed by Vault / AWS
  Secrets Manager / Azure Key Vault / GCP Secret Manager; it must contain
  `jwt-secret`, `database-url`, `redis-url`, `clickhouse-url`, and
  `redpanda-brokers`. Never ship literals. The API fails closed at startup if
  `JWT_SECRET` is unset (`security/secret_gate.py`).
- **Secrets Store CSI:** optionally set
  `secrets.secretProviderClass.enabled=true`, its provider-specific
  `parameters`, and `secretObjects`. The chart creates and mounts a
  `SecretProviderClass`; `secretObjects` must synchronize the Secret named by
  `secrets.existingSecret`. The CSI driver/provider and secret-sync feature are
  cluster prerequisites.
- **TLS:** terminate at the Ingress (`api.ingress.tls`) and on the SDK ↔ agent
  ↔ control-plane path.
- **Migrations:** run `alembic upgrade head` (one-off Job or `kubectl exec`)
  before first traffic — see `NOTES.txt`.
- **EPA consumer scaling:** each replica joins the `epa-fleet` consumer group;
  scale up to (not beyond) the `runtime.events` partition count.

## Validate before applying

```bash
helm lint deploy/helm/ai-security-platform \
  --set secrets.existingSecret=aisp-secrets \
  --set image.digest=sha256:REPLACE_WITH_APPROVED_RELEASE_DIGEST \
  --set frontend.image.digest=sha256:REPLACE_WITH_APPROVED_FRONTEND_DIGEST
helm template aisp deploy/helm/ai-security-platform \
  --set secrets.existingSecret=aisp-secrets \
  --set image.digest=sha256:REPLACE_WITH_APPROVED_RELEASE_DIGEST \
  --set frontend.image.digest=sha256:REPLACE_WITH_APPROVED_FRONTEND_DIGEST \
  --set frontend.ingress.enabled=true \
  | kubectl apply --dry-run=server -f -
```
