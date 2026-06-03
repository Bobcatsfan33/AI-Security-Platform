# HA / DR Runbook & Residency Notes (Phase G — SCAFFOLDING)

> **Status: SCAFFOLDING, not validated.** This document captures the intended
> HA/DR architecture and the steps an operator must execute and *verify*. None
> of the failover/restore procedures below have been exercised in a game-day.
> Phase G is not complete until each "Verify" step has a recorded, passing run.

## High availability (target topology)

| Tier | HA approach | Status |
| --- | --- | --- |
| PostgreSQL 16 + pgvector | Primary + ≥1 streaming replica; automated failover (Patroni / cloud-managed) | ☐ not configured |
| Redis 7 | Sentinel or managed cluster; AOF persistence | ☐ not configured |
| ClickHouse | ReplicatedMergeTree, ≥2 replicas per shard | ☐ not configured |
| Redpanda | RF ≥ 3, `min.insync.replicas=2` | ☐ not configured |
| Control plane (FastAPI) | ≥2 stateless replicas behind a load balancer (already stateless) | ☐ replicas not set |
| EPA consumer fleet | Partitioned by `agent_instance_id`; rebalances on member loss (Sprint 6) | ☐ not deployed as a service |

Helm values to add (then verify a rolling restart keeps detection live):
- `replicaCount: 2+` for the control plane and EPA consumer deployments
- PodDisruptionBudget, readiness/liveness probes (ServiceMonitor already shipped)
- Anti-affinity so replicas span nodes/zones

## Disaster recovery

Targets (proposed — confirm with the business): **RPO ≤ 5 min, RTO ≤ 30 min.**

| Store | Backup mechanism | Restore procedure | Verified? |
| --- | --- | --- | --- |
| PostgreSQL | WAL archiving + nightly base backup (PITR) | restore base + replay WAL | ☐ |
| ClickHouse | `BACKUP TABLE` to object storage | `RESTORE` from latest | ☐ |
| Redis | AOF + RDB snapshot | reload AOF (envelopes/narratives are rebuildable from ClickHouse replay) | ☐ |
| Audit log | hash-chained; export the chain off-box | verify chain integrity on restore (INTEGRITY_VERIFIED) | ☐ |

**Game-day procedure (must be run + recorded):**
1. Snapshot baseline `/v1/validation/efficacy` (detection still 1.0).
2. Kill the PG primary; confirm failover < RTO; confirm no audit-chain gap.
3. Restore ClickHouse from backup into a clean namespace; confirm `causal-subtree`
   queries return the expected flows (RPO check).
4. Re-run `/v1/validation/efficacy`; detection rate must remain 1.0.
5. Record timings; file gaps as blockers.

## Data residency

- Pin each tenant's operational (PG) and telemetry (ClickHouse) data to a region;
  document the per-region data-flow diagram. ☐ not implemented (needs a
  tenant→region mapping + region-scoped connections).
- Redpanda topics and Redis must be region-local; cross-region replication only
  for DR, with residency-compatible destinations.

## Tenant isolation under load

- Per-tenant rate limiting at the API and per-`org_id` fairness in the EPA
  consumer (avoid a noisy tenant starving others). ☐ not implemented.
