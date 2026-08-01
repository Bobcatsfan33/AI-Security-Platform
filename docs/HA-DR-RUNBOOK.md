# HA / DR Runbook & Residency Notes (Phase G)

> **Status: the topology is BUILT and partly EXERCISED; the game-day has NOT
> been run.** P13 turned the table below from an intention into a chart that
> renders, a checker that refuses it when it is wrong, and — for PostgreSQL,
> Redis, and the control plane — transcripts from services that actually ran.
> Phase G is still not complete: the restore, failover-under-load, RPO, and RTO
> procedures in *Disaster recovery* below remain unexercised. That is P14.
>
> **[`HA-TOPOLOGY.md`](HA-TOPOLOGY.md) is the claim-by-claim record** of what
> has live evidence and what is verified only as a rendered manifest. Read it
> before citing anything here as done.

## High availability (topology)

Defined in [`deploy/helm/aisp-data-tier`](../deploy/helm/aisp-data-tier) (data
tier) and [`deploy/helm/ai-security-platform`](../deploy/helm/ai-security-platform)
(control plane). `helm template` **fails** rather than rendering anything below
these floors, and `scripts/verify_topology.py` re-checks the rendered output.

| Tier | HA approach | Status |
| --- | --- | --- |
| PostgreSQL 16 + pgvector | Primary + streaming standby, replication slot, synchronous commit, WAL archive + scheduled base backup | ☑ defined & render-enforced; **replication, archiving and read-only standby exercised live** |
| Redis 7 | AOF persistence; 3 Sentinels, quorum 2 | ☑ defined & render-enforced; **failover and demotion exercised live** |
| ClickHouse | ReplicatedMergeTree ≥2 replicas, 3 Keeper nodes, scheduled `BACKUP` | ☑ defined & render-enforced; ☐ **not exercised** (no image/cluster available) |
| Redpanda | RF ≥ 3, `min.insync.replicas=2` | ☑ defined & render-enforced; ☐ **not exercised** (no image/cluster available) |
| Control plane (FastAPI) | ≥2 replicas (HPA floor 2), PDB, probes | ☑ defined; **rolling restart dropped 0 requests** |
| EPA consumer fleet | ≥2 replicas, PDB, heartbeat liveness probe | ☑ defined (probe added in P13 — it had none) |

Every workload carries a PodDisruptionBudget, liveness and readiness probes, and
pod anti-affinity. The stateful tier uses **required** anti-affinity: a standby
co-scheduled with its primary cannot survive the node it exists to survive, so
it stays `Pending` — a visible failure instead of silent loss of redundancy.

Images are digest-only. There is no tag fallback in the data-tier chart, so it
cannot emit a mutable reference even if values are edited later.

## Migration discipline (A5 — DONE)

- **Apply + rollback are now REHEARSED against a real database.**
  `scripts/migration_rehearsal.sh` seeds data, walks the chain to base and back
  to head, and compares a schema fingerprint on both sides (318 columns,
  byte-identical). Transcript:
  [`evidence/p13/migration-rehearsal.txt`](evidence/p13/migration-rehearsal.txt).
  This found a real defect the unit tests could not: `0003_asset_graph_v2`'s
  upgrade drops the v1 governance tables as a documented one-way pivot, so the
  unconditional `op.drop_table` calls in `0001` and `0002` hit tables that were
  already gone and raised `UndefinedTableError`. The chain could not reach base
  on any real database. Fixed by scoping `IF EXISTS` to exactly the pivot's
  table list.
- **Apply + rollback are CI-verified.** `tests/unit/test_migrations.py` enforces
  a single linear revision chain (one base, one head, no dangling
  down_revisions), a real downgrade on every migration (forward+rollback
  discipline), no model→migration drift (every model table has a
  `create_table`), and a **DB-free offline round-trip**: Alembic emits symmetric
  forward `CREATE TABLE` ↔ rollback `DROP TABLE` SQL. ✅
- CI also runs `alembic upgrade head` against a real Postgres before the suite. ✅
- Open: a live downgrade→upgrade drill against a production-shaped DB (part of
  the game-day below).

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

**Engineering control implemented; deployment validation remains open.** Every
`Organization` has a non-null `data_region`. Each production process and Helm
release must declare exactly one `DEPLOYMENT_REGION`; JWT, API-key, SSO, SAML
metadata, refresh, and SCIM entry points return `421 tenant_region_unavailable`
before tenant context or a write is armed when the values differ. Refresh
tokens are inspected for routing without consuming the single-use token in the
wrong cell. `/v1/auth/me` returns the verified `data_region`.

Each regional cell must use region-local PostgreSQL, ClickHouse, Redis, audit
sinks, and Redpanda. Production configuration requires
`RUNTIME_EVENTS_TOPIC` to end in `.<DEPLOYMENT_REGION>` so regional EPA fleets
cannot accidentally share the same topic name. Helm renders neither operational
URLs nor credentials from values in production; the region's externally
managed Secret supplies those endpoints.

### Provisioning and verification

1. Approve the tenant's region and data-flow record before creating data.
   Migration `0012_tenant_data_region` deliberately marks existing tenants
   `local`; production rejects them until an operator assigns an approved
   region under change control.
2. Set the tenant mapping in its current authoritative PostgreSQL cell:
   `UPDATE organizations SET data_region = 'us-east-1' WHERE id = '<tenant>';`.
   There is no tenant self-service region-change endpoint.
3. Deploy one release per region with, for example,
   `config.deploymentRegion=us-east-1` and
   `config.runtimeEventsTopic=runtime.events.us-east-1`. Use region-specific
   Secrets, namespaces/accounts, ingress, audit destinations, backup stores,
   KMS keys, and network allowlists.
4. Configure the trusted global ingress from its protected tenant directory.
   Regional services do not reveal or redirect to the target region.
5. Verify a resident JWT and API key return the configured region from
   `/v1/auth/me`; replay both against another cell and retain the expected 421
   responses plus `tenant.residency.route_denied` audit evidence.
6. Verify the regional topic, consumer group, ClickHouse rows, Redis keys,
   PostgreSQL rows, audit output, backups, and model/provider egress remain
   inside the approved boundary.

A region change is a controlled data migration, not a field edit: quiesce the
tenant, copy and verify every store, preserve audit-chain continuity, change
the ingress mapping and `data_region` atomically, test both cells, then destroy
the old copies under the approved retention policy. Cross-region replication
is permitted only for DR destinations covered by the tenant's residency terms.
The production-topology residency exercise and its signed evidence are still
open.

## Tenant isolation under load

- Per-tenant rate limiting at the API and per-`org_id` fairness in the EPA
  consumer (avoid a noisy tenant starving others). ☐ not implemented.
