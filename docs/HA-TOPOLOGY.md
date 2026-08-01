# HA topology — one regional cell (P13)

> **Status: the venue is built; the drill has not been run.** This describes a
> production-*shaped* staging topology and records exactly which of its claims
> have live evidence and which are verified only as rendered manifests. It does
> **not** discharge the DR gate. Backup/restore and failover under a business
> RPO/RTO is P14, and P14 cannot start until Ryan approves those numbers.

[`HA-DR-RUNBOOK.md`](HA-DR-RUNBOOK.md) said what the topology should be. Every
row of its HA table was `☐ not configured`, because the topology existed only
as prose. This turns it into something that renders, gets checked, and — for
part of it — actually runs.

## What the cell is made of

| Tier | Shape | Where |
| --- | --- | --- |
| PostgreSQL | primary + streaming standby, replication slot, synchronous commit, WAL archived + scheduled base backup (PITR) | `deploy/helm/aisp-data-tier/templates/postgres.yaml` |
| Redis | primary + replica, AOF persistence, 3 Sentinels (quorum 2) | `.../redis.yaml` |
| ClickHouse | 2 ReplicatedMergeTree replicas + 3 Keeper nodes, scheduled `BACKUP` to a destination | `.../clickhouse.yaml` |
| Redpanda | 3 brokers, RF 3, min in-sync replicas 2 | `.../redpanda.yaml` |
| Control plane | ≥2 API replicas (HPA floor 2), PDB, probes | `deploy/helm/ai-security-platform/templates/api.yaml` |
| EPA consumer | ≥2 replicas, PDB, **new** heartbeat liveness probe | `.../epa-consumer.yaml` |

Every workload carries a PodDisruptionBudget, liveness and readiness probes,
and pod anti-affinity. The stateful tier uses **required** anti-affinity rather
than preferred: a standby co-scheduled with its primary cannot survive the node
that the standby exists to survive, so it stays `Pending` instead — a visible
failure rather than a silent loss of redundancy.

## The gates that hold it in place

**Immutable digests, enforced at render.** `templates/validate.yaml` refuses
anything that is not `sha256:<64 hex>` — including version tags like
`:v24.2.7`, which a registry owner can re-point whenever they like. There is no
tag fallback anywhere in the chart, so the helper *cannot* emit a mutable
reference. Unconditional, unlike the control-plane chart's production-only
gate: a staging cell floating on mutable tags cannot serve as game-day
evidence, because the thing you tested is not the thing you would restore.

**HA floors, enforced at render.** RF < 3, min-ISR < 2, fewer than 3 sentinels
or keepers, a single ClickHouse replica, a primary with no standby, PITR with
no archive destination, a backup with no destination, AOF disabled — each fails
`helm template` with a message that says why it matters. Thirteen of these are
exercised as negative renders in CI.

**Post-render verification.** `scripts/verify_topology.py` reads the *rendered*
manifests — not the values — because the gap between an input and its output is
exactly where a conditional silently drops a PDB. It checks digest pinning, the
absence of plaintext secrets, replica floors, PDBs, anti-affinity strength,
probes, and the durability annotations. It is unit-tested against fixtures that
violate each rule individually, so a rule that stopped working would be caught.

## What has live evidence, and what does not

This is the part worth reading carefully.

| Claim | Evidence | Transcript |
| --- | --- | --- |
| PostgreSQL streams to a standby; the standby is read-only and in recovery | **live** | [`evidence/p13/replication-rehearsal.txt`](evidence/p13/replication-rehearsal.txt) |
| A committed row arrives on the standby | **live** | same |
| WAL reaches the archive with zero failures | **live** | same |
| Redis AOF on; replica linked; key replicates | **live** | same |
| Sentinel quorum reachable; **a real failover elects a new master**; the old primary is demoted rather than returning as a second master | **live** | same |
| Migration upgrade → downgrade-to-base → upgrade, schema byte-identical | **live** | [`evidence/p13/migration-rehearsal.txt`](evidence/p13/migration-rehearsal.txt) |
| A regional cell serves a resident tenant and refuses a foreign-region tenant with 421 `tenant_region_unavailable` | **live** | [`evidence/p13/cell-rehearsal.txt`](evidence/p13/cell-rehearsal.txt) |
| A rolling replacement of API replicas drops zero requests | **live** | same |
| Digest-only admission; no plaintext secrets; replica/PDB/probe/anti-affinity floors | **rendered + checked** | [`evidence/p13/deployment-receipt.txt`](evidence/p13/deployment-receipt.txt) |
| **ClickHouse replication actually replicating** | **NOT verified** | — |
| **Redpanda RF 3 / min-ISR 2 actually enforced by a running cluster** | **NOT verified** | — |
| **Anti-affinity honoured by a real scheduler** | **NOT verified** | — |
| Backup *restore*, failover under load, RPO/RTO | **NOT verified — P14** | — |

The four `NOT verified` rows are shape-only: the manifests say the right thing
and the render refuses the wrong thing, but nothing has run them.

### Why those four are not verified

This sprint had no staging cluster (`kubectl config get-contexts` was empty), so
the fallback was a local multi-node cluster. That was not possible either:
Docker's DNS on this machine returns **IPv6-only** addresses for registries with
no IPv6 route, so `docker pull` hangs indefinitely — a 10 KB `hello-world` did
not complete in five minutes while `curl` to the same registries returned
normally. No pulls means no `kindest/node` image, so no kind/k3d cluster, and no
ClickHouse or Redpanda images.

Repairing it requires restarting Docker Desktop, which would have killed
containers other work on this machine depends on. So the rehearsals were run
against the images already present locally (`pgvector/pgvector`, `redis`), which
is why PostgreSQL and Redis have live evidence and ClickHouse and Redpanda do
not. Docker also caps out at ~3.8 GiB here, well under what a 3-broker Redpanda
plus replicated ClickHouse would need.

Running the four remaining claims needs a real cluster. That is a prerequisite
for P14, not an optional extra.

## Running it yourself

```sh
# Render, verify, and produce a receipt (digests are required, never defaulted)
CELL_REGION=us-east-1 PG_DIGEST=sha256:... REDIS_DIGEST=sha256:... \
CH_DIGEST=sha256:... CH_KEEPER_DIGEST=sha256:... RP_DIGEST=sha256:... \
APP_DIGEST=sha256:... FRONTEND_DIGEST=sha256:... \
scripts/topology_receipt.sh

# Live data-tier rehearsal (PostgreSQL + Redis; recreates the cell first)
scripts/replication_rehearsal.sh

# Live control-plane rehearsal (region refusal + rolling restart)
scripts/cell_rehearsal.sh

# Migration rehearsal — refuses any non-local or production-labelled DATABASE_URL
scripts/migration_rehearsal.sh
```

The rehearsal compose file is `deploy/staging-cell/docker-compose.rehearsal.yml`.
It is **not** the topology — the chart is. It exists because a chart cannot
demonstrate that replication streams or that a failover elects.

## Two defects these rehearsals found

Both were invisible to the existing test suite, which is the argument for
running things rather than inspecting them.

1. **The migration chain could not reach base against a real database.**
   `0003_asset_graph_v2`'s upgrade drops the v1 governance tables as a
   documented one-way pivot and never restores them, so the unconditional
   `op.drop_table` calls in `0001` and `0002` hit tables that were already gone
   and raised `UndefinedTableError`. `test_migrations.py` passed throughout: it
   checks that each migration *has* a downgrade and that its offline SQL is
   symmetric, neither of which executes the chain against data. Fixed by scoping
   `IF EXISTS` to exactly the pivot's table list — not blanket, which would turn
   real schema drift into a silent no-op.

2. **The EPA consumer had no liveness probe and no health signal at all.** It
   serves no port, so there was nothing to probe; meanwhile the ways it actually
   stops working — a rebalance that never completes, a half-closed broker
   connection, an await that never returns — all leave the container `Up` while
   detection has silently stopped. Now the loop records a heartbeat each time
   round and an exec probe reads its age (`app/epa/heartbeat.py`). A file rather
   than an endpoint, because the probe has to work when the process is too
   wedged to answer a request — which is the case it exists for.

## What this does not claim

The deployment decision is unchanged: **not approved**, **not a release
candidate**. `ENG-PRODUCTION` and the DR gate stay open and blocking. This
sprint built the venue; the drill is P14, and it needs business-approved RPO and
RTO targets before it can be scheduled.
