# GA Readiness Checklist (Phase H)

> **Status update.** Track A engineering (A1–A5) is COMPLETE and merged:
> inline ML/LLM enforcement, coverage ratchet 24→40, control-plane Helm chart
> with HA, Prometheus/OTel observability, and migration integrity guards.
> Track B docs are DONE: SOC 2 evidence map (`docs/SOC2-EVIDENCE-MAP.md`) and
> the detection-content authoring guide (`docs/PATTERN-AUTHORING-GUIDE.md`).
>
> What remains genuinely requires **external parties + a multi-month window**
> (penetration testers, SOC 2 auditor) or **live infrastructure** (HA-DR
> game-day). Those cannot be completed autonomously and are NOT done — this
> file tracks them.

## HA topology (P13) — the venue for the game-day
- ☑ Define the regional cell as a chart that **renders or fails**: PostgreSQL
  primary + standby with PITR, Redis with AOF + 3 Sentinels, replicated
  ClickHouse + Keeper with a backup destination, Redpanda RF 3 / min-ISR 2, ≥2
  control-plane replicas, an EPA consumer fleet, PDBs, required anti-affinity,
  and probes. Digest-only images: mutable tags fail rendering, with no tag
  fallback to leak through. Thirteen negative renders are asserted in CI.
- ☑ Verify the **rendered** manifests (`scripts/verify_topology.py`): digest
  pinning, no plaintext secrets, replica floors, PDBs, anti-affinity strength,
  probes, durability annotations. Unit-tested against fixtures violating each
  rule so the checker cannot quietly stop checking.
- ☑ Exercise, with retained transcripts under `docs/evidence/p13/`: PostgreSQL
  streaming replication + WAL archiving + read-only standby; Redis Sentinel
  failover and demotion of the old primary; migration downgrade-to-base and
  re-upgrade (schema byte-identical); regional refusal of a foreign tenant
  (421); a rolling API replacement dropping zero requests.
- ☐ **Not exercised — needs a real cluster:** ClickHouse replication, Redpanda
  replication-factor enforcement, scheduler-honoured anti-affinity. No cluster
  was reachable and image pulls were unavailable in this environment; see
  [HA-TOPOLOGY.md](HA-TOPOLOGY.md) for the claim-by-claim split.
- ☐ Stand the cell up on a real staging cluster. **This is a prerequisite for
  the game-day below, not an optional extra.**

## Third-party penetration test
- ☐ Engage a third-party pen-test firm. **Book by the start of efficacy
  validation, not at the end** — findings reset the timeline.
- Scope must include:
  - ☐ Runtime agent reverse proxy (auth bypass, request smuggling, SSRF to upstream)
  - ☐ SDK ↔ control-plane trust boundary + the causal-lineage propagation headers
    (can a client forge `x-aisp-*` / `traceparent` to poison the poset?)
  - ☐ Pattern DSL evaluation sandbox (resource exhaustion via crafted patterns)
  - ☐ Multi-tenant isolation (cross-`org_id` access on every `/v1` route,
    incl. narratives / suppressions / validation)
  - ☐ Suppression abuse (can an attacker get a malicious flow auto-suppressed?)
- ☐ Remediate criticals/highs; re-test.

## SOC 2 Type II readiness
- ☐ Leverage the existing evidence-pack builder (`app/compliance/evidence_pack.py`).
- Control areas to evidence:
  - ☐ Access control — RBAC (`auth/rbac.py`), SCIM deprovisioning
  - ☐ Audit — hash-chained `security/audit_log.py`; verify dispositions,
    suppression activations, narrative promotions are all captured
  - ☐ Encryption — field-level (`security/field_crypto.py`), TLS, secrets resolver
  - ☐ Change management — CI gates, this branch+PR workflow
  - ☐ Availability — the HA/DR game-day results (see HA-DR-RUNBOOK.md)
  - ☐ Monitoring — platform OTel/Prometheus self-observability (Phase 0 item;
    confirm coverage of the EPA fleet)
- ☐ Map controls → evidence artifacts; dry-run with the auditor.

## Commercial / GA
- ☐ Metering + tiers (the roadmap's deferred Tier-4); billing hooks
- ☐ Entitlement enforcement for paid tiers (the source is Apache-2.0 — this
  gates the hosted/supported offering, not the right to run the code)
- ☐ GA docs: install, operator runbook, **detection-content authoring guide**
  (the pattern DSL — Sprint 9/10), API reference, upgrade/migration guide
- ☐ Support runbooks, SLA definition, on-call, status page

## Coverage-ratchet exit (carried from Phase 0)
- ☑ Raise the backend coverage floor to the 80% standard. Measured coverage of
  `app` is **84.05%** under the full Postgres + Redis suite (2026-07-31, 1392
  passed / 1 skipped), up from 75.29%, and `fail_under` is raised 70 → 80 so CI
  prevents regression below the target itself. The concentrations this item
  named are closed: connector `generate()` and error paths, API routes,
  policy-cache invalidation and failure modes, report generation, and SCIM
  lifecycle and malformed-input handling. No `# pragma: no cover`, `omit`
  entry, or exclusion was added to reach the number — the floor sits below
  measured coverage only to absorb ordinary variance, not to hide untested code.
  Two latent defects the new tests surfaced were fixed rather than asserted
  around: a malformed policy-invalidation message killed the Redis subscriber
  for an entire org (leaving a retired policy enforceable behind a silently
  dead cache), and an out-of-taxonomy finding severity raised `KeyError`
  through report generation.
- ☑ Enforce the repository-wide Ruff baseline in CI. The full `app` and
  `tests` trees are clean; narrowly documented exceptions preserve FastAPI,
  SCIM, and public plugin naming contracts rather than disabling rule families.
- ☑ Normalize and enforce the repository-wide Black baseline in CI so formatter
  drift is rejected on every backend change.
