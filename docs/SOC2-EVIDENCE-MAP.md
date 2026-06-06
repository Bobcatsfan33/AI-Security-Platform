# SOC 2 Type II — Scope & Evidence Map (B0)

> **Status: evidence mapping DONE; observation window + audit NOT started.**
> B0 (this document) maps each in-scope control to a concrete platform artifact
> so the auditor can dry-run the evidence pack before the observation window
> opens. B1 (pen test) and B3 (Type II observation + auditor report) require
> external parties and a 3–6 month window — they cannot be completed here.

## Scope

- **Trust Services Criteria in scope:** Security (CC, mandatory) + Availability
  (A) + Confidentiality (C).
- **System boundary:** the control-plane API, the EPA detection consumer fleet,
  the runtime agent, and their data stores (Postgres, ClickHouse, Redis,
  Redpanda). SDKs are client libraries (in scope for the trust boundary only).
- **Evidence automation:** `app/compliance/evidence_pack.py` (`build_pack`)
  already emits a `soc2` control pack (ZIP of per-control evidence + audit-log
  export + findings/policy snapshots). This map extends its `CONTROL_MAPPINGS`.

## Control → evidence

| TSC | Control | Platform evidence (artifact) | Status |
| --- | --- | --- | --- |
| CC6.1 | Logical access control | `auth/rbac.py` (5-role RBAC), OIDC/SAML (`identity/`), SCIM 2.0 deprovisioning (`scim/`); every `/v1` route is `org_id`-scoped | ✅ implemented |
| CC6.6 | Encryption in transit | TLS at the Ingress (Helm `api.ingress.tls`) + SDK↔agent↔control-plane | ✅ impl; ☐ verify in cluster |
| CC6.7 | Encryption at rest / secrets | `security/field_crypto.py` (Fernet, rotation), `security/secret_gate.py` (fail-closed if `JWT_SECRET` unset), external Secret via Helm `secrets.existingSecret` | ✅ implemented |
| CC7.1 | Vulnerability management | CI gates; **third-party pen test (B1)** | ☐ B1 (external) |
| CC7.2 | System monitoring | Prometheus `/metrics` + golden-signal + domain metrics (`observability/`, A4); optional OTel tracing; ServiceMonitor (Helm) | ✅ implemented |
| CC7.3 | Anomaly / threat detection | The RAPIDE detection stack: poset graph, EPA fleet, cross-agent correlation, Tier-3 narratives; efficacy measured (`/v1/validation/efficacy`, A4/Sprint 13) | ✅ implemented |
| CC7.2 | Audit logging | `security/audit_log.py` — hash-chained, tamper-evident. Captures auth, policy changes, **narrative dispositions, suppression activations, narrative promotions** (verified by code: `api/v1/narratives.py`, `api/v1/suppressions.py`) | ✅ implemented |
| CC8.1 | Change management | Branch + PR + CI (pytest+coverage ratchet, Go `-race`, frontend build) must be green to merge; this very roadmap | ✅ implemented |
| A1.1 | Availability / HA | Helm HPA + PDB + anti-affinity (A3); **HA-DR game-day** (`docs/HA-DR-RUNBOOK.md`) | ✅ HA primitives; ☐ game-day (infra) |
| A1.2 | Backup / recovery | PITR (PG) + ClickHouse/Redpanda snapshots; migration apply+rollback CI-verified (A5) | ✅ migrations; ☐ restore drill (infra) |
| C1.1 | Confidentiality | Field-level crypto (`field_crypto.py`); threat-intel anonymisation (`threat_intel/anonymize.py` — deterministic hashing + PII redaction before cross-tenant clustering) | ✅ implemented |
| C1.2 | Multi-tenant isolation | ~189 `org_id` scoping filters across `api/v1`; **pen-test cross-tenant probing (B1)** | ✅ impl; ☐ B1 verify |

## Remaining (external / time-gated)

- **B1 — penetration test:** scope in `docs/GA-READINESS-CHECKLIST.md` (agent
  proxy, SDK↔control-plane causal-header forgery, DSL sandbox, multi-tenant
  isolation, suppression abuse). Book before the observation window.
- **B3 — Type II observation window (3–6 mo):** run controls operating over
  time, collecting continuous evidence via `build_pack` + the A4 monitoring,
  then auditor engagement → report. **Start the clock as soon as B0 + the core
  controls (A3 secrets, A4 monitoring, A5 availability) are deployed.**
