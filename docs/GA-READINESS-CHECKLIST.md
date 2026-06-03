# GA Readiness Checklist (Phase H — SCAFFOLDING)

> **Status: SCAFFOLDING / checklist.** These items require external parties
> (penetration testers, SOC 2 auditor) and human sign-off. They cannot be
> completed autonomously and are NOT done. This file is the tracking surface.

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
- ☐ License enforcement (BUSL-1.1)
- ☐ GA docs: install, operator runbook, **detection-content authoring guide**
  (the pattern DSL — Sprint 9/10), API reference, upgrade/migration guide
- ☐ Support runbooks, SLA definition, on-call, status page

## Coverage-ratchet exit (carried from Phase 0)
- ☐ Raise the backend coverage floor (currently 24%, an honest ratchet) toward
  the 80% standard as the testing workstream adds tests. The RAPIDE modules
  added this cycle (poset/EPA/patterns/narratives/feedback/validation) ship with
  high coverage; legacy domain modules (siem, soar, threat_intel, scim filters)
  remain the gap.
