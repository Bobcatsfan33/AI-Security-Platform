# Product incident and vulnerability response

This runbook covers the control plane, frontend, runtime agent, SDKs, model artifacts, policies,
audit evidence, identity boundary, and deployment artifacts. It supplements private reporting in
[`SECURITY.md`](../SECURITY.md); it does not claim a staffed on-call program that does not exist.

## Classify and preserve

- **Critical:** cross-tenant access, authentication bypass, remote execution, signing-key
  compromise, audit-chain compromise, or silent bypass of a fail-closed security decision.
- **High:** confidential-data exposure, exploitable denial of service, policy or model substitution,
  recovery-integrity loss, or security monitoring bypass.
- **Medium/low:** bounded defects without demonstrated confidentiality, integrity, or availability
  impact.

Preserve affected commits, release receipts, image and model digests, SBOMs, provenance, policy
versions, audit-chain exports, logs, and reproduction material. Never copy customer data or secrets
into a public issue or unapproved evidence location.

## Contain and scope

1. Freeze affected releases and admission allowlists; revoke compromised credentials, certificates,
   workflow trust, or image digests.
2. Identify affected tenants, components, routes, agents, SDK versions, policy versions, models,
   regions, and deployment topologies.
3. Use the kill switch or fail-closed policy where it reduces harm, preserving evidence before
   deletion, rollback, rotation, or reprocessing changes state.
4. Validate audit-chain continuity and isolate suspicious telemetry, findings, model artifacts, and
   policy content.

## Remediate and recover

Require a DCO-signed fix, focused regression test, normal CI/security gates, clean release build,
and exact artifact-digest record. Re-run tenant-isolation, fail-closed, model-integrity,
vulnerability, SBOM, signature, provenance, Helm, migration, and recovery checks relevant to the
incident.

Restore only from verified backups and artifacts. Before returning traffic, validate identity,
tenant scoping, policy distribution, audit integrity, telemetry continuity, model identity, and
the affected detection behavior in the target topology.

## Close and learn

Retain a timeline, root cause, affected-version matrix, containment and recovery evidence, customer
impact, and corrective actions with owners. Add permanent regression coverage and update the threat
model, runbooks, controls, gaps, and readiness index.

Named 24x7 responders, exercised customer and regulator notification, production incident drills,
and independent retesting remain open deployment gates.
