# Enterprise procurement and deployment decision

[`enterprise-readiness.json`](enterprise-readiness.json) is the authoritative, expiring index of
product evidence, control gaps, and deployment gates. CI verifies the evidence paths and refuses an
approval claim while controls or blocking gates remain open.

The current decision is **not approved**, and the product is **not yet a software release
candidate**. Signed images, SBOMs, provenance, hardened Helm paths, and strong engineering evidence
exist. Tenant-to-region pinning now fails closed across enterprise identity entry points and
regional runtime topics, but production topology and migration evidence is still required. The
backend test suite measures 84.05 percent statement coverage of `app` under the full Postgres and
Redis suite, and CI enforces an 80 percent floor, so the internal engineering-verification target
is met and protected against regression. These controls do not replace a penetration test,
production HA/DR/residency exercise, representative efficacy evaluation, security operations, or
organizational assurance — and coverage is a measure of what the suite executes, not evidence that
the product behaves correctly in production.

The index is organized for [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final),
[SLSA 1.2](https://slsa.dev/spec/v1.2/),
[OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/),
[CSA CCM/CAIQ 4.1](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1),
[CSA AI-CAIQ 1.0.2](https://cloudsecurityalliance.org/artifacts/ai-consensus-assessments-initiative-questionnaire-ai-caiq),
and [NIST AI RMF 1.0](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10).
AI RMF 1.0 is under revision, so its pinned version must be reassessed when NIST publishes a final
replacement.

Repository CI cannot produce SOC 2 or ISO assurance, Shared Assessments SIG responses, legal and
data-processing terms, subprocessor and residency disclosures, insurance, financial viability,
accessibility, support, or reference checks. Those are vendor and organizational evidence.

Run `python3 scripts/verify_enterprise_readiness.py` before relying on the index.
