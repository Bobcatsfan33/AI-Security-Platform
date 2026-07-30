# Enterprise procurement and deployment decision

[`enterprise-readiness.json`](enterprise-readiness.json) is the authoritative, expiring index of
product evidence, control gaps, and deployment gates. CI verifies the evidence paths and refuses an
approval claim while controls or blocking gates remain open.

The current decision is **not approved**, and the product is **not yet a software release
candidate**. Signed images, SBOMs, provenance, hardened Helm paths, and strong engineering evidence
exist. They do not replace a penetration test, production HA/DR exercise, representative efficacy
evaluation, enterprise identity promotion, security operations, or organizational assurance.

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
