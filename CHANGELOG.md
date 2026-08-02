# Changelog

All notable changes to this project. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[semantic versioning](https://semver.org/).

This is a summary, not a commit log. Each entry links the pull request that
carries the reasoning, the measurements, and the tests.

## [0.1.0] — 2026-08-02

First tagged release. The codebase predates it by several months; this is the
point at which it became something a stranger could pick up, which is a
different milestone from "the code works".

**Not production-ready, and the repository says so mechanically.**
[`docs/enterprise-readiness.json`](docs/enterprise-readiness.json) records a
deployment decision of `not-approved` with six open blocking gates, and CI
refuses to let the repository claim otherwise while any gate is open. See
[Status](README.md#status).

### Added

**Detection and enforcement**

- Three-stage policy pipeline — regex/PII, ONNX classifier with an honest
  heuristic fallback, and an LLM judge on escalation — running inline in a Go
  reverse proxy, fail-closed by default (#100, #101, #108).
- Trust-aware prompt-injection model: content arriving from retrieved
  documents and tool output is judged by stricter rules than text a user typed,
  because the trust boundary is a policy input rather than something guessed
  from the text (#108).
- Multilingual injection detection across 13 languages, generated from slot
  vocabulary in both word orders rather than hand-written per language (#128).
- Reported-speech handling: attack text that is quoted *and* framed as a topic
  — a translation request, a test fixture, a blocklist review — is not treated
  as an attack. Quoting alone is not an alibi, and the exemption does not apply
  to untrusted content (#129).
- Script-aware quality signals: the gibberish detector abstains outside Latin
  script instead of scoring every CJK, Cyrillic, and Arabic sentence as
  suspicious (#128).
- Automated red teaming with a strategy library and a judge; successful attacks
  are promoted into the regression suite.
- AI-BOM asset posture, SIEM forwarders (Splunk, Elastic, Sentinel, Datadog,
  Chronicle, webhook), SOAR incident sinks, and OWASP/NIST/EU-AI-Act reports.

**Multi-tenancy and identity**

- Enforced tenant isolation: an ORM guard plus PostgreSQL row-level security,
  with cross-tenant tests required on every mounted route (#124).
- Regional data residency that fails closed — a tenant's traffic reaching the
  wrong regional cell is refused with `421 tenant_region_unavailable` before
  any write is armed (#120).
- Enterprise identity provisioning: OIDC, SAML 2.0, SCIM 2.0, RS256/JWKS
  (#106, #119).

**Operations and supply chain**

- Signed container images (cosign, keyless), SPDX and CycloneDX SBOMs, SLSA
  provenance, CodeQL, Trivy, and a dependency-lock drift gate (#109).
- Production-shaped HA topology as a chart that refuses to render below its own
  floors — replication factor, quorum sizes, PodDisruptionBudgets, required
  anti-affinity, digest-only images (#125).
- Observability as code: 14 alert rules, each with a `promtool` unit test that
  feeds the triggering condition; dashboards whose queries are parsed in CI; a
  synthetic canary that checks detection end to end in both directions (#127).
- Liveness for the EPA consumer fleet, which previously had no health signal at
  all — its failure modes leave the process running while detection silently
  stops (#125).

**Measurement**

- An efficacy harness that consumes hash-pinned corpora with required
  provenance and labeling protocol, refuses train/test leakage before computing
  any metric, reports per-slice precision, recall, FPR and Wilson intervals,
  and **refuses** to satisfy its customer-distribution slice from synthetic
  data (#126).
- Latency benchmarks and an under-load proxy test with the numbers written down
  rather than asserted (#96, #97, #98).

### Changed

- **Relicensed BUSL-1.1 → Apache-2.0** (#130). BUSL states plainly that it is
  not an open-source license; Apache-2.0 was already its declared Change
  License, so this brings that date forward. Third-party attribution is in
  [`NOTICE`](NOTICE) (#131).
- Coverage floor raised 70 → 80 with measured coverage at 84% (#123).
- Repository-wide Ruff and Black baselines enforced in CI (#121, #122).
- README rewritten for a stranger: 60-second quickstart needing no services, an
  architecture diagram, and a Status section that presents the readiness
  manifest as a feature rather than a caveat (#132, #133).

### Fixed

- The migration chain could not reach `base` against a real database — a
  documented one-way pivot left later downgrades dropping tables that were
  already gone. The unit tests could not catch it because they never executed
  the chain against data (#125).
- Malformed policy-invalidation messages killed the Redis subscriber for an
  entire organization, silently, leaving a retired policy enforceable behind a
  stale cache (#123).
- An out-of-taxonomy finding severity raised `KeyError` through report
  generation, and findings mapped outside the pinned OWASP revision vanished
  from an auditor-facing document (#123).
- MCP attribution integrity, unprovisioned-subject writes, and stored tool
  profile sanitization (#91, #92, #94).

### Known limitations

Written down rather than smoothed over — see [`docs/GAPS.md`](docs/GAPS.md) and
the manifest.

- **No independent security assessment.** No penetration test has been
  commissioned.
- **Efficacy numbers are synthetic.** Every measurement in this repository was
  taken on hand-authored corpora and is stamped `synthetic-demonstration`. They
  show that a fix generalises beyond the cases that motivated it — nothing
  about real-world traffic. Real efficacy is unmeasured.
- **No disaster-recovery drill.** The HA topology renders and part of it has
  been exercised, but backup/restore, failover under load, RPO and RTO have
  not. ClickHouse replication and Redpanda replication-factor enforcement are
  verified only as rendered manifests.
- **No approved SLOs and no staffed rotation.** The alert rules fire correctly
  in tests; nothing pages anyone.
- **Single maintainer, no production deployments, no reference customers.**

[0.1.0]: https://github.com/Bobcatsfan33/AI-Security-Platform/releases/tag/v0.1.0
