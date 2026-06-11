# Secure SDLC Policy

> One-page policy of record for the AI Security Platform's development lifecycle
> and its enforced gates. Input to the NIST SSDF (SP 800-218) self-attestation
> and F500 vendor-security review. Owner: @Bobcatsfan33. Review cadence: annual
> or on any change to the gates below.

## 1. Scope

All first-party code in this repository — the FastAPI control plane (`backend/`),
the Go runtime agent (`runtime-agent/`), the Next.js workbench (`frontend/`), and
infrastructure-as-code (`deploy/`, `.github/`).

## 2. AI-assisted development workflow

Code in this repository is authored with AI assistance under human direction.
Every change — AI-assisted or not — is subject to the **same** enforced gates
below; AI authorship grants no exception. The human maintainer is accountable for
every merged line. The intent is recorded here so the assisted workflow is a
documented, governed process rather than an undisclosed one (SSDF PO.3, PW.1).

## 3. Change flow (PW, RV)

1. **Branch.** No direct commits to `main` (SH-2 branch protection).
2. **Pull request.** Every change lands via PR with a description and test plan.
3. **Review.** At least one approving review from a CODEOWNER who is **not** the
   author (`.github/CODEOWNERS`, `require_last_push_approval`). Security-sensitive
   paths (auth, db, security, scim, runtime-agent, .github, deploy) require a
   code-owner review specifically.
4. **Status checks.** All required checks must pass and the branch must be
   up to date before merge (`strict` status checks).
5. **Signed commits.** `required_signatures` is enforced on `main`.
6. **Merge.** Squash merge; the feature branch is deleted.

## 4. Enforced gates (PW.7, PW.8, RV.1)

| Gate | Tool / job | Blocks merge |
|------|-----------|--------------|
| Unit + integration tests | `Backend unit tests` (pytest, Postgres+Redis) | yes |
| Frontend build | `Frontend (Next.js)` | yes |
| Go build + race | `Runtime agent (Go)` (`go test -race`) | yes |
| Secret scanning | `Security gates` → gitleaks | yes |
| Python SAST | `Security gates` → bandit (high) | yes |
| Go SAST | `Security gates` → gosec (high/high) | yes |
| Dependency audit | `Security gates` → npm audit (high), pip-audit | yes |
| SAST (CodeQL) | `security-suite / codeql` (python, go, javascript) | yes¹ |
| Image scan | `security-suite / build-scan-sign` → Trivy (HIGH/CRITICAL) | yes¹ |
| SBOM + signing + provenance | `security-suite` → CycloneDX, cosign, SLSA | yes¹ |

¹ Added by the supply-chain workstream (A-3); calls the org-level reusable
workflow `Bobcatsfan33/.github/.github/workflows/security-reusable.yml`.

## 5. Tenant isolation (SC, AC)

Cross-tenant access is prevented at two independent layers — an ORM guard and
Postgres Row-Level Security (`backend/app/db/tenancy.py`, migration
`0006_enable_rls`). The only sanctioned guard bypasses are API-key and SCIM IdP
resolution, both audited and grep-enforced to exactly two sites. See
`docs/` and the A-1 PR for detail.

## 6. Vulnerability response (RV.2, RV.3)

A HIGH/CRITICAL finding from any gate blocks release. The only waiver path is a
justified, time-boxed entry in `.trivyignore` / `.gitleaks.toml` / a `# nosec`
with rationale, added by PR and therefore itself reviewed. Exposed secrets are
rotated immediately and the exposure window is recorded.

## 7. Continuity

Two maintainers with merge rights (SH-2) so the project does not depend on a
single person. Onboarding the second maintainer is tracked as the remaining SH-2
external dependency.
