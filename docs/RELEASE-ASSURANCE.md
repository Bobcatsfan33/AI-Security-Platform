# Release assurance

The repository release workflow is the policy of record for the backend,
frontend, and runtime-agent images. A production artifact is eligible for
deployment only when all of the following are true:

1. the source commit passed the normal CI, CodeQL, release-equivalent image
   build, locked-down runtime smoke test, SPDX SBOM generation, and the fixable
   HIGH/CRITICAL vulnerability gate;
2. a protected semantic-version tag (`vMAJOR.MINOR.PATCH`) identifies a commit
   already merged to `main`;
3. required reviewers approve the `production-release` GitHub environment;
4. the workflow signs the exact GHCR digest, attaches an SPDX attestation and
   GitHub build provenance, then verifies both against the tag-qualified
   workflow identity; and
5. deployment admission allows the approved digest from the retained release
   receipt. Mutable tags are discovery labels, not authorization.

No repository setting is created by this document. Administrators must protect
release tags, require the release environment reviewers, prevent self-approval,
retain Actions evidence, and make the security and CI jobs required merge
checks.

## Verify before admission

Set the image and digest from the reviewed release receipt:

```bash
export IMAGE=ghcr.io/bobcatsfan33/ai-security-platform
export DIGEST=sha256:REPLACE_WITH_RELEASE_RECEIPT_DIGEST
export TAG=v1.2.3

cosign verify \
  --certificate-identity "https://github.com/Bobcatsfan33/AI-Security-Platform/.github/workflows/security.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "${IMAGE}@${DIGEST}"

cosign verify-attestation \
  --certificate-identity "https://github.com/Bobcatsfan33/AI-Security-Platform/.github/workflows/security.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --type spdxjson \
  "${IMAGE}@${DIGEST}"

gh attestation verify "oci://${IMAGE}@${DIGEST}" \
  --repo Bobcatsfan33/AI-Security-Platform
```

Repeat with `asp-frontend` and `ai-security-platform-agent`. An admission policy
must match the repository, workflow, tag identity, and an approved digest
allowlist. Verifying only that *some* GitHub identity signed an image is
insufficient.

## Pinned build inputs

Docker base indexes and every third-party action in the release workflow are
commit- or digest-pinned. Dependabot proposes action updates; base-image updates
are explicit reviewed pull requests. The workflow asserts the expected base
metadata so a Dockerfile/workflow drift fails before release.

The runtime agent ships from `scratch` as a static binary with only the CA
bundle copied from its pinned Go builder. Backend runtime dependencies are
installed from the hashed lock; frontend dependencies use `npm ci`.

## Evidence and exceptions

Pull-request SBOM and vulnerability JSON artifacts are retained for 30 days.
Release SBOMs and receipts are retained for 90 days in addition to registry
attestations. A fixable HIGH or CRITICAL vulnerability blocks release. Any
exception for an unfixed or proven-unreachable vulnerability requires a
reviewed, owned, time-boxed ledger entry; the repository currently has no image
vulnerability exceptions.

## Rotation and rollback

Rebuild after a base, dependency, compiler, signing-workflow, or material source
change. Never retag an old digest as a new release. Rollback selects a previously
approved digest whose signing identity and attestations still verify; it does
not rebuild from an old tag.
