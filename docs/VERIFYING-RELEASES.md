# Verifying a release

Every released image is signed with [cosign](https://docs.sigstore.dev/) using
keyless (OIDC) signing, ships an SPDX SBOM as a signed attestation, and carries
GitHub build provenance. None of that is worth anything if nobody checks it, so
here is how — and what each check actually proves.

You need [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/)
and, for the provenance step, the [`gh`](https://cli.github.com/) CLI.

```sh
export IMAGE=ghcr.io/bobcatsfan33/ai-security-platform
export VERSION=v0.1.0
```

## 1. Resolve the tag to a digest, then stop using the tag

```sh
DIGEST=$(cosign triangulate --type digest "${IMAGE}:${VERSION}")
echo "${DIGEST}"
```

A tag is a mutable pointer. Everything below verifies the **digest**, because
verifying a tag proves only what that name pointed at when you looked.

## 2. Verify the signature

```sh
cosign verify \
  --certificate-identity-regexp '^https://github\.com/Bobcatsfan33/AI-Security-Platform/\.github/workflows/security\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "${DIGEST}"
echo "exit=$?"     # 0 means verified
```

**Both flags are load-bearing, and the exit code is the result.** `cosign
verify` without an identity constraint checks that *somebody* signed the image,
which is a much weaker claim than it looks — anyone can sign anything. Pinning
the identity to this repository's release workflow at a version tag is what
makes the signature mean "this came from that pipeline", and a zero exit with
those flags set is the proof. cosign prints the human-readable summary to
stderr; the JSON on stdout confirms which digest was checked:

```sh
cosign verify --certificate-identity-regexp '...' --certificate-oidc-issuer '...' \
  "${DIGEST}" 2>/dev/null | jq -r '.[0].critical.image."docker-manifest-digest"'
```

(Earlier drafts of this page suggested `jq '.[0].optional.Subject'`. That field
is empty on current cosign releases, so the command printed nothing and looked
like a failure. Verified against cosign 3.x before publishing v0.1.0.)

## 3. Verify the SBOM attestation

```sh
cosign verify-attestation \
  --type spdxjson \
  --certificate-identity-regexp '^https://github\.com/Bobcatsfan33/AI-Security-Platform/\.github/workflows/security\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "${DIGEST}" \
  | jq -r '.payload' | base64 -d | jq '.predicate.name, (.predicate.packages | length)'
```

Proves the SBOM was produced by the same pipeline and describes this exact
image, rather than being a file somebody uploaded next to it.

## 4. Verify build provenance

```sh
gh attestation verify "oci://${DIGEST}" --repo Bobcatsfan33/AI-Security-Platform
```

Proves which workflow, at which commit, built these bytes.

## What this does and does not tell you

**Does:** these bytes were built by this repository's release workflow, from a
commit on `main`, and have not been altered since. The SBOM lists what is inside
them.

**Does not:** that the code is free of vulnerabilities, that it has been audited,
or that it is fit for production. A signature is a claim about *provenance*, not
about *quality*. This project's own assessment of its readiness is in
[`docs/enterprise-readiness.json`](enterprise-readiness.json), and the current
deployment decision is `not-approved`.

## If verification fails

Do not use the image. Signature verification failing is either tampering, or a
release published outside the normal pipeline; both are worth an issue.

A common false alarm: an identity regex that does not match because the release
was cut from a differently-named workflow or ref. Check the actual certificate
subject before assuming the worst:

```sh
cosign verify --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "${DIGEST}"
```

cosign prints the certificate subject and issuer in its stderr summary; that is
where to look when the identity regex is what failed.

That command is for *diagnosis only* — `--certificate-identity-regexp '.*'`
accepts a signature from anyone, so never use it as your actual check.
