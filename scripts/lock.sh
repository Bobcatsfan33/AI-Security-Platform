#!/usr/bin/env bash
# Regenerate backend/requirements.lock from backend/pyproject.toml.
#
# Run this whenever you change a dependency in pyproject.toml, and commit the
# result. CI verifies the lock still matches pyproject and fails if it drifted —
# a lock that has drifted is worse than no lock, because it reports a resolution
# nobody asked for while looking authoritative.
#
# Why a lock exists at all (GAP-016): before it, `pip install -e ".[dev]"`
# resolved whatever was newest at install time, so a laptop and a CI runner
# installed DIFFERENT major versions of the same library — fastapi 0.136 locally
# vs 0.139 in CI. Guardrail 4 says "full suite green before every commit", and
# that guarantee is worth very little when the two suites are running against
# different code. It cost a real CI break to learn.
#
# The lock is also part of the supply-chain story, not just dev hygiene: it
# carries --generate-hashes, and CI installs with --require-hashes, so every
# artifact must match a hash committed to this repo. That is what makes the SBOM
# and SLSA provenance describe something reproducible — an SBOM generated from a
# floating resolution documents one machine's afternoon.
#
# Universal resolution (--universal) so ONE file serves every interpreter in
# requires-python (>=3.11) and both linux CI and macOS dev, rather than a
# per-platform lock that is only true where it was generated.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../backend"

UV_VERSION="0.11.29"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is not installed. Install it with:  pip install uv==${UV_VERSION}" >&2
  exit 1
fi

echo "Regenerating backend/requirements.lock with uv $(uv --version)…"
uv pip compile pyproject.toml \
  --all-extras \
  --universal \
  --generate-hashes \
  -o requirements.lock

echo ""
echo "Done. Review the diff and commit it:"
echo "    git diff backend/requirements.lock"
echo ""
echo "Install from it exactly as CI does:"
echo "    pip install --require-hashes -r backend/requirements.lock"
echo "    pip install -e backend --no-deps"
