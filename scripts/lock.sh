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
#
# --python-version is pinned to the requires-python FLOOR, and that is
# load-bearing rather than cosmetic: without it, uv annotates the "# via"
# comments using the markers of whichever interpreter runs the tool, so the same
# command produced different bytes on macOS/3.14 than in CI/3.12 (anyio,
# starlette and pytest-asyncio need typing-extensions on 3.12 but not 3.14). The
# resolution was identical; the file was not — and a byte-diff drift check
# cannot tell those apart. Pinning makes the output a function of the FLAG, not
# of the machine, which is the same property the lock itself exists to give the
# dependency tree.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../backend"

UV_VERSION="0.11.29"
# Must match requires-python's floor in backend/pyproject.toml, and the
# --python-version in .github/workflows/ci.yml's sync check.
PYTHON_FLOOR="3.11"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is not installed. Install it with:  pip install uv==${UV_VERSION}" >&2
  exit 1
fi

echo "Regenerating backend/requirements.lock with uv $(uv --version)…"
uv pip compile pyproject.toml \
  --all-extras \
  --universal \
  --generate-hashes \
  --python-version "$PYTHON_FLOOR" \
  -o requirements.lock

echo ""
echo "Done. Review the diff and commit it:"
echo "    git diff backend/requirements.lock"
echo ""
echo "Install from it exactly as CI does:"
echo "    pip install --require-hashes -r backend/requirements.lock"
echo "    pip install -e backend --no-deps"
