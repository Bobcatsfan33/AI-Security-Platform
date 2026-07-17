#!/usr/bin/env bash
# Regenerate the backend dependency locks from backend/pyproject.toml.
#
# TWO locks, from one pyproject, both hashed:
#
#   requirements.lock          --all-extras   (100 pkgs) — CI and dev
#   requirements-runtime.lock  no extras      ( 75 pkgs) — the production image
#
# The split is not tidiness. backend/Dockerfile's runtime stage does
# `COPY --from=builder /install /usr/local`, so ANYTHING installed in the
# builder lands in the shipped image. Installing the all-extras lock there would
# put pytest, ruff, mypy and bandit in production — contradicting the
# Dockerfile's own "prod deps only" header, inflating the image the A-2 work
# shrank, and handing Trivy 25 extra packages of attack surface to find CVEs in.
# The image gets exactly what it runs.
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

# Enforce the pinned uv, do not merely name it. uv's output format is a function
# of its version, so a developer on a newer uv regenerates different bytes and
# gets a CI rejection that is deterministic, correct, and utterly baffling. The
# tool that makes the build reproducible has to be reproducible itself.
ACTUAL_UV="$(uv --version | awk '{print $2}')"
if [ "$ACTUAL_UV" != "$UV_VERSION" ]; then
  cat >&2 <<EOF
This repo locks with uv ${UV_VERSION}; you have ${ACTUAL_UV}.

uv's output format depends on its version, so regenerating with a different one
produces different bytes and CI's sync check will reject them — correctly, and
confusingly. Match it:

    pip install uv==${UV_VERSION}

To move the whole repo to a newer uv, bump UV_VERSION here AND the pinned
install in .github/workflows/ci.yml, then regenerate.
EOF
  exit 1
fi

echo "Regenerating backend locks with uv ${ACTUAL_UV}…"

# CI + dev: everything, including the dev extra.
uv pip compile pyproject.toml \
  --all-extras \
  --universal \
  --generate-hashes \
  --python-version "$PYTHON_FLOOR" \
  -o requirements.lock

# The production image: runtime deps ONLY. See the header for why this is
# separate rather than a subset filtered at install time.
#
# --constraint the full lock so the two agree VERSION for version. Without it
# the resolutions drift: a dev extra can hold a shared transitive back, and the
# first run of this split had CI testing huggingface-hub 1.23.0 while the image
# shipped 1.24.0. Two locks that disagree mean the thing we test is not the
# thing we ship — which is the bug GAP-016 exists to kill, reintroduced one
# level down. Constraining makes runtime a strict subset of what CI ran.
uv pip compile pyproject.toml \
  --universal \
  --generate-hashes \
  --python-version "$PYTHON_FLOOR" \
  --constraint requirements.lock \
  -o requirements-runtime.lock

echo ""
echo "Done. Review the diff and commit BOTH:"
echo "    git diff backend/requirements.lock backend/requirements-runtime.lock"
echo ""
echo "Install from it exactly as CI does:"
echo "    pip install --require-hashes -r backend/requirements.lock"
echo "    pip install -e backend --no-deps"
