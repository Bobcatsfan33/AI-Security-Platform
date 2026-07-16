#!/usr/bin/env bash
# Proves the SDK fail-closed suites actually bite.
#
# A green test suite says the code passes its tests. It does not say the tests
# would notice if the code were wrong — and for THIS branch (whether unprotected
# LLM traffic ships) that difference is the whole point. The suites were
# mutation-tested by hand when they were written; a hand result is a claim about
# a moment, and this repo's rule is that claims point at something mechanical.
# So the mutation runs in CI.
#
# The mutation is the exact regression that matters: revert the fail-closed
# default so an unset/unrecognised PLATFORM_ENV falls back to unprotected direct
# calls — the bug the reviewers caught, reintroduced on purpose. If the suites
# stay green against it, they are decoration and this script fails the build.
#
# Usage: sdks/mutation_check.sh   (from anywhere; paths resolve off this file)
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

PY_SRC="python/platform_sdk/_routing.py"
NODE_SRC="node/src/routing.ts"

# Restore from byte-for-byte COPIES, never `git checkout --`.
#
# git checkout would restore the files to HEAD, which silently destroys any
# uncommitted work in them — as it did to the very change this script exists to
# protect, the first time it ran on a dirty tree. A tool that mutates your
# source must put back exactly what it found, not what the index thinks was
# there.
BACKUP_DIR="$(mktemp -d)"
cp "$PY_SRC" "$BACKUP_DIR/routing.py"
cp "$NODE_SRC" "$BACKUP_DIR/routing.ts"

restore() {
  cp "$BACKUP_DIR/routing.py" "$PY_SRC"
  cp "$BACKUP_DIR/routing.ts" "$NODE_SRC"
  rm -rf "$BACKUP_DIR"
  # Leave dist/ rebuilt from the restored source, not the mutated source.
  (cd node && npm run build >/dev/null 2>&1) || true
}
# Restore on ANY exit path. A mutation script that leaves the tree mutated
# because it died halfway is worse than no mutation script.
trap restore EXIT INT TERM

fail() { echo "MUTATION CHECK FAILED: $1" >&2; exit 1; }

echo "--- baseline: both suites must be green before mutating"
(cd python && python -m pytest -q >/dev/null 2>&1) || fail "python suite is not green before mutation"
(cd node && npm run build >/dev/null 2>&1 && npm test >/dev/null 2>&1) || fail "node suite is not green before mutation"

echo "--- mutating: restore the permissive default (unset PLATFORM_ENV -> fall back)"
python3 - <<'PY'
import pathlib, sys

py = pathlib.Path("python/platform_sdk/_routing.py")
s = py.read_text()
old_py = '    return os.environ.get("PLATFORM_ENV", "").strip().lower() in _NON_PRODUCTION_ENVS'
new_py = '    return os.environ.get("PLATFORM_ENV", "").strip().lower() not in ("prod", "production")'
if old_py not in s:
    sys.exit("python mutation target not found — has fallback_direct been refactored? "
             "Update sdks/mutation_check.sh so it keeps testing the real branch.")
py.write_text(s.replace(old_py, new_py, 1))

ts = pathlib.Path("node/src/routing.ts")
s = ts.read_text()
old_ts = '  return NON_PRODUCTION_ENVS.has((process.env.PLATFORM_ENV ?? "").trim().toLowerCase());'
new_ts = '  return !["prod","production"].includes((process.env.PLATFORM_ENV ?? "").trim().toLowerCase());'
if old_ts not in s:
    sys.exit("node mutation target not found — has fallbackDirect been refactored? "
             "Update sdks/mutation_check.sh so it keeps testing the real branch.")
ts.write_text(s.replace(old_ts, new_ts, 1))
PY
[ $? -eq 0 ] || fail "could not apply the mutation (see above)"

echo "--- the suites MUST now fail"
if (cd python && python -m pytest -q >/dev/null 2>&1); then
  fail "python suite still passes with the fail-closed default removed — it is not testing the branch it claims to"
fi
if (cd node && npm run build >/dev/null 2>&1 && npm test >/dev/null 2>&1); then
  fail "node suite still passes with the fail-closed default removed — it is not testing the branch it claims to"
fi

echo "OK: both suites detect the removal of the fail-closed default."
