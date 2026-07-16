#!/usr/bin/env bash
# Proves the security-critical test suites actually bite.
#
# A green suite says the code passes its tests. It does not say the tests would
# NOTICE if the code were wrong — and for the branches covered here (whether
# unprotected LLM traffic ships; whether a gated SIEM exporter can be rewritten)
# that difference is the whole point.
#
# Each target reintroduces a real regression — one that actually shipped and was
# caught in review — and asserts the suite goes red. If it stays green, the
# suite is decoration and this script fails the build.
#
# This exists because the repo's rule ("a claim points at something mechanical")
# applies to claims about tests too. "Mutation-verified" asserted in a PR
# description is a claim about a moment on someone's laptop; this is the thing
# it should have pointed at.
#
# Usage:
#   scripts/mutation_check.sh            # every target
#   scripts/mutation_check.sh sdk        # SDK fail-closed default only
#   scripts/mutation_check.sh backend    # SIEM exporter tier gate only
#
# Split by target because the dependencies differ: CI's SDK job has no backend
# environment and vice versa, so each job runs the target it can.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT="$(pwd)"

TARGET="${1:-all}"
case "$TARGET" in
  all | sdk | backend) ;;
  *)
    echo "usage: $0 [all|sdk|backend]" >&2
    exit 2
    ;;
esac

PY_SDK="sdks/python/platform_sdk/_routing.py"
NODE_SDK="sdks/node/src/routing.ts"
SIEM_API="backend/app/api/v1/siem.py"

fail() {
  echo ""
  echo "MUTATION CHECK FAILED: $1" >&2
  exit 1
}

targets_for() {
  case "$1" in
    sdk) echo "$PY_SDK $NODE_SDK" ;;
    backend) echo "$SIEM_API" ;;
    all) echo "$PY_SDK $NODE_SDK $SIEM_API" ;;
  esac
}

FILES="$(targets_for "$TARGET")"

# ── the dirty-tree guard ─────────────────────────────────────────────────────
#
# This script edits your source in place. The byte-copy restore below fixes what
# it PUTS BACK; this guard fixes what you can LOSE. Both are needed, and we know
# that because the first version of this script restored via `git checkout --`
# and destroyed the very uncommitted change it existed to protect.
#
# Guarded per-file rather than on the whole tree: those are the only files at
# risk, and refusing to run because some unrelated doc is dirty would just teach
# people to skip the check.
DIRTY=""
for f in $FILES; do
  if [ -n "$(git status --porcelain -- "$f" 2>/dev/null)" ]; then
    DIRTY="$DIRTY $f"
  fi
done
if [ -n "$DIRTY" ]; then
  {
    echo "MUTATION CHECK REFUSED: uncommitted changes in the files this script mutates:"
    for f in $DIRTY; do echo "    $f"; done
    echo ""
    echo "This script rewrites those files and restores them afterwards. It restores from"
    echo "byte-for-byte copies, so a clean run is safe — but if it is killed at the wrong"
    echo "moment the copies are all that stand between you and losing that work."
    echo ""
    echo "    git stash push --$DIRTY"
    echo ""
    echo "Set MUTATION_CHECK_ALLOW_DIRTY=1 to override."
  } >&2
  if [ "${MUTATION_CHECK_ALLOW_DIRTY:-0}" != "1" ]; then
    exit 1
  fi
  echo "MUTATION_CHECK_ALLOW_DIRTY=1 — proceeding on a dirty tree at your own risk." >&2
fi

# ── restore from copies, never `git checkout --` ─────────────────────────────
BACKUP_DIR="$(mktemp -d)"
for f in $FILES; do
  cp "$f" "$BACKUP_DIR/$(basename "$f")"
done

restore() {
  for f in $FILES; do
    cp "$BACKUP_DIR/$(basename "$f")" "$f" 2>/dev/null || true
  done
  rm -rf "$BACKUP_DIR"
  # Leave dist/ rebuilt from restored source, not mutated source.
  if [ "$TARGET" = "sdk" ] || [ "$TARGET" = "all" ]; then
    (cd "$REPO_ROOT/sdks/node" && npm run build >/dev/null 2>&1) || true
  fi
}
trap restore EXIT INT TERM

# ── the targets ──────────────────────────────────────────────────────────────

run_sdk_suites() {
  (cd "$REPO_ROOT/sdks/python" && python -m pytest -q >/dev/null 2>&1) || return 1
  (cd "$REPO_ROOT/sdks/node" && npm run build >/dev/null 2>&1 && npm test >/dev/null 2>&1) || return 1
  return 0
}

run_backend_suite() {
  (cd "$REPO_ROOT/backend" && python -m pytest tests/unit/test_siem_write_path_gating.py -q >/dev/null 2>&1)
}

check_sdk() {
  echo "=== TARGET: sdk — the SDK fail-closed default"
  echo "--- baseline: suites must be green before mutating"
  run_sdk_suites || fail "the SDK suites are not green before mutation — fix that first"

  echo "--- mutating: restore the permissive default (unset PLATFORM_ENV -> fall back)"
  python3 - "$PY_SDK" "$NODE_SDK" <<'PY' || fail "could not apply the SDK mutation"
import pathlib, sys

py = pathlib.Path(sys.argv[1])
s = py.read_text()
old = '    return os.environ.get("PLATFORM_ENV", "").strip().lower() in _NON_PRODUCTION_ENVS'
new = '    return os.environ.get("PLATFORM_ENV", "").strip().lower() not in ("prod", "production")'
if old not in s:
    sys.exit("python mutation target not found — has fallback_direct been refactored? "
             "Update scripts/mutation_check.sh so it keeps testing the real branch.")
py.write_text(s.replace(old, new, 1))

ts = pathlib.Path(sys.argv[2])
s = ts.read_text()
old = '  return NON_PRODUCTION_ENVS.has((process.env.PLATFORM_ENV ?? "").trim().toLowerCase());'
new = '  return !["prod","production"].includes((process.env.PLATFORM_ENV ?? "").trim().toLowerCase());'
if old not in s:
    sys.exit("node mutation target not found — has fallbackDirect been refactored? "
             "Update scripts/mutation_check.sh so it keeps testing the real branch.")
ts.write_text(s.replace(old, new, 1))
PY

  echo "--- the suites MUST now fail"
  if run_sdk_suites; then
    fail "the SDK suites still pass with the fail-closed default removed — they are not testing the branch they claim to"
  fi

  for f in $PY_SDK $NODE_SDK; do cp "$BACKUP_DIR/$(basename "$f")" "$f"; done
  echo "OK: both SDK suites detect the removal of the fail-closed default."
}

check_backend() {
  echo "=== TARGET: backend — the SIEM exporter tier gate"
  echo "--- baseline: suite must be green before mutating"
  run_backend_suite || fail "test_siem_write_path_gating is not green before mutation — fix that first"

  # The regression: the blanket disable carve-out that shipped in #65's first
  # cut. It made `enabled: false` a skeleton key — a PUT could rewrite a gated
  # exporter's config and secret refs while calling itself a disable, and a POST
  # could stage a brand-new gated exporter to go live when the flag flips.
  echo "--- mutating: restore the blanket 'enabled:false is always allowed' carve-out"
  python3 - "$SIEM_API" <<'PY' || fail "could not apply the backend mutation"
import pathlib, sys

p = pathlib.Path(sys.argv[1])
s = p.read_text()

create_anchor = '''    if exporter_type_allowed(exporter.type):
        return
    if not exporter_type_known(exporter.type):'''
update_anchor = '    stored_type = str(stored.get("type") or "")'

if create_anchor not in s or update_anchor not in s:
    sys.exit("SIEM mutation target not found — have the tier validators been refactored? "
             "Update scripts/mutation_check.sh so it keeps testing the real branch.")

s = s.replace(create_anchor, '    if not exporter.enabled:\n        return\n' + create_anchor, 1)
s = s.replace(update_anchor, '    if not exporter.enabled:\n        return\n' + update_anchor, 1)
p.write_text(s)
PY

  echo "--- the suite MUST now fail"
  if run_backend_suite; then
    fail "test_siem_write_path_gating still passes with the blanket carve-out restored — it is not testing the branch it claims to"
  fi

  cp "$BACKUP_DIR/$(basename "$SIEM_API")" "$SIEM_API"
  echo "OK: the SIEM write-path suite detects the blanket disable carve-out."
}

case "$TARGET" in
  sdk) check_sdk ;;
  backend) check_backend ;;
  all)
    check_sdk
    check_backend
    ;;
esac

echo ""
echo "mutation check passed ($TARGET)."
