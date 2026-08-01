#!/usr/bin/env bash
# Migration rehearsal: upgrade -> downgrade -> upgrade, against a real database.
#
# tests/unit/test_migrations.py already proves the revision chain is linear,
# that every migration HAS a downgrade, and that the offline SQL is symmetric.
# All of that is true of migrations that still fail on contact with data,
# because none of it executes against a database holding rows.
#
# This does. It seeds data, walks the chain down to base and back up, and
# checks the schema is the same on the far side. The transcript is the artifact:
# "we can roll back" is a claim, and this is the thing it points at.
#
# Usage:  scripts/migration_rehearsal.sh [output-transcript-path]
#
# Requires DATABASE_URL and JWT_SECRET in the environment, and a database the
# script is allowed to destroy. It refuses anything that looks production.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT="$(pwd)"
TRANSCRIPT="${1:-docs/evidence/p13/migration-rehearsal.txt}"
PYTHON="${PYTHON:-$REPO_ROOT/backend/.venv/bin/python}"
ALEMBIC="${ALEMBIC:-$REPO_ROOT/backend/.venv/bin/alembic}"

fail() { echo "MIGRATION REHEARSAL FAILED: $1" >&2; exit 1; }

[ -n "${DATABASE_URL:-}" ] || fail "DATABASE_URL must be set"
[ -x "$PYTHON" ] || fail "no interpreter at $PYTHON"

# ── the blast-radius guard ───────────────────────────────────────────────────
# This walks the schema to base. Running it against anything real would be
# unrecoverable, so refuse on the two signals available without asking a human:
# a production-shaped URL, or a host that is not local.
case "$DATABASE_URL" in
  *prod*|*production*|*live*) fail "DATABASE_URL looks production-labelled; refusing" ;;
esac
case "$DATABASE_URL" in
  *@localhost:*|*@127.0.0.1:*|*@postgres:*|*@db:*) ;;
  *) fail "DATABASE_URL does not point at a local host; refusing to downgrade a remote database" ;;
esac

mkdir -p "$(dirname "$TRANSCRIPT")"

# Everything from here goes to the transcript AND the terminal. The transcript
# is evidence, so it records the failures too — a rehearsal that only writes a
# file when it passes is a file that means nothing.
exec > >(tee "$TRANSCRIPT") 2>&1

echo "=============================================================="
echo " MIGRATION REHEARSAL — upgrade / downgrade / upgrade"
echo "=============================================================="
echo "repository : $(git rev-parse HEAD)"
echo "branch     : $(git rev-parse --abbrev-ref HEAD)"
# Host and database only. The URL carries a password.
echo "database   : $(printf '%s' "$DATABASE_URL" | sed -E 's#//[^@]*@#//<redacted>@#')"
echo "started    : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo

cd "$REPO_ROOT/backend"

schema_fingerprint() {
  # Sorted table+column+type list. Compared before and after the round trip:
  # a downgrade that drops a column and an upgrade that re-adds it with a
  # different type is exactly the silent divergence this is here to catch.
  "$PYTHON" - <<'PY'
import asyncio, os, sys
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

QUERY = """
SELECT table_name, column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_schema = 'public'
ORDER BY table_name, column_name
"""

async def main() -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"])
    async with engine.connect() as conn:
        rows = (await conn.execute(text(QUERY))).all()
    await engine.dispose()
    for row in rows:
        print("|".join(str(x) for x in row))

asyncio.run(main())
PY
}

step() {
  echo "--------------------------------------------------------------"
  echo ">>> $*"
  echo "--------------------------------------------------------------"
}

step "1. upgrade head (establish the baseline)"
"$ALEMBIC" upgrade head || fail "initial upgrade failed"
"$ALEMBIC" current

step "2. capture the schema fingerprint at head"
schema_fingerprint > /tmp/schema-before.txt || fail "could not read the schema"
echo "columns at head: $(wc -l < /tmp/schema-before.txt)"

step "3. seed a row so the downgrade runs against data, not an empty schema"
"$PYTHON" - <<'PY' || exit 1
import asyncio, os, uuid
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

async def main() -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"])
    org = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO organizations (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": org, "n": "rehearsal", "s": f"rehearsal-{org.hex[:10]}"},
        )
    await engine.dispose()
    print(f"seeded organization {org}")

asyncio.run(main())
PY

step "4. downgrade base (the step nobody runs until the night they must)"
"$ALEMBIC" downgrade base || fail "downgrade to base failed"
"$ALEMBIC" current

step "5. upgrade head again"
"$ALEMBIC" upgrade head || fail "re-upgrade after downgrade failed"
"$ALEMBIC" current

step "6. compare the schema fingerprint"
schema_fingerprint > /tmp/schema-after.txt || fail "could not re-read the schema"
if diff -u /tmp/schema-before.txt /tmp/schema-after.txt; then
  echo "IDENTICAL: $(wc -l < /tmp/schema-after.txt) columns, byte-for-byte"
else
  fail "schema diverged across the downgrade/upgrade round trip (diff above)"
fi

echo
echo "=============================================================="
echo " RESULT: PASS"
echo " finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================================="
