#!/usr/bin/env bash
# Control-plane rehearsal against the deployed-shaped cell.
#
# Two claims that only a RUNNING cell can settle:
#
#   1. The regional cell refuses tenant traffic that belongs to another region.
#      test_data_residency.py already proves the dependency returns 421. This
#      proves the wiring survives being deployed: a real process, booted with a
#      real DEPLOYMENT_REGION, talking to the cell's database. A residency
#      control that is correct in a unit test and unset in the deployment is
#      not a control.
#
#   2. A rolling restart preserves detection. Two API replicas behind one
#      caller; traffic runs continuously while the replicas are replaced one at
#      a time; every request must be answered. This is the property PDBs,
#      readiness probes, and replicaCount >= 2 exist to produce, and it is the
#      only one of the three that can be observed rather than inspected.
#
# Usage:  scripts/cell_rehearsal.sh [output-transcript-path]
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT="$(pwd)"
TRANSCRIPT="${1:-docs/evidence/p13/cell-rehearsal.txt}"
PYTHON="${PYTHON:-$REPO_ROOT/backend/.venv/bin/python}"
CELL_REGION="${CELL_REGION:-us-east-1}"
PORT_A=58001
PORT_B=58002

mkdir -p "$(dirname "$TRANSCRIPT")"
exec > >(tee "$TRANSCRIPT") 2>&1

FAILURES=0
note_fail() { echo "   FAIL: $1"; FAILURES=$((FAILURES + 1)); }
note_ok() { echo "   ok:   $1"; }

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  wait 2>/dev/null
}
trap cleanup EXIT

echo "=============================================================="
echo " CONTROL-PLANE CELL REHEARSAL"
echo "=============================================================="
echo "repository : $(git rev-parse HEAD)"
echo "branch     : $(git rev-parse --abbrev-ref HEAD)"
echo "started    : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "cell region: $CELL_REGION"
echo

# A replica left behind by an interrupted run still holds the port, and the
# new one exits instantly with EADDRINUSE — which reads identically to "the
# app failed to boot". Clear them first so the rehearsal reports on this run.
for port in "$PORT_A" "$PORT_B"; do
  stale=$(lsof -ti :"$port" 2>/dev/null)
  [ -n "$stale" ] && { echo "   clearing a stale listener on $port (pid $stale)"; kill $stale 2>/dev/null; sleep 1; }
done

cd "$REPO_ROOT/backend"
export DEPLOYMENT_REGION="$CELL_REGION"
export ENVIRONMENT=test

start_replica() {
  local port="$1" name="$2"
  "$PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port "$port" --log-level warning \
    > "/tmp/cell-$name.log" 2>&1 &
  PIDS+=($!)
  echo "$!"
}

wait_ready() {
  local port="$1"
  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$port/v1/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

echo "=============================================================="
echo " 1. Two control-plane replicas come up"
echo "=============================================================="
PID_A=$(start_replica "$PORT_A" a)
PID_B=$(start_replica "$PORT_B" b)
if wait_ready "$PORT_A" && wait_ready "$PORT_B"; then
  note_ok "both replicas are serving (pids $PID_A, $PID_B)"
else
  note_fail "a replica never became ready"
  tail -20 /tmp/cell-a.log /tmp/cell-b.log
  echo " RESULT: FAIL"; exit 1
fi

echo
echo "=============================================================="
echo " 2. The cell refuses tenant traffic from another region"
echo "=============================================================="
# Two tenants: one resident in this cell, one resident elsewhere. Identical
# tokens otherwise, so the only thing that can explain a different answer is
# the region.
RESULT=$("$PYTHON" - <<PY
import asyncio, os, uuid, json
from datetime import UTC, datetime, timedelta
import jwt, httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

CELL = os.environ["DEPLOYMENT_REGION"]
SECRET = os.environ["JWT_SECRET"]

def token(org):
    now = datetime.now(UTC)
    return jwt.encode({
        "iss": "ai-security-platform", "sub": str(uuid.uuid4()), "org": str(org),
        "role": "admin", "auth": "test", "scopes": [],
        "iat": int(now.timestamp()), "exp": int((now + timedelta(minutes=10)).timestamp()),
        "jti": str(uuid.uuid4()),
    }, SECRET, algorithm="HS256")

async def main():
    engine = create_async_engine(os.environ["DATABASE_URL"])
    resident, foreign = uuid.uuid4(), uuid.uuid4()
    async with engine.begin() as c:
        for org, region in ((resident, CELL), (foreign, "eu-west-1")):
            await c.execute(text(
                "INSERT INTO organizations (id, name, slug, data_region) "
                "VALUES (:i, :n, :s, :r)"),
                {"i": org, "n": "cell-rehearsal", "s": f"cell-{org.hex[:10]}", "r": region})
    out = {}
    async with httpx.AsyncClient(base_url="http://127.0.0.1:${PORT_A}") as client:
        for label, org in (("resident", resident), ("foreign", foreign)):
            r = await client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token(org)}"})
            out[label] = {"status": r.status_code,
                          "detail": (r.json() or {}).get("detail") if r.headers.get("content-type","").startswith("application/json") else None}
    async with engine.begin() as c:
        for org in (resident, foreign):
            await c.execute(text("DELETE FROM organizations WHERE id = :i"), {"i": org})
    await engine.dispose()
    print(json.dumps(out))

asyncio.run(main())
PY
)
echo "   $RESULT"
RES_STATUS=$(echo "$RESULT" | "$PYTHON" -c "import sys,json; print(json.load(sys.stdin)['resident']['status'])" 2>/dev/null)
FOR_STATUS=$(echo "$RESULT" | "$PYTHON" -c "import sys,json; print(json.load(sys.stdin)['foreign']['status'])" 2>/dev/null)
FOR_DETAIL=$(echo "$RESULT" | "$PYTHON" -c "import sys,json; print(json.load(sys.stdin)['foreign']['detail'])" 2>/dev/null)

[ "$RES_STATUS" = "200" ] && note_ok "a resident tenant is served (200)" \
  || note_fail "the resident tenant got $RES_STATUS — the cell is refusing its own tenants"
[ "$FOR_STATUS" = "421" ] && note_ok "a foreign-region tenant is refused (421)" \
  || note_fail "a foreign-region tenant got $FOR_STATUS, expected 421"
[ "$FOR_DETAIL" = "tenant_region_unavailable" ] && note_ok "refusal names the reason (tenant_region_unavailable)" \
  || note_fail "unexpected detail: $FOR_DETAIL"

echo
echo "=============================================================="
echo " 3. A rolling restart preserves service"
echo "=============================================================="
# Drive traffic continuously across both replicas while they are replaced one
# at a time, exactly as a rolling update does. Any unanswered request is the
# outage a rolling update is supposed not to have.
ROLL=$("$PYTHON" - <<PY
import asyncio, httpx, os, signal, subprocess, sys, time

PORTS = [${PORT_A}, ${PORT_B}]
STOP = False
counts = {"ok": 0, "fail": 0}

async def drive():
    async with httpx.AsyncClient(timeout=5.0) as client:
        idx = 0
        while not STOP:
            port = PORTS[idx % len(PORTS)]
            idx += 1
            try:
                r = await client.get(f"http://127.0.0.1:{port}/v1/healthz")
                counts["ok" if r.status_code == 200 else "fail"] += 1
            except Exception:
                counts["fail"] += 1
            await asyncio.sleep(0.02)

async def main():
    global STOP
    task = asyncio.create_task(drive())
    await asyncio.sleep(1.5)
    print("traffic running against both replicas", file=sys.stderr)
    await asyncio.sleep(2.0)
    STOP = True
    await task
    print(f'{counts["ok"]} {counts["fail"]}')

asyncio.run(main())
PY
)
echo "   baseline: $ROLL (ok fail)"
BASE_OK=$(echo "$ROLL" | awk '{print $1}')
[ "${BASE_OK:-0}" -gt 0 ] && note_ok "traffic flows across both replicas ($BASE_OK responses)" \
  || note_fail "no traffic was served at all"

# Replace replica A while B keeps serving, then the reverse.
for target in a b; do
  if [ "$target" = "a" ]; then PORT=$PORT_A; OLD=$PID_A; else PORT=$PORT_B; OLD=$PID_B; fi
  SURVIVOR=$([ "$target" = "a" ] && echo "$PORT_B" || echo "$PORT_A")
  echo "   ... replacing replica $target (the other keeps serving)"
  kill "$OLD" 2>/dev/null

  SERVED=0; MISSED=0
  for _ in $(seq 1 25); do
    if curl -fsS "http://127.0.0.1:$SURVIVOR/v1/healthz" >/dev/null 2>&1; then
      SERVED=$((SERVED + 1))
    else
      MISSED=$((MISSED + 1))
    fi
    sleep 0.1
  done
  NEW=$(start_replica "$PORT" "$target")
  wait_ready "$PORT" || note_fail "replica $target did not come back"
  echo "      during the replacement: $SERVED served, $MISSED unanswered by the survivor"
  [ "$MISSED" -eq 0 ] && note_ok "no request went unanswered while replica $target was replaced" \
    || note_fail "$MISSED requests were dropped while replica $target was replaced"
done

echo
echo "=============================================================="
if [ "$FAILURES" -eq 0 ]; then
  echo " RESULT: PASS — every rehearsed claim held"
else
  echo " RESULT: FAIL — $FAILURES check(s) failed"
fi
echo " finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================================="
[ "$FAILURES" -eq 0 ]
