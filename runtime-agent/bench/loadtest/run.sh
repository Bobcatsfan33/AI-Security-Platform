#!/usr/bin/env bash
# End-to-end proxy load sweep (Phase 2 increment 3). Drives the REAL proxy on
# :18400 against a mock upstream on :19000 at three RPS levels, and measures the
# upstream directly at each level so the proxy's ADDED overhead is the checkable
# difference. Env-stamped; reported in docs/BENCHMARKS.md, never CI-gated.
#
# Usage (from runtime-agent/):
#   LOCUST=/path/to/locust ./bench/loadtest/run.sh
# Prefers a quiet, AC-powered machine (same caveat as the microbench tail).
set -euo pipefail
cd "$(dirname "$0")/../.."   # runtime-agent/

LOCUST="${LOCUST:-locust}"
PROXY="127.0.0.1:18400"
UPSTREAM="127.0.0.1:19000"
DUR="${DUR:-30s}"
OUT="${OUT:-/tmp/agent-loadtest}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
mkdir -p "$OUT"

go build -o "$OUT/loadserver" ./bench/loadserver/
PROXY_ADDR="$PROXY" UPSTREAM_ADDR="$UPSTREAM" "$OUT/loadserver" >"$OUT/loadserver.log" 2>&1 &
LS=$!
trap 'kill "$LS" 2>/dev/null || true' EXIT
sleep 2

run_one() { # users host path tag
  LOAD_PATH="$3" "$LOCUST" -f bench/loadtest/locustfile.py --host "http://$2" \
    --headless -u "$1" -r "$1" --run-time "$DUR" --csv "$OUT/$4" >/dev/null 2>&1 || true
}

# Three RPS levels via user count (PER_USER_RPS≈25): idle-ish, mid, and the
# clean near-saturation point. The SHAPE of the curve is the finding, not any
# one number. NOTE on this single-machine loopback rig: above ~750 RPS the
# reverse-proxy/loopback CONNECTION handling (not the pipeline) hits a failure
# cliff (~23% errors at 900 RPS) — that is a rig limit, so the top level stays
# at the clean knee. True saturation needs a multi-host rig (out of scope, like
# real ONNX inference).
LEVELS="4:idle 20:mid 30:high"
for lv in $LEVELS; do
  users="${lv%%:*}"; name="${lv##*:}"
  echo "== level $name ($users users) =="
  run_one "$users" "$PROXY"    /proxy/v1/chat/completions "proxy_$name"
  run_one "$users" "$UPSTREAM" /v1/chat/completions       "upstream_$name"
done

python3 bench/loadtest/summarize.py "$OUT" "$COMMIT" idle mid high
echo
echo "results.json + CSVs in $OUT"
