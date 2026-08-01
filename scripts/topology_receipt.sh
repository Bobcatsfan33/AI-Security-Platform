#!/usr/bin/env bash
# Render both charts, verify them, and record what was verified.
#
# The receipt is the artifact the readiness index points at. It names the exact
# image digests, the exact chart versions, and the commit — so a reader can ask
# "what was actually checked?" and get an answer that does not depend on anyone
# remembering.
#
# Digests are supplied by the caller, never defaulted. A receipt that invented
# its own digests would attest to a deployment nobody ever rendered.
#
# Usage:
#   CELL_REGION=us-east-1 \
#   PG_DIGEST=sha256:... REDIS_DIGEST=sha256:... \
#   CH_DIGEST=sha256:... CH_KEEPER_DIGEST=sha256:... RP_DIGEST=sha256:... \
#   APP_DIGEST=sha256:... FRONTEND_DIGEST=sha256:... \
#   scripts/topology_receipt.sh [output-dir]
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
OUT="${1:-docs/evidence/p13}"
PYTHON="${PYTHON:-$PWD/backend/.venv/bin/python}"
CELL_REGION="${CELL_REGION:-us-east-1}"

fail() { echo "TOPOLOGY RECEIPT FAILED: $1" >&2; exit 1; }
for var in PG_DIGEST REDIS_DIGEST CH_DIGEST CH_KEEPER_DIGEST RP_DIGEST APP_DIGEST FRONTEND_DIGEST; do
  [ -n "${!var:-}" ] || fail "$var must be set (no defaults — a receipt must name real bytes)"
done

mkdir -p "$OUT"
DATA_RENDER="$OUT/rendered-data-tier.yaml"
CP_RENDER="$OUT/rendered-control-plane.yaml"
RECEIPT="$OUT/deployment-receipt.txt"

helm template cell deploy/helm/aisp-data-tier \
  --set "deploymentRegion=$CELL_REGION" \
  --set "postgres.image.digest=$PG_DIGEST" \
  --set "redis.image.digest=$REDIS_DIGEST" \
  --set "clickhouse.image.digest=$CH_DIGEST" \
  --set "clickhouse.keeper.image.digest=$CH_KEEPER_DIGEST" \
  --set "redpanda.image.digest=$RP_DIGEST" \
  --set "postgres.pitr.archiveDestination=s3://aisp-$CELL_REGION-wal/cell" \
  --set "clickhouse.backup.destination=s3://aisp-$CELL_REGION-clickhouse/backup" \
  > "$DATA_RENDER" || fail "the data tier did not render"

helm template cell deploy/helm/ai-security-platform \
  --set secrets.existingSecret=cell-secrets \
  --set "image.digest=$APP_DIGEST" \
  --set "frontend.image.digest=$FRONTEND_DIGEST" \
  --set "config.deploymentRegion=$CELL_REGION" \
  --set "config.runtimeEventsTopic=runtime.events.$CELL_REGION" \
  > "$CP_RENDER" || fail "the control plane did not render"

{
  echo "=============================================================="
  echo " DEPLOYMENT RECEIPT — one regional cell"
  echo "=============================================================="
  echo "generated : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit    : $(git rev-parse HEAD)"
  echo "branch    : $(git rev-parse --abbrev-ref HEAD)"
  echo "region    : $CELL_REGION"
  echo "helm      : $(helm version --short 2>/dev/null)"
  echo
  echo "charts"
  echo "  data tier     : aisp-data-tier $(grep '^version:' deploy/helm/aisp-data-tier/Chart.yaml | awk '{print $2}')"
  echo "  control plane : ai-security-platform $(grep '^version:' deploy/helm/ai-security-platform/Chart.yaml | awk '{print $2}')"
  echo
  echo "image digests (every workload; no tags anywhere)"
  echo
  echo "  PROVENANCE is checked, not assumed. 'verified-present' means the exact"
  echo "  digest resolves to an image on this machine, so the render names bytes"
  echo "  that demonstrably exist. 'not-resolvable-here' means it does not, and"
  echo "  THIS RECEIPT DOES NOT ATTEST TO THOSE BYTES — it attests only that the"
  echo "  manifests rendered and passed the checks below with that digest in"
  echo "  place. A receipt that quietly blurred the two would be the exact thing"
  echo "  digest pinning exists to prevent."
  echo
  grep -hE "^\s+image: " "$DATA_RENDER" "$CP_RENDER" | sed 's/^ *image: //' | sort -u | while read -r ref; do
    if docker image inspect "$ref" >/dev/null 2>&1; then
      echo "  [verified-present]     $ref"
    else
      echo "  [not-resolvable-here]  $ref"
    fi
  done
  echo
  echo "rendered objects"
  for f in "$DATA_RENDER" "$CP_RENDER"; do
    echo "  $(basename "$f"):"
    grep "^kind:" "$f" | sort | uniq -c | sed 's/^/    /'
  done
  echo
  echo "=============================================================="
  echo " VERIFICATION"
  echo "=============================================================="
  echo "-- data tier --"
  "$PYTHON" scripts/verify_topology.py "$DATA_RENDER" --profile data-tier
  DATA_RC=$?
  echo
  echo "-- control plane --"
  "$PYTHON" scripts/verify_topology.py "$CP_RENDER" --profile control-plane
  CP_RC=$?
  echo
  if [ $DATA_RC -eq 0 ] && [ $CP_RC -eq 0 ]; then
    echo "RESULT: PASS"
  else
    echo "RESULT: FAIL (data-tier=$DATA_RC control-plane=$CP_RC)"
  fi
} | tee "$RECEIPT"

grep -q "^RESULT: PASS" "$RECEIPT" || fail "verification did not pass; receipt retained at $RECEIPT"
echo
echo "receipt : $RECEIPT"
