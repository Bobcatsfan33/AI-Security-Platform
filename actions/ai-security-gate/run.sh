#!/usr/bin/env bash
# Composite-action runner for the AI Security Platform evaluation gate.
#
# Required environment:
#   PLATFORM_URL, API_KEY, ASSET_ID
# Optional:
#   MAX_TEST_CASES, GATE_MAX_CRITICAL, GATE_MAX_HIGH, GATE_MIN_SCORE,
#   TIMEOUT_SECONDS, GH_TOKEN, PR_NUMBER, REPO
#
# Behavior:
#   1. POST /v1/evaluations with the asset_id (triggered_by=ci_cd)
#   2. Poll the evaluation until status ∈ {completed, failed, cancelled}
#   3. Compare against gate thresholds; print summary
#   4. If running on a PR: POST a Markdown comment
#   5. Exit non-zero on gate failure
set -euo pipefail

: "${PLATFORM_URL:?PLATFORM_URL is required}"
: "${API_KEY:?API_KEY is required}"
: "${ASSET_ID:?ASSET_ID is required}"

GATE_MAX_CRITICAL="${GATE_MAX_CRITICAL:-0}"
GATE_MAX_HIGH="${GATE_MAX_HIGH:-5}"
GATE_MIN_SCORE="${GATE_MIN_SCORE:-60}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-600}"

auth_header=(-H "X-API-Key: $API_KEY")
content_header=(-H "Content-Type: application/json")

# Build trigger context from the GitHub event payload
trigger_context=$(
  jq -n \
    --arg sha "${GITHUB_SHA:-}" \
    --arg ref "${GITHUB_REF:-}" \
    --arg run_id "${GITHUB_RUN_ID:-}" \
    --arg pr "${PR_NUMBER:-}" \
    '{commit_sha: $sha, ref: $ref, run_id: $run_id, pr_number: $pr}'
)

body=$(
  jq -n \
    --arg asset_id "$ASSET_ID" \
    --argjson max_tests "${MAX_TEST_CASES:-null}" \
    --argjson ctx "$trigger_context" \
    '{
       asset_id: $asset_id,
       eval_type: "full",
       triggered_by: "ci_cd",
       trigger_context: $ctx,
       max_test_cases: $max_tests
     } | with_entries(select(.value != null))'
)

echo "Kicking off evaluation for asset $ASSET_ID..."
resp=$(curl -fsSL -X POST "$PLATFORM_URL/v1/evaluations" \
  "${auth_header[@]}" "${content_header[@]}" \
  --data "$body")
eval_id=$(echo "$resp" | jq -r '.id')
if [[ -z "$eval_id" || "$eval_id" == "null" ]]; then
  echo "::error::Failed to create evaluation: $resp"
  exit 2
fi
echo "Evaluation $eval_id created."

# Poll for terminal state
elapsed=0
while [[ $elapsed -lt $TIMEOUT_SECONDS ]]; do
  status_resp=$(curl -fsSL "$PLATFORM_URL/v1/evaluations/$eval_id" "${auth_header[@]}")
  status=$(echo "$status_resp" | jq -r '.status')
  case "$status" in
    completed|failed|cancelled)
      break
      ;;
  esac
  sleep 5
  elapsed=$((elapsed + 5))
done

if [[ "$status" != "completed" ]]; then
  echo "::error::Evaluation ended in status: $status (after ${elapsed}s)"
  echo "$status_resp"
  exit 3
fi

score=$(echo "$status_resp" | jq -r '.score')
findings=$(echo "$status_resp" | jq -r '.findings_count')
critical=$(echo "$status_resp" | jq -r '.critical_findings')
high_count=$(curl -fsSL "$PLATFORM_URL/v1/findings?evaluation_id=$eval_id&severity=high&limit=500" \
  "${auth_header[@]}" | jq 'length')

echo "Evaluation $eval_id complete."
echo "  score=$score"
echo "  findings=$findings (critical=$critical, high=$high_count)"

gate="pass"
reasons=()
if (( $(echo "$score < $GATE_MIN_SCORE" | bc -l) )); then
  gate="fail"
  reasons+=("score $score < required $GATE_MIN_SCORE")
fi
if [[ "$critical" -gt "$GATE_MAX_CRITICAL" ]]; then
  gate="fail"
  reasons+=("$critical critical findings (max $GATE_MAX_CRITICAL)")
fi
if [[ "$high_count" -gt "$GATE_MAX_HIGH" ]]; then
  gate="fail"
  reasons+=("$high_count high findings (max $GATE_MAX_HIGH)")
fi

{
  echo "evaluation_id=$eval_id"
  echo "score=$score"
  echo "findings_count=$findings"
  echo "critical_count=$critical"
  echo "gate_result=$gate"
} >> "$GITHUB_OUTPUT"

# Compose the PR comment
report_md=$(curl -fsSL \
  "$PLATFORM_URL/v1/reports/$eval_id?template=executive_summary" \
  "${auth_header[@]}")

emoji="✅"
[[ "$gate" == "fail" ]] && emoji="❌"

comment=$(
  cat <<EOF
## $emoji AI Security Platform — Evaluation Gate

- **Score:** $score / 100
- **Findings:** $findings (critical: $critical · high: $high_count)
- **Gate result:** **$gate**
EOF
)
if [[ ${#reasons[@]} -gt 0 ]]; then
  comment+=$'\n- **Reasons:**'
  for r in "${reasons[@]}"; do
    comment+=$'\n  - '$r
  done
fi
comment+=$'\n\n<details><summary>Executive summary</summary>\n\n'"$report_md"$'\n</details>'

if [[ -n "${PR_NUMBER:-}" && -n "${GH_TOKEN:-}" && -n "${REPO:-}" ]]; then
  echo "Posting PR comment to #$PR_NUMBER..."
  curl -fsSL \
    -X POST "https://api.github.com/repos/$REPO/issues/$PR_NUMBER/comments" \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    --data "$(jq -n --arg body "$comment" '{body: $body}')" \
    >/dev/null
fi

# Final summary for the GitHub Step Summary
{
  echo "## $emoji AI Security Evaluation"
  echo ""
  echo "| Metric | Value |"
  echo "|---|---|"
  echo "| Score | $score / 100 |"
  echo "| Findings | $findings |"
  echo "| Critical | $critical |"
  echo "| High | $high_count |"
  echo "| Gate | $gate |"
} >> "$GITHUB_STEP_SUMMARY"

if [[ "$gate" == "fail" ]]; then
  echo "::error::Evaluation failed gate policy: ${reasons[*]}"
  exit 1
fi
