#!/usr/bin/env bash
# scripts/org/protect.sh — branch protection as code (SH-2).
#
# One-time per repo; requires an admin token (gh auth with admin:repo or a PAT).
# Enforces, on main: PR required with 1 approving review that is NOT the author,
# code-owner review, up-to-date status checks, no force-push, no deletion, and
# signed commits.
#
#   bash scripts/org/protect.sh AI-Security-Platform
#
# EXTERNAL DEPENDENCY: require_approving_review_count=1 + require_last_push_
# approval means the author cannot self-approve. A SECOND maintainer with merge
# rights (see .github/CODEOWNERS) must exist before this is enabled, or all
# merges block. Do not run this until that account is onboarded.
#
# Status-check contexts below are this repo's current required checks. After the
# supply-chain workstream (A-3) lands, add "security-suite / build-scan-sign".
set -euo pipefail

REPO="${1:?usage: protect.sh <repo-name>}"
OWNER="Bobcatsfan33"

gh api -X PUT "repos/${OWNER}/${REPO}/branches/main/protection" \
  -H "Accept: application/vnd.github+json" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Backend unit tests",
      "Frontend (Next.js)",
      "Runtime agent (Go)",
      "Security gates"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_signatures": true
}
JSON

echo "branch protection applied to ${OWNER}/${REPO}@main"
