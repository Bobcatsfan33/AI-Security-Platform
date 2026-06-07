"""IAM entitlement analysis for AI assets.

Detects over-privileged identities attached to AI models/agents — a core
AI-SPM control (prevent identity over-privileging so models and users only
access necessary data). Pure analysis over an entitlement snapshot; no cloud
calls here (a discovery connector supplies the snapshot)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# Permissions considered sensitive/dangerous for an AI principal to hold.
_DANGEROUS = {
    "iam:*",
    "*:*",
    "s3:DeleteBucket",
    "s3:*",
    "kms:Decrypt",
    "secretsmanager:GetSecretValue",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "sts:AssumeRole",
    "ec2:*",
    "rds:*",
    "bedrock:*",
    "dynamodb:*",
    "lambda:InvokeFunction",
}
_WILDCARD_WEIGHT = 0.4
_ADMIN_PRINCIPALS = {"admin", "root", "owner"}


@dataclass(frozen=True)
class EntitlementFinding:
    principal: str
    issue: str
    severity: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IAMReport:
    asset_id: str
    findings: tuple[EntitlementFinding, ...]
    over_privilege_score: float  # 0..1
    principal_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "over_privilege_score": round(self.over_privilege_score, 4),
            "principal_count": self.principal_count,
            "findings": [asdict(f) for f in self.findings],
        }


def analyze_entitlements(asset: dict[str, Any]) -> IAMReport:
    """``asset`` shape::

    {
      "id": "model-1",
      "principals": [
         {"name": "svc-rag", "permissions": ["s3:GetObject","bedrock:InvokeModel"],
          "last_used_days": 3},
         ...
      ]
    }
    """
    principals = asset.get("principals", []) or []
    findings: list[EntitlementFinding] = []
    risk_accum = 0.0

    for p in principals:
        name = p.get("name", "unknown")
        perms = set(p.get("permissions", []))
        dangerous = sorted(perms & _DANGEROUS)
        wildcards = sorted(x for x in perms if x.endswith(":*") or x == "*:*")
        last_used = p.get("last_used_days")

        if dangerous:
            sev = "critical" if any(x in {"iam:*", "*:*", "s3:*"} for x in dangerous) else "high"
            findings.append(
                EntitlementFinding(name, "dangerous_permissions", sev, {"permissions": dangerous})
            )
            risk_accum += 0.5 + 0.1 * min(len(dangerous), 3)
        if wildcards:
            findings.append(
                EntitlementFinding(name, "wildcard_permissions", "high", {"wildcards": wildcards})
            )
            risk_accum += _WILDCARD_WEIGHT
        if isinstance(last_used, (int, float)) and last_used > 90 and perms:
            findings.append(
                EntitlementFinding(
                    name, "stale_unused_grant", "medium", {"last_used_days": last_used}
                )
            )
            risk_accum += 0.2
        if name.lower() in _ADMIN_PRINCIPALS:
            findings.append(EntitlementFinding(name, "admin_principal_on_ai_asset", "high", {}))
            risk_accum += 0.3

    score = 0.0 if not principals else min(risk_accum / max(len(principals), 1), 1.0)
    return IAMReport(
        asset_id=asset.get("id", "unknown"),
        findings=tuple(findings),
        over_privilege_score=score,
        principal_count=len(principals),
    )
