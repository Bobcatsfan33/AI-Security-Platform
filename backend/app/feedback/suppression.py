"""Suppression learning — the alert-fatigue feedback loop (RAPIDE Phase E).

When an analyst dispositions a narrative as a false positive, the system
suggests a suppression rule so the same benign pattern stops surfacing. Two
guard-rails keep this from hiding real threats:

  1. Suggested rules are NOT active until a human approves them.
  2. Active rules EXPIRE and must be recertified — suppression is never
     permanent, so a rule can't silently mask a threat forever.

A rule's signature is (kind, asset_id, agents): a new narrative is suppressed
only when an active, unexpired rule matches its kind + asset and shares at
least one agent (or the rule is agent-agnostic).
"""

from __future__ import annotations

import dataclasses
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from app.narratives.narrative import ThreatNarrative

SuppressionStatus = Literal["suggested", "active", "expired"]
DEFAULT_TTL_SECONDS = 30 * 24 * 3600  # active rules recertify monthly


@dataclass(frozen=True)
class SuppressionRule:
    id: uuid.UUID
    org_id: str
    kind: str
    asset_id: str
    agents: tuple[str, ...]
    reason: str
    status: SuppressionStatus = "suggested"
    created_by: str = ""
    approved_by: str = ""
    source_narrative_id: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    activated_at: datetime | None = None
    expires_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "org_id": self.org_id,
            "kind": self.kind,
            "asset_id": self.asset_id,
            "agents": list(self.agents),
            "reason": self.reason,
            "status": self.status,
            "created_by": self.created_by,
            "approved_by": self.approved_by,
            "source_narrative_id": self.source_narrative_id,
            "created_at": self.created_at.isoformat(),
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SuppressionRule":
        return cls(
            id=uuid.UUID(d["id"]),
            org_id=d.get("org_id", ""),
            kind=d.get("kind", ""),
            asset_id=d.get("asset_id", ""),
            agents=tuple(d.get("agents", [])),
            reason=d.get("reason", ""),
            status=d.get("status", "suggested"),
            created_by=d.get("created_by", ""),
            approved_by=d.get("approved_by", ""),
            source_narrative_id=d.get("source_narrative_id", ""),
            created_at=_dt(d.get("created_at")) or datetime.now(timezone.utc),
            activated_at=_dt(d.get("activated_at")),
            expires_at=_dt(d.get("expires_at")),
        )


def _dt(raw: Any) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw))
    except (ValueError, TypeError):
        return None


def suggest_from_narrative(
    narrative: ThreatNarrative, *, reason: str, created_by: str
) -> SuppressionRule:
    """Build a SUGGESTED suppression rule from a false-positive narrative.
    Not active until approved."""
    return SuppressionRule(
        id=uuid.uuid4(),
        org_id=narrative.org_id,
        kind=narrative.kind,
        asset_id=narrative.asset_id,
        agents=narrative.agents,
        reason=reason or "auto-suggested from false-positive disposition",
        status="suggested",
        created_by=created_by,
        source_narrative_id=str(narrative.id),
    )


def activate(
    rule: SuppressionRule, *, approved_by: str, ttl_seconds: int = DEFAULT_TTL_SECONDS
) -> SuppressionRule:
    """Approve + activate a suggested rule with an expiry (recertification)."""
    now = datetime.now(timezone.utc)
    return dataclasses.replace(
        rule,
        status="active",
        approved_by=approved_by,
        activated_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
    )


def expire(rule: SuppressionRule) -> SuppressionRule:
    return dataclasses.replace(rule, status="expired")


def is_expired(rule: SuppressionRule, *, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    return rule.expires_at is not None and now >= rule.expires_at


def matches(rule: SuppressionRule, narrative: ThreatNarrative) -> bool:
    if rule.kind != narrative.kind or rule.asset_id != narrative.asset_id:
        return False
    # Agent-agnostic rule matches any; otherwise require an agent overlap.
    if not rule.agents:
        return True
    return bool(set(rule.agents) & set(narrative.agents))


def is_suppressed(
    narrative: ThreatNarrative,
    rules: list[SuppressionRule],
    *,
    now: datetime | None = None,
) -> bool:
    """True when an ACTIVE, UNEXPIRED rule matches the narrative."""
    now = now or datetime.now(timezone.utc)
    for rule in rules:
        if rule.status != "active":
            continue
        if is_expired(rule, now=now):
            continue
        if matches(rule, narrative):
            return True
    return False
