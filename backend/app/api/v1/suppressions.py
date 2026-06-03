"""Suppression-rule routes (Phase E feedback loop).

Analysts review auto-suggested suppressions and approve them (admin); approval
activates a rule with an expiry so it must be recertified — suppression is
never permanent. FP-rate metrics live here too: the number that proves the
feedback loop is reducing alert volume.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.auth.dependencies import require_role
from app.feedback.metrics import fp_rate_by_kind, overall_fp_rate
from app.feedback.store import RedisSuppressionStore
from app.feedback.suppression import activate, expire
from app.identity.types import IdentityContext
from app.narratives.store import RedisNarrativeStore
from app.security.audit_log import log_event
from app.services.redis_client import get_redis

router = APIRouter(tags=["suppressions"])


class SuppressionOut(BaseModel):
    id: str
    kind: str
    asset_id: str
    agents: list[str]
    reason: str
    status: str
    created_by: str
    approved_by: str = ""
    created_at: str
    expires_at: Optional[str] = None


class ActivateIn(BaseModel):
    ttl_seconds: int = 30 * 24 * 3600


def _out(r: Any) -> SuppressionOut:
    d = r.to_dict()
    return SuppressionOut(
        id=d["id"],
        kind=d["kind"],
        asset_id=d["asset_id"],
        agents=d["agents"],
        reason=d["reason"],
        status=d["status"],
        created_by=d["created_by"],
        approved_by=d["approved_by"],
        created_at=d["created_at"],
        expires_at=d["expires_at"],
    )


async def _store() -> RedisSuppressionStore:
    return RedisSuppressionStore(await get_redis())


@router.get("", response_model=list[SuppressionOut])
async def list_suppressions(
    status: Optional[str] = Query(None),
    identity: IdentityContext = Depends(require_role("analyst")),
) -> list[SuppressionOut]:
    rules = await (await _store()).list(str(identity.org_id), status=status)
    return [_out(r) for r in rules]


@router.post("/{rule_id}/activate", response_model=SuppressionOut)
async def activate_suppression(
    rule_id: str,
    body: ActivateIn,
    identity: IdentityContext = Depends(require_role("admin")),
) -> SuppressionOut:
    store = await _store()
    rule = await store.get(str(identity.org_id), rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="suppression rule not found")
    activated = activate(rule, approved_by=identity.email, ttl_seconds=body.ttl_seconds)
    await store.save(activated)
    log_event(
        "suppression.activated",
        tenant_id=str(identity.org_id),
        subject=identity.email,
        resource=f"suppression/{rule_id}",
        detail={"kind": rule.kind, "asset_id": rule.asset_id, "ttl_seconds": body.ttl_seconds},
    )
    return _out(activated)


@router.post("/{rule_id}/expire", response_model=SuppressionOut)
async def expire_suppression(
    rule_id: str,
    identity: IdentityContext = Depends(require_role("admin")),
) -> SuppressionOut:
    store = await _store()
    rule = await store.get(str(identity.org_id), rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="suppression rule not found")
    expired = expire(rule)
    await store.save(expired)
    log_event(
        "suppression.expired",
        tenant_id=str(identity.org_id),
        subject=identity.email,
        resource=f"suppression/{rule_id}",
    )
    return _out(expired)


@router.get("/fp-metrics")
async def fp_metrics(
    identity: IdentityContext = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """FP rate overall + per kind, over dispositioned narratives — the measured
    proof the feedback loop is reducing false positives."""
    narratives = await RedisNarrativeStore(await get_redis()).list(str(identity.org_id))
    by_kind = fp_rate_by_kind(narratives)
    return {
        "overall_fp_rate": round(overall_fp_rate(narratives), 4),
        "by_kind": {
            k: {
                "confirmed": s.confirmed,
                "false_positive": s.false_positive,
                "total": s.total,
                "fp_rate": round(s.fp_rate, 4),
            }
            for k, s in by_kind.items()
        },
    }
