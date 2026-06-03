"""Threat-narrative workbench routes (Tier-3, Phase E).

The analyst workbench lists narratives, opens one (with its causal timeline and
contributing signals), and dispositions it (confirmed / false_positive /
suppressed / resolved + rationale). Every disposition is written to the
hash-chained audit log, and confirmed narratives are forwarded to SOAR with the
causal flow as correlation_id.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.auth.dependencies import require_role
from app.identity.types import IdentityContext
from app.narratives.narrative import narrative_to_incident
from app.narratives.store import RedisNarrativeStore, apply_disposition
from app.security.audit_log import log_event
from app.services.redis_client import get_redis

router = APIRouter(tags=["narratives"])

DispositionStatus = Literal["open", "confirmed", "false_positive", "suppressed", "resolved"]


class NarrativeOut(BaseModel):
    id: str
    correlation_id: str
    title: str
    severity: str
    kind: str
    confidence: float
    agents: list[str]
    asset_id: str
    signal_count: int
    status: str
    assignee: str = ""
    rationale: str = ""
    created_at: str
    disposition_at: Optional[str] = None
    contributing: list[dict[str, Any]] = Field(default_factory=list)
    causal_timeline: list[dict[str, Any]] = Field(default_factory=list)


class DispositionIn(BaseModel):
    status: DispositionStatus
    rationale: str = ""
    assignee: str = ""


async def _store() -> RedisNarrativeStore:
    return RedisNarrativeStore(await get_redis())


def _serialise(n: Any) -> NarrativeOut:
    d = n.to_dict()
    return NarrativeOut(**d)


@router.get("", response_model=list[NarrativeOut])
async def list_narratives(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    identity: IdentityContext = Depends(require_role("analyst")),
) -> list[NarrativeOut]:
    store = await _store()
    items = await store.list(str(identity.org_id), status=status, severity=severity)
    return [_serialise(n) for n in items]


@router.get("/{narrative_id}", response_model=NarrativeOut)
async def get_narrative(
    narrative_id: str,
    identity: IdentityContext = Depends(require_role("analyst")),
) -> NarrativeOut:
    store = await _store()
    n = await store.get(str(identity.org_id), narrative_id)
    if n is None:
        raise HTTPException(status_code=404, detail="narrative not found")
    return _serialise(n)


@router.patch("/{narrative_id}/disposition", response_model=NarrativeOut)
async def disposition_narrative(
    narrative_id: str,
    body: DispositionIn,
    identity: IdentityContext = Depends(require_role("analyst")),
) -> NarrativeOut:
    store = await _store()
    n = await store.get(str(identity.org_id), narrative_id)
    if n is None:
        raise HTTPException(status_code=404, detail="narrative not found")

    assignee = body.assignee or identity.email
    updated = apply_disposition(n, status=body.status, rationale=body.rationale, assignee=assignee)
    await store.save(updated)

    # Tamper-evident audit trail for the disposition.
    log_event(
        "narrative.disposition",
        tenant_id=str(identity.org_id),
        subject=identity.email,
        resource=f"narrative/{narrative_id}",
        correlation_id=updated.correlation_id,
        detail={"status": body.status, "rationale": body.rationale, "assignee": assignee},
    )

    # A confirmed narrative becomes a SOAR incident carrying the causal chain.
    if body.status == "confirmed":
        try:
            from app.soar.incidents import build_adapters

            incident = narrative_to_incident(updated)
            for sink in build_adapters([]):  # org SOAR config wired in prod
                await sink.open(incident)
        except Exception:  # noqa: BLE001 - SOAR is fail-open
            pass

    return _serialise(updated)
