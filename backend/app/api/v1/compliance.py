"""Compliance evidence-pack download routes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.compliance.evidence_pack import (
    CONTROL_MAPPINGS,
    EvidencePackInputs,
    build_pack,
)
from app.db.session import get_db
from app.identity.types import IdentityContext

router = APIRouter(tags=["compliance"])

Framework = Literal["soc2", "iso27001", "fedramp_moderate"]


@router.get("/evidence-pack")
async def evidence_pack(
    framework: Framework = Query(...),
    period_start: datetime = Query(...),
    period_end: datetime = Query(...),
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    if period_start >= period_end:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="period_start must precede period_end",
        )
    if framework not in CONTROL_MAPPINGS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unsupported framework",
        )
    inputs = EvidencePackInputs(
        org_id=identity.org_id,
        framework=framework,
        period_start=period_start.astimezone(timezone.utc),
        period_end=period_end.astimezone(timezone.utc),
    )
    blob = await build_pack(db, inputs)
    filename = (
        f"evidence-pack-{framework}-"
        f"{period_start.strftime('%Y%m%d')}-{period_end.strftime('%Y%m%d')}.zip"
    )
    return Response(
        content=blob,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/frameworks", response_model=list[dict])
async def list_frameworks(
    identity: IdentityContext = Depends(require_role("viewer")),
) -> list[dict]:
    out: list[dict] = []
    for fw_id, controls in CONTROL_MAPPINGS.items():
        out.append(
            {
                "id": fw_id,
                "name": _framework_name(fw_id),
                "control_count": len(controls),
                "controls": [
                    {"id": cid, "title": c["title"]}
                    for cid, c in controls.items()
                ],
            }
        )
    return out


def _framework_name(fw_id: str) -> str:
    return {
        "soc2": "SOC 2 Type II",
        "iso27001": "ISO 27001",
        "fedramp_moderate": "FedRAMP Moderate",
    }.get(fw_id, fw_id)
