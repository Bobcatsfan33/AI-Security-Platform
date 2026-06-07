"""Dynamic remediation route — turn red-team findings into rails."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.auth.dependencies import require_role
from app.identity.types import IdentityContext
from app.redteam.remediation import generate_plan, plan_from_campaign_report

router = APIRouter(tags=["remediation"])


class GeneratePlanRequest(BaseModel):
    # category -> success rate (0..1)
    successful_categories: dict[str, float] = Field(default_factory=dict)
    base_system_prompt: str = ""
    asset_id: str | None = None


class FromReportRequest(BaseModel):
    report: dict[str, Any]
    base_system_prompt: str = ""


@router.post("/plan")
async def plan(
    body: GeneratePlanRequest,
    identity: IdentityContext = Depends(require_role("admin")),
) -> dict[str, Any]:
    return generate_plan(
        successful_categories=body.successful_categories,
        base_system_prompt=body.base_system_prompt,
        asset_id=body.asset_id,
    ).to_dict()


@router.post("/plan-from-report")
async def plan_from_report(
    body: FromReportRequest,
    identity: IdentityContext = Depends(require_role("admin")),
) -> dict[str, Any]:
    return plan_from_campaign_report(body.report, body.base_system_prompt).to_dict()
