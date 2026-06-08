"""AI Risk Index route.

Exposes the deterministic risk scorer (:mod:`app.spm.risk_index`) that blends
supply-chain, IAM over-privilege, runtime detector exposure, and red-team
exposure into a single 0-100 index + letter grade. The caller supplies the
four component scores (each 0-1); wiring them automatically from the asset
graph / AIBOM / red-team stores is a follow-on — this surfaces the scoring
engine itself so a UI (and clients) can render the index today.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.auth.dependencies import require_role
from app.identity.types import IdentityContext
from app.spm.risk_index import GRADE_BANDS, WEIGHTS, compute_risk_index

router = APIRouter(tags=["risk-index"])


class RiskIndexRequest(BaseModel):
    asset_id: str = Field(min_length=1)
    supply_chain_score: float = Field(default=0.0, ge=0.0, le=1.0)
    iam_over_privilege: float = Field(default=0.0, ge=0.0, le=1.0)
    runtime_block_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    redteam_success_rate: float = Field(default=0.0, ge=0.0, le=1.0)


@router.post("/compute")
async def compute(
    body: RiskIndexRequest,
    identity: IdentityContext = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Compute the blended AI Risk Index for an asset from its component scores."""
    index = compute_risk_index(
        asset_id=body.asset_id,
        supply_chain_score=body.supply_chain_score,
        iam_over_privilege=body.iam_over_privilege,
        runtime_block_rate=body.runtime_block_rate,
        redteam_success_rate=body.redteam_success_rate,
    )
    return index.to_dict()


@router.get("/model")
async def model(
    identity: IdentityContext = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """The scoring model itself — component weights and grade bands. Backs a
    UI that explains how the index is derived."""
    return {
        "weights": WEIGHTS,
        "grade_bands": GRADE_BANDS,
    }
