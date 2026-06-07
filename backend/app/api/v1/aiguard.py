"""AI Guard inspection route — inline content inspection over the full
detector suite, returning the flat Allow | Block | Detect response body.

This is the surface that LLM gateways (LiteLLM, Portkey, …) and the SDKs
call synchronously on every prompt/response.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.aiguard.service import get_service
from app.auth.dependencies import require_role
from app.detectors import default_thresholds, names
from app.detectors.base import DetectorContext, Direction
from app.identity.types import IdentityContext

router = APIRouter(tags=["aiguard"])


class DetectorConfig(BaseModel):
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    action: Literal["block", "detect", "off"] | None = None
    enabled: bool = True


class InspectRequest(BaseModel):
    text: str
    direction: Literal["inbound", "outbound"] = "inbound"
    config: dict[str, DetectorConfig] = Field(default_factory=dict)
    allowed_topics: list[str] = Field(default_factory=list)
    competitor_terms: list[str] = Field(default_factory=list)
    brand_terms: list[str] = Field(default_factory=list)
    allowed_languages: list[str] = Field(default_factory=list)


@router.post("/inspect")
async def inspect(
    body: InspectRequest,
    identity: IdentityContext = Depends(require_role("analyst")),
) -> dict[str, Any]:
    direction = Direction.OUTBOUND if body.direction == "outbound" else Direction.INBOUND
    ctx = DetectorContext(
        direction=direction,
        allowed_topics=tuple(body.allowed_topics),
        competitor_terms=tuple(body.competitor_terms),
        brand_terms=tuple(body.brand_terms),
        allowed_languages=tuple(body.allowed_languages),
    )
    config = {k: v.model_dump(exclude_none=True) for k, v in body.config.items()}
    resp = get_service().inspect(text=body.text, direction=direction, config=config, context=ctx)
    return resp.to_dict()


@router.get("/detectors")
async def list_detectors(
    identity: IdentityContext = Depends(require_role("analyst")),
) -> dict[str, Any]:
    """Catalogue + default thresholds — backs the 'sliding threshold' UI."""
    return {"detectors": list(names()), "default_thresholds": default_thresholds()}
