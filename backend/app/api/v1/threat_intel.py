"""Threat intelligence routes — clusters, novel detections, STIX export."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.db.session import get_db
from app.identity.types import IdentityContext
from app.threat_intel import engine as engine_module
from app.threat_intel.stix_export import clusters_to_bundle

router = APIRouter(tags=["threat-intel"])


class ClusterSummary(BaseModel):
    id: str
    category: str
    severity: str
    size: int
    supporting_orgs: int
    top_keywords: list[str]
    top_controls: list[str]
    fingerprint: str


class EngineStatus(BaseModel):
    samples_processed: int
    cluster_count: int
    novel_count: int
    last_built_at: str | None


@router.post("/rebuild", response_model=EngineStatus)
async def rebuild(
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> EngineStatus:
    state = await engine_module.rebuild_clusters(db)
    return EngineStatus(
        samples_processed=state.samples_processed,
        cluster_count=len(state.clusterer.clusters()),
        novel_count=len(state.novel_samples),
        last_built_at=state.last_built_at.isoformat() if state.last_built_at else None,
    )


@router.get("/status", response_model=EngineStatus)
async def status(
    identity: IdentityContext = Depends(require_role("analyst")),
) -> EngineStatus:
    state = engine_module.current_state()
    return EngineStatus(
        samples_processed=state.samples_processed,
        cluster_count=len(state.clusterer.clusters()),
        novel_count=len(state.novel_samples),
        last_built_at=state.last_built_at.isoformat() if state.last_built_at else None,
    )


@router.get("/clusters", response_model=list[ClusterSummary])
async def list_clusters(
    identity: IdentityContext = Depends(require_role("analyst")),
) -> list[ClusterSummary]:
    return [ClusterSummary(**row) for row in engine_module.cluster_summary()]


@router.get("/stix")
async def stix_bundle(
    identity: IdentityContext = Depends(require_role("analyst")),
) -> Response:
    bundle = clusters_to_bundle(engine_module.clusters_snapshot())
    import json
    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/stix+json;version=2.1",
    )
