"""Discovery overview — aggregate connector + sync health."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.db.models.ai_asset import AIAsset
from app.db.models.connector import Connector
from app.db.session import get_db
from app.identity.types import IdentityContext

router = APIRouter(tags=["discovery"])


class ConnectorStatusRow(BaseModel):
    id: str
    name: str
    connector_type: str
    is_enabled: bool
    last_sync_at: Optional[datetime]
    last_sync_status: Optional[str]


class DiscoveryStatus(BaseModel):
    total_connectors: int
    enabled_connectors: int
    healthy_connectors: int
    total_assets: int
    connectors: list[ConnectorStatusRow]


@router.get("/status", response_model=DiscoveryStatus)
async def get_status(
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> DiscoveryStatus:
    connectors = (
        await db.execute(select(Connector).order_by(Connector.name))
    ).scalars().all()
    total_assets = int(
        (
            await db.execute(select(func.count()).select_from(AIAsset))
        ).scalar_one()
        or 0
    )
    healthy = sum(
        1
        for c in connectors
        if c.is_enabled and c.last_sync_status == "completed"
    )
    return DiscoveryStatus(
        total_connectors=len(connectors),
        enabled_connectors=sum(1 for c in connectors if c.is_enabled),
        healthy_connectors=healthy,
        total_assets=total_assets,
        connectors=[
            ConnectorStatusRow(
                id=str(c.id),
                name=c.name,
                connector_type=c.connector_type,
                is_enabled=c.is_enabled,
                last_sync_at=c.last_sync_at,
                last_sync_status=c.last_sync_status,
            )
            for c in connectors
        ],
    )
