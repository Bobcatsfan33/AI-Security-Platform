"""Connector CRUD + test-connection + manual-sync routes (v2).

Replaces the v1 connector-config CRUD. A v2 connector is an *ingest
endpoint* — it has a connector_type that maps to a registered class in
``app.connectors.discovery`` and a (currently opaque) ``config`` blob.

POST /v1/connectors            — register
GET  /v1/connectors            — list with last-sync status
GET  /v1/connectors/available  — catalog of registered connector types
GET  /v1/connectors/{id}       — detail
POST /v1/connectors/{id}/test  — call test_connection()
POST /v1/connectors/{id}/sync  — run SyncService
DELETE /v1/connectors/{id}     — soft delete (sets is_enabled=false)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.connectors.discovery import (
    ConnectionStatus,
    ConnectorMetadata,
    UnknownConnectorTypeError,
    get as get_connector_class,
    list_available,
)
from app.db.models.connector import Connector
from app.db.session import get_db
from app.identity.types import IdentityContext
from app.services.sync_service import SyncResult, SyncService

router = APIRouter(tags=["connectors"])


# ─────────────────────────────────────────────── DTOs


class ConnectorCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    connector_type: str = Field(min_length=1, max_length=64)
    config: dict[str, Any] = Field(default_factory=dict)
    schedule: Optional[str] = None
    is_enabled: bool = True


class ConnectorRead(BaseModel):
    id: uuid.UUID
    name: str
    connector_type: str
    schedule: Optional[str]
    is_enabled: bool
    last_sync_at: Optional[datetime]
    last_sync_status: Optional[str]
    created_at: datetime
    updated_at: datetime


class ConnectionTestResponse(BaseModel):
    connected: bool
    message: str
    latency_ms: Optional[float] = None


class SyncTriggerResponse(BaseModel):
    sync_job_id: uuid.UUID
    status: str
    assets_discovered: int
    assets_updated: int
    assets_removed: int
    error_message: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime]


# ─────────────────────────────────────────────── helpers


def _to_read(row: Connector) -> ConnectorRead:
    return ConnectorRead(
        id=row.id,
        name=row.name,
        connector_type=row.connector_type,
        schedule=row.schedule,
        is_enabled=row.is_enabled,
        last_sync_at=row.last_sync_at,
        last_sync_status=row.last_sync_status,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def _load_connector(
    db: AsyncSession, connector_id: uuid.UUID
) -> Connector:
    row = (
        await db.execute(select(Connector).where(Connector.id == connector_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="connector_not_found"
        )
    return row


# ─────────────────────────────────────────────── routes


@router.get("/available", response_model=list[ConnectorMetadata])
async def list_available_types(
    identity: IdentityContext = Depends(require_role("viewer")),
) -> list[ConnectorMetadata]:
    """Catalog of registered connector types + their JSON-Schema configs."""
    return list_available()


@router.post(
    "",
    response_model=ConnectorRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_connector(
    payload: ConnectorCreate,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> ConnectorRead:
    try:
        get_connector_class(payload.connector_type)
    except UnknownConnectorTypeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown connector_type: {payload.connector_type}",
        )
    row = Connector(
        name=payload.name,
        connector_type=payload.connector_type,
        config_encrypted=payload.config,
        schedule=payload.schedule,
        is_enabled=payload.is_enabled,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _to_read(row)


@router.get("", response_model=list[ConnectorRead])
async def list_connectors(
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[ConnectorRead]:
    rows = (
        await db.execute(
            select(Connector).order_by(Connector.created_at.desc())
        )
    ).scalars().all()
    return [_to_read(r) for r in rows]


@router.get("/{connector_id}", response_model=ConnectorRead)
async def get_connector(
    connector_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> ConnectorRead:
    return _to_read(await _load_connector(db, connector_id))


@router.post(
    "/{connector_id}/test", response_model=ConnectionTestResponse
)
async def test_connector(
    connector_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> ConnectionTestResponse:
    row = await _load_connector(db, connector_id)
    try:
        cls = get_connector_class(row.connector_type)
    except UnknownConnectorTypeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"connector_type {row.connector_type!r} not registered",
        )
    instance = cls(config=row.config_encrypted or {})
    result: ConnectionStatus = await instance.test_connection()
    return ConnectionTestResponse(
        connected=result.connected,
        message=result.message,
        latency_ms=result.latency_ms,
    )


@router.post("/{connector_id}/sync", response_model=SyncTriggerResponse)
async def trigger_sync(
    connector_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> SyncTriggerResponse:
    await _load_connector(db, connector_id)
    service = SyncService()
    try:
        result: SyncResult = await service.run(db, connector_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        )
    return SyncTriggerResponse(
        sync_job_id=result.sync_job_id,
        status=result.status,
        assets_discovered=result.assets_discovered,
        assets_updated=result.assets_updated,
        assets_removed=result.assets_removed,
        error_message=result.error_message,
        started_at=result.started_at,
        completed_at=result.completed_at,
    )


@router.delete(
    "/{connector_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def soft_delete(
    connector_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> None:
    row = await _load_connector(db, connector_id)
    row.is_enabled = False
    await db.commit()
