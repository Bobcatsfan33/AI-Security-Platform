"""Connector configuration CRUD + /test endpoint.

Admins register model providers via this surface. Like the IDP admin
routes, plaintext credentials passed as ``api_key_ref="enc-pending:..."``
are auto-encrypted at storage with the field_crypto key, so the DB
never holds plaintext keys even in dev.

The ``/test`` endpoint runs the connector's ``health_check`` and records
the outcome to ``verification_status``. The dashboard reads this field
to show connection health without needing to re-call the provider on
every render.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.connectors.base import (
    ConnectorAuthError,
    ConnectorConfigError,
    ConnectorError,
)
from app.connectors.registry import SUPPORTED_PROVIDERS, build_connector
from app.db.models.connector_config import ConnectorConfig
from app.db.session import get_db
from app.identity.types import IdentityContext
from app.security.audit_log import AuditEventType, AuditOutcome, log_event
from app.security.field_crypto import FieldCryptoError, encrypt as fc_encrypt

router = APIRouter(tags=["connectors"])


ENC_PENDING_PREFIX = "enc-pending:"


# ─────────────────────────────────────────────── DTOs


class ConnectorConfigCreate(BaseModel):
    provider: Literal[
        "openai", "anthropic", "ollama", "azure_openai", "bedrock", "custom"
    ]
    display_name: str = Field(min_length=1, max_length=255)
    model: str = Field(min_length=1, max_length=128)
    api_key_ref: str = Field(default="")
    config: dict[str, Any] = Field(default_factory=dict)
    notes: str | None = None


class ConnectorConfigUpdate(BaseModel):
    display_name: str | None = None
    model: str | None = None
    api_key_ref: str | None = None
    config: dict[str, Any] | None = None
    is_active: bool | None = None
    notes: str | None = None


class ConnectorConfigResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    provider: str
    display_name: str
    model: str
    api_key_ref_present: bool  # never return the ref itself
    config: dict[str, Any]
    verification_status: dict[str, Any]
    is_active: bool
    notes: str | None
    created_at: datetime
    updated_at: datetime


class TestResult(BaseModel):
    ok: bool
    tested_at: datetime
    error: str | None = None
    latency_ms: int | None = None


def _to_response(row: ConnectorConfig) -> ConnectorConfigResponse:
    return ConnectorConfigResponse(
        id=row.id,
        org_id=row.org_id,
        provider=row.provider,
        display_name=row.display_name,
        model=row.model,
        # Surface only whether a ref is set, not its value
        api_key_ref_present=bool(row.api_key_ref),
        config=row.config or {},
        verification_status=row.verification_status or {},
        is_active=row.is_active,
        notes=row.notes,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


# ─────────────────────────────────────────────── helpers


def _maybe_encrypt_pending_key(api_key_ref: str) -> str:
    """If api_key_ref starts with ``enc-pending:<plaintext>``, encrypt and
    return the resulting ``enc:vN:<ciphertext>`` reference."""
    if not api_key_ref.startswith(ENC_PENDING_PREFIX):
        return api_key_ref
    plaintext = api_key_ref[len(ENC_PENDING_PREFIX) :]
    if not plaintext:
        raise HTTPException(
            status_code=400, detail="enc_pending_empty_plaintext"
        )
    try:
        ciphertext = fc_encrypt(plaintext)
    except FieldCryptoError as exc:
        raise HTTPException(
            status_code=500, detail=f"field_crypto_unavailable: {exc}"
        ) from exc
    return f"enc:{ciphertext}"


def _provider_requires_key(provider: str) -> bool:
    """Whether the provider requires a non-empty api_key_ref at create time.

    Bedrock can use the default boto3 credential chain (env / IAM role)
    when api_key_ref is empty, so we don't enforce it here.
    The 'custom' provider can be unauthenticated for local vLLM/TGI/
    LM Studio.
    """
    return provider in {"openai", "anthropic", "azure_openai"}


async def _load_owned(
    db: AsyncSession, connector_id: uuid.UUID, org_id: uuid.UUID
) -> ConnectorConfig:
    row = (
        await db.execute(
            select(ConnectorConfig).where(
                ConnectorConfig.id == connector_id,
                ConnectorConfig.org_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
    return row


# ─────────────────────────────────────────────── routes


@router.get("", response_model=list[ConnectorConfigResponse])
async def list_connectors(
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[ConnectorConfigResponse]:
    rows = (
        await db.execute(
            select(ConnectorConfig).where(ConnectorConfig.org_id == identity.org_id)
        )
    ).scalars().all()
    return [_to_response(r) for r in rows]


@router.post(
    "",
    response_model=ConnectorConfigResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_connector(
    payload: ConnectorConfigCreate,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> ConnectorConfigResponse:
    if payload.provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail="unsupported_provider")
    if _provider_requires_key(payload.provider) and not payload.api_key_ref:
        raise HTTPException(
            status_code=400,
            detail=f"api_key_ref_required_for_{payload.provider}",
        )

    api_key_ref = _maybe_encrypt_pending_key(payload.api_key_ref)

    row = ConnectorConfig(
        id=uuid.uuid4(),
        org_id=identity.org_id,
        provider=payload.provider,
        display_name=payload.display_name,
        model=payload.model,
        api_key_ref=api_key_ref,
        config=payload.config,
        verification_status={},
        is_active=True,
        notes=payload.notes,
        created_by=identity.user_id,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    log_event(
        AuditEventType.CONFIG_CHANGED,
        AuditOutcome.SUCCESS,
        tenant_id=str(identity.org_id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"connector_config:{row.id}",
        detail={
            "action": "created",
            "provider": row.provider,
            "model": row.model,
        },
    )
    return _to_response(row)


@router.get("/{connector_id}", response_model=ConnectorConfigResponse)
async def get_connector(
    connector_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> ConnectorConfigResponse:
    row = await _load_owned(db, connector_id, identity.org_id)
    return _to_response(row)


@router.patch("/{connector_id}", response_model=ConnectorConfigResponse)
async def update_connector(
    connector_id: uuid.UUID,
    payload: ConnectorConfigUpdate,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> ConnectorConfigResponse:
    row = await _load_owned(db, connector_id, identity.org_id)
    updates = payload.model_dump(exclude_unset=True)
    if "api_key_ref" in updates and isinstance(updates["api_key_ref"], str):
        updates["api_key_ref"] = _maybe_encrypt_pending_key(updates["api_key_ref"])
    for field, value in updates.items():
        setattr(row, field, value)
    await db.commit()
    await db.refresh(row)

    log_event(
        AuditEventType.CONFIG_CHANGED,
        AuditOutcome.SUCCESS,
        tenant_id=str(identity.org_id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"connector_config:{row.id}",
        detail={"action": "updated", "fields_changed": sorted(updates.keys())},
    )
    return _to_response(row)


@router.delete("/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connector(
    connector_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> None:
    row = await _load_owned(db, connector_id, identity.org_id)
    provider = row.provider
    model = row.model
    await db.delete(row)
    await db.commit()
    log_event(
        AuditEventType.CONFIG_CHANGED,
        AuditOutcome.SUCCESS,
        tenant_id=str(identity.org_id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"connector_config:{connector_id}",
        detail={"action": "deleted", "provider": provider, "model": model},
    )


@router.post("/{connector_id}/test", response_model=TestResult)
async def test_connector(
    connector_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> TestResult:
    """Run the connector's health_check and persist the outcome to
    ``verification_status``. Returns the result for immediate display."""
    import time

    row = await _load_owned(db, connector_id, identity.org_id)
    try:
        connector = build_connector(row)
    except (ConnectorConfigError, ConnectorError) as exc:
        result = TestResult(
            ok=False, tested_at=datetime.now(timezone.utc), error=str(exc)
        )
        row.verification_status = result.model_dump(mode="json")
        await db.commit()
        return result

    start = time.perf_counter()
    try:
        await connector.health_check()
        latency_ms = int((time.perf_counter() - start) * 1000)
        result = TestResult(
            ok=True,
            tested_at=datetime.now(timezone.utc),
            latency_ms=latency_ms,
        )
    except ConnectorAuthError as exc:
        result = TestResult(
            ok=False, tested_at=datetime.now(timezone.utc), error=f"auth: {exc}"
        )
    except ConnectorError as exc:
        result = TestResult(
            ok=False, tested_at=datetime.now(timezone.utc), error=str(exc)
        )

    row.verification_status = result.model_dump(mode="json")
    await db.commit()

    log_event(
        AuditEventType.CONFIG_CHANGED,
        AuditOutcome.SUCCESS if result.ok else AuditOutcome.FAILURE,
        tenant_id=str(identity.org_id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"connector_config:{connector_id}",
        detail={
            "action": "health_check",
            "ok": result.ok,
            "error": result.error,
            "latency_ms": result.latency_ms,
        },
    )
    return result
