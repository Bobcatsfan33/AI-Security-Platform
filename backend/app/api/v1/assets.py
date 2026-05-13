"""AI Asset CRUD — the surface where operators register what to protect.

An AI Asset is a deployed model / agent / RAG system / copilot the
platform monitors. The schema lives in
:class:`app.db.models.ai_asset.AIAsset` and carries every field the
evaluation engine, AI-BOM, and runtime agent need to do their work.

The DTOs here are intentionally permissive: most JSONB fields default
to empty so a freshly-registered asset doesn't require the operator
to fill in 30 fields just to start an evaluation. Operators refine
configuration over time as they integrate more of the platform.

Audit emissions on every mutation (create / update / delete /
status-change) flow into the hash-chained audit log via the existing
:mod:`app.security.audit_log` plumbing.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.db.models.ai_asset import AIAsset
from app.db.session import get_db
from app.identity.types import IdentityContext
from app.security.audit_log import AuditEventType, AuditOutcome, log_event

router = APIRouter(tags=["assets"])


# ─────────────────────────────────────────────── DTOs


Provider = Literal[
    "openai",
    "anthropic",
    "google",
    "azure_openai",
    "bedrock",
    "ollama",
    "vllm",
    "custom",
]
Hosting = Literal["saas_api", "self_hosted", "private_cloud", "on_prem"]
Environment = Literal["dev", "staging", "production"]
Exposure = Literal["internal_only", "customer_facing", "public", "api_only"]
DataClassification = Literal[
    "public", "internal", "confidential", "restricted", "regulated"
]
AssetStatus = Literal["active", "inactive", "decommissioned", "under_review"]


class AssetCreate(BaseModel):
    """Required + optional fields at creation. Most JSONB fields default
    to empty; operators refine over time."""

    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    provider: Provider
    model_name: str = Field(min_length=1, max_length=128)
    model_version: str | None = None
    hosting: Hosting = "saas_api"
    endpoint_url: str | None = None
    connector_config: dict[str, Any] = Field(default_factory=dict)

    system_prompt: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    top_p: float | None = None
    tools: list[dict[str, Any]] = Field(default_factory=list)
    mcp_servers: list[dict[str, Any]] = Field(default_factory=list)
    rag_sources: list[dict[str, Any]] = Field(default_factory=list)
    plugins: list[dict[str, Any]] = Field(default_factory=list)
    fine_tuning: dict[str, Any] = Field(default_factory=dict)

    environment: Environment = "dev"
    exposure: Exposure = "internal_only"
    data_classification: DataClassification = "internal"
    user_base_size: int | None = None
    interactions_per_day: int | None = None
    regulatory_scope: list[str] = Field(default_factory=list)

    dependencies: list[dict[str, Any]] = Field(default_factory=list)
    data_lineage: list[dict[str, Any]] = Field(default_factory=list)
    upstream_services: list[dict[str, Any]] = Field(default_factory=list)
    downstream_consumers: list[dict[str, Any]] = Field(default_factory=list)

    is_agentic: bool = False
    agent_framework: str | None = None
    max_tool_calls_per_session: int | None = None
    human_in_loop_required: bool = False
    allowed_external_actions: list[dict[str, Any]] = Field(default_factory=list)

    team: str | None = None
    tags: list[str] = Field(default_factory=list)


class AssetUpdate(BaseModel):
    """Every field optional — partial update semantics."""

    name: str | None = None
    description: str | None = None
    status: AssetStatus | None = None
    provider: Provider | None = None
    model_name: str | None = None
    model_version: str | None = None
    hosting: Hosting | None = None
    endpoint_url: str | None = None
    connector_config: dict[str, Any] | None = None

    system_prompt: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    top_p: float | None = None
    tools: list[dict[str, Any]] | None = None
    mcp_servers: list[dict[str, Any]] | None = None
    rag_sources: list[dict[str, Any]] | None = None
    plugins: list[dict[str, Any]] | None = None
    fine_tuning: dict[str, Any] | None = None

    environment: Environment | None = None
    exposure: Exposure | None = None
    data_classification: DataClassification | None = None
    user_base_size: int | None = None
    interactions_per_day: int | None = None
    regulatory_scope: list[str] | None = None

    dependencies: list[dict[str, Any]] | None = None
    data_lineage: list[dict[str, Any]] | None = None
    upstream_services: list[dict[str, Any]] | None = None
    downstream_consumers: list[dict[str, Any]] | None = None

    is_agentic: bool | None = None
    agent_framework: str | None = None
    max_tool_calls_per_session: int | None = None
    human_in_loop_required: bool | None = None
    allowed_external_actions: list[dict[str, Any]] | None = None

    team: str | None = None
    tags: list[str] | None = None
    runtime_policy_id: uuid.UUID | None = None


class AssetResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    description: str | None
    status: str
    provider: str
    model_name: str
    model_version: str | None
    hosting: str
    endpoint_url: str | None
    connector_config: dict[str, Any]
    system_prompt: str | None
    temperature: float | None
    max_tokens: int | None
    top_p: float | None
    tools: list[dict[str, Any]]
    mcp_servers: list[dict[str, Any]]
    rag_sources: list[dict[str, Any]]
    plugins: list[dict[str, Any]]
    fine_tuning: dict[str, Any]
    environment: str
    exposure: str
    data_classification: str
    regulatory_scope: list[str]
    is_agentic: bool
    agent_framework: str | None
    human_in_loop_required: bool
    open_findings_count: int
    critical_findings_count: int
    last_evaluation_score: float | None
    last_evaluation_date: datetime | None
    runtime_agent_connected: bool
    runtime_policy_id: uuid.UUID | None
    owner_id: uuid.UUID | None
    team: str | None
    tags: list[str]
    created_at: datetime
    updated_at: datetime


def _to_response(row: AIAsset) -> AssetResponse:
    return AssetResponse(
        id=row.id,
        org_id=row.org_id,
        name=row.name,
        description=row.description,
        status=row.status,
        provider=row.provider,
        model_name=row.model_name,
        model_version=row.model_version,
        hosting=row.hosting,
        endpoint_url=row.endpoint_url,
        connector_config=row.connector_config or {},
        system_prompt=row.system_prompt,
        temperature=row.temperature,
        max_tokens=row.max_tokens,
        top_p=row.top_p,
        tools=row.tools or [],
        mcp_servers=row.mcp_servers or [],
        rag_sources=row.rag_sources or [],
        plugins=row.plugins or [],
        fine_tuning=row.fine_tuning or {},
        environment=row.environment,
        exposure=row.exposure,
        data_classification=row.data_classification,
        regulatory_scope=row.regulatory_scope or [],
        is_agentic=row.is_agentic,
        agent_framework=row.agent_framework,
        human_in_loop_required=row.human_in_loop_required,
        open_findings_count=row.open_findings_count,
        critical_findings_count=row.critical_findings_count,
        last_evaluation_score=row.last_evaluation_score,
        last_evaluation_date=row.last_evaluation_date,
        runtime_agent_connected=row.runtime_agent_connected,
        runtime_policy_id=row.runtime_policy_id,
        owner_id=row.owner_id,
        team=row.team,
        tags=row.tags or [],
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


# ─────────────────────────────────────────────── helpers


async def _load_owned(
    db: AsyncSession, asset_id: uuid.UUID, org_id: uuid.UUID
) -> AIAsset:
    row = (
        await db.execute(
            select(AIAsset).where(
                AIAsset.id == asset_id, AIAsset.org_id == org_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
    return row


def _append_change_log(
    row: AIAsset,
    *,
    changed_by: uuid.UUID | None,
    fields_changed: dict[str, Any],
) -> None:
    """Append one change-log entry for every field that changed.

    The AI-BOM drift detector reads this log to reconstruct historical
    snapshots. Bounded to the most recent 100 entries to keep the JSONB
    column tractable; older entries are dropped silently. Production
    deployments wanting full audit history should rely on the hash-
    chained audit log instead.
    """
    log = list(row.change_log or [])
    now = datetime.now(timezone.utc).isoformat()
    by = str(changed_by) if changed_by else "system"
    for field, change in fields_changed.items():
        log.append(
            {
                "timestamp": now,
                "field": field,
                "old_value": change["old"],
                "new_value": change["new"],
                "changed_by": by,
            }
        )
    if len(log) > 100:
        log = log[-100:]
    row.change_log = log


# ─────────────────────────────────────────────── routes


@router.get("", response_model=list[AssetResponse])
async def list_assets(
    environment: Environment | None = Query(None),
    exposure: Exposure | None = Query(None),
    provider: Provider | None = Query(None),
    status_filter: AssetStatus | None = Query(None, alias="status"),
    team: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[AssetResponse]:
    stmt = select(AIAsset).where(AIAsset.org_id == identity.org_id)
    if environment:
        stmt = stmt.where(AIAsset.environment == environment)
    if exposure:
        stmt = stmt.where(AIAsset.exposure == exposure)
    if provider:
        stmt = stmt.where(AIAsset.provider == provider)
    if status_filter:
        stmt = stmt.where(AIAsset.status == status_filter)
    if team:
        stmt = stmt.where(AIAsset.team == team)
    stmt = stmt.order_by(AIAsset.created_at.desc()).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_response(r) for r in rows]


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: AssetCreate,
    identity: IdentityContext = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    row = AIAsset(
        id=uuid.uuid4(),
        org_id=identity.org_id,
        owner_id=identity.user_id,
        status="active",
        **payload.model_dump(mode="json"),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    log_event(
        AuditEventType.CONFIG_CHANGED,
        AuditOutcome.SUCCESS,
        tenant_id=str(identity.org_id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"asset:{row.id}",
        detail={
            "action": "created",
            "name": row.name,
            "provider": row.provider,
            "model_name": row.model_name,
            "environment": row.environment,
        },
    )
    return _to_response(row)


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    row = await _load_owned(db, asset_id, identity.org_id)
    return _to_response(row)


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    identity: IdentityContext = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    row = await _load_owned(db, asset_id, identity.org_id)
    updates = payload.model_dump(exclude_unset=True)

    # Collect old values for change_log BEFORE we mutate
    changes: dict[str, dict[str, Any]] = {}
    for field, value in updates.items():
        old = getattr(row, field, None)
        if old != value:
            changes[field] = {"old": _serializable(old), "new": _serializable(value)}

    for field, value in updates.items():
        setattr(row, field, value)

    if changes:
        _append_change_log(row, changed_by=identity.user_id, fields_changed=changes)

    await db.commit()
    await db.refresh(row)
    log_event(
        AuditEventType.CONFIG_CHANGED,
        AuditOutcome.SUCCESS,
        tenant_id=str(identity.org_id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"asset:{row.id}",
        detail={
            "action": "updated",
            "fields_changed": sorted(changes.keys()),
        },
    )
    return _to_response(row)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Soft-delete: status → decommissioned. Hard delete reserved for
    explicit /purge endpoint (Sprint 11)."""
    row = await _load_owned(db, asset_id, identity.org_id)
    old_status = row.status
    row.status = "decommissioned"
    _append_change_log(
        row,
        changed_by=identity.user_id,
        fields_changed={"status": {"old": old_status, "new": "decommissioned"}},
    )
    await db.commit()
    log_event(
        AuditEventType.CONFIG_CHANGED,
        AuditOutcome.SUCCESS,
        tenant_id=str(identity.org_id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"asset:{asset_id}",
        detail={"action": "decommissioned", "previous_status": old_status},
    )


def _serializable(v: Any) -> Any:
    """Coerce datetime / UUID into JSON-safe values for change_log."""
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, uuid.UUID):
        return str(v)
    return v
