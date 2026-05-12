"""MCP routes — tool registry, per-call inspection, violation surface.

All routes are org-scoped via the standard JWT/API-key auth layer; the
runtime agent (Sprint 7) calls ``POST /v1/mcp/inspect`` on every MCP
tool invocation it sees and acts on the recommendation.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.db.models.mcp import McpCall, McpToolProfile, McpViolation
from app.db.session import get_db
from app.identity.types import IdentityContext
from app.mcp import service as mcp_service
from app.mcp.inspector import DEFAULT_TOOL_PROFILES

router = APIRouter(tags=["mcp"])


# ─────────────────────────────────────────────── Tool profile DTOs


class ToolProfileCreate(BaseModel):
    tool_name: str = Field(min_length=1, max_length=128)
    access_mode: Literal["read", "write", "execute", "admin", "exfil"]
    description: str = ""
    allowed_params: list[str] = Field(default_factory=list)
    forbidden_params: list[str] = Field(default_factory=list)
    param_constraints: dict[str, dict[str, Any]] = Field(default_factory=dict)


class ToolProfileUpdate(BaseModel):
    access_mode: Literal["read", "write", "execute", "admin", "exfil"] | None = None
    description: str | None = None
    allowed_params: list[str] | None = None
    forbidden_params: list[str] | None = None
    param_constraints: dict[str, dict[str, Any]] | None = None


class ToolProfileResponse(BaseModel):
    id: uuid.UUID | None
    tool_name: str
    access_mode: str
    description: str
    allowed_params: list[str]
    forbidden_params: list[str]
    param_constraints: dict[str, dict[str, Any]]
    is_builtin: bool


# ─────────────────────────────────────────────── Inspection DTOs


class InspectRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(default="", max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)
    params: dict[str, Any] = Field(default_factory=dict)


class InspectResponse(BaseModel):
    call_id: uuid.UUID
    tool_name: str
    access_mode: str | None
    allowed: bool
    recommendation: str
    risk_score: float
    violations: list[dict[str, Any]]
    chain_matches: list[dict[str, Any]]


class ViolationResponse(BaseModel):
    id: uuid.UUID
    call_id: uuid.UUID
    session_id: str
    tool_name: str
    recommendation: str
    risk_score: float
    violations: list[dict[str, Any]]
    chain_matches: list[dict[str, Any]]
    resolution_status: str
    resolution_notes: str | None
    resolved_at: datetime | None
    created_at: datetime


class ResolveViolationRequest(BaseModel):
    status: Literal["acknowledged", "resolved", "false_positive"]
    notes: str | None = None


class CallEntry(BaseModel):
    id: uuid.UUID
    tool_name: str
    access_mode: str
    recommendation: str
    risk_score: float
    called_at: datetime


# ─────────────────────────────────────────────── Tool profile routes


@router.get("/tools", response_model=list[ToolProfileResponse])
async def list_tools(
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[ToolProfileResponse]:
    """Return the union of org-custom + built-in profiles.

    Org-custom profiles override built-ins by ``tool_name``.
    """
    custom_rows = (
        await db.execute(
            select(McpToolProfile).where(McpToolProfile.org_id == identity.org_id)
        )
    ).scalars().all()
    custom_names = {r.tool_name for r in custom_rows}

    out: list[ToolProfileResponse] = []
    for r in custom_rows:
        out.append(
            ToolProfileResponse(
                id=r.id,
                tool_name=r.tool_name,
                access_mode=r.access_mode,
                description=r.description,
                allowed_params=list(r.allowed_params or []),
                forbidden_params=list(r.forbidden_params or []),
                param_constraints=dict(r.param_constraints or {}),
                is_builtin=False,
            )
        )
    for p in DEFAULT_TOOL_PROFILES:
        if p.tool_name in custom_names:
            continue
        out.append(
            ToolProfileResponse(
                id=None,
                tool_name=p.tool_name,
                access_mode=p.access_mode,
                description=p.description,
                allowed_params=list(p.allowed_params),
                forbidden_params=list(p.forbidden_params),
                param_constraints=dict(p.param_constraints),
                is_builtin=True,
            )
        )
    return out


@router.post(
    "/tools",
    response_model=ToolProfileResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_tool(
    payload: ToolProfileCreate,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> ToolProfileResponse:
    existing = (
        await db.execute(
            select(McpToolProfile).where(
                McpToolProfile.org_id == identity.org_id,
                McpToolProfile.tool_name == payload.tool_name,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="tool_name_already_registered"
        )
    row = McpToolProfile(
        id=uuid.uuid4(),
        org_id=identity.org_id,
        tool_name=payload.tool_name,
        access_mode=payload.access_mode,
        description=payload.description,
        allowed_params=payload.allowed_params,
        forbidden_params=payload.forbidden_params,
        param_constraints=payload.param_constraints,
        created_by=identity.user_id,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return ToolProfileResponse(
        id=row.id,
        tool_name=row.tool_name,
        access_mode=row.access_mode,
        description=row.description,
        allowed_params=list(row.allowed_params or []),
        forbidden_params=list(row.forbidden_params or []),
        param_constraints=dict(row.param_constraints or {}),
        is_builtin=False,
    )


@router.patch("/tools/{tool_id}", response_model=ToolProfileResponse)
async def update_tool(
    tool_id: uuid.UUID,
    payload: ToolProfileUpdate,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> ToolProfileResponse:
    row = (
        await db.execute(
            select(McpToolProfile).where(
                McpToolProfile.id == tool_id,
                McpToolProfile.org_id == identity.org_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="not_found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(row, field, value)
    await db.commit()
    await db.refresh(row)
    return ToolProfileResponse(
        id=row.id,
        tool_name=row.tool_name,
        access_mode=row.access_mode,
        description=row.description,
        allowed_params=list(row.allowed_params or []),
        forbidden_params=list(row.forbidden_params or []),
        param_constraints=dict(row.param_constraints or {}),
        is_builtin=False,
    )


@router.delete("/tools/{tool_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tool(
    tool_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> None:
    row = (
        await db.execute(
            select(McpToolProfile).where(
                McpToolProfile.id == tool_id,
                McpToolProfile.org_id == identity.org_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="not_found")
    await db.delete(row)
    await db.commit()


# ─────────────────────────────────────────────── Inspection


@router.post("/inspect", response_model=InspectResponse)
async def inspect(
    payload: InspectRequest,
    request: Request,
    identity: IdentityContext = Depends(require_role("api_only")),
    db: AsyncSession = Depends(get_db),
) -> InspectResponse:
    """Inspect one MCP tool call.

    Called by the runtime agent (Sprint 7) before forwarding the call to
    the tool. The agent BLOCKS on this round-trip, so the route should
    return in well under the agent's policy-enforcement budget.

    Requires ``api_only`` minimum role — this is a machine-to-machine
    endpoint hit by the runtime agent's API key, not by a human.
    """
    source_ip = request.client.host if request.client else "0.0.0.0"
    result, call = await mcp_service.inspect_and_record(
        db,
        org_id=identity.org_id,
        session_id=payload.session_id,
        agent_id=payload.agent_id,
        tool_name=payload.tool_name,
        params=payload.params,
        source_ip=source_ip,
    )
    return InspectResponse(
        call_id=call.id,
        tool_name=result.tool_name,
        access_mode=result.access_mode,
        allowed=result.allowed,
        recommendation=result.recommendation,
        risk_score=result.risk_score,
        violations=[
            {"type": v.type, "detail": v.detail, "severity": v.severity}
            for v in result.violations
        ],
        chain_matches=[
            {
                "name": c.name,
                "severity": c.severity,
                "mitre_technique": c.mitre_technique,
                "confidence": c.confidence,
            }
            for c in result.chain_matches
        ],
    )


# ─────────────────────────────────────────────── Violations + chain


@router.get("/violations", response_model=list[ViolationResponse])
async def list_violations(
    status_filter: Literal["open", "acknowledged", "resolved", "false_positive"]
    | None = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
    identity: IdentityContext = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> list[ViolationResponse]:
    stmt = select(McpViolation).where(McpViolation.org_id == identity.org_id)
    if status_filter:
        stmt = stmt.where(McpViolation.resolution_status == status_filter)
    stmt = stmt.order_by(McpViolation.created_at.desc()).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        ViolationResponse(
            id=r.id,
            call_id=r.call_id,
            session_id=r.session_id,
            tool_name=r.tool_name,
            recommendation=r.recommendation,
            risk_score=r.risk_score,
            violations=list(r.violations or []),
            chain_matches=list(r.chain_matches or []),
            resolution_status=r.resolution_status,
            resolution_notes=r.resolution_notes,
            resolved_at=r.resolved_at,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.post("/violations/{violation_id}/resolve", response_model=ViolationResponse)
async def resolve_violation(
    violation_id: uuid.UUID,
    payload: ResolveViolationRequest,
    identity: IdentityContext = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> ViolationResponse:
    from datetime import datetime, timezone

    row = (
        await db.execute(
            select(McpViolation).where(
                McpViolation.id == violation_id,
                McpViolation.org_id == identity.org_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="not_found")
    row.resolution_status = payload.status
    row.resolution_notes = payload.notes
    row.resolved_by = identity.user_id
    row.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(row)
    return ViolationResponse(
        id=row.id,
        call_id=row.call_id,
        session_id=row.session_id,
        tool_name=row.tool_name,
        recommendation=row.recommendation,
        risk_score=row.risk_score,
        violations=list(row.violations or []),
        chain_matches=list(row.chain_matches or []),
        resolution_status=row.resolution_status,
        resolution_notes=row.resolution_notes,
        resolved_at=row.resolved_at,
        created_at=row.created_at,
    )


@router.get("/chain/{session_id}", response_model=list[CallEntry])
async def get_chain(
    session_id: str,
    limit: int = Query(200, ge=1, le=1000),
    identity: IdentityContext = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> list[CallEntry]:
    rows = (
        await db.execute(
            select(McpCall)
            .where(
                McpCall.org_id == identity.org_id, McpCall.session_id == session_id
            )
            .order_by(McpCall.called_at.asc())
            .limit(limit)
        )
    ).scalars().all()
    return [
        CallEntry(
            id=r.id,
            tool_name=r.tool_name,
            access_mode=r.access_mode,
            recommendation=r.recommendation,
            risk_score=r.risk_score,
            called_at=r.called_at,
        )
        for r in rows
    ]
