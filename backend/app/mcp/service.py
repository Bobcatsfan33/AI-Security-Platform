"""MCP service layer — persists inspections, records violations, surfaces
recent-call context for chain matching.

The route handlers in ``app/api/v1/mcp.py`` orchestrate auth and DTO
mapping; the actual storage operations live here so the inspection
logic can be tested independently of HTTP.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.mcp import McpCall, McpToolProfile, McpViolation
from app.mcp.inspector import (
    DEFAULT_TOOL_PROFILES,
    AccessMode,
    InspectionResult,
    ToolProfile,
    builtin_profiles_by_name,
    inspect_call,
)
from app.security.audit_log import AuditEventType, AuditOutcome, log_event


# Lookback window for chain pattern matching. Calls older than this are
# not considered part of the current chain — same default as TokenDNA's
# CHAIN_PATTERN_WINDOW_SECONDS so behavior is consistent.
CHAIN_LOOKBACK_SECONDS = 3600
CHAIN_LOOKBACK_LIMIT = 50


# ─────────────────────────────────────────────── Tool profile registry


async def resolve_profile(
    db: AsyncSession, *, org_id: uuid.UUID, tool_name: str
) -> ToolProfile | None:
    """Resolve a tool name to its profile.

    Resolution order:
      1. Org-specific custom profile (mcp_tool_profiles row)
      2. Built-in DEFAULT_TOOL_PROFILES
      3. None (caller will record an unregistered_tool violation)
    """
    row = (
        await db.execute(
            select(McpToolProfile).where(
                McpToolProfile.org_id == org_id,
                McpToolProfile.tool_name == tool_name,
            )
        )
    ).scalar_one_or_none()
    if row is not None:
        return ToolProfile(
            tool_name=row.tool_name,
            access_mode=row.access_mode,  # type: ignore[arg-type]
            description=row.description,
            allowed_params=tuple(row.allowed_params or []),
            forbidden_params=tuple(row.forbidden_params or []),
            param_constraints=dict(row.param_constraints or {}),
        )

    return builtin_profiles_by_name().get(tool_name)


# ─────────────────────────────────────────────── Recent-call context


async def recent_access_modes(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    session_id: str,
    now: datetime | None = None,
) -> list[AccessMode]:
    """Return the recent access_mode sequence for a session, oldest-first.

    The list excludes calls older than CHAIN_LOOKBACK_SECONDS so a long-
    idle session doesn't trip patterns that span hours of inactivity.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=CHAIN_LOOKBACK_SECONDS)

    rows = (
        await db.execute(
            select(McpCall.access_mode)
            .where(
                McpCall.org_id == org_id,
                McpCall.session_id == session_id,
                McpCall.called_at >= cutoff,
            )
            .order_by(McpCall.called_at.asc())
            .limit(CHAIN_LOOKBACK_LIMIT)
        )
    ).scalars().all()
    return list(rows)  # type: ignore[return-value]


# ─────────────────────────────────────────────── Top-level inspect


async def inspect_and_record(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    session_id: str,
    agent_id: str,
    tool_name: str,
    params: dict[str, Any],
    source_ip: str = "0.0.0.0",
) -> tuple[InspectionResult, McpCall]:
    """End-to-end inspection: resolve profile, pull recent chain, run
    :func:`inspect_call`, persist McpCall, and persist McpViolation when
    the recommendation isn't ``allow``.

    Audit emissions on every non-allow outcome.
    """
    profile = await resolve_profile(db, org_id=org_id, tool_name=tool_name)

    history = await recent_access_modes(db, org_id=org_id, session_id=session_id)
    # Append THIS call's access mode so chain matching includes it as the
    # final step (chain patterns are anchored on the latest call).
    if profile is not None:
        history_with_current = list(history) + [profile.access_mode]
    else:
        history_with_current = list(history)

    result = inspect_call(
        tool_name=tool_name,
        params=params,
        profile=profile,
        recent_modes=history_with_current,
    )

    # Persist the call regardless of outcome — chain history must include
    # every call, even allowed ones, or future matches will miss anchors.
    call = McpCall(
        id=uuid.uuid4(),
        org_id=org_id,
        session_id=session_id,
        agent_id=agent_id,
        tool_name=tool_name,
        access_mode=result.access_mode or "read",
        params=dict(params),
        recommendation=result.recommendation,
        risk_score=result.risk_score,
        violations=[_violation_to_dict(v) for v in result.violations],
        chain_matches=[_chain_match_to_dict(c) for c in result.chain_matches],
    )
    db.add(call)
    await db.flush()  # need call.id below

    if result.recommendation != "allow":
        violation = McpViolation(
            id=uuid.uuid4(),
            org_id=org_id,
            call_id=call.id,
            session_id=session_id,
            tool_name=tool_name,
            recommendation=result.recommendation,
            risk_score=result.risk_score,
            violations=call.violations,
            chain_matches=call.chain_matches,
            resolution_status="open",
        )
        db.add(violation)
        await db.flush()

        log_event(
            AuditEventType.ACCESS_DENIED
            if result.recommendation == "block"
            else AuditEventType.POLICY_UPDATED,  # closest existing event_type
            AuditOutcome.FAILURE
            if result.recommendation == "block"
            else AuditOutcome.UNKNOWN,
            tenant_id=str(org_id),
            subject=agent_id or "agent",
            source_ip=source_ip,
            resource=f"mcp:{tool_name}",
            detail={
                "session_id": session_id,
                "risk_score": result.risk_score,
                "recommendation": result.recommendation,
                "chain_matches": [c.name for c in result.chain_matches],
                "violation_types": sorted({v.type for v in result.violations}),
            },
        )

    await db.commit()
    return result, call


# ─────────────────────────────────────────────── Helpers


def _violation_to_dict(v) -> dict[str, Any]:  # noqa: ANN001
    return {"type": v.type, "detail": v.detail, "severity": v.severity}


def _chain_match_to_dict(c) -> dict[str, Any]:  # noqa: ANN001
    return {
        "name": c.name,
        "description": c.description,
        "sequence": list(c.sequence),
        "severity": c.severity,
        "mitre_technique": c.mitre_technique,
        "positions": list(c.positions),
        "gap": c.gap,
        "confidence": c.confidence,
    }
