"""Runtime ingest + heartbeat + kill-switch control plane.

Three endpoints hit by the Go agent (runtime-agent/cmd/agent):

  POST /v1/runtime/events       batch telemetry events → ClickHouse
  POST /v1/runtime/heartbeat    "I'm alive + my counters"
  GET  /v1/runtime/control      long-poll for kill-switch commands

All require the agent's API key (X-API-Key header) carrying the
``runtime:ingest`` scope.

Heartbeat data lives in Redis with a 5-min TTL so the dashboard can
show "last seen" without a dedicated table. Kill-switch commands also
live in Redis as a per-agent list — operators push commands via
``POST /v1/runtime/agents/{agent_id}/control`` (admin role); agents
consume via long-poll.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.auth.dependencies import require_role, require_scope
from app.identity.types import IdentityContext
from app.services.redis_client import get_redis
from app.siem.exporters import SiemEvent
from app.siem.forwarder import get_forwarder
from app.streaming.events import get_producer
from app.telemetry.clickhouse_writer import record_runtime_event
from app.telemetry.runtime_event import RuntimeEvent

logger = logging.getLogger("platform.runtime")
router = APIRouter(tags=["runtime"])

HEARTBEAT_KEY_PREFIX = "runtime:heartbeat:"
HEARTBEAT_TTL_SECONDS = 300

CONTROL_QUEUE_PREFIX = "runtime:control:"
CONTROL_LONGPOLL_DEFAULT_S = 30
CONTROL_QUEUE_TTL_SECONDS = 86_400


# ─────────────────────────────────────────────── DTOs


EventType = Literal[
    "request",
    "response",
    "tool_call",
    "tool_result",
    "rag_retrieval",
    "memory_access",
    "file_access",
    "external_api_call",
    "policy_violation",
    "block",
    "downgrade",
    "kill_switch",
    "alert",
]
Direction = Literal["inbound", "outbound", "internal"]
EnforcementLevel = Literal["fast", "balanced", "comprehensive"]
PipelineExitStage = Literal["stage1_regex", "stage2_ml", "stage3_judge", "no_match"]
ActionTaken = Literal["allowed", "blocked", "modified", "flagged", "escalated"]


class EventIn(BaseModel):
    """Inbound event from the Go agent. Field names match
    ``runtime-agent/telemetry/event.go`` exactly. Optional fields are
    permissive — agents on older versions may omit later additions."""

    event_id: str = Field(...)
    org_id: uuid.UUID
    asset_id: uuid.UUID
    agent_instance_id: str = ""
    session_id: str = ""
    timestamp: datetime
    event_type: EventType
    direction: Direction

    prompt_hash: str = ""
    prompt_snippet: str = ""
    response_hash: str = ""
    response_snippet: str = ""
    tool_name: str | None = None
    tool_args_hash: str | None = None

    policies_checked: int = 0
    policies_failed: int = 0
    policy_results: str = "[]"
    enforcement_level: EnforcementLevel = "fast"
    pipeline_exit_stage: PipelineExitStage = "no_match"
    action_taken: ActionTaken = "allowed"
    block_reason: str | None = None

    risk_score: float = 0.0
    latency_ms: int = 0
    stage1_latency_us: int = 0
    stage2_latency_us: int | None = None
    stage3_latency_ms: int | None = None
    model_latency_ms: int = 0
    token_count_input: int = 0
    token_count_output: int = 0
    estimated_cost_usd: float = 0.0

    agent_step_number: int | None = None
    agent_total_steps: int | None = None
    memory_items_accessed: int | None = None
    rag_documents_retrieved: int | None = None

    source_ip: str = "0.0.0.0"
    user_identifier_hash: str = ""
    sdk_version: str = ""
    agent_version: str = ""

    # Causal lineage (poset spine). Optional so older agents that don't
    # emit lineage still ingest cleanly; absent => fresh root downstream.
    parent_event_id: uuid.UUID | None = None
    root_event_id: uuid.UUID | None = None
    causal_depth: int = 0
    correlation_key: str = ""


class EventBatch(BaseModel):
    events: list[EventIn] = Field(..., min_length=1, max_length=500)


class IngestResult(BaseModel):
    accepted: int
    rejected: int
    rejected_reasons: list[str] = Field(default_factory=list)


# ─────────────────────────────────────────────── routes


@router.post("/events", response_model=IngestResult)
async def ingest_events(
    batch: EventBatch,
    identity: IdentityContext = Depends(require_scope("runtime:ingest")),
) -> IngestResult:
    """Accept a batch of runtime telemetry events and enqueue for
    ClickHouse insertion.

    Validation:
      - Caller must be API-key-authenticated with ``runtime:ingest`` scope
      - Every event's org_id must match the caller's org_id (no cross-
        tenant ingestion)
      - Malformed events are counted but don't fail the batch
    """
    accepted = 0
    rejected_reasons: list[str] = []
    for event in batch.events:
        if event.org_id != identity.org_id:
            rejected_reasons.append(f"event {event.event_id}: org_id mismatch")
            continue
        try:
            ev = _to_runtime_event(event)
        except Exception as exc:  # noqa: BLE001
            rejected_reasons.append(f"event {event.event_id}: coerce failed: {exc}")
            continue
        enqueued = await record_runtime_event(ev)
        if not enqueued:
            rejected_reasons.append(f"event {event.event_id}: telemetry queue full or writer down")
            continue
        accepted += 1
        # Dual-write to the streaming spine so the EPA fleet sees events live.
        # ClickHouse is the durable store; the broker is best-effort — a
        # publish failure must never fail an already-accepted ingest.
        producer = get_producer()
        if producer is not None:
            try:
                await producer.publish(ev)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "runtime_event_stream_publish_failed",
                    extra={"event_id": event.event_id, "error": str(exc)},
                )
        # Mirror security-relevant runtime events to the SIEM forwarder.
        if event.event_type in {"policy_violation", "block", "kill_switch", "alert", "downgrade"}:
            get_forwarder().submit(
                SiemEvent(
                    timestamp=event.timestamp,
                    org_id=str(event.org_id),
                    event_type="runtime_event",
                    severity=_severity_from_event(event),
                    source="runtime_agent",
                    title=f"runtime.{event.event_type}",
                    asset_id=str(event.asset_id),
                    correlation_id=event.session_id or event.event_id,
                    detail={
                        "agent_instance_id": event.agent_instance_id,
                        "action_taken": event.action_taken,
                        "pipeline_exit_stage": event.pipeline_exit_stage,
                        "risk_score": event.risk_score,
                        "prompt_hash": event.prompt_hash,
                        "response_hash": event.response_hash,
                    },
                )
            )
    if accepted:
        from app.observability.metrics import RUNTIME_EVENTS_INGESTED

        RUNTIME_EVENTS_INGESTED.inc(accepted)
    return IngestResult(
        accepted=accepted,
        rejected=len(batch.events) - accepted,
        rejected_reasons=rejected_reasons[:20],  # cap to keep response small
    )


def _severity_from_event(event: EventIn) -> str:
    """Derive a SIEM severity from event type + risk score. The agent
    doesn't send severity directly — we infer it from the action."""
    if event.event_type == "kill_switch":
        return "critical"
    if event.event_type in {"block", "policy_violation"}:
        return "high" if event.risk_score >= 0.6 else "medium"
    if event.event_type == "downgrade":
        return "medium"
    if event.event_type == "alert":
        return "high" if event.risk_score >= 0.8 else "medium"
    return "low"


def _to_runtime_event(e: EventIn) -> RuntimeEvent:
    """Translate the wire DTO into the internal RuntimeEvent dataclass
    that the ClickHouse writer expects."""
    try:
        event_uuid = uuid.UUID(e.event_id)
    except ValueError:
        # The Go agent generates UUIDs; an invalid one is a coercion
        # error we surface to the caller.
        raise ValueError(f"invalid event_id UUID: {e.event_id!r}")
    return RuntimeEvent(
        event_id=event_uuid,
        org_id=e.org_id,
        asset_id=e.asset_id,
        agent_instance_id=e.agent_instance_id,
        session_id=e.session_id,
        timestamp=e.timestamp,
        event_type=e.event_type,
        direction=e.direction,
        prompt_hash=e.prompt_hash,
        prompt_snippet=e.prompt_snippet,
        response_hash=e.response_hash,
        response_snippet=e.response_snippet,
        tool_name=e.tool_name,
        tool_args_hash=e.tool_args_hash,
        policies_checked=e.policies_checked,
        policies_failed=e.policies_failed,
        policy_results=e.policy_results,
        enforcement_level=e.enforcement_level,
        pipeline_exit_stage=e.pipeline_exit_stage,
        action_taken=e.action_taken,
        block_reason=e.block_reason,
        risk_score=e.risk_score,
        latency_ms=e.latency_ms,
        stage1_latency_us=e.stage1_latency_us,
        stage2_latency_us=e.stage2_latency_us,
        stage3_latency_ms=e.stage3_latency_ms,
        model_latency_ms=e.model_latency_ms,
        token_count_input=e.token_count_input,
        token_count_output=e.token_count_output,
        estimated_cost_usd=e.estimated_cost_usd,
        agent_step_number=e.agent_step_number,
        agent_total_steps=e.agent_total_steps,
        memory_items_accessed=e.memory_items_accessed,
        rag_documents_retrieved=e.rag_documents_retrieved,
        source_ip=e.source_ip,
        user_identifier_hash=e.user_identifier_hash,
        sdk_version=e.sdk_version,
        agent_version=e.agent_version,
        parent_event_id=e.parent_event_id,
        root_event_id=e.root_event_id,
        causal_depth=e.causal_depth,
        correlation_key=e.correlation_key,
    )


# ─────────────────────────────────────────────── Heartbeat


class HeartbeatPayload(BaseModel):
    agent_id: str
    org_id: uuid.UUID
    version: str
    policy_id: uuid.UUID | None = None
    policy_version: int = 0
    policy_loaded_at: str | None = None
    policy_stale: bool = False
    counters: dict[str, Any] = Field(default_factory=dict)
    emitted_at: str | None = None


@router.post("/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
async def heartbeat(
    payload: HeartbeatPayload,
    identity: IdentityContext = Depends(require_scope("runtime:ingest")),
) -> None:
    """Record the agent's heartbeat in Redis with a 5-min TTL.

    The runtime monitoring dashboard reads from this key to show
    "agents connected" and "policy version per agent" without needing
    its own table. The TTL handles "agent went away" — keys naturally
    expire 5 min after the last heartbeat.
    """
    if payload.org_id != identity.org_id:
        raise HTTPException(status_code=403, detail="org_id_mismatch")

    redis = await get_redis()
    key = HEARTBEAT_KEY_PREFIX + payload.agent_id
    body = payload.model_dump(mode="json")
    body["received_at"] = datetime.now(timezone.utc).isoformat()
    await redis.set(key, json.dumps(body, separators=(",", ":")), ex=HEARTBEAT_TTL_SECONDS)


@router.get("/agents", response_model=list[dict[str, Any]])
async def list_agents(
    identity: IdentityContext = Depends(require_role("viewer")),
) -> list[dict[str, Any]]:
    """List every agent that's emitted a heartbeat in the last 5 min.

    Backed by a Redis SCAN on the heartbeat key prefix — fine for
    deployments with up to a few thousand agents per org. Larger
    deployments should swap in a dedicated table (Sprint 11).
    """
    redis = await get_redis()
    pattern = HEARTBEAT_KEY_PREFIX + "*"
    out: list[dict[str, Any]] = []
    async for key in redis.scan_iter(match=pattern):
        raw = await redis.get(key)
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if data.get("org_id") != str(identity.org_id):
            continue
        out.append(data)
    return out


# ─────────────────────────────────────────────── Kill-switch control


class KillSwitchCommandIn(BaseModel):
    type: Literal[
        "block_all",
        "unblock_all",
        "block_asset",
        "unblock_asset",
        "disable_tool",
        "enable_tool",
        "downgrade_model",
    ]
    asset_id: uuid.UUID | None = None
    tool_name: str | None = None


class KillSwitchCommandOut(BaseModel):
    command_id: str
    type: str
    asset_id: str = ""
    tool_name: str = ""
    issued_at: str
    issued_by: str = ""


@router.post(
    "/agents/{agent_id}/control",
    response_model=KillSwitchCommandOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def enqueue_command(
    agent_id: str,
    payload: KillSwitchCommandIn,
    identity: IdentityContext = Depends(require_role("admin")),
) -> KillSwitchCommandOut:
    """Push a kill-switch command onto the agent's queue.

    Admin-only — kill-switch commands are emergency overrides and must
    not be triggerable by lower-privileged roles. The agent's long-poll
    consumer (``GET /control``) drains the queue.
    """
    cmd = KillSwitchCommandOut(
        command_id=str(uuid.uuid4()),
        type=payload.type,
        asset_id=str(payload.asset_id) if payload.asset_id else "",
        tool_name=payload.tool_name or "",
        issued_at=datetime.now(timezone.utc).isoformat(),
        issued_by=str(identity.user_id) if identity.user_id else "system",
    )
    redis = await get_redis()
    queue_key = CONTROL_QUEUE_PREFIX + agent_id
    await redis.rpush(queue_key, json.dumps(cmd.model_dump(mode="json"), separators=(",", ":")))
    await redis.expire(queue_key, CONTROL_QUEUE_TTL_SECONDS)

    logger.info(
        "killswitch_enqueued",
        extra={
            "agent_id": agent_id,
            "command_id": cmd.command_id,
            "type": cmd.type,
            "issued_by": cmd.issued_by,
        },
    )
    return cmd


@router.get(
    "/control",
    responses={
        200: {"description": "One or more commands ready"},
        204: {"description": "No commands within long-poll timeout"},
    },
)
async def long_poll_commands(
    agent_id: str = Query(...),
    ack: str | None = Query(None),
    timeout_seconds: int = Query(CONTROL_LONGPOLL_DEFAULT_S, ge=1, le=120),
    identity: IdentityContext = Depends(require_scope("runtime:ingest")),
) -> dict[str, Any]:
    """Agent long-poll for kill-switch commands.

    Returns 204 if no commands are ready within ``timeout_seconds``.
    Returns 200 with ``{"commands": [...]}`` when at least one command
    is queued. The ``ack`` parameter is the last command_id the agent
    successfully applied — included for visibility in logs; we do NOT
    require it because each command is queue-popped on first read
    (LPOP is atomic).
    """
    if ack:
        logger.debug("killswitch_ack", extra={"agent_id": agent_id, "ack": ack})

    redis = await get_redis()
    queue_key = CONTROL_QUEUE_PREFIX + agent_id

    # Try an immediate non-blocking pop first; otherwise BLPOP for up to
    # timeout_seconds. asyncio-aware blocking via the asyncio redis
    # client.
    raw = await redis.lpop(queue_key)
    if raw is None:
        result = await redis.blpop(queue_key, timeout=timeout_seconds)
        if result is None:
            return _no_content()
        # blpop returns (key, value) in async aioredis-compatible client
        _, raw = result

    commands: list[dict[str, Any]] = []
    try:
        commands.append(json.loads(raw))
    except json.JSONDecodeError:
        logger.warning("killswitch_bad_payload", extra={"raw": str(raw)[:200]})
        return _no_content()

    # Drain anything else immediately available so the agent applies a
    # burst of commands in one poll.
    for _ in range(99):
        more = await redis.lpop(queue_key)
        if not more:
            break
        try:
            commands.append(json.loads(more))
        except json.JSONDecodeError:
            continue

    return {"commands": commands}


def _no_content() -> dict[str, Any]:
    # FastAPI doesn't have an easy "return 204 from a non-204 route" path;
    # we return an empty payload and rely on the agent to treat the empty
    # commands list as no-op. Keeping the return shape consistent helps
    # client deserialization.
    return {"commands": []}
