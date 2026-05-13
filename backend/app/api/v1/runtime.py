"""Runtime telemetry ingest — receives event batches from the Go agent.

Wire-compatible with ``runtime-agent/telemetry/event.go``. The agent
POSTs a JSON body shaped ``{"events": [Event, ...]}``. We validate,
coerce types, and enqueue to the async ClickHouse writer.

Authentication is via the agent's API key (X-API-Key header). The key
must carry the ``runtime:ingest`` scope. Agent provisioning produces
these keys via the regular ``/v1/admin/...`` flow (Sprint 11 will add
a dedicated agent-key UI).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.auth.dependencies import require_scope
from app.identity.types import IdentityContext
from app.telemetry.clickhouse_writer import record_runtime_event
from app.telemetry.runtime_event import RuntimeEvent

router = APIRouter(tags=["runtime"])


# ─────────────────────────────────────────────── DTOs


EventType = Literal[
    "request", "response", "tool_call", "tool_result",
    "rag_retrieval", "memory_access", "file_access",
    "external_api_call", "policy_violation", "block",
    "downgrade", "kill_switch", "alert",
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
            rejected_reasons.append(
                f"event {event.event_id}: org_id mismatch"
            )
            continue
        try:
            ev = _to_runtime_event(event)
        except Exception as exc:  # noqa: BLE001
            rejected_reasons.append(
                f"event {event.event_id}: coerce failed: {exc}"
            )
            continue
        enqueued = await record_runtime_event(ev)
        if not enqueued:
            rejected_reasons.append(
                f"event {event.event_id}: telemetry queue full or writer down"
            )
            continue
        accepted += 1
    return IngestResult(
        accepted=accepted,
        rejected=len(batch.events) - accepted,
        rejected_reasons=rejected_reasons[:20],  # cap to keep response small
    )


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
    )
