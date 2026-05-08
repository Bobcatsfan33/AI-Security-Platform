"""Typed RuntimeEvent matching the ClickHouse ``telemetry.runtime_events`` schema.

Used by the writer (this package) and by the runtime-agent ingest endpoint
(Sprint 7). The fields mirror the SQL schema exactly so the writer can map
them positionally without an extra translation layer.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal, Optional

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


@dataclass(frozen=True)
class RuntimeEvent:
    """One row of telemetry.runtime_events.

    Frozen by design — events are immutable once emitted; the writer batches
    and flushes them as-is.
    """

    org_id: uuid.UUID
    asset_id: uuid.UUID
    agent_instance_id: str
    session_id: str
    event_type: EventType
    direction: Direction

    enforcement_level: EnforcementLevel
    pipeline_exit_stage: PipelineExitStage
    action_taken: ActionTaken

    # Optional / defaulted fields
    event_id: uuid.UUID = field(default_factory=uuid.uuid4)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    prompt_hash: str = ""
    prompt_snippet: str = ""
    response_hash: str = ""
    response_snippet: str = ""
    tool_name: Optional[str] = None
    tool_args_hash: Optional[str] = None

    policies_checked: int = 0
    policies_failed: int = 0
    policy_results: str = "[]"  # JSON string
    block_reason: Optional[str] = None

    risk_score: float = 0.0
    latency_ms: int = 0
    stage1_latency_us: int = 0
    stage2_latency_us: Optional[int] = None
    stage3_latency_ms: Optional[int] = None
    model_latency_ms: int = 0
    token_count_input: int = 0
    token_count_output: int = 0
    estimated_cost_usd: float = 0.0

    agent_step_number: Optional[int] = None
    agent_total_steps: Optional[int] = None
    memory_items_accessed: Optional[int] = None
    rag_documents_retrieved: Optional[int] = None

    source_ip: str = "0.0.0.0"
    user_identifier_hash: str = ""
    sdk_version: str = ""
    agent_version: str = ""

    def to_row(self) -> tuple:
        """Return a positional tuple matching the column order of the
        ``runtime_events`` table. Used by the writer's bulk insert path."""
        return (
            self.event_id,
            self.org_id,
            self.asset_id,
            self.agent_instance_id,
            self.session_id,
            self.timestamp,
            self.event_type,
            self.direction,
            self.prompt_hash,
            self.prompt_snippet,
            self.response_hash,
            self.response_snippet,
            self.tool_name,
            self.tool_args_hash,
            self.policies_checked,
            self.policies_failed,
            self.policy_results,
            self.enforcement_level,
            self.pipeline_exit_stage,
            self.action_taken,
            self.block_reason,
            self.risk_score,
            self.latency_ms,
            self.stage1_latency_us,
            self.stage2_latency_us,
            self.stage3_latency_ms,
            self.model_latency_ms,
            self.token_count_input,
            self.token_count_output,
            self.estimated_cost_usd,
            self.agent_step_number,
            self.agent_total_steps,
            self.memory_items_accessed,
            self.rag_documents_retrieved,
            self.source_ip,
            self.user_identifier_hash,
            self.sdk_version,
            self.agent_version,
        )


# Column order MUST match the schema in clickhouse/init/01-create-runtime-events.sql
# AND the order in RuntimeEvent.to_row(). Verify both sides on any change.
RUNTIME_EVENTS_COLUMNS: tuple[str, ...] = (
    "event_id",
    "org_id",
    "asset_id",
    "agent_instance_id",
    "session_id",
    "timestamp",
    "event_type",
    "direction",
    "prompt_hash",
    "prompt_snippet",
    "response_hash",
    "response_snippet",
    "tool_name",
    "tool_args_hash",
    "policies_checked",
    "policies_failed",
    "policy_results",
    "enforcement_level",
    "pipeline_exit_stage",
    "action_taken",
    "block_reason",
    "risk_score",
    "latency_ms",
    "stage1_latency_us",
    "stage2_latency_us",
    "stage3_latency_ms",
    "model_latency_ms",
    "token_count_input",
    "token_count_output",
    "estimated_cost_usd",
    "agent_step_number",
    "agent_total_steps",
    "memory_items_accessed",
    "rag_documents_retrieved",
    "source_ip",
    "user_identifier_hash",
    "sdk_version",
    "agent_version",
)
