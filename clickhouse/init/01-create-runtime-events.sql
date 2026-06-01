-- ClickHouse schema for runtime telemetry — append-only, never queried in
-- the policy enforcement hot path.
-- Sprint 1 ships the schema only. The Python client and the runtime agent
-- writer are wired in follow-on sprints (Sprint 1 follow-on for the Python
-- service, Sprint 7 for the agent).

CREATE DATABASE IF NOT EXISTS telemetry;

CREATE TABLE IF NOT EXISTS telemetry.runtime_events (
    event_id UUID,
    org_id UUID,
    asset_id UUID,
    agent_instance_id String,
    session_id String,
    timestamp DateTime64(3),

    event_type Enum('request' = 1, 'response' = 2, 'tool_call' = 3, 'tool_result' = 4,
                    'rag_retrieval' = 5, 'memory_access' = 6, 'file_access' = 7,
                    'external_api_call' = 8, 'policy_violation' = 9, 'block' = 10,
                    'downgrade' = 11, 'kill_switch' = 12, 'alert' = 13),
    direction Enum('inbound' = 1, 'outbound' = 2, 'internal' = 3),

    prompt_hash String,
    prompt_snippet String,
    response_hash String,
    response_snippet String,
    tool_name Nullable(String),
    tool_args_hash Nullable(String),

    policies_checked UInt16,
    policies_failed UInt16,
    policy_results String,
    enforcement_level Enum('fast' = 1, 'balanced' = 2, 'comprehensive' = 3),
    pipeline_exit_stage Enum('stage1_regex' = 1, 'stage2_ml' = 2, 'stage3_judge' = 3, 'no_match' = 4),
    action_taken Enum('allowed' = 1, 'blocked' = 2, 'modified' = 3, 'flagged' = 4, 'escalated' = 5),
    block_reason Nullable(String),

    risk_score Float32,
    latency_ms UInt32,
    stage1_latency_us UInt32,
    stage2_latency_us Nullable(UInt32),
    stage3_latency_ms Nullable(UInt32),
    model_latency_ms UInt32,
    token_count_input UInt32,
    token_count_output UInt32,
    estimated_cost_usd Float32,

    agent_step_number Nullable(UInt16),
    agent_total_steps Nullable(UInt16),
    memory_items_accessed Nullable(UInt16),
    rag_documents_retrieved Nullable(UInt16),

    source_ip String,
    user_identifier_hash String,
    sdk_version String,
    agent_version String,

    -- Causal lineage (poset spine). parent_event_id is the event that
    -- caused this one; root_event_id is the originating request; causal_depth
    -- is the hop count from root; correlation_key threads a flow across
    -- agent instances. See backend/app/telemetry/runtime_event.py.
    parent_event_id Nullable(UUID),
    root_event_id Nullable(UUID),
    causal_depth UInt16 DEFAULT 0,
    correlation_key String DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (org_id, asset_id, timestamp)
TTL timestamp + INTERVAL 90 DAY;
