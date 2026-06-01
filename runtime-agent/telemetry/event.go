// Package telemetry buffers runtime events in memory and uploads them
// to the control plane. Wire-compatible with the Python platform's
// telemetry.runtime_events ClickHouse table.
package telemetry

import (
	"time"

	"github.com/google/uuid"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
)

// Event mirrors backend/app/telemetry/runtime_event.py::RuntimeEvent.
// Field names use snake_case to match the wire format the control plane
// expects on POST /v1/runtime/events.
type Event struct {
	EventID         string    `json:"event_id"`
	OrgID           string    `json:"org_id"`
	AssetID         string    `json:"asset_id"`
	AgentInstanceID string    `json:"agent_instance_id"`
	SessionID       string    `json:"session_id"`
	Timestamp       time.Time `json:"timestamp"`
	EventType       string    `json:"event_type"`
	Direction       string    `json:"direction"`

	PromptHash      string `json:"prompt_hash"`
	PromptSnippet   string `json:"prompt_snippet"`
	ResponseHash    string `json:"response_hash"`
	ResponseSnippet string `json:"response_snippet"`
	ToolName        string `json:"tool_name,omitempty"`
	ToolArgsHash    string `json:"tool_args_hash,omitempty"`

	PoliciesChecked   int                      `json:"policies_checked"`
	PoliciesFailed    int                      `json:"policies_failed"`
	PolicyResults     string                   `json:"policy_results"` // JSON string
	EnforcementLevel  policy.EnforcementLevel  `json:"enforcement_level"`
	PipelineExitStage policy.PipelineExitStage `json:"pipeline_exit_stage"`
	ActionTaken       policy.Action            `json:"action_taken"`
	BlockReason       string                   `json:"block_reason,omitempty"`

	RiskScore        float32 `json:"risk_score"`
	LatencyMS        uint32  `json:"latency_ms"`
	Stage1LatencyUS  uint32  `json:"stage1_latency_us"`
	Stage2LatencyUS  *uint32 `json:"stage2_latency_us,omitempty"`
	Stage3LatencyMS  *uint32 `json:"stage3_latency_ms,omitempty"`
	ModelLatencyMS   uint32  `json:"model_latency_ms"`
	TokenCountInput  uint32  `json:"token_count_input"`
	TokenCountOutput uint32  `json:"token_count_output"`
	EstimatedCostUSD float32 `json:"estimated_cost_usd"`

	SourceIP           string `json:"source_ip"`
	UserIdentifierHash string `json:"user_identifier_hash"`
	SDKVersion         string `json:"sdk_version"`
	AgentVersion       string `json:"agent_version"`

	// Causal lineage (poset spine). Mirrors the Python RuntimeEvent.
	// ParentEventID is the event that caused this one; RootEventID is the
	// originating request; CausalDepth is the hop count from the root;
	// CorrelationKey threads a flow across agent instances. Populated from
	// inbound propagation headers (see proxy/causal.go); empty/zero for a
	// fresh root event.
	ParentEventID  string `json:"parent_event_id,omitempty"`
	RootEventID    string `json:"root_event_id,omitempty"`
	CausalDepth    uint16 `json:"causal_depth"`
	CorrelationKey string `json:"correlation_key,omitempty"`
}

// NewEvent constructs a fresh event with auto-generated event_id and
// current timestamp. Caller fills in the rest.
func NewEvent(orgID, assetID, agentInstanceID, sessionID string) *Event {
	return &Event{
		EventID:         uuid.NewString(),
		OrgID:           orgID,
		AssetID:         assetID,
		AgentInstanceID: agentInstanceID,
		SessionID:       sessionID,
		Timestamp:       time.Now().UTC(),
	}
}
