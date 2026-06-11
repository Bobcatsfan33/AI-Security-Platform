// Package policy implements the three-stage policy pipeline for the
// runtime agent. Sprint 7 ships Stage 1 only; Stages 2 (Rust+CGo ONNX)
// and 3 (LLM judge) are wired through the same interfaces but return
// no-match.
//
// Wire compatibility: the on-the-wire policy shape, the Redis pub/sub
// channel name, and the rule schema MUST match the Python control
// plane's app/policy/compiled.py. Reviewers: if you change a field
// here, change it there too.
package policy

import "time"

// EnforcementLevel matches the Python platform's literal type.
type EnforcementLevel string

const (
	EnforcementFast          EnforcementLevel = "fast"
	EnforcementBalanced      EnforcementLevel = "balanced"
	EnforcementComprehensive EnforcementLevel = "comprehensive"
)

// FailBehavior controls what happens when policy cache is stale.
type FailBehavior string

const (
	FailOpen   FailBehavior = "open"
	FailClosed FailBehavior = "closed"
)

// Action is the final disposition for an inspected request.
type Action string

const (
	ActionAllowed   Action = "allowed"
	ActionBlocked   Action = "blocked"
	ActionModified  Action = "modified"
	ActionFlagged   Action = "flagged"
	ActionEscalated Action = "escalated"
)

// PipelineExitStage records which stage produced the final verdict.
type PipelineExitStage string

const (
	ExitStage1Regex PipelineExitStage = "stage1_regex"
	ExitStage2ML    PipelineExitStage = "stage2_ml"
	ExitStage3Judge PipelineExitStage = "stage3_judge"
	ExitNoMatch     PipelineExitStage = "no_match"
)

// Severity ranks finding criticality. Ordering matters: higher index =
// more severe (see SeverityRank).
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// SeverityRank returns a comparable rank for severity ordering.
func SeverityRank(s Severity) int { return severityRank[s] }

// Direction is whether the payload is going to the model (Inbound) or
// coming back from it (Outbound).
type Direction string

const (
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
)

// Input is the payload being inspected.
type Input struct {
	Text      string
	Direction Direction
	AssetID   string
	SessionID string
	ToolName  string
	ToolArgs  map[string]any
	SourceIP  string
	Timestamp time.Time
}

// StageResult is one stage's verdict on one input.
type StageResult struct {
	Stage      PipelineExitStage
	Matched    bool
	Action     Action
	Severity   Severity
	Category   string
	RuleID     string
	Confidence float64
	Reason     string
	LatencyUS  int64
	Evidence   map[string]any
	// Mode names how the verdict was ACTUALLY computed — the honesty field.
	// e.g. "stage1_regex", "stage2_heuristic", "stage3_deterministic",
	// "stage3_http", or "disabled" (the stage has no real backend and did NOT
	// compute a verdict). Mirrors the Python control-plane (Phase 0.5).
	Mode string
}

// Decision is the orchestrator's combined verdict across stages.
type Decision struct {
	Action            Action
	Severity          Severity
	PipelineExitStage PipelineExitStage
	EnforcementLevel  EnforcementLevel
	MatchedRules      []string
	StageResults      []StageResult
	TotalLatencyUS    int64
	BlockReason       string
}

// Allowed reports whether the request should be forwarded to the target.
func (d Decision) Allowed() bool { return d.Action == ActionAllowed }

// Blocked reports whether the request must be rejected.
func (d Decision) Blocked() bool { return d.Action == ActionBlocked }
