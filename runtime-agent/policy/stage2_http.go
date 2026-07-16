package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// HTTPStage2 is the production inline ML classifier: it calls an ONNX inference
// sidecar over HTTP instead of binding the runtime via CGo. This keeps the Go
// agent a single static binary while the model runs in a co-located sidecar
// (one network hop on localhost). Provision a trained model into the sidecar
// and point Endpoint at it; absent a sidecar, NewHeuristicStage2 is the
// zero-config fallback.
//
// Contract (request → response JSON):
//
//	POST {Endpoint}  {"text": "...", "max_length": 8192}
//	200  {"matched": bool, "confidence": 0.0-1.0, "category": "prompt_injection"}
//
// Fail behaviour follows the policy, exactly as Stage 3 does: a sidecar that
// cannot answer blocks under fail_behavior "closed" and allows under "open"
// (and under a nil policy, which cannot express intent). Either way the result
// carries Mode=ModeStage2Unavailable, so "the model said clean" and "the model
// never answered" are distinguishable downstream — they are different facts,
// and collapsing them is how comprehensive enforcement silently degrades to
// Stage-1-only with nothing in the telemetry to show it.
type HTTPStage2 struct {
	Endpoint  string
	MaxLength int
	client    *http.Client
}

// Mode values for Stage 2. See StageResult.Mode in types.go: Mode names how the
// verdict was ACTUALLY computed, so a non-verdict is never labelled as one.
const (
	// ModeStage2HTTP — the sidecar answered and this is its classification.
	ModeStage2HTTP = "stage2_http"
	// ModeStage2Unavailable — the sidecar did not answer. The Action here comes
	// from the policy's fail behaviour, NOT from the model.
	ModeStage2Unavailable = "stage2_unavailable"
)

type stage2Request struct {
	Text      string `json:"text"`
	MaxLength int    `json:"max_length"`
}

type stage2Response struct {
	Matched    bool    `json:"matched"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
}

// NewHTTPStage2 builds an inference-sidecar classifier with a bounded timeout
// (Stage 2 is on the request hot path — keep it tight; default 150ms).
func NewHTTPStage2(endpoint string, timeout time.Duration) *HTTPStage2 {
	if timeout <= 0 {
		timeout = 150 * time.Millisecond
	}
	return &HTTPStage2{
		Endpoint:  endpoint,
		MaxLength: 8192,
		client:    &http.Client{Timeout: timeout},
	}
}

func (h *HTTPStage2) Classify(ctx context.Context, in *Input, p *CompiledPolicy) StageResult {
	start := time.Now()
	// A nil policy cannot express intent, so it keeps the historical default.
	// The proxy's no-policy-at-all path is decided separately (GAP-003).
	failClosed := p != nil && p.FailBehavior == FailClosed

	body, err := json.Marshal(stage2Request{Text: in.Text, MaxLength: h.MaxLength})
	if err != nil {
		return stage2Fail(start, failClosed, "stage 2 request could not be encoded")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.Endpoint, bytes.NewReader(body))
	if err != nil {
		return stage2Fail(start, failClosed, "stage 2 endpoint is not a valid request target")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return stage2Fail(start, failClosed, "stage 2 classifier unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return stage2Fail(start, failClosed, "stage 2 classifier returned a non-200")
	}

	var out stage2Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return stage2Fail(start, failClosed, "stage 2 classifier returned a malformed response")
	}
	latency := time.Since(start).Microseconds()
	if !out.Matched {
		return StageResult{
			Stage:     ExitStage2ML,
			Mode:      ModeStage2HTTP,
			Matched:   false,
			Action:    ActionAllowed,
			LatencyUS: latency,
		}
	}
	severity := SeverityMedium
	if out.Confidence >= 0.7 {
		severity = SeverityHigh
	}
	category := out.Category
	if category == "" {
		category = "ml_detection"
	}
	return StageResult{
		Stage:      ExitStage2ML,
		Mode:       ModeStage2HTTP,
		Matched:    true,
		Action:     ActionFlagged,
		Severity:   severity,
		Category:   category,
		RuleID:     "onnx-stage2",
		Confidence: out.Confidence,
		Reason:     "ONNX classifier matched " + category,
		LatencyUS:  latency,
	}
}

// stage2Fail is the single exit for "the classifier did not answer". Mirrors
// stage3Fail. The Action reflects the policy's fail behaviour; Mode records
// that no model produced this — so a fail-closed block is never mistaken for a
// detection, and a fail-open allow is never mistaken for a clean bill.
func stage2Fail(start time.Time, failClosed bool, reason string) StageResult {
	if failClosed {
		return StageResult{
			Stage:    ExitStage2ML,
			Mode:     ModeStage2Unavailable,
			Matched:  true,
			Action:   ActionBlocked,
			Severity: SeverityHigh,
			// Deliberately NO RuleID. decide() folds RuleIDs into
			// Decision.MatchedRules — the list of rules that FIRED. A classifier
			// that never answered fired nothing, and naming "onnx-stage2" there
			// would tell an operator the model made a call it never made. The
			// Mode field is where this result explains itself.
			Reason:    reason + "; fail-closed",
			LatencyUS: time.Since(start).Microseconds(),
		}
	}
	return StageResult{
		Stage:     ExitStage2ML,
		Mode:      ModeStage2Unavailable,
		Matched:   false,
		Action:    ActionAllowed,
		Reason:    reason + "; fail-open",
		LatencyUS: time.Since(start).Microseconds(),
	}
}
