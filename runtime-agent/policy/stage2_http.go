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
// Fail-open: any sidecar error returns matched=false so a down/slow model
// never breaks the proxy hot path (the request still gets Stage 1 + Stage 3).
type HTTPStage2 struct {
	Endpoint  string
	MaxLength int
	client    *http.Client
}

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

func (h *HTTPStage2) Classify(ctx context.Context, in *Input, _ *CompiledPolicy) StageResult {
	start := time.Now()
	body, err := json.Marshal(stage2Request{Text: in.Text, MaxLength: h.MaxLength})
	if err != nil {
		return stage2Miss(start)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.Endpoint, bytes.NewReader(body))
	if err != nil {
		return stage2Miss(start)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return stage2Miss(start) // fail-open: sidecar unreachable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return stage2Miss(start)
	}

	var out stage2Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return stage2Miss(start)
	}
	latency := time.Since(start).Microseconds()
	if !out.Matched {
		return StageResult{Stage: ExitStage2ML, Matched: false, Action: ActionAllowed, LatencyUS: latency}
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

func stage2Miss(start time.Time) StageResult {
	return StageResult{
		Stage:     ExitStage2ML,
		Matched:   false,
		Action:    ActionAllowed,
		LatencyUS: time.Since(start).Microseconds(),
	}
}
