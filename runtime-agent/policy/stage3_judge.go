package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"time"
)

// Stage 3 is the slow, expensive arbiter the orchestrator invokes only on
// UNCERTAIN Stage 2 results under "comprehensive" enforcement. Two engines:
//
//   DeterministicStage3 — zero-config default. Confirms only on strong,
//     unambiguous markers, so it can knock down Stage 2's uncertain guesses
//     without a model. Mirrors the control plane's deterministic_judge.
//
//   HTTPStage3 — production: calls the customer's configured LLM-judge
//     endpoint with a bounded timeout and policy-driven fail behavior.

var strongJudgeMarker = regexp.MustCompile(
	`(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b` +
		`|\b(?:DAN|do\s+anything\s+now)\b` +
		`|\boverride\s+(?:your\s+)?(?:safety|guidelines|rules)\b` +
		`|\brepeat\s+(?:the\s+)?(?:text|words|everything)\s+above\b`,
)

// DeterministicStage3 is the zero-config judge.
type DeterministicStage3 struct{}

// NewDeterministicStage3 returns the default judge.
func NewDeterministicStage3() *DeterministicStage3 { return &DeterministicStage3{} }

func (DeterministicStage3) Judge(_ context.Context, in *Input, _ *CompiledPolicy) StageResult {
	start := time.Now()
	if strongJudgeMarker.MatchString(in.Text) {
		return StageResult{
			Stage:      ExitStage3Judge,
			Mode:       "stage3_deterministic",
			Matched:    true,
			Action:     ActionBlocked,
			Severity:   SeverityHigh,
			Category:   "prompt_injection",
			RuleID:     "deterministic-judge",
			Confidence: 0.85,
			Reason:     "judge confirmed strong injection marker",
			LatencyUS:  time.Since(start).Microseconds(),
		}
	}
	return StageResult{Stage: ExitStage3Judge, Mode: "stage3_deterministic", Matched: false, Action: ActionAllowed, LatencyUS: time.Since(start).Microseconds()}
}

// HTTPStage3 calls a configured LLM-judge endpoint.
//
// Contract:
//
//	POST {Endpoint}  {"text": "..."}
//	200  {"is_violation": bool, "confidence": 0.0-1.0, "category": "...", "reason": "..."}
//
// Verdict → action: confidence ≥ 0.8 → blocked; ≥ 0.5 → escalated; else allow.
// On error/timeout the FailBehavior decides: FailOpen → allow (matched=false);
// FailClosed → block (the judge couldn't clear the request).
type HTTPStage3 struct {
	Endpoint string
	client   *http.Client
}

type stage3Request struct {
	Text string `json:"text"`
}

type stage3Response struct {
	IsViolation bool    `json:"is_violation"`
	Confidence  float64 `json:"confidence"`
	Category    string  `json:"category"`
	Reason      string  `json:"reason"`
}

// NewHTTPStage3 builds an LLM-judge engine. Stage 3 is the slow path; default
// timeout is generous (3s) but strictly bounded so it can't hang the proxy.
func NewHTTPStage3(endpoint string, timeout time.Duration) *HTTPStage3 {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &HTTPStage3{Endpoint: endpoint, client: &http.Client{Timeout: timeout}}
}

func (h *HTTPStage3) Judge(ctx context.Context, in *Input, p *CompiledPolicy) StageResult {
	start := time.Now()
	failClosed := p != nil && p.FailBehavior == FailClosed

	body, err := json.Marshal(stage3Request{Text: in.Text})
	if err != nil {
		return stage3Fail(start, failClosed)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.Endpoint, bytes.NewReader(body))
	if err != nil {
		return stage3Fail(start, failClosed)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return stage3Fail(start, failClosed)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return stage3Fail(start, failClosed)
	}
	var out stage3Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return stage3Fail(start, failClosed)
	}

	latency := time.Since(start).Microseconds()
	if !out.IsViolation {
		return StageResult{Stage: ExitStage3Judge, Matched: false, Action: ActionAllowed, Confidence: out.Confidence, LatencyUS: latency}
	}
	action := ActionAllowed
	matched := false
	switch {
	case out.Confidence >= 0.8:
		action, matched = ActionBlocked, true
	case out.Confidence >= 0.5:
		action, matched = ActionEscalated, true
	}
	if !matched {
		return StageResult{Stage: ExitStage3Judge, Matched: false, Action: ActionAllowed, Confidence: out.Confidence, LatencyUS: latency}
	}
	category := out.Category
	if category == "" {
		category = "policy_violation"
	}
	return StageResult{
		Stage:      ExitStage3Judge,
		Matched:    true,
		Action:     action,
		Severity:   SeverityHigh,
		Category:   category,
		RuleID:     "llm-judge",
		Confidence: out.Confidence,
		Reason:     out.Reason,
		LatencyUS:  latency,
	}
}

func stage3Fail(start time.Time, failClosed bool) StageResult {
	if failClosed {
		return StageResult{
			Stage:     ExitStage3Judge,
			Matched:   true,
			Action:    ActionBlocked,
			Severity:  SeverityHigh,
			RuleID:    "llm-judge",
			Reason:    "judge unavailable; fail-closed",
			LatencyUS: time.Since(start).Microseconds(),
		}
	}
	return StageResult{Stage: ExitStage3Judge, Matched: false, Action: ActionAllowed, LatencyUS: time.Since(start).Microseconds()}
}
