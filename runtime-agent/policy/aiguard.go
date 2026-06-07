package policy

import (
	"context"
	"fmt"
	"time"
)

// AIGuard runs the detector suite with per-detector sliding thresholds and
// produces an Allow | Block | Detect decision. It is the inline analogue of
// the control plane's app/aiguard/service.py.

// AGAction is the flat response action.
type AGAction string

const (
	AGAllow  AGAction = "allow"
	AGBlock  AGAction = "block"
	AGDetect AGAction = "detect"
)

// DetectorOutcome is one detector's contribution to the decision.
type DetectorOutcome struct {
	Name       string
	Category   string
	Confidence float64
	Threshold  float64
	Triggered  bool
	Action     string // block | detect | off
	Severity   Severity
}

// AIGuardResponse is the flat response body.
type AIGuardResponse struct {
	Action    AGAction
	Direction Direction
	Triggered []string
	Detectors []DetectorOutcome
	LatencyMS float64
	Reason    string
}

// AIGuard holds the detector catalogue.
type AIGuard struct {
	detectors []Detector
}

// NewAIGuard builds the guard with the full detector catalogue.
func NewAIGuard() *AIGuard { return &AIGuard{detectors: allDetectorsList()} }

func defaultAction(d Detector) string {
	if d.Severity == SeverityHigh || d.Severity == SeverityCritical {
		return "block"
	}
	return "detect"
}

// Inspect runs all applicable, enabled detectors and returns the verdict.
// cfg maps detector name -> {"threshold": float64, "action": string}.
func (g *AIGuard) Inspect(text string, dir Direction, cfg map[string]map[string]any, ctx DetectorContext) AIGuardResponse {
	ctx.Direction = dir
	start := time.Now()
	outcomes := make([]DetectorOutcome, 0, len(g.detectors))
	triggered := []string{}
	var worstBlock *DetectorOutcome

	for _, det := range g.detectors {
		c := cfg[det.Name]
		action := defaultAction(det)
		threshold := det.DefaultThreshold
		if c != nil {
			if a, ok := c["action"].(string); ok && a != "" {
				action = a
			}
			if t, ok := asFloat(c["threshold"]); ok {
				threshold = t
			}
		}
		if action == "off" {
			continue
		}
		if !det.Applies(dir) {
			continue
		}
		r := det.Detect(text, ctx)
		isTrig := r.Confidence >= threshold && r.Confidence > 0
		oc := DetectorOutcome{
			Name: r.Name, Category: r.Category, Confidence: r.Confidence,
			Threshold: threshold, Triggered: isTrig, Action: action, Severity: r.Severity,
		}
		outcomes = append(outcomes, oc)
		if isTrig {
			triggered = append(triggered, r.Name)
			if action == "block" && (worstBlock == nil || oc.Confidence > worstBlock.Confidence) {
				v := oc
				worstBlock = &v
			}
		}
	}

	var action AGAction
	var reason string
	switch {
	case worstBlock != nil:
		action = AGBlock
		reason = fmt.Sprintf("%s (%.2f) >= %.2f", worstBlock.Name, worstBlock.Confidence, worstBlock.Threshold)
	case len(triggered) > 0:
		action = AGDetect
		reason = fmt.Sprintf("%d detector(s) flagged", len(triggered))
	default:
		action = AGAllow
		reason = "no detectors triggered"
	}

	return AIGuardResponse{
		Action: action, Direction: dir, Triggered: triggered, Detectors: outcomes,
		LatencyMS: float64(time.Since(start).Microseconds()) / 1000.0, Reason: reason,
	}
}

func asFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}

// ───────────────────────────── Stage 2 adapter

// DetectorSuiteStage2 adapts the AI Guard detector suite to the Stage2Engine
// interface so the full detector breadth enforces inline in the pipeline.
// Per-detector config is read from policy.ContentFilters["detectors"]; topic/
// brand/competitor/language context from the same ContentFilters bag.
type DetectorSuiteStage2 struct {
	guard *AIGuard
}

// NewDetectorSuiteStage2 builds the adapter.
func NewDetectorSuiteStage2() *DetectorSuiteStage2 {
	return &DetectorSuiteStage2{guard: NewAIGuard()}
}

// Classify implements Stage2Engine.
func (s *DetectorSuiteStage2) Classify(_ context.Context, in *Input, p *CompiledPolicy) StageResult {
	start := time.Now()
	cfg, ctx := parseContentFilters(p)
	resp := s.guard.Inspect(in.Text, in.Direction, cfg, ctx)
	latency := time.Since(start).Microseconds()

	if resp.Action == AGAllow {
		return StageResult{Stage: ExitStage2ML, Matched: false, Action: ActionAllowed, LatencyUS: latency}
	}
	// characterize by the strongest triggered detector
	var top *DetectorOutcome
	for i := range resp.Detectors {
		d := &resp.Detectors[i]
		if d.Triggered && (top == nil || d.Confidence > top.Confidence) {
			top = d
		}
	}
	action := ActionFlagged
	if resp.Action == AGBlock {
		action = ActionBlocked
	}
	sr := StageResult{
		Stage: ExitStage2ML, Matched: true, Action: action, LatencyUS: latency,
		Reason: resp.Reason, Evidence: map[string]any{"triggered": resp.Triggered},
	}
	if top != nil {
		sr.Severity = top.Severity
		sr.Category = top.Category
		sr.RuleID = "detector:" + top.Name
		sr.Confidence = top.Confidence
	}
	return sr
}

func parseContentFilters(p *CompiledPolicy) (map[string]map[string]any, DetectorContext) {
	cfg := map[string]map[string]any{}
	ctx := DetectorContext{}
	if p == nil || p.ContentFilters == nil {
		return cfg, ctx
	}
	cf := p.ContentFilters
	if raw, ok := cf["detectors"].(map[string]any); ok {
		for name, v := range raw {
			if m, ok := v.(map[string]any); ok {
				cfg[name] = m
			}
		}
	}
	ctx.AllowedTopics = toStringSlice(cf["allowed_topics"])
	ctx.CompetitorTerms = toStringSlice(cf["competitor_terms"])
	ctx.BrandTerms = toStringSlice(cf["brand_terms"])
	ctx.AllowedLanguages = toStringSlice(cf["allowed_languages"])
	return cfg, ctx
}

func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
