package policy

import (
	"context"
	"regexp"
	"time"
)

// HeuristicStage2 is the zero-config inline Stage 2 classifier. It mirrors the
// control plane's app/policy/stage2_heuristic.py: a deterministic lexical /
// structural detector for prompt-injection and jailbreak attempts that runs
// inline with NO model weights, so "balanced"/"comprehensive" enforcement does
// real ML-ish detection out of the box (replacing the old noopStage2{}).
//
// When a trained ONNX model is provisioned, HTTPStage2 (an inference sidecar)
// supersedes this — see stage2_http.go. The heuristic remains the fallback so
// the agent is never stuck at Stage-1-only.
type HeuristicStage2 struct {
	signals []heuristicSignal
}

type heuristicSignal struct {
	re       *regexp.Regexp
	weight   float64
	category string
}

// Compiled once. Weights tuned so a single strong phrase lands in the high
// band (act now) and a single weak/structural signal in the uncertain band
// (escalate to Stage 3) — matching the Python heuristic.
var stage2Signals = []heuristicSignal{
	{regexp.MustCompile(`(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b`), 0.75, "prompt_injection"},
	{regexp.MustCompile(`(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|the\s+above)\b`), 0.7, "prompt_injection"},
	{regexp.MustCompile(`(?i)\byou\s+are\s+now\b`), 0.45, "jailbreak"},
	{regexp.MustCompile(`(?i)\b(?:DAN|do\s+anything\s+now)\b`), 0.7, "jailbreak"},
	{regexp.MustCompile(`(?i)\bdeveloper\s+mode\b`), 0.55, "jailbreak"},
	{regexp.MustCompile(`(?i)\b(?:system|initial)\s+prompt\b`), 0.5, "prompt_injection"},
	{regexp.MustCompile(`(?i)\brepeat\s+(?:the\s+)?(?:text|words|everything)\s+above\b`), 0.6, "prompt_injection"},
	{regexp.MustCompile(`(?i)\bpretend\s+(?:to\s+be|you\s+are)\b`), 0.4, "jailbreak"},
	{regexp.MustCompile(`(?i)\boverride\s+(?:your\s+)?(?:safety|guidelines|rules)\b`), 0.65, "jailbreak"},
	// Structural: a long contiguous base64/hex blob often hides a payload.
	{regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}`), 0.35, "prompt_injection"},
}

// NewHeuristicStage2 returns the zero-config inline classifier.
func NewHeuristicStage2() *HeuristicStage2 {
	return &HeuristicStage2{signals: stage2Signals}
}

// Classify implements Stage2Engine. Returns matched with a calibrated
// confidence; the orchestrator handles routing (high → act, uncertain →
// Stage 3). Allocation-light: no work beyond the regex scans on the hot path.
func (h *HeuristicStage2) Classify(_ context.Context, in *Input, _ *CompiledPolicy) StageResult {
	start := time.Now()
	text := in.Text

	var confidence float64
	hits := 0
	byCategory := map[string]float64{}
	for _, s := range h.signals {
		if s.re.MatchString(text) {
			confidence += s.weight
			hits++
			byCategory[s.category] += s.weight
		}
	}
	if confidence > 1.0 {
		confidence = 1.0
	}
	latency := time.Since(start).Microseconds()

	if hits == 0 {
		return StageResult{
			Stage:     ExitStage2ML,
			Matched:   false,
			Action:    ActionAllowed,
			LatencyUS: latency,
		}
	}

	category := ""
	var best float64
	for c, w := range byCategory {
		if w > best {
			best, category = w, c
		}
	}
	severity := SeverityMedium
	if confidence >= 0.7 {
		severity = SeverityHigh
	}
	return StageResult{
		Stage:      ExitStage2ML,
		Matched:    true,
		Action:     ActionFlagged,
		Severity:   severity,
		Category:   category,
		RuleID:     "heuristic-stage2",
		Confidence: confidence,
		Reason:     "heuristic Stage 2 matched " + category,
		LatencyUS:  latency,
		Evidence:   map[string]any{"signals": hits, "confidence": confidence},
	}
}
