package policy

import (
	"context"
	"encoding/json"
	"testing"
)

// stubStage2 returns a configurable Stage 2 result.
type stubStage2 struct {
	matched    bool
	confidence float64
}

func (s stubStage2) Classify(_ context.Context, _ *Input, _ *CompiledPolicy) StageResult {
	return StageResult{
		Stage:      ExitStage2ML,
		Matched:    s.matched,
		Action:     ActionBlocked,
		Severity:   SeverityHigh,
		Confidence: s.confidence,
		RuleID:     "stage2",
	}
}

type stubStage3 struct {
	matched bool
	called  *bool
}

func (s stubStage3) Judge(_ context.Context, _ *Input, _ *CompiledPolicy) StageResult {
	if s.called != nil {
		*s.called = true
	}
	return StageResult{
		Stage:    ExitStage3Judge,
		Matched:  s.matched,
		Action:   ActionBlocked,
		Severity: SeverityHigh,
	}
}

func compileWithLevel(t *testing.T, level string) *CompiledPolicy {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"id":                              "p",
		"org_id":                          "org",
		"version":                         1,
		"enforcement_level":               level,
		"fail_behavior":                   "open",
		"ml_confidence_threshold_high":    0.7,
		"ml_confidence_threshold_low":     0.3,
	})
	p, err := CompileFromJSON(raw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

func TestPipelineFastMode(t *testing.T) {
	p := compileWithLevel(t, "fast")
	stage3Called := false
	pipeline := &Pipeline{
		Stage1: NewStage1Engine(),
		Stage2: stubStage2{matched: true, confidence: 1.0},
		Stage3: stubStage3{called: &stage3Called},
	}
	d := pipeline.Evaluate(
		context.Background(),
		&Input{Text: "hi", Direction: DirectionInbound},
		p,
		"",
	)
	if d.Action != ActionAllowed {
		t.Errorf("expected allowed; got %v", d.Action)
	}
	if d.PipelineExitStage != ExitNoMatch {
		t.Errorf("expected no_match exit; got %v", d.PipelineExitStage)
	}
	if stage3Called {
		t.Error("stage3 was called in fast mode")
	}
}

func TestPipelineBalancedHighConfidence(t *testing.T) {
	p := compileWithLevel(t, "balanced")
	stage3Called := false
	pipeline := &Pipeline{
		Stage1: NewStage1Engine(),
		Stage2: stubStage2{matched: true, confidence: 0.95},
		Stage3: stubStage3{called: &stage3Called},
	}
	d := pipeline.Evaluate(
		context.Background(),
		&Input{Text: "hi", Direction: DirectionInbound},
		p,
		"",
	)
	if d.PipelineExitStage != ExitStage2ML {
		t.Errorf("expected stage2_ml exit; got %v", d.PipelineExitStage)
	}
	if d.Action != ActionBlocked {
		t.Errorf("expected blocked; got %v", d.Action)
	}
	if stage3Called {
		t.Error("stage3 was called when stage2 was high-confidence")
	}
}

func TestPipelineComprehensiveUncertainEscalates(t *testing.T) {
	p := compileWithLevel(t, "comprehensive")
	stage3Called := false
	pipeline := &Pipeline{
		Stage1: NewStage1Engine(),
		Stage2: stubStage2{matched: true, confidence: 0.5}, // uncertain band
		Stage3: stubStage3{matched: true, called: &stage3Called},
	}
	d := pipeline.Evaluate(
		context.Background(),
		&Input{Text: "hi", Direction: DirectionInbound},
		p,
		"",
	)
	if !stage3Called {
		t.Error("stage3 was not called for uncertain stage2 in comprehensive mode")
	}
	if d.PipelineExitStage != ExitStage3Judge {
		t.Errorf("expected stage3_judge exit; got %v", d.PipelineExitStage)
	}
}

func TestPipelineBalancedUncertainDoesNotEscalate(t *testing.T) {
	p := compileWithLevel(t, "balanced")
	stage3Called := false
	pipeline := &Pipeline{
		Stage1: NewStage1Engine(),
		Stage2: stubStage2{matched: true, confidence: 0.5},
		Stage3: stubStage3{called: &stage3Called},
	}
	pipeline.Evaluate(
		context.Background(),
		&Input{Text: "hi", Direction: DirectionInbound},
		p,
		"",
	)
	if stage3Called {
		t.Error("stage3 was called in balanced mode")
	}
}

func TestPipelineLatencyRecorded(t *testing.T) {
	p := compileWithLevel(t, "fast")
	pipeline := NewDefaultPipeline()
	d := pipeline.Evaluate(
		context.Background(),
		&Input{Text: "anything", Direction: DirectionInbound},
		p,
		"",
	)
	if d.TotalLatencyUS < 0 {
		t.Errorf("negative latency: %d", d.TotalLatencyUS)
	}
}
