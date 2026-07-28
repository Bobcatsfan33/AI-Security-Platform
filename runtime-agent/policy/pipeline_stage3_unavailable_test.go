package policy

import (
	"context"
	"testing"
	"time"
)

// A Stage 3 that cannot answer must exit the pipeline HONESTLY, mirroring
// pipeline_stage2_unavailable_test.go. Before this, a fail-closed judge exited
// ExitStage3Judge (a non-verdict wearing a real ruling's exit label) and a
// fail-open judge fell through to ExitNoMatch (a fail-open allow labelled "the
// judge found nothing") — the two mislabelings the Stage-2 fix eliminated,
// reproduced one stage over. The explicit ExitStage3Unavailable, taken for BOTH
// behaviours, removes them.

// uncertainStage2 forces the pipeline to consult Stage 3: matched with a
// confidence between the low/high thresholds is the "uncertain" band. Its action
// is Allowed so it does not itself dominate the decision — we are testing what
// Stage 3's unavailability does, not Stage 2's verdict.
type uncertainStage2 struct{}

func (uncertainStage2) Classify(context.Context, *Input, *CompiledPolicy) StageResult {
	return StageResult{Stage: ExitStage2ML, Mode: ModeStage2HTTP, Matched: true, Action: ActionAllowed, Confidence: 0.5}
}

func comprehensivePolicy(fb FailBehavior) *CompiledPolicy {
	return &CompiledPolicy{
		FailBehavior:              fb,
		EnforcementLevel:          EnforcementComprehensive,
		MLConfidenceThresholdLow:  0.4,
		MLConfidenceThresholdHigh: 0.8,
	}
}

// pipelineWithDownStage3 wires an uncertain Stage 2 (to reach Stage 3) and a
// real HTTPStage3 pointed at a dead port, so the unavailable path is exercised
// end to end rather than faked.
func pipelineWithDownStage3() *Pipeline {
	return &Pipeline{
		Stage1: NewStage1Engine(),
		Stage2: uncertainStage2{},
		Stage3: NewHTTPStage3("http://127.0.0.1:0", 20*time.Millisecond),
	}
}

func TestPipelineStage3UnavailableFailClosedExitsExplicitly(t *testing.T) {
	d := pipelineWithDownStage3().Evaluate(
		context.Background(), &Input{Text: "hello"}, comprehensivePolicy(FailClosed), "production",
	)
	if !d.Blocked() {
		t.Fatalf("fail-closed with a down judge must block, got action=%q", d.Action)
	}
	if d.PipelineExitStage != ExitStage3Unavailable {
		t.Errorf("PipelineExitStage = %q, want %q — a fail-closed block must not wear the real-ruling label %q",
			d.PipelineExitStage, ExitStage3Unavailable, ExitStage3Judge)
	}
	if d.BlockReason == "" {
		t.Error("a block must carry a reason an operator can act on")
	}
}

func TestPipelineStage3UnavailableFailOpenExitsExplicitly(t *testing.T) {
	d := pipelineWithDownStage3().Evaluate(
		context.Background(), &Input{Text: "hello"}, comprehensivePolicy(FailOpen), "production",
	)
	if d.Blocked() {
		t.Fatalf("fail-open with a down judge must allow, got action=%q", d.Action)
	}
	if d.PipelineExitStage != ExitStage3Unavailable {
		t.Errorf("PipelineExitStage = %q, want %q — a fail-open allow must not fall through to %q",
			d.PipelineExitStage, ExitStage3Unavailable, ExitNoMatch)
	}
}

func TestPipelineStage3UnavailableEmitsNoJudgeRule(t *testing.T) {
	// MatchedRules is the rules that FIRED. A judge that never answered fired
	// nothing; "llm-judge" there would claim a ruling it never made.
	d := pipelineWithDownStage3().Evaluate(
		context.Background(), &Input{Text: "hello"}, comprehensivePolicy(FailClosed), "production",
	)
	for _, r := range d.MatchedRules {
		if r == "llm-judge" {
			t.Errorf("MatchedRules contains %q for a judge that never answered: %v", "llm-judge", d.MatchedRules)
		}
	}
}

// TestStage3TimeoutStillExitsUnavailable — a timeout (not just an unreachable
// port) also produces the explicit exit; the failure mode must not matter.
func TestStage3TimeoutStillExitsUnavailable(t *testing.T) {
	p := &Pipeline{Stage1: NewStage1Engine(), Stage2: uncertainStage2{},
		Stage3: NewHTTPStage3("http://127.0.0.1:0", 1*time.Millisecond)}
	d := p.Evaluate(context.Background(), &Input{Text: "hello"}, comprehensivePolicy(FailClosed), "production")
	if d.PipelineExitStage != ExitStage3Unavailable {
		t.Errorf("PipelineExitStage = %q, want %q", d.PipelineExitStage, ExitStage3Unavailable)
	}
}
