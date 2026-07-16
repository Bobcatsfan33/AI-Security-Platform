package policy

import (
	"context"
	"testing"
	"time"
)

// A Stage 2 that cannot answer must exit the pipeline HONESTLY.
//
// Before this, stage2Fail returned Matched:true/ActionBlocked with no
// Confidence. That fails both confidence gates in Evaluate (0 >= threshold is
// false), so it fell through to `decide(results, policy, ExitNoMatch, start)`.
// The block only survived because decide()'s max-actionRank fold happened to
// pick the blocked result up — and the Decision shipped
// PipelineExitStage:"no_match" on a blocked request, plus RuleID "onnx-stage2"
// in MatchedRules for a model that never ran.
//
// That is a non-verdict labelled as a verdict: the exact thing the Mode field
// exists to prevent, arrived at from the other direction. A fail-closed block
// is a real decision and must say so; it must not depend on an incidental fold
// to reach the proxy at all.

func unavailableStage2Policy(fb FailBehavior, level EnforcementLevel) *CompiledPolicy {
	return &CompiledPolicy{
		FailBehavior:              fb,
		EnforcementLevel:          level,
		MLConfidenceThresholdLow:  0.4,
		MLConfidenceThresholdHigh: 0.8,
	}
}

// pipelineWithDownStage2 wires a real HTTPStage2 pointed at a dead port, so the
// unavailable path is exercised end to end rather than faked.
func pipelineWithDownStage2() *Pipeline {
	p := NewPipeline(StageConfig{})
	p.Stage2 = NewHTTPStage2("http://127.0.0.1:0", 20*time.Millisecond)
	return p
}

func TestPipelineStage2UnavailableFailClosedExitsExplicitly(t *testing.T) {
	d := pipelineWithDownStage2().Evaluate(
		context.Background(),
		&Input{Text: "hello"},
		unavailableStage2Policy(FailClosed, EnforcementBalanced),
		"production",
	)

	if !d.Blocked() {
		t.Fatalf("fail-closed with a down sidecar must block, got action=%q", d.Action)
	}
	if d.PipelineExitStage != ExitStage2Unavailable {
		t.Errorf("PipelineExitStage = %q, want %q — a blocked request must not be "+
			"labelled %q", d.PipelineExitStage, ExitStage2Unavailable, ExitNoMatch)
	}
	if d.BlockReason == "" {
		t.Error("a block must carry a reason an operator can act on")
	}
}

// TestPipelineStage2UnavailableEmitsNoMatchedRule — MatchedRules is the list of
// rules that FIRED. A classifier that never answered fired nothing; naming
// "onnx-stage2" there would tell an operator the model made a call it never
// made.
func TestPipelineStage2UnavailableEmitsNoMatchedRule(t *testing.T) {
	d := pipelineWithDownStage2().Evaluate(
		context.Background(),
		&Input{Text: "hello"},
		unavailableStage2Policy(FailClosed, EnforcementBalanced),
		"production",
	)

	for _, rule := range d.MatchedRules {
		if rule == "onnx-stage2" {
			t.Errorf("MatchedRules = %v — a backend that never answered must not "+
				"appear as a matched rule", d.MatchedRules)
		}
	}
}

func TestPipelineStage2UnavailableFailOpenAllowsAndSaysSo(t *testing.T) {
	d := pipelineWithDownStage2().Evaluate(
		context.Background(),
		&Input{Text: "hello"},
		unavailableStage2Policy(FailOpen, EnforcementBalanced),
		"production",
	)

	if !d.Allowed() {
		t.Fatalf("fail-open with a down sidecar must allow, got action=%q", d.Action)
	}
	if d.PipelineExitStage != ExitStage2Unavailable {
		t.Errorf("PipelineExitStage = %q, want %q — allowing because the model was "+
			"down is not the same fact as allowing because it found nothing, and "+
			"%q cannot tell them apart",
			d.PipelineExitStage, ExitStage2Unavailable, ExitNoMatch)
	}
}

// TestPipelineStage2UnavailableCarriesTheHonestyMode — the stage result the
// proxy ships as telemetry must still say HOW the verdict was reached.
func TestPipelineStage2UnavailableCarriesTheHonestyMode(t *testing.T) {
	for _, fb := range []FailBehavior{FailClosed, FailOpen} {
		d := pipelineWithDownStage2().Evaluate(
			context.Background(),
			&Input{Text: "hello"},
			unavailableStage2Policy(fb, EnforcementBalanced),
			"production",
		)

		var found bool
		for _, r := range d.StageResults {
			if r.Stage == ExitStage2ML {
				found = true
				if r.Mode != ModeStage2Unavailable {
					t.Errorf("fail_behavior=%v: stage result Mode = %q, want %q",
						fb, r.Mode, ModeStage2Unavailable)
				}
			}
		}
		if !found {
			t.Errorf("fail_behavior=%v: no Stage 2 result in StageResults — the "+
				"telemetry must show the stage ran and could not answer", fb)
		}
	}
}

// TestPipelineStage2UnavailableIsNotReachedAtFastEnforcement — Stage 2 does
// not run at `fast`, so a down sidecar must not block there. Fail-closed
// applies to stages the policy actually asked for.
func TestPipelineStage2UnavailableIsNotReachedAtFastEnforcement(t *testing.T) {
	d := pipelineWithDownStage2().Evaluate(
		context.Background(),
		&Input{Text: "hello"},
		unavailableStage2Policy(FailClosed, EnforcementFast),
		"production",
	)

	if d.Blocked() {
		t.Errorf("fast enforcement does not run Stage 2, so a down sidecar must "+
			"not block: exit=%q action=%q", d.PipelineExitStage, d.Action)
	}
}

// TestPipelineHealthyStage2StillExitsNormally — the unavailable path must not
// swallow real classifications.
func TestPipelineHealthyStage2StillExitsNormally(t *testing.T) {
	d := NewPipeline(StageConfig{}).Evaluate(
		context.Background(),
		&Input{Text: "hello, how are you"},
		unavailableStage2Policy(FailClosed, EnforcementBalanced),
		"production",
	)

	if d.PipelineExitStage == ExitStage2Unavailable {
		t.Errorf("the default heuristic Stage 2 is always available; exit must not "+
			"be %q", ExitStage2Unavailable)
	}
	if d.Blocked() {
		t.Errorf("benign text with a working Stage 2 must not block, got %+v", d)
	}
}
