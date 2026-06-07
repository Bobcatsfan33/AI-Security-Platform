package policy

import "context"

// CompositeStage2 runs the AI Guard detector suite and the legacy heuristic
// and returns whichever produced the stronger verdict. This gives the inline
// agent the full detector breadth while preserving the tuned heuristic's
// prompt-injection/jailbreak confidence calibration. Selected via
// StageConfig.UseDetectorSuite.
type CompositeStage2 struct {
	suite     *DetectorSuiteStage2
	heuristic *HeuristicStage2
}

// NewCompositeStage2 builds the composite engine.
func NewCompositeStage2() *CompositeStage2 {
	return &CompositeStage2{suite: NewDetectorSuiteStage2(), heuristic: NewHeuristicStage2()}
}

// Classify implements Stage2Engine.
func (c *CompositeStage2) Classify(ctx context.Context, in *Input, p *CompiledPolicy) StageResult {
	a := c.suite.Classify(ctx, in, p)
	b := c.heuristic.Classify(ctx, in, p)
	// Prefer a blocking match; otherwise the higher-confidence matched result.
	switch {
	case a.Matched && a.Action == ActionBlocked:
		return a
	case b.Matched && b.Action == ActionBlocked:
		return b
	case a.Matched && b.Matched:
		if a.Confidence >= b.Confidence {
			return a
		}
		return b
	case a.Matched:
		return a
	default:
		return b
	}
}
