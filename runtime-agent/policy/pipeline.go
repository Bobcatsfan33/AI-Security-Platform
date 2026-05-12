package policy

import (
	"context"
	"time"
)

// Stage2Engine runs the ONNX classifier. Sprint 7 follow-on; currently
// a no-op stub.
type Stage2Engine interface {
	Classify(ctx context.Context, in *Input, p *CompiledPolicy) StageResult
}

// Stage3Engine calls the customer's LLM judge endpoint. Sprint 7
// follow-on; currently a no-op stub.
type Stage3Engine interface {
	Judge(ctx context.Context, in *Input, p *CompiledPolicy) StageResult
}

type noopStage2 struct{}

func (noopStage2) Classify(_ context.Context, _ *Input, _ *CompiledPolicy) StageResult {
	return StageResult{Stage: ExitStage2ML, Matched: false, Action: ActionAllowed}
}

type noopStage3 struct{}

func (noopStage3) Judge(_ context.Context, _ *Input, _ *CompiledPolicy) StageResult {
	return StageResult{Stage: ExitStage3Judge, Matched: false, Action: ActionAllowed}
}

// Pipeline orchestrates Stage 1 → 2 → 3 based on enforcement_level
// and confidence routing. Constructed once at agent startup; safe for
// concurrent use.
type Pipeline struct {
	Stage1 *Stage1Engine
	Stage2 Stage2Engine
	Stage3 Stage3Engine
}

// NewDefaultPipeline wires Stage 1 (real) + no-op Stages 2/3. Sprint 7
// follow-on will swap in the real Stage 2 + 3.
func NewDefaultPipeline() *Pipeline {
	return &Pipeline{
		Stage1: NewStage1Engine(),
		Stage2: noopStage2{},
		Stage3: noopStage3{},
	}
}

// Evaluate runs the pipeline against one input. Returns a Decision the
// proxy uses to allow / block / modify the forwarded request.
func (p *Pipeline) Evaluate(
	ctx context.Context, in *Input, policy *CompiledPolicy, environment string,
) Decision {
	start := time.Now()
	var results []StageResult

	s1 := p.Stage1.Evaluate(ctx, in, policy, environment)
	results = append(results, s1)
	if s1.Matched && s1.Action == ActionBlocked {
		return decide(results, policy, ExitStage1Regex, start)
	}

	if policy.EnforcementLevel == EnforcementBalanced ||
		policy.EnforcementLevel == EnforcementComprehensive {
		s2 := p.Stage2.Classify(ctx, in, policy)
		results = append(results, s2)
		if s2.Matched && s2.Confidence >= policy.MLConfidenceThresholdHigh {
			return decide(results, policy, ExitStage2ML, start)
		}
		uncertain := s2.Matched &&
			s2.Confidence >= policy.MLConfidenceThresholdLow &&
			s2.Confidence < policy.MLConfidenceThresholdHigh
		if uncertain && policy.EnforcementLevel == EnforcementComprehensive {
			s3 := p.Stage3.Judge(ctx, in, policy)
			results = append(results, s3)
			if s3.Matched {
				return decide(results, policy, ExitStage3Judge, start)
			}
		}
	}

	return decide(results, policy, ExitNoMatch, start)
}

func decide(
	results []StageResult, policy *CompiledPolicy,
	exit PipelineExitStage, start time.Time,
) Decision {
	var matched []StageResult
	for _, r := range results {
		if r.Matched {
			matched = append(matched, r)
		}
	}

	action := ActionAllowed
	severity := SeverityInfo
	blockReason := ""

	if len(matched) > 0 {
		chosen := matched[0]
		for _, r := range matched[1:] {
			if actionRank(r.Action) > actionRank(chosen.Action) {
				chosen = r
			}
		}
		action = chosen.Action
		severity = chosen.Severity
		if action == ActionBlocked {
			blockReason = chosen.Reason
		}
	}

	rules := make([]string, 0, len(matched))
	for _, r := range matched {
		if r.RuleID != "" {
			rules = append(rules, r.RuleID)
		}
	}

	return Decision{
		Action:            action,
		Severity:          severity,
		PipelineExitStage: exit,
		EnforcementLevel:  policy.EnforcementLevel,
		MatchedRules:      rules,
		StageResults:      results,
		TotalLatencyUS:    time.Since(start).Microseconds(),
		BlockReason:       blockReason,
	}
}

func actionRank(a Action) int {
	switch a {
	case ActionBlocked:
		return 4
	case ActionEscalated:
		return 3
	case ActionModified:
		return 2
	case ActionFlagged:
		return 1
	default:
		return 0
	}
}
