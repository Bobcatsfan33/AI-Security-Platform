package policy

import (
	"context"
	"time"
)

// Stage2Engine runs the inline ML classifier (heuristic by default; ONNX
// sidecar when provisioned — see stage2_heuristic.go / stage2_http.go).
type Stage2Engine interface {
	Classify(ctx context.Context, in *Input, p *CompiledPolicy) StageResult
}

// Stage3Engine is the LLM judge for uncertain Stage 2 results (deterministic
// by default; HTTP LLM-judge when configured — see stage3_judge.go).
type Stage3Engine interface {
	Judge(ctx context.Context, in *Input, p *CompiledPolicy) StageResult
}

// noopStage2 / noopStage3 — explicit "off" engines, kept for fast-only
// deployments and tests that want Stage-1-only behaviour.
type noopStage2 struct{}

func (noopStage2) Classify(_ context.Context, _ *Input, _ *CompiledPolicy) StageResult {
	return StageResult{Stage: ExitStage2ML, Mode: "disabled", Matched: false, Action: ActionAllowed}
}

// noopStage3 is the honest "no judge configured" engine (Phase 0.5): it reports
// Mode "disabled" and computes nothing — it must NOT run a regex stand-in and
// emit a verdict labelled as a judge ruling.
type noopStage3 struct{}

func (noopStage3) Judge(_ context.Context, _ *Input, _ *CompiledPolicy) StageResult {
	return StageResult{Stage: ExitStage3Judge, Mode: "disabled", Matched: false, Action: ActionAllowed}
}

// StageConfig configures the inline Stage 2/3 backends. When an endpoint is
// set the HTTP-backed engine (ONNX sidecar / LLM judge) is used; otherwise the
// zero-config heuristic / deterministic engine runs inline.
type StageConfig struct {
	Stage2Endpoint string // ONNX inference sidecar URL ("" → heuristic/suite)
	Stage2Timeout  time.Duration
	Stage3Endpoint string // LLM-judge URL ("" → deterministic)
	Stage3Timeout  time.Duration
	// UseDetectorSuite selects the full AI Guard 18-detector CompositeStage2
	// (detector suite ⊕ tuned heuristic) inline, instead of the bare
	// heuristic. Ignored when Stage2Endpoint is set (ONNX wins).
	UseDetectorSuite bool
}

// Pipeline orchestrates Stage 1 → 2 → 3 based on enforcement_level
// and confidence routing. Constructed once at agent startup; safe for
// concurrent use.
type Pipeline struct {
	Stage1 *Stage1Engine
	Stage2 Stage2Engine
	Stage3 Stage3Engine
}

// NewDefaultPipeline wires the zero-config inline engines: Stage 1 (regex/PII)
// + Stage 2 (heuristic) run live; Stage 3 is DISABLED until a judge endpoint
// is configured (Phase 0.5 honesty — no hidden-regex verdict). Callers that
// genuinely want the dependency-free second opinion set Stage3 =
// NewDeterministicStage3() explicitly (reported as "stage3_deterministic").
func NewDefaultPipeline() *Pipeline {
	return &Pipeline{
		Stage1: NewStage1Engine(),
		Stage2: NewHeuristicStage2(),
		Stage3: noopStage3{},
	}
}

// NewPipeline wires the inline pipeline per StageConfig: an HTTP ONNX sidecar /
// LLM judge when an endpoint is configured, else the zero-config heuristic /
// deterministic engine. This is what the agent constructs at startup.
func NewPipeline(cfg StageConfig) *Pipeline {
	var s2 Stage2Engine = NewHeuristicStage2()
	switch {
	case cfg.Stage2Endpoint != "":
		s2 = NewHTTPStage2(cfg.Stage2Endpoint, cfg.Stage2Timeout) // ONNX sidecar wins
	case cfg.UseDetectorSuite:
		s2 = NewCompositeStage2() // full AI Guard detector breadth, inline
	}
	// No judge endpoint → Stage 3 DISABLED (honest), not a hidden-regex verdict.
	var s3 Stage3Engine = noopStage3{}
	if cfg.Stage3Endpoint != "" {
		s3 = NewHTTPStage3(cfg.Stage3Endpoint, cfg.Stage3Timeout)
	}
	return &Pipeline{Stage1: NewStage1Engine(), Stage2: s2, Stage3: s3}
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

		// Stage 2 could not answer, so fail_behavior decided — not the model.
		// Exit explicitly: a fail-closed result carries no Confidence, so it
		// fails both gates below and would otherwise fall through to
		// ExitNoMatch, reaching the proxy only because decide()'s
		// max-actionRank fold happens to pick a blocked result up. A block that
		// survives by accident and reports "no_match" is a non-verdict wearing
		// a verdict's label.
		//
		// Fail-open exits here too: the request is allowed either way (Matched
		// is false, so the gates below could not fire), but "allowed because
		// the model was down" and "allowed because the model found nothing" are
		// different facts and only this label distinguishes them.
		if s2.Mode == ModeStage2Unavailable {
			return decide(results, policy, ExitStage2Unavailable, start)
		}

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
