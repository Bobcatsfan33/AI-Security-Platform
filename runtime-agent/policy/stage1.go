package policy

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// Stage1Engine runs the deterministic Stage 1 checks: regex / keyword /
// PII / tool firewall. Stateless and safe to share across goroutines.
type Stage1Engine struct{}

// NewStage1Engine returns a default Stage 1 engine.
func NewStage1Engine() *Stage1Engine { return &Stage1Engine{} }

// Evaluate runs the engine against one input against one policy.
// Returns a StageResult; never errors — Stage 1 always produces a
// verdict (matched / not-matched), and the orchestrator decides what
// the next step is based on policy.EnforcementLevel.
func (e *Stage1Engine) Evaluate(
	_ context.Context, in *Input, p *CompiledPolicy, environment string,
) StageResult {
	start := time.Now()

	// 1. Tool firewall first — applies when the input describes a tool call
	if in.ToolName != "" {
		if r, ok := e.checkToolFirewall(in.ToolName, p); ok {
			return stampLatency(r, start)
		}
	}

	// 2. Walk enabled rules. Block actions short-circuit; otherwise
	//    accumulate and pick the highest-severity match.
	var accumulated []StageResult
	for _, rule := range p.Rules {
		if !rule.Enabled {
			continue
		}
		if environment != "" && len(rule.Environments) > 0 && !contains(rule.Environments, environment) {
			continue
		}

		match, matched := e.matchRule(&rule, in.Text)
		if !matched {
			continue
		}
		if rule.Action == "block" {
			return stampLatency(match, start)
		}
		accumulated = append(accumulated, match)
	}

	if len(accumulated) > 0 {
		chosen := accumulated[0]
		for _, r := range accumulated[1:] {
			if SeverityRank(r.Severity) > SeverityRank(chosen.Severity) {
				chosen = r
			}
		}
		return stampLatency(chosen, start)
	}

	return stampLatency(StageResult{
		Stage:   ExitStage1Regex,
		Matched: false,
		Action:  ActionAllowed,
	}, start)
}

func (e *Stage1Engine) checkToolFirewall(
	toolName string, p *CompiledPolicy,
) (StageResult, bool) {
	if _, ok := p.ToolDenylist[toolName]; ok {
		return StageResult{
			Stage:      ExitStage1Regex,
			Matched:    true,
			Action:     ActionBlocked,
			Severity:   SeverityCritical,
			Category:   "unsafe_tool_use",
			RuleID:     "tool_firewall:denylist",
			Confidence: 1.0,
			Reason:     "tool on denylist: " + toolName,
			Evidence:   map[string]any{"tool_name": toolName},
		}, true
	}
	if _, ok := p.ToolApprovalRequired[toolName]; ok {
		return StageResult{
			Stage:      ExitStage1Regex,
			Matched:    true,
			Action:     ActionEscalated,
			Severity:   SeverityHigh,
			Category:   "unsafe_tool_use",
			RuleID:     "tool_firewall:approval_required",
			Confidence: 1.0,
			Reason:     "tool requires approval: " + toolName,
			Evidence:   map[string]any{"tool_name": toolName},
		}, true
	}
	// Allowlist enforcement: empty allowlist = no enforcement
	if len(p.ToolAllowlist) > 0 {
		if _, ok := p.ToolAllowlist[toolName]; !ok {
			return StageResult{
				Stage:      ExitStage1Regex,
				Matched:    true,
				Action:     ActionBlocked,
				Severity:   SeverityHigh,
				Category:   "unsafe_tool_use",
				RuleID:     "tool_firewall:not_allowlisted",
				Confidence: 1.0,
				Reason:     "tool not on allowlist: " + toolName,
				Evidence:   map[string]any{"tool_name": toolName},
			}, true
		}
	}
	return StageResult{}, false
}

func (e *Stage1Engine) matchRule(rule *CompiledRule, text string) (StageResult, bool) {
	switch rule.Type {
	case "regex":
		for _, pattern := range rule.RegexPatterns {
			if m := pattern.FindStringIndex(text); m != nil {
				return resultFor(rule, map[string]any{
					"matched_text": redactMatch(text[m[0]:m[1]]),
				}), true
			}
		}
	case "keyword":
		lowered := strings.ToLower(text)
		for _, kw := range rule.Keywords {
			if kw != "" && strings.Contains(lowered, kw) {
				return resultFor(rule, map[string]any{"keyword": kw}), true
			}
		}
	case "pii_pattern":
		for _, pattern := range rule.RegexPatterns {
			if m := pattern.FindString(text); m != "" {
				// Credit card regex over-fires; require Luhn
				if isCardPattern(pattern) && !LuhnCheck(m) {
					continue
				}
				return resultFor(rule, map[string]any{"pii_detected": true}), true
			}
		}
	}
	return StageResult{}, false
}

func resultFor(rule *CompiledRule, evidence map[string]any) StageResult {
	return StageResult{
		Stage:      ExitStage1Regex,
		Matched:    true,
		Action:     actionToTaken(rule.Action),
		Severity:   rule.Severity,
		Category:   rule.Category,
		RuleID:     fallback(rule.ID, rule.Name),
		Confidence: 1.0,
		Reason:     "matched " + rule.Type + " rule " + rule.Name,
		Evidence:   evidence,
	}
}

func actionToTaken(action string) Action {
	switch action {
	case "block":
		return ActionBlocked
	case "flag":
		return ActionFlagged
	case "modify":
		return ActionModified
	case "escalate":
		return ActionEscalated
	case "log_only":
		return ActionAllowed
	default:
		return ActionFlagged
	}
}

func redactMatch(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

func isCardPattern(p *regexp.Regexp) bool {
	// Sentinel match against the credit_card pattern.
	return strings.HasPrefix(p.String(), `\b(?:\d[- ]?){12,18}`)
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func fallback(primary, secondary string) string {
	if primary != "" {
		return primary
	}
	return secondary
}

func stampLatency(r StageResult, start time.Time) StageResult {
	r.LatencyUS = time.Since(start).Microseconds()
	return r
}
