package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// CompiledRule mirrors backend/app/policy/compiled.py::CompiledRule.
// Regex patterns are pre-compiled at unmarshal time so the hot path
// never re-compiles.
type CompiledRule struct {
	ID            string
	Name          string
	Type          string // "regex" | "keyword" | "pii_pattern" | "tool_firewall" | ...
	Category      string
	Severity      Severity
	Action        string // "block" | "flag" | "modify" | "escalate" | "log_only"
	Enabled       bool
	Environments  []string
	RegexPatterns []*regexp.Regexp
	Keywords      []string
	Threshold     float64
	Config        map[string]any
}

// CompiledPolicy is the read-only, allocation-free hot-path snapshot
// loaded from the control plane and refreshed via Redis pub/sub.
type CompiledPolicy struct {
	PolicyID                  string
	OrgID                     string
	Version                   int
	EnforcementLevel          EnforcementLevel
	FailBehavior              FailBehavior
	MLConfidenceThresholdHigh float64
	MLConfidenceThresholdLow  float64
	Rules                     []CompiledRule
	ToolAllowlist             map[string]struct{}
	ToolDenylist              map[string]struct{}
	ToolApprovalRequired      map[string]struct{}
	RateLimits                map[string]any
	ContentFilters            map[string]any
}

// rawPolicy is the JSON shape returned by the Python control plane's
// GET /v1/policies/{id} endpoint. Field names match exactly.
type rawPolicy struct {
	ID                        string           `json:"id"`
	OrgID                     string           `json:"org_id"`
	Version                   int              `json:"version"`
	EnforcementLevel          string           `json:"enforcement_level"`
	FailBehavior              string           `json:"fail_behavior"`
	MLConfidenceThresholdHigh float64          `json:"ml_confidence_threshold_high"`
	MLConfidenceThresholdLow  float64          `json:"ml_confidence_threshold_low"`
	Rules                     []map[string]any `json:"rules"`
	ToolAllowlist             []string         `json:"tool_allowlist"`
	ToolDenylist              []string         `json:"tool_denylist"`
	ToolApprovalRequired      []string         `json:"tool_approval_required"`
	RateLimits                map[string]any   `json:"rate_limits"`
	ContentFilters            map[string]any   `json:"content_filters"`
}

// CompileFromJSON parses a control-plane policy response into a
// CompiledPolicy, pre-compiling regex patterns. Errors include the
// rule ID so operators can diagnose malformed configs.
func CompileFromJSON(data []byte) (*CompiledPolicy, error) {
	var raw rawPolicy
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("policy unmarshal: %w", err)
	}
	rules, err := compileRules(raw.Rules)
	if err != nil {
		return nil, err
	}
	return &CompiledPolicy{
		PolicyID:                  raw.ID,
		OrgID:                     raw.OrgID,
		Version:                   raw.Version,
		EnforcementLevel:          EnforcementLevel(raw.EnforcementLevel),
		FailBehavior:              FailBehavior(raw.FailBehavior),
		MLConfidenceThresholdHigh: raw.MLConfidenceThresholdHigh,
		MLConfidenceThresholdLow:  raw.MLConfidenceThresholdLow,
		Rules:                     rules,
		ToolAllowlist:             toSet(raw.ToolAllowlist),
		ToolDenylist:              toSet(raw.ToolDenylist),
		ToolApprovalRequired:      toSet(raw.ToolApprovalRequired),
		RateLimits:                raw.RateLimits,
		ContentFilters:            raw.ContentFilters,
	}, nil
}

func compileRules(raws []map[string]any) ([]CompiledRule, error) {
	out := make([]CompiledRule, 0, len(raws))
	for _, r := range raws {
		rule, err := compileRule(r)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}

func compileRule(r map[string]any) (CompiledRule, error) {
	id, _ := r["id"].(string)
	name, _ := r["name"].(string)
	ruleType, _ := r["type"].(string)
	if ruleType == "" {
		ruleType = "regex"
	}
	enabled := true
	if v, ok := r["enabled"].(bool); ok {
		enabled = v
	}
	severity := SeverityMedium
	if s, ok := r["severity"].(string); ok && s != "" {
		severity = Severity(s)
	}
	action, _ := r["action"].(string)
	if action == "" {
		action = "flag"
	}
	category, _ := r["category"].(string)

	envs := stringSlice(r["environments"])

	config := map[string]any{}
	if c, ok := r["config"].(map[string]any); ok {
		config = c
	}

	rule := CompiledRule{
		ID:           id,
		Name:         name,
		Type:         ruleType,
		Category:     category,
		Severity:     severity,
		Action:       action,
		Enabled:      enabled,
		Environments: envs,
		Threshold:    floatOf(config["threshold"]),
		Config:       config,
	}

	switch ruleType {
	case "regex":
		patterns := stringSlice(config["patterns"])
		for _, p := range patterns {
			compiled, err := regexp.Compile("(?i)" + p)
			if err != nil {
				return rule, fmt.Errorf("rule %q regex compile: %w", id, err)
			}
			rule.RegexPatterns = append(rule.RegexPatterns, compiled)
		}
	case "keyword":
		kws := stringSlice(config["keywords"])
		rule.Keywords = make([]string, 0, len(kws))
		for _, k := range kws {
			rule.Keywords = append(rule.Keywords, strings.ToLower(k))
		}
	case "pii_pattern":
		types := stringSlice(config["types"])
		for _, t := range types {
			if pat, ok := PIIPatterns[t]; ok {
				rule.RegexPatterns = append(rule.RegexPatterns, pat)
			}
		}
	}

	return rule, nil
}

func toSet(s []string) map[string]struct{} {
	out := make(map[string]struct{}, len(s))
	for _, v := range s {
		out[v] = struct{}{}
	}
	return out
}

func stringSlice(v any) []string {
	if v == nil {
		return nil
	}
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

func floatOf(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}
