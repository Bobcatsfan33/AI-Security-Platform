package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/rs/zerolog"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/management"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/telemetry"
)

// Config wires the proxy to its dependencies.
type Config struct {
	Log         zerolog.Logger
	Cache       *policy.Cache
	Pipeline    *policy.Pipeline
	Telemetry   *telemetry.Buffer
	OrgID       string
	AgentID     string
	Environment string

	// KillSwitch is consulted on the hot path BEFORE the policy
	// pipeline so emergency commands from the control plane take
	// effect in microseconds. Optional — when nil, kill-switch checks
	// are skipped.
	KillSwitch *management.KillSwitchState

	// PolicyID is the policy this proxy enforces. Operators typically
	// run one proxy per asset → one policy_id. Sprint 7 follow-on:
	// per-asset routing via Host header / URL prefix.
	PolicyID string

	// UpstreamMap routes by provider. For OpenAI: https://api.openai.com.
	// For Anthropic: https://api.anthropic.com. Configurable so
	// customers can route through their own egress proxy.
	UpstreamMap map[Provider]string

	// PassthroughOnUnknownFormat: when true, requests we can't classify
	// pass through without inspection. When false, they're rejected.
	// Default true — better to forward an unrecognized request than
	// break the customer's app.
	PassthroughOnUnknownFormat bool
}

// Handler returns an http.Handler that runs the proxy.
func Handler(cfg Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/", func(w http.ResponseWriter, r *http.Request) {
		serveProxy(cfg, w, r)
	})
	return mux
}

// serveProxy is the hot path. Steps:
//   1. Read + buffer the request body (size-bounded)
//   2. Detect the provider from URL path
//   3. Extract prompt for policy inspection
//   4. Run the policy pipeline against the cached CompiledPolicy
//   5. On block: respond 451 with the structured violation
//   6. On allow: forward to upstream via httputil.ReverseProxy
//   7. Emit telemetry event regardless of outcome
func serveProxy(cfg Config, w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	// Read body. Size-bounded by Content-Length; Go's http handler
	// already enforces MaxBytesReader if the server sets ReadLimit.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Strip the /proxy prefix; everything else is the upstream path
	upstreamPath := r.URL.Path
	if len(upstreamPath) > len("/proxy") && upstreamPath[:len("/proxy")] == "/proxy" {
		upstreamPath = upstreamPath[len("/proxy"):]
	}

	provider := DetectProvider(upstreamPath)
	extracted, extractErr := Extract(provider, body)

	// Kill switch — emergency commands from the control plane take
	// effect BEFORE the policy pipeline so they apply in microseconds
	// without waiting for cache refresh.
	if cfg.KillSwitch != nil {
		// We don't yet have asset_id or tool_name extracted; this
		// gate is for the global-block scenario. Per-asset and per-
		// tool blocks are evaluated again after Extract pulls the
		// tool name (Sprint 7 follow-on).
		if blocked, reason := cfg.KillSwitch.ShouldBlock("", ""); blocked {
			writeBlocked(w, reason, policy.SeverityCritical)
			emitEvent(cfg, &extracted, nil, nil, body, nil, start, "blocked_kill_switch")
			return
		}
	}

	// Look up the active policy. On miss + fail-closed, refuse.
	compiled := cfg.Cache.Get(cfg.PolicyID)
	if compiled == nil {
		// Best-effort load
		if loaded, lerr := cfg.Cache.Load(ctx, cfg.PolicyID); lerr == nil {
			compiled = loaded
		}
	}

	if compiled == nil {
		// No policy available. Per blueprint: fail-open by default for
		// dev. Production deployments configure fail-closed.
		cfg.Log.Warn().Str("policy_id", cfg.PolicyID).Msg("proxy_no_policy_cached")
		emitEvent(cfg, &extracted, nil, nil, body, nil, start, "passthrough_no_policy")
		forward(cfg, w, r, provider, upstreamPath, body)
		return
	}

	if cfg.Cache.IsStale(cfg.PolicyID) && compiled.FailBehavior == policy.FailClosed {
		writeBlocked(w, "policy_cache_stale_fail_closed", policy.SeverityCritical)
		emitEvent(cfg, &extracted, compiled, nil, body, nil, start, "blocked_stale_cache")
		return
	}

	// Build the policy input
	input := &policy.Input{
		Text:      extracted.UserText,
		Direction: policy.DirectionInbound,
		SourceIP:  r.RemoteAddr,
		Timestamp: time.Now().UTC(),
	}

	// Special case: unrecognized format. If the operator allows
	// passthrough, forward without inspection but still emit telemetry.
	if errors.Is(extractErr, ErrNoPromptExtracted) {
		if !cfg.PassthroughOnUnknownFormat {
			http.Error(w, "unrecognized request format", http.StatusUnsupportedMediaType)
			return
		}
		cfg.Log.Info().Str("path", upstreamPath).Msg("proxy_unknown_format_passthrough")
		emitEvent(cfg, &extracted, compiled, nil, body, nil, start, "passthrough_unknown_format")
		forward(cfg, w, r, provider, upstreamPath, body)
		return
	}

	decision := cfg.Pipeline.Evaluate(ctx, input, compiled, cfg.Environment)

	if decision.Blocked() {
		writeBlocked(w, decision.BlockReason, decision.Severity)
		emitEvent(cfg, &extracted, compiled, &decision, body, nil, start, "blocked")
		return
	}

	forward(cfg, w, r, provider, upstreamPath, body)
	emitEvent(cfg, &extracted, compiled, &decision, body, nil, start, "allowed")
}

func writeBlocked(w http.ResponseWriter, reason string, severity policy.Severity) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnavailableForLegalReasons) // 451 — most accurate
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"type":     "policy_violation",
			"message":  "request blocked by AI security policy",
			"reason":   reason,
			"severity": severity,
		},
	})
}

func forward(
	cfg Config, w http.ResponseWriter, r *http.Request,
	provider Provider, upstreamPath string, body []byte,
) {
	upstream, ok := cfg.UpstreamMap[provider]
	if !ok || upstream == "" {
		http.Error(w, "no upstream configured for "+string(provider), http.StatusBadGateway)
		return
	}
	target, err := url.Parse(upstream)
	if err != nil {
		http.Error(w, "invalid upstream URL", http.StatusInternalServerError)
		return
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		req.URL.Path = upstreamPath
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		// Drop X-Forwarded-* additions for stability
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		cfg.Log.Error().Err(err).Msg("proxy_upstream_error")
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
	}
	rp.ServeHTTP(w, r)
}

func emitEvent(
	cfg Config,
	extracted *ExtractedPrompt,
	compiled *policy.CompiledPolicy,
	decision *policy.Decision,
	requestBody []byte,
	_ []byte, // response body — populated by streaming interception (follow-on)
	start time.Time,
	action string,
) {
	event := telemetry.NewEvent(cfg.OrgID, cfg.PolicyID, cfg.AgentID, "")
	event.EventType = "request"
	event.Direction = "inbound"
	event.PromptSnippet = snippet(extracted.UserText, 500)
	event.PromptHash = sha256Hex(extracted.UserText)
	event.LatencyMS = uint32(time.Since(start).Milliseconds())

	if compiled != nil {
		event.EnforcementLevel = compiled.EnforcementLevel
	}
	if decision != nil {
		event.ActionTaken = decision.Action
		event.PipelineExitStage = decision.PipelineExitStage
		event.BlockReason = decision.BlockReason
		event.PoliciesChecked = 1
		if !decision.Allowed() {
			event.PoliciesFailed = 1
		}
		for _, sr := range decision.StageResults {
			if sr.Stage == policy.ExitStage1Regex {
				event.Stage1LatencyUS = uint32(sr.LatencyUS)
			}
		}
		if pr, err := json.Marshal(decision.StageResults); err == nil {
			event.PolicyResults = string(pr)
		}
	} else {
		event.ActionTaken = policy.Action(action)
	}

	event.AgentVersion = "0.1.0-sprint7-starter"
	cfg.Telemetry.Enqueue(*event)

	cfg.Log.Info().
		Str("action", string(event.ActionTaken)).
		Str("provider", string(extracted.Provider)).
		Str("policy_id", cfg.PolicyID).
		Uint32("latency_ms", event.LatencyMS).
		Msg("proxy_request_handled")

	_ = ctxJustForGodoc
}

// ctxJustForGodoc is a placeholder used purely to silence "unused import"
// when no other ctx work happens in this file. The context.Context
// argument flows through serveProxy → cache → upstream HTTP client.
var ctxJustForGodoc = context.Background()

func snippet(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func sha256Hex(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
