package bench

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"time"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
)

// representativeRegexPatterns is a small but realistic prompt-injection ruleset,
// so Stage 1 does real work on the hot path. An empty policy would flatter the
// numbers by measuring a pipeline with nothing to match against — the opposite
// of a defensible benchmark.
var representativeRegexPatterns = []string{
	`ignore (all )?previous instructions`,
	`disregard (the )?above`,
	`you are now (a|an|in) `,
	`reveal your (system )?prompt`,
	`repeat the (text|words) above`,
	`begin your reply with`,
	`bypass (the )?(safety|content) (filter|policy)`,
	`developer mode`,
	`pretend to be`,
	`\bDAN\b`,
	`jailbreak`,
	`override your (instructions|guidelines)`,
}

// RepresentativePolicy compiles a realistic policy at the given enforcement
// level through the SAME CompileFromJSON path production uses — so the
// benchmark exercises the real compiled ruleset, not a hand-built shortcut.
func RepresentativePolicy(level policy.EnforcementLevel) *policy.CompiledPolicy {
	raw, _ := json.Marshal(map[string]any{
		"id":                           "bench-policy",
		"org_id":                       "bench-org",
		"version":                      1,
		"enforcement_level":            string(level),
		"fail_behavior":                "closed",
		"ml_confidence_threshold_high": 0.7,
		"ml_confidence_threshold_low":  0.3,
		"rules": []map[string]any{
			{
				"id": "pi-regex", "name": "prompt-injection", "type": "regex",
				"severity": "high", "action": "block", "category": "prompt_injection",
				"config": map[string]any{"patterns": representativeRegexPatterns},
			},
			{
				"id": "secret-kw", "name": "secret-keywords", "type": "keyword",
				"severity": "medium", "action": "flag", "category": "data_leak",
				"config": map[string]any{
					"keywords": []string{"password", "api_key", "secret", "ssh-rsa"},
				},
			},
		},
	})
	p, err := policy.CompileFromJSON(raw)
	if err != nil {
		panic("bench: representative policy failed to compile: " + err.Error())
	}
	return p
}

// BenignInput is a representative allow-path prompt: it does NOT match the
// ruleset, so the pipeline runs to completion (the worst case for latency —
// a Stage-1 block would short-circuit and under-measure the later stages).
func BenignInput() *policy.Input {
	return &policy.Input{
		Text:      "Summarize the quarterly earnings report in three concise bullet points.",
		Direction: policy.DirectionInbound,
		SessionID: "bench-session",
		AssetID:   "bench-asset",
	}
}

// SidecarResponse is the JSON an ONNX Stage-2 sidecar returns
// (stage2_http.go contract: {matched, confidence, category}).
type SidecarResponse struct {
	Matched    bool    `json:"matched"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
}

// MockStage2 stands in for the ONNX inference sidecar at a FIXED added latency.
// It measures the agent's marshal + one-localhost-hop transport cost, not real
// model inference. latency=0 isolates pure transport/marshal overhead.
func MockStage2(latency time.Duration, resp SidecarResponse) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if latency > 0 {
			time.Sleep(latency)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// judgeResponse is the Stage-3 judge contract (stage3_judge.go:
// {is_violation, confidence, category, reason}).
type judgeResponse struct {
	IsViolation bool    `json:"is_violation"`
	Confidence  float64 `json:"confidence"`
	Category    string  `json:"category"`
	Reason      string  `json:"reason"`
}

// MockStage3 stands in for the LLM-judge sidecar at a FIXED added latency,
// returning a clean (non-violation) verdict so the comprehensive path runs to
// completion.
func MockStage3(latency time.Duration, confidence float64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if latency > 0 {
			time.Sleep(latency)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(judgeResponse{IsViolation: false, Confidence: confidence})
	}))
}

// Percentiles is the reported single-request latency distribution for one mode.
type Percentiles struct {
	Mode   string  `json:"mode"`
	N      int     `json:"n"`
	MeanUS float64 `json:"mean_us"`
	P50US  float64 `json:"p50_us"`
	P95US  float64 `json:"p95_us"`
	P99US  float64 `json:"p99_us"`
	MaxUS  float64 `json:"max_us"`
}

// Sample runs fn n times (after warmup discards), records each call's wall-clock
// latency, and returns the distribution in microseconds. Single-request, no
// concurrency — queuing tail under load is the locust harness's job.
func Sample(mode string, n, warmup int, fn func()) Percentiles {
	for range warmup {
		fn()
	}
	xs := make([]float64, n)
	for i := range n {
		t := time.Now()
		fn()
		xs[i] = float64(time.Since(t).Nanoseconds()) / 1000.0
	}
	sort.Float64s(xs)
	var sum float64
	for _, x := range xs {
		sum += x
	}
	return Percentiles{
		Mode:   mode,
		N:      n,
		MeanUS: sum / float64(n),
		P50US:  percentile(xs, 0.50),
		P95US:  percentile(xs, 0.95),
		P99US:  percentile(xs, 0.99),
		MaxUS:  xs[n-1],
	}
}

// percentile uses the nearest-rank method on an already-sorted slice.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p*float64(len(sorted)-1) + 0.5)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// EnvStamp records where a reported number was produced, so a number in
// docs/BENCHMARKS.md is evidence (regenerable, attributable) not a bare claim.
type EnvStamp struct {
	Timestamp string `json:"timestamp"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	NumCPU    int    `json:"num_cpu"`
	Commit    string `json:"commit,omitempty"`
}

// CaptureEnv stamps the current environment. Commit is taken from the
// BENCH_COMMIT env var when set (regen.sh injects `git rev-parse` there, since
// `go test` runs carry no VCS revision in ReadBuildInfo), falling back to the
// build's embedded VCS info. A stamp without a commit is a number you cannot
// trace back to the code that produced it — the one thing evidence must never be.
func CaptureEnv() EnvStamp {
	e := EnvStamp{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		NumCPU:    runtime.NumCPU(),
	}
	if c := os.Getenv("BENCH_COMMIT"); c != "" {
		e.Commit = c
	} else if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				e.Commit = s.Value
			}
		}
	}
	return e
}
