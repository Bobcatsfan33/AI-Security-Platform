package bench

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
)

// benchEvaluate is the shared inner loop: it measures ONLY Pipeline.Evaluate —
// the pipeline-added latency that is the product's "added latency" claim.
func benchEvaluate(b *testing.B, pl *policy.Pipeline, pol *policy.CompiledPolicy) {
	in := BenignInput()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = pl.Evaluate(ctx, in, pol, "production")
	}
}

// ── Deterministic, in-process (gated in CI on allocs/op + B/op) ──────────────

func BenchmarkEvaluate_Fast(b *testing.B) {
	benchEvaluate(b, policy.NewPipeline(policy.StageConfig{}), RepresentativePolicy(policy.EnforcementFast))
}

func BenchmarkEvaluate_BalancedHeuristic(b *testing.B) {
	benchEvaluate(b, policy.NewPipeline(policy.StageConfig{}), RepresentativePolicy(policy.EnforcementBalanced))
}

func BenchmarkEvaluate_ComprehensiveHeuristic(b *testing.B) {
	benchEvaluate(b, policy.NewPipeline(policy.StageConfig{}), RepresentativePolicy(policy.EnforcementComprehensive))
}

// ── Sidecar-backed (reported: includes one localhost hop; NOT inference) ─────

func BenchmarkEvaluate_BalancedSidecar(b *testing.B) {
	s2 := MockStage2(0, SidecarResponse{Matched: false, Confidence: 0.1})
	defer s2.Close()
	pl := policy.NewPipeline(policy.StageConfig{Stage2Endpoint: s2.URL, Stage2Timeout: time.Second})
	benchEvaluate(b, pl, RepresentativePolicy(policy.EnforcementBalanced))
}

func BenchmarkEvaluate_ComprehensiveSidecar(b *testing.B) {
	// Stage-2 returns an UNCERTAIN confidence (between low 0.3 and high 0.7) so
	// the comprehensive path escalates to the Stage-3 judge — exercising all
	// three stages, the true worst case.
	s2 := MockStage2(0, SidecarResponse{Matched: true, Confidence: 0.5, Category: "prompt_injection"})
	defer s2.Close()
	s3 := MockStage3(0, 0.2)
	defer s3.Close()
	pl := policy.NewPipeline(policy.StageConfig{
		Stage2Endpoint: s2.URL, Stage2Timeout: time.Second,
		Stage3Endpoint: s3.URL, Stage3Timeout: time.Second,
	})
	benchEvaluate(b, pl, RepresentativePolicy(policy.EnforcementComprehensive))
}

// TestLatencyDistribution samples p50/p95/p99 of single-request Evaluate latency
// per mode. It always logs the distribution; with BENCH_WRITE=1 it also writes
// bench/measured.json (the regeneration path — see bench/regen.sh). It is not an
// assertion gate: the CI regression gate lives in the benchmarks' allocs/op
// (increment 2), and the tail numbers are reported evidence, not pass/fail.
func TestLatencyDistribution(t *testing.T) {
	if testing.Short() {
		t.Skip("latency sampling skipped under -short")
	}
	const n, warmup = 5000, 300
	ctx := context.Background()

	fastPol := RepresentativePolicy(policy.EnforcementFast)
	fastPl := policy.NewPipeline(policy.StageConfig{})

	balPol := RepresentativePolicy(policy.EnforcementBalanced)
	balPl := policy.NewPipeline(policy.StageConfig{})

	s2 := MockStage2(0, SidecarResponse{Matched: true, Confidence: 0.5, Category: "prompt_injection"})
	defer s2.Close()
	s3 := MockStage3(0, 0.2)
	defer s3.Close()
	compPol := RepresentativePolicy(policy.EnforcementComprehensive)
	compPl := policy.NewPipeline(policy.StageConfig{
		Stage2Endpoint: s2.URL, Stage2Timeout: time.Second,
		Stage3Endpoint: s3.URL, Stage3Timeout: time.Second,
	})

	in := BenignInput()
	dists := []Percentiles{
		Sample("fast (stage1, in-process)", n, warmup, func() { _ = fastPl.Evaluate(ctx, in, fastPol, "production") }),
		Sample("balanced (stage1+2 heuristic, in-process)", n, warmup, func() { _ = balPl.Evaluate(ctx, in, balPol, "production") }),
		Sample("comprehensive (stage1+2+3, two sidecar hops, no inference)", n/2, warmup, func() { _ = compPl.Evaluate(ctx, in, compPol, "production") }),
	}

	for _, d := range dists {
		t.Logf("%-52s n=%d  p50=%.1fus  p95=%.1fus  p99=%.1fus  max=%.1fus  mean=%.1fus",
			d.Mode, d.N, d.P50US, d.P95US, d.P99US, d.MaxUS, d.MeanUS)
	}

	if os.Getenv("BENCH_WRITE") == "1" {
		report := struct {
			Env  EnvStamp      `json:"env"`
			Dist []Percentiles `json:"distributions"`
		}{Env: CaptureEnv(), Dist: dists}
		data, _ := json.MarshalIndent(report, "", "  ")
		data = append(data, '\n')
		if err := os.WriteFile("measured.json", data, 0o644); err != nil {
			t.Fatalf("write measured.json: %v", err)
		}
		t.Logf("wrote measured.json")
	}
}
