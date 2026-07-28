// Command loadserver stands up the REAL agent proxy hot path (proxy.Handler)
// against a mock upstream, for the end-to-end load test (docs/BENCHMARKS.md).
//
// It is the honest end-to-end rig the single-request microbench deliberately is
// not: locust drives the proxy on :18400 over a real socket, the proxy runs the
// real pipeline + reverse-proxy forward, and a mock upstream on :19000 returns a
// canned completion at near-zero delay. Point locust at :18400 to measure
// proxy+upstream, and at :19000 to measure the upstream baseline to subtract.
// (High ports on purpose — :8400/:9000 collide with the real agent and other
// dev services.)
//
// This is a benchmark rig, not a deployment: the policy is seeded from an
// in-process stub fetcher (no control plane), telemetry is discarded, the kill
// switch is absent. Everything ELSE on the request path is the production code.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/bench"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/proxy"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/telemetry"
)

// cannedCompletion is a minimal OpenAI chat-completion response. Small on
// purpose: the load test measures AGENT overhead, so the upstream body should
// not dominate.
var cannedCompletion = []byte(`{"id":"chatcmpl-bench","object":"chat.completion",` +
	`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)

type discardUploader struct{}

func (discardUploader) Upload(context.Context, []telemetry.Event) error { return nil }

type stubFetcher struct{ data []byte }

func (f stubFetcher) Fetch(context.Context, string) ([]byte, error) { return f.data, nil }

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	proxyAddr := env("PROXY_ADDR", "127.0.0.1:18400")
	upstreamAddr := env("UPSTREAM_ADDR", "127.0.0.1:19000")
	mode := policy.EnforcementLevel(env("MODE", "balanced"))
	const policyID = "bench-policy"

	// Mock upstream: canned completion, near-zero delay.
	upstream := &http.Server{
		Addr: upstreamAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(cannedCompletion)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := upstream.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("loadserver: mock upstream: %v", err)
		}
	}()

	// Telemetry buffer with a discard uploader (the real emit path runs, the
	// bytes go nowhere).
	buf := telemetry.NewBuffer(zerolog.Nop(), discardUploader{}, 100, time.Second, 100000)
	go func() { _ = buf.Run(context.Background()) }()

	// Seed the policy cache through the real Cache/CompileFromJSON path.
	cache := policy.NewCache(zerolog.Nop(), stubFetcher{bench.RepresentativePolicyJSON(mode)}, time.Hour)
	if _, err := cache.Load(context.Background(), policyID); err != nil {
		log.Fatalf("loadserver: seed policy: %v", err)
	}

	cfg := proxy.Config{
		Log:         zerolog.Nop(),
		Cache:       cache,
		Pipeline:    policy.NewPipeline(policy.StageConfig{}), // inline heuristic Stage 2
		Telemetry:   buf,
		OrgID:       "bench-org",
		AgentID:     "loadserver",
		Environment: "production",
		PolicyID:    policyID,
		UpstreamMap: map[proxy.Provider]string{proxy.ProviderOpenAI: "http://" + upstreamAddr},
	}

	log.Printf("loadserver: proxy=%s upstream=%s mode=%s", proxyAddr, upstreamAddr, mode)
	server := &http.Server{Addr: proxyAddr, Handler: proxy.Handler(cfg), ReadHeaderTimeout: 5 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("loadserver: proxy: %v", err)
	}
}
