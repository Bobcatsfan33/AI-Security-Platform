package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/telemetry"
)

// Malformed-upstream behaviour, documented as tests (not aspiration). The agent
// inspects the REQUEST (prompt) and enforces policy on it; it does NOT inspect
// or validate the upstream RESPONSE — response-side interception is a documented
// follow-on. So these tests pin the ACTUAL behaviour, and docs/AGENT-FAILURE-
// MODES.md states plainly that this is a scope decision: the agent does not
// protect against a compromised or malformed upstream RESPONSE today.

func proxyTo(t *testing.T, upstreamURL string) (http.Handler, func()) {
	t.Helper()
	buf := telemetry.NewBuffer(zerolog.Nop(), discardKS{}, 100, time.Second, 100000)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = buf.Run(ctx) }()

	pol := []byte(`{"id":"mu-pol","org_id":"o","version":1,"enforcement_level":"fast",` +
		`"fail_behavior":"open","ml_confidence_threshold_high":0.7,"ml_confidence_threshold_low":0.3}`)
	cache := policy.NewCache(zerolog.Nop(), ksFetcher{pol}, time.Hour)
	if _, err := cache.Load(context.Background(), "mu-pol"); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	cfg := Config{
		Log:         zerolog.Nop(),
		Cache:       cache,
		Pipeline:    policy.NewPipeline(policy.StageConfig{}),
		Telemetry:   buf,
		OrgID:       "o",
		AgentID:     "mu-test",
		PolicyID:    "mu-pol",
		UpstreamMap: map[Provider]string{ProviderOpenAI: upstreamURL},
	}
	return Handler(cfg), cancel
}

func TestMalformedUpstreamBodyStreamsThroughUnaltered(t *testing.T) {
	// A 200 with a non-JSON / garbage body is forwarded verbatim: the agent is a
	// transparent proxy for the response. This is the honest current behaviour.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("this is not valid json <<<garbage>>>"))
	}))
	defer upstream.Close()
	h, cancel := proxyTo(t, upstream.URL)
	defer cancel()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, ksRequest())
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (streamed through)", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "this is not valid json <<<garbage>>>" {
		t.Errorf("upstream body was altered: %q — the proxy is expected to stream it verbatim", body)
	}
}

func TestUpstreamErrorStatusStreamsThrough(t *testing.T) {
	// A 5xx from the upstream is passed through as-is (it is the upstream's
	// verdict, not the agent's), NOT rewritten to a 502.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"upstream boom"}`))
	}))
	defer upstream.Close()
	h, cancel := proxyTo(t, upstream.URL)
	defer cancel()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, ksRequest())
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500 passed through", rec.Code)
	}
}

func TestDeadUpstreamReturns502(t *testing.T) {
	// A transport failure (upstream unreachable) is the ONE upstream condition
	// the proxy translates: the reverse-proxy ErrorHandler returns 502. The
	// request was already allowed by policy; this is a delivery failure.
	h, cancel := proxyTo(t, "http://127.0.0.1:1") // nothing listens on :1
	defer cancel()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, ksRequest())
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d, want 502 for an unreachable upstream", rec.Code)
	}
}
