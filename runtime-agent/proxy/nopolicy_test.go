package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/telemetry"
)

// GAP-003: cold start with no policy cached.
//
// Before this, the proxy forwarded EVERY request uninspected when no policy was
// available — an open proxy — and the code comment claimed "production
// deployments configure fail-closed" for a setting that did not exist. Start
// the agent before the control plane is reachable and traffic flowed
// unprotected behind nothing but a warn line.
//
// The resolution mirrors the SDK's fail-closed convention (sdks/*/routing) so
// the platform documents one shape, not two:
//
//	explicit AGENT_NO_POLICY_BEHAVIOR always wins;
//	unset    → resolve by environment: production → closed, otherwise open.
//
// The agent reads its existing AGENT_ENVIRONMENT rather than the SDK's
// PLATFORM_ENV — same convention, each process reading the variable it already
// has, rather than two env vars meaning one thing inside one process.

func TestResolveNoPolicyBehavior(t *testing.T) {
	cases := []struct {
		name        string
		explicit    string
		environment string
		want        NoPolicyBehavior
	}{
		// Explicit wins, in both directions, regardless of environment.
		{"explicit closed in dev", "closed", "development", NoPolicyClosed},
		{"explicit open in prod", "open", "production", NoPolicyOpen},
		{"explicit is case-insensitive", "CLOSED", "development", NoPolicyClosed},
		{"explicit tolerates whitespace", "  open  ", "production", NoPolicyOpen},

		// Unset → resolve by environment. Deny-by-default in production.
		{"unset in production", "", "production", NoPolicyClosed},
		{"unset in prod shorthand", "", "prod", NoPolicyClosed},
		{"unset is case-insensitive", "", "PRODUCTION", NoPolicyClosed},
		{"unset in development", "", "development", NoPolicyOpen},
		{"unset in staging", "", "staging", NoPolicyOpen},
		{"unset in test", "", "test", NoPolicyOpen},

		// AGENT_ENVIRONMENT itself defaults to "production" (cmd/agent), so an
		// operator who configures nothing at all is protected.
		{"nothing configured at all", "", "", NoPolicyClosed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveNoPolicyBehavior(tc.explicit, tc.environment)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("ResolveNoPolicyBehavior(%q, %q) = %q, want %q",
					tc.explicit, tc.environment, got, tc.want)
			}
		})
	}
}

func TestResolveNoPolicyBehaviorRejectsGarbage(t *testing.T) {
	// A typo must not silently resolve to the permissive branch. The agent
	// already refuses to start on partial mTLS config rather than downgrade
	// quietly (cmd/agent/main.go); this follows that precedent — an
	// unparseable security setting is a startup error, not a guess.
	for _, bad := range []string{"yes", "true", "1", "fail-open", "openish"} {
		if _, err := ResolveNoPolicyBehavior(bad, "production"); err == nil {
			t.Errorf("ResolveNoPolicyBehavior(%q, …) must error, not guess", bad)
		}
	}
}

// ── the hot path ──────────────────────────────────────────────────────────

// noPolicyFixture wires a proxy whose cache can never produce a policy
// (nilFetcher always errors), so every request lands on the no-policy branch.
type noPolicyFixture struct {
	handler  http.Handler
	uploader *captureUploader
	logs     *strings.Builder
	upstream *httptest.Server
}

func newNoPolicyFixture(t *testing.T, behavior NoPolicyBehavior) *noPolicyFixture {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(upstream.Close)

	cap := newCaptureUploader()
	buf := telemetry.NewBuffer(zerolog.Nop(), cap, 1, 5*time.Millisecond, 100)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = buf.Run(ctx) }()

	logs := &strings.Builder{}
	cfg := Config{
		Log:              zerolog.New(logs),
		Cache:            policy.NewCache(zerolog.Nop(), nilFetcher{}, time.Minute),
		Pipeline:         policy.NewPipeline(policy.StageConfig{}),
		Telemetry:        buf,
		OrgID:            uuid.NewString(),
		AgentID:          "agent-coldstart",
		PolicyID:         "policy-does-not-exist",
		Environment:      "production",
		NoPolicyBehavior: behavior,
		UpstreamMap:      map[Provider]string{ProviderOpenAI: upstream.URL},
	}

	return &noPolicyFixture{
		handler:  Handler(cfg),
		uploader: cap,
		logs:     logs,
		upstream: upstream,
	}
}

func (f *noPolicyFixture) post() *httptest.ResponseRecorder {
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/proxy/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// awaitEvent waits for the buffer to flush the emitted event.
func (f *noPolicyFixture) awaitEvent(t *testing.T) telemetry.Event {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if ev, n := f.uploader.first(); n > 0 {
			return ev
		}
		select {
		case <-deadline:
			t.Fatal("no telemetry event was emitted for the no-policy branch")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestNoPolicyFailClosedBlocks(t *testing.T) {
	// THE test: control plane unreachable at startup, nothing cached. A
	// fail-closed agent must refuse rather than become an open proxy.
	f := newNoPolicyFixture(t, NoPolicyClosed)

	rec := f.post()

	if rec.Code != http.StatusUnavailableForLegalReasons {
		t.Fatalf("status = %d, want 451 — no policy must not mean no inspection", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no_policy") {
		t.Errorf("block reason should name the cause, got %s", rec.Body.String())
	}
}

func TestNoPolicyFailClosedIsLoud(t *testing.T) {
	// A fail-closed cold start is an outage. It has to be diagnosable in
	// seconds from the logs, not inferred from an unexplained 451.
	f := newNoPolicyFixture(t, NoPolicyClosed)

	f.post()

	out := f.logs.String()
	if !strings.Contains(out, "proxy_no_policy_fail_closed") {
		t.Errorf("expected a fail-closed log event, got: %s", out)
	}
	if !strings.Contains(out, "policy-does-not-exist") {
		t.Errorf("log must name the policy_id an operator has to go fix, got: %s", out)
	}
}

func TestNoPolicyFailOpenForwardsButIsLoud(t *testing.T) {
	// Fail-open stays available for dev — but must never be silent, or an
	// unprotected dev setup looks identical to a protected one.
	f := newNoPolicyFixture(t, NoPolicyOpen)

	rec := f.post()

	if rec.Code == http.StatusUnavailableForLegalReasons {
		t.Fatalf("fail-open must not block, got %d", rec.Code)
	}
	if !strings.Contains(f.logs.String(), "proxy_no_policy_fail_open") {
		t.Errorf("expected a fail-open log event, got: %s", f.logs.String())
	}
}

// TestNoPolicyEmitsDistinguishableTelemetry — logs are for the operator reading
// one box; telemetry is for the fleet view. A cold start must be visible in
// both, and the two branches must not look alike.
func TestNoPolicyEmitsDistinguishableTelemetry(t *testing.T) {
	cases := []struct {
		behavior NoPolicyBehavior
		want     policy.Action
	}{
		{NoPolicyClosed, policy.Action("blocked_no_policy")},
		{NoPolicyOpen, policy.Action("passthrough_no_policy")},
	}

	for _, tc := range cases {
		t.Run(string(tc.behavior), func(t *testing.T) {
			f := newNoPolicyFixture(t, tc.behavior)

			f.post()

			if got := f.awaitEvent(t).ActionTaken; got != tc.want {
				t.Errorf("ActionTaken = %q, want %q", got, tc.want)
			}
		})
	}
}
