package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// GAP-004: Stage 2 must honour the policy's fail_behavior, and a degraded
// Stage 2 must be distinguishable from a clean one.
//
// Before this, HTTPStage2.Classify took `_ *CompiledPolicy` — it discarded the
// policy and always failed open. So `fail_behavior: "closed"` did not make
// Stage 2 fail closed, and a down sidecar was indistinguishable from a clean
// verdict: both produced Matched:false with no Mode set. `comprehensive`
// enforcement silently degraded to Stage-1-only, and nothing in the telemetry
// said so.
//
// The Mode field is the existing honesty convention (types.go: "names how the
// verdict was ACTUALLY computed"). Stage 2 now uses it the way Stage 3 already
// did: a real classification is "stage2_http", a backend that never answered is
// "stage2_unavailable". Same idea as Stage 3's "disabled" — never label a
// non-verdict as a verdict.

// downStage2 points at a port nothing listens on.
func downStage2() *HTTPStage2 { return NewHTTPStage2("http://127.0.0.1:0", 50*time.Millisecond) }

func TestStage2FailClosedBlocksWhenSidecarDown(t *testing.T) {
	// The headline: a fail-closed policy means fail-closed at EVERY stage that
	// can fail, not just Stage 3.
	r := downStage2().Classify(context.Background(), &Input{Text: "x"}, &CompiledPolicy{FailBehavior: FailClosed})

	if !r.Matched || r.Action != ActionBlocked {
		t.Fatalf("fail-closed policy must block when the sidecar is down, got %+v", r)
	}
	if r.Mode != ModeStage2Unavailable {
		t.Errorf("Mode = %q, want %q — a block must not masquerade as a real classification", r.Mode, ModeStage2Unavailable)
	}
}

func TestStage2FailOpenAllowsWhenSidecarDown(t *testing.T) {
	// Fail-open remains the behaviour for a fail-open policy: a down model must
	// not break the hot path when the operator asked for availability.
	r := downStage2().Classify(context.Background(), &Input{Text: "x"}, &CompiledPolicy{FailBehavior: FailOpen})

	if r.Matched || r.Action != ActionAllowed {
		t.Fatalf("fail-open policy must allow when the sidecar is down, got %+v", r)
	}
	if r.Mode != ModeStage2Unavailable {
		t.Errorf("Mode = %q, want %q — failing open must still be visible", r.Mode, ModeStage2Unavailable)
	}
}

func TestStage2NilPolicyFailsOpen(t *testing.T) {
	// A nil policy cannot express intent, so it keeps the historical default.
	// The proxy's no-policy-at-all path is a separate decision (GAP-003).
	r := downStage2().Classify(context.Background(), &Input{Text: "x"}, nil)

	if r.Matched {
		t.Errorf("nil policy must fail open, got %+v", r)
	}
}

// TestStage2UnavailableIsDistinguishableFromClean is the whole point of the
// Mode field: "the model said clean" and "the model never answered" are
// different facts and must not collapse into the same telemetry.
func TestStage2UnavailableIsDistinguishableFromClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(stage2Response{Matched: false})
	}))
	defer srv.Close()

	clean := NewHTTPStage2(srv.URL, time.Second).Classify(context.Background(), &Input{Text: "x"}, nil)
	unavailable := downStage2().Classify(context.Background(), &Input{Text: "x"}, nil)

	if clean.Matched || unavailable.Matched {
		t.Fatal("precondition: both are non-matches")
	}
	if clean.Mode == unavailable.Mode {
		t.Fatalf("a clean verdict and an unreachable sidecar both report Mode=%q — "+
			"an operator cannot tell enforcement degraded", clean.Mode)
	}
	if clean.Mode != ModeStage2HTTP {
		t.Errorf("clean verdict Mode = %q, want %q", clean.Mode, ModeStage2HTTP)
	}
}

// TestStage2AllBackendFailuresHonourFailClosed walks every way the sidecar can
// let us down. Each previously funnelled into the same unconditional
// fail-open return.
func TestStage2AllBackendFailuresHonourFailClosed(t *testing.T) {
	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer badJSON.Close()

	serverError := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer serverError.Close()

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(stage2Response{Matched: false})
	}))
	defer slow.Close()

	cases := []struct {
		name   string
		stage2 *HTTPStage2
	}{
		{"unreachable", downStage2()},
		{"malformed response", NewHTTPStage2(badJSON.URL, time.Second)},
		{"5xx", NewHTTPStage2(serverError.URL, time.Second)},
		{"timeout", NewHTTPStage2(slow.URL, 30*time.Millisecond)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			closed := tc.stage2.Classify(context.Background(), &Input{Text: "x"}, &CompiledPolicy{FailBehavior: FailClosed})
			if !closed.Matched || closed.Action != ActionBlocked {
				t.Errorf("fail-closed must block on %s, got %+v", tc.name, closed)
			}
			if closed.Mode != ModeStage2Unavailable {
				t.Errorf("Mode = %q, want %q", closed.Mode, ModeStage2Unavailable)
			}

			open := tc.stage2.Classify(context.Background(), &Input{Text: "x"}, &CompiledPolicy{FailBehavior: FailOpen})
			if open.Matched {
				t.Errorf("fail-open must allow on %s, got %+v", tc.name, open)
			}
		})
	}
}

// TestStage2SuccessPathIgnoresFailBehavior — fail_behavior governs failure, not
// verdicts. A working sidecar's answer is the answer under either setting.
func TestStage2SuccessPathIgnoresFailBehavior(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(stage2Response{Matched: false})
	}))
	defer srv.Close()
	s2 := NewHTTPStage2(srv.URL, time.Second)

	for _, fb := range []FailBehavior{FailOpen, FailClosed} {
		r := s2.Classify(context.Background(), &Input{Text: "x"}, &CompiledPolicy{FailBehavior: fb})
		if r.Matched {
			t.Errorf("a reachable sidecar reporting clean must allow under fail_behavior=%v, got %+v", fb, r)
		}
		if r.Mode != ModeStage2HTTP {
			t.Errorf("Mode = %q, want %q", r.Mode, ModeStage2HTTP)
		}
	}
}

func TestStage2MatchSetsHTTPMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(stage2Response{Matched: true, Confidence: 0.91, Category: "jailbreak"})
	}))
	defer srv.Close()

	r := NewHTTPStage2(srv.URL, time.Second).Classify(context.Background(), &Input{Text: "x"}, nil)

	if !r.Matched || r.Mode != ModeStage2HTTP {
		t.Fatalf("real match must report Mode=%q, got %+v", ModeStage2HTTP, r)
	}
}
