package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Failure-mode coverage for Stage 3 (the LLM judge), mirroring
// stage2_failbehavior_test.go in full. Three claims — the same three the Stage-2
// fix (GAP-004) established, applied one stage over:
//
//  1. A down/erroring judge honours the policy's fail_behavior at EVERY backend
//     failure mode (unreachable / timeout / 5xx / malformed), in BOTH directions.
//  2. Such a result carries Mode "stage3_unavailable" (vs "stage3_http" for a
//     real ruling), so a failed-open judge is not mistaken for a clean verdict.
//  3. It carries NO RuleID — a judge that never answered fired nothing, and
//     decide() folds RuleIDs into Decision.MatchedRules (the rules that FIRED).

func downStage3() *HTTPStage3 { return NewHTTPStage3("http://127.0.0.1:0", 50*time.Millisecond) }

func TestStage3FailClosedBlocksWhenJudgeDown(t *testing.T) {
	r := downStage3().Judge(context.Background(), &Input{Text: "x"}, &CompiledPolicy{FailBehavior: FailClosed})
	if !r.Matched || r.Action != ActionBlocked {
		t.Fatalf("fail-closed policy must block when the judge is down, got %+v", r)
	}
	if r.Mode != ModeStage3Unavailable {
		t.Errorf("Mode = %q, want %q — a block must not masquerade as a real ruling", r.Mode, ModeStage3Unavailable)
	}
	if r.RuleID != "" {
		t.Errorf("RuleID = %q, want empty — a judge that never answered fired no rule", r.RuleID)
	}
}

func TestStage3FailOpenAllowsWhenJudgeDown(t *testing.T) {
	r := downStage3().Judge(context.Background(), &Input{Text: "x"}, &CompiledPolicy{FailBehavior: FailOpen})
	if r.Matched || r.Action != ActionAllowed {
		t.Fatalf("fail-open policy must allow when the judge is down, got %+v", r)
	}
	if r.Mode != ModeStage3Unavailable {
		t.Errorf("Mode = %q, want %q — failing open must still be visible in telemetry", r.Mode, ModeStage3Unavailable)
	}
}

func TestStage3NilPolicyFailsOpen(t *testing.T) {
	r := downStage3().Judge(context.Background(), &Input{Text: "x"}, nil)
	if r.Matched || r.Action != ActionAllowed {
		t.Fatalf("nil policy must fail open (historical default), got %+v", r)
	}
	if r.Mode != ModeStage3Unavailable {
		t.Errorf("Mode = %q, want %q — a nil-policy fail-open is still a non-verdict", r.Mode, ModeStage3Unavailable)
	}
}

func TestStage3RealVerdictIsLabelledHTTP(t *testing.T) {
	// A judge that actually answers reports Mode stage3_http — the contrast that
	// makes "unavailable" meaningful.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"is_violation":false,"confidence":0.1}`))
	}))
	defer srv.Close()
	r := NewHTTPStage3(srv.URL, time.Second).Judge(context.Background(), &Input{Text: "x"}, &CompiledPolicy{FailBehavior: FailClosed})
	if r.Mode != ModeStage3HTTP {
		t.Errorf("Mode = %q, want %q for a real answered verdict", r.Mode, ModeStage3HTTP)
	}
	if r.Matched {
		t.Errorf("a clean verdict must not match, got %+v", r)
	}
}

func TestStage3AllBackendFailuresHonourFailBehavior(t *testing.T) {
	// Every way the judge can fail to produce a verdict must route through the
	// same fail_behavior decision, in BOTH directions — not just an unreachable
	// endpoint failing closed. They all funnel through one stage3Fail, so the
	// full matrix is cheap and worth pinning.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"is_violation":false}`))
	}))
	defer slow.Close()
	fivexx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer fivexx.Close()
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json at all`))
	}))
	defer garbage.Close()

	modes := []struct {
		name  string
		judge *HTTPStage3
	}{
		{"unreachable", downStage3()},
		{"timeout", NewHTTPStage3(slow.URL, 30*time.Millisecond)},
		{"http_500", NewHTTPStage3(fivexx.URL, time.Second)},
		{"malformed_json", NewHTTPStage3(garbage.URL, time.Second)},
	}
	behaviors := []struct {
		name        string
		fb          FailBehavior
		wantBlocked bool
	}{
		{"fail_closed", FailClosed, true},
		{"fail_open", FailOpen, false},
	}
	for _, m := range modes {
		for _, b := range behaviors {
			t.Run(m.name+"/"+b.name, func(t *testing.T) {
				r := m.judge.Judge(context.Background(), &Input{Text: "x"}, &CompiledPolicy{FailBehavior: b.fb})
				if b.wantBlocked && (!r.Matched || r.Action != ActionBlocked) {
					t.Errorf("%s/%s must block, got %+v", m.name, b.name, r)
				}
				if !b.wantBlocked && (r.Matched || r.Action != ActionAllowed) {
					t.Errorf("%s/%s must allow, got %+v", m.name, b.name, r)
				}
				if r.Mode != ModeStage3Unavailable {
					t.Errorf("%s/%s: Mode = %q, want %q", m.name, b.name, r.Mode, ModeStage3Unavailable)
				}
				if r.RuleID != "" {
					t.Errorf("%s/%s: RuleID = %q, want empty", m.name, b.name, r.RuleID)
				}
			})
		}
	}
}
