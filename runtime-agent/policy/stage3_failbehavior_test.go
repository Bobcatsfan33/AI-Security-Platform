package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Failure-mode coverage for Stage 3 (the LLM judge), mirroring
// stage2_failbehavior_test.go. Two claims:
//
//  1. A down/erroring judge honours the policy's fail_behavior — blocks under
//     "closed", allows under "open" — at EVERY backend failure mode.
//  2. A judge that never answered is DISTINGUISHABLE from one that ran and
//     cleared the input: the fail path reports Mode "stage3_unavailable", the
//     real path "stage3_http". Before this, HTTPStage3 set no Mode at all, so a
//     failed-open judge looked identical to a clean verdict in telemetry — the
//     same honesty gap GAP-004 closed for Stage 2.

func downStage3() *HTTPStage3 { return NewHTTPStage3("http://127.0.0.1:0", 50*time.Millisecond) }

func TestStage3FailClosedBlocksWhenJudgeDown(t *testing.T) {
	r := downStage3().Judge(context.Background(), &Input{Text: "x"}, &CompiledPolicy{FailBehavior: FailClosed})
	if !r.Matched || r.Action != ActionBlocked {
		t.Fatalf("fail-closed policy must block when the judge is down, got %+v", r)
	}
	if r.Mode != "stage3_unavailable" {
		t.Errorf("Mode = %q, want stage3_unavailable — a block must not masquerade as a real ruling", r.Mode)
	}
}

func TestStage3FailOpenAllowsWhenJudgeDown(t *testing.T) {
	r := downStage3().Judge(context.Background(), &Input{Text: "x"}, &CompiledPolicy{FailBehavior: FailOpen})
	if r.Matched || r.Action != ActionAllowed {
		t.Fatalf("fail-open policy must allow when the judge is down, got %+v", r)
	}
	if r.Mode != "stage3_unavailable" {
		t.Errorf("Mode = %q, want stage3_unavailable — failing open must still be visible in telemetry", r.Mode)
	}
}

func TestStage3NilPolicyFailsOpen(t *testing.T) {
	r := downStage3().Judge(context.Background(), &Input{Text: "x"}, nil)
	if r.Matched || r.Action != ActionAllowed {
		t.Fatalf("nil policy must fail open (historical default), got %+v", r)
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
	if r.Mode != "stage3_http" {
		t.Errorf("Mode = %q, want stage3_http for a real answered verdict", r.Mode)
	}
	if r.Matched {
		t.Errorf("a clean verdict must not match, got %+v", r)
	}
}

func TestStage3AllBackendFailuresHonourFailClosed(t *testing.T) {
	// Every way the judge can fail to produce a verdict must route through the
	// same fail_behavior decision — not just an unreachable endpoint.
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

	cases := []struct {
		name  string
		judge *HTTPStage3
	}{
		{"unreachable", downStage3()},
		{"timeout", NewHTTPStage3(slow.URL, 30*time.Millisecond)},
		{"http_500", NewHTTPStage3(fivexx.URL, time.Second)},
		{"malformed_json", NewHTTPStage3(garbage.URL, time.Second)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.judge.Judge(context.Background(), &Input{Text: "x"}, &CompiledPolicy{FailBehavior: FailClosed})
			if !r.Matched || r.Action != ActionBlocked {
				t.Errorf("%s under fail-closed must block, got %+v", tc.name, r)
			}
			if r.Mode != "stage3_unavailable" {
				t.Errorf("%s: Mode = %q, want stage3_unavailable", tc.name, r.Mode)
			}
		})
	}
}
