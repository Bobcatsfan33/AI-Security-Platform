package proxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/management"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/telemetry"
)

// GAP-010: the kill switch is the control you demo to a security team, and the
// block-all path at handler.go:122 had no test. These drive real requests
// through serveProxy while the switch is flipped, proving the emergency block
// takes effect on the very NEXT request (no cache-refresh wait) and lifts
// cleanly — and that flipping it under concurrent traffic is race-safe.

type ksFetcher struct{ data []byte }

func (f ksFetcher) Fetch(context.Context, string) ([]byte, error) { return f.data, nil }

// ksHarness wires a Config whose allow-path forwards to a mock upstream, so a
// non-blocked request returns 200 and a kill-switched one returns 451.
func ksHarness(t *testing.T) (http.Handler, *management.KillSwitchState, func()) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	buf := telemetry.NewBuffer(zerolog.Nop(), discardKS{}, 100, time.Second, 100000)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = buf.Run(ctx) }()

	pol := []byte(`{"id":"ks-pol","org_id":"o","version":1,"enforcement_level":"fast",` +
		`"fail_behavior":"open","ml_confidence_threshold_high":0.7,"ml_confidence_threshold_low":0.3}`)
	cache := policy.NewCache(zerolog.Nop(), ksFetcher{pol}, time.Hour)
	if _, err := cache.Load(context.Background(), "ks-pol"); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	ks := management.NewKillSwitchState()

	cfg := Config{
		Log:         zerolog.Nop(),
		Cache:       cache,
		Pipeline:    policy.NewPipeline(policy.StageConfig{}),
		Telemetry:   buf,
		OrgID:       "o",
		AgentID:     "ks-test",
		PolicyID:    "ks-pol",
		KillSwitch:  ks,
		UpstreamMap: map[Provider]string{ProviderOpenAI: upstream.URL},
	}
	cleanup := func() { cancel(); upstream.Close() }
	return Handler(cfg), ks, cleanup
}

type discardKS struct{}

func (discardKS) Upload(context.Context, []telemetry.Event) error { return nil }

func ksRequest() *http.Request {
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`)
	return httptest.NewRequest("POST", "/proxy/v1/chat/completions", bytes.NewReader(body))
}

func TestKillSwitchBlocksMidTraffic(t *testing.T) {
	h, ks, cleanup := ksHarness(t)
	defer cleanup()

	// Before: forwarded to upstream.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, ksRequest())
	if rec.Code != http.StatusOK {
		t.Fatalf("before kill switch: got %d, want 200 (forwarded)", rec.Code)
	}

	// Flip block_all — must take effect on the very next request.
	ks.Apply(management.KillSwitchCommand{Type: "block_all"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, ksRequest())
	if rec.Code != http.StatusUnavailableForLegalReasons { // 451
		t.Fatalf("after block_all: got %d, want 451 (blocked)", rec.Code)
	}

	// Lift it — traffic flows again.
	ks.Apply(management.KillSwitchCommand{Type: "unblock_all"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, ksRequest())
	if rec.Code != http.StatusOK {
		t.Fatalf("after unblock_all: got %d, want 200 (recovered)", rec.Code)
	}
}

func TestKillSwitchFlipUnderConcurrentTrafficIsRaceSafe(t *testing.T) {
	// -race proves the atomic kill-switch state has no data race while it is
	// flipped under load; every request must resolve to a definite 200 or 451,
	// never a panic or a torn read.
	h, ks, cleanup := ksHarness(t)
	defer cleanup()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Flipper.
	wg.Add(1)
	go func() {
		defer wg.Done()
		on := false
		for {
			select {
			case <-stop:
				return
			default:
				on = !on
				typ := "unblock_all"
				if on {
					typ = "block_all"
				}
				ks.Apply(management.KillSwitchCommand{Type: typ})
			}
		}
	}()
	// Traffic.
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, ksRequest())
				if rec.Code != http.StatusOK && rec.Code != http.StatusUnavailableForLegalReasons {
					t.Errorf("unexpected status under concurrent flip: %d", rec.Code)
					return
				}
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
