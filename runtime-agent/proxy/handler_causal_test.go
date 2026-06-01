package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/management"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/telemetry"
)

// captureUploader records every batch the buffer flushes. The mutex makes
// it race-safe; done signals the test that at least one batch arrived.
type captureUploader struct {
	mu     sync.Mutex
	events []telemetry.Event
	done   chan struct{}
}

func newCaptureUploader() *captureUploader {
	return &captureUploader{done: make(chan struct{}, 1)}
}

func (c *captureUploader) Upload(_ context.Context, batch []telemetry.Event) error {
	c.mu.Lock()
	c.events = append(c.events, batch...)
	c.mu.Unlock()
	select {
	case c.done <- struct{}{}:
	default:
	}
	return nil
}

func (c *captureUploader) first() (telemetry.Event, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return telemetry.Event{}, 0
	}
	return c.events[0], len(c.events)
}

type nilFetcher struct{}

func (nilFetcher) Fetch(_ context.Context, _ string) ([]byte, error) {
	return nil, context.Canceled
}

// TestServeProxyThreadsCausalLineage drives a request carrying poset
// lineage headers through the real serveProxy hot path (via the kill
// switch branch, which emits telemetry then returns without an upstream)
// and asserts the emitted event carries the threaded lineage with depth
// incremented by one.
func TestServeProxyThreadsCausalLineage(t *testing.T) {
	cap := newCaptureUploader()
	buf := telemetry.NewBuffer(zerolog.Nop(), cap, 1, 10*time.Millisecond, 100)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = buf.Run(ctx) }()

	ks := management.NewKillSwitchState()
	ks.Apply(management.KillSwitchCommand{Type: "block_all"})

	cfg := Config{
		Log:         zerolog.Nop(),
		Cache:       policy.NewCache(zerolog.Nop(), nilFetcher{}, time.Minute),
		Telemetry:   buf,
		OrgID:       uuid.NewString(),
		AgentID:     "agent-B",
		PolicyID:    uuid.NewString(),
		KillSwitch:  ks,
		UpstreamMap: map[Provider]string{},
	}

	rootID := uuid.New()
	parentID := uuid.New()
	inbound := CausalContext{
		RootEventID:    rootID,
		ParentEventID:  parentID,
		CorrelationKey: "task-9",
		CausalDepth:    2,
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/proxy/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`),
	)
	inbound.Apply(req.Header)
	rec := httptest.NewRecorder()

	Handler(cfg).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnavailableForLegalReasons {
		t.Fatalf("expected 451 (kill switch block), got %d", rec.Code)
	}

	// Wait for the buffer to flush the emitted event.
	select {
	case <-cap.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for telemetry flush")
	}

	e, n := cap.first()
	if n != 1 {
		t.Fatalf("expected 1 emitted event, got %d", n)
	}
	if e.RootEventID != rootID.String() {
		t.Errorf("root: got %q, want %q", e.RootEventID, rootID.String())
	}
	if e.ParentEventID != parentID.String() {
		t.Errorf("parent: got %q, want %q", e.ParentEventID, parentID.String())
	}
	if e.CorrelationKey != "task-9" {
		t.Errorf("correlation: got %q, want task-9", e.CorrelationKey)
	}
	if e.CausalDepth != 3 {
		t.Errorf("depth: got %d, want 3 (inbound 2 + 1)", e.CausalDepth)
	}
}

// TestServeProxyFreshRootWhenNoLineage confirms a request WITHOUT lineage
// headers emits an event with empty lineage (the control plane then treats
// its event_id as a fresh poset root).
func TestServeProxyFreshRootWhenNoLineage(t *testing.T) {
	cap := newCaptureUploader()
	buf := telemetry.NewBuffer(zerolog.Nop(), cap, 1, 10*time.Millisecond, 100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = buf.Run(ctx) }()

	ks := management.NewKillSwitchState()
	ks.Apply(management.KillSwitchCommand{Type: "block_all"})

	cfg := Config{
		Log:         zerolog.Nop(),
		Cache:       policy.NewCache(zerolog.Nop(), nilFetcher{}, time.Minute),
		Telemetry:   buf,
		OrgID:       uuid.NewString(),
		AgentID:     "agent-A",
		PolicyID:    uuid.NewString(),
		KillSwitch:  ks,
		UpstreamMap: map[Provider]string{},
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/proxy/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`),
	)
	rec := httptest.NewRecorder()
	Handler(cfg).ServeHTTP(rec, req)

	select {
	case <-cap.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for telemetry flush")
	}
	e, _ := cap.first()
	if e.ParentEventID != "" || e.RootEventID != "" || e.CausalDepth != 0 {
		t.Errorf("expected empty lineage for fresh root, got root=%q parent=%q depth=%d",
			e.RootEventID, e.ParentEventID, e.CausalDepth)
	}
}
