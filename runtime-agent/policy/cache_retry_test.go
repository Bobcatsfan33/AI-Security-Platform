package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/internal/backoff"
)

type funcFetcher func(context.Context, string) ([]byte, error)

func (f funcFetcher) Fetch(ctx context.Context, id string) ([]byte, error) { return f(ctx, id) }

var validPolicyJSON = []byte(`{"id":"p","org_id":"o","version":1,"enforcement_level":"fast","fail_behavior":"open"}`)

var fastBackoff = backoff.Config{Base: time.Millisecond, Max: 3 * time.Millisecond, Factor: 2}

// Cold-start policy load: bounded backoff, then success.
func TestLoadWithRetrySucceedsAfterTransientFailures(t *testing.T) {
	n := 0
	f := funcFetcher(func(context.Context, string) ([]byte, error) {
		n++
		if n < 3 {
			return nil, errors.New("control plane unreachable")
		}
		return validPolicyJSON, nil
	})
	c := NewCache(zerolog.Nop(), f, time.Hour)

	p, err := c.LoadWithRetry(context.Background(), "p", fastBackoff, 5)
	if err != nil || p == nil {
		t.Fatalf("want success once the control plane answers, got err=%v p=%v", err, p)
	}
	if n != 3 {
		t.Errorf("fetch attempts = %d, want 3", n)
	}
}

// The give-up contract: bounded, so the caller can PROCEED to
// AGENT_NO_POLICY_BEHAVIOR — never an unbounded startup hang.
func TestLoadWithRetryGivesUpBounded(t *testing.T) {
	n := 0
	f := funcFetcher(func(context.Context, string) ([]byte, error) {
		n++
		return nil, errors.New("down")
	})
	c := NewCache(zerolog.Nop(), f, time.Hour)

	p, err := c.LoadWithRetry(context.Background(), "p", fastBackoff, 4)
	if err == nil {
		t.Fatal("want an error after give-up, so the caller falls through to NoPolicyBehavior")
	}
	if p != nil {
		t.Errorf("want nil policy on give-up, got %v", p)
	}
	if n != 4 {
		t.Errorf("fetch attempts = %d, want exactly maxAttempts=4 (bounded, no infinite loop)", n)
	}
}

// Redis reconnect (GAP-012): the loop reconnects across drops and RE-FETCHES on
// each reconnect (the staleness fix), and stops cleanly on context cancel.
func TestReconnectLoopRefetchesAndStops(t *testing.T) {
	fetches := 0
	f := funcFetcher(func(context.Context, string) ([]byte, error) {
		fetches++
		return validPolicyJSON, nil
	})
	c := NewCache(zerolog.Nop(), f, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	subs := 0
	subscribe := func(context.Context) error {
		subs++
		if subs >= 3 { // stop after two reconnects
			cancel()
			return context.Canceled
		}
		return errors.New("channel closed") // simulate a Redis drop
	}

	c.reconnectLoop(ctx, "p", fastBackoff, subscribe)

	if subs < 3 {
		t.Errorf("subscribe called %d times, want >=3 — it must reconnect after a drop, not give up", subs)
	}
	if fetches < 2 {
		t.Errorf("re-fetch (Load) called %d times, want >=2 — one per reconnect is the staleness fix", fetches)
	}
}

func TestReconnectLoopExitsImmediatelyIfContextDone(t *testing.T) {
	c := NewCache(zerolog.Nop(), funcFetcher(func(context.Context, string) ([]byte, error) {
		return validPolicyJSON, nil
	}), time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	subs := 0
	c.reconnectLoop(ctx, "p", fastBackoff, func(context.Context) error { subs++; return nil })
	if subs != 0 {
		t.Errorf("subscribe called %d times on an already-cancelled ctx, want 0", subs)
	}
}
