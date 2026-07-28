package backoff

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBaseDelayGrowsAndCaps(t *testing.T) {
	c := Config{Base: 100 * time.Millisecond, Max: 1 * time.Second, Factor: 2}
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 100 * time.Millisecond},
		{1, 200 * time.Millisecond},
		{2, 400 * time.Millisecond},
		{3, 800 * time.Millisecond},
		{4, 1 * time.Second}, // 1600ms capped to Max
		{10, 1 * time.Second},
	}
	for _, tc := range cases {
		if got := c.baseDelay(tc.attempt); got != tc.want {
			t.Errorf("baseDelay(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestZeroValueConfigIsSanitizedNotAHotLoop(t *testing.T) {
	// A Config nobody filled in must never yield a 0 delay — that would turn a
	// reconnect loop into a busy spin against the control plane.
	var zero Config
	if d := zero.baseDelay(0); d <= 0 {
		t.Fatalf("zero-value baseDelay(0) = %v, want a sane positive default", d)
	}
	// And it still grows and caps.
	if zero.baseDelay(0) >= zero.baseDelay(3) {
		t.Errorf("zero-value config should still grow with attempts")
	}
	if got := zero.baseDelay(100); got > 30*time.Second {
		t.Errorf("zero-value baseDelay must cap, got %v", got)
	}
}

func TestDelayStaysWithinFullJitterBounds(t *testing.T) {
	c := Config{Base: 200 * time.Millisecond, Max: 1 * time.Second, Factor: 2}
	for attempt := 0; attempt < 6; attempt++ {
		base := c.baseDelay(attempt)
		for range 200 {
			d := c.Delay(attempt)
			if d < 0 || d > base {
				t.Fatalf("Delay(%d) = %v out of full-jitter bounds [0, %v]", attempt, d, base)
			}
		}
	}
}

func TestRetrySucceedsAfterTransientFailures(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), Config{Base: time.Millisecond, Max: 5 * time.Millisecond, Factor: 2}, 5,
		func(context.Context) error {
			calls++
			if calls < 3 {
				return errors.New("transient")
			}
			return nil
		})
	if err != nil {
		t.Fatalf("want success after transient failures, got %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestRetryGivesUpBounded(t *testing.T) {
	calls := 0
	want := errors.New("always")
	err := Retry(context.Background(), Config{Base: time.Millisecond, Max: 2 * time.Millisecond, Factor: 2}, 4,
		func(context.Context) error { calls++; return want })
	if !errors.Is(err, want) {
		t.Errorf("want the last error returned, got %v", err)
	}
	if calls != 4 {
		t.Errorf("calls = %d, want exactly maxAttempts=4 (bounded, no infinite loop)", calls)
	}
}

func TestRetryStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	go func() { time.Sleep(5 * time.Millisecond); cancel() }()
	err := Retry(ctx, Config{Base: 50 * time.Millisecond, Max: time.Second, Factor: 2}, 100,
		func(context.Context) error { calls++; return errors.New("fail") })
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled, got %v", err)
	}
	if calls > 3 {
		t.Errorf("calls = %d — should have stopped promptly on cancel", calls)
	}
}
