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
