// Package backoff is the agent's one jittered, capped exponential-backoff
// primitive — shared by the two retry paths Phase 2 increment 5 closes
// (cold-start policy load and Redis subscriber reconnect) so the timing policy
// lives in one place with one test.
//
// Jitter is AWS "full jitter" (delay uniform in [0, base]): it spreads a
// reconnect storm across a fleet far better than a fixed or equal-jitter delay,
// which matter the moment more than one agent reconnects to the same control
// plane at once.
package backoff

import (
	"context"
	"math"
	"math/rand"
	"time"
)

// Config is a capped exponential schedule. Base is the (pre-jitter) delay before
// the first retry; each subsequent attempt multiplies by Factor, capped at Max.
type Config struct {
	Base   time.Duration
	Max    time.Duration
	Factor float64
}

// baseDelay is the un-jittered, capped delay for a 0-based attempt number.
func (c Config) baseDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := float64(c.Base) * math.Pow(c.Factor, float64(attempt))
	if math.IsInf(d, 1) || d > float64(c.Max) {
		return c.Max
	}
	return time.Duration(d)
}

// Delay returns the jittered delay for an attempt: uniform in [0, baseDelay].
func (c Config) Delay(attempt int) time.Duration {
	base := int64(c.baseDelay(attempt))
	if base <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(base + 1))
}

// Retry calls fn until it returns nil, ctx is cancelled, or maxAttempts is
// reached; it returns the last error on give-up. It is BOUNDED on purpose —
// callers that must eventually proceed (cold-start policy load composes with
// AGENT_NO_POLICY_BEHAVIOR: backoff-then-proceed, never backoff-forever) use
// this; a caller that must retry indefinitely (the reconnect loop) drives Delay
// itself.
func Retry(ctx context.Context, cfg Config, maxAttempts int, fn func(context.Context) error) error {
	var last error
	for attempt := 0; ; attempt++ {
		if last = fn(ctx); last == nil {
			return nil
		}
		if attempt >= maxAttempts-1 {
			return last
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.Delay(attempt)):
		}
	}
}
