package policy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// End-to-end pub/sub tests against a real (in-memory) Redis, so the confirm →
// catch-up → receive ordering is exercised over an actual SUBSCRIBE/PUBLISH, not
// a fake.

type recordingFetcher struct {
	mu  sync.Mutex
	ids []string
}

func (r *recordingFetcher) Fetch(_ context.Context, id string) ([]byte, error) {
	r.mu.Lock()
	r.ids = append(r.ids, id)
	r.mu.Unlock()
	return []byte(`{"id":"` + id + `","org_id":"o","version":1,"enforcement_level":"fast","fail_behavior":"open"}`), nil
}

func (r *recordingFetcher) fetched(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.ids {
		if x == id {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, cond func() bool, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", within)
}

func TestSubscribeCatchesInvalidationAfterEstablish(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	rf := &recordingFetcher{}
	c := NewCache(zerolog.Nop(), rf, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	go func() { _ = c.Subscribe(ctx, rdb, "o", func() error { close(ready); return nil }) }()
	<-ready // subscription confirmed live + onReady ran

	if err := rdb.Publish(ctx, "policy:invalidation:o",
		`{"policy_id":"p1","version":2,"event":"update"}`).Err(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return rf.fetched("p1") }, 2*time.Second)
}

// TestSubscribePublishDuringCatchupIsCaught is the regression test for the
// reordering fix: a publish that lands DURING the catch-up window (onReady) must
// be caught. Under the old fetch-then-subscribe order the subscription was not
// yet live during catch-up, so such a publish was lost; under confirm-then-
// catch-up it is buffered on the connection and delivered by the receive loop.
func TestSubscribePublishDuringCatchupIsCaught(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	rf := &recordingFetcher{}
	c := NewCache(zerolog.Nop(), rf, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The subscription is already confirmed live when onReady runs, so this
	// publish (representing an invalidation racing the catch-up) is buffered and
	// delivered by the receive loop after onReady returns.
	onReady := func() error {
		return rdb.Publish(ctx, "policy:invalidation:o",
			`{"policy_id":"p2","version":3,"event":"update"}`).Err()
	}
	go func() { _ = c.Subscribe(ctx, rdb, "o", onReady) }()

	waitFor(t, func() bool { return rf.fetched("p2") }, 2*time.Second)
}
