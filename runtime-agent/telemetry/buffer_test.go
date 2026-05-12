package telemetry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type captureUploader struct {
	mu       sync.Mutex
	batches  [][]Event
	failNext int
}

func (u *captureUploader) Upload(_ context.Context, batch []Event) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.failNext > 0 {
		u.failNext--
		return errors.New("simulated failure")
	}
	cp := make([]Event, len(batch))
	copy(cp, batch)
	u.batches = append(u.batches, cp)
	return nil
}

func (u *captureUploader) totalUploaded() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, b := range u.batches {
		n += len(b)
	}
	return n
}

func TestBufferDrainOnInterval(t *testing.T) {
	logger := zerolog.Nop()
	up := &captureUploader{}
	buf := NewBuffer(logger, up, 100, 50*time.Millisecond, 1000)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = buf.Run(ctx)
		close(done)
	}()

	for i := 0; i < 3; i++ {
		buf.Enqueue(Event{EventID: "e"})
	}
	time.Sleep(150 * time.Millisecond) // wait for at least one flush

	if got := up.totalUploaded(); got != 3 {
		t.Errorf("uploaded: got %d, want 3", got)
	}
}

func TestBufferDrainOnBatchSize(t *testing.T) {
	logger := zerolog.Nop()
	up := &captureUploader{}
	buf := NewBuffer(logger, up, 3, 10*time.Second, 1000)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = buf.Run(ctx)
		close(done)
	}()

	for i := 0; i < 3; i++ {
		buf.Enqueue(Event{EventID: "e"})
	}
	// Batch threshold reached → flush should fire well before the
	// 10-second interval
	time.Sleep(100 * time.Millisecond)
	if got := up.totalUploaded(); got != 3 {
		t.Errorf("uploaded: got %d, want 3 (batch-size trigger)", got)
	}
}

func TestBufferFailedUploadIncrementsDropped(t *testing.T) {
	logger := zerolog.Nop()
	up := &captureUploader{failNext: 1}
	buf := NewBuffer(logger, up, 1, 10*time.Millisecond, 1000)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = buf.Run(ctx) }()

	buf.Enqueue(Event{EventID: "e"})
	time.Sleep(50 * time.Millisecond)

	if stats := buf.Stats(); stats.Dropped == 0 {
		t.Errorf("expected dropped > 0 after failed upload; got %+v", stats)
	}
}

func TestBufferStatsTrackEnqueue(t *testing.T) {
	logger := zerolog.Nop()
	up := &captureUploader{}
	buf := NewBuffer(logger, up, 1000, 1*time.Second, 1000)
	for i := 0; i < 5; i++ {
		buf.Enqueue(Event{EventID: "e"})
	}
	s := buf.Stats()
	if s.Enqueued != 5 {
		t.Errorf("enqueued: got %d, want 5", s.Enqueued)
	}
	if s.Pending != 5 {
		t.Errorf("pending: got %d, want 5", s.Pending)
	}
}
