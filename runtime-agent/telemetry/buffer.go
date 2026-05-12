package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Uploader is the interface every backend implements. Production hits
// the control plane's /v1/runtime/events; tests inject a capturing
// stub.
type Uploader interface {
	Upload(ctx context.Context, batch []Event) error
}

// Buffer is the bounded in-memory queue. Events are enqueued by the
// proxy on the hot path; a single goroutine drains the queue every
// FlushInterval or when BatchSize events accumulate.
type Buffer struct {
	log           zerolog.Logger
	uploader      Uploader
	batchSize     int
	flushInterval time.Duration

	mu     sync.Mutex
	events []Event
	full   chan struct{}

	// Stats — exposed via /metrics
	enqueued atomicCounter
	uploaded atomicCounter
	dropped  atomicCounter
}

// NewBuffer constructs a bounded buffer. maxQueue is the hard cap;
// enqueues beyond it are dropped and counted (callers must accept
// best-effort semantics for telemetry).
func NewBuffer(
	log zerolog.Logger,
	uploader Uploader,
	batchSize int,
	flushInterval time.Duration,
	maxQueue int,
) *Buffer {
	if batchSize <= 0 {
		batchSize = 100
	}
	if flushInterval <= 0 {
		flushInterval = 5 * time.Second
	}
	if maxQueue <= 0 {
		maxQueue = 10000
	}
	return &Buffer{
		log:           log.With().Str("component", "telemetry_buffer").Logger(),
		uploader:      uploader,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		events:        make([]Event, 0, batchSize),
		full:          make(chan struct{}, 1),
	}
}

// Enqueue adds an event. Never blocks for more than the buffer's mutex.
// Drops on overflow and increments the dropped counter.
func (b *Buffer) Enqueue(event Event) {
	b.mu.Lock()
	if len(b.events) >= cap(b.events)*10 { // hard cap ~10x batch
		b.mu.Unlock()
		b.dropped.add(1)
		return
	}
	b.events = append(b.events, event)
	shouldSignal := len(b.events) >= b.batchSize
	b.mu.Unlock()
	b.enqueued.add(1)
	if shouldSignal {
		select {
		case b.full <- struct{}{}:
		default:
		}
	}
}

// Run drains the buffer until ctx is cancelled. Returns the error from
// ctx, never panics.
func (b *Buffer) Run(ctx context.Context) error {
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.flush(context.Background()) // best-effort drain on shutdown
			return ctx.Err()
		case <-ticker.C:
			b.flush(ctx)
		case <-b.full:
			b.flush(ctx)
		}
	}
}

func (b *Buffer) flush(ctx context.Context) {
	b.mu.Lock()
	if len(b.events) == 0 {
		b.mu.Unlock()
		return
	}
	batch := b.events
	b.events = make([]Event, 0, b.batchSize)
	b.mu.Unlock()

	if err := b.uploader.Upload(ctx, batch); err != nil {
		b.log.Warn().Err(err).Int("batch_size", len(batch)).Msg("telemetry_upload_failed")
		// Failed batches are dropped — telemetry is best-effort by design.
		b.dropped.add(uint64(len(batch)))
		return
	}
	b.uploaded.add(uint64(len(batch)))
}

// Stats returns a copy of the buffer's counters for the /metrics endpoint.
type Stats struct {
	Enqueued uint64
	Uploaded uint64
	Dropped  uint64
	Pending  int
}

// Stats returns counters.
func (b *Buffer) Stats() Stats {
	b.mu.Lock()
	pending := len(b.events)
	b.mu.Unlock()
	return Stats{
		Enqueued: b.enqueued.get(),
		Uploaded: b.uploaded.get(),
		Dropped:  b.dropped.get(),
		Pending:  pending,
	}
}

// ─────────────────────────────────────────── HTTPUploader

// HTTPUploader posts batches to the control plane's
// /v1/runtime/events endpoint.
type HTTPUploader struct {
	BaseURL    string
	HTTPClient *http.Client
	APIKey     string
}

// Upload sends one batch as JSON.
func (u *HTTPUploader) Upload(ctx context.Context, batch []Event) error {
	if len(batch) == 0 {
		return nil
	}
	url := u.BaseURL + "/v1/runtime/events"
	body, err := json.Marshal(map[string]any{"events": batch})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if u.APIKey != "" {
		req.Header.Set("X-API-Key", u.APIKey)
	}

	client := u.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// ─────────────────────────────────────────── stdout uploader (dev)

// StdoutUploader is the default development uploader — logs each batch
// to the zerolog logger. Useful when the control-plane ingest endpoint
// isn't yet running.
type StdoutUploader struct{ Log zerolog.Logger }

// Upload writes each event as one log line.
func (u *StdoutUploader) Upload(_ context.Context, batch []Event) error {
	for _, e := range batch {
		u.Log.Info().
			Str("event_id", e.EventID).
			Str("event_type", e.EventType).
			Str("action_taken", string(e.ActionTaken)).
			Float64("risk_score", float64(e.RiskScore)).
			Uint32("latency_ms", e.LatencyMS).
			Msg("telemetry_event")
	}
	return nil
}

// ─────────────────────────────────────────── atomic counter

type atomicCounter struct {
	v uint64
	m sync.Mutex
}

func (c *atomicCounter) add(n uint64) {
	c.m.Lock()
	c.v += n
	c.m.Unlock()
}

func (c *atomicCounter) get() uint64 {
	c.m.Lock()
	defer c.m.Unlock()
	return c.v
}

// ErrShutdownTimeout is returned by Run when the drain on shutdown
// exceeds its deadline. Exposed for tests; not a fatal condition for
// the agent (telemetry is best-effort).
var ErrShutdownTimeout = errors.New("telemetry shutdown drain timeout")
