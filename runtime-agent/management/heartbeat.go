package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/telemetry"
)

// HeartbeatConfig wires the heartbeat goroutine.
type HeartbeatConfig struct {
	Log         zerolog.Logger
	BaseURL     string
	APIKey      string
	AgentID     string
	OrgID       string
	Version     string
	PolicyID    string
	Cache       *policy.Cache
	Telemetry   *telemetry.Buffer
	Interval    time.Duration
	HTTPClient  *http.Client
}

// HeartbeatRunner emits periodic POSTs to /v1/runtime/heartbeat so the
// control plane can show "this agent is alive" in the runtime monitoring
// dashboard. Heartbeats also carry policy_version so the control plane
// can flag agents lagging behind on policy updates.
type HeartbeatRunner struct {
	cfg HeartbeatConfig
}

// NewHeartbeatRunner constructs a runner. Interval defaults to 30s when
// the caller passes zero.
func NewHeartbeatRunner(cfg HeartbeatConfig) *HeartbeatRunner {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &HeartbeatRunner{cfg: cfg}
}

// Run blocks until ctx is cancelled, emitting one heartbeat per interval.
// Failed heartbeats are logged but never crash the runner; the control
// plane treats absence of heartbeats as the alert signal, not error
// responses.
func (r *HeartbeatRunner) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()

	// Emit one immediately so the dashboard sees the agent on first start.
	r.emit(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			r.emit(ctx)
		}
	}
}

func (r *HeartbeatRunner) emit(ctx context.Context) {
	policyVersion := 0
	if compiled := r.cfg.Cache.Get(r.cfg.PolicyID); compiled != nil {
		policyVersion = compiled.Version
	}
	policyLoadedAt := r.cfg.Cache.LoadedAt(r.cfg.PolicyID)
	stats := r.cfg.Telemetry.Stats()

	payload := map[string]any{
		"agent_id":         r.cfg.AgentID,
		"org_id":           r.cfg.OrgID,
		"version":          r.cfg.Version,
		"policy_id":        r.cfg.PolicyID,
		"policy_version":   policyVersion,
		"policy_loaded_at": policyLoadedAt.UTC().Format(time.RFC3339Nano),
		"policy_stale":     r.cfg.Cache.IsStale(r.cfg.PolicyID),
		"counters": map[string]any{
			"telemetry_enqueued": stats.Enqueued,
			"telemetry_uploaded": stats.Uploaded,
			"telemetry_dropped":  stats.Dropped,
			"telemetry_pending":  stats.Pending,
		},
		"emitted_at": time.Now().UTC().Format(time.RFC3339Nano),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		r.cfg.Log.Warn().Err(err).Msg("heartbeat_marshal_failed")
		return
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		r.cfg.BaseURL+"/v1/runtime/heartbeat",
		bytes.NewReader(body),
	)
	if err != nil {
		r.cfg.Log.Warn().Err(err).Msg("heartbeat_request_build_failed")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if r.cfg.APIKey != "" {
		req.Header.Set("X-API-Key", r.cfg.APIKey)
	}

	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		r.cfg.Log.Debug().Err(err).Msg("heartbeat_post_failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		r.cfg.Log.Debug().
			Int("status", resp.StatusCode).
			Msg("heartbeat_non_2xx")
		return
	}
	r.cfg.Log.Debug().
		Int("policy_version", policyVersion).
		Msg("heartbeat_sent")
}

// FormatHeartbeatURL is exposed for diagnostic tooling that wants to
// show the heartbeat endpoint the agent uses.
func FormatHeartbeatURL(baseURL string) string {
	return fmt.Sprintf("%s/v1/runtime/heartbeat", baseURL)
}
