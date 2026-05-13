package management

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

// KillSwitchCommand is a server-side directive the agent must honor
// immediately. Commands are pulled via long-poll rather than WebSocket
// to simplify the wire — long-poll works through every load balancer,
// is trivially proxy-able, and survives short network interruptions
// without reconnection logic.
type KillSwitchCommand struct {
	// One of: "block_all" | "unblock_all" | "block_asset" |
	// "unblock_asset" | "disable_tool" | "enable_tool" | "downgrade_model".
	Type      string `json:"type"`
	AssetID   string `json:"asset_id,omitempty"`
	ToolName  string `json:"tool_name,omitempty"`
	IssuedAt  string `json:"issued_at"`
	IssuedBy  string `json:"issued_by,omitempty"`
	CommandID string `json:"command_id"`
}

// KillSwitchState is the agent-local set of currently-active overrides.
// The proxy hot path consults this BEFORE invoking the policy pipeline
// so kill-switch commands take effect in microseconds, regardless of
// what the cached policy says.
type KillSwitchState struct {
	blockAll       atomic.Bool
	blockedAssets  *concurrentSet
	disabledTools  *concurrentSet
}

// NewKillSwitchState returns an empty state.
func NewKillSwitchState() *KillSwitchState {
	return &KillSwitchState{
		blockedAssets: newConcurrentSet(),
		disabledTools: newConcurrentSet(),
	}
}

// ShouldBlock returns (true, reason) when the kill switch state says
// to reject a request. Cheap — no allocations in the hot path when
// all fields are empty.
func (s *KillSwitchState) ShouldBlock(assetID, toolName string) (bool, string) {
	if s.blockAll.Load() {
		return true, "kill_switch:block_all"
	}
	if assetID != "" && s.blockedAssets.Has(assetID) {
		return true, "kill_switch:asset_blocked"
	}
	if toolName != "" && s.disabledTools.Has(toolName) {
		return true, "kill_switch:tool_disabled"
	}
	return false, ""
}

// Apply mutates the state to reflect a single command. Idempotent.
func (s *KillSwitchState) Apply(cmd KillSwitchCommand) {
	switch cmd.Type {
	case "block_all":
		s.blockAll.Store(true)
	case "unblock_all":
		s.blockAll.Store(false)
	case "block_asset":
		if cmd.AssetID != "" {
			s.blockedAssets.Add(cmd.AssetID)
		}
	case "unblock_asset":
		s.blockedAssets.Remove(cmd.AssetID)
	case "disable_tool":
		if cmd.ToolName != "" {
			s.disabledTools.Add(cmd.ToolName)
		}
	case "enable_tool":
		s.disabledTools.Remove(cmd.ToolName)
	}
}

// Snapshot returns a serializable view for /metrics.
func (s *KillSwitchState) Snapshot() map[string]any {
	return map[string]any{
		"block_all":          s.blockAll.Load(),
		"blocked_assets":     s.blockedAssets.List(),
		"disabled_tools":     s.disabledTools.List(),
	}
}

// ─────────────────────────────────────────── poller

// KillSwitchPoller pulls commands from the control plane on a long-poll
// loop. The control plane's /v1/runtime/control endpoint blocks until
// a command is ready OR the long-poll timeout elapses; the agent then
// reconnects immediately.
type KillSwitchPoller struct {
	Log        zerolog.Logger
	BaseURL    string
	APIKey     string
	AgentID    string
	HTTPClient *http.Client
	State      *KillSwitchState
	Timeout    time.Duration

	lastAck atomic.Pointer[string]
}

// NewKillSwitchPoller constructs a poller bound to the given state.
func NewKillSwitchPoller(
	log zerolog.Logger,
	baseURL, apiKey, agentID string,
	state *KillSwitchState,
) *KillSwitchPoller {
	return &KillSwitchPoller{
		Log:        log,
		BaseURL:    baseURL,
		APIKey:     apiKey,
		AgentID:    agentID,
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
		State:      state,
		Timeout:    30 * time.Second,
	}
}

// Run blocks until ctx is cancelled. On every iteration: long-poll the
// control endpoint, apply any commands returned, then immediately
// re-poll. On transport errors, back off for 5 seconds.
func (p *KillSwitchPoller) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := p.pollOnce(ctx); err != nil {
			p.Log.Debug().Err(err).Msg("killswitch_poll_error")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (p *KillSwitchPoller) pollOnce(ctx context.Context) error {
	url := fmt.Sprintf(
		"%s/v1/runtime/control?agent_id=%s&timeout_seconds=%d",
		p.BaseURL,
		p.AgentID,
		int(p.Timeout.Seconds()),
	)
	if ack := p.lastAck.Load(); ack != nil && *ack != "" {
		url += "&ack=" + *ack
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if p.APIKey != "" {
		req.Header.Set("X-API-Key", p.APIKey)
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil // no commands; immediate re-poll
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	var body struct {
		Commands []KillSwitchCommand `json:"commands"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}
	for _, cmd := range body.Commands {
		p.State.Apply(cmd)
		p.Log.Info().
			Str("type", cmd.Type).
			Str("command_id", cmd.CommandID).
			Str("asset_id", cmd.AssetID).
			Str("tool_name", cmd.ToolName).
			Msg("killswitch_command_applied")
		ack := cmd.CommandID
		p.lastAck.Store(&ack)
	}
	return nil
}

// ─────────────────────────────────────────── concurrent set helper

type concurrentSet struct {
	m atomic.Pointer[map[string]struct{}]
}

func newConcurrentSet() *concurrentSet {
	s := &concurrentSet{}
	empty := map[string]struct{}{}
	s.m.Store(&empty)
	return s
}

func (s *concurrentSet) Has(k string) bool {
	if k == "" {
		return false
	}
	m := s.m.Load()
	if m == nil {
		return false
	}
	_, ok := (*m)[k]
	return ok
}

func (s *concurrentSet) Add(k string) {
	for {
		old := s.m.Load()
		var src map[string]struct{}
		if old != nil {
			src = *old
		}
		next := make(map[string]struct{}, len(src)+1)
		for v := range src {
			next[v] = struct{}{}
		}
		next[k] = struct{}{}
		if s.m.CompareAndSwap(old, &next) {
			return
		}
	}
}

func (s *concurrentSet) Remove(k string) {
	for {
		old := s.m.Load()
		if old == nil {
			return
		}
		src := *old
		if _, ok := src[k]; !ok {
			return
		}
		next := make(map[string]struct{}, len(src)-1)
		for v := range src {
			if v != k {
				next[v] = struct{}{}
			}
		}
		if s.m.CompareAndSwap(old, &next) {
			return
		}
	}
}

func (s *concurrentSet) List() []string {
	m := s.m.Load()
	if m == nil {
		return nil
	}
	out := make([]string, 0, len(*m))
	for k := range *m {
		out = append(out, k)
	}
	return out
}
