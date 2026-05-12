package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// PolicyFetcher returns a JSON-encoded policy from the control plane.
// Real impl hits GET /v1/policies/{id}; tests inject a fake.
type PolicyFetcher interface {
	Fetch(ctx context.Context, policyID string) ([]byte, error)
}

// Cache is the runtime agent's in-process snapshot store. Reads are
// lock-free (atomic.Pointer); writes happen on Redis pub/sub messages
// or explicit Load calls. The stale-cache grace period determines how
// long a policy stays usable after Redis becomes unreachable.
type Cache struct {
	log     zerolog.Logger
	fetcher PolicyFetcher

	mu       sync.RWMutex
	policies map[string]*atomic.Pointer[CompiledPolicy]
	loadedAt map[string]time.Time

	staleGracePeriod time.Duration
}

// NewCache constructs an empty cache with the given fetcher and grace
// period. A grace period of 5 minutes is the platform default.
func NewCache(log zerolog.Logger, fetcher PolicyFetcher, stale time.Duration) *Cache {
	if stale <= 0 {
		stale = 5 * time.Minute
	}
	return &Cache{
		log:              log.With().Str("component", "policy_cache").Logger(),
		fetcher:          fetcher,
		policies:         make(map[string]*atomic.Pointer[CompiledPolicy]),
		loadedAt:         make(map[string]time.Time),
		staleGracePeriod: stale,
	}
}

// Get returns the currently-cached policy for an ID, or nil if not
// loaded. Lock-free in the common case.
func (c *Cache) Get(policyID string) *CompiledPolicy {
	c.mu.RLock()
	ptr, ok := c.policies[policyID]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	return ptr.Load()
}

// Load fetches a policy from the control plane and swaps it into the
// cache. Atomic — concurrent readers see either the old or new policy,
// never a partial.
func (c *Cache) Load(ctx context.Context, policyID string) (*CompiledPolicy, error) {
	data, err := c.fetcher.Fetch(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("fetch policy %s: %w", policyID, err)
	}
	compiled, err := CompileFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("compile policy %s: %w", policyID, err)
	}
	c.swap(policyID, compiled)
	c.log.Info().
		Str("policy_id", policyID).
		Int("version", compiled.Version).
		Msg("policy_cache_loaded")
	return compiled, nil
}

// Evict removes a policy from the cache. Called when the subscriber
// receives a delete invalidation message.
func (c *Cache) Evict(policyID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.policies[policyID]
	delete(c.policies, policyID)
	delete(c.loadedAt, policyID)
	return ok
}

// IsStale reports whether the cached policy is older than the grace
// period. Callers combine this with the policy's FailBehavior to decide
// whether to allow or block on stale reads.
func (c *Cache) IsStale(policyID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	loaded, ok := c.loadedAt[policyID]
	if !ok {
		return true
	}
	return time.Since(loaded) > c.staleGracePeriod
}

// LoadedAt returns when the policy was last refreshed, or zero time.
func (c *Cache) LoadedAt(policyID string) time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loadedAt[policyID]
}

func (c *Cache) swap(policyID string, p *CompiledPolicy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ptr, ok := c.policies[policyID]
	if !ok {
		ptr = &atomic.Pointer[CompiledPolicy]{}
		c.policies[policyID] = ptr
	}
	ptr.Store(p)
	c.loadedAt[policyID] = time.Now()
}

// Subscribe subscribes to the org's Redis invalidation channel and
// refreshes the cache on every message. Blocks until ctx is cancelled.
// Wire-compatible with backend/app/services/policy_pubsub.py.
func (c *Cache) Subscribe(ctx context.Context, rdb *redis.Client, orgID string) error {
	channel := fmt.Sprintf("policy:invalidation:%s", orgID)
	pubsub := rdb.Subscribe(ctx, channel)
	defer pubsub.Close()

	c.log.Info().Str("channel", channel).Msg("policy_cache_subscriber_started")
	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-ch:
			if !ok {
				return fmt.Errorf("policy_cache_subscriber_channel_closed")
			}
			c.handleMessage(ctx, msg.Payload)
		}
	}
}

// invalidationMsg is the JSON payload the Python control plane
// publishes. Must stay in lockstep with
// backend/app/services/policy_pubsub.py::publish_policy_change.
type invalidationMsg struct {
	PolicyID string `json:"policy_id"`
	Version  int    `json:"version"`
	Event    string `json:"event"` // "create" | "update" | "delete"
}

func (c *Cache) handleMessage(ctx context.Context, payload string) {
	var msg invalidationMsg
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		c.log.Warn().Err(err).Str("payload", payload).Msg("policy_cache_bad_payload")
		return
	}
	if msg.Event == "delete" {
		evicted := c.Evict(msg.PolicyID)
		c.log.Info().
			Str("policy_id", msg.PolicyID).
			Bool("was_present", evicted).
			Msg("policy_cache_evicted")
		return
	}
	if _, err := c.Load(ctx, msg.PolicyID); err != nil {
		c.log.Error().Err(err).
			Str("policy_id", msg.PolicyID).
			Msg("policy_cache_refresh_failed")
	}
}

// ─────────────────────────────────────────── HTTPFetcher

// HTTPFetcher is the production PolicyFetcher — hits the control plane.
type HTTPFetcher struct {
	BaseURL    string
	HTTPClient *http.Client
	APIKey     string
}

// Fetch retrieves the policy JSON. The control plane's
// GET /v1/policies/{id} requires viewer-or-above role; the agent
// authenticates with an API key created via /v1/admin/idp-configs.
func (f *HTTPFetcher) Fetch(ctx context.Context, policyID string) ([]byte, error) {
	url := fmt.Sprintf("%s/v1/policies/%s", f.BaseURL, policyID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if f.APIKey != "" {
		req.Header.Set("X-API-Key", f.APIKey)
	}

	client := f.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}
	return body, nil
}
