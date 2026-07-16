// Agent entrypoint — wires config, policy cache, telemetry buffer,
// reverse proxy, and diagnostic endpoints. Two HTTP listeners:
//   - proxy on :8400 (configurable; faces customer traffic)
//   - diagnostic on localhost:8401 (configurable; for ops only)
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/internal/controlplane"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/management"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/proxy"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/telemetry"
)

const agentVersion = "0.1.0-sprint7-starter"

type config struct {
	bindProxy        string
	bindDiagnostic   string
	platformURL      string
	redisURL         string
	orgID            string
	policyID         string
	agentID          string
	environment      string
	platformAPIKey   string
	staleGracePeriod time.Duration

	// Control-plane mTLS (A-4). When all three are set, agent → control-plane
	// calls use a client-cert-authenticated, platform-CA-pinned client with
	// hot-reload; unset → the default client (backward compatible).
	controlPlaneCAPath   string
	controlPlaneCertPath string
	controlPlaneKeyPath  string

	upstreamOpenAI    string
	upstreamAnthropic string
	upstreamAzure     string
	upstreamBedrock   string

	// Inline Stage 2/3 backends. Empty → zero-config heuristic / deterministic
	// engine; set an endpoint to use the ONNX inference sidecar / LLM judge.
	stage2Endpoint string
	stage2Timeout  time.Duration
	stage3Endpoint string
	stage3Timeout  time.Duration
	// Run the full AI Guard 18-detector suite inline at Stage 2.
	useDetectorSuite bool

	// Cold-start posture: what to do when NO policy is cached and the control
	// plane is unreachable. "" → resolved from environment (see
	// proxy.ResolveNoPolicyBehavior). GAP-003.
	noPolicyBehavior string
}

func loadConfig() config {
	return config{
		bindProxy:            envOr("AGENT_BIND", ":8400"),
		bindDiagnostic:       envOr("AGENT_DIAG_BIND", "127.0.0.1:8401"),
		platformURL:          envOr("PLATFORM_URL", "http://localhost:8000"),
		redisURL:             envOr("REDIS_URL", "redis://localhost:6379/0"),
		orgID:                os.Getenv("AGENT_ORG_ID"),
		policyID:             os.Getenv("AGENT_POLICY_ID"),
		agentID:              envOr("AGENT_ID", "agent-default"),
		environment:          envOr("AGENT_ENVIRONMENT", "production"),
		noPolicyBehavior:     os.Getenv("AGENT_NO_POLICY_BEHAVIOR"),
		platformAPIKey:       os.Getenv("AGENT_API_KEY"),
		staleGracePeriod:     parseDuration(envOr("AGENT_STALE_GRACE", "5m")),
		controlPlaneCAPath:   os.Getenv("CONTROL_PLANE_CA_PATH"),
		controlPlaneCertPath: os.Getenv("CONTROL_PLANE_CERT_PATH"),
		controlPlaneKeyPath:  os.Getenv("CONTROL_PLANE_KEY_PATH"),
		upstreamOpenAI:       envOr("UPSTREAM_OPENAI", "https://api.openai.com"),
		upstreamAnthropic:    envOr("UPSTREAM_ANTHROPIC", "https://api.anthropic.com"),
		upstreamAzure:        os.Getenv("UPSTREAM_AZURE"),
		upstreamBedrock:      envOr("UPSTREAM_BEDROCK", "https://bedrock-runtime.us-east-1.amazonaws.com"),
		stage2Endpoint:       os.Getenv("STAGE2_ONNX_ENDPOINT"),
		stage2Timeout:        parseDuration(envOr("STAGE2_TIMEOUT", "150ms")),
		stage3Endpoint:       os.Getenv("STAGE3_JUDGE_ENDPOINT"),
		stage3Timeout:        parseDuration(envOr("STAGE3_TIMEOUT", "3s")),
		useDetectorSuite:     os.Getenv("STAGE2_DETECTOR_SUITE") == "true",
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 5 * time.Minute
	}
	return d
}

// buildControlPlaneClient returns the mTLS HTTP client for control-plane calls
// when the CONTROL_PLANE_* certs are configured, or nil to use each component's
// default client. A partial configuration is fatal: silently falling back to a
// non-mTLS client would be an unflagged security downgrade.
func buildControlPlaneClient(cfg config, log zerolog.Logger) *http.Client {
	set := 0
	for _, p := range []string{cfg.controlPlaneCAPath, cfg.controlPlaneCertPath, cfg.controlPlaneKeyPath} {
		if p != "" {
			set++
		}
	}
	if set == 0 {
		return nil
	}
	if set != 3 {
		log.Fatal().Msg("mTLS partially configured: set all of CONTROL_PLANE_CA_PATH, " +
			"CONTROL_PLANE_CERT_PATH, CONTROL_PLANE_KEY_PATH")
	}
	client, err := controlplane.NewHTTPClient(
		cfg.controlPlaneCAPath, cfg.controlPlaneCertPath, cfg.controlPlaneKeyPath,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("control_plane_mtls_init_failed")
	}
	log.Info().Msg("control_plane_mtls_enabled")
	return client
}

func main() {
	log := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("component", "agent").
		Str("version", agentVersion).
		Logger()

	cfg := loadConfig()
	if cfg.orgID == "" {
		log.Fatal().Msg("AGENT_ORG_ID is required")
	}
	if cfg.policyID == "" {
		log.Fatal().Msg("AGENT_POLICY_ID is required")
	}

	log.Info().
		Str("bind_proxy", cfg.bindProxy).
		Str("bind_diag", cfg.bindDiagnostic).
		Str("platform_url", cfg.platformURL).
		Str("org_id", cfg.orgID).
		Str("policy_id", cfg.policyID).
		Msg("agent_starting")

	rdb, err := newRedis(cfg.redisURL)
	if err != nil {
		log.Fatal().Err(err).Msg("redis_init_failed")
	}
	defer rdb.Close()

	// The single mTLS-pinned client for every control-plane call (nil when not
	// configured → each component uses its default client).
	cpClient := buildControlPlaneClient(cfg, log)

	// Telemetry — for now log to stdout. Production sets an HTTPUploader
	// pointing at the control plane.
	uploader := pickUploader(cfg, log, cpClient)
	buf := telemetry.NewBuffer(log, uploader, 100, 5*time.Second, 10000)

	// Policy cache
	fetcher := &policy.HTTPFetcher{
		BaseURL:    cfg.platformURL,
		APIKey:     cfg.platformAPIKey,
		HTTPClient: cpClient,
	}
	cache := policy.NewCache(log, fetcher, cfg.staleGracePeriod)

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Background goroutines: telemetry drainer + redis subscriber
	go func() {
		if err := buf.Run(rootCtx); err != nil && !errors.Is(err, context.Canceled) {
			log.Error().Err(err).Msg("telemetry_runner_exited")
		}
	}()
	go func() {
		if err := cache.Subscribe(rootCtx, rdb, cfg.orgID); err != nil &&
			!errors.Is(err, context.Canceled) {
			log.Error().Err(err).Msg("policy_subscriber_exited")
		}
	}()

	// Warm load
	if _, err := cache.Load(rootCtx, cfg.policyID); err != nil {
		log.Warn().Err(err).Msg("policy_initial_load_failed")
	}

	pipeline := policy.NewPipeline(policy.StageConfig{
		Stage2Endpoint:   cfg.stage2Endpoint,
		Stage2Timeout:    cfg.stage2Timeout,
		Stage3Endpoint:   cfg.stage3Endpoint,
		Stage3Timeout:    cfg.stage3Timeout,
		UseDetectorSuite: cfg.useDetectorSuite,
	})
	log.Info().
		Bool("stage2_onnx", cfg.stage2Endpoint != "").
		Bool("stage3_judge", cfg.stage3Endpoint != "").
		Msg("inline_pipeline_wired")

	// Kill switch state — emergency commands from the control plane
	killSwitch := management.NewKillSwitchState()
	if cfg.platformAPIKey != "" {
		poller := management.NewKillSwitchPoller(
			log, cfg.platformURL, cfg.platformAPIKey, cfg.agentID, killSwitch,
		)
		if cpClient != nil {
			poller.HTTPClient = cpClient
		}
		go func() {
			if err := poller.Run(rootCtx); err != nil &&
				!errors.Is(err, context.Canceled) {
				log.Error().Err(err).Msg("killswitch_poller_exited")
			}
		}()

		// Heartbeat
		hb := management.NewHeartbeatRunner(management.HeartbeatConfig{
			Log:        log,
			BaseURL:    cfg.platformURL,
			APIKey:     cfg.platformAPIKey,
			AgentID:    cfg.agentID,
			OrgID:      cfg.orgID,
			Version:    agentVersion,
			PolicyID:   cfg.policyID,
			Cache:      cache,
			Telemetry:  buf,
			Interval:   30 * time.Second,
			HTTPClient: cpClient,
		})
		go func() {
			if err := hb.Run(rootCtx); err != nil &&
				!errors.Is(err, context.Canceled) {
				log.Error().Err(err).Msg("heartbeat_runner_exited")
			}
		}()
	}

	upstreams := map[proxy.Provider]string{
		proxy.ProviderOpenAI:    cfg.upstreamOpenAI,
		proxy.ProviderAnthropic: cfg.upstreamAnthropic,
		proxy.ProviderAzure:     cfg.upstreamAzure,
		proxy.ProviderBedrock:   cfg.upstreamBedrock,
	}

	// Cold-start posture (GAP-003). Resolved once, here, so a bad value stops
	// the agent at startup rather than being discovered on the hot path — the
	// same refusal-to-guess as the mTLS partial-config check above.
	noPolicyBehavior, err := proxy.ResolveNoPolicyBehavior(cfg.noPolicyBehavior, cfg.environment)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid AGENT_NO_POLICY_BEHAVIOR")
	}
	log.Info().
		Str("no_policy_behavior", string(noPolicyBehavior)).
		Str("environment", cfg.environment).
		Msg("cold_start_posture_resolved")

	proxyHandler := proxy.Handler(proxy.Config{
		Log:                        log,
		Cache:                      cache,
		Pipeline:                   pipeline,
		Telemetry:                  buf,
		OrgID:                      cfg.orgID,
		AgentID:                    cfg.agentID,
		Environment:                cfg.environment,
		KillSwitch:                 killSwitch,
		PolicyID:                   cfg.policyID,
		UpstreamMap:                upstreams,
		PassthroughOnUnknownFormat: true,
		NoPolicyBehavior:           noPolicyBehavior,
	})

	diagHandler := management.DiagnosticHandler(cache, buf, cfg.policyID, agentVersion)

	proxyServer := &http.Server{
		Addr:              cfg.bindProxy,
		Handler:           proxyHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	diagServer := &http.Server{
		Addr:              cfg.bindDiagnostic,
		Handler:           diagHandler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Info().Str("addr", cfg.bindProxy).Msg("proxy_listening")
		if err := proxyServer.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("proxy_server_crashed")
		}
	}()
	go func() {
		log.Info().Str("addr", cfg.bindDiagnostic).Msg("diag_listening")
		if err := diagServer.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("diag_server_crashed")
		}
	}()

	// Graceful shutdown on SIGINT / SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Info().Msg("agent_shutting_down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = proxyServer.Shutdown(shutdownCtx)
	_ = diagServer.Shutdown(shutdownCtx)
	cancel() // stops telemetry + subscriber goroutines
	log.Info().Msg("agent_stopped")
}

func newRedis(rawURL string) (*redis.Client, error) {
	opts, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	return redis.NewClient(opts), nil
}

func pickUploader(cfg config, log zerolog.Logger, cpClient *http.Client) telemetry.Uploader {
	// In dev / when no API key is configured, log to stdout — the
	// control plane's ingest endpoint is a Sprint 7 follow-on.
	if cfg.platformAPIKey == "" {
		return &telemetry.StdoutUploader{Log: log}
	}
	return &telemetry.HTTPUploader{
		BaseURL:    cfg.platformURL,
		APIKey:     cfg.platformAPIKey,
		HTTPClient: cpClient,
	}
}
