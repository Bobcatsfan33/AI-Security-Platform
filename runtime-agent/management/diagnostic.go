// Package management exposes the agent's introspection endpoints on a
// localhost-only diagnostic port. Operators hit these from the
// surrounding pod or sidecar for health checks, readiness probes, and
// Prometheus metrics scraping.
package management

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/telemetry"
)

// DiagnosticHandler returns an http.Handler exposing /healthz, /readyz,
// and /metrics. Bind it to localhost:<diag_port> separately from the
// proxy port so the diagnostic surface isn't reachable from the
// customer's network.
func DiagnosticHandler(
	cache *policy.Cache,
	buf *telemetry.Buffer,
	policyID string,
	version string,
) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"version": version,
		})
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		ready := cache.Get(policyID) != nil
		w.Header().Set("Content-Type", "application/json")
		status := "ready"
		code := http.StatusOK
		if !ready {
			status = "policy_not_loaded"
			code = http.StatusServiceUnavailable
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":         status,
			"policy_id":      policyID,
			"policy_loaded":  ready,
			"policy_stale":   cache.IsStale(policyID),
			"loaded_at":      cache.LoadedAt(policyID),
		})
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		stats := buf.Stats()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		// Prometheus exposition format. Keeps the metric set minimal —
		// extending it is a Sprint 7 follow-on.
		writeMetric(w, "platform_agent_telemetry_enqueued_total", stats.Enqueued)
		writeMetric(w, "platform_agent_telemetry_uploaded_total", stats.Uploaded)
		writeMetric(w, "platform_agent_telemetry_dropped_total", stats.Dropped)
		writeMetric(w, "platform_agent_telemetry_pending", uint64(stats.Pending))
		writeMetric(w, "platform_agent_policy_stale", boolMetric(cache.IsStale(policyID)))
		writeMetric(w, "platform_agent_uptime_seconds", uint64(time.Since(startedAt).Seconds()))
	})

	return mux
}

var startedAt = time.Now()

func writeMetric(w http.ResponseWriter, name string, v uint64) {
	_, _ = w.Write([]byte(name))
	_, _ = w.Write([]byte(" "))
	_, _ = w.Write([]byte(formatUint(v)))
	_, _ = w.Write([]byte("\n"))
}

func boolMetric(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func formatUint(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
