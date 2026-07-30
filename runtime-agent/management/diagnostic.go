// Package management exposes the agent's introspection endpoints on a
// localhost-only diagnostic port. Operators hit these from the
// surrounding pod or sidecar for health checks, readiness probes, and
// Prometheus metrics scraping.
package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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
	killSwitch *KillSwitchState,
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
			"status":        status,
			"policy_id":     policyID,
			"policy_loaded": ready,
			"policy_stale":  cache.IsStale(policyID),
			"loaded_at":     cache.LoadedAt(policyID),
		})
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		stats := buf.Stats()
		security := buf.SecurityStats()
		killSwitchStats := killSwitch.Metrics()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		writePrometheusMetric(w, "platform_agent_telemetry_enqueued_total", "Agent telemetry events accepted by the local buffer.", "counter", stats.Enqueued)
		writePrometheusMetric(w, "platform_agent_telemetry_uploaded_total", "Agent telemetry events uploaded successfully.", "counter", stats.Uploaded)
		writePrometheusMetric(w, "platform_agent_telemetry_dropped_total", "Agent telemetry events dropped due to overflow or upload failure.", "counter", stats.Dropped)
		writePrometheusMetric(w, "platform_agent_telemetry_pending", "Agent telemetry events currently pending upload.", "gauge", uint64(stats.Pending))
		writePrometheusMetric(w, "platform_agent_policy_stale", "Whether the active policy cache is stale.", "gauge", boolMetric(cache.IsStale(policyID)))
		writePrometheusMetric(w, "platform_agent_uptime_seconds", "Agent process uptime in seconds.", "gauge", uint64(time.Since(startedAt).Seconds()))

		writeHelpType(w, "platform_agent_requests_total", "Security decisions handled by the agent, by bounded action.", "counter")
		for index, action := range telemetry.SecurityActions {
			writeLabeledUint(w, "platform_agent_requests_total", `action="`+action+`"`, security.Actions[index])
		}

		writeHelpType(w, "platform_agent_fail_open_total", "Requests allowed without the full intended security control, by bounded reason.", "counter")
		for index, reason := range telemetry.FailOpenReasons {
			writeLabeledUint(w, "platform_agent_fail_open_total", `reason="`+reason+`"`, security.FailOpen[index])
		}

		writeHelpType(w, "platform_agent_stage_unavailable_total", "Policy-stage unavailability decisions by stage and fail behavior.", "counter")
		for stageIndex, stage := range [...]string{"stage2", "stage3"} {
			for behaviorIndex, behavior := range [...]string{"open", "closed"} {
				labels := `stage="` + stage + `",behavior="` + behavior + `"`
				writeLabeledUint(w, "platform_agent_stage_unavailable_total", labels, security.StageUnavailable[stageIndex][behaviorIndex])
			}
		}

		writeHelpType(w, "platform_agent_request_duration_milliseconds", "End-to-end agent request duration in milliseconds.", "histogram")
		writeHistogram(w, "platform_agent_request_duration_milliseconds", "", security.RequestDuration)
		writeHelpType(w, "platform_agent_stage_duration_milliseconds", "Policy-stage evaluation duration in milliseconds.", "histogram")
		for index, stage := range [...]string{"stage1", "stage2", "stage3"} {
			writeHistogram(w, "platform_agent_stage_duration_milliseconds", `stage="`+stage+`"`, security.StageDuration[index])
		}

		writePrometheusMetric(w, "platform_agent_kill_switch_block_all", "Whether the global emergency kill switch is active.", "gauge", boolMetric(killSwitchStats.BlockAll))
		writePrometheusMetric(w, "platform_agent_kill_switch_blocked_assets", "Number of asset-specific emergency blocks.", "gauge", uint64(killSwitchStats.BlockedAssets))
		writePrometheusMetric(w, "platform_agent_kill_switch_disabled_tools", "Number of tool-specific emergency disables.", "gauge", uint64(killSwitchStats.DisabledTools))
	})

	return mux
}

var startedAt = time.Now()

func writePrometheusMetric(w http.ResponseWriter, name, help, metricType string, value uint64) {
	writeHelpType(w, name, help, metricType)
	writeUint(w, name, value)
}

func writeHelpType(w http.ResponseWriter, name, help, metricType string) {
	_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func writeUint(w http.ResponseWriter, name string, value uint64) {
	_, _ = fmt.Fprintf(w, "%s %s\n", name, formatUint(value))
}

func writeLabeledUint(w http.ResponseWriter, name, labels string, value uint64) {
	_, _ = fmt.Fprintf(w, "%s{%s} %s\n", name, labels, formatUint(value))
}

func writeHistogram(
	w http.ResponseWriter,
	name, labels string,
	histogram telemetry.DurationSnapshot,
) {
	labelPrefix := ""
	if labels != "" {
		labelPrefix = labels + ","
	}
	for index, upper := range telemetry.DurationBucketsMS {
		_, _ = fmt.Fprintf(
			w,
			"%s_bucket{%sle=\"%s\"} %s\n",
			name,
			labelPrefix,
			strconv.FormatFloat(upper, 'f', -1, 64),
			formatUint(histogram.Buckets[index]),
		)
	}
	_, _ = fmt.Fprintf(w, "%s_bucket{%sle=\"+Inf\"} %s\n", name, labelPrefix, formatUint(histogram.Count))
	if labels == "" {
		_, _ = fmt.Fprintf(w, "%s_sum %s\n%s_count %s\n", name, strconv.FormatFloat(histogram.Sum, 'f', -1, 64), name, formatUint(histogram.Count))
		return
	}
	_, _ = fmt.Fprintf(w, "%s_sum{%s} %s\n%s_count{%s} %s\n", name, labels, strconv.FormatFloat(histogram.Sum, 'f', -1, 64), name, labels, formatUint(histogram.Count))
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
