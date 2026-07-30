package management

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/policy"
	"github.com/Bobcatsfan33/ai-security-platform/runtime-agent/telemetry"
)

type discardUploader struct{}

func (discardUploader) Upload(context.Context, []telemetry.Event) error { return nil }

func TestDiagnosticMetricsExposeBoundedSecuritySignals(t *testing.T) {
	buf := telemetry.NewBuffer(zerolog.Nop(), discardUploader{}, 100, time.Hour, 1000)
	stage2US := uint32(2500)
	stage3MS := uint32(4)
	buf.Enqueue(telemetry.Event{
		ActionTaken:       policy.ActionAllowed,
		PipelineExitStage: policy.ExitStage2Unavailable,
		LatencyMS:         12,
		Stage1LatencyUS:   200,
		Stage2LatencyUS:   &stage2US,
	})
	buf.Enqueue(telemetry.Event{
		ActionTaken:       policy.ActionBlocked,
		PipelineExitStage: policy.ExitStage3Unavailable,
		LatencyMS:         25,
		Stage3LatencyMS:   &stage3MS,
	})
	buf.Enqueue(telemetry.Event{ActionTaken: policy.Action("passthrough_no_policy"), LatencyMS: 2})
	buf.Enqueue(telemetry.Event{ActionTaken: policy.Action("passthrough_unknown_format"), LatencyMS: 3})
	buf.Enqueue(telemetry.Event{ActionTaken: policy.Action("future_action"), LatencyMS: 5})
	buf.RecordFailOpen("policy_stale")
	buf.RecordFailOpen("future_reason")

	killSwitch := NewKillSwitchState()
	killSwitch.Apply(KillSwitchCommand{Type: "block_all"})
	killSwitch.Apply(KillSwitchCommand{Type: "block_asset", AssetID: "sensitive-asset-id"})
	killSwitch.Apply(KillSwitchCommand{Type: "disable_tool", ToolName: "sensitive-tool-name"})

	cache := policy.NewCache(zerolog.Nop(), nil, time.Hour)
	body := scrapeMetrics(t, DiagnosticHandler(cache, buf, killSwitch, "policy-1", "test"))

	expected := []string{
		"# HELP platform_agent_requests_total Security decisions handled by the agent, by bounded action.",
		"# TYPE platform_agent_requests_total counter",
		`platform_agent_requests_total{action="allowed"} 1`,
		`platform_agent_requests_total{action="blocked"} 1`,
		`platform_agent_requests_total{action="passthrough_no_policy"} 1`,
		`platform_agent_requests_total{action="passthrough_unknown_format"} 1`,
		`platform_agent_requests_total{action="other"} 1`,
		`platform_agent_fail_open_total{reason="no_policy"} 1`,
		`platform_agent_fail_open_total{reason="policy_stale"} 1`,
		`platform_agent_fail_open_total{reason="stage2_unavailable"} 1`,
		`platform_agent_fail_open_total{reason="unknown_format"} 1`,
		`platform_agent_fail_open_total{reason="other"} 1`,
		`platform_agent_stage_unavailable_total{stage="stage2",behavior="open"} 1`,
		`platform_agent_stage_unavailable_total{stage="stage3",behavior="closed"} 1`,
		`platform_agent_request_duration_milliseconds_count 5`,
		`platform_agent_stage_duration_milliseconds_count{stage="stage1"} 1`,
		`platform_agent_stage_duration_milliseconds_count{stage="stage2"} 1`,
		`platform_agent_stage_duration_milliseconds_count{stage="stage3"} 1`,
		"platform_agent_kill_switch_block_all 1",
		"platform_agent_kill_switch_blocked_assets 1",
		"platform_agent_kill_switch_disabled_tools 1",
	}
	for _, want := range expected {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("metrics missing %q\n%s", want, body)
		}
	}
	for _, metadata := range []string{
		"# HELP platform_agent_request_duration_milliseconds",
		"# TYPE platform_agent_request_duration_milliseconds",
		"# HELP platform_agent_stage_duration_milliseconds",
		"# TYPE platform_agent_stage_duration_milliseconds",
	} {
		if got := strings.Count(body, metadata); got != 1 {
			t.Errorf("%q count = %d, want 1", metadata, got)
		}
	}
	for _, secret := range []string{"sensitive-asset-id", "sensitive-tool-name"} {
		if strings.Contains(body, secret) {
			t.Errorf("metrics leaked sensitive or unbounded identifier %q", secret)
		}
	}
}

func TestDiagnosticMetricsAreRaceSafeDuringUpdates(t *testing.T) {
	buf := telemetry.NewBuffer(zerolog.Nop(), discardUploader{}, 100, time.Hour, 1000)
	killSwitch := NewKillSwitchState()
	cache := policy.NewCache(zerolog.Nop(), nil, time.Hour)
	handler := DiagnosticHandler(cache, buf, killSwitch, "policy-1", "test")

	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				buf.Enqueue(telemetry.Event{ActionTaken: policy.ActionAllowed, LatencyMS: uint32(i)})
				killSwitch.Apply(KillSwitchCommand{Type: "block_asset", AssetID: "asset"})
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
				if rec.Code != http.StatusOK {
					t.Errorf("metrics status = %d, want 200", rec.Code)
				}
			}
		}()
	}
	wg.Wait()
}

func scrapeMetrics(t *testing.T, handler http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; version=0.0.4" {
		t.Fatalf("content type = %q", got)
	}
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
